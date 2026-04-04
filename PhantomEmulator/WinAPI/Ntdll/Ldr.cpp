/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * Ldr.cpp — Ntdll Loader (Ldr) function handler implementations
 *
 * Emulates the NT module loader for dynamic API resolution. Maintains a
 * table of known DLL names mapped to fake base addresses and resolves
 * function names to APIDispatcher hook addresses so dynamically resolved
 * calls are intercepted identically to statically imported ones.
 *
 * Case-insensitive, path-stripping normalization handles real-world
 * malware patterns: "KERNEL32.DLL", "kernel32", "C:\Windows\...\kernel32.dll".
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "Ldr.hpp"
#include "../APIDispatcher.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Errors.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>

namespace Phantom::WinAPI::Ntdll {
namespace {

// ============================================================================
// Constants
// ============================================================================

static constexpr uint32_t kMaxAnsiLen    = 4096;
static constexpr uint32_t kMaxWideChars  = 2048;

// ============================================================================
// Known DLL Table — Fake base addresses for emulated modules
// ============================================================================
// These addresses are in the high-canonical range that real Windows uses for
// system DLLs. Each is spaced 16 MB apart to avoid collisions.

struct KnownDllEntry {
    const wchar_t* name;
    GuestAddress   base;
};

static constexpr KnownDllEntry kKnownDlls[] = {
    { L"ntdll.dll",       0x7FF800000000ULL },
    { L"kernel32.dll",    0x7FF801000000ULL },
    { L"kernelbase.dll",  0x7FF802000000ULL },
    { L"advapi32.dll",    0x7FF803000000ULL },
    { L"ws2_32.dll",      0x7FF804000000ULL },
    { L"wininet.dll",     0x7FF805000000ULL },
    { L"winhttp.dll",     0x7FF806000000ULL },
    { L"user32.dll",      0x7FF807000000ULL },
    { L"shell32.dll",     0x7FF808000000ULL },
    { L"ole32.dll",       0x7FF809000000ULL },
    { L"urlmon.dll",      0x7FF80A000000ULL },
    { L"msvcrt.dll",      0x7FF80B000000ULL },
};

// ============================================================================
// Ldr State — Module tracking (Meyers' singleton)
// ============================================================================

struct LdrState {
    APIDispatcher* dispatcher = nullptr;

    // Loaded module tracking: normalized lowercase name → base address
    std::unordered_map<std::wstring, GuestAddress> loadedModules;
    // Reverse lookup: base address → normalized lowercase name
    std::unordered_map<GuestAddress, std::wstring> baseToName;

    static LdrState& Get() noexcept {
        static LdrState instance;
        return instance;
    }
};

// ============================================================================
// Helpers
// ============================================================================

/// Normalize a DLL name: strip path, lowercase, ensure .dll suffix.
[[nodiscard]] static std::wstring NormalizeDllName(std::wstring_view input) noexcept {
    // Strip path prefix
    const auto sep = input.find_last_of(L"\\/");
    const auto name = (sep != std::wstring_view::npos) ? input.substr(sep + 1) : input;

    std::wstring result;
    result.reserve(name.size() + 4);

    for (const auto c : name) {
        result.push_back((c >= L'A' && c <= L'Z')
                             ? static_cast<wchar_t>(c + 32)
                             : c);
    }

    // Append .dll if missing
    if (result.size() < 4 || result.compare(result.size() - 4, 4, L".dll") != 0) {
        result += L".dll";
    }

    return result;
}

/// Look up a normalized name in the known DLL table.
[[nodiscard]] static std::optional<GuestAddress> FindKnownDllBase(
        const std::wstring& normalized) noexcept {
    for (const auto& entry : kKnownDlls) {
        if (normalized == entry.name) {
            return entry.base;
        }
    }
    return std::nullopt;
}

/// Narrow a wide string to ASCII (for APIDispatcher lookups).
[[nodiscard]] static std::string NarrowString(const std::wstring& ws) noexcept {
    std::string result;
    result.reserve(ws.size());
    for (const auto c : ws) {
        result.push_back(static_cast<char>(c < 128 ? c : '?'));
    }
    return result;
}

/// Write a guest pointer (size-aware: 4 bytes on x86, 8 bytes on x64).
static void WriteGuestPtr(APIContext& ctx, GuestAddress dest, GuestAddress value) noexcept {
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(dest, value);
    } else {
        ctx.Memory().WriteU32(dest, static_cast<uint32_t>(value));
    }
}

/// Read an ANSI_STRING structure from guest memory and return the string.
/// Layout: u16 Length, u16 MaxLen, [u32 pad on x64], ptr Buffer.
[[nodiscard]] static std::string ReadGuestAnsiStringStruct(
        APIContext& ctx, GuestAddress addr) noexcept {
    auto& mem = ctx.Memory();

    uint16_t length = 0;
    if (mem.ReadU16(addr, length) != ErrorCode::Success) return {};
    if (length == 0 || length > kMaxAnsiLen) return {};

    GuestAddress buffer = 0;
    if (ctx.Is64Bit()) {
        uint64_t ptr = 0;
        if (mem.ReadU64(addr + 8, ptr) != ErrorCode::Success) return {};
        buffer = ptr;
    } else {
        uint32_t ptr = 0;
        if (mem.ReadU32(addr + 4, ptr) != ErrorCode::Success) return {};
        buffer = static_cast<GuestAddress>(ptr);
    }

    if (buffer == 0) return {};
    return ctx.ReadAnsiString(buffer, std::min<uint32_t>(length, kMaxAnsiLen));
}

// ============================================================================
// LdrLoadDll Handler
// ============================================================================
// NTSTATUS LdrLoadDll(
//     PWSTR PathToFile,          // arg0 — optional search path
//     PULONG Flags,              // arg1 — optional flags
//     PUNICODE_STRING ModuleName,// arg2 — DLL name to load
//     PHANDLE ModuleHandle       // arg3 — receives module base address
// )

static bool HandleLdrLoadDll(APIContext& ctx) {
    const GuestAddress moduleNamePtr   = ctx.GetArgPtr(2);
    const GuestAddress moduleHandlePtr = ctx.GetArgPtr(3);

    if (moduleNamePtr == 0 || moduleHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Read the UNICODE_STRING module name
    const std::wstring rawName = ctx.ReadUnicodeString(moduleNamePtr);
    if (rawName.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    const std::wstring normalized = NormalizeDllName(rawName);
    auto& state = LdrState::Get();

    // Already loaded? Return existing base.
    auto it = state.loadedModules.find(normalized);
    if (it != state.loadedModules.end()) {
        WriteGuestPtr(ctx, moduleHandlePtr, it->second);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // Look up in known DLL table
    auto baseOpt = FindKnownDllBase(normalized);
    if (!baseOpt) {
        ctx.SetReturnNtStatus(NT::STATUS_DLL_NOT_FOUND);
        return true;
    }

    const GuestAddress base = *baseOpt;

    // Track the newly "loaded" module
    state.loadedModules[normalized] = base;
    state.baseToName[base]          = normalized;

    WriteGuestPtr(ctx, moduleHandlePtr, base);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// LdrGetProcedureAddress Handler
// ============================================================================
// NTSTATUS LdrGetProcedureAddress(
//     HMODULE ModuleHandle,            // arg0 — base address of loaded DLL
//     PANSI_STRING FunctionName,       // arg1 — function name (NULL if by ordinal)
//     WORD Ordinal,                    // arg2 — ordinal (used if name is NULL)
//     PVOID *FunctionAddress           // arg3 — receives function pointer
// )

static bool HandleLdrGetProcedureAddress(APIContext& ctx) {
    const GuestAddress moduleHandle = ctx.GetArgPtr(0);
    const GuestAddress funcNamePtr  = ctx.GetArgPtr(1);
    const GuestAddress funcAddrPtr  = ctx.GetArgPtr(3);

    if (funcAddrPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& state = LdrState::Get();

    // Resolve which DLL this module handle belongs to
    auto modIt = state.baseToName.find(moduleHandle);
    if (modIt == state.baseToName.end()) {
        // Module handle not recognized — might be the process image itself
        // or an untracked module. Allow known DLL bases to be used directly.
        for (const auto& entry : kKnownDlls) {
            if (entry.base == moduleHandle) {
                const std::wstring name(entry.name);
                state.loadedModules[name] = entry.base;
                state.baseToName[entry.base] = name;
                modIt = state.baseToName.find(moduleHandle);
                break;
            }
        }
        if (modIt == state.baseToName.end()) {
            ctx.SetReturnNtStatus(NT::STATUS_DLL_NOT_FOUND);
            return true;
        }
    }

    const std::string dllName = NarrowString(modIt->second);

    // Read function name from ANSI_STRING structure
    std::string funcName;
    if (funcNamePtr != 0) {
        funcName = ReadGuestAnsiStringStruct(ctx, funcNamePtr);
    }

    if (funcName.empty()) {
        // Ordinal-based lookup — we do not maintain ordinal tables
        ctx.SetReturnNtStatus(NT::STATUS_PROCEDURE_NOT_FOUND);
        return true;
    }

    // Query the dispatcher for the hook address of this function
    if (state.dispatcher == nullptr) {
        ctx.SetReturnNtStatus(NT::STATUS_PROCEDURE_NOT_FOUND);
        return true;
    }

    auto hookAddr = state.dispatcher->GetHookAddress(dllName, funcName);
    if (!hookAddr) {
        ctx.SetReturnNtStatus(NT::STATUS_PROCEDURE_NOT_FOUND);
        return true;
    }

    WriteGuestPtr(ctx, funcAddrPtr, *hookAddr);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// LdrGetDllHandle Handler
// ============================================================================
// NTSTATUS LdrGetDllHandle(
//     PWSTR DllPath,                  // arg0 — optional search path
//     PULONG DllCharacteristics,      // arg1 — optional
//     PUNICODE_STRING DllName,        // arg2 — DLL name
//     PHANDLE DllHandle               // arg3 — receives module base address
// )

static bool HandleLdrGetDllHandle(APIContext& ctx) {
    const GuestAddress dllNamePtr   = ctx.GetArgPtr(2);
    const GuestAddress dllHandlePtr = ctx.GetArgPtr(3);

    if (dllNamePtr == 0 || dllHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    const std::wstring rawName = ctx.ReadUnicodeString(dllNamePtr);
    if (rawName.empty()) {
        ctx.SetReturnNtStatus(NT::STATUS_DLL_NOT_FOUND);
        return true;
    }

    const std::wstring normalized = NormalizeDllName(rawName);
    auto& state = LdrState::Get();

    // Check already-loaded modules first
    auto it = state.loadedModules.find(normalized);
    if (it != state.loadedModules.end()) {
        WriteGuestPtr(ctx, dllHandlePtr, it->second);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // Auto-load if it's a known DLL (common pattern: GetModuleHandle before LoadLibrary)
    auto baseOpt = FindKnownDllBase(normalized);
    if (baseOpt) {
        state.loadedModules[normalized] = *baseOpt;
        state.baseToName[*baseOpt]      = normalized;

        WriteGuestPtr(ctx, dllHandlePtr, *baseOpt);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_DLL_NOT_FOUND);
    return true;
}

// ============================================================================
// LdrUnloadDll Handler
// ============================================================================
// NTSTATUS LdrUnloadDll(HANDLE DllHandle)
// No-op — we never truly unload, as subsequent resolution must still work.

static bool HandleLdrUnloadDll(APIContext& ctx) {
    (void)ctx;
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration Table
// ============================================================================

static const APIRegistration kLdrRegistrations[] = {
    { "ntdll.dll", "LdrLoadDll",              HandleLdrLoadDll,              4, false },
    { "ntdll.dll", "LdrGetProcedureAddress",  HandleLdrGetProcedureAddress,  4, false },
    { "ntdll.dll", "LdrGetDllHandle",         HandleLdrGetDllHandle,         4, false },
    { "ntdll.dll", "LdrUnloadDll",            HandleLdrUnloadDll,            1, false },
};

} // anonymous namespace

// ============================================================================
// Public API
// ============================================================================

void RegisterLdrHandlers(APIDispatcher& dispatcher) noexcept {
    // Store back-pointer so LdrGetProcedureAddress can resolve hook addresses
    LdrState::Get().dispatcher = &dispatcher;

    dispatcher.RegisterBatch(kLdrRegistrations,
                             static_cast<uint32_t>(std::size(kLdrRegistrations)));
}

void ResetLdrState() noexcept {
    auto& state = LdrState::Get();
    state.dispatcher = nullptr;
    state.loadedModules.clear();
    state.baseToName.clear();
}

} // namespace Phantom::WinAPI::Ntdll
