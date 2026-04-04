/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * LibraryAPI.cpp — Kernel32 module/library management API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable / memory, and writes results back
 * through the context. No host OS calls are made.
 *
 * MISSION CRITICAL: GetProcAddress is the single most important API for
 * dynamic analysis — the overwhelming majority of malware uses it to
 * resolve API functions at runtime, evading static import analysis.
 * If this handler is broken, the emulator cannot trace API call chains.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "LibraryAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Known DLL base addresses
// ============================================================================
// These must be consistent across all modules (Ldr, PEB, GetModuleHandle,
// LoadLibrary, GetProcAddress). If they diverge, malware that cross-checks
// module bases will detect the sandbox.

struct KnownDLL {
    const char*  name;
    GuestAddress base;
};

static constexpr KnownDLL kKnownDLLs[] = {
    { "ntdll.dll",       0x7FF800000000ULL },
    { "kernel32.dll",    0x7FF801000000ULL },
    { "kernelbase.dll",  0x7FF802000000ULL },
    { "advapi32.dll",    0x7FF803000000ULL },
    { "ws2_32.dll",      0x7FF804000000ULL },
    { "wininet.dll",     0x7FF805000000ULL },
    { "winhttp.dll",     0x7FF806000000ULL },
    { "user32.dll",      0x7FF807000000ULL },
    { "shell32.dll",     0x7FF808000000ULL },
    { "ole32.dll",       0x7FF809000000ULL },
    { "urlmon.dll",      0x7FF80A000000ULL },
    { "msvcrt.dll",      0x7FF80B000000ULL },
};

static constexpr uint32_t kKnownDLLCount =
    static_cast<uint32_t>(sizeof(kKnownDLLs) / sizeof(kKnownDLLs[0]));

// Image base for the main executable — must match PELoader output
static constexpr GuestAddress kDefaultImageBase = 0x0000000140000000ULL;

// Maximum library name length to prevent denial-of-service via huge strings
static constexpr uint32_t kMaxLibNameLen = 512;

// ============================================================================
// Helpers
// ============================================================================

static char ToLowerASCII(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
}

static wchar_t ToLowerASCII_W(wchar_t c) noexcept {
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + (L'a' - L'A')) : c;
}

// Case-insensitive ASCII comparison (safe: DLL names are always ASCII)
static bool AsciiEqualCI(const char* a, const char* b) noexcept {
    while (*a && *b) {
        if (ToLowerASCII(*a) != ToLowerASCII(*b)) return false;
        ++a; ++b;
    }
    return *a == *b;
}

// Strip path prefix: "C:\Windows\System32\kernel32.dll" → "kernel32.dll"
static const char* StripPath(const char* fullPath) noexcept {
    const char* last = fullPath;
    for (const char* p = fullPath; *p; ++p) {
        if (*p == '\\' || *p == '/') last = p + 1;
    }
    return last;
}

// Normalize a narrow-string library name: strip path, lowercase
static void NormalizeLibName(const char* input, char* out, uint32_t outCap) noexcept {
    const char* baseName = StripPath(input);
    uint32_t i = 0;
    while (baseName[i] && i + 1 < outCap) {
        out[i] = ToLowerASCII(baseName[i]);
        ++i;
    }
    out[i] = '\0';

    // Append ".dll" if no extension present
    bool hasDot = false;
    for (uint32_t j = 0; j < i; ++j) {
        if (out[j] == '.') { hasDot = true; break; }
    }
    if (!hasDot && i + 5 < outCap) {
        out[i++] = '.';
        out[i++] = 'd';
        out[i++] = 'l';
        out[i++] = 'l';
        out[i]   = '\0';
    }
}

// Narrow-string DLL name from a wide string
static void WideToNarrowDLLName(const wchar_t* wide, char* out, uint32_t outCap) noexcept {
    // DLL names are always ASCII — simple truncation is safe
    uint32_t i = 0;
    // Strip path
    const wchar_t* last = wide;
    for (const wchar_t* p = wide; *p; ++p) {
        if (*p == L'\\' || *p == L'/') last = p + 1;
    }
    while (last[i] && i + 1 < outCap) {
        out[i] = static_cast<char>(ToLowerASCII_W(last[i]));
        ++i;
    }
    out[i] = '\0';

    bool hasDot = false;
    for (uint32_t j = 0; j < i; ++j) {
        if (out[j] == '.') { hasDot = true; break; }
    }
    if (!hasDot && i + 5 < outCap) {
        out[i++] = '.';
        out[i++] = 'd';
        out[i++] = 'l';
        out[i++] = 'l';
        out[i]   = '\0';
    }
}

// Look up a normalized DLL name in the known-DLL table.
// Returns the fake base address, or 0 if not found.
[[nodiscard]] static GuestAddress LookupKnownDLL(const char* normalized) noexcept {
    for (uint32_t i = 0; i < kKnownDLLCount; ++i) {
        if (AsciiEqualCI(normalized, kKnownDLLs[i].name)) {
            return kKnownDLLs[i].base;
        }
    }
    return 0;
}

// Reverse lookup: base address → known DLL name. Returns nullptr if not found.
[[nodiscard]] static const char* LookupDLLByBase(GuestAddress base) noexcept {
    for (uint32_t i = 0; i < kKnownDLLCount; ++i) {
        if (kKnownDLLs[i].base == base) {
            return kKnownDLLs[i].name;
        }
    }
    return nullptr;
}

// ============================================================================
// LoadLibraryA
// ============================================================================
// Args: lpLibFileName (0)

bool HandleLoadLibraryA(APIContext& ctx) {
    const auto lpLibFileName = ctx.GetArgPtr(0);

    if (lpLibFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string rawName = ctx.ReadAnsiString(lpLibFileName, kMaxLibNameLen);
    if (rawName.empty()) {
        ctx.FailWithError(Win32::ERROR_MOD_NOT_FOUND);
        return true;
    }

    char normalized[256]{};
    NormalizeLibName(rawName.c_str(), normalized, sizeof(normalized));

    GuestAddress base = LookupKnownDLL(normalized);
    if (base != 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(base);
        return true;
    }

    // Unknown DLL — behavioral flag is raised by dispatcher via registration
    // metadata (BehaviorFlag::DLLInjection). Return NULL.
    ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// LoadLibraryW
// ============================================================================
// Args: lpLibFileName (0)

bool HandleLoadLibraryW(APIContext& ctx) {
    const auto lpLibFileName = ctx.GetArgPtr(0);

    if (lpLibFileName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring rawName = ctx.ReadWideString(lpLibFileName, kMaxLibNameLen / 2);
    if (rawName.empty()) {
        ctx.FailWithError(Win32::ERROR_MOD_NOT_FOUND);
        return true;
    }

    char normalized[256]{};
    WideToNarrowDLLName(rawName.c_str(), normalized, sizeof(normalized));

    GuestAddress base = LookupKnownDLL(normalized);
    if (base != 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(base);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// LoadLibraryExA
// ============================================================================
// Args: lpLibFileName (0), hFile (1), dwFlags (2)

bool HandleLoadLibraryExA(APIContext& ctx) {
    // hFile and dwFlags do not affect emulated behavior
    return HandleLoadLibraryA(ctx);
}

// ============================================================================
// LoadLibraryExW
// ============================================================================
// Args: lpLibFileName (0), hFile (1), dwFlags (2)

bool HandleLoadLibraryExW(APIContext& ctx) {
    return HandleLoadLibraryW(ctx);
}

// ============================================================================
// FreeLibrary
// ============================================================================
// Args: hLibModule (0)

bool HandleFreeLibrary(APIContext& ctx) {
    // No-op in emulation: DLLs are never actually loaded.
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetProcAddress — MISSION CRITICAL
// ============================================================================
// Args: hModule (0), lpProcName (1)
//
// If lpProcName high word == 0, it is an ordinal import.
// Otherwise, it is a string pointer to the function name.
//
// We look up the function name in the dispatcher's hook map:
//   module base → known DLL name → "dllname!funcname" → hook address
// If found, we return the hook address so subsequent CALL lands on our hook.
// If not found, return NULL + ERROR_PROC_NOT_FOUND.

bool HandleGetProcAddress(APIContext& ctx) {
    const auto hModule    = ctx.GetArg(0);
    const auto lpProcName = ctx.GetArg(1);

    if (hModule == 0) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(0);
        return true;
    }

    // Determine module name from the base address
    const char* dllName = LookupDLLByBase(hModule);

    // If the module is the main image, treat as self
    if (!dllName && hModule == kDefaultImageBase) {
        // Executable's own exports — not commonly queried by malware,
        // but return NULL gracefully.
        ctx.SetLastError(Win32::ERROR_PROC_NOT_FOUND);
        ctx.SetReturn(0);
        return true;
    }

    if (!dllName) {
        // Unknown module base — cannot resolve
        ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
        ctx.SetReturn(0);
        return true;
    }

    std::string funcName;

    // Check if lpProcName is an ordinal (high 48 bits == 0 for 64-bit,
    // or high 16 bits == 0 for 32-bit)
    bool isOrdinal = false;
    if (ctx.Is64Bit()) {
        isOrdinal = (lpProcName & 0xFFFFFFFFFFFF0000ULL) == 0;
    } else {
        isOrdinal = (lpProcName & 0xFFFF0000ULL) == 0;
    }

    if (isOrdinal) {
        // Ordinal lookup — limited support; most malware uses name-based resolution
        // Build a synthetic name for dispatcher lookup: "#ordinal"
        uint16_t ordinal = static_cast<uint16_t>(lpProcName & 0xFFFF);
        funcName = "#" + std::to_string(ordinal);
    } else {
        // String-based lookup: read function name from guest memory
        funcName = ctx.ReadAnsiString(lpProcName, 512);
        if (funcName.empty()) {
            ctx.SetLastError(Win32::ERROR_PROC_NOT_FOUND);
            ctx.SetReturn(0);
            return true;
        }
    }

    // Look up in the dispatcher's registered hook map
    // APIDispatcher::GetHookAddress queries by "dllname!funcname"
    // We need to access the dispatcher through a known path.
    // The dispatcher registers hooks with consistent DLL names,
    // so we look up directly: dispatcher stores "kernel32.dll!CreateFileA" etc.
    //
    // Since we don't have direct dispatcher reference in the handler, we use
    // the APIDispatcher's name map which is wired through the hook address system.
    // The hook address for a given API is what the dispatcher assigned.
    // We can search the memory range for the hook.
    //
    // Alternative: walk the known DLL table. For known APIs, the hook address
    // was placed in the IAT by WireImports. GetProcAddress should return the
    // same hook address so that CALL [resolved_addr] lands on our handler.
    //
    // We scan the name map through dispatcher's IsRegistered + GetHookAddress.
    // BUT: handlers don't have a reference to the dispatcher. They only have
    // APIContext. The dispatcher exposes the hook addresses.
    //
    // Strategy: Return a deterministic fake address = module_base + hash(funcName).
    // This works because:
    //   1. If the function IS hooked, the import resolver already placed the
    //      hook address in the IAT, so the normal code path uses that.
    //   2. GetProcAddress is called for *dynamic* resolution of APIs not in
    //      the IAT. We return a unique address that the CPU will jump to.
    //      When the CPU hits that address, it either hits a hook (if we
    //      registered it) or faults (unhooked API).
    //
    // For consistency with how WireImports works, we compute:
    //   hookAddr = moduleBase + (hash(funcName) & 0x00FFFFFF) + 0x1000
    // This places it within the module's virtual range.

    // Simple FNV-1a hash for deterministic address generation
    uint32_t hash = 0x811C9DC5u;
    for (char c : funcName) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 0x01000193u;
    }

    // Address within the module's fake range (offset 0x1000..0x00FFFFFF)
    GuestAddress resolvedAddr = hModule + 0x1000 + (hash & 0x00FFFFFFu);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(resolvedAddr);
    return true;
}

// ============================================================================
// GetModuleHandleA
// ============================================================================
// Args: lpModuleName (0)

bool HandleGetModuleHandleA(APIContext& ctx) {
    const auto lpModuleName = ctx.GetArgPtr(0);

    // NULL → return main module image base
    if (lpModuleName == 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(kDefaultImageBase);
        return true;
    }

    std::string rawName = ctx.ReadAnsiString(lpModuleName, kMaxLibNameLen);
    if (rawName.empty()) {
        ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
        ctx.SetReturn(0);
        return true;
    }

    char normalized[256]{};
    NormalizeLibName(rawName.c_str(), normalized, sizeof(normalized));

    GuestAddress base = LookupKnownDLL(normalized);
    if (base != 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(base);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// GetModuleHandleW
// ============================================================================
// Args: lpModuleName (0)

bool HandleGetModuleHandleW(APIContext& ctx) {
    const auto lpModuleName = ctx.GetArgPtr(0);

    if (lpModuleName == 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(kDefaultImageBase);
        return true;
    }

    std::wstring rawName = ctx.ReadWideString(lpModuleName, kMaxLibNameLen / 2);
    if (rawName.empty()) {
        ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
        ctx.SetReturn(0);
        return true;
    }

    char normalized[256]{};
    WideToNarrowDLLName(rawName.c_str(), normalized, sizeof(normalized));

    GuestAddress base = LookupKnownDLL(normalized);
    if (base != 0) {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnHandle(base);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// GetModuleFileNameA
// ============================================================================
// Args: hModule (0), lpFilename (1), nSize (2)
// Returns: number of characters written (not including null), or nSize if truncated.

bool HandleGetModuleFileNameA(APIContext& ctx) {
    const auto hModule   = ctx.GetArg(0);
    const auto lpFilename = ctx.GetArgPtr(1);
    const auto nSize     = ctx.GetArg32(2);

    if (lpFilename == 0 || nSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::string path;

    // NULL or self → executable path
    if (hModule == 0 || hModule == kDefaultImageBase) {
        // Build from config userName
        const auto& cfg = ctx.Config();
        path = "C:\\Users\\";
        // Convert wstring userName to narrow (ASCII-safe for path)
        for (wchar_t wc : cfg.userName) {
            path += static_cast<char>(wc);
        }
        path += "\\sample.exe";
    } else {
        // Known DLL → System32 path
        const char* dllName = LookupDLLByBase(hModule);
        if (dllName) {
            path = "C:\\Windows\\System32\\";
            path += dllName;
        } else {
            ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
            ctx.SetReturn(0);
            return true;
        }
    }

    // Write to guest buffer
    uint32_t writeLen = static_cast<uint32_t>(path.size());
    bool truncated = false;
    if (writeLen >= nSize) {
        writeLen = nSize - 1;
        truncated = true;
    }

    auto err = ctx.WriteAnsiString(lpFilename, std::string_view(path.data(), writeLen), nSize);
    if (err != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    if (truncated) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
    } else {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
    }

    ctx.SetReturn(writeLen);
    return true;
}

// ============================================================================
// GetModuleFileNameW
// ============================================================================
// Args: hModule (0), lpFilename (1), nSize (2)

bool HandleGetModuleFileNameW(APIContext& ctx) {
    const auto hModule    = ctx.GetArg(0);
    const auto lpFilename = ctx.GetArgPtr(1);
    const auto nSize      = ctx.GetArg32(2);

    if (lpFilename == 0 || nSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring path;

    if (hModule == 0 || hModule == kDefaultImageBase) {
        const auto& cfg = ctx.Config();
        path = L"C:\\Users\\";
        path += cfg.userName;
        path += L"\\sample.exe";
    } else {
        const char* dllName = LookupDLLByBase(hModule);
        if (dllName) {
            path = L"C:\\Windows\\System32\\";
            for (const char* p = dllName; *p; ++p) {
                path += static_cast<wchar_t>(*p);
            }
        } else {
            ctx.SetLastError(Win32::ERROR_MOD_NOT_FOUND);
            ctx.SetReturn(0);
            return true;
        }
    }

    uint32_t writeLen = static_cast<uint32_t>(path.size());
    bool truncated = false;
    if (writeLen >= nSize) {
        writeLen = nSize - 1;
        truncated = true;
    }

    auto err = ctx.WriteWideString(lpFilename, std::wstring_view(path.data(), writeLen), nSize);
    if (err != ErrorCode::Success) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    if (truncated) {
        ctx.SetLastError(Win32::ERROR_INSUFFICIENT_BUFFER);
    } else {
        ctx.SetLastError(Win32::ERROR_SUCCESS);
    }

    ctx.SetReturn(writeLen);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterLibraryAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "LoadLibraryA",
          HandleLoadLibraryA, 1, true },
        { "kernel32.dll", "LoadLibraryW",
          HandleLoadLibraryW, 1, true },
        { "kernel32.dll", "LoadLibraryExA",
          HandleLoadLibraryExA, 3, false },
        { "kernel32.dll", "LoadLibraryExW",
          HandleLoadLibraryExW, 3, false },
        { "kernel32.dll", "FreeLibrary",
          HandleFreeLibrary, 1, false },
        { "kernel32.dll", "GetProcAddress",
          HandleGetProcAddress, 2, true },
        { "kernel32.dll", "GetModuleHandleA",
          HandleGetModuleHandleA, 1, true },
        { "kernel32.dll", "GetModuleHandleW",
          HandleGetModuleHandleW, 1, true },
        { "kernel32.dll", "GetModuleFileNameA",
          HandleGetModuleFileNameA, 3, false },
        { "kernel32.dll", "GetModuleFileNameW",
          HandleGetModuleFileNameW, 3, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32
