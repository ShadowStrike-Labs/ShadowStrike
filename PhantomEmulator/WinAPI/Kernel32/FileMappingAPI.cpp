/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * FileMappingAPI.cpp — Kernel32 memory-mapped file API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory / HandleTable, and writes results
 * back to guest memory pointers. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - CreateFileMapping with SEC_IMAGE is process hollowing setup
 *     (T1055.012): the attacker maps a PE image into a suspended
 *     process and overwrites its entry point.
 *   - Named sections enable shared-memory C2 channels between
 *     injected DLLs and their controller processes.
 *   - MapViewOfFile with executable protection bypasses DEP by
 *     loading code outside the normal PE loader path.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "FileMappingAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>
#include <unordered_map>

// DESIGN: VirtualMemory::Free returns [[nodiscard]] ErrorCode. In Kernel32
// section-mapping shims we discard it — UnmapViewOfFile's Win32 contract
// surfaces failure via GetLastError / BOOL only. Scope: this TU only.
#pragma warning(push)
#pragma warning(disable: 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

// Section attribute flags (matching Windows SDK)
static constexpr uint32_t SEC_IMAGE          = 0x01000000;
static constexpr uint32_t SEC_RESERVE        = 0x04000000;
static constexpr uint32_t SEC_COMMIT         = 0x08000000;
static constexpr uint32_t SEC_NOCACHE        = 0x10000000;
static constexpr uint32_t SEC_LARGE_PAGES    = 0x80000000;

// File mapping access flags for MapViewOfFile
static constexpr uint32_t FILE_MAP_WRITE     = 0x0002;
static constexpr uint32_t FILE_MAP_READ      = 0x0004;
static constexpr uint32_t FILE_MAP_ALL_ACCESS = 0x000F001F;
static constexpr uint32_t FILE_MAP_EXECUTE   = 0x0020;
static constexpr uint32_t FILE_MAP_COPY      = 0x0001;

// Maximum mapping size cap (defense against hostile input)
static constexpr uint64_t kMaxMappingSize    = 128ULL * 1024 * 1024;  // 128 MB
static constexpr uint64_t kDefaultMapSize    = 64 * 1024;             // 64 KB fallback

// Tracked mapped views: mapped guest address → size
static std::unordered_map<GuestAddress, GuestSize> s_mappedViews;

// ============================================================================
// Helpers
// ============================================================================

static bool IsExecutableProtection(uint32_t protect) noexcept {
    uint32_t base = protect & 0xFF;
    return base == NT::PAGE_EXECUTE ||
           base == NT::PAGE_EXECUTE_READ ||
           base == NT::PAGE_EXECUTE_READWRITE ||
           base == NT::PAGE_EXECUTE_WRITECOPY;
}

static MemProt MapAccessToMemProt(uint32_t desiredAccess) noexcept {
    if (desiredAccess & FILE_MAP_EXECUTE) {
        if (desiredAccess & FILE_MAP_WRITE) return MemProt::RWX;
        return MemProt::RX;
    }
    if (desiredAccess & FILE_MAP_WRITE)  return MemProt::RW;
    if (desiredAccess & FILE_MAP_ALL_ACCESS) return MemProt::RW;
    if (desiredAccess & FILE_MAP_READ)   return MemProt::Read;
    if (desiredAccess & FILE_MAP_COPY)   return MemProt::RW;
    return MemProt::Read;
}

// ============================================================================
// CreateFileMappingA
// ============================================================================
// Args: hFile (0), lpAttributes (1), flProtect (2),
//       dwMaximumSizeHigh (3), dwMaximumSizeLow (4), lpName (5)
// Returns: HANDLE to the section object, or NULL on failure.

static bool CreateFileMappingImpl(APIContext& ctx, bool isWide) {
    const auto hFile              = ctx.GetArg(0);
    // arg1: lpFileMappingAttributes (ignored)
    const auto flProtect          = ctx.GetArg32(2);
    const auto dwMaximumSizeHigh  = ctx.GetArg32(3);
    const auto dwMaximumSizeLow   = ctx.GetArg32(4);
    const auto lpName             = ctx.GetArgPtr(5);

    (void)hFile;

    // Compute maximum size
    uint64_t maxSize = (static_cast<uint64_t>(dwMaximumSizeHigh) << 32) |
                       static_cast<uint64_t>(dwMaximumSizeLow);
    if (maxSize == 0) {
        maxSize = kDefaultMapSize;
    }
    if (maxSize > kMaxMappingSize) {
        maxSize = kMaxMappingSize;
    }

    // Read section name if provided
    std::wstring sectionName;
    if (lpName != 0) {
        if (isWide) {
            sectionName = ctx.ReadWideString(lpName, 512);
        } else {
            std::string ansiName = ctx.ReadAnsiString(lpName, 512);
            sectionName = std::wstring(ansiName.begin(), ansiName.end());
        }
    }

    // Extract base protection (strip section attributes)
    uint32_t baseProt = flProtect & 0x00FFFFFF;

    // SEC_IMAGE maps a PE as an image — the exact primitive used for
    // process hollowing / module stomping (T1055.012).
    if ((flProtect & SEC_IMAGE) != 0) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessHollowing);
    }
    // Executable section protection is a DEP-bypass / shellcode-loader
    // pattern when combined with writable protections (RWX).
    if (IsExecutableProtection(baseProt)) {
        if (baseProt == NT::PAGE_EXECUTE_READWRITE ||
            baseProt == NT::PAGE_EXECUTE_WRITECOPY) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        } else {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    // Create section handle
    SectionData secData{};
    secData.name       = std::move(sectionName);
    secData.maxSize    = maxSize;
    secData.protection = baseProt;
    secData.mappedBase = 0;
    secData.mappedSize = 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Section, secData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

bool HandleCreateFileMappingA(APIContext& ctx) {
    return CreateFileMappingImpl(ctx, false);
}

bool HandleCreateFileMappingW(APIContext& ctx) {
    return CreateFileMappingImpl(ctx, true);
}

// ============================================================================
// OpenFileMappingA/W
// ============================================================================
// Args: dwDesiredAccess (0), bInheritHandle (1), lpName (2)
// Returns: HANDLE or NULL.

static bool OpenFileMappingImpl(APIContext& ctx, bool isWide) {
    const auto dwDesiredAccess = ctx.GetArg32(0);
    const auto bInheritHandle  = ctx.GetArg32(1);
    const auto lpName          = ctx.GetArgPtr(2);

    (void)dwDesiredAccess;
    (void)bInheritHandle;

    if (lpName == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    std::wstring sectionName;
    if (isWide) {
        sectionName = ctx.ReadWideString(lpName, 512);
    } else {
        std::string ansiName = ctx.ReadAnsiString(lpName, 512);
        sectionName = std::wstring(ansiName.begin(), ansiName.end());
    }

    // In emulation, opening a named section always "succeeds" with a new handle
    // to allow the malware to continue along its execution path.
    SectionData secData{};
    secData.name       = std::move(sectionName);
    secData.maxSize    = kDefaultMapSize;
    secData.protection = NT::PAGE_READWRITE;
    secData.mappedBase = 0;
    secData.mappedSize = 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Section, secData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

bool HandleOpenFileMappingA(APIContext& ctx) {
    return OpenFileMappingImpl(ctx, false);
}

bool HandleOpenFileMappingW(APIContext& ctx) {
    return OpenFileMappingImpl(ctx, true);
}

// ============================================================================
// MapViewOfFile
// ============================================================================
// Args: hFileMappingObject (0), dwDesiredAccess (1),
//       dwFileOffsetHigh (2), dwFileOffsetLow (3), dwNumberOfBytesToMap (4)
// Returns: LPVOID base address of the mapped view, or NULL on failure.

bool HandleMapViewOfFile(APIContext& ctx) {
    const auto hMapping        = ctx.GetArg(0);
    const auto dwDesiredAccess = ctx.GetArg32(1);
    const auto dwOffsetHigh    = ctx.GetArg32(2);
    const auto dwOffsetLow     = ctx.GetArg32(3);
    auto       dwNumBytes      = ctx.GetArg(4);

    // Look up the section handle
    auto entry = ctx.Handles().Lookup(hMapping, HandleType::Section);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    const auto* secData = std::get_if<SectionData>(&entry->data);
    if (!secData) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // If dwNumBytes is 0, map the entire section
    if (dwNumBytes == 0) {
        dwNumBytes = secData->maxSize;
    }
    if (dwNumBytes > kMaxMappingSize) {
        dwNumBytes = kMaxMappingSize;
    }

    (void)dwOffsetHigh;
    (void)dwOffsetLow;

    // Determine memory protection from desired access
    MemProt prot = MapAccessToMemProt(dwDesiredAccess);

    // Mapping with execute permission outside the PE loader path is a classic
    // DEP-bypass / shellcode-loader primitive. RWX is the strongest signal.
    if ((dwDesiredAccess & FILE_MAP_EXECUTE) != 0) {
        if ((dwDesiredAccess & FILE_MAP_WRITE) != 0) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        } else {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    // Allocate guest memory for the mapped view
    GuestSize alignedSize = AlignUp(dwNumBytes, kPageSize);
    auto result = ctx.Memory().Allocate(0, alignedSize, prot);
    if (!result.has_value()) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    GuestAddress mappedBase = *result;

    // Track the mapped view for UnmapViewOfFile
    s_mappedViews[mappedBase] = alignedSize;

    // Update the section handle with mapped address info
    ctx.Handles().Modify<SectionData>(hMapping, [mappedBase, alignedSize](SectionData& sd) {
        sd.mappedBase = mappedBase;
        sd.mappedSize = alignedSize;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(mappedBase);
    return true;
}

// ============================================================================
// MapViewOfFileEx — Same as MapViewOfFile with preferred base address
// ============================================================================
// Args: hFileMappingObject (0), dwDesiredAccess (1),
//       dwFileOffsetHigh (2), dwFileOffsetLow (3),
//       dwNumberOfBytesToMap (4), lpBaseAddress (5)
// Returns: LPVOID base address or NULL.

bool HandleMapViewOfFileEx(APIContext& ctx) {
    const auto hMapping        = ctx.GetArg(0);
    const auto dwDesiredAccess = ctx.GetArg32(1);
    const auto dwOffsetHigh    = ctx.GetArg32(2);
    const auto dwOffsetLow     = ctx.GetArg32(3);
    auto       dwNumBytes      = ctx.GetArg(4);
    const auto lpBaseAddress   = ctx.GetArgPtr(5);

    (void)dwOffsetHigh;
    (void)dwOffsetLow;

    auto entry = ctx.Handles().Lookup(hMapping, HandleType::Section);
    if (!entry.has_value()) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    const auto* secData = std::get_if<SectionData>(&entry->data);
    if (!secData) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    if (dwNumBytes == 0) {
        dwNumBytes = secData->maxSize;
    }
    if (dwNumBytes > kMaxMappingSize) {
        dwNumBytes = kMaxMappingSize;
    }

    MemProt prot = MapAccessToMemProt(dwDesiredAccess);
    GuestSize alignedSize = AlignUp(dwNumBytes, kPageSize);

    // Same CodeInjection / SuspiciousAPI wiring as MapViewOfFile — RWX or
    // executable mapping is the DEP-bypass primitive.
    if ((dwDesiredAccess & FILE_MAP_EXECUTE) != 0) {
        if ((dwDesiredAccess & FILE_MAP_WRITE) != 0) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        } else {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    // Try preferred base address first, fall back to any address
    auto result = ctx.Memory().Allocate(lpBaseAddress, alignedSize, prot);
    if (!result.has_value() && lpBaseAddress != 0) {
        result = ctx.Memory().Allocate(0, alignedSize, prot);
    }

    if (!result.has_value()) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    GuestAddress mappedBase = *result;
    s_mappedViews[mappedBase] = alignedSize;

    ctx.Handles().Modify<SectionData>(hMapping, [mappedBase, alignedSize](SectionData& sd) {
        sd.mappedBase = mappedBase;
        sd.mappedSize = alignedSize;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(mappedBase);
    return true;
}

// ============================================================================
// UnmapViewOfFile
// ============================================================================
// Args: lpBaseAddress (0)
// Returns: BOOL — nonzero on success.

bool HandleUnmapViewOfFile(APIContext& ctx) {
    const auto lpBaseAddress = ctx.GetArgPtr(0);

    if (lpBaseAddress == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto it = s_mappedViews.find(lpBaseAddress);
    if (it != s_mappedViews.end()) {
        ctx.Memory().Free(lpBaseAddress, it->second);
        s_mappedViews.erase(it);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// FlushViewOfFile — No-op in emulation
// ============================================================================
// Args: lpBaseAddress (0), dwNumberOfBytesToFlush (1)
// Returns: BOOL — nonzero on success.

bool HandleFlushViewOfFile(APIContext& ctx) {
    const auto lpBaseAddress = ctx.GetArgPtr(0);

    if (lpBaseAddress == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterFileMappingAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "CreateFileMappingA",
          HandleCreateFileMappingA, 6, false },
        { "kernel32.dll", "CreateFileMappingW",
          HandleCreateFileMappingW, 6, false },
        { "kernel32.dll", "OpenFileMappingA",
          HandleOpenFileMappingA, 3, false },
        { "kernel32.dll", "OpenFileMappingW",
          HandleOpenFileMappingW, 3, false },
        { "kernel32.dll", "MapViewOfFile",
          HandleMapViewOfFile, 5, false },
        { "kernel32.dll", "MapViewOfFileEx",
          HandleMapViewOfFileEx, 6, false },
        { "kernel32.dll", "UnmapViewOfFile",
          HandleUnmapViewOfFile, 1, false },
        { "kernel32.dll", "FlushViewOfFile",
          HandleFlushViewOfFile, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
