/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * MemoryAPI.cpp — Kernel32 memory management API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory / HandleTable, and writes results
 * back to guest memory pointers. No host OS calls are made.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "MemoryAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <mutex>

// DESIGN: the VirtualMemory / APIContext write helpers are [[nodiscard]] because
// a partial write almost always means guest corruption. In MemoryAPI the guest
// has already been told the operation succeeded (we set the return/last-error
// before the MBI or byte-count writeback), and a failed output write is a
// non-fatal guest-side access violation the guest's own code must cope with.
// We therefore intentionally discard these return codes and scope the warning
// suppression tightly to this translation unit.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint64_t kMaxAllocationSize = 256ULL * 1024 * 1024;
static constexpr uint64_t kMaxBufferSize     = 16ULL * 1024 * 1024;
static constexpr uint64_t kMaxHeapBlockSize  = 64ULL * 1024 * 1024;
static constexpr uint32_t kDefaultHeapSize   = 4 * 1024 * 1024;

// Win32 MEMORY_BASIC_INFORMATION constants
static constexpr uint32_t kMemBasicInfoSize64 = 0x30; // 48 bytes
static constexpr uint32_t kMemStateFree       = 0x00010000;
static constexpr uint32_t kMemStateReserve    = 0x00002000;
static constexpr uint32_t kMemStateCommit     = 0x00001000;
static constexpr uint32_t kMemTypePrivate     = 0x00020000;

// Heap flags
static constexpr uint32_t HEAP_ZERO_MEMORY      = 0x00000008;
static constexpr uint32_t HEAP_REALLOC_IN_PLACE  = 0x00000010;
static constexpr uint32_t HEAP_GENERATE_EXCEPTIONS = 0x00000004;

// GMEM/LMEM flags
static constexpr uint32_t GMEM_FIXED    = 0x0000;
static constexpr uint32_t GMEM_ZEROINIT = 0x0040;
static constexpr uint32_t LMEM_FIXED    = 0x0000;
static constexpr uint32_t LMEM_ZEROINIT = 0x0040;

// Our emulated process PID
static constexpr uint32_t kOurPid = 4444;

// ============================================================================
// Heap tracking — per-session state
// ============================================================================

static std::unordered_map<GuestAddress, uint64_t> s_heapBlocks;
static GuestAddress s_defaultHeap = 0x00000001'00000000;
static std::mutex s_heapMutex;

// ============================================================================
// Helpers
// ============================================================================

static bool IsSelfProcess(GuestHandle handle, const HandleTable& handles) noexcept {
    if (handle == kCurrentProcess || handle == kNullHandle) {
        return true;
    }
    auto entry = handles.Lookup(handle, HandleType::Process);
    if (entry.has_value()) {
        auto* pd = std::get_if<ProcessHandleData>(&entry->data);
        if (pd && pd->isSelf) return true;
    }
    return false;
}

// DESIGN: centralised "is this win32 protection mask executable" predicate.
// Any handler that accepts a PAGE_* mask and could stage shellcode must use
// this to decide whether to raise CodeInjection. Strips reserved modifier
// bits (SEC_IMAGE/GUARD/NOCACHE/WRITECOMBINE) before comparing.
[[nodiscard]] static bool IsExecutableWin32Prot(uint32_t flProtect) noexcept {
    const uint32_t base = flProtect & 0x000000FFu;
    return base == NT::PAGE_EXECUTE ||
           base == NT::PAGE_EXECUTE_READ ||
           base == NT::PAGE_EXECUTE_READWRITE ||
           base == NT::PAGE_EXECUTE_WRITECOPY;
}

[[nodiscard]] static bool IsRWXWin32Prot(uint32_t flProtect) noexcept {
    const uint32_t base = flProtect & 0x000000FFu;
    return base == NT::PAGE_EXECUTE_READWRITE ||
           base == NT::PAGE_EXECUTE_WRITECOPY;
}

// ============================================================================
// VirtualAlloc — lpAddress(0), dwSize(1), flAllocationType(2), flProtect(3)
// ============================================================================

bool HandleVirtualAlloc(APIContext& ctx) {
    const auto lpAddress       = ctx.GetArgPtr(0);
    auto       dwSize          = ctx.GetArg(1);
    const auto flAllocType     = ctx.GetArg32(2);
    const auto flProtect       = ctx.GetArg32(3);

    if (dwSize == 0 || dwSize > kMaxAllocationSize) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    const uint64_t alignedSize = AlignUp(dwSize, kPageSize);
    const MemProt prot = Win32ProtToMemProt(flProtect);

    const bool doReserve = (flAllocType & NT::MEM_RESERVE) != 0;
    const bool doCommit  = (flAllocType & NT::MEM_COMMIT)  != 0;

    if (!doReserve && !doCommit) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    std::optional<GuestAddress> result;

    if (doReserve && doCommit) {
        result = mem.Allocate(lpAddress, alignedSize, prot);
    } else if (doReserve) {
        result = mem.Allocate(lpAddress, alignedSize, MemProt::None);
    } else {
        // Commit-only on already-reserved memory
        if (lpAddress == 0) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
        if (!mem.Protect(lpAddress, alignedSize, prot)) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
        result = lpAddress;
    }

    if (!result.has_value()) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // IOC: private RWX / executable page allocation — T1055.002 shellcode
    // staging primitive used by virtually every loader. Committed executable
    // private memory (no image/section backing) is not something normal
    // applications do; even JITs go through dedicated CreateFileMapping
    // flows or have gone to RX-only pages since CET shadow stacks shipped.
    if (doCommit && IsExecutableWin32Prot(flProtect)) {
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        if (IsRWXWin32Prot(flProtect)) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(result.value());
    return true;
}

// ============================================================================
// VirtualAllocEx — hProcess(0), lpAddress(1), dwSize(2), flAllocationType(3),
//                  flProtect(4)
// ============================================================================

bool HandleVirtualAllocEx(APIContext& ctx) {
    const auto hProcess        = ctx.GetArg(0);
    const auto lpAddress       = ctx.GetArgPtr(1);
    auto       dwSize          = ctx.GetArg(2);
    const auto flAllocType     = ctx.GetArg32(3);
    const auto flProtect       = ctx.GetArg32(4);

    if (IsSelfProcess(hProcess, ctx.Handles())) {
        // Re-route to self-process path
        if (dwSize == 0 || dwSize > kMaxAllocationSize) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }

        const uint64_t alignedSize = AlignUp(dwSize, kPageSize);
        const MemProt prot = Win32ProtToMemProt(flProtect);

        const bool doReserve = (flAllocType & NT::MEM_RESERVE) != 0;
        const bool doCommit  = (flAllocType & NT::MEM_COMMIT)  != 0;

        if (!doReserve && !doCommit) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }

        auto& mem = ctx.Memory();
        std::optional<GuestAddress> result;

        if (doReserve && doCommit) {
            result = mem.Allocate(lpAddress, alignedSize, prot);
        } else if (doReserve) {
            result = mem.Allocate(lpAddress, alignedSize, MemProt::None);
        } else {
            if (lpAddress == 0) {
                ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
                return true;
            }
            if (!mem.Protect(lpAddress, alignedSize, prot)) {
                ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
                return true;
            }
            result = lpAddress;
        }

        if (!result.has_value()) {
            ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
            return true;
        }

        // IOC mirrors VirtualAlloc self-path: executable private allocation.
        if (doCommit && IsExecutableWin32Prot(flProtect)) {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
            if (IsRWXWin32Prot(flProtect)) {
                ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
            }
        }

        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturn(result.value());
        return true;
    }

    // Remote process allocation — defining T1055.002 (Process Injection:
    // Portable Executable Injection) / T1055 primitive used by every remote
    // injector from CreateRemoteThread-shellcode to process hollowing. Raise
    // ProcessInjection unconditionally on the remote path, and CodeInjection
    // when the allocation is requested with executable rights (shellcode
    // destination) — benign inter-process helpers use RW-only shared memory.
    ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    if (IsExecutableWin32Prot(flProtect)) {
        ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
    }

    // Remote process allocation — strong code injection signal
    // Return a fake address but flag the behavior
    const uint64_t fakeAddr = 0x00007FFE'10000000ULL;
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(fakeAddr);
    return true;
}

// ============================================================================
// VirtualFree — lpAddress(0), dwSize(1), dwFreeType(2)
// ============================================================================

bool HandleVirtualFree(APIContext& ctx) {
    const auto lpAddress = ctx.GetArgPtr(0);
    const auto dwSize    = ctx.GetArg(1);
    const auto dwFreeType = ctx.GetArg32(2);

    if (lpAddress == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    if (dwFreeType & NT::MEM_RELEASE) {
        // MEM_RELEASE: dwSize must be 0 per Windows semantics
        const uint64_t releaseSize = (dwSize != 0) ? AlignUp(dwSize, kPageSize) : kPageSize;
        if (!mem.Free(lpAddress, releaseSize)) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
    } else if (dwFreeType & NT::MEM_DECOMMIT) {
        if (dwSize == 0) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
        const uint64_t alignedSize = AlignUp(dwSize, kPageSize);
        mem.Protect(lpAddress, alignedSize, MemProt::None);
    } else {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// VirtualFreeEx — hProcess(0), lpAddress(1), dwSize(2), dwFreeType(3)
// ============================================================================

bool HandleVirtualFreeEx(APIContext& ctx) {
    const auto hProcess  = ctx.GetArg(0);
    const auto lpAddress = ctx.GetArgPtr(1);
    const auto dwSize    = ctx.GetArg(2);
    const auto dwFreeType = ctx.GetArg32(3);

    if (!IsSelfProcess(hProcess, ctx.Handles())) {
        // Remote free — suspicious but return success
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnBool(true);
        return true;
    }

    if (lpAddress == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    if (dwFreeType & NT::MEM_RELEASE) {
        const uint64_t releaseSize = (dwSize != 0) ? AlignUp(dwSize, kPageSize) : kPageSize;
        if (!mem.Free(lpAddress, releaseSize)) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
    } else if (dwFreeType & NT::MEM_DECOMMIT) {
        if (dwSize == 0) {
            ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
            return true;
        }
        const uint64_t alignedSize = AlignUp(dwSize, kPageSize);
        mem.Protect(lpAddress, alignedSize, MemProt::None);
    } else {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// VirtualProtect — lpAddress(0), dwSize(1), flNewProtect(2), lpflOldProtect(3)
// ============================================================================

bool HandleVirtualProtect(APIContext& ctx) {
    const auto lpAddress     = ctx.GetArgPtr(0);
    const auto dwSize        = ctx.GetArg(1);
    const auto flNewProtect  = ctx.GetArg32(2);
    const auto lpflOldProt   = ctx.GetArgPtr(3);

    if (lpAddress == 0 || dwSize == 0 || dwSize > kMaxAllocationSize) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (lpflOldProt == 0) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    auto& mem = ctx.Memory();
    const GuestAddress alignedBase = PageBase(lpAddress);
    const uint64_t alignedSize = AlignUp(dwSize, kPageSize);

    // Capture old protection
    auto oldProtOpt = mem.GetProtection(alignedBase);
    uint32_t oldWin32Prot = NT::PAGE_NOACCESS;
    if (oldProtOpt.has_value()) {
        oldWin32Prot = MemProtToWin32(oldProtOpt.value());
    }

    // Apply new protection
    const MemProt newProt = Win32ProtToMemProt(flNewProtect);
    if (!mem.Protect(alignedBase, alignedSize, newProt)) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Write old protection to output pointer
    mem.WriteU32(lpflOldProt, oldWin32Prot);

    // IOC: transition to an executable mapping — T1055.009 (Proc Memory)
    // "AddressOfNtdllLdrLoadDll-style" JIT loader, shellcode unpacker,
    // or Cobalt Strike BeaconDLL flip of a PAGE_READWRITE staging area to
    // PAGE_EXECUTE_READ(/WRITE) once the payload is decoded in place.
    // Benign code paths (JIT, .NET ReadyToRun) use dedicated memory APIs
    // (CreateFileMapping SEC_IMAGE / VirtualAlloc2 with MEM_EXECUTE_OPTIONS)
    // rather than post-hoc protection flips on anonymous private memory.
    if (IsExecutableWin32Prot(flNewProtect)) {
        const bool wasNonExec = oldProtOpt.has_value() &&
                                !HasProt(oldProtOpt.value(), MemProt::Execute);
        if (wasNonExec || IsRWXWin32Prot(flNewProtect)) {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// VirtualProtectEx — hProcess(0), lpAddress(1), dwSize(2), flNewProtect(3),
//                    lpflOldProtect(4)
// ============================================================================

bool HandleVirtualProtectEx(APIContext& ctx) {
    const auto hProcess      = ctx.GetArg(0);
    const auto lpAddress     = ctx.GetArgPtr(1);
    const auto dwSize        = ctx.GetArg(2);
    const auto flNewProtect  = ctx.GetArg32(3);
    const auto lpflOldProt   = ctx.GetArgPtr(4);

    if (!IsSelfProcess(hProcess, ctx.Handles())) {
        // Remote process protection change — T1055 (Process Injection):
        // the "flip staging buffer to RX" step of every hollowing / PE-
        // injection chain (the sequence is typically VirtualAllocEx →
        // WriteProcessMemory → VirtualProtectEx → CreateRemoteThread).
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        if (IsExecutableWin32Prot(flNewProtect)) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        }

        if (lpflOldProt != 0) {
            ctx.Memory().WriteU32(lpflOldProt, NT::PAGE_READWRITE);
        }
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnBool(true);
        return true;
    }

    if (lpAddress == 0 || dwSize == 0 || dwSize > kMaxAllocationSize) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (lpflOldProt == 0) {
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    auto& mem = ctx.Memory();
    const GuestAddress alignedBase = PageBase(lpAddress);
    const uint64_t alignedSize = AlignUp(dwSize, kPageSize);

    auto oldProtOpt = mem.GetProtection(alignedBase);
    uint32_t oldWin32Prot = NT::PAGE_NOACCESS;
    if (oldProtOpt.has_value()) {
        oldWin32Prot = MemProtToWin32(oldProtOpt.value());
    }

    const MemProt newProt = Win32ProtToMemProt(flNewProtect);
    if (!mem.Protect(alignedBase, alignedSize, newProt)) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    mem.WriteU32(lpflOldProt, oldWin32Prot);

    // Same IOC logic as VirtualProtect for the self-process path.
    if (IsExecutableWin32Prot(flNewProtect)) {
        const bool wasNonExec = oldProtOpt.has_value() &&
                                !HasProt(oldProtOpt.value(), MemProt::Execute);
        if (wasNonExec || IsRWXWin32Prot(flNewProtect)) {
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// VirtualQuery — lpAddress(0), lpBuffer(1), dwLength(2)
// ============================================================================
// Fills MEMORY_BASIC_INFORMATION (x64, 48 bytes):
//   +0x00 BaseAddress(8), +0x08 AllocationBase(8),
//   +0x10 AllocationProtect(4), +0x14 pad(2)+pad(2),
//   +0x18 RegionSize(8), +0x20 State(4), +0x24 Protect(4),
//   +0x28 Type(4), +0x2C pad(4)

bool HandleVirtualQuery(APIContext& ctx) {
    const auto lpAddress = ctx.GetArgPtr(0);
    const auto lpBuffer  = ctx.GetArgPtr(1);
    const auto dwLength  = ctx.GetArg(2);

    if (lpBuffer == 0 || dwLength < kMemBasicInfoSize64) {
        ctx.SetReturn(0);
        return true;
    }

    auto& mem = ctx.Memory();
    const GuestAddress pageAligned = PageBase(lpAddress);
    auto protOpt = mem.GetProtection(pageAligned);
    const bool accessible = protOpt.has_value();

    uint8_t mbi[kMemBasicInfoSize64] = {};

    // BaseAddress
    std::memcpy(mbi + 0x00, &pageAligned, 8);
    // AllocationBase
    std::memcpy(mbi + 0x08, &pageAligned, 8);

    if (accessible) {
        const MemProt prot = protOpt.value();
        const uint32_t win32AllocProt = MemProtToWin32(prot);
        const uint32_t win32CurProt   = win32AllocProt;
        const uint64_t regionSize     = kPageSize;
        const uint32_t state          = kMemStateCommit;
        const uint32_t memType        = kMemTypePrivate;

        std::memcpy(mbi + 0x10, &win32AllocProt, 4);
        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
        std::memcpy(mbi + 0x24, &win32CurProt, 4);
        std::memcpy(mbi + 0x28, &memType, 4);
    } else {
        const uint64_t regionSize = kPageSize;
        const uint32_t state      = kMemStateFree;

        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
    }

    if (mem.Write(lpBuffer, mbi, kMemBasicInfoSize64) != ErrorCode::Success) {
        ctx.SetReturn(0);
        return true;
    }

    ctx.SetReturn(kMemBasicInfoSize64);
    return true;
}

// ============================================================================
// VirtualQueryEx — hProcess(0), lpAddress(1), lpBuffer(2), dwLength(3)
// ============================================================================

bool HandleVirtualQueryEx(APIContext& ctx) {
    const auto hProcess  = ctx.GetArg(0);
    const auto lpAddress = ctx.GetArgPtr(1);
    const auto lpBuffer  = ctx.GetArgPtr(2);
    const auto dwLength  = ctx.GetArg(3);

    if (!IsSelfProcess(hProcess, ctx.Handles())) {
        // Remote query — return a plausible committed private region
        if (lpBuffer == 0 || dwLength < kMemBasicInfoSize64) {
            ctx.SetReturn(0);
            return true;
        }

        uint8_t mbi[kMemBasicInfoSize64] = {};
        const GuestAddress pageAligned = PageBase(lpAddress);
        const uint32_t allocProt  = NT::PAGE_READWRITE;
        const uint64_t regionSize = kPageSize;
        const uint32_t state      = kMemStateCommit;
        const uint32_t memType    = kMemTypePrivate;

        std::memcpy(mbi + 0x00, &pageAligned, 8);
        std::memcpy(mbi + 0x08, &pageAligned, 8);
        std::memcpy(mbi + 0x10, &allocProt, 4);
        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
        std::memcpy(mbi + 0x24, &allocProt, 4);
        std::memcpy(mbi + 0x28, &memType, 4);

        ctx.Memory().Write(lpBuffer, mbi, kMemBasicInfoSize64);
        ctx.SetReturn(kMemBasicInfoSize64);
        return true;
    }

    // Self process — delegate to same logic as VirtualQuery
    if (lpBuffer == 0 || dwLength < kMemBasicInfoSize64) {
        ctx.SetReturn(0);
        return true;
    }

    auto& mem = ctx.Memory();
    const GuestAddress pageAligned = PageBase(lpAddress);
    auto protOpt = mem.GetProtection(pageAligned);
    const bool accessible = protOpt.has_value();

    uint8_t mbi[kMemBasicInfoSize64] = {};

    std::memcpy(mbi + 0x00, &pageAligned, 8);
    std::memcpy(mbi + 0x08, &pageAligned, 8);

    if (accessible) {
        const MemProt prot = protOpt.value();
        const uint32_t win32AllocProt = MemProtToWin32(prot);
        const uint32_t win32CurProt   = win32AllocProt;
        const uint64_t regionSize     = kPageSize;
        const uint32_t state          = kMemStateCommit;
        const uint32_t memType        = kMemTypePrivate;

        std::memcpy(mbi + 0x10, &win32AllocProt, 4);
        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
        std::memcpy(mbi + 0x24, &win32CurProt, 4);
        std::memcpy(mbi + 0x28, &memType, 4);
    } else {
        const uint64_t regionSize = kPageSize;
        const uint32_t state      = kMemStateFree;

        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
    }

    if (mem.Write(lpBuffer, mbi, kMemBasicInfoSize64) != ErrorCode::Success) {
        ctx.SetReturn(0);
        return true;
    }

    ctx.SetReturn(kMemBasicInfoSize64);
    return true;
}

// ============================================================================
// ReadProcessMemory — hProcess(0), lpBaseAddress(1), lpBuffer(2),
//                     nSize(3), lpNumberOfBytesRead(4)
// ============================================================================

bool HandleReadProcessMemory(APIContext& ctx) {
    const auto hProcess        = ctx.GetArg(0);
    const auto lpBaseAddress   = ctx.GetArgPtr(1);
    const auto lpBuffer        = ctx.GetArgPtr(2);
    auto       nSize           = ctx.GetArg(3);
    const auto lpBytesReadPtr  = ctx.GetArgPtr(4);

    if (!IsSelfProcess(hProcess, ctx.Handles())) {
        // Remote process read — T1003 (OS Credential Dumping) when the
        // caller attempts to read from LSASS-like contexts, or the readout
        // half of a process-hollowing reconnaissance pass. Flag as
        // CredentialAccess + AntiAnalysis and deny the read.
        ctx.AddBehaviorFlag(BehaviorFlag::CredentialAccess);
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

        // Remote process read — flag and fail
        if (lpBytesReadPtr != 0) {
            ctx.Memory().WriteU64(lpBytesReadPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    if (lpBaseAddress == 0 || lpBuffer == 0 || nSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    nSize = std::min(nSize, kMaxBufferSize);
    auto& mem = ctx.Memory();

    std::vector<uint8_t> staging(static_cast<size_t>(nSize));

    auto readErr = mem.Read(lpBaseAddress, staging.data(),
                            static_cast<uint32_t>(nSize));
    if (readErr != ErrorCode::Success) {
        if (lpBytesReadPtr != 0) {
            mem.WriteU64(lpBytesReadPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    auto writeErr = mem.Write(lpBuffer, staging.data(),
                              static_cast<uint32_t>(nSize));
    if (writeErr != ErrorCode::Success) {
        if (lpBytesReadPtr != 0) {
            mem.WriteU64(lpBytesReadPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    if (lpBytesReadPtr != 0) {
        mem.WriteU64(lpBytesReadPtr, nSize);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WriteProcessMemory — hProcess(0), lpBaseAddress(1), lpBuffer(2),
//                      nSize(3), lpNumberOfBytesWritten(4)
// ============================================================================

bool HandleWriteProcessMemory(APIContext& ctx) {
    const auto hProcess           = ctx.GetArg(0);
    const auto lpBaseAddress      = ctx.GetArgPtr(1);
    const auto lpBuffer           = ctx.GetArgPtr(2);
    auto       nSize              = ctx.GetArg(3);
    const auto lpBytesWrittenPtr  = ctx.GetArgPtr(4);

    if (!IsSelfProcess(hProcess, ctx.Handles())) {
        // Remote process write — canonical T1055.002 (Process Injection:
        // PE Injection) / T1055 write-half primitive. This is the step
        // that actually copies shellcode or an unpacked PE image into the
        // victim's address space. Raise ProcessInjection+CodeInjection
        // unconditionally on the remote path.
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

        // Remote process write — code injection signal
        if (lpBytesWrittenPtr != 0) {
            ctx.Memory().WriteU64(lpBytesWrittenPtr, nSize);
        }
        ctx.SetLastError(Win32::ERROR_SUCCESS);
        ctx.SetReturnBool(true);
        return true;
    }

    if (lpBaseAddress == 0 || lpBuffer == 0 || nSize == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    nSize = std::min(nSize, kMaxBufferSize);
    auto& mem = ctx.Memory();

    std::vector<uint8_t> staging(static_cast<size_t>(nSize));

    auto readErr = mem.Read(lpBuffer, staging.data(),
                            static_cast<uint32_t>(nSize));
    if (readErr != ErrorCode::Success) {
        if (lpBytesWrittenPtr != 0) {
            mem.WriteU64(lpBytesWrittenPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    auto writeErr = mem.Write(lpBaseAddress, staging.data(),
                              static_cast<uint32_t>(nSize));
    if (writeErr != ErrorCode::Success) {
        if (lpBytesWrittenPtr != 0) {
            mem.WriteU64(lpBytesWrittenPtr, 0);
        }
        ctx.FailWithError(Win32::ERROR_NOACCESS);
        return true;
    }

    if (lpBytesWrittenPtr != 0) {
        mem.WriteU64(lpBytesWrittenPtr, nSize);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HeapCreate — flOptions(0), dwInitialSize(1), dwMaximumSize(2)
// ============================================================================

bool HandleHeapCreate(APIContext& ctx) {
    auto dwInitialSize  = ctx.GetArg(1);
    // arg2 = dwMaximumSize (ignored in emulation — all heaps are growable)

    if (dwInitialSize == 0) {
        dwInitialSize = kDefaultHeapSize;
    }
    dwInitialSize = std::min(dwInitialSize, kMaxAllocationSize);

    const uint64_t alignedSize = AlignUp(dwInitialSize, kPageSize);

    auto& mem = ctx.Memory();
    auto result = mem.Allocate(0, alignedSize, MemProt::RW);
    if (!result.has_value()) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // The heap handle IS the base address of the heap region
    const GuestAddress heapHandle = result.value();

    {
        std::lock_guard lock(s_heapMutex);
        s_heapBlocks[heapHandle] = alignedSize;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(heapHandle);
    return true;
}

// ============================================================================
// HeapDestroy — hHeap(0)
// ============================================================================

bool HandleHeapDestroy(APIContext& ctx) {
    const auto hHeap = ctx.GetArg(0);

    if (hHeap == s_defaultHeap) {
        // Cannot destroy the default process heap
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    {
        std::lock_guard lock(s_heapMutex);
        auto it = s_heapBlocks.find(hHeap);
        if (it != s_heapBlocks.end()) {
            ctx.Memory().Free(hHeap, it->second);
            s_heapBlocks.erase(it);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HeapAlloc — hHeap(0), dwFlags(1), dwBytes(2)
// ============================================================================

bool HandleHeapAlloc(APIContext& ctx) {
    const auto dwFlags = ctx.GetArg32(1);
    auto       dwBytes = ctx.GetArg(2);

    if (dwBytes == 0) {
        dwBytes = 1; // Win32: HeapAlloc(0) returns a valid pointer
    }

    if (dwBytes > kMaxHeapBlockSize) {
        ctx.SetReturn(0);
        return true;
    }

    const uint64_t alignedSize = AlignUp(dwBytes, 16); // 16-byte aligned blocks

    auto& mem = ctx.Memory();
    auto result = mem.Allocate(0, AlignUp(alignedSize, kPageSize), MemProt::RW);
    if (!result.has_value()) {
        if (dwFlags & HEAP_GENERATE_EXCEPTIONS) {
            ctx.SetReturn(0);
        } else {
            ctx.SetReturn(0);
        }
        return true;
    }

    const GuestAddress blockAddr = result.value();

    if (dwFlags & HEAP_ZERO_MEMORY) {
        // VirtualMemory::Allocate returns zeroed pages, so this is implicit
    }

    {
        std::lock_guard lock(s_heapMutex);
        s_heapBlocks[blockAddr] = alignedSize;
    }

    ctx.SetReturn(blockAddr);
    return true;
}

// ============================================================================
// HeapFree — hHeap(0), dwFlags(1), lpMem(2)
// ============================================================================

bool HandleHeapFree(APIContext& ctx) {
    const auto lpMem = ctx.GetArgPtr(2);

    if (lpMem == 0) {
        // Freeing NULL is a no-op per Win32 spec
        ctx.SetReturnBool(true);
        return true;
    }

    uint64_t blockSize = 0;
    {
        std::lock_guard lock(s_heapMutex);
        auto it = s_heapBlocks.find(lpMem);
        if (it != s_heapBlocks.end()) {
            blockSize = it->second;
            s_heapBlocks.erase(it);
        }
    }

    if (blockSize > 0) {
        ctx.Memory().Free(lpMem, AlignUp(blockSize, kPageSize));
    }

    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HeapReAlloc — hHeap(0), dwFlags(1), lpMem(2), dwBytes(3)
// ============================================================================

bool HandleHeapReAlloc(APIContext& ctx) {
    const auto dwFlags = ctx.GetArg32(1);
    const auto lpMem   = ctx.GetArgPtr(2);
    auto       dwBytes = ctx.GetArg(3);

    if (dwBytes > kMaxHeapBlockSize) {
        ctx.SetReturn(0);
        return true;
    }

    if (dwBytes == 0) {
        dwBytes = 1;
    }

    const uint64_t newAlignedSize = AlignUp(dwBytes, 16);
    auto& mem = ctx.Memory();

    // Find existing block
    uint64_t oldBlockSize = 0;
    {
        std::lock_guard lock(s_heapMutex);
        auto it = s_heapBlocks.find(lpMem);
        if (it != s_heapBlocks.end()) {
            oldBlockSize = it->second;
        }
    }

    if (oldBlockSize == 0 && lpMem != 0) {
        // Unknown block — cannot realloc
        ctx.SetReturn(0);
        return true;
    }

    // If the new size fits in the old allocation, reuse
    if (newAlignedSize <= AlignUp(oldBlockSize, kPageSize) && lpMem != 0) {
        std::lock_guard lock(s_heapMutex);
        s_heapBlocks[lpMem] = newAlignedSize;
        ctx.SetReturn(lpMem);
        return true;
    }

    // Allocate new block
    auto result = mem.Allocate(0, AlignUp(newAlignedSize, kPageSize), MemProt::RW);
    if (!result.has_value()) {
        ctx.SetReturn(0);
        return true;
    }

    const GuestAddress newAddr = result.value();

    // Copy old data
    if (lpMem != 0 && oldBlockSize > 0) {
        const uint64_t copySize = std::min(oldBlockSize, newAlignedSize);
        std::vector<uint8_t> staging(static_cast<size_t>(copySize));
        if (mem.Read(lpMem, staging.data(), static_cast<uint32_t>(copySize)) == ErrorCode::Success) {
            mem.Write(newAddr, staging.data(), static_cast<uint32_t>(copySize));
        }

        // Free old block
        mem.Free(lpMem, AlignUp(oldBlockSize, kPageSize));
    }

    {
        std::lock_guard lock(s_heapMutex);
        if (lpMem != 0) {
            s_heapBlocks.erase(lpMem);
        }
        s_heapBlocks[newAddr] = newAlignedSize;
    }

    if (dwFlags & HEAP_ZERO_MEMORY) {
        // New pages are zeroed by VirtualMemory::Allocate
    }

    ctx.SetReturn(newAddr);
    return true;
}

// ============================================================================
// HeapSize — hHeap(0), dwFlags(1), lpMem(2)
// ============================================================================

bool HandleHeapSize(APIContext& ctx) {
    const auto lpMem = ctx.GetArgPtr(2);

    if (lpMem == 0) {
        ctx.SetReturn(static_cast<uint64_t>(-1));
        return true;
    }

    {
        std::lock_guard lock(s_heapMutex);
        auto it = s_heapBlocks.find(lpMem);
        if (it != s_heapBlocks.end()) {
            ctx.SetReturn(it->second);
            return true;
        }
    }

    // Unknown block
    ctx.SetReturn(static_cast<uint64_t>(-1));
    return true;
}

// ============================================================================
// GetProcessHeap — no arguments
// ============================================================================

bool HandleGetProcessHeap(APIContext& ctx) {
    ctx.SetReturnHandle(s_defaultHeap);
    return true;
}

// ============================================================================
// GlobalAlloc — uFlags(0), dwBytes(1)
// ============================================================================

bool HandleGlobalAlloc(APIContext& ctx) {
    const auto uFlags  = ctx.GetArg32(0);
    auto       dwBytes = ctx.GetArg(1);

    // DESIGN: GMEM_MOVEABLE (0x0002) returns a movable handle on real
    // Windows; the emulator models every allocation as FIXED — the guest
    // would have to call GlobalLock to dereference a moveable handle and
    // our shim already hands back a direct address. GMEM_ZEROINIT (0x0040)
    // is implicit because VirtualMemory::Allocate zero-fills. We still
    // consume uFlags here so /W4 does not flag it as unreferenced and so
    // future behavior wiring has a handle to attach to.
    (void)uFlags;

    if (dwBytes == 0) {
        dwBytes = 1;
    }

    if (dwBytes > kMaxHeapBlockSize) {
        ctx.SetReturn(0);
        return true;
    }

    const uint64_t alignedSize = AlignUp(dwBytes, kPageSize);
    auto& mem = ctx.Memory();

    auto result = mem.Allocate(0, alignedSize, MemProt::RW);
    if (!result.has_value()) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    const GuestAddress blockAddr = result.value();

    {
        std::lock_guard lock(s_heapMutex);
        s_heapBlocks[blockAddr] = dwBytes;
    }

    ctx.SetReturn(blockAddr);
    return true;
}

// ============================================================================
// GlobalFree — hMem(0)
// ============================================================================

bool HandleGlobalFree(APIContext& ctx) {
    const auto hMem = ctx.GetArgPtr(0);

    if (hMem == 0) {
        ctx.SetReturn(0);
        return true;
    }

    uint64_t blockSize = 0;
    {
        std::lock_guard lock(s_heapMutex);
        auto it = s_heapBlocks.find(hMem);
        if (it != s_heapBlocks.end()) {
            blockSize = it->second;
            s_heapBlocks.erase(it);
        }
    }

    if (blockSize > 0) {
        ctx.Memory().Free(hMem, AlignUp(blockSize, kPageSize));
    }

    ctx.SetReturn(0); // GlobalFree returns NULL on success
    return true;
}

// ============================================================================
// LocalAlloc — uFlags(0), uBytes(1)
// ============================================================================

bool HandleLocalAlloc(APIContext& ctx) {
    // LocalAlloc is functionally identical to GlobalAlloc in modern Windows
    return HandleGlobalAlloc(ctx);
}

// ============================================================================
// LocalFree — hMem(0)
// ============================================================================

bool HandleLocalFree(APIContext& ctx) {
    return HandleGlobalFree(ctx);
}

// ============================================================================
// Registration
// ============================================================================

void RegisterMemoryAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "VirtualAlloc",
          HandleVirtualAlloc, 4, true },
        { "kernel32.dll", "VirtualAllocEx",
          HandleVirtualAllocEx, 5, true },
        { "kernel32.dll", "VirtualFree",
          HandleVirtualFree, 3, true },
        { "kernel32.dll", "VirtualFreeEx",
          HandleVirtualFreeEx, 4, false },
        { "kernel32.dll", "VirtualProtect",
          HandleVirtualProtect, 4, true },
        { "kernel32.dll", "VirtualProtectEx",
          HandleVirtualProtectEx, 5, false },
        { "kernel32.dll", "VirtualQuery",
          HandleVirtualQuery, 3, false },
        { "kernel32.dll", "VirtualQueryEx",
          HandleVirtualQueryEx, 4, false },
        { "kernel32.dll", "ReadProcessMemory",
          HandleReadProcessMemory, 5, false },
        { "kernel32.dll", "WriteProcessMemory",
          HandleWriteProcessMemory, 5, false },
        { "kernel32.dll", "HeapCreate",
          HandleHeapCreate, 3, false },
        { "kernel32.dll", "HeapDestroy",
          HandleHeapDestroy, 1, false },
        { "kernel32.dll", "HeapAlloc",
          HandleHeapAlloc, 3, true },
        { "kernel32.dll", "HeapFree",
          HandleHeapFree, 3, true },
        { "kernel32.dll", "HeapReAlloc",
          HandleHeapReAlloc, 4, false },
        { "kernel32.dll", "HeapSize",
          HandleHeapSize, 3, false },
        { "kernel32.dll", "GetProcessHeap",
          HandleGetProcessHeap, 0, true },
        { "kernel32.dll", "GlobalAlloc",
          HandleGlobalAlloc, 2, false },
        { "kernel32.dll", "GlobalFree",
          HandleGlobalFree, 1, false },
        { "kernel32.dll", "LocalAlloc",
          HandleLocalAlloc, 2, false },
        { "kernel32.dll", "LocalFree",
          HandleLocalFree, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
