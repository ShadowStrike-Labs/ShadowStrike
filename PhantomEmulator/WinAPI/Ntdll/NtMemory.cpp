/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtMemory.cpp — Nt* virtual-memory and section syscall implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on VirtualMemory / HandleTable, and writes results
 * back to guest memory pointers. No host OS calls are made.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtMemory.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

// DESIGN: Guest writebacks via WriteU32/WriteU64 are [[nodiscard]] so the
// caller can detect guest-side AVs. Every target pointer here is either
// null-checked or proven valid by a size check above the write; a guest
// AV on writeback is a guest fault that the emulated code handles.
// Pragma is namespace-scoped; explicit guards and return-status semantics
// remain intact.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ntdll {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint64_t kMaxBufferSize     = 16ULL * 1024 * 1024; // 16 MB cap
static constexpr uint64_t kMaxAllocationSize = 256ULL * 1024 * 1024;

// Win32 MEM_* allocation state constants for MEMORY_BASIC_INFORMATION.State
static constexpr uint32_t kMemStateFree    = 0x00010000;
static constexpr uint32_t kMemStateReserve = 0x00002000;
static constexpr uint32_t kMemStateCommit  = 0x00001000;

// Win32 memory type constants for MEMORY_BASIC_INFORMATION.Type
static constexpr uint32_t kMemTypePrivate  = 0x00020000;
static constexpr uint32_t kMemTypeMapped   = 0x00040000;

// ============================================================================
// Helpers
// ============================================================================

static bool IsSelfProcess(uint64_t handle) noexcept {
    return handle == kCurrentProcess || handle == kNullHandle;
}

// Write IoStatusBlock: { NTSTATUS Status; ULONG_PTR Information; }
[[maybe_unused]] static void WriteIoStatus(VirtualMemory& mem, GuestAddress iosbAddr,
                          GuestNtStatus status, uint64_t info) noexcept {
    if (iosbAddr == 0) return;
    mem.WriteU32(iosbAddr, static_cast<uint32_t>(status));
    mem.WriteU64(iosbAddr + 8, info);
}

// ============================================================================
// NtAllocateVirtualMemory
// ============================================================================
// Args (x64): RCX=ProcessHandle, RDX=*BaseAddress, R8=ZeroBits,
//             R9=*RegionSize, [RSP+0x28]=AllocationType, [RSP+0x30]=Protect

bool HandleNtAllocateVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddrPtr   = ctx.GetArgPtr(1);
    // arg2 = ZeroBits (ignored in emulation)
    const auto regionSizePtr = ctx.GetArgPtr(3);
    const auto allocType     = ctx.GetArg32(4);
    const auto win32Prot     = ctx.GetArg32(5);

    if (!IsSelfProcess(processHandle)) {
        // IOC: T1055 Process Injection — allocating memory in a remote
        // process is the first stage of classic injection (VirtualAllocEx
        // equivalent). Emitted before the emulator refuses the call so
        // the behavior is captured even when the call "fails".
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::MemoryManipulation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (baseAddrPtr == 0 || regionSizePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Read the values pointed to by the guest pointers
    uint64_t requestedBase = 0;
    uint64_t requestedSize = 0;
    auto& mem = ctx.Memory();

    if (mem.ReadU64(baseAddrPtr, requestedBase) != ErrorCode::Success ||
        mem.ReadU64(regionSizePtr, requestedSize) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    // Validate: cap size to prevent resource exhaustion
    if (requestedSize == 0 || requestedSize > kMaxAllocationSize) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Page-align the size upward
    const uint64_t alignedSize = AlignUp(requestedSize, kPageSize);

    // Convert Win32 PAGE_xxx → MemProt
    const MemProt prot = Win32ProtToMemProt(win32Prot);

    const bool doReserve = (allocType & NT::MEM_RESERVE) != 0;
    const bool doCommit  = (allocType & NT::MEM_COMMIT) != 0;

    if (!doReserve && !doCommit) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    std::optional<GuestAddress> result;

    if (doReserve && doCommit) {
        // Reserve + commit in one shot
        result = mem.Allocate(requestedBase, alignedSize, prot);
    } else if (doReserve) {
        // Reserve only — no access permissions until committed
        result = mem.Allocate(requestedBase, alignedSize, MemProt::None);
    } else {
        // Commit on already-reserved memory — set the requested protection
        if (requestedBase == 0) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
            return true;
        }
        if (!mem.Protect(requestedBase, alignedSize, prot)) {
            ctx.SetReturnNtStatus(NT::STATUS_CONFLICTING_ADDRESSES);
            return true;
        }
        result = requestedBase;
    }

    if (!result.has_value()) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    // Write results back to guest pointers
    mem.WriteU64(baseAddrPtr, result.value());
    mem.WriteU64(regionSizePtr, alignedSize);

    // Behavioral analysis: PAGE_EXECUTE_READWRITE is suspicious
    // IOC: T1055.002 Process Injection via RWX allocation is the canonical
    // shellcode-staging/unpacking signature — emit both MemoryManipulation
    // and SuspiciousAPI directly from the NT layer so direct-syscall
    // callers are not missed by Win32-only dispatcher metadata.
    if (win32Prot == NT::PAGE_EXECUTE_READWRITE) {
        ctx.AddBehaviorFlag(BehaviorFlag::MemoryManipulation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtProtectVirtualMemory
// ============================================================================
// Args: ProcessHandle, *BaseAddress, *RegionSize, NewProtect, *OldProtect

bool HandleNtProtectVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddrPtr   = ctx.GetArgPtr(1);
    const auto regionSizePtr = ctx.GetArgPtr(2);
    const auto newWin32Prot  = ctx.GetArg32(3);
    const auto oldProtPtr    = ctx.GetArgPtr(4);

    if (!IsSelfProcess(processHandle)) {
        // IOC: T1055 Process Injection — flipping page protection in a
        // remote process is the final stage of RW→RX shellcode activation.
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (baseAddrPtr == 0 || regionSizePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    uint64_t baseAddr = 0;
    uint64_t regionSize = 0;
    if (mem.ReadU64(baseAddrPtr, baseAddr) != ErrorCode::Success ||
        mem.ReadU64(regionSizePtr, regionSize) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    if (regionSize == 0 || regionSize > kMaxAllocationSize) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    const uint64_t alignedSize = AlignUp(regionSize, kPageSize);
    const GuestAddress alignedBase = PageBase(baseAddr);

    // Capture the current protection for OldProtect output
    auto currentProt = mem.GetProtection(alignedBase);
    uint32_t oldWin32Prot = NT::PAGE_NOACCESS;
    if (currentProt.has_value()) {
        oldWin32Prot = MemProtToWin32(currentProt.value());
    }

    // Apply new protection
    const MemProt newProt = Win32ProtToMemProt(newWin32Prot);
    if (!mem.Protect(alignedBase, alignedSize, newProt)) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // IOC: RW→RX / *→RWX / *→RX transitions on a writable region are the
    // canonical shellcode-activation signature (T1055.002 / T1055.012).
    // The emulator sees every transition so we escalate based on the new
    // protection regardless of the prior state.
    if (newWin32Prot == NT::PAGE_EXECUTE_READWRITE ||
        newWin32Prot == NT::PAGE_EXECUTE_READ ||
        newWin32Prot == NT::PAGE_EXECUTE) {
        ctx.AddBehaviorFlag(BehaviorFlag::MemoryManipulation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        if (oldWin32Prot == NT::PAGE_READWRITE ||
            oldWin32Prot == NT::PAGE_WRITECOPY ||
            newWin32Prot == NT::PAGE_EXECUTE_READWRITE) {
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        }
    }

    // Write old protection to output pointer
    if (oldProtPtr != 0) {
        mem.WriteU32(oldProtPtr, oldWin32Prot);
    }

    // Write back possibly-aligned base and size
    mem.WriteU64(baseAddrPtr, alignedBase);
    mem.WriteU64(regionSizePtr, alignedSize);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtFreeVirtualMemory
// ============================================================================
// Args: ProcessHandle, *BaseAddress, *RegionSize, FreeType

bool HandleNtFreeVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddrPtr   = ctx.GetArgPtr(1);
    const auto regionSizePtr = ctx.GetArgPtr(2);
    const auto freeType      = ctx.GetArg32(3);

    if (!IsSelfProcess(processHandle)) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (baseAddrPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    uint64_t baseAddr = 0;
    uint64_t regionSize = 0;
    if (mem.ReadU64(baseAddrPtr, baseAddr) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }
    if (regionSizePtr != 0) {
        mem.ReadU64(regionSizePtr, regionSize);
    }

    if (baseAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    if (freeType & NT::MEM_RELEASE) {
        // MEM_RELEASE: free entire region (regionSize must be 0 per NT semantics)
        const uint64_t releaseSize = (regionSize != 0)
            ? AlignUp(regionSize, kPageSize)
            : kPageSize;

        if (!mem.Free(baseAddr, releaseSize)) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
            return true;
        }

        if (baseAddrPtr != 0) mem.WriteU64(baseAddrPtr, baseAddr);
        if (regionSizePtr != 0) mem.WriteU64(regionSizePtr, releaseSize);
    } else if (freeType & NT::MEM_DECOMMIT) {
        // MEM_DECOMMIT: remove commitment but keep reservation
        const uint64_t alignedSize = AlignUp(regionSize, kPageSize);
        mem.Protect(baseAddr, alignedSize, MemProt::None);

        if (baseAddrPtr != 0) mem.WriteU64(baseAddrPtr, baseAddr);
        if (regionSizePtr != 0) mem.WriteU64(regionSizePtr, alignedSize);
    } else {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtReadVirtualMemory
// ============================================================================
// Args: ProcessHandle, BaseAddress, Buffer, BufferSize, *NumberOfBytesRead

bool HandleNtReadVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto srcAddr       = ctx.GetArgPtr(1);
    const auto dstBuffer     = ctx.GetArgPtr(2);
    auto       bufferSize    = ctx.GetArg(3);
    const auto bytesReadPtr  = ctx.GetArgPtr(4);

    if (!IsSelfProcess(processHandle)) {
        // IOC: T1003 Credential Access precursor — reading another
        // process's address space (canonical LSASS / Chrome / keepass
        // read pattern). Always emit before refusing the call.
        ctx.AddBehaviorFlag(BehaviorFlag::CredentialAccess);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (srcAddr == 0 || dstBuffer == 0 || bufferSize == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Cap to prevent resource exhaustion
    bufferSize = std::min(bufferSize, kMaxBufferSize);

    auto& mem = ctx.Memory();

    // Allocate a host-side staging buffer (capped at 16 MB)
    std::vector<uint8_t> staging;
    staging.resize(static_cast<size_t>(bufferSize));

    auto readErr = mem.Read(srcAddr, staging.data(),
                            static_cast<uint32_t>(bufferSize));
    if (readErr != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    auto writeErr = mem.Write(dstBuffer, staging.data(),
                              static_cast<uint32_t>(bufferSize));
    if (writeErr != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    if (bytesReadPtr != 0) {
        mem.WriteU64(bytesReadPtr, bufferSize);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtWriteVirtualMemory
// ============================================================================
// Args: ProcessHandle, BaseAddress, Buffer, BufferSize, *NumberOfBytesWritten

bool HandleNtWriteVirtualMemory(APIContext& ctx) {
    const auto processHandle  = ctx.GetArg(0);
    const auto dstAddr        = ctx.GetArgPtr(1);
    const auto srcBuffer      = ctx.GetArgPtr(2);
    auto       bufferSize     = ctx.GetArg(3);
    const auto bytesWrittenPtr = ctx.GetArgPtr(4);

    // Writing to another process is a process-injection signal
    if (!IsSelfProcess(processHandle)) {
        // IOC: T1055 Process Injection — WriteProcessMemory-equivalent
        // primitive. Combined with NtAllocateVirtualMemory + CreateThread
        // this is the classic shellcode injection triad.
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (dstAddr == 0 || srcBuffer == 0 || bufferSize == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    bufferSize = std::min(bufferSize, kMaxBufferSize);

    auto& mem = ctx.Memory();

    std::vector<uint8_t> staging;
    staging.resize(static_cast<size_t>(bufferSize));

    auto readErr = mem.Read(srcBuffer, staging.data(),
                            static_cast<uint32_t>(bufferSize));
    if (readErr != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    auto writeErr = mem.Write(dstAddr, staging.data(),
                              static_cast<uint32_t>(bufferSize));
    if (writeErr != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    if (bytesWrittenPtr != 0) {
        mem.WriteU64(bytesWrittenPtr, bufferSize);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtQueryVirtualMemory
// ============================================================================
// Args: ProcessHandle, BaseAddress, MemInfoClass, MemInfo, MemInfoLength,
//       *ReturnLength
//
// Only MemoryBasicInformation (class 0) is supported.
// MEMORY_BASIC_INFORMATION (x64 layout, 48 bytes):
//   +0x00  PVOID  BaseAddress
//   +0x08  PVOID  AllocationBase
//   +0x10  DWORD  AllocationProtect
//   +0x14  WORD   PartitionId (padding)
//   +0x16  [2 pad]
//   +0x18  SIZE_T RegionSize
//   +0x20  DWORD  State
//   +0x24  DWORD  Protect
//   +0x28  DWORD  Type
//   +0x2C  [4 pad]

static constexpr uint32_t kMemBasicInfoSize64 = 0x30; // 48 bytes

bool HandleNtQueryVirtualMemory(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto queryAddr     = ctx.GetArgPtr(1);
    const auto infoClass     = ctx.GetArg32(2);
    const auto infoBuffer    = ctx.GetArgPtr(3);
    const auto infoLength    = ctx.GetArg32(4);
    const auto retLengthPtr  = ctx.GetArgPtr(5);

    if (!IsSelfProcess(processHandle)) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    // Only MemoryBasicInformation (class 0)
    if (infoClass != 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }

    if (infoBuffer == 0 || infoLength < kMemBasicInfoSize64) {
        ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
        return true;
    }

    auto& mem = ctx.Memory();

    const GuestAddress pageAligned = PageBase(queryAddr);
    auto protOpt = mem.GetProtection(pageAligned);
    const bool accessible = protOpt.has_value();

    // Build the structure in a local buffer, then write once
    uint8_t mbi[kMemBasicInfoSize64] = {};

    // BaseAddress
    std::memcpy(mbi + 0x00, &pageAligned, 8);
    // AllocationBase (approximate: use page-aligned base)
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
        // Region is free
        const uint64_t regionSize = kPageSize;
        const uint32_t state      = kMemStateFree;

        std::memcpy(mbi + 0x18, &regionSize, 8);
        std::memcpy(mbi + 0x20, &state, 4);
    }

    if (mem.Write(infoBuffer, mbi, kMemBasicInfoSize64) != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    if (retLengthPtr != 0) {
        mem.WriteU64(retLengthPtr, kMemBasicInfoSize64);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtCreateSection
// ============================================================================
// Args: *SectionHandle, DesiredAccess, *ObjectAttributes, *MaximumSize,
//       SectionPageProtection, AllocationAttributes, FileHandle

bool HandleNtCreateSection(APIContext& ctx) {
    const auto sectionHandlePtr = ctx.GetArgPtr(0);
    // arg1 = DesiredAccess (informational, not enforced in emulation)
    // arg2 = ObjectAttributes (optional name — not critical for emulation)
    const auto maxSizePtr       = ctx.GetArgPtr(3);
    const auto sectionProt      = ctx.GetArg32(4);
    // arg5 = AllocationAttributes (SEC_COMMIT, SEC_IMAGE, etc.)
    const auto fileHandle       = ctx.GetArg(6);

    if (sectionHandlePtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    auto& mem     = ctx.Memory();
    auto& handles = ctx.Handles();

    // Read maximum size if pointer is non-null
    uint64_t maxSize = 0;
    if (maxSizePtr != 0) {
        mem.ReadU64(maxSizePtr, maxSize);
    }

    // Cap maximum section size
    if (maxSize > kMaxAllocationSize) {
        maxSize = kMaxAllocationSize;
    }
    if (maxSize == 0) {
        // If backed by a file, use file size; otherwise default
        if (fileHandle != 0 && fileHandle != kNullHandle) {
            auto entry = handles.Lookup(fileHandle, HandleType::File);
            if (entry.has_value()) {
                auto* fd = std::get_if<FileHandleData>(&entry->data);
                if (fd) maxSize = fd->fileSize;
            }
        }
        if (maxSize == 0) maxSize = kPageSize;
    }

    // Build section data
    SectionData sd;
    sd.maxSize    = maxSize;
    sd.protection = sectionProt;
    // Associate file handle if provided
    if (fileHandle != 0 && fileHandle != kNullHandle) {
        auto entry = handles.Lookup(fileHandle, HandleType::File);
        if (entry.has_value()) {
            auto* fd = std::get_if<FileHandleData>(&entry->data);
            if (fd) sd.name = fd->path;
        }
    }

    GuestHandle gh = handles.Create(HandleType::Section, std::move(sd));
    if (gh == kNullHandle) {
        ctx.SetReturnNtStatus(NT::STATUS_INSUFFICIENT_RESOURCES);
        return true;
    }

    mem.WriteU64(sectionHandlePtr, gh);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtMapViewOfSection
// ============================================================================
// Args (10): SectionHandle, ProcessHandle, *BaseAddress, ZeroBits,
//            CommitSize, *SectionOffset, *ViewSize, InheritDisposition,
//            AllocationType, Win32Protect

bool HandleNtMapViewOfSection(APIContext& ctx) {
    const auto sectionHandle = ctx.GetArg(0);
    const auto processHandle = ctx.GetArg(1);
    const auto baseAddrPtr   = ctx.GetArgPtr(2);
    // arg3 = ZeroBits (ignored)
    // arg4 = CommitSize (ignored — we always commit fully)
    // arg5 = SectionOffset (optional, not emulated)
    const auto viewSizePtr   = ctx.GetArgPtr(6);
    // arg7 = InheritDisposition (ignored)
    // arg8 = AllocationType (ignored)
    const auto win32Prot     = ctx.GetArg32(9);

    if (!IsSelfProcess(processHandle)) {
        // IOC: T1055.012 Process Hollowing / Section Injection — mapping a
        // section view into a remote process is the primary primitive for
        // hollowing and AtomBombing-style injection chains.
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessHollowing);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto& mem     = ctx.Memory();
    auto& handles = ctx.Handles();

    // Look up the section
    auto entry = handles.Lookup(sectionHandle, HandleType::Section);
    if (!entry.has_value()) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    auto* sd = std::get_if<SectionData>(&entry->data);
    if (!sd) {
        ctx.SetReturnNtStatus(NT::STATUS_OBJECT_TYPE_MISMATCH);
        return true;
    }

    // Determine view size
    uint64_t viewSize = 0;
    if (viewSizePtr != 0) {
        mem.ReadU64(viewSizePtr, viewSize);
    }
    if (viewSize == 0) {
        viewSize = sd->maxSize;
    }
    viewSize = std::min(viewSize, kMaxAllocationSize);
    viewSize = AlignUp(viewSize, kPageSize);

    uint64_t requestedBase = 0;
    if (baseAddrPtr != 0) {
        mem.ReadU64(baseAddrPtr, requestedBase);
    }

    // Allocate the region
    const MemProt prot = Win32ProtToMemProt(win32Prot);
    auto allocResult = mem.Allocate(requestedBase, viewSize, prot);
    if (!allocResult.has_value()) {
        ctx.SetReturnNtStatus(NT::STATUS_NO_MEMORY);
        return true;
    }

    const GuestAddress mappedBase = allocResult.value();

    // Update section tracking with mapped address
    handles.Modify<SectionData>(sectionHandle, [&](SectionData& s) {
        s.mappedBase = mappedBase;
        s.mappedSize = viewSize;
    });

    // Write results back
    if (baseAddrPtr != 0)   mem.WriteU64(baseAddrPtr, mappedBase);
    if (viewSizePtr != 0)   mem.WriteU64(viewSizePtr, viewSize);

    // IOC: RWX view mapping (shellcode / reflective DLL primitive).
    if (win32Prot == NT::PAGE_EXECUTE_READWRITE ||
        win32Prot == NT::PAGE_EXECUTE_READ ||
        win32Prot == NT::PAGE_EXECUTE) {
        ctx.AddBehaviorFlag(BehaviorFlag::MemoryManipulation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtUnmapViewOfSection
// ============================================================================
// Args: ProcessHandle, BaseAddress

bool HandleNtUnmapViewOfSection(APIContext& ctx) {
    const auto processHandle = ctx.GetArg(0);
    const auto baseAddr      = ctx.GetArgPtr(1);

    if (!IsSelfProcess(processHandle)) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    if (baseAddr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Find matching section in the handle table to get the mapped size
    auto& handles = ctx.Handles();
    auto& mem     = ctx.Memory();

    auto sectionHandles = handles.GetHandlesByType(HandleType::Section);
    GuestSize unmapSize = kPageSize; // fallback

    for (auto gh : sectionHandles) {
        auto entry = handles.Lookup(gh, HandleType::Section);
        if (!entry.has_value()) continue;
        auto* sd = std::get_if<SectionData>(&entry->data);
        if (sd && sd->mappedBase == baseAddr && sd->mappedSize > 0) {
            unmapSize = sd->mappedSize;
            // Clear tracking
            handles.Modify<SectionData>(gh, [](SectionData& s) {
                s.mappedBase = 0;
                s.mappedSize = 0;
            });
            break;
        }
    }

    mem.Free(baseAddr, unmapSize);

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtMemory(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ntdll.dll", "NtAllocateVirtualMemory",
          HandleNtAllocateVirtualMemory, 6, true },
        { "ntdll.dll", "NtProtectVirtualMemory",
          HandleNtProtectVirtualMemory, 5, true },
        { "ntdll.dll", "NtFreeVirtualMemory",
          HandleNtFreeVirtualMemory, 4, true },
        { "ntdll.dll", "NtReadVirtualMemory",
          HandleNtReadVirtualMemory, 5, false },
        { "ntdll.dll", "NtWriteVirtualMemory",
          HandleNtWriteVirtualMemory, 5, false },
        { "ntdll.dll", "NtQueryVirtualMemory",
          HandleNtQueryVirtualMemory, 6, true },
        { "ntdll.dll", "NtCreateSection",
          HandleNtCreateSection, 7, false },
        { "ntdll.dll", "NtMapViewOfSection",
          HandleNtMapViewOfSection, 10, false },
        { "ntdll.dll", "NtUnmapViewOfSection",
          HandleNtUnmapViewOfSection, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ntdll

#pragma warning(pop)
