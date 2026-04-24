/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtProcess.cpp — Nt* process management syscall handler implementations
 *
 * Handles NtOpenProcess, NtTerminateProcess, and NtQueryInformationProcess.
 * Anti-debug information classes (ProcessDebugPort, ProcessDebugObjectHandle,
 * ProcessDebugFlags) are MISSION CRITICAL: they determine whether malware
 * detonates its payload or evades analysis.
 *
 * Author: ShadowStrike-Labs contact@ShadowStrike.dev
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtProcess.hpp"
#include "../APIDispatcher.hpp"
#include "../APIDatabase.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

#include <cstring>
#include <string>
#include <iterator>

// DESIGN: Guest writebacks (WriteU16/U32/U64/WriteGuestPtr) are [[nodiscard]]
// so the caller can detect guest-side AVs. Every target is null-checked or
// proven valid by a length check above; a guest AV on writeback is a guest
// fault. Pragma is namespace-scoped; validation guards and return-status
// semantics remain intact.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

// Guest wide characters are always UTF-16LE (2 bytes), regardless of host.
static_assert(sizeof(wchar_t) == 2,
    "PhantomEmulator requires sizeof(wchar_t)==2 (UTF-16). "
    "Build with MSVC on Windows.");

namespace Phantom {
namespace WinAPI::Ntdll {

// ============================================================================
// Emulated process environment constants
// ============================================================================

static constexpr uint32_t kEmulatedPID       = 4444;
static constexpr uint32_t kEmulatedParentPID = 1000;  // Fake explorer.exe PID
static constexpr uint32_t kSessionId         = 1;

// Fake PEB base addresses (realistic user-mode addresses)
static constexpr GuestAddress kPebBase64 = 0x00000000'002C1000ULL;
static constexpr GuestAddress kPebBase32 = 0x7FFD4000ULL;

// ============================================================================
// ProcessInformationClass values (matching NT::ProcessInformationClass enum)
// ============================================================================

static constexpr uint32_t kProcessBasicInfo          = 0;
static constexpr uint32_t kProcessDebugPort          = 7;
static constexpr uint32_t kProcessWow64Info          = 26;
static constexpr uint32_t kProcessImageFileName      = 27;
static constexpr uint32_t kProcessBreakOnTermination = 29;
static constexpr uint32_t kProcessDebugObjectHandle  = 30;
static constexpr uint32_t kProcessDebugFlags         = 31;
static constexpr uint32_t kProcessImageFileNameWin32 = 43;

// ============================================================================
// Structure sizes
// ============================================================================

// PROCESS_BASIC_INFORMATION
static constexpr uint32_t kPBI64Size = 48;
static constexpr uint32_t kPBI32Size = 24;

// UNICODE_STRING header
static constexpr uint32_t kUnicodeStringHeader64 = 16;  // 2+2+4(pad)+8
static constexpr uint32_t kUnicodeStringHeader32 = 8;   // 2+2+4

// Guest UTF-16 character size
static constexpr uint32_t kGuestWCharSize = 2;

// ============================================================================
// Helper: Write a pointer-sized value to guest memory
// ============================================================================

static ErrorCode WriteGuestPtr(VirtualMemory& mem, GuestAddress addr,
                               uint64_t value, bool is64) noexcept {
    if (is64) {
        return mem.WriteU64(addr, value);
    }
    return mem.WriteU32(addr, static_cast<uint32_t>(value));
}

// ============================================================================
// Helper: Read a pointer-sized value from guest memory
// ============================================================================

static ErrorCode ReadGuestPtr(VirtualMemory& mem, GuestAddress addr,
                              uint64_t& value, bool is64) noexcept {
    if (is64) {
        return mem.ReadU64(addr, value);
    }
    uint32_t val32 = 0;
    auto err = mem.ReadU32(addr, val32);
    value = val32;
    return err;
}

// ============================================================================
// Helper: Pointer size for current bitness
// ============================================================================

static constexpr uint32_t PtrSize(bool is64) noexcept {
    return is64 ? 8u : 4u;
}

// ============================================================================
// Helper: Build NT-style image path from config
// ============================================================================

static std::wstring BuildNtImagePath(const EmulationConfig& config) {
    // Cap username length to prevent excessive allocation
    std::wstring_view name = config.userName;
    if (name.size() > 256) {
        name = name.substr(0, 256);
    }
    std::wstring path;
    path.reserve(64 + name.size());
    path += L"\\Device\\HarddiskVolume3\\Users\\";
    path += name;
    path += L"\\sample.exe";
    return path;
}

// ============================================================================
// Helper: Build Win32 image path from config
// ============================================================================

static std::wstring BuildWin32ImagePath(const EmulationConfig& config) {
    std::wstring_view name = config.userName;
    if (name.size() > 256) {
        name = name.substr(0, 256);
    }
    std::wstring path;
    path.reserve(32 + name.size());
    path += L"C:\\Users\\";
    path += name;
    path += L"\\sample.exe";
    return path;
}

// ============================================================================
// Helper: Write UNICODE_STRING structure + trailing string data into a
//         guest buffer. The Buffer pointer inside the structure points to
//         the string data placed immediately after the header.
// ============================================================================

static ErrorCode WriteUnicodeStringToBuffer(
    VirtualMemory& mem, GuestAddress bufAddr, uint32_t bufLen,
    const std::wstring& str, bool is64, uint32_t* bytesWritten) noexcept
{
    const uint32_t headerSize = is64 ? kUnicodeStringHeader64
                                     : kUnicodeStringHeader32;
    const uint32_t strByteLen = static_cast<uint32_t>(str.size() * kGuestWCharSize);
    const uint32_t totalNeeded = headerSize + strByteLen + kGuestWCharSize;

    if (bytesWritten) {
        *bytesWritten = totalNeeded;
    }

    if (bufLen < totalNeeded) {
        return ErrorCode::AccessViolationWrite;
    }

    // Zero the header to clear padding bytes
    uint8_t zeroBuf[16] = {};
    auto err = mem.Write(bufAddr, zeroBuf, headerSize);
    if (err != ErrorCode::Success) return err;

    // Length: byte count excluding null terminator
    err = mem.WriteU16(bufAddr, static_cast<uint16_t>(strByteLen));
    if (err != ErrorCode::Success) return err;

    // MaximumLength: byte count including null terminator
    err = mem.WriteU16(bufAddr + 2,
                       static_cast<uint16_t>(strByteLen + kGuestWCharSize));
    if (err != ErrorCode::Success) return err;

    // Buffer pointer → address of string data (right after header)
    const GuestAddress strDataAddr = bufAddr + headerSize;
    const uint32_t bufPtrOffset = is64 ? 8u : 4u;
    err = WriteGuestPtr(mem, bufAddr + bufPtrOffset, strDataAddr, is64);
    if (err != ErrorCode::Success) return err;

    // Write the UTF-16LE string data
    if (strByteLen > 0) {
        err = mem.Write(strDataAddr, str.data(), strByteLen);
        if (err != ErrorCode::Success) return err;
    }

    // Null terminator
    const uint16_t nullTerm = 0;
    err = mem.WriteU16(strDataAddr + strByteLen, nullTerm);
    return err;
}

// ============================================================================
// Helper: Write ReturnLength to an optional output pointer
// ============================================================================

static void WriteReturnLength(VirtualMemory& mem, GuestAddress ptr,
                              uint32_t value) noexcept {
    if (ptr != 0) {
        mem.WriteU32(ptr, value);
    }
}

// ============================================================================
// NtOpenProcess
// ============================================================================
// NTSTATUS NtOpenProcess(
//     OUT PHANDLE            ProcessHandle,   // arg 0
//     IN  ACCESS_MASK        DesiredAccess,    // arg 1
//     IN  POBJECT_ATTRIBUTES ObjectAttributes, // arg 2
//     IN  PCLIENT_ID         ClientId          // arg 3
// );
//
// Opens a handle to a process identified by ClientId->UniqueProcess.
// If the target PID matches our emulated PID, the handle is self-referential.
// Opening a foreign PID indicates potential process injection.

bool HandleNtOpenProcess(APIContext& ctx) {
    const bool is64       = ctx.Is64Bit();
    auto& mem             = ctx.Memory();

    const GuestAddress handleOutPtr = ctx.GetArgPtr(0);
    const uint32_t desiredAccess    = ctx.GetArg32(1);
    const GuestAddress clientIdPtr  = ctx.GetArgPtr(3);

    // Validate mandatory output pointer
    if (handleOutPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Validate ClientId pointer
    if (clientIdPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Read UniqueProcess from CLIENT_ID { HANDLE UniqueProcess; HANDLE UniqueThread; }
    uint64_t targetPid = 0;
    auto err = ReadGuestPtr(mem, clientIdPtr, targetPid, is64);
    if (err != ErrorCode::Success) {
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    const bool isSelf = (static_cast<uint32_t>(targetPid) == kEmulatedPID);

    // IOC: classify the open based on the requested access mask.
    // Win32 PROCESS_* access constants:
    //   PROCESS_CREATE_THREAD   = 0x0002  (remote-thread injection primitive)
    //   PROCESS_VM_OPERATION    = 0x0008  (required for VirtualAllocEx/ProtectEx)
    //   PROCESS_VM_READ         = 0x0010  (LSASS/secrets read — T1003)
    //   PROCESS_VM_WRITE        = 0x0020  (WriteProcessMemory injection)
    //   PROCESS_TERMINATE       = 0x0001  (T1562.001 impair defenses)
    //   PROCESS_ALL_ACCESS      = 0x001FFFFF
    if (!isSelf) {
        constexpr uint32_t kProcCreateThread  = 0x0002;
        constexpr uint32_t kProcVmOperation   = 0x0008;
        constexpr uint32_t kProcVmRead        = 0x0010;
        constexpr uint32_t kProcVmWrite       = 0x0020;
        constexpr uint32_t kProcTerminate     = 0x0001;
        constexpr uint32_t kProcAllAccess     = 0x001FFFFFu;

        const bool injectSet =
            (desiredAccess & (kProcCreateThread | kProcVmOperation |
                              kProcVmWrite)) != 0;
        const bool readSet =
            (desiredAccess & kProcVmRead) != 0;
        const bool terminateSet =
            (desiredAccess & kProcTerminate) != 0;
        const bool allSet =
            (desiredAccess & kProcAllAccess) == kProcAllAccess;

        if (injectSet || allSet) {
            ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
        if (readSet || allSet) {
            ctx.AddBehaviorFlag(BehaviorFlag::CredentialAccess);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
        if (terminateSet && !(injectSet || readSet)) {
            ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        }
    }

    ProcessHandleData pd{};
    pd.pid        = static_cast<uint32_t>(targetPid);
    pd.accessMask = desiredAccess;
    pd.isSelf     = isSelf;
    pd.imageBase  = 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Process, std::move(pd));

    // Write the new handle to the caller's output pointer
    err = WriteGuestPtr(mem, handleOutPtr, handle, is64);
    if (err != ErrorCode::Success) {
        ctx.Handles().Close(handle);
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtTerminateProcess
// ============================================================================
// NTSTATUS NtTerminateProcess(
//     IN HANDLE ProcessHandle,  // arg 0
//     IN NTSTATUS ExitStatus    // arg 1
// );
//
// If the handle refers to the current process (NULL or kCurrentProcess),
// emulation must stop (StopReason::ExitProcess). This is one of the few
// handlers that returns false.

bool HandleNtTerminateProcess(APIContext& ctx) {
    const GuestHandle handle = static_cast<GuestHandle>(ctx.GetArg(0));

    // NULL handle (0) or current-process pseudo-handle (-1) → terminate self
    if (handle == kNullHandle || handle == kCurrentProcess) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return false;  // Stop emulation
    }

    // Look up the handle in the table
    auto entry = ctx.Handles().Lookup(handle, HandleType::Process);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    const auto& pd = std::get<ProcessHandleData>(entry->data);

    // Self-termination via an explicit handle to our own PID
    if (pd.isSelf || pd.pid == kEmulatedPID) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return false;  // Stop emulation
    }

    // External process: emulator cannot actually terminate it.
    // IOC: T1562.001 Impair Defenses — terminating another process is
    // the canonical AV/EDR-kill primitive (e.g. avkiller, bring-your-
    // own-driver chains ending in userland NtTerminateProcess).
    ctx.AddBehaviorFlag(BehaviorFlag::DefenseEvasion);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtQueryInformationProcess
// ============================================================================
// NTSTATUS NtQueryInformationProcess(
//     IN  HANDLE           ProcessHandle,           // arg 0
//     IN  PROCESSINFOCLASS ProcessInformationClass,  // arg 1
//     OUT PVOID            ProcessInformation,        // arg 2
//     IN  ULONG            ProcessInformationLength,  // arg 3
//     OUT PULONG           ReturnLength OPTIONAL       // arg 4
// );
//
// Anti-debug critical info classes:
//   - ProcessDebugPort (7):         return 0 → "no debugger attached"
//   - ProcessDebugObjectHandle (30): return STATUS_PORT_NOT_SET → "no debug object"
//   - ProcessDebugFlags (31):       return 1 → PROCESS_DEBUG_FLAGS_NO_DEBUGGER
//
// Malware checks these to decide whether to detonate. Returning the wrong
// value here means the sample evades analysis entirely.

bool HandleNtQueryInformationProcess(APIContext& ctx) {
    const bool is64 = ctx.Is64Bit();
    auto& mem       = ctx.Memory();

    const GuestHandle handle        = static_cast<GuestHandle>(ctx.GetArg(0));
    const uint32_t infoClass        = ctx.GetArg32(1);
    const GuestAddress infoBuffer   = ctx.GetArgPtr(2);
    const uint32_t infoLength       = ctx.GetArg32(3);
    const GuestAddress returnLenPtr = ctx.GetArgPtr(4);

    // Validate the handle: must be current-process pseudo-handle or a valid
    // process handle in the table. NULL handle is accepted (means current).
    if (handle != kCurrentProcess && handle != kNullHandle) {
        auto entry = ctx.Handles().Lookup(handle, HandleType::Process);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    if (infoBuffer == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    switch (infoClass) {

    // ==================================================================
    // ProcessBasicInformation (0)
    // ==================================================================
    case kProcessBasicInfo: {
        const uint32_t requiredSize = is64 ? kPBI64Size : kPBI32Size;

        if (infoLength < requiredSize) {
            WriteReturnLength(mem, returnLenPtr, requiredSize);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        const GuestAddress pebBase = is64 ? kPebBase64 : kPebBase32;
        const uint64_t affinityMask =
            (1ULL << ctx.Config().processorCount) - 1;

        if (is64) {
            // x64 PROCESS_BASIC_INFORMATION (48 bytes):
            //  0: NTSTATUS  ExitStatus           (4) + 4 pad
            //  8: PPEB      PebBaseAddress        (8)
            // 16: ULONG_PTR AffinityMask          (8)
            // 24: KPRIORITY BasePriority           (4) + 4 pad
            // 32: ULONG_PTR UniqueProcessId        (8)
            // 40: ULONG_PTR InheritedFromUniquePid (8)
            uint8_t buf[48] = {};
            mem.Write(infoBuffer, buf, sizeof(buf));

            mem.WriteU32(infoBuffer + 0,  0);                 // STILL_ACTIVE
            mem.WriteU64(infoBuffer + 8,  pebBase);
            mem.WriteU64(infoBuffer + 16, affinityMask);
            mem.WriteU32(infoBuffer + 24, 8);                 // BasePriority
            mem.WriteU64(infoBuffer + 32, kEmulatedPID);
            mem.WriteU64(infoBuffer + 40, kEmulatedParentPID);
        } else {
            // x86 PROCESS_BASIC_INFORMATION (24 bytes):
            //  0: NTSTATUS  ExitStatus           (4)
            //  4: PPEB      PebBaseAddress        (4)
            //  8: ULONG_PTR AffinityMask          (4)
            // 12: KPRIORITY BasePriority           (4)
            // 16: ULONG_PTR UniqueProcessId        (4)
            // 20: ULONG_PTR InheritedFromUniquePid (4)
            uint8_t buf[24] = {};
            mem.Write(infoBuffer, buf, sizeof(buf));

            mem.WriteU32(infoBuffer + 0,  0);
            mem.WriteU32(infoBuffer + 4,  static_cast<uint32_t>(pebBase));
            mem.WriteU32(infoBuffer + 8,  static_cast<uint32_t>(affinityMask));
            mem.WriteU32(infoBuffer + 12, 8);
            mem.WriteU32(infoBuffer + 16, kEmulatedPID);
            mem.WriteU32(infoBuffer + 20, kEmulatedParentPID);
        }

        WriteReturnLength(mem, returnLenPtr, requiredSize);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessDebugPort (7) — ANTI-DEBUG
    // Returns 0 (no debugger port). Malware checks: if (port != 0) exit;
    // ==================================================================
    case kProcessDebugPort: {
        // IOC: T1622 Debugger Evasion — every query of these info-classes
        // is a live anti-analysis signal. We still return the benign
        // answer so the sample proceeds past the check and reveals the
        // next stage; the flag is emitted so downstream correlation sees
        // the evasion attempt regardless of the spoofed result.
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        const uint32_t ptrSz = PtrSize(is64);

        if (infoLength < ptrSz) {
            WriteReturnLength(mem, returnLenPtr, ptrSz);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        // Zero = no debugger attached
        WriteGuestPtr(mem, infoBuffer, 0, is64);
        WriteReturnLength(mem, returnLenPtr, ptrSz);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessWow64Information (26)
    // Returns 0 for native 64-bit, non-zero (PEB32 addr) for WoW64.
    // ==================================================================
    case kProcessWow64Info: {
        const uint32_t ptrSz = PtrSize(is64);

        if (infoLength < ptrSz) {
            WriteReturnLength(mem, returnLenPtr, ptrSz);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        // 64-bit process → not WoW64 (0). 32-bit → return PEB32 address.
        const uint64_t wow64Value = is64 ? 0 : kPebBase32;
        WriteGuestPtr(mem, infoBuffer, wow64Value, is64);
        WriteReturnLength(mem, returnLenPtr, ptrSz);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessImageFileName (27) — NT device path
    // Returns UNICODE_STRING with "\Device\HarddiskVolume3\Users\...\sample.exe"
    // ==================================================================
    case kProcessImageFileName: {
        const std::wstring ntPath = BuildNtImagePath(ctx.Config());
        const uint32_t headerSize = is64 ? kUnicodeStringHeader64
                                         : kUnicodeStringHeader32;
        const uint32_t strBytes =
            static_cast<uint32_t>(ntPath.size() * kGuestWCharSize);
        const uint32_t required = headerSize + strBytes + kGuestWCharSize;

        if (infoLength < required) {
            WriteReturnLength(mem, returnLenPtr, required);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        uint32_t written = 0;
        auto err = WriteUnicodeStringToBuffer(
            mem, infoBuffer, infoLength, ntPath, is64, &written);
        if (err != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }

        WriteReturnLength(mem, returnLenPtr, written);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessBreakOnTermination (29)
    // Returns 0 (process is not marked as critical).
    // ==================================================================
    case kProcessBreakOnTermination: {
        if (infoLength < 4) {
            WriteReturnLength(mem, returnLenPtr, 4);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        mem.WriteU32(infoBuffer, 0);  // Not a critical process
        WriteReturnLength(mem, returnLenPtr, 4);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessDebugObjectHandle (30) — ANTI-DEBUG
    // Returns STATUS_PORT_NOT_SET (no debug object exists).
    // Malware checks: if (NT_SUCCESS(status)) exit;
    // ==================================================================
    case kProcessDebugObjectHandle: {
        // IOC: T1622 Debugger Evasion (see ProcessDebugPort above).
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        // Do NOT write any data — just return the error status.
        // Windows returns STATUS_PORT_NOT_SET when no debug object is attached.
        ctx.SetReturnNtStatus(NT::STATUS_PORT_NOT_SET);
        return true;
    }

    // ==================================================================
    // ProcessDebugFlags (31) — ANTI-DEBUG
    // Returns 1 = PROCESS_DEBUG_FLAGS_NO_DEBUGGER.
    // Malware checks: if (flags == 0) exit;  (0 means debugger IS present)
    // ==================================================================
    case kProcessDebugFlags: {
        // IOC: T1622 Debugger Evasion (see ProcessDebugPort above).
        ctx.AddBehaviorFlag(BehaviorFlag::AntiAnalysis);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
        if (infoLength < 4) {
            WriteReturnLength(mem, returnLenPtr, 4);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        mem.WriteU32(infoBuffer, 1);  // No debugger
        WriteReturnLength(mem, returnLenPtr, 4);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ProcessImageFileNameWin32 (43) — Win32 path
    // Returns UNICODE_STRING with "C:\Users\...\sample.exe"
    // ==================================================================
    case kProcessImageFileNameWin32: {
        const std::wstring win32Path = BuildWin32ImagePath(ctx.Config());
        const uint32_t headerSize = is64 ? kUnicodeStringHeader64
                                         : kUnicodeStringHeader32;
        const uint32_t strBytes =
            static_cast<uint32_t>(win32Path.size() * kGuestWCharSize);
        const uint32_t required = headerSize + strBytes + kGuestWCharSize;

        if (infoLength < required) {
            WriteReturnLength(mem, returnLenPtr, required);
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        uint32_t written = 0;
        auto err = WriteUnicodeStringToBuffer(
            mem, infoBuffer, infoLength, win32Path, is64, &written);
        if (err != ErrorCode::Success) {
            ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
            return true;
        }

        WriteReturnLength(mem, returnLenPtr, written);
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // Unsupported information class
    // ==================================================================
    default:
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_INFO_CLASS);
        return true;
    }
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtProcess(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration regs[] = {
        { "ntdll.dll", "NtOpenProcess",
          HandleNtOpenProcess,             4, true },
        { "ntdll.dll", "NtTerminateProcess",
          HandleNtTerminateProcess,        2, true },
        { "ntdll.dll", "NtQueryInformationProcess",
          HandleNtQueryInformationProcess, 5, true },
    };

    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

} // namespace WinAPI::Ntdll
} // namespace Phantom

#pragma warning(pop)
