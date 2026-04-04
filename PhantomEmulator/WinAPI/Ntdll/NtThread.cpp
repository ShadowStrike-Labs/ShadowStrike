/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtThread.cpp — Nt* thread management syscall handler implementations
 *
 * Handles NtCreateThreadEx (remote thread injection detection),
 * NtResumeThread, NtSuspendThread, NtTerminateThread,
 * NtQueryInformationThread, and NtSetInformationThread.
 *
 * NtSetInformationThread with ThreadHideFromDebugger is a CRITICAL
 * anti-debug indicator — malware uses it to prevent debugger attachment.
 * The behavioral flag is set by the dispatcher's DetectBehaviors engine
 * based on the info class argument.
 *
 * NtCreateThreadEx targeting a foreign process handle is the canonical
 * signal for remote thread injection (shellcode/DLL injection finale).
 *
 * Author: ShadowStrike-Labs contact@ShadowStrike.dev
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "NtThread.hpp"
#include "../APIDispatcher.hpp"
#include "../APIDatabase.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"

#include <cstring>
#include <iterator>

// Guest wide characters are always UTF-16LE (2 bytes).
static_assert(sizeof(wchar_t) == 2,
    "PhantomEmulator requires sizeof(wchar_t)==2 (UTF-16). "
    "Build with MSVC on Windows.");

namespace Phantom {
namespace WinAPI::Ntdll {

// ============================================================================
// Thread environment constants
// ============================================================================

static constexpr uint32_t kEmulatedPID    = 4444;
static constexpr uint32_t kMainThreadTID  = 5555;

// TID counter for newly created threads (starts after main thread TID)
static uint32_t s_nextTID = 5556;

// Fake TEB base addresses (each thread gets its own page)
static constexpr GuestAddress kMainTebBase64 = 0x00000000'002BF000ULL;
static constexpr GuestAddress kMainTebBase32 = 0x7FFD3000ULL;

// NtCreateThreadEx create flags
static constexpr uint32_t kThreadCreateSuspended = 0x1;

// ThreadInformationClass values
static constexpr uint32_t kThreadBasicInformation   = 0;
static constexpr uint32_t kThreadHideFromDebugger   = 0x11;
static constexpr uint32_t kThreadIsImpersonating     = 37;

// THREAD_BASIC_INFORMATION structure sizes
static constexpr uint32_t kTBI64Size = 48;
static constexpr uint32_t kTBI32Size = 28;

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
// Helper: Pointer size for current bitness
// ============================================================================

static constexpr uint32_t PtrSize(bool is64) noexcept {
    return is64 ? 8u : 4u;
}

// ============================================================================
// Helper: Compute TEB address for a given TID
// ============================================================================

static GuestAddress ComputeTebAddress(uint32_t tid, bool is64) noexcept {
    const GuestAddress base = is64 ? kMainTebBase64 : kMainTebBase32;
    // Each thread's TEB occupies one page, offset from main thread's TEB
    const uint32_t offset = (tid >= kMainThreadTID)
                          ? (tid - kMainThreadTID)
                          : 0;
    return base + static_cast<GuestAddress>(offset) * kPageSize;
}

// ============================================================================
// Helper: Determine if a process handle refers to the current process
// ============================================================================

static bool IsCurrentProcessHandle(APIContext& ctx, GuestHandle handle) noexcept {
    if (handle == kCurrentProcess || handle == kNullHandle) {
        return true;
    }

    auto entry = ctx.Handles().Lookup(handle, HandleType::Process);
    if (!entry) {
        return false;
    }

    const auto& pd = std::get<ProcessHandleData>(entry->data);
    return pd.isSelf || pd.pid == kEmulatedPID;
}

// ============================================================================
// Helper: Get the PID associated with a process handle
// ============================================================================

static uint32_t GetProcessHandlePID(APIContext& ctx,
                                    GuestHandle handle) noexcept {
    if (handle == kCurrentProcess || handle == kNullHandle) {
        return kEmulatedPID;
    }

    auto entry = ctx.Handles().Lookup(handle, HandleType::Process);
    if (!entry) {
        return 0;
    }

    return std::get<ProcessHandleData>(entry->data).pid;
}

// ============================================================================
// Helper: Get TID from a thread handle (kCurrentThread returns main TID)
// ============================================================================

static uint32_t GetThreadTID(APIContext& ctx, GuestHandle handle) noexcept {
    if (handle == kCurrentThread) {
        return kMainThreadTID;
    }

    auto entry = ctx.Handles().Lookup(handle, HandleType::Thread);
    if (!entry) {
        return 0;
    }

    return std::get<ThreadHandleData>(entry->data).tid;
}

// ============================================================================
// NtCreateThreadEx
// ============================================================================
// NTSTATUS NtCreateThreadEx(
//     OUT PHANDLE     ThreadHandle,      // arg 0
//     IN  ACCESS_MASK DesiredAccess,      // arg 1
//     IN  POBJECT_ATTRIBUTES ObjAttrs,    // arg 2  (may be NULL)
//     IN  HANDLE      ProcessHandle,      // arg 3
//     IN  PVOID       StartRoutine,       // arg 4
//     IN  PVOID       Argument,           // arg 5  (may be NULL)
//     IN  ULONG       CreateFlags,        // arg 6
//     IN  SIZE_T      ZeroBits,           // arg 7
//     IN  SIZE_T      StackSize,          // arg 8
//     IN  SIZE_T      MaximumStackSize,   // arg 9
//     IN  PVOID       AttributeList       // arg 10 (may be NULL)
// );
//
// If ProcessHandle refers to the current process → local thread.
// If ProcessHandle refers to a foreign process → REMOTE THREAD INJECTION.
// We do not actually spawn threads; we record the start address and argument
// for the behavioral analysis engine.

bool HandleNtCreateThreadEx(APIContext& ctx) {
    const bool is64 = ctx.Is64Bit();
    auto& mem       = ctx.Memory();

    const GuestAddress handleOutPtr = ctx.GetArgPtr(0);
    const uint32_t desiredAccess    = ctx.GetArg32(1);
    const GuestHandle processHandle = static_cast<GuestHandle>(ctx.GetArg(3));
    const GuestAddress startRoutine = ctx.GetArgPtr(4);
    const uint32_t createFlags      = ctx.GetArg32(6);

    // Validate mandatory output pointer
    if (handleOutPtr == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Validate the process handle
    if (processHandle != kCurrentProcess && processHandle != kNullHandle) {
        auto entry = ctx.Handles().Lookup(processHandle, HandleType::Process);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    const bool isSelfProcess = IsCurrentProcessHandle(ctx, processHandle);
    const uint32_t ownerPid  = isSelfProcess
                             ? kEmulatedPID
                             : GetProcessHandlePID(ctx, processHandle);

    // Allocate a new TID
    const uint32_t newTID = s_nextTID++;

    // Determine initial suspend state
    const bool suspended = (createFlags & kThreadCreateSuspended) != 0;

    // Create the thread handle entry
    ThreadHandleData td{};
    td.tid        = newTID;
    td.ownerPid   = ownerPid;
    td.accessMask = desiredAccess;
    td.suspended  = suspended;

    GuestHandle handle = ctx.Handles().Create(HandleType::Thread, std::move(td));

    // Write the handle to the caller's output pointer
    auto err = WriteGuestPtr(mem, handleOutPtr, handle, is64);
    if (err != ErrorCode::Success) {
        ctx.Handles().Close(handle);
        ctx.SetReturnNtStatus(NT::STATUS_ACCESS_VIOLATION);
        return true;
    }

    // Start address and argument are captured automatically by the
    // dispatcher's CaptureArgs into the API call log (args[4] and args[5]).
    // The behavioral analysis engine can retrieve them from there.
    // Remote thread detection is handled by DetectBehaviors in the dispatcher.

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtResumeThread
// ============================================================================
// NTSTATUS NtResumeThread(
//     IN  HANDLE ThreadHandle,            // arg 0
//     OUT PULONG PreviousSuspendCount      // arg 1 (optional)
// );

bool HandleNtResumeThread(APIContext& ctx) {
    const bool is64 = ctx.Is64Bit();
    auto& mem       = ctx.Memory();

    const GuestHandle handle        = static_cast<GuestHandle>(ctx.GetArg(0));
    const GuestAddress prevCountPtr = ctx.GetArgPtr(1);

    // Validate handle
    if (handle != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(handle, HandleType::Thread);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    // Mark the thread as unsuspended
    if (handle == kCurrentThread) {
        // Current thread is always running — no state change needed
    } else {
        ctx.Handles().Modify<ThreadHandleData>(handle,
            [](ThreadHandleData& td) {
                td.suspended = false;
            });
    }

    // Write previous suspend count (1 = was suspended before this call)
    if (prevCountPtr != 0) {
        mem.WriteU32(prevCountPtr, 1);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtSuspendThread
// ============================================================================
// NTSTATUS NtSuspendThread(
//     IN  HANDLE ThreadHandle,            // arg 0
//     OUT PULONG PreviousSuspendCount      // arg 1 (optional)
// );

bool HandleNtSuspendThread(APIContext& ctx) {
    const bool is64 = ctx.Is64Bit();
    auto& mem       = ctx.Memory();

    const GuestHandle handle        = static_cast<GuestHandle>(ctx.GetArg(0));
    const GuestAddress prevCountPtr = ctx.GetArgPtr(1);

    // Validate handle
    if (handle != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(handle, HandleType::Thread);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
    }

    // Mark the thread as suspended
    if (handle != kCurrentThread) {
        ctx.Handles().Modify<ThreadHandleData>(handle,
            [](ThreadHandleData& td) {
                td.suspended = true;
            });
    }

    // Write previous suspend count (0 = was not suspended before this call)
    if (prevCountPtr != 0) {
        mem.WriteU32(prevCountPtr, 0);
    }

    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtTerminateThread
// ============================================================================
// NTSTATUS NtTerminateThread(
//     IN HANDLE   ThreadHandle,   // arg 0
//     IN NTSTATUS ExitStatus      // arg 1
// );
//
// If the target is the main thread, emulation must stop.

bool HandleNtTerminateThread(APIContext& ctx) {
    const GuestHandle handle = static_cast<GuestHandle>(ctx.GetArg(0));

    // Current-thread pseudo-handle → main thread in single-threaded emulation
    if (handle == kCurrentThread) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return false;  // Stop emulation
    }

    // Look up the thread handle
    auto entry = ctx.Handles().Lookup(handle, HandleType::Thread);
    if (!entry) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
        return true;
    }

    const auto& td = std::get<ThreadHandleData>(entry->data);

    // If this is the main thread, stop emulation
    if (td.tid == kMainThreadTID) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return false;  // Stop emulation
    }

    // Secondary thread: close the handle and continue
    ctx.Handles().Close(handle);
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// NtQueryInformationThread
// ============================================================================
// NTSTATUS NtQueryInformationThread(
//     IN  HANDLE          ThreadHandle,           // arg 0
//     IN  THREADINFOCLASS ThreadInformationClass,  // arg 1
//     OUT PVOID           ThreadInformation,        // arg 2
//     IN  ULONG           ThreadInformationLength,  // arg 3
//     OUT PULONG          ReturnLength OPTIONAL      // arg 4
// );

bool HandleNtQueryInformationThread(APIContext& ctx) {
    const bool is64 = ctx.Is64Bit();
    auto& mem       = ctx.Memory();

    const GuestHandle handle        = static_cast<GuestHandle>(ctx.GetArg(0));
    const uint32_t infoClass        = ctx.GetArg32(1);
    const GuestAddress infoBuffer   = ctx.GetArgPtr(2);
    const uint32_t infoLength       = ctx.GetArg32(3);
    const GuestAddress returnLenPtr = ctx.GetArgPtr(4);

    if (infoBuffer == 0) {
        ctx.SetReturnNtStatus(NT::STATUS_INVALID_PARAMETER);
        return true;
    }

    // Resolve TID and owner PID for the target thread
    uint32_t tid = kMainThreadTID;
    uint32_t ownerPid = kEmulatedPID;

    if (handle != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(handle, HandleType::Thread);
        if (!entry) {
            ctx.SetReturnNtStatus(NT::STATUS_INVALID_HANDLE);
            return true;
        }
        const auto& td = std::get<ThreadHandleData>(entry->data);
        tid      = td.tid;
        ownerPid = td.ownerPid;
    }

    switch (infoClass) {

    // ==================================================================
    // ThreadBasicInformation (0)
    // ==================================================================
    case kThreadBasicInformation: {
        const uint32_t requiredSize = is64 ? kTBI64Size : kTBI32Size;

        if (infoLength < requiredSize) {
            if (returnLenPtr != 0) {
                mem.WriteU32(returnLenPtr, requiredSize);
            }
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        const GuestAddress tebAddr = ComputeTebAddress(tid, is64);
        const uint64_t affinityMask =
            (1ULL << ctx.Config().processorCount) - 1;

        if (is64) {
            // x64 THREAD_BASIC_INFORMATION (48 bytes):
            //  0: NTSTATUS  ExitStatus        (4) + 4 pad
            //  8: PVOID     TebBaseAddress     (8)
            // 16: CLIENT_ID { UniqueProcess(8), UniqueThread(8) }
            // 32: KAFFINITY AffinityMask       (8)
            // 40: KPRIORITY Priority            (4)
            // 44: LONG      BasePriority        (4)
            uint8_t buf[48] = {};
            mem.Write(infoBuffer, buf, sizeof(buf));

            mem.WriteU32(infoBuffer + 0,  0);             // ExitStatus = STILL_ACTIVE
            mem.WriteU64(infoBuffer + 8,  tebAddr);       // TebBaseAddress
            mem.WriteU64(infoBuffer + 16, ownerPid);      // ClientId.UniqueProcess
            mem.WriteU64(infoBuffer + 24, tid);           // ClientId.UniqueThread
            mem.WriteU64(infoBuffer + 32, affinityMask);  // AffinityMask
            mem.WriteU32(infoBuffer + 40, 8);             // Priority (NORMAL)
            mem.WriteU32(infoBuffer + 44, 8);             // BasePriority
        } else {
            // x86 THREAD_BASIC_INFORMATION (28 bytes):
            //  0: NTSTATUS  ExitStatus        (4)
            //  4: PVOID     TebBaseAddress     (4)
            //  8: CLIENT_ID { UniqueProcess(4), UniqueThread(4) }
            // 16: KAFFINITY AffinityMask       (4)
            // 20: KPRIORITY Priority            (4)
            // 24: LONG      BasePriority        (4)
            uint8_t buf[28] = {};
            mem.Write(infoBuffer, buf, sizeof(buf));

            mem.WriteU32(infoBuffer + 0,  0);
            mem.WriteU32(infoBuffer + 4,  static_cast<uint32_t>(tebAddr));
            mem.WriteU32(infoBuffer + 8,  ownerPid);
            mem.WriteU32(infoBuffer + 12, tid);
            mem.WriteU32(infoBuffer + 16, static_cast<uint32_t>(affinityMask));
            mem.WriteU32(infoBuffer + 20, 8);
            mem.WriteU32(infoBuffer + 24, 8);
        }

        if (returnLenPtr != 0) {
            mem.WriteU32(returnLenPtr, requiredSize);
        }

        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // ==================================================================
    // ThreadIsImpersonating (37)
    // Returns 0 (ULONG): thread is NOT impersonating another token.
    // ==================================================================
    case kThreadIsImpersonating: {
        if (infoLength < 4) {
            if (returnLenPtr != 0) {
                mem.WriteU32(returnLenPtr, 4);
            }
            ctx.SetReturnNtStatus(NT::STATUS_INFO_LENGTH_MISMATCH);
            return true;
        }

        mem.WriteU32(infoBuffer, 0);  // Not impersonating

        if (returnLenPtr != 0) {
            mem.WriteU32(returnLenPtr, 4);
        }

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
// NtSetInformationThread
// ============================================================================
// NTSTATUS NtSetInformationThread(
//     IN HANDLE          ThreadHandle,           // arg 0
//     IN THREADINFOCLASS ThreadInformationClass,  // arg 1
//     IN PVOID           ThreadInformation,        // arg 2
//     IN ULONG           ThreadInformationLength   // arg 3
// );
//
// ThreadHideFromDebugger (0x11) is the MOST CRITICAL anti-debug indicator.
// Malware calls this to detach any debugger from the thread. We return
// STATUS_SUCCESS to convince the sample it succeeded, while the behavioral
// analysis engine flags AntiAnalysis via DetectBehaviors.

bool HandleNtSetInformationThread(APIContext& ctx) {
    const uint32_t infoClass = ctx.GetArg32(1);

    // ThreadHideFromDebugger (0x11): CRITICAL ANTI-DEBUG
    // The behavioral flag AntiAnalysis is automatically set by the
    // dispatcher's DetectBehaviors engine when it sees this info class
    // in the captured args. We return success to let the malware proceed.
    if (infoClass == kThreadHideFromDebugger) {
        ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
        return true;
    }

    // All other information classes: accept silently (no-op).
    // Real Windows would validate the buffer, but for emulation we simply
    // succeed to avoid blocking sample execution on benign calls.
    ctx.SetReturnNtStatus(NT::STATUS_SUCCESS);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterNtThread(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration regs[] = {
        { "ntdll.dll", "NtCreateThreadEx",
          HandleNtCreateThreadEx,          11, true },
        { "ntdll.dll", "NtResumeThread",
          HandleNtResumeThread,             2, true },
        { "ntdll.dll", "NtSuspendThread",
          HandleNtSuspendThread,            2, true },
        { "ntdll.dll", "NtTerminateThread",
          HandleNtTerminateThread,          2, true },
        { "ntdll.dll", "NtQueryInformationThread",
          HandleNtQueryInformationThread,   5, true },
        { "ntdll.dll", "NtSetInformationThread",
          HandleNtSetInformationThread,     4, true },
    };

    dispatcher.RegisterBatch(regs, static_cast<uint32_t>(std::size(regs)));
}

} // namespace WinAPI::Ntdll
} // namespace Phantom
