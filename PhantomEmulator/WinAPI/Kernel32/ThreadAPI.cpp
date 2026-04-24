/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ThreadAPI.cpp — Kernel32 thread management API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL: CreateRemoteThread detection is the #1 signal
 * for cross-process code injection (DLL injection, shellcode injection,
 * process hollowing chains). SetThreadContext is the second half of
 * the process hollowing technique.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "ThreadAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

// DESIGN: CONTEXT writeback, thread-id writeback and HandleTable::Modify are
// all best-effort side effects. A partial guest-memory write is a guest-side
// access violation the caller must cope with; the Win32 BOOL result is
// driven off the preceding validated Lookup. Pragma is namespace-scoped and
// every handle-lookup / input-validation return is still checked explicitly.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kCreateSuspended       = 0x00000004;
static constexpr uint32_t kFakeMainThreadId       = 5555;
static constexpr uint32_t kFakeProcessId          = 4444;
static constexpr uint32_t kFakeRemoteProcessId    = 8888;
static constexpr uint32_t kContextFull            = 0x10001F;

// Thread ID counter — monotonically increasing to avoid collisions.
static uint32_t s_nextThreadId = kFakeMainThreadId + 1;

// ============================================================================
// Helpers
// ============================================================================

static bool IsSelfProcess(GuestHandle handle) noexcept {
    return handle == kCurrentProcess || handle == kNullHandle;
}

// DESIGN: classify a thread start address. Shellcode / reflective loaders
// land RIP on anonymous RWX private memory; legitimate threads land on
// image-backed executable-readonly pages. We cannot perfectly distinguish
// "image section" vs "private" here without walking the VAD tree, but the
// single most reliable cross-cutting heuristic is "start address sits on a
// writable-executable page", which no compiler toolchain emits in 2026.
enum class StartAddrClass {
    ImageBacked,     // executable but not writable — benign pattern
    WritableExec,    // RWX private memory — shellcode signature
    NonExecutable,   // start address has no X bit — will fault on first
                     // fetch; still an IOC of a bad / hollowed RIP target
    Unbacked         // address has no mapping at all — deliberate-AV tricks
};

[[nodiscard]] static StartAddrClass
ClassifyStartAddress(const VirtualMemory& mem, GuestAddress startAddr) noexcept {
    auto protOpt = mem.GetProtection(startAddr);
    if (!protOpt.has_value()) {
        return StartAddrClass::Unbacked;
    }
    const MemProt prot = protOpt.value();
    const bool hasExec  = HasProt(prot, MemProt::Execute);
    const bool hasWrite = HasProt(prot, MemProt::Write);
    if (!hasExec)        return StartAddrClass::NonExecutable;
    if (hasWrite)        return StartAddrClass::WritableExec;
    return StartAddrClass::ImageBacked;
}

// Emit the behaviour flags associated with a CreateThread-family start
// address. `remote` tightens the verdict — a RWX private destination in
// another process is the unambiguous T1055.002 shellcode pattern.
static void EmitStartAddrIOCs(APIContext& ctx, StartAddrClass c, bool remote) noexcept {
    switch (c) {
        case StartAddrClass::WritableExec:
            ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
            if (remote) {
                ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
            }
            break;
        case StartAddrClass::Unbacked:
        case StartAddrClass::NonExecutable:
            // A thread whose start address isn't executable will fault on
            // first fetch; this is occasionally seen in packers that pre-
            // allocate a stub page and expect VirtualProtect to be called
            // externally, but it is never a benign code path.
            ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
            break;
        case StartAddrClass::ImageBacked:
            // Benign pattern — do not flag.
            break;
    }
}

// ============================================================================
// CreateThread
// ============================================================================
// Args: lpThreadAttributes (0), dwStackSize (1), lpStartAddress (2),
//       lpParameter (3), dwCreationFlags (4), lpThreadId (5)

bool HandleCreateThread(APIContext& ctx) {
    // arg0: lpThreadAttributes (ignored in emulation)
    const auto dwStackSize    = ctx.GetArg(1);
    const auto lpStartAddress = ctx.GetArgPtr(2);
    const auto lpParameter    = ctx.GetArg(3);
    const auto dwCreationFlags = ctx.GetArg32(4);
    const auto lpThreadId     = ctx.GetArgPtr(5);

    (void)dwStackSize;
    (void)lpParameter;

    // IOC: classify the start address before doing anything else. A RWX
    // private start address — even in-process — is the shellcode pattern
    // every packer / MSF / Cobalt Strike loader eventually executes.
    const auto startClass = ClassifyStartAddress(ctx.Memory(), lpStartAddress);
    EmitStartAddrIOCs(ctx, startClass, /*remote=*/false);

    const uint32_t newTid = s_nextThreadId++;

    ThreadHandleData threadData{};
    threadData.tid       = newTid;
    threadData.ownerPid  = kFakeProcessId;
    threadData.accessMask = NT::THREAD_ALL_ACCESS;
    threadData.suspended = (dwCreationFlags & kCreateSuspended) != 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Thread, threadData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    if (lpThreadId != 0) {
        ctx.Memory().WriteU32(lpThreadId, newTid);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateRemoteThread — ENTERPRISE CRITICAL: #1 injection technique
// ============================================================================
// Args: hProcess (0), lpThreadAttributes (1), dwStackSize (2),
//       lpStartAddress (3), lpParameter (4), dwCreationFlags (5),
//       lpThreadId (6)
//
// If the target process handle is not self, this is a remote thread
// injection — the most common code injection technique.

bool HandleCreateRemoteThread(APIContext& ctx) {
    const auto hProcess        = ctx.GetArg(0);
    // arg1: lpThreadAttributes (ignored)
    const auto dwStackSize     = ctx.GetArg(1);
    const auto lpStartAddress  = ctx.GetArgPtr(3);
    const auto lpParameter     = ctx.GetArg(4);
    const auto dwCreationFlags = ctx.GetArg32(5);
    const auto lpThreadId      = ctx.GetArgPtr(6);

    (void)dwStackSize;
    (void)lpParameter;

    const bool isRemote = !IsSelfProcess(hProcess);

    // IOC: remote thread creation — baseline T1055 ProcessInjection +
    // RemoteThreadCreation; when the start address is RWX/unbacked the
    // verdict escalates through EmitStartAddrIOCs().
    if (isRemote) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::RemoteThreadCreation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }
    const auto startClass = ClassifyStartAddress(ctx.Memory(), lpStartAddress);
    EmitStartAddrIOCs(ctx, startClass, isRemote);

    const uint32_t newTid = s_nextThreadId++;
    const uint32_t ownerPid = isRemote ? kFakeRemoteProcessId : kFakeProcessId;

    ThreadHandleData threadData{};
    threadData.tid       = newTid;
    threadData.ownerPid  = ownerPid;
    threadData.accessMask = NT::THREAD_ALL_ACCESS;
    threadData.suspended = (dwCreationFlags & kCreateSuspended) != 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Thread, threadData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Write thread ID to output pointer if non-null
    if (lpThreadId != 0) {
        ctx.Memory().WriteU32(lpThreadId, newTid);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateRemoteThreadEx — Same as CreateRemoteThread + attribute list
// ============================================================================
// Args: hProcess (0), lpThreadAttributes (1), dwStackSize (2),
//       lpStartAddress (3), lpParameter (4), dwCreationFlags (5),
//       lpAttributeList (6), lpThreadId (7)

bool HandleCreateRemoteThreadEx(APIContext& ctx) {
    const auto hProcess        = ctx.GetArg(0);
    // arg1: lpThreadAttributes (ignored)
    const auto lpStartAddress  = ctx.GetArgPtr(3);
    const auto lpParameter     = ctx.GetArg(4);
    const auto dwCreationFlags = ctx.GetArg32(5);
    // arg6: lpAttributeList (ignored in emulation)
    const auto lpThreadId      = ctx.GetArgPtr(7);

    (void)lpParameter;

    const bool isRemote = !IsSelfProcess(hProcess);

    // IOC: remote thread creation via the Ex variant carries the same
    // semantic load as CreateRemoteThread.
    if (isRemote) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::RemoteThreadCreation);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }
    const auto startClassEx = ClassifyStartAddress(ctx.Memory(), lpStartAddress);
    EmitStartAddrIOCs(ctx, startClassEx, isRemote);

    const uint32_t newTid = s_nextThreadId++;
    const uint32_t ownerPid = isRemote ? kFakeRemoteProcessId : kFakeProcessId;

    ThreadHandleData threadData{};
    threadData.tid       = newTid;
    threadData.ownerPid  = ownerPid;
    threadData.accessMask = NT::THREAD_ALL_ACCESS;
    threadData.suspended = (dwCreationFlags & kCreateSuspended) != 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Thread, threadData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    if (lpThreadId != 0) {
        ctx.Memory().WriteU32(lpThreadId, newTid);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// ResumeThread
// ============================================================================
// Args: hThread (0)
// Returns: Previous suspend count (DWORD), or (DWORD)-1 on error.

bool HandleResumeThread(APIContext& ctx) {
    const auto hThread = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hThread, HandleType::Thread);
    if (!entry.has_value()) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(static_cast<uint64_t>(0xFFFFFFFF));
        return true;
    }

    // Mark unsuspended; return previous suspend count (1 if was suspended, 0 otherwise)
    const auto* td = std::get_if<ThreadHandleData>(&entry->data);

    // IOC: resuming a thread that belongs to another process is the final
    // step of process hollowing / thread-hijack chains (CreateProcess
    // SUSPENDED → unmap → alloc → write → SetThreadContext → ResumeThread).
    if (td && td->ownerPid != kFakeProcessId) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessHollowing);
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    uint32_t previousCount = (td && td->suspended) ? 1u : 0u;

    ctx.Handles().Modify<ThreadHandleData>(hThread, [](ThreadHandleData& data) {
        data.suspended = false;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(previousCount);
    return true;
}

// ============================================================================
// SuspendThread
// ============================================================================
// Args: hThread (0)
// Returns: Previous suspend count (DWORD), or (DWORD)-1 on error.

bool HandleSuspendThread(APIContext& ctx) {
    const auto hThread = ctx.GetArg(0);

    auto entry = ctx.Handles().Lookup(hThread, HandleType::Thread);
    if (!entry.has_value()) {
        ctx.SetLastError(Win32::ERROR_INVALID_HANDLE);
        ctx.SetReturn(static_cast<uint64_t>(0xFFFFFFFF));
        return true;
    }

    const auto* td = std::get_if<ThreadHandleData>(&entry->data);

    // IOC: suspending a thread in another process precedes
    // SetThreadContext-based thread execution hijack (T1055.003).
    if (td && td->ownerPid != kFakeProcessId) {
        ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    }

    uint32_t previousCount = (td && td->suspended) ? 1u : 0u;

    ctx.Handles().Modify<ThreadHandleData>(hThread, [](ThreadHandleData& data) {
        data.suspended = true;
    });

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(previousCount);
    return true;
}

// ============================================================================
// TerminateThread
// ============================================================================
// Args: hThread (0), dwExitCode (1)

bool HandleTerminateThread(APIContext& ctx) {
    const auto hThread   = ctx.GetArg(0);
    const auto dwExitCode = ctx.GetArg32(1);

    (void)dwExitCode;

    if (!ctx.Handles().IsValid(hThread)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    ctx.Handles().Close(hThread);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// ExitThread
// ============================================================================
// Args: dwExitCode (0)
// Returns: false to stop emulation if this is the main thread.
// ExitThread has no return value (VOID), so we do not set RAX.

bool HandleExitThread(APIContext& ctx) {
    const auto dwExitCode = ctx.GetArg32(0);
    (void)dwExitCode;

    // If this is the main (only) emulated thread, stop emulation.
    // In our single-threaded emulation model, ExitThread always halts.
    return false;
}

// ============================================================================
// GetCurrentThreadId
// ============================================================================
// Args: none
// Returns: DWORD thread ID

bool HandleGetCurrentThreadId(APIContext& ctx) {
    ctx.SetReturn(kFakeMainThreadId);
    return true;
}

// ============================================================================
// GetCurrentThread
// ============================================================================
// Args: none
// Returns: pseudo-handle (HANDLE)-2

bool HandleGetCurrentThread(APIContext& ctx) {
    ctx.SetReturnHandle(kCurrentThread);
    return true;
}

// ============================================================================
// SetThreadContext — Used in process hollowing
// ============================================================================
// Args: hThread (0), lpContext (1)
//
// Process hollowing sequence: CreateProcess(SUSPENDED) → NtUnmapViewOfSection
// → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread.
// SetThreadContext sets RIP/EIP to the injected code entry point.
// We flag CodeInjection behavior here.

bool HandleSetThreadContext(APIContext& ctx) {
    const auto hThread  = ctx.GetArg(0);
    const auto lpContext = ctx.GetArgPtr(1);

    if (lpContext == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto entry = ctx.Handles().Lookup(hThread, HandleType::Thread);
    // Accept pseudo-handle kCurrentThread as well
    if (!entry.has_value() && hThread != kCurrentThread) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // IOC: SetThreadContext is the second half of T1055.012 process
    // hollowing (redirects RIP/EIP to injected code); when the target
    // belongs to another process the verdict escalates to ProcessHollowing.
    ctx.AddBehaviorFlag(BehaviorFlag::CodeInjection);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);
    if (entry.has_value()) {
        const auto* td = std::get_if<ThreadHandleData>(&entry->data);
        if (td && td->ownerPid != kFakeProcessId) {
            ctx.AddBehaviorFlag(BehaviorFlag::ProcessHollowing);
            ctx.AddBehaviorFlag(BehaviorFlag::ProcessInjection);
        }
    }

    // No actual context modification in emulation — the behavioral flag
    // (CodeInjection) is raised above.

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// GetThreadContext
// ============================================================================
// Args: hThread (0), lpContext (1)
//
// Fills a fake CONTEXT structure. Malware reads CONTEXT to check for
// debug registers (DR0-DR3) or to extract the EIP/RIP of a suspended thread.

bool HandleGetThreadContext(APIContext& ctx) {
    const auto hThread   = ctx.GetArg(0);
    const auto lpContext  = ctx.GetArgPtr(1);

    if (lpContext == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto entry = ctx.Handles().Lookup(hThread, HandleType::Thread);
    if (!entry.has_value() && hThread != kCurrentThread) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    auto& mem = ctx.Memory();

    if (ctx.Is64Bit()) {
        // x64 CONTEXT structure — fill key fields with plausible values.
        // Offset 0x30: ContextFlags
        mem.WriteU32(lpContext + 0x30, kContextFull);

        // Debug registers — zeroed (clean: no hardware breakpoints)
        mem.WriteU64(lpContext + 0x38, 0); // Dr0
        mem.WriteU64(lpContext + 0x40, 0); // Dr1
        mem.WriteU64(lpContext + 0x48, 0); // Dr2
        mem.WriteU64(lpContext + 0x50, 0); // Dr3
        mem.WriteU64(lpContext + 0x58, 0); // Dr6
        mem.WriteU64(lpContext + 0x60, 0); // Dr7

        // EFlags at offset 0x44 in the CONTEXT_FLAGS area... use standard offset
        // Rax at offset 0x78, Rcx at 0x80, etc. — fill with current CPU state
        mem.WriteU64(lpContext + 0x78, ctx.CPU().RAX());
        mem.WriteU64(lpContext + 0x80, ctx.CPU().RCX());
        mem.WriteU64(lpContext + 0x88, ctx.CPU().RDX());
        mem.WriteU64(lpContext + 0x90, ctx.CPU().RBX());
        mem.WriteU64(lpContext + 0x98, ctx.CPU().RSP());
        mem.WriteU64(lpContext + 0xA0, ctx.CPU().RBP());
        mem.WriteU64(lpContext + 0xA8, ctx.CPU().RSI());
        mem.WriteU64(lpContext + 0xB0, ctx.CPU().RDI());
        // Rip at offset 0xF8
        mem.WriteU64(lpContext + 0xF8, ctx.CPU().GetRIP());
    } else {
        // x86 CONTEXT structure
        // Offset 0x00: ContextFlags
        mem.WriteU32(lpContext + 0x00, kContextFull);

        // Debug registers at offsets 0x04-0x18 — zeroed
        mem.WriteU32(lpContext + 0x04, 0); // Dr0
        mem.WriteU32(lpContext + 0x08, 0); // Dr1
        mem.WriteU32(lpContext + 0x0C, 0); // Dr2
        mem.WriteU32(lpContext + 0x10, 0); // Dr3
        mem.WriteU32(lpContext + 0x14, 0); // Dr6
        mem.WriteU32(lpContext + 0x18, 0); // Dr7

        // GPRs starting at offset 0x9C
        mem.WriteU32(lpContext + 0x9C, ctx.CPU().GetReg32(GPR::RDI));  // Edi
        mem.WriteU32(lpContext + 0xA0, ctx.CPU().GetReg32(GPR::RSI));  // Esi
        mem.WriteU32(lpContext + 0xA4, ctx.CPU().GetReg32(GPR::RBX));  // Ebx
        mem.WriteU32(lpContext + 0xA8, ctx.CPU().GetReg32(GPR::RDX));  // Edx
        mem.WriteU32(lpContext + 0xAC, ctx.CPU().GetReg32(GPR::RCX));  // Ecx
        mem.WriteU32(lpContext + 0xB0, ctx.CPU().GetReg32(GPR::RAX));  // Eax
        mem.WriteU32(lpContext + 0xB4, ctx.CPU().GetReg32(GPR::RBP));  // Ebp
        // Eip at offset 0xB8
        mem.WriteU32(lpContext + 0xB8, static_cast<uint32_t>(ctx.CPU().GetRIP()));
        // Esp at offset 0xC4
        mem.WriteU32(lpContext + 0xC4, ctx.CPU().GetReg32(GPR::RSP));
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterThreadAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "CreateThread",
          HandleCreateThread, 6, false },
        { "kernel32.dll", "CreateRemoteThread",
          HandleCreateRemoteThread, 7, true },
        { "kernel32.dll", "CreateRemoteThreadEx",
          HandleCreateRemoteThreadEx, 8, true },
        { "kernel32.dll", "ResumeThread",
          HandleResumeThread, 1, false },
        { "kernel32.dll", "SuspendThread",
          HandleSuspendThread, 1, false },
        { "kernel32.dll", "TerminateThread",
          HandleTerminateThread, 2, false },
        { "kernel32.dll", "ExitThread",
          HandleExitThread, 1, false },
        { "kernel32.dll", "GetCurrentThreadId",
          HandleGetCurrentThreadId, 0, false },
        { "kernel32.dll", "GetCurrentThread",
          HandleGetCurrentThread, 0, false },
        { "kernel32.dll", "SetThreadContext",
          HandleSetThreadContext, 2, true },
        { "kernel32.dll", "GetThreadContext",
          HandleGetThreadContext, 2, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32

#pragma warning(pop)
