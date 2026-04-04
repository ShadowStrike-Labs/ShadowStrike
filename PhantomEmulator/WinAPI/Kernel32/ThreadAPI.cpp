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

    // Write thread ID to output pointer if non-null
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

    // No actual context modification in emulation — the behavioral flag
    // (CodeInjection) is raised by the dispatcher's DetectBehaviors via
    // the registration metadata.

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
