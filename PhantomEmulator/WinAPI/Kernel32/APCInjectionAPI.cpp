/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APCInjectionAPI.cpp — Kernel32 APC injection, timer queue, and
 *                       deferred execution API implementations
 *
 * Every handler reads arguments from guest registers / guest stack via
 * APIContext, operates on HandleTable, and writes results back through
 * the context. No host OS calls are made.
 *
 * ENTERPRISE CRITICAL:
 *   - QueueUserAPC to a thread in another process is APC injection
 *     (T1055.004) — one of the stealthiest injection primitives.
 *   - Timer queue callbacks pointing to writable memory indicate
 *     shellcode staging through deferred execution.
 *   - RegisterWaitForSingleObject with W+X callbacks is a callback
 *     abuse vector for executing injected code.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "APCInjectionAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace Phantom::WinAPI::Kernel32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kFakeProcessId          = 4444;
static constexpr uint32_t kFakeMainThreadId       = 5555;

// Timer queue callback flags (matching Windows SDK)
static constexpr uint32_t WT_EXECUTEDEFAULT       = 0x00000000;
static constexpr uint32_t WT_EXECUTEINTIMERTHREAD  = 0x00000020;
static constexpr uint32_t WT_EXECUTEONLYONCE       = 0x00000008;

// SetTimer constants
static constexpr uint32_t USER_TIMER_MAXIMUM       = 0x7FFFFFFF;
static constexpr uint32_t kMinTimerElapse          = 10;  // USER_TIMER_MINIMUM

// Fake base addresses for timer queue objects
static constexpr uint64_t kFakeTimerQueueBase      = 0x0000BEEF'00010000ULL;
static constexpr uint64_t kFakeWaitHandle          = 0x0000BEEF'00020000ULL;
static constexpr uint64_t kFakeTimerIdBase         = 1000;

// Handle counter for timer queues and wait objects
static uint32_t s_nextTimerQueueId  = 1;
static uint32_t s_nextTimerId       = 1;
static uint32_t s_nextWaitId        = 1;

// Tracked timer IDs for SetTimer (UINT_PTR return values)
static uint32_t s_nextSetTimerId    = static_cast<uint32_t>(kFakeTimerIdBase);

// ============================================================================
// Helpers
// ============================================================================

static bool IsCallbackInWritableMemory(VirtualMemory& mem,
                                       GuestAddress callbackAddr) noexcept {
    if (callbackAddr == 0) return false;
    auto prot = mem.GetProtection(callbackAddr);
    if (!prot.has_value()) return false;
    return HasProt(*prot, MemProt::Write);
}

static bool IsCallbackInExecutableMemory(VirtualMemory& mem,
                                         GuestAddress callbackAddr) noexcept {
    if (callbackAddr == 0) return false;
    auto prot = mem.GetProtection(callbackAddr);
    if (!prot.has_value()) return false;
    return HasProt(*prot, MemProt::Execute);
}

static bool IsCallbackInWXMemory(VirtualMemory& mem,
                                 GuestAddress callbackAddr) noexcept {
    if (callbackAddr == 0) return false;
    auto prot = mem.GetProtection(callbackAddr);
    if (!prot.has_value()) return false;
    return HasProt(*prot, MemProt::Write) && HasProt(*prot, MemProt::Execute);
}

static bool IsSelfThread(GuestHandle hThread, const HandleTable& handles) noexcept {
    if (hThread == kCurrentThread) return true;
    auto entry = handles.Lookup(hThread, HandleType::Thread);
    if (!entry.has_value()) return false;
    const auto* td = std::get_if<ThreadHandleData>(&entry->data);
    return td && td->ownerPid == kFakeProcessId;
}

// ============================================================================
// QueueUserAPC — MITRE ATT&CK T1055.004 (APC Process Injection)
// ============================================================================
// Args: pfnAPC (0), hThread (1), dwData (2)
// Returns: BOOL — nonzero on success.
//
// When the target thread handle belongs to a different process, this is
// cross-process APC injection — an extremely stealthy injection technique.
// The APC routine runs when the target thread enters an alertable wait.

bool HandleQueueUserAPC(APIContext& ctx) {
    const auto pfnAPC  = ctx.GetArgPtr(0);
    const auto hThread = ctx.GetArg(1);
    const auto dwData  = ctx.GetArg(2);

    (void)dwData;

    if (pfnAPC == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Validate thread handle (accept pseudo-handles)
    if (hThread != kCurrentThread) {
        auto entry = ctx.Handles().Lookup(hThread, HandleType::Thread);
        if (!entry.has_value()) {
            ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
            return true;
        }
    }

    // Behavioral analysis: is this a cross-process or cross-thread APC?
    // The dispatcher records flags, but the handler sets them on the context
    // through the call detail. For self-thread APC (e.g., shellcode staging),
    // we still flag CodeInjection if the callback is in writable memory.
    // For cross-process APC, we flag ProcessInjection.
    //
    // Note: The behavioral flags here are informational — they are accumulated
    // by the dispatcher's RecordCall / DetectBehaviors path. The handler just
    // needs to return plausible values.

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// CreateTimerQueue
// ============================================================================
// Args: none
// Returns: HANDLE to the timer queue, or NULL on failure.

bool HandleCreateTimerQueue(APIContext& ctx) {
    SyncObjectData queueData{};
    queueData.name     = L"TimerQueue_" + std::to_wstring(s_nextTimerQueueId++);
    queueData.signaled = false;
    queueData.count    = 0;

    GuestHandle handle = ctx.Handles().Create(HandleType::Timer, queueData);
    if (handle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(handle);
    return true;
}

// ============================================================================
// CreateTimerQueueTimer
// ============================================================================
// Args: phNewTimer (0), TimerQueue (1), Callback (2), Parameter (3),
//       DueTime (4), Period (5), Flags (6)
// Returns: BOOL — nonzero on success. Writes new timer handle to *phNewTimer.
//
// If the callback points to writable memory, this is suspicious — legitimate
// code uses code-section callbacks, not heap/stack addresses.

bool HandleCreateTimerQueueTimer(APIContext& ctx) {
    const auto phNewTimer   = ctx.GetArgPtr(0);
    const auto hTimerQueue  = ctx.GetArg(1);
    const auto pfnCallback  = ctx.GetArgPtr(2);
    const auto pvParameter  = ctx.GetArg(3);
    const auto dwDueTime    = ctx.GetArg32(4);
    const auto dwPeriod     = ctx.GetArg32(5);
    const auto dwFlags      = ctx.GetArg32(6);

    (void)pvParameter;
    (void)dwDueTime;
    (void)dwPeriod;
    (void)dwFlags;

    if (phNewTimer == 0 || pfnCallback == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Validate timer queue handle if not the default queue (NULL)
    if (hTimerQueue != kNullHandle) {
        if (!ctx.Handles().IsValid(hTimerQueue)) {
            ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
            return true;
        }
    }

    // Create a timer handle entry
    SyncObjectData timerData{};
    timerData.name     = L"Timer_" + std::to_wstring(s_nextTimerId++);
    timerData.signaled = false;
    timerData.count    = 0;

    GuestHandle timerHandle = ctx.Handles().Create(HandleType::Timer, timerData);
    if (timerHandle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Write the new timer handle to the output pointer
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phNewTimer, timerHandle);
    } else {
        ctx.Memory().WriteU32(phNewTimer, static_cast<uint32_t>(timerHandle));
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// DeleteTimerQueueTimer
// ============================================================================
// Args: TimerQueue (0), Timer (1), CompletionEvent (2)
// Returns: BOOL — nonzero on success.

bool HandleDeleteTimerQueueTimer(APIContext& ctx) {
    const auto hTimerQueue     = ctx.GetArg(0);
    const auto hTimer          = ctx.GetArg(1);
    const auto hCompletionEvent = ctx.GetArg(2);

    (void)hTimerQueue;
    (void)hCompletionEvent;

    if (hTimer != kNullHandle && ctx.Handles().IsValid(hTimer)) {
        ctx.Handles().Close(hTimer);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// DeleteTimerQueueEx
// ============================================================================
// Args: TimerQueue (0), CompletionEvent (1)
// Returns: BOOL — nonzero on success.

bool HandleDeleteTimerQueueEx(APIContext& ctx) {
    const auto hTimerQueue      = ctx.GetArg(0);
    const auto hCompletionEvent = ctx.GetArg(1);

    (void)hCompletionEvent;

    if (hTimerQueue != kNullHandle && ctx.Handles().IsValid(hTimerQueue)) {
        ctx.Handles().Close(hTimerQueue);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// SetTimer (User32-style, but often resolved via Kernel32 forwarding)
// ============================================================================
// Args: hWnd (0), nIDEvent (1), uElapse (2), lpTimerFunc (3)
// Returns: UINT_PTR timer ID (nonzero on success), 0 on failure.
//
// If lpTimerFunc points to suspicious memory, this could be a callback-based
// code execution technique.

bool HandleSetTimer(APIContext& ctx) {
    const auto hWnd        = ctx.GetArg(0);
    const auto nIDEvent    = ctx.GetArg(1);
    const auto uElapse     = ctx.GetArg32(2);
    const auto lpTimerFunc = ctx.GetArgPtr(3);

    (void)hWnd;
    (void)uElapse;

    // Return a timer ID. If hWnd is NULL and nIDEvent is 0, Windows assigns one.
    uint64_t timerId = (nIDEvent != 0) ? nIDEvent : s_nextSetTimerId++;

    // Suspicious callback detection is handled by the dispatcher's behavioral
    // analysis. The handler returns a plausible timer ID.

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(timerId);
    return true;
}

// ============================================================================
// RegisterWaitForSingleObject
// ============================================================================
// Args: phNewWaitObject (0), hObject (1), Callback (2), Context (3),
//       dwMilliseconds (4), dwFlags (5)
// Returns: BOOL — nonzero on success.
//
// If the callback is in W+X memory, this is a strong indicator of shellcode
// execution through wait callback abuse.

bool HandleRegisterWaitForSingleObject(APIContext& ctx) {
    const auto phNewWaitObject = ctx.GetArgPtr(0);
    const auto hObject         = ctx.GetArg(1);
    const auto pfnCallback     = ctx.GetArgPtr(2);
    const auto pvContext        = ctx.GetArg(3);
    const auto dwMilliseconds  = ctx.GetArg32(4);
    const auto dwFlags         = ctx.GetArg32(5);

    (void)hObject;
    (void)pvContext;
    (void)dwMilliseconds;
    (void)dwFlags;

    if (phNewWaitObject == 0 || pfnCallback == 0) {
        ctx.FailWithError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Create a tracked wait object
    SyncObjectData waitData{};
    waitData.name     = L"WaitObject_" + std::to_wstring(s_nextWaitId++);
    waitData.signaled = false;
    waitData.count    = 0;

    GuestHandle waitHandle = ctx.Handles().Create(HandleType::Event, waitData);
    if (waitHandle == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Write the wait handle to the output pointer
    if (ctx.Is64Bit()) {
        ctx.Memory().WriteU64(phNewWaitObject, waitHandle);
    } else {
        ctx.Memory().WriteU32(phNewWaitObject, static_cast<uint32_t>(waitHandle));
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// UnregisterWait
// ============================================================================
// Args: WaitHandle (0)
// Returns: BOOL — nonzero on success.

bool HandleUnregisterWait(APIContext& ctx) {
    const auto hWaitHandle = ctx.GetArg(0);

    if (hWaitHandle != kNullHandle && ctx.Handles().IsValid(hWaitHandle)) {
        ctx.Handles().Close(hWaitHandle);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterAPCInjectionAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "kernel32.dll", "QueueUserAPC",
          HandleQueueUserAPC, 3, true },
        { "kernel32.dll", "CreateTimerQueue",
          HandleCreateTimerQueue, 0, false },
        { "kernel32.dll", "CreateTimerQueueTimer",
          HandleCreateTimerQueueTimer, 7, false },
        { "kernel32.dll", "DeleteTimerQueueTimer",
          HandleDeleteTimerQueueTimer, 3, false },
        { "kernel32.dll", "DeleteTimerQueueEx",
          HandleDeleteTimerQueueEx, 2, false },
        { "user32.dll", "SetTimer",
          HandleSetTimer, 4, false },
        { "kernel32.dll", "RegisterWaitForSingleObject",
          HandleRegisterWaitForSingleObject, 6, false },
        { "kernel32.dll", "UnregisterWait",
          HandleUnregisterWait, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Kernel32
