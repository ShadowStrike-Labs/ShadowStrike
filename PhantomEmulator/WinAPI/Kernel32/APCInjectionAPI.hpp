/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * APCInjectionAPI.hpp — Kernel32 APC injection, timer queue, and
 *                       deferred execution API handlers
 *
 * Covers QueueUserAPC, CreateTimerQueueTimer, DeleteTimerQueueTimer,
 * CreateTimerQueue, DeleteTimerQueueEx, SetTimer,
 * RegisterWaitForSingleObject, UnregisterWait.
 *
 * ENTERPRISE CRITICAL:
 *   - QueueUserAPC is MITRE ATT&CK T1055.004 (APC process injection).
 *     Cross-process APC queueing is one of the stealthiest injection
 *     techniques — harder to detect than CreateRemoteThread.
 *   - Timer queues enable delayed/periodic execution — used for
 *     persistence, staged payload delivery, and sandbox evasion.
 *   - RegisterWaitForSingleObject with W+X callbacks indicates
 *     shellcode execution through callback abuse.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all APC injection / timer queue handlers with the dispatcher.
void RegisterAPCInjectionAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

// APC injection — MITRE T1055.004
bool HandleQueueUserAPC(APIContext& ctx);

// Timer queue management — delayed/periodic execution
bool HandleCreateTimerQueue(APIContext& ctx);
bool HandleCreateTimerQueueTimer(APIContext& ctx);
bool HandleDeleteTimerQueueTimer(APIContext& ctx);
bool HandleDeleteTimerQueueEx(APIContext& ctx);

// Classic SetTimer callback registration
bool HandleSetTimer(APIContext& ctx);

// Wait callback registration — callback abuse detection
bool HandleRegisterWaitForSingleObject(APIContext& ctx);
bool HandleUnregisterWait(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
