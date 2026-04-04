/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SyncAPI.hpp — Kernel32 synchronization API handlers
 *
 * Covers WaitForSingleObject, WaitForMultipleObjects,
 * CreateMutexA/W, CreateEventA/W, SetEvent, ResetEvent,
 * Sleep, SleepEx.
 *
 * Named mutex tracking catches infection markers used by
 * malware to prevent reinfection of already-compromised hosts.
 * Sleep acceleration prevents sandbox evasion through long delays.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 synchronization handlers with the dispatcher.
void RegisterSyncAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop
bool HandleWaitForSingleObject(APIContext& ctx);
bool HandleWaitForMultipleObjects(APIContext& ctx);
bool HandleCreateMutexA(APIContext& ctx);
bool HandleCreateMutexW(APIContext& ctx);
bool HandleCreateEventA(APIContext& ctx);
bool HandleCreateEventW(APIContext& ctx);
bool HandleSetEvent(APIContext& ctx);
bool HandleResetEvent(APIContext& ctx);
bool HandleSleep(APIContext& ctx);
bool HandleSleepEx(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
