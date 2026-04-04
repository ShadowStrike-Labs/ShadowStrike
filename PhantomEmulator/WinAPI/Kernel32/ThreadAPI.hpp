/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ThreadAPI.hpp — Kernel32 thread management API handlers
 *
 * Covers CreateThread, CreateRemoteThread/Ex, ResumeThread,
 * SuspendThread, TerminateThread, ExitThread, GetCurrentThreadId,
 * GetCurrentThread, SetThreadContext, GetThreadContext.
 *
 * CreateRemoteThread detection is ENTERPRISE CRITICAL — it is the
 * #1 technique for cross-process code injection.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 thread management handlers with the dispatcher.
void RegisterThreadAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop
bool HandleCreateThread(APIContext& ctx);
bool HandleCreateRemoteThread(APIContext& ctx);
bool HandleCreateRemoteThreadEx(APIContext& ctx);
bool HandleResumeThread(APIContext& ctx);
bool HandleSuspendThread(APIContext& ctx);
bool HandleTerminateThread(APIContext& ctx);
bool HandleExitThread(APIContext& ctx);
bool HandleGetCurrentThreadId(APIContext& ctx);
bool HandleGetCurrentThread(APIContext& ctx);
bool HandleSetThreadContext(APIContext& ctx);
bool HandleGetThreadContext(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
