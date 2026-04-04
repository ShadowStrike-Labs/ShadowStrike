/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtThread.hpp — Nt* thread management syscall handlers
 *
 * Covers NtCreateThreadEx, NtResumeThread, NtSuspendThread,
 * NtTerminateThread, NtQueryInformationThread, and
 * NtSetInformationThread (including ThreadHideFromDebugger
 * anti-debug detection).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* thread handlers with the dispatcher.
void RegisterNtThread(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop (e.g., main thread termination)
bool HandleNtCreateThreadEx(APIContext& ctx);
bool HandleNtResumeThread(APIContext& ctx);
bool HandleNtSuspendThread(APIContext& ctx);
bool HandleNtTerminateThread(APIContext& ctx);
bool HandleNtQueryInformationThread(APIContext& ctx);
bool HandleNtSetInformationThread(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
