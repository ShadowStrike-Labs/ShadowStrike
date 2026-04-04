/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ProcessAPI.hpp — Kernel32 process management API handlers
 *
 * Covers CreateProcessA/W, OpenProcess, TerminateProcess,
 * ExitProcess, GetCurrentProcessId, GetCurrentProcess,
 * GetExitCodeProcess, IsWow64Process.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 process management handlers with the dispatcher.
void RegisterProcessAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleCreateProcessA(APIContext& ctx);
bool HandleCreateProcessW(APIContext& ctx);
bool HandleOpenProcess(APIContext& ctx);
bool HandleTerminateProcess(APIContext& ctx);
bool HandleExitProcess(APIContext& ctx);
bool HandleGetCurrentProcessId(APIContext& ctx);
bool HandleGetCurrentProcess(APIContext& ctx);
bool HandleGetExitCodeProcess(APIContext& ctx);
bool HandleIsWow64Process(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
