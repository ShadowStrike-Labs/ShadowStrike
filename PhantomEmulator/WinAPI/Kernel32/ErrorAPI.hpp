/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ErrorAPI.hpp — Kernel32 error handling and anti-debug API handlers
 *
 * Covers SetLastError, GetLastError, IsDebuggerPresent,
 * CheckRemoteDebuggerPresent.
 *
 * MISSION CRITICAL: IsDebuggerPresent and CheckRemoteDebuggerPresent
 * must ALWAYS return FALSE. Malware universally checks these to
 * detect analysis environments.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 error/anti-debug handlers with the dispatcher.
void RegisterErrorAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleSetLastError(APIContext& ctx);
bool HandleGetLastError(APIContext& ctx);
bool HandleIsDebuggerPresent(APIContext& ctx);
bool HandleCheckRemoteDebuggerPresent(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
