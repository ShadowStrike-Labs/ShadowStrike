/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ConsoleAPI.hpp — Kernel32 console and debug output API handlers
 *
 * Covers OutputDebugStringA/W, GetStdHandle, WriteConsoleA/W.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 console/debug output handlers with the dispatcher.
void RegisterConsoleAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleOutputDebugStringA(APIContext& ctx);
bool HandleOutputDebugStringW(APIContext& ctx);
bool HandleGetStdHandle(APIContext& ctx);
bool HandleWriteConsoleA(APIContext& ctx);
bool HandleWriteConsoleW(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
