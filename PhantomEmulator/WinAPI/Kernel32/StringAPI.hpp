/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * StringAPI.hpp — Kernel32 string manipulation API handlers
 *
 * Covers lstrlenA/W, lstrcmpA/W, lstrcpyA/W,
 * MultiByteToWideChar, WideCharToMultiByte.
 *
 * All string operations cap reads/writes to prevent guest memory
 * exhaustion attacks.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 string manipulation handlers with the dispatcher.
void RegisterStringAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleLstrlenA(APIContext& ctx);
bool HandleLstrlenW(APIContext& ctx);
bool HandleLstrcmpA(APIContext& ctx);
bool HandleLstrcmpW(APIContext& ctx);
bool HandleLstrcpyA(APIContext& ctx);
bool HandleLstrcpyW(APIContext& ctx);
bool HandleMultiByteToWideChar(APIContext& ctx);
bool HandleWideCharToMultiByte(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
