/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * LibraryAPI.hpp — Kernel32 module/library management API handlers
 *
 * Covers LoadLibraryA/W, LoadLibraryExA/W, FreeLibrary,
 * GetProcAddress, GetModuleHandleA/W, GetModuleFileNameA/W.
 *
 * GetProcAddress is MISSION CRITICAL — the majority of malware
 * resolves API addresses dynamically to evade static imports.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 module/library handlers with the dispatcher.
void RegisterLibraryAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop
bool HandleLoadLibraryA(APIContext& ctx);
bool HandleLoadLibraryW(APIContext& ctx);
bool HandleLoadLibraryExA(APIContext& ctx);
bool HandleLoadLibraryExW(APIContext& ctx);
bool HandleFreeLibrary(APIContext& ctx);
bool HandleGetProcAddress(APIContext& ctx);
bool HandleGetModuleHandleA(APIContext& ctx);
bool HandleGetModuleHandleW(APIContext& ctx);
bool HandleGetModuleFileNameA(APIContext& ctx);
bool HandleGetModuleFileNameW(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
