/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TimeAPI.hpp — Kernel32 timing API handlers
 *
 * Covers GetTickCount, GetTickCount64, QueryPerformanceCounter,
 * QueryPerformanceFrequency, GetSystemTime, GetLocalTime,
 * GetSystemTimeAsFileTime.
 *
 * CRITICAL: All timing functions MUST be mutually consistent.
 * Malware uses paired timing calls (e.g., GetTickCount + QPC) to
 * detect emulation speedup or timing inconsistency.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Kernel32 {

// Register all Kernel32 timing handlers with the dispatcher.
void RegisterTimeAPI(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleGetTickCount(APIContext& ctx);
bool HandleGetTickCount64(APIContext& ctx);
bool HandleQueryPerformanceCounter(APIContext& ctx);
bool HandleQueryPerformanceFrequency(APIContext& ctx);
bool HandleGetSystemTime(APIContext& ctx);
bool HandleGetLocalTime(APIContext& ctx);
bool HandleGetSystemTimeAsFileTime(APIContext& ctx);

} // namespace WinAPI::Kernel32
} // namespace Phantom
