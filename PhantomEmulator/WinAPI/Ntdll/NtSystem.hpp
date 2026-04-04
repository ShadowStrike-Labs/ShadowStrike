/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtSystem.hpp — Nt* system information, timing, and object syscall handlers
 *
 * Covers NtQuerySystemInformation, NtQueryPerformanceCounter,
 * NtDelayExecution, NtDuplicateObject, and NtQueryObject.
 *
 * These handlers are MISSION CRITICAL for anti-evasion. Malware uses
 * NtQuerySystemInformation to detect VMs, sandboxes, and debuggers
 * by inspecting process lists, firmware tables, kernel debugger state,
 * and code integrity information. Every response must match a real
 * Windows 10 Pro workstation to defeat fingerprinting.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* system info, timing, and object handlers with the dispatcher.
void RegisterNtSystem(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop

// Anti-evasion critical: returns system info matching a real workstation.
bool HandleNtQuerySystemInformation(APIContext& ctx);

// Monotonically increasing performance counter (anti-timing-detection).
bool HandleNtQueryPerformanceCounter(APIContext& ctx);

// Sleep/delay with optional timing acceleration and evasion detection.
bool HandleNtDelayExecution(APIContext& ctx);

// Handle duplication via the handle table.
bool HandleNtDuplicateObject(APIContext& ctx);

// Object type/name queries for handle introspection.
bool HandleNtQueryObject(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
