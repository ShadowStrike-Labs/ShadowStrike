/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtSync.hpp — Nt* synchronization and object syscall handlers
 *
 * Covers NtWaitForSingleObject, NtWaitForMultipleObjects,
 * NtCreateEvent, NtSetEvent, NtCreateMutant, NtOpenMutant,
 * NtOpenSection, and NtOpenKeyEx.
 *
 * Named synchronization primitives (mutexes, events) are critical
 * malware indicators — infection markers, single-instance checks,
 * and anti-analysis gates. All names are recorded for behavioral
 * analysis by the detection engine.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* synchronization and object handlers with the dispatcher.
void RegisterNtSync(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract:
//   bool Handler(APIContext& ctx);
//   Returns true  → execution continues
//   Returns false → execution should stop
bool HandleNtWaitForSingleObject(APIContext& ctx);
bool HandleNtWaitForMultipleObjects(APIContext& ctx);
bool HandleNtCreateEvent(APIContext& ctx);
bool HandleNtSetEvent(APIContext& ctx);
bool HandleNtCreateMutant(APIContext& ctx);
bool HandleNtOpenMutant(APIContext& ctx);
bool HandleNtOpenSection(APIContext& ctx);
bool HandleNtOpenKeyEx(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
