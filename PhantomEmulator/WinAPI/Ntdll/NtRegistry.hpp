/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtRegistry.hpp — Nt* registry syscall handlers
 *
 * Covers NtOpenKey, NtCreateKey, NtSetValueKey, NtQueryValueKey,
 * NtDeleteKey, NtDeleteValueKey, NtEnumerateKey, NtEnumerateValueKey.
 *
 * All operations target a virtual registry tree pre-populated with
 * realistic Windows 10 Pro values. Anti-VM keys (hardware descriptions,
 * BIOS info, MachineGuid) are populated with non-VM-artifact values.
 * Write operations to autostart locations (Run, RunOnce, Services)
 * are flagged as persistence indicators.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* registry handlers with the dispatcher.
void RegisterNtRegistry(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleNtOpenKey(APIContext& ctx);
bool HandleNtCreateKey(APIContext& ctx);
bool HandleNtSetValueKey(APIContext& ctx);
bool HandleNtQueryValueKey(APIContext& ctx);
bool HandleNtDeleteKey(APIContext& ctx);
bool HandleNtDeleteValueKey(APIContext& ctx);
bool HandleNtEnumerateKey(APIContext& ctx);
bool HandleNtEnumerateValueKey(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
