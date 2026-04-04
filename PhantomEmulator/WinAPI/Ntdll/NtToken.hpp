/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * NtToken.hpp — Nt* token and privilege syscall handlers
 *
 * Covers NtOpenProcessToken, NtOpenThreadToken,
 * NtQueryInformationToken, and NtAdjustPrivilegesToken.
 *
 * Returns a fake elevated admin token so malware proceeds along
 * its privileged code path, exposing maximum behavioral surface.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ntdll {

// Register all Nt* token/privilege handlers with the dispatcher.
void RegisterNtToken(APIDispatcher& dispatcher) noexcept;

// Individual handlers — each follows the APIHandlerFn contract.
bool HandleNtOpenProcessToken(APIContext& ctx);
bool HandleNtOpenThreadToken(APIContext& ctx);
bool HandleNtQueryInformationToken(APIContext& ctx);
bool HandleNtAdjustPrivilegesToken(APIContext& ctx);

} // namespace WinAPI::Ntdll
} // namespace Phantom
