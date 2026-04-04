/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SecurityAPI.hpp — Advapi32 security/token API handlers
 *
 * Covers OpenProcessToken, AdjustTokenPrivileges, LookupPrivilegeValueA/W,
 * GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf.
 *
 * All privilege requests succeed to allow malware to proceed along its
 * intended execution path while flagging PrivilegeEscalation behavior.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterSecurityAPI(APIDispatcher& dispatcher) noexcept;

bool HandleOpenProcessToken(APIContext& ctx);
bool HandleAdjustTokenPrivileges(APIContext& ctx);
bool HandleLookupPrivilegeValueA(APIContext& ctx);
bool HandleLookupPrivilegeValueW(APIContext& ctx);
bool HandleGetTokenInformation(APIContext& ctx);
bool HandleImpersonateLoggedOnUser(APIContext& ctx);
bool HandleRevertToSelf(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
