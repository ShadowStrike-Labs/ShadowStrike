/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ServiceAPI.hpp — Advapi32 Service Control Manager API handlers
 *
 * Covers OpenSCManagerA/W, CreateServiceA/W, StartServiceA/W,
 * OpenServiceA/W, DeleteService, CloseServiceHandle.
 *
 * Service creation and manipulation are high-value IOCs for persistence
 * (MITRE T1543.003). All operations are flagged as ServiceManipulation.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterServiceAPI(APIDispatcher& dispatcher) noexcept;

bool HandleOpenSCManagerA(APIContext& ctx);
bool HandleOpenSCManagerW(APIContext& ctx);
bool HandleCreateServiceA(APIContext& ctx);
bool HandleCreateServiceW(APIContext& ctx);
bool HandleStartServiceA(APIContext& ctx);
bool HandleStartServiceW(APIContext& ctx);
bool HandleOpenServiceA(APIContext& ctx);
bool HandleOpenServiceW(APIContext& ctx);
bool HandleDeleteService(APIContext& ctx);
bool HandleCloseServiceHandle(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
