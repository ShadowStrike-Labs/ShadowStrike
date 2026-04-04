/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * ServiceExtAPI.hpp — Advapi32 extended Service Control Manager API handlers
 *
 * Covers ChangeServiceConfigA/W, ChangeServiceConfig2A/W,
 * EnumServicesStatusA/W, EnumServicesStatusExA/W,
 * QueryServiceStatusEx, QueryServiceConfigA/W,
 * GetServiceDisplayNameA/W, GetServiceKeyNameA/W,
 * ControlService, StartServiceCtrlDispatcherA/W,
 * RegisterServiceCtrlHandlerExA/W, SetServiceStatus.
 *
 * Service reconfiguration (T1543.003), security service tampering,
 * and malware registering as a service are high-value IOCs.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Advapi32 {

void RegisterServiceExtAPI(APIDispatcher& dispatcher) noexcept;

bool HandleChangeServiceConfigA(APIContext& ctx);
bool HandleChangeServiceConfigW(APIContext& ctx);
bool HandleChangeServiceConfig2A(APIContext& ctx);
bool HandleChangeServiceConfig2W(APIContext& ctx);
bool HandleEnumServicesStatusA(APIContext& ctx);
bool HandleEnumServicesStatusW(APIContext& ctx);
bool HandleEnumServicesStatusExA(APIContext& ctx);
bool HandleEnumServicesStatusExW(APIContext& ctx);
bool HandleQueryServiceStatusEx(APIContext& ctx);
bool HandleQueryServiceConfigA(APIContext& ctx);
bool HandleQueryServiceConfigW(APIContext& ctx);
bool HandleGetServiceDisplayNameA(APIContext& ctx);
bool HandleGetServiceDisplayNameW(APIContext& ctx);
bool HandleGetServiceKeyNameA(APIContext& ctx);
bool HandleGetServiceKeyNameW(APIContext& ctx);
bool HandleControlService(APIContext& ctx);
bool HandleStartServiceCtrlDispatcherA(APIContext& ctx);
bool HandleStartServiceCtrlDispatcherW(APIContext& ctx);
bool HandleRegisterServiceCtrlHandlerExA(APIContext& ctx);
bool HandleRegisterServiceCtrlHandlerExW(APIContext& ctx);
bool HandleSetServiceStatus(APIContext& ctx);

} // namespace WinAPI::Advapi32
} // namespace Phantom
