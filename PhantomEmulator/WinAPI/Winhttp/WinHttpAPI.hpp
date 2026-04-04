/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WinHttpAPI.hpp — WinHTTP session / request API handlers
 *
 * Covers WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
 * WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
 * WinHttpQueryHeaders, WinHttpCloseHandle.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Winhttp {

void RegisterWinHttpAPI(APIDispatcher& dispatcher) noexcept;

bool HandleWinHttpOpen(APIContext& ctx);
bool HandleWinHttpConnect(APIContext& ctx);
bool HandleWinHttpOpenRequest(APIContext& ctx);
bool HandleWinHttpSendRequest(APIContext& ctx);
bool HandleWinHttpReceiveResponse(APIContext& ctx);
bool HandleWinHttpReadData(APIContext& ctx);
bool HandleWinHttpQueryHeaders(APIContext& ctx);
bool HandleWinHttpCloseHandle(APIContext& ctx);

} // namespace WinAPI::Winhttp
} // namespace Phantom
