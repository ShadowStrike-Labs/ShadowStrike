/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * HttpStreamAPI.hpp — Wininet streaming HTTP API handlers
 *
 * Covers HttpSendRequestExA/W, InternetReadFileExA/W,
 * InternetSetOptionA/W, InternetGetConnectedState,
 * InternetCheckConnectionA/W, HttpEndRequestA/W,
 * InternetWriteFile, InternetQueryDataAvailable,
 * InternetSetStatusCallback, InternetQueryOptionA/W.
 *
 * Streaming HTTP APIs are critical for C2 communication detection.
 * Proxy manipulation, SSL bypass, and large data transfers are
 * high-value IOCs flagged here.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Wininet {

void RegisterHttpStreamAPI(APIDispatcher& dispatcher) noexcept;

bool HandleHttpSendRequestExA(APIContext& ctx);
bool HandleHttpSendRequestExW(APIContext& ctx);
bool HandleInternetReadFileExA(APIContext& ctx);
bool HandleInternetReadFileExW(APIContext& ctx);
bool HandleInternetSetOptionA(APIContext& ctx);
bool HandleInternetSetOptionW(APIContext& ctx);
bool HandleInternetGetConnectedState(APIContext& ctx);
bool HandleInternetCheckConnectionA(APIContext& ctx);
bool HandleInternetCheckConnectionW(APIContext& ctx);
bool HandleHttpEndRequestA(APIContext& ctx);
bool HandleHttpEndRequestW(APIContext& ctx);
bool HandleInternetWriteFile(APIContext& ctx);
bool HandleInternetQueryDataAvailable(APIContext& ctx);
bool HandleInternetSetStatusCallback(APIContext& ctx);
bool HandleInternetQueryOptionA(APIContext& ctx);
bool HandleInternetQueryOptionW(APIContext& ctx);

} // namespace WinAPI::Wininet
} // namespace Phantom
