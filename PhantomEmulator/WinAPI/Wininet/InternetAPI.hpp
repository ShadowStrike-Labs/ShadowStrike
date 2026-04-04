/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * InternetAPI.hpp — Wininet high-level HTTP API handlers
 *
 * Covers InternetOpen, InternetConnect, HttpOpenRequest,
 * HttpSendRequest, InternetReadFile, InternetCloseHandle,
 * HttpQueryInfo (A/W variants).
 *
 * All HTTP verb + path + user-agent combos are logged. User-agent
 * strings often fingerprint C2 frameworks (Cobalt Strike, Metasploit).
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Wininet {

void RegisterInternetAPI(APIDispatcher& dispatcher) noexcept;

bool HandleInternetOpenA(APIContext& ctx);
bool HandleInternetOpenW(APIContext& ctx);
bool HandleInternetConnectA(APIContext& ctx);
bool HandleInternetConnectW(APIContext& ctx);
bool HandleHttpOpenRequestA(APIContext& ctx);
bool HandleHttpOpenRequestW(APIContext& ctx);
bool HandleHttpSendRequestA(APIContext& ctx);
bool HandleHttpSendRequestW(APIContext& ctx);
bool HandleInternetReadFile(APIContext& ctx);
bool HandleInternetCloseHandle(APIContext& ctx);
bool HandleHttpQueryInfoA(APIContext& ctx);
bool HandleHttpQueryInfoW(APIContext& ctx);

} // namespace WinAPI::Wininet
} // namespace Phantom
