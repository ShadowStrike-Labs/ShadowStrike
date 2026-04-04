/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * DnsAPI.hpp — Ws2_32 DNS and address-conversion API handlers
 *
 * Covers gethostbyname, gethostname, getaddrinfo, freeaddrinfo,
 * inet_ntoa, inet_addr, htons, htonl, ntohs, ntohl.
 *
 * DNS lookups are CRITICAL IOCs — every resolved hostname is logged
 * as a potential C2 domain indicator.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ws2_32 {

void RegisterDnsAPI(APIDispatcher& dispatcher) noexcept;

bool HandleGethostbyname(APIContext& ctx);
bool HandleGethostname(APIContext& ctx);
bool HandleGetaddrinfo(APIContext& ctx);
bool HandleFreeaddrinfo(APIContext& ctx);
bool HandleInet_ntoa(APIContext& ctx);
bool HandleInet_addr(APIContext& ctx);
bool HandleHtons(APIContext& ctx);
bool HandleHtonl(APIContext& ctx);
bool HandleNtohs(APIContext& ctx);
bool HandleNtohl(APIContext& ctx);

} // namespace WinAPI::Ws2_32
} // namespace Phantom
