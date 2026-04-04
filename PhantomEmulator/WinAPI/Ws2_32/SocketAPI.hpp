/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SocketAPI.hpp — Ws2_32 core socket API handlers
 *
 * Covers WSAStartup, WSACleanup, socket, connect, send, recv,
 * closesocket, bind, listen, accept, setsockopt, getsockopt,
 * ioctlsocket, and select.
 *
 * Every connection attempt is logged as a C2 IOC. We intentionally
 * return success for connect/send so the malware reveals its full
 * network intent before we flag it.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ws2_32 {

void RegisterSocketAPI(APIDispatcher& dispatcher) noexcept;

bool HandleWSAStartup(APIContext& ctx);
bool HandleWSACleanup(APIContext& ctx);
bool HandleSocket(APIContext& ctx);
bool HandleConnect(APIContext& ctx);
bool HandleSend(APIContext& ctx);
bool HandleRecv(APIContext& ctx);
bool HandleClosesocket(APIContext& ctx);
bool HandleBind(APIContext& ctx);
bool HandleListen(APIContext& ctx);
bool HandleAccept(APIContext& ctx);
bool HandleSetsockopt(APIContext& ctx);
bool HandleGetsockopt(APIContext& ctx);
bool HandleIoctlsocket(APIContext& ctx);
bool HandleSelect(APIContext& ctx);

} // namespace WinAPI::Ws2_32
} // namespace Phantom
