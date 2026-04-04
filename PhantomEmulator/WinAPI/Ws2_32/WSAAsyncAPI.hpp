/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WSAAsyncAPI.hpp — Ws2_32 extended / async Winsock API handlers
 *
 * Covers WSAGetLastError, WSASetLastError, WSASocketA/W,
 * WSASend, WSARecv.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../APITypes.hpp"

namespace Phantom {

class APIDispatcher;

namespace WinAPI::Ws2_32 {

void RegisterWSAAsyncAPI(APIDispatcher& dispatcher) noexcept;

bool HandleWSAGetLastError(APIContext& ctx);
bool HandleWSASetLastError(APIContext& ctx);
bool HandleWSASocketA(APIContext& ctx);
bool HandleWSASocketW(APIContext& ctx);
bool HandleWSASend(APIContext& ctx);
bool HandleWSARecv(APIContext& ctx);

} // namespace WinAPI::Ws2_32
} // namespace Phantom
