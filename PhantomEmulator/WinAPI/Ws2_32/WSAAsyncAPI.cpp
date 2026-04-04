/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WSAAsyncAPI.cpp — Ws2_32 extended / async Winsock API implementations
 *
 * WSASocket, WSASend, WSARecv are thin wrappers over the core socket APIs
 * with additional parameters. WSAGetLastError / WSASetLastError manage
 * per-thread Winsock error state via ThreadLocalState.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "WSAAsyncAPI.hpp"
#include "SocketAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>

namespace Phantom::WinAPI::Ws2_32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxBufferSize  = 64 * 1024;
static constexpr int32_t  kWSAENotSock    = 10038;

// Per-thread Winsock error — stored in ThreadLocalState.lastError.
// In real Windows, WSAGetLastError and GetLastError share the same TLS slot.

// ============================================================================
// WSAGetLastError — no args
// ============================================================================

bool HandleWSAGetLastError(APIContext& ctx) {
    ctx.SetReturn32(ctx.GetLastError());
    return true;
}

// ============================================================================
// WSASetLastError — iError(0)
// ============================================================================

bool HandleWSASetLastError(APIContext& ctx) {
    const auto iError = ctx.GetArg32(0);
    ctx.SetLastError(iError);
    // WSASetLastError returns void; set RAX/EAX to 0
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// WSASocketA — af(0), type(1), protocol(2), lpProtocolInfo(3),
//              g(4), dwFlags(5)
// ============================================================================
// Functionally equivalent to socket() for our emulation purposes.
// The extra params (protocol info, group, flags) are irrelevant to
// behavioral analysis — we just need the socket handle.

bool HandleWSASocketA(APIContext& ctx) {
    const auto af       = ctx.GetArg32(0);
    const auto type     = ctx.GetArg32(1);
    const auto protocol = ctx.GetArg32(2);

    SocketData sd;
    sd.family   = static_cast<int32_t>(af);
    sd.type     = static_cast<int32_t>(type);
    sd.protocol = static_cast<int32_t>(protocol);

    GuestHandle h = ctx.Handles().Create(HandleType::Socket, std::move(sd));
    if (h == kNullHandle) {
        ctx.SetReturn(kInvalidHandleValue);
        ctx.SetLastError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetReturn(h);
    return true;
}

// ============================================================================
// WSASocketW — same args as WSASocketA, wide-string irrelevant here
// ============================================================================

bool HandleWSASocketW(APIContext& ctx) {
    return HandleWSASocketA(ctx);
}

// ============================================================================
// WSASend — s(0), lpBuffers(1), dwBufferCount(2), lpNumberOfBytesSent(3),
//           dwFlags(4), lpOverlapped(5), lpCompletionRoutine(6)
// ============================================================================
// WSABUF layout: { ULONG len; CHAR* buf; }

bool HandleWSASend(APIContext& ctx) {
    const auto s                = ctx.GetArg(0);
    const auto lpBuffers        = ctx.GetArgPtr(1);
    const auto dwBufferCount    = ctx.GetArg32(2);
    const auto lpBytesSent      = ctx.GetArgPtr(3);

    (void)s;

    if (lpBuffers == 0 || dwBufferCount == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();
    const bool is64 = ctx.Is64Bit();

    // Sum total bytes across all WSABUF entries
    uint32_t totalBytes = 0;
    const uint32_t maxBufs = std::min(dwBufferCount, 64u); // Cap scatter count
    const uint32_t wsaBufSize = is64 ? 16 : 8; // { ULONG len; CHAR* buf; }

    for (uint32_t i = 0; i < maxBufs; ++i) {
        uint32_t bufLen = 0;
        mem.ReadU32(lpBuffers + i * wsaBufSize, bufLen);
        if (bufLen > kMaxBufferSize) bufLen = kMaxBufferSize;
        totalBytes += bufLen;
        if (totalBytes > kMaxBufferSize) {
            totalBytes = kMaxBufferSize;
            break;
        }
    }

    // Write bytes-sent output
    if (lpBytesSent != 0) {
        mem.WriteU32(lpBytesSent, totalBytes);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// WSARecv — s(0), lpBuffers(1), dwBufferCount(2),
//           lpNumberOfBytesRecvd(3), lpFlags(4),
//           lpOverlapped(5), lpCompletionRoutine(6)
// ============================================================================

bool HandleWSARecv(APIContext& ctx) {
    const auto lpBytesRecvd = ctx.GetArgPtr(3);

    // Simulate connection closed — 0 bytes received
    if (lpBytesRecvd != 0) {
        ctx.Memory().WriteU32(lpBytesRecvd, 0);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterWSAAsyncAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ws2_32.dll", "WSAGetLastError",
          HandleWSAGetLastError, 0, false },
        { "ws2_32.dll", "WSASetLastError",
          HandleWSASetLastError, 1, false },
        { "ws2_32.dll", "WSASocketA",
          HandleWSASocketA, 6, false },
        { "ws2_32.dll", "WSASocketW",
          HandleWSASocketW, 6, false },
        { "ws2_32.dll", "WSASend",
          HandleWSASend, 7, false },
        { "ws2_32.dll", "WSARecv",
          HandleWSARecv, 7, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ws2_32
