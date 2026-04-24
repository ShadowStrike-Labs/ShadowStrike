/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * SocketAPI.cpp — Ws2_32 core socket API implementations
 *
 * Every handler reads arguments from guest registers/stack via
 * APIContext, operates on VirtualMemory / HandleTable, and writes
 * results back. No host OS network calls are ever made.
 *
 * Network connections are always allowed to succeed so the malware
 * fully reveals its C2 infrastructure before detonation scoring.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "SocketAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

// DESIGN: Guest-memory writebacks (sockaddr read-backs, WSAData struct emit)
// are [[nodiscard]]; guest-side faults do not affect emulator correctness.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Ws2_32 {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxBufferSize     = 64 * 1024; // 64 KB cap
static constexpr uint32_t kWSADataSize64     = 400;       // sizeof(WSADATA) on x64
static constexpr uint32_t kWSADataSize32     = 400;       // sizeof(WSADATA) on x86
static constexpr uint16_t kWinsockVersion    = 0x0202;    // v2.2
static constexpr uint16_t kSockaddrInSize    = 16;
static constexpr uint16_t kAF_INET           = 2;

// Winsock error codes
static constexpr int32_t kWSAESuccess        = 0;
static constexpr int32_t kWSAENotSock        = 10038;
static constexpr int32_t kWSAENOTCONN        = 10057;

// ============================================================================
// WSAStartup — wVersionRequired(0), lpWSAData(1)
// ============================================================================

bool HandleWSAStartup(APIContext& ctx) {
    const auto wVersionRequired = ctx.GetArg32(0);
    const auto lpWSAData        = ctx.GetArgPtr(1);

    (void)wVersionRequired;

    if (lpWSAData == 0) {
        ctx.SetReturn32(kWSAENotSock);
        return true;
    }

    auto& mem = ctx.Memory();

    // Zero the entire WSAData structure first
    const uint32_t wsaDataSize = ctx.Is64Bit() ? kWSADataSize64 : kWSADataSize32;
    std::array<uint8_t, 400> zeroBuf{};
    mem.Write(lpWSAData, zeroBuf.data(),
              std::min(wsaDataSize, static_cast<uint32_t>(zeroBuf.size())));

    // wVersion (offset 0): negotiated version — 2.2
    mem.WriteU16(lpWSAData + 0, kWinsockVersion);
    // wHighVersion (offset 2): highest supported — 2.2
    mem.WriteU16(lpWSAData + 2, kWinsockVersion);
    // iMaxSockets (offset 4 on x86, but after szDescription/szSystemStatus on real struct)
    // Real WSADATA layout:
    //   WORD wVersion;          // +0
    //   WORD wHighVersion;      // +2
    //   char szDescription[257];// +4  (x86) or after on x64
    //   char szSystemStatus[129];
    //   unsigned short iMaxSockets;
    //   unsigned short iMaxUdpDg;
    //   char FAR* lpVendorInfo;
    // For x86: szDescription at +4, szSystemStatus at +261, iMaxSockets at +390
    // For x64: layout is reordered — iMaxSockets at +4, iMaxUdpDg at +6, lpVendorInfo at +8
    if (ctx.Is64Bit()) {
        // x64 WSADATA: wVersion(2) wHighVersion(2) iMaxSockets(2) iMaxUdpDg(2)
        //              lpVendorInfo(8) szDescription(257) szSystemStatus(129)
        mem.WriteU16(lpWSAData + 4, 4096);      // iMaxSockets
        mem.WriteU16(lpWSAData + 6, 65467);      // iMaxUdpDg
        // szDescription at +16
        static constexpr char kDesc[] = "Winsock 2.0";
        mem.Write(lpWSAData + 16, kDesc, sizeof(kDesc));
    } else {
        // x86 WSADATA: wVersion(2) wHighVersion(2) szDescription(257)
        //              szSystemStatus(129) iMaxSockets(2) iMaxUdpDg(2) lpVendorInfo(4)
        static constexpr char kDesc[] = "Winsock 2.0";
        mem.Write(lpWSAData + 4, kDesc, sizeof(kDesc));
        // iMaxSockets at +4+257+129 = +390
        mem.WriteU16(lpWSAData + 390, 4096);
        mem.WriteU16(lpWSAData + 392, 65467);
    }

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// WSACleanup — no args
// ============================================================================

bool HandleWSACleanup(APIContext& ctx) {
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// socket — af(0), type(1), protocol(2)
// ============================================================================

bool HandleSocket(APIContext& ctx) {
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
// connect — s(0), sockaddr*(1), namelen(2)
// ============================================================================

bool HandleConnect(APIContext& ctx) {
    const auto s        = ctx.GetArg(0);
    const auto pAddr    = ctx.GetArgPtr(1);
    const auto nameLen  = ctx.GetArg32(2);

    if (pAddr == 0 || nameLen < kSockaddrInSize) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    auto& mem = ctx.Memory();

    // Read sockaddr_in: family(2) + port(2) + addr(4) + zero(8)
    uint16_t family = 0;
    uint16_t portBE = 0;
    uint32_t addrBE = 0;
    mem.ReadU16(pAddr, family);
    mem.ReadU16(pAddr + 2, portBE);
    mem.ReadU32(pAddr + 4, addrBE);

    // Convert from network byte order
    const uint16_t port = static_cast<uint16_t>((portBE >> 8) | (portBE << 8));
    const uint8_t a = static_cast<uint8_t>(addrBE & 0xFF);
    const uint8_t b = static_cast<uint8_t>((addrBE >> 8) & 0xFF);
    const uint8_t c = static_cast<uint8_t>((addrBE >> 16) & 0xFF);
    const uint8_t d = static_cast<uint8_t>((addrBE >> 24) & 0xFF);

    std::string ipStr = std::to_string(a) + "." + std::to_string(b) + "."
                      + std::to_string(c) + "." + std::to_string(d);

    // Update socket data with connection target
    ctx.Handles().Modify<SocketData>(s, [&](SocketData& sd) {
        sd.remoteAddr = ipStr;
        sd.remotePort = port;
        sd.connected  = true;
    });

    // T1071 Application Layer Protocol. APIDatabase.hpp:397 raises
    // NetworkC2; SuspiciousAPI flags the raw-socket connect primitive
    // (reverse shells, custom C2, port-scan egress).
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// send — s(0), buf(1), len(2), flags(3)
// ============================================================================

bool HandleSend(APIContext& ctx) {
    const auto s     = ctx.GetArg(0);
    const auto buf   = ctx.GetArgPtr(1);
    auto       len   = ctx.GetArg32(2);

    (void)s;

    if (buf == 0 || len == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Cap buffer read to prevent resource exhaustion
    if (len > kMaxBufferSize) {
        len = kMaxBufferSize;
    }

    // T1071 / T1041 reinforcement. APIDatabase.hpp:398 raises NetworkC2;
    // SuspiciousAPI weights the transmission primitive for data-exfil /
    // C2-beacon correlation.
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    // Return success: malware thinks data was sent — reveals payload size
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn32(len);
    return true;
}

// ============================================================================
// recv — s(0), buf(1), len(2), flags(3)
// ============================================================================

bool HandleRecv(APIContext& ctx) {
    const auto s     = ctx.GetArg(0);
    const auto buf   = ctx.GetArgPtr(1);
    auto       len   = ctx.GetArg32(2);

    (void)s;

    if (buf == 0 || len == 0) {
        ctx.SetReturn32(static_cast<uint32_t>(-1));
        ctx.SetLastError(Win32::ERROR_INVALID_PARAMETER);
        return true;
    }

    // Simulate connection closed — write nothing, return 0
    // This signals graceful close to the malware, which is the safest
    // behavior to avoid infinite recv loops.
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// closesocket — s(0)
// ============================================================================

bool HandleClosesocket(APIContext& ctx) {
    const auto s = ctx.GetArg(0);
    ctx.Handles().Close(s);
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// bind — s(0), sockaddr*(1), namelen(2)
// ============================================================================

bool HandleBind(APIContext& ctx) {
    const auto s        = ctx.GetArg(0);
    const auto pAddr    = ctx.GetArgPtr(1);
    const auto nameLen  = ctx.GetArg32(2);

    if (pAddr != 0 && nameLen >= kSockaddrInSize) {
        auto& mem = ctx.Memory();
        uint16_t family = 0;
        uint16_t portBE = 0;
        uint32_t addrBE = 0;
        mem.ReadU16(pAddr, family);
        mem.ReadU16(pAddr + 2, portBE);
        mem.ReadU32(pAddr + 4, addrBE);

        const uint16_t port = static_cast<uint16_t>((portBE >> 8) | (portBE << 8));
        const uint8_t a = static_cast<uint8_t>(addrBE & 0xFF);
        const uint8_t b = static_cast<uint8_t>((addrBE >> 8) & 0xFF);
        const uint8_t c = static_cast<uint8_t>((addrBE >> 16) & 0xFF);
        const uint8_t d = static_cast<uint8_t>((addrBE >> 24) & 0xFF);

        std::string localIp = std::to_string(a) + "." + std::to_string(b) + "."
                            + std::to_string(c) + "." + std::to_string(d);

        ctx.Handles().Modify<SocketData>(s, [&](SocketData& sd) {
            sd.localAddr = localIp;
            sd.localPort = port;
            sd.bound     = true;
        });
    }

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// listen — s(0), backlog(1)
// ============================================================================

bool HandleListen(APIContext& ctx) {
    const auto s = ctx.GetArg(0);

    ctx.Handles().Modify<SocketData>(s, [](SocketData& sd) {
        sd.listening = true;
    });

    // T1205 Traffic Signaling / T1021 Remote Services. A process that
    // opens a listening socket is typically a backdoor / reverse-shell
    // server. APIDatabase.hpp:401 raises NetworkC2; SuspiciousAPI
    // distinguishes the listener primitive from ambient traffic.
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// accept — s(0), sockaddr*(1), addrlen*(2)
// ============================================================================

bool HandleAccept(APIContext& ctx) {
    const auto s        = ctx.GetArg(0);
    const auto pAddr    = ctx.GetArgPtr(1);
    const auto pAddrLen = ctx.GetArgPtr(2);

    (void)s;

    // Create a new connected socket for the "accepted" connection
    SocketData sd;
    sd.family    = kAF_INET;
    sd.type      = 1; // SOCK_STREAM
    sd.connected = true;
    sd.remoteAddr = "10.0.0.2";
    sd.remotePort = 12345;

    GuestHandle newSock = ctx.Handles().Create(HandleType::Socket, std::move(sd));
    if (newSock == kNullHandle) {
        ctx.SetReturn(kInvalidHandleValue);
        ctx.SetLastError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // Write fake peer address if caller provided output buffers
    if (pAddr != 0 && pAddrLen != 0) {
        auto& mem = ctx.Memory();
        // Write sockaddr_in for the fake peer
        std::array<uint8_t, 16> sa{};
        sa[0] = kAF_INET & 0xFF;
        sa[1] = (kAF_INET >> 8) & 0xFF;
        sa[2] = 0x30; sa[3] = 0x39; // port 12345 in network byte order
        sa[4] = 10; sa[5] = 0; sa[6] = 0; sa[7] = 2; // 10.0.0.2
        mem.Write(pAddr, sa.data(), kSockaddrInSize);
        mem.WriteU32(pAddrLen, kSockaddrInSize);
    }

    ctx.SetReturn(newSock);
    return true;
}

// ============================================================================
// setsockopt — s(0), level(1), optname(2), optval(3), optlen(4)
// ============================================================================

bool HandleSetsockopt(APIContext& ctx) {
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// getsockopt — s(0), level(1), optname(2), optval(3), optlen*(4)
// ============================================================================

bool HandleGetsockopt(APIContext& ctx) {
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// ioctlsocket — s(0), cmd(1), argp*(2)
// ============================================================================

bool HandleIoctlsocket(APIContext& ctx) {
    ctx.SetReturn32(0);
    return true;
}

// ============================================================================
// select — nfds(0), readfds(1), writefds(2), exceptfds(3), timeout(4)
// ============================================================================

bool HandleSelect(APIContext& ctx) {
    const auto writefds = ctx.GetArgPtr(2);

    // If writefds was provided, indicate 1 socket ready for write.
    // fd_set layout: first uint32_t is fd_count, followed by SOCKET array.
    if (writefds != 0) {
        auto& mem = ctx.Memory();
        uint32_t fdCount = 0;
        mem.ReadU32(writefds, fdCount);
        // Leave the fd_set as-is — the sockets provided are "ready"
        if (fdCount == 0) {
            // If empty writefds, set count to 0 — nothing to report
            ctx.SetReturn32(0);
            return true;
        }
    }

    // Return 1: one socket ready
    ctx.SetReturn32(1);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterSocketAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "ws2_32.dll", "WSAStartup",
          HandleWSAStartup, 2, true },
        { "ws2_32.dll", "WSACleanup",
          HandleWSACleanup, 0, false },
        { "ws2_32.dll", "socket",
          HandleSocket, 3, true },
        { "ws2_32.dll", "connect",
          HandleConnect, 3, true },
        { "ws2_32.dll", "send",
          HandleSend, 4, true },
        { "ws2_32.dll", "recv",
          HandleRecv, 4, true },
        { "ws2_32.dll", "closesocket",
          HandleClosesocket, 1, false },
        { "ws2_32.dll", "bind",
          HandleBind, 3, false },
        { "ws2_32.dll", "listen",
          HandleListen, 2, false },
        { "ws2_32.dll", "accept",
          HandleAccept, 3, false },
        { "ws2_32.dll", "setsockopt",
          HandleSetsockopt, 5, false },
        { "ws2_32.dll", "getsockopt",
          HandleGetsockopt, 5, false },
        { "ws2_32.dll", "ioctlsocket",
          HandleIoctlsocket, 3, false },
        { "ws2_32.dll", "select",
          HandleSelect, 5, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Ws2_32

#pragma warning(pop)

