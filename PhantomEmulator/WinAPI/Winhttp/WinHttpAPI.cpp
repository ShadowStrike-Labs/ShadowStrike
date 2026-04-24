/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * WinHttpAPI.cpp — WinHTTP session / request API implementations
 *
 * WinHTTP is the modern Windows HTTP client library, preferred by
 * sophisticated malware and C2 frameworks over Wininet. The call chain
 * WinHttpOpen → WinHttpConnect → WinHttpOpenRequest → WinHttpSendRequest
 * → WinHttpReceiveResponse → WinHttpReadData mirrors Wininet but uses
 * wide strings exclusively.
 *
 * All server names, ports, verbs, paths, and user-agents are captured
 * as IOCs for behavioral analysis and MITRE ATT&CK mapping.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "WinHttpAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>

// DESIGN: Guest writebacks in WinHttpQueryHeaders / WinHttpReadData are
// [[nodiscard]] but guest-side faults don't affect our correctness.
#pragma warning(push)
#pragma warning(disable : 4834 6031)

namespace Phantom::WinAPI::Winhttp {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxHeaderLen  = 8192;

// Handle sub-types stored in SocketData.family
static constexpr int32_t kWinHttpSession    = 0x2001;
static constexpr int32_t kWinHttpConnection = 0x2002;
static constexpr int32_t kWinHttpRequest    = 0x2003;

// WINHTTP_QUERY_STATUS_CODE
static constexpr uint32_t kWINHTTP_QUERY_STATUS_CODE = 19;
static constexpr uint32_t kWINHTTP_QUERY_STATUS_TEXT = 20;
static constexpr uint32_t kWINHTTP_QUERY_FLAG_NUMBER = 0x20000000;

// ============================================================================
// Helper: wide string to narrow (ASCII-safe)
// ============================================================================

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string result;
    result.reserve(ws.size());
    for (wchar_t wc : ws) {
        result.push_back(static_cast<char>(wc & 0x7F));
    }
    return result;
}

// ============================================================================
// WinHttpOpen — pszAgentW(0), dwAccessType(1), pszProxyW(2),
//               pszProxyBypassW(3), dwFlags(4)
// ============================================================================

bool HandleWinHttpOpen(APIContext& ctx) {
    const auto pszAgentW = ctx.GetArgPtr(0);

    std::string userAgent;
    if (pszAgentW != 0) {
        std::wstring wAgent = ctx.ReadWideString(pszAgentW, kMaxStringLen / 2);
        userAgent = WideToNarrow(wAgent);
    }

    SocketData sd;
    sd.family = kWinHttpSession;
    if (!userAgent.empty()) {
        sd.remoteAddr = userAgent;
    }

    GuestHandle h = ctx.Handles().Create(HandleType::Socket, std::move(sd));
    if (h == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(h);
    return true;
}

// ============================================================================
// WinHttpConnect — hSession(0), pswzServerName(1), nServerPort(2),
//                  dwReserved(3)
// ============================================================================

bool HandleWinHttpConnect(APIContext& ctx) {
    const auto hSession       = ctx.GetArg(0);
    const auto pswzServerName = ctx.GetArgPtr(1);
    const auto nServerPort    = static_cast<uint16_t>(ctx.GetArg32(2));

    (void)hSession;

    std::string serverName;
    if (pswzServerName != 0) {
        std::wstring wServer = ctx.ReadWideString(pswzServerName, kMaxStringLen / 2);
        serverName = WideToNarrow(wServer);
    }

    SocketData sd;
    sd.family     = kWinHttpConnection;
    sd.remoteAddr = serverName;
    sd.remotePort = nServerPort;
    sd.connected  = true;

    GuestHandle h = ctx.Handles().Create(HandleType::Socket, std::move(sd));
    if (h == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    // T1071.001 Application Layer Protocol (Web). WinHttpConnect binds a
    // WinHTTP session to a specific remote server:port — this is the
    // canonical C2-beaconing setup step (APT28/APT29/Emotet/IcedID).
    ctx.AddBehaviorFlag(BehaviorFlag::NetworkC2);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(h);
    return true;
}

// ============================================================================
// WinHttpOpenRequest — hConnect(0), pwszVerb(1), pwszObjectName(2),
//   pwszVersion(3), pwszReferrer(4), ppwszAcceptTypes(5), dwFlags(6)
// ============================================================================

bool HandleWinHttpOpenRequest(APIContext& ctx) {
    const auto hConnect        = ctx.GetArg(0);
    const auto pwszVerb        = ctx.GetArgPtr(1);
    const auto pwszObjectName  = ctx.GetArgPtr(2);

    (void)hConnect;

    std::string verb = "GET";
    if (pwszVerb != 0) {
        std::wstring wVerb = ctx.ReadWideString(pwszVerb, 32);
        verb = WideToNarrow(wVerb);
    }

    std::string path = "/";
    if (pwszObjectName != 0) {
        std::wstring wPath = ctx.ReadWideString(pwszObjectName, kMaxStringLen / 2);
        path = WideToNarrow(wPath);
    }

    SocketData sd;
    sd.family     = kWinHttpRequest;
    sd.remoteAddr = verb + " " + path;

    GuestHandle h = ctx.Handles().Create(HandleType::Socket, std::move(sd));
    if (h == kNullHandle) {
        ctx.FailWithError(Win32::ERROR_NOT_ENOUGH_MEMORY);
        return true;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnHandle(h);
    return true;
}

// ============================================================================
// WinHttpSendRequest — hRequest(0), pwszHeaders(1), dwHeadersLength(2),
//   lpOptional(3), dwOptionalLength(4), dwTotalLength(5), dwContext(6)
// ============================================================================

bool HandleWinHttpSendRequest(APIContext& ctx) {
    // Headers and optional data are captured via APICallDetail args.
    // T1071.001 beaconing — WinHttpSendRequest is THE transmission primitive
    // and deserves the strong NetworkC2 flag on every invocation.
    ctx.AddBehaviorFlag(BehaviorFlag::NetworkC2);
    ctx.AddBehaviorFlag(BehaviorFlag::SuspiciousAPI);

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WinHttpReceiveResponse — hRequest(0), lpReserved(1)
// ============================================================================

bool HandleWinHttpReceiveResponse(APIContext& ctx) {
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WinHttpReadData — hRequest(0), lpBuffer(1), dwNumberOfBytesToRead(2),
//                   lpdwNumberOfBytesRead(3)
// ============================================================================

bool HandleWinHttpReadData(APIContext& ctx) {
    const auto lpdwBytesRead = ctx.GetArgPtr(3);

    // Simulate empty response — 0 bytes read
    if (lpdwBytesRead != 0) {
        ctx.Memory().WriteU32(lpdwBytesRead, 0);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WinHttpQueryHeaders — hRequest(0), dwInfoLevel(1), pwszName(2),
//   lpBuffer(3), lpdwBufferLength(4), lpdwIndex(5)
// ============================================================================

bool HandleWinHttpQueryHeaders(APIContext& ctx) {
    const auto dwInfoLevel   = ctx.GetArg32(1);
    const auto lpBuffer      = ctx.GetArgPtr(3);
    const auto lpdwBufferLen = ctx.GetArgPtr(4);

    auto& mem = ctx.Memory();

    const uint32_t infoId = dwInfoLevel & 0x0000FFFF;
    const bool asNumber = (dwInfoLevel & kWINHTTP_QUERY_FLAG_NUMBER) != 0;

    if (infoId == kWINHTTP_QUERY_STATUS_CODE) {
        if (asNumber) {
            if (lpBuffer != 0) {
                mem.WriteU32(lpBuffer, 200);
            }
            if (lpdwBufferLen != 0) {
                mem.WriteU32(lpdwBufferLen, 4);
            }
        } else {
            // Return L"200" as wide string
            static constexpr wchar_t kStatus[] = L"200";
            if (lpBuffer != 0) {
                mem.Write(lpBuffer, kStatus, sizeof(kStatus));
            }
            if (lpdwBufferLen != 0) {
                mem.WriteU32(lpdwBufferLen, sizeof(kStatus));
            }
        }
    } else if (infoId == kWINHTTP_QUERY_STATUS_TEXT) {
        static constexpr wchar_t kStatusText[] = L"OK";
        if (lpBuffer != 0) {
            mem.Write(lpBuffer, kStatusText, sizeof(kStatusText));
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, sizeof(kStatusText));
        }
    } else {
        // Unknown query — return empty
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 0);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// WinHttpCloseHandle — hInternet(0)
// ============================================================================

bool HandleWinHttpCloseHandle(APIContext& ctx) {
    const auto hInternet = ctx.GetArg(0);
    ctx.Handles().Close(hInternet);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterWinHttpAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "winhttp.dll", "WinHttpOpen",
          HandleWinHttpOpen, 5, true },
        { "winhttp.dll", "WinHttpConnect",
          HandleWinHttpConnect, 4, true },
        { "winhttp.dll", "WinHttpOpenRequest",
          HandleWinHttpOpenRequest, 7, true },
        { "winhttp.dll", "WinHttpSendRequest",
          HandleWinHttpSendRequest, 7, true },
        { "winhttp.dll", "WinHttpReceiveResponse",
          HandleWinHttpReceiveResponse, 2, false },
        { "winhttp.dll", "WinHttpReadData",
          HandleWinHttpReadData, 4, true },
        { "winhttp.dll", "WinHttpQueryHeaders",
          HandleWinHttpQueryHeaders, 6, false },
        { "winhttp.dll", "WinHttpCloseHandle",
          HandleWinHttpCloseHandle, 1, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Winhttp

#pragma warning(pop)

