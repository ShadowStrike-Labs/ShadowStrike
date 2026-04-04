/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * InternetAPI.cpp — Wininet high-level HTTP API implementations
 *
 * Wininet is the go-to library for malware performing HTTP-based C2.
 * The InternetOpen → InternetConnect → HttpOpenRequest → HttpSendRequest
 * chain is one of the most common patterns in commodity malware and
 * advanced RATs alike.
 *
 * Every user-agent, server:port, HTTP verb+path is logged as IOC.
 * We return success for all operations so the malware reveals its full
 * network intent.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "InternetAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <cstring>
#include <string>

namespace Phantom::WinAPI::Wininet {

// ============================================================================
// Internal constants and types
// ============================================================================

static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxHeaderLen  = 8192;

// Internet handle types tracked in SocketData (reusing Socket handle type)
// We distinguish by the sub-fields:
//   - Internet session: family = 0x1001
//   - Connection:       family = 0x1002
//   - Request:          family = 0x1003
static constexpr int32_t kInetSession    = 0x1001;
static constexpr int32_t kInetConnection = 0x1002;
static constexpr int32_t kInetRequest    = 0x1003;

// HTTP_QUERY_STATUS_CODE for HttpQueryInfo
static constexpr uint32_t kHTTP_QUERY_STATUS_CODE = 19;
static constexpr uint32_t kHTTP_QUERY_STATUS_TEXT = 20;
static constexpr uint32_t kHTTP_QUERY_FLAG_NUMBER = 0x20000000;

// ============================================================================
// InternetOpenA — lpszAgent(0), dwAccessType(1), lpszProxy(2),
//                 lpszProxyBypass(3), dwFlags(4)
// ============================================================================

bool HandleInternetOpenA(APIContext& ctx) {
    const auto lpszAgent = ctx.GetArgPtr(0);

    std::string userAgent;
    if (lpszAgent != 0) {
        userAgent = ctx.ReadAnsiString(lpszAgent, kMaxStringLen);
    }
    // IOC: user-agent is logged via APICallDetail — identifies C2 framework

    SocketData sd;
    sd.family = kInetSession;
    if (!userAgent.empty()) {
        sd.remoteAddr = userAgent; // Stash user-agent in remoteAddr for IOC extraction
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
// InternetOpenW — wide-string variant
// ============================================================================

bool HandleInternetOpenW(APIContext& ctx) {
    const auto lpszAgent = ctx.GetArgPtr(0);

    std::wstring userAgentW;
    if (lpszAgent != 0) {
        userAgentW = ctx.ReadWideString(lpszAgent, kMaxStringLen / 2);
    }

    SocketData sd;
    sd.family = kInetSession;
    if (!userAgentW.empty()) {
        // Convert to narrow for IOC storage
        std::string narrow;
        narrow.reserve(userAgentW.size());
        for (wchar_t wc : userAgentW) {
            narrow.push_back(static_cast<char>(wc & 0x7F));
        }
        sd.remoteAddr = std::move(narrow);
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
// InternetConnectA — hInternet(0), lpszServerName(1), nServerPort(2),
//   lpszUserName(3), lpszPassword(4), dwService(5), dwFlags(6), dwContext(7)
// ============================================================================

bool HandleInternetConnectA(APIContext& ctx) {
    const auto hInternet     = ctx.GetArg(0);
    const auto lpszServer    = ctx.GetArgPtr(1);
    const auto nServerPort   = static_cast<uint16_t>(ctx.GetArg32(2));

    (void)hInternet;

    std::string serverName;
    if (lpszServer != 0) {
        serverName = ctx.ReadAnsiString(lpszServer, kMaxStringLen);
    }

    SocketData sd;
    sd.family     = kInetConnection;
    sd.remoteAddr = serverName;
    sd.remotePort = nServerPort;
    sd.connected  = true;

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
// InternetConnectW — wide-string variant
// ============================================================================

bool HandleInternetConnectW(APIContext& ctx) {
    const auto hInternet     = ctx.GetArg(0);
    const auto lpszServer    = ctx.GetArgPtr(1);
    const auto nServerPort   = static_cast<uint16_t>(ctx.GetArg32(2));

    (void)hInternet;

    std::string serverName;
    if (lpszServer != 0) {
        std::wstring wServer = ctx.ReadWideString(lpszServer, kMaxStringLen / 2);
        serverName.reserve(wServer.size());
        for (wchar_t wc : wServer) {
            serverName.push_back(static_cast<char>(wc & 0x7F));
        }
    }

    SocketData sd;
    sd.family     = kInetConnection;
    sd.remoteAddr = serverName;
    sd.remotePort = nServerPort;
    sd.connected  = true;

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
// HttpOpenRequestA — hConnect(0), lpszVerb(1), lpszObjectName(2),
//   lpszVersion(3), lpszReferrer(4), lplpszAcceptTypes(5),
//   dwFlags(6), dwContext(7)
// ============================================================================

bool HandleHttpOpenRequestA(APIContext& ctx) {
    const auto hConnect       = ctx.GetArg(0);
    const auto lpszVerb       = ctx.GetArgPtr(1);
    const auto lpszObjectName = ctx.GetArgPtr(2);

    (void)hConnect;

    std::string verb = "GET";
    if (lpszVerb != 0) {
        verb = ctx.ReadAnsiString(lpszVerb, 32);
    }

    std::string path = "/";
    if (lpszObjectName != 0) {
        path = ctx.ReadAnsiString(lpszObjectName, kMaxStringLen);
    }

    // IOC: HTTP verb + path logged in SocketData for analysis
    SocketData sd;
    sd.family     = kInetRequest;
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
// HttpOpenRequestW — wide-string variant
// ============================================================================

bool HandleHttpOpenRequestW(APIContext& ctx) {
    const auto hConnect       = ctx.GetArg(0);
    const auto lpszVerb       = ctx.GetArgPtr(1);
    const auto lpszObjectName = ctx.GetArgPtr(2);

    (void)hConnect;

    std::string verb = "GET";
    if (lpszVerb != 0) {
        std::wstring wVerb = ctx.ReadWideString(lpszVerb, 32);
        verb.clear();
        verb.reserve(wVerb.size());
        for (wchar_t wc : wVerb) verb.push_back(static_cast<char>(wc & 0x7F));
    }

    std::string path = "/";
    if (lpszObjectName != 0) {
        std::wstring wPath = ctx.ReadWideString(lpszObjectName, kMaxStringLen / 2);
        path.clear();
        path.reserve(wPath.size());
        for (wchar_t wc : wPath) path.push_back(static_cast<char>(wc & 0x7F));
    }

    SocketData sd;
    sd.family     = kInetRequest;
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
// HttpSendRequestA — hRequest(0), lpszHeaders(1), dwHeadersLength(2),
//                     lpOptional(3), dwOptionalLength(4)
// ============================================================================

bool HandleHttpSendRequestA(APIContext& ctx) {
    const auto lpszHeaders     = ctx.GetArgPtr(1);
    const auto dwHeadersLength = ctx.GetArg32(2);

    // Log headers if present (may contain custom C2 tokens, cookies)
    if (lpszHeaders != 0 && dwHeadersLength > 0) {
        const uint32_t safeLen = std::min(dwHeadersLength, kMaxHeaderLen);
        // Headers are captured through the APICallDetail args
        (void)safeLen;
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true); // TRUE
    return true;
}

// ============================================================================
// HttpSendRequestW — wide-string variant
// ============================================================================

bool HandleHttpSendRequestW(APIContext& ctx) {
    // Same behavioral result — headers logged via args
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetReadFile — hFile(0), lpBuffer(1), dwNumberOfBytesToRead(2),
//                    lpdwNumberOfBytesRead(3)
// ============================================================================

bool HandleInternetReadFile(APIContext& ctx) {
    const auto lpBuffer          = ctx.GetArgPtr(1);
    const auto lpdwBytesRead     = ctx.GetArgPtr(3);

    (void)lpBuffer;

    // Simulate empty response / connection closed: 0 bytes read
    if (lpdwBytesRead != 0) {
        ctx.Memory().WriteU32(lpdwBytesRead, 0);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetCloseHandle — hInternet(0)
// ============================================================================

bool HandleInternetCloseHandle(APIContext& ctx) {
    const auto hInternet = ctx.GetArg(0);
    ctx.Handles().Close(hInternet);
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HttpQueryInfoA — hRequest(0), dwInfoLevel(1), lpBuffer(2),
//                  lpdwBufferLength(3), lpdwIndex(4)
// ============================================================================

bool HandleHttpQueryInfoA(APIContext& ctx) {
    const auto dwInfoLevel     = ctx.GetArg32(1);
    const auto lpBuffer        = ctx.GetArgPtr(2);
    const auto lpdwBufferLen   = ctx.GetArgPtr(3);

    auto& mem = ctx.Memory();

    const uint32_t infoId = dwInfoLevel & 0x0000FFFF;
    const bool asNumber = (dwInfoLevel & kHTTP_QUERY_FLAG_NUMBER) != 0;

    if (infoId == kHTTP_QUERY_STATUS_CODE) {
        if (asNumber) {
            // Return 200 as DWORD
            if (lpBuffer != 0) {
                mem.WriteU32(lpBuffer, 200);
            }
            if (lpdwBufferLen != 0) {
                mem.WriteU32(lpdwBufferLen, 4);
            }
        } else {
            // Return "200" as string
            static constexpr char kStatus[] = "200";
            if (lpBuffer != 0) {
                mem.Write(lpBuffer, kStatus, sizeof(kStatus));
            }
            if (lpdwBufferLen != 0) {
                mem.WriteU32(lpdwBufferLen, sizeof(kStatus));
            }
        }
    } else if (infoId == kHTTP_QUERY_STATUS_TEXT) {
        static constexpr char kStatusText[] = "OK";
        if (lpBuffer != 0) {
            mem.Write(lpBuffer, kStatusText, sizeof(kStatusText));
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, sizeof(kStatusText));
        }
    } else {
        // Unknown info level — return empty
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 0);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HttpQueryInfoW — wide-string variant
// ============================================================================

bool HandleHttpQueryInfoW(APIContext& ctx) {
    const auto dwInfoLevel     = ctx.GetArg32(1);
    const auto lpBuffer        = ctx.GetArgPtr(2);
    const auto lpdwBufferLen   = ctx.GetArgPtr(3);

    auto& mem = ctx.Memory();

    const uint32_t infoId = dwInfoLevel & 0x0000FFFF;
    const bool asNumber = (dwInfoLevel & kHTTP_QUERY_FLAG_NUMBER) != 0;

    if (infoId == kHTTP_QUERY_STATUS_CODE) {
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
    } else if (infoId == kHTTP_QUERY_STATUS_TEXT) {
        static constexpr wchar_t kStatusText[] = L"OK";
        if (lpBuffer != 0) {
            mem.Write(lpBuffer, kStatusText, sizeof(kStatusText));
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, sizeof(kStatusText));
        }
    } else {
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 0);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// Registration
// ============================================================================

void RegisterInternetAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "wininet.dll", "InternetOpenA",
          HandleInternetOpenA, 5, true },
        { "wininet.dll", "InternetOpenW",
          HandleInternetOpenW, 5, true },
        { "wininet.dll", "InternetConnectA",
          HandleInternetConnectA, 8, true },
        { "wininet.dll", "InternetConnectW",
          HandleInternetConnectW, 8, true },
        { "wininet.dll", "HttpOpenRequestA",
          HandleHttpOpenRequestA, 8, true },
        { "wininet.dll", "HttpOpenRequestW",
          HandleHttpOpenRequestW, 8, true },
        { "wininet.dll", "HttpSendRequestA",
          HandleHttpSendRequestA, 5, true },
        { "wininet.dll", "HttpSendRequestW",
          HandleHttpSendRequestW, 5, true },
        { "wininet.dll", "InternetReadFile",
          HandleInternetReadFile, 4, true },
        { "wininet.dll", "InternetCloseHandle",
          HandleInternetCloseHandle, 1, false },
        { "wininet.dll", "HttpQueryInfoA",
          HandleHttpQueryInfoA, 5, false },
        { "wininet.dll", "HttpQueryInfoW",
          HandleHttpQueryInfoW, 5, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Wininet
