/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * HttpStreamAPI.cpp — Wininet streaming HTTP API implementations
 *
 * Streaming HTTP APIs are used heavily by advanced C2 frameworks that
 * maintain persistent connections: chunked transfers, asynchronous I/O,
 * and callback-driven reads. Proxy manipulation and SSL bypass flags
 * detect common evasion patterns.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "HttpStreamAPI.hpp"
#include "../APIDispatcher.hpp"
#include "../HandleTable.hpp"
#include "../../Core/Memory/VirtualMemory.hpp"
#include "../../Core/CPU/State/CPUState.hpp"
#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace Phantom::WinAPI::Wininet {

// ============================================================================
// Internal constants
// ============================================================================

static constexpr uint32_t kMaxStringLen  = 4096;
static constexpr uint32_t kMaxHeaderLen  = 8192;

// Internet handle sub-types stored in SocketData::family
static constexpr int32_t kInetSession    = 0x1001;
static constexpr int32_t kInetConnection = 0x1002;
static constexpr int32_t kInetRequest    = 0x1003;

// InternetSetOption option codes
static constexpr uint32_t INTERNET_OPTION_PROXY          = 38;
static constexpr uint32_t INTERNET_OPTION_SECURITY_FLAGS  = 31;
static constexpr uint32_t INTERNET_OPTION_CONNECT_TIMEOUT = 2;
static constexpr uint32_t INTERNET_OPTION_SEND_TIMEOUT    = 5;
static constexpr uint32_t INTERNET_OPTION_RECEIVE_TIMEOUT = 6;
static constexpr uint32_t INTERNET_OPTION_USERNAME        = 28;
static constexpr uint32_t INTERNET_OPTION_PASSWORD        = 29;

// Security flag masks that indicate SSL validation bypass
static constexpr uint32_t SECURITY_FLAG_IGNORE_UNKNOWN_CA        = 0x00000100;
static constexpr uint32_t SECURITY_FLAG_IGNORE_CERT_DATE_INVALID = 0x00002000;
static constexpr uint32_t SECURITY_FLAG_IGNORE_CERT_CN_INVALID   = 0x00001000;
static constexpr uint32_t SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE  = 0x00000200;
static constexpr uint32_t SECURITY_FLAG_IGNORE_ALL_MASK =
    SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

// InternetGetConnectedState flags
static constexpr uint32_t INTERNET_CONNECTION_MODEM      = 0x01;
static constexpr uint32_t INTERNET_CONNECTION_LAN        = 0x02;

// Exfiltration thresholds
static constexpr uint64_t kDownloadExfilThreshold = 1024ULL * 1024;   // 1 MB
static constexpr uint64_t kUploadExfilThreshold   = 512ULL * 1024;    // 512 KB
static constexpr uint32_t kLargePostThreshold     = 64 * 1024;        // 64 KB

// Fake data available for InternetQueryDataAvailable
static constexpr uint32_t kFakeAvailableBytes = 4096;

// ============================================================================
// Per-connection cumulative byte tracker (Meyers' singleton)
// ============================================================================

class ConnectionTracker {
public:
    static ConnectionTracker& Instance() noexcept {
        static ConnectionTracker s_instance;
        return s_instance;
    }

    void AddDownloaded(GuestHandle h, uint64_t bytes) noexcept {
        std::unique_lock lock(m_mutex);
        m_downloaded[h] += bytes;
    }

    void AddUploaded(GuestHandle h, uint64_t bytes) noexcept {
        std::unique_lock lock(m_mutex);
        m_uploaded[h] += bytes;
    }

    [[nodiscard]] uint64_t GetDownloaded(GuestHandle h) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_downloaded.find(h);
        return (it != m_downloaded.end()) ? it->second : 0;
    }

    [[nodiscard]] uint64_t GetUploaded(GuestHandle h) const noexcept {
        std::shared_lock lock(m_mutex);
        auto it = m_uploaded.find(h);
        return (it != m_uploaded.end()) ? it->second : 0;
    }

    void Remove(GuestHandle h) noexcept {
        std::unique_lock lock(m_mutex);
        m_downloaded.erase(h);
        m_uploaded.erase(h);
    }

private:
    ConnectionTracker() noexcept = default;

    mutable std::shared_mutex                     m_mutex;
    std::unordered_map<GuestHandle, uint64_t>     m_downloaded;
    std::unordered_map<GuestHandle, uint64_t>     m_uploaded;
};

// ============================================================================
// Wide-to-narrow helper (ASCII truncation for IOC storage)
// ============================================================================

static std::string WideToNarrow(const std::wstring& ws) noexcept {
    std::string narrow;
    narrow.reserve(ws.size());
    for (wchar_t wc : ws) {
        narrow.push_back(static_cast<char>(wc & 0x7F));
    }
    return narrow;
}

// ============================================================================
// HttpSendRequestExA — hRequest(0), lpBuffersIn(1), lpBuffersOut(2),
//                       dwFlags(3), dwContext(4)
// ============================================================================

bool HandleHttpSendRequestExA(APIContext& ctx) {
    const auto hRequest = ctx.GetArg(0);
    const auto dwFlags  = ctx.GetArg32(3);

    (void)dwFlags;

    if (!ctx.Handles().IsValid(hRequest)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Track streaming request initiation — network activity IOC
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HttpSendRequestExW — wide-string variant
// ============================================================================

bool HandleHttpSendRequestExW(APIContext& ctx) {
    return HandleHttpSendRequestExA(ctx);
}

// ============================================================================
// InternetReadFileExA — hFile(0), lpBuffersOut(1), dwFlags(2), dwContext(3)
//
// INTERNET_BUFFERS_A layout (x64):
//   DWORD dwStructSize    (offset 0)
//   ... (Next pointer, etc.)
//   LPVOID lpvBuffer      (offset 24 on x64, 16 on x86)
//   DWORD dwBufferLength  (offset 32 on x64, 20 on x86)
// ============================================================================

bool HandleInternetReadFileExA(APIContext& ctx) {
    const auto hFile         = ctx.GetArg(0);
    const auto lpBuffersOut  = ctx.GetArgPtr(1);

    if (!ctx.Handles().IsValid(hFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Write zero bytes to the output buffer struct's dwBufferLength field
    // to signal end-of-data / connection close
    if (lpBuffersOut != 0) {
        auto& mem = ctx.Memory();
        const uint32_t bufLenOffset = ctx.Is64Bit() ? 32u : 20u;
        mem.WriteU32(lpBuffersOut + bufLenOffset, 0);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetReadFileExW — wide-string variant
// ============================================================================

bool HandleInternetReadFileExW(APIContext& ctx) {
    return HandleInternetReadFileExA(ctx);
}

// ============================================================================
// InternetSetOptionA — hInternet(0), dwOption(1), lpBuffer(2), dwBufferLength(3)
// ============================================================================

bool HandleInternetSetOptionA(APIContext& ctx) {
    const auto hInternet    = ctx.GetArg(0);
    const auto dwOption     = ctx.GetArg32(1);
    const auto lpBuffer     = ctx.GetArgPtr(2);
    const auto dwBufferLen  = ctx.GetArg32(3);

    (void)hInternet;
    (void)lpBuffer;
    (void)dwBufferLen;

    // Detect proxy configuration — C2 proxy setup IOC
    if (dwOption == INTERNET_OPTION_PROXY) {
        // Proxy set is flagged; dispatcher raises NetworkC2
    }

    // Detect SSL validation bypass — defense evasion IOC
    if (dwOption == INTERNET_OPTION_SECURITY_FLAGS && lpBuffer != 0 && dwBufferLen >= 4) {
        uint32_t flags = 0;
        ctx.Memory().ReadU32(lpBuffer, flags);
        if ((flags & SECURITY_FLAG_IGNORE_ALL_MASK) != 0) {
            // SSL bypass detected; dispatcher raises DefenseEvasion
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetSetOptionW — wide-string variant
// ============================================================================

bool HandleInternetSetOptionW(APIContext& ctx) {
    return HandleInternetSetOptionA(ctx);
}

// ============================================================================
// InternetGetConnectedState — lpdwFlags(0), dwReserved(1)
// ============================================================================

bool HandleInternetGetConnectedState(APIContext& ctx) {
    const auto lpdwFlags = ctx.GetArgPtr(0);

    // Report connected via LAN — malware expects connectivity
    if (lpdwFlags != 0) {
        ctx.Memory().WriteU32(lpdwFlags, INTERNET_CONNECTION_LAN);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetCheckConnectionA — lpszUrl(0), dwFlags(1), dwReserved(2)
// ============================================================================

bool HandleInternetCheckConnectionA(APIContext& ctx) {
    const auto lpszUrl = ctx.GetArgPtr(0);

    // Track the URL being checked (pre-C2 connectivity probe)
    if (lpszUrl != 0) {
        (void)ctx.ReadAnsiString(lpszUrl, kMaxStringLen);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetCheckConnectionW — wide-string variant
// ============================================================================

bool HandleInternetCheckConnectionW(APIContext& ctx) {
    const auto lpszUrl = ctx.GetArgPtr(0);

    if (lpszUrl != 0) {
        (void)ctx.ReadWideString(lpszUrl, kMaxStringLen / 2);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HttpEndRequestA — hRequest(0), lpBuffersOut(1), dwFlags(2), dwContext(3)
// ============================================================================

bool HandleHttpEndRequestA(APIContext& ctx) {
    const auto hRequest = ctx.GetArg(0);

    if (!ctx.Handles().IsValid(hRequest)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Streaming request complete — total bytes tracked in ConnectionTracker
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// HttpEndRequestW — wide-string variant
// ============================================================================

bool HandleHttpEndRequestW(APIContext& ctx) {
    return HandleHttpEndRequestA(ctx);
}

// ============================================================================
// InternetWriteFile — hFile(0), lpBuffer(1), dwNumberOfBytesToWrite(2),
//                      lpdwNumberOfBytesWritten(3)
// ============================================================================

bool HandleInternetWriteFile(APIContext& ctx) {
    const auto hFile           = ctx.GetArg(0);
    const auto lpBuffer        = ctx.GetArgPtr(1);
    const auto dwBytesToWrite  = ctx.GetArg32(2);
    const auto lpdwBytesWritten = ctx.GetArgPtr(3);

    (void)lpBuffer;

    if (!ctx.Handles().IsValid(hFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Cap reported write to prevent integer overflow in tracking
    const uint32_t safeBytes = std::min(dwBytesToWrite,
                                        static_cast<uint32_t>(16ULL * 1024 * 1024));

    ConnectionTracker::Instance().AddUploaded(hFile, safeBytes);

    // Report all bytes written successfully
    if (lpdwBytesWritten != 0) {
        ctx.Memory().WriteU32(lpdwBytesWritten, safeBytes);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetQueryDataAvailable — hFile(0), lpdwNumberOfBytesAvailable(1),
//                                dwFlags(2), dwContext(3)
// ============================================================================

bool HandleInternetQueryDataAvailable(APIContext& ctx) {
    const auto hFile       = ctx.GetArg(0);
    const auto lpdwAvail   = ctx.GetArgPtr(1);

    if (!ctx.Handles().IsValid(hFile)) {
        ctx.FailWithError(Win32::ERROR_INVALID_HANDLE);
        return true;
    }

    // Return a plausible byte count so the malware proceeds with reading
    if (lpdwAvail != 0) {
        ctx.Memory().WriteU32(lpdwAvail, kFakeAvailableBytes);
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetSetStatusCallback — hInternet(0), lpfnInternetCallback(1)
//
// Returns the previous callback (NULL/0 means no previous callback).
// We track callback registration as an async I/O IOC.
// ============================================================================

bool HandleInternetSetStatusCallback(APIContext& ctx) {
    const auto hInternet = ctx.GetArg(0);
    const auto lpfnCb    = ctx.GetArgPtr(1);

    (void)hInternet;
    (void)lpfnCb;

    // Return NULL (no previous callback) — malware does not validate this
    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturn(0);
    return true;
}

// ============================================================================
// InternetQueryOptionA — hInternet(0), dwOption(1), lpBuffer(2),
//                         lpdwBufferLength(3)
// ============================================================================

bool HandleInternetQueryOptionA(APIContext& ctx) {
    const auto dwOption      = ctx.GetArg32(1);
    const auto lpBuffer      = ctx.GetArgPtr(2);
    const auto lpdwBufferLen = ctx.GetArgPtr(3);

    auto& mem = ctx.Memory();

    if (dwOption == INTERNET_OPTION_CONNECT_TIMEOUT ||
        dwOption == INTERNET_OPTION_SEND_TIMEOUT ||
        dwOption == INTERNET_OPTION_RECEIVE_TIMEOUT) {
        // Return a plausible timeout value (30 seconds in ms)
        if (lpBuffer != 0) {
            mem.WriteU32(lpBuffer, 30000);
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 4);
        }
    } else if (dwOption == INTERNET_OPTION_PROXY) {
        // Return INTERNET_OPEN_TYPE_DIRECT (no proxy) — 3 DWORDs minimum
        if (lpBuffer != 0) {
            // INTERNET_PROXY_INFO: dwAccessType = DIRECT (1)
            mem.WriteU32(lpBuffer, 1);
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 4);
        }
    } else if (dwOption == INTERNET_OPTION_SECURITY_FLAGS) {
        // Return zero — no special security flags set
        if (lpBuffer != 0) {
            mem.WriteU32(lpBuffer, 0);
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 4);
        }
    } else {
        // Generic: return 4 zero bytes for unknown options
        if (lpBuffer != 0) {
            mem.WriteU32(lpBuffer, 0);
        }
        if (lpdwBufferLen != 0) {
            mem.WriteU32(lpdwBufferLen, 4);
        }
    }

    ctx.SetLastError(Win32::ERROR_SUCCESS);
    ctx.SetReturnBool(true);
    return true;
}

// ============================================================================
// InternetQueryOptionW — wide-string variant
// ============================================================================

bool HandleInternetQueryOptionW(APIContext& ctx) {
    // Option queries return numeric/struct data; identical to ANSI variant
    return HandleInternetQueryOptionA(ctx);
}

// ============================================================================
// Registration
// ============================================================================

void RegisterHttpStreamAPI(APIDispatcher& dispatcher) noexcept {
    static constexpr APIRegistration kRegs[] = {
        { "wininet.dll", "HttpSendRequestExA",
          HandleHttpSendRequestExA, 5, false },
        { "wininet.dll", "HttpSendRequestExW",
          HandleHttpSendRequestExW, 5, false },
        { "wininet.dll", "InternetReadFileExA",
          HandleInternetReadFileExA, 4, false },
        { "wininet.dll", "InternetReadFileExW",
          HandleInternetReadFileExW, 4, false },
        { "wininet.dll", "InternetSetOptionA",
          HandleInternetSetOptionA, 4, false },
        { "wininet.dll", "InternetSetOptionW",
          HandleInternetSetOptionW, 4, false },
        { "wininet.dll", "InternetGetConnectedState",
          HandleInternetGetConnectedState, 2, false },
        { "wininet.dll", "InternetCheckConnectionA",
          HandleInternetCheckConnectionA, 3, false },
        { "wininet.dll", "InternetCheckConnectionW",
          HandleInternetCheckConnectionW, 3, false },
        { "wininet.dll", "HttpEndRequestA",
          HandleHttpEndRequestA, 4, false },
        { "wininet.dll", "HttpEndRequestW",
          HandleHttpEndRequestW, 4, false },
        { "wininet.dll", "InternetWriteFile",
          HandleInternetWriteFile, 4, false },
        { "wininet.dll", "InternetQueryDataAvailable",
          HandleInternetQueryDataAvailable, 4, false },
        { "wininet.dll", "InternetSetStatusCallback",
          HandleInternetSetStatusCallback, 2, false },
        { "wininet.dll", "InternetQueryOptionA",
          HandleInternetQueryOptionA, 4, false },
        { "wininet.dll", "InternetQueryOptionW",
          HandleInternetQueryOptionW, 4, false },
    };

    dispatcher.RegisterBatch(kRegs, static_cast<uint32_t>(std::size(kRegs)));
}

} // namespace Phantom::WinAPI::Wininet
