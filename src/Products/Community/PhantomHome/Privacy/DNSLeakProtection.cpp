/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * ============================================================================
 * ShadowStrike NGAV - DNS LEAK PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file DNSLeakProtection.cpp
 * @brief Enterprise-grade DNS leak protection with DoH/DoT support
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - Integration with Windows DNS APIs
 *
 * PROTECTION LAYERS:
 * 1. Encrypted DNS enforcement (DoH, DoT, DoQ)
 * 2. DNS leak detection (VPN bypass, IPv6, WebRTC)
 * 3. Hijack detection (resolver modification, DHCP override)
 * 4. Cache poisoning protection (DNSSEC, cross-validation)
 * 5. Domain filtering (malware, trackers, custom blocklists)
 *
 * PERFORMANCE TARGETS:
 * - DNS query: <50ms for cache hit
 * - DoH query: <200ms for secure resolution
 * - Leak check: <100ms for full scan
 * - Hijack detection: <50ms per adapter check
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "DNSLeakProtection.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/Timer.hpp"
#include "../Utils/HashUtils.hpp"
#include <windns.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <ws2tcpip.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <fstream>
#include <condition_variable>

#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {
    using namespace ShadowStrike::Privacy;

    /// @brief DNS header size
    constexpr size_t DNS_HEADER_SIZE = 12;

    /// @brief Maximum DNS name length
    constexpr size_t MAX_DNS_NAME = 253;

    /// @brief Monitoring interval (ms)
    constexpr uint32_t MONITORING_INTERVAL_MS = 5000;

    /// @brief Cache cleanup interval (ms)
    constexpr uint32_t CACHE_CLEANUP_INTERVAL_MS = 60000;

    /// @brief Default DoH providers
    struct DefaultProvider {
        const char* id;
        const char* name;
        const char* url;
        const char* ip;
    };

    constexpr DefaultProvider DEFAULT_PROVIDERS[] = {
        {"cloudflare", "Cloudflare", "https://cloudflare-dns.com/dns-query", "1.1.1.1"},
        {"cloudflare-family", "Cloudflare Family", "https://family.cloudflare-dns.com/dns-query", "1.1.1.3"},
        {"google", "Google Public DNS", "https://dns.google/dns-query", "8.8.8.8"},
        {"quad9", "Quad9", "https://dns.quad9.net/dns-query", "9.9.9.9"},
        {"adguard", "AdGuard DNS", "https://dns.adguard-dns.com/dns-query", "94.140.14.14"}
    };

    /**
     * @brief Known VPN adapters
     */
    constexpr const char* VPN_ADAPTERS[] = {
        "TAP-Windows",
        "WireGuard",
        "OpenVPN",
        "NordVPN",
        "ExpressVPN",
        "ProtonVPN",
        "Surfshark",
        "CyberGhost",
        "IPVanish",
        "Mullvad"
    };

    /**
     * @brief Check if adapter is VPN
     */
    [[nodiscard]] bool IsVPNAdapter(const std::string& adapterName) {
        for (const auto* vpnName : VPN_ADAPTERS) {
            if (adapterName.find(vpnName) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Generate query ID
     */
    [[nodiscard]] uint64_t GenerateQueryId() {
        static std::atomic<uint64_t> s_counter{0};
        return s_counter++;
    }

    /// Maximum DoH JSON response size (64KB) to prevent OOM from malicious servers
    constexpr size_t MAX_DOH_RESPONSE_BYTES = 65536;

    /// Maximum domains in an imported blocklist
    constexpr size_t MAX_BLOCKLIST_DOMAINS = 500000;

    /// Maximum blocklist file size (50MB)
    constexpr uintmax_t MAX_BLOCKLIST_FILE_BYTES = 50ULL * 1024 * 1024;

    /// Maximum recent events kept in history buffers
    constexpr size_t MAX_EVENT_HISTORY = 1000;

    /**
     * @brief RAII wrapper for WinHTTP handles - prevents leaks on all exit paths
     */
    class WinHttpHandleGuard final {
    public:
        explicit WinHttpHandleGuard(HINTERNET h = nullptr) noexcept : m_handle(h) {}
        ~WinHttpHandleGuard() noexcept { if (m_handle) ::WinHttpCloseHandle(m_handle); }

        WinHttpHandleGuard(const WinHttpHandleGuard&) = delete;
        WinHttpHandleGuard& operator=(const WinHttpHandleGuard&) = delete;
        WinHttpHandleGuard(WinHttpHandleGuard&& other) noexcept
            : m_handle(other.m_handle) { other.m_handle = nullptr; }
        WinHttpHandleGuard& operator=(WinHttpHandleGuard&& other) noexcept {
            if (this != &other) {
                if (m_handle) ::WinHttpCloseHandle(m_handle);
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        [[nodiscard]] HINTERNET get() const noexcept { return m_handle; }
        [[nodiscard]] explicit operator bool() const noexcept { return m_handle != nullptr; }
    private:
        HINTERNET m_handle = nullptr;
    };

    /**
     * @brief URL-encode a domain name for safe use in DoH query parameters.
     *        Prevents parameter injection attacks.
     */
    [[nodiscard]] std::string UrlEncodeDomain(const std::string& domain) {
        std::string encoded;
        encoded.reserve(domain.size());
        for (unsigned char c : domain) {
            if (std::isalnum(c) || c == '-' || c == '.' || c == '_' || c == '~') {
                encoded += static_cast<char>(c);
            } else {
                char hex[4];
                std::snprintf(hex, sizeof(hex), "%%%02X", c);
                encoded += hex;
            }
        }
        return encoded;
    }

    /**
     * @brief Normalize domain name to canonical form (lowercase, no trailing dot).
     *        Required for consistent cache/blocklist lookups.
     */
    [[nodiscard]] std::string NormalizeDomain(const std::string& domain) {
        std::string normalized;
        normalized.reserve(domain.size());
        for (char c : domain) {
            normalized += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!normalized.empty() && normalized.back() == '.') {
            normalized.pop_back();
        }
        return normalized;
    }

    /**
     * @brief Flush system DNS resolver cache via dnsapi.dll private API.
     *        Safe replacement for system("ipconfig /flushdns").
     */
    void FlushSystemDnsCache() {
        using DnsFlushProc = BOOL(WINAPI*)();
        HMODULE hDnsApi = ::GetModuleHandleW(L"dnsapi.dll");
        if (hDnsApi) {
            auto pfnFlush = reinterpret_cast<DnsFlushProc>(
                ::GetProcAddress(hDnsApi, "DnsFlushResolverCache"));
            if (pfnFlush) {
                pfnFlush();
            }
        }
    }

    /**
     * @brief Trim an event history vector to MAX_EVENT_HISTORY
     */
    template <typename T>
    void TrimEventHistory(std::vector<T>& events) {
        if (events.size() > MAX_EVENT_HISTORY) {
            events.erase(events.begin(),
                events.begin() + static_cast<ptrdiff_t>(events.size() - MAX_EVENT_HISTORY));
        }
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::Privacy {

class DNSLeakProtectionImpl final {
public:
    DNSLeakProtectionImpl() = default;
    ~DNSLeakProtectionImpl() {
        StopMonitoring();
    }

    // Delete copy/move
    DNSLeakProtectionImpl(const DNSLeakProtectionImpl&) = delete;
    DNSLeakProtectionImpl& operator=(const DNSLeakProtectionImpl&) = delete;
    DNSLeakProtectionImpl(DNSLeakProtectionImpl&&) = delete;
    DNSLeakProtectionImpl& operator=(DNSLeakProtectionImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    DNSConfiguration m_config;
    DNSStatistics m_stats;

    // Current state
    std::atomic<bool> m_secureDnsEnabled{false};
    std::atomic<bool> m_monitoringActive{false};
    std::atomic<bool> m_vpnLeakDetected{false};
    DNSProvider m_currentProvider;

    // DNS cache
    std::unordered_map<std::string, DNSCacheEntry> m_dnsCache;

    // Blocklists
    std::unordered_set<std::string> m_blockedDomains;
    std::unordered_set<std::string> m_whitelistedDomains;

    // Event history
    std::vector<DNSLeakEvent> m_recentLeaks;
    std::vector<DNSHijackAlert> m_recentHijacks;

    // Saved DNS settings
    std::vector<std::string> m_savedDnsServers;
    // Per-adapter DNS settings for restoration
    struct SavedAdapterDns {
        std::wstring adapterGuid;
        std::wstring adapterName;
        std::string dnsServers;  // comma-separated, registry NameServer format
    };
    std::vector<SavedAdapterDns> m_savedAdapterDns;

    // Callbacks
    QueryCallback m_queryCallback;
    ResponseCallback m_responseCallback;
    LeakCallback m_leakCallback;
    HijackCallback m_hijackCallback;
    ErrorCallback m_errorCallback;

    // Monitoring
    std::thread m_monitoringThread;
    std::thread m_cacheCleanupThread;
    std::mutex m_shutdownMtx;
    std::condition_variable m_shutdownCv;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Invoke error callbacks
     */
    void NotifyError(const std::string& message, int code = 0) {
        std::shared_lock lock(m_mutex);
        if (m_errorCallback) {
            try {
                m_errorCallback(message, code);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Error callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown error callback exception");
            }
        }
    }

    /**
     * @brief Invoke leak callback
     */
    void NotifyLeak(const DNSLeakEvent& leak) {
        std::shared_lock lock(m_mutex);
        if (m_leakCallback) {
            try {
                m_leakCallback(leak);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Leak callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown leak callback exception");
            }
        }
    }

    /**
     * @brief Invoke hijack callback
     */
    void NotifyHijack(const DNSHijackAlert& alert) {
        std::shared_lock lock(m_mutex);
        if (m_hijackCallback) {
            try {
                m_hijackCallback(alert);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Hijack callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown hijack callback exception");
            }
        }
    }

    /**
     * @brief Get system DNS servers
     */
    [[nodiscard]] std::vector<std::string> GetSystemDnsServersInternal() {
        std::vector<std::string> servers;

        try {
            FIXED_INFO* fixedInfo = nullptr;
            ULONG bufferSize = sizeof(FIXED_INFO);
            std::vector<uint8_t> buffer(bufferSize);

            fixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());

            if (::GetNetworkParams(fixedInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                fixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());
            }

            if (::GetNetworkParams(fixedInfo, &bufferSize) == ERROR_SUCCESS) {
                IP_ADDR_STRING* dnsServer = &fixedInfo->DnsServerList;
                while (dnsServer) {
                    servers.push_back(dnsServer->IpAddress.String);
                    dnsServer = dnsServer->Next;
                }
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("GetSystemDnsServers failed: {}", e.what());
        }

        return servers;
    }

    /**
     * @brief Check if VPN is active by enumerating network adapters
     */
    [[nodiscard]] bool IsVPNActive() {
        try {
            ULONG bufferSize = 15000;
            std::vector<uint8_t> buffer(bufferSize);

            DWORD result = ::GetAdaptersInfo(
                reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data()), &bufferSize);

            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                result = ::GetAdaptersInfo(
                    reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data()), &bufferSize);
            }

            if (result == ERROR_SUCCESS) {
                auto* adapter = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());

                while (adapter) {
                    std::string adapterName = adapter->Description;
                    if (IsVPNAdapter(adapterName)) {
                        return true;
                    }
                    adapter = adapter->Next;
                }
            } else {
                Utils::Logger::Error("IsVPNActive: GetAdaptersInfo failed, error={}", result);
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("IsVPNActive check failed: {}", e.what());
        }

        return false;
    }

    /**
     * @brief Perform DoH (DNS-over-HTTPS) query with RAII handle management,
     *        URL injection prevention, response size cap, and proper JSON parsing.
     */
    [[nodiscard]] DNSResponse PerformDoHQuery(const std::string& domain, DNSRecordType recordType) {
        DNSResponse response;
        response.domain = domain;
        response.status = DNSResponseStatus::NetworkError;

        try {
            auto startTime = std::chrono::steady_clock::now();

            // URL-encode the domain to prevent parameter injection (e.g., &type=TXT&name=evil)
            std::string encodedDomain = UrlEncodeDomain(domain);

            // Build DoH URL with encoded domain
            std::string urlStr = m_currentProvider.primaryUrl;
            urlStr += "?name=" + encodedDomain + "&type=";
            switch (recordType) {
                case DNSRecordType::A:     urlStr += "A"; break;
                case DNSRecordType::AAAA:  urlStr += "AAAA"; break;
                case DNSRecordType::CNAME: urlStr += "CNAME"; break;
                case DNSRecordType::MX:    urlStr += "MX"; break;
                case DNSRecordType::TXT:   urlStr += "TXT"; break;
                default:                   urlStr += "A"; break;
            }

            std::wstring url = Utils::StringUtils::ToWide(urlStr);

            // RAII WinHTTP session
            WinHttpHandleGuard hSession(::WinHttpOpen(
                L"ShadowStrike DNS/3.0",
                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME,
                WINHTTP_NO_PROXY_BYPASS,
                0));

            if (!hSession) {
                Utils::Logger::Error("DoH: WinHttpOpen failed, error={}", ::GetLastError());
                return response;
            }

            // Configure timeouts to prevent hanging on malicious/slow servers
            ::WinHttpSetTimeouts(hSession.get(), 5000, 10000, 5000,
                static_cast<int>(m_config.queryTimeoutMs));

            // Parse URL components
            URL_COMPONENTS urlComp{};
            urlComp.dwStructSize = sizeof(urlComp);
            wchar_t hostName[256] = {};
            wchar_t urlPath[2048] = {};
            urlComp.lpszHostName = hostName;
            urlComp.dwHostNameLength = _countof(hostName);
            urlComp.lpszUrlPath = urlPath;
            urlComp.dwUrlPathLength = _countof(urlPath);

            if (!::WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
                Utils::Logger::Error("DoH: WinHttpCrackUrl failed, error={}", ::GetLastError());
                return response;
            }

            // RAII connection handle
            WinHttpHandleGuard hConnect(::WinHttpConnect(
                hSession.get(), urlComp.lpszHostName, urlComp.nPort, 0));

            if (!hConnect) {
                Utils::Logger::Error("DoH: WinHttpConnect failed, error={}", ::GetLastError());
                return response;
            }

            // RAII request handle
            WinHttpHandleGuard hRequest(::WinHttpOpenRequest(
                hConnect.get(), L"GET", urlComp.lpszUrlPath,
                nullptr, WINHTTP_NO_REFERER,
                WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE));

            if (!hRequest) {
                Utils::Logger::Error("DoH: WinHttpOpenRequest failed, error={}", ::GetLastError());
                return response;
            }

            // Request JSON response format for DoH
            ::WinHttpAddRequestHeaders(hRequest.get(),
                L"Accept: application/dns-json", -1L,
                WINHTTP_ADDREQ_FLAG_ADD);

            // Send and receive
            if (!::WinHttpSendRequest(hRequest.get(),
                    WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                Utils::Logger::Error("DoH: WinHttpSendRequest failed, error={}", ::GetLastError());
                return response;
            }

            if (!::WinHttpReceiveResponse(hRequest.get(), nullptr)) {
                Utils::Logger::Error("DoH: WinHttpReceiveResponse failed, error={}", ::GetLastError());
                return response;
            }

            // Verify HTTP 200 status
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            ::WinHttpQueryHeaders(hRequest.get(),
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode,
                &statusCodeSize, WINHTTP_NO_HEADER_INDEX);

            if (statusCode != 200) {
                Utils::Logger::Warn("DoH: HTTP {} for domain '{}'", statusCode, domain);
                response.status = DNSResponseStatus::ServerFailure;
                return response;
            }

            // Read response with size cap to prevent OOM from malicious server
            DWORD bytesAvailable = 0;
            std::string responseData;
            responseData.reserve(4096);

            while (::WinHttpQueryDataAvailable(hRequest.get(), &bytesAvailable) &&
                   bytesAvailable > 0) {
                if (responseData.size() + bytesAvailable > MAX_DOH_RESPONSE_BYTES) {
                    Utils::Logger::Warn("DoH: Response exceeded {}B limit for '{}'",
                        MAX_DOH_RESPONSE_BYTES, domain);
                    break;
                }

                std::vector<char> chunk(bytesAvailable);
                DWORD bytesRead = 0;
                if (::WinHttpReadData(hRequest.get(), chunk.data(),
                                      bytesAvailable, &bytesRead)) {
                    responseData.append(chunk.data(), bytesRead);
                }
            }

            // Parse JSON response using nlohmann::json via Utils
            if (!responseData.empty()) {
                try {
                    using ShadowStrike::Utils::JSON::Json;
                    auto json = Json::parse(responseData, nullptr, false);

                    if (json.is_discarded()) {
                        Utils::Logger::Error("DoH: Invalid JSON response for '{}'", domain);
                        return response;
                    }

                    // Map DNS RCODE to our status enum
                    int dnsStatus = json.value("Status", -1);
                    switch (dnsStatus) {
                        case 0: response.status = DNSResponseStatus::Success; break;
                        case 1: response.status = DNSResponseStatus::FormatError; return response;
                        case 2: response.status = DNSResponseStatus::ServerFailure; return response;
                        case 3: response.status = DNSResponseStatus::NonExistent; return response;
                        case 5: response.status = DNSResponseStatus::Refused; return response;
                        default:
                            response.status = DNSResponseStatus::NetworkError;
                            return response;
                    }

                    // Parse all Answer records
                    if (json.contains("Answer") && json["Answer"].is_array()) {
                        for (const auto& answer : json["Answer"]) {
                            if (answer.contains("data") && answer["data"].is_string()) {
                                std::string data = answer["data"].get<std::string>();
                                if (!data.empty() && data.size() <= 256) {
                                    // Sanitize: only printable ASCII in addresses
                                    bool safe = true;
                                    for (char c : data) {
                                        if (c < 0x20 || c > 0x7E) {
                                            safe = false;
                                            break;
                                        }
                                    }
                                    if (safe) {
                                        response.addresses.push_back(std::move(data));
                                    }
                                }
                            }
                            if (response.ttl == 0 && answer.contains("TTL")) {
                                response.ttl = answer.value("TTL", 0u);
                            }
                        }
                    }

                    // DNSSEC Authenticated Data flag
                    response.dnssecValidated = json.value("AD", false);

                } catch (const std::exception& e) {
                    Utils::Logger::Error("DoH: JSON parse error for '{}': {}", domain, e.what());
                    response.status = DNSResponseStatus::NetworkError;
                    return response;
                }
            }

            auto endTime = std::chrono::steady_clock::now();
            response.responseTimeMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    endTime - startTime).count());
            response.server = m_currentProvider.name;
            response.queryId = GenerateQueryId();

            m_stats.encryptedQueries++;

        } catch (const std::exception& e) {
            Utils::Logger::Error("DoH query failed for '{}': {}", domain, e.what());
            response.status = DNSResponseStatus::NetworkError;
        }

        return response;
    }

    /**
     * @brief Perform standard DNS query
     */
    [[nodiscard]] DNSResponse PerformStandardQuery(const std::string& domain, DNSRecordType recordType) {
        DNSResponse response;
        response.domain = domain;
        response.status = DNSResponseStatus::NetworkError;

        try {
            auto startTime = std::chrono::steady_clock::now();

            std::wstring wideDomain = Utils::StringUtils::ToWide(domain);
            PDNS_RECORD pDnsRecord = nullptr;

            WORD wType = DNS_TYPE_A;
            switch (recordType) {
                case DNSRecordType::A: wType = DNS_TYPE_A; break;
                case DNSRecordType::AAAA: wType = DNS_TYPE_AAAA; break;
                case DNSRecordType::CNAME: wType = DNS_TYPE_CNAME; break;
                case DNSRecordType::MX: wType = DNS_TYPE_MX; break;
                case DNSRecordType::TXT: wType = DNS_TYPE_TEXT; break;
                default: wType = DNS_TYPE_A; break;
            }

            DNS_STATUS status = ::DnsQuery_W(
                wideDomain.c_str(),
                wType,
                DNS_QUERY_STANDARD,
                nullptr,
                &pDnsRecord,
                nullptr);

            if (status == ERROR_SUCCESS && pDnsRecord) {
                response.status = DNSResponseStatus::Success;

                PDNS_RECORD pRecord = pDnsRecord;
                while (pRecord) {
                    if (pRecord->wType == DNS_TYPE_A) {
                        IN_ADDR addr;
                        addr.S_un.S_addr = pRecord->Data.A.IpAddress;
                        char ipStr[INET_ADDRSTRLEN];
                        ::inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
                        response.addresses.push_back(ipStr);
                    }
                    else if (pRecord->wType == DNS_TYPE_AAAA) {
                        char ipStr[INET6_ADDRSTRLEN];
                        ::inet_ntop(AF_INET6, &pRecord->Data.AAAA.Ip6Address, ipStr, sizeof(ipStr));
                        response.addresses.push_back(ipStr);
                    }

                    response.ttl = pRecord->dwTtl;
                    pRecord = pRecord->pNext;
                }

                ::DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
            }
            else {
                switch (status) {
                    case DNS_ERROR_RCODE_NAME_ERROR:
                        response.status = DNSResponseStatus::NonExistent;
                        break;
                    case DNS_ERROR_RCODE_SERVER_FAILURE:
                        response.status = DNSResponseStatus::ServerFailure;
                        break;
                    default:
                        response.status = DNSResponseStatus::NetworkError;
                        break;
                }
            }

            auto endTime = std::chrono::steady_clock::now();
            response.responseTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - startTime).count();

        } catch (const std::exception& e) {
            Utils::Logger::Error("DNS query failed: {}", e.what());
            response.status = DNSResponseStatus::NetworkError;
        }

        return response;
    }

    /**
     * @brief Monitoring thread function with interruptible sleep
     */
    void MonitoringThreadFunc() {
        Utils::Logger::Info("DNS monitoring thread started");

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // Check for DNS hijacking
                CheckForHijackingInternal();

                // Check for DNS leaks if VPN is active
                if (IsVPNActive()) {
                    CheckForLeaksInternal();
                }

            } catch (const std::exception& e) {
                Utils::Logger::Error("Monitoring thread error: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown monitoring thread error");
            }

            // Interruptible sleep - wakes immediately on shutdown signal
            {
                std::unique_lock lock(m_shutdownMtx);
                m_shutdownCv.wait_for(lock,
                    std::chrono::milliseconds(MONITORING_INTERVAL_MS),
                    [this]{ return !m_monitoringActive.load(std::memory_order_acquire); });
            }
        }

        Utils::Logger::Info("DNS monitoring thread stopped");
    }

    /**
     * @brief Cache cleanup thread - uses two-phase eviction to minimize lock hold time
     */
    void CacheCleanupThreadFunc() {
        Utils::Logger::Info("DNS cache cleanup thread started");

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // Phase 1: identify expired keys under shared lock (no blocking)
                std::vector<std::string> expiredKeys;
                {
                    std::shared_lock readLock(m_mutex);
                    for (const auto& [domain, entry] : m_dnsCache) {
                        if (entry.IsExpired()) {
                            expiredKeys.push_back(domain);
                        }
                    }
                }

                // Phase 2: erase under unique lock (brief hold)
                if (!expiredKeys.empty()) {
                    std::unique_lock writeLock(m_mutex);
                    for (const auto& key : expiredKeys) {
                        m_dnsCache.erase(key);
                    }
                }

            } catch (const std::exception& e) {
                Utils::Logger::Error("Cache cleanup error: {}", e.what());
            }

            // Interruptible sleep
            {
                std::unique_lock lock(m_shutdownMtx);
                m_shutdownCv.wait_for(lock,
                    std::chrono::milliseconds(CACHE_CLEANUP_INTERVAL_MS),
                    [this]{ return !m_monitoringActive.load(std::memory_order_acquire); });
            }
        }

        Utils::Logger::Info("DNS cache cleanup thread stopped");
    }

    /**
     * @brief Check for DNS leaks by comparing system DNS servers against VPN adapter DNS.
     *        Uses GetAdaptersAddresses for proper IPv4/IPv6 adapter enumeration.
     */
    void CheckForLeaksInternal() {
        try {
            // Enumerate adapters to discover VPN vs non-VPN DNS servers
            ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
            ULONG bufferSize = 16384;
            std::vector<uint8_t> buffer(bufferSize);

            DWORD result = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferSize);

            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                result = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferSize);
            }

            if (result != ERROR_SUCCESS) {
                Utils::Logger::Error("CheckForLeaks: GetAdaptersAddresses failed, error={}", result);
                return;
            }

            std::unordered_set<std::string> vpnDnsServers;
            std::unordered_set<std::string> nonVpnDnsServers;
            bool vpnAdapterFound = false;

            auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            while (adapter) {
                // Skip down/loopback adapters
                if (adapter->OperStatus != IfOperStatusUp ||
                    adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    adapter = adapter->Next;
                    continue;
                }

                std::string adapterDesc = Utils::StringUtils::ToNarrow(adapter->Description);
                bool isVpn = IsVPNAdapter(adapterDesc) ||
                             adapter->IfType == IF_TYPE_TUNNEL ||
                             adapter->IfType == IF_TYPE_PPP;

                if (isVpn) vpnAdapterFound = true;

                // Collect DNS servers for this adapter
                auto* dnsServer = adapter->FirstDnsServerAddress;
                while (dnsServer) {
                    char ipStr[INET6_ADDRSTRLEN] = {};
                    if (dnsServer->Address.lpSockaddr->sa_family == AF_INET) {
                        auto* sa = reinterpret_cast<sockaddr_in*>(dnsServer->Address.lpSockaddr);
                        ::inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
                    } else if (dnsServer->Address.lpSockaddr->sa_family == AF_INET6) {
                        auto* sa6 = reinterpret_cast<sockaddr_in6*>(dnsServer->Address.lpSockaddr);
                        ::inet_ntop(AF_INET6, &sa6->sin6_addr, ipStr, sizeof(ipStr));
                    }

                    if (ipStr[0] != '\0') {
                        if (isVpn) {
                            vpnDnsServers.insert(ipStr);
                        } else {
                            nonVpnDnsServers.insert(ipStr);
                        }
                    }
                    dnsServer = dnsServer->Next;
                }

                adapter = adapter->Next;
            }

            if (!vpnAdapterFound || vpnDnsServers.empty()) {
                return;  // No VPN active or no VPN DNS configured
            }

            // Leak detection: system-level DNS servers not routed through VPN
            auto systemServers = GetSystemDnsServersInternal();

            for (const auto& server : systemServers) {
                if (server == "127.0.0.1" || server == "::1") continue;

                if (vpnDnsServers.find(server) == vpnDnsServers.end()) {
                    DNSLeakEvent leak;
                    leak.eventId = GenerateQueryId();
                    leak.leakType = DNSLeakType::VPNBypass;
                    leak.actualServer = server;
                    leak.vpnActive = true;
                    leak.severity = 8;
                    leak.timestamp = std::chrono::system_clock::now();
                    leak.description = "DNS server " + server +
                        " is not in VPN tunnel DNS set - potential DNS leak";

                    if (!vpnDnsServers.empty()) {
                        leak.expectedServer = *vpnDnsServers.begin();
                    }

                    {
                        std::unique_lock lock(m_mutex);
                        m_recentLeaks.push_back(leak);
                        TrimEventHistory(m_recentLeaks);
                    }

                    m_vpnLeakDetected.store(true, std::memory_order_release);
                    m_stats.leaksDetected++;

                    NotifyLeak(leak);

                    Utils::Logger::Warn("DNS leak detected: server {} not in VPN DNS set", server);
                }
            }

            // IPv6 leak detection
            if (m_config.blockIPv6DNS) {
                for (const auto& server : nonVpnDnsServers) {
                    if (server.find(':') != std::string::npos) {
                        DNSLeakEvent leak;
                        leak.eventId = GenerateQueryId();
                        leak.leakType = DNSLeakType::IPv6Leak;
                        leak.actualServer = server;
                        leak.vpnActive = true;
                        leak.severity = 6;
                        leak.timestamp = std::chrono::system_clock::now();
                        leak.description = "IPv6 DNS server " + server +
                            " on non-VPN adapter while VPN active";

                        {
                            std::unique_lock lock(m_mutex);
                            m_recentLeaks.push_back(leak);
                            TrimEventHistory(m_recentLeaks);
                        }

                        m_stats.leaksDetected++;
                        NotifyLeak(leak);
                        Utils::Logger::Warn("IPv6 DNS leak detected: {}", server);
                    }
                }
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("CheckForLeaksInternal failed: {}", e.what());
        }
    }

    /**
     * @brief Check for DNS hijacking - compares current system DNS against saved baseline.
     *        Updates saved state atomically before releasing lock to prevent race window.
     */
    void CheckForHijackingInternal() {
        auto currentServers = GetSystemDnsServersInternal();

        std::unique_lock lock(m_mutex);

        if (!m_savedDnsServers.empty() && currentServers != m_savedDnsServers) {
            DNSHijackAlert alert;
            alert.alertId = GenerateQueryId();
            alert.alertType = "DNS Server Modification";
            alert.previousServers = m_savedDnsServers;
            alert.newServers = currentServers;
            alert.changeSource = "Unknown";
            alert.severity = 7;
            alert.timestamp = std::chrono::system_clock::now();

            m_recentHijacks.push_back(alert);
            TrimEventHistory(m_recentHijacks);

            m_stats.hijackAttemptsDetected++;

            // Update saved servers BEFORE releasing lock to prevent race
            m_savedDnsServers = currentServers;

            lock.unlock();
            NotifyHijack(alert);

            Utils::Logger::Warn("DNS hijack detected: servers changed ({} -> {} entries)",
                               alert.previousServers.size(), alert.newServers.size());
        }
    }

    /**
     * @brief Save per-adapter DNS settings from registry for later restoration
     */
    void SavePerAdapterDns() {
        try {
            m_savedAdapterDns.clear();

            ULONG flags = GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST;
            ULONG bufferSize = 16384;
            std::vector<uint8_t> buffer(bufferSize);

            DWORD result = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferSize);

            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                result = ::GetAdaptersAddresses(AF_UNSPEC, flags, nullptr,
                    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &bufferSize);
            }

            if (result != ERROR_SUCCESS) {
                Utils::Logger::Error("SavePerAdapterDns: GetAdaptersAddresses failed, error={}", result);
                return;
            }

            auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            while (adapter) {
                if (adapter->OperStatus == IfOperStatusUp) {
                    SavedAdapterDns saved;
                    saved.adapterGuid = adapter->AdapterName
                        ? Utils::StringUtils::ToWide(adapter->AdapterName)
                        : L"";
                    saved.adapterName = adapter->FriendlyName
                        ? adapter->FriendlyName
                        : L"";

                    // Read current NameServer from registry for this adapter
                    std::wstring regPath =
                        L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
                        + saved.adapterGuid;

                    HKEY hKey = nullptr;
                    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(),
                                        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                        // RAII guard to prevent handle leak on exception
                        auto keyGuard = [&hKey]() { if (hKey) { ::RegCloseKey(hKey); hKey = nullptr; } };
                        struct KeyGuardRAII { decltype(keyGuard)& fn; ~KeyGuardRAII() { fn(); } } keyCleanup{keyGuard};

                        wchar_t nameServer[512] = {};
                        DWORD size = sizeof(nameServer);
                        DWORD type = 0;
                        if (::RegQueryValueExW(hKey, L"NameServer", nullptr, &type,
                                reinterpret_cast<BYTE*>(nameServer), &size) == ERROR_SUCCESS
                            && type == REG_SZ) {
                            saved.dnsServers = Utils::StringUtils::ToNarrow(nameServer);
                        }
                    }

                    if (!saved.adapterGuid.empty()) {
                        m_savedAdapterDns.push_back(std::move(saved));
                    }
                }
                adapter = adapter->Next;
            }

            Utils::Logger::Info("Saved DNS settings for {} adapters", m_savedAdapterDns.size());

        } catch (const std::exception& e) {
            Utils::Logger::Error("SavePerAdapterDns failed: {}", e.what());
        }
    }

    /**
     * @brief Stop monitoring threads with immediate wakeup via condition variable
     */
    void StopMonitoring() {
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);

            // Wake sleeping threads immediately instead of waiting up to 5s/60s
            m_shutdownCv.notify_all();

            if (m_monitoringThread.joinable()) {
                m_monitoringThread.join();
            }

            if (m_cacheCleanupThread.joinable()) {
                m_cacheCleanupThread.join();
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> DNSLeakProtection::s_instanceCreated{false};

[[nodiscard]] DNSLeakProtection& DNSLeakProtection::Instance() noexcept {
    static DNSLeakProtection instance;
    return instance;
}

[[nodiscard]] bool DNSLeakProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

DNSLeakProtection::DNSLeakProtection()
    : m_impl(std::make_unique<DNSLeakProtectionImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    Utils::Logger::Info("DNSLeakProtection singleton created");
}

DNSLeakProtection::~DNSLeakProtection() {
    try {
        Shutdown();
        Utils::Logger::Info("DNSLeakProtection singleton destroyed");
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool DNSLeakProtection::Initialize(const DNSConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            Utils::Logger::Warn("DNSLeakProtection already initialized");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid DNSLeakProtection configuration");
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }

        m_impl->m_config = config;

        // Set default provider if not set
        if (m_impl->m_config.primaryProvider.providerId.empty()) {
            m_impl->m_config.primaryProvider.providerId = "cloudflare";
            m_impl->m_config.primaryProvider.name = "Cloudflare";
            m_impl->m_config.primaryProvider.primaryUrl = "https://cloudflare-dns.com/dns-query";
            m_impl->m_config.primaryProvider.primaryIp = "1.1.1.1";
            m_impl->m_config.primaryProvider.protocol = DNSProtocol::DoH;
        }

        m_impl->m_currentProvider = m_impl->m_config.primaryProvider;

        // Save current DNS servers
        m_impl->m_savedDnsServers = m_impl->GetSystemDnsServersInternal();

        // Save per-adapter DNS settings for restoration capability
        m_impl->SavePerAdapterDns();

        // Reset statistics
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        // Enable secure DNS if configured
        if (config.forceEncryptedDNS) {
            m_impl->m_secureDnsEnabled.store(true, std::memory_order_release);
        }

        m_impl->m_status = ModuleStatus::Running;

        Utils::Logger::Info("DNSLeakProtection initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DNSLeakProtection initialization failed: {}", e.what());
        m_impl->m_status = ModuleStatus::Error;
        m_impl->NotifyError("Initialization failed: " + std::string(e.what()), -1);
        return false;
    }
}

void DNSLeakProtection::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;

        // Stop monitoring
        lock.unlock();
        m_impl->StopMonitoring();
        lock.lock();

        // Clear caches
        m_impl->m_dnsCache.clear();
        m_impl->m_blockedDomains.clear();
        m_impl->m_recentLeaks.clear();
        m_impl->m_recentHijacks.clear();

        // Clear callbacks
        m_impl->m_queryCallback = nullptr;
        m_impl->m_responseCallback = nullptr;
        m_impl->m_leakCallback = nullptr;
        m_impl->m_hijackCallback = nullptr;
        m_impl->m_errorCallback = nullptr;

        m_impl->m_secureDnsEnabled.store(false, std::memory_order_release);
        m_impl->m_vpnLeakDetected.store(false, std::memory_order_release);
        m_impl->m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("DNSLeakProtection shut down");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool DNSLeakProtection::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == ModuleStatus::Running || status == ModuleStatus::Monitoring;
}

[[nodiscard]] ModuleStatus DNSLeakProtection::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

[[nodiscard]] bool DNSLeakProtection::UpdateConfiguration(const DNSConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_impl->m_config = config;

        Utils::Logger::Info("DNSLeakProtection configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Configuration update failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] DNSConfiguration DNSLeakProtection::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// SECURE DNS
// ============================================================================

[[nodiscard]] bool DNSLeakProtection::EnableSecureDns(const std::string& providerUrl) {
    try {
        if (providerUrl.empty()) {
            Utils::Logger::Error("EnableSecureDns: Empty provider URL");
            return false;
        }

        std::unique_lock lock(m_impl->m_mutex);

        // Find provider by URL in known providers
        bool found = false;
        for (const auto& provider : DEFAULT_PROVIDERS) {
            if (providerUrl == provider.url) {
                m_impl->m_currentProvider.providerId = provider.id;
                m_impl->m_currentProvider.name = provider.name;
                m_impl->m_currentProvider.primaryUrl = provider.url;
                m_impl->m_currentProvider.primaryIp = provider.ip;
                m_impl->m_currentProvider.protocol = DNSProtocol::DoH;
                found = true;
                break;
            }
        }

        if (!found) {
            // Accept custom provider URL - must use HTTPS
            if (providerUrl.rfind("https://", 0) != 0) {
                Utils::Logger::Error("EnableSecureDns: Custom provider must use HTTPS, got '{}'",
                    providerUrl.substr(0, std::min<size_t>(providerUrl.size(), 32)));
                return false;
            }
            m_impl->m_currentProvider.providerId = "custom";
            m_impl->m_currentProvider.name = "Custom";
            m_impl->m_currentProvider.primaryUrl = providerUrl;
            m_impl->m_currentProvider.protocol = DNSProtocol::DoH;
        }

        m_impl->m_secureDnsEnabled.store(true, std::memory_order_release);

        Utils::Logger::Info("Secure DNS enabled: {}", m_impl->m_currentProvider.name);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EnableSecureDns failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool DNSLeakProtection::DisableSecureDns() {
    try {
        m_impl->m_secureDnsEnabled.store(false, std::memory_order_release);
        Utils::Logger::Info("Secure DNS disabled");
        return true;

    } catch (...) {
        return false;
    }
}

[[nodiscard]] bool DNSLeakProtection::IsSecureDnsEnabled() const noexcept {
    return m_impl->m_secureDnsEnabled.load(std::memory_order_acquire);
}

[[nodiscard]] bool DNSLeakProtection::SetProvider(const DNSProvider& provider) {
    try {
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_currentProvider = provider;

        Utils::Logger::Info("DNS provider set to: {}", provider.name);
        return true;

    } catch (...) {
        return false;
    }
}

[[nodiscard]] DNSProvider DNSLeakProtection::GetCurrentProvider() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentProvider;
}

[[nodiscard]] std::vector<DNSProvider> DNSLeakProtection::GetAvailableProviders() const {
    std::vector<DNSProvider> providers;

    for (const auto& provider : DEFAULT_PROVIDERS) {
        DNSProvider p;
        p.providerId = provider.id;
        p.name = provider.name;
        p.primaryUrl = provider.url;
        p.primaryIp = provider.ip;
        p.protocol = DNSProtocol::DoH;
        p.supportsDNSSEC = true;
        providers.push_back(p);
    }

    return providers;
}

// ============================================================================
// MONITORING
// ============================================================================

[[nodiscard]] bool DNSLeakProtection::MonitorDnsActivity() {
    try {
        if (m_impl->m_monitoringActive.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("Monitoring already active");
            return true;
        }

        m_impl->m_monitoringActive.store(true, std::memory_order_release);
        m_impl->m_status = ModuleStatus::Monitoring;

        // Start monitoring thread
        m_impl->m_monitoringThread = std::thread(
            &DNSLeakProtectionImpl::MonitoringThreadFunc, m_impl.get());

        // Start cache cleanup thread
        m_impl->m_cacheCleanupThread = std::thread(
            &DNSLeakProtectionImpl::CacheCleanupThreadFunc, m_impl.get());

        Utils::Logger::Info("DNS monitoring started");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("MonitorDnsActivity failed: {}", e.what());
        m_impl->NotifyError("Failed to start monitoring: " + std::string(e.what()), -1);
        return false;
    }
}

void DNSLeakProtection::StopMonitoring() {
    m_impl->StopMonitoring();
    m_impl->m_status = ModuleStatus::Running;
    Utils::Logger::Info("DNS monitoring stopped");
}

[[nodiscard]] bool DNSLeakProtection::IsMonitoringActive() const noexcept {
    return m_impl->m_monitoringActive.load(std::memory_order_acquire);
}

// ============================================================================
// LEAK DETECTION
// ============================================================================

[[nodiscard]] std::vector<DNSLeakEvent> DNSLeakProtection::CheckForLeaks() {
    std::vector<DNSLeakEvent> leaks;

    try {
        if (m_impl->IsVPNActive()) {
            m_impl->CheckForLeaksInternal();
        }

        std::shared_lock lock(m_impl->m_mutex);
        leaks = m_impl->m_recentLeaks;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckForLeaks failed: {}", e.what());
    }

    return leaks;
}

[[nodiscard]] bool DNSLeakProtection::IsVPNLeakDetected() const noexcept {
    return m_impl->m_vpnLeakDetected.load(std::memory_order_acquire);
}

[[nodiscard]] std::vector<DNSLeakEvent> DNSLeakProtection::GetRecentLeaks(size_t limit) {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<DNSLeakEvent> leaks = m_impl->m_recentLeaks;
    if (leaks.size() > limit) {
        leaks.resize(limit);
    }

    return leaks;
}

// ============================================================================
// HIJACK DETECTION
// ============================================================================

[[nodiscard]] std::vector<DNSHijackAlert> DNSLeakProtection::CheckForHijacking() {
    std::vector<DNSHijackAlert> alerts;

    try {
        m_impl->CheckForHijackingInternal();

        std::shared_lock lock(m_impl->m_mutex);
        alerts = m_impl->m_recentHijacks;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckForHijacking failed: {}", e.what());
    }

    return alerts;
}

[[nodiscard]] std::vector<std::string> DNSLeakProtection::GetSystemDNSServers() {
    return m_impl->GetSystemDnsServersInternal();
}

[[nodiscard]] bool DNSLeakProtection::RestoreDNSSettings() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_savedAdapterDns.empty()) {
            Utils::Logger::Warn("No saved per-adapter DNS settings to restore");
            return false;
        }

        bool allRestored = true;

        for (const auto& saved : m_impl->m_savedAdapterDns) {
            // Write original DNS server configuration back to the adapter registry key
            std::wstring regPath =
                L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
                + saved.adapterGuid;

            HKEY hKey = nullptr;
            LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(),
                0, KEY_SET_VALUE, &hKey);

            if (status != ERROR_SUCCESS) {
                Utils::Logger::Error("RestoreDNS: Failed to open registry for adapter '{}', error={}",
                    Utils::StringUtils::ToNarrow(saved.adapterName), status);
                allRestored = false;
                continue;
            }

            // Write the NameServer value (comma-separated IP list matching original)
            std::wstring wServers = Utils::StringUtils::ToWide(saved.dnsServers);
            status = ::RegSetValueExW(hKey, L"NameServer", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(wServers.c_str()),
                static_cast<DWORD>((wServers.length() + 1) * sizeof(wchar_t)));

            ::RegCloseKey(hKey);

            if (status != ERROR_SUCCESS) {
                Utils::Logger::Error("RestoreDNS: Failed to write DNS for adapter '{}', error={}",
                    Utils::StringUtils::ToNarrow(saved.adapterName), status);
                allRestored = false;
            } else {
                Utils::Logger::Info("RestoreDNS: Restored DNS for adapter '{}'",
                    Utils::StringUtils::ToNarrow(saved.adapterName));
            }
        }

        lock.unlock();

        // Flush system DNS resolver cache to apply the restored settings
        FlushSystemDnsCache();

        Utils::Logger::Info("DNS settings restoration {}",
            allRestored ? "completed successfully" : "completed with errors");
        return allRestored;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RestoreDNSSettings failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::vector<DNSHijackAlert> DNSLeakProtection::GetRecentHijackAlerts(size_t limit) {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<DNSHijackAlert> alerts = m_impl->m_recentHijacks;
    if (alerts.size() > limit) {
        alerts.resize(limit);
    }

    return alerts;
}

// ============================================================================
// CACHE POISONING
// ============================================================================

[[nodiscard]] std::vector<DNSCacheEntry> DNSLeakProtection::CheckCacheForPoisoning() {
    std::vector<DNSCacheEntry> suspicious;

    try {
        // Snapshot cache entries under shared lock to minimize lock duration
        std::vector<std::pair<std::string, DNSCacheEntry>> snapshot;
        {
            std::shared_lock lock(m_impl->m_mutex);
            snapshot.reserve(m_impl->m_dnsCache.size());
            for (const auto& [domain, entry] : m_impl->m_dnsCache) {
                snapshot.emplace_back(domain, entry);
            }
        }

        for (const auto& [domain, entry] : snapshot) {
            bool isSuspicious = false;

            // Heuristic 1: Extremely low TTL often indicates poisoned entries.
            // CDNs typically use TTL >= 30; poisoned entries often use < 10.
            if (entry.originalTtl > 0 && entry.originalTtl < 10) {
                isSuspicious = true;
            }

            // Heuristic 2: Cross-reference with DoH if secure DNS is available.
            // Mismatches between local cache and DoH resolution indicate tampering.
            if (m_impl->m_secureDnsEnabled.load(std::memory_order_acquire) &&
                !entry.addresses.empty()) {
                auto dohResponse = m_impl->PerformDoHQuery(domain, entry.recordType);
                if (dohResponse.status == DNSResponseStatus::Success &&
                    !dohResponse.addresses.empty()) {
                    bool hasMatch = false;
                    for (const auto& cachedAddr : entry.addresses) {
                        for (const auto& dohAddr : dohResponse.addresses) {
                            if (cachedAddr == dohAddr) {
                                hasMatch = true;
                                break;
                            }
                        }
                        if (hasMatch) break;
                    }

                    if (!hasMatch) {
                        isSuspicious = true;
                        Utils::Logger::Warn("Cache poisoning suspected for '{}': "
                            "cached={}, DoH={}",
                            domain,
                            entry.addresses.empty() ? "none" : entry.addresses[0],
                            dohResponse.addresses.empty() ? "none" : dohResponse.addresses[0]);
                    }
                }
            }

            if (isSuspicious) {
                suspicious.push_back(entry);
                m_impl->m_stats.poisoningAttemptsDetected++;
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckCacheForPoisoning failed: {}", e.what());
    }

    return suspicious;
}

[[nodiscard]] PoisoningStatus DNSLeakProtection::VerifyDomainResolution(const std::string& domain) {
    try {
        // Query from multiple providers and compare results
        auto response1 = m_impl->PerformDoHQuery(domain, DNSRecordType::A);

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        auto response2 = m_impl->PerformStandardQuery(domain, DNSRecordType::A);

        // Compare results
        if (response1.addresses == response2.addresses) {
            return PoisoningStatus::Verified;
        } else if (response1.addresses.empty() || response2.addresses.empty()) {
            return PoisoningStatus::Clean;
        } else {
            Utils::Logger::Warn("DNS poisoning suspected for domain: {}", domain);
            m_impl->m_stats.poisoningAttemptsDetected++;
            return PoisoningStatus::Suspicious;
        }

    } catch (...) {
        return PoisoningStatus::Clean;
    }
}

[[nodiscard]] bool DNSLeakProtection::ClearDNSCache() {
    try {
        {
            std::unique_lock lock(m_impl->m_mutex);
            m_impl->m_dnsCache.clear();
        }

        // Flush system DNS resolver cache via dnsapi.dll API
        // (replaces vulnerable system("ipconfig /flushdns") call)
        FlushSystemDnsCache();

        Utils::Logger::Info("DNS cache cleared (internal + system resolver)");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ClearDNSCache failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// DNS QUERIES
// ============================================================================

[[nodiscard]] DNSResponse DNSLeakProtection::ResolveDomain(
    const std::string& domain,
    DNSRecordType recordType)
{
    DNSResponse response;
    response.domain = domain;

    try {
        // Validate domain name before any processing
        if (!IsValidDomainName(domain)) {
            Utils::Logger::Warn("ResolveDomain: Invalid domain name rejected");
            response.status = DNSResponseStatus::FormatError;
            return response;
        }

        std::string normalized = NormalizeDomain(domain);

        m_impl->m_stats.totalQueries++;

        // Check cache first (unique_lock needed since hitCount is modified)
        if (m_impl->m_config.enableCache) {
            std::unique_lock lock(m_impl->m_mutex);
            auto it = m_impl->m_dnsCache.find(normalized);
            if (it != m_impl->m_dnsCache.end() && !it->second.IsExpired()) {
                response.domain = domain;
                response.addresses = it->second.addresses;
                response.status = DNSResponseStatus::Success;
                response.ttl = it->second.ttlRemaining;
                response.server = "Cache";

                it->second.hitCount++;
                m_impl->m_stats.cacheHits++;

                return response;
            }
        }

        m_impl->m_stats.cacheMisses++;

        // Check if domain is blocked
        {
            std::shared_lock lock(m_impl->m_mutex);
            if (m_impl->m_blockedDomains.count(normalized) > 0) {
                response.status = DNSResponseStatus::Blocked;
                m_impl->m_stats.blockedDomains++;
                return response;
            }
        }

        // Perform query
        if (m_impl->m_secureDnsEnabled.load(std::memory_order_acquire)) {
            response = m_impl->PerformDoHQuery(domain, recordType);
        } else {
            response = m_impl->PerformStandardQuery(domain, recordType);
        }

        // Cache response with size limit enforcement
        if (response.status == DNSResponseStatus::Success && m_impl->m_config.enableCache) {
            std::unique_lock lock(m_impl->m_mutex);

            // Enforce cache size limit - evict oldest entry
            if (m_impl->m_dnsCache.size() >= DNSConstants::MAX_DNS_CACHE) {
                auto oldest = m_impl->m_dnsCache.begin();
                for (auto it = m_impl->m_dnsCache.begin(); it != m_impl->m_dnsCache.end(); ++it) {
                    if (it->second.creationTime < oldest->second.creationTime) {
                        oldest = it;
                    }
                }
                if (oldest != m_impl->m_dnsCache.end()) {
                    m_impl->m_dnsCache.erase(oldest);
                }
            }

            DNSCacheEntry entry;
            entry.domain = normalized;
            entry.recordType = recordType;
            entry.addresses = response.addresses;
            entry.originalTtl = response.ttl;
            entry.ttlRemaining = response.ttl;
            entry.creationTime = std::chrono::system_clock::now();
            entry.expirationTime = entry.creationTime + std::chrono::seconds(response.ttl);
            entry.source = response.server;

            m_impl->m_dnsCache[normalized] = std::move(entry);
        }

        // Invoke response callback safely under lock
        {
            std::shared_lock lock(m_impl->m_mutex);
            if (m_impl->m_responseCallback) {
                try {
                    m_impl->m_responseCallback(response);
                } catch (const std::exception& e) {
                    Utils::Logger::Error("Response callback exception: {}", e.what());
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("ResolveDomain failed for '{}': {}", domain, e.what());
        response.status = DNSResponseStatus::NetworkError;
    }

    return response;
}

[[nodiscard]] std::optional<DNSCacheEntry> DNSLeakProtection::GetCachedEntry(
    const std::string& domain)
{
    std::shared_lock lock(m_impl->m_mutex);

    auto it = m_impl->m_dnsCache.find(domain);
    if (it != m_impl->m_dnsCache.end() && !it->second.IsExpired()) {
        return it->second;
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<DNSCacheEntry> DNSLeakProtection::GetCacheEntries() {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<DNSCacheEntry> entries;
    entries.reserve(m_impl->m_dnsCache.size());

    for (const auto& [domain, entry] : m_impl->m_dnsCache) {
        if (!entry.IsExpired()) {
            entries.push_back(entry);
        }
    }

    return entries;
}

// ============================================================================
// FILTERING
// ============================================================================

[[nodiscard]] bool DNSLeakProtection::BlockDomain(const std::string& domain) {
    try {
        if (!IsValidDomainName(domain)) {
            Utils::Logger::Warn("BlockDomain: Invalid domain name '{}'", domain);
            return false;
        }

        std::string normalized = NormalizeDomain(domain);
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_blockedDomains.insert(std::move(normalized));

        Utils::Logger::Info("Domain blocked: {}", domain);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("BlockDomain failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool DNSLeakProtection::UnblockDomain(const std::string& domain) {
    try {
        std::string normalized = NormalizeDomain(domain);
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_blockedDomains.erase(normalized);

        Utils::Logger::Info("Domain unblocked: {}", domain);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UnblockDomain failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool DNSLeakProtection::IsDomainBlocked(const std::string& domain) {
    std::string normalized = NormalizeDomain(domain);
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_blockedDomains.count(normalized) > 0;
}

[[nodiscard]] bool DNSLeakProtection::WhitelistDomain(const std::string& domain) {
    try {
        if (!IsValidDomainName(domain)) {
            Utils::Logger::Warn("WhitelistDomain: Invalid domain name '{}'", domain);
            return false;
        }

        std::string normalized = NormalizeDomain(domain);
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_whitelistedDomains.insert(std::move(normalized));

        Utils::Logger::Info("Domain whitelisted: {}", domain);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("WhitelistDomain failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool DNSLeakProtection::ImportBlocklist(const fs::path& listPath) {
    try {
        std::error_code ec;
        if (!fs::exists(listPath, ec) || ec) {
            Utils::Logger::Error("Blocklist file not found: {}", listPath.string());
            return false;
        }

        // Cap file size to prevent memory exhaustion from adversarial input
        auto fileSize = fs::file_size(listPath, ec);
        if (ec || fileSize > MAX_BLOCKLIST_FILE_BYTES) {
            Utils::Logger::Error("Blocklist file too large or unreadable: {} bytes", fileSize);
            return false;
        }

        std::ifstream file(listPath);
        if (!file.is_open()) {
            Utils::Logger::Error("Failed to open blocklist file: {}", listPath.string());
            return false;
        }

        std::vector<std::string> validDomains;
        validDomains.reserve(
            std::min<size_t>(static_cast<size_t>(fileSize / 10), MAX_BLOCKLIST_DOMAINS));

        std::string line;
        size_t lineNum = 0;

        while (std::getline(file, line)) {
            ++lineNum;

            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;

            // Trim whitespace
            size_t start = line.find_first_not_of(" \t\r\n");
            size_t end = line.find_last_not_of(" \t\r\n");
            if (start == std::string::npos) continue;

            line = line.substr(start, end - start + 1);
            if (line.empty()) continue;

            // Handle hosts-file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
            if (line[0] >= '0' && line[0] <= '9') {
                size_t spacePos = line.find_first_of(" \t");
                if (spacePos != std::string::npos) {
                    size_t domStart = line.find_first_not_of(" \t", spacePos);
                    if (domStart != std::string::npos) {
                        line = line.substr(domStart);
                        // Strip trailing inline comments
                        size_t commentPos = line.find('#');
                        if (commentPos != std::string::npos) {
                            line = line.substr(0, commentPos);
                            size_t trimEnd = line.find_last_not_of(" \t\r\n");
                            if (trimEnd != std::string::npos) {
                                line = line.substr(0, trimEnd + 1);
                            } else {
                                continue;
                            }
                        }
                    }
                }
            }

            std::string normalized = NormalizeDomain(line);

            if (!normalized.empty() && IsValidDomainName(normalized)) {
                validDomains.push_back(std::move(normalized));
            }

            if (validDomains.size() >= MAX_BLOCKLIST_DOMAINS) {
                Utils::Logger::Warn("Blocklist domain limit reached ({}) at line {}",
                    MAX_BLOCKLIST_DOMAINS, lineNum);
                break;
            }
        }

        // Bulk insert under single lock
        {
            std::unique_lock lock(m_impl->m_mutex);
            for (auto& d : validDomains) {
                m_impl->m_blockedDomains.insert(std::move(d));
            }
        }

        Utils::Logger::Info("Imported {} domains from blocklist '{}'",
            validDomains.size(), listPath.filename().string());
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ImportBlocklist failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void DNSLeakProtection::RegisterQueryCallback(QueryCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_queryCallback = std::move(callback);
}

void DNSLeakProtection::RegisterResponseCallback(ResponseCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_responseCallback = std::move(callback);
}

void DNSLeakProtection::RegisterLeakCallback(LeakCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_leakCallback = std::move(callback);
}

void DNSLeakProtection::RegisterHijackCallback(HijackCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_hijackCallback = std::move(callback);
}

void DNSLeakProtection::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallback = std::move(callback);
}

void DNSLeakProtection::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_mutex);

    m_impl->m_queryCallback = nullptr;
    m_impl->m_responseCallback = nullptr;
    m_impl->m_leakCallback = nullptr;
    m_impl->m_hijackCallback = nullptr;
    m_impl->m_errorCallback = nullptr;

    Utils::Logger::Info("All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] DNSStatistics DNSLeakProtection::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void DNSLeakProtection::ResetStatistics() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    m_impl->m_stats.startTime = Clock::now();

    Utils::Logger::Info("Statistics reset");
}

[[nodiscard]] bool DNSLeakProtection::SelfTest() {
    try {
        Utils::Logger::Info("Running DNSLeakProtection self-test...");

        bool allPassed = true;

        // Test 1: Configuration validation
        DNSConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("Self-test failed: Invalid default configuration");
            allPassed = false;
        }

        // Test 2: Domain validation
        if (!IsValidDomainName("google.com")) {
            Utils::Logger::Error("Self-test failed: Domain validation");
            allPassed = false;
        }

        if (IsValidDomainName("invalid domain with spaces")) {
            Utils::Logger::Error("Self-test failed: Invalid domain accepted");
            allPassed = false;
        }

        // Test 3: Provider list
        auto providers = GetAvailableProviders();
        if (providers.empty()) {
            Utils::Logger::Error("Self-test failed: No providers available");
            allPassed = false;
        }

        // Test 4: DNS resolution (if initialized)
        if (IsInitialized()) {
            auto response = ResolveDomain("cloudflare.com", DNSRecordType::A);
            if (response.status != DNSResponseStatus::Success) {
                Utils::Logger::Warn("Self-test: DNS resolution failed (expected in offline mode)");
            }
        }

        if (allPassed) {
            Utils::Logger::Info("Self-test PASSED - All tests successful");
        } else {
            Utils::Logger::Error("Self-test FAILED - See errors above");
        }

        return allPassed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string DNSLeakProtection::GetVersionString() noexcept {
    return std::to_string(DNSConstants::VERSION_MAJOR) + "." +
           std::to_string(DNSConstants::VERSION_MINOR) + "." +
           std::to_string(DNSConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string DNSQuery::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["queryId"] = queryId;
    j["domain"] = domain;
    j["recordType"] = static_cast<int>(recordType);
    j["processId"] = processId;
    j["processName"] = processName;
    j["dnsServer"] = dnsServer;
    j["port"] = port;
    j["protocol"] = static_cast<int>(protocol);
    j["isEncrypted"] = isEncrypted;
    j["timestamp"] = timestamp.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string DNSResponse::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["queryId"] = queryId;
    j["domain"] = domain;
    j["status"] = static_cast<int>(status);
    j["addresses"] = addresses;
    j["cnameChain"] = cnameChain;
    j["ttl"] = ttl;
    j["responseTimeMs"] = responseTimeMs;
    j["server"] = server;
    j["dnssecValidated"] = dnssecValidated;
    j["poisoningStatus"] = static_cast<int>(poisoningStatus);

    return j.dump(2);
}

[[nodiscard]] std::string DNSLeakEvent::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["eventId"] = eventId;
    j["leakType"] = static_cast<int>(leakType);
    j["query"] = Json::parse(query.ToJson());
    j["expectedServer"] = expectedServer;
    j["actualServer"] = actualServer;
    j["vpnActive"] = vpnActive;
    j["description"] = description;
    j["severity"] = severity;
    j["timestamp"] = timestamp.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string DNSHijackAlert::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["alertId"] = alertId;
    j["alertType"] = alertType;
    j["previousServers"] = previousServers;
    j["newServers"] = newServers;
    j["changeSource"] = changeSource;
    j["suspectPid"] = suspectPid;
    j["suspectProcess"] = suspectProcess;
    j["severity"] = severity;
    j["remediated"] = remediated;
    j["timestamp"] = timestamp.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string DNSProvider::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["providerId"] = providerId;
    j["name"] = name;
    j["primaryUrl"] = primaryUrl;
    j["backupUrl"] = backupUrl;
    j["primaryIp"] = primaryIp;
    j["backupIp"] = backupIp;
    j["protocol"] = static_cast<int>(protocol);
    j["port"] = port;
    j["supportsDNSSEC"] = supportsDNSSEC;
    j["malwareFiltering"] = malwareFiltering;
    j["adultFiltering"] = adultFiltering;

    return j.dump(2);
}

[[nodiscard]] bool DNSCacheEntry::IsExpired() const noexcept {
    return std::chrono::system_clock::now() >= expirationTime;
}

[[nodiscard]] std::string DNSCacheEntry::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["domain"] = domain;
    j["recordType"] = static_cast<int>(recordType);
    j["addresses"] = addresses;
    j["ttlRemaining"] = ttlRemaining;
    j["originalTtl"] = originalTtl;
    j["creationTime"] = creationTime.time_since_epoch().count();
    j["expirationTime"] = expirationTime.time_since_epoch().count();
    j["source"] = source;
    j["hitCount"] = hitCount;

    return j.dump(2);
}

void DNSStatistics::Reset() noexcept {
    totalQueries.store(0, std::memory_order_relaxed);
    encryptedQueries.store(0, std::memory_order_relaxed);
    leaksDetected.store(0, std::memory_order_relaxed);
    leaksBlocked.store(0, std::memory_order_relaxed);
    hijackAttemptsDetected.store(0, std::memory_order_relaxed);
    poisoningAttemptsDetected.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    blockedDomains.store(0, std::memory_order_relaxed);
    dnssecValidations.store(0, std::memory_order_relaxed);
    dnssecFailures.store(0, std::memory_order_relaxed);
    averageResponseTimeMs.store(0, std::memory_order_relaxed);

    for (auto& proto : byProtocol) {
        proto.store(0, std::memory_order_relaxed);
    }
}

[[nodiscard]] std::string DNSStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["totalQueries"] = totalQueries.load(std::memory_order_relaxed);
    j["encryptedQueries"] = encryptedQueries.load(std::memory_order_relaxed);
    j["leaksDetected"] = leaksDetected.load(std::memory_order_relaxed);
    j["leaksBlocked"] = leaksBlocked.load(std::memory_order_relaxed);
    j["hijackAttemptsDetected"] = hijackAttemptsDetected.load(std::memory_order_relaxed);
    j["poisoningAttemptsDetected"] = poisoningAttemptsDetected.load(std::memory_order_relaxed);
    j["cacheHits"] = cacheHits.load(std::memory_order_relaxed);
    j["cacheMisses"] = cacheMisses.load(std::memory_order_relaxed);
    j["blockedDomains"] = blockedDomains.load(std::memory_order_relaxed);
    j["dnssecValidations"] = dnssecValidations.load(std::memory_order_relaxed);
    j["dnssecFailures"] = dnssecFailures.load(std::memory_order_relaxed);
    j["averageResponseTimeMs"] = averageResponseTimeMs.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] bool DNSConfiguration::IsValid() const noexcept {
    if (queryTimeoutMs == 0 || queryTimeoutMs > 60000) return false;
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDNSProtocolName(DNSProtocol protocol) noexcept {
    switch (protocol) {
        case DNSProtocol::Standard: return "Standard";
        case DNSProtocol::DoH: return "DoH";
        case DNSProtocol::DoT: return "DoT";
        case DNSProtocol::DoQ: return "DoQ";
        case DNSProtocol::DNSSEC: return "DNSSEC";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetLeakTypeName(DNSLeakType type) noexcept {
    switch (type) {
        case DNSLeakType::None: return "None";
        case DNSLeakType::VPNBypass: return "VPNBypass";
        case DNSLeakType::IPv6Leak: return "IPv6Leak";
        case DNSLeakType::WebRTCLeak: return "WebRTCLeak";
        case DNSLeakType::SplitTunnel: return "SplitTunnel";
        case DNSLeakType::FallbackLeak: return "FallbackLeak";
        case DNSLeakType::DHCPOverride: return "DHCPOverride";
        case DNSLeakType::MalwareRedirect: return "MalwareRedirect";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetRecordTypeName(DNSRecordType type) noexcept {
    switch (type) {
        case DNSRecordType::A: return "A";
        case DNSRecordType::AAAA: return "AAAA";
        case DNSRecordType::CNAME: return "CNAME";
        case DNSRecordType::MX: return "MX";
        case DNSRecordType::TXT: return "TXT";
        case DNSRecordType::NS: return "NS";
        case DNSRecordType::SOA: return "SOA";
        case DNSRecordType::PTR: return "PTR";
        case DNSRecordType::SRV: return "SRV";
        case DNSRecordType::CAA: return "CAA";
        case DNSRecordType::DNSKEY: return "DNSKEY";
        case DNSRecordType::DS: return "DS";
        case DNSRecordType::RRSIG: return "RRSIG";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetResponseStatusName(DNSResponseStatus status) noexcept {
    switch (status) {
        case DNSResponseStatus::Success: return "Success";
        case DNSResponseStatus::FormatError: return "FormatError";
        case DNSResponseStatus::ServerFailure: return "ServerFailure";
        case DNSResponseStatus::NonExistent: return "NonExistent";
        case DNSResponseStatus::NotImplemented: return "NotImplemented";
        case DNSResponseStatus::Refused: return "Refused";
        case DNSResponseStatus::Timeout: return "Timeout";
        case DNSResponseStatus::NetworkError: return "NetworkError";
        case DNSResponseStatus::Blocked: return "Blocked";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetPoisoningStatusName(PoisoningStatus status) noexcept {
    switch (status) {
        case PoisoningStatus::Clean: return "Clean";
        case PoisoningStatus::Suspicious: return "Suspicious";
        case PoisoningStatus::Poisoned: return "Poisoned";
        case PoisoningStatus::Verified: return "Verified";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsValidDomainName(const std::string& domain) {
    if (domain.empty() || domain.length() > MAX_DNS_NAME) {
        return false;
    }

    // Must contain at least one dot
    if (domain.find('.') == std::string::npos) {
        return false;
    }

    size_t labelStart = 0;
    size_t dotCount = 0;

    for (size_t i = 0; i <= domain.length(); ++i) {
        if (i == domain.length() || domain[i] == '.') {
            size_t labelLen = i - labelStart;

            // Each label must be 1-63 characters
            if (labelLen == 0 || labelLen > 63) {
                return false;
            }

            // Label must start and end with alphanumeric
            if (!std::isalnum(static_cast<unsigned char>(domain[labelStart]))) {
                return false;
            }
            if (!std::isalnum(static_cast<unsigned char>(domain[i - 1]))) {
                return false;
            }

            // Label can only contain alphanumeric and hyphens
            for (size_t j = labelStart; j < i; ++j) {
                char c = domain[j];
                if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-') {
                    return false;
                }
            }

            if (i < domain.length()) {
                ++dotCount;
            }
            labelStart = i + 1;
        }
    }

    // TLD must be at least 2 characters and all alphabetic
    size_t lastDot = domain.rfind('.');
    if (lastDot == std::string::npos) return false;

    std::string_view tld(domain.data() + lastDot + 1, domain.length() - lastDot - 1);
    if (tld.length() < 2) return false;

    for (char c : tld) {
        if (!std::isalpha(static_cast<unsigned char>(c))) {
            return false;
        }
    }

    return dotCount >= 1;
}

[[nodiscard]] std::vector<std::string> ParseDNSResponse(
    const std::vector<uint8_t>& response)
{
    std::vector<std::string> addresses;

    // DNS wire format requires minimum 12-byte header
    if (response.size() < DNS_HEADER_SIZE) {
        return addresses;
    }

    // Parse header flags
    uint16_t flags = (static_cast<uint16_t>(response[2]) << 8) | response[3];
    bool isResponse = (flags & 0x8000) != 0;
    uint8_t rcode = static_cast<uint8_t>(flags & 0x000F);

    if (!isResponse || rcode != 0) {
        return addresses;
    }

    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | response[5];
    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | response[7];

    // Cap counts to prevent malicious packets from causing excessive processing
    if (qdcount > 100 || ancount > 500) {
        return addresses;
    }

    size_t offset = DNS_HEADER_SIZE;

    // Skip question section
    for (uint16_t i = 0; i < qdcount && offset < response.size(); ++i) {
        // Skip QNAME: sequence of length-prefixed labels
        while (offset < response.size()) {
            uint8_t labelLen = response[offset];
            if (labelLen == 0) {
                ++offset;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                offset += 2;  // compression pointer (2 bytes)
                break;
            }
            if (labelLen > response.size() || offset > response.size() - 1 - labelLen) return addresses;
            offset += 1 + labelLen;
        }
        // QTYPE (2 bytes) + QCLASS (2 bytes)
        if (offset + 4 > response.size()) return addresses;
        offset += 4;
    }

    // Parse answer section
    for (uint16_t i = 0; i < ancount && offset < response.size(); ++i) {
        // Skip NAME (may be compressed)
        while (offset < response.size()) {
            uint8_t labelLen = response[offset];
            if (labelLen == 0) {
                ++offset;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            if (labelLen > response.size() || offset > response.size() - 1 - labelLen) return addresses;
            offset += 1 + labelLen;
        }

        // Need TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes minimum
        if (offset + 10 > response.size()) break;

        uint16_t rtype = (static_cast<uint16_t>(response[offset]) << 8) | response[offset + 1];
        offset += 2;  // TYPE
        offset += 2;  // CLASS
        offset += 4;  // TTL
        uint16_t rdlength = (static_cast<uint16_t>(response[offset]) << 8) | response[offset + 1];
        offset += 2;  // RDLENGTH

        if (offset + rdlength > response.size()) break;

        if (rtype == 1 && rdlength == 4) {
            // A record: 4-byte IPv4 address
            char ipStr[INET_ADDRSTRLEN];
            IN_ADDR addr;
            std::memcpy(&addr, &response[offset], 4);
            if (::inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr))) {
                addresses.emplace_back(ipStr);
            }
        } else if (rtype == 28 && rdlength == 16) {
            // AAAA record: 16-byte IPv6 address
            char ipStr[INET6_ADDRSTRLEN];
            IN6_ADDR addr;
            std::memcpy(&addr, &response[offset], 16);
            if (::inet_ntop(AF_INET6, &addr, ipStr, sizeof(ipStr))) {
                addresses.emplace_back(ipStr);
            }
        }

        offset += rdlength;
    }

    return addresses;
}

[[nodiscard]] DNSRecordType GetRecordTypeFromId(uint16_t typeId) {
    switch (typeId) {
        case 1: return DNSRecordType::A;
        case 28: return DNSRecordType::AAAA;
        case 5: return DNSRecordType::CNAME;
        case 15: return DNSRecordType::MX;
        case 16: return DNSRecordType::TXT;
        case 2: return DNSRecordType::NS;
        case 6: return DNSRecordType::SOA;
        case 12: return DNSRecordType::PTR;
        case 33: return DNSRecordType::SRV;
        case 257: return DNSRecordType::CAA;
        case 48: return DNSRecordType::DNSKEY;
        case 43: return DNSRecordType::DS;
        case 46: return DNSRecordType::RRSIG;
        default: return DNSRecordType::A;
    }
}

}  // namespace ShadowStrike::Privacy
