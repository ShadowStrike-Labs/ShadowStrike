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
 * ShadowStrike NGAV - IP LEAK PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file IPLeakProtection.cpp
 * @brief Enterprise-grade IP leak protection with kill switch and WebRTC blocking
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - Integration with Windows Filtering Platform (WFP)
 *
 * PROTECTION LAYERS:
 * 1. Kill switch (block all non-VPN traffic)
 * 2. WebRTC leak prevention (STUN/TURN blocking)
 * 3. IPv6 leak protection (tunnel blocking, dual-stack)
 * 4. VPN monitoring (adapter detection, status tracking)
 * 5. IP leak detection (public IP checks, comparison)
 *
 * PERFORMANCE TARGETS:
 * - Kill switch activation: <100ms
 * - Leak detection: <500ms per check
 * - VPN status check: <50ms
 * - Public IP lookup: <2s (network dependent)
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
#include "IPLeakProtection.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/Timer.hpp"
#include "../Utils/HashUtils.hpp"
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <fwpmu.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <regex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "fwpuclnt.lib")

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {
    using namespace ShadowStrike::Privacy;

    /// @brief Monitoring interval (ms)
    constexpr uint32_t MONITORING_INTERVAL_MS = 1000;

    /// @brief Public IP check timeout (ms)
    constexpr uint32_t PUBLIC_IP_TIMEOUT_MS = 5000;

    // {A7B3F1E2-9C4D-4A8B-B6E5-2D1F0C3E5A7B} - ShadowStrike registered WFP sublayer
    const GUID SHADOWSTRIKE_SUBLAYER_GUID = {
        0xA7B3F1E2, 0x9C4D, 0x4A8B,
        {0xB6, 0xE5, 0x2D, 0x1F, 0x0C, 0x3E, 0x5A, 0x7B}
    };

    // {C8D4E2F6-1A3B-5C7D-9E0F-4B6A8D2C1E3F} - WebRTC blocking sublayer
    const GUID SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID = {
        0xC8D4E2F6, 0x1A3B, 0x5C7D,
        {0x9E, 0x0F, 0x4B, 0x6A, 0x8D, 0x2C, 0x1E, 0x3F}
    };

    /**
     * @brief Known VPN adapter patterns
     */
    constexpr const char* VPN_ADAPTER_PATTERNS[] = {
        "TAP-Windows",
        "WireGuard",
        "OpenVPN",
        "NordVPN",
        "ExpressVPN",
        "ProtonVPN",
        "Surfshark",
        "CyberGhost",
        "IPVanish",
        "Mullvad",
        "Private Internet Access",
        "TunnelBear",
        "Hotspot Shield",
        "VyprVPN",
        "IPSec",
        "L2TP",
        "PPTP"
    };

    /**
     * @brief Public IP check services
     */
    struct IPCheckService {
        const wchar_t* host;
        const wchar_t* path;
        bool isJSON;
    };

    constexpr IPCheckService IP_CHECK_SERVICES[] = {
        {L"api.ipify.org", L"/", false},
        {L"icanhazip.com", L"/", false},
        {L"ipinfo.io", L"/ip", false},
        {L"ifconfig.me", L"/ip", false}
    };

    /**
     * @brief Generate event ID
     */
    [[nodiscard]] uint64_t GenerateEventId() {
        static std::atomic<uint64_t> s_counter{
            static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFFFFFF) << 32
        };
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    /// @brief Maximum response size for public IP queries (defense against DoS)
    constexpr size_t MAX_PUBLIC_IP_RESPONSE_BYTES = 4096;

    /// @brief Maximum history entries for leak/kill switch events
    constexpr size_t MAX_HISTORY_ENTRIES = 500;

    /**
     * @brief RAII wrapper for WinHTTP handles
     */
    class WinHttpHandle final {
    public:
        WinHttpHandle() noexcept = default;
        explicit WinHttpHandle(HINTERNET h) noexcept : m_handle(h) {}
        ~WinHttpHandle() { Close(); }

        WinHttpHandle(const WinHttpHandle&) = delete;
        WinHttpHandle& operator=(const WinHttpHandle&) = delete;

        WinHttpHandle(WinHttpHandle&& other) noexcept : m_handle(other.m_handle) {
            other.m_handle = nullptr;
        }
        WinHttpHandle& operator=(WinHttpHandle&& other) noexcept {
            if (this != &other) {
                Close();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        void Close() noexcept {
            if (m_handle) {
                ::WinHttpCloseHandle(m_handle);
                m_handle = nullptr;
            }
        }

        [[nodiscard]] explicit operator bool() const noexcept { return m_handle != nullptr; }
        [[nodiscard]] HINTERNET Get() const noexcept { return m_handle; }
        HINTERNET* Put() noexcept { Close(); return &m_handle; }

    private:
        HINTERNET m_handle = nullptr;
    };

    /**
     * @brief Execute a netsh command safely via CreateProcessW (no shell injection)
     * @param args Full command line arguments for netsh (e.g., L"interface teredo set state disabled")
     * @return true if command executed successfully
     */
    [[nodiscard]] bool RunNetshCommand(const wchar_t* args) {
        if (!args || !args[0]) {
            return false;
        }

        // Build full command: "netsh <args>"
        std::wstring cmdLine = L"netsh ";
        cmdLine += args;

        // Cap command line length
        if (cmdLine.size() > 1024) {
            Utils::Logger::Error("RunNetshCommand: command line too long");
            return false;
        }

        STARTUPINFOW si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};

        // CreateProcessW needs a mutable command line buffer
        std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
        cmdBuf.push_back(L'\0');

        BOOL created = ::CreateProcessW(
            nullptr,
            cmdBuf.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &si,
            &pi);

        if (!created) {
            Utils::Logger::Error("RunNetshCommand: CreateProcessW failed, error={}",
                ::GetLastError());
            return false;
        }

        // Wait up to 10 seconds for completion
        DWORD waitResult = ::WaitForSingleObject(pi.hProcess, 10000);
        DWORD exitCode = 1;

        if (waitResult == WAIT_OBJECT_0) {
            ::GetExitCodeProcess(pi.hProcess, &exitCode);
        } else {
            Utils::Logger::Warn("RunNetshCommand: timed out, terminating child");
            ::TerminateProcess(pi.hProcess, 1);
        }

        ::CloseHandle(pi.hProcess);
        ::CloseHandle(pi.hThread);

        return (exitCode == 0);
    }

    /**
     * @brief RAII wrapper for WFP engine handle
     */
    class WfpEngineHandle final {
    public:
        WfpEngineHandle() noexcept = default;
        ~WfpEngineHandle() { Close(); }

        WfpEngineHandle(const WfpEngineHandle&) = delete;
        WfpEngineHandle& operator=(const WfpEngineHandle&) = delete;

        [[nodiscard]] bool Open() {
            if (m_handle) return true;
            DWORD result = ::FwpmEngineOpen0(
                nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &m_handle);
            return (result == ERROR_SUCCESS);
        }

        void Close() noexcept {
            if (m_handle) {
                ::FwpmEngineClose0(m_handle);
                m_handle = nullptr;
            }
        }

        [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] explicit operator bool() const noexcept { return m_handle != nullptr; }

    private:
        HANDLE m_handle = nullptr;
    };

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::Privacy {

class IPLeakProtectionImpl final {
public:
    IPLeakProtectionImpl() = default;
    ~IPLeakProtectionImpl() {
        StopMonitoring();
        DeactivateKillSwitch();
        // Clean up WebRTC WFP engine if still open
        if (m_webRtcWfpEngine) {
            ::FwpmSubLayerDeleteByKey0(m_webRtcWfpEngine, &SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID);
            ::FwpmEngineClose0(m_webRtcWfpEngine);
            m_webRtcWfpEngine = nullptr;
        }
    }

    // Delete copy/move
    IPLeakProtectionImpl(const IPLeakProtectionImpl&) = delete;
    IPLeakProtectionImpl& operator=(const IPLeakProtectionImpl&) = delete;
    IPLeakProtectionImpl(IPLeakProtectionImpl&&) = delete;
    IPLeakProtectionImpl& operator=(IPLeakProtectionImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    IPLeakConfiguration m_config;
    IPLeakStatistics m_stats;

    // Current state
    std::atomic<bool> m_killSwitchActive{false};
    std::atomic<bool> m_webRTCBlocked{false};
    std::atomic<bool> m_ipv6Disabled{false};
    std::atomic<VPNStatus> m_vpnStatus{VPNStatus::Unknown};
    std::atomic<bool> m_monitoringActive{false};

    // WFP handles
    HANDLE m_wfpEngine = nullptr;
    HANDLE m_webRtcWfpEngine = nullptr;

    // Current VPN connection
    std::optional<VPNConnectionInfo> m_vpnConnection;
    std::string m_currentPublicIP;

    // Event history
    std::vector<IPLeakEvent> m_recentLeaks;
    std::vector<KillSwitchEvent> m_killSwitchEvents;

    // Callbacks
    std::vector<LeakDetectedCallback> m_leakCallbacks;
    std::vector<KillSwitchCallback> m_killSwitchCallbacks;
    std::vector<VPNStatusCallback> m_vpnStatusCallbacks;
    std::vector<AdapterCallback> m_adapterCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Monitoring thread
    std::thread m_monitoringThread;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Invoke error callbacks
     */
    void NotifyError(const std::string& message, int code = 0) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Error callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown error callback exception");
            }
        }
    }

    /**
     * @brief Invoke leak callbacks
     */
    void NotifyLeak(const IPLeakEvent& leak) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_leakCallbacks) {
            try {
                callback(leak);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Leak callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown leak callback exception");
            }
        }
    }

    /**
     * @brief Invoke kill switch callbacks
     */
    void NotifyKillSwitch(const KillSwitchEvent& event) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_killSwitchCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Kill switch callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown kill switch callback exception");
            }
        }
    }

    /**
     * @brief Invoke VPN status callbacks
     */
    void NotifyVPNStatus(VPNStatus status) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_vpnStatusCallbacks) {
            try {
                callback(status);
            } catch (const std::exception& e) {
                Utils::Logger::Error("VPN status callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown VPN status callback exception");
            }
        }
    }

    /**
     * @brief Invoke adapter callbacks
     */
    void NotifyAdapter(const NetworkAdapterInfo& adapter, bool added) {
        std::shared_lock lock(m_mutex);
        for (const auto& callback : m_adapterCallbacks) {
            try {
                callback(adapter, added);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Adapter callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown adapter callback exception");
            }
        }
    }

    /**
     * @brief Get network adapters
     */
    [[nodiscard]] std::vector<NetworkAdapterInfo> GetNetworkAdaptersInternal() {
        std::vector<NetworkAdapterInfo> adapters;

        try {
            ULONG bufferSize = 15000;
            std::vector<uint8_t> buffer(bufferSize);

            ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
            ULONG result = ::GetAdaptersAddresses(AF_UNSPEC,
                flags,
                nullptr,
                reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                &bufferSize);

            if (result == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                result = ::GetAdaptersAddresses(AF_UNSPEC,
                    flags,
                    nullptr,
                    reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
                    &bufferSize);
            }

            if (result == ERROR_SUCCESS) {
                PIP_ADAPTER_ADDRESSES adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

                while (adapter) {
                    NetworkAdapterInfo info;

                    // AdapterName is already a narrow GUID string (e.g., "{GUID}")
                    if (adapter->AdapterName) {
                        info.guid = adapter->AdapterName;
                    }

                    info.name = Utils::StringUtils::WideToUtf8(adapter->FriendlyName);
                    info.description = Utils::StringUtils::WideToUtf8(adapter->Description);

                    // Detect type
                    info.type = DetectAdapterTypeInternal(info.description);
                    info.isVPN = IsVPNAdapterInternal(info.name, info.description);

                    // MAC address
                    if (adapter->PhysicalAddressLength > 0) {
                        std::ostringstream mac;
                        for (UINT i = 0; i < adapter->PhysicalAddressLength; ++i) {
                            if (i > 0) mac << ":";
                            mac << std::hex << std::setw(2) << std::setfill('0')
                                << static_cast<int>(adapter->PhysicalAddress[i]);
                        }
                        info.macAddress = mac.str();
                    }

                    // IP addresses
                    PIP_ADAPTER_UNICAST_ADDRESS unicast = adapter->FirstUnicastAddress;
                    while (unicast) {
                        char ipStr[INET6_ADDRSTRLEN] = {};
                        DWORD ipStrLen = INET6_ADDRSTRLEN;

                        if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                            sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                            ::inet_ntop(AF_INET, &sa->sin_addr, ipStr, ipStrLen);
                            info.ipv4Addresses.push_back(ipStr);
                        }
                        else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                            sockaddr_in6* sa = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                            ::inet_ntop(AF_INET6, &sa->sin6_addr, ipStr, ipStrLen);
                            info.ipv6Addresses.push_back(ipStr);
                        }

                        unicast = unicast->Next;
                    }

                    // Gateway
                    PIP_ADAPTER_GATEWAY_ADDRESS gateway = adapter->FirstGatewayAddress;
                    if (gateway) {
                        char ipStr[INET6_ADDRSTRLEN] = {};
                        DWORD ipStrLen = INET6_ADDRSTRLEN;

                        if (gateway->Address.lpSockaddr->sa_family == AF_INET) {
                            sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(gateway->Address.lpSockaddr);
                            ::inet_ntop(AF_INET, &sa->sin_addr, ipStr, ipStrLen);
                            info.gateway = ipStr;
                        }
                    }

                    info.isConnected = (adapter->OperStatus == IfOperStatusUp);
                    info.isEnabled = (adapter->OperStatus != IfOperStatusDown);

                    adapters.push_back(info);

                    adapter = adapter->Next;
                }
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("GetNetworkAdapters failed: {}", e.what());
        }

        return adapters;
    }

    /**
     * @brief Detect adapter type
     */
    [[nodiscard]] AdapterType DetectAdapterTypeInternal(const std::string& description) const {
        if (description.find("VPN") != std::string::npos ||
            description.find("TAP") != std::string::npos ||
            description.find("TUN") != std::string::npos) {
            return AdapterType::VPN;
        }

        if (description.find("Wireless") != std::string::npos ||
            description.find("WiFi") != std::string::npos ||
            description.find("802.11") != std::string::npos) {
            return AdapterType::WiFi;
        }

        if (description.find("Ethernet") != std::string::npos ||
            description.find("Gigabit") != std::string::npos) {
            return AdapterType::Ethernet;
        }

        if (description.find("Loopback") != std::string::npos) {
            return AdapterType::Loopback;
        }

        if (description.find("Virtual") != std::string::npos) {
            return AdapterType::Virtual;
        }

        return AdapterType::Unknown;
    }

    /**
     * @brief Check if adapter is VPN
     */
    [[nodiscard]] bool IsVPNAdapterInternal(const std::string& name, const std::string& description) const {
        for (const auto* pattern : VPN_ADAPTER_PATTERNS) {
            if (name.find(pattern) != std::string::npos ||
                description.find(pattern) != std::string::npos) {
                return true;
            }
        }

        // Check configured patterns
        std::shared_lock lock(m_mutex);
        for (const auto& pattern : m_config.vpnAdapterPatterns) {
            if (name.find(pattern) != std::string::npos ||
                description.find(pattern) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Get public IP address
     */
    [[nodiscard]] std::optional<std::string> GetPublicIPInternal() {
        try {
            for (const auto& service : IP_CHECK_SERVICES) {
                WinHttpHandle hSession(::WinHttpOpen(
                    L"ShadowStrike IP/3.0",
                    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                    WINHTTP_NO_PROXY_NAME,
                    WINHTTP_NO_PROXY_BYPASS,
                    0));

                if (!hSession) continue;

                WinHttpHandle hConnect(::WinHttpConnect(
                    hSession.Get(),
                    service.host,
                    INTERNET_DEFAULT_HTTPS_PORT,
                    0));

                if (!hConnect) continue;

                WinHttpHandle hRequest(::WinHttpOpenRequest(
                    hConnect.Get(),
                    L"GET",
                    service.path,
                    nullptr,
                    WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES,
                    WINHTTP_FLAG_SECURE));

                if (!hRequest) continue;

                // Set all timeouts: resolve, connect, send, receive
                DWORD timeout = PUBLIC_IP_TIMEOUT_MS;
                ::WinHttpSetOption(hRequest.Get(), WINHTTP_OPTION_RESOLVE_TIMEOUT, &timeout, sizeof(timeout));
                ::WinHttpSetOption(hRequest.Get(), WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
                ::WinHttpSetOption(hRequest.Get(), WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
                ::WinHttpSetOption(hRequest.Get(), WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

                if (!::WinHttpSendRequest(hRequest.Get(),
                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                    continue;
                }

                if (!::WinHttpReceiveResponse(hRequest.Get(), nullptr)) {
                    continue;
                }

                // Verify HTTP 200
                DWORD statusCode = 0;
                DWORD statusSize = sizeof(statusCode);
                if (!::WinHttpQueryHeaders(hRequest.Get(),
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX,
                        &statusCode, &statusSize,
                        WINHTTP_NO_HEADER_INDEX) || statusCode != 200) {
                    continue;
                }

                DWORD bytesAvailable = 0;
                std::string responseData;
                responseData.reserve(64);

                while (::WinHttpQueryDataAvailable(hRequest.Get(), &bytesAvailable) && bytesAvailable > 0) {
                    // Cap total response size to prevent DoS
                    if (responseData.size() + bytesAvailable > MAX_PUBLIC_IP_RESPONSE_BYTES) {
                        Utils::Logger::Warn("GetPublicIP: response exceeded size limit from {}",
                            Utils::StringUtils::WideToUtf8(service.host));
                        responseData.clear();
                        break;
                    }

                    std::vector<char> buffer(bytesAvailable + 1);
                    DWORD bytesRead = 0;

                    if (::WinHttpReadData(hRequest.Get(), buffer.data(), bytesAvailable, &bytesRead)) {
                        responseData.append(buffer.data(), bytesRead);
                    }
                }

                if (!responseData.empty()) {
                    // Trim whitespace and newlines
                    auto start = responseData.find_first_not_of(" \t\r\n");
                    auto end = responseData.find_last_not_of(" \t\r\n");
                    if (start == std::string::npos) continue;
                    responseData = responseData.substr(start, end - start + 1);

                    // Validate: must look like an IP address (digits, dots, colons, hex)
                    if (responseData.length() >= 7 && responseData.length() <= 45) {
                        bool validChars = std::all_of(responseData.begin(), responseData.end(),
                            [](char c) {
                                return std::isxdigit(static_cast<unsigned char>(c)) ||
                                       c == '.' || c == ':';
                            });
                        if (validChars) {
                            return responseData;
                        }
                    }
                }
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("GetPublicIP failed: {}", e.what());
        }

        return std::nullopt;
    }

    /**
     * @brief Activate kill switch via WFP
     */
    [[nodiscard]] bool ActivateKillSwitch() {
        try {
            Utils::Logger::Info("Activating kill switch");

            // Open WFP engine
            DWORD result = ::FwpmEngineOpen0(
                nullptr,
                RPC_C_AUTHN_WINNT,
                nullptr,
                nullptr,
                &m_wfpEngine);

            if (result != ERROR_SUCCESS) {
                Utils::Logger::Error("Failed to open WFP engine: error={}", result);
                return false;
            }

            // Begin transaction for atomic filter installation
            result = ::FwpmTransactionBegin0(m_wfpEngine, 0);
            if (result != ERROR_SUCCESS) {
                Utils::Logger::Error("Failed to begin WFP transaction: error={}", result);
                ::FwpmEngineClose0(m_wfpEngine);
                m_wfpEngine = nullptr;
                return false;
            }

            bool transactionActive = true;
            auto abortTransaction = [&]() {
                if (transactionActive) {
                    ::FwpmTransactionAbort0(m_wfpEngine);
                    transactionActive = false;
                }
                ::FwpmEngineClose0(m_wfpEngine);
                m_wfpEngine = nullptr;
            };

            // Add sublayer
            FWPM_SUBLAYER0 sublayer = {};
            sublayer.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
            sublayer.displayData.name = const_cast<wchar_t*>(L"ShadowStrike Kill Switch");
            sublayer.displayData.description = const_cast<wchar_t*>(L"Block non-VPN traffic");
            sublayer.weight = 0xFFFF;

            result = ::FwpmSubLayerAdd0(m_wfpEngine, &sublayer, nullptr);
            if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
                Utils::Logger::Error("Failed to add WFP sublayer: error={}", result);
                abortTransaction();
                return false;
            }

            UINT64 filterId = 0;

            // --- PERMIT FILTERS (higher weight = evaluated first) ---

            // Permit loopback IPv4 (127.0.0.0/8)
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Permit Loopback IPv4");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 14;
                filter.action.type = FWP_ACTION_PERMIT;

                FWP_V4_ADDR_AND_MASK loopback = {};
                loopback.addr = 0x7F000000;  // 127.0.0.0
                loopback.mask = 0xFF000000;  // /8

                FWPM_FILTER_CONDITION0 cond = {};
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_V4_ADDR_MASK;
                cond.conditionValue.v4AddrMask = &loopback;

                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                result = ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
                if (result != ERROR_SUCCESS) {
                    Utils::Logger::Error("Failed to add loopback permit filter: error={}", result);
                    abortTransaction();
                    return false;
                }
            }

            // Permit loopback IPv6 (::1)
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Permit Loopback IPv6");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 14;
                filter.action.type = FWP_ACTION_PERMIT;

                FWP_V6_ADDR_AND_MASK loopback6 = {};
                loopback6.addr[15] = 1;  // ::1
                loopback6.prefixLength = 128;

                FWPM_FILTER_CONDITION0 cond = {};
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_V6_ADDR_MASK;
                cond.conditionValue.v6AddrMask = &loopback6;

                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                result = ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
                if (result != ERROR_SUCCESS) {
                    Utils::Logger::Error("Failed to add IPv6 loopback permit filter: error={}", result);
                    abortTransaction();
                    return false;
                }
            }

            // Permit DHCP (UDP port 67/68) so network stays configured
            // Outbound: client sends to server port 67
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Permit DHCP Out");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 14;
                filter.action.type = FWP_ACTION_PERMIT;

                FWPM_FILTER_CONDITION0 cond = {};
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_UINT16;
                cond.conditionValue.uint16 = 67;

                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
            }
            // Inbound: server responds from port 67 to client port 68
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Permit DHCP In");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 14;
                filter.action.type = FWP_ACTION_PERMIT;

                FWPM_FILTER_CONDITION0 cond = {};
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_UINT16;
                cond.conditionValue.uint16 = 67;

                filter.filterCondition = &cond;
                filter.numFilterConditions = 1;

                ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
            }

            // Permit traffic on VPN adapters (by detecting connected VPN adapters)
            {
                auto vpnAdapters = DetectVPNAdaptersInternal();
                for (const auto& vpnAdapter : vpnAdapters) {
                    if (!vpnAdapter.isConnected || vpnAdapter.ipv4Addresses.empty()) continue;

                    // Permit traffic from VPN adapter's local IP
                    for (const auto& vpnIP : vpnAdapter.ipv4Addresses) {
                        FWPM_FILTER0 filter = {};
                        filter.displayData.name = const_cast<wchar_t*>(L"SS Permit VPN Adapter");
                        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                        filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                        filter.weight.type = FWP_UINT8;
                        filter.weight.uint8 = 13;
                        filter.action.type = FWP_ACTION_PERMIT;

                        // Parse VPN IP to build condition
                        IN_ADDR vpnAddr = {};
                        if (::inet_pton(AF_INET, vpnIP.c_str(), &vpnAddr) == 1) {
                            FWP_V4_ADDR_AND_MASK addrMask = {};
                            addrMask.addr = ntohl(vpnAddr.S_un.S_addr);
                            addrMask.mask = 0xFFFFFFFF;  // /32

                            FWPM_FILTER_CONDITION0 cond = {};
                            cond.fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
                            cond.matchType = FWP_MATCH_EQUAL;
                            cond.conditionValue.type = FWP_V4_ADDR_MASK;
                            cond.conditionValue.v4AddrMask = &addrMask;

                            filter.filterCondition = &cond;
                            filter.numFilterConditions = 1;

                            ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
                        }
                    }
                }
            }

            // --- BLOCK FILTERS (lower weight = fallback) ---

            // Block all IPv4 outbound (catch-all)
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Block All IPv4");
                filter.displayData.description = const_cast<wchar_t*>(L"Kill switch - block non-VPN IPv4");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 1;
                filter.action.type = FWP_ACTION_BLOCK;
                filter.numFilterConditions = 0;

                result = ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
                if (result != ERROR_SUCCESS) {
                    Utils::Logger::Error("Failed to add IPv4 block filter: error={}", result);
                    abortTransaction();
                    return false;
                }
            }

            // Block all IPv6 outbound (catch-all)
            {
                FWPM_FILTER0 filter = {};
                filter.displayData.name = const_cast<wchar_t*>(L"SS Block All IPv6");
                filter.displayData.description = const_cast<wchar_t*>(L"Kill switch - block non-VPN IPv6");
                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                filter.subLayerKey = SHADOWSTRIKE_SUBLAYER_GUID;
                filter.weight.type = FWP_UINT8;
                filter.weight.uint8 = 1;
                filter.action.type = FWP_ACTION_BLOCK;
                filter.numFilterConditions = 0;

                result = ::FwpmFilterAdd0(m_wfpEngine, &filter, nullptr, &filterId);
                if (result != ERROR_SUCCESS) {
                    Utils::Logger::Error("Failed to add IPv6 block filter: error={}", result);
                    abortTransaction();
                    return false;
                }
            }

            // Commit transaction atomically
            result = ::FwpmTransactionCommit0(m_wfpEngine);
            transactionActive = false;

            if (result != ERROR_SUCCESS) {
                Utils::Logger::Error("Failed to commit WFP transaction: error={}", result);
                ::FwpmEngineClose0(m_wfpEngine);
                m_wfpEngine = nullptr;
                return false;
            }

            m_killSwitchActive.store(true, std::memory_order_release);
            m_status.store(ModuleStatus::KillSwitchActive, std::memory_order_release);
            m_stats.killSwitchActivations.fetch_add(1, std::memory_order_relaxed);

            KillSwitchEvent event;
            event.eventId = GenerateEventId();
            event.reason = "VPN disconnected or manual activation";
            event.vpnStatusBefore = m_vpnStatus.load(std::memory_order_acquire);
            event.vpnStatusAfter = VPNStatus::Disconnected;
            event.activationTime = std::chrono::system_clock::now();

            {
                std::unique_lock lock(m_mutex);
                m_killSwitchEvents.push_back(event);
                if (m_killSwitchEvents.size() > MAX_HISTORY_ENTRIES) {
                    m_killSwitchEvents.erase(m_killSwitchEvents.begin());
                }
            }

            NotifyKillSwitch(event);

            Utils::Logger::Info("Kill switch activated: IPv4+IPv6 blocked, VPN/loopback/DHCP permitted");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("ActivateKillSwitch failed: {}", e.what());
            if (m_wfpEngine) {
                ::FwpmEngineClose0(m_wfpEngine);
                m_wfpEngine = nullptr;
            }
            return false;
        }
    }

    /**
     * @brief Deactivate kill switch
     */
    void DeactivateKillSwitch() {
        try {
            if (m_wfpEngine) {
                // Remove all filters in our sublayer, then close engine
                ::FwpmSubLayerDeleteByKey0(m_wfpEngine, &SHADOWSTRIKE_SUBLAYER_GUID);
                ::FwpmEngineClose0(m_wfpEngine);
                m_wfpEngine = nullptr;
            }

            bool wasActive = m_killSwitchActive.exchange(false, std::memory_order_acq_rel);

            // Restore correct status based on current operational state
            if (m_monitoringActive.load(std::memory_order_acquire)) {
                m_status.store(ModuleStatus::Monitoring, std::memory_order_release);
            } else {
                m_status.store(ModuleStatus::Running, std::memory_order_release);
            }

            if (wasActive) {
                Utils::Logger::Info("Kill switch deactivated");
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("DeactivateKillSwitch failed: {}", e.what());
        }
    }

    /**
     * @brief Block WebRTC
     */
    [[nodiscard]] bool BlockWebRTCInternal() {
        try {
            Utils::Logger::Info("Blocking WebRTC leaks");
            bool anySuccess = false;

            // ================================================================
            // Method 1: Block STUN/TURN ports via WFP
            // ================================================================
            {
                HANDLE wfpEngine = nullptr;
                DWORD result = ::FwpmEngineOpen0(
                    nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &wfpEngine);

                if (result == ERROR_SUCCESS) {
                    // Add WebRTC sublayer
                    FWPM_SUBLAYER0 sublayer = {};
                    sublayer.subLayerKey = SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID;
                    sublayer.displayData.name = const_cast<wchar_t*>(L"ShadowStrike WebRTC Block");
                    sublayer.displayData.description = const_cast<wchar_t*>(L"Block STUN/TURN traffic");
                    sublayer.weight = 0xFFFE;

                    ::FwpmSubLayerAdd0(wfpEngine, &sublayer, nullptr);

                    // Block STUN port 3478 (UDP)
                    constexpr uint16_t WEBRTC_PORTS[] = {3478, 3479, 3480, 3481, 5349, 5350};

                    result = ::FwpmTransactionBegin0(wfpEngine, 0);
                    if (result == ERROR_SUCCESS) {
                        for (uint16_t port : WEBRTC_PORTS) {
                            // Block UDP outbound to this port (IPv4)
                            {
                                FWPM_FILTER0 filter = {};
                                filter.displayData.name = const_cast<wchar_t*>(L"SS Block STUN/TURN Port");
                                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                                filter.subLayerKey = SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID;
                                filter.weight.type = FWP_UINT8;
                                filter.weight.uint8 = 15;
                                filter.action.type = FWP_ACTION_BLOCK;

                                FWPM_FILTER_CONDITION0 cond = {};
                                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                                cond.matchType = FWP_MATCH_EQUAL;
                                cond.conditionValue.type = FWP_UINT16;
                                cond.conditionValue.uint16 = port;

                                filter.filterCondition = &cond;
                                filter.numFilterConditions = 1;

                                UINT64 fid = 0;
                                ::FwpmFilterAdd0(wfpEngine, &filter, nullptr, &fid);
                            }

                            // Block UDP outbound to this port (IPv6)
                            {
                                FWPM_FILTER0 filter = {};
                                filter.displayData.name = const_cast<wchar_t*>(L"SS Block STUN/TURN Port v6");
                                filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                                filter.subLayerKey = SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID;
                                filter.weight.type = FWP_UINT8;
                                filter.weight.uint8 = 15;
                                filter.action.type = FWP_ACTION_BLOCK;

                                FWPM_FILTER_CONDITION0 cond = {};
                                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                                cond.matchType = FWP_MATCH_EQUAL;
                                cond.conditionValue.type = FWP_UINT16;
                                cond.conditionValue.uint16 = port;

                                filter.filterCondition = &cond;
                                filter.numFilterConditions = 1;

                                UINT64 fid = 0;
                                ::FwpmFilterAdd0(wfpEngine, &filter, nullptr, &fid);
                            }
                        }

                        if (::FwpmTransactionCommit0(wfpEngine) == ERROR_SUCCESS) {
                            anySuccess = true;
                            Utils::Logger::Info("WebRTC STUN/TURN ports blocked via WFP");
                        } else {
                            ::FwpmTransactionAbort0(wfpEngine);
                        }
                    }

                    // Store engine handle for cleanup in m_webRtcWfpEngine
                    m_webRtcWfpEngine = wfpEngine;
                } else {
                    Utils::Logger::Warn("Failed to open WFP engine for WebRTC blocking: error={}", result);
                }
            }

            // ================================================================
            // Method 2: Set browser policies via registry
            // ================================================================

            // Chrome: Disable WebRTC via policy
            {
                HKEY hKey = nullptr;
                LONG regResult = ::RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Google\\Chrome",
                    0, nullptr, REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE, nullptr, &hKey, nullptr);

                if (regResult == ERROR_SUCCESS) {
                    // WebRtcLocalIpsAllowedUrls = empty (no exceptions)
                    // WebRtcUdpPortRange = "0-0" (block all WebRTC UDP)
                    const wchar_t* portRange = L"0-0";
                    ::RegSetValueExW(hKey, L"WebRtcUdpPortRange", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(portRange),
                        static_cast<DWORD>((wcslen(portRange) + 1) * sizeof(wchar_t)));

                    // WebRtcIPHandlingPolicy = disable_non_proxied_udp
                    const wchar_t* policy = L"disable_non_proxied_udp";
                    ::RegSetValueExW(hKey, L"WebRtcIPHandlingPolicy", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(policy),
                        static_cast<DWORD>((wcslen(policy) + 1) * sizeof(wchar_t)));

                    ::RegCloseKey(hKey);
                    anySuccess = true;
                    Utils::Logger::Info("Chrome WebRTC policy set");
                }
            }

            // Firefox: Disable WebRTC via policy
            {
                HKEY hKey = nullptr;
                LONG regResult = ::RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Mozilla\\Firefox",
                    0, nullptr, REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE, nullptr, &hKey, nullptr);

                if (regResult == ERROR_SUCCESS) {
                    // media.peerconnection.enabled = false
                    DWORD disabled = 0;
                    ::RegSetValueExW(hKey, L"DisableWebRTC", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&disabled),
                        sizeof(disabled));
                    ::RegCloseKey(hKey);
                    anySuccess = true;
                    Utils::Logger::Info("Firefox WebRTC policy set");
                }
            }

            // Edge: Disable WebRTC via policy (same as Chrome)
            {
                HKEY hKey = nullptr;
                LONG regResult = ::RegCreateKeyExW(
                    HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Policies\\Microsoft\\Edge",
                    0, nullptr, REG_OPTION_NON_VOLATILE,
                    KEY_SET_VALUE, nullptr, &hKey, nullptr);

                if (regResult == ERROR_SUCCESS) {
                    const wchar_t* policy = L"disable_non_proxied_udp";
                    ::RegSetValueExW(hKey, L"WebRtcIPHandlingPolicy", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(policy),
                        static_cast<DWORD>((wcslen(policy) + 1) * sizeof(wchar_t)));

                    const wchar_t* portRange = L"0-0";
                    ::RegSetValueExW(hKey, L"WebRtcUdpPortRange", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(portRange),
                        static_cast<DWORD>((wcslen(portRange) + 1) * sizeof(wchar_t)));

                    ::RegCloseKey(hKey);
                    anySuccess = true;
                    Utils::Logger::Info("Edge WebRTC policy set");
                }
            }

            if (anySuccess) {
                m_webRTCBlocked.store(true, std::memory_order_release);
                m_stats.webRTCBlocked.fetch_add(1, std::memory_order_relaxed);
                Utils::Logger::Info("WebRTC blocking enabled (WFP + browser policies)");
            } else {
                Utils::Logger::Error("WebRTC blocking: all methods failed");
            }

            return anySuccess;

        } catch (const std::exception& e) {
            Utils::Logger::Error("BlockWebRTC failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Unblock WebRTC
     */
    [[nodiscard]] bool UnblockWebRTCInternal() {
        try {
            Utils::Logger::Info("Removing WebRTC blocks");

            // Remove WFP filters
            if (m_webRtcWfpEngine) {
                ::FwpmSubLayerDeleteByKey0(m_webRtcWfpEngine, &SHADOWSTRIKE_WEBRTC_SUBLAYER_GUID);
                ::FwpmEngineClose0(m_webRtcWfpEngine);
                m_webRtcWfpEngine = nullptr;
            }

            // Remove Chrome policy
            {
                HKEY hKey = nullptr;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Policies\\Google\\Chrome",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    ::RegDeleteValueW(hKey, L"WebRtcUdpPortRange");
                    ::RegDeleteValueW(hKey, L"WebRtcIPHandlingPolicy");
                    ::RegCloseKey(hKey);
                }
            }

            // Remove Firefox policy
            {
                HKEY hKey = nullptr;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Policies\\Mozilla\\Firefox",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    ::RegDeleteValueW(hKey, L"DisableWebRTC");
                    ::RegCloseKey(hKey);
                }
            }

            // Remove Edge policy
            {
                HKEY hKey = nullptr;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Policies\\Microsoft\\Edge",
                        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                    ::RegDeleteValueW(hKey, L"WebRtcIPHandlingPolicy");
                    ::RegDeleteValueW(hKey, L"WebRtcUdpPortRange");
                    ::RegCloseKey(hKey);
                }
            }

            m_webRTCBlocked.store(false, std::memory_order_release);
            Utils::Logger::Info("WebRTC blocking disabled");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("UnblockWebRTC failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Disable IPv6
     */
    [[nodiscard]] bool DisableIPv6Internal() {
        try {
            Utils::Logger::Info("Disabling IPv6");

            // Set registry key to disable IPv6
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
            // DisabledComponents = 0xFF

            HKEY hKey = nullptr;
            LONG result = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
                0,
                KEY_SET_VALUE,
                &hKey);

            if (result == ERROR_SUCCESS) {
                DWORD value = 0xFF;  // Disable all IPv6 components
                result = ::RegSetValueExW(
                    hKey,
                    L"DisabledComponents",
                    0,
                    REG_DWORD,
                    reinterpret_cast<const BYTE*>(&value),
                    sizeof(value));

                ::RegCloseKey(hKey);

                if (result == ERROR_SUCCESS) {
                    m_ipv6Disabled.store(true, std::memory_order_release);
                    m_stats.ipv6Blocked++;
                    Utils::Logger::Info("IPv6 disabled (requires reboot)");
                    return true;
                }
            }

            Utils::Logger::Error("Failed to disable IPv6: {}", result);
            return false;

        } catch (const std::exception& e) {
            Utils::Logger::Error("DisableIPv6 failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Enable IPv6
     */
    [[nodiscard]] bool EnableIPv6Internal() {
        try {
            HKEY hKey = nullptr;
            LONG result = ::RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters",
                0,
                KEY_SET_VALUE,
                &hKey);

            if (result == ERROR_SUCCESS) {
                DWORD value = 0x00;  // Enable IPv6
                result = ::RegSetValueExW(
                    hKey,
                    L"DisabledComponents",
                    0,
                    REG_DWORD,
                    reinterpret_cast<const BYTE*>(&value),
                    sizeof(value));

                ::RegCloseKey(hKey);

                if (result == ERROR_SUCCESS) {
                    m_ipv6Disabled.store(false, std::memory_order_release);
                    Utils::Logger::Info("IPv6 enabled (requires reboot)");
                    return true;
                }
            }

            return false;

        } catch (const std::exception& e) {
            Utils::Logger::Error("EnableIPv6 failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Detect VPN adapters
     */
    [[nodiscard]] std::vector<NetworkAdapterInfo> DetectVPNAdaptersInternal() {
        auto allAdapters = GetNetworkAdaptersInternal();

        std::vector<NetworkAdapterInfo> vpnAdapters;
        for (const auto& adapter : allAdapters) {
            if (adapter.isVPN || adapter.type == AdapterType::VPN) {
                vpnAdapters.push_back(adapter);
            }
        }

        return vpnAdapters;
    }

    /**
     * @brief Detect VPN status
     */
    [[nodiscard]] VPNStatus DetectVPNStatus() {
        auto vpnAdapters = DetectVPNAdaptersInternal();

        for (const auto& adapter : vpnAdapters) {
            if (adapter.isConnected && !adapter.ipv4Addresses.empty()) {
                return VPNStatus::Connected;
            }
        }

        // Check if any VPN adapter exists but not connected
        if (!vpnAdapters.empty()) {
            return VPNStatus::Disconnected;
        }

        return VPNStatus::Unknown;
    }

    /**
     * @brief Check for IP leaks
     */
    [[nodiscard]] std::vector<IPLeakEvent> CheckForLeaksInternal() {
        std::vector<IPLeakEvent> leaks;

        try {
            auto adapters = GetNetworkAdaptersInternal();
            auto publicIP = GetPublicIPInternal();

            // Check if VPN is active
            bool vpnActive = (m_vpnStatus.load(std::memory_order_acquire) == VPNStatus::Connected);

            // Snapshot config under lock
            IPv6ProtectionMode ipv6Mode;
            {
                std::shared_lock lock(m_mutex);
                ipv6Mode = m_config.ipv6Protection;
            }

            if (vpnActive && publicIP.has_value()) {
                const auto& detectedPublicIP = publicIP.value();

                // Collect all IPs assigned to VPN adapters
                std::vector<std::string> vpnIPs;
                for (const auto& adapter : adapters) {
                    if (adapter.isVPN && adapter.isConnected) {
                        vpnIPs.insert(vpnIPs.end(),
                            adapter.ipv4Addresses.begin(),
                            adapter.ipv4Addresses.end());
                    }
                }

                // Collect all IPs from non-VPN adapters (potential leak sources)
                std::unordered_set<std::string> nonVpnIPs;
                for (const auto& adapter : adapters) {
                    if (!adapter.isVPN && adapter.isConnected) {
                        nonVpnIPs.insert(adapter.ipv4Addresses.begin(),
                            adapter.ipv4Addresses.end());
                    }
                }

                // A leak is detected if:
                // 1. Public IP matches a non-VPN adapter IP (direct exposure)
                // 2. Public IP doesn't match any VPN IP and non-VPN adapters are present
                bool publicIPMatchesNonVPN = nonVpnIPs.count(detectedPublicIP) > 0;
                bool publicIPMatchesVPN = false;
                for (const auto& vpnIP : vpnIPs) {
                    if (detectedPublicIP == vpnIP) {
                        publicIPMatchesVPN = true;
                        break;
                    }
                }

                if (!publicIPMatchesVPN && !vpnIPs.empty()) {
                    IPLeakEvent leak;
                    leak.eventId = GenerateEventId();
                    leak.leakType = publicIPMatchesNonVPN ?
                        IPLeakType::VPNDrop : IPLeakType::SplitTunnel;
                    leak.leakedIP.address = detectedPublicIP;
                    leak.leakedIP.isVPN = false;
                    if (!vpnIPs.empty()) {
                        leak.expectedIP = vpnIPs[0];
                    }
                    leak.detectionMethod = "Public IP vs VPN adapter comparison";
                    leak.severity = publicIPMatchesNonVPN ? 9 : 7;
                    leak.wasBlocked = m_killSwitchActive.load(std::memory_order_acquire);
                    leak.timestamp = std::chrono::system_clock::now();

                    leaks.push_back(leak);

                    {
                        std::unique_lock lock(m_mutex);
                        m_recentLeaks.push_back(leak);
                        if (m_recentLeaks.size() > MAX_HISTORY_ENTRIES) {
                            m_recentLeaks.erase(m_recentLeaks.begin());
                        }
                    }
                    m_stats.leaksDetected.fetch_add(1, std::memory_order_relaxed);
                    if (leak.wasBlocked) {
                        m_stats.leaksBlocked.fetch_add(1, std::memory_order_relaxed);
                    }
                    auto leakIdx = static_cast<size_t>(leak.leakType);
                    if (leakIdx < m_stats.byLeakType.size()) {
                        m_stats.byLeakType[leakIdx].fetch_add(1, std::memory_order_relaxed);
                    }

                    NotifyLeak(leak);
                }
            }

            // Check for IPv6 leaks on non-VPN adapters
            if (vpnActive && ipv6Mode == IPv6ProtectionMode::VPNOnly) {
                for (const auto& adapter : adapters) {
                    if (!adapter.isVPN && adapter.isConnected && !adapter.ipv6Addresses.empty()) {
                        IPLeakEvent leak;
                        leak.eventId = GenerateEventId();
                        leak.leakType = IPLeakType::IPv6;
                        leak.leakedIP.address = adapter.ipv6Addresses[0];
                        leak.leakedIP.isIPv6 = true;
                        leak.leakedIP.adapterName = adapter.name;
                        leak.detectionMethod = "Non-VPN adapter IPv6 exposure";
                        leak.severity = 7;
                        leak.timestamp = std::chrono::system_clock::now();

                        leaks.push_back(leak);

                        {
                            std::unique_lock lock(m_mutex);
                            m_recentLeaks.push_back(leak);
                            if (m_recentLeaks.size() > MAX_HISTORY_ENTRIES) {
                                m_recentLeaks.erase(m_recentLeaks.begin());
                            }
                        }
                        m_stats.leaksDetected.fetch_add(1, std::memory_order_relaxed);
                        auto leakIdx = static_cast<size_t>(IPLeakType::IPv6);
                        if (leakIdx < m_stats.byLeakType.size()) {
                            m_stats.byLeakType[leakIdx].fetch_add(1, std::memory_order_relaxed);
                        }

                        NotifyLeak(leak);
                    }
                }
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("CheckForLeaks failed: {}", e.what());
        }

        return leaks;
    }

    /**
     * @brief Monitoring thread function
     */
    void MonitoringThreadFunc() {
        Utils::Logger::Info("IP leak monitoring thread started");

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // Snapshot config under lock for thread-safe access
                KillSwitchMode currentKillSwitchMode;
                {
                    std::shared_lock lock(m_mutex);
                    currentKillSwitchMode = m_config.killSwitchMode;
                }

                // Check VPN status
                VPNStatus newStatus = DetectVPNStatus();
                VPNStatus oldStatus = m_vpnStatus.exchange(newStatus, std::memory_order_acq_rel);

                if (newStatus != oldStatus) {
                    NotifyVPNStatus(newStatus);

                    // If VPN disconnected and kill switch enabled, activate it
                    if (oldStatus == VPNStatus::Connected &&
                        newStatus != VPNStatus::Connected &&
                        currentKillSwitchMode != KillSwitchMode::Disabled) {

                        ActivateKillSwitch();
                        m_stats.vpnDisconnections.fetch_add(1, std::memory_order_relaxed);
                    }

                    // If VPN reconnected, deactivate kill switch
                    if (newStatus == VPNStatus::Connected &&
                        m_killSwitchActive.load(std::memory_order_acquire)) {
                        DeactivateKillSwitch();
                    }
                }

                // Periodic leak check
                CheckForLeaksInternal();

            } catch (const std::exception& e) {
                Utils::Logger::Error("Monitoring thread error: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown monitoring thread error");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }

        Utils::Logger::Info("IP leak monitoring thread stopped");
    }

    /**
     * @brief Stop monitoring thread
     */
    void StopMonitoring() {
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);
            if (m_monitoringThread.joinable()) {
                m_monitoringThread.join();
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> IPLeakProtection::s_instanceCreated{false};

[[nodiscard]] IPLeakProtection& IPLeakProtection::Instance() noexcept {
    static IPLeakProtection instance;
    return instance;
}

[[nodiscard]] bool IPLeakProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

IPLeakProtection::IPLeakProtection()
    : m_impl(std::make_unique<IPLeakProtectionImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    Utils::Logger::Info("IPLeakProtection singleton created");
}

IPLeakProtection::~IPLeakProtection() {
    try {
        Shutdown();
        Utils::Logger::Info("IPLeakProtection singleton destroyed");
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool IPLeakProtection::Initialize(const IPLeakConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            Utils::Logger::Warn("IPLeakProtection already initialized");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid IPLeakProtection configuration");
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }

        m_impl->m_config = config;

        // Reset statistics
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        // Detect initial VPN status
        m_impl->m_vpnStatus.store(m_impl->DetectVPNStatus(), std::memory_order_release);

        m_impl->m_status = ModuleStatus::Running;

        Utils::Logger::Info("IPLeakProtection initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("IPLeakProtection initialization failed: {}", e.what());
        m_impl->m_status = ModuleStatus::Error;
        m_impl->NotifyError("Initialization failed: " + std::string(e.what()), -1);
        return false;
    }
}

void IPLeakProtection::Shutdown() {
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
        m_impl->DeactivateKillSwitch();
        lock.lock();

        // Clear history
        m_impl->m_recentLeaks.clear();
        m_impl->m_killSwitchEvents.clear();

        // Clear callbacks
        m_impl->m_leakCallbacks.clear();
        m_impl->m_killSwitchCallbacks.clear();
        m_impl->m_vpnStatusCallbacks.clear();
        m_impl->m_adapterCallbacks.clear();
        m_impl->m_errorCallbacks.clear();

        m_impl->m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("IPLeakProtection shut down");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool IPLeakProtection::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == ModuleStatus::Running ||
           status == ModuleStatus::Monitoring ||
           status == ModuleStatus::KillSwitchActive;
}

[[nodiscard]] ModuleStatus IPLeakProtection::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

[[nodiscard]] bool IPLeakProtection::UpdateConfiguration(const IPLeakConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_impl->m_config = config;

        Utils::Logger::Info("IPLeakProtection configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Configuration update failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] IPLeakConfiguration IPLeakProtection::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// KILL SWITCH
// ============================================================================

[[nodiscard]] bool IPLeakProtection::RunKillSwitch() {
    return m_impl->ActivateKillSwitch();
}

[[nodiscard]] bool IPLeakProtection::StopKillSwitch() {
    m_impl->DeactivateKillSwitch();
    return true;
}

[[nodiscard]] bool IPLeakProtection::IsKillSwitchActive() const noexcept {
    return m_impl->m_killSwitchActive.load(std::memory_order_acquire);
}

void IPLeakProtection::SetKillSwitchMode(KillSwitchMode mode) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.killSwitchMode = mode;
    Utils::Logger::Info("Kill switch mode set to: {}", static_cast<int>(mode));
}

[[nodiscard]] KillSwitchMode IPLeakProtection::GetKillSwitchMode() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.killSwitchMode;
}

// ============================================================================
// WEBRTC PROTECTION
// ============================================================================

[[nodiscard]] bool IPLeakProtection::BlockWebRtcLeaks() {
    return m_impl->BlockWebRTCInternal();
}

[[nodiscard]] bool IPLeakProtection::UnblockWebRtc() {
    return m_impl->UnblockWebRTCInternal();
}

[[nodiscard]] bool IPLeakProtection::IsWebRtcBlocked() const noexcept {
    return m_impl->m_webRTCBlocked.load(std::memory_order_acquire);
}

void IPLeakProtection::SetWebRTCBlockMethod(WebRTCBlockMethod method) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.webRTCBlockMethod = method;
    Utils::Logger::Info("WebRTC block method set to: {}", static_cast<int>(method));
}

// ============================================================================
// IPv6 PROTECTION
// ============================================================================

void IPLeakProtection::SetIPv6ProtectionMode(IPv6ProtectionMode mode) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.ipv6Protection = mode;
    Utils::Logger::Info("IPv6 protection mode set to: {}", static_cast<int>(mode));
}

[[nodiscard]] IPv6ProtectionMode IPLeakProtection::GetIPv6ProtectionMode() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.ipv6Protection;
}

[[nodiscard]] bool IPLeakProtection::DisableIPv6() {
    return m_impl->DisableIPv6Internal();
}

[[nodiscard]] bool IPLeakProtection::EnableIPv6() {
    return m_impl->EnableIPv6Internal();
}

[[nodiscard]] bool IPLeakProtection::IsIPv6Disabled() const noexcept {
    return m_impl->m_ipv6Disabled.load(std::memory_order_acquire);
}

[[nodiscard]] bool IPLeakProtection::BlockIPv6Tunnels() {
    try {
        bool allSuccess = true;

        // Disable Teredo via netsh (safe subprocess)
        if (m_impl->m_config.blockTeredo) {
            if (!RunNetshCommand(L"interface teredo set state disabled")) {
                Utils::Logger::Warn("Failed to disable Teredo tunnel");
                allSuccess = false;
            } else {
                Utils::Logger::Info("Teredo tunnel disabled");
            }
        }

        // Disable ISATAP
        if (m_impl->m_config.blockISATAP) {
            if (!RunNetshCommand(L"interface isatap set state disabled")) {
                Utils::Logger::Warn("Failed to disable ISATAP tunnel");
                allSuccess = false;
            } else {
                Utils::Logger::Info("ISATAP tunnel disabled");
            }
        }

        // Disable 6to4
        if (m_impl->m_config.block6to4) {
            if (!RunNetshCommand(L"interface 6to4 set state disabled")) {
                Utils::Logger::Warn("Failed to disable 6to4 tunnel");
                allSuccess = false;
            } else {
                Utils::Logger::Info("6to4 tunnel disabled");
            }
        }

        if (allSuccess) {
            Utils::Logger::Info("All IPv6 tunnels blocked successfully");
        } else {
            Utils::Logger::Warn("Some IPv6 tunnels could not be blocked (may require elevation)");
        }
        return allSuccess;

    } catch (const std::exception& e) {
        Utils::Logger::Error("BlockIPv6Tunnels failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// VPN MONITORING
// ============================================================================

[[nodiscard]] bool IPLeakProtection::StartVPNMonitoring() {
    try {
        if (m_impl->m_monitoringActive.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("Monitoring already active");
            return true;
        }

        m_impl->m_monitoringActive.store(true, std::memory_order_release);
        m_impl->m_status = ModuleStatus::Monitoring;

        // Start monitoring thread
        m_impl->m_monitoringThread = std::thread(
            &IPLeakProtectionImpl::MonitoringThreadFunc, m_impl.get());

        Utils::Logger::Info("VPN monitoring started");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartVPNMonitoring failed: {}", e.what());
        m_impl->NotifyError("Failed to start monitoring: " + std::string(e.what()), -1);
        return false;
    }
}

void IPLeakProtection::StopVPNMonitoring() {
    m_impl->StopMonitoring();

    // Only set Running if currently in Monitoring state
    ModuleStatus expected = ModuleStatus::Monitoring;
    m_impl->m_status.compare_exchange_strong(expected, ModuleStatus::Running,
        std::memory_order_acq_rel);

    Utils::Logger::Info("VPN monitoring stopped");
}

[[nodiscard]] VPNStatus IPLeakProtection::GetVPNStatus() const noexcept {
    return m_impl->m_vpnStatus.load(std::memory_order_acquire);
}

[[nodiscard]] std::optional<VPNConnectionInfo> IPLeakProtection::GetVPNConnection() {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_vpnConnection;
}

[[nodiscard]] std::vector<NetworkAdapterInfo> IPLeakProtection::DetectVPNAdapters() {
    return m_impl->DetectVPNAdaptersInternal();
}

// ============================================================================
// IP DETECTION
// ============================================================================

[[nodiscard]] std::optional<IPAddressInfo> IPLeakProtection::GetPublicIP() {
    auto publicIPStr = m_impl->GetPublicIPInternal();

    if (publicIPStr.has_value()) {
        IPAddressInfo info;
        info.address = publicIPStr.value();
        info.isIPv6 = IsIPv6Address(info.address);
        info.isPrivate = IsPrivateIP(info.address);

        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_currentPublicIP = info.address;

        return info;
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<IPAddressInfo> IPLeakProtection::GetAllIPAddresses() {
    std::vector<IPAddressInfo> addresses;

    auto adapters = m_impl->GetNetworkAdaptersInternal();

    for (const auto& adapter : adapters) {
        for (const auto& ipv4 : adapter.ipv4Addresses) {
            IPAddressInfo info;
            info.address = ipv4;
            info.isIPv6 = false;
            info.isPrivate = IsPrivateIP(ipv4);
            info.isVPN = adapter.isVPN;
            info.adapterName = adapter.name;
            addresses.push_back(info);
        }

        for (const auto& ipv6 : adapter.ipv6Addresses) {
            IPAddressInfo info;
            info.address = ipv6;
            info.isIPv6 = true;
            info.isPrivate = IsPrivateIP(ipv6);
            info.isVPN = adapter.isVPN;
            info.adapterName = adapter.name;
            addresses.push_back(info);
        }
    }

    return addresses;
}

[[nodiscard]] std::vector<IPLeakEvent> IPLeakProtection::CheckForLeaks() {
    return m_impl->CheckForLeaksInternal();
}

[[nodiscard]] std::vector<NetworkAdapterInfo> IPLeakProtection::GetNetworkAdapters() {
    return m_impl->GetNetworkAdaptersInternal();
}

// ============================================================================
// LEAK HISTORY
// ============================================================================

[[nodiscard]] std::vector<IPLeakEvent> IPLeakProtection::GetRecentLeaks(size_t limit) {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<IPLeakEvent> leaks = m_impl->m_recentLeaks;
    if (leaks.size() > limit) {
        leaks.resize(limit);
    }

    return leaks;
}

[[nodiscard]] std::vector<KillSwitchEvent> IPLeakProtection::GetKillSwitchEvents(size_t limit) {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<KillSwitchEvent> events = m_impl->m_killSwitchEvents;
    if (events.size() > limit) {
        events.resize(limit);
    }

    return events;
}

void IPLeakProtection::ClearHistory() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_recentLeaks.clear();
    m_impl->m_killSwitchEvents.clear();
    Utils::Logger::Info("History cleared");
}

// ============================================================================
// EXCEPTIONS
// ============================================================================

[[nodiscard]] bool IPLeakProtection::AddAllowedAdapter(const std::string& adapterGuid) {
    if (adapterGuid.empty() || adapterGuid.size() > 512) {
        Utils::Logger::Warn("AddAllowedAdapter: invalid adapter GUID");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    auto& adapters = m_impl->m_config.allowedAdapters;

    // Prevent duplicates
    if (std::find(adapters.begin(), adapters.end(), adapterGuid) != adapters.end()) {
        return true;  // Already present
    }

    adapters.push_back(adapterGuid);
    Utils::Logger::Info("Added allowed adapter: {}", adapterGuid);
    return true;
}

[[nodiscard]] bool IPLeakProtection::RemoveAllowedAdapter(const std::string& adapterGuid) {
    std::unique_lock lock(m_impl->m_mutex);
    auto& adapters = m_impl->m_config.allowedAdapters;
    adapters.erase(std::remove(adapters.begin(), adapters.end(), adapterGuid), adapters.end());
    Utils::Logger::Info("Removed allowed adapter: {}", adapterGuid);
    return true;
}

[[nodiscard]] bool IPLeakProtection::AddAllowedProcess(const std::string& processName) {
    if (processName.empty() || processName.size() > 512) {
        Utils::Logger::Warn("AddAllowedProcess: invalid process name");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    auto& processes = m_impl->m_config.allowedProcesses;

    if (std::find(processes.begin(), processes.end(), processName) != processes.end()) {
        return true;
    }

    processes.push_back(processName);
    Utils::Logger::Info("Added allowed process: {}", processName);
    return true;
}

[[nodiscard]] bool IPLeakProtection::RemoveAllowedProcess(const std::string& processName) {
    std::unique_lock lock(m_impl->m_mutex);
    auto& processes = m_impl->m_config.allowedProcesses;
    processes.erase(std::remove(processes.begin(), processes.end(), processName), processes.end());
    Utils::Logger::Info("Removed allowed process: {}", processName);
    return true;
}

[[nodiscard]] bool IPLeakProtection::AddAllowedLocalNetwork(const std::string& cidr) {
    if (cidr.empty() || cidr.size() > 512) {
        Utils::Logger::Warn("AddAllowedLocalNetwork: invalid CIDR");
        return false;
    }

    // Basic CIDR format validation (must contain '/')
    if (cidr.find('/') == std::string::npos) {
        Utils::Logger::Warn("AddAllowedLocalNetwork: CIDR must contain '/' separator");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    auto& networks = m_impl->m_config.allowedLocalNetworks;

    if (std::find(networks.begin(), networks.end(), cidr) != networks.end()) {
        return true;
    }

    networks.push_back(cidr);
    Utils::Logger::Info("Added allowed local network: {}", cidr);
    return true;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void IPLeakProtection::RegisterLeakCallback(LeakDetectedCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_leakCallbacks.push_back(std::move(callback));
}

void IPLeakProtection::RegisterKillSwitchCallback(KillSwitchCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_killSwitchCallbacks.push_back(std::move(callback));
}

void IPLeakProtection::RegisterVPNStatusCallback(VPNStatusCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_vpnStatusCallbacks.push_back(std::move(callback));
}

void IPLeakProtection::RegisterAdapterCallback(AdapterCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_adapterCallbacks.push_back(std::move(callback));
}

void IPLeakProtection::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void IPLeakProtection::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_mutex);

    m_impl->m_leakCallbacks.clear();
    m_impl->m_killSwitchCallbacks.clear();
    m_impl->m_vpnStatusCallbacks.clear();
    m_impl->m_adapterCallbacks.clear();
    m_impl->m_errorCallbacks.clear();

    Utils::Logger::Info("All callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] IPLeakStatistics IPLeakProtection::GetStatistics() const {
    // Construct snapshot by loading each atomic individually
    // (IPLeakStatistics has non-copyable atomics, so we load values explicitly)
    IPLeakStatistics snapshot;
    snapshot.leaksDetected.store(m_impl->m_stats.leaksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.leaksBlocked.store(m_impl->m_stats.leaksBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.webRTCBlocked.store(m_impl->m_stats.webRTCBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.ipv6Blocked.store(m_impl->m_stats.ipv6Blocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.killSwitchActivations.store(m_impl->m_stats.killSwitchActivations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.killSwitchDuration.store(m_impl->m_stats.killSwitchDuration.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.vpnDisconnections.store(m_impl->m_stats.vpnDisconnections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.proxyBypassBlocked.store(m_impl->m_stats.proxyBypassBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    snapshot.connectionsBlocked.store(m_impl->m_stats.connectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);

    for (size_t i = 0; i < m_impl->m_stats.byLeakType.size(); ++i) {
        snapshot.byLeakType[i].store(m_impl->m_stats.byLeakType[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    snapshot.startTime = m_impl->m_stats.startTime;

    return snapshot;
}

void IPLeakProtection::ResetStatistics() {
    m_impl->m_stats.Reset();
    m_impl->m_stats.startTime = Clock::now();
    Utils::Logger::Info("Statistics reset");
}

[[nodiscard]] bool IPLeakProtection::SelfTest() {
    try {
        Utils::Logger::Info("Running IPLeakProtection self-test...");

        bool allPassed = true;

        // Test 1: Configuration validation
        IPLeakConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("Self-test failed: Invalid default configuration");
            allPassed = false;
        }

        // Test 2: Network adapter enumeration
        try {
            auto adapters = GetNetworkAdapters();
            if (adapters.empty()) {
                Utils::Logger::Warn("Self-test: No network adapters found");
            } else {
                Utils::Logger::Debug("Self-test: Found {} network adapters", adapters.size());
            }
        } catch (...) {
            Utils::Logger::Error("Self-test failed: Adapter enumeration");
            allPassed = false;
        }

        // Test 3: VPN detection
        try {
            auto vpnAdapters = DetectVPNAdapters();
            Utils::Logger::Debug("Self-test: Found {} VPN adapters", vpnAdapters.size());
        } catch (...) {
            Utils::Logger::Error("Self-test failed: VPN detection");
            allPassed = false;
        }

        // Test 4: IP address detection
        try {
            auto addresses = GetAllIPAddresses();
            if (addresses.empty()) {
                Utils::Logger::Warn("Self-test: No IP addresses found");
            } else {
                Utils::Logger::Debug("Self-test: Found {} IP addresses", addresses.size());
            }
        } catch (...) {
            Utils::Logger::Error("Self-test failed: IP address detection");
            allPassed = false;
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

[[nodiscard]] std::string IPLeakProtection::GetVersionString() noexcept {
    return std::to_string(IPLeakConstants::VERSION_MAJOR) + "." +
           std::to_string(IPLeakConstants::VERSION_MINOR) + "." +
           std::to_string(IPLeakConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string IPAddressInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["address"] = address;
    j["isIPv6"] = isIPv6;
    j["isPrivate"] = isPrivate;
    j["isVPN"] = isVPN;
    j["adapterName"] = adapterName;
    j["country"] = country;
    j["isp"] = isp;

    return j.dump(2);
}

[[nodiscard]] std::string NetworkAdapterInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["guid"] = guid;
    j["name"] = name;
    j["description"] = description;
    j["type"] = static_cast<int>(type);
    j["macAddress"] = macAddress;
    j["ipv4Addresses"] = ipv4Addresses;
    j["ipv6Addresses"] = ipv6Addresses;
    j["gateway"] = gateway;
    j["dnsServers"] = dnsServers;
    j["isConnected"] = isConnected;
    j["isVPN"] = isVPN;
    j["isEnabled"] = isEnabled;

    return j.dump(2);
}

[[nodiscard]] std::string VPNConnectionInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["connectionName"] = connectionName;
    j["protocol"] = protocol;
    j["serverAddress"] = serverAddress;
    j["serverPort"] = serverPort;
    j["status"] = static_cast<int>(status);
    j["assignedIP"] = assignedIP;
    j["bytesReceived"] = bytesReceived;
    j["bytesSent"] = bytesSent;
    j["adapterGuid"] = adapterGuid;
    j["connectedSince"] = connectedSince.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string IPLeakEvent::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["eventId"] = eventId;
    j["leakType"] = static_cast<int>(leakType);
    j["leakedIP"] = Json::parse(leakedIP.ToJson());
    j["expectedIP"] = expectedIP;
    j["detectionMethod"] = detectionMethod;
    j["processId"] = processId;
    j["processName"] = processName;
    j["destination"] = destination;
    j["severity"] = severity;
    j["wasBlocked"] = wasBlocked;
    j["timestamp"] = timestamp.time_since_epoch().count();

    return j.dump(2);
}

[[nodiscard]] std::string KillSwitchEvent::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["eventId"] = eventId;
    j["reason"] = reason;
    j["vpnStatusBefore"] = static_cast<int>(vpnStatusBefore);
    j["vpnStatusAfter"] = static_cast<int>(vpnStatusAfter);
    j["blockedConnections"] = blockedConnections;
    j["activationTime"] = activationTime.time_since_epoch().count();

    if (deactivationTime.has_value()) {
        j["deactivationTime"] = deactivationTime.value().time_since_epoch().count();
    }

    j["duration"] = duration.count();

    return j.dump(2);
}

IPLeakStatistics::IPLeakStatistics(const IPLeakStatistics& other) noexcept
    : startTime(other.startTime)
{
    leaksDetected.store(other.leaksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    leaksBlocked.store(other.leaksBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    webRTCBlocked.store(other.webRTCBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    ipv6Blocked.store(other.ipv6Blocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    killSwitchActivations.store(other.killSwitchActivations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    killSwitchDuration.store(other.killSwitchDuration.load(std::memory_order_relaxed), std::memory_order_relaxed);
    vpnDisconnections.store(other.vpnDisconnections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    proxyBypassBlocked.store(other.proxyBypassBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    connectionsBlocked.store(other.connectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    for (size_t i = 0; i < byLeakType.size(); ++i) {
        byLeakType[i].store(other.byLeakType[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
}

IPLeakStatistics& IPLeakStatistics::operator=(const IPLeakStatistics& other) noexcept {
    if (this != &other) {
        leaksDetected.store(other.leaksDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
        leaksBlocked.store(other.leaksBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        webRTCBlocked.store(other.webRTCBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        ipv6Blocked.store(other.ipv6Blocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        killSwitchActivations.store(other.killSwitchActivations.load(std::memory_order_relaxed), std::memory_order_relaxed);
        killSwitchDuration.store(other.killSwitchDuration.load(std::memory_order_relaxed), std::memory_order_relaxed);
        vpnDisconnections.store(other.vpnDisconnections.load(std::memory_order_relaxed), std::memory_order_relaxed);
        proxyBypassBlocked.store(other.proxyBypassBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        connectionsBlocked.store(other.connectionsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t i = 0; i < byLeakType.size(); ++i) {
            byLeakType[i].store(other.byLeakType[i].load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        startTime = other.startTime;
    }
    return *this;
}

void IPLeakStatistics::Reset() noexcept {
    leaksDetected.store(0, std::memory_order_relaxed);
    leaksBlocked.store(0, std::memory_order_relaxed);
    webRTCBlocked.store(0, std::memory_order_relaxed);
    ipv6Blocked.store(0, std::memory_order_relaxed);
    killSwitchActivations.store(0, std::memory_order_relaxed);
    killSwitchDuration.store(0, std::memory_order_relaxed);
    vpnDisconnections.store(0, std::memory_order_relaxed);
    proxyBypassBlocked.store(0, std::memory_order_relaxed);
    connectionsBlocked.store(0, std::memory_order_relaxed);

    for (auto& type : byLeakType) {
        type.store(0, std::memory_order_relaxed);
    }
}

[[nodiscard]] std::string IPLeakStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["leaksDetected"] = leaksDetected.load(std::memory_order_relaxed);
    j["leaksBlocked"] = leaksBlocked.load(std::memory_order_relaxed);
    j["webRTCBlocked"] = webRTCBlocked.load(std::memory_order_relaxed);
    j["ipv6Blocked"] = ipv6Blocked.load(std::memory_order_relaxed);
    j["killSwitchActivations"] = killSwitchActivations.load(std::memory_order_relaxed);
    j["killSwitchDuration"] = killSwitchDuration.load(std::memory_order_relaxed);
    j["vpnDisconnections"] = vpnDisconnections.load(std::memory_order_relaxed);
    j["proxyBypassBlocked"] = proxyBypassBlocked.load(std::memory_order_relaxed);
    j["connectionsBlocked"] = connectionsBlocked.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] bool IPLeakConfiguration::IsValid() const noexcept {
    try {
        // Kill switch mode must be a known value
        if (static_cast<uint8_t>(killSwitchMode) > static_cast<uint8_t>(KillSwitchMode::SystemLevel)) {
            return false;
        }

        // WebRTC block method must be known
        if (static_cast<uint8_t>(webRTCBlockMethod) > static_cast<uint8_t>(WebRTCBlockMethod::Combined)) {
            return false;
        }

        // IPv6 protection mode must be known
        if (static_cast<uint8_t>(ipv6Protection) > static_cast<uint8_t>(IPv6ProtectionMode::VPNOnly)) {
            return false;
        }

        // Cap the number of allowed entries to prevent abuse
        constexpr size_t MAX_ALLOWED_ENTRIES = 1000;
        if (allowedAdapters.size() > MAX_ALLOWED_ENTRIES) return false;
        if (allowedProcesses.size() > MAX_ALLOWED_ENTRIES) return false;
        if (allowedLocalNetworks.size() > MAX_ALLOWED_ENTRIES) return false;
        if (vpnAdapterPatterns.size() > MAX_ALLOWED_ENTRIES) return false;

        // Validate that string entries are not excessively long
        constexpr size_t MAX_ENTRY_LENGTH = 512;
        for (const auto& entry : allowedAdapters) {
            if (entry.empty() || entry.size() > MAX_ENTRY_LENGTH) return false;
        }
        for (const auto& entry : allowedProcesses) {
            if (entry.empty() || entry.size() > MAX_ENTRY_LENGTH) return false;
        }
        for (const auto& entry : allowedLocalNetworks) {
            if (entry.empty() || entry.size() > MAX_ENTRY_LENGTH) return false;
        }
        for (const auto& entry : vpnAdapterPatterns) {
            if (entry.empty() || entry.size() > MAX_ENTRY_LENGTH) return false;
        }

        return true;

    } catch (...) {
        return false;
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetIPLeakTypeName(IPLeakType type) noexcept {
    switch (type) {
        case IPLeakType::None: return "None";
        case IPLeakType::WebRTC: return "WebRTC";
        case IPLeakType::IPv6: return "IPv6";
        case IPLeakType::DNS: return "DNS";
        case IPLeakType::HTTPHeader: return "HTTPHeader";
        case IPLeakType::VPNDrop: return "VPNDrop";
        case IPLeakType::SplitTunnel: return "SplitTunnel";
        case IPLeakType::Teredo: return "Teredo";
        case IPLeakType::ISATAP: return "ISATAP";
        case IPLeakType::ProxyBypass: return "ProxyBypass";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetKillSwitchModeName(KillSwitchMode mode) noexcept {
    switch (mode) {
        case KillSwitchMode::Disabled: return "Disabled";
        case KillSwitchMode::Enabled: return "Enabled";
        case KillSwitchMode::AppLevel: return "AppLevel";
        case KillSwitchMode::SystemLevel: return "SystemLevel";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetVPNStatusName(VPNStatus status) noexcept {
    switch (status) {
        case VPNStatus::Unknown: return "Unknown";
        case VPNStatus::Connected: return "Connected";
        case VPNStatus::Connecting: return "Connecting";
        case VPNStatus::Disconnected: return "Disconnected";
        case VPNStatus::Reconnecting: return "Reconnecting";
        case VPNStatus::Error: return "Error";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAdapterTypeName(AdapterType type) noexcept {
    switch (type) {
        case AdapterType::Unknown: return "Unknown";
        case AdapterType::Physical: return "Physical";
        case AdapterType::Virtual: return "Virtual";
        case AdapterType::Loopback: return "Loopback";
        case AdapterType::WiFi: return "WiFi";
        case AdapterType::Ethernet: return "Ethernet";
        case AdapterType::Cellular: return "Cellular";
        case AdapterType::VPN: return "VPN";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetIPv6ProtectionModeName(IPv6ProtectionMode mode) noexcept {
    switch (mode) {
        case IPv6ProtectionMode::Disabled: return "Disabled";
        case IPv6ProtectionMode::DisableAll: return "DisableAll";
        case IPv6ProtectionMode::TunnelsOnly: return "TunnelsOnly";
        case IPv6ProtectionMode::VPNOnly: return "VPNOnly";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetWebRTCBlockMethodName(WebRTCBlockMethod method) noexcept {
    switch (method) {
        case WebRTCBlockMethod::Disabled: return "Disabled";
        case WebRTCBlockMethod::BrowserPolicy: return "BrowserPolicy";
        case WebRTCBlockMethod::NetworkBlock: return "NetworkBlock";
        case WebRTCBlockMethod::ExtensionBased: return "ExtensionBased";
        case WebRTCBlockMethod::Combined: return "Combined";
        default: return "Unknown";
    }
}

[[nodiscard]] bool IsPrivateIP(const std::string& ip) {
    if (ip.empty()) return false;

    // IPv4 private ranges per RFC 1918 + loopback
    if (ip.find(':') == std::string::npos) {
        // Parse first two octets for 172.16-31.x.x check
        if (ip.substr(0, 3) == "10.") return true;
        if (ip.substr(0, 8) == "192.168.") return true;
        if (ip.substr(0, 4) == "127.") return true;
        if (ip.substr(0, 7) == "169.254") return true;  // link-local

        // 172.16.0.0 - 172.31.255.255
        if (ip.size() >= 6 && ip.substr(0, 4) == "172.") {
            auto dotPos = ip.find('.', 4);
            if (dotPos != std::string::npos && dotPos > 4) {
                try {
                    int secondOctet = std::stoi(ip.substr(4, dotPos - 4));
                    if (secondOctet >= 16 && secondOctet <= 31) return true;
                } catch (...) {
                    // Malformed IP, not private
                }
            }
        }
        return false;
    }

    // IPv6 private/special ranges
    if (ip == "::1") return true;  // loopback

    // Unique Local Addresses: fc00::/7 (fc.. and fd..)
    if (ip.size() >= 2) {
        char c0 = static_cast<char>(std::tolower(static_cast<unsigned char>(ip[0])));
        char c1 = static_cast<char>(std::tolower(static_cast<unsigned char>(ip[1])));
        if (c0 == 'f' && (c1 == 'c' || c1 == 'd')) return true;
    }

    // Link-local: fe80::/10
    if (ip.size() >= 4) {
        std::string prefix4;
        prefix4.reserve(4);
        for (size_t i = 0; i < 4 && i < ip.size(); ++i) {
            prefix4 += static_cast<char>(std::tolower(static_cast<unsigned char>(ip[i])));
        }
        if (prefix4 == "fe80") return true;
    }

    return false;
}

[[nodiscard]] bool IsIPv6Address(const std::string& ip) {
    return ip.find(':') != std::string::npos;
}

[[nodiscard]] AdapterType DetectAdapterType(const std::string& description) {
    if (description.find("VPN") != std::string::npos ||
        description.find("TAP") != std::string::npos) {
        return AdapterType::VPN;
    }

    if (description.find("WiFi") != std::string::npos ||
        description.find("Wireless") != std::string::npos) {
        return AdapterType::WiFi;
    }

    if (description.find("Ethernet") != std::string::npos) {
        return AdapterType::Ethernet;
    }

    if (description.find("Loopback") != std::string::npos) {
        return AdapterType::Loopback;
    }

    return AdapterType::Unknown;
}

[[nodiscard]] bool IsVPNAdapter(const std::string& name, const std::string& description) {
    for (const auto* pattern : VPN_ADAPTER_PATTERNS) {
        if (name.find(pattern) != std::string::npos ||
            description.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}  // namespace ShadowStrike::Privacy
