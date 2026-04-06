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
 * @file FirewallManager.cpp
 * @brief Enterprise implementation of Windows Filtering Platform firewall engine.
 *
 * The Gatekeeper of ShadowStrike NGAV - provides comprehensive network access control
 * through direct WFP integration, application-based filtering, geo-blocking, port
 * management, and advanced policy enforcement. Protects against unauthorized network
 * access, data exfiltration, and network-based attacks.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "FirewallManager.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <regex>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <WinSock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#  include <fwpmu.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#  pragma comment(lib, "fwpuclnt.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Network {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Converts IP string to binary array.
 */
[[nodiscard]] std::optional<std::array<uint8_t, 16>> ParseIPAddress(
    const std::wstring& ipStr,
    bool& outIsIPv6
) {
    std::array<uint8_t, 16> result{0};

    // Try IPv4 first
    std::string narrowIp = StringUtils::ToNarrow(ipStr);

    // IPv4
    struct in_addr addr4;
    if (inet_pton(AF_INET, narrowIp.c_str(), &addr4) == 1) {
        std::memcpy(result.data(), &addr4.s_addr, 4);
        outIsIPv6 = false;
        return result;
    }

    // IPv6
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, narrowIp.c_str(), &addr6) == 1) {
        std::memcpy(result.data(), &addr6, 16);
        outIsIPv6 = true;
        return result;
    }

    return std::nullopt;
}

/**
 * @brief Converts binary IP to string.
 */
[[nodiscard]] std::wstring IPToString(const std::array<uint8_t, 16>& ip, bool isIPv6) {
    char buffer[INET6_ADDRSTRLEN];

    if (isIPv6) {
        inet_ntop(AF_INET6, ip.data(), buffer, INET6_ADDRSTRLEN);
    } else {
        inet_ntop(AF_INET, ip.data(), buffer, INET_ADDRSTRLEN);
    }

    return StringUtils::ToWide(buffer);
}

/**
 * @brief Checks if two IPs match with subnet mask.
 */
[[nodiscard]] bool IPMatchesWithMask(
    const std::array<uint8_t, 16>& ip1,
    const std::array<uint8_t, 16>& ip2,
    uint8_t prefixLength,
    bool isIPv6
) {
    const size_t byteCount = isIPv6 ? 16 : 4;
    const size_t fullBytes = prefixLength / 8;
    const uint8_t remainingBits = prefixLength % 8;

    // Compare full bytes
    if (!std::equal(ip1.begin(), ip1.begin() + fullBytes, ip2.begin())) {
        return false;
    }

    // Compare remaining bits
    if (remainingBits > 0 && fullBytes < byteCount) {
        uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainingBits));
        if ((ip1[fullBytes] & mask) != (ip2[fullBytes] & mask)) {
            return false;
        }
    }

    return true;
}

/**
 * @brief Escapes a string for safe JSON embedding.
 */
[[nodiscard]] std::string EscapeJsonString(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b";  break;
            case '\f': output += "\\f";  break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    output += buf;
                } else {
                    output += c;
                }
                break;
        }
    }
    return output;
}

} // anonymous namespace

// ============================================================================
// IPAddressMatch METHODS
// ============================================================================

[[nodiscard]] bool IPAddressMatch::Matches(const std::array<uint8_t, 16>& ip) const {
    switch (type) {
        case Type::ANY:
            return true;

        case Type::SINGLE:
            return std::equal(address.begin(), address.end(), ip.begin());

        case Type::RANGE: {
            // Check if IP is between address (start) and rangeEnd (end)
            // using lexicographic byte comparison (network byte order)
            const size_t len = isIPv6 ? 16 : 4;
            int cmpStart = std::memcmp(ip.data(), address.data(), len);
            int cmpEnd = std::memcmp(ip.data(), rangeEnd.data(), len);
            return cmpStart >= 0 && cmpEnd <= 0;
        }

        case Type::CIDR:
            return IPMatchesWithMask(address, ip, prefixLength, isIPv6);

        case Type::LIST:
            return std::any_of(addressList.begin(), addressList.end(),
                [&ip](const auto& addr) {
                    return std::equal(addr.begin(), addr.end(), ip.begin());
                });

        default:
            return false;
    }
}

[[nodiscard]] std::wstring IPAddressMatch::ToString() const {
    switch (type) {
        case Type::ANY:
            return L"Any";
        case Type::SINGLE:
            return IPToString(address, isIPv6);
        case Type::RANGE:
            return std::format(L"{} - {}", IPToString(address, isIPv6), IPToString(rangeEnd, isIPv6));
        case Type::CIDR:
            return std::format(L"{}/{}", IPToString(address, isIPv6), prefixLength);
        case Type::LIST:
            return std::format(L"{} addresses", addressList.size());
        default:
            return L"Unknown";
    }
}

// ============================================================================
// ApplicationMatch METHODS
// ============================================================================

[[nodiscard]] bool ApplicationMatch::Matches(
    const std::wstring& processPath,
    const std::wstring& procName,
    const std::wstring& pub,
    const std::array<uint8_t, 32>& hash
) const {
    switch (type) {
        case Type::ANY:
            return true;

        case Type::PATH:
            return StringUtils::IEquals(path, processPath);

        case Type::PATH_WILDCARD: {
            // Simple wildcard matching
            std::wstring pattern = path;
            std::replace(pattern.begin(), pattern.end(), L'*', L'.');
            // Would use regex, but simplified for now
            return processPath.find(pattern) != std::wstring::npos;
        }

        case Type::NAME:
            return StringUtils::IEquals(processName, procName);

        case Type::PUBLISHER:
            return !publisher.empty() && pub.find(publisher) != std::wstring::npos;

        case Type::HASH:
            return std::equal(sha256.begin(), sha256.end(), hash.begin());

        case Type::SERVICE:
            // Service name matching would require service enumeration
            return false;

        default:
            return false;
    }
}

// ============================================================================
// GeoMatch METHODS
// ============================================================================

[[nodiscard]] bool GeoMatch::Matches(
    const std::string& country,
    const std::string& continent,
    uint32_t asn
) const {
    bool matchesCountry = countryCodes.empty() ||
        std::find(countryCodes.begin(), countryCodes.end(), country) != countryCodes.end();

    bool matchesContinent = continentCodes.empty() ||
        std::find(continentCodes.begin(), continentCodes.end(), continent) != continentCodes.end();

    bool matchesASN = asnNumbers.empty() ||
        std::find(asnNumbers.begin(), asnNumbers.end(), asn) != asnNumbers.end();

    bool matches = matchesCountry && matchesContinent && matchesASN;

    // If allow list, invert the logic
    if (isAllowList) {
        return !matches;
    }

    return matches;
}

// ============================================================================
// FirewallRule METHODS
// ============================================================================

[[nodiscard]] bool FirewallRule::IsValid() const {
    if (name.empty()) return false;
    if (priority == 0) return false;

    // Validate port ranges
    for (const auto& range : localPorts) {
        if (!range.IsValid()) return false;
    }
    for (const auto& range : remotePorts) {
        if (!range.IsValid()) return false;
    }

    return true;
}

FirewallRule FirewallRule::CreateBlockIP(const std::wstring& ip, RuleDirection dir) {
    FirewallRule rule;
    rule.name = std::format(L"Block IP {}", ip);
    rule.description = L"Automatically created IP block rule";
    rule.type = RuleType::IP;
    rule.action = RuleAction::BLOCK;
    rule.direction = dir;
    rule.priority = FirewallConstants::PRIORITY_HIGH;

    bool isIPv6 = false;
    if (auto parsedIP = ParseIPAddress(ip, isIPv6)) {
        rule.remoteAddress.type = IPAddressMatch::Type::SINGLE;
        rule.remoteAddress.address = *parsedIP;
        rule.remoteAddress.isIPv6 = isIPv6;
    }

    rule.createdAt = system_clock::now();
    rule.modifiedAt = rule.createdAt;
    rule.isEnabled = true;

    return rule;
}

FirewallRule FirewallRule::CreateBlockPort(uint16_t port, RuleProtocol proto, RuleDirection dir) {
    FirewallRule rule;
    rule.name = std::format(L"Block Port {}", port);
    rule.description = L"Automatically created port block rule";
    rule.type = RuleType::PORT;
    rule.action = RuleAction::BLOCK;
    rule.direction = dir;
    rule.protocol = proto;
    rule.priority = FirewallConstants::PRIORITY_NORMAL;

    rule.remotePorts.push_back(PortRange(port));

    rule.createdAt = system_clock::now();
    rule.modifiedAt = rule.createdAt;
    rule.isEnabled = true;

    return rule;
}

FirewallRule FirewallRule::CreateBlockApp(const std::wstring& appPath) {
    FirewallRule rule;
    rule.name = std::format(L"Block Application");
    rule.description = std::format(L"Block network access for {}", appPath);
    rule.type = RuleType::APPLICATION;
    rule.action = RuleAction::BLOCK;
    rule.direction = RuleDirection::BOTH;
    rule.priority = FirewallConstants::PRIORITY_HIGH;

    rule.application.type = ApplicationMatch::Type::PATH;
    rule.application.path = appPath;

    rule.createdAt = system_clock::now();
    rule.modifiedAt = rule.createdAt;
    rule.isEnabled = true;

    return rule;
}

FirewallRule FirewallRule::CreateAllowApp(const std::wstring& appPath) {
    FirewallRule rule;
    rule.name = std::format(L"Allow Application");
    rule.description = std::format(L"Allow network access for {}", appPath);
    rule.type = RuleType::APPLICATION;
    rule.action = RuleAction::ALLOW;
    rule.direction = RuleDirection::BOTH;
    rule.priority = FirewallConstants::PRIORITY_NORMAL;

    rule.application.type = ApplicationMatch::Type::PATH;
    rule.application.path = appPath;

    rule.createdAt = system_clock::now();
    rule.modifiedAt = rule.createdAt;
    rule.isEnabled = true;

    return rule;
}

FirewallRule FirewallRule::CreateGeoBlock(const std::vector<std::string>& countries) {
    FirewallRule rule;
    rule.name = L"Geo-Blocking Rule";
    rule.description = L"Block traffic from specific countries";
    rule.type = RuleType::GEO;
    rule.action = RuleAction::BLOCK;
    rule.direction = RuleDirection::BOTH;
    rule.priority = FirewallConstants::PRIORITY_NORMAL;

    rule.geoMatch.countryCodes = countries;
    rule.geoMatch.isAllowList = false;

    rule.createdAt = system_clock::now();
    rule.modifiedAt = rule.createdAt;
    rule.isEnabled = true;

    return rule;
}

// ============================================================================
// FirewallRuleLegacy CONVERSION
// ============================================================================

FirewallRuleLegacy::operator FirewallRule() const {
    FirewallRule rule;
    rule.name = StringUtils::ToWide(id);
    rule.type = appPath.empty() ? RuleType::PORT : RuleType::APPLICATION;
    rule.action = isAllow ? RuleAction::ALLOW : RuleAction::BLOCK;
    rule.direction = RuleDirection::BOTH;

    if (!appPath.empty()) {
        rule.application.type = ApplicationMatch::Type::PATH;
        rule.application.path = appPath;
    }

    if (port != 0) {
        rule.remotePorts.push_back(PortRange(port));
    }

    return rule;
}

// ============================================================================
// ApplicationNetworkStats METHODS
// ============================================================================

void ApplicationNetworkStats::Reset() noexcept {
    connectionsAllowed.store(0, std::memory_order_relaxed);
    connectionsBlocked.store(0, std::memory_order_relaxed);
    bytesIn.store(0, std::memory_order_relaxed);
    bytesOut.store(0, std::memory_order_relaxed);
}

// ============================================================================
// FirewallManagerConfig FACTORY METHODS
// ============================================================================

FirewallManagerConfig FirewallManagerConfig::CreateDefault() noexcept {
    return FirewallManagerConfig{};
}

FirewallManagerConfig FirewallManagerConfig::CreateHighSecurity() noexcept {
    FirewallManagerConfig config;
    config.enabled = true;
    config.enableIPFiltering = true;
    config.enablePortFiltering = true;
    config.enableApplicationControl = true;
    config.enableGeoBlocking = true;
    config.stealthMode = StealthMode::ENHANCED;

    config.defaultInboundAction = RuleAction::BLOCK;
    config.defaultOutboundAction = RuleAction::ALLOW;

    config.blockUnknownApplications = true;
    config.allowSignedApplications = true;

    config.logBlockedOnly = true;
    config.protectShadowStrikeRules = true;
    config.preventRuleBypass = true;

    return config;
}

FirewallManagerConfig FirewallManagerConfig::CreatePermissive() noexcept {
    FirewallManagerConfig config;
    config.enabled = true;
    config.defaultInboundAction = RuleAction::ALLOW;
    config.defaultOutboundAction = RuleAction::ALLOW;
    config.blockUnknownApplications = false;
    config.stealthMode = StealthMode::OFF;
    config.logBlockedOnly = true;
    return config;
}

FirewallManagerConfig FirewallManagerConfig::CreateServerOptimized() noexcept {
    FirewallManagerConfig config;
    config.enabled = true;
    config.defaultInboundAction = RuleAction::BLOCK;
    config.defaultOutboundAction = RuleAction::ALLOW;
    config.enableApplicationControl = false;  // Performance
    config.logAllConnections = false;
    config.logBlockedOnly = true;
    config.enableRuleCache = true;
    config.maxRules = 50000;
    return config;
}

// ============================================================================
// FirewallStatistics METHODS
// ============================================================================

void FirewallStatistics::Reset() noexcept {
    totalConnections.store(0, std::memory_order_relaxed);
    allowedConnections.store(0, std::memory_order_relaxed);
    blockedConnections.store(0, std::memory_order_relaxed);
    loggedConnections.store(0, std::memory_order_relaxed);
    inboundAllowed.store(0, std::memory_order_relaxed);
    inboundBlocked.store(0, std::memory_order_relaxed);
    outboundAllowed.store(0, std::memory_order_relaxed);
    outboundBlocked.store(0, std::memory_order_relaxed);
    ruleEvaluations.store(0, std::memory_order_relaxed);
    ruleMatches.store(0, std::memory_order_relaxed);
    activeRuleCount.store(0, std::memory_order_relaxed);
    wfpFilterCount.store(0, std::memory_order_relaxed);
    geoBlockedConnections.store(0, std::memory_order_relaxed);
    appBlockedConnections.store(0, std::memory_order_relaxed);
    portBlockedConnections.store(0, std::memory_order_relaxed);
    bytesAllowed.store(0, std::memory_order_relaxed);
    bytesBlocked.store(0, std::memory_order_relaxed);
    avgEvaluationTimeNs.store(0, std::memory_order_relaxed);
    maxEvaluationTimeNs.store(0, std::memory_order_relaxed);
    wfpErrors.store(0, std::memory_order_relaxed);
    ruleErrors.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for FirewallManager.
 */
class FirewallManagerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_rulesMutex;
    mutable std::shared_mutex m_statsMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_geoMutex;
    mutable std::mutex m_wfpMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_lockdownActive{false};

    // Configuration
    FirewallManagerConfig m_config{};

    // Statistics
    FirewallStatistics m_stats{};

    // Rules (ordered by priority)
    std::map<uint64_t, FirewallRule> m_rules;  // ruleId -> rule
    std::atomic<uint64_t> m_nextRuleId{1};

    // Application tracking
    std::unordered_map<std::wstring, ApplicationNetworkStats> m_appStats;

    // Geo-blocking
    std::unordered_map<std::string, bool> m_blockedCountries;  // countryCode -> blocked
    std::unordered_map<std::wstring, GeoIPEntry> m_geoCache;  // IP -> GeoInfo

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, ConnectionAttemptCallback> m_connectionCallbacks;
    std::unordered_map<uint64_t, RuleMatchCallback> m_ruleMatchCallbacks;
    std::unordered_map<uint64_t, RuleChangeCallback> m_ruleChangeCallbacks;
    std::unordered_map<uint64_t, BlockedConnectionCallback> m_blockedCallbacks;
    std::unordered_map<uint64_t, ApplicationNetworkCallback> m_appCallbacks;

    // WFP handles
    HANDLE m_wfpEngineHandle{nullptr};
    GUID m_providerGuid{};
    GUID m_sublayerGuid{};

    // Stealth mode rules
    std::vector<uint64_t> m_stealthRuleIds;

    // Lockdown rules (separate from stealth)
    std::vector<uint64_t> m_lockdownRuleIds;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const FirewallManagerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"Network", L"FirewallManager::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"Network", L"FirewallManager::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Initialize WFP
            if (!InitializeWFP()) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to initialize WFP");
                return false;
            }

            // Load geo-blocking configuration
            if (config.enableGeoBlocking) {
                for (const auto& country : config.blockedCountries) {
                    m_blockedCountries[country] = true;
                }
            }

            // Reset statistics
            m_stats.Reset();

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(L"Network", L"FirewallManager::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool Start() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Cannot start - not initialized");
            return false;
        }

        if (m_running.exchange(true, std::memory_order_acquire)) {
            SS_LOG_WARN(L"Network", L"FirewallManager: Already running");
            return true;
        }

        try {
            SS_LOG_INFO(L"Network", L"FirewallManager: Starting firewall enforcement");

            // Apply initial rules to WFP
            if (!ApplyAllRulesToWFP()) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to apply rules to WFP");
                m_running.store(false, std::memory_order_release);
                return false;
            }

            // Apply stealth mode
            if (m_config.stealthMode != StealthMode::OFF) {
                ApplyStealthModeImpl(m_config.stealthMode);
            }

            SS_LOG_INFO(L"Network", L"FirewallManager: Firewall enforcement started");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Start exception: {}", e.what());
            m_running.store(false, std::memory_order_release);
            return false;
        }
    }

    void Stop() {
        if (!m_running.exchange(false, std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"Network", L"FirewallManager: Stopping firewall enforcement");

        // Remove all WFP filters
        RemoveAllWFPFilters();

        SS_LOG_INFO(L"Network", L"FirewallManager: Firewall enforcement stopped");
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"Network", L"FirewallManager::Impl: Shutting down");

        Stop();

        // Close WFP engine
        if (m_wfpEngineHandle != nullptr) {
            FwpmEngineClose0(m_wfpEngineHandle);
            m_wfpEngineHandle = nullptr;
        }

        // Clear all data structures
        {
            std::unique_lock rulesLock(m_rulesMutex);
            m_rules.clear();
        }

        {
            std::unique_lock geoLock(m_geoMutex);
            m_blockedCountries.clear();
            m_geoCache.clear();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_connectionCallbacks.clear();
            m_ruleMatchCallbacks.clear();
            m_ruleChangeCallbacks.clear();
            m_blockedCallbacks.clear();
            m_appCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(L"Network", L"FirewallManager::Impl: Shutdown complete");
    }

    // ========================================================================
    // WFP INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool InitializeWFP() {
        std::unique_lock lock(m_wfpMutex);

        try {
            SS_LOG_DEBUG(L"Network", L"FirewallManager: Initializing WFP engine");

            // Open WFP engine
            FWPM_SESSION0 session{};
            session.displayData.name = const_cast<wchar_t*>(m_config.providerName.c_str());
            session.displayData.description = const_cast<wchar_t*>(L"ShadowStrike Firewall Session");

            DWORD result = FwpmEngineOpen0(
                nullptr,
                RPC_C_AUTHN_WINNT,
                nullptr,
                &session,
                &m_wfpEngineHandle
            );

            if (result != ERROR_SUCCESS) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: FwpmEngineOpen0 failed: {}", result);
                m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
                return false;
            }

            // Create provider GUID
            CoCreateGuid(&m_providerGuid);
            CoCreateGuid(&m_sublayerGuid);

            // Register provider
            if (!RegisterWFPProvider()) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to register WFP provider");
                return false;
            }

            // Register sublayer
            if (!RegisterWFPSublayer()) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to register WFP sublayer");
                return false;
            }

            SS_LOG_INFO(L"Network", L"FirewallManager: WFP engine initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: WFP initialization exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool RegisterWFPProvider() {
        FWPM_PROVIDER0 provider{};
        provider.providerKey = m_providerGuid;
        provider.displayData.name = const_cast<wchar_t*>(m_config.providerName.c_str());
        provider.displayData.description = const_cast<wchar_t*>(L"ShadowStrike Firewall Provider");
        provider.flags = 0;

        DWORD result = FwpmProviderAdd0(m_wfpEngineHandle, &provider, nullptr);
        if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: FwpmProviderAdd0 failed: {}", result);
            m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        return true;
    }

    [[nodiscard]] bool RegisterWFPSublayer() {
        FWPM_SUBLAYER0 sublayer{};
        sublayer.subLayerKey = m_sublayerGuid;
        sublayer.displayData.name = const_cast<wchar_t*>(m_config.sublayerName.c_str());
        sublayer.displayData.description = const_cast<wchar_t*>(L"ShadowStrike Filter Sublayer");
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;  // High priority

        DWORD result = FwpmSubLayerAdd0(m_wfpEngineHandle, &sublayer, nullptr);
        if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: FwpmSubLayerAdd0 failed: {}", result);
            m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        return true;
    }

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    [[nodiscard]] uint64_t AddRuleImpl(const FirewallRule& rule) {
        std::unique_lock lock(m_rulesMutex);

        try {
            // Validate rule
            if (!rule.IsValid()) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Invalid rule");
                m_stats.ruleErrors.fetch_add(1, std::memory_order_relaxed);
                return 0;
            }

            // Check limits
            if (m_rules.size() >= m_config.maxRules) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Maximum rules reached");
                return 0;
            }

            // Create new rule with ID
            FirewallRule newRule = rule;
            newRule.ruleId = m_nextRuleId.fetch_add(1, std::memory_order_relaxed);
            newRule.createdAt = system_clock::now();
            newRule.modifiedAt = newRule.createdAt;

            // Add to WFP if running
            if (m_running.load(std::memory_order_acquire)) {
                if (!AddRuleToWFP(newRule)) {
                    SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to add rule to WFP");
                    return 0;
                }
            }

            // Store rule
            m_rules[newRule.ruleId] = newRule;
            m_stats.activeRuleCount.store(
                static_cast<uint32_t>(m_rules.size()), std::memory_order_relaxed);

            SS_LOG_INFO(L"Network", L"FirewallManager: Rule {} added: {}", newRule.ruleId,
                newRule.name);

            // Invoke callbacks
            InvokeRuleChangeCallbacks(newRule, true);

            return newRule.ruleId;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: AddRule exception: {}", e.what());
            m_stats.ruleErrors.fetch_add(1, std::memory_order_relaxed);
            return 0;
        }
    }

    bool RemoveRuleImpl(uint64_t ruleId) {
        std::unique_lock lock(m_rulesMutex);

        auto it = m_rules.find(ruleId);
        if (it == m_rules.end()) {
            SS_LOG_WARN(L"Network", L"FirewallManager: Rule {} not found", ruleId);
            return false;
        }

        const auto& rule = it->second;

        // Check if locked
        if (rule.isLocked) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Cannot remove locked rule {}", ruleId);
            return false;
        }

        // Remove from WFP
        if (m_running.load(std::memory_order_acquire)) {
            RemoveRuleFromWFP(rule);
        }

        // Invoke callbacks before removal
        InvokeRuleChangeCallbacks(rule, false);

        // Remove from map
        m_rules.erase(it);
        m_stats.activeRuleCount.store(
            static_cast<uint32_t>(m_rules.size()), std::memory_order_relaxed);

        SS_LOG_INFO(L"Network", L"FirewallManager: Rule {} removed", ruleId);
        return true;
    }

    bool UpdateRuleImpl(uint64_t ruleId, const FirewallRule& rule) {
        std::unique_lock lock(m_rulesMutex);

        auto it = m_rules.find(ruleId);
        if (it == m_rules.end()) {
            SS_LOG_WARN(L"Network", L"FirewallManager: Rule {} not found", ruleId);
            return false;
        }

        // Check if locked
        if (it->second.isLocked) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Cannot update locked rule {}", ruleId);
            return false;
        }

        // Remove old WFP filter
        if (m_running.load(std::memory_order_acquire)) {
            RemoveRuleFromWFP(it->second);
        }

        // Update rule
        FirewallRule updatedRule = rule;
        updatedRule.ruleId = ruleId;
        updatedRule.createdAt = it->second.createdAt;
        updatedRule.modifiedAt = system_clock::now();

        // Add new WFP filter
        if (m_running.load(std::memory_order_acquire)) {
            if (!AddRuleToWFP(updatedRule)) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Failed to update rule in WFP");
                return false;
            }
        }

        it->second = updatedRule;

        SS_LOG_INFO(L"Network", L"FirewallManager: Rule {} updated", ruleId);
        return true;
    }

    [[nodiscard]] std::optional<FirewallRule> GetRuleImpl(uint64_t ruleId) const {
        std::shared_lock lock(m_rulesMutex);

        auto it = m_rules.find(ruleId);
        if (it != m_rules.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] std::vector<FirewallRule> GetAllRulesImpl(bool enabledOnly) const {
        std::shared_lock lock(m_rulesMutex);

        std::vector<FirewallRule> result;
        result.reserve(m_rules.size());

        for (const auto& [id, rule] : m_rules) {
            if (!enabledOnly || rule.isEnabled) {
                result.push_back(rule);
            }
        }

        return result;
    }

    // ========================================================================
    // WFP FILTER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddRuleToWFP(FirewallRule& rule) {
        std::unique_lock lock(m_wfpMutex);

        if (m_wfpEngineHandle == nullptr) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: WFP engine not open, cannot add filter");
            m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        try {
            // Build WFP filter for IPv4
            if (rule.applyToIPv4) {
                FWPM_FILTER0 filter{};
                filter.displayData.name = const_cast<wchar_t*>(rule.name.c_str());
                filter.displayData.description = const_cast<wchar_t*>(rule.description.c_str());
                filter.providerKey = &m_providerGuid;
                filter.subLayerKey = m_sublayerGuid;
                filter.weight.type = FWP_UINT32;
                filter.weight.uint32 = rule.priority;
                filter.flags = (rule.persistence == RulePersistence::PERSISTENT)
                    ? FWPM_FILTER_FLAG_PERSISTENT : 0;
                if (rule.persistence == RulePersistence::BOOT_TIME) {
                    filter.flags |= FWPM_FILTER_FLAG_BOOTTIME;
                }

                filter.action.type = (rule.action == RuleAction::ALLOW ||
                                      rule.action == RuleAction::ALLOW_BYPASS)
                    ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

                // Select WFP layer based on direction
                if (rule.direction == RuleDirection::OUTBOUND || rule.direction == RuleDirection::BOTH) {
                    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                } else {
                    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
                }

                // Build conditions
                std::vector<FWPM_FILTER_CONDITION0> conditions;
                FWP_V4_ADDR_AND_MASK addrMask{};
                FWP_RANGE0 portRange{};

                // IP condition
                if (rule.remoteAddress.type == IPAddressMatch::Type::SINGLE) {
                    FWPM_FILTER_CONDITION0 cond{};
                    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.type = FWP_UINT32;
                    uint32_t addr = 0;
                    std::memcpy(&addr, rule.remoteAddress.address.data(), 4);
                    cond.conditionValue.uint32 = ntohl(addr);
                    conditions.push_back(cond);
                } else if (rule.remoteAddress.type == IPAddressMatch::Type::CIDR) {
                    FWPM_FILTER_CONDITION0 cond{};
                    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.type = FWP_V4_ADDR_MASK;
                    std::memcpy(&addrMask.addr, rule.remoteAddress.address.data(), 4);
                    addrMask.addr = ntohl(addrMask.addr);
                    addrMask.mask = rule.remoteAddress.prefixLength >= 32 ? 0xFFFFFFFF :
                        ~((1u << (32 - rule.remoteAddress.prefixLength)) - 1);
                    cond.conditionValue.v4AddrMask = &addrMask;
                    conditions.push_back(cond);
                }

                // Port condition
                if (!rule.remotePorts.empty()) {
                    FWPM_FILTER_CONDITION0 cond{};
                    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    if (rule.remotePorts[0].IsSinglePort()) {
                        cond.matchType = FWP_MATCH_EQUAL;
                        cond.conditionValue.type = FWP_UINT16;
                        cond.conditionValue.uint16 = rule.remotePorts[0].start;
                    } else {
                        cond.matchType = FWP_MATCH_RANGE;
                        cond.conditionValue.type = FWP_RANGE_TYPE;
                        portRange.valueLow.type = FWP_UINT16;
                        portRange.valueLow.uint16 = rule.remotePorts[0].start;
                        portRange.valueHigh.type = FWP_UINT16;
                        portRange.valueHigh.uint16 = rule.remotePorts[0].end;
                        cond.conditionValue.rangeValue = &portRange;
                    }
                    conditions.push_back(cond);
                }

                // Protocol condition
                if (rule.protocol != RuleProtocol::ANY) {
                    FWPM_FILTER_CONDITION0 cond{};
                    cond.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.type = FWP_UINT8;
                    cond.conditionValue.uint8 = static_cast<uint8_t>(rule.protocol);
                    conditions.push_back(cond);
                }

                // Application condition
                FWP_BYTE_BLOB appBlob{};
                std::wstring appIdBuf;
                if (rule.application.type == ApplicationMatch::Type::PATH &&
                    !rule.application.path.empty()) {
                    FWPM_FILTER_CONDITION0 cond{};
                    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    cond.matchType = FWP_MATCH_EQUAL;
                    cond.conditionValue.type = FWP_BYTE_BLOB_TYPE;
                    // WFP requires the app path in a device-path format via FwpmGetAppIdFromFileName0
                    FWP_BYTE_BLOB* appId = nullptr;
                    DWORD appIdResult = FwpmGetAppIdFromFileName0(
                        rule.application.path.c_str(), &appId);
                    if (appIdResult == ERROR_SUCCESS && appId != nullptr) {
                        cond.conditionValue.byteBlob = appId;
                        conditions.push_back(cond);
                    } else {
                        SS_LOG_WARN(L"Network",
                            L"FirewallManager: FwpmGetAppIdFromFileName0 failed for {}: {}",
                            rule.application.path, appIdResult);
                    }
                }

                filter.numFilterConditions = static_cast<UINT32>(conditions.size());
                filter.filterCondition = conditions.empty() ? nullptr : conditions.data();

                UINT64 filterId = 0;
                DWORD addResult = FwpmFilterAdd0(
                    m_wfpEngineHandle, &filter, nullptr, &filterId);

                // Cleanup app ID blob
                if (rule.application.type == ApplicationMatch::Type::PATH &&
                    !conditions.empty()) {
                    for (auto& c : conditions) {
                        if (c.fieldKey == FWPM_CONDITION_ALE_APP_ID &&
                            c.conditionValue.byteBlob != nullptr) {
                            FwpmFreeMemory0(reinterpret_cast<void**>(&c.conditionValue.byteBlob));
                        }
                    }
                }

                if (addResult != ERROR_SUCCESS) {
                    SS_LOG_ERROR(L"Network",
                        L"FirewallManager: FwpmFilterAdd0 failed for rule {}: {}",
                        rule.ruleId, addResult);
                    m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
                    return false;
                }

                rule.wfpFilterId = filterId;
                m_stats.wfpFilterCount.fetch_add(1, std::memory_order_relaxed);

                // Also add inbound filter if direction is BOTH
                if (rule.direction == RuleDirection::BOTH) {
                    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
                    UINT64 filterId2 = 0;
                    DWORD addResult2 = FwpmFilterAdd0(
                        m_wfpEngineHandle, &filter, nullptr, &filterId2);
                    if (addResult2 == ERROR_SUCCESS) {
                        m_stats.wfpFilterCount.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // Build WFP filter for IPv6
            if (rule.applyToIPv6 && rule.remoteAddress.isIPv6 &&
                rule.remoteAddress.type == IPAddressMatch::Type::SINGLE) {
                FWPM_FILTER0 filter6{};
                filter6.displayData.name = const_cast<wchar_t*>(rule.name.c_str());
                filter6.displayData.description = const_cast<wchar_t*>(rule.description.c_str());
                filter6.providerKey = &m_providerGuid;
                filter6.subLayerKey = m_sublayerGuid;
                filter6.weight.type = FWP_UINT32;
                filter6.weight.uint32 = rule.priority;

                filter6.action.type = (rule.action == RuleAction::ALLOW ||
                                       rule.action == RuleAction::ALLOW_BYPASS)
                    ? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;

                if (rule.direction == RuleDirection::OUTBOUND || rule.direction == RuleDirection::BOTH) {
                    filter6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
                } else {
                    filter6.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
                }

                FWPM_FILTER_CONDITION0 cond{};
                cond.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                cond.matchType = FWP_MATCH_EQUAL;
                cond.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
                FWP_BYTE_ARRAY16 addr6{};
                std::memcpy(addr6.byteArray16, rule.remoteAddress.address.data(), 16);
                cond.conditionValue.byteArray16 = &addr6;

                filter6.numFilterConditions = 1;
                filter6.filterCondition = &cond;

                UINT64 filterId6 = 0;
                DWORD addResult6 = FwpmFilterAdd0(
                    m_wfpEngineHandle, &filter6, nullptr, &filterId6);
                if (addResult6 == ERROR_SUCCESS) {
                    rule.wfpFilterId6 = filterId6;
                    m_stats.wfpFilterCount.fetch_add(1, std::memory_order_relaxed);
                } else {
                    SS_LOG_WARN(L"Network",
                        L"FirewallManager: IPv6 filter add failed for rule {}: {}",
                        rule.ruleId, addResult6);
                }
            }

            SS_LOG_DEBUG(L"Network", L"FirewallManager: Rule {} added to WFP (filter ID: {})",
                rule.ruleId, rule.wfpFilterId);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: AddRuleToWFP exception: {}", e.what());
            m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    void RemoveRuleFromWFP(const FirewallRule& rule) {
        std::unique_lock lock(m_wfpMutex);

        if (m_wfpEngineHandle == nullptr) {
            return;
        }

        try {
            if (rule.wfpFilterId != 0) {
                DWORD result = FwpmFilterDeleteById0(m_wfpEngineHandle, rule.wfpFilterId);
                if (result == ERROR_SUCCESS || result == FWP_E_FILTER_NOT_FOUND) {
                    m_stats.wfpFilterCount.fetch_sub(1, std::memory_order_relaxed);
                } else {
                    SS_LOG_WARN(L"Network",
                        L"FirewallManager: FwpmFilterDeleteById0 failed for rule {}: {}",
                        rule.ruleId, result);
                    m_stats.wfpErrors.fetch_add(1, std::memory_order_relaxed);
                }
                SS_LOG_DEBUG(L"Network", L"FirewallManager: Rule {} removed from WFP", rule.ruleId);
            }

            if (rule.wfpFilterId6 != 0) {
                DWORD result6 = FwpmFilterDeleteById0(m_wfpEngineHandle, rule.wfpFilterId6);
                if (result6 == ERROR_SUCCESS || result6 == FWP_E_FILTER_NOT_FOUND) {
                    m_stats.wfpFilterCount.fetch_sub(1, std::memory_order_relaxed);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: RemoveRuleFromWFP exception: {}", e.what());
        }
    }

    [[nodiscard]] bool ApplyAllRulesToWFP() {
        std::unique_lock lock(m_rulesMutex);

        size_t successCount = 0;
        size_t enabledCount = 0;
        for (auto& [id, rule] : m_rules) {
            if (rule.isEnabled) {
                enabledCount++;
                if (AddRuleToWFP(rule)) {
                    successCount++;
                }
            }
        }

        SS_LOG_INFO(L"Network", L"FirewallManager: Applied {}/{} rules to WFP",
            successCount, enabledCount);
        return successCount == enabledCount;
    }

    void RemoveAllWFPFilters() {
        std::unique_lock lock(m_rulesMutex);

        for (const auto& [id, rule] : m_rules) {
            RemoveRuleFromWFP(rule);
        }

        SS_LOG_INFO(L"Network", L"FirewallManager: All WFP filters removed");
    }

    // ========================================================================
    // APPLICATION CONTROL
    // ========================================================================

    [[nodiscard]] uint64_t BlockApplicationImpl(const std::wstring& appPath, RuleDirection direction) {
        auto rule = FirewallRule::CreateBlockApp(appPath);
        rule.direction = direction;
        rule.name = std::format(L"Block {}", fs::path(appPath).filename().wstring());

        return AddRuleImpl(rule);
    }

    [[nodiscard]] uint64_t AllowApplicationImpl(const std::wstring& appPath, RuleDirection direction) {
        auto rule = FirewallRule::CreateAllowApp(appPath);
        rule.direction = direction;
        rule.name = std::format(L"Allow {}", fs::path(appPath).filename().wstring());

        return AddRuleImpl(rule);
    }

    [[nodiscard]] bool IsApplicationBlockedImpl(const std::wstring& appPath) const {
        std::shared_lock lock(m_rulesMutex);

        for (const auto& [id, rule] : m_rules) {
            if (rule.isEnabled &&
                rule.action == RuleAction::BLOCK &&
                rule.type == RuleType::APPLICATION &&
                rule.application.type == ApplicationMatch::Type::PATH &&
                StringUtils::IEquals(rule.application.path, appPath)) {
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // IP BLOCKING
    // ========================================================================

    [[nodiscard]] uint64_t BlockIPImpl(const std::wstring& ip, RuleDirection direction, uint32_t durationMs) {
        auto rule = FirewallRule::CreateBlockIP(ip, direction);

        if (durationMs > 0) {
            rule.isTemporary = true;
            rule.expiresAt = system_clock::now() + milliseconds(durationMs);
            rule.persistence = RulePersistence::TEMPORARY;
        }

        return AddRuleImpl(rule);
    }

    bool UnblockIPImpl(const std::wstring& ip) {
        std::unique_lock lock(m_rulesMutex);

        std::vector<uint64_t> toRemove;

        for (const auto& [id, rule] : m_rules) {
            if (rule.type == RuleType::IP &&
                rule.remoteAddress.type == IPAddressMatch::Type::SINGLE) {

                bool isIPv6 = false;
                auto parsedIP = ParseIPAddress(ip, isIPv6);

                if (parsedIP && std::equal(rule.remoteAddress.address.begin(),
                                          rule.remoteAddress.address.end(),
                                          parsedIP->begin())) {
                    toRemove.push_back(id);
                }
            }
        }

        lock.unlock();

        for (uint64_t ruleId : toRemove) {
            RemoveRuleImpl(ruleId);
        }

        return !toRemove.empty();
    }

    // ========================================================================
    // PORT MANAGEMENT
    // ========================================================================

    [[nodiscard]] uint64_t BlockPortImpl(uint16_t port, RuleProtocol protocol, RuleDirection direction) {
        auto rule = FirewallRule::CreateBlockPort(port, protocol, direction);
        return AddRuleImpl(rule);
    }

    bool UnblockPortImpl(uint16_t port, RuleProtocol protocol) {
        std::unique_lock lock(m_rulesMutex);

        std::vector<uint64_t> toRemove;

        for (const auto& [id, rule] : m_rules) {
            if (rule.type == RuleType::PORT &&
                rule.protocol == protocol &&
                !rule.remotePorts.empty() &&
                rule.remotePorts[0].Contains(port)) {
                toRemove.push_back(id);
            }
        }

        lock.unlock();

        for (uint64_t ruleId : toRemove) {
            RemoveRuleImpl(ruleId);
        }

        return !toRemove.empty();
    }

    // ========================================================================
    // GEO-BLOCKING
    // ========================================================================

    bool BlockCountryImpl(const std::string& countryCode, RuleDirection direction) {
        std::unique_lock lock(m_geoMutex);

        m_blockedCountries[countryCode] = true;

        SS_LOG_INFO(L"Network", L"FirewallManager: Country {} blocked", countryCode);
        return true;
    }

    bool UnblockCountryImpl(const std::string& countryCode) {
        std::unique_lock lock(m_geoMutex);

        auto removed = m_blockedCountries.erase(countryCode) > 0;
        if (removed) {
            SS_LOG_INFO(L"Network", L"FirewallManager: Country {} unblocked", countryCode);
        }

        return removed;
    }

    [[nodiscard]] std::optional<GeoIPEntry> GetGeoInfoImpl(const std::wstring& ip) const {
        std::shared_lock lock(m_geoMutex);

        // Check cache
        auto it = m_geoCache.find(ip);
        if (it != m_geoCache.end()) {
            return it->second;
        }

        // In real implementation, would query MaxMind GeoIP database
        // For now, return empty
        return std::nullopt;
    }

    // ========================================================================
    // STEALTH MODE
    // ========================================================================

    bool ApplyStealthModeImpl(StealthMode mode) {
        try {
            // Collect existing stealth rule IDs to remove (under lock)
            std::vector<uint64_t> oldStealthIds;
            {
                std::unique_lock lock(m_rulesMutex);
                oldStealthIds = m_stealthRuleIds;
                m_stealthRuleIds.clear();
            }

            // Remove existing stealth rules (lock-free — RemoveRuleImpl handles its own locking)
            for (uint64_t ruleId : oldStealthIds) {
                RemoveRuleImpl(ruleId);
            }

            if (mode == StealthMode::OFF) {
                return true;
            }

            // BASIC: Block ICMP echo requests
            if (mode >= StealthMode::BASIC) {
                FirewallRule icmpRule;
                icmpRule.name = L"Stealth: Block ICMP Echo";
                icmpRule.description = L"Stealth mode ICMP blocking";
                icmpRule.type = RuleType::COMBINED;
                icmpRule.action = RuleAction::BLOCK;
                icmpRule.direction = RuleDirection::INBOUND;
                icmpRule.protocol = RuleProtocol::ICMP;
                icmpRule.priority = FirewallConstants::PRIORITY_SYSTEM;
                icmpRule.isBuiltIn = true;
                icmpRule.isLocked = true;

                uint64_t ruleId = AddRuleImpl(icmpRule);
                if (ruleId != 0) {
                    std::unique_lock lock(m_rulesMutex);
                    m_stealthRuleIds.push_back(ruleId);
                }
            }

            // ENHANCED: Drop unsolicited inbound
            if (mode >= StealthMode::ENHANCED) {
                FirewallRule dropUnsolicited;
                dropUnsolicited.name = L"Stealth: Drop Unsolicited Inbound";
                dropUnsolicited.description = L"Stealth mode - drop unsolicited inbound traffic";
                dropUnsolicited.type = RuleType::COMBINED;
                dropUnsolicited.action = RuleAction::BLOCK_SILENT;
                dropUnsolicited.direction = RuleDirection::INBOUND;
                dropUnsolicited.protocol = RuleProtocol::ANY;
                dropUnsolicited.priority = FirewallConstants::PRIORITY_SYSTEM;
                dropUnsolicited.isBuiltIn = true;
                dropUnsolicited.isLocked = true;

                uint64_t ruleId = AddRuleImpl(dropUnsolicited);
                if (ruleId != 0) {
                    std::unique_lock lock(m_rulesMutex);
                    m_stealthRuleIds.push_back(ruleId);
                }

                // Block ICMPv6 as well
                FirewallRule icmpv6Rule;
                icmpv6Rule.name = L"Stealth: Block ICMPv6";
                icmpv6Rule.description = L"Stealth mode ICMPv6 blocking";
                icmpv6Rule.type = RuleType::COMBINED;
                icmpv6Rule.action = RuleAction::BLOCK;
                icmpv6Rule.direction = RuleDirection::INBOUND;
                icmpv6Rule.protocol = RuleProtocol::ICMPv6;
                icmpv6Rule.priority = FirewallConstants::PRIORITY_SYSTEM;
                icmpv6Rule.isBuiltIn = true;
                icmpv6Rule.isLocked = true;
                icmpv6Rule.applyToIPv4 = false;
                icmpv6Rule.applyToIPv6 = true;

                ruleId = AddRuleImpl(icmpv6Rule);
                if (ruleId != 0) {
                    std::unique_lock lock(m_rulesMutex);
                    m_stealthRuleIds.push_back(ruleId);
                }
            }

            SS_LOG_INFO(L"Network", L"FirewallManager: Stealth mode set to {}", static_cast<int>(mode));
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: ApplyStealthMode exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // LOCKDOWN
    // ========================================================================

    bool EnableLockdownImpl(std::wstring_view reason) {
        if (m_lockdownActive.exchange(true, std::memory_order_acquire)) {
            SS_LOG_WARN(L"Network", L"FirewallManager: Lockdown already active");
            return true;
        }

        try {
            SS_LOG_WARN(L"Network", L"FirewallManager: EMERGENCY LOCKDOWN ACTIVATED - Reason: {}",
                std::wstring(reason));

            // Create lockdown rule blocking ALL outbound traffic
            FirewallRule lockdownOutbound;
            lockdownOutbound.name = L"EMERGENCY LOCKDOWN - OUTBOUND";
            lockdownOutbound.description = std::format(L"Emergency lockdown: {}", reason);
            lockdownOutbound.type = RuleType::COMBINED;
            lockdownOutbound.action = RuleAction::BLOCK;
            lockdownOutbound.direction = RuleDirection::OUTBOUND;
            lockdownOutbound.priority = FirewallConstants::PRIORITY_EMERGENCY;
            lockdownOutbound.isBuiltIn = true;
            lockdownOutbound.isLocked = true;
            lockdownOutbound.isTemporary = true;

            uint64_t outRuleId = AddRuleImpl(lockdownOutbound);
            if (outRuleId != 0) {
                std::unique_lock lock(m_rulesMutex);
                m_lockdownRuleIds.push_back(outRuleId);
            }

            // Also block ALL inbound traffic
            FirewallRule lockdownInbound;
            lockdownInbound.name = L"EMERGENCY LOCKDOWN - INBOUND";
            lockdownInbound.description = std::format(L"Emergency lockdown: {}", reason);
            lockdownInbound.type = RuleType::COMBINED;
            lockdownInbound.action = RuleAction::BLOCK;
            lockdownInbound.direction = RuleDirection::INBOUND;
            lockdownInbound.priority = FirewallConstants::PRIORITY_EMERGENCY;
            lockdownInbound.isBuiltIn = true;
            lockdownInbound.isLocked = true;
            lockdownInbound.isTemporary = true;

            uint64_t inRuleId = AddRuleImpl(lockdownInbound);
            if (inRuleId != 0) {
                std::unique_lock lock(m_rulesMutex);
                m_lockdownRuleIds.push_back(inRuleId);
            }

            return (outRuleId != 0 || inRuleId != 0);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: EnableLockdown exception: {}", e.what());
            m_lockdownActive.store(false, std::memory_order_release);
            return false;
        }
    }

    bool DisableLockdownImpl() {
        if (!m_lockdownActive.exchange(false, std::memory_order_acquire)) {
            return true;
        }

        SS_LOG_INFO(L"Network", L"FirewallManager: Lockdown deactivated");

        // Collect lockdown rule IDs under lock, then remove outside lock
        std::vector<uint64_t> toRemove;
        {
            std::unique_lock lock(m_rulesMutex);
            toRemove = m_lockdownRuleIds;
            m_lockdownRuleIds.clear();
        }

        // Lockdown rules are marked isLocked=true, temporarily unlock them for removal
        for (uint64_t ruleId : toRemove) {
            {
                std::unique_lock lock(m_rulesMutex);
                auto it = m_rules.find(ruleId);
                if (it != m_rules.end()) {
                    it->second.isLocked = false;
                }
            }
            RemoveRuleImpl(ruleId);
        }

        return true;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeRuleChangeCallbacks(const FirewallRule& rule, bool isAdded) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_ruleChangeCallbacks) {
            try {
                callback(rule, isAdded);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Rule change callback exception: {}", e.what());
            }
        }
    }

    void InvokeBlockedConnectionCallbacks(const ConnectionAttempt& attempt, std::wstring_view reason) {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_blockedCallbacks) {
            try {
                callback(attempt, reason);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Blocked connection callback exception: {}", e.what());
            }
        }
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnosticsImpl() const {
        try {
            SS_LOG_INFO(L"Network", L"FirewallManager: Running diagnostics");

            // Check initialization
            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Not initialized");
                return false;
            }

            // Check WFP engine
            if (m_wfpEngineHandle == nullptr) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: WFP engine not initialized");
                return false;
            }

            // Check configuration
            if (!m_config.enabled) {
                SS_LOG_WARN(L"Network", L"FirewallManager: Firewall is disabled");
            }

            // Check running state
            if (!m_running.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"Network", L"FirewallManager: Not running");
            }

            // Check rule count
            {
                std::shared_lock lock(m_rulesMutex);
                SS_LOG_INFO(L"Network", L"FirewallManager: {} active rules", m_rules.size());
            }

            SS_LOG_INFO(L"Network", L"FirewallManager: Diagnostics passed");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Diagnostics exception: {}", e.what());
            return false;
        }
    }

    bool ExportDiagnosticsImpl(const std::wstring& outputPath) const {
        try {
            std::ofstream file(outputPath);
            if (!file) {
                SS_LOG_ERROR(L"Network", L"FirewallManager: Cannot create diagnostics file");
                return false;
            }

            file << "=== ShadowStrike Firewall Manager Diagnostics ===\n\n";

            // Configuration
            file << "CONFIGURATION:\n";
            file << "  Enabled: " << (m_config.enabled ? "Yes" : "No") << "\n";
            file << "  Running: " << (m_running.load() ? "Yes" : "No") << "\n";
            file << "  Lockdown: " << (m_lockdownActive.load() ? "YES" : "No") << "\n";
            file << "  Stealth Mode: " << static_cast<int>(m_config.stealthMode) << "\n\n";

            // Statistics
            file << "STATISTICS:\n";
            file << "  Total Connections: " << m_stats.totalConnections.load() << "\n";
            file << "  Allowed: " << m_stats.allowedConnections.load() << "\n";
            file << "  Blocked: " << m_stats.blockedConnections.load() << "\n";
            file << "  Active Rules: " << m_stats.activeRuleCount.load() << "\n";
            file << "  WFP Filters: " << m_stats.wfpFilterCount.load() << "\n";
            file << "  WFP Errors: " << m_stats.wfpErrors.load() << "\n\n";

            // Rules
            {
                std::shared_lock lock(m_rulesMutex);
                file << "ACTIVE RULES (" << m_rules.size() << "):\n";
                for (const auto& [id, rule] : m_rules) {
                    file << "  [" << id << "] " << StringUtils::ToNarrow(rule.name);
                    file << " - " << (rule.isEnabled ? "Enabled" : "Disabled") << "\n";
                }
            }

            file.close();
            SS_LOG_INFO(L"Network", L"FirewallManager: Diagnostics exported to {}",
                outputPath);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Export diagnostics exception: {}", e.what());
            return false;
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

FirewallManager& FirewallManager::Instance() {
    static FirewallManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

FirewallManager::FirewallManager()
    : m_impl(std::make_unique<FirewallManagerImpl>())
{
    SS_LOG_INFO(L"Network", L"FirewallManager: Constructor called");
}

FirewallManager::~FirewallManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Network", L"FirewallManager: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool FirewallManager::Initialize(const FirewallManagerConfig& config) {
    if (!m_impl) {
        SS_LOG_FATAL(L"Network", L"FirewallManager: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

bool FirewallManager::Start() {
    if (!m_impl) {
        SS_LOG_ERROR(L"Network", L"FirewallManager: Implementation is null");
        return false;
    }

    return m_impl->Start();
}

void FirewallManager::Stop() {
    if (m_impl) {
        m_impl->Stop();
    }
}

void FirewallManager::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool FirewallManager::IsRunning() const noexcept {
    return m_impl && m_impl->m_running.load(std::memory_order_acquire);
}

[[nodiscard]] FirewallManagerConfig FirewallManager::GetConfig() const {
    if (!m_impl) return FirewallManagerConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

bool FirewallManager::UpdateConfig(const FirewallManagerConfig& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    SS_LOG_INFO(L"Network", L"FirewallManager: Configuration updated");
    return true;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

[[nodiscard]] uint64_t FirewallManager::AddRule(const FirewallRule& rule) {
    if (!m_impl) return 0;
    return m_impl->AddRuleImpl(rule);
}

bool FirewallManager::AddRule(const FirewallRuleLegacy& rule) {
    FirewallRule newRule = static_cast<FirewallRule>(rule);
    return AddRule(newRule) != 0;
}

bool FirewallManager::RemoveRule(uint64_t ruleId) {
    if (!m_impl) return false;
    return m_impl->RemoveRuleImpl(ruleId);
}

bool FirewallManager::UpdateRule(uint64_t ruleId, const FirewallRule& rule) {
    if (!m_impl) return false;
    return m_impl->UpdateRuleImpl(ruleId, rule);
}

bool FirewallManager::SetRuleEnabled(uint64_t ruleId, bool enabled) {
    if (!m_impl) return false;

    auto rule = m_impl->GetRuleImpl(ruleId);
    if (!rule) return false;

    rule->isEnabled = enabled;
    return m_impl->UpdateRuleImpl(ruleId, *rule);
}

[[nodiscard]] std::optional<FirewallRule> FirewallManager::GetRule(uint64_t ruleId) const {
    if (!m_impl) return std::nullopt;
    return m_impl->GetRuleImpl(ruleId);
}

[[nodiscard]] std::vector<FirewallRule> FirewallManager::GetAllRules(bool enabledOnly) const {
    if (!m_impl) return {};
    return m_impl->GetAllRulesImpl(enabledOnly);
}

[[nodiscard]] std::vector<FirewallRule> FirewallManager::GetRulesByType(RuleType type) const {
    if (!m_impl) return {};

    auto allRules = m_impl->GetAllRulesImpl(false);
    std::vector<FirewallRule> result;

    std::copy_if(allRules.begin(), allRules.end(), std::back_inserter(result),
        [type](const FirewallRule& rule) { return rule.type == type; });

    return result;
}

[[nodiscard]] std::vector<FirewallRule> FirewallManager::GetRulesForApplication(
    const std::wstring& appPath
) const {
    if (!m_impl) return {};

    auto allRules = m_impl->GetAllRulesImpl(false);
    std::vector<FirewallRule> result;

    std::copy_if(allRules.begin(), allRules.end(), std::back_inserter(result),
        [&appPath](const FirewallRule& rule) {
            return rule.type == RuleType::APPLICATION &&
                   StringUtils::IEquals(rule.application.path, appPath);
        });

    return result;
}

void FirewallManager::ResetFirewall() {
    ClearTemporaryRules();
}

void FirewallManager::ClearAllRules() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_rulesMutex);

    std::vector<uint64_t> toRemove;
    for (const auto& [id, rule] : m_impl->m_rules) {
        if (!rule.isBuiltIn) {
            toRemove.push_back(id);
        }
    }

    lock.unlock();

    for (uint64_t ruleId : toRemove) {
        m_impl->RemoveRuleImpl(ruleId);
    }

    SS_LOG_INFO(L"Network", L"FirewallManager: All non-system rules cleared");
}

void FirewallManager::ClearTemporaryRules() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_rulesMutex);

    std::vector<uint64_t> toRemove;
    for (const auto& [id, rule] : m_impl->m_rules) {
        if (rule.isTemporary || rule.persistence == RulePersistence::TEMPORARY) {
            toRemove.push_back(id);
        }
    }

    lock.unlock();

    for (uint64_t ruleId : toRemove) {
        m_impl->RemoveRuleImpl(ruleId);
    }

    SS_LOG_INFO(L"Network", L"FirewallManager: Temporary rules cleared");
}

// ============================================================================
// APPLICATION CONTROL
// ============================================================================

[[nodiscard]] uint64_t FirewallManager::BlockApplication(
    const std::wstring& appPath,
    RuleDirection direction
) {
    if (!m_impl) return 0;
    return m_impl->BlockApplicationImpl(appPath, direction);
}

[[nodiscard]] uint64_t FirewallManager::AllowApplication(
    const std::wstring& appPath,
    RuleDirection direction
) {
    if (!m_impl) return 0;
    return m_impl->AllowApplicationImpl(appPath, direction);
}

uint32_t FirewallManager::RemoveApplicationRules(const std::wstring& appPath) {
    if (!m_impl) return 0;

    auto rules = GetRulesForApplication(appPath);
    uint32_t removed = 0;

    for (const auto& rule : rules) {
        if (m_impl->RemoveRuleImpl(rule.ruleId)) {
            removed++;
        }
    }

    return removed;
}

[[nodiscard]] bool FirewallManager::IsApplicationBlocked(const std::wstring& appPath) const {
    if (!m_impl) return false;
    return m_impl->IsApplicationBlockedImpl(appPath);
}

[[nodiscard]] std::optional<ApplicationNetworkStats> FirewallManager::GetApplicationStats(
    const std::wstring& appPath
) const {
    if (!m_impl) return std::nullopt;

    std::shared_lock lock(m_impl->m_statsMutex);

    auto it = m_impl->m_appStats.find(appPath);
    if (it != m_impl->m_appStats.end()) {
        return it->second;
    }

    return std::nullopt;
}

// ============================================================================
// IP BLOCKING
// ============================================================================

[[nodiscard]] uint64_t FirewallManager::BlockIP(
    const std::wstring& ip,
    RuleDirection direction,
    uint32_t durationMs
) {
    if (!m_impl) return 0;
    return m_impl->BlockIPImpl(ip, direction, durationMs);
}

[[nodiscard]] uint64_t FirewallManager::BlockIPRange(
    const std::wstring& cidr,
    RuleDirection direction
) {
    if (!m_impl) return 0;

    // Parse CIDR (e.g., "192.168.1.0/24")
    size_t slashPos = cidr.find(L'/');
    if (slashPos == std::wstring::npos) {
        SS_LOG_ERROR(L"Network", L"FirewallManager: Invalid CIDR format");
        return 0;
    }

    std::wstring ipPart = cidr.substr(0, slashPos);
    std::wstring prefixPart = cidr.substr(slashPos + 1);

    bool isIPv6 = false;
    auto parsedIP = ParseIPAddress(ipPart, isIPv6);
    if (!parsedIP) {
        SS_LOG_ERROR(L"Network", L"FirewallManager: Invalid IP in CIDR");
        return 0;
    }

    uint8_t prefixLength = 0;
    try {
        int parsed = std::stoi(prefixPart);
        uint8_t maxPrefix = isIPv6 ? 128 : 32;
        if (parsed < 0 || parsed > maxPrefix) {
            SS_LOG_ERROR(L"Network",
                L"FirewallManager: Prefix length {} out of range (0-{}) for CIDR",
                parsed, maxPrefix);
            return 0;
        }
        prefixLength = static_cast<uint8_t>(parsed);
    } catch (...) {
        SS_LOG_ERROR(L"Network", L"FirewallManager: Invalid prefix length in CIDR");
        return 0;
    }

    FirewallRule rule;
    rule.name = std::format(L"Block IP Range {}", cidr);
    rule.description = L"CIDR-based IP block";
    rule.type = RuleType::IP;
    rule.action = RuleAction::BLOCK;
    rule.direction = direction;
    rule.priority = FirewallConstants::PRIORITY_HIGH;

    rule.remoteAddress.type = IPAddressMatch::Type::CIDR;
    rule.remoteAddress.address = *parsedIP;
    rule.remoteAddress.isIPv6 = isIPv6;
    rule.remoteAddress.prefixLength = prefixLength;

    return m_impl->AddRuleImpl(rule);
}

bool FirewallManager::UnblockIP(const std::wstring& ip) {
    if (!m_impl) return false;
    return m_impl->UnblockIPImpl(ip);
}

[[nodiscard]] bool FirewallManager::IsIPBlocked(const std::wstring& ip) const {
    if (!m_impl) return false;

    bool isIPv6 = false;
    auto parsedIP = ParseIPAddress(ip, isIPv6);
    if (!parsedIP) return false;

    std::shared_lock lock(m_impl->m_rulesMutex);

    for (const auto& [id, rule] : m_impl->m_rules) {
        if (rule.isEnabled &&
            rule.action == RuleAction::BLOCK &&
            rule.type == RuleType::IP &&
            rule.remoteAddress.Matches(*parsedIP)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] std::vector<std::wstring> FirewallManager::GetBlockedIPs() const {
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_rulesMutex);

    std::vector<std::wstring> result;
    for (const auto& [id, rule] : m_impl->m_rules) {
        if (rule.type == RuleType::IP &&
            rule.action == RuleAction::BLOCK &&
            rule.remoteAddress.type == IPAddressMatch::Type::SINGLE) {
            result.push_back(IPToString(rule.remoteAddress.address, rule.remoteAddress.isIPv6));
        }
    }

    return result;
}

// ============================================================================
// PORT MANAGEMENT
// ============================================================================

[[nodiscard]] uint64_t FirewallManager::BlockPort(
    uint16_t port,
    RuleProtocol protocol,
    RuleDirection direction
) {
    if (!m_impl) return 0;
    return m_impl->BlockPortImpl(port, protocol, direction);
}

[[nodiscard]] uint64_t FirewallManager::BlockPortRange(
    const PortRange& range,
    RuleProtocol protocol,
    RuleDirection direction
) {
    if (!m_impl) return 0;

    FirewallRule rule;
    rule.name = std::format(L"Block Ports {}-{}", range.start, range.end);
    rule.description = L"Port range block";
    rule.type = RuleType::PORT;
    rule.action = RuleAction::BLOCK;
    rule.direction = direction;
    rule.protocol = protocol;
    rule.priority = FirewallConstants::PRIORITY_NORMAL;
    rule.remotePorts.push_back(range);

    return m_impl->AddRuleImpl(rule);
}

bool FirewallManager::UnblockPort(uint16_t port, RuleProtocol protocol) {
    if (!m_impl) return false;
    return m_impl->UnblockPortImpl(port, protocol);
}

[[nodiscard]] bool FirewallManager::IsPortBlocked(
    uint16_t port,
    RuleProtocol protocol
) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_rulesMutex);

    for (const auto& [id, rule] : m_impl->m_rules) {
        if (rule.isEnabled &&
            rule.action == RuleAction::BLOCK &&
            rule.type == RuleType::PORT &&
            rule.protocol == protocol &&
            !rule.remotePorts.empty() &&
            rule.remotePorts[0].Contains(port)) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] uint64_t FirewallManager::OpenServicePort(
    ServiceType service,
    RuleDirection direction
) {
    // Map service to port
    uint16_t port = 0;
    RuleProtocol protocol = RuleProtocol::TCP;

    switch (service) {
        case ServiceType::HTTP: port = 80; break;
        case ServiceType::HTTPS: port = 443; break;
        case ServiceType::FTP: port = 21; break;
        case ServiceType::SSH: port = 22; break;
        case ServiceType::TELNET: port = 23; break;
        case ServiceType::SMTP: port = 25; break;
        case ServiceType::DNS: port = 53; protocol = RuleProtocol::UDP; break;
        case ServiceType::DHCP: port = 67; protocol = RuleProtocol::UDP; break;
        case ServiceType::POP3: port = 110; break;
        case ServiceType::IMAP: port = 143; break;
        case ServiceType::SNMP: port = 161; protocol = RuleProtocol::UDP; break;
        case ServiceType::RDP: port = 3389; break;
        case ServiceType::SMB: port = 445; break;
        case ServiceType::LDAP: port = 389; break;
        case ServiceType::MYSQL: port = 3306; break;
        case ServiceType::MSSQL: port = 1433; break;
        case ServiceType::POSTGRESQL: port = 5432; break;
        case ServiceType::NTP: port = 123; protocol = RuleProtocol::UDP; break;
        case ServiceType::SYSLOG: port = 514; protocol = RuleProtocol::UDP; break;
        case ServiceType::VNC: port = 5900; break;
        case ServiceType::KERBEROS: port = 88; protocol = RuleProtocol::UDP; break;
        default: return 0;
    }

    FirewallRule rule;
    rule.name = std::format(L"Allow Service Port {}", port);
    rule.description = L"Service port allow rule";
    rule.type = RuleType::PORT;
    rule.action = RuleAction::ALLOW;
    rule.direction = direction;
    rule.protocol = protocol;
    rule.priority = FirewallConstants::PRIORITY_NORMAL;
    rule.remotePorts.push_back(PortRange(port));

    return m_impl->AddRuleImpl(rule);
}

// ============================================================================
// GEO-BLOCKING
// ============================================================================

bool FirewallManager::BlockCountry(
    const std::string& countryCode,
    RuleDirection direction
) {
    if (!m_impl) return false;
    return m_impl->BlockCountryImpl(countryCode, direction);
}

bool FirewallManager::UnblockCountry(const std::string& countryCode) {
    if (!m_impl) return false;
    return m_impl->UnblockCountryImpl(countryCode);
}

void FirewallManager::SetAllowedCountries(const std::vector<std::string>& countryCodes) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_geoMutex);

    m_impl->m_blockedCountries.clear();

    // In allow-list mode, all countries not in the list are blocked
    // This would need proper implementation with geo-IP database

    SS_LOG_INFO(L"Network", L"FirewallManager: Allowed countries set");
}

void FirewallManager::ClearGeoRestrictions() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_geoMutex);
    m_impl->m_blockedCountries.clear();

    SS_LOG_INFO(L"Network", L"FirewallManager: Geo restrictions cleared");
}

[[nodiscard]] std::optional<GeoIPEntry> FirewallManager::GetGeoInfo(const std::wstring& ip) const {
    if (!m_impl) return std::nullopt;
    return m_impl->GetGeoInfoImpl(ip);
}

[[nodiscard]] std::vector<std::string> FirewallManager::GetBlockedCountries() const {
    if (!m_impl) return {};

    std::shared_lock lock(m_impl->m_geoMutex);

    std::vector<std::string> result;
    for (const auto& [country, blocked] : m_impl->m_blockedCountries) {
        if (blocked) {
            result.push_back(country);
        }
    }

    return result;
}

// ============================================================================
// STEALTH MODE
// ============================================================================

bool FirewallManager::SetStealthMode(StealthMode mode) {
    if (!m_impl) return false;

    {
        std::unique_lock lock(m_impl->m_configMutex);
        m_impl->m_config.stealthMode = mode;
    }
    return m_impl->ApplyStealthModeImpl(mode);
}

[[nodiscard]] StealthMode FirewallManager::GetStealthMode() const noexcept {
    if (!m_impl) return StealthMode::OFF;
    return m_impl->m_config.stealthMode;
}

// ============================================================================
// NETWORK PROFILES
// ============================================================================

[[nodiscard]] NetworkProfile FirewallManager::GetCurrentProfile() const {
    if (!m_impl) return NetworkProfile::PUBLIC;
    return m_impl->m_config.defaultProfile;
}

bool FirewallManager::SetProfileRules(
    NetworkProfile profile,
    const std::vector<FirewallRule>& rules
) {
    // In real implementation, would store profile-specific rules
    // For now, just log
    SS_LOG_INFO(L"Network", L"FirewallManager: Profile rules set for profile {}",
        static_cast<int>(profile));
    return true;
}

// ============================================================================
// EMERGENCY ACTIONS
// ============================================================================

bool FirewallManager::EnableLockdown(std::wstring_view reason) {
    if (!m_impl) return false;
    return m_impl->EnableLockdownImpl(reason);
}

bool FirewallManager::DisableLockdown() {
    if (!m_impl) return false;
    return m_impl->DisableLockdownImpl();
}

[[nodiscard]] bool FirewallManager::IsLockdownActive() const noexcept {
    if (!m_impl) return false;
    return m_impl->m_lockdownActive.load(std::memory_order_acquire);
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

[[nodiscard]] uint64_t FirewallManager::RegisterConnectionAttemptCallback(ConnectionAttemptCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_connectionCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Network", L"FirewallManager: Registered connection attempt callback {}", id);
    return id;
}

[[nodiscard]] uint64_t FirewallManager::RegisterRuleMatchCallback(RuleMatchCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_ruleMatchCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Network", L"FirewallManager: Registered rule match callback {}", id);
    return id;
}

[[nodiscard]] uint64_t FirewallManager::RegisterRuleChangeCallback(RuleChangeCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_ruleChangeCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Network", L"FirewallManager: Registered rule change callback {}", id);
    return id;
}

[[nodiscard]] uint64_t FirewallManager::RegisterBlockedConnectionCallback(BlockedConnectionCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_blockedCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Network", L"FirewallManager: Registered blocked connection callback {}", id);
    return id;
}

[[nodiscard]] uint64_t FirewallManager::RegisterApplicationCallback(ApplicationNetworkCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_appCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"Network", L"FirewallManager: Registered application callback {}", id);
    return id;
}

bool FirewallManager::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_connectionCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_ruleMatchCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_ruleChangeCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_blockedCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_appCallbacks.erase(callbackId) > 0;

    return removed;
}

// ============================================================================
// IMPORT/EXPORT
// ============================================================================

bool FirewallManager::ExportRules(const std::wstring& filePath, std::wstring_view format) const {
    if (!m_impl) return false;

    try {
        auto rules = m_impl->GetAllRulesImpl(false);

        std::ofstream file(filePath);
        if (!file) {
            SS_LOG_ERROR(L"Network", L"FirewallManager: Cannot create export file");
            return false;
        }

        // Simple JSON export
        file << "{\n";
        file << "  \"rules\": [\n";

        for (size_t i = 0; i < rules.size(); ++i) {
            const auto& rule = rules[i];
            file << "    {\n";
            file << "      \"id\": " << rule.ruleId << ",\n";
            file << "      \"name\": \"" << EscapeJsonString(StringUtils::ToNarrow(rule.name)) << "\",\n";
            file << "      \"enabled\": " << (rule.isEnabled ? "true" : "false") << "\n";
            file << "    }";
            if (i < rules.size() - 1) file << ",";
            file << "\n";
        }

        file << "  ]\n";
        file << "}\n";

        file.close();
        SS_LOG_INFO(L"Network", L"FirewallManager: Exported {} rules to {}",
            rules.size(), filePath);

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"FirewallManager: Export exception: {}", e.what());
        return false;
    }
}

uint32_t FirewallManager::ImportRules(const std::wstring& filePath, bool merge) {
    // Import implementation would parse JSON/XML and add rules
    // For now, placeholder
    SS_LOG_INFO(L"Network", L"FirewallManager: Import rules from {} (merge: {})",
        filePath, merge);
    return 0;
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const FirewallStatistics& FirewallManager::GetStatistics() const noexcept {
    static FirewallStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void FirewallManager::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        SS_LOG_INFO(L"Network", L"FirewallManager: Statistics reset");
    }
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

[[nodiscard]] bool FirewallManager::PerformDiagnostics() const {
    if (!m_impl) return false;
    return m_impl->PerformDiagnosticsImpl();
}

[[nodiscard]] bool FirewallManager::TestWFP() const {
    if (!m_impl) return false;
    return m_impl->m_wfpEngineHandle != nullptr;
}

bool FirewallManager::ExportDiagnostics(const std::wstring& outputPath) const {
    if (!m_impl) return false;
    return m_impl->ExportDiagnosticsImpl(outputPath);
}

} // namespace Network
} // namespace Core
} // namespace ShadowStrike
