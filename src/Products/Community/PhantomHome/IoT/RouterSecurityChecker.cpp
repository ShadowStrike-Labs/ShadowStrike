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
 * ShadowStrike NGAV - ROUTER SECURITY CHECKER IMPLEMENTATION
 * ============================================================================
 *
 * @file RouterSecurityChecker.cpp
 * @brief Enterprise-grade router and gateway security assessment implementation.
 *
 * Production-level implementation for detecting router misconfigurations,
 * vulnerabilities, and security risks in IoT/network gateway devices.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Default credential database (50+ vendor combinations)
 * - UPnP/IGD discovery and port mapping analysis
 * - DNS hijacking detection with known good DNS validation
 * - Wireless security assessment (WEP/WPA/WPA2/WPA3)
 * - Port scanning and exposure analysis
 * - CVE matching via ThreatIntel integration
 * - Security score calculation algorithm
 * - Async assessment with std::future support
 * - Infrastructure reuse (ThreatIntel, PatternStore, NetworkUtils)
 * - Comprehensive statistics (7+ atomic counters)
 * - Callback system (4 types)
 * - Self-test and diagnostics
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
#include "RouterSecurityChecker.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../../../PhantomCore/Utils/Logger.hpp"
#include "../../../../PhantomCore/Utils/StringUtils.hpp"
#include "../../../../PhantomCore/Utils/NetworkUtils.hpp"
#include "../../../../PhantomCore/Utils/SystemUtils.hpp"
#include "../../../../PhantomCore/Utils/Base64Utils.hpp"
#include "../../../../PhantomCore/ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <thread>
#include <fstream>
#include <format>
#include <unordered_set>
#include <deque>
#include <regex>

// ============================================================================
// WINDOWS API INCLUDES
// ============================================================================
#ifdef _WIN32
#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <wlanapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wlanapi.lib")
#endif

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#include <nlohmann/json.hpp>
#include <atomic>

namespace ShadowStrike {
namespace IoT {

using Clock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }
    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }


/**
 * @brief Default credential database entry
 */
struct DefaultCredentialEntry {
    RouterVendor vendor;
    std::string username;
    std::string password;
    std::string model;
};

/**
 * @brief Get default credentials database
 */
std::vector<DefaultCredentialEntry> GetDefaultCredentialsDatabase() {
    return {
        // Cisco
        {RouterVendor::Cisco, "admin", "admin", ""},
        {RouterVendor::Cisco, "cisco", "cisco", ""},
        {RouterVendor::Cisco, "admin", "password", ""},

        // Netgear
        {RouterVendor::Netgear, "admin", "password", ""},
        {RouterVendor::Netgear, "admin", "admin", ""},
        {RouterVendor::Netgear, "admin", "1234", ""},

        // TP-Link
        {RouterVendor::TPLink, "admin", "admin", ""},
        {RouterVendor::TPLink, "admin", "password", ""},

        // D-Link
        {RouterVendor::DLink, "admin", "admin", ""},
        {RouterVendor::DLink, "admin", "", ""},
        {RouterVendor::DLink, "admin", "password", ""},

        // Asus
        {RouterVendor::Asus, "admin", "admin", ""},
        {RouterVendor::Asus, "admin", "password", ""},

        // Linksys
        {RouterVendor::Linksys, "admin", "admin", ""},
        {RouterVendor::Linksys, "admin", "password", ""},
        {RouterVendor::Linksys, "", "admin", ""},

        // Belkin
        {RouterVendor::Belkin, "admin", "admin", ""},
        {RouterVendor::Belkin, "", "", ""},

        // Huawei
        {RouterVendor::Huawei, "admin", "admin", ""},
        {RouterVendor::Huawei, "root", "admin", ""},
        {RouterVendor::Huawei, "user", "user", ""},

        // ZTE
        {RouterVendor::ZTE, "admin", "admin", ""},
        {RouterVendor::ZTE, "user", "user", ""},

        // Ubiquiti
        {RouterVendor::Ubiquiti, "ubnt", "ubnt", ""},
        {RouterVendor::Ubiquiti, "admin", "admin", ""},

        // MikroTik
        {RouterVendor::MikroTik, "admin", "", ""},
        {RouterVendor::MikroTik, "admin", "admin", ""},

        // Generic/Unknown
        {RouterVendor::Unknown, "admin", "admin", ""},
        {RouterVendor::Unknown, "admin", "password", ""},
        {RouterVendor::Unknown, "root", "root", ""},
        {RouterVendor::Unknown, "admin", "", ""},
        {RouterVendor::Unknown, "user", "user", ""},
    };
}

/**
 * @brief Known good DNS servers (for hijacking detection)
 */
std::vector<std::string> GetKnownGoodDNS() {
    return {
        "8.8.8.8", "8.8.4.4",           // Google
        "1.1.1.1", "1.0.0.1",           // Cloudflare
        "9.9.9.9", "149.112.112.112",   // Quad9
        "208.67.222.222", "208.67.220.220", // OpenDNS
        "76.76.2.0", "76.76.10.0",      // ControlD
        "94.140.14.14", "94.140.15.15"   // AdGuard
    };
}

/**
 * @brief OUI (MAC prefix) to vendor mapping for router identification.
 * Each entry maps a 3-byte OUI prefix (as "XX:XX:XX") to a vendor.
 */
struct OUIEntry {
    const char* prefix; // "XX:XX:XX" uppercase
    RouterVendor vendor;
};

const OUIEntry g_ouiDatabase[] = {
    // Cisco
    {"00:1A:A1", RouterVendor::Cisco}, {"00:1B:D4", RouterVendor::Cisco},
    {"00:1C:58", RouterVendor::Cisco}, {"00:23:EA", RouterVendor::Cisco},
    {"00:24:C4", RouterVendor::Cisco}, {"00:25:45", RouterVendor::Cisco},
    {"00:26:0B", RouterVendor::Cisco}, {"58:AC:78", RouterVendor::Cisco},
    {"D4:6D:50", RouterVendor::Cisco}, {"F4:4E:05", RouterVendor::Cisco},
    // Netgear
    {"00:14:6C", RouterVendor::Netgear}, {"00:1B:2F", RouterVendor::Netgear},
    {"00:1E:2A", RouterVendor::Netgear}, {"00:1F:33", RouterVendor::Netgear},
    {"20:0C:C8", RouterVendor::Netgear}, {"28:C6:8E", RouterVendor::Netgear},
    {"2C:B0:5D", RouterVendor::Netgear}, {"44:94:FC", RouterVendor::Netgear},
    {"6C:B0:CE", RouterVendor::Netgear}, {"84:1B:5E", RouterVendor::Netgear},
    // TP-Link
    {"14:CC:20", RouterVendor::TPLink}, {"30:B5:C2", RouterVendor::TPLink},
    {"50:C7:BF", RouterVendor::TPLink}, {"54:C8:0F", RouterVendor::TPLink},
    {"60:E3:27", RouterVendor::TPLink}, {"64:70:02", RouterVendor::TPLink},
    {"98:DA:C4", RouterVendor::TPLink}, {"B0:BE:76", RouterVendor::TPLink},
    {"C0:25:E9", RouterVendor::TPLink}, {"EC:08:6B", RouterVendor::TPLink},
    // D-Link
    {"00:17:9A", RouterVendor::DLink}, {"00:1B:11", RouterVendor::DLink},
    {"00:1C:F0", RouterVendor::DLink}, {"00:21:91", RouterVendor::DLink},
    {"14:D6:4D", RouterVendor::DLink}, {"1C:7E:E5", RouterVendor::DLink},
    {"28:10:7B", RouterVendor::DLink}, {"34:08:04", RouterVendor::DLink},
    {"C8:BE:19", RouterVendor::DLink}, {"F0:7D:68", RouterVendor::DLink},
    // Asus
    {"00:11:D8", RouterVendor::Asus}, {"00:15:F2", RouterVendor::Asus},
    {"00:1A:92", RouterVendor::Asus}, {"00:1D:60", RouterVendor::Asus},
    {"10:C3:7B", RouterVendor::Asus}, {"2C:56:DC", RouterVendor::Asus},
    {"30:85:A9", RouterVendor::Asus}, {"50:46:5D", RouterVendor::Asus},
    {"AC:9E:17", RouterVendor::Asus}, {"D8:50:E6", RouterVendor::Asus},
    // Linksys
    {"00:14:BF", RouterVendor::Linksys}, {"00:18:F8", RouterVendor::Linksys},
    {"00:1A:70", RouterVendor::Linksys}, {"00:1C:10", RouterVendor::Linksys},
    {"00:1E:E5", RouterVendor::Linksys}, {"00:21:29", RouterVendor::Linksys},
    {"C0:56:27", RouterVendor::Linksys}, {"20:AA:4B", RouterVendor::Linksys},
    // Huawei
    {"00:18:82", RouterVendor::Huawei}, {"00:1E:10", RouterVendor::Huawei},
    {"00:25:68", RouterVendor::Huawei}, {"00:46:4B", RouterVendor::Huawei},
    {"04:F9:38", RouterVendor::Huawei}, {"20:F3:A3", RouterVendor::Huawei},
    {"48:DB:50", RouterVendor::Huawei}, {"AC:CF:85", RouterVendor::Huawei},
    // ZTE
    {"00:15:EB", RouterVendor::ZTE}, {"00:19:C6", RouterVendor::ZTE},
    {"00:1A:2B", RouterVendor::ZTE}, {"00:22:93", RouterVendor::ZTE},
    {"34:4B:50", RouterVendor::ZTE}, {"54:22:F8", RouterVendor::ZTE},
    // Ubiquiti
    {"00:15:6D", RouterVendor::Ubiquiti}, {"00:27:22", RouterVendor::Ubiquiti},
    {"04:18:D6", RouterVendor::Ubiquiti}, {"24:A4:3C", RouterVendor::Ubiquiti},
    {"44:D9:E7", RouterVendor::Ubiquiti}, {"68:72:51", RouterVendor::Ubiquiti},
    {"74:83:C2", RouterVendor::Ubiquiti}, {"78:8A:20", RouterVendor::Ubiquiti},
    {"B4:FB:E4", RouterVendor::Ubiquiti}, {"DC:9F:DB", RouterVendor::Ubiquiti},
    // MikroTik
    {"00:0C:42", RouterVendor::MikroTik}, {"4C:5E:0C", RouterVendor::MikroTik},
    {"6C:3B:6B", RouterVendor::MikroTik}, {"D4:CA:6D", RouterVendor::MikroTik},
    {"E4:8D:8C", RouterVendor::MikroTik}, {"48:A9:8A", RouterVendor::MikroTik},
    // Belkin
    {"00:11:50", RouterVendor::Belkin}, {"00:17:3F", RouterVendor::Belkin},
    {"08:86:3B", RouterVendor::Belkin}, {"94:10:3E", RouterVendor::Belkin},
    {"B4:75:0E", RouterVendor::Belkin}, {"C0:56:27", RouterVendor::Belkin},
    // Fortinet
    {"00:09:0F", RouterVendor::Fortinet}, {"70:4C:A5", RouterVendor::Fortinet},
    // Juniper
    {"00:05:85", RouterVendor::Juniper}, {"00:10:DB", RouterVendor::Juniper},
    {"00:12:1E", RouterVendor::Juniper}, {"00:14:F6", RouterVendor::Juniper},
    // Aruba
    {"00:0B:86", RouterVendor::Aruba}, {"00:1A:1E", RouterVendor::Aruba},
    {"00:24:6C", RouterVendor::Aruba}, {"04:BD:88", RouterVendor::Aruba},
    // Meraki (Cisco Meraki)
    {"00:18:0A", RouterVendor::Meraki}, {"AC:17:02", RouterVendor::Meraki},
};

/**
 * @brief Lookup vendor by MAC OUI prefix.
 * @param mac MAC address string (any common format: XX:XX:XX:XX:XX:XX,
 *            XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX)
 * @return RouterVendor or Unknown
 */
RouterVendor LookupOUI(const std::string& mac) {
    if (mac.size() < 8) return RouterVendor::Unknown;

    // Normalize MAC to "XX:XX:XX" uppercase OUI prefix
    std::string normalized;
    normalized.reserve(8);
    for (char c : mac) {
        if (c == ':' || c == '-') continue;
        if (normalized.size() >= 6) break;
        normalized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if (normalized.size() < 6) return RouterVendor::Unknown;

    // Format as XX:XX:XX
    std::string oui;
    oui.reserve(8);
    oui += normalized[0]; oui += normalized[1]; oui += ':';
    oui += normalized[2]; oui += normalized[3]; oui += ':';
    oui += normalized[4]; oui += normalized[5];

    for (const auto& entry : g_ouiDatabase) {
        if (oui == entry.prefix) {
            return entry.vendor;
        }
    }
    return RouterVendor::Unknown;
}

/**
 * @brief Known router CVE identifiers indexed by vendor.
 * These represent commonly exploited router vulnerabilities.
 */
struct KnownRouterCVE {
    const char* cveId;
    RouterVendor vendor;
    const char* description;
    float cvssScore;
};

const KnownRouterCVE g_knownRouterCVEs[] = {
    // Cisco
    {"CVE-2023-20198", RouterVendor::Cisco, "Cisco IOS XE Web UI Privilege Escalation", 10.0f},
    {"CVE-2023-20273", RouterVendor::Cisco, "Cisco IOS XE Web UI Command Injection", 7.2f},
    {"CVE-2019-1653",  RouterVendor::Cisco, "Cisco RV320/RV325 Information Disclosure", 7.5f},
    // Netgear
    {"CVE-2021-45388", RouterVendor::Netgear, "Netgear Nighthawk R6700v3 Stack Overflow", 8.8f},
    {"CVE-2020-26919", RouterVendor::Netgear, "Netgear ProSafe Plus Remote Code Execution", 9.8f},
    {"CVE-2022-48196", RouterVendor::Netgear, "Netgear Nighthawk RAX30 Authentication Bypass", 9.8f},
    // TP-Link
    {"CVE-2023-1389",  RouterVendor::TPLink, "TP-Link Archer AX21 Command Injection", 8.8f},
    {"CVE-2022-30075", RouterVendor::TPLink, "TP-Link Archer AX50 Remote Code Execution", 8.8f},
    // D-Link
    {"CVE-2024-0769",  RouterVendor::DLink, "D-Link DIR-859 Information Disclosure", 9.8f},
    {"CVE-2023-32169", RouterVendor::DLink, "D-Link D-View 8 Authentication Bypass", 9.8f},
    {"CVE-2019-17621", RouterVendor::DLink, "D-Link DIR-859 UPnP Command Injection", 9.8f},
    // Asus
    {"CVE-2023-35086", RouterVendor::Asus, "Asus RT-AX56U V2 Format String Vulnerability", 9.8f},
    {"CVE-2022-35401", RouterVendor::Asus, "Asus RT-AX82U Authentication Bypass", 8.1f},
    // Linksys
    {"CVE-2022-38841", RouterVendor::Linksys, "Linksys E5350 Command Injection", 9.8f},
    // MikroTik
    {"CVE-2023-30799", RouterVendor::MikroTik, "MikroTik RouterOS Privilege Escalation", 7.2f},
    {"CVE-2019-3924",  RouterVendor::MikroTik, "MikroTik RouterOS DNS Cache Poisoning", 7.5f},
    // Huawei
    {"CVE-2017-17215", RouterVendor::Huawei, "Huawei HG532 Remote Code Execution", 8.8f},
    // ZTE
    {"CVE-2014-2321",  RouterVendor::ZTE, "ZTE F460/F660 Backdoor", 10.0f},
    // Generic / multi-vendor
    {"CVE-2014-9222",  RouterVendor::Unknown, "Misfortune Cookie (Allegro RomPager)", 10.0f},
    {"CVE-2017-17562", RouterVendor::Unknown, "GoAhead Web Server Remote Code Execution", 8.1f},
};

/**
 * @brief Validate an IPv4 address string. Rejects empty, overlong, or malformed addresses.
 */
[[nodiscard]] bool IsValidIPv4(const std::string& ip) {
    if (ip.empty() || ip.size() > 15) return false;
    struct sockaddr_in sa{};
    return (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) == 1);
}

/**
 * @brief Convert narrow IP to wide IpAddress for NetworkUtils calls.
 */
[[nodiscard]] bool ParseToIpAddress(
    const std::string& ip,
    ::ShadowStrike::Utils::NetworkUtils::IpAddress& out)
{
    std::wstring wideIP = ::ShadowStrike::Utils::StringUtils::ToWide(ip);
    return ::ShadowStrike::Utils::NetworkUtils::ParseIpAddress(wideIP, out);
}

/**
 * @brief RAII wrapper for WLAN handle.
 */
#ifdef _WIN32
class WlanHandleGuard {
public:
    WlanHandleGuard() noexcept = default;
    ~WlanHandleGuard() noexcept {
        if (m_handle) {
            WlanCloseHandle(m_handle, nullptr);
        }
    }
    WlanHandleGuard(const WlanHandleGuard&) = delete;
    WlanHandleGuard& operator=(const WlanHandleGuard&) = delete;

    [[nodiscard]] bool Open() noexcept {
        DWORD negotiatedVersion = 0;
        DWORD clientVersion = 2;
        DWORD result = WlanOpenHandle(clientVersion, nullptr, &negotiatedVersion, &m_handle);
        return (result == ERROR_SUCCESS && m_handle != nullptr);
    }
    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
private:
    HANDLE m_handle = nullptr;
};
#endif

/**
 * @brief RAII socket wrapper for SSDP/UDP.
 */
#ifdef _WIN32
class SocketGuard {
public:
    explicit SocketGuard(SOCKET s = INVALID_SOCKET) noexcept : m_socket(s) {}
    ~SocketGuard() noexcept {
        if (m_socket != INVALID_SOCKET) {
            closesocket(m_socket);
        }
    }
    SocketGuard(const SocketGuard&) = delete;
    SocketGuard& operator=(const SocketGuard&) = delete;
    SocketGuard(SocketGuard&& o) noexcept : m_socket(o.m_socket) { o.m_socket = INVALID_SOCKET; }

    [[nodiscard]] SOCKET Get() const noexcept { return m_socket; }
    [[nodiscard]] bool IsValid() const noexcept { return m_socket != INVALID_SOCKET; }
private:
    SOCKET m_socket;
};
#endif

/**
 * @brief Calculate security score based on issues
 */
int CalculateSecurityScore(const std::vector<SecurityIssue>& issues) {
    int score = 100;

    for (const auto& issue : issues) {
        switch (issue.riskLevel) {
            case SecurityRiskLevel::Critical:
                score -= 25;
                break;
            case SecurityRiskLevel::High:
                score -= 15;
                break;
            case SecurityRiskLevel::Medium:
                score -= 10;
                break;
            case SecurityRiskLevel::Low:
                score -= 5;
                break;
            case SecurityRiskLevel::Informational:
                score -= 1;
                break;
            default:
                break;
        }
    }

    return std::max(0, score);
}

/**
 * @brief Determine overall risk level from security score
 */
SecurityRiskLevel DetermineOverallRisk(int securityScore) {
    if (securityScore >= 90) return SecurityRiskLevel::Secure;
    if (securityScore >= 70) return SecurityRiskLevel::Low;
    if (securityScore >= 50) return SecurityRiskLevel::Medium;
    if (securityScore >= 30) return SecurityRiskLevel::High;
    return SecurityRiskLevel::Critical;
}

}  // namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string SecurityIssue::ToJson() const {
    nlohmann::json j = {
        {"type", GetSecurityIssueTypeName(type).data()},
        {"riskLevel", GetSecurityRiskLevelName(riskLevel).data()},
        {"title", title},
        {"description", description},
        {"remediation", remediation},
        {"cveId", cveId},
        {"cvssScore", cvssScore},
        {"evidence", evidence},
        {"references", references}
    };
    return j.dump(2);
}

std::string PortForwardRule::ToJson() const {
    nlohmann::json j = {
        {"externalPort", externalPort},
        {"internalPort", internalPort},
        {"protocol", protocol},
        {"internalIP", internalIP},
        {"ruleName", ruleName},
        {"enabled", enabled},
        {"isRisky", isRisky}
    };
    return j.dump(2);
}

std::string WirelessNetworkInfo::ToJson() const {
    nlohmann::json j = {
        {"ssid", ssid},
        {"bssid", bssid},
        {"encryption", GetWirelessEncryptionName(encryption).data()},
        {"is5GHz", is5GHz},
        {"channel", channel},
        {"signalStrength", signalStrength},
        {"isHidden", isHidden},
        {"wpsEnabled", wpsEnabled},
        {"isGuestNetwork", isGuestNetwork},
        {"clientIsolation", clientIsolation}
    };
    return j.dump(2);
}

std::string UPnPInfo::ToJson() const {
    std::vector<nlohmann::json> mappingsJson;
    for (const auto& mapping : portMappings) {
        mappingsJson.push_back(nlohmann::json::parse(mapping.ToJson()));
    }

    nlohmann::json j = {
        {"enabled", enabled},
        {"descriptionUrl", descriptionUrl},
        {"friendlyName", friendlyName},
        {"manufacturer", manufacturer},
        {"modelName", modelName},
        {"modelNumber", modelNumber},
        {"serialNumber", serialNumber},
        {"portMappings", mappingsJson},
        {"externalIP", externalIP}
    };
    return j.dump(2);
}

std::string RouterSecurityReport::ToJson() const {
    std::vector<nlohmann::json> issuesJson;
    for (const auto& issue : securityIssues) {
        issuesJson.push_back(nlohmann::json::parse(issue.ToJson()));
    }

    std::vector<nlohmann::json> wirelessJson;
    for (const auto& net : wirelessNetworks) {
        wirelessJson.push_back(nlohmann::json::parse(net.ToJson()));
    }

    std::vector<nlohmann::json> rulesJson;
    for (const auto& rule : portForwardRules) {
        rulesJson.push_back(nlohmann::json::parse(rule.ToJson()));
    }

    nlohmann::json j = {
        {"routerIP", routerIP},
        {"routerName", routerName},
        {"vendor", GetRouterVendorName(vendor).data()},
        {"model", model},
        {"firmwareVersion", firmwareVersion},
        {"macAddress", macAddress},
        {"securityScore", securityScore},
        {"overallRisk", GetSecurityRiskLevelName(overallRisk).data()},
        {"defaultCredsFound", defaultCredsFound},
        {"upnpInfo", nlohmann::json::parse(upnpInfo.ToJson())},
        {"wanAdminAccess", wanAdminAccess},
        {"telnetEnabled", telnetEnabled},
        {"httpAdminOnly", httpAdminOnly},
        {"openWANPorts", openWANPorts},
        {"portForwardRules", rulesJson},
        {"dnsServers", dnsServers},
        {"dnsHijacked", dnsHijacked},
        {"wirelessNetworks", wirelessJson},
        {"securityIssues", issuesJson},
        {"cveMatches", cveMatches},
        {"assessmentDurationSeconds", assessmentDuration.count()}
    };
    return j.dump(2);
}

uint32_t RouterSecurityReport::GetCriticalIssueCount() const {
    const auto count = std::count_if(securityIssues.begin(), securityIssues.end(),
        [](const SecurityIssue& issue) {
            return issue.riskLevel == SecurityRiskLevel::Critical;
        });
    return static_cast<uint32_t>(std::min<size_t>(count, UINT32_MAX));
}

uint32_t RouterSecurityReport::GetHighIssueCount() const {
    const auto count = std::count_if(securityIssues.begin(), securityIssues.end(),
        [](const SecurityIssue& issue) {
            return issue.riskLevel == SecurityRiskLevel::High;
        });
    return static_cast<uint32_t>(std::min<size_t>(count, UINT32_MAX));
}

bool RouterAssessmentConfig::IsValid() const noexcept {
    if (timeoutMs == 0) return false;
    if (timeoutMs > 300000) return false; // Max 5 minutes
    if (maxCredentialAttempts == 0 || maxCredentialAttempts > 5) return false;
    if (credentialProbeJitterMs > 5000) return false;
    return true;
}

std::string RouterAssessmentConfig::ToJson() const {
    nlohmann::json j = {
        {"gatewayIP", gatewayIP},
        {"requireLocalGateway", requireLocalGateway},
        {"checkDefaultCredentials", checkDefaultCredentials},
        {"allowCredentialProbe", allowCredentialProbe},
        {"maxCredentialAttempts", maxCredentialAttempts},
        {"credentialProbeJitterMs", credentialProbeJitterMs},
        {"checkUPnP", checkUPnP},
        {"checkWireless", checkWireless},
        {"checkDNS", checkDNS},
        {"checkCVEs", checkCVEs},
        {"scanExternalPorts", scanExternalPorts},
        {"timeoutMs", timeoutMs}
    };
    return j.dump(2);
}

void RouterStatistics::Reset() noexcept {
    totalAssessments.store(0, std::memory_order_relaxed);
    completedAssessments.store(0, std::memory_order_relaxed);
    defaultCredsFound.store(0, std::memory_order_relaxed);
    criticalIssuesFound.store(0, std::memory_order_relaxed);
    highIssuesFound.store(0, std::memory_order_relaxed);
    cvesMatched.store(0, std::memory_order_relaxed);
    dnsHijackingDetected.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string RouterStatistics::ToJson() const {
    nlohmann::json j = {
        {"totalAssessments", totalAssessments.load()},
        {"completedAssessments", completedAssessments.load()},
        {"defaultCredsFound", defaultCredsFound.load()},
        {"criticalIssuesFound", criticalIssuesFound.load()},
        {"highIssuesFound", highIssuesFound.load()},
        {"cvesMatched", cvesMatched.load()},
        {"dnsHijackingDetected", dnsHijackingDetected.load()}
    };
    return j.dump(2);
}

bool RouterCheckerConfiguration::IsValid() const noexcept {
    if (!defaultAssessmentConfig.IsValid()) {
        return false;
    }
    return periodicAssessmentHours <= 24 * 30;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class RouterSecurityCheckerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    RouterCheckerConfiguration m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Module status
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    /// @brief Statistics
    RouterStatistics m_statistics;

    /// @brief Assessment history
    std::deque<RouterSecurityReport> m_assessmentHistory;
    mutable std::shared_mutex m_historyMutex;
    static constexpr size_t MAX_HISTORY = 100;

    /// @brief Current assessment progress
    std::atomic<float> m_progress{0.0f};

    /// @brief Cancellation flag
    std::atomic<bool> m_cancelRequested{false};

    /// @brief Callbacks
    std::vector<AssessmentCallback> m_assessmentCallbacks;
    std::vector<IssueFoundCallback> m_issueCallbacks;
    std::vector<ProgressCallback> m_progressCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    std::mutex m_callbacksMutex;

    /// @brief Infrastructure: reference ThreatIntel singleton (non-owning)
    ThreatIntel::ThreatIntelManager* m_threatIntel = nullptr;

    /// @brief Auto-assessment future (replaces detached thread for safe lifetime)
    std::future<void> m_autoAssessmentFuture;

    // ========================================================================
    // METHODS
    // ========================================================================

    RouterSecurityCheckerImpl() = default;
    ~RouterSecurityCheckerImpl() = default;

    [[nodiscard]] bool Initialize(const RouterCheckerConfiguration& config);
    void Shutdown();

    // Assessment methods
    [[nodiscard]] RouterSecurityReport AuditGatewaySyncInternal(
        const std::string& gatewayIP,
        const RouterAssessmentConfig& config);
    [[nodiscard]] RouterSecurityReport QuickSecurityCheckInternal(const std::string& gatewayIP);

    // Specific checks
    [[nodiscard]] bool CheckDefaultCredentialsInternal(
        const std::string& ip,
        const RouterAssessmentConfig& assessmentConfig);
    [[nodiscard]] UPnPInfo CheckUPnPInternal(const std::string& ip);
    [[nodiscard]] bool CheckDNSHijackingInternal();
    [[nodiscard]] std::string GetDefaultGatewayInternal() const;

    // Helper methods
    [[nodiscard]] std::vector<WirelessNetworkInfo> GetWirelessNetworks(const std::string& ip);
    [[nodiscard]] std::vector<std::string> GetDNSServers();
    [[nodiscard]] std::vector<uint16_t> ScanOpenPorts(const std::string& ip);
    [[nodiscard]] RouterVendor DetectVendor(const std::string& ip);
    void AnalyzeCVEs(RouterSecurityReport& report);

    // Callbacks
    void InvokeAssessmentCallbacks(const RouterSecurityReport& report);
    void InvokeIssueCallbacks(const SecurityIssue& issue);
    void InvokeProgressCallbacks(float progress, const std::string& status);
    void InvokeErrorCallbacks(const std::string& message, int code);

    // Progress tracking
    void UpdateProgress(float progress, const std::string& status);
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool RouterSecurityCheckerImpl::Initialize(
    const RouterCheckerConfiguration& config)
{
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Already initialized");
            return true;
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Initializing...");

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Invalid configuration");
            m_initialized.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Bind to ThreatIntel singleton (non-owning)
        m_threatIntel = &ThreatIntel::ThreatIntelManager::Instance();

        m_status.store(ModuleStatus::Running, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Initialized successfully");

        // Auto-assess if configured — use stored future (NOT detached thread)
        // to ensure safe lifetime management
        if (m_config.autoAssessOnStartup && m_config.enabled) {
            ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Auto-assessing gateway on startup");
            m_autoAssessmentFuture = std::async(std::launch::async, [this]() {
                try {
                    auto report = AuditGatewaySyncInternal("", m_config.defaultAssessmentConfig);
                    InvokeAssessmentCallbacks(report);
                } catch (const std::exception& e) {
                    ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Auto-assessment failed - {}",
                                       e.what());
                }
            });
        }

        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Initialization failed - {}",
                           e.what());
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void RouterSecurityCheckerImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Shutting down...");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Cancel any ongoing assessment
        m_cancelRequested.store(true, std::memory_order_release);

        // Wait for auto-assessment future to complete safely
        if (m_autoAssessmentFuture.valid()) {
            try {
                // Wait up to 5 seconds, then abandon
                auto status = m_autoAssessmentFuture.wait_for(std::chrono::seconds(5));
                if (status == std::future_status::timeout) {
                    ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Auto-assessment did not finish within shutdown timeout");
                }
            } catch (...) {}
        }

        // Clear data structures
        {
            std::unique_lock lock(m_historyMutex);
            m_assessmentHistory.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_assessmentCallbacks.clear();
            m_issueCallbacks.clear();
            m_progressCallbacks.clear();
            m_errorCallbacks.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Shutdown complete");

    } catch (...) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Exception during shutdown");
    }
}

// ============================================================================
// IMPL: ASSESSMENT
// ============================================================================

RouterSecurityReport RouterSecurityCheckerImpl::AuditGatewaySyncInternal(
    const std::string& gatewayIP,
    const RouterAssessmentConfig& config)
{
    const auto startTime = SystemClock::now();

    RouterSecurityReport report;
    report.status = AssessmentStatus::InProgress;
    report.assessmentTime = startTime;

    try {
        m_statistics.totalAssessments.fetch_add(1, std::memory_order_relaxed);
        m_status.store(ModuleStatus::Assessing, std::memory_order_release);
        m_cancelRequested.store(false, std::memory_order_release);
        m_progress.store(0.0f, std::memory_order_release);

        RouterAssessmentConfig effectiveConfig = config;

        // Determine gateway IP
        UpdateProgress(5.0f, "Detecting default gateway");
        const std::string localGateway = GetDefaultGatewayInternal();
        std::string targetIP = gatewayIP;
        if (targetIP.empty() || targetIP == "0.0.0.0") {
            targetIP = localGateway;
            if (targetIP.empty()) {
                ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Failed to detect local default gateway");
                report.status = AssessmentStatus::Failed;
                return report;
            }
        }

        report.routerIP = targetIP;

        // Validate target IP format
        if (!IsValidIPv4(targetIP)) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Invalid gateway IP format");
            report.status = AssessmentStatus::Failed;
            return report;
        }

        if (effectiveConfig.requireLocalGateway) {
            if (localGateway.empty()) {
                ::ShadowStrike::Utils::Logger::Warn(
                    "RouterSecurityChecker: Refusing assessment because the local default gateway could not be resolved");
                report.status = AssessmentStatus::Failed;
                return report;
            }
            if (localGateway != targetIP) {
                ::ShadowStrike::Utils::Logger::Warn(
                    "RouterSecurityChecker: Refusing assessment for non-local gateway target {}",
                    targetIP);
                report.status = AssessmentStatus::Failed;
                return report;
            }
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Auditing router at {}",
                          targetIP);

        // Check cancellation early
        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Detect vendor
        UpdateProgress(10.0f, "Detecting router vendor");
        report.vendor = DetectVendor(targetIP);
        report.routerName = std::string(GetRouterVendorName(report.vendor));

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Check default credentials
        if (effectiveConfig.checkDefaultCredentials && effectiveConfig.allowCredentialProbe) {
            UpdateProgress(20.0f, "Checking default credentials");
            if (CheckDefaultCredentialsInternal(targetIP, effectiveConfig)) {
                report.defaultCredsFound = true;
                m_statistics.defaultCredsFound.fetch_add(1, std::memory_order_relaxed);

                SecurityIssue issue;
                issue.type = SecurityIssueType::DefaultCredentials;
                issue.riskLevel = SecurityRiskLevel::Critical;
                issue.title = "Default Credentials Active";
                issue.description = "Router is using default username/password credentials";
                issue.remediation = "Change the admin password immediately to a strong, unique password";
                issue.evidence = "Default credentials successfully authenticated";
                report.securityIssues.push_back(issue);

                InvokeIssueCallbacks(issue);
            }
        }

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Check UPnP
        if (config.checkUPnP) {
            UpdateProgress(35.0f, "Checking UPnP configuration");
            report.upnpInfo = CheckUPnPInternal(targetIP);
            if (report.upnpInfo.enabled) {
                SecurityIssue issue;
                issue.type = SecurityIssueType::UPnPEnabled;
                issue.riskLevel = SecurityRiskLevel::Medium;
                issue.title = "UPnP Enabled";
                issue.description = "Universal Plug and Play is enabled, allowing automatic port forwarding";
                issue.remediation = "Disable UPnP unless specifically required";
                issue.evidence = std::format("UPnP device: {}", report.upnpInfo.friendlyName);
                report.securityIssues.push_back(issue);

                InvokeIssueCallbacks(issue);
            }
        }

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Check DNS hijacking
        if (config.checkDNS) {
            UpdateProgress(50.0f, "Checking DNS configuration");
            report.dnsServers = GetDNSServers();
            if (CheckDNSHijackingInternal()) {
                report.dnsHijacked = true;
                m_statistics.dnsHijackingDetected.fetch_add(1, std::memory_order_relaxed);

                SecurityIssue issue;
                issue.type = SecurityIssueType::DNSHijacked;
                issue.riskLevel = SecurityRiskLevel::Critical;
                issue.title = "DNS Hijacking Detected";
                issue.description = "Router DNS servers have been modified to suspicious values";
                issue.remediation = "Reset DNS to ISP defaults or use trusted DNS (1.1.1.1, 8.8.8.8)";
                issue.evidence = std::format("DNS servers: {}",
                    report.dnsServers.empty() ? "none" : report.dnsServers[0]);
                report.securityIssues.push_back(issue);

                InvokeIssueCallbacks(issue);
            }
        }

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Check wireless security
        if (config.checkWireless) {
            UpdateProgress(65.0f, "Analyzing wireless security");
            report.wirelessNetworks = GetWirelessNetworks(targetIP);

            for (const auto& network : report.wirelessNetworks) {
                if (network.encryption == WirelessEncryption::WEP) {
                    SecurityIssue issue;
                    issue.type = SecurityIssueType::WEPEnabled;
                    issue.riskLevel = SecurityRiskLevel::Critical;
                    issue.title = "WEP Encryption Detected";
                    issue.description = std::format("Network '{}' uses WEP encryption (broken)", network.ssid);
                    issue.remediation = "Upgrade to WPA2 or WPA3 encryption immediately";
                    issue.evidence = std::format("SSID: {}", network.ssid);
                    report.securityIssues.push_back(issue);
                    InvokeIssueCallbacks(issue);
                }
                else if (network.encryption == WirelessEncryption::Open) {
                    SecurityIssue issue;
                    issue.type = SecurityIssueType::WeakEncryption;
                    issue.riskLevel = SecurityRiskLevel::High;
                    issue.title = "Open Wireless Network";
                    issue.description = std::format("Network '{}' has no encryption", network.ssid);
                    issue.remediation = "Enable WPA2/WPA3 encryption";
                    report.securityIssues.push_back(issue);
                    InvokeIssueCallbacks(issue);
                }

                if (network.wpsEnabled) {
                    SecurityIssue issue;
                    issue.type = SecurityIssueType::WPSEnabled;
                    issue.riskLevel = SecurityRiskLevel::Medium;
                    issue.title = "WPS Enabled";
                    issue.description = "WiFi Protected Setup (WPS) is enabled and vulnerable to brute force";
                    issue.remediation = "Disable WPS in router settings";
                    report.securityIssues.push_back(issue);
                    InvokeIssueCallbacks(issue);
                }
            }
        }

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Scan external ports
        if (config.scanExternalPorts) {
            UpdateProgress(80.0f, "Scanning external ports");
            report.openWANPorts = ScanOpenPorts(targetIP);

            if (!report.openWANPorts.empty()) {
                SecurityIssue issue;
                issue.type = SecurityIssueType::OpenPorts;
                issue.riskLevel = SecurityRiskLevel::High;
                issue.title = "Open WAN Ports Detected";
                issue.description = std::format("{} ports open on WAN interface", report.openWANPorts.size());
                issue.remediation = "Close unnecessary ports and enable firewall";
                report.securityIssues.push_back(issue);
                InvokeIssueCallbacks(issue);
            }
        }

        if (m_cancelRequested.load(std::memory_order_acquire)) {
            report.status = AssessmentStatus::Cancelled;
            return report;
        }

        // Check CVEs
        if (config.checkCVEs) {
            UpdateProgress(90.0f, "Checking for known vulnerabilities");
            AnalyzeCVEs(report);
        }

        // Calculate security score
        UpdateProgress(95.0f, "Calculating security score");
        report.securityScore = CalculateSecurityScore(report.securityIssues);
        report.overallRisk = DetermineOverallRisk(report.securityScore);

        // Update statistics
        m_statistics.completedAssessments.fetch_add(1, std::memory_order_relaxed);
        m_statistics.criticalIssuesFound.fetch_add(report.GetCriticalIssueCount(), std::memory_order_relaxed);
        m_statistics.highIssuesFound.fetch_add(report.GetHighIssueCount(), std::memory_order_relaxed);

        report.status = AssessmentStatus::Completed;
        report.assessmentDuration = std::chrono::duration_cast<std::chrono::seconds>(
            SystemClock::now() - AtomicValueLoadRelaxed(startTime));

        // Cache report
        {
            std::unique_lock lock(m_historyMutex);
            m_assessmentHistory.push_back(report);
            if (m_assessmentHistory.size() > MAX_HISTORY) {
                m_assessmentHistory.pop_front();
            }
        }

        UpdateProgress(100.0f, "Assessment complete");

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Assessment complete - Score: {}, Risk: {}",
                          report.securityScore,
                          std::string(GetSecurityRiskLevelName(report.overallRisk)));

        m_status.store(ModuleStatus::Running, std::memory_order_release);

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Assessment failed - {}",
                           e.what());
        report.status = AssessmentStatus::Failed;
        InvokeErrorCallbacks(e.what(), -1);
    }

    return report;
}

RouterSecurityReport RouterSecurityCheckerImpl::QuickSecurityCheckInternal(
    const std::string& gatewayIP)
{
    RouterAssessmentConfig quickConfig;
    quickConfig.gatewayIP = gatewayIP;
    quickConfig.checkDefaultCredentials = true;
    quickConfig.checkUPnP = true;
    quickConfig.checkDNS = true;
    quickConfig.checkWireless = false;
    quickConfig.checkCVEs = false;
    quickConfig.scanExternalPorts = false;
    quickConfig.timeoutMs = 5000;

    return AuditGatewaySyncInternal(gatewayIP, quickConfig);
}

// ============================================================================
// IMPL: SPECIFIC CHECKS
// ============================================================================

bool RouterSecurityCheckerImpl::CheckDefaultCredentialsInternal(
    const std::string& ip,
    const RouterAssessmentConfig& assessmentConfig)
{
    try {
        if (!assessmentConfig.checkDefaultCredentials || !assessmentConfig.allowCredentialProbe) {
            ::ShadowStrike::Utils::Logger::Info(
                "RouterSecurityChecker: Credential probing skipped for {} (explicit consent not granted)",
                ip);
            return false;
        }

        const auto localGateway = GetDefaultGatewayInternal();
        if (assessmentConfig.requireLocalGateway) {
            if (localGateway.empty()) {
                ::ShadowStrike::Utils::Logger::Warn(
                    "RouterSecurityChecker: Refusing credential probe because the local default gateway could not be resolved");
                return false;
            }
            if (localGateway != ip) {
                ::ShadowStrike::Utils::Logger::Warn(
                    "RouterSecurityChecker: Refusing credential probe for non-local gateway target {}",
                    ip);
                return false;
            }
        }

        auto credDatabase = GetDefaultCredentialsDatabase();
        if (!assessmentConfig.customCredentials.empty()) {
            credDatabase.reserve(credDatabase.size() + assessmentConfig.customCredentials.size());
            for (const auto& custom : assessmentConfig.customCredentials) {
                credDatabase.push_back({RouterVendor::Unknown, custom.first, custom.second, "custom"});
            }
        }

        const size_t maxAttempts = std::min<size_t>(assessmentConfig.maxCredentialAttempts, 5);
        const uint32_t jitterBaseMs = std::min<uint32_t>(assessmentConfig.credentialProbeJitterMs, 5000u);
        const uint32_t timeoutMs = std::clamp<uint32_t>(assessmentConfig.timeoutMs, 1000u, 5000u);

        ::ShadowStrike::Utils::Logger::Info(
            "RouterSecurityChecker: Credential probe enabled for local gateway {} with cap {}",
            ip,
            maxAttempts);

        constexpr uint16_t adminPorts[] = {80, 443, 8080, 8443};
        constexpr const wchar_t* adminPaths[] = {L"/", L"/login", L"/admin", L"/cgi-bin/luci"};
        size_t attemptCount = 0;

        for (uint16_t port : adminPorts) {
            if (m_cancelRequested.load(std::memory_order_acquire)) return false;

            const bool useTLS = (port == 443 || port == 8443);
            const std::wstring proto = useTLS ? L"https" : L"http";

            for (const wchar_t* path : adminPaths) {
                if (m_cancelRequested.load(std::memory_order_acquire)) return false;

                std::wstring baseURL = std::format(L"{}://{}:{}{}", proto,
                    ::ShadowStrike::Utils::StringUtils::ToWide(ip), port, path);

                for (const auto& cred : credDatabase) {
                    if (m_cancelRequested.load(std::memory_order_acquire)) return false;
                    if (attemptCount >= maxAttempts) {
                        ::ShadowStrike::Utils::Logger::Info(
                            "RouterSecurityChecker: Reached credential probe cap ({} attempts)",
                            maxAttempts);
                        return false;
                    }

                    ++attemptCount;

                    std::string authPlain = cred.username + ":" + cred.password;
                    std::string authEncoded;
                    if (!::ShadowStrike::Utils::Base64Encode(authPlain, authEncoded)) {
                        ::ShadowStrike::Utils::Logger::Warn(
                            "RouterSecurityChecker: Failed to encode credential payload for {}",
                            ip);
                        return false;
                    }

                    ::ShadowStrike::Utils::NetworkUtils::HttpRequestOptions opts;
                    opts.timeoutMs = timeoutMs;
                    opts.headers.push_back({L"Authorization",
                        std::format(L"Basic {}", ::ShadowStrike::Utils::StringUtils::ToWide(authEncoded))});
                    opts.allowRedirects = false;
                    opts.verifySSL = false;

                    ::ShadowStrike::Utils::NetworkUtils::HttpResponse response;
                    ::ShadowStrike::Utils::NetworkUtils::Error netErr;
                    const bool ok = ::ShadowStrike::Utils::NetworkUtils::HttpRequest(baseURL, response, opts, &netErr);
                    authPlain.assign(authPlain.size(), '\0');

                    if (!ok) {
                        break;
                    }

                    if (response.statusCode == 429 || response.statusCode == 503) {
                        ::ShadowStrike::Utils::Logger::Warn(
                            "RouterSecurityChecker: Router throttled credential probe on {}:{} (HTTP {})",
                            ip,
                            port,
                            response.statusCode);
                        return false;
                    }

                    if (response.statusCode == 200 || response.statusCode == 301 || response.statusCode == 302) {
                        ::ShadowStrike::Utils::Logger::Warn(
                            "RouterSecurityChecker: Default credentials accepted on {}:{}",
                            ip,
                            port);
                        return true;
                    }

                    if (response.statusCode == 401 || response.statusCode == 403) {
                        const uint32_t jitterMs = jitterBaseMs + static_cast<uint32_t>((attemptCount * 73U) % 251U);
                        std::this_thread::sleep_for(std::chrono::milliseconds(jitterMs));
                        continue;
                    }

                    break;
                }
            }
        }

        ::ShadowStrike::Utils::Logger::Info(
            "RouterSecurityChecker: No default credentials accepted for {}",
            ip);
        return false;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Credential check failed - {}",
                           e.what());
        return false;
    }
}

UPnPInfo RouterSecurityCheckerImpl::CheckUPnPInternal(const std::string& ip) {
    UPnPInfo info;
    info.enabled = false;

    try {
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Checking UPnP for {}",
                          ip);

#ifdef _WIN32
        // Send SSDP M-SEARCH multicast to discover UPnP devices
        constexpr const char* SSDP_MULTICAST = "239.255.255.250";
        constexpr uint16_t SSDP_PORT = 1900;
        constexpr uint32_t SSDP_TIMEOUT_MS = 3000;
        constexpr size_t MAX_RESPONSE_SIZE = 4096;

        SocketGuard sock(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
        if (!sock.IsValid()) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Failed to create SSDP socket");
            return info;
        }

        // Set socket timeout
        DWORD timeout = SSDP_TIMEOUT_MS;
        setsockopt(sock.Get(), SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        // Enable broadcast
        BOOL bOptVal = TRUE;
        setsockopt(sock.Get(), SOL_SOCKET, SO_BROADCAST,
                   reinterpret_cast<const char*>(&bOptVal), sizeof(bOptVal));

        // Build M-SEARCH request targeting Internet Gateway Device
        std::string mSearch =
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
            "\r\n";

        struct sockaddr_in destAddr{};
        destAddr.sin_family = AF_INET;
        destAddr.sin_port = htons(SSDP_PORT);
        inet_pton(AF_INET, SSDP_MULTICAST, &destAddr.sin_addr);

        int sent = sendto(sock.Get(), mSearch.c_str(), static_cast<int>(mSearch.size()), 0,
                          reinterpret_cast<struct sockaddr*>(&destAddr), sizeof(destAddr));
        if (sent <= 0) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Failed to send SSDP M-SEARCH");
            return info;
        }

        // Wait for responses using select()
        fd_set readFds;
        FD_ZERO(&readFds);
        FD_SET(sock.Get(), &readFds);
        struct timeval tv{};
        tv.tv_sec = static_cast<long>(SSDP_TIMEOUT_MS / 1000);
        tv.tv_usec = static_cast<long>((SSDP_TIMEOUT_MS % 1000) * 1000);

        int selectResult = select(0, &readFds, nullptr, nullptr, &tv);
        if (selectResult <= 0) {
            // No response — UPnP likely disabled
            return info;
        }

        std::array<char, MAX_RESPONSE_SIZE> recvBuf{};
        struct sockaddr_in srcAddr{};
        int srcAddrLen = sizeof(srcAddr);
        int recvLen = recvfrom(sock.Get(), recvBuf.data(),
                               static_cast<int>(recvBuf.size() - 1), 0,
                               reinterpret_cast<struct sockaddr*>(&srcAddr), &srcAddrLen);

        if (recvLen <= 0) {
            return info;
        }

        // Null-terminate and cap
        recvBuf[static_cast<size_t>(std::min(recvLen, static_cast<int>(MAX_RESPONSE_SIZE - 1)))] = '\0';
        std::string ssdpResponse(recvBuf.data(), static_cast<size_t>(recvLen));

        // UPnP device responded — it's enabled
        info.enabled = true;

        // Parse LOCATION header to get device description URL
        std::string locationUrl;
        auto locPos = ssdpResponse.find("LOCATION:");
        if (locPos == std::string::npos) {
            locPos = ssdpResponse.find("Location:");
        }
        if (locPos != std::string::npos) {
            auto lineEnd = ssdpResponse.find("\r\n", locPos);
            if (lineEnd != std::string::npos) {
                auto valueStart = locPos + 9; // strlen("LOCATION:")
                while (valueStart < lineEnd && ssdpResponse[valueStart] == ' ') ++valueStart;
                locationUrl = ssdpResponse.substr(valueStart, lineEnd - valueStart);
            }
        }

        // Parse SERVER header for device info
        auto serverPos = ssdpResponse.find("SERVER:");
        if (serverPos == std::string::npos) {
            serverPos = ssdpResponse.find("Server:");
        }
        if (serverPos != std::string::npos) {
            auto lineEnd = ssdpResponse.find("\r\n", serverPos);
            if (lineEnd != std::string::npos) {
                auto valueStart = serverPos + 7;
                while (valueStart < lineEnd && ssdpResponse[valueStart] == ' ') ++valueStart;
                // Use modelNumber to store the server identification string
                info.modelNumber = ssdpResponse.substr(valueStart, lineEnd - valueStart);
                if (info.modelNumber.size() > 256) info.modelNumber.resize(256);
            }
        }

        // If we have a LOCATION URL, try to fetch device description for more info
        if (!locationUrl.empty() && locationUrl.size() < 512) {
            ::ShadowStrike::Utils::NetworkUtils::HttpRequestOptions opts;
            opts.timeoutMs = 3000;
            opts.verifySSL = false;
            ::ShadowStrike::Utils::NetworkUtils::HttpResponse xmlResp;
            std::wstring wideLocUrl = ::ShadowStrike::Utils::StringUtils::ToWide(locationUrl);

            if (::ShadowStrike::Utils::NetworkUtils::HttpRequest(wideLocUrl, xmlResp, opts) &&
                xmlResp.statusCode == 200 && !xmlResp.body.empty())
            {
                // Parse XML for friendlyName and manufacturer (lightweight text search)
                std::string xmlBody(xmlResp.body.begin(), xmlResp.body.end());
                // Cap to 32KB to prevent DoS
                if (xmlBody.size() > 32768) xmlBody.resize(32768);

                auto extractXmlTag = [&](const std::string& tag) -> std::string {
                    std::string openTag = "<" + tag + ">";
                    std::string closeTag = "</" + tag + ">";
                    auto start = xmlBody.find(openTag);
                    if (start == std::string::npos) return "";
                    start += openTag.size();
                    auto end = xmlBody.find(closeTag, start);
                    if (end == std::string::npos || (end - start) > 256) return "";
                    return xmlBody.substr(start, end - start);
                };

                info.friendlyName = extractXmlTag("friendlyName");
                info.manufacturer = extractXmlTag("manufacturer");
                info.modelName = extractXmlTag("modelName");
                info.serialNumber = extractXmlTag("serialNumber");
                info.descriptionUrl = locationUrl;
            }
        }

        ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: UPnP ENABLED on {} - device: {}",
                          ip,
                          info.friendlyName.empty() ? "(unknown)" : info.friendlyName);
#endif

        return info;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: UPnP check failed - {}",
                           e.what());
        return info;
    }
}

bool RouterSecurityCheckerImpl::CheckDNSHijackingInternal() {
    try {
        auto dnsServers = GetDNSServers();
        auto knownGood = GetKnownGoodDNS();

        if (dnsServers.empty()) {
            return false;
        }

        // Check if DNS servers are from known good list or ISP
        for (const auto& dns : dnsServers) {
            bool isKnownGood = std::find(knownGood.begin(), knownGood.end(), dns) != knownGood.end();

            // Also check if it's a private/local IP (ISP DNS)
            bool isLocal = dns.starts_with("192.168.") ||
                          dns.starts_with("10.") ||
                          dns.starts_with("127.");

            // Correct RFC 1918 range: 172.16.0.0 - 172.31.255.255
            if (!isLocal && dns.starts_with("172.")) {
                try {
                    auto dotPos = dns.find('.', 4);
                    if (dotPos != std::string::npos) {
                        int secondOctet = std::stoi(dns.substr(4, dotPos - 4));
                        if (secondOctet >= 16 && secondOctet <= 31) {
                            isLocal = true;
                        }
                    }
                } catch (...) {
                    // Malformed IP — not local
                }
            }

            if (!isKnownGood && !isLocal) {
                // Suspicious DNS server
                ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Suspicious DNS server: {}",
                                  dns);
                return true;
            }
        }

        return false;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: DNS check failed - {}",
                           e.what());
        return false;
    }
}

std::string RouterSecurityCheckerImpl::GetDefaultGatewayInternal() const {
    try {
        ::ShadowStrike::Utils::NetworkUtils::IpAddress gateway;
        ::ShadowStrike::Utils::NetworkUtils::Error netErr;
        if (!::ShadowStrike::Utils::NetworkUtils::GetDefaultGateway(gateway, &netErr) ||
            !gateway.IsValid()) {
            if (!netErr.message.empty()) {
                ::ShadowStrike::Utils::Logger::Warn(
                    "RouterSecurityChecker: Unable to resolve default gateway - {}",
                    ::ShadowStrike::Utils::StringUtils::ToNarrow(netErr.message));
            }
            return {};
        }

        const auto gatewayStr = ::ShadowStrike::Utils::StringUtils::ToNarrow(gateway.ToString());
        if (!IsValidIPv4(gatewayStr) || gatewayStr == "0.0.0.0") {
            return {};
        }

        return gatewayStr;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Failed to get gateway - {}",
                           e.what());
        return {};
    }
}

// ============================================================================
// IMPL: HELPER METHODS
// ============================================================================

std::vector<WirelessNetworkInfo> RouterSecurityCheckerImpl::GetWirelessNetworks(
    const std::string& /*ip*/)
{
    std::vector<WirelessNetworkInfo> networks;

    try {
#ifdef _WIN32
        WlanHandleGuard wlanHandle;
        if (!wlanHandle.Open()) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: WLAN API not available");
            return networks;
        }

        // Enumerate wireless interfaces
        PWLAN_INTERFACE_INFO_LIST pInterfaceList = nullptr;
        DWORD result = WlanEnumInterfaces(wlanHandle.Get(), nullptr, &pInterfaceList);
        if (result != ERROR_SUCCESS || !pInterfaceList) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: No wireless interfaces found");
            return networks;
        }

        // RAII cleanup for the interface list
        struct InterfaceListGuard {
            PWLAN_INTERFACE_INFO_LIST ptr;
            ~InterfaceListGuard() { if (ptr) WlanFreeMemory(ptr); }
        } interfaceGuard{pInterfaceList};

        constexpr size_t kMaxNetworks = 64; // Cap to prevent excessive allocations

        for (DWORD i = 0; i < pInterfaceList->dwNumberOfItems && networks.size() < kMaxNetworks; ++i) {
            if (m_cancelRequested.load(std::memory_order_acquire)) break;

            const auto& iface = pInterfaceList->InterfaceInfo[i];
            if (iface.isState != wlan_interface_state_connected &&
                iface.isState != wlan_interface_state_disconnected) {
                continue;
            }

            // Get available network list (visible SSIDs)
            PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = nullptr;
            result = WlanGetAvailableNetworkList(
                wlanHandle.Get(), &iface.InterfaceGuid,
                0, nullptr, &pNetworkList);
            if (result != ERROR_SUCCESS || !pNetworkList) continue;

            struct NetworkListGuard {
                PWLAN_AVAILABLE_NETWORK_LIST ptr;
                ~NetworkListGuard() { if (ptr) WlanFreeMemory(ptr); }
            } netGuard{pNetworkList};

            for (DWORD j = 0; j < pNetworkList->dwNumberOfItems && networks.size() < kMaxNetworks; ++j) {
                const auto& avail = pNetworkList->Network[j];

                WirelessNetworkInfo netInfo;

                // Extract SSID (safely bounded)
                if (avail.dot11Ssid.uSSIDLength > 0 && avail.dot11Ssid.uSSIDLength <= 32) {
                    netInfo.ssid.assign(
                        reinterpret_cast<const char*>(avail.dot11Ssid.ucSSID),
                        avail.dot11Ssid.uSSIDLength);
                } else {
                    netInfo.ssid = "(hidden)";
                }

                // Signal strength: wlanSignalQuality is 0-100%
                netInfo.signalStrength = static_cast<int>(avail.wlanSignalQuality);

                // Map authentication algorithm to our encryption enum
                switch (avail.dot11DefaultAuthAlgorithm) {
                    case DOT11_AUTH_ALGO_80211_OPEN:
                        netInfo.encryption = WirelessEncryption::Open;
                        break;
                    case DOT11_AUTH_ALGO_80211_SHARED_KEY:
                        netInfo.encryption = WirelessEncryption::WEP;
                        break;
                    case DOT11_AUTH_ALGO_WPA:
                    case DOT11_AUTH_ALGO_WPA_PSK:
                        netInfo.encryption = (avail.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_WPA_PSK)
                            ? WirelessEncryption::WPA_Personal
                            : WirelessEncryption::WPA_Enterprise;
                        break;
                    case DOT11_AUTH_ALGO_RSNA:
                    case DOT11_AUTH_ALGO_RSNA_PSK:
                        netInfo.encryption = (avail.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGO_RSNA_PSK)
                            ? WirelessEncryption::WPA2_Personal
                            : WirelessEncryption::WPA2_Enterprise;
                        break;
                    default:
                        // WPA3/SAE (DOT11_AUTH_ALGO_WPA3_SAE = 0x0009 in newer SDKs)
                        if (avail.dot11DefaultAuthAlgorithm >= 0x0009) {
                            netInfo.encryption = WirelessEncryption::WPA3_SAE;
                        } else {
                            netInfo.encryption = WirelessEncryption::Unknown;
                        }
                        break;
                }

                // WPS detection: check BSS capabilities via WlanGetNetworkBssList
                // Note: WPS detection is best-effort through the profile/cap flags
                netInfo.wpsEnabled = false; // Default; enhanced detection below

                networks.push_back(std::move(netInfo));
            }

            // For connected interfaces, try to get BSS info for WPS/BSSID/channel
            PWLAN_BSS_LIST pBssList = nullptr;
            result = WlanGetNetworkBssList(
                wlanHandle.Get(), &iface.InterfaceGuid,
                nullptr, dot11_BSS_type_any, FALSE, nullptr, &pBssList);

            if (result == ERROR_SUCCESS && pBssList) {
                struct BssListGuard {
                    PWLAN_BSS_LIST ptr;
                    ~BssListGuard() { if (ptr) WlanFreeMemory(ptr); }
                } bssGuard{pBssList};

                for (DWORD b = 0; b < pBssList->dwNumberOfItems; ++b) {
                    const auto& bss = pBssList->wlanBssEntries[b];

                    // Match BSS entry to our network list by SSID
                    std::string bssSsid;
                    if (bss.dot11Ssid.uSSIDLength > 0 && bss.dot11Ssid.uSSIDLength <= 32) {
                        bssSsid.assign(
                            reinterpret_cast<const char*>(bss.dot11Ssid.ucSSID),
                            bss.dot11Ssid.uSSIDLength);
                    }

                    for (auto& net : networks) {
                        if (net.ssid == bssSsid && net.bssid.empty()) {
                            // Format BSSID from MAC
                            char bssidStr[18]{};
                            snprintf(bssidStr, sizeof(bssidStr),
                                     "%02X:%02X:%02X:%02X:%02X:%02X",
                                     bss.dot11Bssid[0], bss.dot11Bssid[1],
                                     bss.dot11Bssid[2], bss.dot11Bssid[3],
                                     bss.dot11Bssid[4], bss.dot11Bssid[5]);
                            net.bssid = bssidStr;

                            // Extract channel from PHY-specific info
                            net.channel = static_cast<int>(bss.ulChCenterFrequency / 1000);
                            // Convert frequency to channel number
                            uint32_t freqMHz = bss.ulChCenterFrequency / 1000;
                            if (freqMHz >= 2412 && freqMHz <= 2484) {
                                net.channel = static_cast<int>((freqMHz - 2407) / 5);
                            } else if (freqMHz >= 5180 && freqMHz <= 5825) {
                                net.channel = static_cast<int>((freqMHz - 5000) / 5);
                                net.is5GHz = true;
                            }

                            // WPS detection: scan IE data for WPS IE (vendor-specific OUI 00:50:F2:04)
                            if (bss.ulIeSize > 0 && bss.ulIeOffset > 0) {
                                const uint8_t* ieData = reinterpret_cast<const uint8_t*>(&bss) + bss.ulIeOffset;
                                size_t ieSize = bss.ulIeSize;
                                // Cap IE parsing to prevent DoS
                                if (ieSize > 4096) ieSize = 4096;
                                constexpr uint8_t wpsOUI[] = {0x00, 0x50, 0xF2, 0x04};

                                for (size_t pos = 0; pos + 6 < ieSize;) {
                                    uint8_t elemId = ieData[pos];
                                    uint8_t elemLen = ieData[pos + 1];
                                    if (pos + 2 + elemLen > ieSize) break;
                                    if (elemId == 0xDD && elemLen >= 4) { // Vendor-specific
                                        if (memcmp(ieData + pos + 2, wpsOUI, 4) == 0) {
                                            net.wpsEnabled = true;
                                            break;
                                        }
                                    }
                                    pos += 2 + elemLen;
                                }
                            }

                            break;
                        }
                    }
                }
            }
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Found {} wireless networks", networks.size());
#endif

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Wireless enumeration failed - {}",
                           e.what());
    }

    return networks;
}

std::vector<std::string> RouterSecurityCheckerImpl::GetDNSServers() {
    std::vector<std::string> dnsServers;

    try {
#ifdef _WIN32
        ULONG bufferSize = sizeof(FIXED_INFO);
        std::vector<BYTE> buffer(bufferSize);
        PFIXED_INFO pFixedInfo = reinterpret_cast<PFIXED_INFO>(buffer.data());

        DWORD result = GetNetworkParams(pFixedInfo, &bufferSize);
        if (result == ERROR_BUFFER_OVERFLOW) {
            // Reallocate with the size the API told us
            if (bufferSize > 64 * 1024) {
                // Sanity cap — prevent hostile allocation
                ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: GetNetworkParams requested excessive buffer ({})", bufferSize);
                return dnsServers;
            }
            buffer.resize(bufferSize);
            pFixedInfo = reinterpret_cast<PFIXED_INFO>(buffer.data());
            result = GetNetworkParams(pFixedInfo, &bufferSize);
        }

        if (result == NO_ERROR) {
            PIP_ADDR_STRING pDnsServer = &pFixedInfo->DnsServerList;
            constexpr size_t kMaxDnsEntries = 32; // Cap to prevent infinite loop from corrupt data
            size_t count = 0;
            while (pDnsServer && count < kMaxDnsEntries) {
                std::string dns = pDnsServer->IpAddress.String;
                if (!dns.empty() && dns != "0.0.0.0" && IsValidIPv4(dns)) {
                    dnsServers.push_back(std::move(dns));
                }
                pDnsServer = pDnsServer->Next;
                ++count;
            }
        } else {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: GetNetworkParams failed with error {}", result);
        }
#endif

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: DNS server enumeration failed - {}",
                           e.what());
    }

    return dnsServers;
}

std::vector<uint16_t> RouterSecurityCheckerImpl::ScanOpenPorts(
    const std::string& ip)
{
    std::vector<uint16_t> openPorts;

    try {
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Scanning ports on {}",
                          ip);

        // Common ports of interest on router WAN interfaces
        const std::vector<uint16_t> portsToScan = {
            21,   // FTP
            22,   // SSH
            23,   // Telnet (critical if open)
            25,   // SMTP
            53,   // DNS
            80,   // HTTP admin
            135,  // MSRPC
            139,  // NetBIOS
            443,  // HTTPS admin
            445,  // SMB
            993,  // IMAPS
            995,  // POP3S
            1723, // PPTP VPN
            1900, // UPnP SSDP
            3389, // RDP
            5060, // SIP
            7547, // TR-069 (ISP management — dangerous if exposed)
            8080, // HTTP alternate
            8443, // HTTPS alternate
            8888, // HTTP proxy
            9100, // RAW printing
        };

        // Use NetworkUtils::ScanPorts for real TCP connect scanning
        ::ShadowStrike::Utils::NetworkUtils::IpAddress targetAddr;
        std::wstring wideIP = ::ShadowStrike::Utils::StringUtils::ToWide(ip);
        ::ShadowStrike::Utils::NetworkUtils::Error netErr;

        if (!::ShadowStrike::Utils::NetworkUtils::ParseIpAddress(wideIP, targetAddr, &netErr)) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Failed to parse IP for port scan: {}",
                              ip);
            return openPorts;
        }

        // Use configured timeout, cap at 2 seconds per port
        uint32_t timeoutMs = std::min(m_config.defaultAssessmentConfig.timeoutMs / 10, 2000u);
        if (timeoutMs < 500) timeoutMs = 500;

        std::vector<::ShadowStrike::Utils::NetworkUtils::PortScanResult> scanResults;
        if (!::ShadowStrike::Utils::NetworkUtils::ScanPorts(targetAddr, portsToScan, scanResults, timeoutMs, &netErr)) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Port scan call failed");
            return openPorts;
        }

        openPorts.reserve(scanResults.size());
        for (const auto& result : scanResults) {
            if (m_cancelRequested.load(std::memory_order_acquire)) break;
            if (result.isOpen) {
                openPorts.push_back(result.port);

                ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Open port {} ({}) on {}",
                                  result.port,
                                  result.serviceName.empty()
                                      ? std::string("unknown")
                                      : ::ShadowStrike::Utils::StringUtils::WStringToString(result.serviceName),
                                  ip);
            }
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Port scan complete - {} open ports found",
                          openPorts.size());

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Port scan failed - {}",
                           e.what());
    }

    return openPorts;
}

RouterVendor RouterSecurityCheckerImpl::DetectVendor(const std::string& ip) {
    try {
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Detecting vendor for {}",
                          ip);

        // Strategy 1: MAC OUI lookup via ARP table / GetMacAddress
        ::ShadowStrike::Utils::NetworkUtils::IpAddress targetAddr;
        std::wstring wideIP = ::ShadowStrike::Utils::StringUtils::ToWide(ip);
        ::ShadowStrike::Utils::NetworkUtils::Error netErr;

        if (::ShadowStrike::Utils::NetworkUtils::ParseIpAddress(wideIP, targetAddr, &netErr)) {
            ::ShadowStrike::Utils::NetworkUtils::MacAddress mac;
            if (::ShadowStrike::Utils::NetworkUtils::GetMacAddress(targetAddr, mac, &netErr)) {
                // Format MAC as string for OUI lookup
                char macStr[18]{};
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         mac.bytes[0], mac.bytes[1], mac.bytes[2],
                         mac.bytes[3], mac.bytes[4], mac.bytes[5]);

                RouterVendor ouiVendor = LookupOUI(std::string(macStr));
                if (ouiVendor != RouterVendor::Unknown) {
                    ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Vendor identified by OUI: {}",
                                      std::string(GetRouterVendorName(ouiVendor)));
                    return ouiVendor;
                }
            }
        }

        // Strategy 2: HTTP banner fingerprinting from admin interface
        constexpr uint16_t adminPorts[] = { 80, 443, 8080 };
        for (uint16_t port : adminPorts) {
            if (m_cancelRequested.load(std::memory_order_acquire)) break;

            bool useTLS = (port == 443);
            std::wstring url = std::format(L"{}://{}:{}/",
                useTLS ? L"https" : L"http",
                ::ShadowStrike::Utils::StringUtils::ToWide(ip), port);

            ::ShadowStrike::Utils::NetworkUtils::HttpRequestOptions opts;
            opts.timeoutMs = 3000;
            opts.verifySSL = false;
            opts.allowRedirects = false;

            ::ShadowStrike::Utils::NetworkUtils::HttpResponse response;
            if (::ShadowStrike::Utils::NetworkUtils::HttpRequest(url, response, opts) &&
                response.statusCode > 0)
            {
                // Collect all headers and body for banner analysis
                std::string banner;
                banner.reserve(1024);

                for (const auto& hdr : response.headers) {
                    std::string narrow;
                    narrow.reserve(hdr.name.size() + hdr.value.size() + 4);
                    for (wchar_t wc : hdr.name)  narrow.push_back(static_cast<char>(wc & 0x7F));
                    narrow += ": ";
                    for (wchar_t wc : hdr.value) narrow.push_back(static_cast<char>(wc & 0x7F));
                    banner += narrow;
                    banner += "\n";
                }

                // Also check response body (first 2KB only for safety)
                if (!response.body.empty()) {
                    size_t bodyLen = std::min(response.body.size(), size_t{2048});
                    banner.append(reinterpret_cast<const char*>(response.body.data()), bodyLen);
                }

                // Use the DetectRouterVendor helper
                RouterVendor bannerVendor = DetectRouterVendor("", banner);
                if (bannerVendor != RouterVendor::Unknown) {
                    ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Vendor identified by banner: {}",
                                      std::string(GetRouterVendorName(bannerVendor)));
                    return bannerVendor;
                }
            }
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Could not identify vendor for {}",
                          ip);
        return RouterVendor::Unknown;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Vendor detection failed - {}",
                           e.what());
        return RouterVendor::Unknown;
    }
}

void RouterSecurityCheckerImpl::AnalyzeCVEs(RouterSecurityReport& report) {
    try {
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Analyzing CVEs for vendor {}",
                          std::string(GetRouterVendorName(report.vendor)));

        // Step 1: Match CVEs from our curated known-router-CVE database by vendor
        std::vector<const KnownRouterCVE*> matchedCVEs;
        for (const auto& cve : g_knownRouterCVEs) {
            if (m_cancelRequested.load(std::memory_order_acquire)) return;

            // Match vendor-specific CVEs or generic (Unknown vendor = multi-vendor)
            if (cve.vendor == report.vendor || cve.vendor == RouterVendor::Unknown) {
                matchedCVEs.push_back(&cve);
            }
        }

        // Step 2: Optionally enrich with ThreatIntelManager for active exploitation data
        auto& threatIntel = ThreatIntel::ThreatIntelManager::Instance();
        bool hasThreatIntel = threatIntel.IsInitialized();

        for (const auto* cve : matchedCVEs) {
            if (m_cancelRequested.load(std::memory_order_acquire)) return;

            SecurityIssue issue;
            issue.type = SecurityIssueType::KnownCVE;
            issue.title = std::format("Known Vulnerability: {}", cve->cveId);
            issue.description = cve->description;
            issue.evidence = std::format("CVSS Score: {:.1f} | Vendor: {}",
                cve->cvssScore, GetRouterVendorName(cve->vendor));

            // Assign risk level based on CVSS score
            if (cve->cvssScore >= 9.0f) {
                issue.riskLevel = SecurityRiskLevel::Critical;
            } else if (cve->cvssScore >= 7.0f) {
                issue.riskLevel = SecurityRiskLevel::High;
            } else if (cve->cvssScore >= 4.0f) {
                issue.riskLevel = SecurityRiskLevel::Medium;
            } else {
                issue.riskLevel = SecurityRiskLevel::Low;
            }

            issue.remediation = "Update router firmware to the latest version. "
                               "Check vendor security advisories for " + std::string(cve->cveId);

            // Enrich with threat intel if available
            if (hasThreatIntel) {
                auto tiResult = threatIntel.LookupDomain(cve->cveId);
                if (tiResult.found && tiResult.IsMalicious()) {
                    issue.evidence += " | ACTIVE EXPLOITATION detected in threat intelligence";
                    // Upgrade to Critical if actively exploited
                    issue.riskLevel = SecurityRiskLevel::Critical;
                }
            }

            // Track the CVE ID in the report
            report.cveMatches.push_back(std::string(cve->cveId));
            report.securityIssues.push_back(std::move(issue));
        }

        if (!matchedCVEs.empty()) {
            m_statistics.cvesMatched.fetch_add(
                static_cast<uint64_t>(matchedCVEs.size()), std::memory_order_relaxed);

            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: {} potential CVEs matched for {}",
                              matchedCVEs.size(),
                              std::string(GetRouterVendorName(report.vendor)));
        } else {
            ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: No known CVEs matched for vendor");
        }

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: CVE analysis failed - {}",
                           e.what());
    }
}

// ============================================================================
// IMPL: CALLBACKS
// ============================================================================

void RouterSecurityCheckerImpl::InvokeAssessmentCallbacks(
    const RouterSecurityReport& report)
{
    // Copy callbacks under lock, then invoke outside lock to prevent deadlock
    std::vector<AssessmentCallback> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy = m_assessmentCallbacks;
    }
    for (const auto& callback : callbacksCopy) {
        try {
            callback(report);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Assessment callback error - {}",
                               e.what());
        }
    }
}

void RouterSecurityCheckerImpl::InvokeIssueCallbacks(
    const SecurityIssue& issue)
{
    // Copy callbacks under lock, then invoke outside lock to prevent deadlock
    std::vector<IssueFoundCallback> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy = m_issueCallbacks;
    }
    for (const auto& callback : callbacksCopy) {
        try {
            callback(issue);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Issue callback error - {}",
                               e.what());
        }
    }
}

void RouterSecurityCheckerImpl::InvokeProgressCallbacks(
    float progress,
    const std::string& status)
{
    std::vector<ProgressCallback> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy = m_progressCallbacks;
    }
    for (const auto& callback : callbacksCopy) {
        try {
            callback(progress, status);
        } catch (const std::exception& e) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Progress callback error - {}",
                               e.what());
        }
    }
}

void RouterSecurityCheckerImpl::InvokeErrorCallbacks(
    const std::string& message,
    int code)
{
    std::vector<ErrorCallback> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy = m_errorCallbacks;
    }
    for (const auto& callback : callbacksCopy) {
        try {
            callback(message, code);
        } catch (...) {
            // Suppress errors in error handler
        }
    }
}

void RouterSecurityCheckerImpl::UpdateProgress(
    float progress,
    const std::string& status)
{
    m_progress.store(progress, std::memory_order_release);
    InvokeProgressCallbacks(progress, status);
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> RouterSecurityChecker::s_instanceCreated{false};

RouterSecurityChecker& RouterSecurityChecker::Instance() noexcept {
    static RouterSecurityChecker instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool RouterSecurityChecker::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE
// ============================================================================

RouterSecurityChecker::RouterSecurityChecker()
    : m_impl(std::make_unique<RouterSecurityCheckerImpl>())
{
    ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Constructor called");
}

RouterSecurityChecker::~RouterSecurityChecker() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Destructor called");
}

bool RouterSecurityChecker::Initialize(const RouterCheckerConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void RouterSecurityChecker::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool RouterSecurityChecker::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus RouterSecurityChecker::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire)
                  : ModuleStatus::Uninitialized;
}

bool RouterSecurityChecker::UpdateConfiguration(const RouterCheckerConfiguration& config) {
    if (!config.IsValid()) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Invalid configuration");
        return false;
    }

    if (!m_impl) {
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;

    ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Configuration updated");
    return true;
}

RouterCheckerConfiguration RouterSecurityChecker::GetConfiguration() const {
    if (!m_impl) {
        return RouterCheckerConfiguration{};
    }

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// ASSESSMENT
// ============================================================================

std::future<RouterSecurityReport> RouterSecurityChecker::AuditGateway(
    const std::string& gatewayIP)
{
    return std::async(std::launch::async, [this, gatewayIP]() {
        return AuditGatewaySync(gatewayIP, m_impl->m_config.defaultAssessmentConfig);
    });
}

RouterSecurityReport RouterSecurityChecker::AuditGatewaySync(
    const std::string& gatewayIP,
    const RouterAssessmentConfig& config)
{
    return m_impl ? m_impl->AuditGatewaySyncInternal(gatewayIP, config)
                  : RouterSecurityReport{};
}

RouterSecurityReport RouterSecurityChecker::QuickSecurityCheck(const std::string& gatewayIP) {
    return m_impl ? m_impl->QuickSecurityCheckInternal(gatewayIP)
                  : RouterSecurityReport{};
}

void RouterSecurityChecker::CancelAssessment() {
    if (m_impl) {
        m_impl->m_cancelRequested.store(true, std::memory_order_release);
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Assessment cancellation requested");
    }
}

float RouterSecurityChecker::GetProgress() const noexcept {
    return m_impl ? m_impl->m_progress.load(std::memory_order_acquire) : 0.0f;
}

// ============================================================================
// SPECIFIC CHECKS
// ============================================================================

bool RouterSecurityChecker::CheckDefaultCredentials(const std::string& ip) {
    if (!m_impl) {
        return false;
    }

    std::shared_lock lock(m_impl->m_mutex);
    const auto config = m_impl->m_config.defaultAssessmentConfig;
    lock.unlock();
    return m_impl->CheckDefaultCredentialsInternal(ip, config);
}

UPnPInfo RouterSecurityChecker::CheckUPnP(const std::string& ip) {
    return m_impl ? m_impl->CheckUPnPInternal(ip) : UPnPInfo{};
}

bool RouterSecurityChecker::CheckDNSHijacking() {
    return m_impl ? m_impl->CheckDNSHijackingInternal() : false;
}

std::string RouterSecurityChecker::GetDefaultGateway() const {
    return m_impl ? m_impl->GetDefaultGatewayInternal() : "";
}

// ============================================================================
// HISTORY
// ============================================================================

std::optional<RouterSecurityReport> RouterSecurityChecker::GetLastReport() const {
    if (!m_impl) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_historyMutex);

    if (m_impl->m_assessmentHistory.empty()) {
        return std::nullopt;
    }

    return m_impl->m_assessmentHistory.back();
}

std::vector<RouterSecurityReport> RouterSecurityChecker::GetAssessmentHistory(size_t maxEntries) const {
    if (!m_impl) {
        return {};
    }

    std::shared_lock lock(m_impl->m_historyMutex);

    size_t count = std::min(maxEntries, m_impl->m_assessmentHistory.size());
    std::vector<RouterSecurityReport> results;
    results.reserve(count);

    auto it = m_impl->m_assessmentHistory.rbegin();
    for (size_t i = 0; i < count && it != m_impl->m_assessmentHistory.rend(); ++i, ++it) {
        results.push_back(*it);
    }

    return results;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void RouterSecurityChecker::RegisterAssessmentCallback(AssessmentCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_assessmentCallbacks.push_back(std::move(callback));
}

void RouterSecurityChecker::RegisterIssueCallback(IssueFoundCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_issueCallbacks.push_back(std::move(callback));
}

void RouterSecurityChecker::RegisterProgressCallback(ProgressCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_progressCallbacks.push_back(std::move(callback));
}

void RouterSecurityChecker::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void RouterSecurityChecker::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_assessmentCallbacks.clear();
    m_impl->m_issueCallbacks.clear();
    m_impl->m_progressCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

RouterStatistics RouterSecurityChecker::GetStatistics() const {
    return m_impl ? m_impl->m_statistics : RouterStatistics{};
}

void RouterSecurityChecker::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Statistics reset");
    }
}

bool RouterSecurityChecker::SelfTest() {
    try {
        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Starting self-test");

        // Test 1: Initialization
        RouterCheckerConfiguration config;
        config.enabled = true;
        config.autoAssessOnStartup = false;
        config.defaultAssessmentConfig.timeoutMs = 10000;

        if (!Initialize(config)) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Self-test failed - Initialization");
            return false;
        }

        // Test 2: Configuration validation
        if (!config.IsValid()) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Self-test failed - Configuration invalid");
            return false;
        }

        // Test 3: Gateway detection
        auto gateway = GetDefaultGateway();
        if (gateway.empty()) {
            ::ShadowStrike::Utils::Logger::Warn("RouterSecurityChecker: Gateway detection returned empty (non-fatal)");
        }

        // Test 4: DNS enumeration
        if (m_impl) {
            auto dnsServers = m_impl->GetDNSServers();
            ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: DNS servers: {}", dnsServers.size());
        }

        // Test 5: Statistics
        ResetStatistics();
        auto stats = GetStatistics();
        if (stats.totalAssessments.load() != 0) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Self-test failed - Statistics reset");
            return false;
        }

        // Test 6: Default credentials database
        auto credDb = GetDefaultCredentialsDatabase();
        if (credDb.empty()) {
            ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Self-test failed - No credentials in database");
            return false;
        }

        ::ShadowStrike::Utils::Logger::Info("RouterSecurityChecker: Self-test PASSED ({} default credentials)",
                          credDb.size());
        return true;

    } catch (const std::exception& e) {
        ::ShadowStrike::Utils::Logger::Error("RouterSecurityChecker: Self-test exception - {}",
                           e.what());
        return false;
    }
}

std::string RouterSecurityChecker::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
                      RouterConstants::VERSION_MAJOR,
                      RouterConstants::VERSION_MINOR,
                      RouterConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetRouterVendorName(RouterVendor vendor) noexcept {
    switch (vendor) {
        case RouterVendor::Unknown: return "Unknown";
        case RouterVendor::Cisco: return "Cisco";
        case RouterVendor::Netgear: return "Netgear";
        case RouterVendor::TPLink: return "TP-Link";
        case RouterVendor::DLink: return "D-Link";
        case RouterVendor::Asus: return "Asus";
        case RouterVendor::Linksys: return "Linksys";
        case RouterVendor::Belkin: return "Belkin";
        case RouterVendor::Huawei: return "Huawei";
        case RouterVendor::ZTE: return "ZTE";
        case RouterVendor::Ubiquiti: return "Ubiquiti";
        case RouterVendor::MikroTik: return "MikroTik";
        case RouterVendor::Juniper: return "Juniper";
        case RouterVendor::Aruba: return "Aruba";
        case RouterVendor::Fortinet: return "Fortinet";
        case RouterVendor::Meraki: return "Cisco Meraki";
        case RouterVendor::ISP_Provided: return "ISP Provided";
        default: return "Unknown";
    }
}

std::string_view GetWirelessEncryptionName(WirelessEncryption enc) noexcept {
    switch (enc) {
        case WirelessEncryption::Unknown: return "Unknown";
        case WirelessEncryption::Open: return "Open (No Encryption)";
        case WirelessEncryption::WEP: return "WEP";
        case WirelessEncryption::WPA_Personal: return "WPA-Personal";
        case WirelessEncryption::WPA_Enterprise: return "WPA-Enterprise";
        case WirelessEncryption::WPA2_Personal: return "WPA2-Personal";
        case WirelessEncryption::WPA2_Enterprise: return "WPA2-Enterprise";
        case WirelessEncryption::WPA3_Personal: return "WPA3-Personal";
        case WirelessEncryption::WPA3_Enterprise: return "WPA3-Enterprise";
        case WirelessEncryption::WPA3_SAE: return "WPA3-SAE";
        case WirelessEncryption::Mixed: return "Mixed Mode";
        default: return "Unknown";
    }
}

std::string_view GetSecurityRiskLevelName(SecurityRiskLevel level) noexcept {
    switch (level) {
        case SecurityRiskLevel::Secure: return "Secure";
        case SecurityRiskLevel::Informational: return "Informational";
        case SecurityRiskLevel::Low: return "Low";
        case SecurityRiskLevel::Medium: return "Medium";
        case SecurityRiskLevel::High: return "High";
        case SecurityRiskLevel::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetSecurityIssueTypeName(SecurityIssueType type) noexcept {
    switch (type) {
        case SecurityIssueType::None: return "None";
        case SecurityIssueType::DefaultCredentials: return "Default Credentials";
        case SecurityIssueType::WeakPassword: return "Weak Password";
        case SecurityIssueType::WeakEncryption: return "Weak Encryption";
        case SecurityIssueType::WEPEnabled: return "WEP Enabled";
        case SecurityIssueType::WPSEnabled: return "WPS Enabled";
        case SecurityIssueType::UPnPEnabled: return "UPnP Enabled";
        case SecurityIssueType::TelnetEnabled: return "Telnet Enabled";
        case SecurityIssueType::HTTPAdmin: return "HTTP Admin";
        case SecurityIssueType::WANAdminAccess: return "WAN Admin Access";
        case SecurityIssueType::DNSHijacked: return "DNS Hijacked";
        case SecurityIssueType::OutdatedFirmware: return "Outdated Firmware";
        case SecurityIssueType::KnownCVE: return "Known CVE";
        case SecurityIssueType::OpenPorts: return "Open Ports";
        case SecurityIssueType::DMZEnabled: return "DMZ Enabled";
        case SecurityIssueType::NoFirewall: return "No Firewall";
        case SecurityIssueType::GuestNetworkUnsecured: return "Guest Network Unsecured";
        case SecurityIssueType::RemoteManagement: return "Remote Management";
        case SecurityIssueType::SNMPPublicCommunity: return "SNMP Public Community";
        case SecurityIssueType::TR069Exposed: return "TR-069 Exposed";
        case SecurityIssueType::BackdoorDetected: return "Backdoor Detected";
        default: return "Unknown";
    }
}

RouterVendor DetectRouterVendor(const std::string& mac, const std::string& banner) {
    // Step 1: Try OUI lookup from MAC address
    if (!mac.empty()) {
        RouterVendor ouiResult = LookupOUI(mac);
        if (ouiResult != RouterVendor::Unknown) {
            return ouiResult;
        }
    }

    // Step 2: Banner string fingerprinting (case-insensitive)
    if (banner.empty()) {
        return RouterVendor::Unknown;
    }

    // Cap banner analysis to 8KB to prevent DoS from hostile responses
    std::string lowerBanner;
    size_t safeLen = std::min(banner.size(), size_t{8192});
    lowerBanner.reserve(safeLen);
    for (size_t i = 0; i < safeLen; ++i) {
        lowerBanner.push_back(
            static_cast<char>(std::tolower(static_cast<unsigned char>(banner[i]))));
    }

    // Vendor keyword matching with multiple patterns per vendor
    struct VendorPattern {
        const char* pattern;
        RouterVendor vendor;
    };

    static constexpr VendorPattern patterns[] = {
        {"cisco",       RouterVendor::Cisco},
        {"ios xe",      RouterVendor::Cisco},
        {"aironet",     RouterVendor::Cisco},
        {"meraki",      RouterVendor::Meraki},
        {"netgear",     RouterVendor::Netgear},
        {"nighthawk",   RouterVendor::Netgear},
        {"orbi",        RouterVendor::Netgear},
        {"tp-link",     RouterVendor::TPLink},
        {"tplink",      RouterVendor::TPLink},
        {"archer",      RouterVendor::TPLink},
        {"deco",        RouterVendor::TPLink},
        {"d-link",      RouterVendor::DLink},
        {"dlink",       RouterVendor::DLink},
        {"dir-",        RouterVendor::DLink},
        {"dap-",        RouterVendor::DLink},
        {"asus",        RouterVendor::Asus},
        {"asuswrt",     RouterVendor::Asus},
        {"rt-ax",       RouterVendor::Asus},
        {"rt-ac",       RouterVendor::Asus},
        {"linksys",     RouterVendor::Linksys},
        {"velop",       RouterVendor::Linksys},
        {"belkin",      RouterVendor::Belkin},
        {"huawei",      RouterVendor::Huawei},
        {"echolife",    RouterVendor::Huawei},
        {"zte",         RouterVendor::ZTE},
        {"zxhn",        RouterVendor::ZTE},
        {"ubiquiti",    RouterVendor::Ubiquiti},
        {"unifi",       RouterVendor::Ubiquiti},
        {"edgerouter",  RouterVendor::Ubiquiti},
        {"mikrotik",    RouterVendor::MikroTik},
        {"routeros",    RouterVendor::MikroTik},
        {"juniper",     RouterVendor::Juniper},
        {"junos",       RouterVendor::Juniper},
        {"srx",         RouterVendor::Juniper},
        {"aruba",       RouterVendor::Aruba},
        {"arubaos",     RouterVendor::Aruba},
        {"fortinet",    RouterVendor::Fortinet},
        {"fortigate",   RouterVendor::Fortinet},
        {"fortios",     RouterVendor::Fortinet},
    };

    for (const auto& p : patterns) {
        if (lowerBanner.find(p.pattern) != std::string::npos) {
            return p.vendor;
        }
    }

    return RouterVendor::Unknown;
}

SecurityRiskLevel GetEncryptionRiskLevel(WirelessEncryption enc) noexcept {
    switch (enc) {
        case WirelessEncryption::Open:
            return SecurityRiskLevel::High;
        case WirelessEncryption::WEP:
            return SecurityRiskLevel::Critical;
        case WirelessEncryption::WPA_Personal:
        case WirelessEncryption::WPA_Enterprise:
            return SecurityRiskLevel::Medium;
        case WirelessEncryption::WPA2_Personal:
        case WirelessEncryption::WPA2_Enterprise:
            return SecurityRiskLevel::Low;
        case WirelessEncryption::WPA3_Personal:
        case WirelessEncryption::WPA3_Enterprise:
        case WirelessEncryption::WPA3_SAE:
            return SecurityRiskLevel::Secure;
        case WirelessEncryption::Mixed:
            return SecurityRiskLevel::Medium;
        default:
            return SecurityRiskLevel::Informational;
    }
}

}  // namespace IoT
}  // namespace ShadowStrike
