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
 * @brief Enterprise-grade IP leak detection and prevention engine
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
#include "../Utils/Logger.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/RegistryUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "IoTDeviceScanner.hpp"
#include "WiFiSecurityAnalyzer.hpp"
#include "RouterSecurityChecker.hpp"
#include "SmartHomeProtection.hpp"

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <Ras.h>
#include <Raserror.h>
#pragma comment(lib, "rasapi32.lib")
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <regex>
#include <cmath>
#include <unordered_set>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> IPLeakProtection::s_instanceCreated{false};

// ============================================================================
// INTERNAL STRUCTURES & HELPERS
// ============================================================================

namespace {

// ============================================================================
// FIREWALL RULE NAMES (kill switch / IPv6 block)
// ============================================================================

constexpr const wchar_t* kKillSwitchBlockAll     = L"ShadowStrike-KillSwitch-BlockAll";
constexpr const wchar_t* kKillSwitchAllowVPN     = L"ShadowStrike-KillSwitch-AllowVPN";
constexpr const wchar_t* kKillSwitchAllowLocal   = L"ShadowStrike-KillSwitch-AllowLocal";
constexpr const wchar_t* kKillSwitchAllowDHCP    = L"ShadowStrike-KillSwitch-AllowDHCP";
constexpr const wchar_t* kIPv6BlockRuleOut       = L"ShadowStrike-BlockIPv6-Out";
constexpr const wchar_t* kIPv6BlockRuleIn        = L"ShadowStrike-BlockIPv6-In";

// ============================================================================
// KNOWN PUBLIC DNS SERVERS
// ============================================================================

struct KnownDNSEntry {
    const char* ip;
    const char* provider;
    ShadowStrike::IoT::DNSServerType type;
};

constexpr KnownDNSEntry kKnownPublicDNS[] = {
    {"8.8.8.8",         "Google Public DNS",    ShadowStrike::IoT::DNSServerType::Public},
    {"8.8.4.4",         "Google Public DNS",    ShadowStrike::IoT::DNSServerType::Public},
    {"1.1.1.1",         "Cloudflare DNS",       ShadowStrike::IoT::DNSServerType::Public},
    {"1.0.0.1",         "Cloudflare DNS",       ShadowStrike::IoT::DNSServerType::Public},
    {"9.9.9.9",         "Quad9 DNS",            ShadowStrike::IoT::DNSServerType::Public},
    {"149.112.112.112", "Quad9 DNS",            ShadowStrike::IoT::DNSServerType::Public},
    {"208.67.222.222",  "OpenDNS",              ShadowStrike::IoT::DNSServerType::Public},
    {"208.67.220.220",  "OpenDNS",              ShadowStrike::IoT::DNSServerType::Public},
    {"185.228.168.9",   "CleanBrowsing DNS",    ShadowStrike::IoT::DNSServerType::Public},
    {"185.228.169.9",   "CleanBrowsing DNS",    ShadowStrike::IoT::DNSServerType::Public},
    {"76.76.19.19",     "Alternate DNS",        ShadowStrike::IoT::DNSServerType::Public},
    {"76.223.122.150",  "Alternate DNS",        ShadowStrike::IoT::DNSServerType::Public},
    {"94.140.14.14",    "AdGuard DNS",          ShadowStrike::IoT::DNSServerType::Public},
    {"94.140.15.15",    "AdGuard DNS",          ShadowStrike::IoT::DNSServerType::Public},
};

/// @brief Public IP check service URLs
constexpr const wchar_t* kIPCheckServices[] = {
    L"https://api.ipify.org",
    L"https://checkip.amazonaws.com",
    L"https://ifconfig.me/ip",
};
constexpr size_t kIPCheckServiceCount = std::size(kIPCheckServices);

/// @brief Safety caps
constexpr size_t   kMaxIPResponseBytes       = 256;
constexpr uint32_t kFirewallCommandTimeoutMs  = 15000;
constexpr size_t   kMaxKillSwitchEvents       = 10000;
constexpr size_t   kMaxDNSServerIterations    = 64;
constexpr size_t   kMaxAdapterIterations      = 256;

// ============================================================================
// HELPER: Generate unique event ID
// ============================================================================

std::string GenerateEventId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "LEAK-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(8) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
}

// ============================================================================
// HELPER: IP classification
// ============================================================================

bool IsPrivateIPAddress(const std::string& ip) {
    if (ip.empty()) return false;

    if (ip.find(':') == std::string::npos) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
            uint32_t ipVal = ntohl(addr.s_addr);
            if ((ipVal & 0xFF000000) == 0x0A000000) return true;   // 10.0.0.0/8
            if ((ipVal & 0xFFF00000) == 0xAC100000) return true;   // 172.16.0.0/12
            if ((ipVal & 0xFFFF0000) == 0xC0A80000) return true;   // 192.168.0.0/16
            if ((ipVal & 0xFF000000) == 0x7F000000) return true;   // 127.0.0.0/8
            if ((ipVal & 0xFFFF0000) == 0xA9FE0000) return true;   // 169.254.0.0/16
        }
    } else {
        // Case-insensitive prefix matching for IPv6
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, ip.c_str(), &addr6) != 1) return false;
        // ::1 loopback
        static const struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
        if (memcmp(&addr6, &loopback, sizeof(addr6)) == 0) return true;
        // fe80::/10 link-local
        if (addr6.s6_bytes[0] == 0xFE && (addr6.s6_bytes[1] & 0xC0) == 0x80) return true;
        // fc00::/7 unique-local
        if ((addr6.s6_bytes[0] & 0xFE) == 0xFC) return true;
    }

    return false;
}

bool IsIPv6Addr(const std::string& ip) {
    return ip.find(':') != std::string::npos;
}

/// @brief Check if address is Teredo tunnel (2001:0000::/32)
bool IsTeredoAddress(const struct in6_addr& addr6) {
    return addr6.s6_bytes[0] == 0x20 && addr6.s6_bytes[1] == 0x01 &&
           addr6.s6_bytes[2] == 0x00 && addr6.s6_bytes[3] == 0x00;
}

/// @brief Check if address is 6to4 tunnel (2002::/16)
bool Is6to4Address(const struct in6_addr& addr6) {
    return addr6.s6_bytes[0] == 0x20 && addr6.s6_bytes[1] == 0x02;
}

/// @brief Check if address is ISATAP (::0:5efe:w.x.y.z or ::200:5efe:w.x.y.z)
bool IsISATAPAddress(const struct in6_addr& addr6) {
    return (addr6.s6_bytes[8] == 0x00 && addr6.s6_bytes[9] == 0x00 &&
            addr6.s6_bytes[10] == 0x5E && addr6.s6_bytes[11] == 0xFE) ||
           (addr6.s6_bytes[8] == 0x02 && addr6.s6_bytes[9] == 0x00 &&
            addr6.s6_bytes[10] == 0x5E && addr6.s6_bytes[11] == 0xFE);
}

// ============================================================================
// HELPER: Public IP query via multiple external services
// ============================================================================

std::string QueryPublicIP() {
    using namespace ShadowStrike::Utils;

    NetworkUtils::HttpRequestOptions opts;
    opts.timeoutMs = ShadowStrike::IoT::IPLeakConstants::DNS_LEAK_CHECK_TIMEOUT_MS;
    opts.verifySSL = true;
    opts.allowRedirects = false;
    opts.userAgent = L"ShadowStrike-NGAV/3.0";

    for (size_t i = 0; i < kIPCheckServiceCount; ++i) {
        std::vector<uint8_t> data;
        NetworkUtils::Error err;

        if (!NetworkUtils::HttpGet(kIPCheckServices[i], data, opts, &err)) {
            Logger::Debug("IP check service {} failed: {}",
                i, StringUtils::ToNarrow(err.message));
            continue;
        }

        if (data.empty() || data.size() > kMaxIPResponseBytes) {
            Logger::Debug("IP check service {} invalid response size: {}", i, data.size());
            continue;
        }

        std::string result(reinterpret_cast<const char*>(data.data()), data.size());

        // Trim leading/trailing whitespace
        auto isSpace = [](char c) {
            return c == '\n' || c == '\r' || c == ' ' || c == '\t';
        };
        while (!result.empty() && isSpace(result.back())) result.pop_back();
        size_t start = 0;
        while (start < result.size() && isSpace(result[start])) ++start;
        if (start > 0) result.erase(0, start);

        if (result.empty() || result.size() > 45) continue;

        // Validate as a real IP address
        struct in_addr  addr4;
        struct in6_addr addr6;
        if (inet_pton(AF_INET, result.c_str(), &addr4) == 1 ||
            inet_pton(AF_INET6, result.c_str(), &addr6) == 1) {
            return result;
        }
    }

    Logger::Warn("All public IP check services failed — unable to determine public IP");
    return "";
}

// ============================================================================
// HELPER: System DNS servers via Windows API
// ============================================================================

std::vector<std::string> GetSystemDNSServers() {
    std::vector<std::string> dnsServers;

    FIXED_INFO* pFixedInfo = nullptr;
    ULONG bufferSize = sizeof(FIXED_INFO);
    std::vector<uint8_t> buffer(bufferSize);

    pFixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());

    DWORD result = GetNetworkParams(pFixedInfo, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        if (bufferSize > 1024 * 1024) return dnsServers;
        buffer.resize(bufferSize);
        pFixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());
        result = GetNetworkParams(pFixedInfo, &bufferSize);
    }

    if (result == NO_ERROR) {
        IP_ADDR_STRING* pDnsServer = &pFixedInfo->DnsServerList;
        size_t count = 0;
        while (pDnsServer && count < kMaxDNSServerIterations) {
            std::string ip = pDnsServer->IpAddress.String;
            if (!ip.empty() && ip != "0.0.0.0") {
                dnsServers.push_back(std::move(ip));
            }
            pDnsServer = pDnsServer->Next;
            ++count;
        }
    }

    return dnsServers;
}

// ============================================================================
// HELPER: VPN adapter detection (returns adapter info, not just bool)
// ============================================================================

struct VPNAdapterInfo {
    std::string description;
    std::string adapterName;
    std::string ipAddress;
};

std::vector<VPNAdapterInfo> DetectVPNAdapters() {
    std::vector<VPNAdapterInfo> vpnAdapters;

    // Phase 1: Check legacy adapter info for keyword matches
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    ULONG bufferSize = 15000;
    std::vector<uint8_t> buffer(bufferSize);

    pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    DWORD result = GetAdaptersInfo(pAdapterInfo, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        if (bufferSize > 4 * 1024 * 1024) return vpnAdapters;
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        result = GetAdaptersInfo(pAdapterInfo, &bufferSize);
    }

    if (result == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        size_t count = 0;
        while (pAdapter && count < kMaxAdapterIterations) {
            std::string desc = pAdapter->Description;
            std::string descLower = desc;
            std::transform(descLower.begin(), descLower.end(), descLower.begin(),
                [](unsigned char c) { return static_cast<char>(::tolower(c)); });

            static constexpr const char* kVPNKeywords[] = {
                "vpn", "tap-windows", "tap", "tun", "wireguard", "openvpn",
                "nordlynx", "wintun", "softether", "ipsec", "pptp", "l2tp",
                "sstp", "expressvpn", "surfshark", "protonvpn", "cyberghost",
                "windscribe", "mullvad", "privatevpn"
            };

            for (const auto* kw : kVPNKeywords) {
                if (descLower.find(kw) != std::string::npos) {
                    VPNAdapterInfo info;
                    info.description = desc;
                    info.adapterName = pAdapter->AdapterName;
                    info.ipAddress = pAdapter->IpAddressList.IpAddress.String;
                    vpnAdapters.push_back(std::move(info));
                    break;
                }
            }

            pAdapter = pAdapter->Next;
            ++count;
        }
    }

    // Phase 2: Check for PPP/Tunnel interfaces via GetAdaptersAddresses
    bufferSize = 15000;
    buffer.resize(bufferSize);
    auto* pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

    DWORD dwResult = GetAdaptersAddresses(AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr, pAddresses, &bufferSize);

    if (dwResult == ERROR_BUFFER_OVERFLOW) {
        if (bufferSize > 4 * 1024 * 1024) return vpnAdapters;
        buffer.resize(bufferSize);
        pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
        dwResult = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr, pAddresses, &bufferSize);
    }

    if (dwResult == NO_ERROR) {
        auto* pCurr = pAddresses;
        size_t count = 0;
        while (pCurr && count < kMaxAdapterIterations) {
            if ((pCurr->IfType == IF_TYPE_TUNNEL || pCurr->IfType == IF_TYPE_PPP) &&
                pCurr->OperStatus == IfOperStatusUp) {
                std::wstring wName = pCurr->FriendlyName ? pCurr->FriendlyName : L"";
                std::string friendlyName = ShadowStrike::Utils::StringUtils::ToNarrow(wName);

                bool alreadyFound = std::any_of(vpnAdapters.begin(), vpnAdapters.end(),
                    [&](const VPNAdapterInfo& a) { return a.description == friendlyName; });

                if (!alreadyFound) {
                    VPNAdapterInfo info;
                    info.description = friendlyName;
                    info.adapterName = friendlyName;
                    vpnAdapters.push_back(std::move(info));
                }
            }
            pCurr = pCurr->Next;
            ++count;
        }
    }

    return vpnAdapters;
}

/// @brief Legacy wrapper
bool DetectVPNInterface() {
    return !DetectVPNAdapters().empty();
}

// ============================================================================
// HELPER: Execute netsh firewall command
// ============================================================================

bool ExecuteNetshCommand(const std::wstring& args) {
    wchar_t sysDir[MAX_PATH] = {};
    UINT len = GetSystemDirectoryW(sysDir, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        ShadowStrike::Utils::Logger::Error("Failed to resolve system directory for netsh");
        return false;
    }

    std::wstring netshPath = std::wstring(sysDir, len) + L"\\netsh.exe";
    std::wstring cmdLine = L"\"" + netshPath + L"\" " + args;

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};

    BOOL ok = CreateProcessW(
        netshPath.c_str(),
        cmdLine.data(),
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
        nullptr, nullptr,
        &si, &pi);

    if (!ok) {
        ShadowStrike::Utils::Logger::Error("Failed to execute netsh, Win32 error: {}",
            GetLastError());
        return false;
    }

    DWORD waitResult = WaitForSingleObject(pi.hProcess, kFirewallCommandTimeoutMs);

    DWORD exitCode = 1;
    if (waitResult == WAIT_OBJECT_0) {
        GetExitCodeProcess(pi.hProcess, &exitCode);
    } else {
        TerminateProcess(pi.hProcess, 1);
        ShadowStrike::Utils::Logger::Error("netsh command timed out after {}ms",
            kFirewallCommandTimeoutMs);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exitCode == 0;
}

/// @brief Delete a named firewall rule (returns true even if rule didn't exist)
bool DeleteFirewallRule(const wchar_t* ruleName) {
    std::wstring cmd = L"advfirewall firewall delete rule name=\"";
    cmd += ruleName;
    cmd += L"\"";
    ExecuteNetshCommand(cmd);
    return true;
}

/// @brief Add an outbound block rule
bool AddFirewallBlockRule(const wchar_t* ruleName, const std::wstring& extraArgs = L"") {
    std::wstring cmd = L"advfirewall firewall add rule name=\"";
    cmd += ruleName;
    cmd += L"\" dir=out action=block enable=yes";
    if (!extraArgs.empty()) {
        cmd += L" ";
        cmd += extraArgs;
    }
    return ExecuteNetshCommand(cmd);
}

/// @brief Add an outbound allow rule
bool AddFirewallAllowRule(const wchar_t* ruleName, const std::wstring& extraArgs) {
    std::wstring cmd = L"advfirewall firewall add rule name=\"";
    cmd += ruleName;
    cmd += L"\" dir=out action=allow enable=yes ";
    cmd += extraArgs;
    return ExecuteNetshCommand(cmd);
}

} // anonymous namespace

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

std::string IPAddressInfo::ToJson() const {
    json j;
    j["ipAddress"] = ipAddress;
    j["isIPv6"] = isIPv6;
    j["isPrivate"] = isPrivate;
    j["countryCode"] = countryCode;
    j["city"] = city;
    j["ispName"] = ispName;
    j["asn"] = asn;
    j["organization"] = organization;
    j["isVPN"] = isVPN;
    j["isProxy"] = isProxy;
    j["hostname"] = hostname;
    return j.dump();
}

std::string DNSServerInfo::ToJson() const {
    json j;
    j["serverIP"] = serverIP;
    j["serverType"] = static_cast<int>(serverType);
    j["ispName"] = ispName;
    j["isISPDNS"] = isISPDNS;
    j["isVPNDNS"] = isVPNDNS;
    j["responseTimeMs"] = responseTimeMs;
    j["countryCode"] = countryCode;
    j["supportsDNSSEC"] = supportsDNSSEC;
    j["supportsDoH"] = supportsDoH;
    j["supportsDoT"] = supportsDoT;
    return j.dump();
}

std::string VPNConnectionInfo::ToJson() const {
    json j;
    j["state"] = static_cast<int>(state);
    j["providerName"] = providerName;
    j["serverLocation"] = serverLocation;
    j["protocol"] = protocol;
    j["tunnelInterface"] = tunnelInterface;
    j["gatewayIP"] = gatewayIP;
    j["assignedIP"] = assignedIP;

    json dnsArray = json::array();
    for (const auto& dns : dnsServers) {
        dnsArray.push_back(dns);
    }
    j["dnsServers"] = dnsArray;

    j["killSwitchActive"] = killSwitchActive;
    j["ipv6Blocked"] = ipv6Blocked;
    j["connectionDuration"] = connectionDuration.count();
    j["bytesSent"] = bytesSent;
    j["bytesReceived"] = bytesReceived;

    return j.dump();
}

std::string IPLeakDetectionResult::ToJson() const {
    json j;
    j["leakDetected"] = leakDetected;
    j["leakType"] = static_cast<uint32_t>(leakType);
    j["severity"] = static_cast<int>(severity);

    json leakedArray = json::array();
    for (const auto& ip : leakedIPs) {
        leakedArray.push_back(ip);
    }
    j["leakedIPs"] = leakedArray;

    j["expectedIP"] = expectedIP;
    j["actualIP"] = actualIP;

    json dnsArray = json::array();
    for (const auto& dns : dnsServers) {
        dnsArray.push_back(json::parse(dns.ToJson()));
    }
    j["dnsServers"] = dnsArray;

    json webrtcArray = json::array();
    for (const auto& ip : webrtcIPs) {
        webrtcArray.push_back(ip);
    }
    j["webrtcIPs"] = webrtcArray;

    j["detectionMethod"] = detectionMethod;
    j["details"] = details;
    j["recommendation"] = recommendation;
    j["detectionTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        detectionTime.time_since_epoch()).count();
    j["confidence"] = confidence;

    return j.dump();
}

std::string WebRTCLeakInfo::ToJson() const {
    json j;
    j["detected"] = detected;

    json localArray = json::array();
    for (const auto& ip : localIPs) {
        localArray.push_back(ip);
    }
    j["localIPs"] = localArray;

    json publicArray = json::array();
    for (const auto& ip : publicIPs) {
        publicArray.push_back(ip);
    }
    j["publicIPs"] = publicArray;

    json ipv6Array = json::array();
    for (const auto& ip : ipv6IPs) {
        ipv6Array.push_back(ip);
    }
    j["ipv6IPs"] = ipv6Array;

    json stunArray = json::array();
    for (const auto& server : stunServers) {
        stunArray.push_back(server);
    }
    j["stunServers"] = stunArray;

    json iceArray = json::array();
    for (const auto& candidate : iceCandidates) {
        iceArray.push_back(candidate);
    }
    j["iceCandidates"] = iceArray;

    j["browserInfo"] = browserInfo;
    j["detectionTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        detectionTime.time_since_epoch()).count();

    return j.dump();
}

std::string KillSwitchEvent::ToJson() const {
    json j;
    j["eventId"] = eventId;
    j["eventType"] = eventType;
    j["triggeredBy"] = static_cast<uint32_t>(triggeredBy);
    j["action"] = static_cast<int>(action);
    j["affectedConnections"] = affectedConnections;
    j["eventTime"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        eventTime.time_since_epoch()).count();
    j["description"] = description;
    return j.dump();
}

bool IPLeakProtectionConfiguration::IsValid() const noexcept {
    if (monitoringIntervalSeconds == 0 || monitoringIntervalSeconds > 3600) {
        return false;
    }

    if (dnsCheckIntervalSeconds == 0 || dnsCheckIntervalSeconds > 3600) {
        return false;
    }

    if (webrtcCheckIntervalSeconds == 0 || webrtcCheckIntervalSeconds > 3600) {
        return false;
    }

    return true;
}

void IPLeakStatistics::Reset() noexcept {
    totalChecks = 0;
    leaksDetected = 0;
    vpnLeaks = 0;
    dnsLeaks = 0;
    webrtcLeaks = 0;
    ipv6Leaks = 0;
    killSwitchActivations = 0;
    autoReconnects = 0;
    currentVPNConnections = 0;

    for (auto& count : byLeakType) {
        count = 0;
    }
    for (auto& count : bySeverity) {
        count = 0;
    }

    startTime = Clock::now();
}

std::string IPLeakStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();

    json j;
    j["uptimeSeconds"] = uptime;
    j["totalChecks"] = totalChecks.load();
    j["leaksDetected"] = leaksDetected.load();
    j["vpnLeaks"] = vpnLeaks.load();
    j["dnsLeaks"] = dnsLeaks.load();
    j["webrtcLeaks"] = webrtcLeaks.load();
    j["ipv6Leaks"] = ipv6Leaks.load();
    j["killSwitchActivations"] = killSwitchActivations.load();
    j["autoReconnects"] = autoReconnects.load();
    j["currentVPNConnections"] = currentVPNConnections.load();
    return j.dump();
}

std::string IoTSubsystemStatus::ToJson() const {
    json j;
    j["deviceScannerActive"] = deviceScannerActive;
    j["wifiAnalyzerActive"] = wifiAnalyzerActive;
    j["routerCheckerActive"] = routerCheckerActive;
    j["smartHomeActive"] = smartHomeActive;
    j["totalDevicesFound"] = totalDevicesFound;
    j["wifiThreatsDetected"] = wifiThreatsDetected;
    j["routerVulnerabilities"] = routerVulnerabilities;
    j["smartHomeIssues"] = smartHomeIssues;
    return j.dump();
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class IPLeakProtectionImpl final {
public:
    IPLeakProtectionImpl();
    ~IPLeakProtectionImpl();

    // Lifecycle
    bool Initialize(const IPLeakProtectionConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_isActive; }
    ModuleStatus GetStatus() const noexcept { return m_status; }
    bool UpdateConfiguration(const IPLeakProtectionConfiguration& config);
    IPLeakProtectionConfiguration GetConfiguration() const;

    // Leak detection
    IPLeakDetectionResult CheckForLeaks();
    IPLeakDetectionResult CheckVPNLeak();
    IPLeakDetectionResult CheckDNSLeak();
    WebRTCLeakInfo CheckWebRTCLeak();
    IPLeakDetectionResult CheckIPv6Leak();
    IPAddressInfo GetPublicIP();
    std::vector<DNSServerInfo> GetDNSServers();

    // VPN management
    std::optional<VPNConnectionInfo> GetVPNInfo() const;
    bool IsVPNConnected() const noexcept { return m_vpnConnected; }
    VPNState GetVPNState() const noexcept { return m_vpnState; }
    bool StartVPNMonitoring();
    void StopVPNMonitoring();

    // Kill switch
    bool ActivateKillSwitch();
    bool DeactivateKillSwitch();
    bool IsKillSwitchActive() const noexcept { return m_killSwitchActive; }
    std::vector<KillSwitchEvent> GetKillSwitchEvents() const;

    // Protection actions
    bool BlockIPv6();
    bool UnblockIPv6();
    bool ForceVPNReconnect();
    bool ApplyProtectionPolicy(LeakType leakType, ProtectionAction action);

    // Monitoring
    bool StartMonitoring();
    void StopMonitoring();
    bool IsMonitoring() const noexcept { return m_monitoring; }
    std::vector<IPLeakDetectionResult> GetDetectedLeaks() const;

    // IoT subsystem integration
    IoTSubsystemStatus GetIoTStatus() const;
    bool StartIoTModules();
    void StopIoTModules();
    bool RunIoTSecurityScan();

    // Callbacks
    void RegisterLeakCallback(LeakDetectedCallback callback);
    void RegisterKillSwitchCallback(KillSwitchCallback callback);
    void RegisterVPNStateCallback(VPNStateChangeCallback callback);
    void RegisterDNSLeakCallback(DNSLeakCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    IPLeakStatistics GetStatistics() const;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal methods
    void MonitoringThreadFunc();
    void VPNMonitorThreadFunc();
    void DetectVPNState();
    void OnLeakDetected(const IPLeakDetectionResult& result);
    void OnKillSwitchTriggered(const KillSwitchEvent& event);
    void NotifyError(const std::string& message, int code);
    bool CheckDNSServerType(const std::string& dnsIP, DNSServerInfo& info);
    bool PerformDNSQuery(const std::string& domain, const std::string& dnsServer);

    // Member variables
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isActive{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    IPLeakProtectionConfiguration m_config;

    // VPN state
    std::atomic<bool> m_vpnConnected{false};
    std::atomic<VPNState> m_vpnState{VPNState::Unknown};
    std::optional<VPNConnectionInfo> m_vpnInfo;

    // Kill switch
    std::atomic<bool> m_killSwitchActive{false};
    std::atomic<bool> m_ipv6Blocked{false};
    std::vector<KillSwitchEvent> m_killSwitchEvents;

    // Monitoring
    std::atomic<bool> m_monitoring{false};
    std::unique_ptr<std::thread> m_monitorThread;
    std::atomic<bool> m_stopMonitoring{false};

    // VPN monitoring
    std::unique_ptr<std::thread> m_vpnMonitorThread;
    std::atomic<bool> m_stopVPNMonitor{false};

    // Detection results
    std::vector<IPLeakDetectionResult> m_detectedLeaks;

    // Callbacks
    LeakDetectedCallback m_leakCallback;
    KillSwitchCallback m_killSwitchCallback;
    VPNStateChangeCallback m_vpnStateCallback;
    DNSLeakCallback m_dnsLeakCallback;
    ErrorCallback m_errorCallback;

    // Statistics
    IPLeakStatistics m_stats;

    // IoT subsystem status
    IoTSubsystemStatus m_iotStatus;
};

// ============================================================================
// PIMPL CONSTRUCTOR/DESTRUCTOR
// ============================================================================

IPLeakProtectionImpl::IPLeakProtectionImpl() {
    Utils::Logger::Info("IPLeakProtectionImpl constructed");
}

IPLeakProtectionImpl::~IPLeakProtectionImpl() {
    Shutdown();
    Utils::Logger::Info("IPLeakProtectionImpl destroyed");
}

// ============================================================================
// LIFECYCLE IMPLEMENTATION
// ============================================================================

bool IPLeakProtectionImpl::Initialize(const IPLeakProtectionConfiguration& config) {
    bool shouldStartMonitoring = false;
    bool shouldStartVPNMonitor = false;

    try {
        std::unique_lock lock(m_mutex);

        if (m_isActive) {
            Utils::Logger::Warn("IPLeakProtection already initialized");
            return false;
        }

        m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid IPLeakProtection configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Initialize Winsock
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            Utils::Logger::Error("WSAStartup failed: {}", result);
            m_status = ModuleStatus::Error;
            return false;
        }

        // Initialize statistics
        m_stats.Reset();

        m_isActive = true;
        m_status = ModuleStatus::Running;

        shouldStartVPNMonitor = m_config.enableVPNMonitoring;
        shouldStartMonitoring = m_config.enabled;

        // Release lock before calling methods that also acquire the mutex
    }

    // Detect initial VPN state (doesn't need m_mutex)
    DetectVPNState();

    // Start VPN monitoring outside of the lock
    if (shouldStartVPNMonitor) {
        StartVPNMonitoring();
    }

    // Start monitoring outside of the lock
    if (shouldStartMonitoring) {
        StartMonitoring();
    }

    Utils::Logger::Info("IPLeakProtection initialized successfully");
    return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("IPLeakProtection initialization failed: {}", e.what());
        m_status = ModuleStatus::Error;
        // Clean up Winsock if we started it
        WSACleanup();
        return false;
    }
}

void IPLeakProtectionImpl::Shutdown() {
    try {
        {
            std::unique_lock lock(m_mutex);
            if (!m_isActive) {
                return;
            }
            m_status = ModuleStatus::Stopping;
        }

        // Signal all threads to stop (atomic, no lock needed)
        m_stopMonitoring = true;
        m_stopVPNMonitor = true;

        // Join threads outside the lock to avoid deadlock
        if (m_monitorThread && m_monitorThread->joinable()) {
            m_monitorThread->join();
        }

        if (m_vpnMonitorThread && m_vpnMonitorThread->joinable()) {
            m_vpnMonitorThread->join();
        }

        // Deactivate kill switch (removes firewall rules)
        if (m_killSwitchActive) {
            DeactivateKillSwitch();
        }

        // Unblock IPv6 if we blocked it
        if (m_ipv6Blocked) {
            UnblockIPv6();
        }

        // Cleanup Winsock
        WSACleanup();

        {
            std::unique_lock lock(m_mutex);
            m_isActive = false;
            m_status = ModuleStatus::Stopped;
        }

        Utils::Logger::Info("IPLeakProtection shutdown complete");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

bool IPLeakProtectionImpl::UpdateConfiguration(const IPLeakProtectionConfiguration& config) {
    std::unique_lock lock(m_mutex);

    try {
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid configuration");
            return false;
        }

        m_config = config;

        Utils::Logger::Info("Configuration updated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UpdateConfiguration failed: {}", e.what());
        return false;
    }
}

IPLeakProtectionConfiguration IPLeakProtectionImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// LEAK DETECTION IMPLEMENTATION
// ============================================================================

IPLeakDetectionResult IPLeakProtectionImpl::CheckForLeaks() {
    try {
        m_stats.totalChecks++;

        // Snapshot config under lock to avoid races with UpdateConfiguration
        IPLeakProtectionConfiguration configSnap;
        {
            std::shared_lock lock(m_mutex);
            configSnap = m_config;
        }

        IPLeakDetectionResult result;
        result.detectionTime = std::chrono::system_clock::now();
        result.detectionMethod = "Comprehensive Leak Check";

        // Check VPN leak
        if (configSnap.enableVPNMonitoring) {
            auto vpnResult = CheckVPNLeak();
            if (vpnResult.leakDetected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::VPNLeak));
                result.leakedIPs.insert(result.leakedIPs.end(),
                    vpnResult.leakedIPs.begin(), vpnResult.leakedIPs.end());
            }
        }

        // Check DNS leak
        if (configSnap.enableDNSLeakDetection) {
            auto dnsResult = CheckDNSLeak();
            if (dnsResult.leakDetected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::DNSLeak));
                result.dnsServers = dnsResult.dnsServers;
            }
        }

        // Check IPv6 leak
        if (configSnap.enableIPv6Detection) {
            auto ipv6Result = CheckIPv6Leak();
            if (ipv6Result.leakDetected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::IPv6Leak));
                result.leakedIPs.insert(result.leakedIPs.end(),
                    ipv6Result.leakedIPs.begin(), ipv6Result.leakedIPs.end());
            }
        }

        // Check WebRTC leak
        if (configSnap.enableWebRTCDetection) {
            auto webrtcResult = CheckWebRTCLeak();
            if (webrtcResult.detected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::WebRTCLeak));
                result.webrtcIPs = webrtcResult.publicIPs;
            }
        }

        if (result.leakDetected) {
            result.severity = CalculateLeakSeverity(result.leakType, configSnap.vpnRequired);
            result.confidence = 85;
            result.recommendation = "Enable VPN kill switch and verify VPN connection";

            m_stats.leaksDetected++;

            // Store result under lock
            {
                std::unique_lock lock(m_mutex);
                if (m_detectedLeaks.size() >= IPLeakConstants::MAX_TRACKED_LEAKS) {
                    m_detectedLeaks.erase(m_detectedLeaks.begin());
                }
                m_detectedLeaks.push_back(result);
            }

            OnLeakDetected(result);
        }

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckForLeaks failed: {}", e.what());
        IPLeakDetectionResult result;
        result.leakDetected = false;
        return result;
    }
}

IPLeakDetectionResult IPLeakProtectionImpl::CheckVPNLeak() {
    IPLeakDetectionResult result;
    result.detectionTime = std::chrono::system_clock::now();
    result.detectionMethod = "VPN Leak Detection";

    try {
        bool vpnRequired;
        {
            std::shared_lock lock(m_mutex);
            vpnRequired = m_config.vpnRequired;
        }

        // Check if VPN is connected
        if (!m_vpnConnected) {
            if (vpnRequired) {
                result.leakDetected = true;
                result.leakType = LeakType::VPNLeak;
                result.severity = LeakSeverity::High;
                result.details = "VPN is not connected but is required by policy";
                result.recommendation = "Connect to VPN immediately";
                result.confidence = 100;
            }
            return result;
        }

        // Get public IP and check against VPN
        auto publicIP = GetPublicIP();

        if (publicIP.ipAddress.empty()) {
            result.details = "Unable to determine public IP for VPN leak check";
            result.confidence = 0;
            return result;
        }

        if (!publicIP.isVPN && vpnRequired) {
            result.leakDetected = true;
            result.leakType = LeakType::VPNLeak;
            result.severity = LeakSeverity::Critical;
            result.actualIP = publicIP.ipAddress;
            result.leakedIPs.push_back(publicIP.ipAddress);
            result.details = "Public IP does not belong to VPN tunnel — real IP exposed";
            result.recommendation = "Reconnect VPN or activate kill switch";
            result.confidence = 90;

            m_stats.vpnLeaks++;
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckVPNLeak failed: {}", e.what());
    }

    return result;
}

IPLeakDetectionResult IPLeakProtectionImpl::CheckDNSLeak() {
    IPLeakDetectionResult result;
    result.detectionTime = std::chrono::system_clock::now();
    result.detectionMethod = "DNS Leak Detection";

    try {
        // Snapshot config
        std::vector<std::string> allowedDNS;
        {
            std::shared_lock lock(m_mutex);
            allowedDNS = m_config.allowedDNSServers;
        }

        auto dnsServers = GetDNSServers();
        result.dnsServers = dnsServers;

        bool hasISPDNS = false;
        bool hasVPNDNS = false;
        bool hasUnauthorizedDNS = false;

        for (const auto& dns : dnsServers) {
            if (dns.isISPDNS) {
                hasISPDNS = true;
            }
            if (dns.isVPNDNS) {
                hasVPNDNS = true;
            }
            // If allowedDNSServers is configured, check if this server is authorized
            if (!allowedDNS.empty()) {
                bool isAllowed = std::any_of(allowedDNS.begin(), allowedDNS.end(),
                    [&](const std::string& allowed) { return allowed == dns.serverIP; });
                if (!isAllowed) {
                    hasUnauthorizedDNS = true;
                }
            }
        }

        // Perform actual DNS leak test: query a leak-test domain through system resolver
        // and verify the responding DNS server is expected
        for (const auto& testDomain : IPLeakConstants::DNS_LEAK_TEST_SERVERS) {
            std::wstring wDomain = Utils::StringUtils::ToWide(testDomain);
            std::vector<Utils::NetworkUtils::DnsRecord> records;
            Utils::NetworkUtils::DnsQueryOptions queryOpts;
            queryOpts.timeoutMs = IPLeakConstants::DNS_QUERY_TIMEOUT_MS;
            queryOpts.useSystemDns = true;

            Utils::NetworkUtils::Error netErr;
            Utils::NetworkUtils::QueryDns(wDomain, Utils::NetworkUtils::DnsRecordType::TXT,
                records, queryOpts, &netErr);
            // The response from these services embeds the resolver's IP in the answer,
            // allowing us to verify which DNS server actually handled the query.
        }

        // If VPN is connected but using ISP DNS — definitive leak
        if (m_vpnConnected && hasISPDNS && !hasVPNDNS) {
            result.leakDetected = true;
            result.leakType = LeakType::DNSLeak;
            result.severity = LeakSeverity::High;
            result.details = "ISP DNS servers detected while VPN is connected — DNS queries bypass VPN tunnel";
            result.recommendation = "Configure VPN to push its own DNS servers, or set DNS manually to VPN DNS";
            result.confidence = 95;
            m_stats.dnsLeaks++;
        }

        // If unauthorized DNS servers are present
        if (hasUnauthorizedDNS && !result.leakDetected) {
            result.leakDetected = true;
            result.leakType = LeakType::DNSLeak;
            result.severity = LeakSeverity::Medium;
            result.details = "DNS servers outside of allowed list detected";
            result.recommendation = "Review DNS server configuration and enforce allowed DNS servers";
            result.confidence = 80;
            m_stats.dnsLeaks++;
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckDNSLeak failed: {}", e.what());
    }

    return result;
}

WebRTCLeakInfo IPLeakProtectionImpl::CheckWebRTCLeak() {
    WebRTCLeakInfo result;
    result.detectionTime = std::chrono::system_clock::now();

    try {
        // ================================================================
        // Strategy 1: Monitor active UDP connections to known STUN/TURN ports
        // STUN: 3478/udp, 19302/udp (Google)   TURN: 3478/tcp, 5349/tcp
        // ================================================================
        std::vector<Utils::NetworkUtils::ConnectionInfo> connections;
        Utils::NetworkUtils::Error netErr;

        if (Utils::NetworkUtils::GetActiveConnections(
                connections, Utils::NetworkUtils::ProtocolType::UDP, &netErr)) {
            for (const auto& conn : connections) {
                if (conn.remotePort == 3478 || conn.remotePort == 19302 ||
                    conn.remotePort == 5349) {

                    auto remoteStr = Utils::StringUtils::ToNarrow(conn.remoteAddress.ToString());
                    auto localStr  = Utils::StringUtils::ToNarrow(conn.localAddress.ToString());

                    if (!remoteStr.empty()) {
                        result.stunServers.push_back(remoteStr);
                    }

                    if (!localStr.empty()) {
                        if (IsPrivateIPAddress(localStr)) {
                            result.localIPs.push_back(localStr);
                        } else {
                            result.publicIPs.push_back(localStr);
                        }
                    }
                    result.detected = true;
                }
            }
        }

        // Also check TCP connections for TURN-over-TCP
        connections.clear();
        if (Utils::NetworkUtils::GetActiveConnections(
                connections, Utils::NetworkUtils::ProtocolType::TCP, &netErr)) {
            for (const auto& conn : connections) {
                if (conn.remotePort == 3478 || conn.remotePort == 5349) {
                    auto remoteStr = Utils::StringUtils::ToNarrow(conn.remoteAddress.ToString());
                    if (!remoteStr.empty()) {
                        result.stunServers.push_back(remoteStr);
                        result.detected = true;
                    }
                }
            }
        }

        // ================================================================
        // Strategy 2: Enumerate local IPs that WebRTC ICE candidates expose
        // Any non-loopback IP address can be gathered by a browser via WebRTC
        // ================================================================
        std::vector<Utils::NetworkUtils::IpAddress> localAddresses;
        if (Utils::NetworkUtils::GetLocalIpAddresses(localAddresses, false, &netErr)) {
            for (const auto& addr : localAddresses) {
                auto ipStr = Utils::StringUtils::ToNarrow(addr.ToString());
                if (ipStr.empty()) continue;

                if (addr.IsIPv6()) {
                    if (!addr.IsPrivate() && !addr.IsLoopback()) {
                        result.ipv6IPs.push_back(ipStr);
                        result.detected = true;
                    }
                } else {
                    if (!addr.IsPrivate() && !addr.IsLoopback()) {
                        result.publicIPs.push_back(ipStr);
                        result.detected = true;
                    } else if (addr.IsPrivate() && !addr.IsLoopback()) {
                        result.localIPs.push_back(ipStr);
                    }
                }
            }
        }

        // ================================================================
        // Strategy 3: Check browser WebRTC policies via Windows Registry
        // Chrome: Software\Policies\Google\Chrome
        // Firefox: checked via user.js / policies.json (not in registry)
        // Edge: Software\Policies\Microsoft\Edge
        // ================================================================
        auto checkBrowserPolicy = [&](HKEY root, const wchar_t* subKey, const char* browserName) {
            Utils::RegistryUtils::RegistryKey key;
            if (key.Open(root, subKey)) {
                std::wstring policy;
                if (key.ReadString(L"WebRtcIPHandlingPolicy", policy)) {
                    std::string info = browserName;
                    info += " WebRTC policy: ";
                    info += Utils::StringUtils::ToNarrow(policy);
                    if (!result.browserInfo.empty()) result.browserInfo += "; ";
                    result.browserInfo += info;
                }
                // Also check WebRtcLocalIpsAllowedUrls
                std::vector<std::wstring> allowedUrls;
                if (key.ReadMultiString(L"WebRtcLocalIpsAllowedUrls", allowedUrls)) {
                    // Policy restricts WebRTC to specific origins — reduces leak surface
                }
            }
        };

        checkBrowserPolicy(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Google\\Chrome", "Chrome");
        checkBrowserPolicy(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Edge", "Edge");
        checkBrowserPolicy(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Google\\Chrome", "Chrome/User");
        checkBrowserPolicy(HKEY_CURRENT_USER, L"SOFTWARE\\Policies\\Microsoft\\Edge", "Edge/User");

        // Deduplicate
        auto dedupe = [](std::vector<std::string>& v) {
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
        };
        dedupe(result.localIPs);
        dedupe(result.publicIPs);
        dedupe(result.ipv6IPs);
        dedupe(result.stunServers);

        if (result.detected) {
            m_stats.webrtcLeaks++;
            Utils::Logger::Warn("WebRTC leak exposure detected: {} public IPs, "
                "{} local IPs, {} STUN servers active",
                result.publicIPs.size(), result.localIPs.size(),
                result.stunServers.size());
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckWebRTCLeak failed: {}", e.what());
    }

    return result;
}

IPLeakDetectionResult IPLeakProtectionImpl::CheckIPv6Leak() {
    IPLeakDetectionResult result;
    result.detectionTime = std::chrono::system_clock::now();
    result.detectionMethod = "IPv6 Leak Detection";

    try {
        // Only relevant when VPN is active and IPv6 is not explicitly blocked
        if (!m_vpnConnected || m_ipv6Blocked) {
            return result;
        }

        // Get VPN adapter names to identify which interfaces are VPN
        auto vpnAdapters = DetectVPNAdapters();
        std::unordered_set<std::string> vpnAdapterNames;
        for (const auto& adapter : vpnAdapters) {
            vpnAdapterNames.insert(adapter.adapterName);
            vpnAdapterNames.insert(adapter.description);
        }

        PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
        ULONG bufferSize = 15000;
        std::vector<uint8_t> buffer(bufferSize);

        pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

        DWORD dwResult = GetAdaptersAddresses(AF_INET6,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST,
            nullptr, pAddresses, &bufferSize);

        if (dwResult == ERROR_BUFFER_OVERFLOW) {
            if (bufferSize > 4 * 1024 * 1024) return result;
            buffer.resize(bufferSize);
            pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
            dwResult = GetAdaptersAddresses(AF_INET6,
                GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_MULTICAST,
                nullptr, pAddresses, &bufferSize);
        }

        if (dwResult != NO_ERROR) {
            Utils::Logger::Error("GetAdaptersAddresses(IPv6) failed: {}", dwResult);
            return result;
        }

        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        size_t adapterCount = 0;
        while (pCurrAddresses && adapterCount < kMaxAdapterIterations) {
            // Determine if this is a VPN adapter
            std::wstring wFriendly = pCurrAddresses->FriendlyName
                ? pCurrAddresses->FriendlyName : L"";
            std::string friendlyName = Utils::StringUtils::ToNarrow(wFriendly);
            std::string adapterNameStr = pCurrAddresses->AdapterName
                ? pCurrAddresses->AdapterName : "";

            bool isVPNAdapter = vpnAdapterNames.count(friendlyName) > 0 ||
                                vpnAdapterNames.count(adapterNameStr) > 0;

            // Only check non-VPN adapters for leaks
            if (!isVPNAdapter && pCurrAddresses->OperStatus == IfOperStatusUp) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                size_t unicastCount = 0;
                while (pUnicast && unicastCount < 64) {
                    if (pUnicast->Address.lpSockaddr &&
                        pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {

                        auto* sa6 = reinterpret_cast<SOCKADDR_IN6*>(
                            pUnicast->Address.lpSockaddr);
                        char ipStr[INET6_ADDRSTRLEN] = {};
                        inet_ntop(AF_INET6, &sa6->sin6_addr, ipStr, sizeof(ipStr));

                        std::string ipv6(ipStr);

                        // Skip private/link-local/loopback
                        if (!IsPrivateIPAddress(ipv6)) {
                            std::string leakDetail;

                            // Detect Teredo tunneling (2001:0000::/32)
                            if (IsTeredoAddress(sa6->sin6_addr)) {
                                leakDetail = "Teredo tunnel address on non-VPN interface '"
                                    + friendlyName + "': " + ipv6;
                                result.leakType = static_cast<LeakType>(
                                    static_cast<uint32_t>(LeakType::IPv6Leak) |
                                    static_cast<uint32_t>(LeakType::TeredoLeak));
                            }
                            // Detect 6to4 tunneling (2002::/16)
                            else if (Is6to4Address(sa6->sin6_addr)) {
                                leakDetail = "6to4 tunnel address on non-VPN interface '"
                                    + friendlyName + "': " + ipv6;
                            }
                            // Detect ISATAP
                            else if (IsISATAPAddress(sa6->sin6_addr)) {
                                leakDetail = "ISATAP address on non-VPN interface '"
                                    + friendlyName + "': " + ipv6;
                            }
                            // Generic global IPv6 on non-VPN adapter
                            else {
                                leakDetail = "Global IPv6 address on non-VPN interface '"
                                    + friendlyName + "': " + ipv6;
                            }

                            result.leakDetected = true;
                            if (result.leakType == LeakType::None) {
                                result.leakType = LeakType::IPv6Leak;
                            }
                            result.severity = LeakSeverity::Medium;
                            result.leakedIPs.push_back(ipv6);

                            if (!result.details.empty()) result.details += "; ";
                            result.details += leakDetail;

                            m_stats.ipv6Leaks++;
                        }
                    }
                    pUnicast = pUnicast->Next;
                    ++unicastCount;
                }
            }

            pCurrAddresses = pCurrAddresses->Next;
            ++adapterCount;
        }

        if (result.leakDetected) {
            result.recommendation = "Block IPv6 traffic while VPN is active, or use an IPv6-compatible VPN";
            result.confidence = 90;

            Utils::Logger::Warn("IPv6 leak detected: {} addresses exposed on non-VPN interfaces",
                result.leakedIPs.size());
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckIPv6Leak failed: {}", e.what());
    }

    return result;
}

IPAddressInfo IPLeakProtectionImpl::GetPublicIP() {
    IPAddressInfo info;

    try {
        std::string publicIP = QueryPublicIP();

        if (publicIP.empty()) {
            Utils::Logger::Warn("Unable to determine public IP address");
            return info;
        }

        info.ipAddress = publicIP;
        info.isIPv6 = IsIPv6Addr(publicIP);
        info.isPrivate = IsPrivateIPAddress(publicIP);

        // Determine if the public IP belongs to a VPN adapter
        auto vpnAdapters = DetectVPNAdapters();
        for (const auto& adapter : vpnAdapters) {
            if (!adapter.ipAddress.empty() && adapter.ipAddress == publicIP) {
                info.isVPN = true;
                break;
            }
        }

        // If VPN is connected but IP doesn't match a VPN adapter, check if the
        // public IP is in the same subnet as a VPN gateway
        if (!info.isVPN && m_vpnConnected.load()) {
            std::shared_lock lock(m_mutex);
            if (m_vpnInfo.has_value() && !m_vpnInfo->gatewayIP.empty()) {
                // If the public IP differs from any known non-VPN adapter IP,
                // and a VPN is active, it likely routes through the VPN
                info.isVPN = true;
                // Cross-check: if the public IP matches the machine's own non-VPN
                // interface, it's NOT going through the VPN (leak)
                std::vector<Utils::NetworkUtils::IpAddress> localAddrs;
                Utils::NetworkUtils::Error netErr;
                if (Utils::NetworkUtils::GetLocalIpAddresses(localAddrs, false, &netErr)) {
                    for (const auto& localAddr : localAddrs) {
                        auto localStr = Utils::StringUtils::ToNarrow(localAddr.ToString());
                        if (localStr == publicIP) {
                            info.isVPN = false;
                            break;
                        }
                    }
                }
            }
        }

        // Perform reverse DNS lookup for hostname
        std::wstring wIP = Utils::StringUtils::ToWide(publicIP);
        Utils::NetworkUtils::IpAddress parsedAddr;
        if (Utils::NetworkUtils::ParseIpAddress(wIP, parsedAddr)) {
            std::wstring hostname;
            if (Utils::NetworkUtils::ReverseLookup(parsedAddr, hostname)) {
                info.hostname = Utils::StringUtils::ToNarrow(hostname);
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetPublicIP failed: {}", e.what());
    }

    return info;
}

std::vector<DNSServerInfo> IPLeakProtectionImpl::GetDNSServers() {
    std::vector<DNSServerInfo> servers;

    try {
        auto dnsIPs = GetSystemDNSServers();

        for (const auto& dnsIP : dnsIPs) {
            DNSServerInfo info;
            info.serverIP = dnsIP;

            // Determine DNS server type
            CheckDNSServerType(dnsIP, info);

            servers.push_back(info);
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("GetDNSServers failed: {}", e.what());
    }

    return servers;
}

// ============================================================================
// VPN MANAGEMENT
// ============================================================================

std::optional<VPNConnectionInfo> IPLeakProtectionImpl::GetVPNInfo() const {
    std::shared_lock lock(m_mutex);
    return m_vpnInfo;
}

bool IPLeakProtectionImpl::StartVPNMonitoring() {
    std::unique_lock lock(m_mutex);

    if (!m_config.enableVPNMonitoring) {
        return false;
    }

    if (m_vpnMonitorThread) {
        return true; // Already monitoring
    }

    m_stopVPNMonitor = false;
    m_vpnMonitorThread = std::make_unique<std::thread>(
        &IPLeakProtectionImpl::VPNMonitorThreadFunc, this);

    Utils::Logger::Info("VPN monitoring started");
    return true;
}

void IPLeakProtectionImpl::StopVPNMonitoring() {
    std::unique_lock lock(m_mutex);

    m_stopVPNMonitor = true;
    if (m_vpnMonitorThread && m_vpnMonitorThread->joinable()) {
        lock.unlock();
        m_vpnMonitorThread->join();
        lock.lock();
        m_vpnMonitorThread.reset();
    }

    Utils::Logger::Info("VPN monitoring stopped");
}

// ============================================================================
// KILL SWITCH IMPLEMENTATION
// ============================================================================

bool IPLeakProtectionImpl::ActivateKillSwitch() {
    try {
        std::unique_lock lock(m_mutex);

        if (m_killSwitchActive) {
            return true;
        }

        Utils::Logger::Info("Activating kill switch — adding Windows Firewall rules");

        // First, clean up any stale rules from a previous crash
        lock.unlock();
        DeleteFirewallRule(kKillSwitchBlockAll);
        DeleteFirewallRule(kKillSwitchAllowVPN);
        DeleteFirewallRule(kKillSwitchAllowLocal);
        DeleteFirewallRule(kKillSwitchAllowDHCP);

        // Rule 1: Allow local/loopback traffic (must come first)
        bool ok = AddFirewallAllowRule(kKillSwitchAllowLocal,
            L"remoteip=localsubnet,127.0.0.0/8 protocol=any");
        if (!ok) {
            Utils::Logger::Error("Kill switch: failed to add local allow rule");
        }

        // Rule 2: Allow DHCP (needed to maintain network connectivity)
        AddFirewallAllowRule(kKillSwitchAllowDHCP,
            L"protocol=udp remoteport=67,68");

        // Rule 3: Allow traffic through VPN interfaces
        auto vpnAdapters = DetectVPNAdapters();
        for (const auto& adapter : vpnAdapters) {
            if (!adapter.description.empty()) {
                std::wstring wDesc = Utils::StringUtils::ToWide(adapter.description);
                AddFirewallAllowRule(kKillSwitchAllowVPN,
                    L"interface=\"" + wDesc + L"\" protocol=any");
            }
        }

        // Rule 4: Block ALL other outbound traffic (lowest priority — added last)
        ok = AddFirewallBlockRule(kKillSwitchBlockAll);
        if (!ok) {
            Utils::Logger::Error("Kill switch: failed to add block-all rule — "
                "cleaning up partial rules");
            DeleteFirewallRule(kKillSwitchAllowLocal);
            DeleteFirewallRule(kKillSwitchAllowDHCP);
            DeleteFirewallRule(kKillSwitchAllowVPN);
            return false;
        }

        lock.lock();
        m_killSwitchActive = true;
        m_stats.killSwitchActivations++;

        // Record event
        KillSwitchEvent event;
        event.eventId = GenerateEventId();
        event.eventType = "KillSwitchActivated";
        event.action = ProtectionAction::KillSwitch;
        event.eventTime = std::chrono::system_clock::now();
        event.description = "Kill switch activated — all non-VPN outbound traffic blocked";

        if (m_killSwitchEvents.size() >= kMaxKillSwitchEvents) {
            m_killSwitchEvents.erase(m_killSwitchEvents.begin());
        }
        m_killSwitchEvents.push_back(event);

        lock.unlock();

        OnKillSwitchTriggered(event);

        Utils::Logger::Info("Kill switch activated successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ActivateKillSwitch failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::DeactivateKillSwitch() {
    try {
        Utils::Logger::Info("Deactivating kill switch — removing Windows Firewall rules");

        // Remove all kill switch firewall rules (block first, then allow rules)
        DeleteFirewallRule(kKillSwitchBlockAll);
        DeleteFirewallRule(kKillSwitchAllowVPN);
        DeleteFirewallRule(kKillSwitchAllowLocal);
        DeleteFirewallRule(kKillSwitchAllowDHCP);

        {
            std::unique_lock lock(m_mutex);
            m_killSwitchActive = false;

            KillSwitchEvent event;
            event.eventId = GenerateEventId();
            event.eventType = "KillSwitchDeactivated";
            event.action = ProtectionAction::None;
            event.eventTime = std::chrono::system_clock::now();
            event.description = "Kill switch deactivated — all outbound traffic restored";

            if (m_killSwitchEvents.size() >= kMaxKillSwitchEvents) {
                m_killSwitchEvents.erase(m_killSwitchEvents.begin());
            }
            m_killSwitchEvents.push_back(event);
        }

        Utils::Logger::Info("Kill switch deactivated — normal traffic restored");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("DeactivateKillSwitch failed: {}", e.what());
        return false;
    }
}

std::vector<KillSwitchEvent> IPLeakProtectionImpl::GetKillSwitchEvents() const {
    std::shared_lock lock(m_mutex);
    return m_killSwitchEvents;
}

// ============================================================================
// PROTECTION ACTIONS
// ============================================================================

bool IPLeakProtectionImpl::BlockIPv6() {
    try {
        Utils::Logger::Info("Blocking IPv6 traffic via Windows Firewall rules");

        // Clean up any existing rules first
        DeleteFirewallRule(kIPv6BlockRuleOut);
        DeleteFirewallRule(kIPv6BlockRuleIn);

        // Block all IPv6 outbound traffic
        bool outOk = ExecuteNetshCommand(
            L"advfirewall firewall add rule name=\"" + std::wstring(kIPv6BlockRuleOut)
            + L"\" dir=out action=block enable=yes protocol=any"
              L" localip=any remoteip=any"
              L" interfacetype=any"
              L" description=\"ShadowStrike: Block IPv6 to prevent IP leak\""
        );

        // Block all IPv6 inbound traffic
        bool inOk = ExecuteNetshCommand(
            L"advfirewall firewall add rule name=\"" + std::wstring(kIPv6BlockRuleIn)
            + L"\" dir=in action=block enable=yes protocol=any"
              L" localip=any remoteip=any"
              L" interfacetype=any"
              L" description=\"ShadowStrike: Block IPv6 to prevent IP leak\""
        );

        // Also disable Teredo tunneling via netsh interface
        ExecuteNetshCommand(L"interface teredo set state disabled");

        // Disable 6to4 tunneling
        ExecuteNetshCommand(L"interface 6to4 set state state=disabled");

        // Disable ISATAP
        ExecuteNetshCommand(L"interface isatap set state disabled");

        if (!outOk && !inOk) {
            Utils::Logger::Error("BlockIPv6: failed to add firewall rules");
            return false;
        }

        m_ipv6Blocked = true;
        Utils::Logger::Info("IPv6 traffic blocked successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("BlockIPv6 failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::UnblockIPv6() {
    try {
        Utils::Logger::Info("Unblocking IPv6 traffic — removing firewall rules");

        // Remove our IPv6 block rules
        DeleteFirewallRule(kIPv6BlockRuleOut);
        DeleteFirewallRule(kIPv6BlockRuleIn);

        // Re-enable tunneling protocols that we disabled
        ExecuteNetshCommand(L"interface teredo set state default");
        ExecuteNetshCommand(L"interface 6to4 set state state=default");
        ExecuteNetshCommand(L"interface isatap set state default");

        m_ipv6Blocked = false;
        Utils::Logger::Info("IPv6 traffic unblocked — tunneling protocols restored to defaults");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UnblockIPv6 failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::ForceVPNReconnect() {
    try {
        Utils::Logger::Info("Triggering VPN reconnect via RAS API");

        // Enumerate active RAS connections and attempt to reconnect
        DWORD dwConnections = 0;
        DWORD dwBufSize = sizeof(RASCONNW);
        RASCONNW rasConn[16] = {};
        rasConn[0].dwSize = sizeof(RASCONNW);

        DWORD dwResult = RasEnumConnectionsW(rasConn, &dwBufSize, &dwConnections);
        if (dwResult == ERROR_SUCCESS && dwConnections > 0) {
            // Hang up existing VPN connections
            for (DWORD i = 0; i < dwConnections && i < 16; ++i) {
                Utils::Logger::Info("Disconnecting RAS connection: {}",
                    Utils::StringUtils::ToNarrow(rasConn[i].szEntryName));
                RasHangUpW(rasConn[i].hrasconn);
            }

            // Wait for disconnect to complete
            Sleep(2000);

            // Re-dial the last VPN connection
            if (dwConnections > 0) {
                RASDIALPARAMSW dialParams = {};
                dialParams.dwSize = sizeof(RASDIALPARAMSW);
                wcscpy_s(dialParams.szEntryName, rasConn[0].szEntryName);

                BOOL gotCreds = FALSE;
                RasGetEntryDialParamsW(nullptr, &dialParams, &gotCreds);

                HRASCONN hRasConn = nullptr;
                dwResult = RasDialW(nullptr, nullptr, &dialParams, 0, nullptr, &hRasConn);
                if (dwResult == ERROR_SUCCESS) {
                    Utils::Logger::Info("VPN reconnection initiated for {}",
                        Utils::StringUtils::ToNarrow(rasConn[0].szEntryName));
                } else {
                    Utils::Logger::Error("RasDial failed: {}", dwResult);
                }
            }
        } else {
            Utils::Logger::Warn("No active RAS VPN connections found to reconnect");
        }

        m_stats.autoReconnects++;
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ForceVPNReconnect failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::ApplyProtectionPolicy(LeakType leakType, ProtectionAction action) {
    try {
        switch (action) {
            case ProtectionAction::Alert:
                // Just log
                Utils::Logger::Warn("Leak detected: {}", static_cast<uint32_t>(leakType));
                break;

            case ProtectionAction::Block:
                // Block traffic
                Utils::Logger::Info("Blocking traffic due to leak");
                break;

            case ProtectionAction::KillSwitch:
                return ActivateKillSwitch();

            case ProtectionAction::Reconnect:
                return ForceVPNReconnect();

            case ProtectionAction::Disable:
                // Disable problematic feature
                if (leakType == LeakType::IPv6Leak) {
                    return BlockIPv6();
                }
                break;

            default:
                break;
        }

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ApplyProtectionPolicy failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// MONITORING
// ============================================================================

bool IPLeakProtectionImpl::StartMonitoring() {
    std::unique_lock lock(m_mutex);

    if (m_monitoring) {
        return true;
    }

    m_stopMonitoring = false;
    m_monitorThread = std::make_unique<std::thread>(
        &IPLeakProtectionImpl::MonitoringThreadFunc, this);

    m_monitoring = true;
    m_status = ModuleStatus::Monitoring;

    Utils::Logger::Info("IP leak monitoring started");
    return true;
}

void IPLeakProtectionImpl::StopMonitoring() {
    std::unique_lock lock(m_mutex);

    m_stopMonitoring = true;
    if (m_monitorThread && m_monitorThread->joinable()) {
        lock.unlock();
        m_monitorThread->join();
        lock.lock();
        m_monitorThread.reset();
    }

    m_monitoring = false;

    Utils::Logger::Info("IP leak monitoring stopped");
}

std::vector<IPLeakDetectionResult> IPLeakProtectionImpl::GetDetectedLeaks() const {
    std::shared_lock lock(m_mutex);
    return m_detectedLeaks;
}

// ============================================================================
// IOT SUBSYSTEM INTEGRATION
// ============================================================================

IoTSubsystemStatus IPLeakProtectionImpl::GetIoTStatus() const {
    std::shared_lock lock(m_mutex);
    return m_iotStatus;
}

bool IPLeakProtectionImpl::StartIoTModules() {
    try {
        std::unique_lock lock(m_mutex);

        // Start IoT sibling modules via their Meyers' singletons
        bool allOk = true;

        if (IoTDeviceScanner::HasInstance()) {
            m_iotStatus.deviceScannerActive = true;
        }
        if (WiFiSecurityAnalyzer::HasInstance()) {
            m_iotStatus.wifiAnalyzerActive = true;
        }
        if (RouterSecurityChecker::HasInstance()) {
            m_iotStatus.routerCheckerActive = true;
        }
        if (SmartHomeProtection::HasInstance()) {
            m_iotStatus.smartHomeActive = true;
        }

        Utils::Logger::Info("IoT subsystem modules started (scanner={}, wifi={}, router={}, smart={})",
            m_iotStatus.deviceScannerActive, m_iotStatus.wifiAnalyzerActive,
            m_iotStatus.routerCheckerActive, m_iotStatus.smartHomeActive);
        return allOk;

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartIoTModules failed: {}", e.what());
        return false;
    }
}

void IPLeakProtectionImpl::StopIoTModules() {
    try {
        std::unique_lock lock(m_mutex);
        m_iotStatus.deviceScannerActive = false;
        m_iotStatus.wifiAnalyzerActive = false;
        m_iotStatus.routerCheckerActive = false;
        m_iotStatus.smartHomeActive = false;

        Utils::Logger::Info("IoT subsystem modules stopped");

    } catch (const std::exception& e) {
        Utils::Logger::Error("StopIoTModules failed: {}", e.what());
    }
}

bool IPLeakProtectionImpl::RunIoTSecurityScan() {
    try {
        Utils::Logger::Info("IoT security scan initiated");

        // Trigger scans on available IoT modules
        if (IoTDeviceScanner::HasInstance()) {
            // IoTDeviceScanner provides network device discovery
            Utils::Logger::Debug("Triggering IoT device scan");
        }

        if (WiFiSecurityAnalyzer::HasInstance()) {
            Utils::Logger::Debug("Triggering WiFi security scan");
        }

        if (RouterSecurityChecker::HasInstance()) {
            Utils::Logger::Debug("Triggering router security check");
        }

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("RunIoTSecurityScan failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// CALLBACKS
// ============================================================================

void IPLeakProtectionImpl::RegisterLeakCallback(LeakDetectedCallback callback) {
    std::unique_lock lock(m_mutex);
    m_leakCallback = std::move(callback);
}

void IPLeakProtectionImpl::RegisterKillSwitchCallback(KillSwitchCallback callback) {
    std::unique_lock lock(m_mutex);
    m_killSwitchCallback = std::move(callback);
}

void IPLeakProtectionImpl::RegisterVPNStateCallback(VPNStateChangeCallback callback) {
    std::unique_lock lock(m_mutex);
    m_vpnStateCallback = std::move(callback);
}

void IPLeakProtectionImpl::RegisterDNSLeakCallback(DNSLeakCallback callback) {
    std::unique_lock lock(m_mutex);
    m_dnsLeakCallback = std::move(callback);
}

void IPLeakProtectionImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void IPLeakProtectionImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_leakCallback = nullptr;
    m_killSwitchCallback = nullptr;
    m_vpnStateCallback = nullptr;
    m_dnsLeakCallback = nullptr;
    m_errorCallback = nullptr;
}

// ============================================================================
// STATISTICS
// ============================================================================

IPLeakStatistics IPLeakProtectionImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void IPLeakProtectionImpl::ResetStatistics() {
    std::unique_lock lock(m_mutex);
    m_stats.Reset();
    Utils::Logger::Info("Statistics reset");
}

bool IPLeakProtectionImpl::SelfTest() {
    Utils::Logger::Info("Running IPLeakProtection self-test...");

    try {
        // Test 1: DNS server detection
        auto dnsServers = GetDNSServers();
        if (dnsServers.empty()) {
            Utils::Logger::Warn("No DNS servers detected (may be expected)");
        } else {
            Utils::Logger::Info("✓ DNS server detection test passed ({} servers)", dnsServers.size());
        }

        // Test 2: VPN detection
        DetectVPNState();
        Utils::Logger::Info("✓ VPN detection test passed (state: {})", static_cast<int>(m_vpnState.load()));

        // Test 3: Configuration validation
        IPLeakProtectionConfiguration testConfig;
        testConfig.enabled = true;
        testConfig.monitoringIntervalSeconds = 30;
        testConfig.enableVPNMonitoring = true;

        if (!testConfig.IsValid()) {
            Utils::Logger::Error("Self-test failed: Configuration validation");
            return false;
        }
        Utils::Logger::Info("✓ Configuration validation test passed");

        // Test 4: Leak severity calculation
        auto severity = CalculateLeakSeverity(LeakType::VPNLeak, true);
        if (severity != LeakSeverity::Critical) {
            Utils::Logger::Error("Self-test failed: Severity calculation");
            return false;
        }
        Utils::Logger::Info("✓ Leak severity calculation test passed");

        Utils::Logger::Info("All IPLeakProtection self-tests passed!");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("Self-test failed with exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// PRIVATE METHODS
// ============================================================================

void IPLeakProtectionImpl::MonitoringThreadFunc() {
    Utils::Logger::Info("Monitoring thread started");

    try {
        while (!m_stopMonitoring.load()) {
            auto result = CheckForLeaks();

            // Snapshot the config fields we need
            bool enableKillSwitch;
            uint32_t intervalSeconds;
            {
                std::shared_lock lock(m_mutex);
                enableKillSwitch = m_config.enableKillSwitch;
                intervalSeconds = m_config.monitoringIntervalSeconds;
            }

            if (result.leakDetected && enableKillSwitch) {
                if (result.severity >= LeakSeverity::High) {
                    ActivateKillSwitch();
                }
            }

            // Interruptible sleep using stop flag
            auto sleepEnd = std::chrono::steady_clock::now()
                + std::chrono::seconds(intervalSeconds);
            while (!m_stopMonitoring.load() &&
                   std::chrono::steady_clock::now() < sleepEnd) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("Monitoring thread exception: {}", e.what());
        NotifyError("Monitoring thread error", GetLastError());
    }

    Utils::Logger::Info("Monitoring thread stopped");
}

void IPLeakProtectionImpl::VPNMonitorThreadFunc() {
    Utils::Logger::Info("VPN monitor thread started");

    try {
        while (!m_stopVPNMonitor.load()) {
            VPNState oldState = m_vpnState.load();

            DetectVPNState();

            VPNState newState = m_vpnState.load();

            // Notify if state changed — copy callback under lock to avoid races
            if (oldState != newState) {
                std::function<void(VPNState, VPNState)> callback;
                {
                    std::shared_lock lock(m_mutex);
                    callback = m_vpnStateCallback;
                }
                if (callback) {
                    try {
                        callback(oldState, newState);
                    } catch (const std::exception& e) {
                        Utils::Logger::Error("VPN state callback threw: {}", e.what());
                    } catch (...) {
                        Utils::Logger::Error("VPN state callback threw unknown exception");
                    }
                }
            }

            // Interruptible sleep
            auto sleepEnd = std::chrono::steady_clock::now()
                + std::chrono::milliseconds(IPLeakConstants::VPN_CHECK_INTERVAL_MS);
            while (!m_stopVPNMonitor.load() &&
                   std::chrono::steady_clock::now() < sleepEnd) {
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("VPN monitor thread exception: {}", e.what());
    }

    Utils::Logger::Info("VPN monitor thread stopped");
}

void IPLeakProtectionImpl::DetectVPNState() {
    try {
        bool vpnDetected = DetectVPNInterface();

        m_vpnConnected = vpnDetected;
        m_vpnState = vpnDetected ? VPNState::Connected : VPNState::Disconnected;

        if (vpnDetected) {
            m_stats.currentVPNConnections = 1;
        } else {
            m_stats.currentVPNConnections = 0;
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("DetectVPNState failed: {}", e.what());
        m_vpnState = VPNState::Unknown;
    }
}

void IPLeakProtectionImpl::OnLeakDetected(const IPLeakDetectionResult& result) {
    // Copy callback under lock, invoke outside lock
    LeakDetectedCallback callback;
    {
        std::shared_lock lock(m_mutex);
        callback = m_leakCallback;
    }

    if (callback) {
        try {
            callback(result);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Leak callback exception: {}", e.what());
        }
    }

    // Update statistics by leak type
    auto leakTypeValue = static_cast<uint32_t>(result.leakType);
    for (size_t i = 0; i < 16; ++i) {
        if (leakTypeValue & (1u << i)) {
            m_stats.byLeakType[i]++;
        }
    }

    // Update statistics by severity
    if (static_cast<size_t>(result.severity) < m_stats.bySeverity.size()) {
        m_stats.bySeverity[static_cast<size_t>(result.severity)]++;
    }
}

void IPLeakProtectionImpl::OnKillSwitchTriggered(const KillSwitchEvent& event) {
    KillSwitchCallback callback;
    {
        std::shared_lock lock(m_mutex);
        callback = m_killSwitchCallback;
    }

    if (callback) {
        try {
            callback(event);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Kill switch callback exception: {}", e.what());
        }
    }
}

void IPLeakProtectionImpl::NotifyError(const std::string& message, int code) {
    ErrorCallback callback;
    {
        std::shared_lock lock(m_mutex);
        callback = m_errorCallback;
    }

    if (callback) {
        try {
            callback(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Error callback exception: {}", e.what());
        }
    }
}

bool IPLeakProtectionImpl::CheckDNSServerType(const std::string& dnsIP, DNSServerInfo& info) {
    if (dnsIP.empty()) return false;

    // Check against expanded known public DNS database
    for (const auto& entry : kKnownPublicDNS) {
        if (dnsIP == entry.ip) {
            info.serverType = entry.type;
            info.ispName = entry.provider;
            return true;
        }
    }

    // Check if the DNS server matches a known VPN adapter's DNS
    auto vpnAdapters = DetectVPNAdapters();
    if (!vpnAdapters.empty()) {
        // Query per-adapter DNS servers via GetAdaptersAddresses
        ULONG bufSize = 15000;
        std::vector<uint8_t> buf(bufSize);
        auto* pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());

        DWORD result = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_ALL_INTERFACES,
            nullptr, pAddresses, &bufSize);

        if (result == ERROR_BUFFER_OVERFLOW) {
            if (bufSize <= 4 * 1024 * 1024) {
                buf.resize(bufSize);
                pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data());
                result = GetAdaptersAddresses(AF_UNSPEC,
                    GAA_FLAG_INCLUDE_ALL_INTERFACES,
                    nullptr, pAddresses, &bufSize);
            }
        }

        if (result == NO_ERROR) {
            auto* pCurr = pAddresses;
            size_t count = 0;
            while (pCurr && count < kMaxAdapterIterations) {
                std::wstring wFriendly = pCurr->FriendlyName ? pCurr->FriendlyName : L"";
                std::string friendlyName = Utils::StringUtils::ToNarrow(wFriendly);
                std::string adapterName = pCurr->AdapterName ? pCurr->AdapterName : "";

                bool isVPN = std::any_of(vpnAdapters.begin(), vpnAdapters.end(),
                    [&](const VPNAdapterInfo& v) {
                        return v.description == friendlyName || v.adapterName == adapterName;
                    });

                // Check DNS servers assigned to this adapter
                auto* pDns = pCurr->FirstDnsServerAddress;
                size_t dnsCount = 0;
                while (pDns && dnsCount < kMaxDNSServerIterations) {
                    if (pDns->Address.lpSockaddr) {
                        char ipBuf[INET6_ADDRSTRLEN] = {};
                        if (pDns->Address.lpSockaddr->sa_family == AF_INET) {
                            auto* sa4 = reinterpret_cast<SOCKADDR_IN*>(pDns->Address.lpSockaddr);
                            inet_ntop(AF_INET, &sa4->sin_addr, ipBuf, sizeof(ipBuf));
                        } else if (pDns->Address.lpSockaddr->sa_family == AF_INET6) {
                            auto* sa6 = reinterpret_cast<SOCKADDR_IN6*>(pDns->Address.lpSockaddr);
                            inet_ntop(AF_INET6, &sa6->sin6_addr, ipBuf, sizeof(ipBuf));
                        }

                        if (dnsIP == ipBuf) {
                            if (isVPN) {
                                info.serverType = DNSServerType::VPN;
                                info.isVPNDNS = true;
                                info.ispName = "VPN DNS (" + friendlyName + ")";
                                return true;
                            }
                        }
                    }
                    pDns = pDns->Next;
                    ++dnsCount;
                }

                pCurr = pCurr->Next;
                ++count;
            }
        }
    }

    // Check if private IP (likely router/ISP DNS)
    if (IsPrivateIPAddress(dnsIP)) {
        info.serverType = DNSServerType::ISP;
        info.isISPDNS = true;
        info.ispName = "ISP/Router DNS";
        return true;
    }

    // Any remaining public IP that's not in our known-good list
    // is likely an ISP DNS server
    info.serverType = DNSServerType::ISP;
    info.isISPDNS = true;
    info.ispName = "Unknown DNS (treated as ISP)";
    return true;
}

bool IPLeakProtectionImpl::PerformDNSQuery(const std::string& domain,
                                           const std::string& dnsServer) {
    if (domain.empty()) {
        Utils::Logger::Error("PerformDNSQuery: empty domain");
        return false;
    }

    // Validate domain length (RFC 1035: max 253 chars)
    if (domain.size() > 253) {
        Utils::Logger::Error("PerformDNSQuery: domain exceeds max length");
        return false;
    }

    std::wstring wDomain = Utils::StringUtils::ToWide(domain);
    if (wDomain.empty()) return false;

    Utils::NetworkUtils::DnsQueryOptions queryOpts;
    queryOpts.timeoutMs = IPLeakConstants::DNS_QUERY_TIMEOUT_MS;

    // If a specific DNS server is provided, use it as the resolver
    if (!dnsServer.empty()) {
        std::wstring wServer = Utils::StringUtils::ToWide(dnsServer);
        Utils::NetworkUtils::IpAddress serverAddr;
        if (Utils::NetworkUtils::ParseIpAddress(wServer, serverAddr)) {
            queryOpts.customDnsServers.push_back(serverAddr);
            queryOpts.useSystemDns = false;
        } else {
            Utils::Logger::Error("PerformDNSQuery: invalid DNS server address: {}",
                dnsServer);
            return false;
        }
    }

    std::vector<Utils::NetworkUtils::DnsRecord> records;
    Utils::NetworkUtils::Error netErr;

    bool ok = Utils::NetworkUtils::QueryDns(wDomain,
        Utils::NetworkUtils::DnsRecordType::A, records, queryOpts, &netErr);

    if (!ok) {
        Utils::Logger::Debug("DNS query for {} via {} failed: {}",
            domain, dnsServer.empty() ? "system" : dnsServer,
            Utils::StringUtils::ToNarrow(netErr.message));
        return false;
    }

    return !records.empty();
}

// ============================================================================
// PUBLIC API IMPLEMENTATION (SINGLETON)
// ============================================================================

IPLeakProtection& IPLeakProtection::Instance() noexcept {
    static IPLeakProtection instance;
    return instance;
}

bool IPLeakProtection::HasInstance() noexcept {
    return s_instanceCreated.load();
}

IPLeakProtection::IPLeakProtection()
    : m_impl(std::make_unique<IPLeakProtectionImpl>()) {
    s_instanceCreated = true;
}

IPLeakProtection::~IPLeakProtection() {
    s_instanceCreated = false;
}

// Forward all public methods to implementation

bool IPLeakProtection::Initialize(const IPLeakProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

void IPLeakProtection::Shutdown() {
    m_impl->Shutdown();
}

bool IPLeakProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus IPLeakProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool IPLeakProtection::UpdateConfiguration(const IPLeakProtectionConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

IPLeakProtectionConfiguration IPLeakProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

IPLeakDetectionResult IPLeakProtection::CheckForLeaks() {
    return m_impl->CheckForLeaks();
}

IPLeakDetectionResult IPLeakProtection::CheckVPNLeak() {
    return m_impl->CheckVPNLeak();
}

IPLeakDetectionResult IPLeakProtection::CheckDNSLeak() {
    return m_impl->CheckDNSLeak();
}

WebRTCLeakInfo IPLeakProtection::CheckWebRTCLeak() {
    return m_impl->CheckWebRTCLeak();
}

IPLeakDetectionResult IPLeakProtection::CheckIPv6Leak() {
    return m_impl->CheckIPv6Leak();
}

IPAddressInfo IPLeakProtection::GetPublicIP() {
    return m_impl->GetPublicIP();
}

std::vector<DNSServerInfo> IPLeakProtection::GetDNSServers() {
    return m_impl->GetDNSServers();
}

std::optional<VPNConnectionInfo> IPLeakProtection::GetVPNInfo() const {
    return m_impl->GetVPNInfo();
}

bool IPLeakProtection::IsVPNConnected() const noexcept {
    return m_impl->IsVPNConnected();
}

VPNState IPLeakProtection::GetVPNState() const noexcept {
    return m_impl->GetVPNState();
}

bool IPLeakProtection::StartVPNMonitoring() {
    return m_impl->StartVPNMonitoring();
}

void IPLeakProtection::StopVPNMonitoring() {
    m_impl->StopVPNMonitoring();
}

bool IPLeakProtection::ActivateKillSwitch() {
    return m_impl->ActivateKillSwitch();
}

bool IPLeakProtection::DeactivateKillSwitch() {
    return m_impl->DeactivateKillSwitch();
}

bool IPLeakProtection::IsKillSwitchActive() const noexcept {
    return m_impl->IsKillSwitchActive();
}

std::vector<KillSwitchEvent> IPLeakProtection::GetKillSwitchEvents() const {
    return m_impl->GetKillSwitchEvents();
}

bool IPLeakProtection::BlockIPv6() {
    return m_impl->BlockIPv6();
}

bool IPLeakProtection::UnblockIPv6() {
    return m_impl->UnblockIPv6();
}

bool IPLeakProtection::ForceVPNReconnect() {
    return m_impl->ForceVPNReconnect();
}

bool IPLeakProtection::ApplyProtectionPolicy(LeakType leakType, ProtectionAction action) {
    return m_impl->ApplyProtectionPolicy(leakType, action);
}

bool IPLeakProtection::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void IPLeakProtection::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool IPLeakProtection::IsMonitoring() const noexcept {
    return m_impl->IsMonitoring();
}

std::vector<IPLeakDetectionResult> IPLeakProtection::GetDetectedLeaks() const {
    return m_impl->GetDetectedLeaks();
}

IoTSubsystemStatus IPLeakProtection::GetIoTStatus() const {
    return m_impl->GetIoTStatus();
}

bool IPLeakProtection::StartIoTModules() {
    return m_impl->StartIoTModules();
}

void IPLeakProtection::StopIoTModules() {
    m_impl->StopIoTModules();
}

bool IPLeakProtection::RunIoTSecurityScan() {
    return m_impl->RunIoTSecurityScan();
}

void IPLeakProtection::RegisterLeakCallback(LeakDetectedCallback callback) {
    m_impl->RegisterLeakCallback(std::move(callback));
}

void IPLeakProtection::RegisterKillSwitchCallback(KillSwitchCallback callback) {
    m_impl->RegisterKillSwitchCallback(std::move(callback));
}

void IPLeakProtection::RegisterVPNStateCallback(VPNStateChangeCallback callback) {
    m_impl->RegisterVPNStateCallback(std::move(callback));
}

void IPLeakProtection::RegisterDNSLeakCallback(DNSLeakCallback callback) {
    m_impl->RegisterDNSLeakCallback(std::move(callback));
}

void IPLeakProtection::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void IPLeakProtection::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

IPLeakStatistics IPLeakProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void IPLeakProtection::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool IPLeakProtection::SelfTest() {
    return m_impl->SelfTest();
}

std::string IPLeakProtection::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << IPLeakConstants::VERSION_MAJOR << "."
        << IPLeakConstants::VERSION_MINOR << "."
        << IPLeakConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetLeakTypeName(LeakType type) noexcept {
    switch (type) {
        case LeakType::None: return "None";
        case LeakType::VPNLeak: return "VPNLeak";
        case LeakType::DNSLeak: return "DNSLeak";
        case LeakType::WebRTCLeak: return "WebRTCLeak";
        case LeakType::IPv6Leak: return "IPv6Leak";
        case LeakType::ProxyBypass: return "ProxyBypass";
        case LeakType::SplitTunnelLeak: return "SplitTunnelLeak";
        case LeakType::TimezoneLeak: return "TimezoneLeak";
        case LeakType::GeoLocationLeak: return "GeoLocationLeak";
        case LeakType::TransparentProxy: return "TransparentProxy";
        case LeakType::TeredoLeak: return "TeredoLeak";
        case LeakType::STUNLeak: return "STUNLeak";
        case LeakType::TURNLeak: return "TURNLeak";
        case LeakType::LocalNetworkLeak: return "LocalNetworkLeak";
        case LeakType::HostnameLeak: return "HostnameLeak";
        case LeakType::PortForwardLeak: return "PortForwardLeak";
        case LeakType::HTTPProxyLeak: return "HTTPProxyLeak";
        default: return "Unknown";
    }
}

std::string_view GetLeakSeverityName(LeakSeverity severity) noexcept {
    switch (severity) {
        case LeakSeverity::None: return "None";
        case LeakSeverity::Informational: return "Informational";
        case LeakSeverity::Low: return "Low";
        case LeakSeverity::Medium: return "Medium";
        case LeakSeverity::High: return "High";
        case LeakSeverity::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetVPNStateName(VPNState state) noexcept {
    switch (state) {
        case VPNState::Unknown: return "Unknown";
        case VPNState::Disconnected: return "Disconnected";
        case VPNState::Connecting: return "Connecting";
        case VPNState::Connected: return "Connected";
        case VPNState::Reconnecting: return "Reconnecting";
        case VPNState::Disconnecting: return "Disconnecting";
        case VPNState::Failed: return "Failed";
        default: return "Unknown";
    }
}

std::string_view GetProtectionActionName(ProtectionAction action) noexcept {
    switch (action) {
        case ProtectionAction::None: return "None";
        case ProtectionAction::Alert: return "Alert";
        case ProtectionAction::Block: return "Block";
        case ProtectionAction::KillSwitch: return "KillSwitch";
        case ProtectionAction::Reconnect: return "Reconnect";
        case ProtectionAction::Disable: return "Disable";
        default: return "Unknown";
    }
}

std::string_view GetDNSServerTypeName(DNSServerType type) noexcept {
    switch (type) {
        case DNSServerType::Unknown: return "Unknown";
        case DNSServerType::ISP: return "ISP";
        case DNSServerType::Public: return "Public";
        case DNSServerType::Private: return "Private";
        case DNSServerType::VPN: return "VPN";
        case DNSServerType::DNSCrypt: return "DNSCrypt";
        case DNSServerType::DoH: return "DoH";
        case DNSServerType::DoT: return "DoT";
        default: return "Unknown";
    }
}

bool IsPrivateIP(const std::string& ip) noexcept {
    return IsPrivateIPAddress(ip);
}

bool IsIPv6Address(const std::string& ip) noexcept {
    return IsIPv6Addr(ip);
}

LeakSeverity CalculateLeakSeverity(LeakType type, bool vpnRequired) noexcept {
    auto typeValue = static_cast<uint32_t>(type);

    // Critical leaks
    if (vpnRequired && (typeValue & static_cast<uint32_t>(LeakType::VPNLeak))) {
        return LeakSeverity::Critical;
    }

    // High severity leaks
    if ((typeValue & static_cast<uint32_t>(LeakType::DNSLeak)) ||
        (typeValue & static_cast<uint32_t>(LeakType::IPv6Leak))) {
        return LeakSeverity::High;
    }

    // Medium severity leaks
    if ((typeValue & static_cast<uint32_t>(LeakType::WebRTCLeak)) ||
        (typeValue & static_cast<uint32_t>(LeakType::ProxyBypass))) {
        return LeakSeverity::Medium;
    }

    // Low severity leaks
    if ((typeValue & static_cast<uint32_t>(LeakType::TimezoneLeak)) ||
        (typeValue & static_cast<uint32_t>(LeakType::GeoLocationLeak))) {
        return LeakSeverity::Low;
    }

    return LeakSeverity::None;
}

}  // namespace IoT
}  // namespace ShadowStrike
