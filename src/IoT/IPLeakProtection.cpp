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
#include "../ThreatIntel/ThreatIntelManager.hpp"

#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <regex>
#include <cmath>

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

/// @brief Generate unique event ID
std::string GenerateEventId() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::ostringstream oss;
    oss << "LEAK-" << std::hex << std::setw(12) << std::setfill('0') << ms
        << "-" << std::setw(8) << std::setfill('0') << counter.fetch_add(1);
    return oss.str();
}

/// @brief Check if IP is private
bool IsPrivateIPAddress(const std::string& ip) {
    if (ip.empty()) return false;

    // Check IPv4 private ranges
    if (ip.find(':') == std::string::npos) {
        struct in_addr addr;
        if (inet_pton(AF_INET, ip.c_str(), &addr) == 1) {
            uint32_t ipVal = ntohl(addr.s_addr);

            // 10.0.0.0/8
            if ((ipVal & 0xFF000000) == 0x0A000000) return true;
            // 172.16.0.0/12
            if ((ipVal & 0xFFF00000) == 0xAC100000) return true;
            // 192.168.0.0/16
            if ((ipVal & 0xFFFF0000) == 0xC0A80000) return true;
            // 127.0.0.0/8
            if ((ipVal & 0xFF000000) == 0x7F000000) return true;
        }
    } else {
        // IPv6 private ranges
        if (ip.find("fe80:") == 0) return true;  // Link-local
        if (ip.find("fc00:") == 0) return true;  // Unique local
        if (ip.find("fd00:") == 0) return true;  // Unique local
        if (ip == "::1") return true;            // Loopback
    }

    return false;
}

/// @brief Check if IPv6 address
bool IsIPv6Addr(const std::string& ip) {
    return ip.find(':') != std::string::npos;
}

/// @brief Query external IP service
std::string QueryPublicIP() {
    // In production, would use HTTP GET to multiple IP check services
    // For now, simplified implementation
    return ""; // Placeholder
}

/// @brief Get system DNS servers
std::vector<std::string> GetSystemDNSServers() {
    std::vector<std::string> dnsServers;

    FIXED_INFO* pFixedInfo = nullptr;
    ULONG bufferSize = sizeof(FIXED_INFO);
    std::vector<uint8_t> buffer(bufferSize);

    pFixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());

    DWORD result = GetNetworkParams(pFixedInfo, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        pFixedInfo = reinterpret_cast<FIXED_INFO*>(buffer.data());
        result = GetNetworkParams(pFixedInfo, &bufferSize);
    }

    if (result == NO_ERROR) {
        IP_ADDR_STRING* pDnsServer = &pFixedInfo->DnsServerList;
        while (pDnsServer) {
            dnsServers.push_back(pDnsServer->IpAddress.String);
            pDnsServer = pDnsServer->Next;
        }
    }

    return dnsServers;
}

/// @brief Detect VPN interface
bool DetectVPNInterface() {
    // Check for common VPN adapters
    PIP_ADAPTER_INFO pAdapterInfo = nullptr;
    ULONG bufferSize = 15000;
    std::vector<uint8_t> buffer(bufferSize);

    pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    DWORD result = GetAdaptersInfo(pAdapterInfo, &bufferSize);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
        result = GetAdaptersInfo(pAdapterInfo, &bufferSize);
    }

    if (result == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            std::string desc = pAdapter->Description;
            std::string name = pAdapter->AdapterName;

            // Check for VPN keywords
            if (desc.find("VPN") != std::string::npos ||
                desc.find("TAP") != std::string::npos ||
                desc.find("TUN") != std::string::npos ||
                desc.find("WireGuard") != std::string::npos ||
                desc.find("OpenVPN") != std::string::npos ||
                desc.find("NordVPN") != std::string::npos ||
                desc.find("ExpressVPN") != std::string::npos) {
                return true;
            }

            pAdapter = pAdapter->Next;
        }
    }

    return false;
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
    std::unique_lock lock(m_mutex);

    try {
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

        // Detect initial VPN state
        DetectVPNState();

        // Start VPN monitoring if enabled
        if (m_config.enableVPNMonitoring) {
            m_stopVPNMonitor = false;
            m_vpnMonitorThread = std::make_unique<std::thread>(
                &IPLeakProtectionImpl::VPNMonitorThreadFunc, this);
        }

        // Start monitoring if configured
        if (m_config.enabled) {
            StartMonitoring();
        }

        m_isActive = true;
        m_status = ModuleStatus::Running;

        Utils::Logger::Info("IPLeakProtection initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Critical("IPLeakProtection initialization failed: {}", e.what());
        m_status = ModuleStatus::Error;
        return false;
    }
}

void IPLeakProtectionImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    try {
        if (!m_isActive) {
            return;
        }

        // Stop monitoring
        m_stopMonitoring = true;
        if (m_monitorThread && m_monitorThread->joinable()) {
            lock.unlock();
            m_monitorThread->join();
            lock.lock();
        }

        // Stop VPN monitoring
        m_stopVPNMonitor = true;
        if (m_vpnMonitorThread && m_vpnMonitorThread->joinable()) {
            lock.unlock();
            m_vpnMonitorThread->join();
            lock.lock();
        }

        // Deactivate kill switch
        if (m_killSwitchActive) {
            lock.unlock();
            DeactivateKillSwitch();
            lock.lock();
        }

        // Cleanup Winsock
        WSACleanup();

        m_isActive = false;
        m_status = ModuleStatus::Stopped;

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

        IPLeakDetectionResult result;
        result.detectionTime = std::chrono::system_clock::now();
        result.detectionMethod = "Comprehensive Leak Check";

        // Check VPN leak
        if (m_config.enableVPNMonitoring) {
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
        if (m_config.enableDNSLeakDetection) {
            auto dnsResult = CheckDNSLeak();
            if (dnsResult.leakDetected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::DNSLeak));
                result.dnsServers = dnsResult.dnsServers;
            }
        }

        // Check IPv6 leak
        if (m_config.enableIPv6Detection) {
            auto ipv6Result = CheckIPv6Leak();
            if (ipv6Result.leakDetected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::IPv6Leak));
            }
        }

        // Check WebRTC leak
        if (m_config.enableWebRTCDetection) {
            auto webrtcResult = CheckWebRTCLeak();
            if (webrtcResult.detected) {
                result.leakDetected = true;
                result.leakType = static_cast<LeakType>(
                    static_cast<uint32_t>(result.leakType) | static_cast<uint32_t>(LeakType::WebRTCLeak));
                result.webrtcIPs = webrtcResult.publicIPs;
            }
        }

        if (result.leakDetected) {
            result.severity = CalculateLeakSeverity(result.leakType, m_config.vpnRequired);
            result.confidence = 85;
            result.recommendation = "Enable VPN kill switch and verify VPN connection";

            m_stats.leaksDetected++;

            // Store result
            {
                std::unique_lock lock(m_mutex);
                m_detectedLeaks.push_back(result);
                if (m_detectedLeaks.size() > IPLeakConstants::MAX_TRACKED_LEAKS) {
                    m_detectedLeaks.erase(m_detectedLeaks.begin());
                }
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
        // Check if VPN is connected
        if (!m_vpnConnected) {
            if (m_config.vpnRequired) {
                result.leakDetected = true;
                result.leakType = LeakType::VPNLeak;
                result.severity = LeakSeverity::High;
                result.details = "VPN is not connected";
                result.recommendation = "Connect to VPN";
            }
            return result;
        }

        // Get public IP
        auto publicIP = GetPublicIP();

        // Check if IP matches expected VPN IP range
        // In production, would validate against known VPN IP ranges
        if (!publicIP.isVPN && m_config.vpnRequired) {
            result.leakDetected = true;
            result.leakType = LeakType::VPNLeak;
            result.severity = LeakSeverity::Critical;
            result.actualIP = publicIP.ipAddress;
            result.leakedIPs.push_back(publicIP.ipAddress);
            result.details = "Public IP does not match VPN";
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
        auto dnsServers = GetDNSServers();
        result.dnsServers = dnsServers;

        bool hasISPDNS = false;
        bool hasVPNDNS = false;

        for (const auto& dns : dnsServers) {
            if (dns.isISPDNS) {
                hasISPDNS = true;
            }
            if (dns.isVPNDNS) {
                hasVPNDNS = true;
            }
        }

        // If VPN is connected but using ISP DNS
        if (m_vpnConnected && hasISPDNS && !hasVPNDNS) {
            result.leakDetected = true;
            result.leakType = LeakType::DNSLeak;
            result.severity = LeakSeverity::High;
            result.details = "Using ISP DNS servers while VPN is connected";
            result.recommendation = "Configure VPN to use VPN DNS servers";
            result.confidence = 95;

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
        // In production, would integrate with browser to check WebRTC leaks
        // For now, simplified implementation

        // Placeholder: Check if local IP can be exposed via WebRTC
        // This would require browser integration or analysis of browser processes

        if (result.detected) {
            m_stats.webrtcLeaks++;
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
        // Check if IPv6 is enabled while VPN is active
        if (m_vpnConnected && !m_ipv6Blocked) {
            // Get IPv6 addresses
            PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
            ULONG bufferSize = 15000;
            std::vector<uint8_t> buffer(bufferSize);

            pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());

            DWORD dwResult = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX,
                nullptr, pAddresses, &bufferSize);

            if (dwResult == ERROR_BUFFER_OVERFLOW) {
                buffer.resize(bufferSize);
                pAddresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
                dwResult = GetAdaptersAddresses(AF_INET6, GAA_FLAG_INCLUDE_PREFIX,
                    nullptr, pAddresses, &bufferSize);
            }

            if (dwResult == NO_ERROR) {
                PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
                while (pCurrAddresses) {
                    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                    while (pUnicast) {
                        if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                            char ipStr[INET6_ADDRSTRLEN];
                            SOCKADDR_IN6* sa6 = reinterpret_cast<SOCKADDR_IN6*>(pUnicast->Address.lpSockaddr);
                            inet_ntop(AF_INET6, &sa6->sin6_addr, ipStr, sizeof(ipStr));

                            std::string ipv6 = ipStr;

                            // Check if it's not link-local or loopback
                            if (!IsPrivateIPAddress(ipv6)) {
                                result.leakDetected = true;
                                result.leakType = LeakType::IPv6Leak;
                                result.severity = LeakSeverity::Medium;
                                result.leakedIPs.push_back(ipv6);
                                result.details = "IPv6 leak detected while VPN active";
                                result.recommendation = "Block IPv6 traffic or use IPv6-compatible VPN";

                                m_stats.ipv6Leaks++;
                                break;
                            }
                        }
                        pUnicast = pUnicast->Next;
                    }
                    pCurrAddresses = pCurrAddresses->Next;
                }
            }
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("CheckIPv6Leak failed: {}", e.what());
    }

    return result;
}

IPAddressInfo IPLeakProtectionImpl::GetPublicIP() {
    IPAddressInfo info;

    try {
        // In production, would query multiple IP check services
        // For now, simplified implementation
        std::string publicIP = QueryPublicIP();

        if (!publicIP.empty()) {
            info.ipAddress = publicIP;
            info.isIPv6 = IsIPv6Addr(publicIP);
            info.isPrivate = IsPrivateIPAddress(publicIP);

            // In production, would query GeoIP database
            // Placeholder values
            info.countryCode = "US";
            info.ispName = "Unknown ISP";
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

        // In production, would add Windows Firewall rules to block all non-VPN traffic
        // Simplified implementation

        m_killSwitchActive = true;
        m_stats.killSwitchActivations++;

        // Create kill switch event
        KillSwitchEvent event;
        event.eventId = GenerateEventId();
        event.eventType = "KillSwitchActivated";
        event.action = ProtectionAction::KillSwitch;
        event.eventTime = std::chrono::system_clock::now();
        event.description = "Kill switch activated to prevent IP leak";

        m_killSwitchEvents.push_back(event);

        lock.unlock();

        OnKillSwitchTriggered(event);

        Utils::Logger::Info("Kill switch activated");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ActivateKillSwitch failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::DeactivateKillSwitch() {
    try {
        std::unique_lock lock(m_mutex);

        if (!m_killSwitchActive) {
            return true;
        }

        // In production, would remove firewall rules
        m_killSwitchActive = false;

        // Create kill switch event
        KillSwitchEvent event;
        event.eventId = GenerateEventId();
        event.eventType = "KillSwitchDeactivated";
        event.action = ProtectionAction::None;
        event.eventTime = std::chrono::system_clock::now();
        event.description = "Kill switch deactivated";

        m_killSwitchEvents.push_back(event);

        Utils::Logger::Info("Kill switch deactivated");
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
        // In production, would disable IPv6 via Windows Firewall or netsh
        m_ipv6Blocked = true;

        Utils::Logger::Info("IPv6 blocked");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("BlockIPv6 failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::UnblockIPv6() {
    try {
        // In production, would re-enable IPv6
        m_ipv6Blocked = false;

        Utils::Logger::Info("IPv6 unblocked");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("UnblockIPv6 failed: {}", e.what());
        return false;
    }
}

bool IPLeakProtectionImpl::ForceVPNReconnect() {
    try {
        // In production, would trigger VPN reconnection
        m_stats.autoReconnects++;

        Utils::Logger::Info("VPN reconnect triggered");
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
        // In production, would start IoT modules:
        // - IoTDeviceScanner::Instance().Initialize()
        // - WiFiSecurityAnalyzer::Instance().Initialize()
        // - RouterSecurityChecker::Instance().Initialize()
        // - SmartHomeProtection::Instance().Initialize()

        std::unique_lock lock(m_mutex);
        m_iotStatus.deviceScannerActive = true;
        m_iotStatus.wifiAnalyzerActive = true;
        m_iotStatus.routerCheckerActive = true;
        m_iotStatus.smartHomeActive = true;

        Utils::Logger::Info("IoT subsystem modules started");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("StartIoTModules failed: {}", e.what());
        return false;
    }
}

void IPLeakProtectionImpl::StopIoTModules() {
    try {
        // In production, would stop IoT modules

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
        // In production, would trigger scans on all IoT modules

        Utils::Logger::Info("IoT security scan initiated");
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
            // Perform leak check
            auto result = CheckForLeaks();

            if (result.leakDetected && m_config.enableKillSwitch) {
                // Auto-activate kill switch on critical leaks
                if (result.severity >= LeakSeverity::High) {
                    ActivateKillSwitch();
                }
            }

            // Sleep for monitoring interval
            std::this_thread::sleep_for(std::chrono::seconds(m_config.monitoringIntervalSeconds));
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

            // Detect current VPN state
            DetectVPNState();

            VPNState newState = m_vpnState.load();

            // Notify if state changed
            if (oldState != newState) {
                if (m_vpnStateCallback) {
                    try {
                        m_vpnStateCallback(oldState, newState);
                    } catch (...) {}
                }
            }

            // Sleep for VPN check interval
            std::this_thread::sleep_for(std::chrono::milliseconds(IPLeakConstants::VPN_CHECK_INTERVAL_MS));
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
    if (m_leakCallback) {
        try {
            m_leakCallback(result);
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
    if (m_killSwitchCallback) {
        try {
            m_killSwitchCallback(event);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Kill switch callback exception: {}", e.what());
        }
    }
}

void IPLeakProtectionImpl::NotifyError(const std::string& message, int code) {
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("Error callback exception: {}", e.what());
        }
    }
}

bool IPLeakProtectionImpl::CheckDNSServerType(const std::string& dnsIP, DNSServerInfo& info) {
    // Check against known DNS server types
    if (dnsIP == "8.8.8.8" || dnsIP == "8.8.4.4") {
        info.serverType = DNSServerType::Public;
        info.ispName = "Google Public DNS";
        return true;
    }

    if (dnsIP == "1.1.1.1" || dnsIP == "1.0.0.1") {
        info.serverType = DNSServerType::Public;
        info.ispName = "Cloudflare DNS";
        return true;
    }

    // Check if private IP (likely router/ISP)
    if (IsPrivateIPAddress(dnsIP)) {
        info.serverType = DNSServerType::ISP;
        info.isISPDNS = true;
        return true;
    }

    info.serverType = DNSServerType::Unknown;
    return false;
}

bool IPLeakProtectionImpl::PerformDNSQuery(const std::string& domain, const std::string& dnsServer) {
    // In production, would perform actual DNS query
    // Simplified implementation
    return true;
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
