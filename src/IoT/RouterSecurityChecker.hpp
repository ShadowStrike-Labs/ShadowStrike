/**
 * ============================================================================
 * ShadowStrike NGAV - ROUTER SECURITY CHECKER MODULE
 * ============================================================================
 *
 * @file RouterSecurityChecker.hpp
 * @brief Enterprise-grade router and gateway security assessment engine for
 *        detecting misconfigurations, vulnerabilities, and security risks.
 *
 * Provides comprehensive router security analysis including credential
 * testing, configuration assessment, and known vulnerability detection.
 *
 * ASSESSMENT CAPABILITIES:
 * ========================
 *
 * 1. CONFIGURATION ANALYSIS
 *    - Default credential detection
 *    - Weak password testing
 *    - Admin interface exposure
 *    - Remote management settings
 *    - WAN access controls
 *
 * 2. SERVICE ENUMERATION
 *    - UPnP/IGD analysis
 *    - SNMP configuration
 *    - Telnet/SSH access
 *    - HTTP/HTTPS admin panels
 *    - TR-069/CWMP detection
 *
 * 3. WIRELESS SECURITY
 *    - Encryption strength (WEP/WPA/WPA2/WPA3)
 *    - WPS configuration
 *    - SSID security
 *    - Guest network isolation
 *    - Band steering security
 *
 * 4. NETWORK SECURITY
 *    - Firewall configuration
 *    - NAT/port forwarding
 *    - DNS settings (hijacking detection)
 *    - DHCP security
 *    - DMZ configuration
 *
 * 5. VULNERABILITY ASSESSMENT
 *    - Known CVE matching
 *    - Firmware version analysis
 *    - Backdoor detection
 *    - Default configuration risks
 *    - Security feature assessment
 *
 * SUPPORTED PROTOCOLS:
 * ====================
 * - UPnP/IGD
 * - SNMP v1/v2c/v3
 * - HTTP/HTTPS
 * - Telnet
 * - TR-069/CWMP
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for CVE matching
 * - PatternStore for detection patterns
 * - IoTDeviceScanner for discovery
 * - NetworkUtils for communication
 *
 * @note Requires appropriate permissions for some tests.
 * @note Credential testing requires explicit authorization.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <future>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <WinSock2.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::IoT {
    class RouterSecurityCheckerImpl;
}

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace RouterConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default timeout (ms)
    inline constexpr uint32_t DEFAULT_TIMEOUT_MS = 10000;
    
    /// @brief Common router admin ports
    inline constexpr uint16_t ADMIN_PORTS[] = {
        80, 443, 8080, 8443, 8000, 8888
    };
    
    /// @brief Common default usernames
    inline constexpr const char* DEFAULT_USERNAMES[] = {
        "admin", "root", "user", "support", "guest"
    };
    
    /// @brief Common default passwords
    inline constexpr const char* DEFAULT_PASSWORDS[] = {
        "admin", "password", "1234", "12345", "root",
        "default", "user", "guest", ""
    };

}  // namespace RouterConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Router vendor
 */
enum class RouterVendor : uint8_t {
    Unknown         = 0,
    Cisco           = 1,
    Netgear         = 2,
    TPLink          = 3,
    DLink           = 4,
    Asus            = 5,
    Linksys         = 6,
    Belkin          = 7,
    Huawei          = 8,
    ZTE             = 9,
    Ubiquiti        = 10,
    MikroTik        = 11,
    Juniper         = 12,
    Aruba           = 13,
    Fortinet        = 14,
    Meraki          = 15,
    ISP_Provided    = 100
};

/**
 * @brief WiFi encryption type
 */
enum class WirelessEncryption : uint8_t {
    Unknown         = 0,
    Open            = 1,
    WEP             = 2,
    WPA_Personal    = 3,
    WPA_Enterprise  = 4,
    WPA2_Personal   = 5,
    WPA2_Enterprise = 6,
    WPA3_Personal   = 7,
    WPA3_Enterprise = 8,
    WPA3_SAE        = 9,
    Mixed           = 10
};

/**
 * @brief Security risk level
 */
enum class SecurityRiskLevel : uint8_t {
    Secure          = 0,
    Informational   = 1,
    Low             = 2,
    Medium          = 3,
    High            = 4,
    Critical        = 5
};

/**
 * @brief Security issue type
 */
enum class SecurityIssueType : uint32_t {
    None                    = 0,
    DefaultCredentials      = 1 << 0,
    WeakPassword            = 1 << 1,
    WeakEncryption          = 1 << 2,
    WEPEnabled              = 1 << 3,
    WPSEnabled              = 1 << 4,
    UPnPEnabled             = 1 << 5,
    TelnetEnabled           = 1 << 6,
    HTTPAdmin               = 1 << 7,
    WANAdminAccess          = 1 << 8,
    DNSHijacked             = 1 << 9,
    OutdatedFirmware        = 1 << 10,
    KnownCVE                = 1 << 11,
    OpenPorts               = 1 << 12,
    DMZEnabled              = 1 << 13,
    NoFirewall              = 1 << 14,
    GuestNetworkUnsecured   = 1 << 15,
    RemoteManagement        = 1 << 16,
    SNMPPublicCommunity     = 1 << 17,
    TR069Exposed            = 1 << 18,
    BackdoorDetected        = 1 << 19
};

/**
 * @brief Assessment status
 */
enum class AssessmentStatus : uint8_t {
    NotStarted      = 0,
    InProgress      = 1,
    Completed       = 2,
    Failed          = 3,
    Cancelled       = 4,
    PartialSuccess  = 5
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Assessing       = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Security issue details
 */
struct SecurityIssue {
    /// @brief Issue type
    SecurityIssueType type = SecurityIssueType::None;
    
    /// @brief Risk level
    SecurityRiskLevel riskLevel = SecurityRiskLevel::Informational;
    
    /// @brief Issue title
    std::string title;
    
    /// @brief Description
    std::string description;
    
    /// @brief Remediation advice
    std::string remediation;
    
    /// @brief CVE ID (if applicable)
    std::string cveId;
    
    /// @brief CVSS score (if applicable)
    float cvssScore = 0.0f;
    
    /// @brief Evidence
    std::string evidence;
    
    /// @brief Reference URLs
    std::vector<std::string> references;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Port forwarding rule
 */
struct PortForwardRule {
    /// @brief External port
    uint16_t externalPort = 0;
    
    /// @brief Internal port
    uint16_t internalPort = 0;
    
    /// @brief Protocol (TCP/UDP)
    std::string protocol;
    
    /// @brief Internal IP
    std::string internalIP;
    
    /// @brief Rule name
    std::string ruleName;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Is potentially risky
    bool isRisky = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Wireless network info
 */
struct WirelessNetworkInfo {
    /// @brief SSID
    std::string ssid;
    
    /// @brief BSSID
    std::string bssid;
    
    /// @brief Encryption type
    WirelessEncryption encryption = WirelessEncryption::Unknown;
    
    /// @brief Is 5GHz band
    bool is5GHz = false;
    
    /// @brief Channel
    int channel = 0;
    
    /// @brief Signal strength (dBm)
    int signalStrength = 0;
    
    /// @brief Is hidden
    bool isHidden = false;
    
    /// @brief WPS enabled
    bool wpsEnabled = false;
    
    /// @brief Is guest network
    bool isGuestNetwork = false;
    
    /// @brief Client isolation enabled
    bool clientIsolation = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief UPnP/IGD info
 */
struct UPnPInfo {
    /// @brief UPnP enabled
    bool enabled = false;
    
    /// @brief Device description URL
    std::string descriptionUrl;
    
    /// @brief Friendly name
    std::string friendlyName;
    
    /// @brief Manufacturer
    std::string manufacturer;
    
    /// @brief Model name
    std::string modelName;
    
    /// @brief Model number
    std::string modelNumber;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief Port mappings
    std::vector<PortForwardRule> portMappings;
    
    /// @brief External IP
    std::string externalIP;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Router security report
 */
struct RouterSecurityReport {
    /// @brief Router IP
    std::string routerIP;
    
    /// @brief Router name
    std::string routerName;
    
    /// @brief Router vendor
    RouterVendor vendor = RouterVendor::Unknown;
    
    /// @brief Model
    std::string model;
    
    /// @brief Firmware version
    std::string firmwareVersion;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief Overall security score (0-100)
    int securityScore = 0;
    
    /// @brief Overall risk level
    SecurityRiskLevel overallRisk = SecurityRiskLevel::Secure;
    
    /// @brief Default credentials found
    bool defaultCredsFound = false;
    
    /// @brief UPnP info
    UPnPInfo upnpInfo;
    
    /// @brief WAN admin access enabled
    bool wanAdminAccess = false;
    
    /// @brief Telnet enabled
    bool telnetEnabled = false;
    
    /// @brief HTTP admin (no HTTPS)
    bool httpAdminOnly = false;
    
    /// @brief Open ports (external)
    std::vector<uint16_t> openWANPorts;
    
    /// @brief Port forwarding rules
    std::vector<PortForwardRule> portForwardRules;
    
    /// @brief DNS servers
    std::vector<std::string> dnsServers;
    
    /// @brief Is DNS hijacked
    bool dnsHijacked = false;
    
    /// @brief Wireless networks
    std::vector<WirelessNetworkInfo> wirelessNetworks;
    
    /// @brief Security issues found
    std::vector<SecurityIssue> securityIssues;
    
    /// @brief CVEs matched
    std::vector<std::string> cveMatches;
    
    /// @brief Assessment status
    AssessmentStatus status = AssessmentStatus::NotStarted;
    
    /// @brief Assessment time
    SystemTimePoint assessmentTime;
    
    /// @brief Assessment duration
    std::chrono::seconds assessmentDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] uint32_t GetCriticalIssueCount() const;
    [[nodiscard]] uint32_t GetHighIssueCount() const;
};

/**
 * @brief Assessment configuration
 */
struct RouterAssessmentConfig {
    /// @brief Target gateway IP (empty = auto-detect)
    std::string gatewayIP;
    
    /// @brief Check default credentials
    bool checkDefaultCredentials = true;
    
    /// @brief Check UPnP
    bool checkUPnP = true;
    
    /// @brief Check wireless security
    bool checkWireless = true;
    
    /// @brief Check DNS hijacking
    bool checkDNS = true;
    
    /// @brief Check for CVEs
    bool checkCVEs = true;
    
    /// @brief Port scan external ports
    bool scanExternalPorts = false;
    
    /// @brief Timeout (ms)
    uint32_t timeoutMs = RouterConstants::DEFAULT_TIMEOUT_MS;
    
    /// @brief Custom credentials to test
    std::vector<std::pair<std::string, std::string>> customCredentials;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct RouterStatistics {
    std::atomic<uint64_t> totalAssessments{0};
    std::atomic<uint64_t> completedAssessments{0};
    std::atomic<uint64_t> defaultCredsFound{0};
    std::atomic<uint64_t> criticalIssuesFound{0};
    std::atomic<uint64_t> highIssuesFound{0};
    std::atomic<uint64_t> cvesMatched{0};
    std::atomic<uint64_t> dnsHijackingDetected{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Module configuration
 */
struct RouterCheckerConfiguration {
    /// @brief Enable checker
    bool enabled = true;
    
    /// @brief Default assessment config
    RouterAssessmentConfig defaultAssessmentConfig;
    
    /// @brief Auto-assess gateway on startup
    bool autoAssessOnStartup = true;
    
    /// @brief Periodic assessment interval (hours, 0 = disabled)
    uint32_t periodicAssessmentHours = 24;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AssessmentCallback = std::function<void(const RouterSecurityReport&)>;
using IssueFoundCallback = std::function<void(const SecurityIssue&)>;
using ProgressCallback = std::function<void(float progress, const std::string& status)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// ROUTER SECURITY CHECKER CLASS
// ============================================================================

/**
 * @class RouterSecurityChecker
 * @brief Enterprise router security assessment engine
 */
class RouterSecurityChecker final {
public:
    [[nodiscard]] static RouterSecurityChecker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    RouterSecurityChecker(const RouterSecurityChecker&) = delete;
    RouterSecurityChecker& operator=(const RouterSecurityChecker&) = delete;
    RouterSecurityChecker(RouterSecurityChecker&&) = delete;
    RouterSecurityChecker& operator=(RouterSecurityChecker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const RouterCheckerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const RouterCheckerConfiguration& config);
    [[nodiscard]] RouterCheckerConfiguration GetConfiguration() const;

    // ========================================================================
    // ASSESSMENT
    // ========================================================================
    
    /// @brief Audit gateway (async)
    [[nodiscard]] std::future<RouterSecurityReport> AuditGateway(
        const std::string& gatewayIP = "");
    
    /// @brief Audit gateway (sync)
    [[nodiscard]] RouterSecurityReport AuditGatewaySync(
        const std::string& gatewayIP = "",
        const RouterAssessmentConfig& config = {});
    
    /// @brief Quick security check
    [[nodiscard]] RouterSecurityReport QuickSecurityCheck(const std::string& gatewayIP = "");
    
    /// @brief Cancel ongoing assessment
    void CancelAssessment();
    
    /// @brief Get assessment progress
    [[nodiscard]] float GetProgress() const noexcept;

    // ========================================================================
    // SPECIFIC CHECKS
    // ========================================================================
    
    /// @brief Check default credentials
    [[nodiscard]] bool CheckDefaultCredentials(const std::string& ip);
    
    /// @brief Check UPnP
    [[nodiscard]] UPnPInfo CheckUPnP(const std::string& ip);
    
    /// @brief Check DNS hijacking
    [[nodiscard]] bool CheckDNSHijacking();
    
    /// @brief Get default gateway IP
    [[nodiscard]] std::string GetDefaultGateway() const;

    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /// @brief Get last assessment report
    [[nodiscard]] std::optional<RouterSecurityReport> GetLastReport() const;
    
    /// @brief Get assessment history
    [[nodiscard]] std::vector<RouterSecurityReport> GetAssessmentHistory(size_t maxEntries = 10) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAssessmentCallback(AssessmentCallback callback);
    void RegisterIssueCallback(IssueFoundCallback callback);
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] RouterStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    RouterSecurityChecker();
    ~RouterSecurityChecker();
    
    std::unique_ptr<RouterSecurityCheckerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetRouterVendorName(RouterVendor vendor) noexcept;
[[nodiscard]] std::string_view GetWirelessEncryptionName(WirelessEncryption enc) noexcept;
[[nodiscard]] std::string_view GetSecurityRiskLevelName(SecurityRiskLevel level) noexcept;
[[nodiscard]] std::string_view GetSecurityIssueTypeName(SecurityIssueType type) noexcept;
[[nodiscard]] RouterVendor DetectRouterVendor(const std::string& mac, const std::string& banner);
[[nodiscard]] SecurityRiskLevel GetEncryptionRiskLevel(WirelessEncryption enc) noexcept;

}  // namespace IoT
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ROUTER_AUDIT() \
    ::ShadowStrike::IoT::RouterSecurityChecker::Instance().AuditGateway()

#define SS_ROUTER_QUICK_CHECK() \
    ::ShadowStrike::IoT::RouterSecurityChecker::Instance().QuickSecurityCheck()