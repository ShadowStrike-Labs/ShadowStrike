/**
 * ============================================================================
 * ShadowStrike NGAV - IOT DEVICE SCANNER MODULE
 * ============================================================================
 *
 * @file IoTDeviceScanner.hpp
 * @brief Enterprise-grade IoT device discovery and vulnerability assessment
 *        engine for identifying and securing smart devices on networks.
 *
 * Provides comprehensive IoT device scanning including network discovery,
 * device fingerprinting, vulnerability assessment, and botnet detection.
 *
 * SCANNING CAPABILITIES:
 * ======================
 *
 * 1. DEVICE DISCOVERY
 *    - ARP scanning
 *    - mDNS/Bonjour discovery
 *    - UPnP/SSDP discovery
 *    - DHCP lease analysis
 *    - Passive network monitoring
 *
 * 2. DEVICE FINGERPRINTING
 *    - MAC OUI vendor lookup
 *    - TCP/IP stack fingerprinting
 *    - Service banner grabbing
 *    - HTTP/HTTPS headers
 *    - SSDP/UPnP device descriptions
 *
 * 3. VULNERABILITY ASSESSMENT
 *    - Default credential detection
 *    - Open service enumeration
 *    - Known CVE matching
 *    - Firmware version analysis
 *    - Weak configuration detection
 *
 * 4. BOTNET DETECTION
 *    - Mirai signature detection
 *    - C2 traffic analysis
 *    - Anomalous port activity
 *    - DDoS participation
 *    - Scanning behavior detection
 *
 * 5. DEVICE CATEGORIES
 *    - IP cameras
 *    - Smart TVs
 *    - Voice assistants
 *    - Thermostats/HVAC
 *    - Smart lighting
 *    - Network printers
 *    - NAS devices
 *    - Gaming consoles
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for known bad IPs
 * - HashStore for firmware hashes
 * - PatternStore for device patterns
 * - NetworkUtils for scanning
 *
 * @note Requires raw socket access for some scans.
 * @note Active scanning may trigger network alerts.
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
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <variant>
#include <span>

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
#  include <WS2tcpip.h>
#  include <iphlpapi.h>
#else
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::IoT {
    class IoTDeviceScannerImpl;
}

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IoTConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default scan timeout (ms)
    inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 5000;
    
    /// @brief Port scan throttle (ms)
    inline constexpr uint32_t PORT_SCAN_THROTTLE_MS = 50;
    
    /// @brief Maximum devices to track
    inline constexpr size_t MAX_TRACKED_DEVICES = 1000;
    
    /// @brief Common IoT ports
    inline constexpr uint16_t PORT_TELNET = 23;
    inline constexpr uint16_t PORT_SSH = 22;
    inline constexpr uint16_t PORT_HTTP = 80;
    inline constexpr uint16_t PORT_HTTPS = 443;
    inline constexpr uint16_t PORT_RTSP = 554;
    inline constexpr uint16_t PORT_MQTT = 1883;
    inline constexpr uint16_t PORT_MQTTS = 8883;
    inline constexpr uint16_t PORT_UPNP = 1900;
    inline constexpr uint16_t PORT_MDNS = 5353;
    inline constexpr uint16_t PORT_COAP = 5683;
    inline constexpr uint16_t PORT_COAPS = 5684;
    
    /// @brief Common IoT port list
    inline constexpr uint16_t COMMON_IOT_PORTS[] = {
        22, 23, 80, 443, 554, 1883, 1900, 5353,
        5683, 7547, 8008, 8080, 8443, 8883, 9100
    };

}  // namespace IoTConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using IPAddress = std::variant<in_addr, in6_addr>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Device category
 */
enum class DeviceCategory : uint8_t {
    Unknown         = 0,
    Router          = 1,
    Gateway         = 2,
    AccessPoint     = 3,
    IPCamera        = 4,
    SmartTV         = 5,
    SmartSpeaker    = 6,
    VoiceAssistant  = 7,
    Thermostat      = 8,
    SmartLight      = 9,
    SmartPlug       = 10,
    SmartLock       = 11,
    DoorSensor      = 12,
    MotionSensor    = 13,
    Printer         = 14,
    NAS             = 15,
    MediaServer     = 16,
    GamingConsole   = 17,
    SetTopBox       = 18,
    SmartWatch      = 19,
    SmartAppliance  = 20,
    HVACController  = 21,
    SecuritySystem  = 22,
    BabyMonitor     = 23,
    MobileDevice    = 24,
    Computer        = 25,
    NetworkSwitch   = 26,
    IoTHub          = 27
};

/**
 * @brief Vulnerability severity
 */
enum class VulnerabilityLevel : uint8_t {
    None            = 0,
    Informational   = 1,
    Low             = 2,
    Medium          = 3,
    High            = 4,
    Critical        = 5
};

/**
 * @brief Risk factor
 */
enum class RiskFactor : uint32_t {
    None                    = 0,
    DefaultCredentials      = 1 << 0,
    WeakCredentials         = 1 << 1,
    OpenTelnet              = 1 << 2,
    OpenSSHWeakCrypto       = 1 << 3,
    OutdatedFirmware        = 1 << 4,
    KnownCVE                = 1 << 5,
    BotnetCommunication     = 1 << 6,
    UnencryptedStream       = 1 << 7,
    UPnPEnabled             = 1 << 8,
    WPSEnabled              = 1 << 9,
    DNSHijacking            = 1 << 10,
    UnauthorizedService     = 1 << 11,
    ScanningBehavior        = 1 << 12,
    AnomalousTraffic        = 1 << 13,
    DebugInterface          = 1 << 14,
    NoEncryption            = 1 << 15
};

/**
 * @brief Service protocol
 */
enum class ServiceProtocol : uint8_t {
    Unknown         = 0,
    TCP             = 1,
    UDP             = 2,
    Both            = 3
};

/**
 * @brief Discovery method
 */
enum class DiscoveryMethod : uint8_t {
    Unknown         = 0,
    ARPScan         = 1,
    PingSweep       = 2,
    PortScan        = 3,
    MDNSDiscovery   = 4,
    UPnPDiscovery   = 5,
    DHCPLease       = 6,
    PassiveSniff    = 7,
    ManualAdd       = 8
};

/**
 * @brief Scan status
 */
enum class ScanStatus : uint8_t {
    NotStarted      = 0,
    Initializing    = 1,
    Discovering     = 2,
    Scanning        = 3,
    Assessing       = 4,
    Completed       = 5,
    Cancelled       = 6,
    Error           = 7
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Monitoring      = 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Network interface info
 */
struct NetworkInterface {
    /// @brief Interface name
    std::string name;
    
    /// @brief Interface description
    std::string description;
    
    /// @brief IPv4 address
    std::string ipv4Address;
    
    /// @brief IPv6 address
    std::string ipv6Address;
    
    /// @brief Subnet mask
    std::string subnetMask;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief Gateway address
    std::string gatewayAddress;
    
    /// @brief Is wireless
    bool isWireless = false;
    
    /// @brief Is connected
    bool isConnected = false;
    
    /// @brief Interface index
    uint32_t interfaceIndex = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Service information
 */
struct ServiceInfo {
    /// @brief Port number
    uint16_t port = 0;
    
    /// @brief Protocol (TCP/UDP)
    ServiceProtocol protocol = ServiceProtocol::Unknown;
    
    /// @brief Service name
    std::string serviceName;
    
    /// @brief Product name
    std::string product;
    
    /// @brief Version
    std::string version;
    
    /// @brief Banner (raw)
    std::string banner;
    
    /// @brief Is port open
    bool isOpen = false;
    
    /// @brief Is secure (TLS/SSL)
    bool isSecure = false;
    
    /// @brief Requires authentication
    bool requiresAuth = false;
    
    /// @brief Risk factors
    RiskFactor risks = RiskFactor::None;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief CVE information
 */
struct CVEInfo {
    /// @brief CVE ID
    std::string cveId;
    
    /// @brief Description
    std::string description;
    
    /// @brief CVSS score
    float cvssScore = 0.0f;
    
    /// @brief Severity
    VulnerabilityLevel severity = VulnerabilityLevel::None;
    
    /// @brief Has exploit available
    bool hasExploit = false;
    
    /// @brief Affected product
    std::string affectedProduct;
    
    /// @brief Affected versions
    std::vector<std::string> affectedVersions;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief IoT device information
 */
struct IoTDeviceInfo {
    /// @brief Device ID (unique)
    std::string deviceId;
    
    /// @brief IPv4 address
    std::string ipAddress;
    
    /// @brief IPv6 address
    std::string ipv6Address;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief Hostname
    std::string hostName;
    
    /// @brief Device name (friendly)
    std::string deviceName;
    
    /// @brief Vendor (from OUI)
    std::string vendor;
    
    /// @brief Model
    std::string model;
    
    /// @brief Firmware version
    std::string firmwareVersion;
    
    /// @brief Device category
    DeviceCategory category = DeviceCategory::Unknown;
    
    /// @brief Open services
    std::vector<ServiceInfo> services;
    
    /// @brief Vulnerability level
    VulnerabilityLevel vulnerabilityLevel = VulnerabilityLevel::None;
    
    /// @brief Risk factors
    RiskFactor risks = RiskFactor::None;
    
    /// @brief Risk factor list
    std::vector<RiskFactor> riskFactors;
    
    /// @brief Detected CVEs
    std::vector<CVEInfo> cves;
    
    /// @brief Discovery method
    DiscoveryMethod discoveryMethod = DiscoveryMethod::Unknown;
    
    /// @brief Is online
    bool isOnline = false;
    
    /// @brief Is gateway
    bool isGateway = false;
    
    /// @brief Has default credentials
    bool hasDefaultCredentials = false;
    
    /// @brief Is potentially compromised
    bool isPotentiallyCompromised = false;
    
    /// @brief First seen
    SystemTimePoint firstSeen;
    
    /// @brief Last seen
    SystemTimePoint lastSeen;
    
    /// @brief Last scanned
    std::optional<SystemTimePoint> lastScanned;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] int GetOverallRiskScore() const;
};

/**
 * @brief Scan configuration
 */
struct IoTScanConfig {
    /// @brief Enable active scanning
    bool enableActiveScanning = true;
    
    /// @brief Enable passive monitoring
    bool enablePassiveMonitoring = true;
    
    /// @brief Check for default credentials
    bool checkDefaultCredentials = false;
    
    /// @brief Scan common ports only
    bool scanCommonPortsOnly = true;
    
    /// @brief Enable UPnP discovery
    bool enableUPnPDiscovery = true;
    
    /// @brief Enable mDNS discovery
    bool enableMDNSDiscovery = true;
    
    /// @brief Enable ARP scanning
    bool enableARPScanning = true;
    
    /// @brief Enable CVE checking
    bool enableCVEChecking = true;
    
    /// @brief Target subnets (empty = auto-detect)
    std::vector<std::string> targetSubnets;
    
    /// @brief Excluded IP addresses
    std::vector<std::string> excludedIPs;
    
    /// @brief Scan interval (seconds)
    uint32_t scanIntervalSeconds = 3600;
    
    /// @brief Scan timeout (ms)
    uint32_t scanTimeoutMs = IoTConstants::DEFAULT_SCAN_TIMEOUT_MS;
    
    /// @brief Low bandwidth mode
    bool lowBandwidthMode = false;
    
    /// @brief Max parallel scans
    uint32_t maxParallelScans = 10;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan progress
 */
struct IoTScanProgress {
    /// @brief Current status
    ScanStatus status = ScanStatus::NotStarted;
    
    /// @brief Progress percentage
    float progressPercent = 0.0f;
    
    /// @brief Devices found
    uint32_t devicesFound = 0;
    
    /// @brief Devices scanned
    uint32_t devicesScanned = 0;
    
    /// @brief Vulnerabilities found
    uint32_t vulnerabilitiesFound = 0;
    
    /// @brief Current device being scanned
    std::string currentDevice;
    
    /// @brief Estimated time remaining
    std::chrono::seconds estimatedTimeRemaining{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result summary
 */
struct IoTScanResultSummary {
    /// @brief Final status
    ScanStatus status = ScanStatus::NotStarted;
    
    /// @brief Subnet scanned
    std::string subnetScanned;
    
    /// @brief Total devices found
    uint32_t totalDevicesFound = 0;
    
    /// @brief Devices by category
    std::map<DeviceCategory, uint32_t> devicesByCategory;
    
    /// @brief Critical vulnerabilities
    uint32_t criticalVulnerabilities = 0;
    
    /// @brief High vulnerabilities
    uint32_t highVulnerabilities = 0;
    
    /// @brief Medium vulnerabilities
    uint32_t mediumVulnerabilities = 0;
    
    /// @brief Low vulnerabilities
    uint32_t lowVulnerabilities = 0;
    
    /// @brief Devices with default credentials
    uint32_t devicesWithDefaultCreds = 0;
    
    /// @brief Potentially compromised devices
    uint32_t potentiallyCompromised = 0;
    
    /// @brief Scan start time
    SystemTimePoint startTime;
    
    /// @brief Scan end time
    SystemTimePoint endTime;
    
    /// @brief Scan duration
    std::chrono::seconds duration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct IoTScanStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> totalDevicesDiscovered{0};
    std::atomic<uint64_t> totalVulnerabilitiesFound{0};
    std::atomic<uint64_t> defaultCredentialsFound{0};
    std::atomic<uint64_t> botnetIndicatorsDetected{0};
    std::atomic<uint64_t> cvesMatched{0};
    std::atomic<uint64_t> packetsAnalyzed{0};
    std::atomic<uint32_t> activeDevices{0};
    std::array<std::atomic<uint64_t>, 32> byCategory{};
    std::array<std::atomic<uint64_t>, 8> byVulnerabilityLevel{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Module configuration
 */
struct IoTScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Default scan config
    IoTScanConfig defaultScanConfig;
    
    /// @brief Auto-discovery on startup
    bool autoDiscoveryOnStartup = true;
    
    /// @brief Continuous monitoring
    bool continuousMonitoring = true;
    
    /// @brief Alert on new devices
    bool alertOnNewDevices = true;
    
    /// @brief Alert on vulnerabilities
    bool alertOnVulnerabilities = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DeviceFoundCallback = std::function<void(const IoTDeviceInfo&)>;
using VulnerabilityCallback = std::function<void(const IoTDeviceInfo&, RiskFactor)>;
using ScanProgressCallback = std::function<void(const IoTScanProgress&)>;
using ScanCompleteCallback = std::function<void(const IoTScanResultSummary&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// IOT DEVICE SCANNER CLASS
// ============================================================================

/**
 * @class IoTDeviceScanner
 * @brief Enterprise IoT device discovery and vulnerability assessment engine
 */
class IoTDeviceScanner final {
public:
    [[nodiscard]] static IoTDeviceScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    IoTDeviceScanner(const IoTDeviceScanner&) = delete;
    IoTDeviceScanner& operator=(const IoTDeviceScanner&) = delete;
    IoTDeviceScanner(IoTDeviceScanner&&) = delete;
    IoTDeviceScanner& operator=(IoTDeviceScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const IoTScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const IoTScannerConfiguration& config);
    [[nodiscard]] IoTScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Start network discovery
    [[nodiscard]] bool StartDiscovery(const IoTScanConfig& config = {});
    
    /// @brief Stop scan
    void StopScan();
    
    /// @brief Deep scan specific device
    [[nodiscard]] IoTDeviceInfo DeepScanDevice(const std::string& ipAddress);
    
    /// @brief Scan specific subnet
    [[nodiscard]] bool ScanSubnet(const std::string& cidrSubnet);
    
    /// @brief Get scan progress
    [[nodiscard]] IoTScanProgress GetProgress() const;

    // ========================================================================
    // NETWORK MAP
    // ========================================================================
    
    /// @brief Get all discovered devices
    [[nodiscard]] std::vector<IoTDeviceInfo> GetNetworkMap() const;
    
    /// @brief Get device by IP
    [[nodiscard]] std::optional<IoTDeviceInfo> GetDevice(const std::string& ipAddress) const;
    
    /// @brief Get device by MAC
    [[nodiscard]] std::optional<IoTDeviceInfo> GetDeviceByMAC(const std::string& macAddress) const;
    
    /// @brief Get devices by category
    [[nodiscard]] std::vector<IoTDeviceInfo> GetDevicesByCategory(DeviceCategory category) const;
    
    /// @brief Get vulnerable devices
    [[nodiscard]] std::vector<IoTDeviceInfo> GetVulnerableDevices(VulnerabilityLevel minLevel = VulnerabilityLevel::Medium) const;
    
    /// @brief Get network interfaces
    [[nodiscard]] std::vector<NetworkInterface> GetNetworkInterfaces() const;

    // ========================================================================
    // PASSIVE MONITORING
    // ========================================================================
    
    /// @brief Process ARP packet
    void ProcessARPPacket(std::span<const uint8_t> packet);
    
    /// @brief Process DNS packet
    void ProcessDNSPacket(std::span<const uint8_t> packet);
    
    /// @brief Start passive monitoring
    [[nodiscard]] bool StartPassiveMonitoring();
    
    /// @brief Stop passive monitoring
    void StopPassiveMonitoring();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterDeviceFoundCallback(DeviceFoundCallback callback);
    void RegisterVulnerabilityCallback(VulnerabilityCallback callback);
    void RegisterProgressCallback(ScanProgressCallback callback);
    void RegisterCompleteCallback(ScanCompleteCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] IoTScanStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    IoTDeviceScanner();
    ~IoTDeviceScanner();
    
    std::unique_ptr<IoTDeviceScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDeviceCategoryName(DeviceCategory cat) noexcept;
[[nodiscard]] std::string_view GetVulnerabilityLevelName(VulnerabilityLevel level) noexcept;
[[nodiscard]] std::string_view GetRiskFactorName(RiskFactor risk) noexcept;
[[nodiscard]] std::string_view GetServiceProtocolName(ServiceProtocol proto) noexcept;
[[nodiscard]] std::string_view GetDiscoveryMethodName(DiscoveryMethod method) noexcept;
[[nodiscard]] std::string LookupMACVendor(const std::string& mac);
[[nodiscard]] DeviceCategory ClassifyDeviceByVendor(const std::string& vendor);

}  // namespace IoT
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_IOT_SCAN_START() \
    ::ShadowStrike::IoT::IoTDeviceScanner::Instance().StartDiscovery()

#define SS_IOT_SCAN_DEVICE(ip) \
    ::ShadowStrike::IoT::IoTDeviceScanner::Instance().DeepScanDevice(ip)