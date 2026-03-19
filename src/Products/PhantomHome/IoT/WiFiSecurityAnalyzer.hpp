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
 * ShadowStrike NGAV - WIFI SECURITY ANALYZER MODULE
 * ============================================================================
 *
 * @file WiFiSecurityAnalyzer.hpp
 * @brief Enterprise-grade WiFi network security analysis engine for detecting
 *        wireless threats, weak configurations, and attack vectors.
 *
 * Provides comprehensive WiFi security assessment including encryption analysis,
 * evil twin detection, rogue AP identification, and protocol vulnerabilities.
 *
 * ANALYSIS CAPABILITIES:
 * ======================
 *
 * 1. ENCRYPTION ANALYSIS
 *    - WEP weakness detection
 *    - WPA/WPA2 vulnerabilities
 *    - WPA3 support verification
 *    - PMF (Protected Management Frames)
 *    - Key rotation settings
 *
 * 2. ATTACK DETECTION
 *    - Evil Twin detection
 *    - SSID spoofing
 *    - Deauthentication attacks
 *    - KRACK vulnerability
 *    - Dragonblood vulnerabilities
 *    - Karma attacks
 *    - PMKID attacks
 *
 * 3. ROGUE AP DETECTION
 *    - Unauthorized access points
 *    - BSSID anomalies
 *    - Signal strength analysis
 *    - Location inconsistencies
 *    - MAC spoofing detection
 *
 * 4. NETWORK PROFILING
 *    - AP fingerprinting
 *    - Channel analysis
 *    - Signal mapping
 *    - Client tracking
 *    - Hidden SSID detection
 *
 * 5. VULNERABILITY ASSESSMENT
 *    - WPS vulnerabilities
 *    - Default passwords
 *    - Outdated firmware indicators
 *    - Known CVEs
 *    - Configuration weaknesses
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for known rogue APs
 * - PatternStore for detection patterns
 * - Whitelist for trusted networks
 * - NetworkUtils for scanning
 *
 * @note Requires WiFi adapter with monitor mode for advanced detection.
 * @note Some features require administrative privileges.
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
#  include <wlanapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::IoT {
    class WiFiSecurityAnalyzerImpl;
}

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace WiFiConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Scan timeout (ms)
    inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 10000;
    
    /// @brief Evil twin detection signal threshold (dBm)
    inline constexpr int EVIL_TWIN_SIGNAL_THRESHOLD = 10;
    
    /// @brief Minimum signal strength for detection (dBm)
    inline constexpr int MIN_SIGNAL_STRENGTH = -90;
    
    /// @brief Maximum networks to track
    inline constexpr size_t MAX_TRACKED_NETWORKS = 500;
    
    /// @brief BSSID history size
    inline constexpr size_t BSSID_HISTORY_SIZE = 100;
    
    /// @brief Channel frequency table (2.4GHz)
    inline constexpr struct { int channel; int frequency; } CHANNEL_2GHZ[] = {
        {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427},
        {5, 2432}, {6, 2437}, {7, 2442}, {8, 2447},
        {9, 2452}, {10, 2457}, {11, 2462}, {12, 2467},
        {13, 2472}, {14, 2484}
    };

}  // namespace WiFiConstants

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
 * @brief WiFi encryption type
 */
enum class EncryptionType : uint8_t {
    Unknown             = 0,
    Open                = 1,
    WEP                 = 2,
    WPA_Personal        = 3,
    WPA_Enterprise      = 4,
    WPA2_Personal       = 5,
    WPA2_Enterprise     = 6,
    WPA3_Personal       = 7,
    WPA3_Enterprise     = 8,
    WPA3_SAE            = 9,
    WPA2_WPA3_Mixed     = 10,
    OWE                 = 11    // Opportunistic Wireless Encryption
};

/**
 * @brief Authentication type
 */
enum class AuthenticationType : uint8_t {
    Unknown             = 0,
    Open                = 1,
    SharedKey           = 2,
    WPA_PSK             = 3,
    WPA_EAP             = 4,
    WPA2_PSK            = 5,
    WPA2_EAP            = 6,
    WPA3_SAE            = 7,
    WPA3_EAP_192        = 8,
    OWE                 = 9
};

/**
 * @brief WiFi band
 */
enum class WiFiBand : uint8_t {
    Unknown             = 0,
    Band2_4GHz          = 1,
    Band5GHz            = 2,
    Band6GHz            = 3
};

/**
 * @brief Network threat type
 */
enum class WiFiThreatType : uint32_t {
    None                    = 0,
    EvilTwin                = 1 << 0,
    SSIDSpoofing            = 1 << 1,
    RogueAP                 = 1 << 2,
    DeauthAttack            = 1 << 3,
    WeakEncryption          = 1 << 4,
    OpenNetwork             = 1 << 5,
    WPSEnabled              = 1 << 6,
    KRACKVulnerable         = 1 << 7,
    DragonbloodVulnerable   = 1 << 8,
    PMKIDExposed            = 1 << 9,
    KarmaAttack             = 1 << 10,
    HiddenNetwork           = 1 << 11,
    SignalAnomaly           = 1 << 12,
    MACSpoof                = 1 << 13,
    UnknownAP               = 1 << 14,
    ChannelInterference     = 1 << 15
};

/**
 * @brief Security level
 */
enum class SecurityLevel : uint8_t {
    Critical            = 0,    ///< Severe vulnerability
    Weak                = 1,    ///< Significant weakness
    Moderate            = 2,    ///< Minor issues
    Good                = 3,    ///< Reasonably secure
    Excellent           = 4     ///< Best practices
};

/**
 * @brief Network status
 */
enum class NetworkStatus : uint8_t {
    Unknown             = 0,
    Available           = 1,
    Connected           = 2,
    Connecting          = 3,
    Disconnected        = 4,
    Blocked             = 5
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
 * @brief WiFi network information
 */
struct WiFiNetworkInfo {
    /// @brief SSID
    std::string ssid;
    
    /// @brief BSSID (MAC address)
    std::string bssid;
    
    /// @brief Encryption type
    EncryptionType encryption = EncryptionType::Unknown;
    
    /// @brief Authentication type
    AuthenticationType authentication = AuthenticationType::Unknown;
    
    /// @brief WiFi band
    WiFiBand band = WiFiBand::Unknown;
    
    /// @brief Channel
    int channel = 0;
    
    /// @brief Center frequency (MHz)
    int frequency = 0;
    
    /// @brief Signal strength (dBm)
    int signalStrength = -100;
    
    /// @brief Signal quality (0-100)
    int signalQuality = 0;
    
    /// @brief Is hidden SSID
    bool isHidden = false;
    
    /// @brief WPS enabled
    bool wpsEnabled = false;
    
    /// @brief PMF (Protected Management Frames)
    bool pmfEnabled = false;
    
    /// @brief Is connected
    bool isConnected = false;
    
    /// @brief Is known network
    bool isKnown = false;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Security level
    SecurityLevel securityLevel = SecurityLevel::Moderate;
    
    /// @brief Detected threats
    WiFiThreatType threats = WiFiThreatType::None;
    
    /// @brief Vendor (from OUI)
    std::string vendor;
    
    /// @brief Network speed (Mbps)
    int networkSpeed = 0;
    
    /// @brief First seen
    SystemTimePoint firstSeen;
    
    /// @brief Last seen
    SystemTimePoint lastSeen;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] int GetOverallScore() const;
};

/**
 * @brief Current connection info
 */
struct WiFiConnectionInfo {
    /// @brief Is connected
    bool isConnected = false;
    
    /// @brief Network info
    WiFiNetworkInfo network;
    
    /// @brief Interface name
    std::string interfaceName;
    
    /// @brief Interface GUID
    std::string interfaceGuid;
    
    /// @brief Local IP address
    std::string localIP;
    
    /// @brief Gateway IP
    std::string gatewayIP;
    
    /// @brief DNS servers
    std::vector<std::string> dnsServers;
    
    /// @brief Connection duration
    std::chrono::seconds connectionDuration{0};
    
    /// @brief Bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Link speed (Mbps)
    int linkSpeed = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Evil Twin detection result
 */
struct EvilTwinDetectionResult {
    /// @brief Is potential evil twin detected
    bool detected = false;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief Original network
    WiFiNetworkInfo originalNetwork;
    
    /// @brief Suspected evil twin
    WiFiNetworkInfo suspectedTwin;
    
    /// @brief Detection reason
    std::string detectionReason;
    
    /// @brief Signal strength difference
    int signalDifference = 0;
    
    /// @brief BSSID similarity
    float bssidSimilarity = 0.0f;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Security threat info
 */
struct WiFiSecurityThreat {
    /// @brief Threat type
    WiFiThreatType type = WiFiThreatType::None;
    
    /// @brief Severity level
    SecurityLevel severity = SecurityLevel::Moderate;
    
    /// @brief Affected network
    std::string affectedSSID;
    
    /// @brief Affected BSSID
    std::string affectedBSSID;
    
    /// @brief Threat description
    std::string description;
    
    /// @brief Recommended action
    std::string recommendation;
    
    /// @brief CVE ID (if applicable)
    std::string cveId;
    
    /// @brief Detection time
    SystemTimePoint detectionTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief BSSID history entry
 */
struct BSSIDHistoryEntry {
    /// @brief BSSID
    std::string bssid;
    
    /// @brief Signal strength (dBm)
    int signalStrength = -100;
    
    /// @brief Channel
    int channel = 0;
    
    /// @brief Observation time
    SystemTimePoint observationTime;
    
    /// @brief Location hint (if available)
    std::string locationHint;
};

/**
 * @brief Statistics
 */
struct WiFiStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> networksDiscovered{0};
    std::atomic<uint64_t> threatsDetected{0};
    std::atomic<uint64_t> evilTwinsDetected{0};
    std::atomic<uint64_t> rogueAPsDetected{0};
    std::atomic<uint64_t> weakNetworksFound{0};
    std::atomic<uint64_t> deauthAttacksDetected{0};
    std::atomic<uint32_t> currentNetworksTracked{0};
    std::array<std::atomic<uint64_t>, 16> byThreatType{};
    std::array<std::atomic<uint64_t>, 8> bySecurityLevel{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct WiFiAnalyzerConfiguration {
    /// @brief Enable analyzer
    bool enabled = true;
    
    /// @brief Enable continuous monitoring
    bool continuousMonitoring = true;
    
    /// @brief Scan interval (seconds)
    uint32_t scanIntervalSeconds = 60;
    
    /// @brief Enable evil twin detection
    bool enableEvilTwinDetection = true;
    
    /// @brief Enable rogue AP detection
    bool enableRogueAPDetection = true;
    
    /// @brief Alert on weak encryption
    bool alertOnWeakEncryption = true;
    
    /// @brief Alert on open networks
    bool alertOnOpenNetworks = true;
    
    /// @brief Block known threats
    bool blockKnownThreats = false;
    
    /// @brief Track BSSID history
    bool trackBSSIDHistory = true;
    
    /// @brief Evil twin signal threshold (dBm)
    int evilTwinSignalThreshold = WiFiConstants::EVIL_TWIN_SIGNAL_THRESHOLD;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using NetworkFoundCallback = std::function<void(const WiFiNetworkInfo&)>;
using ThreatDetectedCallback = std::function<void(const WiFiSecurityThreat&)>;
using EvilTwinCallback = std::function<void(const EvilTwinDetectionResult&)>;
using ConnectionChangeCallback = std::function<void(const WiFiConnectionInfo&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// WIFI SECURITY ANALYZER CLASS
// ============================================================================

/**
 * @class WiFiSecurityAnalyzer
 * @brief Enterprise WiFi security analysis engine
 */
class WiFiSecurityAnalyzer final {
public:
    [[nodiscard]] static WiFiSecurityAnalyzer& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    WiFiSecurityAnalyzer(const WiFiSecurityAnalyzer&) = delete;
    WiFiSecurityAnalyzer& operator=(const WiFiSecurityAnalyzer&) = delete;
    WiFiSecurityAnalyzer(WiFiSecurityAnalyzer&&) = delete;
    WiFiSecurityAnalyzer& operator=(WiFiSecurityAnalyzer&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const WiFiAnalyzerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const WiFiAnalyzerConfiguration& config);
    [[nodiscard]] WiFiAnalyzerConfiguration GetConfiguration() const;

    // ========================================================================
    // CONNECTION INFO
    // ========================================================================
    
    /// @brief Get current connection info
    [[nodiscard]] WiFiConnectionInfo GetCurrentConnectionInfo();
    
    /// @brief Is connected to WiFi
    [[nodiscard]] bool IsConnected() const noexcept;
    
    /// @brief Get connected network info
    [[nodiscard]] std::optional<WiFiNetworkInfo> GetConnectedNetwork() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan nearby networks
    [[nodiscard]] std::vector<WiFiNetworkInfo> ScanNearbyNetworks();
    
    /// @brief Start continuous monitoring
    [[nodiscard]] bool StartMonitoring();
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // THREAT DETECTION
    // ========================================================================
    
    /// @brief Detect evil twin
    [[nodiscard]] EvilTwinDetectionResult DetectEvilTwin();
    
    /// @brief Check network security
    [[nodiscard]] std::vector<WiFiSecurityThreat> CheckNetworkSecurity(
        const WiFiNetworkInfo& network);
    
    /// @brief Get detected threats
    [[nodiscard]] std::vector<WiFiSecurityThreat> GetDetectedThreats() const;
    
    /// @brief Analyze current connection
    [[nodiscard]] std::vector<WiFiSecurityThreat> AnalyzeCurrentConnection();

    // ========================================================================
    // NETWORK MANAGEMENT
    // ========================================================================
    
    /// @brief Get all tracked networks
    [[nodiscard]] std::vector<WiFiNetworkInfo> GetTrackedNetworks() const;
    
    /// @brief Get network by SSID
    [[nodiscard]] std::optional<WiFiNetworkInfo> GetNetworkBySSID(
        const std::string& ssid) const;
    
    /// @brief Get network by BSSID
    [[nodiscard]] std::optional<WiFiNetworkInfo> GetNetworkByBSSID(
        const std::string& bssid) const;
    
    /// @brief Add network to whitelist
    [[nodiscard]] bool AddToWhitelist(const std::string& bssid);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& bssid);
    
    /// @brief Block network
    [[nodiscard]] bool BlockNetwork(const std::string& bssid);

    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /// @brief Get BSSID history for SSID
    [[nodiscard]] std::vector<BSSIDHistoryEntry> GetBSSIDHistory(
        const std::string& ssid) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterNetworkFoundCallback(NetworkFoundCallback callback);
    void RegisterThreatCallback(ThreatDetectedCallback callback);
    void RegisterEvilTwinCallback(EvilTwinCallback callback);
    void RegisterConnectionCallback(ConnectionChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] WiFiStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    WiFiSecurityAnalyzer();
    ~WiFiSecurityAnalyzer();
    
    std::unique_ptr<WiFiSecurityAnalyzerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetEncryptionTypeName(EncryptionType type) noexcept;
[[nodiscard]] std::string_view GetAuthenticationTypeName(AuthenticationType type) noexcept;
[[nodiscard]] std::string_view GetWiFiBandName(WiFiBand band) noexcept;
[[nodiscard]] std::string_view GetWiFiThreatTypeName(WiFiThreatType type) noexcept;
[[nodiscard]] std::string_view GetSecurityLevelName(SecurityLevel level) noexcept;
[[nodiscard]] SecurityLevel GetEncryptionSecurityLevel(EncryptionType type) noexcept;
[[nodiscard]] WiFiBand GetBandFromFrequency(int frequency) noexcept;
[[nodiscard]] int GetChannelFromFrequency(int frequency) noexcept;

}  // namespace IoT
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_WIFI_SCAN() \
    ::ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance().ScanNearbyNetworks()

#define SS_WIFI_DETECT_EVIL_TWIN() \
    ::ShadowStrike::IoT::WiFiSecurityAnalyzer::Instance().DetectEvilTwin()