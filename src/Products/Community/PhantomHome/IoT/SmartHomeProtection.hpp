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
 * ShadowStrike NGAV - SMART HOME PROTECTION MODULE
 * ============================================================================
 *
 * @file SmartHomeProtection.hpp
 * @brief Enterprise-grade smart home device protection engine for monitoring
 *        and securing IoT devices in home and SOHO environments.
 *
 * Provides comprehensive protection for smart home ecosystems including
 * traffic monitoring, anomaly detection, and unauthorized access prevention.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. DEVICE MONITORING
 *    - Real-time traffic analysis
 *    - Bandwidth monitoring
 *    - Connection tracking
 *    - Activity logging
 *    - State change detection
 *
 * 2. ANOMALY DETECTION
 *    - Unusual traffic volume
 *    - Unexpected connections
 *    - Off-hours activity
 *    - Protocol violations
 *    - Data exfiltration
 *
 * 3. PRIVACY PROTECTION
 *    - Unauthorized streaming detection
 *    - Audio/video access monitoring
 *    - Location data tracking
 *    - Personal data transmission
 *    - Third-party connections
 *
 * 4. PROTOCOL SUPPORT
 *    - Matter protocol
 *    - Zigbee (via hubs)
 *    - Z-Wave (via hubs)
 *    - WiFi devices
 *    - Bluetooth (via gateway)
 *    - Thread protocol
 *
 * 5. DEVICE CATEGORIES
 *    - Smart cameras
 *    - Smart doorbells
 *    - Smart locks
 *    - Thermostats
 *    - Smart speakers
 *    - Smart displays
 *    - Smart appliances
 *    - Baby monitors
 *
 * INTEGRATION:
 * ============
 * - IoTDeviceScanner for discovery
 * - ThreatIntel for known threats
 * - NetworkUtils for monitoring
 * - Whitelist for trusted behavior
 *
 * @note Requires network monitoring capability.
 * @note Works best with managed network switches.
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
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::IoT {
    class SmartHomeProtectionImpl;
    struct IoTDeviceInfo;
}

namespace ShadowStrike {
namespace IoT {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SmartHomeConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum monitored devices
    inline constexpr size_t MAX_MONITORED_DEVICES = 100;
    
    /// @brief Traffic baseline window (hours)
    inline constexpr uint32_t BASELINE_WINDOW_HOURS = 168;  // 1 week
    
    /// @brief Anomaly threshold multiplier
    inline constexpr float ANOMALY_THRESHOLD_MULTIPLIER = 3.0f;
    
    /// @brief Privacy-sensitive ports
    inline constexpr uint16_t PRIVACY_PORTS[] = {
        554,    // RTSP (cameras)
        1935,   // RTMP (streaming)
        8554,   // Alt RTSP
        8080,   // HTTP alt
        443,    // HTTPS
    };

}  // namespace SmartHomeConstants

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
 * @brief Smart device type
 */
enum class SmartDeviceType : uint8_t {
    Unknown             = 0,
    Camera              = 1,
    Doorbell            = 2,
    Lock                = 3,
    Thermostat          = 4,
    Speaker             = 5,
    Display             = 6,
    LightBulb           = 7,
    LightSwitch         = 8,
    Plug                = 9,
    Appliance           = 10,
    Sensor              = 11,
    MotionSensor        = 12,
    DoorSensor          = 13,
    BabyMonitor         = 14,
    SecurityPanel       = 15,
    Garage              = 16,
    Sprinkler           = 17,
    Hub                 = 18,
    TV                  = 19,
    StreamingDevice     = 20
};

/**
 * @brief Device event type
 */
enum class SmartDeviceEvent : uint8_t {
    Unknown             = 0,
    StreamStarted       = 1,
    StreamEnded         = 2,
    AudioActivated      = 3,
    AudioDeactivated    = 4,
    VideoActivated      = 5,
    VideoDeactivated    = 6,
    MotionDetected      = 7,
    DoorOpened          = 8,
    DoorClosed          = 9,
    LockEngaged         = 10,
    LockDisengaged      = 11,
    TempChanged         = 12,
    LightOn             = 13,
    LightOff            = 14,
    FirmwareUpdate      = 15,
    ConfigChange        = 16,
    UnusualTraffic      = 17,
    ExternalConnection  = 18,
    DataExfiltration    = 19,
    UnauthorizedAccess  = 20,
    DeviceOnline        = 21,
    DeviceOffline       = 22
};

/**
 * @brief Alert severity
 */
enum class AlertSeverity : uint8_t {
    Info                = 0,
    Low                 = 1,
    Medium              = 2,
    High                = 3,
    Critical            = 4
};

/**
 * @brief Privacy concern type
 */
enum class PrivacyConcern : uint32_t {
    None                    = 0,
    UnauthorizedVideo       = 1 << 0,
    UnauthorizedAudio       = 1 << 1,
    DataExfiltration        = 1 << 2,
    LocationTracking        = 1 << 3,
    ThirdPartySharing       = 1 << 4,
    CloudUpload             = 1 << 5,
    UnencryptedTransmission = 1 << 6,
    OffHoursActivity        = 1 << 7,
    UnknownDestination      = 1 << 8,
    HighBandwidthUsage      = 1 << 9
};

/**
 * @brief Protection mode
 */
enum class ProtectionMode : uint8_t {
    Monitor             = 0,    ///< Monitor and alert only
    Protect             = 1,    ///< Monitor + block suspicious
    Lockdown            = 2,    ///< Block all non-essential
    Away                = 3,    ///< Away mode (higher alerting)
    Home                = 4,    ///< Home mode (relaxed)
    Sleep               = 5     ///< Sleep mode (no alerts for normal)
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Monitoring      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Monitored device info
 */
struct MonitoredDeviceInfo {
    /// @brief Device ID
    std::string deviceId;
    
    /// @brief MAC address
    std::string macAddress;
    
    /// @brief IP address
    std::string ipAddress;
    
    /// @brief Device name
    std::string deviceName;
    
    /// @brief Device type
    SmartDeviceType type = SmartDeviceType::Unknown;
    
    /// @brief Manufacturer
    std::string manufacturer;
    
    /// @brief Model
    std::string model;
    
    /// @brief Is high priority (cameras, locks, etc.)
    bool isHighPriority = false;
    
    /// @brief Is privacy-sensitive
    bool isPrivacySensitive = false;
    
    /// @brief Current state
    std::string currentState;
    
    /// @brief Is online
    bool isOnline = false;
    
    /// @brief Is streaming
    bool isStreaming = false;
    
    /// @brief Audio active
    bool audioActive = false;
    
    /// @brief Video active
    bool videoActive = false;
    
    /// @brief Monitoring since
    SystemTimePoint monitoringSince;
    
    /// @brief Last activity
    SystemTimePoint lastActivity;
    
    /// @brief Average daily traffic (bytes)
    uint64_t avgDailyTraffic = 0;
    
    /// @brief Today's traffic (bytes)
    uint64_t todayTraffic = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Traffic statistics
 */
struct DeviceTrafficStats {
    /// @brief Total bytes sent
    uint64_t bytesSent = 0;
    
    /// @brief Total bytes received
    uint64_t bytesReceived = 0;
    
    /// @brief Total connections
    uint32_t totalConnections = 0;
    
    /// @brief External connections
    uint32_t externalConnections = 0;
    
    /// @brief Unique destinations
    uint32_t uniqueDestinations = 0;
    
    /// @brief Streaming sessions
    uint32_t streamingSessions = 0;
    
    /// @brief Period start
    SystemTimePoint periodStart;
    
    /// @brief Period end
    SystemTimePoint periodEnd;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Security alert
 */
struct SmartHomeAlert {
    /// @brief Alert ID
    uint64_t alertId = 0;
    
    /// @brief Device ID
    std::string deviceId;
    
    /// @brief Device name
    std::string deviceName;
    
    /// @brief Event type
    SmartDeviceEvent eventType = SmartDeviceEvent::Unknown;
    
    /// @brief Alert severity
    AlertSeverity severity = AlertSeverity::Info;
    
    /// @brief Privacy concerns
    PrivacyConcern privacyConcerns = PrivacyConcern::None;
    
    /// @brief Alert title
    std::string title;
    
    /// @brief Alert description
    std::string description;
    
    /// @brief Destination IP/domain (if applicable)
    std::string destination;
    
    /// @brief Traffic volume (if applicable)
    uint64_t trafficVolume = 0;
    
    /// @brief Is acknowledged
    bool acknowledged = false;
    
    /// @brief Alert time
    SystemTimePoint alertTime;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Connection info
 */
struct DeviceConnection {
    /// @brief Source device ID
    std::string sourceDeviceId;
    
    /// @brief Destination IP
    std::string destinationIP;
    
    /// @brief Destination hostname
    std::string destinationHostname;
    
    /// @brief Destination port
    uint16_t destinationPort = 0;
    
    /// @brief Protocol
    std::string protocol;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Is external (internet)
    bool isExternal = false;
    
    /// @brief Bytes transferred
    uint64_t bytesTransferred = 0;
    
    /// @brief Connection start
    SystemTimePoint startTime;
    
    /// @brief Is active
    bool isActive = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SmartHomeStatistics {
    std::atomic<uint64_t> totalEventsProcessed{0};
    std::atomic<uint64_t> alertsGenerated{0};
    std::atomic<uint64_t> privacyConcernsDetected{0};
    std::atomic<uint64_t> anomaliesDetected{0};
    std::atomic<uint64_t> streamingSessionsDetected{0};
    std::atomic<uint64_t> externalConnectionsBlocked{0};
    std::atomic<uint64_t> totalBytesMonitored{0};
    std::atomic<uint32_t> devicesMonitored{0};
    std::array<std::atomic<uint64_t>, 32> byEventType{};
    std::array<std::atomic<uint64_t>, 8> byDeviceType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SmartHomeConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    /// @brief Protection mode
    ProtectionMode mode = ProtectionMode::Protect;
    
    /// @brief Monitor all devices automatically
    bool autoMonitorNewDevices = true;
    
    /// @brief Alert on streaming
    bool alertOnStreaming = true;
    
    /// @brief Alert on external connections
    bool alertOnExternalConnections = true;
    
    /// @brief Alert on anomalies
    bool alertOnAnomalies = true;
    
    /// @brief Block suspicious connections
    bool blockSuspicious = false;
    
    /// @brief Privacy focus (higher sensitivity for cameras, etc.)
    bool privacyFocus = true;
    
    /// @brief Off-hours start (0-23)
    int offHoursStart = 23;
    
    /// @brief Off-hours end (0-23)
    int offHoursEnd = 6;
    
    /// @brief Anomaly threshold multiplier
    float anomalyThreshold = SmartHomeConstants::ANOMALY_THRESHOLD_MULTIPLIER;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AlertCallback = std::function<void(const SmartHomeAlert&)>;
using DeviceEventCallback = std::function<void(const std::string& deviceId, SmartDeviceEvent event)>;
using ConnectionCallback = std::function<void(const DeviceConnection&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SMART HOME PROTECTION CLASS
// ============================================================================

/**
 * @class SmartHomeProtection
 * @brief Enterprise smart home device protection engine
 */
class SmartHomeProtection final {
public:
    [[nodiscard]] static SmartHomeProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SmartHomeProtection(const SmartHomeProtection&) = delete;
    SmartHomeProtection& operator=(const SmartHomeProtection&) = delete;
    SmartHomeProtection(SmartHomeProtection&&) = delete;
    SmartHomeProtection& operator=(SmartHomeProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SmartHomeConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const SmartHomeConfiguration& config);
    [[nodiscard]] SmartHomeConfiguration GetConfiguration() const;

    // ========================================================================
    // PROTECTION
    // ========================================================================
    
    /// @brief Start protection
    [[nodiscard]] bool StartProtection();
    
    /// @brief Stop protection
    void StopProtection();
    
    /// @brief Is protection active
    [[nodiscard]] bool IsProtectionActive() const noexcept;
    
    /// @brief Set protection mode
    void SetProtectionMode(ProtectionMode mode);
    
    /// @brief Get protection mode
    [[nodiscard]] ProtectionMode GetProtectionMode() const noexcept;

    // ========================================================================
    // DEVICE MANAGEMENT
    // ========================================================================
    
    /// @brief Add device to monitoring
    [[nodiscard]] bool MonitorDevice(const std::string& macAddress);
    
    /// @brief Remove device from monitoring
    [[nodiscard]] bool UnmonitorDevice(const std::string& macAddress);
    
    /// @brief Get monitored devices
    [[nodiscard]] std::vector<MonitoredDeviceInfo> GetMonitoredDevices() const;
    
    /// @brief Get device info
    [[nodiscard]] std::optional<MonitoredDeviceInfo> GetDeviceInfo(const std::string& deviceId) const;
    
    /// @brief Set device priority
    [[nodiscard]] bool SetDevicePriority(const std::string& deviceId, bool highPriority);
    
    /// @brief Set device as privacy-sensitive
    [[nodiscard]] bool SetPrivacySensitive(const std::string& deviceId, bool sensitive);

    // ========================================================================
    // TRAFFIC ANALYSIS
    // ========================================================================
    
    /// @brief Get device traffic stats
    [[nodiscard]] DeviceTrafficStats GetDeviceTraffic(
        const std::string& deviceId,
        std::chrono::hours period = std::chrono::hours{24}) const;
    
    /// @brief Get active connections
    [[nodiscard]] std::vector<DeviceConnection> GetActiveConnections(
        const std::string& deviceId = "") const;
    
    /// @brief Process traffic packet
    void ProcessTrafficPacket(
        const std::string& sourceMac,
        const std::string& destIP,
        uint16_t destPort,
        size_t bytes);

    // ========================================================================
    // ALERTS
    // ========================================================================
    
    /// @brief Get alerts
    [[nodiscard]] std::vector<SmartHomeAlert> GetAlerts(
        size_t maxAlerts = 100,
        bool unacknowledgedOnly = false) const;
    
    /// @brief Acknowledge alert
    [[nodiscard]] bool AcknowledgeAlert(uint64_t alertId);
    
    /// @brief Clear alerts
    void ClearAlerts();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAlertCallback(AlertCallback callback);
    void RegisterDeviceEventCallback(DeviceEventCallback callback);
    void RegisterConnectionCallback(ConnectionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SmartHomeStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SmartHomeProtection();
    ~SmartHomeProtection();
    
    std::unique_ptr<SmartHomeProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSmartDeviceTypeName(SmartDeviceType type) noexcept;
[[nodiscard]] std::string_view GetSmartDeviceEventName(SmartDeviceEvent event) noexcept;
[[nodiscard]] std::string_view GetAlertSeverityName(AlertSeverity severity) noexcept;
[[nodiscard]] std::string_view GetPrivacyConcernName(PrivacyConcern concern) noexcept;
[[nodiscard]] std::string_view GetProtectionModeName(ProtectionMode mode) noexcept;
[[nodiscard]] bool IsPrivacySensitiveDevice(SmartDeviceType type) noexcept;

}  // namespace IoT
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SMARTHOME_START() \
    ::ShadowStrike::IoT::SmartHomeProtection::Instance().StartProtection()

#define SS_SMARTHOME_MONITOR(mac) \
    ::ShadowStrike::IoT::SmartHomeProtection::Instance().MonitorDevice(mac)