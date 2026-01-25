/**
 * ============================================================================
 * ShadowStrike NGAV - USB DEVICE MONITOR MODULE
 * ============================================================================
 *
 * @file USBDeviceMonitor.hpp
 * @brief Enterprise-grade USB device monitoring and control system for
 *        real-time tracking of device connections and enforcing security policies.
 *
 * Provides comprehensive USB device lifecycle management including connection
 * events, policy enforcement, automatic scanning, and device control.
 *
 * MONITORING CAPABILITIES:
 * ========================
 *
 * 1. DEVICE LIFECYCLE
 *    - Connection detection
 *    - Disconnection tracking
 *    - Mount/unmount events
 *    - Driver installation
 *    - Device enumeration
 *
 * 2. DEVICE INFORMATION
 *    - VID/PID extraction
 *    - Serial number
 *    - Manufacturer/Product strings
 *    - Device class
 *    - Interface types
 *    - Capacity (storage devices)
 *
 * 3. POLICY ENFORCEMENT
 *    - Access control (Full/ReadOnly/Block)
 *    - Device whitelisting
 *    - Device blacklisting
 *    - Auto-scan on mount
 *    - Autorun blocking
 *
 * 4. SECURITY FEATURES
 *    - BadUSB detection integration
 *    - Malware scanning trigger
 *    - Emergency device blocking
 *    - Safe ejection
 *    - Forensic logging
 *
 * 5. ENTERPRISE FEATURES
 *    - Centralized management
 *    - Event callbacks
 *    - Audit trail
 *    - SIEM integration
 *    - Device inventory
 *
 * INTEGRATION:
 * ============
 * - DeviceControlManager for policy
 * - BadUSBDetector for HID analysis
 * - USBScanner for malware detection
 * - Whitelist for trusted devices
 * - ThreatIntel for known bad devices
 *
 * @note Requires Windows device notification registration.
 * @note Uses WMI and SetupAPI for device enumeration.
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
#include <deque>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <condition_variable>
#include <filesystem>

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
#include "../Utils/ProcessUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::USB {
    class USBDeviceMonitorImpl;
}

namespace ShadowStrike {
namespace USB {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace USBMonitorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum device history entries
    inline constexpr size_t MAX_DEVICE_HISTORY = 10000;
    
    /// @brief Maximum connected devices to track
    inline constexpr size_t MAX_CONNECTED_DEVICES = 256;
    
    /// @brief Mount wait timeout (seconds)
    inline constexpr uint32_t MOUNT_WAIT_TIMEOUT_SEC = 30;
    
    /// @brief Device refresh interval (ms)
    inline constexpr uint32_t DEVICE_REFRESH_INTERVAL_MS = 1000;
    
    /// @brief Known attack hardware VIDs
    namespace VendorIds {
        inline constexpr uint16_t HAK5 = 0x203A;
        inline constexpr uint16_t DIGISPARK = 0x16D0;
        inline constexpr uint16_t TEENSY = 0x16C0;
        inline constexpr uint16_t ARDUINO = 0x2341;
    }

}  // namespace USBMonitorConstants

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
 * @brief Device event type
 */
enum class DeviceEventType : uint8_t {
    Connected           = 0,
    Disconnected        = 1,
    Mounted             = 2,
    Unmounted           = 3,
    AccessDeniedPolicy  = 4,
    AccessDeniedMalware = 5,
    ScanStarted         = 6,
    ScanCompleted       = 7,
    MalwareDetected     = 8,
    Ejected             = 9,
    DriverInstalling    = 10,
    DriverInstalled     = 11,
    DriverFailed        = 12,
    ReadOnlyEnforced    = 13
};

/**
 * @brief Device type
 */
enum class DeviceType : uint8_t {
    Unknown             = 0,
    MassStorage         = 1,
    HIDKeyboard         = 2,
    HIDMouse            = 3,
    HIDOther            = 4,
    NetworkAdapter      = 5,
    AudioDevice         = 6,
    VideoDevice         = 7,
    Printer             = 8,
    ImagingDevice       = 9,
    SmartCard           = 10,
    Hub                 = 11,
    Composite           = 12,
    WirelessController  = 13,
    VendorSpecific      = 14
};

/**
 * @brief Access level
 */
enum class AccessLevel : uint8_t {
    FullAccess      = 0,
    ReadOnly        = 1,
    Blocked         = 2,
    QuarantineOnly  = 3,
    AuditOnly       = 4
};

/**
 * @brief Device status
 */
enum class DeviceStatus : uint8_t {
    Unknown         = 0,
    Connected       = 1,
    Mounting        = 2,
    Mounted         = 3,
    Scanning        = 4,
    Ready           = 5,
    Blocked         = 6,
    Ejecting        = 7,
    Disconnected    = 8
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
 * @brief USB device information
 */
struct USBDeviceInfo {
    /// @brief Device instance ID (unique identifier)
    std::string deviceId;
    
    /// @brief Vendor ID (hex string)
    std::string vendorId;
    
    /// @brief Product ID (hex string)
    std::string productId;
    
    /// @brief Vendor ID (numeric)
    uint16_t vid = 0;
    
    /// @brief Product ID (numeric)
    uint16_t pid = 0;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief Friendly name
    std::string friendlyName;
    
    /// @brief Manufacturer string
    std::string manufacturer;
    
    /// @brief Product string
    std::string product;
    
    /// @brief Drive letter (storage devices)
    std::string driveLetter;
    
    /// @brief Volume label
    std::string volumeLabel;
    
    /// @brief File system type
    std::string fileSystem;
    
    /// @brief Device type
    DeviceType type = DeviceType::Unknown;
    
    /// @brief Device class code
    uint8_t classCode = 0;
    
    /// @brief Device subclass code
    uint8_t subclassCode = 0;
    
    /// @brief Interface count
    uint8_t interfaceCount = 0;
    
    /// @brief Total capacity (bytes, storage devices)
    uint64_t capacityBytes = 0;
    
    /// @brief Free space (bytes)
    uint64_t freeSpaceBytes = 0;
    
    /// @brief Is bootable
    bool isBootable = false;
    
    /// @brief Has autorun.inf
    bool hasAutorun = false;
    
    /// @brief Is removable
    bool isRemovable = true;
    
    /// @brief Current status
    DeviceStatus status = DeviceStatus::Unknown;
    
    /// @brief Current access level
    AccessLevel accessLevel = AccessLevel::Blocked;
    
    /// @brief Connection time
    SystemTimePoint connectionTime;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Is blacklisted
    bool isBlacklisted = false;
    
    /// @brief Is known bad device (BadUSB)
    bool isKnownBadDevice = false;
    
    /// @brief Last scan time
    std::optional<SystemTimePoint> lastScanTime;
    
    /// @brief Last scan result
    bool lastScanClean = true;
    
    /// @brief Threats found in last scan
    uint32_t threatsFound = 0;
    
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] std::string GetVIDPIDString() const;
};

/**
 * @brief USB event
 */
struct USBEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Event type
    DeviceEventType type = DeviceEventType::Connected;
    
    /// @brief Device info
    USBDeviceInfo device;
    
    /// @brief Access level granted
    AccessLevel accessGranted = AccessLevel::Blocked;
    
    /// @brief Policy rule applied
    std::string policyRuleApplied;
    
    /// @brief Event timestamp
    SystemTimePoint timestamp;
    
    /// @brief User who triggered event
    std::string userName;
    
    /// @brief Additional details
    std::string details;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief USB policy configuration
 */
struct USBPolicyConfig {
    /// @brief Block unknown devices
    bool blockUnknownDevices = false;
    
    /// @brief Block mass storage devices
    bool blockMassStorage = false;
    
    /// @brief Block new keyboards (anti-BadUSB)
    bool blockNewKeyboards = true;
    
    /// @brief Force read-only on storage
    bool forceReadOnly = false;
    
    /// @brief Auto-scan on mount
    bool autoScanOnMount = true;
    
    /// @brief Block autorun
    bool blockAutorun = true;
    
    /// @brief Vaccinate drives
    bool vaccinateDrives = true;
    
    /// @brief Require approval for new devices
    bool requireApprovalForNew = false;
    
    /// @brief Block hubs
    bool blockHubs = false;
    
    /// @brief Block wireless adapters
    bool blockWirelessAdapters = false;
    
    /// @brief Whitelisted serial numbers
    std::vector<std::string> whitelistedSerials;
    
    /// @brief Whitelisted VID/PID pairs
    std::vector<std::pair<uint16_t, uint16_t>> whitelistedVidPid;
    
    /// @brief Blacklisted VID/PID pairs
    std::vector<std::pair<uint16_t, uint16_t>> blacklistedVidPid;
    
    /// @brief Notify user on events
    bool notifyUser = true;
    
    /// @brief Log events
    bool logEvents = true;
    
    /// @brief Safe eject timeout (seconds)
    uint32_t safeEjectTimeoutSec = 30;
    
    bool operator==(const USBPolicyConfig& other) const = default;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Device history entry
 */
struct DeviceHistoryEntry {
    /// @brief Device info
    USBDeviceInfo device;
    
    /// @brief First seen time
    SystemTimePoint firstSeen;
    
    /// @brief Last seen time
    SystemTimePoint lastSeen;
    
    /// @brief Connection count
    uint32_t connectionCount = 0;
    
    /// @brief Times blocked
    uint32_t timesBlocked = 0;
    
    /// @brief Times malware found
    uint32_t timesMalwareFound = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct USBMonitorStatistics {
    std::atomic<uint64_t> totalDevicesConnected{0};
    std::atomic<uint64_t> totalDevicesDisconnected{0};
    std::atomic<uint64_t> devicesBlocked{0};
    std::atomic<uint64_t> devicesAllowed{0};
    std::atomic<uint64_t> devicesReadOnly{0};
    std::atomic<uint64_t> scansTriggered{0};
    std::atomic<uint64_t> malwareDetected{0};
    std::atomic<uint64_t> autorunBlocked{0};
    std::atomic<uint64_t> badUSBDetected{0};
    std::atomic<uint64_t> safeEjects{0};
    std::atomic<uint64_t> emergencyBlocks{0};
    std::atomic<uint32_t> currentlyConnected{0};
    std::array<std::atomic<uint64_t>, 16> byDeviceType{};
    std::array<std::atomic<uint64_t>, 8> byEventType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct USBMonitorConfiguration {
    /// @brief Enable monitoring
    bool enabled = true;
    
    /// @brief Policy config
    USBPolicyConfig policy;
    
    /// @brief Device history size
    size_t deviceHistorySize = USBMonitorConstants::MAX_DEVICE_HISTORY;
    
    /// @brief Enable BadUSB detection
    bool enableBadUSBDetection = true;
    
    /// @brief Enable auto-scan
    bool enableAutoScan = true;
    
    /// @brief Enable device control
    bool enableDeviceControl = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DeviceEventCallback = std::function<void(const USBEvent&)>;
using DeviceConnectedCallback = std::function<void(const USBDeviceInfo&)>;
using DeviceDisconnectedCallback = std::function<void(const USBDeviceInfo&)>;
using PolicyDecisionCallback = std::function<void(const USBDeviceInfo&, AccessLevel)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// USB DEVICE MONITOR CLASS
// ============================================================================

/**
 * @class USBDeviceMonitor
 * @brief Enterprise USB device monitoring and control system
 */
class USBDeviceMonitor final {
public:
    [[nodiscard]] static USBDeviceMonitor& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    USBDeviceMonitor(const USBDeviceMonitor&) = delete;
    USBDeviceMonitor& operator=(const USBDeviceMonitor&) = delete;
    USBDeviceMonitor(USBDeviceMonitor&&) = delete;
    USBDeviceMonitor& operator=(USBDeviceMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const USBMonitorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const USBMonitorConfiguration& config);
    [[nodiscard]] USBMonitorConfiguration GetConfiguration() const;

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start monitoring
    [[nodiscard]] bool StartMonitoring();
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoring() const noexcept;
    
    /// @brief Refresh device list
    void RefreshDevices();

    // ========================================================================
    // DEVICE MANAGEMENT
    // ========================================================================
    
    /// @brief Get connected devices
    [[nodiscard]] std::vector<USBDeviceInfo> GetConnectedDevices() const;
    
    /// @brief Get device by ID
    [[nodiscard]] std::optional<USBDeviceInfo> GetDevice(const std::string& deviceId) const;
    
    /// @brief Get device by drive letter
    [[nodiscard]] std::optional<USBDeviceInfo> GetDeviceByDrive(const std::string& driveLetter) const;
    
    /// @brief Safe eject device
    [[nodiscard]] bool SafeEjectDevice(const std::string& driveLetter);
    
    /// @brief Safe eject device by ID
    [[nodiscard]] bool SafeEjectDeviceById(const std::string& deviceId);
    
    /// @brief Emergency block device
    void EmergencyBlockDevice(const std::string& deviceId);
    
    /// @brief Unblock device
    [[nodiscard]] bool UnblockDevice(const std::string& deviceId);

    // ========================================================================
    // POLICY
    // ========================================================================
    
    /// @brief Update policy
    void UpdatePolicy(const USBPolicyConfig& newPolicy);
    
    /// @brief Get current policy
    [[nodiscard]] USBPolicyConfig GetPolicy() const;
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const std::string& serialOrVidPid);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& serialOrVidPid);
    
    /// @brief Add to blacklist
    [[nodiscard]] bool AddToBlacklist(const std::string& serialOrVidPid);

    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /// @brief Get device history
    [[nodiscard]] std::vector<DeviceHistoryEntry> GetDeviceHistory() const;
    
    /// @brief Get event history
    [[nodiscard]] std::vector<USBEvent> GetEventHistory(
        size_t maxEvents = 1000,
        std::optional<SystemTimePoint> fromTime = std::nullopt) const;
    
    /// @brief Clear history
    void ClearHistory();
    
    /// @brief Export history to file
    [[nodiscard]] bool ExportHistory(const std::filesystem::path& path) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterEventCallback(DeviceEventCallback callback);
    void RegisterConnectedCallback(DeviceConnectedCallback callback);
    void RegisterDisconnectedCallback(DeviceDisconnectedCallback callback);
    void RegisterPolicyCallback(PolicyDecisionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] USBMonitorStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    USBDeviceMonitor();
    ~USBDeviceMonitor();
    
    std::unique_ptr<USBDeviceMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDeviceEventTypeName(DeviceEventType type) noexcept;
[[nodiscard]] std::string_view GetDeviceTypeName(DeviceType type) noexcept;
[[nodiscard]] std::string_view GetAccessLevelName(AccessLevel level) noexcept;
[[nodiscard]] std::string_view GetDeviceStatusName(DeviceStatus status) noexcept;
[[nodiscard]] DeviceType ClassifyDeviceType(uint8_t classCode, uint8_t subclassCode) noexcept;
[[nodiscard]] std::string FormatCapacity(uint64_t bytes);

}  // namespace USB
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_USB_MONITOR_START() \
    ::ShadowStrike::USB::USBDeviceMonitor::Instance().StartMonitoring()

#define SS_USB_MONITOR_STOP() \
    ::ShadowStrike::USB::USBDeviceMonitor::Instance().StopMonitoring()

#define SS_USB_EJECT(drive) \
    ::ShadowStrike::USB::USBDeviceMonitor::Instance().SafeEjectDevice(drive)