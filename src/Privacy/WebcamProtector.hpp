/**
 * ============================================================================
 * ShadowStrike NGAV - WEBCAM PROTECTOR MODULE
 * ============================================================================
 *
 * @file WebcamProtector.hpp
 * @brief Enterprise-grade webcam access control and privacy protection
 *        with hardware-level blocking and application whitelisting.
 *
 * Provides comprehensive webcam privacy protection including unauthorized
 * access detection, application whitelisting, and hardware-level control.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. ACCESS MONITORING
 *    - Real-time camera access detection
 *    - Process identification
 *    - User notification
 *    - Access logging/auditing
 *    - Timeline tracking
 *
 * 2. APPLICATION CONTROL
 *    - Whitelist management
 *    - Per-app permissions
 *    - Time-based access
 *    - User-based access
 *    - Signature verification
 *
 * 3. HARDWARE CONTROL
 *    - USB Video Class (UVC) control
 *    - Driver-level blocking
 *    - Hardware disable
 *    - Virtual camera detection
 *    - Device enumeration
 *
 * 4. PROTECTION MODES
 *    - Full block (all cameras)
 *    - Whitelist only
 *    - Prompt mode
 *    - Silent logging
 *    - Time-based schedules
 *
 * 5. SPYWARE DETECTION
 *    - RAT camera access
 *    - Hidden process detection
 *    - Suspicious timing patterns
 *    - Known spyware signatures
 *
 * DETECTION METHODS:
 * ==================
 * - Kernel callbacks (KsRegisterDeviceInterfaceChangeCallback)
 * - DirectShow filter monitoring
 * - Media Foundation hooks
 * - Device interface notifications
 * - Process handle monitoring
 *
 * @note Requires administrator privileges for hardware control.
 * @note Thread-safe singleton design.
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
#include "../Utils/SystemUtils.hpp"
#include "../Whitelist/WhiteListStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class WebcamProtectorImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace WebcamConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum devices to monitor
    inline constexpr size_t MAX_DEVICES = 32;
    
    /// @brief Maximum whitelist entries
    inline constexpr size_t MAX_WHITELIST = 256;
    
    /// @brief Access cooldown (prevent spam notifications)
    inline constexpr uint32_t ACCESS_COOLDOWN_MS = 1000;
    
    /// @brief UVC class GUID
    inline constexpr const char* UVC_CLASS_GUID = "{65E8773D-8F56-11D0-A3B9-00A0C9223196}";

    /// @brief Default trusted applications
    inline constexpr const char* DEFAULT_TRUSTED_APPS[] = {
        "Zoom.exe",
        "Teams.exe",
        "Skype.exe",
        "WebEx.exe",
        "Discord.exe",
        "Slack.exe",
        "obs64.exe",
        "obs32.exe"
    };

}  // namespace WebcamConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Protection mode
 */
enum class WebcamProtectionMode : uint8_t {
    Disabled        = 0,    ///< No protection
    Monitor         = 1,    ///< Log only
    Prompt          = 2,    ///< Ask user on access
    WhitelistOnly   = 3,    ///< Only whitelist apps
    BlockAll        = 4     ///< Block all access
};

/**
 * @brief Camera access decision
 */
enum class CameraAccessDecision : uint8_t {
    Allow           = 0,    ///< Allow access
    Block           = 1,    ///< Block access
    Prompt          = 2,    ///< Prompt user
    AllowOnce       = 3,    ///< Allow this time only
    AllowTimed      = 4     ///< Allow for limited time
};

/**
 * @brief Camera device type
 */
enum class CameraDeviceType : uint8_t {
    Unknown         = 0,
    IntegratedUSB   = 1,    ///< Built-in laptop camera
    ExternalUSB     = 2,    ///< External USB camera
    Virtual         = 3,    ///< Virtual camera (OBS, etc.)
    IP              = 4,    ///< IP/Network camera
    FireWire        = 5     ///< IEEE 1394
};

/**
 * @brief Access reason
 */
enum class AccessReason : uint8_t {
    Unknown         = 0,
    VideoCall       = 1,
    Streaming       = 2,
    Recording       = 3,
    PhotoCapture    = 4,
    SystemCheck     = 5,
    Malware         = 6,
    SuspiciousRAT   = 7
};

/**
 * @brief Risk level
 */
enum class CameraRiskLevel : uint8_t {
    Safe            = 0,
    Low             = 1,
    Medium          = 2,
    High            = 3,
    Critical        = 4
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Camera device info
 */
struct CameraDevice {
    /// @brief Device ID
    std::string deviceId;
    
    /// @brief Device path (symbolic link)
    std::string devicePath;
    
    /// @brief Friendly name
    std::string friendlyName;
    
    /// @brief Manufacturer
    std::string manufacturer;
    
    /// @brief Device type
    CameraDeviceType type = CameraDeviceType::Unknown;
    
    /// @brief Vendor ID
    uint16_t vendorId = 0;
    
    /// @brief Product ID
    uint16_t productId = 0;
    
    /// @brief Is currently active
    bool isActive = false;
    
    /// @brief Is hardware enabled
    bool isHardwareEnabled = true;
    
    /// @brief Is currently blocked
    bool isBlocked = false;
    
    /// @brief Is virtual camera
    bool isVirtual = false;
    
    /// @brief Last access time
    SystemTimePoint lastAccess;
    
    /// @brief Total access count
    uint64_t accessCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Camera access event
 */
struct CameraAccessEvent {
    /// @brief Event ID
    uint64_t eventId = 0;
    
    /// @brief Device being accessed
    std::string deviceId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Process name
    std::string processName;
    
    /// @brief Process path
    fs::path processPath;
    
    /// @brief Process signature status
    bool isSigned = false;
    
    /// @brief Process publisher
    std::string publisher;
    
    /// @brief User name
    std::string userName;
    
    /// @brief Access reason (detected)
    AccessReason reason = AccessReason::Unknown;
    
    /// @brief Risk level
    CameraRiskLevel riskLevel = CameraRiskLevel::Safe;
    
    /// @brief Decision made
    CameraAccessDecision decision = CameraAccessDecision::Allow;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Access duration (if ended)
    std::chrono::seconds duration{0};
    
    /// @brief Is access ongoing
    bool isOngoing = false;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Whitelist entry
 */
struct CameraWhitelistEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Process name or path pattern
    std::string processPattern;
    
    /// @brief Publisher name (optional)
    std::string publisher;
    
    /// @brief SHA256 hash (optional)
    std::string sha256Hash;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Require signature
    bool requireSigned = false;
    
    /// @brief Time restriction (start hour)
    std::optional<int> allowFromHour;
    
    /// @brief Time restriction (end hour)
    std::optional<int> allowToHour;
    
    /// @brief Days of week (bitmask, Sun=1)
    uint8_t allowedDays = 0x7F;  // All days
    
    /// @brief User restrictions
    std::vector<std::string> allowedUsers;
    
    /// @brief Added by
    std::string addedBy;
    
    /// @brief When added
    SystemTimePoint addedTime;
    
    /// @brief Notes
    std::string notes;
    
    [[nodiscard]] bool IsCurrentlyAllowed() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct WebcamStatistics {
    std::atomic<uint64_t> totalAccessAttempts{0};
    std::atomic<uint64_t> accessAllowed{0};
    std::atomic<uint64_t> accessBlocked{0};
    std::atomic<uint64_t> accessPrompted{0};
    std::atomic<uint64_t> suspiciousAccess{0};
    std::atomic<uint64_t> malwareBlocked{0};
    std::atomic<uint64_t> ratDetected{0};
    std::atomic<uint64_t> whitelistHits{0};
    std::atomic<uint64_t> devicesMonitored{0};
    std::atomic<uint64_t> virtualCameraBlocked{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct WebcamConfiguration {
    /// @brief Protection mode
    WebcamProtectionMode mode = WebcamProtectionMode::WhitelistOnly;
    
    /// @brief Show notification on access
    bool showNotification = true;
    
    /// @brief Notification duration (ms)
    uint32_t notificationDurationMs = 5000;
    
    /// @brief Play sound on access
    bool playSound = false;
    
    /// @brief Log all access
    bool logAllAccess = true;
    
    /// @brief Block unsigned processes
    bool blockUnsigned = false;
    
    /// @brief Block virtual cameras
    bool blockVirtualCameras = false;
    
    /// @brief Block on screensaver
    bool blockOnScreensaver = true;
    
    /// @brief Block on lock screen
    bool blockOnLockScreen = true;
    
    /// @brief Check ThreatIntel for process
    bool checkThreatIntel = true;
    
    /// @brief Auto-block known spyware
    bool autoBlockSpyware = true;
    
    /// @brief Maximum access duration (0 = unlimited)
    std::chrono::seconds maxAccessDuration{0};
    
    /// @brief Hardware control enabled
    bool hardwareControlEnabled = false;
    
    /// @brief Kernel-mode protection
    bool kernelModeEnabled = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AccessEventCallback = std::function<void(const CameraAccessEvent&)>;
using DeviceChangeCallback = std::function<void(const CameraDevice&, bool added)>;
using DecisionCallback = std::function<CameraAccessDecision(const CameraAccessEvent&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// WEBCAM PROTECTOR CLASS
// ============================================================================

/**
 * @class WebcamProtector
 * @brief Enterprise webcam privacy protection
 */
class WebcamProtector final {
public:
    [[nodiscard]] static WebcamProtector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    WebcamProtector(const WebcamProtector&) = delete;
    WebcamProtector& operator=(const WebcamProtector&) = delete;
    WebcamProtector(WebcamProtector&&) = delete;
    WebcamProtector& operator=(WebcamProtector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const WebcamConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const WebcamConfiguration& config);
    [[nodiscard]] WebcamConfiguration GetConfiguration() const;

    // ========================================================================
    // PROTECTION CONTROL
    // ========================================================================
    
    /// @brief Set protection mode
    void SetProtectionMode(WebcamProtectionMode mode);
    
    /// @brief Get protection mode
    [[nodiscard]] WebcamProtectionMode GetProtectionMode() const noexcept;
    
    /// @brief Set camera blocked state (hardware level)
    [[nodiscard]] bool SetCameraBlocked(bool blocked);
    
    /// @brief Is camera blocked
    [[nodiscard]] bool IsCameraBlocked() const noexcept;
    
    /// @brief Block specific device
    [[nodiscard]] bool BlockDevice(const std::string& deviceId);
    
    /// @brief Unblock specific device
    [[nodiscard]] bool UnblockDevice(const std::string& deviceId);

    // ========================================================================
    // DEVICE MANAGEMENT
    // ========================================================================
    
    /// @brief Get all camera devices
    [[nodiscard]] std::vector<CameraDevice> GetCameraDevices();
    
    /// @brief Get device by ID
    [[nodiscard]] std::optional<CameraDevice> GetDevice(const std::string& deviceId);
    
    /// @brief Refresh device list
    [[nodiscard]] bool RefreshDevices();
    
    /// @brief Is any camera currently active
    [[nodiscard]] bool IsAnyCameraActive() const noexcept;
    
    /// @brief Get active cameras
    [[nodiscard]] std::vector<CameraDevice> GetActiveCameras();

    // ========================================================================
    // ACCESS CONTROL
    // ========================================================================
    
    /// @brief Handle camera access attempt (kernel callback)
    [[nodiscard]] bool OnCameraAccessAttempt(uint32_t pid);
    
    /// @brief Evaluate access request
    [[nodiscard]] CameraAccessDecision EvaluateAccess(
        uint32_t processId,
        const std::string& deviceId = "");
    
    /// @brief Allow process temporarily
    [[nodiscard]] bool AllowProcessTemporarily(
        uint32_t processId,
        std::chrono::seconds duration);
    
    /// @brief Revoke temporary access
    void RevokeTemporaryAccess(uint32_t processId);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const CameraWhitelistEntry& entry);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& entryId);
    
    /// @brief Check if process is whitelisted
    [[nodiscard]] bool IsProcessWhitelisted(
        const std::string& processName,
        const fs::path& processPath = {});
    
    /// @brief Get whitelist
    [[nodiscard]] std::vector<CameraWhitelistEntry> GetWhitelist() const;
    
    /// @brief Import default trusted apps
    [[nodiscard]] bool ImportDefaultTrustedApps();

    // ========================================================================
    // MONITORING
    // ========================================================================
    
    /// @brief Start monitoring
    [[nodiscard]] bool StartMonitoring();
    
    /// @brief Stop monitoring
    void StopMonitoring();
    
    /// @brief Is monitoring active
    [[nodiscard]] bool IsMonitoringActive() const noexcept;

    // ========================================================================
    // EVENT HISTORY
    // ========================================================================
    
    /// @brief Get recent access events
    [[nodiscard]] std::vector<CameraAccessEvent> GetRecentEvents(
        size_t limit = 100,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Get events for process
    [[nodiscard]] std::vector<CameraAccessEvent> GetEventsForProcess(
        const std::string& processName);
    
    /// @brief Clear event history
    void ClearEventHistory();

    // ========================================================================
    // SPYWARE DETECTION
    // ========================================================================
    
    /// @brief Check if process is known spyware
    [[nodiscard]] bool IsKnownSpyware(uint32_t processId);
    
    /// @brief Analyze process for RAT behavior
    [[nodiscard]] CameraRiskLevel AnalyzeProcess(uint32_t processId);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAccessCallback(AccessEventCallback callback);
    void RegisterDeviceCallback(DeviceChangeCallback callback);
    void RegisterDecisionCallback(DecisionCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] WebcamStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    WebcamProtector();
    ~WebcamProtector();
    
    std::unique_ptr<WebcamProtectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetProtectionModeName(WebcamProtectionMode mode) noexcept;
[[nodiscard]] std::string_view GetDeviceTypeName(CameraDeviceType type) noexcept;
[[nodiscard]] std::string_view GetAccessReasonName(AccessReason reason) noexcept;
[[nodiscard]] std::string_view GetRiskLevelName(CameraRiskLevel level) noexcept;
[[nodiscard]] std::string_view GetDecisionName(CameraAccessDecision decision) noexcept;

/// @brief Enumerate camera devices using SetupAPI
[[nodiscard]] std::vector<CameraDevice> EnumerateCameraDevices();

/// @brief Get process using camera
[[nodiscard]] std::vector<uint32_t> GetProcessesUsingCamera(const std::string& deviceId);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_WEBCAM_BLOCK_ALL() \
    ::ShadowStrike::Privacy::WebcamProtector::Instance().SetCameraBlocked(true)

#define SS_WEBCAM_UNBLOCK() \
    ::ShadowStrike::Privacy::WebcamProtector::Instance().SetCameraBlocked(false)

#define SS_WEBCAM_IS_BLOCKED() \
    ::ShadowStrike::Privacy::WebcamProtector::Instance().IsCameraBlocked()

#define SS_WEBCAM_WHITELIST(entry) \
    ::ShadowStrike::Privacy::WebcamProtector::Instance().AddToWhitelist(entry)
