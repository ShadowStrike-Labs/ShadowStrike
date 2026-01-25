/**
 * ============================================================================
 * ShadowStrike NGAV - NOTIFICATION MANAGER MODULE
 * ============================================================================
 *
 * @file NotificationManager.hpp
 * @brief Enterprise-grade notification management with Windows toast support,
 *        custom popups, action buttons, and smart quiet mode.
 *
 * Provides comprehensive user notification capabilities including system tray,
 * toast notifications, custom dialogs, and intelligent scheduling.
 *
 * NOTIFICATION CAPABILITIES:
 * ==========================
 *
 * 1. NOTIFICATION TYPES
 *    - Windows Toast notifications
 *    - System tray balloon tips
 *    - Custom popup windows
 *    - Banner notifications
 *    - Silent notifications
 *    - Action center integration
 *
 * 2. INTERACTIVE FEATURES
 *    - Action buttons
 *    - Quick reply
 *    - Progress indicators
 *    - Expandable content
 *    - Images and icons
 *    - Custom sounds
 *
 * 3. SMART SCHEDULING
 *    - Quiet hours mode
 *    - Game mode detection
 *    - Meeting detection
 *    - Focus assist integration
 *    - Priority queue
 *    - Batching
 *
 * 4. NOTIFICATION MANAGEMENT
 *    - History tracking
 *    - Deduplication
 *    - Rate limiting
 *    - User preferences
 *    - Category filtering
 *
 * 5. LOCALIZATION
 *    - Multi-language support
 *    - Dynamic content
 *    - RTL support
 *
 * @note Uses Windows.UI.Notifications API.
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
#include <queue>
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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Communication {
    class NotificationManagerImpl;
}

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace NotificationConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default notification timeout (ms)
    inline constexpr uint32_t DEFAULT_TIMEOUT_MS = 5000;
    
    /// @brief Maximum notifications in queue
    inline constexpr size_t MAX_QUEUE_SIZE = 100;
    
    /// @brief Rate limit (notifications per minute)
    inline constexpr size_t RATE_LIMIT_PER_MINUTE = 30;
    
    /// @brief History retention (notifications)
    inline constexpr size_t MAX_HISTORY_SIZE = 1000;
    
    /// @brief App user model ID
    inline constexpr const wchar_t* APP_USER_MODEL_ID = L"ShadowStrike.NGAV.Client";

}  // namespace NotificationConstants

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
 * @brief Notification level
 */
enum class NotificationLevel : uint8_t {
    Info            = 0,    ///< Informational
    Success         = 1,    ///< Success/completed
    Warning         = 2,    ///< Warning
    Error           = 3,    ///< Error
    Critical        = 4     ///< Critical/urgent
};

/**
 * @brief Notification type
 */
enum class NotificationType : uint8_t {
    Toast           = 0,    ///< Windows toast
    Balloon         = 1,    ///< Tray balloon
    Popup           = 2,    ///< Custom popup
    Banner          = 3,    ///< Banner notification
    Silent          = 4     ///< No visual (history only)
};

/**
 * @brief Notification category
 */
enum class NotificationCategory : uint8_t {
    General         = 0,
    ThreatDetection = 1,
    ScanComplete    = 2,
    UpdateAvailable = 3,
    SystemHealth    = 4,
    PolicyAlert     = 5,
    QuarantineAction= 6,
    BackupComplete  = 7,
    LicenseExpiry   = 8,
    Custom          = 9
};

/**
 * @brief Button style
 */
enum class ButtonStyle : uint8_t {
    Default         = 0,
    Primary         = 1,
    Secondary       = 2,
    Danger          = 3,
    Success         = 4
};

/**
 * @brief Notification status
 */
enum class NotificationStatus : uint8_t {
    Pending         = 0,
    Shown           = 1,
    Clicked         = 2,
    Dismissed       = 3,
    Expired         = 4,
    Suppressed      = 5,
    Failed          = 6
};

/**
 * @brief Quiet mode state
 */
enum class QuietModeState : uint8_t {
    Off             = 0,    ///< Normal mode
    QuietHours      = 1,    ///< Scheduled quiet hours
    Gaming          = 2,    ///< Game mode detected
    Meeting         = 3,    ///< Meeting detected
    PriorityOnly    = 4,    ///< Priority only
    AlarmsOnly      = 5,    ///< Alarms only
    Manual          = 6     ///< Manually enabled
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Processing      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Notification action button
 */
struct NotificationButton {
    /// @brief Button ID
    std::string buttonId;
    
    /// @brief Button text
    std::wstring text;
    
    /// @brief Style
    ButtonStyle style = ButtonStyle::Default;
    
    /// @brief Action to perform
    std::string action;
    
    /// @brief Action arguments
    std::string arguments;
    
    /// @brief Is dismissal action
    bool isDismiss = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Notification content
 */
struct Notification {
    /// @brief Notification ID
    std::string notificationId;
    
    /// @brief Level/severity
    NotificationLevel level = NotificationLevel::Info;
    
    /// @brief Type
    NotificationType type = NotificationType::Toast;
    
    /// @brief Category
    NotificationCategory category = NotificationCategory::General;
    
    /// @brief Title
    std::wstring title;
    
    /// @brief Message body
    std::wstring message;
    
    /// @brief Attribution text
    std::wstring attribution;
    
    /// @brief Hero image path (optional)
    fs::path heroImagePath;
    
    /// @brief App logo path (optional)
    fs::path logoPath;
    
    /// @brief Inline image path (optional)
    fs::path inlineImagePath;
    
    /// @brief Sound to play
    std::wstring soundName;
    
    /// @brief Use custom sound file
    fs::path customSoundPath;
    
    /// @brief Action buttons
    std::vector<NotificationButton> buttons;
    
    /// @brief Timeout (ms, 0 = persistent)
    uint32_t timeoutMs = NotificationConstants::DEFAULT_TIMEOUT_MS;
    
    /// @brief Priority (higher = more important)
    int priority = 0;
    
    /// @brief Show even in quiet mode
    bool bypassQuietMode = false;
    
    /// @brief Tag (for replacement/updates)
    std::string tag;
    
    /// @brief Group
    std::string group;
    
    /// @brief Expiration time
    std::optional<SystemTimePoint> expirationTime;
    
    /// @brief Launch arguments (when clicked)
    std::string launchArguments;
    
    /// @brief Additional data
    std::map<std::string, std::string> data;
    
    /// @brief Status
    NotificationStatus status = NotificationStatus::Pending;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Shown time
    std::optional<SystemTimePoint> shownTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Threat alert notification
 */
struct ThreatNotification {
    /// @brief Threat name
    std::wstring threatName;
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief Threat type
    std::wstring threatType;
    
    /// @brief Severity
    std::wstring severity;
    
    /// @brief Action taken
    std::wstring actionTaken;
    
    /// @brief Show restore button
    bool showRestoreButton = false;
    
    /// @brief Show details button
    bool showDetailsButton = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief User preferences
 */
struct NotificationPreferences {
    /// @brief Enable notifications
    bool enabled = true;
    
    /// @brief Minimum level to show
    NotificationLevel minimumLevel = NotificationLevel::Info;
    
    /// @brief Categories to show (bitmask)
    uint32_t enabledCategories = 0xFFFFFFFF;  // All
    
    /// @brief Use sounds
    bool enableSounds = true;
    
    /// @brief Sound volume (0-100)
    int soundVolume = 100;
    
    /// @brief Show in action center
    bool showInActionCenter = true;
    
    /// @brief Group similar notifications
    bool groupSimilar = true;
    
    /// @brief Max notifications to show at once
    size_t maxConcurrent = 3;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Quiet hours schedule
 */
struct QuietHoursSchedule {
    /// @brief Is enabled
    bool enabled = false;
    
    /// @brief Start time (hour)
    int startHour = 22;
    
    /// @brief Start minute
    int startMinute = 0;
    
    /// @brief End time (hour)
    int endHour = 7;
    
    /// @brief End minute
    int endMinute = 0;
    
    /// @brief Days of week (bitmask, Sun = bit 0)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Allow critical
    bool allowCritical = true;
    
    [[nodiscard]] bool IsActive() const;
};

/**
 * @brief Statistics
 */
struct NotificationStatistics {
    std::atomic<uint64_t> totalShown{0};
    std::atomic<uint64_t> totalClicked{0};
    std::atomic<uint64_t> totalDismissed{0};
    std::atomic<uint64_t> totalExpired{0};
    std::atomic<uint64_t> totalSuppressed{0};
    std::atomic<uint64_t> totalFailed{0};
    std::atomic<uint64_t> totalButtonClicks{0};
    std::atomic<uint64_t> rateLimitHits{0};
    std::atomic<uint64_t> quietModeSuppressions{0};
    std::array<std::atomic<uint64_t>, 8> byLevel{};
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct NotificationConfiguration {
    /// @brief Enable notifications
    bool enabled = true;
    
    /// @brief User preferences
    NotificationPreferences preferences;
    
    /// @brief Quiet hours schedule
    QuietHoursSchedule quietHours;
    
    /// @brief Detect game mode
    bool detectGameMode = true;
    
    /// @brief Detect meetings
    bool detectMeetings = true;
    
    /// @brief Use Windows focus assist
    bool useFocusAssist = true;
    
    /// @brief Rate limit per minute
    size_t rateLimitPerMinute = NotificationConstants::RATE_LIMIT_PER_MINUTE;
    
    /// @brief Enable deduplication
    bool enableDeduplication = true;
    
    /// @brief Dedup window (seconds)
    uint32_t dedupWindowSeconds = 30;
    
    /// @brief Custom sounds folder
    fs::path customSoundsFolder;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using NotificationCallback = std::function<void(const Notification&)>;
using ActionCallback = std::function<void(const std::string& notificationId, const std::string& actionId)>;
using DismissCallback = std::function<void(const std::string& notificationId)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// NOTIFICATION MANAGER CLASS
// ============================================================================

/**
 * @class NotificationManager
 * @brief Enterprise notification management
 */
class NotificationManager final {
public:
    [[nodiscard]] static NotificationManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    NotificationManager(const NotificationManager&) = delete;
    NotificationManager& operator=(const NotificationManager&) = delete;
    NotificationManager(NotificationManager&&) = delete;
    NotificationManager& operator=(NotificationManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const NotificationConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const NotificationConfiguration& config);
    [[nodiscard]] NotificationConfiguration GetConfiguration() const;

    // ========================================================================
    // NOTIFICATION OPERATIONS
    // ========================================================================
    
    /// @brief Show notification
    void Show(
        const std::wstring& title,
        const std::wstring& message,
        NotificationLevel level = NotificationLevel::Info);
    
    /// @brief Show notification (full)
    [[nodiscard]] std::string Show(const Notification& notification);
    
    /// @brief Show threat alert
    void ShowThreatAlert(
        const std::wstring& threatName,
        const std::wstring& filePath);
    
    /// @brief Show threat alert (full)
    [[nodiscard]] std::string ShowThreatAlert(const ThreatNotification& threat);
    
    /// @brief Update existing notification
    [[nodiscard]] bool Update(const Notification& notification);
    
    /// @brief Remove notification
    [[nodiscard]] bool Remove(const std::string& notificationId);
    
    /// @brief Remove by tag
    [[nodiscard]] bool RemoveByTag(const std::string& tag);
    
    /// @brief Clear all notifications
    void ClearAll();

    // ========================================================================
    // QUIET MODE
    // ========================================================================
    
    /// @brief Enable quiet mode
    void EnableQuietMode(QuietModeState state = QuietModeState::Manual);
    
    /// @brief Disable quiet mode
    void DisableQuietMode();
    
    /// @brief Is quiet mode active
    [[nodiscard]] bool IsQuietModeActive() const noexcept;
    
    /// @brief Get quiet mode state
    [[nodiscard]] QuietModeState GetQuietModeState() const noexcept;
    
    /// @brief Set quiet hours schedule
    void SetQuietHoursSchedule(const QuietHoursSchedule& schedule);

    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /// @brief Get notification by ID
    [[nodiscard]] std::optional<Notification> GetNotification(
        const std::string& notificationId);
    
    /// @brief Get recent notifications
    [[nodiscard]] std::vector<Notification> GetRecentNotifications(
        size_t limit = 50);
    
    /// @brief Get notifications by category
    [[nodiscard]] std::vector<Notification> GetNotificationsByCategory(
        NotificationCategory category,
        size_t limit = 50);
    
    /// @brief Clear history
    void ClearHistory();

    // ========================================================================
    // PREFERENCES
    // ========================================================================
    
    /// @brief Set preferences
    void SetPreferences(const NotificationPreferences& prefs);
    
    /// @brief Get preferences
    [[nodiscard]] NotificationPreferences GetPreferences() const;
    
    /// @brief Is category enabled
    [[nodiscard]] bool IsCategoryEnabled(NotificationCategory category) const;
    
    /// @brief Enable/disable category
    void SetCategoryEnabled(NotificationCategory category, bool enabled);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterNotificationCallback(NotificationCallback callback);
    void RegisterActionCallback(ActionCallback callback);
    void RegisterDismissCallback(DismissCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] NotificationStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    NotificationManager();
    ~NotificationManager();
    
    std::unique_ptr<NotificationManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetNotificationLevelName(NotificationLevel level) noexcept;
[[nodiscard]] std::string_view GetNotificationTypeName(NotificationType type) noexcept;
[[nodiscard]] std::string_view GetNotificationCategoryName(NotificationCategory category) noexcept;
[[nodiscard]] std::string_view GetNotificationStatusName(NotificationStatus status) noexcept;
[[nodiscard]] std::string_view GetQuietModeStateName(QuietModeState state) noexcept;

/// @brief Get level icon
[[nodiscard]] std::wstring GetLevelIcon(NotificationLevel level);

/// @brief Is game mode active
[[nodiscard]] bool IsGameModeActive();

/// @brief Is in meeting
[[nodiscard]] bool IsInMeeting();

}  // namespace Communication
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_NOTIFY(title, message) \
    ::ShadowStrike::Communication::NotificationManager::Instance().Show(title, message)

#define SS_NOTIFY_INFO(title, message) \
    ::ShadowStrike::Communication::NotificationManager::Instance().Show( \
        title, message, ::ShadowStrike::Communication::NotificationLevel::Info)

#define SS_NOTIFY_WARNING(title, message) \
    ::ShadowStrike::Communication::NotificationManager::Instance().Show( \
        title, message, ::ShadowStrike::Communication::NotificationLevel::Warning)

#define SS_NOTIFY_CRITICAL(title, message) \
    ::ShadowStrike::Communication::NotificationManager::Instance().Show( \
        title, message, ::ShadowStrike::Communication::NotificationLevel::Critical)

#define SS_NOTIFY_THREAT(threat, path) \
    ::ShadowStrike::Communication::NotificationManager::Instance().ShowThreatAlert(threat, path)
