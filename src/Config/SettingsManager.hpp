/**
 * ============================================================================
 * ShadowStrike NGAV - SETTINGS MANAGER MODULE
 * ============================================================================
 *
 * @file SettingsManager.hpp
 * @brief Enterprise-grade user settings management with preferences, themes,
 *        localization, notification controls, and accessibility support.
 *
 * Manages user-configurable preferences that don't affect security posture,
 * including UI customization, language, notifications, and accessibility.
 *
 * SETTINGS MANAGEMENT CAPABILITIES:
 * ==================================
 *
 * 1. UI CUSTOMIZATION
 *    - Theme selection (Light/Dark/System)
 *    - Color schemes
 *    - Font settings
 *    - Layout preferences
 *    - Tray icon behavior
 *
 * 2. LOCALIZATION
 *    - Language selection
 *    - Regional formats
 *    - Date/time formats
 *    - Number formats
 *    - Custom translations
 *
 * 3. NOTIFICATIONS
 *    - Alert preferences
 *    - Sound settings
 *    - Do-not-disturb
 *    - Priority levels
 *    - Toast behavior
 *
 * 4. STARTUP & BEHAVIOR
 *    - Start with Windows
 *    - Minimize to tray
 *    - Auto-hide
 *    - Scan scheduling
 *    - Update preferences
 *
 * 5. ACCESSIBILITY
 *    - Screen reader support
 *    - High contrast
 *    - Keyboard navigation
 *    - Animation preferences
 *
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
#include "../Utils/FileUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Config {
    class SettingsManagerImpl;
}

namespace ShadowStrike {
namespace Config {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SettingsConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Settings file name
    inline constexpr const char* SETTINGS_FILE_NAME = "user_settings.json";
    
    /// @brief Maximum recent files
    inline constexpr size_t MAX_RECENT_FILES = 50;
    
    /// @brief Maximum custom shortcuts
    inline constexpr size_t MAX_CUSTOM_SHORTCUTS = 100;
    
    /// @brief Auto-save interval (seconds)
    inline constexpr uint32_t AUTO_SAVE_INTERVAL_SECONDS = 30;

}  // namespace SettingsConstants

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
 * @brief UI Theme
 */
enum class Theme : uint8_t {
    Light       = 0,
    Dark        = 1,
    System      = 2,    ///< Follow system setting
    HighContrast= 3,
    Custom      = 4
};

/**
 * @brief Accent color
 */
enum class AccentColor : uint8_t {
    Blue        = 0,
    Green       = 1,
    Red         = 2,
    Orange      = 3,
    Purple      = 4,
    Teal        = 5,
    Pink        = 6,
    Gray        = 7,
    System      = 8,    ///< Follow system accent
    Custom      = 9
};

/**
 * @brief Tray icon behavior
 */
enum class TrayIconBehavior : uint8_t {
    AlwaysShow      = 0,
    HideWhenClean   = 1,
    HideAlways      = 2,
    ShowOnActivity  = 3
};

/**
 * @brief Notification level
 */
enum class NotificationLevel : uint8_t {
    All         = 0,    ///< Show all notifications
    Important   = 1,    ///< Only important (threats, updates)
    Critical    = 2,    ///< Only critical (threats)
    None        = 3     ///< No notifications
};

/**
 * @brief Sound setting
 */
enum class SoundSetting : uint8_t {
    All         = 0,
    Important   = 1,
    None        = 2,
    Custom      = 3
};

/**
 * @brief Date format
 */
enum class DateFormat : uint8_t {
    System      = 0,
    YYYY_MM_DD  = 1,
    DD_MM_YYYY  = 2,
    MM_DD_YYYY  = 3,
    Relative    = 4     ///< "2 hours ago"
};

/**
 * @brief Time format
 */
enum class TimeFormat : uint8_t {
    System      = 0,
    Hour24      = 1,
    Hour12      = 2
};

/**
 * @brief Manager status
 */
enum class SettingsStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Saving          = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Theme settings
 */
struct ThemeSettings {
    /// @brief Theme type
    Theme theme = Theme::System;
    
    /// @brief Accent color
    AccentColor accent = AccentColor::Blue;
    
    /// @brief Custom accent color (RGB)
    uint32_t customAccentRgb = 0x0078D4;
    
    /// @brief Custom theme path
    std::string customThemePath;
    
    /// @brief Enable animations
    bool enableAnimations = true;
    
    /// @brief Enable transparency
    bool enableTransparency = true;
    
    /// @brief Font scale factor (0.8 - 1.5)
    float fontScale = 1.0f;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Localization settings
 */
struct LocalizationSettings {
    /// @brief Language code (e.g., "en-US")
    std::string languageCode = "en-US";
    
    /// @brief Date format
    DateFormat dateFormat = DateFormat::System;
    
    /// @brief Time format
    TimeFormat timeFormat = TimeFormat::System;
    
    /// @brief Number decimal separator
    char decimalSeparator = '.';
    
    /// @brief Number thousands separator
    char thousandsSeparator = ',';
    
    /// @brief Use 24-hour format for time
    bool use24HourFormat = false;
    
    /// @brief First day of week (0 = Sunday)
    uint8_t firstDayOfWeek = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Notification settings
 */
struct NotificationSettings {
    /// @brief Enable notifications
    bool enabled = true;
    
    /// @brief Notification level
    NotificationLevel level = NotificationLevel::All;
    
    /// @brief Sound setting
    SoundSetting sound = SoundSetting::Important;
    
    /// @brief Custom sound path
    std::string customSoundPath;
    
    /// @brief Show toast notifications
    bool showToast = true;
    
    /// @brief Toast display duration (seconds)
    uint32_t toastDurationSeconds = 5;
    
    /// @brief Enable do-not-disturb
    bool doNotDisturbEnabled = false;
    
    /// @brief Do-not-disturb start hour
    uint32_t dndStartHour = 22;
    
    /// @brief Do-not-disturb end hour
    uint32_t dndEndHour = 7;
    
    /// @brief Enable scheduled quiet hours
    bool scheduledQuietHours = false;
    
    /// @brief Show scan progress
    bool showScanProgress = true;
    
    /// @brief Show update notifications
    bool showUpdateNotifications = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Startup settings
 */
struct StartupSettings {
    /// @brief Start with Windows
    bool startWithWindows = true;
    
    /// @brief Start minimized
    bool startMinimized = false;
    
    /// @brief Minimize to tray
    bool minimizeToTray = true;
    
    /// @brief Close to tray (instead of exit)
    bool closeToTray = true;
    
    /// @brief Tray icon behavior
    TrayIconBehavior trayBehavior = TrayIconBehavior::AlwaysShow;
    
    /// @brief Show splash screen
    bool showSplashScreen = true;
    
    /// @brief Check for updates on startup
    bool checkUpdatesOnStartup = true;
    
    /// @brief Run quick scan on startup
    bool quickScanOnStartup = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Accessibility settings
 */
struct AccessibilitySettings {
    /// @brief Enable screen reader support
    bool screenReaderSupport = true;
    
    /// @brief High contrast mode
    bool highContrastMode = false;
    
    /// @brief Reduce motion
    bool reduceMotion = false;
    
    /// @brief Large text
    bool largeText = false;
    
    /// @brief Enable keyboard shortcuts
    bool keyboardShortcuts = true;
    
    /// @brief Focus indicators
    bool focusIndicators = true;
    
    /// @brief Tooltip delay (milliseconds)
    uint32_t tooltipDelayMs = 500;
    
    /// @brief Cursor blink rate (0 = no blink)
    uint32_t cursorBlinkRate = 530;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Window settings
 */
struct WindowSettings {
    /// @brief Remember window position
    bool rememberPosition = true;
    
    /// @brief Window X position
    int32_t windowX = 100;
    
    /// @brief Window Y position
    int32_t windowY = 100;
    
    /// @brief Window width
    uint32_t windowWidth = 1024;
    
    /// @brief Window height
    uint32_t windowHeight = 768;
    
    /// @brief Is maximized
    bool isMaximized = false;
    
    /// @brief Sidebar width
    uint32_t sidebarWidth = 200;
    
    /// @brief Details pane visible
    bool detailsPaneVisible = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan UI settings
 */
struct ScanUISettings {
    /// @brief Show file being scanned
    bool showCurrentFile = true;
    
    /// @brief Show scan statistics
    bool showStatistics = true;
    
    /// @brief Show estimated time remaining
    bool showTimeRemaining = true;
    
    /// @brief Auto-close results on clean scan
    bool autoCloseOnClean = false;
    
    /// @brief Auto-close delay (seconds)
    uint32_t autoCloseDelaySeconds = 5;
    
    /// @brief Default view mode (list/grid)
    std::string defaultViewMode = "list";
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Complete user settings
 */
struct UserSettings {
    /// @brief Theme settings
    ThemeSettings theme;
    
    /// @brief Localization settings
    LocalizationSettings localization;
    
    /// @brief Notification settings
    NotificationSettings notifications;
    
    /// @brief Startup settings
    StartupSettings startup;
    
    /// @brief Accessibility settings
    AccessibilitySettings accessibility;
    
    /// @brief Window settings
    WindowSettings window;
    
    /// @brief Scan UI settings
    ScanUISettings scanUI;
    
    /// @brief Custom keyboard shortcuts
    std::map<std::string, std::string> keyboardShortcuts;
    
    /// @brief Recent files/folders
    std::vector<std::wstring> recentItems;
    
    /// @brief Favorite locations
    std::vector<std::wstring> favoriteLocations;
    
    /// @brief Settings version
    uint32_t settingsVersion = 1;
    
    /// @brief Last modified
    SystemTimePoint lastModified;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Settings change event
 */
struct SettingsChangeEvent {
    /// @brief Category that changed
    std::string category;
    
    /// @brief Setting key
    std::string key;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SettingsStatistics {
    std::atomic<uint64_t> totalLoads{0};
    std::atomic<uint64_t> totalSaves{0};
    std::atomic<uint64_t> settingChanges{0};
    std::atomic<uint64_t> resets{0};
    std::atomic<uint64_t> imports{0};
    std::atomic<uint64_t> exports{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SettingsManagerConfiguration {
    /// @brief Settings file path
    fs::path settingsFilePath;
    
    /// @brief Enable auto-save
    bool enableAutoSave = true;
    
    /// @brief Auto-save interval (seconds)
    uint32_t autoSaveIntervalSeconds = SettingsConstants::AUTO_SAVE_INTERVAL_SECONDS;
    
    /// @brief Create backup before save
    bool createBackupOnSave = true;
    
    /// @brief Maximum backups to keep
    uint32_t maxBackups = 5;
    
    /// @brief Encrypt sensitive settings
    bool encryptSensitiveSettings = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using SettingsChangeCallback = std::function<void(const SettingsChangeEvent&)>;
using ThemeChangeCallback = std::function<void(Theme newTheme)>;
using LanguageChangeCallback = std::function<void(const std::string& newLanguage)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SETTINGS MANAGER CLASS
// ============================================================================

/**
 * @class SettingsManager
 * @brief Enterprise user settings management
 */
class SettingsManager final {
public:
    [[nodiscard]] static SettingsManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SettingsManager(const SettingsManager&) = delete;
    SettingsManager& operator=(const SettingsManager&) = delete;
    SettingsManager(SettingsManager&&) = delete;
    SettingsManager& operator=(SettingsManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SettingsManagerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SettingsStatus GetStatus() const noexcept;

    // ========================================================================
    // LOAD/SAVE
    // ========================================================================
    
    /// @brief Load settings from file
    [[nodiscard]] UserSettings Load();
    
    /// @brief Save settings to file
    [[nodiscard]] bool Save(const UserSettings& settings);
    
    /// @brief Save current settings
    [[nodiscard]] bool SaveCurrent();
    
    /// @brief Get current settings
    [[nodiscard]] UserSettings GetCurrentSettings() const;
    
    /// @brief Set current settings
    void SetCurrentSettings(const UserSettings& settings);

    // ========================================================================
    // THEME
    // ========================================================================
    
    /// @brief Get theme settings
    [[nodiscard]] ThemeSettings GetThemeSettings() const;
    
    /// @brief Set theme
    void SetTheme(Theme theme);
    
    /// @brief Set accent color
    void SetAccentColor(AccentColor accent);
    
    /// @brief Set custom accent color
    void SetCustomAccentColor(uint32_t rgb);
    
    /// @brief Get effective theme (resolves System to actual)
    [[nodiscard]] Theme GetEffectiveTheme() const;

    // ========================================================================
    // LOCALIZATION
    // ========================================================================
    
    /// @brief Get localization settings
    [[nodiscard]] LocalizationSettings GetLocalizationSettings() const;
    
    /// @brief Set language
    void SetLanguage(const std::string& languageCode);
    
    /// @brief Get available languages
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> GetAvailableLanguages() const;
    
    /// @brief Set date format
    void SetDateFormat(DateFormat format);
    
    /// @brief Set time format
    void SetTimeFormat(TimeFormat format);

    // ========================================================================
    // NOTIFICATIONS
    // ========================================================================
    
    /// @brief Get notification settings
    [[nodiscard]] NotificationSettings GetNotificationSettings() const;
    
    /// @brief Set notification settings
    void SetNotificationSettings(const NotificationSettings& settings);
    
    /// @brief Enable/disable notifications
    void SetNotificationsEnabled(bool enabled);
    
    /// @brief Set notification level
    void SetNotificationLevel(NotificationLevel level);
    
    /// @brief Enable do-not-disturb
    void SetDoNotDisturb(bool enabled);

    // ========================================================================
    // STARTUP
    // ========================================================================
    
    /// @brief Get startup settings
    [[nodiscard]] StartupSettings GetStartupSettings() const;
    
    /// @brief Set startup settings
    void SetStartupSettings(const StartupSettings& settings);
    
    /// @brief Set start with Windows
    [[nodiscard]] bool SetStartWithWindows(bool enabled);
    
    /// @brief Check if starts with Windows
    [[nodiscard]] bool GetStartWithWindows() const;

    // ========================================================================
    // ACCESSIBILITY
    // ========================================================================
    
    /// @brief Get accessibility settings
    [[nodiscard]] AccessibilitySettings GetAccessibilitySettings() const;
    
    /// @brief Set accessibility settings
    void SetAccessibilitySettings(const AccessibilitySettings& settings);
    
    /// @brief Enable high contrast
    void SetHighContrastMode(bool enabled);
    
    /// @brief Enable large text
    void SetLargeText(bool enabled);

    // ========================================================================
    // WINDOW
    // ========================================================================
    
    /// @brief Get window settings
    [[nodiscard]] WindowSettings GetWindowSettings() const;
    
    /// @brief Set window settings
    void SetWindowSettings(const WindowSettings& settings);
    
    /// @brief Save current window position
    void SaveWindowPosition(int32_t x, int32_t y, uint32_t width, uint32_t height, bool maximized);

    // ========================================================================
    // RECENT & FAVORITES
    // ========================================================================
    
    /// @brief Add recent item
    void AddRecentItem(const std::wstring& path);
    
    /// @brief Get recent items
    [[nodiscard]] std::vector<std::wstring> GetRecentItems() const;
    
    /// @brief Clear recent items
    void ClearRecentItems();
    
    /// @brief Add favorite location
    void AddFavoriteLocation(const std::wstring& path);
    
    /// @brief Remove favorite location
    void RemoveFavoriteLocation(const std::wstring& path);
    
    /// @brief Get favorite locations
    [[nodiscard]] std::vector<std::wstring> GetFavoriteLocations() const;

    // ========================================================================
    // KEYBOARD SHORTCUTS
    // ========================================================================
    
    /// @brief Set keyboard shortcut
    void SetKeyboardShortcut(const std::string& action, const std::string& shortcut);
    
    /// @brief Get keyboard shortcut
    [[nodiscard]] std::optional<std::string> GetKeyboardShortcut(const std::string& action) const;
    
    /// @brief Get all keyboard shortcuts
    [[nodiscard]] std::map<std::string, std::string> GetAllKeyboardShortcuts() const;
    
    /// @brief Reset keyboard shortcuts to default
    void ResetKeyboardShortcuts();

    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================
    
    /// @brief Export settings to file
    [[nodiscard]] bool ExportSettings(const fs::path& filePath) const;
    
    /// @brief Import settings from file
    [[nodiscard]] bool ImportSettings(const fs::path& filePath);
    
    /// @brief Reset to defaults
    void ResetToDefaults();
    
    /// @brief Get factory defaults
    [[nodiscard]] UserSettings GetFactoryDefaults() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    uint64_t RegisterChangeCallback(SettingsChangeCallback callback);
    uint64_t RegisterThemeChangeCallback(ThemeChangeCallback callback);
    uint64_t RegisterLanguageChangeCallback(LanguageChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SettingsStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SettingsManager();
    ~SettingsManager();
    
    std::unique_ptr<SettingsManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetThemeName(Theme theme) noexcept;
[[nodiscard]] std::string_view GetAccentColorName(AccentColor accent) noexcept;
[[nodiscard]] std::string_view GetTrayBehaviorName(TrayIconBehavior behavior) noexcept;
[[nodiscard]] std::string_view GetNotificationLevelName(NotificationLevel level) noexcept;
[[nodiscard]] std::string_view GetDateFormatName(DateFormat format) noexcept;
[[nodiscard]] std::string_view GetTimeFormatName(TimeFormat format) noexcept;

/// @brief Format date according to settings
[[nodiscard]] std::string FormatDate(const SystemTimePoint& time, DateFormat format);

/// @brief Format time according to settings
[[nodiscard]] std::string FormatTime(const SystemTimePoint& time, TimeFormat format);

/// @brief Get system theme
[[nodiscard]] Theme GetSystemTheme();

/// @brief Get system language code
[[nodiscard]] std::string GetSystemLanguage();

}  // namespace Config
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_GET_THEME() \
    ::ShadowStrike::Config::SettingsManager::Instance().GetEffectiveTheme()

#define SS_SET_THEME(theme) \
    ::ShadowStrike::Config::SettingsManager::Instance().SetTheme(theme)

#define SS_GET_LANGUAGE() \
    ::ShadowStrike::Config::SettingsManager::Instance().GetLocalizationSettings().languageCode
