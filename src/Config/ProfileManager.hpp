/**
 * ============================================================================
 * ShadowStrike NGAV - PROFILE MANAGER MODULE
 * ============================================================================
 *
 * @file ProfileManager.hpp
 * @brief Enterprise-grade system profile management with role-based configuration,
 *        automatic detection, adaptive switching, and resource optimization.
 *
 * Manages different operating profiles (Server, Workstation, Developer, etc.)
 * with automatic detection and adaptive configuration switching.
 *
 * PROFILE MANAGEMENT CAPABILITIES:
 * =================================
 *
 * 1. ROLE-BASED PROFILES
 *    - Server profile (high availability)
 *    - Workstation profile (balanced)
 *    - Developer profile (reduced scanning)
 *    - Locked-down profile (maximum security)
 *    - Gaming profile (performance focus)
 *    - Custom profiles
 *
 * 2. AUTO-DETECTION
 *    - Machine role detection
 *    - Workload analysis
 *    - Hardware capability assessment
 *    - Domain membership check
 *    - Environment detection
 *
 * 3. ADAPTIVE SWITCHING
 *    - Context-aware switching
 *    - Schedule-based profiles
 *    - Event-triggered changes
 *    - User activity detection
 *    - Application-based switching
 *
 * 4. RESOURCE OPTIMIZATION
 *    - CPU usage adjustment
 *    - Memory limits
 *    - I/O throttling
 *    - Network bandwidth
 *    - Scan scheduling
 *
 * 5. HIGH AVAILABILITY
 *    - Failsafe profiles
 *    - Corruption recovery
 *    - Minimal security mode
 *    - Emergency profiles
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
#include <variant>
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
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Config {
    class ProfileManagerImpl;
}

namespace ShadowStrike {
namespace Config {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace ProfileConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum custom profiles
    inline constexpr uint32_t MAX_CUSTOM_PROFILES = 64;
    
    /// @brief Maximum profile name length
    inline constexpr size_t MAX_PROFILE_NAME_LENGTH = 128;
    
    /// @brief Auto-detect interval (seconds)
    inline constexpr uint32_t AUTO_DETECT_INTERVAL_SECONDS = 60;
    
    /// @brief Profile switch cooldown (seconds)
    inline constexpr uint32_t PROFILE_SWITCH_COOLDOWN_SECONDS = 5;

}  // namespace ProfileConstants

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
 * @brief System profile type
 */
enum class SystemProfile : uint8_t {
    Standard        = 0,    ///< Balanced settings (default)
    Server          = 1,    ///< Server-optimized (high availability)
    Developer       = 2,    ///< Reduced file system blocks
    LockedDown      = 3,    ///< High sensitivity/maximum security
    Gaming          = 4,    ///< Performance focus
    LowResource     = 5,    ///< Minimal resource usage
    HighSecurity    = 6,    ///< Maximum detection, performance secondary
    Portable        = 7,    ///< For USB/portable installations
    Silent          = 8,    ///< Minimal notifications
    Emergency       = 9,    ///< Failsafe/recovery mode
    Custom          = 10    ///< User-defined profile
};

/**
 * @brief Machine role (auto-detected)
 */
enum class MachineRole : uint8_t {
    Unknown         = 0,
    Workstation     = 1,
    Server          = 2,
    DomainController= 3,
    VirtualMachine  = 4,
    Terminal        = 5,
    Laptop          = 6,
    Tablet          = 7,
    IoTDevice       = 8,
    Container       = 9
};

/**
 * @brief Profile switch trigger
 */
enum class ProfileTrigger : uint8_t {
    Manual          = 0,    ///< User-initiated
    Scheduled       = 1,    ///< Time-based schedule
    ApplicationStart= 2,    ///< Application launched
    PowerEvent      = 3,    ///< Battery/power change
    NetworkChange   = 4,    ///< Network type change
    UserActivity    = 5,    ///< Idle/active detection
    ResourcePressure= 6,    ///< System resource threshold
    PolicyUpdate    = 7,    ///< Policy-mandated change
    Emergency       = 8     ///< Error/emergency condition
};

/**
 * @brief Profile state
 */
enum class ProfileState : uint8_t {
    Active          = 0,
    Inactive        = 1,
    Switching       = 2,
    Suspended       = 3,
    Error           = 4
};

/**
 * @brief Manager status
 */
enum class ProfileStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Switching       = 3,
    Error           = 4,
    Stopping        = 5,
    Stopped         = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Resource limits for a profile
 */
struct ResourceLimits {
    /// @brief Maximum CPU usage percentage
    uint32_t maxCpuPercent = 50;
    
    /// @brief Maximum memory usage (MB)
    uint32_t maxMemoryMb = 512;
    
    /// @brief I/O priority (0-5, higher = more priority)
    uint32_t ioPriority = 2;
    
    /// @brief Maximum concurrent scans
    uint32_t maxConcurrentScans = 2;
    
    /// @brief Scan thread priority
    int32_t scanThreadPriority = 0;
    
    /// @brief Enable background mode
    bool backgroundMode = false;
    
    /// @brief Network bandwidth limit (KB/s, 0 = unlimited)
    uint32_t networkBandwidthKbps = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan settings for a profile
 */
struct ProfileScanSettings {
    /// @brief Enable real-time protection
    bool realtimeProtection = true;
    
    /// @brief Enable behavior monitoring
    bool behaviorMonitoring = true;
    
    /// @brief Scan archives
    bool scanArchives = true;
    
    /// @brief Maximum archive depth
    uint32_t maxArchiveDepth = 5;
    
    /// @brief Scan network files
    bool scanNetworkFiles = false;
    
    /// @brief Scan on access
    bool scanOnAccess = true;
    
    /// @brief Scan on execute
    bool scanOnExecute = true;
    
    /// @brief Scan on write
    bool scanOnWrite = true;
    
    /// @brief Heuristic level (0-4)
    uint32_t heuristicLevel = 2;
    
    /// @brief Cloud lookup enabled
    bool cloudLookupEnabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Notification settings for a profile
 */
struct ProfileNotificationSettings {
    /// @brief Enable notifications
    bool enabled = true;
    
    /// @brief Enable sound
    bool soundEnabled = true;
    
    /// @brief Show scan progress
    bool showScanProgress = true;
    
    /// @brief Show threat alerts
    bool showThreatAlerts = true;
    
    /// @brief Show update notifications
    bool showUpdateNotifications = true;
    
    /// @brief Notification display duration (seconds)
    uint32_t displayDurationSeconds = 5;
    
    /// @brief Enable do-not-disturb hours
    bool doNotDisturbEnabled = false;
    
    /// @brief Do-not-disturb start hour
    uint32_t dndStartHour = 22;
    
    /// @brief Do-not-disturb end hour
    uint32_t dndEndHour = 7;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Profile definition
 */
struct ProfileDefinition {
    /// @brief Profile type
    SystemProfile profileType = SystemProfile::Standard;
    
    /// @brief Custom profile name (for Custom type)
    std::string customName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Resource limits
    ResourceLimits resources;
    
    /// @brief Scan settings
    ProfileScanSettings scan;
    
    /// @brief Notification settings
    ProfileNotificationSettings notifications;
    
    /// @brief Path exclusions
    std::vector<std::wstring> pathExclusions;
    
    /// @brief Process exclusions
    std::vector<std::wstring> processExclusions;
    
    /// @brief Extension exclusions
    std::vector<std::wstring> extensionExclusions;
    
    /// @brief Is built-in (non-deletable)
    bool isBuiltIn = false;
    
    /// @brief Is read-only
    bool isReadOnly = false;
    
    /// @brief Created timestamp
    SystemTimePoint createdAt;
    
    /// @brief Modified timestamp
    SystemTimePoint modifiedAt;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Profile switch event
 */
struct ProfileSwitchEvent {
    /// @brief Previous profile
    SystemProfile previousProfile = SystemProfile::Standard;
    
    /// @brief New profile
    SystemProfile newProfile = SystemProfile::Standard;
    
    /// @brief Trigger reason
    ProfileTrigger trigger = ProfileTrigger::Manual;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Duration of switch (milliseconds)
    uint32_t switchDurationMs = 0;
    
    /// @brief Success
    bool success = true;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Schedule entry for automatic profile switching
 */
struct ProfileScheduleEntry {
    /// @brief Schedule ID
    uint64_t scheduleId = 0;
    
    /// @brief Target profile
    SystemProfile profile = SystemProfile::Standard;
    
    /// @brief Days of week (bitmask: bit 0 = Sunday)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Start hour (0-23)
    uint32_t startHour = 0;
    
    /// @brief Start minute (0-59)
    uint32_t startMinute = 0;
    
    /// @brief End hour (0-23)
    uint32_t endHour = 23;
    
    /// @brief End minute (0-59)
    uint32_t endMinute = 59;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Priority (higher = takes precedence)
    uint32_t priority = 100;
    
    [[nodiscard]] bool IsActiveNow() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Application trigger rule
 */
struct ApplicationTriggerRule {
    /// @brief Rule ID
    uint64_t ruleId = 0;
    
    /// @brief Application path pattern
    std::wstring applicationPattern;
    
    /// @brief Profile when running
    SystemProfile profileWhenRunning = SystemProfile::Gaming;
    
    /// @brief Profile after exit
    SystemProfile profileAfterExit = SystemProfile::Standard;
    
    /// @brief Switch delay (seconds)
    uint32_t switchDelaySeconds = 0;
    
    /// @brief Exit delay (seconds) - time after app exits to switch back
    uint32_t exitDelaySeconds = 5;
    
    /// @brief Is enabled
    bool enabled = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct ProfileStatistics {
    std::atomic<uint64_t> profileSwitches{0};
    std::atomic<uint64_t> manualSwitches{0};
    std::atomic<uint64_t> scheduledSwitches{0};
    std::atomic<uint64_t> applicationTriggers{0};
    std::atomic<uint64_t> emergencySwitches{0};
    std::atomic<uint64_t> switchFailures{0};
    std::array<std::atomic<uint64_t>, 16> timeInProfile{};  // Seconds per profile
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct ProfileManagerConfiguration {
    /// @brief Initial profile
    SystemProfile initialProfile = SystemProfile::Standard;
    
    /// @brief Enable auto-detection
    bool enableAutoDetection = true;
    
    /// @brief Auto-detect interval (seconds)
    uint32_t autoDetectIntervalSeconds = ProfileConstants::AUTO_DETECT_INTERVAL_SECONDS;
    
    /// @brief Enable scheduled switching
    bool enableScheduledSwitching = true;
    
    /// @brief Enable application triggers
    bool enableApplicationTriggers = true;
    
    /// @brief Profile switch cooldown (seconds)
    uint32_t switchCooldownSeconds = ProfileConstants::PROFILE_SWITCH_COOLDOWN_SECONDS;
    
    /// @brief Enable emergency fallback
    bool enableEmergencyFallback = true;
    
    /// @brief Emergency profile
    SystemProfile emergencyProfile = SystemProfile::Emergency;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ProfileSwitchCallback = std::function<void(const ProfileSwitchEvent&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PROFILE MANAGER CLASS
// ============================================================================

/**
 * @class ProfileManager
 * @brief Enterprise profile management
 */
class ProfileManager final {
public:
    [[nodiscard]] static ProfileManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    ProfileManager(const ProfileManager&) = delete;
    ProfileManager& operator=(const ProfileManager&) = delete;
    ProfileManager(ProfileManager&&) = delete;
    ProfileManager& operator=(ProfileManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const ProfileManagerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ProfileStatus GetStatus() const noexcept;

    // ========================================================================
    // ACTIVE PROFILE
    // ========================================================================
    
    /// @brief Set active profile
    [[nodiscard]] bool SetActiveProfile(SystemProfile profile);
    
    /// @brief Set active profile by name (for custom profiles)
    [[nodiscard]] bool SetActiveProfile(const std::string& profileName);
    
    /// @brief Get active profile
    [[nodiscard]] SystemProfile GetActiveProfile() const noexcept;
    
    /// @brief Get active profile definition
    [[nodiscard]] ProfileDefinition GetActiveProfileDefinition() const;
    
    /// @brief Get profile name
    [[nodiscard]] std::string GetActiveProfileName() const;

    // ========================================================================
    // PROFILE MANAGEMENT
    // ========================================================================
    
    /// @brief Get profile definition
    [[nodiscard]] ProfileDefinition GetProfileDefinition(SystemProfile profile) const;
    
    /// @brief Get custom profile definition
    [[nodiscard]] std::optional<ProfileDefinition> GetCustomProfile(const std::string& name) const;
    
    /// @brief Create custom profile
    [[nodiscard]] bool CreateCustomProfile(const ProfileDefinition& profile);
    
    /// @brief Update custom profile
    [[nodiscard]] bool UpdateCustomProfile(const std::string& name, const ProfileDefinition& profile);
    
    /// @brief Delete custom profile
    [[nodiscard]] bool DeleteCustomProfile(const std::string& name);
    
    /// @brief List all profiles
    [[nodiscard]] std::vector<ProfileDefinition> ListProfiles() const;
    
    /// @brief List custom profiles
    [[nodiscard]] std::vector<std::string> ListCustomProfileNames() const;

    // ========================================================================
    // AUTO-DETECTION
    // ========================================================================
    
    /// @brief Detect machine role
    [[nodiscard]] MachineRole DetectMachineRole() const;
    
    /// @brief Get recommended profile
    [[nodiscard]] SystemProfile GetRecommendedProfile() const;
    
    /// @brief Apply recommended profile
    [[nodiscard]] bool ApplyRecommendedProfile();
    
    /// @brief Enable/disable auto-detection
    void SetAutoDetectionEnabled(bool enabled);
    
    /// @brief Is auto-detection enabled
    [[nodiscard]] bool IsAutoDetectionEnabled() const noexcept;

    // ========================================================================
    // SCHEDULING
    // ========================================================================
    
    /// @brief Add schedule entry
    [[nodiscard]] uint64_t AddScheduleEntry(const ProfileScheduleEntry& entry);
    
    /// @brief Remove schedule entry
    [[nodiscard]] bool RemoveScheduleEntry(uint64_t scheduleId);
    
    /// @brief Update schedule entry
    [[nodiscard]] bool UpdateScheduleEntry(const ProfileScheduleEntry& entry);
    
    /// @brief List schedule entries
    [[nodiscard]] std::vector<ProfileScheduleEntry> ListScheduleEntries() const;
    
    /// @brief Enable/disable scheduled switching
    void SetScheduledSwitchingEnabled(bool enabled);

    // ========================================================================
    // APPLICATION TRIGGERS
    // ========================================================================
    
    /// @brief Add application trigger
    [[nodiscard]] uint64_t AddApplicationTrigger(const ApplicationTriggerRule& rule);
    
    /// @brief Remove application trigger
    [[nodiscard]] bool RemoveApplicationTrigger(uint64_t ruleId);
    
    /// @brief Update application trigger
    [[nodiscard]] bool UpdateApplicationTrigger(const ApplicationTriggerRule& rule);
    
    /// @brief List application triggers
    [[nodiscard]] std::vector<ApplicationTriggerRule> ListApplicationTriggers() const;
    
    /// @brief Enable/disable application triggers
    void SetApplicationTriggersEnabled(bool enabled);

    // ========================================================================
    // RESOURCE LIMITS
    // ========================================================================
    
    /// @brief Get current resource limits
    [[nodiscard]] ResourceLimits GetCurrentResourceLimits() const;
    
    /// @brief Override resource limits temporarily
    void OverrideResourceLimits(const ResourceLimits& limits);
    
    /// @brief Clear resource override
    void ClearResourceOverride();

    // ========================================================================
    // FAILSAFE
    // ========================================================================
    
    /// @brief Activate emergency profile
    [[nodiscard]] bool ActivateEmergencyProfile();
    
    /// @brief Is in emergency mode
    [[nodiscard]] bool IsInEmergencyMode() const noexcept;
    
    /// @brief Exit emergency mode
    [[nodiscard]] bool ExitEmergencyMode();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    uint64_t RegisterSwitchCallback(ProfileSwitchCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] ProfileStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] std::vector<ProfileSwitchEvent> GetSwitchHistory(size_t maxEntries = 100) const;
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    ProfileManager();
    ~ProfileManager();
    
    std::unique_ptr<ProfileManagerImpl> m_impl;
    SystemProfile m_currentProfile = SystemProfile::Standard;
    mutable std::shared_mutex m_mutex;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSystemProfileName(SystemProfile profile) noexcept;
[[nodiscard]] std::string_view GetMachineRoleName(MachineRole role) noexcept;
[[nodiscard]] std::string_view GetProfileTriggerName(ProfileTrigger trigger) noexcept;

/// @brief Get default profile for machine role
[[nodiscard]] SystemProfile GetDefaultProfileForRole(MachineRole role);

}  // namespace Config
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SET_PROFILE(profile) \
    ::ShadowStrike::Config::ProfileManager::Instance().SetActiveProfile(profile)

#define SS_GET_PROFILE() \
    ::ShadowStrike::Config::ProfileManager::Instance().GetActiveProfile()
