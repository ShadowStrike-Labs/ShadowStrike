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
 * ShadowStrike NGAV - GAME MODE MANAGER MODULE
 * ============================================================================
 *
 * @file GameModeManager.hpp
 * @brief Enterprise-grade game mode orchestration with automatic detection,
 *        resource management, notification suppression, and system optimization.
 *
 * Provides comprehensive game mode management for optimal gaming experience
 * while maintaining security through intelligent resource reallocation.
 *
 * GAME MODE CAPABILITIES:
 * =======================
 *
 * 1. AUTOMATIC DETECTION
 *    - Game process detection
 *    - Fullscreen detection
 *    - Game launcher detection
 *    - VR application detection
 *    - Streaming detection
 *
 * 2. RESOURCE MANAGEMENT
 *    - CPU priority adjustment
 *    - I/O throttling
 *    - Memory management
 *    - Thread affinity
 *    - Scan postponement
 *
 * 3. NOTIFICATION CONTROL
 *    - Silent mode
 *    - Critical-only alerts
 *    - Overlay minimization
 *    - Sound suppression
 *    - Action deferral
 *
 * 4. SECURITY MAINTENANCE
 *    - Essential protection
 *    - Real-time scanning
 *    - Threat blocking
 *    - Post-game cleanup
 *    - Deferred actions
 *
 * 5. SCHEDULING
 *    - Time-based rules
 *    - Per-game profiles
 *    - Custom triggers
 *    - Auto-disable timers
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
#include <unordered_map>
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
#include "../Utils/SystemUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::GameMode {
    class GameModeManagerImpl;
}

namespace ShadowStrike {
namespace GameMode {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace GameModeConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default detection interval (ms)
    inline constexpr uint32_t DEFAULT_DETECTION_INTERVAL_MS = 5000;
    
    /// @brief Auto-disable timeout (hours)
    inline constexpr uint32_t DEFAULT_AUTO_DISABLE_HOURS = 4;
    
    /// @brief Scan resume delay after game exit (seconds)
    inline constexpr uint32_t SCAN_RESUME_DELAY_SECONDS = 30;
    
    /// @brief Maximum deferred actions
    inline constexpr size_t MAX_DEFERRED_ACTIONS = 1000;

}  // namespace GameModeConstants

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
 * @brief Game mode activation reason
 */
enum class ActivationReason : uint8_t {
    Manual          = 0,    ///< User activated
    GameDetected    = 1,    ///< Game process detected
    FullscreenDetected = 2, ///< Fullscreen application
    LauncherActive  = 3,    ///< Game launcher active
    VRActive        = 4,    ///< VR application running
    StreamingActive = 5,    ///< Streaming/recording
    Scheduled       = 6,    ///< Scheduled activation
    API             = 7     ///< External API trigger
};

/**
 * @brief Protection level
 */
enum class ProtectionLevel : uint8_t {
    Full            = 0,    ///< Full protection (no game mode)
    Balanced        = 1,    ///< Balanced (default game mode)
    Performance     = 2,    ///< Maximum performance
    Custom          = 3     ///< Custom configuration
};

/**
 * @brief Resource priority
 */
enum class ResourcePriority : uint8_t {
    Normal          = 0,
    BelowNormal     = 1,
    Low             = 2,
    Idle            = 3
};

/**
 * @brief Notification policy
 */
enum class NotificationPolicy : uint8_t {
    All             = 0,    ///< All notifications
    CriticalOnly    = 1,    ///< Critical threats only
    None            = 2     ///< No notifications
};

/**
 * @brief Deferred action type
 */
enum class DeferredActionType : uint8_t {
    Scan            = 0,
    Update          = 1,
    Cleanup         = 2,
    Notification    = 3,
    Maintenance     = 4
};

/**
 * @brief Module status
 */
enum class GameModeStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Inactive        = 2,
    Active          = 3,
    Transitioning   = 4,
    Stopping        = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Game session info
 */
struct GameSession {
    /// @brief Session ID
    std::string sessionId;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Game title
    std::string gameTitle;
    
    /// @brief Activation reason
    ActivationReason reason = ActivationReason::Manual;
    
    /// @brief Started time
    SystemTimePoint startedTime;
    
    /// @brief Ended time
    std::optional<SystemTimePoint> endedTime;
    
    /// @brief Duration (seconds)
    uint64_t durationSeconds = 0;
    
    /// @brief Threats blocked
    uint32_t threatsBlocked = 0;
    
    /// @brief Actions deferred
    uint32_t actionsDeferred = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Deferred action
 */
struct DeferredAction {
    /// @brief Action ID
    std::string actionId;
    
    /// @brief Action type
    DeferredActionType actionType = DeferredActionType::Scan;
    
    /// @brief Description
    std::string description;
    
    /// @brief Deferred time
    SystemTimePoint deferredTime;
    
    /// @brief Context data
    std::map<std::string, std::string> context;
    
    /// @brief Priority
    uint8_t priority = 5;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Game mode profile
 */
struct GameModeProfile {
    /// @brief Profile name
    std::string name;
    
    /// @brief Description
    std::string description;
    
    /// @brief Protection level
    ProtectionLevel protectionLevel = ProtectionLevel::Balanced;
    
    /// @brief Resource priority
    ResourcePriority resourcePriority = ResourcePriority::Low;
    
    /// @brief Notification policy
    NotificationPolicy notificationPolicy = NotificationPolicy::CriticalOnly;
    
    /// @brief Postpone scheduled scans
    bool postponeScans = true;
    
    /// @brief Postpone updates
    bool postponeUpdates = true;
    
    /// @brief Reduce real-time scanning
    bool reduceRealtimeScan = false;
    
    /// @brief Allow critical alerts only
    bool criticalAlertsOnly = true;
    
    /// @brief Enable overlay protection
    bool enableOverlayProtection = true;
    
    /// @brief Auto-disable timeout (minutes, 0 = no timeout)
    uint32_t autoDisableMinutes = 0;
    
    /// @brief Is default profile
    bool isDefault = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Schedule rule
 */
struct GameModeSchedule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::string name;
    
    /// @brief Days of week (bitmap: bit 0 = Sunday)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Start time (minutes from midnight)
    uint16_t startMinutes = 0;
    
    /// @brief End time (minutes from midnight)
    uint16_t endMinutes = 0;
    
    /// @brief Profile to use
    std::string profileName;
    
    /// @brief Is enabled
    bool enabled = true;
    
    [[nodiscard]] bool IsActiveNow() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct GameModeStatistics {
    std::atomic<uint64_t> totalSessions{0};
    std::atomic<uint64_t> totalDurationSeconds{0};
    std::atomic<uint64_t> autoActivations{0};
    std::atomic<uint64_t> manualActivations{0};
    std::atomic<uint64_t> threatsBlocked{0};
    std::atomic<uint64_t> actionsDeferred{0};
    std::atomic<uint64_t> scansPostponed{0};
    std::atomic<uint64_t> notificationsSuppressed{0};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct GameModeConfiguration {
    /// @brief Enable game mode
    bool enabled = true;
    
    /// @brief Enable auto-detection
    bool autoDetectionEnabled = true;
    
    /// @brief Enable fullscreen detection
    bool fullscreenDetectionEnabled = true;
    
    /// @brief Enable launcher detection
    bool launcherDetectionEnabled = true;
    
    /// @brief Enable VR detection
    bool vrDetectionEnabled = true;
    
    /// @brief Detection interval (ms)
    uint32_t detectionIntervalMs = GameModeConstants::DEFAULT_DETECTION_INTERVAL_MS;
    
    /// @brief Default profile
    std::string defaultProfile = "Balanced";
    
    /// @brief Auto-disable timeout (hours)
    uint32_t autoDisableHours = GameModeConstants::DEFAULT_AUTO_DISABLE_HOURS;
    
    /// @brief Resume delay after game exit (seconds)
    uint32_t resumeDelaySeconds = GameModeConstants::SCAN_RESUME_DELAY_SECONDS;
    
    /// @brief Show activation notification
    bool showActivationNotification = true;
    
    /// @brief Play sound on activation
    bool playSoundOnActivation = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using StateChangeCallback = std::function<void(bool active, ActivationReason reason)>;
using GameDetectedCallback = std::function<void(uint32_t pid, const std::wstring& processName)>;
using ActionDeferredCallback = std::function<void(const DeferredAction&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// GAME MODE MANAGER CLASS
// ============================================================================

/**
 * @class GameModeManager
 * @brief Enterprise game mode management
 */
class GameModeManager final {
public:
    [[nodiscard]] static GameModeManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    GameModeManager(const GameModeManager&) = delete;
    GameModeManager& operator=(const GameModeManager&) = delete;
    GameModeManager(GameModeManager&&) = delete;
    GameModeManager& operator=(GameModeManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const GameModeConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] GameModeStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const GameModeConfiguration& config);
    [[nodiscard]] GameModeConfiguration GetConfiguration() const;

    // ========================================================================
    // GAME MODE CONTROL
    // ========================================================================
    
    /// @brief Enable/disable game mode
    void SetEnabled(bool enabled);
    
    /// @brief Manually activate game mode
    [[nodiscard]] bool Activate(const std::string& profileName = "");
    
    /// @brief Manually deactivate game mode
    void Deactivate();
    
    /// @brief Check if active
    [[nodiscard]] bool IsActive() const noexcept;
    
    /// @brief Get activation reason
    [[nodiscard]] ActivationReason GetActivationReason() const noexcept;
    
    /// @brief Get current protection level
    [[nodiscard]] ProtectionLevel GetProtectionLevel() const noexcept;
    
    /// @brief Called when game state changes
    void OnGameStateChanged(bool isGaming);
    
    /// @brief Called when game detected
    void OnGameDetected(uint32_t pid, const std::wstring& processName);
    
    /// @brief Called when game exited
    void OnGameExited(uint32_t pid);

    // ========================================================================
    // PROFILE MANAGEMENT
    // ========================================================================
    
    /// @brief Get profiles
    [[nodiscard]] std::vector<GameModeProfile> GetProfiles() const;
    
    /// @brief Get profile
    [[nodiscard]] std::optional<GameModeProfile> GetProfile(const std::string& name) const;
    
    /// @brief Add/update profile
    [[nodiscard]] bool SaveProfile(const GameModeProfile& profile);
    
    /// @brief Delete profile
    [[nodiscard]] bool DeleteProfile(const std::string& name);
    
    /// @brief Set default profile
    [[nodiscard]] bool SetDefaultProfile(const std::string& name);

    // ========================================================================
    // SCHEDULING
    // ========================================================================
    
    /// @brief Get schedules
    [[nodiscard]] std::vector<GameModeSchedule> GetSchedules() const;
    
    /// @brief Add/update schedule
    [[nodiscard]] bool SaveSchedule(const GameModeSchedule& schedule);
    
    /// @brief Delete schedule
    [[nodiscard]] bool DeleteSchedule(const std::string& ruleId);
    
    /// @brief Check if scheduled now
    [[nodiscard]] bool IsScheduledNow() const;

    // ========================================================================
    // ACTION DEFERRAL
    // ========================================================================
    
    /// @brief Defer an action
    void DeferAction(const DeferredAction& action);
    
    /// @brief Get deferred actions
    [[nodiscard]] std::vector<DeferredAction> GetDeferredActions() const;
    
    /// @brief Execute deferred actions
    void ExecuteDeferredActions();
    
    /// @brief Clear deferred actions
    void ClearDeferredActions();

    // ========================================================================
    // SESSION HISTORY
    // ========================================================================
    
    /// @brief Get current session
    [[nodiscard]] std::optional<GameSession> GetCurrentSession() const;
    
    /// @brief Get session history
    [[nodiscard]] std::vector<GameSession> GetSessionHistory(size_t limit = 100) const;

    // ========================================================================
    // UTILITY CHECKS
    // ========================================================================
    
    /// @brief Should show notification
    [[nodiscard]] bool ShouldShowNotification(uint8_t severity) const;
    
    /// @brief Should defer scan
    [[nodiscard]] bool ShouldDeferScan() const;
    
    /// @brief Should defer update
    [[nodiscard]] bool ShouldDeferUpdate() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterStateChangeCallback(StateChangeCallback callback);
    void RegisterGameDetectedCallback(GameDetectedCallback callback);
    void RegisterActionDeferredCallback(ActionDeferredCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] GameModeStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    GameModeManager();
    ~GameModeManager();
    
    std::unique_ptr<GameModeManagerImpl> m_impl;
    std::atomic<bool> m_manualOverride{false};
    std::atomic<bool> m_autoDetected{false};
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetActivationReasonName(ActivationReason reason) noexcept;
[[nodiscard]] std::string_view GetProtectionLevelName(ProtectionLevel level) noexcept;
[[nodiscard]] std::string_view GetNotificationPolicyName(NotificationPolicy policy) noexcept;
[[nodiscard]] std::string_view GetDeferredActionTypeName(DeferredActionType type) noexcept;
[[nodiscard]] std::string_view GetStatusName(GameModeStatus status) noexcept;

}  // namespace GameMode
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_GAMEMODE_IS_ACTIVE() \
    ::ShadowStrike::GameMode::GameModeManager::Instance().IsActive()

#define SS_GAMEMODE_SHOULD_DEFER_SCAN() \
    ::ShadowStrike::GameMode::GameModeManager::Instance().ShouldDeferScan()
