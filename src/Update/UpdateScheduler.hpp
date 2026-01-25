/**
 * ============================================================================
 * ShadowStrike NGAV - UPDATE SCHEDULER MODULE
 * ============================================================================
 *
 * @file UpdateScheduler.hpp
 * @brief Enterprise-grade update scheduling with intelligent timing,
 *        bandwidth management, and enterprise deployment support.
 *
 * Provides comprehensive update scheduling including time-based rules,
 * system state awareness, and network condition optimization.
 *
 * SCHEDULING CAPABILITIES:
 * ========================
 *
 * 1. TIMING CONTROL
 *    - Periodic checks
 *    - Time-based rules
 *    - Maintenance windows
 *    - Quiet hours
 *    - Custom schedules
 *
 * 2. SYSTEM AWARENESS
 *    - CPU usage detection
 *    - Game mode respect
 *    - Battery state
 *    - Power plan detection
 *    - User activity
 *
 * 3. NETWORK AWARENESS
 *    - Metered connection
 *    - Bandwidth throttling
 *    - Network type detection
 *    - VPN detection
 *    - Proxy support
 *
 * 4. PRIORITY HANDLING
 *    - Critical updates
 *    - Zero-day response
 *    - Deferred updates
 *    - Optional updates
 *
 * 5. ENTERPRISE FEATURES
 *    - Group policy
 *    - WSUS integration
 *    - SCCM support
 *    - Custom endpoints
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

namespace ShadowStrike::Update {
    class UpdateSchedulerImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SchedulerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default check interval (hours)
    inline constexpr uint32_t DEFAULT_CHECK_INTERVAL_HOURS = 1;
    
    /// @brief Minimum check interval (minutes)
    inline constexpr uint32_t MIN_CHECK_INTERVAL_MINUTES = 15;
    
    /// @brief Maximum defer time (hours)
    inline constexpr uint32_t MAX_DEFER_HOURS = 72;
    
    /// @brief CPU threshold for deferral (%)
    inline constexpr uint8_t CPU_DEFER_THRESHOLD = 80;

}  // namespace SchedulerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Duration = std::chrono::hours;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Scheduler state
 */
enum class SchedulerState : uint8_t {
    Stopped         = 0,
    Running         = 1,
    Paused          = 2,
    Checking        = 3,
    Waiting         = 4
};

/**
 * @brief Check trigger
 */
enum class CheckTrigger : uint8_t {
    Scheduled       = 0,    ///< Scheduled check
    Manual          = 1,    ///< User initiated
    Startup         = 2,    ///< Application startup
    NetworkChange   = 3,    ///< Network reconnect
    WakeFromSleep   = 4,    ///< Resume from sleep
    Forced          = 5,    ///< Forced by server
    Enterprise      = 6     ///< Enterprise push
};

/**
 * @brief Deferral reason
 */
enum class DeferralReason : uint8_t {
    None            = 0,
    HighCPU         = 1,
    GameMode        = 2,
    Presentation    = 3,
    MeteredNetwork  = 4,
    OnBattery       = 5,
    QuietHours      = 6,
    UserDeferred    = 7,
    MaintenanceWindow = 8,
    MaxDeferred     = 9     ///< Max deferral reached
};

/**
 * @brief Network type
 */
enum class NetworkType : uint8_t {
    Unknown         = 0,
    Ethernet        = 1,
    WiFi            = 2,
    Cellular        = 3,
    VPN             = 4,
    Satellite       = 5
};

/**
 * @brief Module status
 */
enum class SchedulerStatus : uint8_t {
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
 * @brief Schedule rule
 */
struct ScheduleRule {
    /// @brief Rule ID
    std::string ruleId;
    
    /// @brief Rule name
    std::string name;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Check interval (hours)
    uint32_t intervalHours = SchedulerConstants::DEFAULT_CHECK_INTERVAL_HOURS;
    
    /// @brief Days of week (bitmap: bit 0 = Sunday)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Start time (minutes from midnight)
    uint16_t startMinutes = 0;
    
    /// @brief End time (minutes from midnight)
    uint16_t endMinutes = 24 * 60;  // 24:00
    
    /// @brief Defer on high CPU
    bool deferOnHighCPU = true;
    
    /// @brief CPU threshold (%)
    uint8_t cpuThreshold = SchedulerConstants::CPU_DEFER_THRESHOLD;
    
    /// @brief Defer during gaming
    bool deferDuringGaming = true;
    
    /// @brief Defer on battery
    bool deferOnBattery = true;
    
    /// @brief Defer on metered network
    bool deferOnMetered = true;
    
    [[nodiscard]] bool IsActiveNow() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Quiet hours
 */
struct QuietHours {
    /// @brief Is enabled
    bool enabled = false;
    
    /// @brief Start time (minutes from midnight)
    uint16_t startMinutes = 22 * 60;  // 22:00
    
    /// @brief End time (minutes from midnight)
    uint16_t endMinutes = 7 * 60;     // 07:00
    
    /// @brief Days of week (bitmap)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    [[nodiscard]] bool IsActiveNow() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Maintenance window
 */
struct MaintenanceWindow {
    /// @brief Window ID
    std::string windowId;
    
    /// @brief Name
    std::string name;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Start time
    SystemTimePoint startTime;
    
    /// @brief Duration (minutes)
    uint32_t durationMinutes = 60;
    
    /// @brief Recurrence (0 = once, 1 = daily, 7 = weekly, 30 = monthly)
    uint32_t recurrenceDays = 0;
    
    [[nodiscard]] bool IsActiveNow() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System state for scheduling decisions
 */
struct SystemState {
    /// @brief CPU usage (%)
    uint8_t cpuUsage = 0;
    
    /// @brief Memory usage (%)
    uint8_t memoryUsage = 0;
    
    /// @brief Is gaming
    bool isGaming = false;
    
    /// @brief Is presenting
    bool isPresenting = false;
    
    /// @brief Is on battery
    bool isOnBattery = false;
    
    /// @brief Battery percentage
    uint8_t batteryPercent = 100;
    
    /// @brief Network type
    NetworkType networkType = NetworkType::Unknown;
    
    /// @brief Is metered network
    bool isMetered = false;
    
    /// @brief Is VPN connected
    bool isVPN = false;
    
    /// @brief Is quiet hours
    bool isQuietHours = false;
    
    /// @brief Last activity time
    TimePoint lastActivityTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Schedule info
 */
struct ScheduleInfo {
    /// @brief Next check time
    std::optional<SystemTimePoint> nextCheckTime;
    
    /// @brief Last check time
    std::optional<SystemTimePoint> lastCheckTime;
    
    /// @brief Last check trigger
    CheckTrigger lastCheckTrigger = CheckTrigger::Scheduled;
    
    /// @brief Current deferral reason
    DeferralReason deferralReason = DeferralReason::None;
    
    /// @brief Deferral count
    uint32_t deferralCount = 0;
    
    /// @brief Checks today
    uint32_t checksToday = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SchedulerStatistics {
    std::atomic<uint64_t> checksTriggered{0};
    std::atomic<uint64_t> checksCompleted{0};
    std::atomic<uint64_t> checksFailed{0};
    std::atomic<uint64_t> checksDeferred{0};
    std::atomic<uint64_t> updatesFound{0};
    std::atomic<uint64_t> updatesApplied{0};
    std::array<std::atomic<uint64_t>, 16> byDeferralReason{};
    std::array<std::atomic<uint64_t>, 16> byTrigger{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct UpdateSchedulerConfiguration {
    /// @brief Enable scheduler
    bool enabled = true;
    
    /// @brief Default check interval (hours)
    uint32_t defaultIntervalHours = SchedulerConstants::DEFAULT_CHECK_INTERVAL_HOURS;
    
    /// @brief Enable intelligent scheduling
    bool enableIntelligentScheduling = true;
    
    /// @brief Enable system state checks
    bool enableSystemStateChecks = true;
    
    /// @brief Enable metered connection detection
    bool enableMeteredDetection = true;
    
    /// @brief Enable game mode respect
    bool enableGameModeRespect = true;
    
    /// @brief CPU defer threshold (%)
    uint8_t cpuDeferThreshold = SchedulerConstants::CPU_DEFER_THRESHOLD;
    
    /// @brief Max defer time (hours)
    uint32_t maxDeferHours = SchedulerConstants::MAX_DEFER_HOURS;
    
    /// @brief Quiet hours
    QuietHours quietHours;
    
    /// @brief Check on startup
    bool checkOnStartup = true;
    
    /// @brief Check on network change
    bool checkOnNetworkChange = true;
    
    /// @brief Check on wake from sleep
    bool checkOnWakeFromSleep = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using CheckTriggeredCallback = std::function<void(CheckTrigger)>;
using DeferralCallback = std::function<void(DeferralReason)>;
using StateChangeCallback = std::function<void(SchedulerState)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// UPDATE SCHEDULER CLASS
// ============================================================================

/**
 * @class UpdateScheduler
 * @brief Enterprise update scheduling
 */
class UpdateScheduler final {
public:
    [[nodiscard]] static UpdateScheduler& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    UpdateScheduler(const UpdateScheduler&) = delete;
    UpdateScheduler& operator=(const UpdateScheduler&) = delete;
    UpdateScheduler(UpdateScheduler&&) = delete;
    UpdateScheduler& operator=(UpdateScheduler&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const UpdateSchedulerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] SchedulerStatus GetStatus() const noexcept;

    // ========================================================================
    // SCHEDULER CONTROL
    // ========================================================================
    
    /// @brief Start scheduler
    void Start();
    
    /// @brief Stop scheduler
    void Stop();
    
    /// @brief Pause scheduler
    void Pause();
    
    /// @brief Resume scheduler
    void Resume();
    
    /// @brief Get state
    [[nodiscard]] SchedulerState GetState() const noexcept;
    
    /// @brief Is running
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // INTERVAL CONTROL
    // ========================================================================
    
    /// @brief Set check interval
    void SetInterval(std::chrono::hours interval);
    
    /// @brief Get check interval
    [[nodiscard]] std::chrono::hours GetInterval() const;
    
    /// @brief Trigger immediate check
    void TriggerCheck(CheckTrigger trigger = CheckTrigger::Manual);
    
    /// @brief Get next check time
    [[nodiscard]] std::optional<SystemTimePoint> GetNextCheckTime() const;

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================
    
    /// @brief Add schedule rule
    [[nodiscard]] bool AddRule(const ScheduleRule& rule);
    
    /// @brief Remove schedule rule
    [[nodiscard]] bool RemoveRule(const std::string& ruleId);
    
    /// @brief Get rules
    [[nodiscard]] std::vector<ScheduleRule> GetRules() const;
    
    /// @brief Set quiet hours
    void SetQuietHours(const QuietHours& quietHours);
    
    /// @brief Get quiet hours
    [[nodiscard]] QuietHours GetQuietHours() const;

    // ========================================================================
    // MAINTENANCE WINDOWS
    // ========================================================================
    
    /// @brief Add maintenance window
    [[nodiscard]] bool AddMaintenanceWindow(const MaintenanceWindow& window);
    
    /// @brief Remove maintenance window
    [[nodiscard]] bool RemoveMaintenanceWindow(const std::string& windowId);
    
    /// @brief Get maintenance windows
    [[nodiscard]] std::vector<MaintenanceWindow> GetMaintenanceWindows() const;
    
    /// @brief Is in maintenance window
    [[nodiscard]] bool IsInMaintenanceWindow() const;

    // ========================================================================
    // STATE INFORMATION
    // ========================================================================
    
    /// @brief Get system state
    [[nodiscard]] SystemState GetSystemState() const;
    
    /// @brief Get schedule info
    [[nodiscard]] ScheduleInfo GetScheduleInfo() const;
    
    /// @brief Can update now
    [[nodiscard]] bool CanUpdateNow() const;
    
    /// @brief Get current deferral reason
    [[nodiscard]] DeferralReason GetCurrentDeferralReason() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCheckTriggeredCallback(CheckTriggeredCallback callback);
    void RegisterDeferralCallback(DeferralCallback callback);
    void RegisterStateChangeCallback(StateChangeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SchedulerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    UpdateScheduler();
    ~UpdateScheduler();
    
    std::unique_ptr<UpdateSchedulerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSchedulerStateName(SchedulerState state) noexcept;
[[nodiscard]] std::string_view GetCheckTriggerName(CheckTrigger trigger) noexcept;
[[nodiscard]] std::string_view GetDeferralReasonName(DeferralReason reason) noexcept;
[[nodiscard]] std::string_view GetNetworkTypeName(NetworkType type) noexcept;

/// @brief Check if network is metered
[[nodiscard]] bool IsNetworkMetered();

/// @brief Detect network type
[[nodiscard]] NetworkType DetectNetworkType();

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_START_UPDATE_SCHEDULER() \
    ::ShadowStrike::Update::UpdateScheduler::Instance().Start()

#define SS_TRIGGER_UPDATE_CHECK() \
    ::ShadowStrike::Update::UpdateScheduler::Instance().TriggerCheck()
