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
 * ShadowStrike NGAV - BACKUP SCHEDULER MODULE
 * ============================================================================
 *
 * @file BackupScheduler.hpp
 * @brief Enterprise-grade backup scheduling with time-based, event-based,
 *        and intelligent adaptive scheduling capabilities.
 *
 * Provides comprehensive scheduling for backup operations including periodic
 * backups, event-triggered backups, and smart resource management.
 *
 * SCHEDULING CAPABILITIES:
 * ========================
 *
 * 1. TIME-BASED SCHEDULING
 *    - Hourly backups
 *    - Daily backups
 *    - Weekly backups
 *    - Monthly backups
 *    - Custom intervals
 *    - Cron-style schedules
 *
 * 2. EVENT-BASED TRIGGERS
 *    - Before app install
 *    - Before system update
 *    - On file changes
 *    - On login/logout
 *    - On shutdown
 *    - Manual request
 *
 * 3. SMART THROTTLING
 *    - Battery level check
 *    - Power source detection
 *    - System load monitoring
 *    - Network availability
 *    - User activity detection
 *    - Game mode awareness
 *
 * 4. PRIORITY MANAGEMENT
 *    - Critical backups
 *    - Normal backups
 *    - Low-priority backups
 *    - Queue management
 *    - Conflict resolution
 *
 * 5. ADAPTIVE SCHEDULING
 *    - Learn user patterns
 *    - Optimize timing
 *    - Minimize disruption
 *    - Bandwidth management
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

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Backup {
    class BackupSchedulerImpl;
}

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SchedulerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Minimum battery level for backup (%)
    inline constexpr int MIN_BATTERY_LEVEL = 20;
    
    /// @brief Maximum CPU usage to start backup (%)
    inline constexpr int MAX_CPU_USAGE = 80;
    
    /// @brief Idle time required for low-priority backups (seconds)
    inline constexpr uint32_t IDLE_THRESHOLD_SECONDS = 300;
    
    /// @brief Maximum queued backups
    inline constexpr size_t MAX_QUEUE_SIZE = 100;
    
    /// @brief Schedule check interval (seconds)
    inline constexpr uint32_t CHECK_INTERVAL_SECONDS = 60;

}  // namespace SchedulerConstants

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
 * @brief Schedule frequency
 */
enum class ScheduleFrequency : uint8_t {
    Once            = 0,    ///< One-time backup
    Hourly          = 1,
    Daily           = 2,
    Weekly          = 3,
    Monthly         = 4,
    Custom          = 5,    ///< Custom interval
    Cron            = 6     ///< Cron expression
};

/**
 * @brief Trigger type
 */
enum class TriggerType : uint8_t {
    Scheduled       = 0,    ///< Time-based
    BeforeInstall   = 1,    ///< Before app install
    BeforeUpdate    = 2,    ///< Before system update
    OnFileChange    = 3,    ///< On file changes
    OnLogin         = 4,    ///< On user login
    OnLogout        = 5,    ///< On user logout
    OnShutdown      = 6,    ///< On system shutdown
    OnIdle          = 7,    ///< When system is idle
    Manual          = 8,    ///< Manual request
    OnNetworkChange = 9,    ///< On network change
    OnDriveConnect  = 10    ///< On USB drive connect
};

/**
 * @brief Backup priority
 */
enum class BackupPriority : uint8_t {
    Critical        = 0,    ///< Run immediately
    High            = 1,    ///< Run soon
    Normal          = 2,    ///< Standard priority
    Low             = 3,    ///< Run when idle
    Background      = 4     ///< Run in background
};

/**
 * @brief Schedule status
 */
enum class ScheduleStatus : uint8_t {
    Active          = 0,
    Paused          = 1,
    Disabled        = 2,
    Running         = 3,
    WaitingCondition= 4,    ///< Waiting for conditions
    Error           = 5
};

/**
 * @brief Throttle reason
 */
enum class ThrottleReason : uint8_t {
    None            = 0,
    LowBattery      = 1,
    HighCPU         = 2,
    UserActive      = 3,
    GameMode        = 4,
    NoNetwork       = 5,
    MeteredNetwork  = 6,
    QuietHours      = 7,
    SystemBusy      = 8
};

/**
 * @brief Day of week
 */
enum class DayOfWeek : uint8_t {
    Sunday          = 0,
    Monday          = 1,
    Tuesday         = 2,
    Wednesday       = 3,
    Thursday        = 4,
    Friday          = 5,
    Saturday        = 6
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Executing       = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Schedule definition
 */
struct ScheduleDefinition {
    /// @brief Schedule ID
    std::string scheduleId;
    
    /// @brief Schedule name
    std::string name;
    
    /// @brief Associated job ID
    std::string jobId;
    
    /// @brief Frequency
    ScheduleFrequency frequency = ScheduleFrequency::Daily;
    
    /// @brief Custom interval (for Custom frequency)
    std::chrono::minutes customInterval{0};
    
    /// @brief Cron expression (for Cron frequency)
    std::string cronExpression;
    
    /// @brief Time of day (hour, 0-23)
    int hourOfDay = 2;
    
    /// @brief Minute of hour (0-59)
    int minuteOfHour = 0;
    
    /// @brief Days of week (bitmask, Sunday = bit 0)
    uint8_t daysOfWeek = 0x7F;  // All days
    
    /// @brief Day of month (1-31, for monthly)
    int dayOfMonth = 1;
    
    /// @brief Priority
    BackupPriority priority = BackupPriority::Normal;
    
    /// @brief Status
    ScheduleStatus status = ScheduleStatus::Active;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Last run time
    SystemTimePoint lastRun;
    
    /// @brief Next run time
    SystemTimePoint nextRun;
    
    /// @brief Run count
    uint64_t runCount = 0;
    
    /// @brief Last result
    bool lastRunSuccess = true;
    
    [[nodiscard]] std::string ToJson() const;
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Trigger definition
 */
struct TriggerDefinition {
    /// @brief Trigger ID
    std::string triggerId;
    
    /// @brief Trigger type
    TriggerType type = TriggerType::Scheduled;
    
    /// @brief Associated job ID
    std::string jobId;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Conditions (key-value pairs)
    std::map<std::string, std::string> conditions;
    
    /// @brief Delay before execution (seconds)
    uint32_t delaySeconds = 0;
    
    /// @brief Run even if already backed up recently
    bool forceRun = false;
    
    /// @brief Last triggered
    SystemTimePoint lastTriggered;
    
    /// @brief Trigger count
    uint64_t triggerCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Throttle conditions
 */
struct ThrottleConditions {
    /// @brief Require AC power
    bool requireACPower = false;
    
    /// @brief Minimum battery level (%)
    int minBatteryLevel = SchedulerConstants::MIN_BATTERY_LEVEL;
    
    /// @brief Maximum CPU usage (%)
    int maxCPUUsage = SchedulerConstants::MAX_CPU_USAGE;
    
    /// @brief Require idle time (seconds)
    uint32_t requireIdleSeconds = 0;
    
    /// @brief Skip during game mode
    bool skipGameMode = true;
    
    /// @brief Skip during quiet hours
    bool skipQuietHours = true;
    
    /// @brief Quiet hours start (hour)
    int quietHoursStart = 22;
    
    /// @brief Quiet hours end (hour)
    int quietHoursEnd = 7;
    
    /// @brief Require network connection
    bool requireNetwork = false;
    
    /// @brief Skip metered network
    bool skipMeteredNetwork = true;
    
    /// @brief Allow wake from sleep
    bool allowWake = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Queued backup
 */
struct QueuedBackup {
    /// @brief Queue ID
    std::string queueId;
    
    /// @brief Job ID
    std::string jobId;
    
    /// @brief Schedule ID (if scheduled)
    std::string scheduleId;
    
    /// @brief Trigger ID (if triggered)
    std::string triggerId;
    
    /// @brief Priority
    BackupPriority priority = BackupPriority::Normal;
    
    /// @brief Queued time
    SystemTimePoint queuedTime;
    
    /// @brief Estimated start time
    SystemTimePoint estimatedStart;
    
    /// @brief Throttle reason (if waiting)
    ThrottleReason throttleReason = ThrottleReason::None;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System conditions
 */
struct SystemConditions {
    /// @brief Is on AC power
    bool onACPower = true;
    
    /// @brief Battery level (%)
    int batteryLevel = 100;
    
    /// @brief CPU usage (%)
    int cpuUsage = 0;
    
    /// @brief Memory usage (%)
    int memoryUsage = 0;
    
    /// @brief Is user idle
    bool isUserIdle = false;
    
    /// @brief Idle time (seconds)
    uint32_t idleTimeSeconds = 0;
    
    /// @brief Is game mode active
    bool isGameMode = false;
    
    /// @brief Is network available
    bool networkAvailable = true;
    
    /// @brief Is metered network
    bool isMeteredNetwork = false;
    
    /// @brief Is quiet hours
    bool isQuietHours = false;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SchedulerStatistics {
    std::atomic<uint64_t> scheduledRuns{0};
    std::atomic<uint64_t> triggeredRuns{0};
    std::atomic<uint64_t> manualRuns{0};
    std::atomic<uint64_t> throttledRuns{0};
    std::atomic<uint64_t> skippedRuns{0};
    std::atomic<uint64_t> failedRuns{0};
    std::atomic<uint64_t> successfulRuns{0};
    std::atomic<uint64_t> currentQueueSize{0};
    std::atomic<uint64_t> maxQueueSize{0};
    std::array<std::atomic<uint64_t>, 9> byThrottleReason{};
    std::atomic<TimePoint> startTime{Clock::now()};
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

struct SchedulerStatisticsSnapshot {
    uint64_t scheduledRuns;
    uint64_t triggeredRuns;
    uint64_t manualRuns;
    uint64_t throttledRuns;
    uint64_t skippedRuns;
    uint64_t failedRuns;
    uint64_t successfulRuns;
    uint64_t currentQueueSize;
    uint64_t maxQueueSize;
    std::array<uint64_t, 9> byThrottleReason;
    TimePoint startTime;
};

/**
 * @brief Configuration
 */
struct SchedulerConfiguration {
    /// @brief Enable scheduler
    bool enabled = true;
    
    /// @brief Default throttle conditions
    ThrottleConditions throttleConditions;
    
    /// @brief Check interval (seconds)
    uint32_t checkIntervalSeconds = SchedulerConstants::CHECK_INTERVAL_SECONDS;
    
    /// @brief Max queue size
    size_t maxQueueSize = SchedulerConstants::MAX_QUEUE_SIZE;
    
    /// @brief Allow parallel backups
    bool allowParallel = false;
    
    /// @brief Max parallel backups
    size_t maxParallel = 1;
    
    /// @brief Wake for scheduled backups
    bool wakeForBackups = false;
    
    /// @brief Send notifications
    bool sendNotifications = true;
    
    /// @brief Schedules
    std::vector<ScheduleDefinition> schedules;
    
    /// @brief Triggers
    std::vector<TriggerDefinition> triggers;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScheduleCallback = std::function<void(const ScheduleDefinition&)>;
using TriggerCallback = std::function<void(const TriggerDefinition&)>;
using QueueCallback = std::function<void(const QueuedBackup&)>;
using ThrottleCallback = std::function<void(ThrottleReason reason)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;
using DispatchCallback = std::function<bool(const std::string& jobId)>;

// ============================================================================
// BACKUP SCHEDULER CLASS
// ============================================================================

/**
 * @class BackupScheduler
 * @brief Enterprise backup scheduling
 */
class BackupScheduler final {
public:
    [[nodiscard]] static BackupScheduler& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    BackupScheduler(const BackupScheduler&) = delete;
    BackupScheduler& operator=(const BackupScheduler&) = delete;
    BackupScheduler(BackupScheduler&&) = delete;
    BackupScheduler& operator=(BackupScheduler&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SchedulerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const SchedulerConfiguration& config);
    [[nodiscard]] SchedulerConfiguration GetConfiguration() const;

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
    
    /// @brief Is scheduler running
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // SCHEDULE MANAGEMENT
    // ========================================================================
    
    /// @brief Add schedule
    [[nodiscard]] bool AddSchedule(const ScheduleDefinition& schedule);
    
    /// @brief Update schedule
    [[nodiscard]] bool UpdateSchedule(const ScheduleDefinition& schedule);
    
    /// @brief Remove schedule
    [[nodiscard]] bool RemoveSchedule(const std::string& scheduleId);
    
    /// @brief Enable/disable schedule
    [[nodiscard]] bool SetScheduleEnabled(const std::string& scheduleId, bool enabled);
    
    /// @brief Get schedule
    [[nodiscard]] std::optional<ScheduleDefinition> GetSchedule(const std::string& scheduleId);
    
    /// @brief Get all schedules
    [[nodiscard]] std::vector<ScheduleDefinition> GetSchedules() const;
    
    /// @brief Calculate next run time
    [[nodiscard]] SystemTimePoint CalculateNextRun(const ScheduleDefinition& schedule);

    // ========================================================================
    // TRIGGER MANAGEMENT
    // ========================================================================
    
    /// @brief Add trigger
    [[nodiscard]] bool AddTrigger(const TriggerDefinition& trigger);
    
    /// @brief Remove trigger
    [[nodiscard]] bool RemoveTrigger(const std::string& triggerId);
    
    /// @brief Get triggers
    [[nodiscard]] std::vector<TriggerDefinition> GetTriggers() const;
    
    /// @brief Fire trigger
    void FireTrigger(TriggerType type, const std::map<std::string, std::string>& context = {});

    // ========================================================================
    // INSTANT BACKUP
    // ========================================================================
    
    /// @brief Request instant backup
    void RequestInstantBackup();
    
    /// @brief Request instant backup of job
    void RequestInstantBackup(const std::string& jobId);
    
    /// @brief Request backup with priority
    void RequestBackup(const std::string& jobId, BackupPriority priority);

    // ========================================================================
    // QUEUE MANAGEMENT
    // ========================================================================
    
    /// @brief Get queue
    [[nodiscard]] std::vector<QueuedBackup> GetQueue() const;
    
    /// @brief Clear queue
    void ClearQueue();
    
    /// @brief Remove from queue
    [[nodiscard]] bool RemoveFromQueue(const std::string& queueId);
    
    /// @brief Change priority in queue
    [[nodiscard]] bool ChangePriority(const std::string& queueId, BackupPriority priority);

    // ========================================================================
    // SYSTEM CONDITIONS
    // ========================================================================
    
    /// @brief Get current system conditions
    [[nodiscard]] SystemConditions GetSystemConditions();
    
    /// @brief Check if conditions allow backup
    [[nodiscard]] std::pair<bool, ThrottleReason> CheckConditions(
        const ThrottleConditions& conditions);
    
    /// @brief Set throttle conditions
    void SetThrottleConditions(const ThrottleConditions& conditions);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScheduleCallback(ScheduleCallback callback);
    void RegisterTriggerCallback(TriggerCallback callback);
    void RegisterQueueCallback(QueueCallback callback);
    void RegisterThrottleCallback(ThrottleCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void RegisterDispatchCallback(DispatchCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SchedulerStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    BackupScheduler();
    ~BackupScheduler();
    
    std::unique_ptr<BackupSchedulerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetFrequencyName(ScheduleFrequency frequency) noexcept;
[[nodiscard]] std::string_view GetTriggerTypeName(TriggerType type) noexcept;
[[nodiscard]] std::string_view GetPriorityName(BackupPriority priority) noexcept;
[[nodiscard]] std::string_view GetScheduleStatusName(ScheduleStatus status) noexcept;
[[nodiscard]] std::string_view GetThrottleReasonName(ThrottleReason reason) noexcept;
[[nodiscard]] std::string_view GetDayOfWeekName(DayOfWeek day) noexcept;

/// @brief Parse cron expression
[[nodiscard]] bool ParseCronExpression(
    const std::string& expression,
    SystemTimePoint& nextRun);

/// @brief Check if time is in quiet hours
[[nodiscard]] bool IsInQuietHours(int currentHour, int startHour, int endHour);

}  // namespace Backup
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SCHEDULE_START() \
    ::ShadowStrike::Backup::BackupScheduler::Instance().Start()

#define SS_SCHEDULE_STOP() \
    ::ShadowStrike::Backup::BackupScheduler::Instance().Stop()

#define SS_SCHEDULE_INSTANT() \
    ::ShadowStrike::Backup::BackupScheduler::Instance().RequestInstantBackup()

#define SS_SCHEDULE_ADD(schedule) \
    ::ShadowStrike::Backup::BackupScheduler::Instance().AddSchedule(schedule)
