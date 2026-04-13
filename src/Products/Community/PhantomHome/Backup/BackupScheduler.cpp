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
 * ShadowStrike NGAV - BACKUP SCHEDULER MODULE IMPLEMENTATION
 * ============================================================================
 *
 * @file BackupScheduler.cpp
 * @brief Implementation of the enterprise backup scheduling engine.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "BackupScheduler.hpp"

// ============================================================================
// STANDARD LIBRARY
// ============================================================================
#include <thread>
#include <vector>
#include <map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <charconv>
#include <ctime>

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <powerbase.h>
#include <shellapi.h>

namespace ShadowStrike {
namespace Backup {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"BackupScheduler";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> BackupScheduler::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
namespace {
    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            switch (c) {
                case '"': o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b"; break;
                case '\f': o << "\\f"; break;
                case '\n': o << "\\n"; break;
                case '\r': o << "\\r"; break;
                case '\t': o << "\\t"; break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4)
                          << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    SystemTimePoint Now() {
        return std::chrono::system_clock::now();
    }

    uint64_t TimeToJson(const SystemTimePoint& time) {
        return std::chrono::duration_cast<std::chrono::seconds>(
            time.time_since_epoch()).count();
    }

    /// Atomic counter to guarantee unique queue IDs even under contention
    std::atomic<uint64_t> g_queueIdCounter{0};

    std::string GenerateQueueId() {
        auto ts = Clock::now().time_since_epoch().count();
        auto seq = g_queueIdCounter.fetch_add(1, std::memory_order_relaxed);
        std::ostringstream oss;
        oss << std::hex << ts << "-" << seq;
        return oss.str();
    }
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string ScheduleDefinition::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"scheduleId\":\"" << EscapeJson(scheduleId) << "\","
        << "\"name\":\"" << EscapeJson(name) << "\","
        << "\"jobId\":\"" << EscapeJson(jobId) << "\","
        << "\"frequency\":" << static_cast<int>(frequency) << ","
        << "\"enabled\":" << (enabled ? "true" : "false") << ","
        << "\"priority\":" << static_cast<int>(priority) << ","
        << "\"runCount\":" << runCount << ","
        << "\"lastRun\":" << TimeToJson(lastRun) << ","
        << "\"nextRun\":" << TimeToJson(nextRun)
        << "}";
    return oss.str();
}

bool ScheduleDefinition::IsValid() const noexcept {
    if (scheduleId.empty()) return false;
    if (jobId.empty()) return false;
    if (hourOfDay < 0 || hourOfDay > 23) return false;
    if (minuteOfHour < 0 || minuteOfHour > 59) return false;
    if (dayOfMonth < 1 || dayOfMonth > 31) return false;
    if (frequency == ScheduleFrequency::Custom && customInterval.count() <= 0)
        return false;
    if (frequency == ScheduleFrequency::Cron && cronExpression.empty())
        return false;
    return true;
}

std::string TriggerDefinition::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"triggerId\":\"" << EscapeJson(triggerId) << "\","
        << "\"type\":" << static_cast<int>(type) << ","
        << "\"jobId\":\"" << EscapeJson(jobId) << "\","
        << "\"enabled\":" << (enabled ? "true" : "false") << ","
        << "\"triggerCount\":" << triggerCount
        << "}";
    return oss.str();
}

bool ThrottleConditions::IsValid() const noexcept {
    if (minBatteryLevel < 0 || minBatteryLevel > 100) return false;
    if (maxCPUUsage < 0 || maxCPUUsage > 100) return false;
    if (quietHoursStart < 0 || quietHoursStart > 23) return false;
    if (quietHoursEnd < 0 || quietHoursEnd > 23) return false;
    return true;
}

std::string QueuedBackup::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"queueId\":\"" << EscapeJson(queueId) << "\","
        << "\"jobId\":\"" << EscapeJson(jobId) << "\","
        << "\"priority\":" << static_cast<int>(priority) << ","
        << "\"queuedTime\":" << TimeToJson(queuedTime) << ","
        << "\"estimatedStart\":" << TimeToJson(estimatedStart)
        << "}";
    return oss.str();
}

std::string SystemConditions::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"onACPower\":" << (onACPower ? "true" : "false") << ","
        << "\"batteryLevel\":" << batteryLevel << ","
        << "\"cpuUsage\":" << cpuUsage << ","
        << "\"memoryUsage\":" << memoryUsage << ","
        << "\"isUserIdle\":" << (isUserIdle ? "true" : "false") << ","
        << "\"idleTimeSeconds\":" << idleTimeSeconds << ","
        << "\"isGameMode\":" << (isGameMode ? "true" : "false") << ","
        << "\"networkAvailable\":" << (networkAvailable ? "true" : "false") << ","
        << "\"isMeteredNetwork\":" << (isMeteredNetwork ? "true" : "false") << ","
        << "\"isQuietHours\":" << (isQuietHours ? "true" : "false") << ","
        << "\"timestamp\":" << TimeToJson(timestamp)
        << "}";
    return oss.str();
}

void SchedulerStatistics::Reset() noexcept {
    scheduledRuns.store(0, std::memory_order_relaxed);
    triggeredRuns.store(0, std::memory_order_relaxed);
    manualRuns.store(0, std::memory_order_relaxed);
    throttledRuns.store(0, std::memory_order_relaxed);
    skippedRuns.store(0, std::memory_order_relaxed);
    failedRuns.store(0, std::memory_order_relaxed);
    successfulRuns.store(0, std::memory_order_relaxed);
    currentQueueSize.store(0, std::memory_order_relaxed);
    maxQueueSize.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
    for (auto& v : byThrottleReason) v.store(0, std::memory_order_relaxed);
}

std::string SchedulerStatistics::ToJson() const {
    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    std::ostringstream oss;
    oss << "{"
        << "\"scheduledRuns\":" << scheduledRuns.load(std::memory_order_relaxed) << ","
        << "\"triggeredRuns\":" << triggeredRuns.load(std::memory_order_relaxed) << ","
        << "\"manualRuns\":" << manualRuns.load(std::memory_order_relaxed) << ","
        << "\"throttledRuns\":" << throttledRuns.load(std::memory_order_relaxed) << ","
        << "\"skippedRuns\":" << skippedRuns.load(std::memory_order_relaxed) << ","
        << "\"failedRuns\":" << failedRuns.load(std::memory_order_relaxed) << ","
        << "\"successfulRuns\":" << successfulRuns.load(std::memory_order_relaxed) << ","
        << "\"currentQueueSize\":" << currentQueueSize.load(std::memory_order_relaxed) << ","
        << "\"maxQueueSize\":" << maxQueueSize.load(std::memory_order_relaxed) << ","
        << "\"uptimeSeconds\":" << uptime
        << "}";
    return oss.str();
}

bool SchedulerConfiguration::IsValid() const noexcept {
    if (!throttleConditions.IsValid()) return false;
    if (checkIntervalSeconds == 0) return false;
    if (maxQueueSize == 0) return false;
    return true;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class BackupSchedulerImpl {
public:
    BackupSchedulerImpl() = default;
    ~BackupSchedulerImpl() { Shutdown(); }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize(const SchedulerConfiguration& config) {
        std::unique_lock lock(m_mutex);
        auto status = m_status.load(std::memory_order_acquire);
        if (status != ModuleStatus::Uninitialized && status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized (status=%u)",
                static_cast<unsigned>(status));
            return true;
        }

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid scheduler configuration");
            return false;
        }

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);
        m_config = config;
        m_stats.Reset();

        InitializeCpuBaseline();

        m_status.store(ModuleStatus::Running, std::memory_order_release);
        m_running.store(true, std::memory_order_release);

        if (m_config.enabled) {
            m_thread = std::thread(&BackupSchedulerImpl::SchedulerLoop, this);
        }

        SS_LOG_INFO(LOG_CATEGORY,
            L"Initialized: %zu schedules, %zu triggers, interval=%us",
            m_config.schedules.size(), m_config.triggers.size(),
            m_config.checkIntervalSeconds);
        return true;
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running.load(std::memory_order_acquire)) return;
            SS_LOG_INFO(LOG_CATEGORY, L"Shutting down scheduler");
            m_running.store(false, std::memory_order_release);
            m_status.store(ModuleStatus::Stopping, std::memory_order_release);
            m_cv.notify_all();
        }
        if (m_thread.joinable()) {
            m_thread.join();
        }
        {
            std::unique_lock lock(m_mutex);
            m_status.store(ModuleStatus::Stopped, std::memory_order_release);
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Shutdown complete");
    }

    bool IsInitialized() const noexcept {
        return m_status.load(std::memory_order_acquire) != ModuleStatus::Uninitialized;
    }

    ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    bool UpdateConfiguration(const SchedulerConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"UpdateConfiguration: invalid config");
            return false;
        }
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    SchedulerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // CONTROL
    // ========================================================================

    void Start() {
        std::unique_lock lock(m_mutex);
        if (m_running.load(std::memory_order_relaxed)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Scheduler already running");
            return;
        }
        if (m_status.load(std::memory_order_relaxed) == ModuleStatus::Uninitialized) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot start: not initialized");
            return;
        }
        m_running.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);
        m_thread = std::thread(&BackupSchedulerImpl::SchedulerLoop, this);
        SS_LOG_INFO(LOG_CATEGORY, L"Scheduler started");
    }

    void Stop() {
        Shutdown();
    }

    void Pause() {
        std::unique_lock lock(m_mutex);
        if (m_status.load(std::memory_order_relaxed) == ModuleStatus::Running) {
            m_status.store(ModuleStatus::Paused, std::memory_order_release);
            SS_LOG_INFO(LOG_CATEGORY, L"Scheduler paused");
        }
    }

    void Resume() {
        std::unique_lock lock(m_mutex);
        if (m_status.load(std::memory_order_relaxed) == ModuleStatus::Paused) {
            m_status.store(ModuleStatus::Running, std::memory_order_release);
            m_cv.notify_one();
            SS_LOG_INFO(LOG_CATEGORY, L"Scheduler resumed");
        }
    }

    bool IsRunning() const noexcept {
        return m_status.load(std::memory_order_acquire) == ModuleStatus::Running;
    }

    // ========================================================================
    // SCHEDULE MANAGEMENT
    // ========================================================================

    bool AddSchedule(const ScheduleDefinition& schedule) {
        if (!schedule.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AddSchedule: invalid schedule (id=%hs)",
                schedule.scheduleId.c_str());
            return false;
        }

        ScheduleCallback cb;
        ScheduleDefinition added;
        {
            std::unique_lock lock(m_mutex);
            auto it = std::find_if(m_config.schedules.begin(), m_config.schedules.end(),
                [&](const ScheduleDefinition& s) {
                    return s.scheduleId == schedule.scheduleId;
                });
            if (it != m_config.schedules.end()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Schedule %hs already exists",
                    schedule.scheduleId.c_str());
                return false;
            }

            added = schedule;
            if (added.nextRun.time_since_epoch().count() == 0) {
                added.nextRun = CalculateNextRunInternal(added);
            }
            m_config.schedules.push_back(added);
            cb = m_scheduleCallback;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Added schedule %hs for job %hs (%hs)",
            schedule.scheduleId.c_str(), schedule.jobId.c_str(),
            std::string(GetFrequencyName(schedule.frequency)).c_str());

        if (cb) cb(added);
        return true;
    }

    bool UpdateSchedule(const ScheduleDefinition& schedule) {
        if (!schedule.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"UpdateSchedule: invalid schedule (id=%hs)",
                schedule.scheduleId.c_str());
            return false;
        }

        std::unique_lock lock(m_mutex);
        auto it = std::find_if(m_config.schedules.begin(), m_config.schedules.end(),
            [&](const ScheduleDefinition& s) {
                return s.scheduleId == schedule.scheduleId;
            });
        if (it == m_config.schedules.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"UpdateSchedule: %hs not found",
                schedule.scheduleId.c_str());
            return false;
        }

        *it = schedule;
        if (it->nextRun.time_since_epoch().count() == 0) {
            it->nextRun = CalculateNextRunInternal(*it);
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Updated schedule %hs", schedule.scheduleId.c_str());
        return true;
    }

    bool RemoveSchedule(const std::string& scheduleId) {
        std::unique_lock lock(m_mutex);
        auto it = std::remove_if(m_config.schedules.begin(), m_config.schedules.end(),
            [&](const ScheduleDefinition& s) { return s.scheduleId == scheduleId; });
        if (it == m_config.schedules.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"RemoveSchedule: %hs not found",
                scheduleId.c_str());
            return false;
        }
        m_config.schedules.erase(it, m_config.schedules.end());
        SS_LOG_INFO(LOG_CATEGORY, L"Removed schedule %hs", scheduleId.c_str());
        return true;
    }

    bool SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
        std::unique_lock lock(m_mutex);
        for (auto& s : m_config.schedules) {
            if (s.scheduleId == scheduleId) {
                s.enabled = enabled;
                SS_LOG_INFO(LOG_CATEGORY, L"Schedule %hs %ls",
                    scheduleId.c_str(), enabled ? L"enabled" : L"disabled");
                return true;
            }
        }
        SS_LOG_WARN(LOG_CATEGORY, L"SetScheduleEnabled: %hs not found",
            scheduleId.c_str());
        return false;
    }

    std::optional<ScheduleDefinition> GetSchedule(const std::string& scheduleId) {
        std::shared_lock lock(m_mutex);
        for (const auto& s : m_config.schedules) {
            if (s.scheduleId == scheduleId) return s;
        }
        return std::nullopt;
    }

    std::vector<ScheduleDefinition> GetSchedules() const {
        std::shared_lock lock(m_mutex);
        return m_config.schedules;
    }

    // ========================================================================
    // TRIGGER MANAGEMENT
    // ========================================================================

    bool AddTrigger(const TriggerDefinition& trigger) {
        if (trigger.triggerId.empty() || trigger.jobId.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"AddTrigger: invalid trigger definition");
            return false;
        }

        TriggerCallback cb;
        {
            std::unique_lock lock(m_mutex);
            auto it = std::find_if(m_config.triggers.begin(), m_config.triggers.end(),
                [&](const TriggerDefinition& t) {
                    return t.triggerId == trigger.triggerId;
                });
            if (it != m_config.triggers.end()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Trigger %hs already exists",
                    trigger.triggerId.c_str());
                return false;
            }
            m_config.triggers.push_back(trigger);
            cb = m_triggerCallback;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Added trigger %hs (%hs) for job %hs",
            trigger.triggerId.c_str(),
            std::string(GetTriggerTypeName(trigger.type)).c_str(),
            trigger.jobId.c_str());

        if (cb) cb(trigger);
        return true;
    }

    bool RemoveTrigger(const std::string& triggerId) {
        std::unique_lock lock(m_mutex);
        auto it = std::remove_if(m_config.triggers.begin(), m_config.triggers.end(),
            [&](const TriggerDefinition& t) { return t.triggerId == triggerId; });
        if (it == m_config.triggers.end()) {
            SS_LOG_WARN(LOG_CATEGORY, L"RemoveTrigger: %hs not found",
                triggerId.c_str());
            return false;
        }
        m_config.triggers.erase(it, m_config.triggers.end());
        SS_LOG_INFO(LOG_CATEGORY, L"Removed trigger %hs", triggerId.c_str());
        return true;
    }

    std::vector<TriggerDefinition> GetTriggers() const {
        std::shared_lock lock(m_mutex);
        return m_config.triggers;
    }

    void FireTrigger(TriggerType type, const std::map<std::string, std::string>& context) {
        std::vector<QueuedBackup> newItems;
        QueueCallback queueCb;
        {
            std::unique_lock lock(m_mutex);
            for (auto& t : m_config.triggers) {
                if (!t.enabled || t.type != type) continue;

                if (m_queue.size() >= m_config.maxQueueSize) {
                    m_stats.skippedRuns.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Queue full (%zu), skipping trigger %hs",
                        m_queue.size(), t.triggerId.c_str());
                    continue;
                }

                t.triggerCount++;
                t.lastTriggered = Now();

                QueuedBackup q{};
                q.queueId = GenerateQueueId();
                q.jobId = t.jobId;
                q.triggerId = t.triggerId;
                q.queuedTime = Now();
                q.estimatedStart = q.queuedTime;
                q.priority = BackupPriority::Normal;

                m_queue.push_back(q);
                newItems.push_back(q);
                m_stats.triggeredRuns.fetch_add(1, std::memory_order_relaxed);
                m_stats.currentQueueSize.store(m_queue.size(),
                    std::memory_order_relaxed);
                UpdateMaxQueueSize();
            }
            queueCb = m_queueCallback;
        }

        // Invoke callbacks outside the lock to prevent deadlock
        for (const auto& q : newItems) {
            SS_LOG_INFO(LOG_CATEGORY,
                L"Trigger %hs fired, queued job %hs (qid=%hs)",
                std::string(GetTriggerTypeName(type)).c_str(),
                q.jobId.c_str(), q.queueId.c_str());
            if (queueCb) queueCb(q);
        }
        m_cv.notify_one();
    }

    // ========================================================================
    // INSTANT/QUEUE
    // ========================================================================

    void RequestInstantBackup(const std::string& jobId) {
        QueueCallback queueCb;
        QueuedBackup q{};
        {
            std::unique_lock lock(m_mutex);
            if (m_queue.size() >= m_config.maxQueueSize) {
                SS_LOG_ERROR(LOG_CATEGORY,
                    L"Queue full (%zu), cannot add instant backup for %hs",
                    m_queue.size(), jobId.c_str());
                return;
            }
            q.queueId = GenerateQueueId();
            q.jobId = jobId;
            q.priority = BackupPriority::Critical;
            q.queuedTime = Now();
            q.estimatedStart = q.queuedTime;

            m_queue.push_back(q);
            m_stats.manualRuns.fetch_add(1, std::memory_order_relaxed);
            m_stats.currentQueueSize.store(m_queue.size(),
                std::memory_order_relaxed);
            UpdateMaxQueueSize();
            queueCb = m_queueCallback;
        }

        SS_LOG_INFO(LOG_CATEGORY,
            L"Instant backup requested for job %hs (qid=%hs)",
            jobId.c_str(), q.queueId.c_str());
        if (queueCb) queueCb(q);
        m_cv.notify_one();
    }

    void RequestBackup(const std::string& jobId, BackupPriority priority) {
        QueueCallback queueCb;
        QueuedBackup q{};
        {
            std::unique_lock lock(m_mutex);
            if (m_queue.size() >= m_config.maxQueueSize) {
                SS_LOG_WARN(LOG_CATEGORY,
                    L"Queue full (%zu), rejecting backup request for %hs",
                    m_queue.size(), jobId.c_str());
                return;
            }
            q.queueId = GenerateQueueId();
            q.jobId = jobId;
            q.priority = priority;
            q.queuedTime = Now();
            q.estimatedStart = q.queuedTime;

            m_queue.push_back(q);
            m_stats.currentQueueSize.store(m_queue.size(),
                std::memory_order_relaxed);
            UpdateMaxQueueSize();
            queueCb = m_queueCallback;
        }

        SS_LOG_INFO(LOG_CATEGORY,
            L"Backup requested: job=%hs priority=%hs qid=%hs",
            jobId.c_str(),
            std::string(GetPriorityName(priority)).c_str(),
            q.queueId.c_str());
        if (queueCb) queueCb(q);
        m_cv.notify_one();
    }

    std::vector<QueuedBackup> GetQueue() const {
        std::shared_lock lock(m_mutex);
        return m_queue;
    }

    void ClearQueue() {
        std::unique_lock lock(m_mutex);
        auto count = m_queue.size();
        m_queue.clear();
        m_stats.currentQueueSize.store(0, std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CATEGORY, L"Queue cleared (%zu items removed)", count);
    }

    bool RemoveFromQueue(const std::string& queueId) {
        std::unique_lock lock(m_mutex);
        auto it = std::remove_if(m_queue.begin(), m_queue.end(),
            [&](const QueuedBackup& q) { return q.queueId == queueId; });
        if (it == m_queue.end()) return false;
        m_queue.erase(it, m_queue.end());
        m_stats.currentQueueSize.store(m_queue.size(), std::memory_order_relaxed);
        SS_LOG_INFO(LOG_CATEGORY, L"Removed queue item %hs", queueId.c_str());
        return true;
    }

    bool ChangePriority(const std::string& queueId, BackupPriority priority) {
        std::unique_lock lock(m_mutex);
        for (auto& q : m_queue) {
            if (q.queueId == queueId) {
                auto oldPri = q.priority;
                q.priority = priority;
                SS_LOG_INFO(LOG_CATEGORY,
                    L"Changed priority of %hs: %hs -> %hs",
                    queueId.c_str(),
                    std::string(GetPriorityName(oldPri)).c_str(),
                    std::string(GetPriorityName(priority)).c_str());
                return true;
            }
        }
        return false;
    }

    // ========================================================================
    // SYSTEM CONDITIONS
    // ========================================================================

    SystemConditions GetSystemConditions() {
        SystemConditions cond{};
        cond.timestamp = Now();

        // Power status
        SYSTEM_POWER_STATUS powerStatus{};
        if (GetSystemPowerStatus(&powerStatus)) {
            cond.onACPower = (powerStatus.ACLineStatus == 1);
            // BatteryLifePercent is 255 when unknown (e.g. desktop without battery)
            cond.batteryLevel = (powerStatus.BatteryLifePercent <= 100)
                ? powerStatus.BatteryLifePercent : 100;
        }

        // CPU usage via GetSystemTimes delta
        cond.cpuUsage = MeasureCpuUsage();

        // Memory usage
        MEMORYSTATUSEX memStatus{};
        memStatus.dwLength = sizeof(memStatus);
        if (GlobalMemoryStatusEx(&memStatus)) {
            cond.memoryUsage = static_cast<int>(memStatus.dwMemoryLoad);
        }

        // User idle time using DWORD subtraction (handles 49.7-day wrap correctly)
        LASTINPUTINFO lii{};
        lii.cbSize = sizeof(LASTINPUTINFO);
        if (GetLastInputInfo(&lii)) {
            DWORD currentTick = static_cast<DWORD>(GetTickCount64() & 0xFFFFFFFF);
            DWORD idleMillis = currentTick - lii.dwTime;
            cond.idleTimeSeconds = idleMillis / 1000;
            cond.isUserIdle =
                (cond.idleTimeSeconds >= SchedulerConstants::IDLE_THRESHOLD_SECONDS);
        }

        // Quiet hours detection
        time_t t = std::chrono::system_clock::to_time_t(cond.timestamp);
        tm localTm{};
        localtime_s(&localTm, &t);
        {
            std::shared_lock lock(m_mutex);
            cond.isQuietHours = IsInQuietHours(
                localTm.tm_hour,
                m_config.throttleConditions.quietHoursStart,
                m_config.throttleConditions.quietHoursEnd);
        }

        // Network: default available. Full implementation would use
        // INetworkListManager COM interface for metered network detection.
        cond.networkAvailable = true;
        cond.isMeteredNetwork = false;

        // Game mode: check via user notification state as a proxy.
        // QUERY_USER_NOTIFICATION_STATE reflects presentation/game mode.
        cond.isGameMode = false;
        QUERY_USER_NOTIFICATION_STATE quns = QUNS_ACCEPTS_NOTIFICATIONS;
        if (SUCCEEDED(SHQueryUserNotificationState(&quns))) {
            cond.isGameMode = (quns == QUNS_RUNNING_D3D_FULL_SCREEN ||
                               quns == QUNS_BUSY);
        }

        return cond;
    }

    std::pair<bool, ThrottleReason> CheckConditions(
            const ThrottleConditions& conditions) {
        auto sys = GetSystemConditions();
        return EvaluateConditions(conditions, sys);
    }

    void SetThrottleConditions(const ThrottleConditions& conditions) {
        std::unique_lock lock(m_mutex);
        if (!conditions.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"SetThrottleConditions: invalid conditions");
            return;
        }
        m_config.throttleConditions = conditions;
        SS_LOG_INFO(LOG_CATEGORY, L"Throttle conditions updated");
    }

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    void RegisterScheduleCallback(ScheduleCallback cb) {
        std::unique_lock lock(m_mutex); m_scheduleCallback = std::move(cb);
    }
    void RegisterTriggerCallback(TriggerCallback cb) {
        std::unique_lock lock(m_mutex); m_triggerCallback = std::move(cb);
    }
    void RegisterQueueCallback(QueueCallback cb) {
        std::unique_lock lock(m_mutex); m_queueCallback = std::move(cb);
    }
    void RegisterThrottleCallback(ThrottleCallback cb) {
        std::unique_lock lock(m_mutex); m_throttleCallback = std::move(cb);
    }
    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_mutex); m_errorCallback = std::move(cb);
    }
    void RegisterDispatchCallback(DispatchCallback cb) {
        std::unique_lock lock(m_mutex); m_dispatchCallback = std::move(cb);
    }

    void UnregisterCallbacks() {
        std::unique_lock lock(m_mutex);
        m_scheduleCallback = nullptr;
        m_triggerCallback = nullptr;
        m_queueCallback = nullptr;
        m_throttleCallback = nullptr;
        m_errorCallback = nullptr;
        m_dispatchCallback = nullptr;
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    SchedulerStatisticsSnapshot GetStatistics() const {
        SchedulerStatisticsSnapshot snapshot;
        snapshot.scheduledRuns = m_stats.scheduledRuns.load(std::memory_order_relaxed);
        snapshot.triggeredRuns = m_stats.triggeredRuns.load(std::memory_order_relaxed);
        snapshot.manualRuns = m_stats.manualRuns.load(std::memory_order_relaxed);
        snapshot.throttledRuns = m_stats.throttledRuns.load(std::memory_order_relaxed);
        snapshot.skippedRuns = m_stats.skippedRuns.load(std::memory_order_relaxed);
        snapshot.failedRuns = m_stats.failedRuns.load(std::memory_order_relaxed);
        snapshot.successfulRuns = m_stats.successfulRuns.load(std::memory_order_relaxed);
        snapshot.currentQueueSize = m_stats.currentQueueSize.load(std::memory_order_relaxed);
        snapshot.maxQueueSize = m_stats.maxQueueSize.load(std::memory_order_relaxed);
        for (size_t i = 0; i < m_stats.byThrottleReason.size(); ++i) {
            snapshot.byThrottleReason[i] =
                m_stats.byThrottleReason[i].load(std::memory_order_relaxed);
        }
        snapshot.startTime = m_stats.startTime;
        return snapshot;
    }

    void ResetStatistics() {
        m_stats.Reset();
        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

        if (!IsInitialized()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: not initialized");
            return false;
        }

        // Verify system condition readout
        auto conditions = GetSystemConditions();
        if (conditions.batteryLevel < 0 || conditions.batteryLevel > 100) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Self-test failed: invalid battery level %d",
                conditions.batteryLevel);
            return false;
        }

        // Test schedule round-trip
        ScheduleDefinition testSched;
        testSched.scheduleId = "__selftest_sched__";
        testSched.jobId = "__selftest_job__";
        testSched.frequency = ScheduleFrequency::Daily;
        testSched.hourOfDay = 3;
        testSched.minuteOfHour = 0;

        if (!AddSchedule(testSched)) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Self-test failed: could not add test schedule");
            return false;
        }
        auto retrieved = GetSchedule("__selftest_sched__");
        if (!retrieved.has_value()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Self-test failed: could not retrieve test schedule");
            RemoveSchedule("__selftest_sched__");
            return false;
        }
        if (!RemoveSchedule("__selftest_sched__")) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Self-test failed: could not remove test schedule");
            return false;
        }

        // Verify next-run calculation produces future time
        auto nextRun = CalculateNextRunInternal(testSched);
        if (nextRun <= Now()) {
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Self-test failed: calculated next run is in the past");
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Self-test passed");
        return true;
    }

    // ========================================================================
    // SCHEDULER LOOP
    // ========================================================================

    void SchedulerLoop() {
        SS_LOG_INFO(LOG_CATEGORY, L"Scheduler loop started");

        while (m_running.load(std::memory_order_acquire)) {
            // 1. Read system conditions OUTSIDE the lock (Win32 I/O calls)
            auto sysConditions = GetSystemConditions();

            // 2. Under lock: evaluate schedules and determine dispatches
            std::vector<QueuedBackup> newlyQueued;
            std::vector<QueuedBackup> toDispatch;
            ThrottleReason throttleReason = ThrottleReason::None;
            QueueCallback queueCb;
            ThrottleCallback throttleCb;
            DispatchCallback dispatchCb;
            ErrorCallback errorCb;

            {
                std::unique_lock lock(m_mutex);
                if (m_status.load(std::memory_order_relaxed) == ModuleStatus::Running) {
                    ProcessSchedulesLocked(newlyQueued);
                    ProcessQueueLocked(sysConditions, toDispatch, throttleReason);
                }
                queueCb = m_queueCallback;
                throttleCb = m_throttleCallback;
                dispatchCb = m_dispatchCallback;
                errorCb = m_errorCallback;
            }

            // 3. Invoke callbacks OUTSIDE the lock to prevent deadlock
            for (const auto& q : newlyQueued) {
                if (queueCb) queueCb(q);
            }
            if (throttleReason != ThrottleReason::None && throttleCb) {
                throttleCb(throttleReason);
                m_stats.byThrottleReason[static_cast<size_t>(throttleReason)]
                    .fetch_add(1, std::memory_order_relaxed);
            }
            for (const auto& q : toDispatch) {
                if (dispatchCb) {
                    SS_LOG_INFO(LOG_CATEGORY,
                        L"Dispatching job %hs (qid=%hs, priority=%u)",
                        q.jobId.c_str(), q.queueId.c_str(),
                        static_cast<unsigned>(q.priority));
                    bool ok = dispatchCb(q.jobId);
                    if (ok) {
                        m_stats.successfulRuns.fetch_add(1,
                            std::memory_order_relaxed);
                    } else {
                        m_stats.failedRuns.fetch_add(1,
                            std::memory_order_relaxed);
                        SS_LOG_ERROR(LOG_CATEGORY,
                            L"Dispatch failed for job %hs", q.jobId.c_str());
                        if (errorCb) {
                            errorCb("Backup dispatch failed: " + q.jobId, -1);
                        }
                    }
                } else {
                    m_stats.skippedRuns.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"No dispatch callback, skipping job %hs",
                        q.jobId.c_str());
                }
            }

            // 4. Wait for next check interval or shutdown signal
            {
                std::unique_lock lock(m_mutex);
                auto interval =
                    std::chrono::seconds(m_config.checkIntervalSeconds);
                m_cv.wait_for(lock, interval, [this] {
                    return !m_running.load(std::memory_order_acquire);
                });
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Scheduler loop exiting");
    }

    // ========================================================================
    // NEXT-RUN CALCULATION
    // ========================================================================

    SystemTimePoint CalculateNextRunInternal(const ScheduleDefinition& schedule) {
        auto now = std::chrono::system_clock::now();

        // One-time schedules never recur after first run
        if (schedule.frequency == ScheduleFrequency::Once) {
            if (schedule.runCount > 0) {
                return SystemTimePoint::max();
            }
            // If never run, return the configured time or now
            if (schedule.nextRun.time_since_epoch().count() != 0 &&
                schedule.nextRun > now) {
                return schedule.nextRun;
            }
            return now;
        }

        // Cron expressions
        if (schedule.frequency == ScheduleFrequency::Cron) {
            SystemTimePoint cronNext{};
            if (ParseCronExpression(schedule.cronExpression, cronNext)) {
                return cronNext;
            }
            SS_LOG_ERROR(LOG_CATEGORY,
                L"Failed to parse cron expression for schedule %hs: %hs",
                schedule.scheduleId.c_str(), schedule.cronExpression.c_str());
            return now + std::chrono::hours(24);
        }

        // Custom interval
        if (schedule.frequency == ScheduleFrequency::Custom) {
            if (schedule.customInterval.count() <= 0) {
                return now + std::chrono::hours(24);
            }
            auto next = schedule.lastRun + schedule.customInterval;
            if (next <= now) next = now + schedule.customInterval;
            return next;
        }

        // Time-of-day based schedules (Hourly, Daily, Weekly, Monthly)
        time_t tNow = std::chrono::system_clock::to_time_t(now);
        tm tmNow{};
        localtime_s(&tmNow, &tNow);

        tm tmNext = tmNow;
        tmNext.tm_sec = 0;
        tmNext.tm_min = schedule.minuteOfHour;
        tmNext.tm_hour = schedule.hourOfDay;
        tmNext.tm_isdst = -1;

        auto nextTime = std::chrono::system_clock::from_time_t(std::mktime(&tmNext));
        bool isPast = (nextTime <= now);

        switch (schedule.frequency) {
            case ScheduleFrequency::Hourly: {
                // Reset to current hour + scheduled minute
                tmNext = tmNow;
                tmNext.tm_sec = 0;
                tmNext.tm_min = schedule.minuteOfHour;
                tmNext.tm_isdst = -1;
                nextTime = std::chrono::system_clock::from_time_t(
                    std::mktime(&tmNext));
                while (nextTime <= now) {
                    nextTime += std::chrono::hours(1);
                }
                break;
            }

            case ScheduleFrequency::Daily: {
                if (isPast) nextTime += std::chrono::hours(24);
                break;
            }

            case ScheduleFrequency::Weekly: {
                // Guard against daysOfWeek==0 which would be an infinite loop
                if (schedule.daysOfWeek == 0) {
                    SS_LOG_ERROR(LOG_CATEGORY,
                        L"Weekly schedule %hs has no days selected",
                        schedule.scheduleId.c_str());
                    return now + std::chrono::hours(24 * 7);
                }
                constexpr int kMaxDaysSearch = 8;
                for (int i = 0; i < kMaxDaysSearch; ++i) {
                    if (isPast || i > 0) {
                        nextTime += std::chrono::hours(24);
                    }
                    time_t tNext =
                        std::chrono::system_clock::to_time_t(nextTime);
                    tm tmCheck{};
                    localtime_s(&tmCheck, &tNext);
                    if ((1 << tmCheck.tm_wday) & schedule.daysOfWeek) {
                        break;
                    }
                }
                break;
            }

            case ScheduleFrequency::Monthly: {
                // Robust monthly scheduling with proper day-of-month clamping
                for (int attempt = 0; attempt < 14; ++attempt) {
                    tm trial = tmNext;
                    trial.tm_mday = schedule.dayOfMonth;
                    trial.tm_sec = 0;
                    trial.tm_isdst = -1;

                    int wantMonth = trial.tm_mon;
                    int wantYear = trial.tm_year;
                    time_t trialTime = std::mktime(&trial);

                    // mktime may shift month if dayOfMonth overflows
                    // (e.g. Feb 30 -> Mar 2). Clamp to last day of target month.
                    if (trial.tm_mon != wantMonth || trial.tm_year != wantYear) {
                        tm lastDay{};
                        lastDay.tm_year = wantYear;
                        lastDay.tm_mon = wantMonth + 1;
                        lastDay.tm_mday = 0; // mktime: day 0 = last day of prev month
                        lastDay.tm_hour = schedule.hourOfDay;
                        lastDay.tm_min = schedule.minuteOfHour;
                        lastDay.tm_sec = 0;
                        lastDay.tm_isdst = -1;
                        trialTime = std::mktime(&lastDay);
                        trial = lastDay;
                    }

                    auto candidate =
                        std::chrono::system_clock::from_time_t(trialTime);
                    if (candidate > now) {
                        nextTime = candidate;
                        break;
                    }

                    // Advance to next month
                    tmNext.tm_mon++;
                    tmNext.tm_mday = 1;
                    tmNext.tm_hour = schedule.hourOfDay;
                    tmNext.tm_min = schedule.minuteOfHour;
                    tmNext.tm_sec = 0;
                    tmNext.tm_isdst = -1;
                    std::mktime(&tmNext); // normalize year rollover
                }
                break;
            }

            default:
                if (isPast) nextTime += std::chrono::hours(24);
                break;
        }

        return nextTime;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    /// Evaluate throttle conditions against pre-read system state (no I/O)
    static std::pair<bool, ThrottleReason> EvaluateConditions(
            const ThrottleConditions& conditions,
            const SystemConditions& sys) {

        if (conditions.requireACPower && !sys.onACPower)
            return {false, ThrottleReason::LowBattery};

        if (!sys.onACPower && sys.batteryLevel < conditions.minBatteryLevel)
            return {false, ThrottleReason::LowBattery};

        if (sys.cpuUsage > conditions.maxCPUUsage)
            return {false, ThrottleReason::HighCPU};

        if (conditions.skipGameMode && sys.isGameMode)
            return {false, ThrottleReason::GameMode};

        if (conditions.requireNetwork && !sys.networkAvailable)
            return {false, ThrottleReason::NoNetwork};

        if (conditions.skipMeteredNetwork && sys.isMeteredNetwork)
            return {false, ThrottleReason::MeteredNetwork};

        if (conditions.skipQuietHours && sys.isQuietHours)
            return {false, ThrottleReason::QuietHours};

        if (conditions.requireIdleSeconds > 0 &&
            sys.idleTimeSeconds < conditions.requireIdleSeconds)
            return {false, ThrottleReason::UserActive};

        return {true, ThrottleReason::None};
    }

    void ProcessSchedulesLocked(std::vector<QueuedBackup>& newlyQueued) {
        auto now = Now();
        for (auto& schedule : m_config.schedules) {
            if (!schedule.enabled) continue;

            // Initialize nextRun if not set
            if (schedule.nextRun.time_since_epoch().count() == 0) {
                schedule.nextRun = CalculateNextRunInternal(schedule);
                continue;
            }

            // Skip one-time schedules that already ran
            if (schedule.frequency == ScheduleFrequency::Once &&
                schedule.runCount > 0) {
                continue;
            }

            // Check if due
            if (now >= schedule.nextRun) {
                if (m_queue.size() >= m_config.maxQueueSize) {
                    m_stats.skippedRuns.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"Queue full (%zu), skipping schedule %hs",
                        m_queue.size(), schedule.scheduleId.c_str());
                    continue;
                }

                QueuedBackup q{};
                q.queueId = GenerateQueueId();
                q.jobId = schedule.jobId;
                q.scheduleId = schedule.scheduleId;
                q.priority = schedule.priority;
                q.queuedTime = now;
                q.estimatedStart = now;

                m_queue.push_back(q);
                newlyQueued.push_back(q);

                schedule.lastRun = now;
                schedule.runCount++;
                schedule.nextRun = CalculateNextRunInternal(schedule);

                m_stats.scheduledRuns.fetch_add(1, std::memory_order_relaxed);
                m_stats.currentQueueSize.store(m_queue.size(),
                    std::memory_order_relaxed);
                UpdateMaxQueueSize();

                SS_LOG_INFO(LOG_CATEGORY,
                    L"Schedule %hs due: queued job %hs (run #%llu)",
                    schedule.scheduleId.c_str(), schedule.jobId.c_str(),
                    static_cast<unsigned long long>(schedule.runCount));
            }
        }
    }

    void ProcessQueueLocked(const SystemConditions& sysConditions,
                            std::vector<QueuedBackup>& toDispatch,
                            ThrottleReason& throttleReason) {
        if (m_queue.empty()) return;

        // Sort by priority (lower enum = higher priority)
        std::sort(m_queue.begin(), m_queue.end(),
            [](const QueuedBackup& a, const QueuedBackup& b) {
                return static_cast<int>(a.priority) <
                       static_cast<int>(b.priority);
            });

        auto [allowed, reason] =
            EvaluateConditions(m_config.throttleConditions, sysConditions);

        if (!allowed) {
            throttleReason = reason;
            m_stats.throttledRuns.fetch_add(1, std::memory_order_relaxed);

            // Critical backups bypass throttling
            while (!m_queue.empty() &&
                   m_queue.front().priority == BackupPriority::Critical) {
                toDispatch.push_back(m_queue.front());
                m_queue.erase(m_queue.begin());
            }

            // Update throttle reason on remaining queued items
            for (auto& q : m_queue) {
                q.throttleReason = reason;
            }
        } else {
            // Dispatch according to parallel limits
            size_t maxDispatch = m_config.allowParallel
                ? std::min(m_config.maxParallel, m_queue.size())
                : std::min(size_t{1}, m_queue.size());

            for (size_t i = 0; i < maxDispatch; ++i) {
                toDispatch.push_back(m_queue.front());
                m_queue.erase(m_queue.begin());
            }
        }

        m_stats.currentQueueSize.store(m_queue.size(),
            std::memory_order_relaxed);
    }

    /// CPU usage measurement using GetSystemTimes() deltas
    int MeasureCpuUsage() {
        FILETIME idleTime{}, kernelTime{}, userTime{};
        if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            return 0;
        }

        ULARGE_INTEGER idle, kernel, user;
        idle.LowPart = idleTime.dwLowDateTime;
        idle.HighPart = idleTime.dwHighDateTime;
        kernel.LowPart = kernelTime.dwLowDateTime;
        kernel.HighPart = kernelTime.dwHighDateTime;
        user.LowPart = userTime.dwLowDateTime;
        user.HighPart = userTime.dwHighDateTime;

        auto prevIdle = m_lastIdleTime.load(std::memory_order_relaxed);
        auto prevKernel = m_lastKernelTime.load(std::memory_order_relaxed);
        auto prevUser = m_lastUserTime.load(std::memory_order_relaxed);

        m_lastIdleTime.store(idle.QuadPart, std::memory_order_relaxed);
        m_lastKernelTime.store(kernel.QuadPart, std::memory_order_relaxed);
        m_lastUserTime.store(user.QuadPart, std::memory_order_relaxed);

        // First measurement: no delta available yet
        if (prevIdle == 0 && prevKernel == 0 && prevUser == 0) {
            return 0;
        }

        uint64_t idleDelta = idle.QuadPart - prevIdle;
        uint64_t kernelDelta = kernel.QuadPart - prevKernel;
        uint64_t userDelta = user.QuadPart - prevUser;
        uint64_t totalDelta = kernelDelta + userDelta;

        if (totalDelta == 0) return 0;

        // Kernel time includes idle time
        uint64_t busyDelta = totalDelta - idleDelta;
        return static_cast<int>((busyDelta * 100) / totalDelta);
    }

    void InitializeCpuBaseline() {
        FILETIME idleTime{}, kernelTime{}, userTime{};
        if (GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER idle, kernel, user;
            idle.LowPart = idleTime.dwLowDateTime;
            idle.HighPart = idleTime.dwHighDateTime;
            kernel.LowPart = kernelTime.dwLowDateTime;
            kernel.HighPart = kernelTime.dwHighDateTime;
            user.LowPart = userTime.dwLowDateTime;
            user.HighPart = userTime.dwHighDateTime;
            m_lastIdleTime.store(idle.QuadPart, std::memory_order_relaxed);
            m_lastKernelTime.store(kernel.QuadPart, std::memory_order_relaxed);
            m_lastUserTime.store(user.QuadPart, std::memory_order_relaxed);
        }
    }

    void UpdateMaxQueueSize() {
        auto current = m_queue.size();
        auto prevMax = m_stats.maxQueueSize.load(std::memory_order_relaxed);
        while (current > prevMax) {
            if (m_stats.maxQueueSize.compare_exchange_weak(
                    prevMax, current, std::memory_order_relaxed)) {
                break;
            }
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_running{false};
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::thread m_thread;
    std::condition_variable_any m_cv;

    SchedulerConfiguration m_config;
    SchedulerStatistics m_stats;
    std::vector<QueuedBackup> m_queue;

    // CPU measurement state
    std::atomic<uint64_t> m_lastIdleTime{0};
    std::atomic<uint64_t> m_lastKernelTime{0};
    std::atomic<uint64_t> m_lastUserTime{0};

    // Callbacks
    ScheduleCallback m_scheduleCallback;
    TriggerCallback m_triggerCallback;
    QueueCallback m_queueCallback;
    ThrottleCallback m_throttleCallback;
    ErrorCallback m_errorCallback;
    DispatchCallback m_dispatchCallback;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

BackupScheduler& BackupScheduler::Instance() noexcept {
    static BackupScheduler instance;
    return instance;
}

bool BackupScheduler::HasInstance() noexcept {
    return s_instanceCreated.load();
}

BackupScheduler::BackupScheduler()
    : m_impl(std::make_unique<BackupSchedulerImpl>()) {
    s_instanceCreated.store(true);
}

BackupScheduler::~BackupScheduler() {
    s_instanceCreated.store(false);
}

bool BackupScheduler::Initialize(const SchedulerConfiguration& config) {
    return m_impl->Initialize(config);
}

void BackupScheduler::Shutdown() {
    m_impl->Shutdown();
}

bool BackupScheduler::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus BackupScheduler::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool BackupScheduler::UpdateConfiguration(const SchedulerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

SchedulerConfiguration BackupScheduler::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void BackupScheduler::Start() { m_impl->Start(); }
void BackupScheduler::Stop() { m_impl->Stop(); }
void BackupScheduler::Pause() { m_impl->Pause(); }
void BackupScheduler::Resume() { m_impl->Resume(); }
bool BackupScheduler::IsRunning() const noexcept { return m_impl->IsRunning(); }

bool BackupScheduler::AddSchedule(const ScheduleDefinition& schedule) {
    return m_impl->AddSchedule(schedule);
}

bool BackupScheduler::UpdateSchedule(const ScheduleDefinition& schedule) {
    return m_impl->UpdateSchedule(schedule);
}

bool BackupScheduler::RemoveSchedule(const std::string& scheduleId) {
    return m_impl->RemoveSchedule(scheduleId);
}

bool BackupScheduler::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    return m_impl->SetScheduleEnabled(scheduleId, enabled);
}

std::optional<ScheduleDefinition> BackupScheduler::GetSchedule(const std::string& scheduleId) {
    return m_impl->GetSchedule(scheduleId);
}

std::vector<ScheduleDefinition> BackupScheduler::GetSchedules() const {
    return m_impl->GetSchedules();
}

SystemTimePoint BackupScheduler::CalculateNextRun(const ScheduleDefinition& schedule) {
    return m_impl->CalculateNextRunInternal(schedule);
}

bool BackupScheduler::AddTrigger(const TriggerDefinition& trigger) {
    return m_impl->AddTrigger(trigger);
}

bool BackupScheduler::RemoveTrigger(const std::string& triggerId) {
    return m_impl->RemoveTrigger(triggerId);
}

std::vector<TriggerDefinition> BackupScheduler::GetTriggers() const {
    return m_impl->GetTriggers();
}

void BackupScheduler::FireTrigger(TriggerType type,
        const std::map<std::string, std::string>& context) {
    m_impl->FireTrigger(type, context);
}

void BackupScheduler::RequestInstantBackup() {
    RequestBackup("default", BackupPriority::Critical);
}

void BackupScheduler::RequestInstantBackup(const std::string& jobId) {
    m_impl->RequestInstantBackup(jobId);
}

void BackupScheduler::RequestBackup(const std::string& jobId, BackupPriority priority) {
    m_impl->RequestBackup(jobId, priority);
}

std::vector<QueuedBackup> BackupScheduler::GetQueue() const {
    return m_impl->GetQueue();
}

void BackupScheduler::ClearQueue() {
    m_impl->ClearQueue();
}

bool BackupScheduler::RemoveFromQueue(const std::string& queueId) {
    return m_impl->RemoveFromQueue(queueId);
}

bool BackupScheduler::ChangePriority(const std::string& queueId, BackupPriority priority) {
    return m_impl->ChangePriority(queueId, priority);
}

SystemConditions BackupScheduler::GetSystemConditions() {
    return m_impl->GetSystemConditions();
}

std::pair<bool, ThrottleReason> BackupScheduler::CheckConditions(
        const ThrottleConditions& conditions) {
    return m_impl->CheckConditions(conditions);
}

void BackupScheduler::SetThrottleConditions(const ThrottleConditions& conditions) {
    m_impl->SetThrottleConditions(conditions);
}

void BackupScheduler::RegisterScheduleCallback(ScheduleCallback cb) {
    m_impl->RegisterScheduleCallback(std::move(cb));
}
void BackupScheduler::RegisterTriggerCallback(TriggerCallback cb) {
    m_impl->RegisterTriggerCallback(std::move(cb));
}
void BackupScheduler::RegisterQueueCallback(QueueCallback cb) {
    m_impl->RegisterQueueCallback(std::move(cb));
}
void BackupScheduler::RegisterThrottleCallback(ThrottleCallback cb) {
    m_impl->RegisterThrottleCallback(std::move(cb));
}
void BackupScheduler::RegisterErrorCallback(ErrorCallback cb) {
    m_impl->RegisterErrorCallback(std::move(cb));
}
void BackupScheduler::RegisterDispatchCallback(DispatchCallback cb) {
    m_impl->RegisterDispatchCallback(std::move(cb));
}
void BackupScheduler::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

SchedulerStatisticsSnapshot BackupScheduler::GetStatistics() const {
    return m_impl->GetStatistics();
}

void BackupScheduler::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool BackupScheduler::SelfTest() {
    return m_impl->SelfTest();
}

std::string BackupScheduler::GetVersionString() noexcept {
    return std::to_string(SchedulerConstants::VERSION_MAJOR) + "." +
           std::to_string(SchedulerConstants::VERSION_MINOR) + "." +
           std::to_string(SchedulerConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetFrequencyName(ScheduleFrequency frequency) noexcept {
    switch (frequency) {
        case ScheduleFrequency::Once: return "Once";
        case ScheduleFrequency::Hourly: return "Hourly";
        case ScheduleFrequency::Daily: return "Daily";
        case ScheduleFrequency::Weekly: return "Weekly";
        case ScheduleFrequency::Monthly: return "Monthly";
        case ScheduleFrequency::Custom: return "Custom";
        case ScheduleFrequency::Cron: return "Cron";
        default: return "Unknown";
    }
}

std::string_view GetTriggerTypeName(TriggerType type) noexcept {
    switch (type) {
        case TriggerType::Scheduled: return "Scheduled";
        case TriggerType::BeforeInstall: return "BeforeInstall";
        case TriggerType::BeforeUpdate: return "BeforeUpdate";
        case TriggerType::OnFileChange: return "OnFileChange";
        case TriggerType::OnLogin: return "OnLogin";
        case TriggerType::OnLogout: return "OnLogout";
        case TriggerType::OnShutdown: return "OnShutdown";
        case TriggerType::OnIdle: return "OnIdle";
        case TriggerType::Manual: return "Manual";
        case TriggerType::OnNetworkChange: return "OnNetworkChange";
        case TriggerType::OnDriveConnect: return "OnDriveConnect";
        default: return "Unknown";
    }
}

std::string_view GetPriorityName(BackupPriority priority) noexcept {
    switch (priority) {
        case BackupPriority::Critical: return "Critical";
        case BackupPriority::High: return "High";
        case BackupPriority::Normal: return "Normal";
        case BackupPriority::Low: return "Low";
        case BackupPriority::Background: return "Background";
        default: return "Unknown";
    }
}

std::string_view GetScheduleStatusName(ScheduleStatus status) noexcept {
    switch (status) {
        case ScheduleStatus::Active: return "Active";
        case ScheduleStatus::Paused: return "Paused";
        case ScheduleStatus::Disabled: return "Disabled";
        case ScheduleStatus::Running: return "Running";
        case ScheduleStatus::WaitingCondition: return "WaitingCondition";
        case ScheduleStatus::Error: return "Error";
        default: return "Unknown";
    }
}

std::string_view GetThrottleReasonName(ThrottleReason reason) noexcept {
    switch (reason) {
        case ThrottleReason::None: return "None";
        case ThrottleReason::LowBattery: return "LowBattery";
        case ThrottleReason::HighCPU: return "HighCPU";
        case ThrottleReason::UserActive: return "UserActive";
        case ThrottleReason::GameMode: return "GameMode";
        case ThrottleReason::NoNetwork: return "NoNetwork";
        case ThrottleReason::MeteredNetwork: return "MeteredNetwork";
        case ThrottleReason::QuietHours: return "QuietHours";
        case ThrottleReason::SystemBusy: return "SystemBusy";
        default: return "Unknown";
    }
}

std::string_view GetDayOfWeekName(DayOfWeek day) noexcept {
    switch (day) {
        case DayOfWeek::Sunday: return "Sunday";
        case DayOfWeek::Monday: return "Monday";
        case DayOfWeek::Tuesday: return "Tuesday";
        case DayOfWeek::Wednesday: return "Wednesday";
        case DayOfWeek::Thursday: return "Thursday";
        case DayOfWeek::Friday: return "Friday";
        case DayOfWeek::Saturday: return "Saturday";
        default: return "Unknown";
    }
}

bool ParseCronExpression(const std::string& expression, SystemTimePoint& nextRun) {
    // 5-field cron: minute hour day-of-month month day-of-week
    // Supports: *, specific number, */step
    std::istringstream iss(expression);
    std::string fields[5];
    for (int i = 0; i < 5; ++i) {
        if (!(iss >> fields[i])) return false;
    }
    // Reject extra tokens
    std::string extra;
    if (iss >> extra) return false;

    // Build set of matching values for each field
    auto getMatchingValues = [](const std::string& field, int minVal, int maxVal)
            -> std::vector<int> {
        std::vector<int> result;
        if (field == "*") {
            for (int i = minVal; i <= maxVal; ++i) result.push_back(i);
            return result;
        }
        if (field.size() > 2 && field[0] == '*' && field[1] == '/') {
            int step = 0;
            auto [ptr, ec] = std::from_chars(
                field.data() + 2, field.data() + field.size(), step);
            if (ec != std::errc{} || step <= 0 || ptr != field.data() + field.size())
                return {};
            for (int i = minVal; i <= maxVal; i += step) result.push_back(i);
            return result;
        }
        int num = 0;
        auto [ptr, ec] = std::from_chars(
            field.data(), field.data() + field.size(), num);
        if (ec != std::errc{} || ptr != field.data() + field.size())
            return {};
        if (num < minVal || num > maxVal) return {};
        result.push_back(num);
        return result;
    };

    auto minutes = getMatchingValues(fields[0], 0, 59);
    auto hours   = getMatchingValues(fields[1], 0, 23);
    auto doms    = getMatchingValues(fields[2], 1, 31);
    auto months  = getMatchingValues(fields[3], 1, 12);
    auto dows    = getMatchingValues(fields[4], 0, 6);

    if (minutes.empty() || hours.empty() || doms.empty() ||
        months.empty() || dows.empty()) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    time_t tNow = std::chrono::system_clock::to_time_t(now);
    tm tmNow{};
    localtime_s(&tmNow, &tNow);

    // Start search from the next minute
    tm candidate = tmNow;
    candidate.tm_sec = 0;
    candidate.tm_min++;
    candidate.tm_isdst = -1;
    std::mktime(&candidate); // normalize

    // Search day by day for up to ~2 years
    for (int dayIter = 0; dayIter < 732; ++dayIter) {
        // Check month (tm_mon is 0-based, cron field is 1-based)
        if (std::find(months.begin(), months.end(), candidate.tm_mon + 1) ==
                months.end()) {
            candidate.tm_mday = 1;
            candidate.tm_mon++;
            candidate.tm_hour = 0;
            candidate.tm_min = 0;
            candidate.tm_isdst = -1;
            std::mktime(&candidate);
            continue;
        }

        // Check day-of-month and day-of-week
        bool domOk = std::find(doms.begin(), doms.end(), candidate.tm_mday) !=
                     doms.end();
        bool dowOk = std::find(dows.begin(), dows.end(), candidate.tm_wday) !=
                     dows.end();

        if (!domOk || !dowOk) {
            candidate.tm_mday++;
            candidate.tm_hour = 0;
            candidate.tm_min = 0;
            candidate.tm_isdst = -1;
            std::mktime(&candidate);
            continue;
        }

        // Find matching hour and minute on this day
        for (int h : hours) {
            for (int m : minutes) {
                // On the first day, skip times that are already past
                if (dayIter == 0) {
                    if (h < tmNow.tm_hour) continue;
                    if (h == tmNow.tm_hour && m <= tmNow.tm_min) continue;
                }
                tm result = candidate;
                result.tm_hour = h;
                result.tm_min = m;
                result.tm_sec = 0;
                result.tm_isdst = -1;
                time_t rt = std::mktime(&result);

                // Verify mktime didn't shift the date
                if (result.tm_mday == candidate.tm_mday &&
                    result.tm_mon == candidate.tm_mon &&
                    result.tm_year == candidate.tm_year) {
                    nextRun = std::chrono::system_clock::from_time_t(rt);
                    return true;
                }
            }
        }

        // No match today; advance to next day
        candidate.tm_mday++;
        candidate.tm_hour = 0;
        candidate.tm_min = 0;
        candidate.tm_isdst = -1;
        std::mktime(&candidate);
    }

    return false;
}

bool IsInQuietHours(int currentHour, int startHour, int endHour) {
    if (startHour <= endHour) {
        return currentHour >= startHour && currentHour < endHour;
    } else {
        // Spans midnight (e.g., 22:00 to 07:00)
        return currentHour >= startHour || currentHour < endHour;
    }
}

} // namespace Backup
} // namespace ShadowStrike
