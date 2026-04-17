/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */
#include "pch.h"
#include "Products/Community/PhantomEDR/Playbooks/PlaybookScheduler.hpp"

#include "Products/Community/PhantomEDR/Playbooks/PlaybookEngine.hpp"
#include "PhantomCore/Communication/AlertSystem.hpp"
#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <condition_variable>
#include <memory>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

namespace ShadowStrike::Products::PhantomEDR::Playbooks {

namespace {

using ShadowStrike::Communication::Alert;
using ShadowStrike::Communication::AlertSeverity;
using ShadowStrike::Communication::AlertType;
using ShadowStrike::Database::DatabaseError;
using ShadowStrike::Database::DatabaseManager;
using ShadowStrike::Database::QueryResult;
using ShadowStrike::Utils::Logger;
namespace StringUtils = ShadowStrike::Utils::StringUtils;

constexpr std::string_view kLogPrefix = "[PlaybookScheduler]";
constexpr auto kSchedulerWakeInterval = std::chrono::seconds(5);
constexpr std::string_view kCreateJobsSql = R"(
    CREATE TABLE IF NOT EXISTS playbook_jobs (
        job_id TEXT PRIMARY KEY,
        playbook_id TEXT NOT NULL,
        trigger_type INTEGER NOT NULL,
        schedule_expression TEXT NOT NULL,
        alert_filter_json TEXT NOT NULL,
        manual_context_json TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        next_run_at INTEGER NOT NULL,
        last_run_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        last_status INTEGER NOT NULL,
        last_error TEXT NOT NULL
    );
)";

constexpr std::string_view kCreateJobIndexesSql = R"(
    CREATE INDEX IF NOT EXISTS idx_playbook_jobs_trigger_enabled ON playbook_jobs(trigger_type, enabled, next_run_at);
)";

[[nodiscard]] int64_t ToUnixMillis(const std::chrono::system_clock::time_point value) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();
}

[[nodiscard]] std::chrono::system_clock::time_point FromUnixMillis(const int64_t value) noexcept {
    return std::chrono::system_clock::time_point{ std::chrono::milliseconds(value) };
}

[[nodiscard]] std::string LowerCopy(std::string_view value) {
    std::string normalized;
    normalized.reserve(value.size());
    for (const unsigned char ch : value) {
        normalized.push_back(static_cast<char>(std::tolower(ch)));
    }
    return normalized;
}

struct CronField {
    int min = 0;
    int max = 0;
    std::vector<int> values;
};

[[nodiscard]] bool ContainsValue(const std::vector<int>& values, const int value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

bool ExpandCronToken(const std::string_view token, const int min, const int max, std::vector<int>& output) {
    const auto appendRange = [&](const int start, const int end, const int step) {
        if (start < min || end > max || start > end || step <= 0) {
            return false;
        }
        for (int value = start; value <= end; value += step) {
            if (!ContainsValue(output, value)) {
                output.push_back(value);
            }
        }
        return true;
    };

    if (token == "*") {
        return appendRange(min, max, 1);
    }

    const size_t slash = token.find('/');
    const std::string_view base = slash == std::string_view::npos ? token : token.substr(0, slash);
    int step = 1;
    if (slash != std::string_view::npos) {
        try {
            step = std::stoi(std::string(token.substr(slash + 1)));
        } catch (...) {
            return false;
        }
    }

    if (base == "*") {
        return appendRange(min, max, step);
    }

    const size_t dash = base.find('-');
    if (dash != std::string_view::npos) {
        try {
            const int start = std::stoi(std::string(base.substr(0, dash)));
            const int end = std::stoi(std::string(base.substr(dash + 1)));
            return appendRange(start, end, step);
        } catch (...) {
            return false;
        }
    }

    try {
        const int value = std::stoi(std::string(base));
        return appendRange(value, value, 1);
    } catch (...) {
        return false;
    }
}

[[nodiscard]] std::optional<CronField> ParseCronField(const std::string_view field, const int min, const int max) {
    CronField cronField;
    cronField.min = min;
    cronField.max = max;

    size_t offset = 0;
    while (offset < field.size()) {
        const size_t comma = field.find(',', offset);
        const std::string_view token = comma == std::string_view::npos
            ? field.substr(offset)
            : field.substr(offset, comma - offset);
        if (!ExpandCronToken(token, min, max, cronField.values)) {
            return std::nullopt;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        offset = comma + 1;
    }

    std::sort(cronField.values.begin(), cronField.values.end());
    return cronField;
}

[[nodiscard]] std::optional<std::chrono::system_clock::time_point> ComputeNextRun(
    const std::string_view expression,
    const std::chrono::system_clock::time_point after) {
    const std::string normalized = LowerCopy(expression);
    if (normalized.empty()) {
        return std::nullopt;
    }

    if (normalized == "hourly") {
        return after + std::chrono::hours(1);
    }
    if (normalized == "daily") {
        return after + std::chrono::hours(24);
    }
    if (normalized == "weekly") {
        return after + std::chrono::hours(24 * 7);
    }
    if (normalized.rfind("every:", 0) == 0) {
        try {
            const int seconds = std::stoi(normalized.substr(6));
            if (seconds <= 0) {
                return std::nullopt;
            }
            return after + std::chrono::seconds(seconds);
        } catch (...) {
            return std::nullopt;
        }
    }

    const auto partsWide = StringUtils::Split(StringUtils::ToWide(normalized), L" ");
    std::vector<std::string> parts;
    for (const auto& part : partsWide) {
        if (!part.empty()) {
            parts.push_back(StringUtils::ToNarrow(part));
        }
    }
    if (parts.size() != 5) {
        return std::nullopt;
    }

    const auto minuteField = ParseCronField(parts[0], 0, 59);
    const auto hourField = ParseCronField(parts[1], 0, 23);
    const auto dayField = ParseCronField(parts[2], 1, 31);
    const auto monthField = ParseCronField(parts[3], 1, 12);
    const auto weekDayField = ParseCronField(parts[4], 0, 6);
    if (!minuteField.has_value() || !hourField.has_value() || !dayField.has_value() ||
        !monthField.has_value() || !weekDayField.has_value()) {
        return std::nullopt;
    }

    auto candidate = after + std::chrono::minutes(1);
    candidate -= std::chrono::seconds(
        std::chrono::duration_cast<std::chrono::seconds>(candidate.time_since_epoch()).count() % 60);

    for (size_t i = 0; i < 525600; ++i) {
        std::time_t rawTime = std::chrono::system_clock::to_time_t(candidate);
        std::tm timeInfo{};
        localtime_s(&timeInfo, &rawTime);

        if (ContainsValue(minuteField->values, timeInfo.tm_min) &&
            ContainsValue(hourField->values, timeInfo.tm_hour) &&
            ContainsValue(dayField->values, timeInfo.tm_mday) &&
            ContainsValue(monthField->values, timeInfo.tm_mon + 1) &&
            ContainsValue(weekDayField->values, timeInfo.tm_wday)) {
            return candidate;
        }

        candidate += std::chrono::minutes(1);
    }

    return std::nullopt;
}

[[nodiscard]] std::string AlertSeverityToken(const AlertSeverity severity) {
    switch (severity) {
        case AlertSeverity::Info: return "info";
        case AlertSeverity::Low: return "low";
        case AlertSeverity::Medium: return "medium";
        case AlertSeverity::High: return "high";
        case AlertSeverity::Critical: return "critical";
        case AlertSeverity::Emergency: return "emergency";
    }
    return "info";
}

[[nodiscard]] std::string AlertTypeToken(const AlertType type) {
    switch (type) {
        case AlertType::ThreatDetection: return "threat_detection";
        case AlertType::SystemHealth: return "system_health";
        case AlertType::PolicyViolation: return "policy_violation";
        case AlertType::ComplianceAlert: return "compliance_alert";
        case AlertType::AuditEvent: return "audit_event";
        case AlertType::Operational: return "operational";
        case AlertType::Security: return "security";
        case AlertType::Performance: return "performance";
        case AlertType::Custom: return "custom";
    }
    return "custom";
}

[[nodiscard]] int SeverityRank(const std::string_view severity) {
    const std::string token = LowerCopy(severity);
    if (token == "emergency") {
        return 5;
    }
    if (token == "critical") {
        return 4;
    }
    if (token == "high") {
        return 3;
    }
    if (token == "medium") {
        return 2;
    }
    if (token == "low") {
        return 1;
    }
    return 0;
}

[[nodiscard]] PlaybookJobRecord RowToJob(QueryResult& result) {
    PlaybookJobRecord job;
    job.jobId = result.GetString(0);
    job.playbookId = result.GetString(1);
    job.triggerType = static_cast<PlaybookTriggerType>(result.GetInt(2));
    job.scheduleExpression = result.GetString(3);
    job.alertFilter = Json::parse(result.GetString(4), nullptr, false);
    job.manualContext = Json::parse(result.GetString(5), nullptr, false);
    if (job.alertFilter.is_discarded()) {
        job.alertFilter = Json::object();
    }
    if (job.manualContext.is_discarded()) {
        job.manualContext = Json::object();
    }
    job.enabled = result.GetInt(6) != 0;
    job.nextRunAt = FromUnixMillis(result.GetInt64(7));
    const int64_t lastRun = result.GetInt64(8);
    if (lastRun != 0) {
        job.lastRunAt = FromUnixMillis(lastRun);
    }
    job.createdAt = FromUnixMillis(result.GetInt64(9));
    job.updatedAt = FromUnixMillis(result.GetInt64(10));
    job.lastStatus = static_cast<PlaybookRunStatus>(result.GetInt(11));
    job.lastError = result.GetString(12);
    return job;
}

} // namespace

class PlaybookSchedulerImpl {
public:
    bool initialized = false;
    bool running = false;
    bool stopRequested = false;
    mutable std::shared_mutex mutex;
    std::condition_variable_any wakeCondition;
    std::thread worker;
    std::unordered_map<std::string, PlaybookJobRecord> jobs;

    [[nodiscard]] bool EnsureSchema() const {
        DatabaseError dbError;
        if (!DatabaseManager::Instance().Execute(kCreateJobsSql.data(), &dbError) ||
            !DatabaseManager::Instance().Execute(kCreateJobIndexesSql.data(), &dbError)) {
            Logger::Error("{} Failed to initialize scheduler schema: {}", kLogPrefix, StringUtils::ToNarrow(dbError.message));
            return false;
        }
        return true;
    }

    void LoadJobs() {
        DatabaseError dbError;
        auto rows = DatabaseManager::Instance().QueryWithParams(
            "SELECT job_id, playbook_id, trigger_type, schedule_expression, alert_filter_json, manual_context_json, "
            "enabled, next_run_at, last_run_at, created_at, updated_at, last_status, last_error "
            "FROM playbook_jobs;",
            &dbError);

        jobs.clear();
        while (rows.Next()) {
            PlaybookJobRecord job = RowToJob(rows);
            jobs[job.jobId] = std::move(job);
        }
    }

    [[nodiscard]] bool PersistJob(const PlaybookJobRecord& job) const {
        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO playbook_jobs "
            "(job_id, playbook_id, trigger_type, schedule_expression, alert_filter_json, manual_context_json, enabled, "
            "next_run_at, last_run_at, created_at, updated_at, last_status, last_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(job_id) DO UPDATE SET "
            "playbook_id = excluded.playbook_id, trigger_type = excluded.trigger_type, "
            "schedule_expression = excluded.schedule_expression, alert_filter_json = excluded.alert_filter_json, "
            "manual_context_json = excluded.manual_context_json, enabled = excluded.enabled, next_run_at = excluded.next_run_at, "
            "last_run_at = excluded.last_run_at, updated_at = excluded.updated_at, last_status = excluded.last_status, "
            "last_error = excluded.last_error;",
            &dbError,
            job.jobId,
            job.playbookId,
            static_cast<int>(job.triggerType),
            job.scheduleExpression,
            job.alertFilter.dump(),
            job.manualContext.dump(),
            job.enabled ? 1 : 0,
            ToUnixMillis(job.nextRunAt),
            job.lastRunAt.has_value() ? ToUnixMillis(*job.lastRunAt) : int64_t{ 0 },
            ToUnixMillis(job.createdAt),
            ToUnixMillis(job.updatedAt),
            static_cast<int>(job.lastStatus),
            job.lastError);
    }

    [[nodiscard]] bool DeleteJob(const std::string_view jobId) const {
        DatabaseError dbError;
        return DatabaseManager::Instance().ExecuteWithParams(
            "DELETE FROM playbook_jobs WHERE job_id = ?;",
            &dbError,
            std::string(jobId));
    }

    [[nodiscard]] bool MatchesAlertFilter(const PlaybookJobRecord& job, const Alert& alert) const {
        if (!job.alertFilter.is_object()) {
            return true;
        }

        if (job.alertFilter.contains("min_severity")) {
            const int minRank = SeverityRank(job.alertFilter["min_severity"].get<std::string>());
            if (SeverityRank(AlertSeverityToken(alert.severity)) < minRank) {
                return false;
            }
        }

        if (job.alertFilter.contains("categories") && job.alertFilter["categories"].is_array()) {
            bool matched = false;
            const std::string alertType = AlertTypeToken(alert.type);
            for (const auto& category : job.alertFilter["categories"]) {
                if (LowerCopy(category.get<std::string>()) == alertType) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] Json BuildAlertContext(const Alert& alert) const {
        return Json{
            { "alert", {
                { "id", alert.alertId },
                { "severity", AlertSeverityToken(alert.severity) },
                { "type", AlertTypeToken(alert.type) },
                { "subject", alert.subject },
                { "details", alert.details },
                { "source", alert.source },
                { "hostname", alert.hostname },
                { "user_name", alert.userName },
                { "metadata", alert.metadata }
            } }
        };
    }

    void ExecuteScheduledJob(PlaybookJobRecord& job) {
        Json context = job.manualContext;
        context["job"] = {
            { "id", job.jobId },
            { "trigger_type", ToString(job.triggerType) },
            { "schedule_expression", job.scheduleExpression }
        };

        const auto run = PlaybookEngine::Instance().ExecutePlaybook(
            job.playbookId,
            context,
            PlaybookTriggerType::Schedule,
            job.jobId);

        job.lastRunAt = std::chrono::system_clock::now();
        job.updatedAt = *job.lastRunAt;
        if (run.has_value()) {
            job.lastStatus = run->status;
            job.lastError = run->errorMessage;
        } else {
            job.lastStatus = PlaybookRunStatus::Failed;
            job.lastError = "Playbook execution failed";
        }

        if (const auto nextRun = ComputeNextRun(job.scheduleExpression, *job.lastRunAt); nextRun.has_value()) {
            job.nextRunAt = *nextRun;
        } else {
            job.enabled = false;
            job.nextRunAt = *job.lastRunAt;
            if (job.lastError.empty()) {
                job.lastError = "Invalid schedule expression";
            }
        }

        [[maybe_unused]] const bool persisted = PersistJob(job);
    }

    void WorkerLoop() {
        std::unique_lock lock(mutex);
        while (!stopRequested) {
            const auto now = std::chrono::system_clock::now();
            std::vector<std::string> dueJobIds;
            dueJobIds.reserve(jobs.size());
            for (const auto& [jobId, job] : jobs) {
                if (job.enabled &&
                    job.triggerType == PlaybookTriggerType::Schedule &&
                    job.nextRunAt <= now) {
                    dueJobIds.push_back(jobId);
                }
            }

            if (dueJobIds.empty()) {
                wakeCondition.wait_for(lock, kSchedulerWakeInterval);
                continue;
            }

            std::vector<PlaybookJobRecord> dueJobs;
            for (const auto& jobId : dueJobIds) {
                dueJobs.push_back(jobs[jobId]);
            }

            lock.unlock();
            for (auto& job : dueJobs) {
                ExecuteScheduledJob(job);
                std::unique_lock updateLock(mutex);
                jobs[job.jobId] = job;
            }
            lock.lock();
        }
    }
};

PlaybookScheduler& PlaybookScheduler::Instance() {
    static PlaybookScheduler instance;
    return instance;
}

PlaybookScheduler::PlaybookScheduler()
    : m_impl(std::make_unique<PlaybookSchedulerImpl>()) {
}

PlaybookScheduler::~PlaybookScheduler() = default;

bool PlaybookScheduler::Initialize() {
    std::unique_lock lock(m_impl->mutex);
    if (m_impl->initialized) {
        return true;
    }

    if (!PlaybookEngine::Instance().Initialize()) {
        return false;
    }
    if (!m_impl->EnsureSchema()) {
        return false;
    }

    m_impl->LoadJobs();
    m_impl->initialized = true;
    Logger::Info("{} Initialized successfully", kLogPrefix);
    return true;
}

void PlaybookScheduler::Shutdown() {
    Stop();
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->initialized) {
        return;
    }
    m_impl->jobs.clear();
    m_impl->initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

bool PlaybookScheduler::IsInitialized() const {
    std::shared_lock lock(m_impl->mutex);
    return m_impl->initialized;
}

bool PlaybookScheduler::Start() {
    if (!IsInitialized() && !Initialize()) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    if (m_impl->running) {
        return true;
    }

    m_impl->stopRequested = false;
    m_impl->worker = std::thread([this]() { m_impl->WorkerLoop(); });
    m_impl->running = true;
    Logger::Info("{} Scheduler started", kLogPrefix);
    return true;
}

void PlaybookScheduler::Stop() {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->running) {
        return;
    }

    m_impl->stopRequested = true;
    m_impl->wakeCondition.notify_all();
    lock.unlock();

    if (m_impl->worker.joinable()) {
        m_impl->worker.join();
    }

    lock.lock();
    m_impl->running = false;
    Logger::Info("{} Scheduler stopped", kLogPrefix);
}

bool PlaybookScheduler::RegisterJob(const PlaybookJobRecord& inputJob) {
    if (!IsInitialized() && !Initialize()) {
        return false;
    }

    std::unique_lock lock(m_impl->mutex);
    PlaybookJobRecord job = inputJob;
    const auto now = std::chrono::system_clock::now();
    if (job.jobId.empty()) {
        job.jobId = std::format(
            "job-{}-{}",
            job.playbookId.empty() ? "playbook" : job.playbookId,
            ToUnixMillis(now));
    }
    if (job.createdAt.time_since_epoch().count() == 0) {
        job.createdAt = now;
    }
    job.updatedAt = now;

    if (job.triggerType == PlaybookTriggerType::Schedule) {
        const auto nextRun = ComputeNextRun(job.scheduleExpression, now);
        if (!nextRun.has_value()) {
            Logger::Error("{} Invalid schedule expression for job {}", kLogPrefix, job.jobId);
            return false;
        }
        job.nextRunAt = *nextRun;
    } else {
        job.nextRunAt = now;
    }

    if (!m_impl->PersistJob(job)) {
        Logger::Error("{} Failed to persist job {}", kLogPrefix, job.jobId);
        return false;
    }

    m_impl->jobs[job.jobId] = job;
    m_impl->wakeCondition.notify_all();
    return true;
}

bool PlaybookScheduler::RemoveJob(const std::string_view jobId) {
    std::unique_lock lock(m_impl->mutex);
    if (!m_impl->DeleteJob(jobId)) {
        return false;
    }
    m_impl->jobs.erase(std::string(jobId));
    return true;
}

bool PlaybookScheduler::SetJobEnabled(const std::string_view jobId, const bool enabled) {
    std::unique_lock lock(m_impl->mutex);
    const auto it = m_impl->jobs.find(std::string(jobId));
    if (it == m_impl->jobs.end()) {
        return false;
    }

    it->second.enabled = enabled;
    it->second.updatedAt = std::chrono::system_clock::now();
    if (enabled && it->second.triggerType == PlaybookTriggerType::Schedule) {
        if (const auto nextRun = ComputeNextRun(it->second.scheduleExpression, it->second.updatedAt); nextRun.has_value()) {
            it->second.nextRunAt = *nextRun;
        } else {
            return false;
        }
    }

    const bool persisted = m_impl->PersistJob(it->second);
    if (persisted) {
        m_impl->wakeCondition.notify_all();
    }
    return persisted;
}

std::optional<PlaybookJobRecord> PlaybookScheduler::GetJob(const std::string_view jobId) const {
    std::shared_lock lock(m_impl->mutex);
    const auto it = m_impl->jobs.find(std::string(jobId));
    if (it == m_impl->jobs.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<PlaybookJobRecord> PlaybookScheduler::GetJobs() const {
    std::shared_lock lock(m_impl->mutex);
    std::vector<PlaybookJobRecord> jobs;
    jobs.reserve(m_impl->jobs.size());
    for (const auto& [_, job] : m_impl->jobs) {
        jobs.push_back(job);
    }
    return jobs;
}

std::optional<PlaybookRunRecord> PlaybookScheduler::RunPlaybookNow(
    const std::string_view playbookId,
    const Json& context) {
    if (!IsInitialized() && !const_cast<PlaybookScheduler*>(this)->Initialize()) {
        return std::nullopt;
    }
    return PlaybookEngine::Instance().ExecutePlaybook(playbookId, context, PlaybookTriggerType::Manual, "manual");
}

void PlaybookScheduler::OnAlert(const Alert& alert) {
    std::vector<PlaybookJobRecord> matchingJobs;
    {
        std::shared_lock lock(m_impl->mutex);
        for (const auto& [_, job] : m_impl->jobs) {
            if (!job.enabled || job.triggerType != PlaybookTriggerType::Alert) {
                continue;
            }
            if (m_impl->MatchesAlertFilter(job, alert)) {
                matchingJobs.push_back(job);
            }
        }
    }

    if (matchingJobs.empty()) {
        return;
    }

    const Json alertContext = m_impl->BuildAlertContext(alert);
    for (auto& job : matchingJobs) {
        Json context = job.manualContext;
        context.update(alertContext);
        const auto run = PlaybookEngine::Instance().ExecutePlaybook(
            job.playbookId,
            context,
            PlaybookTriggerType::Alert,
            job.jobId);

        std::unique_lock lock(m_impl->mutex);
        auto liveJob = m_impl->jobs.find(job.jobId);
        if (liveJob == m_impl->jobs.end()) {
            continue;
        }

        liveJob->second.lastRunAt = std::chrono::system_clock::now();
        liveJob->second.updatedAt = *liveJob->second.lastRunAt;
        if (run.has_value()) {
            liveJob->second.lastStatus = run->status;
            liveJob->second.lastError = run->errorMessage;
        } else {
            liveJob->second.lastStatus = PlaybookRunStatus::Failed;
            liveJob->second.lastError = "Alert-triggered playbook execution failed";
        }
        [[maybe_unused]] const bool persisted = m_impl->PersistJob(liveJob->second);
    }
}

std::vector<PlaybookRunRecord> PlaybookScheduler::GetJobHistory(
    const std::string_view playbookId,
    const uint32_t maxRecords) const {
    return PlaybookEngine::Instance().GetRunHistory(playbookId, maxRecords);
}

} // namespace ShadowStrike::Products::PhantomEDR::Playbooks
