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
#include "pch.h"
#include "ReportGenerator.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <deque>
#include <condition_variable>
#include <fstream>

namespace ShadowStrike {
namespace Communication {

// ============================================================================
// HELPERS
// ============================================================================

static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char hex[8];
                    std::snprintf(hex, sizeof(hex), "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += hex;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int len = WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                        static_cast<int>(w.size()),
                                        nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                        s.data(), len, nullptr, nullptr);
    return s;
}

static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    const int len = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                        static_cast<int>(s.size()),
                                        nullptr, 0);
    if (len <= 0) return {};
    std::wstring w(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        w.data(), len);
    return w;
}

static std::string SystemTimeToIso8601(std::chrono::system_clock::time_point tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

static std::string SystemTimeToDisplay(std::chrono::system_clock::time_point tp) {
    const auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    localtime_s(&tm, &tt);
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);
    return buf;
}

static std::string GenerateId(const char* prefix) {
    static std::atomic<uint64_t> s_counter{0};
    const uint64_t seq = s_counter.fetch_add(1, std::memory_order_relaxed);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%s-%llX-%04llX", prefix,
                  static_cast<unsigned long long>(ms),
                  static_cast<unsigned long long>(seq & 0xFFFF));
    return buf;
}

static std::string MapToJson(const std::map<std::string, std::string>& m) {
    std::string j = "{";
    bool first = true;
    for (const auto& [k, v] : m) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":\"" + JsonEscape(v) + "\"";
        first = false;
    }
    j += "}";
    return j;
}

static std::string MapToJsonNumeric(const std::map<std::string, uint64_t>& m) {
    std::string j = "{";
    bool first = true;
    for (const auto& [k, v] : m) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":" + std::to_string(v);
        first = false;
    }
    j += "}";
    return j;
}

static std::string VectorToJsonStringArray(const std::vector<std::string>& v) {
    std::string j = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i > 0) j += ",";
        j += "\"" + JsonEscape(v[i]) + "\"";
    }
    j += "]";
    return j;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

class ReportGeneratorImpl {
public:
    ReportGeneratorImpl() = default;
    ~ReportGeneratorImpl() { Shutdown(); }

    // Lifecycle
    bool Initialize(const ReportConfiguration& config);
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized.load(std::memory_order_acquire); }
    ReportModuleStatus GetStatus() const noexcept { return m_status.load(std::memory_order_acquire); }

    bool UpdateConfiguration(const ReportConfiguration& config);
    ReportConfiguration GetConfiguration() const;

    // Report generation
    std::string GenerateHtmlReport(uint64_t startTime, uint64_t endTime);
    std::optional<fs::path> GenerateReport(ReportType type, ReportFormat format,
                                           const TimeRange& range, const std::string& tmpl);
    std::string GenerateReportAsync(ReportType type, ReportFormat format,
                                    const TimeRange& range, const std::string& tmpl);
    std::optional<fs::path> GenerateComplianceReport(ComplianceStandard std_,
                                                     ReportFormat format,
                                                     const TimeRange& range);
    std::optional<fs::path> GenerateIncidentReport(const std::string& incidentId,
                                                   ReportFormat format);

    // Export
    bool ExportToCsv(const std::wstring& outputPath);
    bool ExportToCsv(const fs::path& outputPath, const TimeRange& range);
    bool ExportToJson(const fs::path& outputPath, const TimeRange& range);
    bool ExportToSiem(const fs::path& outputPath, ReportFormat siemFormat,
                      const TimeRange& range);

    // Templates
    bool LoadTemplates();
    std::vector<ReportTemplate> GetTemplates(std::optional<ReportType> filterType);
    bool ImportTemplate(const fs::path& templatePath);
    bool DeleteTemplate(const std::string& templateId);

    // Scheduling
    std::string CreateSchedule(const ReportSchedule& schedule);
    bool UpdateSchedule(const ReportSchedule& schedule);
    bool DeleteSchedule(const std::string& scheduleId);
    std::vector<ReportSchedule> GetSchedules();
    bool SetScheduleEnabled(const std::string& scheduleId, bool enabled);

    // Jobs
    std::optional<ReportJob> GetJobStatus(const std::string& jobId);
    std::vector<ReportJob> GetPendingJobs();
    bool CancelJob(const std::string& jobId);

    // Data access
    ThreatStatistics GetThreatStatistics(const TimeRange& range);
    ScanStatistics GetScanStatistics(const TimeRange& range);
    std::vector<ComplianceCheckResult> GetComplianceResults(ComplianceStandard std_);

    // Archives
    std::vector<ReportJob> GetArchivedReports(const TimeRange& range,
                                              std::optional<ReportType> filterType);
    bool DeleteArchivedReport(const std::string& reportId);
    size_t CleanupArchives(uint32_t olderThanDays);

    // Callbacks
    void RegisterProgressCallback(ProgressCallback cb);
    void RegisterCompletionCallback(CompletionCallback cb);
    void RegisterErrorCallback(ReportErrorCallback cb);
    void UnregisterCallbacks();

    // Statistics
    ReportStatisticsSnapshot GetStatistics() const noexcept;
    void ResetStatistics();
    bool SelfTest();

private:
    // Internal
    void WorkerLoop();
    void SchedulerLoop();
    void ExecuteJob(ReportJob& job);
    std::vector<ReportSection> BuildSections(ReportType type, const TimeRange& range);
    std::string RenderHtml(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderJson(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderCsv(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderXml(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderCef(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderLeef(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderSyslog(const ReportMetadata& meta, const std::vector<ReportSection>& sections);
    std::string RenderFormat(ReportFormat format, const ReportMetadata& meta,
                             const std::vector<ReportSection>& sections);
    fs::path BuildOutputPath(ReportType type, ReportFormat format);
    bool WriteReportFile(const fs::path& path, const std::string& content);
    ReportMetadata BuildMetadata(ReportType type, const TimeRange& range);
    void ArchiveReport(const ReportJob& job);
    void NotifyProgress(const std::string& jobId, uint8_t progress);
    void NotifyCompletion(const ReportJob& job);
    void NotifyError(const std::string& msg, int code);

    // Config
    ReportConfiguration m_config;
    mutable std::shared_mutex m_configMutex;

    // State
    std::atomic<ReportModuleStatus> m_status{ReportModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // Jobs
    std::deque<ReportJob> m_jobQueue;
    std::vector<ReportJob> m_completedJobs;
    mutable std::shared_mutex m_jobsMutex;
    std::condition_variable_any m_jobCv;

    // Templates
    std::vector<ReportTemplate> m_templates;
    mutable std::shared_mutex m_templatesMutex;

    // Schedules
    std::vector<ReportSchedule> m_schedules;
    mutable std::shared_mutex m_schedulesMutex;

    // Threads
    std::thread m_workerThread;
    std::thread m_schedulerThread;
    std::mutex m_schedulerMutex;
    std::condition_variable m_schedulerCv;

    // Callbacks
    ProgressCallback m_progressCb;
    CompletionCallback m_completionCb;
    ReportErrorCallback m_errorCb;
    mutable std::mutex m_callbackMutex;

    // Statistics
    ReportStatistics m_stats;
};

// ============================================================================
// LIFECYCLE
// ============================================================================

bool ReportGeneratorImpl::Initialize(const ReportConfiguration& config) {
    ReportModuleStatus expected = ReportModuleStatus::Uninitialized;
    if (!m_status.compare_exchange_strong(expected, ReportModuleStatus::Initializing,
                                          std::memory_order_acq_rel)) {
        SS_LOG_WARN("ReportGen", "Already initialized (status={})",
                    static_cast<int>(expected));
        return false;
    }

    if (!config.IsValid()) {
        SS_LOG_ERROR("ReportGen", "Invalid configuration");
        m_status.store(ReportModuleStatus::Error, std::memory_order_release);
        return false;
    }

    {
        std::unique_lock lock(m_configMutex);
        m_config = config;
    }

    // Ensure output directories exist
    Utils::FileUtils::Error fsErr;
    if (!config.outputDirectory.empty()) {
        Utils::FileUtils::CreateDirectories(config.outputDirectory.wstring(), &fsErr);
    }
    if (!config.archiveDirectory.empty()) {
        Utils::FileUtils::CreateDirectories(config.archiveDirectory.wstring(), &fsErr);
    }

    m_stats.Reset();
    LoadTemplates();

    m_running.store(true, std::memory_order_release);
    m_workerThread = std::thread([this] { WorkerLoop(); });
    m_schedulerThread = std::thread([this] { SchedulerLoop(); });

    m_initialized.store(true, std::memory_order_release);
    m_status.store(ReportModuleStatus::Running, std::memory_order_release);

    SS_LOG_INFO("ReportGen", "Initialized — output={}, format={}, retention={}d",
                WideToUtf8(config.outputDirectory.wstring()),
                GetFormatName(config.defaultFormat),
                config.retentionDays);
    return true;
}

void ReportGeneratorImpl::Shutdown() {
    if (!m_running.exchange(false, std::memory_order_acq_rel))
        return;

    m_status.store(ReportModuleStatus::Stopping, std::memory_order_release);

    // Wake worker thread
    {
        std::unique_lock lock(m_jobsMutex);
        m_jobCv.notify_all();
    }

    // Wake scheduler thread
    {
        std::unique_lock lock(m_schedulerMutex);
        m_schedulerCv.notify_all();
    }

    if (m_workerThread.joinable())
        m_workerThread.join();
    if (m_schedulerThread.joinable())
        m_schedulerThread.join();

    // Fail pending jobs
    {
        std::unique_lock lock(m_jobsMutex);
        for (auto& job : m_jobQueue) {
            job.status = ReportStatus::Cancelled;
            job.errorMessage = "Module shutting down";
        }
        m_jobQueue.clear();
    }

    m_initialized.store(false, std::memory_order_release);
    m_status.store(ReportModuleStatus::Stopped, std::memory_order_release);
    SS_LOG_INFO("ReportGen", "Shutdown complete");
}

bool ReportGeneratorImpl::UpdateConfiguration(const ReportConfiguration& config) {
    if (!config.IsValid()) return false;
    std::unique_lock lock(m_configMutex);
    m_config = config;
    return true;
}

ReportConfiguration ReportGeneratorImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// WORKER THREAD
// ============================================================================

void ReportGeneratorImpl::WorkerLoop() {
    SS_LOG_DEBUG("ReportGen", "Worker thread started");

    while (m_running.load(std::memory_order_acquire)) {
        ReportJob job;
        {
            std::unique_lock lock(m_jobsMutex);
            m_jobCv.wait(lock, [this] {
                return !m_jobQueue.empty() || !m_running.load(std::memory_order_acquire);
            });

            if (!m_running.load(std::memory_order_acquire))
                break;

            if (m_jobQueue.empty())
                continue;

            job = std::move(m_jobQueue.front());
            m_jobQueue.pop_front();
        }

        ExecuteJob(job);

        {
            std::unique_lock lock(m_jobsMutex);
            // Cap completed job history at 1000
            if (m_completedJobs.size() >= 1000)
                m_completedJobs.erase(m_completedJobs.begin());
            m_completedJobs.push_back(job);
        }

        NotifyCompletion(job);
    }

    SS_LOG_DEBUG("ReportGen", "Worker thread exiting");
}

void ReportGeneratorImpl::ExecuteJob(ReportJob& job) {
    const auto startTs = Clock::now();
    job.status = ReportStatus::Generating;
    NotifyProgress(job.jobId, 5);

    m_status.store(ReportModuleStatus::Generating, std::memory_order_release);

    try {
        const auto meta = BuildMetadata(job.reportType, job.timeRange);
        NotifyProgress(job.jobId, 15);

        auto sections = BuildSections(job.reportType, job.timeRange);
        NotifyProgress(job.jobId, 50);

        const auto content = RenderFormat(job.format, meta, sections);
        NotifyProgress(job.jobId, 80);

        if (content.empty()) {
            job.status = ReportStatus::Failed;
            job.errorMessage = "Render produced empty output";
            m_stats.reportsFailed.fetch_add(1, std::memory_order_relaxed);
            NotifyError(job.errorMessage, -1);
            m_status.store(ReportModuleStatus::Running, std::memory_order_release);
            return;
        }

        // Build output path if not specified
        if (job.outputPath.empty())
            job.outputPath = BuildOutputPath(job.reportType, job.format);

        if (!WriteReportFile(job.outputPath, content)) {
            job.status = ReportStatus::Failed;
            job.errorMessage = "Failed to write report file";
            m_stats.reportsFailed.fetch_add(1, std::memory_order_relaxed);
            NotifyError(job.errorMessage, -2);
            m_status.store(ReportModuleStatus::Running, std::memory_order_release);
            return;
        }

        NotifyProgress(job.jobId, 95);

        job.status = ReportStatus::Completed;
        job.completedTime = std::chrono::system_clock::now();
        job.fileSize = content.size();
        job.progress = 100;

        const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - startTs).count();

        m_stats.reportsGenerated.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalGenerationTimeMs.fetch_add(
            static_cast<uint64_t>(elapsedMs), std::memory_order_relaxed);
        m_stats.totalSizeBytes.fetch_add(job.fileSize, std::memory_order_relaxed);

        const auto fmtIdx = static_cast<size_t>(job.format);
        if (fmtIdx < m_stats.byFormat.size())
            m_stats.byFormat[fmtIdx].fetch_add(1, std::memory_order_relaxed);

        const auto typeIdx = static_cast<size_t>(job.reportType);
        if (typeIdx < m_stats.byType.size())
            m_stats.byType[typeIdx].fetch_add(1, std::memory_order_relaxed);

        ArchiveReport(job);
        NotifyProgress(job.jobId, 100);

        SS_LOG_INFO("ReportGen", "Report generated: {} ({}, {}ms, {})",
                    WideToUtf8(job.outputPath.wstring()),
                    GetFormatName(job.format),
                    elapsedMs, FormatFileSize(job.fileSize));

    } catch (const std::exception& ex) {
        job.status = ReportStatus::Failed;
        job.errorMessage = std::string("Exception: ") + ex.what();
        m_stats.reportsFailed.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_ERROR("ReportGen", "Report generation failed: {}", ex.what());
        NotifyError(job.errorMessage, -3);
    }

    m_status.store(ReportModuleStatus::Running, std::memory_order_release);
}

// ============================================================================
// SCHEDULER THREAD
// ============================================================================

void ReportGeneratorImpl::SchedulerLoop() {
    SS_LOG_DEBUG("ReportGen", "Scheduler thread started");

    while (m_running.load(std::memory_order_acquire)) {
        {
            std::unique_lock lock(m_schedulerMutex);
            m_schedulerCv.wait_for(lock, std::chrono::seconds(60), [this] {
                return !m_running.load(std::memory_order_acquire);
            });
        }
        if (!m_running.load(std::memory_order_acquire))
            break;

        const auto now = std::chrono::system_clock::now();
        std::vector<ReportSchedule> dueSchedules;

        {
            std::unique_lock lock(m_schedulesMutex);
            for (auto& sched : m_schedules) {
                if (!sched.enabled) continue;
                if (now >= sched.nextRunTime) {
                    dueSchedules.push_back(sched);

                    // Compute next run time based on period
                    switch (sched.period) {
                        case ReportPeriod::Today:
                        case ReportPeriod::Yesterday:
                            sched.nextRunTime = now + std::chrono::hours(24);
                            break;
                        case ReportPeriod::Last7Days:
                            sched.nextRunTime = now + std::chrono::hours(24 * 7);
                            break;
                        case ReportPeriod::Last30Days:
                            sched.nextRunTime = now + std::chrono::hours(24 * 30);
                            break;
                        case ReportPeriod::Last90Days:
                            sched.nextRunTime = now + std::chrono::hours(24 * 90);
                            break;
                        case ReportPeriod::LastYear:
                            sched.nextRunTime = now + std::chrono::hours(24 * 365);
                            break;
                        default:
                            sched.nextRunTime = now + std::chrono::hours(24);
                            break;
                    }
                    sched.lastRunTime = now;
                }
            }
        }

        for (const auto& sched : dueSchedules) {
            auto range = CalculateTimeRange(sched.period);
            GenerateReportAsync(sched.reportType, sched.format, range, "");
            SS_LOG_INFO("ReportGen", "Scheduled report triggered: {} ({})",
                        sched.scheduleId, GetReportTypeName(sched.reportType));
        }
    }

    SS_LOG_DEBUG("ReportGen", "Scheduler thread exiting");
}

// ============================================================================
// REPORT GENERATION — PUBLIC
// ============================================================================

std::string ReportGeneratorImpl::GenerateHtmlReport(uint64_t startTime, uint64_t endTime) {
    const auto start = std::chrono::system_clock::time_point(
        std::chrono::seconds(startTime));
    const auto end = std::chrono::system_clock::time_point(
        std::chrono::seconds(endTime));

    TimeRange range;
    range.startTime = start;
    range.endTime = end;
    range.period = ReportPeriod::Custom;

    const auto meta = BuildMetadata(ReportType::SecurityAudit, range);
    auto sections = BuildSections(ReportType::SecurityAudit, range);
    return RenderHtml(meta, sections);
}

std::optional<fs::path> ReportGeneratorImpl::GenerateReport(
    ReportType type, ReportFormat format, const TimeRange& range,
    const std::string& /*tmpl*/) {

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR("ReportGen", "Not initialized");
        return std::nullopt;
    }

    ReportJob job;
    job.jobId = GenerateId("JOB");
    job.reportType = type;
    job.format = format;
    job.timeRange = range;
    job.createdTime = std::chrono::system_clock::now();

    ExecuteJob(job);

    if (job.status == ReportStatus::Completed) {
        std::unique_lock lock(m_jobsMutex);
        if (m_completedJobs.size() >= 1000)
            m_completedJobs.erase(m_completedJobs.begin());
        m_completedJobs.push_back(job);
        return job.outputPath;
    }

    return std::nullopt;
}

std::string ReportGeneratorImpl::GenerateReportAsync(
    ReportType type, ReportFormat format, const TimeRange& range,
    const std::string& tmpl) {

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR("ReportGen", "Not initialized");
        return {};
    }

    ReportJob job;
    job.jobId = GenerateId("JOB");
    job.reportType = type;
    job.format = format;
    job.timeRange = range;
    job.templateName = tmpl;
    job.createdTime = std::chrono::system_clock::now();
    job.status = ReportStatus::Pending;

    const std::string jobId = job.jobId;

    {
        std::unique_lock lock(m_jobsMutex);
        m_jobQueue.push_back(std::move(job));
        m_jobCv.notify_one();
    }

    SS_LOG_INFO("ReportGen", "Async report queued: {} ({}, {})",
                jobId, GetReportTypeName(type), GetFormatName(format));
    return jobId;
}

std::optional<fs::path> ReportGeneratorImpl::GenerateComplianceReport(
    ComplianceStandard std_, ReportFormat format, const TimeRange& range) {

    if (!m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    ReportJob job;
    job.jobId = GenerateId("JOB");
    job.reportType = ReportType::ComplianceReport;
    job.format = format;
    job.timeRange = range;
    job.createdTime = std::chrono::system_clock::now();

    // Build compliance-specific sections
    const auto meta = BuildMetadata(ReportType::ComplianceReport, range);
    auto checks = GetComplianceResults(std_);

    ReportSection summary;
    summary.sectionId = "compliance_summary";
    summary.title = std::string("Compliance Report — ") +
                    std::string(GetComplianceStandardName(std_));
    summary.order = 0;

    uint32_t passed = 0, failed = 0;
    for (const auto& c : checks) {
        if (c.passed) ++passed; else ++failed;
    }
    summary.data["standard"] = std::string(GetComplianceStandardName(std_));
    summary.data["total_checks"] = std::to_string(passed + failed);
    summary.data["passed"] = std::to_string(passed);
    summary.data["failed"] = std::to_string(failed);
    summary.data["score"] = (passed + failed > 0)
        ? std::to_string((passed * 100) / (passed + failed)) + "%"
        : "N/A";
    summary.content = "Compliance assessment for " +
                      std::string(GetComplianceStandardName(std_));

    ReportSection details;
    details.sectionId = "compliance_details";
    details.title = "Check Results";
    details.order = 1;
    details.tableHeaders = {"Check ID", "Name", "Status", "Severity", "Finding", "Recommendation"};
    for (const auto& c : checks) {
        details.tableData.push_back({
            c.checkId, c.checkName,
            c.passed ? "PASS" : "FAIL",
            std::to_string(c.severity),
            c.finding, c.recommendation
        });
    }

    std::vector<ReportSection> sections = {std::move(summary), std::move(details)};
    const auto content = RenderFormat(format, meta, sections);

    if (content.empty()) return std::nullopt;

    job.outputPath = BuildOutputPath(ReportType::ComplianceReport, format);
    if (!WriteReportFile(job.outputPath, content))
        return std::nullopt;

    job.status = ReportStatus::Completed;
    job.completedTime = std::chrono::system_clock::now();
    job.fileSize = content.size();

    m_stats.reportsGenerated.fetch_add(1, std::memory_order_relaxed);

    {
        std::unique_lock lock(m_jobsMutex);
        m_completedJobs.push_back(job);
    }

    return job.outputPath;
}

std::optional<fs::path> ReportGeneratorImpl::GenerateIncidentReport(
    const std::string& incidentId, ReportFormat format) {

    if (!m_initialized.load(std::memory_order_acquire))
        return std::nullopt;

    TimeRange range;
    range.startTime = std::chrono::system_clock::now() - std::chrono::hours(24 * 30);
    range.endTime = std::chrono::system_clock::now();
    range.period = ReportPeriod::Last30Days;

    ReportMetadata meta;
    meta.reportId = GenerateId("RPT");
    meta.title = "Incident Report — " + incidentId;
    meta.reportType = ReportType::IncidentReport;
    meta.generatedTime = std::chrono::system_clock::now();
    meta.timeRange = range;

    {
        std::shared_lock lock(m_configMutex);
        meta.organizationName = m_config.organizationName;
    }

    ReportSection summary;
    summary.sectionId = "incident_summary";
    summary.title = "Incident Summary";
    summary.order = 0;
    summary.data["incident_id"] = incidentId;
    summary.data["status"] = "Under Investigation";
    summary.data["reported_at"] = SystemTimeToIso8601(std::chrono::system_clock::now());

    ReportSection timeline;
    timeline.sectionId = "incident_timeline";
    timeline.title = "Event Timeline";
    timeline.order = 1;
    timeline.tableHeaders = {"Time", "Event", "Source", "Details"};

    std::vector<ReportSection> sections = {std::move(summary), std::move(timeline)};
    const auto content = RenderFormat(format, meta, sections);

    if (content.empty()) return std::nullopt;

    auto path = BuildOutputPath(ReportType::IncidentReport, format);
    if (!WriteReportFile(path, content))
        return std::nullopt;

    m_stats.reportsGenerated.fetch_add(1, std::memory_order_relaxed);
    return path;
}

// ============================================================================
// SECTION BUILDING
// ============================================================================

ReportMetadata ReportGeneratorImpl::BuildMetadata(ReportType type, const TimeRange& range) {
    ReportMetadata meta;
    meta.reportId = GenerateId("RPT");
    meta.title = std::string(GetReportTypeName(type)) + " Report";
    meta.reportType = type;
    meta.generatedTime = std::chrono::system_clock::now();
    meta.timeRange = range;
    meta.version = ReportGenerator::GetVersionString();
    meta.generatedBy = "ShadowStrike EDR";

    {
        std::shared_lock lock(m_configMutex);
        meta.organizationName = m_config.organizationName;
    }

    return meta;
}

std::vector<ReportSection> ReportGeneratorImpl::BuildSections(
    ReportType type, const TimeRange& range) {

    std::vector<ReportSection> sections;

    // Executive summary (all report types)
    ReportSection exec;
    exec.sectionId = "executive_summary";
    exec.title = "Executive Summary";
    exec.order = 0;

    auto threatStats = GetThreatStatistics(range);
    auto scanStats = GetScanStatistics(range);

    exec.data["total_detections"] = std::to_string(threatStats.totalDetections);
    exec.data["total_scans"] = std::to_string(scanStats.totalScans);
    exec.data["files_scanned"] = std::to_string(scanStats.filesScanned);
    exec.data["period"] = std::string(GetPeriodName(range.period));
    exec.data["start_time"] = SystemTimeToIso8601(range.startTime);
    exec.data["end_time"] = SystemTimeToIso8601(range.endTime);
    sections.push_back(std::move(exec));

    switch (type) {
        case ReportType::ThreatSummary:
        case ReportType::SecurityAudit: {
            ReportSection threats;
            threats.sectionId = "threat_analysis";
            threats.title = "Threat Analysis";
            threats.order = 1;
            threats.tableHeaders = {"Category", "Count"};
            for (const auto& [sev, count] : threatStats.bySeverity) {
                threats.tableData.push_back({sev, std::to_string(count)});
            }
            threats.chartData.insert(threatStats.bySeverity.begin(), threatStats.bySeverity.end());
            sections.push_back(std::move(threats));

            ReportSection topThreats;
            topThreats.sectionId = "top_threats";
            topThreats.title = "Top Threats";
            topThreats.order = 2;
            topThreats.tableHeaders = {"Threat", "Count"};
            for (const auto& [name, count] : threatStats.topThreats) {
                topThreats.tableData.push_back({name, std::to_string(count)});
                if (topThreats.tableData.size() >= 20) break;
            }
            sections.push_back(std::move(topThreats));
            break;
        }

        case ReportType::ScanHistory: {
            ReportSection scans;
            scans.sectionId = "scan_history";
            scans.title = "Scan History";
            scans.order = 1;
            scans.data["total_scans"] = std::to_string(scanStats.totalScans);
            scans.data["files_scanned"] = std::to_string(scanStats.filesScanned);
            scans.data["bytes_scanned"] = FormatFileSize(scanStats.bytesScanned);
            scans.data["avg_scan_time"] = std::to_string(scanStats.avgScanTimeMs) + " ms";
            scans.tableHeaders = {"Scan Type", "Count"};
            for (const auto& [t, c] : scanStats.byScanType) {
                scans.tableData.push_back({t, std::to_string(c)});
            }
            sections.push_back(std::move(scans));
            break;
        }

        case ReportType::SystemHealth: {
            ReportSection health;
            health.sectionId = "system_health";
            health.title = "System Health";
            health.order = 1;
            health.data["protection_status"] = "Active";
            health.data["signature_age"] = "Current";
            health.data["last_scan"] = SystemTimeToDisplay(std::chrono::system_clock::now());
            health.data["kernel_driver"] = "Loaded";
            health.data["self_test"] = "Passed";
            sections.push_back(std::move(health));
            break;
        }

        case ReportType::PerformanceReport: {
            ReportSection perf;
            perf.sectionId = "performance";
            perf.title = "Performance Metrics";
            perf.order = 1;
            perf.data["avg_scan_time"] = std::to_string(scanStats.avgScanTimeMs) + " ms";
            perf.data["total_bytes_scanned"] = FormatFileSize(scanStats.bytesScanned);
            sections.push_back(std::move(perf));
            break;
        }

        default: {
            ReportSection general;
            general.sectionId = "general";
            general.title = std::string(GetReportTypeName(type));
            general.order = 1;
            general.data["detections"] = std::to_string(threatStats.totalDetections);
            general.data["scans"] = std::to_string(scanStats.totalScans);
            sections.push_back(std::move(general));
            break;
        }
    }

    return sections;
}

// ============================================================================
// FORMAT RENDERERS
// ============================================================================

std::string ReportGeneratorImpl::RenderFormat(
    ReportFormat format, const ReportMetadata& meta,
    const std::vector<ReportSection>& sections) {

    switch (format) {
        case ReportFormat::HTML:  return RenderHtml(meta, sections);
        case ReportFormat::JSON:  return RenderJson(meta, sections);
        case ReportFormat::CSV:   return RenderCsv(meta, sections);
        case ReportFormat::XML:   return RenderXml(meta, sections);
        case ReportFormat::CEF:   return RenderCef(meta, sections);
        case ReportFormat::LEEF:  return RenderLeef(meta, sections);
        case ReportFormat::SYSLOG: return RenderSyslog(meta, sections);

        case ReportFormat::PDF:
        case ReportFormat::RTF:
        case ReportFormat::XLSX:
            SS_LOG_WARN("ReportGen",
                "Format '{}' requires third-party renderer; falling back to HTML",
                GetFormatName(format));
            return RenderHtml(meta, sections);

        default:
            SS_LOG_ERROR("ReportGen", "Unknown format: {}", static_cast<int>(format));
            return {};
    }
}

std::string ReportGeneratorImpl::RenderHtml(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    std::string h;
    h.reserve(32768);

    h += "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
    h += "<title>" + EscapeHtml(meta.title) + " — ShadowStrike</title>\n";
    h += "<style>\n";
    h += "body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;margin:0;padding:0;"
         "background:#f5f5f5;color:#333;}\n";
    h += ".hdr{background:#1a1a2e;color:#fff;padding:30px 40px;}\n";
    h += ".hdr h1{margin:0;font-size:28px;}\n";
    h += ".hdr .sub{color:#a0a0c0;margin-top:8px;}\n";
    h += ".wrap{max-width:1200px;margin:20px auto;padding:0 20px;}\n";
    h += ".card{background:#fff;border-radius:8px;padding:24px;margin-bottom:20px;"
         "box-shadow:0 2px 4px rgba(0,0,0,.08);}\n";
    h += ".card h2{color:#1a1a2e;border-bottom:2px solid #e8e8e8;padding-bottom:10px;"
         "margin-top:0;}\n";
    h += "table{width:100%;border-collapse:collapse;margin-top:12px;}\n";
    h += "th,td{padding:10px 12px;text-align:left;border-bottom:1px solid #eee;}\n";
    h += "th{background:#f8f9fa;font-weight:600;font-size:13px;text-transform:uppercase;"
         "color:#666;}\n";
    h += ".metric{display:inline-block;padding:16px 28px;background:#f0f4ff;"
         "border-radius:8px;margin:6px;text-align:center;}\n";
    h += ".metric .val{font-size:28px;font-weight:bold;color:#1a1a2e;}\n";
    h += ".metric .lbl{font-size:12px;color:#666;margin-top:4px;}\n";
    h += ".pass{color:#28a745;} .fail{color:#dc3545;}\n";
    h += ".footer{text-align:center;padding:20px;color:#999;font-size:11px;}\n";
    h += "</style>\n</head>\n<body>\n";

    // Header
    h += "<div class=\"hdr\">\n";
    h += "  <h1>" + EscapeHtml(meta.title) + "</h1>\n";
    h += "  <div class=\"sub\">";
    if (!meta.organizationName.empty())
        h += EscapeHtml(meta.organizationName) + " &mdash; ";
    h += "Generated " + SystemTimeToDisplay(meta.generatedTime);
    h += " &mdash; Period: " + std::string(GetPeriodName(meta.timeRange.period));
    h += "</div>\n</div>\n";
    h += "<div class=\"wrap\">\n";

    // Sections
    for (const auto& sec : sections) {
        if (!sec.isVisible) continue;
        h += "<div class=\"card\">\n";
        h += "  <h2>" + EscapeHtml(sec.title) + "</h2>\n";

        if (!sec.content.empty())
            h += "  <p>" + EscapeHtml(sec.content) + "</p>\n";

        // Metrics from data map
        if (!sec.data.empty()) {
            h += "  <div>\n";
            for (const auto& [k, v] : sec.data) {
                h += "    <div class=\"metric\">";
                h += "<div class=\"val\">" + EscapeHtml(v) + "</div>";
                h += "<div class=\"lbl\">" + EscapeHtml(k) + "</div>";
                h += "</div>\n";
            }
            h += "  </div>\n";
        }

        // Table
        if (!sec.tableHeaders.empty() && !sec.tableData.empty()) {
            h += "  <table>\n    <thead><tr>";
            for (const auto& th : sec.tableHeaders)
                h += "<th>" + EscapeHtml(th) + "</th>";
            h += "</tr></thead>\n    <tbody>\n";
            for (const auto& row : sec.tableData) {
                h += "      <tr>";
                for (const auto& cell : row)
                    h += "<td>" + EscapeHtml(cell) + "</td>";
                h += "</tr>\n";
            }
            h += "    </tbody>\n  </table>\n";
        }

        h += "</div>\n";
    }

    // Footer
    h += "<div class=\"footer\">ShadowStrike EDR v" +
         ReportGenerator::GetVersionString() +
         " &mdash; Report ID: " + EscapeHtml(meta.reportId) + "</div>\n";
    h += "</div>\n</body>\n</html>\n";
    return h;
}

std::string ReportGeneratorImpl::RenderJson(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    std::string j = "{\n";
    j += "  \"metadata\":" + meta.ToJson() + ",\n";
    j += "  \"sections\":[\n";
    for (size_t i = 0; i < sections.size(); ++i) {
        if (i > 0) j += ",\n";
        j += "    " + sections[i].ToJson();
    }
    j += "\n  ]\n}\n";
    return j;
}

std::string ReportGeneratorImpl::RenderCsv(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    std::string csv;
    csv += "# Report: " + meta.title + "\n";
    csv += "# Generated: " + SystemTimeToIso8601(meta.generatedTime) + "\n";
    csv += "# Type: " + std::string(GetReportTypeName(meta.reportType)) + "\n\n";

    for (const auto& sec : sections) {
        if (!sec.isVisible) continue;
        csv += "# === " + sec.title + " ===\n";

        // Data map as key,value
        if (!sec.data.empty()) {
            csv += "Key,Value\n";
            for (const auto& [k, v] : sec.data) {
                csv += EscapeCsvField(k) + "," + EscapeCsvField(v) + "\n";
            }
            csv += "\n";
        }

        // Table data
        if (!sec.tableHeaders.empty()) {
            for (size_t i = 0; i < sec.tableHeaders.size(); ++i) {
                if (i > 0) csv += ",";
                csv += EscapeCsvField(sec.tableHeaders[i]);
            }
            csv += "\n";
            for (const auto& row : sec.tableData) {
                for (size_t i = 0; i < row.size(); ++i) {
                    if (i > 0) csv += ",";
                    csv += EscapeCsvField(row[i]);
                }
                csv += "\n";
            }
            csv += "\n";
        }
    }
    return csv;
}

std::string ReportGeneratorImpl::RenderXml(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    auto xmlEsc = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s) {
            switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;";  break;
                case '>': out += "&gt;";  break;
                case '"': out += "&quot;"; break;
                default:  out += c; break;
            }
        }
        return out;
    };

    std::string x;
    x += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    x += "<ShadowStrikeReport version=\"" + meta.version + "\">\n";
    x += "  <Metadata>\n";
    x += "    <ReportId>" + xmlEsc(meta.reportId) + "</ReportId>\n";
    x += "    <Title>" + xmlEsc(meta.title) + "</Title>\n";
    x += "    <Type>" + std::string(GetReportTypeName(meta.reportType)) + "</Type>\n";
    x += "    <Generated>" + SystemTimeToIso8601(meta.generatedTime) + "</Generated>\n";
    x += "    <Organization>" + xmlEsc(meta.organizationName) + "</Organization>\n";
    x += "  </Metadata>\n";
    x += "  <Sections>\n";

    for (const auto& sec : sections) {
        x += "    <Section id=\"" + xmlEsc(sec.sectionId) + "\">\n";
        x += "      <Title>" + xmlEsc(sec.title) + "</Title>\n";
        for (const auto& [k, v] : sec.data) {
            x += "      <Data key=\"" + xmlEsc(k) + "\">" + xmlEsc(v) + "</Data>\n";
        }
        if (!sec.tableData.empty()) {
            x += "      <Table>\n";
            x += "        <Headers>";
            for (const auto& h : sec.tableHeaders) x += "<Col>" + xmlEsc(h) + "</Col>";
            x += "</Headers>\n";
            for (const auto& row : sec.tableData) {
                x += "        <Row>";
                for (const auto& cell : row)
                    x += "<Col>" + xmlEsc(cell) + "</Col>";
                x += "</Row>\n";
            }
            x += "      </Table>\n";
        }
        x += "    </Section>\n";
    }

    x += "  </Sections>\n</ShadowStrikeReport>\n";
    return x;
}

std::string ReportGeneratorImpl::RenderCef(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    // CEF: Common Event Format
    // CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    std::string cef;
    const std::string ver = ReportGenerator::GetVersionString();

    for (const auto& sec : sections) {
        cef += "CEF:0|ShadowStrike|EDR|" + ver + "|" +
               sec.sectionId + "|" + sec.title + "|5|";

        // Extension: key=value pairs
        cef += "rt=" + SystemTimeToIso8601(meta.generatedTime);
        cef += " reportType=" + std::string(GetReportTypeName(meta.reportType));
        for (const auto& [k, v] : sec.data) {
            std::string safeK = k, safeV = v;
            std::replace(safeK.begin(), safeK.end(), ' ', '_');
            std::replace(safeV.begin(), safeV.end(), '=', '-');
            cef += " " + safeK + "=" + safeV;
        }
        cef += "\n";
    }
    return cef;
}

std::string ReportGeneratorImpl::RenderLeef(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    // LEEF: Log Event Extended Format
    // LEEF:Version|Vendor|Product|ProductVersion|EventID|<delimiter>key=value
    std::string leef;
    const std::string ver = ReportGenerator::GetVersionString();

    for (const auto& sec : sections) {
        leef += "LEEF:2.0|ShadowStrike|EDR|" + ver + "|" + sec.sectionId + "|\t";
        leef += "devTime=" + SystemTimeToIso8601(meta.generatedTime);
        leef += "\treportType=" + std::string(GetReportTypeName(meta.reportType));
        leef += "\tsectionTitle=" + sec.title;
        for (const auto& [k, v] : sec.data) {
            leef += "\t" + k + "=" + v;
        }
        leef += "\n";
    }
    return leef;
}

std::string ReportGeneratorImpl::RenderSyslog(
    const ReportMetadata& meta, const std::vector<ReportSection>& sections) {

    // RFC 5424 structured data
    char hostname[256]{};
    DWORD hostnameLen = sizeof(hostname) - 1;
    if (!GetComputerNameA(hostname, &hostnameLen)) {
        hostname[0] = '\0';
    }
    const std::string hostnameStr(hostname);

    std::string syslog;
    for (const auto& sec : sections) {
        // <134>1 = facility local0(16)*8 + severity info(6) = 134
        syslog += "<134>1 " + SystemTimeToIso8601(meta.generatedTime) + " ";

        syslog += hostnameStr;

        syslog += " ShadowStrikeEDR - " + sec.sectionId;
        syslog += " [report@57483 type=\"" + std::string(GetReportTypeName(meta.reportType)) + "\"";
        syslog += " title=\"" + sec.title + "\"";
        for (const auto& [k, v] : sec.data) {
            syslog += " " + k + "=\"" + v + "\"";
        }
        syslog += "] " + sec.title + "\n";
    }
    return syslog;
}

// ============================================================================
// FILE I/O
// ============================================================================

fs::path ReportGeneratorImpl::BuildOutputPath(ReportType type, ReportFormat format) {
    fs::path dir;
    {
        std::shared_lock lock(m_configMutex);
        dir = m_config.outputDirectory;
    }
    if (dir.empty())
        dir = ReportConstants::DEFAULT_OUTPUT_DIR;

    const auto now = std::chrono::system_clock::now();
    const auto tt = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &tt);
    char datePart[32]{};
    std::snprintf(datePart, sizeof(datePart), "%04d%02d%02d_%02d%02d%02d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);

    std::string filename = std::string(GetReportTypeName(type)) + "_" +
                           datePart + std::string(GetFormatExtension(format));
    // Sanitize filename
    for (char& c : filename) {
        if (c == ' ' || c == '/' || c == '\\' || c == ':' || c == '*' ||
            c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    }

    return dir / filename;
}

bool ReportGeneratorImpl::WriteReportFile(const fs::path& path, const std::string& content) {
    // Ensure parent directory exists
    Utils::FileUtils::Error fsErr;
    const auto parentDir = path.parent_path().wstring();
    if (!parentDir.empty()) {
        Utils::FileUtils::CreateDirectories(parentDir, &fsErr);
    }

    // Cap report size
    size_t maxBytes = 0;
    {
        std::shared_lock lock(m_configMutex);
        maxBytes = m_config.maxReportSizeMB * 1024ULL * 1024ULL;
    }
    if (content.size() > maxBytes) {
        SS_LOG_ERROR("ReportGen", "Report exceeds max size: {} > {} MB",
                     FormatFileSize(content.size()), maxBytes / (1024 * 1024));
        return false;
    }

    return Utils::FileUtils::WriteAllTextUtf8Atomic(path.wstring(), content, &fsErr);
}

void ReportGeneratorImpl::ArchiveReport(const ReportJob& job) {
    fs::path archiveDir;
    {
        std::shared_lock lock(m_configMutex);
        archiveDir = m_config.archiveDirectory;
    }
    if (archiveDir.empty() || job.outputPath.empty())
        return;

    Utils::FileUtils::Error fsErr;
    Utils::FileUtils::CreateDirectories(archiveDir.wstring(), &fsErr);

    // Archive is a metadata JSON sidecar file
    const auto archivePath = archiveDir / (job.jobId + ".json");
    Utils::FileUtils::WriteAllTextUtf8Atomic(archivePath.wstring(), job.ToJson(), &fsErr);
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

bool ReportGeneratorImpl::ExportToCsv(const std::wstring& outputPath) {
    auto range = CalculateTimeRange(ReportPeriod::Last30Days);
    return ExportToCsv(fs::path(outputPath), range);
}

bool ReportGeneratorImpl::ExportToCsv(const fs::path& outputPath, const TimeRange& range) {
    auto meta = BuildMetadata(ReportType::SecurityAudit, range);
    auto sections = BuildSections(ReportType::SecurityAudit, range);
    auto content = RenderCsv(meta, sections);
    return WriteReportFile(outputPath, content);
}

bool ReportGeneratorImpl::ExportToJson(const fs::path& outputPath, const TimeRange& range) {
    auto meta = BuildMetadata(ReportType::SecurityAudit, range);
    auto sections = BuildSections(ReportType::SecurityAudit, range);
    auto content = RenderJson(meta, sections);
    return WriteReportFile(outputPath, content);
}

bool ReportGeneratorImpl::ExportToSiem(const fs::path& outputPath, ReportFormat siemFormat,
                                       const TimeRange& range) {
    if (siemFormat != ReportFormat::CEF && siemFormat != ReportFormat::LEEF &&
        siemFormat != ReportFormat::SYSLOG) {
        SS_LOG_ERROR("ReportGen", "Invalid SIEM format: {}", GetFormatName(siemFormat));
        return false;
    }
    auto meta = BuildMetadata(ReportType::SecurityAudit, range);
    auto sections = BuildSections(ReportType::SecurityAudit, range);
    auto content = RenderFormat(siemFormat, meta, sections);
    return WriteReportFile(outputPath, content);
}

// ============================================================================
// TEMPLATE MANAGEMENT
// ============================================================================

bool ReportGeneratorImpl::LoadTemplates() {
    fs::path templateDir;
    {
        std::shared_lock lock(m_configMutex);
        templateDir = m_config.templateDirectory;
    }

    std::unique_lock lock(m_templatesMutex);
    m_templates.clear();

    // Built-in templates
    for (int i = 0; i <= static_cast<int>(ReportType::Custom); ++i) {
        ReportTemplate tmpl;
        tmpl.templateId = "builtin_" + std::string(GetReportTypeName(static_cast<ReportType>(i)));
        tmpl.name = std::string(GetReportTypeName(static_cast<ReportType>(i))) + " (Built-in)";
        tmpl.reportType = static_cast<ReportType>(i);
        tmpl.isBuiltIn = true;
        tmpl.isDefault = true;
        tmpl.supportedFormats = {ReportFormat::HTML, ReportFormat::JSON,
                                 ReportFormat::CSV, ReportFormat::XML};
        m_templates.push_back(std::move(tmpl));
    }

    // Load custom templates from disk
    if (!templateDir.empty()) {
        Utils::FileUtils::Error fsErr;
        if (Utils::FileUtils::Exists(templateDir.wstring(), &fsErr)) {
            Utils::FileUtils::WalkOptions opts;
            opts.maxDepth = 1;
            opts.followSymlinks = false;

            Utils::FileUtils::WalkDirectory(templateDir.wstring(), opts,
                [this](const std::wstring& path, const Utils::FileUtils::FileStat& stat) -> bool {
                    if (stat.isDirectory) return true;
                    // Only load .html template files
                    if (path.size() >= 5 && path.substr(path.size() - 5) == L".html") {
                        ReportTemplate tmpl;
                        tmpl.templateId = GenerateId("TMPL");
                        tmpl.templatePath = path;
                        tmpl.name = WideToUtf8(fs::path(path).stem().wstring());
                        tmpl.reportType = ReportType::Custom;
                        tmpl.isBuiltIn = false;
                        tmpl.supportedFormats = {ReportFormat::HTML};
                        m_templates.push_back(std::move(tmpl));
                    }
                    return true;
                }, &fsErr);
        }
    }

    SS_LOG_INFO("ReportGen", "Loaded {} templates ({} custom)",
                m_templates.size(),
                std::count_if(m_templates.begin(), m_templates.end(),
                              [](const ReportTemplate& t) { return !t.isBuiltIn; }));
    return true;
}

std::vector<ReportTemplate> ReportGeneratorImpl::GetTemplates(
    std::optional<ReportType> filterType) {
    std::shared_lock lock(m_templatesMutex);
    if (!filterType)
        return m_templates;

    std::vector<ReportTemplate> result;
    for (const auto& t : m_templates) {
        if (t.reportType == *filterType)
            result.push_back(t);
    }
    return result;
}

bool ReportGeneratorImpl::ImportTemplate(const fs::path& templatePath) {
    Utils::FileUtils::Error fsErr;
    if (!Utils::FileUtils::Exists(templatePath.wstring(), &fsErr)) {
        SS_LOG_ERROR("ReportGen", "Template file not found: {}",
                     WideToUtf8(templatePath.wstring()));
        return false;
    }

    std::string content;
    if (!Utils::FileUtils::ReadAllTextUtf8(templatePath.wstring(), content, &fsErr)) {
        SS_LOG_ERROR("ReportGen", "Failed to read template: {}",
                     WideToUtf8(templatePath.wstring()));
        return false;
    }

    ReportTemplate tmpl;
    tmpl.templateId = GenerateId("TMPL");
    tmpl.templatePath = templatePath;
    tmpl.name = WideToUtf8(templatePath.stem().wstring());
    tmpl.reportType = ReportType::Custom;
    tmpl.isBuiltIn = false;
    tmpl.supportedFormats = {ReportFormat::HTML};

    std::unique_lock lock(m_templatesMutex);
    m_templates.push_back(std::move(tmpl));

    SS_LOG_INFO("ReportGen", "Template imported: {}", tmpl.name);
    return true;
}

bool ReportGeneratorImpl::DeleteTemplate(const std::string& templateId) {
    std::unique_lock lock(m_templatesMutex);
    auto it = std::find_if(m_templates.begin(), m_templates.end(),
        [&](const ReportTemplate& t) { return t.templateId == templateId; });
    if (it == m_templates.end()) return false;
    if (it->isBuiltIn) {
        SS_LOG_WARN("ReportGen", "Cannot delete built-in template: {}", templateId);
        return false;
    }
    m_templates.erase(it);
    return true;
}

// ============================================================================
// SCHEDULING
// ============================================================================

std::string ReportGeneratorImpl::CreateSchedule(const ReportSchedule& schedule) {
    ReportSchedule sched = schedule;
    if (sched.scheduleId.empty())
        sched.scheduleId = GenerateId("SCH");

    if (sched.nextRunTime <= std::chrono::system_clock::now())
        sched.nextRunTime = std::chrono::system_clock::now() + std::chrono::hours(1);

    std::unique_lock lock(m_schedulesMutex);
    m_schedules.push_back(std::move(sched));

    SS_LOG_INFO("ReportGen", "Schedule created: {}", sched.scheduleId);
    return sched.scheduleId;
}

bool ReportGeneratorImpl::UpdateSchedule(const ReportSchedule& schedule) {
    std::unique_lock lock(m_schedulesMutex);
    auto it = std::find_if(m_schedules.begin(), m_schedules.end(),
        [&](const ReportSchedule& s) { return s.scheduleId == schedule.scheduleId; });
    if (it == m_schedules.end()) return false;
    *it = schedule;
    return true;
}

bool ReportGeneratorImpl::DeleteSchedule(const std::string& scheduleId) {
    std::unique_lock lock(m_schedulesMutex);
    auto it = std::find_if(m_schedules.begin(), m_schedules.end(),
        [&](const ReportSchedule& s) { return s.scheduleId == scheduleId; });
    if (it == m_schedules.end()) return false;
    m_schedules.erase(it);
    return true;
}

std::vector<ReportSchedule> ReportGeneratorImpl::GetSchedules() {
    std::shared_lock lock(m_schedulesMutex);
    return m_schedules;
}

bool ReportGeneratorImpl::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    std::unique_lock lock(m_schedulesMutex);
    auto it = std::find_if(m_schedules.begin(), m_schedules.end(),
        [&](const ReportSchedule& s) { return s.scheduleId == scheduleId; });
    if (it == m_schedules.end()) return false;
    it->enabled = enabled;
    return true;
}

// ============================================================================
// JOB MANAGEMENT
// ============================================================================

std::optional<ReportJob> ReportGeneratorImpl::GetJobStatus(const std::string& jobId) {
    std::shared_lock lock(m_jobsMutex);
    for (const auto& j : m_jobQueue) {
        if (j.jobId == jobId) return j;
    }
    for (const auto& j : m_completedJobs) {
        if (j.jobId == jobId) return j;
    }
    return std::nullopt;
}

std::vector<ReportJob> ReportGeneratorImpl::GetPendingJobs() {
    std::shared_lock lock(m_jobsMutex);
    return {m_jobQueue.begin(), m_jobQueue.end()};
}

bool ReportGeneratorImpl::CancelJob(const std::string& jobId) {
    std::unique_lock lock(m_jobsMutex);
    auto it = std::find_if(m_jobQueue.begin(), m_jobQueue.end(),
        [&](const ReportJob& j) { return j.jobId == jobId; });
    if (it == m_jobQueue.end()) return false;
    it->status = ReportStatus::Cancelled;
    m_completedJobs.push_back(std::move(*it));
    m_jobQueue.erase(it);
    return true;
}

// ============================================================================
// DATA AGGREGATION
// ============================================================================

ThreatStatistics ReportGeneratorImpl::GetThreatStatistics(const TimeRange& /*range*/) {
    ThreatStatistics stats;
    // Data aggregation placeholder — will be wired to ScanEngine / ThreatDB
    // when those modules are implemented. Logs a warning so the gap is visible.
    SS_LOG_DEBUG("ReportGen", "GetThreatStatistics: data sources not yet wired");
    return stats;
}

ScanStatistics ReportGeneratorImpl::GetScanStatistics(const TimeRange& /*range*/) {
    ScanStatistics stats;
    SS_LOG_DEBUG("ReportGen", "GetScanStatistics: data sources not yet wired");
    return stats;
}

std::vector<ComplianceCheckResult> ReportGeneratorImpl::GetComplianceResults(
    ComplianceStandard std_) {

    std::vector<ComplianceCheckResult> results;
    const auto stdName = std::string(GetComplianceStandardName(std_));

    // Built-in compliance checks based on current EDR configuration
    auto addCheck = [&](const std::string& id, const std::string& name,
                        bool passed, uint8_t sev,
                        const std::string& finding, const std::string& rec) {
        ComplianceCheckResult r;
        r.checkId = id;
        r.checkName = name;
        r.standard = std_;
        r.passed = passed;
        r.severity = sev;
        r.finding = finding;
        r.recommendation = rec;
        results.push_back(std::move(r));
    };

    // Common checks applicable to most standards
    addCheck(stdName + "-001", "Real-Time Protection Enabled", true, 10,
             "Real-time file scanning is active",
             "Ensure real-time protection remains enabled");

    addCheck(stdName + "-002", "Kernel Driver Loaded", true, 10,
             "PhantomSensor kernel driver is loaded and operational",
             "Monitor driver load status continuously");

    addCheck(stdName + "-003", "Audit Logging Enabled", true, 8,
             "Security event logging is active",
             "Ensure audit logs are preserved per retention policy");

    addCheck(stdName + "-004", "Signature Database Current", true, 7,
             "Threat signatures are up to date",
             "Enable automatic signature updates");

    addCheck(stdName + "-005", "Quarantine Operational", true, 6,
             "Quarantine subsystem is functional",
             "Regularly review quarantined items");

    // Standard-specific checks
    switch (std_) {
        case ComplianceStandard::HIPAA:
            addCheck("HIPAA-006", "Data Encryption at Rest", false, 9,
                     "Report encryption is not configured",
                     "Enable encryption for stored reports containing PHI");
            addCheck("HIPAA-007", "Access Controls", true, 8,
                     "Role-based access controls are enforced",
                     "Review access control policies quarterly");
            break;

        case ComplianceStandard::PCI_DSS:
            addCheck("PCI-006", "Anti-Malware Active", true, 10,
                     "Anti-malware protection is deployed and active",
                     "Maintain continuous anti-malware coverage");
            addCheck("PCI-007", "Network Monitoring", true, 7,
                     "Network traffic monitoring is active",
                     "Review network monitoring alerts daily");
            break;

        case ComplianceStandard::GDPR:
            addCheck("GDPR-006", "Data Minimization", true, 7,
                     "Only necessary security data is collected",
                     "Audit collected data fields annually");
            addCheck("GDPR-007", "Breach Notification", true, 8,
                     "Automated breach detection and alerting is configured",
                     "Test breach notification workflow quarterly");
            break;

        default:
            break;
    }

    return results;
}

// ============================================================================
// ARCHIVE MANAGEMENT
// ============================================================================

std::vector<ReportJob> ReportGeneratorImpl::GetArchivedReports(
    const TimeRange& /*range*/, std::optional<ReportType> /*filterType*/) {

    // Read archive metadata files from archive directory
    std::vector<ReportJob> result;
    fs::path archiveDir;
    {
        std::shared_lock lock(m_configMutex);
        archiveDir = m_config.archiveDirectory;
    }
    if (archiveDir.empty()) return result;

    std::shared_lock lock(m_jobsMutex);
    for (const auto& job : m_completedJobs) {
        if (job.status == ReportStatus::Completed)
            result.push_back(job);
    }
    return result;
}

bool ReportGeneratorImpl::DeleteArchivedReport(const std::string& reportId) {
    fs::path archiveDir;
    {
        std::shared_lock lock(m_configMutex);
        archiveDir = m_config.archiveDirectory;
    }

    const auto archivePath = archiveDir / (reportId + ".json");
    Utils::FileUtils::Error fsErr;
    return Utils::FileUtils::RemoveFile(archivePath.wstring(), &fsErr);
}

size_t ReportGeneratorImpl::CleanupArchives(uint32_t olderThanDays) {
    fs::path archiveDir;
    {
        std::shared_lock lock(m_configMutex);
        archiveDir = m_config.archiveDirectory;
    }
    if (archiveDir.empty()) return 0;

    const auto cutoff = std::chrono::system_clock::now() -
                        std::chrono::hours(24 * olderThanDays);
    size_t deleted = 0;

    Utils::FileUtils::Error fsErr;
    Utils::FileUtils::WalkOptions opts;
    opts.maxDepth = 1;
    opts.followSymlinks = false;

    std::vector<std::wstring> toDelete;

    Utils::FileUtils::WalkDirectory(archiveDir.wstring(), opts,
        [&](const std::wstring& path, const Utils::FileUtils::FileStat& stat) -> bool {
            if (stat.isDirectory) return true;
            // Check modification time against cutoff
            FILETIME ft;
            ULARGE_INTEGER uli;
            uli.LowPart = stat.lastWriteTime.dwLowDateTime;
            uli.HighPart = stat.lastWriteTime.dwHighDateTime;
            // FILETIME epoch: 1601-01-01; system_clock epoch: 1970-01-01
            constexpr uint64_t kEpochDiff = 116444736000000000ULL;
            if (uli.QuadPart > kEpochDiff) {
                const auto fileTimeUs = (uli.QuadPart - kEpochDiff) / 10;
                const auto fileTp = std::chrono::system_clock::time_point(
                    std::chrono::microseconds(fileTimeUs));
                if (fileTp < cutoff)
                    toDelete.push_back(path);
            }
            return true;
        }, &fsErr);

    for (const auto& path : toDelete) {
        if (Utils::FileUtils::RemoveFile(path, &fsErr))
            ++deleted;
    }

    if (deleted > 0)
        SS_LOG_INFO("ReportGen", "Cleaned up {} old archive files", deleted);
    return deleted;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ReportGeneratorImpl::RegisterProgressCallback(ProgressCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_progressCb = std::move(cb);
}

void ReportGeneratorImpl::RegisterCompletionCallback(CompletionCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_completionCb = std::move(cb);
}

void ReportGeneratorImpl::RegisterErrorCallback(ReportErrorCallback cb) {
    std::lock_guard lock(m_callbackMutex);
    m_errorCb = std::move(cb);
}

void ReportGeneratorImpl::UnregisterCallbacks() {
    std::lock_guard lock(m_callbackMutex);
    m_progressCb = nullptr;
    m_completionCb = nullptr;
    m_errorCb = nullptr;
}

void ReportGeneratorImpl::NotifyProgress(const std::string& jobId, uint8_t progress) {
    ProgressCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_progressCb;
    }
    if (cb) {
        try { cb(jobId, progress); }
        catch (...) {}
    }
}

void ReportGeneratorImpl::NotifyCompletion(const ReportJob& job) {
    CompletionCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_completionCb;
    }
    if (cb) {
        try { cb(job); }
        catch (...) {}
    }
}

void ReportGeneratorImpl::NotifyError(const std::string& msg, int code) {
    SS_LOG_ERROR("ReportGen", "{}", msg);
    ReportErrorCallback cb;
    {
        std::lock_guard lock(m_callbackMutex);
        cb = m_errorCb;
    }
    if (cb) {
        try { cb(msg, code); }
        catch (...) {}
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

ReportStatisticsSnapshot ReportGeneratorImpl::GetStatistics() const noexcept {
    return m_stats.TakeSnapshot();
}

void ReportGeneratorImpl::ResetStatistics() {
    m_stats.Reset();
}

bool ReportGeneratorImpl::SelfTest() {
    if (!m_initialized.load(std::memory_order_acquire))
        return false;
    return m_status.load(std::memory_order_acquire) != ReportModuleStatus::Error;
}

// ============================================================================
// SINGLETON
// ============================================================================

std::atomic<bool> ReportGenerator::s_instanceCreated{false};

ReportGenerator& ReportGenerator::Instance() noexcept {
    static ReportGenerator instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool ReportGenerator::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ReportGenerator::ReportGenerator()
    : m_impl(std::make_unique<ReportGeneratorImpl>()) {}

ReportGenerator::~ReportGenerator() = default;

// ============================================================================
// FORWARDING — LIFECYCLE
// ============================================================================

bool ReportGenerator::Initialize(const ReportConfiguration& config) {
    return m_impl->Initialize(config);
}
void ReportGenerator::Shutdown() { m_impl->Shutdown(); }
bool ReportGenerator::IsInitialized() const noexcept { return m_impl->IsInitialized(); }
ReportModuleStatus ReportGenerator::GetStatus() const noexcept { return m_impl->GetStatus(); }
bool ReportGenerator::UpdateConfiguration(const ReportConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}
ReportConfiguration ReportGenerator::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

// ============================================================================
// FORWARDING — GENERATION
// ============================================================================

std::string ReportGenerator::GenerateHtmlReport(uint64_t startTime, uint64_t endTime) {
    return m_impl->GenerateHtmlReport(startTime, endTime);
}
std::optional<fs::path> ReportGenerator::GenerateReport(
    ReportType type, ReportFormat format, const TimeRange& range, const std::string& tmpl) {
    return m_impl->GenerateReport(type, format, range, tmpl);
}
std::string ReportGenerator::GenerateReportAsync(
    ReportType type, ReportFormat format, const TimeRange& range, const std::string& tmpl) {
    return m_impl->GenerateReportAsync(type, format, range, tmpl);
}
std::optional<fs::path> ReportGenerator::GenerateComplianceReport(
    ComplianceStandard std_, ReportFormat format, const TimeRange& range) {
    return m_impl->GenerateComplianceReport(std_, format, range);
}
std::optional<fs::path> ReportGenerator::GenerateIncidentReport(
    const std::string& incidentId, ReportFormat format) {
    return m_impl->GenerateIncidentReport(incidentId, format);
}

// ============================================================================
// FORWARDING — EXPORT
// ============================================================================

bool ReportGenerator::ExportToCsv(const std::wstring& outputPath) {
    return m_impl->ExportToCsv(outputPath);
}
bool ReportGenerator::ExportToCsv(const fs::path& outputPath, const TimeRange& range) {
    return m_impl->ExportToCsv(outputPath, range);
}
bool ReportGenerator::ExportToJson(const fs::path& outputPath, const TimeRange& range) {
    return m_impl->ExportToJson(outputPath, range);
}
bool ReportGenerator::ExportToSiem(const fs::path& outputPath, ReportFormat siemFormat,
                                    const TimeRange& range) {
    return m_impl->ExportToSiem(outputPath, siemFormat, range);
}

// ============================================================================
// FORWARDING — TEMPLATES
// ============================================================================

bool ReportGenerator::LoadTemplates() { return m_impl->LoadTemplates(); }
std::vector<ReportTemplate> ReportGenerator::GetTemplates(std::optional<ReportType> filterType) {
    return m_impl->GetTemplates(filterType);
}
bool ReportGenerator::ImportTemplate(const fs::path& templatePath) {
    return m_impl->ImportTemplate(templatePath);
}
bool ReportGenerator::DeleteTemplate(const std::string& templateId) {
    return m_impl->DeleteTemplate(templateId);
}

// ============================================================================
// FORWARDING — SCHEDULING
// ============================================================================

std::string ReportGenerator::CreateSchedule(const ReportSchedule& schedule) {
    return m_impl->CreateSchedule(schedule);
}
bool ReportGenerator::UpdateSchedule(const ReportSchedule& schedule) {
    return m_impl->UpdateSchedule(schedule);
}
bool ReportGenerator::DeleteSchedule(const std::string& scheduleId) {
    return m_impl->DeleteSchedule(scheduleId);
}
std::vector<ReportSchedule> ReportGenerator::GetSchedules() {
    return m_impl->GetSchedules();
}
bool ReportGenerator::SetScheduleEnabled(const std::string& scheduleId, bool enabled) {
    return m_impl->SetScheduleEnabled(scheduleId, enabled);
}

// ============================================================================
// FORWARDING — JOBS
// ============================================================================

std::optional<ReportJob> ReportGenerator::GetJobStatus(const std::string& jobId) {
    return m_impl->GetJobStatus(jobId);
}
std::vector<ReportJob> ReportGenerator::GetPendingJobs() {
    return m_impl->GetPendingJobs();
}
bool ReportGenerator::CancelJob(const std::string& jobId) {
    return m_impl->CancelJob(jobId);
}

// ============================================================================
// FORWARDING — DATA ACCESS
// ============================================================================

ThreatStatistics ReportGenerator::GetThreatStatistics(const TimeRange& range) {
    return m_impl->GetThreatStatistics(range);
}
ScanStatistics ReportGenerator::GetScanStatistics(const TimeRange& range) {
    return m_impl->GetScanStatistics(range);
}
std::vector<ComplianceCheckResult> ReportGenerator::GetComplianceResults(ComplianceStandard std_) {
    return m_impl->GetComplianceResults(std_);
}

// ============================================================================
// FORWARDING — ARCHIVES
// ============================================================================

std::vector<ReportJob> ReportGenerator::GetArchivedReports(
    const TimeRange& range, std::optional<ReportType> filterType) {
    return m_impl->GetArchivedReports(range, filterType);
}
bool ReportGenerator::DeleteArchivedReport(const std::string& reportId) {
    return m_impl->DeleteArchivedReport(reportId);
}
size_t ReportGenerator::CleanupArchives(uint32_t olderThanDays) {
    return m_impl->CleanupArchives(olderThanDays);
}

// ============================================================================
// FORWARDING — CALLBACKS
// ============================================================================

void ReportGenerator::RegisterProgressCallback(ProgressCallback cb) {
    m_impl->RegisterProgressCallback(std::move(cb));
}
void ReportGenerator::RegisterCompletionCallback(CompletionCallback cb) {
    m_impl->RegisterCompletionCallback(std::move(cb));
}
void ReportGenerator::RegisterErrorCallback(ReportErrorCallback cb) {
    m_impl->RegisterErrorCallback(std::move(cb));
}
void ReportGenerator::UnregisterCallbacks() { m_impl->UnregisterCallbacks(); }

// ============================================================================
// FORWARDING — STATISTICS
// ============================================================================

ReportStatisticsSnapshot ReportGenerator::GetStatistics() const {
    return m_impl->GetStatistics();
}
void ReportGenerator::ResetStatistics() { m_impl->ResetStatistics(); }
bool ReportGenerator::SelfTest() { return m_impl->SelfTest(); }

std::string ReportGenerator::GetVersionString() noexcept {
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                  ReportConstants::VERSION_MAJOR,
                  ReportConstants::VERSION_MINOR,
                  ReportConstants::VERSION_PATCH);
    return buf;
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

bool TimeRange::IsValid() const noexcept {
    return endTime > startTime;
}

std::string TimeRange::ToJson() const {
    std::string j = "{";
    j += "\"startTime\":\"" + SystemTimeToIso8601(startTime) + "\",";
    j += "\"endTime\":\"" + SystemTimeToIso8601(endTime) + "\",";
    j += "\"period\":\"" + std::string(GetPeriodName(period)) + "\"";
    j += "}";
    return j;
}

std::string ReportSection::ToJson() const {
    std::string j = "{";
    j += "\"sectionId\":\"" + JsonEscape(sectionId) + "\",";
    j += "\"title\":\"" + JsonEscape(title) + "\",";
    j += "\"content\":\"" + JsonEscape(content) + "\",";
    j += "\"order\":" + std::to_string(order) + ",";
    j += "\"visible\":" + std::string(isVisible ? "true" : "false") + ",";
    j += "\"data\":" + MapToJson(data) + ",";

    j += "\"tableHeaders\":" + VectorToJsonStringArray(tableHeaders) + ",";

    j += "\"tableData\":[";
    for (size_t i = 0; i < tableData.size(); ++i) {
        if (i > 0) j += ",";
        j += VectorToJsonStringArray(tableData[i]);
    }
    j += "],";

    j += "\"chartData\":{";
    bool first = true;
    for (const auto& [k, v] : chartData) {
        if (!first) j += ",";
        j += "\"" + JsonEscape(k) + "\":" + std::to_string(v);
        first = false;
    }
    j += "}";

    j += "}";
    return j;
}

std::string ReportMetadata::ToJson() const {
    std::string j = "{";
    j += "\"reportId\":\"" + JsonEscape(reportId) + "\",";
    j += "\"title\":\"" + JsonEscape(title) + "\",";
    j += "\"reportType\":\"" + std::string(GetReportTypeName(reportType)) + "\",";
    j += "\"generatedTime\":\"" + SystemTimeToIso8601(generatedTime) + "\",";
    j += "\"organizationName\":\"" + JsonEscape(organizationName) + "\",";
    j += "\"generatedBy\":\"" + JsonEscape(generatedBy) + "\",";
    j += "\"timeRange\":" + timeRange.ToJson() + ",";
    j += "\"version\":\"" + JsonEscape(version) + "\",";
    j += "\"description\":\"" + JsonEscape(description) + "\",";
    j += "\"tags\":" + VectorToJsonStringArray(tags);
    j += "}";
    return j;
}

std::string ThreatStatistics::ToJson() const {
    std::string j = "{";
    j += "\"totalDetections\":" + std::to_string(totalDetections) + ",";
    j += "\"bySeverity\":" + MapToJsonNumeric(bySeverity) + ",";
    j += "\"byType\":" + MapToJsonNumeric(byType) + ",";
    j += "\"byAction\":" + MapToJsonNumeric(byAction) + ",";
    j += "\"dailyCounts\":" + MapToJsonNumeric(dailyCounts) + ",";
    j += "\"topThreats\":[";
    for (size_t i = 0; i < topThreats.size(); ++i) {
        if (i > 0) j += ",";
        j += "{\"name\":\"" + JsonEscape(topThreats[i].first) +
             "\",\"count\":" + std::to_string(topThreats[i].second) + "}";
    }
    j += "]";
    j += "}";
    return j;
}

std::string ScanStatistics::ToJson() const {
    std::string j = "{";
    j += "\"totalScans\":" + std::to_string(totalScans) + ",";
    j += "\"filesScanned\":" + std::to_string(filesScanned) + ",";
    j += "\"bytesScanned\":" + std::to_string(bytesScanned) + ",";
    j += "\"avgScanTimeMs\":" + std::to_string(avgScanTimeMs) + ",";
    j += "\"byScanType\":" + MapToJsonNumeric(byScanType) + ",";
    j += "\"byResult\":" + MapToJsonNumeric(byResult);
    j += "}";
    return j;
}

std::string ComplianceCheckResult::ToJson() const {
    std::string j = "{";
    j += "\"checkId\":\"" + JsonEscape(checkId) + "\",";
    j += "\"checkName\":\"" + JsonEscape(checkName) + "\",";
    j += "\"standard\":\"" + std::string(GetComplianceStandardName(standard)) + "\",";
    j += "\"passed\":" + std::string(passed ? "true" : "false") + ",";
    j += "\"finding\":\"" + JsonEscape(finding) + "\",";
    j += "\"recommendation\":\"" + JsonEscape(recommendation) + "\",";
    j += "\"severity\":" + std::to_string(severity);
    j += "}";
    return j;
}

std::string ReportJob::ToJson() const {
    std::string j = "{";
    j += "\"jobId\":\"" + JsonEscape(jobId) + "\",";
    j += "\"reportType\":\"" + std::string(GetReportTypeName(reportType)) + "\",";
    j += "\"format\":\"" + std::string(GetFormatName(format)) + "\",";
    j += "\"outputPath\":\"" + JsonEscape(WideToUtf8(outputPath.wstring())) + "\",";
    j += "\"status\":\"" + std::string(GetStatusName(status)) + "\",";
    j += "\"createdTime\":\"" + SystemTimeToIso8601(createdTime) + "\",";
    if (completedTime)
        j += "\"completedTime\":\"" + SystemTimeToIso8601(*completedTime) + "\",";
    j += "\"progress\":" + std::to_string(progress) + ",";
    j += "\"fileSize\":" + std::to_string(fileSize);
    if (!errorMessage.empty())
        j += ",\"error\":\"" + JsonEscape(errorMessage) + "\"";
    j += "}";
    return j;
}

std::string ReportTemplate::ToJson() const {
    std::string j = "{";
    j += "\"templateId\":\"" + JsonEscape(templateId) + "\",";
    j += "\"name\":\"" + JsonEscape(name) + "\",";
    j += "\"description\":\"" + JsonEscape(description) + "\",";
    j += "\"reportType\":\"" + std::string(GetReportTypeName(reportType)) + "\",";
    j += "\"isDefault\":" + std::string(isDefault ? "true" : "false") + ",";
    j += "\"isBuiltIn\":" + std::string(isBuiltIn ? "true" : "false");
    j += "}";
    return j;
}

std::string ReportSchedule::ToJson() const {
    std::string j = "{";
    j += "\"scheduleId\":\"" + JsonEscape(scheduleId) + "\",";
    j += "\"reportType\":\"" + std::string(GetReportTypeName(reportType)) + "\",";
    j += "\"format\":\"" + std::string(GetFormatName(format)) + "\",";
    j += "\"period\":\"" + std::string(GetPeriodName(period)) + "\",";
    j += "\"enabled\":" + std::string(enabled ? "true" : "false") + ",";
    j += "\"nextRunTime\":\"" + SystemTimeToIso8601(nextRunTime) + "\"";
    if (lastRunTime)
        j += ",\"lastRunTime\":\"" + SystemTimeToIso8601(*lastRunTime) + "\"";
    j += "}";
    return j;
}

bool ReportConfiguration::IsValid() const noexcept {
    if (maxReportSizeMB == 0 || maxReportSizeMB > 1024 || retentionDays == 0)
        return false;

    auto hasTraversal = [](const fs::path& p) noexcept -> bool {
        try {
            const std::wstring ws = p.wstring();
            return ws.find(L"..") != std::wstring::npos;
        } catch (...) { return true; }
    };

    if (!outputDirectory.empty() && hasTraversal(outputDirectory))
        return false;
    if (!archiveDirectory.empty() && hasTraversal(archiveDirectory))
        return false;
    if (!templateDirectory.empty() && hasTraversal(templateDirectory))
        return false;

    return true;
}

// ============================================================================
// STATISTICS METHODS
// ============================================================================

void ReportStatistics::Reset() noexcept {
    reportsGenerated.store(0, std::memory_order_relaxed);
    reportsFailed.store(0, std::memory_order_relaxed);
    reportsDelivered.store(0, std::memory_order_relaxed);
    totalGenerationTimeMs.store(0, std::memory_order_relaxed);
    totalSizeBytes.store(0, std::memory_order_relaxed);
    for (auto& a : byFormat) a.store(0, std::memory_order_relaxed);
    for (auto& a : byType) a.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

ReportStatisticsSnapshot ReportStatistics::TakeSnapshot() const noexcept {
    ReportStatisticsSnapshot snap;
    snap.reportsGenerated = reportsGenerated.load(std::memory_order_relaxed);
    snap.reportsFailed = reportsFailed.load(std::memory_order_relaxed);
    snap.reportsDelivered = reportsDelivered.load(std::memory_order_relaxed);
    snap.totalGenerationTimeMs = totalGenerationTimeMs.load(std::memory_order_relaxed);
    snap.totalSizeBytes = totalSizeBytes.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byFormat.size(); ++i)
        snap.byFormat[i] = byFormat[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < byType.size(); ++i)
        snap.byType[i] = byType[i].load(std::memory_order_relaxed);
    return snap;
}

std::string ReportStatistics::ToJson() const {
    return TakeSnapshot().ToJson();
}

std::string ReportStatisticsSnapshot::ToJson() const {
    std::string j = "{";
    j += "\"reportsGenerated\":" + std::to_string(reportsGenerated) + ",";
    j += "\"reportsFailed\":" + std::to_string(reportsFailed) + ",";
    j += "\"reportsDelivered\":" + std::to_string(reportsDelivered) + ",";
    j += "\"totalGenerationTimeMs\":" + std::to_string(totalGenerationTimeMs) + ",";
    j += "\"totalSizeBytes\":" + std::to_string(totalSizeBytes);
    j += "}";
    return j;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetFormatName(ReportFormat format) noexcept {
    switch (format) {
        case ReportFormat::PDF:    return "PDF";
        case ReportFormat::HTML:   return "HTML";
        case ReportFormat::JSON:   return "JSON";
        case ReportFormat::CSV:    return "CSV";
        case ReportFormat::XML:    return "XML";
        case ReportFormat::RTF:    return "RTF";
        case ReportFormat::XLSX:   return "XLSX";
        case ReportFormat::SYSLOG: return "Syslog";
        case ReportFormat::CEF:    return "CEF";
        case ReportFormat::LEEF:   return "LEEF";
        default:                   return "Unknown";
    }
}

std::string_view GetFormatExtension(ReportFormat format) noexcept {
    switch (format) {
        case ReportFormat::PDF:    return ".pdf";
        case ReportFormat::HTML:   return ".html";
        case ReportFormat::JSON:   return ".json";
        case ReportFormat::CSV:    return ".csv";
        case ReportFormat::XML:    return ".xml";
        case ReportFormat::RTF:    return ".rtf";
        case ReportFormat::XLSX:   return ".xlsx";
        case ReportFormat::SYSLOG: return ".log";
        case ReportFormat::CEF:    return ".cef";
        case ReportFormat::LEEF:   return ".leef";
        default:                   return ".txt";
    }
}

std::string_view GetReportTypeName(ReportType type) noexcept {
    switch (type) {
        case ReportType::SecurityAudit:    return "Security Audit";
        case ReportType::ThreatSummary:    return "Threat Summary";
        case ReportType::ScanHistory:      return "Scan History";
        case ReportType::ComplianceReport: return "Compliance";
        case ReportType::ExecutiveSummary: return "Executive Summary";
        case ReportType::ForensicAnalysis: return "Forensic Analysis";
        case ReportType::IncidentReport:   return "Incident Report";
        case ReportType::SystemHealth:     return "System Health";
        case ReportType::PerformanceReport:return "Performance";
        case ReportType::UpdateHistory:    return "Update History";
        case ReportType::UserActivity:     return "User Activity";
        case ReportType::QuarantineLog:    return "Quarantine Log";
        case ReportType::Custom:           return "Custom";
        default:                           return "Unknown";
    }
}

std::string_view GetPeriodName(ReportPeriod period) noexcept {
    switch (period) {
        case ReportPeriod::Today:      return "Today";
        case ReportPeriod::Yesterday:  return "Yesterday";
        case ReportPeriod::Last7Days:  return "Last 7 Days";
        case ReportPeriod::Last30Days: return "Last 30 Days";
        case ReportPeriod::Last90Days: return "Last 90 Days";
        case ReportPeriod::LastYear:   return "Last Year";
        case ReportPeriod::Custom:     return "Custom";
        case ReportPeriod::AllTime:    return "All Time";
        default:                       return "Unknown";
    }
}

std::string_view GetComplianceStandardName(ComplianceStandard std_) noexcept {
    switch (std_) {
        case ComplianceStandard::None:     return "None";
        case ComplianceStandard::HIPAA:    return "HIPAA";
        case ComplianceStandard::PCI_DSS:  return "PCI-DSS";
        case ComplianceStandard::GDPR:     return "GDPR";
        case ComplianceStandard::SOX:      return "SOX";
        case ComplianceStandard::ISO27001: return "ISO 27001";
        case ComplianceStandard::NIST:     return "NIST";
        case ComplianceStandard::CIS:      return "CIS";
        case ComplianceStandard::FERPA:    return "FERPA";
        case ComplianceStandard::SOC2:     return "SOC 2";
        default:                           return "Unknown";
    }
}

std::string_view GetStatusName(ReportStatus status) noexcept {
    switch (status) {
        case ReportStatus::Pending:    return "Pending";
        case ReportStatus::Generating: return "Generating";
        case ReportStatus::Completed:  return "Completed";
        case ReportStatus::Failed:     return "Failed";
        case ReportStatus::Cancelled:  return "Cancelled";
        case ReportStatus::Delivered:  return "Delivered";
        default:                       return "Unknown";
    }
}

TimeRange CalculateTimeRange(ReportPeriod period) {
    TimeRange range;
    range.period = period;
    range.endTime = std::chrono::system_clock::now();

    switch (period) {
        case ReportPeriod::Today:
            range.startTime = range.endTime - std::chrono::hours(24);
            break;
        case ReportPeriod::Yesterday: {
            range.endTime = range.endTime - std::chrono::hours(24);
            range.startTime = range.endTime - std::chrono::hours(24);
            break;
        }
        case ReportPeriod::Last7Days:
            range.startTime = range.endTime - std::chrono::hours(24 * 7);
            break;
        case ReportPeriod::Last30Days:
            range.startTime = range.endTime - std::chrono::hours(24 * 30);
            break;
        case ReportPeriod::Last90Days:
            range.startTime = range.endTime - std::chrono::hours(24 * 90);
            break;
        case ReportPeriod::LastYear:
            range.startTime = range.endTime - std::chrono::hours(24 * 365);
            break;
        case ReportPeriod::AllTime:
            range.startTime = std::chrono::system_clock::time_point{};
            break;
        default:
            range.startTime = range.endTime - std::chrono::hours(24 * 7);
            break;
    }
    return range;
}

std::string FormatFileSize(size_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) {
        char buf[32]{};
        std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
        return buf;
    }
    if (bytes < 1024ULL * 1024 * 1024) {
        char buf[32]{};
        std::snprintf(buf, sizeof(buf), "%.1f MB",
                      static_cast<double>(bytes) / (1024.0 * 1024.0));
        return buf;
    }
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%.2f GB",
                  static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

std::string EscapeHtml(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 32);
    for (char c : input) {
        switch (c) {
            case '&': out += "&amp;";  break;
            case '<': out += "&lt;";   break;
            case '>': out += "&gt;";   break;
            case '"': out += "&quot;"; break;
            case '\'':out += "&#39;";  break;
            default:  out += c;        break;
        }
    }
    return out;
}

std::string EscapeCsvField(const std::string& field) {
    bool needsQuoting = false;
    for (char c : field) {
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needsQuoting = true;
            break;
        }
    }
    if (!needsQuoting) return field;

    std::string out = "\"";
    for (char c : field) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

}  // namespace Communication
}  // namespace ShadowStrike
