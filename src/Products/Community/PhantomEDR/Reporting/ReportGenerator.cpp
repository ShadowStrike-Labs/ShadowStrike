/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/Reporting/ReportGenerator.hpp"
#include "Products/Community/PhantomEDR/Reporting/ExecutiveSummary.hpp"
#include "Products/Community/PhantomEDR/Reporting/IncidentReport.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <random>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Reporting {

using ShadowStrike::Utils::Logger;
namespace SU = ShadowStrike::Utils::StringUtils;
namespace fs = std::filesystem;

static constexpr std::string_view kLogPrefix = "[ReportGenerator]";

// ============================================================================
// UUID GENERATION (file-scope)
// ============================================================================

static std::string GenerateReportId() {
    static std::mutex s_mtx;
    static std::mt19937_64 s_rng(std::random_device{}());
    std::lock_guard lk(s_mtx);
    std::uniform_int_distribution<uint64_t> dist;
    const uint64_t hi = dist(s_rng);
    const uint64_t lo = dist(s_rng);
    return std::format("RPT-{:016X}{:08X}", hi, lo & 0xFFFFFFFF);
}

// ============================================================================
// TIME HELPERS
// ============================================================================

static int64_t ToMillis(Clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
}

static Clock::time_point FromMillis(int64_t ms) {
    return Clock::time_point(
        std::chrono::duration_cast<Clock::duration>(
            std::chrono::milliseconds(ms)));
}

static std::string FormatTimestamp(Clock::time_point tp) {
    const auto tt = Clock::to_time_t(tp);
    std::tm tm{};
    gmtime_s(&tm, &tt);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

// ============================================================================
// IMPL
// ============================================================================

class ReportGeneratorImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    ReportMetadata Generate(ReportType type, ReportFormat format,
                            Clock::time_point periodStart,
                            Clock::time_point periodEnd);

    std::optional<ReportMetadata> GetReport(std::string_view reportId) const;
    std::vector<ReportMetadata> GetReportHistory(uint32_t maxResults) const;
    bool DeleteReport(std::string_view reportId);
    std::string GetOutputDirectory() const;

private:
    bool EnsureSchema();
    void PersistMetadata(const ReportMetadata& meta);
    ReportMetadata RowToMeta(ShadowStrike::Database::QueryResult& row) const;

    std::string GenerateExecutiveReport(Clock::time_point start, Clock::time_point end,
                                        ReportFormat format);
    std::string GenerateIncidentSummaryReport(Clock::time_point start, Clock::time_point end,
                                              ReportFormat format);
    std::string GeneratePeriodReport(ReportType type, Clock::time_point start,
                                     Clock::time_point end, ReportFormat format);
    bool WriteFile(const std::string& path, const std::string& content);

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
    std::string m_outputDir;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool ReportGeneratorImpl::EnsureSchema() {
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS edr_reports (
            report_id       TEXT PRIMARY KEY,
            type            INTEGER NOT NULL,
            format          INTEGER NOT NULL,
            status          INTEGER NOT NULL DEFAULT 0,
            generated_at    INTEGER NOT NULL,
            period_start    INTEGER NOT NULL,
            period_end      INTEGER NOT NULL,
            file_path       TEXT NOT NULL DEFAULT '',
            file_size       INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_edr_reports_generated
            ON edr_reports(generated_at DESC);
    )SQL";

    if (!db.Execute(sql, &dbErr)) {
        Logger::Error("{} Schema creation failed: {}", kLogPrefix,
                      SU::ToNarrow(dbErr.message));
        return false;
    }
    return true;
}

// ============================================================================
// INITIALIZE / SHUTDOWN
// ============================================================================

bool ReportGeneratorImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;

    // Set output directory relative to executable
    wchar_t exePath[MAX_PATH]{};
    ::GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    fs::path exeDir = fs::path(exePath).parent_path();
    m_outputDir = (exeDir / "reports").string();

    std::error_code ec;
    fs::create_directories(m_outputDir, ec);
    if (ec) {
        Logger::Error("{} Cannot create output directory '{}': {}",
                      kLogPrefix, m_outputDir, ec.message());
        return false;
    }

    if (!EnsureSchema()) return false;

    m_initialized = true;
    Logger::Info("{} Initialized — output dir: {}", kLogPrefix, m_outputDir);
    return true;
}

void ReportGeneratorImpl::Shutdown() {
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// GENERATE
// ============================================================================

ReportMetadata ReportGeneratorImpl::Generate(ReportType type, ReportFormat format,
                                             Clock::time_point periodStart,
                                             Clock::time_point periodEnd) {
    std::unique_lock lk(m_mutex);

    ReportMetadata meta;
    meta.reportId = GenerateReportId();
    meta.type = type;
    meta.format = format;
    meta.status = ReportStatus::Generating;
    meta.generatedAt = Clock::now();
    meta.periodStart = periodStart;
    meta.periodEnd = periodEnd;

    Logger::Info("{} Generating {} {} report for [{}, {}]",
                 kLogPrefix, ToString(type), ToString(format),
                 FormatTimestamp(periodStart), FormatTimestamp(periodEnd));

    // Release lock while generating content (can be slow)
    lk.unlock();

    std::string content;
    try {
        switch (type) {
            case ReportType::Executive:
                content = GenerateExecutiveReport(periodStart, periodEnd, format);
                break;
            case ReportType::Incident:
                content = GenerateIncidentSummaryReport(periodStart, periodEnd, format);
                break;
            default:
                content = GeneratePeriodReport(type, periodStart, periodEnd, format);
                break;
        }
    } catch (const std::exception& ex) {
        Logger::Error("{} Report generation failed: {}", kLogPrefix, ex.what());
        meta.status = ReportStatus::Failed;
        lk.lock();
        PersistMetadata(meta);
        return meta;
    }

    // Write to file
    const std::string ext = (format == ReportFormat::HTML) ? ".html" : ".json";
    const std::string filename = meta.reportId + ext;
    const std::string filePath = (fs::path(m_outputDir) / filename).string();

    if (!WriteFile(filePath, content)) {
        meta.status = ReportStatus::Failed;
        lk.lock();
        PersistMetadata(meta);
        return meta;
    }

    meta.filePath = filePath;
    meta.fileSizeBytes = static_cast<uint64_t>(content.size());
    meta.status = ReportStatus::Completed;

    lk.lock();
    PersistMetadata(meta);
    Logger::Info("{} Report {} generated ({} bytes) → {}",
                 kLogPrefix, meta.reportId, meta.fileSizeBytes, meta.filePath);
    return meta;
}

// ============================================================================
// EXECUTIVE REPORT GENERATION
// ============================================================================

std::string ReportGeneratorImpl::GenerateExecutiveReport(
    Clock::time_point start, Clock::time_point end, ReportFormat format) {

    auto& exec = ExecutiveSummary::Instance();
    if (!exec.IsInitialized()) {
        (void)exec.Initialize();
    }
    const auto metrics = exec.ComputeMetrics(start, end);

    if (format == ReportFormat::JSON) {
        return exec.GenerateJson(metrics);
    }
    return exec.GenerateHtml(metrics);
}

// ============================================================================
// INCIDENT SUMMARY REPORT
// ============================================================================

std::string ReportGeneratorImpl::GenerateIncidentSummaryReport(
    Clock::time_point start, Clock::time_point end, ReportFormat format) {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    const int64_t startMs = ToMillis(start);
    const int64_t endMs = ToMillis(end);

    auto result = db.QueryWithParams(
        "SELECT incident_id FROM edr_incidents "
        "WHERE created_at >= ? AND created_at <= ? "
        "ORDER BY created_at DESC LIMIT 200",
        &dbErr, startMs, endMs);

    std::vector<std::string> incidentIds;
    while (result.Next()) {
        incidentIds.push_back(result.GetString(0));
    }

    auto& irpt = IncidentReport::Instance();
    if (!irpt.IsInitialized()) {
        (void)irpt.Initialize();
    }

    if (format == ReportFormat::JSON) {
        std::ostringstream oss;
        oss << "{\"reportType\":\"IncidentSummary\","
            << "\"periodStart\":\"" << FormatTimestamp(start) << "\","
            << "\"periodEnd\":\"" << FormatTimestamp(end) << "\","
            << "\"totalIncidents\":" << incidentIds.size() << ","
            << "\"incidents\":[";
        bool first = true;
        for (const auto& id : incidentIds) {
            auto data = irpt.GenerateReport(id);
            if (data.incidentId.empty()) continue;
            if (!first) oss << ",";
            first = false;
            oss << irpt.ExportJson(data);
        }
        oss << "]}";
        return oss.str();
    }

    // HTML format
    std::ostringstream oss;
    oss << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        << "<title>ShadowStrike Incident Summary</title>"
        << "<style>"
        << "body{font-family:system-ui,sans-serif;margin:2em;background:#0a0a0a;color:#e0e0e0;}"
        << "h1{color:#00d4aa;}h2{color:#3ea8ff;border-bottom:1px solid #333;padding-bottom:0.3em;}"
        << "table{border-collapse:collapse;width:100%;margin:1em 0;}"
        << "th,td{border:1px solid #333;padding:8px 12px;text-align:left;}"
        << "th{background:#1a1a2e;color:#00d4aa;}"
        << "tr:nth-child(even){background:#111;}"
        << ".critical{color:#ff4444;font-weight:bold;}.high{color:#ff8800;}"
        << ".medium{color:#ffcc00;}.low{color:#88cc00;}"
        << "</style></head><body>"
        << "<h1>ShadowStrike — Incident Summary Report</h1>"
        << "<p>Period: " << FormatTimestamp(start) << " — "
        << FormatTimestamp(end) << "</p>"
        << "<p>Total incidents: <strong>" << incidentIds.size() << "</strong></p>"
        << "<table><thead><tr><th>ID</th><th>Title</th><th>Severity</th>"
        << "<th>Status</th><th>Detected</th><th>IOCs</th><th>MITRE</th></tr></thead><tbody>";

    for (const auto& id : incidentIds) {
        auto data = irpt.GenerateReport(id);
        if (data.incidentId.empty()) continue;
        oss << "<tr><td>" << data.incidentId << "</td>"
            << "<td>" << data.title << "</td>"
            << "<td class='" << data.severity << "'>" << data.severity << "</td>"
            << "<td>" << data.status << "</td>"
            << "<td>" << FormatTimestamp(data.detectedAt) << "</td>"
            << "<td>" << data.iocs.size() << "</td>"
            << "<td>" << data.mitreAttackIds.size() << "</td></tr>";
    }
    oss << "</tbody></table></body></html>";
    return oss.str();
}

// ============================================================================
// PERIOD REPORT (Daily / Weekly / Monthly / OnDemand)
// ============================================================================

std::string ReportGeneratorImpl::GeneratePeriodReport(
    ReportType type, Clock::time_point start, Clock::time_point end,
    ReportFormat format) {

    auto& exec = ExecutiveSummary::Instance();
    if (!exec.IsInitialized()) {
        (void)exec.Initialize();
    }
    const auto metrics = exec.ComputeMetrics(start, end);

    // Also gather incident count breakdown by severity from DB
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    const int64_t startMs = ToMillis(start);
    const int64_t endMs = ToMillis(end);

    struct SeverityCount {
        int critical = 0, high = 0, medium = 0, low = 0, info = 0;
    } sevCounts;

    auto result = db.QueryWithParams(
        "SELECT severity, COUNT(*) FROM edr_incidents "
        "WHERE created_at >= ? AND created_at <= ? GROUP BY severity",
        &dbErr, startMs, endMs);
    while (result.Next()) {
        const int sev = result.GetInt(0);
        const int cnt = result.GetInt(1);
        switch (sev) {
            case 5: sevCounts.critical = cnt; break;
            case 4: sevCounts.high = cnt; break;
            case 3: sevCounts.medium = cnt; break;
            case 2: sevCounts.low = cnt; break;
            default: sevCounts.info += cnt; break;
        }
    }

    if (format == ReportFormat::JSON) {
        std::ostringstream oss;
        oss << "{\"reportType\":\"" << ToString(type) << "\","
            << "\"periodStart\":\"" << FormatTimestamp(start) << "\","
            << "\"periodEnd\":\"" << FormatTimestamp(end) << "\","
            << "\"kpi\":" << exec.GenerateJson(metrics) << ","
            << "\"incidentBreakdown\":{"
            << "\"critical\":" << sevCounts.critical << ","
            << "\"high\":" << sevCounts.high << ","
            << "\"medium\":" << sevCounts.medium << ","
            << "\"low\":" << sevCounts.low << ","
            << "\"info\":" << sevCounts.info
            << "}}";
        return oss.str();
    }

    // HTML
    std::ostringstream oss;
    oss << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        << "<title>ShadowStrike " << ToString(type) << " Report</title>"
        << "<style>"
        << "body{font-family:system-ui,sans-serif;margin:2em;background:#0a0a0a;color:#e0e0e0;}"
        << "h1{color:#00d4aa;}h2{color:#3ea8ff;border-bottom:1px solid #333;padding-bottom:0.3em;}"
        << ".metric{display:inline-block;background:#1a1a2e;border-radius:8px;padding:1em 2em;margin:0.5em;text-align:center;}"
        << ".metric .value{font-size:2em;color:#00d4aa;font-weight:bold;}"
        << ".metric .label{font-size:0.85em;color:#888;}"
        << "table{border-collapse:collapse;width:100%;margin:1em 0;}"
        << "th,td{border:1px solid #333;padding:8px 12px;text-align:left;}"
        << "th{background:#1a1a2e;color:#00d4aa;}"
        << "</style></head><body>"
        << "<h1>ShadowStrike — " << ToString(type) << " Report</h1>"
        << "<p>Period: " << FormatTimestamp(start) << " — " << FormatTimestamp(end) << "</p>"
        << "<h2>Key Metrics</h2>"
        << "<div>"
        << "<div class='metric'><div class='value'>" << metrics.totalThreatsDetected << "</div><div class='label'>Threats Detected</div></div>"
        << "<div class='metric'><div class='value'>" << metrics.totalThreatsBlocked << "</div><div class='label'>Threats Blocked</div></div>"
        << "<div class='metric'><div class='value'>" << metrics.totalIncidents << "</div><div class='label'>Incidents</div></div>"
        << "<div class='metric'><div class='value'>" << std::format("{:.1f}", metrics.meanTimeToDetectMs / 1000.0) << "s</div><div class='label'>MTTD</div></div>"
        << "<div class='metric'><div class='value'>" << std::format("{:.1f}", metrics.meanTimeToRespondMs / 1000.0) << "s</div><div class='label'>MTTR</div></div>"
        << "<div class='metric'><div class='value'>" << metrics.complianceScore << "%</div><div class='label'>Compliance</div></div>"
        << "</div>"
        << "<h2>Incident Breakdown by Severity</h2>"
        << "<table><tr><th>Severity</th><th>Count</th></tr>"
        << "<tr><td>Critical</td><td>" << sevCounts.critical << "</td></tr>"
        << "<tr><td>High</td><td>" << sevCounts.high << "</td></tr>"
        << "<tr><td>Medium</td><td>" << sevCounts.medium << "</td></tr>"
        << "<tr><td>Low</td><td>" << sevCounts.low << "</td></tr>"
        << "<tr><td>Info</td><td>" << sevCounts.info << "</td></tr>"
        << "</table>";

    // Threat breakdown
    if (!metrics.threatBreakdown.empty()) {
        oss << "<h2>Threat Breakdown by Category</h2>"
            << "<table><tr><th>Category</th><th>Detected</th><th>Blocked</th>"
            << "<th>Quarantined</th><th>Allowed</th></tr>";
        for (const auto& tb : metrics.threatBreakdown) {
            oss << "<tr><td>" << ToString(tb.category) << "</td>"
                << "<td>" << tb.count << "</td>"
                << "<td>" << tb.blocked << "</td>"
                << "<td>" << tb.quarantined << "</td>"
                << "<td>" << tb.allowed << "</td></tr>";
        }
        oss << "</table>";
    }

    oss << "</body></html>";
    return oss.str();
}

// ============================================================================
// PERSISTENCE HELPERS
// ============================================================================

void ReportGeneratorImpl::PersistMetadata(const ReportMetadata& meta) {
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    if (!db.ExecuteWithParams(
            "INSERT OR REPLACE INTO edr_reports "
            "(report_id, type, format, status, generated_at, period_start, period_end, file_path, file_size) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &dbErr,
            meta.reportId,
            static_cast<int>(meta.type),
            static_cast<int>(meta.format),
            static_cast<int>(meta.status),
            ToMillis(meta.generatedAt),
            ToMillis(meta.periodStart),
            ToMillis(meta.periodEnd),
            meta.filePath,
            static_cast<int64_t>(meta.fileSizeBytes))) {
        Logger::Error("{} Failed to persist report metadata {}: {}",
                      kLogPrefix, meta.reportId,
                      SU::ToNarrow(dbErr.message));
    }
}

ReportMetadata ReportGeneratorImpl::RowToMeta(
    ShadowStrike::Database::QueryResult& row) const {
    ReportMetadata meta;
    meta.reportId = row.GetString(0);
    meta.type = static_cast<ReportType>(row.GetInt(1));
    meta.format = static_cast<ReportFormat>(row.GetInt(2));
    meta.status = static_cast<ReportStatus>(row.GetInt(3));
    meta.generatedAt = FromMillis(row.GetInt64(4));
    meta.periodStart = FromMillis(row.GetInt64(5));
    meta.periodEnd = FromMillis(row.GetInt64(6));
    meta.filePath = row.GetString(7);
    meta.fileSizeBytes = static_cast<uint64_t>(row.GetInt64(8));
    return meta;
}

// ============================================================================
// QUERY
// ============================================================================

std::optional<ReportMetadata> ReportGeneratorImpl::GetReport(std::string_view reportId) const {
    std::shared_lock lk(m_mutex);
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT report_id, type, format, status, generated_at, "
        "period_start, period_end, file_path, file_size "
        "FROM edr_reports WHERE report_id = ?",
        &dbErr, std::string(reportId));

    if (result.Next()) {
        return RowToMeta(result);
    }
    return std::nullopt;
}

std::vector<ReportMetadata> ReportGeneratorImpl::GetReportHistory(uint32_t maxResults) const {
    std::shared_lock lk(m_mutex);
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT report_id, type, format, status, generated_at, "
        "period_start, period_end, file_path, file_size "
        "FROM edr_reports ORDER BY generated_at DESC LIMIT ?",
        &dbErr, static_cast<int>(maxResults));

    std::vector<ReportMetadata> out;
    while (result.Next()) {
        out.push_back(RowToMeta(result));
    }
    return out;
}

bool ReportGeneratorImpl::DeleteReport(std::string_view reportId) {
    std::unique_lock lk(m_mutex);
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // Get file path first
    auto result = db.QueryWithParams(
        "SELECT file_path FROM edr_reports WHERE report_id = ?",
        &dbErr, std::string(reportId));

    std::string filePath;
    if (result.Next()) {
        filePath = result.GetString(0);
    } else {
        return false;
    }

    // Delete DB record
    if (!db.ExecuteWithParams(
            "DELETE FROM edr_reports WHERE report_id = ?",
            &dbErr, std::string(reportId))) {
        Logger::Error("{} Failed to delete report record {}: {}",
                      kLogPrefix, reportId,
                      SU::ToNarrow(dbErr.message));
        return false;
    }

    // Delete file
    if (!filePath.empty()) {
        std::error_code ec;
        fs::remove(filePath, ec);
        if (ec) {
            Logger::Warn("{} Failed to delete report file '{}': {}",
                         kLogPrefix, filePath, ec.message());
        }
    }

    Logger::Info("{} Deleted report {}", kLogPrefix, reportId);
    return true;
}

std::string ReportGeneratorImpl::GetOutputDirectory() const {
    std::shared_lock lk(m_mutex);
    return m_outputDir;
}

bool ReportGeneratorImpl::WriteFile(const std::string& path, const std::string& content) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) {
        Logger::Error("{} Cannot open file for writing: {}", kLogPrefix, path);
        return false;
    }
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!ofs) {
        Logger::Error("{} Write failed: {}", kLogPrefix, path);
        return false;
    }
    return true;
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

ReportGenerator::ReportGenerator() : m_impl(std::make_unique<ReportGeneratorImpl>()) {}
ReportGenerator::~ReportGenerator() = default;

ReportGenerator& ReportGenerator::Instance() {
    static ReportGenerator inst;
    return inst;
}

bool ReportGenerator::Initialize() { return m_impl->Initialize(); }
void ReportGenerator::Shutdown() { m_impl->Shutdown(); }
bool ReportGenerator::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

ReportMetadata ReportGenerator::Generate(ReportType type, ReportFormat format,
                                         Clock::time_point periodStart,
                                         Clock::time_point periodEnd) {
    return m_impl->Generate(type, format, periodStart, periodEnd);
}

std::optional<ReportMetadata> ReportGenerator::GetReport(std::string_view reportId) const {
    return m_impl->GetReport(reportId);
}

std::vector<ReportMetadata> ReportGenerator::GetReportHistory(uint32_t maxResults) const {
    return m_impl->GetReportHistory(maxResults);
}

bool ReportGenerator::DeleteReport(std::string_view reportId) {
    return m_impl->DeleteReport(reportId);
}

std::string ReportGenerator::GetOutputDirectory() const {
    return m_impl->GetOutputDirectory();
}

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
