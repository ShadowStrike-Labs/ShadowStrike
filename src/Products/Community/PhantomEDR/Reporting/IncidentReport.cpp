/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/Reporting/IncidentReport.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <format>
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

static constexpr std::string_view kLogPrefix = "[IncidentReport]";

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

static std::string FormatDuration(int64_t ms) {
    if (ms < 1000) return std::format("{}ms", ms);
    if (ms < 60'000) return std::format("{:.1f}s", ms / 1000.0);
    if (ms < 3'600'000) return std::format("{:.1f}m", ms / 60'000.0);
    return std::format("{:.1f}h", ms / 3'600'000.0);
}

// ============================================================================
// JSON ESCAPE
// ============================================================================

static std::string JsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out;
}

// ============================================================================
// HTML ESCAPE
// ============================================================================

static std::string HtmlEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;"; break;
            case '<':  out += "&lt;"; break;
            case '>':  out += "&gt;"; break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default:   out += c; break;
        }
    }
    return out;
}

// ============================================================================
// REPORT ID
// ============================================================================

static std::string GenerateReportId() {
    static std::mutex s_mtx;
    static std::mt19937_64 s_rng(std::random_device{}());
    std::lock_guard lk(s_mtx);
    std::uniform_int_distribution<uint64_t> dist;
    return std::format("INC-RPT-{:016X}", dist(s_rng));
}

// ============================================================================
// SEVERITY HELPERS
// ============================================================================

static std::string SeverityToString(int sev) {
    switch (sev) {
        case 5: return "Critical";
        case 4: return "High";
        case 3: return "Medium";
        case 2: return "Low";
        case 1: return "Info";
        default: return "Unknown";
    }
}

static std::string StatusToString(int status) {
    switch (status) {
        case 0: return "New";
        case 1: return "Triaged";
        case 2: return "Investigating";
        case 3: return "Containing";
        case 4: return "Remediating";
        case 5: return "Closed";
        case 6: return "FalsePositive";
        default: return "Unknown";
    }
}

// ============================================================================
// IMPL
// ============================================================================

class IncidentReportImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    IncidentReportData GenerateReport(std::string_view incidentId) const;
    std::string ExportJson(const IncidentReportData& data) const;
    std::string ExportHtml(const IncidentReportData& data) const;
    std::vector<ReportMetadata> GetGeneratedReports(uint32_t maxResults) const;

private:
    bool EnsureSchema();
    void LoadIncidentCore(IncidentReportData& data, std::string_view incidentId) const;
    void LoadTimeline(IncidentReportData& data, std::string_view incidentId) const;
    void LoadIOCs(IncidentReportData& data, std::string_view incidentId) const;
    void LoadMITREMappings(IncidentReportData& data, std::string_view incidentId) const;
    void LoadAffectedAssets(IncidentReportData& data, std::string_view incidentId) const;
    void GenerateNarrative(IncidentReportData& data) const;

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
};

// ============================================================================
// SCHEMA
// ============================================================================

bool IncidentReportImpl::EnsureSchema() {
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    const char* sql = R"SQL(
        CREATE TABLE IF NOT EXISTS edr_incident_reports (
            report_id       TEXT PRIMARY KEY,
            incident_id     TEXT NOT NULL,
            generated_at    INTEGER NOT NULL,
            file_path       TEXT NOT NULL DEFAULT '',
            file_size       INTEGER NOT NULL DEFAULT 0,
            format          INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_edr_inc_rpt_gen
            ON edr_incident_reports(generated_at DESC);
    )SQL";

    if (!db.Execute(sql, &dbErr)) {
        Logger::Error("{} Schema creation failed: {}", kLogPrefix,
                      SU::ToNarrow(dbErr.message));
        return false;
    }
    return true;
}

// ============================================================================
// INIT / SHUTDOWN
// ============================================================================

bool IncidentReportImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;
    if (!EnsureSchema()) return false;
    m_initialized = true;
    Logger::Info("{} Initialized", kLogPrefix);
    return true;
}

void IncidentReportImpl::Shutdown() {
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// LOAD INCIDENT CORE
// ============================================================================

void IncidentReportImpl::LoadIncidentCore(
    IncidentReportData& data, std::string_view incidentId) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT incident_id, title, description, severity, status, "
        "created_at, closed_at "
        "FROM edr_incidents WHERE incident_id = ?",
        &dbErr, std::string(incidentId));

    if (!result.Next()) {
        Logger::Warn("{} Incident '{}' not found in database", kLogPrefix, incidentId);
        return;
    }

    data.incidentId = result.GetString(0);
    data.title = result.GetString(1);
    data.severity = SeverityToString(result.GetInt(3));
    data.status = StatusToString(result.GetInt(4));
    data.detectedAt = FromMillis(result.GetInt64(5));
    if (!result.IsNull(6)) {
        data.closedAt = FromMillis(result.GetInt64(6));
    }
}

// ============================================================================
// LOAD TIMELINE
// ============================================================================

void IncidentReportImpl::LoadTimeline(
    IncidentReportData& data, std::string_view incidentId) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // Timeline from incident notes/audit trail
    auto result = db.QueryWithParams(
        "SELECT timestamp, event_type, description, actor "
        "FROM edr_incident_timeline WHERE incident_id = ? "
        "ORDER BY timestamp ASC",
        &dbErr, std::string(incidentId));

    while (result.Next()) {
        IncidentTimelineEntry entry;
        entry.timestamp = FromMillis(result.GetInt64(0));
        entry.eventType = result.GetString(1);
        entry.description = result.GetString(2);
        entry.actor = result.GetString(3);
        data.timeline.push_back(std::move(entry));
    }

    // If no explicit timeline, build from incident status transitions
    if (data.timeline.empty()) {
        IncidentTimelineEntry detection;
        detection.timestamp = data.detectedAt;
        detection.eventType = "Detection";
        detection.description = "Incident detected: " + data.title;
        detection.actor = "ShadowStrike Engine";
        data.timeline.push_back(std::move(detection));

        if (data.closedAt != Clock::time_point{}) {
            IncidentTimelineEntry closure;
            closure.timestamp = data.closedAt;
            closure.eventType = "Closure";
            closure.description = "Incident closed with status: " + data.status;
            closure.actor = "ShadowStrike Engine";
            data.timeline.push_back(std::move(closure));
        }
    }
}

// ============================================================================
// LOAD IOCs
// ============================================================================

void IncidentReportImpl::LoadIOCs(
    IncidentReportData& data, std::string_view incidentId) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT ioc_type, ioc_value FROM edr_incident_iocs "
        "WHERE incident_id = ? ORDER BY ioc_type",
        &dbErr, std::string(incidentId));

    while (result.Next()) {
        const std::string iocType = result.GetString(0);
        const std::string iocValue = result.GetString(1);
        data.iocs.push_back(iocType + ":" + iocValue);
    }
}

// ============================================================================
// LOAD MITRE MAPPINGS
// ============================================================================

void IncidentReportImpl::LoadMITREMappings(
    IncidentReportData& data, std::string_view incidentId) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT technique_id FROM edr_incident_mitre "
        "WHERE incident_id = ? ORDER BY technique_id",
        &dbErr, std::string(incidentId));

    while (result.Next()) {
        data.mitreAttackIds.push_back(result.GetString(0));
    }
}

// ============================================================================
// LOAD AFFECTED ASSETS
// ============================================================================

void IncidentReportImpl::LoadAffectedAssets(
    IncidentReportData& data, std::string_view incidentId) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // From affected files
    auto fileResult = db.QueryWithParams(
        "SELECT file_path FROM edr_incident_files WHERE incident_id = ?",
        &dbErr, std::string(incidentId));
    while (fileResult.Next()) {
        data.affectedAssets.push_back("File: " + fileResult.GetString(0));
    }

    // From affected processes
    auto procResult = db.QueryWithParams(
        "SELECT process_name, pid FROM edr_incident_processes "
        "WHERE incident_id = ?",
        &dbErr, std::string(incidentId));
    while (procResult.Next()) {
        data.affectedAssets.push_back(
            "Process: " + procResult.GetString(0) +
            " (PID: " + std::to_string(procResult.GetInt(1)) + ")");
    }
}

// ============================================================================
// GENERATE NARRATIVE
// ============================================================================

void IncidentReportImpl::GenerateNarrative(IncidentReportData& data) const {
    // Auto-generate narrative from structured data
    std::ostringstream oss;

    // Summary paragraph
    oss << "On " << FormatTimestamp(data.detectedAt)
        << ", ShadowStrike PhantomEDR detected a " << data.severity
        << " severity incident: \"" << data.title << "\". ";

    if (!data.iocs.empty()) {
        oss << "The detection identified " << data.iocs.size()
            << " indicator(s) of compromise. ";
    }

    if (!data.mitreAttackIds.empty()) {
        oss << "The observed behavior maps to " << data.mitreAttackIds.size()
            << " MITRE ATT&CK technique(s): ";
        for (size_t i = 0; i < data.mitreAttackIds.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << data.mitreAttackIds[i];
        }
        oss << ". ";
    }

    if (!data.affectedAssets.empty()) {
        oss << data.affectedAssets.size() << " asset(s) were affected. ";
    }

    if (data.closedAt != Clock::time_point{}) {
        const int64_t resolutionMs = ToMillis(data.closedAt) - ToMillis(data.detectedAt);
        oss << "The incident was resolved in " << FormatDuration(resolutionMs)
            << " with final status: " << data.status << ".";
    } else {
        oss << "The incident remains open with status: " << data.status << ".";
    }

    data.narrativeSummary = oss.str();

    // Root cause
    if (!data.mitreAttackIds.empty()) {
        data.rootCauseAnalysis =
            "Initial compromise vector mapped to MITRE ATT&CK technique(s). "
            "Detailed root cause analysis requires manual investigation of "
            "the timeline entries and correlated telemetry events.";
    }

    // Remediation
    if (data.status == "Closed" || data.status == "Remediating") {
        data.remediation =
            "Automated containment and remediation actions were executed by "
            "the ShadowStrike engine. See timeline for specific actions taken.";
    }

    // Lessons learned
    data.lessonsLearned =
        "Review detection rules and response playbooks to ensure similar "
        "threats are caught faster in the future. Consider updating "
        "threat intelligence feeds with any new IOCs discovered.";
}

// ============================================================================
// GENERATE REPORT
// ============================================================================

IncidentReportData IncidentReportImpl::GenerateReport(std::string_view incidentId) const {
    std::shared_lock lk(m_mutex);

    IncidentReportData data;
    LoadIncidentCore(data, incidentId);
    if (data.incidentId.empty()) return data;

    LoadTimeline(data, incidentId);
    LoadIOCs(data, incidentId);
    LoadMITREMappings(data, incidentId);
    LoadAffectedAssets(data, incidentId);
    GenerateNarrative(data);

    return data;
}

// ============================================================================
// JSON EXPORT
// ============================================================================

std::string IncidentReportImpl::ExportJson(const IncidentReportData& data) const {
    std::ostringstream oss;
    oss << "{\"incidentId\":\"" << JsonEscape(data.incidentId) << "\","
        << "\"title\":\"" << JsonEscape(data.title) << "\","
        << "\"severity\":\"" << JsonEscape(data.severity) << "\","
        << "\"status\":\"" << JsonEscape(data.status) << "\","
        << "\"detectedAt\":\"" << FormatTimestamp(data.detectedAt) << "\","
        << "\"closedAt\":\"" << FormatTimestamp(data.closedAt) << "\",";

    // Affected assets
    oss << "\"affectedAssets\":[";
    for (size_t i = 0; i < data.affectedAssets.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << JsonEscape(data.affectedAssets[i]) << "\"";
    }
    oss << "],";

    // IOCs
    oss << "\"iocs\":[";
    for (size_t i = 0; i < data.iocs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << JsonEscape(data.iocs[i]) << "\"";
    }
    oss << "],";

    // MITRE
    oss << "\"mitreAttackIds\":[";
    for (size_t i = 0; i < data.mitreAttackIds.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << JsonEscape(data.mitreAttackIds[i]) << "\"";
    }
    oss << "],";

    // Timeline
    oss << "\"timeline\":[";
    for (size_t i = 0; i < data.timeline.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& e = data.timeline[i];
        oss << "{\"timestamp\":\"" << FormatTimestamp(e.timestamp) << "\","
            << "\"eventType\":\"" << JsonEscape(e.eventType) << "\","
            << "\"description\":\"" << JsonEscape(e.description) << "\","
            << "\"actor\":\"" << JsonEscape(e.actor) << "\"}";
    }
    oss << "],";

    // Narrative sections
    oss << "\"narrativeSummary\":\"" << JsonEscape(data.narrativeSummary) << "\","
        << "\"rootCauseAnalysis\":\"" << JsonEscape(data.rootCauseAnalysis) << "\","
        << "\"remediation\":\"" << JsonEscape(data.remediation) << "\","
        << "\"lessonsLearned\":\"" << JsonEscape(data.lessonsLearned) << "\"}";

    return oss.str();
}

// ============================================================================
// HTML EXPORT
// ============================================================================

std::string IncidentReportImpl::ExportHtml(const IncidentReportData& data) const {
    std::ostringstream oss;
    oss << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        << "<title>Incident Report — " << HtmlEscape(data.incidentId) << "</title>"
        << "<style>"
        << "body{font-family:system-ui,sans-serif;margin:2em;background:#0a0a0a;color:#e0e0e0;max-width:900px;margin:2em auto;}"
        << "h1{color:#00d4aa;}h2{color:#3ea8ff;border-bottom:1px solid #333;padding-bottom:0.3em;}"
        << ".meta{background:#1a1a2e;border-radius:8px;padding:1em;margin:1em 0;}"
        << ".meta span{display:inline-block;margin-right:2em;}"
        << ".meta .label{color:#888;font-size:0.85em;}"
        << ".meta .value{font-weight:bold;}"
        << ".critical{color:#ff4444;}.high{color:#ff8800;}.medium{color:#ffcc00;}.low{color:#88cc00;}"
        << "table{border-collapse:collapse;width:100%;margin:1em 0;}"
        << "th,td{border:1px solid #333;padding:8px 12px;text-align:left;}"
        << "th{background:#1a1a2e;color:#00d4aa;}"
        << "tr:nth-child(even){background:#111;}"
        << ".narrative{background:#111;border-left:3px solid #3ea8ff;padding:1em;margin:1em 0;line-height:1.6;}"
        << ".tag{display:inline-block;background:#1a1a2e;border:1px solid #333;border-radius:4px;padding:2px 8px;margin:2px;font-size:0.85em;}"
        << ".footer{margin-top:3em;color:#555;font-size:0.8em;border-top:1px solid #222;padding-top:1em;}"
        << "</style></head><body>";

    // Header
    oss << "<h1>Incident Report</h1>"
        << "<div class='meta'>"
        << "<span><span class='label'>ID: </span><span class='value'>"
        << HtmlEscape(data.incidentId) << "</span></span>"
        << "<span><span class='label'>Title: </span><span class='value'>"
        << HtmlEscape(data.title) << "</span></span>"
        << "<span><span class='label'>Severity: </span><span class='value ";

    // Severity color class (lowercase)
    {
        std::string sevLower = data.severity;
        for (auto& c : sevLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        oss << sevLower;
    }
    oss << "'>" << HtmlEscape(data.severity) << "</span></span>"
        << "<span><span class='label'>Status: </span><span class='value'>"
        << HtmlEscape(data.status) << "</span></span>"
        << "<span><span class='label'>Detected: </span><span class='value'>"
        << FormatTimestamp(data.detectedAt) << "</span></span>";
    if (data.closedAt != Clock::time_point{}) {
        oss << "<span><span class='label'>Closed: </span><span class='value'>"
            << FormatTimestamp(data.closedAt) << "</span></span>";
    }
    oss << "</div>";

    // Narrative
    if (!data.narrativeSummary.empty()) {
        oss << "<h2>Executive Summary</h2>"
            << "<div class='narrative'>" << HtmlEscape(data.narrativeSummary) << "</div>";
    }

    // Timeline
    if (!data.timeline.empty()) {
        oss << "<h2>Timeline</h2><table>"
            << "<tr><th>Timestamp</th><th>Event</th><th>Description</th><th>Actor</th></tr>";
        for (const auto& e : data.timeline) {
            oss << "<tr><td>" << FormatTimestamp(e.timestamp) << "</td>"
                << "<td>" << HtmlEscape(e.eventType) << "</td>"
                << "<td>" << HtmlEscape(e.description) << "</td>"
                << "<td>" << HtmlEscape(e.actor) << "</td></tr>";
        }
        oss << "</table>";
    }

    // IOCs
    if (!data.iocs.empty()) {
        oss << "<h2>Indicators of Compromise</h2><table>"
            << "<tr><th>#</th><th>IOC</th></tr>";
        for (size_t i = 0; i < data.iocs.size(); ++i) {
            oss << "<tr><td>" << (i + 1) << "</td>"
                << "<td><code>" << HtmlEscape(data.iocs[i]) << "</code></td></tr>";
        }
        oss << "</table>";
    }

    // MITRE ATT&CK
    if (!data.mitreAttackIds.empty()) {
        oss << "<h2>MITRE ATT&CK Techniques</h2><p>";
        for (const auto& id : data.mitreAttackIds) {
            oss << "<span class='tag'>" << HtmlEscape(id) << "</span>";
        }
        oss << "</p>";
    }

    // Affected assets
    if (!data.affectedAssets.empty()) {
        oss << "<h2>Affected Assets</h2><ul>";
        for (const auto& a : data.affectedAssets) {
            oss << "<li>" << HtmlEscape(a) << "</li>";
        }
        oss << "</ul>";
    }

    // Root cause
    if (!data.rootCauseAnalysis.empty()) {
        oss << "<h2>Root Cause Analysis</h2>"
            << "<div class='narrative'>" << HtmlEscape(data.rootCauseAnalysis) << "</div>";
    }

    // Remediation
    if (!data.remediation.empty()) {
        oss << "<h2>Remediation</h2>"
            << "<div class='narrative'>" << HtmlEscape(data.remediation) << "</div>";
    }

    // Lessons learned
    if (!data.lessonsLearned.empty()) {
        oss << "<h2>Lessons Learned</h2>"
            << "<div class='narrative'>" << HtmlEscape(data.lessonsLearned) << "</div>";
    }

    oss << "<div class='footer'>Generated by ShadowStrike PhantomEDR — "
        << FormatTimestamp(Clock::now()) << "</div>"
        << "</body></html>";
    return oss.str();
}

// ============================================================================
// GET GENERATED REPORTS
// ============================================================================

std::vector<ReportMetadata> IncidentReportImpl::GetGeneratedReports(uint32_t maxResults) const {
    std::shared_lock lk(m_mutex);
    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT report_id, incident_id, generated_at, file_path, file_size, format "
        "FROM edr_incident_reports ORDER BY generated_at DESC LIMIT ?",
        &dbErr, static_cast<int>(maxResults));

    std::vector<ReportMetadata> out;
    while (result.Next()) {
        ReportMetadata meta;
        meta.reportId = result.GetString(0);
        meta.type = ReportType::Incident;
        meta.generatedAt = FromMillis(result.GetInt64(2));
        meta.filePath = result.GetString(3);
        meta.fileSizeBytes = static_cast<uint64_t>(result.GetInt64(4));
        meta.format = static_cast<ReportFormat>(result.GetInt(5));
        meta.status = ReportStatus::Completed;
        out.push_back(std::move(meta));
    }
    return out;
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

IncidentReport::IncidentReport()
    : m_impl(std::make_unique<IncidentReportImpl>()) {}
IncidentReport::~IncidentReport() = default;

IncidentReport& IncidentReport::Instance() {
    static IncidentReport inst;
    return inst;
}

bool IncidentReport::Initialize() { return m_impl->Initialize(); }
void IncidentReport::Shutdown() { m_impl->Shutdown(); }
bool IncidentReport::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

IncidentReportData IncidentReport::GenerateReport(std::string_view incidentId) const {
    return m_impl->GenerateReport(incidentId);
}

std::string IncidentReport::ExportJson(const IncidentReportData& data) const {
    return m_impl->ExportJson(data);
}

std::string IncidentReport::ExportHtml(const IncidentReportData& data) const {
    return m_impl->ExportHtml(data);
}

std::vector<ReportMetadata> IncidentReport::GetGeneratedReports(uint32_t maxResults) const {
    return m_impl->GetGeneratedReports(maxResults);
}

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
