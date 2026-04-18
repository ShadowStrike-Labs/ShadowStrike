/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */

#include "Products/Community/PhantomEDR/Reporting/ExecutiveSummary.hpp"

#include "PhantomCore/Database/DatabaseManager.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <format>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR::Reporting {

using ShadowStrike::Utils::Logger;
namespace SU = ShadowStrike::Utils::StringUtils;

static constexpr std::string_view kLogPrefix = "[ExecutiveSummary]";

// ============================================================================
// TIME HELPERS
// ============================================================================

static int64_t ToMillis(Clock::time_point tp) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
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
// IMPL
// ============================================================================

class ExecutiveSummaryImpl {
public:
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const noexcept { return m_initialized; }

    KPIMetrics ComputeMetrics(Clock::time_point periodStart,
                              Clock::time_point periodEnd) const;
    std::string GenerateJson(const KPIMetrics& metrics) const;
    std::string GenerateHtml(const KPIMetrics& metrics) const;

private:
    void QueryIncidentMetrics(KPIMetrics& m, int64_t startMs, int64_t endMs) const;
    void QueryThreatMetrics(KPIMetrics& m, int64_t startMs, int64_t endMs) const;
    void QueryTimingMetrics(KPIMetrics& m, int64_t startMs, int64_t endMs) const;
    void QuerySandboxMetrics(KPIMetrics& m, int64_t startMs, int64_t endMs) const;
    void QueryComplianceMetrics(KPIMetrics& m, int64_t startMs, int64_t endMs) const;

    mutable std::shared_mutex m_mutex;
    bool m_initialized = false;
};

// ============================================================================
// INITIALIZE / SHUTDOWN
// ============================================================================

bool ExecutiveSummaryImpl::Initialize() {
    std::unique_lock lk(m_mutex);
    if (m_initialized) return true;
    m_initialized = true;
    Logger::Info("{} Initialized", kLogPrefix);
    return true;
}

void ExecutiveSummaryImpl::Shutdown() {
    std::unique_lock lk(m_mutex);
    m_initialized = false;
    Logger::Info("{} Shutdown complete", kLogPrefix);
}

// ============================================================================
// COMPUTE METRICS — master aggregator
// ============================================================================

KPIMetrics ExecutiveSummaryImpl::ComputeMetrics(
    Clock::time_point periodStart, Clock::time_point periodEnd) const {

    std::shared_lock lk(m_mutex);
    KPIMetrics m;
    m.periodStart = periodStart;
    m.periodEnd = periodEnd;

    const int64_t startMs = ToMillis(periodStart);
    const int64_t endMs = ToMillis(periodEnd);

    QueryIncidentMetrics(m, startMs, endMs);
    QueryThreatMetrics(m, startMs, endMs);
    QueryTimingMetrics(m, startMs, endMs);
    QuerySandboxMetrics(m, startMs, endMs);
    QueryComplianceMetrics(m, startMs, endMs);

    return m;
}

// ============================================================================
// INCIDENT METRICS — from edr_incidents table
// ============================================================================

void ExecutiveSummaryImpl::QueryIncidentMetrics(
    KPIMetrics& m, int64_t startMs, int64_t endMs) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT severity, COUNT(*) FROM edr_incidents "
        "WHERE created_at >= ? AND created_at <= ? GROUP BY severity",
        &dbErr, startMs, endMs);

    uint32_t total = 0;
    while (result.Next()) {
        const int sev = result.GetInt(0);
        const int cnt = result.GetInt(1);
        total += static_cast<uint32_t>(cnt);
        switch (sev) {
            case 5: m.criticalIncidents = static_cast<uint32_t>(cnt); break;
            case 4: m.highIncidents = static_cast<uint32_t>(cnt); break;
            case 3: m.mediumIncidents = static_cast<uint32_t>(cnt); break;
            case 2: m.lowIncidents = static_cast<uint32_t>(cnt); break;
            default: break;
        }
    }
    m.totalIncidents = total;

    // False positives
    auto fpResult = db.QueryWithParams(
        "SELECT COUNT(*) FROM edr_incidents "
        "WHERE created_at >= ? AND created_at <= ? AND status = 6",
        &dbErr, startMs, endMs);
    if (fpResult.Next()) {
        m.falsePositives = static_cast<uint32_t>(fpResult.GetInt(0));
    }
}

// ============================================================================
// THREAT METRICS — from edr_telemetry_events table
// ============================================================================

void ExecutiveSummaryImpl::QueryThreatMetrics(
    KPIMetrics& m, int64_t startMs, int64_t endMs) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // Total threats detected (severity >= Medium in telemetry)
    auto detResult = db.QueryWithParams(
        "SELECT COUNT(*) FROM edr_telemetry_events "
        "WHERE timestamp >= ? AND timestamp <= ? AND severity >= 2",
        &dbErr, startMs, endMs);
    if (detResult.Next()) {
        m.totalThreatsDetected = static_cast<uint32_t>(detResult.GetInt(0));
    }

    // Threats blocked (action taken by the engine)
    auto blockResult = db.QueryWithParams(
        "SELECT COUNT(*) FROM edr_telemetry_events "
        "WHERE timestamp >= ? AND timestamp <= ? AND severity >= 2 AND action_taken = 1",
        &dbErr, startMs, endMs);
    if (blockResult.Next()) {
        m.totalThreatsBlocked = static_cast<uint32_t>(blockResult.GetInt(0));
    }

    // Breakdown by threat category
    // Categories stored as integer in edr_scan_results or telemetry
    auto catResult = db.QueryWithParams(
        "SELECT threat_category, "
        "  SUM(CASE WHEN action_taken = 1 THEN 1 ELSE 0 END) AS blocked, "
        "  SUM(CASE WHEN action_taken = 2 THEN 1 ELSE 0 END) AS quarantined, "
        "  SUM(CASE WHEN action_taken = 0 THEN 1 ELSE 0 END) AS allowed, "
        "  COUNT(*) AS total "
        "FROM edr_telemetry_events "
        "WHERE timestamp >= ? AND timestamp <= ? AND severity >= 2 "
        "GROUP BY threat_category",
        &dbErr, startMs, endMs);

    while (catResult.Next()) {
        ThreatSummary ts;
        ts.category = static_cast<ThreatCategory>(catResult.GetInt(0));
        ts.blocked = static_cast<uint32_t>(catResult.GetInt(1));
        ts.quarantined = static_cast<uint32_t>(catResult.GetInt(2));
        ts.allowed = static_cast<uint32_t>(catResult.GetInt(3));
        ts.count = static_cast<uint32_t>(catResult.GetInt(4));
        m.threatBreakdown.push_back(ts);
    }
}

// ============================================================================
// TIMING METRICS — MTTD and MTTR
// ============================================================================

void ExecutiveSummaryImpl::QueryTimingMetrics(
    KPIMetrics& m, int64_t startMs, int64_t endMs) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // MTTD: average(created_at - first_event_time) for incidents in the period
    // first_event_time is when the earliest related alert fired
    auto mttdResult = db.QueryWithParams(
        "SELECT AVG(created_at - first_event_time) "
        "FROM edr_incidents "
        "WHERE created_at >= ? AND created_at <= ? "
        "AND first_event_time > 0 AND first_event_time <= created_at",
        &dbErr, startMs, endMs);
    if (mttdResult.Next() && !mttdResult.IsNull(0)) {
        m.meanTimeToDetectMs = mttdResult.GetDouble(0);
    }

    // MTTR: average(closed_at - created_at) for incidents closed in the period
    auto mttrResult = db.QueryWithParams(
        "SELECT AVG(closed_at - created_at) "
        "FROM edr_incidents "
        "WHERE closed_at >= ? AND closed_at <= ? "
        "AND closed_at > created_at",
        &dbErr, startMs, endMs);
    if (mttrResult.Next() && !mttrResult.IsNull(0)) {
        m.meanTimeToRespondMs = mttrResult.GetDouble(0);
    }
}

// ============================================================================
// SANDBOX METRICS — from edr_sandbox_detonations
// ============================================================================

void ExecutiveSummaryImpl::QuerySandboxMetrics(
    KPIMetrics& m, int64_t startMs, int64_t endMs) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    auto result = db.QueryWithParams(
        "SELECT COUNT(*), "
        "  SUM(CASE WHEN verdict >= 3 THEN 1 ELSE 0 END) "
        "FROM edr_sandbox_detonations "
        "WHERE submitted_at >= ? AND submitted_at <= ?",
        &dbErr, startMs, endMs);

    if (result.Next()) {
        m.sandboxDetonations = static_cast<uint32_t>(result.GetInt(0));
        m.maliciousDetonations = static_cast<uint32_t>(result.GetInt(1));
    }
}

// ============================================================================
// COMPLIANCE METRICS — from edr_compliance_checks
// ============================================================================

void ExecutiveSummaryImpl::QueryComplianceMetrics(
    KPIMetrics& m, int64_t startMs, int64_t endMs) const {

    auto& db = ShadowStrike::Database::DatabaseManager::Instance();
    ShadowStrike::Database::DatabaseError dbErr;

    // Latest compliance score within the period
    auto result = db.QueryWithParams(
        "SELECT overall_score FROM edr_compliance_checks "
        "WHERE checked_at <= ? ORDER BY checked_at DESC LIMIT 1",
        &dbErr, endMs);

    if (result.Next()) {
        m.complianceScore = static_cast<uint32_t>(result.GetInt(0));
    }
}

// ============================================================================
// JSON OUTPUT
// ============================================================================

std::string ExecutiveSummaryImpl::GenerateJson(const KPIMetrics& metrics) const {
    std::ostringstream oss;
    oss << "{\"periodStart\":\"" << FormatTimestamp(metrics.periodStart) << "\","
        << "\"periodEnd\":\"" << FormatTimestamp(metrics.periodEnd) << "\","
        << "\"totalThreatsDetected\":" << metrics.totalThreatsDetected << ","
        << "\"totalThreatsBlocked\":" << metrics.totalThreatsBlocked << ","
        << "\"totalIncidents\":" << metrics.totalIncidents << ","
        << "\"criticalIncidents\":" << metrics.criticalIncidents << ","
        << "\"highIncidents\":" << metrics.highIncidents << ","
        << "\"mediumIncidents\":" << metrics.mediumIncidents << ","
        << "\"lowIncidents\":" << metrics.lowIncidents << ","
        << "\"falsePositives\":" << metrics.falsePositives << ","
        << "\"meanTimeToDetectMs\":" << std::format("{:.2f}", metrics.meanTimeToDetectMs) << ","
        << "\"meanTimeToRespondMs\":" << std::format("{:.2f}", metrics.meanTimeToRespondMs) << ","
        << "\"complianceScore\":" << metrics.complianceScore << ","
        << "\"sandboxDetonations\":" << metrics.sandboxDetonations << ","
        << "\"maliciousDetonations\":" << metrics.maliciousDetonations << ","
        << "\"threatBreakdown\":[";

    for (size_t i = 0; i < metrics.threatBreakdown.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& tb = metrics.threatBreakdown[i];
        oss << "{\"category\":\"" << JsonEscape(std::string(ToString(tb.category))) << "\","
            << "\"count\":" << tb.count << ","
            << "\"blocked\":" << tb.blocked << ","
            << "\"quarantined\":" << tb.quarantined << ","
            << "\"allowed\":" << tb.allowed << "}";
    }
    oss << "]}";
    return oss.str();
}

// ============================================================================
// HTML OUTPUT
// ============================================================================

std::string ExecutiveSummaryImpl::GenerateHtml(const KPIMetrics& metrics) const {
    std::ostringstream oss;
    oss << "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        << "<title>ShadowStrike Executive Summary</title>"
        << "<style>"
        << "body{font-family:system-ui,sans-serif;margin:2em;background:#0a0a0a;color:#e0e0e0;}"
        << "h1{color:#00d4aa;margin-bottom:0.3em;}"
        << "h2{color:#3ea8ff;border-bottom:1px solid #333;padding-bottom:0.3em;}"
        << ".subtitle{color:#888;margin-top:0;}"
        << ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1em;margin:1.5em 0;}"
        << ".card{background:#1a1a2e;border-radius:10px;padding:1.2em;text-align:center;border:1px solid #222;}"
        << ".card .value{font-size:2.2em;font-weight:bold;color:#00d4aa;}"
        << ".card .label{font-size:0.8em;color:#999;margin-top:0.3em;}"
        << ".card.alert .value{color:#ff4444;}"
        << ".card.warn .value{color:#ff8800;}"
        << "table{border-collapse:collapse;width:100%;margin:1em 0;}"
        << "th,td{border:1px solid #333;padding:8px 12px;text-align:left;}"
        << "th{background:#1a1a2e;color:#00d4aa;}"
        << "tr:nth-child(even){background:#111;}"
        << ".footer{margin-top:3em;color:#555;font-size:0.8em;border-top:1px solid #222;padding-top:1em;}"
        << "</style></head><body>"
        << "<h1>ShadowStrike — Executive Summary</h1>"
        << "<p class='subtitle'>Period: " << FormatTimestamp(metrics.periodStart)
        << " — " << FormatTimestamp(metrics.periodEnd) << "</p>";

    // KPI cards
    oss << "<h2>Key Performance Indicators</h2>"
        << "<div class='grid'>"
        << "<div class='card'><div class='value'>" << metrics.totalThreatsDetected << "</div><div class='label'>Threats Detected</div></div>"
        << "<div class='card'><div class='value'>" << metrics.totalThreatsBlocked << "</div><div class='label'>Threats Blocked</div></div>"
        << "<div class='card" << (metrics.criticalIncidents > 0 ? " alert" : "") << "'>"
        << "<div class='value'>" << metrics.totalIncidents << "</div><div class='label'>Total Incidents</div></div>"
        << "<div class='card" << (metrics.criticalIncidents > 0 ? " alert" : "") << "'>"
        << "<div class='value'>" << metrics.criticalIncidents << "</div><div class='label'>Critical Incidents</div></div>"
        << "<div class='card'><div class='value'>" << std::format("{:.1f}s", metrics.meanTimeToDetectMs / 1000.0)
        << "</div><div class='label'>Mean Time to Detect</div></div>"
        << "<div class='card'><div class='value'>" << std::format("{:.1f}s", metrics.meanTimeToRespondMs / 1000.0)
        << "</div><div class='label'>Mean Time to Respond</div></div>"
        << "<div class='card'><div class='value'>" << metrics.complianceScore << "%</div><div class='label'>Compliance Score</div></div>"
        << "<div class='card'><div class='value'>" << metrics.falsePositives << "</div><div class='label'>False Positives</div></div>"
        << "<div class='card'><div class='value'>" << metrics.sandboxDetonations << "</div><div class='label'>Sandbox Detonations</div></div>"
        << "<div class='card" << (metrics.maliciousDetonations > 0 ? " warn" : "") << "'>"
        << "<div class='value'>" << metrics.maliciousDetonations << "</div><div class='label'>Malicious Detonations</div></div>"
        << "</div>";

    // Incident breakdown
    oss << "<h2>Incidents by Severity</h2>"
        << "<table><tr><th>Severity</th><th>Count</th><th>% of Total</th></tr>";
    struct SevRow { const char* name; uint32_t count; };
    const SevRow sevRows[] = {
        {"Critical", metrics.criticalIncidents},
        {"High", metrics.highIncidents},
        {"Medium", metrics.mediumIncidents},
        {"Low", metrics.lowIncidents}
    };
    for (const auto& sr : sevRows) {
        const double pct = (metrics.totalIncidents > 0)
            ? (static_cast<double>(sr.count) / metrics.totalIncidents * 100.0) : 0.0;
        oss << "<tr><td>" << sr.name << "</td><td>" << sr.count
            << "</td><td>" << std::format("{:.1f}%", pct) << "</td></tr>";
    }
    oss << "</table>";

    // Threat breakdown
    if (!metrics.threatBreakdown.empty()) {
        oss << "<h2>Threat Categories</h2>"
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

    oss << "<div class='footer'>Generated by ShadowStrike PhantomEDR — "
        << FormatTimestamp(Clock::now()) << "</div>"
        << "</body></html>";
    return oss.str();
}

// ============================================================================
// SINGLETON FORWARDING
// ============================================================================

ExecutiveSummary::ExecutiveSummary()
    : m_impl(std::make_unique<ExecutiveSummaryImpl>()) {}
ExecutiveSummary::~ExecutiveSummary() = default;

ExecutiveSummary& ExecutiveSummary::Instance() {
    static ExecutiveSummary inst;
    return inst;
}

bool ExecutiveSummary::Initialize() { return m_impl->Initialize(); }
void ExecutiveSummary::Shutdown() { m_impl->Shutdown(); }
bool ExecutiveSummary::IsInitialized() const noexcept { return m_impl->IsInitialized(); }

KPIMetrics ExecutiveSummary::ComputeMetrics(Clock::time_point periodStart,
                                            Clock::time_point periodEnd) const {
    return m_impl->ComputeMetrics(periodStart, periodEnd);
}

std::string ExecutiveSummary::GenerateJson(const KPIMetrics& metrics) const {
    return m_impl->GenerateJson(metrics);
}

std::string ExecutiveSummary::GenerateHtml(const KPIMetrics& metrics) const {
    return m_impl->GenerateHtml(metrics);
}

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
