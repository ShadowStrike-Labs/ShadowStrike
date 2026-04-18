/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Reporting {

using Clock = std::chrono::system_clock;

// ============================================================================
// ENUMERATIONS
// ============================================================================

enum class ReportFormat : uint8_t {
    JSON = 0,
    HTML = 1
};

enum class ReportType : uint8_t {
    Daily       = 0,
    Weekly      = 1,
    Monthly     = 2,
    Incident    = 3,
    Executive   = 4,
    OnDemand    = 5
};

enum class ReportStatus : uint8_t {
    Pending     = 0,
    Generating  = 1,
    Completed   = 2,
    Failed      = 3
};

enum class ThreatCategory : uint8_t {
    Malware     = 0,
    Ransomware  = 1,
    Phishing    = 2,
    Exploit     = 3,
    PUP         = 4,
    Suspicious  = 5,
    Other       = 255
};

// ============================================================================
// TOSTRING HELPERS
// ============================================================================

[[nodiscard]] constexpr std::string_view ToString(ReportFormat f) noexcept {
    switch (f) {
        case ReportFormat::JSON: return "JSON";
        case ReportFormat::HTML: return "HTML";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(ReportType t) noexcept {
    switch (t) {
        case ReportType::Daily:     return "Daily";
        case ReportType::Weekly:    return "Weekly";
        case ReportType::Monthly:   return "Monthly";
        case ReportType::Incident:  return "Incident";
        case ReportType::Executive: return "Executive";
        case ReportType::OnDemand:  return "On-Demand";
    }
    return "Unknown";
}

[[nodiscard]] constexpr std::string_view ToString(ThreatCategory c) noexcept {
    switch (c) {
        case ThreatCategory::Malware:    return "Malware";
        case ThreatCategory::Ransomware: return "Ransomware";
        case ThreatCategory::Phishing:   return "Phishing";
        case ThreatCategory::Exploit:    return "Exploit";
        case ThreatCategory::PUP:        return "PUP";
        case ThreatCategory::Suspicious: return "Suspicious";
        case ThreatCategory::Other:      return "Other";
    }
    return "Unknown";
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

struct ThreatSummary {
    ThreatCategory  category = ThreatCategory::Other;
    uint32_t        count = 0;
    uint32_t        blocked = 0;
    uint32_t        quarantined = 0;
    uint32_t        allowed = 0;  // false negatives / user overrides
};

struct KPIMetrics {
    Clock::time_point periodStart;
    Clock::time_point periodEnd;

    uint32_t totalThreatsDetected = 0;
    uint32_t totalThreatsBlocked = 0;
    uint32_t totalIncidents = 0;
    uint32_t criticalIncidents = 0;
    uint32_t highIncidents = 0;
    uint32_t mediumIncidents = 0;
    uint32_t lowIncidents = 0;
    uint32_t falsePositives = 0;

    double   meanTimeToDetectMs = 0.0;   // MTTD
    double   meanTimeToRespondMs = 0.0;  // MTTR

    uint32_t endpointScansCompleted = 0;
    uint32_t complianceScore = 0;       // 0-100
    uint32_t sandboxDetonations = 0;
    uint32_t maliciousDetonations = 0;

    std::vector<ThreatSummary> threatBreakdown;
};

struct IncidentTimelineEntry {
    Clock::time_point timestamp;
    std::string       eventType;    // "Detection", "Containment", "Remediation", etc.
    std::string       description;
    std::string       actor;        // system/user who took the action
};

struct IncidentReportData {
    std::string incidentId;
    std::string title;
    std::string severity;       // "Critical", "High", etc.
    std::string status;
    Clock::time_point detectedAt;
    Clock::time_point closedAt;

    std::vector<std::string>          affectedAssets;
    std::vector<std::string>          iocs;
    std::vector<std::string>          mitreAttackIds;
    std::vector<IncidentTimelineEntry> timeline;

    std::string narrativeSummary;   // AI/template-generated narrative
    std::string rootCauseAnalysis;
    std::string remediation;
    std::string lessonsLearned;
};

struct ReportMetadata {
    std::string         reportId;
    ReportType          type = ReportType::OnDemand;
    ReportFormat        format = ReportFormat::JSON;
    ReportStatus        status = ReportStatus::Pending;
    Clock::time_point   generatedAt;
    Clock::time_point   periodStart;
    Clock::time_point   periodEnd;
    std::string         filePath;
    uint64_t            fileSizeBytes = 0;
};

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
