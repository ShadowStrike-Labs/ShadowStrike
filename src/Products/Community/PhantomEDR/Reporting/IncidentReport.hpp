/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/Reporting/ReportTypes.hpp"

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

namespace ShadowStrike::Products::PhantomEDR::Reporting {

class IncidentReportImpl;

/// Per-incident narrative report generator.
/// Builds timeline, IOC lists, MITRE mappings, root-cause analysis,
/// and an auto-generated narrative summary from incident data.
class IncidentReport final {
public:
    [[nodiscard]] static IncidentReport& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Generate a full incident report.
    [[nodiscard]] IncidentReportData GenerateReport(std::string_view incidentId) const;

    /// Export to JSON string.
    [[nodiscard]] std::string ExportJson(const IncidentReportData& data) const;

    /// Export to HTML string.
    [[nodiscard]] std::string ExportHtml(const IncidentReportData& data) const;

    /// Get all incident reports generated so far.
    [[nodiscard]] std::vector<ReportMetadata> GetGeneratedReports(uint32_t maxResults = 50) const;

private:
    IncidentReport();
    ~IncidentReport();
    IncidentReport(const IncidentReport&) = delete;
    IncidentReport& operator=(const IncidentReport&) = delete;
    IncidentReport(IncidentReport&&) = delete;
    IncidentReport& operator=(IncidentReport&&) = delete;
    std::unique_ptr<IncidentReportImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
