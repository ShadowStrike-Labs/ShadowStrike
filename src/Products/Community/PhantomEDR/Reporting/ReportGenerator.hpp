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

class ReportGeneratorImpl;

/// Scheduled and on-demand report generation engine.
/// Produces HTML/JSON reports served to the localhost dashboard.
class ReportGenerator final {
public:
    [[nodiscard]] static ReportGenerator& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Generate a report on demand for the given time period.
    [[nodiscard]] ReportMetadata Generate(ReportType type, ReportFormat format,
                                          Clock::time_point periodStart,
                                          Clock::time_point periodEnd);

    /// Get metadata for a previously generated report.
    [[nodiscard]] std::optional<ReportMetadata> GetReport(std::string_view reportId) const;

    /// Get all report metadata, most recent first.
    [[nodiscard]] std::vector<ReportMetadata> GetReportHistory(uint32_t maxResults = 50) const;

    /// Delete a report and its file.
    [[nodiscard]] bool DeleteReport(std::string_view reportId);

    /// Get the output directory for reports.
    [[nodiscard]] std::string GetOutputDirectory() const;

private:
    ReportGenerator();
    ~ReportGenerator();
    ReportGenerator(const ReportGenerator&) = delete;
    ReportGenerator& operator=(const ReportGenerator&) = delete;
    ReportGenerator(ReportGenerator&&) = delete;
    ReportGenerator& operator=(ReportGenerator&&) = delete;
    std::unique_ptr<ReportGeneratorImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
