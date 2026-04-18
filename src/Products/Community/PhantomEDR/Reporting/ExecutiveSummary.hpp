/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 */
#pragma once

#include "Products/Community/PhantomEDR/Reporting/ReportTypes.hpp"

#include <memory>
#include <string_view>

namespace ShadowStrike::Products::PhantomEDR::Reporting {

class ExecutiveSummaryImpl;

/// Generates KPI dashboard data: threats blocked, MTTD, MTTR, compliance
/// score, incident breakdown. Aggregates data from Telemetry, Incidents,
/// Compliance, and Sandboxing subsystems.
class ExecutiveSummary final {
public:
    [[nodiscard]] static ExecutiveSummary& Instance();
    [[nodiscard]] bool Initialize();
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    /// Compute KPI metrics for a time period.
    [[nodiscard]] KPIMetrics ComputeMetrics(Clock::time_point periodStart,
                                            Clock::time_point periodEnd) const;

    /// Generate a JSON string of the executive summary.
    [[nodiscard]] std::string GenerateJson(const KPIMetrics& metrics) const;

    /// Generate an HTML string of the executive summary.
    [[nodiscard]] std::string GenerateHtml(const KPIMetrics& metrics) const;

private:
    ExecutiveSummary();
    ~ExecutiveSummary();
    ExecutiveSummary(const ExecutiveSummary&) = delete;
    ExecutiveSummary& operator=(const ExecutiveSummary&) = delete;
    ExecutiveSummary(ExecutiveSummary&&) = delete;
    ExecutiveSummary& operator=(ExecutiveSummary&&) = delete;
    std::unique_ptr<ExecutiveSummaryImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Reporting
