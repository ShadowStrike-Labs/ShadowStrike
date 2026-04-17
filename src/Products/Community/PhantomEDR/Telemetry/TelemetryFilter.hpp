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
// ===========================================================================
// ShadowStrike – PhantomEDR Telemetry Filter
//
// Noise-reduction engine that decides which telemetry events to store and
// which to drop.  Applies process-allowlist, path-exclusion, frequency-cap,
// and severity-floor filters.  Events tagged with MITRE ATT&CK IDs always
// bypass all filters.
// ===========================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_set>

#include "TelemetryTypes.hpp"

namespace ShadowStrike::Products::PhantomEDR::Telemetry {

class TelemetryFilterImpl;

// ============================================================================
// FILTER CONFIGURATION
// ============================================================================

struct FilterConfig {
    bool enableProcessFilter   = true;
    bool enablePathFilter      = true;
    bool enableFrequencyFilter = true;

    /// Process allowlist — events from these processes are always dropped
    /// (noisy system processes).  Entries are bare filenames, matched
    /// case-insensitively against the event's process name.
    std::vector<std::wstring> processAllowlist;

    /// Path exclusions — events whose file/process/registry path falls
    /// under one of these prefixes are dropped.  Supports '*' as a
    /// single-component wildcard (e.g. L"C:\\Users\\*\\AppData\\Local\\Temp\\").
    std::vector<std::wstring> pathExclusions;

    /// Maximum events per (processId, category) per minute before the
    /// frequency-cap filter starts dropping.
    uint32_t maxEventsPerProcessPerCategoryPerMinute = 100;

    /// Events below this severity are dropped.
    EventSeverity minimumSeverity = EventSeverity::Info;

    /// Categories in this set are always kept regardless of other filters.
    std::unordered_set<EventCategory> alwaysKeepCategories;
};

// ============================================================================
// TELEMETRY FILTER  (Meyers' Singleton + PIMPL)
// ============================================================================

class TelemetryFilter {
public:
    [[nodiscard]] static TelemetryFilter& Instance();

    [[nodiscard]] bool Initialize(const FilterConfig& config);
    void Shutdown();

    /// Returns true if the event should be KEPT (stored), false if filtered.
    [[nodiscard]] bool ShouldKeep(const TelemetryEvent& event) const;

    // Dynamic filter updates (thread-safe)
    void AddProcessExclusion(std::wstring_view processName);
    void RemoveProcessExclusion(std::wstring_view processName);
    void AddPathExclusion(std::wstring_view path);
    void RemovePathExclusion(std::wstring_view path);
    void SetMinimumSeverity(EventSeverity severity);

    // Statistics
    [[nodiscard]] uint64_t GetFilteredCount() const noexcept;
    [[nodiscard]] uint64_t GetPassedCount() const noexcept;
    void ResetStats();

private:
    TelemetryFilter();
    ~TelemetryFilter();
    TelemetryFilter(const TelemetryFilter&)            = delete;
    TelemetryFilter& operator=(const TelemetryFilter&) = delete;

    std::unique_ptr<TelemetryFilterImpl> m_impl;
};

} // namespace ShadowStrike::Products::PhantomEDR::Telemetry
