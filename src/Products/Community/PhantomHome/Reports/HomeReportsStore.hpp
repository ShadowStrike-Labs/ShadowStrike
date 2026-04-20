/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file HomeReportsStore.hpp
 * @brief In-memory journal of Phantom Home reportable events (scans,
 *        threats, updates, policy changes).
 *
 * Community tier stores reports in-process only. Durable SQLite persistence
 * is tracked by a later tier (T6); the IPC contract and UI integration are
 * unchanged when that backend lands because consumers interact only through
 * this facade.
 *
 * Design
 * ------
 *   - Meyers' singleton. No globals, no double-checked locking.
 *   - Bounded ring buffer (kMaxEntries). Oldest entries are dropped first
 *     so a flood of events cannot exhaust process memory.
 *   - std::shared_mutex: concurrent readers, exclusive writers.
 *   - All mutating entry points are noexcept and swallow exceptions so a
 *     journal failure can never destabilise the caller (scan worker,
 *     protection module callback, IPC handler).
 *   - Strings are clamped to hard caps in the implementation so a hostile
 *     input (e.g. a crafted filename path) cannot balloon the in-memory
 *     footprint of a single entry.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike::PhantomHome::Reports {

/**
 * Report category. Integer values are part of the IPC wire contract
 * (ReportEntry::kind is transmitted as uint32_t). Do not renumber.
 */
enum class ReportKind : std::uint32_t {
    Unknown          = 0,
    ScanCompleted    = 1,
    ThreatDetected   = 2,
    ThreatQuarantined = 3,
    UpdateInstalled  = 4,
    PolicyChanged    = 5,
    ModuleStateChange = 6,
};

/**
 * Severity ladder. Integer values are part of the IPC wire contract.
 * Do not renumber.
 */
enum class ReportSeverity : std::uint32_t {
    Info     = 0,
    Low      = 1,
    Medium   = 2,
    High     = 3,
    Critical = 4,
};

/**
 * A single journal entry. `module` is NOT named `module` on the IPC wire
 * side because `module` is a C++20 keyword in some contexts and clashes
 * with Qt's moc; the IPC layer uses `module_name` instead.
 */
struct ReportEntry {
    std::uint64_t   id                = 0;   ///< 0 on input → auto-assigned.
    std::int64_t    timestamp_unix_ms = 0;   ///< 0 on input → set to now.
    ReportKind      kind              = ReportKind::Unknown;
    ReportSeverity  severity          = ReportSeverity::Info;

    std::string     module;          ///< Producing subsystem (e.g. "ScanEngine").
    std::string     title;           ///< Short human-readable summary.
    std::string     description;     ///< Detailed text (clamped).
    std::string     target;          ///< Subject path / URL / indicator.
    std::string     action;          ///< Resulting action (e.g. "Quarantined").

    std::string     scan_id;         ///< Populated for scan-related entries.
    std::uint64_t   files_scanned    = 0;
    std::uint64_t   threats_found    = 0;
    std::int64_t    duration_ms      = 0;
};

/**
 * Filter for Query(). Empty optionals mean "no filter on this field".
 */
struct ReportQuery {
    std::optional<ReportKind>     kind;
    std::optional<ReportSeverity> min_severity;
    std::optional<std::uint64_t>  since_id;      ///< Returns entries with id > since_id.
    std::size_t                   max_entries = 256;
};

class HomeReportsStore {
public:
    static constexpr std::size_t kMaxEntries = 1024;

    [[nodiscard]] static HomeReportsStore& Instance() noexcept;

    HomeReportsStore(const HomeReportsStore&)            = delete;
    HomeReportsStore& operator=(const HomeReportsStore&) = delete;
    HomeReportsStore(HomeReportsStore&&)                 = delete;
    HomeReportsStore& operator=(HomeReportsStore&&)      = delete;

    /// Append a new entry (id and timestamp auto-filled if zero).
    void Record(ReportEntry entry) noexcept;

    /// Fast-path helper used by the IPC scan worker.
    void RecordScanCompleted(std::string_view scan_id,
                             std::uint64_t   files_scanned,
                             std::uint64_t   threats_found,
                             std::int64_t    duration_ms) noexcept;

    /// Fast-path helper used by real-time detection callbacks.
    void RecordThreatDetected(std::string_view target,
                              std::string_view description,
                              std::string_view action,
                              ReportSeverity   severity) noexcept;

    [[nodiscard]] std::vector<ReportEntry> Query(const ReportQuery& q) const;
    [[nodiscard]] std::vector<ReportEntry> GetRecent(std::size_t max_entries) const;

    [[nodiscard]] std::size_t Size() const noexcept;

    void Clear() noexcept;

private:
    HomeReportsStore()  = default;
    ~HomeReportsStore() = default;

    mutable std::shared_mutex   mtx_;
    std::deque<ReportEntry>     entries_;
    std::atomic<std::uint64_t>  next_id_{1};
};

}  // namespace ShadowStrike::PhantomHome::Reports
