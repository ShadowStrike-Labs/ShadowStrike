/**
 * @file ProcessSnapshotCache.hpp
 * @brief One shared, short-lived process snapshot for all polling consumers.
 *
 * @par Why this exists
 * Several protection modules each took their own system-wide
 * @c CreateToolhelp32Snapshot on their own timer - the banking trojan detector
 * and keylogger protection twice a second each, the screenshot blocker ten times
 * a second. A Toolhelp snapshot walks the kernel's process list under kernel
 * locks, and those are the same locks the minifilter path needs, so the cost is
 * not just the CPU burned in user mode: it is contention against file and
 * process operations for the whole machine. On a two-core box this was enough to
 * stop the desktop responding while total CPU still looked moderate.
 *
 * Taking the same snapshot fourteen times a second from three places produces
 * fourteen identical answers. This collapses them into one.
 *
 * @par Why this loses no detection
 * Every consumer still sees every process. The only thing removed is the
 * redundant re-enumeration: within the freshness window the process list cannot
 * meaningfully differ, and a consumer that needs to know whether anything
 * changed can compare the generation counter instead of walking the list again.
 * Detection of a *new* process does not depend on snapshot frequency - that is
 * what the kernel's process-create notification is for, and it is both immediate
 * and cheaper than polling. Polling at 500 ms actually misses a process that
 * starts and exits in between; event delivery does not.
 *
 * @copyright ShadowStrike Labs. Licensed under AGPL-3.0.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ShadowStrike::Utils {

/// @brief Minimal identity for one running process.
struct ProcessSnapshotEntry {
    uint32_t     pid       = 0;
    uint32_t     parentPid = 0;
    std::wstring name;              ///< Image file name only (no path).
    uint32_t     threadCount = 0;
    int32_t      basePriority = 0;
};

/// @brief An immutable snapshot shared by every consumer.
struct ProcessSnapshot {
    std::vector<ProcessSnapshotEntry> processes;
    /// Increments whenever the observed set of PIDs differs from the previous
    /// snapshot. A consumer that only cares about arrivals and departures can
    /// compare this instead of re-examining every process.
    uint64_t                          generation = 0;
    /// Tick count when this snapshot was taken.
    uint64_t                          takenAtTick = 0;
};

/**
 * @brief Provides a shared process snapshot, refreshed at most once per window.
 *
 * Thread-safe. Consumers receive a shared_ptr to an immutable snapshot, so they
 * may read it without holding any lock and without copying the vector.
 */
class ProcessSnapshotCache {
public:
    /// @brief Minimum interval between two real enumerations.
    ///
    /// Chosen so the fastest consumer still sees sub-second freshness while the
    /// kernel process list is walked around once per second rather than fourteen
    /// times. Arrival latency for new processes is handled by kernel events, not
    /// by shortening this window.
    static constexpr uint64_t kFreshnessWindowMs = 1000;

    [[nodiscard]] static ProcessSnapshotCache& Instance() noexcept;

    /// @brief Get a snapshot, enumerating only if the cached one is stale.
    [[nodiscard]] std::shared_ptr<const ProcessSnapshot> Get();

    /// @brief Force the next Get() to re-enumerate.
    ///
    /// Used when a kernel process-create or process-exit notification arrives, so
    /// event delivery drives freshness rather than a timer.
    void Invalidate() noexcept;

    /// @brief Number of real enumerations performed (diagnostics).
    [[nodiscard]] uint64_t EnumerationCount() const noexcept;

    /// @brief Number of Get() calls served from cache (diagnostics).
    [[nodiscard]] uint64_t CacheHitCount() const noexcept;

private:
    ProcessSnapshotCache() = default;
    ~ProcessSnapshotCache() = default;
    ProcessSnapshotCache(const ProcessSnapshotCache&) = delete;
    ProcessSnapshotCache& operator=(const ProcessSnapshotCache&) = delete;
};

}  // namespace ShadowStrike::Utils
