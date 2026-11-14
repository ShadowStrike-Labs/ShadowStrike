/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "../Utils/ProcessUtils.hpp"
#include "../Utils/Logger.hpp"

/**
 * @file WholeFileAllocationProbe.hpp
 * @brief Attributes the service memory peak to the whole-file allocation sites,
 *        for task 238.
 *
 * WHY THIS EXISTS
 * ---------------
 * The service peaked at 3.1 GB against its own 1 GB target and the peak was
 * never attributed: the emulator's doubled read is fixed (task 240) but the
 * remaining whole-file heap reads - HeuristicAnalyzer's AnalyzeFile, QuickScan
 * and CalculateFileEntropy, RealTimeProtection's deferred deep scan, and the
 * YARA rule compilation in LoadRulesInternal - were never measured, so it is
 * unknown which of them (or which combination, under maxConcurrentScans) drives
 * the peak. Task 238 is explicit: MEASURE before changing anything else.
 *
 * WHAT IT DOES
 * ------------
 * Each instrumented site calls Note() immediately after its whole-file
 * allocation. Note() samples the process working set and advances a lock-free
 * high-water mark. When the working set climbs materially past the last value
 * logged, it emits ONE service-log line naming the site and the bytes it had
 * just allocated. The log therefore contains the trail of sites that drove the
 * working set up to its peak, which is exactly the attribution the task needs,
 * and it lands in the service log that the VM harness already collects.
 *
 * WHY IT DOES NOT FLOOD
 * ---------------------
 * It is a MEASUREMENT, on the on-access hot path, so it must be quiet in the
 * common case. The log fires only when the working set reaches a NEW high-water
 * mark at least kAdvanceThresholdBytes above the last line - on a steady-state
 * machine the working set does not keep climbing, so after the first few lines
 * it goes silent until a genuinely larger peak occurs. A working-set query is
 * one syscall, taken only at whole-file allocation sites that have just done
 * far more expensive file I/O, so its cost is noise against the read it follows.
 *
 * This is header-only on purpose: the state is a pair of process-wide atomics
 * held in function-local statics, so there is no new translation unit to wire
 * into the build and no ordering dependency on a separate .cpp.
 */

namespace ShadowStrike::Diagnostics::WholeFileAllocationProbe {

namespace detail {

/// @brief The monotonic high-water mark, read by PeakWorkingSetBytes().
inline std::atomic<std::uint64_t>& PeakRef() noexcept {
    static std::atomic<std::uint64_t> peak{0};
    return peak;
}

/// @brief The working set at which the last line was logged; throttles output.
inline std::atomic<std::uint64_t>& LastLoggedRef() noexcept {
    static std::atomic<std::uint64_t> lastLogged{0};
    return lastLogged;
}

/// @brief Log only once the working set has climbed this far past the last line.
/// 32 MB is well under the 1 GB whole-file read cap, so no real jump is missed,
/// while small steady-state wobble produces nothing.
inline constexpr std::uint64_t kAdvanceThresholdBytes = 32ull * 1024ull * 1024ull;

} // namespace detail

/// @brief Records a working-set sample for a site and decides whether to log it.
///
/// The working set is SUPPLIED rather than sampled so the high-water-mark and
/// throttle logic can be driven deterministically by a unit test. Returns true
/// iff this sample advanced the logged high-water mark (i.e. it emitted a line).
inline bool RecordSample(const char* site, std::size_t requestedBytes,
                         std::uint64_t workingSetBytes) noexcept {
    // Advance the monotonic high-water mark. Relaxed is sufficient: the value is
    // a diagnostic maximum, not a synchronisation point for other data.
    std::uint64_t prevPeak = detail::PeakRef().load(std::memory_order_relaxed);
    while (workingSetBytes > prevPeak &&
           !detail::PeakRef().compare_exchange_weak(prevPeak, workingSetBytes,
                                                    std::memory_order_relaxed)) {
    }

    // Emit a line only when the working set has advanced materially past the
    // last value logged. The CAS makes "who logs this step" unambiguous under
    // concurrent scans, so at most one line is written per genuine advance.
    std::uint64_t lastLogged = detail::LastLoggedRef().load(std::memory_order_relaxed);
    while (workingSetBytes >= lastLogged + detail::kAdvanceThresholdBytes) {
        if (detail::LastLoggedRef().compare_exchange_weak(
                lastLogged, workingSetBytes, std::memory_order_relaxed)) {
            // Guarded: this runs on the on-access hot path inside a noexcept
            // probe, so a throwing logger must not take the process down.
            try {
                ::ShadowStrike::Utils::Logger::Info(
                    "MEM-PEAK: working set {} MB reached at whole-file allocation "
                    "site {} (just requested {} bytes) - task 238 attribution",
                    workingSetBytes / (1024ull * 1024ull),
                    site != nullptr ? site : "(unknown)",
                    static_cast<std::uint64_t>(requestedBytes));
            } catch (...) {
            }
            return true;
        }
    }
    return false;
}

/// @brief Samples the current process working set at a whole-file allocation
/// site; emits one attribution line when a new high-water mark is crossed.
/// Call immediately after the allocation, so the sample includes it.
inline void Note(const char* site, std::size_t requestedBytes) noexcept {
    ::ShadowStrike::Utils::ProcessUtils::ProcessMemoryInfo mem;
    if (!::ShadowStrike::Utils::ProcessUtils::GetProcessMemoryInfo(
            ::ShadowStrike::Utils::ProcessUtils::GetCurrentProcessId(), mem,
            nullptr)) {
        return;  // Degrade to a no-op rather than disturb the caller.
    }
    (void)RecordSample(site, requestedBytes,
                       static_cast<std::uint64_t>(mem.workingSetSize));
}

/// @brief Highest working set (bytes) observed at any instrumented site this
/// session. Monotonic for the life of the process.
[[nodiscard]] inline std::uint64_t PeakWorkingSetBytes() noexcept {
    return detail::PeakRef().load(std::memory_order_relaxed);
}

/// @brief Test-only: clears the high-water mark and the last-logged value so a
/// test starts from a known state.
inline void ResetForTesting() noexcept {
    detail::PeakRef().store(0, std::memory_order_relaxed);
    detail::LastLoggedRef().store(0, std::memory_order_relaxed);
}

} // namespace ShadowStrike::Diagnostics::WholeFileAllocationProbe
