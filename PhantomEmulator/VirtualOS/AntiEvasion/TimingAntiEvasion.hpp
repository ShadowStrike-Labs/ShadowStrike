/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TimingAntiEvasion.hpp — Centralized timing consistency engine
 *
 * Malware uses paired timing calls (RDTSC, GetTickCount, QPC, FILETIME)
 * to detect sandboxes and emulators. This module derives ALL timing
 * values from a single monotonic instruction counter, guaranteeing
 * mathematical consistency across every timing source.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#pragma once

#include "../../Common/Types.hpp"
#include "../../Common/Config.hpp"
#include <cstdint>
#include <atomic>
#include <mutex>
#include <shared_mutex>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// TimingAntiEvasion — Single timing oracle for all guest timing queries
// ============================================================================

class TimingAntiEvasion {
public:
    [[nodiscard]] static TimingAntiEvasion& Instance() noexcept;

    void Initialize(const EmulationConfig& config) noexcept;
    void Reset() noexcept;

    // Advance the internal clock by emulated instruction count
    void AdvanceTick(uint32_t instructionCount = 1) noexcept;

    // Accelerated sleep: advances clock consistently without real delay
    void SimulateSleep(uint64_t milliseconds) noexcept;

    // === Timing queries (all derived from m_instructionCount) ===

    [[nodiscard]] uint64_t GetTSC() const noexcept;
    [[nodiscard]] uint32_t GetTickCount32() const noexcept;
    [[nodiscard]] uint64_t GetTickCount64() const noexcept;
    [[nodiscard]] int64_t  GetQPC() const noexcept;
    [[nodiscard]] int64_t  GetQPF() const noexcept;
    [[nodiscard]] uint64_t GetSystemTimeAsFileTime() const noexcept;

    struct SystemTime {
        uint16_t year;
        uint16_t month;
        uint16_t dayOfWeek;
        uint16_t day;
        uint16_t hour;
        uint16_t minute;
        uint16_t second;
        uint16_t milliseconds;
    };

    [[nodiscard]] SystemTime GetSystemTime() const noexcept;
    [[nodiscard]] SystemTime GetLocalTime() const noexcept;

    // === Configuration accessors ===

    [[nodiscard]] uint64_t GetTSCFrequency() const noexcept;
    [[nodiscard]] uint32_t GetTimingAcceleration() const noexcept;

private:
    TimingAntiEvasion() noexcept = default;
    ~TimingAntiEvasion() noexcept = default;
    TimingAntiEvasion(const TimingAntiEvasion&) = delete;
    TimingAntiEvasion& operator=(const TimingAntiEvasion&) = delete;

    // Convert a FILETIME value (100-ns intervals since Jan 1, 1601) to SystemTime
    [[nodiscard]] SystemTime FileTimeToSystemTime(uint64_t fileTime) const noexcept;

    // Compute elapsed seconds from instruction counter (returns fixed-point * 1e9)
    [[nodiscard]] uint64_t GetElapsedNanoseconds() const noexcept;

    // Single monotonic source — everything derives from this
    std::atomic<uint64_t> m_instructionCount{0};
    mutable std::shared_mutex m_mutex;

    // Base values (set at initialization)
    uint64_t m_baseTSC         = 0;
    uint64_t m_baseTickCount   = 0;
    uint64_t m_baseFileTime    = 0;

    // Conversion factors
    uint64_t m_tscFrequency       = 3'800'000'000ULL;
    uint64_t m_qpcFrequency       = 10'000'000ULL;
    uint32_t m_tscPerInstruction   = 25;
    uint32_t m_accelerationFactor  = 1000;
    int32_t  m_timezoneOffsetMinutes = -300; // EST = UTC-5

    bool m_initialized = false;
};

} // namespace Phantom::VirtualOS::AntiEvasion
