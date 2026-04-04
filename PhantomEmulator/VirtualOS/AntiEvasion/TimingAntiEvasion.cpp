/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * PhantomEmulator - Custom x86/x64 Emulation Engine
 *
 * TimingAntiEvasion.cpp — Centralized timing consistency engine
 *
 * Every guest-visible timing value (RDTSC, GetTickCount, QPC,
 * GetSystemTimeAsFileTime, GetSystemTime, GetLocalTime) derives
 * from one monotonic instruction counter.  No matter how the
 * malware cross-checks, all clocks agree.
 *
 * Copyright (C) 2025-2026 ShadowStrike Labs
 * AGPL-3.0 License
 */

#include "TimingAntiEvasion.hpp"
#include <algorithm>
#include <cstring>

namespace Phantom::VirtualOS::AntiEvasion {

// ============================================================================
// Calendar constants for FileTime ↔ SystemTime conversion
// ============================================================================

namespace {

// Days in each month for non-leap and leap years
constexpr uint16_t kDaysInMonth[2][12] = {
    { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },  // non-leap
    { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },  // leap
};

// Cumulative days before each month (non-leap / leap)
constexpr uint16_t kCumDays[2][13] = {
    { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 },
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366 },
};

[[nodiscard]] constexpr bool IsLeapYear(uint32_t year) noexcept {
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

[[nodiscard]] constexpr uint32_t DaysInYear(uint32_t year) noexcept {
    return IsLeapYear(year) ? 366 : 365;
}

// FILETIME epoch: January 1, 1601 00:00:00 UTC
// 100-nanosecond intervals per second
constexpr uint64_t kHundredNsPerSecond = 10'000'000ULL;
constexpr uint64_t kHundredNsPerMs     = 10'000ULL;
constexpr uint64_t kHundredNsPerMinute = kHundredNsPerSecond * 60;
constexpr uint64_t kHundredNsPerHour   = kHundredNsPerMinute * 60;
constexpr uint64_t kHundredNsPerDay    = kHundredNsPerHour * 24;

constexpr uint32_t kFileTimeEpochYear = 1601;

// Precomputed: April 2, 2026 10:30:00 UTC as FILETIME
// Days from Jan 1, 1601 to Jan 1, 2026:
//   425 years. Leap years in [1601..2025]: years divisible by 4 minus
//   centuries plus 400-multiples. Total: 103 leap years, 322 non-leap.
//   322*365 + 103*366 = 117530 + 37698 = 155228 days to Jan 1 2026.
//   Jan(31)+Feb(28)+Mar(31)+1 day into April = 91 more days → 155319 days.
//   155319 * 86400 + 10*3600 + 30*60 = 13419561600 + 37800 = 13419599400 sec.
//   × 10,000,000 = 134195994000000000
constexpr uint64_t kDefaultBaseFileTime = 134'195'994'000'000'000ULL;

// Reasonable randomization ranges for base values
constexpr uint64_t kMinBaseTSC       = 1'000'000'000ULL;
constexpr uint64_t kMaxBaseTSC       = 50'000'000'000ULL;
constexpr uint64_t kMinBaseTickCount = 300'000ULL;  // ~5 min uptime
constexpr uint64_t kMaxBaseTickCount = 900'000ULL;  // ~15 min uptime

// Simple deterministic hash for "random" base values (no <random> needed)
[[nodiscard]] constexpr uint64_t SplitMix64(uint64_t seed) noexcept {
    seed += 0x9E3779B97F4A7C15ULL;
    seed = (seed ^ (seed >> 30)) * 0xBF58476D1CE4E5B9ULL;
    seed = (seed ^ (seed >> 27)) * 0x94D049BB133111EBULL;
    return seed ^ (seed >> 31);
}

} // anonymous namespace

// ============================================================================
// Singleton
// ============================================================================

TimingAntiEvasion& TimingAntiEvasion::Instance() noexcept {
    static TimingAntiEvasion instance;
    return instance;
}

// ============================================================================
// Initialize — set all base values and conversion factors
// ============================================================================

void TimingAntiEvasion::Initialize(const EmulationConfig& config) noexcept {
    if (m_initialized) return;

    m_tscFrequency       = config.fakeTSCFrequency;
    m_qpcFrequency       = 10'000'000ULL; // Windows default: 10 MHz
    m_tscPerInstruction   = 25;
    m_accelerationFactor  = config.enableTimingAcceleration ? 1000 : 1;
    m_timezoneOffsetMinutes = -300; // EST (UTC-5)

    // Derive deterministic but varied base values from the TSC frequency seed
    const uint64_t seed = SplitMix64(m_tscFrequency ^ 0xDEADBEEFCAFEBABEULL);

    if (config.fakeTickCount != 0) {
        m_baseTickCount = config.fakeTickCount;
    } else {
        m_baseTickCount = kMinBaseTickCount +
            (SplitMix64(seed) % (kMaxBaseTickCount - kMinBaseTickCount));
    }

    m_baseTSC = kMinBaseTSC +
        (SplitMix64(seed ^ 0x1234567890ABCDEFULL) % (kMaxBaseTSC - kMinBaseTSC));

    m_baseFileTime = kDefaultBaseFileTime;

    m_instructionCount.store(0, std::memory_order_relaxed);
    m_initialized = true;
}

// ============================================================================
// Reset — return to uninitialized state
// ============================================================================

void TimingAntiEvasion::Reset() noexcept {
    m_instructionCount.store(0, std::memory_order_relaxed);
    m_baseTSC         = 0;
    m_baseTickCount   = 0;
    m_baseFileTime    = 0;
    m_tscFrequency    = 3'800'000'000ULL;
    m_qpcFrequency    = 10'000'000ULL;
    m_tscPerInstruction = 25;
    m_accelerationFactor = 1000;
    m_timezoneOffsetMinutes = -300;
    m_initialized     = false;
}

// ============================================================================
// AdvanceTick — called after each emulated instruction
// ============================================================================

void TimingAntiEvasion::AdvanceTick(uint32_t instructionCount) noexcept {
    m_instructionCount.fetch_add(instructionCount, std::memory_order_relaxed);
}

// ============================================================================
// SimulateSleep — advance clock by accelerated sleep duration
// ============================================================================
//
// Instead of truly waiting, we advance the instruction counter so
// that the TSC delta corresponds to (milliseconds / accelerationFactor)
// of real time. After Sleep(5000) with 1000x acceleration, GetTickCount
// shows ~5 ms more, and TSC/QPC agree.

void TimingAntiEvasion::SimulateSleep(uint64_t milliseconds) noexcept {
    if (milliseconds == 0 || m_tscPerInstruction == 0) return;

    // Cap to prevent overflow (max ~49 days of simulated sleep)
    constexpr uint64_t kMaxSleepMs = 4'294'967'295ULL;
    milliseconds = std::min(milliseconds, kMaxSleepMs);

    // TSC ticks that would elapse in the real duration
    // Then divide by acceleration to compress time
    const uint64_t realTscTicks = (milliseconds * m_tscFrequency) / 1000ULL;
    const uint64_t acceleratedTscTicks = realTscTicks / m_accelerationFactor;
    const uint64_t instructionsToAdd = acceleratedTscTicks / m_tscPerInstruction;

    m_instructionCount.fetch_add(instructionsToAdd, std::memory_order_relaxed);
}

// ============================================================================
// GetElapsedNanoseconds — core derivation helper
// ============================================================================

uint64_t TimingAntiEvasion::GetElapsedNanoseconds() const noexcept {
    const uint64_t tscDelta = static_cast<uint64_t>(m_instructionCount.load(
        std::memory_order_relaxed)) * m_tscPerInstruction;

    // elapsed_ns = (tscDelta * 1,000,000,000) / m_tscFrequency
    // Use 128-bit-safe computation to avoid overflow:
    // Split into seconds + remainder
    if (m_tscFrequency == 0) return 0;

    const uint64_t wholeSeconds = tscDelta / m_tscFrequency;
    const uint64_t remainder    = tscDelta % m_tscFrequency;

    return wholeSeconds * 1'000'000'000ULL +
           (remainder * 1'000'000'000ULL) / m_tscFrequency;
}

// ============================================================================
// GetTSC — RDTSC return value
// ============================================================================
// TSC = baseTSC + (instructionCount * tscPerInstruction)

uint64_t TimingAntiEvasion::GetTSC() const noexcept {
    const uint64_t count = m_instructionCount.load(std::memory_order_relaxed);
    return m_baseTSC + (count * m_tscPerInstruction);
}

// ============================================================================
// GetTickCount32 / GetTickCount64 — milliseconds since boot
// ============================================================================

uint32_t TimingAntiEvasion::GetTickCount32() const noexcept {
    return static_cast<uint32_t>(GetTickCount64() & 0xFFFFFFFFULL);
}

uint64_t TimingAntiEvasion::GetTickCount64() const noexcept {
    const uint64_t elapsedNs = GetElapsedNanoseconds();
    const uint64_t elapsedMs = elapsedNs / 1'000'000ULL;
    return m_baseTickCount + elapsedMs;
}

// ============================================================================
// GetQPC / GetQPF — QueryPerformanceCounter / Frequency
// ============================================================================

int64_t TimingAntiEvasion::GetQPC() const noexcept {
    const uint64_t elapsedNs = GetElapsedNanoseconds();
    // QPC = elapsed_seconds * qpcFrequency
    // = (elapsedNs * qpcFrequency) / 1,000,000,000
    const uint64_t wholeSeconds = elapsedNs / 1'000'000'000ULL;
    const uint64_t remainder    = elapsedNs % 1'000'000'000ULL;

    const uint64_t qpc = wholeSeconds * m_qpcFrequency +
                          (remainder * m_qpcFrequency) / 1'000'000'000ULL;
    return static_cast<int64_t>(qpc);
}

int64_t TimingAntiEvasion::GetQPF() const noexcept {
    return static_cast<int64_t>(m_qpcFrequency);
}

// ============================================================================
// GetSystemTimeAsFileTime — 100-ns intervals since Jan 1, 1601
// ============================================================================

uint64_t TimingAntiEvasion::GetSystemTimeAsFileTime() const noexcept {
    const uint64_t elapsedNs = GetElapsedNanoseconds();
    // Convert nanoseconds to 100-ns intervals
    const uint64_t elapsed100ns = elapsedNs / 100ULL;
    return m_baseFileTime + elapsed100ns;
}

// ============================================================================
// FileTimeToSystemTime — pure-math calendar decomposition
// ============================================================================
//
// FILETIME: 100-nanosecond intervals since January 1, 1601 00:00:00 UTC.
// We decompose into year/month/day/hour/minute/second/millisecond and
// compute the day of week. No Windows API needed.

TimingAntiEvasion::SystemTime TimingAntiEvasion::FileTimeToSystemTime(
    uint64_t fileTime) const noexcept
{
    SystemTime st{};

    // Total 100-ns intervals → decompose
    const uint64_t totalSeconds  = fileTime / kHundredNsPerSecond;
    const uint64_t fracHundredNs = fileTime % kHundredNsPerSecond;

    st.milliseconds = static_cast<uint16_t>((fracHundredNs / kHundredNsPerMs) % 1000);

    // Time of day
    const uint64_t totalDays    = totalSeconds / 86400ULL;
    const uint64_t daySeconds   = totalSeconds % 86400ULL;

    st.hour   = static_cast<uint16_t>(daySeconds / 3600);
    st.minute = static_cast<uint16_t>((daySeconds % 3600) / 60);
    st.second = static_cast<uint16_t>(daySeconds % 60);

    // Day of week: January 1, 1601 was a Monday (dayOfWeek = 1)
    st.dayOfWeek = static_cast<uint16_t>((totalDays + 1) % 7); // 0=Sun

    // Decompose totalDays into year/month/day
    // We use a 400-year cycle: 146097 days
    constexpr uint64_t kDaysPer400Years = 146097ULL;
    constexpr uint64_t kDaysPer100Years = 36524ULL;
    constexpr uint64_t kDaysPer4Years   = 1461ULL;

    uint64_t remaining = totalDays;

    // 400-year cycles since 1601
    const uint64_t cycles400 = remaining / kDaysPer400Years;
    remaining %= kDaysPer400Years;

    // 100-year cycles within the 400-year cycle
    uint64_t cycles100 = remaining / kDaysPer100Years;
    if (cycles100 == 4) cycles100 = 3; // Last day of 400-year cycle
    remaining -= cycles100 * kDaysPer100Years;

    // 4-year cycles
    const uint64_t cycles4 = remaining / kDaysPer4Years;
    remaining -= cycles4 * kDaysPer4Years;

    // Remaining single years
    uint64_t years1 = remaining / 365;
    if (years1 == 4) years1 = 3; // Last day of 4-year cycle
    remaining -= years1 * 365;

    const uint32_t year = static_cast<uint32_t>(
        kFileTimeEpochYear + cycles400 * 400 + cycles100 * 100 +
        cycles4 * 4 + years1);

    st.year = static_cast<uint16_t>(year);

    // remaining is now the 0-based day of the year
    const uint32_t leap = IsLeapYear(year) ? 1 : 0;

    uint16_t month = 0;
    for (month = 0; month < 12; ++month) {
        if (remaining < kDaysInMonth[leap][month]) break;
        remaining -= kDaysInMonth[leap][month];
    }

    st.month = static_cast<uint16_t>(month + 1);   // 1-based
    st.day   = static_cast<uint16_t>(remaining + 1); // 1-based

    return st;
}

// ============================================================================
// GetSystemTime — UTC
// ============================================================================

TimingAntiEvasion::SystemTime TimingAntiEvasion::GetSystemTime() const noexcept {
    return FileTimeToSystemTime(GetSystemTimeAsFileTime());
}

// ============================================================================
// GetLocalTime — UTC adjusted by timezone offset
// ============================================================================

TimingAntiEvasion::SystemTime TimingAntiEvasion::GetLocalTime() const noexcept {
    const uint64_t utcFileTime = GetSystemTimeAsFileTime();

    // Apply timezone offset (may be negative — convert minutes to 100-ns)
    const int64_t offsetHundredNs =
        static_cast<int64_t>(m_timezoneOffsetMinutes) * kHundredNsPerMinute;

    uint64_t localFileTime;
    if (offsetHundredNs >= 0) {
        localFileTime = utcFileTime + static_cast<uint64_t>(offsetHundredNs);
    } else {
        const uint64_t absOffset = static_cast<uint64_t>(-offsetHundredNs);
        localFileTime = (utcFileTime >= absOffset) ? (utcFileTime - absOffset) : 0;
    }

    return FileTimeToSystemTime(localFileTime);
}

// ============================================================================
// Configuration accessors
// ============================================================================

uint64_t TimingAntiEvasion::GetTSCFrequency() const noexcept {
    return m_tscFrequency;
}

uint32_t TimingAntiEvasion::GetTimingAcceleration() const noexcept {
    return m_accelerationFactor;
}

} // namespace Phantom::VirtualOS::AntiEvasion
