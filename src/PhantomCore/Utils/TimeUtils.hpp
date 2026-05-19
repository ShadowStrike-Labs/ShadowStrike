/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * AGPL-3.0 — see LICENSE.txt
 *
 * Provides bounded UTC time formatting helpers used by timeline and telemetry code.
 */
#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>

namespace ShadowStrike::Utils {
namespace TimeUtils {

using Clock = std::chrono::system_clock;

/// @brief Converts a time_point to ISO-8601 UTC string.
[[nodiscard]] inline std::string ToIso8601(Clock::time_point tp) {
    const auto tt = Clock::to_time_t(tp);
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &tt) != 0) {
        return {};
    }
#else
    if (gmtime_r(&tt, &utc) == nullptr) {
        return {};
    }
#endif
    std::ostringstream oss;
    oss << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

/// @brief Converts epoch milliseconds to a time_point.
[[nodiscard]] inline Clock::time_point FromEpochMs(int64_t ms) {
    return Clock::time_point(
        std::chrono::duration_cast<Clock::duration>(
            std::chrono::milliseconds(ms)));
}

/// @brief Returns current epoch milliseconds.
[[nodiscard]] inline int64_t NowEpochMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now().time_since_epoch()).count();
}

} // namespace TimeUtils
} // namespace ShadowStrike::Utils
