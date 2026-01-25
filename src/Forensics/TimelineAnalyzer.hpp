/**
 * ============================================================================
 * ShadowStrike Forensics - TIMELINE ANALYZER (The Chronologist)
 * ============================================================================
 *
 * @file TimelineAnalyzer.hpp
 * @brief Reconstruction of the attack sequence.
 *
 * Capabilities:
 * 1. Event Ordering: Sorting file, registry, and process events by 100ns precision.
 * 2. Causal Linkage: Identifying that "Process A" created "File B" which was then
 *    executed as "Process C".
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Forensics {

        struct TimelinePoint {
            uint64_t timestamp;
            std::wstring actor; // PID/Name
            std::wstring action;
            std::wstring object; // File/Key
        };

        class TimelineAnalyzer {
        public:
            static TimelineAnalyzer& Instance();

            /**
             * @brief Reconstruct the events leading up to a detection.
             */
            std::vector<TimelinePoint> BuildAttackTimeline(uint32_t terminalPid);

        private:
            TimelineAnalyzer() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
