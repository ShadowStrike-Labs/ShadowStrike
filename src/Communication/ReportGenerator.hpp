/**
 * ============================================================================
 * ShadowStrike Communication - REPORT GENERATOR (The Scribe)
 * ============================================================================
 *
 * @file ReportGenerator.hpp
 * @brief Logic for creating human-readable security audits.
 *
 * Capabilities:
 * 1. Formats: PDF, HTML, JSON, CSV.
 * 2. Contents: Scan history, detection counts, update status, performance.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Communication {

        class ReportGenerator {
        public:
            static ReportGenerator& Instance();

            /**
             * @brief Create a report for a specific time range.
             */
            std::string GenerateHtmlReport(uint64_t startTime, uint64_t endTime);

            /**
             * @brief Export the threat log to CSV.
             */
            bool ExportToCsv(const std::wstring& outputPath);

        private:
            ReportGenerator() = default;
        };

    } // namespace Communication
} // namespace ShadowStrike
