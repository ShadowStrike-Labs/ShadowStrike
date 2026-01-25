/**
 * ============================================================================
 * ShadowStrike Email Security - THUNDERBIRD SCANNER (The Open-Source Guard)
 * ============================================================================
 *
 * @file ThunderbirdScanner.hpp
 * @brief Analysis of Mozilla Thunderbird profiles.
 *
 * Scans Thunderbird's MBOX files and SQLite databases for malicious attachments.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Email {

        class ThunderbirdScanner {
        public:
            static ThunderbirdScanner& Instance();

            /**
             * @brief Scan all Thunderbird profiles on the machine.
             */
            void ScanProfiles();

        private:
            ThunderbirdScanner() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
