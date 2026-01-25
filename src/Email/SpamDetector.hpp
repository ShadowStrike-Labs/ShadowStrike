/**
 * ============================================================================
 * ShadowStrike Email Security - SPAM DETECTOR (The Filter)
 * ============================================================================
 *
 * @file SpamDetector.hpp
 * @brief Heuristic and Statistical Spam Detection.
 *
 * Capabilities:
 * 1. Bayesian Filtering: Learns from user's "Mark as Spam" actions.
 * 2. Header Analysis: Detects SPF/DKIM/DMARC failures.
 * 3. Keyword Analysis: Looks for "VIAGRA", "LOTTERY", etc. (Multilingual).
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

        struct SpamVerdict {
            bool isSpam;
            double confidence; // 0.0 - 1.0
            std::vector<std::string> reasons;
        };

        class SpamDetector {
        public:
            static SpamDetector& Instance();

            /**
             * @brief Analyze an email for Spam characteristics.
             */
            SpamVerdict Analyze(const std::vector<uint8_t>& rawEmail);

        private:
            SpamDetector() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
