/**
 * ============================================================================
 * ShadowStrike WebBrowser - PHISHING DETECTOR (The Skeptic)
 * ============================================================================
 *
 * @file PhishingDetector.hpp
 * @brief Heuristic detection of Phishing pages.
 *
 * Uses:
 * 1. Homograph Detection: Cyrillic characters mimicking Latin (e.g. рaypal).
 * 2. Visual Similarity: Logo matching (Computer Vision).
 * 3. Form Analysis: Detecting "Password" fields on HTTP pages.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace WebBrowser {

        struct PhishingScore {
            bool isPhishing;
            double score;
            std::string reason; // "Homograph Attack", "Typosquatting"
        };

        class PhishingDetector {
        public:
            static PhishingDetector& Instance();

            PhishingScore AnalyzeURL(const std::string& url);
            PhishingScore AnalyzePageContent(const std::string& html);

        private:
            PhishingDetector() = default;
        };

    } // namespace WebBrowser
} // namespace ShadowStrike
