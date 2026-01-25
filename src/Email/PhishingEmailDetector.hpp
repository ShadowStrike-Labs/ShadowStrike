/**
 * ============================================================================
 * ShadowStrike Email Security - PHISHING DETECTOR (The Validator)
 * ============================================================================
 *
 * @file PhishingEmailDetector.hpp
 * @brief Detection of Business Email Compromise (BEC) and Phishing.
 *
 * Detects:
 * 1. Display Name Spoofing: "CEO Name <hacker@gmail.com>".
 * 2. Look-alike Domains: "micros0ft.com" instead of "microsoft.com".
 * 3. Urgent Language: Detecting social engineering pressure.
 * 4. Suspicious Redirects: Hidden URLs in links.
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

        struct PhishingEmailVerdict {
            bool isPhishing;
            std::string detectedType; // "BEC", "CredentialTheft"
            std::vector<std::string> maliciousLinks;
        };

        class PhishingEmailDetector {
        public:
            static PhishingEmailDetector& Instance();

            /**
             * @brief Comprehensive analysis of an email for phishing indicators.
             */
            PhishingEmailVerdict Analyze(const std::vector<uint8_t>& rawEmail);

        private:
            PhishingEmailDetector() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
