/**
 * ============================================================================
 * ShadowStrike Email Security - EMAIL PROTECTION (The Postmaster)
 * ============================================================================
 *
 * @file EmailProtection.hpp
 * @brief Central controller for email scanning and phishing prevention.
 *
 * This module orchestrates the scanners for Outlook, Thunderbird, and IMAP/POP3.
 * It ensures that all incoming email attachments are scanned by the `ScanEngine`.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "AttachmentScanner.hpp"
#include "PhishingEmailDetector.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Email {

        class EmailProtection {
        public:
            static EmailProtection& Instance();

            bool Initialize();

            /**
             * @brief Scan a raw email message (RFC822).
             */
            void ScanEmail(const std::vector<uint8_t>& rawEmail);

            /**
             * @brief Protect the user from Malicious links in emails.
             */
            bool ProcessEmailLinks(const std::vector<std::string>& links);

        private:
            EmailProtection() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
