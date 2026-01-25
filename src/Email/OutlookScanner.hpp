/**
 * ============================================================================
 * ShadowStrike Email Security - OUTLOOK SCANNER (The Office Guard)
 * ============================================================================
 *
 * @file OutlookScanner.hpp
 * @brief Integration with Microsoft Outlook via MAPI and Add-ins.
 *
 * Capabilities:
 * 1. PST/OST Parsing: Scans local email archives for historical threats.
 * 2. On-Arrival Scan: Intercepts new mail before the user sees it.
 * 3. Safe-Preview: Sanitizes HTML emails.
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

        class OutlookScanner {
        public:
            static OutlookScanner& Instance();

            /**
             * @brief Scan all local PST and OST files.
             */
            void ScanLocalArchives();

            /**
             * @brief Block a specific sender in Outlook.
             */
            bool BlockSender(const std::wstring& emailAddress);

        private:
            OutlookScanner() = default;
        };

    } // namespace Email
} // namespace ShadowStrike
