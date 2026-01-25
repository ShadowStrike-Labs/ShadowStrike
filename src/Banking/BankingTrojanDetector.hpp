/**
 * ============================================================================
 * ShadowStrike Banking Security - TROJAN DETECTOR (The Auditor)
 * ============================================================================
 *
 * @file BankingTrojanDetector.hpp
 * @brief Specific heuristics for financial malware.
 *
 * Capabilities:
 * 1. Form Grabbing Detection: Intercepting `HttpSendRequest` calls to find leaked POST data.
 * 2. Web Injects Detection: Analyzing browser memory for injected scripts (inject.js).
 * 3. Specific Families: Signatures for Ramnit, Gozi, IcedID.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../SignatureStore/SignatureStore.hpp"
#include <vector>
#include <string>

namespace ShadowStrike {
    namespace Banking {

        class BankingTrojanDetector {
        public:
            static BankingTrojanDetector& Instance();

            /**
             * @brief Scan browser memory for known web-inject patterns.
             */
            bool ScanBrowserMemory(uint32_t browserPid);

            /**
             * @brief Analyze a network request for potential leaked credentials.
             */
            bool AnalyzeRequest(const std::string& host, const std::vector<uint8_t>& body);

        private:
            BankingTrojanDetector() = default;
        };

    } // namespace Banking
} // namespace ShadowStrike
