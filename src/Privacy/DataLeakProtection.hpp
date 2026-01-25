/**
 * ============================================================================
 * ShadowStrike Privacy - DATA LEAK PROTECTION (The Shredder)
 * ============================================================================
 *
 * @file DataLeakProtection.hpp
 * @brief Monitoring for egress of Personally Identifiable Information (PII).
 *
 * Capabilities:
 * 1. Pattern Matching: Scans files and network payloads for CC numbers, SSNs, and IBANs.
 * 2. Clipboard Monitor: Blocks PII from being pasted into browsers or chat apps.
 * 3. Tagging: Labels sensitive documents so they cannot be uploaded.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <regex>

namespace ShadowStrike {
    namespace Privacy {

        struct PIIPattern {
            std::string name;
            std::regex pattern;
            int severity;
        };

        class DataLeakProtection {
        public:
            static DataLeakProtection& Instance();

            /**
             * @brief Initialize with a set of PII regex patterns.
             */
            bool Initialize();

            /**
             * @brief Scan a buffer for sensitive data patterns.
             */
            bool ScanBuffer(const std::vector<uint8_t>& buffer);

            /**
             * @brief Intercept and block an upload if it contains PII.
             */
            bool AnalyzeOutboundData(const std::vector<uint8_t>& data);

        private:
            DataLeakProtection() = default;
            std::vector<PIIPattern> m_rules;
        };

    } // namespace Privacy
} // namespace ShadowStrike
