/**
 * ============================================================================
 * ShadowStrike Ransomware - LOCKY DETECTOR (The Extension Guard)
 * ============================================================================
 *
 * @file LockyDetector.hpp
 * @brief Specific logic for detecting Locky-like ransomware.
 *
 * Checks for:
 * 1. Rapid renaming to .locky, .zepto, .odin.
 * 2. VSS destruction via WMIC.
 * 3. Specific C2 communication patterns.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Ransomware {

        class LockyDetector {
        public:
            static LockyDetector& Instance();

            bool Detect(uint32_t pid);

        private:
            LockyDetector() = default;
        };

    } // namespace Ransomware
} // namespace ShadowStrike
