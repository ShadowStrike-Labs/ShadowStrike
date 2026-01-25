/**
 * ============================================================================
 * ShadowStrike Ransomware - WANNACRY DETECTOR (The Worm Hunter)
 * ============================================================================
 *
 * @file WannaCryDetector.hpp
 * @brief Specific logic for detecting WannaCry-like worm behaviors.
 *
 * Checks for:
 * 1. SMB Exploitation: Detecting EternalBlue artifacts.
 * 2. Kill-Switch check: Monitoring DNS for known kill-switch domains.
 * 3. Specific File drops: tasksche.exe, @Please_Read_Me@.txt.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Ransomware {

        class WannaCryDetector {
        public:
            static WannaCryDetector& Instance();

            /**
             * @brief Check for WannaCry artifacts in a process.
             */
            bool Detect(uint32_t pid);

        private:
            WannaCryDetector() = default;
        };

    } // namespace Ransomware
} // namespace ShadowStrike
