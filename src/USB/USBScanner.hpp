/**
 * ============================================================================
 * ShadowStrike USB Security - USB SCANNER (The Inspector)
 * ============================================================================
 *
 * @file USBScanner.hpp
 * @brief Immediate deep scanning of removable media on connection.
 *
 * Automatically triggers a `ScanEngine` task when a new drive is detected.
 *
 * Capabilities:
 * 1. Fast Hash Scan: Checks all files against `HashStore` first.
 * 2. Deep YARA Scan: Scans executables and scripts.
 * 3. Shadow Copy: (Optional) Backs up files before they are accessed.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Engine/ScanEngine.hpp"
#include <string>
#include <atomic>

namespace ShadowStrike {
    namespace USB {

        class USBScanner {
        public:
            static USBScanner& Instance();

            /**
             * @brief Start a background scan of a USB drive.
             */
            void ScanDrive(const std::wstring& drivePath);

            bool IsScanning() const { return m_scanning.load(); }

        private:
            USBScanner() = default;
            std::atomic<bool> m_scanning{ false };
        };

    } // namespace USB
} // namespace ShadowStrike
