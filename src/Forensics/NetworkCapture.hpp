/**
 * ============================================================================
 * ShadowStrike Forensics - NETWORK CAPTURE (The Sniffer)
 * ============================================================================
 *
 * @file NetworkCapture.hpp
 * @brief Logic for capturing malicious network traffic (PCAP).
 *
 * Capabilities:
 * 1. Selective PCAP: Only capturing traffic for a suspicious PID.
 * 2. WFP Callout: Using WFP to mirror packets to our analyzer.
 * 3. SSL Logging: Capturing master secrets (if possible) for HTTPS decryption.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Forensics {

        class NetworkCapture {
        public:
            static NetworkCapture& Instance();

            /**
             * @brief Start capturing traffic for a specific PID.
             */
            bool StartCapture(uint32_t pid, const std::wstring& outputPath);

            /**
             * @brief Stop the capture.
             */
            void StopCapture();

        private:
            NetworkCapture() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
