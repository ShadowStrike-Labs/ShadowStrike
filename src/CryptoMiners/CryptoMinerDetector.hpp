/**
 * ============================================================================
 * ShadowStrike CryptoMiners - MINER DETECTOR (The Prospector)
 * ============================================================================
 *
 * @file CryptoMinerDetector.hpp
 * @brief Detection of unauthorized cryptocurrency mining software.
 *
 * Capabilities:
 * 1. Signature Matching: Detects known miners (XMRig, NiceHash).
 * 2. Stratum Protocol Detection: Detects mining network traffic.
 * 3. Resource Abuse: Uses CPUUsageAnalyzer/GPUMiningDetector.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "CPUUsageAnalyzer.hpp"
#include "GPUMiningDetector.hpp"
#include "../../Core/Network/NetworkMonitor.hpp"
#include <string>

namespace ShadowStrike {
    namespace CryptoMiners {

        class CryptoMinerDetector {
        public:
            static CryptoMinerDetector& Instance();

            /**
             * @brief Comprehensive check for mining activity.
             */
            bool AnalyzeProcess(uint32_t pid);

            /**
             * @brief Network callback for detecting Stratum protocol.
             */
            void OnNetworkTraffic(const Core::Network::EnhancedConnectionInfo& conn);

        private:
            CryptoMinerDetector() = default;
        };

    } // namespace CryptoMiners
} // namespace ShadowStrike
