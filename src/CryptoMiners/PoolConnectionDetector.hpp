/**
 * ============================================================================
 * ShadowStrike CryptoMiners - POOL DETECTOR (The Networker)
 * ============================================================================
 *
 * @file PoolConnectionDetector.hpp
 * @brief Detection of Stratum and Getwork protocols.
 *
 * Stratum is a text-based protocol used by almost all miners.
 * We can detect it by parsing TCP payloads for "mining.submit", "mining.subscribe".
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>

namespace ShadowStrike {
    namespace CryptoMiners {

        class PoolConnectionDetector {
        public:
            static PoolConnectionDetector& Instance();

            /**
             * @brief Inspect payload for Stratum protocol markers.
             */
            bool IsStratumProtocol(const std::vector<uint8_t>& payload);

            /**
             * @brief Check if destination port is a known mining port.
             * e.g., 3333, 4444, 8888.
             */
            bool IsMiningPort(uint16_t port);

        private:
            PoolConnectionDetector() = default;
        };

    } // namespace CryptoMiners
} // namespace ShadowStrike
