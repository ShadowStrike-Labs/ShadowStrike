/**
 * ============================================================================
 * ShadowStrike GameMode - PERFORMANCE OPTIMIZER (The Booster)
 * ============================================================================
 *
 * @file PerformanceOptimizer.hpp
 * @brief Logic for minimizing AV footprint during heavy load.
 *
 * Capabilities:
 * 1. Process Priority: Sets ShadowStrike components to IDLE_PRIORITY_CLASS.
 * 2. IO Throttling: Limits disk throughput for scheduled scans.
 * 3. RAM Release: Aggressively flushes caches to free up memory for games.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

namespace ShadowStrike {
    namespace GameMode {

        class PerformanceOptimizer {
        public:
            static PerformanceOptimizer& Instance();

            /**
             * @brief Apply optimizations for high-performance gaming.
             */
            void BoostSystem();

            /**
             * @brief Revert to standard security priority.
             */
            void RestoreSystem();

        private:
            PerformanceOptimizer() = default;
        };

    } // namespace GameMode
} // namespace ShadowStrike
