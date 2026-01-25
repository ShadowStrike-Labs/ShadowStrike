/**
 * ============================================================================
 * ShadowStrike Update System - UPDATE SCHEDULER (The Watcher)
 * ============================================================================
 *
 * @file UpdateScheduler.hpp
 * @brief Logic for periodic update checks.
 *
 * Capabilities:
 * 1. Intelligent Scheduling: Avoids updates during high CPU usage or Gaming.
 * 2. Metered Connection Support: Detects 4G/LTE and minimizes data usage.
 * 3. Force Update: Critical zero-day signature push.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <chrono>

namespace ShadowStrike {
    namespace Update {

        class UpdateScheduler {
        public:
            static UpdateScheduler& Instance();

            /**
             * @brief Start the periodic check timer.
             */
            void Start();

            /**
             * @brief Change update frequency.
             */
            void SetInterval(std::chrono::hours interval);

        private:
            UpdateScheduler() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
