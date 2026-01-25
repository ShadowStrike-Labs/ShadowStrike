/**
 * ============================================================================
 * ShadowStrike Update System - ROLLBACK MANAGER (The Rewinder)
 * ============================================================================
 *
 * @file RollbackManager.hpp
 * @brief Safety mechanism for recovering from failed updates.
 *
 * Capabilities:
 * 1. Snapshotting: Creates a copy of core files before applying program updates.
 * 2. Boot Loop Detection: Automatically rolls back if the service crashes 3 times
 *    within 5 minutes of an update.
 * 3. Health Check: Validates that the engine is functional post-update.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Update {

        class RollbackManager {
        public:
            static RollbackManager& Instance();

            /**
             * @brief Save current state as "Last Known Good".
             */
            void BackupCurrentVersion();

            /**
             * @brief Perform an emergency rollback.
             */
            bool TriggerRollback();

            /**
             * @brief Check if the system is stable post-update.
             */
            bool VerifyStability();

        private:
            RollbackManager() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
