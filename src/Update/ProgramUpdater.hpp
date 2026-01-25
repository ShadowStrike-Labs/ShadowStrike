/**
 * ============================================================================
 * ShadowStrike Update System - PROGRAM UPDATER (The Builder)
 * ============================================================================
 *
 * @file ProgramUpdater.hpp
 * @brief Logic for updating core service and UI executable files.
 *
 * Capabilities:
 * 1. Self-Replacement: Moves old executables to .bak and replaces them.
 * 2. Driver Update: Installs new versions of the Minifilter driver.
 * 3. Rollback: Automatically reverts if the new version fails to start.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Update {

        class ProgramUpdater {
        public:
            static ProgramUpdater& Instance();

            /**
             * @brief Check for a new program version.
             */
            bool IsNewVersionAvailable();

            /**
             * @brief Download and stage the new installer.
             */
            bool ApplyProgramUpdate();

        private:
            ProgramUpdater() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
