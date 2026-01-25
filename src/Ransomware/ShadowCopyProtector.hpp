/**
 * ============================================================================
 * ShadowStrike Ransomware - SHADOW COPY PROTECTOR (The Sentinel)
 * ============================================================================
 *
 * @file ShadowCopyProtector.hpp
 * @brief Logic for preventing unauthorized deletion of VSS backups.
 *
 * This module hooks into the `vssadmin.exe` and `wmic.exe` command paths to
 * prevent commands like "Delete Shadows".
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Ransomware {

        class ShadowCopyProtector {
        public:
            static ShadowCopyProtector& Instance();

            /**
             * @brief Check if a command line is an attempt to delete shadows.
             */
            bool IsVssDestructionAttempt(const std::wstring& cmdLine);

            /**
             * @brief Protect the VSS service from being stopped.
             */
            void LockVssService();

        private:
            ShadowCopyProtector() = default;
        };

    } // namespace Ransomware
} // namespace ShadowStrike
