/**
 * ============================================================================
 * ShadowStrike Update System - DELTA UPDATER (The Optimizer)
 * ============================================================================
 *
 * @file DeltaUpdater.hpp
 * @brief Logic for applying binary patches to large databases.
 *
 * Instead of downloading a 500MB signature file, we download a 500KB diff.
 * Uses:
 * 1. Courgette or BSDiff algorithm for executable patching.
 * 2. SQLite session extension for database patching.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Update {

        class DeltaUpdater {
        public:
            static DeltaUpdater& Instance();

            /**
             * @brief Apply a delta patch to an existing file.
             */
            bool ApplyPatch(const std::wstring& originalPath, const std::vector<uint8_t>& patchData);

        private:
            DeltaUpdater() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
