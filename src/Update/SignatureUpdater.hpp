/**
 * ============================================================================
 * ShadowStrike Update System - SIGNATURE UPDATER (The Librarian)
 * ============================================================================
 *
 * @file SignatureUpdater.hpp
 * @brief Logic for downloading and hot-reloading signature databases.
 *
 * Capabilities:
 * 1. Differential Updates: Uses `DeltaUpdater` to download only new signatures.
 * 2. Hot-Reload: Notifies `ScanEngine` to swap database handles atomically.
 * 3. Validation: Uses `UpdateVerifier` to check DB integrity.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../SignatureStore/SignatureStore.hpp"
#include <string>

namespace ShadowStrike {
    namespace Update {

        class SignatureUpdater {
        public:
            static SignatureUpdater& Instance();

            /**
             * @brief Download the latest malware signatures.
             */
            bool UpdateSignatures();

            /**
             * @brief Check currently installed DB version vs Server version.
             */
            std::string GetCurrentVersion();

        private:
            SignatureUpdater() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
