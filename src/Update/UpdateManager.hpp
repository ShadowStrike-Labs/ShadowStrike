/**
 * ============================================================================
 * ShadowStrike Update System - UPDATE MANAGER (The Maintainer)
 * ============================================================================
 *
 * @file UpdateManager.hpp
 * @brief Orchestrator for all update operations.
 *
 * Capabilities:
 * 1. Connectivity Check: Verifying access to ShadowStrike update servers.
 * 2. Background Updates: Checking for updates without user interruption.
 * 3. Integrity: Ensuring that all updates are cryptographically signed.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "SignatureUpdater.hpp"
#include "ProgramUpdater.hpp"
#include <atomic>
#include <mutex>

namespace ShadowStrike {
    namespace Update {

        enum class UpdateStatus {
            Idle,
            Checking,
            Downloading,
            Applying,
            RebootRequired,
            Error
        };

        class UpdateManager {
        public:
            static UpdateManager& Instance();

            /**
             * @brief Trigger a check for all updates (Signatures + Program).
             */
            void CheckForUpdates();

            /**
             * @brief Start the update process.
             */
            bool StartUpdate();

            UpdateStatus GetStatus() const { return m_status.load(); }

        private:
            UpdateManager() = default;
            std::atomic<UpdateStatus> m_status{ UpdateStatus::Idle };
        };

    } // namespace Update
} // namespace ShadowStrike
