/**
 * ============================================================================
 * ShadowStrike Security - TAMPER PROTECTION (The Integrity Guard)
 * ============================================================================
 *
 * @file TamperProtection.hpp
 * @brief Global orchestrator for protecting security-sensitive objects.
 *
 * This module coordinates with `FileProtection`, `RegistryProtection`, and 
 * `ProcessProtection` to ensure that the AV's environment is immutable.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <atomic>

namespace ShadowStrike {
    namespace Security {

        class TamperProtection {
        public:
            static TamperProtection& Instance();

            /**
             * @brief Enable global tamper protection.
             */
            void SetEnabled(bool enabled);

            /**
             * @brief Check if protection is active.
             */
            bool IsEnabled() const { return m_enabled.load(); }

        private:
            TamperProtection() = default;
            std::atomic<bool> m_enabled{ true };
        };

    } // namespace Security
} // namespace ShadowStrike
