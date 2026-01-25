/**
 * ============================================================================
 * ShadowStrike Security - REGISTRY PROTECTION (The Hive Guard)
 * ============================================================================
 *
 * @file RegistryProtection.hpp
 * @brief Logic for preventing modification of ShadowStrike configuration keys.
 *
 * Capabilities:
 * 1. Key Lockdown: Monitoring HKLM\SOFTWARE\ShadowStrike.
 * 2. Silent Rollback: (Optional) Reverting keys if they are changed by malware.
 * 3. Access Mask Filtering: Denying KEY_ALL_ACCESS to non-system processes.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Security {

        class RegistryProtection {
        public:
            static RegistryProtection& Instance();

            /**
             * @brief Register critical keys for protection.
             */
            void ProtectKey(const std::wstring& keyPath);

            /**
             * @brief Check if a registry operation should be blocked.
             */
            bool IsOperationAllowed(const std::wstring& keyPath, uint32_t opType);

        private:
            RegistryProtection() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
