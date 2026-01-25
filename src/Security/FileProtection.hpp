/**
 * ============================================================================
 * ShadowStrike Security - FILE PROTECTION (The Archive Guard)
 * ============================================================================
 *
 * @file FileProtection.hpp
 * @brief Logic for preventing deletion of ShadowStrike installation files.
 *
 * Capabilities:
 * 1. Directory Lockdown: Preventing `DELETE` or `RENAME` operations on the
 *    installation path (C:\Program Files\ShadowStrike).
 * 2. Signature Validation: Only allowing ShadowStrike-signed binaries to
 *    update our own files.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace Security {

        class FileProtection {
        public:
            static FileProtection& Instance();

            /**
             * @brief Register the installation directory for lockdown.
             */
            void ProtectDirectory(const std::wstring& path);

            /**
             * @brief Check if a file operation on a protected file should be allowed.
             * Called via Minifilter driver.
             */
            bool IsOperationAllowed(const std::wstring& path, uint32_t desiredAccess);

        private:
            FileProtection() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
