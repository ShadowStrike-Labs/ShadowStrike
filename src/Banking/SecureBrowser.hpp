/**
 * ============================================================================
 * ShadowStrike Banking Security - SECURE BROWSER (The Vault)
 * ============================================================================
 *
 * @file SecureBrowser.hpp
 * @brief Logic for creating a hardened, isolated browser environment.
 *
 * Capabilities:
 * 1. Hardened Runtime: Disables 3rd party plugins and unsigned DLL loading.
 * 2. DNS Pinning: Forces use of ShadowStrike's secure DNS during session.
 * 3. Clipboard Protection: Blocks external apps from reading the clipboard.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Banking {

        class SecureBrowser {
        public:
            static SecureBrowser& Instance();

            /**
             * @brief Launch a browser in "Safe Banking Mode".
             * @param browserPath Path to the browser EXE.
             */
            bool LaunchSecureSession(const std::wstring& browserPath);

            /**
             * @brief Check if a PID is running within our secure vault.
             */
            bool IsSessionSecure(uint32_t pid);

        private:
            SecureBrowser() = default;
        };

    } // namespace Banking
} // namespace ShadowStrike
