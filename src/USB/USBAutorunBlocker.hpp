/**
 * ============================================================================
 * ShadowStrike USB Security - AUTORUN BLOCKER (The Gatekeeper)
 * ============================================================================
 *
 * @file USBAutorunBlocker.hpp
 * @brief Prevention of automatic code execution from removable media.
 *
 * Capabilities:
 * 1. Global Disable: Disables the "AutoRun" feature in registry for all drives.
 * 2. Sanitize: Deletes or renames `autorun.inf` files on newly connected drives.
 * 3. Shortcut Hijack Detection: Detects .LNK files that point to hidden scripts.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>

namespace ShadowStrike {
    namespace USB {

        class USBAutorunBlocker {
        public:
            static USBAutorunBlocker& Instance();

            /**
             * @brief Disables Windows AutoRun functionality via Registry.
             */
            bool ApplyGlobalRegistryHardening();

            /**
             * @brief Scans a new drive for autorun.inf and suspicious .lnk files.
             */
            void SanitizeDrive(const std::wstring& rootPath);

        private:
            USBAutorunBlocker() = default;
        };

    } // namespace USB
} // namespace ShadowStrike
