/**
 * ============================================================================
 * ShadowStrike Banking Security - KEYLOGGER PROTECTION (The Scrambler)
 * ============================================================================
 *
 * @file KeyloggerProtection.hpp
 * @brief Prevention of keystroke interception.
 *
 * Capabilities:
 * 1. Hook Detection: Detects `SetWindowsHookEx` (WH_KEYBOARD_LL) on sensitive apps.
 * 2. Keystroke Encryption: Scrambles keys at the driver level before they reach user mode.
 * 3. Raw Input Monitoring: Detects use of `GetAsyncKeyStatus` polling.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace Banking {

        class KeyloggerProtection {
        public:
            static KeyloggerProtection& Instance();

            /**
             * @brief Enable keystroke protection for a target process.
             */
            bool ProtectProcess(uint32_t pid);

            /**
             * @brief Detect if any global keyboard hooks are active.
             */
            bool ScanForHooks();

        private:
            KeyloggerProtection() = default;
        };

    } // namespace Banking
} // namespace ShadowStrike
