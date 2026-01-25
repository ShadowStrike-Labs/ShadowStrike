/**
 * ============================================================================
 * ShadowStrike Security - ANTI-DEBUG (The Ghost)
 * ============================================================================
 *
 * @file AntiDebug.hpp
 * @brief Logic for preventing reverse engineering of ShadowStrike.
 *
 * Capabilities:
 * 1. PEB Check: Monitoring `BeingDebugged` flag.
 * 2. Hardware Breakpoints: Detecting use of DR0-DR7 registers.
 * 3. Timing: Detecting single-stepping via instruction deltas.
 * 4. Stealth: Hiding threads from debugger using `NtSetInformationThread`.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

namespace ShadowStrike {
    namespace Security {

        class AntiDebug {
        public:
            static AntiDebug& Instance();

            /**
             * @brief Run a battery of anti-debug checks.
             */
            bool IsDebuggerDetected();

            /**
             * @brief Apply persistent protection to the calling thread.
             */
            void SecureThread();

        private:
            AntiDebug() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
