/**
 * ============================================================================
 * ShadowStrike Banking Security - SCREENSHOT BLOCKER (The Blindfold)
 * ============================================================================
 *
 * @file ScreenshotBlocker.hpp
 * @brief Prevention of screen scraping and remote desktop spying.
 *
 * Capabilities:
 * 1. Window Protection: Uses `SetWindowDisplayAffinity` (WDA_EXCLUDEFROMCAPTURE).
 * 2. API Hooking: Blocks `BitBlt` and `PrintWindow` on banking sessions.
 * 3. GDI Hijack Detection: Detects unauthorized mirror drivers.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace Banking {

        class ScreenshotBlocker {
        public:
            static ScreenshotBlocker& Instance();

            /**
             * @brief Protect a window from being captured by screen recorders.
             */
            bool ProtectWindow(void* hWnd);

            /**
             * @brief Global block: Black out screen for unauthorized remote desktop tools.
             */
            void SetGlobalBlock(bool enabled);

        private:
            ScreenshotBlocker() = default;
        };

    } // namespace Banking
} // namespace ShadowStrike
