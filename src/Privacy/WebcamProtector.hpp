/**
 * ============================================================================
 * ShadowStrike Privacy - WEBCAM PROTECTOR (The Shutter)
 * ============================================================================
 *
 * @file WebcamProtector.hpp
 * @brief Prevention of unauthorized webcam access (Anti-Spyware).
 *
 * Capabilities:
 * 1. Callback Notification: Notifies the user whenever an app opens the camera.
 * 2. Hardware Block: Disables the USB Video Class (UVC) driver globally.
 * 3. Whitelisting: Only allows trusted apps (Zoom, Teams) to use the camera.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Process/ProcessMonitor.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Privacy {

        class WebcamProtector {
        public:
            static WebcamProtector& Instance();

            /**
             * @brief Set the global camera policy.
             * @param blocked If true, no app can use the camera.
             */
            void SetCameraBlocked(bool blocked);

            /**
             * @brief Handle an event where a process tries to open the camera.
             * Called via Kernel callback (KsRegisterDeviceInterfaceChangeCallback).
             */
            bool OnCameraAccessAttempt(uint32_t pid);

        private:
            WebcamProtector() = default;
            bool m_isBlocked = false;
        };

    } // namespace Privacy
} // namespace ShadowStrike
