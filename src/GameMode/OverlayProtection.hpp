/**
 * ============================================================================
 * ShadowStrike GameMode - OVERLAY PROTECTION (The Interface Guard)
 * ============================================================================
 *
 * @file OverlayProtection.hpp
 * @brief Ensuring safe rendering of UI elements over games.
 *
 * Capabilities:
 * 1. Integrity: Ensures that our "Threat Detected" overlay isn't hijacked by malware.
 * 2. Hook Prevention: Blocks malicious DLLs from hooking DirectX/Vulkan/OpenGL swapchains.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

namespace ShadowStrike {
    namespace GameMode {

        class OverlayProtection {
        public:
            static OverlayProtection& Instance();

            /**
             * @brief Protect the rendering context of the AV UI.
             */
            bool SecureOverlay();

        private:
            OverlayProtection() = default;
        };

    } // namespace GameMode
} // namespace ShadowStrike
