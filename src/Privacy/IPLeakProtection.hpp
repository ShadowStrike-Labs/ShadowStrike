/**
 * ============================================================================
 * ShadowStrike Privacy - IP LEAK PROTECTION (The Proxy Guard)
 * ============================================================================
 *
 * @file IPLeakProtection.hpp
 * @brief Prevention of real IP exposure during VPN/Proxy usage.
 *
 * Capabilities:
 * 1. WebRTC Block: Preventing IP exposure via WebRTC protocol in browsers.
 * 2. Kill-Switch: Disabling all network traffic if the secure tunnel drops.
 * 3. IPv6 Shield: Disabling IPv6 if the VPN only supports IPv4 (to prevent leak).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/NetworkUtils.hpp"
#include <string>

namespace ShadowStrike {
    namespace Privacy {

        class IPLeakProtection {
        public:
            static IPLeakProtection& Instance();

            /**
             * @brief Monitor network interfaces for unexpected traffic.
             */
            void RunKillSwitch();

            /**
             * @brief Block WebRTC in major browser configurations.
             */
            bool BlockWebRtcLeads();

        private:
            IPLeakProtection() = default;
        };

    } // namespace Privacy
} // namespace ShadowStrike
