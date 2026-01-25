/**
 * ============================================================================
 * ShadowStrike Communication - ALERT SYSTEM (The Siren)
 * ============================================================================
 *
 * @file AlertSystem.hpp
 * @brief High-priority emergency notification logic.
 *
 * Capabilities:
 * 1. Admin Email: Sending SMTP alerts to IT administrators.
 * 2. Webhook: Pushing detection alerts to Slack/Teams/Discord.
 * 3. Local Alarm: Playing an audible tone for critical detections.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Communication {

        class AlertSystem {
        public:
            static AlertSystem& Instance();

            /**
             * @brief Initialize with SMTP and Webhook credentials.
             */
            bool Initialize(const std::string& configJson);

            /**
             * @brief Send an emergency alert.
             */
            void RaiseEmergency(const std::string& subject, const std::string& details);

        private:
            AlertSystem() = default;
        };

    } // namespace Communication
} // namespace ShadowStrike
