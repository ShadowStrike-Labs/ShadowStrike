/**
 * ============================================================================
 * ShadowStrike IoT Security - SMART HOME PROTECTION (The Hub Guard)
 * ============================================================================
 *
 * @file SmartHomeProtection.hpp
 * @brief Behavioral monitoring for IoT devices.
 *
 * Capabilities:
 * 1. Data Exfiltration Detection: A smart camera sending GBs of data to a foreign IP.
 * 2. C2 Detection: IoT devices participating in a botnet (Mirai).
 * 3. Anomaly: A thermostat suddenly trying to scan the local network.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Core/Network/NetworkMonitor.hpp"
#include <string>

namespace ShadowStrike {
    namespace IoT {

        class SmartHomeProtection {
        public:
            static SmartHomeProtection& Instance();

            /**
             * @brief Monitor traffic flows involving known IoT devices.
             */
            void AnalyzeFlow(const Core::Network::EnhancedConnectionInfo& flow);

            /**
             * @brief Block a specific IoT device from accessing the internet.
             */
            bool IsolateDevice(const std::string& macAddress);

        private:
            SmartHomeProtection() = default;
        };

    } // namespace IoT
} // namespace ShadowStrike
