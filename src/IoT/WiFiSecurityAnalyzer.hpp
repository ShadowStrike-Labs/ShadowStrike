/**
 * ============================================================================
 * ShadowStrike IoT Security - WIFI ANALYZER (The Air Guard)
 * ============================================================================
 *
 * @file WiFiSecurityAnalyzer.hpp
 * @brief Analysis of Wireless Security and Rogue AP Detection.
 *
 * Capabilities:
 * 1. Encryption Check: Flags WEP/WPA (Legacy) networks.
 * 2. Evil Twin Detection: Identifies fake APs with the same SSID but different MAC.
 * 3. KRACK/Dragonblood detection: Heuristics for known protocol exploits.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace IoT {

        struct WiFiInfo {
            std::wstring ssid;
            std::string bssid;
            std::string encryption; // "WPA3", "WPA2", "OPEN"
            int signalStrength;
            bool isRogue;
        };

        class WiFiSecurityAnalyzer {
        public:
            static WiFiSecurityAnalyzer& Instance();

            /**
             * @brief Scan surrounding WiFi networks for threats.
             */
            std::vector<WiFiInfo> ScanAirwaves();

            /**
             * @brief Verify the current connected network.
             */
            bool IsCurrentNetworkSafe();

        private:
            WiFiSecurityAnalyzer() = default;
        };

    } // namespace IoT
} // namespace ShadowStrike
