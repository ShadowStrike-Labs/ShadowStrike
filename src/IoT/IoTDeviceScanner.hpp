/**
 * ============================================================================
 * ShadowStrike IoT Security - DEVICE SCANNER (The Neighborhood Watch)
 * ============================================================================
 *
 * @file IoTDeviceScanner.hpp
 * @brief Asset discovery for the Local Area Network (LAN).
 *
 * Uses multiple protocols to identify devices on the network:
 * 1. mDNS (Bonjour): Finding printers, Apple TVs, Smart TVs.
 * 2. UPnP: Finding routers, storage devices.
 * 3. ICMP Ping Sweep: Finding silent devices.
 * 4. ARP Scanning: Mapping IPs to MAC addresses.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/NetworkUtils.hpp"
#include <string>
#include <vector>
#include <mutex>

namespace ShadowStrike {
    namespace IoT {

        struct IoTDevice {
            std::string ipAddress;
            std::string macAddress;
            std::string manufacturer;
            std::string deviceType; // "Camera", "Thermostat", "Printer"
            std::vector<uint16_t> openPorts;
            bool isVulnerable;
        };

        class IoTDeviceScanner {
        public:
            static IoTDeviceScanner& Instance();

            /**
             * @brief Start a full network scan.
             */
            void ScanNetwork();

            /**
             * @brief Get list of discovered devices.
             */
            std::vector<IoTDevice> GetDiscoveredDevices();

        private:
            IoTDeviceScanner() = default;
            
            std::mutex m_deviceMutex;
            std::vector<IoTDevice> m_devices;
        };

    } // namespace IoT
} // namespace ShadowStrike
