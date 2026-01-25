/**
 * ============================================================================
 * ShadowStrike USB Security - DEVICE MONITOR (The Watchman)
 * ============================================================================
 *
 * @file USBDeviceMonitor.hpp
 * @brief Detection of newly connected USB Storage and HID devices.
 *
 * This module listens for Windows Device Broadcasts (DBT_DEVICEARRIVAL).
 * When a USB is plugged in, it notifies the `USBScanner` and `DeviceControlManager`.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <mutex>

namespace ShadowStrike {
    namespace USB {

        struct USBDeviceInfo {
            std::wstring driveLetter;   // e.g. "E:\\"
            std::wstring deviceId;      // Vendor/Product ID
            std::wstring serialNumber;
            bool isStorage;
            bool isKeyboard;            // For BadUSB detection
        };

        class USBDeviceMonitor {
        public:
            static USBDeviceMonitor& Instance();

            /**
             * @brief Starts the background listener for device events.
             */
            bool Start();
            void Stop();

            using USBEventCallback = std::function<void(const USBDeviceInfo&, bool arrival)>;
            void RegisterCallback(USBEventCallback cb);

        private:
            USBDeviceMonitor() = default;
            
            std::vector<USBEventCallback> m_callbacks;
            std::mutex m_callbackMutex;
        };

    } // namespace USB
} // namespace ShadowStrike
