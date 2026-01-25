/**
 * ============================================================================
 * ShadowStrike USB Security - DEVICE CONTROL (The DLP)
 * ============================================================================
 *
 * @file DeviceControlManager.hpp
 * @brief Policy-based control of USB peripherals (Data Loss Prevention).
 *
 * Capabilities:
 * 1. Read-Only Enforcement: Block write access to USB drives.
 * 2. Device Whitelisting: Only allow specific Serial Numbers (Corporate USBs).
 * 3. Class Blocking: Disable entire classes (e.g., Bluetooth, Webcams).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_set>

namespace ShadowStrike {
    namespace USB {

        enum class USBPolicy {
            AllowAll,
            ReadOnly,
            BlockAll,
            WhitelistOnly
        };

        class DeviceControlManager {
        public:
            static DeviceControlManager& Instance();

            /**
             * @brief Set the global USB storage policy.
             */
            void SetPolicy(USBPolicy policy);

            /**
             * @brief Add a device serial number to the trusted list.
             */
            void WhitelistDevice(const std::wstring& serialNumber);

            /**
             * @brief Check if a device is allowed under current policy.
             */
            bool IsAccessAllowed(const std::wstring& serialNumber, bool writeAccess);

        private:
            DeviceControlManager() = default;
            
            USBPolicy m_currentPolicy = USBPolicy::AllowAll;
            std::unordered_set<std::wstring> m_whitelist;
        };

    } // namespace USB
} // namespace ShadowStrike
