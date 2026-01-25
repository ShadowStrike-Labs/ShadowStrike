/**
 * ============================================================================
 * ShadowStrike USB Security - BADUSB DETECTOR (The Keyboard Guard)
 * ============================================================================
 *
 * @file BadUSBDetector.hpp
 * @brief Detection of HID spoofing devices (e.g. Rubber Ducky).
 *
 * BadUSB devices look like a standard keyboard but type malicious commands
 * at super-human speeds when plugged in.
 *
 * Detection:
 * 1. Rapid Typing: Detects keystrokes faster than any human.
 * 2. New Keyboard Delay: Pauses input from a newly connected keyboard for X seconds
 *    while it is analyzed.
 * 3. HID Descriptor Anomaly: Checking vendor IDs against known spoofers.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>
#include <chrono>

namespace ShadowStrike {
    namespace USB {

        class BadUSBDetector {
        public:
            static BadUSBDetector& Instance();

            /**
             * @brief Monitor keystroke timing for a specific device.
             */
            void OnKeyEvent(uint32_t deviceId, uint16_t keyCode);

            /**
             * @brief Called when a new HID device is connected.
             */
            bool AnalyzeHIDDescriptor(const std::wstring& deviceId);

        private:
            BadUSBDetector() = default;
            
            // keystroke rate detection
            uint32_t m_keyCount = 0;
            std::chrono::steady_clock::time_point m_windowStart;
        };

    } // namespace USB
} // namespace ShadowStrike
