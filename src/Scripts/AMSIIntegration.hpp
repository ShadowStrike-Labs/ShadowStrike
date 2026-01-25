/**
 * ============================================================================
 * ShadowStrike Script Security - AMSI INTEGRATION (The OS Bridge)
 * ============================================================================
 *
 * @file AMSIIntegration.hpp
 * @brief Implementation of the Antimalware Scan Interface (AMSI).
 *
 * This module allows Windows to call ShadowStrike whenever a script is about to
 * be executed (PowerShell, VBScript, Office, JS).
 *
 * Capabilities:
 * 1. Contextual Scanning: Receives the script content *after* the interpreter
 *    has de-obfuscated it (Unpacking at the engine level).
 * 2. Real-Time Blocking: Tells Windows to abort execution if malicious.
 * 3. Logging: Captures script content for forensics.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>

// Forward declare AMSI types to avoid full header include if not needed
struct IAmsiStream;

namespace ShadowStrike {
    namespace Scripts {

        enum class AMSIResult {
            Clean,
            Inconclusive,
            Infected,
            BlockedByAdmin
        };

        class AMSIIntegration {
        public:
            static AMSIIntegration& Instance();

            /**
             * @brief Registers ShadowStrike as an AMSI Provider in the Registry.
             * (Requires Administrative privileges).
             */
            bool RegisterProvider();

            /**
             * @brief Unregisters the provider.
             */
            bool UnregisterProvider();

            /**
             * @brief The core scanning function called by the OS.
             */
            AMSIResult ScanBuffer(
                const void* buffer, 
                uint32_t length, 
                const std::wstring& contentName,
                uint32_t processId
            );

        private:
            AMSIIntegration() = default;
        };

    } // namespace Scripts
} // namespace ShadowStrike
