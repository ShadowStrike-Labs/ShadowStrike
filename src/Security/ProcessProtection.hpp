/**
 * ============================================================================
 * ShadowStrike Security - PROCESS PROTECTION (The PPL Guard)
 * ============================================================================
 *
 * @file ProcessProtection.hpp
 * @brief Logic for enabling Windows Protected Process Light (PPL).
 *
 * Capabilities:
 * 1. PPL Enforcement: Setting the protection level to PsProtectedSignerAntimalware.
 * 2. Handle Filtering: Blocking non-protected processes from obtaining full
 *    access handles to ShadowStrike.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <cstdint>

namespace ShadowStrike {
    namespace Security {

        class ProcessProtection {
        public:
            static ProcessProtection& Instance();

            /**
             * @brief Attempt to elevate the current process to PPL status.
             * (Requires driver-level support).
             */
            bool ElevateToPPL();

            /**
             * @brief Check the current protection status of a process.
             */
            uint32_t GetProtectionLevel(uint32_t pid);

        private:
            ProcessProtection() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
