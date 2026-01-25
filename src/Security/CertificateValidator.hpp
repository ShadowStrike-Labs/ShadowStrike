/**
 * ============================================================================
 * ShadowStrike Security - CERTIFICATE VALIDATOR (The Gatekeeper)
 * ============================================================================
 *
 * @file CertificateValidator.hpp
 * @brief Logic for validating SSL/X.509 certificate chains.
 *
 * Capabilities:
 * 1. Revocation Check: Queries CRL and OCSP endpoints.
 * 2. Self-Signed Detection: Flags untrusted root certificates.
 * 3. Expired Check: Validates against current system time.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Security {

        class CertificateValidator {
        public:
            static CertificateValidator& Instance();

            /**
             * @brief Verify a raw certificate buffer.
             */
            bool VerifyCertificate(const std::vector<uint8_t>& certData);

            /**
             * @brief Perform an online revocation check.
             */
            bool IsRevoked(const std::wstring& serialNumber);

        private:
            CertificateValidator() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
