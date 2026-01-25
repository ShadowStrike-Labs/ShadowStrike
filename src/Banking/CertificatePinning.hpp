/**
 * ============================================================================
 * ShadowStrike Banking Security - CERTIFICATE PINNING (The Notary)
 * ============================================================================
 *
 * @file CertificatePinning.hpp
 * @brief Enforcement of strict SSL/TLS validation for banking domains.
 *
 * Capabilities:
 * 1. Pin Store: Hardcoded list of public key hashes for global banks.
 * 2. Revocation Check: Mandatory OCSP/CRL checking during banking sessions.
 * 3. MITM Detection: Detects if a local proxy (like Fiddler/Burp) is intercepting traffic.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/NetworkUtils.hpp"
#include <string>
#include <vector>
#include <unordered_map>

namespace ShadowStrike {
    namespace Banking {

        class CertificatePinning {
        public:
            static CertificatePinning& Instance();

            /**
             * @brief Initialize with a list of pinned certificate hashes.
             */
            bool Initialize();

            /**
             * @brief Verify that a certificate matches the pin for a given domain.
             * @param domain e.g. "chase.com".
             * @param certInfo Extracted from NetworkUtils.
             */
            bool VerifyPin(
                const std::string& domain, 
                const Utils::NetworkUtils::SslCertificateInfo& certInfo
            );

        private:
            CertificatePinning() = default;
            std::unordered_map<std::string, std::vector<std::string>> m_pins;
        };

    } // namespace Banking
} // namespace ShadowStrike
