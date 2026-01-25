/**
 * ============================================================================
 * ShadowStrike Security - DIGITAL SIGNATURE VALIDATOR (The Authenticator)
 * ============================================================================
 *
 * @file DigitalSignatureValidator.hpp
 * @brief Logic for verifying Win32 Authenticode signatures.
 *
 * Capabilities:
 * 1. Integrity: Verifies that the file hasn't been modified since it was signed.
 * 2. Identity: Identifies the signer (e.g. "Microsoft Corporation").
 * 3. Counter-Signatures: Validates timestamps even after certificate expiry.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/PE_sig_verf.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Security {

        struct SignatureInfo {
            bool isValid;
            std::wstring signerName;
            std::wstring issuerName;
            std::wstring serialNumber;
            bool isTrustedRoot;
        };

        class DigitalSignatureValidator {
        public:
            static DigitalSignatureValidator& Instance();

            /**
             * @brief Verify the signature of a PE file.
             */
            SignatureInfo VerifyFile(const std::wstring& filePath);

            /**
             * @brief Check if a file is signed by a specific trusted vendor.
             */
            bool IsSignedBy(const std::wstring& filePath, const std::wstring& vendorName);

        private:
            DigitalSignatureValidator() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
