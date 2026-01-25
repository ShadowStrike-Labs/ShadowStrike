/**
 * ============================================================================
 * ShadowStrike Update System - UPDATE VERIFIER (The Inspector)
 * ============================================================================
 *
 * @file UpdateVerifier.hpp
 * @brief Cryptographic verification of downloaded update packages.
 *
 * Security:
 * - RSA-4096 / SHA-256 signature verification.
 * - Certificate Chain validation (must lead to ShadowStrike Root CA).
 * - Anti-Downgrade: Prevents installing an older version (prevention of rollback attacks).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/CryptoUtils.hpp"
#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Update {

        class UpdateVerifier {
        public:
            static UpdateVerifier& Instance();

            /**
             * @brief Verify that a file was signed by ShadowStrike.
             */
            bool VerifyPackage(const std::wstring& filePath, const std::vector<uint8_t>& signature);

            /**
             * @brief Check if the version is newer than the current one.
             */
            bool ValidateVersionSequence(const std::string& newVersion);

        private:
            UpdateVerifier() = default;
        };

    } // namespace Update
} // namespace ShadowStrike
