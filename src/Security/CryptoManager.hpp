/**
 * ============================================================================
 * ShadowStrike Security - CRYPTO MANAGER (The Vault)
 * ============================================================================
 *
 * @file CryptoManager.hpp
 * @brief Central provider for all cryptographic operations.
 *
 * Capabilities:
 * 1. Symmetric: AES-256-GCM for file and database encryption.
 * 2. Asymmetric: RSA-4096 / ECC for update verification.
 * 3. Key Derivation: PBKDF2 / Argon2 for secure password hashing.
 * 4. Key Management: Securely stores keys using Windows DPAPI or TPM.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/CryptoUtils.hpp"
#include <vector>
#include <string>

namespace ShadowStrike {
    namespace Security {

        class CryptoManager {
        public:
            static CryptoManager& Instance();

            /**
             * @brief Encrypt data using AES-256-GCM.
             */
            std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key);

            /**
             * @brief Decrypt data using AES-256-GCM.
             */
            std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key);

            /**
             * @brief Generate a cryptographically secure random key.
             */
            std::vector<uint8_t> GenerateRandomKey(size_t length = 32);

        private:
            CryptoManager() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
