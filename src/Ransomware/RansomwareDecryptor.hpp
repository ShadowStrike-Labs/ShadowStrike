/**
 * ============================================================================
 * ShadowStrike Ransomware - DECRYPTOR (The Healer)
 * ============================================================================
 *
 * @file RansomwareDecryptor.hpp
 * @brief Logic for recovering files encrypted by known ransomware families.
 *
 * This module contains a collection of decryption keys and algorithms for
 * retired or leaked ransomware families (e.g. older versions of GandCrab, TeslaCrypt).
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Ransomware {

        class RansomwareDecryptor {
        public:
            static RansomwareDecryptor& Instance();

            /**
             * @brief Attempt to decrypt a file using known family keys.
             */
            bool DecryptFile(const std::wstring& filePath, const std::string& familyName);

            /**
             * @brief Identify the ransomware family based on file extension and ransom note.
             */
            std::string IdentifyFamily(const std::wstring& folderPath);

        private:
            RansomwareDecryptor() = default;
        };

    } // namespace Ransomware
} // namespace ShadowStrike
