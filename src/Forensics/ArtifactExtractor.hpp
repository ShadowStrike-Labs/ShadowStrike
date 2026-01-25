/**
 * ============================================================================
 * ShadowStrike Forensics - ARTIFACT EXTRACTOR (The Investigator)
 * ============================================================================
 *
 * @file ArtifactExtractor.hpp
 * @brief Extraction of OS artifacts for post-infection analysis.
 *
 * Capabilities:
 * 1. MFT Parsing: Extracting Master File Table records for deleted files.
 * 2. Shimcache/Amcache: Identifying previously executed binaries.
 * 3. Browser History: Reconstructing where the malware was downloaded from.
 * 4. LNK/JumpLists: Identifying user interaction with malware.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include <string>
#include <vector>

namespace ShadowStrike {
    namespace Forensics {

        class ArtifactExtractor {
        public:
            static ArtifactExtractor& Instance();

            /**
             * @brief Perform a comprehensive artifact sweep.
             */
            void ExtractAll(const std::wstring& outputDir);

            /**
             * @brief Recover a deleted file from MFT (if possible).
             */
            bool RecoverFile(const std::wstring& fileName, std::vector<uint8_t>& outData);

        private:
            ArtifactExtractor() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
