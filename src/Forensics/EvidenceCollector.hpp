/**
 * ============================================================================
 * ShadowStrike Forensics - EVIDENCE COLLECTOR (The Evidence Bag)
 * ============================================================================
 *
 * @file EvidenceCollector.hpp
 * @brief Secure packaging of artifacts for later analysis.
 *
 * Capabilities:
 * 1. Secure Container: Creating an encrypted ZIP or VHD containing the malware.
 * 2. Hash Preservation: Ensuring that original file hashes are recorded.
 * 3. Environment capture: Snapshotting running processes and network state.
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

        class EvidenceCollector {
        public:
            static EvidenceCollector& Instance();

            /**
             * @brief Collect all artifacts related to a specific detection.
             * @param pid The malicious PID.
             * @param filePath The malicious file path.
             */
            bool CollectEvidence(uint32_t pid, const std::wstring& filePath);

            /**
             * @brief Pack the evidence into an encrypted ShadowStrike Forensic Container (.sfc).
             */
            std::wstring ExportEvidence(const std::string& incidentId);

        private:
            EvidenceCollector() = default;
        };

    } // namespace Forensics
} // namespace ShadowStrike
