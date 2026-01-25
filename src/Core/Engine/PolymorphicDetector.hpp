/**
 * ============================================================================
 * ShadowStrike Core Engine - POLYMORPHIC DETECTOR (The Shapeshifter)
 * ============================================================================
 *
 * @file PolymorphicDetector.hpp
 * @brief Detection of metamorphic and polymorphic malware engines.
 *
 * Polymorphic malware changes its code structure (but not logic) in every iteration
 * to defeat signature matching. This module tries to "Normalize" the code.
 *
 * Capabilities:
 * 1. Opcode Normalization: Replaces registers (eax, ebx) with generics (reg1, reg2).
 * 2. Junk Code Removal: Detects and strips dead code insertion.
 * 3. Loop Analysis: Identifies decryption loops characteristic of polymorphic wrappers.
 *
 * Integrations:
 * - **HashStore**: Uses Fuzzy Hashing (SSDEEP) on the *Normalized* buffer.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../HashStore/HashStore.hpp"
#include <vector>
#include <cstdint>

namespace ShadowStrike {
    namespace Core {
        namespace Engine {

            struct PolyResult {
                bool isPolymorphic;
                std::string engineName; // e.g. "Mistfall", "EPC"
                std::vector<uint8_t> normalizedBody;
            };

            class PolymorphicDetector {
            public:
                static PolymorphicDetector& Instance();

                /**
                 * @brief Analyze code for polymorphic properties.
                 * @param code The executable section (.text).
                 */
                PolyResult Analyze(const std::vector<uint8_t>& code);

            private:
                PolymorphicDetector() = default;

                // Strip NOPs and Junk instructions
                std::vector<uint8_t> NormalizeInstructions(const std::vector<uint8_t>& input);
            };

        } // namespace Engine
    } // namespace Core
} // namespace ShadowStrike
