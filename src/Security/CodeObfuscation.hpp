/**
 * ============================================================================
 * ShadowStrike Security - CODE OBFUSCATION (The Puzzle)
 * ============================================================================
 *
 * @file CodeObfuscation.hpp
 * @brief Logic for protecting internal logic from static analysis.
 *
 * Capabilities:
 * 1. String Encryption: Decrypting strings only when needed in memory.
 * 2. Control Flow Flattening: Making function logic harder to graph.
 * 3. VM-Based Execution: (Optional) Running critical logic in a custom bytecode interpreter.
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

        class CodeObfuscation {
        public:
            /**
             * @brief Decrypt a string literal at runtime.
             * (Usage: OBFUSCATED_STR("SensitiveInfo"))
             */
            static std::string DecryptString(const std::vector<uint8_t>& encrypted);

        private:
            CodeObfuscation() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
