/**
 * ============================================================================
 * ShadowStrike Security - MEMORY PROTECTION (The Buffer)
 * ============================================================================
 *
 * @file MemoryProtection.hpp
 * @brief Logic for securing process memory from external reading.
 *
 * Capabilities:
 * 1. ASLR Enforcement: Forcing Address Space Layout Randomization.
 * 2. Secure Allocator: Using Zero-on-Free and Encrypted-at-Rest buffers for keys.
 * 3. Anti-Dumping: Making it harder for tools like Scylla to dump process memory.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright 2026 ShadowStrike Security Suite
 */

#pragma once

#include "../../Utils/MemoryUtils.hpp"
#include <cstdint>

namespace ShadowStrike {
    namespace Security {

        class MemoryProtection {
        public:
            static MemoryProtection& Instance();

            /**
             * @brief Harden the memory of the current process.
             */
            void ApplyProcessHardening();

            /**
             * @brief Allocate sensitive memory that is automatically cleared.
             */
            void* AllocateSecure(size_t size);
            void FreeSecure(void* ptr, size_t size);

        private:
            MemoryProtection() = default;
        };

    } // namespace Security
} // namespace ShadowStrike
