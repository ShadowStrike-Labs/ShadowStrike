/**
 * ============================================================================
 * ShadowStrike NGAV — FuzzyHasher Public API
 * ============================================================================
 *
 * @file FuzzyHasher.hpp
 * @brief Public API for context-triggered piecewise hashing (CTPH)
 *
 * This module provides fuzzy hashing capabilities for identifying
 * similar or modified files. It generates digest strings that can be
 * compared to yield a similarity score (0-100).
 *
 * Usage:
 * @code
 *   #include "FuzzyHasher/FuzzyHasher.hpp"
 *
 *   // Generate a digest
 *   auto digest = ShadowStrike::FuzzyHasher::HashBuffer(fileData);
 *   if (digest) {
 *       // digest.value() = "blocksize:hash1:hash2"
 *   }
 *
 *   // Compare two digests
 *   int score = ShadowStrike::FuzzyHasher::Compare(digest1, digest2);
 *   if (score >= 50) {
 *       // Files are likely related
 *   }
 * @endcode
 *
 * Thread Safety:
 *   All functions are thread-safe. No global or static mutable state.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace ShadowStrike::FuzzyHasher {

    /// Maximum length of a digest result string (including null terminator)
    inline constexpr size_t kMaxResultLength = 148;

    /// Length of each digest signature component
    inline constexpr size_t kSignatureLength = 64;

    /**
     * @brief Compute a fuzzy hash digest of a byte buffer.
     *
     * @param data Input buffer to hash (must not be empty)
     * @return Digest string in "blocksize:hash1:hash2" format,
     *         or std::nullopt on error
     */
    [[nodiscard]] std::optional<std::string> HashBuffer(
        std::span<const uint8_t> data
    ) noexcept;

    /**
     * @brief Compute a fuzzy hash digest into a pre-allocated C buffer.
     *
     * C-compatible buffer interface for existing call sites.
     *
     * @param buf Input data pointer
     * @param buf_len Input data length in bytes
     * @param result Output buffer — must hold at least kMaxResultLength bytes
     * @return 0 on success, -1 on error
     */
    [[nodiscard]] int HashBufferRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept;

    /**
     * @brief Compare two digest strings and return a similarity score.
     *
     * @param digest1 First digest (null-terminated C string)
     * @param digest2 Second digest (null-terminated C string)
     * @return Similarity score 0-100 (100 = identical content),
     *         or -1 on error (null input, malformed digest)
     */
    [[nodiscard]] int Compare(
        const char* digest1,
        const char* digest2
    ) noexcept;

    /**
     * @brief Compare two digest strings (std::string overload).
     */
    [[nodiscard]] int Compare(
        const std::string& digest1,
        const std::string& digest2
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
