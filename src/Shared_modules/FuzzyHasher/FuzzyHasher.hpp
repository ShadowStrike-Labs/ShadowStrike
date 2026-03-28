/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
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
 *   All functions are thread-safe. No global or static mutable state
 *   (the session salt is a read-only static after first use).
 *
 * APT-Hardening Notes:
 *   - Use HashBufferNormalized() for files that may have been padded or
 *     overlaid with junk data to shift trigger-point positions.
 *   - Use HashWithSalt() when storing in-memory digests that should not
 *     be comparable across process lifetimes (prevents offline pre-computation).
 *   - Call IsSuspiciousDigest() on any externally-supplied digest string
 *     before passing it to Compare() to reject score-inflation crafted inputs.
 *   - A score of 100 is necessary but NOT sufficient to confirm identity;
 *     always confirm with a cryptographic hash (SHA-256/SHA-3) on high-value
 *     detections.
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
#include <vector>

namespace ShadowStrike::FuzzyHasher {

    // =========================================================================
    // Module Constants
    // =========================================================================

    /// Maximum length of a digest result string (including null terminator).
    inline constexpr size_t kMaxResultLength = 148;

    /// Length of each digest signature component.
    inline constexpr size_t kSignatureLength = 64;

    /// Maximum input size accepted by HashBuffer() and HashBufferRaw().
    /// Inputs larger than this are rejected to prevent CPU/memory DoS.
    /// 200 MB is a conservative ceiling for endpoint file scanning.
    inline constexpr size_t kMaxHashableSize = 200ULL * 1024ULL * 1024ULL;

    /// Maximum length of a digest string accepted by Compare().
    /// blocksize (10) + ':' + sig1 (64) + ':' + sig2 (32) = 109; 200 is generous.
    inline constexpr size_t kMaxDigestStringLength = 200;

    // =========================================================================
    // Result Types
    // =========================================================================

    /**
     * @brief Result of a normalized hashing operation.
     *
     * When normalization was applied (PE section extraction or zero-pad strip),
     * normalizedDigest reflects only the semantic content of the file.
     * fullFileDigest (populated only for PE files) provides the full-file hash
     * for secondary verification.
     */
    struct NormalizedHashResult {
        std::optional<std::string> normalizedDigest; ///< Hash of normalized content
        std::optional<std::string> fullFileDigest;   ///< Full-file hash (PE only)
        bool wasNormalized = false;                  ///< True if input was modified
    };

    /**
     * @brief One entry in a batch comparison result.
     */
    struct BatchCompareEntry {
        size_t   index = 0;  ///< Position of this candidate in the input span
        int      score = 0;  ///< Similarity score 0-100 (100 = identical)
    };

    // =========================================================================
    // Core API
    // =========================================================================

    /**
     * @brief Compute a fuzzy hash digest of a byte buffer.
     *
     * Rejects inputs larger than kMaxHashableSize to prevent DoS.
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
     * @param buf_len Input data length in bytes (must be <= kMaxHashableSize)
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
     * Both digest1 and digest2 are validated for maximum length
     * (kMaxDigestStringLength) before any scanning, to prevent
     * unbounded strchr traversal on attacker-supplied strings.
     *
     * @param digest1 First digest (null-terminated C string)
     * @param digest2 Second digest (null-terminated C string)
     * @return Similarity score 0-100 (100 = identical content),
     *         or -1 on error (null input, malformed digest, oversized string)
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

    // =========================================================================
    // APT-Hardening Extensions
    // =========================================================================

    /**
     * @brief Compute a fuzzy hash after normalizing the input buffer.
     *
     * Normalization removes features that adversaries use to shift trigger
     * points and change chunk encodings without meaningfully altering the
     * file's executable content:
     *
     *   Non-PE files:
     *     - Strip trailing zero-padding of >= 512 bytes.
     *
     *   PE files (isPE == true, or auto-detected via MZ magic):
     *     - Parse PE headers to locate all executable / code sections.
     *     - Concatenate their raw bytes as the primary hash input.
     *     - Also compute a full-file hash (returned in result.fullFileDigest).
     *     - Strips PE overlay data automatically via section-only extraction.
     *
     * If PE parsing fails or no code sections are found, falls back to the
     * full-buffer hash (wasNormalized = false).
     *
     * @param data   Raw file bytes
     * @param isPE   Hint that the buffer is a PE file.  When false the MZ
     *               magic is still checked and PE normalization is applied
     *               if the file appears to be a PE.
     * @return NormalizedHashResult with at least normalizedDigest set.
     */
    [[nodiscard]] NormalizedHashResult HashBufferNormalized(
        std::span<const uint8_t> data,
        bool isPE = false
    ) noexcept;

    /**
     * @brief Compute a fuzzy hash with a per-session random salt.
     *
     * The salt is mixed into the FNV chunk-hash initial state, making
     * trigger points and their Base64 encodings session-specific.
     * Use this when storing in-memory digests that must not be comparable
     * across process lifetimes (prevents offline pre-computation attacks).
     *
     * When salt == 0 the module's own BCryptGenRandom session salt is used
     * automatically — callers should prefer this default.
     *
     * WARNING: digests produced with different salts MUST NOT be compared
     * against each other.  Use only for intra-session comparisons.
     *
     * @param data Input buffer
     * @param salt 64-bit salt.  Pass 0 to use the built-in session salt.
     * @return Digest string, or std::nullopt on error
     */
    [[nodiscard]] std::optional<std::string> HashWithSalt(
        std::span<const uint8_t> data,
        uint64_t salt = 0
    ) noexcept;

    /**
     * @brief Detect adversarially crafted digest strings.
     *
     * Checks for known score-inflation and comparison-bypass patterns:
     *   1. All-identical-character signature (e.g., "AAAAAAAAAA") — produces
     *      artificially high similarity scores against any file with a run
     *      of that character.
     *   2. Blocksize that is not a power-of-2 multiple of kMinBlockSize (3) —
     *      legitimate CTPH digests always have blocksize = 3 * 2^n.
     *   3. Signature component shorter than kRollingWindowSize (7) — the
     *      minimum required for HasCommonSubstring to return true, so shorter
     *      sigs can never score > 0 but also cannot be caught by that guard.
     *
     * @param digest Digest string to evaluate
     * @return true if the digest exhibits a suspicious pattern
     */
    [[nodiscard]] bool IsSuspiciousDigest(const std::string& digest) noexcept;

    /**
     * @brief Compare one target digest against many candidate digests.
     *
     * More efficient than calling Compare() in a loop when the caller has
     * a large set of candidates: the target is parsed once and reused.
     * Only candidates that produce score > 0 are included in the output.
     *
     * @param candidates Span of candidate digest strings
     * @param target     The reference digest to compare against
     * @return Vector of (index, score) pairs, sorted by score descending.
     *         Empty if no matches or on error.
     */
    [[nodiscard]] std::vector<BatchCompareEntry> BatchCompare(
        std::span<const std::string> candidates,
        const std::string& target
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
