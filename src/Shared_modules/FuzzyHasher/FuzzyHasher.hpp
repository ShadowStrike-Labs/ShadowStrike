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
 *     always call CompareWithCryptoConfirmation() on high-value detections
 *     (threshold >= kCryptoConfirmThreshold) to obtain a cryptographic
 *     exact-match verdict (SHA-3-256 on Windows 10 1903+, SHA-256 otherwise)
 *     on PE-normalized content.  This eliminates false positives caused by
 *     rolling-hash trigger-point manipulation even when the session salt is
 *     known to the adversary.
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

    /// Fuzzy-score threshold above which CompareWithCryptoConfirmation() runs the
    /// cryptographic confirmation pass.  At this score and above the fuzzy engine
    /// has high confidence; the crypto pass resolves whether the match is exact
    /// or a near-variant.  Callers may pass a lower threshold for deeper investigation.
    inline constexpr int kCryptoConfirmThreshold = 90;

    // =========================================================================
    // Result Types
    // =========================================================================

    /**
     * @brief Cryptographic algorithm actually used for confirmation.
     *
     * SHA3_256 is preferred; SHA256 is the fallback on older Windows versions
     * that do not support SHA-3 via BCrypt.
     */
    enum class CryptoAlgorithm : uint8_t {
        SHA256,   ///< SHA-2 256-bit — available on all Windows versions
        SHA3_256  ///< SHA-3 256-bit (Keccak) — Windows 10 1903+ / Server 2022+
    };

    /**
     * @brief Result of a normalized hashing operation.
     *
     * When normalization was applied (PE section extraction or zero-pad strip),
     * normalizedDigest reflects only the semantic content of the file.
     * fullFileDigest (populated only for PE files) provides the full-file hash
     * for secondary verification.
     *
     * sha256Hex is the lowercase SHA-256 hex digest of the same content that
     * normalizedDigest covers.  Populated whenever normalizedDigest is populated.
     * Consumers can store this alongside the fuzzy digest for exact-match lookups
     * without re-hashing.
     */
    struct NormalizedHashResult {
        std::optional<std::string> normalizedDigest; ///< CTPH of normalized content
        std::optional<std::string> fullFileDigest;   ///< CTPH of full file (PE only)
        std::optional<std::string> sha256Hex;        ///< SHA-256 of normalized content (lower-hex)
        bool wasNormalized = false;                  ///< True if input was modified
    };

    /**
     * @brief Result of a fuzzy + cryptographic confirmation comparison.
     *
     * Returned by CompareWithCryptoConfirmation().
     * Combines the CTPH similarity score with a cryptographic exact-match
     * verdict on the PE-normalized content of both buffers.
     */
    struct CryptoConfirmResult {
        /// Fuzzy similarity score (0-100). -1 if fuzzy comparison failed.
        int fuzzyScore = -1;

        /// True if the cryptographic hashes of the normalized content match.
        /// Only meaningful when cryptoRan == true.
        bool exactMatch = false;

        /// True if the crypto confirmation pass was actually executed.
        /// False when fuzzyScore < threshold (fast-path skip) or on error.
        bool cryptoRan = false;

        /// Algorithm used for the cryptographic comparison.
        /// SHA3_256 when available (Windows 10 1903+), SHA256 otherwise.
        CryptoAlgorithm algorithm = CryptoAlgorithm::SHA256;

        /// Lowercase hex hash of the normalized content of buf1.
        /// Populated when cryptoRan == true.
        std::optional<std::string> hash1Hex;

        /// Lowercase hex hash of the normalized content of buf2.
        /// Populated when cryptoRan == true.
        std::optional<std::string> hash2Hex;
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

    /**
     * @brief Perform fuzzy comparison followed by cryptographic confirmation.
     *
     * Algorithm:
     *   1. Normalize both buffers independently (PE section extraction or
     *      trailing-zero-pad strip — same logic as HashBufferNormalized()).
     *   2. Compute fuzzy similarity on the normalized content.
     *   3. If fuzzyScore >= threshold:
     *        a. Compute SHA-3-256 (Windows 10 1903+) or SHA-256 (fallback)
     *           on the normalized bytes of each buffer.
     *        b. Compare the digests in constant time.
     *        c. Populate result.exactMatch, hash1Hex, hash2Hex.
     *
     * Why this matters:
     *   A session salt prevents offline pre-computation, but a privileged
     *   adversary who has read the salt from process memory can still craft
     *   a binary that achieves a target fuzzy score.  A cryptographic hash
     *   on the same normalized content provides an independent, manipulation-
     *   resistant verdict:
     *     - exactMatch == true  → identical code sections (exact match / same
     *                             packer family with no code changes).
     *     - exactMatch == false → genuine code variant (mutation / polymorphism).
     *
     * @param buf1      First raw buffer (file bytes)
     * @param buf2      Second raw buffer (file bytes)
     * @param threshold Fuzzy score at or above which crypto confirmation runs.
     *                  Default: kCryptoConfirmThreshold (90).
     * @return CryptoConfirmResult populated with fuzzy score, crypto verdict,
     *         hashes, and algorithm used.  On total failure, fuzzyScore == -1.
     */
    [[nodiscard]] CryptoConfirmResult CompareWithCryptoConfirmation(
        std::span<const uint8_t> buf1,
        std::span<const uint8_t> buf2,
        int threshold = kCryptoConfirmThreshold
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
