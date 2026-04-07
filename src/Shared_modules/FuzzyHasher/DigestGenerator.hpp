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
 * ShadowStrike NGAV — CTPH Digest Generator
 * ============================================================================
 *
 * @file DigestGenerator.hpp
 * @brief Context-triggered piecewise hash digest generation engine
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

    /// Minimum blocksize — smallest meaningful chunk granularity
    inline constexpr uint32_t kMinBlockSize = 3;

    /// Length of each signature component (max characters per hash part)
    inline constexpr uint32_t kDigestComponentLength = 64;

    /// Half of the digest component length (for the second signature)
    inline constexpr uint32_t kHalfDigestLength = kDigestComponentLength / 2;

    /// Maximum length of a generated digest result string, including null terminator.
    /// Format: "<blocksize>:<sig1>:<sig2>\0"
    ///   blocksize: up to 10 chars for uint32_t max
    ///   sig1:      up to kDigestComponentLength = 64 chars
    ///   sig2:      up to kHalfDigestLength = 32 chars
    ///   colons/null: 3 chars
    ///   Total: 10 + 64 + 32 + 3 = 109; 148 is a conservative ceiling.
    inline constexpr size_t kDigestGeneratorMaxResultLength = 148;

    /**
     * @brief Generate a CTPH digest from a byte buffer.
     *
     * Produces a string in the format "blocksize:hash1:hash2" where:
     *   - blocksize is a decimal integer
     *   - hash1 is a Base64-encoded signature at the chosen blocksize
     *   - hash2 is a Base64-encoded signature at 2x the blocksize
     *
     * @param data Input buffer to hash
     * @return Digest string, or std::nullopt on error
     */
    [[nodiscard]] std::optional<std::string> GenerateDigest(
        std::span<const uint8_t> data
    ) noexcept;

    /**
     * @brief Generate a CTPH digest with a per-session salt mixed into
     *        the chunk hash initial state.
     *
     * The salt is XOR-folded into the FNV offset basis so that all chunk
     * boundaries and their Base64 encodings are session-specific.  An
     * attacker who does not know the salt cannot pre-compute which byte
     * sequences will produce a given digest character, defeating
     * trigger-point manipulation and chunk-content forgery attacks.
     *
     * Two digests produced with different salts MUST NOT be compared
     * with CompareDigests — comparison is only valid within one session.
     *
     * @param data Input buffer to hash
     * @param salt 64-bit per-session random value (from BCryptGenRandom)
     * @return Digest string, or std::nullopt on error
     */
    [[nodiscard]] std::optional<std::string> GenerateDigestWithSalt(
        std::span<const uint8_t> data,
        uint64_t salt
    ) noexcept;

    /**
     * @brief Generate a CTPH digest into a pre-allocated C buffer.
     *
     * @param buf Input data pointer
     * @param buf_len Input data length
     * @param result Output buffer (must be at least kMaxResultLength bytes)
     * @return 0 on success, -1 on error
     */
    [[nodiscard]] int GenerateDigestRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
