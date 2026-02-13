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
     * @brief Generate a CTPH digest into a pre-allocated C buffer.
     *
     * @param buf Input data pointer
     * @param buf_len Input data length
     * @param result Output buffer (must be at least 148 bytes)
     * @return 0 on success, -1 on error
     */
    [[nodiscard]] int GenerateDigestRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
