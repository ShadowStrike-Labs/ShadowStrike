/**
 * ============================================================================
 * ShadowStrike NGAV — FNV-1a Chunk Hash
 * ============================================================================
 *
 * @file ChunkHash.hpp
 * @brief FNV-1a hash for accumulating chunk content between trigger points
 *
 * Each segment of the input (between two consecutive rolling hash trigger
 * points) is summarized into a single Base64 character using this hash.
 * FNV-1a is chosen for its excellent distribution properties, simplicity,
 * and speed on byte-oriented data.
 *
 * FNV-1a is a public domain hash function — no licensing concerns.
 * See: http://www.isthe.com/chongo/tech/comp/fnv/
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#pragma once

#include <cstdint>

namespace ShadowStrike::FuzzyHasher {

    /// FNV-1a 32-bit offset basis
    inline constexpr uint32_t kFnvOffsetBasis = 0x811c9dc5u;

    /// FNV-1a 32-bit prime
    inline constexpr uint32_t kFnvPrime = 0x01000193u;

    /**
     * @brief FNV-1a 32-bit incremental hasher.
     *
     * Accumulates bytes one at a time between trigger points.
     * At each trigger point, the accumulated digest is used to produce
     * one Base64 character for the output signature.
     */
    class ChunkHash final {
    public:
        ChunkHash() noexcept : m_state(kFnvOffsetBasis) {}

        /**
         * @brief Feed one byte into the hash accumulator.
         * @param byte The next input byte
         */
        void Update(uint8_t byte) noexcept {
            m_state ^= static_cast<uint32_t>(byte);
            m_state *= kFnvPrime;
        }

        /**
         * @brief Return the current accumulated digest value.
         */
        [[nodiscard]] uint32_t Digest() const noexcept {
            return m_state;
        }

        /**
         * @brief Reset to the initial FNV offset basis.
         */
        void Reset() noexcept {
            m_state = kFnvOffsetBasis;
        }

    private:
        uint32_t m_state;
    };

} // namespace ShadowStrike::FuzzyHasher
