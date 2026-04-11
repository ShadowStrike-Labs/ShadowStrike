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
     *
     * Supports an optional salted initial state for APT-hardened hashing.
     * When a non-default initialState is provided, Reset() returns to that
     * same salted state, ensuring consistent salt application across all
     * chunks in a single hashing pass.
     */
    class ChunkHash final {
    public:
        /**
         * @brief Construct with optional salted initial state.
         *
         * @param initialState Starting FNV state. Defaults to kFnvOffsetBasis.
         *        Pass a per-session salt-derived value to harden against
         *        offline trigger-point pre-computation by adversaries.
         */
        explicit ChunkHash(uint32_t initialState = kFnvOffsetBasis) noexcept
            : m_state(initialState)
            , m_initialState(initialState)
        {}

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
         * @brief Reset to the initial state (salted or default).
         *
         * Returns to m_initialState rather than hard-coded kFnvOffsetBasis,
         * so that salt is uniformly applied across all chunks.
         */
        void Reset() noexcept {
            m_state = m_initialState;
        }

        /**
         * @brief Return the initial state this hasher was constructed with.
         */
        [[nodiscard]] uint32_t InitialState() const noexcept {
            return m_initialState;
        }

    private:
        uint32_t m_state;
        uint32_t m_initialState;  ///< Restored on Reset(); supports salted hashing
    };

} // namespace ShadowStrike::FuzzyHasher
