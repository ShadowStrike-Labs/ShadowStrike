/**
 * ============================================================================
 * ShadowStrike NGAV — Rolling Hash for Boundary Detection
 * ============================================================================
 *
 * @file RollingHash.hpp
 * @brief Adler-variant rolling hash for context-triggered boundary detection
 *
 * This rolling hash provides alignment-robust boundary detection for
 * piecewise hashing. It uses a sliding window approach where the hash
 * value depends only on the most recent WINDOW_SIZE bytes, enabling
 * automatic re-synchronization after insertions or deletions.
 *
 * The hash combines three components:
 *   - h1: sum of bytes in the window (Adler-like)
 *   - h2: weighted position sum (index-scaled byte accumulation)
 *   - h3: shift-XOR component for large blocksize resilience
 *
 * Reference: Kornblum, J. (2006). "Identifying almost identical files
 *            using context triggered piecewise hashing."
 *            Digital Investigation, 3, 91-97.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <array>

namespace ShadowStrike::FuzzyHasher {

    /**
     * @brief Sliding window size for the rolling hash.
     *
     * A window of 7 bytes provides a good balance between:
     *   - Sensitivity: small enough to detect local context changes
     *   - Stability: large enough to avoid excessive trigger points
     *
     * This value also serves as the minimum common substring length
     * required during digest comparison.
     */
    inline constexpr uint32_t kRollingWindowSize = 7;

    /**
     * @brief Adler-variant rolling hash with a fixed-size sliding window.
     *
     * All state is instance-local — no globals, no statics.
     * Safe for concurrent use across threads (each thread owns its instance).
     */
    class RollingHash final {
    public:
        RollingHash() noexcept { Reset(); }

        /**
         * @brief Feed one byte into the rolling window and return the updated hash.
         * @param byte The next input byte
         * @return Current rolling hash value
         */
        [[nodiscard]] uint32_t Update(uint8_t byte) noexcept {
            // Remove the outgoing byte's contribution and add the incoming byte
            m_h2 -= m_h1;
            m_h2 += kRollingWindowSize * static_cast<uint32_t>(byte);

            m_h1 += static_cast<uint32_t>(byte);
            m_h1 -= static_cast<uint32_t>(m_window[m_pos]);

            m_window[m_pos] = byte;
            m_pos = (m_pos + 1) % kRollingWindowSize;

            // Shift-XOR component: provides additional entropy for large blocksizes
            // where h1+h2 alone would produce too many collisions
            m_h3 = (m_h3 << 5) & 0xFFFFFFFF;
            m_h3 ^= static_cast<uint32_t>(byte);

            return m_h1 + m_h2 + m_h3;
        }

        /**
         * @brief Reset all internal state to initial values.
         */
        void Reset() noexcept {
            m_window.fill(0);
            m_h1 = 0;
            m_h2 = 0;
            m_h3 = 0;
            m_pos = 0;
        }

        /**
         * @brief Return the current hash value without consuming a byte.
         */
        [[nodiscard]] uint32_t Value() const noexcept {
            return m_h1 + m_h2 + m_h3;
        }

    private:
        std::array<uint8_t, kRollingWindowSize> m_window{};
        uint32_t m_h1 = 0;   ///< Sum of bytes in window
        uint32_t m_h2 = 0;   ///< Weighted position sum
        uint32_t m_h3 = 0;   ///< Shift-XOR rolling component
        uint32_t m_pos = 0;  ///< Current write position in circular buffer [0, kRollingWindowSize)
    };

} // namespace ShadowStrike::FuzzyHasher
