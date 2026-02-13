/**
 * ============================================================================
 * ShadowStrike NGAV — Weighted Edit Distance
 * ============================================================================
 *
 * @file EditDistance.hpp
 * @brief Weighted Levenshtein distance for comparing digest strings
 *
 * Computes the minimum-cost sequence of edit operations to transform
 * one string into another. Operations and their costs:
 *   - Insertion:     cost 1
 *   - Deletion:      cost 1
 *   - Substitution:  cost 3
 *
 * The higher substitution cost reflects that a character replacement is
 * a more significant change than an insertion or deletion in the context
 * of piecewise hash signatures — a substitution implies the content of
 * an entire chunk changed, while insert/delete implies a boundary shift.
 *
 * Uses the standard dynamic programming approach with O(min(m,n)) space
 * via a single-row optimization.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>

namespace ShadowStrike::FuzzyHasher {

    /// Maximum signature component length (each of the two hash parts)
    inline constexpr uint32_t kMaxSignatureComponentLength = 64;

    /// Edit operation costs
    inline constexpr uint32_t kInsertCost = 1;
    inline constexpr uint32_t kDeleteCost = 1;
    inline constexpr uint32_t kSubstituteCost = 3;

    /**
     * @brief Compute weighted edit distance between two C strings.
     *
     * @param s1 First string (null-terminated)
     * @param len1 Length of first string
     * @param s2 Second string (null-terminated)
     * @param len2 Length of second string
     * @return Weighted edit distance (lower = more similar)
     *
     * @note Both strings must have length <= kMaxSignatureComponentLength.
     *       Exceeding this returns UINT32_MAX.
     */
    [[nodiscard]] inline uint32_t WeightedEditDistance(
        const char* s1, uint32_t len1,
        const char* s2, uint32_t len2
    ) noexcept {

        if (len1 > kMaxSignatureComponentLength || len2 > kMaxSignatureComponentLength) {
            return UINT32_MAX;
        }

        // Ensure s1 is the shorter string for O(min(m,n)) space
        if (len1 > len2) {
            std::swap(s1, s2);
            std::swap(len1, len2);
        }

        // Single-row DP: prev[j] = cost to transform s1[0..i-1] into s2[0..j-1]
        // +1 for the empty-string column
        std::array<uint32_t, kMaxSignatureComponentLength + 1> prev{};
        std::array<uint32_t, kMaxSignatureComponentLength + 1> curr{};

        // Initialize base case: transforming empty string to s2[0..j-1]
        for (uint32_t j = 0; j <= len2; ++j) {
            prev[j] = j * kInsertCost;
        }

        for (uint32_t i = 1; i <= len1; ++i) {
            curr[0] = i * kDeleteCost;

            for (uint32_t j = 1; j <= len2; ++j) {
                if (s1[i - 1] == s2[j - 1]) {
                    // Characters match — no cost
                    curr[j] = prev[j - 1];
                } else {
                    const uint32_t insertOp  = curr[j - 1] + kInsertCost;
                    const uint32_t deleteOp  = prev[j]     + kDeleteCost;
                    const uint32_t replaceOp = prev[j - 1] + kSubstituteCost;

                    curr[j] = std::min({ insertOp, deleteOp, replaceOp });
                }
            }

            std::swap(prev, curr);
        }

        return prev[len2];
    }

} // namespace ShadowStrike::FuzzyHasher
