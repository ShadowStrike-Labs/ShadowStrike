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
 * ShadowStrike NGAV — CTPH Digest Comparison Engine
 * ============================================================================
 *
 * @file DigestComparer.hpp
 * @brief Similarity scoring between two CTPH digest strings
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace ShadowStrike::FuzzyHasher {

    /**
     * @brief Compare two CTPH digest strings and return a similarity score.
     *
     * The comparison algorithm:
     * 1. Parse both digests to extract blocksize and dual hash strings
     * 2. Verify blocksize compatibility (must match or one must be 2x the other)
     * 3. Eliminate low-information sequences (runs of 3+ identical chars)
     * 4. Verify common substring existence (minimum length = rolling window size)
     * 5. Compute weighted edit distance
     * 6. Scale to 0-100 score
     *
     * @param digest1 First digest string ("blocksize:hash1:hash2")
     * @param digest2 Second digest string ("blocksize:hash1:hash2")
     * @return Similarity score 0-100 (100 = identical), or -1 on error
     */
    [[nodiscard]] int CompareDigests(
        const char* digest1,
        const char* digest2
    ) noexcept;

} // namespace ShadowStrike::FuzzyHasher
