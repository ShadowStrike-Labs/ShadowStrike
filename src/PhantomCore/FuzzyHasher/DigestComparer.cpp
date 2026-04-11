#include "pch.h"
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
 * ShadowStrike NGAV — CTPH Digest Comparison Implementation
 * ============================================================================
 *
 * @file DigestComparer.cpp
 * @brief Similarity scoring between two CTPH digest strings
 *
 * Clean room implementation based on:
 *   - Kornblum, J. (2006). "Identifying almost identical files using
 *     context triggered piecewise hashing." Digital Investigation, 3, 91-97.
 *   - Tridgell, A. spamsum algorithm documentation (README):
 *       "The distance measure is based on the string edit distance...
 *        insert/delete weight=1, substitution weight=3...
 *        rescale to 0-100... weighted so 50 is a reasonable threshold."
 *
 * No code from any GPLv2-licensed project was referenced during implementation.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#include "DigestComparer.hpp"
#include "DigestGenerator.hpp"
#include "RollingHash.hpp"
#include "EditDistance.hpp"

#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <array>
#include <string>
#include <string_view>

namespace ShadowStrike::FuzzyHasher {

    namespace {

        /**
         * @brief Parsed components of a CTPH digest string.
         */
        struct ParsedDigest {
            uint32_t blockSize = 0;
            std::string_view sig1;
            std::string_view sig2;
        };

        /**
         * @brief Parse a digest string "blocksize:hash1:hash2" into components.
         * @return true on success, false on malformed input
         */
        [[nodiscard]] bool ParseDigest(const char* digest, ParsedDigest& out) noexcept {
            if (!digest || digest[0] == '\0') {
                return false;
            }

            // Find first colon — separates blocksize from hash1
            const char* colon1 = std::strchr(digest, ':');
            if (!colon1 || colon1 == digest) {
                return false;
            }

            // BUG-2 FIX: use strtoull (64-bit) instead of strtoul (32-bit on Windows).
            // On Windows, unsigned long is 32 bits. strtoul overflow returns ULONG_MAX
            // (0xFFFFFFFF), making the check bs > 0xFFFFFFFFul always false — a crafted
            // blocksize of 4294967295 would bypass the guard and cascade into BUG-1.
            char* endPtr = nullptr;
            const unsigned long long bsLong = std::strtoull(digest, &endPtr, 10);
            if (endPtr != colon1 || bsLong == 0 || bsLong > 0xFFFFFFFFULL) {
                return false;
            }
            out.blockSize = static_cast<uint32_t>(bsLong);

            // Find second colon — separates hash1 from hash2
            const char* hash1Start = colon1 + 1;
            const char* colon2 = std::strchr(hash1Start, ':');
            if (!colon2) {
                return false;
            }

            out.sig1 = std::string_view(hash1Start, static_cast<size_t>(colon2 - hash1Start));
            out.sig2 = std::string_view(colon2 + 1);

            // Validate component lengths
            if (out.sig1.empty() || out.sig2.empty() ||
                out.sig1.size() > kMaxSignatureComponentLength ||
                out.sig2.size() > kMaxSignatureComponentLength) {
                return false;
            }

            return true;
        }

        /**
         * @brief Eliminate runs of 3+ identical consecutive characters.
         *
         * Sequences of identical characters carry very little information
         * and tend to bias the similarity score unfairly. This filter
         * replaces any run of N identical characters (N >= 4) with exactly 3.
         */
        [[nodiscard]] std::string EliminateSequences(std::string_view input) {
            if (input.size() <= 3) {
                return std::string(input);
            }

            std::string result;
            result.reserve(input.size());

            // Always copy the first 3 characters
            for (size_t i = 0; i < 3 && i < input.size(); ++i) {
                result.push_back(input[i]);
            }

            // For remaining characters, only emit if not extending a run of 3+
            for (size_t i = 3; i < input.size(); ++i) {
                if (input[i] != input[i - 1] ||
                    input[i] != input[i - 2] ||
                    input[i] != input[i - 3]) {
                    result.push_back(input[i]);
                }
            }

            return result;
        }

        /**
         * @brief Check if two signature strings share a common substring
         *        of at least kRollingWindowSize length.
         *
         * Uses the rolling hash as a fast filter for candidate matches,
         * then confirms with a direct comparison. This dramatically reduces
         * false positives for low-score comparisons.
         *
         * Inputs are bounded by kMaxSignatureComponentLength (64 chars) by the
         * caller, so worst-case work is 64×64 = 4 096 hash comparisons.
         * The memcmp path is marked [[unlikely]] because hash collisions in a
         * 7-byte rolling window over a 64-entry array are rare; it exists only
         * as a correctness gate against hash collisions.
         *
         * @return true if a common substring of sufficient length exists
         */
        [[nodiscard]] bool HasCommonSubstring(
            std::string_view s1,
            std::string_view s2
        ) noexcept {
            if (s1.size() < kRollingWindowSize || s2.size() < kRollingWindowSize) {
                return false;
            }

            // Both inputs are bounded to kMaxSignatureComponentLength (64) by
            // ParseDigest validation, so these arrays are always sufficient.
            constexpr size_t kMaxHashes = kMaxSignatureComponentLength;
            std::array<uint32_t, kMaxHashes> hashes{};

            {
                RollingHash roller;
                for (size_t i = 0; i < s1.size(); ++i) {
                    hashes[i] = roller.Update(static_cast<uint8_t>(s1[i]));
                }
            }

            {
                RollingHash roller;
                for (size_t i = 0; i < s2.size(); ++i) {
                    const uint32_t h = roller.Update(static_cast<uint8_t>(s2[i]));

                    if (i < kRollingWindowSize - 1) {
                        continue;
                    }

                    for (size_t j = kRollingWindowSize - 1; j < s1.size(); ++j) {
                        if (hashes[j] == h) [[unlikely]] {
                            // Hash match — confirm with direct string comparison.
                            // [[unlikely]]: rolling-hash collisions over 7-byte windows
                            // in 64-char inputs are rare; memcmp is a correctness gate.
                            const size_t s2Start = i - (kRollingWindowSize - 1);
                            const size_t s1Start = j - (kRollingWindowSize - 1);

                            if (s2Start + kRollingWindowSize <= s2.size() &&
                                s1Start + kRollingWindowSize <= s1.size() &&
                                std::memcmp(
                                    s1.data() + s1Start,
                                    s2.data() + s2Start,
                                    kRollingWindowSize) == 0) {
                                return true;
                            }
                        }
                    }
                }
            }

            return false;
        }

        /**
         * @brief Score two signature component strings on a 0-100 scale.
         *
         * Algorithm:
         *   1. Require a common substring of length >= kRollingWindowSize
         *   2. Compute weighted edit distance
         *   3. Scale by string lengths to get proportion of change
         *   4. Rescale to 0-100 (100 = perfect match, 0 = complete mismatch)
         *   5. Cap score based on blocksize ratio for small files
         */
        [[nodiscard]] uint32_t ScoreStrings(
            std::string_view s1,
            std::string_view s2,
            uint32_t blockSize
        ) noexcept {
            const uint32_t len1 = static_cast<uint32_t>(s1.size());
            const uint32_t len2 = static_cast<uint32_t>(s2.size());

            if (len1 > kMaxSignatureComponentLength || len2 > kMaxSignatureComponentLength) {
                return 0;
            }

            if (len1 == 0 || len2 == 0) {
                return 0;
            }

            // Require a common substring to be considered a candidate match
            if (!HasCommonSubstring(s1, s2)) {
                return 0;
            }

            // Compute weighted edit distance
            const uint32_t editDist = WeightedEditDistance(
                s1.data(), len1,
                s2.data(), len2
            );

            if (editDist == UINT32_MAX) {
                return 0;
            }

            // Scale edit distance by combined string lengths.
            // This normalizes the score relative to the message proportion that changed.
            uint32_t score = (editDist * kDigestComponentLength) / (len1 + len2);

            // Rescale to 0-100 percentage
            score = (100 * score) / kDigestComponentLength;

            // Scores >= 100 indicate a terrible match
            if (score >= 100) {
                return 0;
            }

            // Invert: 0 = mismatch, 100 = perfect match
            score = 100 - score;

            // Cap score for small blocksizes to avoid exaggerating matches
            // on very short inputs.
            // BUG-1 FIX: cap calculation uses uint64_t to prevent overflow.
            // With blockSize up to 0x80000000 and minLen up to 64:
            //   (0x80000000 / 3) * 64 = 45,812,984,832 — overflows uint32_t.
            // Clamp the cap to [0, 100] since score is already in that range.
            const uint32_t minLen = std::min(len1, len2);
            const uint64_t capU64 = (static_cast<uint64_t>(blockSize) / kMinBlockSize)
                                  * static_cast<uint64_t>(minLen);
            const uint32_t cap = static_cast<uint32_t>(
                std::min(capU64, static_cast<uint64_t>(100u))
            );
            if (score > cap) {
                score = cap;
            }

            return score;
        }

    } // anonymous namespace

    int CompareDigests(const char* digest1, const char* digest2) noexcept {
        try {
            if (!digest1 || !digest2) {
                return -1;
            }

            // BUG-3 FIX: bound the strchr scan in ParseDigest by verifying that
            // both strings are within a safe maximum length before touching them.
            // A null-terminator-less string passed by a hostile caller would
            // cause strchr to scan arbitrarily far into memory.
            //
            // Maximum valid digest length:
            //   blocksize (10 chars for uint32_t max) + ':' + sig1 (64) + ':' + sig2 (32) = 109
            // We allow 200 chars to be generous but still bound the scan.
            constexpr size_t kMaxDigestLen = 200;
            if (strnlen(digest1, kMaxDigestLen + 1) > kMaxDigestLen ||
                strnlen(digest2, kMaxDigestLen + 1) > kMaxDigestLen) {
                return -1;
            }

            ParsedDigest d1, d2;

            if (!ParseDigest(digest1, d1) || !ParseDigest(digest2, d2)) {
                return -1;
            }

            // Blocksizes must be compatible: equal, or one must be 2x the other
            if (d1.blockSize != d2.blockSize &&
                d1.blockSize != static_cast<uint64_t>(d2.blockSize) * 2 &&
                d2.blockSize != static_cast<uint64_t>(d1.blockSize) * 2) {
                return 0;
            }

            // Eliminate low-information repeated sequences
            const std::string s1_1 = EliminateSequences(d1.sig1);
            const std::string s1_2 = EliminateSequences(d1.sig2);
            const std::string s2_1 = EliminateSequences(d2.sig1);
            const std::string s2_2 = EliminateSequences(d2.sig2);

            uint32_t score = 0;

            if (d1.blockSize == d2.blockSize) {
                // Same blocksize: compare both signature components, take the best
                const uint32_t score1 = ScoreStrings(s1_1, s2_1, d1.blockSize);
                const uint32_t score2 = ScoreStrings(s1_2, s2_2, d1.blockSize);
                score = std::max(score1, score2);

            } else if (d1.blockSize == d2.blockSize * 2) {
                // d1's primary blocksize matches d2's secondary blocksize
                score = ScoreStrings(s1_1, s2_2, d1.blockSize);

            } else {
                // d2's primary blocksize matches d1's secondary blocksize
                score = ScoreStrings(s1_2, s2_1, d2.blockSize);
            }

            return static_cast<int>(score);

        } catch (...) {
            return -1;
        }
    }

} // namespace ShadowStrike::FuzzyHasher
