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

            // Parse blocksize
            char* endPtr = nullptr;
            const unsigned long bs = std::strtoul(digest, &endPtr, 10);
            if (endPtr != colon1 || bs == 0 || bs > 0xFFFFFFFFul) {
                return false;
            }
            out.blockSize = static_cast<uint32_t>(bs);

            // Find second colon — separates hash1 from hash2
            const char* hash1Start = colon1 + 1;
            const char* colon2 = std::strchr(hash1Start, ':');
            if (!colon2) {
                return false;
            }

            out.sig1 = std::string_view(hash1Start, static_cast<size_t>(colon2 - hash1Start));
            out.sig2 = std::string_view(colon2 + 1);

            // Validate component lengths
            if (out.sig1.size() > kMaxSignatureComponentLength ||
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
         * @return true if a common substring of sufficient length exists
         */
        [[nodiscard]] bool HasCommonSubstring(
            std::string_view s1,
            std::string_view s2
        ) noexcept {
            if (s1.size() < kRollingWindowSize || s2.size() < kRollingWindowSize) {
                return false;
            }

            // Compute rolling hash at each position in s1
            constexpr size_t kMaxHashes = kMaxSignatureComponentLength;
            std::array<uint32_t, kMaxHashes> hashes{};

            {
                RollingHash roller;
                for (size_t i = 0; i < s1.size(); ++i) {
                    hashes[i] = roller.Update(static_cast<uint8_t>(s1[i]));
                }
            }

            // For each position in s2, compute rolling hash and check against s1's hashes
            {
                RollingHash roller;
                for (size_t i = 0; i < s2.size(); ++i) {
                    const uint32_t h = roller.Update(static_cast<uint8_t>(s2[i]));

                    // Need at least kRollingWindowSize bytes before we have a valid window
                    if (i < kRollingWindowSize - 1) {
                        continue;
                    }

                    // Check against all valid hash positions in s1
                    for (size_t j = kRollingWindowSize - 1; j < s1.size(); ++j) {
                        if (hashes[j] == h) {
                            // Hash match — verify with direct string comparison
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
            // on very short inputs
            const uint32_t minLen = std::min(len1, len2);
            const uint32_t cap = (blockSize / kMinBlockSize) * minLen;
            if (score > cap) {
                score = cap;
            }

            return score;
        }

    } // anonymous namespace

    int CompareDigests(const char* digest1, const char* digest2) noexcept {
        try {
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
