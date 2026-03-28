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
 * ShadowStrike NGAV — CTPH Digest Generator Implementation
 * ============================================================================
 *
 * @file DigestGenerator.cpp
 * @brief Context-triggered piecewise hash digest generation
 *
 * Clean room implementation based on:
 *   - Kornblum, J. (2006). "Identifying almost identical files using
 *     context triggered piecewise hashing." Digital Investigation, 3, 91-97.
 *   - Tridgell, A. spamsum algorithm documentation (README).
 *
 * Algorithm summary:
 *   1. Select blocksize so that blocksize * DIGEST_LENGTH >= input_length
 *   2. Scan input byte-by-byte with a rolling hash
 *   3. When rolling_hash % blocksize == blocksize - 1, emit a Base64 char
 *      from the accumulated FNV-1a chunk hash
 *   4. Simultaneously generate a second signature at 2x blocksize
 *   5. Format: "blocksize:signature1:signature2"
 *
 * No code from any GPLv2-licensed project was referenced during implementation.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#include "DigestGenerator.hpp"
#include "RollingHash.hpp"
#include "ChunkHash.hpp"

#include <cstring>
#include <string>
#include <array>

namespace ShadowStrike::FuzzyHasher {

    namespace {

        /// Base64 alphabet for encoding chunk hashes into signature characters
        constexpr char kBase64Alphabet[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        static_assert(sizeof(kBase64Alphabet) == 65, "Base64 alphabet must be 64 chars + null");

        /**
         * @brief Select the appropriate blocksize for a given input length.
         *
         * Starts at kMinBlockSize and doubles until blocksize * kDigestComponentLength
         * is at least as large as the input. This ensures the primary signature
         * fits within kDigestComponentLength characters.
         */
        [[nodiscard]] uint32_t SelectBlockSize(uint64_t inputLength) noexcept {
            uint32_t blockSize = kMinBlockSize;

            while (static_cast<uint64_t>(blockSize) * kDigestComponentLength < inputLength) {
                blockSize *= 2;

                // Guard against overflow for extremely large inputs
                if (blockSize >= 0x80000000u) {
                    break;
                }
            }

            return blockSize;
        }

        /**
         * @brief Perform one pass of digest generation at a given blocksize.
         *
         * Scans the input and emits Base64 characters at trigger points.
         * Also generates the secondary signature at 2x blocksize simultaneously.
         *
         * @param data Input buffer
         * @param blockSize Primary blocksize
         * @param sig1 Output: primary signature buffer (kDigestComponentLength + 1)
         * @param sig1Len Output: length of primary signature
         * @param sig2 Output: secondary signature buffer (kHalfDigestLength + 1)
         * @param sig2Len Output: length of secondary signature
         * @param chunkInitialState Initial FNV state for chunk hashers.
         *        Pass a salt-derived value for APT-hardened hashing (BUG-8).
         *        Defaults to kFnvOffsetBasis (standard CTPH behaviour).
         */
        void GenerateSignatures(
            std::span<const uint8_t> data,
            uint32_t blockSize,
            char* sig1, uint32_t& sig1Len,
            char* sig2, uint32_t& sig2Len,
            uint32_t chunkInitialState = kFnvOffsetBasis
        ) noexcept {
            RollingHash roller;
            ChunkHash chunk1(chunkInitialState);
            ChunkHash chunk2(chunkInitialState);

            sig1Len = 0;
            sig2Len = 0;

            // Track bytes accumulated since the last Reset() on each chunk hasher.
            // Used for explicit finalization (BUG-6): replaces the fragile
            // chunk.Digest() != kFnvOffsetBasis check, which could theoretically
            // produce a false negative on a rare FNV fixed-point coincidence
            // and is also incorrect when a non-default chunkInitialState is used.
            uint32_t chunk1Pending = 0;
            uint32_t chunk2Pending = 0;

            // Use uint64_t to prevent overflow when blockSize >= 0x80000000
            const uint64_t doubleBlockSize = static_cast<uint64_t>(blockSize) * 2;

            for (size_t i = 0; i < data.size(); ++i) {
                const uint8_t byte = data[i];

                const uint32_t rollVal = roller.Update(byte);
                chunk1.Update(byte);
                ++chunk1Pending;
                chunk2.Update(byte);
                ++chunk2Pending;

                // Primary signature: trigger when rolling hash aligns with blocksize
                if ((rollVal % blockSize) == (blockSize - 1)) {
                    sig1[sig1Len] = kBase64Alphabet[chunk1.Digest() % 64];

                    if (sig1Len < kDigestComponentLength - 1) {
                        chunk1.Reset();
                        chunk1Pending = 0;
                        ++sig1Len;
                    }
                    // Saturation path: sig1Len stays at kDigestComponentLength-1.
                    // The slot is repeatedly overwritten with the evolving hash,
                    // so the final character encodes all bytes since the last reset.
                    // chunk1Pending is NOT reset here, enabling correct finalization.
                }

                // Secondary signature: trigger at 2x blocksize
                if ((static_cast<uint64_t>(rollVal) % doubleBlockSize) == (doubleBlockSize - 1)) {
                    sig2[sig2Len] = kBase64Alphabet[chunk2.Digest() % 64];

                    if (sig2Len < kHalfDigestLength - 1) {
                        chunk2.Reset();
                        chunk2Pending = 0;
                        ++sig2Len;
                    }
                }
            }

            // Finalize: emit trailing partial chunk if any unfinalized bytes remain.
            // Uses byte-pending counters rather than FNV state comparison (BUG-6 fix):
            //   - Immune to FNV fixed-point coincidences (theoretically possible)
            //   - Correct when chunkInitialState != kFnvOffsetBasis (salted hashing)
            if (chunk1Pending > 0) {
                if (sig1Len < kDigestComponentLength) {
                    sig1[sig1Len] = kBase64Alphabet[chunk1.Digest() % 64];
                    ++sig1Len;
                }
            }
            if (chunk2Pending > 0) {
                if (sig2Len < kHalfDigestLength) {
                    sig2[sig2Len] = kBase64Alphabet[chunk2.Digest() % 64];
                    ++sig2Len;
                }
            }

            sig1[sig1Len] = '\0';
            sig2[sig2Len] = '\0';
        }

        /**
         * @brief Internal helper shared by GenerateDigest and GenerateDigestWithSalt.
         *
         * Selects blocksize, runs GenerateSignatures (with optional salted state),
         * retries with halved blocksize if the primary signature is too sparse,
         * then formats the "blocksize:sig1:sig2" result string.
         */
        [[nodiscard]] std::optional<std::string> BuildDigest(
            std::span<const uint8_t> data,
            uint32_t chunkInitialState
        ) noexcept {
            uint32_t blockSize = SelectBlockSize(data.size());

            char sig1[kDigestComponentLength + 1] = { 0 };
            char sig2[kHalfDigestLength + 1] = { 0 };
            uint32_t sig1Len = 0;
            uint32_t sig2Len = 0;

            GenerateSignatures(data, blockSize, sig1, sig1Len, sig2, sig2Len, chunkInitialState);

            // If the primary signature is very short, reduce blocksize and retry.
            // This ensures sufficient granularity for meaningful comparison.
            while (blockSize > kMinBlockSize && sig1Len < kDigestComponentLength / 2) {
                blockSize /= 2;
                std::memset(sig1, 0, sizeof(sig1));
                std::memset(sig2, 0, sizeof(sig2));
                sig1Len = 0;
                sig2Len = 0;
                GenerateSignatures(data, blockSize, sig1, sig1Len, sig2, sig2Len, chunkInitialState);
            }

            std::string result;
            result.reserve(20 + sig1Len + sig2Len);
            result += std::to_string(blockSize);
            result += ':';
            result += sig1;
            result += ':';
            result += sig2;
            return result;
        }

    } // anonymous namespace

    std::optional<std::string> GenerateDigest(std::span<const uint8_t> data) noexcept {
        try {
            // BUG-5: single authoritative empty-input guard at this layer.
            // GenerateDigestRaw delegates here, so no duplicate check is needed there.
            if (data.empty()) {
                return std::nullopt;
            }
            return BuildDigest(data, kFnvOffsetBasis);
        } catch (...) {
            return std::nullopt;
        }
    }

    std::optional<std::string> GenerateDigestWithSalt(
        std::span<const uint8_t> data,
        uint64_t salt
    ) noexcept {
        try {
            if (data.empty()) {
                return std::nullopt;
            }

            // Derive a 32-bit initial ChunkHash state from the 64-bit salt by
            // XORing both halves into the standard FNV offset basis.
            // This makes chunk boundaries and content unpredictable to an attacker
            // who does not know the per-session salt.
            const uint32_t saltedState = kFnvOffsetBasis
                ^ static_cast<uint32_t>(salt & 0xFFFFFFFFULL)
                ^ static_cast<uint32_t>(salt >> 32);

            return BuildDigest(data, saltedState);
        } catch (...) {
            return std::nullopt;
        }
    }

    int GenerateDigestRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept {
        // BUG-5: delegate directly to GenerateDigest — no duplicate null/empty guard.
        // GenerateDigest is the single authoritative validation point.
        if (!buf || buf_len == 0 || !result) {
            return -1;
        }

        auto digest = GenerateDigest(std::span<const uint8_t>(buf, buf_len));
        if (!digest.has_value()) {
            return -1;
        }

        const auto& str = digest.value();

        // BUG-7: use kMaxResultLength constant instead of the magic number 148.
        // kMaxResultLength includes the null terminator, so str.size() must be
        // strictly less than kMaxResultLength to leave room for '\0'.
        if (str.size() >= kMaxResultLength) {
            return -1;
        }

        std::memcpy(result, str.c_str(), str.size() + 1);
        return 0;
    }

} // namespace ShadowStrike::FuzzyHasher
