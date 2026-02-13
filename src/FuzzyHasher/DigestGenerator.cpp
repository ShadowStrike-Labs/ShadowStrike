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
         */
        void GenerateSignatures(
            std::span<const uint8_t> data,
            uint32_t blockSize,
            char* sig1, uint32_t& sig1Len,
            char* sig2, uint32_t& sig2Len
        ) noexcept {
            RollingHash roller;
            ChunkHash chunk1;
            ChunkHash chunk2;

            sig1Len = 0;
            sig2Len = 0;

            // Use uint64_t to prevent overflow when blockSize >= 0x80000000
            const uint64_t doubleBlockSize = static_cast<uint64_t>(blockSize) * 2;

            for (size_t i = 0; i < data.size(); ++i) {
                const uint8_t byte = data[i];

                const uint32_t rollVal = roller.Update(byte);
                chunk1.Update(byte);
                chunk2.Update(byte);

                // Primary signature: trigger when rolling hash aligns with blocksize
                if ((rollVal % blockSize) == (blockSize - 1)) {
                    sig1[sig1Len] = kBase64Alphabet[chunk1.Digest() % 64];

                    if (sig1Len < kDigestComponentLength - 1) {
                        chunk1.Reset();
                        ++sig1Len;
                    }
                    // If we've reached max length, keep accumulating into the last
                    // character position — this combines all remaining chunks into
                    // the final character, ensuring the tail is always represented.
                }

                // Secondary signature: trigger at 2x blocksize
                if ((static_cast<uint64_t>(rollVal) % doubleBlockSize) == (doubleBlockSize - 1)) {
                    sig2[sig2Len] = kBase64Alphabet[chunk2.Digest() % 64];

                    if (sig2Len < kHalfDigestLength - 1) {
                        chunk2.Reset();
                        ++sig2Len;
                    }
                }
            }

            // Finalize: if chunk hashers have accumulated data since their last
            // reset (i.e., there's a partial chunk after the last trigger point),
            // emit one more character to capture the tail content
            if (chunk1.Digest() != kFnvOffsetBasis) {
                if (sig1Len < kDigestComponentLength) {
                    sig1[sig1Len] = kBase64Alphabet[chunk1.Digest() % 64];
                    ++sig1Len;
                }
            }
            if (chunk2.Digest() != kFnvOffsetBasis) {
                if (sig2Len < kHalfDigestLength) {
                    sig2[sig2Len] = kBase64Alphabet[chunk2.Digest() % 64];
                    ++sig2Len;
                }
            }

            sig1[sig1Len] = '\0';
            sig2[sig2Len] = '\0';
        }

    } // anonymous namespace

    std::optional<std::string> GenerateDigest(std::span<const uint8_t> data) noexcept {
        try {
            if (data.empty()) {
                return std::nullopt;
            }

            // Select initial blocksize
            uint32_t blockSize = SelectBlockSize(data.size());

            // Signature buffers
            char sig1[kDigestComponentLength + 1] = { 0 };
            char sig2[kHalfDigestLength + 1] = { 0 };
            uint32_t sig1Len = 0;
            uint32_t sig2Len = 0;

            // Generate signatures — may retry with halved blocksize if the
            // primary signature is too short (less than half the target length)
            GenerateSignatures(data, blockSize, sig1, sig1Len, sig2, sig2Len);

            // If the primary signature is very short, reduce blocksize and retry.
            // This ensures we have sufficient granularity for meaningful comparison.
            while (blockSize > kMinBlockSize && sig1Len < kDigestComponentLength / 2) {
                blockSize /= 2;
                std::memset(sig1, 0, sizeof(sig1));
                std::memset(sig2, 0, sizeof(sig2));
                GenerateSignatures(data, blockSize, sig1, sig1Len, sig2, sig2Len);
            }

            // Format: "blocksize:signature1:signature2"
            std::string result;
            result.reserve(20 + sig1Len + sig2Len);

            result += std::to_string(blockSize);
            result += ':';
            result += sig1;
            result += ':';
            result += sig2;

            return result;

        } catch (...) {
            return std::nullopt;
        }
    }

    int GenerateDigestRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept {
        if (!buf || buf_len == 0 || !result) {
            return -1;
        }

        auto digest = GenerateDigest(std::span<const uint8_t>(buf, buf_len));
        if (!digest.has_value()) {
            return -1;
        }

        const auto& str = digest.value();

        // 148 is the documented max result length
        if (str.size() >= 148) {
            return -1;
        }

        std::memcpy(result, str.c_str(), str.size() + 1);
        return 0;
    }

} // namespace ShadowStrike::FuzzyHasher
