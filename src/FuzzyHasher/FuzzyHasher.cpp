/**
 * ============================================================================
 * ShadowStrike NGAV — FuzzyHasher Public API Implementation
 * ============================================================================
 *
 * @file FuzzyHasher.cpp
 * @brief Public API facade for the CTPH fuzzy hashing engine
 *
 * This file delegates to the internal DigestGenerator and DigestComparer
 * modules. It provides input validation, size capping, and a clean
 * public interface.
 *
 * @copyright Copyright (c) ShadowStrike Contributors
 * @license AGPL-3.0-only
 * ============================================================================
 */

#include "FuzzyHasher.hpp"
#include "DigestGenerator.hpp"
#include "DigestComparer.hpp"

namespace ShadowStrike::FuzzyHasher {

    std::optional<std::string> HashBuffer(std::span<const uint8_t> data) noexcept {
        if (data.empty()) {
            return std::nullopt;
        }

        return GenerateDigest(data);
    }

    int HashBufferRaw(
        const uint8_t* buf,
        uint32_t buf_len,
        char* result
    ) noexcept {
        if (!buf || buf_len == 0 || !result) {
            return -1;
        }

        return GenerateDigestRaw(buf, buf_len, result);
    }

    int Compare(const char* digest1, const char* digest2) noexcept {
        if (!digest1 || !digest2) {
            return -1;
        }

        return CompareDigests(digest1, digest2);
    }

    int Compare(const std::string& digest1, const std::string& digest2) noexcept {
        if (digest1.empty() || digest2.empty()) {
            return -1;
        }

        return CompareDigests(digest1.c_str(), digest2.c_str());
    }

} // namespace ShadowStrike::FuzzyHasher
