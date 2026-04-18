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
/*
 * Fuzzer-only dependency seam for the fuzzy hasher harness.
 *
 * These definitions provide a deterministic, minimal link surface for the
 * harness without bringing in the production CTPH implementation.
 */

#include "PhantomCore/FuzzyHasher/DigestComparer.hpp"
#include "PhantomCore/FuzzyHasher/FuzzyHasher.hpp"

#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace ShadowStrike::FuzzyHasher {

namespace {

inline constexpr char kStubDigest[] = "3:fuzz:fuzz";

}  // namespace

// HashBuffer(span<const uint8_t>) is already provided by ScanEngineHarnessDepsStub.cpp.
// Only additional FuzzyHasher symbols not in ScanEngine stub are defined here.

int HashBufferRaw(const uint8_t* buf, uint32_t buf_len, char* result) noexcept {
    if (buf == nullptr || buf_len == 0 || result == nullptr) {
        return -1;
    }

    std::memcpy(result, kStubDigest, sizeof(kStubDigest));
    return 0;
}

int Compare(const char*, const char*) noexcept {
    return 0;
}

int Compare(const std::string&, const std::string&) noexcept {
    return 0;
}

NormalizedHashResult HashBufferNormalized(std::span<const uint8_t> data, bool) noexcept {
    NormalizedHashResult result{};
    result.normalizedDigest = HashBuffer(data);
    result.wasNormalized = false;
    return result;
}

std::optional<std::string> HashWithSalt(std::span<const uint8_t> data, uint64_t) noexcept {
    return HashBuffer(data);
}

bool IsSuspiciousDigest(const std::string&) noexcept {
    return false;
}

std::vector<BatchCompareEntry> BatchCompare(
    std::span<const std::string>,
    const std::string&) noexcept
{
    return {};
}

CryptoConfirmResult CompareWithCryptoConfirmation(
    std::span<const uint8_t>,
    std::span<const uint8_t>,
    int) noexcept
{
    CryptoConfirmResult result{};
    result.fuzzyScore = 0;
    return result;
}

int CompareDigests(const char*, const char*) noexcept {
    return 0;
}

}  // namespace ShadowStrike::FuzzyHasher
