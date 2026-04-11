/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for the public FuzzyHasher facade.
 *
 * Coverage focus:
 * - input validation and digest-format invariants
 * - normalization, salted hashing, and suspicious-digest screening
 * - batch comparison and fuzzy+crypto confirmation behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../../../src/PhantomCore/FuzzyHasher/DigestGenerator.hpp"
#include "../../../src/PhantomCore/FuzzyHasher/FuzzyHasher.hpp"

namespace FH = ShadowStrike::FuzzyHasher;

namespace ShadowStrike::FuzzyHasher::Test {
namespace {

struct DigestParts {
    uint32_t blockSize = 0;
    std::string sig1;
    std::string sig2;
};

std::vector<uint8_t> MakePatternData(size_t size) {
    std::vector<uint8_t> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>((i * 37u + 11u) % 251u);
    }
    return data;
}

std::span<const uint8_t> OversizedSpan() {
    static const uint8_t kDummy = 0x41;
    return {&kDummy, FH::kMaxHashableSize + 1};
}

std::optional<DigestParts> ParseDigest(std::string_view digest) {
    const size_t firstColon = digest.find(':');
    if (firstColon == std::string_view::npos || firstColon == 0) {
        return std::nullopt;
    }

    const size_t secondColon = digest.find(':', firstColon + 1);
    if (secondColon == std::string_view::npos || secondColon == firstColon + 1 ||
        secondColon + 1 >= digest.size()) {
        return std::nullopt;
    }

    DigestParts parts;
    parts.blockSize = static_cast<uint32_t>(std::stoul(std::string(digest.substr(0, firstColon))));
    parts.sig1 = std::string(digest.substr(firstColon + 1, secondColon - firstColon - 1));
    parts.sig2 = std::string(digest.substr(secondColon + 1));
    return parts;
}

std::string BuildDigestString(const DigestParts& parts) {
    return std::to_string(parts.blockSize) + ":" + parts.sig1 + ":" + parts.sig2;
}

bool IsValidBlockSize(uint32_t blockSize) {
    if (blockSize == 0 || blockSize % FH::kMinBlockSize != 0) {
        return false;
    }

    uint32_t quotient = blockSize / FH::kMinBlockSize;
    return quotient != 0 && (quotient & (quotient - 1)) == 0;
}

bool IsLowerHex64(std::string_view value) {
    if (value.size() != 64) {
        return false;
    }

    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isdigit(c) != 0 || (c >= 'a' && c <= 'f');
    });
}

std::string MakeMinorVariant(std::string digest) {
    auto parts = ParseDigest(digest);
    EXPECT_TRUE(parts.has_value());
    if (!parts.has_value()) {
        return digest;
    }

    parts->sig1[0] = (parts->sig1[0] == 'A') ? 'B' : 'A';
    parts->sig2.back() = (parts->sig2.back() == 'A') ? 'B' : 'A';
    return BuildDigestString(*parts);
}

}  // namespace

TEST(FuzzyHasherTest, HashBufferValidatesInputBoundsAndReturnsStableDigestFormat) {
    EXPECT_FALSE(FH::HashBuffer({}).has_value());
    EXPECT_FALSE(FH::HashBuffer(OversizedSpan()).has_value());

    const std::vector<uint8_t> sample = MakePatternData(4096);
    const auto digest = FH::HashBuffer(sample);
    ASSERT_TRUE(digest.has_value());
    ASSERT_TRUE(ParseDigest(*digest).has_value());

    const DigestParts parts = *ParseDigest(*digest);
    EXPECT_TRUE(IsValidBlockSize(parts.blockSize));
    EXPECT_FALSE(parts.sig1.empty());
    EXPECT_FALSE(parts.sig2.empty());
    EXPECT_LE(parts.sig1.size(), FH::kSignatureLength);
    EXPECT_LE(parts.sig2.size(), FH::kSignatureLength / 2);

    const auto repeatedDigest = FH::HashBuffer(sample);
    ASSERT_TRUE(repeatedDigest.has_value());
    EXPECT_EQ(*repeatedDigest, *digest);
}

TEST(FuzzyHasherTest, HashBufferRawMirrorsHashBufferAndRejectsInvalidArguments) {
    char result[FH::kMaxResultLength] = {};
    const std::vector<uint8_t> sample = MakePatternData(1024);
    const auto digest = FH::HashBuffer(sample);
    ASSERT_TRUE(digest.has_value());

    EXPECT_EQ(FH::HashBufferRaw(sample.data(), static_cast<uint32_t>(sample.size()), result), 0);
    EXPECT_STREQ(result, digest->c_str());

    EXPECT_EQ(FH::HashBufferRaw(nullptr, static_cast<uint32_t>(sample.size()), result), -1);
    EXPECT_EQ(FH::HashBufferRaw(sample.data(), 0, result), -1);
    EXPECT_EQ(FH::HashBufferRaw(sample.data(), static_cast<uint32_t>(sample.size()), nullptr), -1);
    EXPECT_EQ(FH::HashBufferRaw(OversizedSpan().data(), static_cast<uint32_t>(OversizedSpan().size()), result), -1);
}

TEST(FuzzyHasherTest, CompareOverloadsValidateInputsAndReportExpectedScores) {
    const std::vector<uint8_t> sample = MakePatternData(4096);
    const auto digest = FH::HashBuffer(sample);
    ASSERT_TRUE(digest.has_value());

    EXPECT_EQ(FH::Compare(digest->c_str(), digest->c_str()), 100);
    EXPECT_EQ(FH::Compare(*digest, *digest), 100);
    EXPECT_EQ(FH::Compare(nullptr, digest->c_str()), -1);
    EXPECT_EQ(FH::Compare(std::string{}, *digest), -1);

    const std::string oversized(FH::kMaxDigestStringLength + 1, 'A');
    EXPECT_EQ(FH::Compare(oversized, *digest), -1);
    EXPECT_EQ(FH::Compare(oversized.c_str(), digest->c_str()), -1);
}

TEST(FuzzyHasherTest, HashBufferNormalizedTrimsTrailingZerosAndFallsBackForMalformedPe) {
    const std::vector<uint8_t> base = MakePatternData(1536);
    const auto baseDigest = FH::HashBuffer(base);
    ASSERT_TRUE(baseDigest.has_value());

    std::vector<uint8_t> belowThresholdPad = base;
    belowThresholdPad.resize(base.size() + 511, 0);
    const auto belowThresholdDigest = FH::HashBuffer(belowThresholdPad);
    const FH::NormalizedHashResult belowThresholdNormalized =
        FH::HashBufferNormalized(belowThresholdPad, false);
    ASSERT_TRUE(belowThresholdDigest.has_value());
    ASSERT_TRUE(belowThresholdNormalized.normalizedDigest.has_value());
    ASSERT_TRUE(belowThresholdNormalized.sha256Hex.has_value());
    EXPECT_FALSE(belowThresholdNormalized.wasNormalized);
    EXPECT_FALSE(belowThresholdNormalized.fullFileDigest.has_value());
    EXPECT_EQ(*belowThresholdNormalized.normalizedDigest, *belowThresholdDigest);

    std::vector<uint8_t> padded = base;
    padded.resize(base.size() + 700, 0);

    const FH::NormalizedHashResult trimmed = FH::HashBufferNormalized(padded, false);
    ASSERT_TRUE(trimmed.normalizedDigest.has_value());
    ASSERT_TRUE(trimmed.sha256Hex.has_value());
    EXPECT_TRUE(trimmed.wasNormalized);
    EXPECT_FALSE(trimmed.fullFileDigest.has_value());
    EXPECT_TRUE(IsLowerHex64(*trimmed.sha256Hex));
    EXPECT_EQ(*trimmed.normalizedDigest, *baseDigest);

    const std::vector<uint8_t> peLike = {'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
    const FH::NormalizedHashResult malformedPe = FH::HashBufferNormalized(peLike, true);
    ASSERT_TRUE(malformedPe.normalizedDigest.has_value());
    ASSERT_TRUE(malformedPe.fullFileDigest.has_value());
    ASSERT_TRUE(malformedPe.sha256Hex.has_value());
    EXPECT_FALSE(malformedPe.wasNormalized);
    EXPECT_EQ(*malformedPe.normalizedDigest, *malformedPe.fullFileDigest);
    EXPECT_TRUE(IsLowerHex64(*malformedPe.sha256Hex));

    const FH::NormalizedHashResult autoDetectedPe = FH::HashBufferNormalized(peLike, false);
    ASSERT_TRUE(autoDetectedPe.normalizedDigest.has_value());
    ASSERT_TRUE(autoDetectedPe.fullFileDigest.has_value());
    ASSERT_TRUE(autoDetectedPe.sha256Hex.has_value());
    EXPECT_FALSE(autoDetectedPe.wasNormalized);
    EXPECT_EQ(*autoDetectedPe.normalizedDigest, *autoDetectedPe.fullFileDigest);

    const FH::NormalizedHashResult forcedPeFallback = FH::HashBufferNormalized(base, true);
    ASSERT_TRUE(forcedPeFallback.normalizedDigest.has_value());
    ASSERT_TRUE(forcedPeFallback.fullFileDigest.has_value());
    ASSERT_TRUE(forcedPeFallback.sha256Hex.has_value());
    EXPECT_FALSE(forcedPeFallback.wasNormalized);
    EXPECT_EQ(*forcedPeFallback.normalizedDigest, *forcedPeFallback.fullFileDigest);
    EXPECT_EQ(*forcedPeFallback.normalizedDigest, *baseDigest);

    const std::vector<uint8_t> allZeros(700, 0);
    const FH::NormalizedHashResult zeroStripped = FH::HashBufferNormalized(allZeros, false);
    const std::vector<uint8_t> singleZero = {0};
    const auto singleZeroDigest = FH::HashBuffer(singleZero);
    ASSERT_TRUE(zeroStripped.normalizedDigest.has_value());
    ASSERT_TRUE(zeroStripped.sha256Hex.has_value());
    ASSERT_TRUE(singleZeroDigest.has_value());
    EXPECT_TRUE(zeroStripped.wasNormalized);
    EXPECT_FALSE(zeroStripped.fullFileDigest.has_value());
    EXPECT_EQ(*zeroStripped.normalizedDigest, *singleZeroDigest);

    const FH::NormalizedHashResult invalid = FH::HashBufferNormalized(OversizedSpan(), false);
    EXPECT_FALSE(invalid.normalizedDigest.has_value());
    EXPECT_FALSE(invalid.fullFileDigest.has_value());
    EXPECT_FALSE(invalid.sha256Hex.has_value());
    EXPECT_FALSE(invalid.wasNormalized);
}

TEST(FuzzyHasherTest, HashWithSaltSupportsFixedAndSessionScopedDeterminism) {
    const std::vector<uint8_t> sample = MakePatternData(4096);

    EXPECT_FALSE(FH::HashWithSalt({}, 0x1234ULL).has_value());
    EXPECT_FALSE(FH::HashWithSalt(OversizedSpan(), 0x1234ULL).has_value());

    const auto saltedA = FH::HashWithSalt(sample, 0x0123456789ABCDEFULL);
    const auto saltedB = FH::HashWithSalt(sample, 0x0123456789ABCDEFULL);
    const auto saltedC = FH::HashWithSalt(sample, 0x13579BDF2468ACE0ULL);
    ASSERT_TRUE(saltedA.has_value());
    ASSERT_TRUE(saltedB.has_value());
    ASSERT_TRUE(saltedC.has_value());
    EXPECT_EQ(*saltedA, *saltedB);
    EXPECT_NE(*saltedA, *saltedC);

    const auto sessionSaltA = FH::HashWithSalt(sample);
    const auto sessionSaltB = FH::HashWithSalt(sample);
    const auto explicitZeroSalt = FH::HashWithSalt(sample, 0);
    ASSERT_TRUE(sessionSaltA.has_value());
    ASSERT_TRUE(sessionSaltB.has_value());
    ASSERT_TRUE(explicitZeroSalt.has_value());
    EXPECT_EQ(*sessionSaltA, *sessionSaltB);
    EXPECT_EQ(*sessionSaltA, *explicitZeroSalt);
}

TEST(FuzzyHasherTest, SuspiciousDigestScreenRejectsCraftedInputsAndAllowsLegitimateDigests) {
    EXPECT_TRUE(FH::IsSuspiciousDigest(""));
    EXPECT_TRUE(FH::IsSuspiciousDigest(std::string(FH::kMaxDigestStringLength + 1, 'A')));
    EXPECT_TRUE(FH::IsSuspiciousDigest("bad-digest"));
    EXPECT_TRUE(FH::IsSuspiciousDigest("5:ABCDEFG:HIJKLMN"));
    EXPECT_TRUE(FH::IsSuspiciousDigest("9:ABCDEFG:HIJKLMN"));
    EXPECT_TRUE(FH::IsSuspiciousDigest("3:ABCDEF:HIJKLMN"));
    EXPECT_TRUE(FH::IsSuspiciousDigest("3:AAAAAAA:HIJKLMN"));
    EXPECT_FALSE(FH::IsSuspiciousDigest("3:ABCDEFG:HIJKLMN"));

    const auto digest = FH::HashBuffer(MakePatternData(4096));
    ASSERT_TRUE(digest.has_value());
    EXPECT_FALSE(FH::IsSuspiciousDigest(*digest));
}

TEST(FuzzyHasherTest, BatchCompareFiltersInvalidCandidatesAndSortsBestMatchesFirst) {
    const std::vector<uint8_t> sample = MakePatternData(4096);
    const auto target = FH::HashBuffer(sample);
    ASSERT_TRUE(target.has_value());

    const std::string nearVariant = MakeMinorVariant(*target);
    EXPECT_GT(FH::Compare(*target, nearVariant), 0);
    EXPECT_LT(FH::Compare(*target, nearVariant), 100);

    const std::vector<std::string> candidates = {
        nearVariant,
        *target,
        "5:ABCDEFG:HIJKLMN",
        std::string{},
        std::string(FH::kMaxDigestStringLength + 1, 'A')
    };

    const auto results = FH::BatchCompare(candidates, *target);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0].index, 1u);
    EXPECT_EQ(results[0].score, 100);
    EXPECT_EQ(results[1].index, 0u);
    EXPECT_GT(results[1].score, 0);
    EXPECT_LT(results[1].score, 100);

    EXPECT_TRUE(FH::BatchCompare({}, *target).empty());
    EXPECT_TRUE(FH::BatchCompare(candidates, std::string{}).empty());
    EXPECT_TRUE(FH::BatchCompare(candidates, std::string(FH::kMaxDigestStringLength + 1, 'A')).empty());
}

TEST(FuzzyHasherTest, CompareWithCryptoConfirmationDistinguishesExactSkippedAndVariantMatches) {
    const std::vector<uint8_t> sample = MakePatternData(4096);
    const FH::CryptoConfirmResult exact = FH::CompareWithCryptoConfirmation(sample, sample);
    EXPECT_EQ(exact.fuzzyScore, 100);
    EXPECT_TRUE(exact.cryptoRan);
    EXPECT_TRUE(exact.exactMatch);
    ASSERT_TRUE(exact.hash1Hex.has_value());
    ASSERT_TRUE(exact.hash2Hex.has_value());
    EXPECT_EQ(*exact.hash1Hex, *exact.hash2Hex);
    EXPECT_TRUE(IsLowerHex64(*exact.hash1Hex));

    const FH::CryptoConfirmResult skipped = FH::CompareWithCryptoConfirmation(sample, sample, 101);
    EXPECT_EQ(skipped.fuzzyScore, 100);
    EXPECT_FALSE(skipped.cryptoRan);
    EXPECT_FALSE(skipped.exactMatch);
    EXPECT_FALSE(skipped.hash1Hex.has_value());
    EXPECT_FALSE(skipped.hash2Hex.has_value());

    const FH::CryptoConfirmResult boundary = FH::CompareWithCryptoConfirmation(sample, sample, 100);
    EXPECT_EQ(boundary.fuzzyScore, 100);
    EXPECT_TRUE(boundary.cryptoRan);
    EXPECT_TRUE(boundary.exactMatch);

    std::vector<uint8_t> variant = sample;
    std::reverse(variant.begin(), variant.end());
    const FH::CryptoConfirmResult different = FH::CompareWithCryptoConfirmation(sample, variant, 0);
    EXPECT_GE(different.fuzzyScore, 0);
    EXPECT_TRUE(different.cryptoRan);
    EXPECT_FALSE(different.exactMatch);
    ASSERT_TRUE(different.hash1Hex.has_value());
    ASSERT_TRUE(different.hash2Hex.has_value());
    EXPECT_NE(*different.hash1Hex, *different.hash2Hex);

    std::vector<uint8_t> padded = sample;
    padded.resize(sample.size() + 700, 0);
    const FH::CryptoConfirmResult normalized = FH::CompareWithCryptoConfirmation(padded, sample, 0);
    EXPECT_EQ(normalized.fuzzyScore, 100);
    EXPECT_TRUE(normalized.cryptoRan);
    EXPECT_TRUE(normalized.exactMatch);

    const FH::CryptoConfirmResult emptyRejected = FH::CompareWithCryptoConfirmation({}, sample, 0);
    EXPECT_EQ(emptyRejected.fuzzyScore, -1);
    EXPECT_FALSE(emptyRejected.cryptoRan);
    EXPECT_FALSE(emptyRejected.hash1Hex.has_value());
    EXPECT_FALSE(emptyRejected.hash2Hex.has_value());

    const FH::CryptoConfirmResult oversizedRejected =
        FH::CompareWithCryptoConfirmation(OversizedSpan(), sample, 0);
    EXPECT_EQ(oversizedRejected.fuzzyScore, -1);
    EXPECT_FALSE(oversizedRejected.cryptoRan);
    EXPECT_FALSE(oversizedRejected.hash1Hex.has_value());
    EXPECT_FALSE(oversizedRejected.hash2Hex.has_value());
}

}  // namespace ShadowStrike::FuzzyHasher::Test
