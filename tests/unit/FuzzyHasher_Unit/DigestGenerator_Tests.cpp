/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for DigestGenerator.cpp.
 *
 * Coverage focus:
 * - digest generation invariants and block-size selection behavior
 * - salted generation determinism
 * - raw C-buffer API validation and parity with std::string results
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/FuzzyHasher/DigestGenerator.hpp"
#include "../../../src/Shared_modules/FuzzyHasher/FuzzyHasher.hpp"

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
        data[i] = static_cast<uint8_t>((i * 17u + 29u) % 251u);
    }
    return data;
}

std::optional<DigestParts> ParseDigest(std::string_view digest) {
    const size_t firstColon = digest.find(':');
    const size_t secondColon = digest.find(':', firstColon == std::string_view::npos ? 0 : firstColon + 1);
    if (firstColon == std::string_view::npos || secondColon == std::string_view::npos) {
        return std::nullopt;
    }

    DigestParts parts;
    parts.blockSize = static_cast<uint32_t>(std::stoul(std::string(digest.substr(0, firstColon))));
    parts.sig1 = std::string(digest.substr(firstColon + 1, secondColon - firstColon - 1));
    parts.sig2 = std::string(digest.substr(secondColon + 1));
    return parts;
}

bool IsValidBlockSize(uint32_t blockSize) {
    if (blockSize == 0 || blockSize % FH::kMinBlockSize != 0) {
        return false;
    }
    const uint32_t quotient = blockSize / FH::kMinBlockSize;
    return quotient != 0 && (quotient & (quotient - 1)) == 0;
}

}  // namespace

TEST(DigestGeneratorTest, GenerateDigestRejectsEmptyInputAndProducesStableWellFormedDigests) {
    EXPECT_FALSE(FH::GenerateDigest({}).has_value());

    const std::vector<uint8_t> singleByte = {0x41};
    const auto singleDigest = FH::GenerateDigest(singleByte);
    ASSERT_TRUE(singleDigest.has_value());
    const auto singleParts = ParseDigest(*singleDigest);
    ASSERT_TRUE(singleParts.has_value());
    EXPECT_EQ(singleParts->blockSize, FH::kMinBlockSize);
    EXPECT_EQ(singleParts->sig1.size(), 1u);
    EXPECT_EQ(singleParts->sig2.size(), 1u);

    const std::vector<uint8_t> sample = MakePatternData(8192);
    const auto digestA = FH::GenerateDigest(sample);
    const auto digestB = FH::GenerateDigest(sample);
    ASSERT_TRUE(digestA.has_value());
    ASSERT_TRUE(digestB.has_value());
    EXPECT_EQ(*digestA, *digestB);

    const auto parsed = ParseDigest(*digestA);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(IsValidBlockSize(parsed->blockSize));
    EXPECT_TRUE(parsed->sig1.size() >= FH::kDigestComponentLength / 2 ||
                parsed->blockSize == FH::kMinBlockSize);
    EXPECT_LE(parsed->sig1.size(), FH::kDigestComponentLength);
    EXPECT_LE(parsed->sig2.size(), FH::kHalfDigestLength);
}

TEST(DigestGeneratorTest, GenerateDigestAdjustsBlockSizeAcrossSmallAndLargeInputs) {
    const auto smallDigest = FH::GenerateDigest(MakePatternData(64));
    const auto largeDigest = FH::GenerateDigest(MakePatternData(65536));
    ASSERT_TRUE(smallDigest.has_value());
    ASSERT_TRUE(largeDigest.has_value());

    const auto smallParts = ParseDigest(*smallDigest);
    const auto largeParts = ParseDigest(*largeDigest);
    ASSERT_TRUE(smallParts.has_value());
    ASSERT_TRUE(largeParts.has_value());

    EXPECT_EQ(smallParts->blockSize, FH::kMinBlockSize);
    EXPECT_GT(largeParts->blockSize, FH::kMinBlockSize);
}

TEST(DigestGeneratorTest, GenerateDigestWithSaltIsDeterministicPerSaltAndVariesAcrossSalts) {
    const std::vector<uint8_t> sample = MakePatternData(4096);

    EXPECT_FALSE(FH::GenerateDigestWithSalt({}, 0x1111ULL).has_value());

    const auto unsalted = FH::GenerateDigest(sample);
    const auto zeroSalt = FH::GenerateDigestWithSalt(sample, 0);
    const auto saltA1 = FH::GenerateDigestWithSalt(sample, 0x0123456789ABCDEFULL);
    const auto saltA2 = FH::GenerateDigestWithSalt(sample, 0x0123456789ABCDEFULL);
    const auto saltB = FH::GenerateDigestWithSalt(sample, 0x0FEDCBA987654321ULL);
    ASSERT_TRUE(unsalted.has_value());
    ASSERT_TRUE(zeroSalt.has_value());
    ASSERT_TRUE(saltA1.has_value());
    ASSERT_TRUE(saltA2.has_value());
    ASSERT_TRUE(saltB.has_value());

    EXPECT_EQ(*zeroSalt, *unsalted);
    EXPECT_EQ(*saltA1, *saltA2);
    EXPECT_NE(*saltA1, *saltB);
    EXPECT_EQ(FH::Compare(*saltA1, *saltA2), 100);
}

TEST(DigestGeneratorTest, GenerateDigestRawValidatesPointersAndCopiesExactDigestText) {
    char result[FH::kDigestGeneratorMaxResultLength] = {};
    const std::vector<uint8_t> sample = MakePatternData(2048);
    const auto digest = FH::GenerateDigest(sample);
    ASSERT_TRUE(digest.has_value());

    EXPECT_EQ(FH::GenerateDigestRaw(sample.data(), static_cast<uint32_t>(sample.size()), result), 0);
    EXPECT_STREQ(result, digest->c_str());
    EXPECT_LT(std::strlen(result), FH::kDigestGeneratorMaxResultLength);

    EXPECT_EQ(FH::GenerateDigestRaw(nullptr, static_cast<uint32_t>(sample.size()), result), -1);
    EXPECT_EQ(FH::GenerateDigestRaw(sample.data(), 0, result), -1);
    EXPECT_EQ(FH::GenerateDigestRaw(sample.data(), static_cast<uint32_t>(sample.size()), nullptr), -1);
}

}  // namespace ShadowStrike::FuzzyHasher::Test
