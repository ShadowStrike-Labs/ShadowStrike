/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for DigestComparer.cpp.
 *
 * Coverage focus:
 * - malformed input rejection
 * - exact, near, and incompatible digest comparisons
 * - public overload validation for the higher-level compare facade
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/FuzzyHasher/DigestComparer.hpp"
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
        data[i] = static_cast<uint8_t>((i * 19u + 7u) % 251u);
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

std::string BuildDigestString(const DigestParts& parts) {
    return std::to_string(parts.blockSize) + ":" + parts.sig1 + ":" + parts.sig2;
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

TEST(DigestComparerTest, CompareDigestsRejectsMalformedAndOverlongInputs) {
    EXPECT_EQ(FH::CompareDigests("", "3:ABCDEFG:HIJKLMN"), -1);
    EXPECT_EQ(FH::CompareDigests("bad-digest", "3:ABCDEFG:HIJKLMN"), -1);
    EXPECT_EQ(FH::CompareDigests("0:ABCDEFG:HIJKLMN", "3:ABCDEFG:HIJKLMN"), -1);

    const std::string oversized(201, 'A');
    EXPECT_EQ(FH::CompareDigests(oversized.c_str(), "3:ABCDEFG:HIJKLMN"), -1);

    const std::string longSig = "3:" + std::string(65, 'A') + ":HIJKLMN";
    EXPECT_EQ(FH::CompareDigests(longSig.c_str(), "3:ABCDEFG:HIJKLMN"), -1);
}

TEST(DigestComparerTest, CompareDigestsHandlesExactNearAndIncompatibleComparisons) {
    const auto digest = FH::HashBuffer(MakePatternData(4096));
    ASSERT_TRUE(digest.has_value());

    EXPECT_EQ(FH::CompareDigests(digest->c_str(), digest->c_str()), 100);

    const std::string nearVariant = MakeMinorVariant(*digest);
    const int nearScore = FH::CompareDigests(digest->c_str(), nearVariant.c_str());
    EXPECT_GT(nearScore, 0);
    EXPECT_LT(nearScore, 100);

    EXPECT_EQ(FH::CompareDigests("3:ABCDEFG:HIJKLMN", "5:ABCDEFG:HIJKLMN"), 0);
}

TEST(DigestComparerTest, PublicCompareOverloadsMirrorComparerSemanticsAndValidateBoundaries) {
    const auto digest = FH::HashBuffer(MakePatternData(4096));
    ASSERT_TRUE(digest.has_value());

    EXPECT_EQ(FH::Compare(*digest, *digest), 100);
    EXPECT_EQ(FH::Compare(digest->c_str(), digest->c_str()), 100);
    EXPECT_EQ(FH::Compare(nullptr, digest->c_str()), -1);
    EXPECT_EQ(FH::Compare(std::string{}, *digest), -1);

    const std::string oversized(FH::kMaxDigestStringLength + 1, 'A');
    EXPECT_EQ(FH::Compare(oversized, *digest), -1);
    EXPECT_EQ(FH::Compare(oversized.c_str(), digest->c_str()), -1);
}

}  // namespace ShadowStrike::FuzzyHasher::Test
