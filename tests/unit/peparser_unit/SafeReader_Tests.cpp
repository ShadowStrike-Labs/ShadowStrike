/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PEParser SafeReader and SafeMath primitives.
 *
 * Focus:
 *   - arithmetic overflow/underflow guards used throughout PE parsing
 *   - bounds-checked typed reads, string handling, and sub-reader creation
 *   - alignment-sensitive array reads and comparison contracts
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <array>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "../../../src/PhantomCore/PEParser/SafeReader.hpp"

namespace ShadowStrike::PEParser::Test {

TEST(SafeMathTest, ArithmeticAndCastGuardsRejectOverflowAndUnderflow) {
    uint32_t u32 = 0;
    ASSERT_TRUE(SafeMath::SafeAdd<uint32_t>(10u, 20u, u32));
    EXPECT_EQ(u32, 30u);
    EXPECT_FALSE(SafeMath::SafeAdd<uint32_t>(std::numeric_limits<uint32_t>::max(), 1u, u32));

    ASSERT_TRUE(SafeMath::SafeMul<uint32_t>(12u, 16u, u32));
    EXPECT_EQ(u32, 192u);
    EXPECT_FALSE(SafeMath::SafeMul<uint32_t>(std::numeric_limits<uint32_t>::max(), 2u, u32));

    ASSERT_TRUE(SafeMath::SafeSub<uint32_t>(30u, 10u, u32));
    EXPECT_EQ(u32, 20u);
    EXPECT_FALSE(SafeMath::SafeSub<uint32_t>(10u, 30u, u32));

    const auto toU16 = SafeMath::SafeCast<uint16_t>(65535u);
    ASSERT_TRUE(toU16.has_value());
    EXPECT_EQ(*toU16, 65535u);
    EXPECT_FALSE(SafeMath::SafeCast<uint16_t>(65536u).has_value());
    EXPECT_FALSE(SafeMath::SafeCast<uint32_t>(-1).has_value());

    const auto signedCast = SafeMath::SafeCast<int16_t>(-123);
    ASSERT_TRUE(signedCast.has_value());
    EXPECT_EQ(*signedCast, -123);
    EXPECT_FALSE(SafeMath::SafeCast<int16_t>(-32769).has_value());
    EXPECT_FALSE(SafeMath::SafeCast<int8_t>(200).has_value());
    EXPECT_FALSE(SafeMath::SafeCast<int8_t>(256u).has_value());
}

TEST(SafeReaderTest, ConstructorsRangeChecksAndPrimitiveReadsStayBounded) {
    const std::array<uint8_t, 8> bytes{0x01, 0x34, 0x12, 0x78, 0x56, 0xBC, 0x9A, 0xEF};
    const SafeReader reader(bytes.data(), bytes.size());

    EXPECT_TRUE(reader.IsValid());
    EXPECT_TRUE(reader.HasData());
    EXPECT_EQ(reader.Size(), bytes.size());
    EXPECT_EQ(reader.Data(), bytes.data());
    EXPECT_TRUE(reader.ValidateRange(0, bytes.size()));
    EXPECT_TRUE(reader.ValidateOffset(bytes.size() - 1));
    EXPECT_FALSE(reader.ValidateOffset(bytes.size()));
    EXPECT_FALSE(reader.ValidateRange(bytes.size() - 1, 2));
    EXPECT_FALSE(reader.ValidateRange(std::numeric_limits<size_t>::max(), 8));

    uint8_t byte = 0;
    ASSERT_TRUE(reader.ReadByte(0, byte));
    EXPECT_EQ(byte, 0x01);
    EXPECT_FALSE(reader.ReadByte(bytes.size(), byte));

    uint16_t u16 = 0;
    ASSERT_TRUE(reader.ReadU16LE(1, u16));
    EXPECT_EQ(u16, 0x1234u);

    uint32_t u32 = 0;
    ASSERT_TRUE(reader.ReadU32LE(1, u32));
    EXPECT_EQ(u32, 0x56781234u);

    uint64_t u64 = 0;
    EXPECT_TRUE(reader.ReadU64LE(0, u64));
    EXPECT_EQ(u64, 0xEF9ABC5678123401ULL);

    const auto optU32 = reader.ReadOpt<uint32_t>(1);
    ASSERT_TRUE(optU32.has_value());
    EXPECT_EQ(*optU32, 0x56781234u);
    EXPECT_FALSE(reader.ReadOpt<uint32_t>(bytes.size() - 1).has_value());

    const SafeReader nullReader(nullptr, 64);
    EXPECT_FALSE(nullReader.IsValid());
    EXPECT_FALSE(nullReader.HasData());
    EXPECT_EQ(nullReader.Size(), 0u);
}

TEST(SafeReaderTest, ArrayStringSubReaderAndComparisonContractsRemainStable) {
    alignas(uint32_t) const std::array<uint32_t, 3> words{
        0x11223344u, 0x55667788u, 0x99AABBCCu
    };
    const SafeReader wordReader(reinterpret_cast<const uint8_t*>(words.data()), sizeof(words));

    std::span<const uint32_t> wordSpan;
    ASSERT_TRUE(wordReader.ReadArray<uint32_t>(0, words.size(), wordSpan));
    ASSERT_EQ(wordSpan.size(), words.size());
    EXPECT_EQ(wordSpan[0], 0x11223344u);
    EXPECT_EQ(wordSpan[2], 0x99AABBCCu);

    std::span<const uint32_t> misalignedSpan;
    EXPECT_FALSE(wordReader.ReadArray<uint32_t>(1, 1, misalignedSpan));
    EXPECT_FALSE(wordReader.ReadArray<uint32_t>(0, std::numeric_limits<size_t>::max(), misalignedSpan));

    std::array<uint8_t, sizeof(words)> copied{};
    ASSERT_TRUE(wordReader.ReadBytes(0, copied.data(), copied.size()));
    EXPECT_FALSE(wordReader.ReadBytes(0, nullptr, copied.size()));
    EXPECT_TRUE(wordReader.CompareBytes(0, words.data(), sizeof(words)));
    EXPECT_FALSE(wordReader.CompareBytes(0, nullptr, sizeof(words)));
    EXPECT_FALSE(wordReader.CompareBytes(sizeof(words), words.data(), 1));

    const std::array<char, 17> stringBytes{
        'a', 'l', 'p', 'h', 'a', '\0',
        'b', 'e', 't', 'a', '\0',
        'X', 'Y', 'Z', '\0',
        'Q', 'R'
    };
    const SafeReader stringReader(
        reinterpret_cast<const uint8_t*>(stringBytes.data()),
        stringBytes.size());

    std::string_view value;
    ASSERT_TRUE(stringReader.ReadString(0, 10, value));
    EXPECT_EQ(value, "alpha");
    ASSERT_TRUE(stringReader.ReadString(6, 5, value));
    EXPECT_EQ(value, "beta");
    EXPECT_FALSE(stringReader.ReadString(15, 4, value));

    std::string fixed;
    ASSERT_TRUE(stringReader.ReadFixedString(11, 4, fixed));
    EXPECT_EQ(fixed, "XYZ");
    ASSERT_TRUE(stringReader.ReadFixedString(15, 2, fixed));
    EXPECT_EQ(fixed, "QR");
    EXPECT_FALSE(stringReader.ReadFixedString(16, 4, fixed));

    const auto sub = stringReader.SubReader(6, 5);
    ASSERT_TRUE(sub.has_value());
    EXPECT_TRUE(sub->IsValid());
    EXPECT_EQ(sub->Size(), 5u);

    const auto tail = stringReader.SubReaderFrom(stringBytes.size());
    ASSERT_TRUE(tail.has_value());
    EXPECT_EQ(tail->Size(), 0u);
    EXPECT_TRUE(tail->IsValid());

    EXPECT_FALSE(stringReader.SubReader(16, 2).has_value());
    EXPECT_FALSE(stringReader.SubReaderFrom(stringBytes.size() + 1).has_value());
}

}  // namespace ShadowStrike::PEParser::Test
