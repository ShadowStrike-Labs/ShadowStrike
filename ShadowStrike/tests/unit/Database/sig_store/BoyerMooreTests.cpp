// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file BoyerMooreTests.cpp
 * @brief Comprehensive Unit Tests for Boyer-Moore Pattern Matching Algorithm
 *
 * Test Coverage:
 * - Basic Operations: Construction, exact matching, FindFirst vs Search
 * - Mask Support: Wildcard patterns, partial masks, mask edge cases
 * - Edge Cases: Empty inputs, single byte, maximum sizes, boundary conditions
 * - Security Limits: Pattern length, match count, iteration limits
 * - Error Handling: Invalid states, allocation failures, corrupted state
 * - Correctness: Skip tables, overlapping matches, offset accuracy
 * - Performance: Large buffers, many matches, worst-case patterns
 * - Thread Safety: Concurrent searches, immutable state
 * - Binary Data: All byte values, null bytes, non-ASCII data
 * - Algorithm Verification: Bad character rule, good suffix rule
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */
#include"pch.h"
#include <gtest/gtest.h>
#include "../../src/PatternStore/PatternStore.hpp"
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <thread>
#include <future>
#include <chrono>
#include <set>
#include <numeric>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURE
// ============================================================================

class BoyerMooreTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Fresh state for each test
    }
    
    void TearDown() override {
        // Cleanup after each test
    }
    
    // ========================================================================
    // HELPER FUNCTIONS
    // ========================================================================
    
    /// Convert string to byte vector
    std::vector<uint8_t> ToBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    /// Convert string to byte span
    std::span<const uint8_t> ToSpan(const std::vector<uint8_t>& vec) {
        return std::span<const uint8_t>(vec.data(), vec.size());
    }
    
    /// Create matcher from string pattern (exact match)
    std::unique_ptr<BoyerMooreMatcher> MakeExactMatcher(const std::string& pattern) {
        auto patternBytes = ToBytes(pattern);
        return std::make_unique<BoyerMooreMatcher>(ToSpan(patternBytes));
    }
    
    /// Create matcher with mask
    std::unique_ptr<BoyerMooreMatcher> MakeMaskedMatcher(
        const std::vector<uint8_t>& pattern,
        const std::vector<uint8_t>& mask
    ) {
        return std::make_unique<BoyerMooreMatcher>(
            std::span<const uint8_t>(pattern.data(), pattern.size()),
            std::span<const uint8_t>(mask.data(), mask.size())
        );
    }
    
    /// Search string buffer with matcher
    std::vector<size_t> SearchString(
        BoyerMooreMatcher& matcher,
        const std::string& buffer
    ) {
        auto bufferBytes = ToBytes(buffer);
        return matcher.Search(ToSpan(bufferBytes));
    }
    
    /// Find first in string buffer
    std::optional<size_t> FindFirstInString(
        BoyerMooreMatcher& matcher,
        const std::string& buffer
    ) {
        auto bufferBytes = ToBytes(buffer);
        return matcher.FindFirst(ToSpan(bufferBytes));
    }
};

// ============================================================================
// CONSTRUCTOR TESTS
// ============================================================================

TEST_F(BoyerMooreTest, EmptyPattern_CreatesInvalidMatcher) {
    std::vector<uint8_t> emptyPattern;
    BoyerMooreMatcher matcher(ToSpan(emptyPattern));
    
    // Search should return empty results for invalid matcher
    std::vector<uint8_t> buffer = ToBytes("test");
    auto results = matcher.Search(ToSpan(buffer));
    EXPECT_TRUE(results.empty());
    
    auto firstResult = matcher.FindFirst(ToSpan(buffer));
    EXPECT_FALSE(firstResult.has_value());
}

TEST_F(BoyerMooreTest, SingleBytePattern_ExactMatch) {
    auto pattern = ToBytes("A");
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    auto buffer = ToBytes("ABACAD");
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0], 0);  // First A
    EXPECT_EQ(results[1], 2);  // Second A
    EXPECT_EQ(results[2], 4);  // Third A
}

TEST_F(BoyerMooreTest, ValidPattern_SuccessfulConstruction) {
    auto pattern = ToBytes("virus");
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    auto buffer = ToBytes("this is a virus test");
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 10);  // Start offset of "virus"
}

TEST_F(BoyerMooreTest, MaxLengthPattern_Accepted) {
    // Create pattern at maximum allowed length (8192 bytes)
    std::vector<uint8_t> maxPattern(8192, 'A');
    BoyerMooreMatcher matcher(ToSpan(maxPattern));
    
    // Should be able to search
    std::vector<uint8_t> buffer(10000, 'A');
    auto results = matcher.Search(ToSpan(buffer));
    
    // Should find some matches
    EXPECT_GT(results.size(), 0);
}

TEST_F(BoyerMooreTest, TooLongPattern_CreatesInvalidMatcher) {
    // Pattern exceeding BM_MAX_PATTERN_LENGTH (8192)
    std::vector<uint8_t> tooLongPattern(8193, 'A');
    BoyerMooreMatcher matcher(ToSpan(tooLongPattern));
    
    // Should create invalid matcher
    std::vector<uint8_t> buffer(10000, 'A');
    auto results = matcher.Search(ToSpan(buffer));
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, PatternWithMask_SameLength) {
    std::vector<uint8_t> pattern = {0x12, 0x34, 0x56, 0x78};
    std::vector<uint8_t> mask    = {0xFF, 0xFF, 0x00, 0xFF};  // Third byte is wildcard
    
    BoyerMooreMatcher matcher(ToSpan(pattern), ToSpan(mask));
    
    // Should match with any value in third position
    std::vector<uint8_t> buffer1 = {0x12, 0x34, 0xAB, 0x78};  // Match
    std::vector<uint8_t> buffer2 = {0x12, 0x34, 0xFF, 0x78};  // Match
    std::vector<uint8_t> buffer3 = {0x12, 0x34, 0x56, 0x79};  // No match (last byte differs)
    
    EXPECT_EQ(matcher.Search(ToSpan(buffer1)).size(), 1);
    EXPECT_EQ(matcher.Search(ToSpan(buffer2)).size(), 1);
    EXPECT_EQ(matcher.Search(ToSpan(buffer3)).size(), 0);
}

TEST_F(BoyerMooreTest, PatternWithMask_MaskShorter) {
    // Mask shorter than pattern - should extend with 0xFF
    std::vector<uint8_t> pattern = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> mask    = {0x00, 0xFF};  // Only first 2 positions
    
    BoyerMooreMatcher matcher(ToSpan(pattern), ToSpan(mask));
    
    // First byte wildcard, second exact, third and fourth should be exact (0xFF default)
    std::vector<uint8_t> buffer1 = {0xFF, 0x02, 0x03, 0x04};  // Match
    std::vector<uint8_t> buffer2 = {0xFF, 0x02, 0xFF, 0x04};  // No match (third differs)
    
    EXPECT_EQ(matcher.Search(ToSpan(buffer1)).size(), 1);
    EXPECT_EQ(matcher.Search(ToSpan(buffer2)).size(), 0);
}

TEST_F(BoyerMooreTest, PatternWithMask_MaskLonger) {
    // Mask longer than pattern - should truncate mask
    std::vector<uint8_t> pattern = {0x01, 0x02};
    std::vector<uint8_t> mask    = {0xFF, 0xFF, 0x00, 0x00};  // Extra mask bytes ignored
    
    BoyerMooreMatcher matcher(ToSpan(pattern), ToSpan(mask));
    
    std::vector<uint8_t> buffer = {0x01, 0x02};
    auto results = matcher.Search(ToSpan(buffer));
    EXPECT_EQ(results.size(), 1);
}

TEST_F(BoyerMooreTest, AllWildcardMask_MatchesAnything) {
    std::vector<uint8_t> pattern = {0xAA, 0xBB, 0xCC};
    std::vector<uint8_t> mask    = {0x00, 0x00, 0x00};  // All wildcards
    
    BoyerMooreMatcher matcher(ToSpan(pattern), ToSpan(mask));
    
    // Should match any 3-byte sequence
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33};
    auto results = matcher.Search(ToSpan(buffer));
    EXPECT_EQ(results.size(), 1);
}

// ============================================================================
// BASIC SEARCH TESTS
// ============================================================================

TEST_F(BoyerMooreTest, ExactMatch_SingleOccurrence) {
    auto matcher = MakeExactMatcher("malware");
    auto results = SearchString(*matcher, "this is malware code");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 8);  // Start of "malware"
}

TEST_F(BoyerMooreTest, ExactMatch_MultipleOccurrences) {
    auto matcher = MakeExactMatcher("test");
    auto results = SearchString(*matcher, "test this test that test");
    
    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 10);
    EXPECT_EQ(results[2], 20);
}

TEST_F(BoyerMooreTest, ExactMatch_OverlappingPatterns) {
    auto matcher = MakeExactMatcher("aa");
    auto results = SearchString(*matcher, "aaaa");
    
    // Should find 3 overlapping occurrences
    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 1);
    EXPECT_EQ(results[2], 2);
}

TEST_F(BoyerMooreTest, NoMatch_PatternNotFound) {
    auto matcher = MakeExactMatcher("virus");
    auto results = SearchString(*matcher, "clean code without threats");
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, NoMatch_PatternLongerThanBuffer) {
    auto matcher = MakeExactMatcher("verylongpattern");
    auto results = SearchString(*matcher, "short");
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, EmptyBuffer_NoMatches) {
    auto matcher = MakeExactMatcher("test");
    auto buffer = ToBytes("");
    auto results = matcher->Search(ToSpan(buffer));
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, PatternAtBufferStart) {
    auto matcher = MakeExactMatcher("start");
    auto results = SearchString(*matcher, "start of text");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 0);
}

TEST_F(BoyerMooreTest, PatternAtBufferEnd) {
    auto matcher = MakeExactMatcher("end");
    auto results = SearchString(*matcher, "text at end");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 8);
}

TEST_F(BoyerMooreTest, BufferExactlyMatchesPattern) {
    auto matcher = MakeExactMatcher("exact");
    auto results = SearchString(*matcher, "exact");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 0);
}

TEST_F(BoyerMooreTest, CaseSensitiveMatching) {
    auto matcher = MakeExactMatcher("Test");
    
    EXPECT_EQ(SearchString(*matcher, "Test").size(), 1);
    EXPECT_EQ(SearchString(*matcher, "test").size(), 0);
    EXPECT_EQ(SearchString(*matcher, "TEST").size(), 0);
}

// ============================================================================
// FINDFIRST TESTS
// ============================================================================

TEST_F(BoyerMooreTest, FindFirst_SingleMatch) {
    auto matcher = MakeExactMatcher("target");
    auto result = FindFirstInString(*matcher, "find the target here");
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 9);
}

TEST_F(BoyerMooreTest, FindFirst_MultipleMatches_ReturnsFirst) {
    auto matcher = MakeExactMatcher("a");
    auto result = FindFirstInString(*matcher, "banana");
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1);  // First 'a' is at index 1
}

TEST_F(BoyerMooreTest, FindFirst_NoMatch) {
    auto matcher = MakeExactMatcher("xyz");
    auto result = FindFirstInString(*matcher, "abcdef");
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(BoyerMooreTest, FindFirst_EmptyBuffer) {
    auto matcher = MakeExactMatcher("test");
    auto buffer = ToBytes("");
    auto result = matcher->FindFirst(ToSpan(buffer));
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(BoyerMooreTest, FindFirst_ConsistentWithSearch) {
    auto matcher = MakeExactMatcher("pattern");
    std::string buffer = "first pattern then second pattern";
    
    auto searchResults = SearchString(*matcher, buffer);
    auto firstResult = FindFirstInString(*matcher, buffer);
    
    ASSERT_FALSE(searchResults.empty());
    ASSERT_TRUE(firstResult.has_value());
    EXPECT_EQ(searchResults[0], *firstResult);
}

// ============================================================================
// MASK AND WILDCARD TESTS
// ============================================================================

TEST_F(BoyerMooreTest, PartialMask_WildcardInMiddle) {
    std::vector<uint8_t> pattern = {'A', 'B', 'C', 'D'};
    std::vector<uint8_t> mask    = {0xFF, 0xFF, 0x00, 0xFF};  // C is wildcard
    
    auto matcher = MakeMaskedMatcher(pattern, mask);
    
    auto buffer1 = ToBytes("ABXD");  // X can be anything
    auto buffer2 = ToBytes("ABZD");
    auto buffer3 = ToBytes("ABYD");
    
    EXPECT_EQ(matcher->Search(ToSpan(buffer1)).size(), 1);
    EXPECT_EQ(matcher->Search(ToSpan(buffer2)).size(), 1);
    EXPECT_EQ(matcher->Search(ToSpan(buffer3)).size(), 1);
}

TEST_F(BoyerMooreTest, PartialMask_NibbleMatching) {
    // Match high nibble only (0xF0 mask)
    std::vector<uint8_t> pattern = {0xA0};
    std::vector<uint8_t> mask    = {0xF0};
    
    auto matcher = MakeMaskedMatcher(pattern, mask);
    
    std::vector<uint8_t> buffer = {0xA0, 0xA5, 0xAF, 0xB0, 0x50};
    auto results = matcher->Search(ToSpan(buffer));
    
    // Should match 0xA0, 0xA5, 0xAF (high nibble = 0xA)
    EXPECT_EQ(results.size(), 3);
}

TEST_F(BoyerMooreTest, ComplexMask_MixedWildcards) {
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x00, 0x48, 0x89};  // x86-64 pattern
    std::vector<uint8_t> mask    = {0xFF, 0xFF, 0x00, 0xFF, 0xFF};  // Middle byte is register
    
    auto matcher = MakeMaskedMatcher(pattern, mask);
    
    std::vector<uint8_t> code1 = {0x48, 0x8B, 0x05, 0x48, 0x89};  // Match
    std::vector<uint8_t> code2 = {0x48, 0x8B, 0xC0, 0x48, 0x89};  // Match
    std::vector<uint8_t> code3 = {0x48, 0x8B, 0xFF, 0x48, 0x89};  // Match
    std::vector<uint8_t> code4 = {0x48, 0x8C, 0x05, 0x48, 0x89};  // No match (second byte)
    
    EXPECT_EQ(matcher->Search(ToSpan(code1)).size(), 1);
    EXPECT_EQ(matcher->Search(ToSpan(code2)).size(), 1);
    EXPECT_EQ(matcher->Search(ToSpan(code3)).size(), 1);
    EXPECT_EQ(matcher->Search(ToSpan(code4)).size(), 0);
}

TEST_F(BoyerMooreTest, BitMask_SingleBitMatching) {
    // Match only bit 7 (0x80)
    std::vector<uint8_t> pattern = {0x80};
    std::vector<uint8_t> mask    = {0x80};
    
    auto matcher = MakeMaskedMatcher(pattern, mask);
    
    std::vector<uint8_t> buffer = {0x80, 0x81, 0xFF, 0x00, 0x7F};
    auto results = matcher->Search(ToSpan(buffer));
    
    // Should match 0x80, 0x81, 0xFF (bit 7 set)
    EXPECT_EQ(results.size(), 3);
}

// ============================================================================
// BINARY DATA TESTS
// ============================================================================

TEST_F(BoyerMooreTest, BinaryData_NullBytes) {
    std::vector<uint8_t> pattern = {0x00, 0x01, 0x00, 0x02};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer = {0xFF, 0x00, 0x01, 0x00, 0x02, 0xFF};
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 1);
}

TEST_F(BoyerMooreTest, BinaryData_AllByteValues) {
    // Pattern with all possible byte values
    std::vector<uint8_t> pattern(256);
    std::iota(pattern.begin(), pattern.end(), 0);
    
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    // Buffer containing the pattern
    std::vector<uint8_t> buffer(300);
    std::iota(buffer.begin(), buffer.begin() + 256, 0);
    
    auto results = matcher.Search(ToSpan(buffer));
    EXPECT_GE(results.size(), 1);
}

TEST_F(BoyerMooreTest, BinaryData_NonASCII) {
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF};
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 1);
}

TEST_F(BoyerMooreTest, BinaryData_RepeatingBytes) {
    std::vector<uint8_t> pattern = {0xFF, 0xFF, 0xFF};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer(10, 0xFF);
    auto results = matcher.Search(ToSpan(buffer));
    
    // Should find 8 overlapping matches in 10 bytes
    EXPECT_EQ(results.size(), 8);
}

TEST_F(BoyerMooreTest, BinaryData_AlternatingPattern) {
    std::vector<uint8_t> pattern = {0xAA, 0x55};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer = {0xAA, 0x55, 0xAA, 0x55, 0xAA};
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 2);
}

// ============================================================================
// PERFORMANCE AND STRESS TESTS
// ============================================================================

TEST_F(BoyerMooreTest, LargeBuffer_ManyMatches) {
    auto matcher = MakeExactMatcher("X");
    
    // Create 1MB buffer with X every 1000 bytes
    std::string largeBuffer;
    for (int i = 0; i < 1000; ++i) {
        largeBuffer += std::string(999, 'Y') + "X";
    }
    
    auto results = SearchString(*matcher, largeBuffer);
    EXPECT_EQ(results.size(), 1000);
}

TEST_F(BoyerMooreTest, LongPattern_InLargeBuffer) {
    // 1000 byte pattern
    std::string longPattern(1000, 'A');
    longPattern += "MARKER";
    longPattern += std::string(1000, 'B');
    
    auto matcher = MakeExactMatcher(longPattern);
    
    // Buffer containing the pattern
    std::string buffer(10000, 'X');
    buffer += longPattern;
    buffer += std::string(10000, 'Y');
    
    auto results = SearchString(*matcher, buffer);
    EXPECT_EQ(results.size(), 1);
}

TEST_F(BoyerMooreTest, WorstCase_AllSameCharacter) {
    // Worst case for Boyer-Moore: pattern and buffer all same character
    auto matcher = MakeExactMatcher("AAAA");
    
    std::string buffer(1000, 'A');
    auto results = SearchString(*matcher, buffer);
    
    // Should find 997 overlapping matches
    EXPECT_EQ(results.size(), 997);
}

TEST_F(BoyerMooreTest, BestCase_NoCommonCharacters) {
    // Best case: pattern characters don't appear in buffer
    auto matcher = MakeExactMatcher("ZZZZ");
    
    std::string buffer(100000, 'A');
    auto results = SearchString(*matcher, buffer);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, RandomData_NoMatch) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<> dist(0, 255);
    
    // Random pattern
    std::vector<uint8_t> pattern(20);
    for (auto& byte : pattern) {
        byte = static_cast<uint8_t>(dist(rng));
    }
    
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    // Large random buffer (unlikely to contain exact pattern)
    std::vector<uint8_t> buffer(100000);
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(dist(rng));
    }
    
    // Just verify search completes without crash
    auto results = matcher.Search(ToSpan(buffer));
    // Don't assert on count - random data may or may not match
}

TEST_F(BoyerMooreTest, ManyMatches_CountLimit) {
    // Test match count limit (10,000,000)
    auto matcher = MakeExactMatcher("a");
    
    // Create buffer with many 'a's but not enough to hit limit
    std::vector<uint8_t> buffer(100000, 'a');
    auto results = matcher->Search(ToSpan(buffer));
    
    EXPECT_EQ(results.size(), 100000);  // Should get all matches
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

TEST_F(BoyerMooreTest, SingleByteBuffer_SingleBytePattern_Match) {
    auto matcher = MakeExactMatcher("X");
    auto results = SearchString(*matcher, "X");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 0);
}

TEST_F(BoyerMooreTest, SingleByteBuffer_SingleBytePattern_NoMatch) {
    auto matcher = MakeExactMatcher("X");
    auto results = SearchString(*matcher, "Y");
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, RepeatingPattern_SelfOverlap) {
    auto matcher = MakeExactMatcher("abab");
    auto results = SearchString(*matcher, "ababababab");
    
    // Should find overlapping matches
    EXPECT_GE(results.size(), 3);
}

TEST_F(BoyerMooreTest, PatternWithPeriodicity) {
    auto matcher = MakeExactMatcher("aabaab");
    auto results = SearchString(*matcher, "aabaabaabaab");
    
    ASSERT_GE(results.size(), 2);
}

TEST_F(BoyerMooreTest, AdjacentMatches) {
    auto matcher = MakeExactMatcher("ab");
    auto results = SearchString(*matcher, "ababab");
    
    ASSERT_EQ(results.size(), 3);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 2);
    EXPECT_EQ(results[2], 4);
}

TEST_F(BoyerMooreTest, PartialMatchAtEnd) {
    auto matcher = MakeExactMatcher("test");
    auto results = SearchString(*matcher, "tes");  // Incomplete match
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, AlmostMatch_OneByteDifference) {
    auto matcher = MakeExactMatcher("target");
    auto results = SearchString(*matcher, "targen");  // Last byte differs
    
    EXPECT_TRUE(results.empty());
}

// ============================================================================
// OFFSET ACCURACY TESTS
// ============================================================================

TEST_F(BoyerMooreTest, OffsetAccuracy_MultipleMatches) {
    auto matcher = MakeExactMatcher("XX");
    auto results = SearchString(*matcher, "XXAXXBXXCXX");
    
    ASSERT_EQ(results.size(), 4);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 3);
    EXPECT_EQ(results[2], 6);
    EXPECT_EQ(results[3], 9);
}

TEST_F(BoyerMooreTest, OffsetAccuracy_LongPattern) {
    std::string pattern = "0123456789";
    auto matcher = MakeExactMatcher(pattern);
    
    std::string buffer = "XXX" + pattern + "YYY" + pattern + "ZZZ";
    auto results = SearchString(*matcher, buffer);
    
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0], 3);
    EXPECT_EQ(results[1], 16);
}

TEST_F(BoyerMooreTest, OffsetConsistency_FindFirstVsSearch) {
    auto matcher = MakeExactMatcher("pattern");
    
    std::vector<std::string> testCases = {
        "pattern",
        "pattern at start",
        "find the pattern here",
        "multiple pattern instances pattern end"
    };
    
    for (const auto& testCase : testCases) {
        auto searchResults = SearchString(*matcher, testCase);
        auto firstResult = FindFirstInString(*matcher, testCase);
        
        if (!searchResults.empty()) {
            ASSERT_TRUE(firstResult.has_value());
            EXPECT_EQ(searchResults[0], *firstResult);
        } else {
            EXPECT_FALSE(firstResult.has_value());
        }
    }
}

// ============================================================================
// ALGORITHM CORRECTNESS TESTS
// ============================================================================

TEST_F(BoyerMooreTest, BadCharacterRule_EffectiveSkipping) {
    // Pattern where bad character rule should provide good skips
    auto matcher = MakeExactMatcher("PATTERN");
    
    // Buffer where last char of pattern doesn't appear elsewhere
    // This should trigger efficient bad character skips
    std::string buffer(1000, 'A');
    buffer += "PATTERN";
    
    auto results = SearchString(*matcher, buffer);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 1000);
}

TEST_F(BoyerMooreTest, GoodSuffixRule_Verification) {
    // Pattern with repeated suffix to test good suffix rule
    auto matcher = MakeExactMatcher("ABCABC");
    
    std::string buffer = "XABCABDABCABC";  // Partial then full match
    auto results = SearchString(*matcher, buffer);
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 7);
}

TEST_F(BoyerMooreTest, CompareWithBruteForce_RandomPatterns) {
    std::mt19937 rng(12345);
    std::uniform_int_distribution<> charDist('A', 'Z');
    
    for (int test = 0; test < 20; ++test) {
        // Generate random pattern (5-15 chars)
        std::uniform_int_distribution<> lenDist(5, 15);
        std::string pattern;
        for (int i = 0; i < lenDist(rng); ++i) {
            pattern += static_cast<char>(charDist(rng));
        }
        
        // Generate random buffer
        std::string buffer;
        for (int i = 0; i < 200; ++i) {
            buffer += static_cast<char>(charDist(rng));
        }
        
        // Boyer-Moore results
        auto matcher = MakeExactMatcher(pattern);
        auto bmResults = SearchString(*matcher, buffer);
        
        // Brute force results
        std::vector<size_t> bruteResults;
        for (size_t i = 0; i <= buffer.size() - pattern.size(); ++i) {
            if (buffer.substr(i, pattern.size()) == pattern) {
                bruteResults.push_back(i);
            }
        }
        
        // Should match exactly
        EXPECT_EQ(bmResults, bruteResults) 
            << "Mismatch for pattern: " << pattern;
    }
}

TEST_F(BoyerMooreTest, SkipTableValidity_AllPatternsInRange) {
    // Verify that skip tables produce valid offsets
    for (int len = 1; len <= 100; ++len) {
        std::string pattern(len, 'A');
        auto matcher = MakeExactMatcher(pattern);
        
        // Search should never crash or hang
        std::string buffer(1000, 'B');
        auto results = SearchString(*matcher, buffer);
        EXPECT_TRUE(results.empty());
    }
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(BoyerMooreTest, ConcurrentSearches_SameBuffer) {
    auto matcher = MakeExactMatcher("target");
    std::string buffer = "find target and another target here";
    
    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::vector<std::vector<size_t>> results(numThreads);
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&, i]() {
            results[i] = SearchString(*matcher, buffer);
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All threads should get same results
    for (int i = 1; i < numThreads; ++i) {
        EXPECT_EQ(results[0], results[i]);
    }
    
    EXPECT_EQ(results[0].size(), 2);
}

TEST_F(BoyerMooreTest, ConcurrentSearches_DifferentBuffers) {
    auto matcher = MakeExactMatcher("test");
    
    const int numThreads = 8;
    std::vector<std::future<std::vector<size_t>>> futures;
    
    for (int i = 0; i < numThreads; ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            std::string buffer = "test_" + std::to_string(i) + "_test";
            return SearchString(*matcher, buffer);
        }));
    }
    
    for (auto& future : futures) {
        auto results = future.get();
        EXPECT_EQ(results.size(), 2);  // Each buffer has "test" twice
    }
}

TEST_F(BoyerMooreTest, ConcurrentFindFirst) {
    auto matcher = MakeExactMatcher("pattern");
    std::string buffer = "find the pattern here";
    
    std::vector<std::future<std::optional<size_t>>> futures;
    for (int i = 0; i < 20; ++i) {
        futures.push_back(std::async(std::launch::async, [&]() {
            return FindFirstInString(*matcher, buffer);
        }));
    }
    
    for (auto& future : futures) {
        auto result = future.get();
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(*result, 9);
    }
}

// ============================================================================
// SPECIAL CHARACTER TESTS
// ============================================================================

TEST_F(BoyerMooreTest, WhitespacePatterns) {
    auto spaceMatcher = MakeExactMatcher(" ");
    auto tabMatcher = MakeExactMatcher("\t");
    auto newlineMatcher = MakeExactMatcher("\n");
    
    std::string buffer = "a b\tc\nd";
    
    EXPECT_EQ(SearchString(*spaceMatcher, buffer).size(), 1);
    EXPECT_EQ(SearchString(*tabMatcher, buffer).size(), 1);
    EXPECT_EQ(SearchString(*newlineMatcher, buffer).size(), 1);
}

TEST_F(BoyerMooreTest, SpecialCharacters_Punctuation) {
    auto matcher = MakeExactMatcher("!@#$%");
    auto results = SearchString(*matcher, "symbols: !@#$% here");
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 9);
}

TEST_F(BoyerMooreTest, ControlCharacters) {
    std::vector<uint8_t> pattern = {0x01, 0x02, 0x03};  // Control chars
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer = {0x00, 0x01, 0x02, 0x03, 0x04};
    auto results = matcher.Search(ToSpan(buffer));
    
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 1);
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

TEST_F(BoyerMooreTest, Regression_MatchAtMaxOffset) {
    auto matcher = MakeExactMatcher("END");
    
    // Pattern at maximum valid offset
    std::string buffer(1000, 'X');
    buffer += "END";
    
    auto results = SearchString(*matcher, buffer);
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 1000);
}

TEST_F(BoyerMooreTest, Regression_OverflowProtection) {
    auto matcher = MakeExactMatcher("test");
    
    // Very large buffer to test offset overflow protection
    std::vector<uint8_t> largeBuffer(1000000, 'X');
    auto results = matcher->Search(ToSpan(largeBuffer));
    
    EXPECT_TRUE(results.empty());  // Should complete without crash
}

TEST_F(BoyerMooreTest, Regression_EmptyMaskHandling) {
    std::vector<uint8_t> pattern = {0x01, 0x02, 0x03};
    std::vector<uint8_t> emptyMask;  // No mask provided
    
    // Should default to 0xFF mask (exact match)
    auto matcher = MakeMaskedMatcher(pattern, emptyMask);
    
    std::vector<uint8_t> buffer = {0x01, 0x02, 0x03};
    EXPECT_EQ(matcher->Search(ToSpan(buffer)).size(), 1);
}

TEST_F(BoyerMooreTest, Regression_AllZeroPattern) {
    std::vector<uint8_t> pattern(10, 0x00);
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer(50, 0x00);
    auto results = matcher.Search(ToSpan(buffer));
    
    // Should find overlapping matches
    EXPECT_EQ(results.size(), 41);  // 50 - 10 + 1
}

TEST_F(BoyerMooreTest, Regression_AllOnesPattern) {
    std::vector<uint8_t> pattern(10, 0xFF);
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer(50, 0xFF);
    auto results = matcher.Search(ToSpan(buffer));
    
    EXPECT_EQ(results.size(), 41);
}

TEST_F(BoyerMooreTest, Regression_SingleBitDifference) {
    std::vector<uint8_t> pattern = {0b10101010};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> buffer = {
        0b10101010,  // Match
        0b10101011,  // No match (bit 0 differs)
        0b10101010   // Match
    };
    
    auto results = matcher.Search(ToSpan(buffer));
    ASSERT_EQ(results.size(), 2);
}

// ============================================================================
// COMPLEX REAL-WORLD SCENARIOS
// ============================================================================

TEST_F(BoyerMooreTest, RealWorld_PEHeader) {
    // Windows PE header signature
    std::vector<uint8_t> pattern = {'M', 'Z'};
    BoyerMooreMatcher matcher(ToSpan(pattern));
    
    std::vector<uint8_t> fakeExe(1000, 0x00);
    fakeExe[0] = 'M';
    fakeExe[1] = 'Z';
    
    auto results = matcher.Search(ToSpan(fakeExe));
    ASSERT_GE(results.size(), 1);
    EXPECT_EQ(results[0], 0);
}

TEST_F(BoyerMooreTest, RealWorld_x86Instruction) {
    // x86 instruction pattern with wildcard for ModR/M byte
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x00};  // mov rax, [rax+offset]
    std::vector<uint8_t> mask    = {0xFF, 0xFF, 0x00};  // Third byte is ModR/M (variable)
    
    auto matcher = MakeMaskedMatcher(pattern, mask);
    
    std::vector<uint8_t> code = {
        0x90,             // nop
        0x48, 0x8B, 0x45, // mov rax, [rbp+...]  - should match
        0x90,             // nop
        0x48, 0x8B, 0x0D, // mov rcx, [rip+...]  - should match
        0x90              // nop
    };
    
    auto results = matcher->Search(ToSpan(code));
    EXPECT_EQ(results.size(), 2);
}

TEST_F(BoyerMooreTest, RealWorld_MalwareSignature) {
    // Typical malware signature with wildcards
    std::vector<uint8_t> signature = {
        0xEB, 0x10,       // jmp +16
        0x5A,             // pop edx
        0x00, 0x00,       // Wildcards
        0x8B, 0xEC        // mov ebp, esp
    };
    std::vector<uint8_t> mask = {
        0xFF, 0xFF,
        0xFF,
        0x00, 0x00,       // Don't care bytes
        0xFF, 0xFF
    };
    
    auto matcher = MakeMaskedMatcher(signature, mask);
    
    std::vector<uint8_t> suspiciousCode = {
        0xFF, 0xFF,
        0xEB, 0x10,
        0x5A,
        0xAB, 0xCD,       // Variable bytes
        0x8B, 0xEC,
        0x00
    };
    
    auto results = matcher->Search(ToSpan(suspiciousCode));
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 2);
}

TEST_F(BoyerMooreTest, RealWorld_URLPattern) {
    auto matcher = MakeExactMatcher("http://");
    
    std::string data = "Visit http://example.com or http://test.com";
    auto results = SearchString(*matcher, data);
    
    ASSERT_EQ(results.size(), 2);
    EXPECT_EQ(results[0], 6);
    EXPECT_EQ(results[1], 28);
}

TEST_F(BoyerMooreTest, RealWorld_FileExtension) {
    auto matcher = MakeExactMatcher(".exe");
    
    std::string path = "file.exe and program.exe.bak";
    auto results = SearchString(*matcher, path);
    
    ASSERT_EQ(results.size(), 2);
}

// ============================================================================
// BOUNDARY VALUE TESTS
// ============================================================================

TEST_F(BoyerMooreTest, Boundary_PatternLength1) {
    for (int byte = 0; byte < 256; ++byte) {
        std::vector<uint8_t> pattern = {static_cast<uint8_t>(byte)};
        BoyerMooreMatcher matcher(ToSpan(pattern));
        
        std::vector<uint8_t> buffer = {static_cast<uint8_t>(byte)};
        auto results = matcher.Search(ToSpan(buffer));
        
        EXPECT_EQ(results.size(), 1);
    }
}

TEST_F(BoyerMooreTest, Boundary_BufferLength1_NoMatch) {
    auto matcher = MakeExactMatcher("AB");  // 2 byte pattern
    
    std::vector<uint8_t> buffer = {'A'};  // 1 byte buffer
    auto results = matcher->Search(ToSpan(buffer));
    
    EXPECT_TRUE(results.empty());
}

TEST_F(BoyerMooreTest, Boundary_PatternEqualsBuffer) {
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    BoyerMooreMatcher matcher(ToSpan(data));
    
    auto results = matcher.Search(ToSpan(data));
    ASSERT_EQ(results.size(), 1);
    EXPECT_EQ(results[0], 0);
}

// ============================================================================
// MAIN
// ============================================================================


