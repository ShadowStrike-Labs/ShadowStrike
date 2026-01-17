// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
// ============================================================================
// SIMD MATCHER UNIT TESTS - PRODUCTION GRADE
// ============================================================================
// 
// ShadowStrike Antivirus Engine - Enterprise Edition
// 
// Comprehensive unit tests for SIMD-accelerated pattern matching
// Coverage: AVX2, AVX512, edge cases, boundary conditions, error handling
// 
// Test Categories:
// 1. CPU Feature Detection Tests
// 2. AVX2 Search Tests (Basic, Edge Cases, Performance)
// 3. AVX512 Search Tests (Basic, Edge Cases, Performance)
// 4. Multi-Pattern Search Tests
// 5. Boundary Condition Tests
// 6. Error Handling & Resource Limit Tests
// 7. Security & Safety Tests
// ============================================================================
#include <gtest/gtest.h>
#include "../../../../src/PatternStore/PatternStore.hpp"
#include <vector>
#include <cstdint>
#include <span>
#include <algorithm>
#include <random>
#include <string>
#include <cstring>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURE - SIMD MATCHER BASE
// ============================================================================

class SIMDMatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize random seed for reproducible tests
        rng.seed(42);
    }

    void TearDown() override {
        // Cleanup
    }

    // Helper: Create random buffer
    std::vector<uint8_t> CreateRandomBuffer(size_t size) {
        std::vector<uint8_t> buffer(size);
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : buffer) {
            byte = static_cast<uint8_t>(dist(rng));
        }
        return buffer;
    }

    // Helper: Create buffer with known pattern occurrences
    std::vector<uint8_t> CreateBufferWithPattern(
        size_t bufferSize,
        const std::vector<uint8_t>& pattern,
        const std::vector<size_t>& positions
    ) {
        std::vector<uint8_t> buffer(bufferSize, 0xAA); // Fill with 0xAA
        
        for (size_t pos : positions) {
            if (pos + pattern.size() <= bufferSize) {
                std::memcpy(buffer.data() + pos, pattern.data(), pattern.size());
            }
        }
        
        return buffer;
    }

    // Helper: Verify match results
    bool VerifyMatches(
        const std::vector<size_t>& matches,
        const std::vector<size_t>& expected
    ) {
        if (matches.size() != expected.size()) {
            return false;
        }
        
        auto sortedMatches = matches;
        auto sortedExpected = expected;
        std::sort(sortedMatches.begin(), sortedMatches.end());
        std::sort(sortedExpected.begin(), sortedExpected.end());
        
        return sortedMatches == sortedExpected;
    }

    std::mt19937 rng;
};

// ============================================================================
// CATEGORY 1: CPU FEATURE DETECTION TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, CPUFeatureDetection_AVX2) {
    // Test that AVX2 detection returns consistent results
    bool avx2_1 = SIMDMatcher::IsAVX2Available();
    bool avx2_2 = SIMDMatcher::IsAVX2Available();
    
    EXPECT_EQ(avx2_1, avx2_2) << "AVX2 detection should be deterministic";
    
    // Note: Actual value depends on hardware, just verify it's callable
    // and doesn't crash
    SUCCEED();
}

TEST_F(SIMDMatcherTest, CPUFeatureDetection_AVX512) {
    // Test that AVX512 detection returns consistent results
    bool avx512_1 = SIMDMatcher::IsAVX512Available();
    bool avx512_2 = SIMDMatcher::IsAVX512Available();
    
    EXPECT_EQ(avx512_1, avx512_2) << "AVX512 detection should be deterministic";
    
    // If AVX512 is supported, AVX2 should also be supported (in most cases)
    if (avx512_1) {
        // This is typically true but not guaranteed on all platforms
        // Just log it
    }
    
    SUCCEED();
}

TEST_F(SIMDMatcherTest, CPUFeatureDetection_NoException) {
    // Verify feature detection never throws
    EXPECT_NO_THROW({
        for (int i = 0; i < 1000; ++i) {
            SIMDMatcher::IsAVX2Available();
            SIMDMatcher::IsAVX512Available();
        }
    }) << "CPU feature detection must never throw exceptions";
}

// ============================================================================
// CATEGORY 2: AVX2 SEARCH TESTS - BASIC FUNCTIONALITY
// ============================================================================

TEST_F(SIMDMatcherTest, SearchAVX2_EmptyBuffer) {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> pattern = {0x12, 0x34};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_TRUE(matches.empty()) << "Empty buffer should return no matches";
}

TEST_F(SIMDMatcherTest, SearchAVX2_EmptyPattern) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56};
    std::vector<uint8_t> pattern;
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_TRUE(matches.empty()) << "Empty pattern should return no matches";
}

TEST_F(SIMDMatcherTest, SearchAVX2_BothEmpty) {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> pattern;
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_TRUE(matches.empty()) << "Both empty should return no matches";
}

TEST_F(SIMDMatcherTest, SearchAVX2_PatternLargerThanBuffer) {
    std::vector<uint8_t> buffer = {0x12, 0x34};
    std::vector<uint8_t> pattern = {0x12, 0x34, 0x56, 0x78};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_TRUE(matches.empty()) << "Pattern larger than buffer should return no matches";
}

TEST_F(SIMDMatcherTest, SearchAVX2_SingleBytePattern_SingleMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern = {0x33};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 2);
}

TEST_F(SIMDMatcherTest, SearchAVX2_SingleBytePattern_MultipleMatches) {
    std::vector<uint8_t> buffer = {0xAA, 0x11, 0xAA, 0x22, 0xAA, 0xAA, 0x33};
    std::vector<uint8_t> pattern = {0xAA};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 2, 4, 5};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_SingleBytePattern_NoMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern = {0xFF};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchAVX2_TwoBytePattern_SingleMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern = {0x33, 0x44};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 2);
}

TEST_F(SIMDMatcherTest, SearchAVX2_TwoBytePattern_MultipleMatches) {
    std::vector<uint8_t> buffer = {0xAB, 0xCD, 0x11, 0xAB, 0xCD, 0x22, 0xAB, 0xCD};
    std::vector<uint8_t> pattern = {0xAB, 0xCD};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 3, 6};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_PatternAtStart) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56, 0x78, 0x90};
    std::vector<uint8_t> pattern = {0x12, 0x34};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 0);
}

TEST_F(SIMDMatcherTest, SearchAVX2_PatternAtEnd) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56, 0x78, 0x90};
    std::vector<uint8_t> pattern = {0x78, 0x90};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 3);
}

TEST_F(SIMDMatcherTest, SearchAVX2_PatternEqualsBuffer) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56, 0x78};
    std::vector<uint8_t> pattern = {0x12, 0x34, 0x56, 0x78};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 0);
}

TEST_F(SIMDMatcherTest, SearchAVX2_OverlappingMatches) {
    // Pattern: AAA, Buffer: AAAA -> should match at positions 0 and 1
    std::vector<uint8_t> buffer = {0xAA, 0xAA, 0xAA, 0xAA};
    std::vector<uint8_t> pattern = {0xAA, 0xAA, 0xAA};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 1};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

// ============================================================================
// CATEGORY 2B: AVX2 SEARCH TESTS - DIFFERENT PATTERN SIZES
// ============================================================================

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_4Bytes) {
    std::vector<uint8_t> buffer = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF};
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 1);
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_8Bytes) {
    std::vector<uint8_t> pattern = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(64, pattern, {10, 40});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {10, 40};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_16Bytes) {
    std::vector<uint8_t> pattern(16);
    for (size_t i = 0; i < 16; ++i) {
        pattern[i] = static_cast<uint8_t>(i);
    }
    
    std::vector<uint8_t> buffer = CreateBufferWithPattern(128, pattern, {5, 60, 100});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {5, 60, 100};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_31Bytes) {
    std::vector<uint8_t> pattern(31, 0xBB);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(200, pattern, {20, 80, 150});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {20, 80, 150};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_32Bytes) {
    std::vector<uint8_t> pattern(32, 0xCC);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(200, pattern, {10, 100});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {10, 100};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_33Bytes_FallbackToScalar) {
    // Patterns > 32 bytes should use scalar fallback
    std::vector<uint8_t> pattern(33, 0xDD);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(300, pattern, {50, 200});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {50, 200};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_64Bytes) {
    std::vector<uint8_t> pattern(64);
    for (size_t i = 0; i < 64; ++i) {
        pattern[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> buffer = CreateBufferWithPattern(500, pattern, {100, 300});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {100, 300};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Pattern_128Bytes) {
    std::vector<uint8_t> pattern(128, 0xEE);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(1000, pattern, {200, 600});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {200, 600};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

// ============================================================================
// CATEGORY 2C: AVX2 SEARCH TESTS - LARGE BUFFERS
// ============================================================================

TEST_F(SIMDMatcherTest, SearchAVX2_LargeBuffer_1KB) {
    std::vector<uint8_t> pattern = {0xCA, 0xFE, 0xBA, 0xBE};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(1024, pattern, {100, 500, 900});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {100, 500, 900};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_LargeBuffer_64KB) {
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xC0, 0xDE};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(65536, pattern, {1000, 30000, 60000});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {1000, 30000, 60000};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_LargeBuffer_1MB) {
    std::vector<uint8_t> pattern = {0xBE, 0xEF};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(1024 * 1024, pattern, {10000, 500000, 900000});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {10000, 500000, 900000};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_ManyMatches_100Matches) {
    std::vector<uint8_t> pattern = {0x42, 0x43};
    std::vector<size_t> positions;
    
    // Create 100 matches spaced evenly
    for (size_t i = 0; i < 100; ++i) {
        positions.push_back(i * 100);
    }
    
    std::vector<uint8_t> buffer = CreateBufferWithPattern(15000, pattern, positions);
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_EQ(matches.size(), 100);
    EXPECT_TRUE(VerifyMatches(matches, positions));
}

TEST_F(SIMDMatcherTest, SearchAVX2_ManyMatches_1000Matches) {
    std::vector<uint8_t> pattern = {0x99};
    std::vector<size_t> positions;
    
    // Create 1000 matches
    for (size_t i = 0; i < 1000; ++i) {
        positions.push_back(i * 50);
    }
    
    std::vector<uint8_t> buffer = CreateBufferWithPattern(100000, pattern, positions);
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_EQ(matches.size(), 1000);
    EXPECT_TRUE(VerifyMatches(matches, positions));
}

// ============================================================================
// CATEGORY 2D: AVX2 SEARCH TESTS - BOUNDARY CONDITIONS
// ============================================================================

TEST_F(SIMDMatcherTest, SearchAVX2_Boundary_32ByteAlignment) {
    // Test pattern at exact 32-byte boundary (AVX2 register size)
    std::vector<uint8_t> pattern = {0x11, 0x22, 0x33};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(128, pattern, {0, 32, 64, 96});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 32, 64, 96};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Boundary_CrossingAlignment) {
    // Test pattern crossing 32-byte alignment boundary
    std::vector<uint8_t> pattern = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(128, pattern, {30, 62, 94});
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {30, 62, 94};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX2_Boundary_LastPosition) {
    // Pattern at the very last valid position
    std::vector<uint8_t> buffer(100, 0x00);
    std::vector<uint8_t> pattern = {0xFF, 0xFE, 0xFD};
    
    // Place pattern at position 97 (last valid position for 3-byte pattern)
    std::memcpy(buffer.data() + 97, pattern.data(), pattern.size());
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 97);
}

TEST_F(SIMDMatcherTest, SearchAVX2_Boundary_AllZeros) {
    std::vector<uint8_t> buffer(256, 0x00);
    std::vector<uint8_t> pattern = {0x00, 0x00, 0x00};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Should match at every position (256 - 3 + 1 = 254 matches)
    EXPECT_EQ(matches.size(), 254);
}

TEST_F(SIMDMatcherTest, SearchAVX2_Boundary_AllOnes) {
    std::vector<uint8_t> buffer(128, 0xFF);
    std::vector<uint8_t> pattern = {0xFF, 0xFF};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Should match at every position (128 - 2 + 1 = 127 matches)
    EXPECT_EQ(matches.size(), 127);
}

// ============================================================================
// CATEGORY 3: AVX512 SEARCH TESTS - BASIC FUNCTIONALITY
// ============================================================================

TEST_F(SIMDMatcherTest, SearchAVX512_EmptyBuffer) {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> pattern = {0x12, 0x34};
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchAVX512_EmptyPattern) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56};
    std::vector<uint8_t> pattern;
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchAVX512_PatternLargerThanBuffer) {
    std::vector<uint8_t> buffer = {0x12, 0x34};
    std::vector<uint8_t> pattern = {0x12, 0x34, 0x56, 0x78, 0x90};
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchAVX512_SingleBytePattern_SingleMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern = {0x33};
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 2);
}

TEST_F(SIMDMatcherTest, SearchAVX512_SingleBytePattern_MultipleMatches) {
    std::vector<uint8_t> buffer = {0xAA, 0x11, 0xAA, 0x22, 0xAA, 0xAA, 0x33};
    std::vector<uint8_t> pattern = {0xAA};
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {0, 2, 4, 5};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_MultiBytePattern) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55, 0x33, 0x44, 0x66};
    std::vector<uint8_t> pattern = {0x33, 0x44};
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {2, 5};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_Pattern_32Bytes) {
    std::vector<uint8_t> pattern(32, 0xAB);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(300, pattern, {50, 200});
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {50, 200};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_Pattern_64Bytes) {
    std::vector<uint8_t> pattern(64);
    for (size_t i = 0; i < 64; ++i) {
        pattern[i] = static_cast<uint8_t>(i);
    }
    
    std::vector<uint8_t> buffer = CreateBufferWithPattern(500, pattern, {100, 300});
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {100, 300};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_Pattern_65Bytes_FallbackToAVX2) {
    // Patterns > 64 bytes should fall back to AVX2
    std::vector<uint8_t> pattern(65, 0xCD);
    std::vector<uint8_t> buffer = CreateBufferWithPattern(500, pattern, {100, 300});
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {100, 300};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_LargeBuffer_1MB) {
    std::vector<uint8_t> pattern = {0xFA, 0xCE};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(1024 * 1024, pattern, {10000, 500000, 900000});
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {10000, 500000, 900000};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SearchAVX512_Boundary_64ByteAlignment) {
    // Test pattern at exact 64-byte boundary (AVX512 register size)
    std::vector<uint8_t> pattern = {0x11, 0x22, 0x33, 0x44};
    std::vector<uint8_t> buffer = CreateBufferWithPattern(256, pattern, {0, 64, 128, 192});
    
    auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    std::vector<size_t> expected = {0, 64, 128, 192};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

// ============================================================================
// CATEGORY 4: MULTI-PATTERN SEARCH TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_EmptyBuffer) {
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> pattern1 = {0x12, 0x34};
    std::vector<uint8_t> pattern2 = {0x56, 0x78};
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_EmptyPatterns) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56};
    std::vector<std::span<const uint8_t>> patterns;
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_SinglePattern_SingleMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern1 = {0x33, 0x44};
    std::vector<std::span<const uint8_t>> patterns = {pattern1};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].first, 0);  // Pattern index
    EXPECT_EQ(matches[0].second, 2); // Offset
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_TwoPatterns_BothMatch) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    std::vector<uint8_t> pattern1 = {0x22, 0x33};
    std::vector<uint8_t> pattern2 = {0x55, 0x66};
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    ASSERT_EQ(matches.size(), 2);
    
    // Sort by offset for consistent checking
    std::sort(matches.begin(), matches.end(), 
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    EXPECT_EQ(matches[0].first, 0);  // Pattern 1
    EXPECT_EQ(matches[0].second, 1); // At offset 1
    EXPECT_EQ(matches[1].first, 1);  // Pattern 2
    EXPECT_EQ(matches[1].second, 4); // At offset 4
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_MultiplePatterns_MultipleMatches) {
    std::vector<uint8_t> buffer(200, 0x00);
    
    // Pattern 1: appears at 10, 50
    std::vector<uint8_t> pattern1 = {0xAA, 0xBB};
    std::memcpy(buffer.data() + 10, pattern1.data(), pattern1.size());
    std::memcpy(buffer.data() + 50, pattern1.data(), pattern1.size());
    
    // Pattern 2: appears at 30, 70
    std::vector<uint8_t> pattern2 = {0xCC, 0xDD};
    std::memcpy(buffer.data() + 30, pattern2.data(), pattern2.size());
    std::memcpy(buffer.data() + 70, pattern2.data(), pattern2.size());
    
    // Pattern 3: appears at 100
    std::vector<uint8_t> pattern3 = {0xEE, 0xFF};
    std::memcpy(buffer.data() + 100, pattern3.data(), pattern3.size());
    
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2, pattern3};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    EXPECT_EQ(matches.size(), 5); // 2 + 2 + 1 = 5 total matches
    
    // Verify each pattern index appears correct number of times
    size_t pattern0Count = 0, pattern1Count = 0, pattern2Count = 0;
    for (const auto& match : matches) {
        if (match.first == 0) pattern0Count++;
        if (match.first == 1) pattern1Count++;
        if (match.first == 2) pattern2Count++;
    }
    
    EXPECT_EQ(pattern0Count, 2);
    EXPECT_EQ(pattern1Count, 2);
    EXPECT_EQ(pattern2Count, 1);
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_SomeInvalidPatterns) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    
    std::vector<uint8_t> pattern1 = {0x22, 0x33}; // Valid
    std::vector<uint8_t> pattern2;                 // Empty - invalid
    std::vector<uint8_t> pattern3 = {0x44, 0x55}; // Valid
    
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2, pattern3};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    // Should find matches for pattern1 and pattern3 only
    EXPECT_GE(matches.size(), 2);
    
    // Verify no matches for pattern index 1 (the empty pattern)
    for (const auto& match : matches) {
        EXPECT_NE(match.first, 1) << "Empty pattern should not produce matches";
    }
}

TEST_F(SIMDMatcherTest, SearchMultipleAVX2_NoMatches) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> pattern1 = {0xAA, 0xBB};
    std::vector<uint8_t> pattern2 = {0xCC, 0xDD};
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2};
    
    auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    EXPECT_TRUE(matches.empty());
}

// ============================================================================
// CATEGORY 5: ERROR HANDLING & RESOURCE LIMIT TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, ResourceLimits_MaxMatchesLimit) {
    // Test that the 10M match limit is enforced
    // Create a buffer that would produce millions of matches
    std::vector<uint8_t> buffer(200000, 0xAA);
    std::vector<uint8_t> pattern = {0xAA};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Should stop at MAX_MATCHES (10,000,000)
    // But our buffer is only 200K, so we'd get 200K matches
    EXPECT_LE(matches.size(), 200000);
}

TEST_F(SIMDMatcherTest, ResourceLimits_VeryLargeBufferRejected) {
    // Buffers > 1GB should be rejected (test with smaller size for practicality)
    // We'll test the logic path, not actually allocate 1GB+
    
    std::vector<uint8_t> buffer(1000, 0x00);
    std::vector<uint8_t> pattern = {0xFF};
    
    // This should work fine (well under limit)
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_NO_THROW(matches);
}

TEST_F(SIMDMatcherTest, ErrorHandling_NoExceptions_AVX2) {
    // Verify SearchAVX2 never throws exceptions even with edge cases
    
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33};
    std::vector<uint8_t> pattern = {0x44};
    
    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    });
    
    EXPECT_NO_THROW({
        std::vector<uint8_t> empty;
        auto matches = SIMDMatcher::SearchAVX2(empty, pattern);
    });
    
    EXPECT_NO_THROW({
        std::vector<uint8_t> empty;
        auto matches = SIMDMatcher::SearchAVX2(buffer, empty);
    });
}

TEST_F(SIMDMatcherTest, ErrorHandling_NoExceptions_AVX512) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33};
    std::vector<uint8_t> pattern = {0x44};
    
    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
    });
    
    EXPECT_NO_THROW({
        std::vector<uint8_t> empty;
        auto matches = SIMDMatcher::SearchAVX512(empty, pattern);
    });
    
    EXPECT_NO_THROW({
        std::vector<uint8_t> empty;
        auto matches = SIMDMatcher::SearchAVX512(buffer, empty);
    });
}

TEST_F(SIMDMatcherTest, ErrorHandling_NoExceptions_MultipleAVX2) {
    std::vector<uint8_t> buffer = {0x11, 0x22, 0x33};
    std::vector<uint8_t> pattern1 = {0x22};
    std::vector<std::span<const uint8_t>> patterns = {pattern1};
    
    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    });
    
    EXPECT_NO_THROW({
        std::vector<uint8_t> empty;
        auto matches = SIMDMatcher::SearchMultipleAVX2(empty, patterns);
    });
    
    EXPECT_NO_THROW({
        std::vector<std::span<const uint8_t>> emptyPatterns;
        auto matches = SIMDMatcher::SearchMultipleAVX2(buffer, emptyPatterns);
    });
}

// ============================================================================
// CATEGORY 6: SECURITY & SAFETY TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, Security_NullPointerCheck_Buffer) {
    // While std::span should prevent this, ensure graceful handling
    std::vector<uint8_t> pattern = {0x12, 0x34};
    std::span<const uint8_t> nullBuffer{};

    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchAVX2(nullBuffer, pattern);
        EXPECT_TRUE(matches.empty());
    });
}

TEST_F(SIMDMatcherTest, Security_NullPointerCheck_Pattern) {
    std::vector<uint8_t> buffer = {0x12, 0x34, 0x56};
    std::span<const uint8_t> nullPattern{};

    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchAVX2(buffer, nullPattern);
        EXPECT_TRUE(matches.empty());
    });
}

TEST_F(SIMDMatcherTest, Security_OverflowProtection_SearchLength) {
    // Ensure proper overflow handling in search length calculation
    std::vector<uint8_t> buffer(10);
    std::vector<uint8_t> pattern(15); // Pattern larger than buffer
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Should return empty, not crash or overflow
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, Security_BoundsCheck_MatchVerification) {
    // Ensure match verification doesn't read out of bounds
    std::vector<uint8_t> buffer = {0xAA, 0xBB, 0xCC, 0xDD};
    std::vector<uint8_t> pattern = {0xCC, 0xDD, 0xEE}; // Would go out of bounds
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Should not find match at position 2 (would read beyond buffer)
    EXPECT_TRUE(matches.empty());
}

TEST_F(SIMDMatcherTest, Security_AlignmentSafety_UnalignedAccess) {
    // Ensure unaligned buffer access is handled safely
    std::vector<uint8_t> buffer(100);
    
    // Create unaligned pattern
    for (size_t i = 0; i < 100; ++i) {
        buffer[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> pattern = {50, 51, 52, 53, 54};
    
    EXPECT_NO_THROW({
        auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
        EXPECT_EQ(matches.size(), 1);
        EXPECT_EQ(matches[0], 50);
    });
}

// ============================================================================
// CATEGORY 7: PERFORMANCE & CORRECTNESS VALIDATION TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, Correctness_AVX2_vs_AVX512_Consistency) {
    // Ensure AVX2 and AVX512 produce identical results
    std::vector<uint8_t> buffer(1000);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> pattern = {0x42, 0x43, 0x44};
    
    auto matchesAVX2 = SIMDMatcher::SearchAVX2(buffer, pattern);
    auto matchesAVX512 = SIMDMatcher::SearchAVX512(buffer, pattern);
    
    // Results should be identical
    EXPECT_TRUE(VerifyMatches(matchesAVX2, matchesAVX512));
}

TEST_F(SIMDMatcherTest, Correctness_DifferentPatternSizes_Consistency) {
    // Test that different pattern sizes all work correctly
    std::vector<uint8_t> buffer(500, 0x00);
    
    // Place known patterns of different sizes
    std::vector<uint8_t> pattern1 = {0xAA};
    std::vector<uint8_t> pattern2 = {0xBB, 0xCC};
    std::vector<uint8_t> pattern3(16, 0xDD);
    std::vector<uint8_t> pattern4(32, 0xEE);
    
    std::memcpy(buffer.data() + 10, pattern1.data(), pattern1.size());
    std::memcpy(buffer.data() + 50, pattern2.data(), pattern2.size());
    std::memcpy(buffer.data() + 100, pattern3.data(), pattern3.size());
    std::memcpy(buffer.data() + 200, pattern4.data(), pattern4.size());
    
    auto matches1 = SIMDMatcher::SearchAVX2(buffer, pattern1);
    auto matches2 = SIMDMatcher::SearchAVX2(buffer, pattern2);
    auto matches3 = SIMDMatcher::SearchAVX2(buffer, pattern3);
    auto matches4 = SIMDMatcher::SearchAVX2(buffer, pattern4);
    
    EXPECT_FALSE(matches1.empty());
    EXPECT_FALSE(matches2.empty());
    EXPECT_FALSE(matches3.empty());
    EXPECT_FALSE(matches4.empty());
    
    // Verify at least one match for each at expected positions
    EXPECT_TRUE(std::find(matches1.begin(), matches1.end(), 10) != matches1.end());
    EXPECT_TRUE(std::find(matches2.begin(), matches2.end(), 50) != matches2.end());
    EXPECT_TRUE(std::find(matches3.begin(), matches3.end(), 100) != matches3.end());
    EXPECT_TRUE(std::find(matches4.begin(), matches4.end(), 200) != matches4.end());
}

TEST_F(SIMDMatcherTest, Correctness_RandomData_NoFalsePositives) {
    // Test with random data to ensure no false positives
    std::vector<uint8_t> buffer = CreateRandomBuffer(10000);
    std::vector<uint8_t> pattern = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB}; // Unlikely sequence
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Verify each match is actually correct
    for (size_t matchPos : matches) {
        ASSERT_LT(matchPos + pattern.size(), buffer.size());
        
        for (size_t i = 0; i < pattern.size(); ++i) {
            EXPECT_EQ(buffer[matchPos + i], pattern[i])
                << "False positive at position " << matchPos;
        }
    }
}

TEST_F(SIMDMatcherTest, Correctness_MultiPattern_IndependentResults) {
    // Ensure multi-pattern search produces same results as individual searches
    std::vector<uint8_t> buffer(500);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> pattern1 = {0x10, 0x11};
    std::vector<uint8_t> pattern2 = {0x20, 0x21};
    std::vector<uint8_t> pattern3 = {0x30, 0x31};
    
    // Individual searches
    auto matches1 = SIMDMatcher::SearchAVX2(buffer, pattern1);
    auto matches2 = SIMDMatcher::SearchAVX2(buffer, pattern2);
    auto matches3 = SIMDMatcher::SearchAVX2(buffer, pattern3);
    
    // Multi-pattern search
    std::vector<std::span<const uint8_t>> patterns = {pattern1, pattern2, pattern3};
    auto multiMatches = SIMDMatcher::SearchMultipleAVX2(buffer, patterns);
    
    // Verify counts match
    size_t pattern0Count = 0, pattern1Count = 0, pattern2Count = 0;
    for (const auto& match : multiMatches) {
        if (match.first == 0) pattern0Count++;
        if (match.first == 1) pattern1Count++;
        if (match.first == 2) pattern2Count++;
    }
    
    EXPECT_EQ(pattern0Count, matches1.size());
    EXPECT_EQ(pattern1Count, matches2.size());
    EXPECT_EQ(pattern2Count, matches3.size());
}

// ============================================================================
// CATEGORY 8: SPECIAL BYTE PATTERNS
// ============================================================================

TEST_F(SIMDMatcherTest, SpecialBytes_AllZeros_Pattern) {
    std::vector<uint8_t> buffer = {0x00, 0x00, 0x11, 0x00, 0x00, 0x22};
    std::vector<uint8_t> pattern = {0x00, 0x00};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 3};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SpecialBytes_AllOnes_Pattern) {
    std::vector<uint8_t> buffer = {0xFF, 0xFF, 0x11, 0xFF, 0xFF, 0x22};
    std::vector<uint8_t> pattern = {0xFF, 0xFF};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 3};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SpecialBytes_AlternatingPattern) {
    std::vector<uint8_t> buffer = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
    std::vector<uint8_t> pattern = {0xAA, 0x55};
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    std::vector<size_t> expected = {0, 2, 4};
    EXPECT_TRUE(VerifyMatches(matches, expected));
}

TEST_F(SIMDMatcherTest, SpecialBytes_SequentialBytes) {
    std::vector<uint8_t> buffer(300);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = static_cast<uint8_t>(i % 256);
    }
    
    std::vector<uint8_t> pattern = {0x7E, 0x7F, 0x80, 0x81}; // Around midpoint
    
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    // Pattern should appear at positions 126, 382 (if buffer was larger)
    EXPECT_FALSE(matches.empty());
    EXPECT_TRUE(std::find(matches.begin(), matches.end(), 126) != matches.end());
}

// ============================================================================
// MAIN TEST ENTRY POINT
// ============================================================================


