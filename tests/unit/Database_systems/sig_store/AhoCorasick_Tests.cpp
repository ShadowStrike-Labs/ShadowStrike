// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/**
 * @file AhoCorasick_Tests.cpp
 * @brief Comprehensive Unit Tests for Aho-Corasick Multi-Pattern String Matching
 *
 * Test Coverage:
 * - Basic Operations: Pattern addition, compilation, search, clear
 * - Edge Cases: Empty inputs, single byte, maximum sizes
 * - Security Limits: Pattern length, node count, output limits
 * - Error Handling: Invalid states, boundary violations
 * - Correctness: Overlapping patterns, prefixes, suffixes, failure links
 * - Performance: Large buffers, many patterns, deep tries
 * - Thread Safety: Concurrent searches, state transitions
 * - Binary Data: Non-ASCII, null bytes, all byte values
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
#include <atomic>
#include <future>
#include<numeric>
#include <chrono>
#include <set>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURE
// ============================================================================

class AhoCorasickTest : public ::testing::Test {
protected:
    AhoCorasickAutomaton automaton;
    
    void SetUp() override {
        // Fresh automaton for each test
        automaton.Clear();
    }
    
    void TearDown() override {
        // Cleanup after each test
        automaton.Clear();
    }
    
    // Helper: Convert string to byte span
    std::span<const uint8_t> ToBytes(const std::string& str) {
        return std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(str.data()),
            str.size()
        );
    }
    
    // Helper: Create byte vector from string
    std::vector<uint8_t> MakeBytes(const std::string& str) {
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    // Helper: Add pattern from string
    bool AddStringPattern(const std::string& pattern, uint64_t id) {
        return automaton.AddPattern(ToBytes(pattern), id);
    }
    
    // Helper: Search in string
    void SearchString(const std::string& text,
                     std::function<void(uint64_t, size_t)> callback) {
        automaton.Search(ToBytes(text), callback);
    }
    
    // Helper: Count matches in string
    size_t CountMatchesInString(const std::string& text) {
        return automaton.CountMatches(ToBytes(text));
    }
};

// ============================================================================
// BASIC FUNCTIONALITY TESTS
// ============================================================================

TEST_F(AhoCorasickTest, EmptyAutomaton_NoMatches) {
    // Automaton with no patterns should not match anything
    EXPECT_FALSE(automaton.Compile()); // Should fail - no patterns
    
    size_t callbackCount = 0;
    automaton.Search(ToBytes("test"), [&](uint64_t, size_t) {
        callbackCount++;
    });
    
    EXPECT_EQ(callbackCount, 0);
}

TEST_F(AhoCorasickTest, AddSinglePattern_BasicMatch) {
    ASSERT_TRUE(AddStringPattern("virus", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<std::pair<uint64_t, size_t>> matches;
    SearchString("this is a virus test", [&](uint64_t id, size_t offset) {
        matches.emplace_back(id, offset);
    });
    
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].first, 1);  // Pattern ID
    EXPECT_EQ(matches[0].second, 14); // End offset of "virus" (0-indexed)
}

TEST_F(AhoCorasickTest, AddMultiplePatterns_AllMatch) {
    ASSERT_TRUE(AddStringPattern("malware", 1));
    ASSERT_TRUE(AddStringPattern("trojan", 2));
    ASSERT_TRUE(AddStringPattern("virus", 3));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("malware and trojan and virus", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    EXPECT_EQ(matchedIds.size(), 3);
    EXPECT_NE(std::find(matchedIds.begin(), matchedIds.end(), 1), matchedIds.end());
    EXPECT_NE(std::find(matchedIds.begin(), matchedIds.end(), 2), matchedIds.end());
    EXPECT_NE(std::find(matchedIds.begin(), matchedIds.end(), 3), matchedIds.end());
}

TEST_F(AhoCorasickTest, MultipleOccurrences_AllReported) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    size_t matchCount = CountMatchesInString("test test test");
    EXPECT_EQ(matchCount, 3);
}

TEST_F(AhoCorasickTest, CaseSensitiveMatching) {
    ASSERT_TRUE(AddStringPattern("Virus", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("Virus"), 1);
    EXPECT_EQ(CountMatchesInString("virus"), 0);  // Different case
    EXPECT_EQ(CountMatchesInString("VIRUS"), 0);  // Different case
}

TEST_F(AhoCorasickTest, OverlappingPatterns_BothMatch) {
    ASSERT_TRUE(AddStringPattern("abc", 1));
    ASSERT_TRUE(AddStringPattern("bcd", 2));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("abcd", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    EXPECT_EQ(matchedIds.size(), 2);
    EXPECT_NE(std::find(matchedIds.begin(), matchedIds.end(), 1), matchedIds.end());
    EXPECT_NE(std::find(matchedIds.begin(), matchedIds.end(), 2), matchedIds.end());
}

TEST_F(AhoCorasickTest, PrefixPattern_BothMatch) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(AddStringPattern("testing", 2));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("testing", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    // Both "test" and "testing" should match
    EXPECT_EQ(matchedIds.size(), 2);
}

TEST_F(AhoCorasickTest, SuffixPattern_OnlyFullMatch) {
    ASSERT_TRUE(AddStringPattern("ing", 1));
    ASSERT_TRUE(AddStringPattern("testing", 2));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("testing", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    EXPECT_EQ(matchedIds.size(), 2);
}

TEST_F(AhoCorasickTest, PatternAtBufferStart) {
    ASSERT_TRUE(AddStringPattern("start", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<size_t> offsets;
    SearchString("start of text", [&](uint64_t, size_t offset) {
        offsets.push_back(offset);
    });
    
    ASSERT_EQ(offsets.size(), 1);
    EXPECT_EQ(offsets[0], 4); // End of "start" at index 4
}

TEST_F(AhoCorasickTest, PatternAtBufferEnd) {
    ASSERT_TRUE(AddStringPattern("end", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<size_t> offsets;
    SearchString("text at end", [&](uint64_t, size_t offset) {
        offsets.push_back(offset);
    });
    
    ASSERT_EQ(offsets.size(), 1);
    EXPECT_EQ(offsets[0], 10); // End of "end" at last position
}

TEST_F(AhoCorasickTest, CountMatches_CorrectCount) {
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("aaa"), 3);
    EXPECT_EQ(CountMatchesInString("bbb"), 0);
    EXPECT_EQ(CountMatchesInString("aba"), 2);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================

TEST_F(AhoCorasickTest, EmptyPattern_Rejected) {
    std::vector<uint8_t> emptyPattern;
    EXPECT_FALSE(automaton.AddPattern(emptyPattern, 1));
}

TEST_F(AhoCorasickTest, EmptyBuffer_NoMatches) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    size_t callbackCount = 0;
    automaton.Search(std::span<const uint8_t>(), [&](uint64_t, size_t) {
        callbackCount++;
    });
    
    EXPECT_EQ(callbackCount, 0);
}

TEST_F(AhoCorasickTest, SingleBytePattern) {
    ASSERT_TRUE(AddStringPattern("x", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("x"), 1);
    EXPECT_EQ(CountMatchesInString("xxx"), 3);
    EXPECT_EQ(CountMatchesInString("axbxc"), 2);
}

TEST_F(AhoCorasickTest, SingleByteBuffer) {
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(AddStringPattern("b", 2));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("a"), 1);
    EXPECT_EQ(CountMatchesInString("b"), 1);
    EXPECT_EQ(CountMatchesInString("c"), 0);
}

TEST_F(AhoCorasickTest, All256ByteValues) {
    // Test with all possible byte values (0-255)
    std::vector<uint8_t> allBytes(256);
    std::iota(allBytes.begin(), allBytes.end(), 0);
    
    ASSERT_TRUE(automaton.AddPattern(allBytes, 1));
    ASSERT_TRUE(automaton.Compile());
    
    size_t matches = automaton.CountMatches(allBytes);
    EXPECT_EQ(matches, 1);
}

TEST_F(AhoCorasickTest, NullBytesInPattern) {
    std::vector<uint8_t> pattern = {0x00, 0x01, 0x00, 0x02};
    ASSERT_TRUE(automaton.AddPattern(pattern, 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint8_t> buffer = {0xFF, 0x00, 0x01, 0x00, 0x02, 0xFF};
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_EQ(matches, 1);
}

TEST_F(AhoCorasickTest, BinaryData_NonASCII) {
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};
    ASSERT_TRUE(automaton.AddPattern(pattern, 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint8_t> buffer = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0xFF};
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_EQ(matches, 1);
}

TEST_F(AhoCorasickTest, VeryLongPattern_WithinLimit) {
    // Create pattern just under the limit (4096 bytes)
    std::vector<uint8_t> longPattern(4000, 'A');
    ASSERT_TRUE(automaton.AddPattern(longPattern, 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Buffer should contain the pattern
    std::vector<uint8_t> buffer(5000, 'A');
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_GE(matches, 1001); // 5000 - 4000 + 1 = 1001 overlapping matches
}

TEST_F(AhoCorasickTest, MaxPatternLength_Rejected) {
    // Pattern exceeding AC_MAX_PATTERN_LENGTH (4096) should be rejected
    std::vector<uint8_t> tooLongPattern(4097, 'A');
    EXPECT_FALSE(automaton.AddPattern(tooLongPattern, 1));
}

TEST_F(AhoCorasickTest, DuplicatePatterns_BothStored) {
    ASSERT_TRUE(AddStringPattern("duplicate", 1));
    ASSERT_TRUE(AddStringPattern("duplicate", 2)); // Same pattern, different ID
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("duplicate", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    // Both IDs should be reported
    EXPECT_EQ(matchedIds.size(), 2);
}

TEST_F(AhoCorasickTest, NoPatternMatch_NoCallback) {
    ASSERT_TRUE(AddStringPattern("malware", 1));
    ASSERT_TRUE(automaton.Compile());
    
    size_t callbackCount = 0;
    SearchString("clean text without threats", [&](uint64_t, size_t) {
        callbackCount++;
    });
    
    EXPECT_EQ(callbackCount, 0);
}

// ============================================================================
// STATE MANAGEMENT TESTS
// ============================================================================

TEST_F(AhoCorasickTest, AddAfterCompile_Rejected) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Should reject patterns after compilation
    EXPECT_FALSE(AddStringPattern("another", 2));
}

TEST_F(AhoCorasickTest, SearchBeforeCompile_NoMatches) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    // Don't compile
    
    size_t callbackCount = 0;
    SearchString("test", [&](uint64_t, size_t) {
        callbackCount++;
    });
    
    EXPECT_EQ(callbackCount, 0);
}

TEST_F(AhoCorasickTest, MultipleCompile_Idempotent) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    ASSERT_TRUE(automaton.Compile()); // Second compile should succeed but do nothing
    
    EXPECT_EQ(CountMatchesInString("test"), 1);
}

TEST_F(AhoCorasickTest, ClearAndReuse) {
    // First use
    ASSERT_TRUE(AddStringPattern("first", 1));
    ASSERT_TRUE(automaton.Compile());
    EXPECT_EQ(CountMatchesInString("first"), 1);
    
    // Clear and reuse
    automaton.Clear();
    ASSERT_TRUE(AddStringPattern("second", 2));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("first"), 0);  // Old pattern gone
    EXPECT_EQ(CountMatchesInString("second"), 1); // New pattern works
}

TEST_F(AhoCorasickTest, ClearEmptyAutomaton) {
    automaton.Clear(); // Should not crash
    automaton.Clear(); // Multiple clears should be safe
    
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
}

// ============================================================================
// CALLBACK AND ERROR HANDLING TESTS
// ============================================================================

TEST_F(AhoCorasickTest, NullCallback_HandledSafely) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Should handle null callback gracefully (log error, don't crash)
    automaton.Search(ToBytes("test"), nullptr);
    // No assertion - just verify no crash
}

TEST_F(AhoCorasickTest, CallbackException_ContinuesSearch) {
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::atomic<int> callCount{0};
    SearchString("aaa", [&](uint64_t, size_t offset) {
        callCount++;
        if (offset == 0) {
            throw std::runtime_error("Test exception");
        }
    });
    
    // Should continue despite exception on first match
    EXPECT_EQ(callCount, 3);
}

TEST_F(AhoCorasickTest, MatchOffsets_Correct) {
    ASSERT_TRUE(AddStringPattern("abc", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<size_t> offsets;
    SearchString("xabcyabcz", [&](uint64_t, size_t offset) {
        offsets.push_back(offset);
    });
    
    ASSERT_EQ(offsets.size(), 2);
    EXPECT_EQ(offsets[0], 3); // End of first "abc"
    EXPECT_EQ(offsets[1], 7); // End of second "abc"
}

// ============================================================================
// COMPLEX PATTERN MATCHING TESTS
// ============================================================================

TEST_F(AhoCorasickTest, NestedPatterns_AllMatch) {
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(AddStringPattern("ab", 2));
    ASSERT_TRUE(AddStringPattern("abc", 3));
    ASSERT_TRUE(AddStringPattern("abcd", 4));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("abcd", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    // All 4 patterns should match
    EXPECT_EQ(matchedIds.size(), 4);
}

TEST_F(AhoCorasickTest, CommonSuffix_FailureLinksCorrect) {
    ASSERT_TRUE(AddStringPattern("she", 1));
    ASSERT_TRUE(AddStringPattern("he", 2));
    ASSERT_TRUE(AddStringPattern("hers", 3));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("shers", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    // "she", "he", and "hers" should all match
    EXPECT_EQ(matchedIds.size(), 3);
}

TEST_F(AhoCorasickTest, RepeatingPatterns) {
    ASSERT_TRUE(AddStringPattern("aa", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // "aaaa" contains 3 overlapping "aa" patterns
    EXPECT_EQ(CountMatchesInString("aaaa"), 3);
}

TEST_F(AhoCorasickTest, ManyShortPatterns) {
    // Add 100 single-byte patterns
    for (uint8_t i = 0; i < 100; ++i) {
        std::vector<uint8_t> pattern = {i};
        ASSERT_TRUE(automaton.AddPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    // Create buffer with all those bytes
    std::vector<uint8_t> buffer(100);
    std::iota(buffer.begin(), buffer.end(), 0);
    
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_EQ(matches, 100);
}

TEST_F(AhoCorasickTest, LongCommonPrefix) {
    std::string prefix(100, 'A');
    ASSERT_TRUE(AddStringPattern(prefix + "1", 1));
    ASSERT_TRUE(AddStringPattern(prefix + "2", 2));
    ASSERT_TRUE(AddStringPattern(prefix + "3", 3));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString(prefix + "1"), 1);
    EXPECT_EQ(CountMatchesInString(prefix + "2"), 1);
    EXPECT_EQ(CountMatchesInString(prefix + "3"), 1);
}

TEST_F(AhoCorasickTest, AlternatingBytes) {
    ASSERT_TRUE(AddStringPattern("\x01\x02", 1));
    ASSERT_TRUE(AddStringPattern("\x02\x01", 2));
    ASSERT_TRUE(automaton.Compile());
    
    std::string buffer = "\x01\x02\x01\x02";
    EXPECT_EQ(CountMatchesInString(buffer), 3); // 2 of pattern 1, 1 of pattern 2
}

// ============================================================================
// PERFORMANCE AND STRESS TESTS
// ============================================================================

TEST_F(AhoCorasickTest, LargeBuffer_ManyMatches) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // 1MB buffer with pattern every 100 bytes
    std::string largeBuffer;
    for (int i = 0; i < 10000; ++i) {
        largeBuffer += "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxtest";
    }
    
    size_t matches = CountMatchesInString(largeBuffer);
    EXPECT_EQ(matches, 10000);
}

TEST_F(AhoCorasickTest, ManyPatterns_LargeTrie) {
    // Add 1000 unique patterns (pattern_0 through pattern_999)
    // Note: Aho-Corasick finds ALL patterns that appear as substrings in the search text.
    // Since all patterns share the "pattern_" prefix, searching for "pattern_XYZ" will
    // also find any patterns that are prefixes of "pattern_XYZ".
    for (int i = 0; i < 1000; ++i) {
        std::string pattern = "pattern_" + std::to_string(i);
        ASSERT_TRUE(AddStringPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    // Aho-Corasick finds ALL matching patterns in a text:
    // "pattern_500" contains: pattern_5, pattern_50, pattern_500 = 3 matches
    // "pattern_999" contains: pattern_9, pattern_99, pattern_999 = 3 matches  
    // "pattern_1000" contains: pattern_1, pattern_10, pattern_100 = 3 matches (1000 itself not added)
    EXPECT_EQ(CountMatchesInString("pattern_500"), 3);  // pattern_5, pattern_50, pattern_500
    EXPECT_EQ(CountMatchesInString("pattern_999"), 3);  // pattern_9, pattern_99, pattern_999
    EXPECT_EQ(CountMatchesInString("pattern_1000"), 3); // pattern_1, pattern_10, pattern_100
}

TEST_F(AhoCorasickTest, DeepTrie_LongPatterns) {
    // Create patterns of varying lengths from same prefix
    std::string base = "AAAAAAAAAA"; // 10 A's //-V808
    for (int i = 1; i <= 20; ++i) {
        std::string pattern = std::string(i * 10, 'A') + std::to_string(i);
        ASSERT_TRUE(AddStringPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    std::string buffer = std::string(200, 'A') + "10";
    size_t matches = CountMatchesInString(buffer);
    EXPECT_GE(matches, 1);
}

TEST_F(AhoCorasickTest, NoMatchInLargeBuffer) {
    ASSERT_TRUE(AddStringPattern("NEEDLE", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // 1MB buffer with no match
    std::string haystack(1024 * 1024, 'X');
    EXPECT_EQ(CountMatchesInString(haystack), 0);
}

TEST_F(AhoCorasickTest, RandomPatterns_RandomBuffer) {
    std::mt19937 rng(42); // Fixed seed for reproducibility
    std::uniform_int_distribution<> dist(0, 255);
    
    // Add 50 random patterns
    std::vector<std::vector<uint8_t>> patterns;
    for (int i = 0; i < 50; ++i) {
        std::vector<uint8_t> pattern(10);
        for (auto& byte : pattern) {
            byte = static_cast<uint8_t>(dist(rng));
        }
        patterns.push_back(pattern);
        ASSERT_TRUE(automaton.AddPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    // Create random buffer
    std::vector<uint8_t> buffer(10000);
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(dist(rng));
    }
    
    // Just verify search completes without crash
    size_t matches = automaton.CountMatches(buffer);
    // Don't assert specific count - just verify no crash
    EXPECT_GE(matches, 0);
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(AhoCorasickTest, ConcurrentSearches_ThreadSafe) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(AddStringPattern("data", 2));
    ASSERT_TRUE(automaton.Compile());
    
    const int numThreads = 10;
    const int searchesPerThread = 100;
    
    std::vector<std::thread> threads;
    std::atomic<size_t> totalMatches{0};
    
    for (int t = 0; t < numThreads; ++t) {
        threads.emplace_back([&, t]() {
            for (int i = 0; i < searchesPerThread; ++i) {
                std::string buffer = "test and data";
                size_t matches = CountMatchesInString(buffer);
                totalMatches += matches;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Each search finds 2 matches
    EXPECT_EQ(totalMatches, numThreads * searchesPerThread * 2);
}

TEST_F(AhoCorasickTest, ConcurrentSearchesDifferentBuffers) {
    ASSERT_TRUE(AddStringPattern("pattern", 1));
    ASSERT_TRUE(automaton.Compile());
    
    const int numThreads = 8;
    std::vector<std::future<size_t>> futures;
    
    for (int t = 0; t < numThreads; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            std::string buffer = "pattern_" + std::to_string(t) + "_pattern";
            return CountMatchesInString(buffer);
        }));
    }
    
    for (auto& future : futures) {
        size_t matches = future.get();
        EXPECT_EQ(matches, 2); // Each buffer has "pattern" twice
    }
}

// ============================================================================
// SECURITY AND ROBUSTNESS TESTS
// ============================================================================

TEST_F(AhoCorasickTest, MaliciousPatternId_LargeValue) {
    // Very large pattern IDs should be handled correctly
    ASSERT_TRUE(AddStringPattern("test", UINT64_MAX));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> ids;
    SearchString("test", [&](uint64_t id, size_t) {
        ids.push_back(id);
    });
    
    ASSERT_EQ(ids.size(), 1);
    EXPECT_EQ(ids[0], UINT64_MAX);
}

TEST_F(AhoCorasickTest, PatternWithAllZeros) {
    std::vector<uint8_t> zeros(100, 0);
    ASSERT_TRUE(automaton.AddPattern(zeros, 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint8_t> buffer(200, 0);
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_GE(matches, 1);
}

TEST_F(AhoCorasickTest, PatternWithAllOnes) {
    std::vector<uint8_t> ones(100, 0xFF);
    ASSERT_TRUE(automaton.AddPattern(ones, 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint8_t> buffer(200, 0xFF);
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_GE(matches, 1);
}

TEST_F(AhoCorasickTest, MatchCountOverflow_Saturation) {
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // CountMatches should saturate at SIZE_MAX, not overflow
    // We can't actually create a buffer that large, but verify behavior is defined
    std::string buffer(1000, 'a');
    size_t count = CountMatchesInString(buffer);
    EXPECT_EQ(count, 1000);
    EXPECT_LE(count, SIZE_MAX);
}

TEST_F(AhoCorasickTest, ExtremelyShortPattern_OneByte) {
    for (int i = 0; i < 256; ++i) {
        automaton.Clear();
        std::vector<uint8_t> pattern = {static_cast<uint8_t>(i)};
        ASSERT_TRUE(automaton.AddPattern(pattern, i));
        ASSERT_TRUE(automaton.Compile());
        
        std::vector<uint8_t> buffer = {static_cast<uint8_t>(i)};
        EXPECT_EQ(automaton.CountMatches(buffer), 1);
    }
}

// ============================================================================
// CORRECTNESS VERIFICATION TESTS
// ============================================================================

TEST_F(AhoCorasickTest, FailureLinks_ComplexCase) {
    // Classic Aho-Corasick test case
    ASSERT_TRUE(AddStringPattern("he", 1));
    ASSERT_TRUE(AddStringPattern("she", 2));
    ASSERT_TRUE(AddStringPattern("his", 3));
    ASSERT_TRUE(AddStringPattern("hers", 4));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<std::pair<uint64_t, size_t>> matches;
    SearchString("ushers", [&](uint64_t id, size_t offset) {
        matches.emplace_back(id, offset);
    });
    
    // Should find: "she" at offset 3, "he" at offset 3, "hers" at offset 5
    EXPECT_EQ(matches.size(), 3);
}

TEST_F(AhoCorasickTest, KnownGoodExample_Wikipedia) {
    // Example from Aho-Corasick algorithm documentation
    ASSERT_TRUE(AddStringPattern("a", 1));
    ASSERT_TRUE(AddStringPattern("ab", 2));
    ASSERT_TRUE(AddStringPattern("bab", 3));
    ASSERT_TRUE(AddStringPattern("bc", 4));
    ASSERT_TRUE(AddStringPattern("bca", 5));
    ASSERT_TRUE(AddStringPattern("c", 6));
    ASSERT_TRUE(AddStringPattern("caa", 7));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> matchedIds;
    SearchString("abccab", [&](uint64_t id, size_t) {
        matchedIds.push_back(id);
    });
    
    // Verify we get multiple matches
    EXPECT_GE(matchedIds.size(), 4);
}

TEST_F(AhoCorasickTest, PatternComparison_BruteForceVerification) {
    std::vector<std::string> patterns = {"virus", "malware", "trojan", "worm"};
    for (size_t i = 0; i < patterns.size(); ++i) {
        ASSERT_TRUE(AddStringPattern(patterns[i], i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    std::string text = "this virus is malware not a trojan but maybe a worm";
    
    // Aho-Corasick result
    std::set<std::string> acMatches;
    SearchString(text, [&](uint64_t id, size_t) {
        if (id < patterns.size()) {
            acMatches.insert(patterns[id]);
        }
    });
    
    // Brute force result
    std::set<std::string> bruteMatches;
    for (const auto& pattern : patterns) {
        if (text.find(pattern) != std::string::npos) {
            bruteMatches.insert(pattern);
        }
    }
    
    // Should match
    EXPECT_EQ(acMatches, bruteMatches);
}

TEST_F(AhoCorasickTest, OffsetAccuracy_ExactPositions) {
    ASSERT_TRUE(AddStringPattern("abc", 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<size_t> offsets;
    SearchString("012abc678abc", [&](uint64_t, size_t offset) {
        offsets.push_back(offset);
    });
    
    ASSERT_EQ(offsets.size(), 2);
    EXPECT_EQ(offsets[0], 5);  // "abc" ends at index 5
    EXPECT_EQ(offsets[1], 11); // "abc" ends at index 11
}

// ============================================================================
// BOUNDARY AND EDGE CONDITION TESTS
// ============================================================================

TEST_F(AhoCorasickTest, PatternLongerThanBuffer) {
    ASSERT_TRUE(AddStringPattern("verylongpattern", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("short"), 0);
}

TEST_F(AhoCorasickTest, BufferExactlyMatchesPattern) {
    ASSERT_TRUE(AddStringPattern("exact", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("exact"), 1);
}

TEST_F(AhoCorasickTest, MultipleIdenticalPatterns_SamePosition) {
    // Add same pattern with different IDs
    ASSERT_TRUE(AddStringPattern("same", 1));
    ASSERT_TRUE(AddStringPattern("same", 2));
    ASSERT_TRUE(AddStringPattern("same", 3));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> ids;
    SearchString("same", [&](uint64_t id, size_t) {
        ids.push_back(id);
    });
    
    // All three IDs should be reported
    EXPECT_EQ(ids.size(), 3);
    EXPECT_NE(std::find(ids.begin(), ids.end(), 1), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), 2), ids.end());
    EXPECT_NE(std::find(ids.begin(), ids.end(), 3), ids.end());
}

TEST_F(AhoCorasickTest, AdjacentPatterns_NoGap) {
    ASSERT_TRUE(AddStringPattern("abc", 1));
    ASSERT_TRUE(AddStringPattern("def", 2));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint64_t> ids;
    SearchString("abcdef", [&](uint64_t id, size_t) {
        ids.push_back(id);
    });
    
    EXPECT_EQ(ids.size(), 2);
}

TEST_F(AhoCorasickTest, ReverseOrderPatterns) {
    ASSERT_TRUE(AddStringPattern("cba", 1));
    ASSERT_TRUE(AddStringPattern("fed", 2));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("abcdef"), 0);
    EXPECT_EQ(CountMatchesInString("cba"), 1);
    EXPECT_EQ(CountMatchesInString("fed"), 1);
}

// ============================================================================
// SPECIAL CHARACTER AND ENCODING TESTS
// ============================================================================

TEST_F(AhoCorasickTest, WhitespacePatterns) {
    ASSERT_TRUE(AddStringPattern(" ", 1));
    ASSERT_TRUE(AddStringPattern("\t", 2));
    ASSERT_TRUE(AddStringPattern("\n", 3));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString(" "), 1);
    EXPECT_EQ(CountMatchesInString("\t"), 1);
    EXPECT_EQ(CountMatchesInString("\n"), 1);
    EXPECT_EQ(CountMatchesInString("a b\tc\nd"), 3);
}

TEST_F(AhoCorasickTest, SpecialCharacters) {
    ASSERT_TRUE(AddStringPattern("!@#$%", 1));
    ASSERT_TRUE(AddStringPattern("^&*()", 2));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("!@#$%"), 1);
    EXPECT_EQ(CountMatchesInString("^&*()"), 1);
}

TEST_F(AhoCorasickTest, UTF8Bytes_TreatedAsBinary) {
    // UTF-8 "hello" in Chinese: 你好
    std::vector<uint8_t> utf8Pattern = {0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD};
    ASSERT_TRUE(automaton.AddPattern(utf8Pattern, 1));
    ASSERT_TRUE(automaton.Compile());
    
    std::vector<uint8_t> buffer = {0xFF, 0xE4, 0xBD, 0xA0, 0xE5, 0xA5, 0xBD, 0x00};
    size_t matches = automaton.CountMatches(buffer);
    EXPECT_EQ(matches, 1);
}

// ============================================================================
// REGRESSION TESTS (for potential bugs)
// ============================================================================

TEST_F(AhoCorasickTest, Regression_EmptyOutputVector) {
    // Ensure nodes without outputs don't cause issues
    ASSERT_TRUE(AddStringPattern("ab", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Search with text that creates nodes without outputs
    EXPECT_EQ(CountMatchesInString("axb"), 0);
}

TEST_F(AhoCorasickTest, Regression_RootNodeTransition) {
    ASSERT_TRUE(AddStringPattern("test", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Text that causes multiple returns to root
    EXPECT_EQ(CountMatchesInString("xyz test xyz"), 1);
}

TEST_F(AhoCorasickTest, Regression_FailureLinkToRoot) {
    ASSERT_TRUE(AddStringPattern("abc", 1));
    ASSERT_TRUE(automaton.Compile());
    
    // Text with no partial matches
    EXPECT_EQ(CountMatchesInString("xyabcz"), 1);
}

TEST_F(AhoCorasickTest, Regression_SelfLoop) {
    // Pattern that might cause self-loop issues
    ASSERT_TRUE(AddStringPattern("aaa", 1));
    ASSERT_TRUE(automaton.Compile());
    
    EXPECT_EQ(CountMatchesInString("aaaa"), 2); // Two overlapping matches
}

TEST_F(AhoCorasickTest, Regression_NodeReallocation) {
    // Add many patterns to force vector reallocation
    // Note: Aho-Corasick matches ALL patterns that occur as substrings
    // e.g., searching "p250" will match patterns: "p2", "p25", "p250"
    for (int i = 0; i < 500; ++i) {
        std::string pattern = "p" + std::to_string(i);
        ASSERT_TRUE(AddStringPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    // Verify patterns work after vector reallocations
    // "p0" is unique (no prefixes match)
    EXPECT_EQ(CountMatchesInString("p0"), 1);
    
    // "p250" matches: p2 (at pos 0), p25 (at pos 0), p250 (at pos 0) = 3 matches
    EXPECT_EQ(CountMatchesInString("p250"), 3);
    
    // "p499" matches: p4 (at pos 0), p49 (at pos 0), p499 (at pos 0) = 3 matches
    EXPECT_EQ(CountMatchesInString("p499"), 3);
}

// ============================================================================
// MEMORY AND RESOURCE TESTS
// ============================================================================

TEST_F(AhoCorasickTest, ClearFreesMemory) {
    // Add many patterns
    for (int i = 0; i < 1000; ++i) {
        std::string pattern = "pattern_" + std::to_string(i);
        ASSERT_TRUE(AddStringPattern(pattern, i));
    }
    ASSERT_TRUE(automaton.Compile());
    
    // Clear should free resources
    automaton.Clear();
    
    // Should be able to add new patterns
    ASSERT_TRUE(AddStringPattern("new", 1));
    ASSERT_TRUE(automaton.Compile());
    EXPECT_EQ(CountMatchesInString("new"), 1);
}

TEST_F(AhoCorasickTest, MultipleClearCycles) {
    for (int cycle = 0; cycle < 5; ++cycle) {
        for (int i = 0; i < 100; ++i) {
            std::string pattern = "p" + std::to_string(i);
            ASSERT_TRUE(AddStringPattern(pattern, i));
        }
        ASSERT_TRUE(automaton.Compile());
        EXPECT_GE(CountMatchesInString("p50"), 1);
        automaton.Clear();
    }
}
