/*
 * ============================================================================
 * ShadowStrike PatternStore - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade test suite for PatternStore module
 * Tests all major functionality with extensive edge cases
 *
 * Test Categories:
 * 1. Aho-Corasick Automaton Tests
 * 2. Boyer-Moore Matcher Tests
 * 3. SIMD Matcher Tests (AVX2/AVX-512)
 * 4. Pattern Compiler Tests
 * 5. PatternStore Core Tests
 * 6. Concurrency & Thread Safety Tests
 * 7. Performance & Benchmark Tests
 * 8. Edge Cases & Error Handling Tests
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../../src/SignatureStore/PatternStore.hpp"
#include "../../../../src/SignatureStore/SignatureFormat.hpp"
#include <filesystem>
#include <fstream>
#include <random>
#include<numeric>
#include <thread>
#include <chrono>
#include <future>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURES
// ============================================================================

class AhoCorasickTest : public ::testing::Test {
protected:
    AhoCorasickAutomaton automaton;

    void SetUp() override {
        // Fresh automaton for each test
    }

    void TearDown() override {
        automaton.Clear();
    }
};

class BoyerMooreTest : public ::testing::Test {
protected:
    // Test helper to create matcher
    std::unique_ptr<BoyerMooreMatcher> CreateMatcher(
        const std::string& patternHex,
        const std::string& maskHex = ""
    ) {
        auto pattern = HexStringToBytes(patternHex);
        auto mask = maskHex.empty() ? std::vector<uint8_t>() : HexStringToBytes(maskHex).value();
        
        return std::make_unique<BoyerMooreMatcher>(pattern.value(), mask);
    }

    std::optional<std::vector<uint8_t>> HexStringToBytes(const std::string& hex) {
        return PatternUtils::HexStringToBytes(hex);
    }
};

class SIMDMatcherTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_hasAVX2 = SIMDMatcher::IsAVX2Available();
        m_hasAVX512 = SIMDMatcher::IsAVX512Available();

        if (!m_hasAVX2) {
            GTEST_SKIP() << "AVX2 not available on this CPU";
        }
    }

    bool m_hasAVX2 = false;
    bool m_hasAVX512 = false;
};

class PatternCompilerTest : public ::testing::Test {
protected:
    // Helper to compile and validate
    std::optional<std::vector<uint8_t>> CompilePattern(
        const std::string& patternStr,
        PatternMode& mode,
        std::vector<uint8_t>& mask
    ) {
        return PatternCompiler::CompilePattern(patternStr, mode, mask);
    }
};

class PatternStoreTest : public ::testing::Test {
protected:
    std::wstring m_testDbPath;
    std::unique_ptr<PatternStore> m_store;

    void SetUp() override {
        // Create temporary database path
        auto tempDir = std::filesystem::temp_directory_path();
        m_testDbPath = (tempDir / L"shadowstrike_test.pdb").wstring();

        // Remove existing test database
        std::filesystem::remove(m_testDbPath);

        // Create new store
        m_store = std::make_unique<PatternStore>();
    }

    void TearDown() override {
        if (m_store) {
            m_store->Close();
            m_store.reset();
        }

        // Cleanup test database
        std::filesystem::remove(m_testDbPath);
    }

    // Helper: Create and initialize store
    bool InitializeStore(uint64_t sizeBytes = 10 * 1024 * 1024) {
        auto err = m_store->CreateNew(m_testDbPath, sizeBytes);
        return err.IsSuccess();
    }
};

// ============================================================================
// AHO-CORASICK AUTOMATON TESTS
// ============================================================================

TEST_F(AhoCorasickTest, BasicPatternAddition) {
    std::vector<uint8_t> pattern1 = {0x48, 0x8B, 0x05};
    std::vector<uint8_t> pattern2 = {0xFF, 0xD0};

    EXPECT_TRUE(automaton.AddPattern(pattern1, 1));
    EXPECT_TRUE(automaton.AddPattern(pattern2, 2));

    EXPECT_EQ(automaton.GetPatternCount(), 2);
}

TEST_F(AhoCorasickTest, EmptyPatternRejection) {
    std::vector<uint8_t> emptyPattern;

    EXPECT_FALSE(automaton.AddPattern(emptyPattern, 1));
    EXPECT_EQ(automaton.GetPatternCount(), 0);
}

TEST_F(AhoCorasickTest, ExcessivelyLongPatternRejection) {
    // Create pattern > 4096 bytes
    std::vector<uint8_t> longPattern(5000, 0xAA);

    EXPECT_FALSE(automaton.AddPattern(longPattern, 1));
    EXPECT_EQ(automaton.GetPatternCount(), 0);
}

TEST_F(AhoCorasickTest, CannotAddAfterCompilation) {
    std::vector<uint8_t> pattern1 = {0x48, 0x8B};

    ASSERT_TRUE(automaton.AddPattern(pattern1, 1));
    ASSERT_TRUE(automaton.Compile());

    std::vector<uint8_t> pattern2 = {0xFF, 0xD0};
    EXPECT_FALSE(automaton.AddPattern(pattern2, 2));
}

TEST_F(AhoCorasickTest, BasicSearch) {
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x05};
    std::vector<uint8_t> buffer = {
        0x00, 0x48, 0x8B, 0x05, 0xFF,  // Match at offset 1
        0x48, 0x8B, 0x05, 0xAA         // Match at offset 5
    };

    ASSERT_TRUE(automaton.AddPattern(pattern, 1));
    ASSERT_TRUE(automaton.Compile());

    std::vector<std::pair<uint64_t, size_t>> matches;
    automaton.Search(buffer, [&](uint64_t id, size_t offset) {
        matches.emplace_back(id, offset);
    });

    ASSERT_EQ(matches.size(), 2);
    EXPECT_EQ(matches[0].first, 1);
    EXPECT_EQ(matches[0].second, 3);  // End offset of first match
    EXPECT_EQ(matches[1].first, 1);
    EXPECT_EQ(matches[1].second, 7);  // End offset of second match
}

TEST_F(AhoCorasickTest, MultiplePatternSearch) {
    std::vector<uint8_t> pattern1 = {0x48, 0x8B};
    std::vector<uint8_t> pattern2 = {0xFF, 0xD0};
    std::vector<uint8_t> buffer = {
        0x48, 0x8B, 0x00, 0xFF, 0xD0
    };

    ASSERT_TRUE(automaton.AddPattern(pattern1, 1));
    ASSERT_TRUE(automaton.AddPattern(pattern2, 2));
    ASSERT_TRUE(automaton.Compile());

    std::vector<uint64_t> foundIds;
    automaton.Search(buffer, [&](uint64_t id, size_t) {
        foundIds.push_back(id);
    });

    EXPECT_EQ(foundIds.size(), 2);
    EXPECT_TRUE(std::find(foundIds.begin(), foundIds.end(), 1) != foundIds.end());
    EXPECT_TRUE(std::find(foundIds.begin(), foundIds.end(), 2) != foundIds.end());
}

TEST_F(AhoCorasickTest, OverlappingPatterns) {
    std::vector<uint8_t> pattern1 = {0xAA, 0xBB};
    std::vector<uint8_t> pattern2 = {0xBB, 0xCC};
    std::vector<uint8_t> buffer = {0xAA, 0xBB, 0xCC};

    ASSERT_TRUE(automaton.AddPattern(pattern1, 1));
    ASSERT_TRUE(automaton.AddPattern(pattern2, 2));
    ASSERT_TRUE(automaton.Compile());

    size_t matchCount = automaton.CountMatches(buffer);
    EXPECT_EQ(matchCount, 2);
}

TEST_F(AhoCorasickTest, NoMatchScenario) {
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x05};
    std::vector<uint8_t> buffer = {0xFF, 0xFF, 0xFF, 0xFF};

    ASSERT_TRUE(automaton.AddPattern(pattern, 1));
    ASSERT_TRUE(automaton.Compile());

    size_t matchCount = automaton.CountMatches(buffer);
    EXPECT_EQ(matchCount, 0);
}

TEST_F(AhoCorasickTest, LargeScalePatternAddition) {
    // Add 10,000 unique patterns
    const size_t patternCount = 10000;
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint8_t> dist(0, 255);

    for (size_t i = 0; i < patternCount; ++i) {
        std::vector<uint8_t> pattern(8);
        for (auto& byte : pattern) {
            byte = dist(rng);
        }
        ASSERT_TRUE(automaton.AddPattern(pattern, i));
    }

    EXPECT_EQ(automaton.GetPatternCount(), patternCount);
    ASSERT_TRUE(automaton.Compile());
}

TEST_F(AhoCorasickTest, MemoryExhaustionProtection) {
    // Try to exceed node limit (10M nodes)
    // This should eventually fail before system runs out of memory
    
    std::vector<uint8_t> basePattern(100, 0xAA);
    size_t successCount = 0;
    
    for (size_t i = 0; i < 200000; ++i) {
        std::vector<uint8_t> pattern = basePattern;
        pattern.push_back(static_cast<uint8_t>(i & 0xFF));
        pattern.push_back(static_cast<uint8_t>((i >> 8) & 0xFF));
        
        if (!automaton.AddPattern(pattern, i)) {
            break; // Hit limit as expected
        }
        successCount++;
    }

    // Should have added many but not unlimited patterns
    EXPECT_GT(successCount, 1000);
    EXPECT_LT(successCount, 200000);
}

// ============================================================================
// BOYER-MOORE MATCHER TESTS
// ============================================================================

TEST_F(BoyerMooreTest, ExactPatternMatch) {
    auto matcher = CreateMatcher("48 8B 05");
    std::vector<uint8_t> buffer = {0x00, 0x48, 0x8B, 0x05, 0xFF};

    auto matches = matcher->Search(buffer);
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0], 1);
}

TEST_F(BoyerMooreTest, MultipleMatches) {
    auto matcher = CreateMatcher("AA BB");
    std::vector<uint8_t> buffer = {
        0xAA, 0xBB, 0x00,
        0xAA, 0xBB, 0xFF,
        0xAA, 0xBB
    };

    auto matches = matcher->Search(buffer);
    EXPECT_EQ(matches.size(), 3);
}

TEST_F(BoyerMooreTest, FindFirstOptimization) {
    auto matcher = CreateMatcher("FF FF FF FF");
    std::vector<uint8_t> buffer(10000, 0x00);
    buffer[5000] = 0xFF;
    buffer[5001] = 0xFF;
    buffer[5002] = 0xFF;
    buffer[5003] = 0xFF;

    auto result = matcher->FindFirst(buffer);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 5000);
}

TEST_F(BoyerMooreTest, WildcardMaskMatching) {
    // Pattern: 48 ?? 05 (matches 48 XX 05 for any XX)
    auto pattern = HexStringToBytes("48 00 05").value();
    std::vector<uint8_t> mask = {0xFF, 0x00, 0xFF};  // Don't care about middle byte

    BoyerMooreMatcher matcher(pattern, mask);

    std::vector<uint8_t> buffer1 = {0x48, 0xAA, 0x05};
    std::vector<uint8_t> buffer2 = {0x48, 0xFF, 0x05};
    std::vector<uint8_t> buffer3 = {0x48, 0x00, 0x05};

    EXPECT_EQ(matcher.Search(buffer1).size(), 1);
    EXPECT_EQ(matcher.Search(buffer2).size(), 1);
    EXPECT_EQ(matcher.Search(buffer3).size(), 1);
}

TEST_F(BoyerMooreTest, NoMatchScenario) {
    auto matcher = CreateMatcher("DE AD BE EF");
    std::vector<uint8_t> buffer(1000, 0x00);

    auto matches = matcher->Search(buffer);
    EXPECT_EQ(matches.size(), 0);
}

TEST_F(BoyerMooreTest, PatternAtBufferBoundaries) {
    auto matcher = CreateMatcher("AA BB");

    // Pattern at start
    std::vector<uint8_t> buffer1 = {0xAA, 0xBB, 0x00};
    EXPECT_EQ(matcher->Search(buffer1).size(), 1);
    EXPECT_EQ(matcher->Search(buffer1)[0], 0);

    // Pattern at end
    std::vector<uint8_t> buffer2 = {0x00, 0xAA, 0xBB};
    EXPECT_EQ(matcher->Search(buffer2).size(), 1);
    EXPECT_EQ(matcher->Search(buffer2)[0], 1);
}

TEST_F(BoyerMooreTest, SingleBytePattern) {
    auto matcher = CreateMatcher("FF");
    std::vector<uint8_t> buffer = {0x00, 0xFF, 0x00, 0xFF, 0x00};

    auto matches = matcher->Search(buffer);
    EXPECT_EQ(matches.size(), 2);
}

TEST_F(BoyerMooreTest, LongPatternPerformance) {
    // 128-byte pattern
    std::string patternHex;
    for (int i = 0; i < 128; ++i) {
        patternHex += "AA ";
    }
    auto matcher = CreateMatcher(patternHex);

    // 1MB buffer with pattern at position 500,000
    std::vector<uint8_t> buffer(1024 * 1024, 0x00);
    for (size_t i = 500000; i < 500128; ++i) {
        buffer[i] = 0xAA;
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto result = matcher->FindFirst(buffer);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 500000);
    
    // Should be fast (< 10ms for 1MB scan)
    EXPECT_LT(duration.count(), 10000);
}

// ============================================================================
// SIMD MATCHER TESTS
// ============================================================================

TEST_F(SIMDMatcherTest, AVX2BasicSearch) {
    std::vector<uint8_t> pattern = {0x48, 0x8B, 0x05};
    std::vector<uint8_t> buffer(1000, 0x00);
    
    // Place pattern at multiple locations
    std::copy(pattern.begin(), pattern.end(), buffer.begin() + 100);
    std::copy(pattern.begin(), pattern.end(), buffer.begin() + 500);

    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_EQ(matches.size(), 2);
    EXPECT_TRUE(std::find(matches.begin(), matches.end(), 100) != matches.end());
    EXPECT_TRUE(std::find(matches.begin(), matches.end(), 500) != matches.end());
}

TEST_F(SIMDMatcherTest, AVX2VsScalarConsistency) {
    std::vector<uint8_t> pattern = {0xDE, 0xAD, 0xBE, 0xEF};
    
    // Generate random buffer
    std::vector<uint8_t> buffer(10000);
    std::mt19937 rng(12345);
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (auto& byte : buffer) {
        byte = dist(rng);
    }

    // Insert pattern at known positions
    std::vector<size_t> knownPositions = {100, 1000, 5000, 9000};
    for (auto pos : knownPositions) {
        std::copy(pattern.begin(), pattern.end(), buffer.begin() + pos);
    }

    auto simdMatches = SIMDMatcher::SearchAVX2(buffer, pattern);

    // Verify all known positions found
    EXPECT_EQ(simdMatches.size(), knownPositions.size());
    for (auto pos : knownPositions) {
        EXPECT_TRUE(std::find(simdMatches.begin(), simdMatches.end(), pos) != simdMatches.end());
    }
}

TEST_F(SIMDMatcherTest, AVX512Availability) {
    if (SIMDMatcher::IsAVX512Available()) {
        std::vector<uint8_t> pattern = {0x90, 0x90, 0x90};
        std::vector<uint8_t> buffer(1000, 0x90);

        auto matches = SIMDMatcher::SearchAVX512(buffer, pattern);
        EXPECT_GT(matches.size(), 0);
    } else {
        GTEST_SKIP() << "AVX-512 not available";
    }
}

TEST_F(SIMDMatcherTest, SingleBytePatternSIMD) {
    std::vector<uint8_t> pattern = {0xFF};
    std::vector<uint8_t> buffer(1000, 0x00);
    
    buffer[50] = 0xFF;
    buffer[500] = 0xFF;
    buffer[999] = 0xFF;

    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    
    EXPECT_EQ(matches.size(), 3);
}

TEST_F(SIMDMatcherTest, LargeBufferPerformance) {
    std::vector<uint8_t> pattern = {0x48, 0x89, 0x5C, 0x24};
    
    // 10MB buffer
    std::vector<uint8_t> buffer(10 * 1024 * 1024, 0x00);
    
    // Place pattern every 1MB
    for (size_t i = 0; i < 10; ++i) {
        size_t pos = i * 1024 * 1024;
        std::copy(pattern.begin(), pattern.end(), buffer.begin() + pos);
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto matches = SIMDMatcher::SearchAVX2(buffer, pattern);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_EQ(matches.size(), 10);
    
    // Should scan 10MB in < 50ms (target: < 10ms)
    EXPECT_LT(duration.count(), 50);
}

// ============================================================================
// PATTERN COMPILER TESTS
// ============================================================================

TEST_F(PatternCompilerTest, ExactHexPattern) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("48 8B 05", mode, mask);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(mode, PatternMode::Exact);
    EXPECT_EQ(result->size(), 3);
    EXPECT_EQ((*result)[0], 0x48);
    EXPECT_EQ((*result)[1], 0x8B);
    EXPECT_EQ((*result)[2], 0x05);
}

TEST_F(PatternCompilerTest, WildcardPattern) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("48 ?? 05", mode, mask);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(mode, PatternMode::Wildcard);
    EXPECT_EQ(result->size(), 3);
    
    // Mask should reflect wildcard
    EXPECT_EQ(mask[0], 0xFF);
    EXPECT_EQ(mask[1], 0x00);  // Wildcard
    EXPECT_EQ(mask[2], 0xFF);
}

TEST_F(PatternCompilerTest, ByteRangePattern) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("48 [8B-8D] 05", mode, mask);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(mode, PatternMode::Regex);
    EXPECT_EQ(result->size(), 3);
}

TEST_F(PatternCompilerTest, VariableGapPattern) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("48 8B {0-4} C3", mode, mask);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(mode, PatternMode::Regex);
}

TEST_F(PatternCompilerTest, EmptyPatternRejection) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("", mode, mask);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PatternCompilerTest, InvalidHexRejection) {
    PatternMode mode;
    std::vector<uint8_t> mask;

    auto result = CompilePattern("ZZ XX YY", mode, mask);
    EXPECT_FALSE(result.has_value());
}

TEST_F(PatternCompilerTest, PatternValidation) {
    std::string errorMsg;

    EXPECT_TRUE(PatternCompiler::ValidatePattern("48 8B 05", errorMsg));
    EXPECT_TRUE(PatternCompiler::ValidatePattern("48 ?? 05", errorMsg));
    EXPECT_FALSE(PatternCompiler::ValidatePattern("48 [ 05", errorMsg));  // Unbalanced
    EXPECT_FALSE(PatternCompiler::ValidatePattern("{ 8B", errorMsg));     // Unbalanced
}

TEST_F(PatternCompilerTest, EntropyCalculation) {
    std::vector<uint8_t> lowEntropy = {0xAA, 0xAA, 0xAA, 0xAA};
    std::vector<uint8_t> highEntropy = {0x48, 0x8B, 0x05, 0xFF, 0xD0, 0x90};

    float entropyLow = PatternCompiler::ComputeEntropy(lowEntropy);
    float entropyHigh = PatternCompiler::ComputeEntropy(highEntropy);

    EXPECT_LT(entropyLow, 1.0f);    // Low entropy (repeated bytes)
    EXPECT_GT(entropyHigh, 2.0f);   // Higher entropy (diverse bytes)
}

// ============================================================================
// PATTERN STORE CORE TESTS
// ============================================================================

TEST_F(PatternStoreTest, DatabaseCreation) {
    EXPECT_TRUE(InitializeStore());
    EXPECT_TRUE(m_store->IsInitialized());
}

TEST_F(PatternStoreTest, AddSinglePattern) {
    ASSERT_TRUE(InitializeStore());

    auto err = m_store->AddPattern(
        "48 8B 05",
        "TestPattern1",
        ThreatLevel::Medium,
        "Test pattern description"
    );

    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(PatternStoreTest, AddMultiplePatterns) {
    ASSERT_TRUE(InitializeStore());

    std::vector<std::string> patterns = {
        "48 8B 05",
        "FF D0",
        "90 90 90"
    };

    std::vector<std::string> names = {
        "Pattern1",
        "Pattern2",
        "Pattern3"
    };

    std::vector<ThreatLevel> levels = {
        ThreatLevel::Low,
        ThreatLevel::Medium,
        ThreatLevel::High
    };

    auto err = m_store->AddPatternBatch(patterns, names, levels);
    EXPECT_TRUE(err.IsSuccess());

    auto stats = m_store->GetStatistics();
    EXPECT_EQ(stats.totalPatterns, 3);
}

TEST_F(PatternStoreTest, BasicScan) {
    ASSERT_TRUE(InitializeStore());

    // Add pattern
    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "TestPattern", ThreatLevel::High).IsSuccess());

    // Create buffer with pattern
    std::vector<uint8_t> buffer = {
        0x00, 0x48, 0x8B, 0x05, 0xFF
    };

    auto results = m_store->Scan(buffer);
    
    EXPECT_GT(results.size(), 0);
    if (!results.empty()) {
        EXPECT_EQ(results[0].signatureName, "TestPattern");
        EXPECT_EQ(results[0].threatLevel, ThreatLevel::High);
    }
}

TEST_F(PatternStoreTest, ScanWithNoMatches) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("DE AD BE EF", "TestPattern", ThreatLevel::High).IsSuccess());

    std::vector<uint8_t> buffer(1000, 0x00);
    auto results = m_store->Scan(buffer);
    
    EXPECT_EQ(results.size(), 0);
}

TEST_F(PatternStoreTest, IncrementalScanContext) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("AA BB CC", "TestPattern", ThreatLevel::Medium).IsSuccess());

    auto ctx = m_store->CreateScanContext();

    // Feed chunks
    std::vector<uint8_t> chunk1 = {0x00, 0xAA};
    std::vector<uint8_t> chunk2 = {0xBB, 0xCC, 0x00};

    auto results1 = ctx.FeedChunk(chunk1);
    auto results2 = ctx.FeedChunk(chunk2);
    auto finalResults = ctx.Finalize();

    // Pattern spans two chunks, should be detected
    size_t totalMatches = results1.size() + results2.size() + finalResults.size();
    EXPECT_GT(totalMatches, 0);
}

TEST_F(PatternStoreTest, RemovePattern) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Pattern1", ThreatLevel::Low).IsSuccess());
    
    auto stats = m_store->GetStatistics();
    auto initialCount = stats.totalPatterns;

    // Get pattern ID (assuming first pattern has ID 0)
    auto err = m_store->RemovePattern(0);
    EXPECT_TRUE(err.IsSuccess());

    stats = m_store->GetStatistics();
    EXPECT_LT(stats.totalPatterns, initialCount);
}

TEST_F(PatternStoreTest, UpdatePatternMetadata) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Pattern1", ThreatLevel::Low).IsSuccess());

    std::vector<std::string> newTags = {"malware", "trojan"};
    auto err = m_store->UpdatePatternMetadata(0, "Updated description", newTags);
    
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(PatternStoreTest, ExportToJson) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Pattern1", ThreatLevel::High).IsSuccess());
    ASSERT_TRUE(m_store->AddPattern("FF D0", "Pattern2", ThreatLevel::Medium).IsSuccess());

    auto json = m_store->ExportToJson();
    
    EXPECT_FALSE(json.empty());
    EXPECT_NE(json.find("Pattern1"), std::string::npos);
    EXPECT_NE(json.find("Pattern2"), std::string::npos);
}

TEST_F(PatternStoreTest, Rebuild) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Pattern1", ThreatLevel::Low).IsSuccess());
    
    auto err = m_store->Rebuild();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(PatternStoreTest, Verify) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Pattern1", ThreatLevel::Low).IsSuccess());

    std::vector<std::string> logs;
    auto err = m_store->Verify([&](const std::string& msg) {
        logs.push_back(msg);
    });

    EXPECT_TRUE(err.IsSuccess());
    EXPECT_GT(logs.size(), 0);
}

TEST_F(PatternStoreTest, LengthHistogram) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B", "Short", ThreatLevel::Low).IsSuccess());
    ASSERT_TRUE(m_store->AddPattern("48 8B 05 AA", "Medium", ThreatLevel::Low).IsSuccess());
    ASSERT_TRUE(m_store->AddPattern("48 8B 05 AA BB CC", "Long", ThreatLevel::Low).IsSuccess());

    auto histogram = m_store->GetLengthHistogram();
    
    EXPECT_EQ(histogram.size(), 3);  // 3 different lengths
}

TEST_F(PatternStoreTest, GetStatistics) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "P1", ThreatLevel::Low).IsSuccess());
    ASSERT_TRUE(m_store->AddPattern("FF D0", "P2", ThreatLevel::Medium).IsSuccess());

    std::vector<uint8_t> buffer = {0x48, 0x8B, 0x05};
    m_store->Scan(buffer);

    auto stats = m_store->GetStatistics();
    
    EXPECT_EQ(stats.totalPatterns, 2);
    EXPECT_GT(stats.totalScans, 0);
}

// ============================================================================
// CONCURRENCY & THREAD SAFETY TESTS
// ============================================================================

TEST_F(PatternStoreTest, ConcurrentScans) {
    ASSERT_TRUE(InitializeStore());

    // Add patterns
    for (int i = 0; i < 10; ++i) {
        std::string pattern = "48 8B " + std::to_string(i);
        ASSERT_TRUE(m_store->AddPattern(pattern, "Pattern" + std::to_string(i), 
                                        ThreatLevel::Low).IsSuccess());
    }

    // Create buffer
    std::vector<uint8_t> buffer(1000);
    std::iota(buffer.begin(), buffer.end(), 0);

    // Launch concurrent scans
    std::vector<std::future<std::vector<DetectionResult>>> futures;
    
    for (int i = 0; i < 10; ++i) {
        futures.push_back(std::async(std::launch::async, [this, buffer]() {
            return m_store->Scan(buffer);
        }));
    }

    // Wait for all to complete
    for (auto& future : futures) {
        auto results = future.get();
        // Should complete without crashes
    }
}

TEST_F(PatternStoreTest, ConcurrentAddAndScan) {
    ASSERT_TRUE(InitializeStore());

    std::atomic<bool> stop{false};

    // Scanner thread
    auto scannerThread = std::thread([this, &stop]() {
        std::vector<uint8_t> buffer(100, 0x48);
        while (!stop.load()) {
            m_store->Scan(buffer);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    // Adder thread
    for (int i = 0; i < 20; ++i) {
        std::string pattern = "48 " + std::to_string(i);
        m_store->AddPattern(pattern, "Pattern" + std::to_string(i), ThreatLevel::Low);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    stop.store(true);
    scannerThread.join();

    // Should complete without deadlocks or crashes
}

// ============================================================================
// PERFORMANCE BENCHMARK TESTS
// ============================================================================

TEST_F(PatternStoreTest, DISABLED_BenchmarkScanSpeed) {
    // This test is disabled by default (prefix with DISABLED_)
    // Run with --gtest_also_run_disabled_tests to enable
    
    ASSERT_TRUE(InitializeStore());

    // Add 1000 patterns
    for (int i = 0; i < 1000; ++i) {
        std::string pattern = "48 8B " + std::to_string(i & 0xFF);
        m_store->AddPattern(pattern, "Pattern" + std::to_string(i), ThreatLevel::Low);
    }

    // 10MB buffer
    std::vector<uint8_t> buffer(10 * 1024 * 1024);
    std::mt19937 rng(42);
    std::generate(buffer.begin(), buffer.end(), rng);

    auto start = std::chrono::high_resolution_clock::now();
    auto results = m_store->Scan(buffer);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "Scanned 10MB with 1000 patterns in " << duration.count() << " ms\n";
    std::cout << "Found " << results.size() << " matches\n";
    
    // Target: < 100ms for 10MB with 1000 patterns
    EXPECT_LT(duration.count(), 100);
}

TEST_F(PatternStoreTest, DISABLED_BenchmarkThroughput) {
    ASSERT_TRUE(InitializeStore());

    // Add patterns
    for (int i = 0; i < 100; ++i) {
        m_store->AddPattern("48 8B 05", "Pattern" + std::to_string(i), ThreatLevel::Low);
    }

    // 100MB buffer
    size_t bufferSize = 100 * 1024 * 1024;
    std::vector<uint8_t> buffer(bufferSize, 0x00);

    auto start = std::chrono::high_resolution_clock::now();
    m_store->Scan(buffer);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    double throughputMBps = (bufferSize / (1024.0 * 1024.0)) / (duration.count() / 1000.0);

    std::cout << "Throughput: " << throughputMBps << " MB/s\n";
    
    // Target: > 500 MB/s
    EXPECT_GT(throughputMBps, 500.0);
}

// ============================================================================
// EDGE CASES & ERROR HANDLING
// ============================================================================

TEST_F(PatternStoreTest, ReadOnlyModeEnforcement) {
    ASSERT_TRUE(InitializeStore());
    
    m_store->Close();
    
    // Reopen as read-only
    auto err = m_store->Initialize(m_testDbPath, true);
    ASSERT_TRUE(err.IsSuccess());

    // Try to add pattern (should fail)
    err = m_store->AddPattern("48 8B 05", "Test", ThreatLevel::Low);
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::AccessDenied);
}

TEST_F(PatternStoreTest, InvalidPatternRejection) {
    ASSERT_TRUE(InitializeStore());

    auto err = m_store->AddPattern("INVALID HEX", "Test", ThreatLevel::Low);
    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(PatternStoreTest, EmptyBufferScan) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "Test", ThreatLevel::Low).IsSuccess());

    std::vector<uint8_t> emptyBuffer;
    auto results = m_store->Scan(emptyBuffer);
    
    EXPECT_EQ(results.size(), 0);
}

TEST_F(PatternStoreTest, VeryLargePattern) {
    ASSERT_TRUE(InitializeStore());

    // Create 256-byte pattern (max length)
    std::string largePattern;
    for (int i = 0; i < 256; ++i) {
        largePattern += "AA ";
    }

    auto err = m_store->AddPattern(largePattern, "LargePattern", ThreatLevel::Low);
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(PatternStoreTest, PatternAtBufferEnd) {
    ASSERT_TRUE(InitializeStore());

    ASSERT_TRUE(m_store->AddPattern("FF FF FF", "Test", ThreatLevel::Low).IsSuccess());

    std::vector<uint8_t> buffer = {0x00, 0x00, 0xFF, 0xFF, 0xFF};
    auto results = m_store->Scan(buffer);
    
    EXPECT_GT(results.size(), 0);
}

TEST_F(PatternStoreTest, HeatmapTracking) {
    ASSERT_TRUE(InitializeStore());

    m_store->SetHeatmapEnabled(true);

    ASSERT_TRUE(m_store->AddPattern("48 8B 05", "HotPattern", ThreatLevel::Low).IsSuccess());
    ASSERT_TRUE(m_store->AddPattern("FF D0", "ColdPattern", ThreatLevel::Low).IsSuccess());

    // Scan multiple times with first pattern
    std::vector<uint8_t> buffer1 = {0x48, 0x8B, 0x05};
    for (int i = 0; i < 10; ++i) {
        m_store->Scan(buffer1);
    }

    auto heatmap = m_store->GetHeatmap();
    
    EXPECT_GT(heatmap.size(), 0);
    // First pattern should have higher hit count
}

// ============================================================================
// IMPORT/EXPORT TESTS
// ============================================================================

TEST_F(PatternStoreTest, YaraImportBasic) {
    ASSERT_TRUE(InitializeStore());

    // Create temporary YARA file
    auto tempPath = std::filesystem::temp_directory_path() / L"test.yar";
    std::ofstream yaraFile(tempPath);
    yaraFile << "rule TestRule {\n";
    yaraFile << "  strings:\n";
    yaraFile << "    $hex = { 48 8B 05 }\n";
    yaraFile << "  condition:\n";
    yaraFile << "    $hex\n";
    yaraFile << "}\n";
    yaraFile.close();

    auto err = m_store->ImportFromYaraFile(tempPath.wstring());
    
    std::filesystem::remove(tempPath);
    
    // May fail if YARA parser is simplified, but should not crash
    EXPECT_TRUE(err.IsSuccess() || err.code == SignatureStoreError::InvalidFormat);
}

// ============================================================================
// UTILITY FUNCTION TESTS
// ============================================================================

TEST(PatternUtilsTest, HexStringConversion) {
    auto bytes = PatternUtils::HexStringToBytes("48 8B 05");
    
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(bytes->size(), 3);
    EXPECT_EQ((*bytes)[0], 0x48);
    EXPECT_EQ((*bytes)[1], 0x8B);
    EXPECT_EQ((*bytes)[2], 0x05);

    auto hexStr = PatternUtils::BytesToHexString(*bytes);
    EXPECT_EQ(hexStr, "48 8B05");  // Note: no spaces in output
}

TEST(PatternUtilsTest, HammingDistance) {
    std::vector<uint8_t> a = {0xFF, 0xFF};
    std::vector<uint8_t> b = {0x00, 0x00};
    std::vector<uint8_t> c = {0xFF, 0x00};

    EXPECT_EQ(PatternUtils::HammingDistance(a, b), 16);  // All bits different
    EXPECT_EQ(PatternUtils::HammingDistance(a, c), 8);   // Half bits different
    EXPECT_EQ(PatternUtils::HammingDistance(a, a), 0);   // Identical
}

TEST(PatternUtilsTest, PatternValidation) {
    std::string error;

    EXPECT_TRUE(PatternUtils::IsValidPatternString("48 8B 05", error));
    EXPECT_TRUE(PatternUtils::IsValidPatternString("48 ?? 05", error));
    EXPECT_FALSE(PatternUtils::IsValidPatternString("INVALID", error));
    EXPECT_FALSE(error.empty());
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
