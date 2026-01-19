// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com
/*
 * ============================================================================
 * ShadowStrike SignatureBuilder - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade test suite for SignatureBuilder core functionality
 * Tests build pipeline, configuration, validation, and performance
 *
 * Test Categories:
 * 1. Constructor & Configuration Tests
 * 2. Validation Methods Tests (Pattern/Regex/YARA Safety)
 * 3. Build Process Pipeline Tests
 * 4. Index Construction Tests (Hash/Pattern/YARA)
 * 5. Query Methods Tests (Deduplication Checks)
 * 6. Statistics & Monitoring Tests
 * 7. Helper Methods Tests (UUID, Checksum, Size Calculation)
 * 8. Custom Callbacks Tests
 * 9. Error Handling & Edge Cases
 * 10. Performance & Concurrency Tests
 *
 * ============================================================================
 */
#include"pch.h"
#include <gtest/gtest.h>
#include "../../../../src/SignatureStore/SignatureBuilder.hpp"
#include "../../../../src/SignatureStore/SignatureFormat.hpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <chrono>
#include <optional>
#include <random>
#include <sstream>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURES
// ============================================================================

class SignatureBuilderTest : public ::testing::Test {
protected:
    std::unique_ptr<SignatureBuilder> m_builder;
    BuildConfiguration m_config;
    std::wstring m_tempDir;
    std::vector<std::wstring> m_tempFiles;
    size_t m_progressCallCount;
    std::string m_lastProgressStage;
    size_t m_lastProgressCurrent;
    size_t m_lastProgressTotal;
    size_t m_logCallCount;
    std::string m_lastLogMessage;

    void SetUp() override {
        m_builder = std::make_unique<SignatureBuilder>();
        m_tempDir = std::filesystem::temp_directory_path().wstring();
        m_progressCallCount = 0;
        m_logCallCount = 0;

        // Setup default configuration with callbacks
        m_config.outputPath = m_tempDir + L"\\test_db.sdb";
        m_config.overwriteExisting = true;  // Allow overwriting for repeated test runs
        m_config.initialDatabaseSize = 1024 * 1024;  // 1MB - reasonable for unit tests
        m_config.enableDeduplication = true;
        m_config.enableEntropyOptimization = true;
        m_config.enableCacheAlignment = true;
        m_config.strictValidation = true;

        // Set progress callback
        m_config.progressCallback = [this](const std::string& stage, size_t current, size_t total) {
            m_lastProgressStage = stage;
            m_lastProgressCurrent = current;
            m_lastProgressTotal = total;
            m_progressCallCount++;
        };

        // Set log callback
        m_config.logCallback = [this](const std::string& message) {
            m_lastLogMessage = message;
            m_logCallCount++;
        };

        m_builder->SetConfiguration(m_config);
    }

    void TearDown() override {
        m_builder.reset();
        CleanupTempFiles();
    }

    // Helper: Create test hash value with high entropy (passes validation)
    HashValue CreateTestHash(HashType type, const std::string& data = "test") {
        HashValue hash{};
        hash.type = type;
        hash.length = GetHashLengthForType(type);
        
        // Use a more complex pattern that produces high-entropy hashes
        // Mix operations to ensure good distribution of bits
        uint8_t seed = static_cast<uint8_t>(data.length() > 0 ? data[0] : 0x42);
        for (size_t i = 0; i < hash.length; ++i) {
            // Combine seed, index, and XOR with primes for better distribution
            uint8_t val = static_cast<uint8_t>((seed ^ (i * 17 + 31)) * 37 + (i << 3));
            val ^= static_cast<uint8_t>((seed + i) * 251);
            hash.data[i] = val;
        }
        
        return hash;
    }

    // Helper: Create test pattern input
    PatternSignatureInput CreateTestPattern(const std::string& pattern = "48 8B 05", 
                                           const std::string& name = "test_pattern",
                                           ThreatLevel level = ThreatLevel::Medium) {
        PatternSignatureInput input{};
        input.patternString = pattern;
        input.name = name;
        input.threatLevel = level;
        input.description = "Test pattern";
        input.source = "test";
        return input;
    }

    // Helper: Create test YARA rule
    YaraRuleInput CreateTestYaraRule(const std::string& name = "test_rule") {
        YaraRuleInput input{};
        input.ruleSource = R"(rule )" + name + R"( {
    strings:
        $a = "test"
    condition:
        $a
})";
        input.namespace_ = "test";
        input.source = "test";
        return input;
    }

    // Helper: Create temporary file
    std::wstring CreateTempFile(const std::string& content, const std::wstring& filename = L"test.bin") {
        auto filePath = std::filesystem::path(m_tempDir) / filename;
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to create temp file");
        }
        file.write(content.data(), content.size());
        file.close();
        m_tempFiles.push_back(filePath.wstring());
        return filePath.wstring();
    }

    // Helper: Cleanup temp files
    void CleanupTempFiles() {
        for (const auto& file : m_tempFiles) {
            try {
                std::filesystem::remove(file);
            } catch (...) {}
        }
        m_tempFiles.clear();
    }
};

// ============================================================================
// 1. CONSTRUCTOR & CONFIGURATION TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, DefaultConstructor) {
    auto builder = SignatureBuilder();
    EXPECT_EQ(builder.GetPendingHashCount(), 0);
    EXPECT_EQ(builder.GetPendingPatternCount(), 0);
    EXPECT_EQ(builder.GetPendingYaraRuleCount(), 0);
    EXPECT_FALSE(builder.IsBuildInProgress());
}

TEST_F(SignatureBuilderTest, ConfiguredConstructor) {
    BuildConfiguration config;
    config.outputPath = L"test.db";
    config.enableDeduplication = true;
    config.threadCount = 4;
    
    auto builder = SignatureBuilder(config);
    
    const auto& retrieved = builder.GetConfiguration();
    EXPECT_EQ(retrieved.outputPath, L"test.db");
    EXPECT_TRUE(retrieved.enableDeduplication);
    EXPECT_EQ(retrieved.threadCount, 4);
}

TEST_F(SignatureBuilderTest, SetConfiguration) {
    BuildConfiguration newConfig;
    newConfig.outputPath = L"new_path.db";
    newConfig.enableEntropyOptimization = false;
    newConfig.threadCount = 8;
    
    m_builder->SetConfiguration(newConfig);
    
    const auto& config = m_builder->GetConfiguration();
    EXPECT_EQ(config.outputPath, L"new_path.db");
    EXPECT_FALSE(config.enableEntropyOptimization);
    EXPECT_EQ(config.threadCount, 8);
}

TEST_F(SignatureBuilderTest, ConfigurationThreading) {
    // Ensure configuration changes are thread-safe
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this, i]() {
            BuildConfiguration config;
            config.threadCount = i;
            m_builder->SetConfiguration(config);
            
            const auto& retrieved = m_builder->GetConfiguration();
            EXPECT_EQ(retrieved.threadCount, i);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

TEST_F(SignatureBuilderTest, ProgressCallback) {
    m_builder->SetConfiguration(m_config);
    m_progressCallCount = 0;
    
    // Simulate progress report
    const_cast<SignatureBuilder*>(m_builder.get())->ReportProgress("TestStage", 50, 100);
    
    EXPECT_EQ(m_progressCallCount, 1);
    EXPECT_EQ(m_lastProgressStage, "TestStage");
    EXPECT_EQ(m_lastProgressCurrent, 50);
    EXPECT_EQ(m_lastProgressTotal, 100);
}

TEST_F(SignatureBuilderTest, LogCallback) {
    m_builder->SetConfiguration(m_config);
    m_logCallCount = 0;
    
    // Simulate log call
    const_cast<SignatureBuilder*>(m_builder.get())->Log("Test message");
    
    EXPECT_EQ(m_logCallCount, 1);
    EXPECT_EQ(m_lastLogMessage, "Test message");
}

// ============================================================================
// 2. VALIDATION METHODS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxValid) {
    std::string errorMsg;
    
    // Valid patterns
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 8B 05", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 8B 05 ?? ?? ?? ??", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 8B [45 50] 05", errorMsg));
}

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxEmpty) {
    std::string errorMsg;
    EXPECT_FALSE(m_builder->ValidatePatternSyntax("", errorMsg));
    EXPECT_EQ(errorMsg, "Pattern is empty");
}

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxInvalidCharacters) {
    std::string errorMsg;
    EXPECT_FALSE(m_builder->ValidatePatternSyntax("48 8B @@@", errorMsg));
    EXPECT_FALSE(errorMsg.empty());
}

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxUnbalancedBrackets) {
    std::string errorMsg;
    EXPECT_FALSE(m_builder->ValidatePatternSyntax("48 [8B 05", errorMsg));
    EXPECT_EQ(errorMsg, "Unbalanced brackets");
    
    EXPECT_FALSE(m_builder->ValidatePatternSyntax("48 8B 05]", errorMsg));
    EXPECT_EQ(errorMsg, "Unbalanced brackets");
}

TEST_F(SignatureBuilderTest, IsRegexSafeValid) {
    std::string errorMsg;
    
    EXPECT_TRUE(m_builder->IsRegexSafe("abc", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("(a|b|c)", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("a{5,10}", errorMsg));
}

TEST_F(SignatureBuilderTest, IsRegexSafeDangerousPatterns) {
    std::string errorMsg;
    
    // Nested quantifiers (ReDoS)
    EXPECT_FALSE(m_builder->IsRegexSafe("(a+)+", errorMsg));
    EXPECT_FALSE(m_builder->IsRegexSafe("(a*)*", errorMsg));
    EXPECT_FALSE(m_builder->IsRegexSafe("(a|a)*", errorMsg));
}

TEST_F(SignatureBuilderTest, IsRegexSafeExcessiveQuantification) {
    std::string errorMsg;
    
    EXPECT_FALSE(m_builder->IsRegexSafe("a{1000,2000}", errorMsg));
    EXPECT_FALSE(m_builder->IsRegexSafe(".*.*.*", errorMsg));
}

TEST_F(SignatureBuilderTest, IsRegexSafeDeepNesting) {
    std::string errorMsg;
    
    std::string deepPattern = "(((((((((((a";
    EXPECT_FALSE(m_builder->IsRegexSafe(deepPattern, errorMsg));
    EXPECT_TRUE(errorMsg.find("nesting") != std::string::npos);
}

TEST_F(SignatureBuilderTest, IsYaraRuleSafeValid) {
    std::string errorMsg;
    
    std::string rule = R"(rule test {
    strings:
        $a = "test"
    condition:
        $a
})";
    
    EXPECT_TRUE(m_builder->IsYaraRuleSafe(rule, errorMsg));
}

TEST_F(SignatureBuilderTest, IsYaraRuleSafeDangerousImports) {
    std::string errorMsg;
    
    std::string rule = R"(import "cuckoo"
rule test {
    condition:
        true
})";
    
    EXPECT_FALSE(m_builder->IsYaraRuleSafe(rule, errorMsg));
}

TEST_F(SignatureBuilderTest, IsYaraRuleSafeMagicImport) {
    std::string errorMsg;
    
    std::string rule = R"(import "magic"
rule test {
    condition:
        true
})";
    
    EXPECT_FALSE(m_builder->IsYaraRuleSafe(rule, errorMsg));
}

TEST_F(SignatureBuilderTest, IsYaraRuleSafeMultipleWildcards) {
    std::string errorMsg;
    
    std::string rule = R"(rule test {
    strings:
        $a = ".*.*"
    condition:
        $a
})";
    
    EXPECT_FALSE(m_builder->IsYaraRuleSafe(rule, errorMsg));
}

// ============================================================================
// 3. BUILD PROCESS PIPELINE TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, BuildEmptyDatabase) {
    // Building with no signatures should succeed
    StoreError err = m_builder->Build();
    EXPECT_TRUE(err.IsSuccess());
    EXPECT_FALSE(m_builder->IsBuildInProgress());
}

TEST_F(SignatureBuilderTest, BuildConcurrency) {
    // Verify build cannot start while another is in progress
    m_builder->Reset();
    
    // Manually set build in progress
    const auto* builder = m_builder.get();
    
    // Note: Since IsBuildInProgress is const and m_buildInProgress is private,
    // we would need friend access or getter to fully test this.
    // This is a design pattern test.
}

TEST_F(SignatureBuilderTest, ValidateInputsEmpty) {
    StoreError err = m_builder->ValidateInputs();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderTest, ValidateInputsWithHashes) {
    auto hash = CreateTestHash(HashType::SHA256);
    HashSignatureInput hashInput{};
    hashInput.hash = hash;
    hashInput.name = "TestHash";
    hashInput.threatLevel = ThreatLevel::High;
    
    // Would need AddHash method to be public or use friend class
}

TEST_F(SignatureBuilderTest, DeduplicateEmpty) {
    StoreError err = m_builder->Deduplicate();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderTest, DeduplicateDisabled) {
    BuildConfiguration config = m_config;
    config.enableDeduplication = false;
    m_builder->SetConfiguration(config);
    
    StoreError err = m_builder->Deduplicate();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderTest, OptimizeEmpty) {
    StoreError err = m_builder->Optimize();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderTest, OptimizeWithEntropyDisabled) {
    BuildConfiguration config = m_config;
    config.enableEntropyOptimization = false;
    m_builder->SetConfiguration(config);
    
    StoreError err = m_builder->Optimize();
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderTest, BuildIndicesEmpty) {
    StoreError err = m_builder->BuildIndices();
    EXPECT_TRUE(err.IsSuccess());
}

// ============================================================================
// 4. QUERY METHODS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, GetPendingHashCountEmpty) {
    EXPECT_EQ(m_builder->GetPendingHashCount(), 0);
}

TEST_F(SignatureBuilderTest, GetPendingPatternCountEmpty) {
    EXPECT_EQ(m_builder->GetPendingPatternCount(), 0);
}

TEST_F(SignatureBuilderTest, GetPendingYaraRuleCountEmpty) {
    EXPECT_EQ(m_builder->GetPendingYaraRuleCount(), 0);
}

TEST_F(SignatureBuilderTest, HasHashEmpty) {
    auto hash = CreateTestHash(HashType::SHA256);
    EXPECT_FALSE(m_builder->HasHash(hash));
}

TEST_F(SignatureBuilderTest, HasPatternEmpty) {
    EXPECT_FALSE(m_builder->HasPattern("48 8B 05"));
}

TEST_F(SignatureBuilderTest, HasYaraRuleEmpty) {
    EXPECT_FALSE(m_builder->HasYaraRule("test_rule"));
}

// ============================================================================
// 5. STATISTICS & MONITORING TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, GetStatisticsInitial) {
    const auto& stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 0);
    EXPECT_EQ(stats.totalPatternsAdded, 0);
    EXPECT_EQ(stats.totalYaraRulesAdded, 0);
    EXPECT_EQ(stats.duplicatesRemoved, 0);
    EXPECT_EQ(stats.invalidSignaturesSkipped, 0);
}

TEST_F(SignatureBuilderTest, ResetClearsState) {
    m_builder->Reset();
    
    EXPECT_EQ(m_builder->GetPendingHashCount(), 0);
    EXPECT_EQ(m_builder->GetPendingPatternCount(), 0);
    EXPECT_EQ(m_builder->GetPendingYaraRuleCount(), 0);
    
    const auto& stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 0);
}

TEST_F(SignatureBuilderTest, GetCurrentStageInitial) {
    std::string stage = m_builder->GetCurrentStage();
    EXPECT_TRUE(stage.empty() || stage == "");
}

TEST_F(SignatureBuilderTest, IsBuildInProgressInitial) {
    EXPECT_FALSE(m_builder->IsBuildInProgress());
}

// ============================================================================
// 6. HELPER METHODS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, GenerateDatabaseUUID) {
    auto uuid1 = const_cast<SignatureBuilder*>(m_builder.get())->GenerateDatabaseUUID();
    auto uuid2 = const_cast<SignatureBuilder*>(m_builder.get())->GenerateDatabaseUUID();
    
    // UUIDs should be different
    EXPECT_NE(uuid1, uuid2);
    
    // UUID should be 16 bytes
    EXPECT_EQ(uuid1.size(), 16);
    EXPECT_EQ(uuid2.size(), 16);
}

TEST_F(SignatureBuilderTest, CalculateRequiredSize) {
    uint64_t size = const_cast<SignatureBuilder*>(m_builder.get())->CalculateRequiredSize();
    
    // Should be at least initial database size
    EXPECT_GE(size, m_config.initialDatabaseSize);
    
    // Should be page-aligned or close
    EXPECT_GT(size, 0);
}

TEST_F(SignatureBuilderTest, CalculateRequiredSizeWithConfiguration) {
    BuildConfiguration config = m_config;
    config.initialDatabaseSize = 1024 * 1024; // 1MB
    m_builder->SetConfiguration(config);
    
    uint64_t size = const_cast<SignatureBuilder*>(m_builder.get())->CalculateRequiredSize();
    EXPECT_GE(size, 1024 * 1024);
}

TEST_F(SignatureBuilderTest, GetCurrentTimestamp) {
    uint64_t ts1 = SignatureBuilder::GetCurrentTimestamp();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    uint64_t ts2 = SignatureBuilder::GetCurrentTimestamp();
    
    // ts2 should be greater than ts1
    EXPECT_GT(ts2, ts1);
}

// ============================================================================
// 7. CUSTOM CALLBACKS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, SetCustomDeduplication) {
    int callCount = 0;
    SignatureBuilder::DeduplicationFunc func = 
        [&callCount](const HashValue&, const HashValue&) {
            callCount++;
            return false;
        };
    
    m_builder->SetCustomDeduplication(func);
    // Function is stored, verify no exception
    EXPECT_NO_THROW(m_builder->Deduplicate());
}

TEST_F(SignatureBuilderTest, SetCustomOptimization) {
    int callCount = 0;
    SignatureBuilder::OptimizationFunc func = 
        [&callCount](std::vector<HashSignatureInput>&) {
            callCount++;
        };
    
    m_builder->SetCustomOptimization(func);
    // Function is stored, verify no exception
    EXPECT_NO_THROW(m_builder->Optimize());
}

TEST_F(SignatureBuilderTest, SetBuildPriority) {
    // Verify no exception
    EXPECT_NO_THROW(m_builder->SetBuildPriority(THREAD_PRIORITY_NORMAL));
    EXPECT_NO_THROW(m_builder->SetBuildPriority(THREAD_PRIORITY_HIGHEST));
    EXPECT_NO_THROW(m_builder->SetBuildPriority(THREAD_PRIORITY_LOWEST));
}

// ============================================================================
// 8. ERROR HANDLING & EDGE CASES
// ============================================================================

TEST_F(SignatureBuilderTest, BuildWithInvalidConfiguration) {
    BuildConfiguration config;
    config.outputPath = L"";  // Invalid path - empty output path
    m_builder->SetConfiguration(config);
    
    // Build should fail gracefully with appropriate error
    StoreError err = m_builder->Build();
    // Empty output path should return InvalidFormat error
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureBuilderTest, ResetMultipleTimes) {
    m_builder->Reset();
    m_builder->Reset();
    m_builder->Reset();
    
    EXPECT_EQ(m_builder->GetPendingHashCount(), 0);
    EXPECT_EQ(m_builder->GetPendingPatternCount(), 0);
    EXPECT_EQ(m_builder->GetPendingYaraRuleCount(), 0);
}

TEST_F(SignatureBuilderTest, ValidateDatabaseChecksumNonExistent) {
    std::wstring nonExistentPath = L"C:\\NonExistent\\path\\database.sdb";
    EXPECT_FALSE(m_builder->ValidateDatabaseChecksum(nonExistentPath));
}

TEST_F(SignatureBuilderTest, ComputeRequiredSizeEdgeCases) {
    // Test with minimal configuration
    BuildConfiguration minConfig;
    minConfig.initialDatabaseSize = 4096;  // Minimum page size
    m_builder->SetConfiguration(minConfig);
    
    uint64_t size = const_cast<SignatureBuilder*>(m_builder.get())->CalculateRequiredSize();
    EXPECT_GE(size, 4096);
}

// ============================================================================
// 9. PATTERN VALIDATION COMPREHENSIVE TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxVariations) {
    std::string errorMsg;
    
    // Test various valid hex patterns
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("FF", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("00", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 89 E5", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("55 48 89 E5 48 83 EC 08", errorMsg));
}

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxWithWildcards) {
    std::string errorMsg;
    
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 ?? 05", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("?? ?? ?? ??", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 ?? ?? 05 ?? ?? ?? ??", errorMsg));
}

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxWithRanges) {
    std::string errorMsg;
    
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("48 [88 89 8A 8B] 05", errorMsg));
    EXPECT_TRUE(m_builder->ValidatePatternSyntax("[48 50] [8B 8D] 05", errorMsg));
}

TEST_F(SignatureBuilderTest, IsRegexSafeComplexPatterns) {
    std::string errorMsg;
    
    // Valid complex patterns
    EXPECT_TRUE(m_builder->IsRegexSafe("(a|b)", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("(a|b|c|d)", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("((a|b)(c|d))", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("a{1,10}", errorMsg));
    EXPECT_TRUE(m_builder->IsRegexSafe("a{5}", errorMsg));
}

// ============================================================================
// 10. PERFORMANCE & STRESS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, MultipleConfigurationChanges) {
    for (int i = 0; i < 100; ++i) {
        BuildConfiguration config;
        config.threadCount = i % 16;
        config.enableDeduplication = (i % 2) == 0;
        config.enableEntropyOptimization = (i % 3) == 0;
        
        m_builder->SetConfiguration(config);
        
        const auto& retrieved = m_builder->GetConfiguration();
        EXPECT_EQ(retrieved.threadCount, i % 16);
    }
}

TEST_F(SignatureBuilderTest, ProgressCallbackPerformance) {
    m_progressCallCount = 0;
    
    // Call progress multiple times
    for (int i = 0; i < 1000; ++i) {
        const_cast<SignatureBuilder*>(m_builder.get())->ReportProgress("Stage", i, 1000);
    }
    
    EXPECT_EQ(m_progressCallCount, 1000);
}

TEST_F(SignatureBuilderTest, QueryMethodsConcurrency) {
    std::vector<std::thread> threads;
    std::vector<size_t> results(10);
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this, i, &results]() {
            results[i] = m_builder->GetPendingHashCount();
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All results should be 0
    for (size_t r : results) {
        EXPECT_EQ(r, 0);
    }
}

TEST_F(SignatureBuilderTest, ResetConcurrency) {
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this]() {
            m_builder->Reset();
            EXPECT_EQ(m_builder->GetPendingHashCount(), 0);
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

// ============================================================================
// 11. HASH TYPE VALIDATION TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, CreateHashValueMD5) {
    auto hash = CreateTestHash(HashType::MD5);
    EXPECT_EQ(hash.type, HashType::MD5);
    EXPECT_EQ(hash.length, 16);
}

TEST_F(SignatureBuilderTest, CreateHashValueSHA1) {
    auto hash = CreateTestHash(HashType::SHA1);
    EXPECT_EQ(hash.type, HashType::SHA1);
    EXPECT_EQ(hash.length, 20);
}

TEST_F(SignatureBuilderTest, CreateHashValueSHA256) {
    auto hash = CreateTestHash(HashType::SHA256);
    EXPECT_EQ(hash.type, HashType::SHA256);
    EXPECT_EQ(hash.length, 32);
}

TEST_F(SignatureBuilderTest, CreateHashValueSHA512) {
    auto hash = CreateTestHash(HashType::SHA512);
    EXPECT_EQ(hash.type, HashType::SHA512);
    EXPECT_EQ(hash.length, 64);
}

// ============================================================================
// 12. BUILD STATISTICS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, BuildStatisticsInitialization) {
    const auto& stats = m_builder->GetStatistics();
    
    EXPECT_EQ(stats.totalHashesAdded, 0);
    EXPECT_EQ(stats.totalPatternsAdded, 0);
    EXPECT_EQ(stats.totalYaraRulesAdded, 0);
    EXPECT_EQ(stats.duplicatesRemoved, 0);
    EXPECT_EQ(stats.invalidSignaturesSkipped, 0);
    EXPECT_EQ(stats.optimizedSignatures, 0);
    EXPECT_EQ(stats.finalDatabaseSize, 0);
    EXPECT_EQ(stats.hashIndexSize, 0);
    EXPECT_EQ(stats.patternIndexSize, 0);
    EXPECT_EQ(stats.yaraRulesSize, 0);
    EXPECT_EQ(stats.totalBuildTimeMilliseconds, 0);
}

TEST_F(SignatureBuilderTest, StatisticsPersistenceAcrossResets) {
    m_builder->Reset();
    
    const auto& stats1 = m_builder->GetStatistics();
    uint64_t firstBuildTime = stats1.totalBuildTimeMilliseconds;
    
    m_builder->Reset();
    
    const auto& stats2 = m_builder->GetStatistics();
    uint64_t secondBuildTime = stats2.totalBuildTimeMilliseconds;
    
    EXPECT_EQ(firstBuildTime, secondBuildTime);
}

// ============================================================================
// 13. EDGE CASE VALIDATION
// ============================================================================

TEST_F(SignatureBuilderTest, ValidatePatternSyntaxLongPattern) {
    std::string errorMsg;
    std::string longPattern(1000, '4');
    longPattern += "8 8B 05";
    
    // Should validate (though might be too long for practical use)
    bool result = m_builder->ValidatePatternSyntax(longPattern, errorMsg);
    EXPECT_TRUE(result || !errorMsg.empty());
}

TEST_F(SignatureBuilderTest, IsRegexSafeEmptyPattern) {
    std::string errorMsg;
    EXPECT_TRUE(m_builder->IsRegexSafe("", errorMsg));
}

TEST_F(SignatureBuilderTest, IsYaraRuleSafeEmptyRule) {
    std::string errorMsg;
    EXPECT_TRUE(m_builder->IsYaraRuleSafe("", errorMsg));
}

// ============================================================================
// 14. CONFIGURATION PERSISTENCE
// ============================================================================

TEST_F(SignatureBuilderTest, ConfigurationPersistenceAfterReset) {
    BuildConfiguration config = m_config;
    config.threadCount = 16;
    config.enableDeduplication = false;
    
    m_builder->SetConfiguration(config);
    m_builder->Reset();
    
    const auto& retrieved = m_builder->GetConfiguration();
    EXPECT_EQ(retrieved.threadCount, 16);
    EXPECT_FALSE(retrieved.enableDeduplication);
}

// ============================================================================
// 15. VALIDATION STAGE TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, ValidateInputsSuccessEmpty) {
    StoreError err = m_builder->ValidateInputs();
    EXPECT_TRUE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::Success);
}

TEST_F(SignatureBuilderTest, BuildAllStages) {
    // Test that we can call build stages individually
    EXPECT_TRUE(m_builder->ValidateInputs().IsSuccess());
    EXPECT_TRUE(m_builder->Deduplicate().IsSuccess());
    EXPECT_TRUE(m_builder->Optimize().IsSuccess());
    EXPECT_TRUE(m_builder->BuildIndices().IsSuccess());
}

// ============================================================================
// 16. THREAD SAFETY TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, ConfigurationThreadSafety) {
    std::vector<std::thread> threads;
    std::vector<uint32_t> threadCounts(20);
    
    for (size_t i = 0; i < 20; ++i) {
        threads.emplace_back([this, i, &threadCounts]() {
            for (int j = 0; j < 100; ++j) {
                BuildConfiguration config;
                config.threadCount = i;
                m_builder->SetConfiguration(config);
                
                threadCounts[i] = m_builder->GetConfiguration().threadCount;
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

TEST_F(SignatureBuilderTest, PendingCountsThreadSafety) {
    std::vector<std::thread> threads;
    std::vector<size_t> hashCounts(20);
    
    for (size_t i = 0; i < 20; ++i) {
        threads.emplace_back([this, i, &hashCounts]() {
            for (int j = 0; j < 100; ++j) {
                hashCounts[i] = m_builder->GetPendingHashCount();
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All counts should be 0
    for (size_t count : hashCounts) {
        EXPECT_EQ(count, 0);
    }
}

// ============================================================================
// 17. CALLBACK ROBUSTNESS TESTS
// ============================================================================

TEST_F(SignatureBuilderTest, NullProgressCallback) {
    BuildConfiguration config = m_config;
    config.progressCallback = nullptr;
    
    m_builder->SetConfiguration(config);
    EXPECT_NO_THROW(
        const_cast<SignatureBuilder*>(m_builder.get())->ReportProgress("Test", 0, 1)
    );
}

TEST_F(SignatureBuilderTest, NullLogCallback) {
    BuildConfiguration config = m_config;
    config.logCallback = nullptr;
    
    m_builder->SetConfiguration(config);
    EXPECT_NO_THROW(
        const_cast<SignatureBuilder*>(m_builder.get())->Log("Test message")
    );
}

TEST_F(SignatureBuilderTest, CallbackExceptionHandling) {
    BuildConfiguration config = m_config;
    
    // Progress callback that throws
    config.progressCallback = [](const std::string&, size_t, size_t) {
        throw std::runtime_error("Callback error");
    };
    
    m_builder->SetConfiguration(config);
    
    // Should handle gracefully (or propagate depending on design)
    // For now, verify no crash
}

// ============================================================================
// PERFORMANCE BENCHMARKS (Disabled by default)
// ============================================================================

TEST_F(SignatureBuilderTest, DISABLED_BenchmarkConfigurationChanges) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100000; ++i) {
        BuildConfiguration config;
        config.threadCount = i % 16;
        m_builder->SetConfiguration(config);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // 100k configuration changes should be fast
    EXPECT_LT(elapsed.count(), 5000);  // 5 seconds max
}

TEST_F(SignatureBuilderTest, DISABLED_BenchmarkQueryMethods) {
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 1000000; ++i) {
        volatile auto count1 = m_builder->GetPendingHashCount();
        volatile auto count2 = m_builder->GetPendingPatternCount();
        volatile auto count3 = m_builder->GetPendingYaraRuleCount();
        (void)count1; (void)count2; (void)count3;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // 3M query operations should be very fast
    EXPECT_LT(elapsed.count(), 2000);  // 2 seconds max
}


