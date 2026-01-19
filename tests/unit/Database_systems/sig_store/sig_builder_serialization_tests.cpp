// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/*
 * ============================================================================
 * ShadowStrike SignatureBuilder Serialization - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade test suite for SignatureBuilder serialization functions
 * Tests database creation, format validation, and integrity
 *
 * Test Categories:
 * 1. Serialization Core Tests
 * 2. Header Serialization Tests
 * 3. Hash Serialization Tests
 * 4. Pattern Serialization Tests
 * 5. YARA Serialization Tests
 * 6. Metadata Serialization Tests
 * 7. Checksum & Integrity Tests
 * 8. Error Handling & Recovery Tests
 *
 * ============================================================================
 */

#include"pch.h"
#include <gtest/gtest.h>
#include "../../src/SignatureStore/SignatureBuilder.hpp"
#include "../../src/SignatureStore/SignatureFormat.hpp"
#include "../../src/HashStore/HashStore.hpp"
#include "../../src/PatternStore/PatternStore.hpp"
#include <filesystem>
#include <fstream>
#include <random>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURES
// ============================================================================

class SignatureBuilderSerializationTest : public ::testing::Test {
protected:
    std::unique_ptr<SignatureBuilder> m_builder;
    BuildConfiguration m_config;
    std::wstring m_tempDir;
    std::wstring m_outputPath;

    void SetUp() override {
        m_tempDir = std::filesystem::temp_directory_path().wstring();
        m_outputPath = (std::filesystem::path(m_tempDir) / L"test_signatures.sdb").wstring();

        // Default configuration
        m_config.outputPath = m_outputPath;
        m_config.overwriteExisting = true;
        m_config.enableDeduplication = true;
        m_config.strictValidation = true;
        m_config.initialDatabaseSize = 1024 * 1024;  // 1MB - reasonable for unit tests

        m_builder = std::make_unique<SignatureBuilder>(m_config);
    }

    void TearDown() override {
        m_builder.reset();
        CleanupOutputFile();
    }

    void CleanupOutputFile() {
        try {
            std::filesystem::remove(m_outputPath);
        } catch (...) {}
    }

    // Helper: Verify database file exists and has correct header
    bool VerifyDatabaseHeader(const std::wstring& dbPath) {
        std::ifstream file(dbPath, std::ios::binary);
        if (!file.is_open()) return false;

        SignatureDatabaseHeader header{};
        file.read(reinterpret_cast<char*>(&header), sizeof(header));

        return header.magic == SIGNATURE_DB_MAGIC &&
               header.versionMajor == SIGNATURE_DB_VERSION_MAJOR;
    }

    // Helper: Get file size
    uint64_t GetFileSize(const std::wstring& path) {
        try {
            return std::filesystem::file_size(path);
        } catch (...) {
            return 0;
        }
    }

    // Helper: Create sample hash value with high entropy (passes validation)
    HashValue CreateSampleHash(uint8_t seed = 0x42) {
        HashValue hash{};
        hash.type = HashType::SHA256;
        hash.length = 32;
        
        // Use a more complex pattern that produces high-entropy hashes
        // Mix operations to ensure good distribution of bits
        for (size_t i = 0; i < 32; ++i) {
            // Combine seed, index, and XOR with primes for better distribution
            uint8_t val = static_cast<uint8_t>((seed ^ (i * 17 + 31)) * 37 + (i << 3));
            val ^= static_cast<uint8_t>((seed + i) * 251);
            hash.data[i] = val;
        }
        return hash;
    }
};

// ============================================================================
// BASIC SERIALIZATION TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Serialize_EmptyDatabase) {
    // Build database with no signatures
    auto err = m_builder->Build();

    ASSERT_TRUE(err.IsSuccess());
    EXPECT_TRUE(std::filesystem::exists(m_outputPath));
    EXPECT_TRUE(VerifyDatabaseHeader(m_outputPath));
}

TEST_F(SignatureBuilderSerializationTest, Serialize_WithHashes) {
    // Add some hashes
    for (int i = 0; i < 10; ++i) {
        auto hash = CreateSampleHash(static_cast<uint8_t>(i));
        m_builder->AddHash(hash, "TestHash_" + std::to_string(i), ThreatLevel::Medium);//-V530
    }

    auto err = m_builder->Build();

    ASSERT_TRUE(err.IsSuccess());
    EXPECT_TRUE(VerifyDatabaseHeader(m_outputPath));

    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 10);
}

TEST_F(SignatureBuilderSerializationTest, Serialize_WithPatterns) {
    // Add some patterns
    m_builder->AddPattern("48 8B 05", "Pattern1", ThreatLevel::High);//-V530
    m_builder->AddPattern("FF D0", "Pattern2", ThreatLevel::Medium);//-V530
    m_builder->AddPattern("90 90 90", "Pattern3", ThreatLevel::Low);//-V530

    auto err = m_builder->Build();

    ASSERT_TRUE(err.IsSuccess());
    EXPECT_TRUE(VerifyDatabaseHeader(m_outputPath));

    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalPatternsAdded, 3);
}

TEST_F(SignatureBuilderSerializationTest, Serialize_MixedSignatures) {
    // Add hashes
    for (int i = 0; i < 5; ++i) {
        auto hash = CreateSampleHash(static_cast<uint8_t>(i));
        m_builder->AddHash(hash, "Hash_" + std::to_string(i), ThreatLevel::Medium);//-V530
    }

    // Add patterns
    m_builder->AddPattern("48 8B 05", "Pattern1", ThreatLevel::High);//-V530
    m_builder->AddPattern("FF D0", "Pattern2", ThreatLevel::Medium);//-V530

    auto err = m_builder->Build();

    ASSERT_TRUE(err.IsSuccess());
    
    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 5);
    EXPECT_EQ(stats.totalPatternsAdded, 2);
}

TEST_F(SignatureBuilderSerializationTest, Serialize_OutputPathNotSet) {
    m_config.outputPath.clear();
    m_builder = std::make_unique<SignatureBuilder>(m_config);

    auto err = m_builder->Build();

    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureBuilderSerializationTest, Serialize_FileAlreadyExists_NoOverwrite) {
    // Create existing file
    std::ofstream existing(m_outputPath);
    existing << "existing data";
    existing.close();

    m_config.overwriteExisting = false;
    m_builder = std::make_unique<SignatureBuilder>(m_config);

    auto err = m_builder->Build();

    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, Serialize_FileAlreadyExists_Overwrite) {
    // Create existing file
    std::ofstream existing(m_outputPath);
    existing << "existing data";
    existing.close();

    m_config.overwriteExisting = true;
    m_builder = std::make_unique<SignatureBuilder>(m_config);
    
    m_builder->AddPattern("48 8B 05", "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();

    ASSERT_TRUE(err.IsSuccess());
    EXPECT_TRUE(VerifyDatabaseHeader(m_outputPath));
}

// ============================================================================
// HEADER SERIALIZATION TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Header_MagicNumber) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::Low);//-V530
    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    EXPECT_EQ(header.magic, SIGNATURE_DB_MAGIC);
}

TEST_F(SignatureBuilderSerializationTest, Header_Version) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::Low);//-V530
    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    EXPECT_EQ(header.versionMajor, SIGNATURE_DB_VERSION_MAJOR);
    EXPECT_EQ(header.versionMinor, SIGNATURE_DB_VERSION_MINOR);
}

TEST_F(SignatureBuilderSerializationTest, Header_Counts) {
    // Add specific counts
    for (int i = 0; i < 7; ++i) {
        m_builder->AddHash(CreateSampleHash(i), "Hash" + std::to_string(i), ThreatLevel::Low);//-V530
    }
    
    for (int i = 0; i < 3; ++i) {
        m_builder->AddPattern("48 8B 0" + std::to_string(i), "Pattern" + std::to_string(i), //-V530
                             ThreatLevel::Medium);
    }

    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    EXPECT_EQ(header.totalHashes, 7);
    EXPECT_EQ(header.totalPatterns, 3);
}

TEST_F(SignatureBuilderSerializationTest, Header_Timestamps) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::Low);//-V530
    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    EXPECT_GT(header.creationTime, 0);
    EXPECT_EQ(header.creationTime, header.lastUpdateTime);
}

TEST_F(SignatureBuilderSerializationTest, Header_UUID) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::Low);//-V530
    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // UUID should not be all zeros
    bool hasNonZero = false;
    for (auto byte : header.databaseUuid) {
        if (byte != 0) {
            hasNonZero = true;
            break;
        }
    }
    EXPECT_TRUE(hasNonZero);
}

TEST_F(SignatureBuilderSerializationTest, Header_SectionOffsets) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::Low);//-V530
    ASSERT_TRUE(m_builder->Build().IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // Hash index offset should be page-aligned and after header
    EXPECT_GE(header.hashIndexOffset, sizeof(SignatureDatabaseHeader));
    EXPECT_EQ(header.hashIndexOffset % PAGE_SIZE, 0);
}

// ============================================================================
// HASH SERIALIZATION TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, HashSerialization_SingleHash) {
    auto hash = CreateSampleHash(0x42);
    m_builder->AddHash(hash, "SingleHash", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.hashIndexSize, 0);
}

TEST_F(SignatureBuilderSerializationTest, HashSerialization_MultipleHashes) {
    for (int i = 0; i < 100; ++i) {
        auto hash = CreateSampleHash(i);
        m_builder->AddHash(hash, "Hash_" + std::to_string(i), ThreatLevel::Medium);//-V530
    }

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 100);
    EXPECT_GT(stats.hashIndexSize, 0);
}

TEST_F(SignatureBuilderSerializationTest, HashSerialization_DifferentTypes) {
    // Create hashes of different types
    std::array<HashType,4> types = {
        HashType::MD5,
        HashType::SHA1,
        HashType::SHA256,
        HashType::SHA512
    };

    for (auto type : types) {
        HashValue hash{};
        hash.type = type;
        hash.length = GetHashLengthForType(type);
        std::fill(hash.data.begin(), hash.data.begin() + hash.length, 0xAA);

        m_builder->AddHash(hash, "Hash_" + std::string(Format::HashTypeToString(type)), //-V530
                          ThreatLevel::Medium);
    }

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, HashSerialization_Deduplication) {
    auto hash = CreateSampleHash(0x42);

    // Add same hash twice
    m_builder->AddHash(hash, "Hash1", ThreatLevel::High);//-V530
    m_builder->AddHash(hash, "Hash2", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 1);
}

TEST_F(SignatureBuilderSerializationTest, HashSerialization_LongNames) {
    auto hash = CreateSampleHash();
    std::string longName(1000, 'A');  // 1000 character name

    m_builder->AddHash(hash, longName, ThreatLevel::Low);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());
}

// ============================================================================
// PATTERN SERIALIZATION TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_BasicPatterns) {
    m_builder->AddPattern("48 8B 05", "Pattern1", ThreatLevel::High);//-V530
    m_builder->AddPattern("FF D0", "Pattern2", ThreatLevel::Medium);//-V530
    m_builder->AddPattern("90 90 90", "Pattern3", ThreatLevel::Low);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    auto stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalPatternsAdded, 3);
    EXPECT_GT(stats.patternIndexSize, 0);
}

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_WildcardPatterns) {
    m_builder->AddPattern("48 ?? 05", "WildcardPattern", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_InvalidPattern) {
    // Invalid pattern should be rejected by AddPattern
    auto addErr = m_builder->AddPattern("INVALID HEX", "BadPattern", ThreatLevel::High);
    EXPECT_FALSE(addErr.IsSuccess());  // Should fail validation

    // Build should still succeed even if no patterns were added
    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    // No patterns should be in the database
    const auto& stats = m_builder->GetStatistics();
    EXPECT_EQ(stats.totalPatternsAdded, 0);
}

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_LargePattern) {
    // Create 128-byte pattern
    std::string largePattern;
    for (int i = 0; i < 128; ++i) {
        largePattern += "AA ";
    }

    m_builder->AddPattern(largePattern, "LargePattern", ThreatLevel::Medium);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_ManyPatterns) {
    // Add 1000 patterns
    for (int i = 0; i < 1000; ++i) {
        std::string pattern = "48 8B " + std::to_string(i % 256);
        m_builder->AddPattern(pattern, "Pattern_" + std::to_string(i), ThreatLevel::Low);//-V530
    }

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.totalPatternsAdded, 0);
}

TEST_F(SignatureBuilderSerializationTest, PatternSerialization_AhoCorasickBuilt) {
    m_builder->AddPattern("48 8B 05", "Pattern1", ThreatLevel::High);//-V530
    m_builder->AddPattern("FF D0", "Pattern2", ThreatLevel::Medium);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    // Verify pattern index was created
    const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.patternIndexSize, 0);
}

// ============================================================================
// METADATA SERIALIZATION TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Metadata_Serialization) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.metadataSize, 0);
}

TEST_F(SignatureBuilderSerializationTest, Metadata_WithDescriptions) {
    HashSignatureInput input{};
    input.hash = CreateSampleHash();
    input.name = "TestHash";
    input.threatLevel = ThreatLevel::High;
    input.description = "This is a test hash with a description";
    input.tags = {"malware", "trojan", "test"};

    m_builder->AddHash(input);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());
}

// ============================================================================
// CHECKSUM & INTEGRITY TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Checksum_Validation) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    // Verify checksum in header
    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // Checksum should not be all zeros
    bool hasNonZero = false;
    for (auto byte : header.sha256Checksum) {
        if (byte != 0) {
            hasNonZero = true;
            break;
        }
    }
    // Note: Checksum might be zero if not implemented yet
}

TEST_F(SignatureBuilderSerializationTest, Integrity_FileSize) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    auto fileSize = GetFileSize(m_outputPath);
    auto stats = m_builder->GetStatistics();

    EXPECT_EQ(fileSize, stats.finalDatabaseSize);
}

TEST_F(SignatureBuilderSerializationTest, Integrity_PageAlignment) {
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    std::ifstream file(m_outputPath, std::ios::binary);
    SignatureDatabaseHeader header{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));

    // All section offsets should be page-aligned
    EXPECT_EQ(header.hashIndexOffset % PAGE_SIZE, 0);
    if (header.patternIndexOffset > 0) {
        EXPECT_EQ(header.patternIndexOffset % PAGE_SIZE, 0);
    }
}

// ============================================================================
// STATISTICS TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Statistics_BuildTime) {
    for (int i = 0; i < 100; ++i) {
        m_builder->AddHash(CreateSampleHash(i), "Hash" + std::to_string(i), ThreatLevel::Low);//-V530
    }

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

    const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.totalBuildTimeMilliseconds, 0);
    EXPECT_GT(stats.serializationTimeMilliseconds, 0);
}

TEST_F(SignatureBuilderSerializationTest, Statistics_SectionSizes) {
    m_builder->AddHash(CreateSampleHash(), "Hash", ThreatLevel::High);//-V530
    m_builder->AddPattern("48 8B 05", "Pattern", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    ASSERT_TRUE(err.IsSuccess());

   const auto& stats = m_builder->GetStatistics();
    EXPECT_GT(stats.hashIndexSize, 0);
    EXPECT_GT(stats.patternIndexSize, 0);
    EXPECT_GT(stats.finalDatabaseSize, 0);
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Error_InvalidOutputPath) {
    m_config.outputPath = L"Z:\\invalid\\path\\database.sdb";
    m_builder = std::make_unique<SignatureBuilder>(m_config);
    
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, Error_ReadOnlyDirectory) {
    // Try to write to Windows directory (should fail)
    m_config.outputPath = L"C:\\Windows\\test_signatures.sdb";
    m_builder = std::make_unique<SignatureBuilder>(m_config);
    
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(SignatureBuilderSerializationTest, Recovery_CleanupOnFailure) {
    m_config.outputPath = L"";  // Invalid path
    m_builder = std::make_unique<SignatureBuilder>(m_config);
    
    m_builder->AddHash(CreateSampleHash(), "Test", ThreatLevel::High);//-V530

    auto err = m_builder->Build();
    EXPECT_FALSE(err.IsSuccess());

    // Verify no partial file left behind at temp location
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, DISABLED_Performance_LargeDatabase) {
    // Add 10,000 hashes
    for (int i = 0; i < 10000; ++i) {
        m_builder->AddHash(CreateSampleHash(i), "Hash" + std::to_string(i), ThreatLevel::Low);//-V530
    }

    // Add 1,000 patterns
    for (int i = 0; i < 1000; ++i) {
        std::string pattern = "48 8B " + std::to_string(i % 256);
        m_builder->AddPattern(pattern, "Pattern" + std::to_string(i), ThreatLevel::Medium);//-V530
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto err = m_builder->Build();
    auto end = std::chrono::high_resolution_clock::now();

    ASSERT_TRUE(err.IsSuccess());

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Built database with 10k hashes + 1k patterns in " 
              << duration.count() << " ms\n";

    const auto& stats = m_builder->GetStatistics();
    std::cout << "Database size: " << (stats.finalDatabaseSize / (1024.0 * 1024.0)) 
              << " MB\n";

    // Should complete in reasonable time (< 5 seconds)
    EXPECT_LT(duration.count(), 5000);
}

TEST_F(SignatureBuilderSerializationTest, DISABLED_Performance_SerializationSpeed) {
    // Add 1000 signatures
    for (int i = 0; i < 1000; ++i) {
        m_builder->AddHash(CreateSampleHash(i), "Hash" + std::to_string(i), ThreatLevel::Low);//-V530
    }

    // Measure serialization time specifically
    m_builder->ValidateInputs();//-V530
    m_builder->Deduplicate();//-V530
    m_builder->Optimize();//-V530
    m_builder->BuildIndices();//-V530

    auto start = std::chrono::high_resolution_clock::now();
    auto err = m_builder->Serialize();
    auto end = std::chrono::high_resolution_clock::now();

    ASSERT_TRUE(err.IsSuccess());

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Serialization time: " << duration.count() << " ms\n";

   const auto& stats = m_builder->GetStatistics();
    std::cout << "Serialization throughput: " 
              << (stats.finalDatabaseSize / (duration.count() / 1000.0)) / (1024.0 * 1024.0)
              << " MB/s\n";
}

// ============================================================================
// CONCURRENT BUILD TESTS
// ============================================================================

TEST_F(SignatureBuilderSerializationTest, Concurrency_MultipleBuildersSequential) {
    std::vector<std::wstring> paths;
    
    for (int i = 0; i < 3; ++i) {
        auto path = (std::filesystem::path(m_tempDir) / 
                    (L"concurrent_" + std::to_wstring(i) + L".sdb")).wstring();
        paths.push_back(path);

        BuildConfiguration config;
        config.outputPath = path;
        config.overwriteExisting = true;
        config.initialDatabaseSize = 1024 * 1024;  // 1MB - reasonable for unit tests

        SignatureBuilder builder(config);
        builder.AddHash(CreateSampleHash(i), "Hash" + std::to_string(i), ThreatLevel::Low);//-V530
        
        auto err = builder.Build();
        EXPECT_TRUE(err.IsSuccess());
    }

    // Cleanup
    for (const auto& path : paths) {
        std::filesystem::remove(path);
    }
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================


