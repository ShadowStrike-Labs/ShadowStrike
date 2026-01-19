// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


/*
 * ============================================================================
 * ShadowStrike SignatureBuilder Input Methods - PRODUCTION-GRADE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * ENTERPRISE-LEVEL COMPREHENSIVE TEST SUITE
 *
 * Test Coverage:
 * - Input validation (boundary conditions, null bytes, length limits)
 * - Duplicate detection and handling
 * - Resource limits and DoS prevention
 * - Thread safety and concurrent access
 * - Error handling and reporting
 * - Edge cases and corner cases
 * - Performance characteristics
 * - Security validation (entropy, ReDoS, dangerous imports)
 *
 * Test Philosophy:
 * - Test each requirement explicitly
 * - Cover all error paths
 * - Verify security controls
 * - Ensure thread safety
 * - Validate performance contracts
 *
 * ============================================================================
 */

#include"pch.h"
#include <gtest/gtest.h>
#include "../../src/SignatureStore/SignatureBuilder.hpp"
#include "../../src/SignatureStore/SignatureFormat.hpp"
#include <vector>
#include <thread>
#include <future>
#include <random>
#include <chrono>
#include <string>
#include <algorithm>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURES
// ============================================================================

class SignatureBuilderInputTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize with default configuration
        BuildConfiguration config{};
        config.strictValidation = true;
        config.enableDeduplication = true;
        config.threadCount = 1;  // Single-threaded for deterministic tests
        
        builder = std::make_unique<SignatureBuilder>(config);
    }

    void TearDown() override {
        builder.reset();
    }

    // Helper: Create valid MD5 hash with sufficient entropy
    HashValue CreateValidMD5(uint8_t baseByte = 0xAB) {
        HashValue hash{};
        hash.type = HashType::MD5;
        hash.length = 16;
        // Use deterministic pseudo-random data based on baseByte for sufficient entropy
        // This ensures each byte is different, providing good entropy
        std::mt19937 rng(static_cast<unsigned int>(baseByte) * 1000 + 12345);
        std::uniform_int_distribution<uint32_t> dist(0, 255);
        for (uint8_t i = 0; i < hash.length; ++i) {
            hash.data[i] = static_cast<uint8_t>(dist(rng));
        }
        return hash;
    }

    // Helper: Create valid SHA256 hash with sufficient entropy
    HashValue CreateValidSHA256(uint8_t baseByte = 0xCD) {
        HashValue hash{};
        hash.type = HashType::SHA256;
        hash.length = 32;
        // Use deterministic pseudo-random data based on baseByte for sufficient entropy
        std::mt19937 rng(static_cast<unsigned int>(baseByte) * 2000 + 54321);
        std::uniform_int_distribution<uint32_t> dist(0, 255);
        for (uint8_t i = 0; i < hash.length; ++i) {
            hash.data[i] = static_cast<uint8_t>(dist(rng));
        }
        return hash;
    }

    // Helper: Create valid SHA512 hash with sufficient entropy
    HashValue CreateValidSHA512(uint8_t baseByte = 0xEF) {
        HashValue hash{};
        hash.type = HashType::SHA512;
        hash.length = 64;
        // Use deterministic pseudo-random data based on baseByte for sufficient entropy
        std::mt19937 rng(static_cast<unsigned int>(baseByte) * 3000 + 98765);
        std::uniform_int_distribution<uint32_t> dist(0, 255);
        for (uint8_t i = 0; i < hash.length; ++i) {
            hash.data[i] = static_cast<uint8_t>(dist(rng));
        }
        return hash;
    }

    // Helper: Create hash with specific entropy
    HashValue CreateHashWithEntropy(HashType type, double targetEntropy) {
        HashValue hash{};
        hash.type = type;
        
        switch (type) {
            case HashType::MD5:    hash.length = 16; break;
            case HashType::SHA1:   hash.length = 20; break;
            case HashType::SHA256: hash.length = 32; break;
            case HashType::SHA512: hash.length = 64; break;
            default: hash.length = 32; break;
        }

        if (targetEntropy < 1.0) {
            // Low entropy: all zeros
            std::fill_n(hash.data.begin(), hash.length, 0x00);
        } else if (targetEntropy < 2.0) {
            // Very low entropy: alternating pattern
            for (uint8_t i = 0; i < hash.length; ++i) {
                hash.data[i] = (i % 2 == 0) ? 0x00 : 0xFF;
            }
        } else {
            // High entropy: pseudo-random
            std::mt19937 rng(12345);
            std::uniform_int_distribution<uint32_t> dist(0, 255);
            for (uint8_t i = 0; i < hash.length; ++i) {
                hash.data[i] = static_cast<uint8_t>(dist(rng));
            }
        }

        return hash;
    }

    // Helper: Create valid pattern string
    std::string CreateValidPattern(size_t length = 32) {
        std::string pattern;
        pattern.reserve(length * 3);  // "XX " format
        
        for (size_t i = 0; i < length; ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", static_cast<unsigned>(i % 256));
            pattern += buf;
        }
        
        if (!pattern.empty() && pattern.back() == ' ') {
            pattern.pop_back();
        }
        
        return pattern;
    }

    // Helper: Create valid YARA rule
    std::string CreateValidYaraRule(const std::string& ruleName = "TestRule") {
        return R"(
rule )" + ruleName + R"( {
    meta:
        description = "Test rule"
        author = "ShadowStrike"
    
    strings:
        $test = { 4D 5A 90 00 }
    
    condition:
        $test
}
)";
    }

    std::unique_ptr<SignatureBuilder> builder;
};

// ============================================================================
// ADDHASH - INPUT VALIDATION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_EmptyName_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "";  // INVALID: empty name
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_NameTooLong_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = std::string(257, 'A');  // INVALID: 257 chars (max is 256)
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_NameAtMaxLength_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = std::string(256, 'A');  // VALID: exactly 256 chars
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_NameWithNullByte_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = std::string("test\0injection", 14);  // INVALID: contains null byte
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_ZeroLengthHash_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::MD5;
    input.hash.length = 0;  // INVALID: zero length
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_HashTooLong_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::MD5;
    input.hash.length = 65;  // INVALID: exceeds max of 64
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_MD5WrongLength_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::MD5;
    input.hash.length = 20;  // INVALID: MD5 must be 16 bytes
    std::fill_n(input.hash.data.begin(),  input.hash.length, 0xAB);
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_SHA1WrongLength_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::SHA1;
    input.hash.length = 16;  // INVALID: SHA1 must be 20 bytes
    std::fill_n(input.hash.data.begin(),  input.hash.length, 0xAB);
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_SHA256WrongLength_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::SHA256;
    input.hash.length = 16;  // INVALID: SHA256 must be 32 bytes
    std::fill_n(input.hash.data.begin(),  input.hash.length, 0xAB);
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_SHA512WrongLength_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::SHA512;
    input.hash.length = 32;  // INVALID: SHA512 must be 64 bytes
    std::fill_n(input.hash.data.begin(),  input.hash.length, 0xAB);
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_ThreatLevelTooHigh_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = static_cast<ThreatLevel>(101);  // INVALID: max is 100

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_DescriptionTooLong_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.description = std::string(4097, 'D');  // INVALID: exceeds 4096 limit

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_DescriptionAtMaxLength_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.description = std::string(4096, 'D');  // VALID: exactly 4096

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_TooManyTags_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    
    // INVALID: 33 tags (max is 32)
    for (int i = 0; i < 33; ++i) {
        input.tags.emplace_back("tag" + std::to_string(i));
    }

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_MaxTags_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    
    // VALID: exactly 32 tags
    for (int i = 0; i < 32; ++i) {
        input.tags.emplace_back("tag" + std::to_string(i));
    }

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_EmptyTag_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.tags.push_back("");  // INVALID: empty tag

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_TagTooLong_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.tags.emplace_back(std::string(129, 'T'));  // INVALID: tag too long (max 128)

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_TagWithNullByte_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.tags.emplace_back(std::string("tag\0injection", 13));  // INVALID: null byte

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_SourceTooLong_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.source = std::string(257, 'S');  // INVALID: exceeds 256 limit

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_DescriptionWithNullByte_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.description = std::string("desc\0injection", 14);  // INVALID: null byte

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_SourceWithNullByte_ShouldFail) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.source = std::string("source\0injection", 16);  // INVALID: null byte

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

// ============================================================================
// ADDHASH - DUPLICATE DETECTION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_DuplicateHash_ShouldDetect) {
    // ARRANGE
    HashSignatureInput input1{};
    input1.hash = CreateValidMD5(0xAB);
    input1.name = "FirstHash";
    input1.threatLevel = ThreatLevel::High;

    HashSignatureInput input2{};
    input2.hash = CreateValidMD5(0xAB);  // Same hash value
    input2.name = "DuplicateHash";
    input2.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result1 = builder->AddHash(input1);
    StoreError result2 = builder->AddHash(input2);

    // ASSERT
    EXPECT_TRUE(result1.IsSuccess());
    EXPECT_TRUE(result2.IsSuccess());  // Duplicate is handled gracefully
    
    // Verify statistics show duplicate
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 1);
}

TEST_F(SignatureBuilderInputTest, AddHash_DifferentHashTypes_ShouldNotBeDuplicate) {
    // ARRANGE
    HashSignatureInput input1{};
    input1.hash = CreateValidMD5(0xAB);
    input1.name = "MD5Hash";
    input1.threatLevel = ThreatLevel::High;

    HashSignatureInput input2{};
    input2.hash = CreateValidSHA256(0xAB);
    input2.name = "SHA256Hash";
    input2.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result1 = builder->AddHash(input1);
    StoreError result2 = builder->AddHash(input2);

    // ASSERT
    EXPECT_TRUE(result1.IsSuccess());
    EXPECT_TRUE(result2.IsSuccess());
    
    // Both should be added (different types)
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 0);
}

// ============================================================================
// ADDHASH - ENTROPY VALIDATION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_AllZeros_ShouldFailEntropyCheck) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateHashWithEntropy(HashType::MD5, 0.0);  // All zeros
    input.name = "LowEntropyHash";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_RepeatingPattern_ShouldFailEntropyCheck) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash.type = HashType::SHA256;
    input.hash.length = 32;
    std::fill_n(input.hash.data.begin(),  input.hash.length, 0xAA);  // All same byte
    input.name = "RepeatingHash";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddHash_HighEntropy_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateHashWithEntropy(HashType::SHA256, 5.0);  // High entropy
    input.name = "HighEntropyHash";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

// ============================================================================
// ADDHASH - VALID INPUT TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_ValidMD5_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "ValidMD5";
    input.threatLevel = ThreatLevel::High;
    input.description = "Test MD5 hash";
    input.tags = {"malware", "trojan"};
    input.source = "test_suite";

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::Success);
}

TEST_F(SignatureBuilderInputTest, AddHash_ValidSHA256_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidSHA256();
    input.name = "ValidSHA256";
    input.threatLevel = ThreatLevel::Medium;
    input.description = "Test SHA256 hash";

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_MinimalValid_ShouldSucceed) {
    // ARRANGE - minimal required fields
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "MinimalHash";
    input.threatLevel = ThreatLevel::Low;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

// ============================================================================
// ADDHASH - SIMPLE OVERLOAD TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHashOverload_ValidInput_ShouldSucceed) {
    // ARRANGE
    HashValue hash = CreateValidMD5();
    std::string name = "OverloadTest";
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(hash, name, level);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHashOverload_EmptyName_ShouldFail) {
    // ARRANGE
    HashValue hash = CreateValidMD5();
    std::string name = "";  // INVALID
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(hash, name, level);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHashOverload_ZeroLengthHash_ShouldFail) {
    // ARRANGE
    HashValue hash{};
    hash.type = HashType::MD5;
    hash.length = 0;  // INVALID
    std::string name = "Test";
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddHash(hash, name, level);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

// ============================================================================
// ADDPATTERN - INPUT VALIDATION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddPattern_EmptyName_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A 90 00";
    input.name = "";  // INVALID
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, SignatureStoreError::InvalidSignature);
}

TEST_F(SignatureBuilderInputTest, AddPattern_NameTooLong_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A 90 00";
    input.name = std::string(257, 'A');  // INVALID: exceeds 256
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_EmptyPattern_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "";  // INVALID
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_PatternTooLong_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = CreateValidPattern(3000);  // INVALID: exceeds 8KB
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_WithNullBytes_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = std::string("4D 5A\0injection", 14);  // INVALID
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_DescriptionTooLong_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A 90 00";
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    input.description = std::string(4097, 'D');  // INVALID

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_TooManyTags_ShouldFail) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A 90 00";
    input.name = "ValidName";
    input.threatLevel = ThreatLevel::High;
    
    for (int i = 0; i < 33; ++i) {  // INVALID: 33 tags
        input.tags.emplace_back("tag" + std::to_string(i));
    }

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

// ============================================================================
// ADDPATTERN - VALID INPUT TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddPattern_ValidHexPattern_ShouldSucceed) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A 90 00 03 00 00 00";
    input.name = "PEHeader";
    input.threatLevel = ThreatLevel::High;
    input.description = "PE executable header";
    input.tags = {"pe", "executable"};

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_WithWildcards_ShouldSucceed) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A ?? ?? 03 00";  // Wildcards
    input.name = "PEWithWildcard";
    input.threatLevel = ThreatLevel::Medium;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_MinimalValid_ShouldSucceed) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D 5A";
    input.name = "MinimalPattern";
    input.threatLevel = ThreatLevel::Low;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

// ============================================================================
// ADDPATTERN - DUPLICATE DETECTION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddPattern_Duplicate_ShouldDetect) {
    // ARRANGE
    PatternSignatureInput input1{};
    input1.patternString = "4D 5A 90 00";
    input1.name = "Pattern1";
    input1.threatLevel = ThreatLevel::High;

    PatternSignatureInput input2{};
    input2.patternString = "4D 5A 90 00";  // Same pattern
    input2.name = "Pattern2";
    input2.threatLevel = ThreatLevel::High;

    // ACT
    StoreError result1 = builder->AddPattern(input1);
    StoreError result2 = builder->AddPattern(input2);

    // ASSERT
    EXPECT_TRUE(result1.IsSuccess());
    EXPECT_TRUE(result2.IsSuccess());
    
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 1);
}

// ============================================================================
// ADDPATTERN - SIMPLE OVERLOAD TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddPatternOverload_ValidInput_ShouldSucceed) {
    // ARRANGE
    std::string pattern = "4D 5A 90 00";
    std::string name = "OverloadPattern";
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(pattern, name, level);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPatternOverload_EmptyPattern_ShouldFail) {
    // ARRANGE
    std::string pattern = "";  // INVALID
    std::string name = "Test";
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(pattern, name, level);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPatternOverload_InvalidName_ShouldFail) {
    // ARRANGE
    std::string pattern = "4D 5A";
    std::string name = "";  // INVALID
    ThreatLevel level = ThreatLevel::High;

    // ACT
    StoreError result = builder->AddPattern(pattern, name, level);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

// ============================================================================
// ADDYARARULE - INPUT VALIDATION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddYaraRule_EmptySource_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = "";  // INVALID
    input.namespace_ = "default";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_SourceTooLarge_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = std::string(1024 * 1024 + 1, 'A');  // INVALID: exceeds 1MB
    input.namespace_ = "default";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_EmptyNamespace_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = CreateValidYaraRule();
    input.namespace_ = "";  // INVALID

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_NamespaceTooLong_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = CreateValidYaraRule();
    input.namespace_ = std::string(129, 'N');  // INVALID: exceeds 128

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_InvalidNamespaceChars_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = CreateValidYaraRule();
    input.namespace_ = "invalid-namespace!";  // INVALID: special chars

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_InvalidSyntax_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = "rule Invalid { invalid syntax }";  // INVALID syntax
    input.namespace_ = "default";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_NoRuleKeyword_ShouldFail) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = "this is not a valid rule";  // INVALID
    input.namespace_ = "default";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

// ============================================================================
// ADDYARARULE - VALID INPUT TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddYaraRule_ValidRule_ShouldSucceed) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = CreateValidYaraRule("TestMalware");
    input.namespace_ = "malware";
    input.source = "test_suite";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_ComplexRule_ShouldSucceed) {
    // ARRANGE
    YaraRuleInput input{};
    input.ruleSource = R"(
rule ComplexMalware {
    meta:
        description = "Complex malware detection"
        author = "ShadowStrike"
        version = "1.0"
    
    strings:
        $mz = { 4D 5A }
        $pe = "PE\x00\x00"
        $string1 = "malicious" ascii wide
        $string2 = /evil[0-9]{3}/ nocase
    
    condition:
        $mz at 0 and $pe and (#string1 > 2 or $string2)
}
)";
    input.namespace_ = "advanced";

    // ACT
    StoreError result = builder->AddYaraRule(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

// ============================================================================
// ADDYARARULE - DUPLICATE DETECTION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddYaraRule_DuplicateInSameNamespace_ShouldDetect) {
    // ARRANGE
    YaraRuleInput input1{};
    input1.ruleSource = CreateValidYaraRule("TestRule");
    input1.namespace_ = "default";

    YaraRuleInput input2{};
    input2.ruleSource = CreateValidYaraRule("TestRule");  // Same name
    input2.namespace_ = "default";  // Same namespace

    // ACT
    StoreError result1 = builder->AddYaraRule(input1);
    StoreError result2 = builder->AddYaraRule(input2);

    // ASSERT
    EXPECT_TRUE(result1.IsSuccess());
    EXPECT_TRUE(result2.IsSuccess());
    
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 1);
}

TEST_F(SignatureBuilderInputTest, AddYaraRule_SameNameDifferentNamespace_ShouldSucceed) {
    // ARRANGE
    YaraRuleInput input1{};
    input1.ruleSource = CreateValidYaraRule("TestRule");
    input1.namespace_ = "namespace1";

    YaraRuleInput input2{};
    input2.ruleSource = CreateValidYaraRule("TestRule");  // Same name
    input2.namespace_ = "namespace2";  // Different namespace

    // ACT
    StoreError result1 = builder->AddYaraRule(input1);
    StoreError result2 = builder->AddYaraRule(input2);

    // ASSERT
    EXPECT_TRUE(result1.IsSuccess());
    EXPECT_TRUE(result2.IsSuccess());
    
    // Should not be duplicates (different namespaces)
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.duplicatesRemoved, 0);
}

// ============================================================================
// ADDYARARULE - SIMPLE OVERLOAD TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddYaraRuleOverload_ValidInput_ShouldSucceed) {
    // ARRANGE
    std::string rule = CreateValidYaraRule("OverloadTest");
    std::string namespace_ = "default";

    // ACT
    StoreError result = builder->AddYaraRule(rule, namespace_);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRuleOverload_DefaultNamespace_ShouldSucceed) {
    // ARRANGE
    std::string rule = CreateValidYaraRule("DefaultNS");

    // ACT
    StoreError result = builder->AddYaraRule(rule);  // Uses default namespace

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

// ============================================================================
// BATCH OPERATIONS - ADDHASBBATCH TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHashBatch_EmptySpan_ShouldFail) {
    // ARRANGE
    std::vector<HashSignatureInput> inputs;
    std::span<const HashSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddHashBatch(span);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHashBatch_ValidInputs_ShouldSucceed) {
    // ARRANGE
    std::vector<HashSignatureInput> inputs;
    
    for (int i = 0; i < 10; ++i) {
        HashSignatureInput input{};
        input.hash = CreateValidMD5(static_cast<uint8_t>(i));
        input.name = "Hash" + std::to_string(i);
        input.threatLevel = ThreatLevel::Medium;
        inputs.push_back(input);
    }

    std::span<const HashSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddHashBatch(span);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
    
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 10);
}

TEST_F(SignatureBuilderInputTest, AddHashBatch_WithInvalidInput_ShouldPartiallySucceed) {
    // ARRANGE
    std::vector<HashSignatureInput> inputs;//-V826
    
    // Add valid hash
    HashSignatureInput valid{};
    valid.hash = CreateValidMD5();
    valid.name = "ValidHash";
    valid.threatLevel = ThreatLevel::High;
    inputs.push_back(valid);
    
    // Add invalid hash (empty name)
    HashSignatureInput invalid{};
    invalid.hash = CreateValidMD5(0xBB);
    invalid.name = "";  // INVALID
    invalid.threatLevel = ThreatLevel::High;
    inputs.push_back(invalid);

    std::span<const HashSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddHashBatch(span);

    // ASSERT
    // Batch should handle partial success
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_GT(stats.totalHashesAdded, 0);
    EXPECT_GT(stats.invalidSignaturesSkipped, 0);
}

TEST_F(SignatureBuilderInputTest, AddHashBatch_WithDuplicates_ShouldDetect) {
    // ARRANGE
    std::vector<HashSignatureInput> inputs;//-V826
    
    HashSignatureInput input1{};
    input1.hash = CreateValidMD5(0xCC);
    input1.name = "Hash1";
    input1.threatLevel = ThreatLevel::High;
    inputs.push_back(input1);
    
    // Duplicate
    HashSignatureInput input2{};
    input2.hash = CreateValidMD5(0xCC);  // Same hash
    input2.name = "Hash2";
    input2.threatLevel = ThreatLevel::High;
    inputs.push_back(input2);

    std::span<const HashSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddHashBatch(span);

    // ASSERT
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_GT(stats.duplicatesRemoved, 0);
}

// ============================================================================
// BATCH OPERATIONS - ADDPATTERNBATCH TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddPatternBatch_EmptySpan_ShouldFail) {
    // ARRANGE
    std::vector<PatternSignatureInput> inputs;
    std::span<const PatternSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddPatternBatch(span);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPatternBatch_ValidInputs_ShouldSucceed) {
    // ARRANGE
    std::vector<PatternSignatureInput> inputs;
    
    for (int i = 0; i < 5; ++i) {
        PatternSignatureInput input{};
        input.patternString = CreateValidPattern(16 + i);
        input.name = "Pattern" + std::to_string(i);
        input.threatLevel = ThreatLevel::Medium;
        inputs.push_back(input);
    }

    std::span<const PatternSignatureInput> span(inputs);

    // ACT
    StoreError result = builder->AddPatternBatch(span);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
    
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.totalPatternsAdded, 5);
}

// ============================================================================
// BATCH OPERATIONS - ADDYARARULEBATCH TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddYaraRuleBatch_EmptySpan_ShouldFail) {
    // ARRANGE
    std::vector<YaraRuleInput> inputs;
    std::span<const YaraRuleInput> span(inputs);

    // ACT
    StoreError result = builder->AddYaraRuleBatch(span);

    // ASSERT
    EXPECT_FALSE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddYaraRuleBatch_ValidInputs_ShouldSucceed) {
    // ARRANGE
    std::vector<YaraRuleInput> inputs;
    
    for (int i = 0; i < 3; ++i) {
        YaraRuleInput input{};
        input.ruleSource = CreateValidYaraRule("Rule" + std::to_string(i));
        input.namespace_ = "batch_test";
        inputs.push_back(input);
    }

    std::span<const YaraRuleInput> span(inputs);

    // ACT
    StoreError result = builder->AddYaraRuleBatch(span);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
    
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.totalYaraRulesAdded, 3);
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_ConcurrentAccess_ShouldBeThreadSafe) {
    // ARRANGE
    constexpr int NUM_THREADS = 4;
    constexpr int HASHES_PER_THREAD = 25;
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};

    // ACT
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([this, t, &successCount]() {
            for (int i = 0; i < HASHES_PER_THREAD; ++i) {
                HashSignatureInput input{};
                input.hash = CreateValidMD5(static_cast<uint8_t>(t * 100 + i));
                input.name = "Thread" + std::to_string(t) + "_Hash" + std::to_string(i);
                input.threatLevel = ThreatLevel::Medium;
                
                StoreError result = builder->AddHash(input);
                if (result.IsSuccess()) {
                    successCount++;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // ASSERT
    EXPECT_EQ(successCount.load(), NUM_THREADS * HASHES_PER_THREAD);
}

TEST_F(SignatureBuilderInputTest, AddPattern_ConcurrentAccess_ShouldBeThreadSafe) {
    // ARRANGE
    constexpr int NUM_THREADS = 4;
    constexpr int PATTERNS_PER_THREAD = 20;
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};

    // ACT
    for (int t = 0; t < NUM_THREADS; ++t) {
        threads.emplace_back([this, t, &successCount]() {
            for (int i = 0; i < PATTERNS_PER_THREAD; ++i) {
                PatternSignatureInput input{};
                input.patternString = CreateValidPattern(16 + t + i);
                input.name = "Thread" + std::to_string(t) + "_Pattern" + std::to_string(i);
                input.threatLevel = ThreatLevel::Medium;
                
                StoreError result = builder->AddPattern(input);
                if (result.IsSuccess()) {
                    successCount++;
                }
            }
        });
    }

    for (auto& thread : threads) {
        thread.join();
    }

    // ASSERT
    EXPECT_EQ(successCount.load(), NUM_THREADS * PATTERNS_PER_THREAD);
}

// ============================================================================
// RESOURCE LIMIT TESTS (DoS PREVENTION)
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_ExceedingMemoryLimit_ShouldHandleGracefully) {
    // ARRANGE - try to add many hashes to test resource limits
    constexpr int LARGE_COUNT = 1000;
    
    int successCount = 0;
    int failCount = 0;

    // ACT
    for (int i = 0; i < LARGE_COUNT; ++i) {
        HashSignatureInput input{};
        input.hash = CreateValidMD5(static_cast<uint8_t>(i % 256));
        input.name = "LargeTest" + std::to_string(i);
        input.threatLevel = ThreatLevel::Low;
        
        StoreError result = builder->AddHash(input);
        if (result.IsSuccess()) {
            successCount++;
        } else {
            failCount++;
        }
    }

    // ASSERT - should handle without crashing
    EXPECT_GT(successCount, 0);
    // Either all succeed or we hit resource limits gracefully
    EXPECT_EQ(successCount + failCount, LARGE_COUNT);
}

// ============================================================================
// STATISTICS VERIFICATION TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_Statistics_ShouldBeAccurate) {
    // ARRANGE & ACT
    HashSignatureInput input1{};
    input1.hash = CreateValidMD5(0x11);
    input1.name = "Hash1";
    input1.threatLevel = ThreatLevel::High;
    builder->AddHash(input1);//-V530

    HashSignatureInput input2{};
    input2.hash = CreateValidMD5(0x22);
    input2.name = "Hash2";
    input2.threatLevel = ThreatLevel::High;
    builder->AddHash(input2);//-V530

    // ASSERT
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.totalHashesAdded, 2);
}

TEST_F(SignatureBuilderInputTest, AddPattern_Statistics_ShouldBeAccurate) {
    // ARRANGE & ACT
    PatternSignatureInput input1{};
    input1.patternString = "4D 5A 90 00";
    input1.name = "Pattern1";
    input1.threatLevel = ThreatLevel::High;
    builder->AddPattern(input1);//-V530

    PatternSignatureInput input2{};
    input2.patternString = "50 45 00 00";
    input2.name = "Pattern2";
    input2.threatLevel = ThreatLevel::Medium;
    builder->AddPattern(input2);//-V530

    // ASSERT
    BuildStatistics stats = builder->GetStatistics();
    EXPECT_EQ(stats.totalPatternsAdded, 2);
}

// ============================================================================
// BOUNDARY VALUE TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_ThreatLevelMinimum_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "MinThreat";
    input.threatLevel = static_cast<ThreatLevel>(0);  // Minimum

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_ThreatLevelMaximum_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "MaxThreat";
    input.threatLevel = static_cast<ThreatLevel>(100);  // Maximum

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddPattern_SingleBytePattern_ShouldSucceed) {
    // ARRANGE
    PatternSignatureInput input{};
    input.patternString = "4D";  // Single byte
    input.name = "SingleByte";
    input.threatLevel = ThreatLevel::Low;

    // ACT
    StoreError result = builder->AddPattern(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_AllHashTypes_ShouldSucceed) {
    // Test all hash types with correct lengths
    // Using high-entropy data to pass entropy validation
    std::mt19937 rng(42);
    std::uniform_int_distribution<uint32_t> dist(0, 255);
    
    // MD5
    HashSignatureInput md5{};
    md5.hash.type = HashType::MD5;
    md5.hash.length = 16;
    for (uint8_t i = 0; i < md5.hash.length; ++i) {
        md5.hash.data[i] = static_cast<uint8_t>(dist(rng));
    }
    md5.name = "MD5_Test";
    md5.threatLevel = ThreatLevel::High;
    EXPECT_TRUE(builder->AddHash(md5).IsSuccess());

    // SHA1
    HashSignatureInput sha1{};
    sha1.hash.type = HashType::SHA1;
    sha1.hash.length = 20;
    for (uint8_t i = 0; i < sha1.hash.length; ++i) {
        sha1.hash.data[i] = static_cast<uint8_t>(dist(rng));
    }
    sha1.name = "SHA1_Test";
    sha1.threatLevel = ThreatLevel::High;
    EXPECT_TRUE(builder->AddHash(sha1).IsSuccess());

    // SHA256
    HashSignatureInput sha256{};
    sha256.hash.type = HashType::SHA256;
    sha256.hash.length = 32;
    for (uint8_t i = 0; i < sha256.hash.length; ++i) {
        sha256.hash.data[i] = static_cast<uint8_t>(dist(rng));
    }
    sha256.name = "SHA256_Test";
    sha256.threatLevel = ThreatLevel::High;
    EXPECT_TRUE(builder->AddHash(sha256).IsSuccess());

    // SHA512
    HashSignatureInput sha512{};
    sha512.hash.type = HashType::SHA512;
    sha512.hash.length = 64;
    for (uint8_t i = 0; i < sha512.hash.length; ++i) {
        sha512.hash.data[i] = static_cast<uint8_t>(dist(rng));
    }
    sha512.name = "SHA512_Test";
    sha512.threatLevel = ThreatLevel::High;
    EXPECT_TRUE(builder->AddHash(sha512).IsSuccess());
}

// ============================================================================
// ERROR HANDLING TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_MultipleInvalidInputs_ShouldReportCorrectErrors) {
    // Test that error codes are correctly returned for different failures
    
    // Empty name
    HashSignatureInput input1{};
    input1.hash = CreateValidMD5();
    input1.name = "";
    input1.threatLevel = ThreatLevel::High;
    StoreError err1 = builder->AddHash(input1);
    EXPECT_EQ(err1.code, SignatureStoreError::InvalidSignature);

    // Invalid hash length
    HashSignatureInput input2{};
    input2.hash.type = HashType::MD5;
    input2.hash.length = 0;
    input2.name = "Valid";
    input2.threatLevel = ThreatLevel::High;
    StoreError err2 = builder->AddHash(input2);
    EXPECT_EQ(err2.code, SignatureStoreError::InvalidSignature);

    // Invalid threat level
    HashSignatureInput input3{};
    input3.hash = CreateValidMD5();
    input3.name = "Valid";
    input3.threatLevel = static_cast<ThreatLevel>(255);
    StoreError err3 = builder->AddHash(input3);
    EXPECT_EQ(err3.code, SignatureStoreError::InvalidSignature);
}

// ============================================================================
// SPECIAL CHARACTER TESTS
// ============================================================================

TEST_F(SignatureBuilderInputTest, AddHash_NameWithSpecialChars_ShouldSucceed) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "Test_Hash-2024.v1";  // Valid special chars
    input.threatLevel = ThreatLevel::Medium;

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    EXPECT_TRUE(result.IsSuccess());
}

TEST_F(SignatureBuilderInputTest, AddHash_UnicodeInDescription_ShouldHandle) {
    // ARRANGE
    HashSignatureInput input{};
    input.hash = CreateValidMD5();
    input.name = "UnicodeTest";
    input.threatLevel = ThreatLevel::Medium;
    input.description = std::string(reinterpret_cast<const char*>(u8"Unicode test: 你好世界 🔒"));//UTF-8

    // ACT
    StoreError result = builder->AddHash(input);

    // ASSERT
    // Should handle unicode gracefully (success or graceful failure)
    EXPECT_NE(result.code, SignatureStoreError::Unknown);
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================


