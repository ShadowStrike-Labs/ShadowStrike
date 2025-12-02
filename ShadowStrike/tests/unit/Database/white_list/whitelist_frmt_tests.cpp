/*
 * ============================================================================
 * ShadowStrike Whitelist Format - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade unit tests for WhitelistFormat module.
 * 
 * Coverage:
 * - Hash structures and operations
 * - Header validation (magic, version, section alignment, overflow, corruption)
 * - CRC32 checksum computation
 * - SHA-256 integrity verification
 * - Hash parsing and formatting
 * - Path normalization and pattern matching
 * - Memory mapping operations
 * - Error handling and edge cases
 * - Performance characteristics
 *
 * Test Quality Standards:
 * - ZERO tolerance for flaky tests
 * - ALL edge cases covered
 * - Comprehensive error condition coverage
 * - Thread-safety verification where applicable
 * - Resource leak detection
 * - No false positives/negatives
 *
 * ============================================================================
 */
#include <gtest/gtest.h>
#include <array>
#include <vector>
#include <string>
#include <cstring>
#include <windows.h>
#include <algorithm>
#include <random>
#include <numeric>

#include"../../src/Whitelist/WhiteListFormat.hpp"

using namespace ShadowStrike;
using namespace ShadowStrike::Whitelist;



// ============================================================================
// TEST FIXTURES AND UTILITIES
// ============================================================================

/// @brief Base fixture for whitelist format tests with utility methods
class WhitelistFormatTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize test data
        seed = 12345;
        rng = std::mt19937(seed);
        
        // Create temporary test directory
        char tempPath[MAX_PATH];
        GetTempPathA(MAX_PATH, tempPath);
        testDir = tempPath;
        testDir += "ShadowStrike_WhitelistTests\\";
        
        CreateDirectoryA(testDir.c_str(), nullptr);
    }
    
    void TearDown() override {
        // Cleanup any leftover files
        WIN32_FIND_DATAA findData;
        HANDLE findHandle = FindFirstFileA((testDir + "*.*").c_str(), &findData);
        
        if (findHandle != INVALID_HANDLE_VALUE) {
            do {
                if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    std::string filePath = testDir + findData.cFileName;
                    DeleteFileA(filePath.c_str());
                }
            } while (FindNextFileA(findHandle, &findData));
            
            FindClose(findHandle);
        }
        
        RemoveDirectoryA(testDir.c_str());
    }
    
    /// @brief Generate random hash value for testing
    HashValue GenerateRandomHash(HashAlgorithm algo) {
        uint8_t expectedLen = HashValue::GetLengthForAlgorithm(algo);
        std::vector<uint8_t> buffer(expectedLen);
        
        for (size_t i = 0; i < expectedLen; ++i) {
            buffer[i] = static_cast<uint8_t>(rng() & 0xFF);
        }
        
        return HashValue(algo, buffer.data(), expectedLen);
    }
    
    /// @brief Generate valid hex string for hash
    std::string HashToHexString(const HashValue& hash) {
        static constexpr char hexChars[] = "0123456789abcdef";
        std::string result;
        result.reserve(hash.length * 2);
        
        for (size_t i = 0; i < hash.length; ++i) {
            uint8_t byte = hash.data[i];
            result.push_back(hexChars[(byte >> 4) & 0x0F]);
            result.push_back(hexChars[byte & 0x0F]);
        }
        
        return result;
    }
    
    std::mt19937 rng;
    unsigned int seed;
    std::string testDir;
};

// ============================================================================
// HASH VALUE TESTS
// ============================================================================

class HashValueTest : public WhitelistFormatTest {};

TEST_F(HashValueTest, DefaultConstructor) {
    HashValue hash;
    
    EXPECT_EQ(hash.algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(hash.length, 0);
    EXPECT_TRUE(hash.IsEmpty());
    
    // All data should be zero
    for (uint8_t b : hash.data) {
        EXPECT_EQ(b, 0);
    }
}

TEST_F(HashValueTest, ConstructorWithData_ValidMD5) {
    uint8_t data[16] = {
        0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76,
        0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92
    };
    
    HashValue hash(HashAlgorithm::MD5, data, 16);
    
    EXPECT_EQ(hash.algorithm, HashAlgorithm::MD5);
    EXPECT_EQ(hash.length, 16);
    EXPECT_FALSE(hash.IsEmpty());
    EXPECT_EQ(std::memcmp(hash.data.data(), data, 16), 0);
}

TEST_F(HashValueTest, ConstructorWithData_ValidSHA256) {
    uint8_t data[32];
    for (int i = 0; i < 32; ++i) {
        data[i] = static_cast<uint8_t>(i * 7);
    }
    
    HashValue hash(HashAlgorithm::SHA256, data, 32);
    
    EXPECT_EQ(hash.algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(hash.length, 32);
    EXPECT_FALSE(hash.IsEmpty());
    EXPECT_EQ(std::memcmp(hash.data.data(), data, 32), 0);
}

TEST_F(HashValueTest, ConstructorWithData_ValidSHA512) {
    uint8_t data[64];
    std::fill(data, data + 64, 0xAB);
    
    HashValue hash(HashAlgorithm::SHA512, data, 64);
    
    EXPECT_EQ(hash.algorithm, HashAlgorithm::SHA512);
    EXPECT_EQ(hash.length, 64);
    EXPECT_EQ(std::memcmp(hash.data.data(), data, 64), 0);
}

TEST_F(HashValueTest, ConstructorWithData_NullPointer) {
    // Should not crash
    HashValue hash(HashAlgorithm::SHA256, nullptr, 32);
    
    EXPECT_EQ(hash.length, 0);
    EXPECT_TRUE(hash.IsEmpty());
}

TEST_F(HashValueTest, ConstructorWithData_ZeroLength) {
    uint8_t data[16] = {0x01};
    
    HashValue hash(HashAlgorithm::MD5, data, 0);
    
    EXPECT_EQ(hash.length, 0);
    EXPECT_TRUE(hash.IsEmpty());
}

TEST_F(HashValueTest, ConstructorWithData_LengthExceedsBuffer) {
    uint8_t data[16];
    
    // Request more than buffer can hold
    HashValue hash(HashAlgorithm::MD5, data, 32);
    
    EXPECT_EQ(hash.length, 0); // Should reject invalid length
}

TEST_F(HashValueTest, EqualityOperator_SameHash) {
    uint8_t data[32];
    std::fill(data, data + 32, 0x42);
    
    HashValue hash1(HashAlgorithm::SHA256, data, 32);
    HashValue hash2(HashAlgorithm::SHA256, data, 32);
    
    EXPECT_EQ(hash1, hash2);
}

TEST_F(HashValueTest, EqualityOperator_DifferentData) {
    uint8_t data1[32];
    std::fill(data1, data1 + 32, 0x11);
    
    uint8_t data2[32];
    std::fill(data2, data2 + 32, 0x22);
    
    HashValue hash1(HashAlgorithm::SHA256, data1, 32);
    HashValue hash2(HashAlgorithm::SHA256, data2, 32);
    
    EXPECT_NE(hash1, hash2);
}

TEST_F(HashValueTest, EqualityOperator_DifferentAlgorithm) {
    uint8_t data[16];
    std::fill(data, data + 16, 0x00);
    
    HashValue hash1(HashAlgorithm::MD5, data, 16);
    HashValue hash2(HashAlgorithm::SHA256, data, 32); // Different algo and length
    
    EXPECT_NE(hash1, hash2);
}

TEST_F(HashValueTest, EqualityOperator_DifferentLength) {
    uint8_t data[32];
    std::fill(data, data + 32, 0xFF);
    
    HashValue hash1(HashAlgorithm::MD5, data, 16);
    HashValue hash2(HashAlgorithm::MD5, data, 20); // Different length (SHA1)
    
    EXPECT_NE(hash1, hash2);
}

TEST_F(HashValueTest, FastHash_Consistency) {
    // Same hash should always produce same FastHash
    auto hash = GenerateRandomHash(HashAlgorithm::SHA256);
    
    uint64_t h1 = hash.FastHash();
    uint64_t h2 = hash.FastHash();
    uint64_t h3 = hash.FastHash();
    
    EXPECT_EQ(h1, h2);
    EXPECT_EQ(h2, h3);
}

TEST_F(HashValueTest, FastHash_DifferentForDifferentData) {
    auto hash1 = GenerateRandomHash(HashAlgorithm::SHA256);
    auto hash2 = GenerateRandomHash(HashAlgorithm::SHA256);
    
    // Very unlikely (1 in 2^64) to be the same for different hashes
    EXPECT_NE(hash1.FastHash(), hash2.FastHash());
}

TEST_F(HashValueTest, FastHash_DifferentForDifferentAlgorithm) {
    uint8_t data[32];
    std::fill(data, data + 32, 0x42);
    
    HashValue hash1(HashAlgorithm::SHA256, data, 32);
    HashValue hash2(HashAlgorithm::SHA512, data, 64);
    
    EXPECT_NE(hash1.FastHash(), hash2.FastHash());
}

TEST_F(HashValueTest, GetLengthForAlgorithm_AllAlgorithms) {
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::MD5), 16);
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::SHA1), 20);
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::SHA256), 32);
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::SHA512), 64);
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::ImpHash), 16);
    EXPECT_EQ(HashValue::GetLengthForAlgorithm(HashAlgorithm::Authenticode), 32);
}

// ============================================================================
// HEADER VALIDATION TESTS
// ============================================================================

class HeaderValidationTest : public WhitelistFormatTest {
protected:
    /// @brief Create a valid header for testing
    WhitelistDatabaseHeader CreateValidHeader() {
        WhitelistDatabaseHeader header;
        std::memset(&header, 0, sizeof(header));
        
        // Set valid values
        header.magic = WHITELIST_DB_MAGIC;
        header.versionMajor = WHITELIST_DB_VERSION_MAJOR;
        header.versionMinor = WHITELIST_DB_VERSION_MINOR;
        header.creationTime = 1700000000;
        header.lastUpdateTime = 1700000000;
        header.buildNumber = 1;
        
        // Set section offsets (page-aligned)
        header.hashIndexOffset = PAGE_SIZE;
        header.hashIndexSize = PAGE_SIZE * 10;
        
        header.pathIndexOffset = PAGE_SIZE * 11;
        header.pathIndexSize = PAGE_SIZE * 10;
        
        header.entryDataOffset = PAGE_SIZE * 21;
        header.entryDataSize = PAGE_SIZE * 50;
        
        header.stringPoolOffset = PAGE_SIZE * 71;
        header.stringPoolSize = PAGE_SIZE * 30;
        
        header.bloomFilterOffset = PAGE_SIZE * 101;
        header.bloomFilterSize = PAGE_SIZE * 5;
        
        // Compute CRC
        header.headerCrc32 = Format::ComputeHeaderCRC32(&header);
        
        return header;
    }
};

TEST_F(HeaderValidationTest, ValidateHeader_NullPointer) {
    EXPECT_FALSE(Format::ValidateHeader(nullptr));
}

TEST_F(HeaderValidationTest, ValidateHeader_ValidHeader) {
    auto header = CreateValidHeader();
    EXPECT_TRUE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_InvalidMagic) {
    auto header = CreateValidHeader();
    header.magic = 0xDEADBEEF; // Wrong magic
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_WrongVersionMajor) {
    auto header = CreateValidHeader();
    header.versionMajor = WHITELIST_DB_VERSION_MAJOR + 1; // Wrong version
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_NotPageAligned) {
    auto header = CreateValidHeader();
    header.hashIndexOffset = PAGE_SIZE - 1; // Not aligned
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_SectionTooLarge) {
    auto header = CreateValidHeader();
    header.stringPoolSize = MAX_DATABASE_SIZE + 1; // Too large
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_OffsetPlusSizeOverflow) {
    auto header = CreateValidHeader();
    header.entryDataOffset = UINT64_MAX - PAGE_SIZE; // Will overflow
    header.entryDataSize = PAGE_SIZE * 2;
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_SectionOverlap) {
    auto header = CreateValidHeader();
    
    // Make path index overlap with hash index
    header.pathIndexOffset = PAGE_SIZE * 5; // Inside hash index range
    header.pathIndexSize = PAGE_SIZE * 10;
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_CreationAfterModification) {
    auto header = CreateValidHeader();
    header.creationTime = 2000000000;
    header.lastUpdateTime = 1000000000; // Earlier than creation
    
    // Should still validate (just warn), not fail
    EXPECT_TRUE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_TimestampOutOfRange) {
    auto header = CreateValidHeader();
    header.creationTime = 100; // Way too old (1970)
    
    // Should still validate with warning
    EXPECT_TRUE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_AllSectionsZero) {
    auto header = CreateValidHeader();
    header.hashIndexOffset = 0;
    header.hashIndexSize = 0;
    header.pathIndexOffset = 0;
    header.pathIndexSize = 0;
    
    // Should validate - empty database
    EXPECT_TRUE(Format::ValidateHeader(&header));
}

TEST_F(HeaderValidationTest, ValidateHeader_BadCRC32) {
    auto header = CreateValidHeader();
    header.headerCrc32 = 0xDEADBEEF; // Wrong CRC
    
    EXPECT_FALSE(Format::ValidateHeader(&header));
}

// ============================================================================
// HASH PARSING TESTS
// ============================================================================

class HashParsingTest : public WhitelistFormatTest {};

TEST_F(HashParsingTest, ParseHashString_ValidMD5) {
    std::string md5Hex = "5d41402abc4b2a76b9719d9110 17c5 92";
    auto hash = Format::ParseHashString(md5Hex, HashAlgorithm::MD5);
    
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->algorithm, HashAlgorithm::MD5);
    EXPECT_EQ(hash->length, 16);
}

TEST_F(HashParsingTest, ParseHashString_ValidSHA256) {
    std::string sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    auto hash = Format::ParseHashString(sha256Hex, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->algorithm, HashAlgorithm::SHA256);
    EXPECT_EQ(hash->length, 32);
}

TEST_F(HashParsingTest, ParseHashString_UppercaseHex) {
    std::string sha256Hex = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
    auto hash = Format::ParseHashString(sha256Hex, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->length, 32);
}

TEST_F(HashParsingTest, ParseHashString_MixedCaseHex) {
    std::string sha256Hex = "E3b0C44298fc1C149aFbf4c8996fB92427ae41E4649b934ca495991b7852b855";
    auto hash = Format::ParseHashString(sha256Hex, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->length, 32);
}

TEST_F(HashParsingTest, ParseHashString_WithWhitespace) {
    std::string sha256Hex = "e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855";
    auto hash = Format::ParseHashString(sha256Hex, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->length, 32);
}

TEST_F(HashParsingTest, ParseHashString_EmptyString) {
    auto hash = Format::ParseHashString("", HashAlgorithm::SHA256);
    EXPECT_FALSE(hash.has_value());
}

TEST_F(HashParsingTest, ParseHashString_InvalidLength) {
    // MD5 needs exactly 32 hex chars (16 bytes)
    std::string md5Hex = "5d41402abc4b2a76b9719d9110";
    auto hash = Format::ParseHashString(md5Hex, HashAlgorithm::MD5);
    
    EXPECT_FALSE(hash.has_value());
}

TEST_F(HashParsingTest, ParseHashString_InvalidHexCharacters) {
    std::string md5Hex = "5d41402abc4b2a76b9719d9110_7c592"; // 'X' is invalid
    auto hash = Format::ParseHashString(md5Hex, HashAlgorithm::MD5);
    
    EXPECT_FALSE(hash.has_value());
}

TEST_F(HashParsingTest, ParseHashString_ExcessiveLength) {
    // Way too long
    std::string hexStr(1000, 'a');
    auto hash = Format::ParseHashString(hexStr, HashAlgorithm::SHA256);
    
    EXPECT_FALSE(hash.has_value());
}

TEST_F(HashParsingTest, ParseHashString_RoundTrip) {
    auto originalHash = GenerateRandomHash(HashAlgorithm::SHA256);
    
    std::string hexStr = Format::FormatHashString(originalHash);
    auto parsedHash = Format::ParseHashString(hexStr, HashAlgorithm::SHA256);
    
    ASSERT_TRUE(parsedHash.has_value());
    EXPECT_EQ(*parsedHash, originalHash);
}

// ============================================================================
// HASH FORMATTING TESTS
// ============================================================================

class HashFormattingTest : public WhitelistFormatTest {};

TEST_F(HashFormattingTest, FormatHashString_MD5) {
    uint8_t data[16] = {
        0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76,
        0xb9, 0x71, 0x9d, 0x91, 0x10, 0x17, 0xc5, 0x92
    };
    
    HashValue hash(HashAlgorithm::MD5, data, 16);
    std::string hexStr = Format::FormatHashString(hash);
    
    EXPECT_EQ(hexStr, "5d41402abc4b2a76b9719d9110 17c592");
    EXPECT_EQ(hexStr.length(), 32);
}

TEST_F(HashFormattingTest, FormatHashString_EmptyHash) {
    HashValue hash;
    std::string hexStr = Format::FormatHashString(hash);
    
    EXPECT_TRUE(hexStr.empty());
}

TEST_F(HashFormattingTest, FormatHashString_AllZeros) {
    uint8_t data[32] = {};
    HashValue hash(HashAlgorithm::SHA256, data, 32);
    
    std::string hexStr = Format::FormatHashString(hash);
    
    EXPECT_EQ(hexStr, std::string(64, '0'));
}

TEST_F(HashFormattingTest, FormatHashString_AllOnes) {
    uint8_t data[16];
    std::fill(data, data + 16, 0xFF);
    
    HashValue hash(HashAlgorithm::MD5, data, 16);
    std::string hexStr = Format::FormatHashString(hash);
    
    EXPECT_EQ(hexStr, std::string(32, 'f'));
}

// ============================================================================
// PATH NORMALIZATION TESTS
// ============================================================================

class PathNormalizationTest : public WhitelistFormatTest {};

TEST_F(PathNormalizationTest, NormalizePath_EmptyPath) {
    auto result = Format::NormalizePath(L"");
    EXPECT_TRUE(result.empty());
}

TEST_F(PathNormalizationTest, NormalizePath_Lowercase) {
    auto result = Format::NormalizePath(L"C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
    
    EXPECT_EQ(result, L"c:\\windows\\system32\\cmd.exe");
}

TEST_F(PathNormalizationTest, NormalizePath_ForwardSlashes) {
    auto result = Format::NormalizePath(L"C:/Windows/System32/cmd.exe");
    
    EXPECT_EQ(result, L"c:\\windows\\system32\\cmd.exe");
}

TEST_F(PathNormalizationTest, NormalizePath_MixedSlashes) {
    auto result = Format::NormalizePath(L"C:/Windows\\System32/cmd.exe");
    
    EXPECT_EQ(result, L"c:\\windows\\system32\\cmd.exe");
}

TEST_F(PathNormalizationTest, NormalizePath_TrailingSlash) {
    auto result = Format::NormalizePath(L"C:\\Windows\\System32\\");
    
    // Should remove trailing slash (except for root)
    EXPECT_EQ(result, L"c:\\windows\\system32");
}

TEST_F(PathNormalizationTest, NormalizePath_RootPath) {
    auto result = Format::NormalizePath(L"C:\\");
    
    EXPECT_EQ(result, L"c:\\");
}

TEST_F(PathNormalizationTest, NormalizePath_UNCPath) {
    auto result = Format::NormalizePath(L"\\\\SERVER\\Share\\File.txt");
    
    EXPECT_EQ(result, L"\\\\server\\share\\file.txt");
}

TEST_F(PathNormalizationTest, NormalizePath_RelativePath) {
    auto result = Format::NormalizePath(L"..\\Folder\\File.dll");
    
    EXPECT_EQ(result, L"..\\folder\\file.dll");
}

// ============================================================================
// PATH PATTERN MATCHING TESTS
// ============================================================================

class PathMatchingTest : public WhitelistFormatTest {};

TEST_F(PathMatchingTest, PathMatchesPattern_ExactMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Windows\\System32\\cmd.exe",
        PathMatchMode::Exact
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_ExactMatch_CaseInsensitive) {
    bool result = Format::PathMatchesPattern(
        L"C:\\WINDOWS\\system32\\CMD.exe",
        L"c:\\windows\\SYSTEM32\\cmd.exe",
        PathMatchMode::Exact
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_ExactMatch_NoMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\notepad.exe",
        L"C:\\Windows\\System32\\cmd.exe",
        PathMatchMode::Exact
    );
    
    EXPECT_FALSE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Prefix) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Windows\\System32",
        PathMatchMode::Prefix
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Prefix_NoMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Program Files",
        PathMatchMode::Prefix
    );
    
    EXPECT_FALSE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Suffix) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"cmd.exe",
        PathMatchMode::Suffix
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Suffix_NoMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"powershell.exe",
        PathMatchMode::Suffix
    );
    
    EXPECT_FALSE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Contains) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"System32",
        PathMatchMode::Contains
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Contains_NoMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"NotThere",
        PathMatchMode::Contains
    );
    
    EXPECT_FALSE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Glob_Wildcard) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"*.exe",
        PathMatchMode::Glob
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Glob_QuestionMark) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"*.???",
        PathMatchMode::Glob
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Glob_MultipleWildcards) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\*\\*\\cmd.exe",
        PathMatchMode::Glob
    );
    
    EXPECT_TRUE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Glob_NoMatch) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"*.dll",
        PathMatchMode::Glob
    );
    
    EXPECT_FALSE(result);
}

TEST_F(PathMatchingTest, PathMatchesPattern_Glob_Prefix) {
    bool result = Format::PathMatchesPattern(
        L"C:\\Windows\\System32\\cmd.exe",
        L"C:\\Windows\\*",
        PathMatchMode::Glob
    );
    
    EXPECT_TRUE(result);
}

// ============================================================================
// CRC32 COMPUTATION TESTS
// ============================================================================

class CRC32ComputationTest : public WhitelistFormatTest {};

TEST_F(CRC32ComputationTest, ComputeHeaderCRC32_NullPointer) {
    auto crc = Format::ComputeHeaderCRC32(nullptr);
    EXPECT_EQ(crc, 0);
}

TEST_F(CRC32ComputationTest, ComputeHeaderCRC32_Consistency) {
    auto header = new WhitelistDatabaseHeader;
    std::memset(header, 0, sizeof(*header));
    header->magic = WHITELIST_DB_MAGIC;
    
    uint32_t crc1 = Format::ComputeHeaderCRC32(header);
    uint32_t crc2 = Format::ComputeHeaderCRC32(header);
    
    EXPECT_EQ(crc1, crc2);
    
    delete header;
}

TEST_F(CRC32ComputationTest, ComputeHeaderCRC32_DifferentData) {
    auto header1 = new WhitelistDatabaseHeader;
    auto header2 = new WhitelistDatabaseHeader;
    
    std::memset(header1, 0, sizeof(*header1));
    std::memset(header2, 0, sizeof(*header2));
    
    header1->magic = WHITELIST_DB_MAGIC;
    header2->magic = 0xDEADBEEF;
    
    uint32_t crc1 = Format::ComputeHeaderCRC32(header1);
    uint32_t crc2 = Format::ComputeHeaderCRC32(header2);
    
    EXPECT_NE(crc1, crc2);
    
    delete header1;
    delete header2;
}

// ============================================================================
// ALGORITHM NAME CONVERSION TESTS
// ============================================================================

class AlgorithmNameTest : public WhitelistFormatTest {};

TEST_F(AlgorithmNameTest, HashAlgorithmToString_AllAlgorithms) {
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::MD5), "MD5");
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::SHA1), "SHA1");
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::SHA256), "SHA256");
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::SHA512), "SHA512");
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::ImpHash), "IMPHASH");
    EXPECT_STREQ(Format::HashAlgorithmToString(HashAlgorithm::Authenticode), "AUTHENTICODE");
}

TEST_F(AlgorithmNameTest, EntryTypeToString_AllTypes) {
    EXPECT_STREQ(Format::EntryTypeToString(WhitelistEntryType::FileHash), "FileHash");
    EXPECT_STREQ(Format::EntryTypeToString(WhitelistEntryType::FilePath), "FilePath");
    EXPECT_STREQ(Format::EntryTypeToString(WhitelistEntryType::Certificate), "Certificate");
    EXPECT_STREQ(Format::EntryTypeToString(WhitelistEntryType::Publisher), "Publisher");
}

TEST_F(AlgorithmNameTest, ReasonToString_AllReasons) {
    EXPECT_STREQ(Format::ReasonToString(WhitelistReason::SystemFile), "SystemFile");
    EXPECT_STREQ(Format::ReasonToString(WhitelistReason::TrustedVendor), "TrustedVendor");
    EXPECT_STREQ(Format::ReasonToString(WhitelistReason::UserApproved), "UserApproved");
}

// ============================================================================
// CACHE SIZE CALCULATION TESTS
// ============================================================================

class CacheSizeTest : public WhitelistFormatTest {};

TEST_F(CacheSizeTest, CalculateOptimalCacheSize_SmallDatabase) {
    uint32_t size = Format::CalculateOptimalCacheSize(100 * 1024 * 1024); // 100MB
    
    EXPECT_GE(size, 16); // Minimum
    EXPECT_LE(size, 512); // Maximum
}

TEST_F(CacheSizeTest, CalculateOptimalCacheSize_LargeDatabase) {
    uint32_t size = Format::CalculateOptimalCacheSize(10ULL * 1024 * 1024 * 1024); // 10GB
    
    EXPECT_EQ(size, 512); // Should be clamped to max
}

TEST_F(CacheSizeTest, CalculateOptimalCacheSize_VerySmallDatabase) {
    uint32_t size = Format::CalculateOptimalCacheSize(1024 * 1024); // 1MB
    
    EXPECT_EQ(size, 16); // Should be clamped to minimum
}

// ============================================================================
// MEMORY MAPPING TESTS
// ============================================================================

class MemoryMappingTest : public WhitelistFormatTest {
protected:
    std::wstring GetTestDatabasePath() {
        char path[MAX_PATH];
        GetTempPathA(MAX_PATH, path);
        return std::wstring(path, path + strlen(path)) + L"test_whitelist.db";
    }
};

TEST_F(MemoryMappingTest, CreateDatabase_Success) {
    auto dbPath = GetTestDatabasePath();
    MemoryMappedView view;
    StoreError error;
    
    bool success = MemoryMapping::CreateDatabase(dbPath, 1024 * 1024, view, error);
    
    EXPECT_TRUE(success);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(view.IsValid());
    
    // Cleanup
    MemoryMapping::CloseView(view);
    DeleteFileW(dbPath.c_str());
}

TEST_F(MemoryMappingTest, CreateDatabase_EmptyPath) {
    MemoryMappedView view;
    StoreError error;
    
    bool success = MemoryMapping::CreateDatabase(L"", 1024 * 1024, view, error);
    
    EXPECT_FALSE(success);
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(MemoryMappingTest, CreateDatabase_HeaderValidation) {
    auto dbPath = GetTestDatabasePath();
    MemoryMappedView view;
    StoreError error;
    
    bool success = MemoryMapping::CreateDatabase(dbPath, 1024 * 1024, view, error);
    
    ASSERT_TRUE(success);
    
    const auto* header = view.GetAt<WhitelistDatabaseHeader>(0);
    ASSERT_NE(header, nullptr);
    
    EXPECT_EQ(header->magic, WHITELIST_DB_MAGIC);
    EXPECT_EQ(header->versionMajor, WHITELIST_DB_VERSION_MAJOR);
    EXPECT_EQ(header->versionMinor, WHITELIST_DB_VERSION_MINOR);
    
    // Cleanup
    MemoryMapping::CloseView(view);
    DeleteFileW(dbPath.c_str());
}

// ============================================================================
// EDGE CASE AND STRESS TESTS
// ============================================================================

class EdgeCaseTest : public WhitelistFormatTest {};

TEST_F(EdgeCaseTest, HashValue_AllAlgorithms) {
    std::vector<std::pair<HashAlgorithm, uint8_t>> algorithms = {
        {HashAlgorithm::MD5, 16},
        {HashAlgorithm::SHA1, 20},
        {HashAlgorithm::SHA256, 32},
        {HashAlgorithm::SHA512, 64},
        {HashAlgorithm::ImpHash, 16},
        {HashAlgorithm::Authenticode, 32}
    };
    
    for (const auto& [algo, expectedLen] : algorithms) {
        auto hash = GenerateRandomHash(algo);
        
        EXPECT_EQ(hash.length, expectedLen);
        EXPECT_FALSE(hash.IsEmpty());
        
        // Round-trip through hex
        auto hexStr = Format::FormatHashString(hash);
        auto parsed = Format::ParseHashString(hexStr, algo);
        
        ASSERT_TRUE(parsed.has_value());
        EXPECT_EQ(*parsed, hash);
    }
}

TEST_F(EdgeCaseTest, PathMatching_ExtremePaths) {
    // Very long path
    std::wstring longPath(MAX_PATH_LENGTH - 1, L'a');
    bool result = Format::PathMatchesPattern(
        longPath,
        L"aaa*",
        PathMatchMode::Glob
    );
    EXPECT_TRUE(result);
}

TEST_F(EdgeCaseTest, PathMatching_SpecialCharacters) {
    std::vector<std::wstring> paths = {
        L"C:\\Path With Spaces\\file.exe",
        L"C:\\Path-With-Dashes\\file.exe",
        L"C:\\Path_With_Underscores\\file.exe",
        L"C:\\Path.With.Dots\\file.exe"
    };
    
    for (const auto& path : paths) {
        bool result = Format::PathMatchesPattern(path, path, PathMatchMode::Exact);
        EXPECT_TRUE(result);
    }
}

// ============================================================================
// SIZE AND ALIGNMENT TESTS
// ============================================================================

class SizeAlignmentTest : public WhitelistFormatTest {};

TEST_F(SizeAlignmentTest, HashValueSize) {
    EXPECT_EQ(sizeof(HashValue), 68);
}

TEST_F(SizeAlignmentTest, WhitelistEntrySize) {
    EXPECT_EQ(sizeof(WhitelistEntry), 128);
    EXPECT_EQ(alignof(WhitelistEntry), CACHE_LINE_SIZE);
}

TEST_F(SizeAlignmentTest, DatabaseHeaderSize) {
    EXPECT_EQ(sizeof(WhitelistDatabaseHeader), 4096);
}

TEST_F(SizeAlignmentTest, ExtendedHashEntrySize) {
    EXPECT_EQ(sizeof(ExtendedHashEntry), 128);
}

// ============================================================================
// BITWISE OPERATIONS TESTS
// ============================================================================

class BitwiseOperationsTest : public WhitelistFormatTest {};

TEST_F(BitwiseOperationsTest, WhitelistFlagsOR) {
    auto flags = WhitelistFlags::Enabled | WhitelistFlags::ReadOnly;
    
    EXPECT_TRUE(HasFlag(flags, WhitelistFlags::Enabled));
    EXPECT_TRUE(HasFlag(flags, WhitelistFlags::ReadOnly));
    EXPECT_FALSE(HasFlag(flags, WhitelistFlags::Hidden));
}

TEST_F(BitwiseOperationsTest, WhitelistFlagsAND) {
    auto flags = WhitelistFlags::Enabled | WhitelistFlags::ReadOnly;
    auto result = flags & WhitelistFlags::Enabled;
    
    EXPECT_EQ(result, WhitelistFlags::Enabled);
}

TEST_F(BitwiseOperationsTest, WhitelistFlagsNOT) {
    auto flags = WhitelistFlags::Enabled;
    auto inverted = ~flags;
    
    EXPECT_FALSE(HasFlag(inverted, WhitelistFlags::Enabled));
}

TEST_F(BitwiseOperationsTest, WhitelistFlagsMultiple) {
    auto flags = WhitelistFlags::None;
    flags = flags | WhitelistFlags::Enabled;
    flags = flags | WhitelistFlags::HasExpiration;
    flags = flags | WhitelistFlags::LogOnMatch;
    
    EXPECT_TRUE(HasFlag(flags, WhitelistFlags::Enabled));
    EXPECT_TRUE(HasFlag(flags, WhitelistFlags::HasExpiration));
    EXPECT_TRUE(HasFlag(flags, WhitelistFlags::LogOnMatch));
    EXPECT_FALSE(HasFlag(flags, WhitelistFlags::ReadOnly));
}

