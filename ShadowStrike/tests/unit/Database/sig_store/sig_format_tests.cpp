/*
 * ============================================================================
 * ShadowStrike SignatureFormat - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade unit tests for SignatureFormat module
 * Tests cover binary format validation, hash parsing, memory mapping, etc.
 *
 * Test Categories:
 * - HashValue structure and operations
 * - HashType utilities
 * - Hash string parsing and formatting
 * - SignatureDatabaseHeader validation
 * - Memory-mapped view operations
 * - Alignment and size calculations
 * - RAII resource management
 * - Error handling
 * - Edge cases and boundary conditions
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../src/SignatureStore/SignatureFormat.hpp"
#include <filesystem>
#include <fstream>
#include <random>
#include <array>
#include <cstring>

using namespace ShadowStrike::SignatureStore;
namespace fs = std::filesystem;

// ============================================================================
// TEST FIXTURES & UTILITIES
// ============================================================================

class SignatureFormatTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        testDir = fs::temp_directory_path() / L"shadowstrike_sigformat_tests";
        fs::create_directories(testDir);
    }

    void TearDown() override {
        // Cleanup test files
        try {
            if (fs::exists(testDir)) {
                fs::remove_all(testDir);
            }
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }

    // Helper: Create valid test header
    [[nodiscard]] SignatureDatabaseHeader CreateValidHeader() const noexcept {
        SignatureDatabaseHeader header{};
        
        header.magic = SIGNATURE_DB_MAGIC;
        header.versionMajor = SIGNATURE_DB_VERSION_MAJOR;
        header.versionMinor = SIGNATURE_DB_VERSION_MINOR;
        
        // Page-aligned offsets
        header.hashIndexOffset = PAGE_SIZE;
        header.hashIndexSize = PAGE_SIZE * 10;
        header.patternIndexOffset = PAGE_SIZE * 11;
        header.patternIndexSize = PAGE_SIZE * 5;
        header.yaraRulesOffset = PAGE_SIZE * 16;
        header.yaraRulesSize = PAGE_SIZE * 2;
        header.metadataOffset = PAGE_SIZE * 18;
        header.metadataSize = PAGE_SIZE;
        header.stringPoolOffset = PAGE_SIZE * 19;
        header.stringPoolSize = PAGE_SIZE * 3;
        
        // Valid timestamps
        header.creationTime = 1700000000; // 2023
        header.lastUpdateTime = 1700100000;
        
        header.totalHashes = 1000;
        header.totalPatterns = 500;
        header.totalYaraRules = 100;
        
        return header;
    }

    // Helper: Create test file
    [[nodiscard]] bool CreateTestFile(
        const std::wstring& filename,
        const void* data,
        size_t dataSize
    ) const noexcept {
        fs::path filePath = testDir / filename;
        
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }
        
        file.write(static_cast<const char*>(data), dataSize);
        return file.good();
    }

    // Helper: Create database file with valid header
    [[nodiscard]] fs::path CreateValidDatabaseFile(
        const std::wstring& filename,
        size_t totalSize = 100 * PAGE_SIZE
    ) const noexcept {
        fs::path filePath = testDir / filename;
        
        std::vector<uint8_t> buffer(totalSize, 0);
        
        // Write valid header
        SignatureDatabaseHeader header = CreateValidHeader();
        std::memcpy(buffer.data(), &header, sizeof(header));
        
        std::ofstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return {};
        }
        
        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        
        return file.good() ? filePath : fs::path{};
    }

    fs::path testDir;
};

// ============================================================================
// HASHVALUE STRUCTURE TESTS
// ============================================================================

TEST(HashValueTest, DefaultConstruction) {
    HashValue hash{};
    
    EXPECT_EQ(hash.type, HashType::MD5);
    EXPECT_EQ(hash.length, 0);
    
    // Data should be zero-initialized
    for (size_t i = 0; i < hash.data.size(); ++i) {
        EXPECT_EQ(hash.data[i], 0);
    }
}

TEST(HashValueTest, SizeIsExact68Bytes) {
    // Critical: HashValue must be exactly 68 bytes for memory mapping
    EXPECT_EQ(sizeof(HashValue), 68);
}

TEST(HashValueTest, EqualityOperator) {
    HashValue hash1{};
    hash1.type = HashType::SHA256;
    hash1.length = 32;
    std::fill_n(hash1.data.data(), 32, 0xAB);
    
    HashValue hash2{};
    hash2.type = HashType::SHA256;
    hash2.length = 32;
    std::fill_n(hash2.data.data(), 32, 0xAB);
    
    HashValue hash3{};
    hash3.type = HashType::SHA256;
    hash3.length = 32;
    std::fill_n(hash3.data.data(), 32, 0xCD);
    
    EXPECT_TRUE(hash1 == hash2);
    EXPECT_FALSE(hash1 == hash3);
}

TEST(HashValueTest, EqualityWithDifferentTypes) {
    HashValue hash1{};
    hash1.type = HashType::MD5;
    hash1.length = 16;
    std::fill_n(hash1.data.data(), 16, 0xAB);
    
    HashValue hash2{};
    hash2.type = HashType::SHA256;
    hash2.length = 16;
    std::fill_n(hash2.data.data(), 16, 0xAB);
    
    EXPECT_FALSE(hash1 == hash2);
}

TEST(HashValueTest, EqualityWithDifferentLengths) {
    HashValue hash1{};
    hash1.type = HashType::SHA256;
    hash1.length = 16;
    std::fill_n(hash1.data.data(), 32, 0xAB);
    
    HashValue hash2{};
    hash2.type = HashType::SHA256;
    hash2.length = 32;
    std::fill_n(hash2.data.data(), 32, 0xAB);
    
    EXPECT_FALSE(hash1 == hash2);
}

TEST(HashValueTest, FastHashConsistency) {
    HashValue hash{};
    hash.type = HashType::SHA256;
    hash.length = 32;
    
    for (uint8_t i = 0; i < 32; ++i) {
        hash.data[i] = i;
    }
    
    uint64_t fastHash1 = hash.FastHash();
    uint64_t fastHash2 = hash.FastHash();
    
    EXPECT_EQ(fastHash1, fastHash2);
}

TEST(HashValueTest, FastHashDifferentForDifferentData) {
    HashValue hash1{};
    hash1.type = HashType::SHA256;
    hash1.length = 32;
    std::fill_n(hash1.data.data(), 32, 0xAA);
    
    HashValue hash2{};
    hash2.type = HashType::SHA256;
    hash2.length = 32;
    std::fill_n(hash2.data.data(), 32, 0xBB);
    
    EXPECT_NE(hash1.FastHash(), hash2.FastHash());
}

TEST(HashValueTest, FastHashZeroLength) {
    HashValue hash{};
    hash.type = HashType::SHA256;
    hash.length = 0;
    
    // Should not crash
    uint64_t fastHash = hash.FastHash();
    
    // Zero-length hash should still produce consistent result
    EXPECT_EQ(fastHash, hash.FastHash());
}

// ============================================================================
// HASH LENGTH UTILITY TESTS
// ============================================================================

TEST(GetHashLengthTest, MD5Is16Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::MD5), 16);
}

TEST(GetHashLengthTest, SHA1Is20Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::SHA1), 20);
}

TEST(GetHashLengthTest, SHA256Is32Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::SHA256), 32);
}

TEST(GetHashLengthTest, SHA512Is64Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::SHA512), 64);
}

TEST(GetHashLengthTest, IMPHASHIs16Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::IMPHASH), 16);
}

TEST(GetHashLengthTest, SSDeepIs64Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::SSDEEP), 64);
}

TEST(GetHashLengthTest, TLSHIs35Bytes) {
    EXPECT_EQ(GetHashLengthForType(HashType::TLSH), 35);
}

// ============================================================================
// HASHTYPE TO STRING TESTS
// ============================================================================

TEST(HashTypeToStringTest, AllTypesHaveValidStrings) {
    EXPECT_STREQ(Format::HashTypeToString(HashType::MD5), "MD5");
    EXPECT_STREQ(Format::HashTypeToString(HashType::SHA1), "SHA1");
    EXPECT_STREQ(Format::HashTypeToString(HashType::SHA256), "SHA256");
    EXPECT_STREQ(Format::HashTypeToString(HashType::SHA512), "SHA512");
    EXPECT_STREQ(Format::HashTypeToString(HashType::IMPHASH), "IMPHASH");
    EXPECT_STREQ(Format::HashTypeToString(HashType::SSDEEP), "SSDEEP");
    EXPECT_STREQ(Format::HashTypeToString(HashType::TLSH), "TLSH");
}

TEST(HashTypeToStringTest, InvalidTypeReturnsUnknown) {
    HashType invalid = static_cast<HashType>(255);
    EXPECT_STREQ(Format::HashTypeToString(invalid), "UNKNOWN");
}

// ============================================================================
// HASH STRING PARSING TESTS
// ============================================================================

TEST(ParseHashStringTest, ValidMD5) {
    std::string md5Hex = "d41d8cd98f00b204e9800998ecf8427e";
    
    auto result = Format::ParseHashString(md5Hex, HashType::MD5);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, HashType::MD5);
    EXPECT_EQ(result->length, 16);
    
    // Verify first and last bytes
    EXPECT_EQ(result->data[0], 0xD4);
    EXPECT_EQ(result->data[15], 0x7E);
}

TEST(ParseHashStringTest, ValidSHA1) {
    std::string sha1Hex = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    
    auto result = Format::ParseHashString(sha1Hex, HashType::SHA1);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, HashType::SHA1);
    EXPECT_EQ(result->length, 20);
}

TEST(ParseHashStringTest, ValidSHA256) {
    std::string sha256Hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    auto result = Format::ParseHashString(sha256Hex, HashType::SHA256);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, HashType::SHA256);
    EXPECT_EQ(result->length, 32);
}

TEST(ParseHashStringTest, ValidSHA512) {
    std::string sha512Hex = 
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    
    auto result = Format::ParseHashString(sha512Hex, HashType::SHA512);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, HashType::SHA512);
    EXPECT_EQ(result->length, 64);
}

TEST(ParseHashStringTest, UppercaseHexAccepted) {
    std::string upperMd5 = "D41D8CD98F00B204E9800998ECF8427E";
    
    auto result = Format::ParseHashString(upperMd5, HashType::MD5);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 16);
}

TEST(ParseHashStringTest, MixedCaseHexAccepted) {
    std::string mixedMd5 = "D41d8Cd98f00B204e9800998ecF8427E";
    
    auto result = Format::ParseHashString(mixedMd5, HashType::MD5);
    
    ASSERT_TRUE(result.has_value());
}

TEST(ParseHashStringTest, WhitespaceStripped) {
    std::string withSpaces = "  d41d8cd9 8f00b204 e9800998 ecf8427e  ";
    
    auto result = Format::ParseHashString(withSpaces, HashType::MD5);
    
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 16);
}

TEST(ParseHashStringTest, EmptyStringReturnsNullopt) {
    auto result = Format::ParseHashString("", HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

TEST(ParseHashStringTest, WrongLengthReturnsNullopt) {
    // MD5 should be 32 hex chars, this is 30
    std::string shortHash = "d41d8cd98f00b204e9800998ecf842";
    
    auto result = Format::ParseHashString(shortHash, HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

TEST(ParseHashStringTest, OddLengthReturnsNullopt) {
    std::string oddLength = "d41d8cd98f00b204e9800998ecf8427"; // 31 chars
    
    auto result = Format::ParseHashString(oddLength, HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

TEST(ParseHashStringTest, InvalidHexCharacterReturnsNullopt) {
    std::string invalidHex = "d41d8cd98f00b204e9800998ecf8427g"; // 'g' is invalid
    
    auto result = Format::ParseHashString(invalidHex, HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

TEST(ParseHashStringTest, VeryLongStringReturnsNullopt) {
    std::string longString(1000, 'a');
    
    auto result = Format::ParseHashString(longString, HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// HASH STRING FORMATTING TESTS
// ============================================================================

TEST(FormatHashStringTest, FormatMD5) {
    HashValue hash{};
    hash.type = HashType::MD5;
    hash.length = 16;
    
    // Set known values
    hash.data[0] = 0xD4;
    hash.data[1] = 0x1D;
    hash.data[14] = 0x42;
    hash.data[15] = 0x7E;
    
    std::string formatted = Format::FormatHashString(hash);
    
    EXPECT_EQ(formatted.length(), 32);
    EXPECT_EQ(formatted.substr(0, 4), "d41d");
    EXPECT_EQ(formatted.substr(28, 4), "427e");
}

TEST(FormatHashStringTest, FormatSHA256) {
    HashValue hash{};
    hash.type = HashType::SHA256;
    hash.length = 32;
    
    for (uint8_t i = 0; i < 32; ++i) {
        hash.data[i] = i;
    }
    
    std::string formatted = Format::FormatHashString(hash);
    
    EXPECT_EQ(formatted.length(), 64);
    EXPECT_EQ(formatted.substr(0, 8), "00010203");
}

TEST(FormatHashStringTest, ZeroLengthReturnsEmpty) {
    HashValue hash{};
    hash.type = HashType::SHA256;
    hash.length = 0;
    
    std::string formatted = Format::FormatHashString(hash);
    
    EXPECT_TRUE(formatted.empty());
}

TEST(FormatHashStringTest, InvalidLengthReturnsEmpty) {
    HashValue hash{};
    hash.type = HashType::SHA256;
    hash.length = 100; // Exceeds data array size
    
    std::string formatted = Format::FormatHashString(hash);
    
    EXPECT_TRUE(formatted.empty());
}

TEST(FormatHashStringTest, RoundTripPreservesData) {
    std::string original = "d41d8cd98f00b204e9800998ecf8427e";
    
    auto parsed = Format::ParseHashString(original, HashType::MD5);
    ASSERT_TRUE(parsed.has_value());
    
    std::string formatted = Format::FormatHashString(*parsed);
    
    EXPECT_EQ(formatted, original);
}

// ============================================================================
// HEADER VALIDATION TESTS
// ============================================================================

TEST_F(SignatureFormatTestFixture, ValidHeaderPassesValidation) {
    SignatureDatabaseHeader header = CreateValidHeader();
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_TRUE(result);
}

TEST_F(SignatureFormatTestFixture, NullHeaderFails) {
    bool result = Format::ValidateHeader(nullptr);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, InvalidMagicFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    header.magic = 0xDEADBEEF;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, InvalidVersionFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    header.versionMajor = 99;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, MisalignedOffsetFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    header.hashIndexOffset = PAGE_SIZE + 1; // Not page-aligned
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, OverlappingSectionsFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    
    // Make sections overlap
    header.hashIndexOffset = PAGE_SIZE;
    header.hashIndexSize = PAGE_SIZE * 20;
    header.patternIndexOffset = PAGE_SIZE * 10; // Overlaps with hash index
    header.patternIndexSize = PAGE_SIZE * 5;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, OffsetPlusSizeOverflowFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    
    // Cause overflow
    header.hashIndexOffset = UINT64_MAX - 100;
    header.hashIndexSize = 1000;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, SizeExceedsMaxFails) {
    SignatureDatabaseHeader header = CreateValidHeader();
    header.hashIndexSize = MAX_DATABASE_SIZE + 1;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_FALSE(result);
}

TEST_F(SignatureFormatTestFixture, ZeroOffsetsAreValid) {
    SignatureDatabaseHeader header = CreateValidHeader();
    
    // Zero offset means section not present
    header.yaraRulesOffset = 0;
    header.yaraRulesSize = 0;
    
    bool result = Format::ValidateHeader(&header);
    
    EXPECT_TRUE(result);
}

TEST_F(SignatureFormatTestFixture, InvalidTimestampOrderWarnsButPasses) {
    SignatureDatabaseHeader header = CreateValidHeader();
    
    // Creation time after last update (suspicious but not fatal)
    header.creationTime = 1700200000;
    header.lastUpdateTime = 1700100000;
    
    bool result = Format::ValidateHeader(&header);
    
    // Should pass (warning only)
    EXPECT_TRUE(result);
}

// ============================================================================
// ALIGNMENT UTILITY TESTS
// ============================================================================

TEST(AlignmentTest, AlignToPageZero) {
    EXPECT_EQ(Format::AlignToPage(0), 0);
}

TEST(AlignmentTest, AlignToPageAlreadyAligned) {
    EXPECT_EQ(Format::AlignToPage(PAGE_SIZE), PAGE_SIZE);
    EXPECT_EQ(Format::AlignToPage(PAGE_SIZE * 5), PAGE_SIZE * 5);
}

TEST(AlignmentTest, AlignToPageRoundsUp) {
    EXPECT_EQ(Format::AlignToPage(1), PAGE_SIZE);
    EXPECT_EQ(Format::AlignToPage(PAGE_SIZE - 1), PAGE_SIZE);
    EXPECT_EQ(Format::AlignToPage(PAGE_SIZE + 1), PAGE_SIZE * 2);
}

TEST(AlignmentTest, AlignToCacheLineZero) {
    EXPECT_EQ(Format::AlignToCacheLine(0), 0);
}

TEST(AlignmentTest, AlignToCacheLineAlreadyAligned) {
    EXPECT_EQ(Format::AlignToCacheLine(CACHE_LINE_SIZE), CACHE_LINE_SIZE);
    EXPECT_EQ(Format::AlignToCacheLine(CACHE_LINE_SIZE * 10), CACHE_LINE_SIZE * 10);
}

TEST(AlignmentTest, AlignToCacheLineRoundsUp) {
    EXPECT_EQ(Format::AlignToCacheLine(1), CACHE_LINE_SIZE);
    EXPECT_EQ(Format::AlignToCacheLine(CACHE_LINE_SIZE - 1), CACHE_LINE_SIZE);
    EXPECT_EQ(Format::AlignToCacheLine(CACHE_LINE_SIZE + 1), CACHE_LINE_SIZE * 2);
}

// ============================================================================
// CACHE SIZE CALCULATION TESTS
// ============================================================================

TEST(CacheSizeCalculationTest, SmallDatabaseGetsMinimumCache) {
    uint64_t smallDb = 10 * 1024 * 1024; // 10MB
    
    uint32_t cacheSize = Format::CalculateOptimalCacheSize(smallDb);
    
    EXPECT_EQ(cacheSize, 16); // Minimum 16MB
}

TEST(CacheSizeCalculationTest, LargeDatabaseGetsMaximumCache) {
    uint64_t largeDb = 100ULL * 1024 * 1024 * 1024; // 100GB
    
    uint32_t cacheSize = Format::CalculateOptimalCacheSize(largeDb);
    
    EXPECT_EQ(cacheSize, 512); // Maximum 512MB
}

TEST(CacheSizeCalculationTest, MediumDatabaseGetsProportionalCache) {
    uint64_t mediumDb = 2ULL * 1024 * 1024 * 1024; // 2GB
    
    uint32_t cacheSize = Format::CalculateOptimalCacheSize(mediumDb);
    
    // 5% of 2GB = ~102MB
    EXPECT_GT(cacheSize, 16);
    EXPECT_LT(cacheSize, 512);
}

// ============================================================================
// MEMORY-MAPPED VIEW TESTS
// ============================================================================

TEST_F(SignatureFormatTestFixture, OpenViewValidDatabase) {
    fs::path dbPath = CreateValidDatabaseFile(L"valid_db.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    bool result = MemoryMapping::OpenView(dbPath.wstring(), true, view, error);
    
    EXPECT_TRUE(result) << "Error: " << error.message;
    EXPECT_TRUE(view.IsValid());
    EXPECT_NE(view.baseAddress, nullptr);
    EXPECT_GT(view.fileSize, 0);
    EXPECT_TRUE(view.readOnly);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, OpenViewNonExistentFileFails) {
    MemoryMappedView view{};
    StoreError error{};
    
    fs::path nonExistent = testDir / L"does_not_exist.ssdb";
    
    bool result = MemoryMapping::OpenView(nonExistent.wstring(), true, view, error);
    
    EXPECT_FALSE(result);
    EXPECT_EQ(error.code, SignatureStoreError::FileNotFound);
    EXPECT_FALSE(view.IsValid());
}

TEST_F(SignatureFormatTestFixture, OpenViewEmptyPathFails) {
    MemoryMappedView view{};
    StoreError error{};
    
    bool result = MemoryMapping::OpenView(L"", true, view, error);
    
    EXPECT_FALSE(result);
    EXPECT_EQ(error.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureFormatTestFixture, OpenViewTooSmallFileFails) {
    // Create file smaller than header
    fs::path smallFile = testDir / L"small_file.ssdb";
    std::ofstream file(smallFile, std::ios::binary);
    file << "tiny";
    file.close();
    
    MemoryMappedView view{};
    StoreError error{};
    
    bool result = MemoryMapping::OpenView(smallFile.wstring(), true, view, error);
    
    EXPECT_FALSE(result);
    EXPECT_EQ(error.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureFormatTestFixture, OpenViewInvalidHeaderFails) {
    // Create file with invalid header
    fs::path invalidFile = testDir / L"invalid_header.ssdb";
    
    std::vector<uint8_t> buffer(sizeof(SignatureDatabaseHeader) * 2, 0);
    
    // Write garbage header
    uint32_t invalidMagic = 0xDEADBEEF;
    std::memcpy(buffer.data(), &invalidMagic, sizeof(invalidMagic));
    
    std::ofstream file(invalidFile, std::ios::binary);
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    file.close();
    
    MemoryMappedView view{};
    StoreError error{};
    
    bool result = MemoryMapping::OpenView(invalidFile.wstring(), true, view, error);
    
    EXPECT_FALSE(result);
    EXPECT_EQ(error.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureFormatTestFixture, CloseViewSafe) {
    fs::path dbPath = CreateValidDatabaseFile(L"close_test.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    ASSERT_TRUE(view.IsValid());
    
    MemoryMapping::CloseView(view);
    
    EXPECT_FALSE(view.IsValid());
    EXPECT_EQ(view.baseAddress, nullptr);
    EXPECT_EQ(view.fileSize, 0);
}

TEST_F(SignatureFormatTestFixture, CloseViewIdempotent) {
    MemoryMappedView view{};
    
    // Should not crash on empty view
    MemoryMapping::CloseView(view);
    MemoryMapping::CloseView(view);
    
    EXPECT_FALSE(view.IsValid());
}

TEST_F(SignatureFormatTestFixture, OpenViewReadWrite) {
    fs::path dbPath = CreateValidDatabaseFile(L"readwrite_test.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    bool result = MemoryMapping::OpenView(dbPath.wstring(), false, view, error);
    
    EXPECT_TRUE(result) << "Error: " << error.message;
    EXPECT_FALSE(view.readOnly);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, FlushViewReadOnlyFails) {
    fs::path dbPath = CreateValidDatabaseFile(L"flush_readonly.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    
    bool result = MemoryMapping::FlushView(view, error);
    
    EXPECT_FALSE(result);
    EXPECT_EQ(error.code, SignatureStoreError::AccessDenied);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, FlushViewReadWrite) {
    fs::path dbPath = CreateValidDatabaseFile(L"flush_readwrite.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), false, view, error));
    
    bool result = MemoryMapping::FlushView(view, error);
    
    EXPECT_TRUE(result) << "Error: " << error.message;
    
    MemoryMapping::CloseView(view);
}

// ============================================================================
// MEMORY MAPPED VIEW TEMPLATE METHODS TESTS
// ============================================================================

TEST_F(SignatureFormatTestFixture, GetAtValidOffset) {
    fs::path dbPath = CreateValidDatabaseFile(L"getat_test.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    
    const SignatureDatabaseHeader* header = view.GetAt<SignatureDatabaseHeader>(0);
    
    ASSERT_NE(header, nullptr);
    EXPECT_EQ(header->magic, SIGNATURE_DB_MAGIC);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, GetAtInvalidOffsetReturnsNull) {
    fs::path dbPath = CreateValidDatabaseFile(L"getat_invalid.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    
    // Offset past end of file
    const uint32_t* ptr = view.GetAt<uint32_t>(view.fileSize + 100);
    
    EXPECT_EQ(ptr, nullptr);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, GetSpanValidRange) {
    fs::path dbPath = CreateValidDatabaseFile(L"getspan_test.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    
    auto span = view.GetSpan(0, 100);
    
    EXPECT_EQ(span.size(), 100);
    EXPECT_NE(span.data(), nullptr);
    
    MemoryMapping::CloseView(view);
}

TEST_F(SignatureFormatTestFixture, GetSpanInvalidRangeReturnsEmpty) {
    fs::path dbPath = CreateValidDatabaseFile(L"getspan_invalid.ssdb");
    ASSERT_FALSE(dbPath.empty());
    
    MemoryMappedView view{};
    StoreError error{};
    
    ASSERT_TRUE(MemoryMapping::OpenView(dbPath.wstring(), true, view, error));
    
    // Range past end of file
    auto span = view.GetSpan(view.fileSize - 10, 100);
    
    EXPECT_TRUE(span.empty());
    
    MemoryMapping::CloseView(view);
}

// ============================================================================
// STORE ERROR TESTS
// ============================================================================

TEST(StoreErrorTest, DefaultIsSuccess) {
    StoreError error{};
    
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(static_cast<bool>(error));
}

TEST(StoreErrorTest, SuccessFactory) {
    StoreError error = StoreError::Success();
    
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(error.code, SignatureStoreError::Success);
}

TEST(StoreErrorTest, FromWin32Factory) {
    StoreError error = StoreError::FromWin32(SignatureStoreError::FileNotFound, 2);
    
    EXPECT_FALSE(error.IsSuccess());
    EXPECT_EQ(error.code, SignatureStoreError::FileNotFound);
    EXPECT_EQ(error.win32Error, 2);
}

TEST(StoreErrorTest, ClearResetsToSuccess) {
    StoreError error{};
    error.code = SignatureStoreError::InvalidFormat;
    error.win32Error = 123;
    error.message = "Test error";
    
    error.Clear();
    
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(error.win32Error, 0);
    EXPECT_TRUE(error.message.empty());
}

// ============================================================================
// BINARY STRUCTURE SIZE TESTS (Critical for Memory Mapping)
// ============================================================================

TEST(StructureSizeTest, HashValueIs68Bytes) {
    EXPECT_EQ(sizeof(HashValue), 68);
}

TEST(StructureSizeTest, PatternEntryIs48Bytes) {
    EXPECT_EQ(sizeof(PatternEntry), 48);
}

TEST(StructureSizeTest, YaraRuleEntryIs48Bytes) {
    EXPECT_EQ(sizeof(YaraRuleEntry), 48);
}

TEST(StructureSizeTest, HeaderIs4096Bytes) {
    EXPECT_EQ(sizeof(SignatureDatabaseHeader), 4096);
}

TEST(StructureSizeTest, BPlusTreeNodeFitsInPage) {
    EXPECT_LE(sizeof(BPlusTreeNode), PAGE_SIZE);
}

TEST(StructureSizeTest, TrieNodeBinaryCorrectSize) {
    EXPECT_EQ(sizeof(TrieNodeBinary), 1052);
}

TEST(StructureSizeTest, TrieIndexHeaderIs96Bytes) {
    EXPECT_EQ(sizeof(TrieIndexHeader), 96);
}

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

TEST(ConstantsTest, PageSizeIs4096) {
    EXPECT_EQ(PAGE_SIZE, 4096);
}

TEST(ConstantsTest, CacheLineSizeIs64) {
    EXPECT_EQ(CACHE_LINE_SIZE, 64);
}

TEST(ConstantsTest, SectorSizeIs512) {
    EXPECT_EQ(SECTOR_SIZE, 512);
}

TEST(ConstantsTest, MagicNumberIsValid) {
    // 'SSSD' = ShadowStrike Signature Database
    EXPECT_EQ(SIGNATURE_DB_MAGIC, 0x53535344);
}

TEST(ConstantsTest, MaxDatabaseSizeIs16GB) {
    EXPECT_EQ(MAX_DATABASE_SIZE, 16ULL * 1024 * 1024 * 1024);
}

// ============================================================================
// DETECTION RESULT TESTS
// ============================================================================

TEST(DetectionResultTest, DefaultConstruction) {
    DetectionResult result{};
    
    EXPECT_EQ(result.signatureId, 0);
    EXPECT_TRUE(result.signatureName.empty());
    EXPECT_EQ(result.threatLevel, ThreatLevel::Info);
}

TEST(DetectionResultTest, MoveConstruction) {
    DetectionResult original{};
    original.signatureId = 12345;
    original.signatureName = "TestTrojan";
    original.threatLevel = ThreatLevel::Critical;
    original.tags.push_back("malware");
    
    DetectionResult moved = std::move(original);
    
    EXPECT_EQ(moved.signatureId, 12345);
    EXPECT_EQ(moved.signatureName, "TestTrojan");
    EXPECT_EQ(moved.threatLevel, ThreatLevel::Critical);
    EXPECT_EQ(moved.tags.size(), 1);
}

TEST(DetectionResultTest, ComparisonByThreatLevel) {
    DetectionResult high{};
    high.threatLevel = ThreatLevel::High;
    
    DetectionResult low{};
    low.threatLevel = ThreatLevel::Low;
    
    // Higher threat level should be "less than" for sorting purposes
    EXPECT_TRUE(high < low);
}

// ============================================================================
// THREAT LEVEL TESTS
// ============================================================================

TEST(ThreatLevelTest, ValuesAreCorrect) {
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::Info), 0);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::Low), 25);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::Medium), 50);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::High), 75);
    EXPECT_EQ(static_cast<uint8_t>(ThreatLevel::Critical), 100);
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
