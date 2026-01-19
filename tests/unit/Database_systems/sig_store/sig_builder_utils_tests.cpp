// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


/*
 * ============================================================================
 * ShadowStrike SignatureBuilder Utils - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade test suite for SignatureBuilder utility functions
 * Tests hash computation, comparison, and RAII resource management
 *
 * Test Categories:
 * 1. File Hash Computation Tests
 * 2. Buffer Hash Computation Tests
 * 3. Hash Comparison Tests
 * 4. RAII Resource Management Tests
 * 5. Error Handling & Edge Cases
 * 6. Performance & Security Tests
 *
 * ============================================================================
 */
#include"pch.h"
#include <gtest/gtest.h>
#include "../../src/SignatureStore/SignatureBuilder.hpp"
#include "../../src/SignatureStore/SignatureFormat.hpp"
#include <filesystem>
#include <fstream>
#include<vector>
#include<future>
#include<optional>
#include <random>
#include <thread>
#include <chrono>

using namespace ShadowStrike::SignatureStore;

// ============================================================================
// TEST FIXTURES
// ============================================================================

class SignatureBuilderUtilsTest : public ::testing::Test {
protected:
    std::unique_ptr<SignatureBuilder> m_builder;
    std::wstring m_tempDir;

    void SetUp() override {
        m_builder = std::make_unique<SignatureBuilder>();
        m_tempDir = std::filesystem::temp_directory_path().wstring();
    }

    void TearDown() override {
        m_builder.reset();
        CleanupTempFiles();
    }

    // Helper: Create temporary file with content
    std::wstring CreateTempFile(const std::string& content, const std::wstring& filename = L"test.bin") {
        auto filePath = std::filesystem::path(m_tempDir) / filename;
        std::ofstream file(filePath, std::ios::binary);
        file.write(content.data(), content.size());
        file.close();
        m_tempFiles.push_back(filePath.wstring());
        return filePath.wstring();
    }

    // Helper: Create temporary file with specific size
    std::wstring CreateTempFileWithSize(size_t sizeBytes, const std::wstring& filename = L"test_large.bin") {
        auto filePath = std::filesystem::path(m_tempDir) / filename;
        std::ofstream file(filePath, std::ios::binary);
        
        std::vector<uint8_t> buffer(1024 * 1024, 0xAA);  // 1MB chunks
        size_t remaining = sizeBytes;
        
        while (remaining > 0) {
            size_t toWrite = std::min(buffer.size(), remaining);
            file.write(reinterpret_cast<const char*>(buffer.data()), toWrite);
            remaining -= toWrite;
        }
        
        file.close();
        m_tempFiles.push_back(filePath.wstring());
        return filePath.wstring();
    }

    // Helper: Cleanup temporary files
    void CleanupTempFiles() {
        for (const auto& file : m_tempFiles) {
            try {
                std::filesystem::remove(file);
            } catch (...) {}
        }
        m_tempFiles.clear();
    }

    // Helper: Convert hex string to bytes
    std::vector<uint8_t> HexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteStr = hex.substr(i, 2);
            bytes.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
        }
        return bytes;
    }
 std::vector<std::wstring> m_tempFiles;
   
};

// ============================================================================
// FILE HASH COMPUTATION TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_MD5_BasicFile) {
    // Create test file with known content
    std::string content = "The quick brown fox jumps over the lazy dog";
    auto filePath = CreateTempFile(content);

    auto hash = m_builder->ComputeFileHash(filePath, HashType::MD5);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::MD5);
    EXPECT_EQ(hash->length, 16);
    
    // MD5("The quick brown fox jumps over the lazy dog") = 9e107d9d372bb6826bd81d3542a419d6
    auto expectedHash = HexToBytes("9e107d9d372bb6826bd81d3542a419d6");
    EXPECT_TRUE(std::equal(expectedHash.begin(), expectedHash.end(), hash->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_SHA256_BasicFile) {
    std::string content = "test content";
    auto filePath = CreateTempFile(content);

    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::SHA256);
    EXPECT_EQ(hash->length, 32);
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_SHA512_BasicFile) {
    std::string content = "test";
    auto filePath = CreateTempFile(content);

    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA512);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::SHA512);
    EXPECT_EQ(hash->length, 64);
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_EmptyFile) {
    auto filePath = CreateTempFile("");

    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::SHA256);
    EXPECT_EQ(hash->length, 32);
    
    // SHA256 of empty string = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    auto expectedHash = HexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_TRUE(std::equal(expectedHash.begin(), expectedHash.end(), hash->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_NonExistentFile) {
    std::wstring nonExistentPath = m_tempDir + L"\\nonexistent_file.bin";

    auto hash = m_builder->ComputeFileHash(nonExistentPath, HashType::SHA256);

    EXPECT_FALSE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_EmptyPath) {
    auto hash = m_builder->ComputeFileHash(L"", HashType::SHA256);

    EXPECT_FALSE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_InvalidHashType_IMPHASH) {
    auto filePath = CreateTempFile("test");

    auto hash = m_builder->ComputeFileHash(filePath, HashType::IMPHASH);

    EXPECT_FALSE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_InvalidHashType_SSDEEP) {
    auto filePath = CreateTempFile("test");

    auto hash = m_builder->ComputeFileHash(filePath, HashType::SSDEEP);

    EXPECT_FALSE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_LargeFile_10MB) {
    // Create 10MB file
    auto filePath = CreateTempFileWithSize(10 * 1024 * 1024, L"large_10mb.bin");

    auto start = std::chrono::high_resolution_clock::now();
    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::SHA256);
    
    // Should complete in reasonable time (< 1 second)
    EXPECT_LT(duration.count(), 1000);
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_ConsistentResults) {
    std::string content = "consistent test data";
    auto filePath = CreateTempFile(content);

    // Compute hash twice
    auto hash1 = m_builder->ComputeFileHash(filePath, HashType::SHA256);
    auto hash2 = m_builder->ComputeFileHash(filePath, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());
    
    // Both hashes should be identical
    EXPECT_EQ(hash1->type, hash2->type);
    EXPECT_EQ(hash1->length, hash2->length);
    EXPECT_TRUE(std::equal(hash1->data.begin(), hash1->data.end(), hash2->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_DifferentContent_DifferentHashes) {
    auto file1 = CreateTempFile("content1", L"file1.bin");
    auto file2 = CreateTempFile("content2", L"file2.bin");

    auto hash1 = m_builder->ComputeFileHash(file1, HashType::SHA256);
    auto hash2 = m_builder->ComputeFileHash(file2, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());
    
    // Hashes should be different
    EXPECT_FALSE(std::equal(hash1->data.begin(), hash1->data.end(), hash2->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeFileHash_AllAlgorithms) {
    auto filePath = CreateTempFile("test data for all algorithms");

    // Test all supported algorithms
    std::array<HashType,4> algorithms = {
        HashType::MD5,
        HashType::SHA1,
        HashType::SHA256,
        HashType::SHA512
    };

    for (auto algo : algorithms) {
        auto hash = m_builder->ComputeFileHash(filePath, algo);
        ASSERT_TRUE(hash.has_value()) << "Failed for algorithm: " << static_cast<int>(algo);
        EXPECT_EQ(hash->type, algo);
        EXPECT_EQ(hash->length, GetHashLengthForType(algo));
    }
}

// ============================================================================
// BUFFER HASH COMPUTATION TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_BasicBuffer) {
    std::string data = "test buffer";
    std::vector<uint8_t> buffer(data.begin(), data.end());

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->type, HashType::SHA256);
    EXPECT_EQ(hash->length, 32);
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_EmptyBuffer) {
    std::vector<uint8_t> emptyBuffer;

    auto hash = m_builder->ComputeBufferHash(emptyBuffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    
    // SHA256 of empty buffer
    auto expectedHash = HexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_TRUE(std::equal(expectedHash.begin(), expectedHash.end(), hash->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_LargeBuffer_100MB) {
    // Create 100MB buffer
    std::vector<uint8_t> largeBuffer(100 * 1024 * 1024, 0xAA);

    auto start = std::chrono::high_resolution_clock::now();
    auto hash = m_builder->ComputeBufferHash(largeBuffer, HashType::SHA256);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    ASSERT_TRUE(hash.has_value());
    
    // Should complete in reasonable time (< 2 seconds)
    EXPECT_LT(duration.count(), 2000);
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_ConsistentResults) {
    std::vector<uint8_t> buffer = {0x01, 0x02, 0x03, 0x04, 0x05};

    auto hash1 = m_builder->ComputeBufferHash(buffer, HashType::SHA256);
    auto hash2 = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());
    EXPECT_TRUE(std::equal(hash1->data.begin(), hash1->data.end(), hash2->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_AllAlgorithms) {
    std::vector<uint8_t> buffer = {0xDE, 0xAD, 0xBE, 0xEF};

    std::array<HashType,4> algorithms = {
        HashType::MD5,
        HashType::SHA1,
        HashType::SHA256,
        HashType::SHA512
    };

    for (auto algo : algorithms) {
        auto hash = m_builder->ComputeBufferHash(buffer, algo);
        ASSERT_TRUE(hash.has_value());
        EXPECT_EQ(hash->type, algo);
        EXPECT_EQ(hash->length, GetHashLengthForType(algo));
    }
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_SingleByte) {
    std::vector<uint8_t> buffer = {0xFF};

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    EXPECT_EQ(hash->length, 32);
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_BoundarySize_256MB) {
    // Test at 256MB boundary (chunk size in implementation)
    std::vector<uint8_t> buffer(256 * 1024 * 1024, 0x42);

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::MD5);

    ASSERT_TRUE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ComputeBufferHash_InvalidType_TLSH) {
    std::vector<uint8_t> buffer = {0x01, 0x02, 0x03};

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::TLSH);

    EXPECT_FALSE(hash.has_value());
}

// ============================================================================
// HASH COMPARISON TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, CompareHashes_IdenticalHashes) {
    std::vector<uint8_t> buffer = {0x01, 0x02, 0x03, 0x04};
    
    auto hash1 = m_builder->ComputeBufferHash(buffer, HashType::SHA256);
    auto hash2 = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());

    EXPECT_TRUE(m_builder->CompareHashes(*hash1, *hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_DifferentHashes) {
    std::vector<uint8_t> buffer1 = {0x01, 0x02, 0x03};
    std::vector<uint8_t> buffer2 = {0x04, 0x05, 0x06};

    auto hash1 = m_builder->ComputeBufferHash(buffer1, HashType::SHA256);
    auto hash2 = m_builder->ComputeBufferHash(buffer2, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());

    EXPECT_FALSE(m_builder->CompareHashes(*hash1, *hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_DifferentTypes) {
    std::vector<uint8_t> buffer = {0xAA, 0xBB, 0xCC};

    auto hash1 = m_builder->ComputeBufferHash(buffer, HashType::MD5);
    auto hash2 = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());

    EXPECT_FALSE(m_builder->CompareHashes(*hash1, *hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_DifferentLengths) {
    HashValue hash1{};
    hash1.type = HashType::MD5;
    hash1.length = 16;
    std::fill(hash1.data.begin(), hash1.data.begin() + 16, 0xAA);

    HashValue hash2{};
    hash2.type = HashType::MD5;
    hash2.length = 32;  // Wrong length for MD5
    std::fill(hash2.data.begin(), hash2.data.begin() + 32, 0xAA);

    EXPECT_FALSE(m_builder->CompareHashes(hash1, hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_EmptyHashes) {
    std::vector<uint8_t> emptyBuffer;

    auto hash1 = m_builder->ComputeBufferHash(emptyBuffer, HashType::SHA256);
    auto hash2 = m_builder->ComputeBufferHash(emptyBuffer, HashType::SHA256);

    ASSERT_TRUE(hash1.has_value());
    ASSERT_TRUE(hash2.has_value());

    EXPECT_TRUE(m_builder->CompareHashes(*hash1, *hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_SingleBitDifference) {
    HashValue hash1{};
    hash1.type = HashType::SHA256;
    hash1.length = 32;
    std::fill(hash1.data.begin(), hash1.data.begin() + 32, 0x00);

    HashValue hash2 = hash1;
    hash2.data[31] = 0x01;  // Single bit difference in last byte

    EXPECT_FALSE(m_builder->CompareHashes(hash1, hash2));
}

TEST_F(SignatureBuilderUtilsTest, CompareHashes_ConstantTime) {
    // Test that comparison is constant-time (timing attack resistance)
    HashValue hash1{};
    hash1.type = HashType::SHA256;
    hash1.length = 32;
    std::fill(hash1.data.begin(), hash1.data.begin() + 32, 0xAA);

    HashValue hash2_early_diff = hash1;
    hash2_early_diff.data[0] = 0xBB;  // Difference at start

    HashValue hash2_late_diff = hash1;
    hash2_late_diff.data[31] = 0xBB;  // Difference at end

    // Both comparisons should take similar time
    auto start1 = std::chrono::high_resolution_clock::now();
    bool result1 = m_builder->CompareHashes(hash1, hash2_early_diff);
    auto end1 = std::chrono::high_resolution_clock::now();

    auto start2 = std::chrono::high_resolution_clock::now();
    bool result2 = m_builder->CompareHashes(hash1, hash2_late_diff);
    auto end2 = std::chrono::high_resolution_clock::now();

    EXPECT_FALSE(result1);
    EXPECT_FALSE(result2);

    // Time difference should be minimal (< 100x difference)
    auto duration1 = std::chrono::duration_cast<std::chrono::nanoseconds>(end1 - start1).count();
    auto duration2 = std::chrono::duration_cast<std::chrono::nanoseconds>(end2 - start2).count();

    if (duration1 > 0 && duration2 > 0) {
        double ratio = static_cast<double>(std::max(duration1, duration2)) / 
                       static_cast<double>(std::min(duration1, duration2));
        EXPECT_LT(ratio, 100.0);
    }
}

// ============================================================================
// FILE & BUFFER HASH CONSISTENCY TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, FileAndBufferHash_Consistency) {
    std::string content = "test consistency between file and buffer hashing";
    auto filePath = CreateTempFile(content);

    std::vector<uint8_t> buffer(content.begin(), content.end());

    auto fileHash = m_builder->ComputeFileHash(filePath, HashType::SHA256);
    auto bufferHash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(fileHash.has_value());
    ASSERT_TRUE(bufferHash.has_value());

    // Hashes should be identical
    EXPECT_TRUE(m_builder->CompareHashes(*fileHash, *bufferHash));
}

TEST_F(SignatureBuilderUtilsTest, FileAndBufferHash_LargeData) {
    // 5MB test
    std::vector<uint8_t> buffer(5 * 1024 * 1024);
    std::mt19937 rng(42);
    for (auto& byte : buffer) {
        byte = static_cast<uint8_t>(rng());
    }

    // Write to file
    auto filePath = std::filesystem::path(m_tempDir) / L"large_consistency.bin";
    std::ofstream file(filePath, std::ios::binary);
    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    file.close();
    m_tempFiles.push_back(filePath.wstring());

    auto fileHash = m_builder->ComputeFileHash(filePath.wstring(), HashType::SHA256);
    auto bufferHash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(fileHash.has_value());
    ASSERT_TRUE(bufferHash.has_value());

    EXPECT_TRUE(m_builder->CompareHashes(*fileHash, *bufferHash));
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, DISABLED_Performance_FileHash_50MB) {
    auto filePath = CreateTempFileWithSize(50 * 1024 * 1024);

    auto start = std::chrono::high_resolution_clock::now();
    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    ASSERT_TRUE(hash.has_value());
    
    double throughputMBps = 50.0 / (duration.count() / 1000.0);
    std::cout << "50MB file hash throughput: " << throughputMBps << " MB/s\n";
    
    // Should achieve > 100 MB/s
    EXPECT_GT(throughputMBps, 100.0);
}

TEST_F(SignatureBuilderUtilsTest, DISABLED_Performance_BufferHash_Benchmark) {
    std::array<size_t,4> sizes = {
        1 * 1024,           // 1KB
        1 * 1024 * 1024,    // 1MB
        10 * 1024 * 1024,   // 10MB
        100 * 1024 * 1024   // 100MB
    };

    for (auto size : sizes) {
        std::vector<uint8_t> buffer(size, 0xAA);

        auto start = std::chrono::high_resolution_clock::now();
        auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        ASSERT_TRUE(hash.has_value());

        double sizeMB = size / (1024.0 * 1024.0);
        double throughput = sizeMB / (duration.count() / 1000000.0);

        std::cout << "Buffer size: " << sizeMB << " MB, Throughput: " 
                  << throughput << " MB/s\n";
    }
}

// ============================================================================
// SECURITY & ERROR HANDLING TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, Security_PathTraversal) {
    // Attempt path traversal attack
    std::wstring maliciousPath = m_tempDir + L"\\..\\..\\..\\windows\\system32\\cmd.exe";

    // Should either fail or only access if permission allowed
    auto hash = m_builder->ComputeFileHash(maliciousPath, HashType::SHA256);//-V808
    
    // Result depends on permissions, but should not crash
    // On most systems, this will either succeed (if readable) or fail gracefully
}

TEST_F(SignatureBuilderUtilsTest, Security_VeryLongPath) {
    // Create very long path (near Windows limit)
    std::wstring longPath = m_tempDir;
    while (longPath.length() < 30000) {
        longPath += L"\\verylongdirectoryname";
    }
    longPath += L"\\test.bin";

    auto hash = m_builder->ComputeFileHash(longPath, HashType::SHA256);
    
    // Should fail gracefully for paths > MAX_PATH_LEN
    EXPECT_FALSE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ErrorHandling_LockedFile) {
    auto filePath = CreateTempFile("test data");

    // Open file with read sharing allowed - this allows other readers to access
    // the file while we have it open. This simulates a file being used by
    // another process but not exclusively locked.
    HANDLE lockedFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,  // Allow read sharing - other processes can read
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    ASSERT_NE(lockedFile, INVALID_HANDLE_VALUE);

    // Try to hash the file while it's open by another handle
    // This should succeed because we opened with FILE_SHARE_READ
    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);

    CloseHandle(lockedFile);

    // Should succeed since the file was opened with FILE_SHARE_READ
    EXPECT_TRUE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, ErrorHandling_ReadOnlyFile) {
    auto filePath = CreateTempFile("readonly content");

    // Make file read-only
    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_READONLY);

    auto hash = m_builder->ComputeFileHash(filePath, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
    
    // Cleanup (remove read-only attribute)
    SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);
}

TEST_F(SignatureBuilderUtilsTest, EdgeCase_ZeroBytePattern) {
    std::vector<uint8_t> buffer(1000, 0x00);

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, EdgeCase_AllFFPattern) {
    std::vector<uint8_t> buffer(1000, 0xFF);

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
}

TEST_F(SignatureBuilderUtilsTest, EdgeCase_AlternatingPattern) {
    std::vector<uint8_t> buffer(1000);
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] = (i % 2 == 0) ? 0xAA : 0x55;
    }

    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA256);

    ASSERT_TRUE(hash.has_value());
}

// ============================================================================
// CONCURRENT HASH COMPUTATION TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, Concurrency_MultipleFileHashes) {
    // Create multiple test files
    std::vector<std::wstring> files;
    for (int i = 0; i < 5; ++i) {
        auto file = CreateTempFile("content " + std::to_string(i), 
                                   L"concurrent_" + std::to_wstring(i) + L".bin");
        files.push_back(file);
    }

    // Compute hashes concurrently
    std::vector<std::future<std::optional<HashValue>>> futures;
    for (const auto& file : files) {
        futures.push_back(std::async(std::launch::async, [this, file]() {
            return m_builder->ComputeFileHash(file, HashType::SHA256);
        }));
    }

    // Wait for all and verify
    for (auto& future : futures) {
        auto hash = future.get();
        EXPECT_TRUE(hash.has_value());
    }
}
TEST_F(SignatureBuilderUtilsTest, Concurrency_MultipleBufferHashes) {
    // Using std::array since the number of buffers is known at compile-time (5)
    // The inner vectors hold the actual data
    std::array<std::vector<uint8_t>, 5> buffers;

    for (size_t i = 0; i < buffers.size(); ++i) {
        // Initialize each buffer with 1000 bytes of unique data based on index
        buffers[i].resize(1000, static_cast<uint8_t>(i));
    }

    // std::future will hold the async results of our hash computations
    std::vector<std::future<std::optional<HashValue>>> futures;
    futures.reserve(buffers.size()); // Optimization: Avoid reallocations

    for (const auto& buffer : buffers) {
        // We pass the buffer by reference (std::ref) to avoid unnecessary copying 
        // because the buffer is guaranteed to stay alive until the thread joins.
        futures.push_back(std::async(std::launch::async, [this, &buffer]() {
            return m_builder->ComputeBufferHash(buffer, HashType::SHA256);
            }));
    }

    // Process the results as they become available
    for (auto& future : futures) {
        auto hash = future.get(); // This will block until the specific thread finishes

        // Assert that the hashing operation was successful
        EXPECT_TRUE(hash.has_value()) << "Hash computation failed for one of the buffers!";
    }
}
// ============================================================================
// ALGORITHM-SPECIFIC TESTS
// ============================================================================

TEST_F(SignatureBuilderUtilsTest, MD5_KnownVector) {
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    std::vector<uint8_t> emptyBuffer;
    auto hash = m_builder->ComputeBufferHash(emptyBuffer, HashType::MD5);

    ASSERT_TRUE(hash.has_value());
    auto expected = HexToBytes("d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), hash->data.begin()));
}

TEST_F(SignatureBuilderUtilsTest, SHA1_KnownVector) {
    // SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
    std::string content = "abc";
    std::vector<uint8_t> buffer(content.begin(), content.end());
    
    auto hash = m_builder->ComputeBufferHash(buffer, HashType::SHA1);

    ASSERT_TRUE(hash.has_value());
    auto expected = HexToBytes("a9993e364706816aba3e25717850c26c9cd0d89d");
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), hash->data.begin()));
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================


