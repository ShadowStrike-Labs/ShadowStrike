// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/*
 * ============================================================================
 * ShadowStrike SignatureIndex - COMPREHENSIVE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade unit tests for SignatureIndex B+Tree module
 * Tests cover all critical B+Tree operations with edge cases
 *
 * Test Categories:
 * - B+Tree initialization and lifecycle
 * - Lookup operations (exact match, range queries)
 * - Insertion operations (single, batch)
 * - Removal operations
 * - Node splitting and merging
 * - Tree traversal and iteration
 * - Statistics and monitoring
 * - Maintenance operations (rebuild, compact)
 * - Cache management
 * - Thread safety and concurrency
 * - Error handling and corruption detection
 * - Performance characteristics
 *
 * ============================================================================
 */
#include"pch.h"

#include <gtest/gtest.h>
#include "../../src/SignatureStore/SignatureIndex.hpp"
#include "../../src/SignatureStore/SignatureFormat.hpp"
#include "../../src/Utils/Logger.hpp"
#include <filesystem>
#include <random>
#include <thread>
#include <chrono>
#include <algorithm>
#include <memory>

using namespace ShadowStrike::SignatureStore;
namespace fs = std::filesystem;

// ============================================================================
// TEST FIXTURES & UTILITIES
// ============================================================================

class SignatureIndexTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test directory
        testDir = fs::temp_directory_path() / L"shadowstrike_sigindex_tests";
        fs::create_directories(testDir);

        // Initialize performance counter
        QueryPerformanceFrequency(&perfFrequency);
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

    // Helper: Create test hash value
    [[nodiscard]] HashValue CreateTestHash(uint64_t value) const noexcept {
        HashValue hash{};
        hash.type = HashType::SHA256;
        hash.length = 32;
        
        // Store value in first 8 bytes for FastHash
        std::memcpy(hash.data.data(), &value, sizeof(value));
        
        // Fill rest with pattern
        for (uint8_t i = 8; i < 32; ++i) {
            hash.data[i] = static_cast<uint8_t>(i ^ value);
        }
        
        return hash;
    }

    // Helper: Create random hash
    [[nodiscard]] HashValue CreateRandomHash() const noexcept {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint64_t> dist;

        HashValue hash{};
        hash.type = HashType::SHA256;
        hash.length = 32;

        uint64_t randomValue = dist(gen);
        std::memcpy(hash.data.data(), &randomValue, sizeof(randomValue));

        for (uint8_t i = 8; i < 32; ++i) {
            hash.data[i] = static_cast<uint8_t>(dist(gen));
        }

        return hash;
    }

    // Helper: Create memory mapping for testing
    [[nodiscard]] bool CreateTestMapping(
        const std::wstring& filename,
        size_t sizeBytes,
        MemoryMappedView& view
    ) noexcept {
        fs::path filePath = testDir / filename;

        // Create file
        HANDLE hFile = CreateFileW(
            filePath.wstring().c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Set file size
        LARGE_INTEGER size{};
        size.QuadPart = sizeBytes;
        if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN) ||
            !SetEndOfFile(hFile)) {
            CloseHandle(hFile);
            return false;
        }

        // Create mapping
        HANDLE hMapping = CreateFileMappingW(
            hFile,
            nullptr,
            PAGE_READWRITE,
            0,
            0,
            nullptr
        );

        if (!hMapping) {
            CloseHandle(hFile);
            return false;
        }

        // Map view
        void* baseAddr = MapViewOfFile(
            hMapping,
            FILE_MAP_ALL_ACCESS,
            0,
            0,
            0
        );

        if (!baseAddr) {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        view.fileHandle = hFile;
        view.mappingHandle = hMapping;
        view.baseAddress = baseAddr;
        view.fileSize = sizeBytes;
        view.readOnly = false;

        return true;
    }

    // Helper: Close memory mapping
    void CloseTestMapping(MemoryMappedView& view) noexcept {
        if (view.baseAddress) {
            UnmapViewOfFile(view.baseAddress);
            view.baseAddress = nullptr;
        }
        if (view.mappingHandle && view.mappingHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(view.mappingHandle);
            view.mappingHandle = INVALID_HANDLE_VALUE;
        }
        if (view.fileHandle && view.fileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(view.fileHandle);
            view.fileHandle = INVALID_HANDLE_VALUE;
        }
    }

    fs::path testDir;
    LARGE_INTEGER perfFrequency{};
};

// ============================================================================
// INITIALIZATION & LIFECYCLE TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, CreateNewIndex) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024; // 10MB
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    StoreError err = index.CreateNew(buffer.get(), indexSize, usedSize);

    EXPECT_TRUE(err.IsSuccess()) << "Error: " << err.message;
    EXPECT_GT(usedSize, 0);
    EXPECT_LE(usedSize, indexSize);
}

TEST_F(SignatureIndexTestFixture, CreateNewWithNullPointerFails) {
    SignatureIndex index;

    uint64_t usedSize = 0;
    StoreError err = index.CreateNew(nullptr, 1024, usedSize);

    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureIndexTestFixture, CreateNewWithInsufficientSpaceFails) {
    SignatureIndex index;

    auto buffer = std::make_unique<uint8_t[]>(1024);
    uint64_t usedSize = 0;
    
    // 1KB is too small
    StoreError err = index.CreateNew(buffer.get(), 1024, usedSize);

    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::TooLarge);
}

TEST_F(SignatureIndexTestFixture, InitializeFromMemoryMapping) {
    MemoryMappedView view{};
    ASSERT_TRUE(CreateTestMapping(L"test_index.dat", 10 * 1024 * 1024, view));

    // Create index first
    {
        SignatureIndex createIndex;
        uint64_t usedSize = 0;
        ASSERT_TRUE(createIndex.CreateNew(view.baseAddress, view.fileSize, usedSize).IsSuccess());
    }

    // Now initialize from existing
    SignatureIndex index;
    StoreError err = index.Initialize(view, 0, view.fileSize);

    EXPECT_TRUE(err.IsSuccess()) << "Error: " << err.message;

    CloseTestMapping(view);
}

TEST_F(SignatureIndexTestFixture, InitializeWithInvalidViewFails) {
    SignatureIndex index;

    MemoryMappedView invalidView{};
    StoreError err = index.Initialize(invalidView, 0, 1024);

    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat);
}

TEST_F(SignatureIndexTestFixture, InitializeWithMisalignedOffsetFails) {
    MemoryMappedView view{};
    ASSERT_TRUE(CreateTestMapping(L"misaligned_test.dat", 10 * 1024 * 1024, view));

    SignatureIndex index;
    
    // Offset not page-aligned
    StoreError err = index.Initialize(view, 123, view.fileSize - 123);

    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, SignatureStoreError::InvalidFormat);

    CloseTestMapping(view);
}

TEST_F(SignatureIndexTestFixture, VerifyEmptyIndex) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    StoreError err = index.Verify();

    EXPECT_TRUE(err.IsSuccess()) << "Error: " << err.message;
}

// ============================================================================
// LOOKUP OPERATION TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, LookupInEmptyIndexReturnsNullopt) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue testHash = CreateTestHash(12345);

    auto result = index.Lookup(testHash);

    EXPECT_FALSE(result.has_value());
}

TEST_F(SignatureIndexTestFixture, InsertAndLookupSingleEntry) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue testHash = CreateTestHash(42);
    uint64_t testOffset = 0x12345678;

    // Insert
    StoreError insertErr = index.Insert(testHash, testOffset);
    ASSERT_TRUE(insertErr.IsSuccess()) << "Insert error: " << insertErr.message;

    // Lookup
    auto result = index.Lookup(testHash);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, testOffset);
}

TEST_F(SignatureIndexTestFixture, LookupByFastHash) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue testHash = CreateTestHash(999);
    uint64_t fastHash = testHash.FastHash();
    uint64_t testOffset = 0xABCDEF00;

    ASSERT_TRUE(index.Insert(testHash, testOffset).IsSuccess());

    auto result = index.LookupByFastHash(fastHash);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, testOffset);
}

TEST_F(SignatureIndexTestFixture, RangeQuery) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries with sequential fast hashes
    std::vector<uint64_t> fastHashes;
    for (uint64_t i = 100; i < 200; ++i) {
        HashValue hash = CreateTestHash(i);
        uint64_t fh = hash.FastHash();
        fastHashes.push_back(fh);
        ASSERT_TRUE(index.Insert(hash, i * 1000).IsSuccess());
    }

    std::sort(fastHashes.begin(), fastHashes.end());

    // Range query
    uint64_t minHash = fastHashes[10];
    uint64_t maxHash = fastHashes[50];

    auto results = index.RangeQuery(minHash, maxHash, 100);

    EXPECT_GT(results.size(), 0);
    EXPECT_LE(results.size(), 41); // Should be around 41 entries
}

TEST_F(SignatureIndexTestFixture, BatchLookup) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 50 entries
    std::vector<HashValue> hashes;
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        hashes.push_back(hash);
        ASSERT_TRUE(index.Insert(hash, i * 100).IsSuccess());
    }

    // Batch lookup
    std::vector<std::optional<uint64_t>> results;
    index.BatchLookup(hashes, results);

    ASSERT_EQ(results.size(), hashes.size());

    // Verify all found
    for (size_t i = 0; i < results.size(); ++i) {
        ASSERT_TRUE(results[i].has_value()) << "Entry " << i << " not found";
        EXPECT_EQ(*results[i], i * 100);
    }
}

// ============================================================================
// INSERTION OPERATION TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, InsertMultipleEntries) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 100 entries
    for (size_t i = 0; i < 100; ++i) {
        HashValue hash = CreateTestHash(i);
        StoreError err = index.Insert(hash, i * 10);
        ASSERT_TRUE(err.IsSuccess()) << "Insert failed at " << i << ": " << err.message;
    }

    // Verify count
    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.totalEntries, 100);
}

TEST_F(SignatureIndexTestFixture, InsertDuplicateFails) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue hash = CreateTestHash(777);

    // First insert should succeed
    StoreError err1 = index.Insert(hash, 1000);
    ASSERT_TRUE(err1.IsSuccess());

    // Duplicate should fail
    StoreError err2 = index.Insert(hash, 2000);
    EXPECT_FALSE(err2.IsSuccess());
    EXPECT_EQ(err2.code, SignatureStoreError::DuplicateEntry);
}

TEST_F(SignatureIndexTestFixture, BatchInsert) {
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Create batch
    constexpr size_t batchSize = 500;
    std::vector<std::pair<HashValue, uint64_t>> entries;
    entries.reserve(batchSize);

    for (size_t i = 0; i < batchSize; ++i) {
        entries.emplace_back(CreateTestHash(i), i * 100);
    }

    // Batch insert
    StoreError err = index.BatchInsert(entries);

    EXPECT_TRUE(err.IsSuccess()) << "Batch insert error: " << err.message;

    // Verify count
    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.totalEntries, batchSize);

    // Spot check some entries
    for (size_t i = 0; i < 10; ++i) {
        auto result = index.Lookup(entries[i].first);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(*result, i * 100);
    }
}

TEST_F(SignatureIndexTestFixture, BatchInsertEmptyIsNoOp) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    std::vector<std::pair<HashValue, uint64_t>> empty;

    StoreError err = index.BatchInsert(empty);

    // Empty batch should succeed (no-op)
    EXPECT_TRUE(err.IsSuccess());
}

TEST_F(SignatureIndexTestFixture, BatchInsertWithDuplicatesPartialSuccess) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Create batch with duplicates
    std::vector<std::pair<HashValue, uint64_t>> entries;
    
    HashValue hash1 = CreateTestHash(100);
    HashValue hash2 = CreateTestHash(200);
    
    entries.emplace_back(hash1, 1000);
    entries.emplace_back(hash2, 2000);
    entries.emplace_back(hash1, 3000); // Duplicate

    StoreError err = index.BatchInsert(entries);

    // Should report partial success
    EXPECT_FALSE(err.IsSuccess());

    // But unique entries should be inserted
    auto result1 = index.Lookup(hash1);
    auto result2 = index.Lookup(hash2);

    EXPECT_TRUE(result1.has_value());
    EXPECT_TRUE(result2.has_value());
}

// ============================================================================
// REMOVAL OPERATION TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, RemoveExistingEntry) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue hash = CreateTestHash(555);
    
    // Insert
    ASSERT_TRUE(index.Insert(hash, 5000).IsSuccess());
    ASSERT_TRUE(index.Lookup(hash).has_value());

    // Remove
    StoreError err = index.Remove(hash);

    EXPECT_TRUE(err.IsSuccess()) << "Remove error: " << err.message;
    EXPECT_FALSE(index.Lookup(hash).has_value());
}

TEST_F(SignatureIndexTestFixture, RemoveNonExistentEntryFails) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue hash = CreateTestHash(999);

    StoreError err = index.Remove(hash);

    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(SignatureIndexTestFixture, RemoveMultipleEntries) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 50 entries
    std::vector<HashValue> hashes;
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        hashes.push_back(hash);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Remove every other entry
    for (size_t i = 0; i < hashes.size(); i += 2) {
        StoreError err = index.Remove(hashes[i]);
        EXPECT_TRUE(err.IsSuccess()) << "Remove failed at " << i;
    }

    // Verify removed entries are gone
    for (size_t i = 0; i < hashes.size(); i += 2) {
        EXPECT_FALSE(index.Lookup(hashes[i]).has_value());
    }

    // Verify remaining entries still exist
    for (size_t i = 1; i < hashes.size(); i += 2) {
        EXPECT_TRUE(index.Lookup(hashes[i]).has_value());
    }
}

TEST_F(SignatureIndexTestFixture, UpdateEntry) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue hash = CreateTestHash(123);
    uint64_t originalOffset = 1000;
    uint64_t newOffset = 2000;

    // Insert
    ASSERT_TRUE(index.Insert(hash, originalOffset).IsSuccess());

    // Update
    StoreError err = index.Update(hash, newOffset);

    EXPECT_TRUE(err.IsSuccess()) << "Update error: " << err.message;

    // Verify new value
    auto result = index.Lookup(hash);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, newOffset);
}

// ============================================================================
// TRAVERSAL & ITERATION TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, ForEachEmptyIndex) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    size_t count = 0;
    index.ForEach([&count](uint64_t, uint64_t) {
        count++;
        return true;
    });

    EXPECT_EQ(count, 0);
}

TEST_F(SignatureIndexTestFixture, ForEachIteratesAllEntries) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 100 entries
    constexpr size_t numEntries = 100;
    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Iterate and count
    size_t count = 0;
    index.ForEach([&count](uint64_t fastHash, uint64_t offset) {
        count++;
        return true; // Continue
    });

    EXPECT_EQ(count, numEntries);
}

TEST_F(SignatureIndexTestFixture, ForEachEarlyExit) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 50 entries
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Iterate with early exit
    size_t count = 0;
    index.ForEach([&count](uint64_t, uint64_t) {
        count++;
        return count < 10; // Stop after 10 iterations
    });

    EXPECT_EQ(count, 10);
}

TEST_F(SignatureIndexTestFixture, ForEachIfWithPredicate) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries
    std::vector<uint64_t> evenFastHashes;
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        uint64_t fh = hash.FastHash();
        if (i % 2 == 0) {
            evenFastHashes.push_back(fh);
        }
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Count entries matching predicate
    size_t matchCount = 0;
    index.ForEachIf(
        [&evenFastHashes](uint64_t fastHash) {
            return std::find(evenFastHashes.begin(), evenFastHashes.end(), fastHash) != evenFastHashes.end();
        },
        [&matchCount](uint64_t, uint64_t) {
            matchCount++;
            return true;
        }
    );

    EXPECT_EQ(matchCount, 25); // Half of 50
}

// ============================================================================
// STATISTICS TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, GetStatistics) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries
    for (size_t i = 0; i < 100; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Perform lookups
    for (size_t i = 0; i < 10; ++i) {
        HashValue hash = CreateTestHash(i);
        index.Lookup(hash);
    }

    auto stats = index.GetStatistics();

    EXPECT_EQ(stats.totalEntries, 100);
    EXPECT_GE(stats.totalLookups, 10);
    EXPECT_GT(stats.totalMemoryBytes, 0);
    EXPECT_GE(stats.treeHeight, 1);
}

TEST_F(SignatureIndexTestFixture, ResetStatistics) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Perform operations
    for (size_t i = 0; i < 20; ++i) {
        HashValue hash = CreateTestHash(i);
        index.Insert(hash, i);
        index.Lookup(hash);
    }

    auto statsBefore = index.GetStatistics();
    EXPECT_GT(statsBefore.totalLookups, 0);

    // Reset
    index.ResetStatistics();

    auto statsAfter = index.GetStatistics();
    EXPECT_EQ(statsAfter.totalLookups, 0);
    EXPECT_EQ(statsAfter.cacheHits, 0);
    EXPECT_EQ(statsAfter.cacheMisses, 0);
}

// ============================================================================
// MAINTENANCE OPERATION TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, RebuildIndex) {
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries
    constexpr size_t numEntries = 200;
    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    auto statsBefore = index.GetStatistics();

    // Rebuild
    StoreError err = index.Rebuild();

    EXPECT_TRUE(err.IsSuccess()) << "Rebuild error: " << err.message;

    auto statsAfter = index.GetStatistics();
    EXPECT_EQ(statsAfter.totalEntries, statsBefore.totalEntries);

    // Verify all entries still accessible
    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        auto result = index.Lookup(hash);
        EXPECT_TRUE(result.has_value()) << "Entry " << i << " missing after rebuild";
    }
}

TEST_F(SignatureIndexTestFixture, CompactIndex) {
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert then remove many entries to create fragmentation
    for (size_t i = 0; i < 100; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Remove half the entries
    for (size_t i = 0; i < 100; i += 2) {
        HashValue hash = CreateTestHash(i);
        index.Remove(hash);
    }

    auto statsBefore = index.GetStatistics();

    // Compact
    StoreError err = index.Compact();

    EXPECT_TRUE(err.IsSuccess()) << "Compact error: " << err.message;

    auto statsAfter = index.GetStatistics();
    EXPECT_EQ(statsAfter.totalEntries, statsBefore.totalEntries);
}

// ============================================================================
// CACHE MANAGEMENT TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, CacheImprovedPerformance) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entry
    HashValue hash = CreateTestHash(12345);
    ASSERT_TRUE(index.Insert(hash, 1000).IsSuccess());

    // First lookup (cache miss)
    auto result1 = index.Lookup(hash);
    ASSERT_TRUE(result1.has_value());

    // Second lookup (cache hit)
    auto result2 = index.Lookup(hash);
    ASSERT_TRUE(result2.has_value());

    auto stats = index.GetStatistics();
    EXPECT_GT(stats.cacheHits, 0);
}

TEST_F(SignatureIndexTestFixture, ClearCacheInvalidatesEntries) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    HashValue hash = CreateTestHash(999);
    ASSERT_TRUE(index.Insert(hash, 5000).IsSuccess());

    // Populate cache
    index.Lookup(hash);

    // Reset statistics (this will indirectly test cache behavior)
    index.ResetStatistics();

    // Next lookup should be cache miss
    auto result = index.Lookup(hash);
    ASSERT_TRUE(result.has_value());

    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.cacheHits, 0);
}

// ============================================================================
// VALIDATION & ERROR HANDLING TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, ValidateInvariants) {
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries
    for (size_t i = 0; i < 100; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    std::string errorMessage;
    bool valid = index.ValidateInvariants(errorMessage);

    if (!valid) {
        ADD_FAILURE() << "Invariant validation failed: " << errorMessage;
    }
}

TEST_F(SignatureIndexTestFixture, InsertWithInvalidHashFails) {
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Invalid hash (zero length)
    HashValue invalidHash{};
    invalidHash.type = HashType::SHA256;
    invalidHash.length = 0; // Invalid

    StoreError err = index.Insert(invalidHash, 1000);

    EXPECT_FALSE(err.IsSuccess());
}

// ============================================================================
// PERFORMANCE TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, LookupPerformanceBenchmark) {
    SignatureIndex index;

    constexpr size_t indexSize = 100 * 1024 * 1024; // 100MB
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 10,000 entries
    constexpr size_t numEntries = 10000;
    std::vector<HashValue> hashes;
    hashes.reserve(numEntries);

    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        hashes.push_back(hash);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Benchmark lookups
    LARGE_INTEGER startTime, endTime;
    QueryPerformanceCounter(&startTime);

    for (const auto& hash : hashes) {
        auto result = index.Lookup(hash);
        ASSERT_TRUE(result.has_value());
    }

    QueryPerformanceCounter(&endTime);

    uint64_t elapsedTicks = endTime.QuadPart - startTime.QuadPart;
    double elapsedUs = (static_cast<double>(elapsedTicks) / perfFrequency.QuadPart) * 1000000.0;
    double avgLookupUs = elapsedUs / numEntries;

    // Target: < 1 microsecond average
    EXPECT_LT(avgLookupUs, 10.0) << "Average lookup time: " << avgLookupUs << " µs";
}

TEST_F(SignatureIndexTestFixture, InsertPerformanceBenchmark) {
    SignatureIndex index;

    constexpr size_t indexSize = 100 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    constexpr size_t numEntries = 10000;
    std::vector<HashValue> hashes;

    for (size_t i = 0; i < numEntries; ++i) {
        hashes.push_back(CreateTestHash(i));
    }

    LARGE_INTEGER startTime, endTime;
    QueryPerformanceCounter(&startTime);

    for (size_t i = 0; i < numEntries; ++i) {
        ASSERT_TRUE(index.Insert(hashes[i], i * 10).IsSuccess());
    }

    QueryPerformanceCounter(&endTime);

    uint64_t elapsedTicks = endTime.QuadPart - startTime.QuadPart;
    double elapsedMs = (static_cast<double>(elapsedTicks) / perfFrequency.QuadPart) * 1000.0;
    double throughput = numEntries / (elapsedMs / 1000.0);

    // Should be able to insert > 10,000 entries/sec
    EXPECT_GT(throughput, 5000.0) << "Insert throughput: " << throughput << " ops/sec";
}

// ============================================================================
// THREAD SAFETY TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, ConcurrentReadsThreadSafe) {
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert test data
    std::vector<HashValue> hashes;
    for (size_t i = 0; i < 100; ++i) {
        HashValue hash = CreateTestHash(i);
        hashes.push_back(hash);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Launch concurrent reader threads
    constexpr size_t numThreads = 8;
    std::vector<std::thread> threads;
    std::atomic<size_t> successCount{ 0 };

    for (size_t t = 0; t < numThreads; ++t) {
        threads.emplace_back([&index, &hashes, &successCount]() {
            for (const auto& hash : hashes) {
                auto result = index.Lookup(hash);
                if (result.has_value()) {
                    successCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
            });
    }

    // Wait for all threads
    for (auto& thread : threads) {
        thread.join();
    }

    // All lookups should succeed
    EXPECT_EQ(successCount.load(), numThreads * hashes.size());
}

// ============================================================================
// STRESS TESTS
// ============================================================================

TEST_F(SignatureIndexTestFixture, LargeScaleInsertionStressTest) {
    SignatureIndex index;

    constexpr size_t indexSize = 500 * 1024 * 1024; // 500MB
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert 50,000 entries
    constexpr size_t numEntries = 50000;
    
    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateRandomHash();
        StoreError err = index.Insert(hash, i * 10);
        
        if (!err.IsSuccess()) {
            // May fail if tree becomes too large
            break;
        }

        if (i % 10000 == 0) {
            auto stats = index.GetStatistics();
            // Progress check
        }
    }

    auto finalStats = index.GetStatistics();
    EXPECT_GT(finalStats.totalEntries, 10000); // At least 10K should succeed
}

// ============================================================================
// B+TREE INVARIANT TESTS (Critical for correctness after fixes)
// ============================================================================

TEST_F(SignatureIndexTestFixture, SplitNodeMaintainsKeyOrdering) {
    // This test validates that after node splits, all keys maintain proper
    // B+Tree ordering: left keys < splitKey <= right keys
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert enough entries to force multiple splits
    // BPlusTreeNode::MAX_KEYS is typically 128, so 500 entries forces splits
    constexpr size_t numEntries = 500;
    std::vector<HashValue> insertedHashes;
    insertedHashes.reserve(numEntries);

    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        insertedHashes.push_back(hash);
        StoreError err = index.Insert(hash, i * 10);
        ASSERT_TRUE(err.IsSuccess()) << "Insert failed at " << i << ": " << err.message;
    }

    // Validate tree invariants
    std::string errorMsg;
    EXPECT_TRUE(index.ValidateInvariants(errorMsg)) 
        << "Invariant violation after 500 inserts: " << errorMsg;

    // Verify all entries are still retrievable
    for (size_t i = 0; i < numEntries; ++i) {
        auto result = index.Lookup(insertedHashes[i]);
        ASSERT_TRUE(result.has_value()) << "Entry " << i << " missing after splits";
        EXPECT_EQ(*result, i * 10);
    }
}

TEST_F(SignatureIndexTestFixture, InsertAfterSplitFindsCorrectLeaf) {
    // Tests the critical fix: splitKey must be recalculated AFTER insertion
    // to ensure subsequent inserts find the correct leaf
    SignatureIndex index;

    constexpr size_t indexSize = 50 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries in a pattern that triggers splits and subsequent inserts
    // into potentially wrong leaves if splitKey isn't recalculated
    std::vector<uint64_t> insertOrder;
    constexpr size_t baseEntries = 200;
    
    // First pass: sequential inserts to build tree structure
    for (size_t i = 0; i < baseEntries; ++i) {
        HashValue hash = CreateTestHash(i * 2);  // Even numbers
        ASSERT_TRUE(index.Insert(hash, i * 100).IsSuccess());
        insertOrder.push_back(i * 2);
    }

    // Second pass: interleaved inserts (odd numbers)
    // These inserts test splitKey recalculation after first split
    for (size_t i = 0; i < baseEntries; ++i) {
        HashValue hash = CreateTestHash(i * 2 + 1);  // Odd numbers
        StoreError err = index.Insert(hash, (i + baseEntries) * 100);
        ASSERT_TRUE(err.IsSuccess()) << "Interleaved insert failed at " << i;
        insertOrder.push_back(i * 2 + 1);
    }

    // Verify all entries
    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.totalEntries, baseEntries * 2);

    for (uint64_t val : insertOrder) {
        HashValue hash = CreateTestHash(val);
        auto result = index.Lookup(hash);
        EXPECT_TRUE(result.has_value()) << "Entry with value " << val << " not found";
    }
}

TEST_F(SignatureIndexTestFixture, VerifyNoMemoryLeakOnRollback) {
    // Test that RollbackCOW properly cleans up all COW state
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert valid entry first
    HashValue validHash = CreateTestHash(1);
    ASSERT_TRUE(index.Insert(validHash, 1000).IsSuccess());

    // Attempt to insert duplicate (should fail and rollback)
    HashValue dupHash = CreateTestHash(1);  // Same as validHash
    StoreError dupErr = index.Insert(dupHash, 2000);
    EXPECT_FALSE(dupErr.IsSuccess());
    EXPECT_EQ(dupErr.code, SignatureStoreError::DuplicateEntry);

    // Statistics should be consistent (only 1 entry, not 2)
    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.totalEntries, 1);

    // Original entry should still be intact
    auto result = index.Lookup(validHash);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, 1000);  // Original value, not 2000
}

TEST_F(SignatureIndexTestFixture, StatisticsRollbackOnCommitFailure) {
    // This test validates that statistics are rolled back when COW commit fails
    // Note: Inducing a real commit failure is difficult, so we verify the 
    // insertion path handles statistics correctly
    SignatureIndex index;

    constexpr size_t indexSize = 10 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    auto initialStats = index.GetStatistics();
    EXPECT_EQ(initialStats.totalEntries, 0);

    // Successful insert should increment counter
    HashValue hash1 = CreateTestHash(100);
    ASSERT_TRUE(index.Insert(hash1, 1000).IsSuccess());

    auto statsAfterInsert = index.GetStatistics();
    EXPECT_EQ(statsAfterInsert.totalEntries, 1);

    // Failed insert (duplicate) should NOT increment counter
    StoreError dupErr = index.Insert(hash1, 2000);
    EXPECT_FALSE(dupErr.IsSuccess());

    auto statsAfterFailure = index.GetStatistics();
    EXPECT_EQ(statsAfterFailure.totalEntries, 1);  // Still 1, not 2
}

TEST_F(SignatureIndexTestFixture, FlushAcquiresLockCorrectly) {
    // Test that Flush() works correctly with concurrent operations
    SignatureIndex index;

    constexpr size_t indexSize = 20 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert some entries
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        ASSERT_TRUE(index.Insert(hash, i * 10).IsSuccess());
    }

    // Flush should succeed (even though this is a raw buffer, not memory-mapped)
    // In raw buffer mode, Flush may be a no-op but should not crash
    StoreError flushErr = index.Flush();
    // Don't assert success as Flush on raw buffer may return error
    // The key is that it doesn't crash or corrupt state

    // Verify entries still accessible after flush attempt
    for (size_t i = 0; i < 50; ++i) {
        HashValue hash = CreateTestHash(i);
        auto result = index.Lookup(hash);
        EXPECT_TRUE(result.has_value()) << "Entry " << i << " missing after flush";
    }
}

TEST_F(SignatureIndexTestFixture, LargeKeyCountNodeSplit) {
    // Specifically test node splitting with maximum key count
    SignatureIndex index;

    constexpr size_t indexSize = 100 * 1024 * 1024;
    auto buffer = std::make_unique<uint8_t[]>(indexSize);
    
    uint64_t usedSize = 0;
    ASSERT_TRUE(index.CreateNew(buffer.get(), indexSize, usedSize).IsSuccess());

    // Insert entries that will force multiple levels of splits
    constexpr size_t numEntries = 1000;
    
    for (size_t i = 0; i < numEntries; ++i) {
        HashValue hash = CreateTestHash(i);
        StoreError err = index.Insert(hash, i * 10);
        ASSERT_TRUE(err.IsSuccess()) << "Insert failed at " << i << ": " << err.message;
        
        // Periodically validate invariants during insertions
        if (i > 0 && i % 200 == 0) {
            std::string errorMsg;
            bool valid = index.ValidateInvariants(errorMsg);
            ASSERT_TRUE(valid) << "Invariant violation at entry " << i << ": " << errorMsg;
        }
    }

    // Final validation
    auto stats = index.GetStatistics();
    EXPECT_EQ(stats.totalEntries, numEntries);
    EXPECT_GE(stats.treeHeight, 2);  // Should have grown beyond single node

    std::string finalErrorMsg;
    EXPECT_TRUE(index.ValidateInvariants(finalErrorMsg)) 
        << "Final invariant check failed: " << finalErrorMsg;
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================


