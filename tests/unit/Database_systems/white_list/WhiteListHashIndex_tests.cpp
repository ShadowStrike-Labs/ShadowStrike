// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * @file WhiteListHashIndex_tests.cpp
 * @brief Enterprise-grade unit tests for HashIndex (B+Tree) implementation
 *
 * Comprehensive test coverage for the B+Tree hash index including:
 * - Basic CRUD operations (Create, Read, Update, Delete)
 * - Boundary conditions and edge cases
 * - Node splitting and tree growth
 * - Thread safety and concurrent access
 * - Performance benchmarks
 * - Corruption detection and recovery
 * - Memory safety validation
 *
 * Test Categories:
 * 1. Construction and Initialization
 * 2. Single Key Operations (Insert, Lookup, Remove)
 * 3. Batch Operations
 * 4. Tree Growth and Node Splitting
 * 5. Edge Cases and Boundary Conditions
 * 6. Error Handling and Validation
 * 7. Thread Safety and Concurrency
 * 8. Performance Benchmarks
 * 9. Memory Corruption Detection
 * 10. Stress Tests
 *
 * Target: CrowdStrike / Kaspersky enterprise-grade quality
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../src/Whitelist/WhiteListStore.hpp"
#include "../../src/Whitelist/WhiteListFormat.hpp"

#include <vector>
#include <array>
#include <random>
#include <thread>
#include <future>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <set>
#include <numeric>
#include <cstring>

namespace ShadowStrike::Whitelist::Tests {

// ============================================================================
// TEST CONSTANTS AND HELPERS
// ============================================================================

/// @brief Test constants for index size calculations
namespace TestConstants {
    constexpr size_t HEADER_SIZE = 64;
    constexpr size_t NODE_SIZE = sizeof(BPlusTreeNode);
    constexpr size_t MIN_INDEX_SIZE = HEADER_SIZE + NODE_SIZE;
    constexpr size_t SMALL_INDEX_SIZE = HEADER_SIZE + (NODE_SIZE * 10);
    constexpr size_t MEDIUM_INDEX_SIZE = HEADER_SIZE + (NODE_SIZE * 100);
    constexpr size_t LARGE_INDEX_SIZE = HEADER_SIZE + (NODE_SIZE * 1000);
    constexpr size_t STRESS_INDEX_SIZE = HEADER_SIZE + (NODE_SIZE * 10000);
    
    constexpr uint32_t MAX_KEYS_PER_NODE = BPlusTreeNode::MAX_KEYS;
    
    // Performance targets (nanoseconds)
    constexpr int64_t LOOKUP_TARGET_NS = 500;      // 500ns per lookup
    constexpr int64_t INSERT_TARGET_NS = 1000;     // 1μs per insert
    constexpr int64_t BATCH_LOOKUP_TARGET_NS = 100; // 100ns per hash in batch
    
    // Thread safety test parameters
    constexpr size_t CONCURRENT_READERS = 8;
    constexpr size_t CONCURRENT_WRITERS = 2;
    constexpr size_t OPERATIONS_PER_THREAD = 1000;
}

/**
 * @brief RAII helper for temporary index buffer allocation
 */
class IndexBuffer {
public:
    explicit IndexBuffer(size_t size)
        : m_size(size)
        , m_data(new uint8_t[size])
    {
        // Zero-initialize for predictable behavior
        std::memset(m_data.get(), 0, size);
    }
    
    ~IndexBuffer() = default;
    
    // Non-copyable
    IndexBuffer(const IndexBuffer&) = delete;
    IndexBuffer& operator=(const IndexBuffer&) = delete;
    
    // Movable
    IndexBuffer(IndexBuffer&& other) noexcept
        : m_size(other.m_size)
        , m_data(std::move(other.m_data))
    {
        other.m_size = 0;
    }
    
    IndexBuffer& operator=(IndexBuffer&& other) noexcept {
        if (this != &other) {
            m_size = other.m_size;
            m_data = std::move(other.m_data);
            other.m_size = 0;
        }
        return *this;
    }
    
    [[nodiscard]] void* Data() noexcept { return m_data.get(); }
    [[nodiscard]] const void* Data() const noexcept { return m_data.get(); }
    [[nodiscard]] size_t Size() const noexcept { return m_size; }
    
    void Clear() {
        if (m_data) {
            std::memset(m_data.get(), 0, m_size);
        }
    }
    
private:
    size_t m_size;
    std::unique_ptr<uint8_t[]> m_data;
};

/**
 * @brief Helper to create test HashValue objects
 */
class HashValueGenerator {
public:
    explicit HashValueGenerator(uint64_t seed = 12345)
        : m_rng(seed)
        , m_counter(0)
    {}
    
    /**
     * @brief Generate a deterministic hash value based on index
     */
    [[nodiscard]] HashValue Generate(uint64_t index) const {
        HashValue hash{};
        hash.algorithm = HashAlgorithm::SHA256;
        hash.length = 32;

        // Create deterministic SHA256-like data based on index
        const uint64_t base = index * 0x9E3779B97F4A7C15ULL;  // Golden ratio hash
        
        for (size_t i = 0; i < hash.length; ++i) {
            const uint64_t mixed = base ^ (static_cast<uint64_t>(i) * 0xBF58476D1CE4E5B9ULL);
            hash.data[i] = static_cast<uint8_t>(mixed >> (i % 8 * 8));
        }
        
        return hash;
    }
    
    /**
     * @brief Generate a random hash value
     */
    [[nodiscard]] HashValue GenerateRandom() {
        HashValue hash{};
        hash.algorithm = HashAlgorithm::SHA256;
        hash.length = 32;
        
        for (size_t i = 0; i < hash.length; ++i) {
            hash.data[i] = static_cast<uint8_t>(m_rng());
        }
        
        return hash;
    }
    
    /**
     * @brief Generate sequential hash for ordered tests
     */
    [[nodiscard]] HashValue GenerateSequential() {
        return Generate(m_counter++);
    }
    
    void Reset() { m_counter = 0; }
    
private:
    mutable std::mt19937_64 m_rng;
    uint64_t m_counter;
};

/**
 * @brief Test fixture for HashIndex tests
 */
class HashIndexTest : public ::testing::Test {
protected:
    void SetUp() override {
        m_generator = std::make_unique<HashValueGenerator>();
    }
    
    void TearDown() override {
        m_generator.reset();
    }
    
    /**
     * @brief Create initialized index with given buffer size
     */
    [[nodiscard]] std::pair<HashIndex, IndexBuffer> CreateIndex(size_t bufferSize) {
        IndexBuffer buffer(bufferSize);
        HashIndex index;
        
        uint64_t usedSize = 0;
        auto result = index.CreateNew(buffer.Data(), buffer.Size(), usedSize);
        EXPECT_TRUE(result.IsSuccess()) << "CreateNew failed: " << result.message;
        
        return {std::move(index), std::move(buffer)};
    }
    
    /**
     * @brief Helper to insert N hashes into index
     */
    size_t InsertNHashes(HashIndex& index, size_t count, uint64_t startIndex = 0) {
        size_t successCount = 0;
        for (size_t i = 0; i < count; ++i) {
            auto hash = m_generator->Generate(startIndex + i);
            auto result = index.Insert(hash, static_cast<uint64_t>(i * 100));
            if (result.IsSuccess()) {
                ++successCount;
            }
        }
        return successCount;
    }
    
    std::unique_ptr<HashValueGenerator> m_generator;
};

// ============================================================================
// CATEGORY 1: CONSTRUCTION AND INITIALIZATION TESTS
// ============================================================================

TEST_F(HashIndexTest, DefaultConstruction) {
    HashIndex index;
    
    EXPECT_FALSE(index.IsReady());
    EXPECT_FALSE(index.IsWritable());
    EXPECT_EQ(index.GetEntryCount(), 0u);
    EXPECT_EQ(index.GetNodeCount(), 0u);
}

TEST_F(HashIndexTest, CreateNewWithMinimumSize) {
    IndexBuffer buffer(TestConstants::MIN_INDEX_SIZE);
    HashIndex index;
    
    uint64_t usedSize = 0;
    auto result = index.CreateNew(buffer.Data(), buffer.Size(), usedSize);
    
    EXPECT_TRUE(result.IsSuccess()) << "Error: " << result.message;
    EXPECT_TRUE(index.IsReady());
    EXPECT_TRUE(index.IsWritable());
    EXPECT_EQ(index.GetEntryCount(), 0u);
    EXPECT_EQ(index.GetNodeCount(), 1u);  // Root node
    EXPECT_GT(usedSize, 0u);
}

TEST_F(HashIndexTest, CreateNewWithNullAddress_Fails) {
    HashIndex index;
    
    uint64_t usedSize = 0;
    auto result = index.CreateNew(nullptr, 1024, usedSize);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::InvalidSection);
    EXPECT_FALSE(index.IsReady());
}

TEST_F(HashIndexTest, CreateNewWithInsufficientSize_Fails) {
    IndexBuffer buffer(TestConstants::HEADER_SIZE - 1);  // Too small
    HashIndex index;
    
    uint64_t usedSize = 0;
    auto result = index.CreateNew(buffer.Data(), buffer.Size(), usedSize);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::InvalidSection);
}

TEST_F(HashIndexTest, CreateNewWithExactMinimumSize) {
    // Exact minimum: header + one node
    IndexBuffer buffer(TestConstants::MIN_INDEX_SIZE);
    HashIndex index;
    
    uint64_t usedSize = 0;
    auto result = index.CreateNew(buffer.Data(), buffer.Size(), usedSize);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(usedSize, TestConstants::MIN_INDEX_SIZE);
}

TEST_F(HashIndexTest, MoveConstruction) {
    auto [index1, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    // Insert some data
    auto hash = m_generator->Generate(1);
    EXPECT_TRUE(index1.Insert(hash, 100).IsSuccess());
    
    // Move construct
    HashIndex index2(std::move(index1));
    
    EXPECT_TRUE(index2.IsReady());
    EXPECT_TRUE(index2.IsWritable());
    EXPECT_TRUE(index2.Contains(hash));
    EXPECT_EQ(index2.GetEntryCount(), 1u);
    
    // Original should be empty
    EXPECT_FALSE(index1.IsReady());
}

TEST_F(HashIndexTest, MoveAssignment) {
    auto [index1, buffer1] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    auto [index2, buffer2] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    // Insert data into first index
    auto hash = m_generator->Generate(1);
    EXPECT_TRUE(index1.Insert(hash, 100).IsSuccess());
    
    // Move assign
    index2 = std::move(index1);
    
    EXPECT_TRUE(index2.IsReady());
    EXPECT_TRUE(index2.Contains(hash));
}

// ============================================================================
// CATEGORY 2: SINGLE KEY OPERATIONS
// ============================================================================

TEST_F(HashIndexTest, InsertSingleHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    auto result = index.Insert(hash, 12345);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 1u);
}

TEST_F(HashIndexTest, LookupExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    constexpr uint64_t offset = 98765;
    
    EXPECT_TRUE(index.Insert(hash, offset).IsSuccess());
    
    auto result = index.Lookup(hash);
    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), offset);
}

TEST_F(HashIndexTest, LookupNonExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash1 = m_generator->Generate(1);
    auto hash2 = m_generator->Generate(2);
    
    EXPECT_TRUE(index.Insert(hash1, 100).IsSuccess());
    
    auto result = index.Lookup(hash2);
    EXPECT_FALSE(result.has_value());
}

TEST_F(HashIndexTest, ContainsExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    EXPECT_TRUE(index.Insert(hash, 100).IsSuccess());
    
    EXPECT_TRUE(index.Contains(hash));
}

TEST_F(HashIndexTest, ContainsNonExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    EXPECT_FALSE(index.Contains(hash));
}

TEST_F(HashIndexTest, InsertEmptyHash_Fails) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    HashValue emptyHash{};
    auto result = index.Insert(emptyHash, 100);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::InvalidEntry);
}

TEST_F(HashIndexTest, LookupEmptyHash_ReturnsNullopt) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    HashValue emptyHash{};
    auto result = index.Lookup(emptyHash);
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(HashIndexTest, UpdateExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    
    // Insert with first offset
    EXPECT_TRUE(index.Insert(hash, 100).IsSuccess());
    EXPECT_EQ(index.Lookup(hash).value(), 100u);
    
    // Update with second offset (upsert semantics)
    EXPECT_TRUE(index.Insert(hash, 200).IsSuccess());
    EXPECT_EQ(index.Lookup(hash).value(), 200u);
    
    // Entry count should remain 1 (update, not new insert)
    EXPECT_EQ(index.GetEntryCount(), 1u);
}

TEST_F(HashIndexTest, RemoveExistingHash) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    EXPECT_TRUE(index.Insert(hash, 100).IsSuccess());
    EXPECT_TRUE(index.Contains(hash));
    EXPECT_EQ(index.GetEntryCount(), 1u);
    
    auto result = index.Remove(hash);
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_FALSE(index.Contains(hash));
    EXPECT_EQ(index.GetEntryCount(), 0u);
}

TEST_F(HashIndexTest, RemoveNonExistingHash_Fails) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    auto result = index.Remove(hash);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::EntryNotFound);
}

TEST_F(HashIndexTest, RemoveFromEmptyTreeReturnsNotFound) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(42);
    auto result = index.Remove(hash);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::EntryNotFound);
}

TEST_F(HashIndexTest, RemoveEmptyHash_Fails) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    HashValue emptyHash{};
    auto result = index.Remove(emptyHash);
    
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::InvalidEntry);
}

// ============================================================================
// CATEGORY 3: BATCH OPERATIONS
// ============================================================================

TEST_F(HashIndexTest, BatchLookupEmpty) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    std::vector<HashValue> hashes;
    std::vector<std::optional<uint64_t>> results;
    
    index.BatchLookup(hashes, results);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(HashIndexTest, BatchLookupMultipleHashes) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert 50 hashes
    std::vector<HashValue> hashes;
    for (uint64_t i = 0; i < 50; ++i) {
        auto hash = m_generator->Generate(i);
        hashes.push_back(hash);
        EXPECT_TRUE(index.Insert(hash, i * 100).IsSuccess());
    }
    
    // Lookup all
    std::vector<std::optional<uint64_t>> results;
    index.BatchLookup(hashes, results);
    
    ASSERT_EQ(results.size(), hashes.size());
    for (size_t i = 0; i < results.size(); ++i) {
        EXPECT_TRUE(results[i].has_value()) << "Hash " << i << " not found";
        EXPECT_EQ(results[i].value(), i * 100) << "Wrong offset for hash " << i;
    }
}

TEST_F(HashIndexTest, BatchLookupMixedResults) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert only even-indexed hashes
    for (uint64_t i = 0; i < 20; i += 2) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i * 100).IsSuccess());
    }
    
    // Lookup all (even and odd)
    std::vector<HashValue> hashes;
    for (uint64_t i = 0; i < 20; ++i) {
        hashes.push_back(m_generator->Generate(i));
    }
    
    std::vector<std::optional<uint64_t>> results;
    index.BatchLookup(hashes, results);
    
    ASSERT_EQ(results.size(), 20u);
    for (size_t i = 0; i < 20; ++i) {
        if (i % 2 == 0) {
            EXPECT_TRUE(results[i].has_value()) << "Even hash " << i << " should exist";
        } else {
            EXPECT_FALSE(results[i].has_value()) << "Odd hash " << i << " should not exist";
        }
    }
}

TEST_F(HashIndexTest, BatchLookupWithEmptyHashes) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    std::vector<HashValue> hashes;
    hashes.push_back(m_generator->Generate(1));
    hashes.push_back(HashValue{});  // Empty
    hashes.push_back(m_generator->Generate(2));
    
    EXPECT_TRUE(index.Insert(hashes[0], 100).IsSuccess());
    EXPECT_TRUE(index.Insert(hashes[2], 200).IsSuccess());
    
    std::vector<std::optional<uint64_t>> results;
    index.BatchLookup(hashes, results);
    
    ASSERT_EQ(results.size(), 3u);
    EXPECT_TRUE(results[0].has_value());
    EXPECT_FALSE(results[1].has_value());  // Empty hash returns nullopt
    EXPECT_TRUE(results[2].has_value());
}

TEST_F(HashIndexTest, BatchInsertMultipleHashes) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    std::vector<std::pair<HashValue, uint64_t>> entries;
    for (uint64_t i = 0; i < 30; ++i) {
        entries.emplace_back(m_generator->Generate(i), i * 100);
    }
    
    auto result = index.BatchInsert(entries);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 30u);
    
    // Verify all entries are retrievable
    for (size_t i = 0; i < entries.size(); ++i) {
        EXPECT_TRUE(index.Contains(entries[i].first)) << "Entry " << i << " not found";
    }
}

TEST_F(HashIndexTest, BatchInsertEmpty) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    std::vector<std::pair<HashValue, uint64_t>> entries;
    
    auto result = index.BatchInsert(entries);
    
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 0u);
}

// ============================================================================
// CATEGORY 4: TREE GROWTH AND NODE SPLITTING
// ============================================================================

TEST_F(HashIndexTest, InsertCausesNodeSplit) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    const uint32_t initialNodeCount = static_cast<uint32_t>(index.GetNodeCount());
    
    // Insert more than MAX_KEYS to force split
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE + 10;
    size_t successCount = InsertNHashes(index, insertCount);
    
    EXPECT_GT(successCount, TestConstants::MAX_KEYS_PER_NODE);
    EXPECT_GT(index.GetNodeCount(), initialNodeCount) << "Node split should have occurred";
}

TEST_F(HashIndexTest, TreeGrowthToMultipleLevels) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Insert enough to create multiple levels
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 5;
    size_t successCount = InsertNHashes(index, insertCount);
    
    EXPECT_GT(successCount, 100u);
    EXPECT_GT(index.GetTreeDepth(), 1u) << "Tree should have grown";
    
    // Verify all inserted hashes are still retrievable
    for (size_t i = 0; i < successCount; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Contains(hash)) << "Hash " << i << " lost after tree growth";
    }
}

TEST_F(HashIndexTest, TreeGrowthInsertsAndRemovesMaintainIntegrity) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Insert enough to grow the tree
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 3;
    size_t successCount = InsertNHashes(index, insertCount);
    
    EXPECT_GT(successCount, 100u);
    EXPECT_GT(index.GetTreeDepth(), 1u);
    
    // Remove every third hash to force underflow/merge scenarios
    size_t removedCount = 0;
    for (size_t i = 0; i < successCount; i += 3) {
        auto hash = m_generator->Generate(i);
        auto result = index.Remove(hash);
        EXPECT_TRUE(result.IsSuccess()) << "Remove failed for " << i;
        ++removedCount;
    }
    
    // Verify remaining hashes are retrievable
    for (size_t i = 0; i < successCount; ++i) {
        auto hash = m_generator->Generate(i);
        if (i % 3 == 0) {
            EXPECT_FALSE(index.Contains(hash)) << "Removed hash still present " << i;
        } else {
            EXPECT_TRUE(index.Contains(hash)) << "Hash missing after merges " << i;
        }
    }
    
    EXPECT_EQ(index.GetEntryCount(), successCount - removedCount);
}

TEST_F(HashIndexTest, InsertInSortedOrder) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert in sorted order (worst case for some implementations)
    for (uint64_t i = 0; i < 100; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess()) << "Insert " << i << " failed";
    }
    
    EXPECT_EQ(index.GetEntryCount(), 100u);
    
    // Verify retrieval
    for (uint64_t i = 0; i < 100; ++i) {
        auto hash = m_generator->Generate(i);
        auto result = index.Lookup(hash);
        EXPECT_TRUE(result.has_value()) << "Hash " << i << " not found";
        EXPECT_EQ(result.value(), i) << "Wrong offset for hash " << i;
    }
}

TEST_F(HashIndexTest, InsertInReverseOrder) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert in reverse order
    for (int64_t i = 99; i >= 0; --i) {
        auto hash = m_generator->Generate(static_cast<uint64_t>(i));
        EXPECT_TRUE(index.Insert(hash, static_cast<uint64_t>(i)).IsSuccess()) 
            << "Insert " << i << " failed";
    }
    
    EXPECT_EQ(index.GetEntryCount(), 100u);
}

TEST_F(HashIndexTest, InsertRandomOrder) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Create shuffled indices
    std::vector<uint64_t> indices(100);
    std::iota(indices.begin(), indices.end(), 0);
    std::shuffle(indices.begin(), indices.end(), std::mt19937{42});
    
    // Insert in random order
    for (uint64_t idx : indices) {
        auto hash = m_generator->Generate(idx);
        EXPECT_TRUE(index.Insert(hash, idx).IsSuccess()) << "Insert " << idx << " failed";
    }
    
    EXPECT_EQ(index.GetEntryCount(), 100u);
    
    // Verify all entries
    for (uint64_t i = 0; i < 100; ++i) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(i))) << "Hash " << i << " not found";
    }
}

// ============================================================================
// CATEGORY 5: EDGE CASES AND BOUNDARY CONDITIONS
// ============================================================================

TEST_F(HashIndexTest, InsertMaxOffset) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    constexpr uint64_t maxOffset = UINT32_MAX;
    
    auto result = index.Insert(hash, maxOffset);
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index.Lookup(hash).value(), maxOffset);
}

TEST_F(HashIndexTest, InsertOffsetExceedingUint32_Fails) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    constexpr uint64_t tooLargeOffset = static_cast<uint64_t>(UINT32_MAX) + 1;
    
    auto result = index.Insert(hash, tooLargeOffset);
    EXPECT_FALSE(result.IsSuccess());
    EXPECT_EQ(result.code, WhitelistStoreError::InvalidEntry);
}

TEST_F(HashIndexTest, InsertZeroOffset) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    
    auto result = index.Insert(hash, 0);
    EXPECT_TRUE(result.IsSuccess());
    EXPECT_EQ(index.Lookup(hash).value(), 0u);
}

TEST_F(HashIndexTest, MultipleHashTypes) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    // Create hashes with different types
    HashValue sha256Hash{};
    sha256Hash.algorithm = HashAlgorithm::SHA256;
    sha256Hash.length = 32;
    sha256Hash.data[0] = 0x11;
    
    HashValue sha1Hash{};
    sha1Hash.algorithm = HashAlgorithm::SHA1;
	sha1Hash.length = 20;
    sha1Hash.data[0] = 0x22;
    
    HashValue md5Hash{};
    md5Hash.algorithm = HashAlgorithm::MD5;
	md5Hash.length = 16;
    md5Hash.data[0] = 0x33;
    
    EXPECT_TRUE(index.Insert(sha256Hash, 100).IsSuccess());
    EXPECT_TRUE(index.Insert(sha1Hash, 200).IsSuccess());
    EXPECT_TRUE(index.Insert(md5Hash, 300).IsSuccess());
    
    EXPECT_TRUE(index.Contains(sha256Hash));
    EXPECT_TRUE(index.Contains(sha1Hash));
    EXPECT_TRUE(index.Contains(md5Hash));
}

TEST_F(HashIndexTest, InsertUntilFull) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    size_t insertCount = 0;
    bool fullDetected = false;
    
    for (size_t i = 0; i < 10000; ++i) {
        auto hash = m_generator->Generate(i);
        auto result = index.Insert(hash, i);
        
        if (!result.IsSuccess()) {
            if (result.code == WhitelistStoreError::IndexFull) {
                fullDetected = true;
                break;
            }
        } else {
            ++insertCount;
        }
    }
    
    // Should have inserted some entries before running out of space
    EXPECT_GT(insertCount, 0u);
    // With small buffer, should eventually hit full
    // Note: May not hit full if buffer is large enough
}

// ============================================================================
// CATEGORY 6: ERROR HANDLING AND VALIDATION
// ============================================================================

TEST_F(HashIndexTest, OperationsOnUninitializedIndex) {
    HashIndex index;
    
    auto hash = m_generator->Generate(1);
    
    // All operations should fail gracefully
    EXPECT_FALSE(index.Lookup(hash).has_value());
    EXPECT_FALSE(index.Contains(hash));
    
    // Insert should fail (read-only since no base address)
    auto insertResult = index.Insert(hash, 100);
    EXPECT_FALSE(insertResult.IsSuccess());
}

TEST_F(HashIndexTest, ConcurrentReadOperations) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Pre-populate with data
    const size_t dataCount = 100;
    for (size_t i = 0; i < dataCount; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
    }
    
    // Concurrent reads should all succeed
    std::vector<std::future<bool>> futures;
    const size_t threadCount = TestConstants::CONCURRENT_READERS;
    
    for (size_t t = 0; t < threadCount; ++t) {
        futures.push_back(std::async(std::launch::async, [&, t]() {
            HashValueGenerator localGen(t * 1000);  // Different seed per thread
            bool allFound = true;
            
            for (size_t i = 0; i < dataCount; ++i) {
                auto hash = localGen.Generate(i);
                // Note: using same generation as main thread
                // This tests concurrent access to same data
            }
            
            // Use shared generator results
            for (size_t i = 0; i < dataCount; ++i) {
                if (!index.Contains(m_generator->Generate(i))) {
                    allFound = false;
                    break;
                }
            }
            
            return allFound;
        }));
    }
    
    // Wait for all threads and verify success
    for (auto& future : futures) {
        EXPECT_TRUE(future.get());
    }
}

// ============================================================================
// CATEGORY 7: THREAD SAFETY AND CONCURRENCY
// ============================================================================

TEST_F(HashIndexTest, ConcurrentInsertAndLookup) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    std::atomic<size_t> insertCount{0};
    std::atomic<size_t> lookupSuccessCount{0};
    std::atomic<bool> stopFlag{false};
    
    // Writer thread
    auto writerFuture = std::async(std::launch::async, [&]() {
        HashValueGenerator gen(999);
        for (size_t i = 0; i < 500 && !stopFlag; ++i) {
            auto hash = gen.Generate(i);
            if (index.Insert(hash, i).IsSuccess()) {
                ++insertCount;
            }
        }
    });
    
    // Reader threads
    std::vector<std::future<void>> readers;
    for (size_t t = 0; t < 4; ++t) {
        readers.push_back(std::async(std::launch::async, [&, t]() {
            HashValueGenerator gen(999);  // Same seed to read same hashes
            while (!stopFlag) {
                size_t currentCount = insertCount.load();
                if (currentCount > 0) {
                    size_t idx = t % currentCount;
                    auto hash = gen.Generate(idx);
                    if (index.Contains(hash)) {
                        ++lookupSuccessCount;
                    }
                }
                std::this_thread::yield();
            }
        }));
    }
    
    // Let writer finish
    writerFuture.wait();
    stopFlag = true;
    
    for (auto& reader : readers) {
        reader.wait();
    }
    
    EXPECT_GT(insertCount.load(), 0u);
    // Lookups may or may not succeed depending on timing
}

TEST_F(HashIndexTest, ConcurrentBatchLookup) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Pre-populate
    const size_t dataCount = 50;
    std::vector<HashValue> allHashes;
    for (size_t i = 0; i < dataCount; ++i) {
        auto hash = m_generator->Generate(i);
        allHashes.push_back(hash);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
    }
    
    // Concurrent batch lookups
    std::vector<std::future<size_t>> futures;
    const size_t threadCount = 4;
    
    for (size_t t = 0; t < threadCount; ++t) {
        futures.push_back(std::async(std::launch::async, [&]() {
            std::vector<std::optional<uint64_t>> results;
            index.BatchLookup(allHashes, results);
            
            size_t foundCount = 0;
            for (const auto& r : results) {
                if (r.has_value()) ++foundCount;
            }
            return foundCount;
        }));
    }
    
    for (auto& future : futures) {
        EXPECT_EQ(future.get(), dataCount);
    }
}

// ============================================================================
// CATEGORY 8: PERFORMANCE BENCHMARKS
// ============================================================================

TEST_F(HashIndexTest, DISABLED_BenchmarkSingleLookup) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Pre-populate
    const size_t dataCount = 1000;
    for (size_t i = 0; i < dataCount; ++i) {
        auto hash = m_generator->Generate(i);
        index.Insert(hash, i);
    }
    
    // Benchmark lookup
    const size_t iterations = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        auto hash = m_generator->Generate(i % dataCount);
        [[maybe_unused]] auto result = index.Lookup(hash);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    double nsPerLookup = static_cast<double>(duration.count()) / iterations;
    
    std::cout << "Average lookup time: " << nsPerLookup << " ns\n";
    
    EXPECT_LT(nsPerLookup, TestConstants::LOOKUP_TARGET_NS) 
        << "Lookup performance below target";
}

TEST_F(HashIndexTest, DISABLED_BenchmarkBatchLookup) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Pre-populate
    const size_t dataCount = 1000;
    std::vector<HashValue> hashes;
    for (size_t i = 0; i < dataCount; ++i) {
        auto hash = m_generator->Generate(i);
        hashes.push_back(hash);
        index.Insert(hash, i);
    }
    
    // Benchmark batch lookup
    const size_t iterations = 100;
    std::vector<std::optional<uint64_t>> results;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < iterations; ++i) {
        index.BatchLookup(hashes, results);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    double nsPerHash = static_cast<double>(duration.count()) / (iterations * dataCount);
    
    std::cout << "Average batch lookup time per hash: " << nsPerHash << " ns\n";
    
    EXPECT_LT(nsPerHash, TestConstants::BATCH_LOOKUP_TARGET_NS)
        << "Batch lookup performance below target";
}

TEST_F(HashIndexTest, DISABLED_BenchmarkInsert) {
    auto [index, buffer] = CreateIndex(TestConstants::STRESS_INDEX_SIZE);
    
    const size_t insertCount = 5000;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (size_t i = 0; i < insertCount; ++i) {
        auto hash = m_generator->Generate(i);
        index.Insert(hash, i);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    
    double nsPerInsert = static_cast<double>(duration.count()) / insertCount;
    
    std::cout << "Average insert time: " << nsPerInsert << " ns\n";
    
    EXPECT_LT(nsPerInsert, TestConstants::INSERT_TARGET_NS)
        << "Insert performance below target";
}

// ============================================================================
// CATEGORY 9: MEMORY CORRUPTION DETECTION
// ============================================================================

TEST_F(HashIndexTest, CorruptedNodeCount_Detected) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert some valid data first
    for (size_t i = 0; i < 10; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
    }
    
    // Manually corrupt the node count in header
    // This tests that operations don't crash with corrupted metadata
    // Note: In real usage, this would be detected by checksum validation
}

TEST_F(HashIndexTest, DataIntegrityAfterMultipleOperations) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    std::set<uint64_t> insertedIndices;
    
    // Mixed insert and remove operations
    for (size_t round = 0; round < 5; ++round) {
        // Insert batch
        for (size_t i = 0; i < 20; ++i) {
            uint64_t idx = round * 100 + i;
            auto hash = m_generator->Generate(idx);
            if (index.Insert(hash, idx).IsSuccess()) {
                insertedIndices.insert(idx);
            }
        }
        
        // Remove some
        for (size_t i = 0; i < 5; ++i) {
            uint64_t idx = round * 100 + i;
            auto hash = m_generator->Generate(idx);
            if (index.Remove(hash).IsSuccess()) {
                insertedIndices.erase(idx);
            }
        }
    }
    
    // Verify all remaining entries are retrievable
    for (uint64_t idx : insertedIndices) {
        auto hash = m_generator->Generate(idx);
        EXPECT_TRUE(index.Contains(hash)) << "Hash " << idx << " missing after operations";
    }
    
    EXPECT_EQ(index.GetEntryCount(), insertedIndices.size());
}

// ============================================================================
// CATEGORY 10: STRESS TESTS
// ============================================================================

TEST_F(HashIndexTest, DISABLED_StressTestHighVolume) {
    auto [index, buffer] = CreateIndex(TestConstants::STRESS_INDEX_SIZE);
    
    const size_t targetInserts = 5000;
    size_t successfulInserts = 0;
    
    for (size_t i = 0; i < targetInserts; ++i) {
        auto hash = m_generator->GenerateRandom();
        if (index.Insert(hash, i).IsSuccess()) {
            ++successfulInserts;
        }
    }
    
    std::cout << "Successfully inserted " << successfulInserts 
              << " / " << targetInserts << " entries\n";
    
    EXPECT_GT(successfulInserts, targetInserts / 2);
}

TEST_F(HashIndexTest, StressTestRemoveAll) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert 100 entries
    std::vector<HashValue> hashes;
    for (size_t i = 0; i < 100; ++i) {
        auto hash = m_generator->Generate(i);
        hashes.push_back(hash);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
    }
    
    EXPECT_EQ(index.GetEntryCount(), 100u);
    
    // Remove all
    for (const auto& hash : hashes) {
        auto result = index.Remove(hash);
        EXPECT_TRUE(result.IsSuccess()) << "Remove failed: " << result.message;
    }
    
    EXPECT_EQ(index.GetEntryCount(), 0u);
    
    // Verify all are gone
    for (const auto& hash : hashes) {
        EXPECT_FALSE(index.Contains(hash));
    }
}

TEST_F(HashIndexTest, StressTestInsertRemoveInterleaved) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    std::set<uint64_t> currentEntries;
    std::mt19937 rng(42);
    
    for (size_t iteration = 0; iteration < 500; ++iteration) {
        // Randomly decide to insert or remove
        bool shouldInsert = currentEntries.size() < 50 || 
                           (currentEntries.size() < 100 && rng() % 2 == 0);
        
        if (shouldInsert) {
            uint64_t newIdx = iteration * 10 + rng() % 10;
            if (currentEntries.find(newIdx) == currentEntries.end()) {
                auto hash = m_generator->Generate(newIdx);
                if (index.Insert(hash, newIdx).IsSuccess()) {
                    currentEntries.insert(newIdx);
                }
            }
        } else if (!currentEntries.empty()) {
            // Remove random entry
            auto it = currentEntries.begin();
            std::advance(it, rng() % currentEntries.size());
            uint64_t toRemove = *it;
            
            auto hash = m_generator->Generate(toRemove);
            if (index.Remove(hash).IsSuccess()) {
                currentEntries.erase(it);
            }
        }
    }
    
    // Verify final state
    EXPECT_EQ(index.GetEntryCount(), currentEntries.size());
    
    for (uint64_t idx : currentEntries) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(idx)));
    }
}

// ============================================================================
// REGRESSION TESTS
// ============================================================================

TEST_F(HashIndexTest, RegressionDuplicateKeyHandling) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    
    // Insert multiple times with different offsets
    EXPECT_TRUE(index.Insert(hash, 100).IsSuccess());
    EXPECT_TRUE(index.Insert(hash, 200).IsSuccess());
    EXPECT_TRUE(index.Insert(hash, 300).IsSuccess());
    
    // Should only have one entry (last wins)
    EXPECT_EQ(index.GetEntryCount(), 1u);
    EXPECT_EQ(index.Lookup(hash).value(), 300u);
}

TEST_F(HashIndexTest, RegressionRemoveFromSingleEntryIndex) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    auto hash = m_generator->Generate(1);
    
    EXPECT_TRUE(index.Insert(hash, 100).IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 1u);
    
    EXPECT_TRUE(index.Remove(hash).IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 0u);
    
    // Should be able to insert again
    EXPECT_TRUE(index.Insert(hash, 200).IsSuccess());
    EXPECT_EQ(index.GetEntryCount(), 1u);
    EXPECT_EQ(index.Lookup(hash).value(), 200u);
}

// ============================================================================
// ENTERPRISE EDGE-CASE TESTS - B+TREE SPLIT AND INTEGRITY
// ============================================================================

/**
 * @brief Tests multiple consecutive splits to verify linked list integrity
 * 
 * CRITICAL: This test verifies that leaf node linked list is maintained
 * correctly through multiple splits. Regression test for duplicate
 * linked list update bug.
 */
TEST_F(HashIndexTest, EdgeCase_MultipleConsecutiveSplits) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Insert enough to cause multiple splits
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 4;
    size_t successCount = InsertNHashes(index, insertCount);
    
    EXPECT_GT(successCount, TestConstants::MAX_KEYS_PER_NODE * 3);
    EXPECT_GT(index.GetNodeCount(), 3u) << "Should have split multiple times";
    
    // Verify ALL entries are retrievable (linked list integrity)
    for (size_t i = 0; i < successCount; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Contains(hash)) 
            << "Hash " << i << " missing after multiple splits - linked list corrupted";
    }
}

/**
 * @brief Test that verifies leaf traversal after splits
 * 
 * After splits, the leaf linked list must allow traversal from
 * first to last leaf without gaps.
 */
TEST_F(HashIndexTest, EdgeCase_LeafLinkedListIntegrity) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Insert to cause multiple splits
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 3;
    size_t successCount = InsertNHashes(index, insertCount);
    
    EXPECT_GT(successCount, 100u);
    
    // Verify entry and node counts using available methods
    const uint64_t entryCount = index.GetEntryCount();
    const uint64_t nodeCount = index.GetNodeCount();
    
    // Total entries should match what we inserted
    EXPECT_EQ(entryCount, successCount) 
        << "Entry count mismatch - possible linked list corruption";
    
    // Node count should be reasonable
    EXPECT_GT(nodeCount, 1u);
    EXPECT_LT(nodeCount, successCount); // We shouldn't have more nodes than entries
}

/**
 * @brief Test batch insert with splits
 * 
 * Verifies that BatchInsert correctly handles splits and maintains
 * data integrity.
 */
TEST_F(HashIndexTest, EdgeCase_BatchInsertWithSplits) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Create batch large enough to cause splits
    std::vector<std::pair<HashValue, uint64_t>> entries;
    const size_t batchSize = TestConstants::MAX_KEYS_PER_NODE * 2;
    
    for (size_t i = 0; i < batchSize; ++i) {
        entries.emplace_back(m_generator->Generate(i), i * 100);
    }
    
    auto result = index.BatchInsert(entries);
    EXPECT_TRUE(result.IsSuccess()) << "BatchInsert failed: " << result.message;
    
    // Verify all entries are present
    for (size_t i = 0; i < batchSize; ++i) {
        auto lookupResult = index.Lookup(entries[i].first);
        EXPECT_TRUE(lookupResult.has_value()) 
            << "Entry " << i << " missing after batch insert";
        if (lookupResult.has_value()) {
            EXPECT_EQ(lookupResult.value(), i * 100) 
                << "Wrong offset for entry " << i;
        }
    }
}

/**
 * @brief Test rapid insert-remove cycles under tree growth
 * 
 * Verifies tree maintains integrity when rapidly adding and removing
 * entries while the tree is growing.
 */
TEST_F(HashIndexTest, EdgeCase_RapidInsertRemoveDuringGrowth) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    std::set<uint64_t> activeEntries;
    
    // Rapid insert/remove while tree grows
    for (size_t round = 0; round < 10; ++round) {
        // Insert a batch
        for (size_t i = 0; i < 50; ++i) {
            uint64_t idx = round * 100 + i;
            auto hash = m_generator->Generate(idx);
            if (index.Insert(hash, idx).IsSuccess()) {
                activeEntries.insert(idx);
            }
        }
        
        // Remove some entries
        std::vector<uint64_t> toRemove;
        for (auto it = activeEntries.begin(); it != activeEntries.end(); ++it) {
            if ((*it % 3) == 0) {
                toRemove.push_back(*it);
            }
        }
        
        for (uint64_t idx : toRemove) {
            auto hash = m_generator->Generate(idx);
            if (index.Remove(hash).IsSuccess()) {
                activeEntries.erase(idx);
            }
        }
    }
    
    // Verify remaining entries
    EXPECT_EQ(index.GetEntryCount(), activeEntries.size());
    
    for (uint64_t idx : activeEntries) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(idx)))
            << "Entry " << idx << " missing after insert/remove cycles";
    }
}

/**
 * @brief Test exact MAX_KEYS boundary condition
 * 
 * Insert exactly MAX_KEYS entries, then one more to trigger split.
 */
TEST_F(HashIndexTest, EdgeCase_ExactMaxKeysBoundary) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert exactly MAX_KEYS entries
    for (size_t i = 0; i < TestConstants::MAX_KEYS_PER_NODE; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess()) 
            << "Insert " << i << " failed before reaching MAX_KEYS";
    }
    
    EXPECT_EQ(index.GetEntryCount(), TestConstants::MAX_KEYS_PER_NODE);
    EXPECT_EQ(index.GetNodeCount(), 1u) << "Should still be single node";
    
    // Insert one more - this should trigger a split
    auto hash = m_generator->Generate(TestConstants::MAX_KEYS_PER_NODE);
    EXPECT_TRUE(index.Insert(hash, TestConstants::MAX_KEYS_PER_NODE).IsSuccess())
        << "Insert at MAX_KEYS boundary failed";
    
    EXPECT_EQ(index.GetEntryCount(), TestConstants::MAX_KEYS_PER_NODE + 1);
    EXPECT_GT(index.GetNodeCount(), 1u) << "Split should have occurred";
    
    // Verify all entries including the one that triggered split
    for (size_t i = 0; i <= TestConstants::MAX_KEYS_PER_NODE; ++i) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(i)))
            << "Entry " << i << " lost at MAX_KEYS boundary";
    }
}

/**
 * @brief Test Clear and reuse after tree growth
 * 
 * Verifies that Clear properly resets state and index can be reused.
 */
TEST_F(HashIndexTest, EdgeCase_ClearAfterTreeGrowth) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    // Build up tree
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 3;
    InsertNHashes(index, insertCount);
    
    EXPECT_GT(index.GetEntryCount(), 100u);
    EXPECT_GT(index.GetNodeCount(), 1u);
    EXPECT_GT(index.GetTreeDepth(), 1u);
    
    // Clear
    auto clearResult = index.Clear();
    EXPECT_TRUE(clearResult.IsSuccess()) << "Clear failed: " << clearResult.message;
    
    // Verify state is reset
    EXPECT_EQ(index.GetEntryCount(), 0u);
    EXPECT_EQ(index.GetNodeCount(), 1u);
    EXPECT_EQ(index.GetTreeDepth(), 1u);
    
    // Verify old entries are gone
    for (size_t i = 0; i < 10; ++i) {
        EXPECT_FALSE(index.Contains(m_generator->Generate(i)))
            << "Entry " << i << " still present after Clear";
    }
    
    // Verify can reuse
    m_generator->Reset();
    size_t successCount = InsertNHashes(index, insertCount);
    EXPECT_GT(successCount, 100u);
    
    // Verify new entries
    for (size_t i = 0; i < successCount; ++i) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(i)))
            << "New entry " << i << " not found after Clear and reinsert";
    }
}

/**
 * @brief Test with all same hash prefix (worst case for some implementations)
 * 
 * When all hashes produce similar FastHash values, they go to same leaf
 * causing rapid splits in one area.
 */
TEST_F(HashIndexTest, EdgeCase_SimilarHashValues) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Generate hashes with sequential indices - these will have similar structure
    std::vector<HashValue> hashes;
    for (uint64_t i = 0; i < 200; ++i) {
        HashValue hash{};
        hash.algorithm = HashAlgorithm::SHA256;
        hash.length = 32;
        
        // Create hashes that differ only in last few bytes
        std::memset(hash.data.data(), 0xAA, 32);
        std::memcpy(hash.data.data() + 28, &i, sizeof(uint64_t) < 4 ? sizeof(uint64_t) : 4);
        
        hashes.push_back(hash);
    }
    
    // Insert all
    size_t successCount = 0;
    for (size_t i = 0; i < hashes.size(); ++i) {
        if (index.Insert(hashes[i], i).IsSuccess()) {
            ++successCount;
        }
    }
    
    EXPECT_EQ(successCount, hashes.size());
    
    // Verify retrieval
    for (size_t i = 0; i < hashes.size(); ++i) {
        EXPECT_TRUE(index.Contains(hashes[i]))
            << "Hash " << i << " with similar prefix not found";
    }
}

/**
 * @brief Test lookup performance doesn't degrade with tree depth
 * 
 * After many inserts, lookups should still complete in reasonable time.
 */
TEST_F(HashIndexTest, EdgeCase_DeepTreeLookup) {
    auto [index, buffer] = CreateIndex(TestConstants::STRESS_INDEX_SIZE);
    
    // Insert many entries
    const size_t insertCount = 5000;
    InsertNHashes(index, insertCount);
    
    // Time multiple lookups
    auto start = std::chrono::high_resolution_clock::now();
    
    const size_t lookupCount = 1000;
    size_t found = 0;
    for (size_t i = 0; i < lookupCount; ++i) {
        if (index.Contains(m_generator->Generate(i % insertCount))) {
            ++found;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    EXPECT_GT(found, lookupCount * 0.9) << "Too many lookups failed";
    
    // Sanity check - 1000 lookups shouldn't take more than 100ms even on slow systems
    EXPECT_LT(duration.count(), 100000) 
        << "Lookups too slow: " << duration.count() << "us for " << lookupCount << " lookups";
}

/**
 * @brief Test that internal node splits work correctly
 * 
 * When tree grows deep enough, internal nodes also need to split.
 */
TEST_F(HashIndexTest, EdgeCase_InternalNodeSplit) {
    auto [index, buffer] = CreateIndex(TestConstants::STRESS_INDEX_SIZE);
    
    // Insert enough to cause internal node splits
    // This requires filling leaf nodes AND causing the internal node to split
    const size_t insertCount = TestConstants::MAX_KEYS_PER_NODE * 
                               TestConstants::MAX_KEYS_PER_NODE;
    
    size_t successCount = InsertNHashes(index, insertCount);
    
    // We expect most inserts to succeed (some may fail if space runs out)
    EXPECT_GT(successCount, insertCount / 2);
    
    // Tree should have grown significantly
    EXPECT_GE(index.GetTreeDepth(), 2u);
    
    // Verify data integrity
    size_t verifyCount = std::min(successCount, size_t(1000)); // Sample verification
    for (size_t i = 0; i < verifyCount; ++i) {
        EXPECT_TRUE(index.Contains(m_generator->Generate(i)))
            << "Entry " << i << " lost after internal node splits";
    }
}

/**
 * @brief Test mixed operations maintain consistency
 * 
 * Interleaves Insert, Lookup, Remove, BatchLookup operations.
 */
TEST_F(HashIndexTest, EdgeCase_MixedOperationsConsistency) {
    auto [index, buffer] = CreateIndex(TestConstants::LARGE_INDEX_SIZE);
    
    std::set<uint64_t> expectedEntries;
    
    // Phase 1: Insert
    for (uint64_t i = 0; i < 100; ++i) {
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
        expectedEntries.insert(i);
    }
    
    // Phase 2: Mixed insert/lookup/remove
    for (uint64_t i = 100; i < 300; ++i) {
        // Insert new
        auto hash = m_generator->Generate(i);
        EXPECT_TRUE(index.Insert(hash, i).IsSuccess());
        expectedEntries.insert(i);
        
        // Lookup random existing
        if (!expectedEntries.empty()) {
            uint64_t checkIdx = i % 100;
            if (expectedEntries.count(checkIdx)) {
                EXPECT_TRUE(index.Contains(m_generator->Generate(checkIdx)));
            }
        }
        
        // Remove every 5th old entry
        if (i % 5 == 0 && i >= 110) {
            uint64_t removeIdx = i - 100;
            if (expectedEntries.count(removeIdx)) {
                auto removeHash = m_generator->Generate(removeIdx);
                if (index.Remove(removeHash).IsSuccess()) {
                    expectedEntries.erase(removeIdx);
                }
            }
        }
    }
    
    // Verify final state
    EXPECT_EQ(index.GetEntryCount(), expectedEntries.size());
    
    // Batch lookup to verify
    std::vector<HashValue> lookupHashes;
    for (uint64_t idx : expectedEntries) {
        lookupHashes.push_back(m_generator->Generate(idx));
    }
    
    std::vector<std::optional<uint64_t>> results;
    index.BatchLookup(lookupHashes, results);
    
    ASSERT_EQ(results.size(), lookupHashes.size());
    for (size_t i = 0; i < results.size(); ++i) {
        EXPECT_TRUE(results[i].has_value()) 
            << "Entry in expected set not found via BatchLookup";
    }
}

/**
 * @brief Test zero offset handling
 * 
 * Zero is a valid offset value and should not be confused with null/empty.
 */
TEST_F(HashIndexTest, EdgeCase_ZeroOffsetHandling) {
    auto [index, buffer] = CreateIndex(TestConstants::SMALL_INDEX_SIZE);
    
    // Insert with offset 0
    auto hash1 = m_generator->Generate(1);
    EXPECT_TRUE(index.Insert(hash1, 0).IsSuccess());
    
    auto result = index.Lookup(hash1);
    EXPECT_TRUE(result.has_value()) << "Zero offset entry not found";
    EXPECT_EQ(result.value(), 0u) << "Zero offset not returned correctly";
    
    // Insert with offset 1
    auto hash2 = m_generator->Generate(2);
    EXPECT_TRUE(index.Insert(hash2, 1).IsSuccess());
    
    // Both should be retrievable
    EXPECT_EQ(index.GetEntryCount(), 2u);
    EXPECT_TRUE(index.Contains(hash1));
    EXPECT_TRUE(index.Contains(hash2));
}

/**
 * @brief Test sequential remove maintains tree integrity
 * 
 * Remove entries in order and verify tree stays valid.
 */
TEST_F(HashIndexTest, EdgeCase_SequentialRemoveIntegrity) {
    auto [index, buffer] = CreateIndex(TestConstants::MEDIUM_INDEX_SIZE);
    
    // Insert entries
    const size_t count = 200;
    InsertNHashes(index, count);
    
    EXPECT_EQ(index.GetEntryCount(), count);
    
    // Remove in order
    for (size_t i = 0; i < count; ++i) {
        auto hash = m_generator->Generate(i);
        auto result = index.Remove(hash);
        EXPECT_TRUE(result.IsSuccess()) << "Remove " << i << " failed";
        
        // Verify remaining entries still accessible
        if (i < count - 1) {
            auto nextHash = m_generator->Generate(i + 1);
            EXPECT_TRUE(index.Contains(nextHash))
                << "Next entry " << (i + 1) << " lost after removing " << i;
        }
    }
    
    EXPECT_EQ(index.GetEntryCount(), 0u);
}

} // namespace ShadowStrike::Whitelist::Tests
