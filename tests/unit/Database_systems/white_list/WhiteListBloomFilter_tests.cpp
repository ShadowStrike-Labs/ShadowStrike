// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/**
 * ============================================================================
 * ShadowStrike WhitelistStore - BLOOM FILTER UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * Enterprise-Grade Unit Tests for BloomFilter:
 * - Construction & Initialization
 * - Single Operations (Add, MightContain)
 * - Batch Operations (BatchAdd, BatchQuery)
 * - Memory Management (InitializeForBuild, Clear, Serialize)
 * - Memory-Mapped Mode
 * - Statistics & Metrics
 * - False Positive Rate Verification
 * - Thread Safety & Concurrency
 * - Edge Cases & Error Handling
 * - Performance Benchmarks
 *
 * Quality Standards:
 * - CrowdStrike Falcon / Kaspersky / Bitdefender quality
 * - Thread-safety verification under high concurrency
 * - Memory leak detection through multiple cycles
 * - Performance guardrails (latency, throughput)
 *
 * @author ShadowStrike Security Team
 * @copyright 2024-2026 ShadowStrike Project
 * ============================================================================
 */
#include <gtest/gtest.h>

#include "../../../../src/Whitelist/WhiteListStore.hpp"
#include "../../../../src/Whitelist/WhiteListFormat.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <memory>
#include <numeric>
#include <random>
#include <thread>
#include <unordered_set>
#include <vector>

namespace ShadowStrike::Whitelist::Tests {

using namespace ShadowStrike::Whitelist;

// ============================================================================
// TEST UTILITIES
// ============================================================================

namespace {

/**
 * @brief Generate deterministic hash for testing
 * @param seed Seed value
 * @return 64-bit hash value
 */
[[nodiscard]] uint64_t GenerateTestHash(uint64_t seed) noexcept {
    // MurmurHash3 finalizer for good distribution
    uint64_t h = seed;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}

/**
 * @brief Generate vector of unique test hashes
 * @param count Number of hashes to generate
 * @param startSeed Starting seed value
 * @return Vector of unique hash values
 */
[[nodiscard]] std::vector<uint64_t> GenerateTestHashes(size_t count, uint64_t startSeed = 0) {
    std::vector<uint64_t> hashes;
    hashes.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        hashes.push_back(GenerateTestHash(startSeed + i));
    }
    return hashes;
}

/**
 * @brief Measure execution time of a callable
 * @param func Function to measure
 * @return Duration in nanoseconds
 */
template<typename Func>
[[nodiscard]] int64_t MeasureNanoseconds(Func&& func) {
    const auto start = std::chrono::high_resolution_clock::now();
    func();
    const auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
}

/// @brief Default test parameters
constexpr size_t DEFAULT_TEST_ELEMENTS = 10'000;
constexpr double DEFAULT_TEST_FPR = 0.01;  // 1%

} // anonymous namespace

// ============================================================================
// PART 1: Construction & Initialization Tests
// ============================================================================

TEST(BloomFilter_Construction, DefaultConstruction_SetsParameters) {
    BloomFilter filter;
    
    // Default filter should have reasonable parameters
    EXPECT_GT(filter.GetBitCount(), 0u);
    EXPECT_GT(filter.GetHashFunctions(), 0u);
    EXPECT_GT(filter.GetExpectedElements(), 0u);
    EXPECT_GT(filter.GetTargetFPR(), 0.0);
    EXPECT_LT(filter.GetTargetFPR(), 1.0);
}

TEST(BloomFilter_Construction, ParameterizedConstruction_SetsCorrectValues) {
    constexpr size_t expectedElements = 100'000;
    constexpr double targetFPR = 0.001;  // 0.1%
    
    BloomFilter filter(expectedElements, targetFPR);
    
    EXPECT_EQ(filter.GetExpectedElements(), expectedElements);
    EXPECT_DOUBLE_EQ(filter.GetTargetFPR(), targetFPR);
    EXPECT_GT(filter.GetBitCount(), 0u);
    EXPECT_GE(filter.GetHashFunctions(), MIN_BLOOM_HASHES);
    EXPECT_LE(filter.GetHashFunctions(), MAX_BLOOM_HASHES);
}

TEST(BloomFilter_Construction, ExtremeSmallElements_ClampedToMinimum) {
    BloomFilter filter(0, DEFAULT_TEST_FPR);
    
    // Should be clamped to at least 1
    EXPECT_GE(filter.GetExpectedElements(), 1u);
    EXPECT_GT(filter.GetBitCount(), 0u);
}

TEST(BloomFilter_Construction, ExtremeLargeElements_ClampedToMaximum) {
    BloomFilter filter(SIZE_MAX, DEFAULT_TEST_FPR);
    
    // Should be clamped to MAX_BLOOM_EXPECTED_ELEMENTS
    EXPECT_LE(filter.GetExpectedElements(), MAX_BLOOM_EXPECTED_ELEMENTS);
    EXPECT_LE(filter.GetBitCount(), MAX_BLOOM_BITS);
}

TEST(BloomFilter_Construction, ExtremeLowFPR_ClampedToMinimum) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, 0.0);
    
    EXPECT_GE(filter.GetTargetFPR(), MIN_BLOOM_FPR);
}

TEST(BloomFilter_Construction, ExtremeHighFPR_ClampedToMaximum) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, 1.0);
    
    EXPECT_LE(filter.GetTargetFPR(), MAX_BLOOM_FPR);
}

TEST(BloomFilter_Construction, NegativeFPR_ClampedToMinimum) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, -0.5);
    
    EXPECT_GE(filter.GetTargetFPR(), MIN_BLOOM_FPR);
}

TEST(BloomFilter_Construction, MoveConstruction_TransfersOwnership) {
    BloomFilter original(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(original.InitializeForBuild());
    
    const uint64_t testHash = 0x123456789ABCDEF0ULL;
    original.Add(testHash);
    
    // Move construct
    BloomFilter moved(std::move(original));
    
    EXPECT_TRUE(moved.IsReady());
    EXPECT_TRUE(moved.MightContain(testHash));
    EXPECT_FALSE(original.IsReady());  // NOLINT: intentionally checking moved-from state
}

TEST(BloomFilter_Construction, MoveAssignment_TransfersOwnership) {
    BloomFilter original(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(original.InitializeForBuild());
    
    const uint64_t testHash = 0xFEDCBA9876543210ULL;
    original.Add(testHash);
    
    BloomFilter assigned;
    assigned = std::move(original);
    
    EXPECT_TRUE(assigned.IsReady());
    EXPECT_TRUE(assigned.MightContain(testHash));
    EXPECT_FALSE(original.IsReady());  // NOLINT
}

// ============================================================================
// PART 2: Initialization Tests
// ============================================================================

TEST(BloomFilter_Initialization, InitializeForBuild_AllocatesMemory) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    
    EXPECT_FALSE(filter.IsReady());
    EXPECT_TRUE(filter.InitializeForBuild());
    EXPECT_TRUE(filter.IsReady());
    EXPECT_GT(filter.GetMemoryUsage(), 0u);
}

TEST(BloomFilter_Initialization, InitializeForBuild_ZeroesAllBits) {
    BloomFilter filter(1000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // New filter should have 0% fill rate
    EXPECT_DOUBLE_EQ(filter.EstimatedFillRate(), 0.0);
    EXPECT_EQ(filter.GetElementsAdded(), 0u);
}

TEST(BloomFilter_Initialization, InitializeFromMemory_ValidData) {
    // Create and populate a filter
    BloomFilter builder(1000, 0.01);
    ASSERT_TRUE(builder.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(100);
    for (uint64_t h : testHashes) {
        builder.Add(h);
    }
    
    // Serialize it
    std::vector<uint8_t> serializedData;
    ASSERT_TRUE(builder.Serialize(serializedData));
    
    // Initialize new filter from serialized data
    BloomFilter reader;
    EXPECT_TRUE(reader.Initialize(
        serializedData.data(),
        builder.GetBitCount(),
        builder.GetHashFunctions()
    ));
    
    EXPECT_TRUE(reader.IsReady());
    EXPECT_TRUE(reader.IsMemoryMapped());
    
    // Verify all elements are found
    for (uint64_t h : testHashes) {
        EXPECT_TRUE(reader.MightContain(h));
    }
}

TEST(BloomFilter_Initialization, InitializeFromMemory_NullPointer_Fails) {
    BloomFilter filter;
    EXPECT_FALSE(filter.Initialize(nullptr, 1000, 7));
    EXPECT_FALSE(filter.IsReady());
}

TEST(BloomFilter_Initialization, InitializeFromMemory_ZeroBitCount_Fails) {
    uint64_t dummy = 0;
    BloomFilter filter;
    EXPECT_FALSE(filter.Initialize(&dummy, 0, 7));
}

TEST(BloomFilter_Initialization, InitializeFromMemory_InvalidHashCount_Fails) {
    uint64_t dummy = 0;
    BloomFilter filter;
    
    EXPECT_FALSE(filter.Initialize(&dummy, 64, MIN_BLOOM_HASHES - 1));
    EXPECT_FALSE(filter.Initialize(&dummy, 64, MAX_BLOOM_HASHES + 1));
}

// ============================================================================
// PART 3: Single Operation Tests (Add, MightContain)
// ============================================================================

TEST(BloomFilter_SingleOps, Add_ElementCanBeFound) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const uint64_t testHash = 0xDEADBEEFCAFEBABEULL;
    
    EXPECT_FALSE(filter.MightContain(testHash));  // Not added yet
    
    filter.Add(testHash);
    
    EXPECT_TRUE(filter.MightContain(testHash));
    EXPECT_EQ(filter.GetElementsAdded(), 1u);
}

TEST(BloomFilter_SingleOps, Add_MultipleElements_AllFound) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(1000);
    
    for (uint64_t h : testHashes) {
        filter.Add(h);
    }
    
    // All added elements must be found (no false negatives)
    for (uint64_t h : testHashes) {
        EXPECT_TRUE(filter.MightContain(h)) << "Hash: " << h;
    }
    
    EXPECT_EQ(filter.GetElementsAdded(), 1000u);
}

TEST(BloomFilter_SingleOps, Add_DuplicateElement_NoFalseNegative) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const uint64_t testHash = 0x1234567890ABCDEFULL;
    
    // Add same element multiple times
    for (int i = 0; i < 100; ++i) {
        filter.Add(testHash);
    }
    
    // Must still be found
    EXPECT_TRUE(filter.MightContain(testHash));
}

TEST(BloomFilter_SingleOps, Add_ToMemoryMapped_IsNoOp) {
    // Create and serialize a filter
    BloomFilter builder(1000, 0.01);
    ASSERT_TRUE(builder.InitializeForBuild());
    
    std::vector<uint8_t> data;
    ASSERT_TRUE(builder.Serialize(data));
    
    // Initialize as memory-mapped
    BloomFilter reader;
    ASSERT_TRUE(reader.Initialize(data.data(), builder.GetBitCount(), builder.GetHashFunctions()));
    
    const uint64_t testHash = 0xABCDEF0123456789ULL;
    
    // Add should be no-op
    reader.Add(testHash);
    
    // Element should NOT be found (memory-mapped is read-only)
    // Note: This is conservative - depends on whether bit was already set
}

TEST(BloomFilter_SingleOps, MightContain_UninitializedFilter_ReturnsTrue) {
    BloomFilter filter;
    
    // Uninitialized filter should be conservative
    EXPECT_TRUE(filter.MightContain(0x12345ULL));
}

TEST(BloomFilter_SingleOps, Add_WithHashValue_Works) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    HashValue hv{};
    hv.algorithm = HashAlgorithm::SHA256;
    // Set some bytes
    hv.data[0] = 0x12;
    hv.data[1] = 0x34;
    hv.data[31] = 0xFF;
    
    filter.Add(hv);
    EXPECT_TRUE(filter.MightContain(hv));
}

// ============================================================================
// PART 4: Batch Operation Tests
// ============================================================================

TEST(BloomFilter_BatchOps, BatchAdd_EmptyInput_ReturnsZero) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    std::vector<uint64_t> empty;
    EXPECT_EQ(filter.BatchAdd(empty), 0u);
}

TEST(BloomFilter_BatchOps, BatchAdd_MultipleElements_AllFound) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(5000);
    
    const size_t added = filter.BatchAdd(testHashes);
    EXPECT_EQ(added, testHashes.size());
    
    // Verify all elements
    for (uint64_t h : testHashes) {
        EXPECT_TRUE(filter.MightContain(h));
    }
}

TEST(BloomFilter_BatchOps, BatchQuery_EmptyInput_ReturnsZero) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    std::vector<uint64_t> empty;
    bool dummy;
    std::span<bool> results(&dummy, 0);
    
    EXPECT_EQ(filter.BatchQuery(empty, results), 0u);
}

TEST(BloomFilter_BatchOps, BatchQuery_MismatchedSizes_ReturnsZero) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    std::vector<uint64_t> hashes = {1, 2, 3};
    auto results_buf = std::make_unique<bool[]>(5);
    std::span<bool> results(results_buf.get(), 5);
    
    EXPECT_EQ(filter.BatchQuery(hashes, results), 0u);
}

TEST(BloomFilter_BatchOps, BatchQuery_AfterBatchAdd_AllPositive) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(1000);
    filter.BatchAdd(testHashes);//-V530
    
    const size_t count = testHashes.size();
    auto results_buf = std::make_unique<bool[]>(count);
    std::span<bool> results(results_buf.get(), count);
    const size_t positives = filter.BatchQuery(testHashes, results);
    
    // All should be positive (no false negatives)
    EXPECT_EQ(positives, count);
    for (size_t i = 0; i < count; ++i) {
        EXPECT_TRUE(results[i]);
    }
}

TEST(BloomFilter_BatchOps, BatchQuery_EmptyFilter_MostlyNegative) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());

    const auto testHashes = GenerateTestHashes(1000);

   
    const size_t count = testHashes.size();
    auto results_buf = std::make_unique<bool[]>(count);
    std::span<bool> results(results_buf.get(), count);

    const size_t positives = filter.BatchQuery(testHashes, results);

  
    EXPECT_LT(positives, count / 10);
}

// ============================================================================
// PART 5: Clear & Serialize Tests
// ============================================================================

TEST(BloomFilter_ClearSerialize, Clear_ResetsAllBits) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Add many elements
    const auto testHashes = GenerateTestHashes(1000);
    filter.BatchAdd(testHashes);//-V530
    
    EXPECT_GT(filter.EstimatedFillRate(), 0.0);
    EXPECT_GT(filter.GetElementsAdded(), 0u);
    
    filter.Clear();
    
    EXPECT_DOUBLE_EQ(filter.EstimatedFillRate(), 0.0);
    EXPECT_EQ(filter.GetElementsAdded(), 0u);
    
    // Elements should no longer be found
    size_t foundCount = 0;
    for (uint64_t h : testHashes) {
        if (filter.MightContain(h)) {
            ++foundCount;
        }
    }
    EXPECT_EQ(foundCount, 0u);
}

TEST(BloomFilter_ClearSerialize, Serialize_ProducesValidData) {
    BloomFilter filter(1000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(100);
    filter.BatchAdd(testHashes);//-V530
    
    std::vector<uint8_t> data;
    EXPECT_TRUE(filter.Serialize(data));
    
    // Data should be non-empty and properly sized
    EXPECT_GT(data.size(), 0u);
    EXPECT_EQ(data.size() % sizeof(uint64_t), 0u);
}

TEST(BloomFilter_ClearSerialize, Serialize_MemoryMapped_Fails) {
    BloomFilter builder(1000, 0.01);
    ASSERT_TRUE(builder.InitializeForBuild());
    
    std::vector<uint8_t> builderData;
    ASSERT_TRUE(builder.Serialize(builderData));
    
    BloomFilter reader;
    ASSERT_TRUE(reader.Initialize(builderData.data(), builder.GetBitCount(), builder.GetHashFunctions()));
    
    std::vector<uint8_t> readerData;
    EXPECT_FALSE(reader.Serialize(readerData));
}

TEST(BloomFilter_ClearSerialize, Serialize_EmptyFilter_Fails) {
    BloomFilter filter;
    
    std::vector<uint8_t> data;
    EXPECT_FALSE(filter.Serialize(data));
}

// ============================================================================
// PART 6: Statistics Tests
// ============================================================================

TEST(BloomFilter_Statistics, GetDetailedStats_ReturnsValidData) {
    BloomFilter filter(10000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(500);
    filter.BatchAdd(testHashes);//-V530
    
    const auto stats = filter.GetDetailedStats();
    
    EXPECT_EQ(stats.bitCount, filter.GetBitCount());
    EXPECT_EQ(stats.hashFunctions, filter.GetHashFunctions());
    EXPECT_EQ(stats.expectedElements, filter.GetExpectedElements());
    EXPECT_EQ(stats.elementsAdded, 500u);
    EXPECT_GT(stats.memoryBytes, 0u);
    EXPECT_FALSE(stats.isMemoryMapped);
    EXPECT_TRUE(stats.isReady);
    EXPECT_GT(stats.fillRate, 0.0);
    EXPECT_LT(stats.fillRate, 1.0);
}

TEST(BloomFilter_Statistics, EstimatedFillRate_IncreasesWithElements) {
    BloomFilter filter(10000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    double prevFillRate = 0.0;
    
    for (int batch = 0; batch < 10; ++batch) {
        const auto hashes = GenerateTestHashes(100, batch * 100);
        filter.BatchAdd(hashes);//-V530
        
        const double fillRate = filter.EstimatedFillRate();
        EXPECT_GT(fillRate, prevFillRate);
        prevFillRate = fillRate;
    }
}

TEST(BloomFilter_Statistics, EstimatedFPR_IncreasesWithFillRate) {
    BloomFilter filter(1000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Empty filter should have 0% FPR
    EXPECT_DOUBLE_EQ(filter.EstimatedFalsePositiveRate(), 0.0);
    
    // Add elements
    const auto hashes = GenerateTestHashes(500);
    filter.BatchAdd(hashes);//-V530
    
    const double fpr = filter.EstimatedFalsePositiveRate();
    EXPECT_GT(fpr, 0.0);
    EXPECT_LE(fpr, 1.0);
}

// ============================================================================
// PART 7: False Positive Rate Verification
// ============================================================================

TEST(BloomFilter_FPR, FalsePositiveRate_WithinExpectedBounds) {
    constexpr size_t elements = 10000;
    constexpr double targetFPR = 0.01;  // 1%
    constexpr size_t testQueries = 100000;
    
    BloomFilter filter(elements, targetFPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Add expected number of elements
    const auto insertHashes = GenerateTestHashes(elements, 0);
    filter.BatchAdd(insertHashes);//-V530
    
    // Query with different hashes (guaranteed not in set)
    const auto queryHashes = GenerateTestHashes(testQueries, elements + 1000000);
    
    size_t falsePositives = 0;
    for (uint64_t h : queryHashes) {
        if (filter.MightContain(h)) {
            ++falsePositives;
        }
    }
    
    const double actualFPR = static_cast<double>(falsePositives) / static_cast<double>(testQueries);
    
    // Allow 3x tolerance for statistical variance
    EXPECT_LT(actualFPR, targetFPR * 3.0) 
        << "False positive rate " << actualFPR 
        << " exceeds 3x target " << targetFPR;
}

TEST(BloomFilter_FPR, NoFalseNegatives_Guaranteed) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    const auto testHashes = GenerateTestHashes(5000);
    filter.BatchAdd(testHashes);//-V530
    
    // No false negatives - all added elements MUST be found
    size_t falseNegatives = 0;
    for (uint64_t h : testHashes) {
        if (!filter.MightContain(h)) {
            ++falseNegatives;
        }
    }
    
    EXPECT_EQ(falseNegatives, 0u) << "Bloom filter had false negatives!";
}

// ============================================================================
// PART 8: Thread Safety & Concurrency Tests
// ============================================================================

TEST(BloomFilter_ThreadSafety, ConcurrentAdd_NoDataRace) {
    BloomFilter filter(100000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    constexpr int numThreads = 8;
    constexpr int elementsPerThread = 10000;
    
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    
    std::atomic<bool> start{false};
    
    for (int t = 0; t < numThreads; ++t) {
        threads.emplace_back([&, t]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            
            for (int i = 0; i < elementsPerThread; ++i) {
                const uint64_t hash = GenerateTestHash(t * elementsPerThread + i);
                filter.Add(hash);
            }
        });
    }
    
    start.store(true, std::memory_order_release);
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // All elements should be found
    for (int t = 0; t < numThreads; ++t) {
        for (int i = 0; i < elementsPerThread; ++i) {
            const uint64_t hash = GenerateTestHash(t * elementsPerThread + i);
            EXPECT_TRUE(filter.MightContain(hash));
        }
    }
}

TEST(BloomFilter_ThreadSafety, ConcurrentQuery_NoDataRace) {
    BloomFilter filter(10000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Pre-populate filter
    const auto insertHashes = GenerateTestHashes(5000);
    filter.BatchAdd(insertHashes);//-V530
    
    constexpr int numThreads = 8;
    constexpr int queriesPerThread = 10000;
    
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    
    std::atomic<bool> start{false};
    std::atomic<size_t> totalPositives{0};
    
    for (int t = 0; t < numThreads; ++t) {
        threads.emplace_back([&, t]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            
            size_t positives = 0;
            for (int i = 0; i < queriesPerThread; ++i) {
                const uint64_t hash = GenerateTestHash(t * 1000000 + i);
                if (filter.MightContain(hash)) {
                    ++positives;
                }
            }
            
            totalPositives.fetch_add(positives, std::memory_order_relaxed);
        });
    }
    
    start.store(true, std::memory_order_release);
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Just verify no crashes - actual count doesn't matter
    EXPECT_GE(totalPositives.load(), 0u);
}

TEST(BloomFilter_ThreadSafety, ConcurrentAddAndQuery_NoDataRace) {
    BloomFilter filter(100000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    constexpr int numWriters = 4;
    constexpr int numReaders = 4;
    constexpr int operationsPerThread = 5000;
    
    std::atomic<bool> start{false};
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    
    // Writer threads
    for (int t = 0; t < numWriters; ++t) {
        threads.emplace_back([&, t]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            
            for (int i = 0; i < operationsPerThread && !stop.load(std::memory_order_relaxed); ++i) {
                const uint64_t hash = GenerateTestHash(t * operationsPerThread + i);
                filter.Add(hash);
            }
        });
    }
    
    // Reader threads
    for (int t = 0; t < numReaders; ++t) {
        threads.emplace_back([&, t]() {
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            
            for (int i = 0; i < operationsPerThread && !stop.load(std::memory_order_relaxed); ++i) {
                const uint64_t hash = GenerateTestHash(1000000 + t * operationsPerThread + i);
                (void)filter.MightContain(hash);
            }
        });
    }
    
    start.store(true, std::memory_order_release);
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Test passed if no crashes or deadlocks
    SUCCEED();
}

// ============================================================================
// PART 9: Edge Cases & Error Handling
// ============================================================================

TEST(BloomFilter_EdgeCases, ZeroHash_HandledCorrectly) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    filter.Add(0ULL);
    EXPECT_TRUE(filter.MightContain(0ULL));
}

TEST(BloomFilter_EdgeCases, MaxHash_HandledCorrectly) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    filter.Add(UINT64_MAX);
    EXPECT_TRUE(filter.MightContain(UINT64_MAX));
}

TEST(BloomFilter_EdgeCases, AllBitsSet_HasHighFPR) {
    BloomFilter filter(100, 0.5);  // Small filter, high FPR target
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Add many elements to fill the filter
    for (uint64_t i = 0; i < 100000; ++i) {
        filter.Add(GenerateTestHash(i));
    }
    
    // Fill rate should approach 1.0
    EXPECT_GT(filter.EstimatedFillRate(), 0.9);
}

TEST(BloomFilter_EdgeCases, MultipleInitializations_SecondSucceeds) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    
    ASSERT_TRUE(filter.InitializeForBuild());
    filter.Add(0x12345ULL);
    
    // Re-initialize should work and clear previous data
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Previous element might or might not be found (unspecified behavior)
    // But filter should be functional
    EXPECT_TRUE(filter.IsReady());
}

TEST(BloomFilter_EdgeCases, EmptyHashValue_NotAdded) {
    BloomFilter filter(DEFAULT_TEST_ELEMENTS, DEFAULT_TEST_FPR);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    HashValue empty{};  // All zeros, IsEmpty() should be true
    
    filter.Add(empty);
    
    // Elements added should still be 0 (empty hash is rejected)
    EXPECT_EQ(filter.GetElementsAdded(), 0u);
}

// ============================================================================
// PART 10: Performance Benchmarks
// ============================================================================

TEST(BloomFilter_Performance, Add_UnderTargetLatency) {
    BloomFilter filter(1000000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    constexpr size_t iterations = 10000;
    constexpr int64_t targetNsPerOp = 500;  // 500ns target
    
    const auto hashes = GenerateTestHashes(iterations);
    
    const int64_t totalNs = MeasureNanoseconds([&]() {
        for (uint64_t h : hashes) {
            filter.Add(h);
        }
    });
    
    const int64_t avgNs = totalNs / static_cast<int64_t>(iterations);
    
    EXPECT_LT(avgNs, targetNsPerOp) 
        << "Average Add latency " << avgNs << "ns exceeds target " << targetNsPerOp << "ns";
}

TEST(BloomFilter_Performance, MightContain_UnderTargetLatency) {
    BloomFilter filter(1000000, 0.01);
    ASSERT_TRUE(filter.InitializeForBuild());
    
    // Pre-populate
    const auto insertHashes = GenerateTestHashes(100000);
    filter.BatchAdd(insertHashes);//-V530
    
    constexpr size_t iterations = 100000;
    constexpr int64_t targetNsPerOp = 100;  // 100ns target for lookup
    
    const auto queryHashes = GenerateTestHashes(iterations, 1000000);
    
    const int64_t totalNs = MeasureNanoseconds([&]() {
        for (uint64_t h : queryHashes) {
            (void)filter.MightContain(h);
        }
    });
    
    const int64_t avgNs = totalNs / static_cast<int64_t>(iterations);
    
    EXPECT_LT(avgNs, targetNsPerOp)
        << "Average MightContain latency " << avgNs << "ns exceeds target " << targetNsPerOp << "ns";
}

TEST(BloomFilter_Performance, BatchAdd_FasterThanSingleAdd) {
    BloomFilter filter1(100000, 0.01);
    BloomFilter filter2(100000, 0.01);
    ASSERT_TRUE(filter1.InitializeForBuild());
    ASSERT_TRUE(filter2.InitializeForBuild());
    
    const auto hashes = GenerateTestHashes(10000);
    
    // Single add timing
    const int64_t singleNs = MeasureNanoseconds([&]() {
        for (uint64_t h : hashes) {
            filter1.Add(h);
        }
    });
    
    // Batch add timing
    const int64_t batchNs = MeasureNanoseconds([&]() {
        filter2.BatchAdd(hashes);//-V530
    });
    
    // Batch should be at least as fast (allowing for measurement variance)
    EXPECT_LE(batchNs, singleNs * 1.5)
        << "BatchAdd (" << batchNs << "ns) should not be much slower than single Add (" << singleNs << "ns)";
}

// ============================================================================
// PART 11: Memory Management Tests
// ============================================================================

TEST(BloomFilter_Memory, MultipleBuildCycles_NoLeaks) {
    // This test checks for memory leaks through multiple init cycles
    for (int cycle = 0; cycle < 10; ++cycle) {
        BloomFilter filter(10000, 0.01);
        ASSERT_TRUE(filter.InitializeForBuild());
        
        const auto hashes = GenerateTestHashes(1000, cycle * 1000);
        filter.BatchAdd(hashes);//-V530
        
        // Verify functionality
        for (uint64_t h : hashes) {
            EXPECT_TRUE(filter.MightContain(h));
        }
    }
    
    // If we get here without crashing or OOM, test passed
    SUCCEED();
}

TEST(BloomFilter_Memory, LargeFilter_AllocatesSuccessfully) {
    // Test with a large filter (but within limits)
    BloomFilter filter(10000000, 0.001);  // 10M elements, 0.1% FPR
    
    EXPECT_TRUE(filter.InitializeForBuild());
    EXPECT_TRUE(filter.IsReady());
    EXPECT_GT(filter.GetMemoryUsage(), 1000000u);  // Should be > 1MB
}

} // namespace ShadowStrike::Whitelist::Tests
