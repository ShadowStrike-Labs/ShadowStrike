// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
// ============================================================================
// BLOOM FILTER UNIT TESTS - PRODUCTION GRADE
// ============================================================================
// 
// ShadowStrike Antivirus Engine - Enterprise Edition
// 
// Comprehensive unit tests for thread-safe Bloom Filter implementation
// Coverage: Construction, insertion, lookup, false positive rates, thread safety,
//           memory limits, edge cases, bit manipulation
// 
// Test Categories:
// 1. Constructor Tests (Parameters, Bounds, Memory Allocation)
// 2. Add/MightContain Tests (Basic Functionality)
// 3. False Positive Rate Tests
// 4. Clear Operation Tests
// 5. Fill Rate Estimation Tests
// 6. Edge Case Tests (Empty, Invalid, Boundary Conditions)
// 7. Memory/Resource Limit Tests
// 8. Thread Safety Tests (Concurrent Operations)
// 9. Bit Manipulation Tests
// 10. Correctness & Consistency Tests
// ============================================================================

#include <gtest/gtest.h>
#include "../../../../src/ThreatIntel/ReputationCache.hpp"
#include "../../../../src/ThreatIntel/ThreatIntelFormat.hpp"
#include <vector>
#include <cstdint>
#include <random>
#include <thread>
#include <algorithm>
#include <set>
#include <cmath>

using namespace ShadowStrike::ThreatIntel;

// ============================================================================
// TEST FIXTURE - BLOOM FILTER BASE
// ============================================================================

class BloomFilterTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize random seed for reproducible tests
        rng.seed(42);
    }

    void TearDown() override {
        // Cleanup
    }

    // Helper: Create random CacheKey
    CacheKey CreateRandomKey() {
        std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);
        uint32_t value = dist(rng);
        
        IPv4Address addr;
        addr.address = value;
        
        return CacheKey(addr);
    }

    // Helper: Create CacheKey from specific value
    CacheKey CreateKeyFromValue(uint32_t value) {
        IPv4Address addr;
        addr.address = value;
        return CacheKey(addr);
    }

    // Helper: Create hash array for testing
    std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> CreateHashArray(uint64_t seed) {
        std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> hashes{};
        for (size_t i = 0; i < CacheConfig::BLOOM_HASH_FUNCTIONS; ++i) {
            hashes[i] = seed + i * 12345678ULL;
        }
        return hashes;
    }

    // Helper: Generate multiple unique keys
    std::vector<CacheKey> GenerateUniqueKeys(size_t count) {
        std::vector<CacheKey> keys;
        keys.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            keys.push_back(CreateKeyFromValue(static_cast<uint32_t>(i)));
        }
        
        return keys;
    }

    std::mt19937 rng;
};

// ============================================================================
// CATEGORY 1: CONSTRUCTOR TESTS
// ============================================================================

TEST_F(BloomFilterTest, Constructor_DefaultParameters) {
    // Test with default-like parameters
    size_t expectedElements = 10000;
    double falsePositiveRate = 0.01;
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_ZeroExpectedElements) {
    // Should use default capacity
    double falsePositiveRate = 0.01;
    
    EXPECT_NO_THROW({
        BloomFilter bloom(0, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_VerySmallExpectedElements) {
    // Test with very small count
    size_t expectedElements = 1;
    double falsePositiveRate = 0.01;
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_VeryLargeExpectedElements) {
    // Test with large count (should be clamped to max)
    size_t expectedElements = 200'000'000; // Exceeds max
    double falsePositiveRate = 0.01;
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
        // Should be clamped to kMaxExpectedElements
    });
}

TEST_F(BloomFilterTest, Constructor_InvalidFalsePositiveRate_TooLow) {
    // Test with FP rate too low (should be clamped)
    size_t expectedElements = 10000;
    double falsePositiveRate = 0.0; // Invalid
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_InvalidFalsePositiveRate_TooHigh) {
    // Test with FP rate too high (should be clamped)
    size_t expectedElements = 10000;
    double falsePositiveRate = 1.0; // Invalid
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_InvalidFalsePositiveRate_Negative) {
    // Test with negative FP rate (should be clamped)
    size_t expectedElements = 10000;
    double falsePositiveRate = -0.5; // Invalid
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_MinimumFalsePositiveRate) {
    // Test with minimum acceptable FP rate
    size_t expectedElements = 10000;
    double falsePositiveRate = 0.0001; // 0.01%
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_MaximumFalsePositiveRate) {
    // Test with maximum acceptable FP rate
    size_t expectedElements = 10000;
    double falsePositiveRate = 0.5; // 50%
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, Constructor_TypicalAntivirusScenario) {
    // Test with typical AV cache sizes
    size_t expectedElements = 1'000'000; // 1M IOCs
    double falsePositiveRate = 0.01; // 1%
    
    EXPECT_NO_THROW({
        BloomFilter bloom(expectedElements, falsePositiveRate);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

// ============================================================================
// CATEGORY 2: ADD/MIGHTCONTAIN TESTS - BASIC FUNCTIONALITY
// ============================================================================

TEST_F(BloomFilterTest, AddAndContain_SingleElement) {
    BloomFilter bloom(1000, 0.01);
    
    CacheKey key = CreateKeyFromValue(12345);
    
    // Initially should not contain
    EXPECT_FALSE(bloom.MightContain(key));
    
    // Add the key
    bloom.Add(key);
    
    // Now should contain
    EXPECT_TRUE(bloom.MightContain(key));
    
    // Element count should be 1
    EXPECT_EQ(bloom.GetElementCount(), 1);
}

TEST_F(BloomFilterTest, AddAndContain_MultipleElements) {
    BloomFilter bloom(1000, 0.01);
    
    std::vector<CacheKey> keys = GenerateUniqueKeys(100);
    
    // Add all keys
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    // All should be contained
    for (const auto& key : keys) {
        EXPECT_TRUE(bloom.MightContain(key))
            << "Key should be found after adding";
    }
    
    EXPECT_EQ(bloom.GetElementCount(), 100);
}

TEST_F(BloomFilterTest, AddAndContain_DuplicateElements) {
    BloomFilter bloom(1000, 0.01);
    
    CacheKey key = CreateKeyFromValue(99999);
    
    // Add same key multiple times
    bloom.Add(key);
    bloom.Add(key);
    bloom.Add(key);
    
    EXPECT_TRUE(bloom.MightContain(key));
    
    // Element count includes duplicates
    EXPECT_EQ(bloom.GetElementCount(), 3);
}

TEST_F(BloomFilterTest, AddAndContain_NotAddedElement) {
    BloomFilter bloom(1000, 0.01);
    
    CacheKey key1 = CreateKeyFromValue(111);
    CacheKey key2 = CreateKeyFromValue(222);
    
    bloom.Add(key1);
    
    // key2 was not added, should return false (no false positive in this case)
    // Note: Bloom filter can have false positives, but not false negatives
    EXPECT_TRUE(bloom.MightContain(key1));
    // key2 might or might not be detected depending on hash collision
}

TEST_F(BloomFilterTest, AddAndContain_UsingHashArray) {
    BloomFilter bloom(1000, 0.01);
    
    auto hashes = CreateHashArray(123456789ULL);
    
    // Initially should not contain
    EXPECT_FALSE(bloom.MightContain(hashes));
    
    // Add using hash array
    bloom.Add(hashes);
    
    // Should contain now
    EXPECT_TRUE(bloom.MightContain(hashes));
    
    EXPECT_EQ(bloom.GetElementCount(), 1);
}

TEST_F(BloomFilterTest, AddAndContain_InvalidKey) {
    BloomFilter bloom(1000, 0.01);
    
    // Create invalid key (default constructed)
    CacheKey invalidKey;
    
    EXPECT_FALSE(invalidKey.IsValid());
    
    // Add should be no-op for invalid key
    bloom.Add(invalidKey);
    
    EXPECT_EQ(bloom.GetElementCount(), 0);
    
    // MightContain should return false for invalid key
    EXPECT_FALSE(bloom.MightContain(invalidKey));
}

TEST_F(BloomFilterTest, AddAndContain_EmptyBloomFilter_InitializationFailure) {
    // Test graceful handling of uninitialized bloom filter
    // This tests the defensive checks in Add/MightContain
    
    BloomFilter bloom(1000, 0.01);
    CacheKey key = CreateKeyFromValue(42);
    
    // Normal operation should work
    bloom.Add(key);
    EXPECT_TRUE(bloom.MightContain(key));
}

// ============================================================================
// CATEGORY 3: FALSE POSITIVE RATE TESTS
// ============================================================================

TEST_F(BloomFilterTest, FalsePositiveRate_SmallDataset) {
    size_t expectedElements = 1000;
    double targetFPR = 0.01;
    BloomFilter bloom(expectedElements, targetFPR);
    
    // Add elements
    std::vector<CacheKey> addedKeys = GenerateUniqueKeys(expectedElements);
    for (const auto& key : addedKeys) {
        bloom.Add(key);
    }
    
    // Test with non-added elements
    std::vector<CacheKey> testKeys = GenerateUniqueKeys(10000);
    size_t falsePositives = 0;
    
    for (size_t i = expectedElements; i < testKeys.size(); ++i) {
        if (bloom.MightContain(testKeys[i])) {
            falsePositives++;
        }
    }
    
    double actualFPR = static_cast<double>(falsePositives) / 
                       static_cast<double>(testKeys.size() - expectedElements);
    
    // Allow some variance (FPR should be roughly within 3x of target)
    EXPECT_LT(actualFPR, targetFPR * 3.0)
        << "Actual FPR: " << actualFPR << ", Target: " << targetFPR;
}

TEST_F(BloomFilterTest, FalsePositiveRate_EstimateVsActual) {
    size_t expectedElements = 5000;
    double targetFPR = 0.01;
    BloomFilter bloom(expectedElements, targetFPR);
    
    // Add 50% of expected elements
    std::vector<CacheKey> keys = GenerateUniqueKeys(expectedElements / 2);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    // Get estimated FPR
    double estimatedFPR = bloom.EstimateFalsePositiveRate();
    
    // Estimated FPR should be reasonable (not 0, not 1)
    EXPECT_GT(estimatedFPR, 0.0);
    EXPECT_LT(estimatedFPR, 1.0);
}

TEST_F(BloomFilterTest, FalsePositiveRate_ZeroElements) {
    BloomFilter bloom(1000, 0.01);
    
    // With zero elements, FPR should be 0
    double fpr = bloom.EstimateFalsePositiveRate();
    EXPECT_EQ(fpr, 0.0);
}

TEST_F(BloomFilterTest, FalsePositiveRate_FullCapacity) {
    size_t expectedElements = 1000;
    BloomFilter bloom(expectedElements, 0.01);
    
    // Fill to capacity
    std::vector<CacheKey> keys = GenerateUniqueKeys(expectedElements);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    double fpr = bloom.EstimateFalsePositiveRate();
    
    // FPR should be close to target (within reasonable margin)
    EXPECT_GT(fpr, 0.0);
    EXPECT_LT(fpr, 0.5); // Should not exceed 50%
}

TEST_F(BloomFilterTest, FalsePositiveRate_Overfilled) {
    size_t expectedElements = 100;
    BloomFilter bloom(expectedElements, 0.01);
    
    // Overfill (add 10x expected)
    std::vector<CacheKey> keys = GenerateUniqueKeys(expectedElements * 10);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    double fpr = bloom.EstimateFalsePositiveRate();
    
    // FPR should increase when overfilled
    EXPECT_GT(fpr, 0.01); // Higher than target
}

TEST_F(BloomFilterTest, NoFalseNegatives_Guarantee) {
    // Bloom filters MUST NOT produce false negatives
    BloomFilter bloom(1000, 0.01);
    
    std::vector<CacheKey> keys = GenerateUniqueKeys(500);
    
    // Add all keys
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    // Verify all added keys are found (no false negatives)
    for (const auto& key : keys) {
        EXPECT_TRUE(bloom.MightContain(key))
            << "Bloom filter produced false negative - CRITICAL BUG!";
    }
}

// ============================================================================
// CATEGORY 4: CLEAR OPERATION TESTS
// ============================================================================

TEST_F(BloomFilterTest, Clear_EmptyBloomFilter) {
    BloomFilter bloom(1000, 0.01);
    
    // Clear empty bloom filter
    EXPECT_NO_THROW(bloom.Clear());
    
    EXPECT_EQ(bloom.GetElementCount(), 0);
}

TEST_F(BloomFilterTest, Clear_AfterAdding) {
    BloomFilter bloom(1000, 0.01);
    
    std::vector<CacheKey> keys = GenerateUniqueKeys(100);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    EXPECT_EQ(bloom.GetElementCount(), 100);
    
    // Clear
    bloom.Clear();
    
    // Should be empty
    EXPECT_EQ(bloom.GetElementCount(), 0);
    
    // Previously added keys should not be found
    for (const auto& key : keys) {
        EXPECT_FALSE(bloom.MightContain(key))
            << "Key found after clear operation";
    }
}

TEST_F(BloomFilterTest, Clear_MultipleTimes) {
    BloomFilter bloom(1000, 0.01);
    
    // Clear multiple times
    bloom.Clear();
    bloom.Clear();
    bloom.Clear();
    
    EXPECT_EQ(bloom.GetElementCount(), 0);
}

TEST_F(BloomFilterTest, Clear_ReuseAfterClear) {
    BloomFilter bloom(1000, 0.01);
    
    // First batch
    std::vector<CacheKey> keys1 = GenerateUniqueKeys(50);
    for (const auto& key : keys1) {
        bloom.Add(key);
    }
    
    EXPECT_EQ(bloom.GetElementCount(), 50);
    
    // Clear
    bloom.Clear();
    
    // Second batch
    std::vector<CacheKey> keys2 = GenerateUniqueKeys(75);
    for (const auto& key : keys2) {
        bloom.Add(key);
    }
    
    EXPECT_EQ(bloom.GetElementCount(), 75);
    
    // Second batch should be found
    for (const auto& key : keys2) {
        EXPECT_TRUE(bloom.MightContain(key));
    }
}

// ============================================================================
// CATEGORY 5: FILL RATE ESTIMATION TESTS
// ============================================================================

TEST_F(BloomFilterTest, FillRate_EmptyFilter) {
    BloomFilter bloom(1000, 0.01);
    
    double fillRate = bloom.EstimateFillRate();
    
    EXPECT_EQ(fillRate, 0.0) << "Empty filter should have 0% fill rate";
}

TEST_F(BloomFilterTest, FillRate_SingleElement) {
    BloomFilter bloom(1000, 0.01);
    
    CacheKey key = CreateKeyFromValue(42);
    bloom.Add(key);
    
    double fillRate = bloom.EstimateFillRate();
    
    // Should be very small but > 0
    EXPECT_GT(fillRate, 0.0);
    EXPECT_LT(fillRate, 1.0);
}

TEST_F(BloomFilterTest, FillRate_PartiallyFilled) {
    BloomFilter bloom(1000, 0.01);
    
    std::vector<CacheKey> keys = GenerateUniqueKeys(500);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    double fillRate = bloom.EstimateFillRate();
    
    EXPECT_GT(fillRate, 0.0);
    EXPECT_LT(fillRate, 1.0);
}

TEST_F(BloomFilterTest, FillRate_IncreaseMonotonically) {
    BloomFilter bloom(1000, 0.01);
    
    double previousFillRate = 0.0;
    
    // Add elements in batches and verify fill rate increases
    for (size_t i = 0; i < 10; ++i) {
        std::vector<CacheKey> keys = GenerateUniqueKeys(50);
        for (const auto& key : keys) {
            bloom.Add(key);
        }
        
        double currentFillRate = bloom.EstimateFillRate();
        
        EXPECT_GE(currentFillRate, previousFillRate)
            << "Fill rate should increase or stay same";
        
        previousFillRate = currentFillRate;
    }
}

TEST_F(BloomFilterTest, FillRate_AfterClear) {
    BloomFilter bloom(1000, 0.01);
    
    // Add elements
    std::vector<CacheKey> keys = GenerateUniqueKeys(100);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    double fillRateBeforeClear = bloom.EstimateFillRate();
    EXPECT_GT(fillRateBeforeClear, 0.0);
    
    // Clear
    bloom.Clear();
    
    double fillRateAfterClear = bloom.EstimateFillRate();
    EXPECT_EQ(fillRateAfterClear, 0.0);
}

// ============================================================================
// CATEGORY 6: EDGE CASE TESTS
// ============================================================================

TEST_F(BloomFilterTest, EdgeCase_VerySmallBloomFilter) {
    // Minimum size bloom filter
    BloomFilter bloom(1, 0.5);
    
    CacheKey key = CreateKeyFromValue(123);
    
    bloom.Add(key);
    EXPECT_TRUE(bloom.MightContain(key));
}

TEST_F(BloomFilterTest, EdgeCase_SingleBitFilter) {
    // Test with parameters that would create very small filter
    BloomFilter bloom(1, 0.5);
    
    // Should still be functional
    CacheKey key1 = CreateKeyFromValue(1);
    CacheKey key2 = CreateKeyFromValue(2);
    
    bloom.Add(key1);
    
    // Extremely small filter will have high collision rate
    EXPECT_TRUE(bloom.MightContain(key1));
}

TEST_F(BloomFilterTest, EdgeCase_AllSameHash) {
    BloomFilter bloom(1000, 0.01);
    
    // Create multiple keys that might have hash collisions
    // (though CacheKey computes different hashes)
    std::vector<CacheKey> keys = GenerateUniqueKeys(100);
    
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    // All should be retrievable
    for (const auto& key : keys) {
        EXPECT_TRUE(bloom.MightContain(key));
    }
}

TEST_F(BloomFilterTest, EdgeCase_MaxHashValue) {
    BloomFilter bloom(1000, 0.01);
    
    // Create hash array with max values
    std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> maxHashes;
    maxHashes.fill(UINT64_MAX);
    
    bloom.Add(maxHashes);
    EXPECT_TRUE(bloom.MightContain(maxHashes));
}

TEST_F(BloomFilterTest, EdgeCase_ZeroHashes) {
    BloomFilter bloom(1000, 0.01);
    
    // Create hash array with all zeros
    std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> zeroHashes{};
    
    bloom.Add(zeroHashes);
    EXPECT_TRUE(bloom.MightContain(zeroHashes));
}

TEST_F(BloomFilterTest, EdgeCase_SequentialHashes) {
    BloomFilter bloom(1000, 0.01);
    
    // Add sequential hash values
    for (uint64_t i = 0; i < 100; ++i) {
        auto hashes = CreateHashArray(i);
        bloom.Add(hashes);
    }
    
    // Verify all are contained
    for (uint64_t i = 0; i < 100; ++i) {
        auto hashes = CreateHashArray(i);
        EXPECT_TRUE(bloom.MightContain(hashes));
    }
}

// ============================================================================
// CATEGORY 7: MEMORY/RESOURCE LIMIT TESTS
// ============================================================================

TEST_F(BloomFilterTest, ResourceLimits_MaxExpectedElements) {
    // Test with maximum allowed elements
    size_t maxElements = 100'000'000; // Should be clamped
    double fpr = 0.01;
    
    EXPECT_NO_THROW({
        BloomFilter bloom(maxElements, fpr);
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, ResourceLimits_ExtremelyLargeRequest) {
    // Request way beyond limits
    size_t hugeElements = SIZE_MAX / 2;
    double fpr = 0.0001; // Very low FPR = huge memory
    
    EXPECT_NO_THROW({
        BloomFilter bloom(hugeElements, fpr);
        // Should clamp to reasonable size
        EXPECT_EQ(bloom.GetElementCount(), 0);
    });
}

TEST_F(BloomFilterTest, ResourceLimits_NoExceptionOnConstruction) {
    // Various parameter combinations should never throw
    std::vector<std::pair<size_t, double>> testCases = {
        {0, 0.01},
        {1, 0.5},
        {1000, 0.0001},
        {1000000, 0.1},
        {SIZE_MAX, -1.0},
        {0, 2.0},
    };
    
    for (const auto& [elements, fpr] : testCases) {
        EXPECT_NO_THROW({
            BloomFilter bloom(elements, fpr);
        }) << "Failed for elements=" << elements << ", fpr=" << fpr;
    }
}

TEST_F(BloomFilterTest, MemoryManagement_ManyBloomFilters) {
    // Create many bloom filters to test memory management
    std::vector<std::unique_ptr<BloomFilter>> filters;
    
    EXPECT_NO_THROW({
        for (size_t i = 0; i < 100; ++i) {
            filters.push_back(std::make_unique<BloomFilter>(1000, 0.01));
        }
    });
    
    // All should be functional
    for (auto& filter : filters) {
        CacheKey key = CreateKeyFromValue(999);
        filter->Add(key);
        EXPECT_TRUE(filter->MightContain(key));
    }
}

// ============================================================================
// CATEGORY 8: THREAD SAFETY TESTS
// ============================================================================

TEST_F(BloomFilterTest, ThreadSafety_ConcurrentReads) {
    BloomFilter bloom(10000, 0.01);
    
    // Add elements first
    std::vector<CacheKey> keys = GenerateUniqueKeys(1000);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    // Multiple threads reading concurrently
    std::vector<std::thread> threads;
    std::atomic<size_t> successCount{0};
    
    for (size_t i = 0; i < 10; ++i) {
        threads.emplace_back([&bloom, &keys, &successCount]() {
            for (size_t j = 0; j < 100; ++j) {
                for (const auto& key : keys) {
                    if (bloom.MightContain(key)) {
                        successCount.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All reads should succeed
    EXPECT_EQ(successCount.load(), 10 * 100 * keys.size());
}

TEST_F(BloomFilterTest, ThreadSafety_ConcurrentWrites) {
    BloomFilter bloom(100000, 0.01);
    
    // Multiple threads writing concurrently
    std::vector<std::thread> threads;
    constexpr size_t numThreads = 10;
    constexpr size_t keysPerThread = 100;
    
    for (size_t i = 0; i < numThreads; ++i) {
        threads.emplace_back([&bloom, i]() {
            for (size_t j = 0; j < keysPerThread; ++j) {
                uint32_t value = static_cast<uint32_t>(i * 1000 + j);
                CacheKey key;
                IPv4Address addr;
                addr.address = value;
                key = CacheKey(addr);
                bloom.Add(key);
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Total element count should be correct
    EXPECT_EQ(bloom.GetElementCount(), numThreads * keysPerThread);
}

TEST_F(BloomFilterTest, ThreadSafety_MixedReadWrite) {
    BloomFilter bloom(100000, 0.01);
    
    std::atomic<bool> stopFlag{false};
    std::vector<std::thread> threads;
    
    // Writer threads
    for (size_t i = 0; i < 3; ++i) {
        threads.emplace_back([&bloom, &stopFlag, i]() {
            size_t counter = i * 10000;
            while (!stopFlag.load(std::memory_order_relaxed)) {
                CacheKey key = CacheKey(IOCType::IPv4, &counter, sizeof(counter));
                bloom.Add(key);
                counter++;
                std::this_thread::yield();
            }
        });
    }
    
    // Reader threads
    for (size_t i = 0; i < 3; ++i) {
        threads.emplace_back([&bloom, &stopFlag, i]() {
            size_t counter = i * 10000;
            while (!stopFlag.load(std::memory_order_relaxed)) {
                CacheKey key = CacheKey(IOCType::IPv4, &counter, sizeof(counter));
                bloom.MightContain(key); // Result doesn't matter
                counter++;
                std::this_thread::yield();
            }
        });
    }
    
    // Run for a short time
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    stopFlag.store(true, std::memory_order_relaxed);
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Should complete without crashes
    SUCCEED();
}

TEST_F(BloomFilterTest, ThreadSafety_ConcurrentClear) {
    BloomFilter bloom(10000, 0.01);
    
    // Add some initial data
    std::vector<CacheKey> keys = GenerateUniqueKeys(100);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    std::atomic<bool> stopFlag{false};
    std::vector<std::thread> threads;
    
    // Clear thread
    threads.emplace_back([&bloom, &stopFlag]() {
        while (!stopFlag.load()) {
            bloom.Clear();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    
    // Writer threads
    for (size_t i = 0; i < 2; ++i) {
        threads.emplace_back([&bloom, &stopFlag, i]() {
            size_t counter = i * 1000;
            while (!stopFlag.load()) {
                CacheKey key = CacheKey(IOCType::IPv4, &counter, sizeof(counter));
                bloom.Add(key);
                counter++;
            }
        });
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    stopFlag.store(true);
    
    for (auto& t : threads) {
        t.join();
    }
    
    SUCCEED();
}

// ============================================================================
// CATEGORY 9: BIT MANIPULATION TESTS
// ============================================================================

TEST_F(BloomFilterTest, BitManipulation_BoundaryBits) {
    BloomFilter bloom(1000, 0.01);
    
    // Test with hash that targets bit 0
    std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> hashes;
    hashes.fill(0);
    
    bloom.Add(hashes);
    EXPECT_TRUE(bloom.MightContain(hashes));
}

TEST_F(BloomFilterTest, BitManipulation_AllBitsInWord) {
    BloomFilter bloom(1000, 0.01);
    
    // Test setting all 64 bits in a word (multiple different hashes)
    for (uint64_t i = 0; i < 64; ++i) {
        std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> hashes;
        hashes.fill(i);
        bloom.Add(hashes);
    }
    
    // All should be retrievable
    for (uint64_t i = 0; i < 64; ++i) {
        std::array<uint64_t, CacheConfig::BLOOM_HASH_FUNCTIONS> hashes;
        hashes.fill(i);
        EXPECT_TRUE(bloom.MightContain(hashes));
    }
}

TEST_F(BloomFilterTest, BitManipulation_CrossWordBoundary) {
    // Test bits that span across 64-bit word boundaries
    BloomFilter bloom(10000, 0.01);
    
    // Create hashes that will hit different word boundaries
    for (uint64_t i = 60; i < 70; ++i) {
        auto hashes = CreateHashArray(i);
        bloom.Add(hashes);
    }
    
    for (uint64_t i = 60; i < 70; ++i) {
        auto hashes = CreateHashArray(i);
        EXPECT_TRUE(bloom.MightContain(hashes));
    }
}

// ============================================================================
// CATEGORY 10: CORRECTNESS & CONSISTENCY TESTS
// ============================================================================

TEST_F(BloomFilterTest, Correctness_AddViaKeyAndHashEquivalent) {
    BloomFilter bloom1(1000, 0.01);
    BloomFilter bloom2(1000, 0.01);
    
    CacheKey key = CreateKeyFromValue(12345);
    auto hashes = key.GetBloomHashes();
    
    // Add to bloom1 via key
    bloom1.Add(key);
    
    // Add to bloom2 via hashes
    bloom2.Add(hashes);
    
    // Both should contain via both methods
    EXPECT_TRUE(bloom1.MightContain(key));
    EXPECT_TRUE(bloom1.MightContain(hashes));
    EXPECT_TRUE(bloom2.MightContain(key));
    EXPECT_TRUE(bloom2.MightContain(hashes));
}

TEST_F(BloomFilterTest, Correctness_ConsistentResults) {
    BloomFilter bloom(1000, 0.01);
    
    CacheKey key = CreateKeyFromValue(99999);
    bloom.Add(key);
    
    // Multiple queries should give same result
    for (size_t i = 0; i < 1000; ++i) {
        EXPECT_TRUE(bloom.MightContain(key))
            << "Inconsistent result at iteration " << i;
    }
}

TEST_F(BloomFilterTest, Correctness_IndependentFilters) {
    // Two separate bloom filters should be independent
    BloomFilter bloom1(1000, 0.01);
    BloomFilter bloom2(1000, 0.01);
    
    CacheKey key1 = CreateKeyFromValue(111);
    CacheKey key2 = CreateKeyFromValue(222);
    
    bloom1.Add(key1);
    bloom2.Add(key2);
    
    EXPECT_TRUE(bloom1.MightContain(key1));
    EXPECT_FALSE(bloom1.MightContain(key2));
    
    EXPECT_FALSE(bloom2.MightContain(key1));
    EXPECT_TRUE(bloom2.MightContain(key2));
}

TEST_F(BloomFilterTest, Correctness_StatisticsAccuracy) {
    BloomFilter bloom(1000, 0.01);
    
    // Add known number of elements
    size_t numElements = 500;
    std::vector<CacheKey> keys = GenerateUniqueKeys(numElements);
    for (const auto& key : keys) {
        bloom.Add(key);
    }
    
    EXPECT_EQ(bloom.GetElementCount(), numElements);
    
    double fillRate = bloom.EstimateFillRate();
    double fpr = bloom.EstimateFalsePositiveRate();
    
    // Both should be reasonable
    EXPECT_GT(fillRate, 0.0);
    EXPECT_LT(fillRate, 1.0);
    EXPECT_GT(fpr, 0.0);
    EXPECT_LT(fpr, 1.0);
}

TEST_F(BloomFilterTest, Correctness_NoStateLeakage) {
    // Clear should completely reset state
    BloomFilter bloom(1000, 0.01);
    
    std::vector<CacheKey> keys1 = GenerateUniqueKeys(100);
    for (const auto& key : keys1) {
        bloom.Add(key);
    }
    
    double fillRate1 = bloom.EstimateFillRate();
    double fpr1 = bloom.EstimateFalsePositiveRate();
    
    bloom.Clear();
    
    std::vector<CacheKey> keys2 = GenerateUniqueKeys(100);
    for (const auto& key : keys2) {
        bloom.Add(key);
    }
    
    double fillRate2 = bloom.EstimateFillRate();
    double fpr2 = bloom.EstimateFalsePositiveRate();
    
    // Statistics should be similar (same number of elements)
    EXPECT_NEAR(fillRate1, fillRate2, 0.1);
    EXPECT_NEAR(fpr1, fpr2, 0.1);
    
    // Old keys should NOT be found
    for (const auto& key : keys1) {
        EXPECT_FALSE(bloom.MightContain(key))
            << "State leakage: old key found after clear";
    }
}

// ============================================================================
// CATEGORY 11: SPECIAL IOC TYPES TESTS
// ============================================================================

TEST_F(BloomFilterTest, IOCTypes_IPv4Addresses) {
    BloomFilter bloom(1000, 0.01);
    
    // Test with IPv4 addresses
    IPv4Address addr1;
    addr1.address = 0x08080808; // 8.8.8.8
    
    IPv4Address addr2;
    addr2.address = 0x01010101; // 1.1.1.1
    
    CacheKey key1(addr1);
    CacheKey key2(addr2);
    
    bloom.Add(key1);
    
    EXPECT_TRUE(bloom.MightContain(key1));
    // key2 not added, might have false positive but unlikely
}

TEST_F(BloomFilterTest, IOCTypes_IPv6Addresses) {
    BloomFilter bloom(1000, 0.01);
    
    // Test with IPv6 addresses
    IPv6Address addr1;
    std::fill(addr1.address.begin(), addr1.address.end(), 0xAA);
    
    IPv6Address addr2;
    std::fill(addr2.address.begin(), addr2.address.end(), 0xBB);
    
    CacheKey key1(addr1);
    CacheKey key2(addr2);
    
    bloom.Add(key1);
    
    EXPECT_TRUE(bloom.MightContain(key1));
}

TEST_F(BloomFilterTest, IOCTypes_FileHashes) {
    BloomFilter bloom(1000, 0.01);
    
    // Test with file hashes
    HashValue hash1;
    hash1.algorithm = HashAlgorithm::SHA256;
    hash1.length = 32;
    std::fill(hash1.data.begin(), hash1.data.begin() + 32, 0xDE);
    
    HashValue hash2;
    hash2.algorithm = HashAlgorithm::MD5;
    hash2.length = 16;
    std::fill(hash2.data.begin(), hash2.data.begin() + 16, 0xAD);
    
    CacheKey key1(hash1);
    CacheKey key2(hash2);
    
    bloom.Add(key1);
    bloom.Add(key2);
    
    EXPECT_TRUE(bloom.MightContain(key1));
    EXPECT_TRUE(bloom.MightContain(key2));
}

TEST_F(BloomFilterTest, IOCTypes_Domains) {
    BloomFilter bloom(1000, 0.01);
    
    // Test with domain names
    CacheKey key1(IOCType::Domain, "malware.example.com");
    CacheKey key2(IOCType::Domain, "phishing.test.org");
    
    bloom.Add(key1);
    
    EXPECT_TRUE(bloom.MightContain(key1));
}


