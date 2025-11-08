/*
 * ============================================================================
 * ShadowStrike CompressionUtils Unit Tests
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Comprehensive test suite for CompressionUtils functionality
 * Tests cover: API availability, algorithm support, buffer operations,
 *              RAII wrappers, edge cases, security limits, error handling
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include "../../../src/Utils/CompressionUtils.hpp"

#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>
#include <iostream>

using namespace ShadowStrike::Utils::CompressionUtils;

// ============================================================================
// Test Fixture
// ============================================================================

class CompressionUtilsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Check if compression API is available on this system
        apiAvailable = IsCompressionApiAvailable();
        
        if (!apiAvailable) {
            GTEST_SKIP() << "Windows Compression API not available on this system";
        }
    }

    // Helper: Generate random binary data
    std::vector<uint8_t> GenerateRandomData(size_t size) {
        static std::mt19937_64 rng(std::random_device{}());
        static std::uniform_int_distribution<int> dist(0, 255);
        
        std::vector<uint8_t> data(size);
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(dist(rng));
        }
        return data;
    }

    // Helper: Generate compressible data (repetitive pattern)
    std::vector<uint8_t> GenerateCompressibleData(size_t size) {
        std::vector<uint8_t> data(size);
        const char pattern[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        const size_t patternLen = strlen(pattern);
        
        for (size_t i = 0; i < size; ++i) {
            data[i] = static_cast<uint8_t>(pattern[i % patternLen]);
        }
        return data;
    }

    // Helper: Verify compressed data is different from original
    bool IsDifferent(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return true;
        return !std::equal(a.begin(), a.end(), b.begin());
    }

    bool apiAvailable = false;
};

// ============================================================================
// API Availability Tests
// ============================================================================

TEST_F(CompressionUtilsTest, ApiAvailability_CheckAvailable) {
    // Should return true on Windows 8+ systems
    bool available = IsCompressionApiAvailable();
    EXPECT_TRUE(available) << "Compression API should be available on Windows 8+";
}

TEST_F(CompressionUtilsTest, ApiAvailability_MultipleCallsConsistent) {
    bool first = IsCompressionApiAvailable();
    bool second = IsCompressionApiAvailable();
    bool third = IsCompressionApiAvailable();
    
    EXPECT_EQ(first, second);
    EXPECT_EQ(second, third);
}

// ============================================================================
// Algorithm Support Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Algorithm_MszipSupported) {
    EXPECT_TRUE(IsAlgorithmSupported(Algorithm::Mszip));
}

TEST_F(CompressionUtilsTest, Algorithm_XpressSupported) {
    EXPECT_TRUE(IsAlgorithmSupported(Algorithm::Xpress));
}

TEST_F(CompressionUtilsTest, Algorithm_XpressHuffSupported) {
    EXPECT_TRUE(IsAlgorithmSupported(Algorithm::XpressHuff));
}

TEST_F(CompressionUtilsTest, Algorithm_LzmsSupported) {
    EXPECT_TRUE(IsAlgorithmSupported(Algorithm::Lzms));
}

TEST_F(CompressionUtilsTest, Algorithm_InvalidAlgorithm) {
    Algorithm invalid = static_cast<Algorithm>(0xFFFF);
    EXPECT_FALSE(IsAlgorithmSupported(invalid));
}

// ============================================================================
// Basic Compression/Decompression Tests - Xpress
// ============================================================================

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_SimpleString) {
    std::string original = "Hello, ShadowStrike! This is a test string.";
    std::vector<uint8_t> input(original.begin(), original.end());
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    EXPECT_GT(compressed.size(), 0u);
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input.size(), decompressed.size());
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_EmptyData) {
    std::vector<uint8_t> empty;
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, empty.data(), empty.size(), compressed));
    EXPECT_EQ(compressed.size(), 0u);
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    EXPECT_EQ(decompressed.size(), 0u);
}

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_SingleByte) {
    std::vector<uint8_t> input = {0x42};
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_CompressibleData) {
    auto input = GenerateCompressibleData(4096);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    // Compressible data should compress well
    EXPECT_LT(compressed.size(), input.size());
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_RandomData) {
    auto input = GenerateRandomData(1024);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    EXPECT_GT(compressed.size(), 0u);
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, Xpress_CompressDecompress_LargeData) {
    // ? FIXED: Restored to 1MB - buffer calculation now handles this correctly
    auto input = GenerateCompressibleData(1024 * 1024); // 1MB compressible data
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed))
        << "Compression failed for 1MB data";
    
    // Compressible data should compress well
    EXPECT_LT(compressed.size(), input.size()) 
        << "Compressed size should be smaller than input";
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed))
        << "Decompression failed for 1MB data";
    
    EXPECT_EQ(input, decompressed) << "Data mismatch after round-trip";
}

TEST_F(CompressionUtilsTest, Xpress_Decompress_WithExpectedSize) {
    std::string original = "Test data with known size";
    std::vector<uint8_t> input(original.begin(), original.end());
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), 
                                  decompressed, input.size()));
    
    EXPECT_EQ(input, decompressed);
}

// ============================================================================
// Algorithm Comparison Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Algorithms_AllAlgorithmsWorkCorrectly) {
    auto input = GenerateCompressibleData(4096);
    
    Algorithm algorithms[] = {
        Algorithm::Mszip,
        Algorithm::Xpress,
        Algorithm::XpressHuff,
        Algorithm::Lzms
    };
    
    for (auto alg : algorithms) {
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(alg, input.data(), input.size(), compressed))
            << "Compression failed for algorithm " << static_cast<int>(alg);
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(DecompressBuffer(alg, compressed.data(), compressed.size(), decompressed))
            << "Decompression failed for algorithm " << static_cast<int>(alg);
        
        EXPECT_EQ(input, decompressed)
            << "Round-trip failed for algorithm " << static_cast<int>(alg);
    }
}

// ============================================================================
// RAII Compressor Class Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Compressor_OpenClose) {
    Compressor comp;
    EXPECT_FALSE(comp.valid());
    
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    EXPECT_TRUE(comp.valid());
    EXPECT_EQ(comp.algorithm(), Algorithm::Xpress);
    
    comp.close();
    EXPECT_FALSE(comp.valid());
}

TEST_F(CompressionUtilsTest, Compressor_MultipleClose) {
    Compressor comp;
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    
    comp.close();
    EXPECT_NO_THROW(comp.close());
    EXPECT_NO_THROW(comp.close());
}

TEST_F(CompressionUtilsTest, Compressor_ReopenDifferentAlgorithm) {
    Compressor comp;
    
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    EXPECT_EQ(comp.algorithm(), Algorithm::Xpress);
    
    ASSERT_TRUE(comp.open(Algorithm::Mszip));
    EXPECT_EQ(comp.algorithm(), Algorithm::Mszip);
}

TEST_F(CompressionUtilsTest, Compressor_CompressWithoutOpen) {
    Compressor comp;
    std::vector<uint8_t> input = {1, 2, 3};
    std::vector<uint8_t> output;
    
    EXPECT_FALSE(comp.compress(input.data(), input.size(), output));
}

TEST_F(CompressionUtilsTest, Compressor_BasicCompression) {
    Compressor comp;
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    
    std::string data = "Test data for RAII compressor";
    std::vector<uint8_t> input(data.begin(), data.end());
    std::vector<uint8_t> output;
    
    ASSERT_TRUE(comp.compress(input.data(), input.size(), output));
    EXPECT_GT(output.size(), 0u);
}

TEST_F(CompressionUtilsTest, Compressor_MoveConstructor) {
    Compressor comp1;
    ASSERT_TRUE(comp1.open(Algorithm::Xpress));
    EXPECT_TRUE(comp1.valid());
    
    Compressor comp2(std::move(comp1));
    EXPECT_FALSE(comp1.valid());
    EXPECT_TRUE(comp2.valid());
    EXPECT_EQ(comp2.algorithm(), Algorithm::Xpress);
}

TEST_F(CompressionUtilsTest, Compressor_MoveAssignment) {
    Compressor comp1;
    ASSERT_TRUE(comp1.open(Algorithm::Xpress));
    
    Compressor comp2;
    ASSERT_TRUE(comp2.open(Algorithm::Mszip));
    
    comp2 = std::move(comp1);
    EXPECT_FALSE(comp1.valid());
    EXPECT_TRUE(comp2.valid());
    EXPECT_EQ(comp2.algorithm(), Algorithm::Xpress);
}

TEST_F(CompressionUtilsTest, Compressor_MultipleCompressions) {
    Compressor comp;
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    
    for (int i = 0; i < 10; ++i) {
        auto input = GenerateCompressibleData(1024);
        std::vector<uint8_t> output;
        
        ASSERT_TRUE(comp.compress(input.data(), input.size(), output))
            << "Compression " << i << " failed";
        EXPECT_GT(output.size(), 0u);
    }
}

// ============================================================================
// RAII Decompressor Class Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Decompressor_OpenClose) {
    Decompressor decomp;
    EXPECT_FALSE(decomp.valid());
    
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    EXPECT_TRUE(decomp.valid());
    EXPECT_EQ(decomp.algorithm(), Algorithm::Xpress);
    
    decomp.close();
    EXPECT_FALSE(decomp.valid());
}

TEST_F(CompressionUtilsTest, Decompressor_MultipleClose) {
    Decompressor decomp;
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    
    decomp.close();
    EXPECT_NO_THROW(decomp.close());
    EXPECT_NO_THROW(decomp.close());
}

TEST_F(CompressionUtilsTest, Decompressor_ReopenDifferentAlgorithm) {
    Decompressor decomp;
    
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    EXPECT_EQ(decomp.algorithm(), Algorithm::Xpress);
    
    ASSERT_TRUE(decomp.open(Algorithm::Mszip));
    EXPECT_EQ(decomp.algorithm(), Algorithm::Mszip);
}

TEST_F(CompressionUtilsTest, Decompressor_DecompressWithoutOpen) {
    Decompressor decomp;
    std::vector<uint8_t> input = {1, 2, 3};
    std::vector<uint8_t> output;
    
    EXPECT_FALSE(decomp.decompress(input.data(), input.size(), output));
}

TEST_F(CompressionUtilsTest, Decompressor_BasicDecompression) {
    std::string original = "Test data for RAII decompressor";
    std::vector<uint8_t> input(original.begin(), original.end());
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    Decompressor decomp;
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    
    std::vector<uint8_t> output;
    ASSERT_TRUE(decomp.decompress(compressed.data(), compressed.size(), output));
    EXPECT_EQ(input, output);
}

TEST_F(CompressionUtilsTest, Decompressor_MoveConstructor) {
    Decompressor decomp1;
    ASSERT_TRUE(decomp1.open(Algorithm::Xpress));
    EXPECT_TRUE(decomp1.valid());
    
    Decompressor decomp2(std::move(decomp1));
    EXPECT_FALSE(decomp1.valid());
    EXPECT_TRUE(decomp2.valid());
    EXPECT_EQ(decomp2.algorithm(), Algorithm::Xpress);
}

TEST_F(CompressionUtilsTest, Decompressor_MoveAssignment) {
    Decompressor decomp1;
    ASSERT_TRUE(decomp1.open(Algorithm::Xpress));
    
    Decompressor decomp2;
    ASSERT_TRUE(decomp2.open(Algorithm::Mszip));
    
    decomp2 = std::move(decomp1);
    EXPECT_FALSE(decomp1.valid());
    EXPECT_TRUE(decomp2.valid());
    EXPECT_EQ(decomp2.algorithm(), Algorithm::Xpress);
}

TEST_F(CompressionUtilsTest, Decompressor_MultipleDecompressions) {
    Decompressor decomp;
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    
    for (int i = 0; i < 10; ++i) {
        auto original = GenerateCompressibleData(1024);
        
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, original.data(), original.size(), compressed));
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(decomp.decompress(compressed.data(), compressed.size(), decompressed))
            << "Decompression " << i << " failed";
        
        EXPECT_EQ(original, decompressed);
    }
}

// ============================================================================
// Combined RAII Workflow Tests
// ============================================================================

TEST_F(CompressionUtilsTest, RAII_CompressorDecompressorWorkflow) {
    Compressor comp;
    Decompressor decomp;
    
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    ASSERT_TRUE(decomp.open(Algorithm::Xpress));
    
    auto original = GenerateCompressibleData(4096);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(comp.compress(original.data(), original.size(), compressed));
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(decomp.decompress(compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(original, decompressed);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Error_CompressNullPointerWithSize) {
    std::vector<uint8_t> output;
    EXPECT_FALSE(CompressBuffer(Algorithm::Xpress, nullptr, 100, output));
}

TEST_F(CompressionUtilsTest, Error_CompressNullPointerZeroSize) {
    std::vector<uint8_t> output;
    EXPECT_TRUE(CompressBuffer(Algorithm::Xpress, nullptr, 0, output));
    EXPECT_EQ(output.size(), 0u);
}

TEST_F(CompressionUtilsTest, Error_DecompressNullPointerWithSize) {
    std::vector<uint8_t> output;
    EXPECT_FALSE(DecompressBuffer(Algorithm::Xpress, nullptr, 100, output));
}

TEST_F(CompressionUtilsTest, Error_DecompressNullPointerZeroSize) {
    std::vector<uint8_t> output;
    EXPECT_TRUE(DecompressBuffer(Algorithm::Xpress, nullptr, 0, output));
    EXPECT_EQ(output.size(), 0u);
}

TEST_F(CompressionUtilsTest, Error_DecompressCorruptedData) {
    auto corrupted = GenerateRandomData(256);
    std::vector<uint8_t> output;
    
    // Random data is unlikely to be valid compressed data
    // This should fail gracefully without crashing
    bool result = DecompressBuffer(Algorithm::Xpress, corrupted.data(), corrupted.size(), output);
    // Result may be true or false depending on random data, but should not crash
}

TEST_F(CompressionUtilsTest, Error_DecompressWrongAlgorithm) {
    std::string original = "Test data";
    std::vector<uint8_t> input(original.begin(), original.end());
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> output;
    // Try to decompress with different algorithm
    bool result = DecompressBuffer(Algorithm::Mszip, compressed.data(), compressed.size(), output);
    // May succeed or fail, but should not crash
}

// ============================================================================
// Security Limit Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Security_MaxCompressedSizeLimit) {
    // MAX_COMPRESSED_SIZE is 256MB
    size_t oversized = MAX_COMPRESSED_SIZE + 1;
    auto data = GenerateRandomData(std::min(oversized, size_t(1024))); // Don't actually allocate 256MB
    
    std::vector<uint8_t> output;
    
    // Should reject if we try to compress data larger than limit
    // Note: We can't actually test with 256MB+ due to memory constraints in tests
    // This test verifies the limit exists in code
    EXPECT_LE(MAX_COMPRESSED_SIZE, 256 * 1024 * 1024);
}

TEST_F(CompressionUtilsTest, Security_MaxDecompressedSizeLimit) {
    // MAX_DECOMPRESSED_SIZE is 512MB
    EXPECT_LE(MAX_DECOMPRESSED_SIZE, 512 * 1024 * 1024);
}

TEST_F(CompressionUtilsTest, Security_CompressionRatioLimit) {
    // MAX_COMPRESSION_RATIO is 100:1
    EXPECT_EQ(MAX_COMPRESSION_RATIO, 100);
}

TEST_F(CompressionUtilsTest, Security_DecompressWithExcessiveExpectedSize) {
    std::string original = "Small data";
    std::vector<uint8_t> input(original.begin(), original.end());
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> output;
    // Try to decompress with ridiculously large expected size (potential bomb)
    size_t hugeSize = MAX_DECOMPRESSED_SIZE + 1;
    
    EXPECT_FALSE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), 
                                   output, hugeSize));
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(CompressionUtilsTest, EdgeCase_AllZeros) {
    std::vector<uint8_t> input(1024, 0x00);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    // All zeros should compress very well
    EXPECT_LT(compressed.size(), input.size() / 2);
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, EdgeCase_AllOnes) {
    std::vector<uint8_t> input(1024, 0xFF);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    EXPECT_LT(compressed.size(), input.size());
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, EdgeCase_BinaryData) {
    std::vector<uint8_t> input = {0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD, 0xBE, 0xEF};
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, EdgeCase_UnicodeText) {
    std::wstring text = L"Hello ?? ?????? ??? ????? ??";
    std::vector<uint8_t> input(reinterpret_cast<const uint8_t*>(text.data()),
                               reinterpret_cast<const uint8_t*>(text.data()) + text.size() * sizeof(wchar_t));
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    std::vector<uint8_t> decompressed;
    ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed));
    
    EXPECT_EQ(input, decompressed);
}

TEST_F(CompressionUtilsTest, EdgeCase_PowerOfTwoSizes) {
    for (size_t size : {64, 128, 256, 512, 1024, 2048, 4096, 8192}) {
        auto input = GenerateCompressibleData(size);
        
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed))
            << "Failed at size " << size;
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed))
            << "Failed at size " << size;
        
        EXPECT_EQ(input, decompressed) << "Mismatch at size " << size;
    }
}

TEST_F(CompressionUtilsTest, EdgeCase_OffByOneSizes) {
    for (size_t size : {63, 64, 65, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025}) {
        auto input = GenerateCompressibleData(size);
        
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed))
            << "Failed at size " << size;
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed))
            << "Failed at size " << size;
        
        EXPECT_EQ(input, decompressed) << "Mismatch at size " << size;
    }
}

// ============================================================================
// Performance Baseline Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Performance_CompressSmallData) {
    auto input = GenerateCompressibleData(1024);
    std::vector<uint8_t> output;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100; ++i) {
        output.clear();
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), output));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "100 compressions of 1KB: " << duration.count() << " ms\n";
    EXPECT_LT(duration.count(), 5000); // Should complete in < 5 seconds
}

TEST_F(CompressionUtilsTest, Performance_DecompressSmallData) {
    auto input = GenerateCompressibleData(1024);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> output;
        ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), output));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "100 decompressions of 1KB: " << duration.count() << " ms\n";
    EXPECT_LT(duration.count(), 5000); // Should complete in < 5 seconds
}

TEST_F(CompressionUtilsTest, Performance_RAIIReuse) {
    Compressor comp;
    ASSERT_TRUE(comp.open(Algorithm::Xpress));
    
    auto input = GenerateCompressibleData(1024);
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> output;
        ASSERT_TRUE(comp.compress(input.data(), input.size(), output));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    std::cout << "100 RAII compressions of 1KB: " << duration.count() << " ms\n";
    EXPECT_LT(duration.count(), 5000);
}

// ============================================================================
// Compression Ratio Tests
// ============================================================================

TEST_F(CompressionUtilsTest, CompressionRatio_HighlyCompressible) {
    std::vector<uint8_t> input(10000, 'A'); // Very compressible
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    double ratio = static_cast<double>(input.size()) / compressed.size();
    std::cout << "Compression ratio for repeated 'A': " << ratio << ":1\n";
    
    // Should compress to less than 10% of original
    EXPECT_LT(compressed.size(), input.size() / 10);
}

TEST_F(CompressionUtilsTest, CompressionRatio_Random) {
    auto input = GenerateRandomData(10000);
    
    std::vector<uint8_t> compressed;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed));
    
    double ratio = static_cast<double>(input.size()) / compressed.size();
    std::cout << "Compression ratio for random data: " << ratio << ":1\n";
    
    // Random data doesn't compress well, may even expand
    // Just verify it doesn't crash
    EXPECT_GT(compressed.size(), 0u);
}

TEST_F(CompressionUtilsTest, CompressionRatio_AlreadyCompressed) {
    auto original = GenerateCompressibleData(4096);
    
    std::vector<uint8_t> compressed1;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, original.data(), original.size(), compressed1));
    
    // Try to compress already compressed data
    std::vector<uint8_t> compressed2;
    ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, compressed1.data(), compressed1.size(), compressed2));
    
    // Already compressed data should not compress further (may expand)
    EXPECT_GE(compressed2.size(), compressed1.size() * 0.9); // Allow some tolerance
}

// ============================================================================
// Data Integrity Tests
// ============================================================================

TEST_F(CompressionUtilsTest, Integrity_MultipleRoundTrips) {
    auto original = GenerateCompressibleData(1024);
    std::vector<uint8_t> current = original;
    
    for (int round = 0; round < 5; ++round) {
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, current.data(), current.size(), compressed))
            << "Compression failed at round " << round;
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed))
            << "Decompression failed at round " << round;
        
        EXPECT_EQ(current, decompressed) << "Data mismatch at round " << round;
        current = decompressed;
    }
    
    EXPECT_EQ(original, current);
}

TEST_F(CompressionUtilsTest, Integrity_DifferentDataSizes) {
    for (size_t size : {1, 10, 100, 500, 1000, 5000, 10000, 50000}) {
        auto input = GenerateCompressibleData(size);
        
        std::vector<uint8_t> compressed;
        ASSERT_TRUE(CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed))
            << "Compression failed at size " << size;
        
        std::vector<uint8_t> decompressed;
        ASSERT_TRUE(DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed))
            << "Decompression failed at size " << size;
        
        EXPECT_EQ(input, decompressed) << "Integrity check failed at size " << size;
    }
}

// ============================================================================
// Thread Safety Tests (Basic)
// ============================================================================

TEST_F(CompressionUtilsTest, ThreadSafety_ConcurrentStatelessOperations) {
    auto input = GenerateCompressibleData(1024);
    std::atomic<int> successCount{0};
    
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&input, &successCount]() {
            for (int i = 0; i < 10; ++i) {
                std::vector<uint8_t> compressed;
                if (CompressBuffer(Algorithm::Xpress, input.data(), input.size(), compressed)) {
                    std::vector<uint8_t> decompressed;
                    if (DecompressBuffer(Algorithm::Xpress, compressed.data(), compressed.size(), decompressed)) {
                        if (input == decompressed) {
                            successCount.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(successCount.load(), 40); // 4 threads * 10 iterations
}

TEST_F(CompressionUtilsTest, ThreadSafety_MultipleRAIIInstances) {
    auto input = GenerateCompressibleData(1024);
    std::atomic<int> successCount{0};
    
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&input, &successCount]() {
            Compressor comp;
            Decompressor decomp;
            
            if (comp.open(Algorithm::Xpress) && decomp.open(Algorithm::Xpress)) {
                for (int i = 0; i < 10; ++i) {
                    std::vector<uint8_t> compressed;
                    if (comp.compress(input.data(), input.size(), compressed)) {
                        std::vector<uint8_t> decompressed;
                        if (decomp.decompress(compressed.data(), compressed.size(), decompressed)) {
                            if (input == decompressed) {
                                successCount.fetch_add(1, std::memory_order_relaxed);
                            }
                        }
                    }
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(successCount.load(), 40);
}
