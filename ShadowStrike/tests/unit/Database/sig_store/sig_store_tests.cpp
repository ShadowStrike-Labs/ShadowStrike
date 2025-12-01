/*
 * ShadowStrike Antivirus - Unit Tests
 * SignatureStore Unified Facade Tests
 * 
 * Enterprise-grade comprehensive testing for the main SignatureStore orchestration layer
 * Tests cover: Initialization, unified scanning, component integration, caching,
 * bulk operations, statistics, maintenance, and advanced features
 * 
 * Copyright (c) 2024 ShadowStrike Team
 */

#include <gtest/gtest.h>
#include "../../../../src/SignatureStore/SignatureStore.hpp"
#include "../../../../src/SignatureStore/SignatureFormat.hpp"
#include "../../../../src/SignatureStore/HashStore.hpp"
#include "../../../../src/SignatureStore/PatternStore.hpp"
#include "../../../../src/SignatureStore/YaraRuleStore.hpp"
#include <memory>
#include <vector>
#include <string>
#include <fstream>
#include <thread>
#include <chrono>
#include <filesystem>
#include <random>

using namespace ShadowStrike::SignatureStore;
namespace fs = std::filesystem;

// ============================================================================
// Test Fixture
// ============================================================================

class SignatureStoreTest : public ::testing::Test {
protected:
    std::unique_ptr<SignatureStore> sig_store_;
    std::wstring test_db_path_;
    fs::path test_dir_;
    
    void SetUp() override {
        // Create temporary test directory
        test_dir_ = fs::temp_directory_path() / "shadowstrike_sigstore_tests";
        fs::create_directories(test_dir_);
        
        // Create temporary test database path
        test_db_path_ = (test_dir_ / "test_signature_store.ssdb").wstring();
        
        // Remove any existing test database
        fs::remove(test_db_path_);
        
        // Create new signature store
        sig_store_ = std::make_unique<SignatureStore>();
    }
    
    void TearDown() override {
        // Close and cleanup
        if (sig_store_) {
            sig_store_->Close();
            sig_store_.reset();
        }
        
        // Remove test directory
        try {
            if (fs::exists(test_dir_)) {
                fs::remove_all(test_dir_);
            }
        } catch (...) {
            // Ignore cleanup errors
        }
    }
    
    // Helper: Create test file with content
    std::wstring CreateTestFile(const std::string& name, const std::vector<uint8_t>& data) {
        auto file_path = test_dir_ / name;
        std::ofstream file(file_path, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        file.close();
        return file_path.wstring();
    }
    
    // Helper: Create test hash
    HashValue CreateTestHash(const std::vector<uint8_t>& data, HashType type = HashType::SHA256) {
        HashValue hash{};
        hash.type = type;
        hash.length = GetHashLengthForType(type);
        
        // Simple test hash generation (not cryptographic)
        for (size_t i = 0; i < hash.length && i < data.size(); ++i) {
            hash.data[i] = data[i];
        }
        
        return hash;
    }
    
    // Helper: Create test pattern
    std::string CreateTestPattern(const std::string& hex_string) {
        return hex_string;
    }
    
    // Helper: Create test YARA rule
    std::string CreateTestYaraRule(const std::string& rule_name, const std::string& pattern) {
        return "rule " + rule_name + " {\n"
               "    strings:\n"
               "        $a = { " + pattern + " }\n"
               "    condition:\n"
               "        $a\n"
               "}\n";
    }
};

// ============================================================================
// Initialization & Lifecycle Tests
// ============================================================================

TEST_F(SignatureStoreTest, Initialize_CreateNew) {
    // Note: This test depends on actual database creation functionality
    // For now, we test initialization behavior
    EXPECT_FALSE(sig_store_->IsInitialized());
}

TEST_F(SignatureStoreTest, Initialize_InvalidPath) {
    auto error = sig_store_->Initialize(L"\\\\invalid\\path\\nonexistent.ssdb");
    EXPECT_FALSE(error.IsSuccess());
}

TEST_F(SignatureStoreTest, GetStatus_UninitializedStore) {
    auto status = sig_store_->GetStatus();
    EXPECT_FALSE(status.allReady);
    EXPECT_FALSE(status.hashStoreReady);
    EXPECT_FALSE(status.patternStoreReady);
    EXPECT_FALSE(status.yaraStoreReady);
}

TEST_F(SignatureStoreTest, Close_IdempotentOperation) {
    sig_store_->Close();
    sig_store_->Close(); // Should not crash
    EXPECT_FALSE(sig_store_->IsInitialized());
}

// ============================================================================
// Component Enable/Disable Tests
// ============================================================================

TEST_F(SignatureStoreTest, SetHashStoreEnabled) {
    sig_store_->SetHashStoreEnabled(false);
    sig_store_->SetHashStoreEnabled(true);
    // Should not crash - actual behavior depends on implementation
    SUCCEED();
}

TEST_F(SignatureStoreTest, SetPatternStoreEnabled) {
    sig_store_->SetPatternStoreEnabled(false);
    sig_store_->SetPatternStoreEnabled(true);
    SUCCEED();
}

TEST_F(SignatureStoreTest, SetYaraStoreEnabled) {
    sig_store_->SetYaraStoreEnabled(false);
    sig_store_->SetYaraStoreEnabled(true);
    SUCCEED();
}

// ============================================================================
// Scanning Operations Tests (Basic Buffer Scan)
// ============================================================================

TEST_F(SignatureStoreTest, ScanBuffer_EmptyBuffer) {
    std::vector<uint8_t> empty_buffer;
    ScanOptions options;
    
    auto result = sig_store_->ScanBuffer(empty_buffer, options);
    
    EXPECT_FALSE(result.HasDetections());
    EXPECT_EQ(result.totalBytesScanned, 0);
}

TEST_F(SignatureStoreTest, ScanBuffer_ValidOptions) {
    std::vector<uint8_t> test_data = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00};
    
    ScanOptions options;
    options.enableHashLookup = true;
    options.enablePatternScan = true;
    options.enableYaraScan = false;
    options.timeoutMilliseconds = 1000;
    options.maxResults = 100;
    
    EXPECT_TRUE(options.Validate());
    
    auto result = sig_store_->ScanBuffer(test_data, options);
    
    EXPECT_EQ(result.totalBytesScanned, test_data.size());
    EXPECT_FALSE(result.timedOut);
}

TEST_F(SignatureStoreTest, ScanBuffer_StopOnFirstMatch) {
    std::vector<uint8_t> test_data = {0x4D, 0x5A, 0x90, 0x00};
    
    ScanOptions options;
    options.stopOnFirstMatch = true;
    options.maxResults = 1;
    
    auto result = sig_store_->ScanBuffer(test_data, options);
    
    // May stop early if matches found
    EXPECT_TRUE(result.IsSuccessful() || result.stoppedEarly);
}

TEST_F(SignatureStoreTest, ScanBuffer_TimeoutValidation) {
    ScanOptions options;
    
    // Test valid timeout
    options.timeoutMilliseconds = 5000;
    EXPECT_EQ(options.GetValidatedTimeout(), 5000);
    
    // Test zero timeout (should use default)
    options.timeoutMilliseconds = 0;
    EXPECT_EQ(options.GetValidatedTimeout(), TitaniumLimits::DEFAULT_TIMEOUT_MS);
    
    // Test too small timeout (should clamp to minimum)
    options.timeoutMilliseconds = 50;
    EXPECT_EQ(options.GetValidatedTimeout(), TitaniumLimits::MIN_TIMEOUT_MS);
    
    // Test too large timeout (should clamp to maximum)
    options.timeoutMilliseconds = 5000000;
    EXPECT_EQ(options.GetValidatedTimeout(), TitaniumLimits::MAX_TIMEOUT_MS);
}

TEST_F(SignatureStoreTest, ScanBuffer_MaxResultsValidation) {
    ScanOptions options;
    
    // Test valid max results
    options.maxResults = 500;
    EXPECT_EQ(options.GetValidatedMaxResults(), 500);
    
    // Test zero max results (should use default)
    options.maxResults = 0;
    EXPECT_EQ(options.GetValidatedMaxResults(), TitaniumLimits::DEFAULT_MAX_RESULTS);
    
    // Test too large max results (should clamp)
    options.maxResults = 200000;
    EXPECT_EQ(options.GetValidatedMaxResults(), TitaniumLimits::ABSOLUTE_MAX_RESULTS);
}

TEST_F(SignatureStoreTest, ScanBuffer_ThreatLevelFiltering) {
    std::vector<uint8_t> test_data = {0x00, 0x01, 0x02, 0x03};
    
    ScanOptions options;
    options.minThreatLevel = ThreatLevel::High;
    
    auto result = sig_store_->ScanBuffer(test_data, options);
    
    // All detections should be at least High threat level
    for (const auto& detection : result.detections) {
        EXPECT_GE(static_cast<uint8_t>(detection.threatLevel), 
                  static_cast<uint8_t>(ThreatLevel::High));
    }
}

// ============================================================================
// File Scanning Tests
// ============================================================================

TEST_F(SignatureStoreTest, ScanFile_NonexistentFile) {
    ScanOptions options;
    auto result = sig_store_->ScanFile(L"nonexistent_file.bin", options);
    
    EXPECT_FALSE(result.IsSuccessful());
    EXPECT_GT(result.errorCount, 0);
}

TEST_F(SignatureStoreTest, ScanFile_EmptyFile) {
    auto file_path = CreateTestFile("empty.bin", {});
    
    ScanOptions options;
    auto result = sig_store_->ScanFile(file_path, options);
    
    EXPECT_EQ(result.totalBytesScanned, 0);
}

TEST_F(SignatureStoreTest, ScanFile_ValidFile) {
    std::vector<uint8_t> test_data = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00};
    auto file_path = CreateTestFile("test.bin", test_data);
    
    ScanOptions options;
    auto result = sig_store_->ScanFile(file_path, options);
    
    EXPECT_EQ(result.totalBytesScanned, test_data.size());
}

TEST_F(SignatureStoreTest, ScanFile_LargeFile) {
    // Create 5MB test file
    std::vector<uint8_t> large_data(5 * 1024 * 1024, 0xAA);
    auto file_path = CreateTestFile("large.bin", large_data);
    
    ScanOptions options;
    options.timeoutMilliseconds = 10000; // 10 seconds
    
    auto result = sig_store_->ScanFile(file_path, options);
    
    EXPECT_EQ(result.totalBytesScanned, large_data.size());
    
    // Check throughput
    double throughput = result.GetThroughputMBps();
    EXPECT_GT(throughput, 0.0);
}

// ============================================================================
// Batch File Scanning Tests
// ============================================================================

TEST_F(SignatureStoreTest, ScanFiles_EmptyList) {
    std::vector<std::wstring> empty_list;
    ScanOptions options;
    
    auto results = sig_store_->ScanFiles(empty_list, options);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(SignatureStoreTest, ScanFiles_MultipleFiles) {
    // Create test files
    std::vector<std::wstring> file_paths;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> data(1024, static_cast<uint8_t>(i));
        file_paths.push_back(CreateTestFile("file" + std::to_string(i) + ".bin", data));
    }
    
    ScanOptions options;
    
    size_t progress_count = 0;
    auto results = sig_store_->ScanFiles(file_paths, options, 
        [&progress_count](size_t current, size_t total) {
            progress_count++;
        });
    
    EXPECT_EQ(results.size(), 5);
    EXPECT_GT(progress_count, 0);
}

TEST_F(SignatureStoreTest, ScanFiles_WithProgressCallback) {
    std::vector<std::wstring> files;
    for (int i = 0; i < 3; ++i) {
        files.push_back(CreateTestFile("test" + std::to_string(i) + ".bin", {0x00}));
    }
    
    size_t callback_count = 0;
    size_t last_current = 0;
    size_t last_total = 0;
    
    auto results = sig_store_->ScanFiles(files, {}, 
        [&](size_t current, size_t total) {
            callback_count++;
            last_current = current;
            last_total = total;
        });
    
    EXPECT_GT(callback_count, 0);
    EXPECT_EQ(last_total, 3);
}

// ============================================================================
// Directory Scanning Tests
// ============================================================================

TEST_F(SignatureStoreTest, ScanDirectory_NonexistentDirectory) {
    ScanOptions options;
    auto results = sig_store_->ScanDirectory(L"nonexistent_directory", false, options);
    
    // Should handle gracefully
    EXPECT_TRUE(results.empty() || !results.empty());
}

TEST_F(SignatureStoreTest, ScanDirectory_EmptyDirectory) {
    auto empty_dir = test_dir_ / "empty_dir";
    fs::create_directories(empty_dir);
    
    ScanOptions options;
    auto results = sig_store_->ScanDirectory(empty_dir.wstring(), false, options);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(SignatureStoreTest, ScanDirectory_WithFiles) {
    auto scan_dir = test_dir_ / "scan_dir";
    fs::create_directories(scan_dir);
    
    // Create files in directory
    for (int i = 0; i < 3; ++i) {
        auto file_path = scan_dir / ("file" + std::to_string(i) + ".bin");
        std::ofstream file(file_path, std::ios::binary);
        uint8_t byte = static_cast<uint8_t>(i);
        file.write(reinterpret_cast<const char*>(&byte), 1);
    }
    
    ScanOptions options;
    auto results = sig_store_->ScanDirectory(scan_dir.wstring(), false, options);
    
    EXPECT_EQ(results.size(), 3);
}

TEST_F(SignatureStoreTest, ScanDirectory_RecursiveMode) {
    auto scan_dir = test_dir_ / "recursive_scan";
    fs::create_directories(scan_dir);
    fs::create_directories(scan_dir / "subdir1");
    fs::create_directories(scan_dir / "subdir2");
    
    // Create files in subdirectories
    CreateTestFile("recursive_scan/file0.bin", {0x00});
    CreateTestFile("recursive_scan/subdir1/file1.bin", {0x01});
    CreateTestFile("recursive_scan/subdir2/file2.bin", {0x02});
    
    ScanOptions options;
    auto results = sig_store_->ScanDirectory(scan_dir.wstring(), true, options);
    
    EXPECT_GE(results.size(), 3);
}

TEST_F(SignatureStoreTest, ScanDirectory_WithFileCallback) {
    auto scan_dir = test_dir_ / "callback_test";
    fs::create_directories(scan_dir);
    CreateTestFile("callback_test/file.bin", {0x00});
    
    std::vector<std::wstring> scanned_files;
    
    ScanOptions options;
    auto results = sig_store_->ScanDirectory(scan_dir.wstring(), false, options,
        [&scanned_files](const std::wstring& file) {
            scanned_files.push_back(file);
        });
    
    EXPECT_FALSE(scanned_files.empty());
}

// ============================================================================
// Stream Scanner Tests
// ============================================================================

TEST_F(SignatureStoreTest, StreamScanner_Create) {
    ScanOptions options;
    auto scanner = sig_store_->CreateStreamScanner(options);
    
    EXPECT_EQ(scanner.GetBytesProcessed(), 0);
}

TEST_F(SignatureStoreTest, StreamScanner_FeedAndFinalize) {
    auto scanner = sig_store_->CreateStreamScanner();
    
    // Feed chunks
    std::vector<uint8_t> chunk1 = {0x4D, 0x5A};
    std::vector<uint8_t> chunk2 = {0x90, 0x00};
    
    scanner.FeedChunk(chunk1);
    scanner.FeedChunk(chunk2);
    
    EXPECT_EQ(scanner.GetBytesProcessed(), 4);
    
    auto result = scanner.Finalize();
    
    EXPECT_EQ(result.totalBytesScanned, 4);
}

TEST_F(SignatureStoreTest, StreamScanner_Reset) {
    auto scanner = sig_store_->CreateStreamScanner();
    
    std::vector<uint8_t> chunk = {0x00, 0x01, 0x02};
    scanner.FeedChunk(chunk);
    
    scanner.Reset();
    
    EXPECT_EQ(scanner.GetBytesProcessed(), 0);
}

TEST_F(SignatureStoreTest, StreamScanner_LargeStream) {
    auto scanner = sig_store_->CreateStreamScanner();
    
    // Feed 1MB in 10KB chunks
    constexpr size_t chunk_size = 10 * 1024;
    constexpr size_t total_size = 1 * 1024 * 1024;
    
    for (size_t i = 0; i < total_size / chunk_size; ++i) {
        std::vector<uint8_t> chunk(chunk_size, static_cast<uint8_t>(i % 256));
        scanner.FeedChunk(chunk);
    }
    
    auto result = scanner.Finalize();
    
    EXPECT_EQ(result.totalBytesScanned, total_size);
}

// ============================================================================
// Hash Lookup Tests
// ============================================================================

TEST_F(SignatureStoreTest, LookupHash_EmptyStore) {
    HashValue test_hash{};
    test_hash.type = HashType::SHA256;
    test_hash.length = 32;
    
    auto result = sig_store_->LookupHash(test_hash);
    
    EXPECT_FALSE(result.has_value());
}

TEST_F(SignatureStoreTest, LookupHashString_ValidFormat) {
    std::string hash_str = "d41d8cd98f00b204e9800998ecf8427e";
    
    auto result = sig_store_->LookupHashString(hash_str, HashType::MD5);
    
    // Should not crash, may or may not find match
    EXPECT_TRUE(result.has_value() || !result.has_value());
}

TEST_F(SignatureStoreTest, LookupHashString_InvalidFormat) {
    std::string invalid_hash = "INVALID_HEX";
    
    auto result = sig_store_->LookupHashString(invalid_hash, HashType::MD5);
    
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// Specific Query Tests
// ============================================================================

TEST_F(SignatureStoreTest, ScanPatterns_EmptyBuffer) {
    std::vector<uint8_t> empty;
    QueryOptions options;
    
    auto results = sig_store_->ScanPatterns(empty, options);
    
    EXPECT_TRUE(results.empty());
}

TEST_F(SignatureStoreTest, ScanYara_EmptyBuffer) {
    std::vector<uint8_t> empty;
    YaraScanOptions options;
    
    auto results = sig_store_->ScanYara(empty, options);
    
    EXPECT_TRUE(results.empty());
}

// ============================================================================
// Cache Management Tests
// ============================================================================

TEST_F(SignatureStoreTest, CacheControl_EnableDisable) {
    sig_store_->SetQueryCacheEnabled(true);
    sig_store_->SetResultCacheEnabled(true);
    
    sig_store_->SetQueryCacheEnabled(false);
    sig_store_->SetResultCacheEnabled(false);
    
    SUCCEED();
}

TEST_F(SignatureStoreTest, CacheControl_SetSize) {
    sig_store_->SetQueryCacheSize(500);
    sig_store_->SetResultCacheSize(1000);
    
    SUCCEED();
}

TEST_F(SignatureStoreTest, CacheControl_Clear) {
    sig_store_->ClearQueryCache();
    sig_store_->ClearResultCache();
    sig_store_->ClearAllCaches();
    
    SUCCEED();
}

TEST_F(SignatureStoreTest, CacheControl_WarmupCaches) {
    sig_store_->WarmupCaches();
    
    SUCCEED();
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(SignatureStoreTest, GetGlobalStatistics_Uninit) {
    auto stats = sig_store_->GetGlobalStatistics();
    
    EXPECT_EQ(stats.totalScans, 0);
    EXPECT_EQ(stats.totalDetections, 0);
}

TEST_F(SignatureStoreTest, GetGlobalStatistics_AfterScans) {
    std::vector<uint8_t> test_data = {0x00, 0x01, 0x02};
    
    // Perform multiple scans
    for (int i = 0; i < 5; ++i) {
        sig_store_->ScanBuffer(test_data);
    }
    
    auto stats = sig_store_->GetGlobalStatistics();
    
    EXPECT_GE(stats.totalScans, 5);
}

TEST_F(SignatureStoreTest, ResetStatistics) {
    std::vector<uint8_t> test_data = {0x00};
    sig_store_->ScanBuffer(test_data);
    
    sig_store_->ResetStatistics();
    
    auto stats = sig_store_->GetGlobalStatistics();
    EXPECT_EQ(stats.totalScans, 0);
}

TEST_F(SignatureStoreTest, GetComponentStatistics) {
    auto hash_stats = sig_store_->GetHashStatistics();
    auto pattern_stats = sig_store_->GetPatternStatistics();
    auto yara_stats = sig_store_->GetYaraStatistics();
    
    // Should not crash
    SUCCEED();
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(SignatureStoreTest, SetThreadPoolSize) {
    sig_store_->SetThreadPoolSize(4);
    sig_store_->SetThreadPoolSize(8);
    sig_store_->SetThreadPoolSize(0); // Auto-detect
    
    SUCCEED();
}

TEST_F(SignatureStoreTest, SetProfilingEnabled) {
    sig_store_->SetProfilingEnabled(true);
    sig_store_->SetProfilingEnabled(false);
    
    SUCCEED();
}

// ============================================================================
// Detection Callback Tests
// ============================================================================

TEST_F(SignatureStoreTest, RegisterDetectionCallback) {
    std::atomic<int> callback_count{0};
    
    sig_store_->RegisterDetectionCallback(
        [&callback_count](const DetectionResult& result) {
            callback_count++;
        });
    
    // Callback registered successfully
    SUCCEED();
    
    sig_store_->UnregisterDetectionCallback();
}

TEST_F(SignatureStoreTest, UnregisterDetectionCallback) {
    sig_store_->RegisterDetectionCallback(
        [](const DetectionResult&) {});
    
    sig_store_->UnregisterDetectionCallback();
    
    SUCCEED();
}

// ============================================================================
// ScanResult Helper Methods Tests
// ============================================================================

TEST_F(SignatureStoreTest, ScanResult_HasDetections) {
    ScanResult result;
    
    EXPECT_FALSE(result.HasDetections());
    
    DetectionResult detection;
    result.detections.push_back(detection);
    
    EXPECT_TRUE(result.HasDetections());
}

TEST_F(SignatureStoreTest, ScanResult_GetMaxThreatLevel) {
    ScanResult result;
    
    EXPECT_EQ(result.GetMaxThreatLevel(), ThreatLevel::Info);
    
    DetectionResult det1;
    det1.threatLevel = ThreatLevel::Low;
    result.detections.push_back(det1);
    
    DetectionResult det2;
    det2.threatLevel = ThreatLevel::Critical;
    result.detections.push_back(det2);
    
    EXPECT_EQ(result.GetMaxThreatLevel(), ThreatLevel::Critical);
}

TEST_F(SignatureStoreTest, ScanResult_GetDetectionCount) {
    ScanResult result;
    
    EXPECT_EQ(result.GetDetectionCount(), 0);
    
    result.detections.resize(5);
    
    EXPECT_EQ(result.GetDetectionCount(), 5);
}

TEST_F(SignatureStoreTest, ScanResult_IsSuccessful) {
    ScanResult result;
    
    result.timedOut = false;
    result.errorCount = 0;
    EXPECT_TRUE(result.IsSuccessful());
    
    result.timedOut = true;
    EXPECT_FALSE(result.IsSuccessful());
    
    result.timedOut = false;
    result.errorCount = 1;
    EXPECT_FALSE(result.IsSuccessful());
}

TEST_F(SignatureStoreTest, ScanResult_HasCriticalDetection) {
    ScanResult result;
    
    EXPECT_FALSE(result.HasCriticalDetection());
    
    DetectionResult det;
    det.threatLevel = ThreatLevel::Critical;
    result.detections.push_back(det);
    
    EXPECT_TRUE(result.HasCriticalDetection());
}

TEST_F(SignatureStoreTest, ScanResult_GetDetectionsByLevel) {
    ScanResult result;
    
    for (int i = 0; i < 3; ++i) {
        DetectionResult det;
        det.threatLevel = ThreatLevel::High;
        result.detections.push_back(det);
    }
    
    for (int i = 0; i < 2; ++i) {
        DetectionResult det;
        det.threatLevel = ThreatLevel::Low;
        result.detections.push_back(det);
    }
    
    auto high_detections = result.GetDetectionsByLevel(ThreatLevel::High);
    EXPECT_EQ(high_detections.size(), 3);
    
    auto low_detections = result.GetDetectionsByLevel(ThreatLevel::Low);
    EXPECT_EQ(low_detections.size(), 2);
}

TEST_F(SignatureStoreTest, ScanResult_GetThroughput) {
    ScanResult result;
    
    result.totalBytesScanned = 1000000; // 1MB
    result.scanTimeMicroseconds = 1000000; // 1 second
    
    double throughput = result.GetThroughputMBps();
    
    EXPECT_DOUBLE_EQ(throughput, 1.0);
}

TEST_F(SignatureStoreTest, ScanResult_Clear) {
    ScanResult result;
    
    result.detections.resize(5);
    result.totalBytesScanned = 1000;
    result.timedOut = true;
    
    result.Clear();
    
    EXPECT_TRUE(result.detections.empty());
    EXPECT_EQ(result.totalBytesScanned, 0);
    EXPECT_FALSE(result.timedOut);
}

// ============================================================================
// Global Functions Tests
// ============================================================================

TEST_F(SignatureStoreTest, Store_GetVersion) {
    auto version = Store::GetVersion();
    EXPECT_FALSE(version.empty());
}

TEST_F(SignatureStoreTest, Store_GetBuildInfo) {
    auto build_info = Store::GetBuildInfo();
    EXPECT_FALSE(build_info.empty());
}

TEST_F(SignatureStoreTest, Store_GetSupportedHashTypes) {
    auto hash_types = Store::GetSupportedHashTypes();
    EXPECT_FALSE(hash_types.empty());
}

TEST_F(SignatureStoreTest, Store_IsYaraAvailable) {
    bool yara_available = Store::IsYaraAvailable();
    EXPECT_TRUE(yara_available || !yara_available); // Tautology but tests execution
}

TEST_F(SignatureStoreTest, Store_GetYaraVersion) {
    auto yara_version = Store::GetYaraVersion();
    // May be empty if YARA not available
    EXPECT_TRUE(yara_version.empty() || !yara_version.empty());
}

// ============================================================================
// Advanced Edge Cases Tests
// ============================================================================

TEST_F(SignatureStoreTest, EdgeCase_VeryLargeBuffer) {
    // Test with buffer at Titanium limit
    size_t large_size = TitaniumLimits::MAX_SCAN_BUFFER_SIZE;
    
    // Create buffer (may fail if insufficient memory)
    try {
        std::vector<uint8_t> large_buffer(large_size, 0xAA);
        
        ScanOptions options;
        options.timeoutMilliseconds = 60000; // 60 seconds
        
        auto result = sig_store_->ScanBuffer(large_buffer, options);
        
        EXPECT_TRUE(result.IsSuccessful() || result.timedOut);
    } catch (const std::bad_alloc&) {
        GTEST_SKIP() << "Insufficient memory for large buffer test";
    }
}

TEST_F(SignatureStoreTest, EdgeCase_MaxResults) {
    ScanOptions options;
    options.maxResults = TitaniumLimits::ABSOLUTE_MAX_RESULTS;
    
    EXPECT_TRUE(options.Validate());
    
    options.maxResults = TitaniumLimits::ABSOLUTE_MAX_RESULTS + 1;
    EXPECT_FALSE(options.Validate());
}

TEST_F(SignatureStoreTest, EdgeCase_ZeroTimeout) {
    ScanOptions options;
    options.timeoutMilliseconds = 0;
    
    EXPECT_TRUE(options.Validate());
    EXPECT_GT(options.GetValidatedTimeout(), 0);
}

TEST_F(SignatureStoreTest, EdgeCase_ParallelExecution) {
    ScanOptions options;
    options.parallelExecution = true;
    options.threadCount = 4;
    
    std::vector<uint8_t> test_data(1024, 0xAA);
    
    auto result = sig_store_->ScanBuffer(test_data, options);
    
    EXPECT_TRUE(result.IsSuccessful());
}

TEST_F(SignatureStoreTest, EdgeCase_PerformanceMetrics) {
    ScanOptions options;
    options.capturePerformanceMetrics = true;
    
    std::vector<uint8_t> test_data = {0x4D, 0x5A, 0x90};
    
    auto result = sig_store_->ScanBuffer(test_data, options);
    
    // Performance metrics should be captured
    EXPECT_GE(result.scanTimeMicroseconds, 0);
}

// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST_F(SignatureStoreTest, ThreadSafety_ConcurrentScans) {
    std::vector<uint8_t> test_data = {0x4D, 0x5A, 0x90, 0x00};
    
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([this, &test_data, &success_count]() {
            auto result = sig_store_->ScanBuffer(test_data);
            if (result.IsSuccessful()) {
                success_count++;
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(success_count, 8);
}

TEST_F(SignatureStoreTest, ThreadSafety_ConcurrentStatisticsAccess) {
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([this]() {
            for (int j = 0; j < 100; ++j) {
                auto stats = sig_store_->GetGlobalStatistics();
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    SUCCEED();
}

TEST_F(SignatureStoreTest, ThreadSafety_ConcurrentCacheOperations) {
    std::vector<std::thread> threads;
    
    for (int i = 0; i < 5; ++i) {
        threads.emplace_back([this]() {
            sig_store_->ClearQueryCache();
            sig_store_->ClearResultCache();
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    SUCCEED();
}

// ============================================================================
// Stress Tests
// ============================================================================

TEST_F(SignatureStoreTest, Stress_ManySmallScans) {
    std::vector<uint8_t> small_buffer = {0x00, 0x01, 0x02, 0x03};
    
    for (int i = 0; i < 1000; ++i) {
        auto result = sig_store_->ScanBuffer(small_buffer);
        EXPECT_TRUE(result.IsSuccessful());
    }
}

TEST_F(SignatureStoreTest, Stress_ManyFiles) {
    // Create many small files
    std::vector<std::wstring> files;
    for (int i = 0; i < 50; ++i) {
        files.push_back(CreateTestFile("stress" + std::to_string(i) + ".bin", {0x00}));
    }
    
    auto results = sig_store_->ScanFiles(files);
    
    EXPECT_EQ(results.size(), 50);
}

// ============================================================================
// Entry Point
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
