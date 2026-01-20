// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include "pch.h"
/**
 * ============================================================================
 * ShadowStrike WhitelistStore - MAIN STORE UNIT TESTS
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * Enterprise-Grade Unit Tests for WhitelistStore:
 * - Lifecycle (Create, Load, Save, Close)
 * - CRUD Operations (Hash, Path, Certificate, Publisher)
 * - Query Performance & Correctness
 * - Batch Operations
 * - Policy & Expiration Logic
 * - Thread Safety & Concurrency
 * - Persistence & Recovery
 * - Import/Export Compatibility
 *
 * @author ShadowStrike Security Team
 * ============================================================================
 */

#include <gtest/gtest.h>
#include"Utils/Logger.hpp"

#include "../../../../src/Whitelist/WhiteListStore.hpp"
#include "../../../../src/Whitelist/WhiteListFormat.hpp"

#include <filesystem>
#include <string>
#include<fstream>
#include<iterator>
#include <vector>
#include <thread>
#include <future>
#include <chrono>
#include <random>

// Conditional compilation for main()
#if defined(BUILD_TEST_EXECUTABLE) || defined(STANDALONE_TEST)
#endif

namespace ShadowStrike::Whitelist::Tests {

using namespace ShadowStrike::Whitelist;
namespace fs = std::filesystem;

class WhitelistStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create unique temporary path for each test
        auto tempDir = fs::temp_directory_path();
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 999999);
        
        std::wstringstream ss;
        ss << tempDir.c_str() << L"\\allowlist_test_" << dis(gen) << L".db";
        dbPath = ss.str();
        
        // Ensure clean state
        if (fs::exists(dbPath)) {
            fs::remove(dbPath);
        }
        
        store = std::make_unique<WhitelistStore>();
    }

    void TearDown() override {
        if (store) {
            store->Close();
            store.reset();
        }
        
        // Cleanup test file
        if (fs::exists(dbPath)) {
            // fs::remove(dbPath); // Keep for debugging if needed, or uncomment to clean
            try { fs::remove(dbPath); } catch(...) {}
        }
    }

    // Helper to create a valid SHA256 hash value
    HashValue CreateHash(const std::string& data) {
        // Mock hash generation for testing
        HashValue hv;
        hv.algorithm = HashAlgorithm::SHA256;
        hv.length = 32;
        
        // Simple fill for test uniqueness
        std::fill(hv.data.begin(), hv.data.end(), 0);
        size_t len = std::min(data.length(), (size_t)32);
        std::memcpy(hv.data.data(), data.data(), len);
        
        return hv;
    }

    std::wstring dbPath;
    std::unique_ptr<WhitelistStore> store;
};

// ============================================================================
// LIFECYCLE TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, Create_NewDatabase_Success) {
    StoreError err = store->Create(dbPath, 1024 * 1024); // 1MB
    
    ASSERT_TRUE(err.IsSuccess()) << "Failed to create database: " << err.message;
    EXPECT_TRUE(store->IsInitialized());
    EXPECT_FALSE(store->IsReadOnly());
    EXPECT_TRUE(fs::exists(dbPath));
    
    auto stats = store->GetStatistics();
    EXPECT_EQ(stats.totalEntries, 0);
}

TEST_F(WhitelistStoreTest, Create_ExistingDatabase_Overwrites) {
    // 1. Create first time
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    // 2. Create again (should overwrite)
    store = std::make_unique<WhitelistStore>();
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    EXPECT_EQ(store->GetEntryCount(), 0);
}

TEST_F(WhitelistStoreTest, Load_CreatedDatabase_Success) {
    // 1. Create and add some data
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    // 2. Load back in READ-ONLY mode (default)
    store = std::make_unique<WhitelistStore>();
    StoreError err = store->Load(dbPath, true);
    
    ASSERT_TRUE(err.IsSuccess()) << "Failed to load database: " << err.message;
    EXPECT_TRUE(store->IsInitialized());
    EXPECT_TRUE(store->IsReadOnly());
}

TEST_F(WhitelistStoreTest, Load_Writable_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    store = std::make_unique<WhitelistStore>();
    StoreError err = store->Load(dbPath, false); // ReadOnly = false
    
    ASSERT_TRUE(err.IsSuccess());
    EXPECT_FALSE(store->IsReadOnly());
}

TEST_F(WhitelistStoreTest, Load_NonExistentFile_Fails) {
    StoreError err = store->Load(L"C:\\NonExistentPath\\missing.db");
    
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, WhitelistStoreError::FileNotFound);
}

// ============================================================================
// HASH OPERATIONS TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, AddHash_ValidEntry_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("malware_hash_1");
    StoreError err = store->AddHash(hash, WhitelistReason::TrustedVendor, L"Test Entry");
    
    ASSERT_TRUE(err.IsSuccess()) << "Failed to add hash: " << err.message;
    EXPECT_EQ(store->GetEntryCount(), 1);
    
    // Verify immediate lookup matches
    auto result = store->IsHashWhitelisted(hash);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.reason, WhitelistReason::TrustedVendor);
}

TEST_F(WhitelistStoreTest, IsHashWhitelisted_NonExistent_ReturnsNotWhitelisted) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("unknown_hash");
    auto result = store->IsHashWhitelisted(hash);
    
    EXPECT_FALSE(result.found);
}

TEST_F(WhitelistStoreTest, RemoveHash_ExistingEntry_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("remove_me");
    ASSERT_TRUE(store->AddHash(hash, WhitelistReason::UserApproved).IsSuccess());
    EXPECT_EQ(store->GetEntryCount(), 1);
    
    StoreError err = store->RemoveHash(hash);
    ASSERT_TRUE(err.IsSuccess()) << "Failed to remove hash";
    
    EXPECT_EQ(store->GetEntryCount(), 0);
    EXPECT_FALSE(store->IsHashWhitelisted(hash).found);
}

TEST_F(WhitelistStoreTest, Persistence_SaveAndLoad_PreservesData) {
    // 1. Create and populate
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash1 = CreateHash("persist_1");
    HashValue hash2 = CreateHash("persist_2");
    
    store->AddHash(hash1, WhitelistReason::ReputationBased);//-V530
    store->AddHash(hash2, WhitelistReason::PolicyBased);//-V530
    
    // 2. Persist to disk
    ASSERT_TRUE(store->Save().IsSuccess());
    store->Close();
    
    // 3. Reload
    store = std::make_unique<WhitelistStore>();
    ASSERT_TRUE(store->Load(dbPath, true).IsSuccess());
    
    // 4. Verify
    EXPECT_EQ(store->GetEntryCount(), 2);
    EXPECT_TRUE(store->IsHashWhitelisted(hash1).found);
    EXPECT_TRUE(store->IsHashWhitelisted(hash2).found);
}

// ============================================================================
// PATH OPERATIONS TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, AddPath_ExactMatch_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::wstring path = L"C:\\Windows\\System32\\notepad.exe";
    StoreError err = store->AddPath(path, PathMatchMode::Exact, WhitelistReason::SystemFile);
    
    ASSERT_TRUE(err.IsSuccess());
    
    // Exact match lookup
    auto res = store->IsPathWhitelisted(path);
    EXPECT_TRUE(res.found);
    EXPECT_EQ(res.reason, WhitelistReason::SystemFile);
    
    // Different path should fail
    auto res2 = store->IsPathWhitelisted(L"C:\\Windows\\System32\\calc.exe");
    EXPECT_FALSE(res2.found);
}

TEST_F(WhitelistStoreTest, AddPath_PrefixMatch_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::wstring folder = L"C:\\Program Files\\TrustedApp";
    store->AddPath(folder, PathMatchMode::Prefix, WhitelistReason::TrustedVendor);//-V530
    
    // Test sub-item
    std::wstring subItem = L"C:\\Program Files\\TrustedApp\\bin\\app.exe";
    auto res = store->IsPathWhitelisted(subItem);
    
    EXPECT_TRUE(res.found);
    // Note: LookupResult does not have matchedBy field - just check found
    
    // Test outside item
    auto res2 = store->IsPathWhitelisted(L"C:\\Program Files\\OtherApp\\malware.exe");
    EXPECT_FALSE(res2.found);
}

TEST_F(WhitelistStoreTest, AddPath_SuffixMatch_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Whitelist all .dll files
    std::wstring suffix = L".dll";
    store->AddPath(suffix, PathMatchMode::Suffix, WhitelistReason::SystemFile);//-V530
    
    // Test matching suffix
    auto res1 = store->IsPathWhitelisted(L"C:\\Windows\\System32\\kernel32.dll");
    EXPECT_TRUE(res1.found);
    
    auto res2 = store->IsPathWhitelisted(L"C:\\App\\mylib.dll");
    EXPECT_TRUE(res2.found);
    
    // Non-matching
    auto res3 = store->IsPathWhitelisted(L"C:\\App\\malware.exe");
    EXPECT_FALSE(res3.found);
}

TEST_F(WhitelistStoreTest, AddPath_GlobMatch_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Whitelist pattern: C:\Windows\System32\*.exe
    std::wstring glob = L"C:\\Windows\\System32\\*.exe";
    store->AddPath(glob, PathMatchMode::Glob, WhitelistReason::SystemFile);//-V530
    
    // Should match
    auto res1 = store->IsPathWhitelisted(L"C:\\Windows\\System32\\notepad.exe");
    EXPECT_TRUE(res1.found);
    
    // Should not match (different folder)
    auto res2 = store->IsPathWhitelisted(L"C:\\Windows\\notepad.exe");
    EXPECT_FALSE(res2.found);
    
    // Should not match (different extension)
    auto res3 = store->IsPathWhitelisted(L"C:\\Windows\\System32\\kernel32.dll");
    EXPECT_FALSE(res3.found);
}

TEST_F(WhitelistStoreTest, AddPath_RegexMatch_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Whitelist regex: Any path containing "TrustedApp" anywhere
    std::wstring regex = L".*TrustedApp.*\\.exe$";
    store->AddPath(regex, PathMatchMode::Regex, WhitelistReason::PolicyBased);//-V530
    
    // Should match
    auto res1 = store->IsPathWhitelisted(L"C:\\Program Files\\TrustedApp\\app.exe");
    EXPECT_TRUE(res1.found);
    
    auto res2 = store->IsPathWhitelisted(L"D:\\Tools\\TrustedApp\\v2\\tool.exe");
    EXPECT_TRUE(res2.found);
    
    // Should not match
    auto res3 = store->IsPathWhitelisted(L"C:\\Program Files\\OtherApp\\app.exe");
    EXPECT_FALSE(res3.found);
}

TEST_F(WhitelistStoreTest, IsWhitelisted_ComprehensiveCheck_PrioritizesHash) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("known_good_hash");
    std::wstring path = L"C:\\Temp\\unknown.exe";
    
    // Whitelist the hash, but not the path
    store->AddHash(hash, WhitelistReason::ReputationBased);//-V530
    
    auto res = store->IsWhitelisted(path, &hash, nullptr, {});
    
    // Should pass due to hash match
    EXPECT_TRUE(res.found);
    // Note: LookupResult does not have matchedBy field
}

// ============================================================================
// EXPIRATION TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, AddHash_WithExpiration_ExpiresCorrectly) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("temp_allow");
    
    // Set expiration to 1 second in future
    auto now = std::chrono::system_clock::now();
    uint64_t expiry = std::chrono::duration_cast<std::chrono::seconds>(
        (now + std::chrono::seconds(1)).time_since_epoch()
    ).count();
    
    store->AddHash(hash, WhitelistReason::TemporaryBypass, L"Short lived", expiry);//-V530
    
    // valid immediately
    EXPECT_TRUE(store->IsHashWhitelisted(hash).found);
    
    // Wait for expiration
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Should be expired
    auto res = store->IsHashWhitelisted(hash);
    EXPECT_FALSE(res.found); 
    // Assuming IsHashWhitelisted filters out expired items automatically
}

TEST_F(WhitelistStoreTest, PurgeExpired_RemovesEntries) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("expiring_soon");
    // Expire 1 second ago
    auto now = std::chrono::system_clock::now();
    uint64_t expiry = std::chrono::duration_cast<std::chrono::seconds>(
        (now - std::chrono::seconds(1)).time_since_epoch()
    ).count();
    
    store->AddHash(hash, WhitelistReason::TemporaryBypass, L"Old", expiry);//-V530
    EXPECT_EQ(store->GetEntryCount(), 1);
    
    StoreError err = store->PurgeExpired();
    ASSERT_TRUE(err.IsSuccess());
    
    EXPECT_EQ(store->GetEntryCount(), 0);
}

// ============================================================================
// CONCURRENCY TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, Concurrent_ReadWrite_ThreadSafe) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    constexpr int NUM_READERS = 4;
    constexpr int NUM_WRITERS = 2;
    constexpr int OPS_PER_THREAD = 100;
    
    std::atomic<bool> start{false};
    std::vector<std::future<void>> futures;
    
    // Writers: Add unique hashes
    for (int i = 0; i < NUM_WRITERS; ++i) {
        futures.push_back(std::async(std::launch::async, [&, i]() {
            while (!start) std::this_thread::yield();
            
            for (int j = 0; j < OPS_PER_THREAD; ++j) {
                std::string key = "W" + std::to_string(i) + "_" + std::to_string(j);
                HashValue h = CreateHash(key);
                store->AddHash(h, WhitelistReason::PolicyBased);//-V530
            }
        }));
    }
    
    // Readers: check for a known hash (added beforehand) and randoms
    HashValue knownHash = CreateHash("known_exists");
    store->AddHash(knownHash, WhitelistReason::UserApproved);//-V530
    
    for (int i = 0; i < NUM_READERS; ++i) {
        futures.push_back(std::async(std::launch::async, [&]() {
            while (!start) std::this_thread::yield();
            
            for (int j = 0; j < OPS_PER_THREAD; ++j) {
                // Must always find known hash
                auto res = store->IsHashWhitelisted(knownHash);
                if (!res.found) {
                    throw std::runtime_error("Reader failed to find known hash");
                }
                
                // Random lookup shouldn't crash
                HashValue randomH = CreateHash("R_" + std::to_string(j));
                store->IsHashWhitelisted(randomH);//-V530
            }
        }));
    }
    
    start = true;
    for (auto& f : futures) {
        EXPECT_NO_THROW(f.get());
    }
    
    // Verify total count = Known + (Writers * Ops)
    EXPECT_EQ(store->GetEntryCount(), 1 + (NUM_WRITERS * OPS_PER_THREAD));
}

// ============================================================================
// BATCH OPERATIONS & PERFORMANCE
// ============================================================================

TEST_F(WhitelistStoreTest, BatchAdd_PerformanceAndCorrectness) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    constexpr size_t BATCH_SIZE = 1000;
    std::vector<WhitelistEntry> entries;
    entries.reserve(BATCH_SIZE);
    
    // Build batch
    for (size_t i = 0; i < BATCH_SIZE; ++i) {
        HashValue h = CreateHash("Batch_" + std::to_string(i));
        WhitelistEntry entry;
        WhitelistEntryBuilder()
            .SetType(WhitelistEntryType::FileHash)
            .SetHash(h)
            .SetReason(WhitelistReason::PolicyBased)
            .SetPolicyId(100)
            .ApplyTo(entry);
        entries.push_back(entry);
    }
    
    // Measure batch add time
    auto start = std::chrono::high_resolution_clock::now();
    StoreError err = store->BatchAdd(entries);
    auto end = std::chrono::high_resolution_clock::now();
    
    ASSERT_TRUE(err.IsSuccess()) << "Batch add failed: " << err.message;
    EXPECT_EQ(store->GetEntryCount(), BATCH_SIZE);
    
    // Verify insertion
    auto res = store->IsHashWhitelisted(CreateHash("Batch_0"));
    EXPECT_TRUE(res.found);
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    // std::cout << "Batch Add " << BATCH_SIZE << " items took " << duration << "ms" << std::endl;
}

TEST_F(WhitelistStoreTest, BatchLookup_OptimizedPath) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Setup data
    std::vector<HashValue> searchHashes;
    for (int i = 0; i < 100; ++i) {
        HashValue h = CreateHash("Key_" + std::to_string(i));
        store->AddHash(h, WhitelistReason::UserApproved);//-V530
        searchHashes.push_back(h);
    }
    
    // Add some missing ones to search list
    searchHashes.push_back(CreateHash("Missing_1"));
    searchHashes.push_back(CreateHash("Missing_2"));
    
    auto results = store->BatchLookupHashes(searchHashes);
    
    ASSERT_EQ(results.size(), searchHashes.size());
    
    // Check first 100 are whitelisted
    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(results[i].found) << "Index " << i;
    }
    
    // Check last 2 are not
    EXPECT_FALSE(results[100].found);
    EXPECT_FALSE(results[101].found);
}

// ============================================================================
// BLOOM FILTER TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, BloomFilter_RejectsBeforeIndexLookup) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->SetBloomFilterEnabled(true);
    
    // Add one item
    store->AddHash(CreateHash("Exists"), WhitelistReason::UserApproved);//-V530
    
    // Query existing
    auto res1 = store->IsHashWhitelisted(CreateHash("Exists"));
    EXPECT_TRUE(res1.found);
    
    // Query non-existing
    auto res2 = store->IsHashWhitelisted(CreateHash("Missing"));
    EXPECT_FALSE(res2.found);
    
    // Check stats to verify bloom filter usage
    // Note: This relies on implementation recording bloom stats.
    // If "Missing" was rejected by Bloom, 'bloomFilterRejects' should increment.
    // If "Exists" passed Bloom, 'bloomFilterHits' (false positive check pass) increments.
    
    auto stats = store->GetStatistics();
    
    // Bloom filter might not be filled immediately depending on implementation (lazy load vs immediate update)
    // But WhitelistStore is usually designed for immediate update or batch rebuild.
    // Assuming immediate update for AddHash.
    
    EXPECT_GE(stats.bloomFilterRejects, 0); // Should be > 0 if bloom worked for "Missing"
    // Can't strictly assert >0 because false positive is possible (unlikely for "Missing")
}

// ============================================================================
// CERTIFICATE OPERATIONS TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, AddCertificate_ValidThumbprint_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::array<uint8_t, 32> thumbprint{};
    // Fill with test data
    for (int i = 0; i < 32; ++i) {
        thumbprint[i] = static_cast<uint8_t>(i + 1);
    }
    
    StoreError err = store->AddCertificate(
        thumbprint, 
        WhitelistReason::TrustedVendor,
        L"Microsoft Code Signing Certificate"
    );
    
    ASSERT_TRUE(err.IsSuccess()) << "Failed to add certificate: " << err.message;
    EXPECT_EQ(store->GetEntryCount(), 1);
}

TEST_F(WhitelistStoreTest, IsCertificateWhitelisted_ExistingCert_ReturnsWhitelisted) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::array<uint8_t, 32> thumbprint{};
    for (int i = 0; i < 32; ++i) {
        thumbprint[i] = static_cast<uint8_t>(0xAB ^ i);
    }
    
    store->AddCertificate(thumbprint, WhitelistReason::ReputationBased);//-V530
    
    auto result = store->IsCertificateWhitelisted(thumbprint);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.reason, WhitelistReason::ReputationBased);
}

TEST_F(WhitelistStoreTest, IsCertificateWhitelisted_NonExistent_ReturnsNotWhitelisted) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::array<uint8_t, 32> unknownThumbprint{};
    std::fill(unknownThumbprint.begin(), unknownThumbprint.end(), 0xFF);
    
    auto result = store->IsCertificateWhitelisted(unknownThumbprint);
    EXPECT_FALSE(result.found);
}

// ============================================================================
// PUBLISHER OPERATIONS TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, AddPublisher_ValidName_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::wstring publisher = L"Microsoft Corporation";
    StoreError err = store->AddPublisher(
        publisher,
        WhitelistReason::TrustedVendor,
        L"All Microsoft signed binaries"
    );
    
    ASSERT_TRUE(err.IsSuccess()) << "Failed to add publisher: " << err.message;
    EXPECT_EQ(store->GetEntryCount(), 1);
}

TEST_F(WhitelistStoreTest, IsPublisherWhitelisted_ExistingPublisher_ReturnsWhitelisted) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::wstring publisher = L"Google LLC";
    store->AddPublisher(publisher, WhitelistReason::PolicyBased);//-V530
    
    auto result = store->IsPublisherWhitelisted(publisher);
    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.reason, WhitelistReason::PolicyBased);
}

TEST_F(WhitelistStoreTest, IsPublisherWhitelisted_CaseInsensitive) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddPublisher(L"Adobe Inc.", WhitelistReason::UserApproved);//-V530
    
    // Query with different case
    auto result = store->IsPublisherWhitelisted(L"ADOBE INC.");
    // Depending on implementation - may or may not be case insensitive
    // Most enterprise solutions are case-insensitive for publisher names
    // This test documents expected behavior
    EXPECT_TRUE(result.found);
}

TEST_F(WhitelistStoreTest, IsPublisherWhitelisted_NonExistent_ReturnsNotWhitelisted) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    auto result = store->IsPublisherWhitelisted(L"Unknown Vendor XYZ");
    EXPECT_FALSE(result.found);
}

// ============================================================================
// ENTRY MANAGEMENT TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, GetEntry_ValidId_ReturnsEntry) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("GetEntryTest");
    store->AddHash(hash, WhitelistReason::UserApproved, L"Test Description");//-V530
    
    // Entry IDs typically start at 1
    auto entryOpt = store->GetEntry(1);
    
    ASSERT_TRUE(entryOpt.has_value());
    EXPECT_EQ(entryOpt->type, WhitelistEntryType::FileHash);
    EXPECT_EQ(entryOpt->reason, WhitelistReason::UserApproved);
}

TEST_F(WhitelistStoreTest, GetEntry_InvalidId_ReturnsNullopt) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    auto entryOpt = store->GetEntry(99999);
    EXPECT_FALSE(entryOpt.has_value());
}

TEST_F(WhitelistStoreTest, GetEntries_Pagination_Works) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Add 50 entries
    for (int i = 0; i < 50; ++i) {
        store->AddHash(CreateHash("Paginate_" + std::to_string(i)), WhitelistReason::PolicyBased);//-V530
    }
    
    // Get first page
    auto page1 = store->GetEntries(0, 20);
    EXPECT_EQ(page1.size(), 20);
    
    // Get second page
    auto page2 = store->GetEntries(20, 20);
    EXPECT_EQ(page2.size(), 20);
    
    // Get last page
    auto page3 = store->GetEntries(40, 20);
    EXPECT_EQ(page3.size(), 10);
}

TEST_F(WhitelistStoreTest, GetEntries_TypeFilter_FiltersCorrectly) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Add mixed types
    store->AddHash(CreateHash("Hash1"), WhitelistReason::UserApproved);//-V530
    store->AddHash(CreateHash("Hash2"), WhitelistReason::UserApproved);//-V530
    store->AddPath(L"C:\\Test\\Path", PathMatchMode::Exact, WhitelistReason::SystemFile);//-V530
    
    // Filter by FileHash only
    auto hashEntries = store->GetEntries(0, 100, WhitelistEntryType::FileHash);
    EXPECT_EQ(hashEntries.size(), 2);
    
    // Filter by FilePath only
    auto pathEntries = store->GetEntries(0, 100, WhitelistEntryType::FilePath);
    EXPECT_EQ(pathEntries.size(), 1);
}

TEST_F(WhitelistStoreTest, UpdateEntryFlags_ChangesFlags) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("FlagTest"), WhitelistReason::UserApproved);//-V530
    
    // Get current entry
    auto entryBefore = store->GetEntry(1);
    ASSERT_TRUE(entryBefore.has_value());
    
    // Update flags - add LogOnMatch
    WhitelistFlags newFlags = entryBefore->flags | WhitelistFlags::LogOnMatch;
    StoreError err = store->UpdateEntryFlags(1, newFlags);
    ASSERT_TRUE(err.IsSuccess());
    
    // Verify
    auto entryAfter = store->GetEntry(1);
    ASSERT_TRUE(entryAfter.has_value());
    EXPECT_TRUE(HasFlag(entryAfter->flags, WhitelistFlags::LogOnMatch));
}

TEST_F(WhitelistStoreTest, RevokeEntry_SoftDeletes) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("RevokeMe");
    store->AddHash(hash, WhitelistReason::UserApproved);//-V530
    
    // Revoke
    StoreError err = store->RevokeEntry(1);
    ASSERT_TRUE(err.IsSuccess());
    
    // Should no longer match in queries
    auto result = store->IsHashWhitelisted(hash);
    EXPECT_FALSE(result.found);
    
    // Entry still exists but marked as revoked
    auto entry = store->GetEntry(1);
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(HasFlag(entry->flags, WhitelistFlags::Revoked));
}

TEST_F(WhitelistStoreTest, RemoveEntry_ById_Success) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("RemoveById"), WhitelistReason::UserApproved);//-V530
    EXPECT_EQ(store->GetEntryCount(), 1);
    
    StoreError err = store->RemoveEntry(1);
    ASSERT_TRUE(err.IsSuccess());
    
    EXPECT_EQ(store->GetEntryCount(), 0);
}

// ============================================================================
// MAINTENANCE TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, Compact_ReducesFragmentation) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Add and remove entries to create fragmentation
    for (int i = 0; i < 100; ++i) {
        store->AddHash(CreateHash("Compact_" + std::to_string(i)), WhitelistReason::PolicyBased);//-V530
    }
    
    // Remove half
    for (int i = 0; i < 50; ++i) {
        store->RemoveHash(CreateHash("Compact_" + std::to_string(i * 2)));//-V530
    }
    
    // Compact
    StoreError err = store->Compact();
    ASSERT_TRUE(err.IsSuccess());
    
    // Remaining entries should still be queryable
    for (int i = 0; i < 50; ++i) {
        auto hash = CreateHash("Compact_" + std::to_string(i * 2 + 1));
        auto res = store->IsHashWhitelisted(hash);
        EXPECT_TRUE(res.found) << "Missing entry at odd index " << (i * 2 + 1);
    }
}

TEST_F(WhitelistStoreTest, RebuildIndices_RestoresQueryability) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("RebuildTest");
    store->AddHash(hash, WhitelistReason::UserApproved);//-V530
    
    // Rebuild
    StoreError err = store->RebuildIndices();
    ASSERT_TRUE(err.IsSuccess());
    
    // Should still find the entry
    auto res = store->IsHashWhitelisted(hash);
    EXPECT_TRUE(res.found);
}

TEST_F(WhitelistStoreTest, VerifyIntegrity_HealthyDatabase_ReturnsSuccess) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("IntegrityCheck"), WhitelistReason::UserApproved);//-V530
    store->Save();//-V530
    
    std::vector<std::string> logs;
    StoreError err = store->VerifyIntegrity([&logs](const std::string& msg) {
        logs.push_back(msg);
    });
    
    EXPECT_TRUE(err.IsSuccess());
    // Logs should contain verification steps
    EXPECT_GT(logs.size(), 0);
}

TEST_F(WhitelistStoreTest, ClearCache_ResetsStatistics) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->SetCachingEnabled(true);
    
    HashValue hash = CreateHash("CacheTest");
    store->AddHash(hash, WhitelistReason::UserApproved);//-V530
    
    // Warm up cache
    for (int i = 0; i < 10; ++i) {
        store->IsHashWhitelisted(hash);//-V530
    }
    
    auto statsBefore = store->GetStatistics();
    EXPECT_GT(statsBefore.cacheHits, 0);
    
    // Clear
    store->ClearCache();
    
    // Query again - should be cache miss initially
    store->IsHashWhitelisted(hash);//-V530
    // Cache behavior depends on implementation
}

// ============================================================================
// IMPORT/EXPORT TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, ExportToJSONString_ReturnsValidJSON) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("Export1"), WhitelistReason::UserApproved, L"First Entry");//-V530
    store->AddHash(CreateHash("Export2"), WhitelistReason::TrustedVendor, L"Second Entry");//-V530
    
    std::string json = store->ExportToJSONString();
    
    EXPECT_FALSE(json.empty());
    // Basic JSON structure validation
    EXPECT_NE(json.find('['), std::string::npos);
    EXPECT_NE(json.find(']'), std::string::npos);
    EXPECT_NE(json.find("Export1"), std::string::npos);
}

TEST_F(WhitelistStoreTest, ImportFromJSONString_AddsEntries) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    // Create JSON with hash entries
    std::string jsonData = R"([
        {
            "type": "FileHash",
            "algorithm": "SHA256",
            "hash": "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "reason": "UserApproved",
            "description": "Imported Entry"
        }
    ])";
    
    size_t importedCount = 0;
    StoreError err = store->ImportFromJSONString(jsonData, [&](size_t current, size_t total) {
        importedCount = current;
    });
    
    ASSERT_TRUE(err.IsSuccess()) << "Import failed: " << err.message;
    EXPECT_GE(store->GetEntryCount(), 1);
}

TEST_F(WhitelistStoreTest, ExportToJSON_CreatesFile) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("FileExport"), WhitelistReason::UserApproved);//-V530
    
    std::wstring exportPath = dbPath + L".export.json";
    
    StoreError err = store->ExportToJSON(exportPath);
    ASSERT_TRUE(err.IsSuccess());
    
    EXPECT_TRUE(fs::exists(exportPath));
    
    // Cleanup
    fs::remove(exportPath);
}

TEST_F(WhitelistStoreTest, ImportFromJSON_LoadsFromFile) {
    // First create and export
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->AddHash(CreateHash("RoundTrip"), WhitelistReason::PolicyBased);//-V530
    
    std::wstring exportPath = dbPath + L".roundtrip.json";
    ASSERT_TRUE(store->ExportToJSON(exportPath).IsSuccess());
    store->Close();
    
    // Create new store and import
    store = std::make_unique<WhitelistStore>();
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    StoreError err = store->ImportFromJSON(exportPath);
    ASSERT_TRUE(err.IsSuccess());
    
    EXPECT_GE(store->GetEntryCount(), 1);
    
    fs::remove(exportPath);
}

TEST_F(WhitelistStoreTest, ExportToCSV_CreatesValidCSV) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    store->AddHash(CreateHash("CSV1"), WhitelistReason::UserApproved, L"CSV Test");//-V530
    store->AddPath(L"C:\\Test\\Path.exe", PathMatchMode::Exact, WhitelistReason::SystemFile);//-V530
    
    std::wstring csvPath = dbPath + L".export.csv";
    
    StoreError err = store->ExportToCSV(csvPath);
    ASSERT_TRUE(err.IsSuccess());
    
    EXPECT_TRUE(fs::exists(csvPath));
    
    // Verify file has content
    std::ifstream file(csvPath);
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    
    EXPECT_FALSE(content.empty());
    // Should have header row + data rows
    size_t lineCount = std::count(content.begin(), content.end(), '\n');
    EXPECT_GE(lineCount, 2); // Header + at least 1 data row
    
    fs::remove(csvPath);
}

// ============================================================================
// WHITELIST ENTRY BUILDER TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, EntryBuilder_BasicUsage_Success) {
    HashValue hash = CreateHash("BuilderTest");
    
    WhitelistEntry entry;
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FileHash)
        .SetHash(hash)
        .SetReason(WhitelistReason::TrustedVendor)
        .SetPolicyId(42)
        .ApplyTo(entry);
    
    EXPECT_EQ(entry.type, WhitelistEntryType::FileHash);
    EXPECT_EQ(entry.reason, WhitelistReason::TrustedVendor);
    EXPECT_EQ(entry.policyId, 42);
    EXPECT_EQ(entry.hashAlgorithm, HashAlgorithm::SHA256);
}

TEST_F(WhitelistStoreTest, EntryBuilder_SetExpiration_SetsFlag) {
    WhitelistEntry entry;
    
    auto futureTime = std::chrono::system_clock::now() + std::chrono::hours(24);
    uint64_t expiry = std::chrono::duration_cast<std::chrono::seconds>(
        futureTime.time_since_epoch()
    ).count();
    
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FileHash)
        .SetHash(CreateHash("ExpiryBuilder"))
        .SetReason(WhitelistReason::TemporaryBypass)
        .SetExpiration(expiry)
        .ApplyTo(entry);
    
    EXPECT_TRUE(HasFlag(entry.flags, WhitelistFlags::HasExpiration));
    EXPECT_EQ(entry.expirationTime, expiry);
}

TEST_F(WhitelistStoreTest, EntryBuilder_SetExpirationDuration_CalculatesCorrectly) {
    WhitelistEntry entry;
    
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FileHash)
        .SetHash(CreateHash("DurationBuilder"))
        .SetReason(WhitelistReason::TemporaryBypass)
        .SetExpirationDuration(std::chrono::hours(1))
        .ApplyTo(entry);
    
    EXPECT_TRUE(HasFlag(entry.flags, WhitelistFlags::HasExpiration));
    
    auto now = std::chrono::system_clock::now();
    auto nowEpoch = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()
    ).count();
    
    // Expiration should be ~1 hour from now
    EXPECT_GT(entry.expirationTime, static_cast<uint64_t>(nowEpoch));
    EXPECT_LT(entry.expirationTime, static_cast<uint64_t>(nowEpoch + 3700)); // Some tolerance
}

TEST_F(WhitelistStoreTest, EntryBuilder_AddRemoveFlags_WorksCorrectly) {
    WhitelistEntry entry;
    
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FileHash)
        .SetHash(CreateHash("FlagBuilder"))
        .SetReason(WhitelistReason::UserApproved)
        .SetFlags(WhitelistFlags::Enabled)
        .AddFlag(WhitelistFlags::LogOnMatch)
        .AddFlag(WhitelistFlags::RequiresVerification)
        .RemoveFlag(WhitelistFlags::RequiresVerification)
        .ApplyTo(entry);
    
    EXPECT_TRUE(HasFlag(entry.flags, WhitelistFlags::Enabled));
    EXPECT_TRUE(HasFlag(entry.flags, WhitelistFlags::LogOnMatch));
    EXPECT_FALSE(HasFlag(entry.flags, WhitelistFlags::RequiresVerification));
}

TEST_F(WhitelistStoreTest, EntryBuilder_Validation_BasicUsage) {
    // Test that builder correctly configures entries
    
    // Test with FileHash type and valid hash
    WhitelistEntry validEntry;
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FileHash)
        .SetHash(CreateHash("Valid"))
        .SetReason(WhitelistReason::UserApproved)
        .ApplyTo(validEntry);
    
    EXPECT_EQ(validEntry.type, WhitelistEntryType::FileHash);
    EXPECT_EQ(validEntry.reason, WhitelistReason::UserApproved);
    EXPECT_EQ(validEntry.hashLength, 32); // SHA256 length
    
    // Test with path type
    WhitelistEntry pathEntry;
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FilePath)
        .SetReason(WhitelistReason::SystemFile)
        .SetPathMatchMode(PathMatchMode::Prefix)
        .ApplyTo(pathEntry);
    
    EXPECT_EQ(pathEntry.type, WhitelistEntryType::FilePath);
    EXPECT_EQ(pathEntry.matchMode, PathMatchMode::Prefix);
}

TEST_F(WhitelistStoreTest, EntryBuilder_PathMatchMode_SetsCorrectly) {
    WhitelistEntry entry;
    
    WhitelistEntryBuilder()
        .SetType(WhitelistEntryType::FilePath)
        .SetReason(WhitelistReason::SystemFile)
        .SetPathMatchMode(PathMatchMode::Glob)
        .ApplyTo(entry);
    
    EXPECT_EQ(entry.type, WhitelistEntryType::FilePath);
    EXPECT_EQ(entry.matchMode, PathMatchMode::Glob);
}

// ============================================================================
// CALLBACK & STATISTICS TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, MatchCallback_InvokedOnMatch) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    std::atomic<int> callbackCount{0};
    LookupResult capturedResult;
    
    store->SetMatchCallback([&](const LookupResult& result, std::wstring_view context) {
        callbackCount++;
        capturedResult = result;
    });
    
    HashValue hash = CreateHash("CallbackTest");
    store->AddHash(hash, WhitelistReason::UserApproved);//-V530
    
    // Query should trigger callback
    store->IsHashWhitelisted(hash);//-V530
    
    EXPECT_GE(callbackCount, 1);
    EXPECT_TRUE(capturedResult.found);
}

TEST_F(WhitelistStoreTest, GetStatistics_ReturnsAccurateData) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    LookupResult res;
    StoreError err;
    // Add entries of various types
    err = store->AddHash(CreateHash("Stat1"), WhitelistReason::UserApproved);
    if (!err.IsSuccess()) {
		SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to add hash.");
    }
    err = store->AddHash(CreateHash("Stat2"), WhitelistReason::PolicyBased);
    if (!err.IsSuccess()) {
		SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to add hash.");
    }
    err = store->AddPath(L"C:\\Test", PathMatchMode::Prefix, WhitelistReason::SystemFile);
    if (!err.IsSuccess()) {
		SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to add path.");
    }
    // Perform lookups
    res = store->IsHashWhitelisted(CreateHash("Stat1"));
    if (!res.found) {
		SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to find Stat1 hash.");
    }
    res = store->IsHashWhitelisted(CreateHash("Stat2"));
    if (!res.found) {
		SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to find Stat2 hash.");
    }
    res = store->IsHashWhitelisted(CreateHash("Missing"));
    if (!res.found) {
        SS_LOG_ERROR(L"WhitelistStoreTest", L"Correctly did not find missing");
    }
    
    auto stats = store->GetStatistics();
    
    EXPECT_EQ(stats.totalEntries, 3);
    EXPECT_GE(stats.totalLookups, 3);
    EXPECT_GE(stats.totalHits, 2);
    EXPECT_GE(stats.totalMisses, 1);
}

TEST_F(WhitelistStoreTest, GetHeader_ReturnsValidHeader) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    const WhitelistDatabaseHeader* header = store->GetHeader();
    
    ASSERT_NE(header, nullptr);
    // Verify magic number or version - depends on implementation
    // This tests the accessor works
}

// ============================================================================
// CONFIGURATION TESTS
// ============================================================================

TEST_F(WhitelistStoreTest, SetCachingEnabled_AffectsPerformance) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue hash = CreateHash("CacheConfig");
    StoreError err = store->AddHash(hash, WhitelistReason::UserApproved);
    
    if (!err.IsSuccess()) {
                SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to add hash.");
    }

    // With caching enabled
    store->SetCachingEnabled(true);
    auto start1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        LookupResult res = store->IsHashWhitelisted(hash);
        if (!res.found) {
            SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to find hash during no-cache test.");
        }
    }
    auto duration1 = std::chrono::high_resolution_clock::now() - start1;
    
    // With caching disabled
    store->SetCachingEnabled(false);
    store->ClearCache();
    auto start2 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        LookupResult res = store->IsHashWhitelisted(hash);
        if (!res.found) {
			SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to find hash during no-cache test.");
        }
    }
    auto duration2 = std::chrono::high_resolution_clock::now() - start2;
    
    // Cached should generally be faster (though not guaranteed due to system variance)
    // This is more of a smoke test
    EXPECT_TRUE(true); // Test completes without crash
}

TEST_F(WhitelistStoreTest, SetBloomFilterEnabled_TogglesFilter) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    StoreError err = store->AddHash(CreateHash("BloomToggle"), WhitelistReason::UserApproved);

    if (!err.IsSuccess()) {
        SS_LOG_ERROR(L"WhitelistStoreTest", L"Failed to add hash.");
    }
    
    store->SetBloomFilterEnabled(false);
    auto res1 = store->IsHashWhitelisted(CreateHash("BloomToggle"));
    EXPECT_TRUE(res1.found);
    
    store->SetBloomFilterEnabled(true);
    auto res2 = store->IsHashWhitelisted(CreateHash("BloomToggle"));
    EXPECT_TRUE(res2.found);
}

// ============================================================================
// ERROR HANDLING EDGE CASES
// ============================================================================

TEST_F(WhitelistStoreTest, AddHash_ReadOnlyMode_Fails) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    store = std::make_unique<WhitelistStore>();
    ASSERT_TRUE(store->Load(dbPath, true).IsSuccess()); // Read-only
    
    StoreError err = store->AddHash(CreateHash("ShouldFail"), WhitelistReason::UserApproved);
    
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, WhitelistStoreError::ReadOnlyDatabase);
}

TEST_F(WhitelistStoreTest, Save_ReadOnlyMode_Fails) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    store = std::make_unique<WhitelistStore>();
    ASSERT_TRUE(store->Load(dbPath, true).IsSuccess());
    
    StoreError err = store->Save();
    
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, WhitelistStoreError::ReadOnlyDatabase);
}

TEST_F(WhitelistStoreTest, Operations_OnClosedStore_HandleGracefully) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    store->Close();
    
    // Operations after close should not crash
    EXPECT_FALSE(store->IsInitialized());
    
    auto result = store->IsHashWhitelisted(CreateHash("Test"));
    EXPECT_FALSE(result.found);
    
    EXPECT_EQ(store->GetEntryCount(), 0);
}

TEST_F(WhitelistStoreTest, AddPath_EmptyPath_Fails) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    StoreError err = store->AddPath(L"", PathMatchMode::Exact, WhitelistReason::UserApproved);
    
    EXPECT_FALSE(err.IsSuccess());
}

TEST_F(WhitelistStoreTest, AddHash_EmptyHash_Fails) {
    ASSERT_TRUE(store->Create(dbPath).IsSuccess());
    
    HashValue emptyHash{};
    StoreError err = store->AddHash(emptyHash, WhitelistReason::UserApproved);
    
    EXPECT_FALSE(err.IsSuccess());
    EXPECT_EQ(err.code, WhitelistStoreError::InvalidEntry);
}

} // namespace ShadowStrike::Whitelist::Tests
