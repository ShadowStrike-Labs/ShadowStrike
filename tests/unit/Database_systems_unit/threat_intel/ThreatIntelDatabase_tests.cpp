/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include"pch.h"
// ============================================================================
// THREAT INTEL DATABASE UNIT TESTS - PRODUCTION GRADE
// ============================================================================
// 
// ShadowStrike Antivirus Engine - Enterprise Edition
// 
// Comprehensive unit tests for memory-mapped database implementation
// Coverage: Creation, Open/Close, Entry Management, Extension, Compaction,
//           Integrity Verification, Thread Safety, Error Handling
// 
// Test Categories:
// 1. Database Creation Tests
// 2. Database Open/Close Lifecycle Tests
// 3. Entry Allocation Tests (Single/Batch)
// 4. Database Extension Tests
// 5. Database Compaction Tests
// 6. Integrity Verification Tests (CRC32)
// 7. Flush/Sync Operation Tests
// 8. Read-Only Mode Tests
// 9. Error Handling Tests
// 10. Thread Safety Tests
// 11. Memory Mapping Tests
// 12. Boundary Condition Tests
// 13. Statistics Tests
// 14. Corruption Recovery Tests
// ============================================================================

#include <gtest/gtest.h>
#include "PhantomCore/ThreatIntel/ThreatIntelDatabase.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelFormat.hpp"
#include <filesystem>
#include <fstream>
#include <vector>
#include <thread>
#include <random>
#include <chrono>

// Guarded: pch.h already defines both, so redefining them here was 2 C4005 warnings.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

using namespace ShadowStrike::ThreatIntel;

// ============================================================================
// TEST FIXTURE - THREAT INTEL DATABASE BASE
// ============================================================================

class ThreatIntelDatabaseTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create unique test database path for each test
        testDbPath = GetTempDatabasePath();
        
        // Clean up any existing file
        CleanupDatabase(testDbPath);
        
        rng.seed(42);
    }

    void TearDown() override {
        // Cleanup test database
        CleanupDatabase(testDbPath);
        
        // Cleanup any additional databases created during test
        for (const auto& path : createdDatabases) {
            CleanupDatabase(path);
        }
        createdDatabases.clear();
    }

    // Helper: Get temporary database path
    std::wstring GetTempDatabasePath() {
        static std::atomic<size_t> counter{0};
        size_t id = counter.fetch_add(1);
        
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        
        std::wstring dbPath = tempPath;
        dbPath += L"ShadowStrike_Test_";
        dbPath += std::to_wstring(GetCurrentProcessId());
        dbPath += L"_";
        dbPath += std::to_wstring(id);
        dbPath += L".tidb";
        
        return dbPath;
    }

    // Helper: Register database for cleanup
    std::wstring RegisterDatabase() {
        auto path = GetTempDatabasePath();
        createdDatabases.push_back(path);
        return path;
    }

    // Helper: Cleanup database file
    void CleanupDatabase(const std::wstring& path) {
        try {
            if (std::filesystem::exists(path)) {
                std::filesystem::remove(path);
            }
        } catch (...) {
            // Ignore cleanup errors
        }
    }

    // Helper: Create minimal valid database file
    bool CreateMinimalDatabase(const std::wstring& path, size_t size = DATABASE_MIN_SIZE) {
        try {
            HANDLE hFile = CreateFileW(
                path.c_str(),
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
            
            LARGE_INTEGER fileSize;
            fileSize.QuadPart = static_cast<LONGLONG>(size);
            
            if (!SetFilePointerEx(hFile, fileSize, nullptr, FILE_BEGIN)) {
                CloseHandle(hFile);
                return false;
            }
            
            if (!SetEndOfFile(hFile)) {
                CloseHandle(hFile);
                return false;
            }
            
            CloseHandle(hFile);
            return true;
        } catch (...) {
            return false;
        }
    }

    // Helper: Corrupt database header
    void CorruptDatabaseHeader(const std::wstring& path) {
        std::ofstream file(path, std::ios::binary | std::ios::in | std::ios::out);
        if (file.is_open()) {
            // Corrupt magic number
            uint32_t badMagic = 0xDEADBEEF;
            file.write(reinterpret_cast<const char*>(&badMagic), sizeof(badMagic));
            file.close();
        }
    }

    // Helper: Verify database file exists
    bool DatabaseExists(const std::wstring& path) {
        return std::filesystem::exists(path);
    }

    // Helper: Get file size
    size_t GetFileSize(const std::wstring& path) {
        try {
            return std::filesystem::file_size(path);
        } catch (...) {
            return 0;
        }
    }

    // Helper: Create IOC entry for testing
    IOCEntry CreateTestEntry(IOCType type, uint32_t value) {
        IOCEntry entry{};
        entry.type = type;
        entry.reputation = ReputationLevel::Malicious;
        entry.confidence = ConfidenceLevel::High;
        entry.category = ThreatCategory::Malware;
        
        if (type == IOCType::IPv4) {
            IPv4Address addr;
            addr.address = value;
            entry.value.ipv4 = addr;
           
        }
        
        return entry;
    }

    std::wstring testDbPath;
    std::vector<std::wstring> createdDatabases;
    std::mt19937 rng;
};

// ============================================================================
// CATEGORY 1: DATABASE CREATION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Create_NewDatabase_DefaultConfig) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    
    // Verify database is open
    EXPECT_TRUE(db.IsOpen());
    EXPECT_FALSE(db.IsReadOnly());
    
    // Verify file was created
    EXPECT_TRUE(DatabaseExists(testDbPath));
    
    // Verify header is valid
    const auto* header = db.GetHeader();
    ASSERT_NE(header, nullptr);
    EXPECT_EQ(header->magic, THREATINTEL_DB_MAGIC);
    EXPECT_EQ(header->versionMajor, THREATINTEL_DB_VERSION_MAJOR);
    
    db.Close();
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, Create_NewDatabase_CustomSize) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = 10 * 1024 * 1024; // 10 MB
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    
    // Verify size
    size_t mappedSize = db.GetMappedSize();
    EXPECT_GE(mappedSize, config.initialSize);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Create_NewDatabase_MinimumSize) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = DATABASE_MIN_SIZE;
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    
    EXPECT_TRUE(db.IsOpen());
    EXPECT_GE(db.GetMappedSize(), DATABASE_MIN_SIZE);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Create_NewDatabase_VerySmallSize) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = 1024; // Too small
    
    ThreatIntelDatabase db;
    // Should handle gracefully (clamp to minimum)
    EXPECT_TRUE(db.Open(config));
    
    if (db.IsOpen()) {
        EXPECT_GE(db.GetMappedSize(), DATABASE_MIN_SIZE);
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, Create_EmptyPath_ShouldFail) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(L"");
    
    ThreatIntelDatabase db;
    EXPECT_FALSE(db.Open(config));
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, Create_InvalidPath_ShouldFail) {
    // Path with invalid characters
    DatabaseConfig config = DatabaseConfig::CreateDefault(L"C:\\Invalid<>Path\\test.tidb");
    
    ThreatIntelDatabase db;
    EXPECT_FALSE(db.Open(config));
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, Create_VeryLongPath_ShouldFail) {
    // Path exceeding Windows limits
    std::wstring longPath(40000, L'A');
    longPath += L".tidb";
    
    DatabaseConfig config = DatabaseConfig::CreateDefault(longPath);
    
    ThreatIntelDatabase db;
    EXPECT_FALSE(db.Open(config));
}

TEST_F(ThreatIntelDatabaseTest, Create_SizeExceedingMaximum_ShouldFail) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = DATABASE_MAX_SIZE + 1;
    
    ThreatIntelDatabase db;
    EXPECT_FALSE(db.Open(config));
}

TEST_F(ThreatIntelDatabaseTest, Create_WithMaxSizeLimit) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = 10 * 1024 * 1024; // 10 MB
    config.maxSize = 50 * 1024 * 1024;     // 50 MB max
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    EXPECT_TRUE(db.IsOpen());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Create_MultipleSequentialCreates) {
    // Test creating multiple databases sequentially
    for (size_t i = 0; i < 5; ++i) {
        auto path = RegisterDatabase();
        DatabaseConfig config = DatabaseConfig::CreateDefault(path);
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        EXPECT_TRUE(db.IsOpen());
        
        db.Close();
        EXPECT_FALSE(db.IsOpen());
    }
}

// ============================================================================
// CATEGORY 2: DATABASE OPEN/CLOSE LIFECYCLE TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, OpenExisting_ValidDatabase) {
    // Create database first
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open existing
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        EXPECT_TRUE(db.IsOpen());
        
        const auto* header = db.GetHeader();
        ASSERT_NE(header, nullptr);
        EXPECT_EQ(header->magic, THREATINTEL_DB_MAGIC);
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, OpenExisting_ReadOnlyMode) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        EXPECT_TRUE(db.IsOpen());
        EXPECT_TRUE(db.IsReadOnly());
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, OpenExisting_NonExistentFile_CreateIfNotExists) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.createIfNotExists = true;
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    EXPECT_TRUE(db.IsOpen());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, OpenExisting_NonExistentFile_DontCreate) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.createIfNotExists = false;
    
    ThreatIntelDatabase db;
    EXPECT_FALSE(db.Open(config));
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, Close_AlreadyClosed) {
    ThreatIntelDatabase db;
    
    // Close without opening
    EXPECT_NO_THROW(db.Close());
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, Close_MultipleCalls) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.Close();
    EXPECT_FALSE(db.IsOpen());
    
    // Close again
    EXPECT_NO_THROW(db.Close());
    EXPECT_FALSE(db.IsOpen());
}

TEST_F(ThreatIntelDatabaseTest, OpenClose_Cycle) {
    ThreatIntelDatabase db;
    
    // Multiple open/close cycles
    for (size_t i = 0; i < 5; ++i) {
        EXPECT_TRUE(db.Open(testDbPath));
        EXPECT_TRUE(db.IsOpen());
        
        db.Close();
        EXPECT_FALSE(db.IsOpen());
    }
}

TEST_F(ThreatIntelDatabaseTest, Open_AlreadyOpen_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Try to open again
    EXPECT_FALSE(db.Open(testDbPath));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Destructor_ClosesDatabase) {
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        EXPECT_TRUE(db.IsOpen());
        // Destructor should close automatically
    }
    
    // Database should be accessible again
    ThreatIntelDatabase db2;
    EXPECT_TRUE(db2.Open(testDbPath));
    db2.Close();
}

// ============================================================================
// CATEGORY 3: ENTRY ALLOCATION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, AllocateEntry_Single) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t index = db.AllocateEntry();
    EXPECT_EQ(index, 0);
    EXPECT_EQ(db.GetEntryCount(), 1);
    
    // Allocate another
    index = db.AllocateEntry();
    EXPECT_EQ(index, 1);
    EXPECT_EQ(db.GetEntryCount(), 2);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, AllocateEntry_ReadOnlyMode_ShouldFail) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        size_t index = db.AllocateEntry();
        EXPECT_EQ(index, SIZE_MAX); // Allocation should fail
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, AllocateEntries_Batch) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t count = 100;
    size_t startIndex = db.AllocateEntries(count);
    
    EXPECT_EQ(startIndex, 0);
    EXPECT_EQ(db.GetEntryCount(), count);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, AllocateEntries_ZeroCount) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t index = db.AllocateEntries(0);
    EXPECT_EQ(index, SIZE_MAX); // Should fail
    EXPECT_EQ(db.GetEntryCount(), 0);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, AllocateEntries_LargeBatch) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t count = 10000;
    size_t startIndex = db.AllocateEntries(count);
    
    EXPECT_EQ(startIndex, 0);
    EXPECT_EQ(db.GetEntryCount(), count);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, AllocateEntries_ExcessiveBatch_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Try to allocate more than reasonable limit
    size_t count = 20'000'000; // 20 million - exceeds kMaxBatchAllocation
    size_t index = db.AllocateEntries(count);
    
    EXPECT_EQ(index, SIZE_MAX); // Should fail
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, GetEntry_ValidIndex) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate entry
    size_t index = db.AllocateEntry();
    
    // Get mutable entry
    IOCEntry* entry = db.GetMutableEntry(index);
    ASSERT_NE(entry, nullptr);
    
    // Set data
    entry->type = IOCType::IPv4;
    entry->reputation = ReputationLevel::Malicious;
    
    // Get const entry
    const IOCEntry* constEntry = db.GetEntry(index);
    ASSERT_NE(constEntry, nullptr);
    EXPECT_EQ(constEntry->type, IOCType::IPv4);
    EXPECT_EQ(constEntry->reputation, ReputationLevel::Malicious);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, GetEntry_InvalidIndex) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Try to get entry at index 0 when no entries allocated
    const IOCEntry* entry = db.GetEntry(0);
    EXPECT_EQ(entry, nullptr);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, GetEntry_OutOfBounds) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntry();
    
    // Try to get entry beyond allocated range
    const IOCEntry* entry = db.GetEntry(100);
    EXPECT_EQ(entry, nullptr);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, SetEntryCount_Increase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_TRUE(db.SetEntryCount(50));
    EXPECT_EQ(db.GetEntryCount(), 50);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, SetEntryCount_Decrease) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(100);
    EXPECT_EQ(db.GetEntryCount(), 100);
    
    EXPECT_TRUE(db.SetEntryCount(50));
    EXPECT_EQ(db.GetEntryCount(), 50);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, IncrementEntryCount_Single) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t count = db.IncrementEntryCount();
    EXPECT_EQ(count, 1);
    EXPECT_EQ(db.GetEntryCount(), 1);
    
    count = db.IncrementEntryCount();
    EXPECT_EQ(count, 2);
    
    db.Close();
}

// ============================================================================
// CATEGORY 4: DATABASE EXTENSION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Extend_IncreaseSize) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t originalSize = db.GetMappedSize();
    size_t newSize = originalSize + 10 * 1024 * 1024; // +10 MB
    
    EXPECT_TRUE(db.Extend(newSize));
    EXPECT_GE(db.GetMappedSize(), newSize);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Extend_ReadOnlyMode_ShouldFail) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        size_t originalSize = db.GetMappedSize();
        EXPECT_FALSE(db.Extend(originalSize + 1024 * 1024));
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, Extend_ZeroSize_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_FALSE(db.Extend(0));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Extend_SmallerSize_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t currentSize = db.GetMappedSize();
    
    // Try to "extend" to smaller size
    EXPECT_FALSE(db.Extend(currentSize / 2));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Extend_ExceedMaxSize_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Try to extend beyond max
    EXPECT_FALSE(db.Extend(DATABASE_MAX_SIZE + 1));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ExtendBy_AddBytes) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t originalSize = db.GetMappedSize();
    size_t additionalBytes = 5 * 1024 * 1024; // 5 MB
    
    EXPECT_TRUE(db.ExtendBy(additionalBytes));
    EXPECT_GE(db.GetMappedSize(), originalSize + additionalBytes);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ExtendBy_ZeroBytes_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_FALSE(db.ExtendBy(0));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ExtendBy_Overflow_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Try to add bytes that would overflow
    EXPECT_FALSE(db.ExtendBy(SIZE_MAX));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, EnsureCapacity_AdditionalEntries) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Fill the database to near capacity first to force extension
    size_t originalMax = db.GetMaxEntries();
    size_t currentCount = db.GetEntryCount();
    
    // Fill to near capacity (leave space for just a few entries)
    if (originalMax > currentCount + 10) {
        size_t toAllocate = originalMax - currentCount - 5; // Leave only 5 slots
        db.AllocateEntries(toAllocate);
    }
    
    size_t preExtendMax = db.GetMaxEntries();
    
    // Now request 1000 additional entries - should force extension
    EXPECT_TRUE(db.EnsureCapacity(1000));
    
    size_t newMax = db.GetMaxEntries();
    
    // After EnsureCapacity, we should have at least 1000 available
    size_t available = newMax - db.GetEntryCount();
    EXPECT_GE(available, 1000);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, EnsureCapacity_ZeroEntries_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_FALSE(db.EnsureCapacity(0));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, EnsureCapacity_AlreadySufficient) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t maxEntries = db.GetMaxEntries();
    
    // Request capacity less than already available
    EXPECT_TRUE(db.EnsureCapacity(10));
    
    // Size should not change
    EXPECT_EQ(db.GetMaxEntries(), maxEntries);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, EnsureCapacity_ExcessiveRequest_ShouldFail) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Request more than kMaxAdditionalEntries
    EXPECT_FALSE(db.EnsureCapacity(200'000'000));
    
    db.Close();
}

// ============================================================================
// CATEGORY 5: DATABASE COMPACTION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Compact_NoDeletedEntries) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate some entries
    db.AllocateEntries(100);
    
    size_t reclaimed = db.Compact();
    EXPECT_EQ(reclaimed, 0); // No entries deleted, nothing reclaimed
    EXPECT_EQ(db.GetEntryCount(), 100);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Compact_WithDeletedEntries) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate entries
    db.AllocateEntries(100);
    
	// Mark some as sinkholed (to be deleted)
    for (size_t i = 0; i < 50; i += 2) {
        IOCEntry* entry = db.GetMutableEntry(i);
        if (entry) {
            entry->flags |= IOCFlags::Sinkholed;
        }
    }
    
    size_t reclaimed = db.Compact();
    EXPECT_GT(reclaimed, 0); // Should reclaim space
    EXPECT_EQ(db.GetEntryCount(), 75); // 100 - 25 deleted = 75
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Compact_AllDeleted) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(50);
    
    // Mark all as deleted
    for (size_t i = 0; i < 50; ++i) {
        IOCEntry* entry = db.GetMutableEntry(i);
        if (entry) {
            entry->flags |= IOCFlags::Sinkholed;
        }
    }
    
    size_t reclaimed = db.Compact();
    EXPECT_GT(reclaimed, 0);
    EXPECT_EQ(db.GetEntryCount(), 0);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Compact_ReadOnlyMode_ShouldFail) {
    // Create and populate database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.AllocateEntries(10);
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        size_t reclaimed = db.Compact();
        EXPECT_EQ(reclaimed, 0); // Should fail in read-only mode
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, Compact_EmptyDatabase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t reclaimed = db.Compact();
    EXPECT_EQ(reclaimed, 0);
    EXPECT_EQ(db.GetEntryCount(), 0);
    
    db.Close();
}

// ============================================================================
// CATEGORY 6: INTEGRITY VERIFICATION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, VerifyIntegrity_ValidDatabase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_TRUE(db.VerifyIntegrity());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, VerifyIntegrity_AfterModification) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Modify database
    db.AllocateEntries(100);
    
    // Update checksum
    EXPECT_TRUE(db.UpdateHeaderChecksum());
    
    // Verify
    EXPECT_TRUE(db.VerifyIntegrity());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, VerifyHeaderChecksum_Valid) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_TRUE(db.VerifyHeaderChecksum());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, VerifyHeaderChecksum_AfterUpdate) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Get mutable header and modify
    auto* header = db.GetMutableHeader();
    ASSERT_NE(header, nullptr);
    header->totalActiveEntries = 42;
    
    // Checksum should be invalid now
    EXPECT_FALSE(db.VerifyHeaderChecksum());
    
    // Update checksum
    EXPECT_TRUE(db.UpdateHeaderChecksum());
    
    // Should be valid now
    EXPECT_TRUE(db.VerifyHeaderChecksum());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, UpdateHeaderChecksum_ReadOnlyMode_ShouldFail) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        EXPECT_FALSE(db.UpdateHeaderChecksum());
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, VerifyOnOpen_CorruptedDatabase) {
    // Create valid database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Corrupt the header
    CorruptDatabaseHeader(testDbPath);
    
    // Try to open with verification
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.verifyOnOpen = true;
        config.createIfNotExists = false;
        
        ThreatIntelDatabase db;
        EXPECT_FALSE(db.Open(config));
    }
}

// ============================================================================
// CATEGORY 7: FLUSH/SYNC OPERATION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Flush_ValidDatabase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate and modify
    db.AllocateEntry();
    
    EXPECT_TRUE(db.Flush());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Flush_ReadOnlyMode_ShouldSucceed) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        // Flush in read-only mode should be no-op but return success
        EXPECT_TRUE(db.Flush());
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, FlushRange_ValidRange) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t offset = 0;
    size_t length = 4096; // One page
    
    EXPECT_TRUE(db.FlushRange(offset, length));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Sync_ValidDatabase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntry();
    
    EXPECT_TRUE(db.Sync());
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Sync_ReadOnlyMode_ShouldSucceed) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        EXPECT_TRUE(db.Sync());
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, FlushOnClose_DataPersists) {
    const uint32_t testValue = 0x12345678;
    
    // Create and modify
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        
        size_t index = db.AllocateEntry();
        IOCEntry* entry = db.GetMutableEntry(index);
        ASSERT_NE(entry, nullptr);
        
        entry->type = IOCType::IPv4;
		entry->value.ipv4.address = testValue;
        
        db.Close(); // Should flush automatically
    }
    
    // Reopen and verify
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        
        const IOCEntry* entry = db.GetEntry(0);
        ASSERT_NE(entry, nullptr);
        EXPECT_EQ(entry->type, IOCType::IPv4);
        EXPECT_EQ(entry->value.ipv4.address, testValue);
        
        db.Close();
    }
}

// ============================================================================
// CATEGORY 8: READ-ONLY MODE TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, ReadOnly_GetOperations) {
    // Create database with data
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.AllocateEntries(10);
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        EXPECT_TRUE(db.IsReadOnly());
        
        // Read operations should work
        EXPECT_EQ(db.GetEntryCount(), 10);
        const IOCEntry* entry = db.GetEntry(0);
        EXPECT_NE(entry, nullptr);
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, ReadOnly_GetMutableHeader_ReturnsNull) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        // Mutable header should be null in read-only mode
        auto* header = db.GetMutableHeader();
        EXPECT_EQ(header, nullptr);
        
        // Const header should work
        const auto* constHeader = db.GetHeader();
        EXPECT_NE(constHeader, nullptr);
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, ReadOnly_GetMutableEntry_ReturnsNull) {
    // Create database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.AllocateEntry();
        db.Close();
    }
    
    // Open read-only
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.readOnly = true;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        // Mutable entry should be null
        IOCEntry* entry = db.GetMutableEntry(0);
        EXPECT_EQ(entry, nullptr);
        
        // Const entry should work
        const IOCEntry* constEntry = db.GetEntry(0);
        EXPECT_NE(constEntry, nullptr);
        
        db.Close();
    }
}

// ============================================================================
// CATEGORY 9: ERROR HANDLING TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, ErrorHandling_OperationsOnClosedDatabase) {
    ThreatIntelDatabase db;
    
    // Operations on closed database should fail gracefully
    EXPECT_EQ(db.AllocateEntry(), SIZE_MAX);
    EXPECT_EQ(db.AllocateEntries(10), SIZE_MAX);
    EXPECT_FALSE(db.SetEntryCount(10));
    EXPECT_EQ(db.IncrementEntryCount(), 0);
    EXPECT_FALSE(db.Extend(1024 * 1024));
    EXPECT_FALSE(db.ExtendBy(1024));
    EXPECT_EQ(db.Compact(), 0);
    EXPECT_TRUE(db.Flush()); // Flush on closed DB is no-op
    EXPECT_EQ(db.GetEntryCount(), 0);
    EXPECT_EQ(db.GetEntry(0), nullptr);
}

TEST_F(ThreatIntelDatabaseTest, ErrorHandling_InvalidOperationSequence) {
    ThreatIntelDatabase db;
    
    // Try operations without opening
    EXPECT_FALSE(db.IsOpen());
    EXPECT_EQ(db.AllocateEntry(), SIZE_MAX);
    
    // Open
    EXPECT_TRUE(db.Open(testDbPath));
    EXPECT_TRUE(db.IsOpen());
    
    // Valid operations
    EXPECT_NE(db.AllocateEntry(), SIZE_MAX);
    
    // Close
    db.Close();
    EXPECT_FALSE(db.IsOpen());
    
    // Operations after close should fail
    EXPECT_EQ(db.AllocateEntry(), SIZE_MAX);
}

TEST_F(ThreatIntelDatabaseTest, ErrorHandling_NoExceptionsThrown) {
    ThreatIntelDatabase db;
    
    // All operations should be noexcept
    EXPECT_NO_THROW({
        db.Open(L"");
        db.Open(L"C:\\Invalid<>Path\\test.db");
        db.AllocateEntry();
        db.AllocateEntries(0);
        db.Close();
        db.Close();
        db.Flush();
        db.VerifyIntegrity();
    });
}

// ============================================================================
// CATEGORY 10: THREAD SAFETY TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, ThreadSafety_ConcurrentReads) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate some entries
    db.AllocateEntries(1000);
    
    std::atomic<size_t> successCount{0};
    std::vector<std::thread> threads;
    
    // Multiple threads reading
    for (size_t i = 0; i < 10; ++i) {
        threads.emplace_back([&db, &successCount]() {
            for (size_t j = 0; j < 100; ++j) {
                const IOCEntry* entry = db.GetEntry(j % 100);
                if (entry != nullptr) {
                    successCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_GT(successCount.load(), 0);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ThreadSafety_ConcurrentWrites) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Pre-allocate space
    db.EnsureCapacity(10000);
    
    std::vector<std::thread> threads;
    constexpr size_t numThreads = 5;
    constexpr size_t entriesPerThread = 100;
    
    // Multiple threads allocating
    for (size_t i = 0; i < numThreads; ++i) {
        threads.emplace_back([&db]() {
            for (size_t j = 0; j < entriesPerThread; ++j) {
                db.AllocateEntry();
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(db.GetEntryCount(), numThreads * entriesPerThread);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ThreadSafety_MixedReadWrite) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.EnsureCapacity(5000);
    
    std::atomic<bool> stopFlag{false};
    std::vector<std::thread> threads;
    
    // Writer threads
    for (size_t i = 0; i < 2; ++i) {
        threads.emplace_back([&db, &stopFlag]() {
            while (!stopFlag.load(std::memory_order_relaxed)) {
                db.AllocateEntry();
                std::this_thread::yield();
            }
        });
    }
    
    // Reader threads
    for (size_t i = 0; i < 3; ++i) {
        threads.emplace_back([&db, &stopFlag]() {
            while (!stopFlag.load(std::memory_order_relaxed)) {
                size_t count = db.GetEntryCount();
                if (count > 0) {
                    db.GetEntry(0);
                }
                std::this_thread::yield();
            }
        });
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    stopFlag.store(true, std::memory_order_relaxed);
    
    for (auto& t : threads) {
        t.join();
    }
    
    db.Close();
}

// ============================================================================
// CATEGORY 11: MEMORY MAPPING TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, MemoryMapping_GetMappedSize) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t mappedSize = db.GetMappedSize();
    EXPECT_GT(mappedSize, 0);
    EXPECT_GE(mappedSize, DATABASE_MIN_SIZE);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, MemoryMapping_GetDataOffset) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t dataOffset = db.GetDataOffset();
    EXPECT_GT(dataOffset, 0);
    EXPECT_GE(dataOffset, sizeof(ThreatIntelDatabaseHeader));
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, MemoryMapping_MaxEntriesCalculation) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t maxEntries = db.GetMaxEntries();
    EXPECT_GT(maxEntries, 0);
    
    // Verify calculation
    size_t mappedSize = db.GetMappedSize();
    size_t dataOffset = db.GetDataOffset();
    size_t expectedMax = (mappedSize - dataOffset) / sizeof(IOCEntry);
    
    EXPECT_EQ(maxEntries, expectedMax);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, MemoryMapping_RemappingPreservesData) {
    const uint32_t testValue1 = 0xDEADBEEF;
    const uint32_t testValue2 = 0xCAFEBABE;
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Allocate and set data
    size_t index1 = db.AllocateEntry();
    IOCEntry* entry1 = db.GetMutableEntry(index1);
    ASSERT_NE(entry1, nullptr);
    entry1->value.ipv4.address = testValue1;
    
    size_t originalSize = db.GetMappedSize();
    
    // Extend (causes remapping)
    EXPECT_TRUE(db.Extend(originalSize + 10 * 1024 * 1024));
    
    // Verify old data still accessible
    const IOCEntry* verifyEntry1 = db.GetEntry(index1);
    ASSERT_NE(verifyEntry1, nullptr);
    EXPECT_EQ(verifyEntry1->value.ipv4.address, testValue1);
    
    // Allocate new entry after remapping
    size_t index2 = db.AllocateEntry();
    IOCEntry* entry2 = db.GetMutableEntry(index2);
    ASSERT_NE(entry2, nullptr);
    entry2->value.ipv4.address = testValue2;
    
    // Verify both entries
    EXPECT_EQ(db.GetEntry(index1)->value.ipv4.address, testValue1);
    EXPECT_EQ(db.GetEntry(index2)->value.ipv4.address, testValue2);
    
    db.Close();
}

// ============================================================================
// CATEGORY 12: BOUNDARY CONDITION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Boundary_MinimumDatabaseSize) {
    DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
    config.initialSize = DATABASE_MIN_SIZE;
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(config));
    EXPECT_GE(db.GetMappedSize(), DATABASE_MIN_SIZE);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Boundary_AllocationUntilFull) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t maxEntries = db.GetMaxEntries();
    
    // Allocate all at once
    size_t startIndex = db.AllocateEntries(maxEntries);
    EXPECT_EQ(startIndex, 0);
    EXPECT_EQ(db.GetEntryCount(), maxEntries);
    
    // Try to allocate one more (should extend or fail gracefully)
    size_t extraIndex = db.AllocateEntry();
    // Either succeeds after extension or fails gracefully
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Boundary_EntryAtLastPosition) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t maxEntries = db.GetMaxEntries();
    
    // Allocate all entries
    db.SetEntryCount(maxEntries);
    
    // Get last entry
    const IOCEntry* lastEntry = db.GetEntry(maxEntries - 1);
    EXPECT_NE(lastEntry, nullptr);
    
    // Try to get beyond last
    const IOCEntry* beyondLast = db.GetEntry(maxEntries);
    EXPECT_EQ(beyondLast, nullptr);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Boundary_ZeroEntryDatabase) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    EXPECT_EQ(db.GetEntryCount(), 0);
    EXPECT_EQ(db.GetEntry(0), nullptr);
    EXPECT_EQ(db.Compact(), 0);
    
    db.Close();
}

// ============================================================================
// CATEGORY 13: STATISTICS TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Statistics_GetStats) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    DatabaseStats stats = db.GetStats();
    
    EXPECT_TRUE(stats.isOpen);
    EXPECT_FALSE(stats.isReadOnly);
    EXPECT_EQ(stats.entryCount, 0);
    EXPECT_GT(stats.maxEntries, 0);
    EXPECT_GT(stats.mappedSize, 0);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Statistics_UpdateAfterAllocation) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(100);
    
    DatabaseStats stats = db.GetStats();
    EXPECT_EQ(stats.entryCount, 100);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Statistics_TimestampUpdates) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    DatabaseStats stats1 = db.GetStats();
    uint64_t ts1 = stats1.lastModifiedTimestamp;
    
    // Wait briefly
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    
    // Trigger timestamp update
    db.UpdateTimestamp();
    
    DatabaseStats stats2 = db.GetStats();
    uint64_t ts2 = stats2.lastModifiedTimestamp;
    
    EXPECT_GE(ts2, ts1);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Statistics_GetFilePath) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    const std::wstring& path = db.GetFilePath();
    EXPECT_EQ(path, testDbPath);
    
    db.Close();
}

// ============================================================================
// CATEGORY 14: CORRUPTION RECOVERY TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Corruption_InvalidMagicNumber) {
    // Create valid database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Corrupt magic number
    CorruptDatabaseHeader(testDbPath);
    
    // Try to open
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.verifyOnOpen = true;
        config.createIfNotExists = false;
        
        ThreatIntelDatabase db;
        EXPECT_FALSE(db.Open(config));
    }
}

TEST_F(ThreatIntelDatabaseTest, Corruption_InvalidChecksum_SkipVerification) {
    // Create valid database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.Close();
    }
    
    // Corrupt checksum
    CorruptDatabaseHeader(testDbPath);
    
    // Open without verification
    {
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.verifyOnOpen = false;
        config.createIfNotExists = false;
        
        ThreatIntelDatabase db;
        // May succeed without verification
        bool opened = db.Open(config);
        if (opened) {
            db.Close();
        }
    }
}

// ============================================================================
// CATEGORY 15: UTILITY FUNCTION TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Utility_DatabaseFileExists) {
    EXPECT_FALSE(DatabaseFileExists(testDbPath));
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    db.Close();
    
    EXPECT_TRUE(DatabaseFileExists(testDbPath));
}

TEST_F(ThreatIntelDatabaseTest, Utility_GetDatabaseFileSize) {
    auto sizeOpt = GetDatabaseFileSize(testDbPath);
    EXPECT_FALSE(sizeOpt.has_value());
    
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    db.Close();
    
    sizeOpt = GetDatabaseFileSize(testDbPath);
    EXPECT_TRUE(sizeOpt.has_value());
    EXPECT_GT(sizeOpt.value(), 0);
}

TEST_F(ThreatIntelDatabaseTest, Utility_BackupDatabase) {
    // Create database
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    db.AllocateEntries(100);
    db.Close();
    
    // Backup
    auto backupPath = RegisterDatabase();
    EXPECT_TRUE(BackupDatabase(testDbPath, backupPath));
    
    // Verify backup exists
    EXPECT_TRUE(DatabaseFileExists(backupPath));
    
    // Verify backup can be opened
    ThreatIntelDatabase backupDb;
    EXPECT_TRUE(backupDb.Open(backupPath));
    EXPECT_EQ(backupDb.GetEntryCount(), 100);
    backupDb.Close();
}

TEST_F(ThreatIntelDatabaseTest, Utility_DeleteDatabaseFile) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    db.Close();
    
    EXPECT_TRUE(DatabaseFileExists(testDbPath));
    EXPECT_TRUE(DeleteDatabaseFile(testDbPath));
    EXPECT_FALSE(DatabaseFileExists(testDbPath));
}

// ============================================================================
// CATEGORY 16: TITANIUM EDGE CASES - HARDENING TESTS
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, Titanium_RapidOpenCloseSequence) {
    // Rapidly open and close database to test resource cleanup
    for (int i = 0; i < 10; ++i) {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        EXPECT_TRUE(db.IsOpen());
        db.AllocateEntry();
        db.Close();
        EXPECT_FALSE(db.IsOpen());
    }
    
    // Verify final state is correct
    ThreatIntelDatabase final_db;
    EXPECT_TRUE(final_db.Open(testDbPath));
    EXPECT_EQ(final_db.GetEntryCount(), 10);
    final_db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_AllocateExactCapacity) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t maxEntries = db.GetMaxEntries();
    size_t currentCount = db.GetEntryCount();
    size_t toAllocate = maxEntries - currentCount;
    
    // Allocate to exact capacity
    if (toAllocate > 0 && toAllocate <= 1000) { // Reasonable limit
        size_t index = db.AllocateEntries(toAllocate);
        EXPECT_NE(index, SIZE_MAX);
        EXPECT_EQ(db.GetEntryCount(), maxEntries);
    }
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_MultipleFlushOperations) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Perform multiple flushes
    for (int i = 0; i < 10; ++i) {
        db.AllocateEntry();
        EXPECT_TRUE(db.Flush());
    }
    
    EXPECT_EQ(db.GetEntryCount(), 10);
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_SyncOnReadOnlyMode) {
    // Create and populate database
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.AllocateEntries(10);
        db.Close();
    }
    
    // Open in read-only mode
    {
        DatabaseConfig config;
        config.filePath = testDbPath;
        config.readOnly = true;
        config.createIfNotExists = false;
        
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(config));
        
        // Sync should succeed (no-op)
        EXPECT_TRUE(db.Sync());
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, Titanium_IntegrityAfterExtension) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Add entries
    db.AllocateEntries(50);
    
    // Extend database
    size_t currentSize = db.GetMappedSize();
    EXPECT_TRUE(db.Extend(currentSize + 5 * 1024 * 1024));
    
    // Update checksum after extension (required for integrity check)
    EXPECT_TRUE(db.UpdateHeaderChecksum());
    
    // Verify integrity after extension with updated checksum
    EXPECT_TRUE(db.VerifyIntegrity());
    EXPECT_EQ(db.GetEntryCount(), 50);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_HeaderChecksumAfterModifications) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Multiple modifications
    for (int i = 0; i < 5; ++i) {
        db.AllocateEntries(10);
        EXPECT_TRUE(db.UpdateHeaderChecksum());
        EXPECT_TRUE(db.VerifyHeaderChecksum());
    }
    
    EXPECT_EQ(db.GetEntryCount(), 50);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_ConcurrentFlushOperations) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(100);
    
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    // Multiple threads flushing simultaneously
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 10; ++j) {
                if (db.Flush()) {
                    successCount++;
                }
                std::this_thread::yield();
            }
        });
    }
    
    for (auto& t : threads) {
        t.join();
    }
    
    // All flushes should succeed
    EXPECT_EQ(successCount.load(), 40);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_MixedRevokedAndSinkholedEntries) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(100);
    
    // Mark some as revoked, some as sinkholed
    for (size_t i = 0; i < 100; i += 4) {
        IOCEntry* entry = db.GetMutableEntry(i);
        if (entry) {
            entry->flags |= IOCFlags::Revoked;
        }
    }
    for (size_t i = 2; i < 100; i += 4) {
        IOCEntry* entry = db.GetMutableEntry(i);
        if (entry) {
            entry->flags |= IOCFlags::Sinkholed;
        }
    }
    
    size_t reclaimed = db.Compact();
    EXPECT_GT(reclaimed, 0);
    
    // 25 revoked + 25 sinkholed = 50 deleted, 50 remaining
    EXPECT_EQ(db.GetEntryCount(), 50);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_DataPersistenceAcrossReopen) {
    const size_t testEntryCount = 100;
    
    // Create and populate
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        db.AllocateEntries(testEntryCount);
        
        // Set some entry data
        for (size_t i = 0; i < testEntryCount; ++i) {
            IOCEntry* entry = db.GetMutableEntry(i);
            if (entry) {
                entry->type = IOCType::IPv4;
                entry->confidence = ConfidenceLevel::High;
            }
        }
        
        EXPECT_TRUE(db.Flush());
        db.Close();
    }
    
    // Reopen and verify
    {
        ThreatIntelDatabase db;
        EXPECT_TRUE(db.Open(testDbPath));
        EXPECT_EQ(db.GetEntryCount(), testEntryCount);
        
        // Verify entry data
        for (size_t i = 0; i < testEntryCount; ++i) {
            const IOCEntry* entry = db.GetEntry(i);
            if (entry) {
                EXPECT_EQ(entry->type, IOCType::IPv4);
                EXPECT_EQ(entry->confidence, ConfidenceLevel::High);
            }
        }
        
        db.Close();
    }
}

TEST_F(ThreatIntelDatabaseTest, Titanium_ExtendBeyondInitialSize) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    size_t originalSize = db.GetMappedSize();
    size_t originalMaxEntries = db.GetMaxEntries();
    
    // Extend significantly
    size_t newSize = originalSize + 20 * 1024 * 1024; // +20MB
    EXPECT_TRUE(db.Extend(newSize));
    
    EXPECT_GE(db.GetMappedSize(), newSize);
    EXPECT_GT(db.GetMaxEntries(), originalMaxEntries);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_DoubleOpenSameDatabase) {
    ThreatIntelDatabase db1;
    EXPECT_TRUE(db1.Open(testDbPath));
    
    // Second open on same instance should fail
    EXPECT_FALSE(db1.Open(testDbPath));
    
    // Second instance trying to open same file (might succeed or fail depending on sharing mode)
    ThreatIntelDatabase db2;
    // Don't assert - behavior depends on file locking implementation
    
    db1.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_AllocateEntryVerifyIndex) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Verify returned indices are sequential
    size_t prevIndex = SIZE_MAX;
    for (int i = 0; i < 10; ++i) {
        size_t index = db.AllocateEntry();
        EXPECT_NE(index, SIZE_MAX);
        if (prevIndex != SIZE_MAX) {
            EXPECT_EQ(index, prevIndex + 1);
        }
        prevIndex = index;
    }
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_FlushRangeValidation) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    db.AllocateEntries(100);
    
    // Valid ranges
    EXPECT_TRUE(db.FlushRange(0, 1024));
    EXPECT_TRUE(db.FlushRange(0, 0)); // Flush entire region
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_StatisticsConsistency) {
    ThreatIntelDatabase db;
    EXPECT_TRUE(db.Open(testDbPath));
    
    // Initial state
    DatabaseStats stats1 = db.GetStats();
    EXPECT_EQ(stats1.entryCount, 0);
    
    // After allocations
    db.AllocateEntries(50);
    DatabaseStats stats2 = db.GetStats();
    EXPECT_EQ(stats2.entryCount, 50);
    
    // After flush
    db.Flush();
    DatabaseStats stats3 = db.GetStats();
    EXPECT_EQ(stats3.flushCount, stats2.flushCount + 1);
    
    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, Titanium_PathHandlingEdgeCases) {
    // Test with various special paths
    ThreatIntelDatabase db;
    
    // Empty path
    EXPECT_FALSE(db.Open(L""));
    
    // Path with special characters (might fail due to file system restrictions)
    // Just verify no crash
    EXPECT_NO_THROW({
        db.Open(L"C:\\NonExistent\\Path\\test.db");
        db.Close();
    });
}

// ============================================================================
// HEADER CHECKSUM STAYS SEALED (task 380)
//
// The header checksum covers the entry count, timestamps and sizes, and the view is
// file-backed. The 1.0.126 VM run lost its database on the next boot: a mutation after
// the last Flush left a stale checksum, the process ended without Close, and
// OpenExisting rejected the file from then on.
// ============================================================================

namespace {

// Bytes of a file another handle holds open for write, read through the cache, the
// way the file looks on disk if its writer ends without Close.
bool CopyOpenDatabase(const std::wstring& from, const std::wstring& to) {
    HANDLE in = CreateFileW(from.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (in == INVALID_HANDLE_VALUE) {
        return false;
    }
    std::ofstream out(to, std::ios::binary | std::ios::trunc);
    std::vector<char> buffer(1 << 16);
    bool ok = out.is_open();
    DWORD got = 0;
    while (ok && ReadFile(in, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr) && got > 0) {
        out.write(buffer.data(), got);
        ok = static_cast<bool>(out);
    }
    CloseHandle(in);
    return ok;
}

}  // namespace

TEST_F(ThreatIntelDatabaseTest, HeaderChecksumHoldsAfterEveryMutation) {
    createdDatabases.push_back(testDbPath + L".strings");
    ThreatIntelDatabase db;
    ASSERT_TRUE(db.Open(testDbPath));

    ASSERT_NE(db.AllocateEntry(), SIZE_MAX);
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "AllocateEntry";

    ASSERT_NE(db.AllocateEntries(16), SIZE_MAX);
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "AllocateEntries";

    ASSERT_TRUE(db.SetEntryCount(12));
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "SetEntryCount";

    ASSERT_EQ(db.IncrementEntryCount(), 13u);
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "IncrementEntryCount";

    IOCEntry* doomed = db.GetMutableEntry(0);
    ASSERT_NE(doomed, nullptr);
    doomed->flags |= IOCFlags::Revoked;
    (void)db.Compact();
    ASSERT_EQ(db.GetEntryCount(), 12u) << "Compact must remove the revoked entry";
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "Compact";

    const size_t before = db.GetStats().mappedSize;
    ASSERT_TRUE(db.ExtendBy(DATABASE_PAGE_SIZE * 4));
    ASSERT_GT(db.GetStats().mappedSize, before);
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "Extend";

    // The timestamp has one-second resolution, so wait for it to move or the check
    // below could not tell a resealed header from an unchanged one.
    const uint64_t stamp = db.GetHeader()->lastUpdateTime;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (db.GetHeader()->lastUpdateTime == stamp && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        db.UpdateTimestamp();
    }
    ASSERT_NE(db.GetHeader()->lastUpdateTime, stamp);
    EXPECT_TRUE(db.VerifyHeaderChecksum()) << "UpdateTimestamp";

    db.Close();
}

TEST_F(ThreatIntelDatabaseTest, ADatabaseWhoseWriterNeverClosedReopens) {
    const std::wstring copy = testDbPath + L".unclosed";
    createdDatabases.push_back(testDbPath + L".strings");
    createdDatabases.push_back(copy);
    createdDatabases.push_back(copy + L".strings");

    ThreatIntelDatabase writer;
    ASSERT_TRUE(writer.Open(testDbPath));
    ASSERT_TRUE(writer.Flush());
    // What the feed sync does: entries, then a timestamp, with no Flush after it.
    ASSERT_NE(writer.AllocateEntries(3), SIZE_MAX);
    writer.UpdateTimestamp();
    ASSERT_TRUE(CopyOpenDatabase(testDbPath, copy));

    ThreatIntelDatabase reopened;
    EXPECT_TRUE(reopened.Open(copy))
        << "a database whose writer ended without Close must open on the next start";
    if (reopened.IsOpen()) {
        EXPECT_EQ(reopened.GetEntryCount(), 3u);
        reopened.Close();
    }
    writer.Close();
}

// OPEN NAMES WHY IT FAILED (task 380)
//
// The store replaces a database only on UnusableContent, so the class must be right:
// a sharing or ACL failure misread as bad content would destroy a healthy file.
// ============================================================================

TEST_F(ThreatIntelDatabaseTest, OpenNamesWhyItFailed) {
    using Failure = ThreatIntelDatabase::OpenFailure;
    createdDatabases.push_back(testDbPath + L".strings");

    {   // bytes that are not a database
        std::ofstream(testDbPath, std::ios::binary).write(std::string(64 * 1024, '\0').data(), 64 * 1024);
        ThreatIntelDatabase db;
        EXPECT_FALSE(db.Open(testDbPath));
        EXPECT_EQ(db.GetLastOpenFailure(), Failure::UnusableContent);
        CleanupDatabase(testDbPath);
    }
    {   // a healthy database another handle holds without sharing
        ThreatIntelDatabase writer;
        ASSERT_TRUE(writer.Open(testDbPath));
        writer.Close();
        HANDLE held = CreateFileW(testDbPath.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                                  FILE_ATTRIBUTE_NORMAL, nullptr);
        ASSERT_NE(held, INVALID_HANDLE_VALUE);
        ThreatIntelDatabase db;
        EXPECT_FALSE(db.Open(testDbPath));
        EXPECT_EQ(db.GetLastOpenFailure(), Failure::AccessFailed);
        EXPECT_EQ(db.GetLastOpenError(), static_cast<uint32_t>(ERROR_SHARING_VIOLATION));
        CloseHandle(held);
        CleanupDatabase(testDbPath);
    }
    {   // no file, and creation not allowed
        DatabaseConfig config = DatabaseConfig::CreateDefault(testDbPath);
        config.createIfNotExists = false;
        ThreatIntelDatabase db;
        EXPECT_FALSE(db.Open(config));
        EXPECT_EQ(db.GetLastOpenFailure(), Failure::NotFound);
    }
    {   // a second Open of an open database; success clears the class
        ThreatIntelDatabase db;
        ASSERT_TRUE(db.Open(testDbPath));
        EXPECT_EQ(db.GetLastOpenFailure(), Failure::None);
        EXPECT_FALSE(db.Open(testDbPath));
        EXPECT_EQ(db.GetLastOpenFailure(), Failure::InvalidRequest);
        db.Close();
    }
}
