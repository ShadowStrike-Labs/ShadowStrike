// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include"pch.h"
#include <gtest/gtest.h>
#include "../../../src/Database/LogDB.hpp"
#include"../../../src/Utils/StringUtils.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>
#include <fstream>

#include"winsqlite/winsqlite3.h"

using namespace ShadowStrike::Database;
using namespace std::chrono_literals;

namespace fs = std::filesystem;

// ============================================================================
// Test Utilities & Helpers
// ============================================================================

namespace {
    // Generate unique test paths
    std::wstring GenerateTestBasePath() {
        static std::atomic<int> counter{ 0 };
        auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        auto id = counter.fetch_add(1, std::memory_order_relaxed);

        std::wstring path = L"C:\\Temp\\LogDBTest_";
        path += std::to_wstring(timestamp);
        path += L"_";
        path += std::to_wstring(id);

        return path;
    }

    // Clean up test directory
    void CleanupTestDirectory(const std::wstring& path) {
        try {
            if (fs::exists(path)) {
                fs::remove_all(path);
            }
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }

    // RAII wrapper for test directory cleanup
    class TestDirectoryGuard {
    public:
        explicit TestDirectoryGuard(std::wstring path) : m_path(std::move(path)) {}

        ~TestDirectoryGuard() {
            LogDB::Instance().Shutdown();
            std::this_thread::sleep_for(100ms);
            CleanupTestDirectory(m_path);
        }

        const std::wstring& GetPath() const { return m_path; }

    private:
        std::wstring m_path;
    };

    // Create test configuration
    LogDB::Config CreateTestConfig(const std::wstring& basePath) {
        LogDB::Config config;
        config.dbPath = basePath + L"\\logs_test.db";
        config.enableWAL = true;
        config.dbCacheSizeKB = 4096;
        config.maxConnections = 3;
        config.minLogLevel = LogDB::LogLevel::Trace;
        config.logToConsole = false;
        config.logToFile = true;
        config.asyncLogging = false;  // Disable for deterministic tests
        config.enableRotation = false; // Disable for tests
        config.maxLogSizeMB = 100;
        config.maxLogAge = std::chrono::hours(24 * 7); // 7 days
        config.archivePath = basePath + L"\\archive";
        config.batchSize = 50;
        config.batchFlushInterval = std::chrono::seconds(1);
        config.enableFullTextSearch = false;
        config.enableStatistics = true;

        return config;
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

class LogDBTest : public ::testing::Test {
protected:
    void SetUp() override {
        // FORCE COMPLETE SHUTDOWN OF ALL DATABASE INSTANCES
        LogDB::Instance().Shutdown();
        DatabaseManager::Instance().Shutdown();

        std::this_thread::sleep_for(100ms);  // Increased wait time

        // Generate unique test paths
        m_basePath = GenerateTestBasePath();

        // Create directories FIRST
        fs::create_directories(m_basePath);

        // Create config
        m_config = CreateTestConfig(m_basePath);

        // NO GUARD YET - Initialize first!
    }

    void TearDown() override {
        // EXPLICIT CLEANUP ORDER
        LogDB::Instance().Shutdown();
        DatabaseManager::Instance().Shutdown();

        std::this_thread::sleep_for(100ms);

        // Manual cleanup instead of guard
        CleanupTestDirectory(m_basePath);
    }

    // Helper: Initialize LogDB
    bool InitializeLogDB() {
        DatabaseError err;
        bool success = LogDB::Instance().Initialize(m_config, &err);
        if (!success) {
            std::string errorMsg;
            if (!err.message.empty()) {
                int size = WideCharToMultiByte(CP_UTF8, 0, err.message.data(),
                    static_cast<int>(err.message.size()), nullptr, 0, nullptr, nullptr);
                if (size > 0) {
                    errorMsg.resize(size);
                    WideCharToMultiByte(CP_UTF8, 0, err.message.data(),
                        static_cast<int>(err.message.size()), &errorMsg[0], size, nullptr, nullptr);
                }
            }

            ADD_FAILURE() << "LogDB initialization failed: " << errorMsg;
        }
        return success;
    }
    std::wstring m_basePath;
    LogDB::Config m_config;
    
};

// ============================================================================
// Initialization & Lifecycle Tests
// ============================================================================

TEST_F(LogDBTest, InitializeSucceeds) {
    EXPECT_TRUE(InitializeLogDB());
    EXPECT_TRUE(LogDB::Instance().IsInitialized());
}

TEST_F(LogDBTest, InitializeCreatesDatabase) {
    EXPECT_TRUE(InitializeLogDB());
    EXPECT_TRUE(fs::exists(m_config.dbPath));
}

TEST_F(LogDBTest, InitializeWithInvalidPathFails) {
    m_config.dbPath = L"Z:\\invalid\\path\\logs.db";

    DatabaseError err;
    EXPECT_FALSE(LogDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(err.HasError());
}

TEST_F(LogDBTest, DoubleInitializeSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    EXPECT_TRUE(LogDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(LogDB::Instance().IsInitialized());
}

TEST_F(LogDBTest, ShutdownClearsInitializedFlag) {
    EXPECT_TRUE(InitializeLogDB());
    EXPECT_TRUE(LogDB::Instance().IsInitialized());

    LogDB::Instance().Shutdown();

    EXPECT_FALSE(LogDB::Instance().IsInitialized());
}

TEST_F(LogDBTest, InitializeAfterShutdownSucceeds) {
    EXPECT_TRUE(InitializeLogDB());
    LogDB::Instance().Shutdown();

    std::this_thread::sleep_for(100ms);

    EXPECT_TRUE(InitializeLogDB());
    EXPECT_TRUE(LogDB::Instance().IsInitialized());
}

// ============================================================================
// Basic Logging Operations Tests
// ============================================================================

TEST_F(LogDBTest, LogBasicEntrySucceeds) {
    std::cout << "\n========== LogBasicEntrySucceeds START ==========\n";

    EXPECT_TRUE(InitializeLogDB());

    // ✅ DEBUG: Check config after init
    auto config = LogDB::Instance().GetConfig();
    std::cout << "Config after init:\n";
    std::cout << "  asyncLogging: " << (config.asyncLogging ? "TRUE" : "FALSE") << "\n";
    std::cout << "  minLogLevel: " << static_cast<int>(config.minLogLevel) << "\n";
	std::cout << "  dbPath: " << ShadowStrike::Utils::StringUtils::ToNarrow(config.dbPath) << "\n";

    DatabaseError err;
    std::cout << "Calling Log()...\n";

    int64_t entryId = LogDB::Instance().Log(
        LogDB::LogLevel::Info,
        LogDB::LogCategory::General,
        L"TestSource",
        L"Test message",
        &err
    );

    std::cout << "Log() returned: " << entryId << "\n";
    if (err.HasError()) {
        std::cout << "ERROR: " << ShadowStrike::Utils::StringUtils::ToNarrow(err.message) << "\n";
    }

    EXPECT_GT(entryId, 0) << "Entry ID should be > 0, got: " << entryId;
    EXPECT_FALSE(err.HasError());

    // Verify entry was created
    std::cout << "Calling GetEntry(" << entryId << ")...\n";
    auto entry = LogDB::Instance().GetEntry(entryId, &err);

    std::cout << "GetEntry() returned: " << (entry.has_value() ? "VALID" : "NULL") << "\n";
    if (!entry.has_value()) {
        std::cout << "ERROR: Entry not found!\n";
        if (err.HasError()) {
            std::cout << "Database error: " << ShadowStrike::Utils::StringUtils::ToNarrow(err.message) << "\n";
        }
    }

    ASSERT_TRUE(entry.has_value()) << "Entry should exist!";
    EXPECT_EQ(entry->level, LogDB::LogLevel::Info);
    EXPECT_EQ(entry->category, LogDB::LogCategory::General);
    EXPECT_EQ(entry->source, L"TestSource");
    EXPECT_EQ(entry->message, L"Test message");

    std::cout << "========== LogBasicEntrySucceeds END ==========\n\n";
}


TEST_F(LogDBTest, LogDetailedEntrySucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = LogDB::LogLevel::Error;
    entry.category = LogDB::LogCategory::Security;
    entry.source = L"SecurityModule";
    entry.message = L"Security violation detected";
    entry.details = L"Unauthorized access attempt";
    entry.errorCode = 12345;
    entry.errorContext = L"File: test.dll";

    DatabaseError err;
    int64_t entryId = LogDB::Instance().LogDetailed(entry, &err);

    EXPECT_GT(entryId, 0);
    EXPECT_FALSE(err.HasError());

    // Verify detailed entry
    auto retrieved = LogDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(retrieved.has_value());
    EXPECT_EQ(retrieved->level, LogDB::LogLevel::Error);
    EXPECT_EQ(retrieved->category, LogDB::LogCategory::Security);
    EXPECT_EQ(retrieved->message, L"Security violation detected");
    EXPECT_EQ(retrieved->details, L"Unauthorized access attempt");
    EXPECT_EQ(retrieved->errorCode, 12345);
    EXPECT_EQ(retrieved->errorContext, L"File: test.dll");
}

TEST_F(LogDBTest, ConvenienceMethodsWork) {
    std::cout << "\n========== ConvenienceMethodsWork START ==========\n";

    EXPECT_TRUE(InitializeLogDB());

    // ✅ DEBUG: Check config
    auto config = LogDB::Instance().GetConfig();
    std::cout << "asyncLogging: " << (config.asyncLogging ? "TRUE" : "FALSE") << "\n";

    std::cout << "LogTrace: ";
    int64_t id1 = LogDB::Instance().LogTrace(L"Source", L"Trace message");
    std::cout << id1 << "\n";
    EXPECT_GT(id1, 0) << "Trace failed with: " << id1;

    std::cout << "LogDebug: ";
    int64_t id2 = LogDB::Instance().LogDebug(L"Source", L"Debug message");
    std::cout << id2 << "\n";
    EXPECT_GT(id2, 0) << "Debug failed with: " << id2;

    std::cout << "LogInfo: ";
    int64_t id3 = LogDB::Instance().LogInfo(L"Source", L"Info message");
    std::cout << id3 << "\n";
    EXPECT_GT(id3, 0) << "Info failed with: " << id3;

    std::cout << "LogWarn: ";
    int64_t id4 = LogDB::Instance().LogWarn(L"Source", L"Warn message");
    std::cout << id4 << "\n";
    EXPECT_GT(id4, 0) << "Warn failed with: " << id4;

    std::cout << "LogError: ";
    int64_t id5 = LogDB::Instance().LogError(L"Source", L"Error message");
    std::cout << id5 << "\n";
    EXPECT_GT(id5, 0) << "Error failed with: " << id5;

    std::cout << "LogFatal: ";
    int64_t id6 = LogDB::Instance().LogFatal(L"Source", L"Fatal message");
    std::cout << id6 << "\n";
    EXPECT_GT(id6, 0) << "Fatal failed with: " << id6;

    std::cout << "========== ConvenienceMethodsWork END ==========\n\n";
}

TEST_F(LogDBTest, LogErrorWithCodeWorks) {
    EXPECT_TRUE(InitializeLogDB());

    int64_t entryId = LogDB::Instance().LogErrorWithCode(
        L"TestModule",
        L"Operation failed",
        0x80070005,
        L"Access denied"
    );

    EXPECT_GT(entryId, 0);

    DatabaseError err;
    auto entry = LogDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->errorCode, 0x80070005);
    EXPECT_EQ(entry->errorContext, L"Access denied");
}

TEST_F(LogDBTest, LogPerformanceWorks) {
    EXPECT_TRUE(InitializeLogDB());

    int64_t entryId = LogDB::Instance().LogPerformance(
        L"Scanner",
        L"File scan",
        1250,
        L"Scanned 1000 files"
    );

    EXPECT_GT(entryId, 0);

    DatabaseError err;
    auto entry = LogDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->category, LogDB::LogCategory::Performance);
    EXPECT_EQ(entry->durationMs, 1250);
    EXPECT_EQ(entry->details, L"Scanned 1000 files");
}

TEST_F(LogDBTest, LogBatchSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    std::vector<LogDB::LogEntry> entries;
    for (int i = 0; i < 10; ++i) {
        LogDB::LogEntry entry;
        entry.timestamp = std::chrono::system_clock::now();
        entry.level = LogDB::LogLevel::Info;
        entry.category = LogDB::LogCategory::General;
        entry.source = L"BatchTest";
        entry.message = L"Message " + std::to_wstring(i);
        entries.push_back(entry);
    }

    DatabaseError err;
    bool success = LogDB::Instance().LogBatch(entries, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());

    // Verify entries were created
    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_GE(count, 10);
}

TEST_F(LogDBTest, MinLogLevelFiltersCorrectly) {
    m_config.minLogLevel = LogDB::LogLevel::Warn;
    EXPECT_TRUE(InitializeLogDB());

    // These should be filtered out
    EXPECT_EQ(LogDB::Instance().LogTrace(L"Test", L"Trace"), 0);
    EXPECT_EQ(LogDB::Instance().LogDebug(L"Test", L"Debug"), 0);
    EXPECT_EQ(LogDB::Instance().LogInfo(L"Test", L"Info"), 0);

    // These should be logged
    EXPECT_GT(LogDB::Instance().LogWarn(L"Test", L"Warn"), 0);
    EXPECT_GT(LogDB::Instance().LogError(L"Test", L"Error"), 0);
    EXPECT_GT(LogDB::Instance().LogFatal(L"Test", L"Fatal"), 0);

    DatabaseError err;
    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_EQ(count, 3); // Only Warn, Error, Fatal
}

// ============================================================================
// Query Operations Tests
// ============================================================================

TEST_F(LogDBTest, GetEntryReturnsCorrectData) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    int64_t entryId = LogDB::Instance().Log(
        LogDB::LogLevel::Error,
        LogDB::LogCategory::FileSystem,
        L"FileModule",
        L"File not found",
        &err
    );
    ASSERT_GT(entryId, 0);

    auto entry = LogDB::Instance().GetEntry(entryId, &err);

    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->id, entryId);
    EXPECT_EQ(entry->level, LogDB::LogLevel::Error);
    EXPECT_EQ(entry->category, LogDB::LogCategory::FileSystem);
    EXPECT_EQ(entry->source, L"FileModule");
    EXPECT_EQ(entry->message, L"File not found");
}

TEST_F(LogDBTest, GetNonExistentEntryReturnsNullopt) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    auto entry = LogDB::Instance().GetEntry(99999, &err);

    EXPECT_FALSE(entry.has_value());
}

TEST_F(LogDBTest, GetRecentReturnsLatestEntries) {
    EXPECT_TRUE(InitializeLogDB());

    // Create 20 entries
    for (int i = 0; i < 20; ++i) {
        LogDB::Instance().LogInfo(L"Test", L"Message " + std::to_wstring(i));
        std::this_thread::sleep_for(1ms); // Ensure different timestamps
    }

    DatabaseError err;
    auto entries = LogDB::Instance().GetRecent(10, LogDB::LogLevel::Info, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 10);

    // Should be in descending order (newest first)
    for (size_t i = 1; i < entries.size(); ++i) {
        EXPECT_GE(entries[i - 1].timestamp, entries[i].timestamp);
    }
}

TEST_F(LogDBTest, GetByLevelFiltersCorrectly) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Info 1");
    LogDB::Instance().LogInfo(L"Test", L"Info 2");
    LogDB::Instance().LogError(L"Test", L"Error 1");
    LogDB::Instance().LogWarn(L"Test", L"Warn 1");

    DatabaseError err;
    auto entries = LogDB::Instance().GetByLevel(LogDB::LogLevel::Info, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 2);

    for (const auto& entry : entries) {
        EXPECT_EQ(entry.level, LogDB::LogLevel::Info);
    }
}

TEST_F(LogDBTest, GetByCategoryFiltersCorrectly) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().Log(LogDB::LogLevel::Info, LogDB::LogCategory::Security, L"Test", L"Security 1");
    LogDB::Instance().Log(LogDB::LogLevel::Info, LogDB::LogCategory::Security, L"Test", L"Security 2");
    LogDB::Instance().Log(LogDB::LogLevel::Info, LogDB::LogCategory::Network, L"Test", L"Network 1");

    DatabaseError err;
    auto entries = LogDB::Instance().GetByCategory(LogDB::LogCategory::Security, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 2);

    for (const auto& entry : entries) {
        EXPECT_EQ(entry.category, LogDB::LogCategory::Security);
    }
}

TEST_F(LogDBTest, GetByTimeRangeWorks) {
    EXPECT_TRUE(InitializeLogDB());

    auto start = std::chrono::system_clock::now();

    LogDB::Instance().LogInfo(L"Test", L"Before");
    std::this_thread::sleep_for(10ms);

    auto rangeStart = std::chrono::system_clock::now();
    std::this_thread::sleep_for(10ms);

    LogDB::Instance().LogInfo(L"Test", L"In range 1");
    std::this_thread::sleep_for(10ms);
    LogDB::Instance().LogInfo(L"Test", L"In range 2");
    std::this_thread::sleep_for(10ms);

    auto rangeEnd = std::chrono::system_clock::now();
    std::this_thread::sleep_for(10ms);

    LogDB::Instance().LogInfo(L"Test", L"After");

    DatabaseError err;
    auto entries = LogDB::Instance().GetByTimeRange(rangeStart, rangeEnd, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 2);
}

TEST_F(LogDBTest, GetByProcessWorks) {
    EXPECT_TRUE(InitializeLogDB());

    uint32_t currentPid = GetCurrentProcessId();

    LogDB::Instance().LogInfo(L"Test", L"Process message 1");
    LogDB::Instance().LogInfo(L"Test", L"Process message 2");

    DatabaseError err;
    auto entries = LogDB::Instance().GetByProcess(currentPid, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_GE(entries.size(), 2);

    for (const auto& entry : entries) {
        EXPECT_EQ(entry.processId, currentPid);
    }
}

TEST_F(LogDBTest, SearchTextFindsMatches) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Database connection failed");
    LogDB::Instance().LogInfo(L"Test", L"Network timeout occurred");
    LogDB::Instance().LogInfo(L"Test", L"Database query executed");

    DatabaseError err;
    auto entries = LogDB::Instance().SearchText(L"Database", false, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 2);
}
TEST_F(LogDBTest, CountEntriesReturnsCorrectCount) {
    std::cout << "\n========== CountEntriesReturnsCorrectCount START ==========\n";

    EXPECT_TRUE(InitializeLogDB());

    std::cout << "Logging 15 entries...\n";
    for (int i = 0; i < 15; ++i) {
        int64_t id = LogDB::Instance().LogInfo(L"Test", L"Message " + std::to_wstring(i));
        std::cout << "  Entry " << i << ": ID=" << id << "\n";
    }

    DatabaseError err;
    std::cout << "Calling CountEntries()...\n";
    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);

    std::cout << "CountEntries() returned: " << count << "\n";
    if (err.HasError()) {
        std::cout << "ERROR: " << ShadowStrike::Utils::StringUtils::ToNarrow(err.message) << "\n";
    }

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(count, 15) << "Expected 15 entries, got: " << count;

    std::cout << "========== CountEntriesReturnsCorrectCount END ==========\n\n";

}

TEST_F(LogDBTest, QueryWithFilterWorks) {
    EXPECT_TRUE(InitializeLogDB());

    // Create diverse entries
    LogDB::Instance().Log(LogDB::LogLevel::Info, LogDB::LogCategory::Security, L"SecModule", L"Security message");
    LogDB::Instance().Log(LogDB::LogLevel::Error, LogDB::LogCategory::Security, L"SecModule", L"Security error");
    LogDB::Instance().Log(LogDB::LogLevel::Info, LogDB::LogCategory::Network, L"NetModule", L"Network message");

    LogDB::QueryFilter filter;
    filter.category = LogDB::LogCategory::Security;
    filter.minLevel = LogDB::LogLevel::Info;

    DatabaseError err;
    auto entries = LogDB::Instance().Query(filter, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(entries.size(), 2);

    for (const auto& entry : entries) {
        EXPECT_EQ(entry.category, LogDB::LogCategory::Security);
    }
}

// ============================================================================
// Management Operations Tests
// ============================================================================

TEST_F(LogDBTest, DeleteEntrySucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    int64_t entryId = LogDB::Instance().LogInfo(L"Test", L"To be deleted");
    ASSERT_GT(entryId, 0);

    bool success = LogDB::Instance().DeleteEntry(entryId, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());

    // Verify entry is gone
    auto entry = LogDB::Instance().GetEntry(entryId, &err);
    EXPECT_FALSE(entry.has_value());
}

TEST_F(LogDBTest, DeleteBeforeWorks) {
    EXPECT_TRUE(InitializeLogDB());

    // Create old entries
    LogDB::Instance().LogInfo(L"Test", L"Old 1");
    LogDB::Instance().LogInfo(L"Test", L"Old 2");

    std::this_thread::sleep_for(50ms);
    auto cutoffTime = std::chrono::system_clock::now();
    std::this_thread::sleep_for(50ms);

    // Create new entries
    LogDB::Instance().LogInfo(L"Test", L"New 1");
    LogDB::Instance().LogInfo(L"Test", L"New 2");

    DatabaseError err;
    bool success = LogDB::Instance().DeleteBefore(cutoffTime, &err);

    EXPECT_TRUE(success);

    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_EQ(count, 2); // Only new entries remain
}

TEST_F(LogDBTest, DeleteByLevelWorks) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Info 1");
    LogDB::Instance().LogInfo(L"Test", L"Info 2");
    LogDB::Instance().LogError(L"Test", L"Error 1");

    DatabaseError err;
    bool success = LogDB::Instance().DeleteByLevel(LogDB::LogLevel::Info, &err);

    EXPECT_TRUE(success);

    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_EQ(count, 1); // Only error remains
}

TEST_F(LogDBTest, DeleteAllWorks) {
    EXPECT_TRUE(InitializeLogDB());

    for (int i = 0; i < 10; ++i) {
        LogDB::Instance().LogInfo(L"Test", L"Message " + std::to_wstring(i));
    }

    DatabaseError err;
    bool success = LogDB::Instance().DeleteAll(&err);

    EXPECT_TRUE(success);

    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_EQ(count, 0);
}

TEST_F(LogDBTest, FlushSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Message");

    DatabaseError err;
    bool success = LogDB::Instance().Flush(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(LogDBTest, GetStatisticsReturnsValidData) {
    EXPECT_TRUE(InitializeLogDB());

    // Create diverse entries
    LogDB::Instance().LogInfo(L"Test", L"Info 1");
    LogDB::Instance().LogInfo(L"Test", L"Info 2");
    LogDB::Instance().LogError(L"Test", L"Error 1");
    LogDB::Instance().LogWarn(L"Test", L"Warn 1");

    DatabaseError err;
    auto stats = LogDB::Instance().GetStatistics(&err);

    EXPECT_FALSE(err.HasError());
    EXPECT_GE(stats.totalEntries, 4);
    EXPECT_GT(stats.totalWrites, 0);
    EXPECT_GE(stats.entriesByLevel[static_cast<size_t>(LogDB::LogLevel::Info)], 2);
    EXPECT_GE(stats.entriesByLevel[static_cast<size_t>(LogDB::LogLevel::Error)], 1);
}

TEST_F(LogDBTest, ResetStatisticsWorks) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Message");

    LogDB::Instance().ResetStatistics();

    auto stats = LogDB::Instance().GetStatistics(nullptr);

    EXPECT_EQ(stats.totalWrites, 0);
    EXPECT_EQ(stats.totalReads, 0);
}

// ============================================================================
// Utility Functions Tests
// ============================================================================

TEST_F(LogDBTest, LogLevelStringConversionWorks) {
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Trace), L"TRACE");
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Debug), L"DEBUG");
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Info), L"INFO");
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Warn), L"WARN");
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Error), L"ERROR");
    EXPECT_EQ(LogDB::LogLevelToString(LogDB::LogLevel::Fatal), L"FATAL");

    EXPECT_EQ(LogDB::StringToLogLevel(L"TRACE"), LogDB::LogLevel::Trace);
    EXPECT_EQ(LogDB::StringToLogLevel(L"DEBUG"), LogDB::LogLevel::Debug);
    EXPECT_EQ(LogDB::StringToLogLevel(L"INFO"), LogDB::LogLevel::Info);
    EXPECT_EQ(LogDB::StringToLogLevel(L"WARN"), LogDB::LogLevel::Warn);
    EXPECT_EQ(LogDB::StringToLogLevel(L"ERROR"), LogDB::LogLevel::Error);
    EXPECT_EQ(LogDB::StringToLogLevel(L"FATAL"), LogDB::LogLevel::Fatal);
}

TEST_F(LogDBTest, LogCategoryStringConversionWorks) {
    EXPECT_EQ(LogDB::LogCategoryToString(LogDB::LogCategory::General), L"General");
    EXPECT_EQ(LogDB::LogCategoryToString(LogDB::LogCategory::Security), L"Security");
    EXPECT_EQ(LogDB::LogCategoryToString(LogDB::LogCategory::Network), L"Network");

    EXPECT_EQ(LogDB::StringToLogCategory(L"General"), LogDB::LogCategory::General);
    EXPECT_EQ(LogDB::StringToLogCategory(L"Security"), LogDB::LogCategory::Security);
    EXPECT_EQ(LogDB::StringToLogCategory(L"Network"), LogDB::LogCategory::Network);
}

TEST_F(LogDBTest, FormatLogEntryWorks) {
    LogDB::LogEntry entry;
    entry.timestamp = std::chrono::system_clock::now();
    entry.level = LogDB::LogLevel::Error;
    entry.category = LogDB::LogCategory::Security;
    entry.source = L"TestModule";
    entry.message = L"Test error message";
    entry.details = L"Additional details";
    entry.errorCode = 12345;

    std::wstring formatted = LogDB::FormatLogEntry(entry, false);

    EXPECT_FALSE(formatted.empty());
    EXPECT_NE(formatted.find(L"ERROR"), std::wstring::npos);
    EXPECT_NE(formatted.find(L"Security"), std::wstring::npos);
    EXPECT_NE(formatted.find(L"TestModule"), std::wstring::npos);
    EXPECT_NE(formatted.find(L"Test error message"), std::wstring::npos);
}

// ============================================================================
// Export Operations Tests
// ============================================================================

TEST_F(LogDBTest, ExportToFileSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"Export test 1");
    LogDB::Instance().LogInfo(L"Test", L"Export test 2");

    std::wstring exportPath = m_basePath + L"\\export.log";

    DatabaseError err;
    bool success = LogDB::Instance().ExportToFile(exportPath, nullptr, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(exportPath));
    EXPECT_GT(fs::file_size(exportPath), 0);
}

TEST_F(LogDBTest, ExportToJSONSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"JSON test 1");
    LogDB::Instance().LogError(L"Test", L"JSON test 2");

    std::wstring exportPath = m_basePath + L"\\export.json";

    DatabaseError err;
    bool success = LogDB::Instance().ExportToJSON(exportPath, nullptr, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(exportPath));
    EXPECT_GT(fs::file_size(exportPath), 0);
}

TEST_F(LogDBTest, ExportToCSVSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().LogInfo(L"Test", L"CSV test 1");
    LogDB::Instance().LogWarn(L"Test", L"CSV test 2");

    std::wstring exportPath = m_basePath + L"\\export.csv";

    DatabaseError err;
    bool success = LogDB::Instance().ExportToCSV(exportPath, nullptr, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(exportPath));
    EXPECT_GT(fs::file_size(exportPath), 0);
}

// ============================================================================
// Maintenance Operations Tests
// ============================================================================

TEST_F(LogDBTest, VacuumSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    bool success = LogDB::Instance().Vacuum(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(LogDBTest, CheckIntegritySucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    bool success = LogDB::Instance().CheckIntegrity(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(LogDBTest, OptimizeSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    bool success = LogDB::Instance().Optimize(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(LogDBTest, RebuildIndicesSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    bool success = LogDB::Instance().RebuildIndices(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(LogDBTest, GetConfigReturnsCorrectValues) {
    EXPECT_TRUE(InitializeLogDB());

    auto config = LogDB::Instance().GetConfig();

    EXPECT_EQ(config.dbPath, m_config.dbPath);
    EXPECT_EQ(config.minLogLevel, m_config.minLogLevel);
    EXPECT_EQ(config.enableWAL, m_config.enableWAL);
}

TEST_F(LogDBTest, SetMinLogLevelWorks) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().SetMinLogLevel(LogDB::LogLevel::Error);

    // Info should be filtered
    EXPECT_EQ(LogDB::Instance().LogInfo(L"Test", L"Info"), 0);

    // Error should pass
    EXPECT_GT(LogDB::Instance().LogError(L"Test", L"Error"), 0);
}

TEST_F(LogDBTest, SetAsyncLoggingWorks) {
    EXPECT_TRUE(InitializeLogDB());

    LogDB::Instance().SetAsyncLogging(false);

    auto config = LogDB::Instance().GetConfig();
    EXPECT_FALSE(config.asyncLogging);
}

// ============================================================================
// Edge Cases & Error Handling Tests
// ============================================================================

TEST_F(LogDBTest, DeleteNonExistentEntryFails) {
    EXPECT_TRUE(InitializeLogDB());

    DatabaseError err;
    bool success = LogDB::Instance().DeleteEntry(99999, &err);

    
    EXPECT_FALSE(success);
}


TEST_F(LogDBTest, LogEmptyMessageSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    int64_t entryId = LogDB::Instance().LogInfo(L"Test", L"");

    EXPECT_GT(entryId, 0);

    DatabaseError err;
    auto entry = LogDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->message.empty());
}

TEST_F(LogDBTest, LogVeryLongMessageSucceeds) {
    EXPECT_TRUE(InitializeLogDB());

    std::wstring longMessage(10000, L'A');

    int64_t entryId = LogDB::Instance().LogInfo(L"Test", longMessage);

    EXPECT_GT(entryId, 0);

    DatabaseError err;
    auto entry = LogDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->message.length(), 10000);
}

// ============================================================================
// Performance Tests (Basic)
// ============================================================================

TEST_F(LogDBTest, LogMultipleEntriesPerformance) {
    EXPECT_TRUE(InitializeLogDB());

    auto start = std::chrono::steady_clock::now();

    // Log 100 entries
    for (int i = 0; i < 100; ++i) {
        LogDB::Instance().LogInfo(L"PerfTest", L"Performance test message " + std::to_wstring(i));
    }

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time (< 5 seconds for 100 entries)
    EXPECT_LT(duration.count(), 5000);

    DatabaseError err;
    int64_t count = LogDB::Instance().CountEntries(nullptr, &err);
    EXPECT_EQ(count, 100);
}

