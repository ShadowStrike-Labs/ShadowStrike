

#include <gtest/gtest.h>
#include "../../../src/Database/QuarantineDB.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>
#include <fstream>

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

        std::wstring path = L"C:\\Temp\\QuarantineTest_";
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
            QuarantineDB::Instance().Shutdown();
            std::this_thread::sleep_for(100ms);
            CleanupTestDirectory(m_path);
        }

        const std::wstring& GetPath() const { return m_path; }

    private:
        std::wstring m_path;
    };

    // Create test configuration
    QuarantineDB::Config CreateTestConfig(const std::wstring& basePath) {
        QuarantineDB::Config config;
        config.dbPath = basePath + L"\\quarantine_test.db";
        config.quarantineBasePath = basePath + L"\\quarantine";
        config.enableWAL = true;
        config.dbCacheSizeKB = 2048;
        config.maxConnections = 3;
        config.enableEncryption = true;
        config.enableCompression = true;
        config.enableAutoCleanup = false; // Disable for deterministic tests
        config.enableIntegrityChecks = true;
        config.maxRetentionDays = std::chrono::hours(24 * 30); // 30 days for tests
        config.maxQuarantineSize = 100 * 1024 * 1024; // 100MB for tests
        config.enableAuditLog = true;

        return config;
    }

    // Create a test file
    std::wstring CreateTestFile(const std::wstring& basePath, const std::string& content) {
        static std::atomic<int> fileCounter{ 0 };
        int id = fileCounter.fetch_add(1, std::memory_order_relaxed);

        std::wstring filePath = basePath + L"\\test_file_" + std::to_wstring(id) + L".txt";

        std::ofstream file(filePath, std::ios::binary);
        if (file.is_open()) {
            file.write(content.data(), content.size());
            file.close();
        }

        return filePath;
    }

    // Generate random file content
    std::vector<uint8_t> GenerateRandomData(size_t size) {
        std::vector<uint8_t> data(size);
        std::mt19937 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(0, 255);

        for (auto& byte : data) {
            byte = static_cast<uint8_t>(dist(rng));
        }

        return data;
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

class QuarantineDBTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state
        QuarantineDB::Instance().Shutdown();
        std::this_thread::sleep_for(50ms);

        // Generate unique test paths
        m_basePath = GenerateTestBasePath();
        m_guard = std::make_unique<TestDirectoryGuard>(m_basePath);

        // Create test files directory
        m_testFilesPath = m_basePath + L"\\test_files";
        fs::create_directories(m_testFilesPath);

        m_config = CreateTestConfig(m_basePath);
    }

    void TearDown() override {
        QuarantineDB::Instance().Shutdown();
        std::this_thread::sleep_for(50ms);
        m_guard.reset(); // Triggers cleanup
    }

    // Helper: Initialize quarantine DB
    bool InitializeQuarantine() {
        DatabaseError err;
        bool success = QuarantineDB::Instance().Initialize(m_config, &err);
        if (!success) {
            ADD_FAILURE() << "QuarantineDB initialization failed: "
                << std::string(err.message.begin(), err.message.end());
        }
        return success;
    }

    std::wstring m_basePath;
    std::wstring m_testFilesPath;
    std::unique_ptr<TestDirectoryGuard> m_guard;
    QuarantineDB::Config m_config;
};

// ============================================================================
// Initialization & Lifecycle Tests
// ============================================================================

TEST_F(QuarantineDBTest, InitializeSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());
    EXPECT_TRUE(QuarantineDB::Instance().IsInitialized());
}

TEST_F(QuarantineDBTest, InitializeCreatesDirectories) {
    EXPECT_TRUE(InitializeQuarantine());
    EXPECT_TRUE(fs::exists(m_config.quarantineBasePath));
    EXPECT_TRUE(fs::exists(m_config.dbPath));
}

TEST_F(QuarantineDBTest, InitializeWithInvalidPathFails) {
    m_config.dbPath = L"Z:\\invalid\\path\\quarantine.db";

    DatabaseError err;
    EXPECT_FALSE(QuarantineDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(err.HasError());
}

TEST_F(QuarantineDBTest, DoubleInitializeSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    EXPECT_TRUE(QuarantineDB::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(QuarantineDB::Instance().IsInitialized());
}

TEST_F(QuarantineDBTest, ShutdownClearsInitializedFlag) {
    EXPECT_TRUE(InitializeQuarantine());
    EXPECT_TRUE(QuarantineDB::Instance().IsInitialized());

    QuarantineDB::Instance().Shutdown();

    EXPECT_FALSE(QuarantineDB::Instance().IsInitialized());
}

TEST_F(QuarantineDBTest, InitializeAfterShutdownSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());
    QuarantineDB::Instance().Shutdown();

    std::this_thread::sleep_for(100ms);

    EXPECT_TRUE(InitializeQuarantine());
    EXPECT_TRUE(QuarantineDB::Instance().IsInitialized());
}

// ============================================================================
// Basic Quarantine Operations Tests
// ============================================================================

TEST_F(QuarantineDBTest, QuarantineFileSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create test file
    std::string content = "This is a test malware file!";
    std::wstring testFile = CreateTestFile(m_testFilesPath, content);
    ASSERT_TRUE(fs::exists(testFile));

    DatabaseError err;
    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Virus.A",
        L"Test detection",
        &err
    );

    EXPECT_GT(entryId, 0);
    EXPECT_FALSE(err.HasError());

    // Verify entry was created
    auto entry = QuarantineDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->threatType, QuarantineDB::ThreatType::Virus);
    EXPECT_EQ(entry->severity, QuarantineDB::ThreatSeverity::High);
    EXPECT_EQ(entry->threatName, L"Test.Virus.A");
}

TEST_F(QuarantineDBTest, QuarantineNonExistentFileFails) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        L"C:\\nonexistent\\file.exe",
        QuarantineDB::ThreatType::Trojan,
        QuarantineDB::ThreatSeverity::Critical,
        L"Test.Trojan",
        L"",
        &err
    );

    EXPECT_EQ(entryId, -1);
    EXPECT_TRUE(err.HasError());
}

TEST_F(QuarantineDBTest, RestoreFileSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create and quarantine test file
    std::string content = "Test file for restoration!";
    std::wstring testFile = CreateTestFile(m_testFilesPath, content);

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::PUA,
        QuarantineDB::ThreatSeverity::Low,
        L"Test.PUA",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    // Delete original file
    fs::remove(testFile);
    ASSERT_FALSE(fs::exists(testFile));

    // Restore file
    DatabaseError err;
    bool success = QuarantineDB::Instance().RestoreFile(
        entryId,
        testFile,
        L"TestUser",
        L"Test restoration",
        &err
    );

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(testFile));

    // Verify restored content
    std::ifstream restoredFile(testFile, std::ios::binary);
    std::string restoredContent((std::istreambuf_iterator<char>(restoredFile)),
        std::istreambuf_iterator<char>());
    EXPECT_EQ(restoredContent, content);
}

TEST_F(QuarantineDBTest, DeleteQuarantinedFileSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create and quarantine test file
    std::wstring testFile = CreateTestFile(m_testFilesPath, "Delete test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Ransomware,
        QuarantineDB::ThreatSeverity::Critical,
        L"Test.Ransomware",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    // Delete quarantined file
    DatabaseError err;
    bool success = QuarantineDB::Instance().DeleteQuarantinedFile(
        entryId,
        L"TestUser",
        L"Test deletion",
        &err
    );

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());

    // Verify entry status changed to Deleted
    auto entry = QuarantineDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->status, QuarantineDB::QuarantineStatus::Deleted);
}

// ============================================================================
// Query Operations Tests
// ============================================================================

TEST_F(QuarantineDBTest, GetEntryReturnsCorrectData) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring testFile = CreateTestFile(m_testFilesPath, "Query test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Trojan,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Trojan.B",
        L"Test detection reason",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    DatabaseError err;
    auto entry = QuarantineDB::Instance().GetEntry(entryId, &err);

    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->id, entryId);
    EXPECT_EQ(entry->threatType, QuarantineDB::ThreatType::Trojan);
    EXPECT_EQ(entry->severity, QuarantineDB::ThreatSeverity::High);
    EXPECT_EQ(entry->threatName, L"Test.Trojan.B");
    EXPECT_EQ(entry->status, QuarantineDB::QuarantineStatus::Active);
    EXPECT_FALSE(entry->sha256Hash.empty());
}

TEST_F(QuarantineDBTest, GetActiveEntriesReturnsOnlyActive) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create multiple entries
    for (int i = 0; i < 5; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Active test " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Virus,
            QuarantineDB::ThreatSeverity::Medium,
            L"Test.Virus." + std::to_wstring(i),
            L"",
            nullptr
        );
    }

    // Delete one entry
    QuarantineDB::Instance().DeleteQuarantinedFile(1, L"", L"", nullptr);

    DatabaseError err;
    auto activeEntries = QuarantineDB::Instance().GetActiveEntries(100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(activeEntries.size(), 4); // 5 - 1 deleted

    for (const auto& entry : activeEntries) {
        EXPECT_EQ(entry.status, QuarantineDB::QuarantineStatus::Active);
    }
}

TEST_F(QuarantineDBTest, QueryByThreatTypeWorks) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create entries with different threat types
    std::wstring virus = CreateTestFile(m_testFilesPath, "virus");
    std::wstring trojan = CreateTestFile(m_testFilesPath, "trojan");
    std::wstring worm = CreateTestFile(m_testFilesPath, "worm");

    QuarantineDB::Instance().QuarantineFile(virus, QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::High, L"Virus.A", L"", nullptr);
    QuarantineDB::Instance().QuarantineFile(trojan, QuarantineDB::ThreatType::Trojan,
        QuarantineDB::ThreatSeverity::High, L"Trojan.A", L"", nullptr);
    QuarantineDB::Instance().QuarantineFile(worm, QuarantineDB::ThreatType::Worm,
        QuarantineDB::ThreatSeverity::High, L"Worm.A", L"", nullptr);

    DatabaseError err;
    auto virusEntries = QuarantineDB::Instance().GetByThreatType(
        QuarantineDB::ThreatType::Virus, 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(virusEntries.size(), 1);
    EXPECT_EQ(virusEntries[0].threatType, QuarantineDB::ThreatType::Virus);
}

TEST_F(QuarantineDBTest, SearchByFileNameFindsMatches) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring file1 = CreateTestFile(m_testFilesPath, "search");
    std::wstring file2 = CreateTestFile(m_testFilesPath, "search");

    // Rename files to have known names
    std::wstring namedFile1 = m_testFilesPath + L"\\malware_sample_1.exe";
    std::wstring namedFile2 = m_testFilesPath + L"\\malware_sample_2.exe";
    fs::rename(file1, namedFile1);
    fs::rename(file2, namedFile2);

    QuarantineDB::Instance().QuarantineFile(namedFile1, QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::High, L"Virus.1", L"", nullptr);
    QuarantineDB::Instance().QuarantineFile(namedFile2, QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::High, L"Virus.2", L"", nullptr);

    DatabaseError err;
    auto results = QuarantineDB::Instance().SearchByFileName(L"malware_sample", 100, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(results.size(), 2);
}

TEST_F(QuarantineDBTest, CountEntriesReturnsCorrectCount) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create 10 entries
    for (int i = 0; i < 10; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Count test " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Virus,
            QuarantineDB::ThreatSeverity::Medium,
            L"Test.Virus." + std::to_wstring(i),
            L"",
            nullptr
        );
    }

    DatabaseError err;
    int64_t count = QuarantineDB::Instance().CountEntries(nullptr, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(count, 10);
}

// ============================================================================
// File Operations Tests
// ============================================================================

TEST_F(QuarantineDBTest, ExtractFileDataSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    std::string originalContent = "Extract test data!";
    std::wstring testFile = CreateTestFile(m_testFilesPath, originalContent);

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Suspicious,
        QuarantineDB::ThreatSeverity::Low,
        L"Test.Suspicious",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    DatabaseError err;
    std::vector<uint8_t> extractedData;
    bool success = QuarantineDB::Instance().ExtractFileData(entryId, extractedData, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(extractedData.size(), originalContent.size());

    std::string extractedContent(extractedData.begin(), extractedData.end());
    EXPECT_EQ(extractedContent, originalContent);
}

TEST_F(QuarantineDBTest, GetFileHashReturnsValidHashes) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring testFile = CreateTestFile(m_testFilesPath, "Hash test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Virus.Hash",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    DatabaseError err;
    std::wstring md5, sha1, sha256;
    bool success = QuarantineDB::Instance().GetFileHash(entryId, md5, sha1, sha256, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_FALSE(md5.empty());
    EXPECT_FALSE(sha1.empty());
    EXPECT_FALSE(sha256.empty());

    // SHA256 should be 64 hex characters
    EXPECT_EQ(sha256.length(), 64);
}

TEST_F(QuarantineDBTest, VerifyIntegrityPassesForValidFile) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring testFile = CreateTestFile(m_testFilesPath, "Integrity test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Trojan,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Trojan.Integrity",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    DatabaseError err;
    bool isValid = QuarantineDB::Instance().VerifyIntegrity(entryId, &err);

    EXPECT_TRUE(isValid);
    EXPECT_FALSE(err.HasError());
}

TEST_F(QuarantineDBTest, AddNotesSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring testFile = CreateTestFile(m_testFilesPath, "Notes test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Virus,
        QuarantineDB::ThreatSeverity::Medium,
        L"Test.Virus.Notes",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    DatabaseError err;
    bool success = QuarantineDB::Instance().AddNotes(entryId, L"This is a test note", &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());

    auto entry = QuarantineDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->notes.find(L"test note") != std::wstring::npos);
}

// ============================================================================
// Batch Operations Tests
// ============================================================================

TEST_F(QuarantineDBTest, QuarantineBatchSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create multiple test files
    std::vector<std::wstring> testFiles;
    for (int i = 0; i < 5; ++i) {
        testFiles.push_back(CreateTestFile(m_testFilesPath, "Batch test " + std::to_string(i)));
    }

    DatabaseError err;
    bool success = QuarantineDB::Instance().QuarantineBatch(
        testFiles,
        QuarantineDB::ThreatType::Worm,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Worm.Batch",
        &err
    );

    EXPECT_TRUE(success);

    // Verify all files were quarantined
    int64_t count = QuarantineDB::Instance().CountEntries(nullptr, nullptr);
    EXPECT_EQ(count, 5);
}

TEST_F(QuarantineDBTest, RestoreBatchSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Quarantine multiple files
    std::vector<int64_t> entryIds;
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Restore batch " + std::to_string(i));
        int64_t id = QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::PUA,
            QuarantineDB::ThreatSeverity::Low,
            L"Test.PUA.Batch",
            L"",
            nullptr
        );
        ASSERT_GT(id, 0);
        entryIds.push_back(id);
    }

    DatabaseError err;
    bool success = QuarantineDB::Instance().RestoreBatch(entryIds, L"TestUser", &err);

    EXPECT_TRUE(success);

    // Verify all entries were restored
    for (int64_t id : entryIds) {
        auto entry = QuarantineDB::Instance().GetEntry(id, &err);
        ASSERT_TRUE(entry.has_value());
        EXPECT_EQ(entry->status, QuarantineDB::QuarantineStatus::Restored);
    }
}

TEST_F(QuarantineDBTest, DeleteBatchSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Quarantine multiple files
    std::vector<int64_t> entryIds;
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Delete batch " + std::to_string(i));
        int64_t id = QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Trojan,
            QuarantineDB::ThreatSeverity::High,
            L"Test.Trojan.Batch",
            L"",
            nullptr
        );
        ASSERT_GT(id, 0);
        entryIds.push_back(id);
    }

    DatabaseError err;
    bool success = QuarantineDB::Instance().DeleteBatch(entryIds, L"TestUser", &err);

    EXPECT_TRUE(success);

    // Verify all entries were deleted
    for (int64_t id : entryIds) {
        auto entry = QuarantineDB::Instance().GetEntry(id, &err);
        ASSERT_TRUE(entry.has_value());
        EXPECT_EQ(entry->status, QuarantineDB::QuarantineStatus::Deleted);
    }
}

// ============================================================================
// Statistics & Reporting Tests
// ============================================================================

TEST_F(QuarantineDBTest, GetStatisticsReturnsValidData) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create some entries
    for (int i = 0; i < 5; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Stats test " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Virus,
            QuarantineDB::ThreatSeverity::High,
            L"Test.Virus.Stats",
            L"",
            nullptr
        );
    }

    DatabaseError err;
    auto stats = QuarantineDB::Instance().GetStatistics(&err);

    EXPECT_FALSE(err.HasError());
    EXPECT_GE(stats.totalEntries, 5);
    EXPECT_GE(stats.activeEntries, 5);
    EXPECT_GT(stats.totalQuarantineSize, 0);
}

TEST_F(QuarantineDBTest, GenerateReportSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create entries
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Report test " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Ransomware,
            QuarantineDB::ThreatSeverity::Critical,
            L"Test.Ransomware.Report",
            L"",
            nullptr
        );
    }

    std::wstring report = QuarantineDB::Instance().GenerateReport(nullptr);

    EXPECT_FALSE(report.empty());
    EXPECT_TRUE(report.find(L"QUARANTINE REPORT") != std::wstring::npos);
    EXPECT_TRUE(report.find(L"Total Entries") != std::wstring::npos);
}

// ============================================================================
// Export/Import Tests
// ============================================================================

TEST_F(QuarantineDBTest, ExportEntrySucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring testFile = CreateTestFile(m_testFilesPath, "Export test");

    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Spyware,
        QuarantineDB::ThreatSeverity::High,
        L"Test.Spyware.Export",
        L"",
        nullptr
    );
    ASSERT_GT(entryId, 0);

    std::wstring exportPath = m_basePath + L"\\exported_entry.json";

    DatabaseError err;
    bool success = QuarantineDB::Instance().ExportEntry(entryId, exportPath, true, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(exportPath));
}

TEST_F(QuarantineDBTest, ImportEntrySucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // First export an entry
    std::wstring testFile = CreateTestFile(m_testFilesPath, "Import test");

    int64_t originalId = QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Adware,
        QuarantineDB::ThreatSeverity::Low,
        L"Test.Adware.Import",
        L"",
        nullptr
    );
    ASSERT_GT(originalId, 0);

    std::wstring exportPath = m_basePath + L"\\import_test.json";
    QuarantineDB::Instance().ExportEntry(originalId, exportPath, true, nullptr);

    // Clear database
    QuarantineDB::Instance().Shutdown();
    fs::remove(m_config.dbPath);
    EXPECT_TRUE(InitializeQuarantine());

    // Import
    DatabaseError err;
    int64_t importedId = QuarantineDB::Instance().ImportEntry(exportPath, &err);

    EXPECT_GT(importedId, 0);
    EXPECT_FALSE(err.HasError());

    auto entry = QuarantineDB::Instance().GetEntry(importedId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->threatName, L"Test.Adware.Import");
}

TEST_F(QuarantineDBTest, ExportToJSONSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create entries
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "JSON export " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Rootkit,
            QuarantineDB::ThreatSeverity::Critical,
            L"Test.Rootkit.JSON",
            L"",
            nullptr
        );
    }

    std::wstring jsonPath = m_basePath + L"\\export.json";

    DatabaseError err;
    bool success = QuarantineDB::Instance().ExportToJSON(jsonPath, nullptr, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(jsonPath));
    EXPECT_GT(fs::file_size(jsonPath), 0);
}

TEST_F(QuarantineDBTest, ExportToCSVSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create entries
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "CSV export " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Backdoor,
            QuarantineDB::ThreatSeverity::High,
            L"Test.Backdoor.CSV",
            L"",
            nullptr
        );
    }

    std::wstring csvPath = m_basePath + L"\\export.csv";

    DatabaseError err;
    bool success = QuarantineDB::Instance().ExportToCSV(csvPath, nullptr, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(csvPath));
    EXPECT_GT(fs::file_size(csvPath), 0);
}

// ============================================================================
// Backup & Restore Tests
// ============================================================================

TEST_F(QuarantineDBTest, BackupQuarantineSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create entries
    for (int i = 0; i < 3; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Backup " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Exploit,
            QuarantineDB::ThreatSeverity::High,
            L"Test.Exploit.Backup",
            L"",
            nullptr
        );
    }

    std::wstring backupPath = m_basePath + L"\\backup.json";

    DatabaseError err;
    bool success = QuarantineDB::Instance().BackupQuarantine(backupPath, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(backupPath));
    EXPECT_GT(fs::file_size(backupPath), 0);
}

TEST_F(QuarantineDBTest, RestoreQuarantineSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create and backup
    std::wstring testFile = CreateTestFile(m_testFilesPath, "Restore test");
    QuarantineDB::Instance().QuarantineFile(
        testFile,
        QuarantineDB::ThreatType::Script,
        QuarantineDB::ThreatSeverity::Medium,
        L"Test.Script.Restore",
        L"",
        nullptr
    );

    std::wstring backupPath = m_basePath + L"\\restore_backup.json";
    QuarantineDB::Instance().BackupQuarantine(backupPath, nullptr);

    // Clear database
    QuarantineDB::Instance().Shutdown();
    fs::remove(m_config.dbPath);
    EXPECT_TRUE(InitializeQuarantine());

    // Restore
    DatabaseError err;
    bool success = QuarantineDB::Instance().RestoreQuarantine(backupPath, &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());

    int64_t count = QuarantineDB::Instance().CountEntries(nullptr, nullptr);
    EXPECT_GE(count, 1);
}

// ============================================================================
// Maintenance Operations Tests
// ============================================================================

TEST_F(QuarantineDBTest, VacuumSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    bool success = QuarantineDB::Instance().Vacuum(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(QuarantineDBTest, CheckIntegritySucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    bool success = QuarantineDB::Instance().CheckIntegrity(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(QuarantineDBTest, OptimizeSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    bool success = QuarantineDB::Instance().Optimize(&err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Utility Functions Tests
// ============================================================================

TEST_F(QuarantineDBTest, ThreatTypeStringConversionWorks) {
    EXPECT_EQ(QuarantineDB::ThreatTypeToString(QuarantineDB::ThreatType::Virus), L"Virus");
    EXPECT_EQ(QuarantineDB::ThreatTypeToString(QuarantineDB::ThreatType::Trojan), L"Trojan");
    EXPECT_EQ(QuarantineDB::ThreatTypeToString(QuarantineDB::ThreatType::Ransomware), L"Ransomware");

    EXPECT_EQ(QuarantineDB::StringToThreatType(L"Virus"), QuarantineDB::ThreatType::Virus);
    EXPECT_EQ(QuarantineDB::StringToThreatType(L"Trojan"), QuarantineDB::ThreatType::Trojan);
    EXPECT_EQ(QuarantineDB::StringToThreatType(L"Ransomware"), QuarantineDB::ThreatType::Ransomware);
}

TEST_F(QuarantineDBTest, ThreatSeverityStringConversionWorks) {
    EXPECT_EQ(QuarantineDB::ThreatSeverityToString(QuarantineDB::ThreatSeverity::Low), L"Low");
    EXPECT_EQ(QuarantineDB::ThreatSeverityToString(QuarantineDB::ThreatSeverity::High), L"High");
    EXPECT_EQ(QuarantineDB::ThreatSeverityToString(QuarantineDB::ThreatSeverity::Critical), L"Critical");

    EXPECT_EQ(QuarantineDB::StringToThreatSeverity(L"Low"), QuarantineDB::ThreatSeverity::Low);
    EXPECT_EQ(QuarantineDB::StringToThreatSeverity(L"High"), QuarantineDB::ThreatSeverity::High);
    EXPECT_EQ(QuarantineDB::StringToThreatSeverity(L"Critical"), QuarantineDB::ThreatSeverity::Critical);
}

TEST_F(QuarantineDBTest, QuarantineStatusStringConversionWorks) {
    EXPECT_EQ(QuarantineDB::QuarantineStatusToString(QuarantineDB::QuarantineStatus::Active), L"Active");
    EXPECT_EQ(QuarantineDB::QuarantineStatusToString(QuarantineDB::QuarantineStatus::Restored), L"Restored");
    EXPECT_EQ(QuarantineDB::QuarantineStatusToString(QuarantineDB::QuarantineStatus::Deleted), L"Deleted");

    EXPECT_EQ(QuarantineDB::StringToQuarantineStatus(L"Active"), QuarantineDB::QuarantineStatus::Active);
    EXPECT_EQ(QuarantineDB::StringToQuarantineStatus(L"Restored"), QuarantineDB::QuarantineStatus::Restored);
    EXPECT_EQ(QuarantineDB::StringToQuarantineStatus(L"Deleted"), QuarantineDB::QuarantineStatus::Deleted);
}

// ============================================================================
// Edge Cases & Error Handling Tests
// ============================================================================

TEST_F(QuarantineDBTest, RestoreNonExistentEntryFails) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    bool success = QuarantineDB::Instance().RestoreFile(99999, L"", L"", L"", &err);

    EXPECT_FALSE(success);
    EXPECT_TRUE(err.HasError());
}

TEST_F(QuarantineDBTest, DeleteNonExistentEntryFails) {
    EXPECT_TRUE(InitializeQuarantine());

    DatabaseError err;
    bool success = QuarantineDB::Instance().DeleteQuarantinedFile(99999, L"", L"", &err);

    EXPECT_FALSE(success);
    EXPECT_TRUE(err.HasError());
}

TEST_F(QuarantineDBTest, QuarantineLargeFileSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    // Create 5MB test file
    auto largeData = GenerateRandomData(5 * 1024 * 1024);
    std::wstring largeFile = m_basePath + L"\\large_test.bin";

    std::ofstream file(largeFile, std::ios::binary);
    file.write(reinterpret_cast<const char*>(largeData.data()), largeData.size());
    file.close();

    DatabaseError err;
    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        largeFile,
        QuarantineDB::ThreatType::Ransomware,
        QuarantineDB::ThreatSeverity::Critical,
        L"Test.LargeFile",
        L"",
        &err
    );

    EXPECT_GT(entryId, 0);
    EXPECT_FALSE(err.HasError());

    // Verify integrity
    bool isValid = QuarantineDB::Instance().VerifyIntegrity(entryId, &err);
    EXPECT_TRUE(isValid);
}

TEST_F(QuarantineDBTest, QuarantineEmptyFileSucceeds) {
    EXPECT_TRUE(InitializeQuarantine());

    std::wstring emptyFile = CreateTestFile(m_testFilesPath, "");

    DatabaseError err;
    int64_t entryId = QuarantineDB::Instance().QuarantineFile(
        emptyFile,
        QuarantineDB::ThreatType::Suspicious,
        QuarantineDB::ThreatSeverity::Info,
        L"Test.Empty",
        L"",
        &err
    );

    EXPECT_GT(entryId, 0);
    EXPECT_FALSE(err.HasError());

    auto entry = QuarantineDB::Instance().GetEntry(entryId, &err);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->originalSize, 0);
}

// ============================================================================
// Performance Tests (Basic)
// ============================================================================

TEST_F(QuarantineDBTest, QuarantineMultipleFilesPerformance) {
    EXPECT_TRUE(InitializeQuarantine());

    auto start = std::chrono::steady_clock::now();

    // Quarantine 50 files
    for (int i = 0; i < 50; ++i) {
        std::wstring testFile = CreateTestFile(m_testFilesPath, "Perf test " + std::to_string(i));
        QuarantineDB::Instance().QuarantineFile(
            testFile,
            QuarantineDB::ThreatType::Virus,
            QuarantineDB::ThreatSeverity::Medium,
            L"Test.Virus.Perf",
            L"",
            nullptr
        );
    }

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time (< 10 seconds for 50 files)
    EXPECT_LT(duration.count(), 10000);

    int64_t count = QuarantineDB::Instance().CountEntries(nullptr, nullptr);
    EXPECT_EQ(count, 50);
}