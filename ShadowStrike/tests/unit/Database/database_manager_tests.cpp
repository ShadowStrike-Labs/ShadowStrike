

#include <gtest/gtest.h>
#include "../../../src/Database/DatabaseManager.hpp"
#include <filesystem>
#include <thread>
#include <chrono>
#include <atomic>
#include <vector>
#include <random>

using namespace ShadowStrike::Database;
using namespace std::chrono_literals;

namespace fs = std::filesystem;

// ============================================================================
// Test Utilities & Helpers
// ============================================================================

namespace {
    // Generate unique test database path
    std::wstring GenerateTestDbPath() {
        static std::atomic<int> counter{ 0 };
        auto timestamp = std::chrono::system_clock::now().time_since_epoch().count();
        auto id = counter.fetch_add(1, std::memory_order_relaxed);

        std::wstring path = L"test_db_";
        path += std::to_wstring(timestamp);
        path += L"_";
        path += std::to_wstring(id);
        path += L".db";

        return path;
    }

    // Clean up test database file
    void CleanupTestDb(const std::wstring& path) {
        try {
            if (fs::exists(path)) {
                fs::remove(path);
            }

            // Also remove -wal and -shm files
            std::wstring walPath = path + L"-wal";
            std::wstring shmPath = path + L"-shm";

            if (fs::exists(walPath)) fs::remove(walPath);
            if (fs::exists(shmPath)) fs::remove(shmPath);
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }

    // RAII wrapper for test database cleanup
    class TestDatabaseGuard {
    public:
        explicit TestDatabaseGuard(std::wstring path) : m_path(std::move(path)) {}

        ~TestDatabaseGuard() {
            // Ensure database is shut down before cleanup
            DatabaseManager::Instance().Shutdown();
            std::this_thread::sleep_for(100ms); // Give time for file handles to close
            CleanupTestDb(m_path);
        }

        const std::wstring& GetPath() const { return m_path; }

    private:
        std::wstring m_path;
    };

    // Create default test configuration
    DatabaseConfig CreateTestConfig(const std::wstring& dbPath) {
        DatabaseConfig config;
        config.databasePath = dbPath;
        config.enableWAL = true;
        config.enableForeignKeys = true;
        config.enableSecureDelete = false; // Faster for tests
        config.enableMemoryMappedIO = false; // Safer for tests
        config.cacheSizeKB = 2048; // 2MB - smaller for tests
        config.busyTimeoutMs = 5000;
        config.minConnections = 12;
        config.maxConnections = 12;
        config.autoBackup = false; // Disable for tests
        config.journalMode = L"WAL";
        config.synchronousMode = L"NORMAL";

        return config;
    }

    // Create in-memory database config (fastest)
    DatabaseConfig CreateMemoryConfig() {
        DatabaseConfig config;
        config.databasePath = L":memory:";
        config.enableWAL = false; // WAL not supported for :memory:
        config.enableForeignKeys = true;
        config.cacheSizeKB = 2048;
        config.minConnections = 1;
        config.maxConnections = 3;
        config.autoBackup = false;
        config.journalMode = L"MEMORY";
        config.synchronousMode = L"OFF"; // Fastest for in-memory

        return config;
    }
}

// ============================================================================
// Test Fixture
// ============================================================================

class DatabaseManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state
        DatabaseManager::Instance().Shutdown();
        std::this_thread::sleep_for(50ms);

        // Generate unique database path
        m_dbPath = GenerateTestDbPath();
        m_guard = std::make_unique<TestDatabaseGuard>(m_dbPath);

        m_config = CreateTestConfig(m_dbPath);
    }

    void TearDown() override {
        // Shutdown and cleanup
        DatabaseManager::Instance().Shutdown();
        std::this_thread::sleep_for(50ms);
        m_guard.reset(); // Triggers cleanup
    }

    // Helper: Initialize database
    bool InitializeDb() {
        DatabaseError err;
        bool success = DatabaseManager::Instance().Initialize(m_config, &err);
        if (!success) {
            ADD_FAILURE() << "Database initialization failed: "
                << std::string(err.message.begin(), err.message.end());
        }
        return success;
    }

    // Helper: Create a simple test table
    bool CreateTestTable(const std::string& tableName = "test_table") {
        std::string sql = "CREATE TABLE IF NOT EXISTS " + tableName + " ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT NOT NULL, "
            "value INTEGER, "
            "data BLOB)";

        DatabaseError err;
        bool success = DatabaseManager::Instance().Execute(sql, &err);
        if (!success) {
            ADD_FAILURE() << "Failed to create test table: "
                << std::string(err.message.begin(), err.message.end());
        }
        return success;
    }

    std::wstring m_dbPath;
    std::unique_ptr<TestDatabaseGuard> m_guard;
    DatabaseConfig m_config;
};

// ============================================================================
// Initialization & Lifecycle Tests
// ============================================================================

TEST_F(DatabaseManagerTest, InitializeSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, InitializeCreatesFile) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(fs::exists(m_dbPath));
}

TEST_F(DatabaseManagerTest, InitializeWithInvalidPathFails) {
    m_config.databasePath = L"Z:\\invalid\\path\\to\\database.db";

    DatabaseError err;
    EXPECT_FALSE(DatabaseManager::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(err.HasError());
    EXPECT_FALSE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, DoubleInitializeSucceeds) {
    EXPECT_TRUE(InitializeDb());

    // Second initialization should return true
    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().Initialize(m_config, &err));
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, ShutdownClearsInitializedFlag) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());

    DatabaseManager::Instance().Shutdown();

    EXPECT_FALSE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, ShutdownWithoutInitializeIsNoop) {
    EXPECT_NO_THROW(DatabaseManager::Instance().Shutdown());
}

TEST_F(DatabaseManagerTest, DoubleShutdownIsNoop) {
    EXPECT_TRUE(InitializeDb());

    DatabaseManager::Instance().Shutdown();
    EXPECT_NO_THROW(DatabaseManager::Instance().Shutdown());
}

TEST_F(DatabaseManagerTest, InitializeAfterShutdownSucceeds) {
    EXPECT_TRUE(InitializeDb());
    DatabaseManager::Instance().Shutdown();

    std::this_thread::sleep_for(100ms);

    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

// ============================================================================
// Configuration Tests
// ============================================================================

TEST_F(DatabaseManagerTest, GetConfigReturnsCorrectConfig) {
    EXPECT_TRUE(InitializeDb());

    const auto& config = DatabaseManager::Instance().GetConfig();

    EXPECT_EQ(config.databasePath, m_config.databasePath);
    EXPECT_EQ(config.enableWAL, m_config.enableWAL);
    EXPECT_EQ(config.minConnections, m_config.minConnections);
    EXPECT_EQ(config.maxConnections, m_config.maxConnections);
}

TEST_F(DatabaseManagerTest, InitializeWithCustomCacheSizeSucceeds) {
    m_config.cacheSizeKB = 5120; // 5MB

    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, InitializeWithMemoryMappedIOSucceeds) {
    m_config.enableMemoryMappedIO = true;
    m_config.mmapSizeMB = 128;

    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

TEST_F(DatabaseManagerTest, InitializeWithDisabledWALSucceeds) {
    m_config.enableWAL = false;
    m_config.journalMode = L"DELETE";

    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(DatabaseManager::Instance().IsInitialized());
}

// ============================================================================
// Execute & Query Tests
// ============================================================================

TEST_F(DatabaseManagerTest, ExecuteSimpleQuerySucceeds) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    bool success = DatabaseManager::Instance().Execute("SELECT 1", &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ExecuteCreateTableSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());
}

TEST_F(DatabaseManagerTest, ExecuteInsertSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    bool success = DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test', 42)", &err);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ExecuteInvalidSQLFails) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    bool success = DatabaseManager::Instance().Execute("INVALID SQL STATEMENT", &err);

    EXPECT_FALSE(success);
    EXPECT_TRUE(err.HasError());
    EXPECT_NE(err.sqliteCode, SQLITE_OK);
}

TEST_F(DatabaseManagerTest, ExecuteWithoutInitializeFails) {
    DatabaseError err;
    bool success = DatabaseManager::Instance().Execute("SELECT 1", &err);

    EXPECT_FALSE(success);
    EXPECT_TRUE(err.HasError());
}

TEST_F(DatabaseManagerTest, QueryReturnsResults) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test', 42)", nullptr);

    DatabaseError err;
    auto result = DatabaseManager::Instance().Query("SELECT * FROM test_table", &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(result.HasRows());
    EXPECT_GT(result.ColumnCount(), 0);
}

TEST_F(DatabaseManagerTest, QueryEmptyTableSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    auto result = DatabaseManager::Instance().Query("SELECT * FROM test_table", &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_FALSE(result.Next()); // No rows
}

TEST_F(DatabaseManagerTest, QueryIteratesAllRows) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    // Insert multiple rows
    for (int i = 0; i < 10; ++i) {
        std::string sql = "INSERT INTO test_table (name, value) VALUES ('test', " + std::to_string(i) + ")";
        DatabaseManager::Instance().Execute(sql, nullptr);
    }

    DatabaseError err;
    auto result = DatabaseManager::Instance().Query("SELECT * FROM test_table", &err);

    int rowCount = 0;
    while (result.Next()) {
        ++rowCount;
    }

    EXPECT_EQ(rowCount, 10);
}

// ============================================================================
// Parameterized Query Tests
// ============================================================================

TEST_F(DatabaseManagerTest, ExecuteWithParamsIntSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    bool success = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT INTO test_table (name, value) VALUES ('test', ?)", &err, 42);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ExecuteWithParamsStringSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    bool success = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT INTO test_table (name, value) VALUES (?, ?)", &err,
        std::string("test_name"), 123);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, QueryWithParamsReturnsCorrectResults) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test1', 10)", nullptr);
    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test2', 20)", nullptr);

    DatabaseError err;
    auto result = DatabaseManager::Instance().QueryWithParams(
        "SELECT * FROM test_table WHERE value > ?", &err, 15);

    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(result.Next());
    EXPECT_EQ(result.GetString("name"), "test2");
    EXPECT_EQ(result.GetInt("value"), 20);
}

TEST_F(DatabaseManagerTest, ExecuteWithParamsMultipleTypesSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    bool success = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT INTO test_table (name, value) VALUES (?, ?)", &err,
        std::string("mixed_test"), 999);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ExecuteWithParamsBlobSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    std::vector<uint8_t> blobData = { 0x01, 0x02, 0x03, 0x04, 0x05 };

    DatabaseError err;
    bool success = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT INTO test_table (name, data) VALUES (?, ?)", &err,
        std::string("blob_test"), blobData);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Transaction Tests
// ============================================================================

TEST_F(DatabaseManagerTest, BeginTransactionSucceeds) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Deferred, &err);

    EXPECT_NE(trans, nullptr);
    EXPECT_TRUE(trans->IsActive());
    EXPECT_FALSE(err.HasError());
}
TEST_F(DatabaseManagerTest, TransactionCommitSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);
    ASSERT_NE(trans, nullptr);

    // Use Transaction::Execute instead of DatabaseManager::Execute
    EXPECT_TRUE(trans->Execute(
        "INSERT INTO test_table (name, value) VALUES ('trans_test', 100)", &err));

    EXPECT_TRUE(trans->Commit(&err));
    EXPECT_FALSE(trans->IsActive());

    // Verify data was committed
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 1);
}

TEST_F(DatabaseManagerTest, TransactionSavepointSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);
    ASSERT_NE(trans, nullptr);

    // Use Transaction::Execute
    EXPECT_TRUE(trans->Execute(
        "INSERT INTO test_table (name, value) VALUES ('before_savepoint', 1)", &err));

    EXPECT_TRUE(trans->CreateSavepoint("sp1", &err));

    EXPECT_TRUE(trans->Execute(
        "INSERT INTO test_table (name, value) VALUES ('after_savepoint', 2)", &err));

    EXPECT_TRUE(trans->RollbackToSavepoint("sp1", &err));
    EXPECT_TRUE(trans->Commit(&err));

    // Verify only first insert was committed
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 1);
}

TEST_F(DatabaseManagerTest, TransactionRollbackSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);
    ASSERT_NE(trans, nullptr);

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('rollback_test', 200)", nullptr);

    EXPECT_TRUE(trans->Rollback(&err));
    EXPECT_FALSE(trans->IsActive());

    // Verify data was NOT committed
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 0);
}

TEST_F(DatabaseManagerTest, TransactionAutoRollbackOnDestroy) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    {
        DatabaseError err;
        auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);
        ASSERT_NE(trans, nullptr);

        DatabaseManager::Instance().Execute(
            "INSERT INTO test_table (name, value) VALUES ('auto_rollback', 300)", nullptr);

        // Transaction destroyed without commit → auto rollback
    }

    // Verify data was NOT committed
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 0);
}



// ============================================================================
// Schema & Metadata Tests
// ============================================================================

TEST_F(DatabaseManagerTest, CreateTablesSucceeds) {
    EXPECT_TRUE(InitializeDb());

    // CreateTables is called during Initialize, verify tables exist
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("_metadata"));
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("threat_definitions"));
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("scan_history"));
}

TEST_F(DatabaseManagerTest, TableExistsReturnsTrueForExistingTable) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("test_table", &err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, TableExistsReturnsFalseForNonExistingTable) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    EXPECT_FALSE(DatabaseManager::Instance().TableExists("non_existing_table", &err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ColumnExistsReturnsTrueForExistingColumn) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().ColumnExists("test_table", "name", &err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, ColumnExistsReturnsFalseForNonExistingColumn) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    EXPECT_FALSE(DatabaseManager::Instance().ColumnExists("test_table", "non_existing_column", &err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, IndexExistsReturnsTrueForExistingIndex) {
    EXPECT_TRUE(InitializeDb());

    // Default indices created by CreateTables
    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().IndexExists("idx_threats_name", &err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, GetTableNamesReturnsAllTables) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    auto tables = DatabaseManager::Instance().GetTableNames(&err);

    EXPECT_FALSE(err.HasError());
    EXPECT_GT(tables.size(), 0);

    // Check for some expected tables
    EXPECT_TRUE(std::find(tables.begin(), tables.end(), "_metadata") != tables.end());
    EXPECT_TRUE(std::find(tables.begin(), tables.end(), "threat_definitions") != tables.end());
}

TEST_F(DatabaseManagerTest, GetColumnNamesReturnsAllColumns) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    auto columns = DatabaseManager::Instance().GetColumnNames("test_table", &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(columns.size(), 4); // id, name, value, data

    EXPECT_TRUE(std::find(columns.begin(), columns.end(), "id") != columns.end());
    EXPECT_TRUE(std::find(columns.begin(), columns.end(), "name") != columns.end());
    EXPECT_TRUE(std::find(columns.begin(), columns.end(), "value") != columns.end());
    EXPECT_TRUE(std::find(columns.begin(), columns.end(), "data") != columns.end());
}

// ============================================================================
// Utility Function Tests
// ============================================================================

TEST_F(DatabaseManagerTest, LastInsertRowIdReturnsCorrectId) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test', 1)", nullptr);

    int64_t id = DatabaseManager::Instance().LastInsertRowId();
    EXPECT_GT(id, 0);
}

TEST_F(DatabaseManagerTest, GetChangedRowCountReturnsCorrectCount) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test1', 1)", nullptr);
    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test2', 2)", nullptr);
    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('test3', 3)", nullptr);

    DatabaseManager::Instance().Execute("UPDATE test_table SET value = 10 WHERE value < 3", nullptr);

    int count = DatabaseManager::Instance().GetChangedRowCount();
    EXPECT_EQ(count, 2); // Two rows updated
}

TEST_F(DatabaseManagerTest, GetStatsReturnsValidStatistics) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    auto stats = DatabaseManager::Instance().GetStats(&err);

    EXPECT_FALSE(err.HasError());
    EXPECT_GT(stats.totalSize, 0);
    EXPECT_GT(stats.pageCount, 0);
    EXPECT_GT(stats.pageSize, 0);
    EXPECT_GE(stats.totalQueries, 0);
}

// ============================================================================
// Maintenance Operation Tests
// ============================================================================

TEST_F(DatabaseManagerTest, VacuumSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    // Insert and delete data to create fragmentation
    for (int i = 0; i < 100; ++i) {
        std::string sql = "INSERT INTO test_table (name, value) VALUES ('test', " + std::to_string(i) + ")";
        DatabaseManager::Instance().Execute(sql, nullptr);
    }
    DatabaseManager::Instance().Execute("DELETE FROM test_table WHERE value < 50", nullptr);

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().Vacuum(&err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, AnalyzeSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().Analyze(&err));
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, CheckIntegrityPassesForHealthyDatabase) {
    EXPECT_TRUE(InitializeDb());

    std::vector<std::wstring> issues;
    DatabaseError err;

    EXPECT_TRUE(DatabaseManager::Instance().CheckIntegrity(issues, &err));
    EXPECT_TRUE(issues.empty());
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, OptimizeSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().Optimize(&err));
    EXPECT_FALSE(err.HasError());
}

// ============================================================================
// Backup & Restore Tests
// ============================================================================

TEST_F(DatabaseManagerTest, BackupToFileSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('backup_test', 123)", nullptr);

    std::wstring backupPath = m_dbPath + L".backup";
    TestDatabaseGuard backupGuard(backupPath);

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().BackupToFile(backupPath, &err));
    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(fs::exists(backupPath));
}

TEST_F(DatabaseManagerTest, RestoreFromFileSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    DatabaseManager::Instance().Execute(
        "INSERT INTO test_table (name, value) VALUES ('restore_test', 456)", nullptr);

    // Create backup
    std::wstring backupPath = m_dbPath + L".backup";
    TestDatabaseGuard backupGuard(backupPath);
    DatabaseManager::Instance().BackupToFile(backupPath, nullptr);

    // Modify database
    DatabaseManager::Instance().Execute("DELETE FROM test_table", nullptr);

    // Restore
    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().RestoreFromFile(backupPath, &err));
    EXPECT_FALSE(err.HasError());

    // Verify restoration
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 1);
}

TEST_F(DatabaseManagerTest, RestoreNonExistentBackupFails) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    EXPECT_FALSE(DatabaseManager::Instance().RestoreFromFile(L"non_existent_backup.db", &err));
    EXPECT_TRUE(err.HasError());
}

// ============================================================================
// Connection Pool Tests
// ============================================================================

TEST_F(DatabaseManagerTest, AcquireConnectionSucceeds) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    auto conn = DatabaseManager::Instance().AcquireConnection(&err);

    EXPECT_NE(conn, nullptr);
    EXPECT_FALSE(err.HasError());

    DatabaseManager::Instance().ReleaseConnection(conn);
}

TEST_F(DatabaseManagerTest, AcquireMultipleConnectionsSucceeds) {
    EXPECT_TRUE(InitializeDb());

    std::vector<std::shared_ptr<SQLite::Database>> connections;

    for (size_t i = 0; i < m_config.maxConnections; ++i) {
        DatabaseError err;
        auto conn = DatabaseManager::Instance().AcquireConnection(&err);
        EXPECT_NE(conn, nullptr);
        connections.push_back(conn);
    }

    // Release all
    for (auto& conn : connections) {
        DatabaseManager::Instance().ReleaseConnection(conn);
    }
}

TEST_F(DatabaseManagerTest, AcquireConnectionWithoutInitializeFails) {
    DatabaseError err;
    auto conn = DatabaseManager::Instance().AcquireConnection(&err);

    EXPECT_EQ(conn, nullptr);
    EXPECT_TRUE(err.HasError());
}

// ============================================================================
// Concurrency Tests
// ============================================================================

TEST_F(DatabaseManagerTest, ConcurrentInsertsSucceed) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    constexpr int THREAD_COUNT = 5;
    constexpr int INSERTS_PER_THREAD = 20;

    std::vector<std::thread> threads;
    std::atomic<int> successCount{ 0 };

    for (int t = 0; t < THREAD_COUNT; ++t) {
        threads.emplace_back([t, &successCount]() {
            for (int i = 0; i < INSERTS_PER_THREAD; ++i) {
                std::string sql = "INSERT INTO test_table (name, value) VALUES ('thread" +
                    std::to_string(t) + "', " + std::to_string(i) + ")";

                DatabaseError err;
                if (DatabaseManager::Instance().Execute(sql, &err)) {
                    successCount.fetch_add(1, std::memory_order_relaxed);
                }
            }
            });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(successCount.load(), THREAD_COUNT * INSERTS_PER_THREAD);

    // Verify count in database
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), THREAD_COUNT * INSERTS_PER_THREAD);
}
TEST_F(DatabaseManagerTest, ConcurrentQueriesSucceed) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    // Insert test data
    for (int i = 0; i < 100; ++i) {
        DatabaseManager::Instance().ExecuteWithParams(
            "INSERT INTO test_table (name, value) VALUES (?, ?)", nullptr,
            std::string("test"), i);
    }

    
    constexpr int THREAD_COUNT = 10;
    std::vector<std::thread> threads;
    std::atomic<int> queryCount{ 0 };

    for (int t = 0; t < THREAD_COUNT; ++t) {
        threads.emplace_back([&queryCount]() {
            for (int i = 0; i < 10; ++i) {
                {
                    
                    auto result = DatabaseManager::Instance().Query(
                        "SELECT COUNT(*) FROM test_table", nullptr);

                    if (result.Next()) {
                        int count = result.GetInt(0);
                        if (count == 100) {
                            queryCount.fetch_add(1, std::memory_order_relaxed);
                        }
                    }
                   
                }
            }
            });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(queryCount.load(), THREAD_COUNT * 10);
}
TEST_F(DatabaseManagerTest, ConcurrentTransactionsSucceed) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    constexpr int THREAD_COUNT = 5;
    std::vector<std::thread> threads;
    std::atomic<int> committedCount{ 0 };

    for (int t = 0; t < THREAD_COUNT; ++t) {
        threads.emplace_back([t, &committedCount]() {
            DatabaseError err;
            auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);

            if (trans && trans->IsActive()) {
                std::string sql = "INSERT INTO test_table (name, value) VALUES ('trans" +
                    std::to_string(t) + "', " + std::to_string(t) + ")";

               
                if (trans->Execute(sql, &err)) {
                    if (trans->Commit(&err)) {
                        committedCount.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }
            });
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(committedCount.load(), THREAD_COUNT);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST_F(DatabaseManagerTest, DatabaseErrorCapturesDetails) {
    EXPECT_TRUE(InitializeDb());

    DatabaseError err;
    DatabaseManager::Instance().Execute("INVALID SQL", &err);

    EXPECT_TRUE(err.HasError());
    EXPECT_NE(err.sqliteCode, SQLITE_OK);
    EXPECT_FALSE(err.message.empty());
}

TEST_F(DatabaseManagerTest, DatabaseErrorClearWorks) {
    DatabaseError err;
    err.sqliteCode = SQLITE_ERROR;
    err.message = L"Test error";

    EXPECT_TRUE(err.HasError());

    err.Clear();

    EXPECT_FALSE(err.HasError());
    EXPECT_EQ(err.sqliteCode, SQLITE_OK);
    EXPECT_TRUE(err.message.empty());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

TEST_F(DatabaseManagerTest, InsertLargeBlobSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    // Create 1MB blob
    std::vector<uint8_t> largeBlob(1024 * 1024);
    std::mt19937 rng;
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& byte : largeBlob) {
        byte = static_cast<uint8_t>(dist(rng));
    }

    DatabaseError err;
    bool success = DatabaseManager::Instance().ExecuteWithParams(
        "INSERT INTO test_table (name, data) VALUES (?, ?)", &err,
        std::string("large_blob"), largeBlob);

    EXPECT_TRUE(success);
    EXPECT_FALSE(err.HasError());
}

TEST_F(DatabaseManagerTest, QueryLargeResultSetSucceeds) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    
    DatabaseError err;
    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, &err);
    ASSERT_NE(trans, nullptr);

    for (int i = 0; i < 1000; ++i) {
        std::string sql = "INSERT INTO test_table (name, value) VALUES ('row', " + std::to_string(i) + ")";
        EXPECT_TRUE(trans->Execute(sql, &err));
    }
    EXPECT_TRUE(trans->Commit(&err));

    auto result = DatabaseManager::Instance().Query("SELECT * FROM test_table", nullptr);

    int count = 0;
    while (result.Next()) {
        ++count;
    }

    EXPECT_EQ(count, 1000);
}

TEST_F(DatabaseManagerTest, ExecuteManyStatementsSucceeds) {
    EXPECT_TRUE(InitializeDb());

    std::vector<std::string> statements = {
        "CREATE TABLE table1 (id INTEGER PRIMARY KEY)",
        "CREATE TABLE table2 (id INTEGER PRIMARY KEY)",
        "CREATE TABLE table3 (id INTEGER PRIMARY KEY)"
    };

    DatabaseError err;
    EXPECT_TRUE(DatabaseManager::Instance().ExecuteMany(statements, &err));
    EXPECT_FALSE(err.HasError());

    EXPECT_TRUE(DatabaseManager::Instance().TableExists("table1"));
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("table2"));
    EXPECT_TRUE(DatabaseManager::Instance().TableExists("table3"));
}

TEST_F(DatabaseManagerTest, ExecuteManyRollsBackOnFailure) {
    EXPECT_TRUE(InitializeDb());

    std::vector<std::string> statements = {
        "CREATE TABLE valid_table (id INTEGER PRIMARY KEY)",
        "INVALID SQL STATEMENT", // This will fail
        "CREATE TABLE another_table (id INTEGER PRIMARY KEY)"
    };

    DatabaseError err;
    EXPECT_FALSE(DatabaseManager::Instance().ExecuteMany(statements, &err));
    EXPECT_TRUE(err.HasError());

    // First table should NOT exist (rollback)
    EXPECT_FALSE(DatabaseManager::Instance().TableExists("valid_table"));
    EXPECT_FALSE(DatabaseManager::Instance().TableExists("another_table"));
}

// ============================================================================
// Performance Tests (Basic)
// ============================================================================

TEST_F(DatabaseManagerTest, BulkInsertPerformance) {
    EXPECT_TRUE(InitializeDb());
    EXPECT_TRUE(CreateTestTable());

    auto start = std::chrono::steady_clock::now();

    auto trans = DatabaseManager::Instance().BeginTransaction(Transaction::Type::Immediate, nullptr);

    for (int i = 0; i < 1000; ++i) {
        // ✅ FIX: Use Transaction::ExecuteWithParams instead!
        trans->ExecuteWithParams(
            "INSERT INTO test_table (name, value) VALUES (?, ?)", nullptr,
            std::string("bulk"), i);
    }

    trans->Commit(nullptr);

    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time (< 1 second)
    EXPECT_LT(duration.count(), 1000);

    // Verify count
    auto result = DatabaseManager::Instance().Query("SELECT COUNT(*) FROM test_table", nullptr);
    ASSERT_TRUE(result.Next());
    EXPECT_EQ(result.GetInt(0), 1000);
}