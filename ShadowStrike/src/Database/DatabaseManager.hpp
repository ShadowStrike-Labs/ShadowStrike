#pragma once

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>  // For SQLite constants

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <optional>
#include <functional>
#include <chrono>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <atomic>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // Error Handling
        // ============================================================================

        struct DatabaseError {
            int sqliteCode = SQLITE_OK;
            int extendedCode = 0;
            std::wstring message;
            std::wstring query;
            std::wstring context;

            bool HasError() const noexcept { return sqliteCode != SQLITE_OK; }
            void Clear() noexcept {
                sqliteCode = SQLITE_OK;
                extendedCode = 0;
                message.clear();
                query.clear();
                context.clear();
            }
        };

        // ============================================================================
        // Configuration
        // ============================================================================

        struct DatabaseConfig {
            std::wstring databasePath;
            bool enableWAL = true;                      // Write-Ahead Logging for better concurrency
            bool enableForeignKeys = true;
            bool enableSecureDelete = true;             // Overwrite deleted data
            bool enableMemoryMappedIO = true;
            size_t pageSizeBytes = 4096;
            size_t cacheSizeKB = 10240;                 // 10MB default cache
            size_t mmapSizeMB = 256;                    // Memory-mapped I/O size
            int busyTimeoutMs = 30000;                  // 30 second timeout
            std::wstring tempStore = L"MEMORY";         // MEMORY/FILE/DEFAULT
            
            // Connection pooling
            size_t maxConnections = 10;
            size_t minConnections = 2;
            std::chrono::milliseconds connectionTimeout = std::chrono::seconds(30);
            
            // Security
            bool readOnly = false;
            bool encryptionEnabled = false;
            std::vector<uint8_t> encryptionKey;         // AES-256 key if using SQLCipher
            
            // Backup & integrity
            bool autoBackup = true;
            std::chrono::hours backupInterval = std::chrono::hours(24);
            size_t maxBackupCount = 7;
            std::wstring backupDirectory;
            
            // Performance tuning
            std::wstring journalMode = L"WAL";          // DELETE/TRUNCATE/PERSIST/MEMORY/WAL/OFF
            std::wstring synchronousMode = L"NORMAL";   // OFF/NORMAL/FULL/EXTRA
            int lookaside = 1;                          // Enable lookaside memory allocator
        };

        // ============================================================================
        // Query Result Structures
        // ============================================================================

        class QueryResult {
        public:
            QueryResult() = default;
            explicit QueryResult(std::unique_ptr<SQLite::Statement>&& stmt) noexcept;
            
            bool Next();
            bool HasRows() const noexcept { return m_hasRows; }
            int ColumnCount() const noexcept;
            std::wstring ColumnName(int index) const;
            
            // Type-safe value retrieval
            int GetInt(int columnIndex) const;
            int64_t GetInt64(int columnIndex) const;
            double GetDouble(int columnIndex) const;
            std::string GetString(int columnIndex) const;
            std::wstring GetWString(int columnIndex) const;
            std::vector<uint8_t> GetBlob(int columnIndex) const;
            
            // Named column access
            int GetInt(std::string_view columnName) const;
            int64_t GetInt64(std::string_view columnName) const;
            double GetDouble(std::string_view columnName) const;
            std::string GetString(std::string_view columnName) const;
            std::wstring GetWString(std::string_view columnName) const;
            std::vector<uint8_t> GetBlob(std::string_view columnName) const;
            
            // Null checking
            bool IsNull(int columnIndex) const;
            bool IsNull(std::string_view columnName) const;
            
            // Type information
            int GetColumnType(int columnIndex) const;
            int GetColumnType(std::string_view columnName) const;
            
        private:
            int getColumnIndex(std::string_view columnName) const;
            
            std::unique_ptr<SQLite::Statement> m_statement;
            bool m_hasRows = false;
            mutable std::unordered_map<std::string, int> m_columnIndexCache;
        };

        // ============================================================================
        // Prepared Statement Manager (for performance)
        // ============================================================================

        class PreparedStatementCache {
        public:
            explicit PreparedStatementCache(size_t maxSize = 100) noexcept;
            
            std::shared_ptr<SQLite::Statement> Get(
                SQLite::Database& db,
                std::string_view sql,
                DatabaseError* err = nullptr
            );
            
            void Clear() noexcept;
            size_t Size() const noexcept;
            
        private:
            struct CacheEntry {
                std::shared_ptr<SQLite::Statement> statement;
                std::chrono::steady_clock::time_point lastUsed;
            };
            
            mutable std::mutex m_mutex;
            std::unordered_map<std::string, CacheEntry> m_cache;
            size_t m_maxSize;
            
            void evictOldest();
        };

        // ============================================================================
        // Connection Pool
        // ============================================================================

        class ConnectionPool {
        public:
            explicit ConnectionPool(const DatabaseConfig& config) noexcept;
            ~ConnectionPool();
            
            ConnectionPool(const ConnectionPool&) = delete;
            ConnectionPool& operator=(const ConnectionPool&) = delete;
            
            bool Initialize(DatabaseError* err = nullptr);
            void Shutdown();
            
            std::shared_ptr<SQLite::Database> Acquire(
                std::chrono::milliseconds timeout = std::chrono::seconds(30),
                DatabaseError* err = nullptr
            );
            
            void Release(std::shared_ptr<SQLite::Database> conn);
            
            size_t AvailableConnections() const noexcept;
            size_t TotalConnections() const noexcept;
            
        private:
            struct PooledConnection {
                std::shared_ptr<SQLite::Database> connection;
                std::chrono::steady_clock::time_point lastUsed;
                bool inUse = false;
            };
            
            bool createConnection(DatabaseError* err);
            bool configureConnection(SQLite::Database& db, DatabaseError* err);
            
            DatabaseConfig m_config;
            mutable std::mutex m_mutex;
            std::condition_variable m_cv;
            std::vector<PooledConnection> m_connections;
            std::atomic<bool> m_shutdown{ false };
            std::atomic<size_t> m_activeCount{ 0 };
        };

        // ============================================================================
        // Transaction Manager (RAII)
        // ============================================================================

        class Transaction {
        public:
            enum class Type {
                Deferred,   // Default, lock acquired on first read/write
                Immediate,  // Reserved lock acquired immediately
                Exclusive   // Exclusive lock acquired immediately
            };
            
            explicit Transaction(
                SQLite::Database& db,
                Type type = Type::Deferred,
                DatabaseError* err = nullptr
            );
            
            ~Transaction();
            
            Transaction(const Transaction&) = delete;
            Transaction& operator=(const Transaction&) = delete;
            Transaction(Transaction&&) noexcept;
            Transaction& operator=(Transaction&&) noexcept;
            
            bool Commit(DatabaseError* err = nullptr);
            bool Rollback(DatabaseError* err = nullptr);
            bool IsActive() const noexcept { return m_active; }
            
            // Savepoint support
            bool CreateSavepoint(std::string_view name, DatabaseError* err = nullptr);
            bool RollbackToSavepoint(std::string_view name, DatabaseError* err = nullptr);
            bool ReleaseSavepoint(std::string_view name, DatabaseError* err = nullptr);
            
        private:
            SQLite::Database* m_db = nullptr;
            bool m_active = false;
            bool m_committed = false;
        };

        // ============================================================================
        // Database Manager (Main Interface)
        // ============================================================================

        class DatabaseManager {
        public:
            static DatabaseManager& Instance();
            
            // Initialization
            bool Initialize(const DatabaseConfig& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }
            
            // Schema management
            bool CreateTables(DatabaseError* err = nullptr);
            bool UpgradeSchema(int currentVersion, int targetVersion, DatabaseError* err = nullptr);
            int GetSchemaVersion(DatabaseError* err = nullptr);
            bool SetSchemaVersion(int version, DatabaseError* err = nullptr);
            
            // Query execution
            bool Execute(std::string_view sql, DatabaseError* err = nullptr);
            bool ExecuteMany(const std::vector<std::string>& statements, DatabaseError* err = nullptr);
            
            QueryResult Query(std::string_view sql, DatabaseError* err = nullptr);
            
            // Prepared statements with binding
            template<typename... Args>
            bool ExecuteWithParams(
                std::string_view sql,
                DatabaseError* err,
                Args&&... args
            );
            
            template<typename... Args>
            QueryResult QueryWithParams(
                std::string_view sql,
                DatabaseError* err,
                Args&&... args
            );
            
            // Transaction support
            std::unique_ptr<Transaction> BeginTransaction(
                Transaction::Type type = Transaction::Type::Deferred,
                DatabaseError* err = nullptr
            );
            
            // Batch operations
            template<typename Func>
            bool BatchInsert(
                std::string_view tableName,
                const std::vector<std::string>& columns,
                size_t rowCount,
                Func&& bindFunc,
                DatabaseError* err = nullptr
            );
            
            // Utility functions
            int64_t LastInsertRowId();
            int GetChangedRowCount();
            
            bool TableExists(std::string_view tableName, DatabaseError* err = nullptr);
            bool ColumnExists(std::string_view tableName, std::string_view columnName, DatabaseError* err = nullptr);
            bool IndexExists(std::string_view indexName, DatabaseError* err = nullptr);
            
            std::vector<std::string> GetTableNames(DatabaseError* err = nullptr);
            std::vector<std::string> GetColumnNames(std::string_view tableName, DatabaseError* err = nullptr);
            
            // Maintenance operations
            bool Vacuum(DatabaseError* err = nullptr);
            bool Analyze(DatabaseError* err = nullptr);
            bool CheckIntegrity(std::vector<std::wstring>& issues, DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);
            
            // Backup & restore
            bool BackupToFile(std::wstring_view backupPath, DatabaseError* err = nullptr);
            bool RestoreFromFile(std::wstring_view backupPath, DatabaseError* err = nullptr);
            bool CreateAutoBackup(DatabaseError* err = nullptr);
            
            // Statistics
            struct DatabaseStats {
                size_t totalSize = 0;
                size_t pageCount = 0;
                size_t pageSize = 0;
                size_t freePages = 0;
                size_t cacheHitRate = 0;
                int64_t totalQueries = 0;
                int64_t totalTransactions = 0;
                std::chrono::milliseconds averageQueryTime{};
            };
            
            DatabaseStats GetStats(DatabaseError* err = nullptr);
            
            // Configuration
            const DatabaseConfig& GetConfig() const noexcept { return m_config; }
            
            // Connection access (use with caution)
            std::shared_ptr<SQLite::Database> AcquireConnection(DatabaseError* err = nullptr);
            void ReleaseConnection(std::shared_ptr<SQLite::Database> conn);
            
        private:
            DatabaseManager();
            ~DatabaseManager();
            
            DatabaseManager(const DatabaseManager&) = delete;
            DatabaseManager& operator=(const DatabaseManager&) = delete;
            
            // Initialization helpers
            bool createDatabaseFile(DatabaseError* err);
            bool configurePragmas(SQLite::Database& db, DatabaseError* err);
            bool enableSecurity(SQLite::Database& db, DatabaseError* err);
            
            // Schema helpers
            bool executeSchemaMigration(SQLite::Database& db, int version, DatabaseError* err);
            
            // Backup helpers
            void backgroundBackupThread();
            bool performBackup(const std::wstring& backupPath, DatabaseError* err);
            void cleanupOldBackups();
            
            // Error handling
            void setError(DatabaseError* err, int code, std::wstring_view msg, std::wstring_view ctx = L"") const;
            void setError(DatabaseError* err, const SQLite::Exception& ex, std::wstring_view ctx = L"") const;
            
            // Helper for binding parameters
            template<typename T>
            void bindParameter(SQLite::Statement& stmt, int index, T&& value);
            
            template<typename T, typename... Args>
            void bindParameters(SQLite::Statement& stmt, int index, T&& first, Args&&... rest);
            
            void bindParameters(SQLite::Statement& stmt, int index) {}  // Base case
            
            // State
            std::atomic<bool> m_initialized{ false };
            DatabaseConfig m_config;
            
            std::unique_ptr<ConnectionPool> m_connectionPool;
            std::unique_ptr<PreparedStatementCache> m_statementCache;
            
            mutable std::shared_mutex m_configMutex;
            
            // Statistics
            std::atomic<int64_t> m_totalQueries{ 0 };
            std::atomic<int64_t> m_totalTransactions{ 0 };
            
            // Background backup
            std::thread m_backupThread;
            std::atomic<bool> m_shutdownBackupThread{ false };
            std::condition_variable m_backupCv;
            std::mutex m_backupMutex;
            std::chrono::steady_clock::time_point m_lastBackup;
        };

        // ============================================================================
        // Template Implementations
        // ============================================================================

        template<typename... Args>
        bool DatabaseManager::ExecuteWithParams(
            std::string_view sql,
            DatabaseError* err,
            Args&&... args
        ) {
            try {
                auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                auto stmt = m_statementCache->Get(*conn, sql, err);
                if (!stmt) {
                    ReleaseConnection(conn);
                    return false;
                }
                
                bindParameters(*stmt, 1, std::forward<Args>(args)...);
                
                stmt->exec();
                m_totalQueries.fetch_add(1, std::memory_order_relaxed);
                
                ReleaseConnection(conn);
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"ExecuteWithParams");
                return false;
            }
        }

        template<typename... Args>
        QueryResult DatabaseManager::QueryWithParams(
            std::string_view sql,
            DatabaseError* err,
            Args&&... args
        ) {
            try {
                auto conn = AcquireConnection(err);
                if (!conn) return QueryResult{};
                
                auto stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                
                bindParameters(*stmt, 1, std::forward<Args>(args)...);
                
                m_totalQueries.fetch_add(1, std::memory_order_relaxed);
                
                // Note: Connection released when QueryResult is destroyed
                return QueryResult{ std::move(stmt) };
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"QueryWithParams");
                return QueryResult{};
            }
        }

        template<typename Func>
        bool DatabaseManager::BatchInsert(
            std::string_view tableName,
            const std::vector<std::string>& columns,
            size_t rowCount,
            Func&& bindFunc,
            DatabaseError* err
        ) {
            if (columns.empty() || rowCount == 0) {
                setError(err, SQLITE_MISUSE, L"Invalid batch insert parameters");
                return false;
            }
            
            try {
                auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                // Build INSERT statement
                std::string sql = "INSERT INTO ";
                sql += tableName;
                sql += " (";
                for (size_t i = 0; i < columns.size(); ++i) {
                    if (i > 0) sql += ", ";
                    sql += columns[i];
                }
                sql += ") VALUES (";
                for (size_t i = 0; i < columns.size(); ++i) {
                    if (i > 0) sql += ", ";
                    sql += "?";
                }
                sql += ")";
                
                auto trans = BeginTransaction(Transaction::Type::Immediate, err);
                if (!trans || !trans->IsActive()) {
                    ReleaseConnection(conn);
                    return false;
                }
                
                SQLite::Statement stmt(*conn, sql);
                
                for (size_t row = 0; row < rowCount; ++row) {
                    stmt.reset();
                    stmt.clearBindings();
                    
                    // Call user's binding function
                    bindFunc(stmt, row);
                    
                    stmt.exec();
                }
                
                if (!trans->Commit(err)) {
                    ReleaseConnection(conn);
                    return false;
                }
                
                ReleaseConnection(conn);
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"BatchInsert");
                return false;
            }
        }

        template<typename T>
        void DatabaseManager::bindParameter(SQLite::Statement& stmt, int index, T&& value) {
            using DecayT = std::decay_t<T>;
            
            if constexpr (std::is_same_v<DecayT, bool>) {
                stmt.bind(index, static_cast<int>(value));
            }
            else if constexpr (std::is_same_v<DecayT, int>) {
                stmt.bind(index, value);
            }
            else if constexpr (std::is_same_v<DecayT, int64_t> || std::is_same_v<DecayT, long long>) {
                stmt.bind(index, static_cast<sqlite3_int64>(value));
            }
            else if constexpr (std::is_same_v<DecayT, double> || std::is_same_v<DecayT, float>) {
                stmt.bind(index, static_cast<double>(value));
            }
            else if constexpr (std::is_same_v<DecayT, const char*> || std::is_same_v<DecayT, std::string>) {
                stmt.bind(index, std::string(value));
            }
            else if constexpr (std::is_same_v<DecayT, std::string_view>) {
                stmt.bind(index, std::string(value));
            }
            else if constexpr (std::is_same_v<DecayT, std::vector<uint8_t>>) {
                if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
                    
					SS_LOG_ERROR(L"Database", L"Blob size exceeds maximum allowed size for binding");
                }
                stmt.bind(index, value.data(), static_cast<int>(value.size()));
            }
            else if constexpr (std::is_same_v<DecayT, std::nullptr_t>) {
                stmt.bind(index);  // NULL
            }
            else {
                static_assert(sizeof(T) == 0, "Unsupported parameter type");
            }
        }

        template<typename T, typename... Args>
        void DatabaseManager::bindParameters(SQLite::Statement& stmt, int index, T&& first, Args&&... rest) {
            bindParameter(stmt, index, std::forward<T>(first));
            bindParameters(stmt, index + 1, std::forward<Args>(rest)...);
        }

    } // namespace Database
} // namespace ShadowStrike