#pragma once

/**
 * ============================================================================
 * ShadowStrike DatabaseManager - HEADER
 * ============================================================================
 *
 * @file DatabaseManager.hpp
 * @brief Enterprise-grade SQLite database management with connection pooling.
 *
 * This header defines the database abstraction layer for the ShadowStrike
 * antivirus engine. It provides a high-level, type-safe interface for all
 * database operations with enterprise features like connection pooling,
 * prepared statement caching, and automatic backups.
 *
 * Architecture Overview:
 * ----------------------
 *
 *   Application Code
 *         │
 *         ▼
 *   ┌──────────────────────────────────────────────────────────────────┐
 *   │                    DatabaseManager (Singleton)                   │
 *   │  ┌─────────────────────────────────────────────────────────┐   │
 *   │  │ Execute(), Query(), BeginTransaction(), QueryWithParams()│   │
 *   │  └─────────────────────────────────────────────────────────┘   │
 *   │                              │                                  │
 *   │         ┌───────────────────┼───────────────────┐              │
 *   │         ▼                   ▼                   ▼              │
 *   │  ┌────────────┐    ┌────────────────┐    ┌──────────────┐     │
 *   │  │ Connection │    │ PreparedStmt   │    │ Transaction  │     │
 *   │  │   Pool     │    │    Cache       │    │   Manager    │     │
 *   │  └────────────┘    └────────────────┘    └──────────────┘     │
 *   │         │                                                       │
 *   │         ▼                                                       │
 *   │  ┌──────────────────────────────────────────────────────────┐  │
 *   │  │              SQLite3 Connections (via SQLiteCpp)          │  │
 *   │  └──────────────────────────────────────────────────────────┘  │
 *   └──────────────────────────────────────────────────────────────────┘
 *
 * Key Components:
 * ---------------
 *
 * 1. DatabaseConfig
 *    Configuration structure for all database settings including:
 *    - Connection parameters (path, timeouts, pool sizes)
 *    - Performance tuning (cache size, page size, WAL mode)
 *    - Security options (encryption, secure delete)
 *    - Backup settings (auto-backup, retention)
 *
 * 2. DatabaseError
 *    Structured error information including SQLite codes, extended
 *    codes, and context for debugging.
 *
 * 3. QueryResult
 *    Iterator-style result set with type-safe column access.
 *    Automatically returns connection to pool on destruction.
 *
 * 4. PreparedStatementCache
 *    LRU cache for compiled SQL statements. Eliminates repeated
 *    parsing overhead for frequently executed queries.
 *
 * 5. ConnectionPool
 *    Pre-warmed connection pool for low-latency acquisition.
 *    Configurable min/max connections with timeout-based waiting.
 *
 * 6. Transaction
 *    RAII-based transaction management with automatic rollback
 *    on scope exit. Supports DEFERRED, IMMEDIATE, EXCLUSIVE types.
 *
 * 7. DatabaseManager
 *    Singleton facade providing the primary API. Thread-safe
 *    initialization and operations.
 *
 * Thread Safety:
 * --------------
 * - DatabaseManager: Thread-safe singleton
 * - ConnectionPool: Thread-safe acquire/release
 * - PreparedStatementCache: Thread-safe get/clear
 * - QueryResult: NOT thread-safe (single-thread use)
 * - Transaction: NOT thread-safe (single-thread use)
 *
 * Usage Example:
 * --------------
 * @code
 *   // Initialize (typically at application startup)
 *   DatabaseConfig config;
 *   config.databasePath = L"C:\\Data\\shadowstrike.db";
 *   config.enableWAL = true;
 *   config.minConnections = 2;
 *   config.maxConnections = 10;
 *   
 *   DatabaseError err;
 *   if (!DatabaseManager::Instance().Initialize(config, &err)) {
 *       // Handle error
 *   }
 *   
 *   // Execute a query
 *   auto result = DatabaseManager::Instance().QueryWithParams(
 *       "SELECT * FROM threats WHERE severity > ?",
 *       &err,
 *       5
 *   );
 *   
 *   while (result.Next()) {
 *       auto name = result.GetWString("name");
 *       auto severity = result.GetInt("severity");
 *       // Process row...
 *   }
 *   
 *   // Transaction example
 *   auto txn = DatabaseManager::Instance().BeginTransaction(
 *       Transaction::Type::Immediate, &err
 *   );
 *   
 *   if (txn && txn->IsActive()) {
 *       DatabaseManager::Instance().Execute("INSERT INTO ...", &err);
 *       DatabaseManager::Instance().Execute("UPDATE ...", &err);
 *       txn->Commit(&err);
 *   }
 * @endcode
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * ============================================================================
 */

#include <SQLiteCpp/SQLiteCpp.h>
#include "../../include/SQLiteCpp/sqlite3.h" // For SQLite constants


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

        // Forward declaration for QueryResult dependency
        class DatabaseManager;

        // ============================================================================
        // ERROR HANDLING
        // ============================================================================

        /**
         * @brief Structured error information for database operations.
         *
         * Contains SQLite error codes, extended codes, and contextual
         * information for debugging and logging.
         *
         * @note All fields are cleared on Clear() call
         */
        struct DatabaseError {
            int sqliteCode = SQLITE_OK;     ///< Primary SQLite result code
            int extendedCode = 0;           ///< Extended error code for details
            std::wstring message;           ///< Human-readable error message
            std::wstring query;             ///< SQL query that caused the error
            std::wstring context;           ///< Operation context (function name)

            /** @brief Returns true if an error is present */
            bool HasError() const noexcept { return sqliteCode != SQLITE_OK; }

            /** @brief Resets all error fields to default state */
            void Clear() noexcept {
                sqliteCode = SQLITE_OK;
                extendedCode = 0;
                message.clear();
                query.clear();
                context.clear();
            }
        };

        // ============================================================================
        // CONFIGURATION
        // ============================================================================

        /**
         * @brief Configuration options for DatabaseManager initialization.
         *
         * Provides comprehensive control over SQLite behavior, connection
         * pooling, security features, and backup settings.
         *
         * @note Changes only take effect on next Initialize() call
         */
        struct DatabaseConfig {
            // === Core Settings ===
            std::wstring databasePath;                  ///< Full path to database file
            bool enableWAL = true;                      ///< Enable Write-Ahead Logging
            bool enableForeignKeys = true;             ///< Enable FK constraint checking
            bool enableSecureDelete = true;            ///< Overwrite deleted data
            bool enableMemoryMappedIO = true;          ///< Use memory-mapped I/O

            // === Performance Tuning ===
            size_t pageSizeBytes = 4096;               ///< Database page size (power of 2)
            size_t cacheSizeKB = 10240;                ///< Page cache size (10MB default)
            size_t mmapSizeMB = 256;                   ///< Memory-mapped I/O size
            int busyTimeoutMs = 30000;                 ///< Wait time for locked database
            std::wstring tempStore = L"MEMORY";        ///< Temp storage: MEMORY/FILE/DEFAULT
            
            // === Connection Pooling ===
            size_t maxConnections = 10;                ///< Maximum pool size
            size_t minConnections = 2;                 ///< Pre-warmed connections
            std::chrono::milliseconds connectionTimeout = std::chrono::seconds(30);
            
            // === Security ===
            bool readOnly = false;                     ///< Open database read-only
            bool encryptionEnabled = false;            ///< Enable SQLCipher encryption
            std::vector<uint8_t> encryptionKey;        ///< AES-256 key for SQLCipher
            
            // === Backup & Integrity ===
            bool autoBackup = true;                    ///< Enable automatic backups
            std::chrono::hours backupInterval = std::chrono::hours(24);
            size_t maxBackupCount = 7;                 ///< Backup retention count
            std::wstring backupDirectory;              ///< Backup storage location
            
            // === Advanced SQLite PRAGMAs ===
            std::wstring journalMode = L"WAL";         ///< DELETE/TRUNCATE/PERSIST/MEMORY/WAL/OFF
            std::wstring synchronousMode = L"NORMAL";  ///< OFF/NORMAL/FULL/EXTRA
            int lookaside = 1;                         ///< Lookaside memory allocator
        };

        // ============================================================================
        // QUERY RESULT
        // ============================================================================

        /**
         * @brief Iterator-style result set wrapper for SELECT queries.
         *
         * QueryResult provides type-safe access to query result columns.
         * It manages the lifecycle of the underlying prepared statement
         * and returns the connection to the pool when destroyed.
         *
         * @note Move-only semantics - cannot be copied
         * @note NOT thread-safe - use from single thread only
         *
         * @code
         *   auto result = manager.Query("SELECT id, name FROM users");
         *   while (result.Next()) {
         *       int id = result.GetInt("id");
         *       std::wstring name = result.GetWString("name");
         *   }
         * @endcode
         */
        class QueryResult {
        public:
            /** @brief Constructs empty result (no data) */
            QueryResult() = default;

            /** @brief Constructs from statement only (internal use) */
            explicit QueryResult(std::unique_ptr<SQLite::Statement>&& stmt) noexcept
                : m_statement(std::move(stmt))
            {
                if (m_statement) {
                    m_hasRows = (m_statement->getColumnCount() > 0);
                }
            }

            /**
             * @brief Constructs result with connection management.
             * 
             * @param stmt Prepared statement (takes ownership)
             * @param conn Database connection (shared ownership)
             * @param manager Pointer to manager for connection release
             */
            explicit QueryResult(
                std::unique_ptr<SQLite::Statement>&& stmt,
                std::shared_ptr<SQLite::Database> conn,
                DatabaseManager* manager
            ) noexcept;

            /** @brief Destructor - releases statement and connection */
            ~QueryResult();

            // Disable copy (move-only semantics)
            QueryResult(const QueryResult&) = delete;
            QueryResult& operator=(const QueryResult&) = delete;

            // Enable move
            QueryResult(QueryResult&& other) noexcept;
            QueryResult& operator=(QueryResult&& other) noexcept;
            
            // === Navigation ===
            
            /** @brief Advances to the next row. @return false if no more rows */
            bool Next();
            
            /** @brief Returns true if query returned rows */
            bool HasRows() const noexcept { return m_hasRows; }
            
            /** @brief Returns number of columns in result set */
            int ColumnCount() const noexcept;
            
            /** @brief Returns column name at given index */
            std::wstring ColumnName(int index) const;
            
            // === Type-safe Value Retrieval (by index) ===
            
            int GetInt(int columnIndex) const;
            int64_t GetInt64(int columnIndex) const;
            double GetDouble(int columnIndex) const;
            std::string GetString(int columnIndex) const;
            std::wstring GetWString(int columnIndex) const;
            std::vector<uint8_t> GetBlob(int columnIndex) const;
            
            // === Type-safe Value Retrieval (by name) ===
            
            int GetInt(std::string_view columnName) const;
            int64_t GetInt64(std::string_view columnName) const;
            double GetDouble(std::string_view columnName) const;
            std::string GetString(std::string_view columnName) const;
            std::wstring GetWString(std::string_view columnName) const;
            std::vector<uint8_t> GetBlob(std::string_view columnName) const;
            
            // === NULL Checking ===
            
            bool IsNull(int columnIndex) const;
            bool IsNull(std::string_view columnName) const;
            
            // Type information
            int GetColumnType(int columnIndex) const;
            int GetColumnType(std::string_view columnName) const;
            
        private:
            int getColumnIndex(std::string_view columnName) const;
            
            std::unique_ptr<SQLite::Statement> m_statement;
            std::shared_ptr<SQLite::Database> m_connection;  
            DatabaseManager* m_manager = nullptr;             
            bool m_hasRows = false;
            mutable std::unordered_map<std::string, int> m_columnIndexCache;
        };

        // ============================================================================
        // PREPARED STATEMENT CACHE
        // ============================================================================

        /**
         * @brief LRU cache for compiled SQL statements.
         *
         * Caches prepared statements to avoid repeated parsing overhead.
         * Uses Least Recently Used (LRU) eviction when at capacity.
         *
         * Performance Impact:
         * - First query execution: ~100-500μs (parse + optimize)
         * - Cached execution: ~1-5μs (bind + execute)
         *
         * @note Thread-safe via internal mutex
         */
        class PreparedStatementCache {
        public:
            /**
             * @brief Constructs cache with maximum entry count.
             * @param maxSize Maximum cached statements (default 100)
             */
            explicit PreparedStatementCache(size_t maxSize = 100) noexcept;
            
            /**
             * @brief Gets or creates a prepared statement.
             * @param db Database to prepare statement on
             * @param sql SQL query string
             * @param err Optional error output
             * @return Prepared statement, nullptr on error
             */
            std::shared_ptr<SQLite::Statement> Get(
                SQLite::Database& db,
                std::string_view sql,
                DatabaseError* err = nullptr
            );
            
            /** @brief Clears all cached statements */
            void Clear() noexcept;
            
            /** @brief Returns number of cached statements */
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
        // CONNECTION POOL
        // ============================================================================

        /**
         * @brief Manages a pool of database connections for reuse.
         *
         * Maintains pre-warmed connections for low-latency acquisition.
         * Grows dynamically up to maxConnections when needed.
         *
         * Lifecycle:
         * 1. Initialize() - Creates minConnections
         * 2. Acquire() - Gets connection from pool (or waits)
         * 3. Release() - Returns connection to pool
         * 4. Shutdown() - Closes all connections
         *
         * @note Thread-safe via mutex and condition variable
         */
        class ConnectionPool {
        public:
            explicit ConnectionPool(const DatabaseConfig& config) noexcept;
            ~ConnectionPool();
            
            // Non-copyable
            ConnectionPool(const ConnectionPool&) = delete;
            ConnectionPool& operator=(const ConnectionPool&) = delete;
            
            /**
             * @brief Initializes pool with minimum connections.
             * @param err Optional error output
             * @return true if initialized successfully
             */
            bool Initialize(DatabaseError* err = nullptr);
            
            /** @brief Shuts down pool and closes all connections */
            void Shutdown();
            
            /**
             * @brief Acquires a connection from the pool.
             * @param timeout Maximum wait time
             * @param err Optional error output
             * @return Connection, nullptr on timeout/error
             */
            std::shared_ptr<SQLite::Database> Acquire(
                std::chrono::milliseconds timeout = std::chrono::seconds(30),
                DatabaseError* err = nullptr
            );
            
            /** @brief Returns connection to pool */
            void Release(std::shared_ptr<SQLite::Database> conn);
            
            /** @brief Returns count of idle connections */
            size_t AvailableConnections() const noexcept;
            
            /** @brief Returns total connections (idle + active) */
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
        // TRANSACTION (RAII)
        // ============================================================================

        /**
         * @brief RAII-based transaction management.
         *
         * Automatically rolls back if not explicitly committed.
         * Ensures data consistency even when exceptions occur.
         *
         * Transaction Types:
         * - DEFERRED: Lock on first access (default, good for reads)
         * - IMMEDIATE: Write lock immediately (prevents deadlocks)
         * - EXCLUSIVE: Full database lock (serialized access)
         *
         * @code
         *   auto txn = manager.BeginTransaction(Transaction::Type::Immediate);
         *   if (txn->IsActive()) {
         *       txn->Execute("INSERT INTO ...");
         *       txn->Execute("UPDATE ...");
         *       txn->Commit();
         *   }
         *   // If Commit() not called, destructor rolls back
         * @endcode
         *
         * @note NOT thread-safe - use from single thread only
         */
        class Transaction {
        public:
            /**
             * @brief Transaction isolation levels.
             */
            enum class Type {
                Deferred,   ///< Lock acquired on first read/write
                Immediate,  ///< RESERVED lock acquired immediately
                Exclusive   ///< EXCLUSIVE lock acquired immediately
            };
            
            /**
             * @brief Constructs and begins a transaction.
             * @param db Database reference
             * @param conn Connection for lifecycle management
             * @param manager DatabaseManager for connection release
             * @param type Transaction isolation level
             * @param err Optional error output
             */
            explicit Transaction(
                SQLite::Database& db,
				std::shared_ptr<SQLite::Database> conn,
                DatabaseManager* manager,
                Type type = Type::Deferred,
                DatabaseError* err = nullptr
            );
            
            /** @brief Destructor - rolls back if not committed */
            ~Transaction();
            
            // Non-copyable, movable
            Transaction(const Transaction&) = delete;
            Transaction& operator=(const Transaction&) = delete;
            Transaction(Transaction&&) noexcept;
            Transaction& operator=(Transaction&&) noexcept;
            
            /** @brief Commits all changes. @return true on success */
            bool Commit(DatabaseError* err = nullptr);
            
            /** @brief Rolls back all changes. @return true on success */
            bool Rollback(DatabaseError* err = nullptr);
            
            /** @brief Returns true if transaction is active */
            bool IsActive() const noexcept { return m_active; }

            /**
             * @brief Executes SQL within this transaction.
             * @param sql SQL statement
             * @param err Optional error output
             * @return true on success
             */
			bool Execute(std::string_view sql, DatabaseError* err = nullptr);

            /**
             * @brief Executes parameterized SQL within this transaction.
             * @tparam Args Parameter types
             * @param sql SQL with ? placeholders
             * @param err Optional error output
             * @param args Parameter values
             * @return true on success
             */
            template<typename... Args>
            bool ExecuteWithParams(std::string_view sql, DatabaseError* err, Args&&... args);
              
            // === Savepoint Support ===
            
            /** @brief Creates a savepoint for partial rollback */
            bool CreateSavepoint(std::string_view name, DatabaseError* err = nullptr);
            
            /** @brief Rolls back to a savepoint */
            bool RollbackToSavepoint(std::string_view name, DatabaseError* err = nullptr);
            
            /** @brief Releases (commits) a savepoint */
            bool ReleaseSavepoint(std::string_view name, DatabaseError* err = nullptr);
            
        private:
            SQLite::Database* m_db = nullptr;
			std::shared_ptr<SQLite::Database> m_connection;
			DatabaseManager* m_manager = nullptr;
            bool m_active = false;
            bool m_committed = false;
        };

        // ============================================================================
        // DATABASE MANAGER (MAIN INTERFACE)
        // ============================================================================

        /**
         * @brief Singleton facade for all database operations.
         *
         * DatabaseManager is the primary entry point for database access.
         * It provides thread-safe initialization, query execution,
         * transaction management, and maintenance operations.
         *
         * Lifecycle:
         * 1. Initialize() - Call once at application startup
         * 2. Use Execute/Query/BeginTransaction throughout app
         * 3. Shutdown() - Call at application exit (or rely on destructor)
         *
         * @note Thread-safe singleton
         * @note All public methods are thread-safe
         */
        class DatabaseManager {
        public:
            /** @brief Returns the singleton instance */
            static DatabaseManager& Instance();
            
            // === Initialization ===
            
            /**
             * @brief Initializes database with given configuration.
             * @param config Database configuration
             * @param err Optional error output
             * @return true if initialized successfully
             */
            bool Initialize(const DatabaseConfig& config, DatabaseError* err = nullptr);
            
            /** @brief Shuts down database and releases resources */
            void Shutdown();
            
            /** @brief Returns true if database is initialized */
            bool IsInitialized() const noexcept { return m_initialized.load(); }
            
            // === Schema Management ===
            
            /** @brief Creates application database tables */
            bool CreateTables(DatabaseError* err = nullptr);
            
            /** @brief Upgrades schema from current to target version */
            bool UpgradeSchema(int currentVersion, int targetVersion, DatabaseError* err = nullptr);
            
            /** @brief Gets current schema version */
            int GetSchemaVersion(DatabaseError* err = nullptr);
            
            /** @brief Sets schema version */
            bool SetSchemaVersion(int version, DatabaseError* err = nullptr);
            
            // === Query Execution ===
            
            /** @brief Executes a single SQL statement (no results) */
            bool Execute(std::string_view sql, DatabaseError* err = nullptr);
            
            /** @brief Executes multiple statements in a transaction */
            bool ExecuteMany(const std::vector<std::string>& statements, DatabaseError* err = nullptr);
            
            /** @brief Executes SELECT query and returns result set */
            QueryResult Query(std::string_view sql, DatabaseError* err = nullptr);
            
            // === Parameterized Queries ===
            
            /**
             * @brief Executes parameterized statement (no results).
             * @tparam Args Parameter types (auto-deduced)
             * @param sql SQL with ? placeholders
             * @param err Optional error output
             * @param args Parameter values (bound by position)
             * @return true on success
             */
            template<typename... Args>
            bool ExecuteWithParams(
                std::string_view sql,
                DatabaseError* err,
                Args&&... args
            );
            
            /**
             * @brief Executes parameterized SELECT query.
             * @tparam Args Parameter types (auto-deduced)
             * @param sql SQL with ? placeholders
             * @param err Optional error output
             * @param args Parameter values (bound by position)
             * @return QueryResult for iteration
             */
            template<typename... Args>
            QueryResult QueryWithParams(
                std::string_view sql,
                DatabaseError* err,
                Args&&... args 
            );

            /**
             * @brief Executes query with vector of string parameters.
             * @param sql SQL with ? placeholders
             * @param params Vector of string parameters
             * @param err Optional error output
             * @return QueryResult for iteration
             */
            QueryResult QueryWithParamsVector(std::string_view sql,
                const std::vector<std::string>& params,
                DatabaseError* err = nullptr);
            
            // === Transactions ===
            
            /**
             * @brief Begins a new transaction.
             * @param type Transaction isolation level
             * @param err Optional error output
             * @return Transaction object (unique_ptr)
             */
            std::unique_ptr<Transaction> BeginTransaction(
                Transaction::Type type = Transaction::Type::Deferred,
                DatabaseError* err = nullptr
            );

            // === Batch Operations ===
            
            /**
             * @brief Performs efficient batch insert operation.
             * @tparam Func Callable with signature void(int rowIndex, SQLite::Statement& stmt)
             * @param tableName Target table
             * @param columns Column names for INSERT
             * @param rowCount Number of rows to insert
             * @param bindFunc Function to bind values for each row
             * @param err Optional error output
             * @return true if all rows inserted
             */
            template<typename Func>
            bool BatchInsert(
                std::string_view tableName,
                const std::vector<std::string>& columns,
                size_t rowCount,
                Func&& bindFunc,
                DatabaseError* err = nullptr
            );
            
            // === Utility Functions ===
            
            /** @brief Returns ROWID of last INSERT */
            int64_t LastInsertRowId();
            
            /** @brief Returns rows affected by last statement */
            int GetChangedRowCount();
            
            /** @brief Alias for GetChangedRowCount() @deprecated */
            int GetChanges();
            
            /** @brief Checks if a table exists */
            bool TableExists(std::string_view tableName, DatabaseError* err = nullptr);
            
            /** @brief Checks if a column exists in a table */
            bool ColumnExists(std::string_view tableName, std::string_view columnName, DatabaseError* err = nullptr);
            
            /** @brief Checks if an index exists */
            bool IndexExists(std::string_view indexName, DatabaseError* err = nullptr);
            
            /** @brief Gets list of all table names */
            std::vector<std::string> GetTableNames(DatabaseError* err = nullptr);
            
            /** @brief Gets column names for a table */
            std::vector<std::string> GetColumnNames(std::string_view tableName, DatabaseError* err = nullptr);
            
            // === Maintenance Operations ===
            
            /** @brief Rebuilds database file to reclaim space */
            bool Vacuum(DatabaseError* err = nullptr);
            
            /** @brief Updates query planner statistics */
            bool Analyze(DatabaseError* err = nullptr);
            
            /** @brief Checks database integrity, returns issues */
            bool CheckIntegrity(std::vector<std::wstring>& issues, DatabaseError* err = nullptr);
            
            /** @brief Runs database optimization */
            bool Optimize(DatabaseError* err = nullptr);
            
            // === Backup & Restore ===
            
            /** @brief Creates backup at specified path */
            bool BackupToFile(std::wstring_view backupPath, DatabaseError* err = nullptr);
            
            /** @brief Restores database from backup file */
            bool RestoreFromFile(std::wstring_view backupPath, DatabaseError* err = nullptr);
            
            /** @brief Creates automatic backup with timestamp */
            bool CreateAutoBackup(DatabaseError* err = nullptr);
            
            // === Statistics ===
            
            /**
             * @brief Database statistics structure.
             */
            struct DatabaseStats {
                size_t totalSize = 0;              ///< Total database size in bytes
                size_t pageCount = 0;              ///< Number of pages
                size_t pageSize = 0;               ///< Page size in bytes
                size_t freePages = 0;              ///< Unused pages
                size_t cacheHitRate = 0;           ///< Cache hit percentage
                int64_t totalQueries = 0;          ///< Total queries executed
                int64_t totalTransactions = 0;     ///< Total transactions
                std::chrono::milliseconds averageQueryTime{};
            };
            
            /** @brief Gets database statistics */
            DatabaseStats GetStats(DatabaseError* err = nullptr);
            
            // === Configuration Access ===
            
            /** @brief Returns current configuration (read-only) */
            const DatabaseConfig& GetConfig() const noexcept { return m_config; }
            
            // === Connection Access (Advanced) ===
            
            /**
             * @brief Directly acquires a connection from pool.
             * @warning Caller MUST release via ReleaseConnection()
             */
            std::shared_ptr<SQLite::Database> AcquireConnection(DatabaseError* err = nullptr);
            
            /** @brief Returns connection to pool */
            void ReleaseConnection(std::shared_ptr<SQLite::Database> conn);

            // === Parameter Binding Helpers ===
            
            /** @brief Binds a single parameter to statement */
            template<typename T>
            void bindParameter(SQLite::Statement& stmt, int index, T&& value);

            /** @brief Recursively binds multiple parameters */
            template<typename T, typename... Args>
            void bindParameters(SQLite::Statement& stmt, int index, T&& first, Args&&... rest);

            /** @brief Base case for parameter binding recursion */
            void bindParameters(SQLite::Statement& stmt, int index) {}
            
        private:
            // Private constructor for singleton
            DatabaseManager();
            ~DatabaseManager();
            
            // Non-copyable
            DatabaseManager(const DatabaseManager&) = delete;
            DatabaseManager& operator=(const DatabaseManager&) = delete;
            
            // === Initialization Helpers ===
            bool createDatabaseFile(DatabaseError* err);
            bool configurePragmas(SQLite::Database& db, DatabaseError* err);
            bool enableSecurity(SQLite::Database& db, DatabaseError* err);
            
            // === Schema Helpers ===
            bool executeSchemaMigration(SQLite::Database& db, int version, DatabaseError* err);
            
            // === Backup Helpers ===
            void backgroundBackupThread();
            bool performBackup(const std::wstring& backupPath, DatabaseError* err);
            void cleanupOldBackups();
            
            // === Error Handling ===
            void setError(DatabaseError* err, int code, std::wstring_view msg, std::wstring_view ctx = L"") const;
            void setError(DatabaseError* err, const SQLite::Exception& ex, std::wstring_view ctx = L"") const;
            
            // === Member Variables ===
            
            std::atomic<bool> m_initialized{ false };   ///< Initialization flag
            DatabaseConfig m_config;                     ///< Current configuration
            
            std::unique_ptr<ConnectionPool> m_connectionPool;    ///< Connection pool
            std::unique_ptr<PreparedStatementCache> m_statementCache;  ///< Statement cache
            
            mutable std::shared_mutex m_configMutex;    ///< Config access synchronization
            
            // === Statistics Counters ===
            std::atomic<int64_t> m_totalQueries{ 0 };        ///< Total queries executed
            std::atomic<int64_t> m_totalTransactions{ 0 };   ///< Total transactions
            
            // === Background Backup Thread ===
            std::thread m_backupThread;                       ///< Background backup thread
            std::atomic<bool> m_shutdownBackupThread{ false };///< Shutdown signal
            std::condition_variable m_backupCv;               ///< Backup wake condition
            std::mutex m_backupMutex;                         ///< Backup synchronization
            std::chrono::steady_clock::time_point m_lastBackup; ///< Last backup timestamp
        };

        // ============================================================================
        // TEMPLATE IMPLEMENTATIONS
        // ============================================================================
        //
        // Template implementations must be in the header file due to C++
        // template instantiation rules. These provide type-safe parameter
        // binding for queries and statements.
        // ============================================================================

        /**
         * @brief Executes parameterized statement within a transaction.
         *
         * Binds parameters using variadic template expansion.
         *
         * @tparam Args Parameter types (auto-deduced)
         * @param sql SQL with ? placeholders
         * @param err Optional error output
         * @param args Parameter values
         * @return true on success
         */
        template<typename... Args>
        bool Transaction::ExecuteWithParams(std::string_view sql, DatabaseError* err, Args&&... args) {
            if (!m_active || !m_db) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Transaction not active";
                }
                return false;
            }

            try {
                SQLite::Statement stmt(*m_db, sql.data());

                // Use DatabaseManager's binding helpers
                if (m_manager) {
                    m_manager->bindParameters(stmt, 1, std::forward<Args>(args)...);
                }

                stmt.exec();
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();

                    // Convert exception message to wide string
                    std::string msg = ex.what();
                    err->message = std::wstring(msg.begin(), msg.end());
                    err->context = L"Transaction::ExecuteWithParams";
                }
                return false;
            }
        }

        /**
         * @brief Executes parameterized statement on main manager.
         *
         * Acquires connection, binds parameters, executes, and releases.
         * Uses RAII ConnectionGuard for exception safety.
         *
         * @tparam Args Parameter types
         * @param sql SQL with ? placeholders
         * @param err Optional error output
         * @param args Parameter values
         * @return true on success
         */
        template<typename... Args>
        bool DatabaseManager::ExecuteWithParams(std::string_view sql, DatabaseError* err, Args&&... args) {
            auto conn = this->AcquireConnection(err);
            if (!conn) return false;

            // RAII guard ensures connection release even on exception
            struct ConnectionGuard {
                DatabaseManager* mgr;
                std::shared_ptr<SQLite::Database> conn;

                ~ConnectionGuard() {
                    if (conn && mgr) {
                        mgr->ReleaseConnection(conn);
                    }
                }
            } guard{ this, conn };

            try {
                auto stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                this->bindParameters(*stmt, 1, std::forward<Args>(args)...);
                stmt->exec();
                this->m_totalQueries.fetch_add(1, std::memory_order_relaxed);

                return true;
            }
            catch (const SQLite::Exception& ex) {
                this->setError(err, ex, L"ExecuteWithParams");
                return false;
            }
        }

        /**
         * @brief Executes parameterized SELECT query.
         *
         * Returns QueryResult that takes ownership of the connection.
         *
         * @tparam Args Parameter types
         * @param sql SQL with ? placeholders
         * @param err Optional error output
         * @param args Parameter values
         * @return QueryResult for iteration
         */
        template<typename... Args>
        QueryResult DatabaseManager::QueryWithParams(std::string_view sql, DatabaseError* err, Args&&... args) {
            auto conn = this->AcquireConnection(err);
            if (!conn) return QueryResult{};

            struct ConnectionGuard {
                DatabaseManager* mgr;
                std::shared_ptr<SQLite::Database> conn;
                bool released = false;

                ~ConnectionGuard() {
                    if (conn && mgr && !released) {
                        mgr->ReleaseConnection(conn);
                    }
                }
            } guard{ this, conn };

            try {
                auto stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                this->bindParameters(*stmt, 1, std::forward<Args>(args)...);
                this->m_totalQueries.fetch_add(1, std::memory_order_relaxed);

                // QueryResult will handle release, so mark as released
                guard.released = true;
                return QueryResult{ std::move(stmt), conn, this };
            }
            catch (const SQLite::Exception& ex) {
                this->setError(err, ex, L"QueryWithParams");
                // ConnectionGuard handles release on exception!
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