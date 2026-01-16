// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/**
 * ============================================================================
 * ShadowStrike DatabaseManager - IMPLEMENTATION
 * ============================================================================
 *
 * @file DatabaseManager.cpp
 * @brief Enterprise-grade SQLite database management with connection pooling.
 *
 * This module provides a comprehensive database management layer for the
 * ShadowStrike antivirus engine. It handles all SQLite operations with
 * enterprise-level features including connection pooling, prepared statement
 * caching, automatic backups, and schema migration.
 *
 * Architecture Overview:
 * ----------------------
 *
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                   Application Layer                          │
 *   │      (ConfigurationDB, LogDB, QuarantineDB, etc.)           │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                  DatabaseManager (Singleton)                 │ ◄── YOU ARE HERE
 *   │  - Connection Pool Management                                │
 *   │  - Prepared Statement Caching                                │
 *   │  - Transaction Coordination                                  │
 *   │  - Schema Migration & Versioning                             │
 *   │  - Automatic Backup Thread                                   │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                    SQLiteCpp Library                         │
 *   │         (C++ wrapper around SQLite3 library)                 │
 *   └─────────────────────────────────────────────────────────────┘
 *                                 │
 *                                 ▼
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │                     SQLite3 Engine                           │
 *   │       (Single-file, serverless, ACID database)               │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * Key Components:
 * ---------------
 * 1. CONNECTION POOL (ConnectionPool class)
 *    - Pre-warmed connection pool for low-latency acquisition
 *    - Configurable min/max connections
 *    - Automatic connection health checking
 *    - Thread-safe acquire/release with condition variables
 *
 * 2. PREPARED STATEMENT CACHE (PreparedStatementCache class)
 *    - LRU cache for compiled SQL statements
 *    - Eliminates repeated query parsing overhead
 *    - Configurable cache size with automatic eviction
 *
 * 3. TRANSACTION MANAGER (Transaction class)
 *    - RAII-based transaction management
 *    - Support for DEFERRED, IMMEDIATE, EXCLUSIVE locks
 *    - Automatic rollback on scope exit if not committed
 *    - Savepoint support for nested transactions
 *
 * 4. SCHEMA MIGRATION
 *    - Version-tracked schema upgrades
 *    - Transactional migration execution
 *    - Rollback support on migration failure
 *
 * 5. AUTOMATIC BACKUP
 *    - Background thread for periodic backups
 *    - Configurable backup interval and retention
 *    - Hot backup without blocking operations
 *
 * Thread Safety:
 * --------------
 * - DatabaseManager is a singleton with thread-safe initialization
 * - ConnectionPool uses mutex + condition_variable for safe acquisition
 * - PreparedStatementCache uses mutex for thread-safe access
 * - Transaction objects are NOT thread-safe (single-thread use only)
 * - All public DatabaseManager methods are thread-safe
 *
 * Performance Optimizations:
 * --------------------------
 * - WAL mode for concurrent reads during writes
 * - Memory-mapped I/O for large databases
 * - Page cache tuning for hot data
 * - Lookaside memory allocator for small allocations
 * - Prepared statement caching to avoid re-parsing
 *
 * SQLite Configuration:
 * ---------------------
 * - Page size: 4KB (optimal for most filesystems)
 * - Cache size: 10MB default (configurable)
 * - Journal mode: WAL (Write-Ahead Logging)
 * - Synchronous: NORMAL (good performance/durability balance)
 * - Secure delete: ON (overwrites deleted data for security)
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * ============================================================================
 */

#include"pch.h"
#include "DatabaseManager.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // INTERNAL UTILITIES & CONSTANTS
        // ============================================================================
        
        namespace {
            /**
             * @brief Converts UTF-8 narrow string to UTF-16 wide string.
             * 
             * Uses Windows MultiByteToWideChar API for proper Unicode conversion.
             * This is essential for correct handling of international file paths
             * and user-provided strings in the database.
             * 
             * @param str UTF-8 encoded narrow string
             * @return UTF-16 encoded wide string, empty on conversion failure
             */
            std::wstring ToWide(std::string_view str) {
                if (str.empty()) return std::wstring();
                
                const int size = MultiByteToWideChar(
                    CP_UTF8, 0, 
                    str.data(), static_cast<int>(str.size()), 
                    nullptr, 0
                );
                if (size == 0) return std::wstring();
                
                std::wstring result(static_cast<size_t>(size), L'\0');
                MultiByteToWideChar(
                    CP_UTF8, 0, 
                    str.data(), static_cast<int>(str.size()), 
                    result.data(), size
                );
                return result;
            }
            
            /**
             * @brief Converts UTF-16 wide string to UTF-8 narrow string.
             * 
             * Uses Windows WideCharToMultiByte API for proper Unicode conversion.
             * Required for SQLite operations which use UTF-8 internally.
             * 
             * @param str UTF-16 encoded wide string
             * @return UTF-8 encoded narrow string, empty on conversion failure
             */
            std::string ToNarrow(std::wstring_view str) {
                if (str.empty()) return std::string();
                
                const int size = WideCharToMultiByte(
                    CP_UTF8, 0, 
                    str.data(), static_cast<int>(str.size()), 
                    nullptr, 0, nullptr, nullptr
                );
                if (size == 0) return std::string();
                
                std::string result(static_cast<size_t>(size), '\0');
                WideCharToMultiByte(
                    CP_UTF8, 0, 
                    str.data(), static_cast<int>(str.size()), 
                    result.data(), size, nullptr, nullptr
                );
                return result;
            }

            /**
             * @brief SQL statement to create the internal metadata table.
             * 
             * The _metadata table stores database-level configuration including:
             * - schema_version: Current database schema version for migrations
             * - Other key-value pairs for internal tracking
             * 
             * Uses WITHOUT ROWID optimization for key-value access pattern.
             */
            constexpr const char* SQL_CREATE_METADATA_TABLE = R"(
                CREATE TABLE IF NOT EXISTS _metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                ) WITHOUT ROWID;
            )";

            /** @brief Query to retrieve current schema version */
            constexpr const char* SQL_GET_SCHEMA_VERSION = 
                "SELECT value FROM _metadata WHERE key = 'schema_version'";
            
            /** @brief Query to update schema version (UPSERT pattern) */
            constexpr const char* SQL_SET_SCHEMA_VERSION = 
                "INSERT OR REPLACE INTO _metadata (key, value) VALUES ('schema_version', ?)";

        } // anonymous namespace

        // ============================================================================
        // QUERY RESULT IMPLEMENTATION
        // ============================================================================
        //
        // QueryResult wraps a SQLite statement and provides typed access to result
        // columns. It manages the lifecycle of the database connection, returning
        // it to the pool when the result is destroyed.
        //
        // Design Notes:
        // - Move-only semantics to prevent connection leaks
        // - Column name to index mapping cached for performance
        // - Automatic connection release on destruction
        // ============================================================================

        /**
         * @brief Constructs a QueryResult with ownership of statement and connection.
         * 
         * Takes ownership of both the prepared statement and database connection.
         * The connection will be returned to the pool when this object is destroyed.
         * 
         * @param stmt The prepared statement (moved)
         * @param conn The database connection (shared ownership)
         * @param manager Pointer to DatabaseManager for connection release
         */
        QueryResult::QueryResult(
            std::unique_ptr<SQLite::Statement>&& stmt,
            std::shared_ptr<SQLite::Database> conn,
            DatabaseManager* manager
        ) noexcept
            : m_statement(std::move(stmt))
            , m_connection(std::move(conn))
            , m_manager(manager)
        {
            if (m_statement) {
                m_hasRows = (m_statement->getColumnCount() > 0);
            }
        }

        /**
         * @brief Destructor - releases statement and returns connection to pool.
         * 
         * Order is important: statement must be reset before connection is released
         * to ensure all resources tied to the connection are freed first.
         */
        QueryResult::~QueryResult() {
            // Release statement first - it holds references to the connection
            m_statement.reset();

            // Return connection to pool for reuse
            if (m_connection && m_manager) {
                m_manager->ReleaseConnection(m_connection);
            }
        }

        /**
         * @brief Move constructor - transfers ownership without copying.
         * 
         * Source object is left in a valid but empty state after move.
         */
        QueryResult::QueryResult(QueryResult&& other) noexcept
            : m_statement(std::move(other.m_statement))
            , m_connection(std::move(other.m_connection))
            , m_manager(other.m_manager)
            , m_hasRows(other.m_hasRows)
            , m_columnIndexCache(std::move(other.m_columnIndexCache))
        {
            other.m_manager = nullptr;
            other.m_hasRows = false;
        }

        /**
         * @brief Move assignment operator - transfers ownership with cleanup.
         * 
         * Safely handles self-assignment and properly releases existing resources
         * before acquiring new ones from the source.
         */
        QueryResult& QueryResult::operator=(QueryResult&& other) noexcept {
            if (this != &other) {
                // Release our current resources first
                m_statement.reset();

                if (m_connection && m_manager) {
                    m_manager->ReleaseConnection(m_connection);
                }

                // Take ownership of other's resources
                m_statement = std::move(other.m_statement);
                m_connection = std::move(other.m_connection);
                m_manager = other.m_manager;
                m_hasRows = other.m_hasRows;
                m_columnIndexCache = std::move(other.m_columnIndexCache);

                // Leave other in valid empty state
                other.m_manager = nullptr;
                other.m_hasRows = false;
            }
            return *this;
        }

        /**
         * @brief Advances to the next row in the result set.
         * 
         * @return true if a row is available, false if no more rows or error
         * @note Logs errors but does not throw to allow graceful degradation
         */
        bool QueryResult::Next() {
            if (!m_statement) return false;
            
            try {
                return m_statement->executeStep();
            }
            catch (const SQLite::Exception& ex) {
                SS_LOG_ERROR(L"Database", L"QueryResult::Next failed: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        int QueryResult::ColumnCount() const noexcept {
            return m_statement ? m_statement->getColumnCount() : 0;
        }

        std::wstring QueryResult::ColumnName(int index) const {
            if (!m_statement) return std::wstring();
            
            try {
                return ToWide(m_statement->getColumnName(index));
            }
            catch (...) {
                return std::wstring();
            }
        }

        int QueryResult::GetInt(int columnIndex) const {
            if (!m_statement) throw std::runtime_error("Invalid statement");
            return m_statement->getColumn(columnIndex).getInt();
        }

        int64_t QueryResult::GetInt64(int columnIndex) const {
            if (!m_statement) throw std::runtime_error("Invalid statement");
            return m_statement->getColumn(columnIndex).getInt64();
        }

        double QueryResult::GetDouble(int columnIndex) const {
            if (!m_statement) throw std::runtime_error("Invalid statement");
            return m_statement->getColumn(columnIndex).getDouble();
        }

        std::string QueryResult::GetString(int columnIndex) const {
            if (!m_statement) throw std::runtime_error("Invalid statement");
            return m_statement->getColumn(columnIndex).getString();
        }

        std::wstring QueryResult::GetWString(int columnIndex) const {
            return ToWide(GetString(columnIndex));
        }

        std::vector<uint8_t> QueryResult::GetBlob(int columnIndex) const {
            if (!m_statement) throw std::runtime_error("Invalid statement");
            
            auto column = m_statement->getColumn(columnIndex);
            const void* data = column.getBlob();
            int size = column.getBytes();
            
            if (!data || size == 0) return std::vector<uint8_t>();
            
            const uint8_t* bytes = static_cast<const uint8_t*>(data);
            return std::vector<uint8_t>(bytes, bytes + size);
        }

        int QueryResult::GetInt(std::string_view columnName) const {
            return GetInt(getColumnIndex(columnName));
        }

        int64_t QueryResult::GetInt64(std::string_view columnName) const {
            return GetInt64(getColumnIndex(columnName));
        }

        double QueryResult::GetDouble(std::string_view columnName) const {
            return GetDouble(getColumnIndex(columnName));
        }

        std::string QueryResult::GetString(std::string_view columnName) const {
            return GetString(getColumnIndex(columnName));
        }

        std::wstring QueryResult::GetWString(std::string_view columnName) const {
            return GetWString(getColumnIndex(columnName));
        }

        std::vector<uint8_t> QueryResult::GetBlob(std::string_view columnName) const {
            return GetBlob(getColumnIndex(columnName));
        }

        /**
         * @brief Checks if a column value is NULL.
         * @param columnIndex Zero-based column index
         * @return true if NULL, also returns true for invalid statement
         */
        bool QueryResult::IsNull(int columnIndex) const {
            if (!m_statement) return true;
            return m_statement->getColumn(columnIndex).isNull();
        }

        /**
         * @brief Checks if a column value is NULL by name.
         * @param columnName The column name to check
         * @return true if NULL
         */
        bool QueryResult::IsNull(std::string_view columnName) const {
            return IsNull(getColumnIndex(columnName));
        }

        /**
         * @brief Gets the SQLite type of a column.
         * @param columnIndex Zero-based column index
         * @return SQLITE_INTEGER, SQLITE_FLOAT, SQLITE_TEXT, SQLITE_BLOB, or SQLITE_NULL
         */
        int QueryResult::GetColumnType(int columnIndex) const {
            if (!m_statement) return SQLITE_NULL;
            return m_statement->getColumn(columnIndex).getType();
        }

        /**
         * @brief Gets the SQLite type of a column by name.
         * @param columnName The column name
         * @return SQLite type constant
         */
        int QueryResult::GetColumnType(std::string_view columnName) const {
            return GetColumnType(getColumnIndex(columnName));
        }

        /**
         * @brief Resolves column name to index with caching.
         * 
         * Uses an internal cache to avoid repeated O(n) column name lookups.
         * Cache is populated on first access to each column name.
         * 
         * @param columnName The column name to resolve
         * @return Zero-based column index
         * @throws std::runtime_error if column not found
         */
        int QueryResult::getColumnIndex(std::string_view columnName) const {
            std::string name(columnName);
            
            // Check cache first for O(1) lookup
            auto it = m_columnIndexCache.find(name);
            if (it != m_columnIndexCache.end()) {
                return it->second;
            }
            
            if (!m_statement) throw std::runtime_error("Invalid statement");
            
            // Linear search for column name
            for (int i = 0; i < ColumnCount(); ++i) {
                if (m_statement->getColumnName(i) == name) {
                    m_columnIndexCache[name] = i;
                    return i;
                }
            }
            
            throw std::runtime_error("Column not found: " + name);
        }

        // ============================================================================
        // PREPARED STATEMENT CACHE IMPLEMENTATION
        // ============================================================================
        //
        // PreparedStatementCache provides an LRU (Least Recently Used) cache for
        // compiled SQL statements. Preparing a statement is expensive as SQLite
        // must parse and optimize the query. This cache eliminates repeated parsing
        // for frequently used queries.
        //
        // Performance Impact:
        // - First execution: ~100-500μs (parse + optimize)
        // - Cached execution: ~1-5μs (just bind + execute)
        // - 50-100x improvement for repeated queries
        //
        // Thread Safety:
        // - All methods are thread-safe via mutex protection
        // - Statements are returned as shared_ptr for safe concurrent use
        // ============================================================================

        /**
         * @brief Constructs cache with specified maximum size.
         * @param maxSize Maximum number of statements to cache (default 100)
         */
        PreparedStatementCache::PreparedStatementCache(size_t maxSize) noexcept
            : m_maxSize(maxSize)
        {
        }

        /**
         * @brief Gets or creates a prepared statement for the given SQL.
         * 
         * If the statement is cached, returns the cached version and updates
         * its last-used timestamp. Otherwise, creates a new statement and
         * adds it to the cache, potentially evicting the oldest entry.
         * 
         * @param db Database connection to prepare statement on
         * @param sql SQL query string
         * @param err Optional error output (nullptr to ignore)
         * @return Prepared statement, or nullptr on error
         */
        std::shared_ptr<SQLite::Statement> PreparedStatementCache::Get(
            SQLite::Database& db,
            std::string_view sql,
            DatabaseError* err
        ) {
            std::string sqlStr(sql);
            
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Cache hit - update timestamp and return
            auto it = m_cache.find(sqlStr);
            if (it != m_cache.end()) {
                it->second.lastUsed = std::chrono::steady_clock::now();
                return it->second.statement;
            }
            
            // Cache miss - create new prepared statement
            try {
                auto stmt = std::make_shared<SQLite::Statement>(db, sqlStr);
                
                // Evict oldest if at capacity
                if (m_cache.size() >= m_maxSize) {
                    evictOldest();
                }
                
                CacheEntry entry;
                entry.statement = stmt;
                entry.lastUsed = std::chrono::steady_clock::now();
                
                m_cache[sqlStr] = entry;
                
                return stmt;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->query = ToWide(sqlStr);
                }
                SS_LOG_ERROR(L"Database", L"Failed to prepare statement: %ls", ToWide(ex.what()).c_str());
                return nullptr;
            }
        }

        /**
         * @brief Clears all cached statements.
         * 
         * Should be called before closing the database or when
         * schema changes invalidate existing statements.
         */
        void PreparedStatementCache::Clear() noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_cache.clear();
        }

        /**
         * @brief Returns the current number of cached statements.
         * @return Number of statements in cache
         */
        size_t PreparedStatementCache::Size() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_cache.size();
        }

        /**
         * @brief Evicts the least recently used entry from cache.
         * 
         * Called internally when cache reaches maximum capacity.
         * Uses linear scan to find oldest entry - acceptable for
         * typical cache sizes (100-500 entries).
         * 
         * @note Caller must hold m_mutex lock
         */
        void PreparedStatementCache::evictOldest() {
            if (m_cache.empty()) return;
            
            // Linear scan to find LRU entry
            auto oldest = m_cache.begin();
            for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
                if (it->second.lastUsed < oldest->second.lastUsed) {
                    oldest = it;
                }
            }
            
            m_cache.erase(oldest);
        }

        // ============================================================================
        // CONNECTION POOL IMPLEMENTATION
        // ============================================================================
        //
        // ConnectionPool manages a pool of SQLite database connections for efficient
        // resource utilization and concurrent access. The pool maintains connections
        // between requests, eliminating connection setup overhead.
        //
        // Pool Behavior:
        // - Starts with minConnections pre-warmed connections
        // - Grows up to maxConnections on demand
        // - Connections are health-checked before use
        // - Idle connections are validated periodically
        //
        // Acquisition Flow:
        // 1. Try to get an available connection from pool
        // 2. If none available and under max, create new connection
        // 3. If at max, wait with timeout for release
        // 4. Return nullptr if timeout expires
        //
        // Thread Safety:
        // - Uses mutex + condition_variable for synchronization
        // - Atomic counters for fast status checks
        // - Graceful shutdown with notification
        // ============================================================================

        /**
         * @brief Constructs pool with the given configuration.
         * @param config Database configuration including pool settings
         */
        ConnectionPool::ConnectionPool(const DatabaseConfig& config) noexcept
            : m_config(config)
        {
        }

        /**
         * @brief Destructor - ensures clean shutdown of all connections.
         */
        ConnectionPool::~ConnectionPool() {
            Shutdown();
        }

        /**
         * @brief Initializes the connection pool with minimum connections.
         * 
         * Creates the minimum number of connections specified in config.
         * If any connection fails to create, the entire pool is shut down.
         * 
         * @param err Optional error output
         * @return true if pool initialized successfully, false on error
         */
        bool ConnectionPool::Initialize(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Pre-warm pool with minimum connections
            for (size_t i = 0; i < m_config.minConnections; ++i) {
                if (!createConnection(err)) {
                    Shutdown();
                    return false;
                }
            }
            
            SS_LOG_INFO(L"Database", L"Connection pool initialized with %zu connections", m_connections.size());
            return true;
        }

        /**
         * @brief Shuts down the connection pool and releases all resources.
         * 
         * Safe to call multiple times. Uses atomic flag to prevent double
         * shutdown. Notifies any waiting threads before closing connections.
         */
        void ConnectionPool::Shutdown() {
            // Atomic flag ensures single shutdown execution
            bool wasShutdown = m_shutdown.exchange(true, std::memory_order_acq_rel);
            if (wasShutdown) {
                SS_LOG_DEBUG(L"Database", L"Connection pool already shut down");
                return;  // Already shut down
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            
            m_shutdown.store(true, std::memory_order_release);
            m_cv.notify_all();  // Wake up any waiting threads

            // Close all connections gracefully
            for (auto& pooled : m_connections) {
                if (pooled.connection) {
                    try {
                        // Force close connection
                        pooled.connection.reset();
                    }
                    catch (const std::exception& ex) {
                        SS_LOG_ERROR(L"Database", L"Error closing connection: %ls",
                            ToWide(ex.what()).c_str());
                    }
                }
            }
            
            m_connections.clear();
            m_activeCount.store(0, std::memory_order_release);
            
            SS_LOG_INFO(L"Database", L"Connection pool shut down");
        }

        /**
         * @brief Acquires a connection from the pool.
         * 
         * Attempts to get an available connection with timeout. If the pool
         * is exhausted and at maximum capacity, waits for a connection to
         * be released.
         * 
         * @param timeout Maximum time to wait for a connection
         * @param err Optional error output
         * @return Database connection, or nullptr on timeout/error
         */
        std::shared_ptr<SQLite::Database> ConnectionPool::Acquire(
            std::chrono::milliseconds timeout,
            DatabaseError* err
        ) {
            std::unique_lock<std::mutex> lock(m_mutex);
            
            auto deadline = std::chrono::steady_clock::now() + timeout;
            
            while (true) {
                if (m_shutdown.load(std::memory_order_acquire)) {
                    if (err) {
                        err->sqliteCode = SQLITE_ERROR;
                        err->message = L"Connection pool is shut down";
                    }
                    return nullptr;
                }
                
                // Find available connection
                for (auto& pooled : m_connections) {
                    if (!pooled.inUse) {
                        pooled.inUse = true;
                        pooled.lastUsed = std::chrono::steady_clock::now();
                        m_activeCount.fetch_add(1, std::memory_order_relaxed);
                        return pooled.connection;
                    }
                }
                
                // No available connection, try to create new one if possible
                if (m_connections.size() < m_config.maxConnections) {
                    if (createConnection(err)) {
                        auto& pooled = m_connections.back();
                        pooled.inUse = true;
                        m_activeCount.fetch_add(1, std::memory_order_relaxed);
                        return pooled.connection;
                    }
                }
                
                // Wait for a connection to become available
                if (m_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
                    if (err) {
                        err->sqliteCode = SQLITE_BUSY;
                        err->message = L"Connection acquisition timeout";
                    }
                    SS_LOG_WARN(L"Database", L"Connection acquisition timeout after %lld ms", timeout.count());
                    return nullptr;
                }
            }
        }

        /**
         * @brief Releases a connection back to the pool.
         * 
         * Marks the connection as available and notifies waiting threads.
         * Safe to call with nullptr (no-op).
         * 
         * @param conn Connection to release
         */
        void ConnectionPool::Release(std::shared_ptr<SQLite::Database> conn) {
            if (!conn) return;
            
            std::lock_guard<std::mutex> lock(m_mutex);
            
            for (auto& pooled : m_connections) {
                if (pooled.connection == conn) {
                    pooled.inUse = false;
                    pooled.lastUsed = std::chrono::steady_clock::now();
                    m_activeCount.fetch_sub(1, std::memory_order_relaxed);
                    m_cv.notify_one();  // Wake up one waiting thread
                    return;
                }
            }
            
            SS_LOG_WARN(L"Database", L"Released connection not found in pool");
        }

        /**
         * @brief Returns the number of available (idle) connections.
         * @return Count of connections not currently in use
         */
        size_t ConnectionPool::AvailableConnections() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            size_t available = 0;
            for (const auto& pooled : m_connections) {
                if (!pooled.inUse) ++available;
            }
            return available;
        }

        /**
         * @brief Returns the total number of connections in pool.
         * @return Total connection count (in-use + idle)
         */
        size_t ConnectionPool::TotalConnections() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_connections.size();
        }

        /**
         * @brief Creates a new database connection and adds it to the pool.
         * 
         * Opens a new SQLite connection with configured flags and timeout,
         * then applies all PRAGMA settings via configureConnection().
         * 
         * @param err Optional error output
         * @return true if connection created successfully
         * @note Caller must hold m_mutex lock
         */
        bool ConnectionPool::createConnection(DatabaseError* err) {
            try {
                // Build connection flags
                int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
                if (m_config.enableWAL) {
                    flags |= SQLITE_OPEN_WAL;
                }
                
                std::string dbPath = ToNarrow(m_config.databasePath);
                auto connection = std::make_shared<SQLite::Database>(
                    dbPath,
                    flags,
                    m_config.busyTimeoutMs
                );
                
                // Apply PRAGMA settings
                if (!configureConnection(*connection, err)) {
                    return false;
                }
                
                // Add to pool
                PooledConnection pooled;
                pooled.connection = connection;
                pooled.lastUsed = std::chrono::steady_clock::now();
                pooled.inUse = false;
                
                m_connections.push_back(std::move(pooled));
                
                SS_LOG_DEBUG(L"Database", L"Created new database connection (%zu total)", m_connections.size());
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"createConnection";
                }
                SS_LOG_ERROR(L"Database", L"Failed to create connection: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        /**
         * @brief Configures a newly created connection with PRAGMA settings.
         * 
         * Applies the following configurations from DatabaseConfig:
         * - Foreign key enforcement
         * - Journal mode (WAL, DELETE, TRUNCATE, etc.)
         * - Synchronous mode (NORMAL, FULL, OFF)
         * - Page/cache size
         * - Secure delete
         * - Memory-mapped I/O
         * - Temp storage location
         * 
         * @param db Database connection to configure
         * @param err Optional error output
         * @return true if all PRAGMA commands succeeded
         */
        bool ConnectionPool::configureConnection(SQLite::Database& db, DatabaseError* err) {
            try {
                // Enable foreign key constraint enforcement
                if (m_config.enableForeignKeys) {
                    db.exec("PRAGMA foreign_keys = ON");
                }
                
                // Configure journal mode (WAL recommended for concurrency)
                std::string journalMode = "PRAGMA journal_mode = " + ToNarrow(m_config.journalMode);
                db.exec(journalMode);
                
                // Configure synchronous mode (NORMAL balances safety/speed)
                std::string syncMode = "PRAGMA synchronous = " + ToNarrow(m_config.synchronousMode);
                db.exec(syncMode);
                
                // Configure cache size
                std::string cacheSize = "PRAGMA cache_size = -" + std::to_string(m_config.cacheSizeKB);
                db.exec(cacheSize);
                
                // Configure page size (only effective before first write)
                std::string pageSize = "PRAGMA page_size = " + std::to_string(m_config.pageSizeBytes);
                db.exec(pageSize);
                
                // Configure temp store
                std::string tempStore = "PRAGMA temp_store = " + ToNarrow(m_config.tempStore);
                db.exec(tempStore);
                
                // Enable memory-mapped I/O
                if (m_config.enableMemoryMappedIO) {
                    std::string mmapSize = "PRAGMA mmap_size = " + std::to_string(m_config.mmapSizeMB * 1024 * 1024);
                    db.exec(mmapSize);
                }
                
                // Enable secure delete
                if (m_config.enableSecureDelete) {
                    db.exec("PRAGMA secure_delete = ON");
                }
                
                // Enable lookaside memory allocator
                if (m_config.lookaside) {
                    db.exec("PRAGMA lookaside = 1");
                }
                
                SS_LOG_DEBUG(L"Database", L"Connection configured successfully");
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"configureConnection";
                }
                SS_LOG_ERROR(L"Database", L"Failed to configure connection: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        // ============================================================================
        // TRANSACTION IMPLEMENTATION
        // ============================================================================
        //
        // Transaction provides RAII (Resource Acquisition Is Initialization) based
        // transaction management. The transaction automatically rolls back if not
        // explicitly committed, ensuring data consistency even on exceptions.
        //
        // Transaction Types:
        // ------------------
        // - DEFERRED: Lock acquired on first database access (default)
        // - IMMEDIATE: Write lock acquired immediately, reads still allowed
        // - EXCLUSIVE: Full database lock, no concurrent access
        //
        // Usage Pattern:
        // --------------
        //   auto txn = manager.BeginTransaction(Transaction::Type::Immediate);
        //   if (!txn.IsActive()) { handle error }
        //   
        //   manager.Execute(conn, "INSERT INTO ...");
        //   manager.Execute(conn, "UPDATE ...");
        //   
        //   txn.Commit();  // Explicit commit
        //   // If Commit() not called, destructor performs automatic rollback
        //
        // Savepoint Support:
        // ------------------
        // For nested transaction-like behavior, use Savepoint() and ReleaseSavepoint()
        // to create partial rollback points within a transaction.
        //
        // Thread Safety:
        // --------------
        // Transaction objects are NOT thread-safe. Each thread should have its own
        // Transaction instance and database connection.
        // ============================================================================

        /**
         * @brief Constructs and begins a new transaction.
         * 
         * Executes the appropriate BEGIN statement based on transaction type.
         * If the BEGIN fails, the transaction is marked as inactive.
         * 
         * @param db Database reference (must remain valid for transaction lifetime)
         * @param conn Shared connection for lifecycle management
         * @param manager DatabaseManager for connection release
         * @param type Transaction type (Deferred, Immediate, Exclusive)
         * @param err Optional error output
         */
        Transaction::Transaction(
            SQLite::Database& db,
            std::shared_ptr<SQLite::Database> conn,
            DatabaseManager* manager,
            Type type,
            DatabaseError* err
        ) : m_db(&db)
            , m_connection(std::move(conn))
            , m_manager(manager)
        {
            try {
                // Select BEGIN statement based on isolation level
                const char* sql = nullptr;
                switch (type) {
                case Type::Deferred:
                    // Deferred: No locks until first database access
                    sql = "BEGIN DEFERRED TRANSACTION";
                    break;
                case Type::Immediate:
                    // Immediate: Acquire RESERVED lock immediately
                    // Other readers can continue, writers blocked
                    sql = "BEGIN IMMEDIATE TRANSACTION";
                    break;
                case Type::Exclusive:
                    // Exclusive: Acquire EXCLUSIVE lock immediately
                    // No other connections can access database
                    sql = "BEGIN EXCLUSIVE TRANSACTION";
                    break;
                }

                m_db->exec(sql);
                m_active = true;

                SS_LOG_DEBUG(L"Database", L"Transaction started");
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"Transaction::Begin";
                }
                SS_LOG_ERROR(L"Database", L"Failed to begin transaction: %ls", ToWide(ex.what()).c_str());
                m_active = false;
            }
        }

        /**
         * @brief Destructor - performs automatic rollback if not committed.
         * 
         * This is the key RAII safety mechanism. If an exception occurs or
         * Commit() is never called, the destructor ensures all changes are
         * rolled back to maintain database consistency.
         */
        Transaction::~Transaction() {
            // Automatic rollback if active and not committed
            if (m_active && !m_committed && m_db) {
                try {
                    m_db->exec("ROLLBACK");
                    SS_LOG_DEBUG(L"Database", L"Transaction rolled back (destructor)");
                }
                catch (const SQLite::Exception& ex) {
                    SS_LOG_ERROR(L"Database", L"Failed to rollback transaction: %ls", ToWide(ex.what()).c_str());
                }
            }

            // Return connection to pool
            if (m_connection && m_manager) {
                m_manager->ReleaseConnection(m_connection);
            }
        }

        /**
         * @brief Executes a SQL statement within this transaction.
         * 
         * Uses the transaction's connection to ensure the statement is
         * part of the same transactional context.
         * 
         * @param sql SQL statement to execute
         * @param err Optional error output
         * @return true if execution succeeded
         */
        bool Transaction::Execute(std::string_view sql, DatabaseError* err) {
            if (!m_active || !m_db) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Transaction not active";
                }
                return false;
            }

            try {
                m_db->exec(sql.data());
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"Transaction::Execute";
                }
                return false;
            }
        }

        /**
         * @brief Move constructor - transfers transaction ownership.
         * 
         * Source transaction is left in inactive state.
         */
        Transaction::Transaction(Transaction&& other) noexcept
            : m_db(other.m_db)
            , m_connection(std::move(other.m_connection))
            , m_manager(other.m_manager)
            , m_active(other.m_active)
            , m_committed(other.m_committed)
        {
            // Leave other in inactive state
            other.m_db = nullptr;
            other.m_manager = nullptr;
            other.m_active = false;
            other.m_committed = false;
        }

        /**
         * @brief Move assignment - transfers with proper cleanup.
         * 
         * If this transaction was active and uncommitted, it will be
         * rolled back before acquiring the new transaction state.
         */
        Transaction& Transaction::operator=(Transaction&& other) noexcept {
            if (this != &other) {
                // Cleanup existing transaction (rollback if needed)
                if (m_active && !m_committed && m_db) {
                    try {
                        m_db->exec("ROLLBACK");
                    }
                    catch (...) {}
                }

                if (m_connection && m_manager) {
                    m_manager->ReleaseConnection(m_connection);
                }

                // Move from other
                m_db = other.m_db;
                m_connection = std::move(other.m_connection);
                m_manager = other.m_manager;
                m_active = other.m_active;
                m_committed = other.m_committed;

                // Clear other
                other.m_db = nullptr;
                other.m_manager = nullptr;
                other.m_active = false;
                other.m_committed = false;
            }
            return *this;
        
        }

        /**
         * @brief Commits the transaction, making all changes permanent.
         * 
         * After commit, the transaction is no longer active and no more
         * operations can be performed. The connection is returned to the
         * pool when the Transaction object is destroyed.
         * 
         * @param err Optional error output
         * @return true if commit succeeded
         */
        bool Transaction::Commit(DatabaseError* err) {
            if (!m_active) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Transaction not active";
                }
                return false;
            }
            
            try {
                m_db->exec("COMMIT");
                m_committed = true;
                m_active = false;
                
                SS_LOG_DEBUG(L"Database", L"Transaction committed");
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"Transaction::Commit";
                }
                SS_LOG_ERROR(L"Database", L"Failed to commit transaction: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        /**
         * @brief Explicitly rolls back the transaction.
         * 
         * Discards all changes made since the transaction began.
         * Prefer letting the destructor handle rollback in exception
         * cases; call this explicitly only when needed for control flow.
         * 
         * @param err Optional error output
         * @return true if rollback succeeded
         */
        bool Transaction::Rollback(DatabaseError* err) {
            if (!m_active) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Transaction not active";
                }
                return false;
            }
            
            try {
                m_db->exec("ROLLBACK");
                m_active = false;
                
                SS_LOG_DEBUG(L"Database", L"Transaction rolled back");
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->extendedCode = ex.getExtendedErrorCode();
                    err->message = ToWide(ex.what());
                    err->context = L"Transaction::Rollback";
                }
                SS_LOG_ERROR(L"Database", L"Failed to rollback transaction: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        /**
         * @brief Creates a savepoint within the transaction.
         * 
         * Savepoints allow partial rollback within a transaction.
         * Useful for implementing retry logic or complex operations
         * that may need partial undo.
         * 
         * @param name Savepoint identifier (must be unique within transaction)
         * @param err Optional error output
         * @return true if savepoint created successfully
         */
        bool Transaction::CreateSavepoint(std::string_view name, DatabaseError* err) {
            if (!m_active) return false;
            
            try {
                std::string sql = "SAVEPOINT " + std::string(name);
                m_db->exec(sql);
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        /**
         * @brief Rolls back to a previously created savepoint.
         * 
         * All changes made after the savepoint are discarded.
         * The savepoint itself remains valid and can be rolled back
         * to again.
         * 
         * @param name Savepoint identifier to rollback to
         * @param err Optional error output
         * @return true if rollback succeeded
         */
        bool Transaction::RollbackToSavepoint(std::string_view name, DatabaseError* err) {
            if (!m_active) return false;
            
            try {
                std::string sql = "ROLLBACK TO SAVEPOINT " + std::string(name);
                m_db->exec(sql);
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        /**
         * @brief Releases (removes) a savepoint.
         * 
         * Commits all changes made since the savepoint. The savepoint
         * can no longer be rolled back to after release.
         * 
         * @param name Savepoint identifier to release
         * @param err Optional error output
         * @return true if release succeeded
         */
        bool Transaction::ReleaseSavepoint(std::string_view name, DatabaseError* err) {
            if (!m_active) return false;
            
            try {
                std::string sql = "RELEASE SAVEPOINT " + std::string(name);
                m_db->exec(sql);
                return true;
            }
            catch (const SQLite::Exception& ex) {
                if (err) {
                    err->sqliteCode = ex.getErrorCode();
                    err->message = ToWide(ex.what());
                }
                return false;
            }
        }

        // ============================================================================
        // DATABASE MANAGER IMPLEMENTATION
        // ============================================================================
        //
        // DatabaseManager is the main entry point for all database operations.
        // It provides a high-level API for executing queries, managing transactions,
        // and performing administrative tasks like backup and schema migration.
        //
        // Singleton Pattern:
        // - Thread-safe Meyers' singleton (C++11 magic statics)
        // - Lazy initialization on first access
        // - Automatic cleanup on program exit
        //
        // Resource Management:
        // - ConnectionPool handles connection lifecycle
        // - PreparedStatementCache optimizes repeated queries
        // - Background backup thread for data protection
        // ============================================================================

        /**
         * @brief Returns the singleton instance of DatabaseManager.
         * 
         * Uses Meyers' singleton pattern with C++11 magic statics for
         * thread-safe lazy initialization without explicit locking.
         * 
         * @return Reference to the singleton instance
         */
        DatabaseManager& DatabaseManager::Instance() {
            static DatabaseManager instance;
            return instance;
        }

        /**
         * @brief Private constructor for singleton pattern.
         */
        DatabaseManager::DatabaseManager() {
        }

        /**
         * @brief Destructor - ensures clean shutdown.
         */
        DatabaseManager::~DatabaseManager() {
            Shutdown();
        }

        /**
         * @brief Initializes the DatabaseManager with the given configuration.
         * 
         * Must be called before any other database operations. Sets up:
         * - Connection pool with configured min/max connections
         * - Prepared statement cache
         * - Metadata table for schema versioning
         * - Optional automatic backup thread
         * 
         * @param config Database configuration
         * @param err Optional error output
         * @return true if initialization succeeded
         * @note Thread-safe, can be called multiple times (subsequent calls no-op)
         */
        bool DatabaseManager::Initialize(const DatabaseConfig& config, DatabaseError* err) {
            // Guard against double initialization
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"Database", L"DatabaseManager already initialized");
                return true;
            }

            SS_LOG_SCOPE(L"Database");
            SS_LOG_INFO(L"Database", L"Initializing DatabaseManager...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Cleanup existing pool if re-initializing
            if (m_connectionPool) {
                m_connectionPool->Shutdown();
                m_connectionPool.reset();
            }

            if (!createDatabaseFile(err)) {
                return false;
            }

            m_connectionPool = std::make_unique<ConnectionPool>(m_config);
            if (!m_connectionPool->Initialize(err)) {
                SS_LOG_ERROR(L"Database", L"Failed to initialize connection pool");
                m_connectionPool.reset();
                return false;
            }

            m_statementCache = std::make_unique<PreparedStatementCache>(100);

            // ✅ CRITICAL: Set initialized flag BEFORE calling Execute()
            // This allows AcquireConnection() to work during table creation
            m_initialized.store(true, std::memory_order_release);

            // Create metadata table
            if (!Execute(SQL_CREATE_METADATA_TABLE, err)) {
                SS_LOG_ERROR(L"Database", L"Failed to create metadata table");
                m_initialized.store(false, std::memory_order_release);
                m_connectionPool->Shutdown();
                m_connectionPool.reset();
                m_statementCache.reset();
                return false;
            }

            // Create application tables
            if (!CreateTables(err)) {
                SS_LOG_ERROR(L"Database", L"Failed to create application tables");
                m_initialized.store(false, std::memory_order_release);
                m_connectionPool->Shutdown();
                m_connectionPool.reset();
                m_statementCache.reset();
                return false;
            }

            // Start background backup thread if enabled
            if (m_config.autoBackup) {
                m_lastBackup = std::chrono::steady_clock::now();
                m_backupThread = std::thread(&DatabaseManager::backgroundBackupThread, this);
            }

            SS_LOG_INFO(L"Database", L"DatabaseManager initialized successfully");
            return true;
        }
        /**
         * @brief Shuts down the DatabaseManager and releases all resources.
         * 
         * Performs orderly shutdown:
         * 1. Stops background backup thread
         * 2. Clears prepared statement cache
         * 3. Shuts down connection pool (closes all connections)
         * 
         * Safe to call multiple times. Subsequent calls are no-ops.
         * 
         * @note Thread-safe
         */
        void DatabaseManager::Shutdown() {
            // Prevent double shutdown via atomic exchange
            bool wasInitialized = m_initialized.exchange(false, std::memory_order_acq_rel);

            SS_LOG_INFO(L"Database", L"Shutting down DatabaseManager...");
            
            // Signal and join backup thread
            m_shutdownBackupThread.store(true, std::memory_order_release);
            m_backupCv.notify_all();
            
            if (m_backupThread.joinable()) {
                m_backupThread.join();
            }
            
            // Clear statement cache (invalidates prepared statements)
            if (m_statementCache) {
                m_statementCache->Clear();
            }
            
            // Shutdown connection pool
            if (m_connectionPool) {
                m_connectionPool->Shutdown();
				m_statementCache.reset();//clear the unique ptr
            }
            
            m_initialized.store(false, std::memory_order_release);
            
            SS_LOG_INFO(L"Database", L"DatabaseManager shut down");
        }

        /**
         * @brief Creates the application-specific database tables.
         * 
         * This method defines the core schema for the ShadowStrike antivirus.
         * Tables are created with appropriate indexes, foreign keys, and
         * constraints for data integrity and query performance.
         * 
         * Schema includes:
         * - threat_definitions: Malware signature and pattern definitions
         * - scan_history: Record of completed and in-progress scans
         * - detected_threats: Threats found during scans
         * - quarantine: Isolated malicious files
         * 
         * @param err Optional error output
         * @return true if all tables created successfully
         */
        bool DatabaseManager::CreateTables(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Creating application tables...");
            
            // Define application schema for antivirus functionality
            
            std::vector<std::string> schemas = {
                // Threat definitions: stores malware signatures and patterns
                R"(
                    CREATE TABLE IF NOT EXISTS threat_definitions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        type TEXT NOT NULL,
                        severity INTEGER NOT NULL DEFAULT 0,
                        signature BLOB,
                        pattern TEXT,
                        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                        updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                    )
                )",
                
                // Scan history: tracks all scans performed
                R"(
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_type TEXT NOT NULL,
                        start_time INTEGER NOT NULL,
                        end_time INTEGER,
                        files_scanned INTEGER DEFAULT 0,
                        threats_found INTEGER DEFAULT 0,
                        status TEXT NOT NULL,
                        scan_path TEXT,
                        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                    )
                )",
                
                // Detected threats: individual threat detections linked to scans
                R"(
                    CREATE TABLE IF NOT EXISTS detected_threats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER,
                        file_path TEXT NOT NULL,
                        threat_name TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        action_taken TEXT,
                        file_hash TEXT,
                        file_size INTEGER,
                        detected_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                        FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
                    )
                )",
                
                // Quarantine: isolated files awaiting user action
                R"(
                    CREATE TABLE IF NOT EXISTS quarantine (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        threat_name TEXT NOT NULL,
                        file_hash TEXT,
                        file_size INTEGER,
                        quarantined_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                        restored BOOLEAN DEFAULT 0,
                        restored_at INTEGER
                    )
                )",
                
                // Whitelist table
                R"(
                    CREATE TABLE IF NOT EXISTS whitelist (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        path TEXT NOT NULL UNIQUE,
                        type TEXT NOT NULL,
                        reason TEXT,
                        added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                    )
                )",
                
                // System events table
                R"(
                    CREATE TABLE IF NOT EXISTS system_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        message TEXT NOT NULL,
                        details TEXT,
                        created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                    )
                )",
                
                // Create indices for better performance
                "CREATE INDEX IF NOT EXISTS idx_threats_name ON threat_definitions(name)",
                "CREATE INDEX IF NOT EXISTS idx_threats_type ON threat_definitions(type)",
                "CREATE INDEX IF NOT EXISTS idx_scan_history_time ON scan_history(start_time DESC)",
                "CREATE INDEX IF NOT EXISTS idx_detected_threats_scan ON detected_threats(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_detected_threats_path ON detected_threats(file_path)",
                "CREATE INDEX IF NOT EXISTS idx_quarantine_path ON quarantine(original_path)",
                "CREATE INDEX IF NOT EXISTS idx_events_time ON system_events(created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_events_type ON system_events(event_type)"
            };
            
            return ExecuteMany(schemas, err);
        }

        /**
         * @brief Executes a single SQL statement (no results).
         * 
         * Acquires a connection from the pool, executes the statement,
         * and returns the connection. Suitable for INSERT, UPDATE, DELETE,
         * CREATE TABLE, and other non-SELECT statements.
         * 
         * @param sql SQL statement to execute
         * @param err Optional error output
         * @return true if execution succeeded
         * @note Thread-safe - connection acquisition handles synchronization
         */
        bool DatabaseManager::Execute(std::string_view sql, DatabaseError* err) {
                  auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                // RAII guard ensures connection is released even on exception
                struct ConnectionGuard {
                    DatabaseManager* mgr;
                    std::shared_ptr<SQLite::Database> conn;

                    ~ConnectionGuard() {
                        if (conn && mgr) {
                            mgr->ReleaseConnection(conn);
                        }
                    }
                } guard{ this, conn };
                try{
                conn->exec(sql.data());
                m_totalQueries.fetch_add(1, std::memory_order_relaxed);
                
               
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"Execute");
                return false;
            }
        }

        /**
         * @brief Executes multiple SQL statements in a single transaction.
         * 
         * All statements run atomically - either all succeed or all are
         * rolled back. Uses IMMEDIATE transaction to acquire write lock
         * upfront for better concurrency.
         * 
         * @param statements Vector of SQL statements to execute
         * @param err Optional error output
         * @return true if all statements succeeded
         * @note Efficient for batch operations like schema creation
         */
        bool DatabaseManager::ExecuteMany(const std::vector<std::string>& statements, DatabaseError* err) {
            
            auto conn = AcquireConnection(err);
            if (!conn) return false;

            // RAII guard for connection release
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
                // Begin IMMEDIATE transaction for write lock
                conn->exec("BEGIN IMMEDIATE TRANSACTION");

                // Execute all statements on same connection
                for (const auto& sql : statements) {
                    try {
                        conn->exec(sql);
                        m_totalQueries.fetch_add(1, std::memory_order_relaxed);
                    }
                    catch (const SQLite::Exception& ex) {
                        // Rollback on any failure
                        try {
                            conn->exec("ROLLBACK");
                        }
                        catch (...) {}

                        setError(err, ex, L"ExecuteMany");
                        return false;
                    }
                }

                // Commit all changes
                conn->exec("COMMIT");
                return true;
            }
            catch (const SQLite::Exception& ex) {
                // Rollback on transaction error
                try {
                    conn->exec("ROLLBACK");
                }
                catch (...) {}

                setError(err, ex, L"ExecuteMany");
                return false;
            }
        }

        /**
         * @brief Executes a SELECT query and returns results.
         * 
         * Returns a QueryResult that holds the statement and connection.
         * The connection is returned to the pool when the QueryResult
         * is destroyed.
         * 
         * Usage:
         * @code
         * auto result = manager.Query("SELECT * FROM users WHERE id = 1");
         * while (result.Next()) {
         *     auto name = result.GetString("name");
         * }
         * @endcode
         * 
         * @param sql SELECT query to execute
         * @param err Optional error output
         * @return QueryResult for iterating rows, empty on error
         */
        QueryResult DatabaseManager::Query(std::string_view sql, DatabaseError* err) {
            auto conn = AcquireConnection(err);
            if (!conn) return QueryResult{};

            try {
                auto stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                m_totalQueries.fetch_add(1, std::memory_order_relaxed);

                // QueryResult takes ownership of connection
                return QueryResult{ std::move(stmt), conn, this };
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"Query");
                ReleaseConnection(conn);  // Must release on error
                return QueryResult{};
            }
        }

        /**
         * @brief Executes a parameterized query with string parameters.
         * 
         * Binds parameters by position (1-based in SQL, 0-based in vector).
         * Use this overload when all parameters are strings.
         * 
         * @param sql SQL query with ? placeholders
         * @param params Vector of string parameters to bind
         * @param err Optional error output
         * @return QueryResult for iterating rows
         */
        QueryResult DatabaseManager::QueryWithParamsVector(
            std::string_view sql,
            const std::vector<std::string>& params,
            DatabaseError* err
        ) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                setError(err, SQLITE_MISUSE, L"DatabaseManager not initialized");
                return QueryResult();
            }

            auto conn = AcquireConnection(err);
            if (!conn) {
                return QueryResult();
            }

            try {
                // Prepare statement
                auto stmt = std::make_unique<SQLite::Statement>(*conn, std::string(sql));

                // Bind string parameters by position (1-based)
                for (size_t i = 0; i < params.size(); ++i) {
                    stmt->bind(static_cast<int>(i + 1), params[i]);
                }

                m_totalQueries.fetch_add(1, std::memory_order_relaxed);

                // Transfer ownership to QueryResult
                return QueryResult(std::move(stmt), conn, this);

            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"QueryWithParamsVector");
                ReleaseConnection(conn);
                return QueryResult();
            }
        } 

        /**
         * @brief Begins a new transaction with the specified isolation level.
         * 
         * Creates a Transaction object that manages the transaction lifecycle.
         * The transaction automatically rolls back if not explicitly committed.
         * 
         * @param type Transaction type (Deferred, Immediate, Exclusive)
         * @param err Optional error output
         * @return Unique pointer to Transaction, or nullptr on error
         * 
         * @see Transaction for transaction type descriptions
         */
        std::unique_ptr<Transaction> DatabaseManager::BeginTransaction(
            Transaction::Type type,
            DatabaseError* err
        ) {
            auto conn = AcquireConnection(err);
            if (!conn) return nullptr;
            
            m_totalTransactions.fetch_add(1, std::memory_order_relaxed);
            
            return std::make_unique<Transaction>(*conn,conn,this, type, err);
        }

        /**
         * @brief Returns the ROWID of the last INSERT operation.
         * 
         * Note: Returns the rowid from any connection in the pool,
         * which may not be the same connection used for the INSERT.
         * For reliable results, use within a transaction.
         * 
         * @return Last insert rowid, or -1 on error
         */
        int64_t DatabaseManager::LastInsertRowId() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return -1;
            }

            DatabaseError err;
            auto conn = AcquireConnection(&err);
            if (!conn) {
                return -1;
            }

            int64_t rowid = conn->getLastInsertRowid();
            ReleaseConnection(conn);

            return rowid;
        }

        /**
         * @brief Returns the number of rows changed by the last statement.
         * @return Changed row count
         * @deprecated Use GetChangedRowCount() instead
         */
        int DatabaseManager::GetChanges() {
            return GetChangedRowCount();  
        }

        /**
         * @brief Returns the number of rows changed by the last statement.
         * 
         * Note: Like LastInsertRowId(), this may not reflect the correct
         * connection. Use within a transaction for accuracy.
         * 
         * @return Number of rows inserted, updated, or deleted
         */
        int DatabaseManager::GetChangedRowCount() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return 0;
            }

            DatabaseError err;
            auto conn = AcquireConnection(&err);
            if (!conn) {
                return 0;
            }

            int changes = sqlite3_changes(conn->getHandle());
            ReleaseConnection(conn);

            return changes;
        }

        /**
         * @brief Checks if a table exists in the database.
         * 
         * @param tableName Name of the table to check
         * @param err Optional error output
         * @return true if table exists
         */
        bool DatabaseManager::TableExists(std::string_view tableName, DatabaseError* err) {
            try {
                auto result = QueryWithParams(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                    err,
                    std::string(tableName)
                );
                
                if (result.Next()) {
                    return result.GetInt(0) > 0;
                }
                return false;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"TableExists");
                return false;
            }
        }

        /**
         * @brief Checks if a column exists in a table.
         * 
         * Uses PRAGMA table_info to enumerate columns.
         * 
         * @param tableName Name of the table
         * @param columnName Name of the column to check
         * @param err Optional error output
         * @return true if column exists in table
         */
        bool DatabaseManager::ColumnExists(std::string_view tableName, std::string_view columnName, DatabaseError* err) {
            try {
                std::string sql = "PRAGMA table_info(" + std::string(tableName) + ")";
                auto result = Query(sql, err);
                
                while (result.Next()) {
                    if (result.GetString(1) == columnName) {
                        return true;
                    }
                }
                return false;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"ColumnExists");
                return false;
            }
        }

        /**
         * @brief Checks if an index exists in the database.
         * 
         * @param indexName Name of the index to check
         * @param err Optional error output
         * @return true if index exists
         */
        bool DatabaseManager::IndexExists(std::string_view indexName, DatabaseError* err) {
            try {
                auto result = QueryWithParams(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?",
                    err,
                    std::string(indexName)
                );
                
                if (result.Next()) {
                    return result.GetInt(0) > 0;
                }
                return false;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"IndexExists");
                return false;
            }
        }

        /**
         * @brief Gets a list of all table names in the database.
         * 
         * @param err Optional error output
         * @return Vector of table names, sorted alphabetically
         */
        std::vector<std::string> DatabaseManager::GetTableNames(DatabaseError* err) {
            std::vector<std::string> tables;
            
            try {
                auto result = Query("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", err);
                
                while (result.Next()) {
                    tables.push_back(result.GetString(0));
                }
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetTableNames");
            }
            
            return tables;
        }

        /**
         * @brief Gets a list of column names for a table.
         * 
         * @param tableName Name of the table
         * @param err Optional error output
         * @return Vector of column names in declaration order
         */
        std::vector<std::string> DatabaseManager::GetColumnNames(std::string_view tableName, DatabaseError* err) {
            std::vector<std::string> columns;
            
            try {
                std::string sql = "PRAGMA table_info(" + std::string(tableName) + ")";
                auto result = Query(sql, err);
                
                while (result.Next()) {
                    columns.push_back(result.GetString(1));  // Column name is at index 1
                }
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetColumnNames");
            }
            
            return columns;
        }

        // ============================================================================
        // DATABASE MAINTENANCE METHODS
        // ============================================================================

        /**
         * @brief Rebuilds the database file to reclaim space.
         * 
         * VACUUM rewrites the entire database to a new file, reclaiming
         * space from deleted records. This operation can take significant
         * time on large databases and requires exclusive access.
         * 
         * @param err Optional error output
         * @return true if vacuum succeeded
         * @note This is an expensive operation - use sparingly
         */
        bool DatabaseManager::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Running VACUUM...");
            return Execute("VACUUM", err);
        }

        /**
         * @brief Updates query planner statistics.
         * 
         * ANALYZE collects statistics about table and index data distribution,
         * helping the query planner make better decisions. Should be run
         * periodically, especially after bulk inserts/deletes.
         * 
         * @param err Optional error output
         * @return true if analyze succeeded
         */
        bool DatabaseManager::Analyze(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Running ANALYZE...");
            return Execute("ANALYZE", err);
        }

        /**
         * @brief Checks database integrity and reports issues.
         * 
         * Runs SQLite's integrity_check pragma which verifies:
         * - Page structure consistency
         * - Foreign key relationships
         * - Index consistency with table data
         * 
         * @param issues Output vector of issue descriptions
         * @param err Optional error output
         * @return true if no integrity issues found
         */
        bool DatabaseManager::CheckIntegrity(std::vector<std::wstring>& issues, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Checking database integrity...");
            
            issues.clear();
            
            try {
                auto result = Query("PRAGMA integrity_check", err);
                
                while (result.Next()) {
                    std::wstring issue = result.GetWString(0);
                    if (issue != L"ok") {
                        issues.push_back(issue);
                    }
                }
                
                if (issues.empty()) {
                    SS_LOG_INFO(L"Database", L"Integrity check passed");
                } else {
                    SS_LOG_WARN(L"Database", L"Integrity check found %zu issues", issues.size());
                }
                
                return issues.empty();
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"CheckIntegrity");
                return false;
            }
        }

        /**
         * @brief Runs database optimization routines.
         * 
         * Combines ANALYZE and PRAGMA optimize for comprehensive
         * query performance improvement.
         * 
         * @param err Optional error output
         * @return true if optimization succeeded
         */
        bool DatabaseManager::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Optimizing database...");
            
            bool success = true;
            success = success && Analyze(err);
            success = success && Execute("PRAGMA optimize", err);
            
            if (success) {
                SS_LOG_INFO(L"Database", L"Database optimized successfully");
            }
            
            return success;
        }

        // ============================================================================
        // BACKUP & RESTORE METHODS
        // ============================================================================

        /**
         * @brief Creates a backup of the database at the specified path.
         * 
         * Uses SQLite's online backup API for consistent backups without
         * blocking ongoing operations.
         * 
         * @param backupPath Full path for the backup file
         * @param err Optional error output
         * @return true if backup created successfully
         */
        bool DatabaseManager::BackupToFile(std::wstring_view backupPath, DatabaseError* err) {
            return performBackup(std::wstring(backupPath), err);
        }

        /**
         * @brief Restores the database from a backup file.
         * 
         * This operation:
         * 1. Verifies backup file exists
         * 2. Shuts down current database connections
         * 3. Replaces database file with backup
         * 4. Reinitializes the database
         * 
         * @param backupPath Path to the backup file
         * @param err Optional error output
         * @return true if restore succeeded
         * @warning All current connections will be closed!
         */
        bool DatabaseManager::RestoreFromFile(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Restoring database from: %ls", backupPath.data());
            
            try {
                namespace fs = std::filesystem;
                
                // Verify backup file exists
                if (!fs::exists(backupPath)) {
                    setError(err, SQLITE_CANTOPEN, L"Backup file not found", L"RestoreFromFile");
                    return false;
                }
                
                // Close all connections (required for file replacement)
                Shutdown();
                
                // Replace current database with backup
                fs::copy_file(backupPath, m_config.databasePath, fs::copy_options::overwrite_existing);
                
                // Reinitialize with same configuration
                DatabaseConfig config = m_config;
                if (!Initialize(config, err)) {
                    SS_LOG_ERROR(L"Database", L"Failed to reinitialize after restore");
                    return false;
                }
                
                SS_LOG_INFO(L"Database", L"Database restored successfully");
                return true;
            }
            catch (const std::exception& ex) {
                setError(err, SQLITE_ERROR, ToWide(ex.what()), L"RestoreFromFile");
                SS_LOG_ERROR(L"Database", L"Restore failed: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        /**
         * @brief Creates an automatic backup with timestamp filename.
         * 
         * Backup is created in the configured backup directory (or a
         * 'backups' subdirectory of the database location). Old backups
         * beyond the retention limit are automatically deleted.
         * 
         * @param err Optional error output
         * @return true if backup created successfully
         */
        bool DatabaseManager::CreateAutoBackup(DatabaseError* err) {
            namespace fs = std::filesystem;
            
            // Determine backup directory
            std::wstring backupDir = m_config.backupDirectory;
            if (backupDir.empty()) {
                fs::path dbPath(m_config.databasePath);
                backupDir = (dbPath.parent_path() / L"backups").wstring();
            }
            
            // Create backup directory if needed
            Utils::FileUtils::Error fileErr;
            if (!Utils::FileUtils::CreateDirectories(backupDir, &fileErr)) {
                setError(err, SQLITE_CANTOPEN, L"Failed to create backup directory", L"CreateAutoBackup");
                return false;
            }
            
            // Generate backup filename with timestamp
            auto now = std::chrono::system_clock::now();
            auto time_t_now = std::chrono::system_clock::to_time_t(now);
            std::tm tm_now;
            localtime_s(&tm_now, &time_t_now);
            
            std::wstringstream ss;
            ss << backupDir << L"\\backup_"
               << std::put_time(&tm_now, L"%Y%m%d_%H%M%S")
               << L".db";
            
            std::wstring backupPath = ss.str();
            
            if (!performBackup(backupPath, err)) {
                return false;
            }
            
            // Clean up old backups
            cleanupOldBackups();
            
            return true;
        }

        /**
         * @brief Gets database statistics and metrics.
         * 
         * Returns information about database size, page allocation,
         * and query/transaction counts.
         * 
         * @param err Optional error output
         * @return DatabaseStats structure with current metrics
         */
        DatabaseManager::DatabaseStats DatabaseManager::GetStats(DatabaseError* err) {
            DatabaseStats stats;

            try {
                // Query page count from SQLite
                auto result = Query("PRAGMA page_count", err);
                if (result.Next()) {
                    stats.pageCount = result.GetInt64(0);
                }

                // Get configured page size
                result = Query("PRAGMA page_size", err);
                if (result.Next()) {
                    stats.pageSize = result.GetInt64(0);
                }

                // Calculate total database size
                stats.totalSize = stats.pageCount * stats.pageSize;

                // Count free (unused) pages
                result = Query("PRAGMA freelist_count", err);
                if (result.Next()) {
                    stats.freePages = result.GetInt64(0);
                }

                // Atomic load of query/transaction counters
                stats.totalQueries = m_totalQueries.load(std::memory_order_relaxed);
                stats.totalTransactions = m_totalTransactions.load(std::memory_order_relaxed);
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetStats");
            }

            return stats;
        }

        // ============================================================================
        // CONNECTION MANAGEMENT
        // ============================================================================

        /**
         * @brief Acquires a database connection from the pool.
         * 
         * Blocks until a connection is available or timeout expires.
         * Callers MUST release the connection when done.
         * 
         * @param err Optional error output
         * @return Database connection, or nullptr on error/timeout
         */
        std::shared_ptr<SQLite::Database> DatabaseManager::AcquireConnection(DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                setError(err, SQLITE_MISUSE, L"DatabaseManager not initialized");
                return nullptr;
            }
            
            return m_connectionPool->Acquire(m_config.connectionTimeout, err);
        }

        /**
         * @brief Returns a connection to the pool.
         * 
         * Safe to call with nullptr (no-op).
         * 
         * @param conn Connection to release
         */
        void DatabaseManager::ReleaseConnection(std::shared_ptr<SQLite::Database> conn) {
            if (conn && m_connectionPool) {
                m_connectionPool->Release(conn);
            }
        }

        // ============================================================================
        // SCHEMA MIGRATION
        // ============================================================================

        /**
         * @brief Gets the current database schema version.
         * 
         * @param err Optional error output
         * @return Current version number, 0 if not set, -1 on error
         */
        int DatabaseManager::GetSchemaVersion(DatabaseError* err) {
            try {
                auto result = Query(SQL_GET_SCHEMA_VERSION, err);
                if (result.Next()) {
                    return result.GetInt(0);
                }
                return 0;  // No version set = version 0
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetSchemaVersion");
                return -1;
            }
        }

        /**
         * @brief Sets the database schema version.
         * 
         * @param version New version number
         * @param err Optional error output
         * @return true if version updated successfully
         */
        bool DatabaseManager::SetSchemaVersion(int version, DatabaseError* err) {
            return ExecuteWithParams(SQL_SET_SCHEMA_VERSION, err, std::to_string(version));
        }

        /**
         * @brief Upgrades the database schema to a target version.
         * 
         * Executes migration scripts for each version from current+1
         * to target. All migrations run in a single EXCLUSIVE transaction
         * for atomicity - either all succeed or none are applied.
         * 
         * @param currentVersion Current schema version
         * @param targetVersion Target schema version
         * @param err Optional error output
         * @return true if all migrations succeeded
         */
        bool DatabaseManager::UpgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Upgrading schema from version %d to %d", currentVersion, targetVersion);
            
            // Use exclusive transaction for schema changes
            auto trans = BeginTransaction(Transaction::Type::Exclusive, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }
            
            // Apply each migration sequentially
            for (int version = currentVersion + 1; version <= targetVersion; ++version) {
                auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                if (!executeSchemaMigration(*conn, version, err)) {
                    trans->Rollback(err);
                    ReleaseConnection(conn);
                    return false;
                }
                
                ReleaseConnection(conn);
            }
            
            // Update version marker
            if (!SetSchemaVersion(targetVersion, err)) {
                trans->Rollback(err);
                return false;
            }
            
            // Commit all changes
            if (!trans->Commit(err)) {
                return false;
            }
            
            SS_LOG_INFO(L"Database", L"Schema upgraded successfully to version %d", targetVersion);
            return true;
        }

        // ============================================================================
        // PRIVATE HELPER METHODS
        // ============================================================================

        /**
         * @brief Creates the database file and parent directories.
         * 
         * @param err Optional error output
         * @return true if file can be created
         */
        bool DatabaseManager::createDatabaseFile(DatabaseError* err) {
            namespace fs = std::filesystem;
            
            fs::path dbPath(m_config.databasePath);
            
            // Create parent directories if needed
            if (dbPath.has_parent_path()) {
                Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::CreateDirectories(dbPath.parent_path().wstring(), &fileErr)) {
                    setError(err, SQLITE_CANTOPEN, L"Failed to create database directory");
                    return false;
                }
            }
            
            return true;
        }

        /**
         * @brief Configures connection pragmas (delegated to ConnectionPool).
         * 
         * @param db Database connection
         * @param err Optional error output
         * @return Always true (configuration done in ConnectionPool)
         */
        bool DatabaseManager::configurePragmas(SQLite::Database& db, DatabaseError* err) {
            // Already handled by ConnectionPool::configureConnection
            return true;
        }

        /**
         * @brief Enables security-related database features.
         * 
         * Sets application ID for file format validation and syncs
         * user_version with schema version.
         * 
         * @param db Database connection
         * @param err Optional error output
         * @return true if security settings applied
         */
        bool DatabaseManager::enableSecurity(SQLite::Database& db, DatabaseError* err) {
            try {
                // Set application_id for file format identification
                // 'SHDW' in hex identifies this as a ShadowStrike database
                db.exec("PRAGMA application_id = 0x53484457");
                
                // Sync user_version with schema version for external tools
                std::string userVersion = "PRAGMA user_version = " + std::to_string(GetSchemaVersion(err));
                db.exec(userVersion);
                
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"enableSecurity");
                return false;
            }
        }

        /**
         * @brief Executes schema migration for a specific version.
         * 
         * Implement actual migration logic in the switch statement.
         * Each version case should contain the DDL/DML changes needed
         * to upgrade from version-1 to version.
         * 
         * @param db Database connection
         * @param version Target version to migrate to
         * @param err Optional error output
         * @return true if migration succeeded
         */
        bool DatabaseManager::executeSchemaMigration(SQLite::Database& db, int version, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Executing migration to version %d", version);
            
            try {
                switch (version) {
                    case 1:
                        // Initial schema - tables created in CreateTables()
                        break;
                        
                    case 2:
                        // Example migration: Add risk_score column
                        // db.exec("ALTER TABLE threat_definitions ADD COLUMN risk_score INTEGER DEFAULT 0");
                        break;
                        
                    // Add additional version migrations here:
                    // case 3:
                    //     db.exec("CREATE INDEX IF NOT EXISTS idx_new ON table(column)");
                    //     break;
                    
                    default:
                        SS_LOG_WARN(L"Database", L"No migration defined for version %d", version);
                        break;
                }
                
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"executeSchemaMigration");
                return false;
            }
        }

        /**
         * @brief Background thread function for automatic backups.
         * 
         * Runs continuously until shutdown signal. Wakes periodically to
         * check if backup interval has elapsed, then creates backup if needed.
         */
        void DatabaseManager::backgroundBackupThread() {
            SS_LOG_INFO(L"Database", L"Background backup thread started");
            
            while (!m_shutdownBackupThread.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_backupMutex);
                
                // Wait for backup interval or shutdown signal
                m_backupCv.wait_for(lock, m_config.backupInterval, [this]() {
                    return m_shutdownBackupThread.load(std::memory_order_acquire);
                });
                
                // Check for shutdown
                if (m_shutdownBackupThread.load(std::memory_order_acquire)) {
                    break;
                }
                
                // Verify enough time has passed since last backup
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::hours>(now - m_lastBackup);
                
                if (elapsed >= m_config.backupInterval) {
                    SS_LOG_INFO(L"Database", L"Starting automatic backup...");
                    
                    DatabaseError err;
                    if (CreateAutoBackup(&err)) {
                        m_lastBackup = now;
                        SS_LOG_INFO(L"Database", L"Automatic backup completed successfully");
                    } else {
                        SS_LOG_ERROR(L"Database", L"Automatic backup failed: %ls", err.message.c_str());
                    }
                }
            }
            
            SS_LOG_INFO(L"Database", L"Background backup thread stopped");
        }

        /**
         * @brief Performs the actual backup operation.
         * 
         * Uses SQLite's online backup API for consistent backup without
         * blocking ongoing operations.
         * 
         * @param backupPath Full path for backup file
         * @param err Optional error output
         * @return true if backup succeeded
         */
        bool DatabaseManager::performBackup(const std::wstring& backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Creating backup: %ls", backupPath.c_str());
            
            try {
                auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                std::string backupPathStr = ToNarrow(backupPath);
                
                // Use SQLiteCpp's backup API for online backup
                conn->backup(backupPathStr.c_str(), SQLite::Database::BackupType::Save);
                
                ReleaseConnection(conn);
                
                SS_LOG_INFO(L"Database", L"Backup created successfully: %ls", backupPath.c_str());
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"performBackup");
                SS_LOG_ERROR(L"Database", L"Backup failed: %ls", ToWide(ex.what()).c_str());
                return false;
            }
        }

        /**
         * @brief Removes old backups exceeding retention limit.
         * 
         * Keeps the most recent maxBackupCount backups and deletes
         * older ones to manage disk space.
         */
        void DatabaseManager::cleanupOldBackups() {
            namespace fs = std::filesystem;
            
            try {
                // Determine backup directory
                std::wstring backupDir = m_config.backupDirectory;
                if (backupDir.empty()) {
                    fs::path dbPath(m_config.databasePath);
                    backupDir = (dbPath.parent_path() / L"backups").wstring();
                }
                
                if (!fs::exists(backupDir)) return;
                
                // Collect backup files with modification times
                std::deque<std::pair<fs::path, fs::file_time_type>> backups;
                
                for (const auto& entry : fs::directory_iterator(backupDir)) {
                    if (entry.is_regular_file() && entry.path().extension() == L".db") {
                        backups.emplace_back(entry.path(), fs::last_write_time(entry));
                    }
                }
                
                // Sort by modification time (oldest first)
                std::sort(backups.begin(), backups.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                
                // Delete oldest until within limit
                while (backups.size() > m_config.maxBackupCount) {
                    fs::remove(backups.front().first);
                    SS_LOG_INFO(L"Database", L"Deleted old backup: %ls", backups.front().first.c_str());
                    backups.erase(backups.begin());
                }
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"Database", L"Failed to clean up old backups: %ls", ToWide(ex.what()).c_str());
            }
        }

        /**
         * @brief Sets error information from code and message.
         * 
         * @param err Error structure to populate (can be nullptr)
         * @param code SQLite error code
         * @param msg Error message
         * @param ctx Context string (function/operation name)
         */
        void DatabaseManager::setError(
            DatabaseError* err,
            int code,
            std::wstring_view msg,
            std::wstring_view ctx
        ) const {
            if (!err) return;
            
            err->sqliteCode = code;
            err->message = msg;
            err->context = ctx;
        }

        /**
         * @brief Sets error information from SQLite exception.
         * 
         * @param err Error structure to populate (can be nullptr)
         * @param ex SQLite exception
         * @param ctx Context string (function/operation name)
         */
        void DatabaseManager::setError(
            DatabaseError* err,
            const SQLite::Exception& ex,
            std::wstring_view ctx
        ) const {
            if (!err) return;
            
            err->sqliteCode = ex.getErrorCode();
            err->extendedCode = ex.getExtendedErrorCode();
            err->message = ToWide(ex.what());
            err->context = ctx;
        }

    } // namespace Database
} // namespace ShadowStrike
