#include "DatabaseManager.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace ShadowStrike {
    namespace Database {

        namespace {
            // Helper to convert narrow string to wide string
            std::wstring ToWide(std::string_view str) {
                if (str.empty()) return std::wstring();
                
                int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
                if (size == 0) return std::wstring();
                
                std::wstring result(size, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &result[0], size);
                return result;
            }
            
            // Helper to convert wide string to narrow string
            std::string ToNarrow(std::wstring_view str) {
                if (str.empty()) return std::string();
                
                int size = WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
                if (size == 0) return std::string();
                
                std::string result(size, '\0');
                WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), &result[0], size, nullptr, nullptr);
                return result;
            }

            // Schema version table creation
            constexpr const char* SQL_CREATE_METADATA_TABLE = R"(
                CREATE TABLE IF NOT EXISTS _metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL,
                    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
                ) WITHOUT ROWID;
            )";

            // Schema version queries
            constexpr const char* SQL_GET_SCHEMA_VERSION = "SELECT value FROM _metadata WHERE key = 'schema_version'";
            constexpr const char* SQL_SET_SCHEMA_VERSION = "INSERT OR REPLACE INTO _metadata (key, value) VALUES ('schema_version', ?)";

        } // anonymous namespace

        // ============================================================================
        // QueryResult Implementation
        // ============================================================================

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

        QueryResult::~QueryResult() {
            
            m_statement.reset();

           
            if (m_connection && m_manager) {
                m_manager->ReleaseConnection(m_connection);
            }
        }
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

        QueryResult& QueryResult::operator=(QueryResult&& other) noexcept {
            if (this != &other) {
                
                m_statement.reset();

                if (m_connection && m_manager) {
                    m_manager->ReleaseConnection(m_connection);
                }

                
                m_statement = std::move(other.m_statement);
                m_connection = std::move(other.m_connection);
                m_manager = other.m_manager;
                m_hasRows = other.m_hasRows;
                m_columnIndexCache = std::move(other.m_columnIndexCache);

                
                other.m_manager = nullptr;
                other.m_hasRows = false;
            }
            return *this;
        }

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

        bool QueryResult::IsNull(int columnIndex) const {
            if (!m_statement) return true;
            return m_statement->getColumn(columnIndex).isNull();
        }

        bool QueryResult::IsNull(std::string_view columnName) const {
            return IsNull(getColumnIndex(columnName));
        }

        int QueryResult::GetColumnType(int columnIndex) const {
            if (!m_statement) return SQLITE_NULL;
            return m_statement->getColumn(columnIndex).getType();
        }

        int QueryResult::GetColumnType(std::string_view columnName) const {
            return GetColumnType(getColumnIndex(columnName));
        }

        int QueryResult::getColumnIndex(std::string_view columnName) const {
            std::string name(columnName);
            
            auto it = m_columnIndexCache.find(name);
            if (it != m_columnIndexCache.end()) {
                return it->second;
            }
            
            if (!m_statement) throw std::runtime_error("Invalid statement");
            
            for (int i = 0; i < ColumnCount(); ++i) {
                if (m_statement->getColumnName(i) == name) {
                    m_columnIndexCache[name] = i;
                    return i;
                }
            }
            
            throw std::runtime_error("Column not found: " + name);
        }

        // ============================================================================
        // PreparedStatementCache Implementation
        // ============================================================================

        PreparedStatementCache::PreparedStatementCache(size_t maxSize) noexcept
            : m_maxSize(maxSize)
        {
        }

        std::shared_ptr<SQLite::Statement> PreparedStatementCache::Get(
            SQLite::Database& db,
            std::string_view sql,
            DatabaseError* err
        ) {
            std::string sqlStr(sql);
            
            std::lock_guard<std::mutex> lock(m_mutex);
            
            auto it = m_cache.find(sqlStr);
            if (it != m_cache.end()) {
                it->second.lastUsed = std::chrono::steady_clock::now();
                return it->second.statement;
            }
            
            // Not in cache, create new
            try {
                auto stmt = std::make_shared<SQLite::Statement>(db, sqlStr);
                
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

        void PreparedStatementCache::Clear() noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_cache.clear();
        }

        size_t PreparedStatementCache::Size() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_cache.size();
        }

        void PreparedStatementCache::evictOldest() {
            if (m_cache.empty()) return;
            
            auto oldest = m_cache.begin();
            for (auto it = m_cache.begin(); it != m_cache.end(); ++it) {
                if (it->second.lastUsed < oldest->second.lastUsed) {
                    oldest = it;
                }
            }
            
            m_cache.erase(oldest);
        }

        // ============================================================================
        // ConnectionPool Implementation
        // ============================================================================

        ConnectionPool::ConnectionPool(const DatabaseConfig& config) noexcept
            : m_config(config)
        {
        }

        ConnectionPool::~ConnectionPool() {
            Shutdown();
        }

        bool ConnectionPool::Initialize(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            // Create minimum number of connections
            for (size_t i = 0; i < m_config.minConnections; ++i) {
                if (!createConnection(err)) {
                    Shutdown();
                    return false;
                }
            }
            
            SS_LOG_INFO(L"Database", L"Connection pool initialized with %zu connections", m_connections.size());
            return true;
        }

        void ConnectionPool::Shutdown() {

            bool wasShutdown = m_shutdown.exchange(true, std::memory_order_acq_rel);
            if (wasShutdown) {
                SS_LOG_DEBUG(L"Database", L"Connection pool already shut down");
                return;  // Already shut down
            }

            std::lock_guard<std::mutex> lock(m_mutex);
            
            m_shutdown.store(true, std::memory_order_release);
            m_cv.notify_all();

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

        void ConnectionPool::Release(std::shared_ptr<SQLite::Database> conn) {
            if (!conn) return;
            
            std::lock_guard<std::mutex> lock(m_mutex);
            
            for (auto& pooled : m_connections) {
                if (pooled.connection == conn) {
                    pooled.inUse = false;
                    pooled.lastUsed = std::chrono::steady_clock::now();
                    m_activeCount.fetch_sub(1, std::memory_order_relaxed);
                    m_cv.notify_one();
                    return;
                }
            }
            
            SS_LOG_WARN(L"Database", L"Released connection not found in pool");
        }

        size_t ConnectionPool::AvailableConnections() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            
            size_t available = 0;
            for (const auto& pooled : m_connections) {
                if (!pooled.inUse) ++available;
            }
            return available;
        }

        size_t ConnectionPool::TotalConnections() const noexcept {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_connections.size();
        }

        bool ConnectionPool::createConnection(DatabaseError* err) {
            try {
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
                
                if (!configureConnection(*connection, err)) {
                    return false;
                }
                
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

        bool ConnectionPool::configureConnection(SQLite::Database& db, DatabaseError* err) {
            try {
                // Enable foreign keys
                if (m_config.enableForeignKeys) {
                    db.exec("PRAGMA foreign_keys = ON");
                }
                
                // Configure journal mode
                std::string journalMode = "PRAGMA journal_mode = " + ToNarrow(m_config.journalMode);
                db.exec(journalMode);
                
                // Configure synchronous mode
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
        // Transaction Implementation
        // ============================================================================

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
                const char* sql = nullptr;
                switch (type) {
                case Type::Deferred:
                    sql = "BEGIN DEFERRED TRANSACTION";
                    break;
                case Type::Immediate:
                    sql = "BEGIN IMMEDIATE TRANSACTION";
                    break;
                case Type::Exclusive:
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

        Transaction::~Transaction() {
            if (m_active && !m_committed && m_db) {
                try {
                    m_db->exec("ROLLBACK");
                    SS_LOG_DEBUG(L"Database", L"Transaction rolled back (destructor)");
                }
                catch (const SQLite::Exception& ex) {
                    SS_LOG_ERROR(L"Database", L"Failed to rollback transaction: %ls", ToWide(ex.what()).c_str());
                }
            }

            // ✅ Release connection
            if (m_connection && m_manager) {
                m_manager->ReleaseConnection(m_connection);
            }
        }

        // ✅ NEW: Execute on transaction's connection
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

        Transaction::Transaction(Transaction&& other) noexcept
            : m_db(other.m_db)
            , m_connection(std::move(other.m_connection))
            , m_manager(other.m_manager)
            , m_active(other.m_active)
            , m_committed(other.m_committed)
        {
            other.m_db = nullptr;
            other.m_manager = nullptr;
            other.m_active = false;
            other.m_committed = false;
        }

        Transaction& Transaction::operator=(Transaction&& other) noexcept {
            if (this != &other) {
                // Cleanup
                if (m_active && !m_committed && m_db) {
                    try {
                        m_db->exec("ROLLBACK");
                    }
                    catch (...) {}
                }

                if (m_connection && m_manager) {
                    m_manager->ReleaseConnection(m_connection);
                }

                // Move
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
        // DatabaseManager Implementation
        // ============================================================================

        DatabaseManager& DatabaseManager::Instance() {
            static DatabaseManager instance;
            return instance;
        }

        DatabaseManager::DatabaseManager() {
        }

        DatabaseManager::~DatabaseManager() {
            Shutdown();
        }

        bool DatabaseManager::Initialize(const DatabaseConfig& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"Database", L"DatabaseManager already initialized");
                return true;
            }

            SS_LOG_SCOPE(L"Database");
            SS_LOG_INFO(L"Database", L"Initializing DatabaseManager...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

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
        void DatabaseManager::Shutdown() {
           
            bool wasInitialized = m_initialized.exchange(false, std::memory_order_acq_rel);

            SS_LOG_INFO(L"Database", L"Shutting down DatabaseManager...");
            
            // Stop backup thread
            m_shutdownBackupThread.store(true, std::memory_order_release);
            m_backupCv.notify_all();
            
            if (m_backupThread.joinable()) {
                m_backupThread.join();
            }
            
            // Clear caches
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

        bool DatabaseManager::CreateTables(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Creating application tables...");
            
            // Define your application's schema here
            // This is a sample schema for an antivirus application
            
            std::vector<std::string> schemas = {
                // Threat definitions table
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
                
                // Scan history table
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
                
                // Detected threats table
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
                
                // Quarantine table
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

        bool DatabaseManager::Execute(std::string_view sql, DatabaseError* err) {
                  auto conn = AcquireConnection(err);
                if (!conn) return false;
                
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

        bool DatabaseManager::ExecuteMany(const std::vector<std::string>& statements, DatabaseError* err) {
            
            auto conn = AcquireConnection(err);
            if (!conn) return false;

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
                // Start transaction on THIS connection
                conn->exec("BEGIN IMMEDIATE TRANSACTION");

                // Execute all statements on SAME connection
                for (const auto& sql : statements) {
                    try {
                        conn->exec(sql);
                        m_totalQueries.fetch_add(1, std::memory_order_relaxed);
                    }
                    catch (const SQLite::Exception& ex) {
                        // Rollback on error
                        try {
                            conn->exec("ROLLBACK");
                        }
                        catch (...) {}

                        setError(err, ex, L"ExecuteMany");
                        return false;
                    }
                }

                // Commit transaction
                conn->exec("COMMIT");
                return true;
            }
            catch (const SQLite::Exception& ex) {
                // Rollback on error
                try {
                    conn->exec("ROLLBACK");
                }
                catch (...) {}

                setError(err, ex, L"ExecuteMany");
                return false;
            }
        }

        QueryResult DatabaseManager::Query(std::string_view sql, DatabaseError* err) {
            auto conn = AcquireConnection(err);
            if (!conn) return QueryResult{};

            try {
                auto stmt = std::make_unique<SQLite::Statement>(*conn, sql.data());
                m_totalQueries.fetch_add(1, std::memory_order_relaxed);

               
                return QueryResult{ std::move(stmt), conn, this };
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"Query");
                ReleaseConnection(conn);  
                return QueryResult{};
            }
        }

        std::unique_ptr<Transaction> DatabaseManager::BeginTransaction(
            Transaction::Type type,
            DatabaseError* err
        ) {
            auto conn = AcquireConnection(err);
            if (!conn) return nullptr;
            
            m_totalTransactions.fetch_add(1, std::memory_order_relaxed);
            
            return std::make_unique<Transaction>(*conn,conn,this, type, err);
        }

        int64_t DatabaseManager::LastInsertRowId() {
            auto conn = AcquireConnection();
            if (!conn) return -1;
            
            int64_t id = conn->getLastInsertRowid();
            ReleaseConnection(conn);
            return id;
        }

        int DatabaseManager::GetChangedRowCount() {
            auto conn = AcquireConnection();
            if (!conn) return -1;
            
            int count = conn->getChanges();
            ReleaseConnection(conn);
            return count;
        }

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

        bool DatabaseManager::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Running VACUUM...");
            return Execute("VACUUM", err);
        }

        bool DatabaseManager::Analyze(DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Running ANALYZE...");
            return Execute("ANALYZE", err);
        }

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

        bool DatabaseManager::BackupToFile(std::wstring_view backupPath, DatabaseError* err) {
            return performBackup(std::wstring(backupPath), err);
        }

        bool DatabaseManager::RestoreFromFile(std::wstring_view backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Restoring database from: %ls", backupPath.data());
            
            try {
                namespace fs = std::filesystem;
                
                // Verify backup file exists
                if (!fs::exists(backupPath)) {
                    setError(err, SQLITE_CANTOPEN, L"Backup file not found", L"RestoreFromFile");
                    return false;
                }
                
                // Close all connections
                Shutdown();
                
                // Copy backup over current database
                fs::copy_file(backupPath, m_config.databasePath, fs::copy_options::overwrite_existing);
                
                // Reinitialize
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

        bool DatabaseManager::CreateAutoBackup(DatabaseError* err) {
            namespace fs = std::filesystem;
            
            std::wstring backupDir = m_config.backupDirectory;
            if (backupDir.empty()) {
                fs::path dbPath(m_config.databasePath);
                backupDir = (dbPath.parent_path() / L"backups").wstring();
            }
            
            // Create backup directory
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

        DatabaseManager::DatabaseStats DatabaseManager::GetStats(DatabaseError* err) {
            DatabaseStats stats;

            try {
                

                // Get page count and page size
                auto result = Query("PRAGMA page_count", err);
                if (result.Next()) {
                    stats.pageCount = result.GetInt64(0);
                }

                result = Query("PRAGMA page_size", err);
                if (result.Next()) {
                    stats.pageSize = result.GetInt64(0);
                }

                stats.totalSize = stats.pageCount * stats.pageSize;

                // Get free pages
                result = Query("PRAGMA freelist_count", err);
                if (result.Next()) {
                    stats.freePages = result.GetInt64(0);
                }

                stats.totalQueries = m_totalQueries.load(std::memory_order_relaxed);
                stats.totalTransactions = m_totalTransactions.load(std::memory_order_relaxed);

                
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetStats");
            }

            return stats;
        }

        std::shared_ptr<SQLite::Database> DatabaseManager::AcquireConnection(DatabaseError* err) {
            if (!m_initialized.load(std::memory_order_acquire)) {
                setError(err, SQLITE_MISUSE, L"DatabaseManager not initialized");
                return nullptr;
            }
            
            return m_connectionPool->Acquire(m_config.connectionTimeout, err);
        }

        void DatabaseManager::ReleaseConnection(std::shared_ptr<SQLite::Database> conn) {
            if (conn && m_connectionPool) {
                m_connectionPool->Release(conn);
            }
        }

        int DatabaseManager::GetSchemaVersion(DatabaseError* err) {
            try {
                auto result = Query(SQL_GET_SCHEMA_VERSION, err);
                if (result.Next()) {
                    return result.GetInt(0);
                }
                return 0;  // No version set
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"GetSchemaVersion");
                return -1;
            }
        }

        bool DatabaseManager::SetSchemaVersion(int version, DatabaseError* err) {
            return ExecuteWithParams(SQL_SET_SCHEMA_VERSION, err, std::to_string(version));
        }

        bool DatabaseManager::UpgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Upgrading schema from version %d to %d", currentVersion, targetVersion);
            
            auto trans = BeginTransaction(Transaction::Type::Exclusive, err);
            if (!trans || !trans->IsActive()) {
                return false;
            }
            
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
            
            if (!SetSchemaVersion(targetVersion, err)) {
                trans->Rollback(err);
                return false;
            }
            
            if (!trans->Commit(err)) {
                return false;
            }
            
            SS_LOG_INFO(L"Database", L"Schema upgraded successfully to version %d", targetVersion);
            return true;
        }

        bool DatabaseManager::createDatabaseFile(DatabaseError* err) {
            namespace fs = std::filesystem;
            
            fs::path dbPath(m_config.databasePath);
            
            // Create parent directory if needed
            if (dbPath.has_parent_path()) {
                Utils::FileUtils::Error fileErr;
                if (!Utils::FileUtils::CreateDirectories(dbPath.parent_path().wstring(), &fileErr)) {
                    setError(err, SQLITE_CANTOPEN, L"Failed to create database directory");
                    return false;
                }
            }
            
            return true;
        }

        bool DatabaseManager::configurePragmas(SQLite::Database& db, DatabaseError* err) {
            // Already done in ConnectionPool::configureConnection
            return true;
        }

        bool DatabaseManager::enableSecurity(SQLite::Database& db, DatabaseError* err) {
            try {
                // Enable application_id for file format validation
                db.exec("PRAGMA application_id = 0x53484457");  // 'SHDW' in hex
                
                // Set user_version for schema tracking
                std::string userVersion = "PRAGMA user_version = " + std::to_string(GetSchemaVersion(err));
                db.exec(userVersion);
                
                return true;
            }
            catch (const SQLite::Exception& ex) {
                setError(err, ex, L"enableSecurity");
                return false;
            }
        }

        bool DatabaseManager::executeSchemaMigration(SQLite::Database& db, int version, DatabaseError* err) {
            // Implement  schema migration logic here
            // This is called for each version upgrade
            
            SS_LOG_INFO(L"Database", L"Executing migration to version %d", version);
            
            try {
                switch (version) {
                    case 1:
                        // Initial schema (already created in CreateTables)
                        break;
                        
                    case 2:
                        // Example: Add new column
                        // db.exec("ALTER TABLE threat_definitions ADD COLUMN risk_score INTEGER DEFAULT 0");
                        break;
                        
                    // Add more migration cases as needed
                    
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

        void DatabaseManager::backgroundBackupThread() {
            SS_LOG_INFO(L"Database", L"Background backup thread started");
            
            while (!m_shutdownBackupThread.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_backupMutex);
                
                // Wait for backup interval or shutdown signal
                m_backupCv.wait_for(lock, m_config.backupInterval, [this]() {
                    return m_shutdownBackupThread.load(std::memory_order_acquire);
                });
                
                if (m_shutdownBackupThread.load(std::memory_order_acquire)) {
                    break;
                }
                
                // Check if enough time has passed since last backup
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

        bool DatabaseManager::performBackup(const std::wstring& backupPath, DatabaseError* err) {
            SS_LOG_INFO(L"Database", L"Creating backup: %ls", backupPath.c_str());
            
            try {
                auto conn = AcquireConnection(err);
                if (!conn) return false;
                
                std::string backupPathStr = ToNarrow(backupPath);
                
                // Perform backup using SQLiteCpp API
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

        void DatabaseManager::cleanupOldBackups() {
            namespace fs = std::filesystem;
            
            try {
                std::wstring backupDir = m_config.backupDirectory;
                if (backupDir.empty()) {
                    fs::path dbPath(m_config.databasePath);
                    backupDir = (dbPath.parent_path() / L"backups").wstring();
                }
                
                if (!fs::exists(backupDir)) return;
                
                // Collect all backup files with their modification times
                std::vector<std::pair<fs::path, fs::file_time_type>> backups;
                
                for (const auto& entry : fs::directory_iterator(backupDir)) {
                    if (entry.is_regular_file() && entry.path().extension() == L".db") {
                        backups.emplace_back(entry.path(), fs::last_write_time(entry));
                    }
                }
                
                // Sort by modification time (oldest first)
                std::sort(backups.begin(), backups.end(),
                    [](const auto& a, const auto& b) { return a.second < b.second; });
                
                // Delete oldest backups if we exceed max count
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
