#include "CacheDB.hpp"

#include <algorithm>
#include <sstream>

namespace ShadowStrike {
    namespace Database {

        namespace {
            // Database schema version
            constexpr int CACHEDB_SCHEMA_VERSION = 1;

            // SQL statements
            constexpr const char* SQL_CREATE_CACHE_TABLE = R"(
                CREATE TABLE IF NOT EXISTS cache_entries (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL,
                    expire_timestamp INTEGER NOT NULL,
                    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    accessed_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
                    access_count INTEGER NOT NULL DEFAULT 0
                ) WITHOUT ROWID;
            )";

            constexpr const char* SQL_CREATE_INDICES = R"(
                CREATE INDEX IF NOT EXISTS idx_cache_expire ON cache_entries(expire_timestamp);
                CREATE INDEX IF NOT EXISTS idx_cache_accessed ON cache_entries(accessed_at DESC);
            )";

            constexpr const char* SQL_INSERT_ENTRY = R"(
                INSERT OR REPLACE INTO cache_entries (key, value, expire_timestamp, accessed_at, access_count)
                VALUES (?, ?, ?, strftime('%s', 'now'), 
                    COALESCE((SELECT access_count FROM cache_entries WHERE key = ?), 0) + 1)
            )";

            constexpr const char* SQL_SELECT_ENTRY = R"(
                SELECT value, expire_timestamp FROM cache_entries WHERE key = ?
            )";

            constexpr const char* SQL_DELETE_ENTRY = R"(
                DELETE FROM cache_entries WHERE key = ?
            )";

            constexpr const char* SQL_EXISTS_ENTRY = R"(
                SELECT 1 FROM cache_entries WHERE key = ? LIMIT 1
            )";

            constexpr const char* SQL_SELECT_BY_PREFIX = R"(
                SELECT key FROM cache_entries WHERE key LIKE ? || '%' LIMIT ?
            )";

            constexpr const char* SQL_SELECT_BY_PATTERN = R"(
                SELECT key FROM cache_entries WHERE key LIKE ? LIMIT ?
            )";

            constexpr const char* SQL_DELETE_BY_PREFIX = R"(
                DELETE FROM cache_entries WHERE key LIKE ? || '%'
            )";

            constexpr const char* SQL_DELETE_EXPIRED = R"(
                DELETE FROM cache_entries WHERE expire_timestamp < strftime('%s', 'now')
            )";

            constexpr const char* SQL_COUNT_ENTRIES = R"(
                SELECT COUNT(*) FROM cache_entries
            )";

            constexpr const char* SQL_SELECT_TOP_N = R"(
                SELECT key, value, expire_timestamp FROM cache_entries 
                ORDER BY access_count DESC, accessed_at DESC 
                LIMIT ?
            )";

            constexpr const char* SQL_UPDATE_ACCESS = R"(
                UPDATE cache_entries SET accessed_at = strftime('%s', 'now'), 
                access_count = access_count + 1 WHERE key = ?
            )";

            // Helper to convert wstring to UTF-8
            std::string ToUTF8(std::wstring_view wstr) {
                if (wstr.empty()) return std::string();
                
                int size = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), 
                    static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
                if (size == 0) return std::string();
                
                std::string result(size, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), 
                    &result[0], size, nullptr, nullptr);
                return result;
            }

            // Helper to convert UTF-8 to wstring
            std::wstring ToWide(std::string_view str) {
                if (str.empty()) return std::wstring();
                
                int size = MultiByteToWideChar(CP_UTF8, 0, str.data(), 
                    static_cast<int>(str.size()), nullptr, 0);
                if (size == 0) return std::wstring();
                
                std::wstring result(size, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), 
                    &result[0], size);
                return result;
            }
        }

        // ============================================================================
        // CacheDB Implementation
        // ============================================================================

        CacheDB& CacheDB::Instance() {
            static CacheDB instance;
            return instance;
        }

        CacheDB::CacheDB() {
        }

        CacheDB::~CacheDB() {
            Shutdown();
        }

        bool CacheDB::Initialize(const Config& config, DatabaseError* err) {
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"CacheDB", L"Already initialized");
                return true;
            }

            SS_LOG_INFO(L"CacheDB", L"Initializing CacheDB...");

            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config = config;

            // Initialize DatabaseManager
            DatabaseConfig dbConfig;
            dbConfig.databasePath = m_config.dbPath;
            dbConfig.enableWAL = m_config.enableWAL;
            dbConfig.cacheSizeKB = m_config.dbCacheSizeKB;
            dbConfig.maxConnections = 5;
            dbConfig.minConnections = 2;

            if (!DatabaseManager::Instance().Initialize(dbConfig, err)) {
                SS_LOG_ERROR(L"CacheDB", L"Failed to initialize DatabaseManager");
                return false;
            }

            // Create schema
            if (!createSchema(err)) {
                SS_LOG_ERROR(L"CacheDB", L"Failed to create schema");
                DatabaseManager::Instance().Shutdown();
                return false;
            }

            // Initialize CacheManager
            Utils::CacheManager::Instance().Initialize(
                m_config.cachePath,
                m_config.maxCacheEntries,
                m_config.maxCacheBytes,
                m_config.maintenanceInterval
            );

            // Start write-behind thread if needed
            if (m_config.writeStrategy == WriteStrategy::WriteBehind) {
                m_shutdownWriteBehind.store(false, std::memory_order_release);
                m_writeBehindThread = std::thread(&CacheDB::writeBehindThread, this);
            }

            // Warm up cache from database if enabled
            if (m_config.warmupOnStartup) {
                SS_LOG_INFO(L"CacheDB", L"Warming up cache from database...");
                WarmUpCache(m_config.warmupMaxEntries, err);
            }

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"CacheDB", L"CacheDB initialized successfully");
            return true;
        }

        void CacheDB::Shutdown() {
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"CacheDB", L"Shutting down CacheDB...");

            // Flush pending writes
            DatabaseError err;
            FlushPendingWrites(&err);

            // Stop write-behind thread
            m_shutdownWriteBehind.store(true, std::memory_order_release);
            m_writeBehindCV.notify_all();

            if (m_writeBehindThread.joinable()) {
                m_writeBehindThread.join();
            }

            // Shutdown managers
            Utils::CacheManager::Instance().Shutdown();
            DatabaseManager::Instance().Shutdown();

            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"CacheDB", L"CacheDB shut down");
        }

        // ============================================================================
        // Basic Operations
        // ============================================================================

        bool CacheDB::Put(std::wstring_view key,
                         const uint8_t* data, size_t size,
                         std::chrono::milliseconds ttl,
                         DatabaseError* err)
        {
            if (key.empty() || !data || size == 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid parameters";
                }
                return false;
            }

            int64_t expireTimestamp = calculateExpireTimestamp(ttl);

            // Write to cache based on policy
            if (m_config.cachePolicy != CachePolicy::DatabaseOnly) {
                if (!cacheWrite(key, data, size, ttl)) {
                    SS_LOG_WARN(L"CacheDB", L"Cache write failed for key: %ls", key.data());
                }
            }

            // Write to database based on strategy
            bool dbSuccess = false;

            switch (m_config.writeStrategy) {
                case WriteStrategy::WriteThrough:
                    dbSuccess = dbWrite(key, data, size, expireTimestamp, err);
                    break;

                case WriteStrategy::WriteBack:
                    // Queue for async write
                    enqueuePendingWrite(std::wstring(key), 
                        std::vector<uint8_t>(data, data + size), 
                        expireTimestamp);
                    dbSuccess = true;
                    break;

                case WriteStrategy::WriteBehind:
                    // Queue for batched write
                    enqueuePendingWrite(std::wstring(key), 
                        std::vector<uint8_t>(data, data + size), 
                        expireTimestamp);
                    dbSuccess = true;
                    break;
            }

            if (dbSuccess) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.cacheWrites++;
                m_stats.dbWrites++;
            }

            return dbSuccess;
        }

        bool CacheDB::Put(std::wstring_view key,
                         const std::vector<uint8_t>& data,
                         std::chrono::milliseconds ttl,
                         DatabaseError* err)
        {
            return Put(key, data.data(), data.size(), ttl, err);
        }

        bool CacheDB::PutString(std::wstring_view key,
                               std::wstring_view value,
                               std::chrono::milliseconds ttl,
                               DatabaseError* err)
        {
            const uint8_t* data = reinterpret_cast<const uint8_t*>(value.data());
            size_t size = value.size() * sizeof(wchar_t);
            return Put(key, data, size, ttl, err);
        }

        bool CacheDB::Get(std::wstring_view key,
                         std::vector<uint8_t>& outData,
                         DatabaseError* err)
        {
            if (key.empty()) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid key";
                }
                return false;
            }

            outData.clear();

            auto startTime = std::chrono::steady_clock::now();

            // Try cache first based on policy
            bool cacheHit = false;
            if (m_config.cachePolicy == CachePolicy::CacheFirst || 
                m_config.cachePolicy == CachePolicy::CacheOnly) {
                
                cacheHit = cacheRead(key, outData);
                
                if (cacheHit) {
                    auto endTime = std::chrono::steady_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                    
                    updateStatistics(true, false);
                    
                    SS_LOG_DEBUG(L"CacheDB", L"Cache hit for key: %ls (took %lld ms)", 
                        key.data(), duration.count());
                    return true;
                }

                // Cache miss - try database if not cache-only
                if (m_config.cachePolicy == CachePolicy::CacheOnly) {
                    updateStatistics(false, false);
                    return false;
                }
            }

            // Try database
            int64_t expireTimestamp = 0;
            bool dbSuccess = dbRead(key, outData, expireTimestamp, err);

            if (dbSuccess) {
                // Check if expired
                if (isExpired(expireTimestamp)) {
                    dbRemove(key, nullptr);
                    outData.clear();
                    updateStatistics(false, true);
                    return false;
                }

                // Populate cache with DB data (cache-aside pattern)
                if (m_config.cachePolicy != CachePolicy::DatabaseOnly) {
                    int64_t nowTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    
                    std::chrono::milliseconds ttl = 
                        std::chrono::seconds(expireTimestamp - nowTimestamp);
                    
                    if (ttl.count() > 0) {
                        cacheWrite(key, outData.data(), outData.size(), ttl);
                    }
                }

                auto endTime = std::chrono::steady_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
                
                updateStatistics(false, true);
                
                SS_LOG_DEBUG(L"CacheDB", L"Database hit for key: %ls (took %lld ms)", 
                    key.data(), duration.count());
                return true;
            }

            updateStatistics(false, true);
            return false;
        }

        bool CacheDB::GetString(std::wstring_view key,
                               std::wstring& outValue,
                               DatabaseError* err)
        {
            std::vector<uint8_t> data;
            if (!Get(key, data, err)) {
                return false;
            }

            if (data.empty() || data.size() % sizeof(wchar_t) != 0) {
                if (err) {
                    err->sqliteCode = SQLITE_MISMATCH;
                    err->message = L"Invalid string data";
                }
                return false;
            }

            const wchar_t* wstr = reinterpret_cast<const wchar_t*>(data.data());
            size_t len = data.size() / sizeof(wchar_t);
            outValue.assign(wstr, len);

            return true;
        }

        bool CacheDB::Remove(std::wstring_view key, DatabaseError* err) {
            if (key.empty()) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Invalid key";
                }
                return false;
            }

            // Remove from cache
            cacheRemove(key);

            // Remove from database
            bool dbSuccess = dbRemove(key, err);

            if (dbSuccess) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.dbDeletes++;
            }

            return dbSuccess;
        }

        bool CacheDB::Contains(std::wstring_view key) const {
            if (key.empty()) return false;

            // Check cache first
            if (m_config.cachePolicy != CachePolicy::DatabaseOnly) {
                if (cacheContains(key)) {
                    return true;
                }
            }

            // Check database
            return const_cast<CacheDB*>(this)->dbExists(key);
        }

        void CacheDB::Clear() {
            SS_LOG_INFO(L"CacheDB", L"Clearing all cache entries...");

            // Clear memory cache
            Utils::CacheManager::Instance().Clear();

            // Clear database
            DatabaseError err;
            DatabaseManager::Instance().Execute("DELETE FROM cache_entries", &err);

            // Reset statistics
            ResetStatistics();

            SS_LOG_INFO(L"CacheDB", L"Cache cleared");
        }

        // ============================================================================
        // Advanced Operations
        // ============================================================================

        bool CacheDB::PutBatch(const std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& entries,
                              std::chrono::milliseconds ttl,
                              DatabaseError* err)
        {
            if (entries.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            int64_t expireTimestamp = calculateExpireTimestamp(ttl);

            for (const auto& [key, data] : entries) {
                // Write to cache
                if (m_config.cachePolicy != CachePolicy::DatabaseOnly) {
                    cacheWrite(key, data.data(), data.size(), ttl);
                }

                // Write to database
                if (!dbWrite(key, data.data(), data.size(), expireTimestamp, err)) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.cacheWrites += entries.size();
            m_stats.dbWrites += entries.size();

            SS_LOG_INFO(L"CacheDB", L"Batch put %zu entries", entries.size());
            return true;
        }

        bool CacheDB::GetBatch(const std::vector<std::wstring>& keys,
                              std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& results,
                              DatabaseError* err)
        {
            results.clear();
            results.reserve(keys.size());

            for (const auto& key : keys) {
                std::vector<uint8_t> data;
                if (Get(key, data, err)) {
                    results.emplace_back(key, std::move(data));
                }
            }

            return true;
        }

        bool CacheDB::RemoveBatch(const std::vector<std::wstring>& keys,
                                 DatabaseError* err)
        {
            if (keys.empty()) return true;

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            for (const auto& key : keys) {
                cacheRemove(key);
                
                if (!dbRemove(key, err)) {
                    trans->Rollback(err);
                    return false;
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.dbDeletes += keys.size();

            SS_LOG_INFO(L"CacheDB", L"Batch removed %zu entries", keys.size());
            return true;
        }

        std::vector<std::wstring> CacheDB::GetKeysByPrefix(std::wstring_view prefix,
                                                            size_t maxResults)
        {
            std::vector<std::wstring> keys;

            DatabaseError err;
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_BY_PREFIX,
                &err,
                ToUTF8(prefix),
                static_cast<int>(maxResults)
            );

            while (result.Next()) {
                keys.push_back(ToWide(result.GetString(0)));
            }

            return keys;
        }

        bool CacheDB::RemoveByPrefix(std::wstring_view prefix, DatabaseError* err) {
            // Get keys first
            auto keys = GetKeysByPrefix(prefix, 10000);

            // Remove from cache
            for (const auto& key : keys) {
                cacheRemove(key);
            }

            // Remove from database
            bool success = DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_BY_PREFIX,
                err,
                ToUTF8(prefix)
            );

            if (success) {
                std::lock_guard<std::mutex> lock(m_statsMutex);
                m_stats.dbDeletes += keys.size();
            }

            return success;
        }

        std::vector<std::wstring> CacheDB::GetKeysByPattern(std::wstring_view pattern,
                                                             size_t maxResults)
        {
            std::vector<std::wstring> keys;

            DatabaseError err;
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_BY_PATTERN,
                &err,
                ToUTF8(pattern),
                static_cast<int>(maxResults)
            );

            while (result.Next()) {
                keys.push_back(ToWide(result.GetString(0)));
            }

            return keys;
        }

        // ============================================================================
        // Cache Management
        // ============================================================================

        bool CacheDB::RefreshCache(DatabaseError* err) {
            SS_LOG_INFO(L"CacheDB", L"Refreshing cache from database...");

            // Clear current cache
            Utils::CacheManager::Instance().Clear();

            // Warm up again
            return WarmUpCache(m_config.warmupMaxEntries, err);
        }

        void CacheDB::InvalidateCache(std::wstring_view key) {
            cacheRemove(key);
        }

        void CacheDB::InvalidateAllCache() {
            Utils::CacheManager::Instance().Clear();
        }

        bool CacheDB::FlushPendingWrites(DatabaseError* err) {
            std::lock_guard<std::mutex> lock(m_writeBehindMutex);
            
            if (m_pendingWrites.empty()) {
                return true;
            }

            SS_LOG_INFO(L"CacheDB", L"Flushing %zu pending writes...", m_pendingWrites.size());

            bool success = processPendingWrites(err);

            if (success) {
                std::lock_guard<std::mutex> statsLock(m_statsMutex);
                m_stats.lastFlush = std::chrono::system_clock::now();
            }

            return success;
        }

        bool CacheDB::Sync(DatabaseError* err) {
            SS_LOG_INFO(L"CacheDB", L"Synchronizing cache with database...");

            // Flush pending writes
            if (!FlushPendingWrites(err)) {
                return false;
            }

            // Delete expired entries from database
            DatabaseManager::Instance().Execute(SQL_DELETE_EXPIRED, err);

            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats.lastSync = std::chrono::system_clock::now();

            SS_LOG_INFO(L"CacheDB", L"Sync completed");
            return true;
        }

        bool CacheDB::WarmUpCache(size_t maxEntries, DatabaseError* err) {
            if (maxEntries == 0) {
                maxEntries = m_config.warmupMaxEntries;
            }

            SS_LOG_INFO(L"CacheDB", L"Warming up cache with %zu entries...", maxEntries);

            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_TOP_N,
                err,
                static_cast<int>(maxEntries)
            );

            size_t loaded = 0;
            while (result.Next()) {
                std::wstring key = ToWide(result.GetString(0));
                std::vector<uint8_t> value = result.GetBlob(1);
                int64_t expireTimestamp = result.GetInt64(2);

                // Check if not expired
                if (!isExpired(expireTimestamp)) {
                    int64_t nowTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    
                    std::chrono::milliseconds ttl = 
                        std::chrono::seconds(expireTimestamp - nowTimestamp);

                    if (cacheWrite(key, value.data(), value.size(), ttl)) {
                        loaded++;
                    }
                }
            }

            SS_LOG_INFO(L"CacheDB", L"Cache warmed up with %zu entries", loaded);
            return true;
        }

        // ============================================================================
        // Statistics
        // ============================================================================

        CacheDB::Statistics CacheDB::GetStatistics() const {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            
            Statistics stats = m_stats;

            // Calculate hit rate
            uint64_t totalAccess = stats.cacheHits + stats.cacheMisses;
            if (totalAccess > 0) {
                stats.cacheHitRate = (static_cast<double>(stats.cacheHits) / totalAccess) * 100.0;
            }

            // Get current sizes
            auto cacheStats = Utils::CacheManager::Instance().GetStats();
            stats.currentCacheSize = cacheStats.totalBytes;
            stats.maxCacheSize = cacheStats.maxBytes;

            auto dbStats = DatabaseManager::Instance().GetStats();
            stats.dbSize = dbStats.totalSize;

            return stats;
        }

        void CacheDB::ResetStatistics() {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            m_stats = Statistics{};
        }

        CacheDB::Config CacheDB::GetConfig() const {
            std::shared_lock<std::shared_mutex> lock(m_configMutex);
            return m_config;
        }

        void CacheDB::SetWriteStrategy(WriteStrategy strategy) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.writeStrategy = strategy;
        }

        void CacheDB::SetCachePolicy(CachePolicy policy) {
            std::unique_lock<std::shared_mutex> lock(m_configMutex);
            m_config.cachePolicy = policy;
        }

        // ============================================================================
        // Maintenance
        // ============================================================================

        bool CacheDB::Vacuum(DatabaseError* err) {
            SS_LOG_INFO(L"CacheDB", L"Running VACUUM...");
            return DatabaseManager::Instance().Vacuum(err);
        }

        bool CacheDB::CheckIntegrity(DatabaseError* err) {
            SS_LOG_INFO(L"CacheDB", L"Checking database integrity...");
            std::vector<std::wstring> issues;
            return DatabaseManager::Instance().CheckIntegrity(issues, err);
        }

        bool CacheDB::Optimize(DatabaseError* err) {
            SS_LOG_INFO(L"CacheDB", L"Optimizing database...");
            
            // Delete expired entries
            DatabaseManager::Instance().Execute(SQL_DELETE_EXPIRED, err);
            
            // Optimize database
            return DatabaseManager::Instance().Optimize(err);
        }

        // ============================================================================
        // Internal Operations
        // ============================================================================

        bool CacheDB::dbWrite(std::wstring_view key,
                             const uint8_t* data, size_t size,
                             int64_t expireTimestamp,
                             DatabaseError* err)
        {
            std::string keyUtf8 = ToUTF8(key);
            std::vector<uint8_t> valueBlob(data, data + size);

            return DatabaseManager::Instance().ExecuteWithParams(
                SQL_INSERT_ENTRY,
                err,
                keyUtf8,
                valueBlob,
                expireTimestamp,
                keyUtf8  // For access_count increment
            );
        }

        bool CacheDB::dbRead(std::wstring_view key,
                            std::vector<uint8_t>& outData,
                            int64_t& outExpireTimestamp,
                            DatabaseError* err)
        {
            std::string keyUtf8 = ToUTF8(key);

            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_SELECT_ENTRY,
                err,
                keyUtf8
            );

            if (result.Next()) {
                outData = result.GetBlob(0);
                outExpireTimestamp = result.GetInt64(1);

                // Update access statistics
                DatabaseManager::Instance().ExecuteWithParams(
                    SQL_UPDATE_ACCESS,
                    nullptr,  // Ignore errors for stats update
                    keyUtf8
                );

                return true;
            }

            return false;
        }

        bool CacheDB::dbRemove(std::wstring_view key, DatabaseError* err) {
            return DatabaseManager::Instance().ExecuteWithParams(
                SQL_DELETE_ENTRY,
                err,
                ToUTF8(key)
            );
        }

        bool CacheDB::dbExists(std::wstring_view key) {
            DatabaseError err;
            auto result = DatabaseManager::Instance().QueryWithParams(
                SQL_EXISTS_ENTRY,
                &err,
                ToUTF8(key)
            );

            return result.Next();
        }

        bool CacheDB::cacheWrite(std::wstring_view key,
                                const uint8_t* data, size_t size,
                                std::chrono::milliseconds ttl)
        {
            return Utils::CacheManager::Instance().Put(
                std::wstring(key),
                data, size,
                ttl,
                false,  // Not persistent (DB is persistent layer)
                false   // Not sliding
            );
        }

        bool CacheDB::cacheRead(std::wstring_view key,
                               std::vector<uint8_t>& outData)
        {
            return Utils::CacheManager::Instance().Get(std::wstring(key), outData);
        }

        void CacheDB::cacheRemove(std::wstring_view key) {
            Utils::CacheManager::Instance().Remove(std::wstring(key));
        }

        bool CacheDB::cacheContains(std::wstring_view key) const {
            return Utils::CacheManager::Instance().Contains(std::wstring(key));
        }

        void CacheDB::writeBehindThread() {
            SS_LOG_INFO(L"CacheDB", L"Write-behind thread started");

            while (!m_shutdownWriteBehind.load(std::memory_order_acquire)) {
                std::unique_lock<std::mutex> lock(m_writeBehindMutex);

                // Wait for flush interval or shutdown
                m_writeBehindCV.wait_for(lock, m_config.writeBehindFlushInterval, [this]() {
                    return m_shutdownWriteBehind.load(std::memory_order_acquire) ||
                           m_pendingWrites.size() >= m_config.writeBehindBatchSize;
                });

                if (m_shutdownWriteBehind.load(std::memory_order_acquire)) {
                    break;
                }

                if (!m_pendingWrites.empty()) {
                    DatabaseError err;
                    processPendingWrites(&err);
                }
            }

            // Final flush on shutdown
            DatabaseError err;
            FlushPendingWrites(&err);

            SS_LOG_INFO(L"CacheDB", L"Write-behind thread stopped");
        }

        void CacheDB::enqueuePendingWrite(std::wstring key,
                                          std::vector<uint8_t> data,
                                          int64_t expireTimestamp)
        {
            std::lock_guard<std::mutex> lock(m_writeBehindMutex);

            PendingWrite write;
            write.key = std::move(key);
            write.data = std::move(data);
            write.expireTimestamp = expireTimestamp;
            write.queuedTime = std::chrono::steady_clock::now();

            m_pendingWrites.push_back(std::move(write));

            // Notify if batch size reached
            if (m_pendingWrites.size() >= m_config.writeBehindBatchSize) {
                m_writeBehindCV.notify_one();
            }
        }

        bool CacheDB::processPendingWrites(DatabaseError* err) {
            if (m_pendingWrites.empty()) {
                return true;
            }

            auto trans = DatabaseManager::Instance().BeginTransaction(
                Transaction::Type::Immediate, err);
            
            if (!trans || !trans->IsActive()) {
                return false;
            }

            size_t processed = 0;
            for (const auto& write : m_pendingWrites) {
                if (dbWrite(write.key, write.data.data(), write.data.size(), 
                           write.expireTimestamp, err)) {
                    processed++;
                } else {
                    SS_LOG_ERROR(L"CacheDB", L"Failed to write pending entry: %ls", write.key.c_str());
                }
            }

            if (!trans->Commit(err)) {
                return false;
            }

            m_pendingWrites.clear();

            SS_LOG_DEBUG(L"CacheDB", L"Processed %zu pending writes", processed);
            return true;
        }

        bool CacheDB::createSchema(DatabaseError* err) {
            // Create cache table
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_CACHE_TABLE, err)) {
                return false;
            }

            // Create indices
            if (!DatabaseManager::Instance().Execute(SQL_CREATE_INDICES, err)) {
                return false;
            }

            SS_LOG_INFO(L"CacheDB", L"Schema created successfully");
            return true;
        }

        bool CacheDB::upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err) {
            // Future schema migrations go here
            return true;
        }

        int64_t CacheDB::calculateExpireTimestamp(std::chrono::milliseconds ttl) const {
            auto now = std::chrono::system_clock::now();
            auto expireTime = now + ttl;
            return std::chrono::duration_cast<std::chrono::seconds>(
                expireTime.time_since_epoch()).count();
        }

        bool CacheDB::isExpired(int64_t expireTimestamp) const {
            auto now = std::chrono::system_clock::now();
            int64_t nowTimestamp = std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()).count();
            return expireTimestamp < nowTimestamp;
        }

        void CacheDB::updateStatistics(bool cacheHit, bool dbRead) {
            std::lock_guard<std::mutex> lock(m_statsMutex);

            if (cacheHit) {
                m_stats.cacheHits++;
            } else {
                m_stats.cacheMisses++;
            }

            if (dbRead) {
                m_stats.dbReads++;
            }
        }

        // ============================================================================
        // CacheDBTransaction Implementation
        // ============================================================================

        CacheDBTransaction::CacheDBTransaction(CacheDB& cache)
            : m_cache(cache)
            , m_active(true)
        {
        }

        CacheDBTransaction::~CacheDBTransaction() {
            if (m_active && !m_committed) {
                Rollback();
            }
        }

        bool CacheDBTransaction::Commit(DatabaseError* err) {
            if (!m_active) {
                if (err) {
                    err->sqliteCode = SQLITE_MISUSE;
                    err->message = L"Transaction not active";
                }
                return false;
            }

            // Flush any pending writes
            if (!m_cache.FlushPendingWrites(err)) {
                return false;
            }

            m_committed = true;
            m_active = false;
            return true;
        }

        void CacheDBTransaction::Rollback() {
            // For CacheDB, rollback means clearing cache
            // Database rollback is handled by DatabaseManager transactions
            m_active = false;
        }

    } // namespace Database
} // namespace ShadowStrike
