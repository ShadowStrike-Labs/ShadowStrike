#pragma once

#include "DatabaseManager.hpp"
#include "../Utils/CacheManager.hpp"
#include "../Utils/Logger.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <mutex>
#include <shared_mutex>

namespace ShadowStrike {
    namespace Database {

        // ============================================================================
        // CacheDB - Hybrid In-Memory + Database Caching System
        // ============================================================================

        /**
         * @brief Hybrid caching system combining fast in-memory cache (CacheManager) 
         *        with persistent database storage (DatabaseManager).
         * 
         * Features:
         * - Two-tier caching: Memory cache for speed, DB for persistence
         * - Automatic cache warming from database on startup
         * - Write-through and write-behind strategies
         * - Cache invalidation and refresh
         * - Statistics and monitoring
         * - Thread-safe operations
         */
        class CacheDB {
        public:
            // ============================================================================
            // Configuration
            // ============================================================================

            enum class WriteStrategy {
                WriteThrough,    // Write to both cache and DB immediately (slower, safer)
                WriteBack,       // Write to cache immediately, DB asynchronously (faster, less safe)
                WriteBehind      // Write to cache, batch DB writes (fastest, least safe)
            };

            enum class CachePolicy {
                CacheFirst,      // Try cache first, fallback to DB
                DatabaseFirst,   // Try DB first, populate cache
                CacheOnly,       // Only use memory cache (no DB reads)
                DatabaseOnly     // Only use database (no caching)
            };

            struct Config {
                // Memory cache settings
                std::wstring cachePath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\Cache";
                size_t maxCacheEntries = 100000;
                size_t maxCacheBytes = 256ULL * 1024 * 1024;  // 256MB
                std::chrono::milliseconds defaultTTL = std::chrono::hours(24);
                std::chrono::milliseconds maintenanceInterval = std::chrono::minutes(1);

                // Database settings
                std::wstring dbPath = L"C:\\ProgramData\\Bitdefender\\ShadowStrike\\cache.db";
                bool enableWAL = true;
                size_t dbCacheSizeKB = 20480;  // 20MB
                
                // Strategy settings
                WriteStrategy writeStrategy = WriteStrategy::WriteThrough;
                CachePolicy cachePolicy = CachePolicy::CacheFirst;
                
                // Write-behind settings
                size_t writeBehindBatchSize = 100;
                std::chrono::milliseconds writeBehindFlushInterval = std::chrono::seconds(5);
                
                // Warm-up settings
                bool warmupOnStartup = true;
                size_t warmupMaxEntries = 10000;
                
                // Statistics
                bool enableStatistics = true;
            };

            struct Statistics {
                // Cache stats
                uint64_t cacheHits = 0;
                uint64_t cacheMisses = 0;
                uint64_t cacheWrites = 0;
                uint64_t cacheEvictions = 0;
                
                // Database stats
                uint64_t dbReads = 0;
                uint64_t dbWrites = 0;
                uint64_t dbDeletes = 0;
                
                // Performance
                double cacheHitRate = 0.0;
                std::chrono::milliseconds avgCacheReadTime{};
                std::chrono::milliseconds avgDbReadTime{};
                
                // Memory usage
                size_t currentCacheSize = 0;
                size_t maxCacheSize = 0;
                size_t dbSize = 0;
                
                // Timing
                std::chrono::system_clock::time_point lastSync;
                std::chrono::system_clock::time_point lastFlush;
            };

            // ============================================================================
            // Lifecycle
            // ============================================================================

            static CacheDB& Instance();

            bool Initialize(const Config& config, DatabaseError* err = nullptr);
            void Shutdown();
            bool IsInitialized() const noexcept { return m_initialized.load(); }

            // ============================================================================
            // Basic Operations
            // ============================================================================

            // Put data (binary)
            bool Put(std::wstring_view key,
                     const uint8_t* data, size_t size,
                     std::chrono::milliseconds ttl = std::chrono::hours(24),
                     DatabaseError* err = nullptr);

            bool Put(std::wstring_view key,
                     const std::vector<uint8_t>& data,
                     std::chrono::milliseconds ttl = std::chrono::hours(24),
                     DatabaseError* err = nullptr);

            // Put string (UTF-16)
            bool PutString(std::wstring_view key,
                          std::wstring_view value,
                          std::chrono::milliseconds ttl = std::chrono::hours(24),
                          DatabaseError* err = nullptr);

            // Get data (binary)
            bool Get(std::wstring_view key,
                    std::vector<uint8_t>& outData,
                    DatabaseError* err = nullptr);

            // Get string (UTF-16)
            bool GetString(std::wstring_view key,
                          std::wstring& outValue,
                          DatabaseError* err = nullptr);

            // Remove entry
            bool Remove(std::wstring_view key, DatabaseError* err = nullptr);

            // Check existence
            bool Contains(std::wstring_view key) const;

            // Clear all entries
            void Clear();

            // ============================================================================
            // Advanced Operations
            // ============================================================================

            // Batch operations
            bool PutBatch(const std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& entries,
                         std::chrono::milliseconds ttl = std::chrono::hours(24),
                         DatabaseError* err = nullptr);

            bool GetBatch(const std::vector<std::wstring>& keys,
                         std::vector<std::pair<std::wstring, std::vector<uint8_t>>>& results,
                         DatabaseError* err = nullptr);

            bool RemoveBatch(const std::vector<std::wstring>& keys,
                            DatabaseError* err = nullptr);

            // Prefix operations
            std::vector<std::wstring> GetKeysByPrefix(std::wstring_view prefix,
                                                       size_t maxResults = 1000);

            bool RemoveByPrefix(std::wstring_view prefix, DatabaseError* err = nullptr);

            // Pattern matching (SQL LIKE)
            std::vector<std::wstring> GetKeysByPattern(std::wstring_view pattern,
                                                        size_t maxResults = 1000);

            // ============================================================================
            // Cache Management
            // ============================================================================

            // Refresh cache from database
            bool RefreshCache(DatabaseError* err = nullptr);
            
            // Invalidate specific key in cache
            void InvalidateCache(std::wstring_view key);
            
            // Invalidate all cache entries
            void InvalidateAllCache();

            // Force flush pending writes to database
            bool FlushPendingWrites(DatabaseError* err = nullptr);

            // Synchronize cache with database
            bool Sync(DatabaseError* err = nullptr);

            // Warm up cache from database
            bool WarmUpCache(size_t maxEntries = 0, DatabaseError* err = nullptr);

            // ============================================================================
            // Configuration & Statistics
            // ============================================================================

            Statistics GetStatistics() const;
            void ResetStatistics();

            Config GetConfig() const;
            void SetWriteStrategy(WriteStrategy strategy);
            void SetCachePolicy(CachePolicy policy);

            // ============================================================================
            // Maintenance
            // ============================================================================

            bool Vacuum(DatabaseError* err = nullptr);
            bool CheckIntegrity(DatabaseError* err = nullptr);
            bool Optimize(DatabaseError* err = nullptr);

        private:
            CacheDB();
            ~CacheDB();

            CacheDB(const CacheDB&) = delete;
            CacheDB& operator=(const CacheDB&) = delete;

            // ============================================================================
            // Internal Operations
            // ============================================================================

            // Database operations
            bool dbWrite(std::wstring_view key, 
                        const uint8_t* data, size_t size,
                        int64_t expireTimestamp,
                        DatabaseError* err);

            bool dbRead(std::wstring_view key,
                       std::vector<uint8_t>& outData,
                       int64_t& outExpireTimestamp,
                       DatabaseError* err);

            bool dbRemove(std::wstring_view key, DatabaseError* err);
            bool dbExists(std::wstring_view key);

            // Cache operations
            bool cacheWrite(std::wstring_view key,
                          const uint8_t* data, size_t size,
                          std::chrono::milliseconds ttl);

            bool cacheRead(std::wstring_view key,
                          std::vector<uint8_t>& outData);

            void cacheRemove(std::wstring_view key);
            bool cacheContains(std::wstring_view key) const;

            // Write-behind support
            void writeBehindThread();
            void enqueuePendingWrite(std::wstring key,
                                    std::vector<uint8_t> data,
                                    int64_t expireTimestamp);
            bool processPendingWrites(DatabaseError* err);

            // Schema management
            bool createSchema(DatabaseError* err);
            bool upgradeSchema(int currentVersion, int targetVersion, DatabaseError* err);

            // Utilities
            int64_t calculateExpireTimestamp(std::chrono::milliseconds ttl) const;
            bool isExpired(int64_t expireTimestamp) const;
            void updateStatistics(bool cacheHit, bool dbRead);

            // ============================================================================
            // State
            // ============================================================================

            std::atomic<bool> m_initialized{ false };
            Config m_config;
            mutable std::shared_mutex m_configMutex;

            // Write-behind queue
            struct PendingWrite {
                std::wstring key;
                std::vector<uint8_t> data;
                int64_t expireTimestamp;
                std::chrono::steady_clock::time_point queuedTime;
            };

            std::mutex m_writeBehindMutex;
            std::condition_variable m_writeBehindCV;
            std::vector<PendingWrite> m_pendingWrites;
            std::thread m_writeBehindThread;
            std::atomic<bool> m_shutdownWriteBehind{ false };

            // Statistics
            mutable std::mutex m_statsMutex;
            Statistics m_stats;
        };

        // ============================================================================
        // RAII Helper for Batch Operations
        // ============================================================================

        class CacheDBTransaction {
        public:
            explicit CacheDBTransaction(CacheDB& cache);
            ~CacheDBTransaction();

            CacheDBTransaction(const CacheDBTransaction&) = delete;
            CacheDBTransaction& operator=(const CacheDBTransaction&) = delete;

            bool Commit(DatabaseError* err = nullptr);
            void Rollback();

            bool IsActive() const noexcept { return m_active; }

        private:
            CacheDB& m_cache;
            bool m_active = false;
            bool m_committed = false;
        };

    } // namespace Database
} // namespace ShadowStrike
