/*
 * ============================================================================
 * ShadowStrike Cache Manager
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade in-memory cache with disk persistence:
 *   - Thread-safe LRU eviction policy
 *   - Configurable memory and entry count limits
 *   - Optional TTL with absolute or sliding expiration
 *   - Persistent storage with HMAC-SHA256 integrity (falls back to FNV-1a)
 *   - Atomic disk operations with crash recovery
 *   - Background maintenance thread for expired entry cleanup
 *
 * Thread Safety:
 *   - All public methods are thread-safe
 *   - Uses SRWLock for reader-writer synchronization
 *   - Separate locks for memory operations and disk I/O
 *
 * Security Considerations:
 *   - HMAC key generation via BCryptGenRandom
 *   - Path traversal protection in disk operations
 *   - Secure key zeroing on shutdown
 *   - Input validation on all public methods
 *
 * ============================================================================
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <list>
#include <thread>
#include <limits>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "Logger.hpp"

namespace ShadowStrike {
    namespace Utils {

        /**
         * @brief Thread-safe LRU cache with optional disk persistence.
         * 
         * Singleton pattern - use Instance() to access.
         * Must call Initialize() before use and Shutdown() before process exit.
         */
        class CacheManager final {
        public:
            // ================================================================
            // Public Types
            // ================================================================

            /**
             * @brief Cache statistics snapshot.
             * 
             * All values are consistent as of the time GetStats() was called.
             */
            struct Stats final {
                size_t entryCount = 0;                                  ///< Current number of entries
                size_t totalBytes = 0;                                  ///< Current memory usage
                size_t maxEntries = 0;                                  ///< Configured entry limit (0 = unlimited)
                size_t maxBytes = 0;                                    ///< Configured byte limit (0 = unlimited)
                std::chrono::system_clock::time_point lastMaintenance{}; ///< Last maintenance cycle time
            };

            // ================================================================
            // Singleton Access
            // ================================================================

            /**
             * @brief Get the singleton instance.
             * @return Reference to the global CacheManager instance.
             * 
             * Thread Safety: Thread-safe (static initialization).
             */
            static CacheManager& Instance();

            // ================================================================
            // Lifecycle Management
            // ================================================================

            /**
             * @brief Initialize the cache manager.
             * 
             * Must be called before any cache operations. Idempotent if already
             * initialized and running. If previously shutdown, reinitializes.
             * 
             * @param baseDir Base directory for persistent storage.
             *                Empty string uses %ProgramData%\ShadowStrike\Cache.
             * @param maxEntries Maximum number of entries (0 = unlimited).
             * @param maxBytes Maximum memory usage in bytes (0 = unlimited, minimum 1024 if set).
             * @param maintenanceInterval Interval between maintenance cycles (minimum 1 second).
             * 
             * Thread Safety: Thread-safe but should typically be called once at startup.
             */
            void Initialize(
                const std::wstring& baseDir = L"",
                size_t maxEntries = 100000,
                size_t maxBytes = 256 * 1024 * 1024,
                std::chrono::milliseconds maintenanceInterval = std::chrono::minutes(1)
            );

            /**
             * @brief Shutdown the cache manager.
             * 
             * Stops maintenance thread, waits for pending disk operations,
             * clears all entries, and securely zeros sensitive data.
             * 
             * Thread Safety: Thread-safe. Safe to call multiple times.
             */
            void Shutdown();

            // ================================================================
            // Cache Operations
            // ================================================================

            /**
             * @brief Store binary data in the cache.
             * 
             * @param key Unique key (non-empty, max 2048 wchar_t).
             * @param data Pointer to data (nullptr allowed if size == 0).
             * @param size Data size in bytes (max 100MB).
             * @param ttl Time-to-live (minimum 1 second, maximum 30 days).
             * @param persistent If true, data is written to disk.
             * @param sliding If true, TTL resets on each access.
             * @return true on success, false on failure.
             * 
             * Thread Safety: Thread-safe.
             */
            [[nodiscard]] bool Put(
                const std::wstring& key,
                const uint8_t* data,
                size_t size,
                std::chrono::milliseconds ttl,
                bool persistent = false,
                bool sliding = false
            );

            /**
             * @brief Store vector data in the cache.
             * @see Put(const std::wstring&, const uint8_t*, size_t, std::chrono::milliseconds, bool, bool)
             */
            [[nodiscard]] bool Put(
                const std::wstring& key,
                const std::vector<uint8_t>& data,
                std::chrono::milliseconds ttl,
                bool persistent = false,
                bool sliding = false
            ) {
                // Handle empty vector safely - data() may return nullptr
                const uint8_t* p = data.empty() ? nullptr : data.data();
                return Put(key, p, data.size(), ttl, persistent, sliding);
            }

            /**
             * @brief Store a wide string in the cache.
             * 
             * Stores the raw UTF-16 bytes of the string.
             * 
             * @param key Unique key.
             * @param value String value to store.
             * @param ttl Time-to-live.
             * @param persistent If true, data is written to disk.
             * @param sliding If true, TTL resets on each access.
             * @return true on success, false on failure.
             */
            [[nodiscard]] bool PutStringW(
                const std::wstring& key,
                const std::wstring& value,
                std::chrono::milliseconds ttl,
                bool persistent = false,
                bool sliding = false
            ) {
                // Empty string is valid - store zero bytes
                if (value.empty()) {
                    return Put(key, nullptr, 0, ttl, persistent, sliding);
                }
                const uint8_t* p = reinterpret_cast<const uint8_t*>(value.data());
                const size_t cb = value.size() * sizeof(wchar_t);
                return Put(key, p, cb, ttl, persistent, sliding);
            }

            /**
             * @brief Retrieve binary data from the cache.
             * 
             * If the entry exists and is not expired, copies data to outData.
             * If sliding expiration is enabled, resets the TTL.
             * 
             * @param key Key to look up.
             * @param outData Output vector (cleared on call, populated on success).
             * @return true if found and not expired, false otherwise.
             * 
             * Thread Safety: Thread-safe.
             */
            [[nodiscard]] bool Get(const std::wstring& key, std::vector<uint8_t>& outData);

            /**
             * @brief Retrieve a wide string from the cache.
             * 
             * @param key Key to look up.
             * @param outValue Output string (cleared on call, populated on success).
             * @return true if found and valid UTF-16, false otherwise.
             */
            [[nodiscard]] bool GetStringW(const std::wstring& key, std::wstring& outValue) {
                std::vector<uint8_t> buf;
                if (!Get(key, buf)) {
                    outValue.clear();
                    return false;
                }
                // Validate alignment for wchar_t
                if ((buf.size() % sizeof(wchar_t)) != 0) {
                    outValue.clear();
                    return false;
                }
                // Safe even if buf is empty (size / sizeof(wchar_t) == 0)
                const wchar_t* begin = reinterpret_cast<const wchar_t*>(buf.data());
                const size_t charCount = buf.size() / sizeof(wchar_t);
                outValue.assign(begin, begin + charCount);
                return true;
            }

            /**
             * @brief Remove an entry from the cache.
             * 
             * Removes from both memory and disk (if persistent).
             * 
             * @param key Key to remove.
             * @return true if entry existed and was removed, false if not found.
             */
            [[nodiscard]] bool Remove(const std::wstring& key);

            /**
             * @brief Clear all entries from the cache.
             * 
             * Removes all entries from memory and deletes all cache files from disk.
             * 
             * Thread Safety: Thread-safe.
             */
            void Clear();

            /**
             * @brief Check if a key exists and is not expired.
             * 
             * @param key Key to check.
             * @return true if key exists and is not expired.
             */
            [[nodiscard]] bool Contains(const std::wstring& key) const;

            // ================================================================
            // Configuration
            // ================================================================

            /**
             * @brief Set maximum entry count.
             * 
             * If current count exceeds new limit, triggers eviction.
             * 
             * @param maxEntries New limit (0 = unlimited).
             */
            void SetMaxEntries(size_t maxEntries);

            /**
             * @brief Set maximum memory usage.
             * 
             * If current usage exceeds new limit, triggers eviction.
             * 
             * @param maxBytes New limit in bytes (0 = unlimited).
             */
            void SetMaxBytes(size_t maxBytes);

            /**
             * @brief Get current cache statistics.
             * @return Snapshot of cache statistics.
             */
            [[nodiscard]] Stats GetStats() const;

        private:
            // ================================================================
            // Private Types
            // ================================================================

            /**
             * @brief Internal cache entry structure.
             */
            struct Entry final {
                std::wstring key;                           ///< Cache key
                std::vector<uint8_t> value;                 ///< Cached data
                FILETIME expire{};                          ///< Absolute expiration time (FILETIME)
                std::chrono::milliseconds ttl{0};           ///< TTL duration (for sliding expiration)
                bool sliding = false;                       ///< Whether TTL slides on access
                bool persistent = false;                    ///< Whether entry is disk-backed
                size_t sizeBytes = 0;                       ///< Calculated memory footprint
                std::list<std::wstring>::iterator lruIt{};  ///< Position in LRU list

                Entry() = default;
                ~Entry() = default;
                Entry(const Entry&) = default;
                Entry& operator=(const Entry&) = default;
                Entry(Entry&&) noexcept = default;
                Entry& operator=(Entry&&) noexcept = default;
            };

            /**
             * @brief RAII wrapper for exclusive SRWLock acquisition.
             */
            class SRWExclusive final {
            public:
                explicit SRWExclusive(SRWLOCK& lock) noexcept : m_lock(lock) {
                    AcquireSRWLockExclusive(&m_lock);
                }
                ~SRWExclusive() noexcept {
                    ReleaseSRWLockExclusive(&m_lock);
                }
                SRWExclusive(const SRWExclusive&) = delete;
                SRWExclusive& operator=(const SRWExclusive&) = delete;
                SRWExclusive(SRWExclusive&&) = delete;
                SRWExclusive& operator=(SRWExclusive&&) = delete;
            private:
                SRWLOCK& m_lock;
            };

            /**
             * @brief RAII wrapper for shared SRWLock acquisition.
             */
            class SRWShared final {
            public:
                explicit SRWShared(SRWLOCK& lock) noexcept : m_lock(lock) {
                    AcquireSRWLockShared(&m_lock);
                }
                ~SRWShared() noexcept {
                    ReleaseSRWLockShared(&m_lock);
                }
                SRWShared(const SRWShared&) = delete;
                SRWShared& operator=(const SRWShared&) = delete;
                SRWShared(SRWShared&&) = delete;
                SRWShared& operator=(SRWShared&&) = delete;
            private:
                SRWLOCK& m_lock;
            };

            // ================================================================
            // Constructor / Destructor (Singleton)
            // ================================================================

            CacheManager();
            ~CacheManager();

            CacheManager(const CacheManager&) = delete;
            CacheManager& operator=(const CacheManager&) = delete;
            CacheManager(CacheManager&&) = delete;
            CacheManager& operator=(CacheManager&&) = delete;

            // ================================================================
            // Maintenance Thread
            // ================================================================

            void maintenanceThread();
            void performMaintenance();

            // ================================================================
            // Eviction and Expiration (called with m_lock held)
            // ================================================================

            void evictIfNeeded_NoLock();
            void removeExpired_NoLock(std::vector<std::wstring>& removedKeys);
            [[nodiscard]] bool isExpired_NoLock(const Entry& e, const FILETIME& now) const noexcept;

            // ================================================================
            // LRU Management (called with m_lock held)
            // ================================================================

            void touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& e);

            // ================================================================
            // Persistence Helpers
            // ================================================================

            [[nodiscard]] bool ensureBaseDir();
            [[nodiscard]] bool ensureSubdirForHash(const std::wstring& hex2);
            [[nodiscard]] bool persistWrite(const std::wstring& key, const Entry& e);
            [[nodiscard]] bool persistRead(const std::wstring& key, Entry& out);
            [[nodiscard]] bool persistRemoveByKey(const std::wstring& key);
            [[nodiscard]] std::wstring pathForKeyHex(const std::wstring& hex) const;

            // ================================================================
            // Hash Helpers
            // ================================================================

            [[nodiscard]] std::wstring hashKeyToHex(const std::wstring& key) const;

            // ================================================================
            // Time Helpers
            // ================================================================

            [[nodiscard]] static FILETIME nowFileTime() noexcept;
            [[nodiscard]] static bool fileTimeLessOrEqual(const FILETIME& a, const FILETIME& b) noexcept;

            // ================================================================
            // Initialization Helpers
            // ================================================================

            void loadPersistentEntries();

            // ================================================================
            // Member Variables
            // ================================================================

            // Configuration (set during Initialize, read during operation)
            std::wstring m_baseDir;                                         ///< Base directory for cache files
            size_t m_maxEntries = 0;                                        ///< Max entry count (0 = unlimited)
            size_t m_maxBytes = 0;                                          ///< Max memory (0 = unlimited)

            // Synchronization primitives
            mutable SRWLOCK m_lock{};                                       ///< Protects m_map, m_lru, m_totalBytes
            mutable SRWLOCK m_diskLock{};                                   ///< Protects disk operations

            // In-memory cache data (protected by m_lock)
            std::unordered_map<std::wstring, std::shared_ptr<Entry>> m_map; ///< Key -> Entry mapping
            std::list<std::wstring> m_lru;                                  ///< LRU order (front = most recent)
            size_t m_totalBytes = 0;                                        ///< Current memory usage

            // Thread management (atomic for lock-free access)
            std::atomic<bool> m_shutdown{false};                            ///< Shutdown flag
            std::thread m_maintThread;                                      ///< Background maintenance thread
            std::chrono::milliseconds m_maintInterval{std::chrono::minutes(1)}; ///< Maintenance interval
            std::atomic<uint64_t> m_lastMaint{0};                           ///< Last maintenance timestamp

            // Disk I/O tracking
            std::atomic<size_t> m_pendingDiskOps{0};                        ///< Count of in-flight disk ops

            // Security
            std::vector<uint8_t> m_hmacKey;                                 ///< HMAC key for cache file integrity

            // ================================================================
            // Constants
            // ================================================================

            static constexpr size_t kMaxKeySize = 2048;                     ///< Max key length in wchar_t
            static constexpr size_t kMaxValueSize = 100ULL * 1024 * 1024;   ///< Max value size (100MB)
            static constexpr auto kMaxTTL = std::chrono::hours(24 * 30);    ///< Max TTL (30 days)
            static constexpr auto kMinTTL = std::chrono::seconds(1);        ///< Min TTL (1 second)
            static constexpr size_t kMaxEvictionsPerCycle = 10000;          ///< Safety limit for eviction loop
        };

    } // namespace Utils
} // namespace ShadowStrike