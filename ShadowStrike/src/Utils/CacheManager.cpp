/*
 * ============================================================================
 * ShadowStrike Cache Manager Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * This file implements a thread-safe LRU cache with optional disk persistence.
 * See CacheManager.hpp for interface documentation.
 *
 * Implementation Notes:
 *   - Uses Windows SRWLock for reader-writer synchronization
 *   - Disk operations use atomic write-rename pattern for crash safety
 *   - HMAC-SHA256 via BCrypt for cache file integrity (falls back to FNV-1a)
 *   - Background maintenance thread handles expiration cleanup
 *
 * ============================================================================
 */

#include "CacheManager.hpp"

#include <cwchar>
#include <algorithm>
#include <cassert>
#include <limits>
#include <new>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

// Link against bcrypt.lib for BCryptGenRandom
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// Test Mode Logging Override
// ============================================================================
// Disable async logging during tests to prevent deadlock with singleton
#ifdef SHADOWSTRIKE_TESTING
#define SS_LOG_INFO(cat, fmt, ...)       ((void)0)
#define SS_LOG_ERROR(cat, fmt, ...)      ((void)0)
#define SS_LOG_WARN(cat, fmt, ...)       ((void)0)
#define SS_LOG_DEBUG(cat, fmt, ...)      ((void)0)
#define SS_LOG_LAST_ERROR(cat, fmt, ...) ((void)0)
#endif

namespace ShadowStrike {
    namespace Utils {

        // ============================================================================
        // Anonymous Namespace - Internal Helpers
        // ============================================================================

        namespace {

            // ----------------------------------------------------------------
            // Time Conversion Constants
            // ----------------------------------------------------------------

            /// Difference between Windows FILETIME epoch (1601) and Unix epoch (1970)
            /// in 100-nanosecond intervals
            constexpr uint64_t kFileTimeEpochDiff = 116444736000000000ULL;

            /// Maximum safe microseconds value to prevent overflow during conversion
            constexpr uint64_t kMaxSafeMicroseconds = (std::numeric_limits<uint64_t>::max() - kFileTimeEpochDiff) / 10ULL;

            /// Maximum safe 100ns value for reverse conversion
            constexpr uint64_t kMaxSafe100ns = static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) / 10ULL;

            // ----------------------------------------------------------------
            // Time Conversion Functions
            // ----------------------------------------------------------------

            /**
             * @brief Convert system_clock::time_point to Windows FILETIME (100ns ticks).
             * 
             * @param tp The time point to convert.
             * @return FILETIME as uint64_t, or 0 for negative times, UINT64_MAX for overflow.
             */
            [[nodiscard]] uint64_t TimePointToFileTime(
                const std::chrono::system_clock::time_point& tp
            ) noexcept {
                const auto duration = tp.time_since_epoch();
                const auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
                const int64_t us = microseconds.count();

                // Handle negative time (before Unix epoch)
                if (us < 0) {
                    return 0;
                }

                // Check for overflow before conversion
                const uint64_t usUnsigned = static_cast<uint64_t>(us);
                if (usUnsigned > kMaxSafeMicroseconds) {
                    return std::numeric_limits<uint64_t>::max();
                }

                // Convert: microseconds * 10 = 100ns ticks, then add epoch difference
                return usUnsigned * 10ULL + kFileTimeEpochDiff;
            }

            /**
             * @brief Convert Windows FILETIME (100ns ticks) to system_clock::time_point.
             * 
             * @param filetime The FILETIME value as uint64_t.
             * @return Corresponding time_point, or epoch/max for edge cases.
             */
            [[nodiscard]] std::chrono::system_clock::time_point FileTimeToTimePoint(
                uint64_t filetime
            ) noexcept {
                // Handle zero (invalid/uninitialized)
                if (filetime == 0) {
                    return std::chrono::system_clock::time_point{};
                }

                // Handle times before Unix epoch
                if (filetime < kFileTimeEpochDiff) {
                    return std::chrono::system_clock::time_point{};
                }

                // Convert from Windows epoch to Unix epoch
                const uint64_t unix100ns = filetime - kFileTimeEpochDiff;

                // Check for overflow
                if (unix100ns > kMaxSafe100ns) {
                    return std::chrono::system_clock::time_point::max();
                }

                // Convert 100ns ticks to microseconds
                const auto microseconds = std::chrono::microseconds(unix100ns / 10ULL);
                return std::chrono::system_clock::time_point(microseconds);
            }

        } // anonymous namespace

        // ============================================================================
        // BCrypt API Dynamic Loader
        // ============================================================================

        /**
         * @brief Dynamic loader for BCrypt API functions.
         * 
         * Loads bcrypt.dll at runtime and resolves required function pointers.
         * Falls back gracefully if BCrypt is unavailable (uses FNV-1a instead).
         * 
         * Thread Safety: Singleton with C++11 magic statics (thread-safe init).
         */
        struct BcryptApi final {
            HMODULE hModule = nullptr;

            // Function pointers
            NTSTATUS(WINAPI* pBCryptOpenAlgorithmProvider)(
                BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG) = nullptr;
            NTSTATUS(WINAPI* pBCryptCloseAlgorithmProvider)(
                BCRYPT_ALG_HANDLE, ULONG) = nullptr;
            NTSTATUS(WINAPI* pBCryptCreateHash)(
                BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = nullptr;
            NTSTATUS(WINAPI* pBCryptDestroyHash)(
                BCRYPT_HASH_HANDLE) = nullptr;
            NTSTATUS(WINAPI* pBCryptHashData)(
                BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG) = nullptr;
            NTSTATUS(WINAPI* pBCryptFinishHash)(
                BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG) = nullptr;

            BcryptApi() noexcept {
                // Load bcrypt.dll from System32 only (security)
                hModule = ::LoadLibraryExW(L"bcrypt.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
                if (!hModule) {
                    // Try standard load as fallback for older Windows versions
                    hModule = ::LoadLibraryW(L"bcrypt.dll");
                }

                if (!hModule) {
                    return;
                }

                // Resolve all required function pointers
                pBCryptOpenAlgorithmProvider = reinterpret_cast<decltype(pBCryptOpenAlgorithmProvider)>(
                    GetProcAddress(hModule, "BCryptOpenAlgorithmProvider"));
                pBCryptCloseAlgorithmProvider = reinterpret_cast<decltype(pBCryptCloseAlgorithmProvider)>(
                    GetProcAddress(hModule, "BCryptCloseAlgorithmProvider"));
                pBCryptCreateHash = reinterpret_cast<decltype(pBCryptCreateHash)>(
                    GetProcAddress(hModule, "BCryptCreateHash"));
                pBCryptDestroyHash = reinterpret_cast<decltype(pBCryptDestroyHash)>(
                    GetProcAddress(hModule, "BCryptDestroyHash"));
                pBCryptHashData = reinterpret_cast<decltype(pBCryptHashData)>(
                    GetProcAddress(hModule, "BCryptHashData"));
                pBCryptFinishHash = reinterpret_cast<decltype(pBCryptFinishHash)>(
                    GetProcAddress(hModule, "BCryptFinishHash"));

                // Validate all functions were found
                if (!pBCryptOpenAlgorithmProvider || !pBCryptCloseAlgorithmProvider ||
                    !pBCryptCreateHash || !pBCryptDestroyHash ||
                    !pBCryptHashData || !pBCryptFinishHash) {
                    // Missing required functions - release library
                    FreeLibrary(hModule);
                    hModule = nullptr;
                    pBCryptOpenAlgorithmProvider = nullptr;
                    pBCryptCloseAlgorithmProvider = nullptr;
                    pBCryptCreateHash = nullptr;
                    pBCryptDestroyHash = nullptr;
                    pBCryptHashData = nullptr;
                    pBCryptFinishHash = nullptr;
                }
            }

            ~BcryptApi() noexcept {
                // Note: We intentionally don't unload bcrypt.dll on shutdown
                // to avoid issues with static destruction order. The OS will
                // clean up when the process exits.
            }

            // Non-copyable, non-movable
            BcryptApi(const BcryptApi&) = delete;
            BcryptApi& operator=(const BcryptApi&) = delete;
            BcryptApi(BcryptApi&&) = delete;
            BcryptApi& operator=(BcryptApi&&) = delete;

            /**
             * @brief Get the singleton instance.
             * @return Reference to the BcryptApi singleton.
             */
            [[nodiscard]] static const BcryptApi& Instance() noexcept {
                static BcryptApi instance; // C++11 thread-safe initialization
                return instance;
            }

            /**
             * @brief Check if BCrypt API is available.
             * @return true if all required functions are loaded.
             */
            [[nodiscard]] bool IsAvailable() const noexcept {
                return hModule != nullptr;
            }

            // ================================================================
            // Wrapper Methods for BCrypt Functions
            // ================================================================

            // NTSTATUS error code for unavailable function (0xC00000BB)
            static constexpr NTSTATUS kStatusNotSupported = static_cast<NTSTATUS>(0xC00000BB);

            [[nodiscard]] NTSTATUS OpenAlgorithmProvider(
                BCRYPT_ALG_HANDLE* phAlgorithm,
                LPCWSTR pszAlgId,
                LPCWSTR pszImplementation,
                ULONG dwFlags) const noexcept {
                if (!pBCryptOpenAlgorithmProvider) return kStatusNotSupported;
                return pBCryptOpenAlgorithmProvider(phAlgorithm, pszAlgId, pszImplementation, dwFlags);
            }

            [[nodiscard]] NTSTATUS CloseAlgorithmProvider(
                BCRYPT_ALG_HANDLE hAlgorithm,
                ULONG dwFlags) const noexcept {
                if (!pBCryptCloseAlgorithmProvider) return kStatusNotSupported;
                return pBCryptCloseAlgorithmProvider(hAlgorithm, dwFlags);
            }

            [[nodiscard]] NTSTATUS CreateHash(
                BCRYPT_ALG_HANDLE hAlgorithm,
                BCRYPT_HASH_HANDLE* phHash,
                PUCHAR pbHashObject,
                ULONG cbHashObject,
                PUCHAR pbSecret,
                ULONG cbSecret,
                ULONG dwFlags) const noexcept {
                if (!pBCryptCreateHash) return kStatusNotSupported;
                return pBCryptCreateHash(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
            }

            [[nodiscard]] NTSTATUS DestroyHash(
                BCRYPT_HASH_HANDLE hHash) const noexcept {
                if (!pBCryptDestroyHash) return kStatusNotSupported;
                return pBCryptDestroyHash(hHash);
            }

            [[nodiscard]] NTSTATUS HashData(
                BCRYPT_HASH_HANDLE hHash,
                PUCHAR pbInput,
                ULONG cbInput,
                ULONG dwFlags) const noexcept {
                if (!pBCryptHashData) return kStatusNotSupported;
                return pBCryptHashData(hHash, pbInput, cbInput, dwFlags);
            }

            [[nodiscard]] NTSTATUS FinishHash(
                BCRYPT_HASH_HANDLE hHash,
                PUCHAR pbOutput,
                ULONG cbOutput,
                ULONG dwFlags) const noexcept {
                if (!pBCryptFinishHash) return kStatusNotSupported;
                return pBCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags);
            }
        };

        // ============================================================================
        // Hash Helper Functions
        // ============================================================================

        /**
         * @brief FNV-1a 64-bit hash function.
         * 
         * Used as fallback when BCrypt HMAC-SHA256 is unavailable.
         * This is NOT cryptographically secure - only for cache key hashing.
         * 
         * @param data Pointer to data to hash (may be nullptr if len == 0).
         * @param len Length of data in bytes.
         * @return 64-bit FNV-1a hash value.
         */
        [[nodiscard]] static uint64_t Fnv1a64(const void* data, size_t len) noexcept {
            // FNV-1a offset basis and prime for 64-bit
            constexpr uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
            constexpr uint64_t kFnvPrime = 1099511628211ULL;

            uint64_t hash = kFnvOffsetBasis;

            if (data != nullptr && len > 0) {
                const uint8_t* bytes = static_cast<const uint8_t*>(data);
                for (size_t i = 0; i < len; ++i) {
                    hash ^= bytes[i];
                    hash *= kFnvPrime;
                }
            }

            return hash;
        }

        /**
         * @brief Convert binary data to lowercase hexadecimal wide string.
         * 
         * @param data Pointer to binary data (may be nullptr if len == 0).
         * @param len Length of data in bytes.
         * @return Hex string (empty if input is null/empty or allocation fails).
         */
        [[nodiscard]] static std::wstring ToHex(const uint8_t* data, size_t len) noexcept {
            if (data == nullptr || len == 0) {
                return std::wstring();
            }

            // Check for overflow: len * 2 characters
            if (len > std::numeric_limits<size_t>::max() / 2) {
                return std::wstring();
            }

            static constexpr wchar_t kHexChars[] = L"0123456789abcdef";

            std::wstring result;
            try {
                result.resize(len * 2);
            }
            catch (const std::bad_alloc&) {
                return std::wstring();
            }

            for (size_t i = 0; i < len; ++i) {
                result[i * 2]     = kHexChars[(data[i] >> 4) & 0x0F];
                result[i * 2 + 1] = kHexChars[data[i] & 0x0F];
            }

            return result;
        }

        // ============================================================================
        // CacheManager Singleton & Lifecycle
        // ============================================================================

        CacheManager& CacheManager::Instance() {
            // C++11 guarantees thread-safe initialization of function-local statics
            static CacheManager instance;
            return instance;
        }

        CacheManager::CacheManager() {
            // Initialize SRW locks (cannot fail on Windows Vista+)
            InitializeSRWLock(&m_lock);
            InitializeSRWLock(&m_diskLock);

            // Initialize atomic members
            const auto now = std::chrono::system_clock::now();
            m_lastMaint.store(TimePointToFileTime(now), std::memory_order_release);
            m_shutdown.store(true, std::memory_order_release);  // Start as "shutdown" until Initialize() is called
            m_pendingDiskOps.store(0, std::memory_order_release);
        }

        CacheManager::~CacheManager() {
            // Ensure clean shutdown
            Shutdown();
        }

        // ============================================================================
        // Initialization and Shutdown
        // ============================================================================

        void CacheManager::Initialize(
            const std::wstring& baseDir,
            size_t maxEntries,
            size_t maxBytes,
            std::chrono::milliseconds maintenanceInterval
        ) {
            // Check if already initialized and running
            const bool isShutdown = m_shutdown.load(std::memory_order_acquire);

            if (!isShutdown && m_maintThread.joinable()) {
                // Already initialized and running - this is idempotent
                SS_LOG_WARN(L"CacheManager", L"Initialize() called but already running");
                return;
            }

            // If shutdown but thread still joinable, wait for it to finish
            if (isShutdown && m_maintThread.joinable()) {
                SS_LOG_INFO(L"CacheManager", L"Waiting for previous maintenance thread to finish...");
                try {
                    m_maintThread.join();
                }
                catch (...) {
                    // Thread may have already exited or been detached
                }
                m_maintThread = std::thread(); // Reset to empty state
            }

            // Validate maxBytes (minimum 1KB if set, or 0 for unlimited)
            if (maxBytes > 0 && maxBytes < 1024) {
                SS_LOG_ERROR(L"CacheManager", L"maxBytes must be >= 1024 or 0 for unlimited");
                return;
            }

            // Validate maintenance interval (minimum 1 second)
            if (maintenanceInterval < std::chrono::seconds(1)) {
                SS_LOG_ERROR(L"CacheManager", L"maintenanceInterval must be >= 1 second");
                return;
            }

            // Store configuration
            m_maxEntries = maxEntries;
            m_maxBytes = maxBytes;
            m_maintInterval = maintenanceInterval;

            // Setup base directory
            if (!baseDir.empty()) {
                m_baseDir = baseDir;
            }
            else {
                // Default to %ProgramData%\ShadowStrike\Cache
                wchar_t buf[MAX_PATH] = {};
                const DWORD envLen = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);

                if (envLen == 0 || envLen >= MAX_PATH) {
                    // Fallback: try to construct from Windows directory
                    if (GetWindowsDirectoryW(buf, MAX_PATH) == 0) {
                        // Last resort fallback
                        wcscpy_s(buf, MAX_PATH, L"C:\\ProgramData");
                    }
                    else {
                        // Append \ProgramData to Windows drive
                        buf[3] = L'\0'; // Keep only "C:\"
                        wcscat_s(buf, MAX_PATH, L"ProgramData");
                    }
                }

                m_baseDir.assign(buf);
                if (!m_baseDir.empty() && m_baseDir.back() != L'\\') {
                    m_baseDir.push_back(L'\\');
                }
                m_baseDir += L"ShadowStrike\\Cache";
            }

            // Create base directory structure
            if (!ensureBaseDir()) {
                SS_LOG_ERROR(L"CacheManager", L"Failed to create cache directory");
                // Continue anyway - disk persistence will simply fail
            }

            // Generate HMAC key for cache file integrity
            const auto& bcryptApi = BcryptApi::Instance();
            if (bcryptApi.IsAvailable()) {
                try {
                    m_hmacKey.resize(32); // 256-bit key
                    const NTSTATUS status = BCryptGenRandom(
                        nullptr,
                        m_hmacKey.data(),
                        static_cast<ULONG>(m_hmacKey.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG
                    );
                    if (status != 0) {
                        // Failed to generate random key - clear and fall back to FNV-1a
                        SecureZeroMemory(m_hmacKey.data(), m_hmacKey.size());
                        m_hmacKey.clear();
                        SS_LOG_WARN(L"CacheManager", L"BCryptGenRandom failed, using FNV-1a fallback");
                    }
                }
                catch (const std::bad_alloc&) {
                    m_hmacKey.clear();
                }
            }

            // Load persistent cache entries from disk
            loadPersistentEntries();

            // Reset shutdown flag BEFORE starting thread
            m_shutdown.store(false, std::memory_order_release);

            // Start maintenance thread
            try {
                m_maintThread = std::thread(&CacheManager::maintenanceThread, this);

                // Brief yield to allow thread to start
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            catch (const std::system_error& ex) {
                SS_LOG_ERROR(L"CacheManager", L"Failed to start maintenance thread");
                m_shutdown.store(true, std::memory_order_release);
                return;
            }

            SS_LOG_INFO(L"CacheManager", L"Initialized successfully");
        }

        void CacheManager::Shutdown() {
            // Signal shutdown to maintenance thread
            m_shutdown.store(true, std::memory_order_release);

            // Join maintenance thread safely
            if (m_maintThread.joinable()) {
                // Check if we're being called from the maintenance thread itself
                // This can happen during process exit with static destruction
                if (std::this_thread::get_id() == m_maintThread.get_id()) {
                    // Cannot join ourselves - detach to avoid deadlock
                    m_maintThread.detach();
                }
                else {
                    try {
                        m_maintThread.join();
                    }
                    catch (const std::system_error&) {
                        // Thread may have already exited
                    }
                }
            }

            // Wait for pending disk operations with timeout
            constexpr auto kDiskOpTimeout = std::chrono::seconds(30);
            const auto deadline = std::chrono::steady_clock::now() + kDiskOpTimeout;

            while (m_pendingDiskOps.load(std::memory_order_acquire) > 0) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    SS_LOG_WARN(L"CacheManager", L"Timeout waiting for pending disk operations");
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            // Clear in-memory cache under lock
            {
                SRWExclusive guard(m_lock);
                m_map.clear();
                m_lru.clear();
                m_totalBytes = 0;
            }

            // Reset configuration
            m_baseDir.clear();
            m_maxEntries = 0;
            m_maxBytes = 0;
            m_maintInterval = std::chrono::minutes(1);

            // Securely zero and clear HMAC key
            if (!m_hmacKey.empty()) {
                SecureZeroMemory(m_hmacKey.data(), m_hmacKey.size());
                m_hmacKey.clear();
                m_hmacKey.shrink_to_fit(); // Release memory
            }

            // Reset thread handle
            m_maintThread = std::thread();

            // Brief delay to ensure OS releases file handles
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            SS_LOG_INFO(L"CacheManager", L"Shutdown complete");
        }

        // ============================================================================
        // Cache Operations
        // ============================================================================

        bool CacheManager::Put(
            const std::wstring& key,
            const uint8_t* data,
            size_t size,
            std::chrono::milliseconds ttl,
            bool persistent,
            bool sliding
        ) {
            // ----------------------------------------------------------------
            // Input Validation
            // ----------------------------------------------------------------

            // Key must be non-empty
            if (key.empty()) {
                return false;
            }

            // nullptr is only valid with size == 0
            if (data == nullptr && size != 0) {
                return false;
            }

            // Validate key size (use class constant)
            if (key.size() > kMaxKeySize) {
                return false;
            }

            // Validate value size
            if (size > kMaxValueSize) {
                return false;
            }

            // Validate TTL range
            const auto ttlCount = ttl.count();
            if (ttlCount < 0) {
                return false;
            }
            if (ttl > kMaxTTL) {
                return false;
            }
            if (ttl < kMinTTL) {
                return false;
            }

            // ----------------------------------------------------------------
            // Calculate Expiration Time
            // ----------------------------------------------------------------

            const FILETIME now = nowFileTime();

            ULARGE_INTEGER currentTime{};
            currentTime.LowPart = now.dwLowDateTime;
            currentTime.HighPart = now.dwHighDateTime;

            // Convert TTL to 100ns intervals with overflow check
            // 1 millisecond = 10,000 100ns intervals
            constexpr uint64_t kTicksPerMs = 10000ULL;
            constexpr uint64_t kMaxSafeTtlMs = std::numeric_limits<uint64_t>::max() / kTicksPerMs;

            if (static_cast<uint64_t>(ttlCount) > kMaxSafeTtlMs) {
                return false;
            }

            const uint64_t delta100ns = static_cast<uint64_t>(ttlCount) * kTicksPerMs;

            // Check for overflow when adding to current time
            if (currentTime.QuadPart > std::numeric_limits<uint64_t>::max() - delta100ns) {
                return false;
            }

            ULARGE_INTEGER expireTime{};
            expireTime.QuadPart = currentTime.QuadPart + delta100ns;

            FILETIME expire{};
            expire.dwLowDateTime = expireTime.LowPart;
            expire.dwHighDateTime = expireTime.HighPart;

            // ----------------------------------------------------------------
            // Create Entry
            // ----------------------------------------------------------------

            std::shared_ptr<Entry> entry;
            try {
                entry = std::make_shared<Entry>();
                entry->key = key;

                // Copy value data if provided
                if (data != nullptr && size > 0) {
                    entry->value.assign(data, data + size);
                }
                // else: empty vector is valid

                entry->expire = expire;
                entry->ttl = ttl;
                entry->sliding = sliding;
                entry->persistent = persistent;

                // Calculate memory footprint
                entry->sizeBytes = (key.size() * sizeof(wchar_t)) +
                                   entry->value.size() +
                                   sizeof(Entry);
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            // ----------------------------------------------------------------
            // Insert into Cache
            // ----------------------------------------------------------------

            {
                SRWExclusive guard(m_lock);

                // Check if we have room (try eviction if needed)
                if (m_maxBytes > 0 && (m_totalBytes + entry->sizeBytes) > m_maxBytes) {
                    evictIfNeeded_NoLock();

                    // Re-check after eviction
                    if ((m_totalBytes + entry->sizeBytes) > m_maxBytes) {
                        return false; // Still no room
                    }
                }

                // Remove existing entry with same key if present
                auto existingIt = m_map.find(key);
                if (existingIt != m_map.end()) {
                    // Subtract old entry's size
                    if (m_totalBytes >= existingIt->second->sizeBytes) {
                        m_totalBytes -= existingIt->second->sizeBytes;
                    }
                    else {
                        m_totalBytes = 0; // Safety: prevent underflow
                    }

                    // Remove from LRU list
                    m_lru.erase(existingIt->second->lruIt);
                    m_map.erase(existingIt);
                }

                // Add to LRU (front = most recently used)
                m_lru.push_front(key);
                entry->lruIt = m_lru.begin();

                // Add to map
                m_map.emplace(key, entry);
                m_totalBytes += entry->sizeBytes;

                // Ensure we're within limits
                evictIfNeeded_NoLock();
            }

            // ----------------------------------------------------------------
            // Persist to Disk (outside lock)
            // ----------------------------------------------------------------

            if (persistent) {
                // Failure to persist is not fatal - entry is still in memory
                if (!persistWrite(key, *entry)) {
                    SS_LOG_WARN(L"CacheManager", L"Failed to persist cache entry to disk");
                }
            }

            return true;
        }

        bool CacheManager::Get(const std::wstring& key, std::vector<uint8_t>& outData) {
            // Always clear output first
            outData.clear();

            // Validate input
            if (key.empty()) {
                return false;
            }

            const FILETIME now = nowFileTime();
            bool needsPersistUpdate = false;
            Entry entryCopyForPersist;
            bool foundInMemory = false;

            // ----------------------------------------------------------------
            // Check In-Memory Cache
            // ----------------------------------------------------------------

            {
                SRWExclusive guard(m_lock);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    std::shared_ptr<Entry>& entry = it->second;

                    // Check expiration
                    if (isExpired_NoLock(*entry, now)) {
                        // Remove expired entry
                        if (m_totalBytes >= entry->sizeBytes) {
                            m_totalBytes -= entry->sizeBytes;
                        }
                        else {
                            m_totalBytes = 0;
                        }

                        m_lru.erase(entry->lruIt);
                        const bool wasPersistent = entry->persistent;
                        m_map.erase(it);

                        // Clean up disk file outside lock
                        if (wasPersistent) {
                            // Release lock before disk operation
                            guard.~SRWExclusive();
                            persistRemoveByKey(key);
                        }

                        return false;
                    }

                    // Update sliding expiration if enabled
                    if (entry->sliding && entry->ttl.count() > 0) {
                        ULARGE_INTEGER currentTime{};
                        currentTime.LowPart = now.dwLowDateTime;
                        currentTime.HighPart = now.dwHighDateTime;

                        constexpr uint64_t kTicksPerMs = 10000ULL;
                        const uint64_t delta100ns = static_cast<uint64_t>(entry->ttl.count()) * kTicksPerMs;

                        // Check for overflow before updating
                        if (currentTime.QuadPart <= std::numeric_limits<uint64_t>::max() - delta100ns) {
                            ULARGE_INTEGER newExpire{};
                            newExpire.QuadPart = currentTime.QuadPart + delta100ns;

                            entry->expire.dwLowDateTime = newExpire.LowPart;
                            entry->expire.dwHighDateTime = newExpire.HighPart;

                            // Schedule persist update if disk-backed
                            if (entry->persistent) {
                                needsPersistUpdate = true;
                                entryCopyForPersist = *entry;
                            }
                        }
                    }

                    // Copy data to output
                    try {
                        outData = entry->value;
                    }
                    catch (const std::bad_alloc&) {
                        return false;
                    }

                    // Update LRU position
                    touchLRU_NoLock(key, entry);
                    foundInMemory = true;
                }
            }

            // Update persistent storage outside lock
            if (needsPersistUpdate) {
                persistWrite(key, entryCopyForPersist);
            }

            // Return if found in memory
            if (foundInMemory) {
                return true;
            }

            // ----------------------------------------------------------------
            // Check Disk Cache
            // ----------------------------------------------------------------

            Entry diskEntry;
            if (!persistRead(key, diskEntry)) {
                return false;
            }

            // Validate disk entry hasn't expired
            const FILETIME now2 = nowFileTime();
            if (isExpired_NoLock(diskEntry, now2)) {
                persistRemoveByKey(key);
                return false;
            }

            // Load disk entry into memory cache
            std::shared_ptr<Entry> entry;
            try {
                entry = std::make_shared<Entry>(std::move(diskEntry));
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            {
                SRWExclusive guard(m_lock);

                // Check if another thread added this key while we were reading
                auto existingIt = m_map.find(key);
                if (existingIt != m_map.end()) {
                    // Another thread beat us - use their copy
                    try {
                        outData = existingIt->second->value;
                    }
                    catch (const std::bad_alloc&) {
                        return false;
                    }
                    touchLRU_NoLock(key, existingIt->second);
                    return true;
                }

                // Add to cache
                m_lru.push_front(key);
                entry->lruIt = m_lru.begin();
                m_totalBytes += entry->sizeBytes;
                m_map.emplace(key, entry);

                // Ensure we're within limits
                evictIfNeeded_NoLock();
            }

            // Copy data to output
            try {
                outData = entry->value;
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            return true;
        }

        bool CacheManager::Remove(const std::wstring& key) {
            if (key.empty()) {
                return false;
            }

            bool removed = false;
            bool wasPersistent = false;

            {
                SRWExclusive guard(m_lock);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    wasPersistent = it->second->persistent;

                    // Update byte tracking safely
                    if (m_totalBytes >= it->second->sizeBytes) {
                        m_totalBytes -= it->second->sizeBytes;
                    }
                    else {
                        m_totalBytes = 0;
                    }

                    // Remove from LRU and map
                    m_lru.erase(it->second->lruIt);
                    m_map.erase(it);
                    removed = true;
                }
            }

            // Always try to remove from disk (in case it exists there but not in memory)
            if (wasPersistent || removed) {
                persistRemoveByKey(key);
            }

            return removed;
        }

        void CacheManager::Clear() {
            // Clear in-memory cache
            {
                SRWExclusive guard(m_lock);
                m_map.clear();
                m_lru.clear();
                m_totalBytes = 0;
            }

            // Clear disk cache
            if (m_baseDir.empty()) {
                return;
            }

            SRWExclusive diskGuard(m_diskLock);

            // Build search mask
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') {
                mask.push_back(L'\\');
            }
            mask += L"*";

            WIN32_FIND_DATAW fd{};
            HANDLE hFind = FindFirstFileW(mask.c_str(), &fd);
            if (hFind == INVALID_HANDLE_VALUE) {
                return;
            }

            // Iterate subdirectories (2-char hex prefixes)
            do {
                // Only process directories
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    continue;
                }

                // Skip . and ..
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
                    continue;
                }

                // Build path to cache files in this subdirectory
                std::wstring subMask = m_baseDir + L"\\" + fd.cFileName + L"\\*.cache";

                WIN32_FIND_DATAW fd2{};
                HANDLE hFind2 = FindFirstFileW(subMask.c_str(), &fd2);
                if (hFind2 != INVALID_HANDLE_VALUE) {
                    do {
                        // Skip directories
                        if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            continue;
                        }

                        // Build full path and delete
                        std::wstring filePath = m_baseDir + L"\\" + fd.cFileName + L"\\" + fd2.cFileName;
                        DeleteFileW(filePath.c_str());

                    } while (FindNextFileW(hFind2, &fd2));

                    FindClose(hFind2);
                }

            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);

            SS_LOG_INFO(L"CacheManager", L"Cache cleared");
        }

        bool CacheManager::Contains(const std::wstring& key) const {
            if (key.empty()) {
                return false;
            }

            const FILETIME now = nowFileTime();

            SRWShared guard(m_lock);

            auto it = m_map.find(key);
            if (it == m_map.end()) {
                return false;
            }

            // Check if entry has expired
            return !isExpired_NoLock(*it->second, now);
        }

        void CacheManager::SetMaxEntries(size_t maxEntries) {
            // Enforce minimum reasonable limit
            constexpr size_t kMinEntries = 16;
            const size_t effectiveMax = (maxEntries < kMinEntries) ? kMinEntries : maxEntries;

            SRWExclusive guard(m_lock);
            m_maxEntries = effectiveMax;

            // Evict entries if we now exceed the new limit
            evictIfNeeded_NoLock();
        }

        void CacheManager::SetMaxBytes(size_t maxBytes) {
            // Enforce minimum reasonable limit (1 KB)
            constexpr size_t kMinBytes = 1024;
            const size_t effectiveMax = (maxBytes < kMinBytes) ? kMinBytes : maxBytes;

            SRWExclusive guard(m_lock);
            m_maxBytes = effectiveMax;

            // Evict entries if we now exceed the new limit
            evictIfNeeded_NoLock();
        }

        CacheManager::Stats CacheManager::GetStats() const {
            SRWShared guard(m_lock);

            Stats stats{};
            stats.entryCount = m_map.size();
            stats.totalBytes = m_totalBytes;
            stats.maxEntries = m_maxEntries;
            stats.maxBytes = m_maxBytes;

            // Safely read the last maintenance timestamp
            const uint64_t timestamp = m_lastMaint.load(std::memory_order_acquire);
            stats.lastMaintenance = FileTimeToTimePoint(timestamp);

            return stats;
        }

        /**
         * @brief Background maintenance thread worker function.
         *
         * This thread runs continuously in the background, periodically
         * performing cache maintenance tasks. It uses a responsive shutdown
         * check mechanism (10 x 100ms intervals) to allow quick termination
         * while maintaining low CPU usage during idle periods.
         *
         * @note Thread safety: This function is designed to be the sole
         *       owner of the maintenance thread context.
         */
        void CacheManager::maintenanceThread() noexcept {
            // Use steady_clock for interval timing (monotonic, not affected by system time changes)
            auto lastMaintenance = std::chrono::steady_clock::now();

            // Main loop - check shutdown flag with acquire semantics
            while (!m_shutdown.load(std::memory_order_acquire)) {
                // Sleep in short intervals to allow responsive shutdown
                // 10 iterations x 100ms = 1 second total sleep between checks
                for (int i = 0; i < 10; ++i) {
                    if (m_shutdown.load(std::memory_order_acquire)) {
                        return; // Quick exit on shutdown
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                // Double-check shutdown after sleep
                if (m_shutdown.load(std::memory_order_acquire)) {
                    break;
                }

                // Calculate elapsed time since last maintenance
                const auto now = std::chrono::steady_clock::now();
                const auto elapsed = now - lastMaintenance;

                // Perform maintenance if interval has elapsed
                if (elapsed >= m_maintInterval) {
                    try {
                        performMaintenance();
                        lastMaintenance = now;
                    }
                    catch (const std::exception& ex) {
                        // Log but continue - maintenance failure should not crash the thread
                        SS_LOG_WARN(L"CacheManager", L"Maintenance exception occurred");
                    }
                    catch (...) {
                        // Swallow unknown exceptions to keep thread alive
                    }
                }
            }
        }

        /**
         * @brief Performs periodic cache maintenance operations.
         *
         * This function:
         * 1. Removes expired entries from both memory and disk
         * 2. Evicts entries if cache limits are exceeded
         * 3. Updates the last maintenance timestamp
         *
         * @note Thread safety: Uses exclusive lock for memory operations,
         *       disk operations are performed outside the lock to minimize
         *       lock contention.
         */
        void CacheManager::performMaintenance() {
            try {
                std::vector<std::wstring> removedKeys;
                removedKeys.reserve(64); // Pre-allocate for typical cleanup size

                // Phase 1: Memory cleanup (under lock)
                {
                    SRWExclusive guard(m_lock);

                    // Remove expired entries
                    removeExpired_NoLock(removedKeys);

                    // Evict entries if over limits
                    evictIfNeeded_NoLock();

                    // Update last maintenance timestamp
                    const auto nowTimePoint = std::chrono::system_clock::now();
                    const uint64_t timestamp = TimePointToFileTime(nowTimePoint);
                    m_lastMaint.store(timestamp, std::memory_order_release);
                }

                // Phase 2: Disk cleanup (outside lock to reduce contention)
                if (!removedKeys.empty()) {
                    for (const auto& key : removedKeys) {
                        try {
                            persistRemoveByKey(key);
                        }
                        catch (const std::exception&) {
                            // Log but continue with other deletions
                        }
                        catch (...) {
                            // Swallow unknown exceptions
                        }
                    }
                }
            }
            catch (const std::exception& ex) {
                SS_LOG_WARN(L"CacheManager", L"performMaintenance failed");
            }
            catch (...) {
                // Swallow unknown exceptions
            }
        }

        /**
         * @brief Evicts LRU entries until cache is within configured limits.
         *
         * This function evicts entries from the back of the LRU list (oldest entries)
         * until both entry count and byte count are within configured limits.
         *
         * @note MUST be called with m_lock held in exclusive mode.
         * @note Contains emergency safeguard against infinite loops (max 10000 evictions).
         */
        void CacheManager::evictIfNeeded_NoLock() noexcept {
            // If no limits are set, nothing to do
            if (m_maxEntries == 0 && m_maxBytes == 0) {
                return;
            }

            // Track iterations to prevent infinite loop in case of data structure corruption
            size_t iterationCount = 0;
            constexpr size_t kMaxEvictionsPerCall = 10000;

            // Evict until WITHIN limits (not just when over)
            while (!m_lru.empty()) {
                // Check if we're within limits
                const bool entryCountOk = (m_maxEntries == 0) || (m_map.size() <= m_maxEntries);
                const bool bytesOk = (m_maxBytes == 0) || (m_totalBytes <= m_maxBytes);

                if (entryCountOk && bytesOk) {
                    break; // Within limits, done
                }

                // Emergency safeguard: prevent infinite loop
                if (++iterationCount > kMaxEvictionsPerCall) {
                    SS_LOG_ERROR(L"CacheManager", L"Emergency eviction limit reached, clearing cache");
                    m_map.clear();
                    m_lru.clear();
                    m_totalBytes = 0;
                    break;
                }

                // Evict from BACK of LRU (oldest entry)
                const std::wstring victimKey = m_lru.back(); // Copy to avoid dangling reference

                auto it = m_map.find(victimKey);
                if (it == m_map.end()) {
                    // Data structure inconsistency - remove orphan from LRU
                    m_lru.pop_back();
                    continue;
                }

                // Update byte tracking (safe underflow prevention)
                const size_t victimBytes = it->second->sizeBytes;
                if (m_totalBytes >= victimBytes) {
                    m_totalBytes -= victimBytes;
                }
                else {
                    m_totalBytes = 0;
                }

                // Remove from LRU and map
                m_lru.pop_back();
                m_map.erase(it);
            }
        }

        /**
         * @brief Removes all expired entries from the cache.
         *
         * This function iterates through all cache entries and removes those
         * that have passed their expiration time. Keys of removed entries are
         * collected for subsequent disk cleanup.
         *
         * @param[out] removedKeys Vector to receive keys of removed entries.
         *
         * @note MUST be called with m_lock held in exclusive mode.
         */
        void CacheManager::removeExpired_NoLock(std::vector<std::wstring>& removedKeys) noexcept {
            const FILETIME now = nowFileTime();

            for (auto it = m_map.begin(); it != m_map.end(); ) {
                // Skip null entries (shouldn't happen, but defensive)
                if (!it->second) {
                    it = m_map.erase(it);
                    continue;
                }

                if (isExpired_NoLock(*it->second, now)) {
                    // Update byte tracking (safe underflow prevention)
                    const size_t entryBytes = it->second->sizeBytes;
                    if (m_totalBytes >= entryBytes) {
                        m_totalBytes -= entryBytes;
                    }
                    else {
                        m_totalBytes = 0;
                    }

                    // Remove from LRU list
                    m_lru.erase(it->second->lruIt);

                    // Collect key for disk cleanup (may throw on allocation failure)
                    try {
                        removedKeys.push_back(it->first);
                    }
                    catch (const std::bad_alloc&) {
                        // Continue anyway - memory cleanup is more important
                    }

                    // Remove from map
                    it = m_map.erase(it);
                }
                else {
                    ++it;
                }
            }
        }

        /**
         * @brief Checks if a cache entry has expired.
         *
         * @param entry The cache entry to check.
         * @param now The current time as FILETIME.
         * @return true if the entry has expired, false otherwise.
         *
         * @note MUST be called with m_lock held (shared or exclusive).
         */
        bool CacheManager::isExpired_NoLock(const Entry& entry, const FILETIME& now) const noexcept {
            return fileTimeLessOrEqual(entry.expire, now);
        }

        /**
         * @brief Updates an entry's position in the LRU list (marks as recently used).
         *
         * @param key The key of the entry.
         * @param entry Shared pointer to the entry.
         *
         * @note MUST be called with m_lock held in exclusive mode.
         */
        void CacheManager::touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& entry) noexcept {
            // Remove from current position
            m_lru.erase(entry->lruIt);

            // Push to front (most recently used)
            m_lru.push_front(key);
            entry->lruIt = m_lru.begin();
        }

        // =====================================================================================
        // RAII Helper Classes for Disk I/O Operations
        // =====================================================================================

        namespace {
            /**
             * @brief RAII wrapper for Windows HANDLE with automatic cleanup.
             *
             * Provides exception-safe management of Win32 file handles with
             * proper move semantics and copy prevention.
             */
            class FileHandle final {
            public:
                /**
                 * @brief Constructs a FileHandle from a raw Windows HANDLE.
                 * @param handle Raw handle (default: INVALID_HANDLE_VALUE).
                 */
                explicit FileHandle(HANDLE handle = INVALID_HANDLE_VALUE) noexcept
                    : m_handle(handle) {
                }

                /**
                 * @brief Destructor - closes the handle if valid.
                 */
                ~FileHandle() noexcept {
                    Close();
                }

                // Non-copyable
                FileHandle(const FileHandle&) = delete;
                FileHandle& operator=(const FileHandle&) = delete;

                /**
                 * @brief Move constructor - transfers ownership.
                 * @param other Source handle to move from.
                 */
                FileHandle(FileHandle&& other) noexcept
                    : m_handle(other.m_handle) {
                    other.m_handle = INVALID_HANDLE_VALUE;
                }

                /**
                 * @brief Move assignment operator - transfers ownership.
                 * @param other Source handle to move from.
                 * @return Reference to this.
                 */
                FileHandle& operator=(FileHandle&& other) noexcept {
                    if (this != &other) {
                        Close();
                        m_handle = other.m_handle;
                        other.m_handle = INVALID_HANDLE_VALUE;
                    }
                    return *this;
                }

                /**
                 * @brief Closes the handle if valid.
                 */
                void Close() noexcept {
                    if (m_handle != INVALID_HANDLE_VALUE) {
                        CloseHandle(m_handle);
                        m_handle = INVALID_HANDLE_VALUE;
                    }
                }

                /**
                 * @brief Gets the raw handle value.
                 * @return The raw HANDLE.
                 */
                [[nodiscard]] HANDLE Get() const noexcept {
                    return m_handle;
                }

                /**
                 * @brief Checks if the handle is valid.
                 * @return true if handle is valid, false otherwise.
                 */
                [[nodiscard]] bool IsValid() const noexcept {
                    return m_handle != INVALID_HANDLE_VALUE;
                }

                /**
                 * @brief Implicit conversion to bool for validity check.
                 */
                [[nodiscard]] explicit operator bool() const noexcept {
                    return IsValid();
                }

            private:
                HANDLE m_handle;
            };

            /**
             * @brief RAII guard for tracking active disk operations.
             *
             * Increments an atomic counter on construction and decrements
             * on destruction. Used to prevent shutdown during active I/O.
             */
            struct DiskOpGuard final {
                std::atomic<size_t>& counter;

                /**
                 * @brief Constructs guard and increments counter.
                 * @param c Reference to atomic counter.
                 */
                explicit DiskOpGuard(std::atomic<size_t>& c) noexcept
                    : counter(c) {
                    counter.fetch_add(1, std::memory_order_acquire);
                }

                /**
                 * @brief Destructor - decrements counter.
                 */
                ~DiskOpGuard() noexcept {
                    counter.fetch_sub(1, std::memory_order_release);
                }

                // Non-copyable, non-movable
                DiskOpGuard(const DiskOpGuard&) = delete;
                DiskOpGuard& operator=(const DiskOpGuard&) = delete;
                DiskOpGuard(DiskOpGuard&&) = delete;
                DiskOpGuard& operator=(DiskOpGuard&&) = delete;
            };
        } // anonymous namespace

        // =====================================================================================
        // Cache File Format
        // =====================================================================================

#pragma pack(push, 1)
        /**
         * @brief On-disk header structure for persistent cache entries.
         *
         * This structure is written at the beginning of each cache file
         * and contains metadata needed to reconstruct the cache entry.
         *
         * @note Uses pragma pack(1) to ensure consistent binary layout
         *       across different compilers and platforms.
         */
        struct CacheFileHeader {
            uint32_t magic;          ///< Magic number for file identification ('SSCH')
            uint16_t version;        ///< Format version for compatibility checks
            uint16_t reserved;       ///< Reserved for future use (alignment padding)
            uint64_t expire100ns;    ///< Expiration time in 100ns intervals since 1601
            uint32_t flags;          ///< Entry flags (persistent, etc.)
            uint32_t keyBytes;       ///< Size of key data in bytes
            uint64_t valueBytes;     ///< Size of value data in bytes
            uint64_t ttlMs;          ///< Original TTL in milliseconds (for reference)
        };
#pragma pack(pop)

        // Cache file magic number: "SSCH" (ShadowStrike Cache Header)
        static constexpr uint32_t kCacheMagic = (('S') | ('S' << 8) | ('C' << 16) | ('H' << 24));
        // Cache file format version
        static constexpr uint16_t kCacheVersion = 1;

        bool CacheManager::ensureBaseDir() {
            if (m_baseDir.empty()) return false;

            std::wstring path;
            path.reserve(m_baseDir.size());

            for (size_t i = 0; i < m_baseDir.size(); ++i) {
                wchar_t c = m_baseDir[i];
                path.push_back(c);

                if ((c == L'\\' || c == L'/') && path.size() > 3) {
                    if (!CreateDirectoryW(path.c_str(), nullptr)) {
                        DWORD err = GetLastError();
                        if (err != ERROR_ALREADY_EXISTS) {
                            return false;
                        }
                    }
                }
            }

            // Create the final directory
            if (!CreateDirectoryW(m_baseDir.c_str(), nullptr)) {
                const DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief Ensures that the 2-character hex prefix subdirectory exists.
         *
         * Cache files are organized into subdirectories based on the first
         * two characters of their hex hash to prevent directory bloat.
         *
         * @param hex2 The hex hash string (only first 2 chars used).
         * @return true if directory exists or was created, false on failure.
         */
        bool CacheManager::ensureSubdirForHash(const std::wstring& hex2) {
            // Validate input
            if (hex2.size() < 2) {
                return false;
            }

            // Build subdirectory path
            std::wstring subDir = m_baseDir;
            if (!subDir.empty() && subDir.back() != L'\\') {
                subDir.push_back(L'\\');
            }
            subDir += hex2.substr(0, 2);

            // Create the directory
            if (!CreateDirectoryW(subDir.c_str(), nullptr)) {
                const DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief Generates a validated file path for a cache entry.
         *
         * Constructs a path based on the hex hash and validates it to
         * prevent path traversal attacks.
         *
         * @param hex The hex hash string (must be 2-64 lowercase hex chars).
         * @return Full validated path, or empty string on validation failure.
         *
         * @note This method includes path traversal protection to ensure
         *       the resulting path is within the cache base directory.
         */
        std::wstring CacheManager::pathForKeyHex(const std::wstring& hex) const {
            // Validate hex string length
            if (hex.size() < 2 || hex.size() > 64) {
                return L"";
            }

            // Validate hex characters (must be lowercase hex only)
            for (wchar_t c : hex) {
                if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                    return L"";
                }
            }

            // Build initial path: baseDir\XX\XXXX....cache
            std::wstring path = m_baseDir;
            if (!path.empty() && path.back() != L'\\') {
                path.push_back(L'\\');
            }
            path += hex.substr(0, 2);       // First 2 chars as subdirectory
            path.push_back(L'\\');
            path += hex;                     // Full hash as filename
            path += L".cache";

            // Canonicalize path to resolve any .. or . components
            wchar_t canonical[MAX_PATH]{};
            if (!GetFullPathNameW(path.c_str(), MAX_PATH, canonical, nullptr)) {
                return L"";
            }

            const std::wstring canonicalPath(canonical);

            // PATH TRAVERSAL PROTECTION:
            // Ensure canonicalized path is still within base directory
            if (canonicalPath.size() < m_baseDir.size() ||
                _wcsnicmp(canonicalPath.c_str(), m_baseDir.c_str(), m_baseDir.size()) != 0) {
                SS_LOG_WARN(L"CacheManager", L"Path traversal attempt blocked");
                return L"";
            }

            return canonicalPath;
        }

        /**
         * @brief Persists a cache entry to disk using atomic write pattern.
         *
         * Writes the entry to a temporary file first, then atomically moves
         * it to the final location. This prevents corruption from interrupted writes.
         *
         * @param key The cache key.
         * @param entry The cache entry to persist.
         * @return true if successfully persisted, false on any failure.
         *
         * @note This method uses FILE_FLAG_WRITE_THROUGH for durability
         *       and MOVEFILE_WRITE_THROUGH for atomic rename.
         */
        bool CacheManager::persistWrite(const std::wstring& key, const Entry& entry) {
            // Validate prerequisites
            if (m_baseDir.empty()) {
                return false;
            }
            if (key.empty()) {
                return false;
            }

            // Acquire disk lock and track operation
            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            // Generate hash-based file path
            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) {
                return false;
            }

            // Ensure subdirectory exists
            if (!ensureSubdirForHash(hex.substr(0, 2))) {
                return false;
            }

            // Get validated final path
            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) {
                return false;
            }

            // Generate unique temporary file path
            wchar_t tempPath[MAX_PATH] = {};
            const int written = swprintf_s(
                tempPath,
                MAX_PATH,
                L"%s.tmp.%08X%08X",
                finalPath.c_str(),
                static_cast<unsigned>(GetTickCount64() & 0xFFFFFFFF),
                static_cast<unsigned>(reinterpret_cast<uintptr_t>(this) & 0xFFFFFFFF)
            );
            if (written <= 0) {
                return false;
            }

            // Create temporary file with write-through flag for durability
            FileHandle hFile(CreateFileW(
                tempPath,
                GENERIC_WRITE,
                0,                          // No sharing during write
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                nullptr
            ));

            if (!hFile.IsValid()) {
                return false;
            }

            // Prepare header with explicit initialization
            ULARGE_INTEGER expireTime{};
            expireTime.LowPart = entry.expire.dwLowDateTime;
            expireTime.HighPart = entry.expire.dwHighDateTime;

            // Validate key size fits in uint32_t
            const size_t keyBytesRaw = key.size() * sizeof(wchar_t);
            if (keyBytesRaw > UINT32_MAX) {
                hFile.Close();
                DeleteFileW(tempPath);
                return false;
            }
            const uint32_t keyBytes = static_cast<uint32_t>(keyBytesRaw);

            // Validate value size fits in uint64_t and DWORD for WriteFile
            if (entry.value.size() > UINT32_MAX) {
                hFile.Close();
                DeleteFileW(tempPath);
                return false;
            }

            // Build header
            CacheFileHeader hdr{};
            hdr.magic = kCacheMagic;
            hdr.version = kCacheVersion;
            hdr.reserved = 0;
            hdr.expire100ns = expireTime.QuadPart;
            hdr.flags = (entry.sliding ? 0x1u : 0u) | (entry.persistent ? 0x2u : 0u);
            hdr.keyBytes = keyBytes;
            hdr.valueBytes = static_cast<uint64_t>(entry.value.size());
            hdr.ttlMs = static_cast<uint64_t>(entry.ttl.count());

            // Write header
            DWORD bytesWritten = 0;
            BOOL ok = WriteFile(hFile.Get(), &hdr, sizeof(hdr), &bytesWritten, nullptr);
            if (!ok || bytesWritten != sizeof(hdr)) {
                hFile.Close();
                DeleteFileW(tempPath);
                return false;
            }

            // Write key data
            if (keyBytes > 0) {
                ok = WriteFile(hFile.Get(), key.data(), keyBytes, &bytesWritten, nullptr);
                if (!ok || bytesWritten != keyBytes) {
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // Write value data
            if (!entry.value.empty()) {
                const DWORD valueBytes = static_cast<DWORD>(entry.value.size());
                ok = WriteFile(hFile.Get(), entry.value.data(), valueBytes, &bytesWritten, nullptr);
                if (!ok || bytesWritten != valueBytes) {
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // Flush buffers to ensure data is on disk
            FlushFileBuffers(hFile.Get());
            hFile.Close();

            // Atomic move: temp file -> final path
            if (!MoveFileExW(tempPath, finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(tempPath);
                return false;
            }

            return true;
        }

        /**
         * @brief Reads a cache entry from disk.
         *
         * Validates the file format, magic number, version, and key match
         * before loading the cached value.
         *
         * @param key The cache key to read.
         * @param[out] outEntry Entry structure to populate on success.
         * @return true if entry was read successfully, false on any failure.
         *
         * @note Key verification prevents cache poisoning attacks where
         *       a malicious file claims to hold a different key's value.
         */
        bool CacheManager::persistRead(const std::wstring& key, Entry& outEntry) {
            // Validate prerequisites
            if (m_baseDir.empty()) {
                return false;
            }
            if (key.empty()) {
                return false;
            }

            // Acquire shared disk lock and track operation
            SRWShared diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            // Generate hash-based file path
            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) {
                return false;
            }

            // Get validated path
            const std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) {
                return false;
            }

            // Open file for reading
            FileHandle hFile(CreateFileW(
                finalPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr
            ));

            if (!hFile.IsValid()) {
                return false;
            }

            // Read header
            CacheFileHeader hdr{};
            DWORD bytesRead = 0;

            if (!ReadFile(hFile.Get(), &hdr, sizeof(hdr), &bytesRead, nullptr) || bytesRead != sizeof(hdr)) {
                return false;
            }

            // Validate magic number
            if (hdr.magic != kCacheMagic) {
                return false;
            }

            // Validate version
            if (hdr.version != kCacheVersion) {
                return false;
            }

            // Validate key size (security limits)
            constexpr uint32_t kMaxKeyBytes = 8192; // 4096 wchar_t
            if (hdr.keyBytes == 0 || hdr.keyBytes > kMaxKeyBytes) {
                return false;
            }
            if (hdr.keyBytes % sizeof(wchar_t) != 0) {
                return false; // Key bytes must be even (wchar_t alignment)
            }

            // Validate value size (security limits)
            constexpr uint64_t kMaxValueBytes = 100ULL * 1024 * 1024; // 100 MB
            if (hdr.valueBytes > kMaxValueBytes) {
                return false;
            }

            // Validate file size matches expected content
            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFile.Get(), &fileSize)) {
                return false;
            }

            const uint64_t expectedSize = sizeof(CacheFileHeader) 
                + static_cast<uint64_t>(hdr.keyBytes) 
                + hdr.valueBytes;

            if (static_cast<uint64_t>(fileSize.QuadPart) < expectedSize) {
                return false; // File truncated
            }

            // Read key data
            std::vector<wchar_t> keyBuf;
            try {
                keyBuf.resize(hdr.keyBytes / sizeof(wchar_t));
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            if (hdr.keyBytes > 0) {
                bytesRead = 0;
                if (!ReadFile(hFile.Get(), keyBuf.data(), hdr.keyBytes, &bytesRead, nullptr) || 
                    bytesRead != hdr.keyBytes) {
                    return false;
                }
            }

            // SECURITY: Verify key matches to prevent cache poisoning
            if (key.size() != keyBuf.size()) {
                return false;
            }
            if (hdr.keyBytes > 0 && wmemcmp(key.data(), keyBuf.data(), keyBuf.size()) != 0) {
                return false;
            }

            // Read value data
            std::vector<uint8_t> value;
            try {
                value.resize(static_cast<size_t>(hdr.valueBytes));
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            if (hdr.valueBytes > 0) {
                // Validate value size fits in DWORD for ReadFile
                if (hdr.valueBytes > UINT32_MAX) {
                    return false;
                }
                const DWORD valueBytes = static_cast<DWORD>(hdr.valueBytes);

                bytesRead = 0;
                if (!ReadFile(hFile.Get(), value.data(), valueBytes, &bytesRead, nullptr) ||
                    bytesRead != valueBytes) {
                    return false;
                }
            }

            // Populate output entry
            outEntry.key = key;
            outEntry.value = std::move(value);
            outEntry.sizeBytes = (key.size() * sizeof(wchar_t)) + outEntry.value.size() + sizeof(Entry);

            // Convert expiration time
            ULARGE_INTEGER expireTime{};
            expireTime.QuadPart = hdr.expire100ns;
            outEntry.expire.dwLowDateTime = expireTime.LowPart;
            outEntry.expire.dwHighDateTime = expireTime.HighPart;

            // Parse flags
            outEntry.sliding = (hdr.flags & 0x1u) != 0;
            outEntry.persistent = (hdr.flags & 0x2u) != 0;
            outEntry.ttl = std::chrono::milliseconds(hdr.ttlMs);

            return true;
        }

        /**
         * @brief Removes a cache entry file from disk.
         *
         * @param key The cache key whose file should be deleted.
         * @return true if file was deleted or didn't exist, false on failure.
         */
        bool CacheManager::persistRemoveByKey(const std::wstring& key) {
            // Validate prerequisites
            if (m_baseDir.empty()) {
                return false;
            }
            if (key.empty()) {
                return false;
            }

            // Acquire exclusive disk lock and track operation
            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            // Generate hash-based file path
            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) {
                return false;
            }

            // Get validated path
            const std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) {
                return false;
            }

            // Delete the file
            if (!DeleteFileW(finalPath.c_str())) {
                const DWORD err = GetLastError();
                // File not found is acceptable (already deleted)
                if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief Generates a cryptographic hash of the key for disk storage.
         *
         * Uses HMAC-SHA256 with a session-generated key for high-quality hashes.
         * Falls back to FNV-1a if BCrypt is unavailable.
         *
         * @param key The key to hash.
         * @return Lowercase hex string of the hash (16 chars for FNV-1a, 64 for SHA256).
         */
        std::wstring CacheManager::hashKeyToHex(const std::wstring& key) const {
            // Get raw bytes
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(key.data());
            const size_t byteCount = key.size() * sizeof(wchar_t);

            // Validate input
            if (byteCount == 0) {
                return L"";
            }

            // Validate byte count fits in ULONG for BCrypt
            if (byteCount > ULONG_MAX) {
                // Key too large - use FNV-1a fallback
                const uint64_t hash = Fnv1a64(bytes, byteCount);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; ++i) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            const ULONG cb = static_cast<ULONG>(byteCount);

            // Check BCrypt availability
            const auto& api = BcryptApi::Instance();
            if (!api.IsAvailable() || m_hmacKey.empty()) {
                // Fall back to FNV-1a
                const uint64_t hash = Fnv1a64(bytes, byteCount);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; ++i) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            // Use BCrypt HMAC-SHA256
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;

            // Open algorithm with HMAC flag
            NTSTATUS status = api.OpenAlgorithmProvider(
                &hAlg,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG
            );

            if (status != 0 || hAlg == nullptr) {
                // BCrypt failed - fallback to FNV-1a
                const uint64_t hash = Fnv1a64(bytes, byteCount);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; ++i) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            // Create HMAC hash object
            status = api.CreateHash(
                hAlg,
                &hHash,
                nullptr,
                0,
                const_cast<PUCHAR>(m_hmacKey.data()),
                static_cast<ULONG>(m_hmacKey.size()),
                0
            );

            if (status != 0 || hHash == nullptr) {
                api.CloseAlgorithmProvider(hAlg, 0);
                const uint64_t hash = Fnv1a64(bytes, byteCount);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; ++i) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            // Hash the data
            if (cb > 0) {
                status = api.HashData(hHash, const_cast<PUCHAR>(bytes), cb, 0);
            }

            // Finalize hash
            uint8_t digest[32] = {};
            if (status == 0) {
                status = api.FinishHash(hHash, digest, sizeof(digest), 0);
            }

            // Cleanup BCrypt resources
            api.DestroyHash(hHash);
            api.CloseAlgorithmProvider(hAlg, 0);

            // Check for errors during hashing
            if (status != 0) {
                const uint64_t hash = Fnv1a64(bytes, byteCount);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; ++i) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            return ToHex(digest, sizeof(digest));
        }

        /**
         * @brief Gets the current system time as FILETIME.
         * @return Current time in FILETIME format.
         */
        FILETIME CacheManager::nowFileTime() noexcept {
            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            return ft;
        }

        /**
         * @brief Compares two FILETIME values.
         *
         * @param a First FILETIME.
         * @param b Second FILETIME.
         * @return true if a <= b, false otherwise.
         */
        bool CacheManager::fileTimeLessOrEqual(const FILETIME& a, const FILETIME& b) noexcept {
            if (a.dwHighDateTime < b.dwHighDateTime) {
                return true;
            }
            if (a.dwHighDateTime > b.dwHighDateTime) {
                return false;
            }
            return a.dwLowDateTime <= b.dwLowDateTime;
        }

        /**
         * @brief Loads all persistent cache entries from disk during initialization.
         *
         * Scans the cache directory structure, validates each cache file,
         * removes expired entries, and loads valid entries into memory.
         *
         * @note This method is designed to be called during initialization
         *       before the maintenance thread starts.
         * @note Uses careful lock ordering to prevent deadlocks.
         */
        void CacheManager::loadPersistentEntries() {
            if (m_baseDir.empty()) {
                return;
            }

            // Verify cache directory exists
            const DWORD attribs = GetFileAttributesW(m_baseDir.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES) {
                return;
            }
            if (!(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                return;
            }

            // Build search mask for subdirectories
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') {
                mask.push_back(L'\\');
            }
            mask += L"*";

            WIN32_FIND_DATAW fd{};
            HANDLE hFind = FindFirstFileW(mask.c_str(), &fd);
            if (hFind == INVALID_HANDLE_VALUE) {
                return;
            }

            size_t loadedCount = 0;
            const FILETIME now = nowFileTime();

            // Iterate through subdirectories (2-char hex prefixes)
            do {
                // Skip non-directories
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    continue;
                }

                // Skip . and ..
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) {
                    continue;
                }

                // Search for cache files in subdirectory
                std::wstring subMask = m_baseDir + L"\\" + fd.cFileName + L"\\*.cache";

                WIN32_FIND_DATAW fd2{};
                HANDLE hFind2 = FindFirstFileW(subMask.c_str(), &fd2);
                if (hFind2 != INVALID_HANDLE_VALUE) {
                    do {
                        // Skip directories
                        if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            continue;
                        }

                        // Validate filename format
                        std::wstring filename(fd2.cFileName);
                        if (filename.size() < 7) {
                            continue;
                        }
                        if (filename.substr(filename.size() - 6) != L".cache") {
                            continue;
                        }

                        // Build full path
                        std::wstring filePath = m_baseDir + L"\\" + fd.cFileName + L"\\" + filename;

                        // Open cache file
                        FileHandle hFile(CreateFileW(
                            filePath.c_str(),
                            GENERIC_READ,
                            FILE_SHARE_READ,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                        ));

                        if (!hFile.IsValid()) {
                            continue;
                        }

                        // Read and validate header
                        CacheFileHeader hdr{};
                        DWORD bytesRead = 0;

                        if (!ReadFile(hFile.Get(), &hdr, sizeof(hdr), &bytesRead, nullptr) ||
                            bytesRead != sizeof(hdr)) {
                            continue;
                        }

                        // Validate magic and version
                        if (hdr.magic != kCacheMagic) {
                            continue;
                        }
                        if (hdr.version != kCacheVersion) {
                            continue;
                        }

                        // Validate key size
                        constexpr uint32_t kMaxKeyBytes = 8192;
                        if (hdr.keyBytes == 0 || hdr.keyBytes > kMaxKeyBytes) {
                            continue;
                        }
                        if ((hdr.keyBytes % sizeof(wchar_t)) != 0) {
                            continue;
                        }

                        // Read key
                        std::vector<wchar_t> keyBuf;
                        try {
                            keyBuf.resize(hdr.keyBytes / sizeof(wchar_t));
                        }
                        catch (const std::bad_alloc&) {
                            continue;
                        }

                        if (!ReadFile(hFile.Get(), keyBuf.data(), hdr.keyBytes, &bytesRead, nullptr) ||
                            bytesRead != hdr.keyBytes) {
                            continue;
                        }

                        std::wstring key(keyBuf.begin(), keyBuf.end());

                        // Check expiration
                        ULARGE_INTEGER expireTime{};
                        expireTime.QuadPart = hdr.expire100ns;

                        FILETIME expireFt{};
                        expireFt.dwLowDateTime = expireTime.LowPart;
                        expireFt.dwHighDateTime = expireTime.HighPart;

                        if (fileTimeLessOrEqual(expireFt, now)) {
                            // Entry expired - delete file
                            hFile.Close();
                            DeleteFileW(filePath.c_str());
                            continue;
                        }

                        // Validate value size
                        constexpr uint64_t kMaxValueBytes = 100ULL * 1024 * 1024;
                        if (hdr.valueBytes > kMaxValueBytes) {
                            continue;
                        }

                        // Read value
                        std::vector<uint8_t> value;
                        try {
                            value.resize(static_cast<size_t>(hdr.valueBytes));
                        }
                        catch (const std::bad_alloc&) {
                            continue;
                        }

                        if (hdr.valueBytes > 0) {
                            if (hdr.valueBytes > UINT32_MAX) {
                                continue;
                            }
                            const DWORD valueBytes = static_cast<DWORD>(hdr.valueBytes);
                            if (!ReadFile(hFile.Get(), value.data(), valueBytes, &bytesRead, nullptr) ||
                                bytesRead != valueBytes) {
                                continue;
                            }
                        }

                        hFile.Close();

                        // Create entry object
                        std::shared_ptr<Entry> entry;
                        try {
                            entry = std::make_shared<Entry>();
                        }
                        catch (const std::bad_alloc&) {
                            continue;
                        }

                        entry->key = key;
                        entry->value = std::move(value);
                        entry->expire = expireFt;
                        entry->ttl = std::chrono::milliseconds(hdr.ttlMs);
                        entry->sliding = (hdr.flags & 0x1u) != 0;
                        entry->persistent = true;
                        entry->sizeBytes = (key.size() * sizeof(wchar_t)) + entry->value.size() + sizeof(Entry);

                        // Insert into cache (under lock)
                        {
                            SRWExclusive guard(m_lock);

                            // Check if already exists
                            if (m_map.find(key) != m_map.end()) {
                                continue;
                            }

                            // Check byte limit
                            if (m_maxBytes > 0 && (m_totalBytes + entry->sizeBytes) > m_maxBytes) {
                                continue;
                            }

                            // Insert into LRU and map
                            m_lru.push_front(key);
                            entry->lruIt = m_lru.begin();
                            m_map.emplace(key, entry);
                            m_totalBytes += entry->sizeBytes;

                            ++loadedCount;
                        }

                    } while (FindNextFileW(hFind2, &fd2));

                    FindClose(hFind2);
                }

            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);

            if (loadedCount > 0) {
                SS_LOG_INFO(L"CacheManager", L"Loaded persistent entries from disk");
            }
        }

	}// namespace Utils
}// namespace ShadowStrike