#include "CacheManager.hpp"

#include <cwchar>
#include <algorithm>
#include <cassert>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

namespace ShadowStrike {
	namespace Utils {

        namespace {

            // Convert system_clock::time_point to FILETIME (100ns ticks)
            uint64_t TimePointToFileTime(const std::chrono::system_clock::time_point& tp) {
                auto duration = tp.time_since_epoch();
                auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
                int64_t us = microseconds.count();

                // ? HANDLE OVERFLOW EXPLICITLY
                if (us < 0) {
                    SS_LOG_ERROR(L"CacheManager", L"Negative timestamp: %lld", us);
                    return 0;
                }

                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
                constexpr uint64_t MAX_SAFE_US = (ULLONG_MAX - EPOCH_DIFF) / 10ULL;

                if (static_cast<uint64_t>(us) > MAX_SAFE_US) {
                    SS_LOG_ERROR(L"CacheManager", L"Timestamp overflow: %lld us", us);
                    return ULLONG_MAX; // ? SATURATE TO MAX
                }

                uint64_t filetime = static_cast<uint64_t>(us) * 10ULL + EPOCH_DIFF;
                return filetime;
            }

            // Convert FILETIME (100ns ticks) back to system_clock::time_point
            std::chrono::system_clock::time_point FileTimeToTimePoint(uint64_t filetime) {
                if (filetime == 0) {
                    SS_LOG_WARN(L"CacheManager", L"Zero FILETIME provided");
                    return std::chrono::system_clock::time_point{};
                }

                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;

                if (filetime < EPOCH_DIFF) {
                    SS_LOG_ERROR(L"CacheManager", L"Invalid FILETIME: %llu (before Unix epoch)", filetime);
                    return std::chrono::system_clock::time_point{};
                }

                uint64_t unix_time_100ns = filetime - EPOCH_DIFF;

                // ? CHECK OVERFLOW
                constexpr uint64_t MAX_SAFE_100NS = LLONG_MAX / 10ULL;
                if (unix_time_100ns > MAX_SAFE_100NS) {
                    SS_LOG_ERROR(L"CacheManager", L"FILETIME overflow: %llu", filetime);
                    return std::chrono::system_clock::time_point::max();
                }

                auto microseconds = std::chrono::microseconds(unix_time_100ns / 10ULL);
                return std::chrono::system_clock::time_point(microseconds);
            }

        }

        // ---- Bcrypt dynamic resolve (SHA-256) ----
        struct BcryptApi {
            HMODULE h = nullptr;
            NTSTATUS(WINAPI* BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG) = nullptr;
            NTSTATUS(WINAPI* BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG) = nullptr;
            NTSTATUS(WINAPI* BCryptCreateHash)(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG) = nullptr;
            NTSTATUS(WINAPI* BCryptDestroyHash)(BCRYPT_HASH_HANDLE) = nullptr;
            NTSTATUS(WINAPI* BCryptHashData)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG) = nullptr;
            NTSTATUS(WINAPI* BCryptFinishHash)(BCRYPT_HASH_HANDLE, PUCHAR, ULONG, ULONG) = nullptr;

            static const BcryptApi& Instance() {
                static BcryptApi api;
                static std::once_flag once;
                std::call_once(once, []() {
                    api.h = ::LoadLibraryW(L"bcrypt.dll");
                    if (!api.h) return;
                    api.BCryptOpenAlgorithmProvider = reinterpret_cast<decltype(api.BCryptOpenAlgorithmProvider)>(GetProcAddress(api.h, "BCryptOpenAlgorithmProvider"));
                    api.BCryptCloseAlgorithmProvider = reinterpret_cast<decltype(api.BCryptCloseAlgorithmProvider)>(GetProcAddress(api.h, "BCryptCloseAlgorithmProvider"));
                    api.BCryptCreateHash = reinterpret_cast<decltype(api.BCryptCreateHash)>(GetProcAddress(api.h, "BCryptCreateHash"));
                    api.BCryptDestroyHash = reinterpret_cast<decltype(api.BCryptDestroyHash)>(GetProcAddress(api.h, "BCryptDestroyHash"));
                    api.BCryptHashData = reinterpret_cast<decltype(api.BCryptHashData)>(GetProcAddress(api.h, "BCryptHashData"));
                    api.BCryptFinishHash = reinterpret_cast<decltype(api.BCryptFinishHash)>(GetProcAddress(api.h, "BCryptFinishHash"));
                    if (!api.BCryptOpenAlgorithmProvider || !api.BCryptCreateHash || !api.BCryptHashData || !api.BCryptFinishHash || !api.BCryptDestroyHash || !api.BCryptCloseAlgorithmProvider) {
                        FreeLibrary(api.h);
                        api.h = nullptr;
                    }
                    });
                return api;
            }

            bool available() const { return h != nullptr; }
        };

        //FNV-1a (64-bit) backup hash
        static uint64_t Fnv1a64(const void* data, size_t len) {
            const uint8_t* p = static_cast<const uint8_t*>(data);
            uint64_t h = 1469598103934665603ULL;
            for (size_t i = 0; i < len; ++i) {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
            return h;
        }


        // Hex helper
        static std::wstring ToHex(const uint8_t* data, size_t len) {
            static const wchar_t* kHex = L"0123456789abcdef";
            std::wstring out;
            out.resize(len * 2);
            for (size_t i = 0; i < len; ++i) {
                out[i * 2] = kHex[(data[i] >> 4) & 0xF];
                out[i * 2 + 1] = kHex[data[i] & 0xF];
            }
            return out;
        }

        // ---- CacheManager impl ----

        CacheManager& CacheManager::Instance() {
            static CacheManager g;
            return g;
        }

        CacheManager::CacheManager() {
            InitializeSRWLock(&m_lock);
            InitializeSRWLock(&m_diskLock); // ? INIT DISK LOCK
            //initialize atomic timestamp
            auto now = std::chrono::system_clock::now();
            m_lastMaint.store(TimePointToFileTime(now), std::memory_order_release);
        }

        CacheManager::~CacheManager() {
            Shutdown();
        }


        void CacheManager::Initialize(const std::wstring& baseDir, size_t maxEntries, size_t maxBytes, std::chrono::milliseconds maintenanceInterval) {
            if (m_maintThread.joinable()) {
                SS_LOG_WARN(L"CacheManager", L"Already initialized - ignoring duplicate call");
                return;
            }

            // ? VALIDATE PARAMETERS
            if (maxBytes > 0 && maxBytes < 1024 * 1024) {
                SS_LOG_ERROR(L"CacheManager", L"maxBytes too small (minimum 1MB)");
                return;
            }

            if (maintenanceInterval < std::chrono::seconds(10)) {
                SS_LOG_ERROR(L"CacheManager", L"maintenanceInterval too short (minimum 10s)");
                return;
            }

            m_maxEntries = maxEntries;
            m_maxBytes = maxBytes;
            m_maintInterval = maintenanceInterval;

            if (!baseDir.empty()) {
                m_baseDir = baseDir;
            }
            else {
                // ProgramData\ShadowStrike\Cache
                wchar_t buf[MAX_PATH] = {};
                DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
                if (n == 0 || n >= MAX_PATH) {
                    // fallback to Windows directory
                    if (!GetWindowsDirectoryW(buf, MAX_PATH)) {
                        wcscpy_s(buf, L"C:\\ProgramData");
                    }
                    else {
                        wcscat_s(buf, L"\\ProgramData");
                    }
                }
                m_baseDir.assign(buf);
                if (!m_baseDir.empty() && m_baseDir.back() != L'\\') m_baseDir.push_back(L'\\');
                m_baseDir += L"ShadowStrike\\Cache";
            }

            if (!ensureBaseDir()) {
                SS_LOG_ERROR(L"CacheManager", L"Base directory could not be created: %ls", m_baseDir.c_str());
            }
            else {
                SS_LOG_INFO(L"CacheManager", L"Cache base directory: %ls", m_baseDir.c_str());
            }

            // ? GENERATE HMAC KEY
            const auto& api = BcryptApi::Instance();
            if (api.available()) {
                m_hmacKey.resize(32);
                NTSTATUS st = BCryptGenRandom(nullptr, m_hmacKey.data(), 32, 
                                              BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (st != 0) {
                    SS_LOG_ERROR(L"CacheManager", L"Failed to generate HMAC key (status: 0x%08X)", st);
                    m_hmacKey.clear();
                }
            }

            m_shutdown.store(false, std::memory_order_release);
            m_maintThread = std::thread(&CacheManager::maintenanceThread, this);
            SS_LOG_INFO(L"CacheManager", L"Initialized. Limits: maxEntries=%zu, maxBytes=%zu", maxEntries, maxBytes);
        }

        void CacheManager::Shutdown() {
            if (!m_maintThread.joinable()) {
                return;
            }

            SS_LOG_INFO(L"CacheManager", L"Shutdown initiated");

            m_shutdown.store(true, std::memory_order_release);
            
            if (m_maintThread.joinable()) {
                m_maintThread.join();
            }

            // ? WAIT FOR PENDING DISK I/O (max 10 seconds)
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
            size_t pending = m_pendingDiskOps.load(std::memory_order_acquire);
            
            while (pending > 0) {
                if (std::chrono::steady_clock::now() >= deadline) {
                    SS_LOG_WARN(L"CacheManager", 
                                L"Shutdown timeout: %zu disk operations still pending", 
                                pending);
                    break;
                }

                SS_LOG_INFO(L"CacheManager", 
                            L"Waiting for %zu pending disk operations...", 
                            pending);
                
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                pending = m_pendingDiskOps.load(std::memory_order_acquire);
            }

            {
                SRWExclusive g(m_lock);
                m_map.clear();
                m_lru.clear();
                m_totalBytes = 0;
            }

            SS_LOG_INFO(L"CacheManager", L"Shutdown complete");
        }


        bool CacheManager::Put(const std::wstring& key,
            const uint8_t* data, size_t size,
            std::chrono::milliseconds ttl,
            bool persistent,
            bool sliding)
        {
            if (key.empty()) return false;
            if (!data && size != 0) return false;

            // MAXIMUM KEY SIZE CHECK
            constexpr size_t MAX_KEY_SIZE = 4096; // 4KB max key size
            if (key.size() * sizeof(wchar_t) > MAX_KEY_SIZE) {
                SS_LOG_ERROR(L"CacheManager", L"Key too large: %zu bytes", key.size() * sizeof(wchar_t));
                return false;
            }

            // MAXIMUM VALUE SIZE CHECK
            constexpr size_t MAX_VALUE_SIZE = 100ULL * 1024 * 1024; // 100MB
            if (size > MAX_VALUE_SIZE) {
                SS_LOG_ERROR(L"CacheManager", L"Value too large: %zu bytes", size);
                return false;
            }

            // ? VALIDATE TTL BEFORE CALCULATION
            const int64_t ttlMs = ttl.count();
            if (ttlMs < 0) {
                SS_LOG_ERROR(L"CacheManager", L"Negative TTL not allowed");
                return false;
            }

            // ? ENFORCE MAXIMUM TTL (30 days)
            constexpr auto MAX_TTL = std::chrono::hours(24 * 30);
            if (ttl > MAX_TTL) {
                SS_LOG_ERROR(L"CacheManager", L"TTL exceeds maximum: %lld ms (max: %lld ms)",
                             ttlMs, MAX_TTL.count());
                return false;
            }

            // ? ENFORCE MINIMUM TTL
            if (ttl < std::chrono::seconds(1)) {
                SS_LOG_ERROR(L"CacheManager", L"TTL too small: %lld ms (min: 1000 ms)", ttlMs);
                return false;
            }

            FILETIME now = nowFileTime();

            // Calculate expiration time with overflow protection
            ULARGE_INTEGER ua{}, ub{};
            ua.LowPart = now.dwLowDateTime;
            ua.HighPart = now.dwHighDateTime;

            // ? CHECK BEFORE MULTIPLICATION
            constexpr int64_t MAX_SAFE_TTL_MS = (ULLONG_MAX / 10000ULL);
            if (ttlMs > MAX_SAFE_TTL_MS) {
                SS_LOG_ERROR(L"CacheManager", L"TTL causes multiplication overflow: %lld ms", ttlMs);
                return false;
            }

            const uint64_t delta100ns = static_cast<uint64_t>(ttlMs) * 10000ULL;

            // CHECK FOR OVERFLOW BEFORE ADDITION
            if (ua.QuadPart > ULLONG_MAX - delta100ns) {
                SS_LOG_ERROR(L"CacheManager", L"TTL causes timestamp overflow");
                return false;
            }

            ub.QuadPart = ua.QuadPart + delta100ns;

            FILETIME expire{};
            expire.dwLowDateTime = ub.LowPart;
            expire.dwHighDateTime = ub.HighPart;

            std::shared_ptr<Entry> e = std::make_shared<Entry>();
            e->key = key;

            try {
                e->value.assign(data, data + size);
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"CacheManager", L"Memory allocation failed for cache entry");
                return false;
            }

            e->expire = expire;
            e->ttl = ttl;
            e->sliding = sliding;
            e->persistent = persistent;

            // PROPER SIZE CALCULATION (key + value + overhead)
            e->sizeBytes = (key.size() * sizeof(wchar_t)) + e->value.size() + sizeof(Entry);

            // CHECK TOTAL CACHE SIZE BEFORE INSERT
            {
                SRWExclusive g(m_lock);

                // Check if adding this entry would exceed max bytes
                if (m_maxBytes > 0 && (m_totalBytes + e->sizeBytes) > m_maxBytes) {
                    // Try to evict enough entries
                    evictIfNeeded_NoLock();

                    // Still too large?
                    if ((m_totalBytes + e->sizeBytes) > m_maxBytes) {
                        SS_LOG_WARN(L"CacheManager", L"Cache full, cannot add entry: %ls", key.c_str());
                        return false;
                    }
                }

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    // Replace existing
                    m_totalBytes -= it->second->sizeBytes;
                    m_lru.erase(it->second->lruIt);
                    m_map.erase(it);
                }

                m_lru.push_front(key);
                e->lruIt = m_lru.begin();
                m_map.emplace(key, e);
                m_totalBytes += e->sizeBytes;

                evictIfNeeded_NoLock();
            }

            if (persistent) {
                if (!persistWrite(key, *e)) {
                    SS_LOG_WARN(L"CacheManager", L"Persist write failed for key: %ls", key.c_str());
                }
            }

            return true;
        }

        bool CacheManager::Get(const std::wstring& key, std::vector<uint8_t>& outData) {
            outData.clear();
            if (key.empty()) return false;

            FILETIME now = nowFileTime();
            bool needsPersist = false;
            Entry entryCopyForPersist; // ? SAFE: Full copy instead of shared_ptr

            {
                SRWExclusive g(m_lock);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    std::shared_ptr<Entry> e = it->second;

                    // Check if expired
                    if (isExpired_NoLock(*e, now)) {
                        // Remove expired entry
                        m_totalBytes -= e->sizeBytes;
                        m_lru.erase(e->lruIt);
                        m_map.erase(it);
                        if (e->persistent) {
                            persistRemoveByKey(key);
                        }
                        return false;
                    }

                    // UPDATE SLIDING EXPIRATION
                    if (e->sliding && e->ttl.count() > 0) {
                        ULARGE_INTEGER ua{}, ub{};
                        ua.LowPart = now.dwLowDateTime;
                        ua.HighPart = now.dwHighDateTime;

                        const uint64_t delta100ns = static_cast<uint64_t>(e->ttl.count()) * 10000ULL;

                        // Check overflow
                        if (ua.QuadPart <= ULLONG_MAX - delta100ns) {
                            ub.QuadPart = ua.QuadPart + delta100ns;
                            e->expire.dwLowDateTime = ub.LowPart;
                            e->expire.dwHighDateTime = ub.HighPart;

                            // ? DEEP COPY FOR PERSISTENCE
                            if (e->persistent) {
                                needsPersist = true;
                                entryCopyForPersist = *e; // COPY, not reference
                            }
                        }
                    }

                    // Copy data BEFORE releasing lock
                    outData = e->value;
                    touchLRU_NoLock(key, e);
                }
            } // RELEASE LOCK HERE

            // ? SAFE: entryCopyForPersist is independent of m_map
            if (needsPersist) {
                if (!persistWrite(key, entryCopyForPersist)) {
                    SS_LOG_WARN(L"CacheManager", L"Failed to update sliding expiration on disk: %ls", key.c_str());
                }
            }

            // IF WE GOT DATA FROM MEMORY, RETURN SUCCESS
            if (!outData.empty()) {
                return true;
            }

            // NOT IN MEMORY - TRY DISK
            Entry diskEntry;
            if (persistRead(key, diskEntry)) {
                FILETIME now2 = nowFileTime();
                if (isExpired_NoLock(diskEntry, now2)) {
                    persistRemoveByKey(key);
                    return false;
                }

                // Put back to memory
                std::shared_ptr<Entry> e = std::make_shared<Entry>(std::move(diskEntry));
                {
                    SRWExclusive g(m_lock);
                    auto it2 = m_map.find(key);
                    if (it2 != m_map.end()) {
                        // Already loaded by another thread
                        m_totalBytes -= it2->second->sizeBytes;
                        m_lru.erase(it2->second->lruIt);
                        m_map.erase(it2);
                    }
                    m_lru.push_front(key);
                    e->lruIt = m_lru.begin();
                    m_totalBytes += e->sizeBytes;
                    m_map.emplace(key, e);
                    evictIfNeeded_NoLock();
                }

                outData = e->value;
                return true;
            }

            return false;
        }

        bool CacheManager::Remove(const std::wstring& key) {
            if (key.empty()) return false;

            bool removed = false;
            bool wasPersistent = false;
            {
                SRWExclusive g(m_lock);
                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    wasPersistent = it->second->persistent;
                    m_totalBytes -= it->second->sizeBytes;
                    m_lru.erase(it->second->lruIt);
                    m_map.erase(it);
                    removed = true;
                }
            }

            if (wasPersistent) {
                persistRemoveByKey(key);
            }
            else {
                // Diskte varsa sil
                persistRemoveByKey(key);
            }

            return removed;
        }

        void CacheManager::Clear() {
            {
                SRWExclusive g(m_lock);
                m_map.clear();
                m_lru.clear();
                m_totalBytes = 0;
            }

            // ? DISK LOCK FOR FILE DELETION
            SRWExclusive diskGuard(m_diskLock);

            //Clear the files on the disk (*.cache)
            WIN32_FIND_DATAW fd{};
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') mask.push_back(L'\\');
            mask += L"*";
            HANDLE h = FindFirstFileW(mask.c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                size_t deletedCount = 0;
                size_t failedCount = 0;

                do {
                    if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {

                        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                        std::wstring subMask = m_baseDir + L"\\" + fd.cFileName + L"\\*.cache";
                        WIN32_FIND_DATAW fd2{};
                        HANDLE h2 = FindFirstFileW(subMask.c_str(), &fd2);
                        if (h2 != INVALID_HANDLE_VALUE) {
                            do {
                                if (!(fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                                    std::wstring p = m_baseDir + L"\\" + fd.cFileName + L"\\" + fd2.cFileName;
                                    if (!DeleteFileW(p.c_str())) {
                                        DWORD err = GetLastError();
                                        if (err != ERROR_FILE_NOT_FOUND) {
                                            SS_LOG_LAST_ERROR(L"CacheManager", L"DeleteFile failed: %ls", p.c_str());
                                            failedCount++;
                                        }
                                    } else {
                                        deletedCount++;
                                    }
                                }
                            } while (FindNextFileW(h2, &fd2));
                            FindClose(h2);
                        }
                    }
                } while (FindNextFileW(h, &fd));
                FindClose(h);

                if (failedCount > 0) {
                    SS_LOG_WARN(L"CacheManager", 
                                L"Clear() deleted %zu files but failed to delete %zu files",
                                deletedCount, failedCount);
                }
            }
        }


        bool CacheManager::Contains(const std::wstring& key) const {
            if (key.empty()) return false;
            FILETIME now = nowFileTime();
            SRWShared g(m_lock);
            auto it = m_map.find(key);
            if (it == m_map.end()) return false;
            return !isExpired_NoLock(*it->second, now);
        }

        void CacheManager::SetMaxEntries(size_t maxEntries) {
            SRWExclusive g(m_lock);
            
            if (maxEntries == 0 && m_maxBytes == 0) {
                SS_LOG_WARN(L"CacheManager", 
                            L"Both maxEntries and maxBytes are 0 - eviction disabled");
            }
            
            m_maxEntries = maxEntries;
            evictIfNeeded_NoLock();
            
            SS_LOG_INFO(L"CacheManager", 
                        L"maxEntries changed to %zu (current: %zu entries)", 
                        maxEntries, m_map.size());
        }

        void CacheManager::SetMaxBytes(size_t maxBytes) {
            SRWExclusive g(m_lock);
            
            if (maxBytes == 0 && m_maxEntries == 0) {
                SS_LOG_WARN(L"CacheManager", 
                            L"Both maxEntries and maxBytes are 0 - eviction disabled");
            }
            
            m_maxBytes = maxBytes;
            evictIfNeeded_NoLock();
            
            SS_LOG_INFO(L"CacheManager", 
                        L"maxBytes changed to %zu (current: %zu bytes)", 
                        maxBytes, m_totalBytes);
        }

        CacheManager::Stats CacheManager::GetStats() const {
            SRWShared g(m_lock);
            Stats s;
            s.entryCount = m_map.size();
            s.totalBytes = m_totalBytes;
            s.maxEntries = m_maxEntries;
            s.maxBytes = m_maxBytes;
            uint64_t timestamp = m_lastMaint.load(std::memory_order_acquire);
            s.lastMaintenance = FileTimeToTimePoint(timestamp);

            return s;
        }

        // ---- Internal helpers ----

        void CacheManager::maintenanceThread() {
            auto lastMaintenance = std::chrono::steady_clock::now(); // ? MONOTONIC CLOCK

            while (!m_shutdown.load(std::memory_order_acquire)) {
                const auto sleepStep = std::chrono::milliseconds(200);
                std::this_thread::sleep_for(sleepStep);

                auto now = std::chrono::steady_clock::now();
                auto elapsed = now - lastMaintenance;

                if (elapsed >= m_maintInterval) {
                    performMaintenance();
                    lastMaintenance = now; // ? RESET TIMER
                }
            }
        }

        void CacheManager::performMaintenance() {
            try {
                FILETIME now = nowFileTime();
                std::vector<std::wstring> removed;

                {
                    SRWExclusive g(m_lock);
                    removeExpired_NoLock(removed);
                    evictIfNeeded_NoLock();

                    // STORE CURRENT TIME AS ATOMIC
                    auto nowTimePoint = std::chrono::system_clock::now();
                    uint64_t timestamp = TimePointToFileTime(nowTimePoint);
                    m_lastMaint.store(timestamp, std::memory_order_release);
                }

                // ? ISOLATED EXCEPTION HANDLING
                if (!removed.empty()) {
                    for (const auto& k : removed) {
                        try {
                            persistRemoveByKey(k);
                        } catch (const std::exception& e) {
                            SS_LOG_ERROR(L"CacheManager", 
                                         L"Exception during persistRemove: %hs", e.what());
                        } catch (...) {
                            SS_LOG_ERROR(L"CacheManager", 
                                         L"Unknown exception during persistRemove");
                        }
                    }
                }

            } catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"CacheManager", L"Out of memory during maintenance");
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"CacheManager", L"Exception in maintenance: %hs", e.what());
            } catch (...) {
                SS_LOG_ERROR(L"CacheManager", L"Unknown exception in maintenance");
            }
        }

        void CacheManager::evictIfNeeded_NoLock() {
			//Dont evict if no limits
            if (m_maxEntries == 0 && m_maxBytes == 0) return;

            // ? PREVENT INFINITE LOOPS
            size_t iterationCount = 0;
            constexpr size_t MAX_EVICTIONS_PER_CALL = 10000;

            while (!m_lru.empty() &&
                ((m_maxEntries > 0 && m_map.size() > m_maxEntries) ||
                    (m_maxBytes > 0 && m_totalBytes > m_maxBytes)))
            {
                // ? SAFETY GUARD
                if (++iterationCount > MAX_EVICTIONS_PER_CALL) {
                    SS_LOG_ERROR(L"CacheManager", 
                                 L"Eviction loop exceeded %zu iterations - possible corruption",
                                 MAX_EVICTIONS_PER_CALL);
                    // FORCE RESET
                    m_map.clear();
                    m_lru.clear();
                    m_totalBytes = 0;
                    break;
                }

                const std::wstring& victimKey = m_lru.back();
                auto it = m_map.find(victimKey);
                if (it == m_map.end()) {
                    m_lru.pop_back();
                    continue;
                }

                // ? PREVENT UNDERFLOW
                if (m_totalBytes < it->second->sizeBytes) {
                    SS_LOG_ERROR(L"CacheManager", 
                                 L"totalBytes underflow detected: %zu < %zu",
                                 m_totalBytes, it->second->sizeBytes);
                    m_totalBytes = 0; // FORCE RESET
                } else {
                    m_totalBytes -= it->second->sizeBytes;
                }

                m_lru.pop_back();
                m_map.erase(it);
            }
        }
        void CacheManager::removeExpired_NoLock(std::vector<std::wstring>& removedKeys) {
            FILETIME now = nowFileTime();
            for (auto it = m_map.begin(); it != m_map.end(); ) {
                if (isExpired_NoLock(*it->second, now)) {
                    m_totalBytes -= it->second->sizeBytes;
                    m_lru.erase(it->second->lruIt);
                    removedKeys.push_back(it->first);
                    it = m_map.erase(it);
                }
                else {
                    ++it;
                }
            }
        }

        bool CacheManager::isExpired_NoLock(const Entry& e, const FILETIME& now) const {
            // Entry is expired if e.expire <= now (expiration time has passed)
            return fileTimeLessOrEqual(e.expire, now);
        }

        void CacheManager::touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& e) {
            m_lru.erase(e->lruIt);
            m_lru.push_front(key);
            e->lruIt = m_lru.begin();
        }


        // ---- Persistence ----

        namespace {
            // ? RAII Handle Wrapper
            class FileHandle {
            public:
                explicit FileHandle(HANDLE h = INVALID_HANDLE_VALUE) : m_handle(h) {}
                ~FileHandle() { Close(); }

                FileHandle(const FileHandle&) = delete;
                FileHandle& operator=(const FileHandle&) = delete;

                FileHandle(FileHandle&& other) noexcept : m_handle(other.m_handle) {
                    other.m_handle = INVALID_HANDLE_VALUE;
                }

                FileHandle& operator=(FileHandle&& other) noexcept {
                    if (this != &other) {
                        Close();
                        m_handle = other.m_handle;
                        other.m_handle = INVALID_HANDLE_VALUE;
                    }
                    return *this;
                }

                void Close() {
                    if (m_handle != INVALID_HANDLE_VALUE) {
                        CloseHandle(m_handle);
                        m_handle = INVALID_HANDLE_VALUE;
                    }
                }

                HANDLE Get() const { return m_handle; }
                bool IsValid() const { return m_handle != INVALID_HANDLE_VALUE; }

                HANDLE Release() {
                    HANDLE h = m_handle;
                    m_handle = INVALID_HANDLE_VALUE;
                    return h;
                }

            private:
                HANDLE m_handle;
            };

            // ? RAII Disk Operation Guard
            struct DiskOpGuard {
                std::atomic<size_t>& counter;
                explicit DiskOpGuard(std::atomic<size_t>& c) : counter(c) {
                    counter.fetch_add(1, std::memory_order_acquire);
                }
                ~DiskOpGuard() {
                    counter.fetch_sub(1, std::memory_order_release);
                }
            };
        }

#pragma pack(push, 1)
        struct CacheFileHeader {
            uint32_t magic;          // 'SSCH' -> 0x48435353 little-endian: 'S','S','C','H'
            uint16_t version;        // 1
            uint16_t reserved;
            uint64_t expire100ns;    // FILETIME compatible (100ns)
            uint32_t flags;          // bit0: sliding, bit1: persistent (For informational purposes)
            uint32_t keyBytes;       // UTF-16LE byte count
            uint64_t valueBytes;     // data size
            uint64_t ttlMs;          //milliseconds for sliding (if not 0)
        };
#pragma pack(pop)

        static constexpr uint32_t kCacheMagic = (('S') | ('S' << 8) | ('C' << 16) | ('H' << 24));
        static constexpr uint16_t kCacheVersion = 1;

        bool CacheManager::ensureBaseDir() {
            if (m_baseDir.empty()) return false;

            // ? CREATE PARENT DIRECTORIES RECURSIVELY
            std::wstring path;
            path.reserve(m_baseDir.size());

            for (size_t i = 0; i < m_baseDir.size(); ++i) {
                wchar_t c = m_baseDir[i];
                path.push_back(c);

                // Create directory at each separator (skip drive letter)
                if ((c == L'\\' || c == L'/') && path.size() > 3) { // Skip "C:\"
                    if (!CreateDirectoryW(path.c_str(), nullptr)) {
                        DWORD err = GetLastError();
                        if (err != ERROR_ALREADY_EXISTS) {
                            SS_LOG_LAST_ERROR(L"CacheManager", 
                                              L"Failed to create parent dir: %ls", path.c_str());
                            return false;
                        }
                    }
                }
            }

            // ? CREATE FINAL DIRECTORY
            if (!CreateDirectoryW(m_baseDir.c_str(), nullptr)) {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
                    SS_LOG_LAST_ERROR(L"CacheManager", 
                                      L"Failed to create base dir: %ls", m_baseDir.c_str());
                    return false;
                }
            }

            return true;
        }


        bool CacheManager::ensureSubdirForHash(const std::wstring& hex2) {
            if (hex2.size() < 2) return false;
            std::wstring sub = m_baseDir;
            if (!sub.empty() && sub.back() != L'\\') sub.push_back(L'\\');
            sub += hex2.substr(0, 2);
            if (!CreateDirectoryW(sub.c_str(), nullptr)) {
                DWORD e = GetLastError();
                if (e != ERROR_ALREADY_EXISTS) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"CreateDirectory (subdir) failed: %ls", sub.c_str());
                    return false;
                }
            }
            return true;
        }

        std::wstring CacheManager::pathForKeyHex(const std::wstring& hex) const {
            // ? VALIDATE HEX STRING (only [0-9a-f])
            if (hex.size() < 2 || hex.size() > 64) {
                SS_LOG_ERROR(L"CacheManager", L"Invalid hex length: %zu", hex.size());
                return L"";
            }

            for (wchar_t c : hex) {
                if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                    SS_LOG_ERROR(L"CacheManager", L"Invalid hex character: %c", c);
                    return L"";
                }
            }

            std::wstring path = m_baseDir;
            if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
            path += hex.substr(0, 2);
            path.push_back(L'\\');
            path += hex;
            path += L".cache";

            // ? CANONICALIZE PATH (prevent ".." traversal)
            wchar_t canonical[MAX_PATH];
            if (!GetFullPathNameW(path.c_str(), MAX_PATH, canonical, nullptr)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"GetFullPathNameW failed");
                return L"";
            }

            // ? VERIFY PATH STAYS WITHIN BASE DIR
            std::wstring canonicalPath(canonical);
            if (canonicalPath.size() < m_baseDir.size() ||
                _wcsnicmp(canonicalPath.c_str(), m_baseDir.c_str(), m_baseDir.size()) != 0) {
                SS_LOG_ERROR(L"CacheManager", L"Path traversal detected: %ls", canonical);
                return L"";
            }

            return canonicalPath;
        }

        bool CacheManager::persistWrite(const std::wstring& key, const Entry& e) {
            if (m_baseDir.empty()) return false;

            // ? DISK LOCK + OPERATION COUNTER
            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            if (!ensureSubdirForHash(hex.substr(0, 2))) return false;

            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false; // Validation failed

            // temp file name
            wchar_t tempPath[MAX_PATH] = {};
            swprintf_s(tempPath, L"%s.tmp.%08X%08X",
                finalPath.c_str(),
                (unsigned)GetTickCount64(),
                (unsigned)(reinterpret_cast<uintptr_t>(this) & 0xFFFFFFFF));

            // ? RAII FILE HANDLE
            FileHandle hFile(CreateFileW(tempPath,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                nullptr));

            if (!hFile.IsValid()) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"CreateFileW (temp) failed: %ls", tempPath);
                return false;
            }

            ULARGE_INTEGER u{};
            u.LowPart = e.expire.dwLowDateTime;
            u.HighPart = e.expire.dwHighDateTime;

            CacheFileHeader hdr{};
            hdr.magic = kCacheMagic;
            hdr.version = kCacheVersion;
            hdr.reserved = 0;
            hdr.expire100ns = u.QuadPart;
            hdr.flags = (e.sliding ? 0x1 : 0) | (e.persistent ? 0x2 : 0);
            const uint32_t keyBytes = static_cast<uint32_t>(key.size() * sizeof(wchar_t));
            hdr.keyBytes = keyBytes;
            hdr.valueBytes = static_cast<uint64_t>(e.value.size());
            hdr.ttlMs = static_cast<uint64_t>(e.ttl.count());

            DWORD written = 0;
            BOOL ok = WriteFile(hFile.Get(), &hdr, sizeof(hdr), &written, nullptr);
            if (!ok || written != sizeof(hdr)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile header failed");
                hFile.Close();
                DeleteFileW(tempPath);
                return false;
            }

            // Key bytes
            if (keyBytes > 0) {
                ok = WriteFile(hFile.Get(), key.data(), keyBytes, &written, nullptr);
                if (!ok || written != keyBytes) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile key failed");
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // Value
            if (!e.value.empty()) {
                ok = WriteFile(hFile.Get(), e.value.data(), static_cast<DWORD>(e.value.size()), &written, nullptr);
                if (!ok || written != e.value.size()) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile value failed");
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // flush and close
            FlushFileBuffers(hFile.Get());
            hFile.Close(); // ? EXPLICIT CLOSE BEFORE MOVE

            // atomic replace
            if (!MoveFileExW(tempPath, finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"MoveFileExW failed to replace %ls", finalPath.c_str());
                DeleteFileW(tempPath);
                return false;
            }

            return true;
        }


        bool CacheManager::persistRead(const std::wstring& key, Entry& out) {
            if (m_baseDir.empty()) return false;

            // ? DISK LOCK + OPERATION COUNTER
            SRWShared diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false;

            // ? REMOVED FILE_SHARE_DELETE (VULN-005 fix)
            FileHandle hFile(CreateFileW(finalPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ, // ? NO FILE_SHARE_DELETE
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr));

            if (!hFile.IsValid()) {
                return false;
            }

            CacheFileHeader hdr{};
            DWORD read = 0;

            if (!ReadFile(hFile.Get(), &hdr, sizeof(hdr), &read, nullptr) || read != sizeof(hdr)) {
                return false;
            }

            //VALIDATE MAGIC AND VERSION
            if (hdr.magic != kCacheMagic) {
                SS_LOG_WARN(L"CacheManager", L"Invalid magic in cache file: %ls (got 0x%08X, expected 0x%08X)",
                    finalPath.c_str(), hdr.magic, kCacheMagic);
                return false;
            }

            if (hdr.version != kCacheVersion) {
                SS_LOG_WARN(L"CacheManager", L"Unsupported version in cache file: %ls (got %u, expected %u)",
                    finalPath.c_str(), hdr.version, kCacheVersion);
                return false;
            }

            // STRICTER KEY SIZE VALIDATION
            constexpr uint32_t MAX_KEY_BYTES = 8192; // 8KB max (4K wchar_t)
            if (hdr.keyBytes == 0 || hdr.keyBytes > MAX_KEY_BYTES) {
                SS_LOG_WARN(L"CacheManager", L"Invalid key size in cache file: %ls (%u bytes)",
                    finalPath.c_str(), hdr.keyBytes);
                return false;
            }

            // CHECK IF keyBytes IS MULTIPLE OF sizeof(wchar_t)
            if (hdr.keyBytes % sizeof(wchar_t) != 0) {
                SS_LOG_WARN(L"CacheManager", L"Key size not aligned to wchar_t: %ls (%u bytes)",
                    finalPath.c_str(), hdr.keyBytes);
                return false;
            }

            // VALUE SIZE VALIDATION
            constexpr uint64_t MAX_VALUE_BYTES = 100ULL * 1024 * 1024; // 100MB
            if (hdr.valueBytes > MAX_VALUE_BYTES) {
                SS_LOG_WARN(L"CacheManager", L"Value too large in cache file: %ls (%llu bytes)",
                    finalPath.c_str(), hdr.valueBytes);
                return false;
            }

            //TOTAL FILE SIZE VALIDATION
            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFile.Get(), &fileSize)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"GetFileSizeEx failed");
                return false;
            }

            const uint64_t expectedSize = sizeof(CacheFileHeader) +
                static_cast<uint64_t>(hdr.keyBytes) +
                hdr.valueBytes;

            if (static_cast<uint64_t>(fileSize.QuadPart) < expectedSize) {
                SS_LOG_WARN(L"CacheManager", L"File too small (possible truncation): %ls", finalPath.c_str());
                return false;
            }

            // Read key
            std::vector<wchar_t> keyBuf;
            try {
                keyBuf.resize(hdr.keyBytes / sizeof(wchar_t));
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"CacheManager", L"Memory allocation failed for key buffer");
                return false;
            }

            read = 0;
            if (hdr.keyBytes > 0) {
                if (!ReadFile(hFile.Get(), keyBuf.data(), hdr.keyBytes, &read, nullptr) || read != hdr.keyBytes) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile key failed");
                    return false;
                }
            }

            // VERIFY KEY MATCHES
            if (key.size() != keyBuf.size() ||
                (hdr.keyBytes > 0 && wmemcmp(key.data(), keyBuf.data(), keyBuf.size()) != 0)) {
                SS_LOG_WARN(L"CacheManager", L"Key mismatch for cache file: %ls", finalPath.c_str());
                return false;
            }

            // Read value
            std::vector<uint8_t> value;
            try {
                value.resize(static_cast<size_t>(hdr.valueBytes));
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"CacheManager", L"Memory allocation failed for value buffer");
                return false;
            }

            read = 0;
            if (hdr.valueBytes > 0) {
                if (!ReadFile(hFile.Get(), value.data(), static_cast<DWORD>(hdr.valueBytes), &read, nullptr) ||
                    read != static_cast<DWORD>(hdr.valueBytes)) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile value failed");
                    return false;
                }
            }

            // Fill output
            out.key = key;
            out.value = std::move(value);
            out.sizeBytes = (key.size() * sizeof(wchar_t)) + out.value.size() + sizeof(Entry);

            ULARGE_INTEGER u{};
            u.QuadPart = hdr.expire100ns;
            out.expire.dwLowDateTime = u.LowPart;
            out.expire.dwHighDateTime = u.HighPart;

            out.sliding = (hdr.flags & 0x1) != 0;
            out.persistent = (hdr.flags & 0x2) != 0;
            out.ttl = std::chrono::milliseconds(hdr.ttlMs);

            return true;
        }
        bool CacheManager::persistRemoveByKey(const std::wstring& key) {
            if (m_baseDir.empty()) return false;

            // ? DISK LOCK + OPERATION COUNTER
            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false;

            if (!DeleteFileW(finalPath.c_str())) {
                DWORD e = GetLastError();
                if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"DeleteFile failed: %ls", finalPath.c_str());
                    return false;
                }
            }
            return true;
        }


        // ---- Hashing ----

        std::wstring CacheManager::hashKeyToHex(const std::wstring& key) const {
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(key.data());
            const ULONG cb = static_cast<ULONG>(key.size() * sizeof(wchar_t));

            // VALIDATE INPUT SIZE
            if (cb == 0) {
                SS_LOG_ERROR(L"CacheManager", L"Empty key for hashing");
                return L"";
            }

            const auto& api = BcryptApi::Instance();
            if (!api.available() || m_hmacKey.empty()) {
                SS_LOG_ERROR(L"CacheManager", L"BCrypt unavailable or HMAC key not initialized - cannot hash securely");
                return L""; // ? FAIL SECURE - don't use weak hash
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;

            // ? USE HMAC-SHA256
            NTSTATUS st = api.BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, 
                                                           nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (st != 0 || !hAlg) {
                SS_LOG_ERROR(L"CacheManager", L"BCryptOpenAlgorithmProvider failed (HMAC): 0x%08X", st);
                return L"";
            }

            st = api.BCryptCreateHash(hAlg, &hHash, nullptr, 0, 
                                      const_cast<PUCHAR>(m_hmacKey.data()), 
                                      static_cast<ULONG>(m_hmacKey.size()), 0);
            if (st != 0 || !hHash) {
                api.BCryptCloseAlgorithmProvider(hAlg, 0);
                SS_LOG_ERROR(L"CacheManager", L"BCryptCreateHash failed (HMAC): 0x%08X", st);
                return L"";
            }

            if (cb > 0) {
                st = api.BCryptHashData(hHash, const_cast<PUCHAR>(bytes), cb, 0);
            }

            uint8_t digest[32] = {}; // SHA-256 = 32 bytes
            if (st == 0) {
                st = api.BCryptFinishHash(hHash, digest, sizeof(digest), 0);
            }

            api.BCryptDestroyHash(hHash);
            api.BCryptCloseAlgorithmProvider(hAlg, 0);

            if (st != 0) {
                SS_LOG_ERROR(L"CacheManager", L"HMAC computation failed: 0x%08X", st);
                return L"";
            }

            return ToHex(digest, sizeof(digest));
        }

        // ---- Time helpers ----

        FILETIME CacheManager::nowFileTime() {
            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            return ft;
        }

        bool CacheManager::fileTimeLessOrEqual(const FILETIME& a, const FILETIME& b) {
            // Returns true if a <= b (i.e., 'a' is earlier than or equal to 'b')
            if (a.dwHighDateTime < b.dwHighDateTime) return true;
            if (a.dwHighDateTime > b.dwHighDateTime) return false;
            return a.dwLowDateTime <= b.dwLowDateTime;
        }

	}// namespace Utils
}// namespace ShadowStrike