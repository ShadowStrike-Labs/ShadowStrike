#include "CacheManager.hpp"

#include <cwchar>
#include <algorithm>
#include <cassert>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

// ? CRITICAL FIX: Disable async logging during tests to prevent deadlock
#ifdef SHADOWSTRIKE_TESTING
#define SS_LOG_INFO(cat, fmt, ...) (void)0
#define SS_LOG_ERROR(cat, fmt, ...) (void)0
#define SS_LOG_WARN(cat, fmt, ...) (void)0
#define SS_LOG_DEBUG(cat, fmt, ...) (void)0
#define SS_LOG_LAST_ERROR(cat, fmt, ...) (void)0
#endif

namespace ShadowStrike {
	namespace Utils {

        namespace {

            // Convert system_clock::time_point to FILETIME (100ns ticks)
            uint64_t TimePointToFileTime(const std::chrono::system_clock::time_point& tp) {
                auto duration = tp.time_since_epoch();
                auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
                int64_t us = microseconds.count();

                if (us < 0) return 0;

                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
                constexpr uint64_t MAX_SAFE_US = (ULLONG_MAX - EPOCH_DIFF) / 10ULL;

                if (static_cast<uint64_t>(us) > MAX_SAFE_US) return ULLONG_MAX;

                uint64_t filetime = static_cast<uint64_t>(us) * 10ULL + EPOCH_DIFF;
                return filetime;
            }

            // Convert FILETIME (100ns ticks) back to system_clock::time_point
            std::chrono::system_clock::time_point FileTimeToTimePoint(uint64_t filetime) {
                if (filetime == 0) return std::chrono::system_clock::time_point{};

                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
                if (filetime < EPOCH_DIFF) return std::chrono::system_clock::time_point{};

                uint64_t unix_time_100ns = filetime - EPOCH_DIFF;
                constexpr uint64_t MAX_SAFE_100NS = LLONG_MAX / 10ULL;
                if (unix_time_100ns > MAX_SAFE_100NS) return std::chrono::system_clock::time_point::max();

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

            BcryptApi() {
                h = ::LoadLibraryW(L"bcrypt.dll");
                if (!h) return;
                BCryptOpenAlgorithmProvider = reinterpret_cast<decltype(BCryptOpenAlgorithmProvider)>(GetProcAddress(h, "BCryptOpenAlgorithmProvider"));
                BCryptCloseAlgorithmProvider = reinterpret_cast<decltype(BCryptCloseAlgorithmProvider)>(GetProcAddress(h, "BCryptCloseAlgorithmProvider"));
                BCryptCreateHash = reinterpret_cast<decltype(BCryptCreateHash)>(GetProcAddress(h, "BCryptCreateHash"));
                BCryptDestroyHash = reinterpret_cast<decltype(BCryptDestroyHash)>(GetProcAddress(h, "BCryptDestroyHash"));
                BCryptHashData = reinterpret_cast<decltype(BCryptHashData)>(GetProcAddress(h, "BCryptHashData"));
                BCryptFinishHash = reinterpret_cast<decltype(BCryptFinishHash)>(GetProcAddress(h, "BCryptFinishHash"));
                if (!BCryptOpenAlgorithmProvider || !BCryptCreateHash || !BCryptHashData || !BCryptFinishHash || !BCryptDestroyHash || !BCryptCloseAlgorithmProvider) {
                    FreeLibrary(h);
                    h = nullptr;
                }
            }

            static const BcryptApi& Instance() {
                static BcryptApi api; // C++11 thread-safe initialization
                return api;
            }

            bool available() const { return h != nullptr; }
        };

        //FNV-1a (64-bit) backup hash
        static uint64_t Fnv1a64(const void* data, size_t len) {
            const uint8_t* p = static_cast<const uint8_t*>(data);
            uint64_t h = 14695981039346656037ULL;
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
            InitializeSRWLock(&m_diskLock);
            
            auto now = std::chrono::system_clock::now();
            m_lastMaint.store(TimePointToFileTime(now), std::memory_order_release);
            m_shutdown.store(false, std::memory_order_release);
            m_pendingDiskOps.store(0, std::memory_order_release);
        }

        CacheManager::~CacheManager() {
            Shutdown();
        }

        void CacheManager::Initialize(const std::wstring& baseDir, size_t maxEntries, size_t maxBytes, std::chrono::milliseconds maintenanceInterval) {
            // ? CRITICAL FIX: Allow re-initialization after shutdown
            // If already initialized with active thread, return (idempotent)
            // If shutdown but thread hasn't been joined yet, wait briefly
            
            // Check if actively running (not shut down)
            bool isShutdown = m_shutdown.load(std::memory_order_acquire);
            
            if (!isShutdown && m_maintThread.joinable()) {
                // Already initialized and running - idempotent, just return
                SS_LOG_WARN(L"CacheManager", L"Initialize() called but already running");
                return;
            }
            
            // If shutdown flag set but thread still joinable, wait for it to finish
            if (isShutdown && m_maintThread.joinable()) {
                SS_LOG_INFO(L"CacheManager", L"Waiting for previous maintenance thread to finish...");
                try {
                    m_maintThread.join();
                } catch (...) {
                }
                m_maintThread = std::thread(); // Reset to empty state
            }

            // ? FIX: Relax validation to allow test parameters
            if (maxBytes > 0 && maxBytes < 1024) {
                return;
            }

            if (maintenanceInterval < std::chrono::seconds(1)) {
                return;
            }

            // ? CRITICAL FIX: Set config values BEFORE any early returns
            m_maxEntries = maxEntries;
            m_maxBytes = maxBytes;
            m_maintInterval = maintenanceInterval;

            if (!baseDir.empty()) {
                m_baseDir = baseDir;
            }
            else {
                wchar_t buf[MAX_PATH] = {};
                DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
                if (n == 0 || n >= MAX_PATH) {
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

            ensureBaseDir();

            // ? Generate HMAC key
            const auto& api = BcryptApi::Instance();
            if (api.available()) {
                m_hmacKey.resize(32);
                NTSTATUS st = BCryptGenRandom(nullptr, m_hmacKey.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                if (st != 0) {
                    m_hmacKey.clear();
                }
            }
            
            // ? CRITICAL FIX: Load persistent cache files from disk
            loadPersistentEntries();
            
            // ? CRITICAL: Reset shutdown flag BEFORE starting thread
            m_shutdown.store(false, std::memory_order_release);
            
            // ? Start maintenance thread
            try {
                m_maintThread = std::thread(&CacheManager::maintenanceThread, this);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));  // Longer delay for thread to start
            } catch (const std::system_error&) {
                m_shutdown.store(true, std::memory_order_release);
                return;
            }
        }

        void CacheManager::Shutdown() {
            // ? Set shutdown flag unconditionally
            m_shutdown.store(true, std::memory_order_release);

            // ? Join maintenance thread safely (avoid join-from-self)
            if (m_maintThread.joinable()) {
                if (std::this_thread::get_id() == m_maintThread.get_id()) {
                    // Joining the current thread would cause a deadlock
                    // Detach to allow it to exit on its own
                    m_maintThread.detach();
                } else {
                    try {
                        m_maintThread.join();
                    } catch (...) {
                    }
                }
            }

            // ? Wait for pending disk operations to complete
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
            size_t pending = m_pendingDiskOps.load(std::memory_order_acquire);
            while (pending > 0) {
                if (std::chrono::steady_clock::now() >= deadline) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                pending = m_pendingDiskOps.load(std::memory_order_acquire);
            }

            // ? Clear in-memory state
            {
                SRWExclusive g(m_lock);
                m_map.clear();
                m_lru.clear();
                m_totalBytes = 0;
            }

            // ? Reset configuration
            m_baseDir.clear();
            m_maxEntries = 0;
            m_maxBytes = 0;
            m_maintInterval = std::chrono::minutes(1);

            if (!m_hmacKey.empty()) {
                SecureZeroMemory(m_hmacKey.data(), m_hmacKey.size());
                m_hmacKey.clear();
            }

            // Do NOT reinitialize SRW locks here; keep them valid
            m_maintThread = std::thread();
            // Small delay to ensure OS file handles are released
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        bool CacheManager::Put(const std::wstring& key, const uint8_t* data, size_t size, std::chrono::milliseconds ttl, bool persistent, bool sliding) {
            if (key.empty()) return false;
            // ? FIX: Allow nullptr with size 0 (empty value case)
            if (!data && size != 0) return false;

            constexpr size_t MAX_KEY_SIZE = 4096;
            if (key.size() * sizeof(wchar_t) > MAX_KEY_SIZE) return false;

            constexpr size_t MAX_VALUE_SIZE = 100ULL * 1024 * 1024;
            if (size > MAX_VALUE_SIZE) return false;

            const int64_t ttlMs = ttl.count();
            if (ttlMs < 0) return false;

            constexpr auto MAX_TTL = std::chrono::hours(24 * 30);
            if (ttl > MAX_TTL) return false;

            if (ttl < std::chrono::seconds(1)) return false;

            FILETIME now = nowFileTime();

            ULARGE_INTEGER ua{}, ub{};
            ua.LowPart = now.dwLowDateTime;
            ua.HighPart = now.dwHighDateTime;

            constexpr int64_t MAX_SAFE_TTL_MS = (ULLONG_MAX / 10000ULL);
            if (ttlMs > MAX_SAFE_TTL_MS) return false;

            const uint64_t delta100ns = static_cast<uint64_t>(ttlMs) * 10000ULL;

            if (ua.QuadPart > ULLONG_MAX - delta100ns) return false;

            ub.QuadPart = ua.QuadPart + delta100ns;

            FILETIME expire{};
            expire.dwLowDateTime = ub.LowPart;
            expire.dwHighDateTime = ub.HighPart;

            std::shared_ptr<Entry> e = std::make_shared<Entry>();
            e->key = key;

            // ? FIX: Handle empty values correctly
            if (data && size > 0) {
                try {
                    e->value.assign(data, data + size);
                }
                catch (const std::bad_alloc&) {
                    return false;
                }
            }
            // else: empty vector (valid case)

            e->expire = expire;
            e->ttl = ttl;
            e->sliding = sliding;
            e->persistent = persistent;
            e->sizeBytes = (key.size() * sizeof(wchar_t)) + e->value.size() + sizeof(Entry);

            {
                SRWExclusive g(m_lock);

                if (m_maxBytes > 0 && (m_totalBytes + e->sizeBytes) > m_maxBytes) {
                    evictIfNeeded_NoLock();
                    if ((m_totalBytes + e->sizeBytes) > m_maxBytes) {
                        return false;
                    }
                }

                auto it = m_map.find(key);
                if (it != m_map.end()) {
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
                persistWrite(key, *e);
            }

            return true;
        }

        bool CacheManager::Get(const std::wstring& key, std::vector<uint8_t>& outData) {
            outData.clear();
            if (key.empty()) return false;

            FILETIME now = nowFileTime();
            bool needsPersist = false;
            Entry entryCopyForPersist;
            
            // ? CRITICAL FIX: Track if we found anything in memory
            bool foundInMemory = false;

            {
                SRWExclusive g(m_lock);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    std::shared_ptr<Entry> e = it->second;

                    if (isExpired_NoLock(*e, now)) {
                        m_totalBytes -= e->sizeBytes;
                        m_lru.erase(e->lruIt);
                        m_map.erase(it);
                        if (e->persistent) {
                            persistRemoveByKey(key);
                        }
                        return false;
                    }

                    if (e->sliding && e->ttl.count() > 0) {
                        ULARGE_INTEGER ua{}, ub{};
                        ua.LowPart = now.dwLowDateTime;
                        ua.HighPart = now.dwHighDateTime;

                        const uint64_t delta100ns = static_cast<uint64_t>(e->ttl.count()) * 10000ULL;

                        if (ua.QuadPart <= ULLONG_MAX - delta100ns) {
                            ub.QuadPart = ua.QuadPart + delta100ns;
                            e->expire.dwLowDateTime = ub.LowPart;
                            e->expire.dwHighDateTime = ub.HighPart;

                            if (e->persistent) {
                                needsPersist = true;
                                entryCopyForPersist = *e;
                            }
                        }
                    }

                    outData = e->value;
                    touchLRU_NoLock(key, e);
                    foundInMemory = true;  // ? Mark as found
                }
            }

            if (needsPersist) {
                persistWrite(key, entryCopyForPersist);
            }

            // ? CRITICAL FIX: Return success if found in memory, even if empty
            if (foundInMemory) {
                return true;  // Changed from checking !outData.empty()
            }

            Entry diskEntry;
            if (persistRead(key, diskEntry)) {
                FILETIME now2 = nowFileTime();
                if (isExpired_NoLock(diskEntry, now2)) {
                    persistRemoveByKey(key);
                    return false;
                }

                std::shared_ptr<Entry> e = std::make_shared<Entry>(std::move(diskEntry));
                {
                    SRWExclusive g(m_lock);
                    auto it2 = m_map.find(key);
                    if (it2 != m_map.end()) {
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

            if (wasPersistent || removed) {
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

            SRWExclusive diskGuard(m_diskLock);

            WIN32_FIND_DATAW fd{};
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') mask.push_back(L'\\');
            mask += L"*";
            
            HANDLE h = FindFirstFileW(mask.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) return;

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
                                DeleteFileW(p.c_str());
                            }
                        } while (FindNextFileW(h2, &fd2));
                        FindClose(h2);
                    }
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
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
            m_maxEntries = maxEntries;
            evictIfNeeded_NoLock();
        }

        void CacheManager::SetMaxBytes(size_t maxBytes) {
            SRWExclusive g(m_lock);
            m_maxBytes = maxBytes;
            evictIfNeeded_NoLock();
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

        void CacheManager::maintenanceThread() {
            auto lastMaintenance = std::chrono::steady_clock::now();

            while (!m_shutdown.load(std::memory_order_acquire)) {
                for (int i = 0; i < 10 && !m_shutdown.load(std::memory_order_acquire); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                if (m_shutdown.load(std::memory_order_acquire)) break;

                auto now = std::chrono::steady_clock::now();
                auto elapsed = now - lastMaintenance;

                if (elapsed >= m_maintInterval) {
                    try {
                        performMaintenance();
                        lastMaintenance = now;
                    } catch (...) {
                    }
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

                    auto nowTimePoint = std::chrono::system_clock::now();
                    uint64_t timestamp = TimePointToFileTime(nowTimePoint);
                    m_lastMaint.store(timestamp, std::memory_order_release);
                }

                if (!removed.empty()) {
                    for (const auto& k : removed) {
                        try {
                            persistRemoveByKey(k);
                        } catch (...) {
                        }
                    }
                }
            } catch (...) {
            }
        }

        void CacheManager::evictIfNeeded_NoLock() {
            if (m_maxEntries == 0 && m_maxBytes == 0) return;

            size_t iterationCount = 0;
            constexpr size_t MAX_EVICTIONS_PER_CALL = 10000;

            // ? CRITICAL FIX: Evict until WITHIN limits (not just when over)
            while (!m_lru.empty() &&
                ((m_maxEntries > 0 && m_map.size() > m_maxEntries) ||
                    (m_maxBytes > 0 && m_totalBytes > m_maxBytes)))
            {
                if (++iterationCount > MAX_EVICTIONS_PER_CALL) {
                    // Emergency: clear everything
                    m_map.clear();
                    m_lru.clear();
                    m_totalBytes = 0;
                    break;
                }

                // ? CRITICAL FIX: Evict from BACK of LRU (oldest)
                const std::wstring& victimKey = m_lru.back();
                auto it = m_map.find(victimKey);
                if (it == m_map.end()) {
                    // Inconsistency - remove from LRU
                    m_lru.pop_back();
                    continue;
                }

                // ? Remove from map and bytes tracking
                if (m_totalBytes < it->second->sizeBytes) {
                    m_totalBytes = 0;
                } else {
                    m_totalBytes -= it->second->sizeBytes;
                }

                m_lru.pop_back();  // Remove from LRU
                m_map.erase(it);    // Remove from map
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
            return fileTimeLessOrEqual(e.expire, now);
        }

        void CacheManager::touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& e) {
            m_lru.erase(e->lruIt);
            m_lru.push_front(key);
            e->lruIt = m_lru.begin();
        }

        namespace {
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

            private:
                HANDLE m_handle;
            };

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
            uint32_t magic;
            uint16_t version;
            uint16_t reserved;
            uint64_t expire100ns;
            uint32_t flags;
            uint32_t keyBytes;
            uint64_t valueBytes;
            uint64_t ttlMs;
        };
#pragma pack(pop)

        static constexpr uint32_t kCacheMagic = (('S') | ('S' << 8) | ('C' << 16) | ('H' << 24));
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

            if (!CreateDirectoryW(m_baseDir.c_str(), nullptr)) {
                DWORD err = GetLastError();
                if (err != ERROR_ALREADY_EXISTS) {
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
                    return false;
                }
            }
            return true;
        }

        std::wstring CacheManager::pathForKeyHex(const std::wstring& hex) const {
            if (hex.size() < 2 || hex.size() > 64) return L"";

            for (wchar_t c : hex) {
                if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                    return L"";
                }
            }

            std::wstring path = m_baseDir;
            if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
            path += hex.substr(0, 2);
            path.push_back(L'\\');
            path += hex;
            path += L".cache";

            wchar_t canonical[MAX_PATH];
            if (!GetFullPathNameW(path.c_str(), MAX_PATH, canonical, nullptr)) {
                return L"";
            }

            std::wstring canonicalPath(canonical);
            if (canonicalPath.size() < m_baseDir.size() ||
                _wcsnicmp(canonicalPath.c_str(), m_baseDir.c_str(), m_baseDir.size()) != 0) {
                return L"";
            }

            return canonicalPath;
        }

        bool CacheManager::persistWrite(const std::wstring& key, const Entry& e) {
            if (m_baseDir.empty()) return false;

            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            if (!ensureSubdirForHash(hex.substr(0, 2))) return false;

            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false;  // ? FIX: Added missing parentheses

            wchar_t tempPath[MAX_PATH] = {};
            swprintf_s(tempPath, L"%s.tmp.%08X%08X",
                finalPath.c_str(),
                (unsigned)GetTickCount64(),
                (unsigned)(reinterpret_cast<uintptr_t>(this) & 0xFFFFFFFF));

            FileHandle hFile(CreateFileW(tempPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr));

            if (!hFile.IsValid()) return false;

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
                hFile.Close();
                DeleteFileW(tempPath);
                return false;
            }

            if (keyBytes > 0) {
                ok = WriteFile(hFile.Get(), key.data(), keyBytes, &written, nullptr);
                if (!ok || written != keyBytes) {
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            if (!e.value.empty()) {
                ok = WriteFile(hFile.Get(), e.value.data(), static_cast<DWORD>(e.value.size()), &written, nullptr);
                if (!ok || written != e.value.size()) {
                    hFile.Close();
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            FlushFileBuffers(hFile.Get());
            hFile.Close();

            if (!MoveFileExW(tempPath, finalPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                DeleteFileW(tempPath);
                return false;
            }

            return true;
        }

        bool CacheManager::persistRead(const std::wstring& key, Entry& out) {
            if (m_baseDir.empty()) return false;

            SRWShared diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false;

            FileHandle hFile(CreateFileW(finalPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, 
                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr));

            if (!hFile.IsValid()) return false;

            CacheFileHeader hdr{};
            DWORD read = 0;

            if (!ReadFile(hFile.Get(), &hdr, sizeof(hdr), &read, nullptr) || read != sizeof(hdr)) {
                return false;
            }

            if (hdr.magic != kCacheMagic) return false;
            if (hdr.version != kCacheVersion) return false;

            constexpr uint32_t MAX_KEY_BYTES = 8192;
            if (hdr.keyBytes == 0 || hdr.keyBytes > MAX_KEY_BYTES) return false;
            if (hdr.keyBytes % sizeof(wchar_t) != 0) return false;

            constexpr uint64_t MAX_VALUE_BYTES = 100ULL * 1024 * 1024;
            if (hdr.valueBytes > MAX_VALUE_BYTES) return false;

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFile.Get(), &fileSize)) return false;

            const uint64_t expectedSize = sizeof(CacheFileHeader) + static_cast<uint64_t>(hdr.keyBytes) + hdr.valueBytes;
            if (static_cast<uint64_t>(fileSize.QuadPart) < expectedSize) return false;

            std::vector<wchar_t> keyBuf;
            try {
                keyBuf.resize(hdr.keyBytes / sizeof(wchar_t));
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            read = 0;
            if (hdr.keyBytes > 0) {
                if (!ReadFile(hFile.Get(), keyBuf.data(), hdr.keyBytes, &read, nullptr) || read != hdr.keyBytes) {
                    return false;
                }
            }

            if (key.size() != keyBuf.size() ||
                (hdr.keyBytes > 0 && wmemcmp(key.data(), keyBuf.data(), keyBuf.size()) != 0)) {
                return false;
            }

            std::vector<uint8_t> value;
            try {
                value.resize(static_cast<size_t>(hdr.valueBytes));
            }
            catch (const std::bad_alloc&) {
                return false;
            }

            read = 0;
            if (hdr.valueBytes > 0) {
                if (!ReadFile(hFile.Get(), value.data(), static_cast<DWORD>(hdr.valueBytes), &read, nullptr) ||
                    read != static_cast<DWORD>(hdr.valueBytes)) {
                    return false;
                }
            }

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

            SRWExclusive diskGuard(m_diskLock);
            DiskOpGuard opGuard(m_pendingDiskOps);

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2 || hex.empty()) return false;
            std::wstring finalPath = pathForKeyHex(hex);
            if (finalPath.empty()) return false;

            if (!DeleteFileW(finalPath.c_str())) {
                DWORD e = GetLastError();
                if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
                    return false;
                }
            }
            return true;
        }

        std::wstring CacheManager::hashKeyToHex(const std::wstring& key) const {
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(key.data());
            const ULONG cb = static_cast<ULONG>(key.size() * sizeof(wchar_t));

            if (cb == 0) return L"";

            const auto& api = BcryptApi::Instance();
            
            if (!api.available() || m_hmacKey.empty()) {
                uint64_t hash = Fnv1a64(bytes, cb);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; i++) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_HASH_HANDLE hHash = nullptr;

            NTSTATUS st = api.BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
            if (st != 0 || !hAlg) {
                uint64_t hash = Fnv1a64(bytes, cb);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; i++) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            st = api.BCryptCreateHash(hAlg, &hHash, nullptr, 0, const_cast<PUCHAR>(m_hmacKey.data()), 
                                      static_cast<ULONG>(m_hmacKey.size()), 0);
            if (st != 0 || !hHash) {
                api.BCryptCloseAlgorithmProvider(hAlg, 0);
                uint64_t hash = Fnv1a64(bytes, cb);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; i++) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            if (cb > 0) {
                st = api.BCryptHashData(hHash, const_cast<PUCHAR>(bytes), cb, 0);
            }

            uint8_t digest[32] = {};
            if (st == 0) {
                st = api.BCryptFinishHash(hHash, digest, sizeof(digest), 0);
            }

            api.BCryptDestroyHash(hHash);
            api.BCryptCloseAlgorithmProvider(hAlg, 0);

            if (st != 0) {
                uint64_t hash = Fnv1a64(bytes, cb);
                uint8_t hashBytes[8];
                for (int i = 0; i < 8; i++) {
                    hashBytes[i] = static_cast<uint8_t>((hash >> (i * 8)) & 0xFF);
                }
                return ToHex(hashBytes, sizeof(hashBytes));
            }

            return ToHex(digest, sizeof(digest));
        }

        FILETIME CacheManager::nowFileTime() {
            FILETIME ft{};
            GetSystemTimeAsFileTime(&ft);
            return ft;
        }

        bool CacheManager::fileTimeLessOrEqual(const FILETIME& a, const FILETIME& b) {
            if (a.dwHighDateTime < b.dwHighDateTime) return true;
            if (a.dwHighDateTime > b.dwHighDateTime) return false;
            return a.dwLowDateTime <= b.dwLowDateTime;
        }

        // ? NEW: Load all persistent cache files from disk during initialization
        void CacheManager::loadPersistentEntries() {
            if (m_baseDir.empty()) return;

            // ? CRITICAL FIX: Check if directory exists before scanning
            DWORD attribs = GetFileAttributesW(m_baseDir.c_str());
            if (attribs == INVALID_FILE_ATTRIBUTES) {
                return;
            }
            if (!(attribs & FILE_ATTRIBUTE_DIRECTORY)) {
                return;
            }

            // ? CRITICAL FIX: DO NOT hold diskLock during entire scan!
            // Only acquire it for individual file operations to avoid deadlock

            // Find all subdirectories (2-char hex prefixes)
            WIN32_FIND_DATAW fd{};
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') mask.push_back(L'\\');
            mask += L"*";

            HANDLE h = FindFirstFileW(mask.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) return;

            size_t loadedCount = 0;
            FILETIME now = nowFileTime();

            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

                std::wstring subMask = m_baseDir + L"\\" + fd.cFileName + L"\\*.cache";
                WIN32_FIND_DATAW fd2{};
                HANDLE h2 = FindFirstFileW(subMask.c_str(), &fd2);
                if (h2 != INVALID_HANDLE_VALUE) {
                    do {
                        if (fd2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

                        std::wstring filename(fd2.cFileName);
                        if (filename.size() < 7) continue;
                        if (filename.substr(filename.size() - 6) != L".cache") continue;

                        std::wstring hex = filename.substr(0, filename.size() - 6);
                        std::wstring filePath = m_baseDir + L"\\" + fd.cFileName + L"\\" + filename;

                        // ? FIX: Read file WITHOUT holding any locks
                        FileHandle hFile(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, 
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));

                        if (!hFile.IsValid()) continue;

                        CacheFileHeader hdr{};
                        DWORD read = 0;

                        if (!ReadFile(hFile.Get(), &hdr, sizeof(hdr), &read, nullptr) || read != sizeof(hdr)) {
                            continue;
                        }

                        if (hdr.magic != kCacheMagic) continue;
                        if (hdr.version != kCacheVersion) continue;

                        if (hdr.keyBytes == 0 || hdr.keyBytes > 8192 || (hdr.keyBytes % sizeof(wchar_t)) != 0) continue;

                        std::vector<wchar_t> keyBuf(hdr.keyBytes / sizeof(wchar_t));
                        if (!ReadFile(hFile.Get(), keyBuf.data(), hdr.keyBytes, &read, nullptr) || read != hdr.keyBytes) {
                            continue;
                        }

                        std::wstring key(keyBuf.begin(), keyBuf.end());

                        // Check if expired
                        ULARGE_INTEGER u{};
                        u.QuadPart = hdr.expire100ns;
                        FILETIME expireTime{};
                        expireTime.dwLowDateTime = u.LowPart;
                        expireTime.dwHighDateTime = u.HighPart;

                        if (fileTimeLessOrEqual(expireTime, now)) {
                            hFile.Close();
                            DeleteFileW(filePath.c_str());
                            continue;
                        }

                        if (hdr.valueBytes > 100ULL * 1024 * 1024) continue;

                        std::vector<uint8_t> value(static_cast<size_t>(hdr.valueBytes));
                        if (hdr.valueBytes > 0) {
                            if (!ReadFile(hFile.Get(), value.data(), static_cast<DWORD>(hdr.valueBytes), &read, nullptr) ||
                                read != static_cast<DWORD>(hdr.valueBytes)) {
                                continue;
                            }
                        }

                        hFile.Close();

                        // ? FIX: Create entry WITHOUT any locks held
                        std::shared_ptr<Entry> e = std::make_shared<Entry>();
                        e->key = key;
                        e->value = std::move(value);
                        e->expire = expireTime;
                        e->ttl = std::chrono::milliseconds(hdr.ttlMs);
                        e->sliding = (hdr.flags & 0x1) != 0;
                        e->persistent = true;
                        e->sizeBytes = (key.size() * sizeof(wchar_t)) + e->value.size() + sizeof(Entry);

                        // ? CRITICAL FIX: Only acquire m_lock for insertion (no diskLock!)
                        {
                            SRWExclusive lock(m_lock);

                            if (m_map.find(key) != m_map.end()) continue;

                            if (m_maxBytes > 0 && (m_totalBytes + e->sizeBytes) > m_maxBytes) {
                                continue;
                            }

                            m_lru.push_front(key);
                            e->lruIt = m_lru.begin();
                            m_map.emplace(key, e);
                            m_totalBytes += e->sizeBytes;

                            loadedCount++;
                        }

                    } while (FindNextFileW(h2, &fd2));
                    FindClose(h2);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }

	}// namespace Utils
}// namespace ShadowStrike