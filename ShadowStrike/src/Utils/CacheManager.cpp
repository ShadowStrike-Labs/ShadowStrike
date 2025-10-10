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
                auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

                // Convert to 100ns intervals (Windows epoch is 1601, Unix is 1970)
                // Add 116444736000000000 to convert from Unix epoch to Windows epoch
                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
                uint64_t filetime = static_cast<uint64_t>(microseconds) * 10ULL + EPOCH_DIFF;

                return filetime;
            }

            // Convert FILETIME (100ns ticks) back to system_clock::time_point
            std::chrono::system_clock::time_point FileTimeToTimePoint(uint64_t filetime) {
                if (filetime == 0) {
                    return std::chrono::system_clock::time_point{};
                }

                constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;

                if (filetime < EPOCH_DIFF) {
                    return std::chrono::system_clock::time_point{};
                }

                uint64_t unix_time_100ns = filetime - EPOCH_DIFF;
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
            //initialize atomic timestamp
            auto now = std::chrono::system_clock::now();
            m_lastMaint.store(TimePointToFileTime(now), std::memory_order_release);
        }

        CacheManager::~CacheManager() {
            Shutdown();
        }


        void CacheManager::Initialize(const std::wstring& baseDir, size_t maxEntries, size_t maxBytes, std::chrono::milliseconds maintenanceInterval) {
            if (m_maintThread.joinable()) {
                // already initialized
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

            m_shutdown.store(false);
            m_maintThread = std::thread(&CacheManager::maintenanceThread, this);
            SS_LOG_INFO(L"CacheManager", L"Initialized. Limits: maxEntries=%zu, maxBytes=%zu", maxEntries, maxBytes);
        }

        void CacheManager::Shutdown() {
            if (!m_maintThread.joinable()) {
                return;
            }

            m_shutdown.store(true);
            if (m_maintThread.joinable()) {
                m_maintThread.join();
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

            FILETIME now = nowFileTime();

            // Calculate expiration time with overflow protection
            ULARGE_INTEGER ua{}, ub{};
            ua.LowPart = now.dwLowDateTime;
            ua.HighPart = now.dwHighDateTime;

            const uint64_t delta100ns = static_cast<uint64_t>(ttl.count()) * 10000ULL;

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
            std::shared_ptr<Entry> entryToUpdate;

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

                            // MARK FOR PERSISTENCE UPDATE
                            if (e->persistent) {
                                needsPersist = true;
                                entryToUpdate = e; // Keep shared_ptr alive
                            }
                        }
                    }

                    // Copy data BEFORE releasing lock
                    outData = e->value;
                    touchLRU_NoLock(key, e);

                    // DON'T RETURN YET - need to persist outside lock
                }
            } // RELEASE LOCK HERE

            // PERSIST OUTSIDE OF LOCK (prevents deadlock)
            if (needsPersist && entryToUpdate) {
                if (!persistWrite(key, *entryToUpdate)) {
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

            //Clear the files on the disk (*.cache)
            WIN32_FIND_DATAW fd{};
            std::wstring mask = m_baseDir;
            if (!mask.empty() && mask.back() != L'\\') mask.push_back(L'\\');
            mask += L"*";
            HANDLE h = FindFirstFileW(mask.c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
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

        // ---- Internal helpers ----

        void CacheManager::maintenanceThread() {
            while (!m_shutdown.load()) {
                const auto sleepStep = std::chrono::milliseconds(200);
                auto waited = std::chrono::milliseconds(0);
                while (!m_shutdown.load() && waited < m_maintInterval) {
                    std::this_thread::sleep_for(sleepStep);
                    waited += sleepStep;
                }
                if (m_shutdown.load()) break;
                performMaintenance();
            }
        }

        void CacheManager::performMaintenance() {
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

            // Delete from disk if persistent
            if (!removed.empty()) {
                for (const auto& k : removed) {
                    persistRemoveByKey(k);
                }
            }
        }

        void CacheManager::evictIfNeeded_NoLock() {
			//Dont evict if no limits
            if (m_maxEntries == 0 && m_maxBytes == 0) return;

            while (!m_lru.empty() &&
                ((m_maxEntries > 0 && m_map.size() > m_maxEntries) ||
                    (m_maxBytes > 0 && m_totalBytes > m_maxBytes)))
            {
                const std::wstring& victimKey = m_lru.back();
                auto it = m_map.find(victimKey);
                if (it == m_map.end()) {
                    m_lru.pop_back();
                    continue;
                }
                m_totalBytes -= it->second->sizeBytes;
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
            // return e.expire <= now
            return fileTimeLessOrEqual(e.expire, now);
        }

        void CacheManager::touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& e) {
            m_lru.erase(e->lruIt);
            m_lru.push_front(key);
            e->lruIt = m_lru.begin();
        }


        // ---- Persistence ----

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
            // Create it as multiple levels : ShadowStrike and Cache
            std::wstring path = m_baseDir;
            // CreateDirectoryW If the parent directories do not exist, you will need to create them one by one.
            // Simply: Let's consider the first two levels in order.
            // e.g., C:\ProgramData\ShadowStrike\Cache
            size_t pos = m_baseDir.find(L'\\');
            (void)pos; //Already waiting absolute path
            if (!CreateDirectoryW(m_baseDir.c_str(), nullptr)) {
                DWORD e = GetLastError();
                if (e != ERROR_ALREADY_EXISTS) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"CreateDirectory failed: %ls", m_baseDir.c_str());
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
            std::wstring path = m_baseDir;
            if (!path.empty() && path.back() != L'\\') path.push_back(L'\\');
            path += hex.substr(0, 2);
            path.push_back(L'\\');
            path += hex;
            path += L".cache";
            return path;
        }

        bool CacheManager::persistWrite(const std::wstring& key, const Entry& e) {
            if (m_baseDir.empty()) return false;

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2) return false;
            if (!ensureSubdirForHash(hex.substr(0, 2))) return false;

            std::wstring finalPath = pathForKeyHex(hex);

            // temp file name
            wchar_t tempPath[MAX_PATH] = {};
            swprintf_s(tempPath, L"%s.tmp.%08X%08X",
                finalPath.c_str(),
                (unsigned)GetTickCount64(),
                (unsigned)(reinterpret_cast<uintptr_t>(this) & 0xFFFFFFFF));

            HANDLE h = CreateFileW(tempPath,
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                nullptr);
            if (h == INVALID_HANDLE_VALUE) {
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
            BOOL ok = WriteFile(h, &hdr, sizeof(hdr), &written, nullptr);
            if (!ok || written != sizeof(hdr)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile header failed");
                CloseHandle(h);
                DeleteFileW(tempPath);
                return false;
            }

            // Key bytes
            if (keyBytes > 0) {
                ok = WriteFile(h, key.data(), keyBytes, &written, nullptr);
                if (!ok || written != keyBytes) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile key failed");
                    CloseHandle(h);
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // Value
            if (!e.value.empty()) {
                ok = WriteFile(h, e.value.data(), static_cast<DWORD>(e.value.size()), &written, nullptr);
                if (!ok || written != e.value.size()) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"WriteFile value failed");
                    CloseHandle(h);
                    DeleteFileW(tempPath);
                    return false;
                }
            }

            // flush and close
            FlushFileBuffers(h);
            CloseHandle(h);

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

            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2) return false;
            std::wstring finalPath = pathForKeyHex(hex);

            HANDLE h = CreateFileW(finalPath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, // Sequential hint
                nullptr);

            if (h == INVALID_HANDLE_VALUE) {
                return false;
            }

            // RAII handle wrapper
            auto handleGuard = [h]() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); };
            struct HandleRAII {
                HANDLE h;
                ~HandleRAII() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
            } hGuard{ h };

            CacheFileHeader hdr{};
            DWORD read = 0;

            if (!ReadFile(h, &hdr, sizeof(hdr), &read, nullptr) || read != sizeof(hdr)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile header failed");
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
            if (!GetFileSizeEx(h, &fileSize)) {
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
                if (!ReadFile(h, keyBuf.data(), hdr.keyBytes, &read, nullptr) || read != hdr.keyBytes) {
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
                if (!ReadFile(h, value.data(), static_cast<DWORD>(hdr.valueBytes), &read, nullptr) ||
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
            const std::wstring hex = hashKeyToHex(key);
            if (hex.size() < 2) return false;
            std::wstring finalPath = pathForKeyHex(hex);
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
            const auto& api = BcryptApi::Instance();
            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(key.data());
            const ULONG cb = static_cast<ULONG>(key.size() * sizeof(wchar_t));

            // VALIDATE INPUT SIZE
            if (cb == 0) {
                SS_LOG_WARN(L"CacheManager", L"Empty key for hashing");
                return L"00000000000000000000000000000000"; // 32 hex digits (SHA-256)
            }

            if (api.available()) {
                BCRYPT_ALG_HANDLE hAlg = nullptr;
                BCRYPT_HASH_HANDLE hHash = nullptr;

                NTSTATUS st = api.BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
                if (st == 0 && hAlg) {
                    st = api.BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);
                    if (st == 0 && hHash) {
                        if (cb > 0) {
                            st = api.BCryptHashData(hHash, const_cast<PUCHAR>(bytes), cb, 0);
                        }

                        uint8_t digest[32] = {}; // SHA-256 = 32 bytes
                        if (st == 0) {
                            st = api.BCryptFinishHash(hHash, digest, sizeof(digest), 0);
                            if (st == 0) {
                                api.BCryptDestroyHash(hHash);
                                api.BCryptCloseAlgorithmProvider(hAlg, 0);
                                return ToHex(digest, sizeof(digest));
                            }
                        }
                        api.BCryptDestroyHash(hHash);
                    }
                    api.BCryptCloseAlgorithmProvider(hAlg, 0);
                }
            }

            // IMPROVED FALLBACK: USE DOUBLE HASH (FNV-1a + SipHash-like)
            // This is much better than single FNV-1a for cache key safety

            // First pass: FNV-1a 64
            uint64_t h1 = Fnv1a64(bytes, cb);

            // Second pass: Use h1 as seed for another hash
            // Mix in key bytes again with different constants
            uint64_t h2 = 0xcbf29ce484222325ULL; // FNV offset basis (different)
            for (size_t i = 0; i < cb; ++i) {
                h2 ^= bytes[i];
                h2 *= 0x100000001b3ULL; // FNV prime
                h2 ^= (h1 >> (i % 64)); // Mix in h1
            }

            // Combine both hashes
            uint8_t buf[16]; // 128-bit combined hash
            for (int i = 0; i < 8; ++i) {
                buf[i] = static_cast<uint8_t>((h1 >> (8 * i)) & 0xFF);
                buf[i + 8] = static_cast<uint8_t>((h2 >> (8 * i)) & 0xFF);
            }

            SS_LOG_WARN(L"CacheManager", L"Using fallback hash (BCrypt unavailable)");
            return ToHex(buf, sizeof(buf));
        }

        // ---- Time helpers ----

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

	}// namespace Utils
}// namespace ShadowStrike