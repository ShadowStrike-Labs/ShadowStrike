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

            FILETIME now = nowFileTime();

            // expire = now + ttl
            ULARGE_INTEGER ua{}, ub{};
            ua.LowPart = now.dwLowDateTime;
            ua.HighPart = now.dwHighDateTime;
            const uint64_t delta100ns = static_cast<uint64_t>(ttl.count()) * 10000ULL; // ms -> 100ns
            ub.QuadPart = ua.QuadPart + delta100ns;
            FILETIME expire{};
            expire.dwLowDateTime = ub.LowPart;
            expire.dwHighDateTime = ub.HighPart;

            std::shared_ptr<Entry> e = std::make_shared<Entry>();
            e->key = key;
            e->value.assign(data, data + size);
            e->expire = expire;
            e->ttl = ttl;
            e->sliding = sliding;
            e->persistent = persistent;
            e->sizeBytes = e->value.size();

            {
                SRWExclusive g(m_lock);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    // replace existing
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

            {
                SRWExclusive g(m_lock); // exclusive for LRU touch

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    std::shared_ptr<Entry> e = it->second;
                    if (isExpired_NoLock(*e, now)) {
                        // remove expired
                        m_totalBytes -= e->sizeBytes;
                        m_lru.erase(e->lruIt);
                        m_map.erase(it);
                        if (e->persistent) {
                            persistRemoveByKey(key);
                        }
                        return false;
                    }

					//Longer the expire for sliding entries
                    if (e->sliding && e->ttl.count() > 0) {
                        ULARGE_INTEGER ua{}, ub{};
                        ua.LowPart = now.dwLowDateTime; ua.HighPart = now.dwHighDateTime;
                        ub.QuadPart = ua.QuadPart + static_cast<uint64_t>(e->ttl.count()) * 10000ULL;
                        e->expire.dwLowDateTime = ub.LowPart;
                        e->expire.dwHighDateTime = ub.HighPart;
                    }

                    outData = e->value;
                    touchLRU_NoLock(key, e);
                    return true;
                }
            }

			// not found in memory, try disk if persistent
            Entry diskEntry;
            if (persistRead(key, diskEntry)) {
                //is it expired?
                FILETIME now2 = nowFileTime();
                if (isExpired_NoLock(diskEntry, now2)) {
                    persistRemoveByKey(key);
                    return false;
                }

                //Put to the memory
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
            s.lastMaintenance = m_lastMaint;
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
                m_lastMaint = std::chrono::system_clock::now();
            }

            if (!removed.empty()) {
				//Delete from disk if its even persistent
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
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (h == INVALID_HANDLE_VALUE) {
                //File could not exist
                return false;
            }

            CacheFileHeader hdr{};
            DWORD read = 0;
            BOOL ok = ReadFile(h, &hdr, sizeof(hdr), &read, nullptr);
            if (!ok || read != sizeof(hdr)) {
                SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile header failed");
                CloseHandle(h);
                return false;
            }

            if (hdr.magic != kCacheMagic || hdr.version != kCacheVersion) {
                SS_LOG_WARN(L"CacheManager", L"Invalid cache header for %ls", finalPath.c_str());
                CloseHandle(h);
                return false;
            }

            if (hdr.keyBytes > (16u * 1024u)) { //Security limit
                SS_LOG_WARN(L"CacheManager", L"Key too large in cache file: %ls", finalPath.c_str());
                CloseHandle(h);
                return false;
            }

            std::vector<wchar_t> keyBuf;
            keyBuf.resize(hdr.keyBytes / sizeof(wchar_t));
            read = 0;
            if (hdr.keyBytes > 0) {
                ok = ReadFile(h, keyBuf.data(), hdr.keyBytes, &read, nullptr);
                if (!ok || read != hdr.keyBytes) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile key failed");
                    CloseHandle(h);
                    return false;
                }
            }

            // Verify key 
            if (key.size() != keyBuf.size() ||
                (hdr.keyBytes > 0 && wmemcmp(key.data(), keyBuf.data(), keyBuf.size()) != 0)) {
                
                SS_LOG_WARN(L"CacheManager", L"Key mismatch for cache file: %ls", finalPath.c_str());
                CloseHandle(h);
                return false;
            }

            if (hdr.valueBytes > (1ull << 31)) {
                SS_LOG_WARN(L"CacheManager", L"Value too large in cache file: %ls", finalPath.c_str());
                CloseHandle(h);
                return false;
            }

            std::vector<uint8_t> value;
            value.resize(static_cast<size_t>(hdr.valueBytes));
            read = 0;
            if (hdr.valueBytes > 0) {
                ok = ReadFile(h, value.data(), static_cast<DWORD>(hdr.valueBytes), &read, nullptr);
                if (!ok || read != hdr.valueBytes) {
                    SS_LOG_LAST_ERROR(L"CacheManager", L"ReadFile value failed");
                    CloseHandle(h);
                    return false;
                }
            }

            CloseHandle(h);

            //Fill
            out.key = key;
            out.value = std::move(value);
            out.sizeBytes = out.value.size();
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
                        uint8_t digest[32] = {};
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

            // Fallback FNV-1a 64
            uint64_t h = Fnv1a64(bytes, cb);
            uint8_t buf[8];
            for (int i = 0; i < 8; ++i) buf[i] = static_cast<uint8_t>((h >> (8 * i)) & 0xFF);
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