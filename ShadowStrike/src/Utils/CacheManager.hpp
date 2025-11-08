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

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "Logger.hpp"

namespace ShadowStrike {
	namespace Utils {

		class CacheManager {
		public:

			struct Stats {
				size_t entryCount = 0;
				size_t totalBytes = 0;
				size_t maxEntries = 0;
				size_t maxBytes = 0;
				std::chrono::system_clock::time_point lastMaintenance{};
			};

			//Singleton
			static CacheManager& Instance();

	      // using L"" ise %ProgramData%\ShadowStrike\Cache as base directory.
			void Initialize(const std::wstring& baseDir = L"",
				size_t maxEntries = 100000,
				size_t maxBytes = 256 * 1024 * 1024,
				std::chrono::milliseconds maintenanceInterval = std::chrono::minutes(1));

			void Shutdown();

			//Binary put
			bool Put(const std::wstring& key,
				const uint8_t* data, size_t size,
				std::chrono::milliseconds ttl,
				bool persistent = false,
				bool sliding = false);

			bool Put(const std::wstring& key,
				const std::vector<uint8_t>& data,
				std::chrono::milliseconds ttl,
				bool persistent = false,
				bool sliding = false)
			{
				const uint8_t* p = data.empty() ? nullptr : data.data();
				return Put(key, p, data.size(), ttl, persistent, sliding);
			}


			// UTF-16 string convenience
			bool PutStringW(const std::wstring& key,
				const std::wstring& value,
				std::chrono::milliseconds ttl,
				bool persistent = false,
				bool sliding = false)
			{
				const uint8_t* p = reinterpret_cast<const uint8_t*>(value.data());
				size_t cb = value.size() * sizeof(wchar_t);
				return Put(key, p, cb, ttl, persistent, sliding);
			}

			//Binary get
			bool Get(const std::wstring& key, std::vector<uint8_t>& outData);

			// UTF-16 string convenience
			bool GetStringW(const std::wstring& key, std::wstring& outValue) {
				std::vector<uint8_t> buf;
				if (!Get(key, buf)) return false;
				if ((buf.size() % sizeof(wchar_t)) != 0) return false;
				outValue.assign(reinterpret_cast<const wchar_t*>(buf.data()),
					reinterpret_cast<const wchar_t*>(buf.data()) + (buf.size() / sizeof(wchar_t)));
				return true;
			}

			bool Remove(const std::wstring& key);
			void Clear();

			bool Contains(const std::wstring& key) const;

			void SetMaxEntries(size_t maxEntries);
			void SetMaxBytes(size_t maxBytes);

			Stats GetStats() const;

		private:
			CacheManager();
			~CacheManager();

			CacheManager(const CacheManager&) = delete;
			CacheManager& operator=(const CacheManager&) = delete;

			struct Entry {
				std::wstring key;
				std::vector<uint8_t> value;
				FILETIME expire{};                        // absolute expire time
				std::chrono::milliseconds ttl{ 0 };       // For sliding
				bool sliding = false;
				bool persistent = false;
				size_t sizeBytes = 0;
				std::list<std::wstring>::iterator lruIt;
			};

			// SRWLock RAII
			class SRWExclusive {
			public:
				explicit SRWExclusive(SRWLOCK& l) : m(l) { AcquireSRWLockExclusive(&m); }
				~SRWExclusive() { ReleaseSRWLockExclusive(&m); }
				SRWExclusive(const SRWExclusive&) = delete;
				SRWExclusive& operator=(const SRWExclusive&) = delete;
			private:
				SRWLOCK& m;
			};
			class SRWShared {
			public:
				explicit SRWShared(SRWLOCK& l) : m(l) { AcquireSRWLockShared(&m); }
				~SRWShared() { ReleaseSRWLockShared(&m); }
				SRWShared(const SRWShared&) = delete;
				SRWShared& operator=(const SRWShared&) = delete;
			private:
				SRWLOCK& m;
			};

			// Maintenance
			void maintenanceThread();
			void performMaintenance();
			void evictIfNeeded_NoLock(); // lock tutuluyken çaðrýlýr
			void removeExpired_NoLock(std::vector<std::wstring>& removedKeys); // lock tutuluyken
			bool isExpired_NoLock(const Entry& e, const FILETIME& now) const;

			// Persistence helpers
			bool ensureBaseDir();
			bool ensureSubdirForHash(const std::wstring& hex2);
			bool persistWrite(const std::wstring& key, const Entry& e);
			bool persistRead(const std::wstring& key, Entry& out);
			bool persistRemoveByKey(const std::wstring& key);
			std::wstring pathForKeyHex(const std::wstring& hex) const;

			// Hash helpers
			std::wstring hashKeyToHex(const std::wstring& key) const;

			// Time helpers
			static FILETIME nowFileTime();
			static bool fileTimeLessOrEqual(const FILETIME& a, const FILETIME& b);

			// LRU helpers
			void touchLRU_NoLock(const std::wstring& key, std::shared_ptr<Entry>& e);
			void loadPersistentEntries();

			private:
				// State
				std::wstring m_baseDir;
				size_t m_maxEntries = 0;
				size_t m_maxBytes = 0;

				mutable SRWLOCK m_lock{};
				mutable SRWLOCK m_diskLock{}; // ? NEW: Protect disk operations
				std::unordered_map<std::wstring, std::shared_ptr<Entry>> m_map;
				std::list<std::wstring> m_lru;
				size_t m_totalBytes = 0;

				std::atomic<bool> m_shutdown{ false };
				std::thread m_maintThread;
				std::chrono::milliseconds m_maintInterval{ std::chrono::minutes(1) };
				std::atomic<uint64_t> m_lastMaint{ 0 };
				std::atomic<size_t> m_pendingDiskOps{ 0 }; // ? NEW: Track pending disk I/O
				std::vector<uint8_t> m_hmacKey; // ? NEW: Secret key for HMAC-SHA256
		};



	}// namespace Utils
}// namespace ShadowStrike