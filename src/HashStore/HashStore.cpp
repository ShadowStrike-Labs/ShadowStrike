
// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

/*
 * ============================================================================
 * ShadowStrike HashStore - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Lightning-fast hash database implementation
 * Bloom filter + B+Tree = < 1?s lookups
 *
 * ============================================================================
 */
#include"pch.h"
#include "HashStore.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../FuzzyHasher/FuzzyHasher.hpp"
#include <tlsh/tlsh.h>
#include <format>
#include <chrono>
#include <random>
#include <limits>
#include <ctime>
#include <cctype>
#include <algorithm>
#include <cmath>
#include<atomic>
#include <bit>
#include<map>
#include <sstream>
#include <fstream>
#include<unordered_set>
#include <thread>

// Windows Crypto API for hash computation
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike {
    namespace SignatureStore {

        // ============================================================================
        // HASH STORE IMPLEMENTATION
        // ============================================================================

        HashStore::HashStore() 
            : m_databasePath()
            , m_mappedView{}
            , m_initialized(false)
            , m_readOnly(true)
            , m_buckets()
            , m_queryCache{}
            , m_cacheAccessCounter(0)
            , m_cachingEnabled(true)
            , m_totalLookups(0)
            , m_cacheHits(0)
            , m_cacheMisses(0)
            , m_totalMatches(0)
            , m_bloomExpectedElements(1'000'000)
            , m_bloomFalsePositiveRate(0.01)
            , m_perfFrequency{}
        {
            // Initialize performance counter with fallback
            if (!QueryPerformanceFrequency(&m_perfFrequency)) {
                SS_LOG_WARN(L"HashStore", L"QueryPerformanceFrequency failed, using fallback");
                m_perfFrequency.QuadPart = 1000000; // 1MHz fallback
            }
            
            // Validate frequency is reasonable
            if (m_perfFrequency.QuadPart <= 0) {
                SS_LOG_ERROR(L"HashStore", L"Invalid performance frequency, using fallback");
                m_perfFrequency.QuadPart = 1000000;
            }

            // Note: m_queryCache is already zero-initialized via {} in member declaration
            // No need for explicit loop - atomic seqlocks are 0 (valid), hash/result/timestamp are default
        }

        HashStore::~HashStore() {
            Close();
        }

        StoreError HashStore::Initialize(
            const std::wstring& databasePath,
            bool readOnly
        ) noexcept {
            SS_LOG_INFO(L"HashStore", L"Initialize: %s (%s)",
                databasePath.c_str(), readOnly ? L"read-only" : L"read-write");

            // Validate input
            if (databasePath.empty()) {
                SS_LOG_ERROR(L"HashStore", L"Initialize: Empty database path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty database path" };
            }

            // Check for double initialization
            if (m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"Already initialized, call Close() first");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Already initialized" };
            }

            // Acquire exclusive lock for initialization
            std::unique_lock<std::shared_mutex> lock(m_globalLock);

            // Double-check after acquiring lock
            if (m_initialized.load(std::memory_order_relaxed)) {
                SS_LOG_ERROR(L"HashStore", L"Already initialized (race condition avoided)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Already initialized" };
            }

            m_databasePath = databasePath;
            m_readOnly.store(readOnly, std::memory_order_release);

            // Open memory mapping
            StoreError err = OpenMemoryMapping(databasePath, readOnly);
            if (!err.IsSuccess()) {
                return err;
            }

            // Initialize hash buckets
            err = InitializeBuckets();
            if (!err.IsSuccess()) {
                CloseMemoryMapping();
                return err;
            }

            m_initialized.store(true, std::memory_order_release);

            SS_LOG_INFO(L"HashStore", L"Initialized successfully");
            return StoreError{ SignatureStoreError::Success };
        }

        StoreError HashStore::CreateNew(
            const std::wstring& databasePath,
            uint64_t initialSizeBytes
        ) noexcept {
            SS_LOG_INFO(L"HashStore", L"CreateNew: %s (size=%llu)",
                databasePath.c_str(), initialSizeBytes);

            // Input validation
            if (databasePath.empty()) {
                SS_LOG_ERROR(L"HashStore", L"CreateNew: Empty database path");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty database path" };
            }

            // Size validation - enforce reasonable bounds
            constexpr uint64_t MIN_DB_SIZE = 1024 * 1024;           // 1MB minimum
            constexpr uint64_t MAX_DB_SIZE = 100ULL * 1024 * 1024 * 1024;  // 100GB maximum

            if (initialSizeBytes < MIN_DB_SIZE) {
                SS_LOG_WARN(L"HashStore", 
                    L"CreateNew: Size %llu too small, using minimum %llu", 
                    initialSizeBytes, MIN_DB_SIZE);
                initialSizeBytes = MIN_DB_SIZE;
            }

            if (initialSizeBytes > MAX_DB_SIZE) {
                SS_LOG_ERROR(L"HashStore", 
                    L"CreateNew: Size %llu exceeds maximum %llu", 
                    initialSizeBytes, MAX_DB_SIZE);
                return StoreError{ SignatureStoreError::TooLarge, 0, "Database size exceeds maximum" };
            }

            // Create file with proper error handling
            HANDLE hFile = CreateFileW(
                databasePath.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                0,  // No sharing during creation
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if (hFile == INVALID_HANDLE_VALUE) {
                DWORD err = GetLastError();
                SS_LOG_LAST_ERROR(L"HashStore", L"Failed to create file");
                return StoreError{ SignatureStoreError::FileNotFound, err, "Failed to create file" };
            }

            // Set file size - use RAII wrapper for handle cleanup
            struct HandleGuard {
                HANDLE h;
                ~HandleGuard() { if (h != INVALID_HANDLE_VALUE) CloseHandle(h); }
            } guard{hFile};

            LARGE_INTEGER size{};
            size.QuadPart = static_cast<LONGLONG>(initialSizeBytes);
            
            if (!SetFilePointerEx(hFile, size, nullptr, FILE_BEGIN)) {
                DWORD err = GetLastError();
                SS_LOG_LAST_ERROR(L"HashStore", L"Failed to set file pointer");
                return StoreError{ SignatureStoreError::Unknown, err, "Failed to set file pointer" };
            }

            if (!SetEndOfFile(hFile)) {
                DWORD err = GetLastError();
                SS_LOG_LAST_ERROR(L"HashStore", L"Failed to set file size");
                return StoreError{ SignatureStoreError::Unknown, err, "Failed to set file size" };
            }

            // ====================================================================
            // CRITICAL: Write database header BEFORE calling Initialize()
            // Initialize() expects a valid header with magic number 0x53535344
            // ====================================================================

            // Reset file pointer to beginning for header write
            LARGE_INTEGER headerPos{};
            headerPos.QuadPart = 0;
            if (!SetFilePointerEx(hFile, headerPos, nullptr, FILE_BEGIN)) {
                DWORD err = GetLastError();
                SS_LOG_LAST_ERROR(L"HashStore", L"Failed to reset file pointer for header");
                return StoreError{ SignatureStoreError::Unknown, err, "Failed to reset file pointer" };
            }

            // Initialize header with valid values
            SignatureDatabaseHeader header{};
            std::memset(&header, 0, sizeof(header));

            // Set magic number and version - CRITICAL for validation
            header.magic = SIGNATURE_DB_MAGIC;                      // 0x53535344 = 'SSSD'
            header.versionMajor = SIGNATURE_DB_VERSION_MAJOR;       // 1
            header.versionMinor = SIGNATURE_DB_VERSION_MINOR;       // 0

            // Generate UUID for database identification (using crypto-random if available)
            // For now, use simple random + timestamp-based UUID
            const uint64_t timestamp = static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch()
                ).count()
            );
            header.creationTime = timestamp;
            header.lastUpdateTime = timestamp;
            header.buildNumber = 1;

            // Generate simple UUID using timestamp and random
            std::random_device rd;
            std::mt19937_64 gen(rd());
            const uint64_t uuidPart1 = gen();
            const uint64_t uuidPart2 = gen() ^ timestamp;
            std::memcpy(header.databaseUuid.data(), &uuidPart1, sizeof(uuidPart1));
            std::memcpy(header.databaseUuid.data() + 8, &uuidPart2, sizeof(uuidPart2));

            // ====================================================================
            // CRITICAL: Set hash index offset and size for bucket initialization
            // Hash index starts immediately after the header (4096 bytes)
            // Hash index size = total file size - header size
            // ====================================================================
            constexpr uint64_t HEADER_SIZE = sizeof(SignatureDatabaseHeader);  // 4096 bytes
            static_assert(HEADER_SIZE == 4096, "Header size must be 4096 bytes");

            header.hashIndexOffset = HEADER_SIZE;                               // Start after header
            header.hashIndexSize = initialSizeBytes - HEADER_SIZE;              // Rest of the file

            // Other sections are not used by HashStore - leave at 0
            // patternIndexOffset, yaraRulesOffset, metadataOffset, stringPoolOffset = 0

            // Performance hints
            header.recommendedCacheSize = 64;  // 64 MB default cache recommendation

            // Checksum will be computed on first flush

            // Write header to file
            DWORD bytesWritten = 0;
            if (!WriteFile(hFile, &header, sizeof(header), &bytesWritten, nullptr)) {
                DWORD err = GetLastError();
                SS_LOG_LAST_ERROR(L"HashStore", L"Failed to write database header");
                return StoreError{ SignatureStoreError::Unknown, err, "Failed to write header" };
            }

            if (bytesWritten != sizeof(header)) {
                SS_LOG_ERROR(L"HashStore", 
                    L"Header write incomplete: wrote %u of %zu bytes",
                    bytesWritten, sizeof(header));
                return StoreError{ SignatureStoreError::Unknown, 0, "Incomplete header write" };
            }

            // Flush to ensure header is on disk before reopening
            if (!FlushFileBuffers(hFile)) {
                SS_LOG_WARN(L"HashStore", L"Failed to flush file buffers (non-fatal)");
            }

            SS_LOG_INFO(L"HashStore", 
                L"Database header written successfully (magic=0x%08X, ver=%u.%u)",
                header.magic, header.versionMajor, header.versionMinor);

            // Close handle before Initialize opens it again
            CloseHandle(hFile);
            guard.h = INVALID_HANDLE_VALUE;  // Prevent double-close

            // Initialize with memory mapping
            return Initialize(databasePath, false);
        }

        void HashStore::Close() noexcept {
            // Fast check without lock
            if (!m_initialized.load(std::memory_order_acquire)) {
                return;
            }

            SS_LOG_INFO(L"HashStore", L"Closing hash store");

            // Acquire exclusive lock for safe shutdown
            std::unique_lock<std::shared_mutex> lock(m_globalLock);

            // Double-check after acquiring lock
            if (!m_initialized.load(std::memory_order_relaxed)) {
                return;
            }

            // Clear buckets first (releases index resources)
            m_buckets.clear();

            // Close memory mapping
            CloseMemoryMapping();

            // Clear cache
            for (auto& entry : m_queryCache) {
                entry.seqlock.store(0, std::memory_order_relaxed);
                entry.hash = HashValue{};
                entry.result = std::nullopt;
                entry.timestamp = 0;
            }

            // Reset state
            m_databasePath.clear();
            m_initialized.store(false, std::memory_order_release);

            SS_LOG_INFO(L"HashStore", L"Hash store closed");
        }


		// ============================================================================
		//================= STATISTICS & MAINTENANCE ==================================
		// ============================================================================

        HashStore::HashStoreStatistics HashStore::GetStatistics() const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            HashStoreStatistics stats{};
            stats.totalLookups = m_totalLookups.load(std::memory_order_relaxed);
            stats.cacheHits = m_cacheHits.load(std::memory_order_relaxed);
            stats.cacheMisses = m_cacheMisses.load(std::memory_order_relaxed);

            // Calculate cache hit rate with division-by-zero protection
            const uint64_t totalCacheAccesses = stats.cacheHits + stats.cacheMisses;
            if (totalCacheAccesses > 0) {
                stats.cacheHitRate = static_cast<double>(stats.cacheHits) / 
                                     static_cast<double>(totalCacheAccesses);
            } else {
                stats.cacheHitRate = 0.0;
            }

            // Count hashes by type
            stats.totalHashes = 0;
            stats.bloomFilterSaves = 0;
            
            for (const auto& [type, bucket] : m_buckets) {
                if (!bucket) {
                    continue;
                }
                
                try {
                    auto bucketStats = bucket->GetStatistics();
                    stats.countsByType[type] = bucketStats.totalHashes;
                    stats.totalHashes += bucketStats.totalHashes;
                    stats.bloomFilterSaves += bucketStats.bloomFilterHits;
                }
                catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"HashStore", 
                        L"GetStatistics: Error getting bucket stats for type %u: %S",
                        static_cast<uint8_t>(type), ex.what());
                }
            }

            // Calculate bloom filter efficiency with division-by-zero protection
            const uint64_t totalBloomChecks = stats.totalLookups;

            if (totalBloomChecks > 0) {
                stats.bloomFilterEfficiency = static_cast<double>(stats.bloomFilterSaves) /
                                              static_cast<double>(totalBloomChecks);
            } else {
                stats.bloomFilterEfficiency = 0.0;
            }

            if (m_mappedView.IsValid()) {
                stats.databaseSizeBytes = m_mappedView.fileSize;
            } else {
                stats.databaseSizeBytes = 0;
            }

            return stats;
        }

        void HashStore::ResetStatistics() noexcept {
            m_totalLookups.store(0, std::memory_order_release);
            m_cacheHits.store(0, std::memory_order_release);
            m_cacheMisses.store(0, std::memory_order_release);
            m_totalMatches.store(0, std::memory_order_release);

            std::shared_lock<std::shared_mutex> lock(m_globalLock);
            for (auto& [type, bucket] : m_buckets) {
                if (bucket) {
                    bucket->ResetStatistics();
                }
            }
        }

        HashBucket::BucketStatistics HashStore::GetBucketStatistics(HashType type) const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            const HashBucket* bucket = GetBucket(type);
            if (!bucket) {
                SS_LOG_DEBUG(L"HashStore", 
                    L"GetBucketStatistics: No bucket for type %u", 
                    static_cast<uint8_t>(type));
                return HashBucket::BucketStatistics{};
            }

            return bucket->GetStatistics();
        }

        StoreError HashStore::Rebuild() noexcept {
            SS_LOG_INFO(L"HashStore", L"Rebuild: Starting comprehensive index rebuild");

            // ========================================================================
            // STEP 1: STATE VALIDATION & PRECONDITIONS
            // ========================================================================

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"Rebuild: Database not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
            }

            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"Rebuild: Cannot rebuild read-only database");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
            }

            // ========================================================================
            // STEP 2: ACQUIRE EXCLUSIVE LOCK (Block all readers/writers)
            // ========================================================================

            std::unique_lock<std::shared_mutex> lock(m_globalLock);

            SS_LOG_INFO(L"HashStore", L"Rebuild: Exclusive lock acquired");

            // ========================================================================
            // STEP 3: PERFORMANCE MONITORING SETUP
            // ========================================================================

            LARGE_INTEGER rebuildStartTime{}, rebuildEndTime{};
            if (!QueryPerformanceCounter(&rebuildStartTime)) {
                rebuildStartTime.QuadPart = 0;
            }

            size_t totalHashesProcessed = 0;
            size_t totalBucketsRebuilt = 0;
            std::vector<StoreError> bucketErrors;

            // ========================================================================
            // STEP 4: COLLECT STATISTICS BEFORE REBUILD
            // ========================================================================

            auto statsBeforeRebuild = GetStatistics();
            SS_LOG_INFO(L"HashStore",
                L"Rebuild: Before rebuild - %llu total hashes, %zu bucket types",
                statsBeforeRebuild.totalHashes, m_buckets.size());

            // ========================================================================
            // STEP 5: VALIDATE ALL BUCKET INDICES (Detect corruption early)
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Rebuild: Validating bucket indices");

            for (auto& [type, bucket] : m_buckets) {
                if (!bucket) {
                    SS_LOG_WARN(L"HashStore", L"Rebuild: Null bucket for type %S",
                        Format::HashTypeToString(type));
                    continue;
                }

                // Validate bucket's index integrity
                StoreError validationErr = bucket->m_index->Verify();
                if (!validationErr.IsSuccess()) {
                    SS_LOG_WARN(L"HashStore",
                        L"Rebuild: Bucket %S validation failed: %S",
                        Format::HashTypeToString(type), validationErr.message.c_str());
                    bucketErrors.push_back(validationErr);
                }
            }

            // ========================================================================
            // STEP 6: ENUMERATE ALL HASHES & COLLECT INTO TEMPORARY VECTORS
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Rebuild: Enumerating all hashes from buckets");

            // Per-bucket collections (maintains hash type separation)
            std::map<HashType, std::vector<std::pair<HashValue, uint64_t>>> bucketHashes;

            for (auto& [bucketType, bucket] : m_buckets) {
                if (!bucket) continue;

                std::vector<std::pair<HashValue, uint64_t>> typeHashes;

                // Enumerate bucket using ForEach callback
                bucket->m_index->ForEach(
                    [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                        // ============================================================
                        // RETRIEVE HASH VALUE FROM MEMORY-MAPPED REGION
                        // ============================================================

                        if (signatureOffset >= m_mappedView.fileSize) {
                            SS_LOG_WARN(L"HashStore",
                                L"Rebuild: Invalid signature offset 0x%llX (file size: 0x%llX)",
                                signatureOffset, m_mappedView.fileSize);
                            return true; // Continue enumeration
                        }

                        const uint8_t* dataBase =
                            static_cast<const uint8_t*>(m_mappedView.baseAddress);
                        const HashValue* hashPtr =
                            reinterpret_cast<const HashValue*>(dataBase + signatureOffset);

                        // Validate bounds
                        if (signatureOffset + sizeof(HashValue) > m_mappedView.fileSize) {
                            SS_LOG_WARN(L"HashStore",
                                L"Rebuild: Hash at 0x%llX exceeds file bounds",
                                signatureOffset);
                            return true;
                        }

                        // Validate hash data
                        if (hashPtr->length == 0 || hashPtr->length > 64) {
                            SS_LOG_WARN(L"HashStore",
                                L"Rebuild: Invalid hash length %u at offset 0x%llX",
                                hashPtr->length, signatureOffset);
                            return true;
                        }

                        // Copy hash (safe copy from memory-mapped region)
                        HashValue hashCopy;
                        std::memcpy(&hashCopy, hashPtr, sizeof(HashValue));

                        // Validate type matches bucket
                        if (hashCopy.type != bucketType) {
                            SS_LOG_WARN(L"HashStore",
                                L"Rebuild: Type mismatch in bucket %S at offset 0x%llX",
                                Format::HashTypeToString(bucketType), signatureOffset);
                            return true;
                        }

                        typeHashes.emplace_back(hashCopy, signatureOffset);
                        totalHashesProcessed++;

                        return true; // Continue enumeration
                    });

                if (!typeHashes.empty()) {
                    bucketHashes[bucketType] = std::move(typeHashes);
                    SS_LOG_DEBUG(L"HashStore",
                        L"Rebuild: Bucket %S: enumerated %zu hashes",
                        Format::HashTypeToString(bucketType), bucketHashes[bucketType].size());
                }
            }

            SS_LOG_INFO(L"HashStore",
                L"Rebuild: Enumerated %zu hashes total from %zu bucket types",
                totalHashesProcessed, bucketHashes.size());

            // ========================================================================
            // STEP 7: SORT HASHES BY FAST-HASH FOR OPTIMAL B+TREE LAYOUT
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Rebuild: Sorting hashes for optimal B+Tree layout");

            for (auto& [type, hashes] : bucketHashes) {
                // Sort by fast-hash value (improves cache locality in B+Tree)
                std::sort(hashes.begin(), hashes.end(),
                    [](const auto& a, const auto& b) {
                        return a.first.FastHash() < b.first.FastHash();
                    });

                SS_LOG_DEBUG(L"HashStore",
                    L"Rebuild: Sorted %zu hashes for type %S",
                    hashes.size(), Format::HashTypeToString(type));
            }

            // ========================================================================
            // STEP 8: REBUILD INDICES FOR EACH BUCKET TYPE
            // ========================================================================

            SS_LOG_INFO(L"HashStore", L"Rebuild: Rebuilding all bucket indices");

            for (auto& [bucketType, bucket] : m_buckets) {
                if (!bucket) {
                    SS_LOG_DEBUG(L"HashStore", L"Rebuild: Skipping null bucket");
                    continue;
                }

                auto it = bucketHashes.find(bucketType);
                if (it == bucketHashes.end() || it->second.empty()) {
                    SS_LOG_DEBUG(L"HashStore",
                        L"Rebuild: No hashes for type %S, clearing bucket",
                        Format::HashTypeToString(bucketType));

                    // Clear empty bucket
                    bucket->m_bloomFilter->Clear();
                    // Index rebuild with empty data
                    StoreError clearErr = bucket->m_index->Rebuild();
                    if (!clearErr.IsSuccess()) {
                        SS_LOG_WARN(L"HashStore",
                            L"Rebuild: Failed to rebuild empty bucket %S: %S",
                            Format::HashTypeToString(bucketType), clearErr.message.c_str());
                    }
                    continue;
                }

                std::vector<std::pair<HashValue, uint64_t>>& hashes = it->second;

                SS_LOG_DEBUG(L"HashStore",
                    L"Rebuild: Rebuilding bucket %S with %zu hashes",
                    Format::HashTypeToString(bucketType), hashes.size());

                // ====================================================================
                // REBUILD BLOOM FILTER (Re-add all hashes)
                // ====================================================================

                bucket->m_bloomFilter->Clear();

                for (const auto& [hash, offset] : hashes) {
                    bucket->m_bloomFilter->Add(hash.FastHash());
                }

                SS_LOG_DEBUG(L"HashStore",
                    L"Rebuild: Bloom filter rebuilt for %S (fill rate: %.2f%%)",
                    Format::HashTypeToString(bucketType),
                    bucket->m_bloomFilter->EstimatedFillRate() * 100.0);

                // ====================================================================
                // REBUILD B+TREE INDEX (Batch insert sorted data)
                // ====================================================================

                // Note: Index rebuild would be a method on SignatureIndex
                // For now, we use batch insert which is nearly as efficient
                StoreError rebuildErr = bucket->m_index->Rebuild();
                if (!rebuildErr.IsSuccess()) {
                    SS_LOG_ERROR(L"HashStore",
                        L"Rebuild: Failed to rebuild index for bucket %S: %S",
                        Format::HashTypeToString(bucketType), rebuildErr.message.c_str());
                    bucketErrors.push_back(rebuildErr);
                    continue;
                }

                // Re-insert sorted hashes
                rebuildErr = bucket->m_index->BatchInsert(hashes);
                if (!rebuildErr.IsSuccess()) {
                    SS_LOG_ERROR(L"HashStore",
                        L"Rebuild: Batch insert failed for bucket %S: %S",
                        Format::HashTypeToString(bucketType), rebuildErr.message.c_str());
                    bucketErrors.push_back(rebuildErr);
                    continue;
                }

                totalBucketsRebuilt++;

                SS_LOG_INFO(L"HashStore",
                    L"Rebuild: Successfully rebuilt bucket %S",
                    Format::HashTypeToString(bucketType));
            }

            // ========================================================================
            // STEP 9: FLUSH CHANGES TO DISK
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Rebuild: Flushing changes to disk");

            for (auto& [type, bucket] : m_buckets) {
                if (!bucket) continue;

                StoreError flushErr = bucket->m_index->Flush();
                if (!flushErr.IsSuccess()) {
                    SS_LOG_WARN(L"HashStore",
                        L"Rebuild: Failed to flush bucket %S: %S",
                        Format::HashTypeToString(type), flushErr.message.c_str());
                }
            }

            // ========================================================================
            // STEP 10: PERFORMANCE ANALYSIS & VALIDATION
            // ========================================================================

            if (!QueryPerformanceCounter(&rebuildEndTime)) {
                rebuildEndTime.QuadPart = rebuildStartTime.QuadPart;
            }
            
            uint64_t rebuildTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && rebuildEndTime.QuadPart >= rebuildStartTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(rebuildEndTime.QuadPart - rebuildStartTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1000000ULL) {
                    rebuildTimeUs = (elapsed * 1000000ULL) / freq;
                } else {
                    rebuildTimeUs = (elapsed / freq) * 1000000ULL;
                }
            }

            auto statsAfterRebuild = GetStatistics();

            SS_LOG_INFO(L"HashStore",
                L"Rebuild: Complete - %zu hashes processed, %zu buckets rebuilt in %llu µs",
                totalHashesProcessed, totalBucketsRebuilt, rebuildTimeUs);

            SS_LOG_INFO(L"HashStore",
                L"Rebuild: Statistics - Before: %llu hashes, After: %llu hashes",
                statsBeforeRebuild.totalHashes, statsAfterRebuild.totalHashes);

            // ========================================================================
            // STEP 11: ERROR REPORTING
            // ========================================================================

            if (!bucketErrors.empty()) {
                SS_LOG_WARN(L"HashStore",
                    L"Rebuild: %zu errors occurred during rebuild",
                    bucketErrors.size());
                return StoreError{ SignatureStoreError::Unknown, 0,
                                  "Rebuild completed with errors" };
            }

            // ========================================================================
            // STEP 12: CLEAR CACHES (Reflect new layout)
            // ========================================================================

            ClearCache();

            SS_LOG_INFO(L"HashStore", L"Rebuild: Complete - cache cleared");

            return StoreError{ SignatureStoreError::Success };
        }

        StoreError HashStore::Compact() noexcept {
            SS_LOG_INFO(L"HashStore", L"Compact: Starting database compaction");

            // ========================================================================
            // STEP 1: VALIDATION
            // ========================================================================

            if (!m_initialized.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"Compact: Database not initialized");
                return StoreError{ SignatureStoreError::Unknown, 0, "Database not initialized" };
            }

            if (m_readOnly.load(std::memory_order_acquire)) {
                SS_LOG_ERROR(L"HashStore", L"Compact: Cannot compact read-only database");
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Database is read-only" };
            }

            // ========================================================================
            // STEP 2: ACQUIRE EXCLUSIVE LOCK
            // ========================================================================

            std::unique_lock<std::shared_mutex> lock(m_globalLock);

            SS_LOG_INFO(L"HashStore", L"Compact: Exclusive lock acquired");

            // ========================================================================
            // STEP 3: PERFORMANCE MONITORING
            // ========================================================================

            LARGE_INTEGER compactStartTime{}, compactEndTime{};
            if (!QueryPerformanceCounter(&compactStartTime)) {
                compactStartTime.QuadPart = 0;
            }

            auto statsBefore = GetStatistics();

            // ========================================================================
            // STEP 4: ANALYZE FRAGMENTATION IN EACH BUCKET
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Compact: Analyzing fragmentation");

            struct BucketFragmentation {
                HashType type;
                size_t totalHashes;
                double bloomFillRate;      // Bloom filter fill rate (0.0 to 1.0)
                bool needsRebuild;         // Whether this bucket needs rebuilding
            };

            std::vector<BucketFragmentation> fragmentationReport;
            size_t totalBucketsAnalyzed = 0;

            for (auto& [bucketType, bucket] : m_buckets) {
                if (!bucket) {
                    SS_LOG_DEBUG(L"HashStore", L"Compact: Skipping null bucket for type %S",
                        Format::HashTypeToString(bucketType));
                    continue;
                }

                totalBucketsAnalyzed++;

                auto bucketStats = bucket->GetStatistics();

                // ====================================================================
                // CALCULATE BLOOM FILTER FILL RATE (CORRECTED)
                // ====================================================================
                // Use the EstimatedFillRate() method directly from bloom filter
                // This is the CORRECT way - get it from the actual bloom filter object
                double bloomFillRate = 0.0;
                if (bucket->m_bloomFilter) {
                    bloomFillRate = bucket->m_bloomFilter->EstimatedFillRate();
                }

                // ====================================================================
                // DETERMINE IF REBUILD IS NEEDED
                // ====================================================================
                // A bucket needs rebuild if:
                // 1. Bloom filter is saturated (> 90% full) - false positive rate too high
                // 2. Very few hashes in bucket despite large bloom filter allocation
                bool needsRebuild = false;

                if (bloomFillRate > 0.90) {
                    // Bloom filter saturated - rebuild needed
                    needsRebuild = true;
                    SS_LOG_WARN(L"HashStore",
                        L"Compact: Bucket %S bloom filter SATURATED (fill: %.2f%%) - rebuild needed",
                        Format::HashTypeToString(bucketType), bloomFillRate * 100.0);
                }
                else if (bloomFillRate < 0.10 && bucketStats.totalHashes > 0) {
                    // Very sparse bloom filter usage despite having hashes
                    needsRebuild = true;
                    SS_LOG_WARN(L"HashStore",
                        L"Compact: Bucket %S bloom filter SPARSE (fill: %.2f%%) with %zu hashes - rebuild needed",
                        Format::HashTypeToString(bucketType), bloomFillRate * 100.0, bucketStats.totalHashes);
                }

                BucketFragmentation frag{
                    bucketType,
                    bucketStats.totalHashes,
                    bloomFillRate,
                    needsRebuild
                };

                fragmentationReport.push_back(frag);

                SS_LOG_DEBUG(L"HashStore",
                    L"Compact: Bucket %S - %zu hashes, bloom fill: %.2f%%, needs rebuild: %s",
                    Format::HashTypeToString(bucketType), frag.totalHashes,
                    bloomFillRate * 100.0, needsRebuild ? "YES" : "NO");
            }

            SS_LOG_INFO(L"HashStore",
                L"Compact: Analyzed %zu bucket types", totalBucketsAnalyzed);

            // ========================================================================
            // STEP 5: CHECK IF COMPACTION IS NECESSARY
            // ========================================================================

            size_t bucketsNeedingRebuild = 0;
            for (const auto& frag : fragmentationReport) {
                if (frag.needsRebuild) {
                    bucketsNeedingRebuild++;
                }
            }

            if (bucketsNeedingRebuild == 0) {
                SS_LOG_INFO(L"HashStore",
                    L"Compact: No buckets need rebuilding - compaction skipped");
                return StoreError{ SignatureStoreError::Success };
            }

            SS_LOG_INFO(L"HashStore",
                L"Compact: %zu buckets need rebuilding - proceeding with compaction",
                bucketsNeedingRebuild);

            // ========================================================================
            // STEP 6: REBUILD BLOOM FILTERS AND INDICES FOR AFFECTED BUCKETS
            // ========================================================================

            SS_LOG_INFO(L"HashStore", L"Compact: Rebuilding bloom filters and indices");

            size_t bucketsRebuilt = 0;
            std::vector<StoreError> rebuildErrors;

            for (auto& [bucketType, bucket] : m_buckets) {
                if (!bucket) continue;

                // Find this bucket's fragmentation info
                auto it = std::find_if(fragmentationReport.begin(), fragmentationReport.end(),
                    [bucketType](const BucketFragmentation& f) { return f.type == bucketType; });

                if (it == fragmentationReport.end() || !it->needsRebuild) {
                    SS_LOG_DEBUG(L"HashStore",
                        L"Compact: Bucket %S does not need rebuild",
                        Format::HashTypeToString(bucketType));
                    continue;
                }

                SS_LOG_DEBUG(L"HashStore",
                    L"Compact: Rebuilding bucket %S (had %zu hashes, bloom fill: %.2f%%)",
                    Format::HashTypeToString(bucketType), it->totalHashes, it->bloomFillRate * 100.0);

                // ====================================================================
                // CLEAR AND REBUILD BLOOM FILTER
                // ====================================================================
                if (bucket->m_bloomFilter) {
                    bucket->m_bloomFilter->Clear();
                    SS_LOG_DEBUG(L"HashStore",
                        L"Compact: Cleared bloom filter for %S",
                        Format::HashTypeToString(bucketType));
                }

                // ====================================================================
                // REBUILD B+TREE INDEX
                // ====================================================================
                StoreError rebuildErr = bucket->m_index->Rebuild();
                if (!rebuildErr.IsSuccess()) {
                    SS_LOG_ERROR(L"HashStore",
                        L"Compact: Failed to rebuild index for bucket %S: %S",
                        Format::HashTypeToString(bucketType), rebuildErr.message.c_str());
                    rebuildErrors.push_back(rebuildErr);
                    continue;
                }

                bucketsRebuilt++;

                // ====================================================================
                // RE-POPULATE BLOOM FILTER WITH CURRENT HASHES
                // ====================================================================
                if (bucket->m_bloomFilter && it->totalHashes > 0) {
                    bucket->m_index->ForEach(
                        [&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                            bucket->m_bloomFilter->Add(fastHash);
                            return true;
                        });

                    double newFillRate = bucket->m_bloomFilter->EstimatedFillRate();
                    SS_LOG_DEBUG(L"HashStore",
                        L"Compact: Rebuilt bloom filter for %S (new fill: %.2f%%)",
                        Format::HashTypeToString(bucketType), newFillRate * 100.0);
                }

                SS_LOG_INFO(L"HashStore",
                    L"Compact: Successfully rebuilt bucket %S",
                    Format::HashTypeToString(bucketType));
            }

            SS_LOG_INFO(L"HashStore",
                L"Compact: Rebuilt %zu buckets", bucketsRebuilt);

            // ========================================================================
            // STEP 7: HANDLE REBUILD ERRORS
            // ========================================================================

            if (!rebuildErrors.empty()) {
                SS_LOG_ERROR(L"HashStore",
                    L"Compact: Encountered %zu rebuild errors", rebuildErrors.size());
            }

            // ========================================================================
            // STEP 8: FLUSH ALL CHANGES TO DISK
            // ========================================================================

            SS_LOG_DEBUG(L"HashStore", L"Compact: Flushing all changes to disk");

            for (auto& [type, bucket] : m_buckets) {
                if (!bucket) continue;

                if (auto flushErr = bucket->m_index->Flush(); !flushErr.IsSuccess()) {
                    SS_LOG_WARN(L"HashStore",
                        L"Compact: Failed to flush bucket %S: %S",
                        Format::HashTypeToString(type), flushErr.message.c_str());
                }
            }

            if (m_mappedView.IsValid()) {
                StoreError mmapFlushErr{};
                auto ret = MemoryMapping::FlushView(m_mappedView, mmapFlushErr);
                if (!ret) {
                    SS_LOG_WARN(L"HashStore", 
                        L"Compact: Failed to flush memory-mapped view: %S",
                        mmapFlushErr.message.c_str());
                }
            }

            // ========================================================================
            // STEP 9: CLEAR QUERY CACHE (Maintain consistency)
            // ========================================================================

            ClearCache();
            SS_LOG_DEBUG(L"HashStore", L"Compact: Query cache cleared");

            // ========================================================================
            // STEP 10: FINAL STATISTICS & PERFORMANCE REPORTING
            // ========================================================================

            if (!QueryPerformanceCounter(&compactEndTime)) {
                compactEndTime.QuadPart = compactStartTime.QuadPart;
            }
            
            uint64_t compactTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0 && compactEndTime.QuadPart >= compactStartTime.QuadPart) {
                const uint64_t elapsed = static_cast<uint64_t>(compactEndTime.QuadPart - compactStartTime.QuadPart);
                const uint64_t freq = static_cast<uint64_t>(m_perfFrequency.QuadPart);
                if (elapsed <= UINT64_MAX / 1000000ULL) {
                    compactTimeUs = (elapsed * 1000000ULL) / freq;
                } else {
                    compactTimeUs = (elapsed / freq) * 1000000ULL;
                }
            }

            auto statsAfter = GetStatistics();

            // ====================================================================
            // VERIFY BLOOM FILTERS ARE NOW HEALTHY
            // ====================================================================
            SS_LOG_INFO(L"HashStore", L"Compact: Verifying bloom filter health after rebuild");

            for (auto& [bucketType, bucket] : m_buckets) {
                if (!bucket || !bucket->m_bloomFilter) continue;

                double finalFillRate = bucket->m_bloomFilter->EstimatedFillRate();

                if (finalFillRate > 0.90) {
                    SS_LOG_WARN(L"HashStore",
                        L"Compact: WARNING - Bucket %S bloom filter still saturated (fill: %.2f%%)",
                        Format::HashTypeToString(bucketType), finalFillRate * 100.0);
                }
                else if (finalFillRate < 0.05) {
                    SS_LOG_WARN(L"HashStore",
                        L"Compact: WARNING - Bucket %S bloom filter underutilized (fill: %.2f%%)",
                        Format::HashTypeToString(bucketType), finalFillRate * 100.0);
                }
                else {
                    SS_LOG_DEBUG(L"HashStore",
                        L"Compact: Bucket %S bloom filter is healthy (fill: %.2f%%)",
                        Format::HashTypeToString(bucketType), finalFillRate * 100.0);
                }
            }

            // ====================================================================
            // LOG FINAL STATISTICS
            // ====================================================================

            SS_LOG_INFO(L"HashStore",
                L"Compact: COMPLETE - %zu buckets rebuilt in %llu µs (%.2f ms)",
                bucketsRebuilt, compactTimeUs, compactTimeUs / 1000.0);

            SS_LOG_INFO(L"HashStore",
                L"Compact: Statistics - Before: %llu hashes, After: %llu hashes",
                statsBefore.totalHashes, statsAfter.totalHashes);

            SS_LOG_INFO(L"HashStore",
                L"Compact: Database size - Before: %llu bytes, After: %llu bytes",
                statsBefore.databaseSizeBytes, statsAfter.databaseSizeBytes);

            if (statsAfter.databaseSizeBytes < statsBefore.databaseSizeBytes) {
                uint64_t freedBytes = statsBefore.databaseSizeBytes - statsAfter.databaseSizeBytes;
                double percentReduction = (static_cast<double>(freedBytes) / statsBefore.databaseSizeBytes) * 100.0;
                SS_LOG_INFO(L"HashStore",
                    L"Compact: Space freed: %llu bytes (%.2f%% reduction)",
                    freedBytes, percentReduction);
            }

            if (!rebuildErrors.empty()) {
                SS_LOG_WARN(L"HashStore",
                    L"Compact: Operation completed with %zu errors", rebuildErrors.size());
                return StoreError{ SignatureStoreError::Unknown, 0,
                                  "Compaction completed with errors" };
            }

            SS_LOG_INFO(L"HashStore", L"Compact: Operation completed successfully");
            return StoreError{ SignatureStoreError::Success };
        }

        StoreError HashStore::Verify(
            std::function<void(const std::string&)> logCallback
        ) const noexcept {
            SS_LOG_INFO(L"HashStore", L"Verify: Checking integrity");

            std::shared_lock<std::shared_mutex> lock(m_globalLock);

            if (logCallback) {
                logCallback("Verifying hash store...");
            }

            // Verify header
            const auto* header = GetHeader();
            if (!header || !Format::ValidateHeader(header)) {
                if (logCallback) {
                    logCallback("ERROR: Invalid header");
                }
                return StoreError{ SignatureStoreError::CorruptedDatabase, 0, "Invalid header" };
            }

            if (logCallback) {
                logCallback("Header valid");
            }

            // Verify buckets
            for (const auto& [type, bucket] : m_buckets) {
                auto stats = bucket->GetStatistics();
                if (logCallback) {
                    std::ostringstream oss;
                    oss << "Bucket " << Format::HashTypeToString(type)
                        << ": " << stats.totalHashes << " hashes";
                    logCallback(oss.str());
                }
            }

            if (logCallback) {
                logCallback("Verification complete");
            }

            SS_LOG_INFO(L"HashStore", L"Verify: Complete");
            return StoreError{ SignatureStoreError::Success };
        }

        StoreError HashStore::Flush() noexcept {
            if (m_readOnly.load(std::memory_order_acquire)) {
                return StoreError{ SignatureStoreError::AccessDenied, 0, "Read-only mode" };
            }

            StoreError err{};
            if (!MemoryMapping::FlushView(m_mappedView, err)) {
                return err;
            }

            return StoreError{ SignatureStoreError::Success };
        }

        void HashStore::ClearCache() noexcept {
            // Clear cache using SeqLock protocol to prevent torn reads
            constexpr int MAX_SPIN_PER_ENTRY = 100;
            
            for (auto& entry : m_queryCache) {
                // Acquire write lock (set to odd)
                uint64_t oldSeq = entry.seqlock.load(std::memory_order_relaxed);
                int spinCount = 0;
                
                while (spinCount < MAX_SPIN_PER_ENTRY) {
                    // Wait if another write is in progress
                    if (oldSeq & 1) {
                        std::this_thread::yield();
                        oldSeq = entry.seqlock.load(std::memory_order_relaxed);
                        ++spinCount;
                        continue;
                    }
                    
                    if (entry.seqlock.compare_exchange_weak(
                            oldSeq, oldSeq + 1, 
                            std::memory_order_acquire, 
                            std::memory_order_relaxed)) {
                        break;
                    }
                    ++spinCount;
                }
                
                if (spinCount >= MAX_SPIN_PER_ENTRY) {
                    // Skip this entry if we can't acquire lock
                    SS_LOG_DEBUG(L"HashStore", L"ClearCache: Skipped entry due to contention");
                    continue;
                }
                
                // Clear the entry
                entry.hash = HashValue{};
                entry.result = std::nullopt;
                entry.timestamp = 0;
                
                // Release write lock (increment to even)
                entry.seqlock.store(oldSeq + 2, std::memory_order_release);
            }
        }

        void HashStore::SetBloomFilterConfig(
            size_t expectedElements,
            double falsePositiveRate
        ) noexcept {
            m_bloomExpectedElements = expectedElements;
            m_bloomFalsePositiveRate = falsePositiveRate;

            SS_LOG_INFO(L"HashStore",
                L"SetBloomFilterConfig: elements=%zu, FPR=%.4f",
                expectedElements, falsePositiveRate);
        }

  // ============================================================================

StoreError HashStore::OpenMemoryMapping(const std::wstring& path, bool readOnly) noexcept {
    StoreError err{};
    if (!MemoryMapping::OpenView(path, readOnly, m_mappedView, err)) {
        return err;
    }
    return StoreError{SignatureStoreError::Success};
}

void HashStore::CloseMemoryMapping() noexcept {
    MemoryMapping::CloseView(m_mappedView);
}

StoreError HashStore::InitializeBuckets() noexcept {
    const auto* header = GetHeader();
    if (!header) {
        SS_LOG_ERROR(L"HashStore", L"InitializeBuckets: Missing or invalid header");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Missing header"};
    }

    // Validate header offsets
    if (header->hashIndexOffset >= m_mappedView.fileSize) {
        SS_LOG_ERROR(L"HashStore", 
            L"InitializeBuckets: Hash index offset %llu exceeds file size %llu",
            header->hashIndexOffset, m_mappedView.fileSize);
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Invalid hash index offset"};
    }

    if (header->hashIndexSize == 0) {
        SS_LOG_ERROR(L"HashStore", L"InitializeBuckets: Zero hash index size");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Zero hash index size"};
    }

    // Calculate number of hash types (TLSH is currently highest enum value)
    constexpr uint8_t NUM_HASH_TYPES = static_cast<uint8_t>(HashType::TLSH) + 1;
    
    // Prevent division by zero
    if (NUM_HASH_TYPES == 0) {
        SS_LOG_ERROR(L"HashStore", L"InitializeBuckets: No hash types defined");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No hash types"};
    }

    const uint64_t bucketSize = header->hashIndexSize / NUM_HASH_TYPES;
    
    if (bucketSize == 0) {
        SS_LOG_ERROR(L"HashStore", 
            L"InitializeBuckets: Bucket size too small (indexSize=%llu, types=%u)",
            header->hashIndexSize, NUM_HASH_TYPES);
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Bucket size too small"};
    }

    uint64_t bucketOffset = header->hashIndexOffset;
    size_t bucketsInitialized = 0;

    for (uint8_t i = 0; i < NUM_HASH_TYPES; ++i) {
        HashType type = static_cast<HashType>(i);
        
        // Bounds check for this bucket
        if (bucketOffset > m_mappedView.fileSize ||
            bucketSize > m_mappedView.fileSize - bucketOffset) {
            SS_LOG_WARN(L"HashStore", 
                L"InitializeBuckets: Bucket %S exceeds file bounds, skipping",
                Format::HashTypeToString(type));
            continue;
        }
        
        try {
            auto bucket = std::make_unique<HashBucket>(type);
            StoreError err = bucket->Initialize(m_mappedView, bucketOffset, bucketSize);
            
            if (!err.IsSuccess()) {
                SS_LOG_WARN(L"HashStore", L"Failed to initialize bucket for %S: %S",
                    Format::HashTypeToString(type), err.message.c_str());
                // Continue with other buckets
            }
            else {
                m_buckets[type] = std::move(bucket);
                bucketsInitialized++;
            }
        }
        catch (const std::bad_alloc& ex) {
            SS_LOG_ERROR(L"HashStore", 
                L"InitializeBuckets: Memory allocation failed for %S: %S",
                Format::HashTypeToString(type), ex.what());
        }
        
        // Safe offset advancement with overflow check
        if (bucketOffset > UINT64_MAX - bucketSize) {
            SS_LOG_ERROR(L"HashStore", L"InitializeBuckets: Offset overflow");
            break;
        }
        bucketOffset += bucketSize;
    }

    if (bucketsInitialized == 0) {
        SS_LOG_ERROR(L"HashStore", L"InitializeBuckets: No buckets initialized");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "No buckets initialized"};
    }

    SS_LOG_INFO(L"HashStore", L"Initialized %zu hash buckets", bucketsInitialized);
    return StoreError{SignatureStoreError::Success};
}

HashBucket* HashStore::GetBucket(HashType type) noexcept {
    auto it = m_buckets.find(type);
    return (it != m_buckets.end()) ? it->second.get() : nullptr;
}

const HashBucket* HashStore::GetBucket(HashType type) const noexcept {
    auto it = m_buckets.find(type);
    return (it != m_buckets.end()) ? it->second.get() : nullptr;
}

uint64_t HashStore::AllocateSignatureEntry(size_t size) noexcept {
    // Thread-safe allocation using atomic fetch_add
    // Initial offset starts after header pages (100 pages reserved)
    static std::atomic<uint64_t> currentOffset{ PAGE_SIZE * 100 };
    
    // Validate size
    if (size == 0) {
        SS_LOG_ERROR(L"HashStore", L"AllocateSignatureEntry: Zero size requested");
        return UINT64_MAX;  // Invalid offset
    }
    
    constexpr size_t MAX_ENTRY_SIZE = 1024 * 1024;  // 1MB max per entry
    if (size > MAX_ENTRY_SIZE) {
        SS_LOG_ERROR(L"HashStore", 
            L"AllocateSignatureEntry: Size %zu exceeds maximum %zu", 
            size, MAX_ENTRY_SIZE);
        return UINT64_MAX;
    }

    const size_t alignedSize = Format::AlignToPage(size);
    
    // Check for overflow before allocation
    uint64_t current = currentOffset.load(std::memory_order_relaxed);
    if (current > UINT64_MAX - alignedSize) {
        SS_LOG_ERROR(L"HashStore", L"AllocateSignatureEntry: Offset overflow");
        return UINT64_MAX;
    }

    // Atomically reserve space and return the starting offset
    uint64_t offset = currentOffset.fetch_add(alignedSize, std::memory_order_acq_rel);
    
    // Verify the allocation is within bounds (if we have a valid file size)
    if (m_mappedView.IsValid() && offset + alignedSize > m_mappedView.fileSize) {
        SS_LOG_ERROR(L"HashStore", 
            L"AllocateSignatureEntry: Allocation exceeds file size (offset=%llu, size=%zu, fileSize=%llu)",
            offset, alignedSize, m_mappedView.fileSize);
        return UINT64_MAX;
    }

    return offset;
}

DetectionResult HashStore::BuildDetectionResult(
    const HashValue& hash,
    uint64_t signatureOffset
) const noexcept {
    DetectionResult result{};
    result.signatureId = signatureOffset;
    result.threatLevel = ThreatLevel::Medium;
    result.fileOffset = 0;
    result.matchTimestamp = static_cast<uint64_t>(
        std::chrono::system_clock::now().time_since_epoch().count());
    result.matchTimeNanoseconds = 0;
    
    // Safely build signature name
    try {
        result.signatureName = "Hash_" + Format::FormatHashString(hash);
    }
    catch (const std::exception&) {
        result.signatureName = "Hash_Unknown";
    }
    
    result.description = "Known malicious hash";
    
    return result;
}

std::optional<DetectionResult> HashStore::GetFromCache(const HashValue& hash) const noexcept {
    // Validate hash before using it for indexing
    if (hash.length == 0 || hash.length > 64) {
        return std::nullopt;
    }

    const uint64_t fastHash = hash.FastHash();
    const size_t cacheIdx = static_cast<size_t>(fastHash % CACHE_SIZE);
    const auto& entry = m_queryCache[cacheIdx];
    
    // SeqLock read: retry if writer is active or sequence changed
    constexpr int MAX_RETRIES = 5;
    for (int retry = 0; retry < MAX_RETRIES; ++retry) {
        uint64_t seq1 = entry.seqlock.load(std::memory_order_acquire);
        
        // Odd sequence means write in progress - yield and retry
        if (seq1 & 1) {
            std::this_thread::yield();
            continue;
        }
        
        // Read the data (these are copies, not references)
        HashValue readHash = entry.hash;
        std::optional<DetectionResult> readResult = entry.result;
        
        // Memory fence before reading sequence again
        std::atomic_thread_fence(std::memory_order_acquire);
        
        uint64_t seq2 = entry.seqlock.load(std::memory_order_acquire);
        
        // If sequence unchanged, read was consistent
        if (seq1 == seq2 && readHash == hash) {
            return readResult;
        }
        // Sequence changed during read - retry
    }
    
    // Cache miss or too many retries
    return std::nullopt;
}

void HashStore::AddToCache(
    const HashValue& hash,
    const std::optional<DetectionResult>& result
) const noexcept {
    // Validate hash before using it for indexing
    if (hash.length == 0 || hash.length > 64) {
        return;
    }

    const uint64_t fastHash = hash.FastHash();
    const size_t cacheIdx = static_cast<size_t>(fastHash % CACHE_SIZE);
    auto& entry = m_queryCache[cacheIdx];
    
    // SeqLock write: increment to odd (writing), write data, increment to even (done)
    uint64_t oldSeq = entry.seqlock.load(std::memory_order_relaxed);
    
    // Try to acquire write lock (set to odd)
    // Simple spin if another writer is active
    constexpr int MAX_SPIN_COUNT = 1000;
    int spinCount = 0;
    
    while (spinCount < MAX_SPIN_COUNT) {
        // Wait if another write is in progress (odd sequence)
        if (oldSeq & 1) {
            std::this_thread::yield();
            oldSeq = entry.seqlock.load(std::memory_order_relaxed);
            ++spinCount;
            continue;
        }
        
        // Try to acquire write lock by setting to odd
        if (entry.seqlock.compare_exchange_weak(
                oldSeq, oldSeq + 1, 
                std::memory_order_acquire, 
                std::memory_order_relaxed)) {
            break;  // Successfully acquired lock
        }
        
        // CAS failed, another thread got there first
        ++spinCount;
    }
    
    if (spinCount >= MAX_SPIN_COUNT) {
        // Gave up trying to acquire lock - skip caching this entry
        SS_LOG_DEBUG(L"HashStore", L"AddToCache: Gave up acquiring write lock");
        return;
    }
    
    // Now we hold the write lock (sequence is odd)
    entry.hash = hash;
    entry.result = result;
    entry.timestamp = m_cacheAccessCounter.fetch_add(1, std::memory_order_relaxed);
    
    // Release write lock (increment to even)
    entry.seqlock.store(oldSeq + 2, std::memory_order_release);
}

const SignatureDatabaseHeader* HashStore::GetHeader() const noexcept {
    return m_mappedView.GetAt<SignatureDatabaseHeader>(0);
}


} // namespace SignatureStore
} // namespace ShadowStrike
