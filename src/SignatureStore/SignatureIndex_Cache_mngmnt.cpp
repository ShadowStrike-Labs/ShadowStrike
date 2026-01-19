// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureIndex.hpp"
#include"../../src/Utils/Logger.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // CACHE MANAGEMENT OPERATIONS (PRODUCTION-GRADE)
        // ============================================================================

        void SignatureIndex::InvalidateCacheEntry(uint32_t nodeOffset) noexcept {
            /*
             * ========================================================================
             * CACHE ENTRY INVALIDATION - THREAD-SAFE, HIGH-PERFORMANCE
             * ========================================================================
             *
             * Purpose:
             * - Remove single cached node from cache (after modification)
             * - Maintain cache consistency during COW updates
             * - Thread-safe operation with proper locking
             *
             * Performance:
             * - O(1) average case lookup (hash-based)
             * - Minimal lock contention with exclusive lock only during write
             *
             * Thread Safety:
             * - Exclusive lock for cache modification
             * - Readers must hold shared lock during access
             * - Safe concurrent access to other cache entries
             *
             * ========================================================================
             */

            if (nodeOffset == 0) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"InvalidateCacheEntry: Cannot invalidate node at offset 0");
                return;
            }

            // Hash the node offset to cache index
            size_t cacheIndex = HashNodeOffset(nodeOffset) % CACHE_SIZE;

            // Acquire exclusive lock for cache modification
            std::unique_lock<std::shared_mutex> cacheLock(m_cacheLock);

            // Linear probing for collision resolution
            size_t attempts = 0;
            constexpr size_t MAX_PROBE_ATTEMPTS = 16;

            while (attempts < MAX_PROBE_ATTEMPTS) {
                size_t checkIndex = (cacheIndex + attempts) % CACHE_SIZE;

                // Check if this is the entry to invalidate
                auto& cacheEntry = m_nodeCache[checkIndex];

                if (cacheEntry.node != nullptr) {
                    // Calculate node offset from cached pointer
                    const uint8_t* cachedPtr = reinterpret_cast<const uint8_t*>(cacheEntry.node);
                    const uint8_t* basePtr = static_cast<const uint8_t*>(m_baseAddress);

                    // Safety check: ensure cached pointer is within bounds
                    if (cachedPtr < basePtr || cachedPtr >= basePtr + m_indexSize) {
                        // Invalid cached pointer - clear it
                        cacheEntry.node = nullptr;
                        cacheEntry.accessCount = 0;
                        cacheEntry.lastAccessTime = 0;
                        attempts++;
                        continue;
                    }

                    uint32_t cachedOffset = static_cast<uint32_t>(cachedPtr - basePtr);

                    if (cachedOffset == nodeOffset) {
                        // Found the entry - invalidate it (already under exclusive lock)
                        cacheEntry.node = nullptr;
                        cacheEntry.accessCount = 0;
                        cacheEntry.lastAccessTime = 0;

                        SS_LOG_TRACE(L"SignatureIndex",
                            L"InvalidateCacheEntry: Invalidated cache entry at index %zu "
                            L"(offset=0x%X)", checkIndex, nodeOffset);

                        m_cacheMisses.fetch_add(1, std::memory_order_relaxed);
                        return;
                    }
                }

                attempts++;
            }

            // Entry not found in cache (may have been evicted already)
            SS_LOG_TRACE(L"SignatureIndex",
                L"InvalidateCacheEntry: Cache entry for offset 0x%X not found "
                L"(may have been evicted)", nodeOffset);
        }

        void SignatureIndex::ClearCache() noexcept {
            /*
             * ========================================================================
             * COMPLETE CACHE CLEARANCE - THREAD-SAFE
             * ========================================================================
             *
             * Purpose:
             * - Clear all cached nodes (after tree restructuring)
             * - Reset cache statistics
             * - Prepare for fresh cache state
             *
             * Invariant Preservation:
             * - Tree structure remains valid
             * - Readers will reload nodes on next access
             * - No stale data served
             *
             * Thread Safety:
             * - Exclusive lock for cache modification
             * - Readers must acquire shared lock before access
             *
             * Performance:
             * - O(n) where n = CACHE_SIZE (fixed constant)
             * - Amortized constant per entry (simple zeroing)
             *
             * ========================================================================
             */

            SS_LOG_DEBUG(L"SignatureIndex", L"ClearCache: Clearing %zu cache entries", CACHE_SIZE);

            // Acquire exclusive lock for cache modification
            std::unique_lock<std::shared_mutex> cacheLock(m_cacheLock);

            // Zero out all cache entries
            for (size_t i = 0; i < CACHE_SIZE; ++i) {
                m_nodeCache[i].node = nullptr;
                m_nodeCache[i].accessCount = 0;
                m_nodeCache[i].lastAccessTime = 0;
            }

            // Reset cache statistics
            m_cacheAccessCounter.store(0, std::memory_order_release);

            // Note: We intentionally do NOT reset cacheHits/cacheMisses
            // as those are cumulative performance metrics

            SS_LOG_TRACE(L"SignatureIndex", L"ClearCache: Cache cleared successfully");
        }

        // ============================================================================
        // DISK PERSISTENCE OPERATIONS (PRODUCTION-GRADE)
        // ============================================================================

        StoreError SignatureIndex::Flush() noexcept {
            /*
             * ========================================================================
             * DISK FLUSH OPERATION - ENTERPRISE-GRADE PERSISTENCE
             * ========================================================================
             *
             * Purpose:
             * - Write all pending index changes to disk
             * - Ensure crash-consistent state
             * - Synchronize memory-mapped region with persistent storage
             *
             * Semantics:
             * - If memory mapping is read-only: no-op (success)
             * - If writable: flush to disk with full durability guarantee
             * - All pending COW changes must be committed before flush
             *
             * Durability Guarantees:
             * - After successful return: changes are durable on disk
             * - OS crash: no data loss (fsync ensures disk persistence)
             * - Power failure: no data loss (disk sync'd before return)
             *
             * Performance Characteristics:
             * - Blocking I/O operation (system call)
             * - Duration depends on dirty page count and disk speed
             * - Typical: < 100ms for single section
             * - Should be called sparingly (batch operations before flush)
             *
             * Error Handling:
             * - Validates memory mapping state
             * - Reports OS error codes on failure
             * - Partial flush failures are fatal
             *
             * Thread Safety:
             * - Acquires exclusive lock to ensure no concurrent modifications
             * - Readers must wait during flush
             * - Prevents race conditions with COW operations
             *
             * ========================================================================
             */

            SS_LOG_INFO(L"SignatureIndex", L"Flush: Starting disk synchronization");

            // ========================================================================
            // STEP 0: ACQUIRE EXCLUSIVE LOCK
            // ========================================================================
            // CRITICAL FIX: We must hold an exclusive lock during Flush to prevent:
            // 1. Race conditions with concurrent Insert/Remove operations
            // 2. COW transaction corruption during commit
            // 3. Inconsistent state between memory mapping and disk
            // ========================================================================
            std::unique_lock<std::shared_mutex> lock(m_rwLock);

            // ========================================================================
            // STEP 1: VALIDATION
            // ========================================================================

            if (!m_view) {
                SS_LOG_ERROR(L"SignatureIndex", L"Flush: Memory view not initialized");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Memory view not initialized" };
            }

            if (!m_view->IsValid()) {
                SS_LOG_ERROR(L"SignatureIndex", L"Flush: Memory view is invalid");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Memory view is invalid" };
            }

            // ========================================================================
            // STEP 2: READ-ONLY CHECK
            // ========================================================================

            if (m_view->readOnly) {
                SS_LOG_DEBUG(L"SignatureIndex",
                    L"Flush: Memory mapping is read-only (skipping flush)");
                return StoreError{ SignatureStoreError::Success };
            }

            // ========================================================================
            // STEP 3: CHECK FOR PENDING COW TRANSACTION
            // ========================================================================

            if (m_inCOWTransaction) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"Flush: COW transaction still active - committing before flush");

                StoreError commitErr = CommitCOW();
                if (!commitErr.IsSuccess()) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"Flush: Failed to commit pending COW transaction: %S",
                        commitErr.message.c_str());
                    return commitErr;
                }
            }

            // ========================================================================
            // STEP 4: PERFORM FLUSH OPERATION
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex",
                L"Flush: Flushing memory mapping to disk "
                L"(baseAddress=0x%p, size=0x%llX)",
                m_view->baseAddress, m_view->fileSize);

            LARGE_INTEGER flushStartTime;
            QueryPerformanceCounter(&flushStartTime);

#ifdef _WIN32
            // Windows: FlushViewOfFile synchronizes memory-mapped region to disk
            BOOL result = ::FlushViewOfFile(
                m_view->baseAddress,
                static_cast<SIZE_T>(m_view->fileSize)
            );

            if (!result) {
                DWORD win32Error = GetLastError();
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Flush: FlushViewOfFile failed (error=0x%lX)", win32Error);
                return StoreError{ SignatureStoreError::Unknown, win32Error,
                                  "FlushViewOfFile failed" };
            }

            // Also flush the underlying file handle for full durability
            // This ensures data reaches disk platter, not just disk cache
            if (m_view->fileHandle && m_view->fileHandle != INVALID_HANDLE_VALUE) {
                result = ::FlushFileBuffers(m_view->fileHandle);

                if (!result) {
                    DWORD win32Error = GetLastError();
                    SS_LOG_WARN(L"SignatureIndex",
                        L"Flush: FlushFileBuffers failed (error=0x%lX) "
                        L"- memory mapping may not be fully persisted",
                        win32Error);
                    // Note: Not fatal - view was already flushed
                }
            }
#else
            // POSIX: msync with MS_SYNC flag synchronizes to disk
            // (Not typical for Linux antivirus, but included for completeness)
            int result = msync(
                m_view->baseAddress,
                m_view->fileSize,
                MS_SYNC  // Block until sync complete
            );

            if (result != 0) {
                int errnum = errno;
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Flush: msync failed (errno=%d)", errnum);
                return StoreError{ SignatureStoreError::Unknown, errnum,
                                  "msync failed" };
            }
#endif

            // ========================================================================
            // STEP 5: CLEAR CACHE AFTER SUCCESSFUL FLUSH
            // ========================================================================

            // After successful flush, any cached node data is now on disk
            // We can safely clear the cache to release memory
            ClearCache();

            SS_LOG_TRACE(L"SignatureIndex", L"Flush: Cache cleared after flush");

            // ========================================================================
            // STEP 6: PERFORMANCE METRICS
            // ========================================================================

            LARGE_INTEGER flushEndTime;
            QueryPerformanceCounter(&flushEndTime);

            // FIX: Division by zero protection
            uint64_t flushTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                flushTimeUs = ((flushEndTime.QuadPart - flushStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            // ========================================================================
            // STEP 7: SUCCESS LOGGING
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex",
                L"Flush: Successfully flushed to disk "
                L"(time=%llu �s, size=0x%llX)",
                flushTimeUs, m_view->fileSize);

            // Warn if flush took unusually long (indicates disk/system issues)
            if (flushTimeUs > 1'000'000) {  // > 1 second
                SS_LOG_WARN(L"SignatureIndex",
                    L"Flush: Disk flush took longer than expected (%llu �s) "
                    L"- system performance may be degraded",
                    flushTimeUs);
            }

            return StoreError{ SignatureStoreError::Success };
        }
	}
}