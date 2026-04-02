/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
#include"pch.h"
#include"SignatureIndex.hpp"
#include"../Utils/Logger.hpp"

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // CACHE MANAGEMENT OPERATIONS (PRODUCTION-GRADE)
        // ============================================================================

        void SignatureIndex::InvalidateCacheEntry(uint64_t nodeOffset) noexcept {
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

            // Hash the node offset to the direct-mapped cache slot.
            // This matches GetNode() which uses the same hash for placement.
            // NOTE: Offset 0 is valid (root node in CreateNew mode).
            const size_t cacheIndex = HashNodeOffset(nodeOffset) % CACHE_SIZE;

            // Acquire exclusive lock for cache modification
            std::unique_lock<std::shared_mutex> cacheLock(m_cacheLock);

            // Direct-mapped cache: check only the hashed slot.
            // GetNode() writes to HashNodeOffset(offset) % CACHE_SIZE with no
            // collision handling, so the entry can only be at this exact index.
            auto& cacheEntry = m_nodeCache[cacheIndex];

            if (cacheEntry.node != nullptr) {
                // Calculate node offset from cached pointer
                const uint8_t* cachedPtr = reinterpret_cast<const uint8_t*>(cacheEntry.node);
                const uint8_t* basePtr = static_cast<const uint8_t*>(m_baseAddress);

                // Safety check: ensure cached pointer is within mapped region
                if (cachedPtr < basePtr || cachedPtr >= basePtr + m_indexSize) {
                    // Stale or corrupted cached pointer - clear unconditionally
                    cacheEntry.node = nullptr;
                    cacheEntry.accessCount = 0;
                    cacheEntry.lastAccessTime = 0;

                    SS_LOG_WARN(L"SignatureIndex",
                        L"InvalidateCacheEntry: Cleared out-of-bounds cached pointer "
                        L"at index %zu (offset=0x%X)", cacheIndex, nodeOffset);
                    return;
                }

                const uint64_t cachedOffset = static_cast<uint64_t>(cachedPtr - basePtr);

                if (cachedOffset == static_cast<uint64_t>(nodeOffset)) {
                    // Found the entry - invalidate it (already under exclusive lock)
                    cacheEntry.node = nullptr;
                    cacheEntry.accessCount = 0;
                    cacheEntry.lastAccessTime = 0;

                    SS_LOG_TRACE(L"SignatureIndex",
                        L"InvalidateCacheEntry: Invalidated cache entry at index %zu "
                        L"(offset=0x%X)", cacheIndex, nodeOffset);
                    return;
                }
            }

            // Entry not found at expected slot (may have been evicted or overwritten
            // by a different offset that hashes to the same slot)
            SS_LOG_TRACE(L"SignatureIndex",
                L"InvalidateCacheEntry: Cache entry for offset 0x%X not found "
                L"at slot %zu (may have been evicted)", nodeOffset, cacheIndex);
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

            // Compute the flush region: only the index section, not the entire file.
            // Flushing the whole file is wasteful and can stall the scan path for
            // seconds on large databases while the exclusive m_rwLock is held.
            const uint8_t* flushBase = static_cast<const uint8_t*>(m_view->baseAddress)
                                       + m_indexOffset;
            const SIZE_T flushSize = static_cast<SIZE_T>(
                (m_indexSize <= m_view->fileSize - m_indexOffset)
                    ? m_indexSize
                    : (m_view->fileSize - m_indexOffset));

            SS_LOG_DEBUG(L"SignatureIndex",
                L"Flush: Flushing index region to disk "
                L"(offset=0x%llX, size=0x%llX)",
                m_indexOffset, static_cast<uint64_t>(flushSize));

            LARGE_INTEGER flushStartTime;
            QueryPerformanceCounter(&flushStartTime);

#ifdef _WIN32
            // Windows: FlushViewOfFile synchronizes the index region to disk.
            // Only the dirty pages within this range are written, so scoping
            // the flush to the index section avoids flushing the header,
            // pattern index, YARA rules, and metadata sections unnecessarily.
            BOOL result = ::FlushViewOfFile(
                flushBase,
                flushSize
            );

            if (!result) {
                DWORD win32Error = GetLastError();
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Flush: FlushViewOfFile failed (error=0x%lX)", win32Error);
                return StoreError{ SignatureStoreError::Unknown, win32Error,
                                  "FlushViewOfFile failed" };
            }

            // FlushFileBuffers ensures data reaches the physical disk platter,
            // not just the OS disk cache. Without this, a power failure after
            // FlushViewOfFile could still lose data that's in the disk write cache.
            if (m_view->fileHandle && m_view->fileHandle != INVALID_HANDLE_VALUE) {
                result = ::FlushFileBuffers(m_view->fileHandle);

                if (!result) {
                    DWORD win32Error = GetLastError();
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"Flush: FlushFileBuffers failed (error=0x%lX) "
                        L"- durability guarantee NOT met, data may be lost on power failure",
                        win32Error);
                    return StoreError{ SignatureStoreError::Unknown, win32Error,
                                      "FlushFileBuffers failed - durability not guaranteed" };
                }
            }
#else
            // POSIX: msync with MS_SYNC flag synchronizes to disk
            int result = msync(
                const_cast<uint8_t*>(flushBase),
                static_cast<size_t>(flushSize),
                MS_SYNC
            );

            if (result != 0) {
                int errnum = errno;
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Flush: msync failed (errno=%d)", errnum);
                return StoreError{ SignatureStoreError::Unknown, static_cast<DWORD>(errnum),
                                  "msync failed" };
            }
#endif

            // ========================================================================
            // STEP 5: PERFORMANCE METRICS
            // ========================================================================
            // NOTE: We intentionally do NOT clear the node cache here.
            // The memory-mapped view is still valid after flush; cached pointers
            // still reference the same (now-persisted) memory locations. Clearing
            // the cache would force every subsequent GetNode call into a cache miss,
            // creating a thundering-herd effect on the hot scan path.
            // If CommitCOW() was called above (pending transaction), it already
            // cleared the cache as part of its commit sequence.

            LARGE_INTEGER flushEndTime;
            QueryPerformanceCounter(&flushEndTime);

            uint64_t flushTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                flushTimeUs = ((flushEndTime.QuadPart - flushStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            // ========================================================================
            // STEP 6: SUCCESS LOGGING
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex",
                L"Flush: Successfully flushed to disk "
                L"(time=%llu us, size=0x%llX)",
                flushTimeUs, static_cast<uint64_t>(flushSize));

            // Warn if flush took unusually long (indicates disk/system issues)
            if (flushTimeUs > 1'000'000) {  // > 1 second
                SS_LOG_WARN(L"SignatureIndex",
                    L"Flush: Disk flush took longer than expected (%llu us) "
                    L"- system performance may be degraded",
                    flushTimeUs);
            }

            return StoreError{ SignatureStoreError::Success };
        }
	}
}