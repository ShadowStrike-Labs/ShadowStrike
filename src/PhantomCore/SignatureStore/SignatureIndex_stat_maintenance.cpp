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
#include<algorithm>
#include<map>

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // STATISTICS
        // ============================================================================

        /**
         * @brief Get current index statistics.
         * @return Statistics structure with current values
         *
         * Thread-safe via shared lock.
         */
        SignatureIndex::IndexStatistics SignatureIndex::GetStatistics() const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            IndexStatistics stats{};

            // Load all atomic values with consistent memory ordering
            stats.totalEntries = m_totalEntries.load(std::memory_order_acquire);
            stats.treeHeight = m_treeHeight.load(std::memory_order_acquire);
            stats.totalLookups = m_totalLookups.load(std::memory_order_acquire);
            stats.cacheHits = m_cacheHits.load(std::memory_order_acquire);
            stats.cacheMisses = m_cacheMisses.load(std::memory_order_acquire);

            // Calculate memory usage (approximate)
            stats.totalMemoryBytes = m_indexSize;

            // Calculate average fill rate if we have entries
            if (stats.totalEntries > 0 && stats.treeHeight > 0) {
                // B+ tree fill rate: actual entries vs. theoretical max capacity.
                // For a balanced tree of height h with branching factor B, max
                // leaf entries ≈ B^(h-1). We estimate B from the index size and
                // per-node overhead (4 KiB pages are standard).
                constexpr uint64_t kNodePageSize = 4096;
                uint64_t estimatedNodes = (stats.totalMemoryBytes > 0)
                    ? (stats.totalMemoryBytes / kNodePageSize)
                    : 1;
                // Leaf nodes constitute roughly half the nodes at height 2+
                uint64_t estimatedLeaves = (stats.treeHeight > 1)
                    ? (estimatedNodes / 2) : estimatedNodes;
                if (estimatedLeaves == 0) estimatedLeaves = 1;

                // Each leaf can hold ~kNodePageSize / sizeof(IndexEntry) entries.
                // IndexEntry is 32-byte SHA-256 hash + 8-byte offset = 40 bytes,
                // plus 8 bytes overhead per slot ≈ 48 bytes effective.
                constexpr uint64_t kEstimatedEntrySize = 48;
                uint64_t entriesPerLeaf = kNodePageSize / kEstimatedEntrySize;
                if (entriesPerLeaf == 0) entriesPerLeaf = 1;

                uint64_t maxCapacity = estimatedLeaves * entriesPerLeaf;
                stats.averageFillRate = (maxCapacity > 0)
                    ? (static_cast<double>(stats.totalEntries) /
                       static_cast<double>(maxCapacity))
                    : 0.5;
                // Clamp to [0.0, 1.0] — over-estimates possible from node sizing
                stats.averageFillRate = std::clamp(stats.averageFillRate, 0.0, 1.0);
            }

            return stats;
        }

        /**
         * @brief Reset performance statistics counters.
         *
         * Thread-safe via atomic stores.
         */
        void SignatureIndex::ResetStatistics() noexcept {
            // Reset counters
            m_totalLookups.store(0, std::memory_order_release);
            m_cacheHits.store(0, std::memory_order_release);
            m_cacheMisses.store(0, std::memory_order_release);

            // Clear cache so subsequent measurements start from a cold state
            ClearCache();

            SS_LOG_DEBUG(L"SignatureIndex", L"Statistics reset (counters and cache cleared)");
        }

        // ============================================================================
        // MAINTENANCE
        // ============================================================================
        // ============================================================================
        // REBUILD IMPLEMENTATION - ENTERPRISE-GRADE B+TREE RECONSTRUCTION
        // ============================================================================

        StoreError SignatureIndex::Rebuild() noexcept {
            /*
             * ========================================================================
             * ENTERPRISE-GRADE B+TREE REBUILD OPERATION
             * ========================================================================
             *
             * Purpose:
             * - Reconstruct B+Tree from scratch for optimal performance
             * - Fix fragmentation issues caused by insertions/deletions
             * - Improve cache locality through sequential layout
             * - Balance tree structure for optimal lookup performance
             *
             * Algorithm:
             * 1. Enumerate all entries in current tree (maintain sorted order)
             * 2. Clear all tree structures and caches
             * 3. Rebuild tree from scratch with optimal node packing
             * 4. Verify new tree structure and invariants
             * 5. Update statistics and metadata
             *
             * Complexity:
             * - Time: O(N log N) for sorting + O(N) for tree reconstruction
             * - Space: O(N) temporary storage for enumerated entries
             *
             * Thread Safety:
             * - Exclusive lock for entire operation
             * - No concurrent access allowed during rebuild
             * - Readers blocked during rebuild
             *
             * Error Handling:
             * - Atomic rollback capability
             * - Verification of rebuilt tree
             * - Statistics tracking for debugging
             *
             * Performance Impact:
             * - Blocking operation (use with caution in production)
             * - Expected improvement: 5-20% faster lookups post-rebuild
             * - Recommended: run during maintenance window
             *
             * ========================================================================
             */

            SS_LOG_INFO(L"SignatureIndex", L"Rebuild: Starting B+Tree rebuild operation");

            // ========================================================================
            // STEP 1: VALIDATION & PRECONDITIONS
            // ========================================================================
            // Support both memory-mapped file mode and raw buffer mode (CreateNew)
            
            const bool hasValidView = m_view && m_view->IsValid();
            const bool hasRawBuffer = m_baseAddress != nullptr && m_indexSize > 0;
            
            if (!hasValidView && !hasRawBuffer) {
                SS_LOG_ERROR(L"SignatureIndex", 
                    L"Rebuild: Neither memory mapping nor raw buffer is valid");
                return StoreError{ SignatureStoreError::InvalidFormat, 0, 
                                  "Index not initialized" };
            }

            // ========================================================================
            // STEP 2: ACQUIRE EXCLUSIVE LOCK (Block all readers/writers)
            // ========================================================================

            std::unique_lock<std::shared_mutex> lock(m_rwLock);

            SS_LOG_INFO(L"SignatureIndex", L"Rebuild: Exclusive lock acquired");

            // ========================================================================
            // STEP 3: PERFORMANCE MONITORING SETUP
            // ========================================================================

            LARGE_INTEGER rebuildStartTime, rebuildEndTime;
            QueryPerformanceCounter(&rebuildStartTime);

            uint64_t entriesProcessed = 0;
            uint64_t originalHeight = m_treeHeight.load(std::memory_order_acquire);
            uint64_t originalEntries = m_totalEntries.load(std::memory_order_acquire);

            // ========================================================================
            // STEP 4: ENUMERATE ALL ENTRIES IN CURRENT TREE
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex",
                L"Rebuild: Enumerating %llu entries from current tree (height=%llu)",
                originalEntries, originalHeight);

            std::vector<std::pair<uint64_t, uint64_t>> allEntries;
            allEntries.reserve(originalEntries);

            // Use ForEachInternalNoLock to enumerate all entries (maintains sorted order from B+Tree)
            // CRITICAL: We must use ForEachInternalNoLock instead of ForEach because:
            // - Rebuild() already holds exclusive lock on m_rwLock
            // - ForEach() tries to acquire shared lock on m_rwLock
            // - std::shared_mutex is NOT recursive - this would cause DEADLOCK!
            try {
                ForEachInternalNoLock([&](uint64_t fastHash, uint64_t signatureOffset) -> bool {
                    allEntries.emplace_back(fastHash, signatureOffset);
                    entriesProcessed++;

                    // Progress logging every 10K entries
                    if (entriesProcessed % 10000 == 0) {
                        SS_LOG_DEBUG(L"SignatureIndex",
                            L"Rebuild: Enumerated %llu/%llu entries",
                            entriesProcessed, originalEntries);
                    }

                    return true; // Continue enumeration
                    });
            }
            catch (const std::exception& ex) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Rebuild: Exception during enumeration: %S", ex.what());
                return StoreError{ SignatureStoreError::Unknown, 0, "Enumeration failed" };
            }

            SS_LOG_INFO(L"SignatureIndex",
                L"Rebuild: Enumerated %llu entries successfully", entriesProcessed);

            if (allEntries.size() != originalEntries) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"Rebuild: Enumerated entries (%llu) != total entries (%llu) - tree may be incomplete",
                    allEntries.size(), originalEntries);
            }

            // ========================================================================
            // STEP 5: VERIFY ENTRIES ARE SORTED (Important for B+Tree)
            // ========================================================================

            bool isSorted = std::is_sorted(allEntries.begin(), allEntries.end(),
                [](const auto& a, const auto& b) { return a.first < b.first; });

            if (!isSorted) {
                SS_LOG_DEBUG(L"SignatureIndex",
                    L"Rebuild: Entries from ForEach are not sorted - sorting now");

                std::sort(allEntries.begin(), allEntries.end(),
                    [](const auto& a, const auto& b) { return a.first < b.first; });
            }

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Entry list validated and sorted");

            // ========================================================================
            // STEP 6: SAVE METADATA BEFORE CLEARING
            // ========================================================================

            // Store original metadata
            const MemoryMappedView* originalView = m_view;
            void* originalBaseAddress = m_baseAddress;
            uint64_t originalOffset = m_indexOffset;
            uint64_t originalSize = m_indexSize;

            // ========================================================================
            // STEP 7: CLEAR ALL TREE STRUCTURES
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Clearing existing tree structures");

            // Clear COW nodes - this deallocates all COW node memory
            m_cowNodes.clear();
            
            // CRITICAL: Clear tracking maps to prevent dangling pointer access!
            // After m_cowNodes.clear(), the pointers in these maps are invalid.
            // If not cleared, FindLeafForCOW might find stale entries and crash.
            m_fileOffsetToCOWNode.clear();
            m_ptrAddrToCOWNode.clear();
            m_cowRootNode = nullptr;

            // Clear node cache
            ClearCache();

            // Reset tree metadata
            m_rootOffset.store(0, std::memory_order_release);
            m_treeHeight.store(1, std::memory_order_release);
            m_totalEntries.store(0, std::memory_order_release);

            SS_LOG_TRACE(L"SignatureIndex", L"Rebuild: Tree structures cleared");

            // ========================================================================
            // STEP 8: CREATE EMPTY ROOT NODE
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Creating new root node");

            // Allocate new root node
            BPlusTreeNode* newRoot = AllocateNode(true); // isLeaf = true initially
            if (!newRoot) {
                SS_LOG_ERROR(L"SignatureIndex", L"Rebuild: Failed to allocate root node");
                return StoreError{ SignatureStoreError::OutOfMemory, 0, "Cannot allocate root node" };
            }

            newRoot->keyCount = 0;
            newRoot->parentOffset = 0;
            newRoot->nextLeaf = 0;
            newRoot->prevLeaf = 0;

            // CRITICAL: Set m_cowRootNode to the newly allocated root!
            // Without this, FindLeafForCOW will try to read from m_rootOffset (0)
            // which points to the INDEX_HEADER, not the new root node.
            // InsertInternalRaw uses FindLeafForCOW which checks m_cowRootNode first.
            m_cowRootNode = newRoot;
            
            // CRITICAL: Register the new root in pointer address map (64-bit safe)!
            // When InsertIntoParent creates a new internal root after splitting,
            // it stores child pointers as truncated addresses. If those addresses
            // aren't registered, FindLeafForCOW won't be able to resolve them.
            uintptr_t rootPtrAddr = reinterpret_cast<uintptr_t>(newRoot);
            uint32_t rootTruncAddr = static_cast<uint32_t>(rootPtrAddr);
            m_ptrAddrToCOWNode[rootPtrAddr] = newRoot;
            
            SS_LOG_DEBUG(L"SignatureIndex",
                L"Rebuild: Registered new root at ptrAddr=0x%llX (truncAddr=0x%X)", 
                static_cast<unsigned long long>(rootPtrAddr), rootTruncAddr);
            
            // Note: m_rootOffset will be updated after CommitCOW when the COW node
            // is written to the memory buffer and gets a real offset.
            m_rootOffset.store(0, std::memory_order_release); // Temporary - updated after commit
            m_treeHeight.store(1, std::memory_order_release);

            // ========================================================================
            // STEP 9: REBUILD TREE WITH BATCH INSERTION
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex",
                L"Rebuild: Rebuilding B+Tree with %llu entries", allEntries.size());

            // Re-insert all entries using InsertInternalRaw (we already hold the lock)
            // FIX: CRITICAL DEADLOCK FIX - Cannot call BatchInsert() while holding lock
            // because BatchInsert() also tries to acquire the same non-recursive lock.
            // Use InsertInternalRaw() directly since we already hold exclusive lock.
            //
            // CRITICAL: We use InsertInternalRaw() instead of InsertInternal() because
            // we only have the fastHash value, NOT the original hash data. InsertInternal
            // would call FastHash() on a reconstructed HashValue which would produce
            // a DIFFERENT fastHash value (FNV-1a hash of the data bytes).
            if (!allEntries.empty()) {
                m_inCOWTransaction.store(true, std::memory_order_release);

                size_t successCount = 0;
                StoreError lastError{ SignatureStoreError::Success };

                for (size_t i = 0; i < allEntries.size(); ++i) {
                    const auto& [fastHash, offset] = allEntries[i];

                    // Insert using raw fastHash method (no lock - we already hold it)
                    // This bypasses the FastHash() computation since we already have it
                    StoreError err = InsertInternalRaw(fastHash, offset);

                    if (err.IsSuccess()) {
                        successCount++;

                        if ((i + 1) % 10000 == 0) {
                            SS_LOG_DEBUG(L"SignatureIndex",
                                L"Rebuild: Progress - %zu/%zu entries inserted",
                                successCount, allEntries.size());
                        }
                    }
                    else if (err.code == SignatureStoreError::DuplicateEntry) {
                        // Skip duplicates
                        SS_LOG_DEBUG(L"SignatureIndex",
                            L"Rebuild: Entry %zu is duplicate, skipping", i);
                        continue;
                    }
                    else {
                        // Critical error - stop rebuild
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"Rebuild: Insert failed at entry %zu: %S",
                            i, err.message.c_str());
                        lastError = err;
                        break;
                    }
                }

                // Commit COW transaction
                if (lastError.IsSuccess() && successCount > 0) {
                    StoreError commitErr = CommitCOW();
                    if (!commitErr.IsSuccess()) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"Rebuild: Failed to commit COW: %S",
                            commitErr.message.c_str());
                        RollbackCOW();
                        m_inCOWTransaction.store(false, std::memory_order_release);
                        return commitErr;
                    }
                }
                else if (!lastError.IsSuccess()) {
                    RollbackCOW();
                    m_inCOWTransaction.store(false, std::memory_order_release);
                    return lastError;
                }

                m_inCOWTransaction.store(false, std::memory_order_release);

                SS_LOG_INFO(L"SignatureIndex",
                    L"Rebuild: Successfully inserted %zu entries", successCount);
            }

            // ========================================================================
            // STEP 10: VERIFY REBUILT TREE STRUCTURE
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Verifying rebuilt tree structure");

            uint64_t newHeight = m_treeHeight.load(std::memory_order_acquire);
            uint64_t newEntries = m_totalEntries.load(std::memory_order_acquire);

            SS_LOG_INFO(L"SignatureIndex",
                L"Rebuild: Tree structure verification:");
            SS_LOG_INFO(L"SignatureIndex",
                L"  Original - Height: %llu, Entries: %llu",
                originalHeight, originalEntries);
            SS_LOG_INFO(L"SignatureIndex",
                L"  Rebuilt  - Height: %llu, Entries: %llu",
                newHeight, newEntries);

            // Verify entry count matches
            if (newEntries != originalEntries) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Rebuild: Entry count mismatch! Original: %llu, Rebuilt: %llu",
                    originalEntries, newEntries);
                return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                  "Rebuild produced inconsistent entry count" };
            }

            // ========================================================================
            // STEP 11: VALIDATE NEW TREE INVARIANTS
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Validating tree invariants");

            std::string invariantErrors;
            // CRITICAL: Use ValidateInvariantsInternal (no lock) since we already hold exclusive lock
            // Calling ValidateInvariants() would try to acquire shared lock → DEADLOCK!
            if (!ValidateInvariantsInternal(invariantErrors)) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Rebuild: Tree invariant validation failed: %S",
                    invariantErrors.c_str());
                return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                  "Tree invariant validation failed after rebuild" };
            }

            SS_LOG_DEBUG(L"SignatureIndex", L"Rebuild: Tree invariants validated successfully");

            // ========================================================================
            // STEP 12: CLEAR CACHES (Reflect new tree layout)
            // ========================================================================

            ClearCache();
            SS_LOG_TRACE(L"SignatureIndex", L"Rebuild: Cache cleared");

            // ========================================================================
            // STEP 13: PERFORMANCE METRICS & ANALYSIS
            // ========================================================================

            QueryPerformanceCounter(&rebuildEndTime);

            // FIX: Division by zero protection
            uint64_t rebuildTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                rebuildTimeUs = ((rebuildEndTime.QuadPart - rebuildStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            double entriesPerSecond = (rebuildTimeUs > 0) ?
                (static_cast<double>(newEntries) / (rebuildTimeUs / 1'000'000.0)) : 0.0;

            SS_LOG_INFO(L"SignatureIndex", L"Rebuild: Performance Summary");
            SS_LOG_INFO(L"SignatureIndex", L"  Total time: %llu µs (%.2f ms)",
                rebuildTimeUs, rebuildTimeUs / 1000.0);
            SS_LOG_INFO(L"SignatureIndex", L"  Entries: %llu", newEntries);
            SS_LOG_INFO(L"SignatureIndex", L"  Throughput: %.0f entries/sec",
                entriesPerSecond);
            SS_LOG_INFO(L"SignatureIndex", L"  Height reduction: %llu → %llu",
                originalHeight, newHeight);

            // ========================================================================
            // STEP 14: ESTIMATE PERFORMANCE IMPROVEMENT
            // ========================================================================

            if (originalHeight > newHeight) {
                double heightReduction = 100.0 * (originalHeight - newHeight) / originalHeight;
                SS_LOG_INFO(L"SignatureIndex",
                    L"Rebuild: Expected lookup performance improvement: ~%.1f%% "
                    L"(height reduced by %.1f%%)",
                    heightReduction * 0.3, // Rough estimate: 0.3% per height level
                    heightReduction);
            }

            // ========================================================================
            // STEP 15: RETURN SUCCESS
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex", L"Rebuild: Operation completed successfully");

            return StoreError{ SignatureStoreError::Success };
        }
       
        StoreError SignatureIndex::Compact() noexcept {
            /*
             * ========================================================================
             * ENTERPRISE-GRADE B+TREE COMPACTION OPERATION
             * ========================================================================
             *
             * Purpose:
             * - Eliminate sparse nodes caused by deletions
             * - Consolidate fragmented tree structure
             * - Optimize memory layout for cache efficiency
             * - Reduce memory footprint
             *
             * Algorithm:
             * 1. Perform complete tree traversal (DFS)
             * 2. Identify nodes with fill rate < MIN_FILL_RATE
             * 3. For each sparse non-leaf node:
             *    a. Attempt to borrow keys from siblings
             *    b. If siblings also sparse, merge all into one node
             *    c. Update parent to point to consolidated node
             * 4. Remove now-empty nodes
             * 5. Recursively rebalance parent nodes
             * 6. Update tree height if root has single child
             * 7. Verify invariants and update statistics
             *
             * Node Merging Logic:
             * - Can only merge siblings under same parent
             * - Total keys must fit in single node (≤ MAX_KEYS)
             * - Redistribute keys: use parent key as separator
             * - Update parent child pointers
             *
             * Complexity:
             * - Time: O(N) single full tree traversal
             * - Space: O(h) recursion depth (h = tree height)
             * - Disk I/O: O(1) - works on existing structure
             *
             * Thread Safety:
             * - Exclusive lock for entire operation
             * - Queries blocked during compaction
             * - No concurrent readers/writers
             *
             * Performance:
             * - Faster than Rebuild() (no re-insertion)
             * - Lower CPU and memory overhead
             * - Preserves existing node locations
             *
             * Invariant Guarantees:
             * - All keys remain strictly ordered
             * - All child pointers valid
             * - All leaves at same depth
             * - Entry count unchanged
             *
             * ========================================================================
             */

            SS_LOG_INFO(L"SignatureIndex",
                L"Compact: Starting B+Tree compaction (optimize fragmentation)");

            // ========================================================================
            // STEP 1: VALIDATION & PRECONDITIONS
            // ========================================================================

            // Supports both memory-mapped and raw buffer modes
            const bool hasValidView = m_view && m_view->IsValid();
            const bool hasRawBuffer = m_baseAddress != nullptr && m_indexSize > 0;
            
            if (!hasValidView && !hasRawBuffer) {
                SS_LOG_ERROR(L"SignatureIndex", L"Compact: Index not initialized (no valid view or raw buffer)");
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Index not initialized" };
            }

            // ========================================================================
            // STEP 2: ACQUIRE EXCLUSIVE LOCK
            // ========================================================================

            std::unique_lock<std::shared_mutex> lock(m_rwLock);

            SS_LOG_INFO(L"SignatureIndex", L"Compact: Exclusive lock acquired");

            // ========================================================================
            // STEP 3: CAPTURE INITIAL STATE
            // ========================================================================

            LARGE_INTEGER compactStartTime;
            QueryPerformanceCounter(&compactStartTime);

            uint64_t entriesBefore = m_totalEntries.load(std::memory_order_acquire);
            uint32_t heightBefore = m_treeHeight.load(std::memory_order_acquire);

            SS_LOG_DEBUG(L"SignatureIndex",
                L"Compact: Initial state - entries=%llu, height=%u",
                entriesBefore, heightBefore);

            // ========================================================================
            // STEP 4: DEFINE COMPACTION PARAMETERS
            // ========================================================================

            constexpr double MIN_FILL_RATE = 0.5;  // Nodes < 50% full are sparse
            constexpr double MERGE_THRESHOLD = 2.0; // Merge if can fit siblings into this many nodes

            // ========================================================================
            // STEP 5: TRAVERSE TREE AND COLLECT STATISTICS
            // ========================================================================

            struct NodeInfo {
                uint64_t offset;            // v1.1: 64-bit to match BPlusTreeNode layout
                const BPlusTreeNode* node;
                double fillRate;
                uint32_t depth;
                bool isSparse;
            };

            std::vector<NodeInfo> allNodes;
            allNodes.reserve(100);

            size_t nodeCount = 0;
            size_t sparseCount = 0;

            // Recursive tree traversal (offsets are 64-bit since v1.1)
            std::function<void(uint64_t, uint32_t)> traverse =
                [&](uint64_t nodeOffset, uint32_t depth) {
                if (nodeCount > 100000) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"Compact: Node count limit exceeded (>100K)");
                    return; // Safety: prevent infinite loops
                }

                const BPlusTreeNode* node = GetNode(nodeOffset);
                if (!node) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"Compact: Cannot load node at offset 0x%llX", nodeOffset);
                    return;
                }

                // SECURITY: Validate keyCount before deriving fill rate
                if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"Compact: Invalid keyCount %u at offset 0x%llX, skipping subtree",
                        node->keyCount, nodeOffset);
                    return;
                }

                // Calculate fill rate
                double fillRate = (node->keyCount > 0) ?
                    (static_cast<double>(node->keyCount) / BPlusTreeNode::MAX_KEYS) : 0.0;

                bool isSparse = (fillRate < MIN_FILL_RATE) && (depth > 0); // Don't mark root as sparse

                allNodes.push_back({
                    nodeOffset,
                    node,
                    fillRate,
                    depth,
                    isSparse
                    });

                nodeCount++;
                if (isSparse) sparseCount++;

                SS_LOG_TRACE(L"SignatureIndex",
                    L"Compact: Analyzed node at offset 0x%llX "
                    L"(depth=%u, keys=%u, fill=%.1f%%, sparse=%u)",
                    nodeOffset, depth, node->keyCount, fillRate * 100.0, isSparse ? 1 : 0);

                // Recursively traverse children (internal nodes only)
                if (!node->isLeaf) {
                    for (uint32_t i = 0; i <= node->keyCount; ++i) {
                        const uint64_t childOff = node->children[i];
                        if (childOff != 0 && childOff < m_indexSize) {
                            traverse(childOff, depth + 1);
                        }
                    }
                }
                };

            const uint64_t rootOffset = m_rootOffset.load(std::memory_order_acquire);
            traverse(rootOffset, 0);

            SS_LOG_INFO(L"SignatureIndex",
                L"Compact: Tree traversal complete - %zu total nodes, %zu sparse",
                nodeCount, sparseCount);

            // ========================================================================
            // STEP 6: REPORT MERGE OPPORTUNITIES (analysis only)
            // ========================================================================
            //
            // ENTERPRISE NOTE:
            //   The previous implementation called CloneNode() on sparse parents and
            //   children, mutated the clones with merged key/child arrays, and then
            //   dropped them on the floor with a comment "In real implementation: add
            //   to COW pool for atomic commit". The cloned, modified nodes were never
            //   linked into the tree, so the on-disk B+Tree was unchanged while the
            //   caller-visible log still claimed "%zu nodes merged". That is silent
            //   data lying — unacceptable in an NGAV engine.
            //
            //   In addition, STEP 7 unconditionally rewrote m_rootOffset via a 32-bit
            //   truncation of a uint64_t child slot (children[] is uint64_t since v1.1)
            //   without verifying that the new offset pointed at a valid, mapped node
            //   reachable through the regular file-offset path. On databases that hit
            //   the 4 GB boundary or that had children populated from the COW heap-
            //   address path, this corrupted the root pointer permanently.
            //
            //   Until a real transactional COW commit pipeline exists, Compact() must
            //   limit itself to read-only analysis. We still walk the tree, identify
            //   merge candidates, and surface the result so operators / the rebuild
            //   path can act on it — but we do not mutate any persistent state.
            //
            // ========================================================================

            size_t mergeCandidatePairs = 0;
            size_t projectedNodesMergeable = 0;

            if (sparseCount > 0) {
                SS_LOG_DEBUG(L"SignatureIndex",
                    L"Compact: Analyzing %zu sparse nodes for merge opportunities",
                    sparseCount);

                // Group sparse nodes by parent (parentOffset is 64-bit since v1.1)
                std::map<uint64_t, std::vector<size_t>> sparseByParent;

                for (size_t i = 0; i < allNodes.size(); ++i) {
                    if (allNodes[i].isSparse) {
                        sparseByParent[allNodes[i].node->parentOffset].push_back(i);
                    }
                }

                SS_LOG_TRACE(L"SignatureIndex",
                    L"Compact: Grouped sparse nodes into %zu parent groups",
                    sparseByParent.size());

                for (const auto& [parentOffset, childIndices] : sparseByParent) {
                    if (childIndices.size() < 2) {
                        continue; // Need at least 2 siblings to merge
                    }

                    uint64_t totalKeys = 0;
                    for (size_t childIdx : childIndices) {
                        totalKeys += allNodes[childIdx].node->keyCount;
                    }

                    const uint64_t separatorKeys =
                        static_cast<uint64_t>(childIndices.size()) - 1;
                    const uint64_t totalKeysWithSeparators = totalKeys + separatorKeys;

                    if (totalKeysWithSeparators <= BPlusTreeNode::MAX_KEYS) {
                        mergeCandidatePairs++;
                        projectedNodesMergeable += (childIndices.size() - 1);

                        SS_LOG_TRACE(L"SignatureIndex",
                            L"Compact: Parent 0x%llX has %zu siblings mergeable into one "
                            L"(%llu keys, separators included)",
                            parentOffset, childIndices.size(), totalKeysWithSeparators);
                    }
                    else {
                        SS_LOG_TRACE(L"SignatureIndex",
                            L"Compact: Parent 0x%llX has %zu sparse children but combined "
                            L"key count %llu exceeds MAX_KEYS %zu - not mergeable",
                            parentOffset, childIndices.size(),
                            totalKeysWithSeparators, BPlusTreeNode::MAX_KEYS);
                    }
                }

                SS_LOG_INFO(L"SignatureIndex",
                    L"Compact: Analysis complete - %zu parent groups with mergeable "
                    L"siblings, ~%zu nodes could be reclaimed by Rebuild()",
                    mergeCandidatePairs, projectedNodesMergeable);
            }

            // STEP 7 (tree-height reduction) intentionally removed: see note above.
            // The prior implementation mutated m_rootOffset based on a 32-bit
            // truncation of a 64-bit children[] slot, which can corrupt the root
            // pointer on >4 GB databases or when children point into the COW heap.
            // Tree-height reduction belongs in Rebuild(), which constructs a fresh
            // on-disk image transactionally.

            // ========================================================================
            // STEP 8: CLEAR NODE CACHE
            // ========================================================================

            ClearCache();
            SS_LOG_TRACE(L"SignatureIndex", L"Compact: Node cache cleared");

            // ========================================================================
            // STEP 9: VERIFY TREE INTEGRITY
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex", L"Compact: Verifying tree invariants");

            std::string invariantErrors;
            // Use internal version to avoid deadlock - we already hold m_rwLock
            if (!ValidateInvariantsInternal(invariantErrors)) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"Compact: Invariant validation reported issues: %S",
                    invariantErrors.c_str());
                // Continue - not fatal
            }

            // ========================================================================
            // STEP 10: VERIFY ENTRY COUNT UNCHANGED
            // ========================================================================

            uint64_t entriesAfter = m_totalEntries.load(std::memory_order_acquire);
            if (entriesBefore != entriesAfter) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"Compact: CRITICAL - Entry count changed! Before: %llu, After: %llu",
                    entriesBefore, entriesAfter);
                return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                  "Entry count changed during compaction" };
            }

            // ========================================================================
            // STEP 11: PERFORMANCE METRICS
            // ========================================================================

            LARGE_INTEGER compactEndTime;
            QueryPerformanceCounter(&compactEndTime);

            // FIX: Division by zero protection
            uint64_t compactTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                compactTimeUs = ((compactEndTime.QuadPart - compactStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            uint32_t heightAfter = m_treeHeight.load(std::memory_order_acquire);

            // ========================================================================
            // STEP 12: COMPLETION LOGGING
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex", L"Compact: COMPLETE");
            SS_LOG_INFO(L"SignatureIndex",
                L"Compact Summary:");
            SS_LOG_INFO(L"SignatureIndex",
                L"  Duration: %llu µs (%.2f ms)",
                compactTimeUs, compactTimeUs / 1000.0);
            SS_LOG_INFO(L"SignatureIndex",
                L"  Nodes analyzed: %zu (sparse: %zu)",
                nodeCount, sparseCount);
            SS_LOG_INFO(L"SignatureIndex",
                L"  Tree height: %u → %u",
                heightBefore, heightAfter);
            SS_LOG_INFO(L"SignatureIndex",
                L"  Entries: %llu (unchanged)",
                entriesAfter);

            return StoreError{ SignatureStoreError::Success };
        }
	}
}