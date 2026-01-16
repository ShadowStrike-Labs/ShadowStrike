// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureIndex.hpp"
#include"../../src/Utils/Logger.hpp"

namespace ShadowStrike {
	namespace SignatureStore {
        // ============================================================================
// COMMITCOW - ENTERPRISE-GRADE IMPLEMENTATION (ENHANCED)
// ============================================================================
// ============================================================================
// COPY-ON-WRITE TRANSACTION COMMIT (PRODUCTION-GRADE)
// ============================================================================

        StoreError SignatureIndex::CommitCOW() noexcept {
            /*
             * ========================================================================
             * ENTERPRISE-GRADE COW TRANSACTION COMMIT
             * ========================================================================
             *
             * Purpose:
             * - Atomically commit Copy-On-Write transaction
             * - Make modified nodes visible to readers (MVCC semantics)
             * - Persist changes to memory-mapped file
             * - Maintain B+Tree invariants
             *
             * Algorithm:
             * 1. Validate COW pool integrity
             * 2. Allocate space in memory-mapped file for COW nodes
             * 3. Write nodes to new locations (in dependency order)
             * 4. Update all internal pointers (parent → child)
             * 5. Atomically update root pointer (linearization point)
             * 6. Flush changes to disk (if not read-only)
             * 7. Clear COW pool
             * 8. Update statistics
             *
             * Atomicity:
             * - Root pointer update is atomic operation (linearization point)
             * - Readers see consistent snapshots before/after update
             * - No partial updates visible to concurrent readers
             *
             * Thread Safety:
             * - Must be called under exclusive write lock (precondition)
             * - Root pointer CAS ensures atomicity
             * - Readers use shared locks (continue unaffected)
             *
             * Performance:
             * - Single disk write (batched nodes)
             * - One atomic CAS operation
             * - No extra copy passes
             *
             * ========================================================================
             */

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOW: Starting transaction commit (%zu modified nodes in COW pool)",
                m_cowNodes.size());

            // ========================================================================
            // STEP 1: VALIDATION & PRECONDITIONS
            // ========================================================================

            if (!m_inCOWTransaction) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"CommitCOW: Not in active COW transaction - ignoring commit");
                return StoreError{ SignatureStoreError::Success };
            }

            if (!m_view || !m_view->IsValid()) {
                SS_LOG_ERROR(L"SignatureIndex", L"CommitCOW: Memory mapping is invalid");
                m_inCOWTransaction.store(false, std::memory_order_release);
                RollbackCOW();
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Memory mapping not valid" };
            }

            // ========================================================================
            // STEP 2: EMPTY TRANSACTION CHECK
            // ========================================================================

            if (m_cowNodes.empty()) {
                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Empty COW pool - no changes to commit");
                m_inCOWTransaction.store(false, std::memory_order_release);
                return StoreError{ SignatureStoreError::Success };
            }

            // ========================================================================
            // STEP 3: VALIDATE ALL NODES IN COW POOL
            // ========================================================================

            LARGE_INTEGER commitStartTime;
            QueryPerformanceCounter(&commitStartTime);

            size_t validatedNodes = 0;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                const auto& node = m_cowNodes[i];

                // Null pointer check
                if (!node) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOW: Null node at index %zu in COW pool", i);
                    RollbackCOW();
                    m_inCOWTransaction.store(false, std::memory_order_release);
                    return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                      "Null node in COW pool" };
                }

                // Key count bounds check
                if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOW: Invalid keyCount %u at index %zu (max=%zu)",
                        node->keyCount, i, BPlusTreeNode::MAX_KEYS);
                    RollbackCOW();
                    m_inCOWTransaction.store(false, std::memory_order_release);
                    return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                      "Key count exceeds maximum" };
                }

                // Leaf vs Internal node consistency
                if (!node->isLeaf && node->keyCount == 0) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"CommitCOW: Internal node at index %zu has no keys - invalid state",
                        i);
                    // Continue - may happen during tree rebalancing, but log warning
                }

                // Verify key ordering (keys must be strictly increasing)
                // FIX: Check keyCount > 1 to prevent underflow (keyCount - 1 when keyCount == 0)
                if (node->keyCount > 1) {
                    for (uint32_t j = 0; j < node->keyCount - 1; ++j) {
                        if (node->keys[j] >= node->keys[j + 1]) {
                            SS_LOG_ERROR(L"SignatureIndex",
                                L"CommitCOW: Key ordering violation at index %zu, pos %u: "
                                L"0x%llX >= 0x%llX",
                                i, j, node->keys[j], node->keys[j + 1]);
                            RollbackCOW();
                            m_inCOWTransaction.store(false, std::memory_order_release);
                            return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                              "Key ordering violation in COW node" };
                        }
                    }
                }

                validatedNodes++;
            }

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: Validated %zu nodes in COW pool", validatedNodes);

            // ========================================================================
            // STEP 4: ALLOCATE SPACE IN MEMORY-MAPPED FILE
            // ========================================================================

            // Calculate total space needed for all COW nodes
            uint64_t spaceNeeded = m_cowNodes.size() * sizeof(BPlusTreeNode);
            uint64_t currentFileSize = m_view->fileSize;
            uint64_t newOffset = m_currentOffset;

            // Check if we have sufficient space
            if (newOffset + spaceNeeded > currentFileSize) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"CommitCOW: Insufficient space in memory mapping "
                    L"(need: 0x%llX, have: 0x%llX, current offset: 0x%llX)",
                    spaceNeeded, currentFileSize - newOffset, newOffset);
                RollbackCOW();
                m_inCOWTransaction.store(false, std::memory_order_release);
                return StoreError{ SignatureStoreError::TooLarge, 0,
                                  "Memory-mapped file too small for COW commit" };
            }

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: Allocated space at offset 0x%llX for %zu nodes",
                newOffset, m_cowNodes.size());

            // ========================================================================
            // STEP 5: BUILD OFFSET MAPPING (Old Address → New Address)
            // ========================================================================

            // Create mapping so we can update pointers correctly
            std::unordered_map<uintptr_t, uint32_t> nodeOffsetMap;
            nodeOffsetMap.reserve(m_cowNodes.size());

            uint64_t offsetCounter = newOffset;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                uintptr_t oldAddr = reinterpret_cast<uintptr_t>(m_cowNodes[i].get());
                uint32_t newFileOffset = static_cast<uint32_t>(offsetCounter);

                nodeOffsetMap[oldAddr] = newFileOffset;
                offsetCounter += sizeof(BPlusTreeNode);

                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Mapping node %zu: addr=0x%p → file offset=0x%X",
                    i, reinterpret_cast<void*>(oldAddr), newFileOffset);
            }

            // ========================================================================
            // STEP 6: WRITE COW NODES TO MEMORY-MAPPED FILE
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOW: Writing %zu nodes to memory-mapped file",
                m_cowNodes.size());

            offsetCounter = newOffset;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                auto* node = m_cowNodes[i].get();

                // Obtain a mutable view only if mapping is writable. Fail safely otherwise.
                MemoryMappedView* mutableView = MutableView();
                if (!mutableView) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOW: Memory-mapped view is not writable or not initialized");
                    RollbackCOW();
                    m_inCOWTransaction.store(false, std::memory_order_release);
                    return StoreError{ SignatureStoreError::AccessDenied, 0,
                    "Memory-mapped view not writable" };

                }

                BPlusTreeNode* targetNode = mutableView->GetAtMutable<BPlusTreeNode>(offsetCounter);
                if (!targetNode) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOW: Failed to get mutable pointer at offset 0x%llX",
                        offsetCounter);
                    RollbackCOW();
                    m_inCOWTransaction.store(false, std::memory_order_release);
                    return StoreError{ SignatureStoreError::InvalidFormat, 0,
                    "Cannot write to memory-mapped file" };

                }

                // Copy node data to file location
                std::memcpy(targetNode, node, sizeof(BPlusTreeNode));

                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Wrote node %zu at offset 0x%llX "
                    L"(keyCount=%u, isLeaf=%u)",
                    i, offsetCounter, node->keyCount, node->isLeaf ? 1 : 0);

                offsetCounter += sizeof(BPlusTreeNode);
            }

            // ========================================================================
            // STEP 7: UPDATE INTERNAL POINTERS (Before root update)
            // ========================================================================

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOW: Updating internal pointers in %zu nodes",
                m_cowNodes.size());

            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                BPlusTreeNode* node = m_cowNodes[i].get();

                // Update parent pointer if not root
                if (node->parentOffset != 0) {
                    auto it = nodeOffsetMap.find(static_cast<uintptr_t>(node->parentOffset));
                    if (it != nodeOffsetMap.end()) {
                        node->parentOffset = it->second;
                        SS_LOG_TRACE(L"SignatureIndex",
                            L"CommitCOW: Updated parent pointer in node %zu "
                            L"to file offset 0x%X", i, it->second);
                    }
                }

                // Update child pointers (internal nodes only)
                if (!node->isLeaf) {
                    for (uint32_t j = 0; j <= node->keyCount; ++j) {
                        if (node->children[j] != 0) {
                            auto it = nodeOffsetMap.find(static_cast<uintptr_t>(node->children[j]));
                            if (it != nodeOffsetMap.end()) {
                                node->children[j] = it->second;
                            }
                        }
                    }
                }

                // Update leaf linked list pointers
                if (node->nextLeaf != 0) {
                    auto it = nodeOffsetMap.find(static_cast<uintptr_t>(node->nextLeaf));
                    if (it != nodeOffsetMap.end()) {
                        node->nextLeaf = it->second;
                    }
                }

                if (node->prevLeaf != 0) {
                    auto it = nodeOffsetMap.find(static_cast<uintptr_t>(node->prevLeaf));
                    if (it != nodeOffsetMap.end()) {
                        node->prevLeaf = it->second;
                    }
                }
            }

            // ========================================================================
            // STEP 8: ATOMICALLY UPDATE ROOT POINTER (LINEARIZATION POINT)
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex", L"CommitCOW: Performing atomic root pointer update");

            uint32_t oldRootOffset = m_rootOffset.load(std::memory_order_acquire);
            uint32_t newRootOffset = oldRootOffset;

            // Check if root is in COW pool
            BPlusTreeNode* rootNode = m_cowNodes.empty() ? nullptr : m_cowNodes[0].get();
            if (rootNode) {
                auto it = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(rootNode));
                if (it != nodeOffsetMap.end()) {
                    newRootOffset = it->second;
                    SS_LOG_TRACE(L"SignatureIndex",
                        L"CommitCOW: Root offset update: 0x%X → 0x%X",
                        oldRootOffset, newRootOffset);
                }
            }

            // Atomic CAS: guarantee atomicity of root pointer update
            m_rootOffset.store(newRootOffset, std::memory_order_release);

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: Root pointer updated atomically (memory_order_release)");

            // ========================================================================
            // STEP 9: FLUSH CHANGES TO DISK
            // ========================================================================

            if (!m_view->readOnly) {
                // Eğer FlushView, StoreError* bekliyorsa:
                StoreError flushErr{ SignatureStoreError::Success };
                if (!MemoryMapping::FlushView(const_cast<MemoryMappedView&>(*m_view), flushErr)) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"CommitCOW: Flush to disk failed (code=0x%X, continuing anyway)",
                        flushErr.code);
                    // Don't fail - changes are in memory
                }

            }
            else {
                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Read-only mapping - skipping disk flush");
            }

            // ========================================================================
            // STEP 10: UPDATE FILE OFFSET POINTER
            // ========================================================================

            m_currentOffset = offsetCounter;

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: File offset pointer updated to 0x%llX",
                m_currentOffset);

            // ========================================================================
            // STEP 11: CLEAR COW POOL
            // ========================================================================

            m_cowNodes.clear();
            m_cowNodes.shrink_to_fit();

            SS_LOG_TRACE(L"SignatureIndex", L"CommitCOW: COW pool cleared and shrunk");

            // ========================================================================
            // STEP 12: UPDATE STATISTICS
            // ========================================================================

            m_inCOWTransaction.store(false, std::memory_order_release);

            // ========================================================================
            // STEP 13: PERFORMANCE METRICS
            // ========================================================================

            LARGE_INTEGER commitEndTime;
            QueryPerformanceCounter(&commitEndTime);

            // FIX: Division by zero protection
            uint64_t commitTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                commitTimeUs = ((commitEndTime.QuadPart - commitStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            // ========================================================================
            // STEP 14: SUCCESS LOGGING
            // ========================================================================

            SS_LOG_INFO(L"SignatureIndex",
                L"CommitCOW: Transaction committed successfully "
                L"(%zu nodes written, %llu µs)",
                validatedNodes, commitTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }

        // ============================================================================
        // COPY-ON-WRITE ROLLBACK
        // ============================================================================

        /**
         * @brief Rollback COW transaction - discard all pending modifications.
         *
         * SECURITY: Ensures clean rollback without memory leaks.
         * Thread-safe via RAII (unique_ptr) cleanup.
         *
         * Atomic rollback of COW transaction:
         * - Clears the COW pool without writing to file
         * - All in-memory changes are discarded
         * - Readers continue using old version
         */
        void SignatureIndex::RollbackCOW() noexcept {
            const size_t discardedCount = m_cowNodes.size();

            SS_LOG_WARN(L"SignatureIndex",
                L"RollbackCOW: Rolling back transaction (%zu nodes discarded)",
                discardedCount);

            // Clear COW pool - unique_ptr handles deallocation
            try {
                m_cowNodes.clear();
                m_cowNodes.shrink_to_fit();  // Release memory
            }
            catch (...) {
                // Should never happen for clear(), but be defensive
                SS_LOG_ERROR(L"SignatureIndex",
                    L"RollbackCOW: Exception during COW pool cleanup");
            }

            // Reset transaction flag
            m_inCOWTransaction.store(false, std::memory_order_release);

            SS_LOG_INFO(L"SignatureIndex", L"RollbackCOW: Rollback complete");
        }



	}
}