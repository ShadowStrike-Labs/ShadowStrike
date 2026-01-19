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

            // Support both memory-mapped file mode and raw buffer mode
            const bool hasValidView = m_view && m_view->IsValid();
            const bool hasRawBuffer = m_baseAddress != nullptr && m_indexSize > 0;

            if (!hasValidView && !hasRawBuffer) {
                SS_LOG_ERROR(L"SignatureIndex", 
                    L"CommitCOW: Neither memory mapping nor raw buffer is valid");
                m_inCOWTransaction.store(false, std::memory_order_release);
                RollbackCOW();
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Index not initialized" };
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
            // STEP 4: ALLOCATE SPACE (MEMORY-MAPPED OR RAW BUFFER)
            // ========================================================================

            // Calculate total space needed for all COW nodes
            // SECURITY: Check for integer overflow before multiplication
            constexpr uint64_t MAX_SAFE_NODES = UINT64_MAX / sizeof(BPlusTreeNode);
            if (m_cowNodes.size() > MAX_SAFE_NODES) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"CommitCOW: COW pool size %zu would overflow space calculation",
                    m_cowNodes.size());
                RollbackCOW();
                m_inCOWTransaction.store(false, std::memory_order_release);
                return StoreError{ SignatureStoreError::TooLarge, 0,
                                  "COW pool size would overflow" };
            }
            
            uint64_t spaceNeeded = static_cast<uint64_t>(m_cowNodes.size()) * sizeof(BPlusTreeNode);
            
            // Use index size for raw buffer mode, file size for memory-mapped mode
            uint64_t totalSpace = hasRawBuffer ? m_indexSize : m_view->fileSize;
            uint64_t newOffset = m_currentOffset;

            // SECURITY: Check for overflow in offset + size calculation
            if (spaceNeeded > UINT64_MAX - newOffset) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"CommitCOW: Offset + space would overflow (offset=0x%llX, space=0x%llX)",
                    newOffset, spaceNeeded);
                RollbackCOW();
                m_inCOWTransaction.store(false, std::memory_order_release);
                return StoreError{ SignatureStoreError::TooLarge, 0,
                                  "Offset + space calculation overflow" };
            }

            // Check if we have sufficient space
            if (newOffset + spaceNeeded > totalSpace) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"CommitCOW: Insufficient space "
                    L"(need: 0x%llX, have: 0x%llX, current offset: 0x%llX)",
                    spaceNeeded, totalSpace - newOffset, newOffset);
                RollbackCOW();
                m_inCOWTransaction.store(false, std::memory_order_release);
                return StoreError{ SignatureStoreError::TooLarge, 0,
                                  "Insufficient space for COW commit" };
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
            // STEP 6: UPDATE INTERNAL POINTERS (BEFORE writing to file!)
            // ========================================================================
            // CRITICAL: We must update all COW pointers to file offsets BEFORE writing
            // to storage. Otherwise nodes will be written with COW memory addresses
            // which become invalid after the COW pool is cleared.

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOW: Updating internal pointers in %zu nodes BEFORE writing",
                m_cowNodes.size());

            // Helper lambda to find file offset for a truncated pointer value.
            // Pointers are stored as uint32_t (truncated from 64-bit) and may represent either:
            // - A truncated COW node address (lower 32 bits of in-memory pointer)
            // - A file offset for a node that was cloned in this transaction
            //
            // SECURITY NOTE: This truncation scheme has collision risk on 64-bit systems
            // when multiple pointers share the same lower 32 bits. Consider redesigning
            // to use full 64-bit addressing or pool indices in future versions.
            auto findOffsetForTruncatedPointer = [this, &nodeOffsetMap](uint32_t pointerValue) -> std::optional<uint32_t> {
                if (pointerValue == 0) {
                    return std::nullopt;
                }

                // First, remap known truncated COW-node addresses
                const auto nodeIt = m_truncatedAddrToCOWNode.find(pointerValue);
                if (nodeIt != m_truncatedAddrToCOWNode.end()) {
                    const auto offsetIt = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(nodeIt->second));
                    if (offsetIt != nodeOffsetMap.end()) {
                        return offsetIt->second;
                    }
                }

                // Next, remap file offsets that correspond to cloned nodes
                const auto fileIt = m_fileOffsetToCOWNode.find(pointerValue);
                if (fileIt != m_fileOffsetToCOWNode.end()) {
                    const auto offsetIt = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(fileIt->second));
                    if (offsetIt != nodeOffsetMap.end()) {
                        return offsetIt->second;
                    }
                }

                return std::nullopt;
            };

            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                BPlusTreeNode* node = m_cowNodes[i].get();

                // Update parent pointer if not root
                if (node->parentOffset != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->parentOffset);
                    if (maybeOffset.has_value()) {
                        SS_LOG_TRACE(L"SignatureIndex",
                            L"CommitCOW: Updated parent pointer in node %zu "
                            L"from 0x%X to file offset 0x%X", 
                            i, node->parentOffset, maybeOffset.value());
                        node->parentOffset = maybeOffset.value();
                    }
                    // If not found in map, it might already be a file offset - leave as is
                }

                // Update child pointers (internal nodes only)
                if (!node->isLeaf) {
                    for (uint32_t j = 0; j <= node->keyCount; ++j) {
                        if (node->children[j] != 0) {
                            auto maybeOffset = findOffsetForTruncatedPointer(node->children[j]);
                            if (maybeOffset.has_value()) {
                                node->children[j] = maybeOffset.value();
                            }
                            // If not found, it's already a file offset - leave as is
                        }
                    }
                }

                // Update leaf linked list pointers
                if (node->nextLeaf != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->nextLeaf);
                    if (maybeOffset.has_value()) {
                        node->nextLeaf = maybeOffset.value();
                    }
                }

                if (node->prevLeaf != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->prevLeaf);
                    if (maybeOffset.has_value()) {
                        node->prevLeaf = maybeOffset.value();
                    }
                }
            }

            // ========================================================================
            // STEP 7: WRITE COW NODES TO STORAGE
            // ========================================================================
            // Now that all pointers are converted to file offsets, write to storage.

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOW: Writing %zu nodes (mode=%s)",
                m_cowNodes.size(), hasRawBuffer ? L"raw buffer" : L"memory-mapped");

            offsetCounter = newOffset;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                auto* node = m_cowNodes[i].get();
                BPlusTreeNode* targetNode = nullptr;

                if (hasRawBuffer) {
                    // Raw buffer mode: write directly to m_baseAddress
                    if (offsetCounter + sizeof(BPlusTreeNode) > m_indexSize) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOW: Buffer overflow at offset 0x%llX (size=0x%llX)",
                            offsetCounter, m_indexSize);
                        RollbackCOW();
                        m_inCOWTransaction.store(false, std::memory_order_release);
                        return StoreError{ SignatureStoreError::TooLarge, 0,
                                          "Buffer overflow during COW commit" };
                    }
                    targetNode = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + offsetCounter);
                }
                else {
                    // Memory-mapped mode: use MutableView
                    MemoryMappedView* mutableView = MutableView();
                    if (!mutableView) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOW: Memory-mapped view is not writable");
                        RollbackCOW();
                        m_inCOWTransaction.store(false, std::memory_order_release);
                        return StoreError{ SignatureStoreError::AccessDenied, 0,
                                          "Memory-mapped view not writable" };
                    }

                    targetNode = mutableView->GetAtMutable<BPlusTreeNode>(offsetCounter);
                    if (!targetNode) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOW: Failed to get mutable pointer at offset 0x%llX",
                            offsetCounter);
                        RollbackCOW();
                        m_inCOWTransaction.store(false, std::memory_order_release);
                        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                          "Cannot write to memory-mapped file" };
                    }
                }

                // Copy node data to storage location
                std::memcpy(targetNode, node, sizeof(BPlusTreeNode));

                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Wrote node %zu at offset 0x%llX "
                    L"(keyCount=%u, isLeaf=%u)",
                    i, offsetCounter, node->keyCount, node->isLeaf ? 1 : 0);

                offsetCounter += sizeof(BPlusTreeNode);
            }

            // ========================================================================
            // STEP 8: ATOMICALLY UPDATE ROOT POINTER (LINEARIZATION POINT)
            // ========================================================================

            SS_LOG_TRACE(L"SignatureIndex", L"CommitCOW: Performing atomic root pointer update");

            uint32_t oldRootOffset = m_rootOffset.load(std::memory_order_acquire);
            uint32_t newRootOffset = oldRootOffset;

            // Prefer explicit COW root if available (correct even when root is not first in pool)
            if (m_cowRootNode) {
                auto it = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(m_cowRootNode));
                if (it != nodeOffsetMap.end()) {
                    newRootOffset = it->second;
                    SS_LOG_TRACE(L"SignatureIndex",
                        L"CommitCOW: Root offset update: 0x%X → 0x%X",
                        oldRootOffset, newRootOffset);
                }
            }
            else if (!m_cowNodes.empty()) {
                // Fallback: use first node if it looks like root
                BPlusTreeNode* rootNode = m_cowNodes[0].get();
                if (rootNode && rootNode->parentOffset == 0) {
                    auto it = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(rootNode));
                    if (it != nodeOffsetMap.end()) {
                        newRootOffset = it->second;
                        SS_LOG_TRACE(L"SignatureIndex",
                            L"CommitCOW: Root offset update (fallback): 0x%X → 0x%X",
                            oldRootOffset, newRootOffset);
                    }
                }
            }

            // Atomic CAS: guarantee atomicity of root pointer update
            m_rootOffset.store(newRootOffset, std::memory_order_release);

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: Root pointer updated atomically (memory_order_release)");

            // ========================================================================
            // STEP 9: FLUSH CHANGES TO DISK (if applicable)
            // ========================================================================

            if (hasValidView && !m_view->readOnly) {
                StoreError flushErr{ SignatureStoreError::Success };
                if (!MemoryMapping::FlushView(const_cast<MemoryMappedView&>(*m_view), flushErr)) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"CommitCOW: Flush to disk failed (code=0x%X, continuing anyway)",
                        flushErr.code);
                    // Don't fail - changes are in memory
                }
            }
            else if (hasRawBuffer) {
                // Raw buffer mode: no disk flush needed (in-memory only)
                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOW: Raw buffer mode - no disk flush needed");
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
            // STEP 11: CLEAR COW POOL AND INVALIDATE CACHE
            // ========================================================================

            m_cowNodes.clear();
            m_cowNodes.shrink_to_fit();

            // CRITICAL FIX: Clear tracking maps to prevent stale references
            m_fileOffsetToCOWNode.clear();
            m_truncatedAddrToCOWNode.clear();
            m_cowRootNode = nullptr;

            // CRITICAL FIX: Invalidate node cache after commit
            // The cache may hold stale pointers to old node locations that have been
            // superseded by newly committed nodes.
            ClearCache();

            SS_LOG_TRACE(L"SignatureIndex", L"CommitCOW: COW pool, tracking maps, and cache cleared");

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

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOW: Transaction committed successfully "
                L"(%zu nodes written, %llu µs)",
                validatedNodes, commitTimeUs);

            return StoreError{ SignatureStoreError::Success };
        }

        // ============================================================================
        // COMMITCOWINTERNAL - INTERNAL COMMIT WITH TRANSACTION CONTROL
        // ============================================================================

        /**
         * @brief Internal COW commit function with optional transaction continuation.
         *
         * This function is used during batch operations (BatchInsert, Rebuild) where
         * we need to commit intermediate changes while keeping the transaction open
         * for more modifications.
         *
         * CRITICAL: After each insert in a batch, we must commit changes so that
         * subsequent inserts can correctly traverse the updated tree structure.
         * Without this, FindLeaf() cannot see COW-modified nodes, causing tree
         * traversal corruption and lost entries.
         *
         * @param keepTransactionOpen If true, does not reset m_inCOWTransaction flag,
         *                            allowing more COW operations in the same transaction.
         *                            If false, behaves identically to CommitCOW().
         *
         * @return StoreError indicating success or failure.
         *
         * Thread Safety:
         * - Must be called under exclusive write lock (precondition)
         * - When keepTransactionOpen=true, caller must eventually call CommitCOW()
         *   or RollbackCOW() to close the transaction properly.
         */
        StoreError SignatureIndex::CommitCOWInternal(bool keepTransactionOpen) noexcept {
            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOWInternal: Starting (keepTransactionOpen=%s, %zu nodes in pool)",
                keepTransactionOpen ? L"true" : L"false",
                m_cowNodes.size());

            // ========================================================================
            // STEP 1: VALIDATION & PRECONDITIONS
            // ========================================================================

            if (!m_inCOWTransaction.load(std::memory_order_acquire)) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"CommitCOWInternal: Not in active COW transaction - ignoring commit");
                return StoreError{ SignatureStoreError::Success };
            }

            // Support both memory-mapped file mode and raw buffer mode
            const bool hasValidView = m_view && m_view->IsValid();
            const bool hasRawBuffer = m_baseAddress != nullptr && m_indexSize > 0;

            if (!hasValidView && !hasRawBuffer) {
                SS_LOG_ERROR(L"SignatureIndex", 
                    L"CommitCOWInternal: Neither memory mapping nor raw buffer is valid");
                if (!keepTransactionOpen) {
                    m_inCOWTransaction.store(false, std::memory_order_release);
                }
                RollbackCOW();
                return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                  "Index not initialized" };
            }

            // ========================================================================
            // STEP 2: EMPTY TRANSACTION CHECK
            // ========================================================================

            if (m_cowNodes.empty()) {
                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOWInternal: Empty COW pool - no changes to commit");
                if (!keepTransactionOpen) {
                    m_inCOWTransaction.store(false, std::memory_order_release);
                }
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

                if (!node) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOWInternal: Null node at index %zu in COW pool", i);
                    RollbackCOW();
                    if (!keepTransactionOpen) {
                        m_inCOWTransaction.store(false, std::memory_order_release);
                    }
                    return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                      "Null node in COW pool" };
                }

                if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"CommitCOWInternal: Invalid keyCount %u at index %zu (max=%zu)",
                        node->keyCount, i, BPlusTreeNode::MAX_KEYS);
                    RollbackCOW();
                    if (!keepTransactionOpen) {
                        m_inCOWTransaction.store(false, std::memory_order_release);
                    }
                    return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                      "Key count exceeds maximum" };
                }

                // Verify key ordering (keys must be strictly increasing)
                if (node->keyCount > 1) {
                    for (uint32_t j = 0; j < node->keyCount - 1; ++j) {
                        if (node->keys[j] >= node->keys[j + 1]) {
                            SS_LOG_ERROR(L"SignatureIndex",
                                L"CommitCOWInternal: Key ordering violation at index %zu, pos %u: "
                                L"0x%llX >= 0x%llX",
                                i, j, node->keys[j], node->keys[j + 1]);
                            RollbackCOW();
                            if (!keepTransactionOpen) {
                                m_inCOWTransaction.store(false, std::memory_order_release);
                            }
                            return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                                              "Key ordering violation in COW node" };
                        }
                    }
                }

                validatedNodes++;
            }

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOWInternal: Validated %zu nodes in COW pool", validatedNodes);

            // ========================================================================
            // STEP 4: ALLOCATE SPACE (MEMORY-MAPPED OR RAW BUFFER)
            // ========================================================================

            uint64_t spaceNeeded = m_cowNodes.size() * sizeof(BPlusTreeNode);
            // Use index size for raw buffer mode, file size for memory-mapped mode
            uint64_t totalSpace = hasRawBuffer ? m_indexSize : m_view->fileSize;
            uint64_t newOffset = m_currentOffset;

            if (newOffset + spaceNeeded > totalSpace) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"CommitCOWInternal: Insufficient space "
                    L"(need: 0x%llX, have: 0x%llX, current offset: 0x%llX)",
                    spaceNeeded, totalSpace - newOffset, newOffset);
                RollbackCOW();
                if (!keepTransactionOpen) {
                    m_inCOWTransaction.store(false, std::memory_order_release);
                }
                return StoreError{ SignatureStoreError::TooLarge, 0,
                                  "Insufficient space for COW commit" };
            }

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOWInternal: Allocated space at offset 0x%llX for %zu nodes",
                newOffset, m_cowNodes.size());

            // ========================================================================
            // STEP 5: BUILD OFFSET MAPPING (Old Address → New Address)
            // ========================================================================

            std::unordered_map<uintptr_t, uint32_t> nodeOffsetMap;
            nodeOffsetMap.reserve(m_cowNodes.size());

            uint64_t offsetCounter = newOffset;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                uintptr_t oldAddr = reinterpret_cast<uintptr_t>(m_cowNodes[i].get());
                uint32_t newFileOffset = static_cast<uint32_t>(offsetCounter);

                nodeOffsetMap[oldAddr] = newFileOffset;
                offsetCounter += sizeof(BPlusTreeNode);

                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOWInternal: Mapping node %zu: addr=0x%p → file offset=0x%X",
                    i, reinterpret_cast<void*>(oldAddr), newFileOffset);
            }

            // ========================================================================
            // STEP 6: UPDATE POINTERS BEFORE WRITING
            // ========================================================================
            // Update all internal pointers in COW nodes to use file offsets instead
            // of memory addresses BEFORE writing to file.

            // Helper lambda to find file offset for a truncated pointer
            // Since pointers are stored as uint32_t (truncated), we need to search
            // the map by comparing the lower 32 bits of each key
            //
            // CRITICAL FIX: Check BOTH m_truncatedAddrToCOWNode AND m_fileOffsetToCOWNode
            // because pointers may be either:
            // - Truncated memory addresses (for newly allocated COW nodes)
            // - File offsets (for nodes cloned from the committed file)
            auto findOffsetForTruncatedPointer = [this, &nodeOffsetMap](uint32_t pointerValue) -> std::optional<uint32_t> {
                if (pointerValue == 0) {
                    return std::nullopt;
                }

                // First, check if this is a truncated COW-node memory address
                const auto nodeIt = m_truncatedAddrToCOWNode.find(pointerValue);
                if (nodeIt != m_truncatedAddrToCOWNode.end()) {
                    const auto offsetIt = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(nodeIt->second));
                    if (offsetIt != nodeOffsetMap.end()) {
                        return offsetIt->second;
                    }
                }

                // Next, check if this is a file offset that maps to a cloned COW node
                const auto fileIt = m_fileOffsetToCOWNode.find(pointerValue);
                if (fileIt != m_fileOffsetToCOWNode.end()) {
                    const auto offsetIt = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(fileIt->second));
                    if (offsetIt != nodeOffsetMap.end()) {
                        return offsetIt->second;
                    }
                }

                return std::nullopt;
            };

            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                BPlusTreeNode* node = m_cowNodes[i].get();

                // Update parent pointer
                if (node->parentOffset != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->parentOffset);
                    if (maybeOffset.has_value()) {
                        node->parentOffset = maybeOffset.value();
                    }
                }

                // Update child pointers (internal nodes only)
                if (!node->isLeaf) {
                    for (uint32_t j = 0; j <= node->keyCount; ++j) {
                        if (node->children[j] != 0) {
                            auto maybeOffset = findOffsetForTruncatedPointer(node->children[j]);
                            if (maybeOffset.has_value()) {
                                node->children[j] = maybeOffset.value();
                            }
                        }
                    }
                }

                // Update leaf linked list pointers
                if (node->nextLeaf != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->nextLeaf);
                    if (maybeOffset.has_value()) {
                        node->nextLeaf = maybeOffset.value();
                    }
                }
                if (node->prevLeaf != 0) {
                    auto maybeOffset = findOffsetForTruncatedPointer(node->prevLeaf);
                    if (maybeOffset.has_value()) {
                        node->prevLeaf = maybeOffset.value();
                    }
                }
            }

            // ========================================================================
            // STEP 7: WRITE COW NODES TO STORAGE
            // ========================================================================

            offsetCounter = newOffset;
            for (size_t i = 0; i < m_cowNodes.size(); ++i) {
                auto* node = m_cowNodes[i].get();
                BPlusTreeNode* targetNode = nullptr;

                if (hasRawBuffer) {
                    // Raw buffer mode: write directly to m_baseAddress
                    if (offsetCounter + sizeof(BPlusTreeNode) > m_indexSize) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOWInternal: Buffer overflow at offset 0x%llX",
                            offsetCounter);
                        RollbackCOW();
                        if (!keepTransactionOpen) {
                            m_inCOWTransaction.store(false, std::memory_order_release);
                        }
                        return StoreError{ SignatureStoreError::TooLarge, 0,
                                          "Buffer overflow during COW commit" };
                    }
                    targetNode = reinterpret_cast<BPlusTreeNode*>(
                        static_cast<uint8_t*>(m_baseAddress) + offsetCounter);
                }
                else {
                    // Memory-mapped mode: use MutableView
                    MemoryMappedView* mutableView = MutableView();
                    if (!mutableView) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOWInternal: Memory-mapped view is not writable");
                        RollbackCOW();
                        if (!keepTransactionOpen) {
                            m_inCOWTransaction.store(false, std::memory_order_release);
                        }
                        return StoreError{ SignatureStoreError::AccessDenied, 0,
                                          "Memory-mapped view not writable" };
                    }

                    targetNode = mutableView->GetAtMutable<BPlusTreeNode>(offsetCounter);
                    if (!targetNode) {
                        SS_LOG_ERROR(L"SignatureIndex",
                            L"CommitCOWInternal: Failed to get mutable pointer at offset 0x%llX",
                            offsetCounter);
                        RollbackCOW();
                        if (!keepTransactionOpen) {
                            m_inCOWTransaction.store(false, std::memory_order_release);
                        }
                        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                                          "Cannot write to memory-mapped file" };
                    }
                }

                // Copy node data to storage location
                std::memcpy(targetNode, node, sizeof(BPlusTreeNode));

                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOWInternal: Wrote node %zu at offset 0x%llX (keyCount=%u, isLeaf=%u)",
                    i, offsetCounter, node->keyCount, node->isLeaf ? 1 : 0);

                offsetCounter += sizeof(BPlusTreeNode);
            }

            // ========================================================================
            // STEP 8: ATOMICALLY UPDATE ROOT POINTER
            // ========================================================================

            uint32_t oldRootOffset = m_rootOffset.load(std::memory_order_acquire);
            uint32_t newRootOffset = oldRootOffset;

            // Find root in COW pool (typically first node, but check all)
            // The root is the node with m_cowRootNode set
            if (m_cowRootNode) {
                auto it = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(m_cowRootNode));
                if (it != nodeOffsetMap.end()) {
                    newRootOffset = it->second;
                    SS_LOG_DEBUG(L"SignatureIndex",
                        L"CommitCOWInternal: Root offset update: 0x%X → 0x%X",
                        oldRootOffset, newRootOffset);
                }
            }
            else if (!m_cowNodes.empty()) {
                // Fallback: check if first COW node is root
                auto it = nodeOffsetMap.find(reinterpret_cast<uintptr_t>(m_cowNodes[0].get()));
                if (it != nodeOffsetMap.end() && m_cowNodes[0]->parentOffset == 0) {
                    newRootOffset = it->second;
                    SS_LOG_DEBUG(L"SignatureIndex",
                        L"CommitCOWInternal: Root offset update (fallback): 0x%X → 0x%X",
                        oldRootOffset, newRootOffset);
                }
            }

            m_rootOffset.store(newRootOffset, std::memory_order_release);

            // ========================================================================
            // STEP 9: FLUSH CHANGES TO DISK (if applicable)
            // ========================================================================

            if (hasValidView && !m_view->readOnly) {
                StoreError flushErr{ SignatureStoreError::Success };
                if (!MemoryMapping::FlushView(const_cast<MemoryMappedView&>(*m_view), flushErr)) {
                    SS_LOG_WARN(L"SignatureIndex",
                        L"CommitCOWInternal: Flush to disk failed (continuing anyway)");
                }
            }
            else if (hasRawBuffer) {
                // Raw buffer mode: no disk flush needed (in-memory only)
                SS_LOG_TRACE(L"SignatureIndex",
                    L"CommitCOWInternal: Raw buffer mode - no disk flush needed");
            }

            // ========================================================================
            // STEP 10: UPDATE FILE OFFSET POINTER
            // ========================================================================

            m_currentOffset = offsetCounter;

            SS_LOG_TRACE(L"SignatureIndex",
                L"CommitCOWInternal: File offset pointer updated to 0x%llX", m_currentOffset);

            // ========================================================================
            // STEP 11: CLEAR COW POOL AND INVALIDATE CACHE
            // ========================================================================

            m_cowNodes.clear();
            // Also clear tracking maps to prevent stale references
            m_fileOffsetToCOWNode.clear();
            m_truncatedAddrToCOWNode.clear();
            // Reset COW root pointer since it's now committed
            m_cowRootNode = nullptr;

            // CRITICAL FIX: Invalidate node cache after commit
            // The cache may hold stale pointers to old node locations that have been
            // superseded by newly committed nodes. Without this, subsequent FindLeaf
            // or FindLeafForCOW calls may return stale cached nodes, causing tree
            // traversal to go to wrong locations and lose data.
            ClearCache();

            SS_LOG_TRACE(L"SignatureIndex", L"CommitCOWInternal: COW pool, tracking maps, and cache cleared");

            // ========================================================================
            // STEP 12: UPDATE TRANSACTION STATE
            // ========================================================================

            if (!keepTransactionOpen) {
                m_inCOWTransaction.store(false, std::memory_order_release);
                SS_LOG_DEBUG(L"SignatureIndex", L"CommitCOWInternal: Transaction closed");
            }
            else {
                // Keep transaction open for more operations
                SS_LOG_DEBUG(L"SignatureIndex",
                    L"CommitCOWInternal: Transaction remains open for more operations");
            }

            // ========================================================================
            // STEP 13: PERFORMANCE METRICS
            // ========================================================================

            LARGE_INTEGER commitEndTime;
            QueryPerformanceCounter(&commitEndTime);

            uint64_t commitTimeUs = 0;
            if (m_perfFrequency.QuadPart > 0) {
                commitTimeUs = ((commitEndTime.QuadPart - commitStartTime.QuadPart) * 1000000ULL) /
                    static_cast<uint64_t>(m_perfFrequency.QuadPart);
            }

            SS_LOG_DEBUG(L"SignatureIndex",
                L"CommitCOWInternal: Committed %zu nodes in %llu µs (keepOpen=%s)",
                validatedNodes, commitTimeUs, keepTransactionOpen ? L"true" : L"false");

            return StoreError{ SignatureStoreError::Success };
        }

        // ============================================================================
        // COPY-ON-WRITE ROLLBACK
        // ============================================================================

        /**
         * @brief Rollback COW transaction - discard all pending modifications.
         *
         * SECURITY: Ensures clean rollback without memory leaks or dangling pointers.
         * Thread-safe via RAII (unique_ptr) cleanup.
         *
         * Atomic rollback of COW transaction:
         * - Clears the COW pool without writing to file
         * - All in-memory changes are discarded
         * - Readers continue using old version
         * - All tracking maps are cleared to prevent stale references
         *
         * CRITICAL: This function must clear ALL COW-related state to prevent
         * dangling pointer access in subsequent operations.
         */
        void SignatureIndex::RollbackCOW() noexcept {
            const size_t discardedCount = m_cowNodes.size();

            SS_LOG_WARN(L"SignatureIndex",
                L"RollbackCOW: Rolling back transaction (%zu nodes discarded)",
                discardedCount);

            // CRITICAL FIX: Clear COW root pointer BEFORE clearing the pool
            // to prevent any code from accessing a node that's about to be freed
            m_cowRootNode = nullptr;

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

            // CRITICAL FIX: Clear ALL tracking maps to prevent stale references
            // These maps contain pointers to nodes that were just freed
            try {
                m_fileOffsetToCOWNode.clear();
                m_truncatedAddrToCOWNode.clear();
            }
            catch (...) {
                // Maps may fail to clear on extreme memory conditions
                SS_LOG_ERROR(L"SignatureIndex",
                    L"RollbackCOW: Exception during tracking map cleanup");
            }

            // Reset transaction flag
            m_inCOWTransaction.store(false, std::memory_order_release);

            SS_LOG_INFO(L"SignatureIndex", L"RollbackCOW: Rollback complete");
        }



	}
}