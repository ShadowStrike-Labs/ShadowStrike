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
#include "SignatureIndex.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <cstring>
#include <new>


namespace ShadowStrike {

    namespace SignatureStore {

// ============================================================================
// COW POOL CONSTANTS
// ============================================================================

namespace {
    // Maximum number of COW (Copy-On-Write) nodes in the transaction pool.
    // This limit prevents unbounded memory growth during large batch inserts.
    // Shared by AllocateNode and CloneNode.
    constexpr size_t MAX_COW_NODES = 10000;
} // anonymous namespace

// ============================================================================
// INTERNAL NODE MANAGEMENT
// ============================================================================
// ============================================================================
// FINDLEAF - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

const BPlusTreeNode* SignatureIndex::FindLeaf(uint64_t fastHash) const noexcept {
    /*
     * ========================================================================
     * ENTERPRISE-GRADE LEAF NODE TRAVERSAL
     * ========================================================================
     *
     * Purpose:
     * - Navigate B+Tree from root to leaf node containing target hash
     * - Thread-safe lock-free reads (multiple concurrent readers)
     * - Cache-aware node access for sub-microsecond performance
     *
     * Algorithm:
     * - Start at root node
     * - Binary search keys in each internal node
     * - Follow child pointers to next level
     * - Repeat until leaf node reached
     *
     * Complexity: O(log N) where N = total entries
     *
     * Security:
     * - Bounds checking on all array accesses
     * - Corruption detection (invalid pointers, offsets)
     * - Infinite loop prevention via cycle detection
     *
     * Performance:
     * - Lock-free reads (no mutex acquisition)
     * - Node cache for hot nodes (< 50ns cache hit)
     * - Cache-line aligned node structure
     *
     * ========================================================================
     */

     // ========================================================================
     // STEP 1: VALIDATE STATE & ACQUIRE ROOT
     // ========================================================================

    uint64_t nodeOffset = m_rootOffset.load(std::memory_order_acquire);

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindLeaf: Starting search for fastHash=0x%llX from root offset=0x%llX",
        fastHash, nodeOffset);

    // Validate root offset is within bounds
    if (nodeOffset >= m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"FindLeaf: Root offset 0x%llX exceeds index size 0x%llX",
            nodeOffset, m_indexSize);
        return nullptr;
    }

    const BPlusTreeNode* node = GetNode(nodeOffset);
    if (!node) {
        SS_LOG_ERROR(L"SignatureIndex", L"FindLeaf: Failed to get root node");
        return nullptr;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindLeaf: Root node isLeaf=%u, keyCount=%u",
        node->isLeaf ? 1 : 0, node->keyCount);

    // ========================================================================
    // STEP 2: TRAVERSE TREE FROM ROOT TO LEAF
    // ========================================================================

    // Infinite loop prevention (max tree height = 10 for 2^127 entries)
    constexpr uint32_t MAX_TREE_DEPTH = 20;
    uint32_t depth = 0;

    // Track visited offsets to detect cycles (corruption detection)
    uint64_t visitedOffsets[MAX_TREE_DEPTH + 1] = { 0 };
    visitedOffsets[0] = nodeOffset;

    while (node && !node->isLeaf) {
        // ====================================================================
        // DEPTH CHECK (Corruption/Loop Detection)
        // ====================================================================

        if (depth >= MAX_TREE_DEPTH) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Maximum tree depth exceeded (depth=%u, fastHash=0x%llX) - "
                L"possible corruption or infinite loop",
                depth, fastHash);
            return nullptr;
        }
        ++depth;

        // ====================================================================
        // VALIDATE NODE STRUCTURE
        // ====================================================================

        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Invalid keyCount %u (max=%zu) at depth %u",
                node->keyCount, BPlusTreeNode::MAX_KEYS, depth);
            return nullptr;
        }

        // Empty internal nodes are invalid in B+Tree
        if (node->keyCount == 0) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Empty internal node at depth %u (corruption)",
                depth);
            return nullptr;
        }

        // ====================================================================
        // BINARY SEARCH FOR CHILD POINTER
        // ====================================================================

        uint32_t pos = BinarySearch(node->keys, node->keyCount, fastHash);

        // Navigate to appropriate child:
        // - If fastHash >= keys[pos], go to right child (pos + 1)
        // - Otherwise, go to left child (pos)
        if (pos < node->keyCount && fastHash >= node->keys[pos]) {
            pos++; // Go to right child
        }

        // ====================================================================
        // BOUNDS CHECKING ON CHILD INDEX
        // ====================================================================

        if (pos >= BPlusTreeNode::MAX_CHILDREN) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Child index %u exceeds MAX_CHILDREN %zu (corruption)",
                pos, BPlusTreeNode::MAX_CHILDREN);
            return nullptr;
        }

        // ====================================================================
        // RETRIEVE NEXT NODE
        // ====================================================================

        nodeOffset = node->children[pos];

        // Validate child offset is non-zero (0 = null pointer in B+Tree)
        if (nodeOffset == 0) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Null child pointer at pos %u, depth %u",
                pos, depth);
            return nullptr;
        }

        // Validate child offset is within index bounds
        if (nodeOffset >= m_indexSize) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Child offset 0x%llX exceeds index size 0x%llX at depth %u",
                nodeOffset, m_indexSize, depth);
            return nullptr;
        }

        // Cycle detection - check if we've visited this offset before
        for (uint32_t i = 0; i < depth; ++i) {
            if (visitedOffsets[i] == nodeOffset) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"FindLeaf: Cycle detected - offset 0x%llX visited at depth %u, now at depth %u",
                    nodeOffset, i, depth);
                return nullptr;
            }
        }
        // Record this offset for future cycle detection
        if (depth < MAX_TREE_DEPTH) {
            visitedOffsets[depth] = nodeOffset;
        }

        // Get next node from cache or memory
        node = GetNode(nodeOffset);

        if (!node) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeaf: Failed to retrieve child node at offset 0x%llX, depth %u",
                nodeOffset, depth);
            return nullptr;
        }

        SS_LOG_TRACE(L"SignatureIndex",
            L"FindLeaf: Traversed to child at offset 0x%llX, depth %u, keyCount=%u",
            nodeOffset, depth, node->keyCount);
    }

    // ========================================================================
    // STEP 3: VALIDATE FINAL LEAF NODE
    // ========================================================================

    if (!node) {
        SS_LOG_WARN(L"SignatureIndex", L"FindLeaf: Traversal resulted in null node");
        return nullptr;
    }

    if (!node->isLeaf) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"FindLeaf: Final node is not a leaf (corruption at depth %u)",
            depth);
        return nullptr;
    }

    // Leaf nodes can have 0 keys (empty tree edge case)
    if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"FindLeaf: Leaf node keyCount %u exceeds MAX_KEYS %zu",
            node->keyCount, BPlusTreeNode::MAX_KEYS);
        return nullptr;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindLeaf: Found leaf at offset=0x%llX, keyCount=%u, fastHash=0x%llX",
        nodeOffset, node->keyCount, fastHash);
    if (node->keyCount > 0) {
        SS_LOG_TRACE(L"SignatureIndex",
            L"FindLeaf: Leaf key[0]=0x%llX, key[last]=0x%llX",
            node->keys[0], node->keys[node->keyCount - 1]);
    }

    return node;
}

// ============================================================================
// FINDLEAFFORCOW - COW-AWARE LEAF TRAVERSAL WITH PATH COPYING
// ============================================================================

BPlusTreeNode* SignatureIndex::FindLeafForCOW(uint64_t fastHash) noexcept {
    /*
     * ========================================================================
     * COW-AWARE LEAF NODE TRAVERSAL WITH PATH COPYING
     * ========================================================================
     *
     * Purpose:
     * - Navigate B+Tree from root to leaf during COW transaction
     * - Clone the entire traversal path (path-copying) for proper COW semantics
     * - Update parent-child pointers along the cloned path
     *
     * Why path-copying is needed:
     * - COW trees require that modifications don't affect the original nodes
     * - When we modify a leaf, its parent's child pointer needs to be updated
     * - But we can't modify the parent in-place (COW), so we clone it too
     * - This continues up to the root, hence "path-copying"
     *
     * Algorithm:
     * 1. If no m_cowRootNode, clone root from file and set m_cowRootNode
     * 2. Traverse from m_cowRootNode, cloning each node along the path
     * 3. Update each parent's child pointer to point to cloned child
     * 4. Return the cloned leaf
     *
     * NOTE (v1.1): All pointer addresses are stored as full 64-bit values in
     * the node's uint64_t fields (children[], parentOffset, nextLeaf, prevLeaf).
     * This eliminates the pointer truncation collision risk that existed when
     * the fields were uint32_t. Lookup uses FindCOWNodeByAddr (exact match).
     *
     * ========================================================================
     */

    // ========================================================================
    // STEP 1: ENSURE COW ROOT EXISTS
    // ========================================================================

    if (!m_cowRootNode) {
        // Clone the file root to start COW transaction
        uint64_t rootOffset = m_rootOffset.load(std::memory_order_acquire);

        // Check if root was already cloned in this transaction
        auto it = m_fileOffsetToCOWNode.find(rootOffset);
        if (it != m_fileOffsetToCOWNode.end()) {
            m_cowRootNode = it->second;
        }
        else {
            // Clone root from file
            const BPlusTreeNode* fileRoot = GetNode(rootOffset);
            if (!fileRoot) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"FindLeafForCOW: Failed to get root node at offset 0x%llX", rootOffset);
                return nullptr;
            }

            BPlusTreeNode* clonedRoot = CloneNode(fileRoot);
            if (!clonedRoot) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"FindLeafForCOW: Failed to clone root node");
                return nullptr;
            }

            // Register the cloned root
            m_fileOffsetToCOWNode[rootOffset] = clonedRoot;
            m_cowRootNode = clonedRoot;

            SS_LOG_TRACE(L"SignatureIndex",
                L"FindLeafForCOW: Cloned file root at offset 0x%llX", rootOffset);
        }
    }

    // ========================================================================
    // STEP 2: TRAVERSE FROM COW ROOT WITH PATH COPYING
    // ========================================================================

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindLeafForCOW: Traversing from COW root for fastHash=0x%llX", fastHash);

    BPlusTreeNode* node = m_cowRootNode;

    // Infinite loop prevention
    constexpr uint32_t MAX_TREE_DEPTH = 20;
    uint32_t depth = 0;

    while (node && !node->isLeaf) {
        // Depth check
        if (depth >= MAX_TREE_DEPTH) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeafForCOW: Maximum tree depth exceeded");
            return nullptr;
        }
        ++depth;

        // Validate node
        if (node->keyCount > BPlusTreeNode::MAX_KEYS || node->keyCount == 0) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeafForCOW: Invalid keyCount %u at depth %u",
                node->keyCount, depth);
            return nullptr;
        }

        // Binary search for child position
        uint32_t pos = BinarySearch(node->keys, node->keyCount, fastHash);

        // Navigate to appropriate child
        if (pos < node->keyCount && fastHash >= node->keys[pos]) {
            pos++; // Go to right child
        }

        if (pos >= BPlusTreeNode::MAX_CHILDREN) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeafForCOW: Child index %u out of bounds", pos);
            return nullptr;
        }

        // Get child value - may be a full pointer address (COW) or file offset
        uint64_t childAddr = node->children[pos];

        if (childAddr == 0) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"FindLeafForCOW: Null child pointer at pos %u", pos);
            return nullptr;
        }

        // ================================================================
        // RESOLVE CHILD: Try COW node first, then file node
        // ================================================================

        // Check if this is a COW node address (exact 64-bit lookup, no truncation)
        BPlusTreeNode* cowNode = FindCOWNodeByAddr(childAddr);
        if (cowNode != nullptr) {
            // Found in COW node map - use COW node directly
            node = cowNode;
            SS_LOG_TRACE(L"SignatureIndex",
                L"FindLeafForCOW: Resolved addr 0x%llX to COW node",
                static_cast<unsigned long long>(childAddr));
        }
        else {
            // Not a COW node address - must be a file offset
            // Check if we already have a COW clone of this file offset
            auto fileIt = m_fileOffsetToCOWNode.find(childAddr);
            if (fileIt != m_fileOffsetToCOWNode.end()) {
                node = fileIt->second;
                SS_LOG_TRACE(L"SignatureIndex",
                    L"FindLeafForCOW: Found existing COW clone for file offset 0x%llX",
                    static_cast<unsigned long long>(childAddr));
            }
            else {
                // Load from file and clone
                if (childAddr >= m_indexSize) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"FindLeafForCOW: Child offset 0x%llX exceeds index size",
                        static_cast<unsigned long long>(childAddr));
                    return nullptr;
                }

                const BPlusTreeNode* fileNode = GetNode(childAddr);
                if (!fileNode) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"FindLeafForCOW: Failed to get node at offset 0x%llX",
                        static_cast<unsigned long long>(childAddr));
                    return nullptr;
                }

                // Clone the file node
                BPlusTreeNode* clonedNode = CloneNode(fileNode);
                if (!clonedNode) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"FindLeafForCOW: Failed to clone node at offset 0x%llX",
                        static_cast<unsigned long long>(childAddr));
                    return nullptr;
                }

                // Register the clone in file offset map
                m_fileOffsetToCOWNode[childAddr] = clonedNode;

                // Update parent's child pointer to point to cloned node.
                // NOTE (v1.1): Store FULL pointer address - children[] is uint64_t,
                // so no truncation is needed. This eliminates collision risk.
                const uint64_t clonedAddr = static_cast<uint64_t>(
                    reinterpret_cast<uintptr_t>(clonedNode));
                node->children[pos] = clonedAddr;

                // Update cloned node's parentOffset to point to current parent
                const uint64_t parentAddr = static_cast<uint64_t>(
                    reinterpret_cast<uintptr_t>(node));
                clonedNode->parentOffset = parentAddr;

                // ================================================================
                // LINKED LIST MAINTENANCE FOR LEAF NODES
                // ================================================================
                // When we clone a leaf node, we MUST update the linked list pointers
                // of adjacent leaves to maintain proper enumeration support.
                //
                // Without this:
                // - ForEach() using linked list would see stale pointers
                // - RangeQuery() would fail to traverse consecutive leaves
                // ================================================================

                if (clonedNode->isLeaf) {
                    uint64_t prevLeafAddr = clonedNode->prevLeaf;
                    uint64_t nextLeafAddr = clonedNode->nextLeaf;

                    SS_LOG_TRACE(L"SignatureIndex",
                        L"FindLeafForCOW: Maintaining linked list for cloned leaf "
                        L"(prevLeaf=0x%llX, nextLeaf=0x%llX)",
                        static_cast<unsigned long long>(prevLeafAddr),
                        static_cast<unsigned long long>(nextLeafAddr));

                    // ============================================================
                    // UPDATE PREVIOUS LEAF'S NEXTLEAF POINTER
                    // ============================================================
                    if (prevLeafAddr != 0) {
                        BPlusTreeNode* prevLeafNode = nullptr;

                        // Check if prevLeaf is already a COW node (exact 64-bit lookup)
                        prevLeafNode = FindCOWNodeByAddr(prevLeafAddr);
                        if (prevLeafNode != nullptr) {
                            SS_LOG_TRACE(L"SignatureIndex",
                                L"FindLeafForCOW: Found prevLeaf in COW pool");
                        }
                        else if (prevLeafAddr < m_indexSize) {
                            // It's a file offset - check if we have a COW clone
                            auto prevFileIt = m_fileOffsetToCOWNode.find(prevLeafAddr);
                            if (prevFileIt != m_fileOffsetToCOWNode.end()) {
                                prevLeafNode = prevFileIt->second;
                            }
                            else {
                                // Need to clone the previous leaf
                                const BPlusTreeNode* prevLeafConst = GetNode(prevLeafAddr);
                                if (prevLeafConst && prevLeafConst->isLeaf) {
                                    prevLeafNode = CloneNode(prevLeafConst);
                                    if (prevLeafNode) {
                                        m_fileOffsetToCOWNode[prevLeafAddr] = prevLeafNode;

                                        // Update clonedNode's prevLeaf to point to cloned prev
                                        const uint64_t prevAddr = static_cast<uint64_t>(
                                            reinterpret_cast<uintptr_t>(prevLeafNode));
                                        clonedNode->prevLeaf = prevAddr;
                                    }
                                }
                            }
                        }

                        // Update prevLeaf's nextLeaf to point to our cloned node
                        if (prevLeafNode) {
                            prevLeafNode->nextLeaf = clonedAddr;
                        }
                    }

                    // ============================================================
                    // UPDATE NEXT LEAF'S PREVLEAF POINTER
                    // ============================================================
                    if (nextLeafAddr != 0) {
                        BPlusTreeNode* nextLeafNode = nullptr;

                        // Check if nextLeaf is already a COW node (exact 64-bit lookup)
                        nextLeafNode = FindCOWNodeByAddr(nextLeafAddr);
                        if (nextLeafNode != nullptr) {
                            SS_LOG_TRACE(L"SignatureIndex",
                                L"FindLeafForCOW: Found nextLeaf in COW pool");
                        }
                        else if (nextLeafAddr < m_indexSize) {
                            // It's a file offset - check if we have a COW clone
                            auto nextFileIt = m_fileOffsetToCOWNode.find(nextLeafAddr);
                            if (nextFileIt != m_fileOffsetToCOWNode.end()) {
                                nextLeafNode = nextFileIt->second;
                            }
                            else {
                                // Need to clone the next leaf
                                const BPlusTreeNode* nextLeafConst = GetNode(nextLeafAddr);
                                if (nextLeafConst && nextLeafConst->isLeaf) {
                                    nextLeafNode = CloneNode(nextLeafConst);
                                    if (nextLeafNode) {
                                        m_fileOffsetToCOWNode[nextLeafAddr] = nextLeafNode;

                                        // Update clonedNode's nextLeaf to point to cloned next
                                        const uint64_t nextAddr = static_cast<uint64_t>(
                                            reinterpret_cast<uintptr_t>(nextLeafNode));
                                        clonedNode->nextLeaf = nextAddr;
                                    }
                                }
                            }
                        }

                        // Update nextLeaf's prevLeaf to point to our cloned node
                        if (nextLeafNode) {
                            nextLeafNode->prevLeaf = clonedAddr;
                        }
                    }
                }

                node = clonedNode;
                SS_LOG_TRACE(L"SignatureIndex",
                    L"FindLeafForCOW: Cloned file node at offset 0x%llX -> COW addr 0x%llX",
                    static_cast<unsigned long long>(childAddr),
                    static_cast<unsigned long long>(clonedAddr));
            }
        }
    }

    // ========================================================================
    // VALIDATE RESULT
    // ========================================================================

    if (!node) {
        SS_LOG_ERROR(L"SignatureIndex", L"FindLeafForCOW: Traversal resulted in null");
        return nullptr;
    }

    if (!node->isLeaf) {
        SS_LOG_ERROR(L"SignatureIndex", L"FindLeafForCOW: Final node is not a leaf");
        return nullptr;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindLeafForCOW: Found leaf keyCount=%u for fastHash=0x%llX",
        node->keyCount, fastHash);

    return node;
}

// ============================================================================
// FINDINSERTIONPOINT - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

uint32_t SignatureIndex::FindInsertionPoint(
    const BPlusTreeNode* node,
    uint64_t fastHash
) const noexcept {
    /*
     * ========================================================================
     * INSERTION POINT FINDER
     * ========================================================================
     *
     * Purpose:
     * - Find correct position to insert new key in sorted array
     * - Maintains B+Tree sorted key invariant
     *
     * Complexity: O(log K) where K = keys in node
     *
     * Returns:
     * - Index where fastHash should be inserted (0 to keyCount)
     * - If duplicate exists, returns index of duplicate
     *
     * ========================================================================
     */

     // ========================================================================
     // VALIDATION
     // ========================================================================

    if (!node) {
        SS_LOG_ERROR(L"SignatureIndex", L"FindInsertionPoint: Null node pointer");
        return 0;
    }

    if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"FindInsertionPoint: Invalid keyCount %u (max=%zu)",
            node->keyCount, BPlusTreeNode::MAX_KEYS);
        return 0;
    }

    // ========================================================================
    // BINARY SEARCH
    // ========================================================================

    uint32_t pos = BinarySearch(node->keys, node->keyCount, fastHash);

    // Validate result is within valid range
    if (pos > node->keyCount) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"FindInsertionPoint: BinarySearch returned out-of-bounds position %u (keyCount=%u)",
            pos, node->keyCount);
        return node->keyCount; // Failsafe: insert at end
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"FindInsertionPoint: pos=%u for fastHash=0x%llX (keyCount=%u)",
        pos, fastHash, node->keyCount);

    return pos;
}

// ============================================================================
// SPLITNODE - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

StoreError SignatureIndex::SplitNode(
    BPlusTreeNode* node,
    uint64_t& splitKey,
    BPlusTreeNode** newNode
) noexcept {
    /*
     * ========================================================================
     * B+TREE NODE SPLITTING
     * ========================================================================
     *
     * Purpose:
     * - Split full node into two nodes
     * - Maintain B+Tree invariants
     * - Update linked list pointers for leaf nodes
     *
     * Algorithm:
     * 1. Allocate new node
     * 2. Split keys/children at midpoint
     * 3. Update key counts
     * 4. Link leaf nodes (if applicable)
     * 5. Return split key for parent update
     *
     * Complexity: O(K) where K = keys in node
     *
     * Invariants Maintained:
     * - All keys in left < splitKey <= all keys in right
     * - Leaf linked list remains intact
     * - Parent pointers correctly set
     *
     * ========================================================================
     */

     // ========================================================================
     // STEP 1: INPUT VALIDATION
     // ========================================================================

    if (!node) {
        SS_LOG_ERROR(L"SignatureIndex", L"SplitNode: Null node pointer");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Null node pointer" };
    }

    if (!newNode) {
        SS_LOG_ERROR(L"SignatureIndex", L"SplitNode: Null output pointer");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Null output pointer" };
    }

    if (node->keyCount == 0) {
        SS_LOG_ERROR(L"SignatureIndex", L"SplitNode: Cannot split empty node");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Empty node" };
    }

    if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"SplitNode: keyCount %u exceeds MAX_KEYS %zu (corruption)",
            node->keyCount, BPlusTreeNode::MAX_KEYS);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Invalid keyCount" };
    }

    SS_LOG_DEBUG(L"SignatureIndex",
        L"SplitNode: Splitting node (keyCount=%u, isLeaf=%d)",
        node->keyCount, node->isLeaf);

    // ========================================================================
    // STEP 2: ALLOCATE NEW NODE
    // ========================================================================

    *newNode = AllocateNode(node->isLeaf);
    if (!*newNode) {
        SS_LOG_ERROR(L"SignatureIndex", L"SplitNode: Failed to allocate new node");
        return StoreError{ SignatureStoreError::OutOfMemory, 0, "Node allocation failed" };
    }

    // ========================================================================
    // STEP 3: CALCULATE SPLIT POINT
    // ========================================================================

    uint32_t midPoint = node->keyCount / 2;

    if (midPoint == 0 || midPoint >= node->keyCount) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"SplitNode: Invalid midpoint %u (keyCount=%u)",
            midPoint, node->keyCount);
        FreeNode(*newNode);
        *newNode = nullptr;
        return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Invalid midpoint" };
    }

    splitKey = node->keys[midPoint];

    SS_LOG_TRACE(L"SignatureIndex",
        L"SplitNode: Split at midpoint %u, splitKey=0x%llX",
        midPoint, splitKey);

    // ========================================================================
    // STEP 4: COPY UPPER HALF TO NEW NODE
    // ========================================================================

    uint32_t keysToMove = 0;

    if (node->isLeaf) {
        keysToMove = node->keyCount - midPoint;

        if (keysToMove > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"SplitNode: Attempting to copy %u keys (max=%zu)",
                keysToMove, BPlusTreeNode::MAX_KEYS);
            FreeNode(*newNode);
            *newNode = nullptr;
            return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Invalid key count" };
        }

        (*newNode)->keyCount = keysToMove;

        for (uint32_t i = 0; i < keysToMove; ++i) {
            const uint32_t srcIdx = midPoint + i;
            if (srcIdx >= BPlusTreeNode::MAX_KEYS || i >= BPlusTreeNode::MAX_KEYS) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"SplitNode: Key copy index out of bounds (src=%u, dst=%u, max=%zu)",
                    srcIdx, i, BPlusTreeNode::MAX_KEYS);
                FreeNode(*newNode);
                *newNode = nullptr;
                return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Array bounds violation" };
            }
            (*newNode)->keys[i] = node->keys[srcIdx];
        }

        for (uint32_t i = 0; i < keysToMove; ++i) {
            const uint32_t srcIdx = midPoint + i;
            if (srcIdx >= BPlusTreeNode::MAX_CHILDREN || i >= BPlusTreeNode::MAX_CHILDREN) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"SplitNode: Children copy index out of bounds (src=%u, dst=%u, max=%zu)",
                    srcIdx, i, BPlusTreeNode::MAX_CHILDREN);
                FreeNode(*newNode);
                *newNode = nullptr;
                return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Children array bounds violation" };
            }
            (*newNode)->children[i] = node->children[srcIdx];
        }
    }
    else {
        // Internal split: splitKey is promoted, not kept in right node
        if (midPoint + 1 > node->keyCount) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"SplitNode: Invalid internal split midpoint %u (keyCount=%u)",
                midPoint, node->keyCount);
            FreeNode(*newNode);
            *newNode = nullptr;
            return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Invalid internal split midpoint" };
        }

        keysToMove = node->keyCount - midPoint - 1;

        if (keysToMove > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"SplitNode: Attempting to copy %u keys (max=%zu)",
                keysToMove, BPlusTreeNode::MAX_KEYS);
            FreeNode(*newNode);
            *newNode = nullptr;
            return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Invalid key count" };
        }

        (*newNode)->keyCount = keysToMove;

        for (uint32_t i = 0; i < keysToMove; ++i) {
            const uint32_t srcIdx = midPoint + 1 + i;
            if (srcIdx >= BPlusTreeNode::MAX_KEYS || i >= BPlusTreeNode::MAX_KEYS) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"SplitNode: Key copy index out of bounds (src=%u, dst=%u, max=%zu)",
                    srcIdx, i, BPlusTreeNode::MAX_KEYS);
                FreeNode(*newNode);
                *newNode = nullptr;
                return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Array bounds violation" };
            }
            (*newNode)->keys[i] = node->keys[srcIdx];
        }

        for (uint32_t i = 0; i < keysToMove + 1; ++i) {
            const uint32_t srcIdx = midPoint + 1 + i;
            if (srcIdx >= BPlusTreeNode::MAX_CHILDREN || i >= BPlusTreeNode::MAX_CHILDREN) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"SplitNode: Children copy index out of bounds (src=%u, dst=%u, max=%zu)",
                    srcIdx, i, BPlusTreeNode::MAX_CHILDREN);
                FreeNode(*newNode);
                *newNode = nullptr;
                return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Children array bounds violation" };
            }
            (*newNode)->children[i] = node->children[srcIdx];
        }
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"SplitNode: Copied %u keys to new node", keysToMove);

    // ========================================================================
    // STEP 5: UPDATE ORIGINAL NODE
    // ========================================================================

    const uint32_t originalKeyCount = node->keyCount;

    if (node->isLeaf) {
        for (uint32_t i = midPoint; i < originalKeyCount; ++i) {
            if (i < BPlusTreeNode::MAX_KEYS) {
                node->keys[i] = 0;
            }
            if (i < BPlusTreeNode::MAX_CHILDREN) {
                node->children[i] = 0;
            }
        }
        node->keyCount = midPoint;
    }
    else {
        for (uint32_t i = midPoint; i < originalKeyCount; ++i) {
            if (i < BPlusTreeNode::MAX_KEYS) {
                node->keys[i] = 0;
            }
        }
        for (uint32_t i = midPoint + 1; i <= originalKeyCount; ++i) {
            if (i < BPlusTreeNode::MAX_CHILDREN) {
                node->children[i] = 0;
            }
        }
        node->keyCount = midPoint;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"SplitNode: Original node keyCount reduced to %u", node->keyCount);

    // ========================================================================
    // STEP 6: UPDATE LINKED LIST (LEAF NODES ONLY)
    // ========================================================================

    if (node->isLeaf) {
        // Order: [prev] <-> [node] <-> [newNode] <-> [next]

        uint64_t originalNext = node->nextLeaf;

        // Store FULL pointer addresses (v1.1: fields are uint64_t, no truncation needed)
        const uint64_t newNodeAddr = static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(*newNode));
        const uint64_t nodeAddr = static_cast<uint64_t>(
            reinterpret_cast<uintptr_t>(node));

        // Link node -> newNode
        node->nextLeaf = newNodeAddr;

        // Link newNode -> original next
        (*newNode)->nextLeaf = originalNext;

        // Link newNode <- node
        (*newNode)->prevLeaf = nodeAddr;

        // ================================================================
        // Update the original next leaf's prevLeaf pointer
        // ================================================================
        if (originalNext != 0) {
            BPlusTreeNode* nextLeafNode = FindCOWNodeByAddr(originalNext);

            if (nextLeafNode != nullptr) {
                SS_LOG_TRACE(L"SignatureIndex",
                    L"SplitNode: Found next leaf in COW pool");
            }
            else if (originalNext < m_indexSize) {
                // It's a file offset - check if we already have a COW clone
                auto fileIt = m_fileOffsetToCOWNode.find(originalNext);
                if (fileIt != m_fileOffsetToCOWNode.end()) {
                    nextLeafNode = fileIt->second;
                }
                else {
                    // Need to clone the next leaf from file
                    const BPlusTreeNode* nextLeafConst = GetNode(originalNext);
                    if (nextLeafConst && nextLeafConst->isLeaf) {
                        nextLeafNode = CloneNode(nextLeafConst);
                        if (nextLeafNode) {
                            m_fileOffsetToCOWNode[originalNext] = nextLeafNode;

                            // Update newNode's nextLeaf to point to cloned node
                            const uint64_t clonedNextAddr = static_cast<uint64_t>(
                                reinterpret_cast<uintptr_t>(nextLeafNode));
                            (*newNode)->nextLeaf = clonedNextAddr;
                        }
                        else {
                            SS_LOG_WARN(L"SignatureIndex",
                                L"SplitNode: Failed to clone next leaf at offset 0x%llX",
                                static_cast<unsigned long long>(originalNext));
                        }
                    }
                    else {
                        SS_LOG_WARN(L"SignatureIndex",
                            L"SplitNode: Next leaf at offset 0x%llX is invalid or not a leaf",
                            static_cast<unsigned long long>(originalNext));
                    }
                }
            }

            // Update the next leaf's prevLeaf pointer to newNode
            if (nextLeafNode) {
                nextLeafNode->prevLeaf = newNodeAddr;
            }
        }

        SS_LOG_TRACE(L"SignatureIndex",
            L"SplitNode: Updated leaf linked list");
    }

    // ========================================================================
    // STEP 7: SET PARENT POINTERS
    // ========================================================================

    (*newNode)->parentOffset = node->parentOffset;

    SS_LOG_TRACE(L"SignatureIndex",
        L"SplitNode: Set parent offset 0x%llX for new node",
        static_cast<unsigned long long>((*newNode)->parentOffset));

    // ========================================================================
    // STEP 8: VALIDATION & RETURN
    // ========================================================================

    if (node->keyCount == 0 || (*newNode)->keyCount == 0) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"SplitNode: Split resulted in empty node (left=%u, right=%u)",
            node->keyCount, (*newNode)->keyCount);
        FreeNode(*newNode);
        *newNode = nullptr;
        return StoreError{ SignatureStoreError::IndexCorrupted, 0, "Empty node after split" };
    }

    SS_LOG_DEBUG(L"SignatureIndex",
        L"SplitNode: Split complete - left=%u keys, right=%u keys, splitKey=0x%llX",
        node->keyCount, (*newNode)->keyCount, splitKey);

    if (node->keyCount > 0) {
        SS_LOG_DEBUG(L"SignatureIndex",
            L"SplitNode: leftNode key[0]=0x%llX, key[last]=0x%llX",
            node->keys[0], node->keys[node->keyCount - 1]);
    }
    if ((*newNode)->keyCount > 0) {
        SS_LOG_DEBUG(L"SignatureIndex",
            L"SplitNode: rightNode key[0]=0x%llX, key[last]=0x%llX",
            (*newNode)->keys[0], (*newNode)->keys[(*newNode)->keyCount - 1]);
    }

    return StoreError{ SignatureStoreError::Success };
}

// ============================================================================
// ALLOCATENODE - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

BPlusTreeNode* SignatureIndex::AllocateNode(bool isLeaf) noexcept {
    /*
     * ========================================================================
     * NODE ALLOCATION
     * ========================================================================
     *
     * Purpose:
     * - Allocate new B+Tree node in COW pool
     * - Initialize all fields to safe defaults
     * - Track allocation for transaction management
     *
     * Memory Management:
     * - Allocated from COW pool (m_cowNodes)
     * - Freed automatically on transaction commit/rollback
     *
     * Thread Safety:
     * - Called only under exclusive write lock
     *
     * ========================================================================
     */

    try {
        // Pre-check COW pool size before allocation to fail fast
        if (m_cowNodes.size() >= MAX_COW_NODES) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"AllocateNode: COW pool already at maximum size (%zu nodes) - allocation denied",
                MAX_COW_NODES);
            return nullptr;
        }

        auto node = std::make_unique<BPlusTreeNode>();
        // Note: make_unique throws std::bad_alloc on failure, never returns null

        // ====================================================================
        // INITIALIZE NODE TO SAFE DEFAULTS
        // ====================================================================

        // Use SecureZeroMemory to ensure zeroing is not optimized away.
        // This prevents potential information leakage from uninitialized memory.
        SecureZeroMemory(node.get(), sizeof(BPlusTreeNode));

        node->isLeaf = isLeaf;
        node->keyCount = 0;
        node->parentOffset = 0;
        node->nextLeaf = 0;
        node->prevLeaf = 0;

        SS_LOG_TRACE(L"SignatureIndex",
            L"AllocateNode: Allocated %s node (size=%zu bytes)",
            isLeaf ? L"leaf" : L"internal", sizeof(BPlusTreeNode));

        // ====================================================================
        // ADD TO COW POOL
        // ====================================================================

        BPlusTreeNode* ptr = node.get();

        try {
            m_cowNodes.push_back(std::move(node));
        } catch (const std::exception& pushEx) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"AllocateNode: Failed to add node to COW pool: %S", pushEx.what());
            return nullptr;
        }

        SS_LOG_TRACE(L"SignatureIndex",
            L"AllocateNode: Added to COW pool (pool size=%zu)",
            m_cowNodes.size());

        // ====================================================================
        // REGISTER IN POINTER ADDRESS MAP (FOR COW TRAVERSAL)
        // ====================================================================
        // Store mapping from full pointer address to COW node.
        // This allows FindCOWNodeByAddr to resolve children[] values back to
        // COW nodes during tree traversal before commit.
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        m_ptrAddrToCOWNode[ptrAddr] = ptr;

        SS_LOG_TRACE(L"SignatureIndex",
            L"AllocateNode: Registered address 0x%llX in COW map",
            static_cast<unsigned long long>(ptrAddr));

        return ptr;
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"SignatureIndex", L"AllocateNode: Out of memory (bad_alloc)");
        return nullptr;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"AllocateNode: Unexpected exception: %S", ex.what());
        return nullptr;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureIndex", L"AllocateNode: Unknown exception");
        return nullptr;
    }
}

// ============================================================================
// FREENODE - COW-MANAGED DEALLOCATION
// ============================================================================

void SignatureIndex::FreeNode(BPlusTreeNode* node) noexcept {
    /*
     * ========================================================================
     * NODE DEALLOCATION (COW-MANAGED)
     * ========================================================================
     *
     * In the COW system, nodes are NOT freed immediately. They are owned by
     * m_cowNodes (unique_ptr) and freed automatically when:
     * 1. Transaction commits (CommitCOW clears m_cowNodes)
     * 2. Transaction rolls back (RollbackCOW clears m_cowNodes)
     * 3. SignatureIndex destructor runs
     *
     * This is intentionally a no-op. Do NOT manually delete the node.
     *
     * ========================================================================
     */

    if (!node) {
        return;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"FreeNode: Node marked for deallocation (will be freed on transaction end)");
}



// ============================================================================
// GETNODE - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

const BPlusTreeNode* SignatureIndex::GetNode(uint64_t nodeOffset) const noexcept {
    /*
     * ========================================================================
     * NODE RETRIEVAL WITH THREAD-SAFE CACHING
     * ========================================================================
     *
     * Thread Safety:
     * - Cache reads are protected by shared lock (multiple concurrent readers)
     * - Cache writes are protected by exclusive lock on m_cacheLock
     * - Atomic access counter prevents data races
     *
     * NOTE (v1.1): Parameter widened from uint32_t to uint64_t to support
     * databases exceeding the 4GB boundary.
     *
     * ========================================================================
     */

    // ========================================================================
    // STEP 1: BOUNDS CHECKING
    // ========================================================================

    if (!m_baseAddress) {
        SS_LOG_ERROR(L"SignatureIndex", L"GetNode: Base address is null");
        return nullptr;
    }

    if (m_indexSize == 0) {
        SS_LOG_ERROR(L"SignatureIndex", L"GetNode: Index size is zero");
        return nullptr;
    }

    if (nodeOffset >= m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"GetNode: Offset 0x%llX exceeds index size 0x%llX",
            nodeOffset, m_indexSize);
        return nullptr;
    }

    // Integer overflow check before addition
    if (nodeOffset + sizeof(BPlusTreeNode) > m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"GetNode: Node at offset 0x%llX would overflow index bounds",
            nodeOffset);
        return nullptr;
    }

    // Validate alignment - misaligned access is undefined behavior
    constexpr size_t NODE_ALIGNMENT = alignof(BPlusTreeNode);
    if (NODE_ALIGNMENT > 1 && (nodeOffset % NODE_ALIGNMENT) != 0) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"GetNode: Offset 0x%llX is not properly aligned (required alignment=%zu)",
            nodeOffset, NODE_ALIGNMENT);
        return nullptr;
    }

    // ========================================================================
    // STEP 2: CHECK CACHE (Thread-Safe Read)
    // ========================================================================

    static_assert(CACHE_SIZE > 0, "CACHE_SIZE must be positive");
    const size_t cacheIdx = HashNodeOffset(nodeOffset) % CACHE_SIZE;

    {
        std::shared_lock<std::shared_mutex> cacheLock(m_cacheLock);

        const auto& cached = m_nodeCache[cacheIdx];

        if (cached.node != nullptr) {
            const uint8_t* nodePtr = reinterpret_cast<const uint8_t*>(cached.node);
            const uint8_t* basePtr = static_cast<const uint8_t*>(m_baseAddress);

            bool inBounds = (nodePtr >= basePtr) &&
                            ((nodePtr + sizeof(BPlusTreeNode)) <= (basePtr + m_indexSize));

            if (inBounds) {
                const uint64_t actualOffset = static_cast<uint64_t>(nodePtr - basePtr);

                if (actualOffset == nodeOffset) {
                    m_cacheHits.fetch_add(1, std::memory_order_relaxed);
                    return cached.node;
                }
            }
        }
    }

    // ========================================================================
    // STEP 3: CACHE MISS - LOAD FROM MEMORY
    // ========================================================================

    m_cacheMisses.fetch_add(1, std::memory_order_relaxed);

    const uint8_t* nodeAddr = static_cast<const uint8_t*>(m_baseAddress) + nodeOffset;
    const auto* node = reinterpret_cast<const BPlusTreeNode*>(nodeAddr);

    // ========================================================================
    // STEP 4: VALIDATE NODE STRUCTURE (Corruption Detection)
    // ========================================================================

    if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"GetNode: Retrieved node has invalid keyCount %u (max=%zu) at offset 0x%llX",
            node->keyCount, BPlusTreeNode::MAX_KEYS, nodeOffset);
        return nullptr;
    }

    // ========================================================================
    // STEP 5: UPDATE CACHE (Thread-Safe Write)
    // ========================================================================

    try {
        std::unique_lock<std::shared_mutex> cacheLock(m_cacheLock);

        auto& cached = m_nodeCache[cacheIdx];
        cached.node = node;
        cached.accessCount = 1;
        cached.lastAccessTime = m_cacheAccessCounter.fetch_add(1, std::memory_order_relaxed);
    }
    catch (const std::exception& ex) {
        // Cache update failure is non-fatal
        SS_LOG_WARN(L"SignatureIndex",
            L"GetNode: Cache update failed (offset=0x%llX): %S - continuing without cache",
            nodeOffset, ex.what());
    }
    catch (...) {
        SS_LOG_WARN(L"SignatureIndex",
            L"GetNode: Cache update failed with unknown exception (offset=0x%llX)",
            nodeOffset);
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"GetNode: Cache miss - loaded node from offset 0x%llX (keyCount=%u, isLeaf=%d)",
        nodeOffset, node->keyCount, node->isLeaf);

    return node;
}

// ============================================================================
// CLONENODE - ENTERPRISE-GRADE IMPLEMENTATION
// ============================================================================

BPlusTreeNode* SignatureIndex::CloneNode(const BPlusTreeNode* original) noexcept {
    /*
     * ========================================================================
     * NODE CLONING FOR COW
     * ========================================================================
     */

    if (!original) {
        SS_LOG_ERROR(L"SignatureIndex", L"CloneNode: Null original pointer");
        return nullptr;
    }

    if (original->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"CloneNode: Original node has invalid keyCount %u (max=%zu)",
            original->keyCount, BPlusTreeNode::MAX_KEYS);
        return nullptr;
    }

    SS_LOG_TRACE(L"SignatureIndex",
        L"CloneNode: Cloning node (keyCount=%u, isLeaf=%d)",
        original->keyCount, original->isLeaf);

    try {
        auto clone = std::make_unique<BPlusTreeNode>();
        // Note: make_unique throws std::bad_alloc on failure, never returns null

        // Use memcpy for performance (entire struct copy)
        std::memcpy(clone.get(), original, sizeof(BPlusTreeNode));

        BPlusTreeNode* ptr = clone.get();

        // Pre-check COW pool size before push_back
        if (m_cowNodes.size() >= MAX_COW_NODES) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"CloneNode: COW pool size limit exceeded (%zu)",
                MAX_COW_NODES);
            return nullptr;
        }

        try {
            m_cowNodes.push_back(std::move(clone));
        } catch (const std::exception& pushEx) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"CloneNode: Failed to add to COW pool: %S", pushEx.what());
            return nullptr;
        }

        // Register in pointer address map for COW traversal (exact 64-bit lookup)
        uintptr_t ptrAddr = reinterpret_cast<uintptr_t>(ptr);
        m_ptrAddrToCOWNode[ptrAddr] = ptr;

        SS_LOG_TRACE(L"SignatureIndex",
            L"CloneNode: Registered address 0x%llX in COW map (pool size=%zu)",
            static_cast<unsigned long long>(ptrAddr), m_cowNodes.size());

        return ptr;
    }
    catch (const std::bad_alloc&) {
        SS_LOG_ERROR(L"SignatureIndex", L"CloneNode: Out of memory");
        return nullptr;
    }
    catch (const std::exception& ex) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"CloneNode: Exception: %S", ex.what());
        return nullptr;
    }
    catch (...) {
        SS_LOG_ERROR(L"SignatureIndex", L"CloneNode: Unknown exception");
        return nullptr;
    }
}



// ============================================================================
// MERGENODES - PRODUCTION-GRADE IMPLEMENTATION
// ============================================================================

StoreError SignatureIndex::MergeNodes(
    BPlusTreeNode* left,
    BPlusTreeNode* right
) noexcept {
    /*
     * ========================================================================
     * B+TREE NODE MERGE OPERATION
     * ========================================================================
     *
     * Purpose:
     * - Merge two B+Tree leaf nodes (combine keys and children)
     * - Called during deletion when leaf nodes underflow
     *
     * IMPORTANT: This function is ONLY correct for leaf node merges.
     * Internal node merges require a separator key from the parent, which
     * this function does not accept. The Remove() path currently does not
     * perform rebalancing (it accepts underflow), so internal merge is not
     * invoked. If rebalancing is added in the future, this function must be
     * extended with a separatorKey parameter for internal nodes.
     *
     * Preconditions:
     * - Both nodes are valid, non-null, same type
     * - Left and right are adjacent siblings
     * - Caller holds exclusive write lock
     *
     * ========================================================================
     */

    SS_LOG_DEBUG(L"SignatureIndex", L"MergeNodes: Merging node structures");

    // ========================================================================
    // STEP 1: INPUT VALIDATION
    // ========================================================================

    if (!left) {
        SS_LOG_ERROR(L"SignatureIndex", L"MergeNodes: Left node is null");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Left node is null" };
    }

    if (!right) {
        SS_LOG_ERROR(L"SignatureIndex", L"MergeNodes: Right node is null");
        return StoreError{ SignatureStoreError::InvalidFormat, 0, "Right node is null" };
    }

    if (left->isLeaf != right->isLeaf) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Node type mismatch (left isLeaf=%d, right isLeaf=%d)",
            left->isLeaf, right->isLeaf);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Cannot merge nodes of different types" };
    }

    // Reject internal node merge - not supported without separator key
    if (!left->isLeaf) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Internal node merge not supported (requires separator key from parent)");
        return StoreError{ SignatureStoreError::InvalidFormat, 0,
                          "Internal node merge requires separator key" };
    }

    if (left->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Left node keyCount (%u) exceeds maximum (%zu)",
            left->keyCount, BPlusTreeNode::MAX_KEYS);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Left node has invalid keyCount" };
    }

    if (right->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Right node keyCount (%u) exceeds maximum (%zu)",
            right->keyCount, BPlusTreeNode::MAX_KEYS);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Right node has invalid keyCount" };
    }

    const uint64_t combinedKeys = static_cast<uint64_t>(left->keyCount) +
                                   static_cast<uint64_t>(right->keyCount);
    if (combinedKeys > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_WARN(L"SignatureIndex",
            L"MergeNodes: Combined keys (%llu) exceed maximum (%zu) - merge not possible",
            combinedKeys, BPlusTreeNode::MAX_KEYS);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Cannot merge: combined keys exceed max capacity" };
    }

    // ========================================================================
    // STEP 2: COPY KEYS AND CHILDREN FROM RIGHT TO LEFT (LEAF MERGE)
    // ========================================================================

    const uint32_t originalLeftCount = left->keyCount;
    const uint32_t originalRightCount = right->keyCount;

    SS_LOG_TRACE(L"SignatureIndex",
        L"MergeNodes: Merging left(%u keys) + right(%u keys), isLeaf=true",
        originalLeftCount, originalRightCount);

    const uint32_t rightKeyCount = right->keyCount;

    for (uint32_t i = 0; i < rightKeyCount; ++i) {
        if (left->keyCount >= BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"MergeNodes: Left node full during merge (keyCount=%u)",
                left->keyCount);
            return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                              "Left node overflowed during merge" };
        }

        if (i >= BPlusTreeNode::MAX_KEYS || left->keyCount >= BPlusTreeNode::MAX_CHILDREN ||
            i >= BPlusTreeNode::MAX_CHILDREN) {
            SS_LOG_ERROR(L"SignatureIndex",
                L"MergeNodes: Index out of bounds (left=%u, right=%u, max=%zu)",
                left->keyCount, i, BPlusTreeNode::MAX_CHILDREN);
            return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                              "Array bounds violation" };
        }

        left->keys[left->keyCount] = right->keys[i];
        left->children[left->keyCount] = right->children[i];
        left->keyCount++;
    }

    // ========================================================================
    // STEP 3: UPDATE LINKED LIST POINTERS
    // ========================================================================

    // Update left's next pointer to point past right
    left->nextLeaf = right->nextLeaf;

    // If right has a next leaf, its prevLeaf should be updated to point to left.
    // In a full COW implementation, the next leaf would need to be cloned too.
    // The caller is responsible for this if needed.

    SS_LOG_TRACE(L"SignatureIndex",
        L"MergeNodes: Updated leaf linked list pointers");

    // ========================================================================
    // STEP 4: VALIDATION
    // ========================================================================

    if (left->keyCount != (originalLeftCount + originalRightCount)) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Key count mismatch after merge (%u != %u + %u)",
            left->keyCount, originalLeftCount, originalRightCount);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Merge resulted in inconsistent key count" };
    }

    if (left->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex",
            L"MergeNodes: Merged node exceeds max keys (%u > %zu)",
            left->keyCount, BPlusTreeNode::MAX_KEYS);
        return StoreError{ SignatureStoreError::IndexCorrupted, 0,
                          "Merged node exceeds capacity" };
    }

    SS_LOG_DEBUG(L"SignatureIndex",
        L"MergeNodes: Merge successful - %u + %u = %u keys",
        originalLeftCount, originalRightCount, left->keyCount);

    return StoreError{ SignatureStoreError::Success };
}



    }//namespace SignatureStore
}//namespace ShadowStrike
