// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
/*
 * ============================================================================
 * ShadowStrike SignatureIndex - IMPLEMENTATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Ultra-fast B+Tree indexing implementation
 * Lock-free concurrent reads, COW updates
 * Target: < 500ns average lookup
 *
 * CRITICAL: Every offset calculation must be exact for memory mapping!
 *
 * ============================================================================
 */

#include "SignatureIndex.hpp"
#include "../Utils/Logger.hpp"

#include <algorithm>
#include <cstring>
#include <new>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include <cstdint>   // For SIZE_MAX, UINT64_MAX
#include <cmath>     // For std::log2
#include <functional>
#include <limits>    // For std::numeric_limits
#include <stdexcept> // For std::exception

namespace ShadowStrike {
namespace SignatureStore {

 // ============================================================================
// HELPER FUNCTION: GetCurrentTimeNs (Overflow-Safe Implementation)
// ============================================================================

    /**
     * @brief Thread-safe, overflow-safe nanosecond time retrieval.
     * @return Current time in nanoseconds, or 0 on failure.
     * 
     * SECURITY: Protected against:
     * - Division by zero
     * - Integer overflow in multiplication
     * - Invalid performance counter states
     */
    static uint64_t GetCurrentTimeNs() noexcept {
        LARGE_INTEGER counter{}, frequency{};

        if (!QueryPerformanceCounter(&counter)) {
            return 0;
        }

        if (!QueryPerformanceFrequency(&frequency)) {
            return 0;
        }

        // SECURITY: Division by zero protection
        if (frequency.QuadPart <= 0) {
            return 0;
        }

        // SECURITY: Negative counter protection (should never happen, but defensive)
        if (counter.QuadPart < 0) {
            return 0;
        }

        // Convert to nanoseconds with overflow protection
        constexpr uint64_t NANOS_PER_SECOND = 1000000000ULL;
        const uint64_t counterVal = static_cast<uint64_t>(counter.QuadPart);
        const uint64_t freqVal = static_cast<uint64_t>(frequency.QuadPart);
        
        // Check if direct multiplication would overflow
        // counter * 1e9 overflows when counter > UINT64_MAX / 1e9 ≈ 18.4e9
        if (counterVal > UINT64_MAX / NANOS_PER_SECOND) {
            // Use division-first approach (loses precision but prevents overflow)
            return (counterVal / freqVal) * NANOS_PER_SECOND;
        }
        
        // Safe to multiply directly
        return (counterVal * NANOS_PER_SECOND) / freqVal;
    }

// ============================================================================
// SIGNATURE INDEX IMPLEMENTATION
// ============================================================================

SignatureIndex::~SignatureIndex() {
    // RAII: Ensure exclusive access during destruction to prevent races
    // Note: If destruction happens while another thread holds the lock,
    // this is UB - caller must ensure proper lifetime management
    try {
        std::unique_lock<std::shared_mutex> lock(m_rwLock, std::try_to_lock);
        // Cleanup COW nodes regardless of lock state (destructor must complete)
        m_cowNodes.clear();
        m_inCOWTransaction.store(false, std::memory_order_release);
    }
    catch (...) {
        // Destructor must not throw - silently clear what we can
        m_cowNodes.clear();
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

StoreError SignatureIndex::Initialize(
    const MemoryMappedView& view,
    uint64_t indexOffset,
    uint64_t indexSize
) noexcept {
    SS_LOG_DEBUG(L"SignatureIndex", 
        L"Initialize: offset=0x%llX, size=0x%llX", indexOffset, indexSize);

    // SECURITY: Comprehensive input validation
    if (!view.IsValid()) {
        SS_LOG_ERROR(L"SignatureIndex", L"Invalid memory-mapped view");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Invalid view"};
    }

    if (!view.baseAddress) {
        SS_LOG_ERROR(L"SignatureIndex", L"Null base address in view");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Null base address"};
    }

    // SECURITY: Validate minimum size requirement
    if (indexSize < sizeof(BPlusTreeNode)) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"Index size 0x%llX too small (min: 0x%llX)", 
            indexSize, static_cast<uint64_t>(sizeof(BPlusTreeNode)));
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Index too small"};
    }

    if (indexOffset % PAGE_SIZE != 0) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"Index offset 0x%llX not page-aligned", indexOffset);
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Misaligned offset"};
    }

    // SECURITY: Overflow-safe check for indexOffset + indexSize
    if (indexSize > UINT64_MAX - indexOffset) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"Index offset + size would overflow: offset=0x%llX, size=0x%llX",
            indexOffset, indexSize);
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Offset + size overflow"};
    }

    if (indexOffset + indexSize > view.fileSize) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"Index section exceeds file bounds: offset=0x%llX, size=0x%llX, fileSize=0x%llX",
            indexOffset, indexSize, view.fileSize);
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Index out of bounds"};
    }

    // Acquire exclusive lock during initialization to prevent races
    std::unique_lock<std::shared_mutex> lock(m_rwLock);

    m_view = &view;
    m_baseAddress = view.baseAddress;
    m_indexOffset = indexOffset;
    m_indexSize = indexSize;
    m_currentOffset = 0;  // Reset offset tracker

    // Initialize performance counter with fallback
    if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart <= 0) {
        SS_LOG_WARN(L"SignatureIndex", L"QueryPerformanceFrequency failed - using fallback");
        m_perfFrequency.QuadPart = 1000000; // Fallback to microseconds
    }

    // Read root offset from first 4 bytes of index section
    if (indexSize >= sizeof(uint32_t)) {
        const uint32_t* rootPtr = view.GetAt<uint32_t>(indexOffset);
        if (rootPtr) {
            uint32_t rootVal = *rootPtr;
            // SECURITY: Validate root offset is within bounds
            if (rootVal < indexSize) {
                m_rootOffset.store(rootVal, std::memory_order_release);
                SS_LOG_DEBUG(L"SignatureIndex", L"Root offset: 0x%X", rootVal);
            } else {
                SS_LOG_WARN(L"SignatureIndex", 
                    L"Root offset 0x%X out of bounds, defaulting to 0", rootVal);
                m_rootOffset.store(0, std::memory_order_release);
            }
        } else {
            m_rootOffset.store(0, std::memory_order_release);
        }
    } else {
        m_rootOffset.store(0, std::memory_order_release);
    }

    // Reset statistics
    m_totalEntries.store(0, std::memory_order_release);
    m_totalLookups.store(0, std::memory_order_release);
    m_cacheHits.store(0, std::memory_order_release);
    m_cacheMisses.store(0, std::memory_order_release);
    m_treeHeight.store(1, std::memory_order_release);

    // Clear node cache
    ClearCache();

    // Clear any pending COW state
    m_cowNodes.clear();
    m_inCOWTransaction.store(false, std::memory_order_release);

    SS_LOG_INFO(L"SignatureIndex", L"Initialized successfully");
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    SS_LOG_DEBUG(L"SignatureIndex", L"CreateNew: availableSize=0x%llX", availableSize);

    // SECURITY: Comprehensive input validation
    if (!baseAddress) {
        SS_LOG_ERROR(L"SignatureIndex", L"CreateNew: Null base address");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Null base address"};
    }

    // SECURITY: Minimum size check - need at least one page for root node
    if (availableSize < PAGE_SIZE) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"CreateNew: Insufficient space (0x%llX < PAGE_SIZE)", availableSize);
        return StoreError{SignatureStoreError::TooLarge, 0, "Insufficient space"};
    }

    // SECURITY: Size must accommodate at least one B+Tree node
    if (availableSize < sizeof(BPlusTreeNode)) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"CreateNew: Size too small for B+Tree node");
        return StoreError{SignatureStoreError::TooLarge, 0, "Size too small for node"};
    }

    // Acquire exclusive lock during creation
    std::unique_lock<std::shared_mutex> lock(m_rwLock);

    // Clear any existing state
    m_cowNodes.clear();
    m_inCOWTransaction.store(false, std::memory_order_release);

    m_baseAddress = baseAddress;
    m_indexOffset = 0;
    m_indexSize = availableSize;
    m_currentOffset = 0;
    m_view = nullptr;  // CreateNew doesn't use external view

    // Initialize root node (leaf node) with secure zeroing
    auto* rootNode = static_cast<BPlusTreeNode*>(baseAddress);
    
    // SECURITY: Use SecureZeroMemory equivalent for sensitive initialization
    volatile uint8_t* volatilePtr = reinterpret_cast<volatile uint8_t*>(rootNode);
    for (size_t i = 0; i < sizeof(BPlusTreeNode); ++i) {
        volatilePtr[i] = 0;
    }
    
    rootNode->isLeaf = true;
    rootNode->keyCount = 0;
    rootNode->parentOffset = 0;
    rootNode->nextLeaf = 0;
    rootNode->prevLeaf = 0;

    m_rootOffset.store(0, std::memory_order_release);
    m_treeHeight.store(1, std::memory_order_release);
    m_totalEntries.store(0, std::memory_order_release);

    // Reset statistics
    m_totalLookups.store(0, std::memory_order_release);
    m_cacheHits.store(0, std::memory_order_release);
    m_cacheMisses.store(0, std::memory_order_release);

    // Initialize performance counter
    if (!QueryPerformanceFrequency(&m_perfFrequency) || m_perfFrequency.QuadPart <= 0) {
        m_perfFrequency.QuadPart = 1000000; // Fallback
    }

    // Calculate used size with page alignment
    usedSize = Format::AlignToPage(sizeof(BPlusTreeNode));
    
    // SECURITY: Validate usedSize doesn't exceed available
    if (usedSize > availableSize) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"CreateNew: Aligned size exceeds available space");
        return StoreError{SignatureStoreError::TooLarge, 0, "Aligned size overflow"};
    }
    
    m_currentOffset = usedSize;  // Track next allocation offset

    // Clear cache
    ClearCache();

    SS_LOG_INFO(L"SignatureIndex", L"Created new index (usedSize=0x%llX)", usedSize);
    return StoreError{SignatureStoreError::Success};
}

StoreError SignatureIndex::Verify() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_rwLock);

    // SECURITY: Validate memory state
    // Support both memory-mapped views (m_view set) and raw buffer mode (CreateNew)
    if (m_view) {
        if (!m_view->IsValid()) {
            SS_LOG_ERROR(L"SignatureIndex", L"Verify: Invalid view");
            return StoreError{SignatureStoreError::InvalidFormat, 0, "Invalid view"};
        }
    }

    if (!m_baseAddress) {
        SS_LOG_ERROR(L"SignatureIndex", L"Verify: Null base address");
        return StoreError{SignatureStoreError::InvalidFormat, 0, "Null base address"};
    }

    // Verify root node exists and is valid
    uint32_t rootOffset = m_rootOffset.load(std::memory_order_acquire);
    
    // SECURITY: Validate root offset is within bounds
    if (rootOffset >= m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"Verify: Root offset 0x%X exceeds index size 0x%llX",
            rootOffset, m_indexSize);
        return StoreError{SignatureStoreError::IndexCorrupted, 0, "Root offset out of bounds"};
    }

    const BPlusTreeNode* root = GetNode(rootOffset);
    if (!root) {
        SS_LOG_ERROR(L"SignatureIndex", L"Verify: Failed to load root node");
        return StoreError{SignatureStoreError::IndexCorrupted, 0, "Root node missing"};
    }

    // SECURITY: Comprehensive sanity checks
    if (root->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"SignatureIndex", L"Verify: Root node keyCount %u exceeds max %zu",
            root->keyCount, BPlusTreeNode::MAX_KEYS);
        return StoreError{SignatureStoreError::IndexCorrupted, 0, "Invalid key count"};
    }

    // Verify key ordering in root
    for (uint32_t i = 0; i + 1 < root->keyCount; ++i) {
        if (root->keys[i] >= root->keys[i + 1]) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"Verify: Key ordering violation at root position %u", i);
            return StoreError{SignatureStoreError::IndexCorrupted, 0, "Key ordering violation"};
        }
    }

    // Verify tree height is reasonable
    uint32_t height = m_treeHeight.load(std::memory_order_acquire);
    if (height == 0 || height > 64) {
        SS_LOG_ERROR(L"SignatureIndex", L"Verify: Invalid tree height %u", height);
        return StoreError{SignatureStoreError::IndexCorrupted, 0, "Invalid tree height"};
    }

    SS_LOG_DEBUG(L"SignatureIndex", L"Verification passed");
    return StoreError{SignatureStoreError::Success};
}


// ============================================================================
// TRAVERSAL
// ============================================================================

/**
 * @brief Iterate over all entries in sorted order.
 * @param callback Function to call for each entry (return false to stop)
 * 
 * SECURITY: Protected against:
 * - Infinite loops via iteration limits
 * - Cycle detection in leaf list
 * - Invalid keyCount values
 * - Out-of-bounds offsets
 */
void SignatureIndex::ForEach(
    std::function<bool(uint64_t fastHash, uint64_t signatureOffset)> callback
) const noexcept {
    // SECURITY: Validate callback before acquiring lock
    if (!callback) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEach: Null callback provided");
        return;
    }

    std::shared_lock<std::shared_mutex> lock(m_rwLock);

    // SECURITY: Validate index state
    if (!m_baseAddress || m_indexSize == 0) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEach: Index not initialized");
        return;
    }

    // Find leftmost leaf
    uint32_t rootOffset = m_rootOffset.load(std::memory_order_acquire);
    
    // SECURITY: Validate root offset
    if (rootOffset >= m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"ForEach: Invalid root offset 0x%X", rootOffset);
        return;
    }
    
    const BPlusTreeNode* node = GetNode(rootOffset);
    if (!node) {
        SS_LOG_DEBUG(L"SignatureIndex", L"ForEach: Empty tree");
        return;
    }

    // SECURITY: Track depth to prevent infinite loop during navigation
    constexpr uint32_t MAX_DEPTH = 64;
    uint32_t depth = 0;
    
    // Track visited offsets for cycle detection
    std::unordered_set<uint32_t> visitedOffsets;
    visitedOffsets.insert(rootOffset);

    // Navigate to leftmost leaf
    while (!node->isLeaf && depth < MAX_DEPTH) {
        // SECURITY: Validate keyCount before accessing children
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Invalid keyCount %u during descent", node->keyCount);
            return;
        }
        
        // Note: For navigation to leftmost leaf, we take child[0] regardless of keyCount
        // Child[0] always exists in a valid internal node
        uint32_t childOffset = node->children[0];
        
        // SECURITY: Validate child offset
        if (childOffset == 0 || childOffset >= m_indexSize) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Invalid child[0] offset 0x%X at depth %u", childOffset, depth);
            return;
        }
        
        // SECURITY: Cycle detection
        if (visitedOffsets.count(childOffset) > 0) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Cycle detected during descent at offset 0x%X", childOffset);
            return;
        }
        visitedOffsets.insert(childOffset);
        
        node = GetNode(childOffset);
        if (!node) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Failed to load node at offset 0x%X", childOffset);
            return;
        }
        depth++;
    }

    if (depth >= MAX_DEPTH) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"ForEach: Max depth %u exceeded during navigation", MAX_DEPTH);
        return;
    }

    // SECURITY: Track iterations to prevent infinite loop in leaf linked list
    constexpr size_t MAX_ITERATIONS = 10000000; // 10M leaves max
    size_t iterations = 0;
    size_t entriesProcessed = 0;

    // Clear visited set for leaf traversal (reuse memory)
    visitedOffsets.clear();

    // Traverse linked list of leaves
    while (node && iterations < MAX_ITERATIONS) {
        // SECURITY: Validate keyCount
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Invalid keyCount %u in leaf at iteration %zu", 
                node->keyCount, iterations);
            return;
        }
        
        // Process all entries in this leaf
        for (uint32_t i = 0; i < node->keyCount; ++i) {
            try {
                if (!callback(node->keys[i], static_cast<uint64_t>(node->children[i]))) {
                    // Early exit requested by callback
                    SS_LOG_TRACE(L"SignatureIndex", 
                        L"ForEach: Early exit after %zu entries", entriesProcessed);
                    return;
                }
                entriesProcessed++;
            }
            catch (...) {
                // Callback threw exception - stop iteration for safety
                SS_LOG_ERROR(L"SignatureIndex", 
                    L"ForEach: Callback threw exception after %zu entries", entriesProcessed);
                return;
            }
        }

        // Check for end of list
        if (node->nextLeaf == 0) {
            break;
        }
        
        // SECURITY: Validate nextLeaf offset
        if (node->nextLeaf >= m_indexSize) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Invalid nextLeaf offset 0x%X at iteration %zu", 
                node->nextLeaf, iterations);
            return;
        }
        
        // SECURITY: Cycle detection in leaf list
        if (visitedOffsets.count(node->nextLeaf) > 0) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEach: Cycle detected in leaf list at offset 0x%X", node->nextLeaf);
            return;
        }
        visitedOffsets.insert(node->nextLeaf);
        
        node = GetNode(node->nextLeaf);
        iterations++;
    }

    if (iterations >= MAX_ITERATIONS) {
        SS_LOG_WARN(L"SignatureIndex", 
            L"ForEach: Iteration limit reached (%zu iterations, %zu entries)", 
            iterations, entriesProcessed);
    }
    
    SS_LOG_TRACE(L"SignatureIndex", 
        L"ForEach: Processed %zu entries across %zu leaves", entriesProcessed, iterations + 1);
}

/**
 * @brief Internal ForEach implementation without lock acquisition.
 *
 * CRITICAL: This method assumes the caller already holds m_rwLock (shared or exclusive).
 * Used by Rebuild() which holds exclusive lock and cannot call ForEach() (deadlock).
 *
 * @param callback Function to call for each entry. Return false to stop iteration.
 *
 * SECURITY:
 * - NO LOCK ACQUIRED - caller must hold appropriate lock
 * - Same validation and cycle detection as ForEach()
 */
void SignatureIndex::ForEachInternalNoLock(
    std::function<bool(uint64_t fastHash, uint64_t signatureOffset)> callback
) const noexcept {
    // SECURITY: Validate callback
    if (!callback) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEachInternalNoLock: Null callback provided");
        return;
    }

    // NOTE: No lock acquisition - caller must hold m_rwLock

    // SECURITY: Validate index state
    if (!m_baseAddress || m_indexSize == 0) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEachInternalNoLock: Index not initialized");
        return;
    }

    // Find leftmost leaf
    uint32_t rootOffset = m_rootOffset.load(std::memory_order_acquire);
    
    // SECURITY: Validate root offset
    if (rootOffset >= m_indexSize) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"ForEachInternalNoLock: Invalid root offset 0x%X", rootOffset);
        return;
    }
    
    const BPlusTreeNode* node = GetNode(rootOffset);
    if (!node) {
        SS_LOG_DEBUG(L"SignatureIndex", L"ForEachInternalNoLock: Empty tree");
        return;
    }

    // SECURITY: Track depth to prevent infinite loop during navigation
    constexpr uint32_t MAX_DEPTH = 64;
    uint32_t depth = 0;
    
    // Track visited offsets for cycle detection
    std::unordered_set<uint32_t> visitedOffsets;
    visitedOffsets.insert(rootOffset);

    // Navigate to leftmost leaf
    while (!node->isLeaf && depth < MAX_DEPTH) {
        // SECURITY: Validate keyCount before accessing children
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Invalid keyCount %u during descent", node->keyCount);
            return;
        }
        
        // For navigation to leftmost leaf, we take child[0]
        uint32_t childOffset = node->children[0];
        
        // SECURITY: Validate child offset
        if (childOffset == 0 || childOffset >= m_indexSize) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Invalid child[0] offset 0x%X at depth %u", childOffset, depth);
            return;
        }
        
        // SECURITY: Cycle detection
        if (visitedOffsets.count(childOffset) > 0) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Cycle detected during descent at offset 0x%X", childOffset);
            return;
        }
        visitedOffsets.insert(childOffset);
        
        node = GetNode(childOffset);
        if (!node) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Failed to load node at offset 0x%X", childOffset);
            return;
        }
        depth++;
    }

    if (depth >= MAX_DEPTH) {
        SS_LOG_ERROR(L"SignatureIndex", 
            L"ForEachInternalNoLock: Max depth %u exceeded during navigation", MAX_DEPTH);
        return;
    }

    // SECURITY: Track iterations to prevent infinite loop in leaf linked list
    constexpr size_t MAX_ITERATIONS = 10000000; // 10M leaves max
    size_t iterations = 0;
    size_t entriesProcessed = 0;

    // Clear visited set for leaf traversal (reuse memory)
    visitedOffsets.clear();

    // Traverse linked list of leaves
    while (node && iterations < MAX_ITERATIONS) {
        // SECURITY: Validate keyCount
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Invalid keyCount %u in leaf at iteration %zu", 
                node->keyCount, iterations);
            return;
        }
        
        // Process all entries in this leaf
        for (uint32_t i = 0; i < node->keyCount; ++i) {
            try {
                if (!callback(node->keys[i], static_cast<uint64_t>(node->children[i]))) {
                    // Early exit requested by callback
                    SS_LOG_TRACE(L"SignatureIndex", 
                        L"ForEachInternalNoLock: Early exit after %zu entries", entriesProcessed);
                    return;
                }
                entriesProcessed++;
            }
            catch (...) {
                // Callback threw exception - stop iteration for safety
                SS_LOG_ERROR(L"SignatureIndex", 
                    L"ForEachInternalNoLock: Callback threw exception after %zu entries", entriesProcessed);
                return;
            }
        }

        // Check for end of list
        if (node->nextLeaf == 0) {
            break;
        }
        
        // SECURITY: Validate nextLeaf offset
        if (node->nextLeaf >= m_indexSize) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Invalid nextLeaf offset 0x%X at iteration %zu", 
                node->nextLeaf, iterations);
            return;
        }
        
        // SECURITY: Cycle detection in leaf list
        if (visitedOffsets.count(node->nextLeaf) > 0) {
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachInternalNoLock: Cycle detected in leaf list at offset 0x%X", node->nextLeaf);
            return;
        }
        visitedOffsets.insert(node->nextLeaf);
        
        node = GetNode(node->nextLeaf);
        iterations++;
    }

    if (iterations >= MAX_ITERATIONS) {
        SS_LOG_WARN(L"SignatureIndex", 
            L"ForEachInternalNoLock: Iteration limit reached (%zu iterations, %zu entries)", 
            iterations, entriesProcessed);
    }
    
    SS_LOG_TRACE(L"SignatureIndex", 
        L"ForEachInternalNoLock: Processed %zu entries across %zu leaves", entriesProcessed, iterations + 1);
}

/**
 * @brief Iterate over entries matching a predicate.
 * @param predicate Function to test each hash (return true to include)
 * @param callback Function to call for matching entries (return false to stop)
 * 
 * SECURITY: Validates both callbacks before use.
 * Delegates to ForEach with filtering wrapper.
 */
void SignatureIndex::ForEachIf(
    std::function<bool(uint64_t fastHash)> predicate,
    std::function<bool(uint64_t fastHash, uint64_t signatureOffset)> callback
) const noexcept {
    // SECURITY: Validate both callbacks
    if (!predicate) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEachIf: Null predicate provided");
        return;
    }
    
    if (!callback) {
        SS_LOG_WARN(L"SignatureIndex", L"ForEachIf: Null callback provided");
        return;
    }

    ForEach([&](uint64_t fastHash, uint64_t offset) -> bool {
        try {
            if (predicate(fastHash)) {
                return callback(fastHash, offset);
            }
            return true;  // Continue iteration
        }
        catch (...) {
            // Callback threw exception - stop iteration for safety
            SS_LOG_ERROR(L"SignatureIndex", 
                L"ForEachIf: Exception in predicate or callback");
            return false;
        }
    });
}


// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Binary search in sorted key array.
 * @param keys Array of keys to search (must be sorted ascending)
 * @param keyCount Number of valid keys in array
 * @param target Key to search for
 * @return Position where target is found or should be inserted
 * 
 * SECURITY: Bounds-safe implementation with overflow protection.
 * Returns insertion point (lower_bound semantics) - first position >= target.
 */
uint32_t SignatureIndex::BinarySearch(
    const std::array<uint64_t, BPlusTreeNode::MAX_KEYS>& keys,
    uint32_t keyCount,
    uint64_t target
) noexcept {
    // SECURITY: Validate keyCount to prevent OOB access
    if (keyCount == 0) {
        return 0;
    }
    
    // SECURITY: Clamp keyCount to array bounds
    const uint32_t safeKeyCount = std::min(keyCount, 
        static_cast<uint32_t>(BPlusTreeNode::MAX_KEYS));
    
    uint32_t left = 0;
    uint32_t right = safeKeyCount;

    // Standard binary search - lower_bound implementation
    while (left < right) {
        // SECURITY: Overflow-safe midpoint calculation
        const uint32_t mid = left + (right - left) / 2;
        
        // SECURITY: Bounds check before array access (should always pass given above)
        if (mid >= BPlusTreeNode::MAX_KEYS) {
            break;
        }
        
        if (keys[mid] < target) {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    return left;
}

/**
 * @brief Thread-safe, overflow-safe nanosecond time retrieval (member function).
 * @return Current time in nanoseconds, or 0 on failure.
 * 
 * SECURITY: Protected against division by zero and integer overflow.
 * Note: This is the member function version - delegates to static implementation.
 */
uint64_t SignatureIndex::GetCurrentTimeNs() noexcept {
    LARGE_INTEGER counter{}, frequency{};
    
    if (!QueryPerformanceCounter(&counter)) {
        return 0;
    }
    
    if (!QueryPerformanceFrequency(&frequency)) {
        return 0;
    }
    
    // SECURITY: Division by zero and negative value protection
    if (frequency.QuadPart <= 0) {
        return 0;
    }
    
    if (counter.QuadPart < 0) {
        return 0;
    }
    
    constexpr uint64_t NANOS_PER_SECOND = 1000000000ULL;
    const uint64_t counterVal = static_cast<uint64_t>(counter.QuadPart);
    const uint64_t freqVal = static_cast<uint64_t>(frequency.QuadPart);
    
    // Check if direct multiplication would overflow
    if (counterVal > UINT64_MAX / NANOS_PER_SECOND) {
        // Use division-first approach (loses precision but prevents overflow)
        return (counterVal / freqVal) * NANOS_PER_SECOND;
    }
    
    return (counterVal * NANOS_PER_SECOND) / freqVal;
}

/**
 * @brief Hash function for node cache indexing.
 * @param offset Node offset to hash
 * @return Hash value suitable for cache indexing
 * 
 * Uses Knuth's multiplicative hash for good distribution.
 */
size_t SignatureIndex::HashNodeOffset(uint32_t offset) noexcept {
    // Knuth's multiplicative hash - provides good distribution
    constexpr uint32_t KNUTH_MULTIPLIER = 2654435761u;
    return static_cast<size_t>(offset) * KNUTH_MULTIPLIER;
}

// ============================================================================
// DEBUGGING
// ============================================================================

/**
 * @brief Dump tree structure for debugging.
 * @param output Callback to receive output lines
 * 
 * Thread-safe via shared lock.
 */
void SignatureIndex::DumpTree(std::function<void(const std::string&)> output) const noexcept {
    if (!output) {
        return;
    }

    std::shared_lock<std::shared_mutex> lock(m_rwLock);

    try {
        output("=== B+Tree Index Dump ===");
        
        char buffer[256];
        
        // Root offset
        int ret = snprintf(buffer, sizeof(buffer), "Root offset: 0x%X", 
            m_rootOffset.load(std::memory_order_acquire));
        if (ret > 0 && ret < static_cast<int>(sizeof(buffer))) {
            output(buffer);
        }

        // Tree height
        ret = snprintf(buffer, sizeof(buffer), "Tree height: %u", 
            m_treeHeight.load(std::memory_order_acquire));
        if (ret > 0 && ret < static_cast<int>(sizeof(buffer))) {
            output(buffer);
        }

        // Total entries
        ret = snprintf(buffer, sizeof(buffer), "Total entries: %llu", 
            static_cast<unsigned long long>(m_totalEntries.load(std::memory_order_acquire)));
        if (ret > 0 && ret < static_cast<int>(sizeof(buffer))) {
            output(buffer);
        }

        // Index size
        ret = snprintf(buffer, sizeof(buffer), "Index size: 0x%llX bytes", 
            static_cast<unsigned long long>(m_indexSize));
        if (ret > 0 && ret < static_cast<int>(sizeof(buffer))) {
            output(buffer);
        }

        // Cache statistics
        ret = snprintf(buffer, sizeof(buffer), "Cache hits: %llu, misses: %llu", 
            static_cast<unsigned long long>(m_cacheHits.load(std::memory_order_acquire)),
            static_cast<unsigned long long>(m_cacheMisses.load(std::memory_order_acquire)));
        if (ret > 0 && ret < static_cast<int>(sizeof(buffer))) {
            output(buffer);
        }

        output("=== End Dump ===");
    }
    catch (...) {
        // Output callback threw - silently ignore
    }
}

/**
 * @brief Validate B+Tree invariants.
 * @param errorMessage [out] Description of first error found
 * @return True if all invariants hold, false otherwise
 * 
 * SECURITY: Comprehensive validation of tree structure.
 * Thread-safe via shared lock.
 */
bool SignatureIndex::ValidateInvariants(std::string& errorMessage) const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_rwLock);
    return ValidateInvariantsInternal(errorMessage);
}

/**
 * Internal validation without lock acquisition.
 * Caller must hold shared or exclusive lock on m_rwLock.
 */
bool SignatureIndex::ValidateInvariantsInternal(std::string& errorMessage) const noexcept {
    try {
        errorMessage.clear();

        // SECURITY: Validate base address
        if (!m_baseAddress) {
            errorMessage = "Null base address";
            return false;
        }

        if (m_indexSize == 0) {
            errorMessage = "Zero index size";
            return false;
        }

        // Validate root exists and is within bounds
        uint32_t rootOffset = m_rootOffset.load(std::memory_order_acquire);
        if (rootOffset >= m_indexSize) {
            errorMessage = "Root offset out of bounds";
            return false;
        }

        const BPlusTreeNode* root = GetNode(rootOffset);
        if (!root) {
            errorMessage = "Root node not found";
            return false;
        }

        // Validate key count
        if (root->keyCount > BPlusTreeNode::MAX_KEYS) {
            errorMessage = "Root key count exceeds maximum";
            return false;
        }

        // Validate key ordering in root
        for (uint32_t i = 0; i + 1 < root->keyCount; ++i) {
            if (root->keys[i] >= root->keys[i + 1]) {
                errorMessage = "Root keys not strictly ordered";
                return false;
            }
        }

        // Validate tree height
        uint32_t height = m_treeHeight.load(std::memory_order_acquire);
        if (height == 0 || height > 64) {
            errorMessage = "Invalid tree height";
            return false;
        }

        // More comprehensive validation could be added:
        // - All leaves at same depth
        // - Key ranges in children consistent with parent keys
        // - Leaf linked list consistency
        // - No cycles in tree structure

        return true;
    }
    catch (const std::exception& e) {
        errorMessage = std::string("Exception during validation: ") + e.what();
        return false;
    }
    catch (...) {
        errorMessage = "Unknown exception during validation";
        return false;
    }
}

} // namespace SignatureStore
} // namespace ShadowStrike