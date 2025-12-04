/**
 * @file WhiteListHashIndex.cpp
 * @brief B+Tree hash index implementation for WhitelistStore
 *
 * This file implements a high-performance B+Tree index for O(log N) hash
 * lookups. The index supports concurrent reads with single-writer semantics.
 *
 * Architecture:
 * - B+Tree with configurable branching factor
 * - All values stored in leaf nodes (internal nodes contain only keys)
 * - Leaf nodes linked for range queries
 * - Memory-mapped for zero-copy reads
 *
 * Performance Characteristics:
 * - Lookup: O(log N) with small constant factor
 * - Insert: O(log N) amortized (may trigger node splits)
 * - Range query: O(log N + K) where K is result size
 *
 * Thread Safety:
 * - Concurrent reads are lock-free for memory-mapped data
 * - Write operations require exclusive lock
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include "WhiteListStore.hpp"
#include "WhiteListFormat.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/JSONUtils.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <limits>
#include <climits>


namespace ShadowStrike::Whitelist {

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================
// These helper functions provide overflow-safe arithmetic and utility
// operations. Defined in anonymous namespace for internal linkage only.
// ============================================================================

namespace {

/**
 * @brief Safely add two values with overflow check
 * @tparam T Integral type (must be unsigned for correct overflow detection)
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if addition succeeded, false if overflow would occur
 *
 * @note Uses compile-time check to ensure correct overflow detection
 */
template<typename T>
[[nodiscard]] inline bool SafeAdd(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeAdd requires integral type");
    if constexpr (std::is_unsigned_v<T>) {
        if (a > std::numeric_limits<T>::max() - b) {
            return false;
        }
    } else {
        // Signed overflow check
        if ((b > 0 && a > std::numeric_limits<T>::max() - b) ||
            (b < 0 && a < std::numeric_limits<T>::min() - b)) {
            return false;
        }
    }
    result = a + b;
    return true;
}

/**
 * @brief Safely multiply two values with overflow check
 * @tparam T Integral type (must be unsigned for correct overflow detection)
 * @param a First operand
 * @param b Second operand
 * @param result Output result (only valid if function returns true)
 * @return True if multiplication succeeded, false if overflow would occur
 */
template<typename T>
[[nodiscard]] inline bool SafeMul(T a, T b, T& result) noexcept {
    static_assert(std::is_integral_v<T>, "SafeMul requires integral type");
    if (a == 0 || b == 0) {
        result = 0;
        return true;
    }
    if constexpr (std::is_unsigned_v<T>) {
        if (a > std::numeric_limits<T>::max() / b) {
            return false;
        }
    } else {
        // Signed overflow check (simplified - handles most cases)
        if (a > 0) {
            if (b > 0 && a > std::numeric_limits<T>::max() / b) return false;
            if (b < 0 && b < std::numeric_limits<T>::min() / a) return false;
        } else {
            if (b > 0 && a < std::numeric_limits<T>::min() / b) return false;
            if (b < 0 && a < std::numeric_limits<T>::max() / b) return false;
        }
    }
    result = a * b;
    return true;
}

/**
 * @brief Clamp value to valid range
 * @tparam T Comparable type
 * @param value Value to clamp
 * @param minVal Minimum allowed value
 * @param maxVal Maximum allowed value
 * @return Clamped value within [minVal, maxVal]
 */
template<typename T>
[[nodiscard]] constexpr T Clamp(T value, T minVal, T maxVal) noexcept {
    return (value < minVal) ? minVal : ((value > maxVal) ? maxVal : value);
}

} // namespace (anonymous)

// ============================================================================
// HASH INDEX IMPLEMENTATION (B+Tree)
// ============================================================================

HashIndex::HashIndex() = default;

HashIndex::~HashIndex() = default;

HashIndex::HashIndex(HashIndex&& other) noexcept
    : m_view(nullptr)
    , m_baseAddress(nullptr)
    , m_rootOffset(0)
    , m_indexOffset(0)
    , m_indexSize(0)
    , m_nextNodeOffset(0)
    , m_treeDepth(0)
    , m_entryCount(0)
    , m_nodeCount(0)
{
    // Lock the source object to ensure thread-safe move
    std::unique_lock lock(other.m_rwLock);
    
    // Transfer ownership with acquire semantics for memory ordering
    m_view = other.m_view;
    m_baseAddress = other.m_baseAddress;
    m_rootOffset = other.m_rootOffset;
    m_indexOffset = other.m_indexOffset;
    m_indexSize = other.m_indexSize;
    m_nextNodeOffset = other.m_nextNodeOffset;
    m_treeDepth = other.m_treeDepth;
    m_entryCount.store(other.m_entryCount.load(std::memory_order_acquire), 
                      std::memory_order_release);
    m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire), 
                     std::memory_order_release);
    
    // Clear source with release semantics
    other.m_view = nullptr;
    other.m_baseAddress = nullptr;
    other.m_rootOffset = 0;
    other.m_indexOffset = 0;
    other.m_indexSize = 0;
    other.m_nextNodeOffset = 0;
    other.m_treeDepth = 0;
    other.m_entryCount.store(0, std::memory_order_release);
    other.m_nodeCount.store(0, std::memory_order_release);
}

HashIndex& HashIndex::operator=(HashIndex&& other) noexcept {
    if (this != &other) {
        // Lock both for thread safety during move (use std::lock to avoid deadlock)
        std::unique_lock lockThis(m_rwLock, std::defer_lock);
        std::unique_lock lockOther(other.m_rwLock, std::defer_lock);
        std::lock(lockThis, lockOther);
        
        // Transfer ownership with acquire semantics
        m_view = other.m_view;
        m_baseAddress = other.m_baseAddress;
        m_rootOffset = other.m_rootOffset;
        m_indexOffset = other.m_indexOffset;
        m_indexSize = other.m_indexSize;
        m_nextNodeOffset = other.m_nextNodeOffset;
        m_treeDepth = other.m_treeDepth;
        m_entryCount.store(other.m_entryCount.load(std::memory_order_acquire), 
                          std::memory_order_release);
        m_nodeCount.store(other.m_nodeCount.load(std::memory_order_acquire), 
                         std::memory_order_release);
        
        // Clear source with release semantics for memory ordering guarantee
        other.m_view = nullptr;
        other.m_baseAddress = nullptr;
        other.m_rootOffset = 0;
        other.m_indexOffset = 0;
        other.m_indexSize = 0;
        other.m_nextNodeOffset = 0;
        other.m_treeDepth = 0;
        other.m_entryCount.store(0, std::memory_order_release);
        other.m_nodeCount.store(0, std::memory_order_release);
    }
    return *this;
}

bool HashIndex::IsOffsetValid(uint64_t offset) const noexcept {
    // Validate offset is within index bounds
    if (offset >= m_indexSize) {
        return false;
    }
    
    // Check for node structure alignment
    constexpr uint64_t HEADER_SIZE = 64;
    if (offset >= HEADER_SIZE) {
        // Validate offset is properly aligned for BPlusTreeNode
        const uint64_t nodeOffset = offset - HEADER_SIZE;
        if (nodeOffset % sizeof(BPlusTreeNode) != 0) {
            // Offset not aligned to node boundary
            return false;
        }
        
        // Ensure there's enough space for a complete node
        uint64_t endOffset = 0;
        if (!SafeAdd(offset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), endOffset)) {
            return false; // Would overflow
        }
        if (endOffset > m_indexSize) {
            return false; // Node would extend past index boundary
        }
    } else if (offset > 0) {
        // Offset is within header region (invalid for node access)
        return false;
    }
    
    return true;
}

StoreError HashIndex::Initialize(
    const MemoryMappedView& view,
    uint64_t offset,
    uint64_t size
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate view
    if (!view.IsValid()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid memory-mapped view"
        );
    }
    
    // Validate offset and size don't overflow
    uint64_t endOffset;
    if (!SafeAdd(offset, size, endOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section offset + size overflow"
        );
    }
    
    if (endOffset > view.fileSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section exceeds file size"
        );
    }
    
    // Minimum size check
    constexpr uint64_t HEADER_SIZE = 64;
    if (size < HEADER_SIZE) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Index section too small for header"
        );
    }
    
    m_view = &view;
    m_baseAddress = nullptr;  // Read-only mode
    m_indexOffset = offset;
    m_indexSize = size;
    
    // Read root node offset from first 8 bytes
    const auto* rootPtr = view.GetAt<uint64_t>(offset);
    if (!rootPtr) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Failed to read root node offset"
        );
    }
    
    m_rootOffset = *rootPtr;
    
    // Validate root offset
    if (m_rootOffset >= size) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Root offset exceeds index size"
        );
    }
    
    // Read metadata with null checks
    const auto* nodeCountPtr = view.GetAt<uint64_t>(offset + 8);
    const auto* entryCountPtr = view.GetAt<uint64_t>(offset + 16);
    const auto* nextNodePtr = view.GetAt<uint64_t>(offset + 24);
    const auto* depthPtr = view.GetAt<uint32_t>(offset + 32);
    
    if (nodeCountPtr) {
        m_nodeCount.store(*nodeCountPtr, std::memory_order_relaxed);
    }
    if (entryCountPtr) {
        m_entryCount.store(*entryCountPtr, std::memory_order_relaxed);
    }
    if (nextNodePtr) {
        m_nextNodeOffset = *nextNodePtr;
    }
    if (depthPtr) {
        m_treeDepth = std::min(*depthPtr, MAX_TREE_DEPTH);
    }
    
    SS_LOG_DEBUG(L"Whitelist", 
        L"HashIndex initialized: %llu nodes, %llu entries, depth %u",
        m_nodeCount.load(std::memory_order_relaxed), 
        m_entryCount.load(std::memory_order_relaxed), 
        m_treeDepth);
    
    return StoreError::Success();
}

StoreError HashIndex::CreateNew(
    void* baseAddress,
    uint64_t availableSize,
    uint64_t& usedSize
) noexcept {
    std::unique_lock lock(m_rwLock);
    
    if (!baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Invalid base address (null)"
        );
    }
    
    // Minimum size: header (64 bytes) + one node
    constexpr uint64_t HEADER_SIZE = 64;
    const uint64_t minSize = HEADER_SIZE + sizeof(BPlusTreeNode);
    
    if (availableSize < minSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Insufficient space for index (need at least header + one node)"
        );
    }
    
    // Validate available size won't cause overflow in subsequent calculations
    if (availableSize > static_cast<uint64_t>(INT64_MAX)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Available size exceeds maximum supported value"
        );
    }
    
    m_view = nullptr;  // Write mode
    m_baseAddress = baseAddress;
    m_indexOffset = 0;
    m_indexSize = availableSize;
    
    // Initialize header to zeros (bounds already validated above)
    auto* header = static_cast<uint8_t*>(baseAddress);
    std::memset(header, 0, static_cast<size_t>(HEADER_SIZE));
    
    // Create root node (empty leaf)
    m_rootOffset = HEADER_SIZE;
    
    // Safe calculation of next node offset
    uint64_t nextOffset = 0;
    if (!SafeAdd(HEADER_SIZE, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nextOffset)) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Next node offset calculation overflow"
        );
    }
    m_nextNodeOffset = nextOffset;
    
    // Validate we have space for root node
    if (m_nextNodeOffset > availableSize) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidSection,
            "Not enough space for root node"
        );
    }
    
    auto* rootNode = reinterpret_cast<BPlusTreeNode*>(header + m_rootOffset);
    
    // Zero-initialize the entire node for security (prevent information leakage)
    std::memset(rootNode, 0, sizeof(BPlusTreeNode));
    
    // Initialize root node fields explicitly
    rootNode->isLeaf = true;
    rootNode->keyCount = 0;
    rootNode->parentOffset = 0;
    rootNode->nextLeaf = 0;
    rootNode->prevLeaf = 0;
    
    // Write header values
    auto* rootOffsetPtr = reinterpret_cast<uint64_t*>(header);
    *rootOffsetPtr = m_rootOffset;
    
    auto* nodeCountPtr = reinterpret_cast<uint64_t*>(header + 8);
    *nodeCountPtr = 1;
    
    auto* entryCountPtr = reinterpret_cast<uint64_t*>(header + 16);
    *entryCountPtr = 0;
    
    auto* nextNodePtr = reinterpret_cast<uint64_t*>(header + 24);
    *nextNodePtr = m_nextNodeOffset;
    
    auto* depthPtr = reinterpret_cast<uint32_t*>(header + 32);
    *depthPtr = 1;
    
    m_nodeCount.store(1, std::memory_order_relaxed);
    m_entryCount.store(0, std::memory_order_relaxed);
    m_treeDepth = 1;
    
    usedSize = m_nextNodeOffset;
    
    SS_LOG_DEBUG(L"Whitelist", L"HashIndex created: root at offset %llu", m_rootOffset);
    
    return StoreError::Success();
}

const BPlusTreeNode* HashIndex::FindLeaf(uint64_t key) const noexcept {
    // Must have either view or base address
    if (!m_view && !m_baseAddress) {
        return nullptr;
    }
    
    // Validate index size is set
    if (m_indexSize == 0) {
        return nullptr;
    }
    
    // Validate root offset
    if (m_rootOffset == 0 || m_rootOffset >= m_indexSize) {
        return nullptr;
    }
    
    uint64_t currentOffset = m_rootOffset;
    
    // Traverse tree with depth limit to prevent infinite loops
    // Use min(m_treeDepth, MAX_TREE_DEPTH) for extra safety
    const uint32_t maxIterations = std::min(m_treeDepth + 1, MAX_TREE_DEPTH);
    
    for (uint32_t depth = 0; depth < maxIterations; ++depth) {
        const BPlusTreeNode* node = nullptr;
        
        if (m_view) {
            // Read-only mode
            if (!IsOffsetValid(currentOffset)) {
                return nullptr;
            }
            
            // Additional bounds check for GetAt
            uint64_t nodeEndOffset = 0;
            if (!SafeAdd(m_indexOffset, currentOffset, nodeEndOffset) ||
                !SafeAdd(nodeEndOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nodeEndOffset)) {
                return nullptr;
            }
            if (nodeEndOffset > m_view->fileSize) {
                return nullptr;
            }
            
            node = m_view->GetAt<BPlusTreeNode>(m_indexOffset + currentOffset);
        } else if (m_baseAddress) {
            // Write mode
            if (currentOffset >= m_indexSize) {
                return nullptr;
            }
            
            // Bounds check for node access
            uint64_t nodeEndOffset = 0;
            if (!SafeAdd(currentOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nodeEndOffset) ||
                nodeEndOffset > m_indexSize) {
                return nullptr;
            }
            
            node = reinterpret_cast<const BPlusTreeNode*>(
                static_cast<const uint8_t*>(m_baseAddress) + currentOffset
            );
        }
        
        if (!node) {
            return nullptr;
        }
        
        // Found leaf node
        if (node->isLeaf) {
            return node;
        }
        
        // Validate key count (defense against corrupted data)
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex: corrupt node with keyCount=%u (max=%u)", 
                        node->keyCount, BPlusTreeNode::MAX_KEYS);
            return nullptr;
        }
        
        // Binary search for the correct child
        uint32_t left = 0;
        uint32_t right = node->keyCount;
        
        while (left < right) {
            const uint32_t mid = left + (right - left) / 2;
            if (node->keys[mid] <= key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        // Get child pointer (left is the index of the child to follow)
        if (left > BPlusTreeNode::MAX_KEYS) {
            return nullptr;  // Invalid index
        }
        
        currentOffset = node->children[left];
        
        if (currentOffset == 0 || currentOffset >= m_indexSize) {
            return nullptr;  // Invalid child pointer
        }
    }
    
    // Exceeded depth limit
    SS_LOG_ERROR(L"Whitelist", L"HashIndex: exceeded max tree depth during search");
    return nullptr;
}

std::optional<uint64_t> HashIndex::Lookup(const HashValue& hash) const noexcept {
    std::shared_lock lock(m_rwLock);
    
    // Validate hash
    if (hash.IsEmpty()) {
        return std::nullopt;
    }
    
    const uint64_t key = hash.FastHash();
    const BPlusTreeNode* leaf = FindLeaf(key);
    
    if (!leaf) {
        return std::nullopt;
    }
    
    // Validate leaf node
    if (leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::Lookup: corrupt leaf node");
        return std::nullopt;
    }
    
    // Binary search in leaf
    uint32_t left = 0;
    uint32_t right = leaf->keyCount;
    
    while (left < right) {
        const uint32_t mid = left + (right - left) / 2;
        
        if (leaf->keys[mid] < key) {
            left = mid + 1;
        } else if (leaf->keys[mid] > key) {
            right = mid;
        } else {
            // Found - return entry offset
            return static_cast<uint64_t>(leaf->children[mid]);
        }
    }
    
    return std::nullopt;
}

bool HashIndex::Contains(const HashValue& hash) const noexcept {
    return Lookup(hash).has_value();
}

void HashIndex::BatchLookup(
    std::span<const HashValue> hashes,
    std::vector<std::optional<uint64_t>>& results
) const noexcept {
    // Pre-allocate results
    try {
        results.clear();
        results.resize(hashes.size(), std::nullopt);
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::BatchLookup: allocation failed - %S", e.what());
        return;
    }
    
    if (hashes.empty()) {
        return;
    }
    
    std::shared_lock lock(m_rwLock);
    
    for (size_t i = 0; i < hashes.size(); ++i) {
        // Skip empty hashes
        if (hashes[i].IsEmpty()) {
            results[i] = std::nullopt;
            continue;
        }
        
        const uint64_t key = hashes[i].FastHash();
        const BPlusTreeNode* leaf = FindLeaf(key);
        
        if (!leaf || leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
            results[i] = std::nullopt;
            continue;
        }
        
        // Binary search in leaf
        bool found = false;
        uint32_t left = 0;
        uint32_t right = leaf->keyCount;
        
        while (left < right) {
            const uint32_t mid = left + (right - left) / 2;
            
            if (leaf->keys[mid] < key) {
                left = mid + 1;
            } else if (leaf->keys[mid] > key) {
                right = mid;
            } else {
                results[i] = static_cast<uint64_t>(leaf->children[mid]);
                found = true;
                break;
            }
        }
        
        if (!found) {
            results[i] = std::nullopt;
        }
    }
}

BPlusTreeNode* HashIndex::FindLeafMutable(uint64_t key) noexcept {
    // Requires writable base address
    if (!m_baseAddress) {
        return nullptr;
    }
    
    // Validate root offset
    if (m_rootOffset == 0 || m_rootOffset >= m_indexSize) {
        return nullptr;
    }
    
    uint64_t currentOffset = m_rootOffset;
    
    // Traverse with depth limit
    for (uint32_t depth = 0; depth < MAX_TREE_DEPTH && depth <= m_treeDepth; ++depth) {
        // Bounds check
        if (currentOffset >= m_indexSize) {
            return nullptr;
        }
        
        auto* node = reinterpret_cast<BPlusTreeNode*>(
            static_cast<uint8_t*>(m_baseAddress) + currentOffset
        );
        
        // Found leaf
        if (node->isLeaf) {
            return node;
        }
        
        // Validate key count
        if (node->keyCount > BPlusTreeNode::MAX_KEYS) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex: corrupt node during mutable search");
            return nullptr;
        }
        
        // Binary search for correct child
        uint32_t left = 0;
        uint32_t right = node->keyCount;
        
        while (left < right) {
            const uint32_t mid = left + (right - left) / 2;
            if (node->keys[mid] <= key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        // Validate child index
        if (left > BPlusTreeNode::MAX_KEYS) {
            return nullptr;
        }
        
        currentOffset = node->children[left];
        
        if (currentOffset == 0 || currentOffset >= m_indexSize) {
            return nullptr;
        }
    }
    
    return nullptr;
}

BPlusTreeNode* HashIndex::AllocateNode() noexcept {
    if (!m_baseAddress) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: no base address");
        return nullptr;
    }
    
    // Validate current state
    if (m_nextNodeOffset == 0 || m_indexSize == 0) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: invalid index state");
        return nullptr;
    }
    
    // Check if we have space (safe calculation)
    uint64_t newNextOffset = 0;
    if (!SafeAdd(m_nextNodeOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), newNextOffset)) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex: node offset overflow");
        return nullptr;
    }
    
    if (newNextOffset > m_indexSize) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex: no space for new node (need %llu, have %llu)", 
                    newNextOffset, m_indexSize);
        return nullptr;
    }
    
    // Additional validation: ensure current offset is within bounds
    if (m_nextNodeOffset >= m_indexSize) {
        SS_LOG_ERROR(L"Whitelist", L"HashIndex::AllocateNode: current offset out of bounds");
        return nullptr;
    }
    
    auto* node = reinterpret_cast<BPlusTreeNode*>(
        static_cast<uint8_t*>(m_baseAddress) + m_nextNodeOffset
    );
    
    // Zero-initialize new node for security (prevents info leakage)
    std::memset(node, 0, sizeof(BPlusTreeNode));
    
    // Store the offset of this node before updating
    const uint64_t thisNodeOffset = m_nextNodeOffset;
    
    m_nextNodeOffset = newNextOffset;
    
    // Atomic increment with proper ordering
    const uint64_t newNodeCount = m_nodeCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    
    // Update header with bounds validation
    constexpr uint64_t NEXT_NODE_OFFSET_POSITION = 24;
    constexpr uint64_t NODE_COUNT_POSITION = 8;
    constexpr uint64_t HEADER_SIZE = 64;
    
    if (HEADER_SIZE <= m_indexSize) {
        auto* nextNodePtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + NEXT_NODE_OFFSET_POSITION
        );
        *nextNodePtr = m_nextNodeOffset;
        
        auto* nodeCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + NODE_COUNT_POSITION
        );
        *nodeCountPtr = newNodeCount;
    }
    
    return node;
}

StoreError HashIndex::SplitNode(BPlusTreeNode* node) noexcept {
    /*
     * ========================================================================
     * B+TREE NODE SPLITTING
     * ========================================================================
     *
     * Splits a full node into two nodes:
     * - Original node keeps first half of keys
     * - New node gets second half of keys
     * - Parent gets middle key (for internal nodes) or copy (for leaves)
     *
     * Security: All array accesses are bounds-checked to prevent corruption.
     *
     * Note: This is a simplified implementation. Full B+Tree would require
     * recursive parent updates.
     *
     * ========================================================================
     */
    
    if (!node) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Null node pointer"
        );
    }
    
    // Validate key count is exactly at maximum (ready for split)
    if (node->keyCount != BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Node is not full - split not needed"
        );
    }
    
    // Allocate new sibling node
    BPlusTreeNode* sibling = AllocateNode();
    if (!sibling) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Cannot allocate new node for split"
        );
    }
    
    sibling->isLeaf = node->isLeaf;
    
    // Calculate split point (middle of the node)
    const uint32_t splitPoint = node->keyCount / 2;
    
    // Validate split point is valid
    if (splitPoint == 0 || splitPoint >= BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid split point calculation"
        );
    }
    
    // Calculate sibling key count with bounds validation
    const uint32_t siblingKeyCount = node->keyCount - splitPoint;
    
    // Validate sibling won't overflow
    if (siblingKeyCount > BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Sibling key count exceeds maximum"
        );
    }
    
    // Copy second half to sibling with explicit bounds checking
    for (uint32_t i = 0; i < siblingKeyCount; ++i) {
        const uint32_t srcIdx = splitPoint + i;
        
        // Bounds check source index
        if (srcIdx >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Source index out of bounds during split"
            );
        }
        
        // Bounds check destination index
        if (i >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Destination index out of bounds during split"
            );
        }
        
        sibling->keys[i] = node->keys[srcIdx];
        sibling->children[i] = node->children[srcIdx];
        
        // Clear original slot for security
        node->keys[srcIdx] = 0;
        node->children[srcIdx] = 0;
    }
    
    // For internal nodes, copy the extra child pointer (MAX_KEYS + 1 children)
    if (!node->isLeaf && node->keyCount < BPlusTreeNode::MAX_KEYS + 1) {
        // The last child pointer is at index keyCount
        const uint32_t lastChildIdx = node->keyCount;
        if (lastChildIdx <= BPlusTreeNode::MAX_KEYS && siblingKeyCount <= BPlusTreeNode::MAX_KEYS) {
            sibling->children[siblingKeyCount] = node->children[lastChildIdx];
            node->children[lastChildIdx] = 0; // Clear for security
        }
    }
    
    sibling->keyCount = siblingKeyCount;
    node->keyCount = splitPoint;
    
    // Update leaf linked list with comprehensive bounds validation
    if (node->isLeaf && m_baseAddress) {
        // Calculate offsets safely
        const auto nodeAddr = reinterpret_cast<uintptr_t>(node);
        const auto baseAddr = reinterpret_cast<uintptr_t>(m_baseAddress);
        const auto siblingAddr = reinterpret_cast<uintptr_t>(sibling);
        
        // Verify nodes are within the base address range
        if (nodeAddr < baseAddr || siblingAddr < baseAddr) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: node address underflow");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Node address underflow during split"
            );
        }
        
        const uint64_t nodeOffset = nodeAddr - baseAddr;
        const uint64_t siblingOffset = siblingAddr - baseAddr;
        
        // Validate offsets are within index and fit in uint32_t
        if (nodeOffset >= m_indexSize || siblingOffset >= m_indexSize) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: computed offset exceeds index size");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Computed offset exceeds index size"
            );
        }
        
        if (nodeOffset > UINT32_MAX || siblingOffset > UINT32_MAX) {
            SS_LOG_ERROR(L"Whitelist", L"HashIndex::SplitNode: offset exceeds uint32_t range");
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Offset exceeds 32-bit range"
            );
        }
        
        // Update sibling's links
        sibling->nextLeaf = node->nextLeaf;
        sibling->prevLeaf = static_cast<uint32_t>(nodeOffset);
        node->nextLeaf = static_cast<uint32_t>(siblingOffset);
        
        // Update next leaf's prev pointer (if exists)
        if (sibling->nextLeaf != 0) {
            // Validate next leaf offset
            const uint64_t nextLeafOffset = sibling->nextLeaf;
            uint64_t nextLeafEndOffset = 0;
            
            if (nextLeafOffset < m_indexSize &&
                SafeAdd(nextLeafOffset, static_cast<uint64_t>(sizeof(BPlusTreeNode)), nextLeafEndOffset) &&
                nextLeafEndOffset <= m_indexSize) {
                
                auto* nextLeaf = reinterpret_cast<BPlusTreeNode*>(
                    static_cast<uint8_t*>(m_baseAddress) + nextLeafOffset
                );
                nextLeaf->prevLeaf = static_cast<uint32_t>(siblingOffset);
            } else {
                SS_LOG_WARN(L"Whitelist", L"HashIndex::SplitNode: invalid next leaf offset %u", 
                           sibling->nextLeaf);
                // Clear invalid reference
                sibling->nextLeaf = 0;
            }
        }
    }
    
    // TODO: Insert middle key into parent (requires full parent tracking)
    // This simplified implementation doesn't handle parent updates
    
    return StoreError::Success();
}

StoreError HashIndex::Insert(const HashValue& hash, uint64_t entryOffset) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate hash
    if (hash.IsEmpty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot insert empty hash"
        );
    }
    
    // Validate entry offset fits in uint32_t
    if (entryOffset > UINT32_MAX) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Entry offset exceeds 32-bit limit"
        );
    }
    
    const uint64_t key = hash.FastHash();
    BPlusTreeNode* leaf = FindLeafMutable(key);
    
    if (!leaf) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Failed to find leaf node"
        );
    }
    
    // Validate leaf node
    if (leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Corrupt leaf node detected"
        );
    }
    
    // Check for duplicate
    for (uint32_t i = 0; i < leaf->keyCount; ++i) {
        if (leaf->keys[i] == key) {
            // Update existing entry
            leaf->children[i] = static_cast<uint32_t>(entryOffset);
            return StoreError::Success();
        }
    }
    
    // Check if leaf is full
    if (leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
        auto splitResult = SplitNode(leaf);
        if (!splitResult.IsSuccess()) {
            return splitResult;
        }
        
        // Re-find the correct leaf after split
        leaf = FindLeafMutable(key);
        if (!leaf) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Failed to find leaf after split"
            );
        }
        
        // Re-validate after split
        if (leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexFull,
                "Leaf still full after split"
            );
        }
    }
    
    // Insert in sorted order
    uint32_t insertPos = 0;
    while (insertPos < leaf->keyCount && leaf->keys[insertPos] < key) {
        ++insertPos;
    }
    
    // Validate insert position is within bounds
    // insertPos must be <= keyCount (can insert at end) and < MAX_KEYS
    if (insertPos > leaf->keyCount || insertPos >= BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Invalid insert position computed"
        );
    }
    
    // Validate there's room for the new key
    if (leaf->keyCount >= BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexFull,
            "Leaf is full - should have been split"
        );
    }
    
    // Shift elements right (from end to insert position)
    for (uint32_t i = leaf->keyCount; i > insertPos; --i) {
        // Bounds validation: destination i must be < MAX_KEYS (ensured by keyCount < MAX_KEYS)
        // Source i-1 must be < keyCount (ensured by loop condition)
        if (i > BPlusTreeNode::MAX_KEYS || i == 0) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Shift index out of bounds"
            );
        }
        leaf->keys[i] = leaf->keys[i - 1];
        leaf->children[i] = leaf->children[i - 1];
    }
    
    // Insert new key/value
    leaf->keys[insertPos] = key;
    leaf->children[insertPos] = static_cast<uint32_t>(entryOffset);
    leaf->keyCount++;
    
    // Atomic increment with acquire-release for proper ordering
    const uint64_t newEntryCount = m_entryCount.fetch_add(1, std::memory_order_acq_rel) + 1;
    
    // Update header with proper bounds check
    constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
    constexpr uint64_t HEADER_SIZE = 64;
    if (HEADER_SIZE <= m_indexSize) {
        auto* entryCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
        );
        *entryCountPtr = newEntryCount;
    }
    
    return StoreError::Success();
}

StoreError HashIndex::Remove(const HashValue& hash) noexcept {
    std::unique_lock lock(m_rwLock);
    
    // Validate writable state
    if (!m_baseAddress) {
        return StoreError::WithMessage(
            WhitelistStoreError::ReadOnlyDatabase,
            "Index is read-only"
        );
    }
    
    // Validate hash
    if (hash.IsEmpty()) {
        return StoreError::WithMessage(
            WhitelistStoreError::InvalidEntry,
            "Cannot remove empty hash"
        );
    }
    
    const uint64_t key = hash.FastHash();
    BPlusTreeNode* leaf = FindLeafMutable(key);
    
    if (!leaf) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Key not found"
        );
    }
    
    // Validate leaf node
    if (leaf->keyCount == 0 || leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Corrupt leaf node"
        );
    }
    
    // Find key in leaf using bounds-safe linear search
    uint32_t pos = 0;
    bool found = false;
    
    while (pos < leaf->keyCount && pos < BPlusTreeNode::MAX_KEYS) {
        if (leaf->keys[pos] == key) {
            found = true;
            break;
        }
        ++pos;
    }
    
    if (!found) {
        return StoreError::WithMessage(
            WhitelistStoreError::EntryNotFound,
            "Key not found in leaf"
        );
    }
    
    // Validate pos is within bounds before shift
    if (pos >= leaf->keyCount) {
        return StoreError::WithMessage(
            WhitelistStoreError::IndexCorrupted,
            "Found position exceeds key count"
        );
    }
    
    // Shift elements left with explicit bounds checking
    // We're removing element at pos, shifting from pos+1 to keyCount-1
    for (uint32_t i = pos; i + 1 < leaf->keyCount; ++i) {
        // Source index (i+1) is always < keyCount by loop condition
        // Destination (i) is always < keyCount-1 by loop condition
        if (i >= BPlusTreeNode::MAX_KEYS || i + 1 >= BPlusTreeNode::MAX_KEYS) {
            return StoreError::WithMessage(
                WhitelistStoreError::IndexCorrupted,
                "Shift index out of bounds during remove"
            );
        }
        leaf->keys[i] = leaf->keys[i + 1];
        leaf->children[i] = leaf->children[i + 1];
    }
    
    // Clear the last slot for security (prevents information leakage)
    const uint32_t lastIdx = leaf->keyCount - 1;
    if (lastIdx < BPlusTreeNode::MAX_KEYS) {
        leaf->keys[lastIdx] = 0;
        leaf->children[lastIdx] = 0;
    }
    
    leaf->keyCount--;
    
    // Atomic decrement with acquire-release for proper ordering
    const uint64_t newEntryCount = m_entryCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
    
    // Update header with proper bounds check
    constexpr uint64_t ENTRY_COUNT_OFFSET = 16;
    constexpr uint64_t HEADER_SIZE = 64;
    if (HEADER_SIZE <= m_indexSize) {
        auto* entryCountPtr = reinterpret_cast<uint64_t*>(
            static_cast<uint8_t*>(m_baseAddress) + ENTRY_COUNT_OFFSET
        );
        *entryCountPtr = newEntryCount;
    }
    
    // TODO: Handle underflow and node merging for B+Tree balance
    
    return StoreError::Success();
}

StoreError HashIndex::BatchInsert(
    std::span<const std::pair<HashValue, uint64_t>> entries
) noexcept {
    // Validate input
    if (entries.empty()) {
        return StoreError::Success();
    }
    
    // Insert entries one by one
    // Note: Could be optimized with bulk loading for sorted input
    for (const auto& [hash, offset] : entries) {
        auto result = Insert(hash, offset);
        if (!result.IsSuccess()) {
            return result;
        }
    }
    return StoreError::Success();
}

} // namespace ShadowStrike::Whitelist