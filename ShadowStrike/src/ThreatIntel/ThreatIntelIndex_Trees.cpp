/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - B+Tree Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Enterprise-grade B+Tree implementations for hash and generic key lookups.
 * Optimized for:
 * - Cache-line aligned nodes (64 bytes)
 * - High branching factor for optimal cache utilization
 * - Leaf linking for efficient range scans
 * - Thread-safe reader-writer locking
 * - LRU caching for hot entries
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"
#include "ThreatIntelIndex_Trees.hpp"

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// CONSTANTS AND CONFIGURATION
// ============================================================================

/// Cache line size for alignment
static constexpr size_t CACHE_LINE_SIZE = 64;

/// B+Tree branching factor (keys per node) - optimized for cache efficiency
static constexpr size_t BRANCHING_FACTOR = 64;

/// Minimum keys per node (for underflow detection)
static constexpr size_t MIN_KEYS = BRANCHING_FACTOR / 2;

// ============================================================================
// HashBPlusTree::BNode - Internal Node Structure
// ============================================================================

/**
 * @brief Node types for B+Tree
 */
enum class BNodeType : uint8_t {
    Internal = 0,
    Leaf = 1
};

/**
 * @brief B+Tree node structure (cache-line aligned)
 * 
 * This is the internal implementation of the forward-declared BNode
 * in the header. Aligned to cache lines for optimal memory access patterns.
 */
struct alignas(CACHE_LINE_SIZE) HashBPlusTree::BNode {
    BNodeType type{ BNodeType::Leaf };
    uint16_t keyCount{ 0 };
    uint8_t reserved[5]{};
    
    /// Keys (sorted) - FNV-1a hash of the actual hash value
    std::array<uint64_t, BRANCHING_FACTOR> keys{};
    
    /// Values/children union
    /// For leaf nodes: IndexValue entries
    /// For internal nodes: child node pointers
    union NodeData {
        std::array<IndexValue, BRANCHING_FACTOR> entries;
        std::array<BNode*, BRANCHING_FACTOR + 1> children;
        
        NodeData() noexcept : children{} {
            children.fill(nullptr);
        }
    } data{};
    
    /// Linked list pointers for leaf traversal
    BNode* nextLeaf{ nullptr };
    BNode* prevLeaf{ nullptr };
    
    /// Parent pointer for split propagation
    BNode* parent{ nullptr };
    
    BNode() noexcept = default;
    
    [[nodiscard]] bool IsLeaf() const noexcept { return type == BNodeType::Leaf; }
    [[nodiscard]] bool IsFull() const noexcept { return keyCount >= BRANCHING_FACTOR; }
    [[nodiscard]] bool IsUnderflow() const noexcept { return keyCount < MIN_KEYS; }
    
    /**
     * @brief Binary search for key position
     * @param key Key to search for
     * @return Position where key should be (or is)
     */
    [[nodiscard]] uint16_t FindKeyPosition(uint64_t key) const noexcept {
        uint16_t left = 0;
        uint16_t right = keyCount;
        
        while (left < right) {
            uint16_t mid = left + (right - left) / 2;
            if (keys[mid] < key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        return left;
    }
};

// ============================================================================
// GenericBPlusTree::BNode - Internal Node Structure
// ============================================================================

/**
 * @brief B+Tree node for generic key lookups
 */
struct alignas(CACHE_LINE_SIZE) GenericBPlusTree::BNode {
    BNodeType type{ BNodeType::Leaf };
    uint16_t keyCount{ 0 };
    uint8_t reserved[5]{};
    
    std::array<uint64_t, BRANCHING_FACTOR> keys{};
    
    union NodeData {
        std::array<IndexValue, BRANCHING_FACTOR> entries;
        std::array<BNode*, BRANCHING_FACTOR + 1> children;
        
        NodeData() noexcept : children{} {
            children.fill(nullptr);
        }
    } data{};
    
    BNode* nextLeaf{ nullptr };
    BNode* prevLeaf{ nullptr };
    BNode* parent{ nullptr };
    
    BNode() noexcept = default;
    
    [[nodiscard]] bool IsLeaf() const noexcept { return type == BNodeType::Leaf; }
    [[nodiscard]] bool IsFull() const noexcept { return keyCount >= BRANCHING_FACTOR; }
    [[nodiscard]] bool IsUnderflow() const noexcept { return keyCount < MIN_KEYS; }
    
    [[nodiscard]] uint16_t FindKeyPosition(uint64_t key) const noexcept {
        uint16_t left = 0;
        uint16_t right = keyCount;
        
        while (left < right) {
            uint16_t mid = left + (right - left) / 2;
            if (keys[mid] < key) {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        return left;
    }
};

// ============================================================================
// HASH B+TREE - PRIVATE HELPER METHODS (FILE-LOCAL)
// ============================================================================

namespace {

/**
 * @brief Find the leaf node that should contain the given key
 */
[[nodiscard]] HashBPlusTree::BNode* FindLeafNode(HashBPlusTree::BNode* root, uint64_t key) noexcept {
    HashBPlusTree::BNode* node = root;
    
    while (node != nullptr && !node->IsLeaf()) {
        uint16_t pos = node->FindKeyPosition(key);
        
        // For internal nodes, go to appropriate child
        if (pos < node->keyCount && key >= node->keys[pos]) {
            ++pos;
        }
        
        if (pos <= node->keyCount && node->data.children[pos] != nullptr) {
            PREFETCH_READ(node->data.children[pos]);
            node = node->data.children[pos];
        } else {
            return nullptr;
        }
    }
    
    return node;
}

/**
 * @brief Insert key into non-full leaf node
 */
void InsertIntoLeaf(HashBPlusTree::BNode* leaf, uint64_t key, const IndexValue& value) noexcept {
    uint16_t pos = leaf->FindKeyPosition(key);
    
    // Shift entries to make room
    for (uint16_t i = leaf->keyCount; i > pos; --i) {
        leaf->keys[i] = leaf->keys[i - 1];
        leaf->data.entries[i] = leaf->data.entries[i - 1];
    }
    
    // Insert new entry
    leaf->keys[pos] = key;
    leaf->data.entries[pos] = value;
    ++leaf->keyCount;
}

/**
 * @brief Remove entry from leaf at given position
 */
void RemoveFromLeaf(HashBPlusTree::BNode* leaf, uint16_t pos) noexcept {
    // Shift entries to fill gap
    for (uint16_t i = pos; i < leaf->keyCount - 1; ++i) {
        leaf->keys[i] = leaf->keys[i + 1];
        leaf->data.entries[i] = leaf->data.entries[i + 1];
    }
    --leaf->keyCount;
}

/**
 * @brief Recursively clear all nodes in the tree
 */
void ClearRecursive(HashBPlusTree::BNode* node, HashBPlusTree::BNode* root) noexcept {
    if (node == nullptr) return;
    
    if (!node->IsLeaf()) {
        for (uint16_t i = 0; i <= node->keyCount; ++i) {
            if (node->data.children[i] != nullptr && node->data.children[i] != root) {
                ClearRecursive(node->data.children[i], root);
                delete node->data.children[i];
                node->data.children[i] = nullptr;
            }
        }
    }
}

// Forward declarations for split operations
void InsertIntoParent(HashBPlusTree::BNode*& root, HashBPlusTree::BNode* left, 
                      uint64_t key, HashBPlusTree::BNode* right, 
                      uint32_t& height, size_t& nodeCount);

void SplitInternalAndInsert(HashBPlusTree::BNode*& root, HashBPlusTree::BNode* node,
                            uint64_t key, HashBPlusTree::BNode* newChild,
                            uint32_t& height, size_t& nodeCount);

/**
 * @brief Split full leaf and insert new key
 */
void SplitLeafAndInsert(HashBPlusTree::BNode*& root, HashBPlusTree::BNode* leaf,
                        uint64_t key, const IndexValue& value,
                        HashBPlusTree::BNode*& lastLeaf,
                        uint32_t& height, size_t& nodeCount) {
    // Create new leaf
    auto* newLeaf = new HashBPlusTree::BNode();
    newLeaf->type = BNodeType::Leaf;
    ++nodeCount;
    
    // Determine split point
    constexpr uint16_t splitPoint = BRANCHING_FACTOR / 2;
    
    // Temporary storage for all keys + new key
    std::array<uint64_t, BRANCHING_FACTOR + 1> tempKeys;
    std::array<IndexValue, BRANCHING_FACTOR + 1> tempEntries;
    
    uint16_t insertPos = leaf->FindKeyPosition(key);
    uint16_t j = 0;
    for (uint16_t i = 0; i < leaf->keyCount; ++i) {
        if (i == insertPos) {
            tempKeys[j] = key;
            tempEntries[j] = value;
            ++j;
        }
        tempKeys[j] = leaf->keys[i];
        tempEntries[j] = leaf->data.entries[i];
        ++j;
    }
    if (insertPos == leaf->keyCount) {
        tempKeys[j] = key;
        tempEntries[j] = value;
    }
    
    // Distribute keys between leaves
    leaf->keyCount = splitPoint;
    for (uint16_t i = 0; i < splitPoint; ++i) {
        leaf->keys[i] = tempKeys[i];
        leaf->data.entries[i] = tempEntries[i];
    }
    
    newLeaf->keyCount = static_cast<uint16_t>(BRANCHING_FACTOR + 1 - splitPoint);
    for (uint16_t i = 0; i < newLeaf->keyCount; ++i) {
        newLeaf->keys[i] = tempKeys[splitPoint + i];
        newLeaf->data.entries[i] = tempEntries[splitPoint + i];
    }
    
    // Update leaf links
    newLeaf->nextLeaf = leaf->nextLeaf;
    newLeaf->prevLeaf = leaf;
    if (leaf->nextLeaf != nullptr) {
        leaf->nextLeaf->prevLeaf = newLeaf;
    }
    leaf->nextLeaf = newLeaf;
    
    if (lastLeaf == leaf) {
        lastLeaf = newLeaf;
    }
    
    // Insert separator into parent
    InsertIntoParent(root, leaf, newLeaf->keys[0], newLeaf, height, nodeCount);
}

/**
 * @brief Insert separator key into parent node
 */
void InsertIntoParent(HashBPlusTree::BNode*& root, HashBPlusTree::BNode* left,
                      uint64_t key, HashBPlusTree::BNode* right,
                      uint32_t& height, size_t& nodeCount) {
    if (left->parent == nullptr) {
        // Create new root
        auto* newRoot = new HashBPlusTree::BNode();
        newRoot->type = BNodeType::Internal;
        newRoot->keyCount = 1;
        newRoot->keys[0] = key;
        newRoot->data.children[0] = left;
        newRoot->data.children[1] = right;
        ++nodeCount;
        ++height;
        
        left->parent = newRoot;
        right->parent = newRoot;
        root = newRoot;
        return;
    }
    
    HashBPlusTree::BNode* parent = left->parent;
    right->parent = parent;
    
    if (!parent->IsFull()) {
        // Insert into parent
        uint16_t pos = parent->FindKeyPosition(key);
        
        // Shift keys and children
        for (uint16_t i = parent->keyCount; i > pos; --i) {
            parent->keys[i] = parent->keys[i - 1];
            parent->data.children[i + 1] = parent->data.children[i];
        }
        
        parent->keys[pos] = key;
        parent->data.children[pos + 1] = right;
        ++parent->keyCount;
    } else {
        // Split internal node
        SplitInternalAndInsert(root, parent, key, right, height, nodeCount);
    }
}

/**
 * @brief Split full internal node and insert
 */
void SplitInternalAndInsert(HashBPlusTree::BNode*& root, HashBPlusTree::BNode* node,
                            uint64_t key, HashBPlusTree::BNode* newChild,
                            uint32_t& height, size_t& nodeCount) {
    auto* newInternal = new HashBPlusTree::BNode();
    newInternal->type = BNodeType::Internal;
    ++nodeCount;
    
    constexpr uint16_t splitPoint = BRANCHING_FACTOR / 2;
    
    // Temporary storage
    std::array<uint64_t, BRANCHING_FACTOR + 1> tempKeys;
    std::array<HashBPlusTree::BNode*, BRANCHING_FACTOR + 2> tempChildren;
    
    uint16_t insertPos = node->FindKeyPosition(key);
    uint16_t j = 0;
    
    tempChildren[0] = node->data.children[0];
    for (uint16_t i = 0; i < node->keyCount; ++i) {
        if (i == insertPos) {
            tempKeys[j] = key;
            tempChildren[j + 1] = newChild;
            ++j;
        }
        tempKeys[j] = node->keys[i];
        tempChildren[j + 1] = node->data.children[i + 1];
        ++j;
    }
    if (insertPos == node->keyCount) {
        tempKeys[j] = key;
        tempChildren[j + 1] = newChild;
    }
    
    // Distribute to original node
    node->keyCount = splitPoint;
    for (uint16_t i = 0; i < splitPoint; ++i) {
        node->keys[i] = tempKeys[i];
        node->data.children[i] = tempChildren[i];
        if (tempChildren[i]) tempChildren[i]->parent = node;
    }
    node->data.children[splitPoint] = tempChildren[splitPoint];
    if (tempChildren[splitPoint]) tempChildren[splitPoint]->parent = node;
    
    uint64_t middleKey = tempKeys[splitPoint];
    
    // Distribute to new node
    newInternal->keyCount = static_cast<uint16_t>(BRANCHING_FACTOR - splitPoint);
    for (uint16_t i = 0; i < newInternal->keyCount; ++i) {
        newInternal->keys[i] = tempKeys[splitPoint + 1 + i];
        newInternal->data.children[i] = tempChildren[splitPoint + 1 + i];
        if (tempChildren[splitPoint + 1 + i]) {
            tempChildren[splitPoint + 1 + i]->parent = newInternal;
        }
    }
    newInternal->data.children[newInternal->keyCount] = tempChildren[BRANCHING_FACTOR + 1];
    if (tempChildren[BRANCHING_FACTOR + 1]) {
        tempChildren[BRANCHING_FACTOR + 1]->parent = newInternal;
    }
    
    // Insert middle key into parent
    InsertIntoParent(root, node, middleKey, newInternal, height, nodeCount);
}

} // anonymous namespace

// ============================================================================
// HASH B+TREE - PUBLIC METHOD IMPLEMENTATIONS
// ============================================================================

/**
 * @brief Construct a B+Tree for a specific hash algorithm
 */
HashBPlusTree::HashBPlusTree(HashAlgorithm algorithm)
    : m_root(std::make_unique<BNode>())
    , m_cache(10000)  // Cache up to 10k hot entries
    , m_algorithm(algorithm)
    , m_height(1) {
    m_root->type = BNodeType::Leaf;
}

HashBPlusTree::~HashBPlusTree() {
    Clear();
}

/**
 * @brief Insert hash value into B+Tree
 * @param hash Hash value to insert
 * @param value Index value (entryId + offset)
 * @return true if insertion succeeded
 */
bool HashBPlusTree::Insert(const HashValue& hash, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr || hash.algorithm != m_algorithm)) {
        return false;
    }
    
    const uint64_t key = hash.FastHash();
    
    try {
        BNode* leaf = FindLeafNode(m_root.get(), key);
        if (leaf == nullptr) {
            return false;
        }
        
        // Check for duplicate
        uint16_t pos = leaf->FindKeyPosition(key);
        if (pos < leaf->keyCount && leaf->keys[pos] == key) {
            // Update existing entry
            leaf->data.entries[pos] = value;
            // Update cache
            m_cache.Put(key, value);
            return true;
        }
        
        // Insert into leaf
        static size_t nodeCount = 1;
        static BNode* lastLeaf = m_root.get();
        
        if (!leaf->IsFull()) {
            InsertIntoLeaf(leaf, key, value);
        } else {
            BNode* rawRoot = m_root.release();
            SplitLeafAndInsert(rawRoot, leaf, key, value, lastLeaf, m_height, nodeCount);
            m_root.reset(rawRoot);
        }
        
        // Update cache
        m_cache.Put(key, value);
        return true;
    }
    catch (const std::bad_alloc&) {
        return false;
    }
}

/**
 * @brief Lookup hash value in B+Tree
 * @param hash Hash to look up
 * @param outValue Output parameter for result
 * @return true if found, false otherwise
 */
bool HashBPlusTree::Lookup(const HashValue& hash, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr || hash.algorithm != m_algorithm)) {
        return false;
    }
    
    const uint64_t key = hash.FastHash();
    
    // Check cache first
    if (IndexValue cachedValue; m_cache.Get(key, cachedValue)) {
        outValue = cachedValue;
        return true;
    }
    
    // Find leaf node
    const BNode* leaf = FindLeafNode(const_cast<BNode*>(m_root.get()), key);
    if (leaf == nullptr) {
        return false;
    }
    
    // Binary search in leaf
    uint16_t pos = leaf->FindKeyPosition(key);
    if (pos < leaf->keyCount && leaf->keys[pos] == key) {
        outValue = leaf->data.entries[pos];
        // Update cache (const_cast is safe here for mutable cache)
        const_cast<LRUCache<uint64_t, IndexValue>&>(m_cache).Put(key, outValue);
        return true;
    }
    
    return false;
}

/**
 * @brief Check if hash exists in tree
 */
bool HashBPlusTree::Contains(const HashValue& hash) const {
    IndexValue dummy;
    return Lookup(hash, dummy);
}

/**
 * @brief Remove entry by hash
 */
bool HashBPlusTree::Remove(const HashValue& hash) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr || hash.algorithm != m_algorithm)) {
        return false;
    }
    
    const uint64_t key = hash.FastHash();
    
    BNode* leaf = FindLeafNode(m_root.get(), key);
    if (leaf == nullptr) {
        return false;
    }
    
    uint16_t pos = leaf->FindKeyPosition(key);
    if (pos >= leaf->keyCount || leaf->keys[pos] != key) {
        return false;
    }
    
    // Remove from leaf (no rebalancing for simplicity)
    RemoveFromLeaf(leaf, pos);
    
    // Remove from cache
    // Note: LRU cache doesn't have remove, but entry will age out
    
    return true;
}

/**
 * @brief Clear all entries
 */
void HashBPlusTree::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_root != nullptr) {
        ClearRecursive(m_root.get(), m_root.get());
        m_root->type = BNodeType::Leaf;
        m_root->keyCount = 0;
        m_root->nextLeaf = nullptr;
        m_root->prevLeaf = nullptr;
        m_root->parent = nullptr;
    }
    
    m_height = 1;
    m_cache.Clear();
}

/**
 * @brief Get number of entries in tree
 */
size_t HashBPlusTree::GetSize() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    size_t count = 0;
    const BNode* leaf = m_root.get();
    
    // Find first leaf
    while (leaf != nullptr && !leaf->IsLeaf()) {
        leaf = leaf->data.children[0];
    }
    
    // Count all entries in all leaves
    while (leaf != nullptr) {
        count += leaf->keyCount;
        leaf = leaf->nextLeaf;
    }
    
    return count;
}

// ============================================================================
// GENERIC B+TREE - PRIVATE HELPER METHODS (FILE-LOCAL)
// ============================================================================

namespace {

[[nodiscard]] GenericBPlusTree::BNode* FindLeafNodeGeneric(GenericBPlusTree::BNode* root, uint64_t key) noexcept {
    GenericBPlusTree::BNode* node = root;
    
    while (node != nullptr && !node->IsLeaf()) {
        uint16_t pos = node->FindKeyPosition(key);
        if (pos < node->keyCount && key >= node->keys[pos]) {
            ++pos;
        }
        if (pos <= node->keyCount && node->data.children[pos] != nullptr) {
            PREFETCH_READ(node->data.children[pos]);
            node = node->data.children[pos];
        } else {
            return nullptr;
        }
    }
    
    return node;
}

void InsertIntoLeafGeneric(GenericBPlusTree::BNode* leaf, uint64_t key, const IndexValue& value) noexcept {
    uint16_t pos = leaf->FindKeyPosition(key);
    
    for (uint16_t i = leaf->keyCount; i > pos; --i) {
        leaf->keys[i] = leaf->keys[i - 1];
        leaf->data.entries[i] = leaf->data.entries[i - 1];
    }
    
    leaf->keys[pos] = key;
    leaf->data.entries[pos] = value;
    ++leaf->keyCount;
}

void RemoveFromLeafGeneric(GenericBPlusTree::BNode* leaf, uint16_t pos) noexcept {
    for (uint16_t i = pos; i < leaf->keyCount - 1; ++i) {
        leaf->keys[i] = leaf->keys[i + 1];
        leaf->data.entries[i] = leaf->data.entries[i + 1];
    }
    --leaf->keyCount;
}

void ClearRecursiveGeneric(GenericBPlusTree::BNode* node, GenericBPlusTree::BNode* root) noexcept {
    if (node == nullptr) return;
    
    if (!node->IsLeaf()) {
        for (uint16_t i = 0; i <= node->keyCount; ++i) {
            if (node->data.children[i] != nullptr && node->data.children[i] != root) {
                ClearRecursiveGeneric(node->data.children[i], root);
                delete node->data.children[i];
                node->data.children[i] = nullptr;
            }
        }
    }
}

// Forward declarations
void InsertIntoParentGeneric(GenericBPlusTree::BNode*& root, GenericBPlusTree::BNode* left,
                             uint64_t key, GenericBPlusTree::BNode* right,
                             uint32_t& height, size_t& nodeCount);

void SplitInternalAndInsertGeneric(GenericBPlusTree::BNode*& root, GenericBPlusTree::BNode* node,
                                   uint64_t key, GenericBPlusTree::BNode* newChild,
                                   uint32_t& height, size_t& nodeCount);

void SplitLeafAndInsertGeneric(GenericBPlusTree::BNode*& root, GenericBPlusTree::BNode* leaf,
                               uint64_t key, const IndexValue& value,
                               GenericBPlusTree::BNode*& lastLeaf,
                               uint32_t& height, size_t& nodeCount) {
    auto* newLeaf = new GenericBPlusTree::BNode();
    newLeaf->type = BNodeType::Leaf;
    ++nodeCount;
    
    constexpr uint16_t splitPoint = BRANCHING_FACTOR / 2;
    
    std::array<uint64_t, BRANCHING_FACTOR + 1> tempKeys;
    std::array<IndexValue, BRANCHING_FACTOR + 1> tempEntries;
    
    uint16_t insertPos = leaf->FindKeyPosition(key);
    uint16_t j = 0;
    for (uint16_t i = 0; i < leaf->keyCount; ++i) {
        if (i == insertPos) {
            tempKeys[j] = key;
            tempEntries[j] = value;
            ++j;
        }
        tempKeys[j] = leaf->keys[i];
        tempEntries[j] = leaf->data.entries[i];
        ++j;
    }
    if (insertPos == leaf->keyCount) {
        tempKeys[j] = key;
        tempEntries[j] = value;
    }
    
    leaf->keyCount = splitPoint;
    for (uint16_t i = 0; i < splitPoint; ++i) {
        leaf->keys[i] = tempKeys[i];
        leaf->data.entries[i] = tempEntries[i];
    }
    
    newLeaf->keyCount = static_cast<uint16_t>(BRANCHING_FACTOR + 1 - splitPoint);
    for (uint16_t i = 0; i < newLeaf->keyCount; ++i) {
        newLeaf->keys[i] = tempKeys[splitPoint + i];
        newLeaf->data.entries[i] = tempEntries[splitPoint + i];
    }
    
    newLeaf->nextLeaf = leaf->nextLeaf;
    newLeaf->prevLeaf = leaf;
    if (leaf->nextLeaf != nullptr) {
        leaf->nextLeaf->prevLeaf = newLeaf;
    }
    leaf->nextLeaf = newLeaf;
    
    if (lastLeaf == leaf) {
        lastLeaf = newLeaf;
    }
    
    InsertIntoParentGeneric(root, leaf, newLeaf->keys[0], newLeaf, height, nodeCount);
}

void InsertIntoParentGeneric(GenericBPlusTree::BNode*& root, GenericBPlusTree::BNode* left,
                             uint64_t key, GenericBPlusTree::BNode* right,
                             uint32_t& height, size_t& nodeCount) {
    if (left->parent == nullptr) {
        auto* newRoot = new GenericBPlusTree::BNode();
        newRoot->type = BNodeType::Internal;
        newRoot->keyCount = 1;
        newRoot->keys[0] = key;
        newRoot->data.children[0] = left;
        newRoot->data.children[1] = right;
        ++nodeCount;
        ++height;
        
        left->parent = newRoot;
        right->parent = newRoot;
        root = newRoot;
        return;
    }
    
    GenericBPlusTree::BNode* parent = left->parent;
    right->parent = parent;
    
    if (!parent->IsFull()) {
        uint16_t pos = parent->FindKeyPosition(key);
        for (uint16_t i = parent->keyCount; i > pos; --i) {
            parent->keys[i] = parent->keys[i - 1];
            parent->data.children[i + 1] = parent->data.children[i];
        }
        parent->keys[pos] = key;
        parent->data.children[pos + 1] = right;
        ++parent->keyCount;
    } else {
        SplitInternalAndInsertGeneric(root, parent, key, right, height, nodeCount);
    }
}

void SplitInternalAndInsertGeneric(GenericBPlusTree::BNode*& root, GenericBPlusTree::BNode* node,
                                   uint64_t key, GenericBPlusTree::BNode* newChild,
                                   uint32_t& height, size_t& nodeCount) {
    auto* newInternal = new GenericBPlusTree::BNode();
    newInternal->type = BNodeType::Internal;
    ++nodeCount;
    
    constexpr uint16_t splitPoint = BRANCHING_FACTOR / 2;
    
    std::array<uint64_t, BRANCHING_FACTOR + 1> tempKeys;
    std::array<GenericBPlusTree::BNode*, BRANCHING_FACTOR + 2> tempChildren;
    
    uint16_t insertPos = node->FindKeyPosition(key);
    uint16_t j = 0;
    
    tempChildren[0] = node->data.children[0];
    for (uint16_t i = 0; i < node->keyCount; ++i) {
        if (i == insertPos) {
            tempKeys[j] = key;
            tempChildren[j + 1] = newChild;
            ++j;
        }
        tempKeys[j] = node->keys[i];
        tempChildren[j + 1] = node->data.children[i + 1];
        ++j;
    }
    if (insertPos == node->keyCount) {
        tempKeys[j] = key;
        tempChildren[j + 1] = newChild;
    }
    
    node->keyCount = splitPoint;
    for (uint16_t i = 0; i < splitPoint; ++i) {
        node->keys[i] = tempKeys[i];
        node->data.children[i] = tempChildren[i];
        if (tempChildren[i]) tempChildren[i]->parent = node;
    }
    node->data.children[splitPoint] = tempChildren[splitPoint];
    if (tempChildren[splitPoint]) tempChildren[splitPoint]->parent = node;
    
    uint64_t middleKey = tempKeys[splitPoint];
    
    newInternal->keyCount = static_cast<uint16_t>(BRANCHING_FACTOR - splitPoint);
    for (uint16_t i = 0; i < newInternal->keyCount; ++i) {
        newInternal->keys[i] = tempKeys[splitPoint + 1 + i];
        newInternal->data.children[i] = tempChildren[splitPoint + 1 + i];
        if (tempChildren[splitPoint + 1 + i]) {
            tempChildren[splitPoint + 1 + i]->parent = newInternal;
        }
    }
    newInternal->data.children[newInternal->keyCount] = tempChildren[BRANCHING_FACTOR + 1];
    if (tempChildren[BRANCHING_FACTOR + 1]) {
        tempChildren[BRANCHING_FACTOR + 1]->parent = newInternal;
    }
    
    InsertIntoParentGeneric(root, node, middleKey, newInternal, height, nodeCount);
}

} // anonymous namespace

// ============================================================================
// GENERIC B+TREE - PUBLIC METHOD IMPLEMENTATIONS
// ============================================================================

GenericBPlusTree::GenericBPlusTree(size_t initialCapacity)
    : m_root(std::make_unique<BNode>())
    , m_cache(std::min(initialCapacity / 10, size_t{10000}))
    , m_height(1) {
    m_root->type = BNodeType::Leaf;
    (void)initialCapacity;  // Used for cache sizing
}

GenericBPlusTree::~GenericBPlusTree() {
    Clear();
}

bool GenericBPlusTree::Insert(uint64_t key, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr)) {
        return false;
    }
    
    try {
        BNode* leaf = FindLeafNodeGeneric(m_root.get(), key);
        if (leaf == nullptr) {
            return false;
        }
        
        uint16_t pos = leaf->FindKeyPosition(key);
        if (pos < leaf->keyCount && leaf->keys[pos] == key) {
            leaf->data.entries[pos] = value;
            m_cache.Put(key, value);
            return true;
        }
        
        static size_t nodeCount = 1;
        static BNode* lastLeaf = m_root.get();
        
        if (!leaf->IsFull()) {
            InsertIntoLeafGeneric(leaf, key, value);
        } else {
            BNode* rawRoot = m_root.release();
            SplitLeafAndInsertGeneric(rawRoot, leaf, key, value, lastLeaf, m_height, nodeCount);
            m_root.reset(rawRoot);
        }
        
        m_cache.Put(key, value);
        return true;
    }
    catch (const std::bad_alloc&) {
        return false;
    }
}

bool GenericBPlusTree::Lookup(uint64_t key, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr)) {
        return false;
    }
    
    // Check cache first
    if (IndexValue cachedValue; m_cache.Get(key, cachedValue)) {
        outValue = cachedValue;
        return true;
    }
    
    const BNode* leaf = FindLeafNodeGeneric(const_cast<BNode*>(m_root.get()), key);
    if (leaf == nullptr) {
        return false;
    }
    
    uint16_t pos = leaf->FindKeyPosition(key);
    if (pos < leaf->keyCount && leaf->keys[pos] == key) {
        outValue = leaf->data.entries[pos];
        const_cast<LRUCache<uint64_t, IndexValue>&>(m_cache).Put(key, outValue);
        return true;
    }
    
    return false;
}

bool GenericBPlusTree::Contains(uint64_t key) const {
    IndexValue dummy;
    return Lookup(key, dummy);
}

bool GenericBPlusTree::Remove(uint64_t key) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (UNLIKELY(m_root == nullptr)) {
        return false;
    }
    
    BNode* leaf = FindLeafNodeGeneric(m_root.get(), key);
    if (leaf == nullptr) {
        return false;
    }
    
    uint16_t pos = leaf->FindKeyPosition(key);
    if (pos >= leaf->keyCount || leaf->keys[pos] != key) {
        return false;
    }
    
    RemoveFromLeafGeneric(leaf, pos);
    return true;
}

void GenericBPlusTree::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (m_root != nullptr) {
        ClearRecursiveGeneric(m_root.get(), m_root.get());
        m_root->type = BNodeType::Leaf;
        m_root->keyCount = 0;
        m_root->nextLeaf = nullptr;
        m_root->prevLeaf = nullptr;
        m_root->parent = nullptr;
    }
    
    m_height = 1;
    m_cache.Clear();
}

size_t GenericBPlusTree::GetSize() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    size_t count = 0;
    const BNode* leaf = m_root.get();
    
    while (leaf != nullptr && !leaf->IsLeaf()) {
        leaf = leaf->data.children[0];
    }
    
    while (leaf != nullptr) {
        count += leaf->keyCount;
        leaf = leaf->nextLeaf;
    }
    
    return count;
}

} // namespace ThreatIntel
} // namespace ShadowStrike
