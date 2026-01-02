/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - LRU Cache Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Thread-safe LRU (Least Recently Used) cache for hot threat intelligence entries.
 * Template-based implementation for type flexibility.
 *
 * ============================================================================
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <unordered_map>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// LRU CACHE IMPLEMENTATION - ENTERPRISE-GRADE
// ============================================================================

/**
 * @brief Thread-safe LRU (Least Recently Used) cache for hot entries
 * 
 * Enterprise-grade implementation with:
 * - O(1) lookup, insert, and eviction
 * - Thread-safe concurrent access
 * - Configurable capacity
 * - Cache statistics tracking
 * 
 * Architecture:
 * - Hash map for O(1) key lookup
 * - Doubly-linked list for O(1) LRU ordering
 * - Reader-writer lock for thread safety
 */
template<typename Key, typename Value>
class LRUCache {
public:
    /**
     * @brief Construct LRU cache with specified capacity
     * @param capacity Maximum number of entries to cache
     */
    explicit LRUCache(size_t capacity)
        : m_capacity(capacity) {
        if (m_capacity == 0) {
            m_capacity = 1; // Minimum capacity
        }
    }
    
    ~LRUCache() {
        Clear();
    }
    
    // Non-copyable, non-movable
    LRUCache(const LRUCache&) = delete;
    LRUCache& operator=(const LRUCache&) = delete;
    LRUCache(LRUCache&&) = delete;
    LRUCache& operator=(LRUCache&&) = delete;
    
    /**
     * @brief Get value from cache
     * @param key Key to look up
     * @return Value if found, nullopt otherwise
     * 
     * Thread-safe: acquires exclusive lock (for LRU reordering)
     */
    [[nodiscard]] std::optional<Value> Get(const Key& key) noexcept {
        std::unique_lock lock(m_mutex);
        
        auto it = m_map.find(key);
        if (it == m_map.end()) {
            m_missCount.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }
        
        // Move to front (most recently used)
        MoveToFront(it->second);
        
        m_hitCount.fetch_add(1, std::memory_order_relaxed);
        return it->second->value;
    }
    
    /**
     * @brief Put key-value pair into cache
     * @param key Key to insert
     * @param value Value to insert
     * 
     * If cache is full, evicts least recently used entry.
     * Thread-safe: acquires exclusive lock
     */
    void Put(const Key& key, const Value& value) noexcept {
        std::unique_lock lock(m_mutex);
        
        // Check if key already exists
        auto it = m_map.find(key);
        if (it != m_map.end()) {
            // Update existing entry
            it->second->value = value;
            MoveToFront(it->second);
            return;
        }
        
        // Check capacity
        if (m_map.size() >= m_capacity) {
            // Evict LRU entry (tail)
            if (m_tail) {
                m_map.erase(m_tail->key);
                RemoveNode(m_tail);
                delete m_tail;
                m_evictionCount.fetch_add(1, std::memory_order_relaxed);
            }
        }
        
        // Create new node
        auto* node = new CacheNode{key, value, nullptr, nullptr};
        m_map[key] = node;
        AddToFront(node);
    }
    
    /**
     * @brief Remove entry from cache
     * @param key Key to remove
     * @return true if entry was found and removed
     */
    bool Remove(const Key& key) noexcept {
        std::unique_lock lock(m_mutex);
        
        auto it = m_map.find(key);
        if (it == m_map.end()) {
            return false;
        }
        
        RemoveNode(it->second);
        delete it->second;
        m_map.erase(it);
        return true;
    }
    
    /**
     * @brief Clear all entries
     */
    void Clear() noexcept {
        std::unique_lock lock(m_mutex);
        
        CacheNode* current = m_head;
        while (current) {
            CacheNode* next = current->next;
            delete current;
            current = next;
        }
        
        m_head = nullptr;
        m_tail = nullptr;
        m_map.clear();
    }
    
    /**
     * @brief Get current cache size
     */
    [[nodiscard]] size_t GetSize() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_map.size();
    }
    
    /**
     * @brief Get cache hit count
     */
    [[nodiscard]] uint64_t GetHitCount() const noexcept {
        return m_hitCount.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get cache miss count
     */
    [[nodiscard]] uint64_t GetMissCount() const noexcept {
        return m_missCount.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get eviction count
     */
    [[nodiscard]] uint64_t GetEvictionCount() const noexcept {
        return m_evictionCount.load(std::memory_order_relaxed);
    }
    
    /**
     * @brief Get cache hit rate
     */
    [[nodiscard]] double GetHitRate() const noexcept {
        uint64_t hits = m_hitCount.load(std::memory_order_relaxed);
        uint64_t misses = m_missCount.load(std::memory_order_relaxed);
        uint64_t total = hits + misses;
        return (total > 0) ? (static_cast<double>(hits) / total) : 0.0;
    }
    
private:
    struct CacheNode {
        Key key;
        Value value;
        CacheNode* prev;
        CacheNode* next;
    };
    
    void AddToFront(CacheNode* node) noexcept {
        node->next = m_head;
        node->prev = nullptr;
        
        if (m_head) {
            m_head->prev = node;
        }
        m_head = node;
        
        if (!m_tail) {
            m_tail = node;
        }
    }
    
    void RemoveNode(CacheNode* node) noexcept {
        if (node->prev) {
            node->prev->next = node->next;
        } else {
            m_head = node->next;
        }
        
        if (node->next) {
            node->next->prev = node->prev;
        } else {
            m_tail = node->prev;
        }
    }
    
    void MoveToFront(CacheNode* node) noexcept {
        if (node == m_head) {
            return; // Already at front
        }
        
        RemoveNode(node);
        AddToFront(node);
    }
    
    size_t m_capacity;
    std::unordered_map<Key, CacheNode*> m_map;
    CacheNode* m_head{nullptr};
    CacheNode* m_tail{nullptr};
    
    std::atomic<uint64_t> m_hitCount{0};
    std::atomic<uint64_t> m_missCount{0};
    std::atomic<uint64_t> m_evictionCount{0};
    
    mutable std::shared_mutex m_mutex;
};

} // namespace ThreatIntel
} // namespace ShadowStrike
