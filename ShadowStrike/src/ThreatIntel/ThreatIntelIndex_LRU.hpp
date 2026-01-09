#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
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
            struct CacheNode {
                Key key;
                Value value;
                CacheNode* prev{ nullptr };
                CacheNode* next{ nullptr };

                CacheNode(const Key& k, const Value& v) : key(k), value(v) {}
            };

            explicit LRUCache(size_t capacity)
                : m_capacity(std::max<size_t>(capacity, 16)) {
            }

            ~LRUCache() {
                Clear();
            }

            // Non-copyable
            LRUCache(const LRUCache&) = delete;
            LRUCache& operator=(const LRUCache&) = delete;

            /**
             * @brief Get value from cache
             * @param key Key to look up
             * @return Value if found, nullopt otherwise
             */
            [[nodiscard]] std::optional<Value> Get(const Key& key) noexcept {
                std::unique_lock<std::shared_mutex> lock(m_mutex);

                auto it = m_map.find(key);
                if (it == m_map.end()) {
                    ++m_missCount;
                    return std::nullopt;
                }

                // Move to front (most recently used)
                MoveToFront(it->second);
                ++m_hitCount;

                return it->second->value;
            }

            /**
             * @brief Get value from cache with output parameter
             * @param key Key to look up
             * @param outValue Output parameter for the value
             * @return true if found, false otherwise
             */
            [[nodiscard]] bool Get(const Key& key, Value& outValue) const noexcept {
                std::unique_lock<std::shared_mutex> lock(m_mutex);

                auto it = m_map.find(key);
                if (it == m_map.end()) {
                    ++m_missCount;
                    return false;
                }

                // Move to front (most recently used) - const_cast safe for mutable LRU ordering
                const_cast<LRUCache*>(this)->MoveToFront(it->second);
                ++m_hitCount;

                outValue = it->second->value;
                return true;
            }

            /**
             * @brief Put value into cache
             * @param key Key
             * @param value Value
             */
            void Put(const Key& key, const Value& value) noexcept {
                std::unique_lock<std::shared_mutex> lock(m_mutex);

                try {
                    auto it = m_map.find(key);

                    if (it != m_map.end()) {
                        // Update existing entry
                        it->second->value = value;
                        MoveToFront(it->second);
                        return;
                    }

                    // Create new node
                    CacheNode* node = new CacheNode(key, value);

                    // Add to front
                    AddToFront(node);
                    m_map[key] = node;

                    // Evict if over capacity
                    while (m_map.size() > m_capacity && m_tail != nullptr) {
                        CacheNode* toEvict = m_tail;
                        m_map.erase(toEvict->key);
                        RemoveNode(toEvict);
                        delete toEvict;
                        ++m_evictionCount;
                    }
                }
                catch (const std::bad_alloc&) {
                    // Ignore - cache is best effort
                }
            }

            /**
             * @brief Remove entry from cache
             * @param key Key to remove
             */
            void Remove(const Key& key) noexcept {
                std::unique_lock<std::shared_mutex> lock(m_mutex);

                auto it = m_map.find(key);
                if (it != m_map.end()) {
                    RemoveNode(it->second);
                    delete it->second;
                    m_map.erase(it);
                }
            }

            /**
             * @brief Clear all entries
             */
            void Clear() noexcept {
                std::unique_lock<std::shared_mutex> lock(m_mutex);

                CacheNode* current = m_head;
                while (current != nullptr) {
                    CacheNode* next = current->next;
                    delete current;
                    current = next;
                }

                m_head = nullptr;
                m_tail = nullptr;
                m_map.clear();
            }

            [[nodiscard]] size_t Size() const noexcept {
                std::shared_lock<std::shared_mutex> lock(m_mutex);
                return m_map.size();
            }

            [[nodiscard]] size_t Capacity() const noexcept { return m_capacity; }
            [[nodiscard]] uint64_t HitCount() const noexcept { return m_hitCount.load(std::memory_order_relaxed); }
            [[nodiscard]] uint64_t MissCount() const noexcept { return m_missCount.load(std::memory_order_relaxed); }
            [[nodiscard]] uint64_t EvictionCount() const noexcept { return m_evictionCount.load(std::memory_order_relaxed); }

            [[nodiscard]] double HitRate() const noexcept {
                uint64_t hits = m_hitCount.load(std::memory_order_relaxed);
                uint64_t misses = m_missCount.load(std::memory_order_relaxed);
                uint64_t total = hits + misses;
                return total > 0 ? static_cast<double>(hits) / total : 0.0;
            }

        private:
            void MoveToFront(CacheNode* node) noexcept {
                if (node == m_head) return;
                RemoveNode(node);
                AddToFront(node);
            }

            void AddToFront(CacheNode* node) noexcept {
                node->prev = nullptr;
                node->next = m_head;

                if (m_head != nullptr) {
                    m_head->prev = node;
                }
                m_head = node;

                if (m_tail == nullptr) {
                    m_tail = node;
                }
            }

            void RemoveNode(CacheNode* node) noexcept {
                if (node->prev != nullptr) {
                    node->prev->next = node->next;
                }
                else {
                    m_head = node->next;
                }

                if (node->next != nullptr) {
                    node->next->prev = node->prev;
                }
                else {
                    m_tail = node->prev;
                }
            }

            size_t m_capacity;
            std::unordered_map<Key, CacheNode*> m_map;
            CacheNode* m_head{ nullptr };
            CacheNode* m_tail{ nullptr };

            std::atomic<uint64_t> m_hitCount{ 0 };
            std::atomic<uint64_t> m_missCount{ 0 };
            std::atomic<uint64_t> m_evictionCount{ 0 };

            mutable std::shared_mutex m_mutex;
        };

} // namespace ThreatIntel
} // namespace ShadowStrike