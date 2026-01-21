/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - B+Tree Declarations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * B+Tree implementations: HashBPlusTree, GenericBPlusTree
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include"ThreatIntelIndex.hpp"
#include "ThreatIntelIndex_LRU.hpp"
#include <cstdint>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

namespace ShadowStrike {
    namespace ThreatIntel {

        // ============================================================================
        // HashBPlusTree Declaration
        // ============================================================================

        class HashBPlusTree {
        public:
            explicit HashBPlusTree(HashAlgorithm algorithm = HashAlgorithm::SHA256);
            ~HashBPlusTree();

            /// @brief Insert a hash with its index value
            /// @return true if inserted successfully, false if already exists
            [[nodiscard]] bool Insert(const HashValue& hash, const IndexValue& value);
            
            /// @brief Lookup a hash
            /// @param hash Hash to look up
            /// @param outValue Output parameter for the result
            /// @return true if found, false otherwise
            [[nodiscard]] bool Lookup(const HashValue& hash, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(const HashValue& hash) const;
            
            /// @brief Remove a hash
            /// @return true if removed successfully, false if not found
            [[nodiscard]] bool Remove(const HashValue& hash);
            void Clear() noexcept;

            /// @brief Iterate over all entries
            /// @param callback Callback function(const HashValue& hash, const IndexValue& value)
            void ForEach(const std::function<void(const HashValue&, const IndexValue&)>& callback) const;

            [[nodiscard]] size_t GetSize() const noexcept;
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }
            [[nodiscard]] HashAlgorithm GetAlgorithm() const noexcept { return m_algorithm; }
            
            /// @brief Get entry count (alias for GetSize)
            [[nodiscard]] size_t GetEntryCount() const noexcept { return GetSize(); }
            
            /// @brief Estimate memory usage in bytes
            [[nodiscard]] size_t GetMemoryUsage() const noexcept;

            // Internal node structure - defined in implementation file
            // Made public for implementation methods to access
            struct BNode;
        
        private:
            std::unique_ptr<BNode> m_root;
            LRUCache<uint64_t, IndexValue> m_cache;
            HashAlgorithm m_algorithm;
            uint32_t m_height = 0;
            
            /// Node count for split tracking - must be per-instance, not static
            size_t m_nodeCount = 1;
            
            /// Last leaf pointer for linked list maintenance
            BNode* m_lastLeaf = nullptr;
            
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // GenericBPlusTree Declaration (for miscellaneous IOC types)
        // ============================================================================

        class GenericBPlusTree {
        public:
            explicit GenericBPlusTree(size_t initialCapacity = 500'000);
            ~GenericBPlusTree();

            /// @brief Insert a key with its index value
            /// @return true if inserted successfully, false if already exists
            [[nodiscard]] bool Insert(uint64_t key, const IndexValue& value);
            
            /// @brief Lookup a key
            /// @param key Key to look up
            /// @param outValue Output parameter for the result
            /// @return true if found, false otherwise
            [[nodiscard]] bool Lookup(uint64_t key, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(uint64_t key) const;
            
            /// @brief Remove a key
            /// @return true if removed successfully, false if not found
            [[nodiscard]] bool Remove(uint64_t key);
            void Clear() noexcept;

            /// @brief Iterate over all entries
            /// @param callback Callback function(uint64_t key, const IndexValue& value)
            void ForEach(const std::function<void(uint64_t, const IndexValue&)>& callback) const;

            [[nodiscard]] size_t GetSize() const noexcept;
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }
            
            /// @brief Get entry count (alias for GetSize)
            [[nodiscard]] size_t GetEntryCount() const noexcept { return GetSize(); }
            
            /// @brief Estimate memory usage in bytes
            [[nodiscard]] size_t GetMemoryUsage() const noexcept;
        
            // Internal node structure - defined in implementation file
            // Made public for implementation methods to access
            struct BNode;
             
        private:
            std::unique_ptr<BNode> m_root;
            LRUCache<uint64_t, IndexValue> m_cache;
            uint32_t m_height = 0;
            
            /// Node count for split tracking - must be per-instance, not static
            size_t m_nodeCount = 1;
            
            /// Last leaf pointer for linked list maintenance
            BNode* m_lastLeaf = nullptr;
            
            mutable std::shared_mutex m_mutex;
        };

    } // namespace ThreatIntel
} // namespace ShadowStrike