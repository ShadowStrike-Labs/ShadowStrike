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
#include "ThreatIntelIndex_LRU.hpp"
#include <cstdint>
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
            explicit HashBPlusTree(size_t initialCapacity = 1'000'000);
            ~HashBPlusTree();

            void Insert(uint64_t hash, const IndexValue& value);
            [[nodiscard]] bool Lookup(uint64_t hash, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(uint64_t hash) const;
            void Remove(uint64_t hash);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetSize() const noexcept;
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }

        private:
            struct BNode;
            std::unique_ptr<BNode> m_root;
            LRUCache<uint64_t, IndexValue> m_cache;
            uint32_t m_height = 0;
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // GenericBPlusTree Declaration (for FileHash)
        // ============================================================================

        class GenericBPlusTree {
        public:
            explicit GenericBPlusTree(size_t initialCapacity = 500'000);
            ~GenericBPlusTree();

            void Insert(std::string_view key, const IndexValue& value);
            [[nodiscard]] bool Lookup(std::string_view key, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(std::string_view key) const;
            void Remove(std::string_view key);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetSize() const noexcept;
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }

        private:
            struct BNode;
            std::unique_ptr<BNode> m_root;
            LRUCache<std::string, IndexValue> m_cache;
            uint32_t m_height = 0;
            mutable std::shared_mutex m_mutex;
        };

    } // namespace ThreatIntel
} // namespace ShadowStrike