
/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Data Structures Declarations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Data structure declarations: IPv4RadixTree, IPv6PatriciaTrie,
 * DomainSuffixTrie, EmailHashTable, IndexBloomFilter
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"
#include <cstdint>
#include <memory>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ShadowStrike {
    namespace ThreatIntel {

        // ============================================================================
        // IndexBloomFilter Declaration
        // ============================================================================

        class IndexBloomFilter {
        public:
            explicit IndexBloomFilter(uint64_t expectedElements = 10'000'000, double falsePosRate = 0.01);
            ~IndexBloomFilter() = default;

            // Non-copyable, movable
            IndexBloomFilter(const IndexBloomFilter&) = delete;
            IndexBloomFilter& operator=(const IndexBloomFilter&) = delete;
            IndexBloomFilter(IndexBloomFilter&&) noexcept;
            IndexBloomFilter& operator=(IndexBloomFilter&&) noexcept;

            void Add(const IOCEntry& entry) noexcept;
            void Add(uint64_t hash) noexcept;
            void BatchAdd(std::span<const IOCEntry> entries) noexcept;

            [[nodiscard]] bool MightContain(const IOCEntry& entry) const noexcept;
            [[nodiscard]] bool MightContain(uint64_t hash) const noexcept;

            void Clear() noexcept;
            [[nodiscard]] double GetEstimatedFillRate() const noexcept;
            [[nodiscard]] double GetEstimatedFalsePositiveRate() const noexcept;

        private:
            std::vector<uint64_t> m_bits;
            uint64_t m_numBits = 0;
            uint32_t m_numHashes = 0;
        };

        // ============================================================================
        // IPv4RadixTree Declaration
        // ============================================================================

        class IPv4RadixTree {
        public:
            IPv4RadixTree();
            ~IPv4RadixTree();

            void Insert(uint32_t ipv4, uint8_t prefixLen, const IndexValue& value);
            [[nodiscard]] bool Lookup(uint32_t ipv4, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(uint32_t ipv4) const;
            void Remove(uint32_t ipv4, uint8_t prefixLen);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetNodeCount() const noexcept { return m_nodeCount; }
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }

        private:
            struct RadixNode;
            std::unique_ptr<RadixNode> m_root;
            size_t m_nodeCount = 0;
            uint32_t m_height = 0;
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // IPv6PatriciaTrie Declaration
        // ============================================================================

        class IPv6PatriciaTrie {
        public:
            IPv6PatriciaTrie();
            ~IPv6PatriciaTrie();

            void Insert(std::string_view ipv6, uint8_t prefixLen, const IndexValue& value);
            [[nodiscard]] bool Lookup(std::string_view ipv6, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(std::string_view ipv6) const;
            void Remove(std::string_view ipv6, uint8_t prefixLen);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetNodeCount() const noexcept { return m_nodeCount; }
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }

        private:
            struct PatriciaNode;
            std::unique_ptr<PatriciaNode> m_root;
            size_t m_nodeCount = 0;
            uint32_t m_height = 0;
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // DomainSuffixTrie Declaration
        // ============================================================================

        class DomainSuffixTrie {
        public:
            DomainSuffixTrie();
            ~DomainSuffixTrie();

            void Insert(std::string_view domain, const IndexValue& value);
            [[nodiscard]] bool Lookup(std::string_view domain, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(std::string_view domain) const;
            void Remove(std::string_view domain);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetNodeCount() const noexcept { return m_nodeCount; }
            [[nodiscard]] uint32_t GetHeight() const noexcept { return m_height; }

        private:
            struct TrieNode;
            std::unique_ptr<TrieNode> m_root;
            size_t m_nodeCount = 0;
            uint32_t m_height = 0;
            mutable std::shared_mutex m_mutex;
        };

        // ============================================================================
        // EmailHashTable Declaration
        // ============================================================================

        class EmailHashTable {
        public:
            explicit EmailHashTable(size_t initialCapacity = 1'000'000);
            ~EmailHashTable() = default;

            void Insert(std::string_view email, const IndexValue& value);
            [[nodiscard]] bool Lookup(std::string_view email, IndexValue& outValue) const;
            [[nodiscard]] bool Contains(std::string_view email) const;
            void Remove(std::string_view email);
            void Clear() noexcept;

            template<typename Func>
            void ForEach(Func&& callback) const;

            [[nodiscard]] size_t GetSize() const noexcept { return m_entries.size(); }
            [[nodiscard]] double GetLoadFactor() const noexcept;

        private:
            std::unordered_map<std::string, IndexValue> m_entries;
            mutable std::shared_mutex m_mutex;
        };

    } // namespace ThreatIntel
} // namespace ShadowStrike