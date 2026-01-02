/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Data Structures Header
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Core data structures for threat intelligence indexing:
 * - IPv4RadixTree (4-level hierarchical tree)
 * - IPv6PatriciaTrie (binary patricia trie)
 * - DomainSuffixTrie (reverse domain matching)
 * - EmailHashTable (O(1) email lookups)
 * - IndexBloomFilter (negative lookups)
 *
 * ============================================================================
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class IndexBloomFilter;
class IPv4RadixTree;
class IPv6PatriciaTrie;
class DomainSuffixTrie;
class EmailHashTable;

// ============================================================================
// BLOOM FILTER
// ============================================================================

/**
 * @brief Simple bloom filter for negative lookups
 * 
 * Enterprise-grade implementation with bounds checking and thread safety.
 */
class IndexBloomFilter {
public:
    explicit IndexBloomFilter(size_t bitCount);
    
    void Add(uint64_t value) noexcept;
    [[nodiscard]] bool MightContain(uint64_t value) const noexcept;
    void Clear() noexcept;
    [[nodiscard]] size_t GetBitCount() const noexcept;
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    [[nodiscard]] double EstimateFalsePositiveRate(size_t numElements) const noexcept;
    
private:
    size_t m_bitCount;
    std::vector<uint64_t> m_data;
};

// ============================================================================
// IPv4 RADIX TREE
// ============================================================================

/**
 * @brief IPv4 radix tree for fast IP lookups with CIDR support
 */
class IPv4RadixTree {
public:
    IPv4RadixTree() = default;
    ~IPv4RadixTree() = default;
    
    IPv4RadixTree(const IPv4RadixTree&) = delete;
    IPv4RadixTree& operator=(const IPv4RadixTree&) = delete;
    IPv4RadixTree(IPv4RadixTree&&) = delete;
    IPv4RadixTree& operator=(IPv4RadixTree&&) = delete;
    
    bool Insert(const IPv4Address& addr, uint64_t entryId, uint64_t entryOffset) noexcept;
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> Lookup(const IPv4Address& addr) const noexcept;
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    bool Remove(const IPv4Address& addr) noexcept;
    [[nodiscard]] bool Contains(const IPv4Address& addr) const noexcept;
    
    template<typename Callback>
    void ForEach(Callback&& callback) const noexcept;
    
    [[nodiscard]] uint32_t GetHeight() const noexcept;
    void Clear() noexcept;
    
private:
    struct RadixNode {
        std::array<std::unique_ptr<RadixNode>, 256> children{};
        uint64_t entryId{0};
        uint64_t entryOffset{0};
        uint8_t prefixLength{32};
        bool isTerminal{false};
    };
    
    [[nodiscard]] uint32_t CalculateHeightRecursive(const RadixNode* node, uint32_t depth) const noexcept;
    
    RadixNode m_root;
    size_t m_entryCount{0};
    size_t m_nodeCount{1};
    mutable std::shared_mutex m_mutex;
};

// ============================================================================
// IPv6 PATRICIA TRIE
// ============================================================================

/**
 * @brief IPv6 patricia trie with path compression
 */
class IPv6PatriciaTrie {
public:
    IPv6PatriciaTrie() = default;
    ~IPv6PatriciaTrie() = default;
    
    IPv6PatriciaTrie(const IPv6PatriciaTrie&) = delete;
    IPv6PatriciaTrie& operator=(const IPv6PatriciaTrie&) = delete;
    IPv6PatriciaTrie(IPv6PatriciaTrie&&) = delete;
    IPv6PatriciaTrie& operator=(IPv6PatriciaTrie&&) = delete;
    
    bool Insert(const IPv6Address& addr, uint64_t entryId, uint64_t entryOffset) noexcept;
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> Lookup(const IPv6Address& addr) const noexcept;
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    bool Remove(const IPv6Address& addr) noexcept;
    [[nodiscard]] bool Contains(const IPv6Address& addr) const noexcept;
    
    template<typename Callback>
    void ForEach(Callback&& callback) const noexcept;
    
    [[nodiscard]] uint32_t GetHeight() const noexcept;
    void Clear() noexcept;
    
private:
    struct PatriciaNode {
        std::array<std::unique_ptr<PatriciaNode>, 2> children{};
        uint64_t entryId{0};
        uint64_t entryOffset{0};
        uint8_t prefixLength{128};
        bool isTerminal{false};
    };
    
    template<typename Callback>
    void ForEachRecursive(const PatriciaNode* node, Callback&& callback, uint32_t depth) const noexcept;
    
    [[nodiscard]] uint32_t CalculateHeightRecursive(const PatriciaNode* node, uint32_t depth) const noexcept;
    
    PatriciaNode m_root;
    size_t m_entryCount{0};
    size_t m_nodeCount{1};
    mutable std::shared_mutex m_mutex;
};

// ============================================================================
// DOMAIN SUFFIX TRIE
// ============================================================================

/**
 * @brief Suffix trie for domain name matching with wildcard support
 */
class DomainSuffixTrie {
public:
    DomainSuffixTrie() = default;
    ~DomainSuffixTrie() = default;
    
    DomainSuffixTrie(const DomainSuffixTrie&) = delete;
    DomainSuffixTrie& operator=(const DomainSuffixTrie&) = delete;
    DomainSuffixTrie(DomainSuffixTrie&&) = delete;
    DomainSuffixTrie& operator=(DomainSuffixTrie&&) = delete;
    
    bool Insert(std::string_view domain, uint64_t entryId, uint64_t entryOffset) noexcept;
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> Lookup(std::string_view domain) const noexcept;
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    bool Remove(std::string_view domain) noexcept;
    [[nodiscard]] bool Contains(std::string_view domain) const noexcept;
    
    template<typename Callback>
    void ForEach(Callback&& callback) const noexcept;
    
    [[nodiscard]] uint32_t GetHeight() const noexcept;
    void Clear() noexcept;
    
private:
    struct SuffixNode {
        std::unordered_map<std::string, std::unique_ptr<SuffixNode>> children;
        std::string label;
        uint64_t entryId{0};
        uint64_t entryOffset{0};
        bool isTerminal{false};
    };
    
    template<typename Callback>
    void ForEachRecursive(const SuffixNode* node, std::string& domain, Callback&& callback) const noexcept;
    
    [[nodiscard]] uint32_t CalculateHeightRecursive(const SuffixNode* node, uint32_t depth) const noexcept;
    
    SuffixNode m_root;
    size_t m_entryCount{0};
    size_t m_nodeCount{1};
    mutable std::shared_mutex m_mutex;
};

// ============================================================================
// EMAIL HASH TABLE
// ============================================================================

/**
 * @brief Hash table for email address lookups
 */
class EmailHashTable {
public:
    EmailHashTable() = default;
    ~EmailHashTable() = default;
    
    EmailHashTable(const EmailHashTable&) = delete;
    EmailHashTable& operator=(const EmailHashTable&) = delete;
    EmailHashTable(EmailHashTable&&) = delete;
    EmailHashTable& operator=(EmailHashTable&&) = delete;
    
    bool Insert(std::string_view email, uint64_t entryId, uint64_t entryOffset) noexcept;
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> Lookup(std::string_view email) const noexcept;
    [[nodiscard]] size_t GetEntryCount() const noexcept;
    [[nodiscard]] size_t GetMemoryUsage() const noexcept;
    bool Remove(std::string_view email) noexcept;
    [[nodiscard]] bool Contains(std::string_view email) const noexcept;
    
    template<typename Callback>
    void ForEach(Callback&& callback) const noexcept;
    
    [[nodiscard]] double GetLoadFactor() const noexcept;
    [[nodiscard]] size_t GetBucketCount() const noexcept;
    void Clear() noexcept;
    
private:
    std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> m_entries;
    size_t m_entryCount{0};
    mutable std::shared_mutex m_mutex;
};

} // namespace ThreatIntel
} // namespace ShadowStrike
