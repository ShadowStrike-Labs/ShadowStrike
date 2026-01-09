/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Data Structures Implementation
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Implementation of:
 * - IndexBloomFilter: Probabilistic set membership testing
 * - IPv4RadixTree: 4-level hierarchical tree for IPv4 addresses
 * - IPv6PatriciaTrie: Patricia trie for 128-bit IPv6 addresses
 * - DomainSuffixTrie: Reverse-label trie for domain names
 * - EmailHashTable: Hash table for email addresses
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"
#include "ThreatIntelIndex_DataStructures.hpp"

#include <algorithm>
#include <cmath>
#include <span>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// LOCAL HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Split domain into labels (reversed for suffix matching)
 * Example: "www.example.com" -> ["com", "example", "www"]
 */
[[nodiscard]] std::vector<std::string_view> SplitDomainLabels(std::string_view domain) noexcept {
    std::vector<std::string_view> labels;
    labels.reserve(8);  // Most domains have < 8 labels
    
    size_t start = 0;
    while (start < domain.size()) {
        size_t end = domain.find('.', start);
        if (end == std::string_view::npos) {
            end = domain.size();
        }
        
        if (end > start) {
            labels.push_back(domain.substr(start, end - start));
        }
        
        start = end + 1;
    }
    
    // Reverse for suffix matching (TLD first)
    std::reverse(labels.begin(), labels.end());
    
    return labels;
}

/**
 * @brief Calculate optimal bloom filter size
 */
[[nodiscard]] inline size_t CalculateBloomFilterSize(size_t expectedElements, double falsePosRate) noexcept {
    // m = -n * ln(p) / (ln(2)^2)
    const double ln2sq = 0.480453013918201;  // ln(2)^2
    return static_cast<size_t>(
        std::ceil(-static_cast<double>(expectedElements) * std::log(falsePosRate) / ln2sq)
    );
}

/**
 * @brief Calculate optimal number of hash functions
 */
[[nodiscard]] inline uint32_t CalculateOptimalHashCount(size_t numBits, size_t expectedElements) noexcept {
    // k = (m/n) * ln(2)
    if (expectedElements == 0) return 1;
    const double k = (static_cast<double>(numBits) / expectedElements) * 0.693147181;  // ln(2)
    return std::max(1u, std::min(16u, static_cast<uint32_t>(std::round(k))));
}

/**
 * @brief Compute multiple hash values using double hashing
 */
[[nodiscard]] std::array<uint64_t, 16> ComputeBloomHashes(uint64_t value, uint32_t numHashes) noexcept {
    std::array<uint64_t, 16> hashes{};
    
    // Double hashing: h_i(x) = h1(x) + i * h2(x)
    const uint64_t h1 = value;
    const uint64_t h2 = value * 0x9E3779B97F4A7C15ULL;  // Golden ratio
    
    for (uint32_t i = 0; i < numHashes && i < 16; ++i) {
        hashes[i] = h1 + i * h2;
    }
    
    return hashes;
}

} // anonymous namespace

// ============================================================================
// INDEX BLOOM FILTER IMPLEMENTATION
// ============================================================================

IndexBloomFilter::IndexBloomFilter(uint64_t expectedElements, double falsePosRate) {
    m_numBits = CalculateBloomFilterSize(expectedElements, falsePosRate);
    m_numHashes = CalculateOptimalHashCount(m_numBits, expectedElements);
    
    // Round up to nearest 64-bit word
    const size_t numWords = (m_numBits + 63) / 64;
    m_bits.resize(numWords, 0);
}

IndexBloomFilter::IndexBloomFilter(IndexBloomFilter&& other) noexcept
    : m_bits(std::move(other.m_bits))
    , m_numBits(other.m_numBits)
    , m_numHashes(other.m_numHashes) {
    other.m_numBits = 0;
    other.m_numHashes = 0;
}

IndexBloomFilter& IndexBloomFilter::operator=(IndexBloomFilter&& other) noexcept {
    if (this != &other) {
        m_bits = std::move(other.m_bits);
        m_numBits = other.m_numBits;
        m_numHashes = other.m_numHashes;
        other.m_numBits = 0;
        other.m_numHashes = 0;
    }
    return *this;
}

void IndexBloomFilter::Add(const IOCEntry& entry) noexcept {
    // Compute hash from entry data
    const uint64_t hash = HashString(std::string_view(
        reinterpret_cast<const char*>(&entry), sizeof(entry)));
    Add(hash);
}

void IndexBloomFilter::Add(uint64_t hash) noexcept {
    if (m_numBits == 0) return;
    
    auto hashes = ComputeBloomHashes(hash, m_numHashes);
    
    for (uint32_t i = 0; i < m_numHashes; ++i) {
        const uint64_t bitIndex = hashes[i] % m_numBits;
        const size_t wordIndex = bitIndex / 64;
        const uint64_t bitMask = 1ULL << (bitIndex % 64);
        
        if (wordIndex < m_bits.size()) {
            m_bits[wordIndex] |= bitMask;
        }
    }
}

void IndexBloomFilter::BatchAdd(std::span<const IOCEntry> entries) noexcept {
    for (const auto& entry : entries) {
        Add(entry);
    }
}

bool IndexBloomFilter::MightContain(const IOCEntry& entry) const noexcept {
    const uint64_t hash = HashString(std::string_view(
        reinterpret_cast<const char*>(&entry), sizeof(entry)));
    return MightContain(hash);
}

bool IndexBloomFilter::MightContain(uint64_t hash) const noexcept {
    if (m_numBits == 0) return false;
    
    auto hashes = ComputeBloomHashes(hash, m_numHashes);
    
    for (uint32_t i = 0; i < m_numHashes; ++i) {
        const uint64_t bitIndex = hashes[i] % m_numBits;
        const size_t wordIndex = bitIndex / 64;
        const uint64_t bitMask = 1ULL << (bitIndex % 64);
        
        if (wordIndex >= m_bits.size() || !(m_bits[wordIndex] & bitMask)) {
            return false;  // Definitely not present
        }
    }
    
    return true;  // Probably present
}

void IndexBloomFilter::Clear() noexcept {
    std::fill(m_bits.begin(), m_bits.end(), 0);
}

double IndexBloomFilter::GetEstimatedFillRate() const noexcept {
    if (m_bits.empty()) return 0.0;
    
    size_t setBits = 0;
    for (const auto& word : m_bits) {
        setBits += __popcnt64(word);
    }
    
    return static_cast<double>(setBits) / m_numBits;
}

double IndexBloomFilter::GetEstimatedFalsePositiveRate() const noexcept {
    // p ≈ (1 - e^(-kn/m))^k
    const double fillRate = GetEstimatedFillRate();
    return std::pow(fillRate, m_numHashes);
}

// ============================================================================
// IPv4 RADIX TREE - NODE STRUCTURE
// ============================================================================

/**
 * @brief 4-level radix tree node for IPv4 addresses
 * 
 * Level 0: /8 prefixes (256 entries)
 * Level 1: /16 prefixes  
 * Level 2: /24 prefixes
 * Level 3: /32 individual addresses
 */
struct IPv4RadixTree::RadixNode {
    /// Child pointers (256 for each octet value)
    std::array<std::unique_ptr<RadixNode>, 256> children{};
    
    /// Entry value (valid if isTerminal)
    IndexValue value{};
    
    /// Is this a terminal node?
    bool isTerminal{ false };
    
    RadixNode() = default;
};

// ============================================================================
// IPv4 RADIX TREE IMPLEMENTATION
// ============================================================================

IPv4RadixTree::IPv4RadixTree()
    : m_root(std::make_unique<RadixNode>())
    , m_nodeCount(1)
    , m_height(0) {
}

IPv4RadixTree::~IPv4RadixTree() = default;

bool IPv4RadixTree::Insert(const IPv4Address& addr, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    RadixNode* node = m_root.get();
    const uint8_t* octets = addr.octets.data();
    
    // Navigate/create path through tree
    for (int level = 0; level < 4; ++level) {
        const uint8_t octet = octets[level];
        
        if (!node->children[octet]) {
            node->children[octet] = std::make_unique<RadixNode>();
            ++m_nodeCount;
            m_height = std::max(m_height, static_cast<uint32_t>(level + 1));
        }
        
        node = node->children[octet].get();
    }
    
    // Check for duplicate
    if (node->isTerminal) {
        // Update existing entry
        node->value = value;
        return true;
    }
    
    node->isTerminal = true;
    node->value = value;
    return true;
}

bool IPv4RadixTree::Lookup(const IPv4Address& addr, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    const RadixNode* node = m_root.get();
    const uint8_t* octets = addr.octets.data();
    
    for (int level = 0; level < 4; ++level) {
        const uint8_t octet = octets[level];
        
        if (!node->children[octet]) {
            return false;
        }
        
        node = node->children[octet].get();
    }
    
    if (node->isTerminal) {
        outValue = node->value;
        return true;
    }
    
    return false;
}

bool IPv4RadixTree::Contains(const IPv4Address& addr) const {
    IndexValue dummy;
    return Lookup(addr, dummy);
}

bool IPv4RadixTree::Remove(const IPv4Address& addr) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    RadixNode* node = m_root.get();
    const uint8_t* octets = addr.octets.data();
    
    for (int level = 0; level < 4; ++level) {
        const uint8_t octet = octets[level];
        
        if (!node->children[octet]) {
            return false;
        }
        
        node = node->children[octet].get();
    }
    
    if (node->isTerminal) {
        node->isTerminal = false;
        node->value = {};
        return true;
    }
    
    return false;
}

void IPv4RadixTree::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    m_root = std::make_unique<RadixNode>();
    m_nodeCount = 1;
    m_height = 0;
}

// ============================================================================
// IPv6 PATRICIA TRIE - NODE STRUCTURE
// ============================================================================

/**
 * @brief Patricia trie node for 128-bit IPv6 addresses
 * 
 * Uses bit-level prefix matching for compact representation
 */
struct IPv6PatriciaTrie::PatriciaNode {
    /// Prefix bit position (0-127)
    uint8_t bitPosition{ 0 };
    
    /// Left child (bit = 0)
    std::unique_ptr<PatriciaNode> left;
    
    /// Right child (bit = 1)
    std::unique_ptr<PatriciaNode> right;
    
    /// Full key for this node (if terminal)
    IPv6Address key{};
    
    /// Entry value (valid if isTerminal)
    IndexValue value{};
    
    /// Is this a terminal node?
    bool isTerminal{ false };
    
    PatriciaNode() = default;
};

// ============================================================================
// IPv6 PATRICIA TRIE IMPLEMENTATION
// ============================================================================

IPv6PatriciaTrie::IPv6PatriciaTrie()
    : m_root(std::make_unique<PatriciaNode>())
    , m_nodeCount(1)
    , m_height(0) {
}

IPv6PatriciaTrie::~IPv6PatriciaTrie() = default;

namespace {

// Get bit at position from IPv6 address (0 = MSB)
[[nodiscard]] inline bool GetBit(const IPv6Address& addr, uint8_t pos) noexcept {
    const uint8_t byteIdx = pos / 8;
    const uint8_t bitIdx = 7 - (pos % 8);  // MSB first
    return (addr.groups[byteIdx / 2] >> (8 * (1 - byteIdx % 2) + bitIdx)) & 1;
}

}// anonymous namespace

bool IPv6PatriciaTrie::Insert(const IPv6Address& addr, const IndexValue& value) {
    // Thread-safety: Write lock for modification
    std::unique_lock<std::shared_mutex> lock(m_mutex);

    if (!m_root) {
        m_root = std::make_unique<PatriciaNode>();
    }

    PatriciaNode* curr = m_root.get();

    // Navigate bit by bit (128 bits for IPv6)
    for (uint8_t bit = 0; bit < 128; ++bit) {
        const bool bitValue = GetBit(addr, bit);

        // Get reference to the unique_ptr itself
        std::unique_ptr<PatriciaNode>& childRef = bitValue ? curr->right : curr->left;

        if (!childRef) {
            // Create new terminal node if path doesn't exist
            childRef = std::make_unique<PatriciaNode>();
            childRef->bitPosition = bit;
            childRef->key = addr;
            childRef->value = value;
            childRef->isTerminal = true;

            ++m_nodeCount;
            m_height = std::max(m_height, static_cast<uint32_t>(bit + 1));
            return true;
        }

        // Move to context
        curr = childRef.get();

        // If we found an existing terminal node with the same key, update it
        if (curr->isTerminal) {
            // Safely compare the 16-byte address array
            if (std::memcmp(curr->key.address.data(), addr.address.data(), 16) == 0) {
                curr->value = value; // Update performance statistics or entry ID
                return true;
            }
        }
    }

    return false;
}
bool IPv6PatriciaTrie::Lookup(const IPv6Address& addr, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    const PatriciaNode* node = m_root.get();
    
    for (uint8_t bit = 0; bit < 128 && node; ++bit) {
        const bool bitValue = GetBit(addr, bit);
        node = bitValue ? node->right.get() : node->left.get();
        
        if (node && node->isTerminal && std::memcmp(&node->key, &addr, sizeof(addr)) == 0) {
            outValue = node->value;
            return true;
        }
    }
    
    return false;
}

bool IPv6PatriciaTrie::Contains(const IPv6Address& addr) const {
    IndexValue dummy;
    return Lookup(addr, dummy);
}

bool IPv6PatriciaTrie::Remove(const IPv6Address& addr) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    PatriciaNode* node = m_root.get();
    
    for (uint8_t bit = 0; bit < 128 && node; ++bit) {
        const bool bitValue = GetBit(addr, bit);
        node = bitValue ? node->right.get() : node->left.get();
        
        if (node && node->isTerminal && std::memcmp(&node->key, &addr, sizeof(addr)) == 0) {
            node->isTerminal = false;
            node->value = {};
            return true;
        }
    }
    
    return false;
}

void IPv6PatriciaTrie::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    m_root = std::make_unique<PatriciaNode>();
    m_nodeCount = 1;
    m_height = 0;
}

// ============================================================================
// DOMAIN SUFFIX TRIE - NODE STRUCTURE
// ============================================================================

/**
 * @brief Trie node for domain suffix matching
 * 
 * Stores domains in reverse label order for efficient suffix matching.
 * Example: "www.example.com" stored as ["com"]["example"]["www"]
 */
struct DomainSuffixTrie::TrieNode {
    /// Children indexed by label hash
    std::unordered_map<std::string, std::unique_ptr<TrieNode>> children;
    
    /// Entry value (valid if isTerminal)
    IndexValue value{};
    
    /// Is this a terminal node?
    bool isTerminal{ false };
    
    TrieNode() = default;
};

// ============================================================================
// DOMAIN SUFFIX TRIE IMPLEMENTATION
// ============================================================================

DomainSuffixTrie::DomainSuffixTrie()
    : m_root(std::make_unique<TrieNode>())
    , m_nodeCount(1)
    , m_height(0) {
}

DomainSuffixTrie::~DomainSuffixTrie() = default;

bool DomainSuffixTrie::Insert(std::string_view domain, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    // Normalize domain
    const std::string normalized = NormalizeDomain(domain);
    if (normalized.empty()) {
        return false;
    }
    
    // Split into labels (reversed)
    auto labels = SplitDomainLabels(normalized);
    if (labels.empty()) {
        return false;
    }
    
    TrieNode* node = m_root.get();
    
    for (size_t i = 0; i < labels.size(); ++i) {
        const std::string label(labels[i]);
        
        auto it = node->children.find(label);
        if (it == node->children.end()) {
            auto [newIt, _] = node->children.emplace(label, std::make_unique<TrieNode>());
            ++m_nodeCount;
            m_height = std::max(m_height, static_cast<uint32_t>(i + 1));
            node = newIt->second.get();
        } else {
            node = it->second.get();
        }
    }
    
    node->isTerminal = true;
    node->value = value;
    return true;
}

bool DomainSuffixTrie::Lookup(std::string_view domain, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    const std::string normalized = NormalizeDomain(domain);
    if (normalized.empty()) {
        return false;
    }
    
    auto labels = SplitDomainLabels(normalized);
    if (labels.empty()) {
        return false;
    }
    
    const TrieNode* node = m_root.get();
    
    for (const auto& label : labels) {
        const std::string labelStr(label);
        auto it = node->children.find(labelStr);
        if (it == node->children.end()) {
            return false;
        }
        node = it->second.get();
    }
    
    if (node->isTerminal) {
        outValue = node->value;
        return true;
    }
    
    return false;
}

bool DomainSuffixTrie::Contains(std::string_view domain) const {
    IndexValue dummy;
    return Lookup(domain, dummy);
}

bool DomainSuffixTrie::Remove(std::string_view domain) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    const std::string normalized = NormalizeDomain(domain);
    if (normalized.empty()) {
        return false;
    }
    
    auto labels = SplitDomainLabels(normalized);
    if (labels.empty()) {
        return false;
    }
    
    TrieNode* node = m_root.get();
    
    for (const auto& label : labels) {
        const std::string labelStr(label);
        auto it = node->children.find(labelStr);
        if (it == node->children.end()) {
            return false;
        }
        node = it->second.get();
    }
    
    if (node->isTerminal) {
        node->isTerminal = false;
        node->value = {};
        return true;
    }
    
    return false;
}

void DomainSuffixTrie::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    m_root = std::make_unique<TrieNode>();
    m_nodeCount = 1;
    m_height = 0;
}

// ============================================================================
// EMAIL HASH TABLE IMPLEMENTATION
// ============================================================================

EmailHashTable::EmailHashTable(size_t initialCapacity) {
    m_entries.reserve(initialCapacity);
}

bool EmailHashTable::Insert(std::string_view email, const IndexValue& value) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (email.empty()) {
        return false;
    }
    
    // Normalize email (lowercase)
    std::string normalized;
    normalized.reserve(email.size());
    for (char c : email) {
        if (c >= 'A' && c <= 'Z') {
            normalized.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            normalized.push_back(c);
        }
    }
    
    auto [it, inserted] = m_entries.try_emplace(std::move(normalized), value);
    if (!inserted) {
        // Update existing
        it->second = value;
    }
    
    return true;
}

bool EmailHashTable::Lookup(std::string_view email, IndexValue& outValue) const {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    
    if (email.empty()) {
        return false;
    }
    
    // Normalize email
    std::string normalized;
    normalized.reserve(email.size());
    for (char c : email) {
        if (c >= 'A' && c <= 'Z') {
            normalized.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            normalized.push_back(c);
        }
    }
    
    auto it = m_entries.find(normalized);
    if (it != m_entries.end()) {
        outValue = it->second;
        return true;
    }
    
    return false;
}

bool EmailHashTable::Contains(std::string_view email) const {
    IndexValue dummy;
    return Lookup(email, dummy);
}

bool EmailHashTable::Remove(std::string_view email) {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    
    if (email.empty()) {
        return false;
    }
    
    // Normalize email
    std::string normalized;
    normalized.reserve(email.size());
    for (char c : email) {
        if (c >= 'A' && c <= 'Z') {
            normalized.push_back(static_cast<char>(c + ('a' - 'A')));
        } else {
            normalized.push_back(c);
        }
    }
    
    return m_entries.erase(normalized) > 0;
}

void EmailHashTable::Clear() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    m_entries.clear();
}

double EmailHashTable::GetLoadFactor() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    return m_entries.load_factor();
}

// ============================================================================
// INDEX STATISTICS IMPLEMENTATION
// ============================================================================
/**
 * @brief Copy constructor for IndexStatistics (handles atomic members)
 */
IndexStatistics::IndexStatistics(const IndexStatistics& other) noexcept
    : ipv4Entries(other.ipv4Entries)
    , ipv6Entries(other.ipv6Entries)
    , domainEntries(other.domainEntries)
    , urlEntries(other.urlEntries)
    , hashEntries(other.hashEntries)
    , emailEntries(other.emailEntries)
    , otherEntries(other.otherEntries)
    , totalEntries(other.totalEntries)
    , ipv4MemoryBytes(other.ipv4MemoryBytes)
    , ipv6MemoryBytes(other.ipv6MemoryBytes)
    , domainMemoryBytes(other.domainMemoryBytes)
    , urlMemoryBytes(other.urlMemoryBytes)
    , hashMemoryBytes(other.hashMemoryBytes)
    , emailMemoryBytes(other.emailMemoryBytes)
    , otherMemoryBytes(other.otherMemoryBytes)
    , bloomFilterBytes(other.bloomFilterBytes)
    , totalMemoryBytes(other.totalMemoryBytes)
    , totalLookups(other.totalLookups.load(std::memory_order_relaxed))
    , successfulLookups(other.successfulLookups.load(std::memory_order_relaxed))
    , failedLookups(other.failedLookups.load(std::memory_order_relaxed))
    , bloomFilterChecks(other.bloomFilterChecks.load(std::memory_order_relaxed))
    , bloomFilterRejects(other.bloomFilterRejects.load(std::memory_order_relaxed))
    , bloomFilterFalsePositives(other.bloomFilterFalsePositives.load(std::memory_order_relaxed))
    , cacheHits(other.cacheHits.load(std::memory_order_relaxed))
    , cacheMisses(other.cacheMisses.load(std::memory_order_relaxed))
    , totalLookupTimeNs(other.totalLookupTimeNs.load(std::memory_order_relaxed))
    , minLookupTimeNs(other.minLookupTimeNs.load(std::memory_order_relaxed))
    , maxLookupTimeNs(other.maxLookupTimeNs.load(std::memory_order_relaxed))
    , avgIPv4LookupNs(other.avgIPv4LookupNs)
    , avgIPv6LookupNs(other.avgIPv6LookupNs)
    , avgDomainLookupNs(other.avgDomainLookupNs)
    , avgURLLookupNs(other.avgURLLookupNs)
    , avgHashLookupNs(other.avgHashLookupNs)
    , avgEmailLookupNs(other.avgEmailLookupNs)
    , ipv4TreeHeight(other.ipv4TreeHeight)
    , ipv4TreeNodes(other.ipv4TreeNodes)
    , ipv4AvgFillRate(other.ipv4AvgFillRate)
    , ipv6TreeHeight(other.ipv6TreeHeight)
    , ipv6TreeNodes(other.ipv6TreeNodes)
    , ipv6CompressionRatio(other.ipv6CompressionRatio)
    , domainTrieHeight(other.domainTrieHeight)
    , domainTrieNodes(other.domainTrieNodes)
    , domainHashBuckets(other.domainHashBuckets)
    , hashTreeHeight(other.hashTreeHeight)
    , hashTreeNodes(other.hashTreeNodes)
    , hashTreeFillRate(other.hashTreeFillRate)
    , urlPatternCount(other.urlPatternCount)
    , urlStateMachineStates(other.urlStateMachineStates)
    , emailHashBuckets(other.emailHashBuckets)
    , emailLoadFactor(other.emailLoadFactor)
    , emailCollisions(other.emailCollisions)
    , totalInsertions(other.totalInsertions.load(std::memory_order_relaxed))
    , totalDeletions(other.totalDeletions.load(std::memory_order_relaxed))
    , totalUpdates(other.totalUpdates.load(std::memory_order_relaxed))
    , cowTransactions(other.cowTransactions.load(std::memory_order_relaxed))
    , indexRebuilds(other.indexRebuilds.load(std::memory_order_relaxed)) {
}

/**
 * @brief Copy assignment operator for IndexStatistics
 */
IndexStatistics& IndexStatistics::operator=(const IndexStatistics& other) noexcept {
    if (this != &other) {
        ipv4Entries = other.ipv4Entries;
        ipv6Entries = other.ipv6Entries;
        domainEntries = other.domainEntries;
        urlEntries = other.urlEntries;
        hashEntries = other.hashEntries;
        emailEntries = other.emailEntries;
        otherEntries = other.otherEntries;
        totalEntries = other.totalEntries;
        ipv4MemoryBytes = other.ipv4MemoryBytes;
        ipv6MemoryBytes = other.ipv6MemoryBytes;
        domainMemoryBytes = other.domainMemoryBytes;
        urlMemoryBytes = other.urlMemoryBytes;
        hashMemoryBytes = other.hashMemoryBytes;
        emailMemoryBytes = other.emailMemoryBytes;
        otherMemoryBytes = other.otherMemoryBytes;
        bloomFilterBytes = other.bloomFilterBytes;
        totalMemoryBytes = other.totalMemoryBytes;

        // Atomic operations
        totalLookups.store(other.totalLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        successfulLookups.store(other.successfulLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        failedLookups.store(other.failedLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
        bloomFilterChecks.store(other.bloomFilterChecks.load(std::memory_order_relaxed), std::memory_order_relaxed);
        bloomFilterRejects.store(other.bloomFilterRejects.load(std::memory_order_relaxed), std::memory_order_relaxed);
        bloomFilterFalsePositives.store(other.bloomFilterFalsePositives.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheHits.store(other.cacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheMisses.store(other.cacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalLookupTimeNs.store(other.totalLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);
        minLookupTimeNs.store(other.minLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);
        maxLookupTimeNs.store(other.maxLookupTimeNs.load(std::memory_order_relaxed), std::memory_order_relaxed);

        avgIPv4LookupNs = other.avgIPv4LookupNs;
        avgIPv6LookupNs = other.avgIPv6LookupNs;
        avgDomainLookupNs = other.avgDomainLookupNs;
        avgURLLookupNs = other.avgURLLookupNs;
        avgHashLookupNs = other.avgHashLookupNs;
        avgEmailLookupNs = other.avgEmailLookupNs;

        ipv4TreeHeight = other.ipv4TreeHeight;
        ipv4TreeNodes = other.ipv4TreeNodes;
        ipv4AvgFillRate = other.ipv4AvgFillRate;
        ipv6TreeHeight = other.ipv6TreeHeight;
        ipv6TreeNodes = other.ipv6TreeNodes;
        ipv6CompressionRatio = other.ipv6CompressionRatio;
        domainTrieHeight = other.domainTrieHeight;
        domainTrieNodes = other.domainTrieNodes;
        domainHashBuckets = other.domainHashBuckets;

        hashTreeHeight = other.hashTreeHeight;
        hashTreeNodes = other.hashTreeNodes;
        hashTreeFillRate = other.hashTreeFillRate;

        urlPatternCount = other.urlPatternCount;
        urlStateMachineStates = other.urlStateMachineStates;

        emailHashBuckets = other.emailHashBuckets;
        emailLoadFactor = other.emailLoadFactor;
        emailCollisions = other.emailCollisions;

        totalInsertions.store(other.totalInsertions.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalDeletions.store(other.totalDeletions.load(std::memory_order_relaxed), std::memory_order_relaxed);
        totalUpdates.store(other.totalUpdates.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cowTransactions.store(other.cowTransactions.load(std::memory_order_relaxed), std::memory_order_relaxed);
        indexRebuilds.store(other.indexRebuilds.load(std::memory_order_relaxed), std::memory_order_relaxed);
    }
    return *this;
}
} // namespace ThreatIntel
} // namespace ShadowStrike
