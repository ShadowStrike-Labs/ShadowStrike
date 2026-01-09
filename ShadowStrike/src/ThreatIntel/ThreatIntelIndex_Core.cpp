/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Core Operations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Core operations: Constructor, Destructor, Initialize, Shutdown, IsInitialized
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Calculate optimal bloom filter size
 */
[[nodiscard]] inline size_t CalculateBloomFilterSize(size_t expectedElements) noexcept {
    // Target 1% false positive rate
    // m = -n * ln(p) / (ln(2)^2)
    // For p = 0.01, m ≈ n * 9.6
    return expectedElements * IndexConfig::BLOOM_BITS_PER_ELEMENT;
}

// ============================================================================
// THREATINTELINDEX - PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

ThreatIntelIndex::ThreatIntelIndex()
    : m_impl(std::make_unique<Impl>()) {
}

ThreatIntelIndex::~ThreatIntelIndex() {
    Shutdown();
}

StoreError ThreatIntelIndex::Initialize(
    const MemoryMappedView& view,
    const ThreatIntelDatabaseHeader* header
) noexcept {
    return Initialize(view, header, IndexBuildOptions::Default());
}

StoreError ThreatIntelIndex::Initialize(
    const MemoryMappedView& view,
    const ThreatIntelDatabaseHeader* header,
    const IndexBuildOptions& options
) noexcept {
    std::lock_guard<std::shared_mutex> lock(m_rwLock);

    if (m_initialized.load(std::memory_order_acquire)) {
        return StoreError::WithMessage(
            ThreatIntelError::AlreadyInitialized,
            "Index already initialized"
        );
    }

    if (!view.IsValid() || header == nullptr) {
        return StoreError::WithMessage(
            ThreatIntelError::InvalidHeader,
            "Invalid memory-mapped view or header"
        );
    }

    // Verify header magic
    if (header->magic != THREATINTEL_DB_MAGIC) {
        return StoreError::WithMessage(
            ThreatIntelError::InvalidMagic,
            "Invalid database magic number"
        );
    }

    // Store view and header
    m_impl->view = &view;
    m_impl->header = header;
    m_impl->buildOptions = options;

    // Initialize index structures
    if (options.buildIPv4) {
        m_impl->ipv4Index = std::make_unique<IPv4RadixTree>();
    }

    if (options.buildIPv6) {
        m_impl->ipv6Index = std::make_unique<IPv6PatriciaTrie>();
    }

    if (options.buildDomain) {
        m_impl->domainIndex = std::make_unique<DomainSuffixTrie>();
    }

    if (options.buildURL) {
        m_impl->urlIndex = std::make_unique<URLPatternMatcher>();
    }

    if (options.buildEmail) {
        m_impl->emailIndex = std::make_unique<EmailHashTable>();
    }

    if (options.buildGeneric) {
        m_impl->genericIndex = std::make_unique<GenericBPlusTree>();
    }

    if (options.buildHash) {
        // Initialize hash indexes for each algorithm
        for (size_t i = 0; i < m_impl->hashIndexes.size(); ++i) {
            m_impl->hashIndexes[i] = std::make_unique<HashBPlusTree>(
                static_cast<HashAlgorithm>(i)
            );
        }
    }

    // Initialize bloom filters if enabled
    if (options.buildBloomFilters) {
        size_t bloomSize = CalculateBloomFilterSize(header->totalActiveEntries);

        if (options.buildIPv4) {
            m_impl->bloomFilters[IOCType::IPv4] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }

        if (options.buildIPv6) {
            m_impl->bloomFilters[IOCType::IPv6] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }

        if (options.buildDomain) {
            m_impl->bloomFilters[IOCType::Domain] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }

        if (options.buildURL) {
            m_impl->bloomFilters[IOCType::URL] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }

        if (options.buildHash) {
            m_impl->bloomFilters[IOCType::FileHash] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }

        if (options.buildEmail) {
            m_impl->bloomFilters[IOCType::Email] =
                std::make_unique<IndexBloomFilter>(bloomSize);
        }
    }

    m_initialized.store(true, std::memory_order_release);

    return StoreError::Success();
}

bool ThreatIntelIndex::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

void ThreatIntelIndex::Shutdown() noexcept {
    std::lock_guard<std::shared_mutex> lock(m_rwLock);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    // Clear all indexes
    m_impl->ipv4Index.reset();
    m_impl->ipv6Index.reset();
    m_impl->domainIndex.reset();
    m_impl->urlIndex.reset();
    m_impl->emailIndex.reset();
    m_impl->genericIndex.reset();

    for (auto& hashIndex : m_impl->hashIndexes) {
        hashIndex.reset();
    }

    m_impl->bloomFilters.clear();

    m_impl->view = nullptr;
    m_impl->header = nullptr;

    m_initialized.store(false, std::memory_order_release);
}

} // namespace ThreatIntel
} // namespace ShadowStrike
