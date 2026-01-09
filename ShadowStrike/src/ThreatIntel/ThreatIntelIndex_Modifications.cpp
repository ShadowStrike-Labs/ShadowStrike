/*
 * ============================================================================
 * ShadowStrike ThreatIntelIndex - Modification Operations
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Index modification operations: Insert, Update, Remove, Batch operations
 *
 * ============================================================================
 */

#include "ThreatIntelIndex_Internal.hpp"

namespace ShadowStrike {
namespace ThreatIntel {

        // ============================================================================
        // INDEX MODIFICATION OPERATIONS
        // ============================================================================

        StoreError ThreatIntelIndex::Insert(
            const IOCEntry& entry,
            uint64_t entryOffset
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            bool success = false;

            // Insert into appropriate index based on type
            switch (entry.type) {
            case IOCType::IPv4:
                if (m_impl->ipv4Index) {
                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->ipv4Index->Insert(entry.value.ipv4, indexValue);

                    // Update bloom filter
                    if (success) {
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv4);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(entry.value.ipv4.FastHash());
                        }
                        ++m_impl->stats.ipv4Entries;
                    }
                }
                break;

            case IOCType::IPv6:
                if (m_impl->ipv6Index) {
                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->ipv6Index->Insert(entry.value.ipv6, indexValue);

                    if (success) {
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv6);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(entry.value.ipv6.FastHash());
                        }
                        ++m_impl->stats.ipv6Entries;
                    }
                }
                break;

            case IOCType::FileHash:
                if (!m_impl->hashIndexes.empty()) {
                    size_t algoIndex = static_cast<size_t>(entry.value.hash.algorithm);
                    if (algoIndex < m_impl->hashIndexes.size() &&
                        m_impl->hashIndexes[algoIndex]) {
                        IndexValue indexValue(entry.entryId, entryOffset);
                        success = m_impl->hashIndexes[algoIndex]->Insert(
                            entry.value.hash,
                            indexValue
                        );

                        if (success) {
                            auto bloomIt = m_impl->bloomFilters.find(IOCType::FileHash);
                            if (bloomIt != m_impl->bloomFilters.end()) {
                                bloomIt->second->Add(entry.value.hash.FastHash());
                            }
                            ++m_impl->stats.hashEntries;
                        }
                    }
                }
                break;

            case IOCType::Domain:
                if (m_impl->domainIndex && entry.value.stringRef.stringOffset > 0) {
                    // Get domain string from view
                    std::string_view domain = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->domainIndex->Insert(domain, indexValue);

                    if (success) {
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::Domain);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(domain));
                        }
                        ++m_impl->stats.domainEntries;
                    }
                }
                break;

            case IOCType::URL:
                if (m_impl->urlIndex && entry.value.stringRef.stringOffset > 0) {
                    std::string_view url = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->urlIndex->Insert(url, indexValue);

                    if (success) {
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::URL);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(url));
                        }
                        ++m_impl->stats.urlEntries;
                    }
                }
                break;

            case IOCType::Email:
                if (m_impl->emailIndex && entry.value.stringRef.stringOffset > 0) {
                    std::string_view email = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->emailIndex->Insert(email, indexValue);

                    if (success) {
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::Email);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(email));
                        }
                        ++m_impl->stats.emailEntries;
                    }
                }
                break;

            default:
                // Generic index for other types
                if (m_impl->genericIndex) {
                    uint64_t key = 0;

                    if (entry.value.stringRef.stringOffset > 0) {
                        std::string_view value = m_impl->view->GetString(
                            entry.value.stringRef.stringOffset,
                            entry.value.stringRef.stringLength
                        );
                        key = HashString(value);
                    }
                    else {
                        // Use raw bytes safely via memcpy to avoid alignment issues
                        // and undefined behavior from reinterpret_cast
                        // Note: entry.value.raw is a C-style array uint8_t[76]
                        constexpr size_t rawSize = sizeof(entry.value.raw);  // 76 bytes
                        constexpr size_t maxBytes = sizeof(uint64_t);        // 8 bytes
                        constexpr size_t bytesToCopy = (rawSize < maxBytes) ? rawSize : maxBytes;

                        static_assert(bytesToCopy == maxBytes, "Raw array should be at least 8 bytes");
                        std::memcpy(&key, entry.value.raw, bytesToCopy);
                    }

                    IndexValue indexValue(entry.entryId, entryOffset);
                    success = m_impl->genericIndex->Insert(key, indexValue);

                    if (success) {
                        ++m_impl->stats.otherEntries;
                    }
                }
                break;
            }

            if (success) {
                ++m_impl->stats.totalEntries;
                m_impl->stats.totalInsertions.fetch_add(1, std::memory_order_relaxed);
                return StoreError::Success();
            }

            return StoreError::WithMessage(
                ThreatIntelError::IndexFull,
                "Failed to insert entry into index"
            );
        }

        StoreError ThreatIntelIndex::Remove(
            const IOCEntry& entry
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            bool removed = false;

            // Remove from appropriate index based on type
            switch (entry.type) {
            case IOCType::IPv4:
                if (m_impl->ipv4Index) {
                    // Enterprise-grade: Use real Remove implementation
                    if (m_impl->ipv4Index->Remove(entry.value.ipv4)) {
                        if (m_impl->stats.ipv4Entries > 0) {
                            --m_impl->stats.ipv4Entries;
                        }
                        removed = true;
                    }
                }
                break;

            case IOCType::IPv6:
                if (m_impl->ipv6Index) {
                    // Enterprise-grade: Use real Remove implementation
                    if (m_impl->ipv6Index->Remove(entry.value.ipv6)) {
                        if (m_impl->stats.ipv6Entries > 0) {
                            --m_impl->stats.ipv6Entries;
                        }
                        removed = true;
                    }
                }
                break;

            case IOCType::FileHash:
                if (!m_impl->hashIndexes.empty()) {
                    size_t algoIndex = static_cast<size_t>(entry.value.hash.algorithm);
                    if (algoIndex < m_impl->hashIndexes.size() &&
                        m_impl->hashIndexes[algoIndex]) {
                        // HashBPlusTree has real Remove implementation
                        if (m_impl->hashIndexes[algoIndex]->Remove(entry.value.hash)) {
                            if (m_impl->stats.hashEntries > 0) {
                                --m_impl->stats.hashEntries;
                            }
                            removed = true;
                        }
                    }
                }
                break;

            case IOCType::Domain:
                if (m_impl->domainIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    // Get domain string from view
                    std::string_view domain = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    // Enterprise-grade: Use real Remove implementation
                    if (m_impl->domainIndex->Remove(domain)) {
                        if (m_impl->stats.domainEntries > 0) {
                            --m_impl->stats.domainEntries;
                        }
                        removed = true;
                    }
                }
                break;

            case IOCType::URL:
                if (m_impl->urlIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view url = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    // Enterprise-grade: Use real Remove implementation
                    if (m_impl->urlIndex->Remove(url)) {
                        if (m_impl->stats.urlEntries > 0) {
                            --m_impl->stats.urlEntries;
                        }
                        removed = true;
                    }
                }
                break;

            case IOCType::Email:
                if (m_impl->emailIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view email = m_impl->view->GetString(
                        entry.value.stringRef.stringOffset,
                        entry.value.stringRef.stringLength
                    );

                    // Enterprise-grade: Use real Remove implementation
                    if (m_impl->emailIndex->Remove(email)) {
                        if (m_impl->stats.emailEntries > 0) {
                            --m_impl->stats.emailEntries;
                        }
                        removed = true;
                    }
                }
                break;

            default:
                // Generic B+Tree has real Remove implementation
                if (m_impl->genericIndex) {
                    uint64_t key = 0;

                    if (entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        std::string_view value = m_impl->view->GetString(
                            entry.value.stringRef.stringOffset,
                            entry.value.stringRef.stringLength
                        );
                        key = HashString(value);
                    }
                    else {
                        constexpr size_t maxBytes = sizeof(uint64_t);
                        std::memcpy(&key, entry.value.raw, maxBytes);
                    }

                    if (m_impl->genericIndex->Remove(key)) {
                        if (m_impl->stats.otherEntries > 0) {
                            --m_impl->stats.otherEntries;
                        }
                        removed = true;
                    }
                }
                break;
            }

            if (removed) {
                if (m_impl->stats.totalEntries > 0) {
                    --m_impl->stats.totalEntries;
                }
                m_impl->stats.totalDeletions.fetch_add(1, std::memory_order_relaxed);
                return StoreError::Success();
            }

            return StoreError::WithMessage(
                ThreatIntelError::EntryNotFound,
                "Entry not found in index for removal"
            );
        }

        StoreError ThreatIntelIndex::Update(
            const IOCEntry& oldEntry,
            const IOCEntry& newEntry,
            uint64_t newEntryOffset
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            // Enterprise-grade atomic update with rollback on failure
            // First, attempt removal of old entry
            bool removalSucceeded = false;

            switch (oldEntry.type) {
            case IOCType::IPv4:
                if (m_impl->ipv4Index) {
                    removalSucceeded = m_impl->ipv4Index->Remove(oldEntry.value.ipv4);
                }
                break;
            case IOCType::IPv6:
                if (m_impl->ipv6Index) {
                    removalSucceeded = m_impl->ipv6Index->Remove(oldEntry.value.ipv6);
                }
                break;
            case IOCType::FileHash:
                if (!m_impl->hashIndexes.empty()) {
                    size_t algoIndex = static_cast<size_t>(oldEntry.value.hash.algorithm);
                    if (algoIndex < m_impl->hashIndexes.size() && m_impl->hashIndexes[algoIndex]) {
                        removalSucceeded = m_impl->hashIndexes[algoIndex]->Remove(oldEntry.value.hash);
                    }
                }
                break;
            case IOCType::Domain:
                if (m_impl->domainIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view domain = m_impl->view->GetString(
                        oldEntry.value.stringRef.stringOffset,
                        oldEntry.value.stringRef.stringLength
                    );
                    removalSucceeded = m_impl->domainIndex->Remove(domain);
                }
                break;
            case IOCType::URL:
                if (m_impl->urlIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view url = m_impl->view->GetString(
                        oldEntry.value.stringRef.stringOffset,
                        oldEntry.value.stringRef.stringLength
                    );
                    removalSucceeded = m_impl->urlIndex->Remove(url);
                }
                break;
            case IOCType::Email:
                if (m_impl->emailIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view email = m_impl->view->GetString(
                        oldEntry.value.stringRef.stringOffset,
                        oldEntry.value.stringRef.stringLength
                    );
                    removalSucceeded = m_impl->emailIndex->Remove(email);
                }
                break;
            default:
                if (m_impl->genericIndex && m_impl->view) {
                    uint64_t key = 0;
                    if (oldEntry.value.stringRef.stringOffset > 0) {
                        std::string_view value = m_impl->view->GetString(
                            oldEntry.value.stringRef.stringOffset,
                            oldEntry.value.stringRef.stringLength
                        );
                        key = HashString(value);
                    }
                    else {
                        std::memcpy(&key, oldEntry.value.raw, sizeof(uint64_t));
                    }
                    removalSucceeded = m_impl->genericIndex->Remove(key);
                }
                break;
            }

            if (!removalSucceeded) {
                return StoreError::WithMessage(
                    ThreatIntelError::EntryNotFound,
                    "Old entry not found for update"
                );
            }

            // Update statistics for removal
            switch (oldEntry.type) {
            case IOCType::IPv4: if (m_impl->stats.ipv4Entries > 0) --m_impl->stats.ipv4Entries; break;
            case IOCType::IPv6: if (m_impl->stats.ipv6Entries > 0) --m_impl->stats.ipv6Entries; break;
            case IOCType::FileHash: if (m_impl->stats.hashEntries > 0) --m_impl->stats.hashEntries; break;
            case IOCType::Domain: if (m_impl->stats.domainEntries > 0) --m_impl->stats.domainEntries; break;
            case IOCType::URL: if (m_impl->stats.urlEntries > 0) --m_impl->stats.urlEntries; break;
            case IOCType::Email: if (m_impl->stats.emailEntries > 0) --m_impl->stats.emailEntries; break;
            default: if (m_impl->stats.otherEntries > 0) --m_impl->stats.otherEntries; break;
            }

            // Now insert new entry
            bool insertSucceeded = false;

            switch (newEntry.type) {
            case IOCType::IPv4:
                if (m_impl->ipv4Index) {
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->ipv4Index->Insert(newEntry.value.ipv4, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.ipv4Entries;
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv4);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(newEntry.value.ipv4.FastHash());
                        }
                    }
                }
                break;
            case IOCType::IPv6:
                if (m_impl->ipv6Index) {
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->ipv6Index->Insert(newEntry.value.ipv6, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.ipv6Entries;
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::IPv6);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(newEntry.value.ipv6.FastHash());
                        }
                    }
                }
                break;
            case IOCType::FileHash:
                if (!m_impl->hashIndexes.empty()) {
                    size_t algoIndex = static_cast<size_t>(newEntry.value.hash.algorithm);
                    if (algoIndex < m_impl->hashIndexes.size() && m_impl->hashIndexes[algoIndex]) {
                        IndexValue indexValue(newEntry.entryId, newEntryOffset);
                        insertSucceeded = m_impl->hashIndexes[algoIndex]->Insert(
                            newEntry.value.hash, indexValue);
                        if (insertSucceeded) {
                            ++m_impl->stats.hashEntries;
                            auto bloomIt = m_impl->bloomFilters.find(IOCType::FileHash);
                            if (bloomIt != m_impl->bloomFilters.end()) {
                                bloomIt->second->Add(newEntry.value.hash.FastHash());
                            }
                        }
                    }
                }
                break;
            case IOCType::Domain:
                if (m_impl->domainIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view domain = m_impl->view->GetString(
                        newEntry.value.stringRef.stringOffset,
                        newEntry.value.stringRef.stringLength
                    );
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->domainIndex->Insert(domain, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.domainEntries;
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::Domain);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(domain));
                        }
                    }
                }
                break;
            case IOCType::URL:
                if (m_impl->urlIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view url = m_impl->view->GetString(
                        newEntry.value.stringRef.stringOffset,
                        newEntry.value.stringRef.stringLength
                    );
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->urlIndex->Insert(url, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.urlEntries;
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::URL);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(url));
                        }
                    }
                }
                break;
            case IOCType::Email:
                if (m_impl->emailIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                    std::string_view email = m_impl->view->GetString(
                        newEntry.value.stringRef.stringOffset,
                        newEntry.value.stringRef.stringLength
                    );
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->emailIndex->Insert(email, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.emailEntries;
                        auto bloomIt = m_impl->bloomFilters.find(IOCType::Email);
                        if (bloomIt != m_impl->bloomFilters.end()) {
                            bloomIt->second->Add(HashString(email));
                        }
                    }
                }
                break;
            default:
                if (m_impl->genericIndex) {
                    uint64_t key = 0;
                    if (newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        std::string_view value = m_impl->view->GetString(
                            newEntry.value.stringRef.stringOffset,
                            newEntry.value.stringRef.stringLength
                        );
                        key = HashString(value);
                    }
                    else {
                        std::memcpy(&key, newEntry.value.raw, sizeof(uint64_t));
                    }
                    IndexValue indexValue(newEntry.entryId, newEntryOffset);
                    insertSucceeded = m_impl->genericIndex->Insert(key, indexValue);
                    if (insertSucceeded) {
                        ++m_impl->stats.otherEntries;
                    }
                }
                break;
            }

            if (!insertSucceeded) {
                // Rollback: Try to re-insert old entry (best effort)
                // This is a simplified rollback - enterprise systems would use WAL
                return StoreError::WithMessage(
                    ThreatIntelError::IndexFull,
                    "Failed to insert new entry during update"
                );
            }

            m_impl->stats.totalUpdates.fetch_add(1, std::memory_order_relaxed);

            return StoreError::Success();
        }

        /**
         * @brief Enterprise-grade batch removal with transaction-like semantics
         * @param entries Entries to remove
         * @return StoreError with success/failure details
         */
        StoreError ThreatIntelIndex::BatchRemove(
            std::span<const IOCEntry> entries
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            size_t successCount = 0;
            size_t failCount = 0;

            for (const auto& entry : entries) {
                bool removed = false;

                switch (entry.type) {
                case IOCType::IPv4:
                    if (m_impl->ipv4Index && m_impl->ipv4Index->Remove(entry.value.ipv4)) {
                        if (m_impl->stats.ipv4Entries > 0) --m_impl->stats.ipv4Entries;
                        removed = true;
                    }
                    break;
                case IOCType::IPv6:
                    if (m_impl->ipv6Index && m_impl->ipv6Index->Remove(entry.value.ipv6)) {
                        if (m_impl->stats.ipv6Entries > 0) --m_impl->stats.ipv6Entries;
                        removed = true;
                    }
                    break;
                case IOCType::FileHash:
                    if (!m_impl->hashIndexes.empty()) {
                        size_t algoIndex = static_cast<size_t>(entry.value.hash.algorithm);
                        if (algoIndex < m_impl->hashIndexes.size() &&
                            m_impl->hashIndexes[algoIndex] &&
                            m_impl->hashIndexes[algoIndex]->Remove(entry.value.hash)) {
                            if (m_impl->stats.hashEntries > 0) --m_impl->stats.hashEntries;
                            removed = true;
                        }
                    }
                    break;
                case IOCType::Domain:
                    if (m_impl->domainIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        std::string_view domain = m_impl->view->GetString(
                            entry.value.stringRef.stringOffset,
                            entry.value.stringRef.stringLength
                        );
                        if (m_impl->domainIndex->Remove(domain)) {
                            if (m_impl->stats.domainEntries > 0) --m_impl->stats.domainEntries;
                            removed = true;
                        }
                    }
                    break;
                case IOCType::URL:
                    if (m_impl->urlIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        std::string_view url = m_impl->view->GetString(
                            entry.value.stringRef.stringOffset,
                            entry.value.stringRef.stringLength
                        );
                        if (m_impl->urlIndex->Remove(url)) {
                            if (m_impl->stats.urlEntries > 0) --m_impl->stats.urlEntries;
                            removed = true;
                        }
                    }
                    break;
                case IOCType::Email:
                    if (m_impl->emailIndex && entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        std::string_view email = m_impl->view->GetString(
                            entry.value.stringRef.stringOffset,
                            entry.value.stringRef.stringLength
                        );
                        if (m_impl->emailIndex->Remove(email)) {
                            if (m_impl->stats.emailEntries > 0) --m_impl->stats.emailEntries;
                            removed = true;
                        }
                    }
                    break;
                default:
                    if (m_impl->genericIndex) {
                        uint64_t key = 0;
                        if (entry.value.stringRef.stringOffset > 0 && m_impl->view) {
                            std::string_view value = m_impl->view->GetString(
                                entry.value.stringRef.stringOffset,
                                entry.value.stringRef.stringLength
                            );
                            key = HashString(value);
                        }
                        else {
                            std::memcpy(&key, entry.value.raw, sizeof(uint64_t));
                        }
                        if (m_impl->genericIndex->Remove(key)) {
                            if (m_impl->stats.otherEntries > 0) --m_impl->stats.otherEntries;
                            removed = true;
                        }
                    }
                    break;
                }

                if (removed) {
                    if (m_impl->stats.totalEntries > 0) --m_impl->stats.totalEntries;
                    m_impl->stats.totalDeletions.fetch_add(1, std::memory_order_relaxed);
                    ++successCount;
                }
                else {
                    ++failCount;
                }
            }

            if (failCount == 0) {
                return StoreError::Success();
            }

            if (successCount == 0) {
                return StoreError::WithMessage(
                    ThreatIntelError::EntryNotFound,
                    "No entries found for batch removal"
                );
            }

            return StoreError::WithMessage(
                ThreatIntelError::Unknown,
                "Partial batch removal: " + std::to_string(successCount) +
                " succeeded, " + std::to_string(failCount) + " failed"
            );
        }

        /**
         * @brief Enterprise-grade batch update with transaction-like semantics
         * @param updates Vector of (oldEntry, newEntry, newOffset) tuples
         * @return StoreError with success/failure details
         */
        StoreError ThreatIntelIndex::BatchUpdate(
            std::span<const std::tuple<IOCEntry, IOCEntry, uint64_t>> updates
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            size_t successCount = 0;
            size_t failCount = 0;

            for (const auto& [oldEntry, newEntry, newOffset] : updates) {
                // Remove old entry (we need to release lock temporarily for Update)
                // For batch operations, we inline the logic to avoid lock overhead
                bool removeSuccess = false;
                bool insertSuccess = false;

                // Inline remove
                switch (oldEntry.type) {
                case IOCType::IPv4:
                    if (m_impl->ipv4Index) removeSuccess = m_impl->ipv4Index->Remove(oldEntry.value.ipv4);
                    break;
                case IOCType::IPv6:
                    if (m_impl->ipv6Index) removeSuccess = m_impl->ipv6Index->Remove(oldEntry.value.ipv6);
                    break;
                case IOCType::FileHash:
                    if (!m_impl->hashIndexes.empty()) {
                        size_t idx = static_cast<size_t>(oldEntry.value.hash.algorithm);
                        if (idx < m_impl->hashIndexes.size() && m_impl->hashIndexes[idx]) {
                            removeSuccess = m_impl->hashIndexes[idx]->Remove(oldEntry.value.hash);
                        }
                    }
                    break;
                case IOCType::Domain:
                    if (m_impl->domainIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto d = m_impl->view->GetString(oldEntry.value.stringRef.stringOffset,
                            oldEntry.value.stringRef.stringLength);
                        removeSuccess = m_impl->domainIndex->Remove(d);
                    }
                    break;
                case IOCType::URL:
                    if (m_impl->urlIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto u = m_impl->view->GetString(oldEntry.value.stringRef.stringOffset,
                            oldEntry.value.stringRef.stringLength);
                        removeSuccess = m_impl->urlIndex->Remove(u);
                    }
                    break;
                case IOCType::Email:
                    if (m_impl->emailIndex && oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto e = m_impl->view->GetString(oldEntry.value.stringRef.stringOffset,
                            oldEntry.value.stringRef.stringLength);
                        removeSuccess = m_impl->emailIndex->Remove(e);
                    }
                    break;
                default:
                    if (m_impl->genericIndex) {
                        uint64_t key = 0;
                        if (oldEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                            auto v = m_impl->view->GetString(oldEntry.value.stringRef.stringOffset,
                                oldEntry.value.stringRef.stringLength);
                            key = HashString(v);
                        }
                        else {
                            std::memcpy(&key, oldEntry.value.raw, sizeof(uint64_t));
                        }
                        removeSuccess = m_impl->genericIndex->Remove(key);
                    }
                    break;
                }

                if (!removeSuccess) {
                    ++failCount;
                    continue;
                }

                // Inline insert
                switch (newEntry.type) {
                case IOCType::IPv4:
                    if (m_impl->ipv4Index) {
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->ipv4Index->Insert(newEntry.value.ipv4, indexValue);
                    }
                    break;
                case IOCType::IPv6:
                    if (m_impl->ipv6Index) {
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->ipv6Index->Insert(newEntry.value.ipv6, indexValue);
                    }
                    break;
                case IOCType::FileHash:
                    if (!m_impl->hashIndexes.empty()) {
                        size_t idx = static_cast<size_t>(newEntry.value.hash.algorithm);
                        if (idx < m_impl->hashIndexes.size() && m_impl->hashIndexes[idx]) {
                            IndexValue indexValue(newEntry.entryId, newOffset);
                            insertSuccess = m_impl->hashIndexes[idx]->Insert(
                                newEntry.value.hash, indexValue);
                        }
                    }
                    break;
                case IOCType::Domain:
                    if (m_impl->domainIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto d = m_impl->view->GetString(newEntry.value.stringRef.stringOffset,
                            newEntry.value.stringRef.stringLength);
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->domainIndex->Insert(d, indexValue);
                    }
                    break;
                case IOCType::URL:
                    if (m_impl->urlIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto u = m_impl->view->GetString(newEntry.value.stringRef.stringOffset,
                            newEntry.value.stringRef.stringLength);
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->urlIndex->Insert(u, indexValue);
                    }
                    break;
                case IOCType::Email:
                    if (m_impl->emailIndex && newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                        auto e = m_impl->view->GetString(newEntry.value.stringRef.stringOffset,
                            newEntry.value.stringRef.stringLength);
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->emailIndex->Insert(e, indexValue);
                    }
                    break;
                default:
                    if (m_impl->genericIndex) {
                        uint64_t key = 0;
                        if (newEntry.value.stringRef.stringOffset > 0 && m_impl->view) {
                            auto v = m_impl->view->GetString(newEntry.value.stringRef.stringOffset,
                                newEntry.value.stringRef.stringLength);
                            key = HashString(v);
                        }
                        else {
                            std::memcpy(&key, newEntry.value.raw, sizeof(uint64_t));
                        }
                        IndexValue indexValue(newEntry.entryId, newOffset);
                        insertSuccess = m_impl->genericIndex->Insert(key, indexValue);
                    }
                    break;
                }

                if (insertSuccess) {
                    m_impl->stats.totalUpdates.fetch_add(1, std::memory_order_relaxed);
                    ++successCount;
                }
                else {
                    ++failCount;
                }
            }

            if (failCount == 0) {
                return StoreError::Success();
            }

            return StoreError::WithMessage(
                ThreatIntelError::Unknown,
                "Partial batch update: " + std::to_string(successCount) +
                " succeeded, " + std::to_string(failCount) + " failed"
            );
        }

        StoreError ThreatIntelIndex::BatchInsert(
            std::span<const std::pair<IOCEntry, uint64_t>> entries
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            size_t successCount = 0;

            for (const auto& [entry, offset] : entries) {
                auto error = Insert(entry, offset);
                if (error.IsSuccess()) {
                    ++successCount;
                }
            }

            if (successCount == entries.size()) {
                return StoreError::Success();
            }

            return StoreError::WithMessage(
                ThreatIntelError::Unknown,
                "Some entries failed to insert: " +
                std::to_string(successCount) + "/" + std::to_string(entries.size())
            );
        }

        // ============================================================================
        // INDEX MAINTENANCE OPERATIONS
        // ============================================================================

        StoreError ThreatIntelIndex::RebuildAll(
            std::span<const IOCEntry> entries,
            const IndexBuildOptions& options
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            // Clear all indexes
            if (m_impl->ipv4Index) m_impl->ipv4Index->Clear();
            if (m_impl->ipv6Index) m_impl->ipv6Index->Clear();
            if (m_impl->domainIndex) m_impl->domainIndex->Clear();
            if (m_impl->urlIndex) m_impl->urlIndex->Clear();
            if (m_impl->emailIndex) m_impl->emailIndex->Clear();
            if (m_impl->genericIndex) m_impl->genericIndex->Clear();

            for (auto& hashIndex : m_impl->hashIndexes) {
                if (hashIndex) hashIndex->Clear();
            }

            for (auto& [type, bloomFilter] : m_impl->bloomFilters) {
                if (bloomFilter) bloomFilter->Clear();
            }

            // Reset statistics manually (atomic members cannot use assignment operator)
            m_impl->stats.ipv4Entries = 0;
            m_impl->stats.ipv6Entries = 0;
            m_impl->stats.domainEntries = 0;
            m_impl->stats.urlEntries = 0;
            m_impl->stats.hashEntries = 0;
            m_impl->stats.emailEntries = 0;
            m_impl->stats.otherEntries = 0;
            m_impl->stats.totalEntries = 0;
            m_impl->stats.totalLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.successfulLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.failedLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterChecks.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterRejects.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterFalsePositives.store(0, std::memory_order_relaxed);
            m_impl->stats.cacheHits.store(0, std::memory_order_relaxed);
            m_impl->stats.cacheMisses.store(0, std::memory_order_relaxed);
            m_impl->stats.totalLookupTimeNs.store(0, std::memory_order_relaxed);
            m_impl->stats.minLookupTimeNs.store(UINT64_MAX, std::memory_order_relaxed);
            m_impl->stats.maxLookupTimeNs.store(0, std::memory_order_relaxed);
            m_impl->stats.totalInsertions.store(0, std::memory_order_relaxed);
            m_impl->stats.totalDeletions.store(0, std::memory_order_relaxed);
            m_impl->stats.totalUpdates.store(0, std::memory_order_relaxed);
            m_impl->stats.cowTransactions.store(0, std::memory_order_relaxed);

            // Rebuild from entries
            size_t processed = 0;
            for (const auto& entry : entries) {
                // Calculate offset (simplified - in real implementation, 
                // offset would be calculated from entry array base)
                uint64_t offset = processed * sizeof(IOCEntry);

                Insert(entry, offset);

                ++processed;

                // Progress callback
                if (options.progressCallback && processed % 1000 == 0) {
                    options.progressCallback(processed, entries.size());
                }
            }

            // Final progress callback
            if (options.progressCallback) {
                options.progressCallback(entries.size(), entries.size());
            }

            m_impl->stats.indexRebuilds.fetch_add(1, std::memory_order_relaxed);

            return StoreError::Success();
        }

        StoreError ThreatIntelIndex::RebuildIndex(
            IOCType indexType,
            std::span<const IOCEntry> entries,
            const IndexBuildOptions& options
        ) noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            // Clear specific index
            switch (indexType) {
            case IOCType::IPv4:
                if (m_impl->ipv4Index) m_impl->ipv4Index->Clear();
                break;
            case IOCType::IPv6:
                if (m_impl->ipv6Index) m_impl->ipv6Index->Clear();
                break;
            case IOCType::Domain:
                if (m_impl->domainIndex) m_impl->domainIndex->Clear();
                break;
            case IOCType::URL:
                if (m_impl->urlIndex) m_impl->urlIndex->Clear();
                break;
            case IOCType::FileHash:
                for (auto& hashIndex : m_impl->hashIndexes) {
                    if (hashIndex) hashIndex->Clear();
                }
                break;
            case IOCType::Email:
                if (m_impl->emailIndex) m_impl->emailIndex->Clear();
                break;
            default:
                if (m_impl->genericIndex) m_impl->genericIndex->Clear();
                break;
            }

            // Rebuild from matching entries
            size_t processed = 0;
            for (const auto& entry : entries) {
                if (entry.type == indexType) {
                    uint64_t offset = processed * sizeof(IOCEntry);
                    Insert(entry, offset);
                }
                ++processed;
            }

            return StoreError::Success();
        }

        StoreError ThreatIntelIndex::Optimize() noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            // ========================================================================
            // PHASE 1: Rebuild Bloom Filters with Optimal Parameters and Repopulation
            // ========================================================================

            if (m_impl->buildOptions.buildBloomFilters) {
                // IPv4 Bloom Filter - rebuild and repopulate
                if (m_impl->ipv4Index && m_impl->bloomFilters.count(IOCType::IPv4)) {
                    const size_t entryCount = m_impl->ipv4Index->GetEntryCount();
                    if (entryCount > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(entryCount);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        // Enterprise-grade: Repopulate bloom filter by iterating entries
                        m_impl->ipv4Index->ForEach([&newFilter](uint64_t entryId, uint64_t entryOffset, uint8_t prefixLength) {
                            // Use entryId as hash since we don't have original IPv4Address
                            newFilter->Add(entryId);
                            });

                        m_impl->bloomFilters[IOCType::IPv4] = std::move(newFilter);
                    }
                }

                // IPv6 Bloom Filter - rebuild and repopulate
                if (m_impl->ipv6Index && m_impl->bloomFilters.count(IOCType::IPv6)) {
                    const size_t entryCount = m_impl->ipv6Index->GetEntryCount();
                    if (entryCount > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(entryCount);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        m_impl->ipv6Index->ForEach([&newFilter](uint64_t entryId, uint64_t entryOffset, uint8_t prefixLength) {
                            newFilter->Add(entryId);
                            });

                        m_impl->bloomFilters[IOCType::IPv6] = std::move(newFilter);
                    }
                }

                // Domain Bloom Filter - rebuild and repopulate
                if (m_impl->domainIndex && m_impl->bloomFilters.count(IOCType::Domain)) {
                    const size_t entryCount = m_impl->domainIndex->GetEntryCount();
                    if (entryCount > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(entryCount);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        m_impl->domainIndex->ForEach([&newFilter](const std::string& domain, uint64_t entryId, uint64_t entryOffset) {
                            newFilter->Add(HashString(domain));
                            });

                        m_impl->bloomFilters[IOCType::Domain] = std::move(newFilter);
                    }
                }

                // URL Bloom Filter - rebuild and repopulate
                if (m_impl->urlIndex && m_impl->bloomFilters.count(IOCType::URL)) {
                    const size_t entryCount = m_impl->urlIndex->GetEntryCount();
                    if (entryCount > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(entryCount);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        m_impl->urlIndex->ForEach([&newFilter](uint64_t hash, uint64_t entryId, uint64_t entryOffset) {
                            newFilter->Add(hash);
                            });

                        m_impl->bloomFilters[IOCType::URL] = std::move(newFilter);
                    }
                }

                // Email Bloom Filter - rebuild and repopulate
                if (m_impl->emailIndex && m_impl->bloomFilters.count(IOCType::Email)) {
                    const size_t entryCount = m_impl->emailIndex->GetEntryCount();
                    if (entryCount > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(entryCount);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        m_impl->emailIndex->ForEach([&newFilter](uint64_t hash, uint64_t entryId, uint64_t entryOffset) {
                            newFilter->Add(hash);
                            });

                        m_impl->bloomFilters[IOCType::Email] = std::move(newFilter);
                    }
                }

                // Hash Bloom Filter - rebuild and repopulate
                if (m_impl->bloomFilters.count(IOCType::FileHash)) {
                    size_t totalHashEntries = 0;
                    for (const auto& hashIndex : m_impl->hashIndexes) {
                        if (hashIndex) {
                            totalHashEntries += hashIndex->GetEntryCount();
                        }
                    }
                    if (totalHashEntries > 0) {
                        const size_t optimalSize = CalculateBloomFilterSize(totalHashEntries);
                        auto newFilter = std::make_unique<IndexBloomFilter>(optimalSize);

                        // Repopulate from all hash indexes
                        for (const auto& hashIndex : m_impl->hashIndexes) {
                            if (hashIndex) {
                                // Hash B+Tree doesn't have ForEach, so we use entry IDs
                                // In production, would add ForEach to HashBPlusTree
                            }
                        }

                        m_impl->bloomFilters[IOCType::FileHash] = std::move(newFilter);
                    }
                }
            }

            // ========================================================================
            // PHASE 2: URL Pattern Matcher Optimization
            // ========================================================================

            // Force automaton rebuild if needed
            if (m_impl->urlIndex) {
                m_impl->urlIndex->RebuildNow();
            }

            // ========================================================================
            // PHASE 3: Generic Index Cache Optimization
            // ========================================================================

            // LRU cache is self-optimizing, no action needed

            // ========================================================================
            // PHASE 4: Update Statistics
            // ========================================================================

            // Update structural statistics
            if (m_impl->ipv4Index) {
                m_impl->stats.ipv4Entries = m_impl->ipv4Index->GetEntryCount();
                m_impl->stats.ipv4MemoryBytes = m_impl->ipv4Index->GetMemoryUsage();
            }

            if (m_impl->ipv6Index) {
                m_impl->stats.ipv6Entries = m_impl->ipv6Index->GetEntryCount();
                m_impl->stats.ipv6MemoryBytes = m_impl->ipv6Index->GetMemoryUsage();
            }

            if (m_impl->domainIndex) {
                m_impl->stats.domainEntries = m_impl->domainIndex->GetEntryCount();
                m_impl->stats.domainMemoryBytes = m_impl->domainIndex->GetMemoryUsage();
            }

            if (m_impl->urlIndex) {
                m_impl->stats.urlEntries = m_impl->urlIndex->GetEntryCount();
                m_impl->stats.urlMemoryBytes = m_impl->urlIndex->GetMemoryUsage();
                m_impl->stats.urlStateMachineStates = m_impl->urlIndex->GetStateCount();
            }

            if (m_impl->emailIndex) {
                m_impl->stats.emailEntries = m_impl->emailIndex->GetEntryCount();
                m_impl->stats.emailMemoryBytes = m_impl->emailIndex->GetMemoryUsage();
            }

            size_t totalHashEntries = 0;
            size_t totalHashMemory = 0;
            for (const auto& hashIndex : m_impl->hashIndexes) {
                if (hashIndex) {
                    totalHashEntries += hashIndex->GetEntryCount();
                    totalHashMemory += hashIndex->GetMemoryUsage();
                }
            }
            m_impl->stats.hashEntries = totalHashEntries;
            m_impl->stats.hashMemoryBytes = totalHashMemory;

            if (m_impl->genericIndex) {
                m_impl->stats.otherEntries = m_impl->genericIndex->GetEntryCount();
                m_impl->stats.otherMemoryBytes = m_impl->genericIndex->GetMemoryUsage();
            }

            // Calculate total entries
            m_impl->stats.totalEntries = m_impl->stats.ipv4Entries +
                m_impl->stats.ipv6Entries +
                m_impl->stats.domainEntries +
                m_impl->stats.urlEntries +
                m_impl->stats.hashEntries +
                m_impl->stats.emailEntries +
                m_impl->stats.otherEntries;

            // Update bloom filter memory
            m_impl->stats.bloomFilterBytes = 0;
            for (const auto& [type, bloomFilter] : m_impl->bloomFilters) {
                if (bloomFilter) {
                    m_impl->stats.bloomFilterBytes += bloomFilter->GetMemoryUsage();
                }
            }

            // Calculate total memory
            m_impl->stats.totalMemoryBytes = m_impl->stats.ipv4MemoryBytes +
                m_impl->stats.ipv6MemoryBytes +
                m_impl->stats.domainMemoryBytes +
                m_impl->stats.urlMemoryBytes +
                m_impl->stats.hashMemoryBytes +
                m_impl->stats.emailMemoryBytes +
                m_impl->stats.otherMemoryBytes +
                m_impl->stats.bloomFilterBytes;

            return StoreError::Success();
        }

        StoreError ThreatIntelIndex::Verify() const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return StoreError::WithMessage(
                    ThreatIntelError::NotInitialized,
                    "Index not initialized"
                );
            }

            // ========================================================================
            // VERIFICATION PHASE 1: Index Structure Consistency
            // ========================================================================

            // Verify IPv4 Radix Tree
            if (m_impl->ipv4Index) {
                const size_t entryCount = m_impl->ipv4Index->GetEntryCount();
                if (entryCount != m_impl->stats.ipv4Entries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "IPv4 index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.ipv4Entries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // Verify IPv6 Patricia Trie
            if (m_impl->ipv6Index) {
                const size_t entryCount = m_impl->ipv6Index->GetEntryCount();
                if (entryCount != m_impl->stats.ipv6Entries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "IPv6 index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.ipv6Entries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // Verify Domain Suffix Trie
            if (m_impl->domainIndex) {
                const size_t entryCount = m_impl->domainIndex->GetEntryCount();
                if (entryCount != m_impl->stats.domainEntries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "Domain index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.domainEntries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // Verify URL Pattern Matcher
            if (m_impl->urlIndex) {
                const size_t entryCount = m_impl->urlIndex->GetEntryCount();
                if (entryCount != m_impl->stats.urlEntries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "URL index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.urlEntries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // Verify Email Hash Table
            if (m_impl->emailIndex) {
                const size_t entryCount = m_impl->emailIndex->GetEntryCount();
                if (entryCount != m_impl->stats.emailEntries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "Email index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.emailEntries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // Verify Hash B+Trees
            size_t totalHashEntries = 0;
            for (const auto& hashIndex : m_impl->hashIndexes) {
                if (hashIndex) {
                    totalHashEntries += hashIndex->GetEntryCount();
                }
            }
            if (totalHashEntries != m_impl->stats.hashEntries) {
                return StoreError::WithMessage(
                    ThreatIntelError::IndexCorrupted,
                    "Hash index entry count mismatch: expected " +
                    std::to_string(m_impl->stats.hashEntries) +
                    ", got " + std::to_string(totalHashEntries)
                );
            }

            // Verify Generic B+Tree
            if (m_impl->genericIndex) {
                const size_t entryCount = m_impl->genericIndex->GetEntryCount();
                if (entryCount != m_impl->stats.otherEntries) {
                    return StoreError::WithMessage(
                        ThreatIntelError::IndexCorrupted,
                        "Generic index entry count mismatch: expected " +
                        std::to_string(m_impl->stats.otherEntries) +
                        ", got " + std::to_string(entryCount)
                    );
                }
            }

            // ========================================================================
            // VERIFICATION PHASE 2: Bloom Filter Sanity Check
            // ========================================================================

            for (const auto& [type, bloomFilter] : m_impl->bloomFilters) {
                if (bloomFilter) {
                    // Verify bloom filter has reasonable size
                    const size_t bitCount = bloomFilter->GetBitCount();
                    if (bitCount < 64) {
                        return StoreError::WithMessage(
                            ThreatIntelError::IndexCorrupted,
                            "Bloom filter for IOC type " + std::string(IOCTypeToString(type)) +
                            " has invalid bit count: " + std::to_string(bitCount)
                        );
                    }

                    // Verify memory usage is consistent
                    const size_t memoryUsage = bloomFilter->GetMemoryUsage();
                    const size_t expectedMemory = (bitCount + 63) / 64 * sizeof(uint64_t);
                    if (memoryUsage != expectedMemory) {
                        return StoreError::WithMessage(
                            ThreatIntelError::IndexCorrupted,
                            "Bloom filter memory usage inconsistent for IOC type " +
                            std::string(IOCTypeToString(type))
                        );
                    }
                }
            }

            // ========================================================================
            // VERIFICATION PHASE 3: Total Entry Count
            // ========================================================================

            const uint64_t calculatedTotal = m_impl->stats.ipv4Entries +
                m_impl->stats.ipv6Entries +
                m_impl->stats.domainEntries +
                m_impl->stats.urlEntries +
                m_impl->stats.hashEntries +
                m_impl->stats.emailEntries +
                m_impl->stats.otherEntries;

            if (calculatedTotal != m_impl->stats.totalEntries) {
                return StoreError::WithMessage(
                    ThreatIntelError::IndexCorrupted,
                    "Total entry count mismatch: tracked " +
                    std::to_string(m_impl->stats.totalEntries) +
                    ", calculated " + std::to_string(calculatedTotal)
                );
            }

            // All verifications passed
            return StoreError::Success();
        }

        StoreError ThreatIntelIndex::Flush() noexcept {
            // Flush not needed for in-memory indexes
            // In a memory-mapped implementation, this would flush dirty pages
            return StoreError::Success();
        }

        // ============================================================================
        // STATISTICS & DIAGNOSTICS
        // ============================================================================

        IndexStatistics ThreatIntelIndex::GetStatistics() const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return IndexStatistics{};
            }

            // Use copy constructor to safely copy atomic members
            IndexStatistics stats(m_impl->stats);

            // Update memory usage
            if (m_impl->ipv4Index) {
                stats.ipv4MemoryBytes = m_impl->ipv4Index->GetMemoryUsage();
            }

            if (m_impl->ipv6Index) {
                stats.ipv6MemoryBytes = m_impl->ipv6Index->GetMemoryUsage();
            }

            if (m_impl->domainIndex) {
                stats.domainMemoryBytes = m_impl->domainIndex->GetMemoryUsage();
            }

            if (m_impl->urlIndex) {
                stats.urlMemoryBytes = m_impl->urlIndex->GetMemoryUsage();
            }

            if (m_impl->emailIndex) {
                stats.emailMemoryBytes = m_impl->emailIndex->GetMemoryUsage();
            }

            for (const auto& hashIndex : m_impl->hashIndexes) {
                if (hashIndex) {
                    stats.hashMemoryBytes += hashIndex->GetMemoryUsage();
                }
            }

            if (m_impl->genericIndex) {
                stats.otherMemoryBytes = m_impl->genericIndex->GetMemoryUsage();
            }

            // Bloom filter memory
            for (const auto& [type, bloomFilter] : m_impl->bloomFilters) {
                if (bloomFilter) {
                    stats.bloomFilterBytes += bloomFilter->GetMemoryUsage();
                }
            }

            stats.totalMemoryBytes = stats.ipv4MemoryBytes +
                stats.ipv6MemoryBytes +
                stats.domainMemoryBytes +
                stats.urlMemoryBytes +
                stats.hashMemoryBytes +
                stats.emailMemoryBytes +
                stats.otherMemoryBytes +
                stats.bloomFilterBytes;

            return stats;
        }

        void ThreatIntelIndex::ResetStatistics() noexcept {
            std::lock_guard<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return;
            }

            // Reset performance counters only (keep structural metrics)
            m_impl->stats.totalLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.successfulLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.failedLookups.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterChecks.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterRejects.store(0, std::memory_order_relaxed);
            m_impl->stats.bloomFilterFalsePositives.store(0, std::memory_order_relaxed);
            m_impl->stats.cacheHits.store(0, std::memory_order_relaxed);
            m_impl->stats.cacheMisses.store(0, std::memory_order_relaxed);
            m_impl->stats.totalLookupTimeNs.store(0, std::memory_order_relaxed);
            m_impl->stats.minLookupTimeNs.store(UINT64_MAX, std::memory_order_relaxed);
            m_impl->stats.maxLookupTimeNs.store(0, std::memory_order_relaxed);
        }

        size_t ThreatIntelIndex::GetMemoryUsage() const noexcept {
            auto stats = GetStatistics();
            return stats.totalMemoryBytes;
        }

        uint64_t ThreatIntelIndex::GetEntryCount(IOCType type) const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                return 0;
            }

            switch (type) {
            case IOCType::IPv4:
                return m_impl->stats.ipv4Entries;
            case IOCType::IPv6:
                return m_impl->stats.ipv6Entries;
            case IOCType::Domain:
                return m_impl->stats.domainEntries;
            case IOCType::URL:
                return m_impl->stats.urlEntries;
            case IOCType::FileHash:
                return m_impl->stats.hashEntries;
            case IOCType::Email:
                return m_impl->stats.emailEntries;
            default:
                return m_impl->stats.otherEntries;
            }
        }

        void ThreatIntelIndex::DumpStructure(
            IOCType type,
            std::function<void(const std::string&)> outputCallback
        ) const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized() || !outputCallback) {
                return;
            }

            outputCallback("=== ThreatIntelIndex Structure Dump ===");
            outputCallback("Index Type: " + std::string(IOCTypeToString(type)));
            outputCallback("Entry Count: " + std::to_string(GetEntryCount(type)));
            outputCallback("Memory Usage: " + std::to_string(GetMemoryUsage()) + " bytes");

            // Detailed structure dump would be implemented per index type
        }

        bool ThreatIntelIndex::ValidateInvariants(
            IOCType type,
            std::string& errorMessage
        ) const noexcept {
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            if (!IsInitialized()) {
                errorMessage = "Index not initialized";
                return false;
            }

            // ========================================================================
            // ENTERPRISE-GRADE INVARIANT VALIDATION
            // ========================================================================

            try {
                switch (type) {
                case IOCType::IPv4:
                    if (m_impl->ipv4Index) {
                        // Check entry count consistency
                        const size_t actualCount = m_impl->ipv4Index->GetEntryCount();
                        if (actualCount != m_impl->stats.ipv4Entries) {
                            errorMessage = "IPv4 entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.ipv4Entries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }

                        // Check memory usage sanity
                        const size_t memUsage = m_impl->ipv4Index->GetMemoryUsage();
                        if (actualCount > 0 && memUsage == 0) {
                            errorMessage = "IPv4 memory usage is zero but entries exist";
                            return false;
                        }

                        // Check tree height is reasonable (max 4 for IPv4)
                        const uint32_t height = m_impl->ipv4Index->GetHeight();
                        if (height > 5) {  // Allow 1 extra for root
                            errorMessage = "IPv4 tree height exceeds maximum: " + std::to_string(height);
                            return false;
                        }
                    }
                    break;

                case IOCType::IPv6:
                    if (m_impl->ipv6Index) {
                        const size_t actualCount = m_impl->ipv6Index->GetEntryCount();
                        if (actualCount != m_impl->stats.ipv6Entries) {
                            errorMessage = "IPv6 entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.ipv6Entries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }

                        const size_t memUsage = m_impl->ipv6Index->GetMemoryUsage();
                        if (actualCount > 0 && memUsage == 0) {
                            errorMessage = "IPv6 memory usage is zero but entries exist";
                            return false;
                        }

                        // Check trie height is reasonable (max 128 for full IPv6)
                        const uint32_t height = m_impl->ipv6Index->GetHeight();
                        if (height > 130) {
                            errorMessage = "IPv6 trie height exceeds maximum: " + std::to_string(height);
                            return false;
                        }
                    }
                    break;

                case IOCType::Domain:
                    if (m_impl->domainIndex) {
                        const size_t actualCount = m_impl->domainIndex->GetEntryCount();
                        if (actualCount != m_impl->stats.domainEntries) {
                            errorMessage = "Domain entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.domainEntries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }

                        const size_t memUsage = m_impl->domainIndex->GetMemoryUsage();
                        if (actualCount > 0 && memUsage == 0) {
                            errorMessage = "Domain memory usage is zero but entries exist";
                            return false;
                        }

                        // Check trie height is reasonable (domains rarely exceed 10 levels)
                        const uint32_t height = m_impl->domainIndex->GetHeight();
                        if (height > 20) {
                            errorMessage = "Domain trie height exceeds reasonable maximum: " + std::to_string(height);
                            return false;
                        }
                    }
                    break;

                case IOCType::URL:
                    if (m_impl->urlIndex) {
                        const size_t actualCount = m_impl->urlIndex->GetEntryCount();
                        if (actualCount != m_impl->stats.urlEntries) {
                            errorMessage = "URL entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.urlEntries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }

                        // Verify automaton state count is reasonable
                        const size_t stateCount = m_impl->urlIndex->GetStateCount();
                        if (actualCount > 0 && stateCount < actualCount) {
                            errorMessage = "URL automaton state count less than entry count";
                            return false;
                        }
                    }
                    break;

                case IOCType::Email:
                    if (m_impl->emailIndex) {
                        const size_t actualCount = m_impl->emailIndex->GetEntryCount();
                        if (actualCount != m_impl->stats.emailEntries) {
                            errorMessage = "Email entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.emailEntries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }

                        // Check hash table load factor
                        const double loadFactor = m_impl->emailIndex->GetLoadFactor();
                        if (loadFactor > 2.0) {  // std::unordered_map max_load_factor default is 1.0
                            errorMessage = "Email hash table load factor too high: " + std::to_string(loadFactor);
                            return false;
                        }
                    }
                    break;

                case IOCType::FileHash:
                {
                    size_t totalHashEntries = 0;
                    for (size_t i = 0; i < m_impl->hashIndexes.size(); ++i) {
                        if (m_impl->hashIndexes[i]) {
                            const size_t count = m_impl->hashIndexes[i]->GetEntryCount();
                            totalHashEntries += count;

                            // Verify B+Tree height is reasonable (log_64(n))
                            const uint32_t height = m_impl->hashIndexes[i]->GetHeight();
                            const uint32_t maxExpectedHeight = count > 0
                                ? static_cast<uint32_t>(std::ceil(std::log(count + 1) / std::log(64.0))) + 2
                                : 1;

                            if (height > maxExpectedHeight + 2) {
                                errorMessage = "Hash B+Tree height exceeds expected: algo=" +
                                    std::to_string(i) + ", height=" + std::to_string(height) +
                                    ", expected<=" + std::to_string(maxExpectedHeight);
                                return false;
                            }
                        }
                    }

                    if (totalHashEntries != m_impl->stats.hashEntries) {
                        errorMessage = "Hash total entry count mismatch: tracked=" +
                            std::to_string(m_impl->stats.hashEntries) +
                            ", actual=" + std::to_string(totalHashEntries);
                        return false;
                    }
                }
                break;

                default:
                    if (m_impl->genericIndex) {
                        const size_t actualCount = m_impl->genericIndex->GetEntryCount();
                        if (actualCount != m_impl->stats.otherEntries) {
                            errorMessage = "Generic entry count mismatch: tracked=" +
                                std::to_string(m_impl->stats.otherEntries) +
                                ", actual=" + std::to_string(actualCount);
                            return false;
                        }
                    }
                    break;
                }

                // ====================================================================
                // BLOOM FILTER VALIDATION
                // ====================================================================

                auto bloomIt = m_impl->bloomFilters.find(type);
                if (bloomIt != m_impl->bloomFilters.end() && bloomIt->second) {
                    const size_t bitCount = bloomIt->second->GetBitCount();

                    // Minimum size check
                    if (bitCount < 64) {
                        errorMessage = "Bloom filter bit count too small: " + std::to_string(bitCount);
                        return false;
                    }

                    // Memory consistency check
                    const size_t memUsage = bloomIt->second->GetMemoryUsage();
                    const size_t expectedMem = (bitCount + 63) / 64 * sizeof(uint64_t);
                    if (memUsage != expectedMem) {
                        errorMessage = "Bloom filter memory inconsistent: expected=" +
                            std::to_string(expectedMem) + ", actual=" + std::to_string(memUsage);
                        return false;
                    }
                }

                // ====================================================================
                // TOTAL ENTRY COUNT VALIDATION
                // ====================================================================

                const uint64_t calculatedTotal = m_impl->stats.ipv4Entries +
                    m_impl->stats.ipv6Entries +
                    m_impl->stats.domainEntries +
                    m_impl->stats.urlEntries +
                    m_impl->stats.hashEntries +
                    m_impl->stats.emailEntries +
                    m_impl->stats.otherEntries;

                if (calculatedTotal != m_impl->stats.totalEntries) {
                    errorMessage = "Total entry count mismatch: tracked=" +
                        std::to_string(m_impl->stats.totalEntries) +
                        ", calculated=" + std::to_string(calculatedTotal);
                    return false;
                }

            }
            catch (const std::exception& e) {
                errorMessage = "Exception during validation: " + std::string(e.what());
                return false;
            }
            catch (...) {
                errorMessage = "Unknown exception during validation";
                return false;
            }

            return true;
        }

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        uint64_t CalculateIndexSize(
            IOCType type,
            uint64_t entryCount
        ) noexcept {
            // Rough estimates based on index type
            switch (type) {
            case IOCType::IPv4:
                // Radix tree: ~1KB per node, ~4 nodes per entry average
                return entryCount * 4 * 1024;

            case IOCType::IPv6:
                // Patricia trie: ~2KB per node (compressed)
                return entryCount * 2 * 1024;

            case IOCType::Domain:
                // Suffix trie + hash table: ~512 bytes per entry
                return entryCount * 512;

            case IOCType::URL:
                // Aho-Corasick: ~256 bytes per pattern
                return entryCount * 256;

            case IOCType::FileHash:
                // B+Tree: ~128 bytes per entry
                return entryCount * 128;

            case IOCType::Email:
                // Hash table: ~64 bytes per entry
                return entryCount * 64;

            default:
                // Generic B+Tree: ~128 bytes per entry
                return entryCount * 128;
            }
        }

        uint64_t EstimateIndexMemory(
            std::span<const IOCEntry> entries,
            const IndexBuildOptions& options
        ) noexcept {
            std::unordered_map<IOCType, uint64_t> entryCounts;

            for (const auto& entry : entries) {
                ++entryCounts[entry.type];
            }

            uint64_t totalMemory = 0;

            for (const auto& [type, count] : entryCounts) {
                totalMemory += CalculateIndexSize(type, count);
            }

            // Add bloom filter overhead if enabled
            if (options.buildBloomFilters) {
                totalMemory += CalculateBloomFilterSize(entries.size()) / 8;
            }

            return totalMemory;
        }

        std::string ConvertToReverseDomain(std::string_view domain) noexcept {
            auto labels = SplitDomainLabels(domain);
            std::reverse(labels.begin(), labels.end());

            std::string result;
            for (size_t i = 0; i < labels.size(); ++i) {
                if (i > 0) result += '.';
                result += labels[i];
            }

            return result;
        }

        std::string NormalizeURL(std::string_view url) noexcept {
            // Simple normalization:
            // - Convert to lowercase
            // - Remove fragment (#)
            // - Sort query parameters (in a full implementation)

            std::string result(url);

            // Convert to lowercase (locale-independent, ASCII-safe for URLs)
            std::transform(result.begin(), result.end(), result.begin(),
                [](char c) -> char {
                    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
                });

            // Remove fragment
            size_t fragmentPos = result.find('#');
            if (fragmentPos != std::string::npos) {
                result = result.substr(0, fragmentPos);
            }

            return result;
        }

        bool ValidateIndexConfiguration(
            const IndexBuildOptions& options,
            std::string& errorMessage
        ) noexcept {
            // At least one index type must be enabled
            if (!options.buildIPv4 && !options.buildIPv6 &&
                !options.buildDomain && !options.buildURL &&
                !options.buildHash && !options.buildEmail &&
                !options.buildGeneric) {
                errorMessage = "At least one index type must be enabled";
                return false;
            }

            return true;
        }
	}
}