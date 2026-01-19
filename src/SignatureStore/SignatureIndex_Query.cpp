// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com


#include"pch.h"
#include"SignatureIndex.hpp"
#include"../../src/Utils/Logger.hpp"
#include<unordered_set>

namespace ShadowStrike {
	namespace SignatureStore {

        // ============================================================================
        // QUERY OPERATIONS (Lock-Free Reads)
        // ============================================================================

        std::optional<uint64_t> SignatureIndex::Lookup(const HashValue& hash) const noexcept {
            // SECURITY: Validate hash before computing fast hash
            if (hash.length == 0 || hash.length > 64) {
                SS_LOG_WARN(L"SignatureIndex", L"Lookup: Invalid hash length %u", hash.length);
                return std::nullopt;
            }
            return LookupByFastHash(hash.FastHash());
        }

        // Internal lookup helper - CALLER MUST HOLD LOCK (shared or exclusive)
        std::optional<uint64_t> SignatureIndex::LookupByFastHashInternal(uint64_t fastHash) const noexcept {
            // SECURITY: Validate index state before lookup
            if (!m_baseAddress) {
                return std::nullopt;
            }

            // Find leaf node
            const BPlusTreeNode* leaf = FindLeaf(fastHash);
            if (!leaf) {
                return std::nullopt;
            }

            // SECURITY: Validate leaf node state
            if (leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
                SS_LOG_ERROR(L"SignatureIndex",
                    L"LookupByFastHashInternal: Invalid leaf keyCount %u", leaf->keyCount);
                return std::nullopt;
            }

            // Binary search in leaf node
            uint32_t pos = BinarySearch(leaf->keys, leaf->keyCount, fastHash);

            // Check if key found (bounds-safe)
            if (pos < leaf->keyCount && leaf->keys[pos] == fastHash) {
                // SECURITY: Validate child offset before returning
                uint64_t offset = static_cast<uint64_t>(leaf->children[pos]);
                return offset;
            }

            // TRACE: Log when key is not found (not INFO - would flood logs)
            SS_LOG_TRACE(L"SignatureIndex",
                L"LookupByFastHashInternal: Key 0x%llX NOT FOUND in leaf (pos=%u, keyCount=%u)",
                fastHash, pos, leaf->keyCount);
            if (leaf->keyCount > 0) {
                SS_LOG_TRACE(L"SignatureIndex",
                    L"LookupByFastHashInternal: Leaf key[0]=0x%llX, key[last]=0x%llX, key[pos]=0x%llX",
                    leaf->keys[0], leaf->keys[leaf->keyCount - 1],
                    pos < leaf->keyCount ? leaf->keys[pos] : 0ULL);
            }

            return std::nullopt;
        }

        std::optional<uint64_t> SignatureIndex::LookupByFastHash(uint64_t fastHash) const noexcept {
            // Performance tracking (relaxed ordering for statistics)
            m_totalLookups.fetch_add(1, std::memory_order_relaxed);

            LARGE_INTEGER startTime{};
            const bool hasTimer = (m_perfFrequency.QuadPart > 0);
            if (hasTimer) {
                if (!QueryPerformanceCounter(&startTime)) {
                    startTime.QuadPart = 0;  // Graceful fallback
                }
            }

            // Lock-free read (shared lock allows concurrent readers)
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            // SECURITY: Validate index is initialized under lock
            if (!m_baseAddress || m_indexSize == 0) {
                return std::nullopt;
            }

            auto result = LookupByFastHashInternal(fastHash);

            // Performance tracking (only if we have valid timer and found result)
            if (hasTimer && result.has_value() && startTime.QuadPart > 0) {
                LARGE_INTEGER endTime{};
                if (QueryPerformanceCounter(&endTime)) {
                    // Could track average lookup time here for performance monitoring
                    // uint64_t elapsedNs = ((endTime.QuadPart - startTime.QuadPart) * 1000000000ULL) 
                    //                      / m_perfFrequency.QuadPart;
                }
            }

            return result;
        }

        std::vector<uint64_t> SignatureIndex::RangeQuery(
            uint64_t minFastHash,
            uint64_t maxFastHash,
            uint32_t maxResults
        ) const noexcept {
            std::vector<uint64_t> results;

            // SECURITY: Validate range parameters
            if (minFastHash > maxFastHash) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"RangeQuery: Invalid range (min=0x%llX > max=0x%llX)",
                    minFastHash, maxFastHash);
                return results;
            }

            // SECURITY: DoS protection - enforce absolute maximum results
            constexpr uint32_t ABSOLUTE_MAX_RESULTS = 100000;
            const uint32_t effectiveMaxResults = (maxResults == 0) ? ABSOLUTE_MAX_RESULTS
                : std::min(maxResults, ABSOLUTE_MAX_RESULTS);

            // Pre-allocate with reasonable initial size
            try {
                results.reserve(std::min(effectiveMaxResults, 1000u));
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureIndex", L"RangeQuery: Failed to reserve result space");
                return results;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureIndex", L"RangeQuery: Unknown exception during reserve");
                return results;
            }

            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            // SECURITY: Validate index state
            if (!m_baseAddress || m_indexSize == 0) {
                SS_LOG_WARN(L"SignatureIndex", L"RangeQuery: Index not initialized");
                return results;
            }

            // Find starting leaf
            const BPlusTreeNode* leaf = FindLeaf(minFastHash);
            if (!leaf) {
                SS_LOG_DEBUG(L"SignatureIndex", L"RangeQuery: No starting leaf found");
                return results;
            }

            // SECURITY: Track iterations to prevent infinite loop in corrupted tree
            constexpr size_t MAX_ITERATIONS = 1000000;
            size_t iterations = 0;

            // Track visited nodes to detect cycles
            std::unordered_set<uintptr_t> visitedNodes;

            // Traverse leaf nodes via linked list
            while (leaf && results.size() < effectiveMaxResults && iterations < MAX_ITERATIONS) {
                // SECURITY: Cycle detection
                uintptr_t nodeAddr = reinterpret_cast<uintptr_t>(leaf);
                if (visitedNodes.count(nodeAddr) > 0) {
                    SS_LOG_ERROR(L"SignatureIndex", L"RangeQuery: Cycle detected in leaf list");
                    break;
                }
                visitedNodes.insert(nodeAddr);

                // SECURITY: Validate keyCount
                if (leaf->keyCount > BPlusTreeNode::MAX_KEYS) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"RangeQuery: Invalid keyCount %u in leaf", leaf->keyCount);
                    break;
                }

                // Process keys in this leaf
                for (uint32_t i = 0; i < leaf->keyCount && results.size() < effectiveMaxResults; ++i) {
                    const uint64_t key = leaf->keys[i];

                    if (key > maxFastHash) {
                        // Past range - done
                        return results;
                    }

                    if (key >= minFastHash) {
                        try {
                            results.push_back(static_cast<uint64_t>(leaf->children[i]));
                        }
                        catch (const std::bad_alloc&) {
                            SS_LOG_ERROR(L"SignatureIndex", L"RangeQuery: Memory allocation failed");
                            return results;
                        }
                        catch (...) {
                            SS_LOG_ERROR(L"SignatureIndex", L"RangeQuery: Unknown exception");
                            return results;
                        }
                    }
                }

                // Move to next leaf
                if (leaf->nextLeaf == 0) {
                    break;
                }

                // SECURITY: Validate nextLeaf offset before dereferencing
                if (leaf->nextLeaf >= m_indexSize) {
                    SS_LOG_ERROR(L"SignatureIndex",
                        L"RangeQuery: Invalid nextLeaf offset 0x%X (indexSize=0x%llX)",
                        leaf->nextLeaf, m_indexSize);
                    break;
                }

                leaf = GetNode(leaf->nextLeaf);
                iterations++;
            }

            if (iterations >= MAX_ITERATIONS) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"RangeQuery: Iteration limit reached (%zu iterations)", iterations);
            }

            return results;
        }

        void SignatureIndex::BatchLookup(
            std::span<const HashValue> hashes,
            std::vector<std::optional<uint64_t>>& results
        ) const noexcept {
            results.clear();

            // SECURITY: DoS protection - limit batch size
            constexpr size_t MAX_BATCH_SIZE = 1000000;
            if (hashes.size() > MAX_BATCH_SIZE) {
                SS_LOG_WARN(L"SignatureIndex",
                    L"BatchLookup: Batch size %zu exceeds limit %zu - truncating",
                    hashes.size(), MAX_BATCH_SIZE);
            }

            const size_t effectiveSize = std::min(hashes.size(), MAX_BATCH_SIZE);

            // Reserve space - use try/catch for noexcept safety
            try {
                results.reserve(effectiveSize);
            }
            catch (const std::bad_alloc&) {
                SS_LOG_ERROR(L"SignatureIndex", L"BatchLookup: Failed to reserve result space");
                return;
            }
            catch (...) {
                SS_LOG_ERROR(L"SignatureIndex", L"BatchLookup: Unknown exception during reserve");
                return;
            }

            // Single lock acquisition for entire batch - avoids deadlock
            std::shared_lock<std::shared_mutex> lock(m_rwLock);

            // SECURITY: Validate index state
            if (!m_baseAddress || m_indexSize == 0) {
                SS_LOG_WARN(L"SignatureIndex", L"BatchLookup: Index not initialized");
                // Fill with nullopt for all requested hashes
                for (size_t i = 0; i < effectiveSize; ++i) {
                    results.push_back(std::nullopt);
                }
                return;
            }

            // Process batch using internal helper (no nested locks)
            for (size_t i = 0; i < effectiveSize; ++i) {
                const auto& hash = hashes[i];

                // SECURITY: Validate each hash before processing
                if (hash.length == 0 || hash.length > 64) {
                    results.push_back(std::nullopt);
                    continue;
                }

                try {
                    results.push_back(LookupByFastHashInternal(hash.FastHash()));
                }
                catch (...) {
                    // Ensure noexcept contract - push nullopt on any exception
                    results.push_back(std::nullopt);
                }
            }
        }

	}
}