/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/*
 * ============================================================================
 * ShadowStrike PatternStore - HIGH-SPEED BYTE PATTERN MATCHER
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 *
 * Ultra-fast byte pattern matching engine
 * Optimized Boyer-Moore-Horspool with SIMD acceleration
 * Target: < 10ms for 10MB file scan with 10,000 patterns
 *
 * Supported Pattern Types:
 * - Exact byte sequences
 * - Wildcard patterns (? = any byte)
 * - Byte masks (XX & MASK == VALUE)
 * - Regular expressions (limited, slower)
 *
 * Optimizations:
 * - Multi-pattern Aho-Corasick automaton
 * - SIMD (AVX2/AVX-512) for exact patterns
 * - Boyer-Moore skip tables for wildcards
 * - Pattern length histogram for quick rejection
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once

#include "../SignatureStore/SignatureFormat.hpp"
#include "../SignatureStore/SignatureIndex.hpp"
#include <memory>
#include <vector>
#include <span>
#include<map>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include<chrono>

namespace ShadowStrike {
    namespace PatternStore {

        // Import specific types from SignatureStore namespace
        // (explicit using-declarations to avoid polluting every includer)
        using ShadowStrike::SignatureStore::StoreError;
        using ShadowStrike::SignatureStore::SignatureStoreError;
        using ShadowStrike::SignatureStore::DetectionResult;
        using ShadowStrike::SignatureStore::ThreatLevel;
        using ShadowStrike::SignatureStore::PatternMode;
        using ShadowStrike::SignatureStore::QueryOptions;
        using ShadowStrike::SignatureStore::MemoryMappedView;
        using ShadowStrike::SignatureStore::SignatureDatabaseHeader;
        using ShadowStrike::SignatureStore::PatternIndex;

        // Format types the pattern load path reads out of the mapped database.
        using ShadowStrike::SignatureStore::PatternEntry;
        using ShadowStrike::SignatureStore::TrieIndexHeader;
        using ShadowStrike::SignatureStore::TRIE_INDEX_MAGIC;
        using ShadowStrike::SignatureStore::TRIE_INDEX_VERSION;
        namespace PatternEntryFlags = ShadowStrike::SignatureStore::PatternEntryFlags;

        // Database-format constants — referenced by PatternStore.cpp
        using ShadowStrike::SignatureStore::SIGNATURE_DB_MAGIC;
        using ShadowStrike::SignatureStore::SIGNATURE_DB_VERSION_MAJOR;
        using ShadowStrike::SignatureStore::SIGNATURE_DB_VERSION_MINOR;

        // Namespace aliases for Format and MemoryMapping utilities
        namespace Format       = ShadowStrike::SignatureStore::Format;
        namespace MemoryMapping = ShadowStrike::SignatureStore::MemoryMapping;

        // ============================================================================
        // AHO-CORASICK AUTOMATON (Multi-Pattern Matching)
        // ============================================================================

        class AhoCorasickAutomaton {
        public:
            AhoCorasickAutomaton() = default;
            ~AhoCorasickAutomaton();

            // Disable copy, enable move
            AhoCorasickAutomaton(const AhoCorasickAutomaton&) = delete;
            AhoCorasickAutomaton& operator=(const AhoCorasickAutomaton&) = delete;
            AhoCorasickAutomaton(AhoCorasickAutomaton&&) noexcept = default;
            AhoCorasickAutomaton& operator=(AhoCorasickAutomaton&&) noexcept = default;

            // ========================================================================
            // CONSTRUCTION
            // ========================================================================

            // Add pattern to automaton (before compilation)
            bool AddPattern(
                std::span<const uint8_t> pattern,
                uint64_t patternId
            ) noexcept;

            // Compile automaton (compute failure links)
            [[nodiscard]] bool Compile() noexcept;

            // Clear all patterns
            void Clear() noexcept;

            // ========================================================================
            // SEARCH
            // ========================================================================

            // Search buffer and invoke callback for each match
            void Search(
                std::span<const uint8_t> buffer,
                std::function<void(uint64_t patternId, size_t offset)> callback
            ) const noexcept;

            // Count matches without callback overhead
            [[nodiscard]] size_t CountMatches(
                std::span<const uint8_t> buffer
            ) const noexcept;

            // ========================================================================
            // STATISTICS
            // ========================================================================

            [[nodiscard]] size_t GetPatternCount() const noexcept { return m_patternCount; }
            [[nodiscard]] size_t GetNodeCount() const noexcept { return m_nodeCount; }
            [[nodiscard]] bool IsCompiled() const noexcept { return m_compiled; }

        private:
            struct ACNode {
                std::array<uint32_t, 256> children{};             // Byte -> child node
                uint32_t failureLink{ 0 };                          // Failure transition
                std::vector<uint64_t> outputs;                    // Matched pattern IDs
                uint32_t depth{ 0 };
            };

            std::vector<ACNode> m_nodes;
            size_t m_patternCount{ 0 };
            size_t m_nodeCount{ 0 };
            bool m_compiled{ false };

            void BuildFailureLinks() noexcept;
        };

        // ============================================================================
        // BOYER-MOORE MATCHER (Single Pattern with Wildcards)
        // ============================================================================

        class BoyerMooreMatcher {
        public:
            explicit BoyerMooreMatcher(
                std::span<const uint8_t> pattern,
                std::span<const uint8_t> mask = {}               // Optional byte mask
            ) noexcept;

            ~BoyerMooreMatcher() = default;

            // Search buffer for pattern
            [[nodiscard]] std::vector<size_t> Search(
                std::span<const uint8_t> buffer
            ) const noexcept;

            // Find first occurrence only (faster)
            [[nodiscard]] std::optional<size_t> FindFirst(
                std::span<const uint8_t> buffer
            ) const noexcept;

            // True when construction produced a usable matcher.
            //
            // The constructor clears its own state on any failure (allocation, a mask
            // whose size cannot be reconciled with the pattern, a good-suffix table
            // that did not build), and Search/FindFirst then return nothing. Without
            // this accessor a matcher that failed to build is indistinguishable from
            // one that found no match, so a pattern could be counted as scanned while
            // no scan of it was ever possible.
            //
            // The conditions checked here are exactly the invariants Search() tests
            // before it does any work, deliberately: if they diverge, this would report
            // healthy for a matcher that refuses to run.
            [[nodiscard]] bool IsValid() const noexcept {
                return !m_pattern.empty()
                    && m_mask.size() == m_pattern.size()
                    && m_goodSuffixTable.size() == m_pattern.size();
            }

        private:
            std::vector<uint8_t> m_pattern;
            std::vector<uint8_t> m_mask;
            std::array<size_t, 256> m_badCharTable{};            // Bad character shift table
            std::vector<size_t> m_goodSuffixTable;               // Good suffix shift table

            void BuildBadCharTable() noexcept;
            void BuildGoodSuffixTable() noexcept;
            [[nodiscard]] bool MatchesAt(
                std::span<const uint8_t> buffer,
                size_t offset
            ) const noexcept;
        };

        // ============================================================================
        // SIMD PATTERN MATCHER (Exact Patterns Only)
        // ============================================================================

        class SIMDMatcher {
        public:
            SIMDMatcher() = default;
            ~SIMDMatcher() = default;

            // Check if SIMD instructions available
            [[nodiscard]] static bool IsAVX2Available() noexcept;
            [[nodiscard]] static bool IsAVX512Available() noexcept;

            // Find pattern using SIMD (AVX2)
            [[nodiscard]] static std::vector<size_t> SearchAVX2(
                std::span<const uint8_t> buffer,
                std::span<const uint8_t> pattern
            ) noexcept;

            // Find pattern using SIMD (AVX-512)
            [[nodiscard]] static std::vector<size_t> SearchAVX512(
                std::span<const uint8_t> buffer,
                std::span<const uint8_t> pattern
            ) noexcept;

            // Find multiple patterns simultaneously (batched SIMD)
            [[nodiscard]] static std::vector<std::pair<size_t, size_t>> SearchMultipleAVX2(
                std::span<const uint8_t> buffer,
                std::span<const std::span<const uint8_t>> patterns
            ) noexcept;
        };

        // ============================================================================
        // PATTERN COMPILER (Pattern String -> Binary)
        // ============================================================================

        class PatternCompiler {
        public:
            // Compile pattern string to binary
            // Format examples:
            //   - "48 8B 05 ?? ?? ?? ??" (hex with wildcards)
            //   - "MZ\x90\x00" (mixed string/hex)
            //   - "{48 8B} [0-4] {C3}" (hex with variable gap)
            [[nodiscard]] static std::optional<std::vector<uint8_t>> CompilePattern(
                const std::string& patternStr,
                PatternMode& outMode,
                std::vector<uint8_t>& outMask
            ) noexcept;

            // Validate pattern syntax
            [[nodiscard]] static bool ValidatePattern(
                const std::string& patternStr,
                std::string& errorMessage
            ) noexcept;

            // Calculate pattern entropy (for optimization)
            [[nodiscard]] static float ComputeEntropy(
                std::span<const uint8_t> pattern
            ) noexcept;
        };

        // ============================================================================
        // PATTERN STORE (Main Interface)
        // ============================================================================

        class PatternStore {
        public:
            PatternStore();
            ~PatternStore();

            // Non-copyable, non-movable (contains std::shared_mutex and std::atomic members)
            PatternStore(const PatternStore&) = delete;
            PatternStore& operator=(const PatternStore&) = delete;
            PatternStore(PatternStore&&) = delete;
            PatternStore& operator=(PatternStore&&) = delete;

            // ========================================================================
            // INITIALIZATION & LIFECYCLE
            // ========================================================================

            // Initialize from database file
            [[nodiscard]] StoreError Initialize(
                const std::wstring& databasePath,
                bool readOnly = true
            ) noexcept;

            // Create new database
            [[nodiscard]] StoreError CreateNew(
                const std::wstring& databasePath,
                uint64_t initialSizeBytes = 100 * 1024 * 1024
            ) noexcept;

            // Close database
            void Close() noexcept;

            [[nodiscard]] bool IsInitialized() const noexcept {
                return m_initialized.load(std::memory_order_acquire);
            }

            // ========================================================================
            // PATTERN SEARCH (High Performance)
            // ========================================================================

            // Scan buffer for all matching patterns
            [[nodiscard]] std::vector<DetectionResult> Scan(
                std::span<const uint8_t> buffer,
                const QueryOptions& options = {}
            ) const noexcept;

            // Scan file (memory-mapped for large files)
            [[nodiscard]] std::vector<DetectionResult> ScanFile(
                const std::wstring& filePath,
                const QueryOptions& options = {}
            ) const noexcept;

            // Incremental scan (for streaming data)
            class ScanContext {
            public:
                ScanContext() = default;
                ~ScanContext() = default;

                void Reset() noexcept;

                [[nodiscard]] std::vector<DetectionResult> FeedChunk(
                    std::span<const uint8_t> chunk
                ) noexcept;

                [[nodiscard]] std::vector<DetectionResult> Finalize() noexcept;

            private:
                friend class PatternStore;
                // LIFETIME CONTRACT: m_store is a non-owning observer pointer.
                // The PatternStore that created this ScanContext MUST outlive it.
                // Destroying the PatternStore while ScanContext is alive is undefined behavior.
                const PatternStore* m_store{ nullptr };
                std::vector<uint8_t> m_buffer;
                size_t m_totalBytesProcessed{ 0 };
                QueryOptions m_options;
            };

            [[nodiscard]] ScanContext CreateScanContext(
                const QueryOptions& options = {}
            ) const noexcept;

            // ========================================================================
            // PATTERN MANAGEMENT
            // ========================================================================

            // Add new pattern
            [[nodiscard]] StoreError AddPattern(
                const std::string& patternStr,
                const std::string& signatureName,
                ThreatLevel threatLevel,
                const std::string& description = "",
                const std::vector<std::string>& tags = {}
            ) noexcept;

            // Add compiled pattern (binary)
            [[nodiscard]] StoreError AddCompiledPattern(
                std::span<const uint8_t> pattern,
                PatternMode mode,
                std::span<const uint8_t> mask,
                const std::string& signatureName,
                ThreatLevel threatLevel
            ) noexcept;

            // Add multiple patterns (bulk import)
            [[nodiscard]] StoreError AddPatternBatch(
                std::span<const std::string> patternStrs,
                std::span<const std::string> signatureNames,
                std::span<const ThreatLevel> threatLevels
            ) noexcept;

            // Remove pattern
            [[nodiscard]] StoreError RemovePattern(
                uint64_t signatureId
            ) noexcept;

            // Update pattern metadata
            [[nodiscard]] StoreError UpdatePatternMetadata(
                uint64_t signatureId,
                const std::string& newDescription,
                const std::vector<std::string>& newTags
            ) noexcept;

            // ========================================================================
            // IMPORT/EXPORT
            // ========================================================================

            // Import patterns from YARA-style file
            [[nodiscard]] StoreError ImportFromYaraFile(
                const std::wstring& filePath,
                std::function<void(size_t current, size_t total)> progressCallback = nullptr
            ) noexcept;

            // Export patterns to JSON
            [[nodiscard]] std::string ExportToJson(
                uint32_t maxEntries = UINT32_MAX
            ) const noexcept;

            // ========================================================================
            // STATISTICS & MONITORING
            // ========================================================================

            struct PatternStoreStatistics {
                uint64_t totalPatterns{ 0 };
                uint64_t exactPatterns{ 0 };
                uint64_t wildcardPatterns{ 0 };
                uint64_t regexPatterns{ 0 };
                uint64_t totalScans{ 0 };
                uint64_t totalMatches{ 0 };
                uint64_t averageScanTimeMicroseconds{ 0 };
                uint64_t peakScanTimeMicroseconds{ 0 };
                uint64_t totalBytesScanned{ 0 };
                double averageThroughputMBps{ 0.0 };
                size_t automatonNodeCount{ 0 };
            };

            // Alias for cross-module integration (SignatureStore.hpp uses PatternStore::StoreStatistics)
            using StoreStatistics = PatternStoreStatistics;

            [[nodiscard]] PatternStoreStatistics GetStatistics() const noexcept;
            void ResetStatistics() noexcept;

            // Get pattern distribution by length
            [[nodiscard]] std::map<size_t, size_t> GetLengthHistogram() const noexcept;

            [[nodiscard]] std::wstring GetDatabasePath() const noexcept;

            // Get database header
            [[nodiscard]] const SignatureDatabaseHeader* GetHeader() const noexcept;

            // ========================================================================
            // OPTIMIZATION & MAINTENANCE
            // ========================================================================

            [[nodiscard]] StoreError Rebuild() noexcept;
            [[nodiscard]] StoreError OptimizeByHitRate() noexcept;

            [[nodiscard]] StoreError Verify(
                std::function<void(const std::string&)> logCallback = nullptr
            ) const noexcept;

            [[nodiscard]] StoreError Flush() noexcept;
            [[nodiscard]] StoreError Compact() noexcept;

            // ========================================================================
            // ADVANCED FEATURES
            // ========================================================================

            void SetSIMDEnabled(bool enabled) noexcept {
                m_simdEnabled.store(enabled, std::memory_order_release);
            }

            // Set scan buffer size (clamped to [64KB, 1GB])
            void SetScanBufferSize(size_t bytes) noexcept {
                constexpr size_t kMin = 64 * 1024;
                constexpr size_t kMax = 1024ULL * 1024ULL * 1024ULL;
                if (bytes < kMin) bytes = kMin;
                if (bytes > kMax) bytes = kMax;
                m_scanBufferSize.store(bytes, std::memory_order_release);
            }

            void SetHeatmapEnabled(bool enabled) noexcept {
                m_heatmapEnabled.store(enabled, std::memory_order_release);
            }

            [[nodiscard]] std::vector<std::pair<uint64_t, uint32_t>> GetHeatmap() const noexcept;

        private:
            // ========================================================================
            // INTERNAL METHODS
            // ========================================================================

            [[nodiscard]] StoreError OpenMemoryMapping(
                const std::wstring& path,
                bool readOnly
            ) noexcept;

            void CloseMemoryMapping() noexcept;

            [[nodiscard]] StoreError BuildAutomaton() noexcept;

            // Populate m_patternCache from the PatternEntry array in the mapped
            // database. Called from Initialize BEFORE BuildAutomaton.
            //
            // This is deliberately an internal path rather than a loop over
            // AddCompiledPattern: AddCompiledPattern refuses on a read-only store, and
            // a store opened read-only is exactly the case that must load. Loading is
            // not a mutation of the database, it is the act of reading it.
            //
            // Caller must NOT hold m_globalLock; this takes it exclusively.
            [[nodiscard]] StoreError LoadPatternsFromDatabase() noexcept;

            // Internal flush without locking (caller must hold appropriate lock)
            [[nodiscard]] StoreError FlushInternal() noexcept;

            // Single O(bytes) pass over every exact pattern.
            //
            // outServedExactPatterns reports whether a compiled automaton was actually
            // available and used. It exists because the caller must decide whether to
            // run the per-pattern fallback, and it cannot answer that by inspecting
            // m_automaton itself: reading that pointer outside this function's lock is
            // the race this signature was introduced to remove, and an empty result set
            // does not distinguish "no automaton" from "no matches".
            [[nodiscard]] std::vector<DetectionResult> ScanWithAutomaton(
                std::span<const uint8_t> buffer,
                const QueryOptions& options,
                const LARGE_INTEGER& deadline,
                bool& outServedExactPatterns
            ) const noexcept;

            // Per-pattern AVX2 scan over every exact pattern. This is O(patterns x
            // bytes) and exists ONLY as the fallback for when no compiled automaton is
            // available - see the dispatch comment in Scan(). It is not the default and
            // must not become one again: the automaton answers the same question for
            // every exact pattern in a single O(bytes) pass.
            [[nodiscard]] std::vector<DetectionResult> ScanWithSIMD(
                std::span<const uint8_t> buffer,
                const QueryOptions& options,
                const LARGE_INTEGER& deadline
            ) const noexcept;

            // Scan the patterns the automaton structurally cannot express: those whose
            // bytes carry a mask with wildcard positions (PatternMode::Wildcard and
            // PatternMode::ByteMask). Aho-Corasick keys transitions on exact byte
            // values, so a "match any byte here" position has no edge to follow; that
            // is a property of the algorithm, not a gap in the implementation.
            //
            // Runs IN ADDITION to the automaton pass, never instead of it, because the
            // two cover disjoint sets of patterns. Returns immediately when the store
            // holds no masked patterns, which is the case for all shipped content today.
            [[nodiscard]] std::vector<DetectionResult> ScanWithMaskedPatterns(
                std::span<const uint8_t> buffer,
                const QueryOptions& options,
                const LARGE_INTEGER& deadline
            ) const noexcept;

            // Rebuild m_maskedMatchers from the current cache.
            //
            // Called from BuildAutomaton, which is the single funnel every mutator
            // already goes through (Initialize, AddCompiledPattern, AddPatternBatch,
            // RemovePattern, Rebuild, Compact, OptimizeByHitRate). Building them
            // anywhere else would let the compiled matchers drift out of sync with the
            // cache they were built from, which is the defect shape this store has
            // already produced twice.
            //
            // Caller must hold m_globalLock EXCLUSIVELY.
            void BuildMaskedMatchers() noexcept;

            [[nodiscard]] DetectionResult BuildDetectionResult(
                uint64_t patternId,
                size_t offset,
                uint64_t matchTimeNs
            ) const noexcept;

            [[nodiscard]] bool IsDeadlineExceeded(const LARGE_INTEGER& deadline) const noexcept;

            // ========================================================================
            // INTERNAL STATE
            // ========================================================================

            std::wstring m_databasePath;
            MemoryMappedView m_mappedView{};
            std::atomic<bool> m_initialized{false};
            std::atomic<bool> m_readOnly{true};

            std::unique_ptr<PatternIndex> m_patternIndex;
            std::unique_ptr<AhoCorasickAutomaton> m_automaton;

            // Compiled Boyer-Moore matchers for the masked patterns, one per pattern,
            // built once per rebuild rather than per scan: constructing a matcher builds
            // a 256-entry bad-character table and a good-suffix table, which is work
            // that depends only on the pattern and would otherwise be repeated on every
            // buffer scanned.
            //
            // cacheIndex is the position in m_patternCache, which is what the hit
            // counters and every DetectionResult are keyed by. It is stored explicitly
            // rather than recomputed because this vector is SPARSE with respect to the
            // cache - it holds only the masked subset, so its own index means nothing.
            //
            // Held under m_globalLock exactly like m_automaton: exclusive to rebuild,
            // shared to scan.
            struct MaskedMatcher {
                size_t cacheIndex{ 0 };
                std::unique_ptr<BoyerMooreMatcher> matcher;
            };
            std::vector<MaskedMatcher> m_maskedMatchers;

            struct PatternMetadata {
                // STORE-LOCAL identity, and it is POSITIONAL: signatureId always
                // equals this entry's index in m_patternCache. AddCompiledPattern
                // assigns m_patternCache.size(), and OptimizeByHitRate, Compact and
                // Rebuild all renumber every entry after reordering. The automaton is
                // keyed by that index and ScanWithAutomaton, BuildDetectionResult and
                // the hit counters all index by it.
                //
                // It is therefore NOT the database's PatternEntry::signatureId, which
                // is a stable hash of the pattern name. Storing that value here would
                // be destroyed by the first OptimizeByHitRate pass anyway, and would
                // make every automaton match fail the cache-bounds check in the
                // meantime. The database identity that survives is the NAME, which is
                // loaded and reported.
                uint64_t signatureId;
                std::string name;
                ThreatLevel threatLevel;
                PatternMode mode;
                std::vector<uint8_t> pattern;
                std::vector<uint8_t> mask;
                float entropy;
                uint32_t hitCount;
                std::string description;
                std::vector<std::string> tags;
                std::chrono::system_clock::time_point created;
                std::chrono::system_clock::time_point lastModified;
                uint32_t modificationCount = 0;
                bool isDeprecated = false;
                std::string deprecationReason;
            };
            mutable std::vector<PatternMetadata> m_patternCache;

            // Hit counters: access only under m_globalLock (shared for reads/increments
            // via atomic_ref, exclusive for resize).
            mutable std::vector<uint64_t> m_hitCounters;

            mutable std::atomic<uint64_t> m_totalScans{0};
            mutable std::atomic<uint64_t> m_totalMatches{0};
            mutable std::atomic<uint64_t> m_totalBytesScanned{0};

            std::atomic<bool> m_simdEnabled{true};
            std::atomic<bool> m_heatmapEnabled{true};
            std::atomic<size_t> m_scanBufferSize{4 * 1024 * 1024};

            mutable std::shared_mutex m_globalLock;

            LARGE_INTEGER m_perfFrequency{};
        };

        // Namespace-level alias so consumers can write PatternStore::StoreStatistics
        using StoreStatistics = PatternStore::PatternStoreStatistics;

        // ============================================================================
        // UTILITY FUNCTIONS
        // ============================================================================

        namespace PatternUtils {

        [[nodiscard]] bool IsValidPatternString(
            const std::string& pattern,
            std::string& errorMessage
        ) noexcept;

        [[nodiscard]] std::optional<std::vector<uint8_t>> HexStringToBytes(
            const std::string& hexStr
        ) noexcept;

        [[nodiscard]] std::string BytesToHexString(
            std::span<const uint8_t> bytes
        ) noexcept;

        [[nodiscard]] size_t HammingDistance(
            std::span<const uint8_t> a,
            std::span<const uint8_t> b
        ) noexcept;

        } // namespace PatternUtils

    } // namespace PatternStore
} // namespace ShadowStrike
