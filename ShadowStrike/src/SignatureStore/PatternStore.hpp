/*
 * ============================================================================
 * ShadowStrike PatternStore - HIGH-SPEED BYTE PATTERN MATCHER
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
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

#include "SignatureFormat.hpp"
#include "SignatureIndex.hpp"
#include <memory>
#include <vector>
#include <span>
#include<map>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include<chrono>

namespace ShadowStrike {
    namespace SignatureStore {

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

            // Disable copy, enable move
            PatternStore(const PatternStore&) = delete;
            PatternStore& operator=(const PatternStore&) = delete;
            PatternStore(PatternStore&&) noexcept = default;
            PatternStore& operator=(PatternStore&&) noexcept = default;

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

            // Import from ClamAV signature format
            [[nodiscard]] StoreError ImportFromClamAV(
                const std::wstring& filePath
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

    // Rebuild automaton (optimize after many updates)
    [[nodiscard]] StoreError Rebuild() noexcept;

    // Optimize pattern order by hit frequency
    [[nodiscard]] StoreError OptimizeByHitRate() noexcept;

    // Verify database integrity
    [[nodiscard]] StoreError Verify(
        std::function<void(const std::string&)> logCallback = nullptr
    ) const noexcept;

    // Flush changes to disk
    [[nodiscard]] StoreError Flush() noexcept;

    // Compact database (remove fragmentation)
    [[nodiscard]] StoreError Compact() noexcept;

    // ========================================================================
    // ADVANCED FEATURES
    // ========================================================================

    // Enable/disable SIMD acceleration
    void SetSIMDEnabled(bool enabled) noexcept {
        m_simdEnabled.store(enabled, std::memory_order_release);
    }

    // Set scan buffer size (for file scanning)
    void SetScanBufferSize(size_t bytes) noexcept {
        m_scanBufferSize = bytes;
    }

    // Enable pattern heatmap tracking
    void SetHeatmapEnabled(bool enabled) noexcept {
        m_heatmapEnabled.store(enabled, std::memory_order_release);
    }

    // Get pattern hit heatmap (for optimization)
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

    [[nodiscard]] std::vector<DetectionResult> ScanWithAutomaton(
        std::span<const uint8_t> buffer,
        const QueryOptions& options
    ) const noexcept;

    [[nodiscard]] std::vector<DetectionResult> ScanWithSIMD(
        std::span<const uint8_t> buffer,
        const QueryOptions& options
    ) const noexcept;

    [[nodiscard]] DetectionResult BuildDetectionResult(
        uint64_t patternId,
        size_t offset,
        uint64_t matchTimeNs
    ) const noexcept;

    void UpdateHitCount(uint64_t patternId) noexcept;

    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    std::wstring m_databasePath;
    MemoryMappedView m_mappedView{};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_readOnly{true};

    // Pattern index and automaton
    std::unique_ptr<PatternIndex> m_patternIndex;
    std::unique_ptr<AhoCorasickAutomaton> m_automaton;

    // Pattern metadata cache
    struct PatternMetadata {
        uint64_t signatureId;
        std::string name;
        ThreatLevel threatLevel;
        PatternMode mode;
        std::vector<uint8_t> pattern;
        std::vector<uint8_t> mask;
        float entropy;
        uint32_t hitCount;
        std::string description;                    // Threat description
        std::vector<std::string> tags;              // Classification tags
        std::chrono::system_clock::time_point created;      // Creation timestamp
        std::chrono::system_clock::time_point lastModified; // Last update
        uint32_t modificationCount = 0;             // Change counter
        bool isDeprecated = false;                  // Deprecation flag
        std::string deprecationReason;              // Why deprecated
    };
   mutable std::vector<PatternMetadata> m_patternCache;
   
    // Lock-free hit counters for thread-safe updates during scanning
    // Indexed by signatureId, resized when patterns are added
    mutable std::vector<std::atomic<uint64_t>> m_hitCounters;

    // Statistics
    mutable std::atomic<uint64_t> m_totalScans{0};
    mutable std::atomic<uint64_t> m_totalMatches{0};
    mutable std::atomic<uint64_t> m_totalBytesScanned{0};

    // Configuration
    std::atomic<bool> m_simdEnabled{true};
    std::atomic<bool> m_heatmapEnabled{true};
    size_t m_scanBufferSize{4 * 1024 * 1024};            // 4MB default

    // Synchronization
    mutable std::shared_mutex m_globalLock;

    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace PatternUtils {

// Validate pattern string syntax
[[nodiscard]] bool IsValidPatternString(
    const std::string& pattern,
    std::string& errorMessage
) noexcept;

// Convert hex string to bytes
[[nodiscard]] std::optional<std::vector<uint8_t>> HexStringToBytes(
    const std::string& hexStr
) noexcept;

// Convert bytes to hex string
[[nodiscard]] std::string BytesToHexString(
    std::span<const uint8_t> bytes
) noexcept;

// Calculate Hamming distance between patterns
[[nodiscard]] size_t HammingDistance(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b
) noexcept;

} // namespace PatternUtils

} // namespace SignatureStore
} // namespace ShadowStrike
