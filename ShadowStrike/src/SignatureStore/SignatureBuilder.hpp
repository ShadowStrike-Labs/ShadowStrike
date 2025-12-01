/*
 * ============================================================================
 * ShadowStrike SignatureBuilder - SIGNATURE COMPILATION & OPTIMIZATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Advanced signature compilation and database building system
 * Optimizes signature layout for maximum performance
 * Handles deduplication, indexing, and compression
 *
 * Build Pipeline:
 * ????????????????????????????????????????????????????
 * ? 1. Input Sources (hashes, patterns, YARA)       ?
 * ????????????????????????????????????????????????????
 * ? 2. Deduplication & Validation                    ?
 * ????????????????????????????????????????????????????
 * ? 3. Optimization (entropy, frequency analysis)    ?
 * ????????????????????????????????????????????????????
 * ? 4. Index Construction (B+Tree, Trie)            ?
 * ????????????????????????????????????????????????????
 * ? 5. Layout Optimization (cache locality)         ?
 * ????????????????????????????????????????????????????
 * ? 6. Serialization (memory-mapped format)         ?
 * ????????????????????????????????????????????????????
 * ? 7. Integrity (SHA-256 checksum)                 ?
 * ????????????????????????????????????????????????????
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once

#include "SignatureFormat.hpp"
#include"../Utils/StringUtils.hpp"
#include"../Utils/JSONUtils.hpp"
#include "HashStore.hpp"
#include "PatternStore.hpp"
#include "YaraRuleStore.hpp"
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <map>
#include <set>

namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// BUILD CONFIGURATION
// ============================================================================

struct BuildConfiguration {
    // Output settings
    std::wstring outputPath;
    uint64_t initialDatabaseSize{500 * 1024 * 1024};      // 500MB default
    bool overwriteExisting{false};
    
    // Optimization flags
    bool enableDeduplication{true};
    bool enableCompression{false};                        // Reserved for future
    bool enableEntropyOptimization{true};                 // Sort patterns by entropy
    bool enableFrequencyOptimization{true};               // Sort by hit frequency
    bool enableCacheAlignment{true};                      // Align hot data to cache lines
    
    // Validation
    bool strictValidation{true};                          // Fail on invalid signatures
    bool validateChecksums{true};                         // Verify input data integrity
    
    // Threading
    uint32_t threadCount{0};                              // 0 = auto-detect
    
    // Progress reporting
    std::function<void(const std::string& stage, size_t current, size_t total)> progressCallback;
    
    // Logging
    std::function<void(const std::string& message)> logCallback;
    
    // Advanced
    uint32_t btreeOrder{BTREE_ORDER};                     // B+Tree node order
    uint32_t bloomFilterElements{1'000'000};              // Expected hash count
    double bloomFilterFPR{0.01};                          // False positive rate
};


// ============================================================================
// BUILD STATISTICS
// ============================================================================

struct BuildStatistics {
    // Input counts
    uint64_t totalHashesAdded{0};
    uint64_t totalPatternsAdded{0};
    uint64_t totalYaraRulesAdded{0};
    
    // Processing results
    uint64_t duplicatesRemoved{0};
    uint64_t invalidSignaturesSkipped{0};
    uint64_t optimizedSignatures{0};
    
    // Output stats
    uint64_t finalDatabaseSize{0};
    uint64_t hashIndexSize{0};
    uint64_t patternIndexSize{0};
    uint64_t yaraRulesSize{0};
    uint64_t metadataSize{0};
    
    // Performance
    uint64_t totalBuildTimeMilliseconds{0};
    uint64_t indexBuildTimeMilliseconds{0};
    uint64_t optimizationTimeMilliseconds{0};
    uint64_t serializationTimeMilliseconds{0};
    
    // Compression (if enabled)
    double compressionRatio{1.0};
};

// ============================================================================
// SIGNATURE INPUT SOURCES
// ============================================================================

// Hash signature input
struct HashSignatureInput {
    HashValue hash;
    std::string name;
    ThreatLevel threatLevel;
    std::string description;
    std::vector<std::string> tags;
    std::string source;                                   // Origin (file, URL, etc.)
};

// Pattern signature input
struct PatternSignatureInput {
    std::string patternString;                            // Hex pattern string
    std::string name;
    ThreatLevel threatLevel;
    std::string description;
    std::vector<std::string> tags;
    std::string source;
};

// YARA rule input
struct YaraRuleInput {
    std::string ruleSource;                               // YARA rule source code
    std::string namespace_;
    std::string source;                                   // File path or identifier
};

// ============================================================================
// SIGNATURE BUILDER (Main Interface)
// ============================================================================

class SignatureBuilder {
public:
    SignatureBuilder();
    explicit SignatureBuilder(const BuildConfiguration& config);
    ~SignatureBuilder();

    // Disable copy, enable move
    SignatureBuilder(const SignatureBuilder&) = delete;
    SignatureBuilder& operator=(const SignatureBuilder&) = delete;
    SignatureBuilder(SignatureBuilder&&) noexcept = default;
    SignatureBuilder& operator=(SignatureBuilder&&) noexcept = default;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    // Set build configuration
    void SetConfiguration(const BuildConfiguration& config) noexcept;

    // Get current configuration
    [[nodiscard]] const BuildConfiguration& GetConfiguration() const noexcept {
        return m_config;
    }

    // ========================================================================
    // INPUT METHODS (Add Signatures)
    // ========================================================================

    // Add hash signature
    [[nodiscard]] StoreError AddHash(
        const HashSignatureInput& input
    ) noexcept;

    // Add hash signature (simple overload)
    [[nodiscard]] StoreError AddHash(
        const HashValue& hash,
        const std::string& name,
        ThreatLevel threatLevel
    ) noexcept;

    // Add multiple hashes
    [[nodiscard]] StoreError AddHashBatch(
        std::span<const HashSignatureInput> inputs
    ) noexcept;

    // Add pattern signature
    [[nodiscard]] StoreError AddPattern(
        const PatternSignatureInput& input
    ) noexcept;

    // Add pattern signature (simple overload)
    [[nodiscard]] StoreError AddPattern(
        const std::string& patternString,
        const std::string& name,
        ThreatLevel threatLevel
    ) noexcept;

    // Add multiple patterns
    [[nodiscard]] StoreError AddPatternBatch(
        std::span<const PatternSignatureInput> inputs
    ) noexcept;

    // Add YARA rule
    [[nodiscard]] StoreError AddYaraRule(
        const YaraRuleInput& input
    ) noexcept;

    // Add YARA rule (simple overload)
    [[nodiscard]] StoreError AddYaraRule(
        const std::string& ruleSource,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Add multiple YARA rules
    [[nodiscard]] StoreError AddYaraRuleBatch(
        std::span<const YaraRuleInput> inputs
    ) noexcept;

    // ========================================================================
    // IMPORT METHODS (From External Sources)
    // ========================================================================

    // Import hashes from text file (format: TYPE:HASH:NAME:LEVEL)
    [[nodiscard]] StoreError ImportHashesFromFile(
        const std::wstring& filePath
    ) noexcept;

    // Import hashes from JSON
    [[nodiscard]] StoreError ImportHashesFromJson(
        const std::string& jsonData
    ) noexcept;

    // Import hashes from CSV
    [[nodiscard]] StoreError ImportHashesFromCsv(
        const std::wstring& filePath,
        char delimiter = ','
    ) noexcept;

    // Import patterns from text file
    [[nodiscard]] StoreError ImportPatternsFromFile(
        const std::wstring& filePath
    ) noexcept;

    // Import patterns from ClamAV signature file
    [[nodiscard]] StoreError ImportPatternsFromClamAV(
        const std::wstring& filePath
    ) noexcept;

    // Import YARA rules from file
    [[nodiscard]] StoreError ImportYaraRulesFromFile(
        const std::wstring& filePath,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Import YARA rules from directory (recursive)
    [[nodiscard]] StoreError ImportYaraRulesFromDirectory(
        const std::wstring& directoryPath,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Import from existing database (merge)
    [[nodiscard]] StoreError ImportFromDatabase(
        const std::wstring& databasePath
    ) noexcept;

    // ========================================================================
    // BUILD PROCESS
    // ========================================================================

    // Execute full build pipeline
    [[nodiscard]] StoreError Build() noexcept;

    // Build individual stages (for fine-grained control)
    [[nodiscard]] StoreError ValidateInputs() noexcept;
    [[nodiscard]] StoreError Deduplicate() noexcept;
    [[nodiscard]] StoreError Optimize() noexcept;
    [[nodiscard]] StoreError BuildIndices() noexcept;
    [[nodiscard]] StoreError Serialize() noexcept;
    [[nodiscard]] StoreError ComputeChecksum() noexcept;

    // ========================================================================
    // QUERY METHODS (Before Build)
    // ========================================================================

    // Get pending signature counts
    [[nodiscard]] size_t GetPendingHashCount() const noexcept;
    [[nodiscard]] size_t GetPendingPatternCount() const noexcept;
    [[nodiscard]] size_t GetPendingYaraRuleCount() const noexcept;

    // Check if signature already exists (deduplication check)
    [[nodiscard]] bool HasHash(const HashValue& hash) const noexcept;
    [[nodiscard]] bool HasPattern(const std::string& patternString) const noexcept;
    [[nodiscard]] bool HasYaraRule(const std::string& ruleName) const noexcept;

    // ========================================================================
    // STATISTICS & MONITORING
    // ========================================================================

    // Get build statistics
    [[nodiscard]] const BuildStatistics& GetStatistics() const noexcept {
        return m_statistics;
    }

    // Reset builder state (clear all inputs)
    void Reset() noexcept;

    // Get current build stage
    [[nodiscard]] std::string GetCurrentStage() const noexcept;

    // Check if build is in progress
    [[nodiscard]] bool IsBuildInProgress() const noexcept {
        return m_buildInProgress.load(std::memory_order_acquire);
    }

    // ========================================================================
    // VALIDATION & TESTING
    // ========================================================================

    // Validate built database
    [[nodiscard]] StoreError ValidateOutput(
        const std::wstring& databasePath
    ) const noexcept;

    // Test database performance
    struct PerformanceMetrics {
        uint64_t averageHashLookupNanoseconds{0};
        uint64_t averagePatternScanMicroseconds{0};
        uint64_t averageYaraScanMilliseconds{0};
        double hashLookupThroughputPerSecond{0.0};
        double patternScanThroughputMBps{0.0};
    };

    [[nodiscard]] PerformanceMetrics BenchmarkDatabase(
        const std::wstring& databasePath
    ) const noexcept;

    bool ValidateDatabaseChecksum(const std::wstring& databasePath) noexcept;

    bool ValidatePatternSyntax(
        const std::string& pattern,
        std::string& errorMessage
    ) noexcept;

    bool IsRegexSafe(
        const std::string& pattern,
        std::string& errorMessage
    ) noexcept;

    bool IsYaraRuleSafe(
        const std::string& ruleSource,
        std::string& errorMessage
    ) noexcept;

    bool TestYaraRuleCompilation(
        const std::string& ruleSource,
        const std::string& namespace_,
        std::vector<std::string>& errors
    ) noexcept;

    // ========================================================================
    // ADVANCED FEATURES
    // ========================================================================

    // Set custom deduplication function
    using DeduplicationFunc = std::function<bool(const HashValue&, const HashValue&)>;
    void SetCustomDeduplication(DeduplicationFunc func) noexcept;

    // Set custom optimization function
    using OptimizationFunc = std::function<void(std::vector<HashSignatureInput>&)>;
    void SetCustomOptimization(OptimizationFunc func) noexcept;

    // Enable incremental build (update existing database)
    void SetIncrementalMode(bool enabled) noexcept {
        m_incrementalMode = enabled;
    }

    // Set build priority (thread priority)
    void SetBuildPriority(int priority) noexcept;

    //CRC64 for checking integrity.
    uint64_t ComputeCRC64(const uint8_t* data, size_t length);

    // CRC64-ECMA polynomial
    static constexpr uint64_t CRC64_POLY = 0x42F0E1EBA9EA3693ULL;

    //Public helpers
    
    // Compute hash of file
    [[nodiscard]] std::optional<HashValue> ComputeFileHash(
        const std::wstring& filePath,
        HashType type
    ) const noexcept;

    // Compute hash of memory buffer
    [[nodiscard]] std::optional<HashValue> ComputeBufferHash(
        std::span<const uint8_t> buffer,
        HashType type
    ) const noexcept;

    // Compare two hashes for equality
    [[nodiscard]] bool CompareHashes(
        const HashValue& a,
        const HashValue& b
    ) const noexcept;

    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};
    LARGE_INTEGER m_buildStartTime{};


private:

    // ========================================================================
   // TRIE SERIALIZATION HELPERS (Private)
   // ========================================================================

   // Helper structure for building trie in memory before serialization
    struct TrieNodeMemory {
        std::array<uint32_t, 256> childOffsets{};        // Offsets or 0
        uint32_t failureLinkOffset{ 0 };                   // Offset or 0
        std::vector<uint64_t> outputs;                   // Pattern IDs at this node
        uint32_t depth{ 0 };
        uint64_t diskOffset{ 0 };                          // Will be calculated during serialization
    };

    // Serialize Aho-Corasick automaton to disk trie format
    [[nodiscard]] StoreError SerializeAhoCorasickToDisk(
        uint64_t& currentOffset
    ) noexcept;

    // Write single trie node to disk
    [[nodiscard]] StoreError WriteTrieNodeToDisk(
        const TrieNodeMemory& nodeMemory,
        uint64_t diskOffset
    ) noexcept;

    // Build output pattern ID pool
    [[nodiscard]] StoreError BuildOutputPool(
        uint64_t poolOffset
    ) noexcept;
    // ========================================================================
    // INTERNAL BUILD STAGES
    // ========================================================================

    [[nodiscard]] StoreError ValidateHashInputs() noexcept;
    [[nodiscard]] StoreError ValidatePatternInputs() noexcept;
    [[nodiscard]] StoreError ValidateYaraInputs() noexcept;

    [[nodiscard]] StoreError DeduplicateHashes() noexcept;
    [[nodiscard]] StoreError DeduplicatePatterns() noexcept;
    [[nodiscard]] StoreError DeduplicateYaraRules() noexcept;

    [[nodiscard]] StoreError OptimizeHashes() noexcept;
    [[nodiscard]] StoreError OptimizePatterns() noexcept;
    [[nodiscard]] StoreError OptimizeYaraRules() noexcept;

    [[nodiscard]] StoreError BuildHashIndex() noexcept;
    [[nodiscard]] StoreError BuildPatternIndex() noexcept;
    [[nodiscard]] StoreError BuildYaraIndex() noexcept;

    [[nodiscard]] StoreError SerializeHashes() noexcept;
    [[nodiscard]] StoreError SerializePatterns() noexcept;
    [[nodiscard]] StoreError SerializeYaraRules() noexcept;
    [[nodiscard]] StoreError SerializeMetadata() noexcept;
    [[nodiscard]] StoreError SerializeHeader() noexcept;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    [[nodiscard]] uint64_t CalculateRequiredSize() const noexcept;
    [[nodiscard]] std::array<uint8_t, 16> GenerateDatabaseUUID() const noexcept;
    [[nodiscard]] std::array<uint8_t, 32> ComputeDatabaseChecksum() const noexcept;

    void ReportProgress(
        const std::string& stage,
        size_t current,
        size_t total
    ) const noexcept;

    void Log(const std::string& message) const noexcept;

    [[nodiscard]] static uint64_t GetCurrentTimestamp() noexcept;

    std::atomic<uint32_t> m_consecutiveDuplicates{ 0 };  // Track duplicate rate
  
    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    BuildConfiguration m_config;
    BuildStatistics m_statistics{};

    // Input collections
    std::vector<HashSignatureInput> m_pendingHashes;
    std::vector<PatternSignatureInput> m_pendingPatterns;
    std::vector<YaraRuleInput> m_pendingYaraRules;

    // Deduplication sets (for fast lookup)
    std::set<uint64_t> m_hashFingerprints;                // Hash of hash values
    std::set<std::string> m_patternFingerprints;          // Pattern strings
    std::set<std::string> m_yaraRuleNames;                // Rule names

    // Output file
    HANDLE m_outputFile{INVALID_HANDLE_VALUE};
    HANDLE m_outputMapping{INVALID_HANDLE_VALUE};
    void* m_outputBase{nullptr};
    uint64_t m_outputSize{0};
    uint64_t m_currentOffset{0};

    // Build state
    std::atomic<bool> m_buildInProgress{false};
    std::string m_currentStage;
    mutable std::shared_mutex m_stateMutex;

    // Custom functions
    DeduplicationFunc m_customDeduplication;
    OptimizationFunc m_customOptimization;

    // Configuration flags
    bool m_incrementalMode{false};


};

class BatchSignatureBuilder {
public:
    BatchSignatureBuilder();
    explicit BatchSignatureBuilder(const BuildConfiguration& config);
    ~BatchSignatureBuilder();

    // Add multiple source files
    [[nodiscard]] StoreError AddSourceFiles(
        std::span<const std::wstring> filePaths
    ) noexcept;

    // Add source directory (recursive scan)
    [[nodiscard]] StoreError AddSourceDirectory(
        const std::wstring& directoryPath,
        bool recursive = true
    ) noexcept;

    // Execute batch build with parallel processing
    [[nodiscard]] StoreError BuildParallel() noexcept;

    // Get progress information
    struct BatchError {
        std::wstring filePath;
        std::string errorMessage;
    };

    struct BatchProgress {
        size_t totalFiles{ 0 };
        size_t processedFiles{ 0 };
        size_t successfulFiles{ 0 };
        size_t failedFiles{ 0 };
        std::vector<BatchError> errors;
    };

    [[nodiscard]] BatchProgress GetProgress() const noexcept;

private:
    BuildConfiguration m_config;
    SignatureBuilder m_builder;
    std::vector<std::wstring> m_sourceFiles;
    BatchProgress m_progress{};
    mutable std::mutex m_progressMutex;
};



// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace BuilderUtils {

// Parse hash signature line (format: TYPE:HASH:NAME:LEVEL)
[[nodiscard]] std::optional<HashSignatureInput> ParseHashLine(
    const std::string& line
) noexcept;

// Parse pattern signature line
[[nodiscard]] std::optional<PatternSignatureInput> ParsePatternLine(
    const std::string& line
) noexcept;

// Detect file format (hash, pattern, YARA, etc.)
enum class FileFormat {
    Unknown,
    HashList,
    PatternList,
    YaraRules,
    ClamAV,
    JSON,
    CSV
};

[[nodiscard]] FileFormat DetectFileFormat(
    const std::wstring& filePath
) noexcept;



} // namespace BuilderUtils

} // namespace SignatureStore
} // namespace ShadowStrike
