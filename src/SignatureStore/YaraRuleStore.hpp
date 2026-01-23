/*
 * ============================================================================
 * ShadowStrike YaraRuleStore - YARA RULE ENGINE INTEGRATION
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * High-performance YARA rule compilation and matching engine
 * Memory-mapped compiled rule storage with zero-copy execution
 * Target: < 50ms for 10MB file scan with 1000 rules
 *
 * Features:
 * - Precompiled YARA rules (avoid runtime compilation overhead)
 * - Memory-mapped rule bytecode (instant loading)
 * - Multi-threaded scanning (parallel rule execution)
 * - Rule dependency resolution
 * - Incremental compilation support
 *
 * Architecture:
 * ????????????????????????????????????????????
 * ? YARA Source Code (.yar files)           ?
 * ????????????????????????????????????????????
 * ? Compilation Layer (libyara)             ?
 * ????????????????????????????????????????????
 * ? Compiled Bytecode (memory-mapped)       ?
 * ????????????????????????????????????????????
 * ? Fast Execution Engine (yr_rules_scan)   ?
 * ????????????????????????????????????????????
 *
 * Performance Standards: Enterprise antivirus quality
 *
 * ============================================================================
 */

#pragma once
#include<yara.h>
#include "SignatureFormat.hpp"

#include <memory>
#include <vector>
#include <string>
#include <span>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <map>
#include <optional>

// YARA library integration (forward declarations to avoid header pollution)


namespace ShadowStrike {
namespace SignatureStore {

// ============================================================================
// TITANIUM RESOURCE LIMITS FOR YARA
// ============================================================================

namespace YaraTitaniumLimits {
    // Buffer size limits
    constexpr size_t MAX_SCAN_BUFFER_SIZE = 500 * 1024 * 1024;      // 500MB max scan buffer
    constexpr size_t MAX_FILE_SIZE = 100 * 1024 * 1024;             // 100MB max file
    constexpr size_t MAX_RULE_SOURCE_SIZE = 10 * 1024 * 1024;       // 10MB max rule source
    constexpr size_t MAX_COMPILED_RULES_SIZE = 500 * 1024 * 1024;   // 500MB max compiled rules
    
    // Stream scanner limits
    constexpr size_t STREAM_SCAN_THRESHOLD = 10 * 1024 * 1024;      // 10MB threshold
    constexpr size_t MAX_STREAM_BUFFER_SIZE = 100 * 1024 * 1024;    // 100MB max stream buffer
    constexpr size_t MAX_SINGLE_CHUNK_SIZE = 50 * 1024 * 1024;      // 50MB max single chunk
    
    // Rule and namespace limits
    constexpr size_t MAX_NAMESPACE_LENGTH = 128;
    constexpr size_t MAX_RULE_NAME_LENGTH = 256;
    constexpr size_t MAX_TAG_LENGTH = 64;
    constexpr size_t MAX_TAGS_PER_RULE = 100;
    
    // Match limits
    constexpr uint32_t DEFAULT_MAX_MATCHES_PER_RULE = 100;
    constexpr uint32_t ABSOLUTE_MAX_MATCHES_PER_RULE = 10000;
    constexpr size_t MAX_MATCH_DATA_CAPTURE = 1024;                 // 1KB max per match
    
    // Timeout limits
    constexpr uint32_t DEFAULT_TIMEOUT_SECONDS = 300;               // 5 minutes
    constexpr uint32_t MIN_TIMEOUT_SECONDS = 1;
    constexpr uint32_t MAX_TIMEOUT_SECONDS = 3600;                  // 1 hour
    
    // Path limits
    constexpr size_t MAX_PATH_LENGTH = 32767;                       // Windows extended path
    
    // Repository import limits
    constexpr size_t MAX_YARA_FILES_IN_REPO = 100000;              // 100K files max
}

// ============================================================================
// YARA RULE METADATA
// ============================================================================

struct YaraRuleMetadata {
    uint64_t ruleId;                                      // Unique identifier
    std::string ruleName;                                 // Rule name (from YARA)
    std::string namespace_;                               // Rule namespace
    std::string author;                                   // Metadata: author
    std::string description;                              // Metadata: description
    std::string reference;                                // Metadata: reference URL
    ThreatLevel threatLevel;                              // Severity
    std::vector<std::string> tags;                        // Rule tags
    uint64_t lastModified;                                // Unix timestamp
    uint32_t compiledSize;                                // Bytecode size
    bool isGlobal;                                        // Global rule flag
    bool isPrivate;                                       // Private rule flag
    
    // Statistics
    uint32_t hitCount{0};                                 // Detection count
    uint64_t averageMatchTimeMicroseconds{0};
};

// ============================================================================
// YARA MATCH RESULT
// ============================================================================

struct YaraMatch {
    uint64_t ruleId;                                      // Matched rule ID
    std::string ruleName;                                 // Rule name
    std::string namespace_;                               // Namespace
    ThreatLevel threatLevel;                              // Severity
    std::vector<std::string> tags;                        // Tags from rule
    
    // Match locations (for string matches)
    struct StringMatch {
        std::string identifier;                           // String identifier ($a, $b, etc.)
        std::vector<uint64_t> offsets;                    // File offsets where matched
        std::vector<std::string> data;                    // Matched data (if requested)
    };
    std::vector<StringMatch> stringMatches;
    
    // Metadata from rule
    std::map<std::string, std::string> metadata;
    
    // Performance metrics
    uint64_t matchTimeMicroseconds{0};
};

// ============================================================================
// YARA SCAN OPTIONS
// ============================================================================

struct YaraScanOptions {
    uint32_t timeoutSeconds{300};                         // Scan timeout (5 min default)
    uint32_t maxMatchesPerRule{100};                      // Prevent DoS
    uint32_t scanFlags{0};                                // YARA scan flags
    bool captureMatchData{false};                         // Store matched strings
    bool fastMode{false};                                 // Stop after first match per rule
    size_t maxFileSizeBytes{100 * 1024 * 1024};          // 100MB default limit
    
    // Threading
    uint32_t threadCount{0};                              // 0 = auto-detect
    
    // Filtering
    ThreatLevel minThreatLevel{ThreatLevel::Info};
    std::vector<std::string> namespaceFilter;             // Only scan these namespaces
    std::vector<std::string> tagFilter;                   // Only scan rules with these tags
};

// ============================================================================
// YARA COMPILER WRAPPER
// ============================================================================

class YaraCompiler {
public:
    YaraCompiler();
    ~YaraCompiler();

    // Disable copy, enable move
    YaraCompiler(const YaraCompiler&) = delete;
    YaraCompiler& operator=(const YaraCompiler&) = delete;
    YaraCompiler(YaraCompiler&&) noexcept;
    YaraCompiler& operator=(YaraCompiler&&) noexcept;

    // ========================================================================
    // RULE COMPILATION
    // ========================================================================

    // Add rule file
    [[nodiscard]] StoreError AddFile(
        const std::wstring& filePath,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Add rule string
    [[nodiscard]] StoreError AddString(
        const std::string& ruleSource,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Add multiple files
    [[nodiscard]] StoreError AddFiles(
        std::span<const std::wstring> filePaths,
        const std::string& namespace_ = "default",
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;

    // Get compilation errors
    [[nodiscard]] std::vector<std::string> GetErrors() const noexcept;
    [[nodiscard]] std::vector<std::string> GetWarnings() const noexcept;

    // Clear errors
    void ClearErrors() noexcept;

    // ========================================================================
    // COMPILED RULES
    // ========================================================================

    // Get compiled rules (transfers ownership)
    [[nodiscard]] YR_RULES* GetRules() noexcept;

    // Save compiled rules to file
    [[nodiscard]] StoreError SaveToFile(
        const std::wstring& filePath
    ) noexcept;

    // Save compiled rules to memory buffer
    [[nodiscard]] std::optional<std::vector<uint8_t>> SaveToBuffer() noexcept;

    // ========================================================================
    // COMPILER OPTIONS
    // ========================================================================

    // Set include directories for imports
    void SetIncludePaths(
        std::span<const std::wstring> paths
    ) noexcept;

    // Define external variable
    void DefineExternalVariable(
        const std::string& name,
        const std::string& value
    ) noexcept;

    void DefineExternalVariable(
        const std::string& name,
        int64_t value
    ) noexcept;

    void DefineExternalVariable(
        const std::string& name,
        bool value
    ) noexcept;

private:
    YR_COMPILER* m_compiler{nullptr};
    std::vector<std::string> m_errors;
    std::vector<std::string> m_warnings;
    std::vector<std::wstring> m_includePaths;

    // YARA callback signature (matches YR_COMPILER_CALLBACK_FUNC)
    static void ErrorCallback(
        int errorLevel,
        const char* fileName,
        int lineNumber,
        const YR_RULE* rule,          // Added for new YARA API
        const char* message,
        void* userData
    );
};

// ============================================================================
// YARA RULE STORE (Main Interface)
// ============================================================================

class YaraRuleStore {
public:
    YaraRuleStore();
    ~YaraRuleStore();

    // TITANIUM: Disable copy AND move - class contains std::shared_mutex, std::mutex,
    // and std::atomic members that cannot be safely moved
    YaraRuleStore(const YaraRuleStore&) = delete;
    YaraRuleStore& operator=(const YaraRuleStore&) = delete;
    YaraRuleStore(YaraRuleStore&&) = delete;
    YaraRuleStore& operator=(YaraRuleStore&&) = delete;

    // ========================================================================
    // INITIALIZATION & LIFECYCLE
    // ========================================================================

    // Initialize YARA library
    [[nodiscard]] static StoreError InitializeYara() noexcept;

    // Finalize YARA library (call at program exit)
    static void FinalizeYara() noexcept;

    // Load precompiled rules from database
    [[nodiscard]] StoreError Initialize(
        const std::wstring& databasePath,
        bool readOnly = true
    ) noexcept;

    // Create new rule database
    [[nodiscard]] StoreError CreateNew(
        const std::wstring& databasePath,
        uint64_t initialSizeBytes = 100 * 1024 * 1024
    ) noexcept;

    // Load compiled rules from file (fast)
    [[nodiscard]] StoreError LoadCompiledRules(
        const std::wstring& compiledRulePath
    ) noexcept;

    // Close database
    void Close() noexcept;

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized.load(std::memory_order_acquire);
    }

    // ========================================================================
    // RULE SCANNING (High Performance)
    // ========================================================================

    // Scan memory buffer
    [[nodiscard]] std::vector<YaraMatch> ScanBuffer(
        std::span<const uint8_t> buffer,
        const YaraScanOptions& options = {}
    ) const noexcept;

    // Scan file (memory-mapped)
    [[nodiscard]] std::vector<YaraMatch> ScanFile(
        const std::wstring& filePath,
        const YaraScanOptions& options = {}
    ) const noexcept;

    // Scan process memory (requires elevated privileges)
    [[nodiscard]] std::vector<YaraMatch> ScanProcess(
        uint32_t processId,
        const YaraScanOptions& options = {}
    ) const noexcept;

    // ========================================================================
    // INCREMENTAL SCANNING (STREAMING) - TITANIUM HARDENED
    // ========================================================================
    class ScanContext {
    public:
        ScanContext() = default;
        ~ScanContext() = default;
        
        // Move semantics for context transfer
        ScanContext(ScanContext&& other) noexcept = default;
        ScanContext& operator=(ScanContext&& other) noexcept = default;
        
        // Copy disabled (holds buffer and state)
        ScanContext(const ScanContext&) = delete;
        ScanContext& operator=(const ScanContext&) = delete;

        // Reset and clear buffer
        void Reset() noexcept;
        
        // Feed data chunk - may trigger intermediate scan
        [[nodiscard]] std::vector<YaraMatch> FeedChunk(
            std::span<const uint8_t> chunk
        ) noexcept;

        // Finalize and scan remaining buffer
        [[nodiscard]] std::vector<YaraMatch> Finalize() noexcept;
        
        // Query context state
        [[nodiscard]] bool IsValid() const noexcept { return m_isValid && m_store != nullptr; }
        [[nodiscard]] size_t GetBufferSize() const noexcept { return m_buffer.size(); }
        [[nodiscard]] size_t GetTotalBytesProcessed() const noexcept { return m_totalBytesProcessed; }

    private:
        friend class YaraRuleStore;
        const YaraRuleStore* m_store{nullptr};
        std::vector<uint8_t> m_buffer;
        YaraScanOptions m_options;
        bool m_isValid{false};                           // Context validity flag
        size_t m_totalBytesProcessed{0};                 // Statistics
    };

    [[nodiscard]] ScanContext CreateScanContext(
        const YaraScanOptions& options = {}
    ) const noexcept;

    // ========================================================================
    // RULE MANAGEMENT
    // ========================================================================

    // Compile and add rules from source
    [[nodiscard]] StoreError AddRulesFromSource(
        const std::string& ruleSource,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Compile and add rules from file
    [[nodiscard]] StoreError AddRulesFromFile(
        const std::wstring& filePath,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Compile and add rules from directory (recursive)
    [[nodiscard]] StoreError AddRulesFromDirectory(
        const std::wstring& directoryPath,
        const std::string& namespace_ = "default",
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;

    // Remove rule by name
    [[nodiscard]] StoreError RemoveRule(
        const std::string& ruleName,
        const std::string& namespace_ = "default"
    ) noexcept;

    // Remove all rules in namespace
    [[nodiscard]] StoreError RemoveNamespace(
        const std::string& namespace_
    ) noexcept;

    // Update rule metadata
    [[nodiscard]] StoreError UpdateRuleMetadata(
        const std::string& ruleName,
        const YaraRuleMetadata& metadata
    ) noexcept;

    // ========================================================================
    // RULE QUERY
    // ========================================================================

    // Get rule metadata by name
    [[nodiscard]] std::optional<YaraRuleMetadata> GetRuleMetadata(
        const std::string& ruleName,
        const std::string& namespace_ = "default"
    ) const noexcept;

    // List all rules
    [[nodiscard]] std::vector<YaraRuleMetadata> ListRules(
        const std::string& namespaceFilter = ""
    ) const noexcept;

    // List all namespaces
    [[nodiscard]] std::vector<std::string> ListNamespaces() const noexcept;

    // Search rules by tag
    [[nodiscard]] std::vector<YaraRuleMetadata> FindRulesByTag(
        const std::string& tag
    ) const noexcept;

    // Search rules by author
    [[nodiscard]] std::vector<YaraRuleMetadata> FindRulesByAuthor(
        const std::string& author
    ) const noexcept;

    // ========================================================================
    // IMPORT/EXPORT
    // ========================================================================

    // Export compiled rules
    [[nodiscard]] StoreError ExportCompiled(
        const std::wstring& outputPath
    ) const noexcept;

    // Export rules as JSON
    [[nodiscard]] std::string ExportToJson() const noexcept;

    // Import from YARA-Rules repository format
    [[nodiscard]] StoreError ImportFromYaraRulesRepo(
        const std::wstring& repoPath,
        std::function<void(size_t current, size_t total)> progressCallback = nullptr
    ) noexcept;

    // ========================================================================
    // STATISTICS & MONITORING
    // ========================================================================

    struct YaraStoreStatistics {
        uint64_t totalRules{0};
        uint64_t totalNamespaces{0};
        uint64_t totalScans{0};
        uint64_t totalMatches{0};
        uint64_t averageScanTimeMicroseconds{0};
        uint64_t peakScanTimeMicroseconds{0};
        uint64_t totalBytesScanned{0};
        double averageThroughputMBps{0.0};
        uint64_t compiledRulesSize{0};
        
        // Per-rule statistics
        std::map<std::string, uint64_t> ruleHitCounts;
    };

    [[nodiscard]] YaraStoreStatistics GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // Get top N most frequently matched rules
    [[nodiscard]] std::vector<std::pair<std::string, uint64_t>> GetTopRules(
        uint32_t topN = 10
    ) const noexcept;

    [[nodiscard]] std::wstring GetDatabasePath() const noexcept;

    // Get database header
    [[nodiscard]] const SignatureDatabaseHeader* GetHeader() const noexcept;

    // ========================================================================
    // MAINTENANCE
    // ========================================================================

    // Recompile all rules (optimize after updates)
    [[nodiscard]] StoreError Recompile() noexcept;

    // Verify database integrity
    [[nodiscard]] StoreError Verify(
        std::function<void(const std::string&)> logCallback = nullptr
    ) const noexcept;

    // Flush changes to disk
    [[nodiscard]] StoreError Flush() noexcept;

    // ========================================================================
    // ADVANCED FEATURES
    // ========================================================================

    // Enable/disable profiling
    void SetProfilingEnabled(bool enabled) noexcept {
        m_profilingEnabled.store(enabled, std::memory_order_release);
    }

    // Set scan timeout (global default)
    void SetScanTimeout(uint32_t seconds) noexcept {
        m_defaultTimeout = seconds;
    }

    // Get YARA version
    [[nodiscard]] static std::string GetYaraVersion() noexcept;

    // Test rule syntax without adding
    [[nodiscard]] StoreError TestRule(
        const std::string& ruleSource,
        std::vector<std::string>& errors
    ) const noexcept;

private:
    // ========================================================================
    // INTERNAL METHODS
    // ========================================================================

    [[nodiscard]] StoreError OpenMemoryMapping(
        const std::wstring& path,
        bool readOnly
    ) noexcept;

    void CloseMemoryMapping() noexcept;

    [[nodiscard]] StoreError LoadRulesInternal() noexcept;

    [[nodiscard]] std::vector<YaraMatch> PerformScan(
        const void* buffer,
        size_t size,
        const YaraScanOptions& options
    ) const noexcept;

    void UpdateRuleHitCount(const std::string& ruleName) noexcept;

    [[nodiscard]] YaraMatch BuildYaraMatch(
        const std::string& ruleName,
        void* yaraRule,
        uint64_t matchTimeUs
    ) const noexcept;

    // YARA callback handlers
    static int ScanCallback(
        int message,
        void* messageData,
        void* userData
    );

    // ========================================================================
    // INTERNAL STATE
    // ========================================================================

    std::wstring m_databasePath;
    MemoryMappedView m_mappedView{};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_readOnly{true};

    // Compiled YARA rules
    YR_RULES* m_rules{nullptr};

    // Rule metadata cache
    std::map<std::string, YaraRuleMetadata> m_ruleMetadata;
    
    // Rule source cache for merging support
    // Key: "namespace::__source__<id>", Value: rule source string
    // This enables proper rule merging by recompiling all sources together
    std::map<std::string, std::string> m_ruleSources;
    
    // Monotonically increasing counter for unique source IDs (avoids hash collisions)
    std::atomic<uint64_t> m_sourceIdCounter{0};

    // Statistics
    mutable std::atomic<uint64_t> m_totalScans{0};
    mutable std::atomic<uint64_t> m_totalMatches{0};
    mutable std::atomic<uint64_t> m_totalBytesScanned{0};

    // Configuration
    std::atomic<bool> m_profilingEnabled{false};
    uint32_t m_defaultTimeout{300};

    // Synchronization
    mutable std::shared_mutex m_globalLock;
    mutable std::mutex m_scanMutex;                       // YARA scanning not thread-safe

    // Performance monitoring
    LARGE_INTEGER m_perfFrequency{};

    // YARA library initialization state
    static std::atomic<bool> s_yaraInitialized;
    static std::mutex s_yaraInitMutex;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace YaraUtils {

// Validate YARA rule syntax
[[nodiscard]] bool ValidateRuleSyntax(
    const std::string& ruleSource,
    std::vector<std::string>& errors
) noexcept;

// Extract metadata from YARA rule source
[[nodiscard]] std::map<std::string, std::string> ExtractMetadata(
    const std::string& ruleSource
) noexcept;

// Extract tags from YARA rule source
[[nodiscard]] std::vector<std::string> ExtractTags(
    const std::string& ruleSource
) noexcept;

// Parse threat level from rule metadata
[[nodiscard]] ThreatLevel ParseThreatLevel(
    const std::map<std::string, std::string>& metadata
) noexcept;

// Find all .yar/.yara files in directory
[[nodiscard]] std::vector<std::wstring> FindYaraFiles(
    const std::wstring& directoryPath,
    bool recursive = true
) noexcept;

} // namespace YaraUtils

} // namespace SignatureStore
} // namespace ShadowStrike
