/**
 * @file ThreatIntelImporter.hpp
 * @brief Enterprise-grade Threat Intelligence Import Module
 *
 * Provides high-performance import capabilities for threat intelligence data
 * from industry-standard formats:
 * - CSV (Comma-Separated Values) with auto-detection and custom mapping
 * - JSON (JavaScript Object Notation) with schema validation
 * - STIX 2.1 (Structured Threat Information Expression) bundles
 * - MISP (Malware Information Sharing Platform) events
 * - OpenIOC (Open Indicators of Compromise) XML format
 * - TAXII 2.1 feeds
 * - Plain text lists (one IOC per line)
 * - CrowdStrike IOC format
 * - AlienVault OTX pulses
 * - Abuse.ch feeds (URLhaus, MalwareBazaar, Feodo Tracker)
 *
 * Performance Targets:
 * - CSV import: >100K entries/second
 * - JSON import: >50K entries/second
 * - STIX parsing: >20K objects/second
 * - Streaming import for unlimited dataset sizes
 *
 * Features:
 * - Streaming imports for memory efficiency
 * - Decompression support (GZIP, LZ4, ZSTD, ZIP)
 * - Schema validation and auto-detection
 * - Duplicate detection and merging
 * - Progress callbacks for UI integration
 * - Async import with cancellation support
 * - Conflict resolution strategies
 * - Data normalization and enrichment
 *
 * @author ShadowStrike Security Team
 * @copyright 2024 ShadowStrike Project
 */

#pragma once

#include "ThreatIntelFormat.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <optional>
#include <functional>
#include <memory>
#include <chrono>
#include <atomic>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <regex>

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Forward Declarations
// ============================================================================

class ThreatIntelDatabase;
class ThreatIntelStore;

// ============================================================================
// Import Format Types
// ============================================================================

/**
 * @brief Supported import formats
 */
enum class ImportFormat : uint8_t {
    /// @brief Auto-detect format from content/extension
    Auto = 0,
    
    /// @brief Comma-Separated Values (RFC 4180)
    CSV = 1,
    
    /// @brief JSON format (RFC 8259)
    JSON = 2,
    
    /// @brief JSON Lines format (one JSON object per line)
    JSONL = 3,
    
    /// @brief STIX 2.1 Bundle format
    STIX21 = 4,
    
    /// @brief MISP event format (JSON)
    MISP = 5,
    
    /// @brief OpenIOC XML format
    OpenIOC = 6,
    
    /// @brief TAXII 2.1 format
    TAXII21 = 7,
    
    /// @brief Plain text (one IOC per line)
    PlainText = 8,
    
    /// @brief Binary format (ShadowStrike native)
    Binary = 9,
    
    /// @brief CrowdStrike IOC format
    CrowdStrike = 10,
    
    /// @brief AlienVault OTX pulse format
    AlienVaultOTX = 11,
    
    /// @brief Abuse.ch URLhaus format
    URLhaus = 12,
    
    /// @brief Abuse.ch MalwareBazaar format
    MalwareBazaar = 13,
    
    /// @brief Abuse.ch Feodo Tracker format
    FeodoTracker = 14,
    
    /// @brief Microsoft Sentinel format
    MSSentinel = 15,
    
    /// @brief Splunk format
    Splunk = 16,
    
    /// @brief Emerging Threats rules format
    EmergingThreats = 17,
    
    /// @brief Snort/Suricata rules format
    SnortRules = 18
};

/**
 * @brief Compression algorithm detection for imports
 */
enum class ImportCompression : uint8_t {
    /// @brief Auto-detect compression from magic bytes/extension
    Auto = 0,
    
    /// @brief No compression
    None = 1,
    
    /// @brief GZIP compression (.gz)
    GZIP = 2,
    
    /// @brief LZ4 compression
    LZ4 = 3,
    
    /// @brief ZSTD compression
    ZSTD = 4,
    
    /// @brief ZIP archive
    ZIP = 5,
    
    /// @brief BZIP2 compression
    BZIP2 = 6,
    
    /// @brief XZ/LZMA compression
    XZ = 7
};

/**
 * @brief Conflict resolution strategy for duplicate IOCs
 */
enum class ConflictResolution : uint8_t {
    /// @brief Skip duplicates, keep existing entries
    SkipDuplicates = 0,
    
    /// @brief Overwrite existing entries with new data
    OverwriteExisting = 1,
    
    /// @brief Update existing entries (merge metadata)
    UpdateExisting = 2,
    
    /// @brief Keep entry with higher confidence
    KeepHigherConfidence = 3,
    
    /// @brief Keep entry with higher reputation score
    KeepHigherReputation = 4,
    
    /// @brief Keep most recent entry (by timestamp)
    KeepMostRecent = 5,
    
    /// @brief Keep oldest entry (first seen)
    KeepOldest = 6,
    
    /// @brief Merge all metadata from both entries
    MergeAll = 7,
    
    /// @brief Use custom callback for resolution
    Custom = 8
};

/**
 * @brief Validation strictness level
 */
enum class ValidationLevel : uint8_t {
    /// @brief No validation (fastest, least safe)
    None = 0,
    
    /// @brief Basic format validation only
    Basic = 1,
    
    /// @brief Standard validation with type checking
    Standard = 2,
    
    /// @brief Strict validation with semantic checks
    Strict = 3,
    
    /// @brief Paranoid validation with external lookups
    Paranoid = 4
};

/**
 * @brief IOC normalization options
 */
enum class NormalizationFlags : uint32_t {
    None = 0,
    
    /// @brief Convert all strings to lowercase
    LowercaseAll = 1 << 0,
    
    /// @brief Normalize domain names (remove www, trailing dots)
    NormalizeDomains = 1 << 1,
    
    /// @brief Normalize URLs (decode percent-encoding, remove fragments)
    NormalizeURLs = 1 << 2,
    
    /// @brief Convert hashes to lowercase
    NormalizeHashes = 1 << 3,
    
    /// @brief Normalize email addresses
    NormalizeEmails = 1 << 4,
    
    /// @brief Remove leading/trailing whitespace
    TrimWhitespace = 1 << 5,
    
    /// @brief Remove duplicate entries in input
    RemoveDuplicates = 1 << 6,
    
    /// @brief Expand CIDR notation to individual IPs
    ExpandCIDR = 1 << 7,
    
    /// @brief Defang IOCs (e.g., remove [.] in domains)
    Defang = 1 << 8,
    
    /// @brief Validate hash lengths match algorithm
    ValidateHashLength = 1 << 9,
    
    /// @brief Strip protocol from URLs
    StripURLProtocol = 1 << 10,
    
    /// @brief Convert IPv6 to standard format
    NormalizeIPv6 = 1 << 11,
    
    /// @brief Standard normalization preset
    Standard = LowercaseAll | TrimWhitespace | NormalizeDomains | NormalizeHashes,
    
    /// @brief Full normalization preset
    Full = 0xFFFFFFFF & ~ExpandCIDR
};

/// @brief Enable bitwise operations on NormalizationFlags
inline constexpr NormalizationFlags operator|(NormalizationFlags a, NormalizationFlags b) noexcept {
    return static_cast<NormalizationFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr NormalizationFlags operator&(NormalizationFlags a, NormalizationFlags b) noexcept {
    return static_cast<NormalizationFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr bool HasNormalizationFlag(NormalizationFlags flags, NormalizationFlags flag) noexcept {
    return (static_cast<uint32_t>(flags) & static_cast<uint32_t>(flag)) != 0;
}

// ============================================================================
// CSV Column Mapping
// ============================================================================

/**
 * @brief Standard CSV column types for auto-detection
 */
enum class CSVColumnType : uint8_t {
    Unknown = 0,
    
    // IOC Value columns
    Value = 1,              ///< Generic IOC value
    IPv4 = 2,               ///< IPv4 address column
    IPv6 = 3,               ///< IPv6 address column
    Domain = 4,             ///< Domain name column
    URL = 5,                ///< URL column
    MD5 = 6,                ///< MD5 hash column
    SHA1 = 7,               ///< SHA1 hash column
    SHA256 = 8,             ///< SHA256 hash column
    SHA512 = 9,             ///< SHA512 hash column
    Email = 10,             ///< Email address column
    Filename = 11,          ///< Filename column
    FilePath = 12,          ///< File path column
    
    // Metadata columns
    Type = 20,              ///< IOC type column
    Reputation = 21,        ///< Reputation score column
    Confidence = 22,        ///< Confidence level column
    Category = 23,          ///< Threat category column
    Source = 24,            ///< Intel source column
    Description = 25,       ///< Description column
    Tags = 26,              ///< Tags/labels column
    MitreAttack = 27,       ///< MITRE ATT&CK ID column
    
    // Timestamp columns
    FirstSeen = 30,         ///< First seen timestamp
    LastSeen = 31,          ///< Last seen timestamp
    CreatedTime = 32,       ///< Creation timestamp
    ExpirationTime = 33,    ///< Expiration timestamp
    
    // Statistics columns
    HitCount = 40,          ///< Hit count column
    FalsePositives = 41,    ///< False positive count
    TruePositives = 42,     ///< True positive count
    
    // Ignore
    Ignore = 255            ///< Column to ignore
};

/**
 * @brief CSV column mapping configuration
 */
struct CSVColumnMapping {
    /// @brief Column index (0-based)
    size_t columnIndex = 0;
    
    /// @brief Column type
    CSVColumnType type = CSVColumnType::Unknown;
    
    /// @brief Original column header name
    std::string headerName;
    
    /// @brief Custom regex pattern for validation
    std::optional<std::string> validationPattern;
    
    /// @brief Default value if column is empty
    std::optional<std::string> defaultValue;
    
    /// @brief Transform function name (for special handling)
    std::optional<std::string> transformFunction;
};

/**
 * @brief CSV parser configuration
 */
struct CSVParserConfig {
    /// @brief Field delimiter character
    char delimiter = ',';
    
    /// @brief Quote character
    char quote = '"';
    
    /// @brief Escape character
    char escape = '\\';
    
    /// @brief Comment line prefix (empty = no comments)
    std::string commentPrefix = "#";
    
    /// @brief First row is header
    bool hasHeader = true;
    
    /// @brief Number of rows to skip at start
    size_t skipRows = 0;
    
    /// @brief Maximum number of rows to import (0 = unlimited)
    size_t maxRows = 0;
    
    /// @brief Allow variable number of columns per row
    bool allowVariableColumns = false;
    
    /// @brief Trim whitespace from fields
    bool trimFields = true;
    
    /// @brief Column mappings (auto-detected if empty)
    std::vector<CSVColumnMapping> columnMappings;
    
    /// @brief Default IOC type when type column is missing
    IOCType defaultIOCType = IOCType::Reserved;
    
    /// @brief Auto-detect IOC type from value format
    bool autoDetectIOCType = true;
};

// ============================================================================
// Import Options
// ============================================================================

/**
 * @brief Configuration options for import operations
 */
struct ImportOptions {
    /// @brief Input format (Auto = detect from extension/content)
    ImportFormat format = ImportFormat::Auto;
    
    /// @brief Compression (Auto = detect from magic bytes)
    ImportCompression compression = ImportCompression::Auto;
    
    /// @brief Conflict resolution strategy
    ConflictResolution conflictResolution = ConflictResolution::UpdateExisting;
    
    /// @brief Validation strictness level
    ValidationLevel validationLevel = ValidationLevel::Standard;
    
    /// @brief Normalization flags
    NormalizationFlags normalization = NormalizationFlags::Standard;
    
    /// @brief CSV parser configuration
    CSVParserConfig csvConfig;
    
    /// @brief Default intel source for imported entries
    ThreatIntelSource defaultSource = ThreatIntelSource::CustomFeed;
    
    /// @brief Default reputation level for entries without one
    ReputationLevel defaultReputation = ReputationLevel::Unknown;
    
    /// @brief Default confidence level for entries without one
    ConfidenceLevel defaultConfidence = ConfidenceLevel::Low;
    
    /// @brief Default threat category for entries without one
    ThreatCategory defaultCategory = ThreatCategory::Unknown;
    
    /// @brief Default TTL in seconds (0 = no expiration)
    uint64_t defaultTTL = 86400 * 30; // 30 days
    
    /// @brief Tags to add to all imported entries
    std::vector<std::string> defaultTags;
    
    /// @brief Feed ID to assign to imported entries
    uint32_t feedId = 0;
    
    /// @brief IOC types to import (empty = all types)
    std::vector<IOCType> allowedIOCTypes;
    
    /// @brief IOC types to exclude
    std::vector<IOCType> excludedIOCTypes;
    
    /// @brief Minimum confidence to import
    ConfidenceLevel minConfidence = ConfidenceLevel::None;
    
    /// @brief Maximum entries to import (0 = unlimited)
    size_t maxEntries = 0;
    
    /// @brief Streaming buffer size
    size_t bufferSize = 1024 * 1024; // 1 MB
    
    /// @brief Batch size for database inserts
    size_t batchSize = 10000;
    
    /// @brief Continue on parse errors (log and skip)
    bool continueOnError = true;
    
    /// @brief Maximum parse errors before aborting
    size_t maxParseErrors = 1000;
    
    /// @brief Log individual parse errors
    bool logParseErrors = true;
    
    /// @brief Update cache after import
    bool updateCache = true;
    
    /// @brief Trigger index rebuild after import
    bool rebuildIndex = false;
    
    /// @brief Enable parallel parsing (multi-threaded)
    bool parallelParsing = true;
    
    /// @brief Number of parser threads (0 = auto)
    size_t parserThreads = 0;
    
    /// @brief Dry run mode (parse without storing)
    bool dryRun = false;
    
    /**
     * @brief Create options for fast bulk import
     */
    static ImportOptions FastBulkImport();
    
    /**
     * @brief Create options for careful validated import
     */
    static ImportOptions ValidatedImport();
    
    /**
     * @brief Create options for incremental feed update
     */
    static ImportOptions FeedUpdate(uint32_t feedId, ThreatIntelSource source);
    
    /**
     * @brief Create options for plain text IP list import
     */
    static ImportOptions IPListImport();
    
    /**
     * @brief Create options for hash list import
     */
    static ImportOptions HashListImport();
};

// ============================================================================
// Import Progress & Callbacks
// ============================================================================

/**
 * @brief Parse error information
 */
struct ParseError {
    /// @brief Line number (1-based)
    size_t lineNumber = 0;
    
    /// @brief Column number (1-based, if applicable)
    size_t columnNumber = 0;
    
    /// @brief Error code
    uint32_t errorCode = 0;
    
    /// @brief Error message
    std::string message;
    
    /// @brief Raw input that caused the error
    std::string rawInput;
    
    /// @brief Was recovery attempted
    bool recoveryAttempted = false;
    
    /// @brief Was recovery successful
    bool recoverySucceeded = false;
};

/**
 * @brief Import progress information
 */
struct ImportProgress {
    /// @brief Total entries to import (may be estimated)
    size_t totalEntries = 0;
    
    /// @brief Entries parsed so far
    size_t parsedEntries = 0;
    
    /// @brief Entries imported (stored) so far
    size_t importedEntries = 0;
    
    /// @brief Entries skipped (filtered, duplicates)
    size_t skippedEntries = 0;
    
    /// @brief Entries updated (existing modified)
    size_t updatedEntries = 0;
    
    /// @brief Entries merged with existing
    size_t mergedEntries = 0;
    
    /// @brief Parse errors encountered
    size_t parseErrors = 0;
    
    /// @brief Bytes read so far
    uint64_t bytesRead = 0;
    
    /// @brief Total bytes (if known)
    uint64_t totalBytes = 0;
    
    /// @brief Elapsed time in milliseconds
    uint64_t elapsedMs = 0;
    
    /// @brief Estimated remaining time in milliseconds
    uint64_t estimatedRemainingMs = 0;
    
    /// @brief Current parse rate (entries/second)
    double entriesPerSecond = 0.0;
    
    /// @brief Current read rate (bytes/second)
    double bytesPerSecond = 0.0;
    
    /// @brief Progress percentage (0.0 - 100.0)
    double percentComplete = 0.0;
    
    /// @brief Current phase description
    std::string currentPhase;
    
    /// @brief Is import complete
    bool isComplete = false;
    
    /// @brief Error message (if any)
    std::string errorMessage;
    
    /// @brief Recent parse errors (last N)
    std::vector<ParseError> recentErrors;
};

/// @brief Progress callback type (return false to cancel)
using ImportProgressCallback = std::function<bool(const ImportProgress&)>;

/// @brief Entry validation callback (return false to skip entry)
using ImportValidationCallback = std::function<bool(IOCEntry& entry)>;

/// @brief Conflict resolution callback (custom resolution)
using ImportConflictCallback = std::function<IOCEntry(const IOCEntry& existing, const IOCEntry& newEntry)>;

/// @brief Parse error callback
using ImportErrorCallback = std::function<void(const ParseError& error)>;

// ============================================================================
// Import Result
// ============================================================================

/**
 * @brief Result of an import operation
 */
struct ImportResult {
    /// @brief Import was successful (even with some errors)
    bool success = false;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Total entries parsed from input
    size_t totalParsed = 0;
    
    /// @brief Total entries imported (new)
    size_t totalImported = 0;
    
    /// @brief Total entries updated (existing modified)
    size_t totalUpdated = 0;
    
    /// @brief Total entries skipped
    size_t totalSkipped = 0;
    
    /// @brief Total entries merged
    size_t totalMerged = 0;
    
    /// @brief Total parse errors
    size_t totalParseErrors = 0;
    
    /// @brief Total validation failures
    size_t totalValidationFailures = 0;
    
    /// @brief Total bytes read
    uint64_t bytesRead = 0;
    
    /// @brief Import duration in milliseconds
    uint64_t durationMs = 0;
    
    /// @brief Average entries per second
    double entriesPerSecond = 0.0;
    
    /// @brief Input file path (if file import)
    std::wstring inputPath;
    
    /// @brief Detected format
    ImportFormat detectedFormat = ImportFormat::Auto;
    
    /// @brief Detected compression
    ImportCompression detectedCompression = ImportCompression::None;
    
    /// @brief Was import cancelled
    bool wasCancelled = false;
    
    /// @brief Was dry run
    bool wasDryRun = false;
    
    /// @brief Parse errors (limited to first N)
    std::vector<ParseError> parseErrors;
    
    /// @brief Statistics by IOC type
    std::unordered_map<IOCType, size_t> countByType;
    
    /// @brief Statistics by source
    std::unordered_map<ThreatIntelSource, size_t> countBySource;
    
    /**
     * @brief Get total entries processed (imported + updated + skipped)
     */
    [[nodiscard]] size_t GetTotalProcessed() const noexcept {
        return totalImported + totalUpdated + totalSkipped;
    }
    
    /**
     * @brief Get success rate (0.0 - 1.0)
     */
    [[nodiscard]] double GetSuccessRate() const noexcept {
        if (totalParsed == 0) return 0.0;
        return static_cast<double>(totalImported + totalUpdated) / totalParsed;
    }
};

// ============================================================================
// String Pool Writer (for storing string data)
// ============================================================================

/**
 * @brief Interface for writing strings to the string pool
 */
class IStringPoolWriter {
public:
    virtual ~IStringPoolWriter() = default;
    
    /**
     * @brief Add string to pool and get reference
     * @param str String to add
     * @return Offset and length in pool
     */
    [[nodiscard]] virtual std::pair<uint64_t, uint32_t> AddString(std::string_view str) = 0;
    
    /**
     * @brief Check if string already exists in pool
     * @param str String to check
     * @return Offset and length if exists, nullopt otherwise
     */
    [[nodiscard]] virtual std::optional<std::pair<uint64_t, uint32_t>> FindString(std::string_view str) const = 0;
    
    /**
     * @brief Get current pool size
     */
    [[nodiscard]] virtual uint64_t GetPoolSize() const noexcept = 0;
};

// ============================================================================
// Import Readers (Strategy Pattern)
// ============================================================================

/**
 * @brief Abstract base class for format-specific readers
 */
class IImportReader {
public:
    virtual ~IImportReader() = default;
    
    /**
     * @brief Initialize reader with options
     * @param options Import options
     * @return true if initialization successful
     */
    virtual bool Initialize(const ImportOptions& options) = 0;
    
    /**
     * @brief Read next entry from input
     * @param entry Output entry
     * @param stringPool String pool writer for metadata
     * @return true if entry was read, false if end of input
     */
    virtual bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) = 0;
    
    /**
     * @brief Check if there are more entries
     */
    [[nodiscard]] virtual bool HasMoreEntries() const noexcept = 0;
    
    /**
     * @brief Get estimated total entries (if known)
     */
    [[nodiscard]] virtual std::optional<size_t> GetEstimatedTotal() const noexcept = 0;
    
    /**
     * @brief Get bytes read so far
     */
    [[nodiscard]] virtual uint64_t GetBytesRead() const noexcept = 0;
    
    /**
     * @brief Get total bytes (if known)
     */
    [[nodiscard]] virtual std::optional<uint64_t> GetTotalBytes() const noexcept = 0;
    
    /**
     * @brief Get last error message
     */
    [[nodiscard]] virtual std::string GetLastError() const = 0;
    
    /**
     * @brief Get last parse error details
     */
    [[nodiscard]] virtual std::optional<ParseError> GetLastParseError() const = 0;
    
    /**
     * @brief Reset reader to beginning (if supported)
     */
    virtual bool Reset() = 0;
};

// ============================================================================
// CSV Import Reader
// ============================================================================

/**
 * @brief CSV format import reader (RFC 4180 compliant)
 */
class CSVImportReader : public IImportReader {
public:
    explicit CSVImportReader(std::istream& input);
    ~CSVImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    std::vector<CSVColumnMapping> m_columnMappings;
    std::vector<std::string> m_currentRow;
    size_t m_currentLine = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    bool m_endOfInput = false;
    
    bool ParseHeader();
    bool AutoDetectColumns(const std::vector<std::string>& headerRow);
    bool ReadRow(std::vector<std::string>& fields);
    bool ParseField(std::string_view field, CSVColumnType type, IOCEntry& entry, IStringPoolWriter* stringPool);
    [[nodiscard]] IOCType DetectIOCType(std::string_view value) const;
    [[nodiscard]] CSVColumnType GuessColumnType(std::string_view headerName, const std::vector<std::string>& samples) const;
};

// ============================================================================
// JSON Import Reader
// ============================================================================

/**
 * @brief JSON format import reader (RFC 8259 compliant)
 */
class JSONImportReader : public IImportReader {
public:
    explicit JSONImportReader(std::istream& input);
    ~JSONImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    std::string m_buffer;
    size_t m_currentIndex = 0;
    size_t m_totalEntries = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    bool m_isJsonLines = false;
    bool m_endOfInput = false;
    
    bool ParseDocument();
    bool ParseEntryFromJSON(const std::string& jsonStr, IOCEntry& entry, IStringPoolWriter* stringPool);
    bool ReadNextJSONLine(std::string& line);
};

// ============================================================================
// STIX 2.1 Import Reader
// ============================================================================

/**
 * @brief STIX 2.1 Bundle format import reader
 */
class STIX21ImportReader : public IImportReader {
public:
    explicit STIX21ImportReader(std::istream& input);
    ~STIX21ImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    std::string m_bundleContent;
    size_t m_currentIndex = 0;
    size_t m_totalObjects = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    
    bool ParseBundle();
    bool ParseIndicator(const std::string& indicatorJson, IOCEntry& entry, IStringPoolWriter* stringPool);
    bool ParseSTIXPattern(std::string_view pattern, IOCEntry& entry, IStringPoolWriter* stringPool);
    [[nodiscard]] IOCType MapSTIXTypeToIOCType(std::string_view stixType) const;
};

// ============================================================================
// MISP Import Reader
// ============================================================================

/**
 * @brief MISP event format import reader
 */
class MISPImportReader : public IImportReader {
public:
    explicit MISPImportReader(std::istream& input);
    ~MISPImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    size_t m_currentIndex = 0;
    size_t m_totalAttributes = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    
    bool ParseEvent();
    bool ParseAttribute(const std::string& attrJson, IOCEntry& entry, IStringPoolWriter* stringPool);
    [[nodiscard]] IOCType MapMISPTypeToIOCType(std::string_view mispType) const;
    [[nodiscard]] ThreatCategory MapMISPCategoryToThreatCategory(std::string_view mispCategory) const;
};

// ============================================================================
// Plain Text Import Reader
// ============================================================================

/**
 * @brief Plain text format import reader (one IOC per line)
 */
class PlainTextImportReader : public IImportReader {
public:
    explicit PlainTextImportReader(std::istream& input);
    ~PlainTextImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    size_t m_currentLine = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    bool m_endOfInput = false;
    
    bool ParseLine(std::string_view line, IOCEntry& entry, IStringPoolWriter* stringPool);
    [[nodiscard]] IOCType DetectIOCType(std::string_view value) const;
    [[nodiscard]] bool IsIPv4Address(std::string_view value) const;
    [[nodiscard]] bool IsIPv6Address(std::string_view value) const;
    [[nodiscard]] bool IsDomain(std::string_view value) const;
    [[nodiscard]] bool IsURL(std::string_view value) const;
    [[nodiscard]] bool IsMD5Hash(std::string_view value) const;
    [[nodiscard]] bool IsSHA1Hash(std::string_view value) const;
    [[nodiscard]] bool IsSHA256Hash(std::string_view value) const;
    [[nodiscard]] bool IsEmail(std::string_view value) const;
};

// ============================================================================
// OpenIOC Import Reader
// ============================================================================

/**
 * @brief OpenIOC XML format import reader
 */
class OpenIOCImportReader : public IImportReader {
public:
    explicit OpenIOCImportReader(std::istream& input);
    ~OpenIOCImportReader() override;
    
    bool Initialize(const ImportOptions& options) override;
    bool ReadNextEntry(IOCEntry& entry, IStringPoolWriter* stringPool) override;
    [[nodiscard]] bool HasMoreEntries() const noexcept override;
    [[nodiscard]] std::optional<size_t> GetEstimatedTotal() const noexcept override;
    [[nodiscard]] uint64_t GetBytesRead() const noexcept override;
    [[nodiscard]] std::optional<uint64_t> GetTotalBytes() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    [[nodiscard]] std::optional<ParseError> GetLastParseError() const override;
    bool Reset() override;
    
private:
    std::istream& m_input;
    ImportOptions m_options;
    size_t m_currentIndex = 0;
    size_t m_totalItems = 0;
    uint64_t m_bytesRead = 0;
    std::string m_lastError;
    std::optional<ParseError> m_lastParseError;
    bool m_initialized = false;
    
    bool ParseDocument();
    [[nodiscard]] IOCType MapOpenIOCSearchToIOCType(std::string_view search) const;
};

// ============================================================================
// ThreatIntelImporter Class
// ============================================================================

/**
 * @brief Main import coordinator class
 *
 * Provides high-level import functionality with streaming support,
 * progress tracking, validation, and multi-format input capabilities.
 *
 * Usage:
 * @code
 * ThreatIntelImporter importer;
 * 
 * // Import from CSV file
 * ImportOptions opts = ImportOptions::FastBulkImport();
 * ImportResult result = importer.ImportFromFile(
 *     database, 
 *     L"threats.csv", 
 *     opts,
 *     [](const ImportProgress& p) {
 *         std::cout << p.percentComplete << "% complete" << std::endl;
 *         return true; // continue
 *     }
 * );
 * 
 * // Import from memory buffer
 * std::string stixBundle = "...";
 * result = importer.ImportFromString(database, stixBundle, opts);
 * @endcode
 */
class ThreatIntelImporter {
public:
    ThreatIntelImporter();
    ~ThreatIntelImporter();
    
    // Non-copyable, movable
    ThreatIntelImporter(const ThreatIntelImporter&) = delete;
    ThreatIntelImporter& operator=(const ThreatIntelImporter&) = delete;
    ThreatIntelImporter(ThreatIntelImporter&&) noexcept;
    ThreatIntelImporter& operator=(ThreatIntelImporter&&) noexcept;
    
    // =========================================================================
    // File Import
    // =========================================================================
    
    /**
     * @brief Import IOC entries from a file
     * @param database Database to import into
     * @param inputPath Input file path
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromFile(
        ThreatIntelDatabase& database,
        const std::wstring& inputPath,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Import IOC entries from file to vector
     * @param inputPath Input file path
     * @param stringPool String pool writer for metadata
     * @param entries Output vector for entries
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromFile(
        const std::wstring& inputPath,
        IStringPoolWriter* stringPool,
        std::vector<IOCEntry>& entries,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Stream Import
    // =========================================================================
    
    /**
     * @brief Import IOC entries from an input stream
     * @param database Database to import into
     * @param input Input stream
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromStream(
        ThreatIntelDatabase& database,
        std::istream& input,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Import IOC entries from stream to vector
     * @param input Input stream
     * @param stringPool String pool writer for metadata
     * @param entries Output vector for entries
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromStream(
        std::istream& input,
        IStringPoolWriter* stringPool,
        std::vector<IOCEntry>& entries,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Memory Import
    // =========================================================================
    
    /**
     * @brief Import IOC entries from a string
     * @param database Database to import into
     * @param input Input string
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromString(
        ThreatIntelDatabase& database,
        std::string_view input,
        const ImportOptions& options
    );
    
    /**
     * @brief Import IOC entries from string to vector
     * @param input Input string
     * @param stringPool String pool writer for metadata
     * @param entries Output vector for entries
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromString(
        std::string_view input,
        IStringPoolWriter* stringPool,
        std::vector<IOCEntry>& entries,
        const ImportOptions& options
    );
    
    /**
     * @brief Import IOC entries from byte vector
     * @param database Database to import into
     * @param input Input bytes
     * @param options Import options
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromBytes(
        ThreatIntelDatabase& database,
        std::span<const uint8_t> input,
        const ImportOptions& options
    );
    
    // =========================================================================
    // Single Entry Parsing
    // =========================================================================
    
    /**
     * @brief Parse a single IOC string to entry
     * @param iocValue IOC value string
     * @param entry Output entry
     * @param stringPool String pool writer for metadata
     * @param options Import options
     * @return true if parsing successful
     */
    [[nodiscard]] bool ParseSingleIOC(
        std::string_view iocValue,
        IOCEntry& entry,
        IStringPoolWriter* stringPool,
        const ImportOptions& options = ImportOptions()
    );
    
    /**
     * @brief Detect IOC type from value
     * @param value IOC value string
     * @return Detected IOC type
     */
    [[nodiscard]] static IOCType DetectIOCType(std::string_view value);
    
    /**
     * @brief Validate IOC value format
     * @param value IOC value string
     * @param type Expected IOC type
     * @return true if valid
     */
    [[nodiscard]] static bool ValidateIOCFormat(std::string_view value, IOCType type);
    
    /**
     * @brief Normalize IOC value
     * @param value IOC value string
     * @param type IOC type
     * @param flags Normalization flags
     * @return Normalized value
     */
    [[nodiscard]] static std::string NormalizeIOCValue(
        std::string_view value,
        IOCType type,
        NormalizationFlags flags
    );
    
    // =========================================================================
    // Format Detection
    // =========================================================================
    
    /**
     * @brief Detect import format from file extension
     * @param filePath File path
     * @return Detected format or Auto if unknown
     */
    [[nodiscard]] static ImportFormat DetectFormatFromExtension(const std::wstring& filePath);
    
    /**
     * @brief Detect import format from content
     * @param content Content to analyze
     * @param maxBytes Maximum bytes to read for detection
     * @return Detected format or Auto if unknown
     */
    [[nodiscard]] static ImportFormat DetectFormatFromContent(
        std::istream& content,
        size_t maxBytes = 8192
    );
    
    /**
     * @brief Detect compression from magic bytes
     * @param data First bytes of file
     * @return Detected compression or None if unknown
     */
    [[nodiscard]] static ImportCompression DetectCompression(std::span<const uint8_t> data);
    
    // =========================================================================
    // Batch Import
    // =========================================================================
    
    /**
     * @brief Import multiple files
     * @param database Database to import into
     * @param inputPaths List of input file paths
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Map of file path to import result
     */
    [[nodiscard]] std::unordered_map<std::wstring, ImportResult> ImportMultipleFiles(
        ThreatIntelDatabase& database,
        const std::vector<std::wstring>& inputPaths,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Import from directory (recursive)
     * @param database Database to import into
     * @param directoryPath Directory path
     * @param filePattern File pattern (e.g., "*.csv")
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromDirectory(
        ThreatIntelDatabase& database,
        const std::wstring& directoryPath,
        const std::wstring& filePattern,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // URL Import
    // =========================================================================
    
    /**
     * @brief Import from URL (HTTP/HTTPS)
     * @param database Database to import into
     * @param url URL to fetch
     * @param options Import options
     * @param progressCallback Optional progress callback
     * @return Import result
     */
    [[nodiscard]] ImportResult ImportFromURL(
        ThreatIntelDatabase& database,
        const std::string& url,
        const ImportOptions& options,
        ImportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Validation Callbacks
    // =========================================================================
    
    /**
     * @brief Set validation callback
     * @param callback Callback function
     */
    void SetValidationCallback(ImportValidationCallback callback);
    
    /**
     * @brief Set conflict resolution callback
     * @param callback Callback function
     */
    void SetConflictCallback(ImportConflictCallback callback);
    
    /**
     * @brief Set parse error callback
     * @param callback Callback function
     */
    void SetErrorCallback(ImportErrorCallback callback);
    
    // =========================================================================
    // Cancellation
    // =========================================================================
    
    /**
     * @brief Request cancellation of ongoing import
     */
    void RequestCancel() noexcept;
    
    /**
     * @brief Check if cancellation was requested
     */
    [[nodiscard]] bool IsCancellationRequested() const noexcept;
    
    /**
     * @brief Reset cancellation state
     */
    void ResetCancellation() noexcept;
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    /**
     * @brief Get total entries imported across all operations
     */
    [[nodiscard]] uint64_t GetTotalEntriesImported() const noexcept;
    
    /**
     * @brief Get total bytes read across all operations
     */
    [[nodiscard]] uint64_t GetTotalBytesRead() const noexcept;
    
    /**
     * @brief Get total import operations performed
     */
    [[nodiscard]] uint32_t GetTotalImportCount() const noexcept;
    
    /**
     * @brief Get total parse errors across all operations
     */
    [[nodiscard]] uint64_t GetTotalParseErrors() const noexcept;
    
private:
    // Implementation helper methods
    [[nodiscard]] std::unique_ptr<IImportReader> CreateReader(
        std::istream& input,
        ImportFormat format
    );
    
    [[nodiscard]] ImportResult DoImport(
        IImportReader& reader,
        IStringPoolWriter* stringPool,
        std::vector<IOCEntry>& entries,
        const ImportOptions& options,
        ImportProgressCallback progressCallback
    );
    
    [[nodiscard]] ImportResult DoImportToDatabase(
        IImportReader& reader,
        ThreatIntelDatabase& database,
        const ImportOptions& options,
        ImportProgressCallback progressCallback
    );
    
    bool ValidateEntry(IOCEntry& entry, const ImportOptions& options);
    void NormalizeEntry(IOCEntry& entry, const ImportOptions& options, IStringPoolWriter* stringPool);
    [[nodiscard]] IOCEntry ResolveConflict(
        const IOCEntry& existing,
        const IOCEntry& newEntry,
        ConflictResolution strategy
    );
    
    void UpdateProgress(
        ImportProgress& progress,
        size_t currentEntry,
        size_t totalEntries,
        uint64_t bytesRead,
        uint64_t totalBytes,
        const std::chrono::steady_clock::time_point& startTime
    );
    
    // Callbacks
    ImportValidationCallback m_validationCallback;
    ImportConflictCallback m_conflictCallback;
    ImportErrorCallback m_errorCallback;
    
    // Statistics
    std::atomic<uint64_t> m_totalEntriesImported{0};
    std::atomic<uint64_t> m_totalBytesRead{0};
    std::atomic<uint32_t> m_totalImportCount{0};
    std::atomic<uint64_t> m_totalParseErrors{0};
    
    // Cancellation
    std::atomic<bool> m_cancellationRequested{false};
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get file extension for import format
 * @param format Import format
 * @return File extension (including dot)
 */
[[nodiscard]] const char* GetImportFormatExtension(ImportFormat format) noexcept;

/**
 * @brief Get human-readable name for import format
 * @param format Import format
 * @return Format name
 */
[[nodiscard]] const char* GetImportFormatName(ImportFormat format) noexcept;

/**
 * @brief Parse import format from string
 * @param str Format string (e.g., "csv", "json", "stix")
 * @return Import format or nullopt if not recognized
 */
[[nodiscard]] std::optional<ImportFormat> ParseImportFormat(std::string_view str) noexcept;

/**
 * @brief Defang IOC value (make safe for display)
 * @param value IOC value
 * @param type IOC type
 * @return Defanged value
 */
[[nodiscard]] std::string DefangIOC(std::string_view value, IOCType type);

/**
 * @brief Refang IOC value (restore from defanged)
 * @param value Defanged IOC value
 * @param type IOC type
 * @return Original value
 */
[[nodiscard]] std::string RefangIOC(std::string_view value, IOCType type);

/**
 * @brief Parse STIX 2.1 pattern to extract IOC value
 * @param pattern STIX pattern string
 * @param type Output IOC type
 * @param value Output IOC value
 * @return true if parsing successful
 */
[[nodiscard]] bool ParseSTIXPattern(
    std::string_view pattern,
    IOCType& type,
    std::string& value
);

/**
 * @brief Parse ISO 8601 timestamp to Unix timestamp
 * @param timestamp ISO 8601 timestamp string
 * @return Unix timestamp or 0 if parsing failed
 */
[[nodiscard]] uint64_t ParseISO8601Timestamp(std::string_view timestamp);

/**
 * @brief Parse timestamp in various formats
 * @param timestamp Timestamp string
 * @return Unix timestamp or 0 if parsing failed
 */
[[nodiscard]] uint64_t ParseTimestamp(std::string_view timestamp);

/**
 * @brief Calculate checksum of import data
 * @param data Input data
 * @return CRC32 checksum
 */
[[nodiscard]] uint32_t CalculateImportChecksum(std::span<const uint8_t> data);

} // namespace ThreatIntel
} // namespace ShadowStrike
