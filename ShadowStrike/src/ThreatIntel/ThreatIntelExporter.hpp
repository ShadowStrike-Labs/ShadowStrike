/**
 * @file ThreatIntelExporter.hpp
 * @brief Enterprise-grade Threat Intelligence Export Module
 *
 * Provides high-performance export capabilities for threat intelligence data
 * to industry-standard formats:
 * - CSV (Comma-Separated Values) for spreadsheet analysis
 * - JSON (JavaScript Object Notation) for API integration
 * - STIX 2.1 (Structured Threat Information Expression) for threat sharing
 * - MISP (Malware Information Sharing Platform) format
 * - OpenIOC (Open Indicators of Compromise) XML format
 * - TAXII 2.1 compatible bundles
 * - Custom binary format for high-performance transfer
 *
 * Performance Targets:
 * - CSV export: >100K entries/second
 * - JSON export: >50K entries/second
 * - STIX bundle creation: >20K objects/second
 * - Streaming export for unlimited dataset sizes
 *
 * Features:
 * - Streaming exports for memory efficiency
 * - Compression support (GZIP, LZ4, ZSTD)
 * - Incremental/delta exports
 * - Field filtering and selection
 * - Progress callbacks for UI integration
 * - Async export with cancellation support
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

namespace ShadowStrike {
namespace ThreatIntel {

// ============================================================================
// Forward Declarations
// ============================================================================

class ThreatIntelDatabase;

// ============================================================================
// Export Format Types
// ============================================================================

/**
 * @brief Supported export formats
 */
enum class ExportFormat : uint8_t {
    /// @brief Comma-Separated Values (RFC 4180 compliant)
    CSV = 0,
    
    /// @brief JSON format (RFC 8259 compliant)
    JSON = 1,
    
    /// @brief JSON Lines format (one JSON object per line)
    JSONL = 2,
    
    /// @brief STIX 2.1 Bundle format
    STIX21 = 3,
    
    /// @brief MISP format (JSON-based)
    MISP = 4,
    
    /// @brief OpenIOC XML format
    OpenIOC = 5,
    
    /// @brief TAXII 2.1 compatible format
    TAXII21 = 6,
    
    /// @brief Plain text (one IOC per line)
    PlainText = 7,
    
    /// @brief Binary format for high-speed transfer
    Binary = 8,
    
    /// @brief CrowdStrike IOC format
    CrowdStrike = 9,
    
    /// @brief Microsoft Sentinel format
    MSSentinel = 10,
    
    /// @brief Splunk-compatible format
    Splunk = 11
};

/**
 * @brief Compression algorithm for exports
 */
enum class ExportCompression : uint8_t {
    /// @brief No compression
    None = 0,
    
    /// @brief GZIP compression (.gz)
    GZIP = 1,
    
    /// @brief LZ4 fast compression
    LZ4 = 2,
    
    /// @brief ZSTD compression (best ratio)
    ZSTD = 3,
    
    /// @brief ZIP archive format
    ZIP = 4
};

/**
 * @brief Export field selection flags
 */
enum class ExportFields : uint32_t {
    None = 0,
    
    // Basic fields
    EntryId = 1 << 0,
    Type = 1 << 1,
    Value = 1 << 2,
    Reputation = 1 << 3,
    Confidence = 1 << 4,
    Category = 1 << 5,
    Source = 1 << 6,
    
    // Timestamps
    FirstSeen = 1 << 7,
    LastSeen = 1 << 8,
    CreatedTime = 1 << 9,
    ExpirationTime = 1 << 10,
    
    // Metadata
    Description = 1 << 11,
    Tags = 1 << 12,
    MitreAttack = 1 << 13,
    RelatedIOCs = 1 << 14,
    
    // Statistics
    HitCount = 1 << 15,
    LastHitTime = 1 << 16,
    FalsePositives = 1 << 17,
    TruePositives = 1 << 18,
    
    // API data
    VTData = 1 << 19,
    AbuseIPDBData = 1 << 20,
    
    // STIX fields
    StixId = 1 << 21,
    StixBundle = 1 << 22,
    
    // Flags
    Flags = 1 << 23,
    Severity = 1 << 24,
    
    // Presets
    Basic = Type | Value | Reputation | Confidence,
    Standard = Basic | Category | Source | FirstSeen | LastSeen,
    Full = 0xFFFFFFFF
};

/// @brief Enable bitwise operations on ExportFields
inline constexpr ExportFields operator|(ExportFields a, ExportFields b) noexcept {
    return static_cast<ExportFields>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ExportFields operator&(ExportFields a, ExportFields b) noexcept {
    return static_cast<ExportFields>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr bool HasExportField(ExportFields fields, ExportFields field) noexcept {
    return (static_cast<uint32_t>(fields) & static_cast<uint32_t>(field)) != 0;
}

// ============================================================================
// Export Filter
// ============================================================================

/**
 * @brief Filter criteria for selective export
 */
struct ExportFilter {
    /// @brief IOC types to include (empty = all)
    std::vector<IOCType> includeTypes;
    
    /// @brief IOC types to exclude
    std::vector<IOCType> excludeTypes;
    
    /// @brief Minimum reputation level
    std::optional<ReputationLevel> minReputation;
    
    /// @brief Maximum reputation level
    std::optional<ReputationLevel> maxReputation;
    
    /// @brief Minimum confidence level
    std::optional<ConfidenceLevel> minConfidence;
    
    /// @brief Categories to include (empty = all)
    std::vector<ThreatCategory> includeCategories;
    
    /// @brief Sources to include (empty = all)
    std::vector<ThreatIntelSource> includeSources;
    
    /// @brief Only export entries created after this timestamp
    std::optional<uint64_t> createdAfter;
    
    /// @brief Only export entries created before this timestamp
    std::optional<uint64_t> createdBefore;
    
    /// @brief Only export entries that were seen after this timestamp
    std::optional<uint64_t> seenAfter;
    
    /// @brief Only export entries that expire after this timestamp
    std::optional<uint64_t> expiresAfter;
    
    /// @brief Only export active (non-expired, non-revoked) entries
    bool onlyActive = true;
    
    /// @brief Only export entries with specific flags set
    IOCFlags requiredFlags = IOCFlags::None;
    
    /// @brief Exclude entries with specific flags set
    IOCFlags excludedFlags = IOCFlags::None;
    
    /// @brief Maximum entries to export (0 = unlimited)
    size_t maxEntries = 0;
    
    /// @brief Starting entry index for pagination
    size_t startIndex = 0;
    
    /// @brief Tag filter (entry must have at least one of these tags)
    std::vector<std::string> includeTags;
    
    /// @brief Feed ID filter (empty = all feeds)
    std::vector<uint32_t> feedIds;
    
    /**
     * @brief Check if an IOC entry passes the filter
     * @param entry Entry to check
     * @return true if entry should be exported
     */
    [[nodiscard]] bool Matches(const IOCEntry& entry) const noexcept;
    
    /**
     * @brief Create filter for active malicious entries
     */
    static ExportFilter MaliciousOnly();
    
    /**
     * @brief Create filter for specific IOC type
     */
    static ExportFilter ByType(IOCType type);
    
    /**
     * @brief Create filter for entries from specific source
     */
    static ExportFilter BySource(ThreatIntelSource source);
    
    /**
     * @brief Create filter for recent entries
     * @param maxAgeHours Maximum age in hours
     */
    static ExportFilter RecentEntries(uint32_t maxAgeHours);
};

// ============================================================================
// Export Options
// ============================================================================

/**
 * @brief Configuration options for export operations
 */
struct ExportOptions {
    /// @brief Output format
    ExportFormat format = ExportFormat::JSON;
    
    /// @brief Compression algorithm
    ExportCompression compression = ExportCompression::None;
    
    /// @brief Fields to include in export
    ExportFields fields = ExportFields::Standard;
    
    /// @brief Filter criteria
    ExportFilter filter;
    
    /// @brief Pretty-print output (JSON/XML)
    bool prettyPrint = false;
    
    /// @brief Include header row (CSV)
    bool includeHeader = true;
    
    /// @brief CSV delimiter character
    char csvDelimiter = ',';
    
    /// @brief CSV quote character
    char csvQuote = '"';
    
    /// @brief Escape special characters
    bool escapeSpecialChars = true;
    
    /// @brief Include BOM for UTF-8 files
    bool includeBOM = false;
    
    /// @brief Newline style (true = CRLF, false = LF)
    bool windowsNewlines = false;
    
    /// @brief Streaming buffer size
    size_t bufferSize = 1024 * 1024; // 1 MB
    
    /// @brief Flush interval for streaming exports
    size_t flushInterval = 10000; // entries
    
    /// @brief STIX 2.1 bundle ID (auto-generated if empty)
    std::string stixBundleId;
    
    /// @brief STIX 2.1 identity ID for created_by reference
    std::string stixIdentityId;
    
    /// @brief STIX 2.1 marking definition refs
    std::vector<std::string> stixMarkingRefs;
    
    /// @brief MISP event UUID (auto-generated if empty)
    std::string mispEventUuid;
    
    /// @brief MISP event info/title
    std::string mispEventInfo;
    
    /// @brief OpenIOC author name
    std::string openIocAuthor;
    
    /// @brief Include statistics in export metadata
    bool includeStatistics = true;
    
    /// @brief Include export timestamp
    bool includeTimestamp = true;
    
    /// @brief Append to existing file instead of overwrite
    bool appendMode = false;
    
    /**
     * @brief Create options for fast CSV export
     */
    static ExportOptions FastCSV();
    
    /**
     * @brief Create options for STIX 2.1 sharing
     */
    static ExportOptions STIX21Sharing();
    
    /**
     * @brief Create options for MISP event export
     */
    static ExportOptions MISPEvent(const std::string& eventInfo);
    
    /**
     * @brief Create options for compressed JSON export
     */
    static ExportOptions CompressedJSON();
};

// ============================================================================
// Export Progress & Callbacks
// ============================================================================

/**
 * @brief Export progress information
 */
struct ExportProgress {
    /// @brief Total entries to export (may be estimated)
    size_t totalEntries = 0;
    
    /// @brief Entries exported so far
    size_t exportedEntries = 0;
    
    /// @brief Entries skipped by filter
    size_t skippedEntries = 0;
    
    /// @brief Bytes written so far
    uint64_t bytesWritten = 0;
    
    /// @brief Elapsed time in milliseconds
    uint64_t elapsedMs = 0;
    
    /// @brief Estimated remaining time in milliseconds
    uint64_t estimatedRemainingMs = 0;
    
    /// @brief Current export rate (entries/second)
    double entriesPerSecond = 0.0;
    
    /// @brief Current write rate (bytes/second)
    double bytesPerSecond = 0.0;
    
    /// @brief Progress percentage (0.0 - 100.0)
    double percentComplete = 0.0;
    
    /// @brief Current phase description
    std::string currentPhase;
    
    /// @brief Is export complete
    bool isComplete = false;
    
    /// @brief Error message (if any)
    std::string errorMessage;
};

/// @brief Progress callback type (return false to cancel)
using ExportProgressCallback = std::function<bool(const ExportProgress&)>;

/// @brief Entry transform callback (modify entry before export)
using ExportTransformCallback = std::function<void(IOCEntry&)>;

// ============================================================================
// Export Result
// ============================================================================

/**
 * @brief Result of an export operation
 */
struct ExportResult {
    /// @brief Export was successful
    bool success = false;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /// @brief Total entries exported
    size_t totalExported = 0;
    
    /// @brief Entries skipped by filter
    size_t totalSkipped = 0;
    
    /// @brief Total bytes written
    uint64_t bytesWritten = 0;
    
    /// @brief Export duration in milliseconds
    uint64_t durationMs = 0;
    
    /// @brief Output file path (if file export)
    std::wstring outputPath;
    
    /// @brief SHA256 hash of output file
    std::string outputHash;
    
    /// @brief Average entries per second
    double entriesPerSecond = 0.0;
    
    /// @brief Export format used
    ExportFormat format = ExportFormat::JSON;
    
    /// @brief Compression used
    ExportCompression compression = ExportCompression::None;
    
    /// @brief Was export cancelled
    bool wasCancelled = false;
};

// ============================================================================
// String Pool Reader (for accessing string data)
// ============================================================================

/**
 * @brief Interface for reading strings from the string pool
 */
class IStringPoolReader {
public:
    virtual ~IStringPoolReader() = default;
    
    /**
     * @brief Read string from pool at offset
     * @param offset Offset in string pool
     * @param length String length
     * @return String view or empty if invalid
     */
    [[nodiscard]] virtual std::string_view ReadString(uint64_t offset, uint32_t length) const noexcept = 0;
    
    /**
     * @brief Check if offset is valid
     */
    [[nodiscard]] virtual bool IsValidOffset(uint64_t offset) const noexcept = 0;
};

// ============================================================================
// Export Writers (Strategy Pattern)
// ============================================================================

/**
 * @brief Abstract base class for format-specific writers
 */
class IExportWriter {
public:
    virtual ~IExportWriter() = default;
    
    /**
     * @brief Begin export operation
     * @param options Export options
     * @return true if initialization successful
     */
    virtual bool Begin(const ExportOptions& options) = 0;
    
    /**
     * @brief Write a single IOC entry
     * @param entry Entry to write
     * @param stringPool String pool reader for metadata
     * @return true if write successful
     */
    virtual bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) = 0;
    
    /**
     * @brief Finalize export and write footer
     * @return true if finalization successful
     */
    virtual bool End() = 0;
    
    /**
     * @brief Flush buffered data to output
     */
    virtual void Flush() = 0;
    
    /**
     * @brief Get bytes written so far
     */
    [[nodiscard]] virtual uint64_t GetBytesWritten() const noexcept = 0;
    
    /**
     * @brief Get last error message
     */
    [[nodiscard]] virtual std::string GetLastError() const = 0;
};

// ============================================================================
// CSV Export Writer
// ============================================================================

/**
 * @brief CSV format export writer (RFC 4180 compliant)
 */
class CSVExportWriter : public IExportWriter {
public:
    explicit CSVExportWriter(std::ostream& output);
    ~CSVExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    std::string m_lastError;
    std::string m_buffer;
    
    void WriteEscapedField(std::string_view field);
    void WriteHeader();
    [[nodiscard]] std::string FormatIOCValue(const IOCEntry& entry, const IStringPoolReader* stringPool) const;
};

// ============================================================================
// JSON Export Writer
// ============================================================================

/**
 * @brief JSON format export writer (RFC 8259 compliant)
 */
class JSONExportWriter : public IExportWriter {
public:
    explicit JSONExportWriter(std::ostream& output);
    ~JSONExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    size_t m_entryCount = 0;
    std::string m_lastError;
    std::string m_buffer;
    bool m_isJsonLines = false;
    
    void WriteEscapedString(std::string_view str);
    void WriteEntryJSON(const IOCEntry& entry, const IStringPoolReader* stringPool);
    void WriteIndent(int level);
};

// ============================================================================
// STIX 2.1 Export Writer
// ============================================================================

/**
 * @brief STIX 2.1 Bundle format export writer
 */
class STIX21ExportWriter : public IExportWriter {
public:
    explicit STIX21ExportWriter(std::ostream& output);
    ~STIX21ExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    size_t m_objectCount = 0;
    std::string m_lastError;
    std::string m_bundleId;
    std::string m_buffer;
    
    [[nodiscard]] std::string GenerateSTIXId(const IOCEntry& entry) const;
    [[nodiscard]] std::string MapIOCTypeToSTIXType(IOCType type) const;
    void WriteIndicatorObject(const IOCEntry& entry, const IStringPoolReader* stringPool);
    void WriteSTIXPattern(const IOCEntry& entry, const IStringPoolReader* stringPool);
};

// ============================================================================
// MISP Export Writer
// ============================================================================

/**
 * @brief MISP format export writer
 */
class MISPExportWriter : public IExportWriter {
public:
    explicit MISPExportWriter(std::ostream& output);
    ~MISPExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    size_t m_attributeCount = 0;
    std::string m_lastError;
    std::string m_eventUuid;
    std::string m_buffer;
    
    [[nodiscard]] std::string MapIOCTypeToMISPType(IOCType type) const;
    [[nodiscard]] std::string MapIOCTypeToMISPCategory(IOCType type) const;
    void WriteAttribute(const IOCEntry& entry, const IStringPoolReader* stringPool);
};

// ============================================================================
// OpenIOC Export Writer
// ============================================================================

/**
 * @brief OpenIOC XML format export writer
 */
class OpenIOCExportWriter : public IExportWriter {
public:
    explicit OpenIOCExportWriter(std::ostream& output);
    ~OpenIOCExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    std::string m_lastError;
    std::string m_buffer;
    
    void WriteXMLEscaped(std::string_view str);
    [[nodiscard]] std::string MapIOCTypeToOpenIOCSearch(IOCType type) const;
    void WriteIndicatorItem(const IOCEntry& entry, const IStringPoolReader* stringPool);
};

// ============================================================================
// Plain Text Export Writer
// ============================================================================

/**
 * @brief Plain text format export writer (one IOC per line)
 */
class PlainTextExportWriter : public IExportWriter {
public:
    explicit PlainTextExportWriter(std::ostream& output);
    ~PlainTextExportWriter() override;
    
    bool Begin(const ExportOptions& options) override;
    bool WriteEntry(const IOCEntry& entry, const IStringPoolReader* stringPool) override;
    bool End() override;
    void Flush() override;
    [[nodiscard]] uint64_t GetBytesWritten() const noexcept override;
    [[nodiscard]] std::string GetLastError() const override;
    
private:
    std::ostream& m_output;
    ExportOptions m_options;
    uint64_t m_bytesWritten = 0;
    std::string m_lastError;
    
    [[nodiscard]] std::string FormatIOCValue(const IOCEntry& entry, const IStringPoolReader* stringPool) const;
};

// ============================================================================
// ThreatIntelExporter Class
// ============================================================================

/**
 * @brief Main export coordinator class
 *
 * Provides high-level export functionality with streaming support,
 * progress tracking, and multi-format output capabilities.
 *
 * Usage:
 * @code
 * ThreatIntelExporter exporter;
 * 
 * // Export to CSV
 * ExportOptions opts = ExportOptions::FastCSV();
 * ExportResult result = exporter.ExportToFile(
 *     database, 
 *     L"threats.csv", 
 *     opts,
 *     [](const ExportProgress& p) {
 *         std::cout << p.percentComplete << "% complete" << std::endl;
 *         return true; // continue
 *     }
 * );
 * 
 * // Export to memory buffer
 * std::string jsonData;
 * result = exporter.ExportToString(database, jsonData, ExportOptions());
 * @endcode
 */
class ThreatIntelExporter {
public:
    ThreatIntelExporter();
    ~ThreatIntelExporter();
    
    // Non-copyable, movable
    ThreatIntelExporter(const ThreatIntelExporter&) = delete;
    ThreatIntelExporter& operator=(const ThreatIntelExporter&) = delete;
    ThreatIntelExporter(ThreatIntelExporter&&) noexcept;
    ThreatIntelExporter& operator=(ThreatIntelExporter&&) noexcept;
    
    // =========================================================================
    // File Export
    // =========================================================================
    
    /**
     * @brief Export IOC entries to a file
     * @param database Database to export from
     * @param outputPath Output file path
     * @param options Export options
     * @param progressCallback Optional progress callback
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToFile(
        const ThreatIntelDatabase& database,
        const std::wstring& outputPath,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Export IOC entries from span to file
     * @param entries Span of entries to export
     * @param stringPool String pool reader for metadata
     * @param outputPath Output file path
     * @param options Export options
     * @param progressCallback Optional progress callback
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToFile(
        std::span<const IOCEntry> entries,
        const IStringPoolReader* stringPool,
        const std::wstring& outputPath,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Stream Export
    // =========================================================================
    
    /**
     * @brief Export IOC entries to an output stream
     * @param database Database to export from
     * @param output Output stream
     * @param options Export options
     * @param progressCallback Optional progress callback
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToStream(
        const ThreatIntelDatabase& database,
        std::ostream& output,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    /**
     * @brief Export IOC entries from span to stream
     * @param entries Span of entries to export
     * @param stringPool String pool reader for metadata
     * @param output Output stream
     * @param options Export options
     * @param progressCallback Optional progress callback
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToStream(
        std::span<const IOCEntry> entries,
        const IStringPoolReader* stringPool,
        std::ostream& output,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Memory Export
    // =========================================================================
    
    /**
     * @brief Export IOC entries to a string
     * @param database Database to export from
     * @param output Output string
     * @param options Export options
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToString(
        const ThreatIntelDatabase& database,
        std::string& output,
        const ExportOptions& options
    );
    
    /**
     * @brief Export IOC entries from span to string
     * @param entries Span of entries to export
     * @param stringPool String pool reader for metadata
     * @param output Output string
     * @param options Export options
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToString(
        std::span<const IOCEntry> entries,
        const IStringPoolReader* stringPool,
        std::string& output,
        const ExportOptions& options
    );
    
    /**
     * @brief Export IOC entries to a byte vector
     * @param database Database to export from
     * @param output Output vector
     * @param options Export options
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportToBytes(
        const ThreatIntelDatabase& database,
        std::vector<uint8_t>& output,
        const ExportOptions& options
    );
    
    // =========================================================================
    // Single Entry Export
    // =========================================================================
    
    /**
     * @brief Export a single IOC entry to string
     * @param entry Entry to export
     * @param stringPool String pool reader for metadata
     * @param format Export format
     * @param fields Fields to include
     * @return Exported string
     */
    [[nodiscard]] std::string ExportEntry(
        const IOCEntry& entry,
        const IStringPoolReader* stringPool,
        ExportFormat format = ExportFormat::JSON,
        ExportFields fields = ExportFields::Standard
    );
    
    /**
     * @brief Export IOC value to string representation
     * @param entry Entry containing the value
     * @param stringPool String pool reader
     * @return String representation of the IOC value
     */
    [[nodiscard]] static std::string FormatIOCValue(
        const IOCEntry& entry,
        const IStringPoolReader* stringPool
    );
    
    // =========================================================================
    // Batch Export
    // =========================================================================
    
    /**
     * @brief Export entries by type to separate files
     * @param database Database to export from
     * @param outputDir Output directory
     * @param options Base export options
     * @param progressCallback Optional progress callback
     * @return Map of type to export result
     */
    [[nodiscard]] std::unordered_map<IOCType, ExportResult> ExportByType(
        const ThreatIntelDatabase& database,
        const std::wstring& outputDir,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Incremental Export
    // =========================================================================
    
    /**
     * @brief Export only entries modified since last export
     * @param database Database to export from
     * @param outputPath Output file path
     * @param lastExportTimestamp Timestamp of last export
     * @param options Export options
     * @param progressCallback Optional progress callback
     * @return Export result
     */
    [[nodiscard]] ExportResult ExportIncremental(
        const ThreatIntelDatabase& database,
        const std::wstring& outputPath,
        uint64_t lastExportTimestamp,
        const ExportOptions& options,
        ExportProgressCallback progressCallback = nullptr
    );
    
    // =========================================================================
    // Cancellation
    // =========================================================================
    
    /**
     * @brief Request cancellation of ongoing export
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
     * @brief Get total entries exported across all operations
     */
    [[nodiscard]] uint64_t GetTotalEntriesExported() const noexcept;
    
    /**
     * @brief Get total bytes written across all operations
     */
    [[nodiscard]] uint64_t GetTotalBytesWritten() const noexcept;
    
    /**
     * @brief Get total export operations performed
     */
    [[nodiscard]] uint32_t GetTotalExportCount() const noexcept;
    
private:
    // Implementation helper methods
    [[nodiscard]] std::unique_ptr<IExportWriter> CreateWriter(
        std::ostream& output,
        ExportFormat format
    );
    
    [[nodiscard]] ExportResult DoExport(
        std::span<const IOCEntry> entries,
        const IStringPoolReader* stringPool,
        IExportWriter& writer,
        const ExportOptions& options,
        ExportProgressCallback progressCallback
    );
    
    void UpdateProgress(
        ExportProgress& progress,
        size_t currentEntry,
        size_t totalEntries,
        uint64_t bytesWritten,
        const std::chrono::steady_clock::time_point& startTime
    );
    
    // Statistics
    std::atomic<uint64_t> m_totalEntriesExported{0};
    std::atomic<uint64_t> m_totalBytesWritten{0};
    std::atomic<uint32_t> m_totalExportCount{0};
    
    // Cancellation
    std::atomic<bool> m_cancellationRequested{false};
};

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief Get file extension for export format
 * @param format Export format
 * @return File extension (including dot)
 */
[[nodiscard]] const char* GetExportFormatExtension(ExportFormat format) noexcept;

/**
 * @brief Get MIME type for export format
 * @param format Export format
 * @return MIME type string
 */
[[nodiscard]] const char* GetExportFormatMimeType(ExportFormat format) noexcept;

/**
 * @brief Get human-readable name for export format
 * @param format Export format
 * @return Format name
 */
[[nodiscard]] const char* GetExportFormatName(ExportFormat format) noexcept;

/**
 * @brief Parse export format from string
 * @param str Format string (e.g., "csv", "json", "stix")
 * @return Export format or nullopt if not recognized
 */
[[nodiscard]] std::optional<ExportFormat> ParseExportFormat(std::string_view str) noexcept;

/**
 * @brief Generate UUID v4 for STIX/MISP identifiers
 * @return UUID string in standard format
 */
[[nodiscard]] std::string GenerateUUID();

/**
 * @brief Format timestamp as ISO 8601 string
 * @param timestamp Unix timestamp
 * @return ISO 8601 formatted string
 */
[[nodiscard]] std::string FormatISO8601Timestamp(uint64_t timestamp);

/**
 * @brief Calculate SHA256 hash of file
 * @param filePath Path to file
 * @return SHA256 hash as hex string or empty on error
 */
[[nodiscard]] std::string CalculateFileSHA256(const std::wstring& filePath);

} // namespace ThreatIntel
} // namespace ShadowStrike
