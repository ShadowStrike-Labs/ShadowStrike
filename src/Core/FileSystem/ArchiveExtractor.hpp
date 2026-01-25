/**
 * ============================================================================
 * ShadowStrike Core FileSystem - ARCHIVE EXTRACTOR (The Vault Breaker)
 * ============================================================================
 *
 * @file ArchiveExtractor.hpp
 * @brief Enterprise-grade secure archive extraction and scanning engine.
 *
 * This module provides comprehensive archive handling capabilities with
 * multiple layers of protection against archive bombs, malicious payloads,
 * and evasion techniques commonly used by malware.
 *
 * Key Capabilities:
 * =================
 * 1. FORMAT SUPPORT
 *    - ZIP (PKZip, WinZip, 7-Zip)
 *    - RAR (RAR4, RAR5)
 *    - 7Z (LZMA, LZMA2)
 *    - TAR (plain, gzip, bzip2, xz)
 *    - GZ, BZ2, XZ, LZMA
 *    - CAB (Microsoft Cabinet)
 *    - ISO (ISO9660, UDF)
 *    - VHD/VHDX (Virtual disks)
 *    - WIM (Windows Imaging)
 *    - MSI (Windows Installer)
 *    - DMG (macOS disk image)
 *
 * 2. SECURITY PROTECTIONS
 *    - Zip bomb detection
 *    - Compression ratio limits
 *    - Nested archive limits
 *    - Path traversal prevention
 *    - Symlink attack prevention
 *    - Size limits per entry
 *
 * 3. EXTRACTION MODES
 *    - In-memory extraction
 *    - Streaming extraction
 *    - Selective extraction
 *    - Password handling
 *
 * 4. SCANNING INTEGRATION
 *    - Per-entry callbacks
 *    - Progressive scanning
 *    - Metadata extraction
 *    - Entropy analysis
 *
 * Archive Analysis Architecture:
 * ==============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       ArchiveExtractor                              │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │FormatDetector│  │SecurityGuard │  │    ExtractionEngine      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Magic nums │  │ - Zip bombs  │  │ - Memory extract         │  │
 *   │  │ - Headers    │  │ - Ratios     │  │ - Stream extract         │  │
 *   │  │ - Nested     │  │ - Path       │  │ - Progressive            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │PasswordHandler│ │ MetadataExtract│ │   ScanIntegration       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Dictionary │  │ - Timestamps │  │ - Callbacks              │  │
 *   │  │ - Brute force│  │ - Attributes │  │ - Progress               │  │
 *   │  │ - User input │  │ - Comments   │  │ - Results                │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Zip Bomb Detection:
 * ===================
 * - Compression ratio monitoring (default: 100:1 max)
 * - Quine detection (self-referencing)
 * - Layer bomb detection (nested archives)
 * - Overlapping entries detection
 * - Total decompressed size limits
 *
 * Integration Points:
 * ===================
 * - ScanEngine: Per-entry scanning
 * - FileTypeAnalyzer: Content type detection
 * - CompressionUtils: Low-level decompression
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see FileTypeAnalyzer.hpp for type detection
 * @see CompressionUtils.hpp for decompression
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class ArchiveExtractorImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace ArchiveExtractorConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Security limits
    constexpr double DEFAULT_MAX_COMPRESSION_RATIO = 100.0;
    constexpr uint32_t DEFAULT_MAX_NESTING_DEPTH = 5;
    constexpr uint64_t DEFAULT_MAX_TOTAL_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10 GB
    constexpr uint64_t DEFAULT_MAX_ENTRY_SIZE = 2ULL * 1024 * 1024 * 1024;   // 2 GB
    constexpr uint32_t DEFAULT_MAX_ENTRIES = 1000000;

    // Memory limits
    constexpr size_t MAX_MEMORY_EXTRACTION = 100 * 1024 * 1024;  // 100 MB
    constexpr size_t STREAMING_BUFFER_SIZE = 64 * 1024;          // 64 KB

    // Password attempts
    constexpr uint32_t MAX_PASSWORD_ATTEMPTS = 10;

}  // namespace ArchiveExtractorConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ArchiveFormat
 * @brief Supported archive formats.
 */
enum class ArchiveFormat : uint16_t {
    Unknown = 0,

    // Standard compressed
    ZIP = 1,
    RAR = 2,
    RAR5 = 3,
    SevenZip = 4,
    TAR = 5,
    GZIP = 6,
    BZIP2 = 7,
    XZ = 8,
    LZMA = 9,
    ZSTD = 10,

    // Compound tar
    TarGz = 20,
    TarBz2 = 21,
    TarXz = 22,
    TarZstd = 23,

    // Windows specific
    CAB = 30,
    MSI = 31,
    WIM = 32,

    // Disk images
    ISO = 40,
    VHD = 41,
    VHDX = 42,
    DMG = 43,
    IMG = 44,

    // Other
    ARJ = 50,
    LZH = 51,
    ACE = 52,
    CPIO = 53,
    RPM = 54,
    DEB = 55
};

/**
 * @enum ExtractionMode
 * @brief Extraction mode.
 */
enum class ExtractionMode : uint8_t {
    InMemory = 0,                  // Extract to memory buffer
    ToDisk = 1,                    // Extract to disk
    Streaming = 2,                 // Stream-based extraction
    MetadataOnly = 3               // List only, no extraction
};

/**
 * @enum EntryType
 * @brief Archive entry type.
 */
enum class EntryType : uint8_t {
    Unknown = 0,
    File = 1,
    Directory = 2,
    Symlink = 3,
    Hardlink = 4,
    BlockDevice = 5,
    CharDevice = 6,
    FIFO = 7,
    Archive = 8                    // Nested archive
};

/**
 * @enum ExtractionResult
 * @brief Result of extraction operation.
 */
enum class ExtractionResult : uint8_t {
    Success = 0,
    PartialSuccess = 1,
    PasswordRequired = 2,
    WrongPassword = 3,
    CorruptedArchive = 4,
    UnsupportedFormat = 5,
    ZipBombDetected = 6,
    RatioExceeded = 7,
    SizeExceeded = 8,
    NestingExceeded = 9,
    PathTraversal = 10,
    AccessDenied = 11,
    DiskFull = 12,
    IOError = 13,
    Cancelled = 14
};

/**
 * @enum SecurityFlag
 * @brief Security check flags.
 */
enum class SecurityFlag : uint32_t {
    None = 0,
    ZipBombSuspected = 0x00000001,
    HighCompressionRatio = 0x00000002,
    DeepNesting = 0x00000004,
    PathTraversalAttempt = 0x00000008,
    SymlinkAttack = 0x00000010,
    SuspiciousEntry = 0x00000020,
    EncryptedContent = 0x00000040,
    OverlappingEntries = 0x00000080,
    HiddenEntry = 0x00000100
};

// Enable bitwise operations
inline SecurityFlag operator|(SecurityFlag a, SecurityFlag b) {
    return static_cast<SecurityFlag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline SecurityFlag operator&(SecurityFlag a, SecurityFlag b) {
    return static_cast<SecurityFlag>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ArchiveEntry
 * @brief Information about archive entry.
 */
struct alignas(128) ArchiveEntry {
    // Identity
    uint64_t entryId{ 0 };
    std::wstring path;                     // Path within archive
    std::wstring filename;                 // Just filename
    EntryType type{ EntryType::Unknown };

    // Sizes
    uint64_t compressedSize{ 0 };
    uint64_t uncompressedSize{ 0 };
    double compressionRatio{ 0.0 };

    // Attributes
    uint32_t attributes{ 0 };
    uint32_t permissions{ 0 };
    bool isEncrypted{ false };
    bool isDirectory{ false };
    bool isHidden{ false };

    // Timestamps
    std::chrono::system_clock::time_point modifiedTime;
    std::chrono::system_clock::time_point createdTime;
    std::chrono::system_clock::time_point accessedTime;

    // Compression
    std::string compressionMethod;
    uint8_t compressionLevel{ 0 };

    // Checksums
    uint32_t crc32{ 0 };
    std::array<uint8_t, 32> sha256{ 0 };
    std::string sha256Hex;

    // Analysis
    double entropy{ 0.0 };
    bool isPE{ false };                    // Contains PE header
    bool isScript{ false };                // Contains script
    bool isNestedArchive{ false };
    ArchiveFormat nestedFormat{ ArchiveFormat::Unknown };

    // Security
    SecurityFlag securityFlags{ SecurityFlag::None };
    bool isSuspicious{ false };

    // Link info
    std::wstring linkTarget;

    // Comment
    std::string comment;
};

/**
 * @struct ArchiveInfo
 * @brief Overall archive information.
 */
struct alignas(128) ArchiveInfo {
    // Format
    ArchiveFormat format{ ArchiveFormat::Unknown };
    std::string formatName;
    std::string formatVersion;

    // File info
    std::wstring filePath;
    uint64_t fileSize{ 0 };

    // Contents
    uint32_t totalEntries{ 0 };
    uint32_t fileCount{ 0 };
    uint32_t directoryCount{ 0 };
    uint64_t totalCompressedSize{ 0 };
    uint64_t totalUncompressedSize{ 0 };
    double overallCompressionRatio{ 0.0 };

    // Encryption
    bool hasEncryptedEntries{ false };
    bool isHeaderEncrypted{ false };
    std::string encryptionMethod;

    // Multi-volume
    bool isMultiVolume{ false };
    uint32_t volumeCount{ 0 };
    uint32_t currentVolume{ 0 };

    // Integrity
    bool hasIntegrityCheck{ false };
    bool integrityValid{ true };

    // Security assessment
    SecurityFlag securityFlags{ SecurityFlag::None };
    bool isSuspicious{ false };
    std::vector<std::string> securityWarnings;

    // Comments
    std::string archiveComment;

    // Analysis time
    std::chrono::system_clock::time_point analyzedTime;
};

/**
 * @struct ExtractedData
 * @brief Extracted entry data.
 */
struct alignas(64) ExtractedData {
    uint64_t entryId{ 0 };
    std::wstring entryPath;

    std::vector<uint8_t> data;
    uint64_t size{ 0 };

    ExtractionResult result{ ExtractionResult::Success };
    std::string errorMessage;

    double entropy{ 0.0 };
    std::array<uint8_t, 32> sha256{ 0 };
};

/**
 * @struct ExtractionProgress
 * @brief Progress information.
 */
struct alignas(32) ExtractionProgress {
    uint32_t currentEntry{ 0 };
    uint32_t totalEntries{ 0 };
    uint64_t bytesExtracted{ 0 };
    uint64_t totalBytes{ 0 };
    double percentComplete{ 0.0 };

    std::wstring currentFile;
    uint32_t nestingLevel{ 0 };
};

/**
 * @struct ExtractionOptions
 * @brief Options for extraction.
 */
struct alignas(64) ExtractionOptions {
    // Mode
    ExtractionMode mode{ ExtractionMode::InMemory };
    std::wstring outputDirectory;          // For ToDisk mode

    // Security limits
    double maxCompressionRatio{ ArchiveExtractorConstants::DEFAULT_MAX_COMPRESSION_RATIO };
    uint32_t maxNestingDepth{ ArchiveExtractorConstants::DEFAULT_MAX_NESTING_DEPTH };
    uint64_t maxTotalSize{ ArchiveExtractorConstants::DEFAULT_MAX_TOTAL_SIZE };
    uint64_t maxEntrySize{ ArchiveExtractorConstants::DEFAULT_MAX_ENTRY_SIZE };
    uint32_t maxEntries{ ArchiveExtractorConstants::DEFAULT_MAX_ENTRIES };

    // Filtering
    std::vector<std::wstring> includePatterns;   // Extract only matching
    std::vector<std::wstring> excludePatterns;   // Skip matching

    // Features
    bool extractNestedArchives{ true };
    bool preserveTimestamps{ true };
    bool preservePermissions{ false };
    bool skipEncrypted{ false };
    bool stopOnError{ false };

    // Password
    std::string password;
    std::vector<std::string> passwordList;

    // Factory methods
    static ExtractionOptions CreateDefault() noexcept;
    static ExtractionOptions CreateSecure() noexcept;
    static ExtractionOptions CreateScanOnly() noexcept;
};

/**
 * @struct ExtractionSummary
 * @brief Summary of extraction operation.
 */
struct alignas(64) ExtractionSummary {
    ExtractionResult result{ ExtractionResult::Success };

    uint32_t entriesProcessed{ 0 };
    uint32_t entriesExtracted{ 0 };
    uint32_t entriesSkipped{ 0 };
    uint32_t entriesFailed{ 0 };
    uint32_t nestedArchives{ 0 };

    uint64_t bytesExtracted{ 0 };
    std::chrono::milliseconds duration{ 0 };

    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    SecurityFlag securityFlags{ SecurityFlag::None };
};

/**
 * @struct ArchiveExtractorConfig
 * @brief Configuration for archive extractor.
 */
struct alignas(64) ArchiveExtractorConfig {
    // Default limits
    double defaultMaxRatio{ ArchiveExtractorConstants::DEFAULT_MAX_COMPRESSION_RATIO };
    uint32_t defaultMaxNesting{ ArchiveExtractorConstants::DEFAULT_MAX_NESTING_DEPTH };
    uint64_t defaultMaxTotal{ ArchiveExtractorConstants::DEFAULT_MAX_TOTAL_SIZE };

    // Memory management
    size_t maxMemoryExtraction{ ArchiveExtractorConstants::MAX_MEMORY_EXTRACTION };
    size_t streamingBufferSize{ ArchiveExtractorConstants::STREAMING_BUFFER_SIZE };

    // Parallelization
    uint32_t workerThreads{ 4 };
    bool parallelExtraction{ true };

    // Security
    bool strictSecurityChecks{ true };
    bool abortOnSecurityIssue{ true };

    // Temp directory
    std::wstring tempDirectory;

    // Factory methods
    static ArchiveExtractorConfig CreateDefault() noexcept;
    static ArchiveExtractorConfig CreateHighSecurity() noexcept;
};

/**
 * @struct ArchiveExtractorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) ArchiveExtractorStatistics {
    std::atomic<uint64_t> archivesProcessed{ 0 };
    std::atomic<uint64_t> entriesExtracted{ 0 };
    std::atomic<uint64_t> bytesExtracted{ 0 };

    std::atomic<uint64_t> zipBombsDetected{ 0 };
    std::atomic<uint64_t> pathTraversalsBlocked{ 0 };
    std::atomic<uint64_t> encryptedSkipped{ 0 };

    std::atomic<uint64_t> nestedArchives{ 0 };
    std::atomic<uint64_t> extractionErrors{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for each extracted entry.
 */
using EntryCallback = std::function<void(const ArchiveEntry& entry, const std::vector<uint8_t>& data)>;

/**
 * @brief Callback for entry (streaming mode).
 */
using StreamCallback = std::function<bool(const ArchiveEntry& entry, std::span<const uint8_t> chunk, bool isLast)>;

/**
 * @brief Callback for progress updates.
 */
using ProgressCallback = std::function<void(const ExtractionProgress& progress)>;

/**
 * @brief Callback for password request.
 */
using PasswordCallback = std::function<std::optional<std::string>(const std::wstring& archivePath, const std::wstring& entryPath)>;

/**
 * @brief Callback for security issue.
 */
using SecurityCallback = std::function<bool(const ArchiveEntry& entry, SecurityFlag flags)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class ArchiveExtractor
 * @brief Enterprise-grade secure archive extraction engine.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& extractor = ArchiveExtractor::Instance();
 * 
 * // List contents
 * auto entries = extractor.ListContents(L"suspicious.zip");
 * for (const auto& entry : entries) {
 *     if (entry.compressionRatio > 50.0) {
 *         LOG_WARNING << "High compression ratio: " << entry.path;
 *     }
 * }
 * 
 * // Scan archive with callback
 * extractor.ScanArchive(L"suspicious.zip",
 *     [](const ArchiveEntry& entry, const std::vector<uint8_t>& data) {
 *         // Scan each extracted file
 *         scanner.ScanBuffer(data, entry.path);
 *     },
 *     ExtractionOptions::CreateSecure());
 * 
 * // Handle encrypted archives
 * ExtractionOptions opts;
 * opts.passwordList = {"password1", "password2"};
 * auto summary = extractor.ExtractAll(L"encrypted.rar", L"C:\\temp", opts);
 * @endcode
 */
class ArchiveExtractor {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static ArchiveExtractor& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the archive extractor.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const ArchiveExtractorConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // FORMAT DETECTION
    // ========================================================================

    /**
     * @brief Detects archive format.
     * @param filePath Path to file.
     * @return Archive format.
     */
    [[nodiscard]] ArchiveFormat DetectFormat(const std::wstring& filePath) const;

    /**
     * @brief Detects format from buffer.
     * @param buffer Header bytes.
     * @return Archive format.
     */
    [[nodiscard]] ArchiveFormat DetectFormat(std::span<const uint8_t> buffer) const;

    /**
     * @brief Checks if file is an archive.
     * @param filePath Path to file.
     * @return True if archive.
     */
    [[nodiscard]] bool IsArchive(const std::wstring& filePath) const;

    /**
     * @brief Gets supported formats.
     * @return Vector of supported formats.
     */
    [[nodiscard]] std::vector<ArchiveFormat> GetSupportedFormats() const;

    // ========================================================================
    // ARCHIVE INFORMATION
    // ========================================================================

    /**
     * @brief Gets archive information.
     * @param filePath Path to archive.
     * @return Archive info.
     */
    [[nodiscard]] ArchiveInfo GetArchiveInfo(const std::wstring& filePath) const;

    /**
     * @brief Lists archive contents.
     * @param filePath Path to archive.
     * @param options Extraction options.
     * @return Vector of entries.
     */
    [[nodiscard]] std::vector<ArchiveEntry> ListContents(
        const std::wstring& filePath,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault()) const;

    /**
     * @brief Checks archive integrity.
     * @param filePath Path to archive.
     * @return True if valid.
     */
    [[nodiscard]] bool VerifyIntegrity(const std::wstring& filePath) const;

    // ========================================================================
    // EXTRACTION OPERATIONS
    // ========================================================================

    /**
     * @brief Extracts and scans archive with callback.
     * @param filePath Path to archive.
     * @param callback Callback for each entry.
     * @param options Extraction options.
     * @return Extraction summary.
     */
    ExtractionSummary ScanArchive(
        const std::wstring& filePath,
        EntryCallback callback,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault());

    /**
     * @brief Extracts all entries to directory.
     * @param filePath Path to archive.
     * @param outputDir Output directory.
     * @param options Extraction options.
     * @return Extraction summary.
     */
    ExtractionSummary ExtractAll(
        const std::wstring& filePath,
        const std::wstring& outputDir,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault());

    /**
     * @brief Extracts single entry.
     * @param filePath Path to archive.
     * @param entryPath Path within archive.
     * @param options Extraction options.
     * @return Extracted data.
     */
    [[nodiscard]] ExtractedData ExtractEntry(
        const std::wstring& filePath,
        const std::wstring& entryPath,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault());

    /**
     * @brief Extracts entries matching pattern.
     * @param filePath Path to archive.
     * @param pattern Glob pattern.
     * @param callback Callback for each entry.
     * @param options Extraction options.
     * @return Extraction summary.
     */
    ExtractionSummary ExtractMatching(
        const std::wstring& filePath,
        const std::wstring& pattern,
        EntryCallback callback,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault());

    /**
     * @brief Streaming extraction.
     * @param filePath Path to archive.
     * @param callback Stream callback.
     * @param options Extraction options.
     * @return Extraction summary.
     */
    ExtractionSummary ExtractStreaming(
        const std::wstring& filePath,
        StreamCallback callback,
        const ExtractionOptions& options = ExtractionOptions::CreateDefault());

    // ========================================================================
    // SECURITY ANALYSIS
    // ========================================================================

    /**
     * @brief Performs security analysis.
     * @param filePath Path to archive.
     * @return Archive info with security assessment.
     */
    [[nodiscard]] ArchiveInfo AnalyzeSecurity(const std::wstring& filePath) const;

    /**
     * @brief Checks for zip bomb.
     * @param filePath Path to archive.
     * @return True if zip bomb detected.
     */
    [[nodiscard]] bool IsZipBomb(const std::wstring& filePath) const;

    /**
     * @brief Gets security flags for entry.
     * @param entry Archive entry.
     * @return Security flags.
     */
    [[nodiscard]] SecurityFlag CheckEntrySecurity(const ArchiveEntry& entry) const;

    // ========================================================================
    // PASSWORD HANDLING
    // ========================================================================

    /**
     * @brief Sets password callback.
     * @param callback Password callback.
     */
    void SetPasswordCallback(PasswordCallback callback);

    /**
     * @brief Tests if password is correct.
     * @param filePath Path to archive.
     * @param password Password to test.
     * @return True if correct.
     */
    [[nodiscard]] bool TestPassword(const std::wstring& filePath, const std::string& password) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetProgressCallback(ProgressCallback callback);
    void SetSecurityCallback(SecurityCallback callback);

    // ========================================================================
    // CANCELLATION
    // ========================================================================

    /**
     * @brief Cancels ongoing extraction.
     */
    void Cancel() noexcept;

    /**
     * @brief Checks if extraction was cancelled.
     * @return True if cancelled.
     */
    [[nodiscard]] bool IsCancelled() const noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const ArchiveExtractorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    ArchiveExtractor();
    ~ArchiveExtractor();

    ArchiveExtractor(const ArchiveExtractor&) = delete;
    ArchiveExtractor& operator=(const ArchiveExtractor&) = delete;

    std::unique_ptr<ArchiveExtractorImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
