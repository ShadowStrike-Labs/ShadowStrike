/**
 * ============================================================================
 * ShadowStrike NGAV - EMAIL ATTACHMENT SCANNER MODULE
 * ============================================================================
 *
 * @file AttachmentScanner.hpp
 * @brief Enterprise-grade email attachment scanning engine for detecting
 *        malicious content in email attachments across all formats.
 *
 * Provides comprehensive attachment analysis including archive extraction,
 * format-specific exploit detection, and embedded content scanning.
 *
 * SCANNING CAPABILITIES:
 * ======================
 *
 * 1. ARCHIVE HANDLING
 *    - ZIP extraction
 *    - RAR extraction
 *    - 7z extraction
 *    - TAR/GZIP extraction
 *    - ISO mounting
 *    - Nested archive support
 *    - Password-protected detection
 *
 * 2. DOCUMENT ANALYSIS
 *    - Office macros (VBA)
 *    - PDF JavaScript
 *    - OLE objects
 *    - DDE exploitation
 *    - Template injection
 *    - Embedded executables
 *
 * 3. EXECUTABLE DETECTION
 *    - PE file analysis
 *    - DLL detection
 *    - Script files
 *    - Batch files
 *    - PowerShell scripts
 *    - Disguised executables
 *
 * 4. CONTENT ANALYSIS
 *    - File type verification
 *    - Extension mismatch
 *    - Magic byte validation
 *    - Entropy analysis
 *    - Polyglot detection
 *
 * 5. THREAT DETECTION
 *    - Known malware signatures
 *    - Heuristic analysis
 *    - YARA rules
 *    - Sandbox detonation
 *    - ThreatIntel correlation
 *
 * INTEGRATION:
 * ============
 * - HashStore for known malware
 * - SignatureStore for detection rules
 * - PatternStore for patterns
 * - MacroDetector for VBA analysis
 * - ThreatIntel for IOC matching
 *
 * @note Supports recursive scanning of nested archives.
 * @note Integrates with sandbox for dynamic analysis.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <filesystem>
#include <span>
#include <future>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Scripts/MacroDetector.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Email {
    class AttachmentScannerImpl;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AttachmentConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum attachment size (100 MB)
    inline constexpr size_t MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024;
    
    /// @brief Maximum archive nesting depth
    inline constexpr size_t MAX_ARCHIVE_DEPTH = 10;
    
    /// @brief Maximum extracted files
    inline constexpr size_t MAX_EXTRACTED_FILES = 1000;
    
    /// @brief Maximum extraction size (500 MB)
    inline constexpr size_t MAX_EXTRACTION_SIZE = 500 * 1024 * 1024;
    
    /// @brief High-risk file extensions
    inline constexpr const char* HIGH_RISK_EXTENSIONS[] = {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".ps1", ".psm1", ".psd1", ".msi", ".msp",
        ".hta", ".lnk", ".pif", ".reg", ".inf"
    };
    
    /// @brief Archive extensions
    inline constexpr const char* ARCHIVE_EXTENSIONS[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
        ".xz", ".iso", ".img", ".cab", ".arj"
    };

}  // namespace AttachmentConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Attachment verdict
 */
enum class AttachmentVerdict : uint8_t {
    Clean               = 0,    ///< No threats detected
    Malicious           = 1,    ///< Confirmed malware
    Suspicious          = 2,    ///< Suspicious but not confirmed
    Potentially Unwanted = 3,   ///< PUA/PUP
    HighRisk            = 4,    ///< High-risk file type
    EncryptedArchive    = 5,    ///< Cannot scan (encrypted)
    CorruptedFile       = 6,    ///< File is corrupted
    UnsupportedType     = 7,    ///< Unsupported file type
    SizeLimitExceeded   = 8,    ///< Exceeds size limits
    ScanError           = 255   ///< Scan error occurred
};

/**
 * @brief File type category
 */
enum class FileTypeCategory : uint8_t {
    Unknown             = 0,
    Executable          = 1,
    Script              = 2,
    Document            = 3,
    Spreadsheet         = 4,
    Presentation        = 5,
    PDF                 = 6,
    Archive             = 7,
    DiskImage           = 8,
    Media               = 9,
    Data                = 10,
    Configuration       = 11
};

/**
 * @brief Threat type
 */
enum class AttachmentThreatType : uint32_t {
    None                    = 0,
    KnownMalware            = 1 << 0,
    SuspiciousContent       = 1 << 1,
    MaliciousMacro          = 1 << 2,
    PDFJavaScript           = 1 << 3,
    OLEObject               = 1 << 4,
    DDEExploit              = 1 << 5,
    TemplateInjection       = 1 << 6,
    EmbeddedExecutable      = 1 << 7,
    DisguisedExecutable     = 1 << 8,
    ExtensionMismatch       = 1 << 9,
    HighEntropy             = 1 << 10,
    PolyglotFile            = 1 << 11,
    ExploitCode             = 1 << 12,
    ShellcodeDetected       = 1 << 13,
    PasswordProtected       = 1 << 14,
    ZipBomb                 = 1 << 15
};

/**
 * @brief Scan depth
 */
enum class ScanDepth : uint8_t {
    Quick               = 0,    ///< Fast scan (signatures only)
    Standard            = 1,    ///< Standard scan
    Deep                = 2,    ///< Deep analysis
    Forensic            = 3     ///< Full forensic analysis
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Detected artifact info
 */
struct DetectedArtifact {
    /// @brief Artifact type
    std::string artifactType;
    
    /// @brief Description
    std::string description;
    
    /// @brief Location (file path or offset)
    std::string location;
    
    /// @brief Risk level (0-100)
    int riskLevel = 0;
    
    /// @brief Extraction successful
    bool extractionSuccessful = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Nested file info (from archives)
 */
struct NestedFileInfo {
    /// @brief File name
    std::string fileName;
    
    /// @brief Relative path within archive
    std::string relativePath;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Compressed size
    size_t compressedSize = 0;
    
    /// @brief File type
    FileTypeCategory fileType = FileTypeCategory::Unknown;
    
    /// @brief Is high-risk
    bool isHighRisk = false;
    
    /// @brief Is encrypted
    bool isEncrypted = false;
    
    /// @brief Scan result
    AttachmentVerdict verdict = AttachmentVerdict::Clean;
    
    /// @brief Threat name (if malicious)
    std::string threatName;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Attachment scan result
 */
struct AttachmentScanResult {
    /// @brief File name
    std::string fileName;
    
    /// @brief File path (if from disk)
    std::filesystem::path filePath;
    
    /// @brief Verdict
    AttachmentVerdict verdict = AttachmentVerdict::Clean;
    
    /// @brief File type category
    FileTypeCategory fileType = FileTypeCategory::Unknown;
    
    /// @brief Detected MIME type
    std::string mimeType;
    
    /// @brief Is archive
    bool isArchive = false;
    
    /// @brief Archive depth (nesting level)
    size_t archiveDepth = 0;
    
    /// @brief Threat types detected
    AttachmentThreatType threats = AttachmentThreatType::None;
    
    /// @brief Primary threat name
    std::string threatName;
    
    /// @brief Threat family
    std::string threatFamily;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detected artifacts
    std::vector<DetectedArtifact> artifacts;
    
    /// @brief Nested files (from archives)
    std::vector<NestedFileInfo> nestedFiles;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Matched YARA rules
    std::vector<std::string> matchedYARA;
    
    /// @brief File hashes
    std::string sha256;
    std::string sha1;
    std::string md5;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Has macros
    bool hasMacros = false;
    
    /// @brief Has embedded content
    bool hasEmbeddedContent = false;
    
    /// @brief Is password protected
    bool isPasswordProtected = false;
    
    /// @brief Extension matches content
    bool extensionMatchesContent = true;
    
    /// @brief Scan time
    SystemTimePoint scanTime;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /// @brief Scan error message
    std::string errorMessage;
    
    [[nodiscard]] bool IsMalicious() const noexcept;
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan configuration
 */
struct AttachmentScanConfig {
    /// @brief Scan depth
    ScanDepth depth = ScanDepth::Standard;
    
    /// @brief Extract archives
    bool extractArchives = true;
    
    /// @brief Maximum archive depth
    size_t maxArchiveDepth = AttachmentConstants::MAX_ARCHIVE_DEPTH;
    
    /// @brief Maximum extraction size
    size_t maxExtractionSize = AttachmentConstants::MAX_EXTRACTION_SIZE;
    
    /// @brief Scan macros
    bool scanMacros = true;
    
    /// @brief Scan embedded content
    bool scanEmbeddedContent = true;
    
    /// @brief Use YARA rules
    bool useYARA = true;
    
    /// @brief Use sandbox detonation
    bool useSandbox = false;
    
    /// @brief Block high-risk extensions
    bool blockHighRiskExtensions = false;
    
    /// @brief Block password-protected archives
    bool blockPasswordProtected = false;
    
    /// @brief Calculate all hashes
    bool calculateAllHashes = true;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct AttachmentStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> cleanDetected{0};
    std::atomic<uint64_t> archivesExtracted{0};
    std::atomic<uint64_t> nestedFilesScanned{0};
    std::atomic<uint64_t> macrosDetected{0};
    std::atomic<uint64_t> passwordProtectedBlocked{0};
    std::atomic<uint64_t> highRiskExtensionsBlocked{0};
    std::atomic<uint64_t> scanErrors{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byFileType{};
    std::array<std::atomic<uint64_t>, 16> byThreatType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Module configuration
 */
struct AttachmentScannerConfiguration {
    /// @brief Enable scanner
    bool enabled = true;
    
    /// @brief Default scan config
    AttachmentScanConfig defaultScanConfig;
    
    /// @brief Quarantine path
    std::filesystem::path quarantinePath;
    
    /// @brief Temp extraction path
    std::filesystem::path tempExtractionPath;
    
    /// @brief Maximum concurrent scans
    size_t maxConcurrentScans = 4;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const AttachmentScanResult&)>;
using ThreatDetectedCallback = std::function<void(const AttachmentScanResult&)>;
using ProgressCallback = std::function<void(float progress, const std::string& currentFile)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// ATTACHMENT SCANNER CLASS
// ============================================================================

/**
 * @class AttachmentScanner
 * @brief Enterprise email attachment scanning engine
 */
class AttachmentScanner final {
public:
    [[nodiscard]] static AttachmentScanner& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    AttachmentScanner(const AttachmentScanner&) = delete;
    AttachmentScanner& operator=(const AttachmentScanner&) = delete;
    AttachmentScanner(AttachmentScanner&&) = delete;
    AttachmentScanner& operator=(AttachmentScanner&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const AttachmentScannerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const AttachmentScannerConfiguration& config);
    [[nodiscard]] AttachmentScannerConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan attachment file
    [[nodiscard]] AttachmentScanResult ScanAttachment(
        const std::filesystem::path& path,
        const AttachmentScanConfig& config = {});
    
    /// @brief Scan attachment from buffer
    [[nodiscard]] AttachmentScanResult ScanBuffer(
        std::span<const uint8_t> buffer,
        const std::string& fileName,
        const AttachmentScanConfig& config = {});
    
    /// @brief Scan attachment async
    [[nodiscard]] std::future<AttachmentScanResult> ScanAttachmentAsync(
        const std::filesystem::path& path,
        const AttachmentScanConfig& config = {});
    
    /// @brief Batch scan multiple attachments
    [[nodiscard]] std::vector<AttachmentScanResult> ScanBatch(
        const std::vector<std::filesystem::path>& paths,
        const AttachmentScanConfig& config = {});

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Detect file type
    [[nodiscard]] FileTypeCategory DetectFileType(const std::filesystem::path& path);
    
    /// @brief Detect file type from buffer
    [[nodiscard]] FileTypeCategory DetectFileType(
        std::span<const uint8_t> buffer,
        const std::string& fileName);
    
    /// @brief Check if extension is high-risk
    [[nodiscard]] bool IsHighRiskExtension(std::string_view extension) const noexcept;
    
    /// @brief Verify extension matches content
    [[nodiscard]] bool VerifyExtension(
        const std::filesystem::path& path);

    // ========================================================================
    // ARCHIVE HANDLING
    // ========================================================================
    
    /// @brief Extract archive
    [[nodiscard]] std::vector<NestedFileInfo> ExtractArchive(
        const std::filesystem::path& archivePath,
        const std::filesystem::path& extractTo);
    
    /// @brief Is password-protected archive
    [[nodiscard]] bool IsPasswordProtectedArchive(const std::filesystem::path& path);
    
    /// @brief Is archive type
    [[nodiscard]] bool IsArchive(const std::filesystem::path& path);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanResultCallback(ScanResultCallback callback);
    void RegisterThreatCallback(ThreatDetectedCallback callback);
    void RegisterProgressCallback(ProgressCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] AttachmentStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    AttachmentScanner();
    ~AttachmentScanner();
    
    std::unique_ptr<AttachmentScannerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetAttachmentVerdictName(AttachmentVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetFileTypeCategoryName(FileTypeCategory cat) noexcept;
[[nodiscard]] std::string_view GetAttachmentThreatTypeName(AttachmentThreatType type) noexcept;
[[nodiscard]] std::string_view GetScanDepthName(ScanDepth depth) noexcept;
[[nodiscard]] FileTypeCategory ClassifyByExtension(std::string_view extension) noexcept;
[[nodiscard]] FileTypeCategory ClassifyByMagic(std::span<const uint8_t> header) noexcept;

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ATTACHMENT_SCAN(path) \
    ::ShadowStrike::Email::AttachmentScanner::Instance().ScanAttachment(path)

#define SS_ATTACHMENT_SCAN_BUFFER(buffer, name) \
    ::ShadowStrike::Email::AttachmentScanner::Instance().ScanBuffer(buffer, name)