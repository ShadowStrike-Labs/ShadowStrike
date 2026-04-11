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
/**
 * ============================================================================
 * ShadowStrike Core FileSystem - FILE TYPE ANALYZER (The True Identifier)
 * ============================================================================
 *
 * @file FileTypeAnalyzer.hpp
 * @brief Enterprise-grade file type identification via magic numbers.
 *
 * This module provides reliable file type identification by analyzing file
 * headers (magic numbers) rather than trusting extensions, which are commonly
 * spoofed by malware.
 *
 * Key Capabilities:
 * =================
 * 1. MAGIC NUMBER DETECTION
 *    - 500+ file format signatures
 *    - Multi-offset signatures
 *    - Variable-length patterns
 *    - Nested format detection
 *
 * 2. SCRIPT DETECTION
 *    - PowerShell scripts
 *    - VBScript/JScript
 *    - Python/Ruby/Perl
 *    - Shell scripts
 *    - Batch files
 *
 * 3. DOCUMENT ANALYSIS
 *    - Office formats (legacy & OOXML)
 *    - PDF versions
 *    - RTF with embedded objects
 *    - OpenDocument
 *
 * 4. EXECUTABLE DETECTION
 *    - PE (32/64-bit)
 *    - ELF (Linux)
 *    - Mach-O (macOS)
 *    - .NET assemblies
 *    - Java bytecode
 *
 * 5. SPOOFING DETECTION
 *    - Extension mismatch
 *    - Double extension abuse
 *    - RTLO character detection
 *    - Homoglyph detection
 *
 * File Analysis Architecture:
 * ===========================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       FileTypeAnalyzer                              │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ MagicDB      │  │ScriptDetector│  │    ExecutableDetector    │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - 500+ sigs  │  │ - Shebang    │  │ - PE/ELF/MachO           │  │
 *   │  │ - Multi-off  │  │ - BOM        │  │ - .NET CLR               │  │
 *   │  │ - Nested     │  │ - Keywords   │  │ - Java class             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │SpoofDetector │  │ MIMEResolver │  │    ExtensionMapper       │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Mismatch   │  │ - Standard   │  │ - True ext               │  │
 *   │  │ - RTLO       │  │ - Custom     │  │ - Category               │  │
 *   │  │ - Double ext │  │ - Fallback   │  │ - Risk                   │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Magic Number Database:
 * ======================
 * - Primary signatures at offset 0
 * - Secondary signatures at various offsets
 * - Pattern-based detection for complex formats
 * - Extensible signature database
 *
 * Integration Points:
 * ===================
 * - ScanEngine: Determines scan type
 * - ExecutableAnalyzer: PE/ELF deep analysis
 * - DocumentScanner: Document format scanning
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1036.007: Double File Extension
 * - T1036.008: Masquerading (RTLO)
 * - T1204: User Execution
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see ExecutableAnalyzer.hpp for binary analysis
 * @see DocumentScanner.hpp for document scanning
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File reading
#include "../../Utils/StringUtils.hpp"        // Extension handling
#include "../../PatternStore/PatternStore.hpp" // Magic number patterns

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <memory>
#include <functional>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class FileTypeAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileTypeAnalyzerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Analysis constants
    constexpr size_t DEFAULT_HEADER_SIZE = 4096;     // Read first 4KB
    constexpr size_t MIN_HEADER_SIZE = 16;
    constexpr size_t MAX_HEADER_SIZE = 64 * 1024;    // Max 64KB for detection

    // Magic number limits
    constexpr size_t MAX_SIGNATURE_LENGTH = 256;
    constexpr size_t MAX_SIGNATURES = 1000;

}  // namespace FileTypeAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum FileCategory
 * @brief High-level file category.
 */
enum class FileCategory : uint8_t {
    Unknown = 0,
    Executable = 1,                // PE, ELF, Mach-O
    Script = 2,                    // PS1, VBS, JS, PY
    Document = 3,                  // PDF, DOCX, RTF
    Spreadsheet = 4,               // XLSX, CSV
    Presentation = 5,              // PPTX
    Archive = 6,                   // ZIP, RAR, 7Z
    Image = 7,                     // JPG, PNG, BMP
    Audio = 8,                     // MP3, WAV, FLAC
    Video = 9,                     // MP4, AVI, MKV
    Database = 10,                 // SQLite, MDB
    Configuration = 11,            // INI, XML, JSON
    Font = 12,                     // TTF, OTF
    DiskImage = 13,                // ISO, VHD
    Installer = 14,                // MSI, DEB, RPM
    Library = 15,                  // DLL, SO, DYLIB
    Driver = 16,                   // SYS
    Certificate = 17,              // CRT, PEM
    SourceCode = 18,               // C, CPP, H
    Data = 19,                     // Binary data
    Empty = 20,                    // Zero-byte file
    Text = 21                      // Plain text
};

/**
 * @enum FileFormat
 * @brief Specific file format.
 */
enum class FileFormat : uint16_t {
    Unknown = 0,

    // Executables (1-99)
    PE32 = 1,
    PE64 = 2,
    DLL32 = 3,
    DLL64 = 4,
    SYS32 = 5,
    SYS64 = 6,
    ELF32 = 10,
    ELF64 = 11,
    MachO32 = 20,
    MachO64 = 21,
    MachOUniversal = 22,
    JavaClass = 30,
    JavaJAR = 31,
    DotNetAssembly = 40,
    WebAssembly = 50,

    // Scripts (100-199)
    PowerShell = 100,
    Batch = 101,
    VBScript = 102,
    JScript = 103,
    JavaScript = 104,
    Python = 105,
    Ruby = 106,
    Perl = 107,
    ShellScript = 108,
    PHP = 109,
    LUA = 110,
    HTA = 111,

    // Documents (200-299)
    PDF = 200,
    DOC = 201,
    DOCX = 202,
    XLS = 203,
    XLSX = 204,
    PPT = 205,
    PPTX = 206,
    RTF = 207,
    ODT = 210,
    ODS = 211,
    ODP = 212,
    HTML = 220,
    XML = 221,
    MHTML = 222,

    // Archives (300-399)
    ZIP = 300,
    RAR = 301,
    RAR5 = 302,
    SevenZip = 303,
    TAR = 304,
    GZIP = 305,
    BZIP2 = 306,
    XZ = 307,
    CAB = 310,
    MSI = 311,
    ISO = 320,
    VHD = 321,
    VHDX = 322,

    // Images (400-499)
    JPEG = 400,
    PNG = 401,
    GIF = 402,
    BMP = 403,
    TIFF = 404,
    ICO = 405,
    WEBP = 406,
    SVG = 410,
    PSD = 411,

    // Audio (500-549)
    MP3 = 500,
    WAV = 501,
    FLAC = 502,
    OGG = 503,
    WMA = 504,
    AAC = 505,
    M4A = 506,

    // Video (550-599)
    MP4 = 550,
    AVI = 551,
    MKV = 552,
    MOV = 553,
    WMV = 554,
    FLV = 555,
    WEBM = 556,

    // Data (600-699)
    SQLite = 600,
    MDB = 601,
    JSON = 610,
    YAML = 611,
    INI = 612,
    REG = 613,

    // Certificates (700-749)
    DER = 700,
    PEM = 701,
    CRT = 702,
    PFX = 703,

    // Fonts (750-799)
    TTF = 750,
    OTF = 751,
    WOFF = 752,
    WOFF2 = 753,

    // Other (800+)
    LNK = 800,
    URL = 801,
    EVTX = 810,
    PREFETCH = 811,
    Registry = 812
};

/**
 * @enum RiskLevel
 * @brief Risk level of file type.
 */
enum class RiskLevel : uint8_t {
    Safe = 0,                      // Images, audio, video
    Low = 1,                       // Text, config
    Medium = 2,                    // Documents (can have macros)
    High = 3,                      // Archives, scripts
    Critical = 4                   // Executables
};

/**
 * @enum SpoofingType
 * @brief Type of extension spoofing.
 */
enum class SpoofingType : uint8_t {
    None = 0,
    ExtensionMismatch = 1,         // .jpg but PE header
    DoubleExtension = 2,           // file.txt.exe
    RTLOverride = 3,               // RTLO character abuse
    Homoglyph = 4,                 // Look-alike characters
    UnicodeAbuse = 5,              // Other Unicode tricks
    HiddenExtension = 6            // Very long filename
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct MagicSignature
 * @brief Magic number signature definition.
 */
struct alignas(32) MagicSignature {
    uint32_t offset{ 0 };
    std::vector<uint8_t> pattern;
    std::vector<uint8_t> mask;             // For wildcard bytes
    FileFormat format{ FileFormat::Unknown };
    std::string description;
};

/**
 * @struct FileTypeInfo
 * @brief Comprehensive file type information.
 */
struct alignas(128) FileTypeInfo {
    // Detection result
    bool detected{ false };
    double confidence{ 0.0 };              // 0.0 to 1.0

    // Classification
    FileCategory category{ FileCategory::Unknown };
    FileFormat format{ FileFormat::Unknown };
    RiskLevel riskLevel{ RiskLevel::Safe };

    // Type details
    std::string extension;                 // True extension (e.g., ".exe")
    std::string mimeType;                  // MIME type
    std::string description;               // Human-readable description
    std::string formatVersion;             // Version if detectable

    // Spoofing detection
    bool isSpoofed{ false };
    SpoofingType spoofingType{ SpoofingType::None };
    std::wstring diskExtension;            // Extension on disk
    std::wstring suggestedExtension;       // What it should be

    // Additional flags
    bool isExecutable{ false };
    bool isScript{ false };
    bool isArchive{ false };
    bool canContainMacros{ false };
    bool canContainScripts{ false };
    bool isCompound{ false };              // OLE compound file

    // Nested type (for containers)
    bool hasNestedType{ false };
    FileFormat nestedFormat{ FileFormat::Unknown };

    // Magic match info
    uint32_t magicOffset{ 0 };
    std::string matchedSignature;

    // File metadata
    uint64_t fileSize{ 0 };
    std::wstring filePath;
};

/**
 * @struct ScriptIndicators
 * @brief Script detection indicators.
 */
struct alignas(32) ScriptIndicators {
    bool hasShebang{ false };
    bool hasBOM{ false };                  // Byte Order Mark
    bool hasScriptKeywords{ false };

    std::string shebangInterpreter;
    std::string bomType;                   // UTF-8, UTF-16, etc.
    std::vector<std::string> detectedKeywords;
    double textConfidence{ 0.0 };
};

/**
 * @struct ExtensionInfo
 * @brief Extension mapping information.
 */
struct alignas(32) ExtensionInfo {
    std::string extension;
    FileFormat format{ FileFormat::Unknown };
    FileCategory category{ FileCategory::Unknown };
    std::string mimeType;
    RiskLevel riskLevel{ RiskLevel::Safe };
    bool isCommon{ false };
};

/**
 * @struct FileTypeAnalyzerConfig
 * @brief Configuration for file type analyzer.
 */
struct alignas(32) FileTypeAnalyzerConfig {
    // Detection options
    size_t headerSize{ FileTypeAnalyzerConstants::DEFAULT_HEADER_SIZE };
    bool detectScripts{ true };
    bool detectSpoofing{ true };
    bool analyzeNestedTypes{ true };

    // Custom signatures
    std::wstring customSignaturePath;

    // Factory methods
    static FileTypeAnalyzerConfig CreateDefault() noexcept;
    static FileTypeAnalyzerConfig CreateFull() noexcept;
    static FileTypeAnalyzerConfig CreateMinimal() noexcept;
};

/**
 * @struct FileTypeAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) FileTypeAnalyzerStatistics {
    std::atomic<uint64_t> filesAnalyzed{ 0 };
    std::atomic<uint64_t> buffersAnalyzed{ 0 };
    std::atomic<uint64_t> spoofingDetected{ 0 };
    std::atomic<uint64_t> scriptsDetected{ 0 };
    std::atomic<uint64_t> executablesDetected{ 0 };
    std::atomic<uint64_t> unknownTypes{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileTypeAnalyzer
 * @brief Enterprise-grade file type identification.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = FileTypeAnalyzer::Instance();
 * 
 * // Analyze file
 * auto info = analyzer.Analyze(L"C:\\Downloads\\invoice.pdf.exe");
 * 
 * if (info.isSpoofed) {
 *     LOG_ALERT << "Extension spoofing detected!";
 *     LOG_ALERT << "Appears to be: " << info.diskExtension;
 *     LOG_ALERT << "Actually is: " << info.extension;
 * }
 * 
 * if (info.isExecutable && info.category != FileCategory::Executable) {
 *     LOG_WARNING << "Hidden executable detected";
 * }
 * 
 * // Check risk level
 * if (info.riskLevel >= RiskLevel::High) {
 *     // Perform deep scan
 *     scanner.DeepScan(filePath);
 * }
 * @endcode
 */
class FileTypeAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static FileTypeAnalyzer& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the analyzer.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FileTypeAnalyzerConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // FILE ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes file on disk.
     * @param filePath Path to file.
     * @return File type information.
     */
    [[nodiscard]] FileTypeInfo Analyze(const std::wstring& filePath) const;

    /**
     * @brief Analyzes memory buffer.
     * @param buffer File header bytes.
     * @param diskExtension Extension from filename (optional).
     * @return File type information.
     */
    [[nodiscard]] FileTypeInfo AnalyzeBuffer(
        std::span<const uint8_t> buffer,
        std::wstring_view diskExtension = L"") const;

    /**
     * @brief Quick format detection.
     * @param filePath Path to file.
     * @return File format.
     */
    [[nodiscard]] FileFormat DetectFormat(const std::wstring& filePath) const;

    /**
     * @brief Quick format detection from buffer.
     * @param buffer File header bytes.
     * @return File format.
     */
    [[nodiscard]] FileFormat DetectFormat(std::span<const uint8_t> buffer) const;

    /**
     * @brief Gets file category.
     * @param filePath Path to file.
     * @return File category.
     */
    [[nodiscard]] FileCategory GetCategory(const std::wstring& filePath) const;

    /**
     * @brief Gets MIME type.
     * @param filePath Path to file.
     * @return MIME type string.
     */
    [[nodiscard]] std::string GetMimeType(const std::wstring& filePath) const;

    // ========================================================================
    // SPECIFIC CHECKS
    // ========================================================================

    /**
     * @brief Checks if file is executable.
     * @param filePath Path to file.
     * @return True if executable.
     */
    [[nodiscard]] bool IsExecutable(const std::wstring& filePath) const;

    /**
     * @brief Checks if file is executable from buffer.
     * @param buffer File header bytes.
     * @return True if executable.
     */
    [[nodiscard]] bool IsExecutable(std::span<const uint8_t> buffer) const;

    /**
     * @brief Checks if file is a script.
     * @param filePath Path to file.
     * @return True if script.
     */
    [[nodiscard]] bool IsScript(const std::wstring& filePath) const;

    /**
     * @brief Checks if file is an archive.
     * @param filePath Path to file.
     * @return True if archive.
     */
    [[nodiscard]] bool IsArchive(const std::wstring& filePath) const;

    /**
     * @brief Checks if file can contain macros.
     * @param filePath Path to file.
     * @return True if can contain macros.
     */
    [[nodiscard]] bool CanContainMacros(const std::wstring& filePath) const;

    // ========================================================================
    // SPOOFING DETECTION
    // ========================================================================

    /**
     * @brief Checks for extension spoofing.
     * @param filePath Path to file.
     * @return Spoofing type if detected.
     */
    [[nodiscard]] SpoofingType DetectSpoofing(const std::wstring& filePath) const;

    /**
     * @brief Checks filename for RTLO attack.
     * @param filename Filename to check.
     * @return True if RTLO detected.
     */
    [[nodiscard]] bool HasRTLOverride(std::wstring_view filename) const;

    /**
     * @brief Checks for double extension.
     * @param filename Filename to check.
     * @return True if double extension.
     */
    [[nodiscard]] bool HasDoubleExtension(std::wstring_view filename) const;

    // ========================================================================
    // SCRIPT ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes potential script content.
     * @param buffer File content.
     * @return Script indicators.
     */
    [[nodiscard]] ScriptIndicators AnalyzeScript(std::span<const uint8_t> buffer) const;

    /**
     * @brief Detects script type.
     * @param buffer File content.
     * @return File format if script.
     */
    [[nodiscard]] FileFormat DetectScriptType(std::span<const uint8_t> buffer) const;

    // ========================================================================
    // EXTENSION MAPPING
    // ========================================================================

    /**
     * @brief Gets info for extension.
     * @param extension Extension (with or without dot).
     * @return Extension info.
     */
    [[nodiscard]] ExtensionInfo GetExtensionInfo(std::string_view extension) const;

    /**
     * @brief Gets true extension for format.
     * @param format File format.
     * @return Extension string.
     */
    [[nodiscard]] std::string GetExtensionForFormat(FileFormat format) const;

    /**
     * @brief Gets risk level for extension.
     * @param extension Extension to check.
     * @return Risk level.
     */
    [[nodiscard]] RiskLevel GetExtensionRisk(std::string_view extension) const;

    // ========================================================================
    // CUSTOM SIGNATURES
    // ========================================================================

    /**
     * @brief Adds custom signature.
     * @param signature Signature definition.
     * @return True if added.
     */
    bool AddSignature(const MagicSignature& signature);

    /**
     * @brief Loads signatures from file.
     * @param signaturePath Path to signature file.
     * @return Number loaded.
     */
    size_t LoadSignatures(const std::wstring& signaturePath);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileTypeAnalyzerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    FileTypeAnalyzer();
    ~FileTypeAnalyzer();

    FileTypeAnalyzer(const FileTypeAnalyzer&) = delete;
    FileTypeAnalyzer& operator=(const FileTypeAnalyzer&) = delete;

    std::unique_ptr<FileTypeAnalyzerImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
