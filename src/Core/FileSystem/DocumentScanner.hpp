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
 * ShadowStrike Core FileSystem - DOCUMENT SCANNER (The Deep Reader)
 * ============================================================================
 *
 * @file DocumentScanner.hpp
 * @brief Enterprise-grade document threat analysis engine.
 *
 * This module provides comprehensive security analysis of document formats
 * including PDF, Office documents (legacy and OOXML), RTF, and other formats
 * commonly weaponized by malware for initial access.
 *
 * Key Capabilities:
 * =================
 * 1. OFFICE DOCUMENT ANALYSIS
 *    - VBA/VBScript macro detection
 *    - Auto-execution macro identification
 *    - Obfuscated code detection
 *    - DDE/Link exploitation
 *    - Embedded objects (OLE)
 *    - External template injection
 *
 * 2. PDF ANALYSIS
 *    - JavaScript detection
 *    - Action triggers
 *    - Embedded files
 *    - Form XFA analysis
 *    - Launch actions
 *    - OpenAction detection
 *
 * 3. RTF ANALYSIS
 *    - OLE object detection
 *    - Equation Editor exploits
 *    - Embedded executables
 *
 * 4. CVE DETECTION
 *    - Known exploit patterns
 *    - Format-specific vulnerabilities
 *    - Shellcode detection
 *
 * Document Analysis Architecture:
 * ===============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                       DocumentScanner                               │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │OfficeAnalyzer│  │ PDFAnalyzer  │  │    RTFAnalyzer           │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Macros     │  │ - JavaScript │  │ - OLE objects            │  │
 *   │  │ - OLE        │  │ - Actions    │  │ - Exploits               │  │
 *   │  │ - DDE        │  │ - Embedded   │  │ - Shellcode              │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ CVEDetector  │  │CodeDeobfusc  │  │    ThreatScorer          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Patterns   │  │ - VBA        │  │ - Risk assessment        │  │
 *   │  │ - Exploits   │  │ - PowerShell │  │ - Verdict                │  │
 *   │  │ - Shellcode  │  │ - JavaScript │  │ - Recommendations        │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - PatternStore: YARA pattern matching
 * - ThreatIntel: Known malware signatures
 * - ScanEngine: Embedded file scanning
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1566.001: Spearphishing Attachment
 * - T1204.002: Malicious File
 * - T1059.005: Visual Basic
 * - T1059.007: JavaScript
 * - T1221: Template Injection
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see FileTypeAnalyzer.hpp for format detection
 * @see PatternStore.hpp for pattern matching
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // File reading
#include "../../Utils/CompressionUtils.hpp"   // Archive handling
#include "../../Utils/StringUtils.hpp"        // String extraction
#include "../../PatternStore/PatternStore.hpp" // Exploit patterns
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // CVE/exploit database

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
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class DocumentScannerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace DocumentScannerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr size_t MAX_MACRO_SIZE = 10 * 1024 * 1024;   // 10 MB
    constexpr size_t MAX_EMBEDDED_FILES = 1000;
    constexpr size_t MAX_OLE_STREAMS = 500;

    // Thresholds
    constexpr double SUSPICIOUS_ENTROPY_THRESHOLD = 6.5;
    constexpr uint32_t MAX_STRING_LENGTH = 10000;

}  // namespace DocumentScannerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum DocumentType
 * @brief Document format type.
 */
enum class DocumentType : uint8_t {
    Unknown = 0,
    PDF = 1,
    DOC = 2,                       // Legacy binary
    DOCX = 3,                      // OOXML
    DOCM = 4,                      // Macro-enabled
    DOT = 5,                       // Template
    DOTM = 6,                      // Macro template
    XLS = 10,
    XLSX = 11,
    XLSM = 12,
    XLSB = 13,                     // Binary
    XLT = 14,
    PPT = 20,
    PPTX = 21,
    PPTM = 22,
    RTF = 30,
    ODF = 40,                      // OpenDocument
    MSG = 50,                      // Outlook message
    EML = 51,                      // Email
    ONE = 60                       // OneNote
};

/**
 * @enum ThreatType
 * @brief Type of document threat.
 */
enum class ThreatType : uint16_t {
    None = 0,

    // Macro threats
    VBAMacro = 1,
    AutoExecMacro = 2,
    ObfuscatedMacro = 3,
    SuspiciousMacro = 4,
    MacroDownloader = 5,
    MacroPowerShell = 6,
    MacroShellExec = 7,

    // OLE threats
    OLEObject = 10,
    OLEPackage = 11,
    OLEExecutable = 12,
    OLEAutoOpen = 13,

    // DDE/Link threats
    DDELink = 20,
    ExternalLink = 21,
    TemplateInjection = 22,

    // PDF threats
    PDFJavaScript = 30,
    PDFOpenAction = 31,
    PDFLaunchAction = 32,
    PDFSubmitForm = 33,
    PDFEmbeddedFile = 34,
    PDFURIAction = 35,

    // RTF threats
    RTFOLEObject = 40,
    RTFEquationEditor = 41,
    RTFExploit = 42,

    // CVE-specific
    CVEExploit = 50,
    Shellcode = 51,
    HeapSpray = 52,

    // Generic
    SuspiciousString = 60,
    HighEntropy = 61,
    EncodedPayload = 62,
    AntiAnalysis = 63
};

/**
 * @enum ScanVerdict
 * @brief Document scan verdict.
 */
enum class ScanVerdict : uint8_t {
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    HighlyMalicious = 3,
    Error = 4
};

/**
 * @enum MacroRisk
 * @brief Macro risk level.
 */
enum class MacroRisk : uint8_t {
    None = 0,
    Low = 1,                       // Simple, no suspicious calls
    Medium = 2,                    // Some suspicious patterns
    High = 3,                      // Shell execution, downloads
    Critical = 4                   // Confirmed malicious
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct MacroInfo
 * @brief VBA macro information.
 */
struct alignas(128) MacroInfo {
    std::string moduleName;
    std::string moduleType;                // Module, Class, Form
    std::string sourceCode;
    uint32_t lineCount{ 0 };

    // Analysis
    MacroRisk riskLevel{ MacroRisk::None };
    bool isAutoExec{ false };
    bool isObfuscated{ false };
    double entropy{ 0.0 };

    // Suspicious indicators
    bool hasShellExec{ false };
    bool hasPowerShell{ false };
    bool hasDownload{ false };
    bool hasFileWrite{ false };
    bool hasRegistryAccess{ false };
    bool hasWMI{ false };

    // Extracted IOCs
    std::vector<std::string> urls;
    std::vector<std::string> ips;
    std::vector<std::wstring> filePaths;
    std::vector<std::string> commands;

    std::vector<std::string> suspiciousStrings;
    std::vector<std::string> apiCalls;
};

/**
 * @struct OLEObjectInfo
 * @brief Embedded OLE object information.
 */
struct alignas(64) OLEObjectInfo {
    std::string progId;
    std::string clsid;
    std::wstring displayName;

    uint64_t size{ 0 };
    std::vector<uint8_t> data;

    bool isExecutable{ false };
    bool isPackage{ false };
    bool hasAutoStart{ false };

    std::wstring embeddedPath;
    std::string sha256;
};

/**
 * @struct PDFObjectInfo
 * @brief PDF object information.
 */
struct alignas(64) PDFObjectInfo {
    uint32_t objectId{ 0 };
    std::string objectType;

    bool hasJavaScript{ false };
    bool hasAction{ false };
    bool hasEmbeddedFile{ false };

    std::string javaScriptCode;
    std::string actionType;
    std::wstring embeddedFileName;
};

/**
 * @struct DocumentThreat
 * @brief Detected document threat.
 */
struct alignas(128) DocumentThreat {
    uint64_t threatId{ 0 };
    ThreatType type{ ThreatType::None };
    uint8_t severity{ 0 };                 // 0-100

    std::string description;
    std::string location;                  // Where in document
    std::string mitreId;

    // Evidence
    std::string evidence;
    std::vector<std::string> indicators;

    // For CVEs
    std::string cveId;
    std::string cveName;
};

/**
 * @struct DocumentScanResult
 * @brief Complete document scan result.
 */
struct alignas(256) DocumentScanResult {
    // Basic info
    std::wstring filePath;
    DocumentType documentType{ DocumentType::Unknown };
    uint64_t fileSize{ 0 };

    // Verdict
    ScanVerdict verdict{ ScanVerdict::Clean };
    uint8_t riskScore{ 0 };                // 0-100
    std::string verdictReason;

    // Macros
    bool hasMacros{ false };
    uint32_t macroCount{ 0 };
    MacroRisk highestMacroRisk{ MacroRisk::None };
    std::vector<MacroInfo> macros;

    // OLE objects
    bool hasOLEObjects{ false };
    uint32_t oleObjectCount{ 0 };
    std::vector<OLEObjectInfo> oleObjects;

    // Links
    bool hasDDELinks{ false };
    bool hasExternalLinks{ false };
    bool hasTemplateInjection{ false };
    std::vector<std::string> externalUrls;

    // PDF-specific
    bool hasPDFJavaScript{ false };
    bool hasPDFActions{ false };
    std::vector<PDFObjectInfo> pdfObjects;

    // Threats
    std::vector<DocumentThreat> threats;
    uint32_t criticalThreats{ 0 };
    uint32_t highThreats{ 0 };
    uint32_t mediumThreats{ 0 };

    // Extracted IOCs
    std::vector<std::string> urls;
    std::vector<std::string> domains;
    std::vector<std::string> ips;
    std::vector<std::wstring> filePaths;
    std::vector<std::string> emails;

    // Embedded files
    std::vector<std::wstring> embeddedFiles;

    // Metadata
    std::wstring author;
    std::wstring title;
    std::wstring subject;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point modified;

    // Scan metadata
    std::chrono::system_clock::time_point scanTime;
    std::chrono::milliseconds scanDuration{ 0 };
    bool hadErrors{ false };
    std::vector<std::string> errors;
};

/**
 * @struct DocumentScannerConfig
 * @brief Configuration for document scanner.
 */
struct alignas(64) DocumentScannerConfig {
    // Analysis options
    bool analyzeMacros{ true };
    bool analyzeOLEObjects{ true };
    bool analyzePDFJavaScript{ true };
    bool detectCVEs{ true };
    bool extractIOCs{ true };

    // Extraction
    bool extractEmbeddedFiles{ true };
    bool deobfuscateMacros{ true };
    size_t maxMacroSize{ DocumentScannerConstants::MAX_MACRO_SIZE };
    size_t maxEmbeddedFiles{ DocumentScannerConstants::MAX_EMBEDDED_FILES };

    // Scanning
    bool scanEmbeddedFiles{ true };
    bool recursiveScan{ true };
    uint32_t maxRecursionDepth{ 5 };

    // Factory methods
    static DocumentScannerConfig CreateDefault() noexcept;
    static DocumentScannerConfig CreateQuick() noexcept;
    static DocumentScannerConfig CreateDeep() noexcept;
};

/**
 * @struct DocumentScannerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) DocumentScannerStatistics {
    std::atomic<uint64_t> documentsScanned{ 0 };
    std::atomic<uint64_t> macrosDetected{ 0 };
    std::atomic<uint64_t> maliciousMacros{ 0 };
    std::atomic<uint64_t> oleObjectsDetected{ 0 };
    std::atomic<uint64_t> pdfJavaScriptDetected{ 0 };
    std::atomic<uint64_t> cvesDetected{ 0 };
    std::atomic<uint64_t> maliciousDocuments{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for scan progress.
 */
using DocumentProgressCallback = std::function<void(const std::wstring& stage, uint32_t percent)>;

/**
 * @brief Callback for threat detection.
 */
using ThreatCallback = std::function<void(const DocumentThreat& threat)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DocumentScanner
 * @brief Enterprise-grade document security scanner.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& scanner = DocumentScanner::Instance();
 * 
 * // Scan document
 * auto result = scanner.Scan(L"suspicious.docm");
 * 
 * if (result.verdict == ScanVerdict::Malicious) {
 *     LOG_ALERT << "Malicious document: " << result.verdictReason;
 *     
 *     for (const auto& threat : result.threats) {
 *         LOG_ALERT << "Threat: " << threat.description;
 *         LOG_ALERT << "MITRE: " << threat.mitreId;
 *     }
 * }
 * 
 * // Check macros specifically
 * if (result.hasMacros) {
 *     for (const auto& macro : result.macros) {
 *         if (macro.isAutoExec && macro.hasPowerShell) {
 *             LOG_WARNING << "Auto-exec macro with PowerShell!";
 *         }
 *     }
 * }
 * 
 * // Extract IOCs
 * for (const auto& url : result.urls) {
 *     threatIntel.CheckURL(url);
 * }
 * @endcode
 */
class DocumentScanner {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static DocumentScanner& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the scanner.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const DocumentScannerConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    // ========================================================================
    // DOCUMENT SCANNING
    // ========================================================================

    /**
     * @brief Performs full document scan.
     * @param filePath Path to document.
     * @param config Scan configuration.
     * @return Scan result.
     */
    [[nodiscard]] DocumentScanResult Scan(
        const std::wstring& filePath,
        const DocumentScannerConfig& config = DocumentScannerConfig::CreateDefault());

    /**
     * @brief Scans document buffer.
     * @param buffer Document data.
     * @param docType Document type.
     * @return Scan result.
     */
    [[nodiscard]] DocumentScanResult ScanBuffer(
        std::span<const uint8_t> buffer,
        DocumentType docType);

    /**
     * @brief Quick macro check.
     * @param filePath Path to document.
     * @return True if has macros.
     */
    [[nodiscard]] bool HasMacros(const std::wstring& filePath) const;

    /**
     * @brief Quick malicious check.
     * @param filePath Path to document.
     * @return True if likely malicious.
     */
    [[nodiscard]] bool IsMalicious(const std::wstring& filePath) const;

    // ========================================================================
    // MACRO ANALYSIS
    // ========================================================================

    /**
     * @brief Extracts macros from document.
     * @param filePath Path to document.
     * @return Vector of macro info.
     */
    [[nodiscard]] std::vector<MacroInfo> ExtractMacros(const std::wstring& filePath) const;

    /**
     * @brief Analyzes VBA code.
     * @param vbaCode VBA source code.
     * @return Macro analysis result.
     */
    [[nodiscard]] MacroInfo AnalyzeVBACode(const std::string& vbaCode) const;

    /**
     * @brief Deobfuscates macro code.
     * @param obfuscatedCode Obfuscated VBA code.
     * @return Deobfuscated code.
     */
    [[nodiscard]] std::string DeobfuscateMacro(const std::string& obfuscatedCode) const;

    // ========================================================================
    // OLE ANALYSIS
    // ========================================================================

    /**
     * @brief Extracts OLE objects.
     * @param filePath Path to document.
     * @return Vector of OLE objects.
     */
    [[nodiscard]] std::vector<OLEObjectInfo> ExtractOLEObjects(const std::wstring& filePath) const;

    /**
     * @brief Lists OLE streams.
     * @param filePath Path to document.
     * @return Vector of stream names.
     */
    [[nodiscard]] std::vector<std::string> ListOLEStreams(const std::wstring& filePath) const;

    // ========================================================================
    // PDF ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes PDF structure.
     * @param filePath Path to PDF.
     * @return Vector of PDF objects.
     */
    [[nodiscard]] std::vector<PDFObjectInfo> AnalyzePDF(const std::wstring& filePath) const;

    /**
     * @brief Extracts JavaScript from PDF.
     * @param filePath Path to PDF.
     * @return Vector of JavaScript code.
     */
    [[nodiscard]] std::vector<std::string> ExtractPDFJavaScript(const std::wstring& filePath) const;

    // ========================================================================
    // IOC EXTRACTION
    // ========================================================================

    /**
     * @brief Extracts all IOCs from document.
     * @param filePath Path to document.
     * @return Scan result with IOCs.
     */
    [[nodiscard]] DocumentScanResult ExtractIOCs(const std::wstring& filePath) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetProgressCallback(DocumentProgressCallback callback);
    void SetThreatCallback(ThreatCallback callback);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const DocumentScannerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    DocumentScanner();
    ~DocumentScanner();

    DocumentScanner(const DocumentScanner&) = delete;
    DocumentScanner& operator=(const DocumentScanner&) = delete;

    std::unique_ptr<DocumentScannerImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
