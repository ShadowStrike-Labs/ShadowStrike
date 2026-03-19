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
 * ShadowStrike NGAV - MACRO DETECTOR MODULE
 * ============================================================================
 *
 * @file MacroDetector.hpp
 * @brief Enterprise-grade Microsoft Office macro (VBA/XLM) analysis engine
 *        for detection of malicious document-based attacks.
 *
 * Provides comprehensive detection of macro-based malware including VBA,
 * Excel 4.0 (XLM) macros, and embedded scripts in Office documents.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. VBA MACRO ANALYSIS
 *    - AutoOpen/AutoExec detection
 *    - Document_Open handlers
 *    - Workbook_Open handlers
 *    - Shell execution calls
 *    - WScript.Shell usage
 *    - PowerShell invocation
 *    - Suspicious API calls (CreateObject, etc.)
 *
 * 2. EXCEL 4.0 (XLM) MACRO DETECTION
 *    - EXEC function detection
 *    - CALL function analysis
 *    - Hidden sheets with macros
 *    - Auto-execution formulas
 *    - External link abuse
 *
 * 3. OBFUSCATION DETECTION
 *    - String encoding/encryption
 *    - Character manipulation
 *    - Array-based storage
 *    - Form control value hiding
 *    - UserForm data storage
 *    - Document property abuse
 *
 * 4. DOCUMENT FORMAT SUPPORT
 *    - OLE Compound Documents (.doc, .xls, .ppt)
 *    - OpenXML (.docx, .xlsx, .pptm)
 *    - RTF with embedded OLE
 *    - OpenDocument Format (.odt, .ods)
 *    - Publisher documents
 *    - Visio documents
 *
 * 5. VBA PROJECT ANALYSIS
 *    - Module enumeration
 *    - Reference inspection
 *    - Project protection bypass
 *    - P-code analysis
 *    - Form extraction
 *
 * 6. MALDOC DETECTION
 *    - Emotet/Trickbot droppers
 *    - Dridex delivery
 *    - QakBot documents
 *    - Hancitor downloaders
 *    - BazarLoader documents
 *    - TA575/TA577 techniques
 *
 * INTEGRATION:
 * ============
 * - PatternStore for macro patterns
 * - SignatureStore for maldoc signatures
 * - ThreatIntel for document IOCs
 *
 * @note Requires OLE/COM for document parsing.
 * @note Supports password-protected document detection.
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
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>

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
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Scripts {
    class MacroDetectorImpl;
}

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MacroConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum document size (100 MB)
    inline constexpr size_t MAX_DOCUMENT_SIZE = 100 * 1024 * 1024;
    
    /// @brief Maximum VBA project size
    inline constexpr size_t MAX_VBA_PROJECT_SIZE = 50 * 1024 * 1024;
    
    /// @brief Maximum modules to analyze
    inline constexpr size_t MAX_VBA_MODULES = 256;
    
    /// @brief Auto-execute function names (VBA)
    inline constexpr const char* VBA_AUTO_EXEC_FUNCTIONS[] = {
        "AutoExec", "AutoOpen", "Auto_Open", "AutoClose", "Auto_Close",
        "AutoNew", "AutoExit", "Document_Open", "Document_Close",
        "Document_New", "Workbook_Open", "Workbook_Activate",
        "Workbook_Close", "Workbook_BeforeClose", "Workbook_BeforeSave",
    };
    
    /// @brief Suspicious VBA API calls
    inline constexpr const char* SUSPICIOUS_VBA_APIS[] = {
        "Shell", "CreateObject", "GetObject", "Environ", "CallByName",
        "MacScript", "ExecuteExcel4Macro", "Run", "WScript.Shell",
        "Scripting.FileSystemObject", "MSXML2.XMLHTTP", "ADODB.Stream",
    };

}  // namespace MacroConstants

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
 * @brief Document/macro type
 */
enum class MacroType : uint8_t {
    Unknown         = 0,
    VBALegacy       = 1,    ///< VBA in OLE (Word 97-2003, etc.)
    VBAModern       = 2,    ///< VBA in OpenXML (Office 2007+)
    Excel4XLM       = 3,    ///< Excel 4.0 XLM macros
    DDE             = 4,    ///< Dynamic Data Exchange
    SLK             = 5,    ///< Symbolic Link (Excel)
    RTF_OLE         = 6,    ///< RTF with embedded OLE
    Publisher       = 7,    ///< Publisher macros
    Visio           = 8,    ///< Visio macros
    OpenDocument    = 9     ///< OpenDocument macros
};

/**
 * @brief Document format
 */
enum class DocumentFormat : uint8_t {
    Unknown         = 0,
    DOC             = 1,    ///< Word 97-2003 (.doc)
    DOCX            = 2,    ///< Word 2007+ (.docx)
    DOCM            = 3,    ///< Word 2007+ macro-enabled (.docm)
    XLS             = 4,    ///< Excel 97-2003 (.xls)
    XLSX            = 5,    ///< Excel 2007+ (.xlsx)
    XLSM            = 6,    ///< Excel 2007+ macro-enabled (.xlsm)
    XLSB            = 7,    ///< Excel binary workbook (.xlsb)
    PPT             = 8,    ///< PowerPoint 97-2003 (.ppt)
    PPTX            = 9,    ///< PowerPoint 2007+ (.pptx)
    PPTM            = 10,   ///< PowerPoint 2007+ macro-enabled (.pptm)
    RTF             = 11,   ///< Rich Text Format (.rtf)
    ODT             = 12,   ///< OpenDocument Text (.odt)
    ODS             = 13,   ///< OpenDocument Spreadsheet (.ods)
    MHT             = 14,   ///< MHTML format
    PUB             = 15,   ///< Publisher (.pub)
    VSD             = 16    ///< Visio (.vsd, .vsdx)
};

/**
 * @brief VBA module type
 */
enum class VBAModuleType : uint8_t {
    Unknown         = 0,
    Standard        = 1,    ///< Standard module (.bas)
    ClassModule     = 2,    ///< Class module (.cls)
    UserForm        = 3,    ///< UserForm (.frm)
    Document        = 4,    ///< Document module (ThisDocument)
    Workbook        = 5     ///< Workbook module (ThisWorkbook)
};

/**
 * @brief Threat category
 */
enum class MacroThreatCategory : uint8_t {
    None            = 0,
    Downloader      = 1,    ///< Downloads payload
    Dropper         = 2,    ///< Drops embedded payload
    Ransomware      = 3,    ///< Ransomware
    BankingTrojan   = 4,    ///< Banking trojan delivery
    RAT             = 5,    ///< Remote access trojan
    InfoStealer     = 6,    ///< Information stealer
    Backdoor        = 7,    ///< Backdoor installation
    Phishing        = 8,    ///< Credential phishing
    Reconnaissance  = 9,    ///< System enumeration
    Persistence     = 10    ///< Persistence mechanism
};

/**
 * @brief Obfuscation technique
 */
enum class MacroObfuscationType : uint8_t {
    None                = 0,
    StringEncryption    = 1,    ///< Encrypted strings
    CharManipulation    = 2,    ///< Chr()/Asc() manipulation
    ArrayStorage        = 3,    ///< Data in arrays
    FormControlStorage  = 4,    ///< Data in form controls
    DocumentProperty    = 5,    ///< Data in document properties
    CommentHiding       = 6,    ///< Code in comments
    VariableNaming      = 7,    ///< Meaningless variable names
    ControlFlow         = 8,    ///< Complex control flow
    StompedPCode        = 9,    ///< P-code stomping
    VBAStomping         = 10    ///< VBA code stomping
};

/**
 * @brief Scan status
 */
enum class MacroScanStatus : uint8_t {
    Clean               = 0,
    Suspicious          = 1,
    Malicious           = 2,
    ErrorFileAccess     = 3,
    ErrorParsing        = 4,
    ErrorPassword       = 5,    ///< Password protected
    ErrorCorrupted      = 6,
    SkippedWhitelisted  = 7,
    SkippedSizeLimit    = 8
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief VBA module information
 */
struct VBAModuleInfo {
    /// @brief Module name
    std::string moduleName;
    
    /// @brief Module type
    VBAModuleType type = VBAModuleType::Unknown;
    
    /// @brief Source code
    std::string sourceCode;
    
    /// @brief Source code size
    size_t sourceSize = 0;
    
    /// @brief Has auto-execute functions
    bool hasAutoExec = false;
    
    /// @brief Auto-execute function names
    std::vector<std::string> autoExecFunctions;
    
    /// @brief Suspicious API calls
    std::vector<std::string> suspiciousAPIs;
    
    /// @brief Line count
    size_t lineCount = 0;
    
    /// @brief Is obfuscated
    bool isObfuscated = false;
    
    /// @brief Obfuscation type
    MacroObfuscationType obfuscationType = MacroObfuscationType::None;
    
    /// @brief Contains shell commands
    bool containsShell = false;
    
    /// @brief Contains network calls
    bool containsNetwork = false;
    
    /// @brief Contains file operations
    bool containsFileOps = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief VBA project information
 */
struct VBAProjectInfo {
    /// @brief Project name
    std::string projectName;
    
    /// @brief Is protected
    bool isProtected = false;
    
    /// @brief Protection type
    std::string protectionType;
    
    /// @brief Modules
    std::vector<VBAModuleInfo> modules;
    
    /// @brief Module count
    size_t moduleCount = 0;
    
    /// @brief Total source size
    size_t totalSourceSize = 0;
    
    /// @brief References
    std::vector<std::string> references;
    
    /// @brief UserForms
    std::vector<std::string> userForms;
    
    /// @brief Has P-code only (VBA stomping indicator)
    bool hasPCodeOnly = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Excel 4.0 XLM macro info
 */
struct XLMMacroInfo {
    /// @brief Sheet name
    std::string sheetName;
    
    /// @brief Is hidden sheet
    bool isHidden = false;
    
    /// @brief Is very hidden
    bool isVeryHidden = false;
    
    /// @brief Has auto_open
    bool hasAutoOpen = false;
    
    /// @brief Macro formulas
    std::vector<std::string> formulas;
    
    /// @brief EXEC calls
    std::vector<std::string> execCalls;
    
    /// @brief CALL function usage
    std::vector<std::string> callFunctions;
    
    /// @brief External links
    std::vector<std::string> externalLinks;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Scan result
 */
struct MacroScanResult {
    /// @brief Scan status
    MacroScanStatus status = MacroScanStatus::Clean;
    
    /// @brief Has macros
    bool hasMacros = false;
    
    /// @brief Is malicious
    bool isMalicious = false;
    
    /// @brief Threat category
    MacroThreatCategory category = MacroThreatCategory::None;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Detected family
    std::string detectedFamily;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Document format
    DocumentFormat format = DocumentFormat::Unknown;
    
    /// @brief Macro types found
    std::vector<MacroType> macroTypes;
    
    /// @brief VBA project info
    std::optional<VBAProjectInfo> vbaProject;
    
    /// @brief XLM macro info (Excel 4.0)
    std::vector<XLMMacroInfo> xlmMacros;
    
    /// @brief Trigger functions (auto-exec)
    std::vector<std::string> triggerFunctions;
    
    /// @brief Suspicious APIs
    std::vector<std::string> suspiciousAPIs;
    
    /// @brief Extracted IOCs
    std::vector<std::string> extractedIOCs;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief File path
    std::filesystem::path filePath;
    
    /// @brief File hash (SHA-256)
    std::string sha256;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Scan time
    SystemTimePoint scanTime;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /**
     * @brief Check if should block
     */
    [[nodiscard]] bool ShouldBlock() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct MacroStatistics {
    std::atomic<uint64_t> totalScans{0};
    std::atomic<uint64_t> documentsWithMacros{0};
    std::atomic<uint64_t> maliciousDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> xlmMacrosDetected{0};
    std::atomic<uint64_t> vbaMacrosDetected{0};
    std::atomic<uint64_t> obfuscatedDetected{0};
    std::atomic<uint64_t> passwordProtected{0};
    std::atomic<uint64_t> parseErrors{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::array<std::atomic<uint64_t>, 16> byFormat{};
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct MacroDetectorConfiguration {
    /// @brief Enable detection
    bool enabled = true;
    
    /// @brief Block documents with macros
    bool blockAllMacros = false;
    
    /// @brief Block documents with auto-execute macros
    bool blockAutoExecMacros = true;
    
    /// @brief Enable XLM macro detection
    bool enableXLMDetection = true;
    
    /// @brief Enable VBA analysis
    bool enableVBAAnalysis = true;
    
    /// @brief Enable deobfuscation
    bool enableDeobfuscation = true;
    
    /// @brief Extract IOCs
    bool extractIOCs = true;
    
    /// @brief Maximum document size
    size_t maxDocumentSize = MacroConstants::MAX_DOCUMENT_SIZE;
    
    /// @brief Scan embedded documents
    bool scanEmbeddedDocuments = true;
    
    /// @brief Trusted signers (code signing)
    std::vector<std::wstring> trustedSigners;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const MacroScanResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// MACRO DETECTOR CLASS
// ============================================================================

/**
 * @class MacroDetector
 * @brief Enterprise-grade Office macro malware detection
 */
class MacroDetector final {
public:
    [[nodiscard]] static MacroDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    MacroDetector(const MacroDetector&) = delete;
    MacroDetector& operator=(const MacroDetector&) = delete;
    MacroDetector(MacroDetector&&) = delete;
    MacroDetector& operator=(MacroDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const MacroDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const MacroDetectorConfiguration& config);
    [[nodiscard]] MacroDetectorConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan document file
    [[nodiscard]] MacroScanResult ScanDocument(const std::filesystem::path& path);
    
    /// @brief Scan document from memory
    [[nodiscard]] MacroScanResult ScanDocument(
        std::span<const uint8_t> content,
        const std::string& fileName = "memory.doc");
    
    /// @brief Quick check if document has macros
    [[nodiscard]] bool HasMacros(const std::filesystem::path& path);
    
    /// @brief Quick check if document has auto-execute macros
    [[nodiscard]] bool HasAutoExecMacros(const std::filesystem::path& path);

    // ========================================================================
    // EXTRACTION
    // ========================================================================
    
    /// @brief Extract VBA source code
    [[nodiscard]] std::string ExtractVBA(const std::filesystem::path& path);
    
    /// @brief Extract VBA project info
    [[nodiscard]] std::optional<VBAProjectInfo> ExtractVBAProject(
        const std::filesystem::path& path);
    
    /// @brief Extract XLM macros
    [[nodiscard]] std::vector<XLMMacroInfo> ExtractXLMMacros(
        const std::filesystem::path& path);
    
    /// @brief Extract all macro content
    [[nodiscard]] std::string ExtractAllMacroContent(const std::filesystem::path& path);

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Detect document format
    [[nodiscard]] DocumentFormat DetectFormat(const std::filesystem::path& path);
    
    /// @brief Detect document format from content
    [[nodiscard]] DocumentFormat DetectFormat(std::span<const uint8_t> content);
    
    /// @brief Analyze VBA for threats
    [[nodiscard]] MacroScanResult AnalyzeVBA(const std::string& vbaCode);
    
    /// @brief Deobfuscate macro code
    [[nodiscard]] std::string Deobfuscate(const std::string& code);
    
    /// @brief Extract IOCs from macro
    [[nodiscard]] std::vector<std::string> ExtractIOCs(const std::string& code);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] MacroStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MacroDetector();
    ~MacroDetector();
    
    std::unique_ptr<MacroDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetMacroTypeName(MacroType type) noexcept;
[[nodiscard]] std::string_view GetDocumentFormatName(DocumentFormat format) noexcept;
[[nodiscard]] std::string_view GetVBAModuleTypeName(VBAModuleType type) noexcept;
[[nodiscard]] std::string_view GetMacroThreatCategoryName(MacroThreatCategory cat) noexcept;
[[nodiscard]] std::string_view GetMacroObfuscationTypeName(MacroObfuscationType type) noexcept;
[[nodiscard]] bool IsAutoExecFunction(std::string_view functionName) noexcept;
[[nodiscard]] bool IsSuspiciousVBAAPI(std::string_view apiName) noexcept;

}  // namespace Scripts
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_MACRO_SCAN(path) \
    ::ShadowStrike::Scripts::MacroDetector::Instance().ScanDocument(path)

#define SS_MACRO_HAS_MACROS(path) \
    ::ShadowStrike::Scripts::MacroDetector::Instance().HasMacros(path)

#define SS_MACRO_EXTRACT_VBA(path) \
    ::ShadowStrike::Scripts::MacroDetector::Instance().ExtractVBA(path)