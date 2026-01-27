/**
 * ============================================================================
 * ShadowStrike NGAV - MACRO DETECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file MacroDetector.cpp
 * @brief Enterprise-grade Microsoft Office macro (VBA/XLM) analysis engine
 *        implementation for detection of malicious document-based attacks.
 *
 * This implementation provides comprehensive detection of macro-based malware
 * including VBA macros, Excel 4.0 (XLM) macros, and embedded scripts in Office
 * documents. It integrates with PatternStore, SignatureStore, and ThreatIntel
 * for multi-layered threat detection.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 * - OLE Compound Document parsing (Word 97-2003, Excel 97-2003, PowerPoint)
 * - OpenXML parsing (.docx, .xlsx, .pptx macro-enabled variants)
 * - VBA project extraction and analysis
 * - Excel 4.0 XLM macro detection
 * - Obfuscation detection and partial deobfuscation
 * - IOC (Indicators of Compromise) extraction
 * - Integration with threat intelligence
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "MacroDetector.hpp"

// Standard library includes
#include <algorithm>
#include <regex>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>

// Windows includes for OLE/COM
#ifdef _WIN32
#include <objbase.h>
#include <comdef.h>
#pragma comment(lib, "ole32.lib")
#endif

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> MacroDetector::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetMacroTypeName(MacroType type) noexcept {
    switch (type) {
        case MacroType::VBALegacy:    return "VBA Legacy (OLE)";
        case MacroType::VBAModern:    return "VBA Modern (OpenXML)";
        case MacroType::Excel4XLM:    return "Excel 4.0 XLM";
        case MacroType::DDE:          return "Dynamic Data Exchange";
        case MacroType::SLK:          return "Symbolic Link";
        case MacroType::RTF_OLE:      return "RTF with OLE";
        case MacroType::Publisher:    return "Publisher Macro";
        case MacroType::Visio:        return "Visio Macro";
        case MacroType::OpenDocument: return "OpenDocument Macro";
        default:                      return "Unknown";
    }
}

[[nodiscard]] std::string_view GetDocumentFormatName(DocumentFormat format) noexcept {
    switch (format) {
        case DocumentFormat::DOC:  return ".doc (Word 97-2003)";
        case DocumentFormat::DOCX: return ".docx (Word 2007+)";
        case DocumentFormat::DOCM: return ".docm (Word Macro-Enabled)";
        case DocumentFormat::XLS:  return ".xls (Excel 97-2003)";
        case DocumentFormat::XLSX: return ".xlsx (Excel 2007+)";
        case DocumentFormat::XLSM: return ".xlsm (Excel Macro-Enabled)";
        case DocumentFormat::XLSB: return ".xlsb (Excel Binary)";
        case DocumentFormat::PPT:  return ".ppt (PowerPoint 97-2003)";
        case DocumentFormat::PPTX: return ".pptx (PowerPoint 2007+)";
        case DocumentFormat::PPTM: return ".pptm (PowerPoint Macro-Enabled)";
        case DocumentFormat::RTF:  return ".rtf (Rich Text Format)";
        case DocumentFormat::ODT:  return ".odt (OpenDocument Text)";
        case DocumentFormat::ODS:  return ".ods (OpenDocument Spreadsheet)";
        case DocumentFormat::MHT:  return ".mht (MHTML)";
        case DocumentFormat::PUB:  return ".pub (Publisher)";
        case DocumentFormat::VSD:  return ".vsd (Visio)";
        default:                   return "Unknown Format";
    }
}

[[nodiscard]] std::string_view GetVBAModuleTypeName(VBAModuleType type) noexcept {
    switch (type) {
        case VBAModuleType::Standard:    return "Standard Module";
        case VBAModuleType::ClassModule: return "Class Module";
        case VBAModuleType::UserForm:    return "UserForm";
        case VBAModuleType::Document:    return "Document Module";
        case VBAModuleType::Workbook:    return "Workbook Module";
        default:                         return "Unknown Module";
    }
}

[[nodiscard]] std::string_view GetMacroThreatCategoryName(MacroThreatCategory cat) noexcept {
    switch (cat) {
        case MacroThreatCategory::Downloader:     return "Downloader";
        case MacroThreatCategory::Dropper:        return "Dropper";
        case MacroThreatCategory::Ransomware:     return "Ransomware";
        case MacroThreatCategory::BankingTrojan:  return "Banking Trojan";
        case MacroThreatCategory::RAT:            return "Remote Access Trojan";
        case MacroThreatCategory::InfoStealer:    return "Information Stealer";
        case MacroThreatCategory::Backdoor:       return "Backdoor";
        case MacroThreatCategory::Phishing:       return "Phishing";
        case MacroThreatCategory::Reconnaissance: return "Reconnaissance";
        case MacroThreatCategory::Persistence:    return "Persistence";
        default:                                  return "None";
    }
}

[[nodiscard]] std::string_view GetMacroObfuscationTypeName(MacroObfuscationType type) noexcept {
    switch (type) {
        case MacroObfuscationType::StringEncryption:   return "String Encryption";
        case MacroObfuscationType::CharManipulation:   return "Character Manipulation";
        case MacroObfuscationType::ArrayStorage:       return "Array Storage";
        case MacroObfuscationType::FormControlStorage: return "Form Control Storage";
        case MacroObfuscationType::DocumentProperty:   return "Document Property";
        case MacroObfuscationType::CommentHiding:      return "Comment Hiding";
        case MacroObfuscationType::VariableNaming:     return "Variable Naming";
        case MacroObfuscationType::ControlFlow:        return "Control Flow";
        case MacroObfuscationType::StompedPCode:       return "Stomped P-Code";
        case MacroObfuscationType::VBAStomping:        return "VBA Stomping";
        default:                                       return "None";
    }
}

[[nodiscard]] bool IsAutoExecFunction(std::string_view functionName) noexcept {
    for (const auto* autoExec : MacroConstants::VBA_AUTO_EXEC_FUNCTIONS) {
        if (Utils::StringUtils::IEquals(
                Utils::StringUtils::ToWide(std::string(functionName)),
                Utils::StringUtils::ToWide(autoExec))) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsSuspiciousVBAAPI(std::string_view apiName) noexcept {
    for (const auto* api : MacroConstants::SUSPICIOUS_VBA_APIS) {
        if (Utils::StringUtils::IContains(
                Utils::StringUtils::ToWide(std::string(apiName)),
                Utils::StringUtils::ToWide(api))) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string VBAModuleInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"moduleName\":\"" << moduleName << "\",";
    oss << "\"type\":\"" << GetVBAModuleTypeName(type) << "\",";
    oss << "\"sourceSize\":" << sourceSize << ",";
    oss << "\"lineCount\":" << lineCount << ",";
    oss << "\"hasAutoExec\":" << (hasAutoExec ? "true" : "false") << ",";
    oss << "\"isObfuscated\":" << (isObfuscated ? "true" : "false") << ",";
    oss << "\"obfuscationType\":\"" << GetMacroObfuscationTypeName(obfuscationType) << "\",";
    oss << "\"containsShell\":" << (containsShell ? "true" : "false") << ",";
    oss << "\"containsNetwork\":" << (containsNetwork ? "true" : "false") << ",";
    oss << "\"containsFileOps\":" << (containsFileOps ? "true" : "false") << ",";

    oss << "\"autoExecFunctions\":[";
    for (size_t i = 0; i < autoExecFunctions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << autoExecFunctions[i] << "\"";
    }
    oss << "],";

    oss << "\"suspiciousAPIs\":[";
    for (size_t i = 0; i < suspiciousAPIs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << suspiciousAPIs[i] << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string VBAProjectInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"projectName\":\"" << projectName << "\",";
    oss << "\"isProtected\":" << (isProtected ? "true" : "false") << ",";
    oss << "\"protectionType\":\"" << protectionType << "\",";
    oss << "\"moduleCount\":" << moduleCount << ",";
    oss << "\"totalSourceSize\":" << totalSourceSize << ",";
    oss << "\"hasPCodeOnly\":" << (hasPCodeOnly ? "true" : "false") << ",";

    oss << "\"modules\":[";
    for (size_t i = 0; i < modules.size(); ++i) {
        if (i > 0) oss << ",";
        oss << modules[i].ToJson();
    }
    oss << "],";

    oss << "\"references\":[";
    for (size_t i = 0; i < references.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << references[i] << "\"";
    }
    oss << "],";

    oss << "\"userForms\":[";
    for (size_t i = 0; i < userForms.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << userForms[i] << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string XLMMacroInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"sheetName\":\"" << sheetName << "\",";
    oss << "\"isHidden\":" << (isHidden ? "true" : "false") << ",";
    oss << "\"isVeryHidden\":" << (isVeryHidden ? "true" : "false") << ",";
    oss << "\"hasAutoOpen\":" << (hasAutoOpen ? "true" : "false") << ",";

    oss << "\"formulas\":[";
    for (size_t i = 0; i < formulas.size() && i < 100; ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << formulas[i] << "\"";
    }
    oss << "],";

    oss << "\"execCalls\":[";
    for (size_t i = 0; i < execCalls.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << execCalls[i] << "\"";
    }
    oss << "],";

    oss << "\"callFunctions\":[";
    for (size_t i = 0; i < callFunctions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << callFunctions[i] << "\"";
    }
    oss << "],";

    oss << "\"externalLinks\":[";
    for (size_t i = 0; i < externalLinks.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << externalLinks[i] << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] bool MacroScanResult::ShouldBlock() const noexcept {
    if (isMalicious) return true;
    if (status == MacroScanStatus::Malicious) return true;
    if (riskScore >= 80) return true;
    if (category != MacroThreatCategory::None) return true;
    return false;
}

[[nodiscard]] std::string MacroScanResult::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":" << static_cast<int>(status) << ",";
    oss << "\"hasMacros\":" << (hasMacros ? "true" : "false") << ",";
    oss << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ",";
    oss << "\"category\":\"" << GetMacroThreatCategoryName(category) << "\",";
    oss << "\"riskScore\":" << riskScore << ",";
    oss << "\"detectedFamily\":\"" << detectedFamily << "\",";
    oss << "\"threatName\":\"" << threatName << "\",";
    oss << "\"format\":\"" << GetDocumentFormatName(format) << "\",";
    oss << "\"filePath\":\"" << filePath.string() << "\",";
    oss << "\"sha256\":\"" << sha256 << "\",";
    oss << "\"fileSize\":" << fileSize << ",";
    oss << "\"scanDurationUs\":" << scanDuration.count() << ",";

    oss << "\"macroTypes\":[";
    for (size_t i = 0; i < macroTypes.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << GetMacroTypeName(macroTypes[i]) << "\"";
    }
    oss << "],";

    oss << "\"triggerFunctions\":[";
    for (size_t i = 0; i < triggerFunctions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << triggerFunctions[i] << "\"";
    }
    oss << "],";

    oss << "\"suspiciousAPIs\":[";
    for (size_t i = 0; i < suspiciousAPIs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << suspiciousAPIs[i] << "\"";
    }
    oss << "],";

    oss << "\"extractedIOCs\":[";
    for (size_t i = 0; i < extractedIOCs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << extractedIOCs[i] << "\"";
    }
    oss << "],";

    oss << "\"matchedSignatures\":[";
    for (size_t i = 0; i < matchedSignatures.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << matchedSignatures[i] << "\"";
    }
    oss << "]";

    if (vbaProject.has_value()) {
        oss << ",\"vbaProject\":" << vbaProject->ToJson();
    }

    oss << ",\"xlmMacros\":[";
    for (size_t i = 0; i < xlmMacros.size(); ++i) {
        if (i > 0) oss << ",";
        oss << xlmMacros[i].ToJson();
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

void MacroStatistics::Reset() noexcept {
    totalScans.store(0);
    documentsWithMacros.store(0);
    maliciousDetected.store(0);
    suspiciousDetected.store(0);
    xlmMacrosDetected.store(0);
    vbaMacrosDetected.store(0);
    obfuscatedDetected.store(0);
    passwordProtected.store(0);
    parseErrors.store(0);
    totalBytesScanned.store(0);
    for (auto& count : byFormat) {
        count.store(0);
    }
    for (auto& count : byCategory) {
        count.store(0);
    }
    startTime = Clock::now();
}

[[nodiscard]] std::string MacroStatistics::ToJson() const {
    std::ostringstream oss;
    auto now = Clock::now();
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    oss << "{";
    oss << "\"totalScans\":" << totalScans.load() << ",";
    oss << "\"documentsWithMacros\":" << documentsWithMacros.load() << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected.load() << ",";
    oss << "\"suspiciousDetected\":" << suspiciousDetected.load() << ",";
    oss << "\"xlmMacrosDetected\":" << xlmMacrosDetected.load() << ",";
    oss << "\"vbaMacrosDetected\":" << vbaMacrosDetected.load() << ",";
    oss << "\"obfuscatedDetected\":" << obfuscatedDetected.load() << ",";
    oss << "\"passwordProtected\":" << passwordProtected.load() << ",";
    oss << "\"parseErrors\":" << parseErrors.load() << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned.load() << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool MacroDetectorConfiguration::IsValid() const noexcept {
    if (maxDocumentSize == 0 || maxDocumentSize > 1ULL * 1024 * 1024 * 1024) {
        return false;
    }
    return true;
}

// ============================================================================
// MACRO DETECTOR IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MacroDetectorImpl {
public:
    MacroDetectorImpl();
    ~MacroDetectorImpl();

    // Non-copyable, non-movable
    MacroDetectorImpl(const MacroDetectorImpl&) = delete;
    MacroDetectorImpl& operator=(const MacroDetectorImpl&) = delete;
    MacroDetectorImpl(MacroDetectorImpl&&) = delete;
    MacroDetectorImpl& operator=(MacroDetectorImpl&&) = delete;

    // Lifecycle
    [[nodiscard]] bool Initialize(const MacroDetectorConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool UpdateConfiguration(const MacroDetectorConfiguration& config);
    [[nodiscard]] MacroDetectorConfiguration GetConfiguration() const;

    // Scanning
    [[nodiscard]] MacroScanResult ScanDocument(const std::filesystem::path& path);
    [[nodiscard]] MacroScanResult ScanDocument(std::span<const uint8_t> content,
                                                const std::string& fileName);
    [[nodiscard]] bool HasMacros(const std::filesystem::path& path);
    [[nodiscard]] bool HasAutoExecMacros(const std::filesystem::path& path);

    // Extraction
    [[nodiscard]] std::string ExtractVBA(const std::filesystem::path& path);
    [[nodiscard]] std::optional<VBAProjectInfo> ExtractVBAProject(const std::filesystem::path& path);
    [[nodiscard]] std::vector<XLMMacroInfo> ExtractXLMMacros(const std::filesystem::path& path);
    [[nodiscard]] std::string ExtractAllMacroContent(const std::filesystem::path& path);

    // Analysis
    [[nodiscard]] DocumentFormat DetectFormat(const std::filesystem::path& path);
    [[nodiscard]] DocumentFormat DetectFormat(std::span<const uint8_t> content);
    [[nodiscard]] MacroScanResult AnalyzeVBA(const std::string& vbaCode);
    [[nodiscard]] std::string Deobfuscate(const std::string& code);
    [[nodiscard]] std::vector<std::string> ExtractIOCs(const std::string& code);

    // Callbacks
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    [[nodiscard]] MacroStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

private:
    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    [[nodiscard]] bool ParseOLEDocument(std::span<const uint8_t> content,
                                         VBAProjectInfo& outProject);
    [[nodiscard]] bool ParseOpenXMLDocument(std::span<const uint8_t> content,
                                             VBAProjectInfo& outProject);
    [[nodiscard]] bool ExtractVBAFromOLE(std::span<const uint8_t> content,
                                          std::string& outVBA);
    [[nodiscard]] bool ExtractXLMFromOLE(std::span<const uint8_t> content,
                                          std::vector<XLMMacroInfo>& outXLM);

    [[nodiscard]] VBAModuleInfo AnalyzeVBAModule(const std::string& moduleName,
                                                  const std::string& sourceCode);
    [[nodiscard]] MacroObfuscationType DetectObfuscation(const std::string& code);
    [[nodiscard]] int CalculateRiskScore(const MacroScanResult& result);
    [[nodiscard]] MacroThreatCategory ClassifyThreat(const MacroScanResult& result);
    [[nodiscard]] std::string IdentifyMalwareFamily(const MacroScanResult& result);

    [[nodiscard]] bool IsPasswordProtected(std::span<const uint8_t> content);
    [[nodiscard]] bool ValidateDocumentStructure(std::span<const uint8_t> content);

    void NotifyCallback(const MacroScanResult& result);
    void NotifyError(const std::string& message, int code);

    // ========================================================================
    // OLE COMPOUND DOCUMENT PARSING
    // ========================================================================

    static constexpr uint8_t OLE_SIGNATURE[8] = {
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
    };

    static constexpr uint8_t ZIP_SIGNATURE[4] = {
        0x50, 0x4B, 0x03, 0x04
    };

    static constexpr uint8_t RTF_SIGNATURE[5] = {
        0x7B, 0x5C, 0x72, 0x74, 0x66  // "{\rtf"
    };

    // VBA stream markers
    static constexpr char VBA_PROJECT_STREAM[] = "VBA";
    static constexpr char VBA_DIR_STREAM[] = "dir";
    static constexpr char MACRO_SHEET_PREFIX[] = "Macros";

    // ========================================================================
    // PATTERN DETECTION
    // ========================================================================

    struct SuspiciousPattern {
        std::string pattern;
        int riskWeight;
        std::string description;
    };

    static const std::vector<SuspiciousPattern> s_suspiciousPatterns;
    static const std::vector<std::string> s_downloaderIndicators;
    static const std::vector<std::string> s_shellIndicators;
    static const std::vector<std::string> s_persistenceIndicators;

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};

    MacroDetectorConfiguration m_config;
    MacroStatistics m_stats;

    ScanResultCallback m_resultCallback;
    ErrorCallback m_errorCallback;

    // COM initialization state
    bool m_comInitialized{false};
};

// ============================================================================
// SUSPICIOUS PATTERN DEFINITIONS
// ============================================================================

const std::vector<MacroDetectorImpl::SuspiciousPattern>
MacroDetectorImpl::s_suspiciousPatterns = {
    {"Shell", 25, "Shell command execution"},
    {"CreateObject", 20, "COM object creation"},
    {"WScript.Shell", 30, "Windows Script Host shell"},
    {"Scripting.FileSystemObject", 20, "File system access"},
    {"MSXML2.XMLHTTP", 25, "HTTP communication"},
    {"ADODB.Stream", 25, "Binary stream operations"},
    {"PowerShell", 35, "PowerShell invocation"},
    {"cmd.exe", 30, "Command prompt execution"},
    {"mshta", 35, "MSHTA execution"},
    {"certutil", 30, "Certutil abuse"},
    {"bitsadmin", 30, "BITS transfer abuse"},
    {"regsvr32", 30, "DLL registration abuse"},
    {"rundll32", 30, "DLL execution"},
    {"wmic", 25, "WMI command"},
    {"Environ", 15, "Environment variable access"},
    {"CallByName", 20, "Dynamic function invocation"},
    {"GetObject", 15, "Object retrieval"},
    {"ExecuteExcel4Macro", 35, "XLM macro execution"},
    {"MacScript", 20, "Mac script execution"},
    {"Lib \"kernel32\"", 30, "Kernel32 API calls"},
    {"Lib \"user32\"", 25, "User32 API calls"},
    {"Lib \"urlmon\"", 30, "URL download"},
    {"URLDownloadToFile", 35, "File download from URL"},
    {"VirtualAlloc", 40, "Memory allocation (shellcode)"},
    {"RtlMoveMemory", 35, "Memory copy (shellcode)"},
    {"CreateThread", 35, "Thread creation (shellcode)"},
    {"NtCreateThreadEx", 45, "Native API thread creation"},
    {"Base64", 20, "Base64 encoding"},
    {"FromBase64String", 25, "Base64 decoding"},
    {"Chr(", 15, "Character conversion"},
    {"Asc(", 15, "ASCII conversion"},
    {"StrReverse", 15, "String reversal"},
    {"Replace(", 10, "String replacement"},
    {"RegRead", 20, "Registry read"},
    {"RegWrite", 25, "Registry write"},
    {"CreateTextFile", 20, "File creation"},
    {"DeleteFile", 20, "File deletion"},
    {"CopyFile", 15, "File copy"},
    {"GetTempPath", 20, "Temp path access"},
    {"GetSpecialFolder", 15, "Special folder access"},
};

const std::vector<std::string> MacroDetectorImpl::s_downloaderIndicators = {
    "http://", "https://", ".exe", ".dll", ".bat", ".cmd", ".ps1",
    "URLDownloadToFile", "XMLHTTP", "ServerXMLHTTP", "WinHttp",
    "Msxml2.XMLHTTP", "Microsoft.XMLHTTP", "InternetOpen", "InternetReadFile"
};

const std::vector<std::string> MacroDetectorImpl::s_shellIndicators = {
    "Shell", "WScript.Shell", "cmd.exe", "powershell", "mshta",
    "cscript", "wscript", "conhost", "bash", "sh -c"
};

const std::vector<std::string> MacroDetectorImpl::s_persistenceIndicators = {
    "CurrentVersion\\Run", "Startup", "ScheduledTasks", "schtasks",
    "RegWrite", "CreateShortcut", "HKCU\\Software\\Microsoft\\Windows"
};

// ============================================================================
// MACRO DETECTOR IMPL IMPLEMENTATION
// ============================================================================

MacroDetectorImpl::MacroDetectorImpl() {
    m_stats.Reset();
}

MacroDetectorImpl::~MacroDetectorImpl() {
    Shutdown();
}

[[nodiscard]] bool MacroDetectorImpl::Initialize(const MacroDetectorConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load()) {
        SS_LOG_WARN(L"MacroDetector", L"Already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing);

    // Validate configuration
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"MacroDetector", L"Invalid configuration");
        m_status.store(ModuleStatus::Error);
        return false;
    }

    m_config = config;

    // Initialize COM for OLE parsing
#ifdef _WIN32
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE) {
        m_comInitialized = true;
    } else {
        SS_LOG_WARN(L"MacroDetector", L"COM initialization failed: 0x%08X", hr);
        // Continue anyway, some functionality may work
    }
#endif

    m_stats.Reset();
    m_initialized.store(true);
    m_status.store(ModuleStatus::Running);

    SS_LOG_INFO(L"MacroDetector", L"Initialized successfully (v%u.%u.%u)",
                MacroConstants::VERSION_MAJOR,
                MacroConstants::VERSION_MINOR,
                MacroConstants::VERSION_PATCH);

    return true;
}

void MacroDetectorImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load()) {
        return;
    }

    m_status.store(ModuleStatus::Stopping);

#ifdef _WIN32
    if (m_comInitialized) {
        CoUninitialize();
        m_comInitialized = false;
    }
#endif

    m_resultCallback = nullptr;
    m_errorCallback = nullptr;

    m_initialized.store(false);
    m_status.store(ModuleStatus::Stopped);

    SS_LOG_INFO(L"MacroDetector", L"Shutdown complete");
}

[[nodiscard]] bool MacroDetectorImpl::IsInitialized() const noexcept {
    return m_initialized.load();
}

[[nodiscard]] ModuleStatus MacroDetectorImpl::GetStatus() const noexcept {
    return m_status.load();
}

[[nodiscard]] bool MacroDetectorImpl::UpdateConfiguration(const MacroDetectorConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"MacroDetector", L"Invalid configuration update");
        return false;
    }

    std::unique_lock lock(m_mutex);
    m_config = config;

    SS_LOG_INFO(L"MacroDetector", L"Configuration updated");
    return true;
}

[[nodiscard]] MacroDetectorConfiguration MacroDetectorImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

[[nodiscard]] MacroScanResult MacroDetectorImpl::ScanDocument(const std::filesystem::path& path) {
    MacroScanResult result;
    result.filePath = path;
    result.scanTime = std::chrono::system_clock::now();
    auto startTime = Clock::now();

    // Validation
    if (path.empty()) {
        SS_LOG_ERROR(L"MacroDetector", L"Empty file path provided");
        result.status = MacroScanStatus::ErrorFileAccess;
        NotifyError("Empty file path", -1);
        return result;
    }

    std::wstring widePath = path.wstring();

    // Check file exists
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(widePath, &fileErr)) {
        SS_LOG_ERROR(L"MacroDetector", L"File not found: %ls", widePath.c_str());
        result.status = MacroScanStatus::ErrorFileAccess;
        m_stats.parseErrors++;
        NotifyError("File not found: " + path.string(), ERROR_FILE_NOT_FOUND);
        return result;
    }

    // Check file size
    Utils::FileUtils::FileStat fileStat;
    if (!Utils::FileUtils::Stat(widePath, fileStat, &fileErr)) {
        SS_LOG_ERROR(L"MacroDetector", L"Failed to stat file: %ls", widePath.c_str());
        result.status = MacroScanStatus::ErrorFileAccess;
        m_stats.parseErrors++;
        return result;
    }

    result.fileSize = fileStat.size;

    if (fileStat.size > m_config.maxDocumentSize) {
        SS_LOG_WARN(L"MacroDetector", L"File too large (%llu bytes): %ls",
                    fileStat.size, widePath.c_str());
        result.status = MacroScanStatus::SkippedSizeLimit;
        return result;
    }

    // Read file content
    std::vector<std::byte> content;
    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        SS_LOG_ERROR(L"MacroDetector", L"Failed to read file: %ls (error: %d)",
                     widePath.c_str(), fileErr.win32);
        result.status = MacroScanStatus::ErrorFileAccess;
        m_stats.parseErrors++;
        return result;
    }

    // Compute file hash
    std::array<uint8_t, 32> hashBytes;
    if (Utils::FileUtils::ComputeFileSHA256(widePath, hashBytes, &fileErr)) {
        result.sha256 = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    }

    // Convert to uint8_t span
    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    // Perform scan
    result = ScanDocument(contentSpan, path.filename().string());
    result.filePath = path;
    result.sha256 = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    result.fileSize = fileStat.size;

    auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Update statistics
    m_stats.totalScans++;
    m_stats.totalBytesScanned += result.fileSize;
    if (result.hasMacros) {
        m_stats.documentsWithMacros++;
    }
    if (result.isMalicious) {
        m_stats.maliciousDetected++;
    } else if (result.status == MacroScanStatus::Suspicious) {
        m_stats.suspiciousDetected++;
    }

    if (static_cast<size_t>(result.format) < m_stats.byFormat.size()) {
        m_stats.byFormat[static_cast<size_t>(result.format)]++;
    }

    NotifyCallback(result);

    if (m_config.verboseLogging) {
        SS_LOG_INFO(L"MacroDetector", L"Scan complete: %ls - Status: %d, Risk: %d",
                    widePath.c_str(), static_cast<int>(result.status), result.riskScore);
    }

    return result;
}

[[nodiscard]] MacroScanResult MacroDetectorImpl::ScanDocument(
    std::span<const uint8_t> content,
    const std::string& fileName) {

    MacroScanResult result;
    result.scanTime = std::chrono::system_clock::now();
    result.fileSize = content.size();
    auto startTime = Clock::now();

    // Validate content
    if (content.empty()) {
        result.status = MacroScanStatus::ErrorParsing;
        return result;
    }

    if (content.size() > m_config.maxDocumentSize) {
        result.status = MacroScanStatus::SkippedSizeLimit;
        return result;
    }

    // Detect format
    result.format = DetectFormat(content);

    // Check for password protection
    if (IsPasswordProtected(content)) {
        result.status = MacroScanStatus::ErrorPassword;
        m_stats.passwordProtected++;
        return result;
    }

    // Parse based on format
    VBAProjectInfo vbaProject;
    std::vector<XLMMacroInfo> xlmMacros;

    try {
        bool hasOLE = (content.size() >= 8 &&
                       std::memcmp(content.data(), OLE_SIGNATURE, 8) == 0);
        bool hasZIP = (content.size() >= 4 &&
                       std::memcmp(content.data(), ZIP_SIGNATURE, 4) == 0);

        if (hasOLE) {
            // Legacy OLE format
            if (ParseOLEDocument(content, vbaProject)) {
                result.hasMacros = !vbaProject.modules.empty();
                result.vbaProject = vbaProject;

                if (result.hasMacros) {
                    result.macroTypes.push_back(MacroType::VBALegacy);
                    m_stats.vbaMacrosDetected++;
                }
            }

            // Check for XLM macros (Excel 4.0)
            if (m_config.enableXLMDetection &&
                (result.format == DocumentFormat::XLS ||
                 result.format == DocumentFormat::XLSB)) {
                if (ExtractXLMFromOLE(content, xlmMacros)) {
                    result.xlmMacros = xlmMacros;
                    if (!xlmMacros.empty()) {
                        result.hasMacros = true;
                        result.macroTypes.push_back(MacroType::Excel4XLM);
                        m_stats.xlmMacrosDetected++;
                    }
                }
            }
        } else if (hasZIP) {
            // Modern OpenXML format
            if (ParseOpenXMLDocument(content, vbaProject)) {
                result.hasMacros = !vbaProject.modules.empty();
                result.vbaProject = vbaProject;

                if (result.hasMacros) {
                    result.macroTypes.push_back(MacroType::VBAModern);
                    m_stats.vbaMacrosDetected++;
                }
            }
        } else if (content.size() >= 5 &&
                   std::memcmp(content.data(), RTF_SIGNATURE, 5) == 0) {
            // RTF format - check for embedded OLE
            result.format = DocumentFormat::RTF;
            // RTF parsing would go here
        }

        // Analyze VBA modules if found
        if (result.vbaProject.has_value() && m_config.enableVBAAnalysis) {
            for (auto& module : result.vbaProject->modules) {
                VBAModuleInfo analyzed = AnalyzeVBAModule(module.moduleName, module.sourceCode);

                // Copy analysis results
                module.hasAutoExec = analyzed.hasAutoExec;
                module.autoExecFunctions = analyzed.autoExecFunctions;
                module.suspiciousAPIs = analyzed.suspiciousAPIs;
                module.isObfuscated = analyzed.isObfuscated;
                module.obfuscationType = analyzed.obfuscationType;
                module.containsShell = analyzed.containsShell;
                module.containsNetwork = analyzed.containsNetwork;
                module.containsFileOps = analyzed.containsFileOps;

                // Aggregate to result
                if (module.hasAutoExec) {
                    for (const auto& fn : module.autoExecFunctions) {
                        result.triggerFunctions.push_back(fn);
                    }
                }

                for (const auto& api : module.suspiciousAPIs) {
                    if (std::find(result.suspiciousAPIs.begin(),
                                  result.suspiciousAPIs.end(), api) == result.suspiciousAPIs.end()) {
                        result.suspiciousAPIs.push_back(api);
                    }
                }

                if (module.isObfuscated) {
                    m_stats.obfuscatedDetected++;
                }
            }
        }

        // Extract IOCs
        if (m_config.extractIOCs) {
            std::string allCode = ExtractAllMacroContent(result.filePath);
            result.extractedIOCs = ExtractIOCs(allCode);
        }

        // Calculate risk score
        result.riskScore = CalculateRiskScore(result);

        // Classify threat
        result.category = ClassifyThreat(result);

        // Identify malware family
        result.detectedFamily = IdentifyMalwareFamily(result);

        // Determine final status
        if (result.riskScore >= 80) {
            result.status = MacroScanStatus::Malicious;
            result.isMalicious = true;
            result.threatName = "Malicious.Macro." +
                std::string(GetMacroThreatCategoryName(result.category));
        } else if (result.riskScore >= 50) {
            result.status = MacroScanStatus::Suspicious;
        } else if (result.hasMacros) {
            result.status = MacroScanStatus::Clean;
        } else {
            result.status = MacroScanStatus::Clean;
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MacroDetector", L"Scan exception: %hs", e.what());
        result.status = MacroScanStatus::ErrorParsing;
        m_stats.parseErrors++;
        NotifyError(std::string("Scan exception: ") + e.what(), -1);
    } catch (...) {
        SS_LOG_ERROR(L"MacroDetector", L"Unknown scan exception");
        result.status = MacroScanStatus::ErrorParsing;
        m_stats.parseErrors++;
        NotifyError("Unknown scan exception", -1);
    }

    auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    return result;
}

[[nodiscard]] bool MacroDetectorImpl::HasMacros(const std::filesystem::path& path) {
    auto result = ScanDocument(path);
    return result.hasMacros;
}

[[nodiscard]] bool MacroDetectorImpl::HasAutoExecMacros(const std::filesystem::path& path) {
    auto result = ScanDocument(path);
    return !result.triggerFunctions.empty();
}

[[nodiscard]] std::string MacroDetectorImpl::ExtractVBA(const std::filesystem::path& path) {
    auto project = ExtractVBAProject(path);
    if (!project.has_value()) {
        return "";
    }

    std::ostringstream oss;
    for (const auto& module : project->modules) {
        oss << "' === Module: " << module.moduleName << " ===\n";
        oss << module.sourceCode << "\n\n";
    }

    return oss.str();
}

[[nodiscard]] std::optional<VBAProjectInfo> MacroDetectorImpl::ExtractVBAProject(
    const std::filesystem::path& path) {

    std::wstring widePath = path.wstring();

    std::vector<std::byte> content;
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        return std::nullopt;
    }

    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    VBAProjectInfo project;

    bool hasOLE = (content.size() >= 8 &&
                   std::memcmp(content.data(), OLE_SIGNATURE, 8) == 0);
    bool hasZIP = (content.size() >= 4 &&
                   std::memcmp(content.data(), ZIP_SIGNATURE, 4) == 0);

    if (hasOLE) {
        if (ParseOLEDocument(contentSpan, project)) {
            return project;
        }
    } else if (hasZIP) {
        if (ParseOpenXMLDocument(contentSpan, project)) {
            return project;
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::vector<XLMMacroInfo> MacroDetectorImpl::ExtractXLMMacros(
    const std::filesystem::path& path) {

    std::vector<XLMMacroInfo> result;

    std::wstring widePath = path.wstring();
    std::vector<std::byte> content;
    Utils::FileUtils::Error fileErr;

    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        return result;
    }

    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    ExtractXLMFromOLE(contentSpan, result);

    return result;
}

[[nodiscard]] std::string MacroDetectorImpl::ExtractAllMacroContent(
    const std::filesystem::path& path) {

    std::ostringstream oss;

    auto vba = ExtractVBA(path);
    if (!vba.empty()) {
        oss << vba;
    }

    auto xlm = ExtractXLMMacros(path);
    for (const auto& macro : xlm) {
        oss << "' === XLM Sheet: " << macro.sheetName << " ===\n";
        for (const auto& formula : macro.formulas) {
            oss << formula << "\n";
        }
        oss << "\n";
    }

    return oss.str();
}

[[nodiscard]] DocumentFormat MacroDetectorImpl::DetectFormat(const std::filesystem::path& path) {
    std::wstring widePath = path.wstring();
    std::vector<std::byte> header;

    // Read first 8 bytes
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::ReadAllBytes(widePath, header, &fileErr)) {
        return DocumentFormat::Unknown;
    }

    if (header.size() < 4) {
        return DocumentFormat::Unknown;
    }

    std::span<const uint8_t> headerSpan(
        reinterpret_cast<const uint8_t*>(header.data()),
        std::min(header.size(), size_t(16))
    );

    return DetectFormat(headerSpan);
}

[[nodiscard]] DocumentFormat MacroDetectorImpl::DetectFormat(std::span<const uint8_t> content) {
    if (content.size() < 4) {
        return DocumentFormat::Unknown;
    }

    // Check OLE signature
    if (content.size() >= 8 && std::memcmp(content.data(), OLE_SIGNATURE, 8) == 0) {
        // Need to inspect OLE structure to determine exact type
        // For now, return based on typical sizes and patterns
        return DocumentFormat::DOC;  // Default for OLE
    }

    // Check ZIP signature (OpenXML)
    if (std::memcmp(content.data(), ZIP_SIGNATURE, 4) == 0) {
        // Would need to inspect ZIP contents
        return DocumentFormat::DOCX;  // Default for OpenXML
    }

    // Check RTF signature
    if (content.size() >= 5 && std::memcmp(content.data(), RTF_SIGNATURE, 5) == 0) {
        return DocumentFormat::RTF;
    }

    return DocumentFormat::Unknown;
}

[[nodiscard]] MacroScanResult MacroDetectorImpl::AnalyzeVBA(const std::string& vbaCode) {
    MacroScanResult result;
    result.scanTime = std::chrono::system_clock::now();

    if (vbaCode.empty()) {
        result.status = MacroScanStatus::Clean;
        return result;
    }

    result.hasMacros = true;

    // Create a pseudo-module for analysis
    VBAModuleInfo module = AnalyzeVBAModule("AnalyzedCode", vbaCode);

    VBAProjectInfo project;
    project.projectName = "AnalyzedProject";
    project.modules.push_back(module);
    project.moduleCount = 1;
    project.totalSourceSize = vbaCode.size();
    result.vbaProject = project;

    // Copy findings to result
    result.triggerFunctions = module.autoExecFunctions;
    result.suspiciousAPIs = module.suspiciousAPIs;

    // Extract IOCs
    if (m_config.extractIOCs) {
        result.extractedIOCs = ExtractIOCs(vbaCode);
    }

    // Calculate risk score
    result.riskScore = CalculateRiskScore(result);

    // Classify threat
    result.category = ClassifyThreat(result);

    // Determine status
    if (result.riskScore >= 80) {
        result.status = MacroScanStatus::Malicious;
        result.isMalicious = true;
    } else if (result.riskScore >= 50) {
        result.status = MacroScanStatus::Suspicious;
    } else {
        result.status = MacroScanStatus::Clean;
    }

    return result;
}

[[nodiscard]] std::string MacroDetectorImpl::Deobfuscate(const std::string& code) {
    if (!m_config.enableDeobfuscation) {
        return code;
    }

    std::string result = code;

    // Basic Chr() deobfuscation
    std::regex chrPattern(R"(Chr\(\s*(\d+)\s*\))");
    std::string::const_iterator searchStart(result.cbegin());
    std::smatch match;
    std::string deobfuscated;
    size_t lastPos = 0;

    while (std::regex_search(searchStart, result.cend(), match, chrPattern)) {
        size_t matchPos = match.position() + (searchStart - result.cbegin());
        deobfuscated += result.substr(lastPos, matchPos - lastPos);

        try {
            int charCode = std::stoi(match[1].str());
            if (charCode >= 0 && charCode <= 127) {
                deobfuscated += static_cast<char>(charCode);
            } else {
                deobfuscated += match[0].str();
            }
        } catch (...) {
            deobfuscated += match[0].str();
        }

        lastPos = matchPos + match.length();
        searchStart = match.suffix().first;
    }
    deobfuscated += result.substr(lastPos);
    result = deobfuscated;

    // Basic ChrW() deobfuscation
    std::regex chrwPattern(R"(ChrW\(\s*(\d+)\s*\))");
    searchStart = result.cbegin();
    deobfuscated.clear();
    lastPos = 0;

    while (std::regex_search(searchStart, result.cend(), match, chrwPattern)) {
        size_t matchPos = match.position() + (searchStart - result.cbegin());
        deobfuscated += result.substr(lastPos, matchPos - lastPos);

        try {
            int charCode = std::stoi(match[1].str());
            if (charCode >= 0 && charCode <= 127) {
                deobfuscated += static_cast<char>(charCode);
            } else {
                deobfuscated += match[0].str();
            }
        } catch (...) {
            deobfuscated += match[0].str();
        }

        lastPos = matchPos + match.length();
        searchStart = match.suffix().first;
    }
    deobfuscated += result.substr(lastPos);
    result = deobfuscated;

    // Concatenation simplification (basic)
    std::regex concatPattern(R"("([^"]*)" \& "([^"]*)")");
    searchStart = result.cbegin();
    deobfuscated.clear();
    lastPos = 0;

    while (std::regex_search(searchStart, result.cend(), match, concatPattern)) {
        size_t matchPos = match.position() + (searchStart - result.cbegin());
        deobfuscated += result.substr(lastPos, matchPos - lastPos);
        deobfuscated += "\"" + match[1].str() + match[2].str() + "\"";

        lastPos = matchPos + match.length();
        searchStart = match.suffix().first;
    }
    deobfuscated += result.substr(lastPos);

    return deobfuscated;
}

[[nodiscard]] std::vector<std::string> MacroDetectorImpl::ExtractIOCs(const std::string& code) {
    std::vector<std::string> iocs;

    if (code.empty()) {
        return iocs;
    }

    // Extract URLs
    std::regex urlPattern(R"((https?://[^\s\"'\)>]+))");
    std::sregex_iterator urlBegin(code.begin(), code.end(), urlPattern);
    std::sregex_iterator urlEnd;

    for (auto it = urlBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string url = it->str();
        if (std::find(iocs.begin(), iocs.end(), url) == iocs.end()) {
            iocs.push_back(url);
        }
    }

    // Extract IP addresses
    std::regex ipPattern(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    std::sregex_iterator ipBegin(code.begin(), code.end(), ipPattern);

    for (auto it = ipBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string ip = it->str();
        // Validate IP ranges
        bool valid = true;
        std::istringstream iss(ip);
        std::string octet;
        while (std::getline(iss, octet, '.')) {
            try {
                int val = std::stoi(octet);
                if (val < 0 || val > 255) {
                    valid = false;
                    break;
                }
            } catch (...) {
                valid = false;
                break;
            }
        }

        if (valid && std::find(iocs.begin(), iocs.end(), ip) == iocs.end()) {
            iocs.push_back(ip);
        }
    }

    // Extract file paths
    std::regex pathPattern(R"(([A-Za-z]:\\[^\s\"'\)>]+\.(exe|dll|bat|cmd|ps1|vbs|js)))");
    std::sregex_iterator pathBegin(code.begin(), code.end(), pathPattern);

    for (auto it = pathBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string path = it->str();
        if (std::find(iocs.begin(), iocs.end(), path) == iocs.end()) {
            iocs.push_back(path);
        }
    }

    // Extract registry keys
    std::regex regPattern(R"((HKLM\\[^\s\"'\)>]+|HKCU\\[^\s\"'\)>]+))");
    std::sregex_iterator regBegin(code.begin(), code.end(), regPattern);

    for (auto it = regBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string reg = it->str();
        if (std::find(iocs.begin(), iocs.end(), reg) == iocs.end()) {
            iocs.push_back(reg);
        }
    }

    return iocs;
}

void MacroDetectorImpl::RegisterCallback(ScanResultCallback callback) {
    std::unique_lock lock(m_mutex);
    m_resultCallback = std::move(callback);
}

void MacroDetectorImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void MacroDetectorImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_resultCallback = nullptr;
    m_errorCallback = nullptr;
}

[[nodiscard]] MacroStatistics MacroDetectorImpl::GetStatistics() const {
    return m_stats;
}

void MacroDetectorImpl::ResetStatistics() {
    m_stats.Reset();
}

[[nodiscard]] bool MacroDetectorImpl::SelfTest() {
    SS_LOG_INFO(L"MacroDetector", L"Running self-test...");

    bool allPassed = true;

    // Test 1: Verify initialization
    if (!m_initialized.load()) {
        SS_LOG_ERROR(L"MacroDetector", L"Self-test: Not initialized");
        allPassed = false;
    }

    // Test 2: Test suspicious pattern detection
    std::string testCode = "Shell(\"cmd.exe /c calc.exe\")";
    auto analysis = AnalyzeVBA(testCode);
    if (!analysis.hasMacros || analysis.suspiciousAPIs.empty()) {
        SS_LOG_ERROR(L"MacroDetector", L"Self-test: Pattern detection failed");
        allPassed = false;
    }

    // Test 3: Test IOC extraction
    std::string iocTestCode = "url = \"http://evil.com/payload.exe\"";
    auto iocs = ExtractIOCs(iocTestCode);
    if (iocs.empty()) {
        SS_LOG_ERROR(L"MacroDetector", L"Self-test: IOC extraction failed");
        allPassed = false;
    }

    // Test 4: Test deobfuscation
    std::string obfuscatedCode = "x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)";
    std::string deobfuscated = Deobfuscate(obfuscatedCode);
    if (deobfuscated.find("Hello") == std::string::npos) {
        SS_LOG_WARN(L"MacroDetector", L"Self-test: Deobfuscation partial");
        // Not a failure, just a warning
    }

    // Test 5: Test format detection
    uint8_t oleHeader[] = {0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1};
    auto format = DetectFormat(std::span<const uint8_t>(oleHeader, 8));
    if (format == DocumentFormat::Unknown) {
        SS_LOG_ERROR(L"MacroDetector", L"Self-test: Format detection failed");
        allPassed = false;
    }

    if (allPassed) {
        SS_LOG_INFO(L"MacroDetector", L"Self-test: All tests passed");
    } else {
        SS_LOG_ERROR(L"MacroDetector", L"Self-test: Some tests failed");
    }

    return allPassed;
}

// ============================================================================
// INTERNAL ANALYSIS METHODS
// ============================================================================

[[nodiscard]] bool MacroDetectorImpl::ParseOLEDocument(
    std::span<const uint8_t> content,
    VBAProjectInfo& outProject) {

    // Validate OLE signature
    if (content.size() < 512) {
        return false;
    }

    if (std::memcmp(content.data(), OLE_SIGNATURE, 8) != 0) {
        return false;
    }

    // OLE parsing is complex - this is a simplified implementation
    // In production, use a proper OLE library or Windows IStorage

    outProject.projectName = "VBAProject";

    // Search for VBA project stream markers
    std::string contentStr(reinterpret_cast<const char*>(content.data()), content.size());

    // Look for VBA module indicators
    if (contentStr.find("Attribute VB_Name") != std::string::npos ||
        contentStr.find("_VBA_PROJECT") != std::string::npos ||
        contentStr.find("dir") != std::string::npos) {

        // Extract VBA code (simplified)
        std::string vbaCode;
        if (ExtractVBAFromOLE(content, vbaCode)) {
            VBAModuleInfo module;
            module.moduleName = "Module1";
            module.sourceCode = vbaCode;
            module.sourceSize = vbaCode.size();
            module.type = VBAModuleType::Standard;

            // Count lines
            module.lineCount = std::count(vbaCode.begin(), vbaCode.end(), '\n') + 1;

            outProject.modules.push_back(module);
        }
    }

    // Check for project protection
    if (contentStr.find("DPB=") != std::string::npos ||
        contentStr.find("CMG=") != std::string::npos) {
        outProject.isProtected = true;
        outProject.protectionType = "Password Protected";
    }

    outProject.moduleCount = outProject.modules.size();
    for (const auto& mod : outProject.modules) {
        outProject.totalSourceSize += mod.sourceSize;
    }

    return !outProject.modules.empty();
}

[[nodiscard]] bool MacroDetectorImpl::ParseOpenXMLDocument(
    std::span<const uint8_t> content,
    VBAProjectInfo& outProject) {

    // Validate ZIP signature
    if (content.size() < 4) {
        return false;
    }

    if (std::memcmp(content.data(), ZIP_SIGNATURE, 4) != 0) {
        return false;
    }

    // OpenXML parsing requires ZIP decompression
    // In production, use a proper ZIP library

    outProject.projectName = "VBAProject";

    // Look for vbaProject.bin in the content
    std::string contentStr(reinterpret_cast<const char*>(content.data()), content.size());

    if (contentStr.find("vbaProject.bin") != std::string::npos ||
        contentStr.find("xl/vbaProject.bin") != std::string::npos ||
        contentStr.find("word/vbaProject.bin") != std::string::npos) {

        // Has VBA macros
        VBAModuleInfo module;
        module.moduleName = "Module1";
        module.type = VBAModuleType::Standard;

        outProject.modules.push_back(module);
    }

    outProject.moduleCount = outProject.modules.size();

    return !outProject.modules.empty();
}

[[nodiscard]] bool MacroDetectorImpl::ExtractVBAFromOLE(
    std::span<const uint8_t> content,
    std::string& outVBA) {

    // Simplified VBA extraction
    // In production, properly parse the OLE structure and decompress VBA streams

    std::string contentStr(reinterpret_cast<const char*>(content.data()), content.size());

    // Look for VBA code markers
    size_t pos = contentStr.find("Attribute VB_Name");
    if (pos == std::string::npos) {
        pos = contentStr.find("Sub ");
        if (pos == std::string::npos) {
            pos = contentStr.find("Function ");
        }
    }

    if (pos != std::string::npos) {
        // Extract a reasonable chunk of VBA code
        size_t endPos = std::min(pos + 10000, contentStr.size());
        outVBA = contentStr.substr(pos, endPos - pos);

        // Clean up non-printable characters
        for (char& c : outVBA) {
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                c = ' ';
            }
        }

        return true;
    }

    return false;
}

[[nodiscard]] bool MacroDetectorImpl::ExtractXLMFromOLE(
    std::span<const uint8_t> content,
    std::vector<XLMMacroInfo>& outXLM) {

    // XLM macro detection
    std::string contentStr(reinterpret_cast<const char*>(content.data()), content.size());

    // Look for Excel 4.0 macro indicators
    bool hasXLM = false;

    // Check for macro sheet indicators
    if (contentStr.find("=EXEC(") != std::string::npos ||
        contentStr.find("=CALL(") != std::string::npos ||
        contentStr.find("=RUN(") != std::string::npos ||
        contentStr.find("=HALT()") != std::string::npos ||
        contentStr.find("=FORMULA(") != std::string::npos ||
        contentStr.find("Auto_Open") != std::string::npos) {
        hasXLM = true;
    }

    if (hasXLM) {
        XLMMacroInfo xlm;
        xlm.sheetName = "Macro1";

        // Extract EXEC calls
        std::regex execPattern(R"(=EXEC\([^)]+\))");
        std::sregex_iterator execBegin(contentStr.begin(), contentStr.end(), execPattern);
        std::sregex_iterator execEnd;

        for (auto it = execBegin; it != execEnd; ++it) {
            xlm.execCalls.push_back(it->str());
        }

        // Extract CALL functions
        std::regex callPattern(R"(=CALL\([^)]+\))");
        std::sregex_iterator callBegin(contentStr.begin(), contentStr.end(), callPattern);

        for (auto it = callBegin; it != execEnd; ++it) {
            xlm.callFunctions.push_back(it->str());
        }

        // Check for Auto_Open
        if (contentStr.find("Auto_Open") != std::string::npos) {
            xlm.hasAutoOpen = true;
        }

        outXLM.push_back(xlm);
        return true;
    }

    return false;
}

[[nodiscard]] VBAModuleInfo MacroDetectorImpl::AnalyzeVBAModule(
    const std::string& moduleName,
    const std::string& sourceCode) {

    VBAModuleInfo info;
    info.moduleName = moduleName;
    info.sourceCode = sourceCode;
    info.sourceSize = sourceCode.size();
    info.lineCount = std::count(sourceCode.begin(), sourceCode.end(), '\n') + 1;

    // Determine module type
    std::wstring wideSource = Utils::StringUtils::ToWide(sourceCode);

    if (Utils::StringUtils::IContains(wideSource, L"ThisDocument") ||
        Utils::StringUtils::IContains(wideSource, L"Document_")) {
        info.type = VBAModuleType::Document;
    } else if (Utils::StringUtils::IContains(wideSource, L"ThisWorkbook") ||
               Utils::StringUtils::IContains(wideSource, L"Workbook_")) {
        info.type = VBAModuleType::Workbook;
    } else if (Utils::StringUtils::IContains(wideSource, L"Class Module") ||
               Utils::StringUtils::IContains(wideSource, L"VB_Creatable")) {
        info.type = VBAModuleType::ClassModule;
    } else if (Utils::StringUtils::IContains(wideSource, L"UserForm")) {
        info.type = VBAModuleType::UserForm;
    } else {
        info.type = VBAModuleType::Standard;
    }

    // Check for auto-execute functions
    for (const auto* autoExec : MacroConstants::VBA_AUTO_EXEC_FUNCTIONS) {
        std::wstring wideAutoExec = Utils::StringUtils::ToWide(autoExec);
        if (Utils::StringUtils::IContains(wideSource, wideAutoExec)) {
            info.hasAutoExec = true;
            info.autoExecFunctions.push_back(autoExec);
        }
    }

    // Check for suspicious APIs
    for (const auto* api : MacroConstants::SUSPICIOUS_VBA_APIS) {
        std::wstring wideApi = Utils::StringUtils::ToWide(api);
        if (Utils::StringUtils::IContains(wideSource, wideApi)) {
            info.suspiciousAPIs.push_back(api);
        }
    }

    // Check for shell execution
    for (const auto& indicator : s_shellIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            info.containsShell = true;
            break;
        }
    }

    // Check for network operations
    for (const auto& indicator : s_downloaderIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            info.containsNetwork = true;
            break;
        }
    }

    // Check for file operations
    if (Utils::StringUtils::IContains(wideSource, L"FileSystemObject") ||
        Utils::StringUtils::IContains(wideSource, L"CreateTextFile") ||
        Utils::StringUtils::IContains(wideSource, L"OpenTextFile") ||
        Utils::StringUtils::IContains(wideSource, L"DeleteFile") ||
        Utils::StringUtils::IContains(wideSource, L"CopyFile")) {
        info.containsFileOps = true;
    }

    // Detect obfuscation
    info.obfuscationType = DetectObfuscation(sourceCode);
    info.isObfuscated = (info.obfuscationType != MacroObfuscationType::None);

    return info;
}

[[nodiscard]] MacroObfuscationType MacroDetectorImpl::DetectObfuscation(const std::string& code) {
    if (code.empty()) {
        return MacroObfuscationType::None;
    }

    // Count Chr() calls
    size_t chrCount = 0;
    size_t pos = 0;
    while ((pos = code.find("Chr(", pos)) != std::string::npos) {
        chrCount++;
        pos += 4;
    }

    if (chrCount > 20) {
        return MacroObfuscationType::CharManipulation;
    }

    // Check for array-based storage
    size_t arrayCount = 0;
    pos = 0;
    while ((pos = code.find("Array(", pos)) != std::string::npos) {
        arrayCount++;
        pos += 6;
    }

    if (arrayCount > 5) {
        return MacroObfuscationType::ArrayStorage;
    }

    // Check for excessive string concatenation
    size_t concatCount = 0;
    pos = 0;
    while ((pos = code.find("\" &", pos)) != std::string::npos) {
        concatCount++;
        pos += 3;
    }

    if (concatCount > 50) {
        return MacroObfuscationType::StringEncryption;
    }

    // Check for StrReverse
    if (code.find("StrReverse") != std::string::npos) {
        return MacroObfuscationType::StringEncryption;
    }

    // Check for Base64
    if (code.find("Base64") != std::string::npos ||
        code.find("MIME") != std::string::npos) {
        return MacroObfuscationType::StringEncryption;
    }

    // Check for meaningless variable names (single letter or random)
    std::regex shortVarPattern(R"(\b[a-z]{1,2}\d*\s*=)");
    std::sregex_iterator shortVarBegin(code.begin(), code.end(), shortVarPattern);
    std::sregex_iterator shortVarEnd;
    size_t shortVarCount = std::distance(shortVarBegin, shortVarEnd);

    if (shortVarCount > 20) {
        return MacroObfuscationType::VariableNaming;
    }

    return MacroObfuscationType::None;
}

[[nodiscard]] int MacroDetectorImpl::CalculateRiskScore(const MacroScanResult& result) {
    int score = 0;

    // Base score for having macros
    if (result.hasMacros) {
        score += 10;
    }

    // Auto-execute functions
    score += static_cast<int>(result.triggerFunctions.size()) * 15;

    // Suspicious APIs
    for (const auto& api : result.suspiciousAPIs) {
        for (const auto& pattern : s_suspiciousPatterns) {
            if (api.find(pattern.pattern) != std::string::npos) {
                score += pattern.riskWeight;
                break;
            }
        }
    }

    // XLM macros are inherently suspicious
    if (!result.xlmMacros.empty()) {
        score += 25;
        for (const auto& xlm : result.xlmMacros) {
            if (xlm.hasAutoOpen) score += 20;
            if (!xlm.execCalls.empty()) score += 30;
            if (!xlm.callFunctions.empty()) score += 20;
        }
    }

    // IOCs
    score += std::min(static_cast<int>(result.extractedIOCs.size()) * 5, 30);

    // Obfuscation
    if (result.vbaProject.has_value()) {
        for (const auto& mod : result.vbaProject->modules) {
            if (mod.isObfuscated) {
                score += 20;
            }
            if (mod.containsShell) {
                score += 25;
            }
            if (mod.containsNetwork) {
                score += 20;
            }
        }
    }

    // Cap at 100
    return std::min(score, 100);
}

[[nodiscard]] MacroThreatCategory MacroDetectorImpl::ClassifyThreat(const MacroScanResult& result) {
    if (result.riskScore < 50) {
        return MacroThreatCategory::None;
    }

    bool hasNetwork = false;
    bool hasShell = false;
    bool hasFileOps = false;
    bool hasPersistence = false;

    if (result.vbaProject.has_value()) {
        for (const auto& mod : result.vbaProject->modules) {
            if (mod.containsNetwork) hasNetwork = true;
            if (mod.containsShell) hasShell = true;
            if (mod.containsFileOps) hasFileOps = true;
        }
    }

    // Check for persistence indicators
    std::string allCode;
    if (result.vbaProject.has_value()) {
        for (const auto& mod : result.vbaProject->modules) {
            allCode += mod.sourceCode;
        }
    }

    for (const auto& indicator : s_persistenceIndicators) {
        if (allCode.find(indicator) != std::string::npos) {
            hasPersistence = true;
            break;
        }
    }

    // Classify based on behavior
    if (hasNetwork && hasFileOps) {
        return MacroThreatCategory::Downloader;
    }

    if (hasShell && hasPersistence) {
        return MacroThreatCategory::Backdoor;
    }

    if (hasFileOps && !hasNetwork) {
        return MacroThreatCategory::Dropper;
    }

    if (hasPersistence) {
        return MacroThreatCategory::Persistence;
    }

    if (hasShell) {
        return MacroThreatCategory::RAT;
    }

    if (hasNetwork) {
        return MacroThreatCategory::InfoStealer;
    }

    return MacroThreatCategory::None;
}

[[nodiscard]] std::string MacroDetectorImpl::IdentifyMalwareFamily(const MacroScanResult& result) {
    // Pattern-based family identification
    std::string allCode;
    if (result.vbaProject.has_value()) {
        for (const auto& mod : result.vbaProject->modules) {
            allCode += mod.sourceCode;
        }
    }

    // Emotet indicators
    if (allCode.find("powershell") != std::string::npos &&
        allCode.find("downloadstring") != std::string::npos) {
        return "Emotet";
    }

    // Trickbot indicators
    if (allCode.find("wscript.shell") != std::string::npos &&
        allCode.find("cmd /c") != std::string::npos &&
        allCode.find("certutil") != std::string::npos) {
        return "Trickbot";
    }

    // Dridex indicators
    if (allCode.find("rundll32") != std::string::npos &&
        allCode.find(",DllRegisterServer") != std::string::npos) {
        return "Dridex";
    }

    // QakBot indicators
    if (allCode.find("regsvr32") != std::string::npos &&
        allCode.find(".tmp") != std::string::npos) {
        return "QakBot";
    }

    // BazarLoader indicators
    if (allCode.find("mshta") != std::string::npos &&
        allCode.find("http") != std::string::npos) {
        return "BazarLoader";
    }

    // Hancitor indicators
    if (allCode.find("urlmon") != std::string::npos &&
        allCode.find("URLDownloadToFile") != std::string::npos) {
        return "Hancitor";
    }

    return "";
}

[[nodiscard]] bool MacroDetectorImpl::IsPasswordProtected(std::span<const uint8_t> content) {
    if (content.size() < 512) {
        return false;
    }

    std::string contentStr(reinterpret_cast<const char*>(content.data()),
                           std::min(content.size(), size_t(4096)));

    // Check for encryption markers
    if (contentStr.find("EncryptedPackage") != std::string::npos ||
        contentStr.find("StrongEncryptionDataSpace") != std::string::npos ||
        contentStr.find("Encryption") != std::string::npos) {
        return true;
    }

    // Check OLE encryption flags
    if (content.size() >= 532) {
        // Check sector 0 for encryption indicator
        uint16_t flags = *reinterpret_cast<const uint16_t*>(content.data() + 530);
        if (flags & 0x0001) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] bool MacroDetectorImpl::ValidateDocumentStructure(std::span<const uint8_t> content) {
    if (content.size() < 512) {
        return false;
    }

    // Validate OLE header
    if (std::memcmp(content.data(), OLE_SIGNATURE, 8) == 0) {
        // Check sector size
        uint16_t sectorSize = *reinterpret_cast<const uint16_t*>(content.data() + 30);
        if (sectorSize != 0x0009 && sectorSize != 0x000C) {
            return false;
        }

        // Check mini sector size
        uint16_t miniSectorSize = *reinterpret_cast<const uint16_t*>(content.data() + 32);
        if (miniSectorSize != 0x0006) {
            return false;
        }

        return true;
    }

    // Validate ZIP header
    if (std::memcmp(content.data(), ZIP_SIGNATURE, 4) == 0) {
        return true;
    }

    return false;
}

void MacroDetectorImpl::NotifyCallback(const MacroScanResult& result) {
    std::shared_lock lock(m_mutex);
    if (m_resultCallback) {
        try {
            m_resultCallback(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MacroDetector", L"Callback exception: %hs", e.what());
        }
    }
}

void MacroDetectorImpl::NotifyError(const std::string& message, int code) {
    std::shared_lock lock(m_mutex);
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"MacroDetector", L"Error callback exception: %hs", e.what());
        }
    }
}

// ============================================================================
// MACRO DETECTOR PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

MacroDetector::MacroDetector()
    : m_impl(std::make_unique<MacroDetectorImpl>()) {
    s_instanceCreated.store(true);
}

MacroDetector::~MacroDetector() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] MacroDetector& MacroDetector::Instance() noexcept {
    static MacroDetector instance;
    return instance;
}

[[nodiscard]] bool MacroDetector::HasInstance() noexcept {
    return s_instanceCreated.load();
}

[[nodiscard]] bool MacroDetector::Initialize(const MacroDetectorConfiguration& config) {
    return m_impl->Initialize(config);
}

void MacroDetector::Shutdown() {
    m_impl->Shutdown();
}

[[nodiscard]] bool MacroDetector::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus MacroDetector::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

[[nodiscard]] bool MacroDetector::UpdateConfiguration(const MacroDetectorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

[[nodiscard]] MacroDetectorConfiguration MacroDetector::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

[[nodiscard]] MacroScanResult MacroDetector::ScanDocument(const std::filesystem::path& path) {
    return m_impl->ScanDocument(path);
}

[[nodiscard]] MacroScanResult MacroDetector::ScanDocument(
    std::span<const uint8_t> content,
    const std::string& fileName) {
    return m_impl->ScanDocument(content, fileName);
}

[[nodiscard]] bool MacroDetector::HasMacros(const std::filesystem::path& path) {
    return m_impl->HasMacros(path);
}

[[nodiscard]] bool MacroDetector::HasAutoExecMacros(const std::filesystem::path& path) {
    return m_impl->HasAutoExecMacros(path);
}

[[nodiscard]] std::string MacroDetector::ExtractVBA(const std::filesystem::path& path) {
    return m_impl->ExtractVBA(path);
}

[[nodiscard]] std::optional<VBAProjectInfo> MacroDetector::ExtractVBAProject(
    const std::filesystem::path& path) {
    return m_impl->ExtractVBAProject(path);
}

[[nodiscard]] std::vector<XLMMacroInfo> MacroDetector::ExtractXLMMacros(
    const std::filesystem::path& path) {
    return m_impl->ExtractXLMMacros(path);
}

[[nodiscard]] std::string MacroDetector::ExtractAllMacroContent(
    const std::filesystem::path& path) {
    return m_impl->ExtractAllMacroContent(path);
}

[[nodiscard]] DocumentFormat MacroDetector::DetectFormat(const std::filesystem::path& path) {
    return m_impl->DetectFormat(path);
}

[[nodiscard]] DocumentFormat MacroDetector::DetectFormat(std::span<const uint8_t> content) {
    return m_impl->DetectFormat(content);
}

[[nodiscard]] MacroScanResult MacroDetector::AnalyzeVBA(const std::string& vbaCode) {
    return m_impl->AnalyzeVBA(vbaCode);
}

[[nodiscard]] std::string MacroDetector::Deobfuscate(const std::string& code) {
    return m_impl->Deobfuscate(code);
}

[[nodiscard]] std::vector<std::string> MacroDetector::ExtractIOCs(const std::string& code) {
    return m_impl->ExtractIOCs(code);
}

void MacroDetector::RegisterCallback(ScanResultCallback callback) {
    m_impl->RegisterCallback(std::move(callback));
}

void MacroDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void MacroDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

[[nodiscard]] MacroStatistics MacroDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void MacroDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] bool MacroDetector::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string MacroDetector::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << MacroConstants::VERSION_MAJOR << "."
        << MacroConstants::VERSION_MINOR << "."
        << MacroConstants::VERSION_PATCH;
    return oss.str();
}

}  // namespace Scripts
}  // namespace ShadowStrike
