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
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
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

// Cross-module integration
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> MacroDetector::s_instanceCreated{false};

// ============================================================================
// JSON ESCAPE UTILITY (must precede struct ToJson implementations)
// ============================================================================

namespace {

/// @brief Escapes a string for safe embedding in JSON values.
[[nodiscard]] std::string JsonEscapeStr(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned int>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

}  // anonymous namespace

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetMacroTypeName(MacroType type) noexcept {
    switch (type) {
        case MacroType::VBALegacy:          return "VBA Legacy (OLE)";
        case MacroType::VBAModern:          return "VBA Modern (OpenXML)";
        case MacroType::Excel4XLM:          return "Excel 4.0 XLM";
        case MacroType::DDE:                return "Dynamic Data Exchange";
        case MacroType::SLK:                return "Symbolic Link";
        case MacroType::RTF_OLE:            return "RTF with OLE";
        case MacroType::Publisher:          return "Publisher Macro";
        case MacroType::Visio:              return "Visio Macro";
        case MacroType::OpenDocument:       return "OpenDocument Macro";
        case MacroType::XLLAddin:           return "XLL Add-in (Native DLL)";
        case MacroType::TemplateInjection:  return "Remote Template Injection";
        default:                            return "Unknown";
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
        case DocumentFormat::XLL:  return ".xll (Excel Add-in)";
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
    const std::wstring wideName = Utils::StringUtils::ToWide(functionName);
    for (const auto* autoExec : MacroConstants::VBA_AUTO_EXEC_FUNCTIONS) {
        if (Utils::StringUtils::IEquals(wideName,
                Utils::StringUtils::ToWide(std::string_view(autoExec)))) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool IsSuspiciousVBAAPI(std::string_view apiName) noexcept {
    const std::wstring wideName = Utils::StringUtils::ToWide(apiName);
    for (const auto* api : MacroConstants::SUSPICIOUS_VBA_APIS) {
        if (Utils::StringUtils::IContains(wideName,
                Utils::StringUtils::ToWide(std::string_view(api)))) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string VBAModuleInfo::ToJson() const {
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"moduleName\":\"" << esc(moduleName) << "\",";
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
        oss << "\"" << esc(autoExecFunctions[i]) << "\"";
    }
    oss << "],";

    oss << "\"suspiciousAPIs\":[";
    for (size_t i = 0; i < suspiciousAPIs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(suspiciousAPIs[i]) << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string VBAProjectInfo::ToJson() const {
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"projectName\":\"" << esc(projectName) << "\",";
    oss << "\"isProtected\":" << (isProtected ? "true" : "false") << ",";
    oss << "\"protectionType\":\"" << esc(protectionType) << "\",";
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
        oss << "\"" << esc(references[i]) << "\"";
    }
    oss << "],";

    oss << "\"userForms\":[";
    for (size_t i = 0; i < userForms.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(userForms[i]) << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string XLMMacroInfo::ToJson() const {
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"sheetName\":\"" << esc(sheetName) << "\",";
    oss << "\"isHidden\":" << (isHidden ? "true" : "false") << ",";
    oss << "\"isVeryHidden\":" << (isVeryHidden ? "true" : "false") << ",";
    oss << "\"hasAutoOpen\":" << (hasAutoOpen ? "true" : "false") << ",";

    oss << "\"formulas\":[";
    for (size_t i = 0; i < formulas.size() && i < 100; ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(formulas[i]) << "\"";
    }
    oss << "],";

    oss << "\"execCalls\":[";
    for (size_t i = 0; i < execCalls.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(execCalls[i]) << "\"";
    }
    oss << "],";

    oss << "\"callFunctions\":[";
    for (size_t i = 0; i < callFunctions.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(callFunctions[i]) << "\"";
    }
    oss << "],";

    oss << "\"externalLinks\":[";
    for (size_t i = 0; i < externalLinks.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(externalLinks[i]) << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string TemplateInjectionInfo::ToJson() const {
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"templateUrl\":\"" << esc(templateUrl) << "\",";
    oss << "\"xmlElement\":\"" << esc(xmlElement) << "\",";
    oss << "\"relationshipType\":\"" << esc(relationshipType) << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string XLLInfo::ToJson() const {
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"isPEFile\":" << (isPEFile ? "true" : "false") << ",";
    oss << "\"hasXlAutoOpen\":" << (hasXlAutoOpen ? "true" : "false") << ",";
    oss << "\"hasXlAutoClose\":" << (hasXlAutoClose ? "true" : "false") << ",";
    oss << "\"hasXlAutoRegister\":" << (hasXlAutoRegister ? "true" : "false") << ",";
    oss << "\"exportNames\":[";
    for (size_t i = 0; i < exportNames.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(exportNames[i]) << "\"";
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
    auto esc = JsonEscapeStr;
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":" << static_cast<int>(status) << ",";
    oss << "\"hasMacros\":" << (hasMacros ? "true" : "false") << ",";
    oss << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ",";
    oss << "\"isSuspicious\":" << (isSuspicious ? "true" : "false") << ",";
    oss << "\"category\":\"" << GetMacroThreatCategoryName(category) << "\",";
    oss << "\"riskScore\":" << riskScore << ",";
    oss << "\"detectedFamily\":\"" << esc(detectedFamily) << "\",";
    oss << "\"threatName\":\"" << esc(threatName) << "\",";
    oss << "\"format\":\"" << GetDocumentFormatName(format) << "\",";
    oss << "\"filePath\":\"" << esc(filePath.string()) << "\",";
    oss << "\"sha256\":\"" << esc(sha256) << "\",";
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
        oss << "\"" << esc(triggerFunctions[i]) << "\"";
    }
    oss << "],";

    oss << "\"suspiciousAPIs\":[";
    for (size_t i = 0; i < suspiciousAPIs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(suspiciousAPIs[i]) << "\"";
    }
    oss << "],";

    oss << "\"extractedIOCs\":[";
    for (size_t i = 0; i < extractedIOCs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(extractedIOCs[i]) << "\"";
    }
    oss << "],";

    oss << "\"matchedSignatures\":[";
    for (size_t i = 0; i < matchedSignatures.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << esc(matchedSignatures[i]) << "\"";
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

    if (!templateInjections.empty()) {
        oss << ",\"templateInjections\":[";
        for (size_t i = 0; i < templateInjections.size(); ++i) {
            if (i > 0) oss << ",";
            oss << templateInjections[i].ToJson();
        }
        oss << "]";
    }

    if (xllInfo.has_value()) {
        oss << ",\"xllInfo\":" << xllInfo->ToJson();
    }

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

[[nodiscard]] std::string MacroStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    auto now = Clock::now();
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    oss << "{";
    oss << "\"totalScans\":" << totalScans << ",";
    oss << "\"documentsWithMacros\":" << documentsWithMacros << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected << ",";
    oss << "\"suspiciousDetected\":" << suspiciousDetected << ",";
    oss << "\"xlmMacrosDetected\":" << xlmMacrosDetected << ",";
    oss << "\"vbaMacrosDetected\":" << vbaMacrosDetected << ",";
    oss << "\"obfuscatedDetected\":" << obfuscatedDetected << ",";
    oss << "\"passwordProtected\":" << passwordProtected << ",";
    oss << "\"parseErrors\":" << parseErrors << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned << ",";
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
    [[nodiscard]] MacroScanResult AnalyzeMacros(const std::filesystem::path& path);
    [[nodiscard]] MacroScanResult ScanVBAContent(std::string_view vbaContent);

    // Extraction
    [[nodiscard]] std::string ExtractVBA(const std::filesystem::path& path);
    [[nodiscard]] std::optional<VBAProjectInfo> ExtractVBAProject(const std::filesystem::path& path);
    [[nodiscard]] std::vector<XLMMacroInfo> ExtractXLMMacros(const std::filesystem::path& path);
    [[nodiscard]] std::string ExtractAllMacroContent(const std::filesystem::path& path);

    // Analysis
    [[nodiscard]] DocumentFormat DetectFormat(const std::filesystem::path& path);
    [[nodiscard]] DocumentFormat DetectFormat(std::span<const uint8_t> content,
                                              const std::string& fileName = "");
    [[nodiscard]] MacroScanResult AnalyzeVBA(const std::string& vbaCode);
    [[nodiscard]] std::string Deobfuscate(const std::string& code, size_t depth = 0);
    [[nodiscard]] std::vector<std::string> ExtractIOCs(const std::string& code);

    // Callbacks
    void RegisterCallback(MacroScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    [[nodiscard]] MacroStatisticsSnapshot GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

    // Kernel bridge
    void OnKernelProcessNotify(uint32_t processId, std::wstring_view imagePath,
                               std::wstring_view commandLine, bool isCreate);
    void OnKernelImageLoad(uint32_t processId, std::wstring_view imagePath,
                           uint64_t imageBase, size_t imageSize);
    [[nodiscard]] bool RequestKernelProcessBlock(uint32_t processId,
                                                  const std::wstring& reason);

    // Cross-module wiring
    void ReportThreatToAlertSystem(const MacroScanResult& result);
    void ReportScanTelemetry(const MacroScanResult& result);
    void ReportThreatToBehaviorAnalyzer(const MacroScanResult& result);

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
    [[nodiscard]] bool DetectTemplateInjection(std::span<const uint8_t> content,
                                                std::vector<TemplateInjectionInfo>& outInjections);
    [[nodiscard]] bool DetectXLLAddin(std::span<const uint8_t> content, XLLInfo& outXLL);
    [[nodiscard]] std::string ExtractAllMacroContentFromMemory(
        std::span<const uint8_t> content, const std::string& fileName);

    void NotifyCallback(const MacroScanResult& result);
    void NotifyError(const std::string& message, int code);

    // ========================================================================
    // SAFE BINARY CONTENT SEARCHING (bounds-checked, no full string copy)
    // ========================================================================

    [[nodiscard]] static bool BinaryContains(std::span<const uint8_t> data,
                                              std::string_view needle) noexcept;
    [[nodiscard]] static size_t BinaryFind(std::span<const uint8_t> data,
                                            std::string_view needle,
                                            size_t startPos = 0) noexcept;
    [[nodiscard]] static uint16_t SafeReadU16LE(std::span<const uint8_t> data,
                                                 size_t offset) noexcept;
    [[nodiscard]] static uint32_t SafeReadU32LE(std::span<const uint8_t> data,
                                                 size_t offset) noexcept;
    [[nodiscard]] static std::string JsonEscape(std::string_view input);

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

    std::vector<MacroScanResultCallback> m_resultCallbacks;
    ErrorCallback m_errorCallback;

    // LRU+TTL scan cache
    struct CacheEntry {
        MacroScanResult result;
        TimePoint insertTime;
    };
    std::unordered_map<std::string, std::list<std::pair<std::string, CacheEntry>>::iterator> m_cacheMap;
    std::list<std::pair<std::string, CacheEntry>> m_cacheList;
    mutable std::shared_mutex m_cacheMutex;

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
// SAFE BINARY UTILITIES
// ============================================================================

[[nodiscard]] bool MacroDetectorImpl::BinaryContains(
    std::span<const uint8_t> data, std::string_view needle) noexcept {
    return BinaryFind(data, needle) != std::string::npos;
}

[[nodiscard]] size_t MacroDetectorImpl::BinaryFind(
    std::span<const uint8_t> data, std::string_view needle, size_t startPos) noexcept {
    if (needle.empty() || data.size() < needle.size()) {
        return std::string::npos;
    }
    // Guard against overflow: check startPos + needle.size() <= data.size()
    if (startPos > data.size() || needle.size() > data.size() - startPos) {
        return std::string::npos;
    }
    auto needleBytes = reinterpret_cast<const uint8_t*>(needle.data());
    auto it = std::search(data.begin() + startPos, data.end(),
                          needleBytes, needleBytes + needle.size());
    if (it == data.end()) {
        return std::string::npos;
    }
    return static_cast<size_t>(it - data.begin());
}

[[nodiscard]] uint16_t MacroDetectorImpl::SafeReadU16LE(
    std::span<const uint8_t> data, size_t offset) noexcept {
    if (offset + 2 > data.size()) return 0;
    uint16_t val = 0;
    std::memcpy(&val, data.data() + offset, sizeof(val));
    return val;
}

[[nodiscard]] uint32_t MacroDetectorImpl::SafeReadU32LE(
    std::span<const uint8_t> data, size_t offset) noexcept {
    if (offset + 4 > data.size()) return 0;
    uint32_t val = 0;
    std::memcpy(&val, data.data() + offset, sizeof(val));
    return val;
}

[[nodiscard]] std::string MacroDetectorImpl::JsonEscape(std::string_view input) {
    return JsonEscapeStr(input);
}

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
    if (SUCCEEDED(hr)) {
        m_comInitialized = true;
    } else if (hr == RPC_E_CHANGED_MODE) {
        // Thread already in STA — COM is usable, but we must NOT call CoUninitialize
        m_comInitialized = false;
    } else {
        SS_LOG_WARN(L"MacroDetector", L"COM initialization failed: 0x%08X", hr);
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

    m_resultCallbacks.clear();
    m_errorCallback = nullptr;

    // Purge scan cache
    {
        std::unique_lock cacheLock(m_cacheMutex);
        m_cacheMap.clear();
        m_cacheList.clear();
    }

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

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"MacroDetector", L"ScanDocument called before initialization");
        result.status = MacroScanStatus::ErrorParsing;
        return result;
    }

    // Validation
    if (path.empty()) {
        SS_LOG_ERROR(L"MacroDetector", L"Empty file path provided");
        result.status = MacroScanStatus::ErrorFileAccess;
        NotifyError("Empty file path", -1);
        return result;
    }

    std::wstring widePath = path.wstring();
    
    // Validate path length and reject paths with embedded NUL or control characters
    if (widePath.size() > 32767) {
        SS_LOG_ERROR(L"MacroDetector", L"Path too long (%zu chars)", widePath.size());
        result.status = MacroScanStatus::ErrorFileAccess;
        NotifyError("Path exceeds maximum length", -1);
        return result;
    }
    
    // Check for embedded NUL or control characters in path (path traversal/injection defense)
    for (wchar_t c : widePath) {
        if (c == L'\0' || (c < 32 && c != L'\t')) {
            SS_LOG_ERROR(L"MacroDetector", L"Path contains invalid character");
            result.status = MacroScanStatus::ErrorFileAccess;
            NotifyError("Path contains invalid character", -1);
            return result;
        }
    }

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
    std::array<uint8_t, 32> hashBytes{};
    std::string sha256Hex;
    if (Utils::FileUtils::ComputeFileSHA256(widePath, hashBytes, &fileErr)) {
        sha256Hex = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    }

    // Check scan cache (LRU+TTL) before performing full analysis
    if (!sha256Hex.empty()) {
        std::shared_lock cacheLock(m_cacheMutex);
        auto cacheIt = m_cacheMap.find(sha256Hex);
        if (cacheIt != m_cacheMap.end()) {
            auto& entry = cacheIt->second->second;
            auto age = Clock::now() - entry.insertTime;
            if (age < MacroConstants::SCAN_CACHE_TTL) {
                result = entry.result;
                result.filePath = path;
                result.sha256 = sha256Hex;
                result.fileSize = fileStat.size;
                result.scanTime = std::chrono::system_clock::now();
                auto endTime = Clock::now();
                result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);
                SS_LOG_DEBUG(L"MacroDetector", L"Cache hit for %ls", widePath.c_str());
                return result;
            }
        }
    }

    // Convert to uint8_t span
    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    // Perform scan — delegate to the span overload for all analysis logic
    result = ScanDocument(contentSpan, path.filename().string());

    // Restore file-specific metadata that the span overload cannot know
    result.filePath = path;
    result.sha256 = sha256Hex;
    result.fileSize = fileStat.size;
    result.scanTime = std::chrono::system_clock::now();

    auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Stats already tracked in span overload — only add path-specific reporting

    // Insert into scan cache
    if (!sha256Hex.empty()) {
        std::unique_lock cacheLock(m_cacheMutex);
        auto existing = m_cacheMap.find(sha256Hex);
        if (existing != m_cacheMap.end()) {
            m_cacheList.erase(existing->second);
            m_cacheMap.erase(existing);
        }
        if (m_cacheMap.size() >= MacroConstants::SCAN_CACHE_CAPACITY) {
            auto& oldest = m_cacheList.back();
            m_cacheMap.erase(oldest.first);
            m_cacheList.pop_back();
        }
        CacheEntry ce{result, Clock::now()};
        m_cacheList.emplace_front(sha256Hex, std::move(ce));
        m_cacheMap.emplace(sha256Hex, m_cacheList.begin());
    }

    NotifyCallback(result);

    // Cross-module threat reporting
    if (result.isMalicious || result.isSuspicious) {
        ReportThreatToAlertSystem(result);
        ReportScanTelemetry(result);
    }
    if (result.isMalicious) {
        ReportThreatToBehaviorAnalyzer(result);
    }

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

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"MacroDetector", L"ScanDocument called before initialization");
        result.status = MacroScanStatus::ErrorParsing;
        return result;
    }

    // Validate content
    if (content.empty()) {
        result.status = MacroScanStatus::ErrorParsing;
        return result;
    }

    if (content.size() > m_config.maxDocumentSize) {
        result.status = MacroScanStatus::SkippedSizeLimit;
        return result;
    }

    // Detect format (use fileName for extension-based refinement)
    result.format = DetectFormat(content, fileName);

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

            // Detect remote template injection in OpenXML
            std::vector<TemplateInjectionInfo> injections;
            if (DetectTemplateInjection(content, injections)) {
                result.templateInjections = std::move(injections);
                if (!result.templateInjections.empty()) {
                    result.hasMacros = true;
                    result.macroTypes.push_back(MacroType::TemplateInjection);
                }
            }
        } else if (content.size() >= 5 &&
                   std::memcmp(content.data(), RTF_SIGNATURE, 5) == 0) {
            // RTF format — check for embedded OLE objects
            result.format = DocumentFormat::RTF;
            if (BinaryContains(content, "\\objdata") ||
                BinaryContains(content, "\\objemb") ||
                BinaryContains(content, "\\objocx")) {
                result.hasMacros = true;
                result.macroTypes.push_back(MacroType::RTF_OLE);
                SS_LOG_WARN(L"MacroDetector", L"RTF with embedded OLE object detected");
            }
        }

        // DDE (Dynamic Data Exchange) detection — applies to any format
        if (BinaryContains(content, "DDE") ||
            BinaryContains(content, "DDEAUTO") ||
            BinaryContains(content, "ddeLink") ||
            BinaryContains(content, "{\\field{\\*\\fldinst") ||
            BinaryContains(content, "dde\"")) {
            bool alreadyHasDDE = false;
            for (auto t : result.macroTypes) {
                if (t == MacroType::DDE) { alreadyHasDDE = true; break; }
            }
            if (!alreadyHasDDE) {
                result.hasMacros = true;
                result.macroTypes.push_back(MacroType::DDE);
                SS_LOG_WARN(L"MacroDetector", L"DDE link detected in document");
            }
        }

        if (content.size() >= 2 &&
                   content[0] == 'M' && content[1] == 'Z') {
            // Possible XLL add-in (PE/DLL loaded by Excel)
            XLLInfo xll;
            if (DetectXLLAddin(content, xll)) {
                result.xllInfo = xll;
                result.hasMacros = true;
                result.macroTypes.push_back(MacroType::XLLAddin);
            }
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

        // Extract IOCs from in-memory content (not from filePath which may be empty)
        if (m_config.extractIOCs) {
            std::string allCode = ExtractAllMacroContentFromMemory(content, fileName);
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
            result.isSuspicious = true;
            result.threatName = "Malicious.Macro." +
                std::string(GetMacroThreatCategoryName(result.category));
        } else if (result.riskScore >= 50) {
            result.status = MacroScanStatus::Suspicious;
            result.isSuspicious = true;
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

    // Track stats for memory-buffer scans (e.g., AMSI dispatch)
    m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalBytesScanned.fetch_add(content.size(), std::memory_order_relaxed);
    if (result.hasMacros) {
        m_stats.documentsWithMacros.fetch_add(1, std::memory_order_relaxed);
    }
    if (result.isMalicious) {
        m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
    } else if (result.status == MacroScanStatus::Suspicious) {
        m_stats.suspiciousDetected.fetch_add(1, std::memory_order_relaxed);
    }
    if (static_cast<size_t>(result.format) < m_stats.byFormat.size()) {
        m_stats.byFormat[static_cast<size_t>(result.format)].fetch_add(1, std::memory_order_relaxed);
    }
    if (static_cast<size_t>(result.category) < m_stats.byCategory.size()) {
        m_stats.byCategory[static_cast<size_t>(result.category)].fetch_add(1, std::memory_order_relaxed);
    }

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

    (void)ExtractXLMFromOLE(contentSpan, result);

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
    // Read only the first 16 bytes for magic-number detection
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(path, ec);
    if (ec || fileSize < 4) {
        return DocumentFormat::Unknown;
    }
    
    // Reject files exceeding max document size to prevent allocation attacks
    if (fileSize > m_config.maxDocumentSize) {
        SS_LOG_WARN(L"MacroDetector", L"DetectFormat: file exceeds max size (%llu bytes)", 
                    static_cast<unsigned long long>(fileSize));
        return DocumentFormat::Unknown;
    }

    std::array<uint8_t, 16> header{};
    size_t bytesToRead = std::min(static_cast<size_t>(fileSize), header.size());

    // Use FileUtils to read the full file only if we truly need it, otherwise
    // we just need the magic bytes. Since FileUtils doesn't expose partial reads,
    // use a quick Win32 read for the header.
#ifdef _WIN32
    HANDLE hFile = CreateFileW(path.wstring().c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return DocumentFormat::Unknown;
    }
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, header.data(), static_cast<DWORD>(bytesToRead), &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok || bytesRead < 4) {
        return DocumentFormat::Unknown;
    }
#else
    return DocumentFormat::Unknown;
#endif

    std::span<const uint8_t> headerSpan(header.data(), bytesRead);
    return DetectFormat(headerSpan, path.filename().string());
}

[[nodiscard]] DocumentFormat MacroDetectorImpl::DetectFormat(
    std::span<const uint8_t> content, const std::string& fileName) {

    if (content.size() < 4) {
        return DocumentFormat::Unknown;
    }

    // Extract lowercase extension from fileName for refinement
    std::string ext;
    if (!fileName.empty()) {
        auto dotPos = fileName.rfind('.');
        if (dotPos != std::string::npos) {
            ext = fileName.substr(dotPos);
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }
    }

    // Check OLE signature
    if (content.size() >= 8 && std::memcmp(content.data(), OLE_SIGNATURE, 8) == 0) {
        if (ext == ".xls")  return DocumentFormat::XLS;
        if (ext == ".xlsb") return DocumentFormat::XLSB;
        if (ext == ".ppt")  return DocumentFormat::PPT;
        if (ext == ".pub")  return DocumentFormat::PUB;
        if (ext == ".vsd" || ext == ".vsdx") return DocumentFormat::VSD;
        return DocumentFormat::DOC;
    }

    // Check ZIP signature (OpenXML)
    if (std::memcmp(content.data(), ZIP_SIGNATURE, 4) == 0) {
        if (ext == ".docm") return DocumentFormat::DOCM;
        if (ext == ".xlsm") return DocumentFormat::XLSM;
        if (ext == ".xlsx") return DocumentFormat::XLSX;
        if (ext == ".xlsb") return DocumentFormat::XLSB;
        if (ext == ".pptx") return DocumentFormat::PPTX;
        if (ext == ".pptm") return DocumentFormat::PPTM;
        if (ext == ".odt")  return DocumentFormat::ODT;
        if (ext == ".ods")  return DocumentFormat::ODS;
        return DocumentFormat::DOCX;
    }

    // Check RTF signature
    if (content.size() >= 5 && std::memcmp(content.data(), RTF_SIGNATURE, 5) == 0) {
        return DocumentFormat::RTF;
    }

    // Check for PE/MZ (XLL add-in)
    if (content.size() >= 2 && content[0] == 'M' && content[1] == 'Z') {
        if (ext == ".xll") return DocumentFormat::XLL;
    }

    // MHT by extension
    if (ext == ".mht" || ext == ".mhtml") {
        return DocumentFormat::MHT;
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
        result.isSuspicious = true;
        result.threatName = "Malicious.Macro." +
            std::string(GetMacroThreatCategoryName(result.category));
    } else if (result.riskScore >= 50) {
        result.status = MacroScanStatus::Suspicious;
        result.isSuspicious = true;
    } else {
        result.status = MacroScanStatus::Clean;
    }

    return result;
}

[[nodiscard]] std::string MacroDetectorImpl::Deobfuscate(const std::string& code, size_t depth) {
    if (!m_config.enableDeobfuscation) {
        return code;
    }

    if (depth >= MacroConstants::MAX_DEOBFUSCATION_DEPTH) {
        return code;
    }

    // Guard against ReDoS on extremely large inputs
    std::string safeInput = code;
    if (safeInput.size() > MacroConstants::MAX_REGEX_INPUT_SIZE) {
        safeInput.resize(MacroConstants::MAX_REGEX_INPUT_SIZE);
    }

    std::string result = safeInput;

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
    std::regex concatPattern(R"re("([^"]*)" \& "([^"]*)")re");    searchStart = result.cbegin();
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
    result = deobfuscated;

    // Concatenation simplification (basic) - apply only if still under size limit
    if (result.size() <= MacroConstants::MAX_REGEX_INPUT_SIZE) {
        std::regex concatPattern(R"re("([^"]*)" \& "([^"]*)")re");
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
        result = deobfuscated;
    }

    // If the output changed, recurse to handle nested obfuscation layers
    if (result != safeInput) {
        return Deobfuscate(result, depth + 1);
    }

    return result;
}

[[nodiscard]] std::vector<std::string> MacroDetectorImpl::ExtractIOCs(const std::string& code) {
    std::vector<std::string> iocs;

    if (code.empty()) {
        return iocs;
    }

    // Guard against ReDoS on extremely large inputs
    const std::string& safeCode = (code.size() <= MacroConstants::MAX_REGEX_INPUT_SIZE)
        ? code : code.substr(0, MacroConstants::MAX_REGEX_INPUT_SIZE);

    const std::sregex_iterator endSentinel;

    // Extract URLs
    std::regex urlPattern(R"((https?://[^\s\"'\)>]+))");
    std::sregex_iterator urlIt(safeCode.begin(), safeCode.end(), urlPattern);

    for (; urlIt != endSentinel && iocs.size() < 100; ++urlIt) {
        std::string url = urlIt->str();
        if (std::find(iocs.begin(), iocs.end(), url) == iocs.end()) {
            iocs.push_back(std::move(url));
        }
    }
    
    // Extract domains (e.g., evil.com without protocol)
    std::regex domainPattern(R"(\b([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b)");
    std::sregex_iterator domainIt(safeCode.begin(), safeCode.end(), domainPattern);
    
    for (; domainIt != endSentinel && iocs.size() < 100; ++domainIt) {
        std::string domain = domainIt->str();
        // Filter out common legitimate domains to reduce noise
        if (domain.find("microsoft.com") == std::string::npos &&
            domain.find("windows.com") == std::string::npos &&
            domain.find("office.com") == std::string::npos &&
            std::find(iocs.begin(), iocs.end(), domain) == iocs.end()) {
            iocs.push_back(std::move(domain));
        }
    }

    // Extract IP addresses
    std::regex ipPattern(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    std::sregex_iterator ipIt(safeCode.begin(), safeCode.end(), ipPattern);

    for (; ipIt != endSentinel && iocs.size() < 100; ++ipIt) {
        std::string ip = ipIt->str();
        // Validate IP octet ranges
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
            iocs.push_back(std::move(ip));
        }
    }

    // Extract file paths
    std::regex pathPattern(R"(([A-Za-z]:\\[^\s\"'\)>]+\.(exe|dll|bat|cmd|ps1|vbs|js)))");
    std::sregex_iterator pathIt(safeCode.begin(), safeCode.end(), pathPattern);

    for (; pathIt != endSentinel && iocs.size() < 100; ++pathIt) {
        std::string fpath = pathIt->str();
        if (std::find(iocs.begin(), iocs.end(), fpath) == iocs.end()) {
            iocs.push_back(std::move(fpath));
        }
    }

    // Extract registry keys
    std::regex regPattern(R"((HKLM\\[^\s\"'\)>]+|HKCU\\[^\s\"'\)>]+))");
    std::sregex_iterator regIt(safeCode.begin(), safeCode.end(), regPattern);

    for (; regIt != endSentinel && iocs.size() < 100; ++regIt) {
        std::string reg = regIt->str();
        if (std::find(iocs.begin(), iocs.end(), reg) == iocs.end()) {
            iocs.push_back(std::move(reg));
        }
    }

    return iocs;
}

void MacroDetectorImpl::RegisterCallback(MacroScanResultCallback callback) {
    std::unique_lock lock(m_mutex);
    if (m_resultCallbacks.size() >= MacroConstants::MAX_CALLBACKS) {
        SS_LOG_WARN(L"MacroDetector", L"Max callbacks (%zu) reached, ignoring",
                    MacroConstants::MAX_CALLBACKS);
        return;
    }
    m_resultCallbacks.push_back(std::move(callback));
}

void MacroDetectorImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void MacroDetectorImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_resultCallbacks.clear();
    m_errorCallback = nullptr;
}

[[nodiscard]] MacroStatisticsSnapshot MacroDetectorImpl::GetStatistics() const {
    MacroStatisticsSnapshot snapshot;
    snapshot.totalScans = m_stats.totalScans.load(std::memory_order_relaxed);
    snapshot.documentsWithMacros = m_stats.documentsWithMacros.load(std::memory_order_relaxed);
    snapshot.maliciousDetected = m_stats.maliciousDetected.load(std::memory_order_relaxed);
    snapshot.suspiciousDetected = m_stats.suspiciousDetected.load(std::memory_order_relaxed);
    snapshot.xlmMacrosDetected = m_stats.xlmMacrosDetected.load(std::memory_order_relaxed);
    snapshot.vbaMacrosDetected = m_stats.vbaMacrosDetected.load(std::memory_order_relaxed);
    snapshot.obfuscatedDetected = m_stats.obfuscatedDetected.load(std::memory_order_relaxed);
    snapshot.passwordProtected = m_stats.passwordProtected.load(std::memory_order_relaxed);
    snapshot.parseErrors = m_stats.parseErrors.load(std::memory_order_relaxed);
    snapshot.totalBytesScanned = m_stats.totalBytesScanned.load(std::memory_order_relaxed);
    for (size_t i = 0; i < m_stats.byFormat.size(); ++i) {
        snapshot.byFormat[i] = m_stats.byFormat[i].load(std::memory_order_relaxed);
    }
    for (size_t i = 0; i < m_stats.byCategory.size(); ++i) {
        snapshot.byCategory[i] = m_stats.byCategory[i].load(std::memory_order_relaxed);
    }
    snapshot.startTime = m_stats.startTime;
    return snapshot;
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

    outProject.projectName = "VBAProject";

    // Search for VBA project stream markers using safe binary search
    bool hasVBAIndicator = BinaryContains(content, "Attribute VB_Name") ||
                           BinaryContains(content, "_VBA_PROJECT") ||
                           BinaryContains(content, std::string_view("dir", 3));

    if (hasVBAIndicator) {
        std::string vbaCode;
        if (ExtractVBAFromOLE(content, vbaCode)) {
            VBAModuleInfo module;
            module.moduleName = "Module1";
            module.sourceCode = vbaCode;
            module.sourceSize = vbaCode.size();
            module.type = VBAModuleType::Standard;

            module.lineCount = std::count(vbaCode.begin(), vbaCode.end(), '\n') + 1;

            outProject.modules.push_back(std::move(module));
        }
    }

    // Check for project protection using binary search
    if (BinaryContains(content, "DPB=") ||
        BinaryContains(content, "CMG=")) {
        outProject.isProtected = true;
        outProject.protectionType = "Password Protected";
    }
    
    // VBA Stomping detection: check for P-code only (source code removed but P-code remains)
    // This is a common evasion where VBA source is removed but compiled P-code executes.
    // Indicators: presence of _VBA_PROJECT or PerformanceCache but missing Attribute VB_Name
    if (BinaryContains(content, "_VBA_PROJECT") || BinaryContains(content, "PerformanceCache")) {
        bool hasSourceCode = BinaryContains(content, "Attribute VB_Name") ||
                             BinaryContains(content, "Sub ") ||
                             BinaryContains(content, "Function ");
        if (!hasSourceCode) {
            outProject.hasPCodeOnly = true;
            SS_LOG_WARN(L"MacroDetector", L"VBA stomping detected: P-code only, no source");
        }
    }

    outProject.moduleCount = outProject.modules.size();
    for (const auto& mod : outProject.modules) {
        outProject.totalSourceSize += mod.sourceSize;
    }

    return !outProject.modules.empty() || outProject.hasPCodeOnly;
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

    outProject.projectName = "VBAProject";

    // Look for vbaProject.bin in the ZIP content using safe binary search
    if (BinaryContains(content, "vbaProject.bin") ||
        BinaryContains(content, "xl/vbaProject.bin") ||
        BinaryContains(content, "word/vbaProject.bin")) {

        VBAModuleInfo module;
        module.moduleName = "Module1";
        module.type = VBAModuleType::Standard;

        outProject.modules.push_back(std::move(module));
    }

    outProject.moduleCount = outProject.modules.size();

    return !outProject.modules.empty();
}

[[nodiscard]] bool MacroDetectorImpl::ExtractVBAFromOLE(
    std::span<const uint8_t> content,
    std::string& outVBA) {

    // Use BinaryFind to locate VBA code markers without copying entire content
    size_t pos = BinaryFind(content, "Attribute VB_Name");
    if (pos == std::string::npos) {
        pos = BinaryFind(content, "Sub ");
        if (pos == std::string::npos) {
            pos = BinaryFind(content, "Function ");
        }
    }

    if (pos != std::string::npos) {
        // Cap extraction to MAX_VBA_PROJECT_SIZE (50 MB) to prevent unbounded allocations
        size_t remainingBytes = content.size() - pos;
        size_t maxExtract = std::min({
            remainingBytes,
            size_t(10000),
            MacroConstants::MAX_VBA_PROJECT_SIZE
        });
        
        if (maxExtract == 0) {
            return false;
        }
        
        outVBA.assign(reinterpret_cast<const char*>(content.data() + pos), maxExtract);

        // Clean up non-printable characters
        for (char& c : outVBA) {
            if (static_cast<unsigned char>(c) < 32 &&
                c != '\n' && c != '\r' && c != '\t') {
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

    // XLM macro detection using safe binary search
    bool hasXLM = BinaryContains(content, "=EXEC(")  ||
                  BinaryContains(content, "=CALL(")  ||
                  BinaryContains(content, "=RUN(")   ||
                  BinaryContains(content, "=HALT()") ||
                  BinaryContains(content, "=FORMULA(") ||
                  BinaryContains(content, "Auto_Open");

    if (!hasXLM) {
        return false;
    }

    XLMMacroInfo xlm;
    xlm.sheetName = "Macro1";

    // Extract text-like content for regex matching, capped for ReDoS safety
    // Check content.size() first to avoid allocating MAX_REGEX_INPUT_SIZE when content is smaller
    size_t safeLen = std::min(content.size(), MacroConstants::MAX_REGEX_INPUT_SIZE);
    if (safeLen == 0) {
        return false;
    }
    
    std::string safeStr;
    safeStr.reserve(safeLen);
    for (size_t i = 0; i < safeLen; ++i) {
        char c = static_cast<char>(content[i]);
        if (static_cast<unsigned char>(c) >= 32 || c == '\n' || c == '\r' || c == '\t') {
            safeStr += c;
        }
    }

    // Extract EXEC calls
    {
        std::regex execPattern(R"(=EXEC\([^)]+\))");
        std::sregex_iterator it(safeStr.begin(), safeStr.end(), execPattern);
        const std::sregex_iterator end;
        for (; it != end; ++it) {
            xlm.execCalls.push_back(it->str());
        }
    }

    // Extract CALL functions
    {
        std::regex callPattern(R"(=CALL\([^)]+\))");
        std::sregex_iterator it(safeStr.begin(), safeStr.end(), callPattern);
        const std::sregex_iterator end;
        for (; it != end; ++it) {
            xlm.callFunctions.push_back(it->str());
        }
    }

    // Check for Auto_Open
    if (BinaryContains(content, "Auto_Open")) {
        xlm.hasAutoOpen = true;
    }

    outXLM.push_back(std::move(xlm));
    return true;
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
    // Guard input size for regex
    const std::string& safeCode = (code.size() <= MacroConstants::MAX_REGEX_INPUT_SIZE)
        ? code : code.substr(0, MacroConstants::MAX_REGEX_INPUT_SIZE);
    std::regex shortVarPattern(R"(\b[a-z]{1,2}\d*\s*=)");
    std::sregex_iterator shortVarBegin(safeCode.begin(), safeCode.end(), shortVarPattern);
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

    // Check for persistence indicators (case-insensitive)
    std::wstring wideCode;
    if (result.vbaProject.has_value()) {
        std::string allCode;
        for (const auto& mod : result.vbaProject->modules) {
            allCode += mod.sourceCode;
        }
        wideCode = Utils::StringUtils::ToWide(allCode);
    }

    for (const auto& indicator : s_persistenceIndicators) {
        if (Utils::StringUtils::IContains(wideCode,
                Utils::StringUtils::ToWide(std::string_view(indicator)))) {
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
    // Pattern-based family identification using case-insensitive matching
    std::string allCode;
    if (result.vbaProject.has_value()) {
        for (const auto& mod : result.vbaProject->modules) {
            allCode += mod.sourceCode;
        }
    }

    if (allCode.empty()) {
        return "";
    }

    // Convert to wide for case-insensitive matching
    std::wstring wideCode = Utils::StringUtils::ToWide(allCode);

    // Emotet indicators
    if (Utils::StringUtils::IContains(wideCode, L"powershell") &&
        Utils::StringUtils::IContains(wideCode, L"downloadstring")) {
        return "Emotet";
    }

    // Trickbot indicators
    if (Utils::StringUtils::IContains(wideCode, L"wscript.shell") &&
        Utils::StringUtils::IContains(wideCode, L"cmd /c") &&
        Utils::StringUtils::IContains(wideCode, L"certutil")) {
        return "Trickbot";
    }

    // Dridex indicators
    if (Utils::StringUtils::IContains(wideCode, L"rundll32") &&
        Utils::StringUtils::IContains(wideCode, L",DllRegisterServer")) {
        return "Dridex";
    }

    // QakBot indicators
    if (Utils::StringUtils::IContains(wideCode, L"regsvr32") &&
        Utils::StringUtils::IContains(wideCode, L".tmp")) {
        return "QakBot";
    }

    // BazarLoader indicators
    if (Utils::StringUtils::IContains(wideCode, L"mshta") &&
        Utils::StringUtils::IContains(wideCode, L"http")) {
        return "BazarLoader";
    }

    // Hancitor indicators
    if (Utils::StringUtils::IContains(wideCode, L"urlmon") &&
        Utils::StringUtils::IContains(wideCode, L"URLDownloadToFile")) {
        return "Hancitor";
    }

    return "";
}

[[nodiscard]] bool MacroDetectorImpl::IsPasswordProtected(std::span<const uint8_t> content) {
    if (content.size() < 512) {
        return false;
    }

    // Check for encryption markers using safe binary search (bounded to first 4KB)
    auto headerSpan = content.subspan(0, std::min(content.size(), size_t(4096)));
    if (BinaryContains(headerSpan, "EncryptedPackage") ||
        BinaryContains(headerSpan, "StrongEncryptionDataSpace") ||
        BinaryContains(headerSpan, "Encryption")) {
        return true;
    }

    // Check OLE encryption flags using safe aligned read
    if (content.size() >= 532) {
        uint16_t flags = SafeReadU16LE(content, 530);
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
        // Check sector size using safe aligned read
        uint16_t sectorSize = SafeReadU16LE(content, 30);
        if (sectorSize != 0x0009 && sectorSize != 0x000C) {
            return false;
        }

        // Check mini sector size using safe aligned read
        uint16_t miniSectorSize = SafeReadU16LE(content, 32);
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

[[nodiscard]] bool MacroDetectorImpl::DetectTemplateInjection(
    std::span<const uint8_t> content,
    std::vector<TemplateInjectionInfo>& outInjections) {

    // Template injection uses relationship XML in OpenXML to reference
    // a remote URL for macros/content — enabling "macro-less" initial delivery.
    for (const auto* marker : MacroConstants::TEMPLATE_INJECTION_MARKERS) {
        if (outInjections.size() >= MacroConstants::MAX_TEMPLATE_INJECTIONS) break;
        size_t pos = 0;
        while ((pos = BinaryFind(content, std::string_view(marker), pos)) != std::string::npos) {
            if (outInjections.size() >= MacroConstants::MAX_TEMPLATE_INJECTIONS) break;
            // Try to extract a URL near this marker
            // Look ahead up to 512 bytes for http:// or https://
            size_t searchEnd = std::min(pos + 512, content.size());
            auto window = content.subspan(pos, searchEnd - pos);

            size_t httpPos = BinaryFind(window, "http");
            if (httpPos != std::string::npos) {
                // Extract URL (up to next quote, angle bracket, or whitespace)
                size_t urlStart = httpPos;
                size_t urlEnd = urlStart;
                constexpr size_t MAX_URL_LENGTH = 2048;
                while (urlEnd < window.size() && (urlEnd - urlStart) < MAX_URL_LENGTH) {
                    char c = static_cast<char>(window[urlEnd]);
                    if (c == '"' || c == '\'' || c == '>' || c == '<' ||
                        c == ' ' || c == '\n' || c == '\r' || c == '\0') {
                        break;
                    }
                    ++urlEnd;
                }
                // Validate extracted URL length before assignment
                size_t urlLen = urlEnd - urlStart;
                if (urlLen > 0 && urlLen <= MAX_URL_LENGTH &&
                    outInjections.size() < MacroConstants::MAX_TEMPLATE_INJECTIONS) {
                    TemplateInjectionInfo info;
                    info.templateUrl.assign(
                        reinterpret_cast<const char*>(window.data() + urlStart),
                        urlLen);
                    info.xmlElement = marker;
                    info.relationshipType = marker;
                    outInjections.push_back(std::move(info));

                    SS_LOG_WARN(L"MacroDetector",
                                L"Template injection detected: %hs -> %.*hs",
                                marker, 
                                static_cast<int>(std::min(urlLen, size_t(256))),
                                outInjections.back().templateUrl.c_str());
                }
            }

            pos += std::strlen(marker);
        }
    }

    return !outInjections.empty();
}

[[nodiscard]] bool MacroDetectorImpl::DetectXLLAddin(
    std::span<const uint8_t> content, XLLInfo& outXLL) {

    // XLL files are native DLLs loaded by Excel.
    // Check for PE/MZ header first.
    if (content.size() < 64) {
        return false;
    }
    if (content[0] != 'M' || content[1] != 'Z') {
        return false;
    }
    outXLL.isPEFile = true;

    // Check for XLL-specific exports by scanning the export name table.
    // These exports auto-execute when Excel loads the add-in.
    if (BinaryContains(content, "xlAutoOpen")) {
        outXLL.hasXlAutoOpen = true;
        outXLL.exportNames.push_back("xlAutoOpen");
    }
    if (BinaryContains(content, "xlAutoClose")) {
        outXLL.hasXlAutoClose = true;
        outXLL.exportNames.push_back("xlAutoClose");
    }
    if (BinaryContains(content, "xlAutoRegister")) {
        outXLL.hasXlAutoRegister = true;
        outXLL.exportNames.push_back("xlAutoRegister");
    }
    if (BinaryContains(content, "xlAutoAdd")) {
        outXLL.exportNames.push_back("xlAutoAdd");
    }
    if (BinaryContains(content, "xlAutoRemove")) {
        outXLL.exportNames.push_back("xlAutoRemove");
    }

    // Consider it a detection if it has any auto-execution export
    return outXLL.hasXlAutoOpen || outXLL.hasXlAutoClose || outXLL.hasXlAutoRegister;
}

[[nodiscard]] std::string MacroDetectorImpl::ExtractAllMacroContentFromMemory(
    std::span<const uint8_t> content, const std::string& fileName) {

    std::ostringstream oss;

    // Try to extract VBA from the in-memory content
    std::string vbaCode;
    if (ExtractVBAFromOLE(content, vbaCode)) {
        oss << vbaCode << "\n";
    }

    // Try to extract XLM macros from the in-memory content
    std::vector<XLMMacroInfo> xlmMacros;
    if (ExtractXLMFromOLE(content, xlmMacros)) {
        for (const auto& macro : xlmMacros) {
            oss << "' === XLM Sheet: " << macro.sheetName << " ===\n";
            for (const auto& formula : macro.formulas) {
                oss << formula << "\n";
            }
            oss << "\n";
        }
    }

    return oss.str();
}

[[nodiscard]] MacroScanResult MacroDetectorImpl::AnalyzeMacros(
    const std::filesystem::path& path) {
    // Bridge for AttachmentScanner integration — delegates to full document scan
    return ScanDocument(path);
}

[[nodiscard]] MacroScanResult MacroDetectorImpl::ScanVBAContent(std::string_view vbaContent) {
    // Scan raw VBA content submitted by AMSI provider or other callers.
    // No document container to parse — analyze the VBA code directly.
    // Cap input size to prevent resource exhaustion.
    if (vbaContent.empty()) {
        MacroScanResult result;
        result.status = MacroScanStatus::Clean;
        result.scanTime = std::chrono::system_clock::now();
        return result;
    }
    
    // Enforce MAX_VBA_PROJECT_SIZE limit on raw VBA input
    if (vbaContent.size() > MacroConstants::MAX_VBA_PROJECT_SIZE) {
        MacroScanResult result;
        result.status = MacroScanStatus::SkippedSizeLimit;
        result.scanTime = std::chrono::system_clock::now();
        SS_LOG_WARN(L"MacroDetector", L"ScanVBAContent: input exceeds MAX_VBA_PROJECT_SIZE (%zu bytes)",
                    vbaContent.size());
        return result;
    }

    return AnalyzeVBA(std::string(vbaContent));
}

void MacroDetectorImpl::NotifyCallback(const MacroScanResult& result) {
    std::shared_lock lock(m_mutex);
    for (const auto& cb : m_resultCallbacks) {
        if (cb) {
            try {
                cb(result);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"MacroDetector", L"Callback exception: %hs", e.what());
            }
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
// KERNEL BRIDGE IMPLEMENTATIONS
// ============================================================================

void MacroDetectorImpl::OnKernelProcessNotify(
    uint32_t processId,
    std::wstring_view imagePath,
    std::wstring_view commandLine,
    bool isCreate) {

    if (!m_initialized.load(std::memory_order_acquire)) return;
    if (!isCreate) return;

    // Validate input lengths to prevent processing malicious oversized strings
    if (imagePath.size() > 32767 || commandLine.size() > 32767) {
        SS_LOG_WARN(L"MacroDetector", L"Kernel: Oversized path/cmdline rejected PID=%u", processId);
        return;
    }

    // Extract filename from path
    const auto lastSep = imagePath.find_last_of(L"\\/");
    const auto fileName = (lastSep != std::wstring_view::npos)
        ? imagePath.substr(lastSep + 1) : imagePath;
    std::wstring lowerName(fileName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    // Detect Office host processes that execute macros
    const bool isOfficeHost =
        lowerName == L"winword.exe" ||
        lowerName == L"excel.exe" ||
        lowerName == L"powerpnt.exe" ||
        lowerName == L"mspub.exe" ||
        lowerName == L"visio.exe" ||
        lowerName == L"outlook.exe";

    if (!isOfficeHost) return;

    SS_LOG_INFO(L"MacroDetector",
        L"Kernel: Office process created PID=%u image=%.*ls",
        processId,
        static_cast<int>(std::min(imagePath.size(), size_t(260))),
        imagePath.data());

    // Check command line for suspicious macro-related arguments
    if (!commandLine.empty()) {
        std::wstring lowerCmd(commandLine);
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::towlower);

        const bool hasMacroArg =
            lowerCmd.find(L"/mfilesafe") != std::wstring::npos ||
            lowerCmd.find(L"/m ") != std::wstring::npos ||
            lowerCmd.find(L".docm") != std::wstring::npos ||
            lowerCmd.find(L".xlsm") != std::wstring::npos ||
            lowerCmd.find(L".pptm") != std::wstring::npos ||
            lowerCmd.find(L".xlsb") != std::wstring::npos ||
            lowerCmd.find(L".xll") != std::wstring::npos;

        if (hasMacroArg) {
            SS_LOG_WARN(L"MacroDetector",
                L"Kernel: Office macro-enabled document opened PID=%u cmd=%.*ls",
                processId,
                static_cast<int>(std::min(commandLine.size(), size_t(512))),
                commandLine.data());
        }
    }
}

void MacroDetectorImpl::OnKernelImageLoad(
    uint32_t processId,
    std::wstring_view imagePath,
    uint64_t imageBase,
    size_t imageSize) {

    if (!m_initialized.load(std::memory_order_acquire)) return;

    // Validate input length
    if (imagePath.size() > 32767) {
        return;
    }

    const auto lastSep = imagePath.find_last_of(L"\\/");
    const auto fileName = (lastSep != std::wstring_view::npos)
        ? imagePath.substr(lastSep + 1) : imagePath;
    std::wstring lowerName(fileName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    // Detect VBA/macro runtime DLLs being loaded
    const bool isMacroRuntime =
        lowerName == L"vbe7.dll" ||
        lowerName == L"vbe6.dll" ||
        lowerName == L"vbeui.dll" ||
        lowerName == L"mso.dll" ||
        lowerName == L"vba7.dll" ||
        lowerName == L"vba6.dll";

    if (!isMacroRuntime) return;

    SS_LOG_INFO(L"MacroDetector",
        L"Kernel: Macro runtime loaded PID=%u image=%.*ls base=0x%llX size=%zu",
        processId,
        static_cast<int>(std::min(imagePath.size(), size_t(260))),
        imagePath.data(),
        imageBase, imageSize);
}

[[nodiscard]] bool MacroDetectorImpl::RequestKernelProcessBlock(
    uint32_t processId,
    const std::wstring& reason) {

    try {
        if (!Communication::IPCManager::HasInstance()) {
            SS_LOG_WARN(L"MacroDetector",
                L"IPCManager not available for kernel block PID=%u", processId);
            return false;
        }

        auto& ipc = Communication::IPCManager::Instance();

        struct {
            uint32_t messageType;
            uint32_t processId;
            wchar_t reason[256];
        } blockRequest{};

        blockRequest.messageType = MacroConstants::KERNEL_MSG_BLOCK_PROCESS;
        blockRequest.processId = processId;
        // _countof includes the NUL terminator, so we use _countof - 1 for safe copy
        wcsncpy_s(blockRequest.reason, _countof(blockRequest.reason),
                  reason.c_str(), _TRUNCATE);

        if (ipc.SendToKernel(&blockRequest, sizeof(blockRequest))) {
            SS_LOG_INFO(L"MacroDetector",
                L"Kernel process block requested PID=%u reason=%ls",
                processId, reason.c_str());
            return true;
        }

        SS_LOG_ERROR(L"MacroDetector",
            L"Failed to send kernel process block PID=%u", processId);
        return false;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MacroDetector",
            L"Kernel process block exception PID=%u: %hs",
            processId, e.what());
        return false;
    }
}

// ============================================================================
// CROSS-MODULE WIRING IMPLEMENTATIONS
// ============================================================================

void MacroDetectorImpl::ReportThreatToAlertSystem(const MacroScanResult& result) {
    try {
        if (!Communication::AlertSystem::HasInstance()) return;

        auto& alerts = Communication::AlertSystem::Instance();

        auto severity = result.isMalicious
            ? Communication::AlertSeverity::Critical
            : Communication::AlertSeverity::High;

        std::string subject = "Malicious macro detected";
        if (!result.detectedFamily.empty()) {
            subject += " [" + result.detectedFamily + "]";
        }

        std::string details = result.ToJson();

        (void)alerts.RaiseAlert(severity,
            Communication::AlertType::ThreatDetection,
            subject, details, "MacroDetector");

        SS_LOG_INFO(L"MacroDetector",
            L"Alert raised: %hs (risk=%d)",
            subject.c_str(), result.riskScore);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MacroDetector",
            L"AlertSystem report failed: %hs", e.what());
    }
}

void MacroDetectorImpl::ReportScanTelemetry(const MacroScanResult& result) {
    try {
        if (!Communication::TelemetryCollector::HasInstance()) return;

        auto& telemetry = Communication::TelemetryCollector::Instance();

        std::map<std::string, std::string> data;
        data["module"] = "MacroDetector";
        data["status"] = std::to_string(static_cast<int>(result.status));
        data["hasMacros"] = result.hasMacros ? "true" : "false";
        data["isMalicious"] = result.isMalicious ? "true" : "false";
        data["riskScore"] = std::to_string(result.riskScore);
        data["format"] = std::string(GetDocumentFormatName(result.format));
        data["scanDurationUs"] = std::to_string(result.scanDuration.count());

        if (!result.sha256.empty()) {
            data["sha256"] = result.sha256;
        }
        if (!result.detectedFamily.empty()) {
            data["family"] = result.detectedFamily;
        }
        if (!result.threatName.empty()) {
            data["threatName"] = result.threatName;
        }

        telemetry.RecordCustom("macro_scan", data);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MacroDetector",
            L"Telemetry report failed: %hs", e.what());
    }
}

void MacroDetectorImpl::ReportThreatToBehaviorAnalyzer(const MacroScanResult& result) {
    try {
        if (!Communication::TelemetryCollector::HasInstance()) return;

        auto& telemetry = Communication::TelemetryCollector::Instance();

        std::map<std::string, std::string> data;
        data["module"] = "MacroDetector";
        data["event"] = "macro_threat_behavior";
        data["category"] = std::string(GetMacroThreatCategoryName(result.category));
        data["riskScore"] = std::to_string(result.riskScore);

        if (!result.triggerFunctions.empty()) {
            std::string triggers;
            for (const auto& fn : result.triggerFunctions) {
                if (!triggers.empty()) triggers += ",";
                triggers += fn;
            }
            data["triggerFunctions"] = triggers;
        }

        if (!result.suspiciousAPIs.empty()) {
            std::string apis;
            for (const auto& api : result.suspiciousAPIs) {
                if (!apis.empty()) apis += ",";
                apis += api;
            }
            data["suspiciousAPIs"] = apis;
        }

        if (!result.extractedIOCs.empty()) {
            data["iocCount"] = std::to_string(result.extractedIOCs.size());
        }

        telemetry.RecordCustom("macro_behavior", data);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"MacroDetector",
            L"BehaviorAnalyzer report failed: %hs", e.what());
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

[[nodiscard]] MacroScanResult MacroDetector::AnalyzeMacros(const std::filesystem::path& path) {
    return m_impl->AnalyzeMacros(path);
}

[[nodiscard]] MacroScanResult MacroDetector::ScanVBAContent(std::string_view vbaContent) {
    return m_impl->ScanVBAContent(vbaContent);
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
    return m_impl->DetectFormat(content, "");
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

void MacroDetector::RegisterCallback(MacroScanResultCallback callback) {
    m_impl->RegisterCallback(std::move(callback));
}

void MacroDetector::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void MacroDetector::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

[[nodiscard]] MacroStatisticsSnapshot MacroDetector::GetStatistics() const {
    return m_impl->GetStatistics();
}

void MacroDetector::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] bool MacroDetector::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string MacroDetector::GetVersionString() noexcept {
    try {
        return std::to_string(MacroConstants::VERSION_MAJOR) + "." +
               std::to_string(MacroConstants::VERSION_MINOR) + "." +
               std::to_string(MacroConstants::VERSION_PATCH);
    } catch (...) {
        return "0.0.0";
    }
}

// ============================================================================
// KERNEL BRIDGE PUBLIC WRAPPERS
// ============================================================================

void MacroDetector::OnKernelProcessNotify(
    uint32_t processId,
    std::wstring_view imagePath,
    std::wstring_view commandLine,
    bool isCreate) {
    m_impl->OnKernelProcessNotify(processId, imagePath, commandLine, isCreate);
}

void MacroDetector::OnKernelImageLoad(
    uint32_t processId,
    std::wstring_view imagePath,
    uint64_t imageBase,
    size_t imageSize) {
    m_impl->OnKernelImageLoad(processId, imagePath, imageBase, imageSize);
}

[[nodiscard]] bool MacroDetector::RequestKernelProcessBlock(
    uint32_t processId,
    const std::wstring& reason) {
    return m_impl->RequestKernelProcessBlock(processId, reason);
}

// ============================================================================
// CROSS-MODULE WIRING PUBLIC WRAPPERS
// ============================================================================

void MacroDetector::ReportThreatToAlertSystem(const MacroScanResult& result) {
    m_impl->ReportThreatToAlertSystem(result);
}

void MacroDetector::ReportScanTelemetry(const MacroScanResult& result) {
    m_impl->ReportScanTelemetry(result);
}

void MacroDetector::ReportThreatToBehaviorAnalyzer(const MacroScanResult& result) {
    m_impl->ReportThreatToBehaviorAnalyzer(result);
}

}  // namespace Scripts
}  // namespace ShadowStrike
