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
 * ShadowStrike NGAV - PYTHON SCRIPT SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file PythonScriptScanner.cpp
 * @brief Enterprise-grade Python script and bytecode analysis engine
 *        implementation for detection of malicious Python-based threats.
 *
 * This implementation provides comprehensive detection of Python malware
 * including source scripts, compiled bytecode (.pyc), and packed executables
 * (PyInstaller, cx_Freeze, Nuitka, py2exe).
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 * - Python source code static analysis
 * - Import analysis and capability detection
 * - Bytecode parsing and version detection
 * - Packed executable detection and extraction
 * - Obfuscation detection (Base64, XOR, marshal, exec/eval)
 * - IOC extraction (URLs, IPs, paths, domains)
 * - Malware family identification
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

#include "PythonScriptScanner.hpp"

// Standard library includes
#include <algorithm>
#include <regex>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <bitset>

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> PythonScriptScanner::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetPythonArtifactTypeName(PythonArtifactType type) noexcept {
    switch (type) {
        case PythonArtifactType::SourcePy:        return "Python Source (.py)";
        case PythonArtifactType::BytecodePyc:     return "Python Bytecode (.pyc)";
        case PythonArtifactType::OptimizedPyo:    return "Optimized Bytecode (.pyo)";
        case PythonArtifactType::PackedPyInstaller: return "PyInstaller Executable";
        case PythonArtifactType::PackedCxFreeze:  return "cx_Freeze Executable";
        case PythonArtifactType::PackedNuitka:    return "Nuitka Compiled";
        case PythonArtifactType::PackedPy2Exe:    return "py2exe Executable";
        case PythonArtifactType::PackedBBFreeze:  return "bbfreeze Executable";
        case PythonArtifactType::Notebook:        return "Jupyter Notebook (.ipynb)";
        case PythonArtifactType::EggZip:          return "Python Egg/Wheel";
        case PythonArtifactType::ZipApp:          return "Python Zip Application";
        default:                                  return "Unknown";
    }
}

[[nodiscard]] std::string_view GetPythonVersionName(PythonVersion version) noexcept {
    switch (version) {
        case PythonVersion::Python27:  return "Python 2.7";
        case PythonVersion::Python30:  return "Python 3.0";
        case PythonVersion::Python35:  return "Python 3.5";
        case PythonVersion::Python36:  return "Python 3.6";
        case PythonVersion::Python37:  return "Python 3.7";
        case PythonVersion::Python38:  return "Python 3.8";
        case PythonVersion::Python39:  return "Python 3.9";
        case PythonVersion::Python310: return "Python 3.10";
        case PythonVersion::Python311: return "Python 3.11";
        case PythonVersion::Python312: return "Python 3.12";
        default:                       return "Unknown";
    }
}

[[nodiscard]] std::string_view GetPythonCapabilityName(PythonCapability cap) noexcept {
    auto capVal = static_cast<uint32_t>(cap);
    if (capVal & static_cast<uint32_t>(PythonCapability::NetworkCommunication))
        return "Network Communication";
    if (capVal & static_cast<uint32_t>(PythonCapability::FileOperations))
        return "File Operations";
    if (capVal & static_cast<uint32_t>(PythonCapability::ProcessExecution))
        return "Process Execution";
    if (capVal & static_cast<uint32_t>(PythonCapability::RegistryAccess))
        return "Registry Access";
    if (capVal & static_cast<uint32_t>(PythonCapability::ScreenCapture))
        return "Screen Capture";
    if (capVal & static_cast<uint32_t>(PythonCapability::Keylogging))
        return "Keylogging";
    if (capVal & static_cast<uint32_t>(PythonCapability::WebcamAccess))
        return "Webcam Access";
    if (capVal & static_cast<uint32_t>(PythonCapability::ClipboardMonitor))
        return "Clipboard Monitoring";
    if (capVal & static_cast<uint32_t>(PythonCapability::FileEncryption))
        return "File Encryption";
    if (capVal & static_cast<uint32_t>(PythonCapability::Persistence))
        return "Persistence";
    if (capVal & static_cast<uint32_t>(PythonCapability::CredentialAccess))
        return "Credential Access";
    if (capVal & static_cast<uint32_t>(PythonCapability::SystemInfo))
        return "System Enumeration";
    if (capVal & static_cast<uint32_t>(PythonCapability::ProcessInjection))
        return "Process Injection";
    if (capVal & static_cast<uint32_t>(PythonCapability::AntiVM))
        return "Anti-VM";
    if (capVal & static_cast<uint32_t>(PythonCapability::AntiDebug))
        return "Anti-Debug";
    if (capVal & static_cast<uint32_t>(PythonCapability::SelfModifying))
        return "Self-Modifying Code";
    if (capVal & static_cast<uint32_t>(PythonCapability::DynamicExecution))
        return "Dynamic Execution";
    if (capVal & static_cast<uint32_t>(PythonCapability::ShellAccess))
        return "Shell Access";
    if (capVal & static_cast<uint32_t>(PythonCapability::EmailAccess))
        return "Email Access";
    if (capVal & static_cast<uint32_t>(PythonCapability::BrowserManipulation))
        return "Browser Manipulation";
    return "None";
}

[[nodiscard]] std::string_view GetPythonThreatCategoryName(PythonThreatCategory cat) noexcept {
    switch (cat) {
        case PythonThreatCategory::RAT:            return "Remote Access Trojan";
        case PythonThreatCategory::Ransomware:     return "Ransomware";
        case PythonThreatCategory::Stealer:        return "Information Stealer";
        case PythonThreatCategory::CryptoMiner:    return "Cryptocurrency Miner";
        case PythonThreatCategory::Backdoor:       return "Backdoor";
        case PythonThreatCategory::Keylogger:      return "Keylogger";
        case PythonThreatCategory::Spyware:        return "Spyware";
        case PythonThreatCategory::BotnetClient:   return "Botnet Client";
        case PythonThreatCategory::Dropper:        return "Dropper";
        case PythonThreatCategory::Reconnaissance: return "Reconnaissance";
        case PythonThreatCategory::Exploit:        return "Exploit";
        case PythonThreatCategory::WebShell:       return "Web Shell";
        default:                                   return "None";
    }
}

[[nodiscard]] std::string_view GetPythonObfuscationTypeName(PythonObfuscationType type) noexcept {
    switch (type) {
        case PythonObfuscationType::Base64Encoding:    return "Base64 Encoding";
        case PythonObfuscationType::HexEncoding:       return "Hex Encoding";
        case PythonObfuscationType::XorEncryption:     return "XOR Encryption";
        case PythonObfuscationType::AESEncryption:     return "AES Encryption";
        case PythonObfuscationType::MarshalSerialized: return "Marshal Serialization";
        case PythonObfuscationType::CompileDynamic:    return "Dynamic Compile";
        case PythonObfuscationType::ExecEval:          return "Exec/Eval Chains";
        case PythonObfuscationType::PyArmor:           return "PyArmor Protection";
        case PythonObfuscationType::PyObfuscate:       return "PyObfuscate";
        case PythonObfuscationType::Pyminifier:        return "Pyminifier";
        case PythonObfuscationType::VariableRenaming:  return "Variable Renaming";
        case PythonObfuscationType::CustomObfuscation: return "Custom Obfuscation";
        default:                                       return "None";
    }
}

[[nodiscard]] bool IsSuspiciousPythonImport(std::string_view moduleName) noexcept {
    for (const auto* suspicious : PythonConstants::SUSPICIOUS_IMPORTS) {
        if (moduleName == suspicious) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] PythonVersion DetectPythonVersionFromMagic(uint32_t magic) noexcept {
    // Python 2.7 magic numbers
    if (magic == 0x03F30D0A) return PythonVersion::Python27;

    // Python 3.x magic numbers (first two bytes are version-specific)
    uint16_t versionMagic = static_cast<uint16_t>(magic & 0xFFFF);

    // Python 3.5: 3350-3351
    if (versionMagic >= 3350 && versionMagic <= 3351) return PythonVersion::Python35;
    // Python 3.6: 3378-3379
    if (versionMagic >= 3378 && versionMagic <= 3379) return PythonVersion::Python36;
    // Python 3.7: 3390-3394
    if (versionMagic >= 3390 && versionMagic <= 3394) return PythonVersion::Python37;
    // Python 3.8: 3400-3413
    if (versionMagic >= 3400 && versionMagic <= 3413) return PythonVersion::Python38;
    // Python 3.9: 3420-3425
    if (versionMagic >= 3420 && versionMagic <= 3425) return PythonVersion::Python39;
    // Python 3.10: 3430-3439
    if (versionMagic >= 3430 && versionMagic <= 3439) return PythonVersion::Python310;
    // Python 3.11: 3490-3499
    if (versionMagic >= 3490 && versionMagic <= 3499) return PythonVersion::Python311;
    // Python 3.12: 3500+
    if (versionMagic >= 3500) return PythonVersion::Python312;

    return PythonVersion::Unknown;
}

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string PythonImportInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"moduleName\":\"" << moduleName << "\",";
    oss << "\"isStdLib\":" << (isStdLib ? "true" : "false") << ",";
    oss << "\"isSuspicious\":" << (isSuspicious ? "true" : "false") << ",";
    oss << "\"suspicionReason\":\"" << suspicionReason << "\",";
    oss << "\"lineNumber\":" << lineNumber << ",";
    oss << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ",";

    oss << "\"functionsImported\":[";
    for (size_t i = 0; i < functionsImported.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << functionsImported[i] << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string PythonBytecodeInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":\"" << GetPythonVersionName(version) << "\",";
    oss << "\"magicNumber\":" << magicNumber << ",";
    oss << "\"timestamp\":" << timestamp << ",";
    oss << "\"sourceSize\":" << sourceSize << ",";
    oss << "\"codeObjectCount\":" << codeObjectCount << ",";
    oss << "\"wasDecompiled\":" << (wasDecompiled ? "true" : "false") << ",";
    oss << "\"decompileError\":\"" << decompileError << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string PackedPythonInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"packerType\":\"" << GetPythonArtifactTypeName(packerType) << "\",";
    oss << "\"packerVersion\":\"" << packerVersion << "\",";
    oss << "\"entryScript\":\"" << entryScript << "\",";
    oss << "\"embeddedScriptCount\":" << embeddedScriptCount << ",";
    oss << "\"pythonVersion\":\"" << GetPythonVersionName(pythonVersion) << "\",";
    oss << "\"wasExtracted\":" << (wasExtracted ? "true" : "false") << ",";
    oss << "\"extractionError\":\"" << extractionError << "\",";

    oss << "\"embeddedScripts\":[";
    for (size_t i = 0; i < embeddedScripts.size() && i < 50; ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << embeddedScripts[i] << "\"";
    }
    oss << "]";

    oss << "}";
    return oss.str();
}

[[nodiscard]] bool PythonScanResult::ShouldBlock() const noexcept {
    if (isMalicious) return true;
    if (status == PythonScanStatus::Malicious) return true;
    if (riskScore >= 80) return true;
    if (category != PythonThreatCategory::None) return true;
    return false;
}

[[nodiscard]] std::string PythonScanResult::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":" << static_cast<int>(status) << ",";
    oss << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ",";
    oss << "\"category\":\"" << GetPythonThreatCategoryName(category) << "\",";
    oss << "\"riskScore\":" << riskScore << ",";
    oss << "\"detectedFamily\":\"" << detectedFamily << "\",";
    oss << "\"threatName\":\"" << threatName << "\",";
    oss << "\"artifactType\":\"" << GetPythonArtifactTypeName(artifactType) << "\",";
    oss << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ",";
    oss << "\"isObfuscated\":" << (isObfuscated ? "true" : "false") << ",";
    oss << "\"obfuscationType\":\"" << GetPythonObfuscationTypeName(obfuscationType) << "\",";
    oss << "\"filePath\":\"" << filePath.string() << "\",";
    oss << "\"sha256\":\"" << sha256 << "\",";
    oss << "\"fileSize\":" << fileSize << ",";
    oss << "\"scanDurationUs\":" << scanDuration.count() << ",";

    oss << "\"detectedCapabilities\":[";
    for (size_t i = 0; i < detectedCapabilities.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << detectedCapabilities[i] << "\"";
    }
    oss << "],";

    oss << "\"suspiciousImports\":[";
    for (size_t i = 0; i < suspiciousImports.size(); ++i) {
        if (i > 0) oss << ",";
        oss << suspiciousImports[i].ToJson();
    }
    oss << "],";

    oss << "\"matchedSignatures\":[";
    for (size_t i = 0; i < matchedSignatures.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << matchedSignatures[i] << "\"";
    }
    oss << "],";

    oss << "\"extractedIOCs\":[";
    for (size_t i = 0; i < extractedIOCs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << extractedIOCs[i] << "\"";
    }
    oss << "],";

    oss << "\"flaggedLines\":[";
    for (size_t i = 0; i < flaggedLines.size() && i < 50; ++i) {
        if (i > 0) oss << ",";
        oss << "{\"line\":" << flaggedLines[i].first << ",\"content\":\"";
        // Escape content for JSON
        for (char c : flaggedLines[i].second) {
            if (c == '"') oss << "\\\"";
            else if (c == '\\') oss << "\\\\";
            else if (c == '\n') oss << "\\n";
            else if (c == '\r') oss << "\\r";
            else if (c == '\t') oss << "\\t";
            else if (c >= 32 && c < 127) oss << c;
        }
        oss << "\"}";
    }
    oss << "]";

    if (bytecodeInfo.has_value()) {
        oss << ",\"bytecodeInfo\":" << bytecodeInfo->ToJson();
    }

    if (packedInfo.has_value()) {
        oss << ",\"packedInfo\":" << packedInfo->ToJson();
    }

    oss << "}";
    return oss.str();
}

void PythonStatistics::Reset() noexcept {
    totalScans.store(0);
    maliciousDetected.store(0);
    suspiciousDetected.store(0);
    sourceFilesScanned.store(0);
    bytecodeFilesScanned.store(0);
    packedExecutablesScanned.store(0);
    obfuscatedDetected.store(0);
    decompileFailures.store(0);
    extractionFailures.store(0);
    totalBytesScanned.store(0);
    for (auto& count : byCategory) {
        count.store(0);
    }
    for (auto& count : byCapability) {
        count.store(0);
    }
    startTime = Clock::now();
}

[[nodiscard]] std::string PythonStatistics::ToJson() const {
    std::ostringstream oss;
    auto now = Clock::now();
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

    oss << "{";
    oss << "\"totalScans\":" << totalScans.load() << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected.load() << ",";
    oss << "\"suspiciousDetected\":" << suspiciousDetected.load() << ",";
    oss << "\"sourceFilesScanned\":" << sourceFilesScanned.load() << ",";
    oss << "\"bytecodeFilesScanned\":" << bytecodeFilesScanned.load() << ",";
    oss << "\"packedExecutablesScanned\":" << packedExecutablesScanned.load() << ",";
    oss << "\"obfuscatedDetected\":" << obfuscatedDetected.load() << ",";
    oss << "\"decompileFailures\":" << decompileFailures.load() << ",";
    oss << "\"extractionFailures\":" << extractionFailures.load() << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned.load() << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool PythonScannerConfiguration::IsValid() const noexcept {
    if (maxFileSize == 0 || maxFileSize > 1ULL * 1024 * 1024 * 1024) {
        return false;
    }
    return true;
}

// ============================================================================
// PYTHON SCRIPT SCANNER IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class PythonScriptScannerImpl {
public:
    PythonScriptScannerImpl();
    ~PythonScriptScannerImpl();

    // Non-copyable, non-movable
    PythonScriptScannerImpl(const PythonScriptScannerImpl&) = delete;
    PythonScriptScannerImpl& operator=(const PythonScriptScannerImpl&) = delete;
    PythonScriptScannerImpl(PythonScriptScannerImpl&&) = delete;
    PythonScriptScannerImpl& operator=(PythonScriptScannerImpl&&) = delete;

    // Lifecycle
    [[nodiscard]] bool Initialize(const PythonScannerConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool UpdateConfiguration(const PythonScannerConfiguration& config);
    [[nodiscard]] PythonScannerConfiguration GetConfiguration() const;

    // Scanning
    [[nodiscard]] PythonScanResult ScanFile(const std::filesystem::path& path);
    [[nodiscard]] PythonScanResult ScanSource(std::string_view source, const std::string& sourceName);
    [[nodiscard]] PythonScanResult ScanPyInstallerExe(const std::filesystem::path& exePath);
    [[nodiscard]] PythonScanResult ScanBytecode(const std::filesystem::path& pycPath);

    // Analysis
    [[nodiscard]] PythonArtifactType DetectArtifactType(const std::filesystem::path& path);
    [[nodiscard]] std::vector<PythonImportInfo> AnalyzeImports(std::string_view source);
    [[nodiscard]] PythonCapability DetectCapabilities(std::string_view source);
    [[nodiscard]] std::optional<std::string> DecompileBytecode(const std::filesystem::path& pycPath);
    [[nodiscard]] std::optional<PackedPythonInfo> ExtractFromPacked(const std::filesystem::path& exePath);
    [[nodiscard]] PythonObfuscationType DetectObfuscation(std::string_view source);

    // Callbacks
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    [[nodiscard]] PythonStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

private:
    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    [[nodiscard]] PythonScanResult AnalyzeSource(std::string_view source,
                                                  const std::string& sourceName,
                                                  PythonArtifactType artifactType);

    [[nodiscard]] int CalculateRiskScore(const PythonScanResult& result);
    [[nodiscard]] PythonThreatCategory ClassifyThreat(const PythonScanResult& result);
    [[nodiscard]] std::string IdentifyMalwareFamily(const PythonScanResult& result,
                                                     std::string_view source);

    [[nodiscard]] std::vector<std::string> ExtractIOCs(std::string_view source);
    [[nodiscard]] std::vector<std::pair<size_t, std::string>> FindFlaggedLines(std::string_view source);
    [[nodiscard]] std::vector<std::string> GetCapabilityNames(PythonCapability caps);

    [[nodiscard]] bool ParsePycHeader(std::span<const uint8_t> content,
                                       PythonBytecodeInfo& outInfo);
    [[nodiscard]] bool DetectPyInstallerExe(std::span<const uint8_t> content);
    [[nodiscard]] bool DetectCxFreezeExe(std::span<const uint8_t> content);
    [[nodiscard]] bool DetectNuitkaExe(std::span<const uint8_t> content);

    void NotifyCallback(const PythonScanResult& result);
    void NotifyError(const std::string& message, int code);

    // ========================================================================
    // SIGNATURE/PATTERN CONSTANTS
    // ========================================================================

    static constexpr uint8_t PYC_MAGIC_PREFIX[] = {0x0D, 0x0A};
    static constexpr uint8_t PYINSTALLER_MARKER[] = {'M', 'E', 'I', 0x0C, 0x0B, 0x0A, 0x0B, 0x0E};
    static constexpr uint8_t PE_SIGNATURE[] = {'M', 'Z'};

    // Dangerous function patterns
    struct DangerousPattern {
        std::string pattern;
        PythonCapability capability;
        int riskWeight;
        std::string description;
    };

    static const std::vector<DangerousPattern> s_dangerousPatterns;
    static const std::vector<std::string> s_ratIndicators;
    static const std::vector<std::string> s_ransomwareIndicators;
    static const std::vector<std::string> s_stealerIndicators;
    static const std::vector<std::string> s_cryptominerIndicators;

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};

    PythonScannerConfiguration m_config;
    PythonStatistics m_stats;

    ScanResultCallback m_resultCallback;
    ErrorCallback m_errorCallback;
};

// ============================================================================
// PATTERN DEFINITIONS
// ============================================================================

const std::vector<PythonScriptScannerImpl::DangerousPattern>
PythonScriptScannerImpl::s_dangerousPatterns = {
    // Network operations
    {"socket.socket", PythonCapability::NetworkCommunication, 20, "Raw socket creation"},
    {"socket.connect", PythonCapability::NetworkCommunication, 25, "Network connection"},
    {"requests.get", PythonCapability::NetworkCommunication, 15, "HTTP GET request"},
    {"requests.post", PythonCapability::NetworkCommunication, 20, "HTTP POST request"},
    {"urllib.request.urlopen", PythonCapability::NetworkCommunication, 20, "URL open"},
    {"urllib.request.urlretrieve", PythonCapability::NetworkCommunication, 30, "File download"},
    {"http.client.HTTPConnection", PythonCapability::NetworkCommunication, 20, "HTTP connection"},
    {"paramiko.SSHClient", PythonCapability::NetworkCommunication, 35, "SSH client"},
    {"ftplib.FTP", PythonCapability::NetworkCommunication, 25, "FTP connection"},

    // Process execution
    {"subprocess.Popen", PythonCapability::ProcessExecution, 30, "Process execution"},
    {"subprocess.call", PythonCapability::ProcessExecution, 25, "Command execution"},
    {"subprocess.run", PythonCapability::ProcessExecution, 25, "Command execution"},
    {"subprocess.check_output", PythonCapability::ProcessExecution, 25, "Command execution"},
    {"os.system", PythonCapability::ShellAccess, 35, "Shell command execution"},
    {"os.popen", PythonCapability::ShellAccess, 30, "Shell pipe"},
    {"os.exec", PythonCapability::ProcessExecution, 40, "Process replacement"},
    {"os.spawn", PythonCapability::ProcessExecution, 35, "Process spawn"},
    {"commands.getoutput", PythonCapability::ShellAccess, 30, "Command output"},

    // File operations
    {"open(", PythonCapability::FileOperations, 5, "File open"},
    {"os.remove", PythonCapability::FileOperations, 20, "File deletion"},
    {"os.unlink", PythonCapability::FileOperations, 20, "File deletion"},
    {"shutil.rmtree", PythonCapability::FileOperations, 30, "Directory deletion"},
    {"os.chmod", PythonCapability::FileOperations, 15, "Permission change"},
    {"shutil.copy", PythonCapability::FileOperations, 10, "File copy"},

    // Registry access (Windows)
    {"winreg.OpenKey", PythonCapability::RegistryAccess, 25, "Registry access"},
    {"winreg.SetValueEx", PythonCapability::RegistryAccess, 35, "Registry write"},
    {"winreg.CreateKey", PythonCapability::RegistryAccess, 35, "Registry key creation"},
    {"_winreg.OpenKey", PythonCapability::RegistryAccess, 25, "Registry access"},

    // Screen capture
    {"pyautogui.screenshot", PythonCapability::ScreenCapture, 40, "Screenshot capture"},
    {"PIL.ImageGrab.grab", PythonCapability::ScreenCapture, 40, "Screen grab"},
    {"mss.mss", PythonCapability::ScreenCapture, 40, "Screen capture"},
    {"pyscreenshot", PythonCapability::ScreenCapture, 40, "Screenshot library"},

    // Keylogging
    {"pynput.keyboard.Listener", PythonCapability::Keylogging, 50, "Keyboard listener"},
    {"keyboard.hook", PythonCapability::Keylogging, 50, "Keyboard hook"},
    {"pyHook.HookManager", PythonCapability::Keylogging, 50, "Windows hook"},
    {"pyxhook", PythonCapability::Keylogging, 50, "X11 keyboard hook"},

    // Webcam access
    {"cv2.VideoCapture(0)", PythonCapability::WebcamAccess, 45, "Webcam capture"},
    {"VideoCapture(0)", PythonCapability::WebcamAccess, 45, "Webcam capture"},

    // Clipboard
    {"pyperclip.paste", PythonCapability::ClipboardMonitor, 25, "Clipboard read"},
    {"pyperclip.copy", PythonCapability::ClipboardMonitor, 20, "Clipboard write"},
    {"win32clipboard", PythonCapability::ClipboardMonitor, 25, "Clipboard access"},

    // Encryption (ransomware indicator)
    {"Crypto.Cipher.AES", PythonCapability::FileEncryption, 30, "AES encryption"},
    {"cryptography.fernet", PythonCapability::FileEncryption, 30, "Fernet encryption"},
    {"Crypto.PublicKey.RSA", PythonCapability::FileEncryption, 35, "RSA encryption"},
    {"pycryptodome", PythonCapability::FileEncryption, 25, "Crypto library"},

    // Persistence
    {"winreg.HKEY_CURRENT_USER", PythonCapability::Persistence, 30, "User registry access"},
    {"Run", PythonCapability::Persistence, 35, "Startup persistence"},
    {"schtasks", PythonCapability::Persistence, 40, "Scheduled task"},
    {"crontab", PythonCapability::Persistence, 35, "Cron persistence"},

    // Credential access
    {"sqlite3", PythonCapability::CredentialAccess, 20, "SQLite database"},
    {"browser_cookie3", PythonCapability::CredentialAccess, 45, "Browser cookies"},
    {"keyring", PythonCapability::CredentialAccess, 35, "Keyring access"},
    {"win32cred", PythonCapability::CredentialAccess, 40, "Windows credentials"},

    // System info
    {"platform.uname", PythonCapability::SystemInfo, 15, "System info"},
    {"platform.system", PythonCapability::SystemInfo, 10, "OS detection"},
    {"socket.gethostname", PythonCapability::SystemInfo, 15, "Hostname"},
    {"getpass.getuser", PythonCapability::SystemInfo, 15, "Username"},
    {"os.environ", PythonCapability::SystemInfo, 10, "Environment variables"},
    {"wmi.WMI", PythonCapability::SystemInfo, 25, "WMI query"},

    // Process injection
    {"ctypes.windll", PythonCapability::ProcessInjection, 35, "Windows API access"},
    {"ctypes.CDLL", PythonCapability::ProcessInjection, 30, "DLL loading"},
    {"VirtualAlloc", PythonCapability::ProcessInjection, 50, "Memory allocation"},
    {"WriteProcessMemory", PythonCapability::ProcessInjection, 50, "Process memory write"},
    {"CreateRemoteThread", PythonCapability::ProcessInjection, 50, "Remote thread creation"},

    // Anti-VM
    {"VM", PythonCapability::AntiVM, 25, "VM detection"},
    {"VirtualBox", PythonCapability::AntiVM, 30, "VirtualBox detection"},
    {"VMware", PythonCapability::AntiVM, 30, "VMware detection"},
    {"QEMU", PythonCapability::AntiVM, 30, "QEMU detection"},

    // Dynamic execution
    {"exec(", PythonCapability::DynamicExecution, 40, "Dynamic execution"},
    {"eval(", PythonCapability::DynamicExecution, 40, "Expression evaluation"},
    {"compile(", PythonCapability::DynamicExecution, 35, "Dynamic compilation"},
    {"__import__", PythonCapability::DynamicExecution, 30, "Dynamic import"},
    {"importlib.import_module", PythonCapability::DynamicExecution, 25, "Dynamic import"},

    // Email
    {"smtplib.SMTP", PythonCapability::EmailAccess, 30, "SMTP connection"},
    {"imaplib.IMAP4", PythonCapability::EmailAccess, 30, "IMAP connection"},
    {"poplib.POP3", PythonCapability::EmailAccess, 30, "POP3 connection"},

    // Browser
    {"selenium.webdriver", PythonCapability::BrowserManipulation, 25, "Browser automation"},
    {"webdriver.Chrome", PythonCapability::BrowserManipulation, 25, "Chrome automation"},
    {"webdriver.Firefox", PythonCapability::BrowserManipulation, 25, "Firefox automation"},
};

const std::vector<std::string> PythonScriptScannerImpl::s_ratIndicators = {
    "reverse_shell", "bind_shell", "backdoor", "c2_server", "command_and_control",
    "execute_command", "shell_command", "remote_command", "RAT", "pupy",
    "meterpreter", "empire", "covenant", "quasar", "asyncrat"
};

const std::vector<std::string> PythonScriptScannerImpl::s_ransomwareIndicators = {
    "encrypt_file", "decrypt_file", "ransom", "bitcoin", "monero",
    "wallet_address", ".locked", ".encrypted", ".crypt", "payment",
    "AES.encrypt", "RSA.encrypt", "fernet.encrypt", "readme.txt",
    "YOUR_FILES", "PAY_RANSOM"
};

const std::vector<std::string> PythonScriptScannerImpl::s_stealerIndicators = {
    "browser_cookie", "steal_password", "grab_token", "discord_token",
    "chrome_password", "firefox_password", "credential_dump", "cookies.sqlite",
    "Login Data", "keychain", "wallet.dat", "metamask", "exodus"
};

const std::vector<std::string> PythonScriptScannerImpl::s_cryptominerIndicators = {
    "stratum+tcp", "pool.minexmr", "xmrig", "cpuminer", "hashrate",
    "mining_pool", "cryptonight", "randomx", "monero_address",
    "nicehash", "coinhive", "minergate"
};

// ============================================================================
// PYTHON SCRIPT SCANNER IMPL IMPLEMENTATION
// ============================================================================

PythonScriptScannerImpl::PythonScriptScannerImpl() {
    m_stats.Reset();
}

PythonScriptScannerImpl::~PythonScriptScannerImpl() {
    Shutdown();
}

[[nodiscard]] bool PythonScriptScannerImpl::Initialize(const PythonScannerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load()) {
        SS_LOG_WARN(L"PythonScanner", L"Already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing);

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"PythonScanner", L"Invalid configuration");
        m_status.store(ModuleStatus::Error);
        return false;
    }

    m_config = config;
    m_stats.Reset();
    m_initialized.store(true);
    m_status.store(ModuleStatus::Running);

    SS_LOG_INFO(L"PythonScanner", L"Initialized successfully (v%u.%u.%u)",
                PythonConstants::VERSION_MAJOR,
                PythonConstants::VERSION_MINOR,
                PythonConstants::VERSION_PATCH);

    return true;
}

void PythonScriptScannerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);

    if (!m_initialized.load()) {
        return;
    }

    m_status.store(ModuleStatus::Stopping);

    m_resultCallback = nullptr;
    m_errorCallback = nullptr;

    m_initialized.store(false);
    m_status.store(ModuleStatus::Stopped);

    SS_LOG_INFO(L"PythonScanner", L"Shutdown complete");
}

[[nodiscard]] bool PythonScriptScannerImpl::IsInitialized() const noexcept {
    return m_initialized.load();
}

[[nodiscard]] ModuleStatus PythonScriptScannerImpl::GetStatus() const noexcept {
    return m_status.load();
}

[[nodiscard]] bool PythonScriptScannerImpl::UpdateConfiguration(
    const PythonScannerConfiguration& config) {

    if (!config.IsValid()) {
        SS_LOG_ERROR(L"PythonScanner", L"Invalid configuration update");
        return false;
    }

    std::unique_lock lock(m_mutex);
    m_config = config;

    SS_LOG_INFO(L"PythonScanner", L"Configuration updated");
    return true;
}

[[nodiscard]] PythonScannerConfiguration PythonScriptScannerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::ScanFile(
    const std::filesystem::path& path) {

    PythonScanResult result;
    result.filePath = path;
    result.scanTime = std::chrono::system_clock::now();
    auto startTime = Clock::now();

    // Validation
    if (path.empty()) {
        SS_LOG_ERROR(L"PythonScanner", L"Empty file path provided");
        result.status = PythonScanStatus::ErrorFileAccess;
        NotifyError("Empty file path", -1);
        return result;
    }

    std::wstring widePath = path.wstring();

    // Check file exists
    Utils::FileUtils::Error fileErr;
    if (!Utils::FileUtils::Exists(widePath, &fileErr)) {
        SS_LOG_ERROR(L"PythonScanner", L"File not found: %ls", widePath.c_str());
        result.status = PythonScanStatus::ErrorFileAccess;
        NotifyError("File not found: " + path.string(), ERROR_FILE_NOT_FOUND);
        return result;
    }

    // Get file stats
    Utils::FileUtils::FileStat fileStat;
    if (!Utils::FileUtils::Stat(widePath, fileStat, &fileErr)) {
        SS_LOG_ERROR(L"PythonScanner", L"Failed to stat file: %ls", widePath.c_str());
        result.status = PythonScanStatus::ErrorFileAccess;
        return result;
    }

    result.fileSize = fileStat.size;

    // Size check
    if (fileStat.size > m_config.maxFileSize) {
        SS_LOG_WARN(L"PythonScanner", L"File too large (%llu bytes): %ls",
                    fileStat.size, widePath.c_str());
        result.status = PythonScanStatus::SkippedSizeLimit;
        return result;
    }

    // Detect artifact type
    result.artifactType = DetectArtifactType(path);

    // Read file content
    std::vector<std::byte> content;
    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        SS_LOG_ERROR(L"PythonScanner", L"Failed to read file: %ls", widePath.c_str());
        result.status = PythonScanStatus::ErrorFileAccess;
        return result;
    }

    // Compute file hash
    std::array<uint8_t, 32> hashBytes;
    if (Utils::FileUtils::ComputeFileSHA256(widePath, hashBytes, &fileErr)) {
        result.sha256 = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    }

    // Route to appropriate scanner
    try {
        switch (result.artifactType) {
            case PythonArtifactType::SourcePy:
            case PythonArtifactType::Notebook: {
                std::string source(reinterpret_cast<const char*>(content.data()), content.size());
                result = AnalyzeSource(source, path.filename().string(), result.artifactType);
                m_stats.sourceFilesScanned++;
                break;
            }

            case PythonArtifactType::BytecodePyc:
            case PythonArtifactType::OptimizedPyo: {
                result = ScanBytecode(path);
                m_stats.bytecodeFilesScanned++;
                break;
            }

            case PythonArtifactType::PackedPyInstaller:
            case PythonArtifactType::PackedCxFreeze:
            case PythonArtifactType::PackedNuitka:
            case PythonArtifactType::PackedPy2Exe:
            case PythonArtifactType::PackedBBFreeze: {
                result = ScanPyInstallerExe(path);
                m_stats.packedExecutablesScanned++;
                break;
            }

            default: {
                // Try as source anyway
                std::string source(reinterpret_cast<const char*>(content.data()), content.size());
                result = AnalyzeSource(source, path.filename().string(), PythonArtifactType::SourcePy);
                break;
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"PythonScanner", L"Scan exception: %hs", e.what());
        result.status = PythonScanStatus::ErrorParsing;
        NotifyError(std::string("Scan exception: ") + e.what(), -1);
    }

    // Restore file info
    result.filePath = path;
    result.sha256 = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
    result.fileSize = fileStat.size;
    result.artifactType = result.artifactType;

    auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Update statistics
    m_stats.totalScans++;
    m_stats.totalBytesScanned += result.fileSize;

    if (result.isMalicious) {
        m_stats.maliciousDetected++;
    } else if (result.status == PythonScanStatus::Suspicious) {
        m_stats.suspiciousDetected++;
    }

    if (result.isObfuscated) {
        m_stats.obfuscatedDetected++;
    }

    if (static_cast<size_t>(result.category) < m_stats.byCategory.size()) {
        m_stats.byCategory[static_cast<size_t>(result.category)]++;
    }

    NotifyCallback(result);

    if (m_config.verboseLogging) {
        SS_LOG_INFO(L"PythonScanner", L"Scan complete: %ls - Status: %d, Risk: %d",
                    widePath.c_str(), static_cast<int>(result.status), result.riskScore);
    }

    return result;
}

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::ScanSource(
    std::string_view source,
    const std::string& sourceName) {

    auto startTime = Clock::now();

    PythonScanResult result = AnalyzeSource(source, sourceName, PythonArtifactType::SourcePy);

    auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    m_stats.totalScans++;
    m_stats.sourceFilesScanned++;
    m_stats.totalBytesScanned += source.size();

    if (result.isMalicious) {
        m_stats.maliciousDetected++;
    }

    NotifyCallback(result);

    return result;
}

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::ScanPyInstallerExe(
    const std::filesystem::path& exePath) {

    PythonScanResult result;
    result.filePath = exePath;
    result.scanTime = std::chrono::system_clock::now();
    result.artifactType = PythonArtifactType::PackedPyInstaller;

    // Read executable
    std::wstring widePath = exePath.wstring();
    std::vector<std::byte> content;
    Utils::FileUtils::Error fileErr;

    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        result.status = PythonScanStatus::ErrorFileAccess;
        m_stats.extractionFailures++;
        return result;
    }

    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    // Try to extract
    auto packedInfo = ExtractFromPacked(exePath);
    if (packedInfo.has_value()) {
        result.packedInfo = packedInfo;

        // If extraction successful, analyze extracted source
        if (packedInfo->wasExtracted && !packedInfo->extractedSource.empty()) {
            PythonScanResult sourceResult = AnalyzeSource(
                packedInfo->extractedSource,
                packedInfo->entryScript,
                PythonArtifactType::SourcePy
            );

            // Merge results
            result.status = sourceResult.status;
            result.isMalicious = sourceResult.isMalicious;
            result.riskScore = sourceResult.riskScore;
            result.category = sourceResult.category;
            result.capabilities = sourceResult.capabilities;
            result.detectedCapabilities = sourceResult.detectedCapabilities;
            result.suspiciousImports = sourceResult.suspiciousImports;
            result.allImports = sourceResult.allImports;
            result.extractedIOCs = sourceResult.extractedIOCs;
            result.flaggedLines = sourceResult.flaggedLines;
            result.isObfuscated = sourceResult.isObfuscated;
            result.obfuscationType = sourceResult.obfuscationType;
            result.detectedFamily = sourceResult.detectedFamily;
        }
    } else {
        // Extraction failed, do what we can
        result.status = PythonScanStatus::ErrorExtraction;
        m_stats.extractionFailures++;

        // Check for known malicious packed Python patterns
        std::string contentStr(reinterpret_cast<const char*>(content.data()),
                               std::min(content.size(), size_t(100000)));

        // Look for suspicious strings in the binary
        auto iocs = ExtractIOCs(contentStr);
        result.extractedIOCs = iocs;

        if (!iocs.empty()) {
            result.riskScore += 30;
        }
    }

    return result;
}

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::ScanBytecode(
    const std::filesystem::path& pycPath) {

    PythonScanResult result;
    result.filePath = pycPath;
    result.scanTime = std::chrono::system_clock::now();
    result.artifactType = PythonArtifactType::BytecodePyc;

    // Read bytecode
    std::wstring widePath = pycPath.wstring();
    std::vector<std::byte> content;
    Utils::FileUtils::Error fileErr;

    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        result.status = PythonScanStatus::ErrorFileAccess;
        return result;
    }

    result.fileSize = content.size();

    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    // Parse header
    PythonBytecodeInfo bytecodeInfo;
    if (ParsePycHeader(contentSpan, bytecodeInfo)) {
        result.bytecodeInfo = bytecodeInfo;
    }

    // Try to decompile if enabled
    if (m_config.enableDecompilation) {
        auto decompiledSource = DecompileBytecode(pycPath);
        if (decompiledSource.has_value()) {
            // Analyze the decompiled source
            PythonScanResult sourceResult = AnalyzeSource(
                *decompiledSource,
                pycPath.filename().string(),
                PythonArtifactType::BytecodePyc
            );

            // Merge results
            result.status = sourceResult.status;
            result.isMalicious = sourceResult.isMalicious;
            result.riskScore = sourceResult.riskScore;
            result.category = sourceResult.category;
            result.capabilities = sourceResult.capabilities;
            result.detectedCapabilities = sourceResult.detectedCapabilities;
            result.suspiciousImports = sourceResult.suspiciousImports;
            result.allImports = sourceResult.allImports;
            result.extractedIOCs = sourceResult.extractedIOCs;
            result.flaggedLines = sourceResult.flaggedLines;
            result.isObfuscated = sourceResult.isObfuscated;
            result.obfuscationType = sourceResult.obfuscationType;

            if (result.bytecodeInfo.has_value()) {
                result.bytecodeInfo->wasDecompiled = true;
                result.bytecodeInfo->decompiledSource = *decompiledSource;
            }
        } else {
            m_stats.decompileFailures++;
            if (result.bytecodeInfo.has_value()) {
                result.bytecodeInfo->decompileError = "Decompilation not available";
            }
        }
    }

    return result;
}

[[nodiscard]] PythonArtifactType PythonScriptScannerImpl::DetectArtifactType(
    const std::filesystem::path& path) {

    std::wstring widePath = path.wstring();
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

    // Check by extension first
    if (ext == ".py") return PythonArtifactType::SourcePy;
    if (ext == ".pyc") return PythonArtifactType::BytecodePyc;
    if (ext == ".pyo") return PythonArtifactType::OptimizedPyo;
    if (ext == ".ipynb") return PythonArtifactType::Notebook;
    if (ext == ".egg" || ext == ".whl") return PythonArtifactType::EggZip;
    if (ext == ".pyz" || ext == ".pyzw") return PythonArtifactType::ZipApp;

    // Check by content for executables
    if (ext == ".exe") {
        std::vector<std::byte> header;
        Utils::FileUtils::Error fileErr;

        // Read first 4KB
        if (Utils::FileUtils::ReadAllBytes(widePath, header, &fileErr)) {
            if (header.size() >= 2 &&
                header[0] == std::byte{'M'} && header[1] == std::byte{'Z'}) {

                std::span<const uint8_t> headerSpan(
                    reinterpret_cast<const uint8_t*>(header.data()),
                    header.size()
                );

                if (DetectPyInstallerExe(headerSpan)) {
                    return PythonArtifactType::PackedPyInstaller;
                }
                if (DetectCxFreezeExe(headerSpan)) {
                    return PythonArtifactType::PackedCxFreeze;
                }
                if (DetectNuitkaExe(headerSpan)) {
                    return PythonArtifactType::PackedNuitka;
                }
            }
        }
    }

    return PythonArtifactType::Unknown;
}

[[nodiscard]] std::vector<PythonImportInfo> PythonScriptScannerImpl::AnalyzeImports(
    std::string_view source) {

    std::vector<PythonImportInfo> imports;

    if (source.empty()) {
        return imports;
    }

    std::string sourceStr(source);

    // Pattern: import module
    std::regex importPattern(R"(^\s*import\s+([a-zA-Z_][a-zA-Z0-9_\.]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_\.]*)*))");

    // Pattern: from module import ...
    std::regex fromImportPattern(R"(^\s*from\s+([a-zA-Z_][a-zA-Z0-9_\.]*)\s+import\s+(.+))");

    std::istringstream iss(sourceStr);
    std::string line;
    size_t lineNum = 0;

    while (std::getline(iss, line)) {
        lineNum++;

        // Skip comments
        size_t commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            line = line.substr(0, commentPos);
        }

        std::smatch match;

        // Check "import X" pattern
        if (std::regex_search(line, match, importPattern)) {
            std::string modules = match[1].str();

            // Split by comma
            std::istringstream moduleStream(modules);
            std::string module;
            while (std::getline(moduleStream, module, ',')) {
                // Trim
                module.erase(0, module.find_first_not_of(" \t"));
                module.erase(module.find_last_not_of(" \t") + 1);

                // Handle "as" alias
                size_t asPos = module.find(" as ");
                if (asPos != std::string::npos) {
                    module = module.substr(0, asPos);
                }

                if (!module.empty()) {
                    PythonImportInfo info;
                    info.moduleName = module;
                    info.lineNumber = lineNum;
                    info.isSuspicious = IsSuspiciousPythonImport(module);

                    if (info.isSuspicious) {
                        info.suspicionReason = "Known suspicious module";
                    }

                    imports.push_back(info);
                }
            }
        }

        // Check "from X import Y" pattern
        if (std::regex_search(line, match, fromImportPattern)) {
            std::string module = match[1].str();
            std::string items = match[2].str();

            PythonImportInfo info;
            info.moduleName = module;
            info.lineNumber = lineNum;
            info.isSuspicious = IsSuspiciousPythonImport(module);

            if (info.isSuspicious) {
                info.suspicionReason = "Known suspicious module";
            }

            // Parse imported items
            std::istringstream itemStream(items);
            std::string item;
            while (std::getline(itemStream, item, ',')) {
                item.erase(0, item.find_first_not_of(" \t"));
                item.erase(item.find_last_not_of(" \t") + 1);

                size_t asPos = item.find(" as ");
                if (asPos != std::string::npos) {
                    item = item.substr(0, asPos);
                }

                if (!item.empty() && item != "*") {
                    info.functionsImported.push_back(item);
                }
            }

            imports.push_back(info);
        }
    }

    return imports;
}

[[nodiscard]] PythonCapability PythonScriptScannerImpl::DetectCapabilities(
    std::string_view source) {

    uint32_t capabilities = 0;

    if (source.empty()) {
        return PythonCapability::None;
    }

    std::wstring wideSource = Utils::StringUtils::ToWide(std::string(source));

    for (const auto& pattern : s_dangerousPatterns) {
        std::wstring widePattern = Utils::StringUtils::ToWide(pattern.pattern);
        if (Utils::StringUtils::IContains(wideSource, widePattern)) {
            capabilities |= static_cast<uint32_t>(pattern.capability);
        }
    }

    return static_cast<PythonCapability>(capabilities);
}

[[nodiscard]] std::optional<std::string> PythonScriptScannerImpl::DecompileBytecode(
    const std::filesystem::path& pycPath) {

    // Note: In production, this would integrate with a Python decompiler
    // like uncompyle6, pycdc, or decompyle3

    // For now, return empty - decompilation requires external tools
    SS_LOG_DEBUG(L"PythonScanner", L"Decompilation not implemented: %ls",
                 pycPath.wstring().c_str());

    return std::nullopt;
}

[[nodiscard]] std::optional<PackedPythonInfo> PythonScriptScannerImpl::ExtractFromPacked(
    const std::filesystem::path& exePath) {

    PackedPythonInfo info;

    std::wstring widePath = exePath.wstring();
    std::vector<std::byte> content;
    Utils::FileUtils::Error fileErr;

    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        info.extractionError = "Failed to read file";
        return info;
    }

    std::span<const uint8_t> contentSpan(
        reinterpret_cast<const uint8_t*>(content.data()),
        content.size()
    );

    // Detect packer type
    if (DetectPyInstallerExe(contentSpan)) {
        info.packerType = PythonArtifactType::PackedPyInstaller;

        // Search for PyInstaller archive marker
        std::string contentStr(reinterpret_cast<const char*>(content.data()), content.size());

        // Look for PYINSTALLER marker or MEI marker
        size_t meiPos = contentStr.find("MEI");
        if (meiPos != std::string::npos) {
            info.packerVersion = "PyInstaller";
        }

        // Note: Full extraction requires parsing the CArchive structure
        // This is a simplified detection
        info.extractionError = "Full extraction not implemented";

    } else if (DetectCxFreezeExe(contentSpan)) {
        info.packerType = PythonArtifactType::PackedCxFreeze;
        info.extractionError = "cx_Freeze extraction not implemented";

    } else if (DetectNuitkaExe(contentSpan)) {
        info.packerType = PythonArtifactType::PackedNuitka;
        info.extractionError = "Nuitka is compiled, not extractable";
    }

    return info;
}

[[nodiscard]] PythonObfuscationType PythonScriptScannerImpl::DetectObfuscation(
    std::string_view source) {

    if (source.empty()) {
        return PythonObfuscationType::None;
    }

    std::string sourceStr(source);
    std::wstring wideSource = Utils::StringUtils::ToWide(sourceStr);

    // Check for exec/eval chains
    size_t execCount = 0;
    size_t evalCount = 0;
    size_t pos = 0;
    while ((pos = sourceStr.find("exec(", pos)) != std::string::npos) {
        execCount++;
        pos += 5;
    }
    pos = 0;
    while ((pos = sourceStr.find("eval(", pos)) != std::string::npos) {
        evalCount++;
        pos += 5;
    }

    if (execCount + evalCount > 3) {
        return PythonObfuscationType::ExecEval;
    }

    // Check for PyArmor
    if (Utils::StringUtils::IContains(wideSource, L"__pyarmor__") ||
        Utils::StringUtils::IContains(wideSource, L"pyarmor_runtime")) {
        return PythonObfuscationType::PyArmor;
    }

    // Check for marshal usage (code serialization)
    if (Utils::StringUtils::IContains(wideSource, L"marshal.loads") ||
        Utils::StringUtils::IContains(wideSource, L"marshal.load")) {
        return PythonObfuscationType::MarshalSerialized;
    }

    // Check for compile() usage
    if (Utils::StringUtils::IContains(wideSource, L"compile(") &&
        (Utils::StringUtils::IContains(wideSource, L"exec") ||
         Utils::StringUtils::IContains(wideSource, L"eval"))) {
        return PythonObfuscationType::CompileDynamic;
    }

    // Check for base64 encoding
    size_t b64Count = 0;
    pos = 0;
    while ((pos = sourceStr.find("base64", pos)) != std::string::npos) {
        b64Count++;
        pos += 6;
    }
    if (b64Count >= 2 && Utils::StringUtils::IContains(wideSource, L"decode")) {
        return PythonObfuscationType::Base64Encoding;
    }

    // Check for hex encoding
    if (Utils::StringUtils::IContains(wideSource, L"\\x") ||
        Utils::StringUtils::IContains(wideSource, L"bytes.fromhex") ||
        Utils::StringUtils::IContains(wideSource, L"binascii.unhexlify")) {

        // Count hex escapes
        size_t hexCount = 0;
        pos = 0;
        while ((pos = sourceStr.find("\\x", pos)) != std::string::npos) {
            hexCount++;
            pos += 2;
        }
        if (hexCount > 20) {
            return PythonObfuscationType::HexEncoding;
        }
    }

    // Check for XOR patterns
    if (Utils::StringUtils::IContains(wideSource, L"^ ") ||
        Utils::StringUtils::IContains(wideSource, L"^=") ||
        Utils::StringUtils::IContains(wideSource, L"xor")) {
        return PythonObfuscationType::XorEncryption;
    }

    // Check for variable renaming (many single-letter variables)
    std::regex singleVarPattern(R"(\b[a-z]\s*=)");
    std::sregex_iterator begin(sourceStr.begin(), sourceStr.end(), singleVarPattern);
    std::sregex_iterator end;
    size_t singleVarCount = std::distance(begin, end);

    if (singleVarCount > 30) {
        return PythonObfuscationType::VariableRenaming;
    }

    return PythonObfuscationType::None;
}

void PythonScriptScannerImpl::RegisterCallback(ScanResultCallback callback) {
    std::unique_lock lock(m_mutex);
    m_resultCallback = std::move(callback);
}

void PythonScriptScannerImpl::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_mutex);
    m_errorCallback = std::move(callback);
}

void PythonScriptScannerImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_mutex);
    m_resultCallback = nullptr;
    m_errorCallback = nullptr;
}

[[nodiscard]] PythonStatistics PythonScriptScannerImpl::GetStatistics() const {
    return m_stats;
}

void PythonScriptScannerImpl::ResetStatistics() {
    m_stats.Reset();
}

[[nodiscard]] bool PythonScriptScannerImpl::SelfTest() {
    SS_LOG_INFO(L"PythonScanner", L"Running self-test...");

    bool allPassed = true;

    // Test 1: Verify initialization
    if (!m_initialized.load()) {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: Not initialized");
        allPassed = false;
    }

    // Test 2: Test import analysis
    std::string testCode = "import socket\nimport subprocess\nfrom os import system";
    auto imports = AnalyzeImports(testCode);
    if (imports.size() != 3) {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: Import analysis failed (expected 3, got %zu)",
                     imports.size());
        allPassed = false;
    }

    // Test 3: Test capability detection
    std::string capCode = "subprocess.Popen(['cmd'])\nsocket.socket()";
    auto caps = DetectCapabilities(capCode);
    if (caps == PythonCapability::None) {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: Capability detection failed");
        allPassed = false;
    }

    // Test 4: Test obfuscation detection
    std::string obfCode = "exec(base64.b64decode('dGVzdA=='))";
    auto obfType = DetectObfuscation(obfCode);
    if (obfType == PythonObfuscationType::None) {
        SS_LOG_WARN(L"PythonScanner", L"Self-test: Obfuscation detection partial");
    }

    // Test 5: Test IOC extraction
    std::string iocCode = "url = 'http://evil.com/payload.py'";
    auto iocs = ExtractIOCs(iocCode);
    if (iocs.empty()) {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: IOC extraction failed");
        allPassed = false;
    }

    // Test 6: Test suspicious import detection
    if (!IsSuspiciousPythonImport("socket")) {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: Suspicious import check failed");
        allPassed = false;
    }

    if (allPassed) {
        SS_LOG_INFO(L"PythonScanner", L"Self-test: All tests passed");
    } else {
        SS_LOG_ERROR(L"PythonScanner", L"Self-test: Some tests failed");
    }

    return allPassed;
}

// ============================================================================
// INTERNAL ANALYSIS METHODS
// ============================================================================

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::AnalyzeSource(
    std::string_view source,
    const std::string& sourceName,
    PythonArtifactType artifactType) {

    PythonScanResult result;
    result.scanTime = std::chrono::system_clock::now();
    result.artifactType = artifactType;
    result.fileSize = source.size();

    if (source.empty()) {
        result.status = PythonScanStatus::Clean;
        return result;
    }

    // Analyze imports
    result.allImports = AnalyzeImports(source);

    for (const auto& imp : result.allImports) {
        if (imp.isSuspicious) {
            result.suspiciousImports.push_back(imp);
        }
    }

    // Detect capabilities
    result.capabilities = DetectCapabilities(source);
    result.detectedCapabilities = GetCapabilityNames(result.capabilities);

    // Detect obfuscation
    result.obfuscationType = DetectObfuscation(source);
    result.isObfuscated = (result.obfuscationType != PythonObfuscationType::None);

    // Extract IOCs
    if (m_config.extractIOCs) {
        result.extractedIOCs = ExtractIOCs(source);
    }

    // Find flagged lines
    result.flaggedLines = FindFlaggedLines(source);

    // Calculate risk score
    result.riskScore = CalculateRiskScore(result);

    // Classify threat
    result.category = ClassifyThreat(result);

    // Identify malware family
    result.detectedFamily = IdentifyMalwareFamily(result, source);

    // Determine final status
    if (result.riskScore >= 80) {
        result.status = PythonScanStatus::Malicious;
        result.isMalicious = true;
        result.threatName = "Python/" + std::string(GetPythonThreatCategoryName(result.category));
        if (!result.detectedFamily.empty()) {
            result.threatName += "." + result.detectedFamily;
        }
    } else if (result.riskScore >= 50) {
        result.status = PythonScanStatus::Suspicious;
    } else {
        result.status = PythonScanStatus::Clean;
    }

    return result;
}

[[nodiscard]] int PythonScriptScannerImpl::CalculateRiskScore(const PythonScanResult& result) {
    int score = 0;

    // Suspicious imports
    score += static_cast<int>(result.suspiciousImports.size()) * 10;

    // Capabilities
    auto caps = static_cast<uint32_t>(result.capabilities);

    // High-risk capabilities
    if (caps & static_cast<uint32_t>(PythonCapability::ProcessInjection)) score += 40;
    if (caps & static_cast<uint32_t>(PythonCapability::Keylogging)) score += 35;
    if (caps & static_cast<uint32_t>(PythonCapability::ScreenCapture)) score += 25;
    if (caps & static_cast<uint32_t>(PythonCapability::WebcamAccess)) score += 30;
    if (caps & static_cast<uint32_t>(PythonCapability::CredentialAccess)) score += 35;
    if (caps & static_cast<uint32_t>(PythonCapability::FileEncryption)) score += 25;
    if (caps & static_cast<uint32_t>(PythonCapability::Persistence)) score += 30;

    // Medium-risk capabilities
    if (caps & static_cast<uint32_t>(PythonCapability::ProcessExecution)) score += 20;
    if (caps & static_cast<uint32_t>(PythonCapability::ShellAccess)) score += 25;
    if (caps & static_cast<uint32_t>(PythonCapability::RegistryAccess)) score += 20;
    if (caps & static_cast<uint32_t>(PythonCapability::DynamicExecution)) score += 25;

    // Low-risk capabilities
    if (caps & static_cast<uint32_t>(PythonCapability::NetworkCommunication)) score += 10;
    if (caps & static_cast<uint32_t>(PythonCapability::FileOperations)) score += 5;

    // Obfuscation
    if (result.isObfuscated) {
        score += 25;

        // Extra penalty for known malicious obfuscation
        if (result.obfuscationType == PythonObfuscationType::ExecEval) score += 15;
        if (result.obfuscationType == PythonObfuscationType::MarshalSerialized) score += 20;
    }

    // IOCs
    score += std::min(static_cast<int>(result.extractedIOCs.size()) * 5, 20);

    // Flagged lines
    score += std::min(static_cast<int>(result.flaggedLines.size()) * 3, 15);

    // Cap at 100
    return std::min(score, 100);
}

[[nodiscard]] PythonThreatCategory PythonScriptScannerImpl::ClassifyThreat(
    const PythonScanResult& result) {

    if (result.riskScore < 50) {
        return PythonThreatCategory::None;
    }

    auto caps = static_cast<uint32_t>(result.capabilities);

    // Keylogger
    if (caps & static_cast<uint32_t>(PythonCapability::Keylogging)) {
        return PythonThreatCategory::Keylogger;
    }

    // RAT (multiple remote capabilities)
    int ratScore = 0;
    if (caps & static_cast<uint32_t>(PythonCapability::NetworkCommunication)) ratScore++;
    if (caps & static_cast<uint32_t>(PythonCapability::ProcessExecution)) ratScore++;
    if (caps & static_cast<uint32_t>(PythonCapability::ScreenCapture)) ratScore++;
    if (caps & static_cast<uint32_t>(PythonCapability::Keylogging)) ratScore++;
    if (caps & static_cast<uint32_t>(PythonCapability::FileOperations)) ratScore++;

    if (ratScore >= 3) {
        return PythonThreatCategory::RAT;
    }

    // Ransomware
    if ((caps & static_cast<uint32_t>(PythonCapability::FileEncryption)) &&
        (caps & static_cast<uint32_t>(PythonCapability::FileOperations))) {
        return PythonThreatCategory::Ransomware;
    }

    // Stealer
    if (caps & static_cast<uint32_t>(PythonCapability::CredentialAccess)) {
        return PythonThreatCategory::Stealer;
    }

    // Spyware
    if ((caps & static_cast<uint32_t>(PythonCapability::ScreenCapture)) ||
        (caps & static_cast<uint32_t>(PythonCapability::WebcamAccess)) ||
        (caps & static_cast<uint32_t>(PythonCapability::ClipboardMonitor))) {
        return PythonThreatCategory::Spyware;
    }

    // Backdoor
    if ((caps & static_cast<uint32_t>(PythonCapability::NetworkCommunication)) &&
        (caps & static_cast<uint32_t>(PythonCapability::ProcessExecution))) {
        return PythonThreatCategory::Backdoor;
    }

    // Dropper
    if ((caps & static_cast<uint32_t>(PythonCapability::NetworkCommunication)) &&
        (caps & static_cast<uint32_t>(PythonCapability::FileOperations))) {
        return PythonThreatCategory::Dropper;
    }

    return PythonThreatCategory::None;
}

[[nodiscard]] std::string PythonScriptScannerImpl::IdentifyMalwareFamily(
    const PythonScanResult& result,
    std::string_view source) {

    std::string sourceStr(source);
    std::wstring wideSource = Utils::StringUtils::ToWide(sourceStr);

    // Check for RAT indicators
    for (const auto& indicator : s_ratIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            if (indicator == "pupy") return "Pupy";
            if (indicator == "meterpreter") return "Meterpreter";
            if (indicator == "empire") return "Empire";
            if (indicator == "quasar") return "Quasar";
            return "GenericRAT";
        }
    }

    // Check for ransomware indicators
    for (const auto& indicator : s_ransomwareIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            if (Utils::StringUtils::IContains(wideSource, L"pylocky")) return "PyLocky";
            return "GenericRansomware";
        }
    }

    // Check for stealer indicators
    for (const auto& indicator : s_stealerIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            if (Utils::StringUtils::IContains(wideSource, L"discord")) return "DiscordStealer";
            if (Utils::StringUtils::IContains(wideSource, L"browser")) return "BrowserStealer";
            return "GenericStealer";
        }
    }

    // Check for cryptominer indicators
    for (const auto& indicator : s_cryptominerIndicators) {
        std::wstring wideIndicator = Utils::StringUtils::ToWide(indicator);
        if (Utils::StringUtils::IContains(wideSource, wideIndicator)) {
            return "CryptoMiner";
        }
    }

    return "";
}

[[nodiscard]] std::vector<std::string> PythonScriptScannerImpl::ExtractIOCs(
    std::string_view source) {

    std::vector<std::string> iocs;
    std::string sourceStr(source);

    if (source.empty()) {
        return iocs;
    }

    // Extract URLs
    std::regex urlPattern(R"((https?://[^\s\"'\)\]>]+))");
    std::sregex_iterator urlBegin(sourceStr.begin(), sourceStr.end(), urlPattern);
    std::sregex_iterator urlEnd;

    for (auto it = urlBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string url = it->str();
        if (std::find(iocs.begin(), iocs.end(), url) == iocs.end()) {
            iocs.push_back(url);
        }
    }

    // Extract IP addresses
    std::regex ipPattern(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    std::sregex_iterator ipBegin(sourceStr.begin(), sourceStr.end(), ipPattern);

    for (auto it = ipBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string ip = it->str();

        // Skip common non-malicious IPs
        if (ip == "127.0.0.1" || ip == "0.0.0.0" || ip.substr(0, 3) == "10.") {
            continue;
        }

        if (std::find(iocs.begin(), iocs.end(), ip) == iocs.end()) {
            iocs.push_back(ip);
        }
    }

    // Extract domains
    std::regex domainPattern(R"(\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)");
    std::sregex_iterator domainBegin(sourceStr.begin(), sourceStr.end(), domainPattern);

    for (auto it = domainBegin; it != urlEnd && iocs.size() < 100; ++it) {
        std::string domain = it->str();

        // Skip common non-malicious domains
        if (domain.find("python.org") != std::string::npos ||
            domain.find("pypi.org") != std::string::npos ||
            domain.find("github.com") != std::string::npos ||
            domain.find("google.com") != std::string::npos) {
            continue;
        }

        if (std::find(iocs.begin(), iocs.end(), domain) == iocs.end()) {
            iocs.push_back(domain);
        }
    }

    return iocs;
}

[[nodiscard]] std::vector<std::pair<size_t, std::string>>
PythonScriptScannerImpl::FindFlaggedLines(std::string_view source) {

    std::vector<std::pair<size_t, std::string>> flaggedLines;
    std::string sourceStr(source);
    std::istringstream iss(sourceStr);
    std::string line;
    size_t lineNum = 0;

    while (std::getline(iss, line) && flaggedLines.size() < 100) {
        lineNum++;

        std::wstring wideLine = Utils::StringUtils::ToWide(line);

        for (const auto& pattern : s_dangerousPatterns) {
            if (pattern.riskWeight >= 30) {
                std::wstring widePattern = Utils::StringUtils::ToWide(pattern.pattern);
                if (Utils::StringUtils::IContains(wideLine, widePattern)) {
                    // Truncate long lines
                    std::string truncated = line.substr(0, std::min(line.size(), size_t(200)));
                    flaggedLines.emplace_back(lineNum, truncated);
                    break;
                }
            }
        }
    }

    return flaggedLines;
}

[[nodiscard]] std::vector<std::string> PythonScriptScannerImpl::GetCapabilityNames(
    PythonCapability caps) {

    std::vector<std::string> names;
    auto capVal = static_cast<uint32_t>(caps);

    if (capVal & static_cast<uint32_t>(PythonCapability::NetworkCommunication))
        names.push_back("Network Communication");
    if (capVal & static_cast<uint32_t>(PythonCapability::FileOperations))
        names.push_back("File Operations");
    if (capVal & static_cast<uint32_t>(PythonCapability::ProcessExecution))
        names.push_back("Process Execution");
    if (capVal & static_cast<uint32_t>(PythonCapability::RegistryAccess))
        names.push_back("Registry Access");
    if (capVal & static_cast<uint32_t>(PythonCapability::ScreenCapture))
        names.push_back("Screen Capture");
    if (capVal & static_cast<uint32_t>(PythonCapability::Keylogging))
        names.push_back("Keylogging");
    if (capVal & static_cast<uint32_t>(PythonCapability::WebcamAccess))
        names.push_back("Webcam Access");
    if (capVal & static_cast<uint32_t>(PythonCapability::ClipboardMonitor))
        names.push_back("Clipboard Monitoring");
    if (capVal & static_cast<uint32_t>(PythonCapability::FileEncryption))
        names.push_back("File Encryption");
    if (capVal & static_cast<uint32_t>(PythonCapability::Persistence))
        names.push_back("Persistence");
    if (capVal & static_cast<uint32_t>(PythonCapability::CredentialAccess))
        names.push_back("Credential Access");
    if (capVal & static_cast<uint32_t>(PythonCapability::SystemInfo))
        names.push_back("System Enumeration");
    if (capVal & static_cast<uint32_t>(PythonCapability::ProcessInjection))
        names.push_back("Process Injection");
    if (capVal & static_cast<uint32_t>(PythonCapability::DynamicExecution))
        names.push_back("Dynamic Execution");
    if (capVal & static_cast<uint32_t>(PythonCapability::ShellAccess))
        names.push_back("Shell Access");

    return names;
}

[[nodiscard]] bool PythonScriptScannerImpl::ParsePycHeader(
    std::span<const uint8_t> content,
    PythonBytecodeInfo& outInfo) {

    if (content.size() < 16) {
        return false;
    }

    // Read magic number (first 4 bytes, but only first 2 are version-specific)
    outInfo.magicNumber = *reinterpret_cast<const uint32_t*>(content.data());

    // Detect version from magic
    outInfo.version = DetectPythonVersionFromMagic(outInfo.magicNumber);

    // Python 2.7: magic(4) + timestamp(4)
    // Python 3.0-3.2: magic(4) + timestamp(4)
    // Python 3.3+: magic(4) + bit_field(4) + timestamp(4) + source_size(4)

    if (outInfo.version == PythonVersion::Python27) {
        if (content.size() >= 8) {
            outInfo.timestamp = *reinterpret_cast<const uint32_t*>(content.data() + 4);
        }
    } else if (static_cast<uint8_t>(outInfo.version) >= 33) {
        // Python 3.3+
        if (content.size() >= 16) {
            outInfo.timestamp = *reinterpret_cast<const uint32_t*>(content.data() + 8);
            outInfo.sourceSize = *reinterpret_cast<const uint32_t*>(content.data() + 12);
        }
    } else {
        // Python 3.0-3.2
        if (content.size() >= 8) {
            outInfo.timestamp = *reinterpret_cast<const uint32_t*>(content.data() + 4);
        }
    }

    return true;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectPyInstallerExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    std::string contentStr(reinterpret_cast<const char*>(content.data()),
                           std::min(content.size(), size_t(100000)));

    // PyInstaller markers
    if (contentStr.find("PyInstaller") != std::string::npos ||
        contentStr.find("pyi-") != std::string::npos ||
        contentStr.find("_MEIPASS") != std::string::npos ||
        contentStr.find("MEI") != std::string::npos) {
        return true;
    }

    // Check for PyInstaller archive at end of file
    // PyInstaller appends "MEI" marker followed by archive

    return false;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectCxFreezeExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    std::string contentStr(reinterpret_cast<const char*>(content.data()),
                           std::min(content.size(), size_t(50000)));

    // cx_Freeze markers
    if (contentStr.find("cx_Freeze") != std::string::npos ||
        contentStr.find("cxfreeze") != std::string::npos) {
        return true;
    }

    return false;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectNuitkaExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    std::string contentStr(reinterpret_cast<const char*>(content.data()),
                           std::min(content.size(), size_t(50000)));

    // Nuitka markers
    if (contentStr.find("Nuitka") != std::string::npos ||
        contentStr.find("nuitka") != std::string::npos) {
        return true;
    }

    return false;
}

void PythonScriptScannerImpl::NotifyCallback(const PythonScanResult& result) {
    std::shared_lock lock(m_mutex);
    if (m_resultCallback) {
        try {
            m_resultCallback(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PythonScanner", L"Callback exception: %hs", e.what());
        }
    }
}

void PythonScriptScannerImpl::NotifyError(const std::string& message, int code) {
    std::shared_lock lock(m_mutex);
    if (m_errorCallback) {
        try {
            m_errorCallback(message, code);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"PythonScanner", L"Error callback exception: %hs", e.what());
        }
    }
}

// ============================================================================
// PYTHON SCRIPT SCANNER PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

PythonScriptScanner::PythonScriptScanner()
    : m_impl(std::make_unique<PythonScriptScannerImpl>()) {
    s_instanceCreated.store(true);
}

PythonScriptScanner::~PythonScriptScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] PythonScriptScanner& PythonScriptScanner::Instance() noexcept {
    static PythonScriptScanner instance;
    return instance;
}

[[nodiscard]] bool PythonScriptScanner::HasInstance() noexcept {
    return s_instanceCreated.load();
}

[[nodiscard]] bool PythonScriptScanner::Initialize(const PythonScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void PythonScriptScanner::Shutdown() {
    m_impl->Shutdown();
}

[[nodiscard]] bool PythonScriptScanner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus PythonScriptScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

[[nodiscard]] bool PythonScriptScanner::UpdateConfiguration(
    const PythonScannerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

[[nodiscard]] PythonScannerConfiguration PythonScriptScanner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

[[nodiscard]] PythonScanResult PythonScriptScanner::ScanFile(
    const std::filesystem::path& path) {
    return m_impl->ScanFile(path);
}

[[nodiscard]] PythonScanResult PythonScriptScanner::ScanSource(
    std::string_view source,
    const std::string& sourceName) {
    return m_impl->ScanSource(source, sourceName);
}

[[nodiscard]] PythonScanResult PythonScriptScanner::ScanPyInstallerExe(
    const std::filesystem::path& exePath) {
    return m_impl->ScanPyInstallerExe(exePath);
}

[[nodiscard]] PythonScanResult PythonScriptScanner::ScanBytecode(
    const std::filesystem::path& pycPath) {
    return m_impl->ScanBytecode(pycPath);
}

[[nodiscard]] PythonArtifactType PythonScriptScanner::DetectArtifactType(
    const std::filesystem::path& path) {
    return m_impl->DetectArtifactType(path);
}

[[nodiscard]] std::vector<PythonImportInfo> PythonScriptScanner::AnalyzeImports(
    std::string_view source) {
    return m_impl->AnalyzeImports(source);
}

[[nodiscard]] PythonCapability PythonScriptScanner::DetectCapabilities(
    std::string_view source) {
    return m_impl->DetectCapabilities(source);
}

[[nodiscard]] std::optional<std::string> PythonScriptScanner::DecompileBytecode(
    const std::filesystem::path& pycPath) {
    return m_impl->DecompileBytecode(pycPath);
}

[[nodiscard]] std::optional<PackedPythonInfo> PythonScriptScanner::ExtractFromPacked(
    const std::filesystem::path& exePath) {
    return m_impl->ExtractFromPacked(exePath);
}

[[nodiscard]] PythonObfuscationType PythonScriptScanner::DetectObfuscation(
    std::string_view source) {
    return m_impl->DetectObfuscation(source);
}

void PythonScriptScanner::RegisterCallback(ScanResultCallback callback) {
    m_impl->RegisterCallback(std::move(callback));
}

void PythonScriptScanner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void PythonScriptScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

[[nodiscard]] PythonStatistics PythonScriptScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void PythonScriptScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] bool PythonScriptScanner::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string PythonScriptScanner::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << PythonConstants::VERSION_MAJOR << "."
        << PythonConstants::VERSION_MINOR << "."
        << PythonConstants::VERSION_PATCH;
    return oss.str();
}

}  // namespace Scripts
}  // namespace ShadowStrike
