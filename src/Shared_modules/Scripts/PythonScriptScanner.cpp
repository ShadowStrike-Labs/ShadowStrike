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

#include "pch.h"
#include "PythonScriptScanner.hpp"

// Cross-module wiring
#include "../Communication/AlertSystem.hpp"
#include "../Communication/TelemetryCollector.hpp"
#include "../Communication/IPCManager.hpp"

// Standard library includes
#include <algorithm>
#include <regex>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cctype>
#include <bitset>
#include <format>
#include <charconv>
#include <map>

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
        case PythonVersion::Python313: return "Python 3.13";
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
    if (capVal & static_cast<uint32_t>(PythonCapability::ShellcodeInjection))
        return "Shellcode Injection";
    if (capVal & static_cast<uint32_t>(PythonCapability::LsassDumping))
        return "LSASS Credential Dump";
    if (capVal & static_cast<uint32_t>(PythonCapability::C2Communication))
        return "C2 Communication";
    if (capVal & static_cast<uint32_t>(PythonCapability::AttackFramework))
        return "Attack Framework";
    if (capVal & static_cast<uint32_t>(PythonCapability::ReverseShell))
        return "Reverse Shell";
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
    // .pyc magic is 4 bytes on disk: [version_lo, version_hi, 0x0D, 0x0A]
    // When read as little-endian uint32_t: upper 16 bits = 0x0A0D, lower 16 = version
    uint16_t versionMagic = static_cast<uint16_t>(magic & 0xFFFF);
    uint16_t suffix = static_cast<uint16_t>((magic >> 16) & 0xFFFF);

    // Validate CRLF suffix (0x0A0D in little-endian = bytes 0D 0A)
    if (suffix != PythonConstants::PYC_CRLF_SUFFIX) {
        return PythonVersion::Unknown;
    }

    // Python 2.7: version magic 62211 (0xF303)
    if (versionMagic == PythonConstants::PYC_VERSION_MAGIC_27) {
        return PythonVersion::Python27;
    }

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
    // Python 3.12: 3531
    if (versionMagic >= 3500 && versionMagic <= 3549) return PythonVersion::Python312;
    // Python 3.13: 3550+
    if (versionMagic >= 3550 && versionMagic <= 3599) return PythonVersion::Python313;

    return PythonVersion::Unknown;
}

// ============================================================================
// JSON SERIALIZATION IMPLEMENTATIONS
// ============================================================================

namespace {

/// @brief Escape a string for safe JSON embedding. Handles backslashes,
///        quotes, control characters, and non-printable bytes.
void JsonEscapeInto(std::ostringstream& oss, std::string_view sv) {
    for (const char c : sv) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            case '\b': oss << "\\b";  break;
            case '\f': oss << "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) >= 0x20 &&
                    static_cast<unsigned char>(c) < 0x7F) {
                    oss << c;
                } else {
                    // Encode as \u00XX for control/high bytes
                    oss << "\\u" << std::hex << std::setfill('0')
                        << std::setw(4)
                        << static_cast<unsigned>(static_cast<unsigned char>(c))
                        << std::dec;
                }
                break;
        }
    }
}

}  // anonymous namespace

[[nodiscard]] std::string PythonImportInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"moduleName\":\""; JsonEscapeInto(oss, moduleName); oss << "\",";
    oss << "\"isStdLib\":" << (isStdLib ? "true" : "false") << ",";
    oss << "\"isSuspicious\":" << (isSuspicious ? "true" : "false") << ",";
    oss << "\"suspicionReason\":\""; JsonEscapeInto(oss, suspicionReason); oss << "\",";
    oss << "\"lineNumber\":" << lineNumber << ",";
    oss << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ",";

    oss << "\"functionsImported\":[";
    for (size_t i = 0; i < functionsImported.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\""; JsonEscapeInto(oss, functionsImported[i]); oss << "\"";
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
    oss << "\"decompileError\":\""; JsonEscapeInto(oss, decompileError); oss << "\"";
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string PackedPythonInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"packerType\":\"" << GetPythonArtifactTypeName(packerType) << "\",";
    oss << "\"packerVersion\":\""; JsonEscapeInto(oss, packerVersion); oss << "\",";
    oss << "\"entryScript\":\""; JsonEscapeInto(oss, entryScript); oss << "\",";
    oss << "\"embeddedScriptCount\":" << embeddedScriptCount << ",";
    oss << "\"pythonVersion\":\"" << GetPythonVersionName(pythonVersion) << "\",";
    oss << "\"wasExtracted\":" << (wasExtracted ? "true" : "false") << ",";
    oss << "\"extractionError\":\""; JsonEscapeInto(oss, extractionError); oss << "\",";

    oss << "\"embeddedScripts\":[";
    for (size_t i = 0; i < embeddedScripts.size() && i < 50; ++i) {
        if (i > 0) oss << ",";
        oss << "\""; JsonEscapeInto(oss, embeddedScripts[i]); oss << "\"";
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
    oss << "\"detectedFamily\":\""; JsonEscapeInto(oss, detectedFamily); oss << "\",";
    oss << "\"threatName\":\""; JsonEscapeInto(oss, threatName); oss << "\",";
    oss << "\"artifactType\":\"" << GetPythonArtifactTypeName(artifactType) << "\",";
    oss << "\"capabilities\":" << static_cast<uint32_t>(capabilities) << ",";
    oss << "\"isObfuscated\":" << (isObfuscated ? "true" : "false") << ",";
    oss << "\"obfuscationType\":\"" << GetPythonObfuscationTypeName(obfuscationType) << "\",";
    oss << "\"filePath\":\""; JsonEscapeInto(oss, filePath.string()); oss << "\",";
    oss << "\"sha256\":\""; JsonEscapeInto(oss, sha256); oss << "\",";
    oss << "\"fileSize\":" << fileSize << ",";
    oss << "\"scanDurationUs\":" << scanDuration.count() << ",";

    oss << "\"detectedCapabilities\":[";
    for (size_t i = 0; i < detectedCapabilities.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\""; JsonEscapeInto(oss, detectedCapabilities[i]); oss << "\"";
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
        oss << "\""; JsonEscapeInto(oss, matchedSignatures[i]); oss << "\"";
    }
    oss << "],";

    oss << "\"extractedIOCs\":[";
    for (size_t i = 0; i < extractedIOCs.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\""; JsonEscapeInto(oss, extractedIOCs[i]); oss << "\"";
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

[[nodiscard]] PythonStatisticsSnapshot PythonStatistics::ToSnapshot() const noexcept {
    PythonStatisticsSnapshot snap;
    snap.totalScans = totalScans.load(std::memory_order_relaxed);
    snap.maliciousDetected = maliciousDetected.load(std::memory_order_relaxed);
    snap.suspiciousDetected = suspiciousDetected.load(std::memory_order_relaxed);
    snap.sourceFilesScanned = sourceFilesScanned.load(std::memory_order_relaxed);
    snap.bytecodeFilesScanned = bytecodeFilesScanned.load(std::memory_order_relaxed);
    snap.packedExecutablesScanned = packedExecutablesScanned.load(std::memory_order_relaxed);
    snap.obfuscatedDetected = obfuscatedDetected.load(std::memory_order_relaxed);
    snap.decompileFailures = decompileFailures.load(std::memory_order_relaxed);
    snap.extractionFailures = extractionFailures.load(std::memory_order_relaxed);
    snap.totalBytesScanned = totalBytesScanned.load(std::memory_order_relaxed);
    for (size_t i = 0; i < byCategory.size(); ++i) {
        snap.byCategory[i] = byCategory[i].load(std::memory_order_relaxed);
    }
    for (size_t i = 0; i < byCapability.size(); ++i) {
        snap.byCapability[i] = byCapability[i].load(std::memory_order_relaxed);
    }
    snap.uptime = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - startTime);
    return snap;
}

[[nodiscard]] std::string PythonStatisticsSnapshot::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalScans\":" << totalScans << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected << ",";
    oss << "\"suspiciousDetected\":" << suspiciousDetected << ",";
    oss << "\"sourceFilesScanned\":" << sourceFilesScanned << ",";
    oss << "\"bytecodeFilesScanned\":" << bytecodeFilesScanned << ",";
    oss << "\"packedExecutablesScanned\":" << packedExecutablesScanned << ",";
    oss << "\"obfuscatedDetected\":" << obfuscatedDetected << ",";
    oss << "\"decompileFailures\":" << decompileFailures << ",";
    oss << "\"extractionFailures\":" << extractionFailures << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned << ",";
    oss << "\"uptimeMs\":" << uptime.count();
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
    [[nodiscard]] PythonStatisticsSnapshot GetStatistics() const;
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

    // === APT / NATION-STATE PATTERNS ===

    // Shellcode injection via ctypes (APT29, Cobalt Strike, etc.)
    {"ctypes.windll.kernel32.VirtualAlloc", PythonCapability::ShellcodeInjection, 55, "Ctypes VirtualAlloc for shellcode"},
    {"ctypes.windll.kernel32.CreateThread", PythonCapability::ShellcodeInjection, 55, "Ctypes CreateThread for shellcode exec"},
    {"ctypes.windll.kernel32.RtlMoveMemory", PythonCapability::ShellcodeInjection, 55, "Ctypes memory copy for shellcode"},
    {"ctypes.windll.kernel32.WriteProcessMemory", PythonCapability::ShellcodeInjection, 55, "Ctypes process memory write"},
    {"ctypes.windll.kernel32.CreateRemoteThread", PythonCapability::ShellcodeInjection, 55, "Ctypes remote thread creation"},
    {"ctypes.windll.kernel32.VirtualAllocEx", PythonCapability::ShellcodeInjection, 55, "Ctypes remote memory alloc"},
    {"ctypes.windll.kernel32.OpenProcess", PythonCapability::ShellcodeInjection, 50, "Ctypes process open"},
    {"ctypes.windll.kernel32.VirtualProtect", PythonCapability::ShellcodeInjection, 50, "Ctypes memory protection change"},
    {"ctypes.CFUNCTYPE", PythonCapability::ShellcodeInjection, 50, "Ctypes function pointer cast"},
    {"ctypes.cast", PythonCapability::ShellcodeInjection, 40, "Ctypes type cast for shellcode"},
    {"ctypes.memmove", PythonCapability::ShellcodeInjection, 45, "Ctypes memory move"},
    {"ctypes.c_char_p", PythonCapability::ShellcodeInjection, 35, "Ctypes char pointer"},
    {"kernel32.EnumWindows", PythonCapability::ShellcodeInjection, 45, "EnumWindows callback shellcode exec"},

    // LSASS credential dumping (Mimikatz-like via ctypes)
    {"MiniDumpWriteDump", PythonCapability::LsassDumping, 55, "Memory dump via MiniDumpWriteDump"},
    {"lsass", PythonCapability::LsassDumping, 50, "LSASS process targeting"},
    {"PROCESS_ALL_ACCESS", PythonCapability::LsassDumping, 45, "Full process access rights"},
    {"dbghelp", PythonCapability::LsassDumping, 45, "Debug help library for dumps"},
    {"sekurlsa", PythonCapability::LsassDumping, 50, "Mimikatz sekurlsa module"},

    // C2 communication (download-and-exec pattern)
    {"urllib.request.urlopen", PythonCapability::C2Communication, 30, "URL fetch for C2"},
    {"urllib.request.urlretrieve", PythonCapability::C2Communication, 35, "File download for C2"},
    {"http.server", PythonCapability::C2Communication, 30, "HTTP server for staging"},

    // Attack frameworks
    {"impacket", PythonCapability::AttackFramework, 55, "Impacket attack framework"},
    {"impacket.smbconnection", PythonCapability::AttackFramework, 55, "Impacket SMB attack"},
    {"impacket.dcerpc", PythonCapability::AttackFramework, 55, "Impacket DCERPC attack"},
    {"impacket.ntlm", PythonCapability::AttackFramework, 55, "Impacket NTLM attack"},
    {"impacket.kerberos", PythonCapability::AttackFramework, 55, "Impacket Kerberos attack"},
    {"impacket.secretsdump", PythonCapability::AttackFramework, 55, "Impacket credential dump"},
    {"impacket.wmiexec", PythonCapability::AttackFramework, 55, "Impacket WMI execution"},
    {"impacket.smbexec", PythonCapability::AttackFramework, 55, "Impacket SMB execution"},
    {"impacket.psexec", PythonCapability::AttackFramework, 55, "Impacket PsExec execution"},
    {"impacket.atexec", PythonCapability::AttackFramework, 55, "Impacket AT execution"},
    {"mimikatz", PythonCapability::AttackFramework, 55, "Mimikatz tooling"},
    {"bloodhound", PythonCapability::AttackFramework, 50, "BloodHound AD recon"},
    {"responder", PythonCapability::AttackFramework, 50, "Responder LLMNR/NBT-NS"},
    {"lazagne", PythonCapability::AttackFramework, 50, "LaZagne credential harvester"},

    // Reverse / bind shell patterns
    {"dup2", PythonCapability::ReverseShell, 40, "File descriptor duplication"},
    {"pty.spawn", PythonCapability::ReverseShell, 45, "PTY shell spawn"},
    {"bash -i", PythonCapability::ReverseShell, 50, "Interactive bash shell"},
    {"cmd.exe", PythonCapability::ReverseShell, 40, "Command shell"},
    {"powershell.exe", PythonCapability::ReverseShell, 45, "PowerShell execution"},

    // Registry persistence — Run key
    {"CurrentVersion\\\\Run", PythonCapability::Persistence, 50, "Registry Run key persistence"},
    {"CurrentVersion\\Run", PythonCapability::Persistence, 50, "Registry Run key persistence"},

    // Obfuscation chains
    {"base64.b64decode", PythonCapability::DynamicExecution, 30, "Base64 decode (obfuscation)"},
    {"marshal.loads", PythonCapability::DynamicExecution, 40, "Marshal deserialization"},
    {"zlib.decompress", PythonCapability::DynamicExecution, 25, "Zlib decompression"},
    {"codecs.decode", PythonCapability::DynamicExecution, 25, "Codecs decode"},
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

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PythonScanner", L"ScanFile called before initialization");
        result.status = PythonScanStatus::ErrorParsing;
        return result;
    }

    // Validation
    if (path.empty()) {
        SS_LOG_ERROR(L"PythonScanner", L"Empty file path provided");
        result.status = PythonScanStatus::ErrorFileAccess;
        NotifyError("Empty file path", -1);
        return result;
    }

    // Thread-safe config snapshot
    PythonScannerConfiguration configSnapshot;
    {
        std::shared_lock lock(m_mutex);
        configSnapshot = m_config;
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

    // Size check — use config snapshot, not m_config directly
    if (fileStat.size > configSnapshot.maxFileSize) {
        SS_LOG_WARN(L"PythonScanner", L"File too large (%llu bytes): %ls",
                    static_cast<unsigned long long>(fileStat.size), widePath.c_str());
        result.status = PythonScanStatus::SkippedSizeLimit;
        return result;
    }

    // Detect artifact type
    PythonArtifactType detectedType = DetectArtifactType(path);
    result.artifactType = detectedType;

    // Read file content
    std::vector<std::byte> content;
    if (!Utils::FileUtils::ReadAllBytes(widePath, content, &fileErr)) {
        SS_LOG_ERROR(L"PythonScanner", L"Failed to read file: %ls", widePath.c_str());
        result.status = PythonScanStatus::ErrorFileAccess;
        return result;
    }

    // Compute file hash
    std::array<uint8_t, 32> hashBytes{};
    std::string fileHash;
    if (Utils::FileUtils::ComputeFileSHA256(widePath, hashBytes, &fileErr)) {
        fileHash = Utils::HashUtils::ToHexLower(hashBytes.data(), hashBytes.size());
        result.sha256 = fileHash;
    }

    // Route to appropriate scanner
    try {
        switch (detectedType) {
            case PythonArtifactType::SourcePy:
            case PythonArtifactType::Notebook: {
                std::string source(reinterpret_cast<const char*>(content.data()), content.size());
                result = AnalyzeSource(source, path.filename().string(), detectedType);
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

    // Restore file metadata that sub-scanners may have overwritten
    result.filePath = path;
    if (!fileHash.empty()) {
        result.sha256 = fileHash;
    }
    result.fileSize = fileStat.size;
    result.artifactType = detectedType;

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

    if (configSnapshot.verboseLogging) {
        SS_LOG_INFO(L"PythonScanner", L"Scan complete: %ls - Status: %d, Risk: %d",
                    widePath.c_str(), static_cast<int>(result.status), result.riskScore);
    }

    return result;
}

[[nodiscard]] PythonScanResult PythonScriptScannerImpl::ScanSource(
    std::string_view source,
    const std::string& sourceName) {

    auto startTime = Clock::now();

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PythonScanner", L"ScanSource called before initialization");
        PythonScanResult result;
        result.status = PythonScanStatus::ErrorParsing;
        return result;
    }

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

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PythonScanner", L"ScanPyInstallerExe called before initialization");
        result.status = PythonScanStatus::ErrorParsing;
        return result;
    }

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

    if (!m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"PythonScanner", L"ScanBytecode called before initialization");
        result.status = PythonScanStatus::ErrorParsing;
        return result;
    }

    // Thread-safe config snapshot
    PythonScannerConfiguration configSnapshot;
    {
        std::shared_lock lock(m_mutex);
        configSnapshot = m_config;
    }

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
    if (configSnapshot.enableDecompilation) {
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

        // NOTE: ReadAllBytes reads the entire file. Acceptable here because
        // ScanFile already enforces maxFileSize before reaching this point,
        // and the full content is reused by the caller for scanning.
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

    // Enforce regex input size limit to prevent ReDoS
    std::string sourceStr(source.substr(0,
        std::min(source.size(), PythonConstants::MAX_REGEX_INPUT_SIZE)));

    // Pre-compiled static regex patterns
    static const std::regex importPattern(
        R"(^\s*import\s+([a-zA-Z_][a-zA-Z0-9_\.]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_\.]*)*))");
    static const std::regex fromImportPattern(
        R"(^\s*from\s+([a-zA-Z_][a-zA-Z0-9_\.]*)\s+import\s+(.+))");

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

    const auto countCallPattern = [&](std::string_view name) -> size_t {
        size_t count = 0;
        size_t pos = 0;

        while ((pos = sourceStr.find(name, pos)) != std::string::npos) {
            size_t cursor = pos + name.size();
            while (cursor < sourceStr.size() &&
                   std::isspace(static_cast<unsigned char>(sourceStr[cursor]))) {
                ++cursor;
            }

            if (cursor < sourceStr.size() && sourceStr[cursor] == '(') {
                ++count;
            }

            pos += name.size();
        }

        return count;
    };

    // Check for exec/eval chains
    size_t execCount = countCallPattern("exec");
    size_t evalCount = countCallPattern("eval");

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
    size_t pos = 0;
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

    // Check for XOR patterns — require both XOR operator usage AND
    // byte-level data manipulation to reduce false positives
    {
        size_t xorOpCount = 0;
        size_t xorPos = 0;
        while ((xorPos = sourceStr.find("^=", xorPos)) != std::string::npos) {
            xorOpCount++;
            xorPos += 2;
        }
        xorPos = 0;
        while ((xorPos = sourceStr.find("^ 0x", xorPos)) != std::string::npos) {
            xorOpCount++;
            xorPos += 4;
        }
        bool hasXorByteManip =
            Utils::StringUtils::IContains(wideSource, L"bytearray") ||
            Utils::StringUtils::IContains(wideSource, L"bytes") ||
            Utils::StringUtils::IContains(wideSource, L"chr(") ||
            Utils::StringUtils::IContains(wideSource, L"ord(");

        if (xorOpCount >= 3 && hasXorByteManip) {
            return PythonObfuscationType::XorEncryption;
        }
    }

    // Check for variable renaming (many single-letter variables)
    // Only run regex on bounded input
    if (sourceStr.size() <= PythonConstants::MAX_REGEX_INPUT_SIZE) {
        static const std::regex singleVarPattern(R"(\b[a-z]\s*=)");
        std::sregex_iterator begin(sourceStr.begin(), sourceStr.end(), singleVarPattern);
        std::sregex_iterator end;
        size_t singleVarCount = static_cast<size_t>(std::distance(begin, end));

        if (singleVarCount > 30) {
            return PythonObfuscationType::VariableRenaming;
        }
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

[[nodiscard]] PythonStatisticsSnapshot PythonScriptScannerImpl::GetStatistics() const {
    // startTime is non-atomic; protect reads with shared_lock
    std::shared_lock lock(m_mutex);
    return m_stats.ToSnapshot();
}

void PythonScriptScannerImpl::ResetStatistics() {
    // startTime is non-atomic; protect writes with unique_lock
    std::unique_lock lock(m_mutex);
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

    // Thread-safe config snapshot
    PythonScannerConfiguration configSnapshot;
    {
        std::shared_lock lock(m_mutex);
        configSnapshot = m_config;
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
    if (configSnapshot.extractIOCs) {
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

    // ========================================================================
    // CROSS-MODULE WIRING — AlertSystem + TelemetryCollector
    // ========================================================================

    if (result.status == PythonScanStatus::Malicious ||
        result.status == PythonScanStatus::Suspicious)
    {
        // Raise alert for malicious/suspicious detections
        if (Communication::AlertSystem::HasInstance()) {
            try {
                auto severity = (result.status == PythonScanStatus::Malicious)
                    ? Communication::AlertSeverity::Critical
                    : Communication::AlertSeverity::High;

                auto statusStr = (result.status == PythonScanStatus::Malicious)
                    ? "MALICIOUS" : "SUSPICIOUS";
                auto nameStr = result.threatName.empty()
                    ? result.filePath.string() : result.threatName;
                auto familyStr = result.detectedFamily.empty()
                    ? std::string("unknown") : result.detectedFamily;
                bool obfusc = (result.obfuscationType != PythonObfuscationType::None);

                std::string alertDetail =
                    "PythonScriptScanner detected " + std::string(statusStr) +
                    " script: " + nameStr +
                    " | risk=" + std::to_string(result.riskScore) +
                    " family=" + familyStr +
                    " suspiciousImports=" + std::to_string(result.suspiciousImports.size()) +
                    " matchedSigs=" + std::to_string(result.matchedSignatures.size()) +
                    " obfuscated=" + (obfusc ? "true" : "false");

                [[maybe_unused]] auto alertId =
                    Communication::AlertSystem::Instance().RaiseAlert(
                        severity,
                        Communication::AlertType::ThreatDetection,
                        "PythonScriptScanner",
                        alertDetail,
                        result.sha256);
            }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"PythonScanner",
                    L"AlertSystem wiring failed: %hs", e.what());
            }
        }

        // Emit telemetry for threat intelligence correlation
        if (Communication::TelemetryCollector::HasInstance()) {
            try {
                std::map<std::string, std::string> telemetry;
                telemetry["module"]          = "PythonScriptScanner";
                telemetry["status"]          = (result.status == PythonScanStatus::Malicious) ? "malicious" : "suspicious";
                telemetry["threatName"]      = result.threatName;
                telemetry["riskScore"]       = std::to_string(result.riskScore);
                telemetry["sha256"]          = result.sha256;
                telemetry["family"]          = result.detectedFamily;
                telemetry["category"]        = std::string(GetPythonThreatCategoryName(result.category));
                telemetry["importCount"]     = std::to_string(result.suspiciousImports.size());
                telemetry["sigCount"]        = std::to_string(result.matchedSignatures.size());
                telemetry["obfuscated"]      = (result.obfuscationType != PythonObfuscationType::None) ? "true" : "false";
                telemetry["filePath"]        = result.filePath.string();

                Communication::TelemetryCollector::Instance().RecordCustom(
                    "python_threat_detection", telemetry);
            }
            catch (const std::exception& e) {
                SS_LOG_WARN(L"PythonScanner",
                    L"TelemetryCollector wiring failed: %hs", e.what());
            }
        }

        // Request kernel-level process block for high-risk malicious scripts
        if (result.status == PythonScanStatus::Malicious && result.riskScore >= 90) {
            if (Communication::IPCManager::HasInstance()) {
                auto& ipc = Communication::IPCManager::Instance();
                if (ipc.IsFilterPortConnected()) {
                    SS_LOG_INFO(L"PythonScanner",
                        L"High-risk Python malware detected (score=%d), "
                        L"kernel block available via RequestKernelProcessBlock",
                        result.riskScore);
                }
            }
        }
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
    if (caps & static_cast<uint32_t>(PythonCapability::ShellcodeInjection)) score += 50;
    if (caps & static_cast<uint32_t>(PythonCapability::LsassDumping)) score += 50;
    if (caps & static_cast<uint32_t>(PythonCapability::AttackFramework)) score += 45;
    if (caps & static_cast<uint32_t>(PythonCapability::ReverseShell)) score += 45;

    // Medium-risk capabilities
    if (caps & static_cast<uint32_t>(PythonCapability::ProcessExecution)) score += 20;
    if (caps & static_cast<uint32_t>(PythonCapability::ShellAccess)) score += 25;
    if (caps & static_cast<uint32_t>(PythonCapability::RegistryAccess)) score += 20;
    if (caps & static_cast<uint32_t>(PythonCapability::DynamicExecution)) score += 25;
    if (caps & static_cast<uint32_t>(PythonCapability::C2Communication)) score += 30;
    if (caps & static_cast<uint32_t>(PythonCapability::AntiVM)) score += 20;
    if (caps & static_cast<uint32_t>(PythonCapability::AntiDebug)) score += 20;

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

    // Exploit / attack framework tooling
    if ((caps & static_cast<uint32_t>(PythonCapability::AttackFramework)) ||
        (caps & static_cast<uint32_t>(PythonCapability::ShellcodeInjection)) ||
        (caps & static_cast<uint32_t>(PythonCapability::LsassDumping))) {
        return PythonThreatCategory::Exploit;
    }

    // Reverse shell
    if (caps & static_cast<uint32_t>(PythonCapability::ReverseShell)) {
        return PythonThreatCategory::Backdoor;
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

    if (source.empty()) {
        return iocs;
    }

    // Enforce regex input size limit to prevent ReDoS
    std::string sourceStr(source.substr(0,
        std::min(source.size(), PythonConstants::MAX_REGEX_INPUT_SIZE)));

    // Extract URLs
    static const std::regex urlPattern(R"((https?://[^\s\"'\)\]>]+))");
    std::sregex_iterator urlBegin(sourceStr.begin(), sourceStr.end(), urlPattern);
    std::sregex_iterator iterEnd;  // default-constructed sentinel

    for (auto it = urlBegin; it != iterEnd && iocs.size() < 100; ++it) {
        std::string url = it->str();
        if (std::find(iocs.begin(), iocs.end(), url) == iocs.end()) {
            iocs.push_back(std::move(url));
        }
    }

    // Extract IP addresses
    static const std::regex ipPattern(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    std::sregex_iterator ipBegin(sourceStr.begin(), sourceStr.end(), ipPattern);

    for (auto it = ipBegin; it != iterEnd && iocs.size() < 100; ++it) {
        std::string ip = it->str();

        // Validate octet ranges (0-255)
        bool validIp = true;
        std::istringstream ipStream(ip);
        std::string octet;
        while (std::getline(ipStream, octet, '.')) {
            int val = 0;
            auto [ptr, ec] = std::from_chars(
                octet.data(), octet.data() + octet.size(), val);
            if (ec != std::errc{} || ptr != octet.data() + octet.size() ||
                val > 255)
            {
                validIp = false;
                break;
            }
        }

        if (!validIp) continue;

        // Skip common non-malicious IPs
        if (ip == "127.0.0.1" || ip == "0.0.0.0" ||
            ip.starts_with("10.") || ip.starts_with("192.168.") ||
            ip.starts_with("172.16.") || ip.starts_with("169.254.")) {
            continue;
        }

        if (std::find(iocs.begin(), iocs.end(), ip) == iocs.end()) {
            iocs.push_back(std::move(ip));
        }
    }

    // Extract domains
    static const std::regex domainPattern(
        R"(\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)");
    std::sregex_iterator domainBegin(sourceStr.begin(), sourceStr.end(), domainPattern);

    for (auto it = domainBegin; it != iterEnd && iocs.size() < 100; ++it) {
        std::string domain = it->str();

        // Skip common non-malicious domains
        if (domain.find("python.org") != std::string::npos ||
            domain.find("pypi.org") != std::string::npos ||
            domain.find("github.com") != std::string::npos ||
            domain.find("google.com") != std::string::npos ||
            domain.find("microsoft.com") != std::string::npos ||
            domain.find("stackoverflow.com") != std::string::npos) {
            continue;
        }

        if (std::find(iocs.begin(), iocs.end(), domain) == iocs.end()) {
            iocs.push_back(std::move(domain));
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
    if (capVal & static_cast<uint32_t>(PythonCapability::AntiVM))
        names.push_back("Anti-VM");
    if (capVal & static_cast<uint32_t>(PythonCapability::AntiDebug))
        names.push_back("Anti-Debug");
    if (capVal & static_cast<uint32_t>(PythonCapability::SelfModifying))
        names.push_back("Self-Modifying Code");
    if (capVal & static_cast<uint32_t>(PythonCapability::DynamicExecution))
        names.push_back("Dynamic Execution");
    if (capVal & static_cast<uint32_t>(PythonCapability::ShellAccess))
        names.push_back("Shell Access");
    if (capVal & static_cast<uint32_t>(PythonCapability::EmailAccess))
        names.push_back("Email Access");
    if (capVal & static_cast<uint32_t>(PythonCapability::BrowserManipulation))
        names.push_back("Browser Manipulation");
    if (capVal & static_cast<uint32_t>(PythonCapability::ShellcodeInjection))
        names.push_back("Shellcode Injection");
    if (capVal & static_cast<uint32_t>(PythonCapability::LsassDumping))
        names.push_back("LSASS Credential Dump");
    if (capVal & static_cast<uint32_t>(PythonCapability::C2Communication))
        names.push_back("C2 Communication");
    if (capVal & static_cast<uint32_t>(PythonCapability::AttackFramework))
        names.push_back("Attack Framework");
    if (capVal & static_cast<uint32_t>(PythonCapability::ReverseShell))
        names.push_back("Reverse Shell");

    return names;
}

[[nodiscard]] bool PythonScriptScannerImpl::ParsePycHeader(
    std::span<const uint8_t> content,
    PythonBytecodeInfo& outInfo) {

    if (content.size() < 8) {
        return false;
    }

    // Safe aligned reads via memcpy
    std::memcpy(&outInfo.magicNumber, content.data(), sizeof(uint32_t));

    // Detect version from magic
    outInfo.version = DetectPythonVersionFromMagic(outInfo.magicNumber);

    // Python 2.7: magic(4) + timestamp(4)
    // Python 3.0-3.2: magic(4) + timestamp(4)
    // Python 3.3+: magic(4) + bit_field(4) + timestamp(4) + source_size(4)

    uint16_t versionVal = static_cast<uint16_t>(outInfo.version);

    if (outInfo.version == PythonVersion::Python27) {
        std::memcpy(&outInfo.timestamp, content.data() + 4, sizeof(uint32_t));
    } else if (versionVal >= 35) {
        // Python 3.3+ header with bit_field
        if (content.size() >= 16) {
            std::memcpy(&outInfo.timestamp, content.data() + 8, sizeof(uint32_t));
            std::memcpy(&outInfo.sourceSize, content.data() + 12, sizeof(uint32_t));
        }
    } else {
        // Python 3.0-3.2
        if (content.size() >= 8) {
            std::memcpy(&outInfo.timestamp, content.data() + 4, sizeof(uint32_t));
        }
    }

    return true;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectPyInstallerExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    // Scan a bounded portion for string markers
    size_t scanLimit = std::min(content.size(), size_t(100000));
    std::string_view contentView(reinterpret_cast<const char*>(content.data()), scanLimit);

    // PyInstaller markers (specific enough to avoid false positives)
    if (contentView.find("PyInstaller") != std::string_view::npos ||
        contentView.find("pyi-") != std::string_view::npos ||
        contentView.find("_MEIPASS") != std::string_view::npos) {
        return true;
    }

    // Check for the 8-byte MEI archive magic at the end of the file
    // PyInstaller appends: 'M','E','I',0x0C,0x0B,0x0A,0x0B,0x0E
    if (content.size() >= sizeof(PYINSTALLER_MARKER) + 24) {
        // Marker is typically near the end of the file
        size_t tailStart = content.size() > 4096 ? content.size() - 4096 : 0;
        for (size_t i = tailStart; i + sizeof(PYINSTALLER_MARKER) <= content.size(); ++i) {
            if (std::memcmp(content.data() + i, PYINSTALLER_MARKER,
                            sizeof(PYINSTALLER_MARKER)) == 0) {
                return true;
            }
        }
    }

    return false;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectCxFreezeExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    size_t scanLimit = std::min(content.size(), size_t(50000));
    std::string_view contentView(reinterpret_cast<const char*>(content.data()), scanLimit);

    // cx_Freeze markers
    if (contentView.find("cx_Freeze") != std::string_view::npos ||
        contentView.find("cxfreeze") != std::string_view::npos) {
        return true;
    }

    return false;
}

[[nodiscard]] bool PythonScriptScannerImpl::DetectNuitkaExe(
    std::span<const uint8_t> content) {

    if (content.size() < 1024) {
        return false;
    }

    size_t scanLimit = std::min(content.size(), size_t(50000));
    std::string_view contentView(reinterpret_cast<const char*>(content.data()), scanLimit);

    // Nuitka markers
    if (contentView.find("Nuitka") != std::string_view::npos ||
        contentView.find("nuitka") != std::string_view::npos) {
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

[[nodiscard]] PythonStatisticsSnapshot PythonScriptScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void PythonScriptScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] bool PythonScriptScanner::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string PythonScriptScanner::GetVersionString() noexcept {
    return std::to_string(PythonConstants::VERSION_MAJOR) + "." +
           std::to_string(PythonConstants::VERSION_MINOR) + "." +
           std::to_string(PythonConstants::VERSION_PATCH);
}

// ============================================================================
// KERNEL BRIDGE — IPC integration with PhantomSensor kernel driver
// ============================================================================

void PythonScriptScanner::OnKernelProcessNotify(
    uint32_t pid, uint32_t parentPid,
    std::wstring_view imagePath, bool isCreate)
{
    if (!isCreate || !m_impl || !m_impl->IsInitialized()) return;

    // Detect python.exe / pythonw.exe / python3.exe launches
    auto lowerPath = Utils::StringUtils::ToLowerCopy(imagePath);

    bool isPython = (lowerPath.find(L"python.exe") != std::wstring::npos) ||
                    (lowerPath.find(L"pythonw.exe") != std::wstring::npos) ||
                    (lowerPath.find(L"python3.exe") != std::wstring::npos);

    if (!isPython) return;

    SS_LOG_INFO(L"PythonScanner",
        L"Kernel process notify: Python interpreter launched PID=%u "
        L"ParentPID=%u Path=%.*s",
        pid, parentPid,
        static_cast<int>(imagePath.size()), imagePath.data());

    // Telemetry: Python process creation event
    if (Communication::TelemetryCollector::HasInstance()) {
        try {
            std::map<std::string, std::string> telemetry;
            telemetry["module"]    = "PythonScriptScanner";
            telemetry["event"]     = "python_process_created";
            telemetry["pid"]       = std::to_string(pid);
            telemetry["parentPid"] = std::to_string(parentPid);
            telemetry["imagePath"] = Utils::StringUtils::ToNarrow(imagePath);

            Communication::TelemetryCollector::Instance().RecordCustom(
                "python_process_notify", telemetry);
        }
        catch (const std::exception& e) {
            SS_LOG_WARN(L"PythonScanner",
                L"Telemetry failed for process notify: %hs", e.what());
        }
    }
}

void PythonScriptScanner::OnKernelImageLoad(
    uint32_t pid, std::wstring_view imagePath, uintptr_t imageBase)
{
    if (!m_impl || !m_impl->IsInitialized()) return;

    auto lowerPath = Utils::StringUtils::ToLowerCopy(imagePath);

    // Watch for packed Python executables (PyInstaller, cx_Freeze, py2exe)
    bool isPythonDll = (lowerPath.find(L"python3") != std::wstring::npos &&
                        lowerPath.ends_with(L".dll"));

    if (!isPythonDll) return;

    SS_LOG_DEBUG(L"PythonScanner",
        L"Kernel image load: Python DLL loaded in PID=%u Path=%.*s Base=0x%llX",
        pid,
        static_cast<int>(imagePath.size()), imagePath.data(),
        static_cast<unsigned long long>(imageBase));
}

[[nodiscard]] bool PythonScriptScanner::RequestKernelProcessBlock(
    uint32_t pid, std::wstring_view reason)
{
    if (!Communication::IPCManager::HasInstance()) {
        SS_LOG_WARN(L"PythonScanner",
            L"Cannot block PID=%u: IPCManager not available", pid);
        return false;
    }

    auto& ipc = Communication::IPCManager::Instance();
    if (!ipc.IsFilterPortConnected()) {
        SS_LOG_WARN(L"PythonScanner",
            L"Cannot block PID=%u: kernel filter port not connected", pid);
        return false;
    }

#pragma pack(push, 1)
    struct KernelBlockRequest {
        uint32_t msgType;       // 0x35 = PythonScanner process block
        uint32_t targetPid;
        uint32_t reasonLen;
        wchar_t  reason[256];
    };
#pragma pack(pop)

    KernelBlockRequest req{};
    req.msgType   = 0x35;
    req.targetPid = pid;

    auto copyLen = (std::min)(reason.size(), static_cast<size_t>(255));
    std::memcpy(req.reason, reason.data(), copyLen * sizeof(wchar_t));
    req.reason[copyLen] = L'\0';
    req.reasonLen = static_cast<uint32_t>(copyLen);

    [[maybe_unused]] bool sent = ipc.SendToKernel(&req, sizeof(req));

    SS_LOG_INFO(L"PythonScanner",
        L"Kernel process block request for PID=%u sent=%d reason=%.*s",
        pid, sent ? 1 : 0,
        static_cast<int>(copyLen), reason.data());

    return sent;
}

// ============================================================================
// CROSS-MODULE WIRING — Public API wrappers
// ============================================================================

void PythonScriptScanner::ReportDetectionToAlertSystem(
    uint32_t pid, const PythonScanResult& result)
{
    if (!Communication::AlertSystem::HasInstance()) return;

    try {
        auto severity = Communication::AlertSeverity::High;
        if (result.status == PythonScanStatus::Malicious)
            severity = Communication::AlertSeverity::Critical;

        std::string detail =
            "PythonScriptScanner PID=" + std::to_string(pid) +
            " threat=" + (result.threatName.empty() ? "unknown" : result.threatName) +
            " risk=" + std::to_string(result.riskScore) +
            " family=" + (result.detectedFamily.empty() ? "none" : result.detectedFamily) +
            " sha256=" + (result.sha256.empty() ? "n/a" : result.sha256) +
            " imports=" + std::to_string(result.suspiciousImports.size()) +
            " sigs=" + std::to_string(result.matchedSignatures.size());

        [[maybe_unused]] auto alertId =
            Communication::AlertSystem::Instance().RaiseAlert(
                severity,
                Communication::AlertType::ThreatDetection,
                "PythonScriptScanner",
                detail,
                result.sha256);
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"PythonScanner",
            L"ReportDetectionToAlertSystem failed: %hs", e.what());
    }
}

void PythonScriptScanner::ReportScanTelemetry(const PythonScanResult& result) {
    if (!Communication::TelemetryCollector::HasInstance()) return;

    try {
        std::map<std::string, std::string> telemetry;
        telemetry["module"]       = "PythonScriptScanner";
        telemetry["filePath"]     = result.filePath.string();
        telemetry["status"]       = (result.status == PythonScanStatus::Malicious) ? "malicious" :
                                    (result.status == PythonScanStatus::Suspicious) ? "suspicious" : "clean";
        telemetry["riskScore"]    = std::to_string(result.riskScore);
        telemetry["sha256"]       = result.sha256;
        telemetry["threatName"]   = result.threatName;
        telemetry["family"]       = result.detectedFamily;
        telemetry["category"]     = std::string(GetPythonThreatCategoryName(result.category));

        Communication::TelemetryCollector::Instance().RecordCustom(
            "python_scan_result", telemetry);
    }
    catch (const std::exception& e) {
        SS_LOG_WARN(L"PythonScanner",
            L"ReportScanTelemetry failed: %hs", e.what());
    }
}

}  // namespace Scripts
}  // namespace ShadowStrike
