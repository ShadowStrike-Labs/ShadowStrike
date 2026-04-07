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
 * ShadowStrike Core FileSystem - DOCUMENT SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file DocumentScanner.cpp
 * @brief Enterprise-grade document threat analysis engine implementation.
 *
 * This module provides comprehensive security analysis of document formats
 * including PDF, Office documents (legacy and OOXML), RTF, and other formats
 * commonly weaponized by malware for initial access.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-threaded analysis with shared_mutex protection
 * - Integration with PatternStore, ThreatIntel, HashStore
 * - Zero-copy buffer analysis with std::span
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "DocumentScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../Utils/CompressionUtils.hpp"
#include "../../HashStore/HashStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include <pugixml/pugixml.hpp>

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <unordered_set>
#include <cmath>

namespace fs = std::filesystem;

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

namespace StringUtils = ShadowStrike::Utils::StringUtils;

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Document signatures
    constexpr uint8_t PDF_SIGNATURE[] = { 0x25, 0x50, 0x44, 0x46 }; // %PDF
    constexpr uint8_t OLE_SIGNATURE[] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };
    constexpr uint8_t ZIP_SIGNATURE[] = { 0x50, 0x4B, 0x03, 0x04 }; // OOXML
    constexpr uint8_t RTF_SIGNATURE[] = { 0x7B, 0x5C, 0x72, 0x74, 0x66 }; // {\rtf

    // Analysis limits
    constexpr size_t MAX_DOCUMENT_SIZE = 500 * 1024 * 1024; // 500 MB
    constexpr size_t MAX_STRING_EXTRACT = 1024 * 1024; // 1 MB
    constexpr size_t MAX_JAVASCRIPT_SIZE = 10 * 1024 * 1024; // 10 MB

    // VBA auto-exec functions
    const std::unordered_set<std::string> VBA_AUTOEXEC_FUNCTIONS = {
        "AutoExec", "AutoOpen", "Auto_Open", "DocumentOpen", "Document_Open",
        "AutoClose", "Auto_Close", "DocumentBeforeClose", "Document_Close",
        "Workbook_Open", "Workbook_Activate", "Workbook_Close",
        "AutoNew", "Auto_New", "Document_New",
        "AutoExit", "Auto_Exit"
    };

    // Suspicious VBA API calls
    const std::unordered_set<std::string> SUSPICIOUS_VBA_APIS = {
        "Shell", "CreateObject", "GetObject", "WScript.Shell",
        "Environ", "URLDownloadToFile", "URLDownloadToFileA",
        "WinExec", "ShellExecute", "ShellExecuteA",
        "PowerShell", "cmd.exe", "wscript", "cscript",
        "MSXML2.XMLHTTP", "WinHttp.WinHttpRequest",
        "Scripting.FileSystemObject", "ADODB.Stream",
        "SaveAs", "SaveToFile", "WriteText",
        "RegRead", "RegWrite", "RegDelete",
        "WMI", "Win32_Process", "GetStringFromGUID"
    };

    // PDF action types (malicious)
    const std::unordered_set<std::string> MALICIOUS_PDF_ACTIONS = {
        "/Launch", "/SubmitForm", "/ImportData", "/JavaScript",
        "/GoToE", "/GoToR", "/URI", "/Sound"
    };

    // Known CVE patterns (simplified - full database would be in PatternStore)
    const std::unordered_map<std::string, std::string> CVE_PATTERNS = {
        {"Equation.3", "CVE-2017-11882"}, // Equation Editor
        {"objupdate", "CVE-2015-1641"}, // RTF objupdate
        {"INCLUDEPICTURE", "CVE-2017-0199"}, // Template Injection
        {"objdata 0105000", "CVE-2012-0158"}, // MSCOMCTL
        {"\\\\objhtml", "CVE-2017-8570"}, // Composite Moniker
    };

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class DocumentScannerImpl final {
public:
    DocumentScannerImpl() = default;
    ~DocumentScannerImpl() = default;

    // Delete copy/move
    DocumentScannerImpl(const DocumentScannerImpl&) = delete;
    DocumentScannerImpl& operator=(const DocumentScannerImpl&) = delete;
    DocumentScannerImpl(DocumentScannerImpl&&) = delete;
    DocumentScannerImpl& operator=(DocumentScannerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const DocumentScannerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            if (!m_hashStore) {
                m_hashStore = std::make_shared<HashStore::HashStore>();
            }
            if (!m_patternStore) {
                m_patternStore = std::make_shared<PatternStore::PatternStore>();
            }
            m_initialized = true;

            SS_LOG_INFO(L"DocumentScanner", L"DocumentScanner initialized (macros=%d, ole=%d, pdf=%d, cve=%d)", config.analyzeMacros, config.analyzeOLEObjects, config.analyzePDFJavaScript, config.detectCVEs);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_mutex);

        try {
            m_progressCallback = nullptr;
            m_threatCallback = nullptr;
            m_initialized = false;

            SS_LOG_INFO(L"DocumentScanner", L"DocumentScanner shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    // ========================================================================
    // MAIN SCANNING
    // ========================================================================

    [[nodiscard]] DocumentScanResult Scan(const std::wstring& filePath,
                                          const DocumentScannerConfig& config) {

        auto startTime = std::chrono::steady_clock::now();
        DocumentScanResult result;
        result.filePath = filePath;
        result.scanTime = std::chrono::system_clock::now();

        // Initialized check
        if (!m_initialized) {
            SS_LOG_ERROR(L"DocumentScanner", L"Scan called before initialization");
            result.verdict = ScanVerdict::Error;
            result.errors.push_back("DocumentScanner not initialized");
            return result;
        }

        // Thread-safe read access to shared state
        std::shared_lock lock(m_mutex);

        try {
            // Validate path
            if (filePath.empty()) {
                SS_LOG_WARN(L"DocumentScanner", L"DocumentScanner::Scan - Empty file path");
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("Empty file path");
                return result;
            }

            if (!fs::exists(filePath)) {
                SS_LOG_WARN(L"DocumentScanner", L"DocumentScanner::Scan - File not found: %hs", StringUtils::ToNarrow(filePath).c_str());
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("File not found");
                return result;
            }

            // Check file size
            result.fileSize = fs::file_size(filePath);
            if (result.fileSize > MAX_DOCUMENT_SIZE) {
                SS_LOG_WARN(L"DocumentScanner", L"DocumentScanner::Scan - File too large: %llu bytes", result.fileSize);
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("File exceeds maximum size");
                return result;
            }

            // Detect document type
            result.documentType = DetectDocumentType(filePath);
            if (result.documentType == DocumentType::Unknown) {
                SS_LOG_WARN(L"DocumentScanner", L"DocumentScanner::Scan - Unknown document type");
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("Unknown document type");
                return result;
            }

            ReportProgress(L"Detecting document type", 10);

            // Hash check against known malware
            if (CheckKnownMalwareHash(filePath, result)) {
                result.verdict = ScanVerdict::HighlyMalicious;
                result.riskScore = 100;
                m_stats.maliciousDocuments.fetch_add(1, std::memory_order_relaxed);
                return result;
            }

            ReportProgress(L"Analyzing document structure", 30);

            // Type-specific analysis
            switch (result.documentType) {
                case DocumentType::PDF:
                    AnalyzePDFDocument(filePath, config, result);
                    break;

                case DocumentType::DOC:
                case DocumentType::XLS:
                case DocumentType::PPT:
                case DocumentType::MSG:
                    AnalyzeLegacyOfficeDocument(filePath, config, result);
                    break;

                case DocumentType::DOCX:
                case DocumentType::DOCM:
                case DocumentType::DOTM:
                case DocumentType::XLSX:
                case DocumentType::XLSM:
                case DocumentType::PPTX:
                case DocumentType::PPTM:
                    AnalyzeOOXMLDocument(filePath, config, result);
                    break;

                case DocumentType::RTF:
                    AnalyzeRTFDocument(filePath, config, result);
                    break;

                default:
                    SS_LOG_WARN(L"DocumentScanner", L"DocumentScanner::Scan - Unsupported document type");
                    result.errors.push_back("Unsupported document type");
                    break;
            }

            ReportProgress(L"Extracting IOCs", 70);

            // Extract metadata
            ExtractMetadata(filePath, result);

            // IOC extraction
            if (config.extractIOCs) {
                ExtractAllIOCs(result);
            }

            ReportProgress(L"Calculating risk score", 90);

            // Calculate final verdict
            CalculateVerdict(result);

            // Update statistics
            m_stats.documentsScanned.fetch_add(1, std::memory_order_relaxed);
            if (result.verdict == ScanVerdict::Malicious ||
                result.verdict == ScanVerdict::HighlyMalicious) {
                m_stats.maliciousDocuments.fetch_add(1, std::memory_order_relaxed);
            }

            ReportProgress(L"Scan complete", 100);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::Scan - Exception: %hs", e.what());
            result.verdict = ScanVerdict::Error;
            result.hadErrors = true;
            result.errors.push_back(e.what());
        }

        auto endTime = std::chrono::steady_clock::now();
        result.scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);

        SS_LOG_INFO(L"DocumentScanner", L"DocumentScanner::Scan - Completed in %lldms (verdict=%u, risk=%u)", 
            static_cast<long long>(result.scanDuration.count()), static_cast<unsigned>(result.verdict), result.riskScore);

        return result;
    }

    [[nodiscard]] DocumentScanResult ScanBuffer(std::span<const uint8_t> buffer,
                                                DocumentType docType) {

        DocumentScanResult result;
        result.documentType = docType;
        result.fileSize = buffer.size();
        result.scanTime = std::chrono::system_clock::now();

        try {
            if (buffer.empty()) {
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("Empty buffer");
                return result;
            }

            if (buffer.size() > MAX_DOCUMENT_SIZE) {
                result.verdict = ScanVerdict::Error;
                result.errors.push_back("Buffer exceeds maximum size");
                return result;
            }

            // Type-specific buffer analysis
            switch (docType) {
                case DocumentType::PDF:
                    AnalyzePDFBuffer(buffer, result);
                    break;

                case DocumentType::RTF:
                    AnalyzeRTFBuffer(buffer, result);
                    break;

                default:
                    // For binary formats, need file-based analysis
                    SS_LOG_WARN(L"DocumentScanner", L"Buffer scan not fully supported for this type");
                    break;
            }

            CalculateVerdict(result);
            m_stats.documentsScanned.fetch_add(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::ScanBuffer - Exception: %hs", e.what());
            result.verdict = ScanVerdict::Error;
            result.hadErrors = true;
            result.errors.push_back(e.what());
        }

        return result;
    }

    [[nodiscard]] bool HasMacros(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);

        try {
            auto docType = DetectDocumentType(filePath);

            // Check by file type
            if (docType == DocumentType::DOCM || docType == DocumentType::DOTM ||
                docType == DocumentType::XLSM || docType == DocumentType::PPTM) {
                return true; // Macro-enabled by extension
            }

            // For legacy formats, check for VBA storage
            if (docType == DocumentType::DOC || docType == DocumentType::XLS ||
                docType == DocumentType::PPT) {

                auto streams = ListOLEStreamsInternal(filePath);
                for (const auto& stream : streams) {
                    if (stream.find("VBA") != std::string::npos ||
                        stream.find("Macros") != std::string::npos ||
                        stream == "_VBA_PROJECT") {
                        return true;
                    }
                }
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::HasMacros - Exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsMalicious(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);

        try {
            // Hash-based detection via FileHasher
            auto& hasher = FileHasher::Instance();
            auto hash = hasher.ComputeSHA256(filePath);
            if (!hash.empty() && m_hashStore) {
                auto lookupResult = m_hashStore->LookupHashString(hash, HashStore::HashType::SHA256);
                if (lookupResult.has_value()) {
                    return true;
                }
            }

            // PatternStore YARA-based exploit detection
            if (m_patternStore) {
                auto patternResults = m_patternStore->ScanFile(filePath);
                if (!patternResults.empty()) {
                    for (const auto& det : patternResults) {
                        if (det.threatLevel >= SignatureStore::ThreatLevel::High) {
                            SS_LOG_WARN(L"DocumentScanner", L"Pattern match: %hs", det.signatureName.c_str());
                            return true;
                        }
                    }
                }
            }

            // Quick CVE pattern scan on first 1MB
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return false;

            const auto fileSize = fs::file_size(filePath);
            std::vector<uint8_t> buffer(std::min<size_t>(1024 * 1024, static_cast<size_t>(fileSize)));
            file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            std::string content(buffer.begin(), buffer.end());

            for (const auto& [pattern, cve] : CVE_PATTERNS) {
                if (content.find(pattern) != std::string::npos) {
                    SS_LOG_WARN(L"DocumentScanner", L"Quick malicious check: Found %hs pattern", cve.c_str());
                    return true;
                }
            }

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"IsMalicious - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // MACRO ANALYSIS
    // ========================================================================

    [[nodiscard]] std::vector<MacroInfo> ExtractMacros(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        std::vector<MacroInfo> macros;

        try {
            auto docType = DetectDocumentType(filePath);

            if (docType == DocumentType::DOC || docType == DocumentType::XLS ||
                docType == DocumentType::PPT) {
                macros = ExtractOLEMacros(filePath);
            } else if (docType == DocumentType::DOCM || docType == DocumentType::DOTM ||
                       docType == DocumentType::XLSM || docType == DocumentType::PPTM) {
                macros = ExtractOOXMLMacros(filePath);
            }

            // Analyze each macro
            for (auto& macro : macros) {
                AnalyzeMacroCode(macro);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::ExtractMacros - Exception: %hs", e.what());
        }

        return macros;
    }

    [[nodiscard]] MacroInfo AnalyzeVBACode(const std::string& vbaCode) const {
        MacroInfo info;
        info.sourceCode = vbaCode;
        info.lineCount = static_cast<uint32_t>(
            std::count(vbaCode.begin(), vbaCode.end(), '\n') + 1);

        AnalyzeMacroCode(info);
        return info;
    }

    [[nodiscard]] std::string DeobfuscateMacro(const std::string& obfuscatedCode) const {
        std::string deobfuscated = obfuscatedCode;

        try {
            // 1. Expand Chr() concatenation: Chr(72)&Chr(101) -> "He"
            std::string expanded;
            expanded.reserve(deobfuscated.size());
            size_t pos = 0;
            while (pos < deobfuscated.size()) {
                if (pos + 4 < deobfuscated.size() && deobfuscated.substr(pos, 4) == "Chr(") {
                    size_t numStart = pos + 4;
                    size_t numEnd = deobfuscated.find(')', numStart);
                    if (numEnd != std::string::npos && numEnd - numStart <= 3) {
                        int val = 0;
                        auto [ptr, ec] = std::from_chars(deobfuscated.data() + numStart,
                                                         deobfuscated.data() + numEnd, val);
                        if (ec == std::errc{} && val >= 0 && val <= 127) {
                            expanded += static_cast<char>(val);
                            pos = numEnd + 1;
                            // Skip "&" between Chr() calls
                            while (pos < deobfuscated.size() && (deobfuscated[pos] == '&' || deobfuscated[pos] == ' ')) pos++;
                            continue;
                        }
                    }
                }
                expanded += deobfuscated[pos];
                pos++;
            }
            deobfuscated = std::move(expanded);

            // 2. Remove line continuations (space + underscore + newline)
            std::string cleaned;
            cleaned.reserve(deobfuscated.size());
            for (size_t i = 0; i < deobfuscated.size(); ++i) {
                if (deobfuscated[i] == ' ' && i + 1 < deobfuscated.size() && deobfuscated[i + 1] == '_') {
                    size_t j = i + 2;
                    while (j < deobfuscated.size() && (deobfuscated[j] == '\r' || deobfuscated[j] == '\n')) j++;
                    if (j > i + 2) { i = j - 1; continue; }
                }
                cleaned += deobfuscated[i];
            }
            deobfuscated = std::move(cleaned);

            SS_LOG_DEBUG(L"DocumentScanner", L"Macro deobfuscation: %zu -> %zu bytes",
                obfuscatedCode.size(), deobfuscated.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DeobfuscateMacro - Exception: %hs", e.what());
            return obfuscatedCode;
        }

        return deobfuscated;
    }

    // ========================================================================
    // OLE ANALYSIS
    // ========================================================================

    [[nodiscard]] std::vector<OLEObjectInfo> ExtractOLEObjects(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        std::vector<OLEObjectInfo> objects;

        try {
            auto streams = ListOLEStreamsInternal(filePath);

            for (const auto& stream : streams) {
                // Look for embedded objects
                if (stream.find("ObjectPool") != std::string::npos ||
                    stream.find("\\x01Ole") != std::string::npos) {

                    OLEObjectInfo objInfo;
                    objInfo.displayName = StringUtils::ToWide(stream);

                    // Extract object data (simplified - full implementation would parse OLE structure)
                    // This would use a proper OLE parser library in production

                    objects.push_back(objInfo);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::ExtractOLEObjects - Exception: %hs", e.what());
        }

        return objects;
    }

    [[nodiscard]] std::vector<std::string> ListOLEStreams(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        return ListOLEStreamsInternal(filePath);
    }

    // ========================================================================
    // PDF ANALYSIS
    // ========================================================================

    [[nodiscard]] std::vector<PDFObjectInfo> AnalyzePDF(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);
        std::vector<PDFObjectInfo> objects;

        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) {
                SS_LOG_ERROR(L"DocumentScanner", L"Cannot open PDF file");
                return objects;
            }

            // Cap file read to 100MB
            file.seekg(0, std::ios::end);
            auto fileSize = file.tellg();
            if (fileSize <= 0 || fileSize > 100 * 1024 * 1024) {
                SS_LOG_WARN(L"DocumentScanner", L"PDF file too large or empty (%lld bytes)", static_cast<long long>(fileSize));
                return objects;
            }
            file.seekg(0);

            std::string content(static_cast<size_t>(fileSize), '\0');
            file.read(content.data(), fileSize);

            // Parse PDF objects manually: "<num> <gen> obj ... endobj"
            constexpr size_t kMaxObjects = 5000;
            size_t pos = 0;
            while (pos < content.size() && objects.size() < kMaxObjects) {
                // Find digit sequence followed by space, digit, space, "obj"
                size_t numStart = std::string::npos;
                for (size_t i = pos; i < content.size() - 5; ++i) {
                    if (std::isdigit(static_cast<unsigned char>(content[i]))) {
                        // Parse first number
                        size_t j = i;
                        while (j < content.size() && std::isdigit(static_cast<unsigned char>(content[j]))) j++;
                        if (j >= content.size() || content[j] != ' ') { pos = j; continue; }
                        j++; // skip space
                        // Parse second number (generation)
                        if (j >= content.size() || !std::isdigit(static_cast<unsigned char>(content[j]))) { pos = j; continue; }
                        while (j < content.size() && std::isdigit(static_cast<unsigned char>(content[j]))) j++;
                        // Check for " obj"
                        if (j + 4 <= content.size() && content.substr(j, 4) == " obj") {
                            numStart = i;
                            pos = j + 4;
                            break;
                        }
                        pos = j;
                        continue;
                    }
                    pos = i + 1;
                }
                if (numStart == std::string::npos) break;

                // Parse object ID
                uint32_t objId = 0;
                auto [ptr, ec] = std::from_chars(content.data() + numStart, 
                    content.data() + content.find(' ', numStart), objId);
                if (ec != std::errc{}) { continue; }

                // Find endobj
                size_t objEnd = content.find("endobj", pos);
                if (objEnd == std::string::npos) break;

                // Cap object content to 1MB
                size_t objContentLen = std::min(objEnd - pos, static_cast<size_t>(1024 * 1024));
                std::string_view objContent(content.data() + pos, objContentLen);

                PDFObjectInfo objInfo;
                objInfo.objectId = objId;

                // Check for JavaScript
                if (objContent.find("/JavaScript") != std::string_view::npos ||
                    objContent.find("/JS") != std::string_view::npos) {
                    objInfo.hasJavaScript = true;
                    objInfo.objectType = "JavaScript";
                    // Extract JS content from stream if present
                    std::string objStr(objContent);
                    ExtractPDFJavaScriptFromObject(objStr, objInfo);
                }

                // Check for malicious actions
                for (const auto& action : MALICIOUS_PDF_ACTIONS) {
                    if (objContent.find(action) != std::string_view::npos) {
                        objInfo.hasAction = true;
                        objInfo.actionType = action;
                        break;
                    }
                }

                // Check for embedded files
                if (objContent.find("/EmbeddedFile") != std::string_view::npos) {
                    objInfo.hasEmbeddedFile = true;
                }

                if (objInfo.hasJavaScript || objInfo.hasAction || objInfo.hasEmbeddedFile) {
                    objects.push_back(objInfo);
                }

                pos = objEnd + 6; // Skip past "endobj"
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::AnalyzePDF - Exception: %hs", e.what());
        }

        return objects;
    }

    [[nodiscard]] std::vector<std::string> ExtractPDFJavaScript(const std::wstring& filePath) const {
        std::vector<std::string> scripts;

        try {
            auto objects = AnalyzePDF(filePath);

            for (const auto& obj : objects) {
                if (obj.hasJavaScript && !obj.javaScriptCode.empty()) {
                    scripts.push_back(obj.javaScriptCode);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::ExtractPDFJavaScript - Exception: %hs", e.what());
        }

        return scripts;
    }

    // ========================================================================
    // IOC EXTRACTION
    // ========================================================================

    [[nodiscard]] DocumentScanResult ExtractIOCs(const std::wstring& filePath) const {
        std::shared_lock lock(m_mutex);

        DocumentScanResult result;
        result.filePath = filePath;

        try {
            // Read file content
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return result;

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();

            ExtractIOCsFromContent(content, result);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DocumentScanner::ExtractIOCs - Exception: %hs", e.what());
        }

        return result;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetProgressCallback(DocumentProgressCallback callback) {
        std::unique_lock lock(m_mutex);
        m_progressCallback = std::move(callback);
    }

    void SetThreatCallback(ThreatCallback callback) {
        std::unique_lock lock(m_mutex);
        m_threatCallback = std::move(callback);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const DocumentScannerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    [[nodiscard]] DocumentScannerSnapshotStats GetStatisticsSnapshot() const noexcept {
        DocumentScannerSnapshotStats snap;
        snap.documentsScanned = m_stats.documentsScanned.load(std::memory_order_relaxed);
        snap.macrosDetected = m_stats.macrosDetected.load(std::memory_order_relaxed);
        snap.maliciousMacros = m_stats.maliciousMacros.load(std::memory_order_relaxed);
        snap.oleObjectsDetected = m_stats.oleObjectsDetected.load(std::memory_order_relaxed);
        snap.pdfJavaScriptDetected = m_stats.pdfJavaScriptDetected.load(std::memory_order_relaxed);
        snap.cvesDetected = m_stats.cvesDetected.load(std::memory_order_relaxed);
        snap.maliciousDocuments = m_stats.maliciousDocuments.load(std::memory_order_relaxed);
        return snap;
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_initialized;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    [[nodiscard]] DocumentType DetectDocumentType(const std::wstring& filePath) const {
        try {
            auto& fta = FileTypeAnalyzer::Instance();
            auto fileInfo = fta.Analyze(filePath);

            if (!fileInfo.detected) {
                return DocumentType::Unknown;
            }

            // Map FileFormat to DocumentType using enterprise FileTypeAnalyzer
            switch (fileInfo.format) {
                case FileFormat::PDF:  return DocumentType::PDF;
                case FileFormat::DOC: {
                    if (fileInfo.isCompound) {
                        auto ext = fs::path(filePath).extension().string();
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                        if (ext == ".xls") return DocumentType::XLS;
                        if (ext == ".ppt") return DocumentType::PPT;
                        if (ext == ".msg") return DocumentType::MSG;
                    }
                    return DocumentType::DOC;
                }
                case FileFormat::DOCX: {
                    auto ext = fs::path(filePath).extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if (ext == ".docm") return DocumentType::DOCM;
                    if (ext == ".dotm") return DocumentType::DOTM;
                    if (ext == ".xlsx") return DocumentType::XLSX;
                    if (ext == ".xlsm") return DocumentType::XLSM;
                    if (ext == ".xlsb") return DocumentType::XLSB;
                    if (ext == ".pptx") return DocumentType::PPTX;
                    if (ext == ".pptm") return DocumentType::PPTM;
                    return DocumentType::DOCX;
                }
                case FileFormat::XLS:  return DocumentType::XLS;
                case FileFormat::XLSX: return DocumentType::XLSX;
                case FileFormat::PPT:  return DocumentType::PPT;
                case FileFormat::PPTX: return DocumentType::PPTX;
                case FileFormat::RTF:  return DocumentType::RTF;
                default: break;
            }

            // Extension fallback for types not in FileFormat
            if (fileInfo.category == FileCategory::Document ||
                fileInfo.category == FileCategory::Spreadsheet ||
                fileInfo.category == FileCategory::Presentation) {
                auto ext = fs::path(filePath).extension().string();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".eml") return DocumentType::EML;
                if (ext == ".msg") return DocumentType::MSG;
                if (ext == ".dot") return DocumentType::DOT;
            }

            if (fileInfo.isSpoofed) {
                SS_LOG_WARN(L"DocumentScanner", L"File type spoofing detected: %ls",
                    filePath.c_str());
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"DetectDocumentType - Exception: %hs", e.what());
        }

        return DocumentType::Unknown;
    }

    [[nodiscard]] bool CheckKnownMalwareHash(const std::wstring& filePath,
                                            DocumentScanResult& result) const {
        try {
            // Use enterprise FileHasher for hash computation
            auto& hasher = FileHasher::Instance();
            auto hash = hasher.ComputeSHA256(filePath);
            if (hash.empty()) return false;

            // Check against HashStore known malware database
            if (m_hashStore) {
                auto lookupResult = m_hashStore->LookupHashString(hash, HashStore::HashType::SHA256);
                if (lookupResult.has_value()) {
                    DocumentThreat threat;
                    threat.type = ThreatType::CVEExploit;
                    threat.severity = 100;
                    threat.description = "Known malware hash match: " + hash;
                    threat.evidence = hash;
                    threat.location = "File hash";
                    threat.mitreId = "T1566.001";

                    result.threats.push_back(threat);
                    result.criticalThreats++;
                    ReportThreat(threat);

                    SS_LOG_FATAL(L"DocumentScanner", L"Known malware detected: %hs", hash.c_str());
                    return true;
                }
            }

            // Check file reputation
            auto& reputation = FileReputation::Instance();
            const auto reputationResult = reputation.CheckHash(hash, QueryMode::CloudEnabled);
            if (reputationResult.isMalicious || reputationResult.score <= -80) {
                DocumentThreat threat;
                threat.type = ThreatType::CVEExploit;
                threat.severity = 85;
                threat.description = "Very low file reputation score";
                threat.evidence = "Reputation: " + std::to_string(reputationResult.score);
                threat.location = "Cloud reputation";
                threat.mitreId = "T1566.001";

                result.threats.push_back(threat);
                result.highThreats++;
                ReportThreat(threat);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"CheckKnownMalwareHash - Exception: %hs", e.what());
        }

        return false;
    }

    void AnalyzePDFDocument(const std::wstring& filePath,
                           const DocumentScannerConfig& config,
                           DocumentScanResult& result) {
        try {
            if (!config.analyzePDFJavaScript) return;

            result.pdfObjects = AnalyzePDF(filePath);

            for (const auto& obj : result.pdfObjects) {
                if (obj.hasJavaScript) {
                    result.hasPDFJavaScript = true;
                    m_stats.pdfJavaScriptDetected.fetch_add(1, std::memory_order_relaxed);

                    DocumentThreat threat;
                    threat.type = ThreatType::PDFJavaScript;
                    threat.severity = 60;
                    threat.description = "PDF contains JavaScript";
                    threat.location = "Object " + std::to_string(obj.objectId);
                    threat.evidence = obj.javaScriptCode.substr(0, 500);
                    threat.mitreId = "T1059.007";

                    result.threats.push_back(threat);
                    result.mediumThreats++;
                    ReportThreat(threat);
                }

                if (obj.hasAction) {
                    result.hasPDFActions = true;

                    DocumentThreat threat;
                    threat.type = ThreatType::PDFLaunchAction;
                    threat.severity = 70;
                    threat.description = "Suspicious PDF action: " + obj.actionType;
                    threat.location = "Object " + std::to_string(obj.objectId);
                    threat.mitreId = "T1204.002";

                    result.threats.push_back(threat);
                    result.highThreats++;
                    ReportThreat(threat);
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzePDFDocument - Exception: %hs", e.what());
            result.errors.push_back(std::string("PDF analysis error: ") + e.what());
        }
    }

    void AnalyzeLegacyOfficeDocument(const std::wstring& filePath,
                                     const DocumentScannerConfig& config,
                                     DocumentScanResult& result) {
        try {
            // Extract macros
            if (config.analyzeMacros) {
                result.macros = ExtractOLEMacros(filePath);
                result.macroCount = static_cast<uint32_t>(result.macros.size());
                result.hasMacros = (result.macroCount > 0);

                if (result.hasMacros) {
                    m_stats.macrosDetected.fetch_add(1, std::memory_order_relaxed);

                    for (const auto& macro : result.macros) {
                        if (macro.riskLevel > result.highestMacroRisk) {
                            result.highestMacroRisk = macro.riskLevel;
                        }

                        if (macro.riskLevel >= MacroRisk::High) {
                            m_stats.maliciousMacros.fetch_add(1, std::memory_order_relaxed);

                            DocumentThreat threat;
                            threat.type = macro.isAutoExec ? ThreatType::AutoExecMacro : ThreatType::VBAMacro;
                            threat.severity = static_cast<uint8_t>(macro.riskLevel) * 25;
                            threat.description = "Suspicious VBA macro: " + macro.moduleName;
                            threat.location = "VBA Module: " + macro.moduleName;
                            threat.evidence = macro.sourceCode.substr(0, 500);
                            threat.mitreId = "T1059.005";

                            for (const auto& api : macro.apiCalls) {
                                threat.indicators.push_back("API: " + api);
                            }

                            result.threats.push_back(threat);
                            if (threat.severity >= 75) result.highThreats++;
                            else result.mediumThreats++;

                            ReportThreat(threat);
                        }
                    }
                }
            }

            // Extract OLE objects
            if (config.analyzeOLEObjects) {
                result.oleObjects = ExtractOLEObjects(filePath);
                result.oleObjectCount = static_cast<uint32_t>(result.oleObjects.size());
                result.hasOLEObjects = (result.oleObjectCount > 0);

                if (result.hasOLEObjects) {
                    m_stats.oleObjectsDetected.fetch_add(1, std::memory_order_relaxed);

                    for (const auto& oleObj : result.oleObjects) {
                        if (oleObj.isExecutable || oleObj.hasAutoStart) {
                            DocumentThreat threat;
                            threat.type = oleObj.isExecutable ? ThreatType::OLEExecutable : ThreatType::OLEAutoOpen;
                            threat.severity = 80;
                            threat.description = "Suspicious OLE object";
                            threat.location = "OLE: " + StringUtils::ToNarrow(oleObj.displayName);
                            threat.mitreId = "T1204.002";

                            result.threats.push_back(threat);
                            result.highThreats++;
                            ReportThreat(threat);
                        }
                    }
                }
            }

            // Check for DDE
            CheckForDDE(filePath, result);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzeLegacyOfficeDocument - Exception: %hs", e.what());
            result.errors.push_back(std::string("Legacy Office analysis error: ") + e.what());
        }
    }

    void AnalyzeOOXMLDocument(const std::wstring& filePath,
                              const DocumentScannerConfig& config,
                              DocumentScanResult& result) {
        try {
            // OOXML is a ZIP archive - extract and analyze

            // Check for macros in vbaProject.bin
            if (config.analyzeMacros) {
                result.macros = ExtractOOXMLMacros(filePath);
                result.macroCount = static_cast<uint32_t>(result.macros.size());
                result.hasMacros = (result.macroCount > 0);

                if (result.hasMacros) {
                    m_stats.macrosDetected.fetch_add(1, std::memory_order_relaxed);

                    for (auto& macro : result.macros) {
                        AnalyzeMacroCode(macro);

                        if (macro.riskLevel > result.highestMacroRisk) {
                            result.highestMacroRisk = macro.riskLevel;
                        }

                        if (macro.riskLevel >= MacroRisk::High) {
                            m_stats.maliciousMacros.fetch_add(1, std::memory_order_relaxed);

                            DocumentThreat threat;
                            threat.type = macro.isAutoExec ? ThreatType::AutoExecMacro : ThreatType::VBAMacro;
                            threat.severity = static_cast<uint8_t>(macro.riskLevel) * 25;
                            threat.description = "Suspicious VBA macro: " + macro.moduleName;
                            threat.location = "VBA Module: " + macro.moduleName;
                            threat.evidence = macro.sourceCode.substr(0, 500);
                            threat.mitreId = "T1059.005";

                            for (const auto& api : macro.apiCalls) {
                                threat.indicators.push_back("API: " + api);
                            }

                            result.threats.push_back(threat);
                            if (threat.severity >= 75) result.highThreats++;
                            else result.mediumThreats++;

                            ReportThreat(threat);
                        }
                    }
                }
            }

            // Check for external template injection (T1221)
            CheckTemplateInjection(filePath, result);

            // Check for external links
            CheckExternalLinks(filePath, result);

            // Check for DDE in OOXML
            CheckForDDE(filePath, result);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzeOOXMLDocument - Exception: %hs", e.what());
            result.errors.push_back(std::string("OOXML analysis error: ") + e.what());
        }
    }

    void AnalyzeRTFDocument(const std::wstring& filePath,
                           const DocumentScannerConfig& config,
                           DocumentScanResult& result) {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return;

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();

            // Check for OLE objects in RTF
            if (content.find("\\objdata") != std::string::npos) {
                result.hasOLEObjects = true;

                DocumentThreat threat;
                threat.type = ThreatType::RTFOLEObject;
                threat.severity = 60;
                threat.description = "RTF contains OLE objects";
                threat.mitreId = "T1221";

                result.threats.push_back(threat);
                result.mediumThreats++;
                ReportThreat(threat);
            }

            // Check for known RTF exploits
            if (config.detectCVEs) {
                for (const auto& [pattern, cve] : CVE_PATTERNS) {
                    if (content.find(pattern) != std::string::npos) {
                        m_stats.cvesDetected.fetch_add(1, std::memory_order_relaxed);

                        DocumentThreat threat;
                        threat.type = ThreatType::CVEExploit;
                        threat.severity = 90;
                        threat.description = "Known RTF exploit detected";
                        threat.cveId = cve;
                        threat.cveName = cve;
                        threat.location = "RTF body";
                        threat.mitreId = "T1203";

                        result.threats.push_back(threat);
                        result.criticalThreats++;
                        ReportThreat(threat);
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzeRTFDocument - Exception: %hs", e.what());
            result.errors.push_back(std::string("RTF analysis error: ") + e.what());
        }
    }

    void AnalyzePDFBuffer(std::span<const uint8_t> buffer, DocumentScanResult& result) {
        try {
            std::string content(buffer.begin(), buffer.end());

            // Quick JavaScript check
            if (content.find("/JavaScript") != std::string::npos ||
                content.find("/JS") != std::string::npos) {
                result.hasPDFJavaScript = true;

                DocumentThreat threat;
                threat.type = ThreatType::PDFJavaScript;
                threat.severity = 60;
                threat.description = "PDF contains JavaScript";
                threat.mitreId = "T1059.007";

                result.threats.push_back(threat);
                result.mediumThreats++;
            }

            // Check for malicious actions
            for (const auto& action : MALICIOUS_PDF_ACTIONS) {
                if (content.find(action) != std::string::npos) {
                    result.hasPDFActions = true;

                    DocumentThreat threat;
                    threat.type = ThreatType::PDFLaunchAction;
                    threat.severity = 70;
                    threat.description = "Suspicious PDF action: " + action;
                    threat.mitreId = "T1204.002";

                    result.threats.push_back(threat);
                    result.highThreats++;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzePDFBuffer - Exception: %hs", e.what());
        }
    }

    void AnalyzeRTFBuffer(std::span<const uint8_t> buffer, DocumentScanResult& result) {
        try {
            std::string content(buffer.begin(), buffer.end());

            // Check for exploits
            for (const auto& [pattern, cve] : CVE_PATTERNS) {
                if (content.find(pattern) != std::string::npos) {
                    DocumentThreat threat;
                    threat.type = ThreatType::CVEExploit;
                    threat.severity = 90;
                    threat.description = "Known RTF exploit: " + cve;
                    threat.cveId = cve;
                    threat.mitreId = "T1203";

                    result.threats.push_back(threat);
                    result.criticalThreats++;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzeRTFBuffer - Exception: %hs", e.what());
        }
    }

    [[nodiscard]] std::vector<MacroInfo> ExtractOLEMacros(const std::wstring& filePath) const {
        std::vector<MacroInfo> macros;

        try {
            auto streams = ListOLEStreamsInternal(filePath);
            if (streams.empty()) return macros;

            bool hasVBAProject = false;
            for (const auto& stream : streams) {
                if (stream.find("VBA") != std::string::npos ||
                    stream.find("_VBA_PROJECT") != std::string::npos ||
                    stream.find("Macros") != std::string::npos) {
                    hasVBAProject = true;
                    break;
                }
            }
            if (!hasVBAProject) return macros;

            // Read file for VBA extraction
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file) return macros;

            const auto fileSize = file.tellg();
            if (fileSize > static_cast<std::streamoff>(MAX_DOCUMENT_SIZE)) return macros;
            file.seekg(0);

            std::vector<uint8_t> fileData(static_cast<size_t>(fileSize));
            file.read(reinterpret_cast<char*>(fileData.data()), fileSize);

            // Search for VBA module signatures via Attribute VB_Name directives
            std::string content(fileData.begin(), fileData.end());
            const std::string vbNameMarker = "Attribute VB_Name = \"";
            size_t searchPos = 0;

            while ((searchPos = content.find(vbNameMarker, searchPos)) != std::string::npos) {
                searchPos += vbNameMarker.length();
                size_t nameEnd = content.find('"', searchPos);
                if (nameEnd == std::string::npos || nameEnd - searchPos > 256) break;

                MacroInfo macro;
                macro.moduleName = content.substr(searchPos, nameEnd - searchPos);
                macro.moduleType = "Module";

                // Extract source code block (find readable text around this module)
                size_t codeEnd = content.find(vbNameMarker, searchPos);
                if (codeEnd == std::string::npos) codeEnd = std::min(searchPos + 100000, content.size());
                codeEnd = std::min(codeEnd, searchPos + 100000);

                // Filter non-printable characters for readable VBA source
                std::string codeBlock;
                codeBlock.reserve(codeEnd - searchPos);
                for (size_t i = searchPos; i < codeEnd; ++i) {
                    char c = content[i];
                    if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
                        codeBlock += c;
                    }
                }

                if (codeBlock.size() > m_config.maxMacroSize) {
                    codeBlock.resize(m_config.maxMacroSize);
                }
                macro.sourceCode = std::move(codeBlock);
                macro.lineCount = static_cast<uint32_t>(
                    std::count(macro.sourceCode.begin(), macro.sourceCode.end(), '\n') + 1);

                macros.push_back(std::move(macro));
                searchPos = nameEnd + 1;

                if (macros.size() >= 200) break;
            }

            // Fallback: VBA streams found but no Attribute directives
            if (macros.empty()) {
                for (const auto& stream : streams) {
                    if (stream.find("VBA") != std::string::npos && stream != "_VBA_PROJECT") {
                        MacroInfo macro;
                        macro.moduleName = stream;
                        macro.moduleType = "Module";
                        macro.sourceCode = "[Binary VBA content in stream: " + stream + "]";
                        macro.lineCount = 1;
                        macros.push_back(std::move(macro));
                    }
                }
            }

            SS_LOG_DEBUG(L"DocumentScanner", L"Extracted %zu OLE macros from %ls", macros.size(), filePath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractOLEMacros - Exception: %hs", e.what());
        }

        return macros;
    }

    [[nodiscard]] std::vector<MacroInfo> ExtractOOXMLMacros(const std::wstring& filePath) const {
        std::vector<MacroInfo> macros;

        try {
            // OOXML stores macros in vbaProject.bin inside the ZIP archive
            // Try multiple known locations for the VBA project binary
            auto& archiveExtractor = ArchiveExtractor::Instance();

            const std::vector<std::wstring> vbaProjectPaths = {
                L"word/vbaProject.bin",
                L"xl/vbaProject.bin",
                L"ppt/vbaProject.bin",
                L"vbaProject.bin"
            };

            for (const auto& vbaPath : vbaProjectPaths) {
                try {
                    auto extracted = archiveExtractor.ExtractEntry(filePath, vbaPath);
                    if (extracted.data.empty()) continue;

                    SS_LOG_DEBUG(L"DocumentScanner", L"Found VBA project at %ls (%zu bytes)",
                        vbaPath.c_str(), extracted.data.size());

                    // Write extracted OLE binary to temp for OLE parsing
                    // Parse the extracted vbaProject.bin as an OLE compound file
                    std::string oleContent(extracted.data.begin(), extracted.data.end());

                    // Search for VBA module Attribute directives in the OLE binary
                    const std::string vbNameMarker = "Attribute VB_Name = \"";
                    size_t searchPos = 0;

                    while ((searchPos = oleContent.find(vbNameMarker, searchPos)) != std::string::npos) {
                        searchPos += vbNameMarker.length();
                        size_t nameEnd = oleContent.find('"', searchPos);
                        if (nameEnd == std::string::npos || nameEnd - searchPos > 256) break;

                        MacroInfo macro;
                        macro.moduleName = oleContent.substr(searchPos, nameEnd - searchPos);
                        macro.moduleType = "Module";

                        // Extract readable source code
                        size_t codeEnd = oleContent.find(vbNameMarker, searchPos);
                        if (codeEnd == std::string::npos) codeEnd = std::min(searchPos + 100000, oleContent.size());
                        codeEnd = std::min(codeEnd, searchPos + 100000);

                        std::string codeBlock;
                        codeBlock.reserve(codeEnd - searchPos);
                        for (size_t i = searchPos; i < codeEnd; ++i) {
                            char c = oleContent[i];
                            if ((c >= 0x20 && c <= 0x7E) || c == '\n' || c == '\r' || c == '\t') {
                                codeBlock += c;
                            }
                        }

                        if (codeBlock.size() > m_config.maxMacroSize) {
                            codeBlock.resize(m_config.maxMacroSize);
                        }
                        macro.sourceCode = std::move(codeBlock);
                        macro.lineCount = static_cast<uint32_t>(
                            std::count(macro.sourceCode.begin(), macro.sourceCode.end(), '\n') + 1);

                        macros.push_back(std::move(macro));
                        searchPos = nameEnd + 1;

                        if (macros.size() >= 200) break;
                    }

                    // If we found the vbaProject.bin, stop searching other paths
                    if (!macros.empty()) break;

                    // Fallback: OLE binary present but no Attribute directives found
                    MacroInfo macro;
                    macro.moduleName = "vbaProject";
                    macro.moduleType = "Binary";
                    macro.sourceCode = "[Binary VBA project detected, size: " + std::to_string(extracted.data.size()) + " bytes]";
                    macro.lineCount = 1;
                    macros.push_back(std::move(macro));
                    break;

                } catch (...) {
                    continue; // Path not found in archive, try next
                }
            }

            SS_LOG_DEBUG(L"DocumentScanner", L"Extracted %zu OOXML macros from %ls", macros.size(), filePath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractOOXMLMacros - Exception: %hs", e.what());
        }

        return macros;
    }

    void AnalyzeMacroCode(MacroInfo& macro) const {
        try {
            const std::string& code = macro.sourceCode;

            // Calculate entropy
            macro.entropy = CalculateEntropy(code);
            if (macro.entropy > DocumentScannerConstants::SUSPICIOUS_ENTROPY_THRESHOLD) {
                macro.isObfuscated = true;
            }

            // Convert to lowercase for case-insensitive matching
            std::string lowerCode = code;
            std::transform(lowerCode.begin(), lowerCode.end(), lowerCode.begin(), ::tolower);

            // Check for auto-exec functions
            for (const auto& autoExec : VBA_AUTOEXEC_FUNCTIONS) {
                std::string lowerAutoExec = autoExec;
                std::transform(lowerAutoExec.begin(), lowerAutoExec.end(),
                              lowerAutoExec.begin(), ::tolower);

                if (lowerCode.find(lowerAutoExec) != std::string::npos) {
                    macro.isAutoExec = true;
                    break;
                }
            }

            // Check for suspicious API calls
            for (const auto& api : SUSPICIOUS_VBA_APIS) {
                std::string lowerApi = api;
                std::transform(lowerApi.begin(), lowerApi.end(), lowerApi.begin(), ::tolower);

                if (lowerCode.find(lowerApi) != std::string::npos) {
                    macro.apiCalls.push_back(api);

                    // Set specific flags
                    if (api.find("Shell") != std::string::npos ||
                        api.find("Exec") != std::string::npos) {
                        macro.hasShellExec = true;
                    }
                    if (api.find("PowerShell") != std::string::npos) {
                        macro.hasPowerShell = true;
                    }
                    if (api.find("Download") != std::string::npos ||
                        api.find("XMLHTTP") != std::string::npos) {
                        macro.hasDownload = true;
                    }
                    if (api.find("SaveAs") != std::string::npos ||
                        api.find("WriteText") != std::string::npos) {
                        macro.hasFileWrite = true;
                    }
                    if (api.find("Reg") != std::string::npos) {
                        macro.hasRegistryAccess = true;
                    }
                    if (api.find("WMI") != std::string::npos ||
                        api.find("Win32_") != std::string::npos) {
                        macro.hasWMI = true;
                    }
                }
            }

            // Extract IOCs
            ExtractURLs(code, macro.urls);
            ExtractIPs(code, macro.ips);

            // Calculate risk level
            uint32_t riskScore = 0;
            if (macro.isAutoExec) riskScore += 20;
            if (macro.isObfuscated) riskScore += 25;
            if (macro.hasShellExec) riskScore += 30;
            if (macro.hasPowerShell) riskScore += 25;
            if (macro.hasDownload) riskScore += 20;
            if (macro.hasWMI) riskScore += 15;
            if (!macro.urls.empty()) riskScore += 20;

            if (riskScore >= 80) macro.riskLevel = MacroRisk::Critical;
            else if (riskScore >= 60) macro.riskLevel = MacroRisk::High;
            else if (riskScore >= 30) macro.riskLevel = MacroRisk::Medium;
            else if (riskScore > 0) macro.riskLevel = MacroRisk::Low;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"AnalyzeMacroCode - Exception: %hs", e.what());
        }
    }

    [[nodiscard]] std::vector<std::string> ListOLEStreamsInternal(const std::wstring& filePath) const {
        std::vector<std::string> streams;
        constexpr size_t MAX_DIR_ENTRIES = 10000;

        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return streams;

            // Read and validate CFB header (512 bytes)
            std::vector<uint8_t> header(512);
            file.read(reinterpret_cast<char*>(header.data()), 512);
            if (!file || file.gcount() < 512) return streams;

            // Verify OLE magic signature
            if (!std::equal(std::begin(OLE_SIGNATURE), std::end(OLE_SIGNATURE), header.begin())) {
                return streams;
            }

            // Parse sector size: 2^header[0x1E] (typically 512 for v3, 4096 for v4)
            const uint16_t sectorSizePow = *reinterpret_cast<const uint16_t*>(&header[0x1E]);
            if (sectorSizePow < 7 || sectorSizePow > 16) return streams; // Sanity check
            const uint32_t sectorSize = 1u << sectorSizePow;

            // First directory sector SECT (at offset 0x30)
            const uint32_t firstDirSect = *reinterpret_cast<const uint32_t*>(&header[0x30]);
            if (firstDirSect == 0xFFFFFFFE) return streams; // ENDOFCHAIN

            // Read FAT sectors from DIFAT in header (109 entries at offset 0x4C)
            const uint32_t fatSectors = *reinterpret_cast<const uint32_t*>(&header[0x2C]);
            if (fatSectors > 10000) return streams; // Cap for safety

            // Build FAT table
            std::vector<uint32_t> fat;
            const uint32_t entriesPerSector = sectorSize / 4;
            for (uint32_t fi = 0; fi < std::min(fatSectors, 109u); ++fi) {
                uint32_t fatSectId = *reinterpret_cast<const uint32_t*>(&header[0x4C + fi * 4]);
                if (fatSectId == 0xFFFFFFFE || fatSectId == 0xFFFFFFFF) break;

                std::vector<uint8_t> fatSectData(sectorSize);
                file.seekg(512 + static_cast<std::streamoff>(fatSectId) * sectorSize);
                file.read(reinterpret_cast<char*>(fatSectData.data()), sectorSize);
                if (!file) break;

                for (uint32_t j = 0; j < entriesPerSector; ++j) {
                    fat.push_back(*reinterpret_cast<const uint32_t*>(&fatSectData[j * 4]));
                }
            }

            // Traverse directory sector chain and read directory entries
            uint32_t dirSect = firstDirSect;
            size_t dirEntriesRead = 0;
            constexpr uint32_t DIR_ENTRY_SIZE = 128;
            const uint32_t entriesPerDirSector = sectorSize / DIR_ENTRY_SIZE;

            while (dirSect != 0xFFFFFFFE && dirSect != 0xFFFFFFFF && dirEntriesRead < MAX_DIR_ENTRIES) {
                if (dirSect >= fat.size()) break; // Invalid sector reference

                std::vector<uint8_t> dirData(sectorSize);
                file.seekg(512 + static_cast<std::streamoff>(dirSect) * sectorSize);
                file.read(reinterpret_cast<char*>(dirData.data()), sectorSize);
                if (!file) break;

                for (uint32_t e = 0; e < entriesPerDirSector && dirEntriesRead < MAX_DIR_ENTRIES; ++e) {
                    const uint8_t* entry = &dirData[e * DIR_ENTRY_SIZE];
                    const uint8_t objectType = entry[0x42];

                    // objectType: 0=unknown/empty, 1=storage, 2=stream, 5=root
                    if (objectType == 0) continue;

                    // Read name (UTF-16LE, 64 bytes max)
                    const uint16_t nameSize = *reinterpret_cast<const uint16_t*>(&entry[0x40]);
                    if (nameSize == 0 || nameSize > 64) { dirEntriesRead++; continue; }

                    std::wstring wname(reinterpret_cast<const wchar_t*>(entry), nameSize / 2);
                    // Remove null terminator
                    while (!wname.empty() && wname.back() == L'\\0') wname.pop_back();

                    std::string name = StringUtils::ToNarrow(wname);
                    if (!name.empty()) {
                        streams.push_back(name);
                    }
                    dirEntriesRead++;
                }

                // Follow the FAT chain to next directory sector
                dirSect = fat[dirSect];
            }

            SS_LOG_DEBUG(L"DocumentScanner", L"OLE streams found: %zu in %ls", streams.size(), filePath.c_str());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ListOLEStreamsInternal - Exception: %hs", e.what());
        }

        return streams;
    }

    void ExtractPDFJavaScriptFromObject(const std::string& objContent, PDFObjectInfo& objInfo) const {
        try {
            // Look for JavaScript streams
            size_t jsStart = objContent.find("/JS");
            if (jsStart == std::string::npos) {
                jsStart = objContent.find("/JavaScript");
            }

            if (jsStart != std::string::npos) {
                // Extract the JavaScript code (simplified - full parser would handle encoding)
                size_t streamStart = objContent.find("stream", jsStart);
                size_t streamEnd = objContent.find("endstream", streamStart);

                if (streamStart != std::string::npos && streamEnd != std::string::npos) {
                    objInfo.javaScriptCode = objContent.substr(
                        streamStart + 6, streamEnd - streamStart - 6);

                    // Limit size
                    if (objInfo.javaScriptCode.size() > MAX_JAVASCRIPT_SIZE) {
                        objInfo.javaScriptCode.resize(MAX_JAVASCRIPT_SIZE);
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractPDFJavaScriptFromObject - Exception: %hs", e.what());
        }
    }

    void CheckForDDE(const std::wstring& filePath, DocumentScanResult& result) {
        try {
            std::ifstream file(filePath, std::ios::binary);
            if (!file) return;

            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string content = buffer.str();

            // Look for DDE patterns
            if (content.find("DDE") != std::string::npos ||
                content.find("DDEAUTO") != std::string::npos) {

                result.hasDDELinks = true;

                DocumentThreat threat;
                threat.type = ThreatType::DDELink;
                threat.severity = 75;
                threat.description = "Document contains DDE links";
                threat.mitreId = "T1559.002";

                result.threats.push_back(threat);
                result.highThreats++;
                ReportThreat(threat);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"CheckForDDE - Exception: %hs", e.what());
        }
    }

    void CheckTemplateInjection(const std::wstring& filePath, DocumentScanResult& result) {
        try {
            // Extract and parse OOXML relationship files for external template references (T1221)
            auto& archiveExtractor = ArchiveExtractor::Instance();

            const std::vector<std::wstring> relsPaths = {
                L"word/_rels/settings.xml.rels",
                L"word/_rels/document.xml.rels",
                L"xl/_rels/workbook.xml.rels",
                L"ppt/_rels/presentation.xml.rels"
            };

            for (const auto& relsPath : relsPaths) {
                try {
                    auto extracted = archiveExtractor.ExtractEntry(filePath, relsPath);
                    if (extracted.data.empty()) continue;

                    pugi::xml_document doc;
                    auto parseResult = doc.load_buffer(extracted.data.data(), extracted.data.size());
                    if (!parseResult) continue;

                    for (auto& rel : doc.child("Relationships").children("Relationship")) {
                        std::string type = rel.attribute("Type").as_string();
                        std::string target = rel.attribute("Target").as_string();
                        std::string targetMode = rel.attribute("TargetMode").as_string();

                        // Template injection: external template reference
                        if (targetMode == "External" &&
                            (type.find("attachedTemplate") != std::string::npos ||
                             type.find("oleObject") != std::string::npos ||
                             type.find("frame") != std::string::npos)) {

                            result.hasTemplateInjection = true;

                            DocumentThreat threat;
                            threat.type = ThreatType::TemplateInjection;
                            threat.severity = 85;
                            threat.description = "External template injection detected";
                            threat.evidence = "Target: " + target;
                            threat.location = StringUtils::ToNarrow(relsPath);
                            threat.mitreId = "T1221";

                            // Extract URL as IOC
                            if (target.find("http") == 0 || target.find("\\\\") == 0) {
                                threat.indicators.push_back("URL: " + target);
                                result.urls.push_back(target);
                            }

                            result.threats.push_back(threat);
                            result.highThreats++;
                            m_stats.cvesDetected.fetch_add(1, std::memory_order_relaxed);
                            ReportThreat(threat);

                            SS_LOG_WARN(L"DocumentScanner", L"Template injection: %hs -> %hs",
                                StringUtils::ToNarrow(relsPath).c_str(), target.c_str());
                        }
                    }
                } catch (...) {
                    continue;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"CheckTemplateInjection - Exception: %hs", e.what());
        }
    }

    void CheckExternalLinks(const std::wstring& filePath, DocumentScanResult& result) {
        try {
            // Parse ALL .rels files for external targets
            auto& archiveExtractor = ArchiveExtractor::Instance();

            // List archive entries to find all .rels files
            try {
                auto archiveInfo = archiveExtractor.ListContents(filePath);

                // Common .rels paths to check
                const std::vector<std::wstring> relsPaths = {
                    L"_rels/.rels",
                    L"word/_rels/document.xml.rels",
                    L"word/_rels/header1.xml.rels",
                    L"word/_rels/footer1.xml.rels",
                    L"xl/_rels/workbook.xml.rels",
                    L"xl/worksheets/_rels/sheet1.xml.rels",
                    L"ppt/_rels/presentation.xml.rels",
                    L"ppt/slides/_rels/slide1.xml.rels"
                };

                for (const auto& relsPath : relsPaths) {
                    try {
                        auto extracted = archiveExtractor.ExtractEntry(filePath, relsPath);
                        if (extracted.data.empty()) continue;

                        pugi::xml_document doc;
                        auto parseResult = doc.load_buffer(extracted.data.data(), extracted.data.size());
                        if (!parseResult) continue;

                        for (auto& rel : doc.child("Relationships").children("Relationship")) {
                            std::string targetMode = rel.attribute("TargetMode").as_string();
                            std::string target = rel.attribute("Target").as_string();

                            if (targetMode == "External" &&
                                (target.find("http://") == 0 || target.find("https://") == 0 ||
                                 target.find("ftp://") == 0 || target.find("\\\\") == 0)) {

                                result.hasExternalLinks = true;
                                result.urls.push_back(target);

                                DocumentThreat threat;
                                threat.type = ThreatType::ExternalLink;
                                threat.severity = 40;
                                threat.description = "External link: " + target;
                                threat.location = StringUtils::ToNarrow(relsPath);
                                threat.mitreId = "T1071.001";
                                threat.indicators.push_back("URL: " + target);

                                result.threats.push_back(threat);
                                result.mediumThreats++;
                            }
                        }
                    } catch (...) {
                        continue;
                    }
                }
            } catch (...) {
                // Archive listing not supported or failed
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"CheckExternalLinks - Exception: %hs", e.what());
        }
    }

    void ExtractMetadata(const std::wstring& filePath, DocumentScanResult& result) {
        try {
            auto docType = result.documentType;

            // OOXML metadata: parse docProps/core.xml
            if (docType == DocumentType::DOCX || docType == DocumentType::DOCM ||
                docType == DocumentType::DOTM || docType == DocumentType::XLSX ||
                docType == DocumentType::XLSM || docType == DocumentType::PPTX ||
                docType == DocumentType::PPTM) {

                auto& archiveExtractor = ArchiveExtractor::Instance();
                try {
                    auto extracted = archiveExtractor.ExtractEntry(filePath, L"docProps/core.xml");
                    if (!extracted.data.empty()) {
                        pugi::xml_document doc;
                        auto parseResult = doc.load_buffer(extracted.data.data(), extracted.data.size());
                        if (parseResult) {
                            auto props = doc.child("cp:coreProperties");
                            if (!props) props = doc.first_child();

                            for (auto& child : props.children()) {
                                std::string name = child.name();
                                std::string value = child.child_value();

                                if (name.find("creator") != std::string::npos && !value.empty()) {
                                    result.author = StringUtils::ToWide(value);
                                }
                                if (name.find("title") != std::string::npos && !value.empty()) {
                                    result.title = StringUtils::ToWide(value);
                                }
                                if (name.find("subject") != std::string::npos && !value.empty()) {
                                    result.subject = StringUtils::ToWide(value);
                                }
                            }
                        }
                    }
                } catch (...) {
                    // docProps/core.xml not found or parse error
                }
            }

            // PDF metadata: parse /Info dictionary
            if (docType == DocumentType::PDF) {
                std::ifstream file(filePath, std::ios::binary);
                if (!file) return;

                // Read first 64KB for metadata (usually near the end, but /Info can be early)
                const size_t readSize = std::min<size_t>(65536, static_cast<size_t>(fs::file_size(filePath)));
                std::vector<char> buf(readSize);
                file.read(buf.data(), readSize);
                std::string content(buf.begin(), buf.end());

                // Extract /Author, /Title, /Subject from PDF /Info dict
                auto extractPdfField = [&](const std::string& field) -> std::string {
                    size_t pos = content.find("/" + field);
                    if (pos == std::string::npos) return "";
                    pos = content.find('(', pos);
                    if (pos == std::string::npos) return "";
                    size_t end = content.find(')', pos + 1);
                    if (end == std::string::npos || end - pos > 512) return "";
                    return content.substr(pos + 1, end - pos - 1);
                };

                auto author = extractPdfField("Author");
                auto title = extractPdfField("Title");
                auto subject = extractPdfField("Subject");

                if (!author.empty()) result.author = StringUtils::ToWide(author);
                if (!title.empty()) result.title = StringUtils::ToWide(title);
                if (!subject.empty()) result.subject = StringUtils::ToWide(subject);
            }

            // OLE metadata: look for SummaryInformation stream
            if (docType == DocumentType::DOC || docType == DocumentType::XLS ||
                docType == DocumentType::PPT) {
                auto streams = ListOLEStreamsInternal(filePath);
                for (const auto& stream : streams) {
                    if (stream.find("SummaryInformation") != std::string::npos) {
                        SS_LOG_DEBUG(L"DocumentScanner", L"Found SummaryInformation stream in %ls", filePath.c_str());
                        break;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractMetadata - Exception: %hs", e.what());
        }
    }

    void ExtractAllIOCs(DocumentScanResult& result) {
        try {
            // Aggregate IOCs from all macros
            for (const auto& macro : result.macros) {
                result.urls.insert(result.urls.end(), macro.urls.begin(), macro.urls.end());
                result.ips.insert(result.ips.end(), macro.ips.begin(), macro.ips.end());
                result.filePaths.insert(result.filePaths.end(),
                    macro.filePaths.begin(), macro.filePaths.end());
            }

            // Remove duplicates
            std::sort(result.urls.begin(), result.urls.end());
            result.urls.erase(std::unique(result.urls.begin(), result.urls.end()),
                result.urls.end());

            std::sort(result.ips.begin(), result.ips.end());
            result.ips.erase(std::unique(result.ips.begin(), result.ips.end()),
                result.ips.end());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractAllIOCs - Exception: %hs", e.what());
        }
    }

    void ExtractIOCsFromContent(const std::string& content, DocumentScanResult& result) const {
        try {
            ExtractURLs(content, result.urls);
            ExtractIPs(content, result.ips);
            ExtractEmails(content, result.emails);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractIOCsFromContent - Exception: %hs", e.what());
        }
    }

    void ExtractURLs(const std::string& content, std::vector<std::string>& urls) const {
        try {
            // Manual URL extraction — no std::regex (ReDoS-safe, production performance)
            const size_t len = content.size();
            size_t i = 0;

            while (i < len - 8) {
                bool isUrl = false;
                size_t urlStart = i;

                // Check for http:// or https:// or ftp://
                if (i + 7 < len && content[i] == 'h' && content[i+1] == 't' && content[i+2] == 't' && content[i+3] == 'p') {
                    if (content[i+4] == ':' && content[i+5] == '/' && content[i+6] == '/') {
                        isUrl = true; i += 7;
                    } else if (i + 8 < len && content[i+4] == 's' && content[i+5] == ':' && content[i+6] == '/' && content[i+7] == '/') {
                        isUrl = true; i += 8;
                    }
                } else if (i + 6 < len && content[i] == 'f' && content[i+1] == 't' && content[i+2] == 'p' && content[i+3] == ':' && content[i+4] == '/' && content[i+5] == '/') {
                    isUrl = true; i += 6;
                }

                if (isUrl) {
                    // Scan until whitespace or terminator
                    while (i < len && content[i] != ' ' && content[i] != '\n' && content[i] != '\r' &&
                           content[i] != '\t' && content[i] != '"' && content[i] != '\'' &&
                           content[i] != ')' && content[i] != ']' && content[i] != '}' &&
                           content[i] != '>' && content[i] != '\0') {
                        i++;
                    }
                    if (i - urlStart >= 10 && i - urlStart < 2048) {
                        urls.push_back(content.substr(urlStart, i - urlStart));
                        if (urls.size() >= 1000) return; // Cap IOCs
                    }
                } else {
                    i++;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractURLs - Exception: %hs", e.what());
        }
    }

    void ExtractIPs(const std::string& content, std::vector<std::string>& ips) const {
        try {
            // Manual IPv4 extraction — no std::regex (ReDoS-safe)
            const size_t len = content.size();

            for (size_t i = 0; i < len; ++i) {
                if (content[i] < '0' || content[i] > '9') continue;

                // Try to parse N.N.N.N pattern
                int octets[4] = {0, 0, 0, 0};
                size_t pos = i;
                bool valid = true;

                for (int o = 0; o < 4 && valid; ++o) {
                    int val = 0;
                    int digits = 0;
                    while (pos < len && content[pos] >= '0' && content[pos] <= '9' && digits < 3) {
                        val = val * 10 + (content[pos] - '0');
                        pos++;
                        digits++;
                    }
                    if (digits == 0 || val > 255) { valid = false; break; }
                    octets[o] = val;

                    if (o < 3) {
                        if (pos >= len || content[pos] != '.') { valid = false; break; }
                        pos++;
                    }
                }

                // Verify it's not part of a larger number
                if (valid && pos > i + 6) {
                    if (i > 0 && (std::isalnum(static_cast<unsigned char>(content[i-1])) || content[i-1] == '.')) { i = pos; continue; }
                    if (pos < len && (std::isdigit(static_cast<unsigned char>(content[pos])) || content[pos] == '.')) { i = pos; continue; }

                    // Skip loopback and link-local
                    if (octets[0] != 127 && octets[0] != 0 && !(octets[0] == 169 && octets[1] == 254)) {
                        std::string ip = std::to_string(octets[0]) + "." + std::to_string(octets[1]) + "." +
                                        std::to_string(octets[2]) + "." + std::to_string(octets[3]);
                        ips.push_back(ip);
                        if (ips.size() >= 1000) return;
                    }
                    i = pos - 1;
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractIPs - Exception: %hs", e.what());
        }
    }

    void ExtractEmails(const std::string& content, std::vector<std::string>& emails) const {
        try {
            // Manual email extraction — no std::regex (ReDoS-safe)
            const size_t len = content.size();

            for (size_t i = 1; i < len; ++i) {
                if (content[i] != '@') continue;

                // Scan backward for local part
                size_t localStart = i;
                while (localStart > 0) {
                    char c = content[localStart - 1];
                    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '+' || c == '-' || c == '%') {
                        localStart--;
                    } else {
                        break;
                    }
                }
                if (localStart == i) continue; // No local part

                // Scan forward for domain part
                size_t domainEnd = i + 1;
                bool hasDot = false;
                while (domainEnd < len) {
                    char c = content[domainEnd];
                    if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-') {
                        if (c == '.') hasDot = true;
                        domainEnd++;
                    } else {
                        break;
                    }
                }

                if (hasDot && domainEnd - i > 4 && domainEnd - localStart < 256) {
                    std::string email = content.substr(localStart, domainEnd - localStart);
                    // Basic validation: must have TLD of 2+ chars
                    size_t lastDot = email.rfind('.');
                    if (lastDot != std::string::npos && email.size() - lastDot > 2) {
                        emails.push_back(email);
                        if (emails.size() >= 500) return;
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"ExtractEmails - Exception: %hs", e.what());
        }
    }

    void CalculateVerdict(DocumentScanResult& result) {
        try {
            // Calculate risk score based on threats
            uint32_t totalRisk = 0;

            totalRisk += result.criticalThreats * 30;
            totalRisk += result.highThreats * 20;
            totalRisk += result.mediumThreats * 10;

            // Macro risk
            if (result.highestMacroRisk == MacroRisk::Critical) totalRisk += 40;
            else if (result.highestMacroRisk == MacroRisk::High) totalRisk += 30;
            else if (result.highestMacroRisk == MacroRisk::Medium) totalRisk += 15;

            // AI/ML analysis (PhantomCortex integration)
            if (m_config.enableAI) {
                try {
                    auto& cortex = AI::PhantomCortex::Instance();
                    if (cortex.IsOperational() && !result.filePath.empty()) {
                        // Read file for AI analysis
                        std::ifstream aiFile(result.filePath, std::ios::binary | std::ios::ate);
                        if (aiFile) {
                            const auto fileSize = aiFile.tellg();
                            if (fileSize > 0 && fileSize <= static_cast<std::streamoff>(MAX_DOCUMENT_SIZE)) {
                                aiFile.seekg(0);
                                std::vector<uint8_t> fileBuffer(static_cast<size_t>(fileSize));
                                aiFile.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);

                                auto aiVerdict = cortex.AnalyzeFile(std::span<const uint8_t>(fileBuffer));
                                result.aiAnalysisPerformed = true;
                                result.aiMaliciousConfidence = aiVerdict.confidence;
                                result.aiClassification = (aiVerdict.verdict == AI::ThreatVerdict::Malicious) ? "Malicious" :
                                                          (aiVerdict.verdict == AI::ThreatVerdict::Suspicious) ? "Suspicious" : "Benign";

                                if (aiVerdict.verdict == AI::ThreatVerdict::Malicious &&
                                    aiVerdict.confidence >= m_config.aiConfidenceThreshold) {
                                    totalRisk += static_cast<uint32_t>(aiVerdict.confidence * 40.0f);
                                    m_stats.maliciousDocuments.fetch_add(1, std::memory_order_relaxed);

                                    SS_LOG_WARN(L"DocumentScanner", L"AI classified as malicious (confidence: %.2f)",
                                        aiVerdict.confidence);
                                } else if (aiVerdict.verdict == AI::ThreatVerdict::Suspicious) {
                                    totalRisk += static_cast<uint32_t>(aiVerdict.confidence * 15.0f);
                                }
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    SS_LOG_DEBUG(L"DocumentScanner", L"AI analysis skipped: %hs", e.what());
                }
            }

            // PatternStore YARA-based detection
            if (!result.filePath.empty()) {
                try {
                    if (m_patternStore) {
                        auto patternResults = m_patternStore->ScanFile(result.filePath);
                        for (const auto& det : patternResults) {
                            if (det.threatLevel >= SignatureStore::ThreatLevel::High) {
                                totalRisk += 30;
                                m_stats.cvesDetected.fetch_add(1, std::memory_order_relaxed);

                                DocumentThreat threat;
                                threat.type = ThreatType::CVEExploit;
                                threat.severity = 90;
                                threat.description = "YARA pattern match: " + det.signatureName;
                                threat.location = "PatternStore";
                                threat.mitreId = "T1203";
                                result.threats.push_back(threat);
                                result.criticalThreats++;
                                ReportThreat(threat);
                            }
                        }
                    }
                } catch (...) {
                    // PatternStore not available
                }
            }

            // Cap at 100
            result.riskScore = std::min(totalRisk, 100u);

            // Determine verdict
            if (result.criticalThreats > 0 || result.riskScore >= 80) {
                result.verdict = ScanVerdict::HighlyMalicious;
                result.verdictReason = "Critical threats detected";
            } else if (result.highThreats > 0 || result.riskScore >= 60) {
                result.verdict = ScanVerdict::Malicious;
                result.verdictReason = "High-risk threats detected";
            } else if (result.mediumThreats > 0 || result.riskScore >= 30) {
                result.verdict = ScanVerdict::Suspicious;
                result.verdictReason = "Suspicious patterns detected";
            } else {
                result.verdict = ScanVerdict::Clean;
                result.verdictReason = "No threats detected";
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"DocumentScanner", L"CalculateVerdict - Exception: %hs", e.what());
            result.verdict = ScanVerdict::Error;
        }
    }

    [[nodiscard]] double CalculateEntropy(const std::string& data) const noexcept {
        if (data.empty()) return 0.0;

        std::array<uint64_t, 256> freq{};

        for (unsigned char c : data) {
            freq[c]++;
        }

        double entropy = 0.0;
        double length = static_cast<double>(data.size());

        for (uint64_t f : freq) {
            if (f > 0) {
                double p = static_cast<double>(f) / length;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    void ReportProgress(const std::wstring& stage, uint32_t percent) const {
        // Copy callback under lock to invoke outside (prevent deadlock)
        DocumentProgressCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_progressCallback;
        }
        try {
            if (cb) {
                cb(stage, percent);
            }
        } catch (...) {
            // Suppress callback exceptions
        }
    }

    void ReportThreat(const DocumentThreat& threat) const {
        // Copy callback under lock to invoke outside (prevent deadlock)
        ThreatCallback cb;
        {
            std::shared_lock lock(m_mutex);
            cb = m_threatCallback;
        }
        try {
            if (cb) {
                cb(threat);
            }
        } catch (...) {
            // Suppress callback exceptions
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };

    DocumentScannerConfig m_config;
    DocumentScannerStatistics m_stats;
    std::shared_ptr<HashStore::HashStore> m_hashStore;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;

    DocumentProgressCallback m_progressCallback;
    ThreatCallback m_threatCallback;
};

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

DocumentScannerConfig DocumentScannerConfig::CreateDefault() noexcept {
    DocumentScannerConfig config;
    config.analyzeMacros = true;
    config.analyzeOLEObjects = true;
    config.analyzePDFJavaScript = true;
    config.detectCVEs = true;
    config.extractIOCs = true;
    config.extractEmbeddedFiles = true;
    config.deobfuscateMacros = true;
    config.scanEmbeddedFiles = true;
    config.recursiveScan = true;
    config.maxRecursionDepth = 5;
    return config;
}

DocumentScannerConfig DocumentScannerConfig::CreateQuick() noexcept {
    DocumentScannerConfig config;
    config.analyzeMacros = true;
    config.analyzeOLEObjects = false;
    config.analyzePDFJavaScript = true;
    config.detectCVEs = true;
    config.extractIOCs = false;
    config.extractEmbeddedFiles = false;
    config.deobfuscateMacros = false;
    config.scanEmbeddedFiles = false;
    config.recursiveScan = false;
    config.maxRecursionDepth = 1;
    return config;
}

DocumentScannerConfig DocumentScannerConfig::CreateDeep() noexcept {
    DocumentScannerConfig config;
    config.analyzeMacros = true;
    config.analyzeOLEObjects = true;
    config.analyzePDFJavaScript = true;
    config.detectCVEs = true;
    config.extractIOCs = true;
    config.extractEmbeddedFiles = true;
    config.deobfuscateMacros = true;
    config.scanEmbeddedFiles = true;
    config.recursiveScan = true;
    config.maxRecursionDepth = 10;
    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void DocumentScannerStatistics::Reset() noexcept {
    documentsScanned = 0;
    macrosDetected = 0;
    maliciousMacros = 0;
    oleObjectsDetected = 0;
    pdfJavaScriptDetected = 0;
    cvesDetected = 0;
    maliciousDocuments = 0;
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

DocumentScanner& DocumentScanner::Instance() {
    static DocumentScanner instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

DocumentScanner::DocumentScanner()
    : m_impl(std::make_unique<DocumentScannerImpl>()) {

    SS_LOG_INFO(L"DocumentScanner", L"DocumentScanner instance created");
}

DocumentScanner::~DocumentScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"DocumentScanner", L"DocumentScanner instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool DocumentScanner::Initialize(const DocumentScannerConfig& config) {
    return m_impl->Initialize(config);
}

void DocumentScanner::Shutdown() noexcept {
    m_impl->Shutdown();
}

DocumentScanResult DocumentScanner::Scan(const std::wstring& filePath,
                                         const DocumentScannerConfig& config) {
    return m_impl->Scan(filePath, config);
}

DocumentScanResult DocumentScanner::ScanBuffer(std::span<const uint8_t> buffer,
                                              DocumentType docType) {
    return m_impl->ScanBuffer(buffer, docType);
}

bool DocumentScanner::HasMacros(const std::wstring& filePath) const {
    return m_impl->HasMacros(filePath);
}

bool DocumentScanner::IsMalicious(const std::wstring& filePath) const {
    return m_impl->IsMalicious(filePath);
}

std::vector<MacroInfo> DocumentScanner::ExtractMacros(const std::wstring& filePath) const {
    return m_impl->ExtractMacros(filePath);
}

MacroInfo DocumentScanner::AnalyzeVBACode(const std::string& vbaCode) const {
    return m_impl->AnalyzeVBACode(vbaCode);
}

std::string DocumentScanner::DeobfuscateMacro(const std::string& obfuscatedCode) const {
    return m_impl->DeobfuscateMacro(obfuscatedCode);
}

std::vector<OLEObjectInfo> DocumentScanner::ExtractOLEObjects(const std::wstring& filePath) const {
    return m_impl->ExtractOLEObjects(filePath);
}

std::vector<std::string> DocumentScanner::ListOLEStreams(const std::wstring& filePath) const {
    return m_impl->ListOLEStreams(filePath);
}

std::vector<PDFObjectInfo> DocumentScanner::AnalyzePDF(const std::wstring& filePath) const {
    return m_impl->AnalyzePDF(filePath);
}

std::vector<std::string> DocumentScanner::ExtractPDFJavaScript(const std::wstring& filePath) const {
    return m_impl->ExtractPDFJavaScript(filePath);
}

DocumentScanResult DocumentScanner::ExtractIOCs(const std::wstring& filePath) const {
    return m_impl->ExtractIOCs(filePath);
}

void DocumentScanner::SetProgressCallback(DocumentProgressCallback callback) {
    m_impl->SetProgressCallback(std::move(callback));
}

void DocumentScanner::SetThreatCallback(ThreatCallback callback) {
    m_impl->SetThreatCallback(std::move(callback));
}

const DocumentScannerStatistics& DocumentScanner::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void DocumentScanner::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

DocumentScannerSnapshotStats DocumentScanner::GetStatisticsSnapshot() const noexcept {
    return m_impl->GetStatisticsSnapshot();
}

bool DocumentScanner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
