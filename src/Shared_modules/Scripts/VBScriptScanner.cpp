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
 * ShadowStrike NGAV - VBSCRIPT SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file VBScriptScanner.cpp
 * @brief Enterprise-grade VBScript malware analysis engine implementation.
 *
 * Implements comprehensive detection of VBScript-based malware including:
 * - Dangerous COM object detection (WScript.Shell, ADODB.Stream, etc.)
 * - Obfuscation detection and deobfuscation (Chr(), Execute, Eval)
 * - VBE (Script Encoder) decoding
 * - IOC extraction (URLs, IPs, commands)
 * - HTA and WSF file parsing
 * - Integration with PatternStore, HashStore, ThreatIntel
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
#include "VBScriptScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../HashStore/HashStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// LOG CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"VBScriptScanner";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================
std::atomic<bool> VBScriptScanner::s_instanceCreated{ false };

// ============================================================================
// ANONYMOUS HELPER NAMESPACE
// ============================================================================
namespace {

    // Current timestamp
    std::chrono::system_clock::time_point Now() {
        return std::chrono::system_clock::now();
    }

    // Generate unique callback ID
    uint64_t GenerateCallbackId() {
        static std::atomic<uint64_t> s_counter{ 1 };
        return s_counter.fetch_add(1, std::memory_order_relaxed);
    }

    // Convert to lowercase
    std::string ToLower(std::string_view str) {
        std::string result(str);
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

    // Trim whitespace
    std::string Trim(std::string_view str) {
        size_t start = str.find_first_not_of(" \t\r\n");
        if (start == std::string_view::npos) return "";
        size_t end = str.find_last_not_of(" \t\r\n");
        return std::string(str.substr(start, end - start + 1));
    }

    // Calculate Shannon entropy
    double CalculateEntropy(std::string_view data) {
        if (data.empty()) return 0.0;

        std::array<size_t, 256> freq{};
        for (unsigned char c : data) {
            freq[c]++;
        }

        double entropy = 0.0;
        double len = static_cast<double>(data.size());

        for (size_t f : freq) {
            if (f > 0) {
                double p = static_cast<double>(f) / len;
                entropy -= p * std::log2(p);
            }
        }

        return entropy;
    }

    // Check if string contains pattern (case-insensitive)
    bool ContainsCI(std::string_view haystack, std::string_view needle) {
        if (needle.empty()) return true;
        if (haystack.size() < needle.size()) return false;

        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](char a, char b) {
                return std::tolower(static_cast<unsigned char>(a)) ==
                       std::tolower(static_cast<unsigned char>(b));
            });

        return it != haystack.end();
    }

    // Find all occurrences of pattern (case-insensitive)
    std::vector<size_t> FindAllCI(std::string_view haystack, std::string_view needle) {
        std::vector<size_t> positions;
        if (needle.empty() || haystack.size() < needle.size()) return positions;

        std::string lowerHay = ToLower(haystack);
        std::string lowerNeedle = ToLower(needle);

        size_t pos = 0;
        while ((pos = lowerHay.find(lowerNeedle, pos)) != std::string::npos) {
            positions.push_back(pos);
            pos += 1;
        }

        return positions;
    }

    // Extract line number from position
    size_t GetLineNumber(std::string_view source, size_t pos) {
        if (pos >= source.size()) return 0;
        return std::count(source.begin(), source.begin() + pos, '\n') + 1;
    }

    // Microsoft Script Encoder uses three independent substitution tables
    // selected via a combination (pick) table that rotates per character index.
    // Each printable char (0x20-0x7F) maps through one of three tables.
    const uint8_t VBE_DECODE_TABLE[3][128] = {
        // Table 0
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x57, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x2E, 0x47, 0x7A, 0x56, 0x42, 0x6A, 0x2F, 0x26,
            0x49, 0x41, 0x34, 0x32, 0x5B, 0x76, 0x72, 0x43,
            0x38, 0x39, 0x70, 0x45, 0x68, 0x71, 0x4F, 0x09,
            0x62, 0x44, 0x23, 0x75, 0x3C, 0x7E, 0x3E, 0x5E,
            0xFF, 0x77, 0x4A, 0x61, 0x5D, 0x22, 0x4B, 0x6F,
            0x4E, 0x3B, 0x4C, 0x50, 0x67, 0x2A, 0x7D, 0x74,
            0x54, 0x2B, 0x2D, 0x2C, 0x30, 0x6E, 0x6B, 0x66,
            0x35, 0x25, 0x21, 0x64, 0x4D, 0x52, 0x63, 0x29,
            0x60, 0x6C, 0x48, 0x7F, 0x73, 0x55, 0x46, 0x33,
            0x65, 0x51, 0x6D, 0x31, 0x36, 0x7C, 0x37, 0x7B,
            0x79, 0x5A, 0x59, 0x40, 0x78, 0x27, 0x5F, 0x28,
            0x53, 0x3A, 0x24, 0x3D, 0x58, 0x5C, 0x3F, 0x20
        },
        // Table 1
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x7B, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x32, 0x30, 0x21, 0x29, 0x5B, 0x38, 0x33, 0x3D,
            0x58, 0x3A, 0x35, 0x65, 0x23, 0x44, 0x27, 0x2C,
            0x4E, 0x37, 0x4F, 0x4A, 0x51, 0x25, 0x2D, 0x48,
            0x34, 0x6C, 0x6D, 0x46, 0x3E, 0x55, 0x3C, 0x42,
            0xFF, 0x2E, 0x45, 0x6A, 0x68, 0x72, 0x56, 0x73,
            0x39, 0x66, 0x78, 0x41, 0x6E, 0x76, 0x77, 0x75,
            0x5C, 0x43, 0x40, 0x67, 0x63, 0x28, 0x79, 0x62,
            0x70, 0x7C, 0x5E, 0x74, 0x53, 0x6B, 0x7E, 0x2B,
            0x4D, 0x22, 0x5D, 0x7A, 0x31, 0x4C, 0x2F, 0x5F,
            0x52, 0x36, 0x26, 0x7F, 0x57, 0x7D, 0x50, 0x60,
            0x54, 0x47, 0x71, 0x61, 0x24, 0x2A, 0x6F, 0x4B,
            0x59, 0x64, 0x5A, 0x49, 0x69, 0x09, 0x3F, 0x20
        },
        // Table 2
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x6E, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
            0x2D, 0x75, 0x52, 0x60, 0x71, 0x5E, 0x49, 0x5C,
            0x62, 0x7D, 0x29, 0x36, 0x20, 0x7C, 0x7A, 0x7F,
            0x6B, 0x63, 0x33, 0x2B, 0x68, 0x51, 0x66, 0x76,
            0x31, 0x64, 0x54, 0x43, 0x3E, 0x22, 0x45, 0x28,
            0xFF, 0x78, 0x79, 0x5D, 0x44, 0x72, 0x26, 0x2A,
            0x6C, 0x24, 0x40, 0x5F, 0x73, 0x4A, 0x39, 0x48,
            0x70, 0x2F, 0x7B, 0x35, 0x2E, 0x5B, 0x6D, 0x46,
            0x57, 0x27, 0x47, 0x55, 0x3A, 0x4D, 0x38, 0x25,
            0x59, 0x56, 0x4F, 0x37, 0x41, 0x67, 0x2C, 0x23,
            0x6F, 0x6A, 0x4E, 0x42, 0x34, 0x32, 0x30, 0x4C,
            0x21, 0x50, 0x3D, 0x4B, 0x58, 0x3C, 0x61, 0x7E,
            0x69, 0x53, 0x09, 0x65, 0x5A, 0x77, 0x3F, 0x20
        }
    };

    // Combination/pick table: for each of 64 rotation positions, selects
    // which of the 3 decode sub-tables to use for the current character.
    const uint8_t VBE_COMBINATION[64][3] = {
        {0, 1, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}, {2, 1, 0},
        {1, 0, 2}, {2, 1, 0}, {0, 1, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1},
        {2, 1, 0}, {0, 2, 1}, {1, 0, 2}, {2, 0, 1}, {0, 1, 2}, {1, 2, 0},
        {0, 2, 1}, {1, 0, 2}, {2, 1, 0}, {0, 1, 2}, {1, 2, 0}, {2, 0, 1},
        {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}, {2, 1, 0}, {0, 1, 2},
        {2, 0, 1}, {0, 1, 2}, {1, 2, 0}, {0, 2, 1}, {1, 0, 2}, {2, 1, 0},
        {0, 1, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}, {2, 1, 0},
        {1, 0, 2}, {2, 1, 0}, {0, 1, 2}, {1, 2, 0}, {2, 0, 1}, {0, 2, 1},
        {2, 1, 0}, {0, 2, 1}, {1, 0, 2}, {2, 0, 1}, {0, 1, 2}, {1, 2, 0},
        {0, 2, 1}, {1, 0, 2}, {2, 1, 0}, {0, 1, 2}, {1, 2, 0}, {2, 0, 1},
        {1, 2, 0}, {2, 0, 1}, {0, 2, 1}, {1, 0, 2}
    };

    // Characters that pass through the VBE encoder without transformation
    bool IsVBEPassthroughChar(unsigned char c) {
        return (c < 0x20) || (c == 0x7F);
    }

    // Regex iteration limit for attacker-controlled content
    constexpr size_t MAX_REGEX_ITERATIONS = 50000;

    // Dangerous COM objects map
    const std::unordered_map<std::string, DangerousObjectType> DANGEROUS_COM_MAP = {
        {"wscript.shell", DangerousObjectType::WScriptShell},
        {"scripting.filesystemobject", DangerousObjectType::FileSystemObject},
        {"adodb.stream", DangerousObjectType::ADODBStream},
        {"msxml2.xmlhttp", DangerousObjectType::XMLHTTP},
        {"msxml2.serverxmlhttp", DangerousObjectType::XMLHTTP},
        {"microsoft.xmlhttp", DangerousObjectType::XMLHTTP},
        {"shell.application", DangerousObjectType::ShellApplication},
        {"wbemscripting.swbemlocator", DangerousObjectType::WMI},
        {"schedule.service", DangerousObjectType::Scheduler},
        {"mmc20.application", DangerousObjectType::ShellApplication},
        {"excel.application", DangerousObjectType::OfficeApp},
        {"word.application", DangerousObjectType::OfficeApp},
        {"outlook.application", DangerousObjectType::OfficeApp},
        {"wscript.network", DangerousObjectType::Network},
        {"internetexplorer.application", DangerousObjectType::IE},
        {"winhttp.winhttprequest.5.1", DangerousObjectType::WinHttp},
        {"winhttp.winhttprequest", DangerousObjectType::WinHttp},
        {"msxml2.xmlhttp.6.0", DangerousObjectType::XMLHTTP},
        {"msxml2.xmlhttp.3.0", DangerousObjectType::XMLHTTP},
        {"msxml2.serverxmlhttp.6.0", DangerousObjectType::XMLHTTP}
    };

    // Dangerous method patterns
    const std::vector<std::pair<std::string, std::string>> DANGEROUS_METHODS = {
        {"run", "Command execution via Run()"},
        {"exec", "Command execution via Exec()"},
        {"shellexecute", "Shell execution"},
        {"regread", "Registry read access"},
        {"regwrite", "Registry write access"},
        {"regdelete", "Registry delete access"},
        {"copyfile", "File copy operation"},
        {"deletefile", "File delete operation"},
        {"createtextfile", "File creation"},
        {"opentextfile", "File access"},
        {"write", "Data write operation"},
        {"savetofile", "Binary file save"},
        {"open", "HTTP/file open"},
        {"send", "HTTP send"},
        {"responsetext", "HTTP response access"},
        {"responsebody", "HTTP binary response"},
        {"execquery", "WMI query execution"},
        {"create", "Object/process creation"},
        {"terminate", "Process termination"}
    };

    // URL regex pattern
    const std::regex URL_REGEX(
        R"((https?|ftp)://[^\s"'<>\[\]{}|\\^`]+)",
        std::regex::icase | std::regex::optimize);

    // IP address regex pattern
    const std::regex IP_REGEX(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)",
        std::regex::optimize);

    // Chr() pattern
    const std::regex CHR_PATTERN(
        R"(chr[w]?\s*\(\s*(\d+)\s*\))",
        std::regex::icase | std::regex::optimize);

    // CreateObject pattern
    const std::regex CREATEOBJECT_PATTERN(
        R"(createobject\s*\(\s*["']([^"']+)["']\s*\))",
        std::regex::icase | std::regex::optimize);

    // GetObject pattern
    const std::regex GETOBJECT_PATTERN(
        R"(getobject\s*\(\s*["']([^"']+)["']\s*\))",
        std::regex::icase | std::regex::optimize);

} // anonymous namespace

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

std::string COMObjectUsage::ToJson() const {
    json j;
    j["objectName"] = objectName;
    j["type"] = static_cast<int>(type);
    j["methodsCalled"] = methodsCalled;
    j["lineNumber"] = lineNumber;
    j["isDangerous"] = isDangerous;
    j["dangerReason"] = dangerReason;
    j["capabilities"] = static_cast<uint32_t>(capabilities);
    return j.dump();
}

std::string VBSDeobfuscationResult::ToJson() const {
    json j;
    j["success"] = success;
    j["obfuscationType"] = static_cast<int>(obfuscationType);
    j["depth"] = depth;
    j["chrCallCount"] = chrCallCount;
    j["extractedStrings"] = extractedStrings;
    j["extractedUrls"] = extractedUrls;
    j["extractedIps"] = extractedIps;
    if (!errorMessage.empty()) {
        j["errorMessage"] = errorMessage;
    }
    // Don't include full scripts in JSON for size reasons
    j["originalLength"] = originalScript.size();
    j["deobfuscatedLength"] = deobfuscatedScript.size();
    return j.dump();
}

bool VBSScanResult::ShouldBlock() const noexcept {
    if (status == VBSScanStatus::Malicious) return true;
    if (status == VBSScanStatus::Suspicious && riskScore >= 80) return true;
    return false;
}

std::string VBSScanResult::ToJson() const {
    json j;
    j["status"] = static_cast<int>(status);
    j["isMalicious"] = isMalicious;
    j["category"] = static_cast<int>(category);
    j["riskScore"] = riskScore;
    j["detectedFamily"] = detectedFamily;
    j["threatName"] = threatName;
    j["fileType"] = static_cast<int>(fileType);
    j["capabilities"] = static_cast<uint32_t>(capabilities);
    j["detectedCapabilities"] = detectedCapabilities;
    j["isObfuscated"] = isObfuscated;
    j["obfuscationType"] = static_cast<int>(obfuscationType);
    j["matchedSignatures"] = matchedSignatures;
    j["extractedIOCs"] = extractedIOCs;
    j["extractedUrls"] = extractedUrls;
    j["extractedCommands"] = extractedCommands;
    j["filePath"] = filePath.string();
    j["sha256"] = sha256;
    j["fileSize"] = fileSize;
    j["scanDurationUs"] = scanDuration.count();

    // COM objects summary
    json comArray = json::array();
    for (const auto& com : dangerousObjects) {
        comArray.push_back({
            {"name", com.objectName},
            {"dangerous", com.isDangerous},
            {"reason", com.dangerReason}
        });
    }
    j["dangerousObjects"] = comArray;

    // Flagged lines summary (limit to 20)
    json flaggedArray = json::array();
    size_t count = 0;
    for (const auto& [line, content] : flaggedLines) {
        if (count++ >= 20) break;
        flaggedArray.push_back({{"line", line}, {"content", content.substr(0, 200)}});
    }
    j["flaggedLines"] = flaggedArray;

    return j.dump(2);
}

void VBSStatistics::Reset() noexcept {
    totalScans = 0;
    maliciousDetected = 0;
    suspiciousDetected = 0;
    vbsFilesScanned = 0;
    vbeFilesScanned = 0;
    wsfFilesScanned = 0;
    htaFilesScanned = 0;
    obfuscatedDetected = 0;
    deobfuscationSuccess = 0;
    deobfuscationFailure = 0;
    dangerousObjectsFound = 0;
    totalBytesScanned = 0;
    for (auto& c : byCategory) c = 0;
    for (auto& c : byCapability) c = 0;
    startTime = Clock::now();
}

std::string VBSStatistics::ToJson() const {
    json j;
    j["totalScans"] = totalScans.load();
    j["maliciousDetected"] = maliciousDetected.load();
    j["suspiciousDetected"] = suspiciousDetected.load();
    j["vbsFilesScanned"] = vbsFilesScanned.load();
    j["vbeFilesScanned"] = vbeFilesScanned.load();
    j["wsfFilesScanned"] = wsfFilesScanned.load();
    j["htaFilesScanned"] = htaFilesScanned.load();
    j["obfuscatedDetected"] = obfuscatedDetected.load();
    j["deobfuscationSuccess"] = deobfuscationSuccess.load();
    j["deobfuscationFailure"] = deobfuscationFailure.load();
    j["dangerousObjectsFound"] = dangerousObjectsFound.load();
    j["totalBytesScanned"] = totalBytesScanned.load();

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

std::string VBSStatisticsSnapshot::ToJson() const {
    json j;
    j["totalScans"] = totalScans;
    j["maliciousDetected"] = maliciousDetected;
    j["suspiciousDetected"] = suspiciousDetected;
    j["vbsFilesScanned"] = vbsFilesScanned;
    j["vbeFilesScanned"] = vbeFilesScanned;
    j["wsfFilesScanned"] = wsfFilesScanned;
    j["htaFilesScanned"] = htaFilesScanned;
    j["obfuscatedDetected"] = obfuscatedDetected;
    j["deobfuscationSuccess"] = deobfuscationSuccess;
    j["deobfuscationFailure"] = deobfuscationFailure;
    j["dangerousObjectsFound"] = dangerousObjectsFound;
    j["totalBytesScanned"] = totalBytesScanned;

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

bool VBSScannerConfiguration::IsValid() const noexcept {
    if (maxFileSize == 0 || maxFileSize > 100 * 1024 * 1024) return false;
    if (maxDeobfuscationDepth == 0 || maxDeobfuscationDepth > 100) return false;
    return true;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class VBScriptScannerImpl {
public:
    // =========================================================================
    // MEMBERS
    // =========================================================================

    // Configuration & State
    VBSScannerConfiguration m_config;
    std::atomic<bool> m_initialized{ false };
    std::atomic<ModuleStatus> m_status{ ModuleStatus::Uninitialized };

    // Thread Safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_cacheMutex;

    // Statistics
    VBSStatistics m_stats;

    // Callbacks
    std::vector<VBSScanResultCallback> m_scanCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Cache: SHA256 -> ScanResult (for recently scanned files)
    struct CacheEntry {
        VBSScanResult result;
        std::chrono::system_clock::time_point expiry;
    };
    std::unordered_map<std::string, CacheEntry> m_scanCache;
    static constexpr size_t MAX_CACHE_SIZE = 10000;
    static constexpr std::chrono::minutes CACHE_TTL{ 30 };

    // External Integrations (optional, may be null)
    PatternStore::PatternStore* m_patternStore{ nullptr };
    SignatureStore::SignatureStore* m_signatureStore{ nullptr };
    HashStore::HashStore* m_hashStore{ nullptr };
    ThreatIntel::ThreatIntelManager* m_threatIntel{ nullptr };
    Whitelist::WhiteListStore* m_whitelistStore{ nullptr };

    // =========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // =========================================================================

    VBScriptScannerImpl() {
        m_stats.startTime = Clock::now();
    }

    ~VBScriptScannerImpl() {
        Shutdown();
    }

    // =========================================================================
    // LIFECYCLE
    // =========================================================================

    bool Initialize(const VBSScannerConfiguration& config) {
        if (m_initialized.exchange(true)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing...");
        m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            m_initialized = false;
            m_status = ModuleStatus::Error;
            return false;
        }

        {
            std::unique_lock lock(m_configMutex);
            m_config = config;
        }

        // Connect to infrastructure singletons (optional — graceful if unavailable)
        try {
            auto& sigStore = SignatureStore::SignatureStore::Instance();
            if (sigStore.IsInitialized()) m_signatureStore = &sigStore;
        } catch (...) {}
        try {
            auto& hashStore = HashStore::HashStore::Instance();
            if (hashStore.IsInitialized()) m_hashStore = &hashStore;
        } catch (...) {}
        try {
            auto& tiStore = ThreatIntel::ThreatIntelManager::Instance();
            if (tiStore.IsInitialized()) m_threatIntel = &tiStore;
        } catch (...) {}
        try {
            auto& wlStore = Whitelist::WhiteListStore::Instance();
            if (wlStore.IsInitialized()) m_whitelistStore = &wlStore;
        } catch (...) {}

        if (!m_signatureStore && !m_hashStore && !m_threatIntel) {
            SS_LOG_WARN(LOG_CATEGORY, L"Some infrastructure modules unavailable");
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"Initialized successfully");
        return true;
    }

    void Shutdown() {
        if (!m_initialized.exchange(false)) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down...");
        m_status = ModuleStatus::Stopping;

        // Clear cache
        {
            std::unique_lock lock(m_cacheMutex);
            m_scanCache.clear();
        }

        // Clear callbacks
        {
            std::unique_lock lock(m_callbackMutex);
            m_scanCallbacks.clear();
            m_errorCallbacks.clear();
        }

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"Shutdown complete");
    }

    // =========================================================================
    // FILE TYPE DETECTION
    // =========================================================================

    VBSFileType DetectFileType(const fs::path& path) {
        // Check extension first (no I/O needed)
        std::wstring ext = path.extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

        if (ext == L".vbs") return VBSFileType::VBS;
        if (ext == L".vbe") return VBSFileType::VBE;
        if (ext == L".wsf") return VBSFileType::WSF;
        if (ext == L".hta") return VBSFileType::HTA;

        // Check content for embedded scripts
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file) return VBSFileType::Unknown;

            std::string header(512, '\0');
            file.read(header.data(), 512);
            header.resize(file.gcount());

            std::string lowerHeader = ToLower(header);

            // Check for VBE signature
            if (lowerHeader.find("#@~^") != std::string::npos) {
                return VBSFileType::VBE;
            }

            // Check for WSF XML structure
            if (lowerHeader.find("<job") != std::string::npos ||
                lowerHeader.find("<script") != std::string::npos) {
                return VBSFileType::WSF;
            }

            // Check for HTA
            if (lowerHeader.find("<hta:application") != std::string::npos ||
                (lowerHeader.find("<html") != std::string::npos &&
                 lowerHeader.find("vbscript") != std::string::npos)) {
                return VBSFileType::HTA;
            }

            // Check for VBScript keywords
            if (ContainsCI(header, "dim ") ||
                ContainsCI(header, "sub ") ||
                ContainsCI(header, "function ") ||
                ContainsCI(header, "wscript.")) {
                return VBSFileType::VBS;
            }

        } catch (...) {
            // Fall through to unknown
        }

        return VBSFileType::Unknown;
    }

    // =========================================================================
    // VBE DECODING
    // =========================================================================

    std::optional<std::string> DecodeVBE(std::string_view encoded) {
        // Microsoft Script Encoder format:
        // #@~^XXXXXX==ENCODED_DATA==XXXXXX^#~@
        // Where XXXXXX is a 6-char base64 checksum, and ENCODED_DATA is the
        // substitution-ciphered script using 3-table rotation.
        size_t start = encoded.find("#@~^");
        if (start == std::string_view::npos) return std::nullopt;

        size_t end = encoded.find("^#~@", start + 4);
        if (end == std::string_view::npos) return std::nullopt;

        // Content between #@~^ and ^#~@
        std::string_view block = encoded.substr(start + 4, end - (start + 4));

        // Block format: <6-char-len-encoding>==<encoded-data>==<6-char-checksum>
        // Find the first == delimiter (after length prefix)
        size_t firstEq = block.find("==");
        if (firstEq == std::string_view::npos || firstEq < 1) return std::nullopt;

        // Find the trailing == (before checksum)
        size_t lastEq = block.rfind("==");
        if (lastEq == std::string_view::npos || lastEq <= firstEq) return std::nullopt;

        // Encoded data lies between the two == markers
        size_t dataStart = firstEq + 2;
        size_t dataEnd = lastEq;
        if (dataStart >= dataEnd) return std::nullopt;

        std::string_view data = block.substr(dataStart, dataEnd - dataStart);

        // Cap decoded size to prevent memory bombs
        if (data.size() > VBSConstants::MAX_SCRIPT_SIZE) {
            SS_LOG_WARN(LOG_CATEGORY, L"VBE encoded data exceeds size limit");
            return std::nullopt;
        }

        std::string decoded;
        decoded.reserve(data.size());

        size_t charIndex = 0; // Rotation counter for printable chars only
        for (size_t i = 0; i < data.size(); ++i) {
            unsigned char c = static_cast<unsigned char>(data[i]);

            // Whitespace/control chars pass through untransformed
            if (c == '\r' || c == '\n' || c == '\t') {
                decoded += static_cast<char>(c);
                continue;
            }

            // The @ character is an escape: next char passes through literally
            if (c == '@') {
                if (i + 1 < data.size()) {
                    decoded += static_cast<char>(data[++i]);
                }
                continue;
            }

            // Characters < 0x20 pass through unchanged
            if (c < 0x20) {
                decoded += static_cast<char>(c);
                continue;
            }

            // For printable characters (0x20-0x7F): apply 3-table substitution
            if (c < 0x80) {
                size_t combo = charIndex % 64;
                // VBE_COMBINATION[combo] gives {pickA, pickB, pickC}
                // The first element selects which of 3 tables to use
                uint8_t tableIdx = VBE_COMBINATION[combo][0];
                uint8_t decodedChar = VBE_DECODE_TABLE[tableIdx][c];

                // 0xFF is an invalid mapping marker
                if (decodedChar == 0xFF) {
                    decoded += static_cast<char>(c);
                } else {
                    decoded += static_cast<char>(decodedChar);
                }
                charIndex++;
            } else {
                // High-byte chars: pass through
                decoded += static_cast<char>(c);
            }
        }

        if (decoded.empty()) return std::nullopt;

        SS_LOG_DEBUG(LOG_CATEGORY, L"VBE decoded %zu bytes -> %zu bytes",
            data.size(), decoded.size());
        return decoded;
    }

    // =========================================================================
    // OBFUSCATION DETECTION
    // =========================================================================

    VBSObfuscationType DetectObfuscation(std::string_view source) {
        std::string src(source); // Copy once for regex safety
        std::string lowerSrc = ToLower(src);

        // Count Chr() calls with iteration limit
        size_t chrCount = 0;
        {
            std::sregex_iterator it(src.begin(), src.end(), CHR_PATTERN);
            std::sregex_iterator end;
            size_t iters = 0;
            while (it != end && iters < MAX_REGEX_ITERATIONS) {
                ++chrCount;
                ++it;
                ++iters;
            }
        }

        // High Chr() count indicates obfuscation
        if (chrCount >= VBSConstants::CHR_OBFUSCATION_THRESHOLD) {
            return VBSObfuscationType::ChrEncoding;
        }

        // Check for Execute/ExecuteGlobal with string building
        if ((ContainsCI(source, "execute") || ContainsCI(source, "executeglobal")) &&
            (chrCount > 0 || ContainsCI(source, "& chr") || ContainsCI(source, "&chr"))) {
            return VBSObfuscationType::ExecuteChain;
        }

        // Check for Eval usage
        if (ContainsCI(source, "eval(") && chrCount > 3) {
            return VBSObfuscationType::EvalUsage;
        }

        // Check for excessive string concatenation
        size_t ampersandCount = std::count(source.begin(), source.end(), '&');
        size_t lineCount = std::count(source.begin(), source.end(), '\n') + 1;
        double avgConcatPerLine = static_cast<double>(ampersandCount) / lineCount;

        if (avgConcatPerLine > 5.0 && chrCount > 0) {
            return VBSObfuscationType::StringConcatenation;
        }

        // Check for Replace() based deobfuscation
        {
            size_t replaceCount = 0;
            size_t pos = 0;
            while ((pos = lowerSrc.find("replace(", pos)) != std::string::npos) {
                replaceCount++;
                pos++;
            }
            if (replaceCount >= 5) {
                return VBSObfuscationType::ReplaceTechnique;
            }
        }

        // Check for StrReverse-based obfuscation
        {
            size_t reverseCount = 0;
            size_t pos = 0;
            while ((pos = lowerSrc.find("strreverse(", pos)) != std::string::npos) {
                reverseCount++;
                pos++;
            }
            if (reverseCount >= 2) {
                return VBSObfuscationType::ReplaceTechnique;
            }
        }

        // Check entropy for custom encoding
        double entropy = CalculateEntropy(source);
        if (entropy > 5.5 && chrCount > 5) {
            return VBSObfuscationType::CustomEncoder;
        }

        // Check for VBE encoding markers
        if (source.find("#@~^") != std::string_view::npos) {
            return VBSObfuscationType::VBEEncoding;
        }

        return VBSObfuscationType::None;
    }

    // =========================================================================
    // DEOBFUSCATION
    // =========================================================================

    VBSDeobfuscationResult Deobfuscate(std::string_view source) {
        VBSDeobfuscationResult result;
        result.originalScript = std::string(source);
        result.obfuscationType = DetectObfuscation(source);

        if (result.obfuscationType == VBSObfuscationType::None) {
            result.success = true;
            result.deobfuscatedScript = result.originalScript;
            return result;
        }

        try {
            std::string current(source);
            size_t maxDepth;
            {
                std::shared_lock lock(m_configMutex);
                maxDepth = m_config.maxDeobfuscationDepth;
            }

            for (size_t depth = 0; depth < maxDepth; ++depth) {
                result.depth = depth + 1;
                std::string previous = current;

                // Decode Chr()/ChrW() calls
                current = DecodeChrCalls(current, result.chrCallCount);

                // Resolve StrReverse() calls
                current = ResolveStrReverse(current);

                // Resolve simple string concatenations
                current = ResolveStringConcat(current);

                // Check if we made progress
                if (current == previous) {
                    break;
                }
            }

            result.deobfuscatedScript = current;

            // Extract strings, URLs, IPs from deobfuscated content
            ExtractStringsFromScript(result.deobfuscatedScript, result.extractedStrings);
            result.extractedUrls = ExtractURLs(result.deobfuscatedScript);
            result.extractedIps = ExtractIPs(result.deobfuscatedScript);

            result.success = true;
            m_stats.deobfuscationSuccess++;

        } catch (const std::exception& e) {
            result.success = false;
            result.errorMessage = e.what();
            m_stats.deobfuscationFailure++;
        }

        return result;
    }

    std::string DecodeChrCalls(std::string_view source, size_t& chrCount) {
        std::string result;
        result.reserve(source.size());

        std::string src(source);
        std::smatch match;

        size_t lastPos = 0;
        std::string::const_iterator searchStart = src.cbegin();

        while (std::regex_search(searchStart, src.cend(), match, CHR_PATTERN)) {
            size_t matchPos = match.position() + (searchStart - src.cbegin());

            // Append text before match
            result.append(src, lastPos, matchPos - lastPos);

            // Decode Chr value
            try {
                int charCode = std::stoi(match[1].str());
                if (charCode >= 0 && charCode <= 255) {
                    result += static_cast<char>(charCode);
                    chrCount++;
                } else {
                    result += match[0].str(); // Keep original if invalid
                }
            } catch (...) {
                result += match[0].str();
            }

            lastPos = matchPos + match[0].length();
            searchStart = match.suffix().first;
        }

        // Append remaining text
        result.append(src, lastPos, std::string::npos);

        return result;
    }

    std::string ResolveStringConcat(std::string_view source) {
        // Resolve "str1" & "str2" -> "str1str2"
        std::string result(source);

        static const std::regex concatPattern(R"("([^"]*)"\s*&\s*"([^"]*)")",
            std::regex::optimize);

        std::string previous;
        size_t iters = 0;
        while (previous != result && iters < 100) {
            previous = result;
            result = std::regex_replace(result, concatPattern, "\"$1$2\"");
            ++iters;
        }

        return result;
    }

    std::string ResolveStrReverse(std::string_view source) {
        // Resolve StrReverse("literal") -> reversed string
        static const std::regex reversePattern(
            R"(strreverse\s*\(\s*"([^"]*)"\s*\))",
            std::regex::icase | std::regex::optimize);

        std::string result(source);
        std::smatch match;
        size_t iters = 0;

        while (std::regex_search(result, match, reversePattern) && iters < MAX_REGEX_ITERATIONS) {
            std::string literal = match[1].str();
            std::string reversed(literal.rbegin(), literal.rend());
            std::string replacement = "\"" + reversed + "\"";

            result = match.prefix().str() + replacement + match.suffix().str();
            ++iters;
        }

        return result;
    }

    void ExtractStringsFromScript(std::string_view source, std::vector<std::string>& strings) {
        static const std::regex stringPattern(R"("([^"]{4,})")", std::regex::optimize);
        std::string src(source);

        std::sregex_iterator it(src.begin(), src.end(), stringPattern);
        std::sregex_iterator end;

        std::unordered_set<std::string> seen;
        size_t iters = 0;
        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            std::string str = (*it)[1].str();
            if (seen.insert(str).second) {
                strings.push_back(str);
            }
            ++it;
            ++iters;
        }
    }

    std::vector<std::string> ExtractURLs(std::string_view source) {
        std::vector<std::string> urls;
        std::string src(source);

        std::sregex_iterator it(src.begin(), src.end(), URL_REGEX);
        std::sregex_iterator end;

        std::unordered_set<std::string> seen;
        size_t iters = 0;
        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            std::string url = (*it)[0].str();
            if (seen.insert(url).second) {
                urls.push_back(url);
            }
            ++it;
            ++iters;
        }

        return urls;
    }

    std::vector<std::string> ExtractIPs(std::string_view source) {
        std::vector<std::string> ips;
        std::string src(source);

        std::sregex_iterator it(src.begin(), src.end(), IP_REGEX);
        std::sregex_iterator end;

        std::unordered_set<std::string> seen;
        size_t iters = 0;
        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            std::string ip = (*it)[0].str();
            if (ip != "0.0.0.0" && seen.insert(ip).second) {
                ips.push_back(ip);
            }
            ++it;
            ++iters;
        }

        return ips;
    }

    // =========================================================================
    // COM OBJECT ANALYSIS
    // =========================================================================

    std::vector<COMObjectUsage> AnalyzeCOMUsage(std::string_view source) {
        std::vector<COMObjectUsage> objects;
        std::string src(source);

        // Find CreateObject calls
        std::sregex_iterator it(src.begin(), src.end(), CREATEOBJECT_PATTERN);
        std::sregex_iterator end;
        size_t iters = 0;

        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            COMObjectUsage usage;
            usage.objectName = (*it)[1].str();
            usage.lineNumber = GetLineNumber(source, (*it).position());

            // Classify the object
            std::string lowerName = ToLower(usage.objectName);
            auto typeIt = DANGEROUS_COM_MAP.find(lowerName);
            if (typeIt != DANGEROUS_COM_MAP.end()) {
                usage.type = typeIt->second;
                usage.isDangerous = true;
                usage.dangerReason = GetDangerReason(usage.type);
                usage.capabilities = GetCapabilitiesForObject(usage.type);
            }

            objects.push_back(usage);
            ++it;
            ++iters;
        }

        // Find GetObject calls (for WMI, etc.)
        std::sregex_iterator git(src.begin(), src.end(), GETOBJECT_PATTERN);
        iters = 0;
        while (git != end && iters < MAX_REGEX_ITERATIONS) {
            COMObjectUsage usage;
            usage.objectName = (*git)[1].str();
            usage.lineNumber = GetLineNumber(source, (*git).position());

            // Check for WMI monikers
            if (ContainsCI(usage.objectName, "winmgmts:")) {
                usage.type = DangerousObjectType::WMI;
                usage.isDangerous = true;
                usage.dangerReason = "WMI access via GetObject()";
                usage.capabilities = VBSCapability::WMIAccess;
            }

            objects.push_back(usage);
            ++git;
            ++iters;
        }

        // Analyze method calls for each object
        for (auto& obj : objects) {
            obj.methodsCalled = FindMethodCalls(source, obj.objectName);
        }

        return objects;
    }

    std::string GetDangerReason(DangerousObjectType type) {
        switch (type) {
            case DangerousObjectType::WScriptShell:
                return "Command execution capability";
            case DangerousObjectType::FileSystemObject:
                return "File system manipulation";
            case DangerousObjectType::ADODBStream:
                return "Binary file creation";
            case DangerousObjectType::XMLHTTP:
                return "Network download capability";
            case DangerousObjectType::ShellApplication:
                return "Process execution";
            case DangerousObjectType::WMI:
                return "WMI system access";
            case DangerousObjectType::Scheduler:
                return "Task scheduler access";
            case DangerousObjectType::OfficeApp:
                return "Office application automation";
            case DangerousObjectType::Network:
                return "Network configuration access";
            case DangerousObjectType::IE:
                return "Internet Explorer automation";
            case DangerousObjectType::WinHttp:
                return "WinHTTP download capability";
            default:
                return "Unknown danger";
        }
    }

    VBSCapability GetCapabilitiesForObject(DangerousObjectType type) {
        switch (type) {
            case DangerousObjectType::WScriptShell:
                return static_cast<VBSCapability>(
                    static_cast<uint32_t>(VBSCapability::CommandExecution) |
                    static_cast<uint32_t>(VBSCapability::RegistryAccess));
            case DangerousObjectType::FileSystemObject:
                return VBSCapability::FileOperations;
            case DangerousObjectType::ADODBStream:
                return VBSCapability::BinaryFileCreate;
            case DangerousObjectType::XMLHTTP:
                return VBSCapability::NetworkDownload;
            case DangerousObjectType::WinHttp:
                return VBSCapability::NetworkDownload;
            case DangerousObjectType::ShellApplication:
                return VBSCapability::ProcessCreation;
            case DangerousObjectType::WMI:
                return VBSCapability::WMIAccess;
            case DangerousObjectType::Scheduler:
                return VBSCapability::ScheduledTask;
            case DangerousObjectType::OfficeApp:
                return VBSCapability::DocumentEmbed;
            default:
                return VBSCapability::None;
        }
    }

    std::vector<std::string> FindMethodCalls(std::string_view source, const std::string& /*objectName*/) {
        std::vector<std::string> methods;

        for (const auto& [method, desc] : DANGEROUS_METHODS) {
            if (ContainsCI(source, std::string(".") + method)) {
                methods.push_back(method);
            }
        }

        return methods;
    }

    // =========================================================================
    // CAPABILITY DETECTION
    // =========================================================================

    VBSCapability DetectCapabilities(std::string_view source) {
        uint32_t caps = 0;
        std::string lowerSrc = ToLower(std::string(source));

        // Command Execution
        if (ContainsCI(source, "wscript.shell") ||
            ContainsCI(source, ".run") ||
            ContainsCI(source, ".exec")) {
            caps |= static_cast<uint32_t>(VBSCapability::CommandExecution);
        }

        // File Operations
        if (ContainsCI(source, "filesystemobject") ||
            ContainsCI(source, "createtextfile") ||
            ContainsCI(source, "opentextfile")) {
            caps |= static_cast<uint32_t>(VBSCapability::FileOperations);
        }

        // Network Download (fixed precedence; also detect WinHttp)
        if (ContainsCI(source, "xmlhttp") ||
            ContainsCI(source, "serverxmlhttp") ||
            ContainsCI(source, "winhttprequest") ||
            (ContainsCI(source, ".open") && ContainsCI(source, ".send"))) {
            caps |= static_cast<uint32_t>(VBSCapability::NetworkDownload);
        }

        // Binary File Creation
        if (ContainsCI(source, "adodb.stream") ||
            ContainsCI(source, "savetofile")) {
            caps |= static_cast<uint32_t>(VBSCapability::BinaryFileCreate);
        }

        // Registry Access
        if (ContainsCI(source, "regread") ||
            ContainsCI(source, "regwrite") ||
            ContainsCI(source, "regdelete")) {
            caps |= static_cast<uint32_t>(VBSCapability::RegistryAccess);
        }

        // Process Creation
        if (ContainsCI(source, "shell.application") ||
            ContainsCI(source, "shellexecute")) {
            caps |= static_cast<uint32_t>(VBSCapability::ProcessCreation);
        }

        // WMI Access
        if (ContainsCI(source, "wbemscripting") ||
            ContainsCI(source, "winmgmts:") ||
            ContainsCI(source, "execquery") ||
            ContainsCI(source, "execmethod")) {
            caps |= static_cast<uint32_t>(VBSCapability::WMIAccess);
        }

        // Scheduled Task
        if (ContainsCI(source, "schedule.service") ||
            ContainsCI(source, "schtasks")) {
            caps |= static_cast<uint32_t>(VBSCapability::ScheduledTask);
        }

        // PowerShell Invocation
        if (ContainsCI(source, "powershell") ||
            ContainsCI(source, "pwsh")) {
            caps |= static_cast<uint32_t>(VBSCapability::PowerShellInvoke);
        }

        // Persistence
        if ((ContainsCI(source, "startup") && ContainsCI(source, "regwrite")) ||
            ContainsCI(source, "\\run\\") ||
            ContainsCI(source, "runonce")) {
            caps |= static_cast<uint32_t>(VBSCapability::Persistence);
        }

        // Email Access
        if (ContainsCI(source, "outlook.application") ||
            ContainsCI(source, "sendmail")) {
            caps |= static_cast<uint32_t>(VBSCapability::EmailAccess);
        }

        // System Info
        if (ContainsCI(source, "computername") ||
            ContainsCI(source, "username") ||
            ContainsCI(source, "userdomain") ||
            (ContainsCI(source, "environ(") && ContainsCI(source, "temp"))) {
            caps |= static_cast<uint32_t>(VBSCapability::SystemInfo);
        }

        // Dynamic Execution
        if (ContainsCI(source, "execute") ||
            ContainsCI(source, "executeglobal") ||
            ContainsCI(source, "eval(")) {
            caps |= static_cast<uint32_t>(VBSCapability::DynamicExecution);
        }

        // Encoded Payload
        if (ContainsCI(source, "base64") ||
            ContainsCI(source, "frombase64")) {
            caps |= static_cast<uint32_t>(VBSCapability::EncodedPayload);
        }

        // Anti-Sandbox
        if (ContainsCI(source, "win32_computersystem") ||
            ContainsCI(source, "sandbox") ||
            ContainsCI(source, "vmware") ||
            ContainsCI(source, "virtualbox")) {
            caps |= static_cast<uint32_t>(VBSCapability::AntiSandbox);
        }

        // Sleep Evasion
        if (ContainsCI(source, "wscript.sleep") ||
            ContainsCI(source, "sleep(")) {
            caps |= static_cast<uint32_t>(VBSCapability::SleepEvasion);
        }

        return static_cast<VBSCapability>(caps);
    }

    // =========================================================================
    // IOC EXTRACTION
    // =========================================================================

    std::vector<std::string> ExtractIOCs(std::string_view source) {
        std::vector<std::string> iocs;

        // Extract URLs
        auto urls = ExtractURLs(source);
        for (const auto& url : urls) {
            iocs.push_back("url:" + url);
        }

        // Extract IPs
        auto ips = ExtractIPs(source);
        for (const auto& ip : ips) {
            iocs.push_back("ip:" + ip);
        }

        // Extract domains from URLs
        static const std::regex domainPattern(R"(https?://([^/\s:]+))",
            std::regex::icase | std::regex::optimize);
        std::string src(source);
        std::sregex_iterator it(src.begin(), src.end(), domainPattern);
        std::sregex_iterator end;

        std::unordered_set<std::string> seenDomains;
        size_t iters = 0;
        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            std::string domain = (*it)[1].str();
            if (seenDomains.insert(domain).second) {
                iocs.push_back("domain:" + domain);
            }
            ++it;
            ++iters;
        }

        // Extract file paths
        static const std::regex pathPattern(
            R"(([a-zA-Z]:\\[^\s"'<>|]+\.(exe|dll|bat|cmd|ps1|vbs|js)))",
            std::regex::icase | std::regex::optimize);
        std::sregex_iterator pit(src.begin(), src.end(), pathPattern);
        iters = 0;
        while (pit != end && iters < MAX_REGEX_ITERATIONS) {
            iocs.push_back("path:" + (*pit)[0].str());
            ++pit;
            ++iters;
        }

        return iocs;
    }

    // =========================================================================
    // THREAT CLASSIFICATION
    // =========================================================================

    VBSThreatCategory ClassifyThreat(const VBSScanResult& result) {
        uint32_t caps = static_cast<uint32_t>(result.capabilities);

        // Ransomware indicators
        bool hasFileOps = caps & static_cast<uint32_t>(VBSCapability::FileOperations);
        bool hasBinaryCreate = caps & static_cast<uint32_t>(VBSCapability::BinaryFileCreate);
        if (hasFileOps && hasBinaryCreate && ContainsCI(result.threatName, "ransom")) {
            return VBSThreatCategory::Ransomware;
        }

        // Downloader
        bool hasNetwork = caps & static_cast<uint32_t>(VBSCapability::NetworkDownload);
        bool hasExec = caps & static_cast<uint32_t>(VBSCapability::CommandExecution);
        if (hasNetwork && (hasExec || hasBinaryCreate)) {
            return VBSThreatCategory::Downloader;
        }

        // RAT indicators
        bool hasWMI = caps & static_cast<uint32_t>(VBSCapability::WMIAccess);
        bool hasPersistence = caps & static_cast<uint32_t>(VBSCapability::Persistence);
        if (hasNetwork && hasExec && (hasWMI || hasPersistence)) {
            return VBSThreatCategory::RAT;
        }

        // Stealer
        bool hasRegistry = caps & static_cast<uint32_t>(VBSCapability::RegistryAccess);
        bool hasEmail = caps & static_cast<uint32_t>(VBSCapability::EmailAccess);
        if ((hasRegistry || hasFileOps) && (hasNetwork || hasEmail)) {
            return VBSThreatCategory::Stealer;
        }

        // Persistence mechanism
        if (hasPersistence && !hasNetwork) {
            return VBSThreatCategory::Persistence;
        }

        // Reconnaissance
        bool hasSysInfo = caps & static_cast<uint32_t>(VBSCapability::SystemInfo);
        if (hasSysInfo && hasNetwork) {
            return VBSThreatCategory::Reconnaissance;
        }

        // Launcher
        if (hasExec) {
            return VBSThreatCategory::Launcher;
        }

        // Dropper
        if (hasBinaryCreate) {
            return VBSThreatCategory::Dropper;
        }

        return VBSThreatCategory::None;
    }

    // =========================================================================
    // RISK SCORE CALCULATION
    // =========================================================================

    int CalculateRiskScore(const VBSScanResult& result) {
        int score = 0;

        // Base score from capabilities
        uint32_t caps = static_cast<uint32_t>(result.capabilities);

        if (caps & static_cast<uint32_t>(VBSCapability::CommandExecution)) score += 25;
        if (caps & static_cast<uint32_t>(VBSCapability::NetworkDownload)) score += 20;
        if (caps & static_cast<uint32_t>(VBSCapability::BinaryFileCreate)) score += 20;
        if (caps & static_cast<uint32_t>(VBSCapability::RegistryAccess)) score += 15;
        if (caps & static_cast<uint32_t>(VBSCapability::WMIAccess)) score += 15;
        if (caps & static_cast<uint32_t>(VBSCapability::Persistence)) score += 25;
        if (caps & static_cast<uint32_t>(VBSCapability::PowerShellInvoke)) score += 20;
        if (caps & static_cast<uint32_t>(VBSCapability::ScheduledTask)) score += 15;
        if (caps & static_cast<uint32_t>(VBSCapability::DynamicExecution)) score += 15;
        if (caps & static_cast<uint32_t>(VBSCapability::EncodedPayload)) score += 10;
        if (caps & static_cast<uint32_t>(VBSCapability::AntiSandbox)) score += 20;

        // Obfuscation penalty
        if (result.isObfuscated) {
            score += 15;
        }

        // Dangerous objects penalty
        score += static_cast<int>(result.dangerousObjects.size()) * 10;

        // IOC presence
        if (!result.extractedUrls.empty()) score += 10;

        // Matched signatures
        score += static_cast<int>(result.matchedSignatures.size()) * 15;

        // Cap at 100
        return std::min(score, 100);
    }

    // =========================================================================
    // MAIN SCAN LOGIC
    // =========================================================================

    VBSScanResult ScanSource(std::string_view source, const std::string& sourceName) {
        auto startTime = Clock::now();

        VBSScanResult result;
        result.scanTime = Now();
        result.fileType = VBSFileType::Memory;
        result.fileSize = source.size();

        // Take a snapshot of config under lock to avoid repeated lock acquisitions
        VBSScannerConfiguration config;
        {
            std::shared_lock lock(m_configMutex);
            config = m_config;
        }

        m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
        m_stats.totalBytesScanned.fetch_add(source.size(), std::memory_order_relaxed);

        // Input validation
        if (source.empty()) {
            result.status = VBSScanStatus::Clean;
            result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - startTime);
            return result;
        }

        if (source.size() > config.maxFileSize) {
            result.status = VBSScanStatus::SkippedSizeLimit;
            result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - startTime);
            SS_LOG_WARN(LOG_CATEGORY, L"File exceeds size limit: %ls",
                Utils::StringUtils::ToWide(sourceName).c_str());
            return result;
        }

        try {
            // Calculate hash
            {
                std::vector<uint8_t> hashBytes;
                Utils::HashUtils::Error hashErr;
                if (Utils::HashUtils::Compute(
                        Utils::HashUtils::Algorithm::SHA256,
                        source.data(),
                        source.size(),
                        hashBytes,
                        &hashErr)) {
                    result.sha256 = Utils::HashUtils::ToHexLower(hashBytes);
                }
            }

            // Check cache
            {
                std::shared_lock lock(m_cacheMutex);
                auto cacheIt = m_scanCache.find(result.sha256);
                if (cacheIt != m_scanCache.end() &&
                    cacheIt->second.expiry > std::chrono::system_clock::now()) {
                    return cacheIt->second.result;
                }
            }

            // Check hash store for known malware
            if (m_hashStore && !result.sha256.empty()) {
                auto hashLookup = m_hashStore->LookupHashString(
                    result.sha256, HashStore::HashType::SHA256);
                if (hashLookup.has_value()) {
                    result.status = VBSScanStatus::Malicious;
                    result.isMalicious = true;
                    result.threatName = hashLookup->signatureName;
                    result.matchedSignatures.push_back("HASH:" + hashLookup->signatureName);
                    m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
                    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                        Clock::now() - startTime);
                    InvokeScanCallbacks(result);
                    return result;
                }
            }

            // Check whitelist by hash — skip scanning for known-good files
            if (m_whitelistStore && !result.sha256.empty()) {
                HashStore::HashValue wlHash{};
                wlHash.type = HashStore::HashType::SHA256;
                Utils::HashUtils::FromHex(result.sha256, wlHash.bytes);
                auto wlResult = m_whitelistStore->IsHashWhitelisted(wlHash);
                if (wlResult.isWhitelisted) {
                    result.status = VBSScanStatus::SkippedWhitelisted;
                    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                        Clock::now() - startTime);
                    return result;
                }
            }

            // Detect obfuscation
            result.obfuscationType = DetectObfuscation(source);
            result.isObfuscated = (result.obfuscationType != VBSObfuscationType::None);

            if (result.isObfuscated) {
                m_stats.obfuscatedDetected.fetch_add(1, std::memory_order_relaxed);
            }

            // Deobfuscate if needed
            std::string analysisSource(source);
            if (result.isObfuscated && config.enableDeobfuscation) {
                result.deobfuscation = Deobfuscate(source);
                if (result.deobfuscation->success) {
                    analysisSource = result.deobfuscation->deobfuscatedScript;
                }
            }

            // Analyze COM objects
            result.comObjectUsage = AnalyzeCOMUsage(analysisSource);

            // Filter dangerous objects
            for (const auto& com : result.comObjectUsage) {
                if (com.isDangerous) {
                    result.dangerousObjects.push_back(com);
                    m_stats.dangerousObjectsFound.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Detect capabilities
            result.capabilities = DetectCapabilities(analysisSource);

            // Convert capabilities to string list
            result.detectedCapabilities = CapabilitiesToStrings(result.capabilities);

            // Extract IOCs
            if (config.extractIOCs) {
                result.extractedIOCs = ExtractIOCs(analysisSource);
                result.extractedUrls = ExtractURLs(analysisSource);
                result.extractedCommands = ExtractCommands(analysisSource);
            }

            // Detect download+write+execute attack chain (APT dropper pattern)
            DetectAttackChains(analysisSource, result);

            // Check threat intelligence for extracted IOCs
            if (m_threatIntel && !result.extractedUrls.empty()) {
                for (const auto& url : result.extractedUrls) {
                    auto intel = m_threatIntel->LookupURL(url);
                    if (intel.found) {
                        result.matchedSignatures.push_back("TI:" + intel.threatName);
                    }
                }
            }
            if (m_threatIntel && !result.extractedIOCs.empty()) {
                for (const auto& ioc : result.extractedIOCs) {
                    // Extract the value after the type prefix (e.g. "ip:1.2.3.4" → "1.2.3.4")
                    auto sep = ioc.find(':');
                    if (sep == std::string::npos) continue;
                    std::string type = ioc.substr(0, sep);
                    std::string value = ioc.substr(sep + 1);
                    ThreatIntel::StoreLookupResult tiResult{};
                    if (type == "ip") {
                        tiResult = m_threatIntel->LookupIP(value);
                    } else if (type == "domain") {
                        tiResult = m_threatIntel->LookupDomain(value);
                    }
                    if (tiResult.found) {
                        result.matchedSignatures.push_back("TI:" + tiResult.threatName);
                    }
                }
            }

            // Find flagged lines
            result.flaggedLines = FindFlaggedLines(analysisSource);

            // Calculate risk score
            result.riskScore = CalculateRiskScore(result);

            // Classify threat
            result.category = ClassifyThreat(result);

            // Determine final status
            if (result.riskScore >= 80 || !result.matchedSignatures.empty()) {
                result.status = VBSScanStatus::Malicious;
                result.isMalicious = true;
                result.threatName = DetermineThreatName(result);
                m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
                auto catIdx = static_cast<size_t>(result.category);
                if (catIdx < m_stats.byCategory.size()) {
                    m_stats.byCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
                }
            } else if (result.riskScore >= 50 || !result.dangerousObjects.empty()) {
                result.status = VBSScanStatus::Suspicious;
                m_stats.suspiciousDetected.fetch_add(1, std::memory_order_relaxed);
            } else {
                result.status = VBSScanStatus::Clean;
            }

            // Populate cache
            {
                std::unique_lock lock(m_cacheMutex);
                if (m_scanCache.size() >= MAX_CACHE_SIZE) {
                    // Evict oldest entries
                    auto now = std::chrono::system_clock::now();
                    std::erase_if(m_scanCache, [&now](const auto& pair) {
                        return pair.second.expiry <= now;
                    });
                    // If still full, clear half
                    if (m_scanCache.size() >= MAX_CACHE_SIZE) {
                        auto it = m_scanCache.begin();
                        size_t toRemove = m_scanCache.size() / 2;
                        while (toRemove > 0 && it != m_scanCache.end()) {
                            it = m_scanCache.erase(it);
                            --toRemove;
                        }
                    }
                }
                m_scanCache[result.sha256] = CacheEntry{
                    result,
                    std::chrono::system_clock::now() + CACHE_TTL
                };
            }

        } catch (const std::exception& e) {
            result.status = VBSScanStatus::ErrorParsing;
            SS_LOG_ERROR(LOG_CATEGORY, L"Scan error: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            InvokeErrorCallbacks(e.what(), 1);
        }

        result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - startTime);

        // Invoke callbacks
        InvokeScanCallbacks(result);

        return result;
    }

    VBSScanResult ScanFile(const fs::path& path) {
        VBSScanResult result;
        result.filePath = path;
        result.scanTime = Now();

        // Validate path
        if (path.empty()) {
            result.status = VBSScanStatus::ErrorFileAccess;
            SS_LOG_ERROR(LOG_CATEGORY, L"Empty file path");
            return result;
        }

        // Detect file type (uses extension first, falls back to content probe)
        result.fileType = DetectFileType(path);

        // Update stats by type
        switch (result.fileType) {
            case VBSFileType::VBS: m_stats.vbsFilesScanned.fetch_add(1, std::memory_order_relaxed); break;
            case VBSFileType::VBE: m_stats.vbeFilesScanned.fetch_add(1, std::memory_order_relaxed); break;
            case VBSFileType::WSF: m_stats.wsfFilesScanned.fetch_add(1, std::memory_order_relaxed); break;
            case VBSFileType::HTA: m_stats.htaFilesScanned.fetch_add(1, std::memory_order_relaxed); break;
            default: break;
        }

        // Read file content
        std::string content;
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                result.status = VBSScanStatus::ErrorFileAccess;
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot open file: %ls", path.wstring().c_str());
                return result;
            }

            // Get file size safely (tellg returns -1 on error)
            file.seekg(0, std::ios::end);
            auto pos = file.tellg();
            if (pos < 0) {
                result.status = VBSScanStatus::ErrorFileAccess;
                SS_LOG_ERROR(LOG_CATEGORY, L"Cannot determine file size: %ls", path.wstring().c_str());
                return result;
            }
            size_t fileSize = static_cast<size_t>(pos);
            file.seekg(0, std::ios::beg);

            result.fileSize = fileSize;

            {
                std::shared_lock lock(m_configMutex);
                if (fileSize > m_config.maxFileSize) {
                    result.status = VBSScanStatus::SkippedSizeLimit;
                    SS_LOG_WARN(LOG_CATEGORY, L"File too large: %ls", path.wstring().c_str());
                    return result;
                }
            }

            content.resize(fileSize);
            file.read(content.data(), static_cast<std::streamsize>(fileSize));

        } catch (const std::exception& e) {
            result.status = VBSScanStatus::ErrorFileAccess;
            SS_LOG_ERROR(LOG_CATEGORY, L"Read error: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            return result;
        }

        // Handle VBE decoding
        if (result.fileType == VBSFileType::VBE) {
            auto decoded = DecodeVBE(content);
            if (decoded) {
                content = *decoded;
            } else {
                SS_LOG_WARN(LOG_CATEGORY, L"VBE decode failed: %ls", path.wstring().c_str());
            }
        }

        // Handle HTA - extract VBScript blocks
        if (result.fileType == VBSFileType::HTA) {
            content = ExtractVBScriptFromHTA(content);
        }

        // Handle WSF - extract VBScript blocks
        if (result.fileType == VBSFileType::WSF) {
            content = ExtractVBScriptFromWSF(content);
        }

        // Scan the content
        VBSScanResult scanResult = ScanSource(content, path.string());

        // Merge file metadata
        scanResult.filePath = path;
        scanResult.fileType = result.fileType;
        scanResult.fileSize = result.fileSize;

        return scanResult;
    }

    // =========================================================================
    // HTA/WSF PARSING
    // =========================================================================

    std::string ExtractVBScriptFromHTA(const std::string& content) {
        std::string extracted;

        // Find <script language="VBScript"> blocks
        static const std::regex scriptPattern(
            R"(<script[^>]*language\s*=\s*["']?vbscript["']?[^>]*>([\s\S]*?)</script>)",
            std::regex::icase | std::regex::optimize);

        std::sregex_iterator it(content.begin(), content.end(), scriptPattern);
        std::sregex_iterator end;
        size_t iters = 0;

        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            extracted += (*it)[1].str();
            extracted += "\n";
            ++it;
            ++iters;
        }

        // If no explicit VBScript blocks, return all script content
        if (extracted.empty()) {
            static const std::regex anyScriptPattern(
                R"(<script[^>]*>([\s\S]*?)</script>)",
                std::regex::icase | std::regex::optimize);
            std::sregex_iterator sit(content.begin(), content.end(), anyScriptPattern);
            iters = 0;
            while (sit != end && iters < MAX_REGEX_ITERATIONS) {
                extracted += (*sit)[1].str();
                extracted += "\n";
                ++sit;
                ++iters;
            }
        }

        return extracted.empty() ? content : extracted;
    }

    std::string ExtractVBScriptFromWSF(const std::string& content) {
        std::string extracted;

        // Find <script language="VBScript"> blocks in WSF
        static const std::regex scriptPattern(
            R"(<script[^>]*language\s*=\s*["']?vbscript["']?[^>]*>([\s\S]*?)</script>)",
            std::regex::icase | std::regex::optimize);

        std::sregex_iterator it(content.begin(), content.end(), scriptPattern);
        std::sregex_iterator end;
        size_t iters = 0;

        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            extracted += (*it)[1].str();
            extracted += "\n";
            ++it;
            ++iters;
        }

        return extracted.empty() ? content : extracted;
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    std::vector<std::string> CapabilitiesToStrings(VBSCapability caps) {
        std::vector<std::string> result;
        uint32_t val = static_cast<uint32_t>(caps);

        if (val & static_cast<uint32_t>(VBSCapability::CommandExecution))
            result.push_back("CommandExecution");
        if (val & static_cast<uint32_t>(VBSCapability::FileOperations))
            result.push_back("FileOperations");
        if (val & static_cast<uint32_t>(VBSCapability::NetworkDownload))
            result.push_back("NetworkDownload");
        if (val & static_cast<uint32_t>(VBSCapability::BinaryFileCreate))
            result.push_back("BinaryFileCreate");
        if (val & static_cast<uint32_t>(VBSCapability::RegistryAccess))
            result.push_back("RegistryAccess");
        if (val & static_cast<uint32_t>(VBSCapability::ProcessCreation))
            result.push_back("ProcessCreation");
        if (val & static_cast<uint32_t>(VBSCapability::WMIAccess))
            result.push_back("WMIAccess");
        if (val & static_cast<uint32_t>(VBSCapability::ScheduledTask))
            result.push_back("ScheduledTask");
        if (val & static_cast<uint32_t>(VBSCapability::PowerShellInvoke))
            result.push_back("PowerShellInvoke");
        if (val & static_cast<uint32_t>(VBSCapability::Persistence))
            result.push_back("Persistence");
        if (val & static_cast<uint32_t>(VBSCapability::EmailAccess))
            result.push_back("EmailAccess");
        if (val & static_cast<uint32_t>(VBSCapability::SystemInfo))
            result.push_back("SystemInfo");
        if (val & static_cast<uint32_t>(VBSCapability::DynamicExecution))
            result.push_back("DynamicExecution");
        if (val & static_cast<uint32_t>(VBSCapability::EncodedPayload))
            result.push_back("EncodedPayload");
        if (val & static_cast<uint32_t>(VBSCapability::AntiSandbox))
            result.push_back("AntiSandbox");
        if (val & static_cast<uint32_t>(VBSCapability::SleepEvasion))
            result.push_back("SleepEvasion");

        return result;
    }

    std::vector<std::string> ExtractCommands(std::string_view source) {
        std::vector<std::string> commands;

        // Find .Run() and .Exec() calls
        static const std::regex runPattern(
            R"(\.(?:run|exec)\s*\(\s*["']([^"']+)["'])",
            std::regex::icase | std::regex::optimize);
        std::string src(source);

        std::sregex_iterator it(src.begin(), src.end(), runPattern);
        std::sregex_iterator end;
        size_t iters = 0;

        while (it != end && iters < MAX_REGEX_ITERATIONS) {
            commands.push_back((*it)[1].str());
            ++it;
            ++iters;
        }

        return commands;
    }

    std::vector<std::pair<size_t, std::string>> FindFlaggedLines(std::string_view source) {
        std::vector<std::pair<size_t, std::string>> flagged;

        std::istringstream stream(std::string(source));
        std::string line;
        size_t lineNum = 0;

        while (std::getline(stream, line)) {
            lineNum++;

            bool isFlagged = false;

            if (ContainsCI(line, "wscript.shell") ||
                ContainsCI(line, "shell.application")) {
                isFlagged = true;
            } else if (ContainsCI(line, ".run") || ContainsCI(line, ".exec")) {
                isFlagged = true;
            } else if (ContainsCI(line, "adodb.stream")) {
                isFlagged = true;
            } else if (ContainsCI(line, "powershell")) {
                isFlagged = true;
            } else if (ContainsCI(line, "execute") || ContainsCI(line, "eval(")) {
                isFlagged = true;
            } else if (ContainsCI(line, "regwrite") || ContainsCI(line, "regread")) {
                isFlagged = true;
            } else if (ContainsCI(line, "xmlhttp") || ContainsCI(line, "winhttprequest")) {
                isFlagged = true;
            } else if (ContainsCI(line, "mshta") || ContainsCI(line, "cscript") ||
                       ContainsCI(line, "wscript")) {
                isFlagged = true;
            } else if (ContainsCI(line, "regsvr32") || ContainsCI(line, ".sct")) {
                isFlagged = true;
            } else if (ContainsCI(line, "winmgmts:") || ContainsCI(line, "execmethod")) {
                isFlagged = true;
            }

            if (isFlagged) {
                flagged.push_back({lineNum, Trim(line)});
            }
        }

        return flagged;
    }

    void DetectAttackChains(std::string_view source, VBSScanResult& result) {
        // Download + Write + Execute chain (Emotet/TrickBot/Qbot dropper pattern)
        bool hasDownload = ContainsCI(source, "xmlhttp") ||
                          ContainsCI(source, "winhttprequest") ||
                          ContainsCI(source, "serverxmlhttp");
        bool hasBinaryWrite = ContainsCI(source, "adodb.stream") ||
                             ContainsCI(source, "savetofile");
        bool hasExec = ContainsCI(source, "wscript.shell") ||
                      ContainsCI(source, ".run") ||
                      ContainsCI(source, "shell.application");

        if (hasDownload && hasBinaryWrite && hasExec) {
            result.matchedSignatures.push_back("CHAIN:Download+Write+Execute");
            SS_LOG_WARN(LOG_CATEGORY, L"Detected download-write-execute chain");
        } else if (hasDownload && hasBinaryWrite) {
            result.matchedSignatures.push_back("CHAIN:Download+Write");
        }

        // mshta.exe / cscript.exe / wscript.exe invocation from script
        if (ContainsCI(source, "mshta") &&
            (ContainsCI(source, "vbscript:") || ContainsCI(source, ".hta"))) {
            result.matchedSignatures.push_back("CHAIN:MshtaVBScript");
        }

        // RegSvr32 scriptlet abuse
        if (ContainsCI(source, "regsvr32") &&
            (ContainsCI(source, "/s") || ContainsCI(source, "/i:") ||
             ContainsCI(source, ".sct"))) {
            result.matchedSignatures.push_back("CHAIN:RegSvr32Scriptlet");
        }

        // WMI process creation chain
        if (ContainsCI(source, "winmgmts:") && ContainsCI(source, "win32_process") &&
            ContainsCI(source, "create")) {
            result.matchedSignatures.push_back("CHAIN:WMI_ProcessCreate");
        }

        // Environ("TEMP") + file write (VBA dropper)
        if (ContainsCI(source, "environ") && ContainsCI(source, "temp") &&
            (ContainsCI(source, "createtextfile") || ContainsCI(source, "savetofile") ||
             ContainsCI(source, "opentextfile"))) {
            result.matchedSignatures.push_back("CHAIN:TempDirDrop");
        }
    }

    std::string DetermineThreatName(const VBSScanResult& result) {
        std::string name = "VBS/";

        switch (result.category) {
            case VBSThreatCategory::Downloader:
                name += "Downloader";
                break;
            case VBSThreatCategory::Dropper:
                name += "Dropper";
                break;
            case VBSThreatCategory::RAT:
                name += "RAT";
                break;
            case VBSThreatCategory::Ransomware:
                name += "Ransom";
                break;
            case VBSThreatCategory::Stealer:
                name += "Stealer";
                break;
            case VBSThreatCategory::Backdoor:
                name += "Backdoor";
                break;
            case VBSThreatCategory::Launcher:
                name += "Launcher";
                break;
            case VBSThreatCategory::Persistence:
                name += "Persist";
                break;
            default:
                name += "Generic";
        }

        // Add obfuscation indicator
        if (result.isObfuscated) {
            name += ".Obfus";
        }

        return name;
    }

    // =========================================================================
    // CALLBACK MANAGEMENT
    // =========================================================================

    void InvokeScanCallbacks(const VBSScanResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& callback : m_scanCallbacks) {
            try {
                callback(result);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }

    void InvokeErrorCallbacks(const std::string& message, int code) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& callback : m_errorCallbacks) {
            try {
                callback(message, code);
            } catch (...) {
                // Don't let callback exceptions propagate
            }
        }
    }

    // =========================================================================
    // SELF TEST
    // =========================================================================

    bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running self-test...");

        bool passed = true;

        try {
            // Test 1: Obfuscation detection (needs >= CHR_OBFUSCATION_THRESHOLD Chr() calls)
            std::string obfuscatedSample =
                "Dim x : x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105) & "
                "Chr(112) & Chr(116) & Chr(46) & Chr(83) & Chr(104) & Chr(101) & Chr(108) & Chr(108)";
            auto obfType = DetectObfuscation(obfuscatedSample);
            if (obfType != VBSObfuscationType::ChrEncoding) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Chr obfuscation detection");
                passed = false;
            }

            // Test 2: Deobfuscation
            auto deobResult = Deobfuscate(obfuscatedSample);
            if (!deobResult.success || deobResult.deobfuscatedScript.find("WScript.Shell") == std::string::npos) {
                SS_LOG_WARN(LOG_CATEGORY, L"Self-test: Deobfuscation incomplete");
            }

            // Test 3: COM object detection
            std::string comSample = "Set objShell = CreateObject(\"WScript.Shell\")";
            auto comUsage = AnalyzeCOMUsage(comSample);
            if (comUsage.empty() || !comUsage[0].isDangerous) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: COM detection");
                passed = false;
            }

            // Test 4: Capability detection
            std::string capSample = "objShell.Run \"cmd.exe /c whoami\"";
            auto caps = DetectCapabilities(capSample);
            if (!(static_cast<uint32_t>(caps) & static_cast<uint32_t>(VBSCapability::CommandExecution))) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Capability detection");
                passed = false;
            }

            // Test 5: URL extraction
            std::string urlSample = "url = \"http://malware.com/payload.exe\"";
            auto urls = ExtractURLs(urlSample);
            if (urls.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: URL extraction");
                passed = false;
            }

            // Test 6: WinHttp.WinHttpRequest detection
            std::string winHttpSample = "Set http = CreateObject(\"WinHttp.WinHttpRequest.5.1\")";
            auto winHttpCom = AnalyzeCOMUsage(winHttpSample);
            if (winHttpCom.empty() || !winHttpCom[0].isDangerous) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: WinHttp detection");
                passed = false;
            }

            // Test 7: StrReverse deobfuscation
            std::string reverseSample = "x = StrReverse(\"dlroW olleH\")";
            auto reverseResult = ResolveStrReverse(reverseSample);
            if (reverseResult.find("Hello World") == std::string::npos) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: StrReverse deobfuscation");
                passed = false;
            }

            // Test 8: VBE decode structure validation
            // Validate the decode tables are internally consistent (no 0xFF at printable positions)
            for (int table = 0; table < 3; ++table) {
                size_t validCount = 0;
                for (int c = 0x20; c < 0x7F; ++c) {
                    if (VBE_DECODE_TABLE[table][c] != 0xFF) {
                        validCount++;
                    }
                }
                if (validCount < 90) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: VBE decode table %d has too few valid entries", table);
                    passed = false;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %ls",
                Utils::StringUtils::ToWide(e.what()).c_str());
            passed = false;
        }

        if (passed) {
            SS_LOG_INFO(LOG_CATEGORY, L"Self-test PASSED");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED");
        }

        return passed;
    }
};

// ============================================================================
// SINGLETON ACCESS
// ============================================================================

VBScriptScanner& VBScriptScanner::Instance() noexcept {
    static VBScriptScanner instance;
    return instance;
}

bool VBScriptScanner::HasInstance() noexcept {
    return s_instanceCreated.load();
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

VBScriptScanner::VBScriptScanner()
    : m_impl(std::make_unique<VBScriptScannerImpl>())
{
    s_instanceCreated = true;
}

VBScriptScanner::~VBScriptScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated = false;
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool VBScriptScanner::Initialize(const VBSScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void VBScriptScanner::Shutdown() {
    m_impl->Shutdown();
}

bool VBScriptScanner::IsInitialized() const noexcept {
    return m_impl->m_initialized.load();
}

ModuleStatus VBScriptScanner::GetStatus() const noexcept {
    return m_impl->m_status.load();
}

bool VBScriptScanner::UpdateConfiguration(const VBSScannerConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration update");
        return false;
    }

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;
    SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
    return true;
}

VBSScannerConfiguration VBScriptScanner::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

VBSScanResult VBScriptScanner::ScanFile(const fs::path& path) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        VBSScanResult err;
        err.status = VBSScanStatus::ErrorParsing;
        err.filePath = path;
        SS_LOG_ERROR(LOG_CATEGORY, L"ScanFile called before initialization");
        return err;
    }
    return m_impl->ScanFile(path);
}

VBSScanResult VBScriptScanner::ScanSource(std::string_view source, const std::string& sourceName) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        VBSScanResult err;
        err.status = VBSScanStatus::ErrorParsing;
        SS_LOG_ERROR(LOG_CATEGORY, L"ScanSource called before initialization");
        return err;
    }
    return m_impl->ScanSource(source, sourceName);
}

VBSScanResult VBScriptScanner::ScanEncodedVBE(const fs::path& vbePath) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        VBSScanResult err;
        err.status = VBSScanStatus::ErrorParsing;
        return err;
    }
    auto result = m_impl->ScanFile(vbePath);
    result.fileType = VBSFileType::VBE;
    return result;
}

VBSScanResult VBScriptScanner::ScanWSF(const fs::path& wsfPath) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        VBSScanResult err;
        err.status = VBSScanStatus::ErrorParsing;
        return err;
    }
    auto result = m_impl->ScanFile(wsfPath);
    result.fileType = VBSFileType::WSF;
    return result;
}

VBSScanResult VBScriptScanner::ScanHTA(const fs::path& htaPath) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        VBSScanResult err;
        err.status = VBSScanStatus::ErrorParsing;
        return err;
    }
    auto result = m_impl->ScanFile(htaPath);
    result.fileType = VBSFileType::HTA;
    return result;
}

// ============================================================================
// ANALYSIS
// ============================================================================

VBSFileType VBScriptScanner::DetectFileType(const fs::path& path) {
    return m_impl->DetectFileType(path);
}

std::vector<COMObjectUsage> VBScriptScanner::AnalyzeCOMUsage(std::string_view source) {
    return m_impl->AnalyzeCOMUsage(source);
}

VBSCapability VBScriptScanner::DetectCapabilities(std::string_view source) {
    return m_impl->DetectCapabilities(source);
}

VBSDeobfuscationResult VBScriptScanner::Deobfuscate(std::string_view source) {
    return m_impl->Deobfuscate(source);
}

std::optional<std::string> VBScriptScanner::DecodeVBE(std::string_view encodedScript) {
    return m_impl->DecodeVBE(encodedScript);
}

VBSObfuscationType VBScriptScanner::DetectObfuscation(std::string_view source) {
    return m_impl->DetectObfuscation(source);
}

std::vector<std::string> VBScriptScanner::ExtractIOCs(std::string_view source) {
    return m_impl->ExtractIOCs(source);
}

bool VBScriptScanner::IsDangerousCOMObject(std::string_view objectName) const noexcept {
    std::string lower = ToLower(objectName);
    return DANGEROUS_COM_MAP.find(lower) != DANGEROUS_COM_MAP.end();
}

// ============================================================================
// CALLBACKS
// ============================================================================

void VBScriptScanner::RegisterCallback(VBSScanResultCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanCallbacks.push_back(std::move(callback));
}

void VBScriptScanner::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void VBScriptScanner::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_scanCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

VBSStatisticsSnapshot VBScriptScanner::GetStatistics() const {
    VBSStatisticsSnapshot snap;
    snap.totalScans = m_impl->m_stats.totalScans.load(std::memory_order_relaxed);
    snap.maliciousDetected = m_impl->m_stats.maliciousDetected.load(std::memory_order_relaxed);
    snap.suspiciousDetected = m_impl->m_stats.suspiciousDetected.load(std::memory_order_relaxed);
    snap.vbsFilesScanned = m_impl->m_stats.vbsFilesScanned.load(std::memory_order_relaxed);
    snap.vbeFilesScanned = m_impl->m_stats.vbeFilesScanned.load(std::memory_order_relaxed);
    snap.wsfFilesScanned = m_impl->m_stats.wsfFilesScanned.load(std::memory_order_relaxed);
    snap.htaFilesScanned = m_impl->m_stats.htaFilesScanned.load(std::memory_order_relaxed);
    snap.obfuscatedDetected = m_impl->m_stats.obfuscatedDetected.load(std::memory_order_relaxed);
    snap.deobfuscationSuccess = m_impl->m_stats.deobfuscationSuccess.load(std::memory_order_relaxed);
    snap.deobfuscationFailure = m_impl->m_stats.deobfuscationFailure.load(std::memory_order_relaxed);
    snap.dangerousObjectsFound = m_impl->m_stats.dangerousObjectsFound.load(std::memory_order_relaxed);
    snap.totalBytesScanned = m_impl->m_stats.totalBytesScanned.load(std::memory_order_relaxed);
    for (size_t i = 0; i < m_impl->m_stats.byCategory.size(); ++i)
        snap.byCategory[i] = m_impl->m_stats.byCategory[i].load(std::memory_order_relaxed);
    for (size_t i = 0; i < m_impl->m_stats.byCapability.size(); ++i)
        snap.byCapability[i] = m_impl->m_stats.byCapability[i].load(std::memory_order_relaxed);
    snap.startTime = m_impl->m_stats.startTime;
    return snap;
}

void VBScriptScanner::ResetStatistics() {
    m_impl->m_stats.Reset();
}

bool VBScriptScanner::SelfTest() {
    return m_impl->SelfTest();
}

std::string VBScriptScanner::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
        VBSConstants::VERSION_MAJOR,
        VBSConstants::VERSION_MINOR,
        VBSConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetVBSFileTypeName(VBSFileType type) noexcept {
    switch (type) {
        case VBSFileType::VBS: return "VBS";
        case VBSFileType::VBE: return "VBE";
        case VBSFileType::WSF: return "WSF";
        case VBSFileType::HTA: return "HTA";
        case VBSFileType::Embedded: return "Embedded";
        case VBSFileType::Memory: return "Memory";
        default: return "Unknown";
    }
}

std::string_view GetDangerousObjectTypeName(DangerousObjectType type) noexcept {
    switch (type) {
        case DangerousObjectType::WScriptShell: return "WScript.Shell";
        case DangerousObjectType::FileSystemObject: return "Scripting.FileSystemObject";
        case DangerousObjectType::ADODBStream: return "ADODB.Stream";
        case DangerousObjectType::XMLHTTP: return "MSXML2.XMLHTTP";
        case DangerousObjectType::ShellApplication: return "Shell.Application";
        case DangerousObjectType::WMI: return "WbemScripting";
        case DangerousObjectType::Scheduler: return "Schedule.Service";
        case DangerousObjectType::OfficeApp: return "Office.Application";
        case DangerousObjectType::Network: return "WScript.Network";
        case DangerousObjectType::IE: return "InternetExplorer.Application";
        case DangerousObjectType::WinHttp: return "WinHttp.WinHttpRequest";
        default: return "None";
    }
}

std::string_view GetVBSCapabilityName(VBSCapability cap) noexcept {
    switch (cap) {
        case VBSCapability::CommandExecution: return "CommandExecution";
        case VBSCapability::FileOperations: return "FileOperations";
        case VBSCapability::NetworkDownload: return "NetworkDownload";
        case VBSCapability::BinaryFileCreate: return "BinaryFileCreate";
        case VBSCapability::RegistryAccess: return "RegistryAccess";
        case VBSCapability::ProcessCreation: return "ProcessCreation";
        case VBSCapability::WMIAccess: return "WMIAccess";
        case VBSCapability::ScheduledTask: return "ScheduledTask";
        case VBSCapability::PowerShellInvoke: return "PowerShellInvoke";
        case VBSCapability::Persistence: return "Persistence";
        case VBSCapability::EmailAccess: return "EmailAccess";
        case VBSCapability::SystemInfo: return "SystemInfo";
        case VBSCapability::DynamicExecution: return "DynamicExecution";
        case VBSCapability::EncodedPayload: return "EncodedPayload";
        case VBSCapability::AntiSandbox: return "AntiSandbox";
        case VBSCapability::SleepEvasion: return "SleepEvasion";
        default: return "None";
    }
}

std::string_view GetVBSThreatCategoryName(VBSThreatCategory cat) noexcept {
    switch (cat) {
        case VBSThreatCategory::Dropper: return "Dropper";
        case VBSThreatCategory::Downloader: return "Downloader";
        case VBSThreatCategory::RAT: return "RAT";
        case VBSThreatCategory::Ransomware: return "Ransomware";
        case VBSThreatCategory::Stealer: return "Stealer";
        case VBSThreatCategory::Backdoor: return "Backdoor";
        case VBSThreatCategory::Worm: return "Worm";
        case VBSThreatCategory::BotClient: return "BotClient";
        case VBSThreatCategory::Reconnaissance: return "Reconnaissance";
        case VBSThreatCategory::Persistence: return "Persistence";
        case VBSThreatCategory::Launcher: return "Launcher";
        default: return "None";
    }
}

std::string_view GetVBSObfuscationTypeName(VBSObfuscationType type) noexcept {
    switch (type) {
        case VBSObfuscationType::ChrEncoding: return "Chr() Encoding";
        case VBSObfuscationType::StringConcatenation: return "String Concatenation";
        case VBSObfuscationType::VariableSubstitution: return "Variable Substitution";
        case VBSObfuscationType::ExecuteChain: return "Execute Chain";
        case VBSObfuscationType::EvalUsage: return "Eval Usage";
        case VBSObfuscationType::ReplaceTechnique: return "Replace Technique";
        case VBSObfuscationType::MixedTechniques: return "Mixed Techniques";
        case VBSObfuscationType::VBEEncoding: return "VBE Encoding";
        case VBSObfuscationType::CustomEncoder: return "Custom Encoder";
        default: return "None";
    }
}

bool IsSuspiciousVBSKeyword(std::string_view keyword) noexcept {
    static const std::unordered_set<std::string> suspiciousKeywords = {
        "execute", "executeglobal", "eval", "run", "exec", "shell",
        "wscript.shell", "adodb.stream", "xmlhttp", "filesystemobject",
        "regwrite", "regread", "powershell", "cmd.exe", "base64",
        "frombase64", "createobject", "getobject", "scheduletask"
    };

    std::string lower = ToLower(keyword);
    return suspiciousKeywords.count(lower) > 0;
}

DangerousObjectType ClassifyCOMObject(std::string_view objectName) noexcept {
    std::string lower = ToLower(objectName);
    auto it = DANGEROUS_COM_MAP.find(lower);
    return (it != DANGEROUS_COM_MAP.end()) ? it->second : DangerousObjectType::None;
}

}  // namespace Scripts
}  // namespace ShadowStrike
