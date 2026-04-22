#include "pch.h"
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
 * ShadowStrike NGAV - CHROME EXTENSION SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file ChromeExtensionScanner.cpp
 * @brief Complete implementation of ChromeExtensionScanner.
 *
 * Provides enterprise-grade scanning of Chrome/Chromium browser extensions
 * with permission analysis, code obfuscation detection via Shannon entropy,
 * ThreatIntel integration, and full JSON serialization.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "ChromeExtensionScanner.hpp"

#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"

#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <numeric>
#include <shlobj.h>

#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;
using Logger = ShadowStrike::Utils::Logger;

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> ChromeExtensionScanner::s_instanceCreated{false};

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

    template<typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template<typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }

    // JSON string escaping for manual serialization paths
    std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (auto c : s) {
            switch (c) {
                case '"':  o << "\\\""; break;
                case '\\': o << "\\\\"; break;
                case '\b': o << "\\b";  break;
                case '\f': o << "\\f";  break;
                case '\n': o << "\\n";  break;
                case '\r': o << "\\r";  break;
                case '\t': o << "\\t";  break;
                default:
                    if (static_cast<unsigned char>(c) < 0x20) {
                        o << "\\u" << std::hex << std::setw(4)
                          << std::setfill('0') << static_cast<int>(c);
                    } else {
                        o << c;
                    }
            }
        }
        return o.str();
    }

    // Shannon entropy of a byte buffer (0.0 = uniform, 8.0 = maximum)
    [[nodiscard]] double ComputeShannonEntropy(const std::string& data) {
        if (data.empty()) return 0.0;

        std::array<uint64_t, 256> freq{};
        for (unsigned char c : data) {
            freq[c]++;
        }

        double entropy = 0.0;
        const double len = static_cast<double>(data.size());
        for (auto count : freq) {
            if (count == 0) continue;
            double p = static_cast<double>(count) / len;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    // Compute SHA-256 hex digest of a file using HashUtils
    [[nodiscard]] std::string ComputeFileSHA256(const fs::path& filePath) {
        std::vector<uint8_t> digest;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), digest)) {
            return {};
        }
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (auto b : digest) {
            hex << std::setw(2) << static_cast<int>(b);
        }
        return hex.str();
    }

    // Suspicious JS patterns (compiled once per process)
    struct SuspiciousPattern {
        const char* pattern;
        const char* apiName;
        bool        isCritical;
    };

    constexpr SuspiciousPattern kSuspiciousPatterns[] = {
        {"eval(",                   "eval",               true },
        {"new Function(",           "Function constructor",true },
        {"chrome.webRequest",       "webRequest",         false},
        {"chrome.downloads",        "downloads API",      false},
        {"chrome.cookies",          "cookies API",        false},
        {"chrome.tabs.executeScript","executeScript",     true },
        {"chrome.debugger",         "debugger API",       true },
        {"document.cookie",         "cookie access",      false},
        {"XMLHttpRequest",          "XHR",                false},
        {"fetch(",                  "fetch",              false},
        {"navigator.sendBeacon",    "sendBeacon",         false},
        {"atob(",                   "base64 decode",      false},
        {"btoa(",                   "base64 encode",      false},
        {"String.fromCharCode",     "charCode obfuscation",true},
        {"\\x",                     "hex escape obfuscation",false},
        {"addEventListener('keydown","keylogger pattern", true },
        {"addEventListener('keypress","keylogger pattern",true },
        {"addEventListener('keyup", "keylogger pattern",  true },
        {"onkeydown",              "keylogger pattern",   true },
        {"crypto.subtle",          "WebCrypto API",       false},
    };

    constexpr const char* kCryptominerPatterns[] = {
        "CoinHive", "coinhive", "Coinimp", "JSEcoin",
        "cryptonight", "stratum+tcp", "stratum+ssl",
        "hashrate", "throttle", "miner.start",
        "deepMiner", "CoinIMP", "WebAssembly.instantiate",
    };

    constexpr const char* kDataExfilPatterns[] = {
        "document.querySelectorAll('input",
        "document.getElementsByTagName('form",
        ".value",
        "localStorage",
        "chrome.storage.local.get",
        "JSON.stringify",
    };

    // Obfuscation entropy threshold: well-written JS ~ 4.5-5.5, obfuscated > 6.0
    constexpr double kObfuscationEntropyThreshold = 5.8;

    // Maximum lines above which long-line check triggers
    constexpr size_t kLongLineThreshold = 5000;

}  // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class ChromeExtensionScannerImpl {
public:
    ChromeExtensionScannerImpl();
    ~ChromeExtensionScannerImpl();

    bool Initialize(const ChromeExtensionScannerConfiguration& config);
    void Shutdown();

    ModuleStatus GetStatus() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_status;
    }

    bool UpdateConfiguration(const ChromeExtensionScannerConfiguration& config);
    ChromeExtensionScannerConfiguration GetConfiguration() const;

    // Scanning
    std::vector<ExtensionScanResult> ScanAll();
    std::vector<ExtensionScanResult> ScanBrowser(ChromiumBrowser browser);
    ExtensionScanResult ScanExtension(const fs::path& extensionPath);

    // Analysis
    ExtensionInfo AnalyzeFolder(const fs::path& path);
    CodeAnalysisResult AnalyzeCode(const fs::path& extensionPath);
    std::vector<PermissionInfo> AnalyzePermissions(
        const std::vector<std::string>& permissions);
    bool IsMalicious(const std::string& extensionId);
    PermissionRisk GetPermissionRisk(const std::string& permission);

    // Profile Discovery
    std::vector<fs::path> GetBrowserProfiles(ChromiumBrowser browser);
    std::vector<fs::path> GetExtensionDirectories(
        ChromiumBrowser browser, const std::string& profileName);

    // Policy
    bool AllowExtension(const std::string& extensionId);
    bool BlockExtension(const std::string& extensionId);
    bool IsExtensionAllowed(const std::string& extensionId) const;
    bool IsExtensionBlocked(const std::string& extensionId) const;

    // Stats & Callbacks
    ChromeExtensionScannerStatistics GetStatistics() const {
        ChromeExtensionScannerStatistics copy;
        copy.totalScanned = m_stats.totalScanned.load();
        copy.safeFound = m_stats.safeFound.load();
        copy.suspiciousFound = m_stats.suspiciousFound.load();
        copy.maliciousFound = m_stats.maliciousFound.load();
        copy.sideloadedFound = m_stats.sideloadedFound.load();
        copy.overPrivilegedFound = m_stats.overPrivilegedFound.load();
        copy.profilesScanned = m_stats.profilesScanned.load();
        copy.jsFilesAnalyzed = m_stats.jsFilesAnalyzed.load();
        copy.obfuscatedFound = m_stats.obfuscatedFound.load();
        copy.cryptominersFound = m_stats.cryptominersFound.load();
        for (size_t i = 0; i < m_stats.byVerdict.size(); ++i)
            copy.byVerdict[i] = m_stats.byVerdict[i].load();
        for (size_t i = 0; i < m_stats.byBrowser.size(); ++i)
            copy.byBrowser[i] = m_stats.byBrowser[i].load();
        AtomicValueStoreRelaxed(copy.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return copy;
    }
    void ResetStatistics() { m_stats.Reset(); }

    void RegisterScanCallback(ScanResultCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_scanCallbacks.push_back(std::move(cb));
    }
    void RegisterMaliciousCallback(MaliciousFoundCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_maliciousCallbacks.push_back(std::move(cb));
    }
    void RegisterErrorCallback(ErrorCallback cb) {
        std::unique_lock lock(m_cbMutex);
        m_errorCallbacks.push_back(std::move(cb));
    }
    void UnregisterCallbacks() {
        std::unique_lock lock(m_cbMutex);
        m_scanCallbacks.clear();
        m_maliciousCallbacks.clear();
        m_errorCallbacks.clear();
    }

    bool SelfTest();

private:
    std::vector<ExtensionInfo> DiscoverExtensions(ChromiumBrowser browser);
    fs::path GetBrowserUserDataPath(ChromiumBrowser browser);
    PermissionRisk CalculatePermissionRisk(const std::string& permission);
    ExtensionVerdict CalculateVerdict(const ExtensionScanResult& result);
    ExtensionRiskLevel CalculateRiskLevel(const ExtensionScanResult& result);
    void NotifyScanResult(const ExtensionScanResult& result);
    void NotifyMalicious(const ExtensionInfo& info);
    void NotifyError(const std::string& message, int code);
    void CheckThreatIntel(ExtensionScanResult& result);

    mutable std::shared_mutex m_mutex;
    ChromeExtensionScannerConfiguration m_config;
    ModuleStatus m_status{ModuleStatus::Uninitialized};

    std::unordered_set<std::string> m_allowedExtensions;
    std::unordered_set<std::string> m_blockedExtensions;

    mutable std::mutex m_cbMutex;
    std::vector<ScanResultCallback> m_scanCallbacks;
    std::vector<MaliciousFoundCallback> m_maliciousCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    mutable ChromeExtensionScannerStatistics m_stats;
};

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

ChromeExtensionScannerImpl::ChromeExtensionScannerImpl() {
    m_stats.Reset();
}

ChromeExtensionScannerImpl::~ChromeExtensionScannerImpl() {
    Shutdown();
}

bool ChromeExtensionScannerImpl::Initialize(
    const ChromeExtensionScannerConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_status == ModuleStatus::Running) {
        return true;
    }

    if (!config.IsValid()) {
        Logger::Error("ChromeExtensionScanner: invalid configuration rejected");
        return false;
    }

    m_config = config;
    m_allowedExtensions.clear();
    m_blockedExtensions.clear();

    for (const auto& id : config.allowedExtensionIds) {
        m_allowedExtensions.insert(id);
    }
    for (const auto& id : config.blockedExtensionIds) {
        m_blockedExtensions.insert(id);
    }

    m_stats.Reset();
    m_status = ModuleStatus::Running;

    Logger::Info("ChromeExtensionScanner initialized v{}.{}.{}, mode={}",
        ChromeExtensionConstants::VERSION_MAJOR,
        ChromeExtensionConstants::VERSION_MINOR,
        ChromeExtensionConstants::VERSION_PATCH,
        config.scanType == ScanType::Deep ? "Deep" : "Standard");

    return true;
}

void ChromeExtensionScannerImpl::Shutdown() {
    std::unique_lock lock(m_mutex);
    if (m_status == ModuleStatus::Running || m_status == ModuleStatus::Scanning) {
        Logger::Info("ChromeExtensionScanner shutting down");
    }
    m_status = ModuleStatus::Stopped;
}

bool ChromeExtensionScannerImpl::UpdateConfiguration(
    const ChromeExtensionScannerConfiguration& config) {
    if (!config.IsValid()) {
        Logger::Warn("ChromeExtensionScanner: configuration update rejected (invalid)");
        return false;
    }
    std::unique_lock lock(m_mutex);
    m_config = config;
    m_allowedExtensions.clear();
    m_blockedExtensions.clear();
    for (const auto& id : config.allowedExtensionIds) m_allowedExtensions.insert(id);
    for (const auto& id : config.blockedExtensionIds) m_blockedExtensions.insert(id);
    return true;
}

ChromeExtensionScannerConfiguration
ChromeExtensionScannerImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

std::vector<ExtensionScanResult> ChromeExtensionScannerImpl::ScanAll() {
    std::vector<ExtensionScanResult> results;

    std::vector<ChromiumBrowser> browsers;
    if (m_config.scanChrome) browsers.push_back(ChromiumBrowser::Chrome);
    if (m_config.scanEdge)   browsers.push_back(ChromiumBrowser::Edge);
    if (m_config.scanBrave)  browsers.push_back(ChromiumBrowser::Brave);
    if (m_config.scanOpera)  browsers.push_back(ChromiumBrowser::Opera);

    for (auto browser : browsers) {
        auto browserResults = ScanBrowser(browser);
        results.insert(results.end(),
            std::make_move_iterator(browserResults.begin()),
            std::make_move_iterator(browserResults.end()));
    }

    return results;
}

std::vector<ExtensionScanResult>
ChromeExtensionScannerImpl::ScanBrowser(ChromiumBrowser browser) {
    std::vector<ExtensionScanResult> results;

    auto extensions = DiscoverExtensions(browser);
    m_stats.totalScanned += extensions.size();

    for (const auto& ext : extensions) {
        ExtensionScanResult result = ScanExtension(ext.extensionPath);

        result.info.browser = browser;
        result.info.profileName = ext.profileName;
        if (result.info.source == ExtensionSource::Unknown) {
            result.info.source = ext.source;
        }

        auto verdictIdx = static_cast<size_t>(result.verdict);
        if (verdictIdx < m_stats.byVerdict.size()) {
            m_stats.byVerdict[verdictIdx]++;
        }
        auto browserIdx = static_cast<size_t>(browser);
        if (browserIdx < m_stats.byBrowser.size()) {
            m_stats.byBrowser[browserIdx]++;
        }

        switch (result.verdict) {
            case ExtensionVerdict::Safe:           m_stats.safeFound++; break;
            case ExtensionVerdict::Suspicious:     m_stats.suspiciousFound++; break;
            case ExtensionVerdict::Malicious:      m_stats.maliciousFound++; break;
            case ExtensionVerdict::Sideloaded:     m_stats.sideloadedFound++; break;
            case ExtensionVerdict::OverPrivileged:  m_stats.overPrivilegedFound++; break;
            default: break;
        }

        results.push_back(result);
        NotifyScanResult(result);

        if (result.verdict == ExtensionVerdict::Malicious) {
            NotifyMalicious(result.info);
            if (m_config.blockMalicious) {
                BlockExtension(result.info.id);
            }
        }
    }

    return results;
}

ExtensionScanResult
ChromeExtensionScannerImpl::ScanExtension(const fs::path& extensionPath) {
    auto start = Clock::now();
    ExtensionScanResult result;

    // 1. Manifest analysis
    result.info = AnalyzeFolder(extensionPath);

    // 2. Permission analysis
    result.info.permissionDetails = AnalyzePermissions(result.info.manifest.permissions);

    // Also analyze host permissions from MV3
    auto hostPermDetails = AnalyzePermissions(result.info.manifest.hostPermissions);
    result.info.permissionDetails.insert(result.info.permissionDetails.end(),
        hostPermDetails.begin(), hostPermDetails.end());

    for (const auto& perm : result.info.permissionDetails) {
        if (perm.riskLevel == PermissionRisk::High)     result.dangerousPermissionsCount++;
        if (perm.riskLevel == PermissionRisk::Critical)  result.criticalPermissionsCount++;
    }

    // 3. Code analysis (if enabled and manifest parsed successfully)
    if (m_config.analyzeCode && result.info.manifest.manifestVersion > 0) {
        result.codeAnalysis = AnalyzeCode(extensionPath);
    }

    // 4. Policy check — blocked/allowed lists take precedence
    if (IsExtensionBlocked(result.info.id)) {
        result.verdict = ExtensionVerdict::PolicyViolation;
        result.issues.push_back("Extension ID is explicitly blocked by policy");
    } else if (IsExtensionAllowed(result.info.id)) {
        result.verdict = ExtensionVerdict::Safe;
    } else {
        // 5. ThreatIntel check against extension file hashes
        if (m_config.checkThreatIntel) {
            CheckThreatIntel(result);
        }

        // 6. Calculate verdict from heuristics (if TI didn't flag it)
        if (result.verdict == ExtensionVerdict::Unknown) {
            result.verdict = CalculateVerdict(result);
        }
    }

    result.riskLevel = CalculateRiskLevel(result);

    // Compute composite risk score (0-100)
    int score = 0;
    score += result.dangerousPermissionsCount * 8;
    score += result.criticalPermissionsCount * 15;
    score += result.codeAnalysis.riskScore;
    if (result.info.isSideloaded) score += 15;
    if (result.codeAnalysis.isObfuscated) score += 20;
    if (result.codeAnalysis.hasCryptominer) score = 100;
    if (result.codeAnalysis.hasKeylogger) score = 100;
    result.riskScore = std::min(score, 100);
    result.codeAnalysis.riskScore = result.riskScore;

    result.scanDuration = std::chrono::duration_cast<
        std::chrono::microseconds>(Clock::now() - start);
    return result;
}

// ============================================================================
// ANALYSIS
// ============================================================================

ExtensionInfo ChromeExtensionScannerImpl::AnalyzeFolder(const fs::path& path) {
    ExtensionInfo info;
    info.extensionPath = path;

    // Extension ID is the containing directory name
    if (path.has_parent_path() && path.parent_path().has_parent_path()) {
        info.id = path.parent_path().filename().string();
    }
    if (info.id.empty()) {
        info.id = path.filename().string();
    }

    // Parse manifest.json
    fs::path manifestPath = path / "manifest.json";
    auto manifestOpt = ParseManifest(manifestPath);

    if (manifestOpt) {
        info.manifest = *manifestOpt;
        info.name = info.manifest.name;
        info.version = info.manifest.version;
        info.description = info.manifest.description;
        info.permissions = info.manifest.permissions;

        // Determine source from update_url
        const auto& updateUrl = info.manifest.updateUrl;
        if (updateUrl.find("google.com") != std::string::npos ||
            updateUrl.find("gstatic.com") != std::string::npos) {
            info.source = ExtensionSource::ChromeWebStore;
            info.webStoreUrl = GetWebStoreUrl(info.id);
        } else if (updateUrl.find("microsoft.com") != std::string::npos ||
                   updateUrl.find("edge.microsoft.com") != std::string::npos) {
            info.source = ExtensionSource::EdgeAddons;
        } else if (updateUrl.empty()) {
            info.source = ExtensionSource::Sideloaded;
            info.isSideloaded = true;
        } else {
            info.source = ExtensionSource::Unknown;
        }

        // Check for "_metadata/verified_contents.json" to distinguish enterprise/dev
        if (fs::exists(path / "_metadata" / "verified_contents.json")) {
            if (info.source == ExtensionSource::Sideloaded) {
                info.source = ExtensionSource::Enterprise;
                info.isSideloaded = false;
            }
        }
    } else {
        info.name = "Unknown (Invalid Manifest)";
        Logger::Warn("ChromeExtensionScanner: failed to parse manifest at {}",
            manifestPath.string());
    }

    return info;
}

CodeAnalysisResult
ChromeExtensionScannerImpl::AnalyzeCode(const fs::path& extensionPath) {
    CodeAnalysisResult result;

    try {
        for (const auto& entry : fs::recursive_directory_iterator(extensionPath,
                fs::directory_options::skip_permission_denied)) {

            if (!entry.is_regular_file()) continue;
            if (entry.path().extension() != ".js") continue;

            const auto fileSize = entry.file_size();
            if (fileSize == 0 || fileSize > m_config.maxCodeSizeToAnalyze) continue;

            result.totalJsFiles++;
            result.totalCodeSize += fileSize;
            m_stats.jsFilesAnalyzed++;

            std::ifstream file(entry.path(), std::ios::binary);
            if (!file) continue;

            std::string code(static_cast<size_t>(fileSize), '\0');
            file.read(code.data(), static_cast<std::streamsize>(fileSize));
            if (!file) continue;

            // Suspicious API pattern matching
            for (const auto& pat : kSuspiciousPatterns) {
                if (code.find(pat.pattern) != std::string::npos) {
                    result.suspiciousAPIs.push_back(pat.apiName);
                    if (pat.isCritical) {
                        result.riskScore += 5;
                    }
                }
            }

            // eval() detection
            if (code.find("eval(") != std::string::npos) {
                result.hasEval = true;
            }

            // Dynamic script loading
            if (code.find("document.createElement('script')") != std::string::npos ||
                code.find("document.createElement(\"script\")") != std::string::npos) {
                result.hasDynamicScriptLoading = true;
            }

            // Cryptominer detection
            for (const auto& pat : kCryptominerPatterns) {
                if (code.find(pat) != std::string::npos) {
                    result.hasCryptominer = true;
                    m_stats.cryptominersFound++;
                    break;
                }
            }

            // Keylogger pattern detection
            if (code.find("addEventListener('keydown") != std::string::npos ||
                code.find("addEventListener('keypress") != std::string::npos ||
                code.find("addEventListener(\"keydown") != std::string::npos ||
                code.find("addEventListener(\"keypress") != std::string::npos) {
                // Cross-reference: also sending data externally
                if (code.find("fetch(") != std::string::npos ||
                    code.find("XMLHttpRequest") != std::string::npos ||
                    code.find("navigator.sendBeacon") != std::string::npos) {
                    result.hasKeylogger = true;
                }
            }

            // Data exfiltration patterns: form data access + external send
            {
                int exfilSignals = 0;
                for (const auto& ep : kDataExfilPatterns) {
                    if (code.find(ep) != std::string::npos) exfilSignals++;
                }
                if (exfilSignals >= 3 &&
                    (code.find("fetch(") != std::string::npos ||
                     code.find("XMLHttpRequest") != std::string::npos)) {
                    result.hasDataExfiltration = true;
                }
            }

            // Shannon entropy-based obfuscation detection
            double entropy = ComputeShannonEntropy(code);
            if (entropy > kObfuscationEntropyThreshold) {
                result.isObfuscated = true;
                result.obfuscationType = "High entropy (Shannon: " +
                    std::to_string(entropy).substr(0, 4) + ")";
                m_stats.obfuscatedFound++;
            }

            // Long line check: packed/minified code
            if (!result.isObfuscated && fileSize > 1024) {
                std::istringstream lineStream(code);
                std::string line;
                while (std::getline(lineStream, line)) {
                    if (line.length() > kLongLineThreshold) {
                        result.isObfuscated = true;
                        result.obfuscationType = "Packed/Minified (line > 5000 chars)";
                        m_stats.obfuscatedFound++;
                        break;
                    }
                }
            }

            // Suspicious URL extraction (basic pattern for external data sends)
            {
                // Look for hardcoded HTTP(S) URLs that aren't to known CDNs
                size_t pos = 0;
                while ((pos = code.find("http", pos)) != std::string::npos) {
                    if (pos + 10 < code.size() &&
                        (code.substr(pos, 8) == "https://" ||
                         code.substr(pos, 7) == "http://")) {
                        size_t end = code.find_first_of("\"' \n\r\t);,}", pos);
                        if (end != std::string::npos && end - pos < 256) {
                            std::string url = code.substr(pos, end - pos);
                            // Exclude common CDN/API URLs
                            if (url.find("googleapis.com") == std::string::npos &&
                                url.find("gstatic.com") == std::string::npos &&
                                url.find("chrome.google.com") == std::string::npos &&
                                url.find("mozilla.org") == std::string::npos &&
                                result.suspiciousUrls.size() < 20) {
                                result.suspiciousUrls.push_back(url);
                            }
                        }
                    }
                    pos++;
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::Error("ChromeExtensionScanner: code analysis failed for {}: {}",
            extensionPath.string(), e.what());
    }

    return result;
}

std::vector<PermissionInfo>
ChromeExtensionScannerImpl::AnalyzePermissions(
    const std::vector<std::string>& permissions) {
    std::vector<PermissionInfo> infos;
    infos.reserve(permissions.size());

    for (const auto& perm : permissions) {
        PermissionInfo info;
        info.name = perm;
        info.riskLevel = CalculatePermissionRisk(perm);

        if (perm.find("://") != std::string::npos || perm == "<all_urls>") {
            info.isHostPermission = true;
        }

        // Provide description per permission
        if (perm == "tabs") {
            info.description = "Read browser tab URLs and titles";
        } else if (perm == "webRequest" || perm == "webRequestBlocking") {
            info.description = "Intercept and modify network requests";
        } else if (perm == "cookies") {
            info.description = "Read and modify browser cookies";
        } else if (perm == "history") {
            info.description = "Access browsing history";
        } else if (perm == "<all_urls>" || perm == "*://*/*") {
            info.description = "Access all websites";
        } else if (perm == "nativeMessaging") {
            info.description = "Communicate with native applications";
        } else if (perm == "debugger") {
            info.description = "Access Chrome debugger protocol";
        } else if (perm == "management") {
            info.description = "Manage other extensions";
        } else if (perm == "clipboardRead") {
            info.description = "Read clipboard contents";
        } else if (perm == "downloads") {
            info.description = "Manage browser downloads";
        } else if (perm == "privacy") {
            info.description = "Modify privacy settings";
        } else if (perm == "proxy") {
            info.description = "Manage proxy settings";
        } else if (info.isHostPermission) {
            info.description = "Access specific website: " + perm;
        } else {
            info.description = "Standard permission";
        }

        infos.push_back(std::move(info));
    }

    return infos;
}

PermissionRisk
ChromeExtensionScannerImpl::CalculatePermissionRisk(const std::string& perm) {
    // Critical permissions checked first
    for (const char* critical : ChromeExtensionConstants::CRITICAL_PERMISSIONS) {
        if (perm == critical) return PermissionRisk::Critical;
    }

    // Dangerous permissions
    for (const char* dangerous : ChromeExtensionConstants::DANGEROUS_PERMISSIONS) {
        if (perm == dangerous) return PermissionRisk::High;
    }

    // Wildcard host patterns
    if (perm == "<all_urls>" || perm.find("*://*/*") != std::string::npos) {
        return PermissionRisk::Critical;
    }

    // Specific host permissions are medium risk
    if (perm.find("://") != std::string::npos) {
        return PermissionRisk::Medium;
    }

    return PermissionRisk::Safe;
}

PermissionRisk
ChromeExtensionScannerImpl::GetPermissionRisk(const std::string& permission) {
    return CalculatePermissionRisk(permission);
}

bool ChromeExtensionScannerImpl::IsMalicious(const std::string& extensionId) {
    if (IsExtensionBlocked(extensionId)) return true;

    // Check ThreatIntel for the extension ID (as a domain IOC)
    auto& tiManager = ThreatIntel::ThreatIntelManager::Instance();
    if (tiManager.IsInitialized()) {
        double score = 0.0;
        std::string threatName;
        if (tiManager.IsKnownMalicious(extensionId, score, threatName)) {
            return true;
        }
    }

    return false;
}

void ChromeExtensionScannerImpl::CheckThreatIntel(ExtensionScanResult& result) {
    auto& tiManager = ThreatIntel::ThreatIntelManager::Instance();
    if (!tiManager.IsInitialized()) return;

    // Check extension ID hash
    if (!result.info.id.empty()) {
        double score = 0.0;
        std::string threatName;
        if (tiManager.IsKnownMalicious(result.info.id, score, threatName)) {
            result.verdict = ExtensionVerdict::Malicious;
            result.info.isMalicious = true;
            result.threatIntelMatches.push_back(
                "Extension ID matched ThreatIntel: " + result.info.id);
            return;
        }
    }

    // Check file hashes of key extension files
    try {
        fs::path manifestPath = result.info.extensionPath / "manifest.json";
        if (fs::exists(manifestPath)) {
            std::string hash = ComputeFileSHA256(manifestPath);
            if (!hash.empty()) {
                result.info.fileHashes["manifest.json"] = hash;
                double score = 0.0;
                std::string threatName;
                if (tiManager.IsKnownMalicious(hash, score, threatName)) {
                    result.verdict = ExtensionVerdict::Malicious;
                    result.info.isMalicious = true;
                    result.threatIntelMatches.push_back(
                        "manifest.json hash matched ThreatIntel: " + hash);
                }
            }
        }
    } catch (...) {
        // Non-fatal: TI check failure doesn't block scan
    }
}

ExtensionVerdict
ChromeExtensionScannerImpl::CalculateVerdict(const ExtensionScanResult& result) {
    if (result.info.isMalicious) return ExtensionVerdict::Malicious;
    if (result.codeAnalysis.hasCryptominer) return ExtensionVerdict::Malicious;
    if (result.codeAnalysis.hasKeylogger) return ExtensionVerdict::Malicious;

    if (result.criticalPermissionsCount >= 3) return ExtensionVerdict::OverPrivileged;

    // Sideloaded + dangerous permissions
    if (result.info.isSideloaded && result.dangerousPermissionsCount >= 2) {
        return ExtensionVerdict::Suspicious;
    }

    // Obfuscated code + network access permissions
    if (result.codeAnalysis.isObfuscated && result.dangerousPermissionsCount > 0) {
        return ExtensionVerdict::Suspicious;
    }

    // Data exfiltration + sensitive permissions
    if (result.codeAnalysis.hasDataExfiltration && result.criticalPermissionsCount > 0) {
        return ExtensionVerdict::Suspicious;
    }

    // Pure sideloaded (no dangerous perms)
    if (result.info.isSideloaded && m_config.flagSideloaded) {
        return ExtensionVerdict::Sideloaded;
    }

    // Over-privileged check
    if (result.criticalPermissionsCount >= 2) {
        return ExtensionVerdict::OverPrivileged;
    }

    return ExtensionVerdict::Safe;
}

ExtensionRiskLevel
ChromeExtensionScannerImpl::CalculateRiskLevel(const ExtensionScanResult& result) {
    switch (result.verdict) {
        case ExtensionVerdict::Malicious:      return ExtensionRiskLevel::Critical;
        case ExtensionVerdict::Suspicious:     return ExtensionRiskLevel::High;
        case ExtensionVerdict::OverPrivileged:  return ExtensionRiskLevel::Medium;
        case ExtensionVerdict::Sideloaded:     return ExtensionRiskLevel::Low;
        case ExtensionVerdict::PolicyViolation: return ExtensionRiskLevel::High;
        case ExtensionVerdict::Safe:           return ExtensionRiskLevel::None;
        default:                               return ExtensionRiskLevel::Low;
    }
}

// ============================================================================
// PROFILE DISCOVERY
// ============================================================================

fs::path ChromeExtensionScannerImpl::GetBrowserUserDataPath(ChromiumBrowser browser) {
    char path[MAX_PATH]{};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, path))) {
        fs::path localAppData(path);

        switch (browser) {
            case ChromiumBrowser::Chrome:
                return localAppData / "Google" / "Chrome" / "User Data";
            case ChromiumBrowser::Edge:
                return localAppData / "Microsoft" / "Edge" / "User Data";
            case ChromiumBrowser::Brave:
                return localAppData / "BraveSoftware" / "Brave-Browser" / "User Data";
            case ChromiumBrowser::Opera: {
                char roamingPath[MAX_PATH]{};
                if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA,
                                                nullptr, 0, roamingPath))) {
                    return fs::path(roamingPath) / "Opera Software" / "Opera Stable";
                }
                break;
            }
            case ChromiumBrowser::Vivaldi:
                return localAppData / "Vivaldi" / "User Data";
            default:
                break;
        }
    }
    return {};
}

std::vector<fs::path>
ChromeExtensionScannerImpl::GetBrowserProfiles(ChromiumBrowser browser) {
    std::vector<fs::path> profiles;
    fs::path userData = GetBrowserUserDataPath(browser);

    if (userData.empty() || !fs::exists(userData)) return profiles;

    try {
        // Default profile
        if (fs::exists(userData / "Default")) {
            profiles.push_back(userData / "Default");
        }

        // Numbered profiles (Profile 1, Profile 2, ...)
        for (const auto& entry : fs::directory_iterator(userData)) {
            if (entry.is_directory()) {
                auto name = entry.path().filename().string();
                if (name.find("Profile ") == 0) {
                    profiles.push_back(entry.path());
                }
            }
        }

        m_stats.profilesScanned += profiles.size();
    } catch (const std::exception& e) {
        Logger::Warn("ChromeExtensionScanner: error enumerating profiles for {}: {}",
            std::string(GetChromiumBrowserName(browser)), e.what());
    }

    return profiles;
}

std::vector<fs::path>
ChromeExtensionScannerImpl::GetExtensionDirectories(
    ChromiumBrowser browser, const std::string& profileName) {
    std::vector<fs::path> dirs;
    fs::path userData = GetBrowserUserDataPath(browser);
    if (userData.empty()) return dirs;

    fs::path extDir = userData / profileName / "Extensions";
    if (!fs::exists(extDir)) return dirs;

    try {
        for (const auto& entry : fs::directory_iterator(extDir)) {
            if (entry.is_directory()) {
                // Each subdirectory is an extension ID; find latest version inside
                fs::path latestVersion;
                for (const auto& verEntry : fs::directory_iterator(entry.path())) {
                    if (verEntry.is_directory()) {
                        if (latestVersion.empty() ||
                            verEntry.path().filename() > latestVersion.filename()) {
                            latestVersion = verEntry.path();
                        }
                    }
                }
                if (!latestVersion.empty()) {
                    dirs.push_back(latestVersion);
                }
            }
        }
    } catch (const std::exception& e) {
        Logger::Warn("ChromeExtensionScanner: error listing extensions in {}: {}",
            extDir.string(), e.what());
    }

    return dirs;
}

std::vector<ExtensionInfo>
ChromeExtensionScannerImpl::DiscoverExtensions(ChromiumBrowser browser) {
    std::vector<ExtensionInfo> extensions;
    auto profiles = GetBrowserProfiles(browser);

    for (const auto& profile : profiles) {
        fs::path extDir = profile / "Extensions";
        if (!fs::exists(extDir)) continue;

        try {
            for (const auto& entry : fs::directory_iterator(extDir)) {
                if (!entry.is_directory()) continue;

                std::string id = entry.path().filename().string();

                // Find latest version directory (lexicographic sort)
                fs::path latestVerDir;
                for (const auto& verEntry : fs::directory_iterator(entry.path())) {
                    if (verEntry.is_directory()) {
                        if (latestVerDir.empty() ||
                            verEntry.path().filename() > latestVerDir.filename()) {
                            latestVerDir = verEntry.path();
                        }
                    }
                }

                if (!latestVerDir.empty()) {
                    ExtensionInfo info;
                    info.extensionPath = latestVerDir;
                    info.id = id;
                    info.profileName = profile.filename().string();
                    extensions.push_back(std::move(info));
                }
            }
        } catch (const std::exception& e) {
            Logger::Warn("ChromeExtensionScanner: error scanning profile {}: {}",
                profile.string(), e.what());
        }
    }

    return extensions;
}

// ============================================================================
// POLICY
// ============================================================================

bool ChromeExtensionScannerImpl::IsExtensionAllowed(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    return m_allowedExtensions.contains(id);
}

bool ChromeExtensionScannerImpl::IsExtensionBlocked(const std::string& id) const {
    std::shared_lock lock(m_mutex);
    return m_blockedExtensions.contains(id);
}

bool ChromeExtensionScannerImpl::BlockExtension(const std::string& id) {
    std::unique_lock lock(m_mutex);
    m_blockedExtensions.insert(id);
    m_allowedExtensions.erase(id);
    Logger::Info("ChromeExtensionScanner: extension {} added to block list", id);
    return true;
}

bool ChromeExtensionScannerImpl::AllowExtension(const std::string& id) {
    std::unique_lock lock(m_mutex);
    m_allowedExtensions.insert(id);
    m_blockedExtensions.erase(id);
    return true;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ChromeExtensionScannerImpl::NotifyScanResult(const ExtensionScanResult& result) {
    std::unique_lock lock(m_cbMutex);
    for (const auto& cb : m_scanCallbacks) {
        try { cb(result); } catch (...) {}
    }
}

void ChromeExtensionScannerImpl::NotifyMalicious(const ExtensionInfo& info) {
    std::unique_lock lock(m_cbMutex);
    for (const auto& cb : m_maliciousCallbacks) {
        try { cb(info); } catch (...) {}
    }
}

void ChromeExtensionScannerImpl::NotifyError(const std::string& message, int code) {
    std::unique_lock lock(m_cbMutex);
    for (const auto& cb : m_errorCallbacks) {
        try { cb(message, code); } catch (...) {}
    }
}

bool ChromeExtensionScannerImpl::SelfTest() {
    // Verify path resolution works
    auto profiles = GetBrowserProfiles(ChromiumBrowser::Chrome);

    // Verify JSON parsing
    fs::path tempManifest = fs::temp_directory_path() / "ss_chrome_selftest.json";
    {
        std::ofstream f(tempManifest);
        if (!f) return false;
        f << R"({"name":"SelfTest","version":"1.0","manifest_version":3,"permissions":["tabs"]})";
    }

    auto result = ParseManifest(tempManifest);
    fs::remove(tempManifest);

    if (!result) return false;
    if (result->name != "SelfTest") return false;
    if (result->version != "1.0") return false;
    if (result->manifestVersion != 3) return false;
    if (result->permissions.size() != 1 || result->permissions[0] != "tabs") return false;

    // Verify entropy calculation
    std::string uniform(256, 'A');
    double ent = ComputeShannonEntropy(uniform);
    if (ent > 0.01) return false;  // Should be ~0

    return true;
}

// ============================================================================
// PUBLIC INTERFACE DELEGATION
// ============================================================================

ChromeExtensionScanner& ChromeExtensionScanner::Instance() noexcept {
    static ChromeExtensionScanner instance;
    return instance;
}

bool ChromeExtensionScanner::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ChromeExtensionScanner::ChromeExtensionScanner()
    : m_impl(std::make_unique<ChromeExtensionScannerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

ChromeExtensionScanner::~ChromeExtensionScanner() = default;

bool ChromeExtensionScanner::Initialize(
    const ChromeExtensionScannerConfiguration& config) {
    return m_impl->Initialize(config);
}

void ChromeExtensionScanner::Shutdown() {
    m_impl->Shutdown();
}

bool ChromeExtensionScanner::IsInitialized() const noexcept {
    return m_impl->GetStatus() != ModuleStatus::Uninitialized &&
           m_impl->GetStatus() != ModuleStatus::Stopped;
}

ModuleStatus ChromeExtensionScanner::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool ChromeExtensionScanner::UpdateConfiguration(
    const ChromeExtensionScannerConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

ChromeExtensionScannerConfiguration
ChromeExtensionScanner::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

std::vector<ExtensionScanResult> ChromeExtensionScanner::ScanAll() {
    return m_impl->ScanAll();
}

std::vector<ExtensionScanResult>
ChromeExtensionScanner::ScanBrowser(ChromiumBrowser browser) {
    return m_impl->ScanBrowser(browser);
}

ExtensionScanResult
ChromeExtensionScanner::ScanExtension(const fs::path& extensionPath) {
    return m_impl->ScanExtension(extensionPath);
}

ExtensionInfo ChromeExtensionScanner::AnalyzeFolder(const std::wstring& path) {
    return m_impl->AnalyzeFolder(fs::path(path));
}

ExtensionInfo ChromeExtensionScanner::AnalyzeFolder(const fs::path& path) {
    return m_impl->AnalyzeFolder(path);
}

std::vector<ExtensionInfo> ChromeExtensionScanner::GetInstalledExtensions() {
    std::vector<ExtensionInfo> all;
    std::vector<ChromiumBrowser> browsers = {
        ChromiumBrowser::Chrome, ChromiumBrowser::Edge,
        ChromiumBrowser::Brave, ChromiumBrowser::Opera
    };

    for (auto browser : browsers) {
        auto results = m_impl->ScanBrowser(browser);
        for (auto& r : results) {
            all.push_back(std::move(r.info));
        }
    }
    return all;
}

std::vector<ExtensionInfo>
ChromeExtensionScanner::GetExtensionsForBrowser(ChromiumBrowser browser) {
    std::vector<ExtensionInfo> exts;
    auto results = m_impl->ScanBrowser(browser);
    for (auto& r : results) {
        exts.push_back(std::move(r.info));
    }
    return exts;
}

std::vector<PermissionInfo>
ChromeExtensionScanner::AnalyzePermissions(
    const std::vector<std::string>& permissions) {
    return m_impl->AnalyzePermissions(permissions);
}

CodeAnalysisResult
ChromeExtensionScanner::AnalyzeCode(const fs::path& extensionPath) {
    return m_impl->AnalyzeCode(extensionPath);
}

bool ChromeExtensionScanner::IsMalicious(const std::string& extensionId) {
    return m_impl->IsMalicious(extensionId);
}

PermissionRisk
ChromeExtensionScanner::GetPermissionRisk(const std::string& permission) {
    return m_impl->GetPermissionRisk(permission);
}

std::vector<fs::path>
ChromeExtensionScanner::GetBrowserProfiles(ChromiumBrowser browser) {
    return m_impl->GetBrowserProfiles(browser);
}

std::vector<fs::path>
ChromeExtensionScanner::GetExtensionDirectories(
    ChromiumBrowser browser, const std::string& profileName) {
    return m_impl->GetExtensionDirectories(browser, profileName);
}

bool ChromeExtensionScanner::AllowExtension(const std::string& extensionId) {
    return m_impl->AllowExtension(extensionId);
}

bool ChromeExtensionScanner::BlockExtension(const std::string& extensionId) {
    return m_impl->BlockExtension(extensionId);
}

bool ChromeExtensionScanner::IsExtensionAllowed(
    const std::string& extensionId) const {
    return m_impl->IsExtensionAllowed(extensionId);
}

bool ChromeExtensionScanner::IsExtensionBlocked(
    const std::string& extensionId) const {
    return m_impl->IsExtensionBlocked(extensionId);
}

void ChromeExtensionScanner::RegisterScanCallback(ScanResultCallback callback) {
    m_impl->RegisterScanCallback(std::move(callback));
}

void ChromeExtensionScanner::RegisterMaliciousCallback(
    MaliciousFoundCallback callback) {
    m_impl->RegisterMaliciousCallback(std::move(callback));
}

void ChromeExtensionScanner::RegisterErrorCallback(ErrorCallback callback) {
    m_impl->RegisterErrorCallback(std::move(callback));
}

void ChromeExtensionScanner::UnregisterCallbacks() {
    m_impl->UnregisterCallbacks();
}

ChromeExtensionScannerStatistics
ChromeExtensionScanner::GetStatistics() const {
    return m_impl->GetStatistics();
}

void ChromeExtensionScanner::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool ChromeExtensionScanner::SelfTest() {
    return m_impl->SelfTest();
}

std::string ChromeExtensionScanner::GetVersionString() noexcept {
    return std::to_string(ChromeExtensionConstants::VERSION_MAJOR) + "." +
           std::to_string(ChromeExtensionConstants::VERSION_MINOR) + "." +
           std::to_string(ChromeExtensionConstants::VERSION_PATCH);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::optional<ManifestInfo> ParseManifest(const fs::path& manifestPath) {
    try {
        std::ifstream file(manifestPath);
        if (!file) return std::nullopt;

        json j = json::parse(file, nullptr, false);
        if (j.is_discarded()) return std::nullopt;

        ManifestInfo info;
        info.name            = j.value("name", "");
        info.version         = j.value("version", "");
        info.description     = j.value("description", "");
        info.author          = j.value("author", "");
        info.updateUrl       = j.value("update_url", "");
        info.homepageUrl     = j.value("homepage_url", "");
        info.manifestVersion = j.value("manifest_version", 2);

        // Permissions
        if (j.contains("permissions") && j["permissions"].is_array()) {
            for (const auto& p : j["permissions"]) {
                if (p.is_string()) info.permissions.push_back(p.get<std::string>());
            }
        }

        // Optional permissions
        if (j.contains("optional_permissions") &&
            j["optional_permissions"].is_array()) {
            for (const auto& p : j["optional_permissions"]) {
                if (p.is_string()) info.optionalPermissions.push_back(p.get<std::string>());
            }
        }

        // Host permissions (MV3)
        if (j.contains("host_permissions") && j["host_permissions"].is_array()) {
            for (const auto& p : j["host_permissions"]) {
                if (p.is_string()) info.hostPermissions.push_back(p.get<std::string>());
            }
        }

        // Content scripts
        if (j.contains("content_scripts") && j["content_scripts"].is_array()) {
            for (const auto& cs : j["content_scripts"]) {
                ContentScriptInfo csi;
                if (cs.contains("matches") && cs["matches"].is_array()) {
                    for (const auto& m : cs["matches"]) {
                        if (m.is_string()) csi.matches.push_back(m.get<std::string>());
                    }
                }
                if (cs.contains("exclude_matches") &&
                    cs["exclude_matches"].is_array()) {
                    for (const auto& m : cs["exclude_matches"]) {
                        if (m.is_string()) csi.excludeMatches.push_back(m.get<std::string>());
                    }
                }
                if (cs.contains("js") && cs["js"].is_array()) {
                    for (const auto& f : cs["js"]) {
                        if (f.is_string()) csi.jsFiles.push_back(f.get<std::string>());
                    }
                }
                if (cs.contains("css") && cs["css"].is_array()) {
                    for (const auto& f : cs["css"]) {
                        if (f.is_string()) csi.cssFiles.push_back(f.get<std::string>());
                    }
                }
                csi.runAt = cs.value("run_at", "document_idle");
                csi.allFrames = cs.value("all_frames", false);
                info.contentScripts.push_back(std::move(csi));
            }
        }

        // Background scripts (MV2)
        if (j.contains("background")) {
            const auto& bg = j["background"];
            if (bg.contains("scripts") && bg["scripts"].is_array()) {
                for (const auto& s : bg["scripts"]) {
                    if (s.is_string()) info.backgroundScripts.push_back(s.get<std::string>());
                }
            }
            if (bg.contains("service_worker") && bg["service_worker"].is_string()) {
                info.serviceWorker = bg["service_worker"].get<std::string>();
            }
        }

        return info;
    } catch (const std::exception& e) {
        Logger::Warn("ChromeExtensionScanner: manifest parse error at {}: {}",
            manifestPath.string(), e.what());
        return std::nullopt;
    }
}

std::string_view GetExtensionVerdictName(ExtensionVerdict verdict) noexcept {
    switch (verdict) {
        case ExtensionVerdict::Safe:            return "Safe";
        case ExtensionVerdict::Suspicious:      return "Suspicious";
        case ExtensionVerdict::Malicious:       return "Malicious";
        case ExtensionVerdict::OverPrivileged:  return "OverPrivileged";
        case ExtensionVerdict::Sideloaded:      return "Sideloaded";
        case ExtensionVerdict::PolicyViolation: return "PolicyViolation";
        case ExtensionVerdict::Unknown:         return "Unknown";
    }
    return "Unknown";
}

std::string_view GetExtensionRiskLevelName(ExtensionRiskLevel level) noexcept {
    switch (level) {
        case ExtensionRiskLevel::None:     return "None";
        case ExtensionRiskLevel::Low:      return "Low";
        case ExtensionRiskLevel::Medium:   return "Medium";
        case ExtensionRiskLevel::High:     return "High";
        case ExtensionRiskLevel::Critical: return "Critical";
    }
    return "None";
}

std::string_view GetExtensionSourceName(ExtensionSource source) noexcept {
    switch (source) {
        case ExtensionSource::Unknown:        return "Unknown";
        case ExtensionSource::ChromeWebStore: return "ChromeWebStore";
        case ExtensionSource::EdgeAddons:     return "EdgeAddons";
        case ExtensionSource::Sideloaded:     return "Sideloaded";
        case ExtensionSource::Enterprise:     return "Enterprise";
        case ExtensionSource::Development:    return "Development";
    }
    return "Unknown";
}

std::string_view GetChromiumBrowserName(ChromiumBrowser browser) noexcept {
    switch (browser) {
        case ChromiumBrowser::Unknown: return "Unknown";
        case ChromiumBrowser::Chrome:  return "Chrome";
        case ChromiumBrowser::Edge:    return "Edge";
        case ChromiumBrowser::Brave:   return "Brave";
        case ChromiumBrowser::Opera:   return "Opera";
        case ChromiumBrowser::Vivaldi: return "Vivaldi";
    }
    return "Unknown";
}

std::string_view GetPermissionRiskName(PermissionRisk risk) noexcept {
    switch (risk) {
        case PermissionRisk::Safe:     return "Safe";
        case PermissionRisk::Low:      return "Low";
        case PermissionRisk::Medium:   return "Medium";
        case PermissionRisk::High:     return "High";
        case PermissionRisk::Critical: return "Critical";
    }
    return "Safe";
}

bool IsDangerousPermission(const std::string& permission) {
    for (const char* dangerous : ChromeExtensionConstants::DANGEROUS_PERMISSIONS) {
        if (permission == dangerous) return true;
    }
    return false;
}

bool IsCriticalPermission(const std::string& permission) {
    for (const char* critical : ChromeExtensionConstants::CRITICAL_PERMISSIONS) {
        if (permission == critical) return true;
    }
    return false;
}

std::string GetWebStoreUrl(const std::string& extensionId) {
    return "https://chrome.google.com/webstore/detail/" + extensionId;
}

// ============================================================================
// STRUCT ToJson IMPLEMENTATIONS
// ============================================================================

std::string PermissionInfo::ToJson() const {
    json j;
    j["name"] = name;
    j["riskLevel"] = std::string(GetPermissionRiskName(riskLevel));
    j["description"] = description;
    j["isHostPermission"] = isHostPermission;
    j["isOptional"] = isOptional;
    return j.dump();
}

std::string ContentScriptInfo::ToJson() const {
    json j;
    j["matches"] = matches;
    j["excludeMatches"] = excludeMatches;
    j["jsFiles"] = jsFiles;
    j["cssFiles"] = cssFiles;
    j["runAt"] = runAt;
    j["allFrames"] = allFrames;
    return j.dump();
}

std::string ManifestInfo::ToJson() const {
    json j;
    j["manifestVersion"] = manifestVersion;
    j["name"] = name;
    j["version"] = version;
    j["description"] = description;
    j["author"] = author;
    j["permissions"] = permissions;
    j["optionalPermissions"] = optionalPermissions;
    j["hostPermissions"] = hostPermissions;
    j["serviceWorker"] = serviceWorker;
    j["updateUrl"] = updateUrl;
    j["homepageUrl"] = homepageUrl;

    json csArray = json::array();
    for (const auto& cs : contentScripts) {
        csArray.push_back(json::parse(cs.ToJson()));
    }
    j["contentScripts"] = csArray;

    j["backgroundScripts"] = backgroundScripts;
    return j.dump();
}

std::string CodeAnalysisResult::ToJson() const {
    json j;
    j["totalJsFiles"] = totalJsFiles;
    j["totalCodeSize"] = totalCodeSize;
    j["isObfuscated"] = isObfuscated;
    j["obfuscationType"] = obfuscationType;
    j["hasEval"] = hasEval;
    j["hasDynamicScriptLoading"] = hasDynamicScriptLoading;
    j["hasDataExfiltration"] = hasDataExfiltration;
    j["hasCryptominer"] = hasCryptominer;
    j["hasKeylogger"] = hasKeylogger;
    j["suspiciousAPIs"] = suspiciousAPIs;
    j["suspiciousUrls"] = suspiciousUrls;
    j["riskScore"] = riskScore;
    return j.dump();
}

std::string ExtensionInfo::ToJson() const {
    json j;
    j["id"] = id;
    j["name"] = name;
    j["version"] = version;
    j["description"] = description;
    j["extensionPath"] = extensionPath.string();
    j["browser"] = std::string(GetChromiumBrowserName(browser));
    j["profileName"] = profileName;
    j["source"] = std::string(GetExtensionSourceName(source));
    j["permissions"] = permissions;
    j["isSideloaded"] = isSideloaded;
    j["isMalicious"] = isMalicious;
    j["isEnabled"] = isEnabled;
    j["webStoreUrl"] = webStoreUrl;
    j["manifest"] = json::parse(manifest.ToJson());

    json hashesObj = json::object();
    for (const auto& [file, hash] : fileHashes) {
        hashesObj[file] = hash;
    }
    j["fileHashes"] = hashesObj;
    return j.dump();
}

bool ExtensionScanResult::IsClean() const noexcept {
    return verdict == ExtensionVerdict::Safe;
}

std::string ExtensionScanResult::ToJson() const {
    json j;
    j["info"] = json::parse(info.ToJson());
    j["verdict"] = std::string(GetExtensionVerdictName(verdict));
    j["riskLevel"] = std::string(GetExtensionRiskLevelName(riskLevel));
    j["riskScore"] = riskScore;
    j["codeAnalysis"] = json::parse(codeAnalysis.ToJson());
    j["dangerousPermissionsCount"] = dangerousPermissionsCount;
    j["criticalPermissionsCount"] = criticalPermissionsCount;
    j["issues"] = issues;
    j["recommendations"] = recommendations;
    j["threatIntelMatches"] = threatIntelMatches;
    j["scanDurationUs"] = scanDuration.count();
    return j.dump();
}

void ChromeExtensionScannerStatistics::Reset() noexcept {
    totalScanned = 0;
    safeFound = 0;
    suspiciousFound = 0;
    maliciousFound = 0;
    sideloadedFound = 0;
    overPrivilegedFound = 0;
    profilesScanned = 0;
    jsFilesAnalyzed = 0;
    obfuscatedFound = 0;
    cryptominersFound = 0;
    for (auto& v : byVerdict) v.store(0, std::memory_order_relaxed);
    for (auto& b : byBrowser) b.store(0, std::memory_order_relaxed);
    AtomicValueStoreRelaxed(startTime, Clock::now());
}

std::string ChromeExtensionScannerStatistics::ToJson() const {
    json j;
    j["totalScanned"] = totalScanned.load();
    j["safeFound"] = safeFound.load();
    j["suspiciousFound"] = suspiciousFound.load();
    j["maliciousFound"] = maliciousFound.load();
    j["sideloadedFound"] = sideloadedFound.load();
    j["overPrivilegedFound"] = overPrivilegedFound.load();
    j["profilesScanned"] = profilesScanned.load();
    j["jsFilesAnalyzed"] = jsFilesAnalyzed.load();
    j["obfuscatedFound"] = obfuscatedFound.load();
    j["cryptominersFound"] = cryptominersFound.load();
    return j.dump();
}

bool ChromeExtensionScannerConfiguration::IsValid() const noexcept {
    if (maxCodeSizeToAnalyze == 0) return false;
    if (maxCodeSizeToAnalyze > ChromeExtensionConstants::MAX_EXTENSION_SIZE) return false;
    return true;
}

}  // namespace WebBrowser
}  // namespace ShadowStrike
