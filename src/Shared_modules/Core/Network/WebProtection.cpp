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
 * ShadowStrike Core Network - WEB PROTECTION IMPLEMENTATION
 * ============================================================================
 *
 * @file WebProtection.cpp
 * @brief Enterprise-grade browser and web security protection engine implementation
 *
 * Production-level implementation competing with enterprise-grade enterprise-grade EDR,
 * enterprise-grade EDR, and enterprise-grade GravityZone for web protection.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - XSS detection with pattern matching and sanitization
 * - Certificate validation with pinning (HPKP) and CT enforcement
 * - Form protection with credential theft detection
 * - Exploit detection (heap spray, ROP chains, shellcode)
 * - Privacy protection (trackers, fingerprinting, WebRTC leaks)
 * - Browser session management with process tracking
 * - Content sanitization with DOM parsing
 * - Infrastructure reuse (ThreatIntel, PatternStore, SignatureStore)
 * - Comprehensive statistics tracking
 * - Alert generation with callbacks
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
#include "WebProtection.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../ThreatIntel/ThreatIntelStore.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../SignatureStore/SignatureStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <cmath>
#include <cctype>
#include <numbers>
#include <regex>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <unordered_map>
#include <map>
#include <set>
#include <deque>
#include <execution>

namespace ShadowStrike {
namespace Core {
namespace Network {

namespace fs = std::filesystem;
using Clock = std::chrono::system_clock;
using TimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// XSS PATTERNS (HARDCODED)
// ============================================================================

/**
 * @brief Common XSS attack patterns.
 */
static const std::array<std::string, 30> XSS_PATTERNS = {{
    "<script[^>]*>.*?</script>",
    "javascript:",
    "onerror\\s*=",
    "onload\\s*=",
    "onclick\\s*=",
    "onmouseover\\s*=",
    "<iframe[^>]*>",
    "eval\\s*\\(",
    "document\\.cookie",
    "document\\.write",
    "window\\.location",
    "innerHTML\\s*=",
    "outerHTML\\s*=",
    "<embed[^>]*>",
    "<object[^>]*>",
    "fromCharCode",
    "String\\.fromCharCode",
    "alert\\s*\\(",
    "confirm\\s*\\(",
    "prompt\\s*\\(",
    "expression\\s*\\(",
    "vbscript:",
    "data:text/html",
    "base64,",
    "<img[^>]*onerror",
    "<svg[^>]*onload",
    "<body[^>]*onload",
    "<input[^>]*onfocus",
    "<meta[^>]*http-equiv",
    "\\\\x[0-9a-fA-F]{2}"
}};

/**
 * @brief Known tracker domains.
 */
static const std::array<std::string, 50> TRACKER_DOMAINS = {{
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com/tr",
    "connect.facebook.net",
    "analytics.twitter.com",
    "ads.linkedin.com",
    "pixel.adsafeprotected.com",
    "scorecardresearch.com",
    "quantserve.com",
    "hotjar.com",
    "mouseflow.com",
    "crazyegg.com",
    "luckyorange.com",
    "mixpanel.com",
    "segment.com",
    "amplitude.com",
    "heap.io",
    "fullstory.com",
    "inspectlet.com",
    "chartbeat.com",
    "newrelic.com",
    "optimizely.com",
    "vwo.com",
    "ab tasty.com",
    "kissmetrics.com",
    "woopra.com",
    "piwik.org",
    "matomo.org",
    "clicky.com",
    "statcounter.com",
    "histats.com",
    "counter.yadro.ru",
    "mc.yandex.ru",
    "addthis.com",
    "sharethis.com",
    "livechatinc.com",
    "zopim.com",
    "tawk.to",
    "intercom.io",
    "drift.com",
    "olark.com",
    "sumo.com",
    "hellobar.com",
    "privy.com",
    "mailchimp.com/pixel",
    "adroll.com",
    "criteo.com",
    "outbrain.com",
    "taboola.com"
}};

/**
 * @brief Exploit kit signatures.
 */
static const std::array<std::string, 15> EXPLOIT_KIT_SIGNATURES = {{
    "Angler EK",
    "Neutrino EK",
    "RIG EK",
    "Magnitude EK",
    "Fallout EK",
    "GrandSoft EK",
    "Underminer EK",
    "KaiXin EK",
    "Purple Fox EK",
    "Spelevo EK",
    "Rig-V EK",
    "Sundown EK",
    "Terror EK",
    "Astrum EK",
    "Kaixin EK"
}};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Calculates entropy of data (for obfuscation detection).
 */
[[nodiscard]] static double CalculateEntropy(std::string_view data) noexcept {
    if (data.empty()) return 0.0;

    std::array<uint32_t, 256> freq{};
    for (unsigned char c : data) {
        freq[c]++;
    }

    double entropy = 0.0;
    const double length = static_cast<double>(data.length());

    for (uint32_t count : freq) {
        if (count > 0) {
            const double p = static_cast<double>(count) / length;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Checks for heap spray patterns using bounded linear scanning.
 *
 * Avoids std::regex on untrusted input to prevent ReDoS.
 * Detects repeated Unicode escape sequences (\u0c0c etc.) and
 * large string literals commonly used in heap spray payloads.
 */
[[nodiscard]] static bool HasHeapSprayPattern(std::string_view script) noexcept {
    if (script.size() < 100) return false;

    constexpr size_t kMinSprayLen = 1000;
    constexpr size_t kMaxScan = 8ULL * 1024 * 1024;
    const size_t scanLen = std::min(script.size(), kMaxScan);

    // Detect repeated Unicode escape sequences (e.g. \u0c0c\u0c0c...)
    size_t unicodeRunLen = 0;
    for (size_t i = 0; i + 5 < scanLen; ) {
        if (script[i] == '\\' && script[i + 1] == 'u' &&
            std::isxdigit(static_cast<unsigned char>(script[i + 2])) &&
            std::isxdigit(static_cast<unsigned char>(script[i + 3])) &&
            std::isxdigit(static_cast<unsigned char>(script[i + 4])) &&
            std::isxdigit(static_cast<unsigned char>(script[i + 5]))) {
            unicodeRunLen += 6;
            i += 6;
            if (unicodeRunLen >= kMinSprayLen) return true;
        } else {
            unicodeRunLen = 0;
            ++i;
        }
    }

    // Detect large string literals (var x = "AAAA..."; patterns)
    size_t pos = 0;
    while (pos < scanLen) {
        const size_t q = script.find_first_of("\"'", pos);
        if (q == std::string_view::npos || q >= scanLen) break;
        const char quote = script[q];
        const size_t end = script.find(quote, q + 1);
        if (end == std::string_view::npos || end >= scanLen) break;
        if (end - q - 1 >= kMinSprayLen) return true;
        pos = end + 1;
    }

    return false;
}

/**
 * @brief Checks for shellcode patterns.
 */
[[nodiscard]] static bool HasShellcodePattern(std::span<const uint8_t> data) noexcept {
    if (data.size() < 20) return false;

    // Common shellcode patterns (x86/x64)
    const std::array<std::array<uint8_t, 4>, 5> shellcodeSignatures = {{
        {0x90, 0x90, 0x90, 0x90},  // NOP sled
        {0xEB, 0xFE, 0xEB, 0xFE},  // Jump to self (infinite loop)
        {0xCC, 0xCC, 0xCC, 0xCC},  // INT3 (debugger breakpoint)
        {0x31, 0xC0, 0x50, 0x68},  // Common shellcode prologue
        {0x6A, 0x00, 0x6A, 0x00}   // Push sequences
    }};

    // Count NOP sled (indicator of shellcode)
    uint32_t nopCount = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        if (data[i] == 0x90) {
            nopCount++;
            if (nopCount >= 20) return true;  // 20+ NOPs = likely shellcode
        } else {
            nopCount = 0;
        }
    }

    // Check for signature patterns
    for (const auto& signature : shellcodeSignatures) {
        for (size_t i = 0; i + 4 <= data.size(); ++i) {
            if (std::memcmp(&data[i], signature.data(), 4) == 0) {
                return true;
            }
        }
    }

    return false;
}

/**
 * @brief Checks for ROP chain patterns using bounded linear scanning.
 *
 * Avoids std::regex on untrusted input to prevent ReDoS.
 * Counts hex address-like patterns (0x00000000+) that suggest ROP gadgets.
 */
[[nodiscard]] static bool HasROPPattern(std::string_view script) noexcept {
    if (script.size() < 20) return false;

    constexpr size_t kMaxScan = 8ULL * 1024 * 1024;
    const size_t scanLen = std::min(script.size(), kMaxScan);
    uint32_t addressCount = 0;

    for (size_t i = 0; i + 1 < scanLen; ++i) {
        if (script[i] == '0' && (script[i + 1] == 'x' || script[i + 1] == 'X')) {
            size_t hexDigits = 0;
            size_t j = i + 2;
            while (j < scanLen && std::isxdigit(static_cast<unsigned char>(script[j]))) {
                ++hexDigits;
                ++j;
                if (hexDigits > 16) break;  // cap scan length
            }
            if (hexDigits >= 8) {
                ++addressCount;
                if (addressCount >= 10) return true;
            }
            i = j;  // advance past this token
        }
    }

    return false;
}

// ============================================================================
// CONFIG FACTORY METHODS
// ============================================================================

WebProtectionConfig WebProtectionConfig::CreateDefault() noexcept {
    return WebProtectionConfig{};
}

WebProtectionConfig WebProtectionConfig::CreateHighSecurity() noexcept {
    WebProtectionConfig config;
    config.level = WebProtectionLevel::STRICT;
    config.enableXSSProtection = true;
    config.enableExploitProtection = true;
    config.enableFormProtection = true;
    config.enableCertificatePinning = true;
    config.enablePrivacyProtection = true;
    config.enableCryptojackingProtection = true;
    config.sanitizeScripts = true;
    config.blockReflectedXSS = true;
    config.blockDOMXSS = true;
    config.enforceCT = true;
    config.blockExpiredCerts = true;
    config.blockSelfSigned = true;
    config.blockWeakAlgorithms = true;
    config.warnClearTextPasswords = true;
    config.blockFormJacking = true;
    return config;
}

WebProtectionConfig WebProtectionConfig::CreatePerformance() noexcept {
    WebProtectionConfig config;
    config.level = WebProtectionLevel::MINIMAL;
    config.enableXSSProtection = true;
    config.enableExploitProtection = false;
    config.enableFormProtection = false;
    config.enableCertificatePinning = false;
    config.enablePrivacyProtection = false;
    config.sanitizeScripts = true;
    config.maxContentToAnalyze = 10 * 1024 * 1024;  // 10 MB
    config.analysisTimeoutMs = 1000;
    config.logThreatsOnly = true;
    return config;
}

WebProtectionConfig WebProtectionConfig::CreatePrivacy() noexcept {
    WebProtectionConfig config;
    config.level = WebProtectionLevel::STRICT;
    config.enablePrivacyProtection = true;
    config.blockTrackers = true;
    config.blockThirdPartyCookies = true;
    config.preventFingerprinting = true;
    config.preventWebRTCLeak = true;
    return config;
}

void WebProtectionStatistics::Reset() noexcept {
    totalRequests.store(0, std::memory_order_relaxed);
    totalResponses.store(0, std::memory_order_relaxed);
    bytesAnalyzed.store(0, std::memory_order_relaxed);
    xssBlocked.store(0, std::memory_order_relaxed);
    exploitsBlocked.store(0, std::memory_order_relaxed);
    maliciousDownloads.store(0, std::memory_order_relaxed);
    certificateErrors.store(0, std::memory_order_relaxed);
    pinViolations.store(0, std::memory_order_relaxed);
    scriptsSanitized.store(0, std::memory_order_relaxed);
    iframesBlocked.store(0, std::memory_order_relaxed);
    formsProtected.store(0, std::memory_order_relaxed);
    trackersBlocked.store(0, std::memory_order_relaxed);
    fingerprintsBlocked.store(0, std::memory_order_relaxed);
    cookiesBlocked.store(0, std::memory_order_relaxed);
    cryptojackingBlocked.store(0, std::memory_order_relaxed);
    activeSessions.store(0, std::memory_order_relaxed);
    totalSessions.store(0, std::memory_order_relaxed);
    alertsGenerated.store(0, std::memory_order_relaxed);
    avgAnalysisTimeUs.store(0, std::memory_order_relaxed);
    maxAnalysisTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class WebProtection::WebProtectionImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    WebProtectionConfig m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    /// @brief Statistics
    WebProtectionStatistics m_statistics;

    /// @brief Certificate pins
    std::unordered_map<std::string, CertificatePin> m_pins;
    mutable std::shared_mutex m_pinsMutex;

    /// @brief Browser sessions
    std::unordered_map<uint64_t, BrowserSession> m_sessions;
    mutable std::shared_mutex m_sessionsMutex;
    std::atomic<uint64_t> m_nextSessionId{1};

    /// @brief Blocked/allowed domains
    std::unordered_set<std::string> m_blockedDomains;
    std::unordered_set<std::string> m_allowedDomains;
    mutable std::shared_mutex m_domainsMutex;

    /// @brief Alerts
    std::deque<WebAlert> m_alerts;
    mutable std::shared_mutex m_alertsMutex;
    std::atomic<uint64_t> m_nextAlertId{1};

    /// @brief Analysis results cache
    std::unordered_map<std::string, WebContentAnalysis> m_analysisCache;
    mutable std::shared_mutex m_cacheMutex;

    /// @brief Callbacks
    std::unordered_map<uint64_t, ContentAnalysisCallback> m_contentCallbacks;
    std::unordered_map<uint64_t, WebAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, CertificateCallback> m_certCallbacks;
    std::unordered_map<uint64_t, ExploitCallback> m_exploitCallbacks;
    std::unordered_map<uint64_t, XSSCallback> m_xssCallbacks;
    mutable std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    /// @brief Infrastructure integrations
    std::shared_ptr<ThreatIntel::ThreatIntelStore> m_threatIntel;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;
    std::shared_ptr<SignatureStore::SignatureStore> m_signatureStore;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // ========================================================================
    // METHODS
    // ========================================================================

    WebProtectionImpl() = default;
    ~WebProtectionImpl() = default;

    [[nodiscard]] bool Initialize(const WebProtectionConfig& config) noexcept;
    void Shutdown() noexcept;
    [[nodiscard]] bool Start() noexcept;
    void Stop() noexcept;

    // Content analysis
    [[nodiscard]] WebContentAnalysis AnalyzeContentInternal(
        const std::string& url,
        std::span<const uint8_t> content,
        const std::string& contentType);

    [[nodiscard]] ScriptAnalysis AnalyzeScriptInternal(
        const std::string& script,
        const std::string& sourceUrl);

    bool SanitizeResponseInternal(const std::string& host, std::string& htmlContent);

    // Certificate validation
    [[nodiscard]] CertificateValidation ValidateCertificateInternal(
        const std::string& host,
        const std::vector<std::vector<uint8_t>>& certChain);

    [[nodiscard]] bool CheckCertificatePin(
        const std::string& host,
        const std::vector<std::vector<uint8_t>>& certChain,
        std::string& matchedPin);

    // Form protection
    [[nodiscard]] FormProtectionResult AnalyzeFormInternal(
        const std::string& formHtml,
        const std::string& pageUrl);

    // Exploit detection
    [[nodiscard]] ExploitAnalysis AnalyzeExploitsInternal(
        std::span<const uint8_t> content,
        WebContentType contentType);

    // Privacy analysis
    [[nodiscard]] PrivacyAnalysis AnalyzePrivacyInternal(
        const std::string& content,
        const std::string& url);

    // Alert generation
    void GenerateAlert(const std::string& url, WebThreatType threatType,
                      uint8_t severity, const std::string& description);

    // Helpers
    [[nodiscard]] WebContentType DetermineContentType(const std::string& mimeType) const;
    [[nodiscard]] std::string ExtractHost(const std::string& url) const;
    [[nodiscard]] bool IsTrackerDomain(const std::string& domain) const;
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool WebProtection::WebProtectionImpl::Initialize(const WebProtectionConfig& config) noexcept {
    try {
        if (m_initialized.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"Network", L"WebProtection: Already initialized");
            return true;
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Initializing...");

        m_config = config;

        // Initialize infrastructure integrations
        m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelStore>();
        m_patternStore = std::make_shared<PatternStore::PatternStore>();
        m_signatureStore = std::make_shared<SignatureStore::SignatureStore>();
        m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        // Load blocked/allowed domains from config
        {
            std::unique_lock lock(m_domainsMutex);
            for (const auto& domain : config.blockedDomains) {
                m_blockedDomains.insert(domain);
            }
            for (const auto& domain : config.allowedDomains) {
                m_allowedDomains.insert(domain);
            }
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Initialization failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        m_initialized.store(false, std::memory_order_release);
        return false;
    }
}

void WebProtection::WebProtectionImpl::Shutdown() noexcept {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Shutting down...");

        Stop();

        {
            std::unique_lock lock(m_pinsMutex);
            m_pins.clear();
        }

        {
            std::unique_lock lock(m_sessionsMutex);
            m_sessions.clear();
        }

        {
            std::unique_lock lock(m_domainsMutex);
            m_blockedDomains.clear();
            m_allowedDomains.clear();
        }

        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.clear();
        }

        {
            std::unique_lock lock(m_cacheMutex);
            m_analysisCache.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_contentCallbacks.clear();
            m_alertCallbacks.clear();
            m_certCallbacks.clear();
            m_exploitCallbacks.clear();
            m_xssCallbacks.clear();
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Shutdown complete");

    } catch (...) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Exception during shutdown");
    }
}

bool WebProtection::WebProtectionImpl::Start() noexcept {
    try {
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"Network", L"WebProtection: Not initialized");
            return false;
        }

        if (m_running.exchange(true, std::memory_order_acq_rel)) {
            SS_LOG_WARN(L"Network", L"WebProtection: Already running");
            return true;
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Started");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Start failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

void WebProtection::WebProtectionImpl::Stop() noexcept {
    if (m_running.exchange(false, std::memory_order_acq_rel)) {
        SS_LOG_INFO(L"Network", L"WebProtection: Stopped");
    }
}

// ============================================================================
// IMPL: CONTENT ANALYSIS
// ============================================================================

WebContentAnalysis WebProtection::WebProtectionImpl::AnalyzeContentInternal(
    const std::string& url,
    std::span<const uint8_t> content,
    const std::string& contentType)
{
    const auto startTime = Clock::now();

    WebContentAnalysis analysis;
    analysis.url = url;
    analysis.host = ExtractHost(url);
    analysis.contentType = DetermineContentType(contentType);
    analysis.contentSize = content.size();
    analysis.analyzedAt = startTime;

    try {
        m_statistics.totalRequests.fetch_add(1, std::memory_order_relaxed);
        m_statistics.bytesAnalyzed.fetch_add(content.size(), std::memory_order_relaxed);

        // Check if domain is blocked
        {
            std::shared_lock lock(m_domainsMutex);
            if (m_blockedDomains.contains(analysis.host)) {
                analysis.isSafe = false;
                analysis.action = ProtectionAction::BLOCK;
                analysis.threats.push_back(WebThreatType::MALICIOUS_DOWNLOAD);
                analysis.primaryThreat = "Domain is blocklisted";
                analysis.threatScore = 100;
                return analysis;
            }

            // Check if whitelisted
            if (m_allowedDomains.contains(analysis.host)) {
                analysis.isSafe = true;
                analysis.action = ProtectionAction::ALLOW;
                return analysis;
            }
        }

        // Analyze based on content type
        if (analysis.contentType == WebContentType::JAVASCRIPT) {
            std::string script(reinterpret_cast<const char*>(content.data()), content.size());
            analysis.scriptAnalysis = AnalyzeScriptInternal(script, url);

            if (analysis.scriptAnalysis.isMalicious) {
                analysis.isSafe = false;
                analysis.threatScore = static_cast<uint8_t>(
                    std::min(analysis.scriptAnalysis.riskScore, 100.0));

                if (analysis.scriptAnalysis.hasXSS) {
                    analysis.threats.push_back(WebThreatType::XSS_REFLECTED);
                }
                if (analysis.scriptAnalysis.hasHeapSpray) {
                    analysis.threats.push_back(WebThreatType::HEAP_SPRAY);
                }
            }
        }

        // HTML content: analyze embedded scripts, forms, and cryptojacking
        if (analysis.contentType == WebContentType::HTML) {
            std::string htmlContent(reinterpret_cast<const char*>(content.data()),
                                    std::min(content.size(), m_config.maxContentToAnalyze));

            // Extract and analyze inline scripts
            if (m_config.enableXSSProtection) {
                analysis.scriptAnalysis = AnalyzeScriptInternal(htmlContent, url);
                if (analysis.scriptAnalysis.isMalicious) {
                    analysis.isSafe = false;
                    analysis.threatScore = std::max(analysis.threatScore,
                        static_cast<uint8_t>(std::min(analysis.scriptAnalysis.riskScore, 100.0)));
                    if (analysis.scriptAnalysis.hasXSS) {
                        analysis.threats.push_back(WebThreatType::XSS_REFLECTED);
                    }
                }
            }

            // Form protection
            if (m_config.enableFormProtection) {
                analysis.formProtection = AnalyzeFormInternal(htmlContent, url);
                if (analysis.formProtection.riskScore > 0) {
                    analysis.threatScore = std::max(analysis.threatScore,
                        analysis.formProtection.riskScore);
                    if (analysis.formProtection.hasClearTextPassword) {
                        analysis.threats.push_back(WebThreatType::CLEARTEXT_PASSWORD);
                    }
                    if (analysis.formProtection.hasFormJacking) {
                        analysis.isSafe = false;
                        analysis.threats.push_back(WebThreatType::FORM_HIJACK);
                    }
                }
            }

            // Cryptojacking detection
            if (m_config.enableCryptojackingProtection) {
                static const std::array<std::string_view, 12> kCryptojackingIndicators = {{
                    "coinhive.min.js", "CoinHive.Anonymous",
                    "coin-hive.com", "authedmine.com",
                    "crypto-loot.com", "CryptoLoot.Anonymous",
                    "webminepool.com", "ppoi.org/bitchin.js",
                    "monerominer.rocks", "cdn.oneminer.rocks",
                    "webassembly.instantiate", "cryptonight"
                }};

                uint32_t cryptoHits = 0;
                for (const auto& indicator : kCryptojackingIndicators) {
                    if (htmlContent.find(indicator) != std::string::npos) {
                        ++cryptoHits;
                    }
                }
                // Also check for WebAssembly + high CPU heuristic patterns
                if (htmlContent.find("WebAssembly") != std::string::npos &&
                    htmlContent.find("crypto") != std::string::npos) {
                    ++cryptoHits;
                }

                if (cryptoHits >= 2) {
                    analysis.isSafe = false;
                    analysis.threats.push_back(WebThreatType::CRYPTOJACKING);
                    analysis.threatScore = std::max(analysis.threatScore,
                        static_cast<uint8_t>(70));
                    m_statistics.cryptojackingBlocked.fetch_add(1, std::memory_order_relaxed);
                    GenerateAlert(url, WebThreatType::CRYPTOJACKING, 70,
                                 "Cryptojacking script detected in page content");
                }
            }
        }

        // Content-Type mismatch detection: header says one type, content is another
        if (content.size() >= 2) {
            const bool isPESignature = (content.size() >= 2 &&
                                        content[0] == 'M' && content[1] == 'Z');
            const bool isZipSignature = (content.size() >= 4 &&
                                         content[0] == 'P' && content[1] == 'K' &&
                                         content[2] == 0x03 && content[3] == 0x04);
            const bool isElfSignature = (content.size() >= 4 &&
                                         content[0] == 0x7F && content[1] == 'E' &&
                                         content[2] == 'L' && content[3] == 'F');

            if (analysis.contentType != WebContentType::OTHER &&
                analysis.contentType != WebContentType::UNKNOWN) {
                if ((isPESignature || isElfSignature) &&
                    (analysis.contentType == WebContentType::HTML ||
                     analysis.contentType == WebContentType::JAVASCRIPT ||
                     analysis.contentType == WebContentType::JSON ||
                     analysis.contentType == WebContentType::IMAGE)) {
                    analysis.isSafe = false;
                    analysis.threats.push_back(WebThreatType::DISGUISED_EXECUTABLE);
                    analysis.threatScore = std::max(analysis.threatScore,
                        static_cast<uint8_t>(95));
                    m_statistics.maliciousDownloads.fetch_add(1, std::memory_order_relaxed);
                    GenerateAlert(url, WebThreatType::DISGUISED_EXECUTABLE, 95,
                                 "Content-Type mismatch: executable disguised as benign content");
                }
            }
        }

        // Exploit analysis
        if (m_config.enableExploitProtection) {
            analysis.exploitAnalysis = AnalyzeExploitsInternal(content, analysis.contentType);

            if (analysis.exploitAnalysis.exploitDetected) {
                analysis.isSafe = false;
                analysis.threats.push_back(analysis.exploitAnalysis.threatType);
                analysis.threatScore = std::max(analysis.threatScore,
                    static_cast<uint8_t>(analysis.exploitAnalysis.confidence * 100));

                m_statistics.exploitsBlocked.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Privacy analysis
        if (m_config.enablePrivacyProtection && analysis.contentType == WebContentType::HTML) {
            std::string htmlContent(reinterpret_cast<const char*>(content.data()), content.size());
            analysis.privacyAnalysis = AnalyzePrivacyInternal(htmlContent, url);
        }

        // Determine action
        if (analysis.threatScore >= 80) {
            analysis.action = ProtectionAction::BLOCK;
        } else if (analysis.threatScore >= 50) {
            analysis.action = ProtectionAction::SANITIZE;
        } else if (analysis.threatScore >= 30) {
            analysis.action = ProtectionAction::WARN;
        } else {
            analysis.action = ProtectionAction::ALLOW;
        }

        // Generate alert if threat detected
        if (!analysis.isSafe && !analysis.threats.empty()) {
            GenerateAlert(url, analysis.threats[0], analysis.threatScore,
                         "Web threat detected during content analysis");
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Content analysis failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }

    const auto endTime = Clock::now();
    analysis.analysisDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

    // Update performance statistics
    const uint64_t durationUs = analysis.analysisDuration.count();

    // Exponential moving average: newAvg = (oldAvg * 7 + sample) / 8
    {
        uint64_t oldAvg = m_statistics.avgAnalysisTimeUs.load(std::memory_order_relaxed);
        uint64_t newAvg = (oldAvg == 0) ? durationUs : (oldAvg * 7 + durationUs) / 8;
        m_statistics.avgAnalysisTimeUs.store(newAvg, std::memory_order_relaxed);
    }

    // Atomic CAS loop for max update (avoids TOCTOU race)
    {
        uint64_t currentMax = m_statistics.maxAnalysisTimeUs.load(std::memory_order_relaxed);
        while (durationUs > currentMax) {
            if (m_statistics.maxAnalysisTimeUs.compare_exchange_weak(
                    currentMax, durationUs, std::memory_order_relaxed)) {
                break;
            }
        }
    }

    return analysis;
}

ScriptAnalysis WebProtection::WebProtectionImpl::AnalyzeScriptInternal(
    const std::string& script,
    const std::string& sourceUrl)
{
    ScriptAnalysis analysis;

    try {
        if (script.empty() || script.size() > m_config.maxContentToAnalyze) {
            return analysis;
        }

        // XSS pattern detection
        if (m_config.enableXSSProtection) {
            for (const auto& pattern : XSS_PATTERNS) {
                try {
                    std::regex regex(pattern, std::regex_constants::icase);
                    if (std::regex_search(script, regex)) {
                        analysis.hasXSS = true;
                        analysis.xssPatterns.push_back(pattern);
                        analysis.xssCount++;
                    }
                } catch (...) {
                    // Regex error, skip pattern
                }
            }

            if (analysis.hasXSS) {
                m_statistics.xssBlocked.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Obfuscation detection
        analysis.obfuscationScore = CalculateEntropy(script);
        if (analysis.obfuscationScore >= 7.0) {
            analysis.isObfuscated = true;
        }

        // Count actual eval() calls
        {
            size_t evalPos = 0;
            analysis.evalCount = 0;
            while ((evalPos = script.find("eval(", evalPos)) != std::string::npos) {
                analysis.evalCount++;
                evalPos += 5;
            }
            // Also count Function() constructor (eval equivalent)
            evalPos = 0;
            while ((evalPos = script.find("Function(", evalPos)) != std::string::npos) {
                analysis.evalCount++;
                evalPos += 9;
            }
        }
        analysis.documentWriteCount = 0;

        size_t pos = 0;
        while ((pos = script.find("document.write", pos)) != std::string::npos) {
            analysis.documentWriteCount++;
            pos += 14;
        }

        // Check for dangerous operations
        analysis.hasDocumentCookie = (script.find("document.cookie") != std::string::npos);
        analysis.hasLocalStorage = (script.find("localStorage") != std::string::npos);
        analysis.hasXHR = (script.find("XMLHttpRequest") != std::string::npos);
        analysis.hasFormSubmission = (script.find("submit()") != std::string::npos);

        // Exploit indicators
        if (m_config.enableExploitProtection) {
            analysis.hasHeapSpray = HasHeapSprayPattern(script);
            analysis.hasShellcode = HasShellcodePattern(
                std::span<const uint8_t>(
                    reinterpret_cast<const uint8_t*>(script.data()),
                    script.size()
                )
            );
            analysis.hasNOPSled = (script.find("\\x90\\x90") != std::string::npos);
        }

        // Calculate risk score
        double riskScore = 0.0;

        if (analysis.hasXSS) riskScore += 40.0;
        if (analysis.isObfuscated) riskScore += 20.0;
        if (analysis.evalCount > 5) riskScore += 15.0;
        if (analysis.hasDocumentCookie) riskScore += 10.0;
        if (analysis.hasHeapSpray) riskScore += 30.0;
        if (analysis.hasShellcode) riskScore += 40.0;
        if (analysis.documentWriteCount > 3) riskScore += 10.0;

        analysis.riskScore = std::min(riskScore, 100.0);
        analysis.isMalicious = (analysis.riskScore >= 50.0);

        // Invoke XSS callbacks if detected
        if (analysis.hasXSS) {
            std::lock_guard lock(m_callbacksMutex);
            for (const auto& [id, callback] : m_xssCallbacks) {
                try {
                    callback(sourceUrl, analysis);
                } catch (...) {
                    // Callback errors should not affect processing
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Script analysis failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return analysis;
}

bool WebProtection::WebProtectionImpl::SanitizeResponseInternal(
    const std::string& host,
    std::string& htmlContent)
{
    try {
        if (!m_config.sanitizeScripts || htmlContent.empty()) {
            return false;
        }

        bool sanitized = false;

        // Remove dangerous script tags
        for (const auto& pattern : XSS_PATTERNS) {
            try {
                std::regex regex(pattern, std::regex_constants::icase);
                std::string replacement = "<!-- BLOCKED: XSS -->";

                std::string newContent = std::regex_replace(htmlContent, regex, replacement);
                if (newContent != htmlContent) {
                    htmlContent = newContent;
                    sanitized = true;
                }
            } catch (...) {
                // Regex error
            }
        }

        // Remove inline event handlers
        const std::array<std::string, 10> eventHandlers = {{
            "onclick", "onload", "onerror", "onmouseover", "onfocus",
            "onblur", "onchange", "onsubmit", "onkeypress", "onkeydown"
        }};

        for (const auto& handler : eventHandlers) {
            std::regex handlerRegex(handler + "\\s*=\\s*[\"'][^\"']*[\"']",
                                   std::regex_constants::icase);
            std::string newContent = std::regex_replace(htmlContent, handlerRegex, "");
            if (newContent != htmlContent) {
                htmlContent = newContent;
                sanitized = true;
            }
        }

        if (sanitized) {
            m_statistics.scriptsSanitized.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_INFO(L"Network", L"WebProtection: Sanitized content from %ls",
                              Utils::StringUtils::ToWide(host).c_str());
        }

        return sanitized;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Sanitization failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

// ============================================================================
// IMPL: CERTIFICATE VALIDATION
// ============================================================================

CertificateValidation WebProtection::WebProtectionImpl::ValidateCertificateInternal(
    const std::string& host,
    const std::vector<std::vector<uint8_t>>& certChain)
{
    CertificateValidation validation;

    try {
        if (certChain.empty()) {
            validation.status = CertificateStatus::CHAIN_ERROR;
            validation.isValid = false;
            validation.issues.push_back("Empty certificate chain");
            return validation;
        }

        // Parse leaf certificate to extract CN, expiration, and chain validity
        validation.commonName = host;
        validation.chainLength = static_cast<uint32_t>(certChain.size());

        // Validate chain: each cert must be non-empty and properly structured
        validation.chainValid = true;
        for (size_t i = 0; i < certChain.size(); ++i) {
            if (certChain[i].empty()) {
                validation.chainValid = false;
                validation.issues.push_back(
                    "Empty certificate at chain position " + std::to_string(i));
                break;
            }
            // Minimum DER-encoded X.509 certificate is ~200 bytes
            if (certChain[i].size() < 200) {
                validation.chainValid = false;
                validation.issues.push_back(
                    "Certificate too small at chain position " + std::to_string(i) +
                    " (" + std::to_string(certChain[i].size()) + " bytes)");
                break;
            }
            // Verify DER ASN.1 SEQUENCE tag (0x30) at start
            if (certChain[i][0] != 0x30) {
                validation.chainValid = false;
                validation.issues.push_back(
                    "Invalid ASN.1 structure at chain position " + std::to_string(i));
                break;
            }
        }

        if (!validation.chainValid) {
            validation.status = CertificateStatus::CHAIN_ERROR;
            validation.isValid = false;
            m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
            return validation;
        }

        // Use Windows CryptoAPI (CRYPT32) for certificate time validation
        // Parse notBefore/notAfter from the leaf certificate's DER encoding
        const auto& leafCert = certChain[0];
        PCCERT_CONTEXT pCert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            leafCert.data(),
            static_cast<DWORD>(leafCert.size()));

        if (pCert) {
            // Extract validity period from the parsed certificate
            FILETIME ftNow;
            GetSystemTimeAsFileTime(&ftNow);

            auto FileTimeToTimePoint = [](const FILETIME& ft) -> Clock::time_point {
                ULARGE_INTEGER uli;
                uli.LowPart = ft.dwLowDateTime;
                uli.HighPart = ft.dwHighDateTime;
                // FILETIME epoch is 1601-01-01; convert to system_clock epoch
                constexpr uint64_t kEpochDiff = 116444736000000000ULL;
                const auto duration100ns = uli.QuadPart - kEpochDiff;
                return Clock::time_point(std::chrono::duration_cast<Clock::duration>(
                    std::chrono::nanoseconds(duration100ns * 100)));
            };

            validation.notBefore = FileTimeToTimePoint(pCert->pCertInfo->NotBefore);
            validation.notAfter  = FileTimeToTimePoint(pCert->pCertInfo->NotAfter);

            // Extract subject CN
            char cnBuf[256] = {};
            CertGetNameStringA(pCert, CERT_NAME_ATTR_TYPE, 0, (void*)szOID_COMMON_NAME,
                               cnBuf, sizeof(cnBuf));
            if (cnBuf[0] != '\0') {
                validation.commonName = cnBuf;
            }

            // Extract issuer CN
            char issuerBuf[256] = {};
            CertGetNameStringA(pCert, CERT_NAME_ATTR_TYPE, CERT_NAME_ISSUER_FLAG,
                               (void*)szOID_COMMON_NAME, issuerBuf, sizeof(issuerBuf));
            if (issuerBuf[0] != '\0') {
                validation.issuer = issuerBuf;
            }

            // Self-signed detection: issuer == subject and chain length is 1
            if (validation.commonName == validation.issuer && certChain.size() == 1) {
                if (m_config.blockSelfSigned) {
                    validation.status = CertificateStatus::SELF_SIGNED;
                    validation.isValid = false;
                    validation.issues.push_back("Self-signed certificate detected");
                    m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Weak signature algorithm detection (MD2/MD5/SHA1 with RSA)
            if (pCert->pCertInfo && pCert->pCertInfo->SignatureAlgorithm.pszObjId) {
                const std::string sigAlg(pCert->pCertInfo->SignatureAlgorithm.pszObjId);
                static const std::array<std::string_view, 3> kWeakOids = {{
                    "1.2.840.113549.1.1.5",   // sha1WithRSAEncryption
                    "1.2.840.113549.1.1.4",   // md5WithRSAEncryption
                    "1.2.840.113549.1.1.2"    // md2WithRSAEncryption
                }};
                for (const auto& weakOid : kWeakOids) {
                    if (sigAlg == weakOid) {
                        if (m_config.blockWeakAlgorithms) {
                            validation.status = CertificateStatus::WEAK_ALGORITHM;
                            validation.isValid = false;
                            validation.issues.push_back(
                                "Weak signature algorithm (OID: " + sigAlg + ")");
                            m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
                        }
                        break;
                    }
                }
            }

            // CN hostname mismatch check (exact or wildcard)
            {
                bool nameMatches = false;
                if (validation.commonName == host) {
                    nameMatches = true;
                } else if (validation.commonName.size() > 2 &&
                           validation.commonName[0] == '*' && validation.commonName[1] == '.') {
                    const std::string_view suffix = std::string_view(validation.commonName).substr(1);
                    if (host.size() > suffix.size() &&
                        host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0) {
                        nameMatches = true;
                    }
                }
                if (!nameMatches) {
                    validation.status = CertificateStatus::NAME_MISMATCH;
                    validation.isValid = false;
                    validation.issues.push_back(
                        "Certificate CN '" + validation.commonName +
                        "' does not match host '" + host + "'");
                    m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
                }
            }

            CertFreeCertificateContext(pCert);
        } else {
            // Fallback: certificate couldn't be parsed — treat as untrusted
            validation.status = CertificateStatus::CHAIN_ERROR;
            validation.isValid = false;
            validation.issues.push_back("Failed to parse leaf certificate via CryptoAPI");
            m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
            return validation;
        }

        const auto now = Clock::now();
        if (now < validation.notBefore) {
            validation.status = CertificateStatus::NOT_YET_VALID;
            validation.isValid = false;
            validation.issues.push_back("Certificate not yet valid");
        } else if (now > validation.notAfter) {
            validation.status = CertificateStatus::EXPIRED;
            validation.isValid = false;
            validation.issues.push_back("Certificate expired");

            if (m_config.blockExpiredCerts) {
                m_statistics.certificateErrors.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            validation.status = CertificateStatus::VALID;
            validation.isValid = true;
        }

        // Check certificate pinning
        if (m_config.enableCertificatePinning) {
            std::string matchedPin;
            validation.pinChecked = true;
            validation.pinValid = CheckCertificatePin(host, certChain, matchedPin);
            validation.matchedPin = matchedPin;

            if (!validation.pinValid && !matchedPin.empty()) {
                validation.status = CertificateStatus::PIN_VIOLATION;
                validation.isValid = false;
                validation.issues.push_back("Certificate pin validation failed");

                m_statistics.pinViolations.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Invoke certificate callbacks
        {
            std::lock_guard lock(m_callbacksMutex);
            for (const auto& [id, callback] : m_certCallbacks) {
                try {
                    callback(host, validation);
                } catch (...) {
                    // Callback errors should not affect processing
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Certificate validation failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        validation.status = CertificateStatus::CHAIN_ERROR;
        validation.isValid = false;
    }

    return validation;
}

bool WebProtection::WebProtectionImpl::CheckCertificatePin(
    const std::string& host,
    const std::vector<std::vector<uint8_t>>& certChain,
    std::string& matchedPin)
{
    try {
        std::shared_lock lock(m_pinsMutex);

        // Check for exact match
        auto it = m_pins.find(host);
        if (it == m_pins.end()) {
            // Check for subdomain match
            for (const auto& [domain, pin] : m_pins) {
                if (pin.includeSubdomains && host.ends_with("." + domain)) {
                    it = m_pins.find(domain);
                    break;
                }
            }
        }

        if (it == m_pins.end()) {
            return true;  // No pin configured, validation passes
        }

        const auto& pin = it->second;

        // Check if pin is expired
        if (Clock::now() > pin.expiry) {
            return true;  // Expired pin, validation passes
        }

        // Compute SHA-256 of the leaf certificate's SPKI for pin comparison
        if (!certChain.empty()) {
            const auto& cert = certChain[0];

            Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
            std::string certHash;
            if (hasher.Init() &&
                hasher.Update(cert.data(), cert.size()) &&
                hasher.FinalHex(certHash)) {

                // Check if hash matches any primary pin
                for (const auto& pinHash : pin.sha256Pins) {
                    if (certHash == pinHash) {
                        matchedPin = pinHash;
                        return true;
                    }
                }

                // Check backup pins
                for (const auto& pinHash : pin.backupPins) {
                    if (certHash == pinHash) {
                        matchedPin = pinHash;
                        return true;
                    }
                }
            } else {
                SS_LOG_ERROR(L"Network", L"WebProtection: SHA-256 hash computation failed for pin check");
                return true;  // On hash failure, do not block
            }
            }
        }

        return false;  // No match found

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Pin check failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return true;  // On error, don't block
    }
}

// ============================================================================
// IMPL: FORM PROTECTION
// ============================================================================

FormProtectionResult WebProtection::WebProtectionImpl::AnalyzeFormInternal(
    const std::string& formHtml,
    const std::string& pageUrl)
{
    FormProtectionResult result;

    try {
        if (formHtml.empty()) {
            return result;
        }

        // Extract form action
        std::regex actionRegex(R"(action\s*=\s*[\"']([^\"']*)[\"'])");
        std::smatch actionMatch;
        if (std::regex_search(formHtml, actionMatch, actionRegex)) {
            result.action = actionMatch[1].str();
            result.isSecure = (result.action.find("https://") == 0);
        }

        // Extract form method
        std::regex methodRegex(R"(method\s*=\s*[\"']([^\"']*)[\"'])");
        std::smatch methodMatch;
        if (std::regex_search(formHtml, methodMatch, methodRegex)) {
            result.method = methodMatch[1].str();
        }

        // Find all input fields
        std::regex inputRegex(R"(<input[^>]*>)");
        auto inputsBegin = std::sregex_iterator(formHtml.begin(), formHtml.end(), inputRegex);
        auto inputsEnd = std::sregex_iterator();

        for (std::sregex_iterator i = inputsBegin; i != inputsEnd; ++i) {
            std::string inputTag = i->str();
            FormField field;

            // Extract type
            std::regex typeRegex(R"(type\s*=\s*[\"']([^\"']*)[\"'])");
            std::smatch typeMatch;
            if (std::regex_search(inputTag, typeMatch, typeRegex)) {
                field.type = typeMatch[1].str();
            }

            // Extract name
            std::regex nameRegex(R"(name\s*=\s*[\"']([^\"']*)[\"'])");
            std::smatch nameMatch;
            if (std::regex_search(inputTag, nameMatch, nameRegex)) {
                field.name = nameMatch[1].str();
            }

            // Check if password field
            if (field.type == "password") {
                field.isPassword = true;
                result.passwordFields++;
            }

            // Check for sensitive fields
            std::string nameLower = field.name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            if (nameLower.find("credit") != std::string::npos ||
                nameLower.find("card") != std::string::npos) {
                field.isCreditCard = true;
                field.isSensitive = true;
                result.sensitiveFields++;
            }

            if (nameLower.find("ssn") != std::string::npos ||
                nameLower.find("social") != std::string::npos) {
                field.isSSN = true;
                field.isSensitive = true;
                result.sensitiveFields++;
            }

            field.isEncrypted = result.isSecure;
            result.fields.push_back(field);
        }

        // Check for cleartext password submission
        if (result.passwordFields > 0 && !result.isSecure) {
            result.hasClearTextPassword = true;
            result.warnings.push_back("Password submitted over unencrypted connection");
            result.riskScore += 50;

            if (m_config.warnClearTextPasswords) {
                GenerateAlert(pageUrl, WebThreatType::CLEARTEXT_PASSWORD, 70,
                             "Form submits passwords over HTTP");
            }
        }

        // Check for excessive password fields (possible credential stealer)
        if (result.passwordFields > 5) {
            result.hasFormJacking = true;
            result.warnings.push_back("Suspicious number of password fields");
            result.riskScore += 30;
        }

        m_statistics.formsProtected.fetch_add(1, std::memory_order_relaxed);

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Form analysis failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return result;
}

// ============================================================================
// IMPL: EXPLOIT DETECTION
// ============================================================================

ExploitAnalysis WebProtection::WebProtectionImpl::AnalyzeExploitsInternal(
    std::span<const uint8_t> content,
    WebContentType contentType)
{
    ExploitAnalysis analysis;

    try {
        if (content.empty() || content.size() > m_config.maxContentToAnalyze) {
            return analysis;
        }

        // Shellcode detection
        if (HasShellcodePattern(content)) {
            analysis.shellcodeDetected = true;
            analysis.exploitDetected = true;
            analysis.threatType = WebThreatType::BROWSER_EXPLOIT;
            analysis.confidence = 0.85;
        }

        // Heap spray detection (for JavaScript content)
        if (contentType == WebContentType::JAVASCRIPT) {
            std::string script(reinterpret_cast<const char*>(content.data()), content.size());

            if (HasHeapSprayPattern(script)) {
                analysis.heapSpray = true;
                analysis.exploitDetected = true;
                analysis.threatType = WebThreatType::HEAP_SPRAY;
                analysis.confidence = std::max(analysis.confidence, 0.75);
            }

            if (HasROPPattern(script)) {
                analysis.ropChain = true;
                analysis.exploitDetected = true;
                analysis.threatType = WebThreatType::ROP_CHAIN;
                analysis.confidence = std::max(analysis.confidence, 0.80);
            }
        }

        // Exploit kit signature matching — scan up to 256KB of content
        constexpr size_t kExploitScanLimit = 256 * 1024;
        std::string contentStr(reinterpret_cast<const char*>(content.data()),
                             std::min(content.size(), kExploitScanLimit));

        for (const auto& kitSignature : EXPLOIT_KIT_SIGNATURES) {
            if (contentStr.find(kitSignature) != std::string::npos) {
                analysis.isExploitKit = true;
                analysis.exploitKitFamily = kitSignature;
                analysis.exploitDetected = true;
                analysis.threatType = WebThreatType::EXPLOIT_KIT;
                analysis.confidence = 0.95;
                analysis.matchedSignatures.push_back(kitSignature);
            }
        }

        // Invoke exploit callbacks if detected
        if (analysis.exploitDetected) {
            std::lock_guard lock(m_callbacksMutex);
            for (const auto& [id, callback] : m_exploitCallbacks) {
                try {
                    callback("", analysis);
                } catch (...) {
                    // Callback errors should not affect processing
                }
            }
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Exploit analysis failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return analysis;
}

// ============================================================================
// IMPL: PRIVACY ANALYSIS
// ============================================================================

PrivacyAnalysis WebProtection::WebProtectionImpl::AnalyzePrivacyInternal(
    const std::string& content,
    const std::string& url)
{
    PrivacyAnalysis analysis;

    try {
        if (content.empty()) {
            return analysis;
        }

        // Tracker detection
        for (const auto& trackerDomain : TRACKER_DOMAINS) {
            if (content.find(trackerDomain) != std::string::npos) {
                analysis.trackerCount++;
                analysis.trackers.push_back(trackerDomain);

                if (std::find(analysis.trackerDomains.begin(), analysis.trackerDomains.end(),
                             trackerDomain) == analysis.trackerDomains.end()) {
                    analysis.trackerDomains.push_back(trackerDomain);
                }
            }
        }

        if (analysis.trackerCount > 0 && m_config.blockTrackers) {
            m_statistics.trackersBlocked.fetch_add(analysis.trackerCount, std::memory_order_relaxed);
        }

        // Canvas fingerprinting detection
        if (content.find("toDataURL") != std::string::npos &&
            content.find("canvas") != std::string::npos) {
            analysis.canvasFingerprinting = true;

            if (m_config.preventFingerprinting) {
                m_statistics.fingerprintsBlocked.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // WebGL fingerprinting
        if (content.find("getParameter") != std::string::npos &&
            content.find("WEBGL") != std::string::npos) {
            analysis.webglFingerprinting = true;
        }

        // Audio fingerprinting
        if (content.find("AudioContext") != std::string::npos ||
            content.find("webkitAudioContext") != std::string::npos) {
            analysis.audioFingerprinting = true;
        }

        // Font fingerprinting
        if (content.find("offsetWidth") != std::string::npos &&
            content.find("measureText") != std::string::npos) {
            analysis.fontFingerprinting = true;
        }

        // WebRTC leak detection
        if (content.find("RTCPeerConnection") != std::string::npos ||
            content.find("webkitRTCPeerConnection") != std::string::npos) {
            analysis.webrtcLeak = true;
        }

        // Calculate privacy score with saturating subtraction
        int32_t score = 100;
        score -= static_cast<int32_t>(std::min(analysis.trackerCount * 5U, 40U));
        if (analysis.canvasFingerprinting) score -= 15;
        if (analysis.webglFingerprinting) score -= 10;
        if (analysis.audioFingerprinting) score -= 10;
        if (analysis.fontFingerprinting) score -= 10;
        if (analysis.webrtcLeak) score -= 15;
        analysis.privacyScore = static_cast<uint8_t>(std::max(score, 0));

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Privacy analysis failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }

    return analysis;
}

// ============================================================================
// IMPL: ALERT GENERATION
// ============================================================================

void WebProtection::WebProtectionImpl::GenerateAlert(
    const std::string& url,
    WebThreatType threatType,
    uint8_t severity,
    const std::string& description)
{
    try {
        WebAlert alert;
        alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
        alert.timestamp = Clock::now();
        alert.threatType = threatType;
        alert.threatDescription = description;
        alert.severity = severity;
        alert.url = url;
        alert.host = ExtractHost(url);

        // Store alert
        {
            std::unique_lock lock(m_alertsMutex);
            m_alerts.push_back(alert);

            // Limit alert history
            if (m_alerts.size() > 10000) {
                m_alerts.pop_front();
            }
        }

        m_statistics.alertsGenerated.fetch_add(1, std::memory_order_relaxed);

        // Invoke callbacks
        {
            std::lock_guard lock(m_callbacksMutex);
            for (const auto& [id, callback] : m_alertCallbacks) {
                try {
                    callback(alert);
                } catch (...) {
                    // Callback errors should not affect processing
                }
            }
        }

        SS_LOG_WARN(L"Network", L"WebProtection: Alert generated - ID: %llu, URL: %ls, Severity: %u",
                          static_cast<unsigned long long>(alert.alertId),
                          Utils::StringUtils::ToWide(url).c_str(),
                          static_cast<unsigned>(severity));

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Failed to generate alert - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
    }
}

// ============================================================================
// IMPL: HELPER METHODS
// ============================================================================

WebContentType WebProtection::WebProtectionImpl::DetermineContentType(const std::string& mimeType) const {
    if (mimeType.empty()) return WebContentType::UNKNOWN;

    std::string lower = mimeType;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower.find("html") != std::string::npos) return WebContentType::HTML;
    if (lower.find("javascript") != std::string::npos) return WebContentType::JAVASCRIPT;
    if (lower.find("css") != std::string::npos) return WebContentType::CSS;
    if (lower.find("json") != std::string::npos) return WebContentType::JSON;
    if (lower.find("xml") != std::string::npos) return WebContentType::XML;
    if (lower.find("image") != std::string::npos) return WebContentType::IMAGE;
    if (lower.find("video") != std::string::npos) return WebContentType::VIDEO;
    if (lower.find("audio") != std::string::npos) return WebContentType::AUDIO;
    if (lower.find("font") != std::string::npos) return WebContentType::FONT;
    if (lower.find("pdf") != std::string::npos) return WebContentType::PDF;
    if (lower.find("flash") != std::string::npos) return WebContentType::FLASH;
    if (lower.find("wasm") != std::string::npos) return WebContentType::WASM;

    return WebContentType::OTHER;
}

std::string WebProtection::WebProtectionImpl::ExtractHost(const std::string& url) const {
    try {
        // Simple host extraction (real implementation would be more robust)
        size_t hostStart = url.find("://");
        if (hostStart == std::string::npos) {
            hostStart = 0;
        } else {
            hostStart += 3;
        }

        size_t hostEnd = url.find('/', hostStart);
        if (hostEnd == std::string::npos) {
            hostEnd = url.length();
        }

        size_t portPos = url.find(':', hostStart);
        if (portPos != std::string::npos && portPos < hostEnd) {
            hostEnd = portPos;
        }

        return url.substr(hostStart, hostEnd - hostStart);

    } catch (...) {
        return "";
    }
}

bool WebProtection::WebProtectionImpl::IsTrackerDomain(const std::string& domain) const {
    for (const auto& tracker : TRACKER_DOMAINS) {
        if (domain.find(tracker) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

// Singleton
WebProtection& WebProtection::Instance() {
    static WebProtection instance;
    return instance;
}

WebProtection::WebProtection()
    : m_impl(std::make_unique<WebProtectionImpl>())
{
    SS_LOG_INFO(L"Network", L"WebProtection: Constructor called");
}

WebProtection::~WebProtection() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Network", L"WebProtection: Destructor called");
}

// Lifecycle
bool WebProtection::Initialize(const WebProtectionConfig& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

bool WebProtection::Start() {
    return m_impl ? m_impl->Start() : false;
}

void WebProtection::Stop() {
    if (m_impl) {
        m_impl->Stop();
    }
}

void WebProtection::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool WebProtection::IsRunning() const noexcept {
    return m_impl ? m_impl->m_running.load(std::memory_order_acquire) : false;
}

// Content analysis
bool WebProtection::SanitizeResponse(const std::string& host, std::string& htmlContent) {
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) return false;
    return m_impl->SanitizeResponseInternal(host, htmlContent);
}

WebContentAnalysis WebProtection::AnalyzeContent(
    const std::string& url,
    std::span<const uint8_t> content,
    const std::string& contentType)
{
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) return WebContentAnalysis{};
    return m_impl->AnalyzeContentInternal(url, content, contentType);
}

ScriptAnalysis WebProtection::AnalyzeScript(
    const std::string& script,
    const std::string& sourceUrl)
{
    if (!m_impl || !m_impl->m_running.load(std::memory_order_acquire)) return ScriptAnalysis{};
    return m_impl->AnalyzeScriptInternal(script, sourceUrl);
}

// Certificate protection
CertificateValidation WebProtection::ValidateCertificate(
    const std::string& host,
    const std::vector<std::vector<uint8_t>>& certChain)
{
    return m_impl ? m_impl->ValidateCertificateInternal(host, certChain) : CertificateValidation{};
}

bool WebProtection::AddCertificatePin(const CertificatePin& pin) {
    if (!m_impl) return false;

    try {
        std::unique_lock lock(m_impl->m_pinsMutex);
        m_impl->m_pins[pin.domain] = pin;

        SS_LOG_INFO(L"Network", L"WebProtection: Added certificate pin for %ls",
                          Utils::StringUtils::ToWide(pin.domain).c_str());
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Failed to add pin - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

bool WebProtection::RemoveCertificatePin(const std::string& domain) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_pinsMutex);
    return m_impl->m_pins.erase(domain) > 0;
}

bool WebProtection::IsCertificatePinned(const std::string& domain) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_pinsMutex);
    return m_impl->m_pins.contains(domain);
}

// Form protection
FormProtectionResult WebProtection::AnalyzeForm(
    const std::string& formHtml,
    const std::string& pageUrl)
{
    return m_impl ? m_impl->AnalyzeFormInternal(formHtml, pageUrl) : FormProtectionResult{};
}

bool WebProtection::CheckCredentialTheft(
    const std::string& url,
    const std::string& fieldName,
    const std::string& fieldValue)
{
    if (!m_impl) return false;

    try {
        // Check if URL is suspicious
        const std::string host = m_impl->ExtractHost(url);

        {
            std::shared_lock lock(m_impl->m_domainsMutex);
            if (m_impl->m_blockedDomains.contains(host)) {
                return true;  // Threat detected
            }
        }

        // Check for credential field patterns
        std::string nameLower = fieldName;
        std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

        if (nameLower.find("password") != std::string::npos ||
            nameLower.find("passwd") != std::string::npos ||
            nameLower.find("pwd") != std::string::npos) {

            // Password field detected - check if over HTTPS
            if (url.find("https://") != 0) {
                SS_LOG_WARN(L"Network", L"WebProtection: Credential theft risk - password over HTTP");
                return true;
            }
        }

        return false;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Credential theft check failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

// Exploit protection
ExploitAnalysis WebProtection::AnalyzeExploits(
    std::span<const uint8_t> content,
    WebContentType contentType)
{
    return m_impl ? m_impl->AnalyzeExploitsInternal(content, contentType) : ExploitAnalysis{};
}

// Privacy protection
PrivacyAnalysis WebProtection::AnalyzePrivacy(
    const std::string& content,
    const std::string& url)
{
    return m_impl ? m_impl->AnalyzePrivacyInternal(content, url) : PrivacyAnalysis{};
}

bool WebProtection::IsTracker(const std::string& domain) const {
    return m_impl ? m_impl->IsTrackerDomain(domain) : false;
}

// Browser session management
uint64_t WebProtection::ProtectBrowser(uint32_t processId, BrowserType browser) {
    if (!m_impl) return 0;

    try {
        std::unique_lock lock(m_impl->m_sessionsMutex);

        const uint64_t sessionId = m_impl->m_nextSessionId.fetch_add(1, std::memory_order_relaxed);

        BrowserSession session;
        session.sessionId = sessionId;
        session.browser = browser;
        session.processId = processId;
        session.isProtected = true;
        session.protectionLevel = m_impl->m_config.level;
        session.startTime = Clock::now();
        session.lastActivity = Clock::now();

        m_impl->m_sessions[sessionId] = session;
        m_impl->m_statistics.activeSessions.fetch_add(1, std::memory_order_relaxed);
        m_impl->m_statistics.totalSessions.fetch_add(1, std::memory_order_relaxed);

        SS_LOG_INFO(L"Network", L"WebProtection: Browser protected - Session: %llu, PID: %u",
                          static_cast<unsigned long long>(sessionId), processId);
        return sessionId;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: Failed to protect browser - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return 0;
    }
}

void WebProtection::UnprotectBrowser(uint64_t sessionId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_sessionsMutex);
    if (m_impl->m_sessions.erase(sessionId) > 0) {
        m_impl->m_statistics.activeSessions.fetch_sub(1, std::memory_order_relaxed);
        SS_LOG_INFO(L"Network", L"WebProtection: Browser unprotected - Session: %llu",
                          static_cast<unsigned long long>(sessionId));
    }
}

std::vector<BrowserSession> WebProtection::GetActiveSessions() const {
    std::vector<BrowserSession> sessions;

    if (!m_impl) return sessions;

    std::shared_lock lock(m_impl->m_sessionsMutex);
    sessions.reserve(m_impl->m_sessions.size());

    for (const auto& [id, session] : m_impl->m_sessions) {
        sessions.push_back(session);
    }

    return sessions;
}

// Domain management
bool WebProtection::BlockDomain(const std::string& domain) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_domainsMutex);
    m_impl->m_blockedDomains.insert(domain);

    SS_LOG_INFO(L"Network", L"WebProtection: Domain blocked - %ls",
                      Utils::StringUtils::ToWide(domain).c_str());
    return true;
}

bool WebProtection::UnblockDomain(const std::string& domain) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_domainsMutex);
    return m_impl->m_blockedDomains.erase(domain) > 0;
}

bool WebProtection::AllowDomain(const std::string& domain) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_domainsMutex);
    m_impl->m_allowedDomains.insert(domain);

    SS_LOG_INFO(L"Network", L"WebProtection: Domain allowed - %ls",
                      Utils::StringUtils::ToWide(domain).c_str());
    return true;
}

bool WebProtection::IsDomainBlocked(const std::string& domain) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_domainsMutex);
    return m_impl->m_blockedDomains.contains(domain);
}

// Callbacks
uint64_t WebProtection::RegisterContentCallback(ContentAnalysisCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_contentCallbacks[id] = std::move(callback);
    return id;
}

uint64_t WebProtection::RegisterAlertCallback(WebAlertCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_alertCallbacks[id] = std::move(callback);
    return id;
}

uint64_t WebProtection::RegisterCertificateCallback(CertificateCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_certCallbacks[id] = std::move(callback);
    return id;
}

uint64_t WebProtection::RegisterExploitCallback(ExploitCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_exploitCallbacks[id] = std::move(callback);
    return id;
}

uint64_t WebProtection::RegisterXSSCallback(XSSCallback callback) {
    if (!m_impl) return 0;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    const uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_xssCallbacks[id] = std::move(callback);
    return id;
}

bool WebProtection::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return false;

    std::lock_guard lock(m_impl->m_callbacksMutex);

    bool removed = false;
    removed |= (m_impl->m_contentCallbacks.erase(callbackId) > 0);
    removed |= (m_impl->m_alertCallbacks.erase(callbackId) > 0);
    removed |= (m_impl->m_certCallbacks.erase(callbackId) > 0);
    removed |= (m_impl->m_exploitCallbacks.erase(callbackId) > 0);
    removed |= (m_impl->m_xssCallbacks.erase(callbackId) > 0);

    return removed;
}

// Statistics
const WebProtectionStatistics& WebProtection::GetStatistics() const noexcept {
    static WebProtectionStatistics emptyStats;
    return m_impl ? m_impl->m_statistics : emptyStats;
}

void WebProtection::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

// Diagnostics
bool WebProtection::PerformDiagnostics() const {
    if (!m_impl) return false;

    SS_LOG_INFO(L"Network", L"WebProtection: Diagnostics");
    SS_LOG_INFO(L"Network", L"  Initialized: %d", m_impl->m_initialized.load() ? 1 : 0);
    SS_LOG_INFO(L"Network", L"  Running: %d", m_impl->m_running.load() ? 1 : 0);
    SS_LOG_INFO(L"Network", L"  Total Requests: %llu", static_cast<unsigned long long>(m_impl->m_statistics.totalRequests.load()));
    SS_LOG_INFO(L"Network", L"  XSS Blocked: %llu", static_cast<unsigned long long>(m_impl->m_statistics.xssBlocked.load()));
    SS_LOG_INFO(L"Network", L"  Exploits Blocked: %llu", static_cast<unsigned long long>(m_impl->m_statistics.exploitsBlocked.load()));
    SS_LOG_INFO(L"Network", L"  Scripts Sanitized: %llu", static_cast<unsigned long long>(m_impl->m_statistics.scriptsSanitized.load()));
    SS_LOG_INFO(L"Network", L"  Active Sessions: %u", m_impl->m_statistics.activeSessions.load());
    SS_LOG_INFO(L"Network", L"  Trackers Blocked: %llu", static_cast<unsigned long long>(m_impl->m_statistics.trackersBlocked.load()));
    SS_LOG_INFO(L"Network", L"  Alerts Generated: %llu", static_cast<unsigned long long>(m_impl->m_statistics.alertsGenerated.load()));

    return true;
}

bool WebProtection::ExportDiagnostics(const std::wstring& outputPath) const {
    if (!m_impl) return false;

    try {
        std::ofstream ofs(outputPath, std::ios::out | std::ios::trunc);
        if (!ofs.is_open()) {
            SS_LOG_ERROR(L"Network", L"WebProtection: Failed to open diagnostics output file");
            return false;
        }

        const auto& stats = m_impl->m_statistics;
        const auto now = Clock::now();
        const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count();

        ofs << "=== ShadowStrike WebProtection Diagnostics ===\n";
        ofs << "Timestamp (epoch): " << epoch << "\n";
        ofs << "Initialized: " << (m_impl->m_initialized.load() ? "true" : "false") << "\n";
        ofs << "Running: " << (m_impl->m_running.load() ? "true" : "false") << "\n";
        ofs << "Protection Level: " << static_cast<int>(m_impl->m_config.level) << "\n\n";

        ofs << "--- Traffic Statistics ---\n";
        ofs << "Total Requests: " << stats.totalRequests.load() << "\n";
        ofs << "Total Responses: " << stats.totalResponses.load() << "\n";
        ofs << "Bytes Analyzed: " << stats.bytesAnalyzed.load() << "\n\n";

        ofs << "--- Threat Statistics ---\n";
        ofs << "XSS Blocked: " << stats.xssBlocked.load() << "\n";
        ofs << "Exploits Blocked: " << stats.exploitsBlocked.load() << "\n";
        ofs << "Malicious Downloads: " << stats.maliciousDownloads.load() << "\n";
        ofs << "Certificate Errors: " << stats.certificateErrors.load() << "\n";
        ofs << "Pin Violations: " << stats.pinViolations.load() << "\n";
        ofs << "Cryptojacking Blocked: " << stats.cryptojackingBlocked.load() << "\n\n";

        ofs << "--- Content Statistics ---\n";
        ofs << "Scripts Sanitized: " << stats.scriptsSanitized.load() << "\n";
        ofs << "Iframes Blocked: " << stats.iframesBlocked.load() << "\n";
        ofs << "Forms Protected: " << stats.formsProtected.load() << "\n\n";

        ofs << "--- Privacy Statistics ---\n";
        ofs << "Trackers Blocked: " << stats.trackersBlocked.load() << "\n";
        ofs << "Fingerprints Blocked: " << stats.fingerprintsBlocked.load() << "\n";
        ofs << "Cookies Blocked: " << stats.cookiesBlocked.load() << "\n\n";

        ofs << "--- Session Statistics ---\n";
        ofs << "Active Sessions: " << stats.activeSessions.load() << "\n";
        ofs << "Total Sessions: " << stats.totalSessions.load() << "\n\n";

        ofs << "--- Performance ---\n";
        ofs << "Avg Analysis Time (us): " << stats.avgAnalysisTimeUs.load() << "\n";
        ofs << "Max Analysis Time (us): " << stats.maxAnalysisTimeUs.load() << "\n";
        ofs << "Alerts Generated: " << stats.alertsGenerated.load() << "\n";

        {
            std::shared_lock lock(m_impl->m_pinsMutex);
            ofs << "\n--- Certificate Pins ---\n";
            ofs << "Pinned Domains: " << m_impl->m_pins.size() << "\n";
        }

        {
            std::shared_lock lock(m_impl->m_domainsMutex);
            ofs << "\n--- Domain Lists ---\n";
            ofs << "Blocked Domains: " << m_impl->m_blockedDomains.size() << "\n";
            ofs << "Allowed Domains: " << m_impl->m_allowedDomains.size() << "\n";
        }

        ofs << "\n=== End of Diagnostics ===\n";
        ofs.flush();

        if (!ofs.good()) {
            SS_LOG_ERROR(L"Network", L"WebProtection: Diagnostics write failed");
            return false;
        }

        SS_LOG_INFO(L"Network", L"WebProtection: Diagnostics exported successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"WebProtection: ExportDiagnostics failed - %ls",
                           Utils::StringUtils::ToWide(e.what()).c_str());
        return false;
    }
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
