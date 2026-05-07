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
 * ShadowStrike Core Network - URL ANALYZER IMPLEMENTATION
 * ============================================================================
 *
 * @file URLAnalyzer.cpp
 * @brief Enterprise-grade URL and domain analysis engine.
 *
 * This module provides comprehensive URL and domain security analysis by
 * combining multiple detection techniques including reputation lookups,
 * pattern matching, DGA detection, phishing analysis, and ML classification.
 *
 * Architecture:
 * - PIMPL pattern for ABI stability
 * - Meyers' Singleton for thread-safe instance management
 * - Multi-layered detection (reputation → patterns → heuristics → ML)
 * - LRU cache with TTL expiration
 * - Integration with ThreatIntel, PatternStore, WhiteListStore
 *
 * Detection Capabilities:
 * - URL reputation via ThreatIntel
 * - Phishing detection (brand impersonation, lookalike domains)
 * - DGA detection (entropy, n-gram, ML classification)
 * - Homograph attack detection (IDN/Punycode)
 * - Typosquatting detection (Levenshtein distance)
 * - Malware distribution patterns
 * - C2 infrastructure detection
 * - Content filtering (50+ categories)
 *
 * MITRE ATT&CK Coverage:
 * - T1566.002: Phishing - Spearphishing Link
 * - T1204.001: User Execution - Malicious Link
 * - T1071.001: Application Layer Protocol
 * - T1568.002: Dynamic Resolution - DGA
 * - T1189: Drive-by Compromise
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "URLAnalyzer.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/CryptoUtils.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"
#include "../../HashStore/HashStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <cctype>
#include <cmath>
#include <limits>
#include <sstream>
#include <iomanip>
#include <thread>
#include <future>

// Shorthand alias for the StringUtils namespace to avoid long qualification
namespace StringUtils = ShadowStrike::Utils::StringUtils;

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================
namespace {

    // Character sets for analysis
    const std::string VOWELS = "aeiouAEIOU";
    const std::string CONSONANTS = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
    const std::string SUSPICIOUS_CHARS = "@%&=#";

    // Suspicious TLDs
    const std::unordered_set<std::string> SUSPICIOUS_TLDS = {
        "tk", "ml", "ga", "cf", "gq",  // Free domains
        "xyz", "top", "work", "click", "link",
        "pw", "cc", "ws"
    };

    // Known brand keywords for phishing detection
    const std::unordered_set<std::string> PROTECTED_BRANDS = {
        "paypal", "amazon", "google", "microsoft", "apple",
        "facebook", "instagram", "twitter", "linkedin",
        "bank", "chase", "wellsfargo", "citibank",
        "netflix", "dropbox", "adobe", "salesforce"
    };

    // URL shorteners
    const std::unordered_set<std::string> URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly",
        "t.co", "short.link", "rebrand.ly"
    };

    // Executable extensions
    const std::unordered_set<std::string> EXECUTABLE_EXTENSIONS = {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".com",
        ".vbs", ".js", ".jar", ".msi", ".app", ".dmg"
    };

    // DGA families (simplified fingerprints)
    struct DGAFamily {
        std::string name;
        double minEntropy;
        double maxConsonantRatio;
        size_t minLength;
    };

    const std::vector<DGAFamily> KNOWN_DGA_FAMILIES = {
        {"Conficker", 3.8, 0.8, 10},
        {"Cryptolocker", 4.0, 0.75, 12},
        {"Bamital", 3.5, 0.7, 8},
        {"Matsnu", 3.9, 0.8, 15},
        {"Generic", 3.5, 0.7, 8}
    };

    // Scoring weights
    constexpr int WEIGHT_REPUTATION = 40;
    constexpr int WEIGHT_PATTERN = 30;
    constexpr int WEIGHT_HEURISTIC = 20;
    constexpr int WEIGHT_ML = 10;

} // anonymous namespace

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// ASCII-only lowercase for domain names (RFC 952 domains are ASCII).
// Does NOT use StringUtils::ToLower which only operates on wide strings.
[[nodiscard]] static std::string NarrowToLower(std::string_view input) {
    std::string result(input);
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); });
    return result;
}

// Checks if a string contains any embedded null bytes (security bypass vector).
[[nodiscard]] static bool ContainsNullByte(std::string_view str) noexcept {
    return str.find('\0') != std::string_view::npos;
}

// Checks for any control character (0x00..0x1F or 0x7F) or whitespace that must
// not appear in a well-formed URL. CR/LF in particular enables HTTP request
// smuggling and log injection. RFC 3986 forbids all of these in URI strings.
[[nodiscard]] static bool ContainsControlOrSpace(std::string_view str) noexcept {
    for (unsigned char c : str) {
        if (c < 0x20 || c == 0x7F || c == ' ' || c == '\t') {
            return true;
        }
    }
    return false;
}

// Sanitize an arbitrary string for safe inclusion in log messages. Strips
// control characters (CR/LF/NUL/...) that could be used for log injection,
// and caps length to avoid log-storage exhaustion. Output is ASCII-only;
// non-ASCII bytes are escaped as '?'. Caller-supplied URL/domain MUST be
// passed through this function before logging via SS_LOG_*.
[[nodiscard]] static std::string SanitizeForLog(std::string_view input) {
    constexpr size_t kMaxLogLen = 256;
    std::string out;
    const size_t n = std::min(input.size(), kMaxLogLen);
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x20 || c == 0x7F) {
            out.push_back('.');
        } else if (c >= 0x80) {
            out.push_back('?');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    if (input.size() > kMaxLogLen) {
        out.append("...");
    }
    return out;
}

// Strict decimal port parser. Returns std::nullopt for empty input,
// for any non-digit character, or for values outside [0, 65535].
// Unlike std::stoi, it does not accept leading whitespace, '+'/'-',
// or trailing garbage -- all of which are common parser-confusion vectors.
[[nodiscard]] static std::optional<uint16_t> ParseStrictPort(std::string_view s) noexcept {
    if (s.empty() || s.size() > 5) {
        return std::nullopt;
    }
    uint32_t value = 0;
    for (char ch : s) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        value = value * 10u + static_cast<uint32_t>(ch - '0');
        if (value > 65535u) {
            return std::nullopt;
        }
    }
    return static_cast<uint16_t>(value);
}

// Checks if a string looks like an IPv4 address (digits and dots, with each
// octet in [0,255]). Reject leading zeros that could indicate octal encoding.
[[nodiscard]] static bool IsIPv4Address(std::string_view host) noexcept {
    if (host.empty() || host.size() > 15) return false;
    int dotCount = 0;
    int digitRun = 0;
    uint32_t octet = 0;
    bool firstDigitInOctet = true;
    bool octetHasLeadingZero = false;
    for (char c : host) {
        if (c == '.') {
            if (digitRun == 0 || digitRun > 3) return false;
            // Reject "01.2.3.4" style which can be interpreted as octal by
            // some resolvers and used to bypass IP-based blocklists.
            if (octetHasLeadingZero && digitRun > 1) return false;
            if (octet > 255u) return false;
            dotCount++;
            digitRun = 0;
            octet = 0;
            firstDigitInOctet = true;
            octetHasLeadingZero = false;
        } else if (c >= '0' && c <= '9') {
            if (firstDigitInOctet && c == '0') {
                octetHasLeadingZero = true;
            }
            firstDigitInOctet = false;
            octet = octet * 10u + static_cast<uint32_t>(c - '0');
            digitRun++;
            if (digitRun > 3 || octet > 255u) return false;
        } else {
            return false;
        }
    }
    if (octetHasLeadingZero && digitRun > 1) return false;
    return dotCount == 3 && digitRun > 0 && digitRun <= 3 && octet <= 255u;
}

// Checks if an IPv4 address is in a private/reserved range.
[[nodiscard]] static bool IsPrivateIPv4(std::string_view host) noexcept {
    if (!IsIPv4Address(host)) return false;
    // Parse first two octets for quick check
    unsigned int a = 0, b = 0;
    int pos = 0;
    for (char c : host) {
        if (c == '.') {
            pos++;
            if (pos >= 2) break;
        } else if (pos == 0) {
            a = a * 10 + static_cast<unsigned>(c - '0');
        } else if (pos == 1) {
            b = b * 10 + static_cast<unsigned>(c - '0');
        }
    }
    // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
    return (a == 10) || (a == 127) || (a == 192 && b == 168) ||
           (a == 172 && b >= 16 && b <= 31) || (a == 169 && b == 254);
}

[[nodiscard]] static bool IsLocalhostAddress(std::string_view host) noexcept {
    auto lower = NarrowToLower(host);
    return lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "[::1]";
}

// Detect double-percent-encoding (e.g., %2525 → %25 → % or %252e → %2e → '.').
[[nodiscard]] static bool HasDoublePercentEncoding(std::string_view str) noexcept {
    // A second-encoded escape sequence is represented as "%25" followed by the
    // hex digits of another percent-encoded byte, such as "%252e" for "%2e".
    for (size_t i = 0; i + 4 < str.size(); ++i) {
        if (str[i] == '%' && str[i + 1] == '2' && str[i + 2] == '5' &&
            std::isxdigit(static_cast<unsigned char>(str[i + 3])) &&
            std::isxdigit(static_cast<unsigned char>(str[i + 4]))) {
            return true;
        }
    }
    return false;
}

// Check for suspicious characters that indicate obfuscation.
[[nodiscard]] static bool ContainsSuspiciousChars(std::string_view str) noexcept {
    for (char c : SUSPICIOUS_CHARS) {
        if (str.find(c) != std::string_view::npos) {
            return true;
        }
    }
    return false;
}

// Bounded Levenshtein distance using a two-row DP rolling buffer.
// Memory complexity is O(min(m,n)) instead of O(m*n) and inputs are capped to
// kMaxLen to make the cost deterministic on attacker-controlled input.
// Returns the integer distance, or kSentinelTooLong if either input exceeds
// the cap (callers should treat that as "not similar").
inline constexpr size_t kLevenshteinMaxLen = 128;
inline constexpr size_t kLevenshteinSentinelTooLong =
    (std::numeric_limits<size_t>::max)();

[[nodiscard]] static size_t CalculateLevenshteinDistance(
    std::string_view s1,
    std::string_view s2) noexcept {

    if (s1.size() > kLevenshteinMaxLen || s2.size() > kLevenshteinMaxLen) {
        return kLevenshteinSentinelTooLong;
    }

    const size_t m = s1.size();
    const size_t n = s2.size();
    if (m == 0) return n;
    if (n == 0) return m;

    // Always iterate over the shorter dimension to bound memory.
    if (m < n) {
        return CalculateLevenshteinDistance(s2, s1);
    }

    // Two rolling rows of length n+1. n <= kLevenshteinMaxLen so this is O(128).
    std::array<size_t, kLevenshteinMaxLen + 1> prev{};
    std::array<size_t, kLevenshteinMaxLen + 1> curr{};
    for (size_t j = 0; j <= n; ++j) {
        prev[j] = j;
    }

    for (size_t i = 1; i <= m; ++i) {
        curr[0] = i;
        for (size_t j = 1; j <= n; ++j) {
            const size_t cost = (s1[i - 1] == s2[j - 1]) ? 0u : 1u;
            curr[j] = (std::min)(
                (std::min)(curr[j - 1] + 1u, prev[j] + 1u),
                prev[j - 1] + cost);
        }
        std::swap(prev, curr);
    }
    return prev[n];
}

[[nodiscard]] static double CalculateSimilarity(std::string_view s1,
                                                std::string_view s2) noexcept {
    const size_t distance = CalculateLevenshteinDistance(s1, s2);
    if (distance == kLevenshteinSentinelTooLong) {
        return 0.0;
    }
    const size_t maxLen = (std::max)(s1.size(), s2.size());
    if (maxLen == 0) return 1.0;
    return 1.0 - (static_cast<double>(distance) / static_cast<double>(maxLen));
}

[[nodiscard]] static bool ContainsBrandKeyword(const std::string& domain) {
    std::string lower = NarrowToLower(domain);
    for (const auto& brand : PROTECTED_BRANDS) {
        if (lower.find(brand) != std::string::npos) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] static bool IsURLShortener(const std::string& domain) {
    std::string lower = NarrowToLower(domain);
    return URL_SHORTENERS.find(lower) != URL_SHORTENERS.end();
}

[[nodiscard]] static bool HasExecutableExtension(const std::string& path) {
    std::string lower = NarrowToLower(path);
    for (const auto& ext : EXECUTABLE_EXTENSIONS) {
        if (lower.ends_with(ext)) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] static bool IsSuspiciousTLD(const std::string& tld) {
    std::string lower = NarrowToLower(tld);
    return SUSPICIOUS_TLDS.find(lower) != SUSPICIOUS_TLDS.end();
}

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

URLAnalyzerConfig URLAnalyzerConfig::CreateDefault() noexcept {
    URLAnalyzerConfig config;
    config.enabled = true;
    config.enableReputation = true;
    config.enablePatternMatching = true;
    config.enableDGADetection = true;
    config.enablePhishingDetection = true;
    config.enableHomographDetection = true;
    config.enableMLClassification = true;
    config.enableContentFiltering = false;
    config.blockThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_MALICIOUS;
    config.warnThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_SUSPICIOUS;
    config.dgaThreshold = URLAnalyzerConstants::DGA_ML_CONFIDENCE;
    config.phishingThreshold = URLAnalyzerConstants::PHISHING_SIMILARITY_THRESHOLD;
    config.enableCaching = true;
    config.maxCacheSize = URLAnalyzerConstants::URL_CACHE_SIZE;
    config.cacheTTLMs = URLAnalyzerConstants::CACHE_TTL_CLEAN_MS;
    config.followRedirects = false;
    config.maxRedirectDepth = URLAnalyzerConstants::MAX_REDIRECT_DEPTH;
    config.logAllAnalysis = false;
    config.logBlockedOnly = true;
    return config;
}

URLAnalyzerConfig URLAnalyzerConfig::CreateHighSecurity() noexcept {
    URLAnalyzerConfig config;
    config.enabled = true;
    config.enableReputation = true;
    config.enablePatternMatching = true;
    config.enableDGADetection = true;
    config.enablePhishingDetection = true;
    config.enableHomographDetection = true;
    config.enableMLClassification = true;
    config.enableContentFiltering = true;
    config.blockThreshold = 60;  // More aggressive
    config.warnThreshold = 40;
    config.dgaThreshold = 0.6;   // Lower threshold
    config.phishingThreshold = 0.75;
    config.enableCaching = true;
    config.maxCacheSize = URLAnalyzerConstants::URL_CACHE_SIZE;
    config.cacheTTLMs = URLAnalyzerConstants::CACHE_TTL_MALICIOUS_MS;
    config.followRedirects = true;
    config.maxRedirectDepth = 5;
    config.logAllAnalysis = true;
    config.logBlockedOnly = false;
    return config;
}

URLAnalyzerConfig URLAnalyzerConfig::CreatePerformance() noexcept {
    URLAnalyzerConfig config;
    config.enabled = true;
    config.enableReputation = true;
    config.enablePatternMatching = true;
    config.enableDGADetection = false;  // Disable expensive checks
    config.enablePhishingDetection = false;
    config.enableHomographDetection = false;
    config.enableMLClassification = false;
    config.enableContentFiltering = false;
    config.blockThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_MALICIOUS;
    config.warnThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_SUSPICIOUS;
    config.enableCaching = true;
    config.maxCacheSize = 2000000;  // Larger cache
    config.cacheTTLMs = URLAnalyzerConstants::CACHE_TTL_CLEAN_MS;
    config.followRedirects = false;
    config.maxRedirectDepth = 0;
    config.logAllAnalysis = false;
    config.logBlockedOnly = true;
    return config;
}

URLAnalyzerConfig URLAnalyzerConfig::CreateContentFiltering() {
    URLAnalyzerConfig config;
    config.enabled = true;
    config.enableReputation = true;
    config.enablePatternMatching = true;
    config.enableDGADetection = false;
    config.enablePhishingDetection = false;
    config.enableHomographDetection = false;
    config.enableMLClassification = false;
    config.enableContentFiltering = true;
    config.blockThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_MALICIOUS;
    config.warnThreshold = URLAnalyzerConstants::SCORE_THRESHOLD_SUSPICIOUS;

    // Block adult, gambling, drugs, weapons, violence
    config.blockedCategories = {
        URLCategory::ADULT,
        URLCategory::GAMBLING,
        URLCategory::DRUGS,
        URLCategory::WEAPONS,
        URLCategory::VIOLENCE,
        URLCategory::HATE_SPEECH
    };

    config.enableCaching = true;
    config.maxCacheSize = URLAnalyzerConstants::URL_CACHE_SIZE;
    config.cacheTTLMs = URLAnalyzerConstants::CACHE_TTL_CLEAN_MS;
    config.followRedirects = false;
    config.logAllAnalysis = false;
    config.logBlockedOnly = true;
    return config;
}

void URLAnalyzerStatistics::Reset() noexcept {
    totalURLsAnalyzed = 0;
    totalDomainsAnalyzed = 0;
    urlsBlocked = 0;
    urlsWarned = 0;
    urlsAllowed = 0;
    phishingDetected = 0;
    malwareDetected = 0;
    c2Detected = 0;
    dgaDetected = 0;
    homographDetected = 0;

    for (auto& counter : categoryHits) {
        counter = 0;
    }

    cacheHits = 0;
    cacheMisses = 0;
    cacheSize = 0;
    avgAnalysisTimeUs = 0;
    maxAnalysisTimeUs = 0;
    analysisPerSecond = 0;
    parseErrors = 0;
    analysisErrors = 0;
}

// ============================================================================
// CACHE ENTRY STRUCTURE
// ============================================================================

struct CacheEntry {
    URLVerdict verdict;
    std::chrono::system_clock::time_point insertTime;
    std::chrono::system_clock::time_point expiryTime;
    mutable std::atomic<uint32_t> hitCount{ 0 };

    CacheEntry() = default;
    CacheEntry(const CacheEntry& other)
        : verdict(other.verdict)
        , insertTime(other.insertTime)
        , expiryTime(other.expiryTime)
        , hitCount(other.hitCount.load(std::memory_order_relaxed)) {}
    CacheEntry& operator=(const CacheEntry& other) {
        if (this != &other) {
            verdict = other.verdict;
            insertTime = other.insertTime;
            expiryTime = other.expiryTime;
            hitCount.store(other.hitCount.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
        return *this;
    }
    CacheEntry(CacheEntry&& other) noexcept
        : verdict(std::move(other.verdict))
        , insertTime(other.insertTime)
        , expiryTime(other.expiryTime)
        , hitCount(other.hitCount.load(std::memory_order_relaxed)) {}
    CacheEntry& operator=(CacheEntry&& other) noexcept {
        if (this != &other) {
            verdict = std::move(other.verdict);
            insertTime = other.insertTime;
            expiryTime = other.expiryTime;
            hitCount.store(other.hitCount.load(std::memory_order_relaxed),
                std::memory_order_relaxed);
        }
        return *this;
    }

    [[nodiscard]] bool IsExpired() const noexcept {
        return std::chrono::system_clock::now() >= expiryTime;
    }
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class URLAnalyzerImpl final {
public:
    URLAnalyzerImpl() = default;
    ~URLAnalyzerImpl() = default;

    // Delete copy/move
    URLAnalyzerImpl(const URLAnalyzerImpl&) = delete;
    URLAnalyzerImpl& operator=(const URLAnalyzerImpl&) = delete;
    URLAnalyzerImpl(URLAnalyzerImpl&&) = delete;
    URLAnalyzerImpl& operator=(URLAnalyzerImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const URLAnalyzerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;

            // Load whitelist/blacklist from config
            for (const auto& domain : config.whitelistedDomains) {
                m_whitelist.insert(NarrowToLower(domain));
            }
            for (const auto& domain : config.blacklistedDomains) {
                m_blacklist[NarrowToLower(domain)] = "Config-Blacklisted";
            }

            // Resolve external subsystem pointers.
            // PatternStore and ThreatIntelLookup are NOT singletons --
            // they are managed by the platform orchestrator and wired
            // in during system startup.  We keep non-owning pointers.
            // If an orchestrator has not registered them yet, we
            // simply run without those engines (graceful degradation).
            // Callers can re-init after the subsystems become available.

            m_initialized = true;

            SS_LOG_INFO(L"Network", L"URLAnalyzer initialized (reputation=%d, DGA=%d, phishing=%d)",
                static_cast<int>(config.enableReputation),
                static_cast<int>(config.enableDGADetection),
                static_cast<int>(config.enablePhishingDetection));

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"URLAnalyzer initialization failed: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // SUBSYSTEM WIRING (called by orchestrator after subsystems are alive)
    // ========================================================================

    void SetThreatIntelLookup(ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
        std::unique_lock lock(m_mutex);
        m_threatIntelLookup = lookup;
    }

    void SetPatternStore(ShadowStrike::PatternStore::PatternStore* store) noexcept {
        std::unique_lock lock(m_mutex);
        m_patternStore = store;
    }

    void Shutdown() noexcept {
        // Signal any outstanding async work to stop BEFORE taking the lock.
        // This avoids a deadlock where a ScanURLAsync thread is
        // inside ScanURL (holding shared_lock) while we wait for exclusive.
        m_shutdownRequested.store(true, std::memory_order_release);

        // Wait for all outstanding async work to complete.
        // We must do this BEFORE acquiring the exclusive lock, because
        // the async threads may need shared_lock to finish.
        {
            std::vector<std::future<void>> pending;
            {
                std::unique_lock lock(m_mutex);
                pending = std::move(m_pendingFutures);
            }
            // Wait outside the lock to avoid deadlock
            for (auto& f : pending) {
                try { f.wait(); } catch (...) {}
            }
        }

        std::unique_lock lock(m_mutex);

        try {
            m_cache.clear();
            m_whitelist.clear();
            m_blacklist.clear();

            m_analysisCallbacks.clear();
            m_threatCallbacks.clear();
            m_phishingCallbacks.clear();
            m_dgaCallbacks.clear();

            // Drop subsystem references -- they are about to be torn down
            m_threatIntelLookup = nullptr;
            m_patternStore = nullptr;

            m_initialized = false;

            SS_LOG_INFO(L"Network", L"URLAnalyzer shutdown complete");

        } catch (...) {
            // Suppress all exceptions in shutdown
        }
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    [[nodiscard]] URLAnalyzerConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    bool UpdateConfig(const URLAnalyzerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            m_config = config;
            SS_LOG_INFO(L"Network", L"URLAnalyzer configuration updated");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"UpdateConfig - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    [[nodiscard]] URLVerdict ScanURL(const std::string& url) {
        auto startTime = std::chrono::steady_clock::now();
        URLVerdict verdict;
        verdict.analyzedUrl = url;

        try {
            // Snapshot config and check initialization under read lock.
            // We copy the config so that all subsequent analysis uses a
            // consistent snapshot, eliminating TOCTOU races against
            // concurrent UpdateConfig() calls.
            URLAnalyzerConfig configSnapshot;
            {
                std::shared_lock lock(m_mutex);
                if (!m_initialized) {
                    SS_LOG_WARN(L"Network", L"ScanURL called before initialization");
                    verdict.category = URLCategory::UNKNOWN;
                    verdict.recommendedAction = URLFilterAction::ALLOW;
                    return verdict;
                }
                configSnapshot = m_config;
            }

            m_stats.totalURLsAnalyzed++;

            // Input validation -- length cap (DoS / overflow protection).
            // Over-cap or empty inputs are rejected with an explicit BLOCK
            // verdict so callers can distinguish from "unknown".
            if (url.empty() || url.length() > URLAnalyzerConstants::MAX_URL_LENGTH) {
                verdict.isBlocked = true;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.severity = VerdictSeverity::HIGH;
                verdict.recommendedAction = URLFilterAction::BLOCK;
                verdict.threatName = url.empty() ? "URL.Empty" : "URL.OverLengthLimit";
                m_stats.parseErrors++;
                m_stats.urlsBlocked++;
                return verdict;
            }

            // Reject URLs with embedded null bytes (security bypass vector)
            if (ContainsNullByte(url)) {
                SS_LOG_WARN(L"Network", L"ScanURL - Rejected URL with embedded null byte");
                verdict.isBlocked = true;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.severity = VerdictSeverity::HIGH;
                verdict.recommendedAction = URLFilterAction::BLOCK;
                verdict.threatName = "URL.EmbeddedNull";
                m_stats.urlsBlocked++;
                return verdict;
            }

            // Reject URLs containing CR/LF/control chars/whitespace.
            // CRLF in a URL enables HTTP request smuggling, log injection,
            // and header splitting.  RFC 3986 forbids these characters.
            if (ContainsControlOrSpace(url)) {
                SS_LOG_WARN(L"Network",
                    L"ScanURL - Rejected URL containing control/whitespace characters");
                verdict.isBlocked = true;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.severity = VerdictSeverity::HIGH;
                verdict.recommendedAction = URLFilterAction::BLOCK;
                verdict.threatName = "URL.ControlChars";
                m_stats.urlsBlocked++;
                return verdict;
            }

            // Parse URL up-front so the cache key is the *post-normalised*
            // form. Caching the raw input would let an attacker bypass a
            // verdict by varying case, default-port, or trailing slashes
            // (cache poisoning).
            ParsedURL parsed = ParseURL(url);
            if (!parsed.isValid) {
                verdict.category = URLCategory::UNKNOWN;
                verdict.recommendedAction = URLFilterAction::BLOCK;
                m_stats.parseErrors++;
                return verdict;
            }

            // Cache key derived from normalised URL (falls back to raw URL
            // only for schemes that produce no normalised form, e.g. mailto:).
            const std::string cacheKey = parsed.normalizedUrl.empty()
                ? url : parsed.normalizedUrl;

            // Check cache first (cache has its own lock)
            if (configSnapshot.enableCaching) {
                auto cached = GetFromCache(cacheKey);
                if (cached.has_value()) {
                    m_stats.cacheHits++;
                    verdict = cached.value();
                    verdict.fromCache = true;
                    return verdict;
                }
                m_stats.cacheMisses++;
            }

            // Check whitelist/blacklist under read lock.
            // NOTE: We must NOT write to the cache under a shared_lock --
            // that would cause a data race.  Instead, we defer caching
            // and use the normal CacheVerdict() (exclusive lock) path.
            {
                std::shared_lock lock(m_mutex);

                if (IsWhitelistedHostOrParent(parsed.hostNormalized,
                        configSnapshot.whitelistSubdomains)) {
                    verdict.category = URLCategory::SAFE;
                    verdict.severity = VerdictSeverity::CLEAN;
                    verdict.recommendedAction = URLFilterAction::ALLOW;
                    verdict.detectionMethod = DetectionMethod::UNKNOWN;
                    // Cache after releasing the shared lock
                    lock.unlock();
                    if (configSnapshot.enableCaching) {
                        CacheVerdict(cacheKey, verdict);
                    }
                    m_stats.urlsAllowed++;
                    return verdict;
                }

                if (IsBlacklistedInternal(parsed.hostNormalized)) {
                    verdict.isBlocked = true;
                    verdict.category = URLCategory::MALWARE_DIST;
                    verdict.severity = VerdictSeverity::CRITICAL;
                    verdict.recommendedAction = URLFilterAction::BLOCK;
                    verdict.detectionMethod = DetectionMethod::MANUAL;
                    verdict.threatName = GetBlacklistThreat(parsed.hostNormalized);
                    // Cache after releasing the shared lock
                    lock.unlock();
                    if (configSnapshot.enableCaching) {
                        CacheVerdict(cacheKey, verdict);
                    }
                    m_stats.urlsBlocked++;
                    return verdict;
                }
            }

            // Multi-layer analysis (uses configSnapshot for all thresholds)
            int totalScore = 0;

            // 1. Reputation check (ThreatIntel integration)
            if (configSnapshot.enableReputation) {
                totalScore += AnalyzeReputation(parsed, verdict);
            }

            // 2. Pattern matching (PatternStore integration)
            if (configSnapshot.enablePatternMatching) {
                totalScore += AnalyzePatterns(parsed, verdict);
            }

            // 3. DGA detection
            if (configSnapshot.enableDGADetection) {
                totalScore += AnalyzeDGA(parsed, verdict, configSnapshot);
            }

            // 4. Phishing detection
            if (configSnapshot.enablePhishingDetection) {
                totalScore += AnalyzePhishing(parsed, verdict, configSnapshot);
            }

            // 5. Homograph detection
            if (configSnapshot.enableHomographDetection) {
                totalScore += AnalyzeHomograph(parsed, verdict);
            }

            // 6. Heuristic analysis
            totalScore += AnalyzeHeuristics(parsed, verdict);

            // Determine final verdict
            verdict.confidenceScore = std::clamp(totalScore, 0, 100);

            if (totalScore >= configSnapshot.blockThreshold) {
                verdict.isBlocked = true;
                verdict.severity = VerdictSeverity::HIGH;
                verdict.recommendedAction = URLFilterAction::BLOCK;
                m_stats.urlsBlocked++;
            } else if (totalScore >= configSnapshot.warnThreshold) {
                verdict.isSuspicious = true;
                verdict.severity = VerdictSeverity::MEDIUM;
                verdict.recommendedAction = URLFilterAction::WARN;
                m_stats.urlsWarned++;
            } else {
                verdict.severity = VerdictSeverity::LOW;
                verdict.recommendedAction = URLFilterAction::ALLOW;
                m_stats.urlsAllowed++;
            }

            // Cache result (exclusive lock inside) -- normalised key.
            if (configSnapshot.enableCaching) {
                CacheVerdict(cacheKey, verdict);
            }

            // Snapshot callbacks under lock, invoke outside lock
            NotifyAnalysis(url, verdict);
            if (verdict.threatType != ThreatType::NONE) {
                NotifyThreat(url, verdict.threatType, verdict);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ScanURL - Exception: %hs", e.what());
            verdict.category = URLCategory::UNKNOWN;
            verdict.recommendedAction = URLFilterAction::BLOCK;
            m_stats.analysisErrors++;
        }

        auto endTime = std::chrono::steady_clock::now();
        verdict.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        UpdatePerformanceStats(verdict.analysisTime.count());

        return verdict;
    }

    [[nodiscard]] URLVerdict ScanURL(const std::string& url, bool followRedirects, bool extractFeatures) {
        auto verdict = ScanURL(url);

        if (followRedirects) {
            // Redirect following requires an HTTP client subsystem (not yet
            // integrated).  Log a warning so operators know the parameter
            // was requested but could not be honoured.
            SS_LOG_WARN(L"Network",
                L"ScanURL: followRedirects requested but HTTP client not integrated");
        }

        if (extractFeatures) {
            verdict.features = ExtractFeaturesInternal(ParseURL(url));
        }

        return verdict;
    }

    [[nodiscard]] std::vector<URLVerdict> ScanURLs(const std::vector<std::string>& urls) {
        std::vector<URLVerdict> results;
        results.reserve(urls.size());

        for (const auto& url : urls) {
            results.push_back(ScanURL(url));
        }

        return results;
    }

    void ScanURLAsync(const std::string& url, URLAnalysisCallback callback) {
        if (!callback) return;

        // Check shutdown before spawning a new thread
        if (m_shutdownRequested.load(std::memory_order_acquire)) return;

        // We must NOT capture `this` in a detached thread -- the singleton
        // may be destroyed during static teardown while the thread is still
        // running, causing use-after-free.  Instead we perform the scan
        // synchronously on a short-lived std::async with a shared_future
        // that the system can abandon, and we guard with the shutdown flag.
        // Using std::async with launch::async ensures the runtime joins or
        // waits on the future destructor, preventing UAF.
        auto fut = std::async(std::launch::async,
            [this, url, cb = std::move(callback)]() {
                try {
                    if (m_shutdownRequested.load(std::memory_order_acquire)) return;
                    auto verdict = ScanURL(url);
                    if (m_shutdownRequested.load(std::memory_order_acquire)) return;
                    cb(url, verdict);
                } catch (const std::exception& e) {
                    SS_LOG_ERROR(L"Network", L"ScanURLAsync - Exception: %hs", e.what());
                }
            });

        // Store the future so the destructor blocks until completion,
        // preventing use-after-free during static destruction.
        {
            std::unique_lock lock(m_mutex);
            // Garbage-collect completed futures first
            std::erase_if(m_pendingFutures, [](std::future<void>& f) {
                return f.valid() &&
                       f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
            });
            // Cap the queue at MAX_PENDING_ASYNC.  An unbounded queue is a
            // straightforward DoS: a hostile caller can spawn ScanURLAsync
            // faster than scans complete and exhaust memory / threads.
            // When at capacity we drop the oldest pending entry (its future
            // destructor waits for completion, so we do not abandon work --
            // we simply pace the producer).
            constexpr size_t MAX_PENDING_ASYNC = 1024;
            if (m_pendingFutures.size() >= MAX_PENDING_ASYNC) {
                SS_LOG_WARN(L"Network",
                    L"ScanURLAsync - pending queue full (%zu); blocking on oldest",
                    m_pendingFutures.size());
                m_pendingFutures.erase(m_pendingFutures.begin());
            }
            m_pendingFutures.push_back(std::move(fut));
        }
    }

    // ========================================================================
    // DOMAIN ANALYSIS
    // ========================================================================

    [[nodiscard]] URLVerdict ScanDomain(const std::string& domain) {
        // Build a synthetic URL for analysis.  The domain MUST NOT contain
        // characters that would alter URL structure when concatenated --
        // otherwise an attacker controlling the domain string could inject
        // a path/query/fragment or a second authority component.
        URLVerdict verdict;
        verdict.analyzedUrl = domain;

        if (domain.empty() ||
            domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
            ContainsNullByte(domain) ||
            ContainsControlOrSpace(domain) ||
            domain.find_first_of("/\\?#@") != std::string::npos) {
            verdict.isBlocked = true;
            verdict.category = URLCategory::SUSPICIOUS;
            verdict.severity = VerdictSeverity::HIGH;
            verdict.recommendedAction = URLFilterAction::BLOCK;
            verdict.threatName = "Domain.Malformed";
            m_stats.parseErrors++;
            return verdict;
        }
        std::string url = "http://" + domain + "/";
        return ScanURL(url);
    }

    [[nodiscard]] DomainVerdict AnalyzeDomain(const std::string& domain) {
        auto startTime = std::chrono::steady_clock::now();
        DomainVerdict verdict;

        try {
            // Input validation -- reject empty / oversized / NUL-tainted /
            // control-char input before any further processing.  Without
            // these checks an attacker could feed a 4GB string or one
            // containing CR/LF for log injection in callees.
            if (domain.empty() ||
                domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
                ContainsNullByte(domain) ||
                ContainsControlOrSpace(domain)) {
                verdict.isBlocked = true;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.threatName = "Domain.Malformed";
                verdict.confidenceScore = 100;
                verdict.reputationScore = 0;
                m_stats.parseErrors++;
                auto endTime = std::chrono::steady_clock::now();
                verdict.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(
                    endTime - startTime);
                return verdict;
            }

            m_stats.totalDomainsAnalyzed++;

            // Snapshot the config and resolve subsystem pointer under lock.
            // Also perform whitelist/blacklist checks while we hold the lock
            // (IsWhitelisted*/IsBlacklistedInternal read shared state).
            URLAnalyzerConfig configSnapshot;
            ShadowStrike::ThreatIntel::ThreatIntelLookup* threatIntelPtr = nullptr;
            bool isWhitelisted = false;
            bool isBlacklisted = false;
            std::string blacklistThreat;
            std::string normalizedDomain = NarrowToLower(domain);

            {
                std::shared_lock lock(m_mutex);
                configSnapshot = m_config;
                threatIntelPtr = m_threatIntelLookup;
                isWhitelisted = IsWhitelistedHostOrParent(normalizedDomain,
                    configSnapshot.whitelistSubdomains);
                if (!isWhitelisted) {
                    isBlacklisted = IsBlacklistedInternal(normalizedDomain);
                    if (isBlacklisted) {
                        blacklistThreat = GetBlacklistThreat(normalizedDomain);
                    }
                }
            }

            // Check whitelist
            if (isWhitelisted) {
                verdict.category = URLCategory::SAFE;
                verdict.confidenceScore = 100;
                verdict.reputationScore = 100;
                auto endTime = std::chrono::steady_clock::now();
                verdict.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(
                    endTime - startTime);
                return verdict;
            }

            // Check blacklist
            if (isBlacklisted) {
                verdict.isBlocked = true;
                verdict.category = URLCategory::MALWARE_DIST;
                verdict.threatName = std::move(blacklistThreat);
                verdict.confidenceScore = 100;
                verdict.reputationScore = 0;
                auto endTime = std::chrono::steady_clock::now();
                verdict.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(
                    endTime - startTime);
                return verdict;
            }

            // DGA detection (use normalised lowercase domain so mixed-case
            // input is analysed consistently).
            if (configSnapshot.enableDGADetection) {
                auto [score, family] = GetDGAScoreInternal(normalizedDomain, configSnapshot);
                verdict.isDGA = (score >= configSnapshot.dgaThreshold);
                verdict.dgaFamily = family;

                if (verdict.isDGA) {
                    verdict.isBlocked = true;
                    verdict.category = URLCategory::DGA;
                    verdict.confidenceScore = static_cast<int>(score * 100);
                    m_stats.dgaDetected++;
                }
            }

            // Reputation check via ThreatIntelLookup (use normalised domain).
            if (threatIntelPtr) {
                try {
                    if (threatIntelPtr->IsInitialized()) {
                        auto result = threatIntelPtr->LookupDomain(normalizedDomain);
                        if (result.found) {
                            verdict.reputationScore = static_cast<uint8_t>(
                                100 - std::min<uint8_t>(result.threatScore, 100));
                            if (result.IsMalicious()) {
                                verdict.isBlocked = true;
                                verdict.category = URLCategory::MALWARE_DIST;
                                verdict.confidenceScore = static_cast<int>(result.threatScore);
                            }
                        }
                    } else {
                        verdict.reputationScore = 50;  // Unknown
                    }
                } catch (...) {
                    verdict.reputationScore = 50;
                }
            } else {
                verdict.reputationScore = 50;  // No ThreatIntel subsystem
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeDomain - Exception: %hs", e.what());
        }

        auto endTime = std::chrono::steady_clock::now();
        verdict.analysisTime = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime);

        return verdict;
    }

    [[nodiscard]] std::unordered_map<std::string, DomainVerdict> AnalyzeDomains(
        const std::vector<std::string>& domains) {

        std::unordered_map<std::string, DomainVerdict> results;

        for (const auto& domain : domains) {
            results[domain] = AnalyzeDomain(domain);
        }

        return results;
    }

    // ========================================================================
    // DGA DETECTION
    // ========================================================================

    [[nodiscard]] bool IsDGA(const std::string& domain) {
        URLAnalyzerConfig configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }
        auto [score, family] = GetDGAScoreInternal(domain, configSnapshot);
        return score >= configSnapshot.dgaThreshold;
    }

    [[nodiscard]] std::pair<double, std::string> GetDGAScoreInternal(
        const std::string& domain,
        const URLAnalyzerConfig& cfg) {
        try {
            // Extract domain without TLD
            std::string domainPart = domain;
            size_t lastDot = domain.find_last_of('.');
            if (lastDot != std::string::npos) {
                domainPart = domain.substr(0, lastDot);
            }

            if (domainPart.length() < URLAnalyzerConstants::DGA_MIN_LENGTH) {
                return {0.0, ""};
            }

            // Calculate entropy
            double entropy = CalculateEntropyInternal(domainPart);

            // Calculate consonant ratio
            size_t consonantCount = 0;
            for (char c : domainPart) {
                if (CONSONANTS.find(c) != std::string::npos) {
                    consonantCount++;
                }
            }
            double consonantRatio = static_cast<double>(consonantCount) / domainPart.length();

            // Calculate digit ratio
            size_t digitCount = 0;
            for (char c : domainPart) {
                if (std::isdigit(static_cast<unsigned char>(c))) {
                    digitCount++;
                }
            }
            double digitRatio = static_cast<double>(digitCount) / domainPart.length();

            // Check against known DGA families
            for (const auto& family : KNOWN_DGA_FAMILIES) {
                if (entropy >= family.minEntropy &&
                    consonantRatio >= family.maxConsonantRatio &&
                    domainPart.length() >= family.minLength) {

                    double score = 0.0;
                    score += (entropy / 5.0) * 0.4;  // Max entropy ~5.0
                    score += consonantRatio * 0.3;
                    score += (digitRatio > 0.2 ? 0.3 : 0.0);

                    return {std::min(score, 1.0), family.name};
                }
            }

            // Generic DGA scoring
            double score = 0.0;
            if (entropy >= URLAnalyzerConstants::DGA_ENTROPY_THRESHOLD) {
                score += 0.4;
            }
            if (consonantRatio >= URLAnalyzerConstants::DGA_CONSONANT_RATIO) {
                score += 0.3;
            }
            if (digitRatio > 0.3) {
                score += 0.3;
            }

            if (score >= cfg.dgaThreshold) {
                return {score, "Generic"};
            }

            return {score, ""};

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"GetDGAScoreInternal - Exception: %hs", e.what());
            return {0.0, ""};
        }
    }

    [[nodiscard]] std::pair<double, std::string> GetDGAScore(const std::string& domain) {
        URLAnalyzerConfig configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }
        return GetDGAScoreInternal(domain, configSnapshot);
    }

    [[nodiscard]] std::vector<std::tuple<std::string, double, std::string>> DetectDGAs(
        const std::vector<std::string>& domains) {

        URLAnalyzerConfig configSnapshot;
        {
            std::shared_lock lock(m_mutex);
            configSnapshot = m_config;
        }

        std::vector<std::tuple<std::string, double, std::string>> results;

        for (const auto& domain : domains) {
            auto [score, family] = GetDGAScoreInternal(domain, configSnapshot);
            if (score >= configSnapshot.dgaThreshold) {
                results.emplace_back(domain, score, family);
            }
        }

        return results;
    }

    // ========================================================================
    // PHISHING DETECTION
    // ========================================================================

    [[nodiscard]] std::optional<BrandMatch> DetectPhishing(
        const std::string& url, const URLAnalyzerConfig& cfg) {
        try {
            ParsedURL parsed = ParseURL(url);
            if (!parsed.isValid) return std::nullopt;

            std::string lowerDomain = NarrowToLower(parsed.hostNormalized);

            for (const auto& brand : PROTECTED_BRANDS) {
                if (lowerDomain.find(brand) != std::string::npos) {
                    // Found brand keyword -- check if it's the legitimate domain
                    BrandMatch match;
                    match.brandName = brand;
                    match.matchedTerm = brand;
                    match.inDomain = true;

                    // Compute actual similarity against known-good domain
                    std::string expectedDomain = brand + ".com";
                    match.similarityScore = CalculateSimilarity(lowerDomain, expectedDomain);

                    // Flag if not exact match to legitimate domain
                    if (lowerDomain != expectedDomain &&
                        lowerDomain != "www." + expectedDomain) {

                        // Also check in subdomain or path for combosquatting
                        if (!parsed.subdomain.empty() &&
                            parsed.subdomain.find(brand) != std::string::npos) {
                            match.inSubdomain = true;
                        }

                        return match;
                    }
                }
            }

            // Also check configured protected brands (with known-good domains)
            {
                // cfg is a snapshot, no lock needed
                for (const auto& [brandName, legitimateDomain] : cfg.protectedBrands) {
                    double sim = CalculateSimilarity(lowerDomain, NarrowToLower(legitimateDomain));
                    if (sim >= cfg.phishingThreshold && lowerDomain != NarrowToLower(legitimateDomain)) {
                        BrandMatch match;
                        match.brandName = brandName;
                        match.legitimateDomain = legitimateDomain;
                        match.similarityScore = sim;
                        match.matchedTerm = brandName;
                        match.inDomain = true;
                        return match;
                    }
                }
            }

            return std::nullopt;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DetectPhishing - Exception: %hs", e.what());
            return std::nullopt;
        }
    }

    [[nodiscard]] HomographAnalysis CheckHomograph(const std::string& domain) {
        HomographAnalysis analysis;
        analysis.originalDomain = domain;

        try {
            // Check for punycode (xn--)
            if (domain.find("xn--") != std::string::npos) {
                analysis.containsHomographs = true;
                analysis.punycodeDecoded = domain;

                // Decode punycode to detect visual spoofing
                std::wstring decoded = StringUtils::ToWide(domain);
                analysis.asciiEquivalent = StringUtils::ToNarrow(decoded);

                // Score based on mixed-script and confusable patterns
                analysis.deceptionScore = 0.8;

                // Check if decoded domain targets a known brand
                std::string lowerDecoded = NarrowToLower(analysis.asciiEquivalent);
                for (const auto& brand : PROTECTED_BRANDS) {
                    double sim = CalculateSimilarity(lowerDecoded, brand + ".com");
                    if (sim >= URLAnalyzerConstants::PHISHING_SIMILARITY_THRESHOLD) {
                        analysis.targetedBrand = brand;
                        analysis.deceptionScore = std::max(analysis.deceptionScore, sim);
                        break;
                    }
                }
            }

            // Check for Unicode characters that look like ASCII (mixed script)
            // Common homoglyph codepoints in URL domain names
            for (unsigned char c : domain) {
                if (c > 127) {
                    // Non-ASCII byte in a domain name is suspicious
                    analysis.containsHomographs = true;
                    analysis.deceptionScore = std::max(analysis.deceptionScore, 0.7);
                    break;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CheckHomograph - Exception: %hs", e.what());
        }

        return analysis;
    }

    [[nodiscard]] double CheckTyposquatting(const std::string& domain, const std::string& targetDomain) {
        try {
            return CalculateSimilarity(domain, targetDomain);
        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CheckTyposquatting - Exception: %hs", e.what());
            return 0.0;
        }
    }

    // ========================================================================
    // URL PARSING (STATIC METHODS)
    // ========================================================================

    [[nodiscard]] static ParsedURL ParseURL(const std::string& url) {
        ParsedURL parsed;
        parsed.originalUrl = url;

        try {
            if (url.empty()) {
                return parsed;
            }

            // Hard length cap to bound parser cost on attacker input.
            if (url.size() > URLAnalyzerConstants::MAX_URL_LENGTH) {
                parsed.isValid = false;
                return parsed;
            }

            // Reject embedded null bytes early
            if (ContainsNullByte(std::string_view(url.data(), url.size()))) {
                parsed.isValid = false;
                return parsed;
            }

            // Reject control characters (CR/LF/TAB/etc.) anywhere in URL.
            // RFC 3986 forbids these and they are common log/HTTP smuggling
            // vectors.  We tolerate a single trailing newline that crept in
            // from line-oriented input formats by trimming below.
            if (ContainsControlOrSpace(url)) {
                parsed.isValid = false;
                return parsed;
            }

            std::string remaining = url;

            // Detect dangerous URI schemes that don't use ://
            {
                std::string lowerUrl = NarrowToLower(url);
                // Strip leading whitespace that could bypass scheme detection
                size_t start = lowerUrl.find_first_not_of(" \t\r\n");
                if (start != std::string::npos) {
                    lowerUrl = lowerUrl.substr(start);
                }

                if (lowerUrl.starts_with("javascript:")) {
                    parsed.scheme = URLScheme::JAVASCRIPT;
                    parsed.schemeString = "javascript";
                    parsed.hasJavaScript = true;
                    parsed.isValid = true;
                    parsed.host = "";
                    parsed.path = url.substr(url.find(':') + 1);
                    return parsed;
                }
                if (lowerUrl.starts_with("data:")) {
                    parsed.scheme = URLScheme::DATA;
                    parsed.schemeString = "data";
                    parsed.hasDataUri = true;
                    parsed.isValid = true;
                    parsed.host = "";
                    parsed.path = url.substr(url.find(':') + 1);
                    return parsed;
                }
                if (lowerUrl.starts_with("mailto:")) {
                    parsed.scheme = URLScheme::MAILTO;
                    parsed.schemeString = "mailto";
                    parsed.isValid = true;
                    parsed.host = "";
                    parsed.path = url.substr(url.find(':') + 1);
                    return parsed;
                }
            }

            // Extract scheme
            size_t schemeEnd = remaining.find("://");
            if (schemeEnd != std::string::npos) {
                parsed.schemeString = remaining.substr(0, schemeEnd);
                remaining = remaining.substr(schemeEnd + 3);

                std::string schemeLower = NarrowToLower(parsed.schemeString);
                if (schemeLower == "http") { parsed.scheme = URLScheme::HTTP; parsed.defaultPort = 80; }
                else if (schemeLower == "https") { parsed.scheme = URLScheme::HTTPS; parsed.defaultPort = 443; }
                else if (schemeLower == "ftp") { parsed.scheme = URLScheme::FTP; parsed.defaultPort = 21; }
                else if (schemeLower == "ftps") { parsed.scheme = URLScheme::FTPS; parsed.defaultPort = 990; }
                else if (schemeLower == "sftp") { parsed.scheme = URLScheme::SFTP; parsed.defaultPort = 22; }
                else if (schemeLower == "file") { parsed.scheme = URLScheme::FILE; }
                else if (schemeLower == "mailto") { parsed.scheme = URLScheme::MAILTO; }
                else parsed.scheme = URLScheme::CUSTOM;
            } else {
                parsed.scheme = URLScheme::HTTP;
                parsed.schemeString = "http";
                parsed.defaultPort = 80;
            }

            // Extract credentials (user:pass@)
            size_t atPos = remaining.find('@');
            size_t authorityTerminatorPos = remaining.find_first_of("/?#");
            if (atPos != std::string::npos &&
                (authorityTerminatorPos == std::string::npos || atPos < authorityTerminatorPos)) {
                std::string creds = remaining.substr(0, atPos);
                remaining = remaining.substr(atPos + 1);
                parsed.hasCredentials = true;

                size_t colonPos = creds.find(':');
                if (colonPos != std::string::npos) {
                    parsed.username = creds.substr(0, colonPos);
                    parsed.password = creds.substr(colonPos + 1);
                } else {
                    parsed.username = creds;
                }
            }

            // Extract authority, path, query, and fragment. Host-only URLs may
            // legally start the query/fragment directly without a '/'.
            const size_t slashPos = remaining.find('/');
            const size_t queryPos = remaining.find('?');
            const size_t fragmentPos = remaining.find('#');

            size_t authorityEnd = remaining.size();
            if (slashPos != std::string::npos) {
                authorityEnd = std::min(authorityEnd, slashPos);
            }
            if (queryPos != std::string::npos) {
                authorityEnd = std::min(authorityEnd, queryPos);
            }
            if (fragmentPos != std::string::npos) {
                authorityEnd = std::min(authorityEnd, fragmentPos);
            }

            const bool hasAuthoritySuffix = authorityEnd < remaining.size();
            std::string hostPort = hasAuthoritySuffix ?
                remaining.substr(0, authorityEnd) : remaining;

            if (!hostPort.empty() && hostPort.front() == '[') {
                // IPv6 bracket notation: [::1]:port (zone-id [::1%eth0]
                // is rejected; we strip anything after '%' which is not a
                // valid identifier in a URL host).
                size_t bracketEnd = hostPort.find(']');
                if (bracketEnd != std::string::npos) {
                    parsed.host = hostPort.substr(1, bracketEnd - 1);
                    // Reject zone identifiers in URL hosts (RFC 6874 requires
                    // them to be percent-encoded; raw '%' here is invalid).
                    if (parsed.host.find('%') != std::string::npos) {
                        parsed.isValid = false;
                        return parsed;
                    }
                    parsed.isIPv6 = true;
                    parsed.isIP = true;
                    if (bracketEnd + 1 < hostPort.size() && hostPort[bracketEnd + 1] == ':') {
                        auto portOpt = ParseStrictPort(
                            std::string_view(hostPort).substr(bracketEnd + 2));
                        if (!portOpt.has_value()) {
                            parsed.isValid = false;
                            return parsed;
                        }
                        parsed.port = *portOpt;
                        parsed.hasPort = true;
                    } else {
                        parsed.port = parsed.defaultPort;
                    }
                } else {
                    parsed.host = hostPort;
                    parsed.port = parsed.defaultPort;
                }
            } else {
                size_t colonPos = hostPort.find(':');
                if (colonPos != std::string::npos) {
                    parsed.host = hostPort.substr(0, colonPos);
                    auto portOpt = ParseStrictPort(
                        std::string_view(hostPort).substr(colonPos + 1));
                    if (!portOpt.has_value()) {
                        parsed.isValid = false;
                        return parsed;
                    }
                    parsed.port = *portOpt;
                    parsed.hasPort = true;
                } else {
                    parsed.host = hostPort;
                    parsed.port = parsed.defaultPort;
                }
            }

            // Cap host length per RFC
            if (parsed.host.length() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH) {
                parsed.isValid = false;
                return parsed;
            }

            // Validate host character set. For non-IPv6 hosts only allow
            // letters, digits, '-', '.', '_' (the last is technically out of
            // RFC but is common in real-world DNS) and high-bit bytes from
            // raw IDN input -- the IDN/punycode pass below converts those.
            // Reject embedded slashes, backslashes, '@' (a second userinfo
            // separator that can be used for authority confusion attacks)
            // and any other delimiter that would re-enter the URL grammar.
            if (!parsed.isIPv6) {
                for (unsigned char c : parsed.host) {
                    if (c == '/' || c == '\\' || c == '?' || c == '#' ||
                        c == '@' || c == '[' || c == ']' || c == ':') {
                        parsed.isValid = false;
                        return parsed;
                    }
                    if (c < 0x20 || c == 0x7F) {
                        parsed.isValid = false;
                        return parsed;
                    }
                }
            }

            parsed.hostNormalized = NarrowToLower(parsed.host);

            // Detect IP-based hosts
            if (!parsed.isIPv6) {
                parsed.isIP = IsIPv4Address(parsed.hostNormalized);
            }
            parsed.isLocalhost = IsLocalhostAddress(parsed.hostNormalized);
            parsed.isPrivateIP = IsPrivateIPv4(parsed.hostNormalized);

            // Extract path, query, fragment
            if (hasAuthoritySuffix) {
                remaining = remaining.substr(authorityEnd);

                size_t queryStart = remaining.find('?');
                size_t fragmentStart = remaining.find('#');

                if (!remaining.empty() && remaining.front() == '?') {
                    parsed.path = "/";
                } else if (!remaining.empty() && remaining.front() == '#') {
                    parsed.path = "/";
                } else if (queryStart != std::string::npos) {
                    parsed.path = remaining.substr(0, queryStart);

                    size_t queryEnd = (fragmentStart != std::string::npos) ? fragmentStart : remaining.length();
                    parsed.query = remaining.substr(queryStart + 1, queryEnd - queryStart - 1);
                } else if (fragmentStart != std::string::npos) {
                    parsed.path = remaining.substr(0, fragmentStart);
                } else {
                    parsed.path = remaining;
                }

                if (queryStart != std::string::npos) {
                    size_t queryEnd = (fragmentStart != std::string::npos) ? fragmentStart : remaining.length();
                    parsed.query = remaining.substr(queryStart + 1, queryEnd - queryStart - 1);
                }

                if (fragmentStart != std::string::npos) {
                    parsed.fragment = remaining.substr(fragmentStart + 1);
                }

                if (parsed.path.empty()) {
                    parsed.path = "/";
                }
            } else {
                parsed.path = "/";
            }

            parsed.pathNormalized = parsed.path;

            // Extract domain parts
            std::string domain = parsed.hostNormalized;
            size_t lastDot = domain.find_last_of('.');
            if (lastDot != std::string::npos && lastDot < domain.length() - 1) {
                parsed.tld = domain.substr(lastDot + 1);
                parsed.effectiveTld = parsed.tld;

                size_t secondLastDot = (lastDot > 0) ?
                    domain.find_last_of('.', lastDot - 1) : std::string::npos;
                if (secondLastDot != std::string::npos) {
                    parsed.registeredDomain = domain.substr(secondLastDot + 1);
                    parsed.subdomain = domain.substr(0, secondLastDot);
                } else {
                    parsed.registeredDomain = domain;
                }
            }

            // Split into labels (cap to prevent pathological input)
            {
                std::stringstream ss(domain);
                std::string label;
                while (std::getline(ss, label, '.') &&
                       parsed.labels.size() < URLAnalyzerConstants::MAX_LABELS) {
                    if (!label.empty()) {
                        parsed.labels.push_back(label);
                    }
                }
            }

            // Check security flags
            parsed.isPunycode = (domain.find("xn--") != std::string::npos);
            parsed.isValid = !parsed.host.empty();
            parsed.hasEncodedChars = (url.find('%') != std::string::npos);
            parsed.hasDoubleEncoding = HasDoublePercentEncoding(url);
            parsed.hasSuspiciousChars = ContainsSuspiciousChars(url);
            parsed.hasLongPath = (parsed.path.length() > URLAnalyzerConstants::MAX_PATH_LENGTH);
            parsed.hasExcessiveSubdomains = (parsed.labels.size() > 5);

            parsed.normalizedUrl = parsed.schemeString + "://";
            if (parsed.isIPv6) {
                parsed.normalizedUrl += "[";
                parsed.normalizedUrl += parsed.hostNormalized;
                parsed.normalizedUrl += "]";
            } else {
                parsed.normalizedUrl += parsed.hostNormalized;
            }
            // Collapse default ports so that "http://x" and "http://x:80"
            // hash to the same cache key (cache-poisoning hardening).
            if (parsed.hasPort && parsed.port != parsed.defaultPort) {
                parsed.normalizedUrl += ":";
                parsed.normalizedUrl += std::to_string(static_cast<unsigned>(parsed.port));
            }
            parsed.normalizedUrl += parsed.path;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ParseURL - Exception: %hs", e.what());
            parsed.isValid = false;
        }

        return parsed;
    }

    [[nodiscard]] static std::string NormalizeURL(const std::string& url) {
        ParsedURL parsed = ParseURL(url);
        return parsed.normalizedUrl;
    }

    [[nodiscard]] static std::string ExtractDomain(const std::string& url) {
        ParsedURL parsed = ParseURL(url);
        return parsed.hostNormalized;
    }

    [[nodiscard]] static std::wstring DecodePunycode(const std::string& domain) {
        return StringUtils::ToWide(domain);
    }

    // ========================================================================
    // FEATURE EXTRACTION
    // ========================================================================

    [[nodiscard]] URLFeatures ExtractFeaturesInternal(const ParsedURL& parsed) const {
        URLFeatures features;

        try {
            // Length features
            features.urlLength = parsed.originalUrl.length();
            features.domainLength = parsed.host.length();
            features.pathLength = parsed.path.length();
            features.queryLength = parsed.query.length();
            features.subdomainLength = parsed.subdomain.length();

            // Count features
            features.dotCount = std::count(parsed.host.begin(), parsed.host.end(), '.');
            features.slashCount = std::count(parsed.path.begin(), parsed.path.end(), '/');
            features.labelCount = parsed.labels.size();

            size_t letterCount = 0;
            size_t vowelCount = 0;
            size_t consonantCount = 0;

            // Count characters in domain (not full URL) for domain-specific ratios
            for (char c : parsed.host) {
                if (std::isdigit(static_cast<unsigned char>(c))) features.digitCount++;
                if (std::isalpha(static_cast<unsigned char>(c))) letterCount++;
                if (VOWELS.find(c) != std::string::npos) vowelCount++;
                if (CONSONANTS.find(c) != std::string::npos) consonantCount++;
                if (c == '-') features.hyphenCount++;
                if (c == '_') features.underscoreCount++;
            }

            // Count URL-wide special chars and @ symbols
            for (char c : parsed.originalUrl) {
                if (!std::isalnum(static_cast<unsigned char>(c))) features.specialCharCount++;
                if (c == '@') features.atSymbolCount++;
            }

            // Count query parameters
            if (!parsed.query.empty()) {
                features.queryParamCount = 1;
                for (char c : parsed.query) {
                    if (c == '&') features.queryParamCount++;
                }
            }

            // Ratio features (domain-specific)
            if (features.domainLength > 0) {
                features.digitRatio = static_cast<double>(features.digitCount) / features.domainLength;
                features.letterRatio = static_cast<double>(letterCount) / features.domainLength;
                features.consonantRatio = static_cast<double>(consonantCount) / features.domainLength;
                features.vowelRatio = static_cast<double>(vowelCount) / features.domainLength;
            }
            if (features.urlLength > 0) {
                features.specialRatio = static_cast<double>(features.specialCharCount) / features.urlLength;
            }

            // Entropy features
            features.domainEntropy = CalculateEntropyInternal(parsed.host);
            features.pathEntropy = CalculateEntropyInternal(parsed.path);
            if (!parsed.query.empty()) {
                features.queryEntropy = CalculateEntropyInternal(parsed.query);
            }
            if (!parsed.subdomain.empty()) {
                features.subdomainEntropy = CalculateEntropyInternal(parsed.subdomain);
            }

            // N-gram features (bigram frequency for domain)
            if (parsed.host.length() >= 2) {
                size_t uncommon = 0;
                // Common English bigrams for reference
                static const std::unordered_set<std::string> commonBigrams = {
                    "th","he","in","er","an","re","on","at","en","nd","ti","es","or","te","of",
                    "ed","is","it","al","ar","st","to","nt","ng","se","ha","as","ou","io","le",
                    "co","me","de","hi","ri","ro","ic","ne","ea","ra","ce","li","ch","ll","be"
                };
                size_t totalBigrams = parsed.host.length() - 1;
                size_t commonCount = 0;
                std::string lower = NarrowToLower(parsed.host);
                for (size_t i = 0; i + 1 < lower.size(); ++i) {
                    std::string bigram = lower.substr(i, 2);
                    if (commonBigrams.count(bigram)) {
                        commonCount++;
                    } else {
                        uncommon++;
                    }
                }
                if (totalBigrams > 0) {
                    features.bigramFrequency = static_cast<double>(commonCount) / totalBigrams;
                }
                features.uncommonBigrams = static_cast<uint32_t>(uncommon);
            }

            // Boolean features
            features.hasIP = parsed.isIP;
            features.hasPort = parsed.hasPort;
            features.hasCredentials = parsed.hasCredentials;
            features.hasSuspiciousTLD = IsSuspiciousTLD(parsed.tld);
            features.hasKnownBrand = ContainsBrandKeyword(parsed.host);
            features.isPunycode = parsed.isPunycode;
            features.hasExecutableExtension = HasExecutableExtension(parsed.path);

            // Check for double extension (e.g., document.pdf.exe)
            size_t lastDot = parsed.path.find_last_of('.');
            if (lastDot != std::string::npos && lastDot > 0) {
                std::string beforeLast = parsed.path.substr(0, lastDot);
                if (beforeLast.find_last_of('.') != std::string::npos) {
                    features.hasDoubleExtension = true;
                }
            }

            // Derived scores
            features.dgaScore = (features.domainEntropy >= URLAnalyzerConstants::DGA_ENTROPY_THRESHOLD &&
                                 features.consonantRatio >= URLAnalyzerConstants::DGA_CONSONANT_RATIO) ? 0.7 : 0.0;
            features.phishingScore = features.hasKnownBrand ? 0.5 : 0.0;
            features.malwareScore = features.hasExecutableExtension ? 0.5 : 0.0;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ExtractFeaturesInternal - Exception: %hs", e.what());
        }

        return features;
    }

    [[nodiscard]] URLFeatures ExtractFeatures(const std::string& url) const {
        ParsedURL parsed = ParseURL(url);
        return ExtractFeaturesInternal(parsed);
    }

    [[nodiscard]] URLFeatures ExtractFeatures(const ParsedURL& parsed) const {
        return ExtractFeaturesInternal(parsed);
    }

    // ========================================================================
    // WHITELIST/BLACKLIST
    // ========================================================================

    bool AddToWhitelist(const std::string& domain, bool includeSubdomains) {
        // Validate before taking the lock so we don't poison the set.
        if (domain.empty() ||
            domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
            ContainsNullByte(domain) ||
            ContainsControlOrSpace(domain)) {
            SS_LOG_WARN(L"Network", L"AddToWhitelist - rejected malformed domain (len=%zu)",
                domain.size());
            return false;
        }
        std::unique_lock lock(m_mutex);

        try {
            std::string normalized = NarrowToLower(domain);
            m_whitelist.insert(normalized);

            SS_LOG_INFO(L"Network", L"Added to URL whitelist: %hs (subdomains=%d)",
                SanitizeForLog(normalized).c_str(), static_cast<int>(includeSubdomains));
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AddToWhitelist - Exception: %hs", e.what());
            return false;
        }
    }

    bool RemoveFromWhitelist(const std::string& domain) {
        if (domain.empty() ||
            domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
            ContainsNullByte(domain) ||
            ContainsControlOrSpace(domain)) {
            return false;
        }
        std::unique_lock lock(m_mutex);

        try {
            std::string normalized = NarrowToLower(domain);
            bool removed = m_whitelist.erase(normalized) > 0;

            if (removed) {
                SS_LOG_INFO(L"Network", L"Removed from URL whitelist: %hs",
                    SanitizeForLog(normalized).c_str());
            }

            return removed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"RemoveFromWhitelist - Exception: %hs", e.what());
            return false;
        }
    }

    bool AddToBlacklist(const std::string& domain, std::string_view threatName) {
        if (domain.empty() ||
            domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
            ContainsNullByte(domain) ||
            ContainsControlOrSpace(domain)) {
            SS_LOG_WARN(L"Network", L"AddToBlacklist - rejected malformed domain (len=%zu)",
                domain.size());
            return false;
        }
        std::unique_lock lock(m_mutex);

        try {
            std::string normalized = NarrowToLower(domain);
            m_blacklist[normalized] = std::string(threatName);

            SS_LOG_WARN(L"Network", L"Added to URL blacklist: %hs (threat: %hs)",
                SanitizeForLog(normalized).c_str(),
                SanitizeForLog(std::string(threatName)).c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AddToBlacklist - Exception: %hs", e.what());
            return false;
        }
    }

    bool RemoveFromBlacklist(const std::string& domain) {
        if (domain.empty() ||
            domain.size() > URLAnalyzerConstants::MAX_DOMAIN_LENGTH ||
            ContainsNullByte(domain) ||
            ContainsControlOrSpace(domain)) {
            return false;
        }
        std::unique_lock lock(m_mutex);

        try {
            std::string normalized = NarrowToLower(domain);
            bool removed = m_blacklist.erase(normalized) > 0;

            if (removed) {
                SS_LOG_INFO(L"Network", L"Removed from URL blacklist: %hs",
                    SanitizeForLog(normalized).c_str());
            }

            return removed;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"RemoveFromBlacklist - Exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool IsWhitelistedInternal(const std::string& domain) const {
        return m_whitelist.find(domain) != m_whitelist.end();
    }

    // Whitelist match that walks up the label chain to honour the
    // `whitelistSubdomains` policy.  When enabled, "a.b.example.com" matches
    // a whitelist entry of "example.com".  The walk is bounded by
    // MAX_LABELS to keep cost deterministic on attacker-controlled input.
    [[nodiscard]] bool IsWhitelistedHostOrParent(const std::string& domain,
                                                 bool includeSubdomains) const {
        if (m_whitelist.empty()) return false;
        if (m_whitelist.find(domain) != m_whitelist.end()) return true;
        if (!includeSubdomains) return false;

        std::string_view cursor(domain);
        size_t hops = 0;
        while (hops < URLAnalyzerConstants::MAX_LABELS) {
            const size_t dot = cursor.find('.');
            if (dot == std::string_view::npos) break;
            cursor.remove_prefix(dot + 1);
            if (cursor.empty()) break;
            if (m_whitelist.find(std::string(cursor)) != m_whitelist.end()) {
                return true;
            }
            ++hops;
        }
        return false;
    }

    [[nodiscard]] bool IsWhitelisted(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        std::string normalized = NarrowToLower(domain);
        return IsWhitelistedHostOrParent(normalized, m_config.whitelistSubdomains);
    }

    [[nodiscard]] bool IsBlacklistedInternal(const std::string& domain) const {
        return m_blacklist.find(domain) != m_blacklist.end();
    }

    [[nodiscard]] bool IsBlacklisted(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        std::string normalized = NarrowToLower(domain);
        return IsBlacklistedInternal(normalized);
    }

    [[nodiscard]] std::string GetBlacklistThreat(const std::string& domain) const {
        auto it = m_blacklist.find(domain);
        return (it != m_blacklist.end()) ? it->second : "Blacklisted";
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    [[nodiscard]] std::optional<URLVerdict> GetFromCache(const std::string& url) const {
        std::shared_lock lock(m_mutex);

        auto it = m_cache.find(url);
        if (it != m_cache.end()) {
            if (!it->second.IsExpired()) {
                // hitCount is atomic, safe to increment under shared_lock
                it->second.hitCount.fetch_add(1, std::memory_order_relaxed);
                return it->second.verdict;
            }
        }

        return std::nullopt;
    }

    // Cache under exclusive lock (caller must NOT hold the lock)
    void CacheVerdict(const std::string& url, const URLVerdict& verdict) {
        std::unique_lock lock(m_mutex);
        CacheVerdictInternal(url, verdict);
    }

    // Cache without acquiring lock (caller must already hold an EXCLUSIVE lock)
    void CacheVerdictInternal(const std::string& url, const URLVerdict& verdict) {
        try {
            if (m_cache.size() >= m_config.maxCacheSize) {
                EvictExpiredAndOldestBatch();
            }

            CacheEntry entry;
            entry.verdict = verdict;
            entry.insertTime = std::chrono::system_clock::now();

            // Malicious verdicts get longer TTL
            uint32_t ttl = m_config.cacheTTLMs;
            if (verdict.isBlocked) {
                ttl = std::max(ttl, URLAnalyzerConstants::CACHE_TTL_MALICIOUS_MS);
            }
            entry.expiryTime = entry.insertTime + std::chrono::milliseconds(ttl);

            m_cache[url] = std::move(entry);
            m_stats.cacheSize.store(static_cast<uint32_t>(m_cache.size()),
                std::memory_order_relaxed);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"CacheVerdict - Exception: %hs", e.what());
        }
    }

    // Batch eviction: remove all expired entries first, then oldest entries if still over limit
    void EvictExpiredAndOldestBatch() {
        auto now = std::chrono::system_clock::now();

        // Phase 1: Remove all expired entries
        for (auto it = m_cache.begin(); it != m_cache.end(); ) {
            if (it->second.expiryTime <= now) {
                it = m_cache.erase(it);
            } else {
                ++it;
            }
        }

        // Phase 2: If still over 90% capacity, evict oldest 10%
        if (m_cache.size() >= (m_config.maxCacheSize * 9 / 10)) {
            size_t toEvict = m_config.maxCacheSize / 10;
            if (toEvict == 0) toEvict = 1;

            // Collect oldest entries by insertion time
            std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> candidates;
            candidates.reserve(m_cache.size());
            for (const auto& [key, entry] : m_cache) {
                candidates.emplace_back(entry.insertTime, key);
            }
            std::partial_sort(candidates.begin(),
                candidates.begin() + std::min(toEvict, candidates.size()),
                candidates.end());

            for (size_t i = 0; i < std::min(toEvict, candidates.size()); ++i) {
                m_cache.erase(candidates[i].second);
            }
        }
    }

    [[nodiscard]] std::optional<URLVerdict> QueryCache(const std::string& url) const {
        // Re-derive the same normalised cache key that ScanURL uses; raw
        // URLs are never written to the cache so a raw lookup would always
        // miss (and previously could be poisoned by mismatched keys).
        ParsedURL parsed = ParseURL(url);
        const std::string& key =
            (parsed.isValid && !parsed.normalizedUrl.empty()) ? parsed.normalizedUrl : url;
        return GetFromCache(key);
    }

    void InvalidateCache(const std::string& url) {
        ParsedURL parsed = ParseURL(url);
        const std::string& key =
            (parsed.isValid && !parsed.normalizedUrl.empty()) ? parsed.normalizedUrl : url;
        std::unique_lock lock(m_mutex);
        if (m_cache.erase(key) > 0) {
            // Keep the published statistic in step with the underlying map.
            // Without this, repeated invalidations make cacheSize drift away
            // from m_cache.size() which other components rely on.
            const size_t newSize = m_cache.size();
            m_stats.cacheSize.store(static_cast<uint32_t>(newSize),
                std::memory_order_relaxed);
        }
    }

    void ClearCache() {
        std::unique_lock lock(m_mutex);
        m_cache.clear();
        m_stats.cacheSize.store(0, std::memory_order_relaxed);
        SS_LOG_INFO(L"Network", L"URL analyzer cache cleared");
    }

    [[nodiscard]] size_t GetCacheSize() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_cache.size();
    }

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAnalysisCallback(URLAnalysisCallback callback) {
        if (!callback) return 0;
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_analysisCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterThreatCallback(URLThreatCallback callback) {
        if (!callback) return 0;
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_threatCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterPhishingCallback(PhishingCallback callback) {
        if (!callback) return 0;
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_phishingCallbacks[id] = std::move(callback);
        return id;
    }

    [[nodiscard]] uint64_t RegisterDGACallback(DGACallback callback) {
        if (!callback) return 0;
        std::unique_lock lock(m_mutex);
        uint64_t id = ++m_nextCallbackId;
        m_dgaCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterCallback(uint64_t callbackId) {
        std::unique_lock lock(m_mutex);

        bool removed = false;
        removed |= (m_analysisCallbacks.erase(callbackId) > 0);
        removed |= (m_threatCallbacks.erase(callbackId) > 0);
        removed |= (m_phishingCallbacks.erase(callbackId) > 0);
        removed |= (m_dgaCallbacks.erase(callbackId) > 0);

        return removed;
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const URLAnalyzerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const {
        std::shared_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"Network", L"=== URLAnalyzer Diagnostics ===");
            SS_LOG_INFO(L"Network", L"Initialized: %d", static_cast<int>(m_initialized));
            SS_LOG_INFO(L"Network", L"Cache size: %zu", m_cache.size());
            SS_LOG_INFO(L"Network", L"Whitelist size: %zu", m_whitelist.size());
            SS_LOG_INFO(L"Network", L"Blacklist size: %zu", m_blacklist.size());
            SS_LOG_INFO(L"Network", L"Total URLs analyzed: %llu", m_stats.totalURLsAnalyzed.load());
            SS_LOG_INFO(L"Network", L"URLs blocked: %llu", m_stats.urlsBlocked.load());
            SS_LOG_INFO(L"Network", L"Phishing detected: %llu", m_stats.phishingDetected.load());
            SS_LOG_INFO(L"Network", L"DGA detected: %llu", m_stats.dgaDetected.load());

            uint64_t total = m_stats.totalURLsAnalyzed.load();
            uint64_t hits = m_stats.cacheHits.load();
            double hitRate = (total > 0) ? (static_cast<double>(hits) * 100.0 / total) : 0.0;
            SS_LOG_INFO(L"Network", L"Cache hit rate: %.2f%%", hitRate);

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"PerformDiagnostics - Exception: %hs", e.what());
            return false;
        }
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        std::shared_lock lock(m_mutex);

        try {
            std::string narrowPath = StringUtils::ToNarrow(outputPath);

            // Build diagnostics report as JSON
            std::ostringstream json;
            json << "{\n";
            json << "  \"module\": \"URLAnalyzer\",\n";
            json << "  \"version\": \"" << URLAnalyzerConstants::VERSION_MAJOR << "."
                 << URLAnalyzerConstants::VERSION_MINOR << "."
                 << URLAnalyzerConstants::VERSION_PATCH << "\",\n";
            json << "  \"initialized\": " << (m_initialized ? "true" : "false") << ",\n";
            json << "  \"cacheSize\": " << m_cache.size() << ",\n";
            json << "  \"whitelistSize\": " << m_whitelist.size() << ",\n";
            json << "  \"blacklistSize\": " << m_blacklist.size() << ",\n";
            json << "  \"totalURLsAnalyzed\": " << m_stats.totalURLsAnalyzed.load() << ",\n";
            json << "  \"totalDomainsAnalyzed\": " << m_stats.totalDomainsAnalyzed.load() << ",\n";
            json << "  \"urlsBlocked\": " << m_stats.urlsBlocked.load() << ",\n";
            json << "  \"urlsWarned\": " << m_stats.urlsWarned.load() << ",\n";
            json << "  \"urlsAllowed\": " << m_stats.urlsAllowed.load() << ",\n";
            json << "  \"phishingDetected\": " << m_stats.phishingDetected.load() << ",\n";
            json << "  \"malwareDetected\": " << m_stats.malwareDetected.load() << ",\n";
            json << "  \"c2Detected\": " << m_stats.c2Detected.load() << ",\n";
            json << "  \"dgaDetected\": " << m_stats.dgaDetected.load() << ",\n";
            json << "  \"homographDetected\": " << m_stats.homographDetected.load() << ",\n";
            json << "  \"cacheHits\": " << m_stats.cacheHits.load() << ",\n";
            json << "  \"cacheMisses\": " << m_stats.cacheMisses.load() << ",\n";
            json << "  \"avgAnalysisTimeUs\": " << m_stats.avgAnalysisTimeUs.load() << ",\n";
            json << "  \"maxAnalysisTimeUs\": " << m_stats.maxAnalysisTimeUs.load() << ",\n";
            json << "  \"parseErrors\": " << m_stats.parseErrors.load() << ",\n";
            json << "  \"analysisErrors\": " << m_stats.analysisErrors.load() << "\n";
            json << "}\n";

            std::string content = json.str();

            // Write to file using Win32 API for reliable wide-path handling
            HANDLE hFile = ::CreateFileW(
                outputPath.c_str(),
                GENERIC_WRITE,
                0, nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Failed to create file: %ls",
                    outputPath.c_str());
                return false;
            }

            DWORD written = 0;
            BOOL ok = ::WriteFile(hFile, content.data(),
                static_cast<DWORD>(content.size()), &written, nullptr);
            ::CloseHandle(hFile);

            if (!ok || written != static_cast<DWORD>(content.size())) {
                SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Write failed for: %ls",
                    outputPath.c_str());
                return false;
            }

            SS_LOG_INFO(L"Network", L"Exported URL analyzer diagnostics to: %hs",
                narrowPath.c_str());
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"ExportDiagnostics - Exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] static double CalculateEntropyInternal(const std::string& str) {
        if (str.empty()) return 0.0;

        std::array<uint64_t, 256> frequency{};
        for (unsigned char c : str) {
            frequency[c]++;
        }

        double entropy = 0.0;
        double size = static_cast<double>(str.length());

        for (uint64_t count : frequency) {
            if (count > 0) {
                double probability = static_cast<double>(count) / size;
                entropy -= probability * std::log2(probability);
            }
        }

        return entropy;
    }

private:
    // ========================================================================
    // INTERNAL ANALYSIS METHODS
    // ========================================================================

    int AnalyzeReputation(const ParsedURL& parsed, URLVerdict& verdict) {
        int score = 0;

        try {
            // Grab the subsystem pointer under lock
            ShadowStrike::ThreatIntel::ThreatIntelLookup* threatIntelPtr = nullptr;
            {
                std::shared_lock lock(m_mutex);
                threatIntelPtr = m_threatIntelLookup;
            }

            if (!threatIntelPtr || !threatIntelPtr->IsInitialized()) {
                verdict.reputationScore = 50;  // Unknown
                verdict.reputationSource = "Unavailable";
                return 0;
            }

            // Lookup the full URL first
            auto urlResult = threatIntelPtr->LookupURL(parsed.normalizedUrl);
            if (urlResult.found) {
                verdict.reputationScore = static_cast<uint8_t>(
                    100 - std::min<uint8_t>(urlResult.threatScore, 100));
                verdict.reputationSource = "ThreatIntel-URL";

                if (!urlResult.mitreTechniques.empty()) {
                    verdict.mitreIds = urlResult.mitreTechniques;
                }

                if (urlResult.IsMalicious()) {
                    score += 60;
                    verdict.detectionMethod = DetectionMethod::REPUTATION;
                    if (!urlResult.description.empty()) {
                        verdict.threatName = urlResult.description;
                    }
                } else if (urlResult.IsSuspicious()) {
                    score += 30;
                }
                return score;
            }

            // Fallback: lookup domain
            auto domainResult = threatIntelPtr->LookupDomain(parsed.hostNormalized);
            if (domainResult.found) {
                verdict.reputationScore = static_cast<uint8_t>(
                    100 - std::min<uint8_t>(domainResult.threatScore, 100));
                verdict.reputationSource = "ThreatIntel-Domain";

                if (!domainResult.mitreTechniques.empty()) {
                    verdict.mitreIds = domainResult.mitreTechniques;
                }

                if (domainResult.IsMalicious()) {
                    score += 50;
                    verdict.detectionMethod = DetectionMethod::REPUTATION;
                    if (!domainResult.description.empty()) {
                        verdict.threatName = domainResult.description;
                    }
                } else if (domainResult.IsSuspicious()) {
                    score += 20;
                }
            } else {
                verdict.reputationScore = 50;
                verdict.reputationSource = "Unknown";
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeReputation - Exception: %hs", e.what());
            verdict.reputationScore = 50;
            verdict.reputationSource = "Error";
        }

        return score;
    }

    int AnalyzePatterns(const ParsedURL& parsed, URLVerdict& verdict) {
        int score = 0;

        try {
            // Grab the subsystem pointer under lock
            ShadowStrike::PatternStore::PatternStore* patternStorePtr = nullptr;
            {
                std::shared_lock lock(m_mutex);
                patternStorePtr = m_patternStore;
            }

            // Scan URL bytes against PatternStore signatures
            if (patternStorePtr && patternStorePtr->IsInitialized()) {
                const std::string& urlStr = parsed.normalizedUrl;
                std::span<const uint8_t> urlBytes(
                    reinterpret_cast<const uint8_t*>(urlStr.data()), urlStr.size());

                auto matches = patternStorePtr->Scan(urlBytes);
                if (!matches.empty()) {
                    // Take the highest-severity match
                    score += static_cast<int>(matches.size()) * 15;
                    score = std::min(score, 60);

                    verdict.detectionMethod = DetectionMethod::PATTERN_MATCH;
                    verdict.matchedPattern = matches.front().signatureName;

                    SS_LOG_DEBUG(L"Network", L"PatternStore matched %zu patterns on URL",
                        matches.size());
                }
            }

            // Additional inline pattern checks for known malware URLs
            const std::string& urlLower = NarrowToLower(parsed.normalizedUrl);

            // Encoded base64 payloads in query parameters
            if (!parsed.query.empty() && parsed.query.length() > 100) {
                // Long query strings with base64 charset are suspicious
                size_t b64Chars = 0;
                for (char c : parsed.query) {
                    if (std::isalnum(static_cast<unsigned char>(c)) ||
                        c == '+' || c == '/' || c == '=') {
                        b64Chars++;
                    }
                }
                double b64Ratio = static_cast<double>(b64Chars) / parsed.query.length();
                if (b64Ratio > 0.9 && parsed.query.length() > 200) {
                    score += 15;
                }
            }

            // Known exploit kit landing page patterns
            if (urlLower.find("/gate.php") != std::string::npos ||
                urlLower.find("/payload.") != std::string::npos ||
                urlLower.find("/download.php?id=") != std::string::npos ||
                urlLower.find("&cmd=") != std::string::npos ||
                urlLower.find("?exec=") != std::string::npos) {
                score += 20;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzePatterns - Exception: %hs", e.what());
        }

        return score;
    }

    int AnalyzeDGA(const ParsedURL& parsed, URLVerdict& verdict,
                   const URLAnalyzerConfig& cfg) {
        int score = 0;

        try {
            auto [dgaScore, family] = GetDGAScoreInternal(parsed.hostNormalized, cfg);

            if (dgaScore >= cfg.dgaThreshold) {
                score += 60;
                verdict.category = URLCategory::DGA;
                verdict.threatType = ThreatType::DGA_DOMAIN;
                verdict.detectionMethod = DetectionMethod::DGA_ANALYSIS;
                verdict.threatName = "DGA." + family;
                m_stats.dgaDetected++;

                NotifyDGA(parsed.hostNormalized, dgaScore, family);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeDGA - Exception: %hs", e.what());
        }

        return score;
    }

    int AnalyzePhishing(const ParsedURL& parsed, URLVerdict& verdict,
                        const URLAnalyzerConfig& cfg) {
        int score = 0;

        try {
            auto brandMatch = DetectPhishing(parsed.originalUrl, cfg);
            if (brandMatch.has_value()) {
                score += 70;
                verdict.category = URLCategory::PHISHING;
                verdict.threatType = ThreatType::PHISHING_GENERIC;
                verdict.detectionMethod = DetectionMethod::BRAND_DETECTION;
                verdict.brandMatch = brandMatch;
                verdict.threatName = "Phishing." + brandMatch->brandName;
                m_stats.phishingDetected++;

                NotifyPhishing(parsed.originalUrl, brandMatch.value(), verdict);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzePhishing - Exception: %hs", e.what());
        }

        return score;
    }

    int AnalyzeHomograph(const ParsedURL& parsed, URLVerdict& verdict) {
        int score = 0;

        try {
            if (parsed.isPunycode) {
                auto analysis = CheckHomograph(parsed.host);
                if (analysis.containsHomographs) {
                    score += 50;
                    verdict.category = URLCategory::TYPOSQUATTING;
                    verdict.threatType = ThreatType::HOMOGRAPH;
                    verdict.detectionMethod = DetectionMethod::HOMOGRAPH;
                    verdict.homographAnalysis = analysis;
                    m_stats.homographDetected++;
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeHomograph - Exception: %hs", e.what());
        }

        return score;
    }

    int AnalyzeHeuristics(const ParsedURL& parsed, URLVerdict& verdict) {
        int score = 0;

        try {
            // javascript: URI — always block
            if (parsed.hasJavaScript) {
                score += 80;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.threatType = ThreatType::DRIVE_BY_DOWNLOAD;
                verdict.threatName = "URL.JavaScriptScheme";
            }

            // data: URI — high risk for XSS / credential harvesting
            if (parsed.hasDataUri) {
                score += 60;
                verdict.category = URLCategory::SUSPICIOUS;
                verdict.threatName = "URL.DataURIScheme";
            }

            // Suspicious TLD
            if (IsSuspiciousTLD(parsed.tld)) {
                score += 10;
            }

            // Excessive subdomains (evasion technique)
            if (parsed.labels.size() > 5) {
                score += 15;
            }

            // IP address in URL (no DNS, common in phishing/C2)
            if (parsed.isIP) {
                score += 20;
                // Private IP is even more suspicious in external URL context
                if (parsed.isPrivateIP) {
                    score += 10;
                }
            }

            // Credentials in URL (credential harvesting indicator)
            if (parsed.hasCredentials) {
                score += 25;
            }

            // URL shortener (obfuscation)
            if (IsURLShortener(parsed.host)) {
                score += 5;
            }

            // Executable extension in path
            if (HasExecutableExtension(parsed.path)) {
                score += 30;
                verdict.threatType = ThreatType::MALWARE_DOWNLOAD;
            }

            // Long path (obfuscation / evasion)
            if (parsed.path.length() > 200) {
                score += 10;
            }

            // Double encoding (evasion attempt)
            if (parsed.hasDoubleEncoding) {
                score += 20;
            }

            // Suspicious characters (@, %, etc.) in unexpected positions
            if (parsed.hasSuspiciousChars) {
                score += 5;
            }

            // Non-standard port (often C2 or exfiltration)
            if (parsed.hasPort && parsed.port != parsed.defaultPort &&
                parsed.port != 80 && parsed.port != 443 && parsed.port != 8080) {
                score += 10;
            }

            // Punycode domain (potential homograph)
            if (parsed.isPunycode) {
                score += 15;
            }

            // Very long query string (possible encoded payload)
            if (parsed.query.length() > URLAnalyzerConstants::MAX_QUERY_LENGTH) {
                score += 10;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"AnalyzeHeuristics - Exception: %hs", e.what());
        }

        return score;
    }

    void NotifyAnalysis(const std::string& url, const URLVerdict& verdict) {
        // Snapshot callbacks under lock to avoid iterator invalidation
        std::vector<URLAnalysisCallback> snapshot;
        {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_analysisCallbacks.size());
            for (const auto& [id, cb] : m_analysisCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        // Invoke outside lock
        for (const auto& callback : snapshot) {
            try {
                callback(url, verdict);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NotifyAnalysis callback exception: %hs", e.what());
            }
        }
    }

    void NotifyThreat(const std::string& url, ThreatType threat, const URLVerdict& verdict) {
        std::vector<URLThreatCallback> snapshot;
        {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_threatCallbacks.size());
            for (const auto& [id, cb] : m_threatCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(url, threat, verdict);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NotifyThreat callback exception: %hs", e.what());
            }
        }
    }

    void NotifyPhishing(const std::string& url, const BrandMatch& brandMatch, const URLVerdict& verdict) {
        std::vector<PhishingCallback> snapshot;
        {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_phishingCallbacks.size());
            for (const auto& [id, cb] : m_phishingCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(url, brandMatch, verdict);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NotifyPhishing callback exception: %hs", e.what());
            }
        }
    }

    void NotifyDGA(const std::string& domain, double score, const std::string& family) {
        std::vector<DGACallback> snapshot;
        {
            std::shared_lock lock(m_mutex);
            snapshot.reserve(m_dgaCallbacks.size());
            for (const auto& [id, cb] : m_dgaCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        }
        for (const auto& callback : snapshot) {
            try {
                callback(domain, score, family);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"NotifyDGA callback exception: %hs", e.what());
            }
        }
    }

    void UpdatePerformanceStats(uint64_t latencyUs) noexcept {
        try {
            uint64_t queries = m_stats.totalURLsAnalyzed.load(std::memory_order_relaxed);
            if (queries == 0) return;  // Guard division by zero

            // Update running average using the incremental form
            //   newAvg = oldAvg + (latency - oldAvg) / queries
            // which avoids the overflow that the multiplicative form
            // (oldAvg * (queries-1) + latency) suffers once the analysed
            // count is large.  Implemented as a CAS loop so concurrent
            // writers cannot lose an update.
            uint64_t currentAvg = m_stats.avgAnalysisTimeUs.load(std::memory_order_relaxed);
            for (;;) {
                uint64_t newAvg;
                if (latencyUs >= currentAvg) {
                    newAvg = currentAvg + (latencyUs - currentAvg) / queries;
                } else {
                    newAvg = currentAvg - (currentAvg - latencyUs) / queries;
                }
                if (m_stats.avgAnalysisTimeUs.compare_exchange_weak(
                        currentAvg, newAvg, std::memory_order_relaxed)) {
                    break;
                }
            }

            // Update max (CAS loop to handle concurrent updates)
            uint64_t currentMax = m_stats.maxAnalysisTimeUs.load(std::memory_order_relaxed);
            while (latencyUs > currentMax) {
                if (m_stats.maxAnalysisTimeUs.compare_exchange_weak(
                        currentMax, latencyUs, std::memory_order_relaxed)) {
                    break;
                }
            }

        } catch (...) {
            // Suppress exceptions in stats path
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_shutdownRequested{ false };

    URLAnalyzerConfig m_config;
    URLAnalyzerStatistics m_stats;

    // External subsystem references (non-owning, set during init or wiring)
    ShadowStrike::ThreatIntel::ThreatIntelLookup* m_threatIntelLookup{ nullptr };
    ShadowStrike::PatternStore::PatternStore* m_patternStore{ nullptr };

    // Cache
    mutable std::unordered_map<std::string, CacheEntry> m_cache;

    // Whitelist/Blacklist
    std::unordered_set<std::string> m_whitelist;
    std::unordered_map<std::string, std::string> m_blacklist;  // domain -> threat

    // Callbacks
    std::unordered_map<uint64_t, URLAnalysisCallback> m_analysisCallbacks;
    std::unordered_map<uint64_t, URLThreatCallback> m_threatCallbacks;
    std::unordered_map<uint64_t, PhishingCallback> m_phishingCallbacks;
    std::unordered_map<uint64_t, DGACallback> m_dgaCallbacks;
    uint64_t m_nextCallbackId{ 0 };

    // Outstanding async work (futures held to prevent use-after-free)
    std::vector<std::future<void>> m_pendingFutures;
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

URLAnalyzer& URLAnalyzer::Instance() {
    static URLAnalyzer instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

URLAnalyzer::URLAnalyzer()
    : m_impl(std::make_unique<URLAnalyzerImpl>()) {
    SS_LOG_INFO(L"Network", L"URLAnalyzer instance created");
}

URLAnalyzer::~URLAnalyzer() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"Network", L"URLAnalyzer instance destroyed");
}

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

bool URLAnalyzer::Initialize() {
    auto config = URLAnalyzerConfig::CreateDefault();
    return m_impl->Initialize(config);
}

bool URLAnalyzer::Initialize(const URLAnalyzerConfig& config) {
    return m_impl->Initialize(config);
}

void URLAnalyzer::Shutdown() noexcept {
    m_impl->Shutdown();
}

void URLAnalyzer::SetThreatIntelLookup(
    ShadowStrike::ThreatIntel::ThreatIntelLookup* lookup) noexcept {
    m_impl->SetThreatIntelLookup(lookup);
}

void URLAnalyzer::SetPatternStore(
    ShadowStrike::PatternStore::PatternStore* store) noexcept {
    m_impl->SetPatternStore(store);
}

bool URLAnalyzer::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

URLAnalyzerConfig URLAnalyzer::GetConfig() const {
    return m_impl->GetConfig();
}

bool URLAnalyzer::UpdateConfig(const URLAnalyzerConfig& config) {
    return m_impl->UpdateConfig(config);
}

URLVerdict URLAnalyzer::ScanURL(const std::string& url) {
    return m_impl->ScanURL(url);
}

URLVerdict URLAnalyzer::ScanURL(const std::string& url, bool followRedirects, bool extractFeatures) {
    return m_impl->ScanURL(url, followRedirects, extractFeatures);
}

std::vector<URLVerdict> URLAnalyzer::ScanURLs(const std::vector<std::string>& urls) {
    return m_impl->ScanURLs(urls);
}

void URLAnalyzer::ScanURLAsync(const std::string& url, URLAnalysisCallback callback) {
    m_impl->ScanURLAsync(url, std::move(callback));
}

URLVerdict URLAnalyzer::ScanDomain(const std::string& domain) {
    return m_impl->ScanDomain(domain);
}

DomainVerdict URLAnalyzer::AnalyzeDomain(const std::string& domain) {
    return m_impl->AnalyzeDomain(domain);
}

std::unordered_map<std::string, DomainVerdict> URLAnalyzer::AnalyzeDomains(
    const std::vector<std::string>& domains) {
    return m_impl->AnalyzeDomains(domains);
}

bool URLAnalyzer::IsDGA(const std::string& domain) {
    return m_impl->IsDGA(domain);
}

std::pair<double, std::string> URLAnalyzer::GetDGAScore(const std::string& domain) {
    return m_impl->GetDGAScore(domain);
}

std::vector<std::tuple<std::string, double, std::string>> URLAnalyzer::DetectDGAs(
    const std::vector<std::string>& domains) {
    return m_impl->DetectDGAs(domains);
}

std::optional<BrandMatch> URLAnalyzer::DetectPhishing(const std::string& url) {
    URLAnalyzerConfig cfg = m_impl->GetConfig();
    return m_impl->DetectPhishing(url, cfg);
}

HomographAnalysis URLAnalyzer::CheckHomograph(const std::string& domain) {
    return m_impl->CheckHomograph(domain);
}

double URLAnalyzer::CheckTyposquatting(const std::string& domain, const std::string& targetDomain) {
    return m_impl->CheckTyposquatting(domain, targetDomain);
}

ParsedURL URLAnalyzer::ParseURL(const std::string& url) {
    return URLAnalyzerImpl::ParseURL(url);
}

std::string URLAnalyzer::NormalizeURL(const std::string& url) {
    return URLAnalyzerImpl::NormalizeURL(url);
}

std::string URLAnalyzer::ExtractDomain(const std::string& url) {
    return URLAnalyzerImpl::ExtractDomain(url);
}

std::wstring URLAnalyzer::DecodePunycode(const std::string& domain) {
    return URLAnalyzerImpl::DecodePunycode(domain);
}

URLFeatures URLAnalyzer::ExtractFeatures(const std::string& url) const {
    return m_impl->ExtractFeatures(url);
}

URLFeatures URLAnalyzer::ExtractFeatures(const ParsedURL& parsed) const {
    return m_impl->ExtractFeatures(parsed);
}

bool URLAnalyzer::AddToWhitelist(const std::string& domain, bool includeSubdomains) {
    return m_impl->AddToWhitelist(domain, includeSubdomains);
}

bool URLAnalyzer::RemoveFromWhitelist(const std::string& domain) {
    return m_impl->RemoveFromWhitelist(domain);
}

bool URLAnalyzer::AddToBlacklist(const std::string& domain, std::string_view threatName) {
    return m_impl->AddToBlacklist(domain, threatName);
}

bool URLAnalyzer::RemoveFromBlacklist(const std::string& domain) {
    return m_impl->RemoveFromBlacklist(domain);
}

bool URLAnalyzer::IsWhitelisted(const std::string& domain) const {
    return m_impl->IsWhitelisted(domain);
}

bool URLAnalyzer::IsBlacklisted(const std::string& domain) const {
    return m_impl->IsBlacklisted(domain);
}

std::optional<URLVerdict> URLAnalyzer::QueryCache(const std::string& url) const {
    return m_impl->QueryCache(url);
}

void URLAnalyzer::InvalidateCache(const std::string& url) {
    m_impl->InvalidateCache(url);
}

void URLAnalyzer::ClearCache() {
    m_impl->ClearCache();
}

size_t URLAnalyzer::GetCacheSize() const noexcept {
    return m_impl->GetCacheSize();
}

uint64_t URLAnalyzer::RegisterAnalysisCallback(URLAnalysisCallback callback) {
    return m_impl->RegisterAnalysisCallback(std::move(callback));
}

uint64_t URLAnalyzer::RegisterThreatCallback(URLThreatCallback callback) {
    return m_impl->RegisterThreatCallback(std::move(callback));
}

uint64_t URLAnalyzer::RegisterPhishingCallback(PhishingCallback callback) {
    return m_impl->RegisterPhishingCallback(std::move(callback));
}

uint64_t URLAnalyzer::RegisterDGACallback(DGACallback callback) {
    return m_impl->RegisterDGACallback(std::move(callback));
}

bool URLAnalyzer::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const URLAnalyzerStatistics& URLAnalyzer::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void URLAnalyzer::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool URLAnalyzer::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool URLAnalyzer::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

double URLAnalyzer::CalculateEntropy(std::string_view str) {
    return URLAnalyzerImpl::CalculateEntropyInternal(std::string(str));
}

std::string_view URLAnalyzer::GetCategoryName(URLCategory category) noexcept {
    switch (category) {
        case URLCategory::SAFE: return "Safe";
        case URLCategory::UNKNOWN: return "Unknown";
        case URLCategory::SUSPICIOUS: return "Suspicious";
        case URLCategory::PHISHING: return "Phishing";
        case URLCategory::MALWARE_DIST: return "Malware Distribution";
        case URLCategory::C2: return "Command & Control";
        case URLCategory::EXPLOIT_KIT: return "Exploit Kit";
        case URLCategory::CRYPTOMINING: return "Cryptomining";
        case URLCategory::RANSOMWARE: return "Ransomware";
        case URLCategory::BOTNET: return "Botnet";
        case URLCategory::SPAM: return "Spam";
        case URLCategory::SCAM: return "Scam";
        case URLCategory::TYPOSQUATTING: return "Typosquatting";
        case URLCategory::DGA: return "DGA";
        case URLCategory::ADULT: return "Adult Content";
        case URLCategory::GAMBLING: return "Gambling";
        case URLCategory::DRUGS: return "Drugs";
        case URLCategory::WEAPONS: return "Weapons";
        case URLCategory::VIOLENCE: return "Violence";
        case URLCategory::HATE_SPEECH: return "Hate Speech";
        default: return "Unknown";
    }
}

std::string_view URLAnalyzer::GetThreatTypeName(ThreatType threat) noexcept {
    switch (threat) {
        case ThreatType::NONE: return "None";
        case ThreatType::PHISHING_GENERIC: return "Phishing (Generic)";
        case ThreatType::PHISHING_BANKING: return "Phishing (Banking)";
        case ThreatType::MALWARE_DOWNLOAD: return "Malware Download";
        case ThreatType::EXPLOIT_KIT_LANDING: return "Exploit Kit Landing";
        case ThreatType::C2_BEACON: return "C2 Beacon";
        case ThreatType::DGA_DOMAIN: return "DGA Domain";
        case ThreatType::HOMOGRAPH: return "Homograph Attack";
        case ThreatType::TYPOSQUAT: return "Typosquatting";
        case ThreatType::CREDENTIAL_HARVEST: return "Credential Harvesting";
        case ThreatType::DRIVE_BY_DOWNLOAD: return "Drive-by Download";
        default: return "Unknown Threat";
    }
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
