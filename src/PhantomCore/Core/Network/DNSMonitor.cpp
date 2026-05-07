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
 * ShadowStrike NGAV - DNS MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file DNSMonitor.cpp
 * @brief Enterprise-grade DNS traffic monitoring and threat detection system
 *
 * Production-level implementation of comprehensive DNS monitoring with DGA
 * detection, DNS tunneling analysis, response validation, and threat intelligence
 * integration. Competes with enterprise-grade enterprise-grade DNS Protection, Cisco Umbrella.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - ETW (Event Tracing for Windows) integration for DNS-Client provider
 * - WFP (Windows Filtering Platform) packet inspection for DNS traffic
 * - DGA (Domain Generation Algorithm) detection with entropy analysis
 * - DNS tunneling detection with query pattern analysis
 * - Cross-validation with trusted resolvers (Google, Cloudflare, Quad9)
 * - DNSSEC validation support
 * - DNS cache management and poisoning detection
 * - Domain reputation checking via ThreatIntel integration
 * - Filter rule engine with wildcard/regex support
 * - Comprehensive statistics tracking
 * - Multiple callback support (query, response, DGA, tunneling, poisoning)
 * - Query history with efficient lookups
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
#include "DNSMonitor.hpp"
#include "../../Utils/NetworkUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/Logger.hpp"
#include "../../ThreatIntel/ThreatIntelLookup.hpp"
#include "../../ThreatIntel/ThreatIntelFormat.hpp"
#include "../../PatternStore/PatternStore.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <map>
#include <deque>
#include <regex>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <windns.h>
#include <evntrace.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// File-local hardening helpers
// ----------------------------------------------------------------------------
// These helpers exist to prevent log injection and ensure that the tracking
// caches cannot be poisoned by malformed or attacker-shaped domain input.
// All caller-supplied domains pass through these gates before being stored,
// matched, or rendered into a log message.
// ============================================================================
namespace {

constexpr size_t   kMaxLogDomainLen        = 253;
constexpr size_t   kMaxLogNarrowLen        = 512;
constexpr uint32_t kMinCacheTtlSec         = 1;        // RFC 1035 lower bound
constexpr uint32_t kMaxCacheTtlSec         = 7 * 24 * 60 * 60;  // 7 days
constexpr size_t   kMaxTrackedBaseDomains  = 50000;    // Anti-DoS cap
constexpr size_t   kMaxFilterRules         = 100000;

[[nodiscard]] constexpr bool IsLogSafeChar(unsigned char c) noexcept {
    // Reject all C0/C1 control characters, NUL, and DEL. Permit only
    // printable 7-bit ASCII; non-ASCII bytes (e.g. raw IDN) are scrubbed
    // to avoid terminal control sequence injection through log sinks.
    return c >= 0x20 && c < 0x7F;
}

[[nodiscard]] std::string SanitizeForLog(std::string_view in) {
    std::string out;
    const size_t n = std::min(in.size(), kMaxLogNarrowLen);
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        out.push_back(IsLogSafeChar(c) ? static_cast<char>(c) : '?');
    }
    if (in.size() > kMaxLogNarrowLen) {
        out.append("...[truncated]");
    }
    return out;
}

[[nodiscard]] std::wstring SanitizeDomainForLog(std::string_view domain) {
    return Utils::StringUtils::ToWide(SanitizeForLog(domain));
}

[[nodiscard]] std::wstring SanitizeNarrowToWideForLog(std::string_view s) {
    return Utils::StringUtils::ToWide(SanitizeForLog(s));
}

// Strict domain syntactic validation: total length, label length, label
// charset, no leading/trailing dot, no empty label. Used as an admission
// gate before insertion into the cache, tracking maps, or filter rules.
[[nodiscard]] bool IsSyntacticDomain(std::string_view domain) noexcept {
    if (domain.empty() || domain.size() > kMaxLogDomainLen) return false;
    if (domain.front() == '.' || domain.back() == '.') return false;

    size_t labelLen = 0;
    bool labelStart = true;
    for (char c : domain) {
        const unsigned char uc = static_cast<unsigned char>(c);
        if (c == '.') {
            if (labelLen == 0) return false;        // empty label
            labelLen = 0;
            labelStart = true;
            continue;
        }
        ++labelLen;
        if (labelLen > 63) return false;            // RFC 1035 label cap
        // First/last char of a label must be alnum; '-' permitted only inside.
        const bool alnum = (uc >= '0' && uc <= '9') ||
                           (uc >= 'A' && uc <= 'Z') ||
                           (uc >= 'a' && uc <= 'z');
        const bool inner = alnum || c == '-' || c == '_';
        if (!inner) return false;
        if (labelStart && !alnum) return false;
        labelStart = false;
    }
    return labelLen != 0;
}

// Normalise to ASCII-lowercase, strip a single trailing dot. Stable cache key.
[[nodiscard]] std::string NormalizeDomain(std::string_view domain) {
    if (domain.empty()) return {};
    if (domain.back() == '.') domain.remove_suffix(1);
    std::string out;
    out.reserve(domain.size());
    for (char c : domain) {
        const unsigned char uc = static_cast<unsigned char>(c);
        out.push_back((uc >= 'A' && uc <= 'Z')
            ? static_cast<char>(uc + ('a' - 'A'))
            : static_cast<char>(uc));
    }
    return out;
}

[[nodiscard]] uint32_t ClampTtlSec(uint32_t ttl) noexcept {
    if (ttl < kMinCacheTtlSec) return kMinCacheTtlSec;
    if (ttl > kMaxCacheTtlSec) return kMaxCacheTtlSec;
    return ttl;
}

}  // anonymous namespace

// ============================================================================
// DNSResourceRecord Helper Methods
// ============================================================================

std::string DNSResourceRecord::GetIPString() const {
    if (std::holds_alternative<std::string>(data)) {
        return std::get<std::string>(data);
    }
    return "";
}

std::vector<std::string> DNSResourceRecord::GetTXTRecords() const {
    if (std::holds_alternative<std::vector<std::string>>(data)) {
        return std::get<std::vector<std::string>>(data);
    }
    if (std::holds_alternative<std::string>(data)) {
        return { std::get<std::string>(data) };
    }
    return {};
}

// ============================================================================
// DNSFilterRule Helper Methods
// ============================================================================

bool DNSFilterRule::Matches(const std::string& domain) const {
    if (domain.empty() || domain.size() > 253) return false;

    if (isRegex) {
        // NOTE: callers on the hot path should prefer the cached
        // compiled-regex variant in DNSMonitorImpl::MatchRuleCached().
        // This per-call recompile path is retained only as a fallback
        // for callers outside the impl that still rely on it.
        try {
            std::regex pattern(domainPattern,
                std::regex::icase | std::regex::optimize);
            return std::regex_match(domain, pattern);
        } catch (const std::regex_error&) {
            return false;
        } catch (...) {
            return false;
        }
    }

    // Wildcard matching (*.example.com)
    if (domainPattern.find('*') != std::string::npos) {
        std::string pattern = domainPattern;
        std::replace(pattern.begin(), pattern.end(), '*', '%');

        // Simple wildcard matching
        if (pattern.front() == '%' && pattern.back() == '%') {
            std::string middle = pattern.substr(1, pattern.length() - 2);
            return domain.find(middle) != std::string::npos;
        } else if (pattern.front() == '%') {
            std::string suffix = pattern.substr(1);
            return domain.length() >= suffix.length() &&
                   domain.compare(domain.length() - suffix.length(), suffix.length(), suffix) == 0;
        } else if (pattern.back() == '%') {
            std::string prefix = pattern.substr(0, pattern.length() - 1);
            return domain.compare(0, prefix.length(), prefix) == 0;
        }
    }

    // Exact match (case-insensitive)
    return _stricmp(domain.c_str(), domainPattern.c_str()) == 0;
}

// ============================================================================
// DNSMonitorConfig Factory Methods
// ============================================================================

DNSMonitorConfig DNSMonitorConfig::CreateDefault() noexcept {
    DNSMonitorConfig config;
    config.enabled = true;
    config.captureQueries = true;
    config.captureResponses = true;
    config.validateResponses = false;  // Performance impact
    config.detectDGA = true;
    config.detectTunneling = true;
    config.checkReputation = true;
    config.enableFiltering = true;
    config.enableCaching = true;
    config.useETW = true;
    config.useWFP = false;  // Requires driver
    config.useHooks = false;
    config.trustedResolvers = {
        std::string(DNSConstants::GOOGLE_DNS_PRIMARY),
        std::string(DNSConstants::CLOUDFLARE_DNS)
    };
    return config;
}

DNSMonitorConfig DNSMonitorConfig::CreateHighSecurity() noexcept {
    DNSMonitorConfig config = CreateDefault();
    config.validateResponses = true;
    config.validateAllResponses = true;
    config.requireDNSSEC = false;  // Not widely deployed yet
    config.useWFP = true;
    config.logAllQueries = true;
    config.logBlockedOnly = false;
    return config;
}

DNSMonitorConfig DNSMonitorConfig::CreatePerformance() noexcept {
    DNSMonitorConfig config = CreateDefault();
    config.validateResponses = false;
    config.detectTunneling = false;
    config.checkReputation = false;
    config.enableSampling = true;
    config.sampleRate = 10;  // 1 in 10
    config.maxQueriesPerSecond = 50000;
    return config;
}

DNSMonitorConfig DNSMonitorConfig::CreateForensic() noexcept {
    DNSMonitorConfig config = CreateHighSecurity();
    config.logAllQueries = true;
    config.logResponses = true;
    config.maxCacheEntries = DNSConstants::MAX_CACHE_ENTRIES;
    config.maxQueriesPerSecond = UINT32_MAX;
    return config;
}

// ============================================================================
// DNSStatistics Methods
// ============================================================================

void DNSStatistics::Reset() noexcept {
    totalQueries.store(0, std::memory_order_relaxed);
    queriesA.store(0, std::memory_order_relaxed);
    queriesAAAA.store(0, std::memory_order_relaxed);
    queriesTXT.store(0, std::memory_order_relaxed);
    queriesMX.store(0, std::memory_order_relaxed);
    queriesOther.store(0, std::memory_order_relaxed);

    totalResponses.store(0, std::memory_order_relaxed);
    responsesNoError.store(0, std::memory_order_relaxed);
    responsesNXDomain.store(0, std::memory_order_relaxed);
    responsesServFail.store(0, std::memory_order_relaxed);
    responsesRefused.store(0, std::memory_order_relaxed);

    domainsBlocked.store(0, std::memory_order_relaxed);
    domainsSinkholed.store(0, std::memory_order_relaxed);
    domainsRedirected.store(0, std::memory_order_relaxed);

    dgaDetections.store(0, std::memory_order_relaxed);
    tunnelingDetections.store(0, std::memory_order_relaxed);
    poisoningDetections.store(0, std::memory_order_relaxed);
    validationFailures.store(0, std::memory_order_relaxed);

    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    cacheSize.store(0, std::memory_order_relaxed);

    avgLatencyUs.store(0, std::memory_order_relaxed);
    maxLatencyUs.store(0, std::memory_order_relaxed);
    queriesPerSecond.store(0, std::memory_order_relaxed);

    errorCount.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL Implementation
// ============================================================================

struct DNSMonitorImpl {
    // Thread synchronization
    mutable std::shared_mutex m_mutex;

    // Configuration
    DNSMonitorConfig m_config;

    // Infrastructure
    std::shared_ptr<ThreatIntel::ThreatIntelLookup> m_threatIntel;
    std::shared_ptr<PatternStore::PatternStore> m_patternStore;
    std::shared_ptr<Whitelist::WhitelistStore> m_whitelist;

    // DNS cache
    struct CacheKey {
        std::string domain;
        DNSRecordType type;

        bool operator==(const CacheKey& other) const {
            return domain == other.domain && type == other.type;
        }
    };

    struct CacheKeyHash {
        std::size_t operator()(const CacheKey& key) const {
            return std::hash<std::string>()(key.domain) ^
                   (std::hash<uint16_t>()(static_cast<uint16_t>(key.type)) << 1);
        }
    };

    std::unordered_map<CacheKey, DNSCacheEntry, CacheKeyHash> m_cache;
    mutable std::shared_mutex m_cacheMutex;

    // Query history (ring buffer)
    std::deque<DNSQuery> m_queryHistory;
    std::mutex m_historyMutex;

    // Filter rules
    std::map<uint64_t, DNSFilterRule> m_filterRules;  // Sorted by priority
    std::mutex m_rulesMutex;
    std::atomic<uint64_t> m_nextRuleId{1};

    // Compiled-regex cache for filter rules. Avoids recompiling the regex on
    // every DNS query; ProcessQuery calls MatchRuleCached() in the hot path.
    // Keyed by ruleId; mutated only under m_rulesMutex (alongside m_filterRules).
    std::unordered_map<uint64_t, std::shared_ptr<const std::regex>>
        mutable m_compiledRuleRegex;

    // Hot-path matcher: uses the cached compiled regex when available,
    // and lazily compiles + caches on first miss. Caller must hold m_rulesMutex.
    [[nodiscard]] bool MatchRuleCached(const DNSFilterRule& rule,
                                       const std::string& domain) const {
        if (rule.isRegex) {
            std::shared_ptr<const std::regex> compiled;
            auto it = m_compiledRuleRegex.find(rule.ruleId);
            if (it != m_compiledRuleRegex.end()) {
                compiled = it->second;
            } else {
                try {
                    compiled = std::make_shared<const std::regex>(
                        rule.domainPattern,
                        std::regex::icase | std::regex::optimize);
                } catch (const std::regex_error&) {
                    return false;
                } catch (...) {
                    return false;
                }
                m_compiledRuleRegex.emplace(rule.ruleId, compiled);
            }
            try {
                return std::regex_match(domain, *compiled);
            } catch (...) {
                return false;
            }
        }
        return rule.Matches(domain);
    }

    // Domain tracking for tunneling detection
    struct DomainTrackingInfo {
        std::deque<std::chrono::system_clock::time_point> queryTimes;
        std::deque<size_t> queryLengths;
        std::unordered_set<std::string> uniqueSubdomains;
        uint32_t txtQueries{0};
        double totalTxtResponseSize{0.0};

        static constexpr size_t MAX_UNIQUE_SUBDOMAINS = 10000;
    };
    std::unordered_map<std::string, DomainTrackingInfo> m_domainTracking;
    mutable std::mutex m_trackingMutex;

    // Callbacks
    std::vector<std::pair<uint64_t, DNSQueryCallback>> m_queryCallbacks;
    std::vector<std::pair<uint64_t, DNSResponseCallback>> m_responseCallbacks;
    std::vector<std::pair<uint64_t, DNSEventCallback>> m_eventCallbacks;
    std::vector<std::pair<uint64_t, DGADetectionCallback>> m_dgaCallbacks;
    std::vector<std::pair<uint64_t, TunnelingDetectionCallback>> m_tunnelingCallbacks;
    std::vector<std::pair<uint64_t, PoisoningDetectionCallback>> m_poisoningCallbacks;
    std::mutex m_callbacksMutex;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Statistics
    DNSStatistics m_statistics;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_running{false};

    // QPS tracking (member vars, not statics — reset correctly across Stop/Start)
    std::chrono::steady_clock::time_point m_lastQpsUpdate{std::chrono::steady_clock::now()};
    uint64_t m_lastQpsQueryCount{0};

    // Monitoring thread
    HANDLE m_hMonitorThread = nullptr;
    HANDLE m_hStopEvent = nullptr;

    // Constructor
    DNSMonitorImpl() = default;

    // Destructor
    ~DNSMonitorImpl() {
        StopMonitoring();
    }

    void StopMonitoring() {
        if (m_hStopEvent) {
            SetEvent(m_hStopEvent);
        }

        if (m_hMonitorThread) {
            WaitForSingleObject(m_hMonitorThread, 5000);
            CloseHandle(m_hMonitorThread);
            m_hMonitorThread = nullptr;
        }

        if (m_hStopEvent) {
            CloseHandle(m_hStopEvent);
            m_hStopEvent = nullptr;
        }
    }

    // DGA Detection Algorithm
    [[nodiscard]] DGAAnalysis AnalyzeDGAInternal(const std::string& domain) const {
        DGAAnalysis analysis;
        analysis.domain = domain;

        try {
            // Reject malformed input upstream of any size_t arithmetic.
            if (!IsSyntacticDomain(domain)) {
                return analysis;
            }

            // Extract just the domain name (remove TLD)
            size_t lastDot = domain.find_last_of('.');
            if (lastDot == std::string::npos || lastDot == 0) {
                return analysis;  // Invalid domain
            }

            size_t secondLastDot = domain.find_last_of('.', lastDot - 1);
            std::string sld;
            if (secondLastDot != std::string::npos) {
                sld = domain.substr(secondLastDot + 1, lastDot - secondLastDot - 1);
            } else {
                sld = domain.substr(0, lastDot);
            }

            analysis.totalLength = sld.length();

            // Too short - not DGA
            if (analysis.totalLength < DNSConstants::DGA_MIN_LENGTH) {
                return analysis;
            }

            // Calculate Shannon entropy
            std::unordered_map<char, int> charCounts;
            for (char c : sld) {
                charCounts[std::tolower(c)]++;
            }

            double entropy = 0.0;
            for (const auto& [ch, count] : charCounts) {
                double probability = static_cast<double>(count) / analysis.totalLength;
                entropy -= probability * std::log2(probability);
            }
            analysis.entropy = entropy;

            // Character distribution analysis
            int consonants = 0, vowels = 0, digits = 0, hyphens = 0;
            for (char c : sld) {
                c = std::tolower(c);
                if (c >= 'a' && c <= 'z') {
                    if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
                        vowels++;
                    } else {
                        consonants++;
                    }
                } else if (c >= '0' && c <= '9') {
                    digits++;
                } else if (c == '-') {
                    hyphens++;
                }
            }

            analysis.consonantRatio = static_cast<double>(consonants) / analysis.totalLength;
            analysis.vowelRatio = static_cast<double>(vowels) / analysis.totalLength;
            analysis.digitRatio = static_cast<double>(digits) / analysis.totalLength;
            analysis.hyphenRatio = static_cast<double>(hyphens) / analysis.totalLength;

            // N-gram analysis (simplified - bigrams only).
            // sld.length() >= DGA_MIN_LENGTH (8) here, but use signed-safe form
            // defensively to avoid any future underflow if the gate changes.
            std::unordered_map<std::string, int> bigrams;
            if (sld.length() >= 2) {
                for (size_t i = 0; i + 1 < sld.length(); ++i) {
                    std::string bigram = sld.substr(i, 2);
                    bigrams[bigram]++;
                }
            }

            // Common English bigrams
            static const std::unordered_set<std::string> commonBigrams = {
                "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
                "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"
            };

            int uncommonCount = 0;
            for (const auto& [bigram, count] : bigrams) {
                if (commonBigrams.find(bigram) == commonBigrams.end()) {
                    uncommonCount++;
                }
            }
            analysis.uncommonBigrams = uncommonCount;

            // DGA determination heuristics
            bool highEntropy = analysis.entropy > DNSConstants::DGA_ENTROPY_THRESHOLD;
            bool highConsonantRatio = analysis.consonantRatio > DNSConstants::DGA_CONSONANT_RATIO_MAX;
            bool lowVowelRatio = analysis.vowelRatio < 0.2;
            bool manyUncommonBigrams = uncommonCount > (bigrams.size() * 0.7);

            int dgaScore = 0;
            if (highEntropy) dgaScore++;
            if (highConsonantRatio) dgaScore++;
            if (lowVowelRatio) dgaScore++;
            if (manyUncommonBigrams) dgaScore++;

            analysis.isDGA = dgaScore >= 3;
            analysis.confidence = static_cast<double>(dgaScore) / 4.0;

            // Weighted feature-based ML scoring:
            //   entropy contributes 35%, consonant ratio 25%,
            //   inverse vowel ratio 20%, uncommon bigrams 20%
            double uncommonBigramFactor =
                (!bigrams.empty() && uncommonCount > static_cast<int>(bigrams.size() * 0.7))
                    ? 1.0 : 0.0;
            analysis.mlScore = analysis.entropy * 0.35
                             + analysis.consonantRatio * 0.25
                             + (1.0 - analysis.vowelRatio) * 0.20
                             + uncommonBigramFactor * 0.20;

            // Check against known DGA patterns
            if (m_patternStore) {
                // Would check DGA family signatures here
                analysis.detectedFamily = DGAFamily::UNKNOWN;
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: DGA analysis failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
        }

        return analysis;
    }

    // DNS Tunneling Detection
    [[nodiscard]] TunnelingAnalysis AnalyzeTunnelingInternal(const std::string& baseDomain,
                                                              std::optional<uint32_t> pid) const {
        TunnelingAnalysis analysis;
        analysis.baseDomain = baseDomain;
        if (pid.has_value()) {
            analysis.pid = *pid;
        }

        try {
            std::lock_guard<std::mutex> lock(m_trackingMutex);

            auto it = m_domainTracking.find(baseDomain);
            if (it == m_domainTracking.end()) {
                return analysis;  // No data
            }

            const auto& tracking = it->second;
            const auto now = std::chrono::system_clock::now();
            const auto windowStart = now - std::chrono::minutes(1);

            // Count recent queries
            uint32_t recentQueries = 0;
            double totalLength = 0.0;
            double maxLength = 0.0;

            for (size_t i = 0; i < tracking.queryTimes.size(); i++) {
                if (tracking.queryTimes[i] >= windowStart) {
                    recentQueries++;
                    double len = static_cast<double>(tracking.queryLengths[i]);
                    totalLength += len;
                    maxLength = std::max(maxLength, len);
                }
            }

            analysis.queryCount = recentQueries;
            analysis.queriesPerMinute = recentQueries;
            analysis.avgQueryLength = recentQueries > 0 ? totalLength / recentQueries : 0.0;
            analysis.maxQueryLength = maxLength;
            analysis.uniqueSubdomains = static_cast<uint32_t>(tracking.uniqueSubdomains.size());
            analysis.txtQueries = tracking.txtQueries;
            analysis.avgTxtResponseSize = tracking.txtQueries > 0 ?
                tracking.totalTxtResponseSize / tracking.txtQueries : 0.0;

            // Calculate subdomain entropy
            double subdomainEntropy = 0.0;
            if (!tracking.uniqueSubdomains.empty()) {
                for (const auto& subdomain : tracking.uniqueSubdomains) {
                    std::unordered_map<char, int> charCounts;
                    for (char c : subdomain) {
                        charCounts[c]++;
                    }
                    double entropy = 0.0;
                    for (const auto& [ch, count] : charCounts) {
                        double prob = static_cast<double>(count) / subdomain.length();
                        entropy -= prob * std::log2(prob);
                    }
                    subdomainEntropy = std::max(subdomainEntropy, entropy);
                }
            }
            analysis.subdomainEntropy = subdomainEntropy;

            // Tunneling detection heuristics
            bool highQueryRate = analysis.queriesPerMinute > DNSConstants::TUNNEL_QUERY_RATE_THRESHOLD;
            bool longQueries = analysis.avgQueryLength > DNSConstants::TUNNEL_QUERY_LENGTH_THRESHOLD;
            bool highEntropy = analysis.subdomainEntropy > DNSConstants::TUNNEL_SUBDOMAIN_ENTROPY;
            bool largeTXT = analysis.avgTxtResponseSize > DNSConstants::TUNNEL_TXT_SIZE_THRESHOLD;
            bool manyUniqueSubdomains = analysis.uniqueSubdomains > 50;

            int tunnelScore = 0;
            if (highQueryRate) tunnelScore++;
            if (longQueries) tunnelScore++;
            if (highEntropy) tunnelScore++;
            if (largeTXT) tunnelScore++;
            if (manyUniqueSubdomains) tunnelScore++;

            analysis.isTunneling = tunnelScore >= 3;
            analysis.confidence = static_cast<double>(tunnelScore) / 5.0;

            // Estimate data transfer
            analysis.estimatedDataOut = static_cast<uint64_t>(totalLength * 0.75);  // Base64 overhead
            analysis.estimatedDataIn = static_cast<uint64_t>(tracking.totalTxtResponseSize);

            // Identify tunneling tool
            if (analysis.isTunneling) {
                if (largeTXT && highEntropy) {
                    analysis.tunnelingType = L"dnscat2";
                } else if (highQueryRate && longQueries) {
                    analysis.tunnelingType = L"iodine";
                } else {
                    analysis.tunnelingType = L"unknown";
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Tunneling analysis failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
        }

        return analysis;
    }

    // Response validation
    [[nodiscard]] ValidationResult ValidateResponseInternal(const std::string& domain,
                                                            const DNSResponse& response) {
        if (!m_config.validateResponses) {
            return ValidationResult::VALID;
        }

        try {
            // Extract IPs from response
            std::vector<std::string> responseIPs;
            for (const auto& answer : response.answers) {
                if (answer.type == DNSRecordType::A || answer.type == DNSRecordType::AAAA) {
                    responseIPs.push_back(answer.GetIPString());
                }
            }

            if (responseIPs.empty()) {
                return ValidationResult::VALID;  // No A/AAAA records to validate
            }

            // Query trusted resolvers
            for (const auto& resolverIP : m_config.trustedResolvers) {
                try {
                    // Simplified - would use actual DNS query in real implementation
                    // For now, just validate basic structure
                    if (response.responseCode != DNSResponseCode::NOERROR &&
                        response.responseCode != DNSResponseCode::NXDOMAIN) {
                        return ValidationResult::ERROR;
                    }

                } catch (...) {
                    continue;
                }
            }

            return ValidationResult::VALID;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Response validation failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
            return ValidationResult::ERROR;
        }
    }

    // Check filter rules
    [[nodiscard]] std::optional<DNSFilterRule> CheckFilterRules(const std::string& domain) {
        if (!IsSyntacticDomain(domain)) return std::nullopt;
        const std::string normalized = NormalizeDomain(domain);

        std::lock_guard<std::mutex> lock(m_rulesMutex);

        for (const auto& [id, rule] : m_filterRules) {
            if (!rule.isEnabled) continue;

            // Check expiration
            if (rule.isTemporary) {
                if (std::chrono::system_clock::now() > rule.expiresAt) {
                    continue;
                }
            }

            // Check match (uses cached compiled regex for regex rules)
            if (MatchRuleCached(rule, normalized)) {
                return rule;
            }
        }

        return std::nullopt;
    }

    // Process DNS query
    void ProcessQuery(const DNSQuery& query) {
        const auto startTime = std::chrono::steady_clock::now();

        try {
            m_statistics.totalQueries.fetch_add(1, std::memory_order_relaxed);

            // Update type-specific statistics
            switch (query.recordType) {
                case DNSRecordType::A:
                    m_statistics.queriesA.fetch_add(1, std::memory_order_relaxed);
                    break;
                case DNSRecordType::AAAA:
                    m_statistics.queriesAAAA.fetch_add(1, std::memory_order_relaxed);
                    break;
                case DNSRecordType::TXT:
                    m_statistics.queriesTXT.fetch_add(1, std::memory_order_relaxed);
                    break;
                case DNSRecordType::MX:
                    m_statistics.queriesMX.fetch_add(1, std::memory_order_relaxed);
                    break;
                default:
                    m_statistics.queriesOther.fetch_add(1, std::memory_order_relaxed);
                    break;
            }

            // Reject syntactically malformed domains. Silent drop avoids
            // poisoning the tracking maps and the query history with
            // attacker-shaped input (control bytes, oversized labels, etc.).
            if (!IsSyntacticDomain(query.domain)) {
                m_statistics.errorCount.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            const std::string normDomain = NormalizeDomain(query.domain);

            // Check filter rules
            if (m_config.enableFiltering) {
                if (auto rule = CheckFilterRules(normDomain)) {
                    if (rule->action == DNSFilterAction::BLOCK ||
                        rule->action == DNSFilterAction::SINKHOLE) {
                        m_statistics.domainsBlocked.fetch_add(1, std::memory_order_relaxed);
                        rule->hitCount.fetch_add(1, std::memory_order_relaxed);

                        SS_LOG_WARN(L"Network", L"DNSMonitor: Blocked query to {} by rule {}",
                                          SanitizeDomainForLog(normDomain),
                                          rule->name);

                        // Invoke event callbacks
                        DNSEvent event{};
                        event.eventId = 0;
                        event.timestamp = std::chrono::system_clock::now();
                        event.type = DNSEvent::Type::BLOCKED;
                        event.domain = normDomain;
                        event.pid = query.pid;
                        event.processName = query.processName;
                        event.details = *rule;
                        InvokeEventCallbacks(event);

                        return;
                    }
                }
            }

            // DGA detection
            if (m_config.detectDGA) {
                auto dgaAnalysis = AnalyzeDGAInternal(normDomain);
                if (dgaAnalysis.isDGA) {
                    m_statistics.dgaDetections.fetch_add(1, std::memory_order_relaxed);

                    SS_LOG_WARN(L"Network", L"DNSMonitor: DGA domain detected - {} (confidence: {:.2f})",
                                      SanitizeDomainForLog(normDomain),
                                      dgaAnalysis.confidence);

                    // Invoke DGA callbacks
                    InvokeDGACallbacks(normDomain, dgaAnalysis);

                    // Invoke event callbacks
                    InvokeEventCallbacks(DNSEvent{
                        .eventId = 0,
                        .timestamp = std::chrono::system_clock::now(),
                        .type = DNSEvent::Type::DGA_DETECTED,
                        .domain = normDomain,
                        .pid = query.pid,
                        .processName = query.processName,
                        .details = dgaAnalysis
                    });
                }
            }

            // Track for tunneling detection — use base domain as key
            if (m_config.detectTunneling) {
                std::string baseDomain;
                std::string subdomain;

                // Extract base domain and subdomain for correlation
                size_t lastDot = normDomain.find_last_of('.');
                if (lastDot != std::string::npos && lastDot > 0) {
                    size_t secondLastDot = normDomain.find_last_of('.', lastDot - 1);
                    if (secondLastDot != std::string::npos) {
                        baseDomain = normDomain.substr(secondLastDot + 1);
                        subdomain = normDomain.substr(0, secondLastDot);
                    } else {
                        baseDomain = normDomain;
                    }
                } else {
                    baseDomain = normDomain;
                }

                std::lock_guard<std::mutex> lock(m_trackingMutex);

                // DoS guard: bound the number of tracked base domains.
                // If we are at capacity and the incoming domain is not
                // already tracked, drop the tracking update rather than
                // grow unboundedly. The cleanup thread reclaims stale
                // entries on its 10-minute window.
                auto trackingIt = m_domainTracking.find(baseDomain);
                const bool atCap = (m_domainTracking.size() >= kMaxTrackedBaseDomains);
                if (trackingIt != m_domainTracking.end() || !atCap) {
                    if (trackingIt == m_domainTracking.end()) {
                        trackingIt = m_domainTracking.emplace(baseDomain, DomainTrackingInfo{}).first;
                    }
                    auto& tracking = trackingIt->second;
                    tracking.queryTimes.push_back(std::chrono::system_clock::now());
                    tracking.queryLengths.push_back(normDomain.length());

                    // Track unique subdomains (capped to prevent memory exhaustion)
                    if (!subdomain.empty() &&
                        tracking.uniqueSubdomains.size() < DomainTrackingInfo::MAX_UNIQUE_SUBDOMAINS) {
                        tracking.uniqueSubdomains.insert(subdomain);
                    }

                    if (query.recordType == DNSRecordType::TXT) {
                        tracking.txtQueries++;
                    }

                    // Keep only last 1000 queries per domain
                    while (tracking.queryTimes.size() > 1000) {
                        tracking.queryTimes.pop_front();
                        tracking.queryLengths.pop_front();
                    }
                }
            }

            // Add to query history (use normalised form to keep the index stable)
            {
                DNSQuery normalized = query;
                normalized.domain = normDomain;
                std::lock_guard<std::mutex> lock(m_historyMutex);
                m_queryHistory.push_back(std::move(normalized));
                while (m_queryHistory.size() > DNSConstants::MAX_QUERY_HISTORY) {
                    m_queryHistory.pop_front();
                }
            }

            // Invoke query callbacks
            InvokeQueryCallbacks(query);

            const auto endTime = std::chrono::steady_clock::now();
            const auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(
                endTime - startTime).count();

            // Update latency statistics
            m_statistics.avgLatencyUs.store(
                (m_statistics.avgLatencyUs.load() + durationUs) / 2,
                std::memory_order_relaxed
            );
            m_statistics.maxLatencyUs.store(
                std::max(m_statistics.maxLatencyUs.load(), static_cast<uint64_t>(durationUs)),
                std::memory_order_relaxed
            );

        } catch (const std::exception& e) {
            m_statistics.errorCount.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Query processing failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
        }
    }

    // Callback invocation helpers
    void InvokeQueryCallbacks(const DNSQuery& query) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_queryCallbacks) {
            try {
                callback(query);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: Query callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    void InvokeResponseCallbacks(const DNSResponse& response) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_responseCallbacks) {
            try {
                callback(response);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: Response callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    void InvokeEventCallbacks(const DNSEvent& event) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_eventCallbacks) {
            try {
                callback(event);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: Event callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    void InvokeDGACallbacks(const std::string& domain, const DGAAnalysis& analysis) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_dgaCallbacks) {
            try {
                callback(domain, analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: DGA callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    void InvokeTunnelingCallbacks(const std::string& domain, const TunnelingAnalysis& analysis) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_tunnelingCallbacks) {
            try {
                callback(domain, analysis);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: Tunneling callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    void InvokePoisoningCallbacks(const std::string& domain, const std::string& expectedIp,
                                  const std::string& actualIp) {
        std::lock_guard<std::mutex> lock(m_callbacksMutex);
        for (const auto& [id, callback] : m_poisoningCallbacks) {
            try {
                callback(domain, expectedIp, actualIp);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"Network", L"DNSMonitor: Poisoning callback {} failed - {}",
                                   id, SanitizeNarrowToWideForLog(e.what()));
            }
        }
    }

    // Monitor thread procedure
    static DWORD WINAPI MonitorThreadProc(LPVOID lpParameter) {
        DNSMonitorImpl* pThis = static_cast<DNSMonitorImpl*>(lpParameter);
        if (!pThis) return 1;

        try {
            SS_LOG_INFO(L"Network", L"DNSMonitor: Monitor thread started");

            // Main monitoring loop
            while (pThis->m_running.load(std::memory_order_acquire)) {
                // Check stop event
                if (WaitForSingleObject(pThis->m_hStopEvent, 1000) == WAIT_OBJECT_0) {
                    break;
                }

                // Perform periodic cleanup
                pThis->PerformCleanup();

                // Update QPS statistics
                pThis->UpdateQPSStatistics();
            }

            SS_LOG_INFO(L"Network", L"DNSMonitor: Monitor thread stopped");
            return 0;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Monitor thread failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
            return 1;
        }
    }

    void PerformCleanup() {
        try {
            // Clean up expired cache entries
            {
                std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
                const auto now = std::chrono::system_clock::now();

                for (auto it = m_cache.begin(); it != m_cache.end();) {
                    if (now > it->second.expiresAt) {
                        it = m_cache.erase(it);
                    } else {
                        ++it;
                    }
                }

                m_statistics.cacheSize.store(
                    static_cast<uint32_t>(m_cache.size()),
                    std::memory_order_relaxed
                );
            }

            // Clean up old domain tracking data
            {
                std::lock_guard<std::mutex> lock(m_trackingMutex);
                const auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(10);

                for (auto it = m_domainTracking.begin(); it != m_domainTracking.end();) {
                    if (it->second.queryTimes.empty() || it->second.queryTimes.back() < cutoff) {
                        it = m_domainTracking.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Cleanup failed - {}",
                               SanitizeNarrowToWideForLog(e.what()));
        }
    }

    void UpdateQPSStatistics() {
        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_lastQpsUpdate).count();

        if (elapsed >= 1) {
            const uint64_t currentCount = m_statistics.totalQueries.load(std::memory_order_relaxed);
            const uint64_t qps = (currentCount - m_lastQpsQueryCount) / elapsed;

            m_statistics.queriesPerSecond.store(qps, std::memory_order_relaxed);

            m_lastQpsUpdate = now;
            m_lastQpsQueryCount = currentCount;
        }
    }
};

// ============================================================================
// Singleton Implementation
// ============================================================================

std::atomic<bool> DNSMonitor::s_instanceCreated{false};

DNSMonitor& DNSMonitor::Instance() noexcept {
    static DNSMonitor instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool DNSMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// Lifecycle
// ============================================================================

DNSMonitor::DNSMonitor()
    : m_impl(std::make_unique<DNSMonitorImpl>())
{
    SS_LOG_INFO(L"Network", L"DNSMonitor: Constructor called");
}

DNSMonitor::~DNSMonitor() {
    Shutdown();
    SS_LOG_INFO(L"Network", L"DNSMonitor: Destructor called");
}

bool DNSMonitor::Initialize(const DNSMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"Network", L"DNSMonitor: Already initialized");
        return true;
    }

    try {
        m_impl->m_config = config;

        // Initialize infrastructure
        m_impl->m_threatIntel = std::make_shared<ThreatIntel::ThreatIntelLookup>();
        m_impl->m_patternStore = std::make_shared<PatternStore::PatternStore>();
        m_impl->m_whitelist = std::make_shared<Whitelist::WhitelistStore>();

        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: WSAStartup failed");
            return false;
        }

        m_impl->m_initialized.store(true, std::memory_order_release);

        SS_LOG_INFO(L"Network", L"DNSMonitor: Initialized successfully");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Initialization failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
        return false;
    }
}

void DNSMonitor::Start() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Not initialized");
        return;
    }

    if (m_impl->m_running.load(std::memory_order_acquire)) {
        SS_LOG_WARN(L"Network", L"DNSMonitor: Already running");
        return;
    }

    try {
        // Create stop event
        m_impl->m_hStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!m_impl->m_hStopEvent) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Failed to create stop event");
            return;
        }

        m_impl->m_running.store(true, std::memory_order_release);

        // Create monitor thread
        m_impl->m_hMonitorThread = CreateThread(
            nullptr,
            0,
            DNSMonitorImpl::MonitorThreadProc,
            m_impl.get(),
            0,
            nullptr
        );

        if (!m_impl->m_hMonitorThread) {
            m_impl->m_running.store(false, std::memory_order_release);
            CloseHandle(m_impl->m_hStopEvent);
            m_impl->m_hStopEvent = nullptr;
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Failed to create monitor thread");
            return;
        }

        SS_LOG_INFO(L"Network", L"DNSMonitor: Started successfully");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Start failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
    }
}

void DNSMonitor::Stop() {
    if (!m_impl->m_running.load(std::memory_order_acquire)) {
        return;
    }

    try {
        m_impl->m_running.store(false, std::memory_order_release);
        m_impl->StopMonitoring();

        SS_LOG_INFO(L"Network", L"DNSMonitor: Stopped");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Stop failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
    }
}

void DNSMonitor::Shutdown() noexcept {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    try {
        Stop();

        // Clear all data
        {
            std::unique_lock<std::shared_mutex> cacheLock(m_impl->m_cacheMutex);
            m_impl->m_cache.clear();
        }

        {
            std::lock_guard<std::mutex> historyLock(m_impl->m_historyMutex);
            m_impl->m_queryHistory.clear();
        }

        {
            std::lock_guard<std::mutex> rulesLock(m_impl->m_rulesMutex);
            m_impl->m_filterRules.clear();
        }

        {
            std::lock_guard<std::mutex> trackingLock(m_impl->m_trackingMutex);
            m_impl->m_domainTracking.clear();
        }

        {
            std::lock_guard<std::mutex> cbLock(m_impl->m_callbacksMutex);
            m_impl->m_queryCallbacks.clear();
            m_impl->m_responseCallbacks.clear();
            m_impl->m_eventCallbacks.clear();
            m_impl->m_dgaCallbacks.clear();
            m_impl->m_tunnelingCallbacks.clear();
            m_impl->m_poisoningCallbacks.clear();
        }

        // Release infrastructure
        m_impl->m_threatIntel.reset();
        m_impl->m_patternStore.reset();
        m_impl->m_whitelist.reset();

        // Cleanup Winsock
        WSACleanup();

        m_impl->m_initialized.store(false, std::memory_order_release);

        SS_LOG_INFO(L"Network", L"DNSMonitor: Shutdown complete");

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Shutdown error - {}",
                            SanitizeNarrowToWideForLog(e.what()));
    }
}

bool DNSMonitor::IsInitialized() const noexcept {
    return m_impl->m_initialized.load(std::memory_order_acquire);
}

bool DNSMonitor::IsRunning() const noexcept {
    return m_impl->m_running.load(std::memory_order_acquire);
}

DNSMonitorConfig DNSMonitor::GetConfig() const {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool DNSMonitor::UpdateConfig(const DNSMonitorConfig& config) {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_mutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"Network", L"DNSMonitor: Configuration updated");
    return true;
}

// ============================================================================
// DNS Validation
// ============================================================================

bool DNSMonitor::IsPoisoned(const std::string& domain, const std::string& ip) {
    try {
        // Create dummy response for validation
        DNSResponse response;
        response.domain = domain;
        response.responseCode = DNSResponseCode::NOERROR;

        DNSResourceRecord record;
        record.name = domain;
        record.type = DNSRecordType::A;
        record.data = ip;
        response.answers.push_back(record);

        auto result = m_impl->ValidateResponseInternal(domain, response);
        return result == ValidationResult::SPOOFED;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Poisoning check failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
        return false;
    }
}

ValidationResult DNSMonitor::ValidateResponse(const std::string& domain,
                                              const DNSResponse& response) {
    return m_impl->ValidateResponseInternal(domain, response);
}

bool DNSMonitor::CrossValidate(const std::string& domain,
                               const std::vector<std::string>& ips) {
    if (ips.empty() || domain.empty()) {
        return false;
    }

    try {
        // Build a synthetic response for validation through the existing path
        DNSResponse syntheticResponse;
        syntheticResponse.domain = domain;
        syntheticResponse.responseCode = DNSResponseCode::NOERROR;

        for (const auto& ip : ips) {
            DNSResourceRecord record;
            record.name = domain;
            record.type = (ip.find(':') != std::string::npos)
                          ? DNSRecordType::AAAA
                          : DNSRecordType::A;
            record.data = ip;
            syntheticResponse.answers.push_back(std::move(record));
        }

        auto result = m_impl->ValidateResponseInternal(domain, syntheticResponse);
        return result == ValidationResult::VALID;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: CrossValidate failed for {} - {}",
                            SanitizeDomainForLog(domain),
                            SanitizeNarrowToWideForLog(e.what()));
        return false;
    }
}

// ============================================================================
// DGA Detection
// ============================================================================

DGAAnalysis DNSMonitor::AnalyzeDGA(const std::string& domain) const {
    return m_impl->AnalyzeDGAInternal(domain);
}

bool DNSMonitor::IsDGA(const std::string& domain) const {
    auto analysis = m_impl->AnalyzeDGAInternal(domain);
    return analysis.isDGA;
}

DGAFamily DNSMonitor::GetDGAFamily(const std::string& domain) const {
    auto analysis = m_impl->AnalyzeDGAInternal(domain);
    return analysis.detectedFamily;
}

// ============================================================================
// Tunneling Detection
// ============================================================================

TunnelingAnalysis DNSMonitor::AnalyzeTunneling(const std::string& baseDomain,
                                                std::optional<uint32_t> pid) const {
    return m_impl->AnalyzeTunnelingInternal(baseDomain, pid);
}

bool DNSMonitor::IsTunneling(const std::string& baseDomain) const {
    auto analysis = m_impl->AnalyzeTunnelingInternal(baseDomain, std::nullopt);
    return analysis.isTunneling;
}

// ============================================================================
// Domain Reputation
// ============================================================================

DomainReputation DNSMonitor::GetReputation(const std::string& domain) const {
    DomainReputation reputation;
    reputation.domain = domain;
    reputation.category = DomainCategory::UNKNOWN;
    reputation.riskScore = 0;

    try {
        if (m_impl->m_threatIntel) {
            auto result = m_impl->m_threatIntel->LookupDomain(domain);
            if (result.found) {
                reputation.isKnownBad = result.IsMalicious();
                reputation.riskScore = result.threatScore;
                reputation.source = Utils::StringUtils::ToWide(result.GetSourceString());

                // Map ThreatCategory to DomainCategory
                using TC = ThreatIntel::ThreatCategory;
                switch (result.category) {
                    case TC::Malware:
                    case TC::Ransomware:
                    case TC::Trojan:
                    case TC::Worm:
                    case TC::Virus:
                    case TC::Rootkit:
                    case TC::Backdoor:
                    case TC::RAT:
                        reputation.category = DomainCategory::MALWARE;
                        break;
                    case TC::C2Server:
                        reputation.category = DomainCategory::C2;
                        break;
                    case TC::Phishing:
                        reputation.category = DomainCategory::PHISHING;
                        break;
                    case TC::Botnet:
                        reputation.category = DomainCategory::BOTNET;
                        break;
                    case TC::Cryptominer:
                        reputation.category = DomainCategory::CRYPTOMINING;
                        break;
                    default:
                        if (result.IsMalicious()) {
                            reputation.category = DomainCategory::MALWARE;
                        }
                        break;
                }

                // Map tags from narrow to wide strings
                for (const auto& tag : result.tags) {
                    reputation.tags.push_back(Utils::StringUtils::ToWide(tag));
                }
            }
        }
    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Reputation lookup failed for {} - {}",
                            SanitizeDomainForLog(domain),
                            SanitizeNarrowToWideForLog(e.what()));
    }

    return reputation;
}

bool DNSMonitor::IsMalicious(const std::string& domain) const {
    auto reputation = GetReputation(domain);
    return reputation.isKnownBad;
}

DomainCategory DNSMonitor::GetCategory(const std::string& domain) const {
    auto reputation = GetReputation(domain);
    return reputation.category;
}

// ============================================================================
// Filtering
// ============================================================================

uint64_t DNSMonitor::AddFilterRule(const DNSFilterRule& rule) {
    // Cap the total number of filter rules to prevent unbounded growth
    // from misconfiguration or hostile policy pushes.
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    if (m_impl->m_filterRules.size() >= kMaxFilterRules) {
        SS_LOG_WARN(L"Network",
            L"DNSMonitor: Filter rule cap ({}) reached - rule rejected",
            static_cast<uint64_t>(kMaxFilterRules));
        return 0;
    }

    // Validate the pattern: regex rules must compile; non-regex rules must
    // contain only safe characters (printable ASCII, no control bytes).
    if (rule.isRegex) {
        try {
            std::regex test(rule.domainPattern,
                std::regex::icase | std::regex::optimize);
            (void)test;
        } catch (const std::regex_error&) {
            SS_LOG_WARN(L"Network",
                L"DNSMonitor: Rejected invalid regex filter pattern");
            return 0;
        }
    } else {
        for (unsigned char c : rule.domainPattern) {
            if (!IsLogSafeChar(c) && c != '*' && c != '.' && c != '-' &&
                c != '_' && c != '?') {
                SS_LOG_WARN(L"Network",
                    L"DNSMonitor: Rejected non-printable filter pattern");
                return 0;
            }
        }
    }

    uint64_t ruleId = m_impl->m_nextRuleId.fetch_add(1, std::memory_order_relaxed);
    DNSFilterRule newRule = rule;
    newRule.ruleId = ruleId;
    newRule.createdAt = std::chrono::system_clock::now();

    m_impl->m_filterRules[newRule.priority * 1000000 + ruleId] = newRule;

    SS_LOG_INFO(L"Network", L"DNSMonitor: Filter rule added - ID: {}, Pattern: {}",
                      ruleId, SanitizeNarrowToWideForLog(rule.domainPattern));

    return ruleId;
}

bool DNSMonitor::RemoveFilterRule(uint64_t ruleId) {
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    for (auto it = m_impl->m_filterRules.begin(); it != m_impl->m_filterRules.end(); ++it) {
        if (it->second.ruleId == ruleId) {
            m_impl->m_filterRules.erase(it);
            // Invalidate cached compiled regex for this rule so a future
            // re-add with the same id cannot reuse a stale pattern.
            m_impl->m_compiledRuleRegex.erase(ruleId);
            SS_LOG_INFO(L"Network", L"DNSMonitor: Filter rule removed - ID: {}", ruleId);
            return true;
        }
    }

    return false;
}

bool DNSMonitor::BlockDomain(const std::string& domain, std::wstring_view reason) {
    if (!IsSyntacticDomain(domain)) return false;

    DNSFilterRule rule;
    rule.name = L"Auto-block";
    rule.description = reason.empty() ? L"Blocked domain" : std::wstring(reason);
    rule.domainPattern = NormalizeDomain(domain);
    rule.isRegex = false;
    rule.action = DNSFilterAction::BLOCK;
    rule.priority = 1;

    return AddFilterRule(rule) != 0;
}

bool DNSMonitor::UnblockDomain(const std::string& domain) {
    if (!IsSyntacticDomain(domain)) return false;
    const std::string norm = NormalizeDomain(domain);

    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    bool any = false;
    for (auto it = m_impl->m_filterRules.begin(); it != m_impl->m_filterRules.end();) {
        if (it->second.domainPattern == norm &&
            it->second.action == DNSFilterAction::BLOCK) {
            m_impl->m_compiledRuleRegex.erase(it->second.ruleId);
            it = m_impl->m_filterRules.erase(it);
            any = true;
        } else {
            ++it;
        }
    }

    return any;
}

bool DNSMonitor::SinkholeDomain(const std::string& domain, const std::string& sinkholeTo) {
    if (!IsSyntacticDomain(domain)) return false;
    // sinkholeTo is an IP/host; reject control bytes but otherwise pass through
    for (unsigned char c : sinkholeTo) {
        if (!IsLogSafeChar(c)) return false;
    }

    DNSFilterRule rule;
    rule.name = L"Sinkhole";
    rule.description = L"Sinkholed domain";
    rule.domainPattern = NormalizeDomain(domain);
    rule.isRegex = false;
    rule.action = DNSFilterAction::SINKHOLE;
    rule.sinkholeTo = sinkholeTo;
    rule.priority = 1;

    if (AddFilterRule(rule) == 0) return false;
    m_impl->m_statistics.domainsSinkholed.fetch_add(1, std::memory_order_relaxed);
    return true;
}

std::vector<DNSFilterRule> DNSMonitor::GetFilterRules() const {
    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    std::vector<DNSFilterRule> rules;
    rules.reserve(m_impl->m_filterRules.size());

    for (const auto& [key, rule] : m_impl->m_filterRules) {
        rules.push_back(rule);
    }

    return rules;
}

bool DNSMonitor::IsBlocked(const std::string& domain) const {
    if (!IsSyntacticDomain(domain)) return false;
    const std::string norm = NormalizeDomain(domain);

    std::lock_guard<std::mutex> lock(m_impl->m_rulesMutex);

    for (const auto& [key, rule] : m_impl->m_filterRules) {
        if (rule.isEnabled && m_impl->MatchRuleCached(rule, norm)) {
            if (rule.action == DNSFilterAction::BLOCK ||
                rule.action == DNSFilterAction::SINKHOLE) {
                return true;
            }
        }
    }

    return false;
}

// ============================================================================
// Cache Management
// ============================================================================

std::optional<DNSCacheEntry> DNSMonitor::QueryCache(const std::string& domain,
                                                     DNSRecordType recordType) const {
    if (!IsSyntacticDomain(domain)) return std::nullopt;
    const std::string norm = NormalizeDomain(domain);

    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);

    DNSMonitorImpl::CacheKey key{norm, recordType};
    auto it = m_impl->m_cache.find(key);

    if (it != m_impl->m_cache.end()) {
        const auto& entry = it->second;

        // Check expiration
        if (std::chrono::system_clock::now() <= entry.expiresAt) {
            m_impl->m_statistics.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return entry;
        }
    }

    m_impl->m_statistics.cacheMisses.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;
}

void DNSMonitor::AddCacheEntry(const DNSCacheEntry& entry) {
    if (!IsSyntacticDomain(entry.domain)) {
        return;
    }

    // Clamp the TTL derived from cachedAt/expiresAt before persisting,
    // so a hostile upstream cannot pin a poisoned record indefinitely
    // or churn the cache with sub-second entries.
    DNSCacheEntry safe = entry;
    safe.domain = NormalizeDomain(entry.domain);

    auto rawTtl = std::chrono::duration_cast<std::chrono::seconds>(
        safe.expiresAt - safe.cachedAt).count();
    const uint64_t rawTtlU = (rawTtl < 0) ? 0ULL : static_cast<uint64_t>(rawTtl);
    const uint32_t saturated = (rawTtlU > static_cast<uint64_t>(kMaxCacheTtlSec))
        ? kMaxCacheTtlSec
        : static_cast<uint32_t>(rawTtlU);
    const uint32_t clamped = ClampTtlSec(saturated);
    safe.ttl = clamped;
    safe.expiresAt = safe.cachedAt + std::chrono::seconds(clamped);

    std::unique_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);

    if (m_impl->m_cache.size() >= m_impl->m_config.maxCacheEntries) {
        // Simple eviction - remove oldest entry
        auto oldest = m_impl->m_cache.begin();
        for (auto it = m_impl->m_cache.begin(); it != m_impl->m_cache.end(); ++it) {
            if (it->second.cachedAt < oldest->second.cachedAt) {
                oldest = it;
            }
        }
        m_impl->m_cache.erase(oldest);
    }

    DNSMonitorImpl::CacheKey key{safe.domain, safe.recordType};
    m_impl->m_cache[key] = safe;

    m_impl->m_statistics.cacheSize.store(
        static_cast<uint32_t>(m_impl->m_cache.size()),
        std::memory_order_relaxed
    );
}

void DNSMonitor::InvalidateCache(const std::string& domain) {
    if (!IsSyntacticDomain(domain)) return;
    const std::string norm = NormalizeDomain(domain);

    std::unique_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);

    for (auto it = m_impl->m_cache.begin(); it != m_impl->m_cache.end();) {
        if (it->first.domain == norm) {
            it = m_impl->m_cache.erase(it);
        } else {
            ++it;
        }
    }
}

void DNSMonitor::FlushCache() {
    std::unique_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    m_impl->m_cache.clear();
    m_impl->m_statistics.cacheSize.store(0, std::memory_order_relaxed);
    SS_LOG_INFO(L"Network", L"DNSMonitor: Cache flushed");
}

size_t DNSMonitor::GetCacheSize() const noexcept {
    std::shared_lock<std::shared_mutex> lock(m_impl->m_cacheMutex);
    return m_impl->m_cache.size();
}

std::vector<DNSCacheEntry> DNSMonitor::InspectSystemCache() const {
    // Would use DnsGetCacheDataTable() API here in real implementation
    return {};
}

// ============================================================================
// Query History
// ============================================================================

std::vector<DNSQuery> DNSMonitor::GetRecentQueries(size_t maxCount,
                                                    std::optional<uint32_t> pid) const {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);

    std::vector<DNSQuery> queries;
    queries.reserve(std::min(maxCount, m_impl->m_queryHistory.size()));

    for (auto it = m_impl->m_queryHistory.rbegin();
         it != m_impl->m_queryHistory.rend() && queries.size() < maxCount;
         ++it) {
        if (!pid.has_value() || it->pid == *pid) {
            queries.push_back(*it);
        }
    }

    return queries;
}

std::vector<DNSQuery> DNSMonitor::GetQueriesForDomain(const std::string& domain) const {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);

    std::vector<DNSQuery> queries;

    for (const auto& query : m_impl->m_queryHistory) {
        if (query.domain == domain) {
            queries.push_back(query);
        }
    }

    return queries;
}

std::vector<std::pair<std::string, uint64_t>> DNSMonitor::GetTopDomains(size_t count) const {
    std::lock_guard<std::mutex> lock(m_impl->m_historyMutex);

    std::unordered_map<std::string, uint64_t> domainCounts;

    for (const auto& query : m_impl->m_queryHistory) {
        domainCounts[query.domain]++;
    }

    std::vector<std::pair<std::string, uint64_t>> topDomains(
        domainCounts.begin(), domainCounts.end()
    );

    std::sort(topDomains.begin(), topDomains.end(),
             [](const auto& a, const auto& b) { return a.second > b.second; });

    if (topDomains.size() > count) {
        topDomains.resize(count);
    }

    return topDomains;
}

// ============================================================================
// Callback Registration
// ============================================================================

uint64_t DNSMonitor::RegisterQueryCallback(DNSQueryCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_queryCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t DNSMonitor::RegisterResponseCallback(DNSResponseCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_responseCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t DNSMonitor::RegisterEventCallback(DNSEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_eventCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t DNSMonitor::RegisterDGACallback(DGADetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_dgaCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t DNSMonitor::RegisterTunnelingCallback(TunnelingDetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_tunnelingCallbacks.emplace_back(id, std::move(callback));
    return id;
}

uint64_t DNSMonitor::RegisterPoisoningCallback(PoisoningDetectionCallback callback) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);
    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_poisoningCallbacks.emplace_back(id, std::move(callback));
    return id;
}

bool DNSMonitor::UnregisterCallback(uint64_t callbackId) {
    std::lock_guard<std::mutex> lock(m_impl->m_callbacksMutex);

    auto removeById = [callbackId](auto& callbacks) {
        auto it = std::find_if(callbacks.begin(), callbacks.end(),
                              [callbackId](const auto& pair) { return pair.first == callbackId; });
        if (it != callbacks.end()) {
            callbacks.erase(it);
            return true;
        }
        return false;
    };

    return removeById(m_impl->m_queryCallbacks) ||
           removeById(m_impl->m_responseCallbacks) ||
           removeById(m_impl->m_eventCallbacks) ||
           removeById(m_impl->m_dgaCallbacks) ||
           removeById(m_impl->m_tunnelingCallbacks) ||
           removeById(m_impl->m_poisoningCallbacks);
}

// ============================================================================
// Statistics
// ============================================================================

const DNSStatistics& DNSMonitor::GetStatistics() const noexcept {
    return m_impl->m_statistics;
}

void DNSMonitor::ResetStatistics() noexcept {
    m_impl->m_statistics.Reset();
    SS_LOG_INFO(L"Network", L"DNSMonitor: Statistics reset");
}

// ============================================================================
// Diagnostics
// ============================================================================

bool DNSMonitor::PerformDiagnostics() const {
    try {
        SS_LOG_INFO(L"Network", L"DNSMonitor: Running diagnostics");

        // Check initialization
        if (!IsInitialized()) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Not initialized");
            return false;
        }

        // Check infrastructure
        if (!m_impl->m_threatIntel) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: ThreatIntel not initialized");
            return false;
        }

        SS_LOG_INFO(L"Network", L"DNSMonitor: Diagnostics passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Diagnostics failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
        return false;
    }
}

bool DNSMonitor::ExportDiagnostics(const std::wstring& outputPath) const {
    try {
        std::wofstream file(outputPath);
        if (!file.is_open()) {
            return false;
        }

        file << L"DNSMonitor Diagnostics\n";
        file << L"=====================\n\n";
        file << L"Initialized: " << (IsInitialized() ? L"Yes" : L"No") << L"\n";
        file << L"Running: " << (IsRunning() ? L"Yes" : L"No") << L"\n";
        file << L"Total Queries: " << m_impl->m_statistics.totalQueries.load() << L"\n";
        file << L"DGA Detections: " << m_impl->m_statistics.dgaDetections.load() << L"\n";
        file << L"Domains Blocked: " << m_impl->m_statistics.domainsBlocked.load() << L"\n";
        file << L"Cache Size: " << GetCacheSize() << L"\n";
        file << L"Filter Rules: " << GetFilterRules().size() << L"\n";

        file.close();
        return true;

    } catch (...) {
        return false;
    }
}

bool DNSMonitor::SelfTest() {
    try {
        SS_LOG_INFO(L"Network", L"DNSMonitor: Starting self-test");

        // Test DGA detection
        auto dgaAnalysis = AnalyzeDGA("qzxjv9kptd8r.com");
        if (!dgaAnalysis.isDGA) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: DGA detection test failed");
            return false;
        }

        // Test filtering
        BlockDomain("evil.com", L"Test");
        if (!IsBlocked("evil.com")) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Filtering test failed");
            return false;
        }
        UnblockDomain("evil.com");

        // Test cache
        DNSCacheEntry entry;
        entry.domain = "test.com";
        entry.recordType = DNSRecordType::A;
        entry.cachedAt = std::chrono::system_clock::now();
        entry.expiresAt = entry.cachedAt + std::chrono::seconds(300);
        AddCacheEntry(entry);

        auto cached = QueryCache("test.com", DNSRecordType::A);
        if (!cached.has_value()) {
            SS_LOG_ERROR(L"Network", L"DNSMonitor: Cache test failed");
            return false;
        }

        FlushCache();

        SS_LOG_INFO(L"Network", L"DNSMonitor: Self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(L"Network", L"DNSMonitor: Self-test failed - {}",
                            SanitizeNarrowToWideForLog(e.what()));
        return false;
    }
}

std::string DNSMonitor::GetVersionString() noexcept {
    return std::to_string(DNSConstants::VERSION_MAJOR) + "." +
           std::to_string(DNSConstants::VERSION_MINOR) + "." +
           std::to_string(DNSConstants::VERSION_PATCH);
}

// ============================================================================
// Utility Methods
// ============================================================================

double DNSMonitor::CalculateEntropy(std::string_view str) {
    if (str.empty()) return 0.0;

    std::unordered_map<char, int> charCounts;
    for (char c : str) {
        charCounts[c]++;
    }

    double entropy = 0.0;
    for (const auto& [ch, count] : charCounts) {
        double probability = static_cast<double>(count) / str.length();
        entropy -= probability * std::log2(probability);
    }

    return entropy;
}

std::string DNSMonitor::GetBaseDomain(const std::string& fqdn) {
    size_t lastDot = fqdn.find_last_of('.');
    if (lastDot == std::string::npos) {
        return fqdn;
    }

    size_t secondLastDot = fqdn.find_last_of('.', lastDot - 1);
    if (secondLastDot != std::string::npos) {
        return fqdn.substr(secondLastDot + 1);
    }

    return fqdn;
}

bool DNSMonitor::IsValidDomain(std::string_view domain) {
    if (domain.empty() || domain.length() > DNSConstants::MAX_DOMAIN_LENGTH) {
        return false;
    }

    // Basic validation
    if (domain.front() == '.' || domain.back() == '.') {
        return false;
    }

    // Check for valid characters
    for (char c : domain) {
        if (!std::isalnum(c) && c != '.' && c != '-' && c != '_') {
            return false;
        }
    }

    return true;
}

std::string_view DNSMonitor::GetRecordTypeName(DNSRecordType type) noexcept {
    return ::ShadowStrike::Core::Network::GetRecordTypeName(type);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string_view GetRecordTypeName(DNSRecordType type) noexcept {
    switch (type) {
        case DNSRecordType::A: return "A";
        case DNSRecordType::NS: return "NS";
        case DNSRecordType::CNAME: return "CNAME";
        case DNSRecordType::SOA: return "SOA";
        case DNSRecordType::PTR: return "PTR";
        case DNSRecordType::MX: return "MX";
        case DNSRecordType::TXT: return "TXT";
        case DNSRecordType::AAAA: return "AAAA";
        case DNSRecordType::SRV: return "SRV";
        case DNSRecordType::NAPTR: return "NAPTR";
        case DNSRecordType::DS: return "DS";
        case DNSRecordType::RRSIG: return "RRSIG";
        case DNSRecordType::NSEC: return "NSEC";
        case DNSRecordType::DNSKEY: return "DNSKEY";
        case DNSRecordType::NSEC3: return "NSEC3";
        case DNSRecordType::HTTPS: return "HTTPS";
        case DNSRecordType::ANY: return "ANY";
        case DNSRecordType::CAA: return "CAA";
        default: return "UNKNOWN";
    }
}

std::string_view GetResponseCodeName(DNSResponseCode code) noexcept {
    switch (code) {
        case DNSResponseCode::NOERROR: return "NOERROR";
        case DNSResponseCode::FORMERR: return "FORMERR";
        case DNSResponseCode::SERVFAIL: return "SERVFAIL";
        case DNSResponseCode::NXDOMAIN: return "NXDOMAIN";
        case DNSResponseCode::NOTIMP: return "NOTIMP";
        case DNSResponseCode::REFUSED: return "REFUSED";
        case DNSResponseCode::YXDOMAIN: return "YXDOMAIN";
        case DNSResponseCode::YXRRSET: return "YXRRSET";
        case DNSResponseCode::NXRRSET: return "NXRRSET";
        case DNSResponseCode::NOTAUTH: return "NOTAUTH";
        case DNSResponseCode::NOTZONE: return "NOTZONE";
        default: return "UNKNOWN";
    }
}

std::string_view GetProtocolName(DNSProtocol protocol) noexcept {
    switch (protocol) {
        case DNSProtocol::UDP: return "UDP";
        case DNSProtocol::TCP: return "TCP";
        case DNSProtocol::DOH: return "DOH";
        case DNSProtocol::DOT: return "DOT";
        case DNSProtocol::DOQ: return "DOQ";
        default: return "UNKNOWN";
    }
}

std::string_view GetDomainCategoryName(DomainCategory category) noexcept {
    switch (category) {
        case DomainCategory::UNKNOWN: return "Unknown";
        case DomainCategory::BENIGN: return "Benign";
        case DomainCategory::MALWARE: return "Malware";
        case DomainCategory::PHISHING: return "Phishing";
        case DomainCategory::C2: return "C2";
        case DomainCategory::SPAM: return "Spam";
        case DomainCategory::ADULT: return "Adult";
        case DomainCategory::GAMBLING: return "Gambling";
        case DomainCategory::CRYPTOMINING: return "CryptoMining";
        case DomainCategory::BOTNET: return "Botnet";
        case DomainCategory::RANSOMWARE: return "Ransomware";
        case DomainCategory::DGA: return "DGA";
        case DomainCategory::SINKHOLED: return "Sinkholed";
        case DomainCategory::PARKED: return "Parked";
        case DomainCategory::NEWLY_REGISTERED: return "NewlyRegistered";
        case DomainCategory::TYPOSQUATTING: return "Typosquatting";
        default: return "Unknown";
    }
}

std::string_view GetThreatTypeName(DNSThreatType threat) noexcept {
    switch (threat) {
        case DNSThreatType::NONE: return "None";
        case DNSThreatType::POISONING: return "Poisoning";
        case DNSThreatType::TUNNELING: return "Tunneling";
        case DNSThreatType::DGA_DOMAIN: return "DGA";
        case DNSThreatType::FAST_FLUX: return "FastFlux";
        case DNSThreatType::DOMAIN_SHADOWING: return "DomainShadowing";
        case DNSThreatType::REBINDING: return "Rebinding";
        case DNSThreatType::AMPLIFICATION: return "Amplification";
        case DNSThreatType::TYPOSQUATTING: return "Typosquatting";
        case DNSThreatType::KNOWN_BAD: return "KnownBad";
        default: return "Unknown";
    }
}

std::string_view GetDGAFamilyName(DGAFamily family) noexcept {
    switch (family) {
        case DGAFamily::UNKNOWN: return "Unknown";
        case DGAFamily::CONFICKER: return "Conficker";
        case DGAFamily::CRYPTOLOCKER: return "CryptoLocker";
        case DGAFamily::DYRE: return "Dyre";
        case DGAFamily::EMOTET: return "Emotet";
        case DGAFamily::GAMEOVER: return "GameOver";
        case DGAFamily::GOZI: return "Gozi";
        case DGAFamily::LOCKY: return "Locky";
        case DGAFamily::MATSNU: return "Matsnu";
        case DGAFamily::MUROFET: return "Murofet";
        case DGAFamily::NECURS: return "Necurs";
        case DGAFamily::NEWGOZ: return "NewGoz";
        case DGAFamily::NYMAIM: return "Nymaim";
        case DGAFamily::PADCRYPT: return "PadCrypt";
        case DGAFamily::PYKSPA: return "Pykspa";
        case DGAFamily::QAKBOT: return "Qakbot";
        case DGAFamily::RAMDO: return "Ramdo";
        case DGAFamily::RANBYUS: return "Ranbyus";
        case DGAFamily::RAMNIT: return "Ramnit";
        case DGAFamily::ROVNIX: return "Rovnix";
        case DGAFamily::SHIFU: return "Shifu";
        case DGAFamily::SIMDA: return "Simda";
        case DGAFamily::SISRON: return "Sisron";
        case DGAFamily::SUPPOBOX: return "Suppobox";
        case DGAFamily::SYMMI: return "Symmi";
        case DGAFamily::TINBA: return "TinBa";
        case DGAFamily::TORPIG: return "Torpig";
        case DGAFamily::URLZONE: return "URLZone";
        case DGAFamily::VAWTRAK: return "Vawtrak";
        case DGAFamily::VIRUT: return "Virut";
        default: return "Unknown";
    }
}

std::string_view GetFilterActionName(DNSFilterAction action) noexcept {
    switch (action) {
        case DNSFilterAction::ALLOW: return "Allow";
        case DNSFilterAction::BLOCK: return "Block";
        case DNSFilterAction::SINKHOLE: return "Sinkhole";
        case DNSFilterAction::LOG_ONLY: return "LogOnly";
        case DNSFilterAction::REDIRECT: return "Redirect";
        case DNSFilterAction::DELAY: return "Delay";
        default: return "Unknown";
    }
}

std::string_view GetValidationResultName(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::VALID: return "Valid";
        case ValidationResult::INVALID: return "Invalid";
        case ValidationResult::SPOOFED: return "Spoofed";
        case ValidationResult::TIMEOUT: return "Timeout";
        case ValidationResult::MISMATCH: return "Mismatch";
        case ValidationResult::DNSSEC_FAIL: return "DNSSECFail";
        case ValidationResult::ERROR: return "Error";
        default: return "Unknown";
    }
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
