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
 * ShadowStrike NGAV - SAFE BROWSING API IMPLEMENTATION
 * ============================================================================
 *
 * @file SafeBrowsingAPI.cpp
 * @brief Enterprise-grade Safe Browsing API implementation with multi-tier
 *        caching and threat intelligence integration.
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
#include "SafeBrowsingAPI.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelLookup.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/NetworkUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"

#include <shared_mutex>
#include <mutex>
#include <unordered_map>
#include <list>
#include <atomic>
#include <thread>
#include <future>
#include <queue>
#include <condition_variable>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>

// JSON library
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace WebBrowser {

using namespace Utils;
using namespace ThreatIntel;
using json = nlohmann::json;

template<typename T>
[[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
    return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
}

template<typename T>
void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
    std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
}

// ============================================================================
// LOGGING MACROS
// ============================================================================

#define SB_LOG_INFO(fmt, ...)    Logger::Info("SafeBrowsingAPI: " fmt, ##__VA_ARGS__)
#define SB_LOG_WARN(fmt, ...)    Logger::Warn("SafeBrowsingAPI: " fmt, ##__VA_ARGS__)
#define SB_LOG_ERROR(fmt, ...)   Logger::Error("SafeBrowsingAPI: " fmt, ##__VA_ARGS__)
#define SB_LOG_DEBUG(fmt, ...)   Logger::Debug("SafeBrowsingAPI: " fmt, ##__VA_ARGS__)

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

[[nodiscard]] bool ContainsUnsafeUrlText(std::string_view value) noexcept {
    return std::any_of(value.begin(), value.end(), [](unsigned char c) {
        return c < 0x20 || c == 0x7F;
    });
}

[[nodiscard]] bool IsValidDomainLabelCharacter(char c) noexcept {
    const unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) != 0 || c == '.' || c == '-';
}

[[nodiscard]] bool IsSafeDomainInput(std::string_view value) noexcept {
    if (value.empty() || value.size() > 253 || ContainsUnsafeUrlText(value)) {
        return false;
    }

    if (value.find("://") != std::string_view::npos ||
        value.find('/') != std::string_view::npos ||
        value.find('\\') != std::string_view::npos ||
        value.find('@') != std::string_view::npos ||
        value.front() == '.' || value.front() == '-') {
        return false;
    }

    bool lastWasDot = true;
    for (char c : value) {
        if (!IsValidDomainLabelCharacter(c)) {
            return false;
        }

        if (c == '.') {
            if (lastWasDot) {
                return false;
            }
            lastWasDot = true;
            continue;
        }

        lastWasDot = false;
    }

    return !lastWasDot;
}

std::string_view GetSeverityName(ThreatSeverity severity) noexcept {
    switch (severity) {
        case ThreatSeverity::None:      return "None";
        case ThreatSeverity::Low:       return "Low";
        case ThreatSeverity::Medium:    return "Medium";
        case ThreatSeverity::High:      return "High";
        case ThreatSeverity::Critical:  return "Critical";
        default:                        return "Unknown";
    }
}

std::string_view GetLookupSourceName(LookupSource source) noexcept {
    switch (source) {
        case LookupSource::Cache:           return "Cache";
        case LookupSource::LocalDatabase:   return "LocalDatabase";
        case LookupSource::ThreatIntel:     return "ThreatIntel";
        case LookupSource::ExternalAPI:     return "ExternalAPI";
        case LookupSource::Heuristic:       return "Heuristic";
        default:                            return "Unknown";
    }
}

std::string_view GetStatusName(SafeBrowsingStatus status) noexcept {
    switch (status) {
        case SafeBrowsingStatus::Uninitialized: return "Uninitialized";
        case SafeBrowsingStatus::Initializing:  return "Initializing";
        case SafeBrowsingStatus::Running:       return "Running";
        case SafeBrowsingStatus::Degraded:      return "Degraded";
        case SafeBrowsingStatus::Stopped:       return "Stopped";
        case SafeBrowsingStatus::Error:         return "Error";
        default:                                return "Unknown";
    }
}

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

bool SafeBrowsingConfig::IsValid() const noexcept {
    if (maxCacheEntries == 0 && enableLocalCache) return false;
    if (minConfidenceThreshold > 100) return false;
    if (lookupTimeout.count() <= 0) return false;
    return true;
}

std::string SafeBrowsingConfig::ToJson() const {
    json j;
    j["enableRealTimeProtection"] = enableRealTimeProtection;
    j["enableLocalCache"] = enableLocalCache;
    j["maxCacheEntries"] = maxCacheEntries;
    j["cacheTTL"] = cacheTTL.count();
    j["blockSuspicious"] = blockSuspicious;
    j["blockKnownMalware"] = blockKnownMalware;
    j["enablePhishingProtection"] = enablePhishingProtection;
    j["enablePUADetection"] = enablePUADetection;
    j["minConfidenceThreshold"] = minConfidenceThreshold;
    j["enableAsyncLookups"] = enableAsyncLookups;
    j["lookupTimeout"] = lookupTimeout.count();
    j["failClosed"] = failClosed;
    j["enableCloudLookups"] = enableCloudLookups;
    j["enableTelemetry"] = enableTelemetry;
    j["verboseLogging"] = verboseLogging;
    return j.dump();
}

bool SafeBrowsingResult::ShouldBlock() const noexcept {
    return isMalicious || isPhishing || (isSuspicious && confidence >= 80);
}

bool SafeBrowsingResult::ShouldWarn() const noexcept {
    return isSuspicious || isPUA;
}

std::string SafeBrowsingResult::ToJson() const {
    json j;
    j["isSafe"] = isSafe;
    j["isMalicious"] = isMalicious;
    j["isSuspicious"] = isSuspicious;
    j["isPhishing"] = isPhishing;
    j["isPUA"] = isPUA;
    j["category"] = static_cast<int>(category);
    j["reputation"] = static_cast<int>(reputation);
    j["severity"] = static_cast<int>(severity);
    j["threatName"] = threatName;
    j["threatFamily"] = threatFamily;
    j["details"] = details;
    j["confidence"] = confidence;
    j["threatScore"] = threatScore;
    j["source"] = std::string(GetLookupSourceName(source));
    j["latencyUs"] = latencyUs;
    j["checkTime"] = std::chrono::system_clock::to_time_t(checkTime);

    if (!mitreTechniques.empty()) {
        j["mitreTechniques"] = mitreTechniques;
    }
    if (!relatedIOCs.empty()) {
        j["relatedIOCs"] = relatedIOCs;
    }

    return j.dump();
}

std::string BatchLookupResult::ToJson() const {
    json j;
    j["totalLatencyUs"] = totalLatencyUs;
    j["cacheHits"] = cacheHits;
    j["threatsFound"] = threatsFound;
    j["resultCount"] = results.size();

    json resultsArray = json::array();
    for (const auto& r : results) {
        resultsArray.push_back(json::parse(r.ToJson()));
    }
    j["results"] = resultsArray;

    return j.dump();
}

void SafeBrowsingStatistics::Reset() noexcept {
    totalLookups = 0;
    urlLookups = 0;
    hashLookups = 0;
    domainLookups = 0;
    cacheHits = 0;
    cacheMisses = 0;
    maliciousDetected = 0;
    suspiciousDetected = 0;
    phishingDetected = 0;
    puaDetected = 0;
    totalBlocked = 0;
    lookupErrors = 0;
    totalProcessingTimeUs = 0;
    AtomicValueStoreRelaxed(startTime, std::chrono::steady_clock::now());
}

double SafeBrowsingStatistics::GetCacheHitRatio() const noexcept {
    uint64_t total = cacheHits.load() + cacheMisses.load();
    if (total == 0) return 0.0;
    return static_cast<double>(cacheHits.load()) / static_cast<double>(total);
}

double SafeBrowsingStatistics::GetAverageLookupTimeUs() const noexcept {
    uint64_t lookups = totalLookups.load();
    if (lookups == 0) return 0.0;
    return static_cast<double>(totalProcessingTimeUs.load()) / static_cast<double>(lookups);
}

double SafeBrowsingStatistics::GetLookupsPerSecond() const noexcept {
    auto elapsed = std::chrono::steady_clock::now() - AtomicValueLoadRelaxed(startTime);
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
    if (seconds == 0) return 0.0;
    return static_cast<double>(totalLookups.load()) / static_cast<double>(seconds);
}

std::string SafeBrowsingStatistics::ToJson() const {
    json j;
    j["totalLookups"] = totalLookups.load();
    j["urlLookups"] = urlLookups.load();
    j["hashLookups"] = hashLookups.load();
    j["domainLookups"] = domainLookups.load();
    j["cacheHits"] = cacheHits.load();
    j["cacheMisses"] = cacheMisses.load();
    j["cacheHitRatio"] = GetCacheHitRatio();
    j["maliciousDetected"] = maliciousDetected.load();
    j["suspiciousDetected"] = suspiciousDetected.load();
    j["phishingDetected"] = phishingDetected.load();
    j["puaDetected"] = puaDetected.load();
    j["totalBlocked"] = totalBlocked.load();
    j["lookupErrors"] = lookupErrors.load();
    j["averageLookupTimeUs"] = GetAverageLookupTimeUs();
    j["lookupsPerSecond"] = GetLookupsPerSecond();

    auto elapsed = std::chrono::steady_clock::now() - AtomicValueLoadRelaxed(startTime);
    j["uptimeSeconds"] = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

    return j.dump();
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class SafeBrowsingAPIImpl {
public:
    SafeBrowsingAPIImpl() {
        m_stats.Reset();
    }

    ~SafeBrowsingAPIImpl() {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const SafeBrowsingConfig& config, ThreatIntelLookup* lookup) {
        std::unique_lock lock(m_mutex);

        if (m_status.load(std::memory_order_acquire) == SafeBrowsingStatus::Running) {
            SB_LOG_WARN("Already initialized");
            return true;
        }

        m_status.store(SafeBrowsingStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            SB_LOG_ERROR("Invalid configuration");
            m_status.store(SafeBrowsingStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;
        if (m_config.enableCloudLookups) {
            SB_LOG_WARN("Cloud lookup opt-in requested, but Community tier has no external Safe Browsing client; forcing local-only mode");
            m_config.enableCloudLookups = false;
        } else {
            SB_LOG_INFO("Cloud lookup path remains disabled (Community default)");
        }

        // Set up threat intelligence integration
        if (lookup) {
            m_threatLookup.store(lookup, std::memory_order_release);
            m_ownsLookup = false;
            SB_LOG_INFO("Using provided ThreatIntelLookup instance");
        } else {
            m_threatLookup.store(nullptr, std::memory_order_release);
            m_ownsLookup = false;
            SB_LOG_WARN("No ThreatIntelLookup available - running in degraded mode");
            m_status.store(SafeBrowsingStatus::Degraded, std::memory_order_release);
        }

        // Initialize caches (must hold cache mutex separately).
        if (m_config.enableLocalCache) {
            std::unique_lock cacheLock(m_cacheMutex);
            ClearCacheInternal();
            SB_LOG_INFO("Cache initialized with max size: {}", m_config.maxCacheEntries);
        }

        if (m_status.load(std::memory_order_acquire) != SafeBrowsingStatus::Degraded) {
            m_status.store(SafeBrowsingStatus::Running, std::memory_order_release);
        }

        SB_LOG_INFO("SafeBrowsingAPI initialized successfully (Status: {})",
                    GetStatusName(m_status.load(std::memory_order_acquire)));
        return true;
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_mutex);

            const SafeBrowsingStatus cur = m_status.load(std::memory_order_acquire);
            if (cur == SafeBrowsingStatus::Stopped ||
                cur == SafeBrowsingStatus::Uninitialized) {
                return;
            }

            // Clear caches under the cache mutex (separate from m_mutex).
            {
                std::unique_lock cacheLock(m_cacheMutex);
                ClearCacheInternal();
            }

            // Clear callbacks
            {
                std::unique_lock cbLock(m_callbackMutex);
                m_threatCallbacks.clear();
            }

            // Always drop the ThreatIntelLookup pointer, whether we owned it
            // or not. The caller may destroy their lookup right after Shutdown
            // returns, so any pointer left in m_threatLookup would dangle.
            m_threatLookup.store(nullptr, std::memory_order_release);
            m_ownsLookup = false;

            m_status.store(SafeBrowsingStatus::Stopped, std::memory_order_release);
        }

        WaitForCallbackTasks();
        SB_LOG_INFO("SafeBrowsingAPI shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        const SafeBrowsingStatus s = m_status.load(std::memory_order_acquire);
        return s == SafeBrowsingStatus::Running ||
               s == SafeBrowsingStatus::Degraded;
    }

    [[nodiscard]] SafeBrowsingStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    // ========================================================================
    // URL CHECKING
    // ========================================================================

    [[nodiscard]] SafeBrowsingResult CheckUrl(std::string_view url) {
        auto startTime = std::chrono::steady_clock::now();

        SafeBrowsingResult result;
        result.checkTime = std::chrono::system_clock::now();

        // Input validation
        if (url.empty()) {
            result.details = "Empty URL";
            m_stats.lookupErrors++;
            return result;
        }

        if (url.length() > SafeBrowsingConstants::MAX_URL_LENGTH) {
            result.details = "URL exceeds maximum length";
            m_stats.lookupErrors++;
            return result;
        }

        if (ContainsUnsafeUrlText(url)) {
            result.details = "URL contains control characters";
            m_stats.lookupErrors++;
            return result;
        }

        // Snapshot config under shared_lock so concurrent UpdateConfig cannot
        // tear reads of failClosed / cacheTTL / thresholds during this lookup.
        SafeBrowsingConfig cfg;
        SafeBrowsingStatus status;
        {
            std::shared_lock lock(m_mutex);
            cfg = m_config;
            status = m_status.load(std::memory_order_acquire);
        }

        if (status != SafeBrowsingStatus::Running && status != SafeBrowsingStatus::Degraded) {
            result.isSafe = !cfg.failClosed;
            result.details = "SafeBrowsingAPI not active";
            m_stats.lookupErrors++;
            return result;
        }

        std::string urlStr(url);

        // Normalize URL for consistent caching
        std::string normalizedUrl = NormalizeUrl(urlStr);

        m_stats.totalLookups++;
        m_stats.urlLookups++;

        // 1. Check local cache
        if (cfg.enableLocalCache) {
            if (auto cached = GetFromCache(normalizedUrl)) {
                m_stats.cacheHits++;
                cached->source = LookupSource::Cache;
                cached->latencyUs = GetElapsedUs(startTime);
                m_stats.totalProcessingTimeUs += cached->latencyUs;
                return *cached;
            }
            m_stats.cacheMisses++;
        }

        // 2. Perform threat intelligence lookup
        ThreatIntelLookup* lookup = m_threatLookup.load(std::memory_order_acquire);
        if (lookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;
                options.minConfidence = static_cast<uint8_t>(cfg.minConfidenceThreshold);

                auto tiResult = lookup->LookupURL(normalizedUrl, options);
                MapThreatResultToSafeBrowsing(tiResult, result, cfg);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("ThreatIntel lookup failed: {}", e.what());
                m_stats.lookupErrors++;

                // Fail-closed or fail-open based on config
                if (cfg.failClosed) {
                    result.isSafe = false;
                    result.isSuspicious = true;
                    result.details = "Lookup failed - blocking due to fail-closed policy";
                } else {
                    result.isSafe = true;
                    result.details = "Lookup failed - allowing due to fail-open policy";
                }
            }
        } else {
            // Degraded mode - no threat intel available
            result.isSafe = true;
            result.details = "No threat intelligence available";
        }

        // 3. Apply heuristic checks
        ApplyHeuristics(urlStr, result);

        // 4. Update statistics
        UpdateStatistics(result);

        // 5. Cache the result
        if (cfg.enableLocalCache) {
            AddToCache(normalizedUrl, result, cfg);
        }

        // 6. Notify callbacks if threat detected
        if (!result.isSafe) {
            NotifyThreatCallbacks(urlStr, result);
        }

        result.latencyUs = GetElapsedUs(startTime);
        m_stats.totalProcessingTimeUs += result.latencyUs;

        if (cfg.verboseLogging) {
            SB_LOG_DEBUG("URL check: {} -> Safe={}, Latency={} us",
                        urlStr, result.isSafe, result.latencyUs);
        }

        return result;
    }

    [[nodiscard]] std::future<SafeBrowsingResult> CheckUrlAsync(std::string url) {
        return std::async(std::launch::async, [this, u = std::move(url)]() {
            return this->CheckUrl(u);
        });
    }

    void CheckUrlWithCallback(std::string url, LookupCompleteCallback callback) {
        ReapCompletedCallbackTasks();
        std::lock_guard taskLock(m_callbackTaskMutex);
        m_callbackTasks.emplace_back(std::async(std::launch::async,
            [this, u = std::move(url), cb = std::move(callback)]() mutable {
                try {
                    auto result = this->CheckUrl(u);
                    if (cb) {
                        cb(result);
                    }
                } catch (const std::exception& e) {
                    SB_LOG_ERROR("Async callback lookup failed: {}", e.what());
                } catch (...) {
                    SB_LOG_ERROR("Async callback lookup failed with unknown exception");
                }
            }));
    }

    [[nodiscard]] BatchLookupResult CheckUrls(std::span<const std::string> urls) {
        auto startTime = std::chrono::steady_clock::now();
        BatchLookupResult batchResult;

        if (urls.size() > SafeBrowsingConstants::MAX_BATCH_SIZE) {
            SB_LOG_WARN("Batch size {} exceeds maximum {}, truncating",
                        urls.size(), SafeBrowsingConstants::MAX_BATCH_SIZE);
        }

        size_t count = std::min(urls.size(), SafeBrowsingConstants::MAX_BATCH_SIZE);
        batchResult.results.reserve(count);

        for (size_t i = 0; i < count; ++i) {
            auto result = CheckUrl(urls[i]);

            if (result.source == LookupSource::Cache) {
                batchResult.cacheHits++;
            }
            if (!result.isSafe) {
                batchResult.threatsFound++;
            }

            batchResult.results.push_back(std::move(result));
        }

        batchResult.totalLatencyUs = GetElapsedUs(startTime);
        return batchResult;
    }

    [[nodiscard]] std::future<BatchLookupResult> CheckUrlsAsync(std::vector<std::string> urls) {
        return std::async(std::launch::async, [this, u = std::move(urls)]() {
            return this->CheckUrls(std::span<const std::string>(u));
        });
    }

    // ========================================================================
    // DOMAIN CHECKING
    // ========================================================================

    [[nodiscard]] SafeBrowsingResult CheckDomain(std::string_view domain) {
        auto startTime = std::chrono::steady_clock::now();

        SafeBrowsingResult result;
        result.checkTime = std::chrono::system_clock::now();

        if (domain.empty()) {
            result.details = "Empty domain";
            m_stats.lookupErrors++;
            return result;
        }

        if (!IsSafeDomainInput(domain)) {
            result.details = "Invalid domain";
            m_stats.lookupErrors++;
            return result;
        }

        SafeBrowsingConfig cfg;
        SafeBrowsingStatus status;
        {
            std::shared_lock lock(m_mutex);
            cfg = m_config;
            status = m_status.load(std::memory_order_acquire);
        }

        if (status != SafeBrowsingStatus::Running && status != SafeBrowsingStatus::Degraded) {
            result.isSafe = !cfg.failClosed;
            result.details = "SafeBrowsingAPI not active";
            m_stats.lookupErrors++;
            return result;
        }

        std::string domainStr(domain);

        // Normalize domain
        std::transform(domainStr.begin(), domainStr.end(), domainStr.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        m_stats.totalLookups++;
        m_stats.domainLookups++;

        // Check cache
        std::string cacheKey = "domain:" + domainStr;
        if (cfg.enableLocalCache) {
            if (auto cached = GetFromCache(cacheKey)) {
                m_stats.cacheHits++;
                cached->source = LookupSource::Cache;
                cached->latencyUs = GetElapsedUs(startTime);
                m_stats.totalProcessingTimeUs += cached->latencyUs;
                return *cached;
            }
            m_stats.cacheMisses++;
        }

        // Perform lookup
        ThreatIntelLookup* lookup = m_threatLookup.load(std::memory_order_acquire);
        if (lookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;

                auto tiResult = lookup->LookupDomain(domainStr, options);
                MapThreatResultToSafeBrowsing(tiResult, result, cfg);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("Domain lookup failed: {}", e.what());
                m_stats.lookupErrors++;
                result.isSafe = !cfg.failClosed;
            }
        }

        // Apply domain-specific heuristics
        ApplyDomainHeuristics(domainStr, result);

        UpdateStatistics(result);

        if (cfg.enableLocalCache) {
            AddToCache(cacheKey, result, cfg);
        }

        result.latencyUs = GetElapsedUs(startTime);
        m_stats.totalProcessingTimeUs += result.latencyUs;

        return result;
    }

    [[nodiscard]] BatchLookupResult CheckDomains(std::span<const std::string> domains) {
        auto startTime = std::chrono::steady_clock::now();
        BatchLookupResult batchResult;
        batchResult.results.reserve(domains.size());

        for (const auto& domain : domains) {
            auto result = CheckDomain(domain);

            if (result.source == LookupSource::Cache) {
                batchResult.cacheHits++;
            }
            if (!result.isSafe) {
                batchResult.threatsFound++;
            }

            batchResult.results.push_back(std::move(result));
        }

        batchResult.totalLatencyUs = GetElapsedUs(startTime);
        return batchResult;
    }

    // ========================================================================
    // HASH CHECKING
    // ========================================================================

    [[nodiscard]] SafeBrowsingResult CheckHash(std::string_view hash) {
        auto startTime = std::chrono::steady_clock::now();

        SafeBrowsingResult result;
        result.checkTime = std::chrono::system_clock::now();

        if (hash.empty()) {
            result.details = "Empty hash";
            m_stats.lookupErrors++;
            return result;
        }

        if (hash.length() > SafeBrowsingConstants::MAX_HASH_LENGTH) {
            result.details = "Hash exceeds maximum length";
            m_stats.lookupErrors++;
            return result;
        }

        // Validate hash is pure hex and has a length matching a known digest
        // (MD5=32, SHA1=40, SHA256=64). Rejecting non-hex up front prevents
        // attacker-controlled cache poisoning via arbitrary string keys and
        // shields the downstream ThreatIntelLookup from malformed input.
        if (hash.length() != 32 && hash.length() != 40 && hash.length() != 64) {
            result.details = "Hash has unsupported length";
            m_stats.lookupErrors++;
            return result;
        }
        for (char c : hash) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (!((uc >= '0' && uc <= '9') ||
                  (uc >= 'a' && uc <= 'f') ||
                  (uc >= 'A' && uc <= 'F'))) {
                result.details = "Hash contains non-hex characters";
                m_stats.lookupErrors++;
                return result;
            }
        }

        SafeBrowsingConfig cfg;
        SafeBrowsingStatus status;
        {
            std::shared_lock lock(m_mutex);
            cfg = m_config;
            status = m_status.load(std::memory_order_acquire);
        }

        if (status != SafeBrowsingStatus::Running && status != SafeBrowsingStatus::Degraded) {
            result.isSafe = !cfg.failClosed;
            result.details = "SafeBrowsingAPI not active";
            m_stats.lookupErrors++;
            return result;
        }

        std::string hashStr(hash);

        // Normalize hash (lowercase). Cast via unsigned char to avoid
        // signed-char undefined behaviour and the implicit-narrowing warning
        // from the bare ::tolower function pointer.
        std::transform(hashStr.begin(), hashStr.end(), hashStr.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        m_stats.totalLookups++;
        m_stats.hashLookups++;

        // Check cache
        std::string cacheKey = "hash:" + hashStr;
        if (cfg.enableLocalCache) {
            if (auto cached = GetFromCache(cacheKey)) {
                m_stats.cacheHits++;
                cached->source = LookupSource::Cache;
                cached->latencyUs = GetElapsedUs(startTime);
                m_stats.totalProcessingTimeUs += cached->latencyUs;
                return *cached;
            }
            m_stats.cacheMisses++;
        }

        // Perform lookup
        ThreatIntelLookup* lookup = m_threatLookup.load(std::memory_order_acquire);
        if (lookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;

                auto tiResult = lookup->LookupHash(hashStr, options);
                MapThreatResultToSafeBrowsing(tiResult, result, cfg);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("Hash lookup failed: {}", e.what());
                m_stats.lookupErrors++;
                result.isSafe = !cfg.failClosed;
            }
        }

        UpdateStatistics(result);

        if (cfg.enableLocalCache) {
            AddToCache(cacheKey, result, cfg);
        }

        result.latencyUs = GetElapsedUs(startTime);
        m_stats.totalProcessingTimeUs += result.latencyUs;

        return result;
    }

    [[nodiscard]] BatchLookupResult CheckHashes(std::span<const std::string> hashes) {
        auto startTime = std::chrono::steady_clock::now();
        BatchLookupResult batchResult;
        batchResult.results.reserve(hashes.size());

        for (const auto& hash : hashes) {
            auto result = CheckHash(hash);

            if (result.source == LookupSource::Cache) {
                batchResult.cacheHits++;
            }
            if (!result.isSafe) {
                batchResult.threatsFound++;
            }

            batchResult.results.push_back(std::move(result));
        }

        batchResult.totalLatencyUs = GetElapsedUs(startTime);
        return batchResult;
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool UpdateConfig(const SafeBrowsingConfig& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            SB_LOG_ERROR("Invalid configuration");
            return false;
        }

        m_config = config;

        // Clear cache if disabled. Must acquire the cache mutex; m_mutex does
        // not protect cache contents.
        if (!m_config.enableLocalCache) {
            std::unique_lock cacheLock(m_cacheMutex);
            ClearCacheInternal();
        }

        SB_LOG_INFO("Configuration updated");
        return true;
    }

    [[nodiscard]] SafeBrowsingConfig GetConfig() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void ClearCache() {
        std::unique_lock lock(m_cacheMutex);
        ClearCacheInternal();
    }

    [[nodiscard]] size_t GetCacheSize() const noexcept {
        std::shared_lock lock(m_cacheMutex);
        return m_cache.size();
    }

    void PreloadCache(std::span<const std::string> urls) {
        // Bound the preload to prevent an attacker (or a misconfigured caller)
        // from forcing an unbounded number of synchronous lookups in a single
        // call, which would otherwise saturate the threat-intel pipeline.
        constexpr size_t kPreloadCap = 4096;
        const size_t count = std::min(urls.size(), kPreloadCap);
        if (urls.size() > kPreloadCap) {
            SB_LOG_WARN("PreloadCache truncated from {} to {} entries", urls.size(), kPreloadCap);
        }
        SB_LOG_INFO("Preloading {} URLs into cache", count);

        for (size_t i = 0; i < count; ++i) {
            (void)CheckUrl(urls[i]);
        }

        SB_LOG_INFO("Cache preload complete");
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatDetectedCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId++;
        m_threatCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterThreatCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        m_threatCallbacks.erase(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] SafeBrowsingStatistics GetStatistics() const {
        // Return a copy of atomic values
        SafeBrowsingStatistics stats;
        stats.totalLookups = m_stats.totalLookups.load();
        stats.urlLookups = m_stats.urlLookups.load();
        stats.hashLookups = m_stats.hashLookups.load();
        stats.domainLookups = m_stats.domainLookups.load();
        stats.cacheHits = m_stats.cacheHits.load();
        stats.cacheMisses = m_stats.cacheMisses.load();
        stats.maliciousDetected = m_stats.maliciousDetected.load();
        stats.suspiciousDetected = m_stats.suspiciousDetected.load();
        stats.phishingDetected = m_stats.phishingDetected.load();
        stats.puaDetected = m_stats.puaDetected.load();
        stats.totalBlocked = m_stats.totalBlocked.load();
        stats.lookupErrors = m_stats.lookupErrors.load();
        stats.totalProcessingTimeUs = m_stats.totalProcessingTimeUs.load();
        AtomicValueStoreRelaxed(stats.startTime, AtomicValueLoadRelaxed(m_stats.startTime));
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
    }

    [[nodiscard]] std::string GetStatisticsJson() const {
        return GetStatistics().ToJson();
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] bool SelfTest() {
        SB_LOG_INFO("Running self-test...");

        // Test 1: Check initialization
        if (!IsInitialized()) {
            SB_LOG_ERROR("Self-test failed: Not initialized");
            return false;
        }

        // Test 2: Check URL parsing
        SafeBrowsingResult result = CheckUrl("https://example.com/test");
        if (result.checkTime == SystemTimePoint{}) {
            SB_LOG_ERROR("Self-test failed: URL check failed");
            return false;
        }

        // Test 3: Check cache operations
        bool cacheEnabled;
        {
            std::shared_lock lock(m_mutex);
            cacheEnabled = m_config.enableLocalCache;
        }
        if (cacheEnabled) {
            std::string testUrl = "https://selftest.example.com/test123";
            (void)CheckUrl(testUrl);  // First call - cache miss
            (void)CheckUrl(testUrl);  // Second call - should be cache hit

            if (m_stats.cacheHits.load() == 0) {
                SB_LOG_ERROR("Self-test failed: Cache not working");
                return false;
            }
        }

        // Test 4: Check statistics
        if (m_stats.totalLookups.load() == 0) {
            SB_LOG_ERROR("Self-test failed: Statistics not tracking");
            return false;
        }

        SB_LOG_INFO("Self-test passed");
        return true;
    }

private:
    // ========================================================================
    // INTERNAL TYPES
    // ========================================================================

    struct CacheEntry {
        SafeBrowsingResult result;
        SteadyTimePoint expiration;
    };

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::mutex m_callbackTaskMutex;

    // m_status is read lock-free from IsInitialized()/GetStatus() (both
    // noexcept and called from hot paths). Make it atomic so concurrent
    // Initialize/Shutdown publish state without tearing.
    std::atomic<SafeBrowsingStatus> m_status{SafeBrowsingStatus::Uninitialized};
    SafeBrowsingConfig m_config;

    // ThreatIntelLookup is owned by the caller (we never delete it). Storing as
    // an atomic guarantees the pointer is published/cleared atomically across
    // Initialize/Shutdown and any concurrent CheckXxx caller, so we cannot tear
    // a partial write and cannot read a stale pointer after Shutdown.
    std::atomic<ThreatIntelLookup*> m_threatLookup{nullptr};
    bool m_ownsLookup{false};

    // LRU Cache
    std::unordered_map<std::string,
        std::list<std::pair<std::string, CacheEntry>>::iterator> m_cache;
    std::list<std::pair<std::string, CacheEntry>> m_lruList;

    // Callbacks
    std::unordered_map<uint64_t, ThreatDetectedCallback> m_threatCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::vector<std::future<void>> m_callbackTasks;

    // Statistics
    mutable SafeBrowsingStatistics m_stats;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    [[nodiscard]] uint64_t GetElapsedUs(SteadyTimePoint startTime) const {
        auto endTime = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime).count();
    }

    [[nodiscard]] std::string NormalizeUrl(const std::string& url) const {
        std::string normalized = url;

        // 1. Drop fragment: phishing payloads commonly stuff junk after '#' so
        //    https://evil.com/login#a and https://evil.com/login#b
        //    must collapse to the same cache key.
        auto hashPos = normalized.find('#');
        if (hashPos != std::string::npos) {
            normalized.erase(hashPos);
        }

        // 2. Lowercase scheme and authority. We only lowercase up to the
        //    path so query strings (which are case-sensitive in many backends)
        //    are preserved.
        size_t protocolEnd = normalized.find("://");
        size_t authorityEnd = std::string::npos;
        if (protocolEnd != std::string::npos) {
            size_t authStart = protocolEnd + 3;
            size_t pathStart = normalized.find('/', authStart);
            size_t queryStart = normalized.find('?', authStart);
            authorityEnd = std::min(pathStart, queryStart);
            if (authorityEnd == std::string::npos) {
                authorityEnd = normalized.length();
            }

            // 3. Strip RFC 3986 userinfo from the authority. Failing to do
            //    this lets "https://paypal.com@evil.com/" produce a cache key
            //    distinct from "https://evil.com/" and lets it slip past
            //    threat-intel domain lookups that hash on the host alone.
            auto at = normalized.find('@', authStart);
            if (at != std::string::npos && at < authorityEnd) {
                normalized.erase(authStart, (at - authStart) + 1);
                authorityEnd -= (at - authStart) + 1;
            }

            std::transform(normalized.begin(), normalized.begin() + authorityEnd,
                          normalized.begin(),
                          [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }

        // 4. Remove trailing slash from the path (but never from the bare
        //    authority — "https://evil.com/" already has the slash directly
        //    after authority, which we keep as-is).
        if (normalized.size() > 1 && normalized.back() == '/') {
            // Only strip if there is actually a path beyond the authority.
            if (authorityEnd != std::string::npos &&
                authorityEnd < normalized.size() - 1) {
                normalized.pop_back();
            }
        }

        return normalized;
    }

    void MapThreatResultToSafeBrowsing(const ThreatLookupResult& tiResult,
                                       SafeBrowsingResult& result,
                                       const SafeBrowsingConfig& cfg) {
        result.isSafe = tiResult.IsSafe();
        result.isMalicious = tiResult.IsMalicious();
        result.isSuspicious = tiResult.IsSuspicious();
        result.category = tiResult.category;
        result.reputation = tiResult.reputation;
        result.confidence = static_cast<uint8_t>(tiResult.confidence);
        result.threatScore = tiResult.threatScore;

        // Map category to flags
        if (tiResult.category == ThreatCategory::Phishing) {
            result.isPhishing = true;
        }
        if (tiResult.category == ThreatCategory::Adware ||
            tiResult.category == ThreatCategory::Spyware) {
            result.isPUA = true;
        }

        // Map to severity
        if (result.isMalicious) {
            result.severity = ThreatSeverity::High;
            if (tiResult.category == ThreatCategory::Ransomware ||
                tiResult.category == ThreatCategory::APT) {
                result.severity = ThreatSeverity::Critical;
            }
        } else if (result.isSuspicious) {
            result.severity = ThreatSeverity::Medium;
        } else if (result.isPUA) {
            result.severity = ThreatSeverity::Low;
        }

        // Extract threat details from the IOC entry
        if (tiResult.entry.has_value()) {
            result.threatName = tiResult.description;
            result.threatFamily = std::string(ThreatCategoryToString(tiResult.category));

            if (tiResult.entry->firstSeen > 0) {
                result.firstSeen = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(tiResult.entry->firstSeen));
            }
            if (tiResult.entry->lastSeen > 0) {
                result.lastSeen = std::chrono::system_clock::from_time_t(
                    static_cast<time_t>(tiResult.entry->lastSeen));
            }
        }

        // Apply configuration-based blocking
        if (result.isMalicious && cfg.blockKnownMalware) {
            result.isSafe = false;
        }
        if (result.isSuspicious && cfg.blockSuspicious &&
            result.confidence >= cfg.minConfidenceThreshold) {
            result.isSafe = false;
        }
        if (result.isPhishing && cfg.enablePhishingProtection) {
            result.isSafe = false;
        }
        if (result.isPUA && cfg.enablePUADetection) {
            result.isSafe = false;
        }
    }

    void ApplyHeuristics(const std::string& url, SafeBrowsingResult& result) {
        // Suspicious URL patterns
        static const std::vector<std::regex> suspiciousPatterns = {
            std::regex(R"(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", std::regex::icase),  // IP address
            std::regex(R"(https?://[^/]*@)", std::regex::icase),  // Credentials in URL
            std::regex(R"(\.(exe|scr|bat|cmd|ps1|vbs|js)\?)", std::regex::icase),  // Executable with params
            std::regex(R"(data:text/html)", std::regex::icase),  // Data URL
        };

        for (const auto& pattern : suspiciousPatterns) {
            if (std::regex_search(url, pattern)) {
                if (!result.isSuspicious) {
                    result.isSuspicious = true;
                    result.source = LookupSource::Heuristic;
                    result.details += "Suspicious URL pattern detected. ";
                }
                break;
            }
        }

        // Check for obfuscation
        if (url.find("%00") != std::string::npos ||
            url.find("%2e%2e") != std::string::npos ||
            url.find("..%2f") != std::string::npos) {
            result.isSuspicious = true;
            result.details += "URL obfuscation detected. ";
        }

        // Check for extremely long URLs
        if (url.length() > 2048) {
            result.isSuspicious = true;
            result.details += "Abnormally long URL. ";
        }
    }

    void ApplyDomainHeuristics(const std::string& domain, SafeBrowsingResult& result) {
        // Check for suspicious TLDs
        static const std::vector<std::string> suspiciousTLDs = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work"
        };

        for (const auto& tld : suspiciousTLDs) {
            if (domain.length() >= tld.length() &&
                domain.compare(domain.length() - tld.length(), tld.length(), tld) == 0) {
                if (!result.isSuspicious) {
                    result.isSuspicious = true;
                    result.severity = ThreatSeverity::Low;
                    result.source = LookupSource::Heuristic;
                    result.details += "Suspicious TLD detected. ";
                }
                break;
            }
        }

        // Check for homograph attacks (mixed scripts)
        bool hasAscii = false;
        bool hasNonAscii = false;
        for (char c : domain) {
            if (static_cast<unsigned char>(c) < 128) {
                hasAscii = true;
            } else {
                hasNonAscii = true;
            }
        }

        if (hasAscii && hasNonAscii) {
            result.isSuspicious = true;
            result.details += "Potential homograph attack (mixed character sets). ";
        }

        // Check for excessive subdomains
        size_t dotCount = std::count(domain.begin(), domain.end(), '.');
        if (dotCount > 4) {
            result.isSuspicious = true;
            result.details += "Excessive subdomain depth. ";
        }
    }

    void UpdateStatistics(const SafeBrowsingResult& result) {
        if (result.isMalicious) {
            m_stats.maliciousDetected++;
            m_stats.totalBlocked++;
        }
        if (result.isSuspicious) {
            m_stats.suspiciousDetected++;
        }
        if (result.isPhishing) {
            m_stats.phishingDetected++;
        }
        if (result.isPUA) {
            m_stats.puaDetected++;
        }
    }

    void NotifyThreatCallbacks(const std::string& url, const SafeBrowsingResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_threatCallbacks) {
            try {
                callback(url, result);
            } catch (const std::exception& e) {
                SB_LOG_ERROR("Callback {} threw exception: {}", id, e.what());
            }
        }
    }

    void ReapCompletedCallbackTasks() {
        std::lock_guard taskLock(m_callbackTaskMutex);
        auto it = m_callbackTasks.begin();
        while (it != m_callbackTasks.end()) {
            if (it->valid() &&
                it->wait_for(std::chrono::seconds(0)) == std::future_status::ready) {
                it->wait();
                it = m_callbackTasks.erase(it);
                continue;
            }
            ++it;
        }
    }

    void WaitForCallbackTasks() {
        std::vector<std::future<void>> tasks;
        {
            std::lock_guard taskLock(m_callbackTaskMutex);
            tasks.swap(m_callbackTasks);
        }

        for (auto& task : tasks) {
            if (task.valid()) {
                task.wait();
            }
        }
    }

    [[nodiscard]] std::optional<SafeBrowsingResult> GetFromCache(const std::string& key) {
        std::unique_lock lock(m_cacheMutex);

        auto it = m_cache.find(key);
        if (it == m_cache.end()) {
            return std::nullopt;
        }

        // Check expiration
        if (std::chrono::steady_clock::now() > it->second->second.expiration) {
            m_lruList.erase(it->second);
            m_cache.erase(it);
            return std::nullopt;
        }

        // Move to front (LRU)
        m_lruList.splice(m_lruList.begin(), m_lruList, it->second);

        return it->second->second.result;
    }

    void AddToCache(const std::string& key, const SafeBrowsingResult& result,
                    const SafeBrowsingConfig& cfg) {
        std::unique_lock lock(m_cacheMutex);

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            // Update existing
            it->second->second.result = result;
            it->second->second.expiration =
                std::chrono::steady_clock::now() + cfg.cacheTTL;
            m_lruList.splice(m_lruList.begin(), m_lruList, it->second);
            return;
        }

        // Evict if full
        while (m_cache.size() >= cfg.maxCacheEntries && !m_lruList.empty()) {
            auto last = m_lruList.end();
            --last;
            m_cache.erase(last->first);
            m_lruList.pop_back();
        }

        // Add new
        CacheEntry entry;
        entry.result = result;
        entry.expiration = std::chrono::steady_clock::now() + cfg.cacheTTL;

        m_lruList.push_front({key, entry});
        m_cache[key] = m_lruList.begin();
    }

    void ClearCacheInternal() {
        m_cache.clear();
        m_lruList.clear();
    }
};

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> SafeBrowsingAPI::s_instanceCreated{false};

// ============================================================================
// SAFEBROWSINGAPI FACADE IMPLEMENTATION
// ============================================================================

SafeBrowsingAPI& SafeBrowsingAPI::Instance() noexcept {
    static SafeBrowsingAPI instance;
    return instance;
}

bool SafeBrowsingAPI::HasInstance() noexcept {
    return s_instanceCreated.load();
}

SafeBrowsingAPI::SafeBrowsingAPI()
    : m_impl(std::make_unique<SafeBrowsingAPIImpl>()) {
    s_instanceCreated.store(true);
}

SafeBrowsingAPI::~SafeBrowsingAPI() {
    s_instanceCreated.store(false);
}

bool SafeBrowsingAPI::Initialize(const SafeBrowsingConfig& config,
                                  ThreatIntelLookup* threatLookup) {
    return m_impl->Initialize(config, threatLookup);
}

void SafeBrowsingAPI::Shutdown() {
    m_impl->Shutdown();
}

bool SafeBrowsingAPI::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

SafeBrowsingStatus SafeBrowsingAPI::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

SafeBrowsingResult SafeBrowsingAPI::CheckUrl(std::string_view url) {
    return m_impl->CheckUrl(url);
}

std::future<SafeBrowsingResult> SafeBrowsingAPI::CheckUrlAsync(std::string url) {
    return m_impl->CheckUrlAsync(std::move(url));
}

void SafeBrowsingAPI::CheckUrlWithCallback(std::string url, LookupCompleteCallback callback) {
    m_impl->CheckUrlWithCallback(std::move(url), std::move(callback));
}

BatchLookupResult SafeBrowsingAPI::CheckUrls(std::span<const std::string> urls) {
    return m_impl->CheckUrls(urls);
}

std::future<BatchLookupResult> SafeBrowsingAPI::CheckUrlsAsync(std::vector<std::string> urls) {
    return m_impl->CheckUrlsAsync(std::move(urls));
}

SafeBrowsingResult SafeBrowsingAPI::CheckDomain(std::string_view domain) {
    return m_impl->CheckDomain(domain);
}

BatchLookupResult SafeBrowsingAPI::CheckDomains(std::span<const std::string> domains) {
    return m_impl->CheckDomains(domains);
}

SafeBrowsingResult SafeBrowsingAPI::CheckHash(std::string_view hash) {
    return m_impl->CheckHash(hash);
}

BatchLookupResult SafeBrowsingAPI::CheckHashes(std::span<const std::string> hashes) {
    return m_impl->CheckHashes(hashes);
}

bool SafeBrowsingAPI::UpdateConfig(const SafeBrowsingConfig& config) {
    return m_impl->UpdateConfig(config);
}

SafeBrowsingConfig SafeBrowsingAPI::GetConfig() const {
    return m_impl->GetConfig();
}

void SafeBrowsingAPI::ClearCache() {
    m_impl->ClearCache();
}

size_t SafeBrowsingAPI::GetCacheSize() const noexcept {
    return m_impl->GetCacheSize();
}

void SafeBrowsingAPI::PreloadCache(std::span<const std::string> urls) {
    m_impl->PreloadCache(urls);
}

uint64_t SafeBrowsingAPI::RegisterThreatCallback(ThreatDetectedCallback callback) {
    return m_impl->RegisterThreatCallback(std::move(callback));
}

void SafeBrowsingAPI::UnregisterThreatCallback(uint64_t callbackId) {
    m_impl->UnregisterThreatCallback(callbackId);
}

SafeBrowsingStatistics SafeBrowsingAPI::GetStatistics() const {
    return m_impl->GetStatistics();
}

void SafeBrowsingAPI::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::string SafeBrowsingAPI::GetStatisticsJson() const {
    return m_impl->GetStatisticsJson();
}

bool SafeBrowsingAPI::SelfTest() {
    return m_impl->SelfTest();
}

std::string SafeBrowsingAPI::GetVersionString() noexcept {
    return std::to_string(SafeBrowsingConstants::VERSION_MAJOR) + "." +
           std::to_string(SafeBrowsingConstants::VERSION_MINOR) + "." +
           std::to_string(SafeBrowsingConstants::VERSION_PATCH);
}

}  // namespace WebBrowser
}  // namespace ShadowStrike

