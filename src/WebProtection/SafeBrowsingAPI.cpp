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
#include "../ThreatIntel/ThreatIntelLookup.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/HashUtils.hpp"

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
    startTime = std::chrono::steady_clock::now();
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
    auto elapsed = std::chrono::steady_clock::now() - startTime;
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

    auto elapsed = std::chrono::steady_clock::now() - startTime;
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

        if (m_status == SafeBrowsingStatus::Running) {
            SB_LOG_WARN("Already initialized");
            return true;
        }

        m_status = SafeBrowsingStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            SB_LOG_ERROR("Invalid configuration");
            m_status = SafeBrowsingStatus::Error;
            return false;
        }

        m_config = config;

        // Set up threat intelligence integration
        if (lookup) {
            m_threatLookup = lookup;
            m_ownsLookup = false;
            SB_LOG_INFO("Using provided ThreatIntelLookup instance");
        } else {
            // Try to get the global ThreatIntelLookup instance
            if (ThreatIntelLookup::HasInstance()) {
                m_threatLookup = &ThreatIntelLookup::Instance();
                m_ownsLookup = false;
                SB_LOG_INFO("Using global ThreatIntelLookup instance");
            } else {
                m_threatLookup = nullptr;
                m_ownsLookup = false;
                SB_LOG_WARN("No ThreatIntelLookup available - running in degraded mode");
                m_status = SafeBrowsingStatus::Degraded;
            }
        }

        // Initialize caches
        if (m_config.enableLocalCache) {
            ClearCacheInternal();
            SB_LOG_INFO("Cache initialized with max size: %zu", m_config.maxCacheEntries);
        }

        if (m_status != SafeBrowsingStatus::Degraded) {
            m_status = SafeBrowsingStatus::Running;
        }

        SB_LOG_INFO("SafeBrowsingAPI initialized successfully (Status: %s)",
                    std::string(GetStatusName(m_status)).c_str());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);

        if (m_status == SafeBrowsingStatus::Stopped ||
            m_status == SafeBrowsingStatus::Uninitialized) {
            return;
        }

        // Clear caches
        ClearCacheInternal();

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_threatCallbacks.clear();
        }

        if (m_ownsLookup && m_threatLookup) {
            m_threatLookup = nullptr;
        }

        m_status = SafeBrowsingStatus::Stopped;
        SB_LOG_INFO("SafeBrowsingAPI shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == SafeBrowsingStatus::Running ||
               m_status == SafeBrowsingStatus::Degraded;
    }

    [[nodiscard]] SafeBrowsingStatus GetStatus() const noexcept {
        return m_status;
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

        std::string urlStr(url);

        // Normalize URL for consistent caching
        std::string normalizedUrl = NormalizeUrl(urlStr);

        m_stats.totalLookups++;
        m_stats.urlLookups++;

        // 1. Check local cache
        if (m_config.enableLocalCache) {
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
        if (m_threatLookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;
                options.confidenceThreshold = m_config.minConfidenceThreshold;

                auto tiResult = m_threatLookup->LookupURL(normalizedUrl, options);
                MapThreatResultToSafeBrowsing(tiResult, result);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("ThreatIntel lookup failed: %s", e.what());
                m_stats.lookupErrors++;

                // Fail-closed or fail-open based on config
                if (m_config.failClosed) {
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
        if (m_config.enableLocalCache) {
            AddToCache(normalizedUrl, result);
        }

        // 6. Notify callbacks if threat detected
        if (!result.isSafe) {
            NotifyThreatCallbacks(urlStr, result);
        }

        result.latencyUs = GetElapsedUs(startTime);
        m_stats.totalProcessingTimeUs += result.latencyUs;

        if (m_config.verboseLogging) {
            SB_LOG_DEBUG("URL check: %s -> Safe=%d, Latency=%llu us",
                        urlStr.c_str(), result.isSafe, result.latencyUs);
        }

        return result;
    }

    [[nodiscard]] std::future<SafeBrowsingResult> CheckUrlAsync(std::string url) {
        return std::async(std::launch::async, [this, u = std::move(url)]() {
            return this->CheckUrl(u);
        });
    }

    void CheckUrlWithCallback(std::string url, LookupCompleteCallback callback) {
        std::thread([this, u = std::move(url), cb = std::move(callback)]() {
            auto result = this->CheckUrl(u);
            if (cb) {
                cb(result);
            }
        }).detach();
    }

    [[nodiscard]] BatchLookupResult CheckUrls(std::span<const std::string> urls) {
        auto startTime = std::chrono::steady_clock::now();
        BatchLookupResult batchResult;

        if (urls.size() > SafeBrowsingConstants::MAX_BATCH_SIZE) {
            SB_LOG_WARN("Batch size %zu exceeds maximum %zu, truncating",
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

        std::string domainStr(domain);

        // Normalize domain
        std::transform(domainStr.begin(), domainStr.end(), domainStr.begin(), ::tolower);

        m_stats.totalLookups++;
        m_stats.domainLookups++;

        // Check cache
        std::string cacheKey = "domain:" + domainStr;
        if (m_config.enableLocalCache) {
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
        if (m_threatLookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;

                auto tiResult = m_threatLookup->LookupDomain(domainStr, options);
                MapThreatResultToSafeBrowsing(tiResult, result);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("Domain lookup failed: %s", e.what());
                m_stats.lookupErrors++;
                result.isSafe = !m_config.failClosed;
            }
        }

        // Apply domain-specific heuristics
        ApplyDomainHeuristics(domainStr, result);

        UpdateStatistics(result);

        if (m_config.enableLocalCache) {
            AddToCache(cacheKey, result);
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

        std::string hashStr(hash);

        // Normalize hash (lowercase)
        std::transform(hashStr.begin(), hashStr.end(), hashStr.begin(), ::tolower);

        m_stats.totalLookups++;
        m_stats.hashLookups++;

        // Check cache
        std::string cacheKey = "hash:" + hashStr;
        if (m_config.enableLocalCache) {
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
        if (m_threatLookup) {
            try {
                UnifiedLookupOptions options;
                options.includeMetadata = true;

                auto tiResult = m_threatLookup->LookupHash(hashStr, options);
                MapThreatResultToSafeBrowsing(tiResult, result);
                result.source = LookupSource::ThreatIntel;
            } catch (const std::exception& e) {
                SB_LOG_ERROR("Hash lookup failed: %s", e.what());
                m_stats.lookupErrors++;
                result.isSafe = !m_config.failClosed;
            }
        }

        UpdateStatistics(result);

        if (m_config.enableLocalCache) {
            AddToCache(cacheKey, result);
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

        // Clear cache if disabled
        if (!m_config.enableLocalCache) {
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
        SB_LOG_INFO("Preloading %zu URLs into cache", urls.size());

        for (const auto& url : urls) {
            CheckUrl(url);
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
        stats.startTime = m_stats.startTime;
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
        if (m_config.enableLocalCache) {
            std::string testUrl = "https://selftest.example.com/test123";
            CheckUrl(testUrl);  // First call - cache miss
            CheckUrl(testUrl);  // Second call - should be cache hit

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
    mutable std::mutex m_callbackMutex;

    SafeBrowsingStatus m_status{SafeBrowsingStatus::Uninitialized};
    SafeBrowsingConfig m_config;

    ThreatIntelLookup* m_threatLookup{nullptr};
    bool m_ownsLookup{false};

    // LRU Cache
    std::unordered_map<std::string,
        std::list<std::pair<std::string, CacheEntry>>::iterator> m_cache;
    std::list<std::pair<std::string, CacheEntry>> m_lruList;

    // Callbacks
    std::unordered_map<uint64_t, ThreatDetectedCallback> m_threatCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{1};

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

        // Remove trailing slash
        if (!normalized.empty() && normalized.back() == '/') {
            normalized.pop_back();
        }

        // Lowercase protocol and domain
        size_t protocolEnd = normalized.find("://");
        if (protocolEnd != std::string::npos) {
            size_t pathStart = normalized.find('/', protocolEnd + 3);
            size_t domainEnd = (pathStart != std::string::npos) ? pathStart : normalized.length();

            std::transform(normalized.begin(), normalized.begin() + domainEnd,
                          normalized.begin(), ::tolower);
        }

        return normalized;
    }

    void MapThreatResultToSafeBrowsing(const ThreatLookupResult& tiResult,
                                       SafeBrowsingResult& result) {
        result.isSafe = tiResult.IsSafe();
        result.isMalicious = tiResult.IsMalicious();
        result.isSuspicious = tiResult.IsSuspicious();
        result.category = tiResult.category;
        result.reputation = tiResult.reputation;
        result.confidence = static_cast<uint8_t>(tiResult.confidence);
        result.threatScore = static_cast<uint8_t>(tiResult.threatScore);

        // Map category to flags
        if (tiResult.category == ThreatCategory::Phishing) {
            result.isPhishing = true;
        }
        if (tiResult.category == ThreatCategory::PUA ||
            tiResult.category == ThreatCategory::Adware) {
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

        // Extract threat details
        if (tiResult.entry) {
            result.threatName = tiResult.entry->threatName;
            result.threatFamily = tiResult.entry->threatFamily;

            if (tiResult.entry->firstSeen.time_since_epoch().count() > 0) {
                result.firstSeen = tiResult.entry->firstSeen;
            }
            if (tiResult.entry->lastSeen.time_since_epoch().count() > 0) {
                result.lastSeen = tiResult.entry->lastSeen;
            }
        }

        // Apply configuration-based blocking
        if (result.isMalicious && m_config.blockKnownMalware) {
            result.isSafe = false;
        }
        if (result.isSuspicious && m_config.blockSuspicious &&
            result.confidence >= m_config.minConfidenceThreshold) {
            result.isSafe = false;
        }
        if (result.isPhishing && m_config.enablePhishingProtection) {
            result.isSafe = false;
        }
        if (result.isPUA && m_config.enablePUADetection) {
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
                SB_LOG_ERROR("Callback %llu threw exception: %s", id, e.what());
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

    void AddToCache(const std::string& key, const SafeBrowsingResult& result) {
        std::unique_lock lock(m_cacheMutex);

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            // Update existing
            it->second->second.result = result;
            it->second->second.expiration =
                std::chrono::steady_clock::now() + m_config.cacheTTL;
            m_lruList.splice(m_lruList.begin(), m_lruList, it->second);
            return;
        }

        // Evict if full
        while (m_cache.size() >= m_config.maxCacheEntries && !m_lruList.empty()) {
            auto last = m_lruList.end();
            --last;
            m_cache.erase(last->first);
            m_lruList.pop_back();
        }

        // Add new
        CacheEntry entry;
        entry.result = result;
        entry.expiration = std::chrono::steady_clock::now() + m_config.cacheTTL;

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
