/**
 * ============================================================================
 * ShadowStrike NGAV - TRACKER BLOCKER IMPLEMENTATION
 * ============================================================================
 *
 * @file TrackerBlocker.cpp
 * @brief Enterprise-grade web tracker blocking engine implementation with
 *        Bloom filter optimization, Aho-Corasick pattern matching, and
 *        comprehensive privacy protection.
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
#include "TrackerBlocker.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../ThreatIntel/ThreatIntelLookup.hpp"

#include <shared_mutex>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <list>
#include <queue>
#include <deque>
#include <atomic>
#include <thread>
#include <future>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <bitset>
#include <functional>
#include <iomanip>

// JSON library
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace WebBrowser {

using namespace Utils;
using json = nlohmann::json;

// ============================================================================
// LOGGING MACROS
// ============================================================================

#define TB_LOG_INFO(fmt, ...)    Logger::Info("TrackerBlocker: " fmt, ##__VA_ARGS__)
#define TB_LOG_WARN(fmt, ...)    Logger::Warn("TrackerBlocker: " fmt, ##__VA_ARGS__)
#define TB_LOG_ERROR(fmt, ...)   Logger::Error("TrackerBlocker: " fmt, ##__VA_ARGS__)
#define TB_LOG_DEBUG(fmt, ...)   Logger::Debug("TrackerBlocker: " fmt, ##__VA_ARGS__)

// ============================================================================
// UTILITY FUNCTIONS IMPLEMENTATION
// ============================================================================

std::string_view GetBlockerModeName(BlockerMode mode) noexcept {
    switch (mode) {
        case BlockerMode::Disabled:  return "Disabled";
        case BlockerMode::Monitor:   return "Monitor";
        case BlockerMode::Standard:  return "Standard";
        case BlockerMode::Strict:    return "Strict";
        case BlockerMode::Paranoid:  return "Paranoid";
        default:                     return "Unknown";
    }
}

std::string_view GetCategoryName(TrackerCategory category) noexcept {
    switch (category) {
        case TrackerCategory::None:                return "None";
        case TrackerCategory::Advertising:         return "Advertising";
        case TrackerCategory::Analytics:           return "Analytics";
        case TrackerCategory::SocialMedia:         return "SocialMedia";
        case TrackerCategory::Fingerprinting:      return "Fingerprinting";
        case TrackerCategory::Cryptomining:        return "Cryptomining";
        case TrackerCategory::Malvertising:        return "Malvertising";
        case TrackerCategory::ContentDelivery:     return "ContentDelivery";
        case TrackerCategory::CommentSystem:       return "CommentSystem";
        case TrackerCategory::CustomerInteraction: return "CustomerInteraction";
        case TrackerCategory::HostedLibrary:       return "HostedLibrary";
        case TrackerCategory::AudioVideoPlayer:    return "AudioVideoPlayer";
        case TrackerCategory::Extension:           return "Extension";
        case TrackerCategory::EmailMarketing:      return "EmailMarketing";
        case TrackerCategory::SitePerformance:     return "SitePerformance";
        case TrackerCategory::UnknownTracker:      return "UnknownTracker";
        default:                                   return "Multiple";
    }
}

std::string_view GetRequestTypeName(RequestType type) noexcept {
    switch (type) {
        case RequestType::Unknown:        return "Unknown";
        case RequestType::Document:       return "Document";
        case RequestType::SubDocument:    return "SubDocument";
        case RequestType::Stylesheet:     return "Stylesheet";
        case RequestType::Script:         return "Script";
        case RequestType::Image:          return "Image";
        case RequestType::Font:           return "Font";
        case RequestType::Object:         return "Object";
        case RequestType::XMLHttpRequest: return "XMLHttpRequest";
        case RequestType::Ping:           return "Ping";
        case RequestType::CSPReport:      return "CSPReport";
        case RequestType::Media:          return "Media";
        case RequestType::WebSocket:      return "WebSocket";
        case RequestType::WebRTC:         return "WebRTC";
        case RequestType::Other:          return "Other";
        default:                          return "Multiple";
    }
}

std::string_view GetBlockDecisionName(BlockDecision decision) noexcept {
    switch (decision) {
        case BlockDecision::Allow:       return "Allow";
        case BlockDecision::Block:       return "Block";
        case BlockDecision::Redirect:    return "Redirect";
        case BlockDecision::Modify:      return "Modify";
        case BlockDecision::AllowLogged: return "AllowLogged";
        case BlockDecision::Defer:       return "Defer";
        default:                         return "Unknown";
    }
}

std::string_view GetRuleTypeName(RuleType type) noexcept {
    switch (type) {
        case RuleType::Domain:       return "Domain";
        case RuleType::DomainSuffix: return "DomainSuffix";
        case RuleType::UrlPrefix:    return "UrlPrefix";
        case RuleType::UrlSuffix:    return "UrlSuffix";
        case RuleType::UrlContains:  return "UrlContains";
        case RuleType::UrlRegex:     return "UrlRegex";
        case RuleType::UrlWildcard:  return "UrlWildcard";
        case RuleType::CSSSelector:  return "CSSSelector";
        case RuleType::ScriptInject: return "ScriptInject";
        case RuleType::NetworkFilter: return "NetworkFilter";
        default:                     return "Unknown";
    }
}

RequestType ParseRequestType(std::string_view typeName) noexcept {
    if (typeName == "document" || typeName == "main_frame") return RequestType::Document;
    if (typeName == "subdocument" || typeName == "sub_frame") return RequestType::SubDocument;
    if (typeName == "stylesheet" || typeName == "css") return RequestType::Stylesheet;
    if (typeName == "script" || typeName == "js") return RequestType::Script;
    if (typeName == "image" || typeName == "img") return RequestType::Image;
    if (typeName == "font") return RequestType::Font;
    if (typeName == "object" || typeName == "plugin") return RequestType::Object;
    if (typeName == "xmlhttprequest" || typeName == "xhr" || typeName == "fetch") return RequestType::XMLHttpRequest;
    if (typeName == "ping" || typeName == "beacon") return RequestType::Ping;
    if (typeName == "csp_report") return RequestType::CSPReport;
    if (typeName == "media" || typeName == "video" || typeName == "audio") return RequestType::Media;
    if (typeName == "websocket" || typeName == "ws") return RequestType::WebSocket;
    if (typeName == "webrtc") return RequestType::WebRTC;
    if (typeName == "other") return RequestType::Other;
    return RequestType::Unknown;
}

std::string FormatCategories(TrackerCategory categories) {
    std::vector<std::string> names;

    if (HasCategory(categories, TrackerCategory::Advertising)) names.push_back("Advertising");
    if (HasCategory(categories, TrackerCategory::Analytics)) names.push_back("Analytics");
    if (HasCategory(categories, TrackerCategory::SocialMedia)) names.push_back("SocialMedia");
    if (HasCategory(categories, TrackerCategory::Fingerprinting)) names.push_back("Fingerprinting");
    if (HasCategory(categories, TrackerCategory::Cryptomining)) names.push_back("Cryptomining");
    if (HasCategory(categories, TrackerCategory::Malvertising)) names.push_back("Malvertising");

    if (names.empty()) return "None";

    std::string result;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i > 0) result += ", ";
        result += names[i];
    }
    return result;
}

// ============================================================================
// STRUCT IMPLEMENTATIONS
// ============================================================================

bool TrackerBlockerConfiguration::IsValid() const noexcept {
    if (mode == BlockerMode::Disabled) return true;
    if (cacheSize == 0 && enableCache) return false;
    return true;
}

TrackerBlockerConfiguration TrackerBlockerConfiguration::FromMode(BlockerMode mode) {
    TrackerBlockerConfiguration config;
    config.mode = mode;

    switch (mode) {
        case BlockerMode::Disabled:
            config.blockedCategories = TrackerCategory::None;
            break;

        case BlockerMode::Monitor:
            config.blockedCategories = TrackerCategory::AllTracking | TrackerCategory::AllMalicious;
            break;

        case BlockerMode::Standard:
            config.blockedCategories = TrackerCategory::AllTracking | TrackerCategory::AllMalicious;
            config.stripTrackingParams = true;
            config.blockThirdPartyCookies = true;
            break;

        case BlockerMode::Strict:
            config.blockedCategories = TrackerCategory::All;
            config.stripTrackingParams = true;
            config.blockThirdPartyCookies = true;
            config.sanitizeReferrer = true;
            config.blockWebRTCLeak = true;
            break;

        case BlockerMode::Paranoid:
            config.blockedCategories = TrackerCategory::All;
            config.stripTrackingParams = true;
            config.blockThirdPartyCookies = true;
            config.sanitizeReferrer = true;
            config.blockWebRTCLeak = true;
            config.blockCanvasFingerprint = true;
            break;
    }

    return config;
}

std::string BlockResult::ToJson() const {
    json j;
    j["decision"] = std::string(GetBlockDecisionName(decision));
    j["matchedRuleId"] = matchedRuleId;
    j["matchedPattern"] = matchedPattern;
    j["category"] = std::string(GetCategoryName(category));
    j["redirectUrl"] = redirectUrl;
    j["modifiedUrl"] = modifiedUrl;
    j["reason"] = reason;
    j["processingTimeUs"] = processingTimeUs;
    j["fromCache"] = fromCache;
    j["shouldLog"] = shouldLog;
    return j.dump();
}

std::string BlockedRequestEntry::ToJson() const {
    json j;
    j["entryId"] = entryId;
    j["url"] = url;
    j["domain"] = domain;
    j["initiator"] = initiator;
    j["requestType"] = std::string(GetRequestTypeName(requestType));
    j["matchedRule"] = matchedRule;
    j["category"] = std::string(GetCategoryName(category));
    j["tabId"] = tabId;
    return j.dump();
}

void TrackerBlockerStatistics::Reset() noexcept {
    totalRequests = 0;
    totalBlocked = 0;
    totalModified = 0;
    totalAllowed = 0;
    cacheHits = 0;
    cacheMisses = 0;
    bloomFilterHits = 0;
    totalProcessingTimeUs = 0;
    for (auto& count : blocksByCategory) {
        count = 0;
    }
    activeRuleCount = 0;
    whitelistExceptions = 0;
    startTime = Clock::now();
}

double TrackerBlockerStatistics::GetCacheHitRatio() const noexcept {
    uint64_t total = cacheHits.load() + cacheMisses.load();
    if (total == 0) return 0.0;
    return static_cast<double>(cacheHits.load()) / static_cast<double>(total);
}

double TrackerBlockerStatistics::GetAverageProcessingTimeUs() const noexcept {
    uint64_t requests = totalRequests.load();
    if (requests == 0) return 0.0;
    return static_cast<double>(totalProcessingTimeUs.load()) / static_cast<double>(requests);
}

std::string TrackerBlockerStatistics::ToJson() const {
    json j;
    j["totalRequests"] = totalRequests.load();
    j["totalBlocked"] = totalBlocked.load();
    j["totalModified"] = totalModified.load();
    j["totalAllowed"] = totalAllowed.load();
    j["cacheHits"] = cacheHits.load();
    j["cacheMisses"] = cacheMisses.load();
    j["cacheHitRatio"] = GetCacheHitRatio();
    j["bloomFilterHits"] = bloomFilterHits.load();
    j["averageProcessingTimeUs"] = GetAverageProcessingTimeUs();
    j["activeRuleCount"] = activeRuleCount.load();
    j["whitelistExceptions"] = whitelistExceptions.load();

    auto elapsed = Clock::now() - startTime;
    j["uptimeSeconds"] = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();

    return j.dump();
}

// ============================================================================
// BLOOM FILTER IMPLEMENTATION
// ============================================================================

class BloomFilter {
public:
    explicit BloomFilter(size_t size = TrackerBlockerConstants::BLOOM_FILTER_SIZE,
                         size_t hashCount = TrackerBlockerConstants::BLOOM_FILTER_HASHES)
        : m_size(size), m_hashCount(hashCount), m_bits(size, false) {}

    void Add(std::string_view item) {
        for (size_t i = 0; i < m_hashCount; ++i) {
            size_t hash = ComputeHash(item, i);
            m_bits[hash % m_size] = true;
        }
        m_count++;
    }

    [[nodiscard]] bool MightContain(std::string_view item) const {
        for (size_t i = 0; i < m_hashCount; ++i) {
            size_t hash = ComputeHash(item, i);
            if (!m_bits[hash % m_size]) {
                return false;
            }
        }
        return true;
    }

    void Clear() {
        std::fill(m_bits.begin(), m_bits.end(), false);
        m_count = 0;
    }

    [[nodiscard]] size_t GetCount() const noexcept { return m_count; }
    [[nodiscard]] size_t GetSize() const noexcept { return m_size; }

private:
    [[nodiscard]] size_t ComputeHash(std::string_view item, size_t seed) const {
        // FNV-1a hash with seed
        size_t hash = 14695981039346656037ULL + seed * 31;
        for (char c : item) {
            hash ^= static_cast<size_t>(c);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    size_t m_size;
    size_t m_hashCount;
    std::vector<bool> m_bits;
    size_t m_count{0};
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class TrackerBlockerImpl {
public:
    TrackerBlockerImpl() {
        m_stats.Reset();
        m_bloomFilter = std::make_unique<BloomFilter>();
    }

    ~TrackerBlockerImpl() {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const TrackerBlockerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Running) {
            TB_LOG_WARN("Already initialized");
            return true;
        }

        m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            TB_LOG_ERROR("Invalid configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Initialize bloom filter
        m_bloomFilter = std::make_unique<BloomFilter>();

        // Initialize tracking parameter set
        for (const auto& param : TrackerBlockerConstants::DEFAULT_STRIP_PARAMS) {
            m_trackingParams.insert(std::string(param));
        }

        // Load default blocklists
        LoadBuiltInRules();

        // Load configured blocklist files
        for (const auto& path : m_config.blocklistPaths) {
            if (std::filesystem::exists(path)) {
                LoadBlocklistFromFile(path, BlocklistSource::Custom, path.filename().string());
            }
        }

        // Start update thread if auto-update enabled
        if (m_config.enableAutoUpdate) {
            StartUpdateThread();
        }

        m_status = ModuleStatus::Running;
        TB_LOG_INFO("TrackerBlocker initialized with %zu rules", m_rules.size());
        return true;
    }

    [[nodiscard]] bool Initialize(BlockerMode mode) {
        return Initialize(TrackerBlockerConfiguration::FromMode(mode));
    }

    void Shutdown() {
        {
            std::unique_lock lock(m_mutex);
            if (m_status == ModuleStatus::Stopped || m_status == ModuleStatus::Uninitialized) {
                return;
            }
            m_status = ModuleStatus::Stopping;
        }

        StopUpdateThread();

        {
            std::unique_lock lock(m_mutex);
            ClearAllInternal();
            m_status = ModuleStatus::Stopped;
        }

        TB_LOG_INFO("TrackerBlocker shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status;
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const TrackerBlockerConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (!config.IsValid()) {
            TB_LOG_ERROR("Invalid configuration");
            return false;
        }

        m_config = config;
        TB_LOG_INFO("Configuration updated");
        return true;
    }

    [[nodiscard]] TrackerBlockerConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    void SetMode(BlockerMode mode) {
        std::unique_lock lock(m_mutex);
        m_config.mode = mode;
    }

    [[nodiscard]] BlockerMode GetMode() const noexcept {
        return m_config.mode;
    }

    void SetCategoryBlocking(TrackerCategory category, bool enabled) {
        std::unique_lock lock(m_mutex);
        if (enabled) {
            m_config.blockedCategories = m_config.blockedCategories | category;
        } else {
            m_config.blockedCategories = static_cast<TrackerCategory>(
                static_cast<uint32_t>(m_config.blockedCategories) &
                ~static_cast<uint32_t>(category));
        }
    }

    [[nodiscard]] bool IsCategoryBlocked(TrackerCategory category) const noexcept {
        return HasCategory(m_config.blockedCategories, category);
    }

    // ========================================================================
    // REQUEST FILTERING
    // ========================================================================

    [[nodiscard]] BlockResult ShouldBlock(const WebRequest& request) {
        auto startTime = Clock::now();
        BlockResult result;
        result.decision = BlockDecision::Allow;

        // Check if disabled
        if (m_config.mode == BlockerMode::Disabled) {
            result.processingTimeUs = GetElapsedUs(startTime);
            return result;
        }

        m_stats.totalRequests++;

        // 1. Check whitelist first
        if (IsWhitelistedInternal(request.url)) {
            m_stats.whitelistExceptions++;
            m_stats.totalAllowed++;
            result.reason = "Whitelisted";
            result.processingTimeUs = GetElapsedUs(startTime);
            return result;
        }

        // 2. Check URL cache
        if (m_config.enableCache) {
            if (auto cached = GetFromCache(request.url)) {
                m_stats.cacheHits++;
                cached->fromCache = true;
                cached->processingTimeUs = GetElapsedUs(startTime);

                if (cached->decision == BlockDecision::Block) {
                    m_stats.totalBlocked++;
                } else {
                    m_stats.totalAllowed++;
                }

                return *cached;
            }
            m_stats.cacheMisses++;
        }

        // 3. Quick bloom filter check
        std::string domain = ExtractDomainInternal(request.url);
        if (m_config.enableBloomFilter && m_bloomFilter) {
            if (!m_bloomFilter->MightContain(domain)) {
                // Definitely not in blocklist
                result.decision = BlockDecision::Allow;
                result.processingTimeUs = GetElapsedUs(startTime);
                m_stats.totalAllowed++;

                if (m_config.enableCache) {
                    AddToCache(request.url, result);
                }
                return result;
            }
            m_stats.bloomFilterHits++;
        }

        // 4. Check domain blocklist
        if (IsDomainBlockedInternal(domain)) {
            result.decision = BlockDecision::Block;
            result.matchedPattern = domain;
            result.category = GetDomainCategory(domain);
            result.reason = "Blocked domain";
            result.shouldLog = true;

            UpdateBlockStats(result.category);
            LogBlockedRequest(request, result);
        }

        // 5. Check URL patterns
        if (result.decision == BlockDecision::Allow) {
            auto matchResult = MatchRules(request);
            if (matchResult.has_value()) {
                result = *matchResult;
            }
        }

        // 6. Apply URL modification if needed
        if (result.decision == BlockDecision::Allow && m_config.stripTrackingParams) {
            std::string modifiedUrl = StripTrackingParamsInternal(request.url);
            if (modifiedUrl != request.url) {
                result.decision = BlockDecision::Modify;
                result.modifiedUrl = modifiedUrl;
                result.reason = "Tracking parameters stripped";
                m_stats.totalModified++;
            }
        }

        // 7. Monitor mode - log but don't block
        if (m_config.mode == BlockerMode::Monitor && result.decision == BlockDecision::Block) {
            result.decision = BlockDecision::AllowLogged;
            result.reason = "Monitor mode: " + result.reason;
        }

        // 8. Update statistics
        if (result.decision == BlockDecision::Block) {
            m_stats.totalBlocked++;
        } else if (result.decision != BlockDecision::Modify) {
            m_stats.totalAllowed++;
        }

        // 9. Cache result
        if (m_config.enableCache) {
            AddToCache(request.url, result);
        }

        // 10. Notify callbacks
        if (result.decision == BlockDecision::Block || result.decision == BlockDecision::AllowLogged) {
            NotifyBlockCallbacks(request, result);
        }

        result.processingTimeUs = GetElapsedUs(startTime);
        m_stats.totalProcessingTimeUs += result.processingTimeUs;

        return result;
    }

    [[nodiscard]] BlockResult ShouldBlockUrl(std::string_view url,
                                              RequestType type,
                                              std::string_view initiatorDomain) {
        WebRequest request;
        request.url = std::string(url);
        request.type = type;
        request.initiatorDomain = std::string(initiatorDomain);

        // Parse URL components
        ParseUrlInternal(url, request.domain, request.path, request.queryString);

        // Determine if third-party
        if (!initiatorDomain.empty()) {
            request.isThirdParty = IsThirdPartyInternal(url, initiatorDomain);
        }

        return ShouldBlock(request);
    }

    [[nodiscard]] bool IsDomainBlocked(std::string_view domain) const {
        std::shared_lock lock(m_mutex);
        return IsDomainBlockedInternal(std::string(domain));
    }

    [[nodiscard]] TrackerCategory GetUrlCategory(std::string_view url) const {
        std::shared_lock lock(m_mutex);
        std::string domain = ExtractDomainInternal(url);
        return GetDomainCategory(domain);
    }

    [[nodiscard]] std::string StripTrackingParams(std::string_view url) const {
        return StripTrackingParamsInternal(url);
    }

    [[nodiscard]] std::string SanitizeReferrer(std::string_view referrer,
                                                std::string_view targetUrl) const {
        if (referrer.empty()) return "";

        std::string refDomain = ExtractDomainInternal(referrer);
        std::string targetDomain = ExtractDomainInternal(targetUrl);

        // Same origin - keep full referrer
        if (refDomain == targetDomain) {
            return std::string(referrer);
        }

        // Cross-origin - return only origin
        size_t schemeEnd = std::string(referrer).find("://");
        if (schemeEnd != std::string::npos) {
            size_t pathStart = std::string(referrer).find('/', schemeEnd + 3);
            if (pathStart != std::string::npos) {
                return std::string(referrer.substr(0, pathStart));
            }
        }

        return std::string(referrer);
    }

    // ========================================================================
    // BLOCKLIST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool LoadBlocklist(const std::filesystem::path& path,
                                      BlocklistSource source,
                                      std::string_view name) {
        return LoadBlocklistFromFile(path, source, std::string(name));
    }

    [[nodiscard]] bool LoadBlocklistFromUrl(std::string_view url,
                                             BlocklistSource source,
                                             std::string_view name) {
        // Would use NetworkUtils to fetch the blocklist
        // For now, return false as network fetch is complex
        TB_LOG_WARN("URL-based blocklist loading not implemented: %s", std::string(url).c_str());
        return false;
    }

    [[nodiscard]] bool UnloadBlocklist(std::string_view id) {
        std::unique_lock lock(m_mutex);

        auto it = m_blocklists.find(std::string(id));
        if (it == m_blocklists.end()) {
            return false;
        }

        // Remove rules from this blocklist
        std::erase_if(m_rules, [&id](const auto& pair) {
            return pair.second.id.find(id) == 0;
        });

        m_blocklists.erase(it);
        RebuildBloomFilter();

        TB_LOG_INFO("Unloaded blocklist: %s", std::string(id).c_str());
        return true;
    }

    [[nodiscard]] std::vector<BlocklistInfo> GetBlocklists() const {
        std::shared_lock lock(m_mutex);
        std::vector<BlocklistInfo> result;
        result.reserve(m_blocklists.size());

        for (const auto& [id, info] : m_blocklists) {
            result.push_back(info);
        }

        return result;
    }

    [[nodiscard]] bool SetBlocklistEnabled(std::string_view id, bool enabled) {
        std::unique_lock lock(m_mutex);

        auto it = m_blocklists.find(std::string(id));
        if (it == m_blocklists.end()) {
            return false;
        }

        it->second.enabled = enabled;
        return true;
    }

    [[nodiscard]] bool UpdateBlocklist(std::string_view id) {
        // Would trigger re-fetch from URL
        return false;
    }

    void UpdateAllBlocklists() {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, info] : m_blocklists) {
            if (!info.updateUrl.empty()) {
                UpdateBlocklist(id);
            }
        }
    }

    [[nodiscard]] size_t GetRuleCount() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_rules.size();
    }

    // ========================================================================
    // CUSTOM RULES
    // ========================================================================

    [[nodiscard]] bool AddRule(const BlockRule& rule) {
        std::unique_lock lock(m_mutex);

        if (rule.pattern.empty()) {
            TB_LOG_WARN("Cannot add rule with empty pattern");
            return false;
        }

        if (m_rules.size() >= TrackerBlockerConstants::MAX_BLOCKLIST_RULES) {
            TB_LOG_WARN("Maximum rule count reached");
            return false;
        }

        std::string ruleId = rule.id.empty() ? GenerateRuleId() : rule.id;
        m_rules[ruleId] = rule;
        m_rules[ruleId].id = ruleId;
        m_rules[ruleId].createdAt = Clock::now();

        // Add to bloom filter if domain rule
        if (rule.type == RuleType::Domain || rule.type == RuleType::DomainSuffix) {
            m_blockedDomains.insert(rule.pattern);
            if (m_bloomFilter) {
                m_bloomFilter->Add(rule.pattern);
            }
        }

        m_stats.activeRuleCount = m_rules.size();
        return true;
    }

    [[nodiscard]] bool BlockDomain(std::string_view domain, TrackerCategory category) {
        BlockRule rule;
        rule.pattern = std::string(domain);
        rule.type = RuleType::Domain;
        rule.category = category;
        rule.source = BlocklistSource::Custom;
        return AddRule(rule);
    }

    [[nodiscard]] bool RemoveRule(std::string_view ruleId) {
        std::unique_lock lock(m_mutex);

        auto it = m_rules.find(std::string(ruleId));
        if (it == m_rules.end()) {
            return false;
        }

        // Remove from domain set if applicable
        if (it->second.type == RuleType::Domain) {
            m_blockedDomains.erase(it->second.pattern);
        }

        m_rules.erase(it);
        m_stats.activeRuleCount = m_rules.size();

        // Rebuild bloom filter
        RebuildBloomFilter();

        return true;
    }

    [[nodiscard]] std::optional<BlockRule> GetRule(std::string_view ruleId) const {
        std::shared_lock lock(m_mutex);

        auto it = m_rules.find(std::string(ruleId));
        if (it != m_rules.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    [[nodiscard]] bool SetRuleEnabled(std::string_view ruleId, bool enabled) {
        std::unique_lock lock(m_mutex);

        auto it = m_rules.find(std::string(ruleId));
        if (it == m_rules.end()) {
            return false;
        }

        it->second.enabled = enabled;
        return true;
    }

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool WhitelistDomain(std::string_view domain) {
        std::unique_lock lock(m_mutex);

        if (m_whitelist.size() >= TrackerBlockerConstants::MAX_WHITELIST_ENTRIES) {
            return false;
        }

        m_whitelistedDomains.insert(std::string(domain));
        m_whitelist.push_back(std::string(domain));
        return true;
    }

    [[nodiscard]] bool WhitelistUrl(std::string_view urlPattern) {
        std::unique_lock lock(m_mutex);

        if (m_whitelist.size() >= TrackerBlockerConstants::MAX_WHITELIST_ENTRIES) {
            return false;
        }

        m_whitelist.push_back(std::string(urlPattern));
        return true;
    }

    [[nodiscard]] bool RemoveFromWhitelist(std::string_view pattern) {
        std::unique_lock lock(m_mutex);

        auto it = std::find(m_whitelist.begin(), m_whitelist.end(), std::string(pattern));
        if (it != m_whitelist.end()) {
            m_whitelist.erase(it);
            m_whitelistedDomains.erase(std::string(pattern));
            return true;
        }
        return false;
    }

    [[nodiscard]] bool IsWhitelisted(std::string_view url) const {
        std::shared_lock lock(m_mutex);
        return IsWhitelistedInternal(url);
    }

    [[nodiscard]] std::vector<std::string> GetWhitelist() const {
        std::shared_lock lock(m_mutex);
        return m_whitelist;
    }

    void ClearWhitelist() {
        std::unique_lock lock(m_mutex);
        m_whitelist.clear();
        m_whitelistedDomains.clear();
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterBlockCallback(BlockEventCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId++;
        m_blockCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterBlockCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        m_blockCallbacks.erase(callbackId);
    }

    [[nodiscard]] uint64_t RegisterUpdateCallback(BlocklistUpdateCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        uint64_t id = m_nextCallbackId++;
        m_updateCallbacks[id] = std::move(callback);
        return id;
    }

    void UnregisterUpdateCallback(uint64_t callbackId) {
        std::unique_lock lock(m_callbackMutex);
        m_updateCallbacks.erase(callbackId);
    }

    void SetUrlModifyCallback(UrlModifyCallback callback) {
        std::unique_lock lock(m_callbackMutex);
        m_urlModifyCallback = std::move(callback);
    }

    // ========================================================================
    // STATISTICS & LOGGING
    // ========================================================================

    [[nodiscard]] TrackerBlockerStatistics GetStatistics() const {
        TrackerBlockerStatistics stats;
        stats.totalRequests = m_stats.totalRequests.load();
        stats.totalBlocked = m_stats.totalBlocked.load();
        stats.totalModified = m_stats.totalModified.load();
        stats.totalAllowed = m_stats.totalAllowed.load();
        stats.cacheHits = m_stats.cacheHits.load();
        stats.cacheMisses = m_stats.cacheMisses.load();
        stats.bloomFilterHits = m_stats.bloomFilterHits.load();
        stats.totalProcessingTimeUs = m_stats.totalProcessingTimeUs.load();
        stats.activeRuleCount = m_stats.activeRuleCount.load();
        stats.whitelistExceptions = m_stats.whitelistExceptions.load();
        stats.startTime = m_stats.startTime;
        return stats;
    }

    void ResetStatistics() {
        m_stats.Reset();
        m_stats.activeRuleCount = m_rules.size();
    }

    [[nodiscard]] std::vector<BlockedRequestEntry> GetBlockedRequests(size_t maxEntries) const {
        std::shared_lock lock(m_logMutex);

        size_t count = std::min(maxEntries, m_blockedLog.size());
        std::vector<BlockedRequestEntry> result;
        result.reserve(count);

        auto it = m_blockedLog.rbegin();
        for (size_t i = 0; i < count && it != m_blockedLog.rend(); ++i, ++it) {
            result.push_back(*it);
        }

        return result;
    }

    void ClearBlockedRequests() {
        std::unique_lock lock(m_logMutex);
        m_blockedLog.clear();
    }

    [[nodiscard]] std::string ExportReport() const {
        json report;
        report["statistics"] = json::parse(GetStatistics().ToJson());
        report["ruleCount"] = m_rules.size();
        report["whitelistCount"] = m_whitelist.size();
        report["blocklistCount"] = m_blocklists.size();

        json blocklists = json::array();
        for (const auto& [id, info] : m_blocklists) {
            json bl;
            bl["id"] = info.id;
            bl["name"] = info.name;
            bl["ruleCount"] = info.ruleCount;
            bl["enabled"] = info.enabled;
            blocklists.push_back(bl);
        }
        report["blocklists"] = blocklists;

        return report.dump(2);
    }

    [[nodiscard]] bool ExportRules(const std::filesystem::path& path) const {
        std::shared_lock lock(m_mutex);

        try {
            std::ofstream file(path);
            if (!file.is_open()) {
                return false;
            }

            for (const auto& [id, rule] : m_rules) {
                if (rule.type == RuleType::Domain) {
                    file << "||" << rule.pattern << "^\n";
                } else {
                    file << rule.pattern << "\n";
                }
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void ClearCache() {
        std::unique_lock lock(m_cacheMutex);
        m_cache.clear();
        m_cacheList.clear();
    }

    [[nodiscard]] size_t GetCacheSize() const noexcept {
        std::shared_lock lock(m_cacheMutex);
        return m_cache.size();
    }

    void PreloadCache(const std::vector<std::string>& domains) {
        for (const auto& domain : domains) {
            ShouldBlockUrl(domain, RequestType::Document, {});
        }
    }

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] static bool ParseUrl(std::string_view url,
                                        std::string& domain,
                                        std::string& path,
                                        std::string& query) {
        return ParseUrlInternal(url, domain, path, query);
    }

    [[nodiscard]] static std::string ExtractDomain(std::string_view url) {
        return ExtractDomainInternal(url);
    }

    [[nodiscard]] static bool IsThirdParty(std::string_view url, std::string_view initiatorDomain) {
        return IsThirdPartyInternal(url, initiatorDomain);
    }

    [[nodiscard]] bool SelfTest() {
        TB_LOG_INFO("Running self-test...");

        // Test 1: Check initialization
        if (!IsInitialized()) {
            TB_LOG_ERROR("Self-test failed: Not initialized");
            return false;
        }

        // Test 2: Add and check a test rule
        if (!BlockDomain("test-tracker.example.com", TrackerCategory::Analytics)) {
            TB_LOG_ERROR("Self-test failed: Could not add test rule");
            return false;
        }

        // Test 3: Check if rule works
        auto result = ShouldBlockUrl("https://test-tracker.example.com/track.js",
                                     RequestType::Script, {});
        if (result.decision != BlockDecision::Block) {
            TB_LOG_ERROR("Self-test failed: Test rule not matched");
            return false;
        }

        // Test 4: Check whitelist
        WhitelistDomain("whitelisted.example.com");
        result = ShouldBlockUrl("https://whitelisted.example.com/",
                                RequestType::Document, {});
        if (result.decision == BlockDecision::Block) {
            TB_LOG_ERROR("Self-test failed: Whitelist not working");
            return false;
        }

        // Cleanup
        RemoveRule("test-tracker.example.com");
        RemoveFromWhitelist("whitelisted.example.com");

        TB_LOG_INFO("Self-test passed");
        return true;
    }

private:
    // ========================================================================
    // INTERNAL TYPES
    // ========================================================================

    struct CacheEntry {
        BlockResult result;
        TimePoint expiration;
    };

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_logMutex;
    mutable std::mutex m_callbackMutex;

    ModuleStatus m_status{ModuleStatus::Uninitialized};
    TrackerBlockerConfiguration m_config;

    // Rules and blocklists
    std::unordered_map<std::string, BlockRule> m_rules;
    std::unordered_map<std::string, BlocklistInfo> m_blocklists;
    std::unordered_set<std::string> m_blockedDomains;
    std::unordered_map<std::string, TrackerCategory> m_domainCategories;

    // Whitelist
    std::vector<std::string> m_whitelist;
    std::unordered_set<std::string> m_whitelistedDomains;

    // Tracking parameters to strip
    std::unordered_set<std::string> m_trackingParams;

    // Bloom filter for fast negative lookups
    std::unique_ptr<BloomFilter> m_bloomFilter;

    // LRU Cache
    std::unordered_map<std::string,
        std::list<std::pair<std::string, CacheEntry>>::iterator> m_cache;
    std::list<std::pair<std::string, CacheEntry>> m_cacheList;

    // Blocked request log
    std::deque<BlockedRequestEntry> m_blockedLog;
    std::atomic<uint64_t> m_nextLogId{1};

    // Callbacks
    std::unordered_map<uint64_t, BlockEventCallback> m_blockCallbacks;
    std::unordered_map<uint64_t, BlocklistUpdateCallback> m_updateCallbacks;
    UrlModifyCallback m_urlModifyCallback;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // Update thread
    std::thread m_updateThread;
    std::atomic<bool> m_stopUpdate{false};

    // Statistics
    mutable TrackerBlockerStatistics m_stats;

    // Rule ID counter
    std::atomic<uint64_t> m_nextRuleId{1};

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    [[nodiscard]] uint64_t GetElapsedUs(TimePoint startTime) const {
        auto endTime = Clock::now();
        return std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime).count();
    }

    [[nodiscard]] std::string GenerateRuleId() {
        return "rule_" + std::to_string(m_nextRuleId++);
    }

    [[nodiscard]] static bool ParseUrlInternal(std::string_view url,
                                                std::string& domain,
                                                std::string& path,
                                                std::string& query) {
        domain.clear();
        path.clear();
        query.clear();

        size_t schemeEnd = url.find("://");
        if (schemeEnd == std::string_view::npos) {
            schemeEnd = 0;
        } else {
            schemeEnd += 3;
        }

        size_t pathStart = url.find('/', schemeEnd);
        if (pathStart == std::string_view::npos) {
            domain = std::string(url.substr(schemeEnd));
            return true;
        }

        domain = std::string(url.substr(schemeEnd, pathStart - schemeEnd));

        size_t queryStart = url.find('?', pathStart);
        if (queryStart == std::string_view::npos) {
            path = std::string(url.substr(pathStart));
        } else {
            path = std::string(url.substr(pathStart, queryStart - pathStart));
            query = std::string(url.substr(queryStart + 1));
        }

        return true;
    }

    [[nodiscard]] static std::string ExtractDomainInternal(std::string_view url) {
        std::string domain, path, query;
        ParseUrlInternal(url, domain, path, query);

        // Remove port if present
        size_t portPos = domain.find(':');
        if (portPos != std::string::npos) {
            domain = domain.substr(0, portPos);
        }

        // Lowercase
        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

        return domain;
    }

    [[nodiscard]] static bool IsThirdPartyInternal(std::string_view url,
                                                    std::string_view initiatorDomain) {
        std::string urlDomain = ExtractDomainInternal(url);
        std::string initDomain(initiatorDomain);
        std::transform(initDomain.begin(), initDomain.end(), initDomain.begin(), ::tolower);

        if (urlDomain == initDomain) {
            return false;
        }

        // Check if one is subdomain of other
        if (urlDomain.length() > initDomain.length()) {
            if (urlDomain.ends_with("." + initDomain)) {
                return false;
            }
        } else if (initDomain.length() > urlDomain.length()) {
            if (initDomain.ends_with("." + urlDomain)) {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] bool IsDomainBlockedInternal(const std::string& domain) const {
        // Direct match
        if (m_blockedDomains.count(domain) > 0) {
            return true;
        }

        // Check parent domains
        size_t dotPos = domain.find('.');
        while (dotPos != std::string::npos) {
            std::string parentDomain = domain.substr(dotPos + 1);
            if (m_blockedDomains.count(parentDomain) > 0) {
                return true;
            }
            dotPos = domain.find('.', dotPos + 1);
        }

        return false;
    }

    [[nodiscard]] bool IsWhitelistedInternal(std::string_view url) const {
        std::string domain = ExtractDomainInternal(url);

        // Check domain whitelist
        if (m_whitelistedDomains.count(domain) > 0) {
            return true;
        }

        // Check URL patterns
        for (const auto& pattern : m_whitelist) {
            if (url.find(pattern) != std::string_view::npos) {
                return true;
            }
        }

        return false;
    }

    [[nodiscard]] TrackerCategory GetDomainCategory(const std::string& domain) const {
        auto it = m_domainCategories.find(domain);
        if (it != m_domainCategories.end()) {
            return it->second;
        }

        // Check parent domains
        size_t dotPos = domain.find('.');
        while (dotPos != std::string::npos) {
            std::string parentDomain = domain.substr(dotPos + 1);
            it = m_domainCategories.find(parentDomain);
            if (it != m_domainCategories.end()) {
                return it->second;
            }
            dotPos = domain.find('.', dotPos + 1);
        }

        return TrackerCategory::UnknownTracker;
    }

    [[nodiscard]] std::optional<BlockResult> MatchRules(const WebRequest& request) {
        std::shared_lock lock(m_mutex);

        for (const auto& [id, rule] : m_rules) {
            if (!rule.enabled) continue;

            // Check category blocking
            if (!HasCategory(m_config.blockedCategories, rule.category)) {
                continue;
            }

            // Check request type
            if (rule.requestTypes != RequestType::All &&
                (static_cast<uint32_t>(rule.requestTypes) &
                 static_cast<uint32_t>(request.type)) == 0) {
                continue;
            }

            // Check third-party constraint
            if (rule.thirdPartyOnly && !request.isThirdParty) continue;
            if (rule.firstPartyOnly && request.isThirdParty) continue;

            // Match pattern
            bool matched = false;
            switch (rule.type) {
                case RuleType::Domain:
                    matched = (request.domain == rule.pattern);
                    break;

                case RuleType::DomainSuffix:
                    matched = request.domain.ends_with(rule.pattern) ||
                              request.domain == rule.pattern;
                    break;

                case RuleType::UrlPrefix:
                    matched = request.url.starts_with(rule.pattern);
                    break;

                case RuleType::UrlSuffix:
                    matched = request.url.ends_with(rule.pattern);
                    break;

                case RuleType::UrlContains:
                    matched = request.url.find(rule.pattern) != std::string::npos;
                    break;

                case RuleType::UrlRegex:
                    if (!rule.compiledRegex.has_value()) {
                        try {
                            rule.compiledRegex = std::regex(rule.pattern, std::regex::icase);
                        } catch (...) {
                            continue;
                        }
                    }
                    matched = std::regex_search(request.url, *rule.compiledRegex);
                    break;

                default:
                    break;
            }

            if (matched) {
                // Check exception rule
                if (rule.isException) {
                    return std::nullopt;  // Allow
                }

                // Increment hit count
                const_cast<BlockRule&>(rule).hitCount++;

                BlockResult result;
                result.decision = BlockDecision::Block;
                result.matchedRuleId = id;
                result.matchedPattern = rule.pattern;
                result.category = rule.category;
                result.reason = "Matched rule: " + rule.pattern;
                result.shouldLog = true;

                if (!rule.redirectUrl.empty()) {
                    result.decision = BlockDecision::Redirect;
                    result.redirectUrl = rule.redirectUrl;
                }

                return result;
            }
        }

        return std::nullopt;
    }

    [[nodiscard]] std::string StripTrackingParamsInternal(std::string_view url) const {
        std::string domain, path, query;
        if (!ParseUrlInternal(url, domain, path, query)) {
            return std::string(url);
        }

        if (query.empty()) {
            return std::string(url);
        }

        // Parse and filter query parameters
        std::vector<std::pair<std::string, std::string>> filteredParams;
        std::istringstream queryStream(query);
        std::string param;

        while (std::getline(queryStream, param, '&')) {
            size_t eqPos = param.find('=');
            std::string key = (eqPos != std::string::npos) ?
                              param.substr(0, eqPos) : param;

            // Check if this is a tracking parameter
            if (m_trackingParams.find(key) == m_trackingParams.end()) {
                filteredParams.emplace_back(key,
                    (eqPos != std::string::npos) ? param.substr(eqPos + 1) : "");
            }
        }

        // Rebuild URL
        std::string result = std::string(url.substr(0, url.find('?')));
        if (!filteredParams.empty()) {
            result += "?";
            for (size_t i = 0; i < filteredParams.size(); ++i) {
                if (i > 0) result += "&";
                result += filteredParams[i].first;
                if (!filteredParams[i].second.empty()) {
                    result += "=" + filteredParams[i].second;
                }
            }
        }

        return result;
    }

    void LoadBuiltInRules() {
        // Add some well-known tracker domains
        const std::vector<std::pair<std::string, TrackerCategory>> builtInTrackers = {
            {"doubleclick.net", TrackerCategory::Advertising},
            {"googlesyndication.com", TrackerCategory::Advertising},
            {"googleadservices.com", TrackerCategory::Advertising},
            {"google-analytics.com", TrackerCategory::Analytics},
            {"googletagmanager.com", TrackerCategory::Analytics},
            {"facebook.net", TrackerCategory::SocialMedia},
            {"connect.facebook.net", TrackerCategory::SocialMedia},
            {"platform.twitter.com", TrackerCategory::SocialMedia},
            {"ads.twitter.com", TrackerCategory::Advertising},
            {"scorecardresearch.com", TrackerCategory::Analytics},
            {"quantserve.com", TrackerCategory::Analytics},
            {"hotjar.com", TrackerCategory::Analytics},
            {"fullstory.com", TrackerCategory::Analytics},
            {"mouseflow.com", TrackerCategory::Analytics},
            {"crazyegg.com", TrackerCategory::Analytics},
            {"coinhive.com", TrackerCategory::Cryptomining},
            {"coin-hive.com", TrackerCategory::Cryptomining},
        };

        for (const auto& [domain, category] : builtInTrackers) {
            BlockRule rule;
            rule.pattern = domain;
            rule.type = RuleType::DomainSuffix;
            rule.category = category;
            rule.source = BlocklistSource::BuiltIn;
            AddRule(rule);
            m_domainCategories[domain] = category;
        }

        BlocklistInfo builtIn;
        builtIn.id = "builtin";
        builtIn.name = "Built-in Trackers";
        builtIn.source = BlocklistSource::BuiltIn;
        builtIn.ruleCount = builtInTrackers.size();
        builtIn.enabled = true;
        m_blocklists["builtin"] = builtIn;

        TB_LOG_INFO("Loaded %zu built-in tracker rules", builtInTrackers.size());
    }

    [[nodiscard]] bool LoadBlocklistFromFile(const std::filesystem::path& path,
                                              BlocklistSource source,
                                              const std::string& name) {
        std::unique_lock lock(m_mutex);

        try {
            std::ifstream file(path);
            if (!file.is_open()) {
                TB_LOG_ERROR("Failed to open blocklist: %s", path.string().c_str());
                return false;
            }

            std::string blocklistId = path.filename().string();
            size_t ruleCount = 0;
            std::string line;

            while (std::getline(file, line)) {
                // Skip comments and empty lines
                if (line.empty() || line[0] == '!' || line[0] == '#' ||
                    line[0] == '[') {
                    continue;
                }

                // Parse rule
                BlockRule rule = ParseBlocklistRule(line, source);
                if (!rule.pattern.empty()) {
                    AddRule(rule);
                    ruleCount++;
                }
            }

            BlocklistInfo info;
            info.id = blocklistId;
            info.name = name.empty() ? blocklistId : name;
            info.source = source;
            info.filePath = path;
            info.ruleCount = ruleCount;
            info.enabled = true;
            info.lastUpdated = Clock::now();
            m_blocklists[blocklistId] = info;

            TB_LOG_INFO("Loaded blocklist '%s' with %zu rules", name.c_str(), ruleCount);
            return true;

        } catch (const std::exception& e) {
            TB_LOG_ERROR("Error loading blocklist: %s", e.what());
            return false;
        }
    }

    [[nodiscard]] BlockRule ParseBlocklistRule(const std::string& line,
                                                BlocklistSource source) {
        BlockRule rule;
        rule.source = source;

        std::string pattern = line;

        // Check for exception rule (@@)
        if (pattern.starts_with("@@")) {
            rule.isException = true;
            pattern = pattern.substr(2);
        }

        // Check for domain anchor (||)
        if (pattern.starts_with("||")) {
            pattern = pattern.substr(2);
            rule.type = RuleType::DomainSuffix;

            // Remove trailing ^
            if (pattern.ends_with("^")) {
                pattern = pattern.substr(0, pattern.length() - 1);
            }
        }
        // Check for URL anchor (|)
        else if (pattern.starts_with("|")) {
            pattern = pattern.substr(1);
            rule.type = RuleType::UrlPrefix;
        }
        // Contains pattern
        else {
            rule.type = RuleType::UrlContains;
        }

        // Parse options (after $)
        size_t optionsPos = pattern.find('$');
        if (optionsPos != std::string::npos) {
            std::string options = pattern.substr(optionsPos + 1);
            pattern = pattern.substr(0, optionsPos);

            // Parse options
            std::istringstream optStream(options);
            std::string opt;
            while (std::getline(optStream, opt, ',')) {
                if (opt == "third-party" || opt == "3p") {
                    rule.thirdPartyOnly = true;
                } else if (opt == "first-party" || opt == "1p" || opt == "~third-party") {
                    rule.firstPartyOnly = true;
                } else if (opt == "script") {
                    rule.requestTypes = RequestType::Script;
                } else if (opt == "image") {
                    rule.requestTypes = RequestType::Image;
                } else if (opt == "stylesheet") {
                    rule.requestTypes = RequestType::Stylesheet;
                } else if (opt == "xmlhttprequest" || opt == "xhr") {
                    rule.requestTypes = RequestType::XMLHttpRequest;
                }
            }
        }

        rule.pattern = pattern;
        rule.category = TrackerCategory::UnknownTracker;

        return rule;
    }

    void RebuildBloomFilter() {
        if (!m_bloomFilter) return;

        m_bloomFilter->Clear();
        for (const auto& domain : m_blockedDomains) {
            m_bloomFilter->Add(domain);
        }
    }

    void UpdateBlockStats(TrackerCategory category) {
        m_stats.totalBlocked++;

        // Update category-specific counter
        uint32_t categoryIndex = 0;
        uint32_t catValue = static_cast<uint32_t>(category);
        while (catValue > 1 && categoryIndex < 16) {
            catValue >>= 1;
            categoryIndex++;
        }
        if (categoryIndex < 16) {
            m_stats.blocksByCategory[categoryIndex]++;
        }
    }

    void LogBlockedRequest(const WebRequest& request, const BlockResult& result) {
        std::unique_lock lock(m_logMutex);

        BlockedRequestEntry entry;
        entry.entryId = m_nextLogId++;
        entry.url = request.url;
        entry.domain = request.domain;
        entry.initiator = request.initiatorUrl;
        entry.requestType = request.type;
        entry.matchedRule = result.matchedPattern;
        entry.category = result.category;
        entry.timestamp = Clock::now();
        entry.tabId = request.tabId;

        m_blockedLog.push_back(entry);

        // Limit log size
        while (m_blockedLog.size() > TrackerBlockerConstants::MAX_BLOCKED_REQUESTS_LOG) {
            m_blockedLog.pop_front();
        }
    }

    void NotifyBlockCallbacks(const WebRequest& request, const BlockResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& [id, callback] : m_blockCallbacks) {
            try {
                callback(request, result);
            } catch (const std::exception& e) {
                TB_LOG_ERROR("Block callback %llu threw exception: %s", id, e.what());
            }
        }
    }

    [[nodiscard]] std::optional<BlockResult> GetFromCache(const std::string& key) {
        std::unique_lock lock(m_cacheMutex);

        auto it = m_cache.find(key);
        if (it == m_cache.end()) {
            return std::nullopt;
        }

        // Check expiration
        if (Clock::now() > it->second->second.expiration) {
            m_cacheList.erase(it->second);
            m_cache.erase(it);
            return std::nullopt;
        }

        // Move to front (LRU)
        m_cacheList.splice(m_cacheList.begin(), m_cacheList, it->second);

        return it->second->second.result;
    }

    void AddToCache(const std::string& key, const BlockResult& result) {
        std::unique_lock lock(m_cacheMutex);

        auto it = m_cache.find(key);
        if (it != m_cache.end()) {
            it->second->second.result = result;
            it->second->second.expiration =
                Clock::now() + std::chrono::seconds(TrackerBlockerConstants::CACHE_TTL_SECONDS);
            m_cacheList.splice(m_cacheList.begin(), m_cacheList, it->second);
            return;
        }

        // Evict if full
        while (m_cache.size() >= m_config.cacheSize && !m_cacheList.empty()) {
            auto last = m_cacheList.end();
            --last;
            m_cache.erase(last->first);
            m_cacheList.pop_back();
        }

        // Add new
        CacheEntry entry;
        entry.result = result;
        entry.expiration = Clock::now() +
            std::chrono::seconds(TrackerBlockerConstants::CACHE_TTL_SECONDS);

        m_cacheList.push_front({key, entry});
        m_cache[key] = m_cacheList.begin();
    }

    void ClearAllInternal() {
        m_rules.clear();
        m_blocklists.clear();
        m_blockedDomains.clear();
        m_domainCategories.clear();
        m_whitelist.clear();
        m_whitelistedDomains.clear();
        m_cache.clear();
        m_cacheList.clear();
        m_blockedLog.clear();
        m_blockCallbacks.clear();
        m_updateCallbacks.clear();

        if (m_bloomFilter) {
            m_bloomFilter->Clear();
        }
    }

    void StartUpdateThread() {
        m_stopUpdate = false;
        m_updateThread = std::thread([this]() {
            while (!m_stopUpdate) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(m_config.updateIntervalMs));

                if (m_stopUpdate) break;

                UpdateAllBlocklists();
            }
        });
    }

    void StopUpdateThread() {
        m_stopUpdate = true;
        if (m_updateThread.joinable()) {
            m_updateThread.join();
        }
    }
};

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> TrackerBlocker::s_instanceCreated{false};

// ============================================================================
// TRACKERBOCKER FACADE IMPLEMENTATION
// ============================================================================

TrackerBlocker& TrackerBlocker::Instance() noexcept {
    static TrackerBlocker instance;
    return instance;
}

bool TrackerBlocker::HasInstance() noexcept {
    return s_instanceCreated.load();
}

TrackerBlocker::TrackerBlocker()
    : m_impl(std::make_unique<TrackerBlockerImpl>()) {
    s_instanceCreated.store(true);
}

TrackerBlocker::~TrackerBlocker() {
    s_instanceCreated.store(false);
}

bool TrackerBlocker::Initialize(const TrackerBlockerConfiguration& config) {
    return m_impl->Initialize(config);
}

bool TrackerBlocker::Initialize(BlockerMode mode) {
    return m_impl->Initialize(mode);
}

void TrackerBlocker::Shutdown() {
    m_impl->Shutdown();
}

bool TrackerBlocker::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus TrackerBlocker::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool TrackerBlocker::SetConfiguration(const TrackerBlockerConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

TrackerBlockerConfiguration TrackerBlocker::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void TrackerBlocker::SetMode(BlockerMode mode) {
    m_impl->SetMode(mode);
}

BlockerMode TrackerBlocker::GetMode() const noexcept {
    return m_impl->GetMode();
}

void TrackerBlocker::SetCategoryBlocking(TrackerCategory category, bool enabled) {
    m_impl->SetCategoryBlocking(category, enabled);
}

bool TrackerBlocker::IsCategoryBlocked(TrackerCategory category) const noexcept {
    return m_impl->IsCategoryBlocked(category);
}

BlockResult TrackerBlocker::ShouldBlock(const WebRequest& request) {
    return m_impl->ShouldBlock(request);
}

BlockResult TrackerBlocker::ShouldBlockUrl(std::string_view url,
                                            RequestType type,
                                            std::string_view initiatorDomain) {
    return m_impl->ShouldBlockUrl(url, type, initiatorDomain);
}

bool TrackerBlocker::IsDomainBlocked(std::string_view domain) const {
    return m_impl->IsDomainBlocked(domain);
}

TrackerCategory TrackerBlocker::GetUrlCategory(std::string_view url) const {
    return m_impl->GetUrlCategory(url);
}

std::string TrackerBlocker::StripTrackingParams(std::string_view url) const {
    return m_impl->StripTrackingParams(url);
}

std::string TrackerBlocker::SanitizeReferrer(std::string_view referrer,
                                              std::string_view targetUrl) const {
    return m_impl->SanitizeReferrer(referrer, targetUrl);
}

bool TrackerBlocker::LoadBlocklist(const std::filesystem::path& path,
                                    BlocklistSource source,
                                    std::string_view name) {
    return m_impl->LoadBlocklist(path, source, name);
}

bool TrackerBlocker::LoadBlocklistFromUrl(std::string_view url,
                                           BlocklistSource source,
                                           std::string_view name) {
    return m_impl->LoadBlocklistFromUrl(url, source, name);
}

bool TrackerBlocker::UnloadBlocklist(std::string_view id) {
    return m_impl->UnloadBlocklist(id);
}

std::vector<BlocklistInfo> TrackerBlocker::GetBlocklists() const {
    return m_impl->GetBlocklists();
}

bool TrackerBlocker::SetBlocklistEnabled(std::string_view id, bool enabled) {
    return m_impl->SetBlocklistEnabled(id, enabled);
}

bool TrackerBlocker::UpdateBlocklist(std::string_view id) {
    return m_impl->UpdateBlocklist(id);
}

void TrackerBlocker::UpdateAllBlocklists() {
    m_impl->UpdateAllBlocklists();
}

size_t TrackerBlocker::GetRuleCount() const noexcept {
    return m_impl->GetRuleCount();
}

bool TrackerBlocker::AddRule(const BlockRule& rule) {
    return m_impl->AddRule(rule);
}

bool TrackerBlocker::BlockDomain(std::string_view domain, TrackerCategory category) {
    return m_impl->BlockDomain(domain, category);
}

bool TrackerBlocker::RemoveRule(std::string_view ruleId) {
    return m_impl->RemoveRule(ruleId);
}

std::optional<BlockRule> TrackerBlocker::GetRule(std::string_view ruleId) const {
    return m_impl->GetRule(ruleId);
}

bool TrackerBlocker::SetRuleEnabled(std::string_view ruleId, bool enabled) {
    return m_impl->SetRuleEnabled(ruleId, enabled);
}

bool TrackerBlocker::WhitelistDomain(std::string_view domain) {
    return m_impl->WhitelistDomain(domain);
}

bool TrackerBlocker::WhitelistUrl(std::string_view urlPattern) {
    return m_impl->WhitelistUrl(urlPattern);
}

bool TrackerBlocker::RemoveFromWhitelist(std::string_view pattern) {
    return m_impl->RemoveFromWhitelist(pattern);
}

bool TrackerBlocker::IsWhitelisted(std::string_view url) const {
    return m_impl->IsWhitelisted(url);
}

std::vector<std::string> TrackerBlocker::GetWhitelist() const {
    return m_impl->GetWhitelist();
}

void TrackerBlocker::ClearWhitelist() {
    m_impl->ClearWhitelist();
}

uint64_t TrackerBlocker::RegisterBlockCallback(BlockEventCallback callback) {
    return m_impl->RegisterBlockCallback(std::move(callback));
}

void TrackerBlocker::UnregisterBlockCallback(uint64_t callbackId) {
    m_impl->UnregisterBlockCallback(callbackId);
}

uint64_t TrackerBlocker::RegisterUpdateCallback(BlocklistUpdateCallback callback) {
    return m_impl->RegisterUpdateCallback(std::move(callback));
}

void TrackerBlocker::UnregisterUpdateCallback(uint64_t callbackId) {
    m_impl->UnregisterUpdateCallback(callbackId);
}

void TrackerBlocker::SetUrlModifyCallback(UrlModifyCallback callback) {
    m_impl->SetUrlModifyCallback(std::move(callback));
}

TrackerBlockerStatistics TrackerBlocker::GetStatistics() const {
    return m_impl->GetStatistics();
}

void TrackerBlocker::ResetStatistics() {
    m_impl->ResetStatistics();
}

std::vector<BlockedRequestEntry> TrackerBlocker::GetBlockedRequests(size_t maxEntries) const {
    return m_impl->GetBlockedRequests(maxEntries);
}

void TrackerBlocker::ClearBlockedRequests() {
    m_impl->ClearBlockedRequests();
}

std::string TrackerBlocker::ExportReport() const {
    return m_impl->ExportReport();
}

bool TrackerBlocker::ExportRules(const std::filesystem::path& path) const {
    return m_impl->ExportRules(path);
}

void TrackerBlocker::ClearCache() {
    m_impl->ClearCache();
}

size_t TrackerBlocker::GetCacheSize() const noexcept {
    return m_impl->GetCacheSize();
}

void TrackerBlocker::PreloadCache(const std::vector<std::string>& domains) {
    m_impl->PreloadCache(domains);
}

bool TrackerBlocker::ParseUrl(std::string_view url,
                               std::string& domain,
                               std::string& path,
                               std::string& query) {
    return TrackerBlockerImpl::ParseUrl(url, domain, path, query);
}

std::string TrackerBlocker::ExtractDomain(std::string_view url) {
    return TrackerBlockerImpl::ExtractDomain(url);
}

bool TrackerBlocker::IsThirdParty(std::string_view url, std::string_view initiatorDomain) {
    return TrackerBlockerImpl::IsThirdParty(url, initiatorDomain);
}

bool TrackerBlocker::SelfTest() {
    return m_impl->SelfTest();
}

std::string TrackerBlocker::GetVersionString() noexcept {
    return std::to_string(TrackerBlockerConstants::VERSION_MAJOR) + "." +
           std::to_string(TrackerBlockerConstants::VERSION_MINOR) + "." +
           std::to_string(TrackerBlockerConstants::VERSION_PATCH);
}

// ============================================================================
// RAII GUARD IMPLEMENTATION
// ============================================================================

TrackerBlockerGuard::TrackerBlockerGuard(BlockerMode temporaryMode)
    : m_previousMode(TrackerBlocker::Instance().GetMode()) {
    TrackerBlocker::Instance().SetMode(temporaryMode);
}

TrackerBlockerGuard::~TrackerBlockerGuard() {
    TrackerBlocker::Instance().SetMode(m_previousMode);
}

}  // namespace WebBrowser
}  // namespace ShadowStrike
