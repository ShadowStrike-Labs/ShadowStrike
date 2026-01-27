/**
 * ============================================================================
 * ShadowStrike WebBrowser - TRACKER BLOCKER ENGINE
 * ============================================================================
 *
 * @file TrackerBlocker.hpp
 * @brief Enterprise-grade web tracker blocking system for privacy protection
 *        and malicious script prevention.
 *
 * This module implements comprehensive tracker blocking mechanisms to prevent
 * web-based tracking, fingerprinting, and potentially malicious advertising
 * networks from compromising user privacy and security.
 *
 * PROTECTION MECHANISMS:
 * ======================
 *
 * 1. URL-BASED BLOCKING
 *    - Domain blocklists (advertising networks, analytics)
 *    - URL pattern matching (tracking pixels, beacons)
 *    - Query parameter stripping (UTM, click IDs)
 *    - Redirect chain interception
 *
 * 2. CONTENT-BASED BLOCKING
 *    - JavaScript fingerprinting prevention
 *    - Canvas fingerprint blocking
 *    - WebRTC leak prevention
 *    - Font enumeration blocking
 *
 * 3. NETWORK-LEVEL PROTECTION
 *    - DNS-level blocking (CNAME cloaking detection)
 *    - Third-party cookie blocking
 *    - Cross-origin tracking prevention
 *    - Referrer header sanitization
 *
 * 4. BLOCKLIST MANAGEMENT
 *    - EasyList/EasyPrivacy compatibility
 *    - Custom blocklist support
 *    - Real-time blocklist updates
 *    - Whitelist exceptions
 *
 * 5. THREAT CATEGORIES
 *    - Advertising networks
 *    - Analytics/telemetry
 *    - Social media trackers
 *    - Fingerprinting scripts
 *    - Malvertising
 *    - Cryptojacking scripts
 *
 * PERFORMANCE TARGETS:
 * ====================
 * - URL lookup: < 100ns (with bloom filter)
 * - Pattern match: < 1ms for complex rules
 * - Memory usage: < 50MB for 100K rules
 * - False positive rate: < 0.01%
 *
 * @note Integrates with ShadowStrike ThreatIntel for malicious URL detection.
 * @note Uses Aho-Corasick for multi-pattern URL matching.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: GDPR, CCPA, ePrivacy
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <span>
#include <regex>
#include <filesystem>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class TrackerBlockerImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TrackerBlockerConstants {

    // ========================================================================
    // VERSION
    // ========================================================================

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================

    /// @brief Maximum rules in blocklist
    inline constexpr size_t MAX_BLOCKLIST_RULES = 500000;

    /// @brief Maximum whitelist entries
    inline constexpr size_t MAX_WHITELIST_ENTRIES = 50000;

    /// @brief Maximum URL length for processing
    inline constexpr size_t MAX_URL_LENGTH = 8192;

    /// @brief Maximum domain length
    inline constexpr size_t MAX_DOMAIN_LENGTH = 253;

    /// @brief Maximum pattern length
    inline constexpr size_t MAX_PATTERN_LENGTH = 1024;

    /// @brief Maximum query parameters to strip
    inline constexpr size_t MAX_STRIP_PARAMS = 100;

    /// @brief Maximum blocked requests log
    inline constexpr size_t MAX_BLOCKED_REQUESTS_LOG = 10000;

    /// @brief Maximum custom rules per policy
    inline constexpr size_t MAX_CUSTOM_RULES = 10000;

    // ========================================================================
    // INTERVALS
    // ========================================================================

    /// @brief Blocklist update check interval (milliseconds)
    inline constexpr uint32_t UPDATE_CHECK_INTERVAL_MS = 3600000;  // 1 hour

    /// @brief Statistics aggregation interval (milliseconds)
    inline constexpr uint32_t STATS_AGGREGATION_INTERVAL_MS = 60000;  // 1 minute

    /// @brief Cache cleanup interval (milliseconds)
    inline constexpr uint32_t CACHE_CLEANUP_INTERVAL_MS = 300000;  // 5 minutes

    // ========================================================================
    // CACHE SETTINGS
    // ========================================================================

    /// @brief URL decision cache size
    inline constexpr size_t URL_CACHE_SIZE = 100000;

    /// @brief Domain cache size
    inline constexpr size_t DOMAIN_CACHE_SIZE = 50000;

    /// @brief Cache TTL in seconds
    inline constexpr uint32_t CACHE_TTL_SECONDS = 3600;

    // ========================================================================
    // BLOOM FILTER SETTINGS
    // ========================================================================

    /// @brief Bloom filter size (bits)
    inline constexpr size_t BLOOM_FILTER_SIZE = 1 << 20;  // ~1MB

    /// @brief Bloom filter hash count
    inline constexpr size_t BLOOM_FILTER_HASHES = 7;

    // ========================================================================
    // DEFAULT TRACKING PARAMETERS TO STRIP
    // ========================================================================

    inline constexpr std::array<std::string_view, 25> DEFAULT_STRIP_PARAMS = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "utm_id", "utm_cid", "fbclid", "gclid", "gclsrc",
        "dclid", "zanpid", "msclkid", "_ga", "_gl",
        "mc_cid", "mc_eid", "yclid", "wickedid", "igshid",
        "twclid", "ttclid", "li_fat_id", "ref", "ref_src"
    };

}  // namespace TrackerBlockerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using Milliseconds = std::chrono::milliseconds;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Tracker blocker protection mode
 */
enum class BlockerMode : uint8_t {
    Disabled    = 0,    ///< No blocking
    Monitor     = 1,    ///< Log only, no blocking
    Standard    = 2,    ///< Block known trackers
    Strict      = 3,    ///< Block all third-party resources
    Paranoid    = 4     ///< Maximum blocking (may break sites)
};

/**
 * @brief Tracker/content category
 */
enum class TrackerCategory : uint32_t {
    None                = 0x00000000,
    Advertising         = 0x00000001,
    Analytics           = 0x00000002,
    SocialMedia         = 0x00000004,
    Fingerprinting      = 0x00000008,
    Cryptomining        = 0x00000010,
    Malvertising        = 0x00000020,
    ContentDelivery     = 0x00000040,
    CommentSystem       = 0x00000080,
    CustomerInteraction = 0x00000100,
    HostedLibrary       = 0x00000200,
    AudioVideoPlayer    = 0x00000400,
    Extension           = 0x00000800,
    EmailMarketing      = 0x00001000,
    SitePerformance     = 0x00002000,
    UnknownTracker      = 0x00004000,

    AllTracking         = Advertising | Analytics | SocialMedia | Fingerprinting,
    AllMalicious        = Cryptomining | Malvertising,
    All                 = 0xFFFFFFFF
};

inline constexpr TrackerCategory operator|(TrackerCategory a, TrackerCategory b) noexcept {
    return static_cast<TrackerCategory>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr TrackerCategory operator&(TrackerCategory a, TrackerCategory b) noexcept {
    return static_cast<TrackerCategory>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

inline constexpr bool HasCategory(TrackerCategory value, TrackerCategory check) noexcept {
    return (static_cast<uint32_t>(value) & static_cast<uint32_t>(check)) != 0;
}

/**
 * @brief Request type for filtering
 */
enum class RequestType : uint32_t {
    Unknown         = 0x00000000,
    Document        = 0x00000001,
    SubDocument     = 0x00000002,
    Stylesheet      = 0x00000004,
    Script          = 0x00000008,
    Image           = 0x00000010,
    Font            = 0x00000020,
    Object          = 0x00000040,
    XMLHttpRequest  = 0x00000080,
    Ping            = 0x00000100,
    CSPReport       = 0x00000200,
    Media           = 0x00000400,
    WebSocket       = 0x00000800,
    WebRTC          = 0x00001000,
    Other           = 0x00002000,

    All             = 0xFFFFFFFF
};

inline constexpr RequestType operator|(RequestType a, RequestType b) noexcept {
    return static_cast<RequestType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr RequestType operator&(RequestType a, RequestType b) noexcept {
    return static_cast<RequestType>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Block decision type
 */
enum class BlockDecision : uint8_t {
    Allow           = 0,    ///< Allow request
    Block           = 1,    ///< Block request completely
    Redirect        = 2,    ///< Redirect to safe resource
    Modify          = 3,    ///< Modify request (strip params)
    AllowLogged     = 4,    ///< Allow but log
    Defer           = 5     ///< Defer to other filter
};

/**
 * @brief Rule type for filtering
 */
enum class RuleType : uint8_t {
    Domain          = 0,    ///< Exact domain match
    DomainSuffix    = 1,    ///< Domain suffix match (*.example.com)
    UrlPrefix       = 2,    ///< URL prefix match
    UrlSuffix       = 3,    ///< URL suffix match
    UrlContains     = 4,    ///< URL contains pattern
    UrlRegex        = 5,    ///< Regular expression
    UrlWildcard     = 6,    ///< Wildcard pattern (*, ?)
    CSSSelector     = 7,    ///< CSS element hiding
    ScriptInject    = 8,    ///< Script injection rule
    NetworkFilter   = 9     ///< Network-level filter
};

/**
 * @brief Blocklist source type
 */
enum class BlocklistSource : uint8_t {
    BuiltIn         = 0,    ///< Built-in rules
    EasyList        = 1,    ///< EasyList format
    EasyPrivacy     = 2,    ///< EasyPrivacy format
    UBlockOrigin    = 3,    ///< uBlock Origin format
    HostsFile       = 4,    ///< Hosts file format
    Custom          = 5,    ///< Custom rules
    ThreatIntel     = 6,    ///< ShadowStrike ThreatIntel
    Enterprise      = 7     ///< Enterprise policy
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Tracker blocker configuration
 */
struct TrackerBlockerConfiguration {
    /// @brief Protection mode
    BlockerMode mode = BlockerMode::Standard;

    /// @brief Categories to block
    TrackerCategory blockedCategories = TrackerCategory::AllTracking | TrackerCategory::AllMalicious;

    /// @brief Request types to filter
    RequestType filteredRequestTypes = RequestType::All;

    /// @brief Enable URL caching
    bool enableCache = true;

    /// @brief Cache size
    size_t cacheSize = TrackerBlockerConstants::URL_CACHE_SIZE;

    /// @brief Enable bloom filter for fast negative lookups
    bool enableBloomFilter = true;

    /// @brief Strip tracking parameters from URLs
    bool stripTrackingParams = true;

    /// @brief Block third-party cookies
    bool blockThirdPartyCookies = true;

    /// @brief Sanitize referrer headers
    bool sanitizeReferrer = true;

    /// @brief Block WebRTC IP leak
    bool blockWebRTCLeak = true;

    /// @brief Block canvas fingerprinting
    bool blockCanvasFingerprint = true;

    /// @brief Auto-update blocklists
    bool enableAutoUpdate = true;

    /// @brief Update interval (milliseconds)
    uint32_t updateIntervalMs = TrackerBlockerConstants::UPDATE_CHECK_INTERVAL_MS;

    /// @brief Verbose logging
    bool verboseLogging = false;

    /// @brief Send telemetry
    bool sendTelemetry = true;

    /// @brief Blocklist paths
    std::vector<std::filesystem::path> blocklistPaths;

    /// @brief Whitelist paths
    std::vector<std::filesystem::path> whitelistPaths;

    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;

    /**
     * @brief Create from mode
     */
    static TrackerBlockerConfiguration FromMode(BlockerMode mode);
};

/**
 * @brief Blocking rule definition
 */
struct BlockRule {
    /// @brief Rule ID
    std::string id;

    /// @brief Rule pattern
    std::string pattern;

    /// @brief Rule type
    RuleType type = RuleType::Domain;

    /// @brief Tracker category
    TrackerCategory category = TrackerCategory::None;

    /// @brief Request types this rule applies to
    RequestType requestTypes = RequestType::All;

    /// @brief Source of this rule
    BlocklistSource source = BlocklistSource::BuiltIn;

    /// @brief Is this an exception (whitelist) rule
    bool isException = false;

    /// @brief First-party only
    bool firstPartyOnly = false;

    /// @brief Third-party only
    bool thirdPartyOnly = false;

    /// @brief Domain restrictions (applies only to these domains)
    std::vector<std::string> domains;

    /// @brief Domain exclusions (doesn't apply to these domains)
    std::vector<std::string> excludeDomains;

    /// @brief Redirect URL (for redirect rules)
    std::string redirectUrl;

    /// @brief Priority (higher = evaluated first)
    int32_t priority = 0;

    /// @brief Is rule enabled
    bool enabled = true;

    /// @brief Created timestamp
    TimePoint createdAt;

    /// @brief Hit count
    std::atomic<uint64_t> hitCount{0};

    /// @brief Compiled regex (if type is UrlRegex)
    mutable std::optional<std::regex> compiledRegex;
};

/**
 * @brief Web request information
 */
struct WebRequest {
    /// @brief Request ID
    uint64_t requestId = 0;

    /// @brief Full URL
    std::string url;

    /// @brief Domain extracted from URL
    std::string domain;

    /// @brief Path component
    std::string path;

    /// @brief Query string
    std::string queryString;

    /// @brief Request type
    RequestType type = RequestType::Unknown;

    /// @brief HTTP method
    std::string method = "GET";

    /// @brief Initiator/referrer URL
    std::string initiatorUrl;

    /// @brief Initiator domain
    std::string initiatorDomain;

    /// @brief Is third-party request
    bool isThirdParty = false;

    /// @brief Tab/frame ID
    uint64_t tabId = 0;

    /// @brief Frame ID (for iframes)
    uint64_t frameId = 0;

    /// @brief Parent frame ID
    uint64_t parentFrameId = 0;

    /// @brief Request timestamp
    TimePoint timestamp = Clock::now();

    /// @brief Request headers (optional)
    std::unordered_map<std::string, std::string> headers;

    /// @brief Additional context
    std::unordered_map<std::string, std::string> context;
};

/**
 * @brief Block decision result
 */
struct BlockResult {
    /// @brief Decision
    BlockDecision decision = BlockDecision::Allow;

    /// @brief Matched rule ID
    std::string matchedRuleId;

    /// @brief Matched pattern
    std::string matchedPattern;

    /// @brief Tracker category
    TrackerCategory category = TrackerCategory::None;

    /// @brief Redirect URL (if decision is Redirect)
    std::string redirectUrl;

    /// @brief Modified URL (if decision is Modify)
    std::string modifiedUrl;

    /// @brief Reason for decision
    std::string reason;

    /// @brief Processing time (microseconds)
    uint64_t processingTimeUs = 0;

    /// @brief Was result from cache
    bool fromCache = false;

    /// @brief Should log this decision
    bool shouldLog = false;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Blocked request log entry
 */
struct BlockedRequestEntry {
    /// @brief Entry ID
    uint64_t entryId = 0;

    /// @brief Blocked URL
    std::string url;

    /// @brief Domain
    std::string domain;

    /// @brief Initiator
    std::string initiator;

    /// @brief Request type
    RequestType requestType = RequestType::Unknown;

    /// @brief Matched rule
    std::string matchedRule;

    /// @brief Category
    TrackerCategory category = TrackerCategory::None;

    /// @brief Block timestamp
    TimePoint timestamp = Clock::now();

    /// @brief Tab ID
    uint64_t tabId = 0;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Blocklist information
 */
struct BlocklistInfo {
    /// @brief Blocklist ID
    std::string id;

    /// @brief Display name
    std::string name;

    /// @brief Description
    std::string description;

    /// @brief Source type
    BlocklistSource source = BlocklistSource::Custom;

    /// @brief URL for updates
    std::string updateUrl;

    /// @brief File path (if local)
    std::filesystem::path filePath;

    /// @brief Rule count
    size_t ruleCount = 0;

    /// @brief Is enabled
    bool enabled = true;

    /// @brief Last updated
    TimePoint lastUpdated;

    /// @brief Last check time
    TimePoint lastChecked;

    /// @brief Version string
    std::string version;

    /// @brief Checksum
    std::string checksum;
};

/**
 * @brief Tracker blocker statistics
 */
struct TrackerBlockerStatistics {
    /// @brief Total requests processed
    std::atomic<uint64_t> totalRequests{0};

    /// @brief Total requests blocked
    std::atomic<uint64_t> totalBlocked{0};

    /// @brief Total requests modified
    std::atomic<uint64_t> totalModified{0};

    /// @brief Total requests allowed
    std::atomic<uint64_t> totalAllowed{0};

    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{0};

    /// @brief Cache misses
    std::atomic<uint64_t> cacheMisses{0};

    /// @brief Bloom filter hits
    std::atomic<uint64_t> bloomFilterHits{0};

    /// @brief Total processing time (microseconds)
    std::atomic<uint64_t> totalProcessingTimeUs{0};

    /// @brief Blocks by category
    std::array<std::atomic<uint64_t>, 16> blocksByCategory{};

    /// @brief Active rule count
    std::atomic<uint64_t> activeRuleCount{0};

    /// @brief Whitelist exception count
    std::atomic<uint64_t> whitelistExceptions{0};

    /// @brief Start time
    TimePoint startTime = Clock::now();

    /// @brief Last event time
    TimePoint lastEventTime;

    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;

    /**
     * @brief Get cache hit ratio
     */
    [[nodiscard]] double GetCacheHitRatio() const noexcept;

    /**
     * @brief Get average processing time
     */
    [[nodiscard]] double GetAverageProcessingTimeUs() const noexcept;

    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Callback for block events
using BlockEventCallback = std::function<void(const WebRequest&, const BlockResult&)>;

/// @brief Callback for blocklist update events
using BlocklistUpdateCallback = std::function<void(const BlocklistInfo&)>;

/// @brief Callback for URL modification
using UrlModifyCallback = std::function<std::optional<std::string>(const WebRequest&)>;

// ============================================================================
// TRACKER BLOCKER ENGINE CLASS
// ============================================================================

/**
 * @class TrackerBlocker
 * @brief Enterprise-grade web tracker blocking engine
 *
 * Provides comprehensive web tracker blocking including URL filtering,
 * content blocking, fingerprint prevention, and privacy protection.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& blocker = TrackerBlocker::Instance();
 *
 *     TrackerBlockerConfiguration config;
 *     config.mode = BlockerMode::Strict;
 *     config.blockedCategories = TrackerCategory::AllTracking;
 *
 *     if (!blocker.Initialize(config)) {
 *         LOG_ERROR("Failed to initialize tracker blocker");
 *     }
 *
 *     // Load blocklists
 *     blocker.LoadBlocklist("easylist.txt", BlocklistSource::EasyList);
 *     blocker.LoadBlocklist("easyprivacy.txt", BlocklistSource::EasyPrivacy);
 *
 *     // Check if URL should be blocked
 *     WebRequest request;
 *     request.url = "https://tracker.example.com/collect.js";
 *     request.type = RequestType::Script;
 *
 *     auto result = blocker.ShouldBlock(request);
 *     if (result.decision == BlockDecision::Block) {
 *         // Block the request
 *     }
 * @endcode
 */
class TrackerBlocker final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static TrackerBlocker& Instance() noexcept;

    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;

    // Non-copyable, non-movable
    TrackerBlocker(const TrackerBlocker&) = delete;
    TrackerBlocker& operator=(const TrackerBlocker&) = delete;
    TrackerBlocker(TrackerBlocker&&) = delete;
    TrackerBlocker& operator=(TrackerBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize tracker blocker
     */
    [[nodiscard]] bool Initialize(const TrackerBlockerConfiguration& config = {});

    /**
     * @brief Initialize with mode
     */
    [[nodiscard]] bool Initialize(BlockerMode mode);

    /**
     * @brief Shutdown tracker blocker
     */
    void Shutdown();

    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const TrackerBlockerConfiguration& config);

    /**
     * @brief Get current configuration
     */
    [[nodiscard]] TrackerBlockerConfiguration GetConfiguration() const;

    /**
     * @brief Set blocker mode
     */
    void SetMode(BlockerMode mode);

    /**
     * @brief Get blocker mode
     */
    [[nodiscard]] BlockerMode GetMode() const noexcept;

    /**
     * @brief Enable/disable specific category blocking
     */
    void SetCategoryBlocking(TrackerCategory category, bool enabled);

    /**
     * @brief Check if category is blocked
     */
    [[nodiscard]] bool IsCategoryBlocked(TrackerCategory category) const noexcept;

    // ========================================================================
    // REQUEST FILTERING
    // ========================================================================

    /**
     * @brief Check if request should be blocked
     */
    [[nodiscard]] BlockResult ShouldBlock(const WebRequest& request);

    /**
     * @brief Check URL directly (convenience method)
     */
    [[nodiscard]] BlockResult ShouldBlockUrl(std::string_view url,
                                              RequestType type = RequestType::Unknown,
                                              std::string_view initiatorDomain = {});

    /**
     * @brief Check if domain is in blocklist
     */
    [[nodiscard]] bool IsDomainBlocked(std::string_view domain) const;

    /**
     * @brief Get tracker category for URL
     */
    [[nodiscard]] TrackerCategory GetUrlCategory(std::string_view url) const;

    /**
     * @brief Strip tracking parameters from URL
     */
    [[nodiscard]] std::string StripTrackingParams(std::string_view url) const;

    /**
     * @brief Sanitize referrer header
     */
    [[nodiscard]] std::string SanitizeReferrer(std::string_view referrer,
                                                std::string_view targetUrl) const;

    // ========================================================================
    // BLOCKLIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Load blocklist from file
     */
    [[nodiscard]] bool LoadBlocklist(const std::filesystem::path& path,
                                      BlocklistSource source,
                                      std::string_view name = {});

    /**
     * @brief Load blocklist from URL
     */
    [[nodiscard]] bool LoadBlocklistFromUrl(std::string_view url,
                                             BlocklistSource source,
                                             std::string_view name = {});

    /**
     * @brief Unload blocklist
     */
    [[nodiscard]] bool UnloadBlocklist(std::string_view id);

    /**
     * @brief Get all loaded blocklists
     */
    [[nodiscard]] std::vector<BlocklistInfo> GetBlocklists() const;

    /**
     * @brief Enable/disable blocklist
     */
    [[nodiscard]] bool SetBlocklistEnabled(std::string_view id, bool enabled);

    /**
     * @brief Update blocklist from URL
     */
    [[nodiscard]] bool UpdateBlocklist(std::string_view id);

    /**
     * @brief Update all blocklists
     */
    void UpdateAllBlocklists();

    /**
     * @brief Get total rule count
     */
    [[nodiscard]] size_t GetRuleCount() const noexcept;

    // ========================================================================
    // CUSTOM RULES
    // ========================================================================

    /**
     * @brief Add custom blocking rule
     */
    [[nodiscard]] bool AddRule(const BlockRule& rule);

    /**
     * @brief Add domain to blocklist
     */
    [[nodiscard]] bool BlockDomain(std::string_view domain,
                                    TrackerCategory category = TrackerCategory::UnknownTracker);

    /**
     * @brief Remove custom rule
     */
    [[nodiscard]] bool RemoveRule(std::string_view ruleId);

    /**
     * @brief Get rule by ID
     */
    [[nodiscard]] std::optional<BlockRule> GetRule(std::string_view ruleId) const;

    /**
     * @brief Enable/disable rule
     */
    [[nodiscard]] bool SetRuleEnabled(std::string_view ruleId, bool enabled);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Add domain to whitelist
     */
    [[nodiscard]] bool WhitelistDomain(std::string_view domain);

    /**
     * @brief Add URL to whitelist
     */
    [[nodiscard]] bool WhitelistUrl(std::string_view urlPattern);

    /**
     * @brief Remove from whitelist
     */
    [[nodiscard]] bool RemoveFromWhitelist(std::string_view pattern);

    /**
     * @brief Check if whitelisted
     */
    [[nodiscard]] bool IsWhitelisted(std::string_view url) const;

    /**
     * @brief Get all whitelisted entries
     */
    [[nodiscard]] std::vector<std::string> GetWhitelist() const;

    /**
     * @brief Clear whitelist
     */
    void ClearWhitelist();

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    /**
     * @brief Register block event callback
     */
    [[nodiscard]] uint64_t RegisterBlockCallback(BlockEventCallback callback);

    /**
     * @brief Unregister block event callback
     */
    void UnregisterBlockCallback(uint64_t callbackId);

    /**
     * @brief Register blocklist update callback
     */
    [[nodiscard]] uint64_t RegisterUpdateCallback(BlocklistUpdateCallback callback);

    /**
     * @brief Unregister blocklist update callback
     */
    void UnregisterUpdateCallback(uint64_t callbackId);

    /**
     * @brief Set URL modify callback
     */
    void SetUrlModifyCallback(UrlModifyCallback callback);

    // ========================================================================
    // STATISTICS & LOGGING
    // ========================================================================

    /**
     * @brief Get statistics
     */
    [[nodiscard]] TrackerBlockerStatistics GetStatistics() const;

    /**
     * @brief Reset statistics
     */
    void ResetStatistics();

    /**
     * @brief Get blocked requests log
     */
    [[nodiscard]] std::vector<BlockedRequestEntry> GetBlockedRequests(size_t maxEntries = 100) const;

    /**
     * @brief Clear blocked requests log
     */
    void ClearBlockedRequests();

    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;

    /**
     * @brief Export rules to file
     */
    [[nodiscard]] bool ExportRules(const std::filesystem::path& path) const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Clear URL decision cache
     */
    void ClearCache();

    /**
     * @brief Get cache size
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    /**
     * @brief Preload domains into cache
     */
    void PreloadCache(const std::vector<std::string>& domains);

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Parse URL components
     */
    [[nodiscard]] static bool ParseUrl(std::string_view url,
                                        std::string& domain,
                                        std::string& path,
                                        std::string& query);

    /**
     * @brief Extract domain from URL
     */
    [[nodiscard]] static std::string ExtractDomain(std::string_view url);

    /**
     * @brief Check if URL is third-party relative to initiator
     */
    [[nodiscard]] static bool IsThirdParty(std::string_view url, std::string_view initiatorDomain);

    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();

    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================

    TrackerBlocker();
    ~TrackerBlocker();

    // ========================================================================
    // PIMPL
    // ========================================================================

    std::unique_ptr<TrackerBlockerImpl> m_impl;

    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================

    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get blocker mode name
 */
[[nodiscard]] std::string_view GetBlockerModeName(BlockerMode mode) noexcept;

/**
 * @brief Get tracker category name
 */
[[nodiscard]] std::string_view GetCategoryName(TrackerCategory category) noexcept;

/**
 * @brief Get request type name
 */
[[nodiscard]] std::string_view GetRequestTypeName(RequestType type) noexcept;

/**
 * @brief Get block decision name
 */
[[nodiscard]] std::string_view GetBlockDecisionName(BlockDecision decision) noexcept;

/**
 * @brief Get rule type name
 */
[[nodiscard]] std::string_view GetRuleTypeName(RuleType type) noexcept;

/**
 * @brief Parse request type from string
 */
[[nodiscard]] RequestType ParseRequestType(std::string_view typeName) noexcept;

/**
 * @brief Format category flags for display
 */
[[nodiscard]] std::string FormatCategories(TrackerCategory categories);

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class TrackerBlockerGuard
 * @brief RAII wrapper for temporary mode changes
 */
class TrackerBlockerGuard final {
public:
    explicit TrackerBlockerGuard(BlockerMode temporaryMode);
    ~TrackerBlockerGuard();

    TrackerBlockerGuard(const TrackerBlockerGuard&) = delete;
    TrackerBlockerGuard& operator=(const TrackerBlockerGuard&) = delete;

private:
    BlockerMode m_previousMode;
};

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Check if URL should be blocked
 */
#define SS_SHOULD_BLOCK_URL(url) \
    ::ShadowStrike::WebBrowser::TrackerBlocker::Instance().ShouldBlockUrl((url))

/**
 * @brief Strip tracking parameters from URL
 */
#define SS_STRIP_TRACKING(url) \
    ::ShadowStrike::WebBrowser::TrackerBlocker::Instance().StripTrackingParams((url))

