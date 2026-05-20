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
 * ShadowStrike NGAV - AD BLOCKER MODULE
 * ============================================================================
 *
 * @file AdBlocker.hpp
 * @brief Enterprise-grade ad blocking with network filtering, cosmetic rules,
 *        and privacy protection for comprehensive ad/tracker blocking.
 *
 * Provides multi-layer ad blocking including DNS-level blocking, network request
 * filtering, cosmetic filtering, and malvertising protection.
 *
 * BLOCKING CAPABILITIES:
 * ======================
 *
 * 1. NETWORK FILTERING
 *    - URL pattern matching
 *    - Domain blocking
 *    - Third-party request blocking
 *    - Request type filtering
 *    - CSP injection
 *
 * 2. DNS-LEVEL BLOCKING
 *    - Ad domain sinkholing
 *    - DNS-over-HTTPS support
 *    - Custom DNS resolver
 *    - Pi-hole style blocking
 *
 * 3. COSMETIC FILTERING
 *    - Element hiding rules
 *    - CSS injection
 *    - DOM manipulation
 *    - Script injection
 *    - Procedural cosmetic filters
 *
 * 4. FILTER LISTS
 *    - EasyList support
 *    - EasyPrivacy support
 *    - Adblock Plus syntax
 *    - uBlock Origin syntax
 *    - Custom list support
 *
 * 5. MALVERTISING PROTECTION
 *    - Malicious ad detection
 *    - Redirect blocking
 *    - Cryptominer blocking
 *    - Pop-up/pop-under blocking
 *
 * INTEGRATION:
 * ============
 * - PatternStore for filter rules
 * - ThreatIntel for malvertising IOCs
 * - BrowserProtection orchestrator
 *
 * @note Uses Bloom filters for performance.
 * @note Thread-safe singleton design.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
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
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <regex>

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

#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/PatternStore/PatternStore.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"
#include "WebProtectionCommon.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class AdBlockerImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace AdBlockerConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Bloom filter size
    inline constexpr size_t BLOOM_FILTER_SIZE = 1000000;
    
    /// @brief Domain trie max depth
    inline constexpr size_t MAX_DOMAIN_DEPTH = 10;
    
    /// @brief Maximum rules
    inline constexpr size_t MAX_RULES = 500000;
    
    /// @brief Filter list update interval (hours)
    inline constexpr uint32_t UPDATE_INTERVAL_HOURS = 24;

    /// @brief Built-in filter list URLs
    inline constexpr const char* BUILTIN_FILTER_LISTS[] = {
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist.to/easylist/easyprivacy.txt",
        "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus",
        "https://raw.githubusercontent.com/nickspaargaren/no-google/master/pihole-google-adservices.txt"
    };

    /// @brief Common ad domains (for quick blocking)
    inline constexpr const char* COMMON_AD_DOMAINS[] = {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adnxs.com", "facebook.com/tr", "amazon-adsystem.com",
        "adobedtm.com", "criteo.com", "outbrain.com", "taboola.com"
    };

}  // namespace AdBlockerConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Filter action
 */
enum class FilterAction : uint8_t {
    Allow       = 0,    ///< Allow request
    Block       = 1,    ///< Block request
    Hide        = 2,    ///< Hide element (cosmetic)
    Redirect    = 3,    ///< Redirect to neutral
    Modify      = 4     ///< Modify request/response
};

/**
 * @brief Filter type
 */
enum class FilterType : uint8_t {
    Network         = 0,    ///< Network request filter
    Cosmetic        = 1,    ///< CSS/element hiding
    Script          = 2,    ///< Script injection
    CSP             = 3,    ///< Content Security Policy
    Redirect        = 4,    ///< Redirect filter
    Exception       = 5     ///< Exception rule
};

// RequestType is provided by WebProtectionCommon.hpp (unified across modules).

/**
 * @brief Filter list status
 */
enum class FilterListStatus : uint8_t {
    NotLoaded       = 0,
    Loading         = 1,
    Loaded          = 2,
    Updating        = 3,
    Error           = 4,
    Disabled        = 5
};

// ModuleStatus is provided by WebProtectionCommon.hpp (unified across modules).

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Network filter rule
 */
struct NetworkFilterRule {
    /// @brief Rule ID
    uint32_t ruleId = 0;
    
    /// @brief Pattern
    std::string pattern;
    
    /// @brief Compiled regex (if regex rule)
    std::optional<std::regex> compiledRegex;
    
    /// @brief Action
    FilterAction action = FilterAction::Block;
    
    /// @brief Applicable request types
    RequestType requestTypes = RequestType::All;
    
    /// @brief Is third-party only
    bool thirdPartyOnly = false;
    
    /// @brief Is first-party only
    bool firstPartyOnly = false;
    
    /// @brief Apply to specific domains
    std::vector<std::string> domains;
    
    /// @brief Exclude from domains
    std::vector<std::string> excludeDomains;
    
    /// @brief Is exception rule
    bool isException = false;
    
    /// @brief Is important (override exceptions)
    bool isImportant = false;
    
    /// @brief Redirect target
    std::string redirectTarget;
    
    /// @brief Original rule text
    std::string originalRule;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Cosmetic filter rule
 */
struct CosmeticFilterRule {
    /// @brief Rule ID
    uint32_t ruleId = 0;
    
    /// @brief CSS selector
    std::string selector;
    
    /// @brief Action (hide, style, etc.)
    std::string action;
    
    /// @brief Apply to domains
    std::vector<std::string> domains;
    
    /// @brief Exclude from domains
    std::vector<std::string> excludeDomains;
    
    /// @brief Is procedural filter
    bool isProcedural = false;
    
    /// @brief Procedural operators
    std::vector<std::string> proceduralOps;
    
    /// @brief Is exception
    bool isException = false;
    
    /// @brief Original rule text
    std::string originalRule;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Filter list info
 */
struct FilterListInfo {
    /// @brief List ID
    std::string listId;
    
    /// @brief List name
    std::string name;
    
    /// @brief List URL
    std::string url;
    
    /// @brief Local file path
    std::string localPath;
    
    /// @brief Status
    FilterListStatus status = FilterListStatus::NotLoaded;
    
    /// @brief Rule count
    size_t ruleCount = 0;
    
    /// @brief Network rules
    size_t networkRules = 0;
    
    /// @brief Cosmetic rules
    size_t cosmeticRules = 0;
    
    /// @brief Last update
    SystemTimePoint lastUpdate;
    
    /// @brief Next update
    SystemTimePoint nextUpdate;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Is built-in
    bool isBuiltIn = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Filter match result
 */
struct FilterMatchResult {
    /// @brief URL checked
    std::string url;
    
    /// @brief Action
    FilterAction action = FilterAction::Allow;
    
    /// @brief Was blocked
    bool blocked = false;
    
    /// @brief Matched rule
    std::optional<NetworkFilterRule> matchedRule;
    
    /// @brief Exception rule (if any)
    std::optional<NetworkFilterRule> exceptionRule;
    
    /// @brief Cosmetic rules for domain
    std::vector<CosmeticFilterRule> cosmeticRules;
    
    /// @brief Redirect target
    std::string redirectTarget;
    
    /// @brief Match time
    std::chrono::microseconds matchTime{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct AdBlockerStatistics {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> blockedRequests{0};
    std::atomic<uint64_t> allowedRequests{0};
    std::atomic<uint64_t> hiddenElements{0};
    std::atomic<uint64_t> redirectedRequests{0};
    std::atomic<uint64_t> exceptionsApplied{0};
    std::atomic<uint64_t> popupsBlocked{0};
    std::atomic<uint64_t> cryptominersBlocked{0};
    std::atomic<uint64_t> malvertisementBlocked{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::atomic<uint64_t> bytesBlocked{0};
    std::array<std::atomic<uint64_t>, 16> byRequestType{};
    TimePoint startTime = Clock::now();

    AdBlockerStatistics() noexcept = default;

    AdBlockerStatistics(const AdBlockerStatistics& o) noexcept
        : totalRequests(o.totalRequests.load(std::memory_order_relaxed)),
          blockedRequests(o.blockedRequests.load(std::memory_order_relaxed)),
          allowedRequests(o.allowedRequests.load(std::memory_order_relaxed)),
          hiddenElements(o.hiddenElements.load(std::memory_order_relaxed)),
          redirectedRequests(o.redirectedRequests.load(std::memory_order_relaxed)),
          exceptionsApplied(o.exceptionsApplied.load(std::memory_order_relaxed)),
          popupsBlocked(o.popupsBlocked.load(std::memory_order_relaxed)),
          cryptominersBlocked(o.cryptominersBlocked.load(std::memory_order_relaxed)),
          malvertisementBlocked(o.malvertisementBlocked.load(std::memory_order_relaxed)),
          cacheHits(o.cacheHits.load(std::memory_order_relaxed)),
          cacheMisses(o.cacheMisses.load(std::memory_order_relaxed)),
          bytesBlocked(o.bytesBlocked.load(std::memory_order_relaxed)),
          startTime(std::atomic_ref<TimePoint>(const_cast<TimePoint&>(o.startTime)).load(std::memory_order_relaxed)) {
        for (size_t i = 0; i < byRequestType.size(); ++i) {
            byRequestType[i].store(o.byRequestType[i].load(std::memory_order_relaxed),
                                   std::memory_order_relaxed);
        }
    }

    AdBlockerStatistics& operator=(const AdBlockerStatistics& o) noexcept {
        if (this == &o) return *this;
        totalRequests.store(o.totalRequests.load(std::memory_order_relaxed), std::memory_order_relaxed);
        blockedRequests.store(o.blockedRequests.load(std::memory_order_relaxed), std::memory_order_relaxed);
        allowedRequests.store(o.allowedRequests.load(std::memory_order_relaxed), std::memory_order_relaxed);
        hiddenElements.store(o.hiddenElements.load(std::memory_order_relaxed), std::memory_order_relaxed);
        redirectedRequests.store(o.redirectedRequests.load(std::memory_order_relaxed), std::memory_order_relaxed);
        exceptionsApplied.store(o.exceptionsApplied.load(std::memory_order_relaxed), std::memory_order_relaxed);
        popupsBlocked.store(o.popupsBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cryptominersBlocked.store(o.cryptominersBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        malvertisementBlocked.store(o.malvertisementBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheHits.store(o.cacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
        cacheMisses.store(o.cacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
        bytesBlocked.store(o.bytesBlocked.load(std::memory_order_relaxed), std::memory_order_relaxed);
        for (size_t i = 0; i < byRequestType.size(); ++i) {
            byRequestType[i].store(o.byRequestType[i].load(std::memory_order_relaxed),
                                   std::memory_order_relaxed);
        }
        startTime = std::atomic_ref<TimePoint>(const_cast<TimePoint&>(o.startTime)).load(std::memory_order_relaxed);
        return *this;
    }

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct AdBlockerConfiguration {
    /// @brief Enable ad blocker
    bool enabled = true;
    
    /// @brief Enable network filtering
    bool enableNetworkFiltering = true;
    
    /// @brief Enable cosmetic filtering
    bool enableCosmeticFiltering = true;
    
    /// @brief Enable DNS blocking
    bool enableDNSBlocking = false;
    
    /// @brief Block malvertising
    bool blockMalvertising = true;
    
    /// @brief Block cryptominers
    bool blockCryptominers = true;
    
    /// @brief Block popups
    bool blockPopups = true;
    
    /// @brief Block web bugs
    bool blockWebBugs = true;
    
    /// @brief Auto-update filter lists
    bool autoUpdateLists = true;
    
    /// @brief Update interval (hours)
    uint32_t updateIntervalHours = AdBlockerConstants::UPDATE_INTERVAL_HOURS;
    
    /// @brief Filter list URLs
    std::vector<std::string> filterListUrls;
    
    /// @brief Custom rules
    std::vector<std::string> customRules;
    
    /// @brief Whitelisted domains
    std::vector<std::string> whitelistedDomains;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AdBlockCallback = std::function<void(const std::string& url, const FilterMatchResult&)>;
using UpdateCallback = std::function<void(const FilterListInfo&, bool success)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// AD BLOCKER CLASS
// ============================================================================

/**
 * @class AdBlocker
 * @brief Enterprise ad blocking engine
 */
class AdBlocker final {
public:
    [[nodiscard]] static AdBlocker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    AdBlocker(const AdBlocker&) = delete;
    AdBlocker& operator=(const AdBlocker&) = delete;
    AdBlocker(AdBlocker&&) = delete;
    AdBlocker& operator=(AdBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const AdBlockerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const AdBlockerConfiguration& config);
    [[nodiscard]] AdBlockerConfiguration GetConfiguration() const;

    // ========================================================================
    // FILTERING
    // ========================================================================
    
    /// @brief Check if URL should be blocked
    [[nodiscard]] bool ShouldBlock(const std::string& url);
    
    /// @brief Check URL with full context
    [[nodiscard]] FilterMatchResult CheckURL(
        const std::string& url,
        const std::string& pageUrl = "",
        RequestType requestType = RequestType::Other);
    
    /// @brief Get cosmetic filters for domain
    [[nodiscard]] std::vector<CosmeticFilterRule> GetCosmeticFilters(
        const std::string& domain);
    
    /// @brief Get script filters for domain
    [[nodiscard]] std::vector<std::string> GetScriptFilters(
        const std::string& domain);

    // ========================================================================
    // FILTER LISTS
    // ========================================================================
    
    /// @brief Load filter list from URL
    [[nodiscard]] bool LoadFilterList(const std::string& url);
    
    /// @brief Load filter list from file
    [[nodiscard]] bool LoadFilterListFromFile(const std::string& filePath);
    
    /// @brief Unload filter list
    [[nodiscard]] bool UnloadFilterList(const std::string& listId);
    
    /// @brief Update all filter lists
    [[nodiscard]] bool UpdateAllFilterLists();
    
    /// @brief Update specific filter list
    [[nodiscard]] bool UpdateFilterList(const std::string& listId);
    
    /// @brief Get filter list info
    [[nodiscard]] std::vector<FilterListInfo> GetFilterLists() const;
    
    /// @brief Enable/disable filter list
    [[nodiscard]] bool SetFilterListEnabled(const std::string& listId, bool enabled);

    // ========================================================================
    // CUSTOM RULES
    // ========================================================================
    
    /// @brief Add custom rule
    [[nodiscard]] bool AddCustomRule(const std::string& rule);
    
    /// @brief Remove custom rule
    [[nodiscard]] bool RemoveCustomRule(const std::string& rule);
    
    /// @brief Get custom rules
    [[nodiscard]] std::vector<std::string> GetCustomRules() const;
    
    /// @brief Clear custom rules
    void ClearCustomRules();

    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    /// @brief Add domain to whitelist
    [[nodiscard]] bool AddToWhitelist(const std::string& domain);
    
    /// @brief Remove domain from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& domain);
    
    /// @brief Is domain whitelisted
    [[nodiscard]] bool IsWhitelisted(const std::string& domain) const;
    
    /// @brief Get whitelisted domains
    [[nodiscard]] std::vector<std::string> GetWhitelistedDomains() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterBlockCallback(AdBlockCallback callback);
    void RegisterUpdateCallback(UpdateCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] AdBlockerStatistics GetStatistics() const;
    void ResetStatistics();
    
    /// @brief Get total rule count
    [[nodiscard]] size_t GetTotalRuleCount() const;
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    AdBlocker();
    ~AdBlocker();
    
    std::unique_ptr<AdBlockerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetFilterActionName(FilterAction action) noexcept;
[[nodiscard]] std::string_view GetFilterTypeName(FilterType type) noexcept;
[[nodiscard]] std::string_view GetRequestTypeName(RequestType type) noexcept;
[[nodiscard]] std::string_view GetFilterListStatusName(FilterListStatus status) noexcept;

/// @brief Parse AdBlock Plus format rule
[[nodiscard]] std::optional<NetworkFilterRule> ParseNetworkRule(const std::string& rule);

/// @brief Parse cosmetic rule
[[nodiscard]] std::optional<CosmeticFilterRule> ParseCosmeticRule(const std::string& rule);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_ADBLOCKER_CHECK(url) \
    ::ShadowStrike::WebBrowser::AdBlocker::Instance().ShouldBlock(url)

#define SS_ADBLOCKER_WHITELIST(domain) \
    ::ShadowStrike::WebBrowser::AdBlocker::Instance().AddToWhitelist(domain)

#define SS_ADBLOCKER_ADD_RULE(rule) \
    ::ShadowStrike::WebBrowser::AdBlocker::Instance().AddCustomRule(rule)
