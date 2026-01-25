/**
 * ============================================================================
 * ShadowStrike NGAV - COOKIE MANAGER MODULE
 * ============================================================================
 *
 * @file CookieManager.hpp
 * @brief Enterprise-grade HTTP cookie management with tracking protection,
 *        supercookie detection, and privacy-preserving whitelist support.
 *
 * Provides comprehensive cookie management including enumeration, filtering,
 * tracking protection, and secure deletion across all major browsers.
 *
 * MANAGEMENT CAPABILITIES:
 * ========================
 *
 * 1. COOKIE ENUMERATION
 *    - Read browser SQLite databases
 *    - Parse cookie attributes
 *    - Identify session vs persistent
 *    - Detect third-party cookies
 *    - Fingerprint tracking detection
 *
 * 2. TRACKING PROTECTION
 *    - Known tracker database
 *    - Advertising cookie blocking
 *    - Cross-site tracking prevention
 *    - Fingerprinting cookie detection
 *    - Analytics cookie management
 *
 * 3. SUPERCOOKIE DETECTION
 *    - Flash LSO (Local Shared Objects)
 *    - Silverlight isolated storage
 *    - HTML5 Local Storage
 *    - IndexedDB tracking
 *    - Canvas fingerprinting
 *    - ETags / Cache cookies
 *
 * 4. WHITELIST MANAGEMENT
 *    - Domain whitelisting
 *    - Session preservation
 *    - Essential cookie protection
 *    - Login persistence
 *
 * 5. POLICY ENFORCEMENT
 *    - First-party only
 *    - Session only
 *    - Block third-party
 *    - Tracker blocking
 *    - Per-site policies
 *
 * SUPPORTED BROWSERS:
 * ===================
 * - Google Chrome / Chromium
 * - Mozilla Firefox
 * - Microsoft Edge
 * - Opera / Opera GX
 * - Brave Browser
 * - Vivaldi
 * - Internet Explorer (legacy)
 *
 * @note Requires SQLite for reading browser databases.
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
#include "../Utils/StringUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../PatternStore/PatternStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Privacy {
    class CookieManagerImpl;
}

namespace ShadowStrike {
namespace Privacy {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CookieConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum cookies to process
    inline constexpr size_t MAX_COOKIES = 100000;
    
    /// @brief Maximum tracker list size
    inline constexpr size_t MAX_TRACKER_LIST = 50000;
    
    /// @brief Cookie database scan interval
    inline constexpr uint32_t SCAN_INTERVAL_MS = 60000;

}  // namespace CookieConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Browser type (shared with PrivacyCleaner)
 */
enum class BrowserType : uint8_t {
    Unknown         = 0,
    Chrome          = 1,
    Firefox         = 2,
    Edge            = 3,
    Opera           = 4,
    Brave           = 5,
    Vivaldi         = 6,
    IE              = 7,
    Chromium        = 8,
    All             = 255
};

/**
 * @brief Cookie category
 */
enum class CookieCategory : uint8_t {
    Unknown         = 0,
    Essential       = 1,    ///< Login, session, CSRF
    Functional      = 2,    ///< Preferences, settings
    Analytics       = 3,    ///< Google Analytics, etc.
    Advertising     = 4,    ///< Ads, retargeting
    Social          = 5,    ///< Social media tracking
    Tracking        = 6,    ///< General tracking
    Fingerprinting  = 7,    ///< Fingerprint tracking
    Malicious       = 8     ///< Known malicious
};

/**
 * @brief Cookie scope
 */
enum class CookieScope : uint8_t {
    FirstParty      = 0,
    ThirdParty      = 1,
    CrossSite       = 2
};

/**
 * @brief Cookie policy
 */
enum class CookiePolicy : uint8_t {
    AllowAll        = 0,
    BlockThirdParty = 1,
    BlockTrackers   = 2,
    BlockAll        = 3,
    SessionOnly     = 4,
    WhitelistOnly   = 5
};

/**
 * @brief SameSite attribute
 */
enum class SameSitePolicy : uint8_t {
    None            = 0,    ///< No SameSite attribute
    Lax             = 1,    ///< SameSite=Lax
    Strict          = 2,    ///< SameSite=Strict
    Unset           = 3     ///< Not specified
};

/**
 * @brief Supercookie type
 */
enum class SupercookieType : uint8_t {
    None            = 0,
    FlashLSO        = 1,    ///< Flash Local Shared Object
    SilverlightIS   = 2,    ///< Silverlight Isolated Storage
    LocalStorage    = 3,    ///< HTML5 Local Storage
    SessionStorage  = 4,    ///< HTML5 Session Storage
    IndexedDB       = 5,    ///< IndexedDB
    WebSQL          = 6,    ///< WebSQL (deprecated)
    CacheETag       = 7,    ///< ETag tracking
    HSTS            = 8,    ///< HSTS supercookie
    Canvas          = 9,    ///< Canvas fingerprinting data
    WebGL           = 10,   ///< WebGL fingerprinting data
    AudioContext    = 11    ///< Audio fingerprinting
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Scanning        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Browser cookie
 */
struct BrowserCookie {
    /// @brief Cookie ID (internal)
    uint64_t cookieId = 0;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Host only flag
    bool hostOnly = false;
    
    /// @brief Name
    std::string name;
    
    /// @brief Value (may be encrypted)
    std::string value;
    
    /// @brief Path
    std::string path;
    
    /// @brief Is secure (HTTPS only)
    bool isSecure = false;
    
    /// @brief Is HTTP only
    bool isHttpOnly = false;
    
    /// @brief SameSite policy
    SameSitePolicy sameSite = SameSitePolicy::Unset;
    
    /// @brief Expiration time
    SystemTimePoint expirationTime;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Last access time
    SystemTimePoint lastAccessTime;
    
    /// @brief Is session cookie
    bool isSession = false;
    
    /// @brief Is persistent
    bool isPersistent = false;
    
    /// @brief Category
    CookieCategory category = CookieCategory::Unknown;
    
    /// @brief Scope
    CookieScope scope = CookieScope::FirstParty;
    
    /// @brief Is tracking cookie
    bool isTracking = false;
    
    /// @brief Source browser
    BrowserType browser = BrowserType::Unknown;
    
    /// @brief Browser profile
    std::string profile;
    
    /// @brief Size (bytes)
    size_t sizeBytes = 0;
    
    /// @brief Is encrypted (Chrome)
    bool isEncrypted = false;
    
    [[nodiscard]] bool IsExpired() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Supercookie entry
 */
struct Supercookie {
    /// @brief Type
    SupercookieType type = SupercookieType::None;
    
    /// @brief Domain/Origin
    std::string domain;
    
    /// @brief Storage path
    fs::path storagePath;
    
    /// @brief Key name
    std::string key;
    
    /// @brief Value (may be large)
    std::string value;
    
    /// @brief Size (bytes)
    size_t sizeBytes = 0;
    
    /// @brief Creation time
    SystemTimePoint creationTime;
    
    /// @brief Is tracking
    bool isTracking = false;
    
    /// @brief Browser
    BrowserType browser = BrowserType::Unknown;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Tracker info
 */
struct TrackerInfo {
    /// @brief Tracker ID
    std::string trackerId;
    
    /// @brief Domain pattern
    std::string domainPattern;
    
    /// @brief Cookie name pattern
    std::string cookiePattern;
    
    /// @brief Company name
    std::string company;
    
    /// @brief Category
    CookieCategory category = CookieCategory::Tracking;
    
    /// @brief Description
    std::string description;
    
    /// @brief Privacy policy URL
    std::string privacyPolicyUrl;
    
    /// @brief Is active
    bool isActive = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Whitelist entry
 */
struct CookieWhitelistEntry {
    /// @brief Entry ID
    std::string entryId;
    
    /// @brief Domain pattern (supports wildcards)
    std::string domainPattern;
    
    /// @brief Cookie name pattern (optional)
    std::string cookieNamePattern;
    
    /// @brief Reason
    std::string reason;
    
    /// @brief Is enabled
    bool enabled = true;
    
    /// @brief Added by
    std::string addedBy;
    
    /// @brief When added
    SystemTimePoint addedTime;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Domain cookie summary
 */
struct DomainCookieSummary {
    /// @brief Domain
    std::string domain;
    
    /// @brief Total cookies
    uint32_t totalCookies = 0;
    
    /// @brief Session cookies
    uint32_t sessionCookies = 0;
    
    /// @brief Persistent cookies
    uint32_t persistentCookies = 0;
    
    /// @brief Tracking cookies
    uint32_t trackingCookies = 0;
    
    /// @brief Total size
    uint64_t totalSizeBytes = 0;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Tracker info (if known)
    std::optional<TrackerInfo> trackerInfo;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct CookieStatistics {
    std::atomic<uint64_t> totalCookiesScanned{0};
    std::atomic<uint64_t> totalCookiesDeleted{0};
    std::atomic<uint64_t> trackersBlocked{0};
    std::atomic<uint64_t> thirdPartyBlocked{0};
    std::atomic<uint64_t> supercookiesFound{0};
    std::atomic<uint64_t> supercookiesDeleted{0};
    std::atomic<uint64_t> whitelistHits{0};
    std::atomic<uint64_t> essentialPreserved{0};
    std::atomic<uint64_t> domainsScanned{0};
    std::atomic<uint64_t> bytesReclaimed{0};
    std::array<std::atomic<uint64_t>, 8> byBrowser{};
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct CookieConfiguration {
    /// @brief Enable cookie management
    bool enabled = true;
    
    /// @brief Default policy
    CookiePolicy defaultPolicy = CookiePolicy::BlockTrackers;
    
    /// @brief Block known trackers
    bool blockTrackers = true;
    
    /// @brief Block third-party cookies
    bool blockThirdParty = false;
    
    /// @brief Preserve essential cookies
    bool preserveEssential = true;
    
    /// @brief Delete expired cookies
    bool deleteExpired = true;
    
    /// @brief Scan for supercookies
    bool scanSupercookies = true;
    
    /// @brief Delete supercookies
    bool deleteSupercookies = true;
    
    /// @brief Auto-purge interval (0 = disabled)
    std::chrono::hours autoPurgeInterval{0};
    
    /// @brief Tracker database path
    fs::path trackerDatabasePath;
    
    /// @brief Custom tracker patterns
    std::vector<TrackerInfo> customTrackers;
    
    /// @brief Whitelist
    std::vector<CookieWhitelistEntry> whitelist;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using CookieCallback = std::function<void(const BrowserCookie&)>;
using SupercookieCallback = std::function<void(const Supercookie&)>;
using DomainCallback = std::function<void(const DomainCookieSummary&)>;
using PurgeCallback = std::function<void(uint64_t cookiesPurged, uint64_t bytesReclaimed)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// COOKIE MANAGER CLASS
// ============================================================================

/**
 * @class CookieManager
 * @brief Enterprise cookie management
 */
class CookieManager final {
public:
    [[nodiscard]] static CookieManager& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    CookieManager(const CookieManager&) = delete;
    CookieManager& operator=(const CookieManager&) = delete;
    CookieManager(CookieManager&&) = delete;
    CookieManager& operator=(CookieManager&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const CookieConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const CookieConfiguration& config);
    [[nodiscard]] CookieConfiguration GetConfiguration() const;

    // ========================================================================
    // COOKIE ENUMERATION
    // ========================================================================
    
    /// @brief Get all cookies
    [[nodiscard]] std::vector<BrowserCookie> GetAllCookies();
    
    /// @brief Get cookies for browser
    [[nodiscard]] std::vector<BrowserCookie> GetCookies(BrowserType browser);
    
    /// @brief Get cookies for domain
    [[nodiscard]] std::vector<BrowserCookie> GetCookiesForDomain(
        const std::string& domain);
    
    /// @brief Get tracking cookies
    [[nodiscard]] std::vector<BrowserCookie> GetTrackingCookies();
    
    /// @brief Get third-party cookies
    [[nodiscard]] std::vector<BrowserCookie> GetThirdPartyCookies();
    
    /// @brief Get cookie count
    [[nodiscard]] uint64_t GetCookieCount(BrowserType browser = BrowserType::All);

    // ========================================================================
    // SUPERCOOKIE DETECTION
    // ========================================================================
    
    /// @brief Scan for supercookies
    [[nodiscard]] std::vector<Supercookie> ScanForSupercookies();
    
    /// @brief Get supercookies for domain
    [[nodiscard]] std::vector<Supercookie> GetSupercookiesForDomain(
        const std::string& domain);
    
    /// @brief Delete supercookies
    [[nodiscard]] uint64_t DeleteSupercookies(
        const std::string& domain = "");

    // ========================================================================
    // TRACKING PROTECTION
    // ========================================================================
    
    /// @brief Purge all trackers
    [[nodiscard]] uint64_t PurgeTrackers();
    
    /// @brief Check if domain is tracker
    [[nodiscard]] bool IsTrackerDomain(const std::string& domain);
    
    /// @brief Check if cookie is tracking cookie
    [[nodiscard]] bool IsTrackingCookie(const BrowserCookie& cookie);
    
    /// @brief Get known trackers
    [[nodiscard]] std::vector<TrackerInfo> GetKnownTrackers();
    
    /// @brief Add custom tracker pattern
    [[nodiscard]] bool AddTracker(const TrackerInfo& tracker);
    
    /// @brief Remove tracker pattern
    [[nodiscard]] bool RemoveTracker(const std::string& trackerId);
    
    /// @brief Import tracker list (EasyPrivacy format)
    [[nodiscard]] bool ImportTrackerList(const fs::path& listPath);

    // ========================================================================
    // COOKIE MANAGEMENT
    // ========================================================================
    
    /// @brief Delete cookie
    [[nodiscard]] bool DeleteCookie(const BrowserCookie& cookie);
    
    /// @brief Delete cookies for domain
    [[nodiscard]] uint64_t DeleteCookiesForDomain(const std::string& domain);
    
    /// @brief Delete all cookies (respects whitelist)
    [[nodiscard]] uint64_t DeleteAllCookies(bool respectWhitelist = true);
    
    /// @brief Delete expired cookies
    [[nodiscard]] uint64_t DeleteExpiredCookies();
    
    /// @brief Delete third-party cookies
    [[nodiscard]] uint64_t DeleteThirdPartyCookies();
    
    /// @brief Categorize cookie
    [[nodiscard]] CookieCategory CategorizeCookie(const BrowserCookie& cookie);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================
    
    /// @brief Add to whitelist
    [[nodiscard]] bool AddToWhitelist(const CookieWhitelistEntry& entry);
    
    /// @brief Remove from whitelist
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& entryId);
    
    /// @brief Is domain whitelisted
    [[nodiscard]] bool IsDomainWhitelisted(const std::string& domain);
    
    /// @brief Get whitelist
    [[nodiscard]] std::vector<CookieWhitelistEntry> GetWhitelist() const;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Get domain summaries
    [[nodiscard]] std::vector<DomainCookieSummary> GetDomainSummaries();
    
    /// @brief Get summary for domain
    [[nodiscard]] DomainCookieSummary GetDomainSummary(const std::string& domain);
    
    /// @brief Get top tracking domains
    [[nodiscard]] std::vector<std::string> GetTopTrackingDomains(size_t limit = 20);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterCookieCallback(CookieCallback callback);
    void RegisterSupercookieCallback(SupercookieCallback callback);
    void RegisterPurgeCallback(PurgeCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] CookieStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    CookieManager();
    ~CookieManager();
    
    std::unique_ptr<CookieManagerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetCookieCategoryName(CookieCategory category) noexcept;
[[nodiscard]] std::string_view GetCookieScopeName(CookieScope scope) noexcept;
[[nodiscard]] std::string_view GetCookiePolicyName(CookiePolicy policy) noexcept;
[[nodiscard]] std::string_view GetSameSitePolicyName(SameSitePolicy policy) noexcept;
[[nodiscard]] std::string_view GetSupercookieTypeName(SupercookieType type) noexcept;

/// @brief Parse cookie domain to base domain
[[nodiscard]] std::string GetBaseDomain(const std::string& domain);

/// @brief Is third-party cookie for site
[[nodiscard]] bool IsThirdPartyCookie(
    const std::string& cookieDomain,
    const std::string& siteDomain);

}  // namespace Privacy
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_GET_ALL_COOKIES() \
    ::ShadowStrike::Privacy::CookieManager::Instance().GetAllCookies()

#define SS_PURGE_TRACKERS() \
    ::ShadowStrike::Privacy::CookieManager::Instance().PurgeTrackers()

#define SS_IS_TRACKER(domain) \
    ::ShadowStrike::Privacy::CookieManager::Instance().IsTrackerDomain(domain)

#define SS_WHITELIST_DOMAIN(entry) \
    ::ShadowStrike::Privacy::CookieManager::Instance().AddToWhitelist(entry)
