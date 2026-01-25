/**
 * ============================================================================
 * ShadowStrike NGAV - BROWSER PROTECTION ORCHESTRATOR MODULE
 * ============================================================================
 *
 * @file BrowserProtection.hpp
 * @brief Enterprise-grade central orchestrator for web browser security.
 *        Coordinates protection across Chrome, Firefox, Edge, Brave, and Opera.
 *
 * Provides comprehensive browser protection including navigation interception,
 * download scanning, extension security, and cross-browser policy enforcement.
 *
 * CORE CAPABILITIES:
 * ==================
 *
 * 1. BROWSER INTEGRATION
 *    - Chrome native messaging
 *    - Firefox WebExtensions
 *    - Edge Chromium integration
 *    - Brave browser support
 *    - Opera browser support
 *    - Network layer proxy
 *
 * 2. NAVIGATION PROTECTION
 *    - URL filtering/blocking
 *    - Category-based blocking
 *    - Phishing site detection
 *    - Malware URL blocking
 *    - Redirect chain analysis
 *    - Homograph detection
 *
 * 3. DOWNLOAD PROTECTION
 *    - Real-time download scanning
 *    - File type verification
 *    - Reputation checking
 *    - Sandboxed analysis
 *    - Archive inspection
 *
 * 4. BROWSER HARDENING
 *    - Extension policy enforcement
 *    - Privacy settings management
 *    - Safe search enforcement
 *    - Cookie policy management
 *    - History protection
 *
 * 5. PARENTAL CONTROLS
 *    - Content filtering
 *    - Time-based access
 *    - Category blocking
 *    - Search filtering
 *    - Activity logging
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for URL/domain IOCs
 * - PatternStore for detection patterns
 * - Whitelist for approved sites
 * - Network layer for traffic interception
 *
 * @note Supports all major browsers.
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
#include <future>
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
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/ProcessUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::WebBrowser {
    class BrowserProtectionImpl;
    class SafeBrowsingAPI;
    class PhishingDetector;
    class MaliciousDownloadBlocker;
    class AdBlocker;
    class TrackerBlocker;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace BrowserConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Extension ID (Chrome/Edge)
    inline constexpr const char* CHROME_EXTENSION_ID = "shadowstrike-browser-protection";
    
    /// @brief Firefox extension ID
    inline constexpr const char* FIREFOX_EXTENSION_ID = "shadowstrike@security.com";
    
    /// @brief Native messaging host name
    inline constexpr const char* NATIVE_HOST_NAME = "com.shadowstrike.browser";
    
    /// @brief Maximum URL length
    inline constexpr size_t MAX_URL_LENGTH = 8192;
    
    /// @brief URL cache size
    inline constexpr size_t URL_CACHE_SIZE = 100000;
    
    /// @brief Cache TTL (seconds)
    inline constexpr uint32_t CACHE_TTL_SECONDS = 3600;
    
    /// @brief Block page URL
    inline constexpr const char* BLOCK_PAGE_URL = "shadowstrike://blocked";

    /// @brief Supported browsers
    inline constexpr const char* SUPPORTED_BROWSERS[] = {
        "chrome.exe", "msedge.exe", "firefox.exe",
        "brave.exe", "opera.exe", "vivaldi.exe"
    };

    /// @brief Safe search domains
    inline constexpr const char* SAFE_SEARCH_DOMAINS[] = {
        "google.com", "bing.com", "yahoo.com",
        "duckduckgo.com", "yandex.com"
    };

}  // namespace BrowserConstants

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
 * @brief Browser type
 */
enum class BrowserType : uint8_t {
    Unknown         = 0,
    Chrome          = 1,
    Edge            = 2,
    Firefox         = 3,
    Brave           = 4,
    Opera           = 5,
    Vivaldi         = 6,
    Safari          = 7,    // macOS
    InternetExplorer = 8    // Legacy
};

/**
 * @brief Navigation action
 */
enum class NavigationAction : uint8_t {
    Allow           = 0,    ///< Allow navigation
    Block           = 1,    ///< Block and show block page
    Warn            = 2,    ///< Show warning, allow proceed
    Redirect        = 3,    ///< Redirect to safe page
    Log             = 4,    ///< Log only
    Sandbox         = 5     ///< Open in sandbox
};

/**
 * @brief Block reason
 */
enum class BlockReason : uint32_t {
    None                = 0,
    Malware             = 1 << 0,
    Phishing            = 1 << 1,
    Spam                = 1 << 2,
    AdultContent        = 1 << 3,
    Violence            = 1 << 4,
    Gambling            = 1 << 5,
    SocialMedia         = 1 << 6,
    Streaming           = 1 << 7,
    Gaming              = 1 << 8,
    Shopping            = 1 << 9,
    News                = 1 << 10,
    PolicyViolation     = 1 << 11,
    CustomBlocklist     = 1 << 12,
    CategoryBlocked     = 1 << 13,
    TimeRestriction     = 1 << 14,
    Cryptomining        = 1 << 15,
    Scam                = 1 << 16,
    C2Server            = 1 << 17,
    DGA                 = 1 << 18,   // Domain Generation Algorithm
    Typosquatting       = 1 << 19,
    Reputation          = 1 << 20
};

/**
 * @brief URL category
 */
enum class URLCategory : uint16_t {
    Unknown             = 0,
    Business            = 1,
    Education           = 2,
    Entertainment       = 3,
    Finance             = 4,
    Games               = 5,
    Government          = 6,
    Health              = 7,
    News                = 8,
    Search              = 9,
    Shopping            = 10,
    SocialMedia         = 11,
    Sports              = 12,
    Technology          = 13,
    Travel              = 14,
    Adult               = 15,
    Gambling            = 16,
    Violence            = 17,
    Weapons             = 18,
    Drugs               = 19,
    Hacking             = 20,
    Malware             = 21,
    Phishing            = 22,
    Spam                = 23,
    Proxy               = 24,
    Advertising         = 25,
    Streaming           = 26
};

/**
 * @brief Download verdict
 */
enum class DownloadVerdict : uint8_t {
    Safe            = 0,
    Suspicious      = 1,
    Malware         = 2,
    PUP             = 3,    // Potentially Unwanted Program
    Unknown         = 4,
    Blocked         = 5
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Processing      = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

/**
 * @brief Extension status
 */
enum class ExtensionStatus : uint8_t {
    NotInstalled    = 0,
    Disabled        = 1,
    Enabled         = 2,
    UpdateAvailable = 3,
    Error           = 4
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Browser instance info
 */
struct BrowserInstance {
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Browser type
    BrowserType type = BrowserType::Unknown;
    
    /// @brief Browser version
    std::string version;
    
    /// @brief Profile path
    fs::path profilePath;
    
    /// @brief User data directory
    fs::path userDataDir;
    
    /// @brief Is incognito/private
    bool isPrivate = false;
    
    /// @brief Extension status
    ExtensionStatus extensionStatus = ExtensionStatus::NotInstalled;
    
    /// @brief Native messaging connected
    bool nativeMessagingConnected = false;
    
    /// @brief Window count
    size_t windowCount = 0;
    
    /// @brief Tab count
    size_t tabCount = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Navigation request
 */
struct NavigationRequest {
    /// @brief Request ID
    std::string requestId;
    
    /// @brief URL
    std::string url;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Referrer
    std::string referrer;
    
    /// @brief Browser process ID
    uint32_t browserPid = 0;
    
    /// @brief Tab ID
    int64_t tabId = -1;
    
    /// @brief Frame ID
    int64_t frameId = -1;
    
    /// @brief Is main frame
    bool isMainFrame = true;
    
    /// @brief Method (GET, POST, etc.)
    std::string method = "GET";
    
    /// @brief Type (main_frame, sub_frame, etc.)
    std::string resourceType;
    
    /// @brief User initiator
    std::string userContext;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Navigation result
 */
struct NavigationResult {
    /// @brief Request ID
    std::string requestId;
    
    /// @brief Action
    NavigationAction action = NavigationAction::Allow;
    
    /// @brief Block reasons (bitmask)
    BlockReason blockReasons = BlockReason::None;
    
    /// @brief URL category
    URLCategory category = URLCategory::Unknown;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Redirect URL (if action is Redirect)
    std::string redirectUrl;
    
    /// @brief Block page URL
    std::string blockPageUrl;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Analysis summary
    std::string summary;
    
    /// @brief Matched rules/patterns
    std::vector<std::string> matchedRules;
    
    /// @brief Processing time
    std::chrono::microseconds processingTime{0};
    
    [[nodiscard]] bool IsBlocked() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Download info
 */
struct DownloadInfo {
    /// @brief Download ID
    std::string downloadId;
    
    /// @brief Source URL
    std::string sourceUrl;
    
    /// @brief Referrer URL
    std::string referrerUrl;
    
    /// @brief Filename
    std::string filename;
    
    /// @brief MIME type
    std::string mimeType;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Target path
    fs::path targetPath;
    
    /// @brief Browser PID
    uint32_t browserPid = 0;
    
    /// @brief SHA-256 hash (after download)
    std::string sha256;
    
    /// @brief Content-Disposition header
    std::string contentDisposition;
    
    /// @brief Server
    std::string server;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Download scan result
 */
struct DownloadScanResult {
    /// @brief Download ID
    std::string downloadId;
    
    /// @brief Verdict
    DownloadVerdict verdict = DownloadVerdict::Unknown;
    
    /// @brief Is safe
    bool isSafe = true;
    
    /// @brief Should block
    bool shouldBlock = false;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief File reputation
    int reputation = 50;
    
    /// @brief Matched signatures
    std::vector<std::string> matchedSignatures;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Safe search settings
 */
struct SafeSearchSettings {
    /// @brief Enable safe search
    bool enabled = true;
    
    /// @brief Google safe search
    bool googleSafeSearch = true;
    
    /// @brief Bing safe search
    bool bingSafeSearch = true;
    
    /// @brief YouTube restricted mode
    bool youtubeRestricted = true;
    
    /// @brief DuckDuckGo safe search
    bool duckDuckGoSafeSearch = true;
    
    /// @brief Custom search engines
    std::vector<std::string> customEngines;
};

/**
 * @brief Parental control settings
 */
struct ParentalControlSettings {
    /// @brief Enable parental controls
    bool enabled = false;
    
    /// @brief Blocked categories
    std::set<URLCategory> blockedCategories;
    
    /// @brief Time-based restrictions (hour of day -> allowed)
    std::array<bool, 24> hourlyAccess = {};
    
    /// @brief Daily time limit (minutes, 0 = unlimited)
    uint32_t dailyTimeLimitMinutes = 0;
    
    /// @brief Blocked domains
    std::vector<std::string> blockedDomains;
    
    /// @brief Allowed domains (whitelist)
    std::vector<std::string> allowedDomains;
    
    /// @brief Log all activity
    bool logActivity = true;
};

/**
 * @brief Statistics
 */
struct BrowserProtectionStatistics {
    std::atomic<uint64_t> totalNavigations{0};
    std::atomic<uint64_t> allowedNavigations{0};
    std::atomic<uint64_t> blockedNavigations{0};
    std::atomic<uint64_t> warnedNavigations{0};
    std::atomic<uint64_t> malwareBlocked{0};
    std::atomic<uint64_t> phishingBlocked{0};
    std::atomic<uint64_t> categoryBlocked{0};
    std::atomic<uint64_t> downloadsScanned{0};
    std::atomic<uint64_t> downloadsBlocked{0};
    std::atomic<uint64_t> adsBlocked{0};
    std::atomic<uint64_t> trackersBlocked{0};
    std::atomic<uint64_t> safeSearchEnforced{0};
    std::atomic<uint64_t> cacheHits{0};
    std::atomic<uint64_t> cacheMisses{0};
    std::array<std::atomic<uint64_t>, 32> byBlockReason{};
    std::array<std::atomic<uint64_t>, 32> byCategory{};
    std::array<std::atomic<uint64_t>, 16> byBrowser{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct BrowserProtectionConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    /// @brief Enable URL filtering
    bool enableURLFiltering = true;
    
    /// @brief Enable download scanning
    bool enableDownloadScanning = true;
    
    /// @brief Enable phishing detection
    bool enablePhishingDetection = true;
    
    /// @brief Enable ad blocking
    bool enableAdBlocking = false;
    
    /// @brief Enable tracker blocking
    bool enableTrackerBlocking = false;
    
    /// @brief Enable safe search
    bool enableSafeSearch = false;
    
    /// @brief Enable parental controls
    bool enableParentalControls = false;
    
    /// @brief Enable extension scanning
    bool enableExtensionScanning = true;
    
    /// @brief Block crypto miners
    bool blockCryptoMiners = true;
    
    /// @brief Block known malware domains
    bool blockMalwareDomains = true;
    
    /// @brief Block newly registered domains
    bool blockNewDomains = false;
    
    /// @brief New domain threshold (days)
    int newDomainThresholdDays = 30;
    
    /// @brief Show block page
    bool showBlockPage = true;
    
    /// @brief Allow user override
    bool allowUserOverride = false;
    
    /// @brief Safe search settings
    SafeSearchSettings safeSearch;
    
    /// @brief Parental control settings
    ParentalControlSettings parentalControls;
    
    /// @brief Custom blocklist
    std::vector<std::string> customBlocklist;
    
    /// @brief Custom allowlist
    std::vector<std::string> customAllowlist;
    
    /// @brief Blocked categories
    std::set<URLCategory> blockedCategories;
    
    /// @brief Cache TTL
    uint32_t cacheTTLSeconds = BrowserConstants::CACHE_TTL_SECONDS;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using NavigationCallback = std::function<void(const NavigationRequest&, const NavigationResult&)>;
using DownloadCallback = std::function<void(const DownloadInfo&, const DownloadScanResult&)>;
using BlockCallback = std::function<void(const std::string& url, BlockReason reason)>;
using BrowserEventCallback = std::function<void(const BrowserInstance&, const std::string& event)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

/// @brief Pre-navigation callback (return false to block)
using PreNavigationCallback = std::function<bool(const NavigationRequest&)>;

// ============================================================================
// BROWSER PROTECTION ORCHESTRATOR CLASS
// ============================================================================

/**
 * @class BrowserProtection
 * @brief Enterprise browser protection orchestrator
 */
class BrowserProtection final {
public:
    [[nodiscard]] static BrowserProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    BrowserProtection(const BrowserProtection&) = delete;
    BrowserProtection& operator=(const BrowserProtection&) = delete;
    BrowserProtection(BrowserProtection&&) = delete;
    BrowserProtection& operator=(BrowserProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const BrowserProtectionConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const BrowserProtectionConfiguration& config);
    [[nodiscard]] BrowserProtectionConfiguration GetConfiguration() const;

    // ========================================================================
    // NAVIGATION CONTROL
    // ========================================================================
    
    /// @brief Handle navigation request
    [[nodiscard]] NavigationResult OnNavigate(const NavigationRequest& request);
    
    /// @brief Simple URL check
    [[nodiscard]] NavigationResult CheckURL(
        const std::string& url,
        uint32_t browserPid = 0);
    
    /// @brief Check if URL is blocked
    [[nodiscard]] bool IsURLBlocked(const std::string& url);
    
    /// @brief Get URL category
    [[nodiscard]] URLCategory GetURLCategory(const std::string& url);
    
    /// @brief Get URL risk score
    [[nodiscard]] int GetURLRiskScore(const std::string& url);

    // ========================================================================
    // DOWNLOAD CONTROL
    // ========================================================================
    
    /// @brief Handle download request
    [[nodiscard]] DownloadScanResult OnDownload(const DownloadInfo& download);
    
    /// @brief Scan downloaded file
    [[nodiscard]] DownloadScanResult ScanDownload(const fs::path& filePath);
    
    /// @brief Check download URL reputation
    [[nodiscard]] int GetDownloadReputation(const std::string& url);

    // ========================================================================
    // BROWSER MANAGEMENT
    // ========================================================================
    
    /// @brief Get running browser instances
    [[nodiscard]] std::vector<BrowserInstance> GetBrowserInstances() const;
    
    /// @brief Get browser PIDs by type
    [[nodiscard]] std::vector<uint32_t> GetBrowserPids(
        BrowserType type = BrowserType::Unknown) const;
    
    /// @brief Get browser type from PID
    [[nodiscard]] BrowserType GetBrowserType(uint32_t pid) const;
    
    /// @brief Install browser extension
    [[nodiscard]] bool InstallExtension(BrowserType browser);
    
    /// @brief Check extension status
    [[nodiscard]] ExtensionStatus GetExtensionStatus(BrowserType browser) const;

    // ========================================================================
    // NATIVE MESSAGING
    // ========================================================================
    
    /// @brief Start native messaging host
    [[nodiscard]] bool StartNativeMessaging();
    
    /// @brief Stop native messaging host
    void StopNativeMessaging();
    
    /// @brief Is native messaging running
    [[nodiscard]] bool IsNativeMessagingRunning() const noexcept;
    
    /// @brief Register native messaging host
    [[nodiscard]] bool RegisterNativeHost(BrowserType browser);

    // ========================================================================
    // SAFE SEARCH
    // ========================================================================
    
    /// @brief Enforce safe search
    [[nodiscard]] bool EnforceSafeSearch(bool enable);
    
    /// @brief Is safe search enforced
    [[nodiscard]] bool IsSafeSearchEnforced() const noexcept;
    
    /// @brief Update safe search settings
    [[nodiscard]] bool UpdateSafeSearchSettings(const SafeSearchSettings& settings);

    // ========================================================================
    // PARENTAL CONTROLS
    // ========================================================================
    
    /// @brief Enable parental controls
    [[nodiscard]] bool EnableParentalControls(bool enable);
    
    /// @brief Update parental control settings
    [[nodiscard]] bool UpdateParentalControls(const ParentalControlSettings& settings);
    
    /// @brief Get parental control settings
    [[nodiscard]] ParentalControlSettings GetParentalControls() const;

    // ========================================================================
    // BLOCKLIST/ALLOWLIST
    // ========================================================================
    
    [[nodiscard]] bool AddToBlocklist(const std::string& domain);
    [[nodiscard]] bool RemoveFromBlocklist(const std::string& domain);
    [[nodiscard]] bool IsInBlocklist(const std::string& domain) const;
    
    [[nodiscard]] bool AddToAllowlist(const std::string& domain);
    [[nodiscard]] bool RemoveFromAllowlist(const std::string& domain);
    [[nodiscard]] bool IsInAllowlist(const std::string& domain) const;

    // ========================================================================
    // SUB-COMPONENT ACCESS
    // ========================================================================
    
    [[nodiscard]] SafeBrowsingAPI& GetSafeBrowsingAPI();
    [[nodiscard]] PhishingDetector& GetPhishingDetector();
    [[nodiscard]] MaliciousDownloadBlocker& GetDownloadBlocker();
    [[nodiscard]] AdBlocker& GetAdBlocker();
    [[nodiscard]] TrackerBlocker& GetTrackerBlocker();

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterNavigationCallback(NavigationCallback callback);
    void RegisterDownloadCallback(DownloadCallback callback);
    void RegisterBlockCallback(BlockCallback callback);
    void RegisterBrowserEventCallback(BrowserEventCallback callback);
    void RegisterPreNavigationCallback(PreNavigationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] BrowserProtectionStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    BrowserProtection();
    ~BrowserProtection();
    
    std::unique_ptr<BrowserProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetBrowserTypeName(BrowserType type) noexcept;
[[nodiscard]] std::string_view GetNavigationActionName(NavigationAction action) noexcept;
[[nodiscard]] std::string_view GetBlockReasonName(BlockReason reason) noexcept;
[[nodiscard]] std::string_view GetURLCategoryName(URLCategory category) noexcept;
[[nodiscard]] std::string_view GetDownloadVerdictName(DownloadVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetExtensionStatusName(ExtensionStatus status) noexcept;

/// @brief Extract domain from URL
[[nodiscard]] std::string ExtractDomain(const std::string& url);

/// @brief Normalize URL
[[nodiscard]] std::string NormalizeURL(const std::string& url);

/// @brief Check if URL is HTTPS
[[nodiscard]] bool IsHTTPS(const std::string& url);

/// @brief Detect browser from process
[[nodiscard]] BrowserType DetectBrowserFromProcess(uint32_t pid);

/// @brief Get browser profile paths
[[nodiscard]] std::vector<fs::path> GetBrowserProfilePaths(BrowserType browser);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_BROWSER_CHECK_URL(url) \
    ::ShadowStrike::WebBrowser::BrowserProtection::Instance().CheckURL(url)

#define SS_BROWSER_IS_BLOCKED(url) \
    ::ShadowStrike::WebBrowser::BrowserProtection::Instance().IsURLBlocked(url)

#define SS_BROWSER_SCAN_DOWNLOAD(path) \
    ::ShadowStrike::WebBrowser::BrowserProtection::Instance().ScanDownload(path)
