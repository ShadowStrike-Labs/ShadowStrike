/**
 * ============================================================================
 * ShadowStrike NGAV - TRACKER BLOCKER MODULE
 * ============================================================================
 *
 * @file TrackerBlocker.hpp
 * @brief Enterprise-grade privacy protection with tracker blocking,
 *        fingerprint prevention, and cookie management.
 *
 * Provides comprehensive privacy protection including tracker blocking,
 * browser fingerprinting prevention, cookie management, and data collection prevention.
 *
 * PROTECTION CAPABILITIES:
 * ========================
 *
 * 1. TRACKER BLOCKING
 *    - Known tracker domains
 *    - Tracking pixels
 *    - Web beacons
 *    - Analytics scripts
 *    - Social widgets
 *    - Cross-site tracking
 *
 * 2. FINGERPRINT PROTECTION
 *    - Canvas fingerprinting
 *    - WebGL fingerprinting
 *    - Audio fingerprinting
 *    - Font enumeration
 *    - Hardware enumeration
 *    - Screen resolution masking
 *    - Timezone spoofing
 *
 * 3. COOKIE MANAGEMENT
 *    - Third-party cookie blocking
 *    - Super cookie prevention
 *    - Cookie isolation
 *    - Flash LSO removal
 *    - IndexedDB tracking prevention
 *    - localStorage tracking prevention
 *
 * 4. HEADER PROTECTION
 *    - User-Agent normalization
 *    - Referer header stripping
 *    - Do Not Track enforcement
 *    - Client hints blocking
 *    - Accept headers normalization
 *
 * 5. SCRIPT PROTECTION
 *    - Tracking script blocking
 *    - Behavioral tracking prevention
 *    - Session replay prevention
 *    - Keylogger blocking
 *
 * TRACKER LISTS:
 * ==============
 * - EasyPrivacy
 * - Disconnect
 * - Privacy Badger
 * - Custom tracker lists
 *
 * INTEGRATION:
 * ============
 * - PatternStore for tracker patterns
 * - AdBlocker for unified filtering
 * - BrowserProtection orchestrator
 *
 * @note Privacy-focused design.
 * @note Thread-safe singleton.
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
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

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

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Default safe user agent
    inline constexpr const char* DEFAULT_SAFE_USER_AGENT = 
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    
    /// @brief Tracking pixel max size
    inline constexpr size_t TRACKING_PIXEL_MAX_SIZE = 100;  // bytes
    
    /// @brief Cookie block list update interval (hours)
    inline constexpr uint32_t UPDATE_INTERVAL_HOURS = 24;

    /// @brief Known tracking domains
    inline constexpr const char* KNOWN_TRACKERS[] = {
        "google-analytics.com", "googletagmanager.com",
        "facebook.com/tr", "connect.facebook.net",
        "doubleclick.net", "googlesyndication.com",
        "hotjar.com", "mouseflow.com", "fullstory.com",
        "mixpanel.com", "amplitude.com", "segment.com",
        "newrelic.com", "nr-data.net", "scorecardresearch.com"
    };

    /// @brief Fingerprinting APIs
    inline constexpr const char* FINGERPRINT_APIS[] = {
        "CanvasRenderingContext2D.prototype.getImageData",
        "CanvasRenderingContext2D.prototype.fillText",
        "WebGLRenderingContext.prototype.getParameter",
        "AudioContext.prototype.createAnalyser",
        "navigator.plugins", "navigator.mimeTypes",
        "screen.width", "screen.height", "screen.colorDepth"
    };

}  // namespace TrackerBlockerConstants

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
 * @brief Tracker type
 */
enum class TrackerType : uint8_t {
    Unknown             = 0,
    Analytics           = 1,    ///< Analytics trackers
    Advertising         = 2,    ///< Ad trackers
    Social              = 3,    ///< Social media trackers
    Content             = 4,    ///< Content tracking
    CryptoCurrency      = 5,    ///< Cryptomining
    Fingerprinting      = 6,    ///< Fingerprinting
    SessionReplay       = 7,    ///< Session recording
    Comments            = 8,    ///< Comment systems
    CDN                 = 9,    ///< CDN tracking
    Customer            = 10    ///< Customer engagement
};

/**
 * @brief Fingerprint type
 */
enum class FingerprintType : uint32_t {
    None                = 0,
    Canvas              = 1 << 0,
    WebGL               = 1 << 1,
    Audio               = 1 << 2,
    Fonts               = 1 << 3,
    Plugins             = 1 << 4,
    Screen              = 1 << 5,
    Timezone            = 1 << 6,
    Language            = 1 << 7,
    Hardware            = 1 << 8,
    Battery             = 1 << 9,
    MediaDevices        = 1 << 10,
    WebRTC              = 1 << 11,
    UserAgent           = 1 << 12,
    Navigator           = 1 << 13,
    All                 = 0xFFFF
};

/**
 * @brief Cookie type
 */
enum class CookieType : uint8_t {
    FirstParty          = 0,
    ThirdParty          = 1,
    Session             = 2,
    Persistent          = 3,
    Secure              = 4,
    HttpOnly            = 5,
    Tracking            = 6,
    Super               = 7     // Flash LSO, EverCookie, etc.
};

/**
 * @brief Block action
 */
enum class TrackerAction : uint8_t {
    Allow               = 0,
    Block               = 1,
    Anonymize           = 2,    // Strip identifying info
    Isolate             = 3,    // First-party isolation
    Log                 = 4     // Log only
};

/**
 * @brief Protection level
 */
enum class ProtectionLevel : uint8_t {
    Off                 = 0,
    Basic               = 1,    // Known trackers only
    Standard            = 2,    // Trackers + some fingerprinting
    Strict              = 3,    // All protection enabled
    Custom              = 4     // User-defined
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Blocking        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Tracker info
 */
struct TrackerInfo {
    /// @brief Domain
    std::string domain;
    
    /// @brief Company name
    std::string company;
    
    /// @brief Tracker type
    TrackerType type = TrackerType::Unknown;
    
    /// @brief Categories
    std::vector<std::string> categories;
    
    /// @brief Is known tracker
    bool isKnownTracker = false;
    
    /// @brief Risk level (1-10)
    int riskLevel = 5;
    
    /// @brief Description
    std::string description;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Tracking pixel detection result
 */
struct TrackingPixelResult {
    /// @brief Is tracking pixel
    bool isTrackingPixel = false;
    
    /// @brief Pixel size
    size_t pixelSize = 0;
    
    /// @brief Is transparent
    bool isTransparent = false;
    
    /// @brief Is 1x1 pixel
    bool isOneByOne = false;
    
    /// @brief MIME type
    std::string mimeType;
    
    /// @brief Source URL
    std::string sourceUrl;
    
    /// @brief Tracker company (if known)
    std::string trackerCompany;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Fingerprint detection result
 */
struct FingerprintDetection {
    /// @brief Detected fingerprint types
    FingerprintType detectedTypes = FingerprintType::None;
    
    /// @brief Scripts involved
    std::vector<std::string> involvedScripts;
    
    /// @brief APIs accessed
    std::vector<std::string> accessedAPIs;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Cookie block result
 */
struct CookieBlockResult {
    /// @brief Cookie name
    std::string name;
    
    /// @brief Cookie domain
    std::string domain;
    
    /// @brief Cookie type
    CookieType type = CookieType::FirstParty;
    
    /// @brief Was blocked
    bool wasBlocked = false;
    
    /// @brief Block reason
    std::string blockReason;
    
    /// @brief Tracker company
    std::string trackerCompany;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Spoofed values for fingerprinting protection
 */
struct SpoofedValues {
    /// @brief User agent
    std::string userAgent;
    
    /// @brief Platform
    std::string platform;
    
    /// @brief Screen resolution
    int screenWidth = 1920;
    int screenHeight = 1080;
    
    /// @brief Color depth
    int colorDepth = 24;
    
    /// @brief Timezone offset (minutes)
    int timezoneOffset = 0;
    
    /// @brief Language
    std::string language = "en-US";
    
    /// @brief Plugin count
    int pluginCount = 5;
    
    /// @brief WebGL renderer
    std::string webglRenderer;
    
    /// @brief WebGL vendor
    std::string webglVendor;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Blocking statistics per domain
 */
struct DomainStats {
    /// @brief Domain
    std::string domain;
    
    /// @brief Trackers blocked
    uint32_t trackersBlocked = 0;
    
    /// @brief Cookies blocked
    uint32_t cookiesBlocked = 0;
    
    /// @brief Fingerprint attempts blocked
    uint32_t fingerprintAttempts = 0;
    
    /// @brief Last activity
    SystemTimePoint lastActivity;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct TrackerBlockerStatistics {
    std::atomic<uint64_t> totalRequests{0};
    std::atomic<uint64_t> trackersBlocked{0};
    std::atomic<uint64_t> cookiesBlocked{0};
    std::atomic<uint64_t> fingerprintAttemptsBlocked{0};
    std::atomic<uint64_t> pixelsBlocked{0};
    std::atomic<uint64_t> beaconsBlocked{0};
    std::atomic<uint64_t> socialWidgetsBlocked{0};
    std::atomic<uint64_t> analyticsBlocked{0};
    std::atomic<uint64_t> advertisingBlocked{0};
    std::atomic<uint64_t> sessionReplayBlocked{0};
    std::atomic<uint64_t> refererStripped{0};
    std::atomic<uint64_t> userAgentNormalized{0};
    std::array<std::atomic<uint64_t>, 16> byTrackerType{};
    std::array<std::atomic<uint64_t>, 16> byFingerprintType{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct TrackerBlockerConfiguration {
    /// @brief Enable tracker blocker
    bool enabled = true;
    
    /// @brief Protection level
    ProtectionLevel protectionLevel = ProtectionLevel::Standard;
    
    /// @brief Block known trackers
    bool blockKnownTrackers = true;
    
    /// @brief Block tracking pixels
    bool blockTrackingPixels = true;
    
    /// @brief Block third-party cookies
    bool blockThirdPartyCookies = true;
    
    /// @brief Block super cookies
    bool blockSuperCookies = true;
    
    /// @brief Enable fingerprint protection
    bool enableFingerprintProtection = true;
    
    /// @brief Block canvas fingerprinting
    bool blockCanvasFingerprinting = true;
    
    /// @brief Block WebGL fingerprinting
    bool blockWebGLFingerprinting = true;
    
    /// @brief Block audio fingerprinting
    bool blockAudioFingerprinting = true;
    
    /// @brief Normalize user agent
    bool normalizeUserAgent = true;
    
    /// @brief Strip referer header
    bool stripReferer = true;
    
    /// @brief Enable Do Not Track
    bool enableDoNotTrack = true;
    
    /// @brief Block social widgets
    bool blockSocialWidgets = false;
    
    /// @brief Block session replay
    bool blockSessionReplay = true;
    
    /// @brief First-party isolation
    bool firstPartyIsolation = false;
    
    /// @brief Custom user agent
    std::string customUserAgent;
    
    /// @brief Whitelisted domains
    std::vector<std::string> whitelistedDomains;
    
    /// @brief Custom block list URLs
    std::vector<std::string> blockListUrls;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using TrackerBlockedCallback = std::function<void(const TrackerInfo&, const std::string& url)>;
using CookieBlockedCallback = std::function<void(const CookieBlockResult&)>;
using FingerprintDetectedCallback = std::function<void(const FingerprintDetection&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// TRACKER BLOCKER CLASS
// ============================================================================

/**
 * @class TrackerBlocker
 * @brief Enterprise privacy protection engine
 */
class TrackerBlocker final {
public:
    [[nodiscard]] static TrackerBlocker& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    TrackerBlocker(const TrackerBlocker&) = delete;
    TrackerBlocker& operator=(const TrackerBlocker&) = delete;
    TrackerBlocker(TrackerBlocker&&) = delete;
    TrackerBlocker& operator=(TrackerBlocker&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const TrackerBlockerConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const TrackerBlockerConfiguration& config);
    [[nodiscard]] TrackerBlockerConfiguration GetConfiguration() const;
    
    /// @brief Set protection level
    [[nodiscard]] bool SetProtectionLevel(ProtectionLevel level);

    // ========================================================================
    // TRACKING DETECTION
    // ========================================================================
    
    /// @brief Check if URL is a tracker
    [[nodiscard]] bool IsTracker(const std::string& url);
    
    /// @brief Get tracker info
    [[nodiscard]] std::optional<TrackerInfo> GetTrackerInfo(const std::string& domain);
    
    /// @brief Check if buffer is tracking pixel
    [[nodiscard]] bool IsTrackingPixel(const std::vector<uint8_t>& buffer);
    
    /// @brief Detect tracking pixel
    [[nodiscard]] TrackingPixelResult DetectTrackingPixel(
        const std::vector<uint8_t>& buffer,
        const std::string& sourceUrl = "");
    
    /// @brief Check request for tracking
    [[nodiscard]] TrackerAction CheckRequest(
        const std::string& url,
        const std::string& pageUrl,
        const std::string& resourceType);

    // ========================================================================
    // FINGERPRINT PROTECTION
    // ========================================================================
    
    /// @brief Get safe user agent
    [[nodiscard]] std::string GetSafeUserAgent() const;
    
    /// @brief Get spoofed values for fingerprint protection
    [[nodiscard]] SpoofedValues GetSpoofedValues() const;
    
    /// @brief Set custom user agent
    void SetCustomUserAgent(const std::string& userAgent);
    
    /// @brief Report fingerprint attempt
    void ReportFingerprintAttempt(const FingerprintDetection& detection);
    
    /// @brief Get fingerprint protection script
    [[nodiscard]] std::string GetFingerprintProtectionScript() const;

    // ========================================================================
    // COOKIE MANAGEMENT
    // ========================================================================
    
    /// @brief Should block cookie
    [[nodiscard]] bool ShouldBlockCookie(
        const std::string& cookieName,
        const std::string& cookieDomain,
        const std::string& pageDomain);
    
    /// @brief Get cookie block result
    [[nodiscard]] CookieBlockResult CheckCookie(
        const std::string& cookieName,
        const std::string& cookieDomain,
        const std::string& pageDomain);
    
    /// @brief Clear tracking cookies
    [[nodiscard]] size_t ClearTrackingCookies();

    // ========================================================================
    // HEADER PROTECTION
    // ========================================================================
    
    /// @brief Get sanitized referer
    [[nodiscard]] std::string GetSanitizedReferer(
        const std::string& originalReferer,
        const std::string& targetDomain);
    
    /// @brief Get protected headers
    [[nodiscard]] std::map<std::string, std::string> GetProtectedHeaders(
        const std::map<std::string, std::string>& originalHeaders);

    // ========================================================================
    // WHITELIST
    // ========================================================================
    
    [[nodiscard]] bool AddToWhitelist(const std::string& domain);
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& domain);
    [[nodiscard]] bool IsWhitelisted(const std::string& domain) const;
    [[nodiscard]] std::vector<std::string> GetWhitelistedDomains() const;

    // ========================================================================
    // DOMAIN STATISTICS
    // ========================================================================
    
    /// @brief Get stats for domain
    [[nodiscard]] std::optional<DomainStats> GetDomainStats(const std::string& domain);
    
    /// @brief Get top blocked domains
    [[nodiscard]] std::vector<DomainStats> GetTopBlockedDomains(size_t limit = 10);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterTrackerCallback(TrackerBlockedCallback callback);
    void RegisterCookieCallback(CookieBlockedCallback callback);
    void RegisterFingerprintCallback(FingerprintDetectedCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] TrackerBlockerStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    TrackerBlocker();
    ~TrackerBlocker();
    
    std::unique_ptr<TrackerBlockerImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetTrackerTypeName(TrackerType type) noexcept;
[[nodiscard]] std::string_view GetFingerprintTypeName(FingerprintType type) noexcept;
[[nodiscard]] std::string_view GetCookieTypeName(CookieType type) noexcept;
[[nodiscard]] std::string_view GetTrackerActionName(TrackerAction action) noexcept;
[[nodiscard]] std::string_view GetProtectionLevelName(ProtectionLevel level) noexcept;

/// @brief Detect if image is 1x1 tracking pixel
[[nodiscard]] bool IsOneByOnePixel(const std::vector<uint8_t>& imageData);

/// @brief Get random user agent for spoofing
[[nodiscard]] std::string GetRandomizedUserAgent();

/// @brief Check if domain is third-party
[[nodiscard]] bool IsThirdPartyDomain(
    const std::string& requestDomain,
    const std::string& pageDomain);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_TRACKER_CHECK(url) \
    ::ShadowStrike::WebBrowser::TrackerBlocker::Instance().IsTracker(url)

#define SS_TRACKER_GET_SAFE_UA() \
    ::ShadowStrike::WebBrowser::TrackerBlocker::Instance().GetSafeUserAgent()

#define SS_TRACKER_IS_PIXEL(buffer) \
    ::ShadowStrike::WebBrowser::TrackerBlocker::Instance().IsTrackingPixel(buffer)
