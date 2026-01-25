/**
 * ============================================================================
 * ShadowStrike NGAV - PHISHING EMAIL DETECTOR MODULE
 * ============================================================================
 *
 * @file PhishingEmailDetector.hpp
 * @brief Enterprise-grade phishing detection engine using NLP, heuristics,
 *        and machine learning for comprehensive email threat analysis.
 *
 * Provides comprehensive phishing detection including content analysis,
 * sender verification, URL analysis, and social engineering detection.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. CONTENT ANALYSIS
 *    - NLP sentiment analysis
 *    - Urgency detection
 *    - Fear/pressure tactics
 *    - Authority impersonation
 *    - Grammatical anomalies
 *    - Language inconsistencies
 *
 * 2. SENDER ANALYSIS
 *    - Domain spoofing detection
 *    - Lookalike domain detection
 *    - Display name spoofing
 *    - Envelope/header mismatch
 *    - SPF/DKIM/DMARC verification
 *    - Sender reputation
 *
 * 3. URL ANALYSIS
 *    - Malicious URL detection
 *    - Shortened URL expansion
 *    - Homograph attack detection
 *    - URL/text mismatch
 *    - Redirect chain analysis
 *    - Brand impersonation
 *
 * 4. VISUAL ANALYSIS
 *    - Logo impersonation
 *    - Brand spoofing
 *    - Visual similarity
 *    - HTML template matching
 *    - Rendering anomalies
 *
 * 5. CAMPAIGN DETECTION
 *    - BEC (Business Email Compromise)
 *    - CEO fraud
 *    - Invoice fraud
 *    - Credential harvesting
 *    - Spear phishing
 *    - Whaling attacks
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for URL/domain IOCs
 * - PatternStore for detection patterns
 * - Whitelist for trusted senders
 * - ML models for classification
 *
 * @note Uses ensemble of detection techniques.
 * @note Supports real-time and batch analysis.
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

#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Email {
    class PhishingEmailDetectorImpl;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PhishingConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief High-confidence phishing threshold
    inline constexpr int HIGH_CONFIDENCE_THRESHOLD = 80;
    
    /// @brief Medium-confidence phishing threshold
    inline constexpr int MEDIUM_CONFIDENCE_THRESHOLD = 50;
    
    /// @brief Maximum URLs to analyze
    inline constexpr size_t MAX_URLS_TO_ANALYZE = 100;
    
    /// @brief Commonly spoofed brands
    inline constexpr const char* COMMONLY_SPOOFED_BRANDS[] = {
        "microsoft", "office365", "outlook", "onedrive",
        "google", "gmail", "drive",
        "apple", "icloud", "itunes",
        "amazon", "aws", "prime",
        "paypal", "venmo", "stripe",
        "facebook", "instagram", "whatsapp",
        "netflix", "spotify", "adobe",
        "dropbox", "linkedin", "twitter",
        "dhl", "fedex", "ups", "usps",
        "chase", "wellsfargo", "bankofamerica"
    };

}  // namespace PhishingConstants

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
 * @brief Phishing verdict
 */
enum class PhishingVerdict : uint8_t {
    Clean               = 0,    ///< Not phishing
    Suspicious          = 1,    ///< Possibly phishing
    Phishing            = 2,    ///< Confirmed phishing
    Spear_Phishing      = 3,    ///< Targeted phishing
    BEC                 = 4,    ///< Business Email Compromise
    Whaling             = 5,    ///< Executive targeting
    CredentialHarvest   = 6,    ///< Credential harvesting
    Scam                = 7     ///< Generic scam
};

/**
 * @brief Phishing indicator type
 */
enum class PhishingIndicator : uint32_t {
    None                    = 0,
    UrgencyLanguage         = 1 << 0,
    FearTactics             = 1 << 1,
    PressureTactics         = 1 << 2,
    AuthorityImpersonation  = 1 << 3,
    SpoofedDomain           = 1 << 4,
    LookalikeDomain         = 1 << 5,
    DisplayNameSpoof        = 1 << 6,
    EnvelopeMismatch        = 1 << 7,
    MaliciousURL            = 1 << 8,
    ShortenedURL            = 1 << 9,
    HomographAttack         = 1 << 10,
    URLTextMismatch         = 1 << 11,
    BrandImpersonation      = 1 << 12,
    SuspiciousAttachment    = 1 << 13,
    GrammaticalErrors       = 1 << 14,
    LanguageInconsistency   = 1 << 15,
    SuspiciousReplyTo       = 1 << 16,
    NewSender               = 1 << 17,
    DKIMFailure             = 1 << 18,
    SPFFailure              = 1 << 19,
    DMARCFailure            = 1 << 20,
    IPReputation            = 1 << 21
};

/**
 * @brief Campaign type
 */
enum class PhishingCampaignType : uint8_t {
    Unknown             = 0,
    Generic             = 1,    ///< Generic phishing
    SpearPhishing       = 2,    ///< Targeted individual
    Whaling             = 3,    ///< Executive targeting
    BEC                 = 4,    ///< Business Email Compromise
    CEOFraud            = 5,    ///< CEO impersonation
    InvoiceFraud        = 6,    ///< Fake invoices
    PayrollDiversion    = 7,    ///< Payroll redirect
    W2Scam              = 8,    ///< Tax form theft
    VendorImpersonation = 9,    ///< Vendor fraud
    TechSupport         = 10,   ///< Tech support scam
    RomanceScam         = 11,   ///< Romance fraud
    LotteryScam         = 12    ///< Lottery/prize scam
};

/**
 * @brief URL analysis result
 */
enum class URLVerdict : uint8_t {
    Safe                = 0,
    Suspicious          = 1,
    Malicious           = 2,
    Phishing            = 3,
    Redirect            = 4,
    Unknown             = 255
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Analyzing       = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Phishing indicators found
 */
struct PhishingIndicators {
    /// @brief Has urgency language
    bool hasUrgency = false;
    
    /// @brief Has fear/threat language
    bool hasFearTactics = false;
    
    /// @brief Has spoofed domain
    bool hasSpoofedDomain = false;
    
    /// @brief Has lookalike domain
    bool hasLookalikeDomain = false;
    
    /// @brief Has display name spoof
    bool hasDisplayNameSpoof = false;
    
    /// @brief Has suspicious links
    bool hasSuspiciousLinks = false;
    
    /// @brief Has mismatched sender
    bool hasMismatchedSender = false;
    
    /// @brief Has homograph attack
    bool hasHomographAttack = false;
    
    /// @brief Has brand impersonation
    bool hasBrandImpersonation = false;
    
    /// @brief Impersonated brand
    std::string impersonatedBrand;
    
    /// @brief NLP suspicion score (0-100)
    int nlpSuspicionScore = 0;
    
    /// @brief URL analysis score (0-100)
    int urlAnalysisScore = 0;
    
    /// @brief Sender reputation score (0-100)
    int senderReputationScore = 100;
    
    /// @brief All indicators (bitmask)
    PhishingIndicator allIndicators = PhishingIndicator::None;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief URL analysis result
 */
struct URLAnalysisResult {
    /// @brief Original URL
    std::string originalUrl;
    
    /// @brief Expanded URL (if shortened)
    std::string expandedUrl;
    
    /// @brief Final URL (after redirects)
    std::string finalUrl;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Verdict
    URLVerdict verdict = URLVerdict::Unknown;
    
    /// @brief Is shortened URL
    bool isShortened = false;
    
    /// @brief Has redirects
    bool hasRedirects = false;
    
    /// @brief Redirect count
    int redirectCount = 0;
    
    /// @brief Uses HTTPS
    bool usesHTTPS = false;
    
    /// @brief Has homograph characters
    bool hasHomographChars = false;
    
    /// @brief Impersonates known brand
    bool impersonatesBrand = false;
    
    /// @brief Impersonated brand name
    std::string impersonatedBrand = false;
    
    /// @brief Domain age (days, -1 = unknown)
    int domainAgeDays = -1;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Text displayed for URL (if different)
    std::string displayText;
    
    /// @brief URL text mismatch
    bool textMismatch = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Sender analysis result
 */
struct SenderAnalysisResult {
    /// @brief Sender email
    std::string senderEmail;
    
    /// @brief Display name
    std::string displayName;
    
    /// @brief From domain
    std::string fromDomain;
    
    /// @brief Envelope domain
    std::string envelopeDomain;
    
    /// @brief Reply-To address
    std::string replyTo;
    
    /// @brief Return-Path
    std::string returnPath;
    
    /// @brief SPF result
    bool spfPass = true;
    
    /// @brief DKIM result
    bool dkimPass = true;
    
    /// @brief DMARC result
    bool dmarcPass = true;
    
    /// @brief Is known sender
    bool isKnownSender = false;
    
    /// @brief Is first-time sender
    bool isFirstTimeSender = false;
    
    /// @brief Display name spoofing detected
    bool displayNameSpoofing = false;
    
    /// @brief Domain reputation (0-100)
    int domainReputation = 50;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Complete phishing analysis result
 */
struct PhishingAnalysisResult {
    /// @brief Verdict
    PhishingVerdict verdict = PhishingVerdict::Clean;
    
    /// @brief Is phishing
    bool isPhishing = false;
    
    /// @brief Confidence score (0-100)
    int confidenceScore = 0;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Campaign type
    PhishingCampaignType campaignType = PhishingCampaignType::Unknown;
    
    /// @brief Detected indicators
    PhishingIndicators indicators;
    
    /// @brief URL analysis results
    std::vector<URLAnalysisResult> urlAnalyses;
    
    /// @brief Sender analysis
    SenderAnalysisResult senderAnalysis;
    
    /// @brief Matched patterns
    std::vector<std::string> matchedPatterns;
    
    /// @brief Target brand (if impersonation)
    std::string targetBrand;
    
    /// @brief Threat intelligence matches
    std::vector<std::string> threatIntelMatches;
    
    /// @brief Analysis summary
    std::string analysisSummary;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    /// @brief Analysis time
    SystemTimePoint analysisTime;
    
    /// @brief Analysis duration
    std::chrono::microseconds analysisDuration{0};
    
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct PhishingStatistics {
    std::atomic<uint64_t> totalAnalyzed{0};
    std::atomic<uint64_t> phishingDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> cleanDetected{0};
    std::atomic<uint64_t> becDetected{0};
    std::atomic<uint64_t> spearPhishingDetected{0};
    std::atomic<uint64_t> urlsAnalyzed{0};
    std::atomic<uint64_t> maliciousUrlsDetected{0};
    std::atomic<uint64_t> homographsDetected{0};
    std::atomic<uint64_t> brandImpersonationDetected{0};
    std::array<std::atomic<uint64_t>, 16> byCampaignType{};
    std::array<std::atomic<uint64_t>, 32> byIndicator{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct PhishingDetectorConfiguration {
    /// @brief Enable detector
    bool enabled = true;
    
    /// @brief Enable NLP analysis
    bool enableNLPAnalysis = true;
    
    /// @brief Enable URL analysis
    bool enableURLAnalysis = true;
    
    /// @brief Enable sender verification
    bool enableSenderVerification = true;
    
    /// @brief Expand shortened URLs
    bool expandShortenedURLs = true;
    
    /// @brief Check URL reputation
    bool checkURLReputation = true;
    
    /// @brief Check domain age
    bool checkDomainAge = true;
    
    /// @brief Block new domains
    bool blockNewDomains = false;
    
    /// @brief New domain threshold (days)
    int newDomainThresholdDays = 30;
    
    /// @brief Phishing threshold score
    int phishingThreshold = PhishingConstants::HIGH_CONFIDENCE_THRESHOLD;
    
    /// @brief Suspicious threshold score
    int suspiciousThreshold = PhishingConstants::MEDIUM_CONFIDENCE_THRESHOLD;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AnalysisResultCallback = std::function<void(const PhishingAnalysisResult&)>;
using URLAnalysisCallback = std::function<void(const URLAnalysisResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PHISHING EMAIL DETECTOR CLASS
// ============================================================================

/**
 * @class PhishingEmailDetector
 * @brief Enterprise phishing detection engine
 */
class PhishingEmailDetector final {
public:
    [[nodiscard]] static PhishingEmailDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PhishingEmailDetector(const PhishingEmailDetector&) = delete;
    PhishingEmailDetector& operator=(const PhishingEmailDetector&) = delete;
    PhishingEmailDetector(PhishingEmailDetector&&) = delete;
    PhishingEmailDetector& operator=(PhishingEmailDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const PhishingDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const PhishingDetectorConfiguration& config);
    [[nodiscard]] PhishingDetectorConfiguration GetConfiguration() const;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Analyze email content
    [[nodiscard]] PhishingAnalysisResult AnalyzeContent(
        const std::string& subject,
        const std::string& body,
        const std::string& sender,
        const std::vector<std::string>& urls = {});
    
    /// @brief Analyze email with full headers
    [[nodiscard]] PhishingAnalysisResult AnalyzeEmail(
        const std::string& subject,
        const std::string& bodyText,
        const std::string& bodyHtml,
        const std::string& sender,
        const std::string& replyTo,
        const std::map<std::string, std::string>& headers);
    
    /// @brief Check if URL is malicious
    [[nodiscard]] URLAnalysisResult AnalyzeURL(const std::string& url);
    
    /// @brief Batch analyze URLs
    [[nodiscard]] std::vector<URLAnalysisResult> AnalyzeURLs(
        const std::vector<std::string>& urls);
    
    /// @brief Analyze sender
    [[nodiscard]] SenderAnalysisResult AnalyzeSender(
        const std::string& senderEmail,
        const std::string& displayName,
        const std::map<std::string, std::string>& headers = {});

    // ========================================================================
    // QUICK CHECKS
    // ========================================================================
    
    /// @brief Quick check if link is malicious
    [[nodiscard]] bool IsMaliciousLink(const std::string& url);
    
    /// @brief Check for homograph attack
    [[nodiscard]] bool IsHomographAttack(const std::string& domain);
    
    /// @brief Check if domain impersonates brand
    [[nodiscard]] std::optional<std::string> DetectBrandImpersonation(
        const std::string& domain);
    
    /// @brief Get last analysis
    [[nodiscard]] PhishingIndicators GetLastAnalysis() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAnalysisCallback(AnalysisResultCallback callback);
    void RegisterURLCallback(URLAnalysisCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] PhishingStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PhishingEmailDetector();
    ~PhishingEmailDetector();
    
    std::unique_ptr<PhishingEmailDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPhishingVerdictName(PhishingVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetPhishingIndicatorName(PhishingIndicator indicator) noexcept;
[[nodiscard]] std::string_view GetCampaignTypeName(PhishingCampaignType type) noexcept;
[[nodiscard]] std::string_view GetURLVerdictName(URLVerdict verdict) noexcept;
[[nodiscard]] std::vector<std::string> ExtractURLsFromText(const std::string& text);
[[nodiscard]] std::vector<std::string> ExtractURLsFromHTML(const std::string& html);
[[nodiscard]] bool ContainsHomographCharacters(const std::string& text);

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_PHISHING_ANALYZE(subject, body, sender) \
    ::ShadowStrike::Email::PhishingEmailDetector::Instance().AnalyzeContent(subject, body, sender)

#define SS_PHISHING_CHECK_URL(url) \
    ::ShadowStrike::Email::PhishingEmailDetector::Instance().IsMaliciousLink(url)