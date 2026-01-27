/**
 * ============================================================================
 * ShadowStrike NGAV - WEB PHISHING DETECTOR MODULE
 * ============================================================================
 *
 * @file PhishingDetector.hpp
 * @brief Enterprise-grade web phishing detection using visual analysis, NLP,
 *        and heuristic techniques for comprehensive website threat analysis.
 *
 * Provides multi-layered phishing detection including URL analysis, visual
 * similarity, form analysis, SSL certificate verification, and brand protection.
 *
 * DETECTION TECHNIQUES:
 * =====================
 *
 * 1. URL ANALYSIS
 *    - Homograph/IDN attack detection
 *    - Typosquatting detection
 *    - Punycode analysis
 *    - URL path analysis
 *    - Subdomain analysis
 *    - Domain age checking
 *    - DGA (Domain Generation Algorithm)
 *
 * 2. VISUAL ANALYSIS
 *    - Logo comparison
 *    - Color scheme matching
 *    - Layout fingerprinting
 *    - Screenshot comparison
 *    - Brand element detection
 *    - Favicon analysis
 *
 * 3. CONTENT ANALYSIS
 *    - Form field analysis
 *    - Login form detection
 *    - Input type analysis
 *    - Hidden field detection
 *    - JavaScript analysis
 *    - Credential harvesting patterns
 *
 * 4. SSL/TLS ANALYSIS
 *    - Certificate validation
 *    - Certificate transparency
 *    - CA verification
 *    - Certificate age
 *    - SAN verification
 *
 * 5. BRAND PROTECTION
 *    - Known brand detection
 *    - Impersonation scoring
 *    - Domain similarity
 *    - Logo matching
 *    - Legal entity verification
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for known phishing URLs
 * - PatternStore for detection patterns
 * - SafeBrowsingAPI for real-time checks
 *
 * @note Thread-safe singleton design.
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

namespace ShadowStrike::WebBrowser {
    class PhishingDetectorImpl;
}

namespace ShadowStrike {
namespace WebBrowser {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace PhishingDetectorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Phishing score threshold
    inline constexpr double PHISHING_THRESHOLD = 0.7;
    
    /// @brief Suspicious score threshold
    inline constexpr double SUSPICIOUS_THRESHOLD = 0.4;
    
    /// @brief Maximum URL length
    inline constexpr size_t MAX_URL_LENGTH = 8192;
    
    /// @brief Maximum HTML content size
    inline constexpr size_t MAX_HTML_SIZE = 5 * 1024 * 1024;  // 5MB

    /// @brief Commonly phished brands
    inline constexpr const char* PROTECTED_BRANDS[] = {
        "microsoft", "office365", "outlook", "azure",
        "google", "gmail", "drive",
        "apple", "icloud",
        "amazon", "aws",
        "paypal", "stripe", "square",
        "facebook", "instagram", "whatsapp",
        "netflix", "spotify",
        "dropbox", "linkedin",
        "chase", "wellsfargo", "bankofamerica", "citi",
        "fedex", "ups", "dhl", "usps"
    };

    /// @brief Homograph characters (Cyrillic lookalikes)
    inline constexpr wchar_t HOMOGRAPH_CHARS[][2] = {
        {L'а', L'a'}, {L'е', L'e'}, {L'о', L'o'}, {L'р', L'p'},
        {L'с', L'c'}, {L'х', L'x'}, {L'у', L'y'}, {L'і', L'i'}
    };

}  // namespace PhishingDetectorConstants

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
    Safe            = 0,    ///< Legitimate site
    Suspicious      = 1,    ///< Possibly phishing
    Phishing        = 2,    ///< Confirmed phishing
    Spear_Phishing  = 3,    ///< Targeted phishing
    BrandSpoof      = 4,    ///< Brand impersonation
    KnownBad        = 5     ///< Known phishing site
};

/**
 * @brief Phishing indicator
 */
enum class PhishingIndicator : uint32_t {
    None                    = 0,
    HomographAttack         = 1 << 0,
    Typosquatting           = 1 << 1,
    SuspiciousDomain        = 1 << 2,
    NewDomain               = 1 << 3,
    DGADomain               = 1 << 4,
    IPAddressURL            = 1 << 5,
    LongURL                 = 1 << 6,
    SuspiciousPath          = 1 << 7,
    HiddenURL               = 1 << 8,
    NoHTTPS                 = 1 << 9,
    InvalidCertificate      = 1 << 10,
    SelfSignedCert          = 1 << 11,
    FreeCertificate         = 1 << 12,
    BrandImpersonation      = 1 << 13,
    LoginFormHTTP           = 1 << 14,
    PasswordFieldDetected   = 1 << 15,
    SuspiciousFormAction    = 1 << 16,
    HiddenFormFields        = 1 << 17,
    ExternalFormAction      = 1 << 18,
    LogoMismatch            = 1 << 19,
    VisualSimilarity        = 1 << 20,
    SuspiciousJavaScript    = 1 << 21,
    PopupBlocker            = 1 << 22,
    RedirectChain           = 1 << 23,
    ThreatIntelMatch        = 1 << 24
};

/**
 * @brief Attack type
 */
enum class PhishingAttackType : uint8_t {
    Unknown             = 0,
    Credential_Harvest  = 1,    ///< Credential stealing
    Financial           = 2,    ///< Financial fraud
    Corporate           = 3,    ///< Corporate espionage
    Social_Engineering  = 4,    ///< Social manipulation
    Technical_Support   = 5,    ///< Tech support scam
    Romance_Scam        = 6,    ///< Romance fraud
    Lottery_Scam        = 7     ///< Prize scam
};

/**
 * @brief Form field type
 */
enum class FormFieldType : uint8_t {
    Unknown         = 0,
    Username        = 1,
    Email           = 2,
    Password        = 3,
    CreditCard      = 4,
    SSN             = 5,
    Phone           = 6,
    Address         = 7,
    DateOfBirth     = 8,
    Hidden          = 9,
    OTP             = 10,
    PIN             = 11
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
 * @brief URL analysis detail
 */
struct URLAnalysisDetail {
    /// @brief Original URL
    std::string originalUrl;
    
    /// @brief Normalized URL
    std::string normalizedUrl;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief TLD
    std::string tld;
    
    /// @brief Subdomain
    std::string subdomain;
    
    /// @brief Path
    std::string path;
    
    /// @brief Query string
    std::string query;
    
    /// @brief Is HTTPS
    bool isHTTPS = false;
    
    /// @brief Is IP address
    bool isIPAddress = false;
    
    /// @brief Has port
    bool hasPort = false;
    
    /// @brief Port number
    uint16_t port = 0;
    
    /// @brief URL length
    size_t urlLength = 0;
    
    /// @brief Subdomain count
    int subdomainCount = 0;
    
    /// @brief Special character count
    int specialCharCount = 0;
    
    /// @brief Entropy score
    double entropyScore = 0.0;
    
    /// @brief Detected punycode
    std::string punycodeDomain;
    
    /// @brief Unicode domain
    std::wstring unicodeDomain;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Homograph detection result
 */
struct HomographResult {
    /// @brief Has homograph characters
    bool hasHomograph = false;
    
    /// @brief Original domain
    std::string originalDomain;
    
    /// @brief Decoded domain
    std::string decodedDomain;
    
    /// @brief Targeted brand
    std::string targetedBrand;
    
    /// @brief Confusable characters found
    std::vector<std::pair<wchar_t, char>> confusables;
    
    /// @brief Similarity score (0-1)
    double similarityScore = 0.0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Typosquatting result
 */
struct TyposquattingResult {
    /// @brief Is typosquatting
    bool isTyposquatting = false;
    
    /// @brief Suspicious domain
    std::string suspiciousDomain;
    
    /// @brief Target domain
    std::string targetDomain;
    
    /// @brief Target brand
    std::string targetBrand;
    
    /// @brief Edit distance
    int editDistance = 0;
    
    /// @brief Typo type (swap, missing, extra, etc.)
    std::string typoType;
    
    /// @brief Similarity score
    double similarityScore = 0.0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Form analysis result
 */
struct FormAnalysisResult {
    /// @brief Has login form
    bool hasLoginForm = false;
    
    /// @brief Form count
    int formCount = 0;
    
    /// @brief Password field count
    int passwordFieldCount = 0;
    
    /// @brief Hidden field count
    int hiddenFieldCount = 0;
    
    /// @brief Form actions
    std::vector<std::string> formActions;
    
    /// @brief External form action
    bool hasExternalAction = false;
    
    /// @brief Form over HTTP
    bool formOverHTTP = false;
    
    /// @brief Detected field types
    std::vector<FormFieldType> detectedFieldTypes;
    
    /// @brief Suspicious attributes
    std::vector<std::string> suspiciousAttributes;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Visual analysis result
 */
struct VisualAnalysisResult {
    /// @brief Has brand elements
    bool hasBrandElements = false;
    
    /// @brief Detected brand
    std::string detectedBrand;
    
    /// @brief Logo match confidence
    double logoMatchConfidence = 0.0;
    
    /// @brief Color scheme match
    bool colorSchemeMatch = false;
    
    /// @brief Layout similarity
    double layoutSimilarity = 0.0;
    
    /// @brief Favicon hash
    std::string faviconHash;
    
    /// @brief Is legitimate
    bool isLegitimate = true;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Certificate analysis
 */
struct CertificateAnalysis {
    /// @brief Has certificate
    bool hasCertificate = false;
    
    /// @brief Is valid
    bool isValid = true;
    
    /// @brief Is self-signed
    bool isSelfSigned = false;
    
    /// @brief Is free certificate (Let's Encrypt, etc.)
    bool isFreeCert = false;
    
    /// @brief Subject CN
    std::string subjectCN;
    
    /// @brief Issuer
    std::string issuer;
    
    /// @brief Valid from
    SystemTimePoint validFrom;
    
    /// @brief Valid to
    SystemTimePoint validTo;
    
    /// @brief Days until expiry
    int daysUntilExpiry = 0;
    
    /// @brief Certificate age (days)
    int certificateAgeDays = 0;
    
    /// @brief SAN entries
    std::vector<std::string> sanEntries;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Phishing score result
 */
struct PhishingScore {
    /// @brief Is phishing
    bool isPhishing = false;
    
    /// @brief Score (0-1)
    double score = 0.0;
    
    /// @brief Verdict
    PhishingVerdict verdict = PhishingVerdict::Safe;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief Primary reason
    std::string reason;
    
    /// @brief Indicators (bitmask)
    PhishingIndicator indicators = PhishingIndicator::None;
    
    /// @brief Attack type
    PhishingAttackType attackType = PhishingAttackType::Unknown;
    
    /// @brief Targeted brand
    std::string targetedBrand;
    
    /// @brief URL analysis
    URLAnalysisDetail urlAnalysis;
    
    /// @brief Homograph result
    HomographResult homographResult;
    
    /// @brief Typosquatting result
    TyposquattingResult typosquattingResult;
    
    /// @brief Form analysis
    FormAnalysisResult formAnalysis;
    
    /// @brief Visual analysis
    VisualAnalysisResult visualAnalysis;
    
    /// @brief Certificate analysis
    CertificateAnalysis certificateAnalysis;
    
    /// @brief All reasons
    std::vector<std::string> allReasons;
    
    /// @brief Recommendations
    std::vector<std::string> recommendations;
    
    /// @brief Analysis duration
    std::chrono::microseconds analysisDuration{0};
    
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct PhishingDetectorStatistics {
    std::atomic<uint64_t> totalAnalyzed{0};
    std::atomic<uint64_t> phishingDetected{0};
    std::atomic<uint64_t> suspiciousDetected{0};
    std::atomic<uint64_t> safeDetected{0};
    std::atomic<uint64_t> homographsDetected{0};
    std::atomic<uint64_t> typosquattingDetected{0};
    std::atomic<uint64_t> brandImpersonationDetected{0};
    std::atomic<uint64_t> loginFormsAnalyzed{0};
    std::atomic<uint64_t> certificatesChecked{0};
    std::atomic<uint64_t> threatIntelMatches{0};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
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
    
    /// @brief Enable URL analysis
    bool enableURLAnalysis = true;
    
    /// @brief Enable homograph detection
    bool enableHomographDetection = true;
    
    /// @brief Enable typosquatting detection
    bool enableTyposquattingDetection = true;
    
    /// @brief Enable form analysis
    bool enableFormAnalysis = true;
    
    /// @brief Enable visual analysis
    bool enableVisualAnalysis = false;  // Resource intensive
    
    /// @brief Enable certificate analysis
    bool enableCertificateAnalysis = true;
    
    /// @brief Check threat intelligence
    bool checkThreatIntel = true;
    
    /// @brief Phishing threshold
    double phishingThreshold = PhishingDetectorConstants::PHISHING_THRESHOLD;
    
    /// @brief Suspicious threshold
    double suspiciousThreshold = PhishingDetectorConstants::SUSPICIOUS_THRESHOLD;
    
    /// @brief Protected brands
    std::vector<std::string> protectedBrands;
    
    /// @brief Whitelist domains
    std::vector<std::string> whitelistDomains;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using PhishingDetectionCallback = std::function<void(const std::string& url, const PhishingScore&)>;
using BrandAlertCallback = std::function<void(const std::string& brand, const std::string& url)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// PHISHING DETECTOR CLASS
// ============================================================================

/**
 * @class PhishingDetector
 * @brief Enterprise web phishing detection engine
 */
class PhishingDetector final {
public:
    [[nodiscard]] static PhishingDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    PhishingDetector(const PhishingDetector&) = delete;
    PhishingDetector& operator=(const PhishingDetector&) = delete;
    PhishingDetector(PhishingDetector&&) = delete;
    PhishingDetector& operator=(PhishingDetector&&) = delete;

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
    
    /// @brief Analyze URL for phishing
    [[nodiscard]] PhishingScore AnalyzeURL(const std::string& url);
    
    /// @brief Analyze page content
    [[nodiscard]] PhishingScore AnalyzePageContent(
        const std::string& url,
        const std::string& html);
    
    /// @brief Full analysis (URL + content)
    [[nodiscard]] PhishingScore AnalyzeFull(
        const std::string& url,
        const std::string& html,
        const std::vector<uint8_t>& screenshot = {});
    
    /// @brief Check for homograph attack
    [[nodiscard]] HomographResult CheckHomograph(const std::string& domain);
    
    /// @brief Check for typosquatting
    [[nodiscard]] TyposquattingResult CheckTyposquatting(const std::string& domain);
    
    /// @brief Analyze forms
    [[nodiscard]] FormAnalysisResult AnalyzeForms(const std::string& html);
    
    /// @brief Analyze certificate
    [[nodiscard]] CertificateAnalysis AnalyzeCertificate(const std::string& url);

    // ========================================================================
    // QUICK CHECKS
    // ========================================================================
    
    /// @brief Quick phishing check
    [[nodiscard]] bool IsPhishing(const std::string& url);
    
    /// @brief Get risk score (0-100)
    [[nodiscard]] int GetRiskScore(const std::string& url);
    
    /// @brief Check if domain impersonates brand
    [[nodiscard]] std::optional<std::string> DetectBrandImpersonation(
        const std::string& domain);
    
    /// @brief Check domain legitimacy
    [[nodiscard]] bool IsLegitimeDomain(
        const std::string& domain,
        const std::string& brand);

    // ========================================================================
    // BRAND PROTECTION
    // ========================================================================
    
    /// @brief Add protected brand
    [[nodiscard]] bool AddProtectedBrand(
        const std::string& brandName,
        const std::vector<std::string>& legitimateDomains);
    
    /// @brief Remove protected brand
    [[nodiscard]] bool RemoveProtectedBrand(const std::string& brandName);
    
    /// @brief Get protected brands
    [[nodiscard]] std::vector<std::string> GetProtectedBrands() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterDetectionCallback(PhishingDetectionCallback callback);
    void RegisterBrandAlertCallback(BrandAlertCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] PhishingDetectorStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    PhishingDetector();
    ~PhishingDetector();
    
    std::unique_ptr<PhishingDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPhishingVerdictName(PhishingVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetPhishingIndicatorName(PhishingIndicator indicator) noexcept;
[[nodiscard]] std::string_view GetAttackTypeName(PhishingAttackType type) noexcept;
[[nodiscard]] std::string_view GetFormFieldTypeName(FormFieldType type) noexcept;

/// @brief Detect homograph characters in string
[[nodiscard]] bool ContainsHomograph(const std::wstring& text);

/// @brief Calculate Levenshtein distance
[[nodiscard]] int LevenshteinDistance(
    const std::string& str1,
    const std::string& str2);

/// @brief Calculate string entropy
[[nodiscard]] double CalculateEntropy(const std::string& str);

/// @brief Extract URLs from HTML
[[nodiscard]] std::vector<std::string> ExtractURLsFromHTML(const std::string& html);

/// @brief Decode punycode domain
[[nodiscard]] std::wstring DecodePunycode(const std::string& domain);

}  // namespace WebBrowser
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_PHISHING_CHECK_URL(url) \
    ::ShadowStrike::WebBrowser::PhishingDetector::Instance().IsPhishing(url)

#define SS_PHISHING_ANALYZE(url) \
    ::ShadowStrike::WebBrowser::PhishingDetector::Instance().AnalyzeURL(url)

#define SS_PHISHING_GET_RISK(url) \
    ::ShadowStrike::WebBrowser::PhishingDetector::Instance().GetRiskScore(url)
