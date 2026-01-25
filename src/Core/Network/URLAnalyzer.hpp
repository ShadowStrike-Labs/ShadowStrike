/**
 * ============================================================================
 * ShadowStrike Core Network - URL ANALYZER (The Web Filter)
 * ============================================================================
 *
 * @file URLAnalyzer.hpp
 * @brief Enterprise-grade URL and domain analysis engine for threat detection.
 *
 * This module provides comprehensive URL and domain security analysis by
 * combining multiple detection techniques including reputation lookups,
 * pattern matching, machine learning, and heuristic analysis.
 *
 * Key Capabilities:
 * =================
 * 1. URL REPUTATION ANALYSIS
 *    - Real-time reputation lookups via ThreatIntel
 *    - Multi-vendor reputation aggregation
 *    - Category-based classification (50+ categories)
 *    - Historical reputation tracking
 *    - Whitelisting and blacklisting
 *
 * 2. PHISHING DETECTION
 *    - Brand impersonation detection
 *    - Lookalike domain detection (typosquatting)
 *    - Homograph attack detection (IDN/Punycode)
 *    - URL obfuscation detection
 *    - Form submission analysis
 *    - Credential harvesting patterns
 *
 * 3. DGA DETECTION (Domain Generation Algorithm)
 *    - Entropy-based analysis
 *    - N-gram frequency analysis
 *    - Character distribution patterns
 *    - Machine learning classification
 *    - Known DGA family fingerprinting
 *
 * 4. MALWARE DISTRIBUTION DETECTION
 *    - Drive-by download patterns
 *    - Exploit kit landing page detection
 *    - Malware hosting infrastructure
 *    - Redirect chain analysis
 *    - Payload URL patterns
 *
 * 5. C2 (COMMAND & CONTROL) DETECTION
 *    - Known C2 infrastructure
 *    - Beaconing URL patterns
 *    - Data exfiltration URLs
 *    - Callback patterns
 *    - Dynamic DNS abuse
 *
 * 6. CONTENT FILTERING
 *    - Category-based web filtering
 *    - Parental controls support
 *    - Compliance filtering (CIPA, HIPAA)
 *    - Custom category definitions
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         URLAnalyzer                                 │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │URLParser     │  │ReputationChk │  │    PhishingDetector      │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Normalize  │  │ - ThreatIntel│  │ - Brand Detection        │  │
 *   │  │ - Punycode   │  │ - Categories │  │ - Lookalike              │  │
 *   │  │ - Unescape   │  │ - Scoring    │  │ - Homograph              │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │DGADetector   │  │PatternEngine │  │    MLClassifier          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Entropy    │  │ - Aho-Coras  │  │ - URL Features           │  │
 *   │  │ - N-gram     │  │ - Regex      │  │ - Domain Features        │  │
 *   │  │ - Families   │  │ - Signatures │  │ - Ensemble               │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - NetworkMonitor: DNS query filtering
 * - Browser Extensions: Chrome/Edge/Firefox native messaging
 * - SSL Proxy: HTTPS inspection (if enabled)
 * - Email Scanner: Link extraction and analysis
 * - Sandbox: URL detonation results
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1566.002: Phishing - Spearphishing Link
 * - T1204.001: User Execution - Malicious Link
 * - T1071.001: Application Layer Protocol - Web Protocols
 * - T1568.002: Dynamic Resolution - Domain Generation Algorithms
 * - T1189: Drive-by Compromise
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Pattern matchers use thread-local state
 * - Cache operations are lock-free
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see ThreatIntel/ThreatIntelDatabase.hpp for reputation data
 * @see ThreatIntel/ThreatIntelIndex_URLMatcher.hpp for pattern matching
 * @see Utils/NetworkUtils.hpp for URL parsing utilities
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <regex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class URLAnalyzerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace URLAnalyzerConstants {

    // Version information
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // URL limits
    constexpr size_t MAX_URL_LENGTH = 8192;
    constexpr size_t MAX_DOMAIN_LENGTH = 253;
    constexpr size_t MAX_PATH_LENGTH = 4096;
    constexpr size_t MAX_QUERY_LENGTH = 2048;
    constexpr size_t MAX_LABELS = 127;

    // Cache settings
    constexpr size_t URL_CACHE_SIZE = 1000000;          // 1M URLs
    constexpr size_t DOMAIN_CACHE_SIZE = 500000;        // 500K domains
    constexpr uint32_t CACHE_TTL_CLEAN_MS = 3600000;    // 1 hour
    constexpr uint32_t CACHE_TTL_MALICIOUS_MS = 86400000; // 24 hours

    // DGA detection thresholds
    constexpr double DGA_ENTROPY_THRESHOLD = 3.5;
    constexpr double DGA_CONSONANT_RATIO = 0.75;
    constexpr size_t DGA_MIN_LENGTH = 8;
    constexpr double DGA_ML_CONFIDENCE = 0.7;

    // Phishing detection
    constexpr double PHISHING_SIMILARITY_THRESHOLD = 0.85;
    constexpr size_t MAX_REDIRECT_DEPTH = 10;
    constexpr size_t MAX_BRAND_KEYWORDS = 500;

    // Pattern matching
    constexpr size_t MAX_PATTERNS = 100000;
    constexpr size_t MAX_REGEX_PATTERNS = 1000;

    // Scoring
    constexpr int SCORE_THRESHOLD_SAFE = 20;
    constexpr int SCORE_THRESHOLD_SUSPICIOUS = 50;
    constexpr int SCORE_THRESHOLD_MALICIOUS = 75;

}  // namespace URLAnalyzerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum URLCategory
 * @brief URL/Domain categorization.
 */
enum class URLCategory : uint8_t {
    // Security categories
    SAFE = 0,
    UNKNOWN = 1,
    SUSPICIOUS = 2,
    PHISHING = 3,
    MALWARE_DIST = 4,          ///< Malware distribution
    C2 = 5,                    ///< Command and control
    EXPLOIT_KIT = 6,           ///< Exploit kit landing
    CRYPTOMINING = 7,          ///< Cryptocurrency mining
    RANSOMWARE = 8,            ///< Ransomware infrastructure
    BOTNET = 9,                ///< Botnet C2
    SPAM = 10,                 ///< Spam source
    SCAM = 11,                 ///< Scam/fraud
    TYPOSQUATTING = 12,        ///< Typosquatting domain
    DGA = 13,                  ///< DGA-generated domain

    // Content categories
    ADULT = 20,                ///< Adult content
    GAMBLING = 21,             ///< Gambling
    DRUGS = 22,                ///< Drug-related
    WEAPONS = 23,              ///< Weapons
    VIOLENCE = 24,             ///< Violence/gore
    HATE_SPEECH = 25,          ///< Hate speech

    // Application categories
    SOCIAL_MEDIA = 30,
    STREAMING = 31,
    GAMING = 32,
    SHOPPING = 33,
    NEWS = 34,
    FINANCE = 35,
    HEALTHCARE = 36,
    EDUCATION = 37,
    GOVERNMENT = 38,
    BUSINESS = 39,

    // Technical categories
    CDN = 40,                  ///< Content delivery network
    CLOUD_STORAGE = 41,
    WEBMAIL = 42,
    SEARCH_ENGINE = 43,
    ADVERTISING = 44,
    ANALYTICS = 45,
    VPN_PROXY = 46,
    TOR = 47,
    FILE_SHARING = 48,
    REMOTE_ACCESS = 49,

    // Other
    PARKED = 50,               ///< Parked domain
    NEWLY_REGISTERED = 51,     ///< Recently registered
    DYNAMIC_DNS = 52,          ///< Dynamic DNS
    URL_SHORTENER = 53,        ///< URL shortening service
    PASTEBIN = 54,             ///< Paste services

    CUSTOM = 100,              ///< Custom category
    CATEGORY_COUNT = 101
};

/**
 * @enum ThreatType
 * @brief Specific threat type detected.
 */
enum class ThreatType : uint8_t {
    NONE = 0,
    PHISHING_GENERIC = 1,
    PHISHING_BANKING = 2,
    PHISHING_SOCIAL = 3,
    PHISHING_EMAIL = 4,
    PHISHING_CORPORATE = 5,
    MALWARE_DOWNLOAD = 10,
    MALWARE_DROPPER = 11,
    MALWARE_PAYLOAD = 12,
    EXPLOIT_KIT_LANDING = 20,
    EXPLOIT_KIT_GATE = 21,
    EXPLOIT_KIT_PAYLOAD = 22,
    C2_BEACON = 30,
    C2_EXFILTRATION = 31,
    C2_COMMAND = 32,
    DGA_DOMAIN = 40,
    FAST_FLUX = 41,
    DOMAIN_SHADOWING = 42,
    HOMOGRAPH = 50,
    TYPOSQUAT = 51,
    COMBOSQUAT = 52,
    CREDENTIAL_HARVEST = 60,
    DRIVE_BY_DOWNLOAD = 61,
    REDIRECT_CHAIN = 62
};

/**
 * @enum VerdictSeverity
 * @brief Severity level of verdict.
 */
enum class VerdictSeverity : uint8_t {
    CLEAN = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

/**
 * @enum DetectionMethod
 * @brief How the threat was detected.
 */
enum class DetectionMethod : uint8_t {
    UNKNOWN = 0,
    REPUTATION = 1,            ///< Known bad reputation
    PATTERN_MATCH = 2,         ///< Pattern/signature match
    HEURISTIC = 3,             ///< Heuristic analysis
    ML_CLASSIFIER = 4,         ///< Machine learning
    DGA_ANALYSIS = 5,          ///< DGA detection
    BRAND_DETECTION = 6,       ///< Brand impersonation
    HOMOGRAPH = 7,             ///< Homograph detection
    REDIRECT_ANALYSIS = 8,     ///< Redirect chain analysis
    SANDBOX = 9,               ///< Sandbox detonation
    COMMUNITY = 10,            ///< Community report
    MANUAL = 11                ///< Manual addition
};

/**
 * @enum URLScheme
 * @brief URL scheme/protocol.
 */
enum class URLScheme : uint8_t {
    UNKNOWN = 0,
    HTTP = 1,
    HTTPS = 2,
    FTP = 3,
    FTPS = 4,
    SFTP = 5,
    FILE = 6,
    MAILTO = 7,
    DATA = 8,
    JAVASCRIPT = 9,
    CUSTOM = 10
};

/**
 * @enum FilterAction
 * @brief Action to take based on analysis.
 */
enum class FilterAction : uint8_t {
    ALLOW = 0,
    BLOCK = 1,
    WARN = 2,                  ///< Allow with warning
    MONITOR = 3,               ///< Allow but log
    SANDBOX = 4,               ///< Detonate in sandbox
    CHALLENGE = 5              ///< CAPTCHA or similar
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ParsedURL
 * @brief Fully parsed URL components.
 */
struct alignas(64) ParsedURL {
    // Original
    std::string originalUrl;
    std::string normalizedUrl;

    // Components
    URLScheme scheme{ URLScheme::UNKNOWN };
    std::string schemeString;
    std::string username;
    std::string password;
    std::string host;                            ///< Hostname or IP
    std::string hostNormalized;                  ///< Lowercase, punycode decoded
    uint16_t port{ 0 };
    uint16_t defaultPort{ 0 };
    std::string path;
    std::string pathNormalized;                  ///< URL decoded, normalized
    std::string query;
    std::string fragment;

    // Domain breakdown
    std::string tld;                             ///< Top-level domain
    std::string effectiveTld;                    ///< Public suffix (e.g., co.uk)
    std::string registeredDomain;                ///< Registered domain
    std::string subdomain;                       ///< Subdomain portion
    std::vector<std::string> labels;             ///< Domain labels

    // Flags
    bool isIP{ false };                          ///< Host is IP address
    bool isIPv6{ false };
    bool isLocalhost{ false };
    bool isPrivateIP{ false };
    bool hasPort{ false };
    bool hasCredentials{ false };
    bool isPunycode{ false };                    ///< Contains punycode (xn--)
    bool isValid{ false };

    // Security indicators
    bool hasDataUri{ false };
    bool hasJavaScript{ false };
    bool hasEncodedChars{ false };
    bool hasDoubleEncoding{ false };
    bool hasSuspiciousChars{ false };
    bool hasExcessiveSubdomains{ false };
    bool hasLongPath{ false };
};

/**
 * @struct URLFeatures
 * @brief Extracted features for ML classification.
 */
struct alignas(64) URLFeatures {
    // Length features
    size_t urlLength{ 0 };
    size_t domainLength{ 0 };
    size_t pathLength{ 0 };
    size_t queryLength{ 0 };
    size_t subdomainLength{ 0 };

    // Count features
    size_t dotCount{ 0 };
    size_t slashCount{ 0 };
    size_t digitCount{ 0 };
    size_t specialCharCount{ 0 };
    size_t hyphenCount{ 0 };
    size_t underscoreCount{ 0 };
    size_t atSymbolCount{ 0 };
    size_t queryParamCount{ 0 };
    size_t labelCount{ 0 };

    // Ratio features
    double digitRatio{ 0.0 };
    double letterRatio{ 0.0 };
    double specialRatio{ 0.0 };
    double consonantRatio{ 0.0 };
    double vowelRatio{ 0.0 };

    // Entropy features
    double domainEntropy{ 0.0 };
    double pathEntropy{ 0.0 };
    double queryEntropy{ 0.0 };
    double subdomainEntropy{ 0.0 };

    // N-gram features
    double bigramFrequency{ 0.0 };
    double trigramFrequency{ 0.0 };
    uint32_t uncommonBigrams{ 0 };

    // Boolean features
    bool hasIP{ false };
    bool hasPort{ false };
    bool hasCredentials{ false };
    bool hasSuspiciousTLD{ false };
    bool hasKnownBrand{ false };
    bool isPunycode{ false };
    bool hasDoubleExtension{ false };
    bool hasExecutableExtension{ false };

    // Derived scores
    double dgaScore{ 0.0 };
    double phishingScore{ 0.0 };
    double malwareScore{ 0.0 };
};

/**
 * @struct BrandMatch
 * @brief Brand/company match for phishing detection.
 */
struct alignas(32) BrandMatch {
    std::string brandName;
    std::string legitimateDomain;
    double similarityScore{ 0.0 };
    std::string matchedTerm;
    bool isExactMatch{ false };
    bool inDomain{ false };
    bool inPath{ false };
    bool inSubdomain{ false };
};

/**
 * @struct HomographAnalysis
 * @brief IDN homograph attack analysis.
 */
struct alignas(32) HomographAnalysis {
    std::string originalDomain;
    std::string punycodeDecoded;
    std::string asciiEquivalent;                 ///< What it looks like
    bool containsHomographs{ false };
    std::vector<std::pair<char32_t, char>> confusables; ///< Unicode → ASCII
    double deceptionScore{ 0.0 };
    std::string targetedBrand;
};

/**
 * @struct RedirectInfo
 * @brief Information about URL redirect.
 */
struct alignas(64) RedirectInfo {
    std::string sourceUrl;
    std::string targetUrl;
    uint16_t httpStatus{ 0 };
    std::chrono::system_clock::time_point timestamp;
    bool isCrossOrigin{ false };
    bool isHTTPSDowngrade{ false };
};

/**
 * @struct RedirectChainAnalysis
 * @brief Analysis of redirect chain.
 */
struct alignas(64) RedirectChainAnalysis {
    std::vector<RedirectInfo> redirects;
    std::string finalUrl;
    size_t chainLength{ 0 };
    bool hasSuspiciousRedirect{ false };
    bool hasHTTPSDowngrade{ false };
    bool hasCrossOriginRedirect{ false };
    bool hasURLShortener{ false };
    bool exceededMaxDepth{ false };
    std::vector<std::string> suspiciousDomains;
};

/**
 * @struct URLVerdict
 * @brief Complete analysis verdict for a URL.
 */
struct alignas(128) URLVerdict {
    // Primary verdict
    bool isBlocked{ false };
    bool isSuspicious{ false };
    URLCategory category{ URLCategory::UNKNOWN };
    VerdictSeverity severity{ VerdictSeverity::CLEAN };
    FilterAction recommendedAction{ FilterAction::ALLOW };

    // Threat details
    ThreatType threatType{ ThreatType::NONE };
    std::string threatName;                      ///< e.g., "Phish.Paypal.Fake"
    std::string threatFamily;
    std::vector<std::string> mitreIds;

    // Confidence
    int confidenceScore{ 0 };                    ///< 0-100
    DetectionMethod detectionMethod{ DetectionMethod::UNKNOWN };
    std::string matchedPattern;
    std::string matchedSignature;

    // Additional details
    std::optional<BrandMatch> brandMatch;
    std::optional<HomographAnalysis> homographAnalysis;
    std::optional<RedirectChainAnalysis> redirectAnalysis;

    // Features (for debugging/ML)
    std::optional<URLFeatures> features;

    // Reputation
    uint8_t reputationScore{ 50 };               ///< 0-100 (50 = unknown)
    std::string reputationSource;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    uint64_t globalPrevalence{ 0 };

    // Processing info
    std::chrono::microseconds analysisTime{ 0 };
    bool fromCache{ false };
    std::string analyzedUrl;

    // Multiple categories (if applicable)
    std::vector<URLCategory> additionalCategories;
};

/**
 * @struct DomainVerdict
 * @brief Simplified verdict for domain-only analysis.
 */
struct alignas(64) DomainVerdict {
    bool isBlocked{ false };
    URLCategory category{ URLCategory::UNKNOWN };
    std::string threatName;
    int confidenceScore{ 0 };
    bool isDGA{ false };
    std::string dgaFamily;
    uint8_t reputationScore{ 50 };
    std::chrono::microseconds analysisTime{ 0 };
    bool fromCache{ false };
};

/**
 * @struct URLAnalyzerConfig
 * @brief Configuration for URL analyzer.
 */
struct alignas(64) URLAnalyzerConfig {
    // Feature toggles
    bool enabled{ true };
    bool enableReputation{ true };
    bool enablePatternMatching{ true };
    bool enableDGADetection{ true };
    bool enablePhishingDetection{ true };
    bool enableHomographDetection{ true };
    bool enableMLClassification{ true };
    bool enableContentFiltering{ false };

    // Detection thresholds
    int blockThreshold{ URLAnalyzerConstants::SCORE_THRESHOLD_MALICIOUS };
    int warnThreshold{ URLAnalyzerConstants::SCORE_THRESHOLD_SUSPICIOUS };
    double dgaThreshold{ URLAnalyzerConstants::DGA_ML_CONFIDENCE };
    double phishingThreshold{ URLAnalyzerConstants::PHISHING_SIMILARITY_THRESHOLD };

    // Content filtering categories to block
    std::vector<URLCategory> blockedCategories;

    // Whitelisting
    std::vector<std::string> whitelistedDomains;
    std::vector<std::string> whitelistedPatterns;
    bool whitelistSubdomains{ true };

    // Blacklisting
    std::vector<std::string> blacklistedDomains;
    std::vector<std::string> blacklistedPatterns;

    // Brand protection
    std::vector<std::pair<std::string, std::string>> protectedBrands; ///< name, domain

    // Performance
    bool enableCaching{ true };
    size_t maxCacheSize{ URLAnalyzerConstants::URL_CACHE_SIZE };
    uint32_t cacheTTLMs{ URLAnalyzerConstants::CACHE_TTL_CLEAN_MS };

    // Redirect handling
    bool followRedirects{ false };
    size_t maxRedirectDepth{ URLAnalyzerConstants::MAX_REDIRECT_DEPTH };

    // Logging
    bool logAllAnalysis{ false };
    bool logBlockedOnly{ true };

    // Factory methods
    static URLAnalyzerConfig CreateDefault() noexcept;
    static URLAnalyzerConfig CreateHighSecurity() noexcept;
    static URLAnalyzerConfig CreatePerformance() noexcept;
    static URLAnalyzerConfig CreateContentFiltering() noexcept;
};

/**
 * @struct URLAnalyzerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) URLAnalyzerStatistics {
    // Analysis counts
    std::atomic<uint64_t> totalURLsAnalyzed{ 0 };
    std::atomic<uint64_t> totalDomainsAnalyzed{ 0 };
    std::atomic<uint64_t> urlsBlocked{ 0 };
    std::atomic<uint64_t> urlsWarned{ 0 };
    std::atomic<uint64_t> urlsAllowed{ 0 };

    // Detection counts
    std::atomic<uint64_t> phishingDetected{ 0 };
    std::atomic<uint64_t> malwareDetected{ 0 };
    std::atomic<uint64_t> c2Detected{ 0 };
    std::atomic<uint64_t> dgaDetected{ 0 };
    std::atomic<uint64_t> homographDetected{ 0 };

    // Category counts
    std::array<std::atomic<uint64_t>, static_cast<size_t>(URLCategory::CATEGORY_COUNT)> categoryHits;

    // Cache statistics
    std::atomic<uint64_t> cacheHits{ 0 };
    std::atomic<uint64_t> cacheMisses{ 0 };
    std::atomic<uint32_t> cacheSize{ 0 };

    // Performance
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };
    std::atomic<uint64_t> maxAnalysisTimeUs{ 0 };
    std::atomic<uint64_t> analysisPerSecond{ 0 };

    // Errors
    std::atomic<uint64_t> parseErrors{ 0 };
    std::atomic<uint64_t> analysisErrors{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for URL analysis completion.
 */
using URLAnalysisCallback = std::function<void(
    const std::string& url,
    const URLVerdict& verdict
)>;

/**
 * @brief Callback for threat detection.
 */
using URLThreatCallback = std::function<void(
    const std::string& url,
    ThreatType threat,
    const URLVerdict& verdict
)>;

/**
 * @brief Callback for phishing detection.
 */
using PhishingCallback = std::function<void(
    const std::string& url,
    const BrandMatch& brandMatch,
    const URLVerdict& verdict
)>;

/**
 * @brief Callback for DGA detection.
 */
using DGACallback = std::function<void(
    const std::string& domain,
    double dgaScore,
    const std::string& dgaFamily
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class URLAnalyzer
 * @brief Enterprise-grade URL and domain analysis engine.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& analyzer = URLAnalyzer::Instance();
 * 
 * // Initialize
 * auto config = URLAnalyzerConfig::CreateHighSecurity();
 * analyzer.Initialize(config);
 * 
 * // Analyze a URL
 * auto verdict = analyzer.ScanURL("https://suspicious-site.com/login");
 * if (verdict.isBlocked) {
 *     BlockRequest(verdict.threatName);
 * }
 * 
 * // Check for DGA
 * if (analyzer.IsDGA("xkjdf8sdf9.com")) {
 *     AlertSOC("DGA domain detected");
 * }
 * @endcode
 */
class URLAnalyzer {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    /**
     * @brief Gets the singleton instance.
     * @return Reference to the singleton.
     */
    static URLAnalyzer& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initialize the analyzer and load ThreatIntel indices.
     * @return True if successful.
     */
    bool Initialize();

    /**
     * @brief Initializes with custom configuration.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const URLAnalyzerConfig& config);

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if initialized.
     * @return True if ready.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Gets current configuration.
     * @return Current config.
     */
    [[nodiscard]] URLAnalyzerConfig GetConfig() const;

    /**
     * @brief Updates configuration.
     * @param config New configuration.
     * @return True if successful.
     */
    bool UpdateConfig(const URLAnalyzerConfig& config);

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze a full URL string.
     * @param url URL to analyze.
     * @return Analysis verdict.
     */
    [[nodiscard]] URLVerdict ScanURL(const std::string& url);

    /**
     * @brief Analyze a URL with custom options.
     * @param url URL to analyze.
     * @param followRedirects Whether to follow redirects.
     * @param extractFeatures Whether to extract ML features.
     * @return Analysis verdict.
     */
    [[nodiscard]] URLVerdict ScanURL(
        const std::string& url,
        bool followRedirects,
        bool extractFeatures = false
    );

    /**
     * @brief Batch analyze multiple URLs.
     * @param urls Vector of URLs.
     * @return Vector of verdicts.
     */
    [[nodiscard]] std::vector<URLVerdict> ScanURLs(const std::vector<std::string>& urls);

    /**
     * @brief Async URL analysis.
     * @param url URL to analyze.
     * @param callback Callback for result.
     */
    void ScanURLAsync(const std::string& url, URLAnalysisCallback callback);

    // ========================================================================
    // DOMAIN ANALYSIS
    // ========================================================================

    /**
     * @brief Analyze a domain name (from DNS request).
     * @param domain Domain to analyze.
     * @return Analysis verdict.
     */
    [[nodiscard]] URLVerdict ScanDomain(const std::string& domain);

    /**
     * @brief Simplified domain analysis.
     * @param domain Domain to analyze.
     * @return Domain verdict.
     */
    [[nodiscard]] DomainVerdict AnalyzeDomain(const std::string& domain);

    /**
     * @brief Batch analyze domains.
     * @param domains Vector of domains.
     * @return Map of domain to verdict.
     */
    [[nodiscard]] std::unordered_map<std::string, DomainVerdict> AnalyzeDomains(
        const std::vector<std::string>& domains
    );

    // ========================================================================
    // DGA DETECTION
    // ========================================================================

    /**
     * @brief Check if a domain is a DGA (Domain Generation Algorithm).
     * @param domain Domain to check.
     * @return True if likely DGA.
     */
    [[nodiscard]] bool IsDGA(const std::string& domain);

    /**
     * @brief Get DGA score and family.
     * @param domain Domain to analyze.
     * @return Pair of (score, family name).
     */
    [[nodiscard]] std::pair<double, std::string> GetDGAScore(const std::string& domain);

    /**
     * @brief Batch DGA detection.
     * @param domains Domains to check.
     * @return Vector of DGA domains with scores.
     */
    [[nodiscard]] std::vector<std::tuple<std::string, double, std::string>> DetectDGAs(
        const std::vector<std::string>& domains
    );

    // ========================================================================
    // PHISHING DETECTION
    // ========================================================================

    /**
     * @brief Analyzes URL for phishing indicators.
     * @param url URL to analyze.
     * @return Brand match if phishing detected.
     */
    [[nodiscard]] std::optional<BrandMatch> DetectPhishing(const std::string& url);

    /**
     * @brief Checks for homograph attacks.
     * @param domain Domain to check.
     * @return Homograph analysis.
     */
    [[nodiscard]] HomographAnalysis CheckHomograph(const std::string& domain);

    /**
     * @brief Checks for typosquatting.
     * @param domain Domain to check.
     * @param targetDomain Expected legitimate domain.
     * @return Similarity score (0-1).
     */
    [[nodiscard]] double CheckTyposquatting(
        const std::string& domain,
        const std::string& targetDomain
    );

    // ========================================================================
    // URL PARSING
    // ========================================================================

    /**
     * @brief Parses a URL into components.
     * @param url URL to parse.
     * @return Parsed URL structure.
     */
    [[nodiscard]] static ParsedURL ParseURL(const std::string& url);

    /**
     * @brief Normalizes a URL.
     * @param url URL to normalize.
     * @return Normalized URL.
     */
    [[nodiscard]] static std::string NormalizeURL(const std::string& url);

    /**
     * @brief Extracts domain from URL.
     * @param url Full URL.
     * @return Domain portion.
     */
    [[nodiscard]] static std::string ExtractDomain(const std::string& url);

    /**
     * @brief Decodes punycode domain.
     * @param domain Punycode domain.
     * @return Decoded Unicode domain.
     */
    [[nodiscard]] static std::wstring DecodePunycode(const std::string& domain);

    // ========================================================================
    // FEATURE EXTRACTION
    // ========================================================================

    /**
     * @brief Extracts features for ML classification.
     * @param url URL to analyze.
     * @return Extracted features.
     */
    [[nodiscard]] URLFeatures ExtractFeatures(const std::string& url) const;

    /**
     * @brief Extracts features from parsed URL.
     * @param parsed Parsed URL.
     * @return Extracted features.
     */
    [[nodiscard]] URLFeatures ExtractFeatures(const ParsedURL& parsed) const;

    // ========================================================================
    // WHITELIST/BLACKLIST
    // ========================================================================

    /**
     * @brief Adds a domain to whitelist.
     * @param domain Domain to whitelist.
     * @param includeSubdomains Include subdomains.
     * @return True if added.
     */
    bool AddToWhitelist(const std::string& domain, bool includeSubdomains = true);

    /**
     * @brief Removes a domain from whitelist.
     * @param domain Domain to remove.
     * @return True if removed.
     */
    bool RemoveFromWhitelist(const std::string& domain);

    /**
     * @brief Adds a domain to blacklist.
     * @param domain Domain to blacklist.
     * @param threatName Associated threat name.
     * @return True if added.
     */
    bool AddToBlacklist(const std::string& domain, std::string_view threatName = "");

    /**
     * @brief Removes a domain from blacklist.
     * @param domain Domain to remove.
     * @return True if removed.
     */
    bool RemoveFromBlacklist(const std::string& domain);

    /**
     * @brief Checks if domain is whitelisted.
     * @param domain Domain to check.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(const std::string& domain) const;

    /**
     * @brief Checks if domain is blacklisted.
     * @param domain Domain to check.
     * @return True if blacklisted.
     */
    [[nodiscard]] bool IsBlacklisted(const std::string& domain) const;

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    /**
     * @brief Queries the verdict cache.
     * @param url URL to query.
     * @return Cached verdict, or nullopt.
     */
    [[nodiscard]] std::optional<URLVerdict> QueryCache(const std::string& url) const;

    /**
     * @brief Invalidates cache entry.
     * @param url URL to invalidate.
     */
    void InvalidateCache(const std::string& url);

    /**
     * @brief Clears entire cache.
     */
    void ClearCache();

    /**
     * @brief Gets cache size.
     * @return Number of cached entries.
     */
    [[nodiscard]] size_t GetCacheSize() const noexcept;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    /**
     * @brief Registers URL analysis callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterAnalysisCallback(URLAnalysisCallback callback);

    /**
     * @brief Registers threat detection callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(URLThreatCallback callback);

    /**
     * @brief Registers phishing callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterPhishingCallback(PhishingCallback callback);

    /**
     * @brief Registers DGA callback.
     * @param callback The callback.
     * @return Callback ID.
     */
    [[nodiscard]] uint64_t RegisterDGACallback(DGACallback callback);

    /**
     * @brief Unregisters a callback.
     * @param callbackId Callback ID.
     * @return True if unregistered.
     */
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    /**
     * @brief Gets current statistics.
     * @return Reference to statistics.
     */
    [[nodiscard]] const URLAnalyzerStatistics& GetStatistics() const noexcept;

    /**
     * @brief Resets statistics.
     */
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Performs diagnostic check.
     * @return True if healthy.
     */
    [[nodiscard]] bool PerformDiagnostics() const;

    /**
     * @brief Exports diagnostic data.
     * @param outputPath Output path.
     * @return True if exported.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

    // ========================================================================
    // UTILITY
    // ========================================================================

    /**
     * @brief Calculates string entropy.
     * @param str String to analyze.
     * @return Entropy value.
     */
    [[nodiscard]] static double CalculateEntropy(std::string_view str);

    /**
     * @brief Gets category name.
     * @param category URL category.
     * @return Category name.
     */
    [[nodiscard]] static std::string_view GetCategoryName(URLCategory category) noexcept;

    /**
     * @brief Gets threat type name.
     * @param threat Threat type.
     * @return Threat name.
     */
    [[nodiscard]] static std::string_view GetThreatTypeName(ThreatType threat) noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR (Singleton)
    // ========================================================================
    URLAnalyzer();
    ~URLAnalyzer();

    // Non-copyable, non-movable
    URLAnalyzer(const URLAnalyzer&) = delete;
    URLAnalyzer& operator=(const URLAnalyzer&) = delete;
    URLAnalyzer(URLAnalyzer&&) = delete;
    URLAnalyzer& operator=(URLAnalyzer&&) = delete;

    // ========================================================================
    // PIMPL IMPLEMENTATION
    // ========================================================================
    std::unique_ptr<URLAnalyzerImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike