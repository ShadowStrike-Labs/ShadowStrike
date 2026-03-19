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
 * ShadowStrike Core Network - WEB PROTECTION (The Shield)
 * ============================================================================
 *
 * @file WebProtection.hpp
 * @brief Enterprise-grade browser and web security protection engine.
 *
 * This module provides comprehensive web security through browser protection,
 * content filtering, exploit prevention, and secure browsing enforcement
 * at both network and application layers.
 *
 * Key Capabilities:
 * =================
 * 1. BROWSER PROTECTION
 *    - Certificate pinning enforcement
 *    - SSL/TLS security validation
 *    - Browser exploit protection
 *    - Extension monitoring
 *    - Safe browsing enforcement
 *
 * 2. CONTENT FILTERING
 *    - XSS attack prevention
 *    - JavaScript sanitization
 *    - Malicious iframe detection
 *    - Drive-by download prevention
 *    - Cryptojacking detection
 *
 * 3. CREDENTIAL PROTECTION
 *    - Form field monitoring
 *    - Password theft prevention
 *    - Credential stuffing detection
 *    - Clear-text submission alerts
 *    - Keylogger protection
 *
 * 4. EXPLOIT PREVENTION
 *    - Browser exploit detection
 *    - Exploit kit signatures
 *    - Heap spray detection
 *    - ROP chain detection
 *    - Memory corruption prevention
 *
 * 5. PRIVACY PROTECTION
 *    - Tracker blocking
 *    - Fingerprint protection
 *    - Cookie management
 *    - WebRTC leak prevention
 *    - Canvas fingerprint protection
 *
 * Web Protection Architecture:
 * ============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                        WebProtection                                │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │BrowserGuard  │  │ContentFilter │  │    CertValidator         │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Extensions │  │ - XSS Filter │  │ - HPKP Enforcement       │  │
 *   │  │ - Exploits   │  │ - JS Analyze │  │ - CT Validation          │  │
 *   │  │ - Safe Mode  │  │ - iFrame Sec │  │ - Cert Chain Check       │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │CredProtect   │  │ExploitPrevent│  │    PrivacyGuard          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Form Guard │  │ - Heap Spray │  │ - Tracker Block          │  │
 *   │  │ - Password   │  │ - Exploit Kit│  │ - Fingerprint Prot       │  │
 *   │  │ - Keylogger  │  │ - ROP Chain  │  │ - Cookie Mgmt            │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Browser Integration:
 * ====================
 * - Chrome/Chromium
 * - Firefox
 * - Edge (Chromium)
 * - Internet Explorer (legacy)
 * - Custom WebView applications
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1189: Drive-by Compromise
 * - T1203: Exploitation for Client Execution
 * - T1185: Browser Session Hijacking
 * - T1557: Man-in-the-Browser
 * - T1539: Steal Web Session Cookie
 * - T1056.002: GUI Input Capture
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Browser-specific protection is process-isolated
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see URLAnalyzer.hpp for URL scanning
 * @see TrafficAnalyzer.hpp for traffic inspection
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/NetworkUtils.hpp"       // Network utilities
#include "../../Utils/CertUtils.hpp"          // Certificate validation
#include "../../Utils/StringUtils.hpp"        // Content parsing
#include "../../ThreatIntel/ThreatIntelLookup.hpp"  // Reputation lookups
#include "../../PatternStore/PatternStore.hpp" // XSS/exploit patterns
#include "../../SignatureStore/SignatureStore.hpp" // Exploit signatures
#include "../../Whitelist/WhiteListStore.hpp" // Trusted sites

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
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <span>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class WebProtectionImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace WebProtectionConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Content limits
    constexpr size_t MAX_RESPONSE_SIZE = 50ULL * 1024 * 1024;     // 50 MB
    constexpr size_t MAX_SCRIPT_SIZE = 10ULL * 1024 * 1024;       // 10 MB
    constexpr size_t MAX_COOKIE_SIZE = 8192;
    constexpr size_t MAX_HEADER_SIZE = 64 * 1024;

    // Script analysis
    constexpr size_t MAX_SCRIPT_DEPTH = 10;                       // Nested evals
    constexpr size_t MAX_DOM_MANIPULATIONS = 1000;

    // Form protection
    constexpr size_t MAX_FORM_FIELDS = 500;
    constexpr size_t MAX_PASSWORD_FIELDS = 50;

    // Certificate pinning
    constexpr size_t MAX_PINS_PER_DOMAIN = 10;
    constexpr uint32_t PIN_VALIDITY_DAYS = 30;

    // Performance
    constexpr uint32_t ANALYSIS_TIMEOUT_MS = 5000;
    constexpr size_t MAX_CACHED_DECISIONS = 100000;

}  // namespace WebProtectionConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ThreatType
 * @brief Type of web threat detected.
 */
enum class WebThreatType : uint16_t {
    NONE = 0,

    // Script attacks
    XSS_REFLECTED = 100,
    XSS_STORED = 101,
    XSS_DOM = 102,
    SCRIPT_INJECTION = 103,
    EVAL_INJECTION = 104,

    // Exploit attacks
    EXPLOIT_KIT = 200,
    BROWSER_EXPLOIT = 201,
    HEAP_SPRAY = 202,
    ROP_CHAIN = 203,
    USE_AFTER_FREE = 204,
    BUFFER_OVERFLOW = 205,

    // Download attacks
    DRIVE_BY_DOWNLOAD = 300,
    MALICIOUS_DOWNLOAD = 301,
    DISGUISED_EXECUTABLE = 302,

    // Certificate attacks
    CERTIFICATE_SPOOF = 400,
    CERTIFICATE_EXPIRED = 401,
    CERTIFICATE_REVOKED = 402,
    CERTIFICATE_MISMATCH = 403,
    PIN_VIOLATION = 404,
    CT_VIOLATION = 405,

    // Credential attacks
    CREDENTIAL_THEFT = 500,
    FORM_HIJACK = 501,
    CLEARTEXT_PASSWORD = 502,
    KEYLOGGER = 503,
    SESSION_HIJACK = 504,

    // Content attacks
    MALICIOUS_IFRAME = 600,
    CLICKJACKING = 601,
    CRYPTOJACKING = 602,
    MALVERTISING = 603,

    // Privacy threats
    TRACKER = 700,
    FINGERPRINTING = 701,
    WEBRTC_LEAK = 702,
    CANVAS_FINGERPRINT = 703
};

/**
 * @enum ContentType
 * @brief Type of web content.
 */
enum class WebContentType : uint8_t {
    UNKNOWN = 0,
    HTML = 1,
    JAVASCRIPT = 2,
    CSS = 3,
    JSON = 4,
    XML = 5,
    IMAGE = 6,
    VIDEO = 7,
    AUDIO = 8,
    FONT = 9,
    PDF = 10,
    FLASH = 11,
    WASM = 12,
    OTHER = 255
};

/**
 * @enum ProtectionAction
 * @brief Action to take on threats.
 */
enum class ProtectionAction : uint8_t {
    ALLOW = 0,
    BLOCK = 1,
    SANITIZE = 2,
    WARN = 3,
    QUARANTINE = 4,
    LOG_ONLY = 5
};

/**
 * @enum BrowserType
 * @brief Browser types.
 */
enum class BrowserType : uint8_t {
    UNKNOWN = 0,
    CHROME = 1,
    FIREFOX = 2,
    EDGE = 3,
    IE = 4,
    SAFARI = 5,
    OPERA = 6,
    BRAVE = 7,
    CUSTOM = 255
};

/**
 * @enum ProtectionLevel
 * @brief Level of web protection.
 */
enum class WebProtectionLevel : uint8_t {
    DISABLED = 0,
    MINIMAL = 1,           // Basic XSS only
    STANDARD = 2,          // XSS + exploit detection
    STRICT = 3,            // All protections
    PARANOID = 4           // Maximum restrictions
};

/**
 * @enum CertificateStatus
 * @brief Certificate validation status.
 */
enum class CertificateStatus : uint8_t {
    VALID = 0,
    EXPIRED = 1,
    NOT_YET_VALID = 2,
    REVOKED = 3,
    SELF_SIGNED = 4,
    CHAIN_ERROR = 5,
    NAME_MISMATCH = 6,
    WEAK_ALGORITHM = 7,
    PIN_VIOLATION = 8,
    CT_FAILURE = 9,
    UNKNOWN_CA = 10
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ScriptAnalysis
 * @brief JavaScript analysis results.
 */
struct alignas(64) ScriptAnalysis {
    // Detection
    bool isMalicious{ false };
    double riskScore{ 0.0 };

    // XSS detection
    bool hasXSS{ false };
    std::vector<std::string> xssPatterns;
    uint32_t xssCount{ 0 };

    // Obfuscation
    bool isObfuscated{ false };
    double obfuscationScore{ 0.0 };
    uint32_t evalCount{ 0 };
    uint32_t documentWriteCount{ 0 };

    // Dangerous operations
    bool hasDocumentCookie{ false };
    bool hasLocalStorage{ false };
    bool hasXHR{ false };
    bool hasFormSubmission{ false };

    // Exploit indicators
    bool hasHeapSpray{ false };
    bool hasShellcode{ false };
    bool hasNOPSled{ false };
    uint32_t suspiciousStringCount{ 0 };

    // DOM manipulation
    uint32_t domManipulations{ 0 };
    uint32_t iframeCreations{ 0 };
    uint32_t eventHandlers{ 0 };

    // External resources
    std::vector<std::string> externalScripts;
    std::vector<std::string> externalDomains;
};

/**
 * @struct CertificatePin
 * @brief Certificate pinning configuration.
 */
struct alignas(64) CertificatePin {
    std::string domain;
    std::vector<std::string> sha256Pins;           // Base64 encoded
    std::vector<std::string> backupPins;

    bool includeSubdomains{ true };
    std::chrono::system_clock::time_point expiry;

    // Source
    bool isHPKPHeader{ false };                    // From HTTP header
    bool isBuiltIn{ false };                       // Hardcoded
    bool isUserDefined{ false };
};

/**
 * @struct CertificateValidation
 * @brief Certificate validation result.
 */
struct alignas(128) CertificateValidation {
    // Status
    CertificateStatus status{ CertificateStatus::VALID };
    bool isValid{ false };

    // Certificate info
    std::string commonName;
    std::string issuer;
    std::string serialNumber;
    std::chrono::system_clock::time_point notBefore;
    std::chrono::system_clock::time_point notAfter;

    // Chain
    bool chainValid{ false };
    uint32_t chainLength{ 0 };
    std::string rootCA;

    // Pinning
    bool pinValid{ false };
    bool pinChecked{ false };
    std::string matchedPin;

    // Certificate Transparency
    bool ctValid{ false };
    uint32_t sctCount{ 0 };

    // Issues
    std::vector<std::string> issues;
};

/**
 * @struct FormField
 * @brief Detected form field.
 */
struct alignas(32) FormField {
    std::string name;
    std::string type;
    std::string id;
    std::string autocomplete;

    bool isPassword{ false };
    bool isCreditCard{ false };
    bool isSSN{ false };
    bool isSensitive{ false };

    bool isEncrypted{ false };              // Form action is HTTPS
    bool hasAutocomplete{ true };
};

/**
 * @struct FormProtectionResult
 * @brief Form protection analysis.
 */
struct alignas(64) FormProtectionResult {
    // Form info
    std::string action;
    std::string method;
    bool isSecure{ false };

    // Fields
    std::vector<FormField> fields;
    uint32_t passwordFields{ 0 };
    uint32_t sensitiveFields{ 0 };

    // Threats
    bool hasClearTextPassword{ false };
    bool hasFormJacking{ false };
    bool hasHiddenExfiltration{ false };

    // Risk
    uint8_t riskScore{ 0 };
    std::vector<std::string> warnings;
};

/**
 * @struct ExploitAnalysis
 * @brief Exploit detection results.
 */
struct alignas(64) ExploitAnalysis {
    bool exploitDetected{ false };
    WebThreatType threatType{ WebThreatType::NONE };
    double confidence{ 0.0 };

    // Exploit kit detection
    bool isExploitKit{ false };
    std::string exploitKitFamily;

    // Technique detection
    bool heapSpray{ false };
    bool ropChain{ false };
    bool useAfterFree{ false };
    bool bufferOverflow{ false };

    // Shellcode
    bool shellcodeDetected{ false };
    size_t shellcodeOffset{ 0 };
    size_t shellcodeSize{ 0 };

    // Matched signatures
    std::vector<std::string> matchedSignatures;
    std::vector<std::string> cveIds;
};

/**
 * @struct PrivacyAnalysis
 * @brief Privacy threat analysis.
 */
struct alignas(64) PrivacyAnalysis {
    // Trackers
    uint32_t trackerCount{ 0 };
    std::vector<std::string> trackers;
    std::vector<std::string> trackerDomains;

    // Fingerprinting
    bool canvasFingerprinting{ false };
    bool webglFingerprinting{ false };
    bool audioFingerprinting{ false };
    bool fontFingerprinting{ false };

    // Leaks
    bool webrtcLeak{ false };
    std::vector<std::string> leakedIPs;

    // Cookies
    uint32_t thirdPartyCookies{ 0 };
    uint32_t trackingCookies{ 0 };

    // Overall
    uint8_t privacyScore{ 100 };            // 0-100 (100 = good)
};

/**
 * @struct WebContentAnalysis
 * @brief Complete content analysis result.
 */
struct alignas(256) WebContentAnalysis {
    // Identity
    uint64_t analysisId{ 0 };
    std::string url;
    std::string host;

    // Content info
    WebContentType contentType{ WebContentType::UNKNOWN };
    size_t contentSize{ 0 };
    std::string contentEncoding;

    // Overall result
    bool isSafe{ true };
    ProtectionAction action{ ProtectionAction::ALLOW };
    uint8_t threatScore{ 0 };

    // Threats
    std::vector<WebThreatType> threats;
    std::string primaryThreat;

    // Analysis components
    ScriptAnalysis scriptAnalysis;
    CertificateValidation certValidation;
    FormProtectionResult formProtection;
    ExploitAnalysis exploitAnalysis;
    PrivacyAnalysis privacyAnalysis;

    // Content was sanitized
    bool wasSanitized{ false };
    std::vector<std::string> sanitizations;

    // Timing
    std::chrono::system_clock::time_point analyzedAt;
    std::chrono::microseconds analysisDuration{ 0 };
};

/**
 * @struct WebAlert
 * @brief Alert for web threats.
 */
struct alignas(256) WebAlert {
    // Identity
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Threat
    WebThreatType threatType{ WebThreatType::NONE };
    std::string threatDescription;
    uint8_t severity{ 0 };

    // Context
    std::string url;
    std::string host;
    std::string referer;
    BrowserType browser{ BrowserType::UNKNOWN };
    uint32_t processId{ 0 };
    std::string processName;

    // Action
    ProtectionAction actionTaken{ ProtectionAction::LOG_ONLY };

    // Evidence
    std::vector<std::string> indicators;
    std::string matchedSignature;
    std::string sanitizedContent;

    // Metadata
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct BrowserSession
 * @brief Protected browser session.
 */
struct alignas(128) BrowserSession {
    uint64_t sessionId{ 0 };
    BrowserType browser{ BrowserType::UNKNOWN };
    uint32_t processId{ 0 };

    // State
    bool isProtected{ false };
    WebProtectionLevel protectionLevel{ WebProtectionLevel::STANDARD };

    // Statistics
    uint64_t requestsProcessed{ 0 };
    uint64_t threatsBlocked{ 0 };
    uint64_t scriptsSanitized{ 0 };

    // Current
    std::string currentUrl;
    std::string currentHost;

    // Extensions
    std::vector<std::string> installedExtensions;
    std::vector<std::string> blockedExtensions;

    // Timing
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastActivity;
};

/**
 * @struct WebProtectionConfig
 * @brief Configuration for web protection.
 */
struct alignas(64) WebProtectionConfig {
    // Main settings
    bool enabled{ true };
    WebProtectionLevel level{ WebProtectionLevel::STANDARD };

    // Feature toggles
    bool enableXSSProtection{ true };
    bool enableExploitProtection{ true };
    bool enableFormProtection{ true };
    bool enableCertificatePinning{ true };
    bool enablePrivacyProtection{ true };
    bool enableCryptojackingProtection{ true };

    // XSS settings
    bool sanitizeScripts{ true };
    bool blockReflectedXSS{ true };
    bool blockDOMXSS{ true };

    // Certificate settings
    bool enforceCT{ true };
    bool blockExpiredCerts{ true };
    bool blockSelfSigned{ true };
    bool blockWeakAlgorithms{ true };

    // Form settings
    bool warnClearTextPasswords{ true };
    bool blockFormJacking{ true };

    // Privacy settings
    bool blockTrackers{ false };
    bool blockThirdPartyCookies{ false };
    bool preventFingerprinting{ false };
    bool preventWebRTCLeak{ false };

    // Content filtering
    std::vector<std::string> blockedDomains;
    std::vector<std::string> allowedDomains;

    // Performance
    size_t maxContentToAnalyze{ WebProtectionConstants::MAX_RESPONSE_SIZE };
    uint32_t analysisTimeoutMs{ WebProtectionConstants::ANALYSIS_TIMEOUT_MS };

    // Logging
    bool logAllRequests{ false };
    bool logThreatsOnly{ true };

    // Factory methods
    static WebProtectionConfig CreateDefault() noexcept;
    static WebProtectionConfig CreateHighSecurity() noexcept;
    static WebProtectionConfig CreatePerformance() noexcept;
    static WebProtectionConfig CreatePrivacy() noexcept;
};

/**
 * @struct WebProtectionStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) WebProtectionStatistics {
    // Request statistics
    std::atomic<uint64_t> totalRequests{ 0 };
    std::atomic<uint64_t> totalResponses{ 0 };
    std::atomic<uint64_t> bytesAnalyzed{ 0 };

    // Threat statistics
    std::atomic<uint64_t> xssBlocked{ 0 };
    std::atomic<uint64_t> exploitsBlocked{ 0 };
    std::atomic<uint64_t> maliciousDownloads{ 0 };
    std::atomic<uint64_t> certificateErrors{ 0 };
    std::atomic<uint64_t> pinViolations{ 0 };

    // Content statistics
    std::atomic<uint64_t> scriptsSanitized{ 0 };
    std::atomic<uint64_t> iframesBlocked{ 0 };
    std::atomic<uint64_t> formsProtected{ 0 };

    // Privacy statistics
    std::atomic<uint64_t> trackersBlocked{ 0 };
    std::atomic<uint64_t> fingerprintsBlocked{ 0 };
    std::atomic<uint64_t> cookiesBlocked{ 0 };

    // Crypto mining
    std::atomic<uint64_t> cryptojackingBlocked{ 0 };

    // Session statistics
    std::atomic<uint32_t> activeSessions{ 0 };
    std::atomic<uint64_t> totalSessions{ 0 };

    // Alerts
    std::atomic<uint64_t> alertsGenerated{ 0 };

    // Performance
    std::atomic<uint64_t> avgAnalysisTimeUs{ 0 };
    std::atomic<uint64_t> maxAnalysisTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for content analysis.
 */
using ContentAnalysisCallback = std::function<void(const WebContentAnalysis& analysis)>;

/**
 * @brief Callback for web alerts.
 */
using WebAlertCallback = std::function<void(const WebAlert& alert)>;

/**
 * @brief Callback for certificate events.
 */
using CertificateCallback = std::function<void(
    const std::string& host,
    const CertificateValidation& validation
)>;

/**
 * @brief Callback for exploit detection.
 */
using ExploitCallback = std::function<void(
    const std::string& url,
    const ExploitAnalysis& analysis
)>;

/**
 * @brief Callback for XSS detection.
 */
using XSSCallback = std::function<void(
    const std::string& url,
    const ScriptAnalysis& analysis
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class WebProtection
 * @brief Enterprise-grade browser and web security protection.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& protection = WebProtection::Instance();
 * 
 * // Initialize
 * auto config = WebProtectionConfig::CreateHighSecurity();
 * protection.Initialize(config);
 * 
 * // Register alert callback
 * protection.RegisterAlertCallback([](const WebAlert& alert) {
 *     HandleWebThreat(alert);
 * });
 * 
 * // Sanitize response
 * std::string content = GetHTMLResponse();
 * protection.SanitizeResponse("example.com", content);
 * @endcode
 */
class WebProtection {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static WebProtection& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes web protection.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const WebProtectionConfig& config);

    /**
     * @brief Starts protection threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops protection threads.
     */
    void Stop();

    /**
     * @brief Shuts down and releases resources.
     */
    void Shutdown() noexcept;

    /**
     * @brief Checks if running.
     * @return True if active.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // CONTENT ANALYSIS
    // ========================================================================

    /**
     * @brief Sanitize HTTP response content.
     * @param host Host name.
     * @param htmlContent HTML content (modified in place).
     * @return True if content was sanitized.
     */
    bool SanitizeResponse(const std::string& host, std::string& htmlContent);

    /**
     * @brief Full content analysis.
     * @param url Request URL.
     * @param content Response content.
     * @param contentType MIME type.
     * @return Analysis result.
     */
    [[nodiscard]] WebContentAnalysis AnalyzeContent(
        const std::string& url,
        std::span<const uint8_t> content,
        const std::string& contentType
    );

    /**
     * @brief Analyze JavaScript.
     * @param script JavaScript content.
     * @param sourceUrl Script URL.
     * @return Script analysis.
     */
    [[nodiscard]] ScriptAnalysis AnalyzeScript(
        const std::string& script,
        const std::string& sourceUrl
    );

    // ========================================================================
    // CERTIFICATE PROTECTION
    // ========================================================================

    /**
     * @brief Validates certificate.
     * @param host Host name.
     * @param certChain Certificate chain (DER encoded).
     * @return Validation result.
     */
    [[nodiscard]] CertificateValidation ValidateCertificate(
        const std::string& host,
        const std::vector<std::vector<uint8_t>>& certChain
    );

    /**
     * @brief Adds certificate pin.
     * @param pin Certificate pin configuration.
     * @return True if added.
     */
    bool AddCertificatePin(const CertificatePin& pin);

    /**
     * @brief Removes certificate pin.
     * @param domain Domain to unpin.
     * @return True if removed.
     */
    bool RemoveCertificatePin(const std::string& domain);

    /**
     * @brief Checks if certificate is pinned.
     * @param domain Domain to check.
     * @return True if pinned.
     */
    [[nodiscard]] bool IsCertificatePinned(const std::string& domain) const;

    // ========================================================================
    // FORM PROTECTION
    // ========================================================================

    /**
     * @brief Analyze form for protection.
     * @param formHtml Form HTML content.
     * @param pageUrl Page URL.
     * @return Form protection result.
     */
    [[nodiscard]] FormProtectionResult AnalyzeForm(
        const std::string& formHtml,
        const std::string& pageUrl
    );

    /**
     * @brief Check for credential theft.
     * @param url Target URL.
     * @param fieldName Field name.
     * @param fieldValue Field value.
     * @return True if threat detected.
     */
    [[nodiscard]] bool CheckCredentialTheft(
        const std::string& url,
        const std::string& fieldName,
        const std::string& fieldValue
    );

    // ========================================================================
    // EXPLOIT PROTECTION
    // ========================================================================

    /**
     * @brief Analyze for exploits.
     * @param content Content to analyze.
     * @param contentType Content type.
     * @return Exploit analysis.
     */
    [[nodiscard]] ExploitAnalysis AnalyzeExploits(
        std::span<const uint8_t> content,
        WebContentType contentType
    );

    // ========================================================================
    // PRIVACY PROTECTION
    // ========================================================================

    /**
     * @brief Analyze for privacy threats.
     * @param content Page content.
     * @param url Page URL.
     * @return Privacy analysis.
     */
    [[nodiscard]] PrivacyAnalysis AnalyzePrivacy(
        const std::string& content,
        const std::string& url
    );

    /**
     * @brief Check if domain is tracker.
     * @param domain Domain to check.
     * @return True if tracker.
     */
    [[nodiscard]] bool IsTracker(const std::string& domain) const;

    // ========================================================================
    // BROWSER SESSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Protects a browser process.
     * @param processId Process ID.
     * @param browser Browser type.
     * @return Session ID.
     */
    [[nodiscard]] uint64_t ProtectBrowser(uint32_t processId, BrowserType browser);

    /**
     * @brief Unprotects a browser process.
     * @param sessionId Session ID.
     */
    void UnprotectBrowser(uint64_t sessionId);

    /**
     * @brief Gets active browser sessions.
     * @return Vector of active sessions.
     */
    [[nodiscard]] std::vector<BrowserSession> GetActiveSessions() const;

    // ========================================================================
    // DOMAIN MANAGEMENT
    // ========================================================================

    /**
     * @brief Blocks a domain.
     * @param domain Domain to block.
     * @return True if blocked.
     */
    bool BlockDomain(const std::string& domain);

    /**
     * @brief Unblocks a domain.
     * @param domain Domain to unblock.
     * @return True if unblocked.
     */
    bool UnblockDomain(const std::string& domain);

    /**
     * @brief Allows a domain (whitelist).
     * @param domain Domain to allow.
     * @return True if allowed.
     */
    bool AllowDomain(const std::string& domain);

    /**
     * @brief Checks if domain is blocked.
     * @param domain Domain to check.
     * @return True if blocked.
     */
    [[nodiscard]] bool IsDomainBlocked(const std::string& domain) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterContentCallback(ContentAnalysisCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(WebAlertCallback callback);
    [[nodiscard]] uint64_t RegisterCertificateCallback(CertificateCallback callback);
    [[nodiscard]] uint64_t RegisterExploitCallback(ExploitCallback callback);
    [[nodiscard]] uint64_t RegisterXSSCallback(XSSCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const WebProtectionStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    WebProtection();
    ~WebProtection();

    WebProtection(const WebProtection&) = delete;
    WebProtection& operator=(const WebProtection&) = delete;

    std::unique_ptr<WebProtectionImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
