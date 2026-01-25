/**
 * ============================================================================
 * ShadowStrike Core Network - EMAIL SCANNER (The Sorter)
 * ============================================================================
 *
 * @file EmailScanner.hpp
 * @brief Enterprise-grade email security scanning and threat detection.
 *
 * This module provides comprehensive email security through protocol-level
 * inspection, attachment analysis, phishing detection, and threat prevention
 * for SMTP, IMAP, POP3, and Exchange protocols.
 *
 * Key Capabilities:
 * =================
 * 1. PROTOCOL INSPECTION
 *    - SMTP stream analysis
 *    - IMAP/POP3 monitoring
 *    - Exchange/EWS inspection
 *    - TLS/SSL encrypted mail
 *    - MIME parsing
 *
 * 2. ATTACHMENT ANALYSIS
 *    - Malware scanning
 *    - Archive extraction (nested)
 *    - Executable detection
 *    - Macro analysis
 *    - File type verification
 *
 * 3. PHISHING DETECTION
 *    - URL analysis
 *    - Sender spoofing detection
 *    - Header anomaly detection
 *    - Brand impersonation
 *    - Homograph detection
 *
 * 4. CONTENT ANALYSIS
 *    - Spam filtering
 *    - Data loss prevention (DLP)
 *    - Sensitive data detection
 *    - Business email compromise (BEC)
 *    - Social engineering patterns
 *
 * 5. AUTHENTICATION SECURITY
 *    - Credential theft detection
 *    - Clear-text password alerts
 *    - SPF/DKIM/DMARC validation
 *    - SASL authentication monitoring
 *
 * Email Scanning Architecture:
 * ============================
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         EmailScanner                                │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │ProtocolParse │  │StreamReassem │  │     MIMEDecoder          │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - SMTP       │  │ - TCP Reassm │  │ - Header Parse           │  │
 *   │  │ - IMAP/POP3  │  │ - Fragments  │  │ - Base64/QP Decode       │  │
 *   │  │ - Exchange   │  │ - Ordering   │  │ - Charset Convert        │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │AttachAnalyze │  │PhishDetector │  │     ContentInspector     │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Extract    │  │ - URL Check  │  │ - Spam Filter            │  │
 *   │  │ - Scan       │  │ - Spoof Det  │  │ - DLP Scan               │  │
 *   │  │ - Sandbox    │  │ - Homograph  │  │ - BEC Detection          │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Supported Protocols:
 * ====================
 * - SMTP (port 25, 587)
 * - SMTPS (port 465)
 * - IMAP (port 143)
 * - IMAPS (port 993)
 * - POP3 (port 110)
 * - POP3S (port 995)
 * - Exchange Web Services (EWS)
 * - MAPI over HTTP
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1566: Phishing
 * - T1566.001: Spearphishing Attachment
 * - T1566.002: Spearphishing Link
 * - T1534: Internal Spearphishing
 * - T1204: User Execution
 * - T1114: Email Collection
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Concurrent email processing
 * - Lock-free statistics
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see TrafficAnalyzer.hpp for protocol detection
 * @see URLAnalyzer.hpp for URL scanning
 * @see PatternStore for malware signatures
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
class EmailScannerImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace EmailScannerConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Email limits
    constexpr size_t MAX_EMAIL_SIZE = 100ULL * 1024 * 1024;       // 100 MB
    constexpr size_t MAX_ATTACHMENT_SIZE = 50ULL * 1024 * 1024;   // 50 MB
    constexpr size_t MAX_ATTACHMENTS_PER_EMAIL = 100;
    constexpr size_t MAX_NESTED_ARCHIVE_DEPTH = 10;
    constexpr size_t MAX_HEADER_SIZE = 64 * 1024;                 // 64 KB

    // URL limits
    constexpr size_t MAX_URLS_PER_EMAIL = 1000;
    constexpr size_t MAX_URL_LENGTH = 2048;

    // Session limits
    constexpr size_t MAX_ACTIVE_SESSIONS = 10000;
    constexpr uint32_t SESSION_TIMEOUT_MS = 600000;               // 10 minutes

    // Analysis thresholds
    constexpr double SPAM_THRESHOLD = 0.7;
    constexpr double PHISHING_THRESHOLD = 0.6;
    constexpr double BEC_THRESHOLD = 0.5;

    // Standard ports
    constexpr uint16_t PORT_SMTP = 25;
    constexpr uint16_t PORT_SMTP_SUBMISSION = 587;
    constexpr uint16_t PORT_SMTPS = 465;
    constexpr uint16_t PORT_IMAP = 143;
    constexpr uint16_t PORT_IMAPS = 993;
    constexpr uint16_t PORT_POP3 = 110;
    constexpr uint16_t PORT_POP3S = 995;

}  // namespace EmailScannerConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum EmailProtocol
 * @brief Email protocol types.
 */
enum class EmailProtocol : uint8_t {
    UNKNOWN = 0,
    SMTP = 1,
    SMTPS = 2,
    IMAP = 3,
    IMAPS = 4,
    POP3 = 5,
    POP3S = 6,
    EWS = 7,           // Exchange Web Services
    MAPI = 8           // MAPI over HTTP
};

/**
 * @enum EmailDirection
 * @brief Direction of email flow.
 */
enum class EmailDirection : uint8_t {
    UNKNOWN = 0,
    INBOUND = 1,       // Receiving
    OUTBOUND = 2,      // Sending
    INTERNAL = 3       // Internal transfer
};

/**
 * @enum ThreatType
 * @brief Type of email threat.
 */
enum class ThreatType : uint16_t {
    NONE = 0,

    // Malware
    MALWARE_ATTACHMENT = 100,
    MALWARE_EMBEDDED = 101,
    MALWARE_MACRO = 102,
    MALWARE_SCRIPT = 103,
    RANSOMWARE = 104,
    TROJAN = 105,

    // Phishing
    PHISHING_URL = 200,
    PHISHING_CREDENTIAL = 201,
    PHISHING_BRAND_IMPERSONATION = 202,
    PHISHING_HOMOGRAPH = 203,
    SPEAR_PHISHING = 204,

    // BEC/Social Engineering
    BEC_IMPERSONATION = 300,
    BEC_PAYMENT_FRAUD = 301,
    BEC_DATA_THEFT = 302,
    SOCIAL_ENGINEERING = 303,
    CEO_FRAUD = 304,

    // Spam
    SPAM = 400,
    MARKETING_SPAM = 401,
    SCAM = 402,

    // Authentication
    CREDENTIAL_EXPOSURE = 500,
    SPOOFED_SENDER = 501,
    DKIM_FAILURE = 502,
    SPF_FAILURE = 503,
    DMARC_FAILURE = 504,

    // Content
    DLP_VIOLATION = 600,
    SENSITIVE_DATA = 601,
    PII_EXPOSURE = 602,

    // Protocol abuse
    PROTOCOL_ANOMALY = 700,
    COMMAND_INJECTION = 701
};

/**
 * @enum AttachmentType
 * @brief Type of email attachment.
 */
enum class AttachmentType : uint8_t {
    UNKNOWN = 0,
    EXECUTABLE = 1,
    DOCUMENT = 2,
    SPREADSHEET = 3,
    PRESENTATION = 4,
    PDF = 5,
    ARCHIVE = 6,
    IMAGE = 7,
    VIDEO = 8,
    AUDIO = 9,
    SCRIPT = 10,
    HTML = 11,
    TEXT = 12,
    ICS_CALENDAR = 13,
    VCARD = 14,
    OTHER = 255
};

/**
 * @enum AttachmentRisk
 * @brief Risk level of attachment.
 */
enum class AttachmentRisk : uint8_t {
    SAFE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4,
    BLOCKED = 5
};

/**
 * @enum ContentDisposition
 * @brief How attachment was originally presented.
 */
enum class ContentDisposition : uint8_t {
    INLINE = 0,
    ATTACHMENT = 1,
    FORM_DATA = 2
};

/**
 * @enum ScanResult
 * @brief Result of email scanning.
 */
enum class ScanResult : uint8_t {
    CLEAN = 0,
    SUSPICIOUS = 1,
    MALICIOUS = 2,
    BLOCKED = 3,
    ERROR = 4,
    TIMEOUT = 5
};

/**
 * @enum EmailAction
 * @brief Action to take on email.
 */
enum class EmailAction : uint8_t {
    ALLOW = 0,
    QUARANTINE = 1,
    BLOCK = 2,
    STRIP_ATTACHMENTS = 3,
    REWRITE_URLS = 4,
    TAG_SUSPICIOUS = 5,
    ALERT_ONLY = 6
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct EmailAddress
 * @brief Parsed email address.
 */
struct alignas(32) EmailAddress {
    std::string displayName;
    std::string localPart;
    std::string domain;
    std::string fullAddress;

    // Validation
    bool isValid{ false };
    bool isDomainValid{ false };
    bool hasDisplayNameMismatch{ false };
};

/**
 * @struct EmailHeader
 * @brief Parsed email header.
 */
struct alignas(64) EmailHeader {
    // Addressing
    EmailAddress from;
    std::vector<EmailAddress> to;
    std::vector<EmailAddress> cc;
    std::vector<EmailAddress> bcc;
    EmailAddress replyTo;
    std::string returnPath;

    // Identification
    std::string messageId;
    std::string inReplyTo;
    std::vector<std::string> references;

    // Subject
    std::string subject;
    std::string decodedSubject;

    // Dates
    std::string dateString;
    std::chrono::system_clock::time_point parsedDate;

    // Routing
    std::vector<std::string> receivedHeaders;
    std::string xOriginalIP;
    std::string xOriginatingIP;

    // Authentication
    std::string authenticationResults;
    std::string dkimSignature;
    std::string arcSeal;

    // Client info
    std::string xMailer;
    std::string userAgent;

    // Content
    std::string contentType;
    std::string contentTransferEncoding;
    std::string mimeVersion;

    // Custom headers
    std::unordered_map<std::string, std::string> customHeaders;

    // Anomalies
    std::vector<std::string> anomalies;
};

/**
 * @struct AttachmentInfo
 * @brief Information about email attachment.
 */
struct alignas(128) AttachmentInfo {
    // Identity
    uint64_t attachmentId{ 0 };
    std::string filename;
    std::string contentType;
    ContentDisposition disposition{ ContentDisposition::ATTACHMENT };

    // File info
    size_t size{ 0 };
    AttachmentType type{ AttachmentType::UNKNOWN };
    std::string detectedType;              // Actual type from magic bytes
    bool typeMismatch{ false };            // Extension vs actual type

    // Hashes
    std::array<uint8_t, 32> sha256{ 0 };
    std::array<uint8_t, 16> md5{ 0 };
    std::string sha256Hex;

    // Scanning
    ScanResult scanResult{ ScanResult::CLEAN };
    AttachmentRisk riskLevel{ AttachmentRisk::SAFE };
    std::vector<std::string> matchedSignatures;
    std::vector<ThreatType> threats;

    // Analysis
    bool isEncrypted{ false };
    bool isPasswordProtected{ false };
    bool hasMacros{ false };
    bool hasActiveContent{ false };
    std::vector<std::string> embeddedFiles;

    // Nested archives
    bool isArchive{ false };
    uint32_t nestedDepth{ 0 };
    std::vector<std::string> archiveContents;

    // Raw data (if retained)
    std::vector<uint8_t> data;
};

/**
 * @struct URLInfo
 * @brief Information about URL in email.
 */
struct alignas(64) URLInfo {
    std::string url;
    std::string displayText;
    std::string domain;

    // Location
    std::string location;                  // body, header, attachment
    uint32_t lineNumber{ 0 };

    // Analysis
    bool isPhishing{ false };
    double phishingScore{ 0.0 };
    bool isKnownBad{ false };
    bool isHomograph{ false };
    std::string realDomain;                // If homograph

    // Categorization
    std::string category;
    std::string reputation;
};

/**
 * @struct PhishingAnalysis
 * @brief Phishing analysis results.
 */
struct alignas(128) PhishingAnalysis {
    bool isPhishing{ false };
    double confidence{ 0.0 };

    // Indicators
    std::vector<std::string> indicators;
    uint32_t indicatorCount{ 0 };

    // Sender analysis
    bool senderSpoofed{ false };
    bool domainSpoofed{ false };
    bool displayNameMismatch{ false };
    std::string realSender;

    // Content analysis
    bool hasUrgencyLanguage{ false };
    bool hasCredentialRequest{ false };
    bool hasSuspiciousLinks{ false };
    uint32_t suspiciousUrlCount{ 0 };

    // Brand impersonation
    bool brandImpersonation{ false };
    std::string impersonatedBrand;
    double brandSimilarity{ 0.0 };

    // Homograph
    bool hasHomographDomain{ false };
    std::vector<std::string> homographDomains;
};

/**
 * @struct AuthenticationResults
 * @brief Email authentication analysis.
 */
struct alignas(64) AuthenticationResults {
    // SPF
    bool spfPass{ false };
    std::string spfResult;
    std::string spfDomain;

    // DKIM
    bool dkimPass{ false };
    std::string dkimResult;
    std::string dkimDomain;
    std::string dkimSelector;

    // DMARC
    bool dmarcPass{ false };
    std::string dmarcResult;
    std::string dmarcPolicy;

    // ARC
    bool arcPass{ false };
    std::string arcResult;

    // Overall
    bool allPass{ false };
    bool anyFail{ false };
    std::vector<std::string> failures;
};

/**
 * @struct DLPResult
 * @brief Data Loss Prevention analysis.
 */
struct alignas(64) DLPResult {
    bool hasViolation{ false };
    uint32_t violationCount{ 0 };

    struct Violation {
        std::string policyName;
        std::string dataType;
        std::string match;
        std::string location;
        uint8_t severity{ 0 };
    };
    std::vector<Violation> violations;

    // Detected data types
    bool hasCreditCard{ false };
    bool hasSSN{ false };
    bool hasPII{ false };
    bool hasHealthData{ false };
    bool hasFinancialData{ false };
};

/**
 * @struct EmailAnalysis
 * @brief Complete email analysis result.
 */
struct alignas(512) EmailAnalysis {
    // Identity
    uint64_t analysisId{ 0 };
    std::string messageId;

    // Result
    ScanResult result{ ScanResult::CLEAN };
    EmailAction action{ EmailAction::ALLOW };
    uint8_t threatScore{ 0 };              // 0-100

    // Email info
    EmailProtocol protocol{ EmailProtocol::UNKNOWN };
    EmailDirection direction{ EmailDirection::UNKNOWN };
    size_t emailSize{ 0 };

    // Parsed content
    EmailHeader header;
    std::string bodyText;
    std::string bodyHtml;

    // Threats
    std::vector<ThreatType> threats;
    std::string primaryThreat;

    // Components
    std::vector<AttachmentInfo> attachments;
    std::vector<URLInfo> urls;

    // Analysis results
    PhishingAnalysis phishingAnalysis;
    AuthenticationResults authResults;
    DLPResult dlpResult;

    // Spam
    bool isSpam{ false };
    double spamScore{ 0.0 };
    std::vector<std::string> spamIndicators;

    // BEC
    bool isBEC{ false };
    double becScore{ 0.0 };
    std::vector<std::string> becIndicators;

    // Timing
    std::chrono::system_clock::time_point scannedAt;
    std::chrono::microseconds scanDuration{ 0 };

    // Metadata
    std::unordered_map<std::string, std::string> metadata;
};

/**
 * @struct EmailAlert
 * @brief Alert for email threat.
 */
struct alignas(256) EmailAlert {
    // Identity
    uint64_t alertId{ 0 };
    uint64_t analysisId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    // Threat
    ThreatType threatType{ ThreatType::NONE };
    std::string threatDescription;
    uint8_t severity{ 0 };

    // Email info
    std::string messageId;
    std::string subject;
    std::string sender;
    std::vector<std::string> recipients;
    EmailDirection direction{ EmailDirection::UNKNOWN };

    // Action
    EmailAction actionTaken{ EmailAction::ALLOW };

    // Evidence
    std::vector<std::string> indicators;
    std::string matchedSignature;
    std::string attachmentName;
    std::string maliciousUrl;

    // Context
    std::unordered_map<std::string, std::string> context;
};

/**
 * @struct EmailSession
 * @brief Email protocol session.
 */
struct alignas(128) EmailSession {
    uint64_t sessionId{ 0 };
    EmailProtocol protocol{ EmailProtocol::UNKNOWN };

    // Endpoint info
    std::string clientIP;
    uint16_t clientPort{ 0 };
    std::string serverIP;
    uint16_t serverPort{ 0 };

    // Authentication
    std::string authUser;
    std::string authMethod;
    bool isAuthenticated{ false };
    bool isEncrypted{ false };

    // State
    std::string currentCommand;
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point lastActivity;

    // Statistics
    uint64_t bytesTransferred{ 0 };
    uint32_t emailsProcessed{ 0 };
    uint32_t commandsProcessed{ 0 };

    // Buffer for reassembly
    std::vector<uint8_t> buffer;
};

/**
 * @struct EmailScannerConfig
 * @brief Configuration for email scanner.
 */
struct alignas(64) EmailScannerConfig {
    // Feature toggles
    bool enabled{ true };
    bool enableMalwareScanning{ true };
    bool enablePhishingDetection{ true };
    bool enableSpamFiltering{ true };
    bool enableDLP{ true };
    bool enableBECDetection{ true };
    bool enableAuthValidation{ true };

    // Protocol settings
    bool inspectSMTP{ true };
    bool inspectIMAP{ true };
    bool inspectPOP3{ true };
    bool inspectEWS{ false };

    // Attachment settings
    bool scanAttachments{ true };
    bool extractArchives{ true };
    bool sandboxExecutables{ true };
    size_t maxAttachmentSize{ EmailScannerConstants::MAX_ATTACHMENT_SIZE };
    uint32_t maxArchiveDepth{ static_cast<uint32_t>(EmailScannerConstants::MAX_NESTED_ARCHIVE_DEPTH) };

    // URL settings
    bool scanURLs{ true };
    bool rewriteURLs{ false };
    size_t maxURLsToScan{ EmailScannerConstants::MAX_URLS_PER_EMAIL };

    // Thresholds
    double spamThreshold{ EmailScannerConstants::SPAM_THRESHOLD };
    double phishingThreshold{ EmailScannerConstants::PHISHING_THRESHOLD };
    double becThreshold{ EmailScannerConstants::BEC_THRESHOLD };

    // Actions
    EmailAction malwareAction{ EmailAction::BLOCK };
    EmailAction phishingAction{ EmailAction::QUARANTINE };
    EmailAction spamAction{ EmailAction::TAG_SUSPICIOUS };

    // Whitelist
    std::vector<std::string> whitelistedSenders;
    std::vector<std::string> whitelistedDomains;

    // Performance
    uint32_t workerThreads{ 4 };
    size_t maxActiveSessionsCount{ EmailScannerConstants::MAX_ACTIVE_SESSIONS };
    uint32_t sessionTimeoutMs{ EmailScannerConstants::SESSION_TIMEOUT_MS };

    // Logging
    bool logAllEmails{ false };
    bool logThreatsOnly{ true };
    bool retainEmailContent{ false };

    // Factory methods
    static EmailScannerConfig CreateDefault() noexcept;
    static EmailScannerConfig CreateHighSecurity() noexcept;
    static EmailScannerConfig CreatePerformance() noexcept;
    static EmailScannerConfig CreateForensic() noexcept;
};

/**
 * @struct EmailScannerStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) EmailScannerStatistics {
    // Traffic statistics
    std::atomic<uint64_t> totalPacketsProcessed{ 0 };
    std::atomic<uint64_t> totalBytesProcessed{ 0 };
    std::atomic<uint64_t> totalEmailsScanned{ 0 };

    // Session statistics
    std::atomic<uint32_t> activeSessions{ 0 };
    std::atomic<uint64_t> totalSessions{ 0 };
    std::atomic<uint64_t> sessionsTimedOut{ 0 };

    // Protocol statistics
    std::atomic<uint64_t> smtpEmails{ 0 };
    std::atomic<uint64_t> imapEmails{ 0 };
    std::atomic<uint64_t> pop3Emails{ 0 };

    // Threat statistics
    std::atomic<uint64_t> malwareDetected{ 0 };
    std::atomic<uint64_t> phishingDetected{ 0 };
    std::atomic<uint64_t> spamDetected{ 0 };
    std::atomic<uint64_t> becDetected{ 0 };
    std::atomic<uint64_t> dlpViolations{ 0 };

    // Attachment statistics
    std::atomic<uint64_t> attachmentsScanned{ 0 };
    std::atomic<uint64_t> maliciousAttachments{ 0 };
    std::atomic<uint64_t> archivesExtracted{ 0 };

    // URL statistics
    std::atomic<uint64_t> urlsScanned{ 0 };
    std::atomic<uint64_t> maliciousUrls{ 0 };
    std::atomic<uint64_t> phishingUrls{ 0 };

    // Action statistics
    std::atomic<uint64_t> emailsBlocked{ 0 };
    std::atomic<uint64_t> emailsQuarantined{ 0 };
    std::atomic<uint64_t> attachmentsStripped{ 0 };

    // Performance
    std::atomic<uint64_t> avgScanTimeUs{ 0 };
    std::atomic<uint64_t> maxScanTimeUs{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for email analysis completion.
 */
using EmailAnalysisCallback = std::function<void(const EmailAnalysis& analysis)>;

/**
 * @brief Callback for email alerts.
 */
using EmailAlertCallback = std::function<void(const EmailAlert& alert)>;

/**
 * @brief Callback for attachment analysis.
 */
using AttachmentCallback = std::function<void(
    uint64_t emailId,
    const AttachmentInfo& attachment
)>;

/**
 * @brief Callback for phishing detection.
 */
using PhishingCallback = std::function<void(
    uint64_t emailId,
    const PhishingAnalysis& analysis
)>;

/**
 * @brief Callback for malware detection.
 */
using MalwareCallback = std::function<void(
    uint64_t emailId,
    ThreatType threat,
    const std::string& signature
)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class EmailScanner
 * @brief Enterprise-grade email security scanner.
 *
 * Thread Safety:
 * All public methods are thread-safe. Concurrent email processing supported.
 *
 * Usage Example:
 * @code
 * auto& scanner = EmailScanner::Instance();
 * 
 * // Initialize
 * auto config = EmailScannerConfig::CreateHighSecurity();
 * scanner.Initialize(config);
 * 
 * // Register threat callback
 * scanner.RegisterAlertCallback([](const EmailAlert& alert) {
 *     HandleEmailThreat(alert);
 * });
 * 
 * // Feed network packets
 * scanner.FeedPacket(packetData);
 * @endcode
 */
class EmailScanner {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    static EmailScanner& Instance();

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================

    /**
     * @brief Initializes the email scanner.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const EmailScannerConfig& config);

    /**
     * @brief Starts scanner threads.
     * @return True if started.
     */
    bool Start();

    /**
     * @brief Stops scanner threads.
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
    // PACKET PROCESSING
    // ========================================================================

    /**
     * @brief Feed a chunk of email network traffic.
     * @param data Raw packet data.
     */
    void FeedPacket(const std::vector<uint8_t>& data);

    /**
     * @brief Feed packet with metadata.
     * @param data Raw packet data.
     * @param srcIP Source IP.
     * @param srcPort Source port.
     * @param dstIP Destination IP.
     * @param dstPort Destination port.
     */
    void FeedPacket(
        std::span<const uint8_t> data,
        const std::string& srcIP,
        uint16_t srcPort,
        const std::string& dstIP,
        uint16_t dstPort
    );

    // ========================================================================
    // EMAIL ANALYSIS
    // ========================================================================

    /**
     * @brief Scans raw email content.
     * @param emailData Raw email (RFC 5322).
     * @return Analysis result.
     */
    [[nodiscard]] EmailAnalysis ScanEmail(const std::vector<uint8_t>& emailData);

    /**
     * @brief Scans email from file.
     * @param emlPath Path to .eml file.
     * @return Analysis result.
     */
    [[nodiscard]] EmailAnalysis ScanEmailFile(const std::wstring& emlPath);

    /**
     * @brief Analyzes email headers only.
     * @param headerData Raw headers.
     * @return Parsed header.
     */
    [[nodiscard]] EmailHeader ParseHeaders(std::span<const uint8_t> headerData);

    // ========================================================================
    // ATTACHMENT ANALYSIS
    // ========================================================================

    /**
     * @brief Scans an attachment.
     * @param data Attachment data.
     * @param filename Filename.
     * @param contentType MIME type.
     * @return Attachment info.
     */
    [[nodiscard]] AttachmentInfo ScanAttachment(
        std::span<const uint8_t> data,
        const std::string& filename,
        const std::string& contentType
    );

    /**
     * @brief Extracts and scans archive.
     * @param archiveData Archive data.
     * @param filename Archive filename.
     * @return Vector of attachment info.
     */
    [[nodiscard]] std::vector<AttachmentInfo> ScanArchive(
        std::span<const uint8_t> archiveData,
        const std::string& filename
    );

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes URLs in content.
     * @param content Email content.
     * @return Vector of URL info.
     */
    [[nodiscard]] std::vector<URLInfo> AnalyzeURLs(const std::string& content);

    // ========================================================================
    // PHISHING ANALYSIS
    // ========================================================================

    /**
     * @brief Analyzes email for phishing.
     * @param analysis Email analysis.
     * @return Phishing analysis.
     */
    [[nodiscard]] PhishingAnalysis AnalyzePhishing(const EmailAnalysis& analysis);

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    /**
     * @brief Gets active email sessions.
     * @return Vector of active sessions.
     */
    [[nodiscard]] std::vector<EmailSession> GetActiveSessions() const;

    /**
     * @brief Gets session by ID.
     * @param sessionId Session ID.
     * @return Session info, or nullopt.
     */
    [[nodiscard]] std::optional<EmailSession> GetSession(uint64_t sessionId) const;

    /**
     * @brief Terminates a session.
     * @param sessionId Session ID.
     */
    void TerminateSession(uint64_t sessionId);

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds sender to whitelist.
     * @param sender Sender email address.
     * @return True if added.
     */
    bool AddToWhitelist(const std::string& sender);

    /**
     * @brief Removes from whitelist.
     * @param sender Sender email address.
     * @return True if removed.
     */
    bool RemoveFromWhitelist(const std::string& sender);

    /**
     * @brief Checks if sender is whitelisted.
     * @param sender Sender email address.
     * @return True if whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(const std::string& sender) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAnalysisCallback(EmailAnalysisCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(EmailAlertCallback callback);
    [[nodiscard]] uint64_t RegisterAttachmentCallback(AttachmentCallback callback);
    [[nodiscard]] uint64_t RegisterPhishingCallback(PhishingCallback callback);
    [[nodiscard]] uint64_t RegisterMalwareCallback(MalwareCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const EmailScannerStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool PerformDiagnostics() const;
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    EmailScanner();
    ~EmailScanner();

    EmailScanner(const EmailScanner&) = delete;
    EmailScanner& operator=(const EmailScanner&) = delete;

    std::unique_ptr<EmailScannerImpl> m_impl;
};

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
