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
 * ShadowStrike NGAV - EMAIL PROTECTION ORCHESTRATOR MODULE
 * ============================================================================
 *
 * @file EmailProtection.hpp
 * @brief Enterprise-grade central orchestrator for comprehensive email security.
 *        Coordinates scanning, filtering, and protection across all email clients.
 *
 * Provides unified email protection including malware scanning, phishing detection,
 * spam filtering, and data loss prevention across Outlook, Thunderbird, and network proxies.
 *
 * CORE CAPABILITIES:
 * ==================
 *
 * 1. EMAIL CLIENT INTEGRATION
 *    - Microsoft Outlook MAPI/COM integration
 *    - Thunderbird native extension
 *    - POP3/IMAP/SMTP proxy mode
 *    - Microsoft Exchange Web Services (EWS)
 *    - Microsoft Graph API (Office 365)
 *    - Gmail API integration
 *    - .eml/.msg file scanning
 *
 * 2. THREAT DETECTION
 *    - Attachment malware scanning
 *    - Embedded macro detection
 *    - Phishing URL detection
 *    - Brand impersonation detection
 *    - BEC (Business Email Compromise)
 *    - Spam filtering
 *    - Zero-day attachment protection
 *
 * 3. DATA LOSS PREVENTION
 *    - Sensitive data detection (PII, PCI, PHI)
 *    - Credit card number detection
 *    - Social security number detection
 *    - Policy-based blocking
 *    - Content encryption enforcement
 *
 * 4. ADVANCED ANALYSIS
 *    - Header anomaly detection
 *    - SPF/DKIM/DMARC verification
 *    - Sender reputation scoring
 *    - URL sandboxing
 *    - Attachment sandboxing
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for URL/domain/hash IOCs
 * - SignatureStore for malware signatures
 * - PatternStore for detection patterns
 * - HashStore for known-bad hashes
 * - Whitelist for trusted senders/domains
 *
 * @note Thread-safe singleton design.
 * @note Supports real-time and batch processing.
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
#include <queue>
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
#include "../Utils/FileUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../SignatureStore/SignatureStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Email {
    class EmailProtectionImpl;
    class AttachmentScanner;
    class PhishingEmailDetector;
    class SpamDetector;
    class OutlookScanner;
    class ThunderbirdScanner;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace EmailProtectionConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum email body scan size
    inline constexpr size_t MAX_EMAIL_BODY_SIZE = 10 * 1024 * 1024;  // 10MB
    
    /// @brief Maximum attachment size
    inline constexpr size_t MAX_ATTACHMENT_SIZE = 100 * 1024 * 1024;  // 100MB
    
    /// @brief Maximum attachments per email
    inline constexpr size_t MAX_ATTACHMENTS_PER_EMAIL = 100;
    
    /// @brief Maximum URLs to analyze
    inline constexpr size_t MAX_URLS_PER_EMAIL = 200;
    
    /// @brief Maximum recipients
    inline constexpr size_t MAX_RECIPIENTS = 500;
    
    /// @brief Scan timeout
    inline constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;
    
    /// @brief Queue size
    inline constexpr size_t DEFAULT_QUEUE_SIZE = 10000;

    /// @brief Known dangerous attachment extensions
    inline constexpr const char* DANGEROUS_EXTENSIONS[] = {
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".jse", ".wsh", ".wsf", ".scr", ".hta", ".pif", ".reg",
        ".msi", ".msp", ".dll", ".cpl", ".jar", ".lnk"
    };

    /// @brief Archive extensions requiring deep scan
    inline constexpr const char* ARCHIVE_EXTENSIONS[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        ".cab", ".iso", ".img", ".arj", ".lzh", ".ace"
    };

    /// @brief Office document extensions with macro support
    inline constexpr const char* MACRO_EXTENSIONS[] = {
        ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
        ".dotm", ".xlsb", ".mdb", ".accdb"
    };

}  // namespace EmailProtectionConstants

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
 * @brief Email source/client type
 */
enum class EmailSource : uint8_t {
    Unknown             = 0,
    OutlookAddin        = 1,    ///< Outlook COM/MAPI add-in
    OutlookCOM          = 2,    ///< Outlook COM automation
    ThunderbirdExt      = 3,    ///< Thunderbird extension
    NetworkProxyPOP3    = 4,    ///< POP3 proxy
    NetworkProxyIMAP    = 5,    ///< IMAP proxy
    NetworkProxySMTP    = 6,    ///< SMTP proxy
    ExchangeEWS         = 7,    ///< Exchange Web Services
    Office365Graph      = 8,    ///< Microsoft Graph API
    GmailAPI            = 9,    ///< Gmail API
    FileSystemEML       = 10,   ///< .eml file
    FileSystemMSG       = 11,   ///< .msg file
    FileSystemMBOX      = 12,   ///< mbox format
    ManualSubmission    = 13    ///< User-submitted
};

/**
 * @brief Scan action to take
 */
enum class ScanAction : uint8_t {
    Allow               = 0,    ///< Allow email through
    Block               = 1,    ///< Block/reject email
    Quarantine          = 2,    ///< Move to quarantine
    TagSubject          = 3,    ///< Tag subject (e.g., [SPAM])
    StripAttachments    = 4,    ///< Remove attachments
    Defer               = 5,    ///< Defer for manual review
    Sandbox             = 6,    ///< Send to sandbox
    Encrypt             = 7,    ///< Force encryption
    Redirect            = 8,    ///< Redirect to admin
    Log                 = 9     ///< Log only
};

/**
 * @brief Email threat type
 */
enum class EmailThreatType : uint32_t {
    None                    = 0,
    Malware                 = 1 << 0,
    Phishing                = 1 << 1,
    Spam                    = 1 << 2,
    BEC                     = 1 << 3,
    Ransomware              = 1 << 4,
    MaliciousURL            = 1 << 5,
    MaliciousAttachment     = 1 << 6,
    SuspiciousMacro         = 1 << 7,
    SpoofedSender           = 1 << 8,
    DLPViolation            = 1 << 9,
    PolicyViolation         = 1 << 10,
    HeaderAnomaly           = 1 << 11,
    Impersonation           = 1 << 12,
    ZeroDayThreat           = 1 << 13,
    Scam                    = 1 << 14,
    Extortion               = 1 << 15
};

/**
 * @brief Email direction
 */
enum class EmailDirection : uint8_t {
    Inbound     = 0,
    Outbound    = 1,
    Internal    = 2
};

/**
 * @brief Scan priority
 */
enum class ScanPriority : uint8_t {
    Low         = 0,
    Normal      = 1,
    High        = 2,
    Critical    = 3
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

/**
 * @brief DLP data category
 */
enum class DLPCategory : uint32_t {
    None                = 0,
    CreditCard          = 1 << 0,
    SocialSecurity      = 1 << 1,
    DriverLicense       = 1 << 2,
    Passport            = 1 << 3,
    BankAccount         = 1 << 4,
    HealthInfo          = 1 << 5,
    FinancialData       = 1 << 6,
    SourceCode          = 1 << 7,
    Credentials         = 1 << 8,
    PersonalAddress     = 1 << 9,
    PhoneNumber         = 1 << 10,
    IntellectualProp    = 1 << 11,
    Confidential        = 1 << 12
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Email attachment information
 */
struct EmailAttachment {
    /// @brief Filename
    std::string fileName;
    
    /// @brief MIME type
    std::string mimeType;
    
    /// @brief Content-ID (for inline)
    std::string contentId;
    
    /// @brief Size in bytes
    size_t sizeBytes = 0;
    
    /// @brief Temp file path for scanning
    fs::path tempFilePath;
    
    /// @brief SHA-256 hash
    std::string sha256;
    
    /// @brief MD5 hash (for compatibility)
    std::string md5;
    
    /// @brief SHA-1 hash
    std::string sha1;
    
    /// @brief Is inline attachment
    bool isInline = false;
    
    /// @brief Is encrypted (password protected)
    bool isEncrypted = false;
    
    /// @brief Is archive
    bool isArchive = false;
    
    /// @brief Contains macros
    bool containsMacros = false;
    
    /// @brief Nested file count (if archive)
    size_t nestedFileCount = 0;
    
    /// @brief Detected file type (magic)
    std::string detectedType;
    
    /// @brief Extension mismatch
    bool extensionMismatch = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Email header
 */
struct EmailHeader {
    std::string name;
    std::string value;
    std::string rawValue;  // Unfolded
};

/**
 * @brief Received hop in email path
 */
struct ReceivedHop {
    std::string fromHost;
    std::string byHost;
    std::string timestamp;
    std::string protocol;
    std::string ipAddress;
};

/**
 * @brief Email message
 */
struct EmailMessage {
    /// @brief Unique message ID
    std::string messageId;
    
    /// @brief Internet Message-ID header
    std::string internetMessageId;
    
    /// @brief In-Reply-To header
    std::string inReplyTo;
    
    /// @brief References header
    std::vector<std::string> references;
    
    /// @brief Sender (From header)
    std::string sender;
    
    /// @brief Display name
    std::string senderDisplayName;
    
    /// @brief Envelope from (MAIL FROM)
    std::string envelopeSender;
    
    /// @brief Reply-To address
    std::string replyTo;
    
    /// @brief Return-Path
    std::string returnPath;
    
    /// @brief To recipients
    std::vector<std::string> toRecipients;
    
    /// @brief CC recipients
    std::vector<std::string> ccRecipients;
    
    /// @brief BCC recipients
    std::vector<std::string> bccRecipients;
    
    /// @brief Subject
    std::string subject;
    
    /// @brief Plain text body
    std::string bodyText;
    
    /// @brief HTML body
    std::string bodyHtml;
    
    /// @brief Attachments
    std::vector<EmailAttachment> attachments;
    
    /// @brief Embedded URLs
    std::vector<std::string> embeddedUrls;
    
    /// @brief All headers
    std::vector<EmailHeader> headers;
    
    /// @brief Received hops
    std::vector<ReceivedHop> receivedHops;
    
    /// @brief Email source
    EmailSource source = EmailSource::Unknown;
    
    /// @brief Direction
    EmailDirection direction = EmailDirection::Inbound;
    
    /// @brief Priority
    ScanPriority priority = ScanPriority::Normal;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Date header
    std::string dateHeader;
    
    /// @brief SPF result
    std::optional<bool> spfResult;
    
    /// @brief DKIM result
    std::optional<bool> dkimResult;
    
    /// @brief DMARC result
    std::optional<bool> dmarcResult;
    
    /// @brief Raw email size
    size_t rawSize = 0;
    
    /// @brief Is encrypted (S/MIME or PGP)
    bool isEncrypted = false;
    
    /// @brief Is signed
    bool isSigned = false;
    
    /// @brief User context (for DLP)
    std::string userContext;
    
    [[nodiscard]] std::string GetHeader(const std::string& name) const;
    [[nodiscard]] std::vector<std::string> GetAllRecipients() const;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Threat detail
 */
struct ThreatDetail {
    /// @brief Threat type
    EmailThreatType type = EmailThreatType::None;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Description
    std::string description;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief Severity (1-10)
    int severity = 0;
    
    /// @brief Affected component
    std::string affectedComponent;
    
    /// @brief IOC value
    std::string iocValue;
    
    /// @brief Detection method
    std::string detectionMethod;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DLP violation
 */
struct DLPViolation {
    /// @brief Category
    DLPCategory category = DLPCategory::None;
    
    /// @brief Match count
    int matchCount = 0;
    
    /// @brief Matched pattern
    std::string pattern;
    
    /// @brief Location (body, subject, attachment)
    std::string location;
    
    /// @brief Redacted sample
    std::string redactedSample;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Email scan result
 */
struct EmailScanResult {
    /// @brief Message ID
    std::string messageId;
    
    /// @brief Overall verdict
    bool isClean = true;
    
    /// @brief Is spam
    bool isSpam = false;
    
    /// @brief Spam score (0-100)
    int spamScore = 0;
    
    /// @brief Is phishing
    bool isPhishing = false;
    
    /// @brief Phishing confidence
    int phishingConfidence = 0;
    
    /// @brief Has malware
    bool hasMalware = false;
    
    /// @brief Has DLP violations
    bool hasDLPViolation = false;
    
    /// @brief Recommended action
    ScanAction recommendedAction = ScanAction::Allow;
    
    /// @brief Detected threats (bitmask)
    EmailThreatType detectedThreats = EmailThreatType::None;
    
    /// @brief Threat details
    std::vector<ThreatDetail> threatDetails;
    
    /// @brief DLP violations
    std::vector<DLPViolation> dlpViolations;
    
    /// @brief Malicious attachment names
    std::vector<std::string> maliciousAttachments;
    
    /// @brief Malicious URLs
    std::vector<std::string> maliciousUrls;
    
    /// @brief Blocked attachments
    std::vector<std::string> blockedAttachments;
    
    /// @brief Primary threat name
    std::string primaryThreatName;
    
    /// @brief Risk score (0-100)
    int riskScore = 0;
    
    /// @brief Scan duration
    std::chrono::microseconds scanDuration{0};
    
    /// @brief Scan timestamp
    SystemTimePoint scanTimestamp;
    
    /// @brief Scan log
    std::string scanLog;
    
    /// @brief Action taken
    std::string actionTaken;
    
    [[nodiscard]] bool ShouldBlock() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct EmailProtectionConfiguration {
    /// @brief Enable protection
    bool enabled = true;
    
    // Client integration
    bool enableOutlookIntegration = true;
    bool enableThunderbirdIntegration = false;
    bool enableNetworkProxy = false;
    bool enableO365Integration = false;
    bool enableGmailIntegration = false;
    bool enableExchangeEWS = false;
    
    // Scanning options
    bool scanAttachments = true;
    bool scanLinks = true;
    bool scanArchives = true;
    bool detectSpam = true;
    bool detectPhishing = true;
    bool detectMalware = true;
    bool detectDLP = false;
    bool sandboxAttachments = false;
    bool sandboxUrls = false;
    
    // Authentication checks
    bool verifySPF = true;
    bool verifyDKIM = true;
    bool verifyDMARC = true;
    
    // Actions
    ScanAction actionPhishing = ScanAction::Block;
    ScanAction actionMalware = ScanAction::Quarantine;
    ScanAction actionSpam = ScanAction::TagSubject;
    ScanAction actionDLP = ScanAction::Block;
    ScanAction actionSuspicious = ScanAction::Defer;
    
    // Thresholds
    int spamThreshold = 70;
    int phishingThreshold = 80;
    int dlpThreshold = 1;  // Violations to trigger
    
    // Tags
    std::string spamTagPrefix = "[SPAM] ";
    std::string suspiciousTagPrefix = "[SUSPICIOUS] ";
    
    // Whitelist
    std::vector<std::string> trustedSenders;
    std::vector<std::string> trustedDomains;
    std::vector<std::string> bypassPatterns;
    
    // Block lists
    std::vector<std::string> blockedExtensions;
    std::vector<std::string> blockedMimeTypes;
    
    // Limits
    size_t maxEmailBodySize = EmailProtectionConstants::MAX_EMAIL_BODY_SIZE;
    size_t maxAttachmentSize = EmailProtectionConstants::MAX_ATTACHMENT_SIZE;
    size_t maxAttachmentsPerEmail = EmailProtectionConstants::MAX_ATTACHMENTS_PER_EMAIL;
    uint32_t scanTimeoutMs = EmailProtectionConstants::DEFAULT_SCAN_TIMEOUT_MS;
    
    // Quarantine
    std::string quarantinePath;
    size_t maxQuarantineSize = 10ULL * 1024 * 1024 * 1024;  // 10GB
    uint32_t quarantineRetentionDays = 30;
    
    // Logging
    bool verboseLogging = false;
    bool logCleanEmails = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Statistics
 */
struct EmailProtectionStatistics {
    std::atomic<uint64_t> totalScanned{0};
    std::atomic<uint64_t> cleanEmails{0};
    std::atomic<uint64_t> spamDetected{0};
    std::atomic<uint64_t> phishingDetected{0};
    std::atomic<uint64_t> malwareDetected{0};
    std::atomic<uint64_t> becDetected{0};
    std::atomic<uint64_t> dlpViolations{0};
    std::atomic<uint64_t> attachmentsScanned{0};
    std::atomic<uint64_t> maliciousAttachments{0};
    std::atomic<uint64_t> urlsScanned{0};
    std::atomic<uint64_t> maliciousUrls{0};
    std::atomic<uint64_t> quarantined{0};
    std::atomic<uint64_t> blocked{0};
    std::atomic<uint64_t> tagged{0};
    std::atomic<uint64_t> allowed{0};
    std::atomic<uint64_t> spfFailed{0};
    std::atomic<uint64_t> dkimFailed{0};
    std::atomic<uint64_t> dmarcFailed{0};
    std::atomic<uint64_t> scanErrors{0};
    std::array<std::atomic<uint64_t>, 16> bySource{};
    std::array<std::atomic<uint64_t>, 3> byDirection{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Quarantine entry
 */
struct QuarantineEntry {
    /// @brief Quarantine ID
    std::string quarantineId;
    
    /// @brief Original message ID
    std::string messageId;
    
    /// @brief Subject
    std::string subject;
    
    /// @brief Sender
    std::string sender;
    
    /// @brief Recipients
    std::vector<std::string> recipients;
    
    /// @brief Threat type
    EmailThreatType threatType = EmailThreatType::None;
    
    /// @brief Threat name
    std::string threatName;
    
    /// @brief Quarantine timestamp
    SystemTimePoint quarantineTime;
    
    /// @brief Expiry timestamp
    SystemTimePoint expiryTime;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief File size
    size_t fileSize = 0;
    
    /// @brief Is released
    bool isReleased = false;
    
    /// @brief Released by
    std::string releasedBy;
    
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ScanResultCallback = std::function<void(const EmailScanResult&)>;
using ThreatDetectedCallback = std::function<void(const EmailMessage&, const ThreatDetail&)>;
using QuarantineCallback = std::function<void(const QuarantineEntry&)>;
using DLPViolationCallback = std::function<void(const EmailMessage&, const DLPViolation&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// EMAIL PROTECTION ORCHESTRATOR CLASS
// ============================================================================

/**
 * @class EmailProtection
 * @brief Enterprise email protection orchestrator
 */
class EmailProtection final {
public:
    [[nodiscard]] static EmailProtection& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    EmailProtection(const EmailProtection&) = delete;
    EmailProtection& operator=(const EmailProtection&) = delete;
    EmailProtection(EmailProtection&&) = delete;
    EmailProtection& operator=(EmailProtection&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const EmailProtectionConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const EmailProtectionConfiguration& config);
    [[nodiscard]] EmailProtectionConfiguration GetConfiguration() const;

    // ========================================================================
    // SCANNING
    // ========================================================================
    
    /// @brief Scan email message synchronously
    [[nodiscard]] EmailScanResult ScanMessage(const EmailMessage& message);
    
    /// @brief Scan email message asynchronously
    [[nodiscard]] std::future<EmailScanResult> ScanMessageAsync(
        const EmailMessage& message,
        ScanPriority priority = ScanPriority::Normal);
    
    /// @brief Scan .eml file
    [[nodiscard]] EmailScanResult ScanEMLFile(const fs::path& path);
    
    /// @brief Scan .msg file
    [[nodiscard]] EmailScanResult ScanMSGFile(const fs::path& path);
    
    /// @brief Scan raw email data
    [[nodiscard]] EmailScanResult ScanRawEmail(
        const std::vector<uint8_t>& data,
        EmailSource source = EmailSource::ManualSubmission);
    
    /// @brief Batch scan multiple emails
    [[nodiscard]] std::vector<EmailScanResult> ScanBatch(
        const std::vector<EmailMessage>& messages);

    // ========================================================================
    // CLIENT INTEGRATION
    // ========================================================================
    
    /// @brief Hook into Outlook
    [[nodiscard]] bool HookOutlook();
    
    /// @brief Unhook from Outlook
    void UnhookOutlook();
    
    /// @brief Is Outlook hooked
    [[nodiscard]] bool IsOutlookHooked() const noexcept;
    
    /// @brief Start network proxy
    [[nodiscard]] bool StartNetworkProxy(
        uint16_t pop3Port = 110,
        uint16_t imapPort = 143,
        uint16_t smtpPort = 25);
    
    /// @brief Stop network proxy
    void StopNetworkProxy();

    // ========================================================================
    // QUARANTINE MANAGEMENT
    // ========================================================================
    
    /// @brief Get quarantine entries
    [[nodiscard]] std::vector<QuarantineEntry> GetQuarantineEntries(
        std::optional<size_t> limit = std::nullopt,
        std::optional<SystemTimePoint> since = std::nullopt);
    
    /// @brief Get quarantine entry
    [[nodiscard]] std::optional<QuarantineEntry> GetQuarantineEntry(
        const std::string& quarantineId);
    
    /// @brief Release from quarantine
    [[nodiscard]] bool ReleaseFromQuarantine(
        const std::string& quarantineId,
        const std::string& releasedBy);
    
    /// @brief Delete from quarantine
    [[nodiscard]] bool DeleteFromQuarantine(const std::string& quarantineId);
    
    /// @brief Get original email from quarantine
    [[nodiscard]] std::optional<EmailMessage> GetQuarantinedEmail(
        const std::string& quarantineId);
    
    /// @brief Clean expired quarantine entries
    [[nodiscard]] size_t CleanExpiredQuarantine();
    
    /// @brief Get quarantine statistics
    [[nodiscard]] size_t GetQuarantineCount() const;
    [[nodiscard]] size_t GetQuarantineSize() const;

    // ========================================================================
    // SUB-COMPONENT ACCESS
    // ========================================================================
    
    [[nodiscard]] AttachmentScanner& GetAttachmentScanner();
    [[nodiscard]] PhishingEmailDetector& GetPhishingDetector();
    [[nodiscard]] SpamDetector& GetSpamDetector();

    // ========================================================================
    // WHITELIST/BLOCKLIST
    // ========================================================================
    
    [[nodiscard]] bool AddTrustedSender(const std::string& email);
    [[nodiscard]] bool RemoveTrustedSender(const std::string& email);
    [[nodiscard]] bool IsTrustedSender(const std::string& email) const;
    
    [[nodiscard]] bool AddBlockedExtension(const std::string& extension);
    [[nodiscard]] bool RemoveBlockedExtension(const std::string& extension);

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterScanCallback(ScanResultCallback callback);
    void RegisterThreatCallback(ThreatDetectedCallback callback);
    void RegisterQuarantineCallback(QuarantineCallback callback);
    void RegisterDLPCallback(DLPViolationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] EmailProtectionStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    EmailProtection();
    ~EmailProtection();
    
    std::unique_ptr<EmailProtectionImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetEmailSourceName(EmailSource source) noexcept;
[[nodiscard]] std::string_view GetScanActionName(ScanAction action) noexcept;
[[nodiscard]] std::string_view GetThreatTypeName(EmailThreatType type) noexcept;
[[nodiscard]] std::string_view GetDirectionName(EmailDirection direction) noexcept;
[[nodiscard]] std::string_view GetDLPCategoryName(DLPCategory category) noexcept;

/// @brief Parse .eml file
[[nodiscard]] std::optional<EmailMessage> ParseEMLFile(const fs::path& path);

/// @brief Parse raw email
[[nodiscard]] std::optional<EmailMessage> ParseRawEmail(const std::vector<uint8_t>& data);

/// @brief Extract URLs from HTML
[[nodiscard]] std::vector<std::string> ExtractEmailUrls(
    const std::string& bodyText,
    const std::string& bodyHtml);

/// @brief Check if extension is dangerous
[[nodiscard]] bool IsDangerousExtension(std::string_view extension);

/// @brief Check if MIME type is blocked
[[nodiscard]] bool IsBlockedMimeType(std::string_view mimeType);

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_EMAIL_SCAN(message) \
    ::ShadowStrike::Email::EmailProtection::Instance().ScanMessage(message)

#define SS_EMAIL_SCAN_FILE(path) \
    ::ShadowStrike::Email::EmailProtection::Instance().ScanEMLFile(path)

#define SS_EMAIL_QUARANTINE_RELEASE(id, user) \
    ::ShadowStrike::Email::EmailProtection::Instance().ReleaseFromQuarantine(id, user)