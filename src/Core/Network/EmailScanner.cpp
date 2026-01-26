/**
 * ============================================================================
 * ShadowStrike Core Network - EMAIL SCANNER IMPLEMENTATION
 * ============================================================================
 *
 * @file EmailScanner.cpp
 * @brief Enterprise-grade email security scanning and threat detection.
 *
 * This module provides comprehensive email security through:
 * - MIME parsing with Base64/Quoted-Printable decoding
 * - Malware scanning of attachments (executables, macros, scripts)
 * - Phishing detection (URL analysis, sender spoofing, brand impersonation)
 * - Spam filtering with Bayesian-style scoring
 * - Business Email Compromise (BEC) detection
 * - Data Loss Prevention (DLP) for PII/financial data
 * - SPF/DKIM/DMARC authentication validation
 * - Protocol parsing for SMTP, IMAP, POP3
 *
 * Integration:
 * - FileTypeAnalyzer: File type verification and spoofing detection
 * - ExecutableAnalyzer: PE/ELF binary analysis
 * - PatternStore: Phishing/malware pattern matching
 * - ThreatIntel: Domain/IP reputation lookups
 * - Whitelist: Trusted sender verification
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "EmailScanner.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../FileSystem/FileTypeAnalyzer.hpp"
#include "../FileSystem/ExecutableAnalyzer.hpp"

// Standard library
#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>
#include <iomanip>
#include <ctime>

namespace ShadowStrike {
namespace Core {
namespace Network {

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Base64 decoding.
 */
std::vector<uint8_t> Base64Decode(std::string_view input) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<uint8_t> result;
    result.reserve((input.size() * 3) / 4);

    std::array<int, 4> charArray;
    int i = 0;

    for (char c : input) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        if (c == '=') break;

        const size_t pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;

        charArray[i++] = static_cast<int>(pos);

        if (i == 4) {
            result.push_back(static_cast<uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
            result.push_back(static_cast<uint8_t>(((charArray[1] & 0x0f) << 4) + ((charArray[2] & 0x3c) >> 2)));
            result.push_back(static_cast<uint8_t>(((charArray[2] & 0x03) << 6) + charArray[3]));
            i = 0;
        }
    }

    if (i > 0) {
        if (i >= 2) {
            result.push_back(static_cast<uint8_t>((charArray[0] << 2) + ((charArray[1] & 0x30) >> 4)));
        }
        if (i >= 3) {
            result.push_back(static_cast<uint8_t>(((charArray[1] & 0x0f) << 4) + ((charArray[2] & 0x3c) >> 2)));
        }
    }

    return result;
}

/**
 * @brief Quoted-Printable decoding.
 */
std::string QuotedPrintableDecode(std::string_view input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '=' && i + 2 < input.size()) {
            // Soft line break
            if (input[i + 1] == '\r' && input[i + 2] == '\n') {
                i += 2;
                continue;
            }
            if (input[i + 1] == '\n') {
                i += 1;
                continue;
            }

            // Hex encoded character
            const char hex[3] = { input[i + 1], input[i + 2], '\0' };
            char* end;
            const long val = std::strtol(hex, &end, 16);
            if (end == hex + 2) {
                result += static_cast<char>(val);
                i += 2;
                continue;
            }
        }
        result += input[i];
    }

    return result;
}

/**
 * @brief Extract email address from RFC 5322 format.
 */
EmailAddress ParseEmailAddress(const std::string& input) {
    EmailAddress addr;

    // Pattern: "Display Name" <local@domain> or local@domain
    static const std::regex emailRegex(
        R"((?:([^<]*?)\s*<)?([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+)@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*)>?)"
    );

    std::smatch match;
    if (std::regex_search(input, match, emailRegex)) {
        addr.displayName = match[1].str();
        addr.localPart = match[2].str();
        addr.domain = match[3].str();
        addr.fullAddress = addr.localPart + "@" + addr.domain;
        addr.isValid = true;

        // Trim display name
        if (!addr.displayName.empty()) {
            addr.displayName.erase(0, addr.displayName.find_first_not_of(" \t\""));
            addr.displayName.erase(addr.displayName.find_last_not_of(" \t\"") + 1);
        }

        // Check domain validity
        addr.isDomainValid = !addr.domain.empty() && addr.domain.find('.') != std::string::npos;

        // Check display name mismatch (phishing indicator)
        if (!addr.displayName.empty()) {
            std::string lowerDisplay = addr.displayName;
            std::string lowerDomain = addr.domain;
            std::transform(lowerDisplay.begin(), lowerDisplay.end(), lowerDisplay.begin(), ::tolower);
            std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

            // If display name looks like an email but doesn't match
            if (lowerDisplay.find('@') != std::string::npos &&
                lowerDisplay.find(lowerDomain) == std::string::npos) {
                addr.hasDisplayNameMismatch = true;
            }
        }
    }

    return addr;
}

/**
 * @brief Extract URLs from text content.
 */
std::vector<std::string> ExtractURLs(const std::string& content) {
    std::vector<std::string> urls;

    // Pattern for URLs
    static const std::regex urlRegex(
        R"((https?|ftp)://[^\s<>"{}|\\^`\[\]]+)",
        std::regex::icase
    );

    auto wordsBegin = std::sregex_iterator(content.begin(), content.end(), urlRegex);
    auto wordsEnd = std::sregex_iterator();

    for (std::sregex_iterator i = wordsBegin; i != wordsEnd; ++i) {
        std::smatch match = *i;
        urls.push_back(match.str());
        if (urls.size() >= EmailScannerConstants::MAX_URLS_PER_EMAIL) {
            break;
        }
    }

    return urls;
}

/**
 * @brief Calculate Levenshtein distance for brand impersonation detection.
 */
size_t LevenshteinDistance(std::string_view s1, std::string_view s2) {
    const size_t len1 = s1.size();
    const size_t len2 = s2.size();

    std::vector<std::vector<size_t>> d(len1 + 1, std::vector<size_t>(len2 + 1));

    for (size_t i = 0; i <= len1; ++i) d[i][0] = i;
    for (size_t j = 0; j <= len2; ++j) d[0][j] = j;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            const size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            d[i][j] = std::min({
                d[i - 1][j] + 1,      // deletion
                d[i][j - 1] + 1,      // insertion
                d[i - 1][j - 1] + cost // substitution
            });
        }
    }

    return d[len1][len2];
}

/**
 * @brief Known brands for impersonation detection.
 */
const std::vector<std::string> g_knownBrands = {
    "paypal", "amazon", "microsoft", "google", "apple", "facebook",
    "linkedin", "twitter", "instagram", "netflix", "ebay", "dropbox",
    "adobe", "salesforce", "office365", "outlook", "gmail", "yahoo",
    "bank", "chase", "wellsfargo", "bankofamerica", "citibank"
};

/**
 * @brief Urgency keywords for phishing detection.
 */
const std::vector<std::string> g_urgencyKeywords = {
    "urgent", "immediate", "action required", "verify", "suspended",
    "locked", "expired", "confirm", "alert", "warning", "security",
    "unauthorized", "unusual activity", "click here", "act now",
    "limited time", "within 24 hours", "account will be closed"
};

/**
 * @brief Credential request keywords.
 */
const std::vector<std::string> g_credentialKeywords = {
    "password", "username", "login", "credential", "social security",
    "ssn", "credit card", "account number", "pin", "security code",
    "cvv", "routing number", "bank account", "verify identity"
};

/**
 * @brief Spam indicator keywords.
 */
const std::vector<std::string> g_spamKeywords = {
    "free", "winner", "congratulations", "claim", "prize", "lottery",
    "million dollars", "nigerian prince", "inheritance", "forex",
    "weight loss", "viagra", "cialis", "pharmacy", "casino",
    "click here now", "limited offer", "act fast", "bonus"
};

/**
 * @brief PII regex patterns for DLP.
 */
struct DLPPattern {
    std::regex pattern;
    std::string dataType;
    uint8_t severity;
};

const std::vector<DLPPattern> g_dlpPatterns = {
    // Credit card (basic pattern)
    {std::regex(R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)"), "Credit Card", 9},

    // SSN
    {std::regex(R"(\b\d{3}-\d{2}-\d{4}\b)"), "SSN", 10},

    // Email addresses (for data exfiltration)
    {std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)"), "Email Address", 3},

    // Phone numbers
    {std::regex(R"(\b\d{3}[-.]?\d{3}[-.]?\d{4}\b)"), "Phone Number", 4},
};

} // anonymous namespace

// ============================================================================
// CONFIGURATION STATIC METHODS
// ============================================================================

EmailScannerConfig EmailScannerConfig::CreateDefault() noexcept {
    EmailScannerConfig config;
    // Defaults already set in struct
    return config;
}

EmailScannerConfig EmailScannerConfig::CreateHighSecurity() noexcept {
    EmailScannerConfig config;
    config.enableMalwareScanning = true;
    config.enablePhishingDetection = true;
    config.enableSpamFiltering = true;
    config.enableDLP = true;
    config.enableBECDetection = true;
    config.enableAuthValidation = true;

    config.scanAttachments = true;
    config.extractArchives = true;
    config.sandboxExecutables = true;
    config.maxArchiveDepth = 5;

    config.scanURLs = true;

    config.spamThreshold = 0.6;
    config.phishingThreshold = 0.5;
    config.becThreshold = 0.4;

    config.malwareAction = EmailAction::BLOCK;
    config.phishingAction = EmailAction::BLOCK;
    config.spamAction = EmailAction::QUARANTINE;

    config.logThreatsOnly = true;
    config.retainEmailContent = false;

    return config;
}

EmailScannerConfig EmailScannerConfig::CreatePerformance() noexcept {
    EmailScannerConfig config;
    config.enableMalwareScanning = true;
    config.enablePhishingDetection = true;
    config.enableSpamFiltering = false;
    config.enableDLP = false;
    config.enableBECDetection = false;
    config.enableAuthValidation = false;

    config.scanAttachments = true;
    config.extractArchives = false;
    config.sandboxExecutables = false;

    config.scanURLs = true;
    config.maxURLsToScan = 50;

    config.workerThreads = 8;
    config.logThreatsOnly = true;

    return config;
}

EmailScannerConfig EmailScannerConfig::CreateForensic() noexcept {
    EmailScannerConfig config = CreateHighSecurity();

    config.logAllEmails = true;
    config.logThreatsOnly = false;
    config.retainEmailContent = true;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void EmailScannerStatistics::Reset() noexcept {
    totalPacketsProcessed.store(0, std::memory_order_relaxed);
    totalBytesProcessed.store(0, std::memory_order_relaxed);
    totalEmailsScanned.store(0, std::memory_order_relaxed);

    activeSessions.store(0, std::memory_order_relaxed);
    totalSessions.store(0, std::memory_order_relaxed);
    sessionsTimedOut.store(0, std::memory_order_relaxed);

    smtpEmails.store(0, std::memory_order_relaxed);
    imapEmails.store(0, std::memory_order_relaxed);
    pop3Emails.store(0, std::memory_order_relaxed);

    malwareDetected.store(0, std::memory_order_relaxed);
    phishingDetected.store(0, std::memory_order_relaxed);
    spamDetected.store(0, std::memory_order_relaxed);
    becDetected.store(0, std::memory_order_relaxed);
    dlpViolations.store(0, std::memory_order_relaxed);

    attachmentsScanned.store(0, std::memory_order_relaxed);
    maliciousAttachments.store(0, std::memory_order_relaxed);
    archivesExtracted.store(0, std::memory_order_relaxed);

    urlsScanned.store(0, std::memory_order_relaxed);
    maliciousUrls.store(0, std::memory_order_relaxed);
    phishingUrls.store(0, std::memory_order_relaxed);

    emailsBlocked.store(0, std::memory_order_relaxed);
    emailsQuarantined.store(0, std::memory_order_relaxed);
    attachmentsStripped.store(0, std::memory_order_relaxed);

    avgScanTimeUs.store(0, std::memory_order_relaxed);
    maxScanTimeUs.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterAnalysis(EmailAnalysisCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_analysisCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAlert(EmailAlertCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_alertCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAttachment(AttachmentCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_attachmentCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterPhishing(PhishingCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_phishingCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterMalware(MalwareCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_malwareCallbacks[id] = std::move(callback);
        return id;
    }

    bool Unregister(uint64_t id) {
        std::unique_lock lock(m_mutex);

        if (m_analysisCallbacks.erase(id)) return true;
        if (m_alertCallbacks.erase(id)) return true;
        if (m_attachmentCallbacks.erase(id)) return true;
        if (m_phishingCallbacks.erase(id)) return true;
        if (m_malwareCallbacks.erase(id)) return true;

        return false;
    }

    void InvokeAnalysis(const EmailAnalysis& analysis) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_analysisCallbacks) {
            try {
                callback(analysis);
            } catch (const std::exception& e) {
                Logger::Error("EmailScanner: Analysis callback exception: {}", e.what());
            }
        }
    }

    void InvokeAlert(const EmailAlert& alert) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_alertCallbacks) {
            try {
                callback(alert);
            } catch (const std::exception& e) {
                Logger::Error("EmailScanner: Alert callback exception: {}", e.what());
            }
        }
    }

    void InvokeAttachment(uint64_t emailId, const AttachmentInfo& attachment) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_attachmentCallbacks) {
            try {
                callback(emailId, attachment);
            } catch (const std::exception& e) {
                Logger::Error("EmailScanner: Attachment callback exception: {}", e.what());
            }
        }
    }

    void InvokePhishing(uint64_t emailId, const PhishingAnalysis& analysis) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_phishingCallbacks) {
            try {
                callback(emailId, analysis);
            } catch (const std::exception& e) {
                Logger::Error("EmailScanner: Phishing callback exception: {}", e.what());
            }
        }
    }

    void InvokeMalware(uint64_t emailId, ThreatType threat, const std::string& signature) {
        std::shared_lock lock(m_mutex);
        for (const auto& [id, callback] : m_malwareCallbacks) {
            try {
                callback(emailId, threat, signature);
            } catch (const std::exception& e) {
                Logger::Error("EmailScanner: Malware callback exception: {}", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, EmailAnalysisCallback> m_analysisCallbacks;
    std::unordered_map<uint64_t, EmailAlertCallback> m_alertCallbacks;
    std::unordered_map<uint64_t, AttachmentCallback> m_attachmentCallbacks;
    std::unordered_map<uint64_t, PhishingCallback> m_phishingCallbacks;
    std::unordered_map<uint64_t, MalwareCallback> m_malwareCallbacks;
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class EmailScannerImpl {
public:
    EmailScannerImpl() = default;
    ~EmailScannerImpl() {
        Stop();
    }

    // Prevent copying
    EmailScannerImpl(const EmailScannerImpl&) = delete;
    EmailScannerImpl& operator=(const EmailScannerImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const EmailScannerConfig& config) {
        std::unique_lock lock(m_mutex);

        try {
            Logger::Info("EmailScanner: Initializing...");

            m_config = config;

            // Initialize callback manager
            m_callbackManager = std::make_unique<CallbackManager>();

            // Verify infrastructure
            if (!FileSystem::FileTypeAnalyzer::Instance().Initialize(
                FileSystem::FileTypeAnalyzerConfig::CreateDefault())) {
                Logger::Warn("EmailScanner: FileTypeAnalyzer initialization warning");
            }

            if (!FileSystem::ExecutableAnalyzer::Instance().Initialize()) {
                Logger::Warn("EmailScanner: ExecutableAnalyzer initialization warning");
            }

            m_initialized = true;
            Logger::Info("EmailScanner: Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner: Initialization failed: {}", e.what());
            return false;
        }
    }

    bool Start() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            Logger::Error("EmailScanner: Not initialized");
            return false;
        }

        if (m_running) {
            Logger::Warn("EmailScanner: Already running");
            return true;
        }

        try {
            m_running = true;

            // Start worker threads
            for (uint32_t i = 0; i < m_config.workerThreads; ++i) {
                m_workers.emplace_back([this]() { WorkerThread(); });
            }

            Logger::Info("EmailScanner: Started with {} worker threads", m_config.workerThreads);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner: Start failed: {}", e.what());
            m_running = false;
            return false;
        }
    }

    void Stop() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_running) return;

            Logger::Info("EmailScanner: Stopping...");
            m_running = false;
        }

        m_cv.notify_all();

        // Wait for workers
        for (auto& worker : m_workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        m_workers.clear();

        Logger::Info("EmailScanner: Stopped");
    }

    void Shutdown() noexcept {
        Stop();
        std::unique_lock lock(m_mutex);
        m_initialized = false;
        m_sessions.clear();
        Logger::Info("EmailScanner: Shutdown complete");
    }

    bool IsRunning() const noexcept {
        return m_running.load(std::memory_order_acquire);
    }

    // ========================================================================
    // PACKET PROCESSING
    // ========================================================================

    void FeedPacket(std::span<const uint8_t> data, const std::string& srcIP,
                   uint16_t srcPort, const std::string& dstIP, uint16_t dstPort) {
        if (!m_running || data.empty()) {
            return;
        }

        try {
            m_stats.totalPacketsProcessed.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalBytesProcessed.fetch_add(data.size(), std::memory_order_relaxed);

            // Determine protocol from port
            EmailProtocol protocol = EmailProtocol::UNKNOWN;
            if (dstPort == EmailScannerConstants::PORT_SMTP || srcPort == EmailScannerConstants::PORT_SMTP) {
                protocol = EmailProtocol::SMTP;
            } else if (dstPort == EmailScannerConstants::PORT_SMTPS || srcPort == EmailScannerConstants::PORT_SMTPS) {
                protocol = EmailProtocol::SMTPS;
            } else if (dstPort == EmailScannerConstants::PORT_IMAP || srcPort == EmailScannerConstants::PORT_IMAP) {
                protocol = EmailProtocol::IMAP;
            } else if (dstPort == EmailScannerConstants::PORT_IMAPS || srcPort == EmailScannerConstants::PORT_IMAPS) {
                protocol = EmailProtocol::IMAPS;
            } else if (dstPort == EmailScannerConstants::PORT_POP3 || srcPort == EmailScannerConstants::PORT_POP3) {
                protocol = EmailProtocol::POP3;
            } else if (dstPort == EmailScannerConstants::PORT_POP3S || srcPort == EmailScannerConstants::PORT_POP3S) {
                protocol = EmailProtocol::POP3S;
            }

            if (protocol == EmailProtocol::UNKNOWN) {
                return;
            }

            // Create or update session
            const std::string sessionKey = srcIP + ":" + std::to_string(srcPort) + "-" +
                                          dstIP + ":" + std::to_string(dstPort);

            std::unique_lock lock(m_sessionMutex);
            auto it = m_sessionMap.find(sessionKey);
            if (it == m_sessionMap.end()) {
                // New session
                const uint64_t sessionId = m_nextSessionId++;
                EmailSession session;
                session.sessionId = sessionId;
                session.protocol = protocol;
                session.clientIP = srcIP;
                session.clientPort = srcPort;
                session.serverIP = dstIP;
                session.serverPort = dstPort;
                session.startTime = std::chrono::system_clock::now();
                session.lastActivity = session.startTime;

                m_sessions[sessionId] = session;
                m_sessionMap[sessionKey] = sessionId;
                m_stats.totalSessions.fetch_add(1, std::memory_order_relaxed);
                m_stats.activeSessions.fetch_add(1, std::memory_order_relaxed);

                it = m_sessionMap.find(sessionKey);
            }

            const uint64_t sessionId = it->second;
            auto& session = m_sessions[sessionId];

            // Append data to session buffer
            session.buffer.insert(session.buffer.end(), data.begin(), data.end());
            session.lastActivity = std::chrono::system_clock::now();
            session.bytesTransferred += data.size();

            // Try to parse complete email
            ProcessSessionBuffer(session);

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::FeedPacket: {}", e.what());
        }
    }

    // ========================================================================
    // EMAIL ANALYSIS
    // ========================================================================

    EmailAnalysis ScanEmail(std::span<const uint8_t> emailData) {
        const auto startTime = std::chrono::high_resolution_clock::now();

        EmailAnalysis analysis;
        analysis.analysisId = m_nextAnalysisId.fetch_add(1, std::memory_order_relaxed);
        analysis.scannedAt = std::chrono::system_clock::now();
        analysis.emailSize = emailData.size();

        try {
            // Parse headers
            auto [headerEnd, headerData] = ExtractHeaders(emailData);
            analysis.header = ParseHeadersImpl(headerData);
            analysis.messageId = analysis.header.messageId;

            // Determine direction
            analysis.direction = DetermineDirection(analysis.header);

            // Check whitelist
            if (IsWhitelisted(analysis.header.from.fullAddress)) {
                analysis.result = ScanResult::CLEAN;
                analysis.action = EmailAction::ALLOW;

                const auto endTime = std::chrono::high_resolution_clock::now();
                analysis.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

                m_stats.totalEmailsScanned.fetch_add(1, std::memory_order_relaxed);
                return analysis;
            }

            // Parse body
            if (headerEnd < emailData.size()) {
                auto bodyData = emailData.subspan(headerEnd);
                ParseBody(bodyData, analysis);
            }

            // Scan attachments
            if (m_config.scanAttachments) {
                for (auto& attachment : analysis.attachments) {
                    ScanAttachmentImpl(attachment);
                    m_callbackManager->InvokeAttachment(analysis.analysisId, attachment);

                    if (attachment.riskLevel == AttachmentRisk::CRITICAL ||
                        attachment.riskLevel == AttachmentRisk::BLOCKED) {
                        analysis.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                        m_stats.maliciousAttachments.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // Scan URLs
            if (m_config.scanURLs) {
                std::string combinedContent = analysis.bodyText + " " + analysis.bodyHtml;
                analysis.urls = AnalyzeURLsImpl(combinedContent);
            }

            // Phishing detection
            if (m_config.enablePhishingDetection) {
                analysis.phishingAnalysis = AnalyzePhishingImpl(analysis);
                if (analysis.phishingAnalysis.isPhishing) {
                    analysis.threats.push_back(ThreatType::PHISHING_URL);
                    m_stats.phishingDetected.fetch_add(1, std::memory_order_relaxed);
                    m_callbackManager->InvokePhishing(analysis.analysisId, analysis.phishingAnalysis);
                }
            }

            // Spam detection
            if (m_config.enableSpamFiltering) {
                AnalyzeSpam(analysis);
            }

            // BEC detection
            if (m_config.enableBECDetection) {
                AnalyzeBEC(analysis);
            }

            // DLP scanning
            if (m_config.enableDLP) {
                AnalyzeDLP(analysis);
            }

            // Authentication validation
            if (m_config.enableAuthValidation) {
                analysis.authResults = ParseAuthenticationResults(analysis.header);
            }

            // Calculate threat score and determine action
            CalculateThreatScore(analysis);
            DetermineAction(analysis);

            // Create alerts
            if (analysis.result != ScanResult::CLEAN) {
                CreateAlerts(analysis);
            }

            // Update statistics
            const auto endTime = std::chrono::high_resolution_clock::now();
            analysis.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(endTime - startTime);

            m_stats.totalEmailsScanned.fetch_add(1, std::memory_order_relaxed);
            UpdateScanTimeStats(analysis.scanDuration.count());

            // Invoke callbacks
            m_callbackManager->InvokeAnalysis(analysis);

            Logger::Info("EmailScanner: Scanned email {} - Score: {}, Result: {}, Action: {}",
                analysis.messageId, analysis.threatScore,
                static_cast<int>(analysis.result), static_cast<int>(analysis.action));

            return analysis;

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ScanEmail: {}", e.what());
            analysis.result = ScanResult::ERROR;
            return analysis;
        }
    }

    EmailAnalysis ScanEmailFile(const std::wstring& emlPath) {
        try {
            auto fileData = Utils::FileUtils::ReadFileBytes(emlPath);
            if (fileData.empty()) {
                Logger::Error("EmailScanner: Failed to read email file");
                return EmailAnalysis{};
            }

            return ScanEmail(std::span<const uint8_t>(fileData.data(), fileData.size()));

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ScanEmailFile: {}", e.what());
            return EmailAnalysis{};
        }
    }

    EmailHeader ParseHeaders(std::span<const uint8_t> headerData) {
        return ParseHeadersImpl(headerData);
    }

    // ========================================================================
    // ATTACHMENT ANALYSIS
    // ========================================================================

    AttachmentInfo ScanAttachment(std::span<const uint8_t> data,
                                 const std::string& filename,
                                 const std::string& contentType) {
        AttachmentInfo info;
        info.attachmentId = m_nextAttachmentId.fetch_add(1, std::memory_order_relaxed);
        info.filename = filename;
        info.contentType = contentType;
        info.size = data.size();

        if (data.size() > m_config.maxAttachmentSize) {
            info.riskLevel = AttachmentRisk::BLOCKED;
            info.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
            return info;
        }

        // Store data if requested
        if (m_config.retainEmailContent && data.size() < 10 * 1024 * 1024) {
            info.data.assign(data.begin(), data.end());
        }

        ScanAttachmentImpl(info);
        m_stats.attachmentsScanned.fetch_add(1, std::memory_order_relaxed);

        return info;
    }

    std::vector<AttachmentInfo> ScanArchive(std::span<const uint8_t> archiveData,
                                           const std::string& filename) {
        std::vector<AttachmentInfo> results;

        // Archive extraction would use CompressionUtils
        // Simplified implementation - just mark as archive
        AttachmentInfo info;
        info.filename = filename;
        info.isArchive = true;
        info.size = archiveData.size();
        info.riskLevel = AttachmentRisk::MEDIUM;
        results.push_back(info);

        m_stats.archivesExtracted.fetch_add(1, std::memory_order_relaxed);
        return results;
    }

    // ========================================================================
    // URL ANALYSIS
    // ========================================================================

    std::vector<URLInfo> AnalyzeURLs(const std::string& content) {
        return AnalyzeURLsImpl(content);
    }

    // ========================================================================
    // PHISHING ANALYSIS
    // ========================================================================

    PhishingAnalysis AnalyzePhishing(const EmailAnalysis& analysis) {
        return AnalyzePhishingImpl(analysis);
    }

    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================

    std::vector<EmailSession> GetActiveSessions() const {
        std::shared_lock lock(m_sessionMutex);
        std::vector<EmailSession> sessions;
        sessions.reserve(m_sessions.size());

        for (const auto& [id, session] : m_sessions) {
            sessions.push_back(session);
        }

        return sessions;
    }

    std::optional<EmailSession> GetSession(uint64_t sessionId) const {
        std::shared_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void TerminateSession(uint64_t sessionId) {
        std::unique_lock lock(m_sessionMutex);
        auto it = m_sessions.find(sessionId);
        if (it != m_sessions.end()) {
            // Remove from session map
            const std::string key = it->second.clientIP + ":" +
                                   std::to_string(it->second.clientPort) + "-" +
                                   it->second.serverIP + ":" +
                                   std::to_string(it->second.serverPort);
            m_sessionMap.erase(key);
            m_sessions.erase(it);
            m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    bool AddToWhitelist(const std::string& sender) {
        std::unique_lock lock(m_whitelistMutex);
        auto [it, inserted] = m_whitelist.insert(sender);
        return inserted;
    }

    bool RemoveFromWhitelist(const std::string& sender) {
        std::unique_lock lock(m_whitelistMutex);
        return m_whitelist.erase(sender) > 0;
    }

    bool IsWhitelisted(const std::string& sender) const {
        std::shared_lock lock(m_whitelistMutex);
        return m_whitelist.contains(sender);
    }

    // ========================================================================
    // CALLBACK MANAGEMENT
    // ========================================================================

    uint64_t RegisterAnalysisCallback(EmailAnalysisCallback callback) {
        return m_callbackManager->RegisterAnalysis(std::move(callback));
    }

    uint64_t RegisterAlertCallback(EmailAlertCallback callback) {
        return m_callbackManager->RegisterAlert(std::move(callback));
    }

    uint64_t RegisterAttachmentCallback(AttachmentCallback callback) {
        return m_callbackManager->RegisterAttachment(std::move(callback));
    }

    uint64_t RegisterPhishingCallback(PhishingCallback callback) {
        return m_callbackManager->RegisterPhishing(std::move(callback));
    }

    uint64_t RegisterMalwareCallback(MalwareCallback callback) {
        return m_callbackManager->RegisterMalware(std::move(callback));
    }

    bool UnregisterCallback(uint64_t callbackId) {
        return m_callbackManager->Unregister(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const EmailScannerStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    bool PerformDiagnostics() const {
        Logger::Info("EmailScanner Diagnostics:");
        Logger::Info("  Initialized: {}", m_initialized);
        Logger::Info("  Running: {}", m_running.load());
        Logger::Info("  Active Sessions: {}", m_stats.activeSessions.load());
        Logger::Info("  Emails Scanned: {}", m_stats.totalEmailsScanned.load());
        Logger::Info("  Threats Detected: {}",
            m_stats.malwareDetected.load() + m_stats.phishingDetected.load());
        return true;
    }

    bool ExportDiagnostics(const std::wstring& outputPath) const {
        // Export detailed diagnostics - not implemented
        return false;
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void WorkerThread() {
        Logger::Info("EmailScanner: Worker thread started");

        while (m_running.load(std::memory_order_acquire)) {
            std::unique_lock lock(m_mutex);
            m_cv.wait_for(lock, std::chrono::seconds(1));

            // Session timeout cleanup
            CleanupTimedOutSessions();
        }

        Logger::Info("EmailScanner: Worker thread exited");
    }

    void CleanupTimedOutSessions() {
        std::unique_lock lock(m_sessionMutex);
        const auto now = std::chrono::system_clock::now();
        const auto timeout = std::chrono::milliseconds(m_config.sessionTimeoutMs);

        for (auto it = m_sessions.begin(); it != m_sessions.end();) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - it->second.lastActivity
            );

            if (elapsed > timeout) {
                const std::string key = it->second.clientIP + ":" +
                                       std::to_string(it->second.clientPort) + "-" +
                                       it->second.serverIP + ":" +
                                       std::to_string(it->second.serverPort);
                m_sessionMap.erase(key);
                it = m_sessions.erase(it);
                m_stats.activeSessions.fetch_sub(1, std::memory_order_relaxed);
                m_stats.sessionsTimedOut.fetch_add(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }

    void ProcessSessionBuffer(EmailSession& session) {
        // Look for email boundaries in buffer
        // This is a simplified implementation
        // Full SMTP/IMAP/POP3 parsing would be much more complex

        std::string bufferStr(session.buffer.begin(), session.buffer.end());

        // SMTP: DATA command followed by message and terminated by CRLF.CRLF
        size_t dataPos = bufferStr.find("\r\n.\r\n");
        if (dataPos != std::string::npos) {
            // Found complete email
            std::span<const uint8_t> emailData(session.buffer.data(), dataPos);

            auto analysis = ScanEmail(emailData);
            analysis.protocol = session.protocol;

            // Clear processed data
            session.buffer.erase(session.buffer.begin(), session.buffer.begin() + dataPos + 5);
            session.emailsProcessed++;
        }
    }

    std::pair<size_t, std::span<const uint8_t>> ExtractHeaders(std::span<const uint8_t> emailData) {
        // Find header/body separator (blank line)
        for (size_t i = 0; i + 3 < emailData.size(); ++i) {
            if (emailData[i] == '\r' && emailData[i + 1] == '\n' &&
                emailData[i + 2] == '\r' && emailData[i + 3] == '\n') {
                return {i + 4, emailData.subspan(0, i)};
            }
            if (emailData[i] == '\n' && emailData[i + 1] == '\n') {
                return {i + 2, emailData.subspan(0, i)};
            }
        }

        return {emailData.size(), emailData};
    }

    EmailHeader ParseHeadersImpl(std::span<const uint8_t> headerData) {
        EmailHeader header;

        try {
            std::string headerText(reinterpret_cast<const char*>(headerData.data()), headerData.size());
            std::istringstream stream(headerText);
            std::string line;
            std::string currentHeader;
            std::string currentValue;

            auto processHeader = [&]() {
                if (currentHeader.empty()) return;

                std::string lowerHeader = currentHeader;
                std::transform(lowerHeader.begin(), lowerHeader.end(), lowerHeader.begin(), ::tolower);

                if (lowerHeader == "from") {
                    header.from = ParseEmailAddress(currentValue);
                } else if (lowerHeader == "to") {
                    header.to.push_back(ParseEmailAddress(currentValue));
                } else if (lowerHeader == "cc") {
                    header.cc.push_back(ParseEmailAddress(currentValue));
                } else if (lowerHeader == "subject") {
                    header.subject = currentValue;
                    header.decodedSubject = currentValue; // Simplified
                } else if (lowerHeader == "message-id") {
                    header.messageId = currentValue;
                } else if (lowerHeader == "date") {
                    header.dateString = currentValue;
                } else if (lowerHeader == "reply-to") {
                    header.replyTo = ParseEmailAddress(currentValue);
                } else if (lowerHeader == "return-path") {
                    header.returnPath = currentValue;
                } else if (lowerHeader == "received") {
                    header.receivedHeaders.push_back(currentValue);
                } else if (lowerHeader == "authentication-results") {
                    header.authenticationResults = currentValue;
                } else if (lowerHeader == "dkim-signature") {
                    header.dkimSignature = currentValue;
                } else if (lowerHeader == "x-mailer") {
                    header.xMailer = currentValue;
                } else if (lowerHeader == "user-agent") {
                    header.userAgent = currentValue;
                } else if (lowerHeader == "content-type") {
                    header.contentType = currentValue;
                } else {
                    header.customHeaders[currentHeader] = currentValue;
                }
            };

            while (std::getline(stream, line)) {
                if (line.empty() || line == "\r") break;

                // Remove CR if present
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }

                // Check for header continuation (starts with space or tab)
                if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                    currentValue += " " + line.substr(1);
                } else {
                    // Process previous header
                    processHeader();

                    // Parse new header
                    size_t colonPos = line.find(':');
                    if (colonPos != std::string::npos) {
                        currentHeader = line.substr(0, colonPos);
                        currentValue = line.substr(colonPos + 1);

                        // Trim leading whitespace from value
                        currentValue.erase(0, currentValue.find_first_not_of(" \t"));
                    }
                }
            }

            // Process last header
            processHeader();

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ParseHeadersImpl: {}", e.what());
        }

        return header;
    }

    void ParseBody(std::span<const uint8_t> bodyData, EmailAnalysis& analysis) {
        try {
            const std::string contentType = analysis.header.contentType;

            // Simplified MIME parsing
            if (contentType.find("multipart") != std::string::npos) {
                ParseMultipartBody(bodyData, contentType, analysis);
            } else if (contentType.find("text/plain") != std::string::npos) {
                analysis.bodyText = std::string(
                    reinterpret_cast<const char*>(bodyData.data()),
                    bodyData.size()
                );
            } else if (contentType.find("text/html") != std::string::npos) {
                analysis.bodyHtml = std::string(
                    reinterpret_cast<const char*>(bodyData.data()),
                    bodyData.size()
                );
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ParseBody: {}", e.what());
        }
    }

    void ParseMultipartBody(std::span<const uint8_t> bodyData,
                           const std::string& contentType,
                           EmailAnalysis& analysis) {
        // Extract boundary
        size_t boundaryPos = contentType.find("boundary=");
        if (boundaryPos == std::string::npos) return;

        std::string boundary = contentType.substr(boundaryPos + 9);
        // Remove quotes if present
        if (!boundary.empty() && boundary.front() == '"') {
            boundary = boundary.substr(1, boundary.find('"', 1) - 1);
        }

        const std::string boundaryDelim = "--" + boundary;
        std::string bodyStr(reinterpret_cast<const char*>(bodyData.data()), bodyData.size());

        size_t pos = 0;
        while ((pos = bodyStr.find(boundaryDelim, pos)) != std::string::npos) {
            pos += boundaryDelim.length();

            // Check for end boundary
            if (pos + 2 < bodyStr.length() && bodyStr.substr(pos, 2) == "--") {
                break;
            }

            // Find next boundary
            size_t nextBoundary = bodyStr.find(boundaryDelim, pos);
            if (nextBoundary == std::string::npos) break;

            // Extract part
            std::string part = bodyStr.substr(pos, nextBoundary - pos);
            ParseMIMEPart(part, analysis);

            pos = nextBoundary;
        }
    }

    void ParseMIMEPart(const std::string& part, EmailAnalysis& analysis) {
        // Find headers/body separator
        size_t bodyPos = part.find("\r\n\r\n");
        if (bodyPos == std::string::npos) {
            bodyPos = part.find("\n\n");
            if (bodyPos == std::string::npos) return;
            bodyPos += 2;
        } else {
            bodyPos += 4;
        }

        std::string headers = part.substr(0, bodyPos);
        std::string body = part.substr(bodyPos);

        // Parse Content-Type and Content-Disposition
        std::string contentType;
        std::string contentDisposition;
        std::string contentEncoding;
        std::string filename;

        std::istringstream stream(headers);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("Content-Type:") == 0) {
                contentType = line.substr(13);
            } else if (line.find("Content-Disposition:") == 0) {
                contentDisposition = line.substr(20);

                // Extract filename
                size_t fnPos = contentDisposition.find("filename=");
                if (fnPos != std::string::npos) {
                    filename = contentDisposition.substr(fnPos + 9);
                    size_t endPos = filename.find_first_of(";\r\n");
                    if (endPos != std::string::npos) {
                        filename = filename.substr(0, endPos);
                    }
                    // Remove quotes
                    if (!filename.empty() && filename.front() == '"') {
                        filename = filename.substr(1, filename.length() - 2);
                    }
                }
            } else if (line.find("Content-Transfer-Encoding:") == 0) {
                contentEncoding = line.substr(26);
                contentEncoding.erase(0, contentEncoding.find_first_not_of(" \t"));
            }
        }

        // Decode body based on encoding
        std::vector<uint8_t> decodedBody;
        if (contentEncoding.find("base64") != std::string::npos) {
            decodedBody = Base64Decode(body);
        } else if (contentEncoding.find("quoted-printable") != std::string::npos) {
            std::string decoded = QuotedPrintableDecode(body);
            decodedBody.assign(decoded.begin(), decoded.end());
        } else {
            decodedBody.assign(body.begin(), body.end());
        }

        // Determine if attachment
        if (!filename.empty() || contentDisposition.find("attachment") != std::string::npos) {
            // This is an attachment
            AttachmentInfo attachment;
            attachment.filename = filename;
            attachment.contentType = contentType;
            attachment.size = decodedBody.size();
            attachment.data = std::move(decodedBody);

            if (contentDisposition.find("inline") != std::string::npos) {
                attachment.disposition = ContentDisposition::INLINE;
            } else {
                attachment.disposition = ContentDisposition::ATTACHMENT;
            }

            analysis.attachments.push_back(std::move(attachment));
        } else {
            // This is body content
            if (contentType.find("text/plain") != std::string::npos) {
                analysis.bodyText = std::string(decodedBody.begin(), decodedBody.end());
            } else if (contentType.find("text/html") != std::string::npos) {
                analysis.bodyHtml = std::string(decodedBody.begin(), decodedBody.end());
            }
        }
    }

    void ScanAttachmentImpl(AttachmentInfo& attachment) {
        try {
            // Calculate hashes
            if (!attachment.data.empty()) {
                auto sha256 = Utils::HashUtils::SHA256(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size())
                );
                std::copy(sha256.begin(), sha256.end(), attachment.sha256.begin());

                std::ostringstream oss;
                for (auto byte : sha256) {
                    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                }
                attachment.sha256Hex = oss.str();

                auto md5 = Utils::HashUtils::MD5(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size())
                );
                std::copy(md5.begin(), md5.end(), attachment.md5.begin());
            }

            // Detect actual file type
            if (!attachment.data.empty()) {
                auto typeInfo = FileSystem::FileTypeAnalyzer::Instance().AnalyzeBuffer(
                    std::span<const uint8_t>(attachment.data.data(), attachment.data.size()),
                    Utils::StringUtils::Utf8ToWide(attachment.filename)
                );

                attachment.detectedType = static_cast<int>(typeInfo.category) >= 0 ?
                    std::to_string(static_cast<int>(typeInfo.format)) : "Unknown";

                // Check for type mismatch (spoofing)
                if (typeInfo.isSpoofed) {
                    attachment.typeMismatch = true;
                    attachment.riskLevel = AttachmentRisk::HIGH;
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                }

                // Categorize attachment
                if (typeInfo.isExecutable) {
                    attachment.type = AttachmentType::EXECUTABLE;
                    attachment.riskLevel = AttachmentRisk::CRITICAL;
                    attachment.threats.push_back(ThreatType::MALWARE_ATTACHMENT);
                } else if (typeInfo.isScript) {
                    attachment.type = AttachmentType::SCRIPT;
                    attachment.riskLevel = AttachmentRisk::HIGH;
                    attachment.threats.push_back(ThreatType::MALWARE_SCRIPT);
                } else if (typeInfo.isArchive) {
                    attachment.type = AttachmentType::ARCHIVE;
                    attachment.isArchive = true;
                    attachment.riskLevel = AttachmentRisk::MEDIUM;
                } else if (typeInfo.canContainMacros) {
                    attachment.hasMacros = true;  // Possible
                    attachment.riskLevel = AttachmentRisk::MEDIUM;
                }
            }

            // Update scan result
            if (attachment.riskLevel >= AttachmentRisk::HIGH) {
                attachment.scanResult = ScanResult::MALICIOUS;
            } else if (attachment.riskLevel == AttachmentRisk::MEDIUM) {
                attachment.scanResult = ScanResult::SUSPICIOUS;
            } else {
                attachment.scanResult = ScanResult::CLEAN;
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ScanAttachmentImpl: {}", e.what());
            attachment.scanResult = ScanResult::ERROR;
        }
    }

    std::vector<URLInfo> AnalyzeURLsImpl(const std::string& content) {
        std::vector<URLInfo> urls;

        try {
            auto extractedUrls = ExtractURLs(content);
            m_stats.urlsScanned.fetch_add(extractedUrls.size(), std::memory_order_relaxed);

            for (const auto& url : extractedUrls) {
                URLInfo info;
                info.url = url;

                // Extract domain
                size_t domainStart = url.find("://");
                if (domainStart != std::string::npos) {
                    domainStart += 3;
                    size_t domainEnd = url.find('/', domainStart);
                    if (domainEnd == std::string::npos) {
                        domainEnd = url.length();
                    }
                    info.domain = url.substr(domainStart, domainEnd - domainStart);
                }

                // Check for phishing indicators
                AnalyzeURLForPhishing(info);

                if (info.isPhishing) {
                    m_stats.phishingUrls.fetch_add(1, std::memory_order_relaxed);
                }

                urls.push_back(std::move(info));
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::AnalyzeURLsImpl: {}", e.what());
        }

        return urls;
    }

    void AnalyzeURLForPhishing(URLInfo& info) {
        // Check for homograph attacks (IDN homographs)
        if (info.domain.find("xn--") != std::string::npos) {
            info.isHomograph = true;
            info.phishingScore += 0.3;
        }

        // Check for IP addresses in domain
        std::regex ipRegex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
        if (std::regex_search(info.domain, ipRegex)) {
            info.phishingScore += 0.2;
        }

        // Check for suspicious TLDs
        static const std::vector<std::string> suspiciousTLDs = {
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".pw"
        };
        for (const auto& tld : suspiciousTLDs) {
            if (info.domain.ends_with(tld)) {
                info.phishingScore += 0.15;
                break;
            }
        }

        // Check for brand impersonation in domain
        for (const auto& brand : g_knownBrands) {
            if (info.domain.find(brand) != std::string::npos &&
                info.domain.find(brand + ".com") == std::string::npos) {
                // Brand name in domain but not official domain
                info.phishingScore += 0.25;
            }
        }

        // Check for excessive subdomains
        size_t dotCount = std::count(info.domain.begin(), info.domain.end(), '.');
        if (dotCount > 3) {
            info.phishingScore += 0.1;
        }

        if (info.phishingScore >= 0.5) {
            info.isPhishing = true;
        }
    }

    PhishingAnalysis AnalyzePhishingImpl(const EmailAnalysis& analysis) {
        PhishingAnalysis phishing;

        try {
            double score = 0.0;

            // Check sender spoofing
            if (analysis.header.from.hasDisplayNameMismatch) {
                phishing.displayNameMismatch = true;
                phishing.indicators.push_back("Display name mismatch");
                score += 0.3;
            }

            // Check authentication failures
            if (!analysis.authResults.spfPass) {
                phishing.senderSpoofed = true;
                phishing.indicators.push_back("SPF failure");
                score += 0.2;
            }
            if (!analysis.authResults.dkimPass) {
                phishing.indicators.push_back("DKIM failure");
                score += 0.15;
            }
            if (!analysis.authResults.dmarcPass) {
                phishing.indicators.push_back("DMARC failure");
                score += 0.15;
            }

            // Check for urgency language
            std::string combinedContent = analysis.header.decodedSubject + " " +
                                         analysis.bodyText + " " + analysis.bodyHtml;
            std::string lowerContent = combinedContent;
            std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

            for (const auto& keyword : g_urgencyKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    phishing.hasUrgencyLanguage = true;
                    phishing.indicators.push_back("Urgency: " + keyword);
                    score += 0.05;
                }
            }

            // Check for credential requests
            for (const auto& keyword : g_credentialKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    phishing.hasCredentialRequest = true;
                    phishing.indicators.push_back("Credential request: " + keyword);
                    score += 0.1;
                }
            }

            // Check URLs
            for (const auto& url : analysis.urls) {
                if (url.isPhishing) {
                    phishing.hasSuspiciousLinks = true;
                    phishing.suspiciousUrlCount++;
                    phishing.indicators.push_back("Phishing URL: " + url.url);
                    score += 0.15;
                }
            }

            // Check for brand impersonation
            for (const auto& brand : g_knownBrands) {
                if (lowerContent.find(brand) != std::string::npos) {
                    const std::string senderDomain = analysis.header.from.domain;
                    std::string lowerDomain = senderDomain;
                    std::transform(lowerDomain.begin(), lowerDomain.end(), lowerDomain.begin(), ::tolower);

                    if (lowerDomain.find(brand) == std::string::npos) {
                        // Mentions brand but sender is not from brand domain
                        phishing.brandImpersonation = true;
                        phishing.impersonatedBrand = brand;
                        phishing.indicators.push_back("Brand impersonation: " + brand);
                        score += 0.25;
                        break;
                    }
                }
            }

            phishing.confidence = std::min(score, 1.0);
            phishing.indicatorCount = static_cast<uint32_t>(phishing.indicators.size());
            phishing.isPhishing = (phishing.confidence >= m_config.phishingThreshold);

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::AnalyzePhishingImpl: {}", e.what());
        }

        return phishing;
    }

    void AnalyzeSpam(EmailAnalysis& analysis) {
        try {
            double score = 0.0;

            std::string combinedContent = analysis.header.decodedSubject + " " +
                                         analysis.bodyText + " " + analysis.bodyHtml;
            std::string lowerContent = combinedContent;
            std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

            // Check spam keywords
            for (const auto& keyword : g_spamKeywords) {
                if (lowerContent.find(keyword) != std::string::npos) {
                    analysis.spamIndicators.push_back(keyword);
                    score += 0.1;
                }
            }

            // Excessive caps
            size_t capsCount = std::count_if(combinedContent.begin(), combinedContent.end(), ::isupper);
            if (combinedContent.length() > 0) {
                double capsRatio = static_cast<double>(capsCount) / combinedContent.length();
                if (capsRatio > 0.5) {
                    analysis.spamIndicators.push_back("Excessive capitals");
                    score += 0.15;
                }
            }

            // Excessive exclamation marks
            size_t exclCount = std::count(combinedContent.begin(), combinedContent.end(), '!');
            if (exclCount > 5) {
                analysis.spamIndicators.push_back("Excessive exclamation marks");
                score += 0.1;
            }

            // Missing or suspicious from address
            if (analysis.header.from.fullAddress.empty() || !analysis.header.from.isValid) {
                analysis.spamIndicators.push_back("Invalid sender");
                score += 0.2;
            }

            analysis.spamScore = std::min(score, 1.0);
            analysis.isSpam = (analysis.spamScore >= m_config.spamThreshold);

            if (analysis.isSpam) {
                m_stats.spamDetected.fetch_add(1, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::SPAM);
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::AnalyzeSpam: {}", e.what());
        }
    }

    void AnalyzeBEC(EmailAnalysis& analysis) {
        try {
            double score = 0.0;

            std::string lowerSubject = analysis.header.decodedSubject;
            std::transform(lowerSubject.begin(), lowerSubject.end(), lowerSubject.begin(), ::tolower);

            // Check for payment/financial keywords
            static const std::vector<std::string> becKeywords = {
                "wire transfer", "payment", "invoice", "urgent payment", "bank details",
                "account details", "transfer funds", "payroll", "ceo", "president",
                "executive", "confidential", "discreet", "wire immediately"
            };

            for (const auto& keyword : becKeywords) {
                if (lowerSubject.find(keyword) != std::string::npos) {
                    analysis.becIndicators.push_back(keyword);
                    score += 0.15;
                }
            }

            // Check for executive impersonation
            static const std::vector<std::string> execTitles = {
                "ceo", "cfo", "cto", "president", "vp", "vice president", "director", "executive"
            };

            std::string senderName = analysis.header.from.displayName;
            std::transform(senderName.begin(), senderName.end(), senderName.begin(), ::tolower);

            for (const auto& title : execTitles) {
                if (senderName.find(title) != std::string::npos) {
                    analysis.becIndicators.push_back("Executive title in sender");
                    score += 0.2;
                    break;
                }
            }

            // Check for domain spoofing
            if (analysis.phishingAnalysis.domainSpoofed) {
                analysis.becIndicators.push_back("Domain spoofing");
                score += 0.25;
            }

            // Internal direction with external sender
            if (analysis.direction == EmailDirection::INTERNAL &&
                !analysis.header.from.domain.empty()) {
                // Simplified check - would need organization domain list
                analysis.becIndicators.push_back("External sender, internal mail");
                score += 0.15;
            }

            analysis.becScore = std::min(score, 1.0);
            analysis.isBEC = (analysis.becScore >= m_config.becThreshold);

            if (analysis.isBEC) {
                m_stats.becDetected.fetch_add(1, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::BEC_IMPERSONATION);
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::AnalyzeBEC: {}", e.what());
        }
    }

    void AnalyzeDLP(EmailAnalysis& analysis) {
        try {
            std::string combinedContent = analysis.bodyText + " " + analysis.bodyHtml;

            for (const auto& pattern : g_dlpPatterns) {
                auto begin = std::sregex_iterator(combinedContent.begin(), combinedContent.end(), pattern.pattern);
                auto end = std::sregex_iterator();

                for (std::sregex_iterator i = begin; i != end; ++i) {
                    std::smatch match = *i;

                    DLPResult::Violation violation;
                    violation.dataType = pattern.dataType;
                    violation.match = match.str();
                    violation.location = "Body";
                    violation.severity = pattern.severity;

                    analysis.dlpResult.violations.push_back(violation);
                    analysis.dlpResult.violationCount++;

                    // Set flags
                    if (pattern.dataType == "Credit Card") {
                        analysis.dlpResult.hasCreditCard = true;
                        analysis.dlpResult.hasFinancialData = true;
                    } else if (pattern.dataType == "SSN") {
                        analysis.dlpResult.hasSSN = true;
                        analysis.dlpResult.hasPII = true;
                    }
                }
            }

            if (analysis.dlpResult.violationCount > 0) {
                analysis.dlpResult.hasViolation = true;
                m_stats.dlpViolations.fetch_add(analysis.dlpResult.violationCount, std::memory_order_relaxed);
                analysis.threats.push_back(ThreatType::DLP_VIOLATION);
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::AnalyzeDLP: {}", e.what());
        }
    }

    AuthenticationResults ParseAuthenticationResults(const EmailHeader& header) {
        AuthenticationResults results;

        try {
            // Parse Authentication-Results header
            const std::string& authHeader = header.authenticationResults;
            if (!authHeader.empty()) {
                std::string lower = authHeader;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                // SPF
                if (lower.find("spf=pass") != std::string::npos) {
                    results.spfPass = true;
                    results.spfResult = "pass";
                } else if (lower.find("spf=fail") != std::string::npos) {
                    results.spfResult = "fail";
                    results.failures.push_back("SPF");
                } else if (lower.find("spf=") != std::string::npos) {
                    results.spfResult = "softfail/neutral/none";
                }

                // DKIM
                if (lower.find("dkim=pass") != std::string::npos) {
                    results.dkimPass = true;
                    results.dkimResult = "pass";
                } else if (lower.find("dkim=fail") != std::string::npos) {
                    results.dkimResult = "fail";
                    results.failures.push_back("DKIM");
                }

                // DMARC
                if (lower.find("dmarc=pass") != std::string::npos) {
                    results.dmarcPass = true;
                    results.dmarcResult = "pass";
                } else if (lower.find("dmarc=fail") != std::string::npos) {
                    results.dmarcResult = "fail";
                    results.failures.push_back("DMARC");
                }
            }

            results.allPass = results.spfPass && results.dkimPass && results.dmarcPass;
            results.anyFail = !results.failures.empty();

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::ParseAuthenticationResults: {}", e.what());
        }

        return results;
    }

    EmailDirection DetermineDirection(const EmailHeader& header) {
        // Simplified - would need organization domain configuration
        // Check if sender and recipient are from same domain
        if (!header.from.domain.empty() && !header.to.empty()) {
            if (header.from.domain == header.to[0].domain) {
                return EmailDirection::INTERNAL;
            }
        }

        // Default to inbound for now
        return EmailDirection::INBOUND;
    }

    void CalculateThreatScore(EmailAnalysis& analysis) {
        uint32_t score = 0;

        // Malware attachments (+40)
        for (const auto& attachment : analysis.attachments) {
            if (attachment.riskLevel == AttachmentRisk::CRITICAL) {
                score += 40;
            } else if (attachment.riskLevel == AttachmentRisk::HIGH) {
                score += 25;
            } else if (attachment.riskLevel == AttachmentRisk::MEDIUM) {
                score += 10;
            }
        }

        // Phishing (+30)
        if (analysis.phishingAnalysis.isPhishing) {
            score += static_cast<uint32_t>(analysis.phishingAnalysis.confidence * 30);
        }

        // BEC (+25)
        if (analysis.isBEC) {
            score += static_cast<uint32_t>(analysis.becScore * 25);
        }

        // Spam (+15)
        if (analysis.isSpam) {
            score += static_cast<uint32_t>(analysis.spamScore * 15);
        }

        // DLP (+20)
        if (analysis.dlpResult.hasViolation) {
            score += std::min(analysis.dlpResult.violationCount * 5, 20u);
        }

        // Authentication failures (+10)
        if (analysis.authResults.anyFail) {
            score += static_cast<uint32_t>(analysis.authResults.failures.size() * 3);
        }

        analysis.threatScore = std::min(score, 100u);
    }

    void DetermineAction(EmailAnalysis& analysis) {
        // Determine result
        if (analysis.threatScore >= 70) {
            analysis.result = ScanResult::MALICIOUS;
        } else if (analysis.threatScore >= 40) {
            analysis.result = ScanResult::SUSPICIOUS;
        } else {
            analysis.result = ScanResult::CLEAN;
        }

        // Determine action based on threat types
        bool hasMalware = false;
        bool hasPhishing = false;
        bool hasSpam = false;

        for (const auto& threat : analysis.threats) {
            if (static_cast<int>(threat) >= 100 && static_cast<int>(threat) < 200) {
                hasMalware = true;
            } else if (static_cast<int>(threat) >= 200 && static_cast<int>(threat) < 300) {
                hasPhishing = true;
            } else if (static_cast<int>(threat) == 400) {
                hasSpam = true;
            }
        }

        // Apply configured actions
        if (hasMalware) {
            analysis.action = m_config.malwareAction;
            m_stats.malwareDetected.fetch_add(1, std::memory_order_relaxed);
        } else if (hasPhishing) {
            analysis.action = m_config.phishingAction;
        } else if (hasSpam) {
            analysis.action = m_config.spamAction;
        } else if (analysis.result == ScanResult::SUSPICIOUS) {
            analysis.action = EmailAction::TAG_SUSPICIOUS;
        } else {
            analysis.action = EmailAction::ALLOW;
        }

        // Update action statistics
        if (analysis.action == EmailAction::BLOCK) {
            m_stats.emailsBlocked.fetch_add(1, std::memory_order_relaxed);
        } else if (analysis.action == EmailAction::QUARANTINE) {
            m_stats.emailsQuarantined.fetch_add(1, std::memory_order_relaxed);
        } else if (analysis.action == EmailAction::STRIP_ATTACHMENTS) {
            m_stats.attachmentsStripped.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void CreateAlerts(const EmailAnalysis& analysis) {
        try {
            for (const auto& threat : analysis.threats) {
                EmailAlert alert;
                alert.alertId = m_nextAlertId.fetch_add(1, std::memory_order_relaxed);
                alert.analysisId = analysis.analysisId;
                alert.timestamp = std::chrono::system_clock::now();
                alert.threatType = threat;
                alert.messageId = analysis.messageId;
                alert.subject = analysis.header.decodedSubject;
                alert.sender = analysis.header.from.fullAddress;
                alert.direction = analysis.direction;
                alert.actionTaken = analysis.action;

                // Set severity
                if (static_cast<int>(threat) >= 100 && static_cast<int>(threat) < 200) {
                    alert.severity = 9;  // Malware
                    alert.threatDescription = "Malware detected in email";
                } else if (static_cast<int>(threat) >= 200 && static_cast<int>(threat) < 300) {
                    alert.severity = 8;  // Phishing
                    alert.threatDescription = "Phishing attempt detected";
                } else if (static_cast<int>(threat) >= 300 && static_cast<int>(threat) < 400) {
                    alert.severity = 7;  // BEC
                    alert.threatDescription = "Business Email Compromise detected";
                }

                // Add recipients
                for (const auto& to : analysis.header.to) {
                    alert.recipients.push_back(to.fullAddress);
                }

                // Invoke callback
                m_callbackManager->InvokeAlert(alert);
            }

        } catch (const std::exception& e) {
            Logger::Error("EmailScanner::CreateAlerts: {}", e.what());
        }
    }

    void UpdateScanTimeStats(uint64_t timeUs) {
        const uint64_t currentAvg = m_stats.avgScanTimeUs.load(std::memory_order_relaxed);
        const uint64_t newAvg = (currentAvg + timeUs) / 2;
        m_stats.avgScanTimeUs.store(newAvg, std::memory_order_relaxed);

        const uint64_t currentMax = m_stats.maxScanTimeUs.load(std::memory_order_relaxed);
        if (timeUs > currentMax) {
            m_stats.maxScanTimeUs.store(timeUs, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_sessionMutex;
    mutable std::shared_mutex m_whitelistMutex;

    bool m_initialized{ false };
    std::atomic<bool> m_running{ false };
    EmailScannerConfig m_config;

    // Threading
    std::vector<std::thread> m_workers;
    std::condition_variable m_cv;

    // Sessions
    std::unordered_map<uint64_t, EmailSession> m_sessions;
    std::unordered_map<std::string, uint64_t> m_sessionMap;  // key -> sessionId
    std::atomic<uint64_t> m_nextSessionId{ 1 };

    // Analysis
    std::atomic<uint64_t> m_nextAnalysisId{ 1 };
    std::atomic<uint64_t> m_nextAttachmentId{ 1 };
    std::atomic<uint64_t> m_nextAlertId{ 1 };

    // Whitelist
    std::unordered_set<std::string> m_whitelist;

    // Callbacks
    std::unique_ptr<CallbackManager> m_callbackManager;

    // Statistics
    EmailScannerStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

EmailScanner::EmailScanner()
    : m_impl(std::make_unique<EmailScannerImpl>()) {
}

EmailScanner::~EmailScanner() = default;

EmailScanner& EmailScanner::Instance() {
    static EmailScanner instance;
    return instance;
}

bool EmailScanner::Initialize(const EmailScannerConfig& config) {
    return m_impl->Initialize(config);
}

bool EmailScanner::Start() {
    return m_impl->Start();
}

void EmailScanner::Stop() {
    m_impl->Stop();
}

void EmailScanner::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool EmailScanner::IsRunning() const noexcept {
    return m_impl->IsRunning();
}

void EmailScanner::FeedPacket(const std::vector<uint8_t>& data) {
    m_impl->FeedPacket(std::span<const uint8_t>(data.data(), data.size()),
                      "", 0, "", 0);
}

void EmailScanner::FeedPacket(std::span<const uint8_t> data,
                             const std::string& srcIP, uint16_t srcPort,
                             const std::string& dstIP, uint16_t dstPort) {
    m_impl->FeedPacket(data, srcIP, srcPort, dstIP, dstPort);
}

EmailAnalysis EmailScanner::ScanEmail(const std::vector<uint8_t>& emailData) {
    return m_impl->ScanEmail(std::span<const uint8_t>(emailData.data(), emailData.size()));
}

EmailAnalysis EmailScanner::ScanEmailFile(const std::wstring& emlPath) {
    return m_impl->ScanEmailFile(emlPath);
}

EmailHeader EmailScanner::ParseHeaders(std::span<const uint8_t> headerData) {
    return m_impl->ParseHeaders(headerData);
}

AttachmentInfo EmailScanner::ScanAttachment(std::span<const uint8_t> data,
                                           const std::string& filename,
                                           const std::string& contentType) {
    return m_impl->ScanAttachment(data, filename, contentType);
}

std::vector<AttachmentInfo> EmailScanner::ScanArchive(std::span<const uint8_t> archiveData,
                                                      const std::string& filename) {
    return m_impl->ScanArchive(archiveData, filename);
}

std::vector<URLInfo> EmailScanner::AnalyzeURLs(const std::string& content) {
    return m_impl->AnalyzeURLs(content);
}

PhishingAnalysis EmailScanner::AnalyzePhishing(const EmailAnalysis& analysis) {
    return m_impl->AnalyzePhishing(analysis);
}

std::vector<EmailSession> EmailScanner::GetActiveSessions() const {
    return m_impl->GetActiveSessions();
}

std::optional<EmailSession> EmailScanner::GetSession(uint64_t sessionId) const {
    return m_impl->GetSession(sessionId);
}

void EmailScanner::TerminateSession(uint64_t sessionId) {
    m_impl->TerminateSession(sessionId);
}

bool EmailScanner::AddToWhitelist(const std::string& sender) {
    return m_impl->AddToWhitelist(sender);
}

bool EmailScanner::RemoveFromWhitelist(const std::string& sender) {
    return m_impl->RemoveFromWhitelist(sender);
}

bool EmailScanner::IsWhitelisted(const std::string& sender) const {
    return m_impl->IsWhitelisted(sender);
}

uint64_t EmailScanner::RegisterAnalysisCallback(EmailAnalysisCallback callback) {
    return m_impl->RegisterAnalysisCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterAlertCallback(EmailAlertCallback callback) {
    return m_impl->RegisterAlertCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterAttachmentCallback(AttachmentCallback callback) {
    return m_impl->RegisterAttachmentCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterPhishingCallback(PhishingCallback callback) {
    return m_impl->RegisterPhishingCallback(std::move(callback));
}

uint64_t EmailScanner::RegisterMalwareCallback(MalwareCallback callback) {
    return m_impl->RegisterMalwareCallback(std::move(callback));
}

bool EmailScanner::UnregisterCallback(uint64_t callbackId) {
    return m_impl->UnregisterCallback(callbackId);
}

const EmailScannerStatistics& EmailScanner::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void EmailScanner::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

bool EmailScanner::PerformDiagnostics() const {
    return m_impl->PerformDiagnostics();
}

bool EmailScanner::ExportDiagnostics(const std::wstring& outputPath) const {
    return m_impl->ExportDiagnostics(outputPath);
}

}  // namespace Network
}  // namespace Core
}  // namespace ShadowStrike
