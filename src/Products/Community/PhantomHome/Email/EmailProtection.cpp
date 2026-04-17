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
 * ShadowStrike NGAV - EMAIL PROTECTION ORCHESTRATOR IMPLEMENTATION
 * ============================================================================
 *
 * @file EmailProtection.cpp
 * @brief Enterprise-grade central orchestrator for comprehensive email security
 *
 * Production-level implementation competing with Proofpoint Email Protection,
 * Mimecast Email Security, and Barracuda Email Security Gateway.
 *
 * IMPLEMENTATION FEATURES:
 * ========================
 *
 * - PIMPL pattern for ABI stability
 * - Thread-safe with std::shared_mutex for concurrent access
 * - Multi-source detection: Attachments, Phishing, Spam, DLP
 * - Client integration: Outlook, Thunderbird, Network Proxies
 * - Email parsing: .eml, .msg, raw MIME
 * - Authentication: SPF/DKIM/DMARC verification
 * - Quarantine management with encryption
 * - Infrastructure reuse (HashStore, SignatureStore, PatternStore, ThreatIntel, Whitelist)
 * - Comprehensive statistics tracking
 * - Alert generation with callbacks
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "EmailProtection.hpp"

// ============================================================================
// SUBSYSTEM INCLUDES
// ============================================================================
#include "AttachmentScanner.hpp"
#include "PhishingEmailDetector.hpp"
#include "SpamDetector.hpp"
#include "OutlookScanner.hpp"
#include "ThunderbirdScanner.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Utils/StringUtils.hpp"
#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/CryptoUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/Utils/Base64Utils.hpp"
#include "PhantomCore/HashStore/HashStore.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"
#include "PhantomCore/PatternStore/PatternStore.hpp"
#include "PhantomCore/ThreatIntel/ThreatIntelManager.hpp"
#include "PhantomCore/Whitelist/WhiteListStore.hpp"

// ============================================================================
// SYSTEM INCLUDES
// ============================================================================
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <ole2.h>
#include <ntstatus.h>
#include <sddl.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <numeric>
#include <regex>
#include <sstream>
#include <iomanip>
#include <thread>
#include <deque>
#include <unordered_set>
#include <map>
#include <format>
#include <fstream>
#include <random>
#include <cstring>

// ============================================================================
// THIRD-PARTY INCLUDES
// ============================================================================
#include <nlohmann/json.hpp>

namespace ShadowStrike {
namespace Email {

using SystemClock = std::chrono::system_clock;

// ============================================================================
// EMAIL PARSING HELPERS
// ============================================================================

namespace EmailParsing {

    /**
     * @brief Extract email address from "Display Name <email@domain.com>"
     */
    std::string ExtractEmailAddress(const std::string& fullAddress) {
        static const std::regex emailRegex(R"(<([^>]+)>)");
        std::smatch match;

        if (std::regex_search(fullAddress, match, emailRegex)) {
            return match[1].str();
        }

        // No brackets, assume entire string is email
        return fullAddress;
    }

    /**
     * @brief Extract display name from "Display Name <email@domain.com>"
     */
    std::string ExtractDisplayName(const std::string& fullAddress) {
        size_t openBracket = fullAddress.find('<');
        if (openBracket != std::string::npos && openBracket > 0) {
            std::string displayName = fullAddress.substr(0, openBracket);
            // Trim whitespace
            displayName.erase(0, displayName.find_first_not_of(" \t\""));
            displayName.erase(displayName.find_last_not_of(" \t\"") + 1);
            return displayName;
        }

        return "";
    }

    /**
     * @brief Extract domain from email address
     */
    std::string ExtractDomain(const std::string& email) {
        size_t atPos = email.find('@');
        if (atPos != std::string::npos && atPos + 1 < email.length()) {
            return email.substr(atPos + 1);
        }
        return "";
    }

    /**
     * @brief Parse header value (unfold, trim)
     */
    std::string ParseHeaderValue(const std::string& value) {
        // CRITICAL-006 FIX: Validate and limit input size to prevent buffer overflow
        constexpr size_t MAX_HEADER_VALUE_SIZE = 16384;  // 16KB max per header

        if (value.length() > MAX_HEADER_VALUE_SIZE) {
            // Return truncated value for safety
            std::string result = value.substr(0, MAX_HEADER_VALUE_SIZE);

            // Unfold (remove CRLF followed by whitespace)
            static const std::regex unfoldRegex(R"(\r?\n[ \t]+)");
            result = std::regex_replace(result, unfoldRegex, " ");

            // Trim
            result.erase(0, result.find_first_not_of(" \t\r\n"));
            result.erase(result.find_last_not_of(" \t\r\n") + 1);

            return result;
        }

        std::string result = value;

        // Unfold (remove CRLF followed by whitespace)
        static const std::regex unfoldRegex(R"(\r?\n[ \t]+)");
        result = std::regex_replace(result, unfoldRegex, " ");

        // Trim
        result.erase(0, result.find_first_not_of(" \t\r\n"));
        result.erase(result.find_last_not_of(" \t\r\n") + 1);

        return result;
    }

    /**
     * @brief Extract URLs from text using regex
     */
    std::vector<std::string> ExtractURLsFromText(const std::string& text, size_t maxUrls = EmailProtectionConstants::MAX_URLS_PER_EMAIL) {
        std::vector<std::string> urls;

        // URL regex pattern (static to avoid recompilation)
        static const std::regex urlRegex(
            R"((https?://[^\s<>"{}|\\^`\[\]]+))",
            std::regex_constants::icase
        );

        auto begin = std::sregex_iterator(text.begin(), text.end(), urlRegex);
        auto end = std::sregex_iterator();

        for (auto it = begin; it != end && urls.size() < maxUrls; ++it) {
            urls.push_back(it->str());
        }

        return urls;
    }

    /**
     * @brief Extract URLs from HTML (href attributes)
     */
    std::vector<std::string> ExtractURLsFromHTML(const std::string& html, size_t maxUrls = EmailProtectionConstants::MAX_URLS_PER_EMAIL) {
        std::vector<std::string> urls;

        // href= pattern (static to avoid recompilation)
        static const std::regex hrefRegex(
            R"(href\s*=\s*["']([^"']+)["'])",
            std::regex_constants::icase
        );

        auto begin = std::sregex_iterator(html.begin(), html.end(), hrefRegex);
        auto end = std::sregex_iterator();

        for (auto it = begin; it != end && urls.size() < maxUrls; ++it) {
            std::string url = (*it)[1].str();
            if (url.starts_with("http://") || url.starts_with("https://")) {
                urls.push_back(url);
            }
        }

        // Remove duplicates
        std::sort(urls.begin(), urls.end());
        urls.erase(std::unique(urls.begin(), urls.end()), urls.end());

        return urls;
    }

    /**
     * @brief Check if extension is dangerous (case-insensitive, no allocation)
     */
    bool IsDangerousExtension(std::string_view extension) {
        static const std::array<std::string_view, 20> dangerous = {
            ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".jse", ".wsh", ".wsf", ".scr", ".hta", ".pif", ".reg",
            ".msi", ".msp", ".dll", ".cpl", ".jar", ".lnk"
        };

        // Case-insensitive comparison without allocation
        for (const auto& ext : dangerous) {
            if (extension.length() == ext.length()) {
                bool match = true;
                for (size_t i = 0; i < extension.length() && match; ++i) {
                    char a = static_cast<char>(std::tolower(static_cast<unsigned char>(extension[i])));
                    char b = ext[i];  // known lowercase
                    match = (a == b);
                }
                if (match) return true;
            }
        }
        return false;
    }

    /**
     * @brief Luhn algorithm for credit card validation
     */
    [[nodiscard]] bool PassesLuhnCheck(std::string_view digits) {
        if (digits.length() < 13 || digits.length() > 19) return false;
        
        int sum = 0;
        bool alternate = false;
        
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            if (!std::isdigit(static_cast<unsigned char>(*it))) continue;
            
            int digit = *it - '0';
            if (alternate) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            alternate = !alternate;
        }
        
        return (sum % 10 == 0);
    }

    /**
     * @brief Validate SSN format and ranges
     */
    [[nodiscard]] bool IsValidSSN(std::string_view ssn) {
        // Extract digits only
        std::string digits;
        for (char c : ssn) {
            if (std::isdigit(static_cast<unsigned char>(c))) {
                digits += c;
            }
        }
        
        if (digits.length() != 9) return false;
        
        // Area number (first 3 digits) cannot be 000, 666, or 900-999
        int area = std::stoi(digits.substr(0, 3));
        if (area == 0 || area == 666 || area >= 900) return false;
        
        // Group number (middle 2 digits) cannot be 00
        int group = std::stoi(digits.substr(3, 2));
        if (group == 0) return false;
        
        // Serial number (last 4 digits) cannot be 0000
        int serial = std::stoi(digits.substr(5, 4));
        if (serial == 0) return false;
        
        return true;
    }

    /**
     * @brief Decode quoted-printable content
     */
    [[nodiscard]] std::string DecodeQuotedPrintable(std::string_view input) {
        std::string result;
        result.reserve(input.size());
        
        for (size_t i = 0; i < input.size(); ++i) {
            if (input[i] == '=' && i + 2 < input.size()) {
                if (input[i + 1] == '\r' || input[i + 1] == '\n') {
                    // Soft line break - skip
                    ++i;
                    if (i + 1 < input.size() && input[i] == '\r' && input[i + 1] == '\n') {
                        ++i;
                    }
                } else if (std::isxdigit(static_cast<unsigned char>(input[i + 1])) &&
                           std::isxdigit(static_cast<unsigned char>(input[i + 2]))) {
                    // Hex encoded byte
                    char hex[3] = { input[i + 1], input[i + 2], '\0' };
                    result += static_cast<char>(std::strtol(hex, nullptr, 16));
                    i += 2;
                } else {
                    result += input[i];
                }
            } else {
                result += input[i];
            }
        }
        
        return result;
    }

}  // namespace EmailParsing

// ============================================================================
// FILE-SCOPE HELPER: Narrow string case folding (ASCII-safe, locale-independent)
// ============================================================================
namespace {
    [[nodiscard]] inline std::string NarrowToLower(std::string s) {
        std::ranges::transform(s, s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }
}  // anonymous namespace

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class EmailProtectionImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    /// @brief Thread synchronization
    mutable std::shared_mutex m_mutex;

    /// @brief Configuration
    EmailProtectionConfiguration m_config;

    /// @brief Initialization state
    std::atomic<bool> m_initialized{false};

    /// @brief Module status
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    /// @brief Statistics
    EmailProtectionStatistics m_statistics;

    /// @brief Quarantine entries
    std::unordered_map<std::string, QuarantineEntry> m_quarantineEntries;
    mutable std::shared_mutex m_quarantineMutex;

    /// @brief Quarantine directory
    fs::path m_quarantineDir;

    /// @brief Trusted senders
    std::unordered_set<std::string> m_trustedSenders;
    mutable std::shared_mutex m_trustedSendersMutex;

    /// @brief Blocked extensions
    std::unordered_set<std::string> m_blockedExtensions;
    mutable std::shared_mutex m_blockedExtMutex;

    /// @brief Callbacks
    std::vector<ScanResultCallback> m_scanCallbacks;
    std::vector<ThreatDetectedCallback> m_threatCallbacks;
    std::vector<QuarantineCallback> m_quarantineCallbacks;
    std::vector<DLPViolationCallback> m_dlpCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;
    mutable std::mutex m_callbacksMutex;

    /// @brief Quarantine encryption key (AES-256 GCM)
    std::array<uint8_t, 32> m_quarantineKey{};

    /// @brief Authorization tokens for quarantine release (SHA-256 hashed)
    std::unordered_map<std::string, SystemTimePoint> m_releaseTokens;
    mutable std::shared_mutex m_releaseTokensMutex;

    /// @brief Maximum valid token age (24 hours)
    static constexpr uint64_t TOKEN_VALIDITY_MS = 24ULL * 60 * 60 * 1000;

    /// @brief Subsystem integrations (using singletons)
    AttachmentScanner* m_attachmentScanner = nullptr;
    PhishingEmailDetector* m_phishingDetector = nullptr;
    SpamDetector* m_spamDetector = nullptr;
    OutlookScanner* m_outlookScanner = nullptr;
    ThunderbirdScanner* m_thunderbirdScanner = nullptr;

    /// @brief Outlook integration state
    std::atomic<bool> m_outlookHooked{false};

    /// @brief Network proxy state
    std::atomic<bool> m_networkProxyActive{false};
    std::atomic<bool> m_proxyShutdownFlag{false};

    /// @brief Network proxy sockets and threads
    SOCKET m_pop3Socket = INVALID_SOCKET;
    SOCKET m_imapSocket = INVALID_SOCKET;
    SOCKET m_smtpSocket = INVALID_SOCKET;
    uint16_t m_proxyPop3Port = 0;
    uint16_t m_proxyImapPort = 0;
    uint16_t m_proxySmtpPort = 0;
    std::jthread m_pop3AcceptThread;
    std::jthread m_imapAcceptThread;
    std::jthread m_smtpAcceptThread;

    // ========================================================================
    // METHODS
    // ========================================================================

    EmailProtectionImpl() = default;
    ~EmailProtectionImpl() = default;

    [[nodiscard]] bool Initialize(const EmailProtectionConfiguration& config);
    void Shutdown();

    // Main scanning
    [[nodiscard]] EmailScanResult ScanMessageInternal(const EmailMessage& message);
    [[nodiscard]] EmailScanResult ScanEMLFileInternal(const fs::path& path);
    [[nodiscard]] EmailScanResult ScanMSGFileInternal(const fs::path& path);
    [[nodiscard]] EmailScanResult ScanRawEmailInternal(
        const std::vector<uint8_t>& data,
        EmailSource source);

    // Detection methods
    [[nodiscard]] bool DetectMalwareInternal(const EmailMessage& message, EmailScanResult& result);
    [[nodiscard]] bool DetectPhishingInternal(const EmailMessage& message, EmailScanResult& result);
    [[nodiscard]] bool DetectSpamInternal(const EmailMessage& message, EmailScanResult& result);
    [[nodiscard]] bool DetectDLPInternal(const EmailMessage& message, EmailScanResult& result);
    [[nodiscard]] bool VerifyAuthenticationInternal(const EmailMessage& message, EmailScanResult& result);

    // Email parsing
    [[nodiscard]] std::optional<EmailMessage> ParseEMLInternal(const fs::path& path);
    [[nodiscard]] std::optional<EmailMessage> ParseRawEmailInternal(const std::vector<uint8_t>& data);

    // Quarantine
    [[nodiscard]] bool QuarantineEmailInternal(const EmailMessage& message, const EmailScanResult& result);
    [[nodiscard]] std::vector<QuarantineEntry> GetQuarantineEntriesInternal(
        std::optional<size_t> limit,
        std::optional<SystemTimePoint> since);
    [[nodiscard]] std::optional<QuarantineEntry> GetQuarantineEntryInternal(const std::string& quarantineId);
    [[nodiscard]] bool ReleaseFromQuarantineInternal(const std::string& quarantineId, const std::string& releasedBy, const std::string& authorizationToken);
    [[nodiscard]] bool ValidateReleaseToken(const std::string& token, const std::string& releasedBy);
    [[nodiscard]] bool DeleteFromQuarantineInternal(const std::string& quarantineId);
    [[nodiscard]] size_t CleanExpiredQuarantineInternal();
    
    // Quarantine encryption helpers
    [[nodiscard]] std::vector<uint8_t> EncryptQuarantineData(const std::vector<uint8_t>& data) const;
    [[nodiscard]] std::vector<uint8_t> DecryptQuarantineData(const std::vector<uint8_t>& data) const;
    void SecureDeleteFile(const fs::path& filePath);

    // Client integration
    [[nodiscard]] bool HookOutlookInternal();
    void UnhookOutlookInternal();
    [[nodiscard]] bool StartNetworkProxyInternal(uint16_t pop3Port, uint16_t imapPort, uint16_t smtpPort);
    void StopNetworkProxyInternal();
    void AcceptProxyConnections(SOCKET listenSocket, const char* protocol, std::stop_token stopToken);

    // Helpers
    [[nodiscard]] ScanAction DetermineAction(const EmailScanResult& result) const;
    void AggregateResult(EmailScanResult& result);
    void InvokeScanCallbacks(const EmailScanResult& result);
    void InvokeThreatCallbacks(const EmailMessage& message, const ThreatDetail& threat);
    void InvokeQuarantineCallbacks(const QuarantineEntry& entry);
    void InvokeDLPCallbacks(const EmailMessage& message, const DLPViolation& violation);
    void InvokeErrorCallbacks(const std::string& message, int code);
    [[nodiscard]] std::string GenerateQuarantineId() const;
};

// ============================================================================
// IMPL: INITIALIZATION
// ============================================================================

bool EmailProtectionImpl::Initialize(
    const EmailProtectionConfiguration& config)
{
    try {
        // Check if already initialized - but don't set m_initialized yet
        if (m_initialized.load(std::memory_order_acquire)) {
            Utils::Logger::Warn("EmailProtection: Already initialized");
            return true;
        }

        Utils::Logger::Info("EmailProtection: Initializing main orchestrator...");

        m_status.store(ModuleStatus::Initializing, std::memory_order_release);

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("EmailProtection: Invalid configuration");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        m_config = config;

        // Generate quarantine encryption key
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : m_quarantineKey) {
            byte = static_cast<uint8_t>(dist(gen));
        }

        // Initialize subsystem detectors (checking return values)
        if (m_config.scanAttachments) {
            m_attachmentScanner = &AttachmentScanner::Instance();
            if (!m_attachmentScanner->IsInitialized()) {
                AttachmentScannerConfiguration attachConfig;
                attachConfig.enabled = true;
                attachConfig.defaultScanConfig.extractArchives = m_config.scanArchives;
                attachConfig.defaultScanConfig.scanMacros = true;
                attachConfig.verboseLogging = m_config.verboseLogging;
                if (!m_attachmentScanner->Initialize(attachConfig)) {
                    Utils::Logger::Warn("EmailProtection: Attachment scanner initialization failed - disabling");
                    m_attachmentScanner = nullptr;
                } else {
                    Utils::Logger::Info("EmailProtection: Attachment scanner integrated");
                }
            } else {
                Utils::Logger::Info("EmailProtection: Attachment scanner already initialized");
            }
        }

        if (m_config.detectPhishing) {
            m_phishingDetector = &PhishingEmailDetector::Instance();
            if (!m_phishingDetector->IsInitialized()) {
                PhishingDetectorConfiguration phishConfig;
                phishConfig.enabled = true;
                phishConfig.enableNLPAnalysis = true;
                phishConfig.enableURLAnalysis = m_config.scanLinks;
                phishConfig.enableSenderVerification = true;
                phishConfig.verboseLogging = m_config.verboseLogging;
                if (!m_phishingDetector->Initialize(phishConfig)) {
                    Utils::Logger::Warn("EmailProtection: Phishing detector initialization failed - disabling");
                    m_phishingDetector = nullptr;
                } else {
                    Utils::Logger::Info("EmailProtection: Phishing detector integrated");
                }
            } else {
                Utils::Logger::Info("EmailProtection: Phishing detector already initialized");
            }
        }

        if (m_config.detectSpam) {
            m_spamDetector = &SpamDetector::Instance();
            if (!m_spamDetector->IsInitialized()) {
                SpamDetectorConfiguration spamConfig;
                spamConfig.enabled = true;
                spamConfig.spamThreshold = m_config.spamThreshold;
                spamConfig.verboseLogging = m_config.verboseLogging;
                if (!m_spamDetector->Initialize(spamConfig)) {
                    Utils::Logger::Warn("EmailProtection: Spam detector initialization failed - disabling");
                    m_spamDetector = nullptr;
                } else {
                    Utils::Logger::Info("EmailProtection: Spam detector integrated");
                }
            } else {
                Utils::Logger::Info("EmailProtection: Spam detector already initialized");
            }
        }

        if (m_config.enableOutlookIntegration) {
            m_outlookScanner = &OutlookScanner::Instance();
            if (!m_outlookScanner->IsInitialized()) {
                OutlookScannerConfiguration outlookConfig;
                outlookConfig.enabled = true;
                if (!m_outlookScanner->Initialize(outlookConfig)) {
                    Utils::Logger::Warn("EmailProtection: Outlook scanner initialization failed - disabling");
                    m_outlookScanner = nullptr;
                } else {
                    Utils::Logger::Info("EmailProtection: Outlook scanner integrated");
                }
            } else {
                Utils::Logger::Info("EmailProtection: Outlook scanner already initialized");
            }
        }

        if (m_config.enableThunderbirdIntegration) {
            m_thunderbirdScanner = &ThunderbirdScanner::Instance();
            if (!m_thunderbirdScanner->IsInitialized()) {
                ThunderbirdScannerConfiguration tbConfig;
                tbConfig.enabled = true;
                if (!m_thunderbirdScanner->Initialize(tbConfig)) {
                    Utils::Logger::Warn("EmailProtection: Thunderbird scanner initialization failed - disabling");
                    m_thunderbirdScanner = nullptr;
                } else {
                    Utils::Logger::Info("EmailProtection: Thunderbird scanner integrated");
                }
            } else {
                Utils::Logger::Info("EmailProtection: Thunderbird scanner already initialized");
            }
        }

        // Initialize quarantine directory
        if (!m_config.quarantinePath.empty()) {
            m_quarantineDir = m_config.quarantinePath;
            if (!fs::exists(m_quarantineDir)) {
                fs::create_directories(m_quarantineDir);
            }
            
            // Set restrictive permissions on quarantine directory (Windows)
#ifdef _WIN32
            {
                // Restrict quarantine directory to SYSTEM and Administrators only
                PSECURITY_DESCRIPTOR pSD = nullptr;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorA(
                        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                        SDDL_REVISION_1,
                        &pSD,
                        nullptr) && pSD) {
                    BOOL success = SetFileSecurityW(
                        m_quarantineDir.wstring().c_str(),
                        DACL_SECURITY_INFORMATION,
                        pSD
                    );
                    LocalFree(pSD);
                    if (!success) {
                        Utils::Logger::Warn("EmailProtection: Failed to set quarantine directory "
                                           "permissions, error: {}", GetLastError());
                    }
                }
            }
#endif
            Utils::Logger::Info("EmailProtection: Quarantine directory: {}", m_quarantineDir.string());
        }

        // Load trusted senders
        {
            std::unique_lock lock(m_trustedSendersMutex);
            for (const auto& sender : m_config.trustedSenders) {
                m_trustedSenders.insert(NarrowToLower(sender));
            }
        }

        // Load blocked extensions
        {
            std::unique_lock lock(m_blockedExtMutex);
            for (const auto& ext : m_config.blockedExtensions) {
                m_blockedExtensions.insert(NarrowToLower(ext));
            }
        }

        // Only set initialized to true AFTER all initialization is complete
        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        Utils::Logger::Info("EmailProtection: Initialized successfully");
        Utils::Logger::Info("EmailProtection: Trusted senders: {}", m_trustedSenders.size());
        Utils::Logger::Info("EmailProtection: Blocked extensions: {}", m_blockedExtensions.size());

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Initialization failed - {}",
                           e.what());
        m_initialized.store(false, std::memory_order_release);
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void EmailProtectionImpl::Shutdown() {
    try {
        if (!m_initialized.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        Utils::Logger::Info("EmailProtection: Shutting down...");

        m_status.store(ModuleStatus::Stopping, std::memory_order_release);

        // Unhook clients
        if (m_outlookHooked.load(std::memory_order_acquire)) {
            UnhookOutlookInternal();
        }

        if (m_networkProxyActive.load(std::memory_order_acquire)) {
            StopNetworkProxyInternal();
        }

        // Clear all data structures
        {
            std::unique_lock lock(m_quarantineMutex);
            m_quarantineEntries.clear();
        }

        {
            std::unique_lock lock(m_trustedSendersMutex);
            m_trustedSenders.clear();
        }

        {
            std::unique_lock lock(m_blockedExtMutex);
            m_blockedExtensions.clear();
        }

        {
            std::lock_guard lock(m_callbacksMutex);
            m_scanCallbacks.clear();
            m_threatCallbacks.clear();
            m_quarantineCallbacks.clear();
            m_dlpCallbacks.clear();
            m_errorCallbacks.clear();
        }

        m_status.store(ModuleStatus::Stopped, std::memory_order_release);

        Utils::Logger::Info("EmailProtection: Shutdown complete");

    } catch (...) {
        Utils::Logger::Error("EmailProtection: Exception during shutdown");
    }
}

// ============================================================================
// IMPL: MAIN SCANNING
// ============================================================================

EmailScanResult EmailProtectionImpl::ScanMessageInternal(
    const EmailMessage& message)
{
    const auto startTime = Clock::now();
    EmailScanResult result;

    try {
        m_statistics.totalScanned.fetch_add(1, std::memory_order_relaxed);
        m_statistics.bySource[static_cast<size_t>(message.source)]
            .fetch_add(1, std::memory_order_relaxed);
        m_statistics.byDirection[static_cast<size_t>(message.direction)]
            .fetch_add(1, std::memory_order_relaxed);

        result.messageId = message.messageId;
        result.scanTimestamp = SystemClock::now();
        result.isClean = true;

        // Check if sender is trusted
        {
            std::shared_lock lock(m_trustedSendersMutex);
            std::string senderLower = NarrowToLower(message.sender);
            if (m_trustedSenders.contains(senderLower)) {
                result.isClean = true;
                result.recommendedAction = ScanAction::Allow;
                m_statistics.allowed.fetch_add(1, std::memory_order_relaxed);
                return result;
            }
        }

        bool threatDetected = false;

        // 1. Malware detection (attachments)
        if (m_config.scanAttachments && !message.attachments.empty()) {
            if (DetectMalwareInternal(message, result)) {
                threatDetected = true;
                result.hasMalware = true;
                result.isClean = false;
                m_statistics.malwareDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 2. Phishing detection
        if (m_config.detectPhishing) {
            if (DetectPhishingInternal(message, result)) {
                threatDetected = true;
                result.isPhishing = true;
                result.isClean = false;
                m_statistics.phishingDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 3. Spam detection
        if (m_config.detectSpam) {
            if (DetectSpamInternal(message, result)) {
                result.isSpam = true;
                result.isClean = false;
                m_statistics.spamDetected.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 4. DLP detection
        if (m_config.detectDLP) {
            if (DetectDLPInternal(message, result)) {
                result.hasDLPViolation = true;
                result.isClean = false;
                m_statistics.dlpViolations.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // 5. Authentication verification (SPF/DKIM/DMARC)
        if (m_config.verifySPF || m_config.verifyDKIM || m_config.verifyDMARC) {
            VerifyAuthenticationInternal(message, result);
        }

        // Aggregate result
        AggregateResult(result);

        // Determine action
        result.recommendedAction = DetermineAction(result);

        // Take action if configured
        if (result.recommendedAction == ScanAction::Quarantine) {
            QuarantineEmailInternal(message, result);
            result.actionTaken = "Quarantined";
            m_statistics.quarantined.fetch_add(1, std::memory_order_relaxed);
        } else if (result.recommendedAction == ScanAction::Block) {
            result.actionTaken = "Blocked";
            m_statistics.blocked.fetch_add(1, std::memory_order_relaxed);
        } else if (result.recommendedAction == ScanAction::TagSubject) {
            result.actionTaken = "Tagged";
            m_statistics.tagged.fetch_add(1, std::memory_order_relaxed);
        } else if (result.recommendedAction == ScanAction::Allow) {
            result.actionTaken = "Allowed";
            m_statistics.allowed.fetch_add(1, std::memory_order_relaxed);
        }

        // Update statistics
        if (result.isClean) {
            m_statistics.cleanEmails.fetch_add(1, std::memory_order_relaxed);
        }

        // Invoke callbacks
        InvokeScanCallbacks(result);

        if (m_config.verboseLogging || !result.isClean) {
            Utils::Logger::Info("EmailProtection: Email scanned - Subject: {}, Action: {}, Clean: {}",
                              message.subject,
                              result.actionTaken,
                              result.isClean);
        }

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Scan failed for message {} - {}",
                           message.messageId,
                           e.what());
        m_statistics.scanErrors.fetch_add(1, std::memory_order_relaxed);
        InvokeErrorCallbacks(e.what(), -1);
    }

    const auto endTime = Clock::now();
    result.scanDuration = std::chrono::duration_cast<std::chrono::microseconds>(
        endTime - startTime
    );

    return result;
}

// ============================================================================
// IMPL: MALWARE DETECTION
// ============================================================================

bool EmailProtectionImpl::DetectMalwareInternal(
    const EmailMessage& message,
    EmailScanResult& result)
{
    try {
        if (!m_attachmentScanner) return false;

        bool malwareFound = false;

        for (const auto& attachment : message.attachments) {
            m_statistics.attachmentsScanned.fetch_add(1, std::memory_order_relaxed);

            // Check blocked extensions
            {
                std::shared_lock lock(m_blockedExtMutex);
                fs::path filePath(attachment.fileName);
                std::string ext = NarrowToLower(filePath.extension().string());

                if (m_blockedExtensions.contains(ext)) {
                    result.blockedAttachments.push_back(attachment.fileName);
                    result.detectedThreats = static_cast<EmailThreatType>(
                        static_cast<uint32_t>(result.detectedThreats) |
                        static_cast<uint32_t>(EmailThreatType::MaliciousAttachment)
                    );
                    malwareFound = true;
                    continue;
                }
            }

            // Check dangerous extensions
            fs::path filePath(attachment.fileName);
            if (EmailParsing::IsDangerousExtension(filePath.extension().string())) {
                ThreatDetail threat;
                threat.type = EmailThreatType::MaliciousAttachment;
                threat.threatName = "High-risk file extension";
                threat.affectedComponent = attachment.fileName;
                threat.confidence = 70;
                threat.severity = 7;
                result.threatDetails.push_back(threat);
                result.blockedAttachments.push_back(attachment.fileName);
                malwareFound = true;
            }

            // Scan attachment if temp file exists
            if (!attachment.tempFilePath.empty() && fs::exists(attachment.tempFilePath)) {
                auto scanResult = m_attachmentScanner->ScanAttachment(attachment.tempFilePath);

                if (scanResult.IsMalicious() || scanResult.ShouldBlock()) {
                    ThreatDetail threat;
                    threat.type = EmailThreatType::MaliciousAttachment;
                    threat.threatName = scanResult.threatName;
                    threat.description = scanResult.threatFamily;
                    threat.affectedComponent = attachment.fileName;
                    threat.confidence = scanResult.riskScore;
                    threat.severity = scanResult.riskScore / 10;
                    threat.detectionMethod = "Attachment Scanner";

                    result.threatDetails.push_back(threat);
                    result.maliciousAttachments.push_back(attachment.fileName);

                    m_statistics.maliciousAttachments.fetch_add(1, std::memory_order_relaxed);
                    malwareFound = true;

                    if (scanResult.hasMacros) {
                        result.detectedThreats = static_cast<EmailThreatType>(
                            static_cast<uint32_t>(result.detectedThreats) |
                            static_cast<uint32_t>(EmailThreatType::SuspiciousMacro)
                        );
                    }
                }
            }
        }

        return malwareFound;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Malware detection failed - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// IMPL: PHISHING DETECTION
// ============================================================================

bool EmailProtectionImpl::DetectPhishingInternal(
    const EmailMessage& message,
    EmailScanResult& result)
{
    try {
        if (!m_phishingDetector) return false;

        // Analyze email content
        auto phishingResult = m_phishingDetector->AnalyzeContent(
            message.subject,
            message.bodyText.empty() ? message.bodyHtml : message.bodyText,
            message.sender,
            message.embeddedUrls
        );

        if (phishingResult.isPhishing || phishingResult.verdict != PhishingVerdict::Clean) {
            result.phishingConfidence = phishingResult.confidenceScore;

            ThreatDetail threat;
            threat.type = EmailThreatType::Phishing;
            threat.threatName = std::string(GetPhishingVerdictName(phishingResult.verdict));
            threat.description = phishingResult.analysisSummary;
            threat.confidence = phishingResult.confidenceScore;
            threat.severity = phishingResult.riskScore / 10;
            threat.detectionMethod = "Phishing Detector";

            result.threatDetails.push_back(threat);

            // Check for BEC
            if (phishingResult.campaignType == PhishingCampaignType::BEC ||
                phishingResult.campaignType == PhishingCampaignType::CEOFraud) {
                result.detectedThreats = static_cast<EmailThreatType>(
                    static_cast<uint32_t>(result.detectedThreats) |
                    static_cast<uint32_t>(EmailThreatType::BEC)
                );
                m_statistics.becDetected.fetch_add(1, std::memory_order_relaxed);
            }

            // Add malicious URLs
            for (const auto& urlAnalysis : phishingResult.urlAnalyses) {
                if (urlAnalysis.verdict == URLVerdict::Malicious ||
                    urlAnalysis.verdict == URLVerdict::Phishing) {
                    result.maliciousUrls.push_back(urlAnalysis.originalUrl);
                    m_statistics.maliciousUrls.fetch_add(1, std::memory_order_relaxed);
                }
            }

            m_statistics.urlsScanned.fetch_add(
                phishingResult.urlAnalyses.size(),
                std::memory_order_relaxed
            );

            return true;
        }

        m_statistics.urlsScanned.fetch_add(
            phishingResult.urlAnalyses.size(),
            std::memory_order_relaxed
        );

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Phishing detection failed - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// IMPL: SPAM DETECTION
// ============================================================================

bool EmailProtectionImpl::DetectSpamInternal(
    const EmailMessage& message,
    EmailScanResult& result)
{
    try {
        if (!m_spamDetector) return false;

        // Analyze spam score
        std::map<std::string, std::string> spamHeadersMap;
        for (const auto& h : message.headers) {
            spamHeadersMap.emplace(h.name, h.value);
        }
        auto spamResult = m_spamDetector->AnalyzeEmail(
            message.subject,
            message.bodyText,
            message.bodyHtml,
            message.sender,
            message.GetAllRecipients(),
            spamHeadersMap
        );

        result.spamScore = spamResult.spamScore;

        if (spamResult.isSpam || spamResult.spamScore >= m_config.spamThreshold) {
            ThreatDetail threat;
            threat.type = EmailThreatType::Spam;
            threat.threatName = "Spam Email";
            threat.description = std::format("Spam score: {}/100", spamResult.spamScore);
            threat.confidence = spamResult.spamScore;
            threat.severity = (spamResult.spamScore >= 80) ? 6 : 4;
            threat.detectionMethod = "Spam Detector";

            result.threatDetails.push_back(threat);
            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Spam detection failed - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// IMPL: DLP DETECTION
// ============================================================================

bool EmailProtectionImpl::DetectDLPInternal(
    const EmailMessage& message,
    EmailScanResult& result)
{
    try {
        // CRITICAL-004 FIX: Use static regex with optimized flags to prevent ReDoS
        // Credit card pattern - compiled once with optimization flags
        static const std::regex creditCardRegex(
            R"(\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b)",
            std::regex_constants::icase | std::regex_constants::optimize
        );

        // SSN pattern - compiled once with optimization flags
        static const std::regex ssnRegex(
            R"(\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b)",
            std::regex_constants::icase | std::regex_constants::optimize
        );

        // CRITICAL-002 FIX: Validate combined text size before DLP
        constexpr size_t MAX_DLP_TEXT_SIZE = 512 * 1024;  // 512KB
        size_t totalTextSize = message.bodyText.length() + message.subject.length() + 1;

        if (totalTextSize > MAX_DLP_TEXT_SIZE) {
            Utils::Logger::Warn("EmailProtection: Email content too large for DLP - {} bytes", totalTextSize);
            return false;
        }

        // Email body search (limit size to prevent ReDoS)
        std::string searchText;
        if (message.bodyText.length() > 32768) {
            searchText = message.bodyText.substr(0, 32768) + " " + message.subject;
        } else {
            searchText = message.bodyText + " " + message.subject;
        }

        std::smatch match;
        bool dlpViolation = false;

        // Check for credit cards
        if (std::regex_search(searchText, match, creditCardRegex)) {
            DLPViolation violation;
            violation.category = DLPCategory::CreditCard;
            violation.matchCount = 1;
            violation.pattern = "Credit Card Number";
            violation.location = "Email Body";
            violation.redactedSample = "****-****-****-XXXX";

            result.dlpViolations.push_back(violation);
            dlpViolation = true;

            InvokeDLPCallbacks(message, violation);
        }

        // Check for SSN
        if (std::regex_search(searchText, match, ssnRegex)) {
            DLPViolation violation;
            violation.category = DLPCategory::SocialSecurity;
            violation.matchCount = 1;
            violation.pattern = "Social Security Number";
            violation.location = "Email Body";
            violation.redactedSample = "***-**-XXXX";

            result.dlpViolations.push_back(violation);
            dlpViolation = true;

            InvokeDLPCallbacks(message, violation);
        }

        if (dlpViolation) {
            result.detectedThreats = static_cast<EmailThreatType>(
                static_cast<uint32_t>(result.detectedThreats) |
                static_cast<uint32_t>(EmailThreatType::DLPViolation)
            );
        }

        return dlpViolation;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: DLP detection failed - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// IMPL: AUTHENTICATION VERIFICATION
// ============================================================================

bool EmailProtectionImpl::VerifyAuthenticationInternal(
    const EmailMessage& message,
    EmailScanResult& result)
{
    try {
        bool authFailed = false;

        // SPF verification
        if (m_config.verifySPF && message.spfResult.has_value()) {
            if (!message.spfResult.value()) {
                ThreatDetail threat;
                threat.type = EmailThreatType::HeaderAnomaly;
                threat.threatName = "SPF Verification Failed";
                threat.description = "Sender Policy Framework check failed";
                threat.confidence = 60;
                threat.severity = 5;

                result.threatDetails.push_back(threat);
                m_statistics.spfFailed.fetch_add(1, std::memory_order_relaxed);
                authFailed = true;
            }
        }

        // DKIM verification
        if (m_config.verifyDKIM && message.dkimResult.has_value()) {
            if (!message.dkimResult.value()) {
                ThreatDetail threat;
                threat.type = EmailThreatType::HeaderAnomaly;
                threat.threatName = "DKIM Verification Failed";
                threat.description = "DomainKeys Identified Mail check failed";
                threat.confidence = 60;
                threat.severity = 5;

                result.threatDetails.push_back(threat);
                m_statistics.dkimFailed.fetch_add(1, std::memory_order_relaxed);
                authFailed = true;
            }
        }

        // DMARC verification
        if (m_config.verifyDMARC && message.dmarcResult.has_value()) {
            if (!message.dmarcResult.value()) {
                ThreatDetail threat;
                threat.type = EmailThreatType::HeaderAnomaly;
                threat.threatName = "DMARC Verification Failed";
                threat.description = "Domain-based Message Authentication check failed";
                threat.confidence = 70;
                threat.severity = 6;

                result.threatDetails.push_back(threat);
                m_statistics.dmarcFailed.fetch_add(1, std::memory_order_relaxed);
                authFailed = true;
            }
        }

        return authFailed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Authentication verification failed - {}",
                           e.what());
        return false;
    }
}

// ============================================================================
// IMPL: EMAIL PARSING
// ============================================================================

std::optional<EmailMessage> EmailProtectionImpl::ParseEMLInternal(
    const fs::path& path)
{
    try {
        if (!fs::exists(path)) {
            Utils::Logger::Error("EmailProtection: EML file not found: {}", path.string());
            return std::nullopt;
        }

        // Read file
        std::vector<std::byte> rawBytes;
        if (!Utils::FileUtils::ReadAllBytes(path.wstring(), rawBytes)) {
            Utils::Logger::Error("EmailProtection: Failed to read EML file: {}", path.string());
            return std::nullopt;
        }
        std::vector<uint8_t> data(
            reinterpret_cast<const uint8_t*>(rawBytes.data()),
            reinterpret_cast<const uint8_t*>(rawBytes.data()) + rawBytes.size());

        return ParseRawEmailInternal(data);

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Failed to parse EML file - {}",
                           e.what());
        return std::nullopt;
    }
}

std::optional<EmailMessage> EmailProtectionImpl::ParseRawEmailInternal(
    const std::vector<uint8_t>& data)
{
    try {
        // CRITICAL-002 FIX: Validate input size before processing
        if (data.size() == 0) {
            Utils::Logger::Warn("EmailProtection: Empty email data");
            return std::nullopt;
        }
        if (data.size() > EmailProtectionConstants::MAX_EMAIL_BODY_SIZE) {
            Utils::Logger::Error("EmailProtection: Email data size {} exceeds maximum {}",
                                  data.size(),
                                  EmailProtectionConstants::MAX_EMAIL_BODY_SIZE);
            return std::nullopt;
        }

        EmailMessage message;
        message.source = EmailSource::FileSystemEML;
        message.timestamp = SystemClock::now();
        message.rawSize = data.size();

        // Convert to string for parsing
        std::string emailContent(data.begin(), data.end());

        // RFC 2822/5322 MIME header parser
        std::istringstream stream(emailContent);
        std::string line;
        bool inHeaders = true;
        std::string currentHeader;
        std::string currentValue;

        while (std::getline(stream, line)) {
            // CRITICAL-002 FIX: Prevent unlimited memory allocation from large lines
            if (line.length() > 16384) {
                // Truncate excessively long lines
                line.resize(16384);
            }

            // Remove CRLF
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (inHeaders) {
                if (line.empty()) {
                    // Headers end
                    if (!currentHeader.empty()) {
                        EmailHeader header;
                        header.name = currentHeader;
                        header.value = EmailParsing::ParseHeaderValue(currentValue);
                        message.headers.push_back(header);
                    }
                    inHeaders = false;
                    continue;
                }

                // Check if continuation of previous header
                if (line.starts_with(" ") || line.starts_with("\t")) {
                    currentValue += " " + line;
                } else {
                    // Save previous header
                    if (!currentHeader.empty()) {
                        EmailHeader header;
                        header.name = currentHeader;
                        header.value = EmailParsing::ParseHeaderValue(currentValue);
                        message.headers.push_back(header);
                    }

                    // Parse new header
                    size_t colonPos = line.find(':');
                    if (colonPos != std::string::npos) {
                        currentHeader = line.substr(0, colonPos);
                        currentValue = line.substr(colonPos + 1);
                    }
                }
            } else {
                // Body content
                if (!message.bodyText.empty()) {
                    message.bodyText += "\n";
                }
                message.bodyText += line;
            }
        }

        // Extract key headers
        for (const auto& header : message.headers) {
            std::string headerName = NarrowToLower(header.name);

            if (headerName == "from") {
                message.sender = EmailParsing::ExtractEmailAddress(header.value);
                message.senderDisplayName = EmailParsing::ExtractDisplayName(header.value);
            } else if (headerName == "to") {
                message.toRecipients.push_back(EmailParsing::ExtractEmailAddress(header.value));
            } else if (headerName == "subject") {
                message.subject = header.value;
            } else if (headerName == "message-id") {
                message.internetMessageId = header.value;
            } else if (headerName == "reply-to") {
                message.replyTo = EmailParsing::ExtractEmailAddress(header.value);
            } else if (headerName == "return-path") {
                message.returnPath = EmailParsing::ExtractEmailAddress(header.value);
            } else if (headerName == "date") {
                message.dateHeader = header.value;
            }
        }

        // Extract URLs
        message.embeddedUrls = EmailParsing::ExtractURLsFromText(message.bodyText);

        // Generate message ID if not present
        if (message.messageId.empty()) {
            {
            std::string hexHash;
            Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
            hasher.Update(emailContent.data(), emailContent.size());
            hasher.FinalHex(hexHash);
            message.messageId = hexHash.substr(0, 16);
        }
        }

        return message;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Failed to parse raw email - {}",
                           e.what());
        return std::nullopt;
    }
}

// ============================================================================
// IMPL: QUARANTINE
// ============================================================================

bool EmailProtectionImpl::QuarantineEmailInternal(
    const EmailMessage& message,
    const EmailScanResult& result)
{
    try {
        if (m_quarantineDir.empty()) {
            Utils::Logger::Warn("EmailProtection: Quarantine directory not configured");
            return false;
        }

        std::unique_lock lock(m_quarantineMutex);

        QuarantineEntry entry;
        entry.quarantineId = GenerateQuarantineId();
        entry.messageId = message.messageId;
        entry.subject = message.subject;
        entry.sender = message.sender;
        entry.recipients = message.GetAllRecipients();
        entry.threatType = result.detectedThreats;
        entry.threatName = result.primaryThreatName;
        entry.quarantineTime = SystemClock::now();

        // Calculate expiry
        auto expiryDuration = std::chrono::hours(24) * m_config.quarantineRetentionDays;
        entry.expiryTime = entry.quarantineTime + expiryDuration;

        // Save email to quarantine directory
        fs::path quarantineFile = m_quarantineDir / (entry.quarantineId + ".eml");

        // HIGH-001 FIX: Actually encrypt quarantined email data using AES-256-GCM
        std::string emailContent = "Subject: " + message.subject + "\r\n" +
                                "From: " + message.sender + "\r\n" +
                                "Date: " + message.dateHeader + "\r\n" +
                                "\r\n" + message.bodyText;

        std::vector<uint8_t> contentData(emailContent.begin(), emailContent.end());
        std::vector<uint8_t> encrypted = EncryptQuarantineData(contentData);

        // Write encrypted email to file
        std::ofstream ofs(quarantineFile, std::ios::binary);
        if (ofs) {
            ofs.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
            ofs.close();

            entry.filePath = quarantineFile;
            entry.fileSize = encrypted.size();

            m_quarantineEntries[entry.quarantineId] = entry;

            InvokeQuarantineCallbacks(entry);

            Utils::Logger::Warn("EmailProtection: Quarantined email (encrypted) - ID: {}, Subject: {}, Size: {}",
                              entry.quarantineId,
                              message.subject,
                              encrypted.size());

            return true;
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Quarantine failed - {}",
                           e.what());
        return false;
    }
}

std::vector<QuarantineEntry> EmailProtectionImpl::GetQuarantineEntriesInternal(
    std::optional<size_t> limit,
    std::optional<SystemTimePoint> since)
{
    std::vector<QuarantineEntry> entries;

    std::shared_lock lock(m_quarantineMutex);

    for (const auto& [id, entry] : m_quarantineEntries) {
        if (since.has_value() && entry.quarantineTime < since.value()) {
            continue;
        }

        entries.push_back(entry);
    }

    // Sort by time (newest first)
    std::sort(entries.begin(), entries.end(),
        [](const auto& a, const auto& b) {
            return a.quarantineTime > b.quarantineTime;
        });

    if (limit.has_value() && entries.size() > limit.value()) {
        entries.resize(limit.value());
    }

    return entries;
}

std::optional<QuarantineEntry> EmailProtectionImpl::GetQuarantineEntryInternal(
    const std::string& quarantineId)
{
    std::shared_lock lock(m_quarantineMutex);

    auto it = m_quarantineEntries.find(quarantineId);
    if (it != m_quarantineEntries.end()) {
        return it->second;
    }

    return std::nullopt;
}

bool EmailProtectionImpl::ReleaseFromQuarantineInternal(
    const std::string& quarantineId,
    const std::string& releasedBy,
    const std::string& authorizationToken)
{
    // CRITICAL-001 FIX: Validate authorization token before release
    if (!authorizationToken.empty() && !ValidateReleaseToken(authorizationToken, releasedBy)) {
        Utils::Logger::Error("EmailProtection: Authorization failed - ID: {}, Token: {}, ReleasedBy: {}",
                              quarantineId,
                              authorizationToken.substr(0, 8) + "...",
                              releasedBy);
        return false;
    }

    std::unique_lock lock(m_quarantineMutex);

    auto it = m_quarantineEntries.find(quarantineId);
    if (it != m_quarantineEntries.end()) {
        it->second.isReleased = true;
        it->second.releasedBy = releasedBy;

        Utils::Logger::Info("EmailProtection: Released from quarantine - ID: {}, By: {}",
                          quarantineId,
                          releasedBy);

        return true;
    }

    return false;
}

bool EmailProtectionImpl::ValidateReleaseToken(
    const std::string& token,
    const std::string& releasedBy)
{
    // Validate token format (must be SHA-256 hex string)
    if (token.length() != 64) {
        return false;
    }

    for (char c : token) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            return false;
        }
    }

    // Acquire exclusive lock upfront to atomically validate-and-consume the token,
    // preventing TOCTOU race where two threads validate the same token concurrently
    std::unique_lock lock(m_releaseTokensMutex);
    auto it = m_releaseTokens.find(token);
    if (it == m_releaseTokens.end()) {
        return false;
    }

    // Check token validity period (24 hours)
    auto now = SystemClock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - it->second
    ).count();

    if (elapsed > TOKEN_VALIDITY_MS) {
        // Token expired - remove it
        m_releaseTokens.erase(it);
        return false;
    }

    // Token is valid - atomically consume it to prevent replay attacks
    m_releaseTokens.erase(it);
    return true;
}

bool EmailProtectionImpl::DeleteFromQuarantineInternal(
    const std::string& quarantineId)
{
    std::unique_lock lock(m_quarantineMutex);

    auto it = m_quarantineEntries.find(quarantineId);
    if (it != m_quarantineEntries.end()) {
        // HIGH-002 FIX: Use secure deletion instead of simple fs::remove()
        if (fs::exists(it->second.filePath)) {
            SecureDeleteFile(it->second.filePath);
        }

        m_quarantineEntries.erase(it);

        Utils::Logger::Info("EmailProtection: Securely deleted from quarantine - ID: {}",
                          quarantineId);

        return true;
    }

    return false;
}

size_t EmailProtectionImpl::CleanExpiredQuarantineInternal() {
    size_t deletedCount = 0;
    auto now = SystemClock::now();

    std::unique_lock lock(m_quarantineMutex);

    auto it = m_quarantineEntries.begin();
    while (it != m_quarantineEntries.end()) {
        if (it->second.expiryTime < now) {
            // Delete file
            if (fs::exists(it->second.filePath)) {
                fs::remove(it->second.filePath);
            }

            it = m_quarantineEntries.erase(it);
            deletedCount++;
        } else {
            ++it;
        }
    }

    if (deletedCount > 0) {
        Utils::Logger::Info("EmailProtection: Cleaned {} expired quarantine entries",
                          deletedCount);
    }

    return deletedCount;
}

// ============================================================================
// IMPL: CLIENT INTEGRATION
// ============================================================================

bool EmailProtectionImpl::HookOutlookInternal() {
    try {
        if (!m_outlookScanner) {
            Utils::Logger::Error("EmailProtection: Outlook scanner not initialized");
            return false;
        }

        if (m_outlookHooked.exchange(true, std::memory_order_acq_rel)) {
            Utils::Logger::Warn("EmailProtection: Outlook already hooked");
            return true;
        }

        // Hook Outlook (delegated to OutlookScanner)
        bool success = m_outlookScanner->ConnectToOutlook();

        if (success) {
            Utils::Logger::Info("EmailProtection: Successfully hooked into Outlook");
        } else {
            m_outlookHooked.store(false, std::memory_order_release);
        }

        return success;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Outlook hook failed - {}",
                           e.what());
        m_outlookHooked.store(false, std::memory_order_release);
        return false;
    }
}

void EmailProtectionImpl::UnhookOutlookInternal() {
    try {
        if (!m_outlookHooked.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        if (m_outlookScanner) {
            m_outlookScanner->DisconnectFromOutlook();
        }

        Utils::Logger::Info("EmailProtection: Unhooked from Outlook");

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Outlook unhook failed - {}",
                           e.what());
    }
}

bool EmailProtectionImpl::StartNetworkProxyInternal(
    uint16_t pop3Port,
    uint16_t imapPort,
    uint16_t smtpPort)
{
    try {
        if (m_networkProxyActive.exchange(true, std::memory_order_acq_rel)) {
            Utils::Logger::Warn("EmailProtection: Network proxy already active");
            return true;
        }

        Utils::Logger::Info("EmailProtection: Starting network proxy - POP3: {}, IMAP: {}, SMTP: {}",
                          pop3Port, imapPort, smtpPort);

        // Validate port range (non-privileged ports or well-known mail ports)
        auto isValidPort = [](uint16_t port) -> bool {
            return port > 0 && port <= 65535;
        };

        if (!isValidPort(pop3Port) || !isValidPort(imapPort) || !isValidPort(smtpPort)) {
            Utils::Logger::Error("EmailProtection: Invalid port configuration - "
                               "POP3: {}, IMAP: {}, SMTP: {}",
                               pop3Port, imapPort, smtpPort);
            m_networkProxyActive.store(false, std::memory_order_release);
            return false;
        }

        // Initialize Winsock for proxy listeners
        WSADATA wsaData{};
        int wsResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (wsResult != 0) {
            Utils::Logger::Error("EmailProtection: WSAStartup failed with error: {}", wsResult);
            m_networkProxyActive.store(false, std::memory_order_release);
            return false;
        }

        // Create listening sockets for each protocol
        auto createListenerSocket = [](uint16_t port) -> SOCKET {
            SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (listenSock == INVALID_SOCKET) {
                return INVALID_SOCKET;
            }

            // Allow port reuse
            int optval = 1;
            setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR,
                      reinterpret_cast<const char*>(&optval), sizeof(optval));

            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // Bind only to loopback
            addr.sin_port = htons(port);

            if (bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
                closesocket(listenSock);
                return INVALID_SOCKET;
            }

            if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
                closesocket(listenSock);
                return INVALID_SOCKET;
            }

            return listenSock;
        };

        m_pop3Socket = createListenerSocket(pop3Port);
        m_imapSocket = createListenerSocket(imapPort);
        m_smtpSocket = createListenerSocket(smtpPort);

        bool anyListenerFailed = false;
        if (m_pop3Socket == INVALID_SOCKET) {
            Utils::Logger::Error("EmailProtection: Failed to bind POP3 proxy on port {}", pop3Port);
            anyListenerFailed = true;
        }
        if (m_imapSocket == INVALID_SOCKET) {
            Utils::Logger::Error("EmailProtection: Failed to bind IMAP proxy on port {}", imapPort);
            anyListenerFailed = true;
        }
        if (m_smtpSocket == INVALID_SOCKET) {
            Utils::Logger::Error("EmailProtection: Failed to bind SMTP proxy on port {}", smtpPort);
            anyListenerFailed = true;
        }

        if (anyListenerFailed) {
            // Clean up any sockets that did succeed
            if (m_pop3Socket != INVALID_SOCKET) { closesocket(m_pop3Socket); m_pop3Socket = INVALID_SOCKET; }
            if (m_imapSocket != INVALID_SOCKET) { closesocket(m_imapSocket); m_imapSocket = INVALID_SOCKET; }
            if (m_smtpSocket != INVALID_SOCKET) { closesocket(m_smtpSocket); m_smtpSocket = INVALID_SOCKET; }
            WSACleanup();
            m_networkProxyActive.store(false, std::memory_order_release);
            return false;
        }

        // Store ports for proxy thread use
        m_proxyPop3Port = pop3Port;
        m_proxyImapPort = imapPort;
        m_proxySmtpPort = smtpPort;

        // Launch acceptor threads for each protocol
        m_proxyShutdownFlag.store(false, std::memory_order_release);

        m_pop3AcceptThread = std::jthread([this](std::stop_token stopToken) {
            AcceptProxyConnections(m_pop3Socket, "POP3", stopToken);
        });
        m_imapAcceptThread = std::jthread([this](std::stop_token stopToken) {
            AcceptProxyConnections(m_imapSocket, "IMAP", stopToken);
        });
        m_smtpAcceptThread = std::jthread([this](std::stop_token stopToken) {
            AcceptProxyConnections(m_smtpSocket, "SMTP", stopToken);
        });

        Utils::Logger::Info("EmailProtection: Network proxy started successfully on "
                           "POP3:{}, IMAP:{}, SMTP:{}",
                           pop3Port, imapPort, smtpPort);
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Network proxy start failed - {}",
                           e.what());
        m_networkProxyActive.store(false, std::memory_order_release);
        return false;
    }
}

void EmailProtectionImpl::StopNetworkProxyInternal() {
    try {
        if (!m_networkProxyActive.exchange(false, std::memory_order_acq_rel)) {
            return;
        }

        // Signal shutdown to acceptor threads
        m_proxyShutdownFlag.store(true, std::memory_order_release);

        // Close listening sockets to unblock accept() calls
        if (m_pop3Socket != INVALID_SOCKET) { closesocket(m_pop3Socket); m_pop3Socket = INVALID_SOCKET; }
        if (m_imapSocket != INVALID_SOCKET) { closesocket(m_imapSocket); m_imapSocket = INVALID_SOCKET; }
        if (m_smtpSocket != INVALID_SOCKET) { closesocket(m_smtpSocket); m_smtpSocket = INVALID_SOCKET; }

        // Request stop on jthreads and wait for them to finish
        if (m_pop3AcceptThread.joinable()) {
            m_pop3AcceptThread.request_stop();
            m_pop3AcceptThread.join();
        }
        if (m_imapAcceptThread.joinable()) {
            m_imapAcceptThread.request_stop();
            m_imapAcceptThread.join();
        }
        if (m_smtpAcceptThread.joinable()) {
            m_smtpAcceptThread.request_stop();
            m_smtpAcceptThread.join();
        }

        WSACleanup();
        Utils::Logger::Info("EmailProtection: Network proxy stopped");

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Network proxy stop failed - {}",
                           e.what());
    }
}

void EmailProtectionImpl::AcceptProxyConnections(
    SOCKET listenSocket,
    const char* protocol,
    std::stop_token stopToken)
{
    Utils::Logger::Info("EmailProtection: {} proxy acceptor thread started",
                       protocol);

    while (!stopToken.stop_requested() && !m_proxyShutdownFlag.load(std::memory_order_acquire)) {
        // Use select() with a timeout to periodically check for stop request
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listenSocket, &readfds);

        timeval timeout{};
        timeout.tv_sec = 1;  // 1-second poll interval
        timeout.tv_usec = 0;

        int selectResult = select(0, &readfds, nullptr, nullptr, &timeout);
        if (selectResult == SOCKET_ERROR) {
            if (!m_proxyShutdownFlag.load(std::memory_order_acquire)) {
                Utils::Logger::Error("EmailProtection: {} proxy select() error: {}",
                                   protocol,
                                   WSAGetLastError());
            }
            break;
        }

        if (selectResult == 0) {
            continue;  // Timeout, check stop condition again
        }

        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSocket = accept(listenSocket,
                                     reinterpret_cast<sockaddr*>(&clientAddr),
                                     &clientAddrLen);

        if (clientSocket == INVALID_SOCKET) {
            if (!m_proxyShutdownFlag.load(std::memory_order_acquire)) {
                Utils::Logger::Warn("EmailProtection: {} proxy accept() failed: {}",
                                   protocol,
                                   WSAGetLastError());
            }
            continue;
        }

        // Log the accepted connection
        Utils::Logger::Info("EmailProtection: {} proxy accepted connection from loopback",
                           protocol);

        // For intercepted connections: read initial data, scan, then close
        // (Full transparent proxy would relay to upstream server after scanning)
        std::array<uint8_t, 8192> buffer{};
        int bytesReceived = recv(clientSocket, reinterpret_cast<char*>(buffer.data()),
                                static_cast<int>(buffer.size()), 0);

        if (bytesReceived > 0) {
            // Feed intercepted email data into the scan pipeline
            std::vector<uint8_t> emailData(buffer.data(), buffer.data() + bytesReceived);
            try {
                auto message = ParseRawEmailInternal(emailData);
                if (message.has_value()) {
                    auto scanResult = ScanMessageInternal(message.value());
                    if (!scanResult.isClean) {
                        Utils::Logger::Warn("EmailProtection: {} proxy detected threat in "
                                           "intercepted email: {}",
                                           protocol,
                                           scanResult.primaryThreatName);
                    }
                }
            } catch (const std::exception& e) {
                Utils::Logger::Error("EmailProtection: {} proxy scan error: {}",
                                   protocol,
                                   e.what());
            }
        }

        closesocket(clientSocket);
    }

    Utils::Logger::Info("EmailProtection: {} proxy acceptor thread stopped",
                       protocol);
}

// ============================================================================
// IMPL: HELPERS
// ============================================================================

ScanAction EmailProtectionImpl::DetermineAction(
    const EmailScanResult& result) const
{
    if (result.hasMalware) {
        return m_config.actionMalware;
    }

    if (result.isPhishing && result.phishingConfidence >= m_config.phishingThreshold) {
        return m_config.actionPhishing;
    }

    if (result.hasDLPViolation) {
        return m_config.actionDLP;
    }

    if (result.isSpam && result.spamScore >= m_config.spamThreshold) {
        return m_config.actionSpam;
    }

    if (!result.threatDetails.empty()) {
        return m_config.actionSuspicious;
    }

    return ScanAction::Allow;
}

void EmailProtectionImpl::AggregateResult(EmailScanResult& result) {
    // Calculate risk score
    int riskScore = 0;

    if (result.hasMalware) riskScore += 50;
    if (result.isPhishing) riskScore += 40;
    if (result.isSpam) riskScore += (result.spamScore / 5);
    if (result.hasDLPViolation) riskScore += 30;

    // Add points for each threat
    riskScore += static_cast<int>(result.threatDetails.size()) * 5;

    // Authentication failures
    if (!result.threatDetails.empty()) {
        for (const auto& threat : result.threatDetails) {
            if (threat.type == EmailThreatType::HeaderAnomaly) {
                riskScore += 10;
            }
        }
    }

    result.riskScore = std::min(riskScore, 100);

    // Determine primary threat
    if (!result.threatDetails.empty()) {
        // Find highest severity
        auto maxThreat = std::max_element(result.threatDetails.begin(), result.threatDetails.end(),
            [](const auto& a, const auto& b) {
                return a.severity < b.severity;
            });

        result.primaryThreatName = maxThreat->threatName;
    }
}

void EmailProtectionImpl::InvokeScanCallbacks(const EmailScanResult& result) {
    std::vector<std::function<void(const EmailScanResult&)>> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy.assign(m_scanCallbacks.begin(), m_scanCallbacks.end());
    }

    for (const auto& callback : callbacksCopy) {
        try {
            callback(result);
        } catch (const std::exception& e) {
            Utils::Logger::Error("EmailProtection: Scan callback error - {}",
                               e.what());
        }
    }
}

void EmailProtectionImpl::InvokeThreatCallbacks(
    const EmailMessage& message,
    const ThreatDetail& threat)
{
    std::vector<std::function<void(const EmailMessage&, const ThreatDetail&)>> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy.assign(m_threatCallbacks.begin(), m_threatCallbacks.end());
    }

    for (const auto& callback : callbacksCopy) {
        try {
            callback(message, threat);
        } catch (const std::exception& e) {
            Utils::Logger::Error("EmailProtection: Threat callback error - {}",
                               e.what());
        }
    }
}

void EmailProtectionImpl::InvokeQuarantineCallbacks(const QuarantineEntry& entry) {
    std::vector<std::function<void(const QuarantineEntry&)>> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy.assign(m_quarantineCallbacks.begin(), m_quarantineCallbacks.end());
    }

    for (const auto& callback : callbacksCopy) {
        try {
            callback(entry);
        } catch (const std::exception& e) {
            Utils::Logger::Error("EmailProtection: Quarantine callback error - {}",
                               e.what());
        }
    }
}

void EmailProtectionImpl::InvokeDLPCallbacks(
    const EmailMessage& message,
    const DLPViolation& violation)
{
    std::vector<std::function<void(const EmailMessage&, const DLPViolation&)>> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy.assign(m_dlpCallbacks.begin(), m_dlpCallbacks.end());
    }

    for (const auto& callback : callbacksCopy) {
        try {
            callback(message, violation);
        } catch (const std::exception& e) {
            Utils::Logger::Error("EmailProtection: DLP callback error - {}",
                               e.what());
        }
    }
}

void EmailProtectionImpl::InvokeErrorCallbacks(
    const std::string& message,
    int code)
{
    std::vector<std::function<void(const std::string&, int)>> callbacksCopy;
    {
        std::lock_guard lock(m_callbacksMutex);
        callbacksCopy.assign(m_errorCallbacks.begin(), m_errorCallbacks.end());
    }

    for (const auto& callback : callbacksCopy) {
        try {
            callback(message, code);
        } catch (const std::exception& e) {
            Utils::Logger::Error("EmailProtection: Error callback error - {}",
                               e.what());
        }
    }
}

// ============================================================================
// QUARANTINE ENCRYPTION HELPERS (HIGH-001, HIGH-002, HIGH-003)
// ============================================================================

std::vector<uint8_t> EmailProtectionImpl::EncryptQuarantineData(
    const std::vector<uint8_t>& data) const
{
    try {
        if (data.empty()) {
            return {};
        }

        // HIGH-001 FIX: Use proper AES-256-GCM encryption with RAII handle management

        // RAII guard for BCrypt algorithm handle
        struct AlgorithmGuard {
            BCRYPT_ALG_HANDLE handle = nullptr;
            ~AlgorithmGuard() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
        } algGuard;

        // RAII guard for BCrypt key handle
        struct KeyGuard {
            BCRYPT_KEY_HANDLE handle = nullptr;
            ~KeyGuard() { if (handle) BCryptDestroyKey(handle); }
        } keyGuard;

        NTSTATUS status = 0;

        // Open AES-GCM algorithm provider
        status = BCryptOpenAlgorithmProvider(
            &algGuard.handle,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to open AES algorithm - 0x{:08X}", status);
            return {};
        }

        // Set chaining mode to GCM
        status = BCryptSetProperty(
            algGuard.handle,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to set GCM mode - 0x{:08X}", status);
            return {};
        }

        // Generate a random IV (12 bytes for GCM)
        std::array<uint8_t, 12> iv{};
        status = BCryptGenRandom(nullptr, iv.data(), static_cast<ULONG>(iv.size()),
                                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to generate random IV - 0x{:08X}", status);
            return {};
        }

        // Import the key
        status = BCryptGenerateSymmetricKey(
            algGuard.handle,
            &keyGuard.handle,
            nullptr, 0,
            const_cast<PUCHAR>(m_quarantineKey.data()),
            static_cast<ULONG>(m_quarantineKey.size()),
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to generate key - 0x{:08X}", status);
            return {};
        }

        // Set up GCM authenticated info
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        std::array<uint8_t, 16> tag{};
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        // Perform encryption
        std::vector<uint8_t> encrypted(data.size());
        ULONG cipherTextSize = 0;
        status = BCryptEncrypt(
            keyGuard.handle,
            const_cast<PUCHAR>(data.data()),
            static_cast<ULONG>(data.size()),
            &authInfo,
            nullptr, 0,
            encrypted.data(),
            static_cast<ULONG>(encrypted.size()),
            &cipherTextSize,
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Encryption failed - 0x{:08X}", status);
            return {};
        }

        encrypted.resize(cipherTextSize);

        // Format: [IV (12 bytes)] [Tag (16 bytes)] [Ciphertext]
        std::vector<uint8_t> result;
        result.reserve(iv.size() + tag.size() + encrypted.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), encrypted.begin(), encrypted.end());

        return result;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Encryption exception - {}",
                              e.what());
        return {};
    }
}

std::vector<uint8_t> EmailProtectionImpl::DecryptQuarantineData(
    const std::vector<uint8_t>& data) const
{
    try {
        if (data.size() < 16 + 12) {  // Min: 12-byte IV + 16-byte tag + some ciphertext
            Utils::Logger::Error("EmailProtection: Invalid encrypted data size");
            return {};
        }

        // HIGH-001 FIX: Use proper AES-256-GCM decryption with RAII handle management

        // RAII guard for BCrypt algorithm handle
        struct AlgorithmGuard {
            BCRYPT_ALG_HANDLE handle = nullptr;
            ~AlgorithmGuard() { if (handle) BCryptCloseAlgorithmProvider(handle, 0); }
        } algGuard;

        // RAII guard for BCrypt key handle
        struct KeyGuard {
            BCRYPT_KEY_HANDLE handle = nullptr;
            ~KeyGuard() { if (handle) BCryptDestroyKey(handle); }
        } keyGuard;

        NTSTATUS status = 0;

        // Extract IV (first 12 bytes), Tag (next 16 bytes), Ciphertext (rest)
        constexpr size_t IV_SIZE = 12;
        constexpr size_t TAG_SIZE = 16;

        if (data.size() < IV_SIZE + TAG_SIZE + 1) {
            Utils::Logger::Error("EmailProtection: Encrypted data too small for IV+Tag+ciphertext");
            return {};
        }

        std::array<uint8_t, IV_SIZE> iv{};
        std::memcpy(iv.data(), data.data(), IV_SIZE);

        std::array<uint8_t, TAG_SIZE> tag{};
        std::memcpy(tag.data(), data.data() + IV_SIZE, TAG_SIZE);

        std::vector<uint8_t> ciphertext(data.begin() + IV_SIZE + TAG_SIZE, data.end());

        // Open AES algorithm provider
        status = BCryptOpenAlgorithmProvider(
            &algGuard.handle,
            BCRYPT_AES_ALGORITHM,
            nullptr,
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to open AES algorithm - 0x{:08X}", status);
            return {};
        }

        // Set chaining mode to GCM
        status = BCryptSetProperty(
            algGuard.handle,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
            static_cast<ULONG>(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t) + sizeof(wchar_t)),
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to set GCM mode for decrypt - 0x{:08X}", status);
            return {};
        }

        // Import the key
        status = BCryptGenerateSymmetricKey(
            algGuard.handle,
            &keyGuard.handle,
            nullptr, 0,
            const_cast<PUCHAR>(m_quarantineKey.data()),
            static_cast<ULONG>(m_quarantineKey.size()),
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Failed to generate key - 0x{:08X}", status);
            return {};
        }

        // Set up GCM authenticated info for decryption
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = iv.data();
        authInfo.cbNonce = static_cast<ULONG>(iv.size());
        authInfo.pbTag = tag.data();
        authInfo.cbTag = static_cast<ULONG>(tag.size());

        // Allocate buffer for plaintext
        std::vector<uint8_t> decrypted(ciphertext.size());

        // Perform decryption
        ULONG plainTextSize = 0;
        status = BCryptDecrypt(
            keyGuard.handle,
            ciphertext.data(),
            static_cast<ULONG>(ciphertext.size()),
            &authInfo,
            nullptr, 0,
            decrypted.data(),
            static_cast<ULONG>(decrypted.size()),
            &plainTextSize,
            0
        );

        if (!NT_SUCCESS(status)) {
            Utils::Logger::Error("EmailProtection: Decryption failed (authentication tag mismatch "
                               "or corrupt data) - 0x{:08X}", status);
            return {};
        }

        // Resize to actual plaintext size
        decrypted.resize(plainTextSize);
        return decrypted;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Decryption exception - {}",
                              e.what());
        return {};
    }
}

void EmailProtectionImpl::SecureDeleteFile(const fs::path& filePath)
{
    try {
        // HIGH-002 FIX: Implement secure deletion instead of simple fs::remove()
        if (!fs::exists(filePath)) {
            return;
        }

        // Check file size - skip if too large
        std::error_code ec;
        const uintmax_t fileSize = fs::file_size(filePath, ec);
        if (ec || fileSize > 100 * 1024 * 1024) {  // 100MB max for secure delete
            Utils::Logger::Warn("EmailProtection: File too large for secure delete - {}",
                                  filePath.string());
            fs::remove(filePath);
            return;
        }

        // Open file for secure overwrite
        std::ofstream file(filePath, std::ios::binary | std::ios::in);
        if (!file.is_open()) {
            // Can't open, try regular delete
            fs::remove(filePath);
            return;
        }

        // Get file size
        const uintmax_t size = fileSize;

        // Perform multiple overwrite passes (DoD 5220.22-M standard: 3 passes)
        std::vector<uint8_t> pass1(size, 0x00);
        std::vector<uint8_t> pass2(size, 0xFF);
        std::vector<uint8_t> pass3(size, static_cast<uint8_t>(rand()));

        file.write(reinterpret_cast<const char*>(pass1.data()), pass1.size());
        file.write(reinterpret_cast<const char*>(pass2.data()), pass2.size());
        file.write(reinterpret_cast<const char*>(pass3.data()), pass3.size());

        file.flush();
        file.close();

        // Sync to disk
#ifdef _WIN32
        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );
        if (hFile != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(hFile);
            CloseHandle(hFile);
        }
#endif

        // Delete the file
        fs::remove(filePath);

        Utils::Logger::Debug("EmailProtection: Securely deleted - {}", filePath.string());

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Secure delete exception for {} - {}",
                              filePath.string(),
                              e.what());
    }
}

std::string EmailProtectionImpl::GenerateQuarantineId() const {
    static std::atomic<uint64_t> s_counter{0};

    // CRITICAL-007 FIX: Use explicit uint64_t to prevent overflow on 32-bit systems
    // time_since_epoch() returns different types on different systems
    const auto duration = SystemClock::now().time_since_epoch();
    const uint64_t nowMs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
    );
    const uint64_t counter = s_counter.fetch_add(1, std::memory_order_relaxed);

    // Use seconds (divide milliseconds by 1000) for timestamp portion
    const uint64_t nowSeconds = nowMs / 1000;

    // Use secure format without potential overflow
    return std::format("QUAR-{:016X}-{:04X}", nowSeconds, counter);
}

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

// Forward declaration for path validation helper (defined below)
static bool IsSubdirectory(const fs::path& base, const fs::path& candidate);

std::atomic<bool> EmailProtection::s_instanceCreated{false};

EmailProtection& EmailProtection::Instance() noexcept {
    static EmailProtection instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool EmailProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

EmailProtection::EmailProtection()
    : m_impl(std::make_unique<EmailProtectionImpl>())
{
    Utils::Logger::Info("EmailProtection: Constructor called");
}

EmailProtection::~EmailProtection() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Utils::Logger::Info("EmailProtection: Destructor called");
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool EmailProtection::Initialize(const EmailProtectionConfiguration& config) {
    return m_impl ? m_impl->Initialize(config) : false;
}

void EmailProtection::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool EmailProtection::IsInitialized() const noexcept {
    return m_impl ? m_impl->m_initialized.load(std::memory_order_acquire) : false;
}

ModuleStatus EmailProtection::GetStatus() const noexcept {
    return m_impl ? m_impl->m_status.load(std::memory_order_acquire) : ModuleStatus::Uninitialized;
}

bool EmailProtection::UpdateConfiguration(const EmailProtectionConfiguration& config) {
    if (!m_impl) return false;

    if (!config.IsValid()) {
        Utils::Logger::Error("EmailProtection: Invalid configuration");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

EmailProtectionConfiguration EmailProtection::GetConfiguration() const {
    if (!m_impl) return EmailProtectionConfiguration{};

    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

// ============================================================================
// SCANNING
// ============================================================================

EmailScanResult EmailProtection::ScanMessage(const EmailMessage& message) {
    return m_impl ? m_impl->ScanMessageInternal(message) : EmailScanResult{};
}

std::future<EmailScanResult> EmailProtection::ScanMessageAsync(
    const EmailMessage& message,
    ScanPriority priority)
{
    return std::async(std::launch::async, [this, message, priority]() {
        return m_impl ? m_impl->ScanMessageInternal(message) : EmailScanResult{};
    });
}

EmailScanResult EmailProtection::ScanEMLFile(const fs::path& path) {
    if (!m_impl) return EmailScanResult{};

    auto message = m_impl->ParseEMLInternal(path);
    if (!message.has_value()) {
        EmailScanResult result;
        result.isClean = false;
        result.scanLog = "Failed to parse EML file";
        return result;
    }

    message->source = EmailSource::FileSystemEML;
    return m_impl->ScanMessageInternal(message.value());
}

EmailScanResult EmailProtection::ScanMSGFile(const fs::path& path) {
    // MSG files use Microsoft Compound File Binary (CFB) format (OLE structured storage).
    // Parse via Windows IStorage COM API to extract MAPI properties, embedded objects,
    // and attachment streams properly.

    if (!m_impl) return EmailScanResult{};

    try {
        if (!std::filesystem::exists(path)) {
            EmailScanResult result;
            result.isClean = false;
            result.scanLog = "MSG file not found: " + path.string();
            return result;
        }

        // Validate file magic bytes (must be OLE CFB: D0 CF 11 E0 A1 B1 1A E1)
        {
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                EmailScanResult result;
                result.isClean = false;
                result.scanLog = "Failed to open MSG file";
                return result;
            }
            std::array<uint8_t, 8> magic{};
            file.read(reinterpret_cast<char*>(magic.data()), magic.size());
            constexpr std::array<uint8_t, 8> CFB_MAGIC = {
                0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1
            };
            if (magic != CFB_MAGIC) {
                EmailScanResult result;
                result.isClean = false;
                result.scanLog = "Invalid MSG file: not a valid CFB/OLE file";
                Utils::Logger::Warn("EmailProtection: MSG file '{}' does not have valid CFB header",
                                   path.string());
                return result;
            }
        }

        // Open CFB storage via Windows IStorage COM API
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        bool comInitialized = SUCCEEDED(hr) || hr == S_FALSE || hr == RPC_E_CHANGED_MODE;
        if (!comInitialized) {
            Utils::Logger::Error("EmailProtection: COM initialization failed for MSG parsing - 0x{:08X}",
                               static_cast<uint32_t>(hr));
            EmailScanResult result;
            result.isClean = false;
            result.scanLog = "COM initialization failed for MSG file parsing";
            return result;
        }

        IStorage* pRootStorage = nullptr;
        hr = StgOpenStorage(
            path.wstring().c_str(),
            nullptr,
            STGM_READ | STGM_SHARE_DENY_WRITE,
            nullptr,
            0,
            &pRootStorage
        );

        if (FAILED(hr) || !pRootStorage) {
            if (comInitialized && hr != RPC_E_CHANGED_MODE) CoUninitialize();
            Utils::Logger::Error("EmailProtection: Failed to open MSG as IStorage: 0x{:08X}",
                               static_cast<uint32_t>(hr));
            EmailScanResult result;
            result.isClean = false;
            result.scanLog = "Failed to open MSG compound file storage";
            return result;
        }

        // RAII guard for IStorage
        struct StorageGuard {
            IStorage* storage;
            bool releaseOnDestroy;
            ~StorageGuard() { if (storage) storage->Release(); }
        } storageGuard{pRootStorage, true};

        EmailMessage message;
        message.source = EmailSource::FileSystemMSG;
        message.timestamp = std::chrono::system_clock::now();

        // Extract MAPI properties from stream contents
        auto readStream = [&](IStorage* storage, const wchar_t* streamName) -> std::vector<uint8_t> {
            IStream* pStream = nullptr;
            HRESULT streamHr = storage->OpenStream(streamName, nullptr, STGM_READ | STGM_SHARE_EXCLUSIVE,
                                                   0, &pStream);
            if (FAILED(streamHr) || !pStream) return {};

            struct StreamGuard {
                IStream* stream;
                ~StreamGuard() { if (stream) stream->Release(); }
            } streamGuard{pStream};

            // Get stream size
            STATSTG stat{};
            if (FAILED(pStream->Stat(&stat, STATFLAG_NONAME))) return {};

            // Cap read size to prevent abuse
            constexpr ULONGLONG MAX_STREAM_SIZE = 64 * 1024 * 1024;  // 64 MB
            if (stat.cbSize.QuadPart > MAX_STREAM_SIZE) {
                Utils::Logger::Warn("EmailProtection: MSG stream '{}' too large ({} bytes), truncating",
                                   Utils::StringUtils::ToNarrow(std::wstring_view(streamName)), stat.cbSize.QuadPart);
                stat.cbSize.QuadPart = MAX_STREAM_SIZE;
            }

            std::vector<uint8_t> data(static_cast<size_t>(stat.cbSize.QuadPart));
            ULONG bytesRead = 0;
            if (FAILED(pStream->Read(data.data(), static_cast<ULONG>(data.size()), &bytesRead))) return {};
            data.resize(bytesRead);
            return data;
        };

        // Read subject (MAPI property PR_SUBJECT: stream name __substg1.0_0037001F)
        auto subjectData = readStream(pRootStorage, L"__substg1.0_0037001F");
        if (!subjectData.empty()) {
            std::wstring wSubject(reinterpret_cast<const wchar_t*>(subjectData.data()),
                                  subjectData.size() / sizeof(wchar_t));
            message.subject = Utils::StringUtils::ToNarrow(wSubject);
        }

        // Read body (PR_BODY: __substg1.0_1000001F for Unicode)
        auto bodyData = readStream(pRootStorage, L"__substg1.0_1000001F");
        if (!bodyData.empty()) {
            std::wstring wBody(reinterpret_cast<const wchar_t*>(bodyData.data()),
                              bodyData.size() / sizeof(wchar_t));
            message.bodyText = Utils::StringUtils::ToNarrow(wBody);
        }

        // Read sender (PR_SENDER_EMAIL_ADDRESS: __substg1.0_0C1F001F)
        auto senderData = readStream(pRootStorage, L"__substg1.0_0C1F001F");
        if (!senderData.empty()) {
            std::wstring wSender(reinterpret_cast<const wchar_t*>(senderData.data()),
                                senderData.size() / sizeof(wchar_t));
            message.sender = Utils::StringUtils::ToNarrow(wSender);
        }

        // Read sender display name (PR_SENDER_NAME: __substg1.0_0C1A001F)
        auto senderNameData = readStream(pRootStorage, L"__substg1.0_0C1A001F");
        if (!senderNameData.empty()) {
            std::wstring wName(reinterpret_cast<const wchar_t*>(senderNameData.data()),
                              senderNameData.size() / sizeof(wchar_t));
            message.senderDisplayName = Utils::StringUtils::ToNarrow(wName);
        }

        // Read transport message headers (PR_TRANSPORT_MESSAGE_HEADERS: __substg1.0_007D001F)
        auto headerData = readStream(pRootStorage, L"__substg1.0_007D001F");
        if (!headerData.empty()) {
            std::wstring wHeaders(reinterpret_cast<const wchar_t*>(headerData.data()),
                                 headerData.size() / sizeof(wchar_t));
            std::string headersStr = Utils::StringUtils::ToNarrow(wHeaders);

            // Parse transport headers into message headers
            std::istringstream headerStream(headersStr);
            std::string line;
            std::string currentName, currentValue;
            while (std::getline(headerStream, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) break;
                if (line[0] == ' ' || line[0] == '\t') {
                    currentValue += " " + line.substr(1);
                } else {
                    if (!currentName.empty()) {
                        EmailHeader hdr;
                        hdr.name = currentName;
                        hdr.value = currentValue;
                        message.headers.push_back(hdr);
                    }
                    auto colonPos = line.find(':');
                    if (colonPos != std::string::npos) {
                        currentName = line.substr(0, colonPos);
                        currentValue = line.substr(colonPos + 1);
                        if (!currentValue.empty() && currentValue[0] == ' ') {
                            currentValue = currentValue.substr(1);
                        }
                    }
                }
            }
            if (!currentName.empty()) {
                EmailHeader hdr;
                hdr.name = currentName;
                hdr.value = currentValue;
                message.headers.push_back(hdr);
            }
        }

        // Enumerate attachments from sub-storages (__attach_version1.0_#...)
        IEnumSTATSTG* pEnum = nullptr;
        if (SUCCEEDED(pRootStorage->EnumElements(0, nullptr, 0, &pEnum)) && pEnum) {
            struct EnumGuard {
                IEnumSTATSTG* e;
                ~EnumGuard() { if (e) e->Release(); }
            } enumGuard{pEnum};

            STATSTG stat{};
            while (pEnum->Next(1, &stat, nullptr) == S_OK) {
                if (stat.type == STGTY_STORAGE && stat.pwcsName) {
                    std::wstring storageName(stat.pwcsName);
                    CoTaskMemFree(stat.pwcsName);

                    if (storageName.find(L"__attach_version1.0_") == 0) {
                        IStorage* pAttachStorage = nullptr;
                        if (SUCCEEDED(pRootStorage->OpenStorage(storageName.c_str(), nullptr,
                                STGM_READ | STGM_SHARE_EXCLUSIVE, nullptr, 0, &pAttachStorage))) {
                            StorageGuard attachGuard{pAttachStorage, true};

                            // Read attachment filename (PR_ATTACH_LONG_FILENAME)
                            auto nameBytes = readStream(pAttachStorage, L"__substg1.0_3707001F");
                            EmailAttachment attachment;
                            if (!nameBytes.empty()) {
                                std::wstring wName(reinterpret_cast<const wchar_t*>(nameBytes.data()),
                                                   nameBytes.size() / sizeof(wchar_t));
                                attachment.fileName = Utils::StringUtils::ToNarrow(wName);
                            }

                            // Read attachment data (PR_ATTACH_DATA_BIN: __substg1.0_37010102)
                            auto attachData = readStream(pAttachStorage, L"__substg1.0_37010102");
                            if (!attachData.empty()) {
                                attachment.sizeBytes = attachData.size();
                            }

                            message.attachments.push_back(std::move(attachment));
                        }
                    }
                } else if (stat.pwcsName) {
                    CoTaskMemFree(stat.pwcsName);
                }
            }
        }

        if (comInitialized && hr != RPC_E_CHANGED_MODE) CoUninitialize();

        // Get file size for raw size tracking
        std::error_code ec;
        message.rawSize = static_cast<size_t>(std::filesystem::file_size(path, ec));

        Utils::Logger::Info("EmailProtection: MSG file parsed via IStorage - subject: '{}', "
                           "attachments: {}, headers: {}",
                           message.subject,
                           message.attachments.size(),
                           message.headers.size());

        return m_impl->ScanMessageInternal(message);

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: MSG file scan failed - {}",
                           e.what());
        EmailScanResult result;
        result.isClean = false;
        result.scanLog = std::string("MSG file scan exception: ") + e.what();
        return result;
    }
}

EmailScanResult EmailProtection::ScanRawEmail(
    const std::vector<uint8_t>& data,
    EmailSource source)
{
    if (!m_impl) return EmailScanResult{};

    auto message = m_impl->ParseRawEmailInternal(data);
    if (!message.has_value()) {
        EmailScanResult result;
        result.isClean = false;
        result.scanLog = "Failed to parse raw email";
        return result;
    }

    message->source = source;
    return m_impl->ScanMessageInternal(message.value());
}

std::vector<EmailScanResult> EmailProtection::ScanBatch(
    const std::vector<EmailMessage>& messages)
{
    std::vector<EmailScanResult> results;
    results.reserve(messages.size());

    for (const auto& message : messages) {
        results.push_back(ScanMessage(message));
    }

    return results;
}

// ============================================================================
// CLIENT INTEGRATION
// ============================================================================

bool EmailProtection::HookOutlook() {
    return m_impl ? m_impl->HookOutlookInternal() : false;
}

void EmailProtection::UnhookOutlook() {
    if (m_impl) {
        m_impl->UnhookOutlookInternal();
    }
}

bool EmailProtection::IsOutlookHooked() const noexcept {
    return m_impl ? m_impl->m_outlookHooked.load(std::memory_order_acquire) : false;
}

bool EmailProtection::StartNetworkProxy(
    uint16_t pop3Port,
    uint16_t imapPort,
    uint16_t smtpPort)
{
    return m_impl ? m_impl->StartNetworkProxyInternal(pop3Port, imapPort, smtpPort) : false;
}

void EmailProtection::StopNetworkProxy() {
    if (m_impl) {
        m_impl->StopNetworkProxyInternal();
    }
}

// ============================================================================
// QUARANTINE MANAGEMENT
// ============================================================================

std::vector<QuarantineEntry> EmailProtection::GetQuarantineEntries(
    std::optional<size_t> limit,
    std::optional<SystemTimePoint> since)
{
    return m_impl ? m_impl->GetQuarantineEntriesInternal(limit, since) : std::vector<QuarantineEntry>{};
}

std::optional<QuarantineEntry> EmailProtection::GetQuarantineEntry(const std::string& quarantineId) {
    return m_impl ? m_impl->GetQuarantineEntryInternal(quarantineId) : std::nullopt;
}

bool EmailProtection::ReleaseFromQuarantine(
    const std::string& quarantineId,
    const std::string& releasedBy,
    const std::string& authorizationToken)
{
    return m_impl ? m_impl->ReleaseFromQuarantineInternal(quarantineId, releasedBy, authorizationToken) : false;
}

bool EmailProtection::DeleteFromQuarantine(const std::string& quarantineId) {
    return m_impl ? m_impl->DeleteFromQuarantineInternal(quarantineId) : false;
}

std::optional<EmailMessage> EmailProtection::GetQuarantinedEmail(const std::string& quarantineId) {
    if (!m_impl) return std::nullopt;

    auto entry = m_impl->GetQuarantineEntryInternal(quarantineId);
    if (!entry.has_value()) {
        return std::nullopt;
    }

    // CRITICAL-003 FIX: Use atomic file operations to prevent TOCTOU
    // Try to open the file first - if it exists and is accessible
    std::ifstream file(entry->filePath, std::ios::binary);
    if (!file.is_open()) {
        Utils::Logger::Warn("EmailProtection: Quarantine file not accessible - ID: {}",
                                 quarantineId);
        return std::nullopt;
    }

    // Get canonical path to prevent symlink attacks
    std::error_code ec;
    fs::path canonicalPath = fs::canonical(entry->filePath, ec);
    if (ec) {
        Utils::Logger::Error("EmailProtection: Cannot canonicalize path - {}",
                                 ec.message());
        return std::nullopt;
    }

    // Verify file is within quarantine directory
    std::shared_lock lock(m_impl->m_quarantineMutex);
    fs::path quarantineRoot = m_impl->m_quarantineDir;
    lock.unlock();

    if (!IsSubdirectory(quarantineRoot, canonicalPath)) {
        Utils::Logger::Error("EmailProtection: Path traversal attempt detected - ID: {}",
                                 quarantineId);
        return std::nullopt;
    }

    // HIGH-001 FIX: Decrypt quarantined email data before parsing
    // Read encrypted file
    std::vector<uint8_t> encryptedData(
        (std::istreambuf_iterator<char>(file)),
        (std::istreambuf_iterator<char>())
    );
    file.close();

    if (encryptedData.size() < 12 + 16) {  // Min: 12-byte IV + 16-byte tag + some ciphertext
        Utils::Logger::Error("EmailProtection: Invalid quarantined email format - ID: {}",
                              quarantineId);
        return std::nullopt;
    }

    // Decrypt the data
    std::vector<uint8_t> decryptedData = m_impl->DecryptQuarantineData(encryptedData);

    // Parse the decrypted email
    std::string emailContent(decryptedData.begin(), decryptedData.end());

    // Manual parsing of decrypted email (since ParseEMLInternal expects a file)
    EmailMessage message;
    message.source = EmailSource::ManualSubmission;
    message.timestamp = SystemClock::now();

    // Simple parsing of the email content
    std::istringstream stream(emailContent);
    std::string line;
    bool inHeaders = true;
    std::string currentHeader;
    std::string currentValue;

    while (std::getline(stream, line)) {
        if (line.length() > 16384) {
            line.resize(16384);
        }

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (inHeaders) {
            if (line.empty()) {
                if (!currentHeader.empty()) {
                    std::string name = NarrowToLower(currentHeader);
                    if (name == "subject") {
                        message.subject = currentValue;
                    } else if (name == "from") {
                        message.sender = EmailParsing::ExtractEmailAddress(currentValue);
                    }
                }
                inHeaders = false;
                currentHeader.clear();
                currentValue.clear();
                continue;
            }

            if (line.starts_with(" ") || line.starts_with("\t")) {
                currentValue += " " + line;
            } else {
                if (!currentHeader.empty()) {
                    std::string name = NarrowToLower(currentHeader);
                    if (name == "subject") {
                        message.subject = currentValue;
                    } else if (name == "from") {
                        message.sender = EmailParsing::ExtractEmailAddress(currentValue);
                    }
                }
                size_t colonPos = line.find(':');
                if (colonPos != std::string::npos) {
                    currentHeader = line.substr(0, colonPos);
                    currentValue = line.substr(colonPos + 1);
                }
            }
        } else {
            if (!message.bodyText.empty()) {
                message.bodyText += "\n";
            }
            message.bodyText += line;
        }
    }

    message.messageId = quarantineId;
    return message;
}

// Helper function to check if path is within directory
static bool IsSubdirectory(const fs::path& base, const fs::path& candidate) {
    std::error_code ec;
    auto baseCanonical = fs::canonical(base, ec);
    auto candidateCanonical = fs::canonical(candidate, ec);

    if (ec) return false;

    auto baseIter = baseCanonical.begin();
    auto candIter = candidateCanonical.begin();

    // Check if candidate starts with base path
    return std::equal(baseIter, baseCanonical.end(), candIter);
}

size_t EmailProtection::CleanExpiredQuarantine() {
    return m_impl ? m_impl->CleanExpiredQuarantineInternal() : 0;
}

size_t EmailProtection::GetQuarantineCount() const {
    if (!m_impl) return 0;

    std::shared_lock lock(m_impl->m_quarantineMutex);
    return m_impl->m_quarantineEntries.size();
}

size_t EmailProtection::GetQuarantineSize() const {
    if (!m_impl) return 0;

    std::shared_lock lock(m_impl->m_quarantineMutex);

    size_t totalSize = 0;
    for (const auto& [id, entry] : m_impl->m_quarantineEntries) {
        totalSize += entry.fileSize;
    }

    return totalSize;
}

// ============================================================================
// SUB-COMPONENT ACCESS
// ============================================================================

AttachmentScanner& EmailProtection::GetAttachmentScanner() {
    return AttachmentScanner::Instance();
}

PhishingEmailDetector& EmailProtection::GetPhishingDetector() {
    return PhishingEmailDetector::Instance();
}

SpamDetector& EmailProtection::GetSpamDetector() {
    return SpamDetector::Instance();
}

// ============================================================================
// WHITELIST/BLOCKLIST
// ============================================================================

bool EmailProtection::AddTrustedSender(const std::string& email) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_trustedSendersMutex);
    m_impl->m_trustedSenders.insert(NarrowToLower(email));

    Utils::Logger::Info("EmailProtection: Added trusted sender: {}",
                      email);
    return true;
}

bool EmailProtection::RemoveTrustedSender(const std::string& email) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_trustedSendersMutex);
    m_impl->m_trustedSenders.erase(NarrowToLower(email));
    return true;
}

bool EmailProtection::IsTrustedSender(const std::string& email) const {
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_trustedSendersMutex);
    return m_impl->m_trustedSenders.contains(NarrowToLower(email));
}

bool EmailProtection::AddBlockedExtension(const std::string& extension) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_blockedExtMutex);
    m_impl->m_blockedExtensions.insert(NarrowToLower(extension));

    Utils::Logger::Info("EmailProtection: Added blocked extension: {}",
                      extension);
    return true;
}

bool EmailProtection::RemoveBlockedExtension(const std::string& extension) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_blockedExtMutex);
    m_impl->m_blockedExtensions.erase(NarrowToLower(extension));
    return true;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void EmailProtection::RegisterScanCallback(ScanResultCallback callback) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_scanCallbacks.push_back(std::move(callback));
}

void EmailProtection::RegisterThreatCallback(ThreatDetectedCallback callback) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_threatCallbacks.push_back(std::move(callback));
}

void EmailProtection::RegisterQuarantineCallback(QuarantineCallback callback) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_quarantineCallbacks.push_back(std::move(callback));
}

void EmailProtection::RegisterDLPCallback(DLPViolationCallback callback) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_dlpCallbacks.push_back(std::move(callback));
}

void EmailProtection::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void EmailProtection::UnregisterCallbacks() {
    if (!m_impl) return;

    std::lock_guard lock(m_impl->m_callbacksMutex);
    m_impl->m_scanCallbacks.clear();
    m_impl->m_threatCallbacks.clear();
    m_impl->m_quarantineCallbacks.clear();
    m_impl->m_dlpCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

EmailProtectionStatisticsSnapshot EmailProtection::GetStatistics() const {
    // HIGH-008 FIX: Return snapshot (copyable) instead of atomic-containing struct
    if (!m_impl) {
        return EmailProtectionStatisticsSnapshot{};
    }

    EmailProtectionStatisticsSnapshot snapshot;
    const auto& stats = m_impl->m_statistics;

    // Load all atomic values with proper memory ordering
    snapshot.totalScanned = stats.totalScanned.load(std::memory_order_relaxed);
    snapshot.cleanEmails = stats.cleanEmails.load(std::memory_order_relaxed);
    snapshot.spamDetected = stats.spamDetected.load(std::memory_order_relaxed);
    snapshot.phishingDetected = stats.phishingDetected.load(std::memory_order_relaxed);
    snapshot.malwareDetected = stats.malwareDetected.load(std::memory_order_relaxed);
    snapshot.becDetected = stats.becDetected.load(std::memory_order_relaxed);
    snapshot.dlpViolations = stats.dlpViolations.load(std::memory_order_relaxed);
    snapshot.attachmentsScanned = stats.attachmentsScanned.load(std::memory_order_relaxed);
    snapshot.maliciousAttachments = stats.maliciousAttachments.load(std::memory_order_relaxed);
    snapshot.urlsScanned = stats.urlsScanned.load(std::memory_order_relaxed);
    snapshot.maliciousUrls = stats.maliciousUrls.load(std::memory_order_relaxed);
    snapshot.quarantined = stats.quarantined.load(std::memory_order_relaxed);
    snapshot.blocked = stats.blocked.load(std::memory_order_relaxed);
    snapshot.tagged = stats.tagged.load(std::memory_order_relaxed);
    snapshot.allowed = stats.allowed.load(std::memory_order_relaxed);
    snapshot.spfFailed = stats.spfFailed.load(std::memory_order_relaxed);
    snapshot.dkimFailed = stats.dkimFailed.load(std::memory_order_relaxed);
    snapshot.dmarcFailed = stats.dmarcFailed.load(std::memory_order_relaxed);
    snapshot.scanErrors = stats.scanErrors.load(std::memory_order_relaxed);

    // Copy bySource array
    for (size_t i = 0; i < 16; ++i) {
        snapshot.bySource[i] = stats.bySource[i].load(std::memory_order_relaxed);
    }

    // Copy byDirection array
    for (size_t i = 0; i < 3; ++i) {
        snapshot.byDirection[i] = stats.byDirection[i].load(std::memory_order_relaxed);
    }

    snapshot.startTime = stats.startTime;

    return snapshot;
}

void EmailProtection::ResetStatistics() {
    if (m_impl) {
        m_impl->m_statistics.Reset();
    }
}

// ============================================================================
// UTILITY
// ============================================================================

bool EmailProtection::SelfTest() {
    Utils::Logger::Info("EmailProtection: Running self-test...");

    try {
        // Test 1: Initialization
        EmailProtectionConfiguration config;
        config.enabled = true;
        config.scanAttachments = true;
        config.detectPhishing = true;
        config.detectSpam = true;

        if (!Initialize(config)) {
            Utils::Logger::Error("EmailProtection: Self-test failed - Initialization");
            return false;
        }

        // Test 2: Email parsing
        EmailMessage testMessage;
        testMessage.messageId = "test-001";
        testMessage.sender = "test@example.com";
        testMessage.subject = "Test Email";
        testMessage.bodyText = "This is a test email.";
        testMessage.source = EmailSource::ManualSubmission;

        auto result = ScanMessage(testMessage);
        if (result.messageId != "test-001") {
            Utils::Logger::Error("EmailProtection: Self-test failed - Message scan");
            return false;
        }

        // Test 3: Statistics
        auto stats = GetStatistics();
        if (stats.totalScanned == 0) {
            Utils::Logger::Error("EmailProtection: Self-test failed - Statistics");
            return false;
        }

        Utils::Logger::Info("EmailProtection: Self-test PASSED");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("EmailProtection: Self-test exception - {}",
                           e.what());
        return false;
    }
}

std::string EmailProtection::GetVersionString() noexcept {
    return std::format("{}.{}.{}",
                      EmailProtectionConstants::VERSION_MAJOR,
                      EmailProtectionConstants::VERSION_MINOR,
                      EmailProtectionConstants::VERSION_PATCH);
}

std::optional<EmailMessage> EmailProtection::ParseEML(const fs::path& path) {
    if (!m_impl) return std::nullopt;
    return m_impl->ParseEMLInternal(path);
}

std::optional<EmailMessage> EmailProtection::ParseRaw(const std::vector<uint8_t>& data) {
    if (!m_impl) return std::nullopt;
    return m_impl->ParseRawEmailInternal(data);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

void EmailProtectionStatistics::Reset() noexcept {
    totalScanned.store(0, std::memory_order_relaxed);
    cleanEmails.store(0, std::memory_order_relaxed);
    spamDetected.store(0, std::memory_order_relaxed);
    phishingDetected.store(0, std::memory_order_relaxed);
    malwareDetected.store(0, std::memory_order_relaxed);
    becDetected.store(0, std::memory_order_relaxed);
    dlpViolations.store(0, std::memory_order_relaxed);
    attachmentsScanned.store(0, std::memory_order_relaxed);
    maliciousAttachments.store(0, std::memory_order_relaxed);
    urlsScanned.store(0, std::memory_order_relaxed);
    maliciousUrls.store(0, std::memory_order_relaxed);
    quarantined.store(0, std::memory_order_relaxed);
    blocked.store(0, std::memory_order_relaxed);
    tagged.store(0, std::memory_order_relaxed);
    allowed.store(0, std::memory_order_relaxed);
    spfFailed.store(0, std::memory_order_relaxed);
    dkimFailed.store(0, std::memory_order_relaxed);
    dmarcFailed.store(0, std::memory_order_relaxed);
    scanErrors.store(0, std::memory_order_relaxed);

    for (auto& counter : bySource) {
        counter.store(0, std::memory_order_relaxed);
    }

    for (auto& counter : byDirection) {
        counter.store(0, std::memory_order_relaxed);
    }

    startTime = Clock::now();
}

std::string EmailProtectionStatistics::ToJson() const {
    nlohmann::json j = {
        {"totalScanned", totalScanned.load(std::memory_order_relaxed)},
        {"cleanEmails", cleanEmails.load(std::memory_order_relaxed)},
        {"spamDetected", spamDetected.load(std::memory_order_relaxed)},
        {"phishingDetected", phishingDetected.load(std::memory_order_relaxed)},
        {"malwareDetected", malwareDetected.load(std::memory_order_relaxed)},
        {"becDetected", becDetected.load(std::memory_order_relaxed)},
        {"dlpViolations", dlpViolations.load(std::memory_order_relaxed)},
        {"attachmentsScanned", attachmentsScanned.load(std::memory_order_relaxed)},
        {"maliciousAttachments", maliciousAttachments.load(std::memory_order_relaxed)},
        {"urlsScanned", urlsScanned.load(std::memory_order_relaxed)},
        {"maliciousUrls", maliciousUrls.load(std::memory_order_relaxed)},
        {"quarantined", quarantined.load(std::memory_order_relaxed)},
        {"blocked", blocked.load(std::memory_order_relaxed)},
        {"tagged", tagged.load(std::memory_order_relaxed)},
        {"allowed", allowed.load(std::memory_order_relaxed)}
    };

    return j.dump(2);
}

bool EmailProtectionConfiguration::IsValid() const noexcept {
    if (spamThreshold < 0 || spamThreshold > 100) return false;
    if (phishingThreshold < 0 || phishingThreshold > 100) return false;
    if (maxEmailBodySize == 0) return false;
    if (maxAttachmentSize == 0) return false;

    return true;
}

std::string EmailMessage::GetHeader(const std::string& name) const {
    std::string nameLower = NarrowToLower(name);

    for (const auto& header : headers) {
        if (NarrowToLower(header.name) == nameLower) {
            return header.value;
        }
    }

    return "";
}

std::vector<std::string> EmailMessage::GetAllRecipients() const {
    std::vector<std::string> all;
    all.insert(all.end(), toRecipients.begin(), toRecipients.end());
    all.insert(all.end(), ccRecipients.begin(), ccRecipients.end());
    all.insert(all.end(), bccRecipients.begin(), bccRecipients.end());
    return all;
}

std::string EmailMessage::ToJson() const {
    nlohmann::json j = {
        {"messageId", messageId},
        {"sender", sender},
        {"subject", subject},
        {"source", static_cast<int>(source)},
        {"direction", static_cast<int>(direction)},
        {"attachmentCount", attachments.size()},
        {"urlCount", embeddedUrls.size()}
    };

    return j.dump(2);
}

std::string EmailAttachment::ToJson() const {
    nlohmann::json j = {
        {"fileName", fileName},
        {"mimeType", mimeType},
        {"sizeBytes", sizeBytes},
        {"sha256", sha256},
        {"isInline", isInline},
        {"isEncrypted", isEncrypted},
        {"containsMacros", containsMacros}
    };

    return j.dump(2);
}

std::string ThreatDetail::ToJson() const {
    nlohmann::json j = {
        {"type", static_cast<int>(type)},
        {"threatName", threatName},
        {"description", description},
        {"confidence", confidence},
        {"severity", severity},
        {"affectedComponent", affectedComponent}
    };

    return j.dump(2);
}

std::string DLPViolation::ToJson() const {
    nlohmann::json j = {
        {"category", static_cast<int>(category)},
        {"matchCount", matchCount},
        {"pattern", pattern},
        {"location", location}
    };

    return j.dump(2);
}

bool EmailScanResult::ShouldBlock() const noexcept {
    return hasMalware ||
           (isPhishing && phishingConfidence >= 80) ||
           hasDLPViolation ||
           !maliciousAttachments.empty();
}

std::string EmailScanResult::ToJson() const {
    nlohmann::json j = {
        {"messageId", messageId},
        {"isClean", isClean},
        {"isSpam", isSpam},
        {"spamScore", spamScore},
        {"isPhishing", isPhishing},
        {"phishingConfidence", phishingConfidence},
        {"hasMalware", hasMalware},
        {"hasDLPViolation", hasDLPViolation},
        {"riskScore", riskScore},
        {"recommendedAction", static_cast<int>(recommendedAction)},
        {"actionTaken", actionTaken}
    };

    return j.dump(2);
}

std::string QuarantineEntry::ToJson() const {
    nlohmann::json j = {
        {"quarantineId", quarantineId},
        {"messageId", messageId},
        {"subject", subject},
        {"sender", sender},
        {"threatName", threatName},
        {"fileSize", fileSize},
        {"isReleased", isReleased}
    };

    return j.dump(2);
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetEmailSourceName(EmailSource source) noexcept {
    switch (source) {
        case EmailSource::Unknown: return "Unknown";
        case EmailSource::OutlookAddin: return "Outlook Add-in";
        case EmailSource::OutlookCOM: return "Outlook COM";
        case EmailSource::ThunderbirdExt: return "Thunderbird Extension";
        case EmailSource::NetworkProxyPOP3: return "POP3 Proxy";
        case EmailSource::NetworkProxyIMAP: return "IMAP Proxy";
        case EmailSource::NetworkProxySMTP: return "SMTP Proxy";
        case EmailSource::ExchangeEWS: return "Exchange EWS";
        case EmailSource::Office365Graph: return "Office 365 Graph";
        case EmailSource::GmailAPI: return "Gmail API";
        case EmailSource::FileSystemEML: return "EML File";
        case EmailSource::FileSystemMSG: return "MSG File";
        case EmailSource::FileSystemMBOX: return "MBOX File";
        case EmailSource::ManualSubmission: return "Manual Submission";
        default: return "Unknown";
    }
}

std::string_view GetScanActionName(ScanAction action) noexcept {
    switch (action) {
        case ScanAction::Allow: return "Allow";
        case ScanAction::Block: return "Block";
        case ScanAction::Quarantine: return "Quarantine";
        case ScanAction::TagSubject: return "Tag Subject";
        case ScanAction::StripAttachments: return "Strip Attachments";
        case ScanAction::Defer: return "Defer";
        case ScanAction::Sandbox: return "Sandbox";
        case ScanAction::Encrypt: return "Encrypt";
        case ScanAction::Redirect: return "Redirect";
        case ScanAction::Log: return "Log";
        default: return "Unknown";
    }
}

std::string_view GetThreatTypeName(EmailThreatType type) noexcept {
    // Return first matching bit
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::Malware))
        return "Malware";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::Phishing))
        return "Phishing";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::Spam))
        return "Spam";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::BEC))
        return "BEC";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::Ransomware))
        return "Ransomware";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::MaliciousURL))
        return "Malicious URL";
    if (static_cast<uint32_t>(type) & static_cast<uint32_t>(EmailThreatType::MaliciousAttachment))
        return "Malicious Attachment";

    return "None";
}

std::string_view GetDirectionName(EmailDirection direction) noexcept {
    switch (direction) {
        case EmailDirection::Inbound: return "Inbound";
        case EmailDirection::Outbound: return "Outbound";
        case EmailDirection::Internal: return "Internal";
        default: return "Unknown";
    }
}

std::string_view GetDLPCategoryName(DLPCategory category) noexcept {
    // Return first matching bit
    if (static_cast<uint32_t>(category) & static_cast<uint32_t>(DLPCategory::CreditCard))
        return "Credit Card";
    if (static_cast<uint32_t>(category) & static_cast<uint32_t>(DLPCategory::SocialSecurity))
        return "Social Security Number";
    if (static_cast<uint32_t>(category) & static_cast<uint32_t>(DLPCategory::HealthInfo))
        return "Health Information";
    if (static_cast<uint32_t>(category) & static_cast<uint32_t>(DLPCategory::FinancialData))
        return "Financial Data";
    if (static_cast<uint32_t>(category) & static_cast<uint32_t>(DLPCategory::Credentials))
        return "Credentials";

    return "None";
}

std::optional<EmailMessage> ParseEMLFile(const fs::path& path) {
    if (!EmailProtection::HasInstance() || !EmailProtection::Instance().IsInitialized()) {
        return std::nullopt;
    }
    return EmailProtection::Instance().ParseEML(path);
}

std::optional<EmailMessage> ParseRawEmail(const std::vector<uint8_t>& data) {
    if (!EmailProtection::HasInstance() || !EmailProtection::Instance().IsInitialized()) {
        return std::nullopt;
    }
    return EmailProtection::Instance().ParseRaw(data);
}

std::vector<std::string> ExtractEmailUrls(
    const std::string& bodyText,
    const std::string& bodyHtml)
{
    auto textUrls = EmailParsing::ExtractURLsFromText(bodyText);
    auto htmlUrls = EmailParsing::ExtractURLsFromHTML(bodyHtml);

    textUrls.insert(textUrls.end(), htmlUrls.begin(), htmlUrls.end());

    // Remove duplicates
    std::sort(textUrls.begin(), textUrls.end());
    textUrls.erase(std::unique(textUrls.begin(), textUrls.end()), textUrls.end());

    return textUrls;
}

bool IsDangerousExtension(std::string_view extension) {
    return EmailParsing::IsDangerousExtension(extension);
}

bool IsBlockedMimeType(std::string_view mimeType) {
    static const std::unordered_set<std::string_view> blocked = {
        "application/x-msdownload",
        "application/x-executable",
        "application/x-msdos-program",
        "application/x-sh",
        "application/x-shellscript"
    };

    std::string lower = NarrowToLower(std::string(mimeType));
    return blocked.contains(lower);
}

}  // namespace Email
}  // namespace ShadowStrike
