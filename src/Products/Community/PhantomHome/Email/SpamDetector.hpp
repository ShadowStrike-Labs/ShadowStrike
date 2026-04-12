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
 * ShadowStrike NGAV - SPAM DETECTION ENGINE MODULE
 * ============================================================================
 *
 * @file SpamDetector.hpp
 * @brief Enterprise-grade spam filtering engine using Bayesian classification,
 *        rule-based analysis, and machine learning for comprehensive spam detection.
 *
 * Provides multi-layered spam detection including Bayesian filtering, content analysis,
 * sender reputation, RBL lookups, and machine learning classification.
 *
 * DETECTION TECHNIQUES:
 * =====================
 *
 * 1. BAYESIAN CLASSIFICATION
 *    - Token-based probability
 *    - N-gram analysis
 *    - Header token analysis
 *    - Adaptive learning
 *    - Corpus training
 *
 * 2. CONTENT ANALYSIS
 *    - Keyword density
 *    - Image-to-text ratio
 *    - Hidden text detection
 *    - Character set abuse
 *    - Base64 encoded spam
 *    - HTML obfuscation
 *
 * 3. SENDER REPUTATION
 *    - IP reputation (RBL/DNSBL)
 *    - Domain reputation
 *    - Sender score
 *    - Geographic analysis
 *    - Sending patterns
 *
 * 4. HEADER ANALYSIS
 *    - Missing/malformed headers
 *    - Forged headers
 *    - Inconsistent routing
 *    - Suspicious timestamps
 *    - Bulk mailer fingerprints
 *
 * 5. BEHAVIORAL ANALYSIS
 *    - Send rate analysis
 *    - Recipient patterns
 *    - Campaign detection
 *    - Volume anomalies
 *
 * INTEGRATION:
 * ============
 * - ThreatIntel for IP/domain blacklists
 * - PatternStore for spam patterns
 * - Whitelist for approved senders
 * - RBL/DNSBL services
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

namespace ShadowStrike::Email {
    class SpamDetectorImpl;
}

namespace ShadowStrike {
namespace Email {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SpamConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Spam threshold (0-100)
    inline constexpr int DEFAULT_SPAM_THRESHOLD = 70;
    
    /// @brief High-confidence spam threshold
    inline constexpr int HIGH_SPAM_THRESHOLD = 90;
    
    /// @brief Minimum tokens for Bayesian
    inline constexpr size_t MIN_TOKENS_FOR_BAYES = 5;
    
    /// @brief Maximum corpus size
    inline constexpr size_t MAX_CORPUS_SIZE = 1000000;
    
    /// @brief Default token weight limit
    inline constexpr double TOKEN_WEIGHT_LIMIT = 0.9999;
    
    /// @brief Common RBL providers
    inline constexpr const char* DEFAULT_RBL_PROVIDERS[] = {
        "zen.spamhaus.org",
        "bl.spamcop.net",
        "b.barracudacentral.org",
        "dnsbl-1.uceprotect.net",
        "psbl.surriel.com"
    };

    /// @brief Common spam keywords
    inline constexpr const char* SPAM_KEYWORDS[] = {
        "viagra", "cialis", "pharmacy", "enlargement", "lottery",
        "winner", "inheritance", "million dollars", "nigerian prince",
        "act now", "limited time", "free money", "no obligation",
        "unsubscribe", "click here", "buy now", "order now"
    };

}  // namespace SpamConstants

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
 * @brief Spam verdict
 */
enum class SpamVerdict : uint8_t {
    Ham             = 0,    ///< Not spam (legitimate)
    Unknown         = 1,    ///< Cannot determine
    Suspicious      = 2,    ///< Possibly spam
    Spam            = 3,    ///< Confirmed spam
    Bulk            = 4,    ///< Bulk/marketing email
    Newsletter      = 5,    ///< Newsletter (user preference)
    Phishing        = 6,    ///< Phishing (defer to phishing detector)
    Malware         = 7     ///< Contains malware (defer to AV)
};

/**
 * @brief Spam indicator
 */
enum class SpamIndicator : uint32_t {
    None                    = 0,
    BayesianScore           = 1 << 0,
    KeywordDensity          = 1 << 1,
    RBLListed               = 1 << 2,
    SuspiciousHeaders       = 1 << 3,
    HiddenText              = 1 << 4,
    ImageSpam               = 1 << 5,
    CharacterAbuse          = 1 << 6,
    HTMLObfuscation         = 1 << 7,
    BulkMailer              = 1 << 8,
    ForgedHeaders           = 1 << 9,
    MissingHeaders          = 1 << 10,
    SuspiciousTimestamp     = 1 << 11,
    BadReputation           = 1 << 12,
    ExcessiveRecipients     = 1 << 13,
    Base64Abuse             = 1 << 14,
    UnusualCharset          = 1 << 15,
    SuspiciousLinks         = 1 << 16,
    HighBounceRate          = 1 << 17,
    NewSender               = 1 << 18,
    GrayMail                = 1 << 19
};

/**
 * @brief RBL check result
 */
enum class RBLResult : uint8_t {
    NotListed       = 0,
    Listed          = 1,
    Timeout         = 2,
    Error           = 3
};

/**
 * @brief Training type
 */
enum class TrainingType : uint8_t {
    Spam    = 0,
    Ham     = 1
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Analyzing       = 3,
    Training        = 4,
    Paused          = 5,
    Stopping        = 6,
    Stopped         = 7,
    Error           = 8
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Token statistics for Bayesian
 */
struct TokenStatistics {
    /// @brief Token
    std::string token;
    
    /// @brief Spam count
    uint32_t spamCount = 0;
    
    /// @brief Ham count
    uint32_t hamCount = 0;
    
    /// @brief Spam probability
    double spamProbability = 0.5;
    
    /// @brief Last seen
    SystemTimePoint lastSeen;
    
    [[nodiscard]] double GetWeight() const noexcept;
};

/**
 * @brief RBL check detail
 */
struct RBLCheckResult {
    /// @brief Provider name
    std::string provider;
    
    /// @brief Result
    RBLResult result = RBLResult::NotListed;
    
    /// @brief Return code
    std::string returnCode;
    
    /// @brief Listing reason
    std::string reason;
    
    /// @brief Check duration
    std::chrono::milliseconds duration{0};
};

/**
 * @brief Sender reputation
 */
struct SenderReputation {
    /// @brief Email address
    std::string email;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief IP address
    std::string ipAddress;
    
    /// @brief Reputation score (0-100, higher = better)
    int reputationScore = 50;
    
    /// @brief Total emails from sender
    uint32_t totalEmails = 0;
    
    /// @brief Spam emails from sender
    uint32_t spamEmails = 0;
    
    /// @brief Ham emails from sender
    uint32_t hamEmails = 0;
    
    /// @brief First seen
    SystemTimePoint firstSeen;
    
    /// @brief Last seen
    SystemTimePoint lastSeen;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /// @brief Is blacklisted
    bool isBlacklisted = false;
    
    /// @brief RBL results
    std::vector<RBLCheckResult> rblResults;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Spam analysis result
 */
struct SpamAnalysisResult {
    /// @brief Verdict
    SpamVerdict verdict = SpamVerdict::Unknown;
    
    /// @brief Is spam
    bool isSpam = false;
    
    /// @brief Spam score (0-100)
    int spamScore = 0;
    
    /// @brief Bayesian score (0-100)
    int bayesianScore = 0;
    
    /// @brief Rule score
    int ruleScore = 0;
    
    /// @brief RBL score
    int rblScore = 0;
    
    /// @brief Reputation score
    int reputationScore = 50;
    
    /// @brief Confidence (0-100)
    int confidence = 0;
    
    /// @brief Indicators (bitmask)
    SpamIndicator indicators = SpamIndicator::None;
    
    /// @brief Matched rules
    std::vector<std::string> matchedRules;
    
    /// @brief Top spam tokens
    std::vector<std::pair<std::string, double>> topSpamTokens;
    
    /// @brief RBL results
    std::vector<RBLCheckResult> rblResults;
    
    /// @brief Sender reputation
    SenderReputation senderReputation;
    
    /// @brief Analysis summary
    std::string summary;
    
    /// @brief Analysis duration
    std::chrono::microseconds analysisDuration{0};
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct SpamStatistics {
    std::atomic<uint64_t> totalAnalyzed{0};
    std::atomic<uint64_t> spamDetected{0};
    std::atomic<uint64_t> hamDetected{0};
    std::atomic<uint64_t> unknownDetected{0};
    std::atomic<uint64_t> bulkDetected{0};
    std::atomic<uint64_t> rblHits{0};
    std::atomic<uint64_t> bayesianHits{0};
    std::atomic<uint64_t> ruleHits{0};
    std::atomic<uint64_t> trainedSpam{0};
    std::atomic<uint64_t> trainedHam{0};
    std::atomic<uint64_t> falsePositives{0};
    std::atomic<uint64_t> falseNegatives{0};
    std::atomic<uint64_t> whitelistHits{0};
    std::atomic<uint64_t> blacklistHits{0};
    std::array<std::atomic<uint64_t>, 8> byVerdict{};
    std::array<std::atomic<uint64_t>, 32> byIndicator{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct SpamDetectorConfiguration {
    /// @brief Enable detector
    bool enabled = true;
    
    /// @brief Enable Bayesian filter
    bool enableBayesian = true;
    
    /// @brief Enable rule-based detection
    bool enableRules = true;
    
    /// @brief Enable RBL checking
    bool enableRBL = true;
    
    /// @brief Enable reputation tracking
    bool enableReputation = true;
    
    /// @brief Enable auto-learning
    bool enableAutoLearn = true;
    
    /// @brief Spam threshold (0-100)
    int spamThreshold = SpamConstants::DEFAULT_SPAM_THRESHOLD;
    
    /// @brief Auto-learn threshold (only learn if score > this or < inverse)
    int autoLearnThreshold = 90;
    
    /// @brief RBL timeout (ms)
    uint32_t rblTimeoutMs = 3000;
    
    /// @brief RBL providers
    std::vector<std::string> rblProviders;
    
    /// @brief Whitelist domains
    std::vector<std::string> whitelistDomains;
    
    /// @brief Blacklist domains
    std::vector<std::string> blacklistDomains;
    
    /// @brief Custom spam keywords
    std::vector<std::string> customKeywords;
    
    /// @brief Corpus file path
    std::string corpusPath;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using AnalysisCallback = std::function<void(const SpamAnalysisResult&)>;
using TrainingCallback = std::function<void(TrainingType, size_t count)>;
using RBLCallback = std::function<void(const std::string& ip, const RBLCheckResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// SPAM DETECTOR CLASS
// ============================================================================

/**
 * @class SpamDetector
 * @brief Enterprise spam detection engine
 */
class SpamDetector final {
public:
    [[nodiscard]] static SpamDetector& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    SpamDetector(const SpamDetector&) = delete;
    SpamDetector& operator=(const SpamDetector&) = delete;
    SpamDetector(SpamDetector&&) = delete;
    SpamDetector& operator=(SpamDetector&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const SpamDetectorConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    [[nodiscard]] bool UpdateConfiguration(const SpamDetectorConfiguration& config);
    [[nodiscard]] SpamDetectorConfiguration GetConfiguration() const;

    // ========================================================================
    // ANALYSIS
    // ========================================================================
    
    /// @brief Check if email is spam
    [[nodiscard]] bool IsSpam(const std::string& headers, const std::string& body);
    
    /// @brief Full spam analysis
    [[nodiscard]] SpamAnalysisResult Analyze(
        const std::string& subject,
        const std::string& body,
        const std::string& sender,
        const std::map<std::string, std::string>& headers = {});
    
    /// @brief Analyze with full email structure
    [[nodiscard]] SpamAnalysisResult AnalyzeEmail(
        const std::string& subject,
        const std::string& bodyText,
        const std::string& bodyHtml,
        const std::string& sender,
        const std::vector<std::string>& recipients,
        const std::map<std::string, std::string>& headers);
    
    /// @brief Get spam score (0-100)
    [[nodiscard]] int GetSpamScore(
        const std::string& headers,
        const std::string& body);
    
    /// @brief Check sender IP against RBLs
    [[nodiscard]] std::vector<RBLCheckResult> CheckRBL(const std::string& ipAddress);
    
    /// @brief Get sender reputation
    [[nodiscard]] SenderReputation GetSenderReputation(const std::string& sender);

    // ========================================================================
    // TRAINING
    // ========================================================================
    
    /// @brief Mark content as spam (training)
    void MarkAsSpam(const std::string& content);
    
    /// @brief Mark content as ham (training)
    void MarkAsHam(const std::string& content);
    
    /// @brief Batch train spam
    [[nodiscard]] size_t TrainSpamBatch(const std::vector<std::string>& samples);
    
    /// @brief Batch train ham
    [[nodiscard]] size_t TrainHamBatch(const std::vector<std::string>& samples);
    
    /// @brief Report false positive (was marked spam but is ham)
    void ReportFalsePositive(const std::string& content);
    
    /// @brief Report false negative (was marked ham but is spam)
    void ReportFalseNegative(const std::string& content);
    
    /// @brief Load corpus from file
    [[nodiscard]] bool LoadCorpus(const std::string& filePath);
    
    /// @brief Save corpus to file
    [[nodiscard]] bool SaveCorpus(const std::string& filePath);
    
    /// @brief Get corpus statistics
    [[nodiscard]] std::pair<size_t, size_t> GetCorpusSize() const;  // spam, ham counts

    // ========================================================================
    // WHITELIST/BLACKLIST
    // ========================================================================
    
    [[nodiscard]] bool AddToWhitelist(const std::string& emailOrDomain);
    [[nodiscard]] bool RemoveFromWhitelist(const std::string& emailOrDomain);
    [[nodiscard]] bool IsWhitelisted(const std::string& sender) const;
    
    [[nodiscard]] bool AddToBlacklist(const std::string& emailOrDomain);
    [[nodiscard]] bool RemoveFromBlacklist(const std::string& emailOrDomain);
    [[nodiscard]] bool IsBlacklisted(const std::string& sender) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterAnalysisCallback(AnalysisCallback callback);
    void RegisterTrainingCallback(TrainingCallback callback);
    void RegisterRBLCallback(RBLCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] SpamStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    SpamDetector();
    ~SpamDetector();
    
    std::unique_ptr<SpamDetectorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetSpamVerdictName(SpamVerdict verdict) noexcept;
[[nodiscard]] std::string_view GetSpamIndicatorName(SpamIndicator indicator) noexcept;
[[nodiscard]] std::string_view GetRBLResultName(RBLResult result) noexcept;

/// @brief Tokenize text for Bayesian analysis
[[nodiscard]] std::vector<std::string> TokenizeForBayes(const std::string& text);

/// @brief Calculate Bayesian probability
[[nodiscard]] double CalculateBayesProbability(
    const std::vector<std::pair<std::string, double>>& tokenProbabilities);

/// @brief Detect hidden text in HTML
[[nodiscard]] bool DetectHiddenText(const std::string& html);

/// @brief Calculate keyword density
[[nodiscard]] double CalculateKeywordDensity(
    const std::string& text,
    const std::vector<std::string>& keywords);

}  // namespace Email
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_SPAM_CHECK(headers, body) \
    ::ShadowStrike::Email::SpamDetector::Instance().IsSpam(headers, body)

#define SS_SPAM_ANALYZE(subject, body, sender) \
    ::ShadowStrike::Email::SpamDetector::Instance().Analyze(subject, body, sender)

#define SS_SPAM_TRAIN_SPAM(content) \
    ::ShadowStrike::Email::SpamDetector::Instance().MarkAsSpam(content)

#define SS_SPAM_TRAIN_HAM(content) \
    ::ShadowStrike::Email::SpamDetector::Instance().MarkAsHam(content)