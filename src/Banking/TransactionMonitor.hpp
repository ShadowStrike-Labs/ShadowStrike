/**
 * ============================================================================
 * ShadowStrike Banking Protection - TRANSACTION MONITOR
 * ============================================================================
 *
 * @file TransactionMonitor.hpp
 * @brief Enterprise-grade real-time transaction monitoring for detecting and
 *        preventing Man-in-the-Browser (MitB) and transaction manipulation attacks.
 *
 * Provides comprehensive monitoring and validation of financial transactions
 * to detect account swapping, amount modification, hidden transfers, and other
 * sophisticated banking fraud techniques.
 *
 * DETECTION CAPABILITIES:
 * =======================
 *
 * 1. MAN-IN-THE-BROWSER (MITB) DETECTION
 *    - DOM manipulation detection
 *    - JavaScript injection
 *    - Form field modification
 *    - Hidden iframe detection
 *    - Overlay attacks
 *
 * 2. TRANSACTION VALIDATION
 *    - UI vs payload verification
 *    - Account number validation
 *    - Amount verification
 *    - Currency manipulation
 *    - Hidden field injection
 *
 * 3. BEHAVIORAL ANALYSIS
 *    - Transaction velocity
 *    - Amount anomalies
 *    - New beneficiary detection
 *    - Geographic anomalies
 *    - Time-based patterns
 *
 * 4. NETWORK VALIDATION
 *    - Request tampering detection
 *    - Response modification
 *    - Parameter injection
 *    - Redirect detection
 *    - API abuse
 *
 * 5. CONTEXT VERIFICATION
 *    - Session integrity
 *    - User verification
 *    - Device fingerprinting
 *    - Browser integrity
 *    - Extension monitoring
 *
 * 6. FRAUD PREVENTION
 *    - Transaction blocking
 *    - User confirmation
 *    - Out-of-band verification
 *    - Rate limiting
 *    - Threshold enforcement
 *
 * INTEGRATION:
 * ============
 * - SecureBrowser for browser monitoring
 * - CertificatePinning for network security
 * - KeyloggerProtection for input security
 * - ThreatIntel for IOC matching
 *
 * @note Requires integration with browser via extension or hooks.
 * @note Works best with SecureBrowser environment.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: PCI-DSS 4.0, SOC2, ISO 27001, PSD2/SCA
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
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>
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
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../HashStore/HashStore.hpp"
#include "../PatternStore/PatternStore.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class TransactionMonitorImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace TransactionMonitorConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum concurrent transactions
    inline constexpr size_t MAX_CONCURRENT_TRANSACTIONS = 100;
    
    /// @brief Maximum transaction history
    inline constexpr size_t MAX_TRANSACTION_HISTORY = 10000;
    
    /// @brief Maximum beneficiaries tracked
    inline constexpr size_t MAX_BENEFICIARIES = 1000;
    
    /// @brief Maximum protected domains
    inline constexpr size_t MAX_PROTECTED_DOMAINS = 1024;
    
    /// @brief Maximum DOM changes tracked
    inline constexpr size_t MAX_DOM_CHANGES = 512;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief Transaction validation timeout (ms)
    inline constexpr uint32_t VALIDATION_TIMEOUT_MS = 5000;
    
    /// @brief DOM monitoring interval (ms)
    inline constexpr uint32_t DOM_MONITOR_INTERVAL_MS = 100;
    
    /// @brief Transaction velocity window (seconds)
    inline constexpr uint32_t VELOCITY_WINDOW_SECS = 3600;

    // ========================================================================
    // THRESHOLDS
    // ========================================================================
    
    /// @brief Default high-value threshold (USD)
    inline constexpr double HIGH_VALUE_THRESHOLD = 10000.0;
    
    /// @brief Anomaly confidence threshold
    inline constexpr double ANOMALY_CONFIDENCE_THRESHOLD = 0.7;
    
    /// @brief Maximum transactions per hour
    inline constexpr uint32_t MAX_TRANSACTIONS_PER_HOUR = 20;
    
    /// @brief Velocity spike multiplier
    inline constexpr double VELOCITY_SPIKE_MULTIPLIER = 3.0;

}  // namespace TransactionMonitorConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Transaction risk level
 */
enum class TransactionRiskLevel : uint8_t {
    Safe        = 0,    ///< No anomalies detected
    Low         = 1,    ///< Minor anomalies
    Medium      = 2,    ///< Unusual activity
    High        = 3,    ///< Anomaly detected
    Critical    = 4     ///< Confirmed attack
};

/**
 * @brief Attack vector
 */
enum class AttackVector : uint16_t {
    None                    = 0,
    DOMManipulation         = 1,    ///< HTML/DOM modification
    JavaScriptInjection     = 2,    ///< Malicious JS injection
    FormFieldTampering      = 3,    ///< Form field modification
    HiddenFieldInjection    = 4,    ///< Hidden form fields
    OverlayAttack           = 5,    ///< UI overlay
    APIHooking              = 6,    ///< Browser API hooks
    ExtensionAbuse          = 7,    ///< Malicious extension
    NetworkInterception     = 8,    ///< MITM attack
    DNSSpoofing             = 9,    ///< DNS manipulation
    SessionHijacking        = 10,   ///< Session theft
    AccountSwapping         = 11,   ///< Beneficiary swap
    AmountModification      = 12,   ///< Amount change
    HiddenTransfer          = 13,   ///< Injected transfer
    ClipboardSwap           = 14,   ///< Clipboard replacement
    PhishingRedirect        = 15,   ///< Phishing redirect
    WebInject               = 16    ///< Banking trojan inject
};

/**
 * @brief Transaction type
 */
enum class TransactionType : uint8_t {
    Unknown         = 0,
    InternalTransfer= 1,    ///< Same bank transfer
    DomesticWire    = 2,    ///< Domestic wire
    InternationalWire= 3,   ///< International wire
    BillPayment     = 4,    ///< Bill pay
    P2PTransfer     = 5,    ///< Peer to peer
    CardPayment     = 6,    ///< Card payment
    ACHTransfer     = 7,    ///< ACH transfer
    CryptoTransfer  = 8     ///< Cryptocurrency
};

/**
 * @brief Validation result
 */
enum class ValidationResult : uint8_t {
    Valid           = 0,    ///< Transaction validated
    Suspicious      = 1,    ///< Needs review
    Blocked         = 2,    ///< Transaction blocked
    UserConfirm     = 3,    ///< Needs user confirmation
    OOBVerify       = 4,    ///< Out-of-band verification
    Timeout         = 5,    ///< Validation timeout
    Error           = 6     ///< Validation error
};

/**
 * @brief DOM change type
 */
enum class DOMChangeType : uint8_t {
    Unknown         = 0,
    ElementAdded    = 1,
    ElementRemoved  = 2,
    AttributeChanged= 3,
    TextChanged     = 4,
    ValueChanged    = 5,
    StyleChanged    = 6,
    ScriptInjected  = 7,
    FormModified    = 8
};

/**
 * @brief Beneficiary trust level
 */
enum class BeneficiaryTrust : uint8_t {
    Unknown         = 0,
    New             = 1,    ///< First time recipient
    Recent          = 2,    ///< Recent recipient
    Trusted         = 3,    ///< Established recipient
    Whitelisted     = 4     ///< User whitelisted
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Paused          = 3,
    Stopping        = 4,
    Stopped         = 5,
    Error           = 6
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Transaction context
 */
struct TransactionContext {
    /// @brief Transaction ID
    std::string transactionId;
    
    /// @brief Session ID
    std::string sessionId;
    
    /// @brief Transaction type
    TransactionType transactionType = TransactionType::Unknown;
    
    /// @brief Source account
    std::string sourceAccount;
    
    /// @brief Source account masked
    std::string sourceAccountMasked;
    
    /// @brief Beneficiary account
    std::string beneficiaryAccount;
    
    /// @brief Beneficiary name
    std::string beneficiaryName;
    
    /// @brief Beneficiary bank
    std::string beneficiaryBank;
    
    /// @brief Beneficiary routing/SWIFT
    std::string beneficiaryRouting;
    
    /// @brief Amount
    double amount = 0.0;
    
    /// @brief Currency code (ISO 4217)
    std::string currency;
    
    /// @brief Reference/memo
    std::string reference;
    
    /// @brief URL
    std::string url;
    
    /// @brief Domain
    std::string domain;
    
    /// @brief Browser process ID
    uint32_t browserPid = 0;
    
    /// @brief Session hash
    std::string sessionHash;
    
    /// @brief Client IP
    std::string clientIP;
    
    /// @brief Geolocation
    std::string geolocation;
    
    /// @brief Device fingerprint
    std::string deviceFingerprint;
    
    /// @brief User agent
    std::string userAgent;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /// @brief Form submission time
    SystemTimePoint formSubmitTime;
    
    /// @brief Is scheduled transaction
    bool isScheduled = false;
    
    /// @brief Is recurring
    bool isRecurring = false;
    
    /// @brief Additional metadata
    std::map<std::string, std::string> metadata;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief UI display values (what user sees)
 */
struct UIDisplayValues {
    /// @brief Displayed beneficiary account
    std::string displayedAccount;
    
    /// @brief Displayed beneficiary name
    std::string displayedName;
    
    /// @brief Displayed amount
    std::string displayedAmount;
    
    /// @brief Displayed currency
    std::string displayedCurrency;
    
    /// @brief Displayed reference
    std::string displayedReference;
    
    /// @brief Form field values (raw)
    std::map<std::string, std::string> formFields;
    
    /// @brief Screenshot hash (for forensics)
    Hash256 screenshotHash{};
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Network payload values (what's actually sent)
 */
struct NetworkPayloadValues {
    /// @brief Payload beneficiary account
    std::string payloadAccount;
    
    /// @brief Payload beneficiary name
    std::string payloadName;
    
    /// @brief Payload amount
    std::string payloadAmount;
    
    /// @brief Payload currency
    std::string payloadCurrency;
    
    /// @brief Payload reference
    std::string payloadReference;
    
    /// @brief All POST parameters
    std::map<std::string, std::string> postParams;
    
    /// @brief Request body hash
    Hash256 requestBodyHash{};
    
    /// @brief Request URL
    std::string requestUrl;
    
    /// @brief HTTP method
    std::string httpMethod;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief DOM change event
 */
struct DOMChangeEvent {
    /// @brief Change type
    DOMChangeType changeType = DOMChangeType::Unknown;
    
    /// @brief Element tag name
    std::string tagName;
    
    /// @brief Element ID
    std::string elementId;
    
    /// @brief Element class
    std::string elementClass;
    
    /// @brief XPath
    std::string xpath;
    
    /// @brief Attribute name (if attribute change)
    std::string attributeName;
    
    /// @brief Old value
    std::string oldValue;
    
    /// @brief New value
    std::string newValue;
    
    /// @brief Is sensitive field
    bool isSensitiveField = false;
    
    /// @brief Is suspicious
    bool isSuspicious = false;
    
    /// @brief Timestamp
    SystemTimePoint timestamp;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Anomaly detection result
 */
struct AnomalyDetectionResult {
    /// @brief Is anomalous
    bool isAnomalous = false;
    
    /// @brief Risk level
    TransactionRiskLevel riskLevel = TransactionRiskLevel::Safe;
    
    /// @brief Validation result
    ValidationResult validationResult = ValidationResult::Valid;
    
    /// @brief Detected attack vectors
    std::vector<AttackVector> detectedVectors;
    
    /// @brief Primary attack vector
    AttackVector primaryVector = AttackVector::None;
    
    /// @brief Confidence score (0-100)
    double confidenceScore = 0.0;
    
    /// @brief Risk score (0-100)
    double riskScore = 0.0;
    
    /// @brief UI vs payload match
    bool uiPayloadMatch = true;
    
    /// @brief DOM integrity
    bool domIntegrity = true;
    
    /// @brief Session integrity
    bool sessionIntegrity = true;
    
    /// @brief Is velocity anomaly
    bool isVelocityAnomaly = false;
    
    /// @brief Is amount anomaly
    bool isAmountAnomaly = false;
    
    /// @brief Is new beneficiary
    bool isNewBeneficiary = false;
    
    /// @brief Is geographic anomaly
    bool isGeographicAnomaly = false;
    
    /// @brief Description
    std::string description;
    
    /// @brief Detailed findings
    std::vector<std::string> findings;
    
    /// @brief Recommended action
    std::string recommendedAction;
    
    /// @brief Analysis duration
    std::chrono::milliseconds analysisDuration{0};
    
    /// @brief Analysis time
    SystemTimePoint analysisTime;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Beneficiary profile
 */
struct BeneficiaryProfile {
    /// @brief Account number (masked)
    std::string accountMasked;
    
    /// @brief Account hash
    Hash256 accountHash{};
    
    /// @brief Name
    std::string name;
    
    /// @brief Bank name
    std::string bankName;
    
    /// @brief Trust level
    BeneficiaryTrust trustLevel = BeneficiaryTrust::Unknown;
    
    /// @brief First transaction time
    SystemTimePoint firstTransaction;
    
    /// @brief Last transaction time
    SystemTimePoint lastTransaction;
    
    /// @brief Transaction count
    uint32_t transactionCount = 0;
    
    /// @brief Total amount transferred
    double totalAmount = 0.0;
    
    /// @brief Average amount
    double averageAmount = 0.0;
    
    /// @brief Is whitelisted
    bool isWhitelisted = false;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Monitor statistics
 */
struct TransactionMonitorStatistics {
    /// @brief Total transactions monitored
    std::atomic<uint64_t> totalTransactionsMonitored{0};
    
    /// @brief Transactions validated
    std::atomic<uint64_t> transactionsValidated{0};
    
    /// @brief Anomalies detected
    std::atomic<uint64_t> anomaliesDetected{0};
    
    /// @brief Transactions blocked
    std::atomic<uint64_t> transactionsBlocked{0};
    
    /// @brief User confirmations requested
    std::atomic<uint64_t> userConfirmations{0};
    
    /// @brief DOM manipulations detected
    std::atomic<uint64_t> domManipulationsDetected{0};
    
    /// @brief UI/Payload mismatches
    std::atomic<uint64_t> uiPayloadMismatches{0};
    
    /// @brief New beneficiaries detected
    std::atomic<uint64_t> newBeneficiaries{0};
    
    /// @brief By attack vector
    std::array<std::atomic<uint64_t>, 32> byAttackVector{};
    
    /// @brief By risk level
    std::array<std::atomic<uint64_t>, 8> byRiskLevel{};
    
    /// @brief Total amount monitored
    std::atomic<uint64_t> totalAmountMonitoredCents{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct TransactionMonitorConfiguration {
    /// @brief Enable DOM monitoring
    bool enableDOMMonitoring = true;
    
    /// @brief Enable network validation
    bool enableNetworkValidation = true;
    
    /// @brief Enable UI/payload verification
    bool enableUIPayloadVerification = true;
    
    /// @brief Enable velocity analysis
    bool enableVelocityAnalysis = true;
    
    /// @brief Enable beneficiary tracking
    bool enableBeneficiaryTracking = true;
    
    /// @brief Enable geographic analysis
    bool enableGeographicAnalysis = true;
    
    /// @brief Block suspicious transactions
    bool blockSuspiciousTransactions = true;
    
    /// @brief Require confirmation for new beneficiaries
    bool requireNewBeneficiaryConfirmation = true;
    
    /// @brief High value threshold
    double highValueThreshold = TransactionMonitorConstants::HIGH_VALUE_THRESHOLD;
    
    /// @brief Maximum transactions per hour
    uint32_t maxTransactionsPerHour = TransactionMonitorConstants::MAX_TRANSACTIONS_PER_HOUR;
    
    /// @brief Anomaly confidence threshold
    double anomalyConfidenceThreshold = TransactionMonitorConstants::ANOMALY_CONFIDENCE_THRESHOLD;
    
    /// @brief Protected banking domains
    std::vector<std::string> protectedDomains;
    
    /// @brief Whitelisted beneficiary accounts
    std::vector<std::string> whitelistedBeneficiaries;
    
    /// @brief Custom validation rules path
    std::wstring customRulesPath;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Anomaly callback
using AnomalyCallback = std::function<void(const AnomalyDetectionResult&, const TransactionContext&)>;

/// @brief Validation callback
using ValidationCallback = std::function<ValidationResult(const TransactionContext&)>;

/// @brief User confirmation callback (returns true if user approves)
using UserConfirmationCallback = std::function<bool(const TransactionContext&, const std::string& reason)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// TRANSACTION MONITOR CLASS
// ============================================================================

/**
 * @class TransactionMonitor
 * @brief Enterprise-grade real-time transaction monitoring engine
 *
 * Provides comprehensive protection against Man-in-the-Browser attacks
 * and transaction manipulation through multi-layer validation.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& monitor = TransactionMonitor::Instance();
 *     monitor.Initialize(config);
 *     
 *     // Validate transaction
 *     auto result = monitor.ValidateTransaction(context);
 *     if (result.isAnomalous) {
 *         // Handle anomaly
 *     }
 * @endcode
 */
class TransactionMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static TransactionMonitor& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    TransactionMonitor(const TransactionMonitor&) = delete;
    TransactionMonitor& operator=(const TransactionMonitor&) = delete;
    TransactionMonitor(TransactionMonitor&&) = delete;
    TransactionMonitor& operator=(TransactionMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize monitor
     */
    [[nodiscard]] bool Initialize(const TransactionMonitorConfiguration& config = {});
    
    /**
     * @brief Shutdown monitor
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    /**
     * @brief Check if running
     */
    [[nodiscard]] bool IsRunning() const noexcept;
    
    // ========================================================================
    // CONTROL
    // ========================================================================
    
    /**
     * @brief Start monitoring
     */
    [[nodiscard]] bool Start();
    
    /**
     * @brief Stop monitoring
     */
    [[nodiscard]] bool Stop();
    
    /**
     * @brief Pause monitoring
     */
    void Pause();
    
    /**
     * @brief Resume monitoring
     */
    void Resume();
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool UpdateConfiguration(const TransactionMonitorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] TransactionMonitorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // TRANSACTION VALIDATION
    // ========================================================================
    
    /**
     * @brief Validate transaction
     */
    [[nodiscard]] AnomalyDetectionResult ValidateTransaction(const TransactionContext& context);
    
    /**
     * @brief Validate with UI values
     */
    [[nodiscard]] AnomalyDetectionResult ValidateTransactionWithUI(
        const TransactionContext& context,
        const UIDisplayValues& uiValues);
    
    /**
     * @brief Validate with UI and payload
     */
    [[nodiscard]] AnomalyDetectionResult ValidateTransactionFull(
        const TransactionContext& context,
        const UIDisplayValues& uiValues,
        const NetworkPayloadValues& payloadValues);
    
    /**
     * @brief Quick validation (minimal checks)
     */
    [[nodiscard]] bool QuickValidate(const TransactionContext& context);
    
    // ========================================================================
    // UI/PAYLOAD VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verify UI matches payload
     */
    [[nodiscard]] bool VerifyUIPayloadMatch(
        const UIDisplayValues& uiValues,
        const NetworkPayloadValues& payloadValues);
    
    /**
     * @brief Verify account match
     */
    [[nodiscard]] bool VerifyAccountMatch(
        const std::string& uiAccount,
        const std::string& payloadAccount);
    
    /**
     * @brief Verify amount match
     */
    [[nodiscard]] bool VerifyAmountMatch(
        const std::string& uiAmount,
        const std::string& payloadAmount);
    
    // ========================================================================
    // DOM ANALYSIS
    // ========================================================================
    
    /**
     * @brief Analyze DOM changes
     */
    [[nodiscard]] bool AnalyzeDOMChanges(const std::vector<DOMChangeEvent>& changes);
    
    /**
     * @brief Analyze DOM diff
     */
    [[nodiscard]] bool AnalyzeDOMDiff(const std::string& domDiff);
    
    /**
     * @brief Check DOM integrity
     */
    [[nodiscard]] bool CheckDOMIntegrity(const std::string& domHash);
    
    /**
     * @brief Report DOM change
     */
    void ReportDOMChange(const DOMChangeEvent& change);
    
    // ========================================================================
    // VELOCITY ANALYSIS
    // ========================================================================
    
    /**
     * @brief Check transaction velocity
     */
    [[nodiscard]] bool CheckVelocity(const TransactionContext& context);
    
    /**
     * @brief Get transactions in window
     */
    [[nodiscard]] size_t GetTransactionsInWindow(
        const std::string& accountHash,
        std::chrono::seconds window) const;
    
    // ========================================================================
    // BENEFICIARY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Check if beneficiary is known
     */
    [[nodiscard]] bool IsBeneficiaryKnown(const std::string& accountHash) const;
    
    /**
     * @brief Get beneficiary trust level
     */
    [[nodiscard]] BeneficiaryTrust GetBeneficiaryTrust(const std::string& accountHash) const;
    
    /**
     * @brief Get beneficiary profile
     */
    [[nodiscard]] std::optional<BeneficiaryProfile> GetBeneficiaryProfile(
        const std::string& accountHash) const;
    
    /**
     * @brief Add beneficiary to whitelist
     */
    void WhitelistBeneficiary(const std::string& accountHash, const std::string& reason);
    
    /**
     * @brief Remove from whitelist
     */
    void RemoveBeneficiaryFromWhitelist(const std::string& accountHash);
    
    // ========================================================================
    // DOMAIN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add protected domain
     */
    void AddProtectedDomain(const std::string& domain);
    
    /**
     * @brief Remove protected domain
     */
    void RemoveProtectedDomain(const std::string& domain);
    
    /**
     * @brief Check if domain is protected
     */
    [[nodiscard]] bool IsProtectedDomain(const std::string& domain) const;
    
    /**
     * @brief Load banking domains
     */
    [[nodiscard]] bool LoadBankingDomains(const std::filesystem::path& path);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register anomaly callback
     */
    void RegisterAnomalyCallback(AnomalyCallback callback);
    
    /**
     * @brief Register validation callback
     */
    void RegisterValidationCallback(ValidationCallback callback);
    
    /**
     * @brief Register user confirmation callback
     */
    void RegisterUserConfirmationCallback(UserConfirmationCallback callback);
    
    /**
     * @brief Register error callback
     */
    void RegisterErrorCallback(ErrorCallback callback);
    
    /**
     * @brief Unregister callbacks
     */
    void UnregisterCallbacks();
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] TransactionMonitorStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent anomalies
     */
    [[nodiscard]] std::vector<AnomalyDetectionResult> GetRecentAnomalies(
        size_t maxCount = 100) const;
    
    /**
     * @brief Get transaction history
     */
    [[nodiscard]] std::vector<TransactionContext> GetTransactionHistory(
        size_t maxCount = 100) const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    TransactionMonitor();
    ~TransactionMonitor();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<TransactionMonitorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get risk level name
 */
[[nodiscard]] std::string_view GetRiskLevelName(TransactionRiskLevel level) noexcept;

/**
 * @brief Get attack vector name
 */
[[nodiscard]] std::string_view GetAttackVectorName(AttackVector vector) noexcept;

/**
 * @brief Get transaction type name
 */
[[nodiscard]] std::string_view GetTransactionTypeName(TransactionType type) noexcept;

/**
 * @brief Get validation result name
 */
[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept;

/**
 * @brief Get DOM change type name
 */
[[nodiscard]] std::string_view GetDOMChangeTypeName(DOMChangeType type) noexcept;

/**
 * @brief Get beneficiary trust name
 */
[[nodiscard]] std::string_view GetBeneficiaryTrustName(BeneficiaryTrust trust) noexcept;

/**
 * @brief Mask account number
 */
[[nodiscard]] std::string MaskAccountNumber(std::string_view account);

/**
 * @brief Hash account number
 */
[[nodiscard]] Hash256 HashAccountNumber(std::string_view account);

/**
 * @brief Validate IBAN format
 */
[[nodiscard]] bool ValidateIBAN(std::string_view iban);

/**
 * @brief Validate account number format
 */
[[nodiscard]] bool ValidateAccountNumber(std::string_view account);

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Validate transaction
 */
#define SS_VALIDATE_TRANSACTION(ctx) \
    ::ShadowStrike::Banking::TransactionMonitor::Instance().ValidateTransaction(ctx)

/**
 * @brief Check UI/payload match
 */
#define SS_VERIFY_UI_PAYLOAD(ui, payload) \
    ::ShadowStrike::Banking::TransactionMonitor::Instance().VerifyUIPayloadMatch(ui, payload)