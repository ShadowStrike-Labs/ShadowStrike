/**
 * ============================================================================
 * ShadowStrike Banking Protection - TRANSACTION MONITOR
 * ============================================================================
 *
 * @file TransactionMonitor.cpp
 * @brief Implementation of enterprise-grade real-time transaction monitoring
 *        for detecting and preventing Man-in-the-Browser (MitB) attacks.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "TransactionMonitor.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <deque>
#include <shared_mutex>

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"TransactionMonitor";
}

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> TransactionMonitor::s_instanceCreated{false};

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetRiskLevelName(TransactionRiskLevel level) noexcept {
    switch (level) {
        case TransactionRiskLevel::Safe:     return "Safe";
        case TransactionRiskLevel::Low:      return "Low";
        case TransactionRiskLevel::Medium:   return "Medium";
        case TransactionRiskLevel::High:     return "High";
        case TransactionRiskLevel::Critical: return "Critical";
        default:                             return "Unknown";
    }
}

[[nodiscard]] std::string_view GetAttackVectorName(AttackVector vector) noexcept {
    switch (vector) {
        case AttackVector::None:                 return "None";
        case AttackVector::DOMManipulation:      return "DOMManipulation";
        case AttackVector::JavaScriptInjection:  return "JavaScriptInjection";
        case AttackVector::FormFieldTampering:   return "FormFieldTampering";
        case AttackVector::HiddenFieldInjection: return "HiddenFieldInjection";
        case AttackVector::OverlayAttack:        return "OverlayAttack";
        case AttackVector::APIHooking:           return "APIHooking";
        case AttackVector::ExtensionAbuse:       return "ExtensionAbuse";
        case AttackVector::NetworkInterception:  return "NetworkInterception";
        case AttackVector::DNSSpoofing:          return "DNSSpoofing";
        case AttackVector::SessionHijacking:     return "SessionHijacking";
        case AttackVector::AccountSwapping:      return "AccountSwapping";
        case AttackVector::AmountModification:   return "AmountModification";
        case AttackVector::HiddenTransfer:       return "HiddenTransfer";
        case AttackVector::ClipboardSwap:        return "ClipboardSwap";
        case AttackVector::PhishingRedirect:     return "PhishingRedirect";
        case AttackVector::WebInject:            return "WebInject";
        default:                                 return "Unknown";
    }
}

[[nodiscard]] std::string_view GetTransactionTypeName(TransactionType type) noexcept {
    switch (type) {
        case TransactionType::Unknown:           return "Unknown";
        case TransactionType::InternalTransfer:  return "InternalTransfer";
        case TransactionType::DomesticWire:      return "DomesticWire";
        case TransactionType::InternationalWire: return "InternationalWire";
        case TransactionType::BillPayment:       return "BillPayment";
        case TransactionType::P2PTransfer:       return "P2PTransfer";
        case TransactionType::CardPayment:       return "CardPayment";
        case TransactionType::ACHTransfer:       return "ACHTransfer";
        case TransactionType::CryptoTransfer:    return "CryptoTransfer";
        default:                                 return "Unknown";
    }
}

[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::Valid:       return "Valid";
        case ValidationResult::Suspicious:  return "Suspicious";
        case ValidationResult::Blocked:     return "Blocked";
        case ValidationResult::UserConfirm: return "UserConfirm";
        case ValidationResult::OOBVerify:   return "OOBVerify";
        case ValidationResult::Timeout:     return "Timeout";
        case ValidationResult::Error:       return "Error";
        default:                            return "Unknown";
    }
}

[[nodiscard]] std::string_view GetDOMChangeTypeName(DOMChangeType type) noexcept {
    switch (type) {
        case DOMChangeType::Unknown:          return "Unknown";
        case DOMChangeType::ElementAdded:     return "ElementAdded";
        case DOMChangeType::ElementRemoved:   return "ElementRemoved";
        case DOMChangeType::AttributeChanged: return "AttributeChanged";
        case DOMChangeType::TextChanged:      return "TextChanged";
        case DOMChangeType::ValueChanged:     return "ValueChanged";
        case DOMChangeType::StyleChanged:     return "StyleChanged";
        case DOMChangeType::ScriptInjected:   return "ScriptInjected";
        case DOMChangeType::FormModified:     return "FormModified";
        default:                              return "Unknown";
    }
}

[[nodiscard]] std::string_view GetBeneficiaryTrustName(BeneficiaryTrust trust) noexcept {
    switch (trust) {
        case BeneficiaryTrust::Unknown:     return "Unknown";
        case BeneficiaryTrust::New:         return "New";
        case BeneficiaryTrust::Recent:      return "Recent";
        case BeneficiaryTrust::Trusted:     return "Trusted";
        case BeneficiaryTrust::Whitelisted: return "Whitelisted";
        default:                            return "Unknown";
    }
}

[[nodiscard]] std::string MaskAccountNumber(std::string_view account) {
    if (account.length() <= 4) {
        return std::string(account);
    }
    std::string masked(account.length(), '*');
    std::copy(account.end() - 4, account.end(), masked.end() - 4);
    return masked;
}

[[nodiscard]] Hash256 HashAccountNumber(std::string_view account) {
    // In a real implementation, use Utils::CryptoUtils
    // Here we use a stub implementation for demonstration
    Hash256 hash{};
    uint64_t h = 0xcbf29ce484222325;
    for (char c : account) {
        h ^= c;
        h *= 0x100000001b3;
    }
    std::memcpy(hash.data(), &h, sizeof(h));
    return hash;
}

[[nodiscard]] bool ValidateIBAN(std::string_view iban) {
    // Basic length check for demonstration
    // Real implementation would implement MOD-97 algorithm
    if (iban.length() < 15 || iban.length() > 34) return false;
    return true;
}

[[nodiscard]] bool ValidateAccountNumber(std::string_view account) {
    // Basic check - only digits and dashes
    return std::all_of(account.begin(), account.end(), [](char c) {
        return std::isdigit(c) || c == '-' || c == ' ';
    });
}

// ============================================================================
// STRUCT JSON SERIALIZATION
// ============================================================================

std::string TransactionContext::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"transactionId\":\"" << Utils::StringUtils::EscapeJson(transactionId) << "\","
        << "\"type\":\"" << GetTransactionTypeName(transactionType) << "\","
        << "\"sourceMasked\":\"" << Utils::StringUtils::EscapeJson(sourceAccountMasked) << "\","
        << "\"beneficiaryMasked\":\"" << Utils::StringUtils::EscapeJson(MaskAccountNumber(beneficiaryAccount)) << "\","
        << "\"amount\":" << std::fixed << std::setprecision(2) << amount << ","
        << "\"currency\":\"" << Utils::StringUtils::EscapeJson(currency) << "\","
        << "\"domain\":\"" << Utils::StringUtils::EscapeJson(domain) << "\","
        << "\"timestamp\":" << std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count()
        << "}";
    return oss.str();
}

std::string UIDisplayValues::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"account\":\"" << Utils::StringUtils::EscapeJson(displayedAccount) << "\","
        << "\"name\":\"" << Utils::StringUtils::EscapeJson(displayedName) << "\","
        << "\"amount\":\"" << Utils::StringUtils::EscapeJson(displayedAmount) << "\","
        << "\"currency\":\"" << Utils::StringUtils::EscapeJson(displayedCurrency) << "\""
        << "}";
    return oss.str();
}

std::string NetworkPayloadValues::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"account\":\"" << Utils::StringUtils::EscapeJson(payloadAccount) << "\","
        << "\"name\":\"" << Utils::StringUtils::EscapeJson(payloadName) << "\","
        << "\"amount\":\"" << Utils::StringUtils::EscapeJson(payloadAmount) << "\","
        << "\"currency\":\"" << Utils::StringUtils::EscapeJson(payloadCurrency) << "\","
        << "\"url\":\"" << Utils::StringUtils::EscapeJson(requestUrl) << "\","
        << "\"method\":\"" << Utils::StringUtils::EscapeJson(httpMethod) << "\""
        << "}";
    return oss.str();
}

std::string DOMChangeEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"type\":\"" << GetDOMChangeTypeName(changeType) << "\","
        << "\"tag\":\"" << Utils::StringUtils::EscapeJson(tagName) << "\","
        << "\"id\":\"" << Utils::StringUtils::EscapeJson(elementId) << "\","
        << "\"xpath\":\"" << Utils::StringUtils::EscapeJson(xpath) << "\","
        << "\"suspicious\":" << (isSuspicious ? "true" : "false")
        << "}";
    return oss.str();
}

std::string AnomalyDetectionResult::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"isAnomalous\":" << (isAnomalous ? "true" : "false") << ","
        << "\"riskLevel\":\"" << GetRiskLevelName(riskLevel) << "\","
        << "\"validationResult\":\"" << GetValidationResultName(validationResult) << "\","
        << "\"primaryVector\":\"" << GetAttackVectorName(primaryVector) << "\","
        << "\"confidence\":" << confidenceScore << ","
        << "\"riskScore\":" << riskScore << ","
        << "\"description\":\"" << Utils::StringUtils::EscapeJson(description) << "\""
        << "}";
    return oss.str();
}

std::string BeneficiaryProfile::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"account\":\"" << Utils::StringUtils::EscapeJson(accountMasked) << "\","
        << "\"name\":\"" << Utils::StringUtils::EscapeJson(name) << "\","
        << "\"trust\":\"" << GetBeneficiaryTrustName(trustLevel) << "\","
        << "\"txCount\":" << transactionCount << ","
        << "\"totalAmount\":" << std::fixed << std::setprecision(2) << totalAmount
        << "}";
    return oss.str();
}

void TransactionMonitorStatistics::Reset() noexcept {
    totalTransactionsMonitored = 0;
    transactionsValidated = 0;
    anomaliesDetected = 0;
    transactionsBlocked = 0;
    userConfirmations = 0;
    domManipulationsDetected = 0;
    uiPayloadMismatches = 0;
    newBeneficiaries = 0;
    totalAmountMonitoredCents = 0;
    startTime = Clock::now();

    for (auto& val : byAttackVector) val = 0;
    for (auto& val : byRiskLevel) val = 0;
}

std::string TransactionMonitorStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalMonitored\":" << totalTransactionsMonitored.load() << ","
        << "\"validated\":" << transactionsValidated.load() << ","
        << "\"anomalies\":" << anomaliesDetected.load() << ","
        << "\"blocked\":" << transactionsBlocked.load() << ","
        << "\"domManipulations\":" << domManipulationsDetected.load() << ","
        << "\"uiPayloadMismatches\":" << uiPayloadMismatches.load() << ","
        << "\"totalAmount\":" << (totalAmountMonitoredCents.load() / 100.0)
        << "}";
    return oss.str();
}

bool TransactionMonitorConfiguration::IsValid() const noexcept {
    return highValueThreshold >= 0.0 &&
           maxTransactionsPerHour > 0 &&
           anomalyConfidenceThreshold >= 0.0 &&
           anomalyConfidenceThreshold <= 1.0;
}

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class TransactionMonitorImpl {
public:
    TransactionMonitorImpl() noexcept
        : m_status(ModuleStatus::Uninitialized)
        , m_initialized(false)
        , m_running(false)
    {
        SS_LOG_INFO(LOG_CATEGORY, L"Creating TransactionMonitor implementation");
    }

    ~TransactionMonitorImpl() noexcept {
        Shutdown();
    }

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const TransactionMonitorConfiguration& config) noexcept {
        std::unique_lock lock(m_mutex);

        if (m_initialized) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already initialized");
            return true;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Initializing TransactionMonitor");
        m_status = ModuleStatus::Initializing;

        try {
            if (!config.IsValid()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
                m_status = ModuleStatus::Error;
                return false;
            }

            m_config = config;

            // Load protected domains
            for (const auto& domain : config.protectedDomains) {
                m_protectedDomains.insert(domain);
            }

            // Load whitelisted beneficiaries
            for (const auto& account : config.whitelistedBeneficiaries) {
                // In production: Hash account number before storing
                // Here we simulate loading
            }

            // Initialize anomaly rules engine
            // ...

            m_initialized = true;
            m_status = ModuleStatus::Stopped; // Ready but not running
            m_stats.startTime = Clock::now();

            SS_LOG_INFO(LOG_CATEGORY, L"TransactionMonitor initialized successfully");
            return true;

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", ex.what());
            m_status = ModuleStatus::Error;
            return false;
        }
    }

    void Shutdown() noexcept {
        Stop();

        std::unique_lock lock(m_mutex);
        if (!m_initialized) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Shutting down TransactionMonitor");
        m_status = ModuleStatus::Stopping;

        // Clear data structures
        m_protectedDomains.clear();
        m_beneficiaryCache.clear();
        m_transactionHistory.clear();
        m_recentAnomalies.clear();

        m_initialized = false;
        m_status = ModuleStatus::Stopped;
    }

    [[nodiscard]] bool Start() noexcept {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) return false;
        if (m_running) return true;

        SS_LOG_INFO(LOG_CATEGORY, L"Starting TransactionMonitor");
        m_running = true;
        m_status = ModuleStatus::Running;
        return true;
    }

    [[nodiscard]] bool Stop() noexcept {
        std::unique_lock lock(m_mutex);
        if (!m_initialized) return false;
        if (!m_running) return true;

        SS_LOG_INFO(LOG_CATEGORY, L"Stopping TransactionMonitor");
        m_running = false;
        m_status = ModuleStatus::Stopped;
        return true;
    }

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    bool UpdateConfiguration(const TransactionMonitorConfiguration& config) noexcept {
        if (!config.IsValid()) return false;
        std::unique_lock lock(m_mutex);
        m_config = config;
        return true;
    }

    TransactionMonitorConfiguration GetConfiguration() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // VALIDATION
    // ========================================================================

    [[nodiscard]] AnomalyDetectionResult ValidateTransaction(const TransactionContext& context) {
        if (!m_running) return {};

        AnomalyDetectionResult result;
        result.analysisTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        m_stats.totalTransactionsMonitored++;
        uint64_t amountCents = static_cast<uint64_t>(context.amount * 100);
        m_stats.totalAmountMonitoredCents += amountCents;

        try {
            // 1. Context Validation
            if (m_config.enableNetworkValidation) {
                // Check if domain is protected banking domain
                if (!IsProtectedDomain(context.domain)) {
                    // Log but proceed if configured
                }
            }

            // 2. Beneficiary Analysis
            if (m_config.enableBeneficiaryTracking) {
                Hash256 accountHash = HashAccountNumber(context.beneficiaryAccount);
                if (!IsBeneficiaryKnown(accountHash)) {
                    result.isNewBeneficiary = true;
                    m_stats.newBeneficiaries++;

                    if (m_config.requireNewBeneficiaryConfirmation) {
                        result.riskScore += 40.0;
                        result.findings.push_back("New beneficiary detected");
                    }
                } else {
                    // Analyze historical pattern
                    auto profile = GetBeneficiaryProfile(accountHash);
                    if (profile) {
                        // Check if amount is anomalous for this beneficiary
                        if (context.amount > profile->averageAmount * 3.0 && context.amount > 1000.0) {
                            result.isAmountAnomaly = true;
                            result.riskScore += 30.0;
                            result.findings.push_back("Unusual amount for beneficiary");
                        }
                    }
                }
            }

            // 3. Velocity Analysis
            if (m_config.enableVelocityAnalysis) {
                if (!CheckVelocity(context)) {
                    result.isVelocityAnomaly = true;
                    result.riskScore += 50.0;
                    result.findings.push_back("Transaction velocity limit exceeded");
                }
            }

            // 4. Amount Analysis
            if (context.amount >= m_config.highValueThreshold) {
                result.isAmountAnomaly = true;
                result.riskScore += 20.0;
                result.findings.push_back("High value transaction");
            }

            // Calculate final risk and decision
            CalculateRiskLevel(result);

            // Update stats
            if (result.isAnomalous) {
                m_stats.anomaliesDetected++;
                std::unique_lock lock(m_historyMutex);
                m_recentAnomalies.push_back(result);
                if (m_recentAnomalies.size() > 100) m_recentAnomalies.pop_front();
            }

            // Invoke callbacks
            if (result.isAnomalous && m_anomalyCallback) {
                m_anomalyCallback(result, context);
            }

            // Store history
            {
                std::unique_lock lock(m_historyMutex);
                m_transactionHistory.push_back(context);
                if (m_transactionHistory.size() > TransactionMonitorConstants::MAX_TRANSACTION_HISTORY) {
                    m_transactionHistory.pop_front();
                }
            }

            // Update beneficiary profile
            UpdateBeneficiaryProfile(context);

        } catch (const std::exception& ex) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Validation error: %hs", ex.what());
            result.validationResult = ValidationResult::Error;
        }

        result.analysisDuration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        m_stats.transactionsValidated++;
        return result;
    }

    [[nodiscard]] bool VerifyUIPayloadMatch(
        const UIDisplayValues& uiValues,
        const NetworkPayloadValues& payloadValues) {

        bool mismatch = false;

        // Verify account
        if (uiValues.displayedAccount != payloadValues.payloadAccount) {
            // Allow for masking differences (e.g. ****1234 vs 12345678901234)
            if (!VerifyAccountMatch(uiValues.displayedAccount, payloadValues.payloadAccount)) {
                mismatch = true;
                SS_LOG_WARN(LOG_CATEGORY, L"UI/Payload Account Mismatch: UI='%hs', Payload='%hs'",
                    uiValues.displayedAccount.c_str(), payloadValues.payloadAccount.c_str());
            }
        }

        // Verify amount
        if (uiValues.displayedAmount != payloadValues.payloadAmount) {
            // Need robust number parsing here to handle formats (1,000.00 vs 1000.00)
            if (!VerifyAmountMatch(uiValues.displayedAmount, payloadValues.payloadAmount)) {
                mismatch = true;
                SS_LOG_WARN(LOG_CATEGORY, L"UI/Payload Amount Mismatch: UI='%hs', Payload='%hs'",
                    uiValues.displayedAmount.c_str(), payloadValues.payloadAmount.c_str());
            }
        }

        if (mismatch) {
            m_stats.uiPayloadMismatches++;
        }

        return !mismatch;
    }

    // ========================================================================
    // DOMAIN MANAGEMENT
    // ========================================================================

    void AddProtectedDomain(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        m_protectedDomains.insert(domain);
    }

    void RemoveProtectedDomain(const std::string& domain) {
        std::unique_lock lock(m_mutex);
        m_protectedDomains.erase(domain);
    }

    bool IsProtectedDomain(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        return m_protectedDomains.count(domain) > 0;
    }

    // ========================================================================
    // HELPERS
    // ========================================================================

    bool IsBeneficiaryKnown(const Hash256& accountHash) const {
        std::shared_lock lock(m_profileMutex);
        return m_beneficiaryCache.count(accountHash) > 0;
    }

    std::optional<BeneficiaryProfile> GetBeneficiaryProfile(const Hash256& accountHash) const {
        std::shared_lock lock(m_profileMutex);
        auto it = m_beneficiaryCache.find(accountHash);
        if (it != m_beneficiaryCache.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    void UpdateBeneficiaryProfile(const TransactionContext& ctx) {
        // Only update if transaction was successful/valid (logic simplification)
        Hash256 hash = HashAccountNumber(ctx.beneficiaryAccount);

        std::unique_lock lock(m_profileMutex);
        auto& profile = m_beneficiaryCache[hash];

        if (profile.transactionCount == 0) {
            profile.firstTransaction = ctx.timestamp;
            profile.name = ctx.beneficiaryName;
            profile.accountMasked = MaskAccountNumber(ctx.beneficiaryAccount);
            profile.trustLevel = BeneficiaryTrust::New;
        } else {
            if (profile.trustLevel == BeneficiaryTrust::New && profile.transactionCount > 3) {
                profile.trustLevel = BeneficiaryTrust::Recent;
            } else if (profile.trustLevel == BeneficiaryTrust::Recent && profile.transactionCount > 10) {
                profile.trustLevel = BeneficiaryTrust::Trusted;
            }
        }

        profile.lastTransaction = ctx.timestamp;
        profile.transactionCount++;
        profile.totalAmount += ctx.amount;
        profile.averageAmount = profile.totalAmount / profile.transactionCount;
    }

    bool CheckVelocity(const TransactionContext& ctx) {
        // Simple sliding window check
        std::shared_lock lock(m_historyMutex);

        uint32_t count = 0;
        auto cutoff = ctx.timestamp - std::chrono::hours(1);

        // Reverse iterate for efficiency
        for (auto it = m_transactionHistory.rbegin(); it != m_transactionHistory.rend(); ++it) {
            if (it->timestamp < cutoff) break;

            // Check if same source account
            if (it->sourceAccount == ctx.sourceAccount) {
                count++;
            }
        }

        return count < m_config.maxTransactionsPerHour;
    }

    bool VerifyAccountMatch(const std::string& ui, const std::string& payload) {
        // Strip non-digits
        std::string uiClean, payloadClean;
        std::copy_if(ui.begin(), ui.end(), std::back_inserter(uiClean), ::isdigit);
        std::copy_if(payload.begin(), payload.end(), std::back_inserter(payloadClean), ::isdigit);

        if (uiClean == payloadClean) return true;

        // Check if UI is masked version of payload
        // This is a naive check; enterprise grade would need more complex matching logic
        if (uiClean.length() < payloadClean.length() && !uiClean.empty()) {
            return payloadClean.ends_with(uiClean);
        }

        return false;
    }

    bool VerifyAmountMatch(const std::string& ui, const std::string& payload) {
        // Simple float comparison with tolerance
        try {
            double dUI = std::stod(ui); // Note: locale dependent, needs robust parsing
            double dPayload = std::stod(payload);
            return std::abs(dUI - dPayload) < 0.01;
        } catch (...) {
            return false;
        }
    }

    void CalculateRiskLevel(AnomalyDetectionResult& result) {
        if (result.riskScore >= 80.0) {
            result.riskLevel = TransactionRiskLevel::Critical;
            result.validationResult = ValidationResult::Blocked;
            result.isAnomalous = true;
        } else if (result.riskScore >= 60.0) {
            result.riskLevel = TransactionRiskLevel::High;
            result.validationResult = ValidationResult::OOBVerify;
            result.isAnomalous = true;
        } else if (result.riskScore >= 40.0) {
            result.riskLevel = TransactionRiskLevel::Medium;
            result.validationResult = ValidationResult::UserConfirm;
            result.isAnomalous = true;
        } else if (result.riskScore > 0.0) {
            result.riskLevel = TransactionRiskLevel::Low;
            result.validationResult = ValidationResult::Valid;
            result.isAnomalous = false; // Just low risk warning
        } else {
            result.riskLevel = TransactionRiskLevel::Safe;
            result.validationResult = ValidationResult::Valid;
            result.isAnomalous = false;
        }
    }

    // Callbacks
    AnomalyCallback m_anomalyCallback;
    ValidationCallback m_validationCallback;
    UserConfirmationCallback m_userConfirmationCallback;
    ErrorCallback m_errorCallback;

    // Member variables
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_historyMutex;
    mutable std::shared_mutex m_profileMutex;

    std::atomic<ModuleStatus> m_status;
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_running;

    TransactionMonitorConfiguration m_config;
    TransactionMonitorStatistics m_stats;

    // Data structures
    std::unordered_set<std::string> m_protectedDomains;
    std::deque<TransactionContext> m_transactionHistory;
    std::deque<AnomalyDetectionResult> m_recentAnomalies;
    std::map<Hash256, BeneficiaryProfile> m_beneficiaryCache;
};

// ============================================================================
// PUBLIC FACADE IMPLEMENTATION
// ============================================================================

TransactionMonitor& TransactionMonitor::Instance() noexcept {
    static TransactionMonitor instance;
    return instance;
}

bool TransactionMonitor::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

TransactionMonitor::TransactionMonitor()
    : m_impl(std::make_unique<TransactionMonitorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

TransactionMonitor::~TransactionMonitor() = default;

bool TransactionMonitor::Initialize(const TransactionMonitorConfiguration& config) {
    return m_impl->Initialize(config);
}

void TransactionMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool TransactionMonitor::IsInitialized() const noexcept {
    return m_impl->m_initialized;
}

ModuleStatus TransactionMonitor::GetStatus() const noexcept {
    return m_impl->m_status;
}

bool TransactionMonitor::IsRunning() const noexcept {
    return m_impl->m_running;
}

bool TransactionMonitor::Start() {
    return m_impl->Start();
}

bool TransactionMonitor::Stop() {
    return m_impl->Stop();
}

void TransactionMonitor::Pause() {
    // Basic implementation - could be enhanced in PIMPL
    if (m_impl->m_running) {
        m_impl->m_running = false;
        m_impl->m_status = ModuleStatus::Paused;
    }
}

void TransactionMonitor::Resume() {
    if (!m_impl->m_running && m_impl->m_initialized) {
        m_impl->m_running = true;
        m_impl->m_status = ModuleStatus::Running;
    }
}

bool TransactionMonitor::UpdateConfiguration(const TransactionMonitorConfiguration& config) {
    return m_impl->UpdateConfiguration(config);
}

TransactionMonitorConfiguration TransactionMonitor::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

AnomalyDetectionResult TransactionMonitor::ValidateTransaction(const TransactionContext& context) {
    return m_impl->ValidateTransaction(context);
}

AnomalyDetectionResult TransactionMonitor::ValidateTransactionWithUI(
    const TransactionContext& context,
    const UIDisplayValues& uiValues) {

    // Create payload values from context for comparison
    NetworkPayloadValues payload;
    payload.payloadAccount = context.beneficiaryAccount;
    payload.payloadAmount = std::to_string(context.amount); // Simple conversion

    return ValidateTransactionFull(context, uiValues, payload);
}

AnomalyDetectionResult TransactionMonitor::ValidateTransactionFull(
    const TransactionContext& context,
    const UIDisplayValues& uiValues,
    const NetworkPayloadValues& payloadValues) {

    auto result = m_impl->ValidateTransaction(context);

    if (!m_impl->VerifyUIPayloadMatch(uiValues, payloadValues)) {
        result.uiPayloadMatch = false;
        result.detectedVectors.push_back(AttackVector::AmountModification); // Assumption
        result.riskScore += 100.0; // Critical mismatch
        result.findings.push_back("UI vs Payload mismatch detected");
        m_impl->CalculateRiskLevel(result);
    }

    return result;
}

bool TransactionMonitor::QuickValidate(const TransactionContext& context) {
    auto result = ValidateTransaction(context);
    return !result.isAnomalous;
}

bool TransactionMonitor::VerifyUIPayloadMatch(
    const UIDisplayValues& uiValues,
    const NetworkPayloadValues& payloadValues) {
    return m_impl->VerifyUIPayloadMatch(uiValues, payloadValues);
}

bool TransactionMonitor::VerifyAccountMatch(const std::string& uiAccount, const std::string& payloadAccount) {
    return m_impl->VerifyAccountMatch(uiAccount, payloadAccount);
}

bool TransactionMonitor::VerifyAmountMatch(const std::string& uiAmount, const std::string& payloadAmount) {
    return m_impl->VerifyAmountMatch(uiAmount, payloadAmount);
}

bool TransactionMonitor::CheckVelocity(const TransactionContext& context) {
    return m_impl->CheckVelocity(context);
}

void TransactionMonitor::AddProtectedDomain(const std::string& domain) {
    m_impl->AddProtectedDomain(domain);
}

void TransactionMonitor::RemoveProtectedDomain(const std::string& domain) {
    m_impl->RemoveProtectedDomain(domain);
}

bool TransactionMonitor::IsProtectedDomain(const std::string& domain) const {
    return m_impl->IsProtectedDomain(domain);
}

void TransactionMonitor::RegisterAnomalyCallback(AnomalyCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_anomalyCallback = std::move(callback);
}

TransactionMonitorStatistics TransactionMonitor::GetStatistics() const {
    return m_impl->m_stats;
}

void TransactionMonitor::ResetStatistics() {
    m_impl->m_stats.Reset();
}

bool TransactionMonitor::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running self-test");

    // 1. Test account validation
    if (!ValidateAccountNumber("1234567890") || ValidateAccountNumber("123abc456")) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Account number validation failed");
        return false;
    }

    // 2. Test masking
    if (MaskAccountNumber("1234567890") != "******7890") {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Masking failed");
        return false;
    }

    // 3. Test singleton access
    if (!HasInstance()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Instance check failed");
        return false;
    }

    SS_LOG_INFO(LOG_CATEGORY, L"Self-test passed");
    return true;
}

std::string TransactionMonitor::GetVersionString() noexcept {
    return "3.0.0";
}

// Stub implementations for methods not fully implemented in this iteration
bool TransactionMonitor::AnalyzeDOMChanges(const std::vector<DOMChangeEvent>&) { return true; }
bool TransactionMonitor::AnalyzeDOMDiff(const std::string&) { return true; }
bool TransactionMonitor::CheckDOMIntegrity(const std::string&) { return true; }
void TransactionMonitor::ReportDOMChange(const DOMChangeEvent&) {}
size_t TransactionMonitor::GetTransactionsInWindow(const std::string&, std::chrono::seconds) const { return 0; }
bool TransactionMonitor::IsBeneficiaryKnown(const std::string&) const { return false; }
BeneficiaryTrust TransactionMonitor::GetBeneficiaryTrust(const std::string&) const { return BeneficiaryTrust::Unknown; }
std::optional<BeneficiaryProfile> TransactionMonitor::GetBeneficiaryProfile(const std::string&) const { return std::nullopt; }
void TransactionMonitor::WhitelistBeneficiary(const std::string&, const std::string&) {}
void TransactionMonitor::RemoveBeneficiaryFromWhitelist(const std::string&) {}
bool TransactionMonitor::LoadBankingDomains(const std::filesystem::path&) { return true; }
void TransactionMonitor::RegisterValidationCallback(ValidationCallback) {}
void TransactionMonitor::RegisterUserConfirmationCallback(UserConfirmationCallback) {}
void TransactionMonitor::RegisterErrorCallback(ErrorCallback) {}
void TransactionMonitor::UnregisterCallbacks() {}
std::vector<AnomalyDetectionResult> TransactionMonitor::GetRecentAnomalies(size_t) const { return {}; }
std::vector<TransactionContext> TransactionMonitor::GetTransactionHistory(size_t) const { return {}; }

} // namespace Banking
} // namespace ShadowStrike
