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
#include <cctype>
#include <deque>
#include <fstream>
#include <shared_mutex>

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

namespace {
    constexpr const wchar_t* LOG_CATEGORY = L"TransactionMonitor";

    template <typename T>
    [[nodiscard]] T AtomicValueLoadRelaxed(const T& value) noexcept {
        return std::atomic_ref<T>(const_cast<T&>(value)).load(std::memory_order_relaxed);
    }

    template <typename T>
    void AtomicValueStoreRelaxed(T& target, const T& value) noexcept {
        std::atomic_ref<T>(target).store(value, std::memory_order_relaxed);
    }
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
    if (account.empty()) {
        return std::string{};
    }
    if (account.length() <= 4) {
        return std::string(account.length(), '*');
    }
    std::string masked(account.length(), '*');
    std::copy(account.end() - 4, account.end(), masked.end() - 4);
    return masked;
}

[[nodiscard]] Hash256 HashAccountNumber(std::string_view account) {
    Hash256 hash{};
    if (account.empty()) return hash;

    Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
    if (!hasher.Init()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"HashAccountNumber: SHA-256 hasher init failed");
        return hash;
    }
    if (!hasher.Update(account.data(), account.size())) {
        SS_LOG_ERROR(LOG_CATEGORY, L"HashAccountNumber: SHA-256 update failed");
        return hash;
    }
    std::vector<uint8_t> digest;
    if (!hasher.Final(digest)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"HashAccountNumber: SHA-256 finalize failed");
        return hash;
    }
    const size_t copyLen = (std::min)(digest.size(), hash.size());
    std::memcpy(hash.data(), digest.data(), copyLen);
    return hash;
}

[[nodiscard]] bool ValidateIBAN(std::string_view iban) {
    if (iban.length() < 15 || iban.length() > 34) return false;

    // Country code: 2 letters, check digits: 2 digits
    if (!std::isalpha(static_cast<unsigned char>(iban[0])) ||
        !std::isalpha(static_cast<unsigned char>(iban[1]))) return false;
    if (!std::isdigit(static_cast<unsigned char>(iban[2])) ||
        !std::isdigit(static_cast<unsigned char>(iban[3]))) return false;

    // Remaining characters must be alphanumeric
    for (size_t i = 4; i < iban.length(); ++i) {
        if (!std::isalnum(static_cast<unsigned char>(iban[i]))) return false;
    }

    // MOD-97 check per ISO 13616: move first 4 chars to end, convert letters
    // to digits (A=10..Z=35), compute remainder mod 97 — must equal 1.
    std::string numericStr;
    numericStr.reserve(iban.length() * 2);
    auto appendChar = [&](char c) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            numericStr += c;
        } else {
            int val = std::toupper(static_cast<unsigned char>(c)) - 'A' + 10;
            numericStr += std::to_string(val);
        }
    };
    for (size_t i = 4; i < iban.length(); ++i) appendChar(iban[i]);
    for (size_t i = 0; i < 4; ++i) appendChar(iban[i]);

    // Iterative MOD-97 to avoid big-integer arithmetic
    uint32_t remainder = 0;
    for (char c : numericStr) {
        remainder = (remainder * 10 + static_cast<uint32_t>(c - '0')) % 97;
    }
    return remainder == 1;
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
    AtomicValueStoreRelaxed(startTime, Clock::now());

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
                if (m_beneficiaryCache.size() >= TransactionMonitorConstants::MAX_BENEFICIARIES) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Beneficiary cache capacity reached during whitelist load");
                    break;
                }
                Hash256 hash = HashAccountNumber(account);
                auto& profile = m_beneficiaryCache[hash];
                profile.accountMasked = MaskAccountNumber(account);
                profile.accountHash = hash;
                profile.trustLevel = BeneficiaryTrust::Whitelisted;
                profile.isWhitelisted = true;
            }

            // Initialize anomaly rules engine
            // ...

            m_initialized = true;
            m_status = ModuleStatus::Stopped; // Ready but not running
            AtomicValueStoreRelaxed(m_stats.startTime, Clock::now());

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
        if (!m_running.load(std::memory_order_acquire)) return {};

        AnomalyDetectionResult result;
        result.analysisTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        m_stats.totalTransactionsMonitored++;

        // Snapshot config and callback under shared lock to avoid races
        TransactionMonitorConfiguration config;
        AnomalyCallback anomalyCallback;
        {
            std::shared_lock lock(m_mutex);
            config = m_config;
            anomalyCallback = m_anomalyCallback;
        }

        // Validate amount range before conversion to cents
        if (context.amount < 0.0 || context.amount > 1e15) {
            result.validationResult = ValidationResult::Error;
            result.findings.push_back("Invalid transaction amount: out of range");
            SS_LOG_WARN(LOG_CATEGORY, L"Transaction rejected: amount out of valid range");
            return result;
        }
        uint64_t amountCents = static_cast<uint64_t>(std::llround(context.amount * 100.0));
        m_stats.totalAmountMonitoredCents += amountCents;

        try {
            // 1. Context Validation
            if (config.enableNetworkValidation) {
                if (!IsProtectedDomain(context.domain)) {
                    result.riskScore += 10.0;
                    result.findings.push_back("Transaction on non-protected domain");
                }
            }

            // 2. Beneficiary Analysis
            if (config.enableBeneficiaryTracking) {
                Hash256 accountHash = HashAccountNumber(context.beneficiaryAccount);
                if (!IsBeneficiaryKnown(accountHash)) {
                    result.isNewBeneficiary = true;
                    m_stats.newBeneficiaries++;

                    if (config.requireNewBeneficiaryConfirmation) {
                        result.riskScore += 40.0;
                        result.findings.push_back("New beneficiary detected");
                    }
                } else {
                    auto profile = GetBeneficiaryProfile(accountHash);
                    if (profile) {
                        if (context.amount > profile->averageAmount * 3.0 && context.amount > 1000.0) {
                            result.isAmountAnomaly = true;
                            result.riskScore += 30.0;
                            result.findings.push_back("Unusual amount for beneficiary");
                        }
                    }
                }
            }

            // 3. Velocity Analysis
            if (config.enableVelocityAnalysis) {
                if (!CheckVelocityWithThreshold(context, config.maxTransactionsPerHour)) {
                    result.isVelocityAnomaly = true;
                    result.riskScore += 50.0;
                    result.findings.push_back("Transaction velocity limit exceeded");
                }
            }

            // 4. Amount Analysis
            if (context.amount >= config.highValueThreshold) {
                result.isAmountAnomaly = true;
                result.riskScore += 20.0;
                result.findings.push_back("High value transaction");
            }

            // Calculate final risk and decision
            CalculateRiskLevel(result);

            // Update attack vector stats
            if (result.isAnomalous) {
                m_stats.anomaliesDetected++;
                auto vecIdx = static_cast<size_t>(result.primaryVector);
                if (vecIdx < m_stats.byAttackVector.size()) {
                    m_stats.byAttackVector[vecIdx]++;
                }
                auto riskIdx = static_cast<size_t>(result.riskLevel);
                if (riskIdx < m_stats.byRiskLevel.size()) {
                    m_stats.byRiskLevel[riskIdx]++;
                }
                {
                    std::unique_lock lock(m_historyMutex);
                    m_recentAnomalies.push_back(result);
                    if (m_recentAnomalies.size() > 100) m_recentAnomalies.pop_front();
                }
            }

            if (result.validationResult == ValidationResult::Blocked) {
                m_stats.transactionsBlocked++;
            }
            if (result.validationResult == ValidationResult::UserConfirm) {
                m_stats.userConfirmations++;
            }

            // Invoke callback outside locks to prevent deadlock
            if (result.isAnomalous && anomalyCallback) {
                try {
                    anomalyCallback(result, context);
                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Anomaly callback threw: %hs", ex.what());
                }
            }

            // Store history
            {
                std::unique_lock lock(m_historyMutex);
                m_transactionHistory.push_back(context);
                if (m_transactionHistory.size() > TransactionMonitorConstants::MAX_TRANSACTION_HISTORY) {
                    m_transactionHistory.pop_front();
                }
            }

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
            if (!VerifyAccountMatch(uiValues.displayedAccount, payloadValues.payloadAccount)) {
                mismatch = true;
                SS_LOG_WARN(LOG_CATEGORY, L"UI/Payload Account Mismatch detected");
            }
        }

        // Verify amount
        if (uiValues.displayedAmount != payloadValues.payloadAmount) {
            if (!VerifyAmountMatch(uiValues.displayedAmount, payloadValues.payloadAmount)) {
                mismatch = true;
                SS_LOG_WARN(LOG_CATEGORY, L"UI/Payload Amount Mismatch detected");
            }
        }

        // Verify currency (critical: currency swap can redirect funds silently)
        if (!uiValues.displayedCurrency.empty() && !payloadValues.payloadCurrency.empty()) {
            if (uiValues.displayedCurrency != payloadValues.payloadCurrency) {
                mismatch = true;
                SS_LOG_WARN(LOG_CATEGORY, L"UI/Payload Currency Mismatch detected");
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
        uint32_t maxPerHour;
        {
            std::shared_lock configLock(m_mutex);
            maxPerHour = m_config.maxTransactionsPerHour;
        }
        return CheckVelocityWithThreshold(ctx, maxPerHour);
    }

    bool CheckVelocityWithThreshold(const TransactionContext& ctx, uint32_t maxPerHour) {
        std::shared_lock lock(m_historyMutex);

        uint32_t count = 0;
        auto cutoff = ctx.timestamp - std::chrono::hours(1);

        for (auto it = m_transactionHistory.rbegin(); it != m_transactionHistory.rend(); ++it) {
            if (it->timestamp < cutoff) break;

            if (it->sourceAccount == ctx.sourceAccount) {
                count++;
            }
        }

        return count < maxPerHour;
    }

    bool VerifyAccountMatch(const std::string& ui, const std::string& payload) {
        std::string uiClean, payloadClean;
        std::copy_if(ui.begin(), ui.end(), std::back_inserter(uiClean),
            [](unsigned char c) { return std::isdigit(c); });
        std::copy_if(payload.begin(), payload.end(), std::back_inserter(payloadClean),
            [](unsigned char c) { return std::isdigit(c); });

        if (uiClean == payloadClean) return true;

        // Check if UI is a masked version of the payload.
        // Only trust suffix match if the UI contains masking characters and
        // the number of masked positions is consistent with the hidden portion.
        bool uiIsMasked = (ui.find('*') != std::string::npos ||
                           ui.find('X') != std::string::npos ||
                           ui.find('x') != std::string::npos);

        if (uiIsMasked && !uiClean.empty() && !payloadClean.empty()) {
            if (payloadClean.length() >= uiClean.length() &&
                payloadClean.ends_with(uiClean)) {
                size_t maskCount = static_cast<size_t>(
                    std::count_if(ui.begin(), ui.end(), [](char c) {
                        return c == '*' || c == 'X' || c == 'x';
                    }));
                size_t hiddenDigits = payloadClean.length() - uiClean.length();
                // Mask count should approximate the hidden digit count
                if (hiddenDigits <= maskCount + 2 && maskCount <= hiddenDigits + 2) {
                    return true;
                }
            }
        }

        return false;
    }

    bool VerifyAmountMatch(const std::string& ui, const std::string& payload) {
        // Locale-independent amount normalization to integer cents.
        // Handles formats: "1,000.00", "1000.00", "1000", "1.000,50" (European).
        auto parseToCents = [](const std::string& s) -> std::optional<int64_t> {
            if (s.empty()) return std::nullopt;

            std::string digits;
            digits.reserve(s.size());
            size_t lastSepPos = std::string::npos;

            for (size_t i = 0; i < s.size(); ++i) {
                auto c = static_cast<unsigned char>(s[i]);
                if (std::isdigit(c)) {
                    digits += static_cast<char>(c);
                } else if (c == '.' || c == ',') {
                    lastSepPos = digits.size();
                }
                // Skip currency symbols, whitespace, etc.
            }

            if (digits.empty() || digits.size() > 18) return std::nullopt;

            if (lastSepPos != std::string::npos) {
                size_t fracLen = digits.size() - lastSepPos;
                if (fracLen <= 2) {
                    // Decimal separator — pad to 2
                    while (fracLen < 2) { digits += '0'; ++fracLen; }
                } else {
                    // 3+ digits after last separator → thousands separator
                    digits += "00";
                }
            } else {
                digits += "00";
            }

            try {
                return std::stoll(digits);
            } catch (...) {
                return std::nullopt;
            }
        };

        auto uiCents = parseToCents(ui);
        auto payloadCents = parseToCents(payload);
        if (!uiCents || !payloadCents) return false;
        return *uiCents == *payloadCents;
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

    // ========================================================================
    // PAUSE / RESUME (thread-safe)
    // ========================================================================

    void PauseMonitor() noexcept {
        std::unique_lock lock(m_mutex);
        if (m_running && m_initialized) {
            m_running = false;
            m_status = ModuleStatus::Paused;
            SS_LOG_INFO(LOG_CATEGORY, L"TransactionMonitor paused");
        }
    }

    void ResumeMonitor() noexcept {
        std::unique_lock lock(m_mutex);
        if (!m_running && m_initialized &&
            m_status.load(std::memory_order_relaxed) == ModuleStatus::Paused) {
            m_running = true;
            m_status = ModuleStatus::Running;
            SS_LOG_INFO(LOG_CATEGORY, L"TransactionMonitor resumed");
        }
    }

    // ========================================================================
    // DOM ANALYSIS (real implementations)
    // ========================================================================

    [[nodiscard]] bool AnalyzeDOMChanges(const std::vector<DOMChangeEvent>& changes) {
        if (!m_running.load(std::memory_order_acquire)) return true;
        if (changes.empty()) return true;

        bool integrity = true;

        for (const auto& change : changes) {
            // Script injection always breaks integrity
            if (change.changeType == DOMChangeType::ScriptInjected) {
                integrity = false;
                m_stats.domManipulationsDetected++;
                SS_LOG_WARN(LOG_CATEGORY, L"DOM: script injection at element '%hs'",
                    change.elementId.c_str());
            }

            // Sensitive form field modification
            if (change.changeType == DOMChangeType::FormModified && change.isSensitiveField) {
                integrity = false;
                m_stats.domManipulationsDetected++;
                SS_LOG_WARN(LOG_CATEGORY, L"DOM: sensitive form field modified at '%hs'",
                    change.xpath.c_str());
            }

            // Value change on sensitive fields (MitB hallmark)
            if (change.changeType == DOMChangeType::ValueChanged && change.isSensitiveField) {
                integrity = false;
                m_stats.domManipulationsDetected++;
            }

            // Hidden iframe/script element added
            if (change.changeType == DOMChangeType::ElementAdded) {
                if (change.tagName == "iframe" || change.tagName == "script" ||
                    change.tagName == "object" || change.tagName == "embed") {
                    integrity = false;
                    m_stats.domManipulationsDetected++;
                    SS_LOG_WARN(LOG_CATEGORY, L"DOM: suspicious element <%hs> injected",
                        change.tagName.c_str());
                }
            }

            // Overlay-style attacks via CSS changes on sensitive fields
            if (change.changeType == DOMChangeType::StyleChanged && change.isSuspicious) {
                integrity = false;
                m_stats.domManipulationsDetected++;
            }
        }

        return integrity;
    }

    [[nodiscard]] bool AnalyzeDOMDiff(const std::string& domDiff) {
        if (!m_running.load(std::memory_order_acquire)) return true;
        if (domDiff.empty()) return true;

        bool integrity = true;
        // Check for injected script tags
        if (domDiff.find("<script") != std::string::npos ||
            domDiff.find("javascript:") != std::string::npos ||
            domDiff.find("eval(") != std::string::npos ||
            domDiff.find("document.write") != std::string::npos) {
            integrity = false;
            m_stats.domManipulationsDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"DOM diff contains script injection indicators");
        }

        // Check for hidden iframe injection
        if (domDiff.find("<iframe") != std::string::npos) {
            integrity = false;
            m_stats.domManipulationsDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"DOM diff contains iframe injection");
        }

        // Check for form action modification
        if (domDiff.find("action=") != std::string::npos ||
            domDiff.find("formaction=") != std::string::npos) {
            integrity = false;
            m_stats.domManipulationsDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"DOM diff contains form action modification");
        }

        return integrity;
    }

    [[nodiscard]] bool CheckDOMIntegrity(const std::string& domHash) {
        if (!m_running.load(std::memory_order_acquire)) return true;
        if (domHash.empty()) return false;

        std::shared_lock lock(m_domMutex);
        if (m_lastKnownDOMHash.empty()) {
            return true; // First check — no baseline yet
        }
        bool match = (m_lastKnownDOMHash == domHash);
        if (!match) {
            m_stats.domManipulationsDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"DOM integrity check failed: hash mismatch");
        }
        return match;
    }

    void UpdateDOMHash(const std::string& domHash) {
        std::unique_lock lock(m_domMutex);
        m_lastKnownDOMHash = domHash;
    }

    void ReportDOMChange(const DOMChangeEvent& change) {
        if (!m_running.load(std::memory_order_acquire)) return;

        {
            std::unique_lock lock(m_domMutex);
            m_recentDOMChanges.push_back(change);
            if (m_recentDOMChanges.size() > TransactionMonitorConstants::MAX_DOM_CHANGES) {
                m_recentDOMChanges.pop_front();
            }
        }

        if (change.isSuspicious || change.changeType == DOMChangeType::ScriptInjected) {
            m_stats.domManipulationsDetected++;
            SS_LOG_WARN(LOG_CATEGORY, L"Suspicious DOM change reported: type=%hs, element='%hs'",
                std::string(GetDOMChangeTypeName(change.changeType)).c_str(),
                change.elementId.c_str());
        }
    }

    // ========================================================================
    // ADDITIONAL QUERY HELPERS
    // ========================================================================

    [[nodiscard]] size_t GetTransactionsInWindow(
        const std::string& sourceAccount,
        std::chrono::seconds window) const {
        std::shared_lock lock(m_historyMutex);
        size_t count = 0;
        auto cutoff = std::chrono::system_clock::now() - window;
        for (auto it = m_transactionHistory.rbegin();
             it != m_transactionHistory.rend(); ++it) {
            if (it->timestamp < cutoff) break;
            if (it->sourceAccount == sourceAccount) {
                count++;
            }
        }
        return count;
    }

    [[nodiscard]] std::vector<AnomalyDetectionResult> GetRecentAnomalies(size_t maxCount) const {
        std::shared_lock lock(m_historyMutex);
        std::vector<AnomalyDetectionResult> result;
        size_t count = (std::min)(maxCount, m_recentAnomalies.size());
        result.reserve(count);
        auto it = m_recentAnomalies.rbegin();
        for (size_t i = 0; i < count && it != m_recentAnomalies.rend(); ++i, ++it) {
            result.push_back(*it);
        }
        return result;
    }

    [[nodiscard]] std::vector<TransactionContext> GetTransactionHistory(size_t maxCount) const {
        std::shared_lock lock(m_historyMutex);
        std::vector<TransactionContext> result;
        size_t count = (std::min)(maxCount, m_transactionHistory.size());
        result.reserve(count);
        auto it = m_transactionHistory.rbegin();
        for (size_t i = 0; i < count && it != m_transactionHistory.rend(); ++i, ++it) {
            result.push_back(*it);
        }
        return result;
    }

    void WhitelistBeneficiary(const Hash256& hash, const std::string& accountForMask,
                              const std::string& reason) {
        std::unique_lock lock(m_profileMutex);
        if (m_beneficiaryCache.size() >= TransactionMonitorConstants::MAX_BENEFICIARIES) {
            SS_LOG_WARN(LOG_CATEGORY, L"Beneficiary cache full, cannot whitelist");
            return;
        }
        auto& profile = m_beneficiaryCache[hash];
        profile.trustLevel = BeneficiaryTrust::Whitelisted;
        profile.isWhitelisted = true;
        profile.accountHash = hash;
        if (profile.accountMasked.empty()) {
            profile.accountMasked = MaskAccountNumber(accountForMask);
        }
        SS_LOG_INFO(LOG_CATEGORY, L"Beneficiary whitelisted (reason: %hs)",
            reason.c_str());
    }

    void RemoveBeneficiaryFromWhitelist(const Hash256& hash) {
        std::unique_lock lock(m_profileMutex);
        auto it = m_beneficiaryCache.find(hash);
        if (it != m_beneficiaryCache.end()) {
            it->second.isWhitelisted = false;
            if (it->second.transactionCount > 10) {
                it->second.trustLevel = BeneficiaryTrust::Trusted;
            } else if (it->second.transactionCount > 3) {
                it->second.trustLevel = BeneficiaryTrust::Recent;
            } else {
                it->second.trustLevel = BeneficiaryTrust::New;
            }
        }
    }

    [[nodiscard]] bool LoadBankingDomains(const std::filesystem::path& path) {
        std::error_code ec;
        if (!std::filesystem::exists(path, ec) || ec) {
            SS_LOG_ERROR(LOG_CATEGORY, L"LoadBankingDomains: file not found or inaccessible");
            return false;
        }

        auto fileSize = std::filesystem::file_size(path, ec);
        if (ec || fileSize == 0 || fileSize > 10ULL * 1024 * 1024) {
            SS_LOG_ERROR(LOG_CATEGORY, L"LoadBankingDomains: invalid file size");
            return false;
        }

        std::ifstream file(path);
        if (!file.is_open()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"LoadBankingDomains: failed to open file");
            return false;
        }

        std::string line;
        size_t loaded = 0;
        while (std::getline(file, line) &&
               loaded < TransactionMonitorConstants::MAX_PROTECTED_DOMAINS) {
            auto start = line.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) continue;
            auto end = line.find_last_not_of(" \t\r\n");
            std::string domain = line.substr(start, end - start + 1);

            if (domain.empty() || domain[0] == '#') continue;
            if (domain.length() > 253) continue;

            AddProtectedDomain(domain);
            loaded++;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"LoadBankingDomains: loaded %zu domains", loaded);
        return loaded > 0;
    }

    // Member variables
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_historyMutex;
    mutable std::shared_mutex m_profileMutex;
    mutable std::shared_mutex m_domMutex;

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
    std::deque<DOMChangeEvent> m_recentDOMChanges;
    std::string m_lastKnownDOMHash;
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
    m_impl->PauseMonitor();
}

void TransactionMonitor::Resume() {
    m_impl->ResumeMonitor();
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

    NetworkPayloadValues payload;
    payload.payloadAccount = context.beneficiaryAccount;
    // Fixed-precision formatting — locale-independent via ostringstream with "C" locale
    std::ostringstream oss;
    oss.imbue(std::locale::classic());
    oss << std::fixed << std::setprecision(2) << context.amount;
    payload.payloadAmount = oss.str();
    payload.payloadCurrency = context.currency;

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
    TransactionMonitorStatistics stats;
    stats.totalTransactionsMonitored.store(
        m_impl->m_stats.totalTransactionsMonitored.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.transactionsValidated.store(
        m_impl->m_stats.transactionsValidated.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.anomaliesDetected.store(
        m_impl->m_stats.anomaliesDetected.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.transactionsBlocked.store(
        m_impl->m_stats.transactionsBlocked.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.userConfirmations.store(
        m_impl->m_stats.userConfirmations.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.domManipulationsDetected.store(
        m_impl->m_stats.domManipulationsDetected.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.uiPayloadMismatches.store(
        m_impl->m_stats.uiPayloadMismatches.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.newBeneficiaries.store(
        m_impl->m_stats.newBeneficiaries.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    stats.totalAmountMonitoredCents.store(
        m_impl->m_stats.totalAmountMonitoredCents.load(std::memory_order_relaxed),
        std::memory_order_relaxed);
    for (size_t i = 0; i < stats.byAttackVector.size(); ++i) {
        stats.byAttackVector[i].store(
            m_impl->m_stats.byAttackVector[i].load(std::memory_order_relaxed),
            std::memory_order_relaxed);
    }
    for (size_t i = 0; i < stats.byRiskLevel.size(); ++i) {
        stats.byRiskLevel[i].store(
            m_impl->m_stats.byRiskLevel[i].load(std::memory_order_relaxed),
            std::memory_order_relaxed);
    }
    stats.startTime = AtomicValueLoadRelaxed(m_impl->m_stats.startTime);
    return stats;
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

    // 2. Test masking — short accounts now fully masked, long accounts show last 4
    if (MaskAccountNumber("1234567890") != "******7890") {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Long account masking failed");
        return false;
    }
    if (MaskAccountNumber("1234") != "****") {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test: Short account masking failed");
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

// ============================================================================
// FORMERLY STUB IMPLEMENTATIONS — now properly delegated to PIMPL
// ============================================================================

bool TransactionMonitor::AnalyzeDOMChanges(const std::vector<DOMChangeEvent>& changes) {
    return m_impl->AnalyzeDOMChanges(changes);
}

bool TransactionMonitor::AnalyzeDOMDiff(const std::string& domDiff) {
    return m_impl->AnalyzeDOMDiff(domDiff);
}

bool TransactionMonitor::CheckDOMIntegrity(const std::string& domHash) {
    return m_impl->CheckDOMIntegrity(domHash);
}

void TransactionMonitor::ReportDOMChange(const DOMChangeEvent& change) {
    m_impl->ReportDOMChange(change);
}

size_t TransactionMonitor::GetTransactionsInWindow(
    const std::string& sourceAccount, std::chrono::seconds window) const {
    return m_impl->GetTransactionsInWindow(sourceAccount, window);
}

bool TransactionMonitor::IsBeneficiaryKnown(const std::string& accountNumber) const {
    Hash256 hash = HashAccountNumber(accountNumber);
    return m_impl->IsBeneficiaryKnown(hash);
}

BeneficiaryTrust TransactionMonitor::GetBeneficiaryTrust(const std::string& accountNumber) const {
    Hash256 hash = HashAccountNumber(accountNumber);
    auto profile = m_impl->GetBeneficiaryProfile(hash);
    if (profile) return profile->trustLevel;
    return BeneficiaryTrust::Unknown;
}

std::optional<BeneficiaryProfile> TransactionMonitor::GetBeneficiaryProfile(
    const std::string& accountNumber) const {
    Hash256 hash = HashAccountNumber(accountNumber);
    return m_impl->GetBeneficiaryProfile(hash);
}

void TransactionMonitor::WhitelistBeneficiary(
    const std::string& accountNumber, const std::string& reason) {
    Hash256 hash = HashAccountNumber(accountNumber);
    m_impl->WhitelistBeneficiary(hash, accountNumber, reason);
}

void TransactionMonitor::RemoveBeneficiaryFromWhitelist(const std::string& accountNumber) {
    Hash256 hash = HashAccountNumber(accountNumber);
    m_impl->RemoveBeneficiaryFromWhitelist(hash);
}

bool TransactionMonitor::LoadBankingDomains(const std::filesystem::path& path) {
    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"LoadBankingDomains: monitor not initialized");
        return false;
    }
    return m_impl->LoadBankingDomains(path);
}

void TransactionMonitor::RegisterValidationCallback(ValidationCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_validationCallback = std::move(callback);
}

void TransactionMonitor::RegisterUserConfirmationCallback(UserConfirmationCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_userConfirmationCallback = std::move(callback);
}

void TransactionMonitor::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_errorCallback = std::move(callback);
}

void TransactionMonitor::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_anomalyCallback = nullptr;
    m_impl->m_validationCallback = nullptr;
    m_impl->m_userConfirmationCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
}

std::vector<AnomalyDetectionResult> TransactionMonitor::GetRecentAnomalies(size_t maxCount) const {
    return m_impl->GetRecentAnomalies(maxCount);
}

std::vector<TransactionContext> TransactionMonitor::GetTransactionHistory(size_t maxCount) const {
    return m_impl->GetTransactionHistory(maxCount);
}

} // namespace Banking
} // namespace ShadowStrike
