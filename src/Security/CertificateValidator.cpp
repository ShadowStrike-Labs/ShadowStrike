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
 * ShadowStrike Security - X.509 CERTIFICATE VALIDATION ENGINE IMPLEMENTATION
 * ============================================================================
 *
 * @file CertificateValidator.cpp
 * @brief Enterprise-grade X.509 certificate validation and verification system
 *        implementation for validating SSL/TLS certificates, code signing
 *        certificates, and certificate chains.
 *
 * This implementation provides comprehensive certificate validation capabilities
 * for the ShadowStrike security suite, competing with CrowdStrike Falcon,
 * Kaspersky, and BitDefender's certificate validation engines.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, FIPS 140-2, Common Criteria
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "CertificateValidator.hpp"

// ============================================================================
// WINDOWS CRYPTO SDK
// ============================================================================

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

// ============================================================================
// STANDARD LIBRARY
// ============================================================================

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <condition_variable>
#include <filesystem>
#include <queue>

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"CertificateValidator";

// ============================================================================
// STATIC MEMBER INITIALIZATION
// ============================================================================

std::atomic<bool> CertificateValidator::s_instanceCreated{false};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

// Get current system time point
[[nodiscard]] SystemTimePoint GetCurrentSystemTime() {
    return std::chrono::system_clock::now();
}

// Format time point to ISO 8601
[[nodiscard]] std::string FormatTimePoint(const SystemTimePoint& tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_val{};
    gmtime_s(&tm_val, &time_t_val);

    std::ostringstream oss;
    oss << std::put_time(&tm_val, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// Escape JSON string
[[nodiscard]] std::string EscapeJsonString(const std::string& input) {
    std::ostringstream oss;
    for (char c : input) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b";  break;
            case '\f': oss << "\\f";  break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    oss << "\\u" << std::hex << std::setfill('0')
                        << std::setw(4) << static_cast<int>(c);
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

// Convert wide string to UTF-8
[[nodiscard]] std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return {};

    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                                    static_cast<int>(wide.size()),
                                    nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(),
                        static_cast<int>(wide.size()),
                        result.data(), size, nullptr, nullptr);
    return result;
}

// Convert UTF-8 to wide string
[[nodiscard]] std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return {};

    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                                    static_cast<int>(utf8.size()),
                                    nullptr, 0);
    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(),
                        static_cast<int>(utf8.size()),
                        result.data(), size);
    return result;
}

// Convert bytes to hex string
[[nodiscard]] std::string BytesToHex(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    for (size_t i = 0; i < size; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

// Parse hex string to bytes
[[nodiscard]] bool HexToBytes(std::string_view hex, std::vector<uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;

    out.clear();
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];

        auto hexDigit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };

        int h = hexDigit(high);
        int l = hexDigit(low);
        if (h < 0 || l < 0) return false;

        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return true;
}

// FILETIME to SystemTimePoint
[[nodiscard]] SystemTimePoint FileTimeToSystemTime(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Convert to Unix epoch (100-nanosecond intervals since 1601 -> seconds since 1970)
    constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;
    if (uli.QuadPart < EPOCH_DIFF) {
        return std::chrono::system_clock::time_point{};
    }

    uint64_t unixTime = (uli.QuadPart - EPOCH_DIFF) / 10000000ULL;
    return std::chrono::system_clock::from_time_t(static_cast<time_t>(unixTime));
}

// RAII wrapper for PCCERT_CONTEXT
class CertContextPtr {
public:
    CertContextPtr() = default;
    explicit CertContextPtr(PCCERT_CONTEXT ctx) : m_ctx(ctx) {}
    ~CertContextPtr() { Release(); }

    CertContextPtr(const CertContextPtr&) = delete;
    CertContextPtr& operator=(const CertContextPtr&) = delete;

    CertContextPtr(CertContextPtr&& other) noexcept : m_ctx(other.m_ctx) {
        other.m_ctx = nullptr;
    }

    CertContextPtr& operator=(CertContextPtr&& other) noexcept {
        if (this != &other) {
            Release();
            m_ctx = other.m_ctx;
            other.m_ctx = nullptr;
        }
        return *this;
    }

    void Release() {
        if (m_ctx) {
            CertFreeCertificateContext(m_ctx);
            m_ctx = nullptr;
        }
    }

    void Reset(PCCERT_CONTEXT ctx) {
        Release();
        m_ctx = ctx;
    }

    [[nodiscard]] PCCERT_CONTEXT Get() const noexcept { return m_ctx; }
    [[nodiscard]] PCCERT_CONTEXT* AddressOf() noexcept { return &m_ctx; }
    [[nodiscard]] bool IsValid() const noexcept { return m_ctx != nullptr; }
    [[nodiscard]] operator bool() const noexcept { return IsValid(); }

    PCCERT_CONTEXT Detach() noexcept {
        auto ctx = m_ctx;
        m_ctx = nullptr;
        return ctx;
    }

private:
    PCCERT_CONTEXT m_ctx = nullptr;
};

// RAII wrapper for HCERTSTORE
class CertStorePtr {
public:
    CertStorePtr() = default;
    explicit CertStorePtr(HCERTSTORE store) : m_store(store) {}
    ~CertStorePtr() { Release(); }

    CertStorePtr(const CertStorePtr&) = delete;
    CertStorePtr& operator=(const CertStorePtr&) = delete;

    CertStorePtr(CertStorePtr&& other) noexcept : m_store(other.m_store) {
        other.m_store = nullptr;
    }

    CertStorePtr& operator=(CertStorePtr&& other) noexcept {
        if (this != &other) {
            Release();
            m_store = other.m_store;
            other.m_store = nullptr;
        }
        return *this;
    }

    void Release() {
        if (m_store) {
            CertCloseStore(m_store, 0);
            m_store = nullptr;
        }
    }

    [[nodiscard]] HCERTSTORE Get() const noexcept { return m_store; }
    [[nodiscard]] bool IsValid() const noexcept { return m_store != nullptr; }

private:
    HCERTSTORE m_store = nullptr;
};

// RAII wrapper for PCCERT_CHAIN_CONTEXT
class CertChainPtr {
public:
    CertChainPtr() = default;
    explicit CertChainPtr(PCCERT_CHAIN_CONTEXT chain) : m_chain(chain) {}
    ~CertChainPtr() { Release(); }

    CertChainPtr(const CertChainPtr&) = delete;
    CertChainPtr& operator=(const CertChainPtr&) = delete;

    void Release() {
        if (m_chain) {
            CertFreeCertificateChain(m_chain);
            m_chain = nullptr;
        }
    }

    [[nodiscard]] PCCERT_CHAIN_CONTEXT Get() const noexcept { return m_chain; }
    [[nodiscard]] PCCERT_CHAIN_CONTEXT* AddressOf() noexcept { return &m_chain; }
    [[nodiscard]] bool IsValid() const noexcept { return m_chain != nullptr; }

private:
    PCCERT_CHAIN_CONTEXT m_chain = nullptr;
};

}  // anonymous namespace

// ============================================================================
// STRUCTURE METHOD IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string DistinguishedName::ToString() const {
    std::ostringstream oss;
    if (!commonName.empty()) oss << "CN=" << commonName;
    if (!organization.empty()) {
        if (oss.tellp() > 0) oss << ", ";
        oss << "O=" << organization;
    }
    if (!organizationalUnit.empty()) {
        if (oss.tellp() > 0) oss << ", ";
        oss << "OU=" << organizationalUnit;
    }
    if (!country.empty()) {
        if (oss.tellp() > 0) oss << ", ";
        oss << "C=" << country;
    }
    if (!state.empty()) {
        if (oss.tellp() > 0) oss << ", ";
        oss << "ST=" << state;
    }
    if (!locality.empty()) {
        if (oss.tellp() > 0) oss << ", ";
        oss << "L=" << locality;
    }
    return oss.str();
}

[[nodiscard]] bool DistinguishedName::operator==(const DistinguishedName& other) const {
    return commonName == other.commonName &&
           organization == other.organization &&
           organizationalUnit == other.organizationalUnit &&
           country == other.country &&
           state == other.state &&
           locality == other.locality;
}

[[nodiscard]] bool ValidityPeriod::IsValid() const {
    auto now = GetCurrentSystemTime();
    return now >= notBefore && now <= notAfter;
}

[[nodiscard]] bool ValidityPeriod::IsExpired() const {
    return GetCurrentSystemTime() > notAfter;
}

[[nodiscard]] bool ValidityPeriod::IsNotYetValid() const {
    return GetCurrentSystemTime() < notBefore;
}

[[nodiscard]] int64_t ValidityPeriod::GetRemainingSeconds() const {
    auto now = GetCurrentSystemTime();
    auto remaining = std::chrono::duration_cast<std::chrono::seconds>(
        notAfter - now).count();
    return remaining;
}

[[nodiscard]] std::string CertificateInfo::ToString() const {
    std::ostringstream oss;
    oss << "Certificate:\n";
    oss << "  Subject: " << subject.ToString() << "\n";
    oss << "  Issuer: " << issuer.ToString() << "\n";
    oss << "  Serial: " << serialNumber << "\n";
    oss << "  Valid: " << FormatTimePoint(validity.notBefore)
        << " to " << FormatTimePoint(validity.notAfter) << "\n";
    oss << "  Key Type: " << static_cast<int>(publicKey.type)
        << " (" << publicKey.keySizeBits << " bits)\n";
    oss << "  Is CA: " << (isCA ? "Yes" : "No") << "\n";
    oss << "  Self-Signed: " << (isSelfSigned ? "Yes" : "No") << "\n";
    oss << "  SHA-256: " << BytesToHex(sha256Fingerprint.data(), sha256Fingerprint.size()) << "\n";
    return oss.str();
}

[[nodiscard]] std::string CertificateInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"version\":" << version << ",";
    oss << "\"serialNumber\":\"" << EscapeJsonString(serialNumber) << "\",";
    oss << "\"subject\":\"" << EscapeJsonString(subject.ToString()) << "\",";
    oss << "\"issuer\":\"" << EscapeJsonString(issuer.ToString()) << "\",";
    oss << "\"notBefore\":\"" << FormatTimePoint(validity.notBefore) << "\",";
    oss << "\"notAfter\":\"" << FormatTimePoint(validity.notAfter) << "\",";
    oss << "\"keyType\":" << static_cast<int>(publicKey.type) << ",";
    oss << "\"keySizeBits\":" << publicKey.keySizeBits << ",";
    oss << "\"signatureAlgorithm\":" << static_cast<int>(signatureAlgorithm) << ",";
    oss << "\"isCA\":" << (isCA ? "true" : "false") << ",";
    oss << "\"isSelfSigned\":" << (isSelfSigned ? "true" : "false") << ",";
    oss << "\"sha256Fingerprint\":\"" << BytesToHex(sha256Fingerprint.data(), sha256Fingerprint.size()) << "\",";
    oss << "\"sha1Thumbprint\":\"" << BytesToHex(sha1Thumbprint.data(), sha1Thumbprint.size()) << "\",";
    oss << "\"type\":" << static_cast<int>(type);
    oss << "}";
    return oss.str();
}

[[nodiscard]] std::string ValidationDetails::GetSummary() const {
    std::ostringstream oss;
    oss << "Validation Result: " << GetValidationResultName(result) << "\n";
    oss << "Trust Level: " << GetTrustLevelName(trustLevel) << "\n";
    oss << "Revocation: " << GetRevocationStatusName(revocationStatus) << "\n";
    if (!errorMessage.empty()) {
        oss << "Error: " << errorMessage << "\n";
    }
    oss << "Chain Length: " << chain.size() << "\n";
    if (!warnings.empty()) {
        oss << "Warnings: " << warnings.size() << "\n";
    }
    return oss.str();
}

[[nodiscard]] std::string ValidationDetails::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"result\":" << static_cast<int>(result) << ",";
    oss << "\"resultName\":\"" << GetValidationResultName(result) << "\",";
    oss << "\"errorMessage\":\"" << EscapeJsonString(errorMessage) << "\",";
    oss << "\"errorCode\":" << errorCode << ",";
    oss << "\"trustLevel\":" << static_cast<int>(trustLevel) << ",";
    oss << "\"revocationStatus\":" << static_cast<int>(revocationStatus) << ",";
    oss << "\"isExtendedValidation\":" << (isExtendedValidation ? "true" : "false") << ",";
    oss << "\"chainLength\":" << chain.size() << ",";
    oss << "\"warnings\":[";
    for (size_t i = 0; i < warnings.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJsonString(warnings[i]) << "\"";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

[[nodiscard]] bool CertificateValidatorConfiguration::IsValid() const noexcept {
    if (minRSAKeySize < 1024 || minRSAKeySize > 16384) return false;
    if (minECCKeySize < 160 || minECCKeySize > 521) return false;
    return true;
}

void CertificateValidatorStatistics::Reset() noexcept {
    totalValidations.store(0, std::memory_order_relaxed);
    validCertificates.store(0, std::memory_order_relaxed);
    invalidCertificates.store(0, std::memory_order_relaxed);
    expiredCertificates.store(0, std::memory_order_relaxed);
    revokedCertificates.store(0, std::memory_order_relaxed);
    ocspChecks.store(0, std::memory_order_relaxed);
    ocspCacheHits.store(0, std::memory_order_relaxed);
    crlChecks.store(0, std::memory_order_relaxed);
    crlCacheHits.store(0, std::memory_order_relaxed);
    validationCacheHits.store(0, std::memory_order_relaxed);
    chainBuildFailures.store(0, std::memory_order_relaxed);
    avgValidationTimeUs.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

[[nodiscard]] std::string CertificateValidatorStatistics::ToJson() const {
    auto uptimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - startTime).count();

    std::ostringstream oss;
    oss << "{";
    oss << "\"totalValidations\":" << totalValidations.load(std::memory_order_relaxed) << ",";
    oss << "\"validCertificates\":" << validCertificates.load(std::memory_order_relaxed) << ",";
    oss << "\"invalidCertificates\":" << invalidCertificates.load(std::memory_order_relaxed) << ",";
    oss << "\"expiredCertificates\":" << expiredCertificates.load(std::memory_order_relaxed) << ",";
    oss << "\"revokedCertificates\":" << revokedCertificates.load(std::memory_order_relaxed) << ",";
    oss << "\"ocspChecks\":" << ocspChecks.load(std::memory_order_relaxed) << ",";
    oss << "\"ocspCacheHits\":" << ocspCacheHits.load(std::memory_order_relaxed) << ",";
    oss << "\"crlChecks\":" << crlChecks.load(std::memory_order_relaxed) << ",";
    oss << "\"crlCacheHits\":" << crlCacheHits.load(std::memory_order_relaxed) << ",";
    oss << "\"validationCacheHits\":" << validationCacheHits.load(std::memory_order_relaxed) << ",";
    oss << "\"chainBuildFailures\":" << chainBuildFailures.load(std::memory_order_relaxed) << ",";
    oss << "\"avgValidationTimeUs\":" << avgValidationTimeUs.load(std::memory_order_relaxed) << ",";
    oss << "\"uptimeMs\":" << uptimeMs;
    oss << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTION IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept {
    switch (result) {
        case ValidationResult::Valid:               return "Valid";
        case ValidationResult::Invalid:             return "Invalid";
        case ValidationResult::Expired:             return "Expired";
        case ValidationResult::NotYetValid:         return "NotYetValid";
        case ValidationResult::Revoked:             return "Revoked";
        case ValidationResult::UntrustedRoot:       return "UntrustedRoot";
        case ValidationResult::ChainBuildingFailed: return "ChainBuildingFailed";
        case ValidationResult::SignatureInvalid:    return "SignatureInvalid";
        case ValidationResult::NameMismatch:        return "NameMismatch";
        case ValidationResult::PolicyViolation:     return "PolicyViolation";
        case ValidationResult::UnknownCriticalExt:  return "UnknownCriticalExtension";
        case ValidationResult::RevocationUnknown:   return "RevocationUnknown";
        case ValidationResult::WeakAlgorithm:       return "WeakAlgorithm";
        case ValidationResult::KeyUsageInvalid:     return "KeyUsageInvalid";
        case ValidationResult::PathLengthExceeded:  return "PathLengthExceeded";
        case ValidationResult::Error:               return "Error";
        default:                                    return "Unknown";
    }
}

[[nodiscard]] std::string_view GetCertificateTypeName(CertificateType type) noexcept {
    switch (type) {
        case CertificateType::Unknown:          return "Unknown";
        case CertificateType::RootCA:           return "RootCA";
        case CertificateType::IntermediateCA:   return "IntermediateCA";
        case CertificateType::EndEntity:        return "EndEntity";
        case CertificateType::SelfSigned:       return "SelfSigned";
        case CertificateType::CodeSigning:      return "CodeSigning";
        case CertificateType::ServerAuth:       return "ServerAuth";
        case CertificateType::ClientAuth:       return "ClientAuth";
        case CertificateType::EmailSigning:     return "EmailSigning";
        case CertificateType::Timestamping:     return "Timestamping";
        default:                                return "Unknown";
    }
}

[[nodiscard]] std::string_view GetKeyTypeName(KeyType type) noexcept {
    switch (type) {
        case KeyType::Unknown:  return "Unknown";
        case KeyType::RSA:      return "RSA";
        case KeyType::DSA:      return "DSA";
        case KeyType::ECDSA:    return "ECDSA";
        case KeyType::ECDH:     return "ECDH";
        case KeyType::EdDSA:    return "EdDSA";
        default:                return "Unknown";
    }
}

[[nodiscard]] std::string_view GetSignatureAlgorithmName(SignatureAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case SignatureAlgorithm::Unknown:       return "Unknown";
        case SignatureAlgorithm::MD5_RSA:       return "MD5withRSA";
        case SignatureAlgorithm::SHA1_RSA:      return "SHA1withRSA";
        case SignatureAlgorithm::SHA256_RSA:    return "SHA256withRSA";
        case SignatureAlgorithm::SHA384_RSA:    return "SHA384withRSA";
        case SignatureAlgorithm::SHA512_RSA:    return "SHA512withRSA";
        case SignatureAlgorithm::SHA256_ECDSA:  return "SHA256withECDSA";
        case SignatureAlgorithm::SHA384_ECDSA:  return "SHA384withECDSA";
        case SignatureAlgorithm::SHA512_ECDSA:  return "SHA512withECDSA";
        case SignatureAlgorithm::RSA_PSS:       return "RSA-PSS";
        case SignatureAlgorithm::Ed25519:       return "Ed25519";
        case SignatureAlgorithm::Ed448:         return "Ed448";
        default:                                return "Unknown";
    }
}

[[nodiscard]] std::string_view GetRevocationStatusName(RevocationStatus status) noexcept {
    switch (status) {
        case RevocationStatus::Unknown:         return "Unknown";
        case RevocationStatus::Good:            return "Good";
        case RevocationStatus::Revoked:         return "Revoked";
        case RevocationStatus::Suspended:       return "Suspended";
        case RevocationStatus::CRLNotAvailable: return "CRLNotAvailable";
        case RevocationStatus::OCSPNotAvailable:return "OCSPNotAvailable";
        case RevocationStatus::CheckFailed:     return "CheckFailed";
        default:                                return "Unknown";
    }
}

[[nodiscard]] std::string_view GetRevocationReasonName(RevocationReason reason) noexcept {
    switch (reason) {
        case RevocationReason::Unspecified:             return "Unspecified";
        case RevocationReason::KeyCompromise:           return "KeyCompromise";
        case RevocationReason::CACompromise:            return "CACompromise";
        case RevocationReason::AffiliationChanged:      return "AffiliationChanged";
        case RevocationReason::Superseded:              return "Superseded";
        case RevocationReason::CessationOfOperation:    return "CessationOfOperation";
        case RevocationReason::CertificateHold:         return "CertificateHold";
        case RevocationReason::RemoveFromCRL:           return "RemoveFromCRL";
        case RevocationReason::PrivilegeWithdrawn:      return "PrivilegeWithdrawn";
        case RevocationReason::AACompromise:            return "AACompromise";
        default:                                        return "Unknown";
    }
}

[[nodiscard]] std::string_view GetTrustLevelName(TrustLevel level) noexcept {
    switch (level) {
        case TrustLevel::Untrusted:         return "Untrusted";
        case TrustLevel::Unknown:           return "Unknown";
        case TrustLevel::SelfSigned:        return "SelfSigned";
        case TrustLevel::CustomRoot:        return "CustomRoot";
        case TrustLevel::SystemRoot:        return "SystemRoot";
        case TrustLevel::EnterpriseRoot:    return "EnterpriseRoot";
        case TrustLevel::EVValidated:       return "EVValidated";
        default:                            return "Unknown";
    }
}

// ============================================================================
// CERTIFICATE VALIDATOR IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class CertificateValidatorImpl final {
public:
    CertificateValidatorImpl() = default;
    ~CertificateValidatorImpl() { Shutdown(); }

    // Non-copyable, non-movable
    CertificateValidatorImpl(const CertificateValidatorImpl&) = delete;
    CertificateValidatorImpl& operator=(const CertificateValidatorImpl&) = delete;
    CertificateValidatorImpl(CertificateValidatorImpl&&) = delete;
    CertificateValidatorImpl& operator=(CertificateValidatorImpl&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const CertificateValidatorConfiguration& config) {
        std::unique_lock lock(m_mutex);

        if (m_status != ModuleStatus::Uninitialized &&
            m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CATEGORY, L"CertificateValidator already initialized");
            return true;
        }

        m_status = ModuleStatus::Initializing;

        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            m_status = ModuleStatus::Error;
            return false;
        }

        m_config = config;

        // Open system certificate stores
        if (m_config.useSystemTrustStore) {
            m_rootStore.reset(new CertStorePtr(
                CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                    CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                    L"ROOT")));

            if (!m_rootStore || !m_rootStore->IsValid()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to open ROOT store");
            }

            m_caStore.reset(new CertStorePtr(
                CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                    CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                    L"CA")));

            if (!m_caStore || !m_caStore->IsValid()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to open CA store");
            }
        }

        // Add additional roots
        for (const auto& rootData : m_config.additionalRoots) {
            AddTrustedRootInternal(rootData);
        }

        // Add blocked certificates
        for (const auto& blocked : m_config.blockedCertificates) {
            m_blockedCerts[blocked] = "Configured as blocked";
        }

        m_stats.Reset();
        m_status = ModuleStatus::Running;

        SS_LOG_INFO(LOG_CATEGORY, L"CertificateValidator initialized successfully");
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);

        if (m_status == ModuleStatus::Uninitialized ||
            m_status == ModuleStatus::Stopped) {
            return;
        }

        m_status = ModuleStatus::Stopping;

        // Close stores
        m_rootStore.reset();
        m_caStore.reset();

        // Clear caches
        m_validationCache.clear();
        m_ocspCache.clear();
        m_crlCache.clear();
        m_customRoots.clear();
        m_pinnedCerts.clear();
        m_blockedCerts.clear();

        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CATEGORY, L"CertificateValidator shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        return m_status == ModuleStatus::Running;
    }

    [[nodiscard]] ModuleStatus GetStatus() const noexcept {
        return m_status.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool SetConfiguration(const CertificateValidatorConfiguration& config) {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_config = config;
        SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
        return true;
    }

    [[nodiscard]] CertificateValidatorConfiguration GetConfiguration() const {
        std::shared_lock lock(m_mutex);
        return m_config;
    }

    // ========================================================================
    // CERTIFICATE PARSING
    // ========================================================================

    [[nodiscard]] std::optional<CertificateInfo> ParseCertificate(
        std::span<const uint8_t> certData) {

        if (certData.empty() || certData.size() > CertificateConstants::MAX_CERTIFICATE_SIZE) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid certificate data size");
            return std::nullopt;
        }

        // Detect encoding
        CertificateEncoding encoding = DetectEncoding(certData);

        // Convert PEM to DER if needed
        std::vector<uint8_t> derData;
        if (encoding == CertificateEncoding::PEM) {
            if (!PEMToDER(certData, derData)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to decode PEM certificate");
                return std::nullopt;
            }
            certData = std::span<const uint8_t>(derData.data(), derData.size());
        }

        // Create certificate context
        CertContextPtr certCtx(CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            certData.data(),
            static_cast<DWORD>(certData.size())));

        if (!certCtx) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CertCreateCertificateContext failed: 0x%08X",
                         GetLastError());
            return std::nullopt;
        }

        return ParseCertificateContext(certCtx.Get(), certData);
    }

    [[nodiscard]] std::optional<CertificateInfo> ParsePEM(std::string_view pemData) {
        return ParseCertificate(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(pemData.data()),
            pemData.size()));
    }

    [[nodiscard]] std::vector<CertificateInfo> ParseCertificateChain(
        std::span<const uint8_t> chainData) {

        std::vector<CertificateInfo> result;

        // Try PKCS#7
        CRYPT_DATA_BLOB blob;
        blob.pbData = const_cast<BYTE*>(chainData.data());
        blob.cbData = static_cast<DWORD>(chainData.size());

        HCERTSTORE hStore = CertOpenStore(
            CERT_STORE_PROV_PKCS7,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, 0, &blob);

        if (hStore) {
            CertStorePtr store(hStore);

            PCCERT_CONTEXT pCert = nullptr;
            while ((pCert = CertEnumCertificatesInStore(store.Get(), pCert)) != nullptr) {
                std::span<const uint8_t> certSpan(
                    pCert->pbCertEncoded, pCert->cbCertEncoded);
                auto certInfo = ParseCertificateContext(pCert, certSpan);
                if (certInfo) {
                    result.push_back(std::move(*certInfo));
                }
            }
        }

        return result;
    }

    [[nodiscard]] CertificateEncoding DetectEncoding(std::span<const uint8_t> data) {
        if (data.empty()) return CertificateEncoding::Unknown;

        // Check for PEM
        if (data.size() > 10) {
            std::string_view header(reinterpret_cast<const char*>(data.data()),
                                    std::min(data.size(), size_t(64)));
            if (header.find("-----BEGIN") != std::string_view::npos) {
                return CertificateEncoding::PEM;
            }
        }

        // Check for DER (ASN.1 SEQUENCE)
        if (data[0] == 0x30) {
            return CertificateEncoding::DER;
        }

        // Check for PKCS#7
        if (data.size() > 20 && data[0] == 0x30) {
            // Could be PKCS#7, try to distinguish
            return CertificateEncoding::DER;
        }

        return CertificateEncoding::Unknown;
    }

    // ========================================================================
    // PRIMARY VALIDATION
    // ========================================================================

    [[nodiscard]] bool VerifyCertificate(const std::vector<uint8_t>& certData) {
        auto details = VerifyCertificateWithOptions(
            std::span<const uint8_t>(certData.data(), certData.size()),
            ValidationOptions{});
        return details.IsValid();
    }

    [[nodiscard]] ValidationDetails VerifyCertificateWithOptions(
        std::span<const uint8_t> certData,
        const ValidationOptions& options) {

        auto startTime = Clock::now();
        ValidationDetails details;
        details.validationTime = startTime;

        m_stats.totalValidations.fetch_add(1, std::memory_order_relaxed);

        // Parse certificate
        auto certInfo = ParseCertificate(certData);
        if (!certInfo) {
            details.result = ValidationResult::Error;
            details.errorMessage = "Failed to parse certificate";
            m_stats.invalidCertificates.fetch_add(1, std::memory_order_relaxed);
            return details;
        }

        // Check cache
        if ((options.flags & ValidationFlags::CacheResult) != ValidationFlags::None) {
            std::shared_lock lock(m_mutex);
            auto it = m_validationCache.find(certInfo->sha256Fingerprint);
            if (it != m_validationCache.end()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.validationTime).count();
                if (age < CertificateConstants::VALIDATION_CACHE_DURATION_SECS) {
                    m_stats.validationCacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second;
                }
            }
        }

        // Check if blocked
        if (IsBlockedInternal(certInfo->sha256Fingerprint)) {
            details.result = ValidationResult::Invalid;
            details.errorMessage = "Certificate is blocked";
            m_stats.invalidCertificates.fetch_add(1, std::memory_order_relaxed);
            return details;
        }

        // Verify with options
        details = VerifyCertificateInternal(*certInfo, options);

        // Update statistics
        if (details.IsValid()) {
            m_stats.validCertificates.fetch_add(1, std::memory_order_relaxed);
        } else {
            m_stats.invalidCertificates.fetch_add(1, std::memory_order_relaxed);

            if (details.result == ValidationResult::Expired) {
                m_stats.expiredCertificates.fetch_add(1, std::memory_order_relaxed);
            } else if (details.result == ValidationResult::Revoked) {
                m_stats.revokedCertificates.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Update timing
        auto endTime = Clock::now();
        auto durationUs = std::chrono::duration_cast<std::chrono::microseconds>(
            endTime - startTime).count();
        m_stats.avgValidationTimeUs.store(
            static_cast<uint64_t>(durationUs), std::memory_order_relaxed);

        // Cache result
        if ((options.flags & ValidationFlags::CacheResult) != ValidationFlags::None) {
            std::unique_lock lock(m_mutex);
            if (m_validationCache.size() < CertificateConstants::MAX_CACHED_CERTIFICATES) {
                m_validationCache[certInfo->sha256Fingerprint] = details;
            }
        }

        return details;
    }

    [[nodiscard]] ValidationDetails VerifyCertificateInfo(
        const CertificateInfo& certInfo,
        const ValidationOptions& options) {

        return VerifyCertificateInternal(certInfo, options);
    }

    [[nodiscard]] ValidationDetails VerifyChain(
        const std::vector<CertificateInfo>& chain,
        const ValidationOptions& options) {

        ValidationDetails details;

        if (chain.empty()) {
            details.result = ValidationResult::ChainBuildingFailed;
            details.errorMessage = "Empty certificate chain";
            return details;
        }

        details.chain = chain;

        // Validate each certificate in chain
        for (size_t i = 0; i < chain.size(); ++i) {
            const auto& cert = chain[i];

            // Check validity period
            if (cert.validity.IsExpired()) {
                if ((options.flags & ValidationFlags::IgnoreExpired) == ValidationFlags::None) {
                    details.result = ValidationResult::Expired;
                    details.errorMessage = "Certificate at index " + std::to_string(i) + " is expired";
                    return details;
                } else {
                    details.warnings.push_back("Certificate at index " + std::to_string(i) + " is expired");
                }
            }

            if (cert.validity.IsNotYetValid()) {
                if ((options.flags & ValidationFlags::IgnoreNotYetValid) == ValidationFlags::None) {
                    details.result = ValidationResult::NotYetValid;
                    details.errorMessage = "Certificate at index " + std::to_string(i) + " is not yet valid";
                    return details;
                } else {
                    details.warnings.push_back("Certificate at index " + std::to_string(i) + " is not yet valid");
                }
            }

            // Check if blocked
            if (IsBlockedInternal(cert.sha256Fingerprint)) {
                details.result = ValidationResult::Invalid;
                details.errorMessage = "Certificate at index " + std::to_string(i) + " is blocked";
                return details;
            }

            // Check weak algorithms
            if (!m_config.allowWeakAlgorithms &&
                CertificateValidator::IsWeakAlgorithm(cert.signatureAlgorithm)) {
                if ((options.flags & ValidationFlags::IgnoreWeakAlgorithm) == ValidationFlags::None) {
                    details.result = ValidationResult::WeakAlgorithm;
                    details.errorMessage = "Certificate uses weak algorithm";
                    return details;
                } else {
                    details.warnings.push_back("Certificate uses weak algorithm");
                }
            }
        }

        // Check root trust
        const auto& root = chain.back();
        details.trustLevel = GetTrustLevelInternal(root);

        if (details.trustLevel == TrustLevel::Untrusted) {
            if ((options.flags & ValidationFlags::IgnoreUntrustedRoot) == ValidationFlags::None) {
                details.result = ValidationResult::UntrustedRoot;
                details.errorMessage = "Root certificate is not trusted";
                return details;
            } else {
                details.warnings.push_back("Root certificate is not trusted");
            }
        }

        // Revocation checking
        if ((options.flags & ValidationFlags::IgnoreRevocation) == ValidationFlags::None) {
            for (size_t i = 0; i < chain.size() - 1; ++i) {
                auto revStatus = CheckRevocationInternal(chain[i]);
                if (revStatus == RevocationStatus::Revoked) {
                    details.result = ValidationResult::Revoked;
                    details.revocationStatus = revStatus;
                    details.errorMessage = "Certificate at index " + std::to_string(i) + " is revoked";
                    return details;
                }
                if (revStatus == RevocationStatus::Unknown) {
                    details.revocationStatus = RevocationStatus::Unknown;
                }
            }
        }

        details.result = ValidationResult::Valid;
        return details;
    }

    [[nodiscard]] ValidationDetails VerifyFile(
        const std::wstring& filePath,
        const ValidationOptions& options) {

        ValidationDetails details;

        // Read file
        try {
            if (!std::filesystem::exists(filePath)) {
                details.result = ValidationResult::Error;
                details.errorMessage = "File does not exist";
                return details;
            }

            auto fileSize = std::filesystem::file_size(filePath);
            if (fileSize > CertificateConstants::MAX_CERTIFICATE_SIZE) {
                details.result = ValidationResult::Error;
                details.errorMessage = "File too large";
                return details;
            }

            std::vector<uint8_t> data(static_cast<size_t>(fileSize));

            HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                details.result = ValidationResult::Error;
                details.errorMessage = "Failed to open file";
                details.errorCode = static_cast<int32_t>(GetLastError());
                return details;
            }

            DWORD bytesRead = 0;
            BOOL success = ReadFile(hFile, data.data(), static_cast<DWORD>(fileSize),
                                    &bytesRead, nullptr);
            CloseHandle(hFile);

            if (!success || bytesRead != fileSize) {
                details.result = ValidationResult::Error;
                details.errorMessage = "Failed to read file";
                return details;
            }

            return VerifyCertificateWithOptions(
                std::span<const uint8_t>(data.data(), data.size()), options);

        } catch (const std::exception& e) {
            details.result = ValidationResult::Error;
            details.errorMessage = std::string("Exception: ") + e.what();
            return details;
        }
    }

    void VerifyCertificateAsync(
        std::span<const uint8_t> certData,
        ValidationCallback callback,
        const ValidationOptions& options) {

        // Copy data for async operation
        std::vector<uint8_t> data(certData.begin(), certData.end());

        std::thread([this, data = std::move(data), callback, options]() {
            auto details = VerifyCertificateWithOptions(
                std::span<const uint8_t>(data.data(), data.size()), options);
            if (callback) {
                try {
                    callback(details);
                } catch (...) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"Validation callback threw exception");
                }
            }
        }).detach();
    }

    // ========================================================================
    // REVOCATION CHECKING
    // ========================================================================

    [[nodiscard]] bool IsRevoked(const std::wstring& serialNumber) {
        // This is a simplified check - in production would query OCSP/CRL
        std::shared_lock lock(m_mutex);

        for (const auto& [fp, reason] : m_blockedCerts) {
            // Would need certificate lookup by serial
        }

        return false;
    }

    [[nodiscard]] RevocationStatus CheckRevocation(const CertificateInfo& cert) {
        return CheckRevocationInternal(cert);
    }

    [[nodiscard]] RevocationStatus CheckOCSP(
        const CertificateInfo& cert,
        const CertificateInfo& issuer) {

        if (!m_config.enableOCSP) {
            return RevocationStatus::Unknown;
        }

        m_stats.ocspChecks.fetch_add(1, std::memory_order_relaxed);

        // Check OCSP cache
        {
            std::shared_lock lock(m_mutex);
            auto it = m_ocspCache.find(cert.sha256Fingerprint);
            if (it != m_ocspCache.end()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.cacheTime).count();
                if (age < m_config.ocspCacheDurationSecs) {
                    m_stats.ocspCacheHits.fetch_add(1, std::memory_order_relaxed);
                    return it->second.status;
                }
            }
        }

        if (cert.ocspUrls.empty()) {
            return RevocationStatus::OCSPNotAvailable;
        }

        // In production: send OCSP request to responder
        // For now, return Good (would need HTTP client)

        RevocationStatus status = RevocationStatus::Good;

        // Cache result
        {
            std::unique_lock lock(m_mutex);
            if (m_ocspCache.size() < CertificateConstants::MAX_CACHED_OCSP_RESPONSES) {
                m_ocspCache[cert.sha256Fingerprint] = {status, Clock::now()};
            }
        }

        return status;
    }

    [[nodiscard]] RevocationStatus CheckCRL(
        const CertificateInfo& cert,
        const CertificateInfo& issuer) {

        if (!m_config.enableCRL) {
            return RevocationStatus::Unknown;
        }

        m_stats.crlChecks.fetch_add(1, std::memory_order_relaxed);

        // Check CRL cache
        std::string cacheKey = BytesToHex(issuer.sha256Fingerprint.data(),
                                          issuer.sha256Fingerprint.size());
        {
            std::shared_lock lock(m_mutex);
            auto it = m_crlCache.find(cacheKey);
            if (it != m_crlCache.end()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    Clock::now() - it->second.fetchTime).count();
                if (age < m_config.crlCacheDurationSecs) {
                    m_stats.crlCacheHits.fetch_add(1, std::memory_order_relaxed);

                    // Check if serial is in CRL
                    if (it->second.revokedSerials.find(cert.serialNumber) !=
                        it->second.revokedSerials.end()) {
                        return RevocationStatus::Revoked;
                    }
                    return RevocationStatus::Good;
                }
            }
        }

        if (cert.crlDistributionPoints.empty()) {
            return RevocationStatus::CRLNotAvailable;
        }

        // In production: download and parse CRL
        // For now, return Good

        return RevocationStatus::Good;
    }

    [[nodiscard]] std::optional<std::tuple<RevocationStatus, RevocationReason, SystemTimePoint>>
        GetRevocationDetails(const CertificateInfo& cert) {

        auto status = CheckRevocationInternal(cert);
        if (status == RevocationStatus::Revoked) {
            return std::make_tuple(status, RevocationReason::Unspecified, GetCurrentSystemTime());
        }
        return std::nullopt;
    }

    // ========================================================================
    // CHAIN BUILDING
    // ========================================================================

    [[nodiscard]] std::optional<std::vector<CertificateInfo>> BuildChain(
        const CertificateInfo& endEntityCert) {

        return BuildChainWithOptions(endEntityCert, ValidationOptions{});
    }

    [[nodiscard]] std::optional<std::vector<CertificateInfo>> BuildChainWithOptions(
        const CertificateInfo& endEntityCert,
        const ValidationOptions& options) {

        std::vector<CertificateInfo> chain;
        chain.push_back(endEntityCert);

        if (endEntityCert.isSelfSigned) {
            return chain;
        }

        // Use Windows chain building
        if (!endEntityCert.rawData.empty()) {
            CertContextPtr certCtx(CertCreateCertificateContext(
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                endEntityCert.rawData.data(),
                static_cast<DWORD>(endEntityCert.rawData.size())));

            if (!certCtx) {
                m_stats.chainBuildFailures.fetch_add(1, std::memory_order_relaxed);
                return std::nullopt;
            }

            CERT_CHAIN_PARA chainPara{};
            chainPara.cbSize = sizeof(chainPara);

            CertChainPtr chainCtx;
            if (!CertGetCertificateChain(
                    nullptr,
                    certCtx.Get(),
                    nullptr,
                    nullptr,
                    &chainPara,
                    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
                    nullptr,
                    chainCtx.AddressOf())) {

                m_stats.chainBuildFailures.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(LOG_CATEGORY, L"CertGetCertificateChain failed: 0x%08X",
                            GetLastError());
                return std::nullopt;
            }

            // Extract chain
            if (chainCtx.Get()->cChain > 0) {
                auto* simpleChain = chainCtx.Get()->rgpChain[0];
                chain.clear();

                for (DWORD i = 0; i < simpleChain->cElement; ++i) {
                    auto* element = simpleChain->rgpElement[i];
                    auto* pCert = element->pCertContext;

                    std::span<const uint8_t> certSpan(
                        pCert->pbCertEncoded, pCert->cbCertEncoded);
                    auto certInfo = ParseCertificateContext(pCert, certSpan);
                    if (certInfo) {
                        chain.push_back(std::move(*certInfo));
                    }
                }
            }
        }

        if (chain.size() > CertificateConstants::MAX_CHAIN_LENGTH) {
            m_stats.chainBuildFailures.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }

        return chain;
    }

    void SetCertificateFetchCallback(CertificateFetchCallback callback) {
        std::unique_lock lock(m_mutex);
        m_fetchCallback = std::move(callback);
    }

    // ========================================================================
    // TRUST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool AddTrustedRoot(std::span<const uint8_t> certData) {
        auto certInfo = ParseCertificate(certData);
        if (!certInfo) {
            return false;
        }

        std::unique_lock lock(m_mutex);

        if (m_customRoots.size() >= CertificateConstants::MAX_CUSTOM_ROOTS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Maximum custom roots reached");
            return false;
        }

        m_customRoots[certInfo->sha256Fingerprint] = *certInfo;
        SS_LOG_INFO(LOG_CATEGORY, L"Added trusted root: %hs",
                    certInfo->subject.commonName.c_str());
        return true;
    }

    [[nodiscard]] bool RemoveTrustedRoot(const CertificateFingerprint& fingerprint) {
        std::unique_lock lock(m_mutex);
        return m_customRoots.erase(fingerprint) > 0;
    }

    [[nodiscard]] bool IsTrustedRoot(const CertificateInfo& cert) const {
        return GetTrustLevelInternal(cert) >= TrustLevel::CustomRoot;
    }

    [[nodiscard]] TrustLevel GetTrustLevel(const CertificateInfo& cert) const {
        return GetTrustLevelInternal(cert);
    }

    [[nodiscard]] std::vector<CertificateInfo> GetTrustedRoots() const {
        std::shared_lock lock(m_mutex);

        std::vector<CertificateInfo> roots;
        roots.reserve(m_customRoots.size());

        for (const auto& [fp, cert] : m_customRoots) {
            roots.push_back(cert);
        }

        return roots;
    }

    [[nodiscard]] bool ReloadSystemTrustStore() {
        std::unique_lock lock(m_mutex);

        m_rootStore.reset();
        m_caStore.reset();

        m_rootStore.reset(new CertStorePtr(
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                L"ROOT")));

        m_caStore.reset(new CertStorePtr(
            CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                L"CA")));

        SS_LOG_INFO(LOG_CATEGORY, L"System trust store reloaded");
        return m_rootStore && m_rootStore->IsValid();
    }

    // ========================================================================
    // CERTIFICATE PINNING
    // ========================================================================

    [[nodiscard]] bool PinCertificate(
        std::string_view hostname,
        const CertificateFingerprint& fingerprint) {

        std::unique_lock lock(m_mutex);

        if (m_pinnedCerts.size() >= CertificateConstants::MAX_PINNED_CERTIFICATES) {
            SS_LOG_WARN(LOG_CATEGORY, L"Maximum pinned certificates reached");
            return false;
        }

        m_pinnedCerts[std::string(hostname)] = fingerprint;
        SS_LOG_INFO(LOG_CATEGORY, L"Pinned certificate for %hs",
                    std::string(hostname).c_str());
        return true;
    }

    [[nodiscard]] bool PinCertificateFromData(
        std::string_view hostname,
        std::span<const uint8_t> certData) {

        auto fp = CalculateFingerprint(certData);
        return PinCertificate(hostname, fp);
    }

    [[nodiscard]] bool UnpinCertificate(std::string_view hostname) {
        std::unique_lock lock(m_mutex);
        return m_pinnedCerts.erase(std::string(hostname)) > 0;
    }

    [[nodiscard]] bool IsPinned(std::string_view hostname) const {
        std::shared_lock lock(m_mutex);
        return m_pinnedCerts.find(std::string(hostname)) != m_pinnedCerts.end();
    }

    [[nodiscard]] bool VerifyPinnedCertificate(
        std::string_view hostname,
        const CertificateInfo& cert) const {

        std::shared_lock lock(m_mutex);

        auto it = m_pinnedCerts.find(std::string(hostname));
        if (it == m_pinnedCerts.end()) {
            return true;  // Not pinned, allow
        }

        return it->second == cert.sha256Fingerprint;
    }

    [[nodiscard]] std::unordered_map<std::string, CertificateFingerprint>
        GetPinnedCertificates() const {

        std::shared_lock lock(m_mutex);
        return m_pinnedCerts;
    }

    // ========================================================================
    // BLOCKLIST MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool BlockCertificate(
        const CertificateFingerprint& fingerprint,
        std::string_view reason) {

        std::unique_lock lock(m_mutex);
        m_blockedCerts[fingerprint] = std::string(reason);
        SS_LOG_INFO(LOG_CATEGORY, L"Blocked certificate");
        return true;
    }

    [[nodiscard]] bool UnblockCertificate(const CertificateFingerprint& fingerprint) {
        std::unique_lock lock(m_mutex);
        return m_blockedCerts.erase(fingerprint) > 0;
    }

    [[nodiscard]] bool IsBlocked(const CertificateInfo& cert) const {
        return IsBlockedInternal(cert.sha256Fingerprint);
    }

    [[nodiscard]] std::vector<std::pair<CertificateFingerprint, std::string>>
        GetBlockedCertificates() const {

        std::shared_lock lock(m_mutex);

        std::vector<std::pair<CertificateFingerprint, std::string>> result;
        result.reserve(m_blockedCerts.size());

        for (const auto& [fp, reason] : m_blockedCerts) {
            result.emplace_back(fp, reason);
        }

        return result;
    }

    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================

    void ClearCaches() {
        std::unique_lock lock(m_mutex);
        m_validationCache.clear();
        m_ocspCache.clear();
        m_crlCache.clear();
        SS_LOG_INFO(LOG_CATEGORY, L"All caches cleared");
    }

    void ClearOCSPCache() {
        std::unique_lock lock(m_mutex);
        m_ocspCache.clear();
    }

    void ClearCRLCache() {
        std::unique_lock lock(m_mutex);
        m_crlCache.clear();
    }

    void ClearValidationCache() {
        std::unique_lock lock(m_mutex);
        m_validationCache.clear();
    }

    [[nodiscard]] std::unordered_map<std::string, size_t> GetCacheStats() const {
        std::shared_lock lock(m_mutex);

        return {
            {"validationCache", m_validationCache.size()},
            {"ocspCache", m_ocspCache.size()},
            {"crlCache", m_crlCache.size()},
            {"customRoots", m_customRoots.size()},
            {"pinnedCerts", m_pinnedCerts.size()},
            {"blockedCerts", m_blockedCerts.size()}
        };
    }

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    [[nodiscard]] CertificateFingerprint CalculateFingerprint(
        std::span<const uint8_t> certData) const {

        CertificateFingerprint fp{};

        DWORD hashSize = static_cast<DWORD>(fp.size());
        if (!CryptHashCertificate2(
                BCRYPT_SHA256_ALGORITHM,
                0,
                nullptr,
                certData.data(),
                static_cast<DWORD>(certData.size()),
                fp.data(),
                &hashSize)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CryptHashCertificate2 failed");
        }

        return fp;
    }

    [[nodiscard]] CertificateThumbprint CalculateThumbprint(
        std::span<const uint8_t> certData) const {

        CertificateThumbprint tp{};

        DWORD hashSize = static_cast<DWORD>(tp.size());
        if (!CryptHashCertificate2(
                BCRYPT_SHA1_ALGORITHM,
                0,
                nullptr,
                certData.data(),
                static_cast<DWORD>(certData.size()),
                tp.data(),
                &hashSize)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CryptHashCertificate2 failed");
        }

        return tp;
    }

    [[nodiscard]] bool IsKeySizeSufficient(const PublicKeyInfo& keyInfo) const {
        switch (keyInfo.type) {
            case KeyType::RSA:
            case KeyType::DSA:
                return keyInfo.keySizeBits >= m_config.minRSAKeySize;
            case KeyType::ECDSA:
            case KeyType::ECDH:
            case KeyType::EdDSA:
                return keyInfo.keySizeBits >= m_config.minECCKeySize;
            default:
                return true;
        }
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] CertificateValidatorStatistics GetStatistics() const {
        CertificateValidatorStatistics copy;
        copy.totalValidations.store(m_stats.totalValidations.load(std::memory_order_relaxed));
        copy.validCertificates.store(m_stats.validCertificates.load(std::memory_order_relaxed));
        copy.invalidCertificates.store(m_stats.invalidCertificates.load(std::memory_order_relaxed));
        copy.expiredCertificates.store(m_stats.expiredCertificates.load(std::memory_order_relaxed));
        copy.revokedCertificates.store(m_stats.revokedCertificates.load(std::memory_order_relaxed));
        copy.ocspChecks.store(m_stats.ocspChecks.load(std::memory_order_relaxed));
        copy.ocspCacheHits.store(m_stats.ocspCacheHits.load(std::memory_order_relaxed));
        copy.crlChecks.store(m_stats.crlChecks.load(std::memory_order_relaxed));
        copy.crlCacheHits.store(m_stats.crlCacheHits.load(std::memory_order_relaxed));
        copy.validationCacheHits.store(m_stats.validationCacheHits.load(std::memory_order_relaxed));
        copy.chainBuildFailures.store(m_stats.chainBuildFailures.load(std::memory_order_relaxed));
        copy.avgValidationTimeUs.store(m_stats.avgValidationTimeUs.load(std::memory_order_relaxed));
        copy.startTime = m_stats.startTime;
        return copy;
    }

    void ResetStatistics() {
        m_stats.Reset();
        SS_LOG_INFO(LOG_CATEGORY, L"Statistics reset");
    }

    [[nodiscard]] std::string ExportReport() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"module\": \"CertificateValidator\",\n";
        oss << "  \"version\": \"" << CertificateValidator::GetVersionString() << "\",\n";
        oss << "  \"status\": " << static_cast<int>(m_status.load()) << ",\n";
        oss << "  \"statistics\": " << m_stats.ToJson() << ",\n";

        auto cacheStats = GetCacheStats();
        oss << "  \"caches\": {\n";
        bool first = true;
        for (const auto& [name, size] : cacheStats) {
            if (!first) oss << ",\n";
            oss << "    \"" << name << "\": " << size;
            first = false;
        }
        oss << "\n  }\n";
        oss << "}\n";

        return oss.str();
    }

    [[nodiscard]] bool SelfTest() {
        SS_LOG_INFO(LOG_CATEGORY, L"Running CertificateValidator self-test...");

        bool allPassed = true;

        // Test 1: Status check
        if (m_status != ModuleStatus::Running) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Module not running");
            allPassed = false;
        }

        // Test 2: Fingerprint calculation
        {
            std::vector<uint8_t> testData = {0x30, 0x82, 0x01, 0x00};
            auto fp = CalculateFingerprint(std::span<const uint8_t>(testData.data(), testData.size()));
            bool allZero = true;
            for (auto b : fp) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            if (allZero) {
                SS_LOG_WARN(LOG_CATEGORY, L"Self-test: Fingerprint calculation may have issues");
            }
        }

        // Test 3: Cache operations
        {
            CertificateFingerprint testFp{};
            testFp[0] = 0xFF;

            BlockCertificate(testFp, "Self-test");
            if (!IsBlockedInternal(testFp)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test FAILED: Block/unblock not working");
                allPassed = false;
            }
            UnblockCertificate(testFp);
        }

        // Test 4: Trust store access
        if (m_config.useSystemTrustStore) {
            if (!m_rootStore || !m_rootStore->IsValid()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Self-test: System root store not accessible");
            }
        }

        if (allPassed) {
            SS_LOG_INFO(LOG_CATEGORY, L"CertificateValidator self-test PASSED");
        } else {
            SS_LOG_ERROR(LOG_CATEGORY, L"CertificateValidator self-test FAILED");
        }

        return allPassed;
    }

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    [[nodiscard]] bool PEMToDER(std::span<const uint8_t> pemData, std::vector<uint8_t>& derOut) {
        std::string pem(reinterpret_cast<const char*>(pemData.data()), pemData.size());

        // Find BEGIN/END markers
        auto beginPos = pem.find("-----BEGIN");
        auto endPos = pem.find("-----END");

        if (beginPos == std::string::npos || endPos == std::string::npos) {
            return false;
        }

        // Find end of first line
        auto dataStart = pem.find('\n', beginPos);
        if (dataStart == std::string::npos) return false;
        dataStart++;

        // Find start of END line
        auto dataEnd = pem.rfind('\n', endPos);
        if (dataEnd == std::string::npos || dataEnd <= dataStart) return false;

        std::string base64Data = pem.substr(dataStart, dataEnd - dataStart);

        // Remove whitespace
        base64Data.erase(std::remove_if(base64Data.begin(), base64Data.end(),
            [](char c) { return std::isspace(static_cast<unsigned char>(c)); }),
            base64Data.end());

        // Decode base64
        DWORD decodedSize = 0;
        if (!CryptStringToBinaryA(base64Data.c_str(), static_cast<DWORD>(base64Data.size()),
                                   CRYPT_STRING_BASE64, nullptr, &decodedSize, nullptr, nullptr)) {
            return false;
        }

        derOut.resize(decodedSize);
        if (!CryptStringToBinaryA(base64Data.c_str(), static_cast<DWORD>(base64Data.size()),
                                   CRYPT_STRING_BASE64, derOut.data(), &decodedSize, nullptr, nullptr)) {
            return false;
        }

        return true;
    }

    [[nodiscard]] std::optional<CertificateInfo> ParseCertificateContext(
        PCCERT_CONTEXT pCert,
        std::span<const uint8_t> rawData) {

        CertificateInfo info;

        // Copy raw data
        info.rawData.assign(rawData.begin(), rawData.end());

        // Version
        info.version = pCert->pCertInfo->dwVersion + 1;

        // Serial number
        auto& serialBlob = pCert->pCertInfo->SerialNumber;
        std::vector<uint8_t> serialReversed(serialBlob.pbData,
                                            serialBlob.pbData + serialBlob.cbData);
        std::reverse(serialReversed.begin(), serialReversed.end());
        info.serialNumber = BytesToHex(serialReversed.data(), serialReversed.size());

        // Subject
        info.subject = ParseDistinguishedName(&pCert->pCertInfo->Subject);

        // Issuer
        info.issuer = ParseDistinguishedName(&pCert->pCertInfo->Issuer);

        // Self-signed check
        info.isSelfSigned = (info.subject == info.issuer);

        // Validity period
        info.validity.notBefore = FileTimeToSystemTime(pCert->pCertInfo->NotBefore);
        info.validity.notAfter = FileTimeToSystemTime(pCert->pCertInfo->NotAfter);

        // Signature algorithm
        info.signatureAlgorithmOID = pCert->pCertInfo->SignatureAlgorithm.pszObjId;
        info.signatureAlgorithm = ParseSignatureAlgorithm(info.signatureAlgorithmOID);

        // Public key
        info.publicKey = ParsePublicKeyInfo(&pCert->pCertInfo->SubjectPublicKeyInfo);

        // Fingerprints
        info.sha256Fingerprint = CalculateFingerprint(rawData);
        info.sha1Thumbprint = CalculateThumbprint(rawData);

        // Extensions
        for (DWORD i = 0; i < pCert->pCertInfo->cExtension; ++i) {
            auto& ext = pCert->pCertInfo->rgExtension[i];
            ParseExtension(ext, info);
        }

        // Determine certificate type
        info.type = DetermineCertificateType(info);

        return info;
    }

    [[nodiscard]] DistinguishedName ParseDistinguishedName(PCERT_NAME_BLOB pName) {
        DistinguishedName dn;

        DWORD size = CertNameToStrA(X509_ASN_ENCODING, pName,
                                     CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                                     nullptr, 0);
        if (size > 0) {
            std::vector<char> buffer(size);
            CertNameToStrA(X509_ASN_ENCODING, pName,
                           CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG,
                           buffer.data(), size);
            dn.raw = buffer.data();
        }

        // Parse individual RDNs
        auto getRDN = [&](LPCSTR oid) -> std::string {
            DWORD size = CertGetNameStringA(nullptr, CERT_NAME_ATTR_TYPE, 0,
                                            const_cast<void*>(static_cast<const void*>(oid)),
                                            nullptr, 0);
            // Simplified - would need actual cert context
            return "";
        };

        // Extract CN from raw string
        auto extractField = [&](const std::string& prefix) -> std::string {
            auto pos = dn.raw.find(prefix);
            if (pos == std::string::npos) return "";
            pos += prefix.length();
            auto end = dn.raw.find(',', pos);
            if (end == std::string::npos) end = dn.raw.length();
            return dn.raw.substr(pos, end - pos);
        };

        dn.commonName = extractField("CN=");
        dn.organization = extractField("O=");
        dn.organizationalUnit = extractField("OU=");
        dn.country = extractField("C=");
        dn.state = extractField("ST=");
        dn.locality = extractField("L=");

        return dn;
    }

    [[nodiscard]] SignatureAlgorithm ParseSignatureAlgorithm(const std::string& oid) {
        if (oid == "1.2.840.113549.1.1.11") return SignatureAlgorithm::SHA256_RSA;
        if (oid == "1.2.840.113549.1.1.12") return SignatureAlgorithm::SHA384_RSA;
        if (oid == "1.2.840.113549.1.1.13") return SignatureAlgorithm::SHA512_RSA;
        if (oid == "1.2.840.113549.1.1.5") return SignatureAlgorithm::SHA1_RSA;
        if (oid == "1.2.840.113549.1.1.4") return SignatureAlgorithm::MD5_RSA;
        if (oid == "1.2.840.10045.4.3.2") return SignatureAlgorithm::SHA256_ECDSA;
        if (oid == "1.2.840.10045.4.3.3") return SignatureAlgorithm::SHA384_ECDSA;
        if (oid == "1.2.840.10045.4.3.4") return SignatureAlgorithm::SHA512_ECDSA;
        if (oid == "1.2.840.113549.1.1.10") return SignatureAlgorithm::RSA_PSS;
        return SignatureAlgorithm::Unknown;
    }

    [[nodiscard]] PublicKeyInfo ParsePublicKeyInfo(PCERT_PUBLIC_KEY_INFO pKeyInfo) {
        PublicKeyInfo keyInfo;

        keyInfo.algorithmOID = pKeyInfo->Algorithm.pszObjId;

        // Determine key type
        if (keyInfo.algorithmOID.find("1.2.840.113549.1.1") == 0) {
            keyInfo.type = KeyType::RSA;
        } else if (keyInfo.algorithmOID.find("1.2.840.10045") == 0) {
            keyInfo.type = KeyType::ECDSA;
        } else if (keyInfo.algorithmOID.find("1.2.840.10040.4.1") == 0) {
            keyInfo.type = KeyType::DSA;
        }

        // Get key size
        DWORD keySize = 0;
        if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
                               pKeyInfo->PublicKey.pbData, pKeyInfo->PublicKey.cbData,
                               0, nullptr, &keySize)) {
            // RSA key - size in bits is cbData * 8 roughly
            keyInfo.keySizeBits = pKeyInfo->PublicKey.cbData * 8;
        } else {
            // Estimate based on blob size
            keyInfo.keySizeBits = (pKeyInfo->PublicKey.cbData - 1) * 8;
        }

        // Copy public key data
        keyInfo.publicKeyData.assign(pKeyInfo->PublicKey.pbData,
                                      pKeyInfo->PublicKey.pbData + pKeyInfo->PublicKey.cbData);

        return keyInfo;
    }

    void ParseExtension(const CERT_EXTENSION& ext, CertificateInfo& info) {
        std::string oid = ext.pszObjId;

        if (oid == szOID_BASIC_CONSTRAINTS2) {
            DWORD size = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                                   ext.Value.pbData, ext.Value.cbData,
                                   0, nullptr, &size) && size > 0) {
                std::vector<uint8_t> buffer(size);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                                       ext.Value.pbData, ext.Value.cbData,
                                       0, buffer.data(), &size)) {
                    auto* bc = reinterpret_cast<CERT_BASIC_CONSTRAINTS2_INFO*>(buffer.data());
                    info.isCA = bc->fCA != FALSE;
                    if (bc->fPathLenConstraint) {
                        info.pathLengthConstraint = static_cast<int32_t>(bc->dwPathLenConstraint);
                    }
                }
            }
        } else if (oid == szOID_KEY_USAGE) {
            if (ext.Value.cbData >= 1) {
                uint16_t usage = ext.Value.pbData[0];
                if (ext.Value.cbData >= 2) {
                    usage |= static_cast<uint16_t>(ext.Value.pbData[1]) << 8;
                }
                info.keyUsage = static_cast<KeyUsage>(usage);
            }
        } else if (oid == szOID_ENHANCED_KEY_USAGE) {
            DWORD size = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
                                   ext.Value.pbData, ext.Value.cbData,
                                   0, nullptr, &size) && size > 0) {
                std::vector<uint8_t> buffer(size);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE,
                                       ext.Value.pbData, ext.Value.cbData,
                                       0, buffer.data(), &size)) {
                    auto* eku = reinterpret_cast<CERT_ENHKEY_USAGE*>(buffer.data());
                    for (DWORD i = 0; i < eku->cUsageIdentifier; ++i) {
                        std::string ekuOid = eku->rgpszUsageIdentifier[i];
                        if (ekuOid == szOID_PKIX_KP_SERVER_AUTH) {
                            info.extKeyUsage = info.extKeyUsage | ExtendedKeyUsage::ServerAuth;
                        } else if (ekuOid == szOID_PKIX_KP_CLIENT_AUTH) {
                            info.extKeyUsage = info.extKeyUsage | ExtendedKeyUsage::ClientAuth;
                        } else if (ekuOid == szOID_PKIX_KP_CODE_SIGNING) {
                            info.extKeyUsage = info.extKeyUsage | ExtendedKeyUsage::CodeSigning;
                        } else if (ekuOid == szOID_PKIX_KP_EMAIL_PROTECTION) {
                            info.extKeyUsage = info.extKeyUsage | ExtendedKeyUsage::EmailProtection;
                        } else if (ekuOid == szOID_PKIX_KP_TIMESTAMP_SIGNING) {
                            info.extKeyUsage = info.extKeyUsage | ExtendedKeyUsage::Timestamping;
                        }
                    }
                }
            }
        } else if (oid == szOID_CRL_DIST_POINTS) {
            DWORD size = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_CRL_DIST_POINTS,
                                   ext.Value.pbData, ext.Value.cbData,
                                   0, nullptr, &size) && size > 0) {
                std::vector<uint8_t> buffer(size);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_CRL_DIST_POINTS,
                                       ext.Value.pbData, ext.Value.cbData,
                                       0, buffer.data(), &size)) {
                    auto* cdp = reinterpret_cast<CRL_DIST_POINTS_INFO*>(buffer.data());
                    for (DWORD i = 0; i < cdp->cDistPoint; ++i) {
                        auto& dp = cdp->rgDistPoint[i];
                        if (dp.DistPointName.dwDistPointNameChoice == CRL_DIST_POINT_FULL_NAME) {
                            for (DWORD j = 0; j < dp.DistPointName.FullName.cAltEntry; ++j) {
                                auto& entry = dp.DistPointName.FullName.rgAltEntry[j];
                                if (entry.dwAltNameChoice == CERT_ALT_NAME_URL) {
                                    info.crlDistributionPoints.push_back(
                                        WideToUtf8(entry.pwszURL));
                                }
                            }
                        }
                    }
                }
            }
        } else if (oid == szOID_AUTHORITY_INFO_ACCESS) {
            DWORD size = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_AUTHORITY_INFO_ACCESS,
                                   ext.Value.pbData, ext.Value.cbData,
                                   0, nullptr, &size) && size > 0) {
                std::vector<uint8_t> buffer(size);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_AUTHORITY_INFO_ACCESS,
                                       ext.Value.pbData, ext.Value.cbData,
                                       0, buffer.data(), &size)) {
                    auto* aia = reinterpret_cast<CERT_AUTHORITY_INFO_ACCESS*>(buffer.data());
                    for (DWORD i = 0; i < aia->cAccDescr; ++i) {
                        auto& ad = aia->rgAccDescr[i];
                        if (ad.AccessLocation.dwAltNameChoice == CERT_ALT_NAME_URL) {
                            std::string method = ad.pszAccessMethod;
                            std::string url = WideToUtf8(ad.AccessLocation.pwszURL);

                            if (method == szOID_PKIX_OCSP) {
                                info.ocspUrls.push_back(url);
                            } else if (method == szOID_PKIX_CA_ISSUERS) {
                                info.caIssuersUrls.push_back(url);
                            }
                        }
                    }
                }
            }
        }

        // Store extension
        CertificateExtension certExt;
        certExt.oid = oid;
        certExt.critical = ext.fCritical != FALSE;
        certExt.value.assign(ext.Value.pbData, ext.Value.pbData + ext.Value.cbData);
        info.extensions.push_back(certExt);
    }

    [[nodiscard]] CertificateType DetermineCertificateType(const CertificateInfo& info) {
        if (info.isSelfSigned && info.isCA) {
            return CertificateType::RootCA;
        }
        if (info.isCA) {
            return CertificateType::IntermediateCA;
        }
        if (info.isSelfSigned) {
            return CertificateType::SelfSigned;
        }
        if ((info.extKeyUsage & ExtendedKeyUsage::CodeSigning) != ExtendedKeyUsage::None) {
            return CertificateType::CodeSigning;
        }
        if ((info.extKeyUsage & ExtendedKeyUsage::ServerAuth) != ExtendedKeyUsage::None) {
            return CertificateType::ServerAuth;
        }
        if ((info.extKeyUsage & ExtendedKeyUsage::ClientAuth) != ExtendedKeyUsage::None) {
            return CertificateType::ClientAuth;
        }
        if ((info.extKeyUsage & ExtendedKeyUsage::EmailProtection) != ExtendedKeyUsage::None) {
            return CertificateType::EmailSigning;
        }
        if ((info.extKeyUsage & ExtendedKeyUsage::Timestamping) != ExtendedKeyUsage::None) {
            return CertificateType::Timestamping;
        }
        return CertificateType::EndEntity;
    }

    [[nodiscard]] ValidationDetails VerifyCertificateInternal(
        const CertificateInfo& certInfo,
        const ValidationOptions& options) {

        ValidationDetails details;
        details.validationTime = Clock::now();

        // Check validity period
        if (certInfo.validity.IsExpired()) {
            if ((options.flags & ValidationFlags::IgnoreExpired) == ValidationFlags::None) {
                details.result = ValidationResult::Expired;
                details.errorMessage = "Certificate has expired";
                return details;
            } else {
                details.warnings.push_back("Certificate is expired");
            }
        }

        if (certInfo.validity.IsNotYetValid()) {
            if ((options.flags & ValidationFlags::IgnoreNotYetValid) == ValidationFlags::None) {
                details.result = ValidationResult::NotYetValid;
                details.errorMessage = "Certificate is not yet valid";
                return details;
            } else {
                details.warnings.push_back("Certificate is not yet valid");
            }
        }

        // Check weak algorithms
        if (!m_config.allowWeakAlgorithms &&
            CertificateValidator::IsWeakAlgorithm(certInfo.signatureAlgorithm)) {
            if ((options.flags & ValidationFlags::IgnoreWeakAlgorithm) == ValidationFlags::None) {
                details.result = ValidationResult::WeakAlgorithm;
                details.errorMessage = "Certificate uses weak signature algorithm";
                return details;
            } else {
                details.warnings.push_back("Certificate uses weak algorithm");
            }
        }

        // Check key size
        if (!IsKeySizeSufficient(certInfo.publicKey)) {
            details.warnings.push_back("Certificate key size is below recommended minimum");
        }

        // Build and verify chain
        auto chain = BuildChainWithOptions(certInfo, options);
        if (!chain) {
            details.result = ValidationResult::ChainBuildingFailed;
            details.errorMessage = "Failed to build certificate chain";
            return details;
        }

        details.chain = *chain;

        // Verify chain
        auto chainDetails = VerifyChain(*chain, options);
        if (!chainDetails.IsValid()) {
            return chainDetails;
        }

        details.trustLevel = chainDetails.trustLevel;
        details.revocationStatus = chainDetails.revocationStatus;
        details.warnings.insert(details.warnings.end(),
                                 chainDetails.warnings.begin(),
                                 chainDetails.warnings.end());

        // Hostname verification
        if (!options.expectedHostname.empty()) {
            if (!VerifyHostname(certInfo, options.expectedHostname)) {
                details.result = ValidationResult::NameMismatch;
                details.errorMessage = "Hostname mismatch";
                return details;
            }
        }

        // Certificate pinning check
        if (!options.expectedHostname.empty()) {
            if (!VerifyPinnedCertificate(options.expectedHostname, certInfo)) {
                details.result = ValidationResult::Invalid;
                details.errorMessage = "Certificate pinning failed";
                return details;
            }
        }

        details.result = ValidationResult::Valid;
        return details;
    }

    [[nodiscard]] bool VerifyHostname(const CertificateInfo& cert,
                                       const std::string& hostname) const {
        // Check CN
        if (MatchHostname(cert.subject.commonName, hostname)) {
            return true;
        }

        // Check SANs
        for (const auto& dns : cert.subjectAltName.dnsNames) {
            if (MatchHostname(dns, hostname)) {
                return true;
            }
        }

        return false;
    }

    [[nodiscard]] bool MatchHostname(const std::string& pattern,
                                      const std::string& hostname) const {
        if (pattern.empty() || hostname.empty()) return false;

        // Exact match
        if (_stricmp(pattern.c_str(), hostname.c_str()) == 0) {
            return true;
        }

        // Wildcard match
        if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
            std::string suffix = pattern.substr(1);
            if (hostname.size() > suffix.size()) {
                std::string hostSuffix = hostname.substr(hostname.size() - suffix.size());
                if (_stricmp(suffix.c_str(), hostSuffix.c_str()) == 0) {
                    // Ensure wildcard only matches single level
                    std::string prefix = hostname.substr(0, hostname.size() - suffix.size());
                    if (prefix.find('.') == std::string::npos) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    [[nodiscard]] RevocationStatus CheckRevocationInternal(const CertificateInfo& cert) {
        if ((m_config.defaultFlags & ValidationFlags::IgnoreRevocation) != ValidationFlags::None) {
            return RevocationStatus::Unknown;
        }

        // Prefer OCSP if enabled
        if (m_config.enableOCSP && m_config.preferOCSP && !cert.ocspUrls.empty()) {
            CertificateInfo dummyIssuer;  // Would need real issuer
            auto status = CheckOCSP(cert, dummyIssuer);
            if (status != RevocationStatus::OCSPNotAvailable &&
                status != RevocationStatus::Unknown) {
                return status;
            }
        }

        // Fall back to CRL
        if (m_config.enableCRL && !cert.crlDistributionPoints.empty()) {
            CertificateInfo dummyIssuer;
            auto status = CheckCRL(cert, dummyIssuer);
            if (status != RevocationStatus::CRLNotAvailable &&
                status != RevocationStatus::Unknown) {
                return status;
            }
        }

        return RevocationStatus::Unknown;
    }

    [[nodiscard]] TrustLevel GetTrustLevelInternal(const CertificateInfo& cert) const {
        // Check custom roots
        {
            std::shared_lock lock(m_mutex);
            if (m_customRoots.find(cert.sha256Fingerprint) != m_customRoots.end()) {
                return TrustLevel::CustomRoot;
            }
        }

        // Check system root store
        if (m_rootStore && m_rootStore->IsValid()) {
            CertContextPtr found(CertFindCertificateInStore(
                m_rootStore->Get(),
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_SHA1_HASH,
                &cert.sha1Thumbprint,
                nullptr));

            if (found) {
                return TrustLevel::SystemRoot;
            }
        }

        if (cert.isSelfSigned) {
            return TrustLevel::SelfSigned;
        }

        return TrustLevel::Untrusted;
    }

    [[nodiscard]] bool IsBlockedInternal(const CertificateFingerprint& fp) const {
        std::shared_lock lock(m_mutex);
        return m_blockedCerts.find(fp) != m_blockedCerts.end();
    }

    [[nodiscard]] bool AddTrustedRootInternal(const std::vector<uint8_t>& certData) {
        auto certInfo = ParseCertificate(std::span<const uint8_t>(certData.data(), certData.size()));
        if (!certInfo) return false;

        m_customRoots[certInfo->sha256Fingerprint] = *certInfo;
        return true;
    }

private:
    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_mutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};

    // Configuration
    CertificateValidatorConfiguration m_config;

    // Certificate stores
    std::unique_ptr<CertStorePtr> m_rootStore;
    std::unique_ptr<CertStorePtr> m_caStore;

    // Custom trust anchors
    std::map<CertificateFingerprint, CertificateInfo> m_customRoots;

    // Pinned certificates
    std::unordered_map<std::string, CertificateFingerprint> m_pinnedCerts;

    // Blocked certificates
    std::map<CertificateFingerprint, std::string> m_blockedCerts;

    // Validation cache
    std::map<CertificateFingerprint, ValidationDetails> m_validationCache;

    // OCSP cache
    struct OCSPCacheEntry {
        RevocationStatus status;
        TimePoint cacheTime;
    };
    std::map<CertificateFingerprint, OCSPCacheEntry> m_ocspCache;

    // CRL cache
    struct CRLCacheEntry {
        std::unordered_set<std::string> revokedSerials;
        TimePoint fetchTime;
    };
    std::unordered_map<std::string, CRLCacheEntry> m_crlCache;

    // Certificate fetch callback
    CertificateFetchCallback m_fetchCallback;

    // Statistics
    CertificateValidatorStatistics m_stats;
};

// ============================================================================
// CERTIFICATEVALIDATOR PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

[[nodiscard]] CertificateValidator& CertificateValidator::Instance() noexcept {
    static CertificateValidator instance;
    return instance;
}

[[nodiscard]] bool CertificateValidator::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

CertificateValidator::CertificateValidator()
    : m_impl(std::make_unique<CertificateValidatorImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

CertificateValidator::~CertificateValidator() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
}

[[nodiscard]] bool CertificateValidator::Initialize(
    const CertificateValidatorConfiguration& config) {
    return m_impl->Initialize(config);
}

void CertificateValidator::Shutdown() {
    m_impl->Shutdown();
}

[[nodiscard]] bool CertificateValidator::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

[[nodiscard]] ModuleStatus CertificateValidator::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

[[nodiscard]] bool CertificateValidator::SetConfiguration(
    const CertificateValidatorConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

[[nodiscard]] CertificateValidatorConfiguration CertificateValidator::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

[[nodiscard]] std::optional<CertificateInfo> CertificateValidator::ParseCertificate(
    std::span<const uint8_t> certData) {
    return m_impl->ParseCertificate(certData);
}

[[nodiscard]] std::optional<CertificateInfo> CertificateValidator::ParsePEM(
    std::string_view pemData) {
    return m_impl->ParsePEM(pemData);
}

[[nodiscard]] std::vector<CertificateInfo> CertificateValidator::ParseCertificateChain(
    std::span<const uint8_t> chainData) {
    return m_impl->ParseCertificateChain(chainData);
}

[[nodiscard]] CertificateEncoding CertificateValidator::DetectEncoding(
    std::span<const uint8_t> data) {
    return m_impl->DetectEncoding(data);
}

[[nodiscard]] bool CertificateValidator::VerifyCertificate(
    const std::vector<uint8_t>& certData) {
    return m_impl->VerifyCertificate(certData);
}

[[nodiscard]] ValidationDetails CertificateValidator::VerifyCertificate(
    std::span<const uint8_t> certData,
    const ValidationOptions& options) {
    return m_impl->VerifyCertificateWithOptions(certData, options);
}

[[nodiscard]] ValidationDetails CertificateValidator::VerifyCertificate(
    const CertificateInfo& certInfo,
    const ValidationOptions& options) {
    return m_impl->VerifyCertificateInfo(certInfo, options);
}

[[nodiscard]] ValidationDetails CertificateValidator::VerifyChain(
    const std::vector<CertificateInfo>& chain,
    const ValidationOptions& options) {
    return m_impl->VerifyChain(chain, options);
}

[[nodiscard]] ValidationDetails CertificateValidator::VerifyFile(
    const std::wstring& filePath,
    const ValidationOptions& options) {
    return m_impl->VerifyFile(filePath, options);
}

void CertificateValidator::VerifyCertificateAsync(
    std::span<const uint8_t> certData,
    ValidationCallback callback,
    const ValidationOptions& options) {
    m_impl->VerifyCertificateAsync(certData, std::move(callback), options);
}

[[nodiscard]] bool CertificateValidator::IsRevoked(const std::wstring& serialNumber) {
    return m_impl->IsRevoked(serialNumber);
}

[[nodiscard]] RevocationStatus CertificateValidator::CheckRevocation(
    const CertificateInfo& cert) {
    return m_impl->CheckRevocation(cert);
}

[[nodiscard]] RevocationStatus CertificateValidator::CheckOCSP(
    const CertificateInfo& cert,
    const CertificateInfo& issuer) {
    return m_impl->CheckOCSP(cert, issuer);
}

[[nodiscard]] RevocationStatus CertificateValidator::CheckCRL(
    const CertificateInfo& cert,
    const CertificateInfo& issuer) {
    return m_impl->CheckCRL(cert, issuer);
}

[[nodiscard]] std::optional<std::tuple<RevocationStatus, RevocationReason, SystemTimePoint>>
    CertificateValidator::GetRevocationDetails(const CertificateInfo& cert) {
    return m_impl->GetRevocationDetails(cert);
}

[[nodiscard]] std::optional<std::vector<CertificateInfo>> CertificateValidator::BuildChain(
    const CertificateInfo& endEntityCert) {
    return m_impl->BuildChain(endEntityCert);
}

[[nodiscard]] std::optional<std::vector<CertificateInfo>> CertificateValidator::BuildChain(
    const CertificateInfo& endEntityCert,
    const ValidationOptions& options) {
    return m_impl->BuildChainWithOptions(endEntityCert, options);
}

void CertificateValidator::SetCertificateFetchCallback(CertificateFetchCallback callback) {
    m_impl->SetCertificateFetchCallback(std::move(callback));
}

[[nodiscard]] bool CertificateValidator::AddTrustedRoot(std::span<const uint8_t> certData) {
    return m_impl->AddTrustedRoot(certData);
}

[[nodiscard]] bool CertificateValidator::RemoveTrustedRoot(
    const CertificateFingerprint& fingerprint) {
    return m_impl->RemoveTrustedRoot(fingerprint);
}

[[nodiscard]] bool CertificateValidator::IsTrustedRoot(const CertificateInfo& cert) const {
    return m_impl->IsTrustedRoot(cert);
}

[[nodiscard]] TrustLevel CertificateValidator::GetTrustLevel(const CertificateInfo& cert) const {
    return m_impl->GetTrustLevel(cert);
}

[[nodiscard]] std::vector<CertificateInfo> CertificateValidator::GetTrustedRoots() const {
    return m_impl->GetTrustedRoots();
}

[[nodiscard]] bool CertificateValidator::ReloadSystemTrustStore() {
    return m_impl->ReloadSystemTrustStore();
}

[[nodiscard]] bool CertificateValidator::PinCertificate(
    std::string_view hostname,
    const CertificateFingerprint& fingerprint) {
    return m_impl->PinCertificate(hostname, fingerprint);
}

[[nodiscard]] bool CertificateValidator::PinCertificate(
    std::string_view hostname,
    std::span<const uint8_t> certData) {
    return m_impl->PinCertificateFromData(hostname, certData);
}

[[nodiscard]] bool CertificateValidator::UnpinCertificate(std::string_view hostname) {
    return m_impl->UnpinCertificate(hostname);
}

[[nodiscard]] bool CertificateValidator::IsPinned(std::string_view hostname) const {
    return m_impl->IsPinned(hostname);
}

[[nodiscard]] bool CertificateValidator::VerifyPinnedCertificate(
    std::string_view hostname,
    const CertificateInfo& cert) const {
    return m_impl->VerifyPinnedCertificate(hostname, cert);
}

[[nodiscard]] std::unordered_map<std::string, CertificateFingerprint>
    CertificateValidator::GetPinnedCertificates() const {
    return m_impl->GetPinnedCertificates();
}

[[nodiscard]] bool CertificateValidator::BlockCertificate(
    const CertificateFingerprint& fingerprint,
    std::string_view reason) {
    return m_impl->BlockCertificate(fingerprint, reason);
}

[[nodiscard]] bool CertificateValidator::UnblockCertificate(
    const CertificateFingerprint& fingerprint) {
    return m_impl->UnblockCertificate(fingerprint);
}

[[nodiscard]] bool CertificateValidator::IsBlocked(const CertificateInfo& cert) const {
    return m_impl->IsBlocked(cert);
}

[[nodiscard]] std::vector<std::pair<CertificateFingerprint, std::string>>
    CertificateValidator::GetBlockedCertificates() const {
    return m_impl->GetBlockedCertificates();
}

void CertificateValidator::ClearCaches() {
    m_impl->ClearCaches();
}

void CertificateValidator::ClearOCSPCache() {
    m_impl->ClearOCSPCache();
}

void CertificateValidator::ClearCRLCache() {
    m_impl->ClearCRLCache();
}

void CertificateValidator::ClearValidationCache() {
    m_impl->ClearValidationCache();
}

[[nodiscard]] std::unordered_map<std::string, size_t>
    CertificateValidator::GetCacheStats() const {
    return m_impl->GetCacheStats();
}

[[nodiscard]] CertificateFingerprint CertificateValidator::CalculateFingerprint(
    std::span<const uint8_t> certData) const {
    return m_impl->CalculateFingerprint(certData);
}

[[nodiscard]] CertificateThumbprint CertificateValidator::CalculateThumbprint(
    std::span<const uint8_t> certData) const {
    return m_impl->CalculateThumbprint(certData);
}

[[nodiscard]] std::string CertificateValidator::FingerprintToHex(
    const CertificateFingerprint& fp) {
    return BytesToHex(fp.data(), fp.size());
}

[[nodiscard]] std::string CertificateValidator::ThumbprintToHex(
    const CertificateThumbprint& tp) {
    return BytesToHex(tp.data(), tp.size());
}

[[nodiscard]] std::optional<CertificateFingerprint> CertificateValidator::ParseFingerprint(
    std::string_view hexString) {

    std::vector<uint8_t> bytes;
    if (!HexToBytes(hexString, bytes) || bytes.size() != CertificateConstants::SHA256_SIZE) {
        return std::nullopt;
    }

    CertificateFingerprint fp;
    std::copy(bytes.begin(), bytes.end(), fp.begin());
    return fp;
}

[[nodiscard]] bool CertificateValidator::IsWeakAlgorithm(SignatureAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case SignatureAlgorithm::MD5_RSA:
        case SignatureAlgorithm::SHA1_RSA:
            return true;
        default:
            return false;
    }
}

[[nodiscard]] bool CertificateValidator::IsKeySizeSufficient(const PublicKeyInfo& keyInfo) const {
    return m_impl->IsKeySizeSufficient(keyInfo);
}

[[nodiscard]] CertificateValidatorStatistics CertificateValidator::GetStatistics() const {
    return m_impl->GetStatistics();
}

void CertificateValidator::ResetStatistics() {
    m_impl->ResetStatistics();
}

[[nodiscard]] std::string CertificateValidator::ExportReport() const {
    return m_impl->ExportReport();
}

[[nodiscard]] bool CertificateValidator::SelfTest() {
    return m_impl->SelfTest();
}

[[nodiscard]] std::string CertificateValidator::GetVersionString() noexcept {
    std::ostringstream oss;
    oss << "ShadowStrike CertificateValidator v"
        << CertificateConstants::VERSION_MAJOR << "."
        << CertificateConstants::VERSION_MINOR << "."
        << CertificateConstants::VERSION_PATCH;
    return oss.str();
}

// ============================================================================
// RAII HELPER IMPLEMENTATIONS
// ============================================================================

CertificatePinGuard::CertificatePinGuard(
    std::string_view hostname,
    const CertificateFingerprint& fingerprint)
    : m_hostname(hostname) {
    m_pinned = CertificateValidator::Instance().PinCertificate(hostname, fingerprint);
}

CertificatePinGuard::~CertificatePinGuard() {
    if (m_pinned) {
        CertificateValidator::Instance().UnpinCertificate(m_hostname);
    }
}

}  // namespace Security
}  // namespace ShadowStrike
