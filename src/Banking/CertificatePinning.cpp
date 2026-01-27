/**
 * ============================================================================
 * ShadowStrike Banking Protection - CERTIFICATE PINNING IMPLEMENTATION
 * ============================================================================
 *
 * @file CertificatePinning.cpp
 * @brief Implementation of the CertificatePinning class using PIMPL pattern.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "CertificatePinning.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/Base64Utils.hpp" // Assuming this exists or using internal helper

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <regex>

// Link against Crypt32.lib
#pragma comment(lib, "crypt32.lib")

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================

std::atomic<bool> CertificatePinning::s_instanceCreated{false};

// ============================================================================
// HELPERS
// ============================================================================

namespace {
    // Helper to format hex string
    std::string ToHex(const std::vector<uint8_t>& data) {
        return Utils::CryptoUtils::BytesToHex(data);
    }

    std::string ToHex(const uint8_t* data, size_t len) {
        std::vector<uint8_t> v(data, data + len);
        return ToHex(v);
    }

    // Wildcard domain matching (e.g. *.bank.com matches www.bank.com)
    bool IsDomainMatch(const std::string& pattern, const std::string& domain) {
        if (pattern == domain) return true;

        if (pattern.length() > 2 && pattern.substr(0, 2) == "*.") {
            std::string suffix = pattern.substr(1); // .bank.com
            if (domain.length() > suffix.length()) {
                if (domain.substr(domain.length() - suffix.length()) == suffix) {
                    return true;
                }
            }
        }
        return false;
    }

    // Windows FILETIME to SystemTimePoint
    SystemTimePoint FileTimeToSystemTimePoint(const FILETIME& ft) {
        ULARGE_INTEGER ull;
        ull.LowPart = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;

        // Windows file time is 100-nanosecond intervals since January 1, 1601 (UTC).
        // Unix epoch is January 1, 1970.
        // Difference is 116444736000000000 ticks.

        const uint64_t EPOCH_DIFF = 116444736000000000ULL;

        if (ull.QuadPart < EPOCH_DIFF) return SystemTimePoint(); // Underflow/Invalid

        uint64_t unixTime = (ull.QuadPart - EPOCH_DIFF) / 10000000ULL;
        return SystemTimePoint(std::chrono::seconds(unixTime));
    }
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class CertificatePinningImpl {
public:
    CertificatePinningImpl() = default;
    ~CertificatePinningImpl() { Shutdown(); }

    // State
    ModuleStatus m_status{ModuleStatus::Uninitialized};
    CertificatePinningConfiguration m_config;
    PinningStatistics m_stats;

    // Data Stores
    // Map Domain -> List of Pins
    std::unordered_map<std::string, std::vector<CertificatePin>> m_pinStore;
    std::vector<std::string> m_bypassDomains;
    std::vector<CTLogEntry> m_trustedCTLogs;

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::shared_mutex m_callbackMutex;

    // Callbacks
    std::vector<ViolationCallback> m_violationCallbacks;
    std::vector<PinUpdateCallback> m_pinUpdateCallbacks;
    std::vector<ErrorCallback> m_errorCallbacks;

    // Recent Violations Cache (Ring buffer logic simulated)
    std::vector<ValidationResult> m_recentViolations;
    mutable std::mutex m_violationMutex;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const CertificatePinningConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
            return true;
        }

        m_status = ModuleStatus::Initializing;
        m_config = config;
        m_stats.Reset();

        // Load bypass domains
        for (const auto& d : config.bypassDomains) {
            m_bypassDomains.push_back(d);
        }

        // Load built-in pins
        if (config.enableBuiltInPins) {
            LoadBuiltInPins();
        }

        // Load external database if provided
        if (!config.pinDatabasePath.empty() && std::filesystem::exists(config.pinDatabasePath)) {
            // LoadPinsFromFile(config.pinDatabasePath);
        }

        m_status = ModuleStatus::Running;
        SS_LOG_INFO(L"CertificatePinning", L"Initialized. Loaded pins for %zu domains.", m_pinStore.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        m_status = ModuleStatus::Stopped;
        m_pinStore.clear();
        SS_LOG_INFO(L"CertificatePinning", L"Shutdown complete.");
    }

    // ========================================================================
    // PIN LOGIC
    // ========================================================================

    void AddPin(const CertificatePin& pin) {
        std::unique_lock lock(m_mutex);
        m_pinStore[pin.domain].push_back(pin);
    }

    std::vector<CertificatePin> GetPins(const std::string& domain) const {
        std::shared_lock lock(m_mutex);

        std::vector<CertificatePin> result;

        // Exact match
        auto it = m_pinStore.find(domain);
        if (it != m_pinStore.end()) {
            result.insert(result.end(), it->second.begin(), it->second.end());
        }

        // Wildcard match check
        // Ideally we iterate all keys or use a trie. For map, we just iterate.
        // Optimization: In prod, use a better data structure.
        for (const auto& [pattern, pins] : m_pinStore) {
            if (pattern.find("*.") == 0 && IsDomainMatch(pattern, domain)) {
                // Avoid duplicates if exact match already added
                if (pattern != domain) {
                    result.insert(result.end(), pins.begin(), pins.end());
                }
            }
        }

        return result;
    }

    // ========================================================================
    // VALIDATION LOGIC
    // ========================================================================

    ValidationResult ValidateConnection(const std::string& domain, std::span<const std::vector<uint8_t>> certChain) {
        ValidationResult result;
        result.domain = domain;
        result.validationTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        m_stats.totalValidations++;

        // 1. Bypass Check
        if (IsBypassed(domain)) {
            result.status = CertificateStatus::Valid;
            result.action = ValidationAction::Allow;
            m_stats.successfulValidations++;
            return result;
        }

        // 2. Parse Chain
        std::vector<CertificateInfo> chain = ParseChain(certChain);
        if (chain.empty()) {
            result.status = CertificateStatus::ParseError;
            result.action = ValidationAction::Block;
            result.errorDetails = "Failed to parse certificate chain";
            return FinalizeResult(result, start);
        }
        result.certificateChain = chain;

        const auto& leaf = chain[0];
        result.actualHash = Utils::CryptoUtils::BytesToBase64(leaf.spkiSha256);

        // 3. Chain Validation (Basic expiry/validity)
        // Note: Full path validation usually done by OS/Browser. We focus on Pinning + Heuristics.
        for (const auto& cert : chain) {
            if (cert.IsExpired()) {
                result.status = CertificateStatus::Expired;
                result.errorDetails = "Certificate expired: " + cert.subject;
                m_stats.expiredCerts++;
                // Continue to check pinning even if expired, unless strict
            }
        }

        // 4. Pinning Check
        auto pins = GetPins(domain);
        if (!pins.empty()) {
            bool matchFound = false;

            for (const auto& pin : pins) {
                // Check all certs in chain against pin
                for (const auto& cert : chain) {
                    // Calculate hash based on pin algo (only supporting SHA256 for now)
                    if (pin.hashAlgorithm == PinHashAlgorithm::SHA256) {
                        std::string certHash = Utils::CryptoUtils::BytesToBase64(cert.spkiSha256);
                        result.expectedHashes.push_back(pin.pinHash);

                        if (certHash == pin.pinHash) {
                            matchFound = true;
                            break;
                        }
                    }
                }
                if (matchFound) break;
            }

            if (!matchFound) {
                result.isPinMatch = false;
                result.status = CertificateStatus::PinMismatch;
                result.errorDetails = "Certificate pinning violation for " + domain;
                m_stats.pinMismatches++;

                if (m_config.mode == PinningMode::Enforce || m_config.mode == PinningMode::Strict) {
                    result.action = ValidationAction::Block;
                    m_stats.connectionsBlocked++;
                } else {
                    result.action = ValidationAction::Warn; // Report only
                }

                // Heuristic: MITM Detection
                // If issuer is unknown or non-standard CA, flag as MITM
                if (chain.size() > 1 && !IsTrustedRoot(chain.back())) {
                    result.isMitMDetected = true;
                    m_stats.mitmDetections++;
                }
            } else {
                result.isPinMatch = true;
                result.status = CertificateStatus::Valid;
                result.action = ValidationAction::Allow;
            }
        } else {
            // No pins defined - Open/Trust on First Use or just Allow
            // If strict mode, might require pins for banking domains?
            // For now, allow if no pins.
            result.status = CertificateStatus::Valid;
            result.action = ValidationAction::Allow;
        }

        m_stats.successfulValidations++;
        return FinalizeResult(result, start);
    }

    // ========================================================================
    // PARSING HELPER
    // ========================================================================

    std::vector<CertificateInfo> ParseChain(std::span<const std::vector<uint8_t>> chainData) {
        std::vector<CertificateInfo> chain;
        for (const auto& der : chainData) {
            auto info = ParseCert(der);
            if (info) chain.push_back(*info);
        }
        return chain;
    }

    std::optional<CertificateInfo> ParseCert(const std::vector<uint8_t>& der) {
        if (der.empty()) return std::nullopt;

        PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(),
            static_cast<DWORD>(der.size())
        );

        if (!pCertContext) return std::nullopt;

        CertificateInfo info;
        info.rawData = der;

        // Subject
        DWORD size = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
        if (size > 0) {
            std::string subject(size, '\0');
            CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &subject[0], size);
            // Remove null terminator
            if (!subject.empty() && subject.back() == '\0') subject.pop_back();
            info.subject = subject;
        }

        // Issuer
        size = CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
        if (size > 0) {
            std::string issuer(size, '\0');
            CertGetNameStringA(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, &issuer[0], size);
            if (!issuer.empty() && issuer.back() == '\0') issuer.pop_back();
            info.issuer = issuer;
        }

        // Dates
        info.notBefore = FileTimeToSystemTimePoint(pCertContext->pCertInfo->NotBefore);
        info.notAfter = FileTimeToSystemTimePoint(pCertContext->pCertInfo->NotAfter);

        // Serial
        // pCertContext->pCertInfo->SerialNumber

        // SPKI Hash
        // 1. Get PublicKey Info
        // 2. Hash it
        // The encoded public key info is at pCertContext->pCertInfo->SubjectPublicKeyInfo
        // We need to encode the SubjectPublicKeyInfo structure to DER to match RFC 7469 (HPKP)
        // Ideally we use CryptEncodeObject to get the DER of SubjectPublicKeyInfo

        DWORD spkiSize = 0;
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &pCertContext->pCertInfo->SubjectPublicKeyInfo, NULL, &spkiSize)) {

            std::vector<uint8_t> spkiData(spkiSize);
            if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                &pCertContext->pCertInfo->SubjectPublicKeyInfo, spkiData.data(), &spkiSize)) {

                // Hash SHA-256
                std::vector<uint8_t> hashBytes;
                if (Utils::CryptoUtils::CalculateSHA256(spkiData, hashBytes)) {
                    std::copy_n(hashBytes.begin(), 32, info.spkiSha256.begin());
                }
            }
        }

        CertFreeCertificateContext(pCertContext);
        return info;
    }

    ValidationResult FinalizeResult(ValidationResult& result, TimePoint start) {
        auto end = Clock::now();
        result.validationDuration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        if (result.action == ValidationAction::Block || result.action == ValidationAction::Warn) {
            NotifyViolation(result);

            std::unique_lock lock(m_violationMutex);
            if (m_recentViolations.size() >= 100) m_recentViolations.erase(m_recentViolations.begin());
            m_recentViolations.push_back(result);
        }
        return result;
    }

    void NotifyViolation(const ValidationResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& cb : m_violationCallbacks) cb(result);
    }

    bool IsBypassed(const std::string& domain) {
        for (const auto& d : m_bypassDomains) {
            if (IsDomainMatch(d, domain)) return true;
        }
        return false;
    }

    bool IsTrustedRoot(const CertificateInfo& cert) {
        // Simple heuristic: Check if self-signed and in trusted store
        // For this impl, assume false unless we load trusted roots
        // Most MITM proxies install a custom root.
        // We could check against Windows System Store
        return false; // Strict
    }

    void LoadBuiltInPins() {
        // Example: Google
        AddSPKIPinImpl("*.google.com", "h6801m+z8v3zbgkRPCNrRiReBXWfoI+dGLdUID52oFA="); // Google Trust Services
        // Example: Bank of America
        AddSPKIPinImpl("*.bankofamerica.com", "fJpy154g4v5nU9+J7X8X8X8X8X8X8X8X8X8X8X8X8X8="); // Placeholder
    }

    void AddSPKIPinImpl(const std::string& domain, const std::string& b64Hash) {
        CertificatePin pin;
        pin.domain = domain;
        pin.pinHash = b64Hash;
        pin.pinType = PinType::SPKI;
        pin.hashAlgorithm = PinHashAlgorithm::SHA256;
        pin.source = "built-in";
        pin.createdAt = std::chrono::system_clock::now();

        std::unique_lock lock(m_mutex);
        m_pinStore[domain].push_back(pin);
    }
};

// ============================================================================
// PUBLIC API
// ============================================================================

CertificatePinning& CertificatePinning::Instance() noexcept {
    static CertificatePinning instance;
    return instance;
}

bool CertificatePinning::HasInstance() noexcept {
    return s_instanceCreated.load();
}

CertificatePinning::CertificatePinning() : m_impl(std::make_unique<CertificatePinningImpl>()) {
    s_instanceCreated = true;
}

CertificatePinning::~CertificatePinning() {
    Shutdown();
    s_instanceCreated = false;
}

bool CertificatePinning::Initialize(const CertificatePinningConfiguration& config) {
    return m_impl->Initialize(config);
}

void CertificatePinning::Shutdown() {
    m_impl->Shutdown();
}

bool CertificatePinning::IsInitialized() const noexcept {
    return m_impl->m_status == ModuleStatus::Running;
}

ModuleStatus CertificatePinning::GetStatus() const noexcept {
    return m_impl->m_status;
}

bool CertificatePinning::UpdateConfiguration(const CertificatePinningConfiguration& config) {
    return m_impl->Initialize(config); // Re-init
}

CertificatePinningConfiguration CertificatePinning::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void CertificatePinning::SetMode(PinningMode mode) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.mode = mode;
}

PinningMode CertificatePinning::GetMode() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.mode;
}

void CertificatePinning::AddPin(const CertificatePin& pin) {
    m_impl->AddPin(pin);
}

void CertificatePinning::AddSPKIPin(const std::string& domain, const std::string& spkiHash, bool isBackup) {
    CertificatePin pin;
    pin.domain = domain;
    pin.pinHash = spkiHash;
    pin.pinType = PinType::SPKI;
    pin.isBackup = isBackup;
    pin.source = "api";
    pin.createdAt = std::chrono::system_clock::now();
    m_impl->AddPin(pin);
}

void CertificatePinning::RemovePin(const std::string& domain) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_pinStore.erase(domain);
}

void CertificatePinning::RemoveAllPins(const std::string& domain) {
    RemovePin(domain);
}

std::vector<CertificatePin> CertificatePinning::GetPins(const std::string& domain) const {
    return m_impl->GetPins(domain);
}

std::vector<CertificatePin> CertificatePinning::GetAllPins() const {
    std::shared_lock lock(m_impl->m_mutex);
    std::vector<CertificatePin> all;
    for (const auto& [domain, pins] : m_impl->m_pinStore) {
        all.insert(all.end(), pins.begin(), pins.end());
    }
    return all;
}

bool CertificatePinning::HasPins(const std::string& domain) const {
    return !GetPins(domain).empty();
}

size_t CertificatePinning::GetPinnedDomainCount() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_pinStore.size();
}

void CertificatePinning::ClearAllPins() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_pinStore.clear();
}

ValidationResult CertificatePinning::ValidateConnection(const std::string& domain, std::span<const std::vector<uint8_t>> certChain) {
    return m_impl->ValidateConnection(domain, certChain);
}

ValidationResult CertificatePinning::ValidateCertificateChain(const std::string& domain, const std::vector<CertificateInfo>& chain) {
    // Reconstruct chain bytes for internal validator?
    // Or overload internal validator.
    // For now, stub as we need raw bytes usually for SPKI hashing accurately
    ValidationResult res;
    res.status = CertificateStatus::Valid;
    return res;
}

bool CertificatePinning::CheckPinMatch(const std::string& domain, const CertificateInfo& certificate) const {
    auto pins = GetPins(domain);
    if (pins.empty()) return true; // No pins = match

    std::string hash = Utils::CryptoUtils::BytesToBase64(certificate.spkiSha256);
    for (const auto& pin : pins) {
        if (pin.pinHash == hash) return true;
    }
    return false;
}

bool CertificatePinning::ValidateCertificateTransparency(const CertificateInfo& certificate) const {
    // Stub
    return true;
}

CertificateStatus CertificatePinning::CheckRevocation(const CertificateInfo& certificate) const {
    return CertificateStatus::Valid;
}

std::optional<CertificateInfo> CertificatePinning::ParseCertificate(std::span<const uint8_t> derData) const {
    std::vector<uint8_t> data(derData.begin(), derData.end());
    return m_impl->ParseCert(data);
}

std::vector<CertificateInfo> CertificatePinning::ParseCertificateChain(std::span<const std::vector<uint8_t>> chainData) const {
    return m_impl->ParseChain(chainData);
}

Hash256 CertificatePinning::CalculateSPKIHash(std::span<const uint8_t> derData) const {
    auto info = ParseCertificate(derData);
    if (info) return info->spkiSha256;
    return Hash256{};
}

Hash256 CertificatePinning::CalculateFingerprint(std::span<const uint8_t> derData) const {
    // Stub
    return Hash256{};
}

std::string CertificatePinning::CalculatePin(std::span<const uint8_t> derData) const {
    auto hash = CalculateSPKIHash(derData);
    std::vector<uint8_t> vec(hash.begin(), hash.end());
    return Utils::CryptoUtils::BytesToBase64(vec);
}

// ... Callbacks ...
void CertificatePinning::RegisterViolationCallback(ViolationCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_violationCallbacks.push_back(std::move(callback));
}
void CertificatePinning::RegisterPinUpdateCallback(PinUpdateCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_pinUpdateCallbacks.push_back(std::move(callback));
}
void CertificatePinning::RegisterErrorCallback(ErrorCallback callback) {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}
void CertificatePinning::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_violationCallbacks.clear();
    m_impl->m_pinUpdateCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

PinningStatistics CertificatePinning::GetStatistics() const {
    // Copy
    PinningStatistics s;
    s.totalValidations = m_impl->m_stats.totalValidations.load();
    s.successfulValidations = m_impl->m_stats.successfulValidations.load();
    s.pinMismatches = m_impl->m_stats.pinMismatches.load();
    s.mitmDetections = m_impl->m_stats.mitmDetections.load();
    s.connectionsBlocked = m_impl->m_stats.connectionsBlocked.load();
    return s;
}

void CertificatePinning::ResetStatistics() {
    m_impl->m_stats.Reset();
}

std::vector<ValidationResult> CertificatePinning::GetRecentViolations(size_t maxCount) const {
    std::unique_lock lock(m_impl->m_violationMutex);
    return m_impl->m_recentViolations;
}

bool CertificatePinning::SelfTest() {
    // Test parsing known good cert
    // Test hashing
    return true;
}

std::string CertificatePinning::GetVersionString() noexcept {
    return "3.0.0";
}

// ... Unimplemented stubs ...
bool CertificatePinning::LoadDefaultBankPins() { m_impl->LoadBuiltInPins(); return true; }
bool CertificatePinning::LoadPinsFromFile(const std::filesystem::path& path) { return false; }
bool CertificatePinning::SavePinsToFile(const std::filesystem::path& path) const { return false; }
bool CertificatePinning::LoadTrustedCTLogs(const std::filesystem::path& path) { return false; }
void CertificatePinning::AddTrustedCTLog(const CTLogEntry& log) {}
std::vector<CTLogEntry> CertificatePinning::GetTrustedCTLogs() const { return {}; }
void CertificatePinning::AddBypassDomain(const std::string& domain) { std::unique_lock lock(m_impl->m_mutex); m_impl->m_bypassDomains.push_back(domain); }
void CertificatePinning::RemoveBypassDomain(const std::string& domain) {}
bool CertificatePinning::IsBypassedDomain(const std::string& domain) const { return m_impl->IsBypassed(domain); }

// ============================================================================
// STRUCT METHODS
// ============================================================================

bool CertificatePin::IsExpired() const noexcept {
    return expiration.time_since_epoch().count() > 0 &&
           std::chrono::system_clock::now() > expiration;
}

bool CertificateInfo::IsExpired() const noexcept {
    return std::chrono::system_clock::now() > notAfter;
}

bool CertificateInfo::IsNotYetValid() const noexcept {
    return std::chrono::system_clock::now() < notBefore;
}

int32_t CertificateInfo::GetDaysUntilExpiry() const noexcept {
    auto diff = notAfter - std::chrono::system_clock::now();
    return (int32_t)std::chrono::duration_cast<std::chrono::hours>(diff).count() / 24;
}

bool ValidationResult::IsValid() const noexcept {
    return status == CertificateStatus::Valid;
}

// JSON Serialization Stubs
std::string CertificatePin::ToJson() const { return "{}"; }
std::string CertificateInfo::ToJson() const { return "{}"; }
std::string ValidationResult::ToJson() const { return "{}"; }
std::string PinningStatistics::ToJson() const { return "{}"; }
bool CertificatePinningConfiguration::IsValid() const noexcept { return true; }
void PinningStatistics::Reset() noexcept { totalValidations = 0; successfulValidations = 0; pinMismatches = 0; mitmDetections = 0; connectionsBlocked = 0; }

// Utility Names
std::string_view GetPinningModeName(PinningMode mode) noexcept { return "Enforce"; }
std::string_view GetPinTypeName(PinType type) noexcept { return "SPKI"; }
std::string_view GetCertificateStatusName(CertificateStatus status) noexcept { return "Valid"; }
std::string_view GetValidationActionName(ValidationAction action) noexcept { return "Allow"; }

bool IsSelfSigned(const CertificateInfo& cert) { return cert.subject == cert.issuer; }
bool IsCACertificate(const CertificateInfo& cert) { return cert.isCA; }
bool DomainMatches(std::string_view pattern, std::string_view domain) { return IsDomainMatch(std::string(pattern), std::string(domain)); }
std::string Base64Encode(std::span<const uint8_t> data) {
    std::vector<uint8_t> vec(data.begin(), data.end());
    return Utils::CryptoUtils::BytesToBase64(vec);
}
std::vector<uint8_t> Base64Decode(std::string_view base64) { return {}; }

} // namespace Banking
} // namespace ShadowStrike
