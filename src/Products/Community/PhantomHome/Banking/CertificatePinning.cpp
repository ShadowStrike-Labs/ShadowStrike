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
#include "../Utils/Base64Utils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/JSONUtils.hpp"

#include <filesystem>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <deque>
#include <cctype>

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

    constexpr const wchar_t* LOG_CAT = L"CertPinning";

    std::string ToHex(const uint8_t* data, size_t len) {
        return Utils::HashUtils::ToHexLower(data, len);
    }

    std::string ToHex(const std::vector<uint8_t>& data) {
        return Utils::HashUtils::ToHexLower(data);
    }

    // Case-insensitive ASCII lowercase for domain normalization
    std::string NormalizeDomain(std::string_view domain) {
        std::string result(domain);
        for (auto& c : result) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
        }
        return result;
    }

    // Wildcard domain matching (e.g. *.bank.com matches www.bank.com)
    // Follows RFC 6125 Section 6.4.3:
    //   - Wildcard only in leftmost label
    //   - Must match at least one character
    //   - No partial wildcards (e.g. w*.example.com is rejected)
    //   - Does not match across multiple labels (*.bank.com does NOT match a.b.bank.com)
    bool IsDomainMatch(const std::string& pattern, const std::string& domain) {
        const std::string normPattern = NormalizeDomain(pattern);
        const std::string normDomain = NormalizeDomain(domain);

        if (normPattern == normDomain) return true;

        // Only allow wildcard in leftmost label: "*.suffix"
        if (normPattern.length() > 2 && normPattern[0] == '*' && normPattern[1] == '.') {
            // Reject partial wildcards like "w*.example.com"
            // (already handled - we require exactly "*.")

            std::string_view suffix(normPattern.data() + 1, normPattern.length() - 1); // ".bank.com"

            if (normDomain.length() <= suffix.length()) return false;

            // Verify suffix match
            std::string_view domainSuffix(
                normDomain.data() + (normDomain.length() - suffix.length()),
                suffix.length());

            if (domainSuffix != suffix) return false;

            // The part before the suffix (the leftmost label) must not contain dots
            // This prevents *.bank.com from matching a.b.bank.com
            std::string_view leftLabel(
                normDomain.data(),
                normDomain.length() - suffix.length());

            if (leftLabel.find('.') != std::string_view::npos) return false;

            // Must match at least one character
            if (leftLabel.empty()) return false;

            return true;
        }

        return false;
    }

    // Windows FILETIME to SystemTimePoint
    SystemTimePoint FileTimeToSystemTimePoint(const FILETIME& ft) {
        ULARGE_INTEGER ull;
        ull.LowPart = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;

        constexpr uint64_t EPOCH_DIFF = 116444736000000000ULL;

        if (ull.QuadPart < EPOCH_DIFF) return SystemTimePoint();

        uint64_t unixTime = (ull.QuadPart - EPOCH_DIFF) / 10000000ULL;
        return SystemTimePoint(std::chrono::seconds(unixTime));
    }

    // Constant-time comparison of base64-encoded pin against raw SPKI hash.
    // Decodes the pin first, then compares raw bytes to prevent timing side-channels.
    bool SecurePinCompare(const std::string& base64Pin, const Hash256& spkiHash) {
        std::vector<uint8_t> pinBytes;
        if (!Utils::CryptoUtils::Base64::Decode(base64Pin, pinBytes)) {
            return false;
        }
        if (pinBytes.size() != spkiHash.size()) {
            return false;
        }
        return Utils::CryptoUtils::SecureCompare(
            pinBytes.data(), spkiHash.data(), spkiHash.size());
    }

}  // anonymous namespace

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

    // Data Stores (domain keys are always stored normalized/lowercase)
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

    // Recent Violations Cache (ring buffer via deque, O(1) pop_front)
    std::deque<ValidationResult> m_recentViolations;
    static constexpr size_t MAX_RECENT_VIOLATIONS = 200;
    mutable std::mutex m_violationMutex;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const CertificatePinningConfiguration& config) {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Running) {
            // Already running — apply config update path instead of silently returning
            m_config = config;
            SS_LOG_INFO(LOG_CAT, L"Configuration updated while running.");
            return true;
        }

        if (m_status != ModuleStatus::Uninitialized && m_status != ModuleStatus::Stopped) {
            SS_LOG_WARN(LOG_CAT, L"Initialize called in unexpected state: %u",
                        static_cast<unsigned>(m_status));
            return false;
        }

        m_status = ModuleStatus::Initializing;
        m_config = config;
        m_stats.Reset();
        m_pinStore.clear();
        m_bypassDomains.clear();

        // Load bypass domains (normalized)
        for (const auto& d : config.bypassDomains) {
            m_bypassDomains.push_back(NormalizeDomain(d));
        }

        // Load built-in pins
        if (config.enableBuiltInPins) {
            LoadBuiltInPins();
        }

        // Load external pin database if provided
        if (!config.pinDatabasePath.empty()) {
            // Release main lock during file I/O to avoid blocking other threads
            lock.unlock();
            const auto fsPath = std::filesystem::path(config.pinDatabasePath);
            if (std::filesystem::exists(fsPath)) {
                if (!LoadPinsFromFileImpl(fsPath)) {
                    SS_LOG_WARN(LOG_CAT, L"Failed to load external pin database.");
                }
            }
            lock.lock();
        }

        m_status = ModuleStatus::Running;
        SS_LOG_INFO(LOG_CAT, L"Initialized. Loaded pins for %zu domains.", m_pinStore.size());
        return true;
    }

    void Shutdown() {
        std::unique_lock lock(m_mutex);
        if (m_status == ModuleStatus::Stopped || m_status == ModuleStatus::Uninitialized)
            return;

        m_status = ModuleStatus::Stopping;
        m_pinStore.clear();
        m_bypassDomains.clear();
        m_trustedCTLogs.clear();
        m_status = ModuleStatus::Stopped;
        SS_LOG_INFO(LOG_CAT, L"Shutdown complete.");
    }

    // ========================================================================
    // PIN LOGIC
    // ========================================================================

    void AddPin(const CertificatePin& pin) {
        std::unique_lock lock(m_mutex);

        const std::string normDomain = NormalizeDomain(pin.domain);

        // Enforce per-domain limit
        auto& domainPins = m_pinStore[normDomain];
        if (domainPins.size() >= CertPinningConstants::MAX_PINS_PER_DOMAIN) {
            SS_LOG_WARN(LOG_CAT, L"Pin limit reached for domain (max %zu). Rejecting new pin.",
                        CertPinningConstants::MAX_PINS_PER_DOMAIN);
            return;
        }

        // Enforce global domain limit
        if (m_pinStore.size() >= CertPinningConstants::MAX_PINNED_DOMAINS &&
            domainPins.empty()) {
            SS_LOG_WARN(LOG_CAT, L"Global pinned domain limit reached (max %zu). Rejecting.",
                        CertPinningConstants::MAX_PINNED_DOMAINS);
            return;
        }

        CertificatePin normalizedPin = pin;
        normalizedPin.domain = normDomain;
        domainPins.push_back(std::move(normalizedPin));
    }

    std::vector<CertificatePin> GetPins(const std::string& domain) const {
        std::shared_lock lock(m_mutex);

        const std::string normDomain = NormalizeDomain(domain);
        std::vector<CertificatePin> result;

        // Exact match
        auto it = m_pinStore.find(normDomain);
        if (it != m_pinStore.end()) {
            result.insert(result.end(), it->second.begin(), it->second.end());
        }

        // Wildcard match: iterate all keys for "*.suffix" patterns
        for (const auto& [pattern, pins] : m_pinStore) {
            if (pattern.length() > 2 && pattern[0] == '*' && pattern[1] == '.' &&
                pattern != normDomain) {
                if (IsDomainMatch(pattern, normDomain)) {
                    result.insert(result.end(), pins.begin(), pins.end());
                }
            }
        }

        return result;
    }

    // ========================================================================
    // VALIDATION LOGIC
    // ========================================================================

    ValidationResult ValidateConnection(
        const std::string& domain,
        std::span<const std::vector<uint8_t>> certChain)
    {
        ValidationResult result;
        result.domain = domain;
        result.validationTime = std::chrono::system_clock::now();
        auto start = Clock::now();

        m_stats.totalValidations.fetch_add(1, std::memory_order_relaxed);

        // 1. Input validation
        if (domain.empty()) {
            result.status = CertificateStatus::NameMismatch;
            result.action = ValidationAction::Block;
            result.errorDetails = "Empty domain name";
            return FinalizeResult(result, start);
        }

        // 2. Bypass Check (lock-safe)
        if (IsBypassed(domain)) {
            result.status = CertificateStatus::Valid;
            result.action = ValidationAction::Allow;
            m_stats.successfulValidations.fetch_add(1, std::memory_order_relaxed);
            return result;
        }

        // 3. Parse Chain (with depth/size limits)
        std::vector<CertificateInfo> chain = ParseChain(certChain);
        if (chain.empty()) {
            result.status = CertificateStatus::ParseError;
            result.action = ValidationAction::Block;
            result.errorDetails = "Failed to parse certificate chain";
            m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
            return FinalizeResult(result, start);
        }
        result.certificateChain = chain;

        const auto& leaf = chain[0];
        result.actualHash = Utils::CryptoUtils::Base64::Encode(
            leaf.spkiSha256.data(), leaf.spkiSha256.size());

        // 4. Expiry / Validity Window Check
        bool hasExpiredCert = false;
        bool hasNotYetValid = false;
        for (const auto& cert : chain) {
            if (cert.IsExpired()) {
                hasExpiredCert = true;
                result.errorDetails = "Certificate expired: " + cert.subject;
                m_stats.expiredCerts.fetch_add(1, std::memory_order_relaxed);
            }
            if (cert.IsNotYetValid()) {
                hasNotYetValid = true;
                result.errorDetails = "Certificate not yet valid: " + cert.subject;
            }
        }

        if (hasExpiredCert) {
            result.status = CertificateStatus::Expired;
            result.action = (m_config.mode >= PinningMode::Enforce)
                ? ValidationAction::Block : ValidationAction::Warn;
            if (result.action == ValidationAction::Block) {
                m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                return FinalizeResult(result, start);
            }
        }
        if (hasNotYetValid) {
            result.status = CertificateStatus::NotYetValid;
            result.action = ValidationAction::Block;
            m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
            return FinalizeResult(result, start);
        }

        // 5. Weak Key Detection
        if (leaf.keySize > 0) {
            bool weakKey = false;
            if (leaf.keyAlgorithm.find("RSA") != std::string::npos &&
                leaf.keySize < m_config.minRSAKeySize) {
                weakKey = true;
            }
            if (leaf.keyAlgorithm.find("EC") != std::string::npos &&
                leaf.keySize < m_config.minECKeySize) {
                weakKey = true;
            }
            if (weakKey) {
                result.status = CertificateStatus::WeakKey;
                result.errorDetails = "Weak key: " + leaf.keyAlgorithm +
                    " " + std::to_string(leaf.keySize) + " bits";
                result.action = ValidationAction::Block;
                m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                SS_LOG_WARN(LOG_CAT, L"Weak key detected for domain: %zu bits",
                            static_cast<size_t>(leaf.keySize));
                return FinalizeResult(result, start);
            }
        }

        // 6. Pinning Check (constant-time comparison)
        auto pins = GetPins(domain);
        if (!pins.empty()) {
            bool matchFound = false;

            for (const auto& pin : pins) {
                if (pin.IsExpired()) continue;

                for (const auto& cert : chain) {
                    if (pin.hashAlgorithm == PinHashAlgorithm::SHA256) {
                        result.expectedHashes.push_back(pin.pinHash);
                        if (SecurePinCompare(pin.pinHash, cert.spkiSha256)) {
                            matchFound = true;
                            break;
                        }
                    }
                    // SHA384/SHA512 would need separate hash arrays in CertificateInfo
                    // Currently SPKI hashing only produces SHA-256
                }
                if (matchFound) break;
            }

            if (!matchFound) {
                result.isPinMatch = false;
                result.status = CertificateStatus::PinMismatch;
                result.errorDetails = "Certificate pinning violation for " + domain;
                m_stats.pinMismatches.fetch_add(1, std::memory_order_relaxed);

                if (m_config.mode == PinningMode::Enforce ||
                    m_config.mode == PinningMode::Strict) {
                    result.action = ValidationAction::Block;
                    m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                } else if (m_config.mode == PinningMode::ReportOnly) {
                    result.action = ValidationAction::Warn;
                } else {
                    result.action = ValidationAction::Allow;
                }

                // MITM heuristic: check if root CA is in trusted store
                if (chain.size() > 1 && !IsTrustedRoot(chain.back())) {
                    result.isMitMDetected = true;
                    m_stats.mitmDetections.fetch_add(1, std::memory_order_relaxed);
                    SS_LOG_ERROR(LOG_CAT,
                        L"Potential MITM detected for domain. Untrusted root in chain.");
                }

                return FinalizeResult(result, start);
            }

            result.isPinMatch = true;
        }
        // No pins = allow (no enforcement possible without pins)

        // 7. Revocation Check
        if (m_config.enableRevocationChecking &&
            m_config.revocationMethod != RevocationMethod::None) {
            auto revStatus = CheckRevocationImpl(leaf);
            if (revStatus == CertificateStatus::Revoked) {
                result.status = CertificateStatus::Revoked;
                result.isRevoked = true;
                result.action = ValidationAction::Block;
                result.errorDetails = "Certificate revoked: " + leaf.subject;
                m_stats.revokedCerts.fetch_add(1, std::memory_order_relaxed);
                m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                return FinalizeResult(result, start);
            }
            if (revStatus == CertificateStatus::OCSPError &&
                !m_config.allowRevocationSoftFail) {
                result.status = CertificateStatus::OCSPError;
                result.action = ValidationAction::Block;
                result.errorDetails = "Revocation check failed (hard-fail policy)";
                m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                return FinalizeResult(result, start);
            }
        }

        // 8. Certificate Transparency Check
        if (m_config.enableCTChecking && m_config.mode == PinningMode::Strict) {
            bool ctValid = ValidateCTImpl(leaf);
            result.isCTValid = ctValid;
            if (!ctValid) {
                result.status = CertificateStatus::CTViolation;
                result.action = ValidationAction::Block;
                result.errorDetails = "Certificate Transparency violation: no valid SCTs";
                m_stats.ctViolations.fetch_add(1, std::memory_order_relaxed);
                m_stats.connectionsBlocked.fetch_add(1, std::memory_order_relaxed);
                return FinalizeResult(result, start);
            }
        }

        // All checks passed
        result.status = CertificateStatus::Valid;
        result.action = ValidationAction::Allow;
        m_stats.successfulValidations.fetch_add(1, std::memory_order_relaxed);
        return FinalizeResult(result, start);
    }

    // ========================================================================
    // PARSING
    // ========================================================================

    std::vector<CertificateInfo> ParseChain(
        std::span<const std::vector<uint8_t>> chainData)
    {
        std::vector<CertificateInfo> chain;

        if (chainData.size() > CertPinningConstants::MAX_CHAIN_DEPTH) {
            SS_LOG_WARN(LOG_CAT, L"Certificate chain depth %zu exceeds limit %zu. Truncating.",
                        chainData.size(), CertPinningConstants::MAX_CHAIN_DEPTH);
        }

        const size_t limit = std::min(chainData.size(),
                                       CertPinningConstants::MAX_CHAIN_DEPTH);
        chain.reserve(limit);

        for (size_t i = 0; i < limit; ++i) {
            auto info = ParseCert(chainData[i]);
            if (info) {
                chain.push_back(std::move(*info));
            } else {
                SS_LOG_WARN(LOG_CAT,
                    L"Failed to parse certificate at chain position %zu.", i);
            }
        }
        return chain;
    }

    std::optional<CertificateInfo> ParseCert(const std::vector<uint8_t>& der) {
        if (der.empty()) return std::nullopt;

        // Enforce maximum certificate size to prevent DoS
        if (der.size() > CertPinningConstants::MAX_CERTIFICATE_SIZE) {
            SS_LOG_WARN(LOG_CAT, L"Certificate size %zu exceeds limit %zu. Rejected.",
                        der.size(), CertPinningConstants::MAX_CERTIFICATE_SIZE);
            return std::nullopt;
        }

        PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            der.data(),
            static_cast<DWORD>(der.size())
        );

        if (!pCertContext) return std::nullopt;

        CertificateInfo info;
        info.rawData = der;

        // Subject
        DWORD size = CertGetNameStringA(pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
        if (size > 1) {
            std::string subject(size, '\0');
            CertGetNameStringA(pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &subject[0], size);
            if (!subject.empty() && subject.back() == '\0') subject.pop_back();
            info.subject = std::move(subject);
        }

        // Issuer
        size = CertGetNameStringA(pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, NULL, NULL, 0);
        if (size > 1) {
            std::string issuer(size, '\0');
            CertGetNameStringA(pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG,
                NULL, &issuer[0], size);
            if (!issuer.empty() && issuer.back() == '\0') issuer.pop_back();
            info.issuer = std::move(issuer);
        }

        // Dates
        info.notBefore = FileTimeToSystemTimePoint(pCertContext->pCertInfo->NotBefore);
        info.notAfter = FileTimeToSystemTimePoint(pCertContext->pCertInfo->NotAfter);

        // Serial Number
        const auto& serial = pCertContext->pCertInfo->SerialNumber;
        if (serial.cbData > 0 && serial.pbData != nullptr) {
            // Windows stores serial in little-endian; reverse for display
            info.serialNumber = ToHex(serial.pbData, serial.cbData);
            std::reverse(info.serialNumber.begin(), info.serialNumber.end());
            // Actually reverse byte-pairs for proper hex
            std::string corrected;
            corrected.reserve(serial.cbData * 2);
            for (int i = static_cast<int>(serial.cbData) - 1; i >= 0; --i) {
                char buf[3];
                (void)snprintf(buf, sizeof(buf), "%02x", serial.pbData[i]);
                corrected += buf;
            }
            info.serialNumber = std::move(corrected);
        }

        // Basic Constraints (isCA, pathLengthConstraint)
        PCERT_EXTENSION pExt = CertFindExtension(
            szOID_BASIC_CONSTRAINTS2,
            pCertContext->pCertInfo->cExtension,
            pCertContext->pCertInfo->rgExtension);
        if (pExt) {
            DWORD bcSize = 0;
            if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                    pExt->Value.pbData, pExt->Value.cbData, 0, NULL, &bcSize)) {
                std::vector<uint8_t> bcBuf(bcSize);
                if (CryptDecodeObject(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2,
                        pExt->Value.pbData, pExt->Value.cbData, 0,
                        bcBuf.data(), &bcSize)) {
                    auto* pBC = reinterpret_cast<CERT_BASIC_CONSTRAINTS2_INFO*>(bcBuf.data());
                    info.isCA = (pBC->fCA != FALSE);
                    if (pBC->fPathLenConstraint) {
                        info.pathLengthConstraint = static_cast<int32_t>(pBC->dwPathLenConstraint);
                    }
                }
            }
        }

        // Key size and algorithm from SubjectPublicKeyInfo
        const auto& pubKeyInfo = pCertContext->pCertInfo->SubjectPublicKeyInfo;
        info.keyAlgorithm = pubKeyInfo.Algorithm.pszObjId ? pubKeyInfo.Algorithm.pszObjId : "";
        info.keySize = CertGetPublicKeyLength(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            const_cast<PCERT_PUBLIC_KEY_INFO>(&pubKeyInfo));

        // Signature algorithm
        info.signatureAlgorithm = pCertContext->pCertInfo->SignatureAlgorithm.pszObjId
            ? pCertContext->pCertInfo->SignatureAlgorithm.pszObjId : "";

        // SHA-256 fingerprint of entire certificate
        {
            Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
            if (hasher.Init()) {
                if (hasher.Update(der.data(), der.size())) {
                    std::vector<uint8_t> digest;
                    if (hasher.Final(digest) && digest.size() == 32) {
                        std::copy_n(digest.begin(), 32, info.sha256Fingerprint.begin());
                    }
                }
            }
        }

        // SPKI Hash (RFC 7469 — hash of DER-encoded SubjectPublicKeyInfo)
        DWORD spkiSize = 0;
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
            &pCertContext->pCertInfo->SubjectPublicKeyInfo, NULL, &spkiSize)) {

            std::vector<uint8_t> spkiData(spkiSize);
            if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                &pCertContext->pCertInfo->SubjectPublicKeyInfo,
                spkiData.data(), &spkiSize)) {

                spkiData.resize(spkiSize);
                Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
                if (hasher.Init()) {
                    if (hasher.Update(spkiData.data(), spkiData.size())) {
                        std::vector<uint8_t> digest;
                        if (hasher.Final(digest) && digest.size() == 32) {
                            std::copy_n(digest.begin(), 32, info.spkiSha256.begin());
                        }
                    }
                }
            }
        }

        CertFreeCertificateContext(pCertContext);
        return info;
    }

    // ========================================================================
    // RESULT FINALIZATION
    // ========================================================================

    ValidationResult FinalizeResult(ValidationResult& result, TimePoint start) {
        auto end = Clock::now();
        result.validationDuration =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        if (result.action == ValidationAction::Block ||
            result.action == ValidationAction::Warn) {
            NotifyViolation(result);

            std::unique_lock lock(m_violationMutex);
            while (m_recentViolations.size() >= MAX_RECENT_VIOLATIONS) {
                m_recentViolations.pop_front();
            }
            m_recentViolations.push_back(result);
        }
        return result;
    }

    void NotifyViolation(const ValidationResult& result) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& cb : m_violationCallbacks) {
            if (!cb) continue;
            try {
                cb(result);
            } catch (const std::exception& ex) {
                SS_LOG_ERROR(LOG_CAT,
                    L"Exception in violation callback: user callback threw.");
                (void)ex;
            } catch (...) {
                SS_LOG_ERROR(LOG_CAT,
                    L"Unknown exception in violation callback.");
            }
        }
    }

    void NotifyError(const std::string& message, int code) {
        std::shared_lock lock(m_callbackMutex);
        for (const auto& cb : m_errorCallbacks) {
            if (!cb) continue;
            try {
                cb(message, code);
            } catch (...) {
                SS_LOG_ERROR(LOG_CAT, L"Exception in error callback.");
            }
        }
    }

    // ========================================================================
    // BYPASS CHECK (thread-safe)
    // ========================================================================

    bool IsBypassed(const std::string& domain) const {
        std::shared_lock lock(m_mutex);
        const std::string normDomain = NormalizeDomain(domain);
        for (const auto& d : m_bypassDomains) {
            if (IsDomainMatch(d, normDomain) || d == normDomain) return true;
        }
        return false;
    }

    // ========================================================================
    // TRUSTED ROOT CHECK (via Windows Certificate Store)
    // ========================================================================

    bool IsTrustedRoot(const CertificateInfo& cert) const {
        if (cert.rawData.empty()) return false;

        PCCERT_CONTEXT pCert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            cert.rawData.data(),
            static_cast<DWORD>(cert.rawData.size()));
        if (!pCert) return false;

        HCERTSTORE hStore = CertOpenSystemStoreW(0, L"ROOT");
        if (!hStore) {
            CertFreeCertificateContext(pCert);
            return false;
        }

        PCCERT_CONTEXT pFound = CertFindCertificateInStore(
            hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_EXISTING,
            pCert,
            nullptr);

        const bool found = (pFound != nullptr);
        if (pFound) CertFreeCertificateContext(pFound);
        CertCloseStore(hStore, 0);
        CertFreeCertificateContext(pCert);
        return found;
    }

    // ========================================================================
    // REVOCATION CHECK (via Windows CryptoAPI chain engine)
    // ========================================================================

    CertificateStatus CheckRevocationImpl(const CertificateInfo& cert) const {
        if (cert.rawData.empty()) return CertificateStatus::ParseError;

        PCCERT_CONTEXT pCert = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            cert.rawData.data(),
            static_cast<DWORD>(cert.rawData.size()));
        if (!pCert) return CertificateStatus::ParseError;

        CERT_CHAIN_PARA chainPara{};
        chainPara.cbSize = sizeof(CERT_CHAIN_PARA);
        chainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;

        DWORD flags = 0;
        if (m_config.revocationMethod == RevocationMethod::OCSP ||
            m_config.revocationMethod == RevocationMethod::Both) {
            flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
        }
        if (m_config.revocationMethod == RevocationMethod::CRL ||
            m_config.revocationMethod == RevocationMethod::Both) {
            flags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
        }

        PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
        BOOL ok = CertGetCertificateChain(
            nullptr, pCert, nullptr, nullptr,
            &chainPara, flags, nullptr, &pChainContext);

        CertificateStatus result = CertificateStatus::Valid;

        if (ok && pChainContext) {
            const DWORD errStatus = pChainContext->TrustStatus.dwErrorStatus;

            if (errStatus & CERT_TRUST_IS_REVOKED) {
                result = CertificateStatus::Revoked;
            } else if (errStatus & CERT_TRUST_REVOCATION_STATUS_UNKNOWN) {
                result = CertificateStatus::OCSPError;
            }
            CertFreeCertificateChain(pChainContext);
        } else {
            // Chain build failed — treat as soft error
            result = CertificateStatus::OCSPError;
        }

        CertFreeCertificateContext(pCert);
        return result;
    }

    // ========================================================================
    // CERTIFICATE TRANSPARENCY CHECK
    // ========================================================================

    bool ValidateCTImpl(const CertificateInfo& cert) const {
        // CT validation verifies that the certificate contains Signed Certificate
        // Timestamps (SCTs) from trusted CT logs. Per Chrome's CT policy, at least
        // 2-3 SCTs from independent logs are required.
        //
        // If no SCTs are present in the certificate, CT is considered violated.
        // Full SCT signature verification requires the CT log public keys.

        if (cert.scts.empty()) {
            SS_LOG_WARN(LOG_CAT,
                L"No SCTs found in certificate for CT validation: %hs",
                cert.subject.c_str());
            return false;
        }

        std::shared_lock lock(m_mutex);
        if (m_trustedCTLogs.empty()) {
            // No trusted logs loaded — cannot verify SCT signatures.
            // Allow if SCTs are present (degraded mode) but log warning.
            SS_LOG_WARN(LOG_CAT,
                L"CT log database not loaded. SCT signature verification skipped.");
            return cert.scts.size() >= 2;
        }

        // Verify that at least 2 SCTs are from distinct trusted log operators
        size_t trustedSCTCount = 0;
        std::unordered_set<std::string> seenOperators;

        for (const auto& sctData : cert.scts) {
            for (const auto& ctLog : m_trustedCTLogs) {
                if (!ctLog.isTrusted) continue;
                // In a full implementation, we would parse the SCT, extract
                // the log ID, and verify the signature. Here we check if the
                // SCT contains a reference to a known log.
                if (!sctData.empty() && !ctLog.logId.empty() &&
                    sctData.find(ctLog.logId) != std::string::npos) {
                    if (seenOperators.insert(ctLog.logOperator).second) {
                        ++trustedSCTCount;
                    }
                }
            }
        }

        if (trustedSCTCount < 2) {
            SS_LOG_WARN(LOG_CAT,
                L"Insufficient trusted SCTs (%zu found, 2 required).",
                trustedSCTCount);
            return false;
        }
        return true;
    }

    // ========================================================================
    // BUILT-IN PINS
    // ========================================================================

    void LoadBuiltInPins() {
        // Real SPKI pin hashes for major banking/financial CAs.
        // These are SHA-256 hashes of the SubjectPublicKeyInfo, base64-encoded,
        // matching the format used in HTTP Public Key Pinning (RFC 7469).
        //
        // NOTE: Pin hashes MUST be updated when CAs rotate certificates.
        // Each domain should have at least one backup pin.
        // Pins are sourced from public certificate transparency logs.

        // DigiCert Global Root G2 (widely used by banking sites)
        AddSPKIPinImpl("*.bankofamerica.com",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", false);
        // DigiCert Global Root CA (backup)
        AddSPKIPinImpl("*.bankofamerica.com",
            "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=", true);

        // Entrust Root Certification Authority - G2 (used by many financial institutions)
        AddSPKIPinImpl("*.chase.com",
            "du6FkDdMcVQ3u8prumAo6t3i3G27uMP2EOhR8R0at/U=", false);
        AddSPKIPinImpl("*.chase.com",
            "HqPF5D7WbC2imDpCpKebHpBnhs6fG1hiFBmgBGOofTg=", true);

        // Wells Fargo
        AddSPKIPinImpl("*.wellsfargo.com",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", false);
        AddSPKIPinImpl("*.wellsfargo.com",
            "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=", true);

        // Citibank
        AddSPKIPinImpl("*.citibank.com",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", false);
        AddSPKIPinImpl("*.citibank.com",
            "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=", true);

        // Google Trust Services (for reference/testing)
        AddSPKIPinImpl("*.google.com",
            "hxqRlPTu1bMS/0DITB1SSu0vd4u/8l8TPoNPAqLJ2mQ=", false);
        AddSPKIPinImpl("*.google.com",
            "Vfd95/PLmZSWc8tUGSo8wZ8TaWjDBwKPU/dbEqvLBLA=", true);

        // PayPal
        AddSPKIPinImpl("*.paypal.com",
            "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=", false);
        AddSPKIPinImpl("*.paypal.com",
            "r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=", true);
    }

    void AddSPKIPinImpl(const std::string& domain, const std::string& b64Hash,
                         bool isBackup = false)
    {
        const std::string normDomain = NormalizeDomain(domain);
        CertificatePin pin;
        pin.domain = normDomain;
        pin.pinHash = b64Hash;
        pin.pinType = PinType::SPKI;
        pin.hashAlgorithm = PinHashAlgorithm::SHA256;
        pin.isBackup = isBackup;
        pin.source = "built-in";
        pin.createdAt = std::chrono::system_clock::now();

        // Called during init while lock is already held, or internally
        m_pinStore[normDomain].push_back(std::move(pin));
    }

    // ========================================================================
    // FILE I/O
    // ========================================================================

    bool LoadPinsFromFileImpl(const std::filesystem::path& path) {
        using namespace Utils;
        using Json = Utils::JSON::Json;

        std::string jsonText;
        FileUtils::Error fileErr{};
        if (!FileUtils::ReadAllTextUtf8(path.wstring(), jsonText, &fileErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to read pin database file.");
            return false;
        }

        // Cap file size to prevent abuse
        if (jsonText.size() > 4 * 1024 * 1024) {
            SS_LOG_ERROR(LOG_CAT, L"Pin database file exceeds 4MB size limit.");
            return false;
        }

        Json doc;
        JSON::Error parseErr{};
        if (!JSON::Parse(jsonText, doc, &parseErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to parse pin database JSON.");
            return false;
        }

        if (!doc.contains("pins") || !doc["pins"].is_array()) {
            SS_LOG_ERROR(LOG_CAT, L"Pin database missing 'pins' array.");
            return false;
        }

        std::unique_lock lock(m_mutex);
        size_t loaded = 0;

        for (const auto& entry : doc["pins"]) {
            if (!entry.contains("domain") || !entry.contains("hash")) continue;

            CertificatePin pin;
            pin.domain = NormalizeDomain(entry.value("domain", ""));
            pin.pinHash = entry.value("hash", "");
            pin.pinType = static_cast<PinType>(entry.value("type", 1));
            pin.hashAlgorithm = static_cast<PinHashAlgorithm>(
                entry.value("algorithm", 0));
            pin.isBackup = entry.value("backup", false);
            pin.source = entry.value("source", "file");
            pin.expectedIssuer = entry.value("issuer", "");
            pin.createdAt = std::chrono::system_clock::now();

            if (pin.domain.empty() || pin.pinHash.empty()) continue;

            // Validate base64 encoding of pin hash
            std::vector<uint8_t> decoded;
            if (!CryptoUtils::Base64::Decode(pin.pinHash, decoded) || decoded.empty()) {
                SS_LOG_WARN(LOG_CAT,
                    L"Skipping pin with invalid base64 hash for domain.");
                continue;
            }

            auto& domainPins = m_pinStore[pin.domain];
            if (domainPins.size() < CertPinningConstants::MAX_PINS_PER_DOMAIN) {
                domainPins.push_back(std::move(pin));
                ++loaded;
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Loaded %zu pins from file.", loaded);
        return loaded > 0;
    }

    bool SavePinsToFileImpl(const std::filesystem::path& path) const {
        using Json = Utils::JSON::Json;

        std::shared_lock lock(m_mutex);

        Json doc;
        Json pinsArray = Json::array();

        for (const auto& [domain, pins] : m_pinStore) {
            for (const auto& pin : pins) {
                Json entry;
                entry["domain"] = pin.domain;
                entry["hash"] = pin.pinHash;
                entry["type"] = static_cast<uint8_t>(pin.pinType);
                entry["algorithm"] = static_cast<uint8_t>(pin.hashAlgorithm);
                entry["backup"] = pin.isBackup;
                entry["source"] = pin.source;
                entry["issuer"] = pin.expectedIssuer;
                pinsArray.push_back(std::move(entry));
            }
        }

        doc["pins"] = std::move(pinsArray);
        doc["version"] = CertificatePinning::GetVersionString();

        lock.unlock();

        std::string jsonStr;
        Utils::JSON::StringifyOptions opts;
        opts.pretty = true;
        opts.indentSpaces = 2;
        if (!Utils::JSON::Stringify(doc, jsonStr, opts)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to serialize pin database to JSON.");
            return false;
        }

        Utils::FileUtils::Error fileErr{};
        if (!Utils::FileUtils::WriteAllTextUtf8Atomic(path.wstring(), jsonStr, &fileErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to write pin database file.");
            return false;
        }

        SS_LOG_INFO(LOG_CAT, L"Pin database saved to file.");
        return true;
    }

    bool LoadCTLogsFromFileImpl(const std::filesystem::path& path) {
        using Json = Utils::JSON::Json;

        std::string jsonText;
        Utils::FileUtils::Error fileErr{};
        if (!Utils::FileUtils::ReadAllTextUtf8(path.wstring(), jsonText, &fileErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to read CT logs file.");
            return false;
        }

        Json doc;
        Utils::JSON::Error parseErr{};
        if (!Utils::JSON::Parse(jsonText, doc, &parseErr)) {
            SS_LOG_ERROR(LOG_CAT, L"Failed to parse CT logs JSON.");
            return false;
        }

        if (!doc.contains("logs") || !doc["logs"].is_array()) {
            SS_LOG_ERROR(LOG_CAT, L"CT logs file missing 'logs' array.");
            return false;
        }

        std::unique_lock lock(m_mutex);
        m_trustedCTLogs.clear();

        for (const auto& entry : doc["logs"]) {
            CTLogEntry log;
            log.logId = entry.value("log_id", "");
            log.logName = entry.value("description", "");
            log.logOperator = entry.value("operator", "");
            log.logUrl = entry.value("url", "");
            log.publicKey = entry.value("key", "");
            log.isTrusted = entry.value("trusted", true);

            if (!log.logId.empty()) {
                m_trustedCTLogs.push_back(std::move(log));
            }
        }

        SS_LOG_INFO(LOG_CAT, L"Loaded %zu trusted CT logs.", m_trustedCTLogs.size());
        return !m_trustedCTLogs.empty();
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
    return s_instanceCreated.load(std::memory_order_acquire);
}

CertificatePinning::CertificatePinning()
    : m_impl(std::make_unique<CertificatePinningImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

CertificatePinning::~CertificatePinning() {
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
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
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CAT, L"Invalid configuration rejected.");
        return false;
    }
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;

    // Update bypass domains
    m_impl->m_bypassDomains.clear();
    for (const auto& d : config.bypassDomains) {
        m_impl->m_bypassDomains.push_back(NormalizeDomain(d));
    }

    SS_LOG_INFO(LOG_CAT, L"Configuration updated.");
    return true;
}

CertificatePinningConfiguration CertificatePinning::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

void CertificatePinning::SetMode(PinningMode mode) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config.mode = mode;
    SS_LOG_INFO(LOG_CAT, L"Pinning mode changed to: %hs",
                std::string(GetPinningModeName(mode)).c_str());
}

PinningMode CertificatePinning::GetMode() const noexcept {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config.mode;
}

// ============================================================================
// PIN MANAGEMENT
// ============================================================================

bool CertificatePinning::LoadDefaultBankPins() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->LoadBuiltInPins();
    SS_LOG_INFO(LOG_CAT, L"Default bank pins loaded. Domains: %zu",
                m_impl->m_pinStore.size());
    return true;
}

bool CertificatePinning::LoadPinsFromFile(const std::filesystem::path& path) {
    return m_impl->LoadPinsFromFileImpl(path);
}

bool CertificatePinning::SavePinsToFile(const std::filesystem::path& path) const {
    return m_impl->SavePinsToFileImpl(path);
}

void CertificatePinning::AddPin(const CertificatePin& pin) {
    m_impl->AddPin(pin);
}

void CertificatePinning::AddSPKIPin(const std::string& domain,
                                      const std::string& spkiHash,
                                      bool isBackup)
{
    // Validate the hash is valid base64 before adding
    std::vector<uint8_t> decoded;
    if (!Utils::CryptoUtils::Base64::Decode(spkiHash, decoded) || decoded.empty()) {
        SS_LOG_ERROR(LOG_CAT, L"Rejected SPKI pin: invalid base64 hash.");
        return;
    }
    if (decoded.size() != CertPinningConstants::PIN_HASH_LENGTH) {
        SS_LOG_ERROR(LOG_CAT, L"Rejected SPKI pin: hash size %zu != expected %zu.",
                     decoded.size(), CertPinningConstants::PIN_HASH_LENGTH);
        return;
    }

    CertificatePin pin;
    pin.domain = NormalizeDomain(domain);
    pin.pinHash = spkiHash;
    pin.pinType = PinType::SPKI;
    pin.hashAlgorithm = PinHashAlgorithm::SHA256;
    pin.isBackup = isBackup;
    pin.source = "api";
    pin.createdAt = std::chrono::system_clock::now();
    m_impl->AddPin(pin);
}

void CertificatePinning::RemovePin(const std::string& domain) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_pinStore.erase(NormalizeDomain(domain));
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
    SS_LOG_INFO(LOG_CAT, L"All pins cleared.");
}

// ============================================================================
// VALIDATION
// ============================================================================

ValidationResult CertificatePinning::ValidateConnection(
    const std::string& domain,
    std::span<const std::vector<uint8_t>> certChain)
{
    return m_impl->ValidateConnection(domain, certChain);
}

ValidationResult CertificatePinning::ValidateCertificateChain(
    const std::string& domain,
    const std::vector<CertificateInfo>& chain)
{
    // Re-validate using the CertificateInfo objects that already contain
    // pre-computed SPKI hashes and parsed metadata.
    ValidationResult result;
    result.domain = domain;
    result.validationTime = std::chrono::system_clock::now();
    auto start = Clock::now();

    if (chain.empty()) {
        result.status = CertificateStatus::ParseError;
        result.action = ValidationAction::Block;
        result.errorDetails = "Empty certificate chain";
        return result;
    }

    result.certificateChain = chain;
    const auto& leaf = chain[0];
    result.actualHash = Utils::CryptoUtils::Base64::Encode(
        leaf.spkiSha256.data(), leaf.spkiSha256.size());

    // Check expiry
    for (const auto& cert : chain) {
        if (cert.IsExpired()) {
            result.status = CertificateStatus::Expired;
            result.errorDetails = "Certificate expired: " + cert.subject;
            result.action = ValidationAction::Block;
            return result;
        }
    }

    // Check pins
    auto pins = GetPins(domain);
    if (!pins.empty()) {
        bool matchFound = false;
        for (const auto& pin : pins) {
            if (pin.IsExpired()) continue;
            for (const auto& cert : chain) {
                if (pin.hashAlgorithm == PinHashAlgorithm::SHA256) {
                    result.expectedHashes.push_back(pin.pinHash);
                    if (SecurePinCompare(pin.pinHash, cert.spkiSha256)) {
                        matchFound = true;
                        break;
                    }
                }
            }
            if (matchFound) break;
        }

        result.isPinMatch = matchFound;
        if (!matchFound) {
            result.status = CertificateStatus::PinMismatch;
            result.action = ValidationAction::Block;
            result.errorDetails = "Pin mismatch for " + domain;
            return result;
        }
    }

    result.status = CertificateStatus::Valid;
    result.action = ValidationAction::Allow;
    return result;
}

bool CertificatePinning::CheckPinMatch(
    const std::string& domain,
    const CertificateInfo& certificate) const
{
    auto pins = GetPins(domain);
    if (pins.empty()) return true;

    for (const auto& pin : pins) {
        if (pin.IsExpired()) continue;
        if (pin.hashAlgorithm == PinHashAlgorithm::SHA256) {
            if (SecurePinCompare(pin.pinHash, certificate.spkiSha256)) {
                return true;
            }
        }
    }
    return false;
}

bool CertificatePinning::ValidateCertificateTransparency(
    const CertificateInfo& certificate) const
{
    return m_impl->ValidateCTImpl(certificate);
}

CertificateStatus CertificatePinning::CheckRevocation(
    const CertificateInfo& certificate) const
{
    return m_impl->CheckRevocationImpl(certificate);
}

// ============================================================================
// CERTIFICATE PARSING
// ============================================================================

std::optional<CertificateInfo> CertificatePinning::ParseCertificate(
    std::span<const uint8_t> derData) const
{
    std::vector<uint8_t> data(derData.begin(), derData.end());
    return m_impl->ParseCert(data);
}

std::vector<CertificateInfo> CertificatePinning::ParseCertificateChain(
    std::span<const std::vector<uint8_t>> chainData) const
{
    return m_impl->ParseChain(chainData);
}

Hash256 CertificatePinning::CalculateSPKIHash(
    std::span<const uint8_t> derData) const
{
    auto info = ParseCertificate(derData);
    if (info) return info->spkiSha256;
    return Hash256{};
}

Hash256 CertificatePinning::CalculateFingerprint(
    std::span<const uint8_t> derData) const
{
    Hash256 fingerprint{};
    if (derData.empty()) return fingerprint;

    Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
    if (hasher.Init() &&
        hasher.Update(derData.data(), derData.size())) {
        std::vector<uint8_t> digest;
        if (hasher.Final(digest) && digest.size() == 32) {
            std::copy_n(digest.begin(), 32, fingerprint.begin());
        }
    }
    return fingerprint;
}

std::string CertificatePinning::CalculatePin(
    std::span<const uint8_t> derData) const
{
    auto hash = CalculateSPKIHash(derData);
    return Utils::CryptoUtils::Base64::Encode(hash.data(), hash.size());
}

// ============================================================================
// CT LOG MANAGEMENT
// ============================================================================

bool CertificatePinning::LoadTrustedCTLogs(const std::filesystem::path& path) {
    return m_impl->LoadCTLogsFromFileImpl(path);
}

void CertificatePinning::AddTrustedCTLog(const CTLogEntry& log) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_trustedCTLogs.push_back(log);
    SS_LOG_DEBUG(LOG_CAT, L"Added trusted CT log: %hs", log.logName.c_str());
}

std::vector<CTLogEntry> CertificatePinning::GetTrustedCTLogs() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_trustedCTLogs;
}

// ============================================================================
// BYPASS MANAGEMENT
// ============================================================================

void CertificatePinning::AddBypassDomain(const std::string& domain) {
    std::unique_lock lock(m_impl->m_mutex);
    const std::string norm = NormalizeDomain(domain);
    // Prevent duplicates
    auto it = std::find(m_impl->m_bypassDomains.begin(),
                        m_impl->m_bypassDomains.end(), norm);
    if (it == m_impl->m_bypassDomains.end()) {
        m_impl->m_bypassDomains.push_back(norm);
        SS_LOG_INFO(LOG_CAT, L"Added bypass domain.");
    }
}

void CertificatePinning::RemoveBypassDomain(const std::string& domain) {
    std::unique_lock lock(m_impl->m_mutex);
    const std::string norm = NormalizeDomain(domain);
    auto it = std::find(m_impl->m_bypassDomains.begin(),
                        m_impl->m_bypassDomains.end(), norm);
    if (it != m_impl->m_bypassDomains.end()) {
        m_impl->m_bypassDomains.erase(it);
        SS_LOG_INFO(LOG_CAT, L"Removed bypass domain.");
    }
}

bool CertificatePinning::IsBypassedDomain(const std::string& domain) const {
    return m_impl->IsBypassed(domain);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void CertificatePinning::RegisterViolationCallback(ViolationCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_violationCallbacks.push_back(std::move(callback));
}

void CertificatePinning::RegisterPinUpdateCallback(PinUpdateCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_pinUpdateCallbacks.push_back(std::move(callback));
}

void CertificatePinning::RegisterErrorCallback(ErrorCallback callback) {
    if (!callback) return;
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallbacks.push_back(std::move(callback));
}

void CertificatePinning::UnregisterCallbacks() {
    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_violationCallbacks.clear();
    m_impl->m_pinUpdateCallbacks.clear();
    m_impl->m_errorCallbacks.clear();
}

// ============================================================================
// STATISTICS
// ============================================================================

PinningStatistics CertificatePinning::GetStatistics() const {
    PinningStatistics s;
    s.totalValidations.store(m_impl->m_stats.totalValidations.load(std::memory_order_relaxed));
    s.successfulValidations.store(m_impl->m_stats.successfulValidations.load(std::memory_order_relaxed));
    s.pinMismatches.store(m_impl->m_stats.pinMismatches.load(std::memory_order_relaxed));
    s.mitmDetections.store(m_impl->m_stats.mitmDetections.load(std::memory_order_relaxed));
    s.expiredCerts.store(m_impl->m_stats.expiredCerts.load(std::memory_order_relaxed));
    s.revokedCerts.store(m_impl->m_stats.revokedCerts.load(std::memory_order_relaxed));
    s.ctViolations.store(m_impl->m_stats.ctViolations.load(std::memory_order_relaxed));
    s.connectionsBlocked.store(m_impl->m_stats.connectionsBlocked.load(std::memory_order_relaxed));
    s.cacheHits.store(m_impl->m_stats.cacheHits.load(std::memory_order_relaxed));
    s.startTime = m_impl->m_stats.startTime;
    return s;
}

void CertificatePinning::ResetStatistics() {
    m_impl->m_stats.Reset();
}

std::vector<ValidationResult> CertificatePinning::GetRecentViolations(
    size_t maxCount) const
{
    std::lock_guard lock(m_impl->m_violationMutex);
    const auto& src = m_impl->m_recentViolations;

    if (maxCount == 0 || maxCount >= src.size()) {
        return {src.begin(), src.end()};
    }

    // Return the most recent maxCount entries
    auto startIt = src.end() - static_cast<ptrdiff_t>(maxCount);
    return {startIt, src.end()};
}

// ============================================================================
// SELF-TEST
// ============================================================================

bool CertificatePinning::SelfTest() {
    SS_LOG_INFO(LOG_CAT, L"Starting self-test...");

    // Test 1: Domain matching
    if (!IsDomainMatch("*.bank.com", "www.bank.com")) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: wildcard domain match");
        return false;
    }
    if (IsDomainMatch("*.bank.com", "evil.sub.bank.com")) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: multi-level wildcard should not match");
        return false;
    }
    if (IsDomainMatch("*.bank.com", "bank.com")) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: wildcard should not match bare domain");
        return false;
    }
    // Case insensitivity
    if (!IsDomainMatch("*.BANK.COM", "www.bank.com")) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: case-insensitive domain match");
        return false;
    }

    // Test 2: Base64 round-trip
    const uint8_t testData[] = {0x01, 0x02, 0x03, 0x04};
    std::string b64 = Utils::CryptoUtils::Base64::Encode(testData, 4);
    std::vector<uint8_t> decoded;
    if (b64.empty() || !Utils::CryptoUtils::Base64::Decode(b64, decoded) ||
        decoded.size() != 4) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: Base64 round-trip");
        return false;
    }

    // Test 3: SHA-256 hashing
    Utils::HashUtils::Hasher hasher(Utils::HashUtils::Algorithm::SHA256);
    if (!hasher.Init()) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: Hasher init");
        return false;
    }
    const char* msg = "test";
    if (!hasher.Update(msg, 4)) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: Hasher update");
        return false;
    }
    std::vector<uint8_t> digest;
    if (!hasher.Final(digest) || digest.size() != 32) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: Hasher final");
        return false;
    }

    // Test 4: SecureCompare
    std::vector<uint8_t> a = {1, 2, 3};
    std::vector<uint8_t> b = {1, 2, 3};
    std::vector<uint8_t> c = {1, 2, 4};
    if (!Utils::CryptoUtils::SecureCompare(a, b)) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: SecureCompare equal");
        return false;
    }
    if (Utils::CryptoUtils::SecureCompare(a, c)) {
        SS_LOG_ERROR(LOG_CAT, L"Self-test failed: SecureCompare not-equal");
        return false;
    }

    SS_LOG_INFO(LOG_CAT, L"Self-test passed.");
    return true;
}

std::string CertificatePinning::GetVersionString() noexcept {
    return std::to_string(CertPinningConstants::VERSION_MAJOR) + "." +
           std::to_string(CertPinningConstants::VERSION_MINOR) + "." +
           std::to_string(CertPinningConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCT METHODS
// ============================================================================

bool CertificatePin::IsExpired() const noexcept {
    if (expiration.time_since_epoch().count() == 0) return false; // No expiry set
    return std::chrono::system_clock::now() > expiration;
}

bool CertificateInfo::IsExpired() const noexcept {
    if (notAfter.time_since_epoch().count() == 0) return false; // Uninitialized
    return std::chrono::system_clock::now() > notAfter;
}

bool CertificateInfo::IsNotYetValid() const noexcept {
    if (notBefore.time_since_epoch().count() == 0) return false;
    return std::chrono::system_clock::now() < notBefore;
}

int32_t CertificateInfo::GetDaysUntilExpiry() const noexcept {
    auto diff = notAfter - std::chrono::system_clock::now();
    auto hours = std::chrono::duration_cast<std::chrono::hours>(diff).count();
    return static_cast<int32_t>(hours / 24);
}

bool ValidationResult::IsValid() const noexcept {
    return status == CertificateStatus::Valid &&
           action != ValidationAction::Block;
}

// ============================================================================
// JSON SERIALIZATION
// ============================================================================

std::string CertificatePin::ToJson() const {
    std::ostringstream ss;
    // Manual JSON to avoid header dependency on nlohmann in struct methods
    ss << "{\"domain\":\"" << domain
       << "\",\"pinHash\":\"" << pinHash
       << "\",\"pinType\":" << static_cast<unsigned>(pinType)
       << ",\"hashAlgorithm\":" << static_cast<unsigned>(hashAlgorithm)
       << ",\"isBackup\":" << (isBackup ? "true" : "false")
       << ",\"source\":\"" << source
       << "\",\"expectedIssuer\":\"" << expectedIssuer
       << "\"}";
    return ss.str();
}

std::string CertificateInfo::ToJson() const {
    std::ostringstream ss;
    ss << "{\"subject\":\"" << subject
       << "\",\"issuer\":\"" << issuer
       << "\",\"serialNumber\":\"" << serialNumber
       << "\",\"keyAlgorithm\":\"" << keyAlgorithm
       << "\",\"keySize\":" << keySize
       << ",\"signatureAlgorithm\":\"" << signatureAlgorithm
       << "\",\"isCA\":" << (isCA ? "true" : "false")
       << ",\"daysUntilExpiry\":" << GetDaysUntilExpiry()
       << ",\"fingerprint\":\"" << Utils::HashUtils::ToHexLower(sha256Fingerprint.data(), sha256Fingerprint.size())
       << "\"}";
    return ss.str();
}

std::string ValidationResult::ToJson() const {
    std::ostringstream ss;
    ss << "{\"domain\":\"" << domain
       << "\",\"status\":\"" << GetCertificateStatusName(status)
       << "\",\"action\":\"" << GetValidationActionName(action)
       << "\",\"isPinMatch\":" << (isPinMatch ? "true" : "false")
       << ",\"isMitMDetected\":" << (isMitMDetected ? "true" : "false")
       << ",\"isCTValid\":" << (isCTValid ? "true" : "false")
       << ",\"isRevoked\":" << (isRevoked ? "true" : "false")
       << ",\"actualHash\":\"" << actualHash
       << "\",\"errorDetails\":\"" << errorDetails
       << "\",\"validationDurationMs\":" << validationDuration.count()
       << ",\"chainLength\":" << certificateChain.size()
       << "}";
    return ss.str();
}

std::string PinningStatistics::ToJson() const {
    std::ostringstream ss;
    ss << "{\"totalValidations\":" << totalValidations.load(std::memory_order_relaxed)
       << ",\"successfulValidations\":" << successfulValidations.load(std::memory_order_relaxed)
       << ",\"pinMismatches\":" << pinMismatches.load(std::memory_order_relaxed)
       << ",\"mitmDetections\":" << mitmDetections.load(std::memory_order_relaxed)
       << ",\"expiredCerts\":" << expiredCerts.load(std::memory_order_relaxed)
       << ",\"revokedCerts\":" << revokedCerts.load(std::memory_order_relaxed)
       << ",\"ctViolations\":" << ctViolations.load(std::memory_order_relaxed)
       << ",\"connectionsBlocked\":" << connectionsBlocked.load(std::memory_order_relaxed)
       << ",\"cacheHits\":" << cacheHits.load(std::memory_order_relaxed)
       << "}";
    return ss.str();
}

bool CertificatePinningConfiguration::IsValid() const noexcept {
    if (minRSAKeySize < 1024) return false;
    if (minECKeySize < 160) return false;
    if (mode > PinningMode::Strict) return false;
    if (revocationMethod > RevocationMethod::Both) return false;
    return true;
}

void PinningStatistics::Reset() noexcept {
    totalValidations.store(0, std::memory_order_relaxed);
    successfulValidations.store(0, std::memory_order_relaxed);
    pinMismatches.store(0, std::memory_order_relaxed);
    mitmDetections.store(0, std::memory_order_relaxed);
    expiredCerts.store(0, std::memory_order_relaxed);
    revokedCerts.store(0, std::memory_order_relaxed);
    ctViolations.store(0, std::memory_order_relaxed);
    connectionsBlocked.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetPinningModeName(PinningMode mode) noexcept {
    switch (mode) {
        case PinningMode::Disabled:     return "Disabled";
        case PinningMode::ReportOnly:   return "ReportOnly";
        case PinningMode::Enforce:      return "Enforce";
        case PinningMode::Strict:       return "Strict";
        default:                        return "Unknown";
    }
}

std::string_view GetPinTypeName(PinType type) noexcept {
    switch (type) {
        case PinType::Unknown:          return "Unknown";
        case PinType::SPKI:             return "SPKI";
        case PinType::LeafCert:         return "LeafCert";
        case PinType::IntermediateCert: return "IntermediateCert";
        case PinType::RootCert:         return "RootCert";
        default:                        return "Unknown";
    }
}

std::string_view GetCertificateStatusName(CertificateStatus status) noexcept {
    switch (status) {
        case CertificateStatus::Valid:              return "Valid";
        case CertificateStatus::PinMismatch:        return "PinMismatch";
        case CertificateStatus::Expired:            return "Expired";
        case CertificateStatus::NotYetValid:        return "NotYetValid";
        case CertificateStatus::Revoked:            return "Revoked";
        case CertificateStatus::UntrustedRoot:      return "UntrustedRoot";
        case CertificateStatus::SelfSigned:         return "SelfSigned";
        case CertificateStatus::ChainError:         return "ChainError";
        case CertificateStatus::SignatureInvalid:   return "SignatureInvalid";
        case CertificateStatus::WeakKey:            return "WeakKey";
        case CertificateStatus::WeakSignature:      return "WeakSignature";
        case CertificateStatus::NameMismatch:       return "NameMismatch";
        case CertificateStatus::CTViolation:        return "CTViolation";
        case CertificateStatus::OCSPError:          return "OCSPError";
        case CertificateStatus::CRLError:           return "CRLError";
        case CertificateStatus::ProxyCertificate:   return "ProxyCertificate";
        case CertificateStatus::ParseError:         return "ParseError";
        case CertificateStatus::Unknown:            return "Unknown";
        default:                                    return "Unknown";
    }
}

std::string_view GetValidationActionName(ValidationAction action) noexcept {
    switch (action) {
        case ValidationAction::None:    return "None";
        case ValidationAction::Allow:   return "Allow";
        case ValidationAction::Warn:    return "Warn";
        case ValidationAction::Block:   return "Block";
        default:                        return "Unknown";
    }
}

bool IsSelfSigned(const CertificateInfo& cert) {
    // Case-insensitive subject/issuer comparison for self-signed detection
    return !cert.subject.empty() && !cert.issuer.empty() &&
           NormalizeDomain(cert.subject) == NormalizeDomain(cert.issuer);
}

bool IsCACertificate(const CertificateInfo& cert) {
    return cert.isCA;
}

bool DomainMatches(std::string_view pattern, std::string_view domain) {
    return IsDomainMatch(std::string(pattern), std::string(domain));
}

std::string Base64Encode(std::span<const uint8_t> data) {
    return Utils::CryptoUtils::Base64::Encode(data.data(), data.size());
}

std::vector<uint8_t> Base64Decode(std::string_view base64) {
    std::vector<uint8_t> decoded;
    if (!Utils::CryptoUtils::Base64::Decode(base64, decoded)) {
        return {};
    }
    return decoded;
}

}  // namespace Banking
}  // namespace ShadowStrike
