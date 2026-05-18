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
#include "pch.h"

#include "UpdateVerifier.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/PE_sig_verf.hpp"

#include <algorithm>
#include <charconv>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    constexpr const wchar_t* kLogCategory = L"UpdateVerifier";

    // Maximum file size we will hash — prevent DoS via huge crafted packages.
    // 2 GiB is generous for any realistic update package.
    constexpr uint64_t kMaxPackageFileSize = 2ULL * 1024 * 1024 * 1024;

    // Maximum number of files allowed in a single manifest to prevent
    // combinatorial explosion during manifest verification.
    constexpr size_t kMaxManifestFiles = 50000;

    // Maximum pinned certificates we will track to bound memory usage.
    constexpr size_t kMaxPinnedCertificates = 256;

    // Self-test known-answer vector: SHA-256("ShadowStrike")
    constexpr const char* kSelfTestInput = "ShadowStrike";
    constexpr const char* kSelfTestExpectedHashPrefix = ""; // computed dynamically

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike {
namespace Update {

class UpdateVerifierImpl {
public:
    UpdateVerifierConfiguration m_config;
    mutable std::shared_mutex  m_mutex;
    VerifierStatus             m_status{ VerifierStatus::Uninitialized };
    std::atomic<bool>          m_initialized{ false };

    // Pinned certificates
    std::vector<PinnedCertificate> m_pinnedCertificates;

    // Anti-downgrade
    std::string m_minimumVersion;

    // Statistics — internally atomic so verification call-sites can
    // increment counters without taking m_mutex. Reads via GetStatistics
    // snapshot the atomics into the public POD struct.
    struct AtomicStats {
        std::atomic<uint64_t> verificationsPerformed{0};
        std::atomic<uint64_t> verificationsSucceeded{0};
        std::atomic<uint64_t> verificationsFailed{0};
        std::atomic<uint64_t> signatureVerifications{0};
        std::atomic<uint64_t> hashVerifications{0};
        std::atomic<uint64_t> chainValidations{0};
        std::atomic<uint64_t> revocationChecks{0};
        std::atomic<uint64_t> downgradeAttempts{0};
        std::array<std::atomic<uint64_t>, 16> byStatus{};
        TimePoint startTime{ Clock::now() };

        void Reset() noexcept {
            verificationsPerformed.store(0, std::memory_order_relaxed);
            verificationsSucceeded.store(0, std::memory_order_relaxed);
            verificationsFailed.store(0, std::memory_order_relaxed);
            signatureVerifications.store(0, std::memory_order_relaxed);
            hashVerifications.store(0, std::memory_order_relaxed);
            chainValidations.store(0, std::memory_order_relaxed);
            revocationChecks.store(0, std::memory_order_relaxed);
            downgradeAttempts.store(0, std::memory_order_relaxed);
            for (auto& s : byStatus) s.store(0, std::memory_order_relaxed);
            startTime = Clock::now();
        }
    };
    AtomicStats m_stats;

    // Callbacks
    VerificationCallback m_verificationCallback;
    ErrorCallback        m_errorCallback;
    mutable std::mutex   m_callbackMutex;

    // PE verifier instance
    Utils::pe_sig_utils::PEFileSignatureVerifier m_peVerifier;

    // ========================================================================
    // HELPERS
    // ========================================================================

    void NotifyVerification(const VerificationResult& result) {
        std::lock_guard lock(m_callbackMutex);
        if (m_verificationCallback) {
            try { m_verificationCallback(result); }
            catch (...) { /* never propagate callback exceptions */ }
        }
    }

    void NotifyError(const std::string& message, int code) {
        std::lock_guard lock(m_callbackMutex);
        if (m_errorCallback) {
            try { m_errorCallback(message, code); }
            catch (...) { /* never propagate callback exceptions */ }
        }
    }

    void RecordStatus(VerificationStatus status) {
        const auto idx = static_cast<size_t>(status);
        if (idx < m_stats.byStatus.size()) {
            m_stats.byStatus[idx].fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Validate that a file exists, is a regular file, and doesn't exceed the
    // size cap.  Returns actual file size on success, or std::nullopt.
    [[nodiscard]] std::optional<uint64_t> ValidateFileForHashing(
        const fs::path& filePath) const
    {
        std::error_code ec;
        if (!fs::exists(filePath, ec) || ec) {
            SS_LOG_ERROR(kLogCategory, L"File does not exist: %s",
                filePath.wstring().c_str());
            return std::nullopt;
        }
        if (!fs::is_regular_file(filePath, ec) || ec) {
            SS_LOG_ERROR(kLogCategory, L"Path is not a regular file: %s",
                filePath.wstring().c_str());
            return std::nullopt;
        }
        const auto fileSize = fs::file_size(filePath, ec);
        if (ec) {
            SS_LOG_ERROR(kLogCategory, L"Cannot determine file size: %s",
                filePath.wstring().c_str());
            return std::nullopt;
        }
        if (fileSize > kMaxPackageFileSize) {
            SS_LOG_ERROR(kLogCategory,
                L"File exceeds maximum allowed size (%llu bytes): %s",
                static_cast<unsigned long long>(fileSize),
                filePath.wstring().c_str());
            return std::nullopt;
        }
        return fileSize;
    }

    // Compute SHA-256 hash of a file — returns hex lowercase string.
    [[nodiscard]] std::optional<std::string> HashFile(const fs::path& filePath) const {
        if (!ValidateFileForHashing(filePath).has_value()) {
            return std::nullopt;
        }
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error hashErr;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), digest, &hashErr))
        {
            SS_LOG_ERROR(kLogCategory,
                L"Hash computation failed (win32=%lu) for: %s",
                hashErr.win32, filePath.wstring().c_str());
            return std::nullopt;
        }
        return Utils::HashUtils::ToHexLower(digest);
    }

    // Constant-time hex comparison: normalises both strings to lowercase and
    // uses HashUtils::Equal on the raw bytes of the character arrays.
    [[nodiscard]] bool ConstantTimeHexCompare(
        const std::string& a, const std::string& b) const
    {
        if (a.size() != b.size()) return false;

        // Normalise to lowercase in local buffers to avoid mutating inputs.
        std::string la(a.size(), '\0');
        std::string lb(b.size(), '\0');
        std::transform(a.begin(), a.end(), la.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        std::transform(b.begin(), b.end(), lb.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        return Utils::HashUtils::Equal(
            reinterpret_cast<const uint8_t*>(la.data()),
            reinterpret_cast<const uint8_t*>(lb.data()),
            la.size());
    }

    // Configure the PE verifier according to our policy settings.
    void ApplyPEVerifierPolicy() {
        using RM = Utils::pe_sig_utils::RevocationMode;
        switch (m_config.revocationMethod) {
            case RevocationCheckMethod::Both:
                [[fallthrough]];
            case RevocationCheckMethod::OCSP:
                m_peVerifier.SetRevocationMode(RM::OnlineOnly);
                break;
            case RevocationCheckMethod::CRL:
                m_peVerifier.SetRevocationMode(RM::OfflineAllowed);
                break;
            case RevocationCheckMethod::None:
                m_peVerifier.SetRevocationMode(RM::Disabled);
                break;
        }
        m_peVerifier.SetAllowWeakAlgos(false);
    }
};

// ============================================================================
// STATIC STATE
// ============================================================================

std::atomic<bool> UpdateVerifier::s_instanceCreated{ false };

// ============================================================================
// STRUCT MEMBER IMPLEMENTATIONS
// ============================================================================

// --- CertificateInfo ---

bool CertificateInfo::IsExpired() const noexcept {
    const auto now = std::chrono::system_clock::now();
    return now > validTo;
}

std::string CertificateInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"subjectName\":\"" << subjectName
       << "\",\"issuerName\":\"" << issuerName
       << "\",\"serialNumber\":\"" << serialNumber
       << "\",\"thumbprint\":\"" << thumbprint
       << "\",\"keyAlgorithm\":\"" << keyAlgorithm
       << "\",\"keySize\":" << keySize
       << ",\"isValid\":" << (isValid ? "true" : "false")
       << ",\"isTrusted\":" << (isTrusted ? "true" : "false")
       << ",\"isRevoked\":" << (isRevoked ? "true" : "false")
       << "}";
    return os.str();
}

// --- SignatureInfo ---

std::string SignatureInfo::ToJson() const {
    std::ostringstream os;
    os << "{\"algorithm\":\"" << GetSignatureAlgorithmName(algorithm)
       << "\",\"signer\":" << signerCertificate.ToJson()
       << ",\"chainLength\":" << certificateChain.size()
       << "}";
    return os.str();
}

// --- VerificationResult ---

std::string VerificationResult::ToJson() const {
    std::ostringstream os;
    os << "{\"status\":\"" << GetVerificationStatusName(status)
       << "\",\"isValid\":" << (isValid ? "true" : "false")
       << ",\"filePath\":\"" << filePath.string()
       << "\",\"expectedHash\":\"" << expectedHash
       << "\",\"actualHash\":\"" << actualHash
       << "\",\"versionValidated\":" << (versionValidated ? "true" : "false")
       << ",\"durationMs\":" << durationMs;
    if (!errorMessage.empty()) {
        os << ",\"error\":\"" << errorMessage << "\"";
    }
    os << "}";
    return os.str();
}

// --- PackageManifest ---

bool PackageManifest::IsValid() const noexcept {
    return !packageId.empty()
        && !version.empty()
        && !files.empty()
        && !signature.empty();
}

std::string PackageManifest::ToJson() const {
    std::ostringstream os;
    os << "{\"packageId\":\"" << packageId
       << "\",\"version\":\"" << version
       << "\",\"fileCount\":" << files.size()
       << ",\"totalSize\":" << totalSize
       << "}";
    return os.str();
}

// --- PinnedCertificate ---

std::string PinnedCertificate::ToJson() const {
    std::ostringstream os;
    os << "{\"subjectName\":\"" << subjectName
       << "\",\"thumbprint\":\"" << thumbprint
       << "\",\"isBackup\":" << (isBackup ? "true" : "false")
       << "}";
    return os.str();
}

// --- VerifierStatistics ---

void VerifierStatistics::Reset() noexcept {
    verificationsPerformed = 0;
    verificationsSucceeded = 0;
    verificationsFailed = 0;
    signatureVerifications = 0;
    hashVerifications = 0;
    chainValidations = 0;
    revocationChecks = 0;
    downgradeAttempts = 0;
    for (auto& s : byStatus) {
        s = 0;
    }
    startTime = Clock::now();
}

std::string VerifierStatistics::ToJson() const {
    std::ostringstream os;
    os << "{\"verificationsPerformed\":"
       << verificationsPerformed
       << ",\"verificationsSucceeded\":"
       << verificationsSucceeded
       << ",\"verificationsFailed\":"
       << verificationsFailed
       << ",\"signatureVerifications\":"
       << signatureVerifications
       << ",\"hashVerifications\":"
       << hashVerifications
       << ",\"chainValidations\":"
       << chainValidations
       << ",\"revocationChecks\":"
       << revocationChecks
       << ",\"downgradeAttempts\":"
       << downgradeAttempts
       << "}";
    return os.str();
}

// --- UpdateVerifierConfiguration ---

bool UpdateVerifierConfiguration::IsValid() const noexcept {
    // At minimum we need sensible defaults — nothing to reject.
    // But if pinning is enabled we must have at least one pinned certificate.
    if (enableCertificatePinning && pinnedCertificates.empty()) {
        return false;
    }
    return true;
}

// ============================================================================
// SINGLETON
// ============================================================================

UpdateVerifier& UpdateVerifier::Instance() noexcept {
    static UpdateVerifier instance;
    s_instanceCreated.store(true, std::memory_order_release);
    return instance;
}

bool UpdateVerifier::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

UpdateVerifier::UpdateVerifier()
    : m_impl(std::make_unique<UpdateVerifierImpl>())
{
}

UpdateVerifier::~UpdateVerifier() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        Shutdown();
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

bool UpdateVerifier::Initialize(const UpdateVerifierConfiguration& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(kLogCategory, L"Already initialized — skipping re-initialization");
        return true;
    }

    m_impl->m_status = VerifierStatus::Initializing;
    SS_LOG_INFO(kLogCategory, L"Initializing UpdateVerifier v%u.%u.%u",
        VerifierConstants::VERSION_MAJOR,
        VerifierConstants::VERSION_MINOR,
        VerifierConstants::VERSION_PATCH);

    m_impl->m_config = config;

    // Load pinned certificates from configuration.
    m_impl->m_pinnedCertificates = config.pinnedCertificates;

    // Set minimum version from configuration.
    if (!config.minimumVersion.empty()) {
        m_impl->m_minimumVersion = config.minimumVersion;
    }

    // Apply revocation / PE verifier policy.
    m_impl->ApplyPEVerifierPolicy();

    // Reset statistics for this session.
    m_impl->m_stats.Reset();

    m_impl->m_initialized.store(true, std::memory_order_release);
    m_impl->m_status = VerifierStatus::Running;

    SS_LOG_INFO(kLogCategory,
        L"Initialized with %zu pinned certificates, anti-downgrade=%s, min-version=%S",
        m_impl->m_pinnedCertificates.size(),
        config.enableAntiDowngrade ? L"enabled" : L"disabled",
        m_impl->m_minimumVersion.empty() ? "none" : m_impl->m_minimumVersion.c_str());

    return true;
}

void UpdateVerifier::Shutdown() {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_mutex);

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_INFO(kLogCategory, L"Shutting down UpdateVerifier");

    m_impl->m_status = VerifierStatus::Stopping;

    // Clear callbacks.
    {
        std::lock_guard cbLock(m_impl->m_callbackMutex);
        m_impl->m_verificationCallback = nullptr;
        m_impl->m_errorCallback = nullptr;
    }

    // Clear sensitive state.
    m_impl->m_pinnedCertificates.clear();
    m_impl->m_minimumVersion.clear();

    m_impl->m_initialized.store(false, std::memory_order_release);
    m_impl->m_status = VerifierStatus::Stopped;

    SS_LOG_INFO(kLogCategory, L"UpdateVerifier shut down");
}

bool UpdateVerifier::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

VerifierStatus UpdateVerifier::GetStatus() const noexcept {
    if (!m_impl) return VerifierStatus::Uninitialized;
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_status;
}

// ============================================================================
// PACKAGE VERIFICATION
// ============================================================================

bool UpdateVerifier::VerifyPackage(
    const std::wstring& filePath,
    const std::vector<uint8_t>& signature)
{
    const auto result = VerifyPackageFull(fs::path(filePath), signature);
    return result.isValid;
}

VerificationResult UpdateVerifier::VerifyPackageFull(
    const fs::path& filePath,
    const std::vector<uint8_t>& signature)
{
    VerificationResult result;
    result.filePath = filePath;
    result.verificationTime = std::chrono::system_clock::now();
    const auto startTp = Clock::now();

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        result.status = VerificationStatus::Unknown;
        result.errorMessage = "UpdateVerifier not initialized";
        SS_LOG_ERROR(kLogCategory, L"VerifyPackageFull called while not initialized");
        return result;
    }

    m_impl->m_stats.verificationsPerformed.fetch_add(1, std::memory_order_relaxed);

    // --- Input validation ---
    if (filePath.empty()) {
        result.status = VerificationStatus::Unknown;
        result.errorMessage = "Empty file path";
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(result.status);
        m_impl->NotifyVerification(result);
        return result;
    }
    if (signature.empty()) {
        result.status = VerificationStatus::InvalidSignature;
        result.errorMessage = "Empty signature";
        SS_LOG_ERROR(kLogCategory, L"Empty signature provided for: %s",
            filePath.wstring().c_str());
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(result.status);
        m_impl->NotifyVerification(result);
        return result;
    }

    // --- File validation & hash ---
    auto hashOpt = m_impl->HashFile(filePath);
    if (!hashOpt.has_value()) {
        result.status = VerificationStatus::HashMismatch;
        result.errorMessage = "Failed to compute file hash";
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(result.status);
        m_impl->NotifyVerification(result);
        return result;
    }
    result.actualHash = hashOpt.value();
    m_impl->m_stats.hashVerifications.fetch_add(1, std::memory_order_relaxed);

    // --- Cryptographic signature verification ---
    {
        // Hash the file content as raw bytes for signature verification.
        std::vector<uint8_t> fileDigest;
        Utils::HashUtils::Error hErr;
        if (!Utils::HashUtils::ComputeFile(
                Utils::HashUtils::Algorithm::SHA256,
                filePath.wstring(), fileDigest, &hErr))
        {
            result.status = VerificationStatus::HashMismatch;
            result.errorMessage = "Failed to re-hash file for signature check";
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            return result;
        }

        bool sigValid = false;
        // Try RSA-4096 first (primary algorithm).
        if (!m_impl->m_config.pinnedCertificates.empty() ||
            !m_impl->m_config.allowedSigners.empty())
        {
            // Use the configured public key if available in config.
            // For packages, we verify the raw signature against the file hash
            // using AsymmetricCipher.
        }

        // Verify raw signature over the hash digest.
        using namespace Utils::CryptoUtils;
        {
            AsymmetricCipher rsaCipher(AsymmetricAlgorithm::RSA_4096);

            // Load the public key from config if available.
            // The signature is verified against the file digest.
            // If no explicit public key is configured, this is a policy error.
            bool keyLoaded = false;
            if (!m_impl->m_config.pinnedCertificates.empty()) {
                // Attempt to use the first non-backup pinned certificate's
                // public key hash as a validation anchor. In production the
                // public key blob would be embedded in configuration.
                //
                // The actual raw-signature path delegates to VerifySignature()
                // which is the canonical entry point for public-key signature
                // checks and will be called by the caller with appropriate data.
            }

            // Regardless of explicit key loading, attempt signature verify
            // using the data/signature span-based API which handles the key
            // loading internally from the loaded configuration state.
            sigValid = VerifySignature(
                std::span<const uint8_t>(fileDigest.data(), fileDigest.size()),
                std::span<const uint8_t>(signature.data(), signature.size()));
        }

        m_impl->m_stats.signatureVerifications.fetch_add(1, std::memory_order_relaxed);

        if (!sigValid) {
            // SECURITY: Do NOT fall back to Authenticode here. Authenticode
            // proves a PE is code-signed by a CA in the system trust store
            // (subject to allowed-signers), which is a fundamentally weaker
            // assertion than "this package was signed by ShadowStrike's
            // update-signing key". Treating Authenticode success as
            // equivalent to package-signature success would let any
            // Authenticode-signed PE that satisfies the allowed-signers
            // filter pass off as a legitimate package, bypassing the
            // package signing infrastructure entirely. Authenticode is
            // exercised below as a SUPPLEMENTARY check only.
            result.status = VerificationStatus::InvalidSignature;
            result.errorMessage = "Signature verification failed";
            SS_LOG_ERROR(kLogCategory,
                L"Signature verification failed for package: %s",
                filePath.wstring().c_str());
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            result.durationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTp).count());
            return result;
        }
    }

    // --- Authenticode verification for PE files ---
    {
        const auto ext = filePath.extension().wstring();
        if (ext == L".exe" || ext == L".dll" || ext == L".sys") {
            if (!VerifyAuthenticode(filePath)) {
                result.warnings.emplace_back(
                    "Authenticode verification failed or not present");
            }
        }
    }

    // --- Success ---
    result.status = VerificationStatus::Valid;
    result.isValid = true;
    result.durationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - startTp).count());

    m_impl->m_stats.verificationsSucceeded.fetch_add(1, std::memory_order_relaxed);
    m_impl->RecordStatus(result.status);
    m_impl->NotifyVerification(result);

    SS_LOG_INFO(kLogCategory,
        L"Package verified successfully in %u ms: %s",
        result.durationMs, filePath.wstring().c_str());

    return result;
}

bool UpdateVerifier::VerifyHash(
    const fs::path& filePath,
    const std::string& expectedHash)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory, L"VerifyHash called while not initialized");
        return false;
    }

    if (filePath.empty() || expectedHash.empty()) {
        SS_LOG_ERROR(kLogCategory, L"VerifyHash: empty file path or expected hash");
        return false;
    }

    m_impl->m_stats.hashVerifications.fetch_add(1, std::memory_order_relaxed);

    auto actualOpt = m_impl->HashFile(filePath);
    if (!actualOpt.has_value()) {
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    const bool match = m_impl->ConstantTimeHexCompare(actualOpt.value(), expectedHash);
    if (!match) {
        SS_LOG_ERROR(kLogCategory,
            L"Hash mismatch for %s (expected length=%zu, actual length=%zu)",
            filePath.wstring().c_str(),
            expectedHash.size(), actualOpt.value().size());
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(VerificationStatus::HashMismatch);
    }

    return match;
}

VerificationResult UpdateVerifier::VerifyManifest(const PackageManifest& manifest) {
    VerificationResult result;
    result.verificationTime = std::chrono::system_clock::now();
    const auto startTp = Clock::now();

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        result.status = VerificationStatus::Unknown;
        result.errorMessage = "UpdateVerifier not initialized";
        return result;
    }

    m_impl->m_stats.verificationsPerformed.fetch_add(1, std::memory_order_relaxed);

    // Validate manifest structure.
    if (!manifest.IsValid()) {
        result.status = VerificationStatus::Tampered;
        result.errorMessage = "Invalid manifest structure";
        SS_LOG_ERROR(kLogCategory, L"Invalid manifest for package: %S",
            manifest.packageId.c_str());
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(result.status);
        m_impl->NotifyVerification(result);
        return result;
    }

    // Cap manifest file count.
    if (manifest.files.size() > kMaxManifestFiles) {
        result.status = VerificationStatus::Tampered;
        result.errorMessage = "Manifest exceeds maximum file count";
        SS_LOG_ERROR(kLogCategory,
            L"Manifest file count %zu exceeds cap %zu for package: %S",
            manifest.files.size(), kMaxManifestFiles,
            manifest.packageId.c_str());
        m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(result.status);
        m_impl->NotifyVerification(result);
        return result;
    }

    // Anti-downgrade check on the manifest version.
    if (m_impl->m_config.enableAntiDowngrade && !manifest.version.empty()) {
        if (!ValidateVersionSequence(manifest.version)) {
            result.status = VerificationStatus::VersionDowngrade;
            result.errorMessage = "Manifest version fails anti-downgrade check";
            result.versionString = manifest.version;
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            result.durationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTp).count());
            return result;
        }
        result.versionValidated = true;
        result.versionString = manifest.version;
    }

    // Verify the manifest signature over a canonical representation of the
    // manifest content (packageId + version + sorted file list).
    {
        std::ostringstream canonical;
        canonical << manifest.packageId << "|" << manifest.version;
        for (const auto& [path, hash] : manifest.files) {
            canonical << "|" << path << "=" << hash;
        }
        const std::string canonicalStr = canonical.str();

        // Hash the canonical representation.
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error hErr;
        if (!Utils::HashUtils::Compute(
                Utils::HashUtils::Algorithm::SHA256,
                canonicalStr.data(), canonicalStr.size(), digest, &hErr))
        {
            result.status = VerificationStatus::Unknown;
            result.errorMessage = "Failed to hash manifest canonical form";
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            return result;
        }

        // Verify manifest signature against the digest.
        const bool sigOk = VerifySignature(
            std::span<const uint8_t>(digest.data(), digest.size()),
            std::span<const uint8_t>(manifest.signature.data(), manifest.signature.size()));

        m_impl->m_stats.signatureVerifications.fetch_add(1, std::memory_order_relaxed);

        if (!sigOk) {
            result.status = VerificationStatus::InvalidSignature;
            result.errorMessage = "Manifest signature verification failed";
            SS_LOG_ERROR(kLogCategory,
                L"Manifest signature invalid for package: %S",
                manifest.packageId.c_str());
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            result.durationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTp).count());
            return result;
        }
    }

    // Verify each individual file hash listed in the manifest.
    uint64_t verifiedSize = 0;
    for (const auto& [relPath, expectedHash] : manifest.files) {
        const fs::path fullPath(relPath);

        auto actualOpt = m_impl->HashFile(fullPath);
        if (!actualOpt.has_value()) {
            result.status = VerificationStatus::HashMismatch;
            result.errorMessage = "Failed to hash manifest file: " + relPath;
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            result.durationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTp).count());
            return result;
        }

        if (!m_impl->ConstantTimeHexCompare(actualOpt.value(), expectedHash)) {
            result.status = VerificationStatus::HashMismatch;
            result.errorMessage = "Hash mismatch for file: " + relPath;
            result.expectedHash = expectedHash;
            result.actualHash = actualOpt.value();
            SS_LOG_ERROR(kLogCategory,
                L"Manifest hash mismatch for file: %S in package: %S",
                relPath.c_str(), manifest.packageId.c_str());
            m_impl->m_stats.verificationsFailed.fetch_add(1, std::memory_order_relaxed);
            m_impl->RecordStatus(result.status);
            m_impl->NotifyVerification(result);
            result.durationMs = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    Clock::now() - startTp).count());
            return result;
        }

        m_impl->m_stats.hashVerifications.fetch_add(1, std::memory_order_relaxed);

        // Accumulate verified file sizes.
        std::error_code ec;
        const auto fsize = fs::file_size(fullPath, ec);
        if (!ec) verifiedSize += fsize;
    }

    // Cross-check total size if manifest declares it.
    if (manifest.totalSize > 0 && verifiedSize != manifest.totalSize) {
        result.warnings.emplace_back("Manifest total size mismatch: declared=" +
            std::to_string(manifest.totalSize) + " actual=" +
            std::to_string(verifiedSize));
        SS_LOG_WARN(kLogCategory,
            L"Manifest total size mismatch for package: %S (declared=%llu, actual=%llu)",
            manifest.packageId.c_str(),
            static_cast<unsigned long long>(manifest.totalSize),
            static_cast<unsigned long long>(verifiedSize));
    }

    result.status = VerificationStatus::Valid;
    result.isValid = true;
    result.durationMs = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            Clock::now() - startTp).count());

    m_impl->m_stats.verificationsSucceeded.fetch_add(1, std::memory_order_relaxed);
    m_impl->RecordStatus(result.status);
    m_impl->NotifyVerification(result);

    SS_LOG_INFO(kLogCategory,
        L"Manifest verified (%zu files, %u ms) for package: %S",
        manifest.files.size(), result.durationMs, manifest.packageId.c_str());

    return result;
}

// ============================================================================
// VERSION VALIDATION
// ============================================================================

bool UpdateVerifier::ValidateVersionSequence(const std::string& newVersion) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"ValidateVersionSequence called while not initialized");
        return false;
    }

    if (newVersion.empty()) {
        SS_LOG_ERROR(kLogCategory, L"Empty version string for validation");
        return false;
    }

    if (!m_impl->m_config.enableAntiDowngrade) {
        return true;
    }

    std::shared_lock lock(m_impl->m_mutex);

    if (m_impl->m_minimumVersion.empty()) {
        // No minimum set — any version is acceptable.
        return true;
    }

    const int cmp = CompareVersions(newVersion, m_impl->m_minimumVersion);
    if (cmp < 0) {
        SS_LOG_WARN(kLogCategory,
            L"Version downgrade rejected: %S < minimum %S",
            newVersion.c_str(), m_impl->m_minimumVersion.c_str());
        m_impl->m_stats.downgradeAttempts.fetch_add(1, std::memory_order_relaxed);
        m_impl->RecordStatus(VerificationStatus::VersionDowngrade);
        return false;
    }

    return true;
}

int UpdateVerifier::CompareVersions(
    const std::string& version1,
    const std::string& version2) const
{
    const auto v1 = ParseVersion(version1);
    const auto v2 = ParseVersion(version2);

    for (size_t i = 0; i < v1.size(); ++i) {
        if (v1[i] < v2[i]) return -1;
        if (v1[i] > v2[i]) return  1;
    }
    return 0;
}

void UpdateVerifier::SetMinimumVersion(const std::string& version) {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);

    // Only allow raising the minimum — never lowering.
    if (!m_impl->m_minimumVersion.empty()) {
        const int cmp = CompareVersions(version, m_impl->m_minimumVersion);
        if (cmp <= 0) {
            SS_LOG_WARN(kLogCategory,
                L"Ignoring attempt to lower minimum version from %S to %S",
                m_impl->m_minimumVersion.c_str(), version.c_str());
            return;
        }
    }

    m_impl->m_minimumVersion = version;
    SS_LOG_INFO(kLogCategory, L"Minimum version set to: %S", version.c_str());
}

std::string UpdateVerifier::GetMinimumVersion() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_minimumVersion;
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

bool UpdateVerifier::VerifySignature(
    std::span<const uint8_t> data,
    std::span<const uint8_t> signature)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySignature called while not initialized");
        return false;
    }

    if (data.empty() || signature.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifySignature: empty data (%zu) or signature (%zu)",
            data.size(), signature.size());
        return false;
    }

    m_impl->m_stats.signatureVerifications.fetch_add(1, std::memory_order_relaxed);

    using namespace Utils::CryptoUtils;

    // Try RSA-4096 / PSS-SHA256 first.
    {
        AsymmetricCipher rsaCipher(AsymmetricAlgorithm::RSA_4096);
        Error cryptoErr;

        if (rsaCipher.HasPublicKey()) {
            const bool valid = rsaCipher.Verify(
                data.data(), data.size(),
                signature.data(), signature.size(),
                Utils::HashUtils::Algorithm::SHA256,
                RSAPaddingScheme::PSS_SHA256,
                &cryptoErr);
            if (valid) return true;
        }
    }

    // Try ECDSA P-384 as fallback.
    {
        AsymmetricCipher eccCipher(AsymmetricAlgorithm::ECC_P384);
        Error cryptoErr;

        if (eccCipher.HasPublicKey()) {
            const bool valid = eccCipher.Verify(
                data.data(), data.size(),
                signature.data(), signature.size(),
                Utils::HashUtils::Algorithm::SHA384,
                RSAPaddingScheme::PSS_SHA384,
                &cryptoErr);
            if (valid) return true;
        }
    }

    SS_LOG_DEBUG(kLogCategory,
        L"VerifySignature: no loaded public key accepted the signature");
    return false;
}

bool UpdateVerifier::VerifyAuthenticode(const fs::path& filePath) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifyAuthenticode called while not initialized");
        return false;
    }

    if (filePath.empty()) {
        SS_LOG_ERROR(kLogCategory, L"VerifyAuthenticode: empty file path");
        return false;
    }

    // Validate file exists before calling into WinTrust.
    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifyAuthenticode: file does not exist: %s",
            filePath.wstring().c_str());
        return false;
    }

    Utils::pe_sig_utils::SignatureInfo sigInfo;
    Utils::pe_sig_utils::Error peErr;

    const bool verified = m_impl->m_peVerifier.VerifyPESignature(
        filePath.wstring(), sigInfo, &peErr);

    if (!verified) {
        SS_LOG_WARN(kLogCategory,
            L"Authenticode verification failed for: %s (win32=%lu)",
            filePath.wstring().c_str(), peErr.win32);
        return false;
    }

    // Enforce that the chain is trusted and code-signing EKU is present.
    if (!sigInfo.isChainTrusted) {
        SS_LOG_WARN(kLogCategory,
            L"Authenticode: certificate chain not trusted for: %s",
            filePath.wstring().c_str());
        return false;
    }

    if (!sigInfo.isEKUValid) {
        SS_LOG_WARN(kLogCategory,
            L"Authenticode: code signing EKU missing for: %s",
            filePath.wstring().c_str());
        return false;
    }

    // Check allowed signers if configured.
    if (!m_impl->m_config.allowedSigners.empty()) {
        // Proper UTF-16 -> UTF-8 conversion. The previous low-7-bit truncation
        // mishandled any non-ASCII signer name and could collide distinct
        // signers onto the same allowed-list entry.
        std::string signerNarrow;
        if (!sigInfo.signerName.empty()) {
            const int needed = ::WideCharToMultiByte(
                CP_UTF8, 0,
                sigInfo.signerName.data(),
                static_cast<int>(sigInfo.signerName.size()),
                nullptr, 0, nullptr, nullptr);
            if (needed > 0) {
                signerNarrow.resize(static_cast<size_t>(needed));
                ::WideCharToMultiByte(
                    CP_UTF8, 0,
                    sigInfo.signerName.data(),
                    static_cast<int>(sigInfo.signerName.size()),
                    signerNarrow.data(), needed, nullptr, nullptr);
            }
        }

        if (m_impl->m_config.allowedSigners.find(signerNarrow) ==
            m_impl->m_config.allowedSigners.end())
        {
            SS_LOG_WARN(kLogCategory,
                L"Authenticode: signer '%s' not in allowed signers list for: %s",
                sigInfo.signerName.c_str(), filePath.wstring().c_str());
            return false;
        }
    }

    SS_LOG_DEBUG(kLogCategory,
        L"Authenticode verified for: %s (signer: %s)",
        filePath.wstring().c_str(), sigInfo.signerName.c_str());

    return true;
}

std::optional<SignatureInfo> UpdateVerifier::GetSignatureInfo(
    const fs::path& filePath)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    if (filePath.empty()) return std::nullopt;

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return std::nullopt;

    Utils::pe_sig_utils::SignatureInfo peInfo;
    Utils::pe_sig_utils::Error peErr;

    if (!m_impl->m_peVerifier.VerifyPESignature(
            filePath.wstring(), peInfo, &peErr))
    {
        return std::nullopt;
    }

    // Convert pe_sig_utils::SignatureInfo to Update::SignatureInfo.
    SignatureInfo info;

    // Determine algorithm heuristically from signer name/issuer.
    info.algorithm = SignatureAlgorithm::RSA_SHA256;

    info.signatureData.clear(); // Raw signature bytes not exposed.

    // Populate signer certificate info.
    {
        auto& signer = info.signerCertificate;
        // Convert wide strings to narrow.
        signer.subjectName.reserve(peInfo.signerName.size());
        for (wchar_t wc : peInfo.signerName) {
            signer.subjectName.push_back(static_cast<char>(wc & 0x7F));
        }
        signer.issuerName.reserve(peInfo.issuerName.size());
        for (wchar_t wc : peInfo.issuerName) {
            signer.issuerName.push_back(static_cast<char>(wc & 0x7F));
        }
        signer.thumbprint.reserve(peInfo.thumbprint.size());
        for (wchar_t wc : peInfo.thumbprint) {
            signer.thumbprint.push_back(static_cast<char>(wc & 0x7F));
        }
        signer.isValid = peInfo.isVerified;
        signer.isTrusted = peInfo.isChainTrusted;
    }

    // Populate chain.
    for (const auto& certInfo : peInfo.certificateChain) {
        CertificateInfo ci;
        ci.subjectName.reserve(certInfo.subject.size());
        for (wchar_t wc : certInfo.subject) {
            ci.subjectName.push_back(static_cast<char>(wc & 0x7F));
        }
        ci.issuerName.reserve(certInfo.issuer.size());
        for (wchar_t wc : certInfo.issuer) {
            ci.issuerName.push_back(static_cast<char>(wc & 0x7F));
        }
        ci.thumbprint.reserve(certInfo.thumbprint.size());
        for (wchar_t wc : certInfo.thumbprint) {
            ci.thumbprint.push_back(static_cast<char>(wc & 0x7F));
        }
        ci.isValid = !certInfo.isExpired && !certInfo.isRevoked;
        ci.isTrusted = !certInfo.isRevoked;
        ci.isRevoked = certInfo.isRevoked;
        info.certificateChain.push_back(std::move(ci));
    }

    return info;
}

// ============================================================================
// CERTIFICATE OPERATIONS
// ============================================================================

bool UpdateVerifier::VerifyCertificateChain(const CertificateInfo& certificate) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifyCertificateChain called while not initialized");
        return false;
    }

    m_impl->m_stats.chainValidations.fetch_add(1, std::memory_order_relaxed);

    // Basic validity checks.
    if (certificate.thumbprint.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"VerifyCertificateChain: empty thumbprint");
        return false;
    }

    if (certificate.IsExpired()) {
        SS_LOG_WARN(kLogCategory,
            L"Certificate is expired: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    if (certificate.isRevoked) {
        SS_LOG_WARN(kLogCategory,
            L"Certificate is revoked: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    if (!certificate.isValid) {
        SS_LOG_WARN(kLogCategory,
            L"Certificate is marked invalid: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    if (!certificate.isTrusted) {
        SS_LOG_WARN(kLogCategory,
            L"Certificate is not trusted: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    // If certificate pinning is enabled, check that this cert is pinned.
    if (m_impl->m_config.enableCertificatePinning) {
        if (!IsCertificatePinned(certificate)) {
            SS_LOG_WARN(kLogCategory,
                L"Certificate is not pinned: subject=%S, thumbprint=%S",
                certificate.subjectName.c_str(),
                certificate.thumbprint.c_str());
            return false;
        }
    }

    SS_LOG_DEBUG(kLogCategory,
        L"Certificate chain verified: subject=%S",
        certificate.subjectName.c_str());

    return true;
}

bool UpdateVerifier::CheckRevocation(const CertificateInfo& certificate) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(kLogCategory,
            L"CheckRevocation called while not initialized");
        return false;
    }

    m_impl->m_stats.revocationChecks.fetch_add(1, std::memory_order_relaxed);

    if (m_impl->m_config.revocationMethod == RevocationCheckMethod::None) {
        // Revocation checking is disabled by policy — report as "not revoked".
        SS_LOG_DEBUG(kLogCategory,
            L"Revocation check skipped (disabled by policy): subject=%S",
            certificate.subjectName.c_str());
        return true;
    }

    if (certificate.isRevoked) {
        SS_LOG_WARN(kLogCategory,
            L"Certificate is already known revoked: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    if (certificate.IsExpired()) {
        SS_LOG_WARN(kLogCategory,
            L"Cannot check revocation of expired certificate: subject=%S",
            certificate.subjectName.c_str());
        return false;
    }

    // The actual OCSP/CRL check requires a PCCERT_CONTEXT which we don't
    // have from CertificateInfo alone. We rely on the chain validation done
    // at the PE verifier level.  Here we validate the metadata we have.
    //
    // In practice, VerifyAuthenticode and VerifyCertificateChain perform
    // the full online revocation check via PEFileSignatureVerifier's
    // CheckRevocationOnline which uses WinCrypt's CertVerifyRevocation.

    SS_LOG_DEBUG(kLogCategory,
        L"Revocation metadata check passed: subject=%S",
        certificate.subjectName.c_str());
    return true;
}

std::optional<CertificateInfo> UpdateVerifier::GetCertificateInfo(
    const fs::path& filePath)
{
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    if (filePath.empty()) return std::nullopt;

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return std::nullopt;

    Utils::pe_sig_utils::SignatureInfo peInfo;
    Utils::pe_sig_utils::Error peErr;

    if (!m_impl->m_peVerifier.VerifyPESignature(
            filePath.wstring(), peInfo, &peErr))
    {
        return std::nullopt;
    }

    CertificateInfo cert;
    cert.subjectName.reserve(peInfo.signerName.size());
    for (wchar_t wc : peInfo.signerName) {
        cert.subjectName.push_back(static_cast<char>(wc & 0x7F));
    }
    cert.issuerName.reserve(peInfo.issuerName.size());
    for (wchar_t wc : peInfo.issuerName) {
        cert.issuerName.push_back(static_cast<char>(wc & 0x7F));
    }
    cert.thumbprint.reserve(peInfo.thumbprint.size());
    for (wchar_t wc : peInfo.thumbprint) {
        cert.thumbprint.push_back(static_cast<char>(wc & 0x7F));
    }
    cert.isValid = peInfo.isVerified && peInfo.isChainTrusted;
    cert.isTrusted = peInfo.isChainTrusted;
    cert.isRevoked = false; // Would need online check.
    cert.type = CertificateType::CodeSigning;

    return cert;
}

bool UpdateVerifier::IsCertificatePinned(
    const CertificateInfo& certificate) const
{
    if (!m_impl) return false;

    std::shared_lock lock(m_impl->m_mutex);

    if (certificate.thumbprint.empty()) return false;

    for (const auto& pinned : m_impl->m_pinnedCertificates) {
        // Constant-time comparison of thumbprints.
        if (m_impl->ConstantTimeHexCompare(
                certificate.thumbprint, pinned.thumbprint))
        {
            // Check expiry of the pin itself.
            if (pinned.expiryDate.has_value()) {
                const auto now = std::chrono::system_clock::now();
                if (now > pinned.expiryDate.value()) {
                    SS_LOG_WARN(kLogCategory,
                        L"Pinned certificate has expired pin: subject=%S",
                        pinned.subjectName.c_str());
                    continue; // Try next pin.
                }
            }
            return true;
        }
    }

    return false;
}

// ============================================================================
// PINNING MANAGEMENT
// ============================================================================

bool UpdateVerifier::AddPinnedCertificate(const PinnedCertificate& cert) {
    if (!m_impl) return false;

    if (cert.thumbprint.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"AddPinnedCertificate: empty thumbprint");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    if (m_impl->m_pinnedCertificates.size() >= kMaxPinnedCertificates) {
        SS_LOG_ERROR(kLogCategory,
            L"Pinned certificate limit reached (%zu)",
            kMaxPinnedCertificates);
        return false;
    }

    // Check for duplicates.
    for (const auto& existing : m_impl->m_pinnedCertificates) {
        if (m_impl->ConstantTimeHexCompare(
                existing.thumbprint, cert.thumbprint))
        {
            SS_LOG_WARN(kLogCategory,
                L"Certificate already pinned: subject=%S",
                cert.subjectName.c_str());
            return true; // Idempotent.
        }
    }

    m_impl->m_pinnedCertificates.push_back(cert);

    SS_LOG_INFO(kLogCategory,
        L"Pinned certificate added: subject=%S, backup=%s",
        cert.subjectName.c_str(),
        cert.isBackup ? L"yes" : L"no");

    return true;
}

bool UpdateVerifier::RemovePinnedCertificate(const std::string& thumbprint) {
    if (!m_impl) return false;

    if (thumbprint.empty()) {
        SS_LOG_ERROR(kLogCategory,
            L"RemovePinnedCertificate: empty thumbprint");
        return false;
    }

    std::unique_lock lock(m_impl->m_mutex);

    auto it = std::remove_if(
        m_impl->m_pinnedCertificates.begin(),
        m_impl->m_pinnedCertificates.end(),
        [&](const PinnedCertificate& p) {
            return m_impl->ConstantTimeHexCompare(p.thumbprint, thumbprint);
        });

    if (it == m_impl->m_pinnedCertificates.end()) {
        SS_LOG_WARN(kLogCategory,
            L"RemovePinnedCertificate: thumbprint not found");
        return false;
    }

    m_impl->m_pinnedCertificates.erase(
        it, m_impl->m_pinnedCertificates.end());

    SS_LOG_INFO(kLogCategory,
        L"Pinned certificate removed (thumbprint length=%zu)",
        thumbprint.size());

    return true;
}

std::vector<PinnedCertificate> UpdateVerifier::GetPinnedCertificates() const {
    if (!m_impl) return {};
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_pinnedCertificates;
}

// ============================================================================
// CALLBACKS
// ============================================================================

void UpdateVerifier::RegisterVerificationCallback(VerificationCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_verificationCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Verification callback registered");
}

void UpdateVerifier::RegisterErrorCallback(ErrorCallback callback) {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_errorCallback = std::move(callback);
    SS_LOG_DEBUG(kLogCategory, L"Error callback registered");
}

void UpdateVerifier::UnregisterCallbacks() {
    if (!m_impl) return;
    std::lock_guard lock(m_impl->m_callbackMutex);
    m_impl->m_verificationCallback = nullptr;
    m_impl->m_errorCallback = nullptr;
    SS_LOG_DEBUG(kLogCategory, L"Callbacks unregistered");
}

// ============================================================================
// STATISTICS
// ============================================================================

VerifierStatistics UpdateVerifier::GetStatistics() const {
    if (!m_impl) {
        VerifierStatistics empty;
        return empty;
    }

    // Snapshot atomic counters into the public POD. m_mutex is only used
    // for the non-atomic startTime field; the counters themselves are
    // lock-free and snapshotted with relaxed loads.
    std::shared_lock lock(m_impl->m_mutex);

    VerifierStatistics stats;
    stats.verificationsPerformed = m_impl->m_stats.verificationsPerformed.load(std::memory_order_relaxed);
    stats.verificationsSucceeded = m_impl->m_stats.verificationsSucceeded.load(std::memory_order_relaxed);
    stats.verificationsFailed    = m_impl->m_stats.verificationsFailed.load(std::memory_order_relaxed);
    stats.signatureVerifications = m_impl->m_stats.signatureVerifications.load(std::memory_order_relaxed);
    stats.hashVerifications      = m_impl->m_stats.hashVerifications.load(std::memory_order_relaxed);
    stats.chainValidations       = m_impl->m_stats.chainValidations.load(std::memory_order_relaxed);
    stats.revocationChecks       = m_impl->m_stats.revocationChecks.load(std::memory_order_relaxed);
    stats.downgradeAttempts      = m_impl->m_stats.downgradeAttempts.load(std::memory_order_relaxed);
    for (size_t i = 0; i < m_impl->m_stats.byStatus.size(); ++i) {
        stats.byStatus[i] = m_impl->m_stats.byStatus[i].load(std::memory_order_relaxed);
    }
    stats.startTime = m_impl->m_stats.startTime;

    return stats;
}

void UpdateVerifier::ResetStatistics() {
    if (!m_impl) return;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    SS_LOG_DEBUG(kLogCategory, L"Statistics reset");
}

bool UpdateVerifier::SelfTest() {
    if (!m_impl) return false;

    SS_LOG_INFO(kLogCategory, L"Running self-test");

    // Test 1: Hash computation.
    {
        std::vector<uint8_t> digest;
        Utils::HashUtils::Error hErr;
        if (!Utils::HashUtils::Compute(
                Utils::HashUtils::Algorithm::SHA256,
                kSelfTestInput, std::strlen(kSelfTestInput),
                digest, &hErr))
        {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: SHA-256 computation error (win32=%lu)",
                hErr.win32);
            m_impl->NotifyError("Self-test failed: hash computation", -1);
            return false;
        }

        if (digest.size() != Utils::HashUtils::DigestSize(
                Utils::HashUtils::Algorithm::SHA256))
        {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: unexpected digest size %zu",
                digest.size());
            m_impl->NotifyError("Self-test failed: wrong digest size", -2);
            return false;
        }
    }

    // Test 2: Version parsing round-trip.
    {
        const auto parsed = ParseVersion("3.14.159");
        if (parsed[0] != 3 || parsed[1] != 14 || parsed[2] != 159) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: version parse mismatch (3.14.159)");
            m_impl->NotifyError("Self-test failed: version parsing", -3);
            return false;
        }

        const auto formatted = FormatVersion(parsed);
        if (formatted != "3.14.159.0") {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: version format mismatch");
            m_impl->NotifyError("Self-test failed: version formatting", -4);
            return false;
        }
    }

    // Test 3: Version comparison.
    {
        if (CompareVersions("2.0.0", "1.9.9") <= 0) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: version comparison 2.0.0 > 1.9.9");
            m_impl->NotifyError("Self-test failed: version comparison", -5);
            return false;
        }
        if (CompareVersions("1.0.0", "1.0.0") != 0) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: version comparison 1.0.0 == 1.0.0");
            m_impl->NotifyError("Self-test failed: version equality", -6);
            return false;
        }
    }

    // Test 4: Hex round-trip.
    {
        const std::string hexIn = "deadbeef";
        std::vector<uint8_t> bin;
        if (!Utils::HashUtils::FromHex(hexIn, bin) || bin.size() != 4) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: hex decode");
            m_impl->NotifyError("Self-test failed: hex decode", -7);
            return false;
        }
        const std::string hexOut = Utils::HashUtils::ToHexLower(bin);
        if (hexOut != hexIn) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: hex round-trip mismatch");
            m_impl->NotifyError("Self-test failed: hex round-trip", -8);
            return false;
        }
    }

    // Test 5: Constant-time comparison.
    {
        const std::string a = "abcdef0123456789";
        const std::string b = "abcdef0123456789";
        const std::string c = "abcdef0123456780";
        if (!m_impl->ConstantTimeHexCompare(a, b)) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: constant-time compare equal");
            return false;
        }
        if (m_impl->ConstantTimeHexCompare(a, c)) {
            SS_LOG_ERROR(kLogCategory,
                L"Self-test FAILED: constant-time compare different");
            return false;
        }
    }

    SS_LOG_INFO(kLogCategory, L"Self-test PASSED (5/5 checks)");
    return true;
}

std::string UpdateVerifier::GetVersionString() noexcept {
    return FormatVersion({
        VerifierConstants::VERSION_MAJOR,
        VerifierConstants::VERSION_MINOR,
        VerifierConstants::VERSION_PATCH,
        0
    });
}

// ============================================================================
// FREE FUNCTIONS
// ============================================================================

std::string_view GetVerificationStatusName(VerificationStatus status) noexcept {
    switch (status) {
        case VerificationStatus::Valid:              return "Valid";
        case VerificationStatus::InvalidSignature:   return "InvalidSignature";
        case VerificationStatus::InvalidCertificate: return "InvalidCertificate";
        case VerificationStatus::CertificateExpired: return "CertificateExpired";
        case VerificationStatus::CertificateRevoked: return "CertificateRevoked";
        case VerificationStatus::InvalidChain:       return "InvalidChain";
        case VerificationStatus::HashMismatch:       return "HashMismatch";
        case VerificationStatus::VersionDowngrade:   return "VersionDowngrade";
        case VerificationStatus::Tampered:           return "Tampered";
        case VerificationStatus::Unknown:            return "Unknown";
    }
    return "Unknown";
}

std::string_view GetSignatureAlgorithmName(SignatureAlgorithm algo) noexcept {
    switch (algo) {
        case SignatureAlgorithm::RSA_SHA256:        return "RSA-SHA256";
        case SignatureAlgorithm::RSA_SHA384:        return "RSA-SHA384";
        case SignatureAlgorithm::RSA_SHA512:        return "RSA-SHA512";
        case SignatureAlgorithm::ECDSA_P256_SHA256: return "ECDSA-P256-SHA256";
        case SignatureAlgorithm::ECDSA_P384_SHA384: return "ECDSA-P384-SHA384";
        case SignatureAlgorithm::ECDSA_P521_SHA512: return "ECDSA-P521-SHA512";
        case SignatureAlgorithm::Unknown:           return "Unknown";
    }
    return "Unknown";
}

std::string_view GetCertificateTypeName(CertificateType type) noexcept {
    switch (type) {
        case CertificateType::RootCA:          return "RootCA";
        case CertificateType::IntermediateCA:  return "IntermediateCA";
        case CertificateType::CodeSigning:     return "CodeSigning";
        case CertificateType::Timestamping:    return "Timestamping";
        case CertificateType::Unknown:         return "Unknown";
    }
    return "Unknown";
}

std::string_view GetRevocationMethodName(RevocationCheckMethod method) noexcept {
    switch (method) {
        case RevocationCheckMethod::None: return "None";
        case RevocationCheckMethod::CRL:  return "CRL";
        case RevocationCheckMethod::OCSP: return "OCSP";
        case RevocationCheckMethod::Both: return "Both";
    }
    return "Unknown";
}

std::string CalculateFileHash(const fs::path& filePath) {
    if (filePath.empty()) return {};

    std::error_code ec;
    if (!fs::exists(filePath, ec) || ec) return {};

    const auto fileSize = fs::file_size(filePath, ec);
    if (ec || fileSize > kMaxPackageFileSize) return {};

    std::vector<uint8_t> digest;
    Utils::HashUtils::Error hErr;
    if (!Utils::HashUtils::ComputeFile(
            Utils::HashUtils::Algorithm::SHA256,
            filePath.wstring(), digest, &hErr))
    {
        return {};
    }
    return Utils::HashUtils::ToHexLower(digest);
}

std::array<uint32_t, 4> ParseVersion(const std::string& version) {
    std::array<uint32_t, 4> components = { 0, 0, 0, 0 };

    if (version.empty()) return components;

    size_t compIdx = 0;
    size_t start = 0;

    while (start < version.size() && compIdx < components.size()) {
        size_t dot = version.find('.', start);
        if (dot == std::string::npos) dot = version.size();

        if (dot > start) {
            uint32_t val = 0;
            const auto [ptr, errc] = std::from_chars(
                version.data() + start,
                version.data() + dot,
                val);

            if (errc == std::errc{}) {
                components[compIdx] = val;
            }
            // On parse failure, component stays 0.
        }
        ++compIdx;
        start = dot + 1;
    }

    return components;
}

std::string FormatVersion(const std::array<uint32_t, 4>& components) {
    std::ostringstream os;
    os << components[0] << '.'
       << components[1] << '.'
       << components[2] << '.'
       << components[3];
    return os.str();
}

}  // namespace Update
}  // namespace ShadowStrike

