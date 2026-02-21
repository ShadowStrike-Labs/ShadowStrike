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
 * ShadowStrike NGAV - UPDATE VERIFIER MODULE
 * ============================================================================
 *
 * @file UpdateVerifier.hpp
 * @brief Enterprise-grade cryptographic verification of update packages with
 *        code signing, certificate chain validation, and anti-downgrade.
 *
 * Provides comprehensive update verification ensuring only authentic,
 * properly signed updates from ShadowStrike are installed.
 *
 * VERIFICATION CAPABILITIES:
 * ==========================
 *
 * 1. SIGNATURE VERIFICATION
 *    - RSA-4096 signatures
 *    - ECDSA P-384 signatures
 *    - SHA-256/SHA-384 hashes
 *    - Authenticode verification
 *    - Catalog verification
 *
 * 2. CERTIFICATE CHAIN
 *    - Root CA validation
 *    - Intermediate verification
 *    - CRL checking
 *    - OCSP validation
 *    - Certificate pinning
 *
 * 3. ANTI-DOWNGRADE
 *    - Version sequence validation
 *    - Rollback attack prevention
 *    - Timestamp verification
 *    - Minimum version enforcement
 *
 * 4. INTEGRITY CHECKING
 *    - File hash verification
 *    - Package checksum
 *    - Manifest validation
 *    - Size verification
 *
 * 5. SECURITY FEATURES
 *    - Tamper detection
 *    - Replay attack prevention
 *    - Man-in-the-middle protection
 *    - Secure timestamp
 *
 * @note Thread-safe singleton design.
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
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <span>

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
#  include <wincrypt.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Update {
    class UpdateVerifierImpl;
}

namespace ShadowStrike {
namespace Update {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace VerifierConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief RSA key size
    inline constexpr uint32_t RSA_KEY_SIZE = 4096;
    
    /// @brief ECDSA curve
    inline constexpr const char* ECDSA_CURVE = "P-384";
    
    /// @brief Hash algorithm
    inline constexpr const char* HASH_ALGORITHM = "SHA-256";
    
    /// @brief Root CA subject name
    inline constexpr const char* ROOT_CA_SUBJECT = "CN=ShadowStrike Root CA";
    
    /// @brief Certificate validity window (days)
    inline constexpr uint32_t CERT_VALIDITY_WINDOW_DAYS = 30;

}  // namespace VerifierConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
namespace fs = std::filesystem;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Verification result status
 */
enum class VerificationStatus : uint8_t {
    Valid               = 0,
    InvalidSignature    = 1,
    InvalidCertificate  = 2,
    CertificateExpired  = 3,
    CertificateRevoked  = 4,
    InvalidChain        = 5,
    HashMismatch        = 6,
    VersionDowngrade    = 7,
    Tampered            = 8,
    Unknown             = 9
};

/**
 * @brief Signature algorithm
 */
enum class SignatureAlgorithm : uint8_t {
    RSA_SHA256          = 0,
    RSA_SHA384          = 1,
    RSA_SHA512          = 2,
    ECDSA_P256_SHA256   = 3,
    ECDSA_P384_SHA384   = 4,
    ECDSA_P521_SHA512   = 5,
    Unknown             = 6
};

/**
 * @brief Certificate type
 */
enum class CertificateType : uint8_t {
    RootCA              = 0,
    IntermediateCA      = 1,
    CodeSigning         = 2,
    Timestamping        = 3,
    Unknown             = 4
};

/**
 * @brief Revocation check method
 */
enum class RevocationCheckMethod : uint8_t {
    None                = 0,
    CRL                 = 1,
    OCSP                = 2,
    Both                = 3
};

/**
 * @brief Module status
 */
enum class VerifierStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Verifying       = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Certificate info
 */
struct CertificateInfo {
    /// @brief Subject name
    std::string subjectName;
    
    /// @brief Issuer name
    std::string issuerName;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief Thumbprint (SHA-1)
    std::string thumbprint;
    
    /// @brief Certificate type
    CertificateType type = CertificateType::Unknown;
    
    /// @brief Valid from
    SystemTimePoint validFrom;
    
    /// @brief Valid to
    SystemTimePoint validTo;
    
    /// @brief Key algorithm
    std::string keyAlgorithm;
    
    /// @brief Key size (bits)
    uint32_t keySize = 0;
    
    /// @brief Is valid
    bool isValid = false;
    
    /// @brief Is trusted
    bool isTrusted = false;
    
    /// @brief Is revoked
    bool isRevoked = false;
    
    [[nodiscard]] bool IsExpired() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Signature info
 */
struct SignatureInfo {
    /// @brief Algorithm
    SignatureAlgorithm algorithm = SignatureAlgorithm::Unknown;
    
    /// @brief Signature data
    std::vector<uint8_t> signatureData;
    
    /// @brief Signer certificate
    CertificateInfo signerCertificate;
    
    /// @brief Timestamp
    std::optional<SystemTimePoint> timestamp;
    
    /// @brief Timestamp certificate
    std::optional<CertificateInfo> timestampCertificate;
    
    /// @brief Chain certificates
    std::vector<CertificateInfo> certificateChain;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Verification result
 */
struct VerificationResult {
    /// @brief Status
    VerificationStatus status = VerificationStatus::Unknown;
    
    /// @brief Is valid
    bool isValid = false;
    
    /// @brief File path
    fs::path filePath;
    
    /// @brief Expected hash
    std::string expectedHash;
    
    /// @brief Actual hash
    std::string actualHash;
    
    /// @brief Signature info
    std::optional<SignatureInfo> signatureInfo;
    
    /// @brief Version validated
    bool versionValidated = false;
    
    /// @brief Version string
    std::string versionString;
    
    /// @brief Timestamp validated
    bool timestampValidated = false;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Warnings
    std::vector<std::string> warnings;
    
    /// @brief Verification time
    SystemTimePoint verificationTime;
    
    /// @brief Duration (milliseconds)
    uint32_t durationMs = 0;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Package manifest
 */
struct PackageManifest {
    /// @brief Package ID
    std::string packageId;
    
    /// @brief Version
    std::string version;
    
    /// @brief Files (path -> hash)
    std::map<std::string, std::string> files;
    
    /// @brief Total size
    uint64_t totalSize = 0;
    
    /// @brief Created time
    SystemTimePoint createdTime;
    
    /// @brief Minimum required version
    std::string minimumVersion;
    
    /// @brief Manifest signature
    std::vector<uint8_t> signature;
    
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Pinned certificate
 */
struct PinnedCertificate {
    /// @brief Subject name
    std::string subjectName;
    
    /// @brief Thumbprint (SHA-256)
    std::string thumbprint;
    
    /// @brief Public key hash
    std::string publicKeyHash;
    
    /// @brief Expiry date
    std::optional<SystemTimePoint> expiryDate;
    
    /// @brief Is backup
    bool isBackup = false;
    
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Statistics
 */
struct VerifierStatistics {
    std::atomic<uint64_t> verificationsPerformed{0};
    std::atomic<uint64_t> verificationsSucceeded{0};
    std::atomic<uint64_t> verificationsFailed{0};
    std::atomic<uint64_t> signatureVerifications{0};
    std::atomic<uint64_t> hashVerifications{0};
    std::atomic<uint64_t> chainValidations{0};
    std::atomic<uint64_t> revocationChecks{0};
    std::atomic<uint64_t> downgradeAttempts{0};
    std::array<std::atomic<uint64_t>, 16> byStatus{};
    TimePoint startTime = Clock::now();
    
    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration
 */
struct UpdateVerifierConfiguration {
    /// @brief Enable verification
    bool enabled = true;
    
    /// @brief Require valid signature
    bool requireValidSignature = true;
    
    /// @brief Require valid certificate chain
    bool requireValidChain = true;
    
    /// @brief Require timestamp
    bool requireTimestamp = false;
    
    /// @brief Enable revocation checking
    bool enableRevocationCheck = true;
    
    /// @brief Revocation check method
    RevocationCheckMethod revocationMethod = RevocationCheckMethod::OCSP;
    
    /// @brief Enable certificate pinning
    bool enableCertificatePinning = true;
    
    /// @brief Enable anti-downgrade
    bool enableAntiDowngrade = true;
    
    /// @brief Pinned certificates
    std::vector<PinnedCertificate> pinnedCertificates;
    
    /// @brief Allowed signers
    std::set<std::string> allowedSigners;
    
    /// @brief Minimum version
    std::string minimumVersion;
    
    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using VerificationCallback = std::function<void(const VerificationResult&)>;
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// UPDATE VERIFIER CLASS
// ============================================================================

/**
 * @class UpdateVerifier
 * @brief Enterprise update verification
 */
class UpdateVerifier final {
public:
    [[nodiscard]] static UpdateVerifier& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;
    
    UpdateVerifier(const UpdateVerifier&) = delete;
    UpdateVerifier& operator=(const UpdateVerifier&) = delete;
    UpdateVerifier(UpdateVerifier&&) = delete;
    UpdateVerifier& operator=(UpdateVerifier&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    
    [[nodiscard]] bool Initialize(const UpdateVerifierConfiguration& config = {});
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] VerifierStatus GetStatus() const noexcept;

    // ========================================================================
    // PACKAGE VERIFICATION
    // ========================================================================
    
    /// @brief Verify update package
    [[nodiscard]] bool VerifyPackage(
        const std::wstring& filePath,
        const std::vector<uint8_t>& signature);
    
    /// @brief Verify package with result
    [[nodiscard]] VerificationResult VerifyPackageFull(
        const fs::path& filePath,
        const std::vector<uint8_t>& signature);
    
    /// @brief Verify file hash
    [[nodiscard]] bool VerifyHash(
        const fs::path& filePath,
        const std::string& expectedHash);
    
    /// @brief Verify manifest
    [[nodiscard]] VerificationResult VerifyManifest(const PackageManifest& manifest);

    // ========================================================================
    // VERSION VALIDATION
    // ========================================================================
    
    /// @brief Validate version sequence (anti-downgrade)
    [[nodiscard]] bool ValidateVersionSequence(const std::string& newVersion);
    
    /// @brief Compare versions
    [[nodiscard]] int CompareVersions(
        const std::string& version1,
        const std::string& version2) const;
    
    /// @brief Set minimum version
    void SetMinimumVersion(const std::string& version);
    
    /// @brief Get minimum version
    [[nodiscard]] std::string GetMinimumVersion() const;

    // ========================================================================
    // SIGNATURE VERIFICATION
    // ========================================================================
    
    /// @brief Verify signature
    [[nodiscard]] bool VerifySignature(
        std::span<const uint8_t> data,
        std::span<const uint8_t> signature);
    
    /// @brief Verify Authenticode signature
    [[nodiscard]] bool VerifyAuthenticode(const fs::path& filePath);
    
    /// @brief Get signature info
    [[nodiscard]] std::optional<SignatureInfo> GetSignatureInfo(const fs::path& filePath);

    // ========================================================================
    // CERTIFICATE OPERATIONS
    // ========================================================================
    
    /// @brief Verify certificate chain
    [[nodiscard]] bool VerifyCertificateChain(const CertificateInfo& certificate);
    
    /// @brief Check certificate revocation
    [[nodiscard]] bool CheckRevocation(const CertificateInfo& certificate);
    
    /// @brief Get certificate info
    [[nodiscard]] std::optional<CertificateInfo> GetCertificateInfo(const fs::path& filePath);
    
    /// @brief Is certificate pinned
    [[nodiscard]] bool IsCertificatePinned(const CertificateInfo& certificate) const;

    // ========================================================================
    // PINNING MANAGEMENT
    // ========================================================================
    
    /// @brief Add pinned certificate
    [[nodiscard]] bool AddPinnedCertificate(const PinnedCertificate& cert);
    
    /// @brief Remove pinned certificate
    [[nodiscard]] bool RemovePinnedCertificate(const std::string& thumbprint);
    
    /// @brief Get pinned certificates
    [[nodiscard]] std::vector<PinnedCertificate> GetPinnedCertificates() const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    void RegisterVerificationCallback(VerificationCallback callback);
    void RegisterErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] VerifierStatistics GetStatistics() const;
    void ResetStatistics();
    
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    UpdateVerifier();
    ~UpdateVerifier();
    
    std::unique_ptr<UpdateVerifierImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVerificationStatusName(VerificationStatus status) noexcept;
[[nodiscard]] std::string_view GetSignatureAlgorithmName(SignatureAlgorithm algo) noexcept;
[[nodiscard]] std::string_view GetCertificateTypeName(CertificateType type) noexcept;
[[nodiscard]] std::string_view GetRevocationMethodName(RevocationCheckMethod method) noexcept;

/// @brief Calculate file hash (SHA-256)
[[nodiscard]] std::string CalculateFileHash(const fs::path& filePath);

/// @brief Parse version string to components
[[nodiscard]] std::array<uint32_t, 4> ParseVersion(const std::string& version);

/// @brief Format version from components
[[nodiscard]] std::string FormatVersion(const std::array<uint32_t, 4>& components);

}  // namespace Update
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

#define SS_VERIFY_PACKAGE(path, sig) \
    ::ShadowStrike::Update::UpdateVerifier::Instance().VerifyPackage(path, sig)

#define SS_VERIFY_VERSION(version) \
    ::ShadowStrike::Update::UpdateVerifier::Instance().ValidateVersionSequence(version)
