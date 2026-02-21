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
 * ShadowStrike Security - X.509 CERTIFICATE VALIDATION ENGINE
 * ============================================================================
 *
 * @file CertificateValidator.hpp
 * @brief Enterprise-grade X.509 certificate validation and verification system
 *        for validating SSL/TLS certificates, code signing certificates,
 *        and certificate chains.
 *
 * This module provides comprehensive certificate validation capabilities for
 * the ShadowStrike security suite, including chain validation, revocation
 * checking, and trust evaluation.
 *
 * VALIDATION CAPABILITIES:
 * ========================
 *
 * 1. CERTIFICATE PARSING
 *    - X.509v3 certificate parsing
 *    - Extension extraction (SAN, EKU, KU)
 *    - Subject/Issuer DN parsing
 *    - Signature algorithm identification
 *    - Public key extraction
 *
 * 2. CHAIN VALIDATION
 *    - Full chain building
 *    - Path validation (RFC 5280)
 *    - Cross-certificate support
 *    - Name constraints validation
 *    - Policy constraints validation
 *
 * 3. REVOCATION CHECKING
 *    - CRL checking (local and online)
 *    - OCSP checking
 *    - OCSP stapling support
 *    - Delta CRL support
 *    - Revocation status caching
 *
 * 4. TRUST EVALUATION
 *    - Trusted root store management
 *    - Intermediate CA validation
 *    - Certificate pinning
 *    - Custom trust anchors
 *    - Enterprise CA support
 *
 * 5. TEMPORAL VALIDATION
 *    - Expiration checking
 *    - Not-before validation
 *    - Counter-signature timestamps
 *    - Grace period support
 *    - Clock skew tolerance
 *
 * 6. EXTENDED VALIDATION
 *    - EV certificate detection
 *    - Code signing validation
 *    - SSL/TLS server validation
 *    - Email (S/MIME) validation
 *    - Document signing validation
 *
 * SUPPORTED CERTIFICATE TYPES:
 * ============================
 * - X.509v3 Certificates
 * - PKCS#7 Certificate Chains
 * - PEM and DER encoding
 * - PKCS#12 containers
 * - Authenticode signatures
 *
 * @note Integrates with Windows CryptoAPI and CNG.
 * @note Supports offline validation for air-gapped systems.
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

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <ctime>
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
#include <bitset>

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
#  include <Wintrust.h>
#  include <Softpub.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/TimeUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class CertificateValidatorImpl;
    class DigitalSignatureValidator;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CertificateConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum certificate size
    inline constexpr size_t MAX_CERTIFICATE_SIZE = 64 * 1024;
    
    /// @brief Maximum chain length
    inline constexpr size_t MAX_CHAIN_LENGTH = 20;
    
    /// @brief Maximum CRL size
    inline constexpr size_t MAX_CRL_SIZE = 10 * 1024 * 1024;
    
    /// @brief Maximum OCSP response size
    inline constexpr size_t MAX_OCSP_RESPONSE_SIZE = 64 * 1024;
    
    /// @brief Maximum cached certificates
    inline constexpr size_t MAX_CACHED_CERTIFICATES = 10000;
    
    /// @brief Maximum cached CRLs
    inline constexpr size_t MAX_CACHED_CRLS = 1000;
    
    /// @brief Maximum cached OCSP responses
    inline constexpr size_t MAX_CACHED_OCSP_RESPONSES = 10000;
    
    /// @brief Maximum pinned certificates
    inline constexpr size_t MAX_PINNED_CERTIFICATES = 100;
    
    /// @brief Maximum custom roots
    inline constexpr size_t MAX_CUSTOM_ROOTS = 50;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief OCSP request timeout (milliseconds)
    inline constexpr uint32_t OCSP_TIMEOUT_MS = 10000;
    
    /// @brief CRL download timeout (milliseconds)
    inline constexpr uint32_t CRL_TIMEOUT_MS = 30000;
    
    /// @brief Clock skew tolerance (seconds)
    inline constexpr uint32_t CLOCK_SKEW_TOLERANCE_SECS = 300;
    
    /// @brief Expiration grace period (seconds)
    inline constexpr uint32_t EXPIRATION_GRACE_PERIOD_SECS = 0;

    // ========================================================================
    // CACHE DURATIONS
    // ========================================================================
    
    /// @brief OCSP response cache duration (seconds)
    inline constexpr uint32_t OCSP_CACHE_DURATION_SECS = 3600;
    
    /// @brief CRL cache duration (seconds)
    inline constexpr uint32_t CRL_CACHE_DURATION_SECS = 86400;
    
    /// @brief Validation result cache duration (seconds)
    inline constexpr uint32_t VALIDATION_CACHE_DURATION_SECS = 300;

    // ========================================================================
    // HASH SIZE
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;
    inline constexpr size_t SHA1_SIZE = 20;

    // ========================================================================
    // KNOWN OIDS
    // ========================================================================
    
    inline constexpr std::string_view OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    inline constexpr std::string_view OID_SHA256_RSA = "1.2.840.113549.1.1.11";
    inline constexpr std::string_view OID_SHA384_RSA = "1.2.840.113549.1.1.12";
    inline constexpr std::string_view OID_SHA512_RSA = "1.2.840.113549.1.1.13";
    inline constexpr std::string_view OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    inline constexpr std::string_view OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3";
    inline constexpr std::string_view OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
    inline constexpr std::string_view OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    inline constexpr std::string_view OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    inline constexpr std::string_view OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    inline constexpr std::string_view OID_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
    inline constexpr std::string_view OID_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

}  // namespace CertificateConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using CertificateFingerprint = std::array<uint8_t, 32>;
using CertificateThumbprint = std::array<uint8_t, 20>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Certificate validation result
 */
enum class ValidationResult : uint8_t {
    Valid               = 0,    ///< Certificate is valid
    Invalid             = 1,    ///< Certificate is invalid
    Expired             = 2,    ///< Certificate has expired
    NotYetValid         = 3,    ///< Certificate not yet valid
    Revoked             = 4,    ///< Certificate has been revoked
    UntrustedRoot       = 5,    ///< Root CA not trusted
    ChainBuildingFailed = 6,    ///< Could not build chain
    SignatureInvalid    = 7,    ///< Signature verification failed
    NameMismatch        = 8,    ///< Subject name mismatch
    PolicyViolation     = 9,    ///< Policy constraint violation
    UnknownCriticalExt  = 10,   ///< Unknown critical extension
    RevocationUnknown   = 11,   ///< Revocation status unknown
    WeakAlgorithm       = 12,   ///< Uses deprecated/weak algorithm
    KeyUsageInvalid     = 13,   ///< Key usage violation
    PathLengthExceeded  = 14,   ///< Path length constraint exceeded
    Error               = 255   ///< General error
};

/**
 * @brief Certificate type
 */
enum class CertificateType : uint8_t {
    Unknown             = 0,
    RootCA              = 1,
    IntermediateCA      = 2,
    EndEntity           = 3,
    SelfSigned          = 4,
    CodeSigning         = 5,
    ServerAuth          = 6,
    ClientAuth          = 7,
    EmailSigning        = 8,
    Timestamping        = 9
};

/**
 * @brief Certificate encoding
 */
enum class CertificateEncoding : uint8_t {
    Unknown     = 0,
    DER         = 1,    ///< Distinguished Encoding Rules
    PEM         = 2,    ///< Privacy Enhanced Mail (Base64)
    PKCS7       = 3,    ///< PKCS#7 container
    PKCS12      = 4     ///< PKCS#12 container
};

/**
 * @brief Key type
 */
enum class KeyType : uint8_t {
    Unknown     = 0,
    RSA         = 1,
    DSA         = 2,
    ECDSA       = 3,
    ECDH        = 4,
    EdDSA       = 5
};

/**
 * @brief Signature algorithm
 */
enum class SignatureAlgorithm : uint8_t {
    Unknown         = 0,
    MD5_RSA         = 1,    ///< Deprecated
    SHA1_RSA        = 2,    ///< Deprecated
    SHA256_RSA      = 3,
    SHA384_RSA      = 4,
    SHA512_RSA      = 5,
    SHA256_ECDSA    = 6,
    SHA384_ECDSA    = 7,
    SHA512_ECDSA    = 8,
    RSA_PSS         = 9,
    Ed25519         = 10,
    Ed448           = 11
};

/**
 * @brief Key usage flags
 */
enum class KeyUsage : uint32_t {
    None                = 0x00000000,
    DigitalSignature    = 0x00000001,
    NonRepudiation      = 0x00000002,
    KeyEncipherment     = 0x00000004,
    DataEncipherment    = 0x00000008,
    KeyAgreement        = 0x00000010,
    KeyCertSign         = 0x00000020,
    CRLSign             = 0x00000040,
    EncipherOnly        = 0x00000080,
    DecipherOnly        = 0x00000100,
    
    AllUsage            = 0x000001FF
};

inline constexpr KeyUsage operator|(KeyUsage a, KeyUsage b) noexcept {
    return static_cast<KeyUsage>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr KeyUsage operator&(KeyUsage a, KeyUsage b) noexcept {
    return static_cast<KeyUsage>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Extended key usage
 */
enum class ExtendedKeyUsage : uint32_t {
    None                = 0x00000000,
    ServerAuth          = 0x00000001,
    ClientAuth          = 0x00000002,
    CodeSigning         = 0x00000004,
    EmailProtection     = 0x00000008,
    Timestamping        = 0x00000010,
    OCSPSigning         = 0x00000020,
    SmartCardLogon      = 0x00000040,
    DocumentSigning     = 0x00000080,
    IPSecEndSystem      = 0x00000100,
    IPSecTunnel         = 0x00000200,
    IPSecUser           = 0x00000400,
    KernelModeSigning   = 0x00000800,
    
    AnyPurpose          = 0xFFFFFFFF
};

inline constexpr ExtendedKeyUsage operator|(ExtendedKeyUsage a, ExtendedKeyUsage b) noexcept {
    return static_cast<ExtendedKeyUsage>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Revocation status
 */
enum class RevocationStatus : uint8_t {
    Unknown         = 0,    ///< Revocation status unknown
    Good            = 1,    ///< Certificate is not revoked
    Revoked         = 2,    ///< Certificate has been revoked
    Suspended       = 3,    ///< Certificate is suspended
    CRLNotAvailable = 4,    ///< CRL not available
    OCSPNotAvailable= 5,    ///< OCSP responder not available
    CheckFailed     = 6     ///< Check failed (network error)
};

/**
 * @brief Revocation reason
 */
enum class RevocationReason : uint8_t {
    Unspecified         = 0,
    KeyCompromise       = 1,
    CACompromise        = 2,
    AffiliationChanged  = 3,
    Superseded          = 4,
    CessationOfOperation= 5,
    CertificateHold     = 6,
    RemoveFromCRL       = 8,
    PrivilegeWithdrawn  = 9,
    AACompromise        = 10
};

/**
 * @brief Validation flags
 */
enum class ValidationFlags : uint32_t {
    None                    = 0x00000000,
    IgnoreRevocation        = 0x00000001,
    IgnoreNotYetValid       = 0x00000002,
    IgnoreExpired           = 0x00000004,
    IgnoreUntrustedRoot     = 0x00000008,
    IgnoreNameConstraints   = 0x00000010,
    IgnoreWeakAlgorithm     = 0x00000020,
    RequireEV               = 0x00000040,
    RequireCodeSigning      = 0x00000080,
    RequireServerAuth       = 0x00000100,
    CacheResult             = 0x00000200,
    OnlineCheck             = 0x00000400,
    OfflineOnly             = 0x00000800,
    
    Strict                  = CacheResult | OnlineCheck,
    Lenient                 = IgnoreRevocation | IgnoreNotYetValid | CacheResult
};

inline constexpr ValidationFlags operator|(ValidationFlags a, ValidationFlags b) noexcept {
    return static_cast<ValidationFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ValidationFlags operator&(ValidationFlags a, ValidationFlags b) noexcept {
    return static_cast<ValidationFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief Trust level
 */
enum class TrustLevel : uint8_t {
    Untrusted       = 0,
    Unknown         = 1,
    SelfSigned      = 2,
    CustomRoot      = 3,
    SystemRoot      = 4,
    EnterpriseRoot  = 5,
    EVValidated     = 6
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Distinguished Name (DN) structure
 */
struct DistinguishedName {
    std::string commonName;         ///< CN
    std::string organization;       ///< O
    std::string organizationalUnit; ///< OU
    std::string country;            ///< C
    std::string state;              ///< ST
    std::string locality;           ///< L
    std::string email;              ///< E
    std::string serialNumber;       ///< SERIALNUMBER
    std::string domainComponent;    ///< DC
    std::string raw;                ///< Raw DN string
    
    /**
     * @brief Format as string
     */
    [[nodiscard]] std::string ToString() const;
    
    /**
     * @brief Compare for equality
     */
    [[nodiscard]] bool operator==(const DistinguishedName& other) const;
};

/**
 * @brief Subject Alternative Name (SAN)
 */
struct SubjectAltName {
    std::vector<std::string> dnsNames;
    std::vector<std::string> ipAddresses;
    std::vector<std::string> emails;
    std::vector<std::string> uris;
    std::vector<std::string> directoryNames;
};

/**
 * @brief Public key information
 */
struct PublicKeyInfo {
    KeyType type = KeyType::Unknown;
    uint32_t keySizeBits = 0;
    std::string algorithmOID;
    std::vector<uint8_t> publicKeyData;
    
    /// @brief For ECC: curve name (P-256, P-384, etc.)
    std::string curveName;
    
    /// @brief For RSA: exponent
    std::vector<uint8_t> exponent;
};

/**
 * @brief Certificate validity period
 */
struct ValidityPeriod {
    SystemTimePoint notBefore;
    SystemTimePoint notAfter;
    
    /**
     * @brief Check if currently valid
     */
    [[nodiscard]] bool IsValid() const;
    
    /**
     * @brief Check if expired
     */
    [[nodiscard]] bool IsExpired() const;
    
    /**
     * @brief Check if not yet valid
     */
    [[nodiscard]] bool IsNotYetValid() const;
    
    /**
     * @brief Get remaining validity (seconds)
     */
    [[nodiscard]] int64_t GetRemainingSeconds() const;
};

/**
 * @brief Certificate extension
 */
struct CertificateExtension {
    std::string oid;
    std::string name;
    bool critical = false;
    std::vector<uint8_t> value;
};

/**
 * @brief Parsed certificate information
 */
struct CertificateInfo {
    /// @brief Certificate version (1, 2, or 3)
    uint32_t version = 3;
    
    /// @brief Serial number
    std::string serialNumber;
    
    /// @brief Subject DN
    DistinguishedName subject;
    
    /// @brief Issuer DN
    DistinguishedName issuer;
    
    /// @brief Validity period
    ValidityPeriod validity;
    
    /// @brief Subject Alternative Names
    SubjectAltName subjectAltName;
    
    /// @brief Public key info
    PublicKeyInfo publicKey;
    
    /// @brief Signature algorithm
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm::Unknown;
    
    /// @brief Signature algorithm OID
    std::string signatureAlgorithmOID;
    
    /// @brief Key usage
    KeyUsage keyUsage = KeyUsage::None;
    
    /// @brief Extended key usage
    ExtendedKeyUsage extKeyUsage = ExtendedKeyUsage::None;
    
    /// @brief Basic constraints: is CA
    bool isCA = false;
    
    /// @brief Basic constraints: path length
    std::optional<int32_t> pathLengthConstraint;
    
    /// @brief SHA-256 fingerprint
    CertificateFingerprint sha256Fingerprint{};
    
    /// @brief SHA-1 thumbprint (for compatibility)
    CertificateThumbprint sha1Thumbprint{};
    
    /// @brief Certificate type
    CertificateType type = CertificateType::Unknown;
    
    /// @brief Is self-signed
    bool isSelfSigned = false;
    
    /// @brief Authority Key Identifier
    std::vector<uint8_t> authorityKeyId;
    
    /// @brief Subject Key Identifier
    std::vector<uint8_t> subjectKeyId;
    
    /// @brief CRL Distribution Points
    std::vector<std::string> crlDistributionPoints;
    
    /// @brief OCSP Responder URLs
    std::vector<std::string> ocspUrls;
    
    /// @brief CA Issuers URLs
    std::vector<std::string> caIssuersUrls;
    
    /// @brief All extensions
    std::vector<CertificateExtension> extensions;
    
    /// @brief Raw certificate data (DER)
    std::vector<uint8_t> rawData;
    
    /**
     * @brief Format as string
     */
    [[nodiscard]] std::string ToString() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Validation options
 */
struct ValidationOptions {
    /// @brief Validation flags
    ValidationFlags flags = ValidationFlags::Strict;
    
    /// @brief Expected hostname (for SSL validation)
    std::string expectedHostname;
    
    /// @brief Expected email (for S/MIME validation)
    std::string expectedEmail;
    
    /// @brief Required EKU
    ExtendedKeyUsage requiredEKU = ExtendedKeyUsage::None;
    
    /// @brief Validation time (empty = current time)
    std::optional<SystemTimePoint> validationTime;
    
    /// @brief Custom trust anchors
    std::vector<CertificateFingerprint> trustAnchors;
    
    /// @brief Pinned certificate fingerprints
    std::vector<CertificateFingerprint> pinnedCertificates;
    
    /// @brief OCSP timeout (milliseconds)
    uint32_t ocspTimeoutMs = CertificateConstants::OCSP_TIMEOUT_MS;
    
    /// @brief CRL timeout (milliseconds)
    uint32_t crlTimeoutMs = CertificateConstants::CRL_TIMEOUT_MS;
    
    /// @brief Clock skew tolerance (seconds)
    uint32_t clockSkewToleranceSecs = CertificateConstants::CLOCK_SKEW_TOLERANCE_SECS;
};

/**
 * @brief Validation details
 */
struct ValidationDetails {
    /// @brief Overall result
    ValidationResult result = ValidationResult::Invalid;
    
    /// @brief Error message
    std::string errorMessage;
    
    /// @brief Error code
    int32_t errorCode = 0;
    
    /// @brief Chain information
    std::vector<CertificateInfo> chain;
    
    /// @brief Trust level
    TrustLevel trustLevel = TrustLevel::Untrusted;
    
    /// @brief Revocation status
    RevocationStatus revocationStatus = RevocationStatus::Unknown;
    
    /// @brief Revocation reason (if revoked)
    std::optional<RevocationReason> revocationReason;
    
    /// @brief Revocation time (if revoked)
    std::optional<SystemTimePoint> revocationTime;
    
    /// @brief Is EV certificate
    bool isExtendedValidation = false;
    
    /// @brief Policy OIDs
    std::vector<std::string> policyOIDs;
    
    /// @brief Warnings (non-fatal issues)
    std::vector<std::string> warnings;
    
    /// @brief Validation timestamp
    TimePoint validationTime = Clock::now();
    
    /**
     * @brief Check if valid
     */
    [[nodiscard]] bool IsValid() const noexcept { 
        return result == ValidationResult::Valid; 
    }
    
    /**
     * @brief Get summary
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Certificate validator configuration
 */
struct CertificateValidatorConfiguration {
    /// @brief Enable OCSP checking
    bool enableOCSP = true;
    
    /// @brief Enable CRL checking
    bool enableCRL = true;
    
    /// @brief Prefer OCSP over CRL
    bool preferOCSP = true;
    
    /// @brief Enable result caching
    bool enableCaching = true;
    
    /// @brief OCSP cache duration (seconds)
    uint32_t ocspCacheDurationSecs = CertificateConstants::OCSP_CACHE_DURATION_SECS;
    
    /// @brief CRL cache duration (seconds)
    uint32_t crlCacheDurationSecs = CertificateConstants::CRL_CACHE_DURATION_SECS;
    
    /// @brief Default validation flags
    ValidationFlags defaultFlags = ValidationFlags::Strict;
    
    /// @brief Allow weak algorithms
    bool allowWeakAlgorithms = false;
    
    /// @brief Minimum RSA key size (bits)
    uint32_t minRSAKeySize = 2048;
    
    /// @brief Minimum ECC key size (bits)
    uint32_t minECCKeySize = 256;
    
    /// @brief Use system trust store
    bool useSystemTrustStore = true;
    
    /// @brief Additional trusted roots (DER format)
    std::vector<std::vector<uint8_t>> additionalRoots;
    
    /// @brief Blocked certificates (fingerprints)
    std::vector<CertificateFingerprint> blockedCertificates;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Certificate validation statistics
 */
struct CertificateValidatorStatistics {
    /// @brief Total validations
    std::atomic<uint64_t> totalValidations{0};
    
    /// @brief Valid certificates
    std::atomic<uint64_t> validCertificates{0};
    
    /// @brief Invalid certificates
    std::atomic<uint64_t> invalidCertificates{0};
    
    /// @brief Expired certificates
    std::atomic<uint64_t> expiredCertificates{0};
    
    /// @brief Revoked certificates
    std::atomic<uint64_t> revokedCertificates{0};
    
    /// @brief OCSP checks performed
    std::atomic<uint64_t> ocspChecks{0};
    
    /// @brief OCSP cache hits
    std::atomic<uint64_t> ocspCacheHits{0};
    
    /// @brief CRL checks performed
    std::atomic<uint64_t> crlChecks{0};
    
    /// @brief CRL cache hits
    std::atomic<uint64_t> crlCacheHits{0};
    
    /// @brief Validation cache hits
    std::atomic<uint64_t> validationCacheHits{0};
    
    /// @brief Chain building failures
    std::atomic<uint64_t> chainBuildFailures{0};
    
    /// @brief Average validation time (microseconds)
    std::atomic<uint64_t> avgValidationTimeUs{0};
    
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

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief Validation completion callback
using ValidationCallback = std::function<void(const ValidationDetails&)>;

/// @brief Certificate fetch callback (for chain building)
using CertificateFetchCallback = std::function<std::optional<std::vector<uint8_t>>(
    const DistinguishedName& issuer)>;

/// @brief Revocation check callback
using RevocationCallback = std::function<void(const CertificateInfo&, RevocationStatus)>;

// ============================================================================
// CERTIFICATE VALIDATOR ENGINE CLASS
// ============================================================================

/**
 * @class CertificateValidator
 * @brief Enterprise-grade X.509 certificate validation engine
 *
 * Provides comprehensive certificate validation including chain building,
 * revocation checking (CRL/OCSP), and trust evaluation.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& validator = CertificateValidator::Instance();
 *     
 *     // Initialize
 *     CertificateValidatorConfiguration config;
 *     config.enableOCSP = true;
 *     config.enableCRL = true;
 *     validator.Initialize(config);
 *     
 *     // Verify certificate
 *     auto details = validator.VerifyCertificate(certData);
 *     if (details.IsValid()) {
 *         // Certificate is valid
 *     }
 *     
 *     // Check revocation
 *     auto revoked = validator.IsRevoked(L"1234567890ABCDEF");
 * @endcode
 */
class CertificateValidator final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static CertificateValidator& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    CertificateValidator(const CertificateValidator&) = delete;
    CertificateValidator& operator=(const CertificateValidator&) = delete;
    CertificateValidator(CertificateValidator&&) = delete;
    CertificateValidator& operator=(CertificateValidator&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize certificate validator
     */
    [[nodiscard]] bool Initialize(const CertificateValidatorConfiguration& config = {});
    
    /**
     * @brief Shutdown certificate validator
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
    
    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    
    /**
     * @brief Update configuration
     */
    [[nodiscard]] bool SetConfiguration(const CertificateValidatorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] CertificateValidatorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // CERTIFICATE PARSING
    // ========================================================================
    
    /**
     * @brief Parse certificate from raw data
     */
    [[nodiscard]] std::optional<CertificateInfo> ParseCertificate(
        std::span<const uint8_t> certData);
    
    /**
     * @brief Parse certificate from PEM string
     */
    [[nodiscard]] std::optional<CertificateInfo> ParsePEM(std::string_view pemData);
    
    /**
     * @brief Parse certificate chain
     */
    [[nodiscard]] std::vector<CertificateInfo> ParseCertificateChain(
        std::span<const uint8_t> chainData);
    
    /**
     * @brief Detect certificate encoding
     */
    [[nodiscard]] CertificateEncoding DetectEncoding(std::span<const uint8_t> data);
    
    // ========================================================================
    // PRIMARY VALIDATION METHODS
    // ========================================================================
    
    /**
     * @brief Verify a raw certificate buffer
     */
    [[nodiscard]] bool VerifyCertificate(const std::vector<uint8_t>& certData);
    
    /**
     * @brief Verify certificate with options
     */
    [[nodiscard]] ValidationDetails VerifyCertificate(
        std::span<const uint8_t> certData,
        const ValidationOptions& options = {});
    
    /**
     * @brief Verify certificate info
     */
    [[nodiscard]] ValidationDetails VerifyCertificate(
        const CertificateInfo& certInfo,
        const ValidationOptions& options = {});
    
    /**
     * @brief Verify certificate chain
     */
    [[nodiscard]] ValidationDetails VerifyChain(
        const std::vector<CertificateInfo>& chain,
        const ValidationOptions& options = {});
    
    /**
     * @brief Verify certificate file
     */
    [[nodiscard]] ValidationDetails VerifyFile(const std::wstring& filePath,
                                               const ValidationOptions& options = {});
    
    /**
     * @brief Asynchronous certificate verification
     */
    void VerifyCertificateAsync(std::span<const uint8_t> certData,
                                ValidationCallback callback,
                                const ValidationOptions& options = {});
    
    // ========================================================================
    // REVOCATION CHECKING
    // ========================================================================
    
    /**
     * @brief Perform an online revocation check
     */
    [[nodiscard]] bool IsRevoked(const std::wstring& serialNumber);
    
    /**
     * @brief Check revocation status
     */
    [[nodiscard]] RevocationStatus CheckRevocation(const CertificateInfo& cert);
    
    /**
     * @brief Check revocation via OCSP
     */
    [[nodiscard]] RevocationStatus CheckOCSP(const CertificateInfo& cert,
                                             const CertificateInfo& issuer);
    
    /**
     * @brief Check revocation via CRL
     */
    [[nodiscard]] RevocationStatus CheckCRL(const CertificateInfo& cert,
                                            const CertificateInfo& issuer);
    
    /**
     * @brief Get detailed revocation info
     */
    [[nodiscard]] std::optional<std::tuple<RevocationStatus, RevocationReason, SystemTimePoint>>
        GetRevocationDetails(const CertificateInfo& cert);
    
    // ========================================================================
    // CHAIN BUILDING
    // ========================================================================
    
    /**
     * @brief Build certificate chain
     */
    [[nodiscard]] std::optional<std::vector<CertificateInfo>> BuildChain(
        const CertificateInfo& endEntityCert);
    
    /**
     * @brief Build chain with options
     */
    [[nodiscard]] std::optional<std::vector<CertificateInfo>> BuildChain(
        const CertificateInfo& endEntityCert,
        const ValidationOptions& options);
    
    /**
     * @brief Set certificate fetch callback
     */
    void SetCertificateFetchCallback(CertificateFetchCallback callback);
    
    // ========================================================================
    // TRUST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add trusted root certificate
     */
    [[nodiscard]] bool AddTrustedRoot(std::span<const uint8_t> certData);
    
    /**
     * @brief Remove trusted root
     */
    [[nodiscard]] bool RemoveTrustedRoot(const CertificateFingerprint& fingerprint);
    
    /**
     * @brief Check if certificate is trusted root
     */
    [[nodiscard]] bool IsTrustedRoot(const CertificateInfo& cert) const;
    
    /**
     * @brief Get trust level for certificate
     */
    [[nodiscard]] TrustLevel GetTrustLevel(const CertificateInfo& cert) const;
    
    /**
     * @brief Get all trusted roots
     */
    [[nodiscard]] std::vector<CertificateInfo> GetTrustedRoots() const;
    
    /**
     * @brief Reload system trust store
     */
    [[nodiscard]] bool ReloadSystemTrustStore();
    
    // ========================================================================
    // CERTIFICATE PINNING
    // ========================================================================
    
    /**
     * @brief Pin certificate
     */
    [[nodiscard]] bool PinCertificate(std::string_view hostname,
                                      const CertificateFingerprint& fingerprint);
    
    /**
     * @brief Pin certificate
     */
    [[nodiscard]] bool PinCertificate(std::string_view hostname,
                                      std::span<const uint8_t> certData);
    
    /**
     * @brief Unpin certificate
     */
    [[nodiscard]] bool UnpinCertificate(std::string_view hostname);
    
    /**
     * @brief Check if certificate is pinned
     */
    [[nodiscard]] bool IsPinned(std::string_view hostname) const;
    
    /**
     * @brief Verify pinned certificate
     */
    [[nodiscard]] bool VerifyPinnedCertificate(std::string_view hostname,
                                               const CertificateInfo& cert) const;
    
    /**
     * @brief Get all pinned certificates
     */
    [[nodiscard]] std::unordered_map<std::string, CertificateFingerprint> 
        GetPinnedCertificates() const;
    
    // ========================================================================
    // BLOCKLIST MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Block certificate
     */
    [[nodiscard]] bool BlockCertificate(const CertificateFingerprint& fingerprint,
                                        std::string_view reason = "");
    
    /**
     * @brief Unblock certificate
     */
    [[nodiscard]] bool UnblockCertificate(const CertificateFingerprint& fingerprint);
    
    /**
     * @brief Check if certificate is blocked
     */
    [[nodiscard]] bool IsBlocked(const CertificateInfo& cert) const;
    
    /**
     * @brief Get all blocked certificates
     */
    [[nodiscard]] std::vector<std::pair<CertificateFingerprint, std::string>> 
        GetBlockedCertificates() const;
    
    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Clear all caches
     */
    void ClearCaches();
    
    /**
     * @brief Clear OCSP cache
     */
    void ClearOCSPCache();
    
    /**
     * @brief Clear CRL cache
     */
    void ClearCRLCache();
    
    /**
     * @brief Clear validation cache
     */
    void ClearValidationCache();
    
    /**
     * @brief Get cache statistics
     */
    [[nodiscard]] std::unordered_map<std::string, size_t> GetCacheStats() const;
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /**
     * @brief Calculate certificate fingerprint (SHA-256)
     */
    [[nodiscard]] CertificateFingerprint CalculateFingerprint(
        std::span<const uint8_t> certData) const;
    
    /**
     * @brief Calculate certificate thumbprint (SHA-1)
     */
    [[nodiscard]] CertificateThumbprint CalculateThumbprint(
        std::span<const uint8_t> certData) const;
    
    /**
     * @brief Convert fingerprint to hex string
     */
    [[nodiscard]] static std::string FingerprintToHex(const CertificateFingerprint& fp);
    
    /**
     * @brief Convert thumbprint to hex string
     */
    [[nodiscard]] static std::string ThumbprintToHex(const CertificateThumbprint& tp);
    
    /**
     * @brief Parse fingerprint from hex string
     */
    [[nodiscard]] static std::optional<CertificateFingerprint> 
        ParseFingerprint(std::string_view hexString);
    
    /**
     * @brief Check if algorithm is considered weak
     */
    [[nodiscard]] static bool IsWeakAlgorithm(SignatureAlgorithm algorithm) noexcept;
    
    /**
     * @brief Check if key size is sufficient
     */
    [[nodiscard]] bool IsKeySizeSufficient(const PublicKeyInfo& keyInfo) const;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] CertificateValidatorStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Export report
     */
    [[nodiscard]] std::string ExportReport() const;
    
    // ========================================================================
    // SELF-TEST
    // ========================================================================
    
    /**
     * @brief Run self-test
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
    
    CertificateValidator();
    ~CertificateValidator();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<CertificateValidatorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get validation result name
 */
[[nodiscard]] std::string_view GetValidationResultName(ValidationResult result) noexcept;

/**
 * @brief Get certificate type name
 */
[[nodiscard]] std::string_view GetCertificateTypeName(CertificateType type) noexcept;

/**
 * @brief Get key type name
 */
[[nodiscard]] std::string_view GetKeyTypeName(KeyType type) noexcept;

/**
 * @brief Get signature algorithm name
 */
[[nodiscard]] std::string_view GetSignatureAlgorithmName(SignatureAlgorithm algorithm) noexcept;

/**
 * @brief Get revocation status name
 */
[[nodiscard]] std::string_view GetRevocationStatusName(RevocationStatus status) noexcept;

/**
 * @brief Get revocation reason name
 */
[[nodiscard]] std::string_view GetRevocationReasonName(RevocationReason reason) noexcept;

/**
 * @brief Get trust level name
 */
[[nodiscard]] std::string_view GetTrustLevelName(TrustLevel level) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class CertificatePinGuard
 * @brief RAII wrapper for temporary certificate pinning
 */
class CertificatePinGuard final {
public:
    CertificatePinGuard(std::string_view hostname, const CertificateFingerprint& fingerprint);
    ~CertificatePinGuard();
    
    CertificatePinGuard(const CertificatePinGuard&) = delete;
    CertificatePinGuard& operator=(const CertificatePinGuard&) = delete;
    
    [[nodiscard]] bool IsPinned() const noexcept { return m_pinned; }

private:
    std::string m_hostname;
    bool m_pinned = false;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Verify certificate and get result
 */
#define SS_VERIFY_CERTIFICATE(data) \
    ::ShadowStrike::Security::CertificateValidator::Instance().VerifyCertificate(data)

/**
 * @brief Check if certificate is revoked
 */
#define SS_IS_CERT_REVOKED(serial) \
    ::ShadowStrike::Security::CertificateValidator::Instance().IsRevoked(serial)
