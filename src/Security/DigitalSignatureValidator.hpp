/**
 * ============================================================================
 * ShadowStrike Security - DIGITAL SIGNATURE VALIDATION ENGINE
 * ============================================================================
 *
 * @file DigitalSignatureValidator.hpp
 * @brief Enterprise-grade Authenticode and digital signature verification system
 *        for validating PE files, drivers, scripts, and other signed content.
 *
 * This module provides comprehensive digital signature validation for verifying
 * the authenticity and integrity of executables, DLLs, drivers, scripts, and
 * other signed artifacts in the Windows ecosystem.
 *
 * VALIDATION CAPABILITIES:
 * ========================
 *
 * 1. AUTHENTICODE VERIFICATION
 *    - PE file signature validation
 *    - Catalog-based signatures
 *    - Embedded signatures
 *    - Dual signatures (SHA-1 + SHA-256)
 *    - Timestamp validation
 *
 * 2. DRIVER SIGNATURE VALIDATION
 *    - Kernel-mode code signing
 *    - WHQL certification
 *    - EV code signing
 *    - Cross-signing validation
 *    - Microsoft signature validation
 *
 * 3. SCRIPT SIGNATURE VALIDATION
 *    - PowerShell script signatures
 *    - VBScript/JScript signatures
 *    - Macro signatures
 *    - MSIX/AppX signatures
 *    - ClickOnce signatures
 *
 * 4. CHAIN VALIDATION
 *    - Full chain building
 *    - Root CA verification
 *    - Intermediate CA caching
 *    - Cross-certificate support
 *    - Timestamp chain validation
 *
 * 5. COUNTER-SIGNATURE VALIDATION
 *    - RFC 3161 timestamps
 *    - Legacy Authenticode timestamps
 *    - Multiple timestamp support
 *    - Post-expiry validation
 *    - TSA certificate validation
 *
 * 6. INTEGRITY VERIFICATION
 *    - Hash verification (MD5, SHA-1, SHA-256)
 *    - File modification detection
 *    - Resource section validation
 *    - Debug directory validation
 *    - Version info verification
 *
 * 7. POLICY ENFORCEMENT
 *    - Trusted publisher list
 *    - Blocked signer list
 *    - EV requirement enforcement
 *    - Minimum timestamp enforcement
 *    - Algorithm restrictions
 *
 * SUPPORTED FILE TYPES:
 * =====================
 * - PE executables (.exe, .dll, .sys, .ocx)
 * - Scripts (.ps1, .vbs, .js)
 * - Catalogs (.cat)
 * - MSI packages (.msi, .msp)
 * - APPX/MSIX packages
 * - CAB archives
 *
 * @note Utilizes WinTrust API and CryptoAPI for signature validation.
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
#  include <mscat.h>
#  include <ImageHlp.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/PE_sig_verf.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/PEParser.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class DigitalSignatureValidatorImpl;
    class CertificateValidator;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace SignatureConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum file size for signature verification
    inline constexpr size_t MAX_FILE_SIZE = 2ULL * 1024 * 1024 * 1024;  // 2GB
    
    /// @brief Maximum chain length
    inline constexpr size_t MAX_CHAIN_LENGTH = 20;
    
    /// @brief Maximum signatures per file
    inline constexpr size_t MAX_SIGNATURES_PER_FILE = 10;
    
    /// @brief Maximum trusted publishers
    inline constexpr size_t MAX_TRUSTED_PUBLISHERS = 500;
    
    /// @brief Maximum blocked signers
    inline constexpr size_t MAX_BLOCKED_SIGNERS = 1000;
    
    /// @brief Maximum cached validations
    inline constexpr size_t MAX_CACHED_VALIDATIONS = 50000;
    
    /// @brief Maximum catalog cache
    inline constexpr size_t MAX_CATALOG_CACHE = 1000;

    // ========================================================================
    // TIMEOUTS
    // ========================================================================
    
    /// @brief Online verification timeout (milliseconds)
    inline constexpr uint32_t ONLINE_TIMEOUT_MS = 15000;
    
    /// @brief Revocation check timeout (milliseconds)
    inline constexpr uint32_t REVOCATION_TIMEOUT_MS = 10000;
    
    /// @brief Cache duration for validation results (seconds)
    inline constexpr uint32_t CACHE_DURATION_SECS = 3600;
    
    /// @brief Clock skew tolerance (seconds)
    inline constexpr uint32_t CLOCK_SKEW_TOLERANCE_SECS = 300;

    // ========================================================================
    // HASH SIZES
    // ========================================================================
    
    inline constexpr size_t MD5_SIZE = 16;
    inline constexpr size_t SHA1_SIZE = 20;
    inline constexpr size_t SHA256_SIZE = 32;
    inline constexpr size_t SHA384_SIZE = 48;
    inline constexpr size_t SHA512_SIZE = 64;

    // ========================================================================
    // WELL-KNOWN SIGNERS
    // ========================================================================
    
    inline constexpr std::wstring_view MICROSOFT_SIGNER = L"Microsoft Corporation";
    inline constexpr std::wstring_view MICROSOFT_WINDOWS = L"Microsoft Windows";
    inline constexpr std::wstring_view MICROSOFT_TIMESTAMPING = L"Microsoft Time-Stamp Service";

}  // namespace SignatureConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using FileHash = std::array<uint8_t, 32>;
using CertificateHash = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Signature validation result
 */
enum class SignatureResult : uint8_t {
    Valid               = 0,    ///< Signature is valid
    InvalidSignature    = 1,    ///< Signature verification failed
    InvalidHash         = 2,    ///< File hash doesn't match
    Unsigned            = 3,    ///< File is not signed
    UntrustedRoot       = 4,    ///< Root CA not trusted
    Revoked             = 5,    ///< Certificate has been revoked
    Expired             = 6,    ///< Certificate has expired
    NotYetValid         = 7,    ///< Certificate not yet valid
    BadTimestamp        = 8,    ///< Timestamp invalid or missing
    TamperedFile        = 9,    ///< File has been modified
    InvalidCertificate  = 10,   ///< Certificate is invalid
    ChainError          = 11,   ///< Certificate chain error
    PolicyViolation     = 12,   ///< Policy constraint violated
    CatalogError        = 13,   ///< Catalog signature error
    BlockedSigner       = 14,   ///< Signer is in blocklist
    WeakAlgorithm       = 15,   ///< Uses deprecated algorithm
    Error               = 255   ///< General error
};

/**
 * @brief Signature type
 */
enum class SignatureType : uint8_t {
    None                = 0,    ///< No signature
    Embedded            = 1,    ///< Embedded Authenticode
    Catalog             = 2,    ///< Catalog-based signature
    Detached            = 3,    ///< Detached signature
    PowerShell          = 4,    ///< PowerShell script signature
    VBScript            = 5,    ///< VBScript signature
    MSI                 = 6,    ///< MSI package signature
    APPX                = 7,    ///< APPX/MSIX signature
    CAB                 = 8     ///< CAB archive signature
};

/**
 * @brief Hash algorithm used
 */
enum class HashAlgorithm : uint8_t {
    Unknown     = 0,
    MD5         = 1,    ///< Deprecated
    SHA1        = 2,    ///< Deprecated but still common
    SHA256      = 3,
    SHA384      = 4,
    SHA512      = 5
};

/**
 * @brief Signer trust level
 */
enum class SignerTrustLevel : uint8_t {
    Untrusted       = 0,    ///< Unknown/untrusted signer
    Known           = 1,    ///< Known but not trusted
    Trusted         = 2,    ///< Trusted publisher
    HighlyTrusted   = 3,    ///< Microsoft/OS vendor
    EVValidated     = 4,    ///< EV code signing
    Whitelisted     = 5     ///< Explicitly whitelisted
};

/**
 * @brief Timestamp status
 */
enum class TimestampStatus : uint8_t {
    None            = 0,    ///< No timestamp
    Valid           = 1,    ///< Valid timestamp
    Expired         = 2,    ///< Timestamp expired
    Invalid         = 3,    ///< Timestamp invalid
    UntrustedTSA    = 4,    ///< TSA not trusted
    Future          = 5     ///< Timestamp in future
};

/**
 * @brief Validation flags
 */
enum class ValidationFlags : uint32_t {
    None                    = 0x00000000,
    VerifyChain             = 0x00000001,
    CheckRevocation         = 0x00000002,
    RequireTimestamp        = 0x00000004,
    RequireEV               = 0x00000008,
    AllowExpiredTimestamp   = 0x00000010,
    AllowTestSignatures     = 0x00000020,
    AllowCatalogSignatures  = 0x00000040,
    OnlineCheck             = 0x00000080,
    OfflineOnly             = 0x00000100,
    CacheResult             = 0x00000200,
    VerifyHashOnly          = 0x00000400,
    AllowWeakAlgorithms     = 0x00000800,
    RequireMicrosoft        = 0x00001000,
    VerifyResources         = 0x00002000,
    
    Strict                  = VerifyChain | CheckRevocation | RequireTimestamp | CacheResult,
    Standard                = VerifyChain | CheckRevocation | AllowCatalogSignatures | CacheResult,
    Permissive              = VerifyChain | AllowExpiredTimestamp | AllowCatalogSignatures | CacheResult
};

inline constexpr ValidationFlags operator|(ValidationFlags a, ValidationFlags b) noexcept {
    return static_cast<ValidationFlags>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

inline constexpr ValidationFlags operator&(ValidationFlags a, ValidationFlags b) noexcept {
    return static_cast<ValidationFlags>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @brief File type for signature verification
 */
enum class SignedFileType : uint8_t {
    Unknown         = 0,
    PEExecutable    = 1,    ///< .exe
    PELibrary       = 2,    ///< .dll
    PEDriver        = 3,    ///< .sys
    PowerShellScript= 4,    ///< .ps1
    VBScript        = 5,    ///< .vbs
    JScript         = 6,    ///< .js
    MSIPackage      = 7,    ///< .msi
    MSPPatch        = 8,    ///< .msp
    AppxPackage     = 9,    ///< .appx/.msix
    CatalogFile     = 10,   ///< .cat
    CABArchive      = 11    ///< .cab
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
 * @brief Signer information
 */
struct SignerInfo {
    /// @brief Signer name (CN)
    std::wstring signerName;
    
    /// @brief Issuer name
    std::wstring issuerName;
    
    /// @brief Serial number
    std::wstring serialNumber;
    
    /// @brief Certificate thumbprint (SHA-1)
    std::array<uint8_t, 20> thumbprint{};
    
    /// @brief Certificate fingerprint (SHA-256)
    CertificateHash fingerprint{};
    
    /// @brief Certificate validity start
    SystemTimePoint validFrom;
    
    /// @brief Certificate validity end
    SystemTimePoint validTo;
    
    /// @brief Trust level
    SignerTrustLevel trustLevel = SignerTrustLevel::Untrusted;
    
    /// @brief Is EV certificate
    bool isEV = false;
    
    /// @brief Email address
    std::string email;
    
    /// @brief Organization
    std::wstring organization;
    
    /// @brief Country
    std::wstring country;
    
    /**
     * @brief Check if currently valid
     */
    [[nodiscard]] bool IsValid() const;
    
    /**
     * @brief Check if trusted root
     */
    [[nodiscard]] bool IsTrustedRoot() const noexcept { 
        return trustLevel >= SignerTrustLevel::HighlyTrusted; 
    }
    
    /**
     * @brief Format as string
     */
    [[nodiscard]] std::wstring ToString() const;
};

/**
 * @brief Timestamp information
 */
struct TimestampInfo {
    /// @brief Timestamp value
    SystemTimePoint timestamp;
    
    /// @brief TSA signer name
    std::wstring tsaName;
    
    /// @brief TSA issuer
    std::wstring tsaIssuer;
    
    /// @brief Timestamp type (RFC 3161 or Authenticode)
    bool isRFC3161 = false;
    
    /// @brief Hash algorithm used
    HashAlgorithm hashAlgorithm = HashAlgorithm::Unknown;
    
    /// @brief Status
    TimestampStatus status = TimestampStatus::None;
    
    /// @brief Timestamp hash (for verification)
    std::vector<uint8_t> hash;
    
    /**
     * @brief Check if valid
     */
    [[nodiscard]] bool IsValid() const noexcept { 
        return status == TimestampStatus::Valid; 
    }
};

/**
 * @brief Full signature information
 */
struct SignatureInfo {
    /// @brief Validation result
    SignatureResult result = SignatureResult::Unsigned;
    
    /// @brief Is signature valid
    bool isValid = false;
    
    /// @brief Signer information
    SignerInfo signer;
    
    /// @brief Issuer name (for compatibility)
    std::wstring issuerName;
    
    /// @brief Serial number (for compatibility)
    std::wstring serialNumber;
    
    /// @brief Is trusted root (for compatibility)
    bool isTrustedRoot = false;
    
    /// @brief Signature type
    SignatureType type = SignatureType::None;
    
    /// @brief Hash algorithm used for file
    HashAlgorithm fileHashAlgorithm = HashAlgorithm::Unknown;
    
    /// @brief File hash
    FileHash fileHash{};
    
    /// @brief Timestamp information
    std::vector<TimestampInfo> timestamps;
    
    /// @brief Certificate chain
    std::vector<SignerInfo> chain;
    
    /// @brief Counter-signers (for dual signatures)
    std::vector<SignerInfo> counterSigners;
    
    /// @brief Catalog file path (if catalog-signed)
    std::wstring catalogPath;
    
    /// @brief Is dual-signed (SHA-1 + SHA-256)
    bool isDualSigned = false;
    
    /// @brief Is Microsoft-signed
    bool isMicrosoftSigned = false;
    
    /// @brief Is WHQL-signed (for drivers)
    bool isWHQL = false;
    
    /// @brief Is EV code signing
    bool isEV = false;
    
    /// @brief Error message (if any)
    std::string errorMessage;
    
    /// @brief Win32 error code
    int32_t errorCode = 0;
    
    /// @brief Verification timestamp
    TimePoint verificationTime = Clock::now();
    
    /**
     * @brief Get primary signer name
     */
    [[nodiscard]] std::wstring GetSignerName() const { return signer.signerName; }
    
    /**
     * @brief Check if has valid timestamp
     */
    [[nodiscard]] bool HasValidTimestamp() const;
    
    /**
     * @brief Get newest timestamp
     */
    [[nodiscard]] std::optional<TimestampInfo> GetNewestTimestamp() const;
    
    /**
     * @brief Format summary
     */
    [[nodiscard]] std::string GetSummary() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Validator configuration
 */
struct SignatureValidatorConfiguration {
    /// @brief Default validation flags
    ValidationFlags defaultFlags = ValidationFlags::Standard;
    
    /// @brief Enable signature caching
    bool enableCaching = true;
    
    /// @brief Cache duration (seconds)
    uint32_t cacheDurationSecs = SignatureConstants::CACHE_DURATION_SECS;
    
    /// @brief Enable revocation checking
    bool enableRevocationCheck = true;
    
    /// @brief Revocation check timeout (milliseconds)
    uint32_t revocationTimeoutMs = SignatureConstants::REVOCATION_TIMEOUT_MS;
    
    /// @brief Allow weak algorithms (MD5, SHA-1)
    bool allowWeakAlgorithms = false;
    
    /// @brief Require timestamps for signatures
    bool requireTimestamps = false;
    
    /// @brief Allow catalog signatures
    bool allowCatalogSignatures = true;
    
    /// @brief Allow test signatures
    bool allowTestSignatures = false;
    
    /// @brief Trusted publishers (thumbprints)
    std::vector<std::array<uint8_t, 20>> trustedPublishers;
    
    /// @brief Blocked signers (thumbprints)
    std::vector<std::array<uint8_t, 20>> blockedSigners;
    
    /// @brief Use system catalog database
    bool useSystemCatalogs = true;
    
    /// @brief Additional catalog paths
    std::vector<std::wstring> additionalCatalogPaths;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Validation options (per-request)
 */
struct SignatureValidationOptions {
    /// @brief Validation flags
    ValidationFlags flags = ValidationFlags::Standard;
    
    /// @brief Expected signer name (for pinning)
    std::wstring expectedSigner;
    
    /// @brief Expected thumbprint (for pinning)
    std::optional<std::array<uint8_t, 20>> expectedThumbprint;
    
    /// @brief Minimum timestamp date
    std::optional<SystemTimePoint> minimumTimestamp;
    
    /// @brief Verification time (empty = current time)
    std::optional<SystemTimePoint> verificationTime;
    
    /// @brief File type hint
    SignedFileType fileTypeHint = SignedFileType::Unknown;
};

/**
 * @brief Validation statistics
 */
struct SignatureValidatorStatistics {
    /// @brief Total validations
    std::atomic<uint64_t> totalValidations{0};
    
    /// @brief Valid signatures
    std::atomic<uint64_t> validSignatures{0};
    
    /// @brief Invalid signatures
    std::atomic<uint64_t> invalidSignatures{0};
    
    /// @brief Unsigned files
    std::atomic<uint64_t> unsignedFiles{0};
    
    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{0};
    
    /// @brief Cache misses
    std::atomic<uint64_t> cacheMisses{0};
    
    /// @brief Revocation checks
    std::atomic<uint64_t> revocationChecks{0};
    
    /// @brief Revoked certificates
    std::atomic<uint64_t> revokedCertificates{0};
    
    /// @brief Expired certificates
    std::atomic<uint64_t> expiredCertificates{0};
    
    /// @brief Blocked signers detected
    std::atomic<uint64_t> blockedSigners{0};
    
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
using SignatureCallback = std::function<void(const SignatureInfo&)>;

/// @brief Blocked signer callback
using BlockedSignerCallback = std::function<void(const std::wstring& filePath, 
                                                  const SignerInfo& signer)>;

/// @brief Unknown signer callback
using UnknownSignerCallback = std::function<bool(const std::wstring& filePath,
                                                  const SignerInfo& signer)>;

// ============================================================================
// DIGITAL SIGNATURE VALIDATOR ENGINE CLASS
// ============================================================================

/**
 * @class DigitalSignatureValidator
 * @brief Enterprise-grade Authenticode signature validation engine
 *
 * Provides comprehensive digital signature validation for PE files,
 * scripts, packages, and other signed content.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& validator = DigitalSignatureValidator::Instance();
 *     
 *     // Verify file signature
 *     auto sigInfo = validator.VerifyFile(L"C:\\app.exe");
 *     if (sigInfo.isValid) {
 *         std::wcout << L"Signed by: " << sigInfo.signer.signerName << std::endl;
 *     }
 *     
 *     // Check if signed by specific vendor
 *     if (validator.IsSignedBy(L"C:\\app.exe", L"Microsoft Corporation")) {
 *         // File is signed by Microsoft
 *     }
 * @endcode
 */
class DigitalSignatureValidator final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static DigitalSignatureValidator& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    DigitalSignatureValidator(const DigitalSignatureValidator&) = delete;
    DigitalSignatureValidator& operator=(const DigitalSignatureValidator&) = delete;
    DigitalSignatureValidator(DigitalSignatureValidator&&) = delete;
    DigitalSignatureValidator& operator=(DigitalSignatureValidator&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize signature validator
     */
    [[nodiscard]] bool Initialize(const SignatureValidatorConfiguration& config = {});
    
    /**
     * @brief Shutdown signature validator
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
    [[nodiscard]] bool SetConfiguration(const SignatureValidatorConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] SignatureValidatorConfiguration GetConfiguration() const;
    
    // ========================================================================
    // PRIMARY VALIDATION METHODS
    // ========================================================================
    
    /**
     * @brief Verify the signature of a PE file
     */
    [[nodiscard]] SignatureInfo VerifyFile(const std::wstring& filePath);
    
    /**
     * @brief Verify file with options
     */
    [[nodiscard]] SignatureInfo VerifyFile(std::wstring_view filePath,
                                           const SignatureValidationOptions& options);
    
    /**
     * @brief Verify signature from memory
     */
    [[nodiscard]] SignatureInfo VerifyMemory(std::span<const uint8_t> fileData,
                                             SignedFileType fileType = SignedFileType::Unknown);
    
    /**
     * @brief Verify catalog signature
     */
    [[nodiscard]] SignatureInfo VerifyCatalogSignature(std::wstring_view filePath,
                                                       std::wstring_view catalogPath);
    
    /**
     * @brief Asynchronous file verification
     */
    void VerifyFileAsync(std::wstring_view filePath, SignatureCallback callback,
                         const SignatureValidationOptions& options = {});
    
    // ========================================================================
    // QUICK CHECK METHODS
    // ========================================================================
    
    /**
     * @brief Check if file is signed by a specific trusted vendor
     */
    [[nodiscard]] bool IsSignedBy(const std::wstring& filePath, const std::wstring& vendorName);
    
    /**
     * @brief Quick check if file is signed (no full validation)
     */
    [[nodiscard]] bool IsSigned(std::wstring_view filePath);
    
    /**
     * @brief Check if file is signed by Microsoft
     */
    [[nodiscard]] bool IsMicrosoftSigned(std::wstring_view filePath);
    
    /**
     * @brief Check if driver is WHQL signed
     */
    [[nodiscard]] bool IsWHQLSigned(std::wstring_view filePath);
    
    /**
     * @brief Check if signature uses EV certificate
     */
    [[nodiscard]] bool IsEVSigned(std::wstring_view filePath);
    
    /**
     * @brief Check if file has valid timestamp
     */
    [[nodiscard]] bool HasValidTimestamp(std::wstring_view filePath);
    
    // ========================================================================
    // INTEGRITY VERIFICATION
    // ========================================================================
    
    /**
     * @brief Verify file integrity (hash check only)
     */
    [[nodiscard]] bool VerifyIntegrity(std::wstring_view filePath);
    
    /**
     * @brief Calculate Authenticode hash
     */
    [[nodiscard]] std::optional<FileHash> CalculateAuthenticodeHash(
        std::wstring_view filePath, HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Compare file hash with expected
     */
    [[nodiscard]] bool VerifyHash(std::wstring_view filePath, 
                                  std::span<const uint8_t> expectedHash,
                                  HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    // ========================================================================
    // TRUSTED PUBLISHER MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add trusted publisher
     */
    [[nodiscard]] bool AddTrustedPublisher(const std::array<uint8_t, 20>& thumbprint);
    
    /**
     * @brief Remove trusted publisher
     */
    [[nodiscard]] bool RemoveTrustedPublisher(const std::array<uint8_t, 20>& thumbprint);
    
    /**
     * @brief Check if publisher is trusted
     */
    [[nodiscard]] bool IsTrustedPublisher(const SignerInfo& signer) const;
    
    /**
     * @brief Get all trusted publishers
     */
    [[nodiscard]] std::vector<std::array<uint8_t, 20>> GetTrustedPublishers() const;
    
    // ========================================================================
    // BLOCKED SIGNER MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Block signer
     */
    [[nodiscard]] bool BlockSigner(const std::array<uint8_t, 20>& thumbprint,
                                   std::string_view reason = "");
    
    /**
     * @brief Unblock signer
     */
    [[nodiscard]] bool UnblockSigner(const std::array<uint8_t, 20>& thumbprint);
    
    /**
     * @brief Check if signer is blocked
     */
    [[nodiscard]] bool IsBlockedSigner(const SignerInfo& signer) const;
    
    /**
     * @brief Get all blocked signers
     */
    [[nodiscard]] std::vector<std::pair<std::array<uint8_t, 20>, std::string>> 
        GetBlockedSigners() const;
    
    // ========================================================================
    // CATALOG MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add catalog file to search path
     */
    [[nodiscard]] bool AddCatalog(std::wstring_view catalogPath);
    
    /**
     * @brief Remove catalog file
     */
    [[nodiscard]] bool RemoveCatalog(std::wstring_view catalogPath);
    
    /**
     * @brief Find catalog for file
     */
    [[nodiscard]] std::optional<std::wstring> FindCatalogForFile(std::wstring_view filePath);
    
    /**
     * @brief Refresh catalog cache
     */
    void RefreshCatalogCache();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set blocked signer callback
     */
    void SetBlockedSignerCallback(BlockedSignerCallback callback);
    
    /**
     * @brief Set unknown signer callback
     */
    void SetUnknownSignerCallback(UnknownSignerCallback callback);
    
    // ========================================================================
    // CACHE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Clear validation cache
     */
    void ClearCache();
    
    /**
     * @brief Remove file from cache
     */
    void InvalidateCache(std::wstring_view filePath);
    
    /**
     * @brief Get cache statistics
     */
    [[nodiscard]] std::unordered_map<std::string, size_t> GetCacheStats() const;
    
    // ========================================================================
    // UTILITY METHODS
    // ========================================================================
    
    /**
     * @brief Detect file type
     */
    [[nodiscard]] SignedFileType DetectFileType(std::wstring_view filePath);
    
    /**
     * @brief Extract signer info from certificate context
     */
    [[nodiscard]] SignerInfo ExtractSignerInfo(PCCERT_CONTEXT certContext);
    
    /**
     * @brief Format thumbprint to hex string
     */
    [[nodiscard]] static std::string ThumbprintToHex(
        const std::array<uint8_t, 20>& thumbprint);
    
    /**
     * @brief Parse thumbprint from hex string
     */
    [[nodiscard]] static std::optional<std::array<uint8_t, 20>> 
        ParseThumbprint(std::string_view hexString);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] SignatureValidatorStatistics GetStatistics() const;
    
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
    
    DigitalSignatureValidator();
    ~DigitalSignatureValidator();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<DigitalSignatureValidatorImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get signature result name
 */
[[nodiscard]] std::string_view GetSignatureResultName(SignatureResult result) noexcept;

/**
 * @brief Get signature type name
 */
[[nodiscard]] std::string_view GetSignatureTypeName(SignatureType type) noexcept;

/**
 * @brief Get hash algorithm name
 */
[[nodiscard]] std::string_view GetHashAlgorithmName(HashAlgorithm algorithm) noexcept;

/**
 * @brief Get signer trust level name
 */
[[nodiscard]] std::string_view GetSignerTrustLevelName(SignerTrustLevel level) noexcept;

/**
 * @brief Get timestamp status name
 */
[[nodiscard]] std::string_view GetTimestampStatusName(TimestampStatus status) noexcept;

/**
 * @brief Get file type name
 */
[[nodiscard]] std::string_view GetSignedFileTypeName(SignedFileType type) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class TrustedPublisherGuard
 * @brief RAII wrapper for temporary trusted publisher
 */
class TrustedPublisherGuard final {
public:
    explicit TrustedPublisherGuard(const std::array<uint8_t, 20>& thumbprint);
    ~TrustedPublisherGuard();
    
    TrustedPublisherGuard(const TrustedPublisherGuard&) = delete;
    TrustedPublisherGuard& operator=(const TrustedPublisherGuard&) = delete;
    
    [[nodiscard]] bool IsAdded() const noexcept { return m_added; }

private:
    std::array<uint8_t, 20> m_thumbprint{};
    bool m_added = false;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Verify file signature
 */
#define SS_VERIFY_SIGNATURE(path) \
    ::ShadowStrike::Security::DigitalSignatureValidator::Instance().VerifyFile(path)

/**
 * @brief Check if file is signed by vendor
 */
#define SS_IS_SIGNED_BY(path, vendor) \
    ::ShadowStrike::Security::DigitalSignatureValidator::Instance().IsSignedBy((path), (vendor))

/**
 * @brief Check if file is Microsoft signed
 */
#define SS_IS_MICROSOFT_SIGNED(path) \
    ::ShadowStrike::Security::DigitalSignatureValidator::Instance().IsMicrosoftSigned(path)
