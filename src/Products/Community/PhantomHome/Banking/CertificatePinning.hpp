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
 * ShadowStrike Banking Protection - CERTIFICATE PINNING
 * ============================================================================
 *
 * @file CertificatePinning.hpp
 * @brief Enterprise-grade SSL/TLS certificate pinning and validation engine
 *        for protecting banking and financial communications.
 *
 * Prevents Man-in-the-Middle (MitM) attacks by enforcing certificate pinning
 * for high-value domains including banks, payment gateways, and financial
 * institutions.
 *
 * CAPABILITIES:
 * =============
 *
 * 1. CERTIFICATE PINNING
 *    - SPKI (Subject Public Key Info) pinning
 *    - Leaf certificate pinning
 *    - Intermediate certificate pinning
 *    - Root CA pinning
 *    - Hash-based pinning (SHA-256/SHA-384)
 *
 * 2. CHAIN VALIDATION
 *    - Certificate chain verification
 *    - Path building and validation
 *    - Signature verification
 *    - Expiration checking
 *    - Revocation checking (CRL/OCSP)
 *
 * 3. TRANSPARENCY CHECKING
 *    - Certificate Transparency (CT) log verification
 *    - SCT validation
 *    - Rogue certificate detection
 *    - Pre-certificate analysis
 *
 * 4. MITM DETECTION
 *    - SSL interception detection
 *    - Proxy certificate detection
 *    - Self-signed detection
 *    - Untrusted root detection
 *
 * 5. PIN MANAGEMENT
 *    - Built-in bank pins database
 *    - Dynamic pin updates
 *    - Pin backup mechanisms
 *    - Graceful pin rotation
 *
 * INTEGRATION:
 * ============
 * - Utils::CryptoUtils for hash computation
 * - Utils::NetworkUtils for TLS hooks
 * - ThreatIntel for known bad certificates
 *
 * @note Requires integration with browser/TLS stack for enforcement.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: PCI-DSS 4.0, SOC2, ISO 27001
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
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <filesystem>

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
#  include <schannel.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/NetworkUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/FileUtils.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"
#include "../Whitelist/WhiteListStore.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Banking {
    class CertificatePinningImpl;
}

namespace ShadowStrike {
namespace Banking {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CertPinningConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum pins per domain
    inline constexpr size_t MAX_PINS_PER_DOMAIN = 16;
    
    /// @brief Maximum pinned domains
    inline constexpr size_t MAX_PINNED_DOMAINS = 4096;
    
    /// @brief Maximum certificate chain depth
    inline constexpr size_t MAX_CHAIN_DEPTH = 10;
    
    /// @brief Maximum certificate size
    inline constexpr size_t MAX_CERTIFICATE_SIZE = 64 * 1024;
    
    /// @brief Pin hash length (SHA-256)
    inline constexpr size_t PIN_HASH_LENGTH = 32;

    // ========================================================================
    // TIMING
    // ========================================================================
    
    /// @brief OCSP response cache time (seconds)
    inline constexpr uint32_t OCSP_CACHE_TIME_SECS = 3600;
    
    /// @brief CRL cache time (seconds)
    inline constexpr uint32_t CRL_CACHE_TIME_SECS = 86400;
    
    /// @brief Pin update check interval (hours)
    inline constexpr uint32_t PIN_UPDATE_INTERVAL_HOURS = 24;

    // ========================================================================
    // THRESHOLDS
    // ========================================================================
    
    /// @brief Minimum key size (RSA bits)
    inline constexpr uint32_t MIN_RSA_KEY_SIZE = 2048;
    
    /// @brief Minimum key size (EC bits)
    inline constexpr uint32_t MIN_EC_KEY_SIZE = 256;
    
    /// @brief Minimum days before expiry warning
    inline constexpr uint32_t EXPIRY_WARNING_DAYS = 30;

}  // namespace CertPinningConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;
using Hash384 = std::array<uint8_t, 48>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Pinning mode
 */
enum class PinningMode : uint8_t {
    Disabled        = 0,    ///< No pinning
    ReportOnly      = 1,    ///< Log violations but allow
    Enforce         = 2,    ///< Block on violation
    Strict          = 3     ///< Strict enforcement with CT check
};

/**
 * @brief Pin type
 */
enum class PinType : uint8_t {
    Unknown         = 0,
    SPKI            = 1,    ///< Subject Public Key Info
    LeafCert        = 2,    ///< Leaf certificate
    IntermediateCert= 3,    ///< Intermediate CA
    RootCert        = 4     ///< Root CA
};

/**
 * @brief Hash algorithm for pin
 */
enum class PinHashAlgorithm : uint8_t {
    SHA256          = 0,
    SHA384          = 1,
    SHA512          = 2
};

/**
 * @brief Certificate status
 */
enum class CertificateStatus : uint16_t {
    Valid               = 0,
    PinMismatch         = 1,
    Expired             = 2,
    NotYetValid         = 3,
    Revoked             = 4,
    UntrustedRoot       = 5,
    SelfSigned          = 6,
    ChainError          = 7,
    SignatureInvalid    = 8,
    WeakKey             = 9,
    WeakSignature       = 10,
    NameMismatch        = 11,
    CTViolation         = 12,
    OCSPError           = 13,
    CRLError            = 14,
    ProxyCertificate    = 15,
    ParseError          = 16,
    Unknown             = 0xFFFF
};

/**
 * @brief Validation action
 */
enum class ValidationAction : uint8_t {
    None            = 0,
    Allow           = 1,
    Warn            = 2,
    Block           = 3
};

/**
 * @brief Revocation check method
 */
enum class RevocationMethod : uint8_t {
    None            = 0,
    CRL             = 1,    ///< Certificate Revocation List
    OCSP            = 2,    ///< Online Certificate Status Protocol
    Both            = 3     ///< CRL and OCSP
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
 * @brief Certificate pin
 */
struct CertificatePin {
    /// @brief Domain pattern (e.g., "*.bank.com")
    std::string domain;
    
    /// @brief Pin hash (base64 encoded)
    std::string pinHash;
    
    /// @brief Pin type
    PinType pinType = PinType::SPKI;
    
    /// @brief Hash algorithm
    PinHashAlgorithm hashAlgorithm = PinHashAlgorithm::SHA256;
    
    /// @brief Expected issuer (optional)
    std::string expectedIssuer;
    
    /// @brief Is backup pin
    bool isBackup = false;
    
    /// @brief Expiration time
    SystemTimePoint expiration;
    
    /// @brief Source (e.g., "built-in", "user", "auto-discovered")
    std::string source;
    
    /// @brief Creation time
    SystemTimePoint createdAt;
    
    /**
     * @brief Check if pin is expired
     */
    [[nodiscard]] bool IsExpired() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Certificate info
 */
struct CertificateInfo {
    /// @brief Subject distinguished name
    std::string subject;
    
    /// @brief Issuer distinguished name
    std::string issuer;
    
    /// @brief Serial number (hex)
    std::string serialNumber;
    
    /// @brief SHA-256 fingerprint
    Hash256 sha256Fingerprint{};
    
    /// @brief SPKI SHA-256 hash
    Hash256 spkiSha256{};
    
    /// @brief Not before
    SystemTimePoint notBefore;
    
    /// @brief Not after
    SystemTimePoint notAfter;
    
    /// @brief Key algorithm
    std::string keyAlgorithm;
    
    /// @brief Key size (bits)
    uint32_t keySize = 0;
    
    /// @brief Signature algorithm
    std::string signatureAlgorithm;
    
    /// @brief Subject Alternative Names
    std::vector<std::string> subjectAltNames;
    
    /// @brief Is CA certificate
    bool isCA = false;
    
    /// @brief Path length constraint
    int32_t pathLengthConstraint = -1;
    
    /// @brief Key usage
    std::vector<std::string> keyUsage;
    
    /// @brief Extended key usage
    std::vector<std::string> extKeyUsage;
    
    /// @brief CRL distribution points
    std::vector<std::string> crlDistributionPoints;
    
    /// @brief OCSP responder URLs
    std::vector<std::string> ocspResponders;
    
    /// @brief Certificate Transparency SCTs
    std::vector<std::string> scts;
    
    /// @brief Raw certificate (DER encoded)
    std::vector<uint8_t> rawData;
    
    /**
     * @brief Check if expired
     */
    [[nodiscard]] bool IsExpired() const noexcept;
    
    /**
     * @brief Check if not yet valid
     */
    [[nodiscard]] bool IsNotYetValid() const noexcept;
    
    /**
     * @brief Get days until expiry
     */
    [[nodiscard]] int32_t GetDaysUntilExpiry() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Validation result
 */
struct ValidationResult {
    /// @brief Domain validated
    std::string domain;
    
    /// @brief Certificate status
    CertificateStatus status = CertificateStatus::Unknown;
    
    /// @brief Action taken
    ValidationAction action = ValidationAction::None;
    
    /// @brief Is MITM detected
    bool isMitMDetected = false;
    
    /// @brief Is pin match
    bool isPinMatch = false;
    
    /// @brief Is CT valid
    bool isCTValid = true;
    
    /// @brief Is revoked
    bool isRevoked = false;
    
    /// @brief Actual SPKI hash
    std::string actualHash;
    
    /// @brief Expected hashes
    std::vector<std::string> expectedHashes;
    
    /// @brief Certificate chain
    std::vector<CertificateInfo> certificateChain;
    
    /// @brief Error details
    std::string errorDetails;
    
    /// @brief Chain validation details
    std::string chainDetails;
    
    /// @brief Validation time
    SystemTimePoint validationTime;
    
    /// @brief Validation duration
    std::chrono::milliseconds validationDuration{0};
    
    /**
     * @brief Check if validation passed
     */
    [[nodiscard]] bool IsValid() const noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief CT Log entry
 */
struct CTLogEntry {
    /// @brief Log ID
    std::string logId;
    
    /// @brief Log name
    std::string logName;
    
    /// @brief Log operator
    std::string logOperator;
    
    /// @brief Log URL
    std::string logUrl;
    
    /// @brief Public key (base64)
    std::string publicKey;
    
    /// @brief Is trusted
    bool isTrusted = false;
};

/**
 * @brief Pinning statistics
 */
struct PinningStatistics {
    /// @brief Total validations
    std::atomic<uint64_t> totalValidations{0};
    
    /// @brief Successful validations
    std::atomic<uint64_t> successfulValidations{0};
    
    /// @brief Pin mismatches
    std::atomic<uint64_t> pinMismatches{0};
    
    /// @brief MITM detections
    std::atomic<uint64_t> mitmDetections{0};
    
    /// @brief Expired certificates
    std::atomic<uint64_t> expiredCerts{0};
    
    /// @brief Revoked certificates
    std::atomic<uint64_t> revokedCerts{0};
    
    /// @brief CT violations
    std::atomic<uint64_t> ctViolations{0};
    
    /// @brief Connections blocked
    std::atomic<uint64_t> connectionsBlocked{0};
    
    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{0};
    
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
struct CertificatePinningConfiguration {
    /// @brief Pinning mode
    PinningMode mode = PinningMode::Enforce;
    
    /// @brief Enable built-in bank pins
    bool enableBuiltInPins = true;
    
    /// @brief Enable CT checking
    bool enableCTChecking = true;
    
    /// @brief Enable revocation checking
    bool enableRevocationChecking = true;
    
    /// @brief Revocation check method
    RevocationMethod revocationMethod = RevocationMethod::OCSP;
    
    /// @brief Allow soft fail on revocation check
    bool allowRevocationSoftFail = true;
    
    /// @brief Minimum key size (RSA bits)
    uint32_t minRSAKeySize = CertPinningConstants::MIN_RSA_KEY_SIZE;
    
    /// @brief Minimum key size (EC bits)
    uint32_t minECKeySize = CertPinningConstants::MIN_EC_KEY_SIZE;
    
    /// @brief Block weak signatures
    bool blockWeakSignatures = true;
    
    /// @brief Auto-update pins
    bool autoUpdatePins = true;
    
    /// @brief Pin database path
    std::wstring pinDatabasePath;
    
    /// @brief Trusted CT logs path
    std::wstring trustedCTLogsPath;
    
    /// @brief Bypass domains
    std::vector<std::string> bypassDomains;
    
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

/// @brief Violation callback
using ViolationCallback = std::function<void(const ValidationResult&)>;

/// @brief Pin update callback
using PinUpdateCallback = std::function<void(const std::string& domain, bool added)>;

/// @brief Error callback
using ErrorCallback = std::function<void(const std::string& message, int code)>;

// ============================================================================
// CERTIFICATE PINNING CLASS
// ============================================================================

/**
 * @class CertificatePinning
 * @brief Enterprise-grade SSL/TLS certificate pinning engine
 *
 * Provides comprehensive certificate pinning and validation for
 * protecting banking and financial communications from MITM attacks.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& pinning = CertificatePinning::Instance();
 *     pinning.Initialize(config);
 *     
 *     // Validate connection
 *     auto result = pinning.ValidateConnection(domain, certChain);
 *     if (!result.IsValid()) {
 *         // Block connection
 *     }
 * @endcode
 */
class CertificatePinning final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static CertificatePinning& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    CertificatePinning(const CertificatePinning&) = delete;
    CertificatePinning& operator=(const CertificatePinning&) = delete;
    CertificatePinning(CertificatePinning&&) = delete;
    CertificatePinning& operator=(CertificatePinning&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize pinning engine
     */
    [[nodiscard]] bool Initialize(const CertificatePinningConfiguration& config = {});
    
    /**
     * @brief Shutdown pinning engine
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
    [[nodiscard]] bool UpdateConfiguration(const CertificatePinningConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] CertificatePinningConfiguration GetConfiguration() const;
    
    /**
     * @brief Set pinning mode
     */
    void SetMode(PinningMode mode);
    
    /**
     * @brief Get pinning mode
     */
    [[nodiscard]] PinningMode GetMode() const noexcept;
    
    // ========================================================================
    // PIN MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Load built-in bank pins
     */
    [[nodiscard]] bool LoadDefaultBankPins();
    
    /**
     * @brief Load pins from file
     */
    [[nodiscard]] bool LoadPinsFromFile(const std::filesystem::path& path);
    
    /**
     * @brief Save pins to file
     */
    [[nodiscard]] bool SavePinsToFile(const std::filesystem::path& path) const;
    
    /**
     * @brief Add pin
     */
    void AddPin(const CertificatePin& pin);
    
    /**
     * @brief Add SPKI pin
     */
    void AddSPKIPin(const std::string& domain, const std::string& spkiHash,
                    bool isBackup = false);
    
    /**
     * @brief Remove pin
     */
    void RemovePin(const std::string& domain);
    
    /**
     * @brief Remove all pins for domain
     */
    void RemoveAllPins(const std::string& domain);
    
    /**
     * @brief Get pins for domain
     */
    [[nodiscard]] std::vector<CertificatePin> GetPins(const std::string& domain) const;
    
    /**
     * @brief Get all pins
     */
    [[nodiscard]] std::vector<CertificatePin> GetAllPins() const;
    
    /**
     * @brief Check if domain has pins
     */
    [[nodiscard]] bool HasPins(const std::string& domain) const;
    
    /**
     * @brief Get pinned domain count
     */
    [[nodiscard]] size_t GetPinnedDomainCount() const noexcept;
    
    /**
     * @brief Clear all pins
     */
    void ClearAllPins();
    
    // ========================================================================
    // VALIDATION
    // ========================================================================
    
    /**
     * @brief Validate connection
     */
    [[nodiscard]] ValidationResult ValidateConnection(
        const std::string& domain,
        std::span<const std::vector<uint8_t>> certChain);
    
    /**
     * @brief Validate certificate chain
     */
    [[nodiscard]] ValidationResult ValidateCertificateChain(
        const std::string& domain,
        const std::vector<CertificateInfo>& chain);
    
    /**
     * @brief Check pin match
     */
    [[nodiscard]] bool CheckPinMatch(
        const std::string& domain,
        const CertificateInfo& certificate) const;
    
    /**
     * @brief Validate against CT logs
     */
    [[nodiscard]] bool ValidateCertificateTransparency(
        const CertificateInfo& certificate) const;
    
    /**
     * @brief Check certificate revocation
     */
    [[nodiscard]] CertificateStatus CheckRevocation(
        const CertificateInfo& certificate) const;
    
    // ========================================================================
    // CERTIFICATE PARSING
    // ========================================================================
    
    /**
     * @brief Parse certificate
     */
    [[nodiscard]] std::optional<CertificateInfo> ParseCertificate(
        std::span<const uint8_t> derData) const;
    
    /**
     * @brief Parse certificate chain
     */
    [[nodiscard]] std::vector<CertificateInfo> ParseCertificateChain(
        std::span<const std::vector<uint8_t>> chainData) const;
    
    /**
     * @brief Calculate SPKI hash
     */
    [[nodiscard]] Hash256 CalculateSPKIHash(
        std::span<const uint8_t> derData) const;
    
    /**
     * @brief Calculate certificate fingerprint
     */
    [[nodiscard]] Hash256 CalculateFingerprint(
        std::span<const uint8_t> derData) const;
    
    /**
     * @brief Calculate pin (base64 encoded SPKI hash)
     */
    [[nodiscard]] std::string CalculatePin(
        std::span<const uint8_t> derData) const;
    
    // ========================================================================
    // CT LOG MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Load trusted CT logs
     */
    [[nodiscard]] bool LoadTrustedCTLogs(const std::filesystem::path& path);
    
    /**
     * @brief Add trusted CT log
     */
    void AddTrustedCTLog(const CTLogEntry& log);
    
    /**
     * @brief Get trusted CT logs
     */
    [[nodiscard]] std::vector<CTLogEntry> GetTrustedCTLogs() const;
    
    // ========================================================================
    // BYPASS MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Add bypass domain
     */
    void AddBypassDomain(const std::string& domain);
    
    /**
     * @brief Remove bypass domain
     */
    void RemoveBypassDomain(const std::string& domain);
    
    /**
     * @brief Check if domain is bypassed
     */
    [[nodiscard]] bool IsBypassedDomain(const std::string& domain) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Register violation callback
     */
    void RegisterViolationCallback(ViolationCallback callback);
    
    /**
     * @brief Register pin update callback
     */
    void RegisterPinUpdateCallback(PinUpdateCallback callback);
    
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
    [[nodiscard]] PinningStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get recent violations
     */
    [[nodiscard]] std::vector<ValidationResult> GetRecentViolations(
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
    
    CertificatePinning();
    ~CertificatePinning();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<CertificatePinningImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get pinning mode name
 */
[[nodiscard]] std::string_view GetPinningModeName(PinningMode mode) noexcept;

/**
 * @brief Get pin type name
 */
[[nodiscard]] std::string_view GetPinTypeName(PinType type) noexcept;

/**
 * @brief Get certificate status name
 */
[[nodiscard]] std::string_view GetCertificateStatusName(CertificateStatus status) noexcept;

/**
 * @brief Get validation action name
 */
[[nodiscard]] std::string_view GetValidationActionName(ValidationAction action) noexcept;

/**
 * @brief Check if certificate is self-signed
 */
[[nodiscard]] bool IsSelfSigned(const CertificateInfo& cert);

/**
 * @brief Check if certificate is CA
 */
[[nodiscard]] bool IsCACertificate(const CertificateInfo& cert);

/**
 * @brief Check domain match (including wildcards)
 */
[[nodiscard]] bool DomainMatches(std::string_view pattern, std::string_view domain);

/**
 * @brief Base64 encode
 */
[[nodiscard]] std::string Base64Encode(std::span<const uint8_t> data);

/**
 * @brief Base64 decode
 */
[[nodiscard]] std::vector<uint8_t> Base64Decode(std::string_view base64);

}  // namespace Banking
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Validate SSL connection
 */
#define SS_VALIDATE_SSL(domain, chain) \
    ::ShadowStrike::Banking::CertificatePinning::Instance().ValidateConnection(domain, chain)

/**
 * @brief Add certificate pin
 */
#define SS_ADD_CERT_PIN(domain, hash) \
    ::ShadowStrike::Banking::CertificatePinning::Instance().AddSPKIPin(domain, hash)