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
 * ShadowStrike Security - CRYPTOGRAPHIC OPERATIONS MANAGER
 * ============================================================================
 *
 * @file CryptoManager.hpp
 * @brief Enterprise-grade cryptographic operations manager providing secure
 *        encryption, key management, hashing, and digital signatures for
 *        the ShadowStrike security suite.
 *
 * This module serves as the central cryptographic provider for all security
 * operations, implementing industry-standard algorithms with hardware
 * acceleration support and secure key management.
 *
 * CRYPTOGRAPHIC CAPABILITIES:
 * ===========================
 *
 * 1. SYMMETRIC ENCRYPTION
 *    - AES-128/192/256-GCM (authenticated)
 *    - AES-128/192/256-CBC
 *    - AES-256-XTS (disk encryption)
 *    - ChaCha20-Poly1305
 *    - Hardware AES-NI acceleration
 *
 * 2. ASYMMETRIC CRYPTOGRAPHY
 *    - RSA-2048/3072/4096 (OAEP, PSS)
 *    - ECDSA (P-256, P-384, P-521)
 *    - ECDH (key exchange)
 *    - Ed25519 signatures
 *    - X25519 key agreement
 *
 * 3. HASHING
 *    - SHA-256/384/512
 *    - SHA-3 (256/512)
 *    - BLAKE2b/BLAKE2s
 *    - HMAC (various algorithms)
 *    - HKDF key derivation
 *
 * 4. KEY DERIVATION
 *    - PBKDF2-SHA256 (password hashing)
 *    - Argon2id (memory-hard)
 *    - scrypt
 *    - HKDF (key expansion)
 *
 * 5. KEY MANAGEMENT
 *    - Windows DPAPI integration
 *    - TPM 2.0 support
 *    - Hardware security module (HSM) support
 *    - Secure key storage
 *    - Key rotation
 *
 * 6. RANDOM NUMBER GENERATION
 *    - CSPRNG (Windows CNG)
 *    - Hardware RNG (RDRAND)
 *    - Entropy pool management
 *
 * 7. SECURE MEMORY
 *    - Memory encryption
 *    - Secure zeroing
 *    - Guard pages
 *    - Anti-swap protection
 *
 * SECURITY FEATURES:
 * ==================
 * - Constant-time operations
 * - Side-channel attack mitigations
 * - Memory scrubbing
 * - Key usage enforcement
 * - Audit logging
 *
 * @note Utilizes Windows CNG (Cryptography Next Generation) API.
 * @note FIPS 140-2 compliant algorithms.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, FIPS 140-2, Common Criteria, PCI-DSS
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
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <type_traits>

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
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <wincrypt.h>
#  include <dpapi.h>
#endif

// ============================================================================
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/HashUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Security {
    class CryptoManagerImpl;
}

namespace ShadowStrike {
namespace Security {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace CryptoConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // KEY SIZES
    // ========================================================================
    
    /// @brief AES-128 key size (bytes)
    inline constexpr size_t AES_128_KEY_SIZE = 16;
    
    /// @brief AES-192 key size (bytes)
    inline constexpr size_t AES_192_KEY_SIZE = 24;
    
    /// @brief AES-256 key size (bytes)
    inline constexpr size_t AES_256_KEY_SIZE = 32;
    
    /// @brief ChaCha20 key size (bytes)
    inline constexpr size_t CHACHA20_KEY_SIZE = 32;
    
    /// @brief RSA-2048 key size (bits)
    inline constexpr uint32_t RSA_2048_KEY_BITS = 2048;
    
    /// @brief RSA-3072 key size (bits)
    inline constexpr uint32_t RSA_3072_KEY_BITS = 3072;
    
    /// @brief RSA-4096 key size (bits)
    inline constexpr uint32_t RSA_4096_KEY_BITS = 4096;
    
    /// @brief Ed25519 key size (bytes)
    inline constexpr size_t ED25519_KEY_SIZE = 32;
    
    /// @brief X25519 key size (bytes)
    inline constexpr size_t X25519_KEY_SIZE = 32;

    // ========================================================================
    // IV/NONCE SIZES
    // ========================================================================
    
    /// @brief AES-GCM nonce size (bytes)
    inline constexpr size_t AES_GCM_NONCE_SIZE = 12;
    
    /// @brief AES-CBC IV size (bytes)
    inline constexpr size_t AES_CBC_IV_SIZE = 16;
    
    /// @brief ChaCha20-Poly1305 nonce size (bytes)
    inline constexpr size_t CHACHA20_NONCE_SIZE = 12;

    // ========================================================================
    // TAG/HASH SIZES
    // ========================================================================
    
    /// @brief AES-GCM tag size (bytes)
    inline constexpr size_t AES_GCM_TAG_SIZE = 16;
    
    /// @brief Poly1305 tag size (bytes)
    inline constexpr size_t POLY1305_TAG_SIZE = 16;
    
    /// @brief SHA-256 digest size (bytes)
    inline constexpr size_t SHA256_SIZE = 32;
    
    /// @brief SHA-384 digest size (bytes)
    inline constexpr size_t SHA384_SIZE = 48;
    
    /// @brief SHA-512 digest size (bytes)
    inline constexpr size_t SHA512_SIZE = 64;
    
    /// @brief BLAKE2b-256 digest size (bytes)
    inline constexpr size_t BLAKE2B_256_SIZE = 32;
    
    /// @brief BLAKE2b-512 digest size (bytes)
    inline constexpr size_t BLAKE2B_512_SIZE = 64;

    // ========================================================================
    // KEY DERIVATION
    // ========================================================================
    
    /// @brief Default PBKDF2 iterations
    inline constexpr uint32_t DEFAULT_PBKDF2_ITERATIONS = 600000;
    
    /// @brief Default Argon2 memory (KB)
    inline constexpr uint32_t DEFAULT_ARGON2_MEMORY_KB = 65536;
    
    /// @brief Default Argon2 iterations
    inline constexpr uint32_t DEFAULT_ARGON2_ITERATIONS = 3;
    
    /// @brief Default Argon2 parallelism
    inline constexpr uint32_t DEFAULT_ARGON2_PARALLELISM = 4;
    
    /// @brief Default salt size (bytes)
    inline constexpr size_t DEFAULT_SALT_SIZE = 32;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum encryption size (bytes)
    inline constexpr size_t MAX_ENCRYPTION_SIZE = 2ULL * 1024 * 1024 * 1024;
    
    /// @brief Maximum key count
    inline constexpr size_t MAX_KEY_COUNT = 1000;
    
    /// @brief Maximum cached keys
    inline constexpr size_t MAX_CACHED_KEYS = 100;
    
    /// @brief Key rotation interval (seconds)
    inline constexpr uint32_t DEFAULT_KEY_ROTATION_SECS = 86400 * 30;  // 30 days

}  // namespace CryptoConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// Fixed-size key and hash types
using AES128Key = std::array<uint8_t, 16>;
using AES256Key = std::array<uint8_t, 32>;
using ChaChaKey = std::array<uint8_t, 32>;
using Hash256 = std::array<uint8_t, 32>;
using Hash384 = std::array<uint8_t, 48>;
using Hash512 = std::array<uint8_t, 64>;
using Nonce96 = std::array<uint8_t, 12>;
using IV128 = std::array<uint8_t, 16>;
using Tag128 = std::array<uint8_t, 16>;
using Salt256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Symmetric encryption algorithm
 */
enum class SymmetricAlgorithm : uint8_t {
    None                = 0,
    AES_128_GCM         = 1,    ///< AES-128-GCM (authenticated)
    AES_256_GCM         = 2,    ///< AES-256-GCM (authenticated)
    AES_128_CBC         = 3,    ///< AES-128-CBC (requires separate MAC)
    AES_256_CBC         = 4,    ///< AES-256-CBC (requires separate MAC)
    AES_256_XTS         = 5,    ///< AES-256-XTS (disk encryption)
    ChaCha20_Poly1305   = 6,    ///< ChaCha20-Poly1305 (authenticated)
    AES_192_GCM         = 7,    ///< AES-192-GCM
    AES_128_CTR         = 8,    ///< AES-128-CTR
    AES_256_CTR         = 9     ///< AES-256-CTR
};

/**
 * @brief Asymmetric algorithm
 */
enum class AsymmetricAlgorithm : uint8_t {
    None                = 0,
    RSA_2048            = 1,
    RSA_3072            = 2,
    RSA_4096            = 3,
    ECDSA_P256          = 4,    ///< NIST P-256
    ECDSA_P384          = 5,    ///< NIST P-384
    ECDSA_P521          = 6,    ///< NIST P-521
    ECDH_P256           = 7,    ///< ECDH with P-256
    ECDH_P384           = 8,    ///< ECDH with P-384
    Ed25519             = 9,    ///< Ed25519 signatures
    X25519              = 10    ///< X25519 key agreement
};

/**
 * @brief Hash algorithm
 */
enum class HashAlgorithm : uint8_t {
    None        = 0,
    MD5         = 1,    ///< Deprecated - for compatibility only
    SHA1        = 2,    ///< Deprecated - for compatibility only
    SHA256      = 3,
    SHA384      = 4,
    SHA512      = 5,
    SHA3_256    = 6,
    SHA3_512    = 7,
    BLAKE2b_256 = 8,
    BLAKE2b_512 = 9,
    BLAKE2s_256 = 10,
    BLAKE3      = 11
};

/**
 * @brief Key derivation function
 */
enum class KDFAlgorithm : uint8_t {
    None        = 0,
    PBKDF2_SHA256   = 1,
    PBKDF2_SHA512   = 2,
    Argon2id        = 3,
    Argon2i         = 4,
    Argon2d         = 5,
    scrypt          = 6,
    HKDF_SHA256     = 7,
    HKDF_SHA512     = 8,
    BCrypt          = 9
};

/**
 * @brief Key type
 */
enum class KeyType : uint8_t {
    Symmetric       = 0,    ///< Symmetric encryption key
    RSAPublic       = 1,    ///< RSA public key
    RSAPrivate      = 2,    ///< RSA private key
    ECDSAPublic     = 3,    ///< ECDSA public key
    ECDSAPrivate    = 4,    ///< ECDSA private key
    ECDHPublic      = 5,    ///< ECDH public key
    ECDHPrivate     = 6,    ///< ECDH private key
    Ed25519Public   = 7,    ///< Ed25519 public key
    Ed25519Private  = 8,    ///< Ed25519 private key
    X25519Public    = 9,    ///< X25519 public key
    X25519Private   = 10,   ///< X25519 private key
    HMAC            = 11,   ///< HMAC key
    KDF             = 12    ///< Key derivation key
};

/**
 * @brief Key storage location
 */
enum class KeyStorage : uint8_t {
    Memory          = 0,    ///< In-memory (secure memory)
    DPAPI           = 1,    ///< Windows DPAPI
    TPM             = 2,    ///< TPM 2.0
    HSM             = 3,    ///< Hardware Security Module
    KeyVault        = 4,    ///< Cloud key vault
    File            = 5     ///< Encrypted file
};

/**
 * @brief RSA padding mode
 */
enum class RSAPadding : uint8_t {
    PKCS1           = 0,    ///< PKCS#1 v1.5 (legacy)
    OAEP_SHA256     = 1,    ///< OAEP with SHA-256
    OAEP_SHA384     = 2,    ///< OAEP with SHA-384
    OAEP_SHA512     = 3,    ///< OAEP with SHA-512
    PSS_SHA256      = 4,    ///< PSS with SHA-256 (signatures)
    PSS_SHA384      = 5,    ///< PSS with SHA-384 (signatures)
    PSS_SHA512      = 6     ///< PSS with SHA-512 (signatures)
};

/**
 * @brief Crypto operation result
 */
enum class CryptoResult : uint8_t {
    Success             = 0,
    InvalidKey          = 1,
    InvalidData         = 2,
    InvalidIV           = 3,
    InvalidTag          = 4,
    AuthenticationFailed= 5,
    BufferTooSmall      = 6,
    AlgorithmNotSupported = 7,
    KeyNotFound         = 8,
    TPMError            = 9,
    HSMError            = 10,
    PermissionDenied    = 11,
    InternalError       = 255
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
 * @brief Key metadata
 */
struct KeyMetadata {
    /// @brief Key identifier
    std::string id;
    
    /// @brief Key type
    KeyType type = KeyType::Symmetric;
    
    /// @brief Algorithm
    std::variant<SymmetricAlgorithm, AsymmetricAlgorithm> algorithm;
    
    /// @brief Key size (bits)
    uint32_t keySizeBits = 0;
    
    /// @brief Storage location
    KeyStorage storage = KeyStorage::Memory;
    
    /// @brief Creation time
    SystemTimePoint createdAt;
    
    /// @brief Expiration time
    std::optional<SystemTimePoint> expiresAt;
    
    /// @brief Last used time
    TimePoint lastUsed;
    
    /// @brief Usage count
    uint64_t usageCount = 0;
    
    /// @brief Is exportable
    bool isExportable = false;
    
    /// @brief Is extractable (for HSM/TPM)
    bool isExtractable = false;
    
    /// @brief Description
    std::string description;
    
    /**
     * @brief Check if key is expired
     */
    [[nodiscard]] bool IsExpired() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Key derivation parameters
 */
struct KDFParameters {
    /// @brief Algorithm
    KDFAlgorithm algorithm = KDFAlgorithm::PBKDF2_SHA256;
    
    /// @brief Salt
    std::vector<uint8_t> salt;
    
    /// @brief PBKDF2 iterations
    uint32_t iterations = CryptoConstants::DEFAULT_PBKDF2_ITERATIONS;
    
    /// @brief Argon2 memory (KB)
    uint32_t memoryKB = CryptoConstants::DEFAULT_ARGON2_MEMORY_KB;
    
    /// @brief Argon2 parallelism
    uint32_t parallelism = CryptoConstants::DEFAULT_ARGON2_PARALLELISM;
    
    /// @brief Output key length (bytes)
    size_t outputLength = 32;
    
    /// @brief Additional info (for HKDF)
    std::vector<uint8_t> info;
    
    /**
     * @brief Create PBKDF2 parameters
     */
    static KDFParameters PBKDF2(uint32_t iterations = CryptoConstants::DEFAULT_PBKDF2_ITERATIONS);
    
    /**
     * @brief Create Argon2id parameters
     */
    static KDFParameters Argon2id(uint32_t memoryKB = CryptoConstants::DEFAULT_ARGON2_MEMORY_KB,
                                  uint32_t iterations = CryptoConstants::DEFAULT_ARGON2_ITERATIONS);
    
    /**
     * @brief Create HKDF parameters
     */
    static KDFParameters HKDF(std::span<const uint8_t> info = {});
};

/**
 * @brief Encryption result
 */
struct EncryptionResult {
    /// @brief Result code
    CryptoResult result = CryptoResult::Success;
    
    /// @brief Ciphertext
    std::vector<uint8_t> ciphertext;
    
    /// @brief IV/Nonce (if generated internally)
    std::vector<uint8_t> iv;
    
    /// @brief Authentication tag (for AEAD)
    std::vector<uint8_t> tag;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /**
     * @brief Check if successful
     */
    [[nodiscard]] bool IsSuccess() const noexcept { 
        return result == CryptoResult::Success; 
    }
    
    /**
     * @brief Get combined output (IV + ciphertext + tag)
     */
    [[nodiscard]] std::vector<uint8_t> GetCombinedOutput() const;
};

/**
 * @brief Decryption result
 */
struct DecryptionResult {
    /// @brief Result code
    CryptoResult result = CryptoResult::Success;
    
    /// @brief Plaintext
    std::vector<uint8_t> plaintext;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    /**
     * @brief Check if successful
     */
    [[nodiscard]] bool IsSuccess() const noexcept { 
        return result == CryptoResult::Success; 
    }
};

/**
 * @brief Digital signature result
 */
struct SignatureResult {
    /// @brief Result code
    CryptoResult result = CryptoResult::Success;
    
    /// @brief Signature
    std::vector<uint8_t> signature;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    [[nodiscard]] bool IsSuccess() const noexcept { 
        return result == CryptoResult::Success; 
    }
};

/**
 * @brief Key generation result
 */
struct KeyGenerationResult {
    /// @brief Result code
    CryptoResult result = CryptoResult::Success;
    
    /// @brief Key ID (for managed keys)
    std::string keyId;
    
    /// @brief Key data (for unmanaged keys)
    std::vector<uint8_t> keyData;
    
    /// @brief Public key (for asymmetric)
    std::vector<uint8_t> publicKey;
    
    /// @brief Key metadata
    KeyMetadata metadata;
    
    /// @brief Error message (if failed)
    std::string errorMessage;
    
    [[nodiscard]] bool IsSuccess() const noexcept { 
        return result == CryptoResult::Success; 
    }
};

/**
 * @brief Crypto manager configuration
 */
struct CryptoManagerConfiguration {
    /// @brief Default symmetric algorithm
    SymmetricAlgorithm defaultSymmetricAlgorithm = SymmetricAlgorithm::AES_256_GCM;
    
    /// @brief Default hash algorithm
    HashAlgorithm defaultHashAlgorithm = HashAlgorithm::SHA256;
    
    /// @brief Default KDF algorithm
    KDFAlgorithm defaultKDFAlgorithm = KDFAlgorithm::Argon2id;
    
    /// @brief Enable hardware acceleration
    bool enableHardwareAcceleration = true;
    
    /// @brief Enable secure memory
    bool enableSecureMemory = true;
    
    /// @brief Enable TPM
    bool enableTPM = false;
    
    /// @brief Enable FIPS mode
    bool enableFIPSMode = false;
    
    /// @brief Key rotation interval (seconds)
    uint32_t keyRotationIntervalSecs = CryptoConstants::DEFAULT_KEY_ROTATION_SECS;
    
    /// @brief Maximum cached keys
    size_t maxCachedKeys = CryptoConstants::MAX_CACHED_KEYS;
    
    /// @brief Audit logging
    bool enableAuditLogging = true;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Crypto manager statistics
 */
struct CryptoManagerStatistics {
    /// @brief Total encryptions
    std::atomic<uint64_t> totalEncryptions{0};
    
    /// @brief Total decryptions
    std::atomic<uint64_t> totalDecryptions{0};
    
    /// @brief Total hashes
    std::atomic<uint64_t> totalHashes{0};
    
    /// @brief Total signatures
    std::atomic<uint64_t> totalSignatures{0};
    
    /// @brief Total verifications
    std::atomic<uint64_t> totalVerifications{0};
    
    /// @brief Total key generations
    std::atomic<uint64_t> totalKeyGenerations{0};
    
    /// @brief Total key derivations
    std::atomic<uint64_t> totalKeyDerivations{0};
    
    /// @brief Total random bytes generated
    std::atomic<uint64_t> totalRandomBytes{0};
    
    /// @brief Authentication failures
    std::atomic<uint64_t> authenticationFailures{0};
    
    /// @brief Hardware acceleration used
    std::atomic<uint64_t> hardwareAccelerationOps{0};
    
    /// @brief TPM operations
    std::atomic<uint64_t> tpmOperations{0};
    
    /// @brief Active keys
    std::atomic<size_t> activeKeys{0};
    
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

/// @brief Key rotation callback
using KeyRotationCallback = std::function<void(const std::string& keyId, 
                                               const KeyMetadata& oldMetadata,
                                               const KeyMetadata& newMetadata)>;

/// @brief Audit callback
using CryptoAuditCallback = std::function<void(const std::string& operation,
                                               const std::string& keyId,
                                               bool success)>;

// ============================================================================
// CRYPTO MANAGER ENGINE CLASS
// ============================================================================

/**
 * @class CryptoManager
 * @brief Enterprise-grade cryptographic operations manager
 *
 * Provides comprehensive cryptographic services including symmetric/asymmetric
 * encryption, hashing, digital signatures, and key management.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& crypto = CryptoManager::Instance();
 *     
 *     // Initialize
 *     CryptoManagerConfiguration config;
 *     config.enableTPM = true;
 *     crypto.Initialize(config);
 *     
 *     // Encrypt data using AES-256-GCM
 *     auto key = crypto.GenerateRandomKey(32);
 *     auto result = crypto.Encrypt(data, key);
 *     
 *     // Decrypt data
 *     auto decrypted = crypto.Decrypt(result.ciphertext, key);
 * @endcode
 */
class CryptoManager final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static CryptoManager& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    CryptoManager(const CryptoManager&) = delete;
    CryptoManager& operator=(const CryptoManager&) = delete;
    CryptoManager(CryptoManager&&) = delete;
    CryptoManager& operator=(CryptoManager&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize crypto manager
     */
    [[nodiscard]] bool Initialize(const CryptoManagerConfiguration& config = {});
    
    /**
     * @brief Shutdown crypto manager
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
    [[nodiscard]] bool SetConfiguration(const CryptoManagerConfiguration& config);
    
    /**
     * @brief Get current configuration
     */
    [[nodiscard]] CryptoManagerConfiguration GetConfiguration() const;
    
    // ========================================================================
    // SYMMETRIC ENCRYPTION
    // ========================================================================
    
    /**
     * @brief Encrypt data using AES-256-GCM
     */
    [[nodiscard]] std::vector<uint8_t> Encrypt(const std::vector<uint8_t>& data, 
                                               const std::vector<uint8_t>& key);
    
    /**
     * @brief Encrypt with specified algorithm
     */
    [[nodiscard]] EncryptionResult Encrypt(std::span<const uint8_t> plaintext,
                                           std::span<const uint8_t> key,
                                           SymmetricAlgorithm algorithm = SymmetricAlgorithm::AES_256_GCM,
                                           std::span<const uint8_t> iv = {},
                                           std::span<const uint8_t> aad = {});
    
    /**
     * @brief Decrypt data using AES-256-GCM
     */
    [[nodiscard]] std::vector<uint8_t> Decrypt(const std::vector<uint8_t>& ciphertext, 
                                               const std::vector<uint8_t>& key);
    
    /**
     * @brief Decrypt with specified algorithm
     */
    [[nodiscard]] DecryptionResult Decrypt(std::span<const uint8_t> ciphertext,
                                           std::span<const uint8_t> key,
                                           SymmetricAlgorithm algorithm = SymmetricAlgorithm::AES_256_GCM,
                                           std::span<const uint8_t> iv = {},
                                           std::span<const uint8_t> tag = {},
                                           std::span<const uint8_t> aad = {});
    
    /**
     * @brief Encrypt file
     */
    [[nodiscard]] CryptoResult EncryptFile(std::wstring_view inputPath,
                                           std::wstring_view outputPath,
                                           std::span<const uint8_t> key,
                                           SymmetricAlgorithm algorithm = SymmetricAlgorithm::AES_256_GCM);
    
    /**
     * @brief Decrypt file
     */
    [[nodiscard]] CryptoResult DecryptFile(std::wstring_view inputPath,
                                           std::wstring_view outputPath,
                                           std::span<const uint8_t> key,
                                           SymmetricAlgorithm algorithm = SymmetricAlgorithm::AES_256_GCM);
    
    // ========================================================================
    // ASYMMETRIC OPERATIONS
    // ========================================================================
    
    /**
     * @brief RSA encrypt
     */
    [[nodiscard]] EncryptionResult RSAEncrypt(std::span<const uint8_t> plaintext,
                                              std::span<const uint8_t> publicKey,
                                              RSAPadding padding = RSAPadding::OAEP_SHA256);
    
    /**
     * @brief RSA decrypt
     */
    [[nodiscard]] DecryptionResult RSADecrypt(std::span<const uint8_t> ciphertext,
                                              const std::string& privateKeyId,
                                              RSAPadding padding = RSAPadding::OAEP_SHA256);
    
    /**
     * @brief ECDH key agreement
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> ECDHKeyAgreement(
        std::span<const uint8_t> peerPublicKey,
        const std::string& privateKeyId);
    
    // ========================================================================
    // DIGITAL SIGNATURES
    // ========================================================================
    
    /**
     * @brief Sign data
     */
    [[nodiscard]] SignatureResult Sign(std::span<const uint8_t> data,
                                       const std::string& privateKeyId,
                                       HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Verify signature
     */
    [[nodiscard]] bool Verify(std::span<const uint8_t> data,
                              std::span<const uint8_t> signature,
                              std::span<const uint8_t> publicKey,
                              HashAlgorithm hashAlgorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Sign data with Ed25519
     */
    [[nodiscard]] SignatureResult SignEd25519(std::span<const uint8_t> data,
                                              const std::string& privateKeyId);
    
    /**
     * @brief Verify Ed25519 signature
     */
    [[nodiscard]] bool VerifyEd25519(std::span<const uint8_t> data,
                                     std::span<const uint8_t> signature,
                                     std::span<const uint8_t> publicKey);
    
    // ========================================================================
    // HASHING
    // ========================================================================
    
    /**
     * @brief Compute hash
     */
    [[nodiscard]] std::vector<uint8_t> Hash(std::span<const uint8_t> data,
                                            HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Compute SHA-256 hash
     */
    [[nodiscard]] Hash256 SHA256(std::span<const uint8_t> data);
    
    /**
     * @brief Compute SHA-384 hash
     */
    [[nodiscard]] Hash384 SHA384(std::span<const uint8_t> data);
    
    /**
     * @brief Compute SHA-512 hash
     */
    [[nodiscard]] Hash512 SHA512(std::span<const uint8_t> data);
    
    /**
     * @brief Compute HMAC
     */
    [[nodiscard]] std::vector<uint8_t> HMAC(std::span<const uint8_t> data,
                                            std::span<const uint8_t> key,
                                            HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Verify HMAC
     */
    [[nodiscard]] bool VerifyHMAC(std::span<const uint8_t> data,
                                  std::span<const uint8_t> expectedMAC,
                                  std::span<const uint8_t> key,
                                  HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Hash file
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> HashFile(std::wstring_view filePath,
                                                               HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    // ========================================================================
    // KEY GENERATION
    // ========================================================================
    
    /**
     * @brief Generate a cryptographically secure random key
     */
    [[nodiscard]] std::vector<uint8_t> GenerateRandomKey(size_t length = 32);
    
    /**
     * @brief Generate symmetric key
     */
    [[nodiscard]] KeyGenerationResult GenerateSymmetricKey(SymmetricAlgorithm algorithm,
                                                           KeyStorage storage = KeyStorage::Memory);
    
    /**
     * @brief Generate RSA key pair
     */
    [[nodiscard]] KeyGenerationResult GenerateRSAKeyPair(uint32_t keySizeBits = 2048,
                                                         KeyStorage storage = KeyStorage::Memory);
    
    /**
     * @brief Generate ECDSA key pair
     */
    [[nodiscard]] KeyGenerationResult GenerateECDSAKeyPair(AsymmetricAlgorithm curve = AsymmetricAlgorithm::ECDSA_P256,
                                                           KeyStorage storage = KeyStorage::Memory);
    
    /**
     * @brief Generate Ed25519 key pair
     */
    [[nodiscard]] KeyGenerationResult GenerateEd25519KeyPair(KeyStorage storage = KeyStorage::Memory);
    
    /**
     * @brief Generate X25519 key pair
     */
    [[nodiscard]] KeyGenerationResult GenerateX25519KeyPair(KeyStorage storage = KeyStorage::Memory);
    
    // ========================================================================
    // KEY DERIVATION
    // ========================================================================
    
    /**
     * @brief Derive key from password
     */
    [[nodiscard]] std::vector<uint8_t> DeriveKey(std::string_view password,
                                                 std::span<const uint8_t> salt,
                                                 const KDFParameters& params = KDFParameters::Argon2id());
    
    /**
     * @brief Derive key using HKDF
     */
    [[nodiscard]] std::vector<uint8_t> HKDF(std::span<const uint8_t> inputKeyMaterial,
                                            std::span<const uint8_t> salt,
                                            std::span<const uint8_t> info,
                                            size_t outputLength = 32,
                                            HashAlgorithm algorithm = HashAlgorithm::SHA256);
    
    /**
     * @brief Hash password (for storage)
     */
    [[nodiscard]] std::string HashPassword(std::string_view password,
                                           KDFAlgorithm algorithm = KDFAlgorithm::Argon2id);
    
    /**
     * @brief Verify password against hash
     */
    [[nodiscard]] bool VerifyPassword(std::string_view password,
                                      std::string_view hash);
    
    // ========================================================================
    // RANDOM NUMBER GENERATION
    // ========================================================================
    
    /**
     * @brief Generate random bytes
     */
    [[nodiscard]] std::vector<uint8_t> GenerateRandom(size_t length);
    
    /**
     * @brief Generate random nonce
     */
    [[nodiscard]] Nonce96 GenerateNonce();
    
    /**
     * @brief Generate random IV
     */
    [[nodiscard]] IV128 GenerateIV();
    
    /**
     * @brief Generate random salt
     */
    [[nodiscard]] Salt256 GenerateSalt();
    
    /**
     * @brief Generate random uint32
     */
    [[nodiscard]] uint32_t GenerateRandomUInt32();
    
    /**
     * @brief Generate random uint64
     */
    [[nodiscard]] uint64_t GenerateRandomUInt64();
    
    // ========================================================================
    // KEY MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Store key
     */
    [[nodiscard]] std::string StoreKey(std::span<const uint8_t> keyData,
                                       KeyType type,
                                       KeyStorage storage = KeyStorage::DPAPI,
                                       std::string_view description = "");
    
    /**
     * @brief Retrieve key
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> RetrieveKey(const std::string& keyId);
    
    /**
     * @brief Delete key
     */
    [[nodiscard]] bool DeleteKey(const std::string& keyId);
    
    /**
     * @brief Get key metadata
     */
    [[nodiscard]] std::optional<KeyMetadata> GetKeyMetadata(const std::string& keyId) const;
    
    /**
     * @brief List all keys
     */
    [[nodiscard]] std::vector<KeyMetadata> ListKeys() const;
    
    /**
     * @brief Rotate key
     */
    [[nodiscard]] std::string RotateKey(const std::string& oldKeyId);
    
    /**
     * @brief Export key (if exportable)
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> ExportKey(const std::string& keyId,
                                                                std::span<const uint8_t> wrappingKey);
    
    /**
     * @brief Import key
     */
    [[nodiscard]] std::string ImportKey(std::span<const uint8_t> wrappedKey,
                                        std::span<const uint8_t> wrappingKey,
                                        KeyType type,
                                        KeyStorage storage = KeyStorage::DPAPI);
    
    // ========================================================================
    // DPAPI OPERATIONS
    // ========================================================================
    
    /**
     * @brief Protect data with DPAPI
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> DPAPIProtect(std::span<const uint8_t> data,
                                                                    std::span<const uint8_t> entropy = {});
    
    /**
     * @brief Unprotect data with DPAPI
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> DPAPIUnprotect(std::span<const uint8_t> protectedData,
                                                                      std::span<const uint8_t> entropy = {});
    
    // ========================================================================
    // TPM OPERATIONS
    // ========================================================================
    
    /**
     * @brief Check if TPM is available
     */
    [[nodiscard]] bool IsTPMAvailable() const;
    
    /**
     * @brief Create TPM-protected key
     */
    [[nodiscard]] std::string CreateTPMKey(KeyType type);
    
    /**
     * @brief Seal data with TPM
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> TPMSeal(std::span<const uint8_t> data);
    
    /**
     * @brief Unseal data with TPM
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> TPMUnseal(std::span<const uint8_t> sealedData);
    
    // ========================================================================
    // SECURE MEMORY
    // ========================================================================
    
    /**
     * @brief Allocate secure memory
     */
    [[nodiscard]] void* SecureAlloc(size_t size);
    
    /**
     * @brief Free secure memory
     */
    void SecureFree(void* ptr, size_t size);
    
    /**
     * @brief Secure zero memory
     */
    void SecureZero(void* ptr, size_t size);
    
    /**
     * @brief Compare in constant time
     */
    [[nodiscard]] bool ConstantTimeCompare(std::span<const uint8_t> a, 
                                           std::span<const uint8_t> b);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set key rotation callback
     */
    void SetKeyRotationCallback(KeyRotationCallback callback);
    
    /**
     * @brief Set audit callback
     */
    void SetAuditCallback(CryptoAuditCallback callback);
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Check if hardware acceleration is available
     */
    [[nodiscard]] bool IsHardwareAccelerationAvailable() const;
    
    /**
     * @brief Check if FIPS mode is enabled
     */
    [[nodiscard]] bool IsFIPSModeEnabled() const;
    
    /**
     * @brief Get supported algorithms
     */
    [[nodiscard]] std::vector<std::string> GetSupportedAlgorithms() const;
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] CryptoManagerStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
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
    
    CryptoManager();
    ~CryptoManager();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<CryptoManagerImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get symmetric algorithm name
 */
[[nodiscard]] std::string_view GetSymmetricAlgorithmName(SymmetricAlgorithm algorithm) noexcept;

/**
 * @brief Get asymmetric algorithm name
 */
[[nodiscard]] std::string_view GetAsymmetricAlgorithmName(AsymmetricAlgorithm algorithm) noexcept;

/**
 * @brief Get hash algorithm name
 */
[[nodiscard]] std::string_view GetHashAlgorithmName(HashAlgorithm algorithm) noexcept;

/**
 * @brief Get KDF algorithm name
 */
[[nodiscard]] std::string_view GetKDFAlgorithmName(KDFAlgorithm algorithm) noexcept;

/**
 * @brief Get crypto result name
 */
[[nodiscard]] std::string_view GetCryptoResultName(CryptoResult result) noexcept;

/**
 * @brief Get key type name
 */
[[nodiscard]] std::string_view GetKeyTypeName(KeyType type) noexcept;

/**
 * @brief Get key storage name
 */
[[nodiscard]] std::string_view GetKeyStorageName(KeyStorage storage) noexcept;

// ============================================================================
// RAII HELPERS
// ============================================================================

/**
 * @class SecureBuffer
 * @brief RAII wrapper for secure memory buffer
 */
template<size_t Size>
class SecureBuffer final {
public:
    SecureBuffer() { 
        CryptoManager::Instance().SecureZero(m_data.data(), Size);
    }
    
    ~SecureBuffer() {
        CryptoManager::Instance().SecureZero(m_data.data(), Size);
    }
    
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    
    [[nodiscard]] uint8_t* data() noexcept { return m_data.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return m_data.data(); }
    [[nodiscard]] constexpr size_t size() const noexcept { return Size; }
    [[nodiscard]] std::span<uint8_t> span() noexcept { return m_data; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return m_data; }

private:
    std::array<uint8_t, Size> m_data{};
};

/**
 * @class SecureVector
 * @brief RAII wrapper for secure vector
 */
class SecureVector final {
public:
    explicit SecureVector(size_t size = 0);
    ~SecureVector();
    
    SecureVector(const SecureVector&) = delete;
    SecureVector& operator=(const SecureVector&) = delete;
    SecureVector(SecureVector&& other) noexcept;
    SecureVector& operator=(SecureVector&& other) noexcept;
    
    void resize(size_t newSize);
    void clear();
    
    [[nodiscard]] uint8_t* data() noexcept { return m_data.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return m_data.data(); }
    [[nodiscard]] size_t size() const noexcept { return m_data.size(); }
    [[nodiscard]] bool empty() const noexcept { return m_data.empty(); }
    [[nodiscard]] std::span<uint8_t> span() noexcept { return m_data; }

private:
    std::vector<uint8_t> m_data;
};

}  // namespace Security
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Encrypt data
 */
#define SS_ENCRYPT(data, key) \
    ::ShadowStrike::Security::CryptoManager::Instance().Encrypt((data), (key))

/**
 * @brief Decrypt data
 */
#define SS_DECRYPT(data, key) \
    ::ShadowStrike::Security::CryptoManager::Instance().Decrypt((data), (key))

/**
 * @brief Compute SHA-256 hash
 */
#define SS_SHA256(data) \
    ::ShadowStrike::Security::CryptoManager::Instance().SHA256(data)

/**
 * @brief Generate random key
 */
#define SS_RANDOM_KEY(size) \
    ::ShadowStrike::Security::CryptoManager::Instance().GenerateRandomKey(size)
