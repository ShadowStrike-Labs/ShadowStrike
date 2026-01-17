/**
 * @file CryptoUtils.hpp
 * @brief Enterprise-grade cryptographic utilities for ShadowStrike Security Suite
 *
 * Provides comprehensive cryptographic functionality including:
 * - Symmetric encryption (AES-CBC, AES-GCM, AES-CFB, ChaCha20-Poly1305)
 * - Asymmetric encryption (RSA, ECC with NIST curves)
 * - Secure random number generation (BCryptGenRandom)
 * - Key derivation (PBKDF2, HKDF)
 * - Digital signatures (RSA-PSS, ECDSA)
 * - Secure memory management (SecureBuffer, SecureString)
 *
 * All implementations use Windows CNG (Cryptography Next Generation) APIs
 * with FIPS 140-2 compliant algorithms where applicable.
 *
 * @note Thread Safety: Individual cipher instances are NOT thread-safe.
 *       Use separate instances per thread or external synchronization.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 * @license MIT License
 */

#pragma once

// ============================================================================
// Standard Library Headers
// ============================================================================
#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <optional>
#include <memory>
#include <functional>
#include <span>
#include <limits>
#include <type_traits>

// ============================================================================
// Windows Platform Headers
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
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#  pragma comment(lib, "crypt32.lib")
#endif

// ============================================================================
// Project Headers
// ============================================================================
#include "HashUtils.hpp"
#include "Logger.hpp"

namespace ShadowStrike {
    namespace Utils {
        namespace CryptoUtils {

            // ============================================================================
            // Security Constants
            // ============================================================================

            /**
             * @brief Minimum allowed PBKDF2 iterations for security compliance
             * @note OWASP recommends 310,000+ for SHA-256 as of 2023
             */
            inline constexpr uint32_t MIN_PBKDF2_ITERATIONS = 100000UL;

            /**
             * @brief Maximum key size in bytes (512-bit key maximum)
             */
            inline constexpr size_t MAX_KEY_SIZE_BYTES = 64ULL;

            /**
             * @brief Maximum IV/nonce size in bytes
             */
            inline constexpr size_t MAX_IV_SIZE_BYTES = 16ULL;

            /**
             * @brief Maximum plaintext size for single encryption operation (256 MiB)
             */
            inline constexpr size_t MAX_PLAINTEXT_SIZE = 256ULL * 1024ULL * 1024ULL;

            /**
             * @brief Maximum ciphertext size for single decryption operation (256 MiB + overhead)
             */
            inline constexpr size_t MAX_CIPHERTEXT_SIZE = 256ULL * 1024ULL * 1024ULL + 1024ULL;

            /**
             * @brief GCM authentication tag size in bytes (128-bit)
             */
            inline constexpr size_t GCM_TAG_SIZE_BYTES = 16ULL;

            /**
             * @brief GCM nonce size in bytes (96-bit, NIST recommended)
             */
            inline constexpr size_t GCM_NONCE_SIZE_BYTES = 12ULL;

            /**
             * @brief AES block size in bytes
             */
            inline constexpr size_t AES_BLOCK_SIZE_BYTES = 16ULL;

            /**
             * @brief Default salt size for key derivation (256-bit)
             */
            inline constexpr size_t DEFAULT_SALT_SIZE_BYTES = 32ULL;

            /**
             * @brief Minimum password length for key derivation
             */
            inline constexpr size_t MIN_PASSWORD_LENGTH = 8ULL;

            // ============================================================================
            // Error Handling
            // ============================================================================

            /**
             * @brief Cryptographic operation error information
             *
             * Captures both Win32 and NTSTATUS error codes along with
             * descriptive messages for debugging and logging purposes.
             */
            struct Error {
                DWORD win32 = ERROR_SUCCESS;      ///< Win32 error code
                LONG ntstatus = 0;                 ///< NTSTATUS code from BCrypt APIs
                std::wstring message;              ///< Human-readable error message
                std::wstring context;              ///< Operation context where error occurred

                /**
                 * @brief Check if an error occurred
                 * @return true if any error code is set
                 */
                [[nodiscard]] bool HasError() const noexcept {
                    return win32 != ERROR_SUCCESS || ntstatus != 0;
                }

                /**
                 * @brief Reset error state to success
                 */
                void Clear() noexcept {
                    win32 = ERROR_SUCCESS;
                    ntstatus = 0;
                    message.clear();
                    context.clear();
                }

                /**
                 * @brief Set Win32 error with context
                 * @param code Win32 error code
                 * @param msg Error message
                 * @param ctx Operation context
                 */
                void SetWin32Error(DWORD code, std::wstring_view msg, std::wstring_view ctx = L"") noexcept {
                    win32 = code;
                    ntstatus = 0;
                    try {
                        message = msg;
                        context = ctx;
                    }
                    catch (...) {
                        // Allocation failure - keep codes, lose strings
                    }
                }

                /**
                 * @brief Set NTSTATUS error with context
                 * @param status NTSTATUS code
                 * @param msg Error message
                 * @param ctx Operation context
                 */
                void SetNtStatus(LONG status, std::wstring_view msg, std::wstring_view ctx = L"") noexcept {
                    win32 = ERROR_SUCCESS;
                    ntstatus = status;
                    try {
                        message = msg;
                        context = ctx;
                    }
                    catch (...) {
                        // Allocation failure - keep codes, lose strings
                    }
                }
            };

            // ============================================================================
            // Symmetric Encryption Algorithms
            // ============================================================================

            /**
             * @brief Supported symmetric encryption algorithms
             *
             * All algorithms use Windows CNG implementations with hardware
             * acceleration where available (AES-NI, etc.).
             *
             * @note GCM modes are AEAD (Authenticated Encryption with Associated Data)
             *       and provide both confidentiality and integrity.
             */
            enum class SymmetricAlgorithm : uint8_t {
                AES_128_CBC = 0,   ///< AES-128 in CBC mode (requires padding)
                AES_192_CBC = 1,   ///< AES-192 in CBC mode (requires padding)
                AES_256_CBC = 2,   ///< AES-256 in CBC mode (requires padding)
                AES_128_GCM = 3,   ///< AES-128 in GCM mode (AEAD, recommended)
                AES_192_GCM = 4,   ///< AES-192 in GCM mode (AEAD)
                AES_256_GCM = 5,   ///< AES-256 in GCM mode (AEAD, most secure)
                AES_128_CFB = 6,   ///< AES-128 in CFB mode (stream cipher mode)
                AES_192_CFB = 7,   ///< AES-192 in CFB mode (stream cipher mode)
                AES_256_CFB = 8,   ///< AES-256 in CFB mode (stream cipher mode)
                ChaCha20_Poly1305 = 9  ///< ChaCha20-Poly1305 AEAD (modern, fast on non-AES-NI CPUs)
            };

            /**
             * @brief Padding modes for block cipher operations
             *
             * @note Only PKCS7 is recommended for production use.
             *       None should only be used when data is already block-aligned.
             */
            enum class PaddingMode : uint8_t {
                None = 0,   ///< No padding (data must be block-aligned)
                PKCS7 = 1   ///< PKCS#7 padding (RFC 5652, industry standard)
            };

            // ============================================================================
            // Asymmetric Encryption Algorithms
            // ============================================================================

            /**
             * @brief Supported asymmetric encryption algorithms
             *
             * RSA algorithms support both encryption and digital signatures.
             * ECC algorithms support ECDH key agreement and ECDSA signatures.
             *
             * @note RSA-2048 is minimum recommended for new applications.
             *       ECC P-256 provides equivalent security to RSA-3072.
             */
            enum class AsymmetricAlgorithm : uint8_t {
                RSA_2048 = 0,   ///< RSA with 2048-bit key (minimum recommended)
                RSA_3072 = 1,   ///< RSA with 3072-bit key (128-bit security)
                RSA_4096 = 2,   ///< RSA with 4096-bit key (high security)
                ECC_P256 = 3,   ///< NIST P-256 curve (secp256r1, 128-bit security)
                ECC_P384 = 4,   ///< NIST P-384 curve (secp384r1, 192-bit security)
                ECC_P521 = 5    ///< NIST P-521 curve (secp521r1, 256-bit security)
            };

            /**
             * @brief RSA padding schemes for encryption and signatures
             *
             * @note OAEP with SHA-256 or higher is recommended for encryption.
             *       PSS with SHA-256 or higher is recommended for signatures.
             *       PKCS1 is legacy and should be avoided for new applications.
             */
            enum class RSAPaddingScheme : uint8_t {
                PKCS1 = 0,       ///< RSAES-PKCS1-v1_5 (legacy, avoid for new code)
                OAEP_SHA1 = 1,   ///< RSAES-OAEP with SHA-1 (legacy)
                OAEP_SHA256 = 2, ///< RSAES-OAEP with SHA-256 (recommended)
                OAEP_SHA384 = 3, ///< RSAES-OAEP with SHA-384
                OAEP_SHA512 = 4, ///< RSAES-OAEP with SHA-512 (maximum security)
                PSS_SHA256 = 5,  ///< RSASSA-PSS with SHA-256 (for signatures)
                PSS_SHA384 = 6,  ///< RSASSA-PSS with SHA-384 (for signatures)
                PSS_SHA512 = 7   ///< RSASSA-PSS with SHA-512 (for signatures)
            };

            // ============================================================================
            // Key Derivation
            // ============================================================================

            /**
             * @brief Supported key derivation function algorithms
             *
             * @note PBKDF2-SHA256 with 100k+ iterations is OWASP recommended minimum.
             *       Argon2id is preferred for password hashing when available.
             *       HKDF is for key expansion, not password hashing.
             */
            enum class KDFAlgorithm : uint8_t {
                PBKDF2_SHA256 = 0,  ///< PBKDF2 with SHA-256 (recommended minimum)
                PBKDF2_SHA384 = 1,  ///< PBKDF2 with SHA-384
                PBKDF2_SHA512 = 2,  ///< PBKDF2 with SHA-512
                HKDF_SHA256 = 3,    ///< HKDF with SHA-256 (key expansion only)
                HKDF_SHA384 = 4,    ///< HKDF with SHA-384 (key expansion only)
                HKDF_SHA512 = 5,    ///< HKDF with SHA-512 (key expansion only)
                Scrypt = 6,         ///< scrypt (memory-hard, requires external lib)
                Argon2id = 7        ///< Argon2id (preferred, requires external lib)
            };

            /**
             * @brief Parameters for key derivation functions
             *
             * Contains all configuration needed for various KDF algorithms.
             * Some fields are algorithm-specific (e.g., memoryCostKB for Argon2).
             */
            struct KDFParams {
                KDFAlgorithm algorithm = KDFAlgorithm::PBKDF2_SHA256;  ///< Algorithm to use
                uint32_t iterations = MIN_PBKDF2_ITERATIONS;           ///< PBKDF2 iterations
                uint32_t memoryCostKB = 65536UL;   ///< Memory cost for Scrypt/Argon2 (64 MiB)
                uint32_t parallelism = 4UL;        ///< Thread parallelism for Argon2
                size_t keyLength = 32ULL;          ///< Output key length in bytes
                std::vector<uint8_t> salt;         ///< Salt (auto-generated if empty)
                std::vector<uint8_t> info;         ///< Context info for HKDF

                /**
                 * @brief Validate KDF parameters
                 * @return true if parameters are valid
                 */
                [[nodiscard]] bool IsValid() const noexcept {
                    // Key length validation
                    if (keyLength == 0 || keyLength > MAX_KEY_SIZE_BYTES * 4) {
                        return false;
                    }
                    // Iteration count validation for PBKDF2
                    if (algorithm == KDFAlgorithm::PBKDF2_SHA256 ||
                        algorithm == KDFAlgorithm::PBKDF2_SHA384 ||
                        algorithm == KDFAlgorithm::PBKDF2_SHA512) {
                        if (iterations < MIN_PBKDF2_ITERATIONS / 10) { // Allow some flexibility
                            return false;
                        }
                    }
                    // Memory cost validation for Argon2/Scrypt
                    if (algorithm == KDFAlgorithm::Argon2id || algorithm == KDFAlgorithm::Scrypt) {
                        if (memoryCostKB < 1024UL || parallelism == 0 || parallelism > 255) {
                            return false;
                        }
                    }
                    return true;
                }
            };

            // ============================================================================
            // Secure Random Number Generation
            // ============================================================================

            /**
             * @brief Cryptographically secure random number generator
             *
             * Uses Windows BCryptGenRandom with BCRYPT_RNG_ALG_HANDLE for
             * cryptographically secure pseudo-random number generation.
             *
             * @note This class is NOT thread-safe. Use separate instances per thread
             *       or external synchronization.
             *
             * @example
             * @code
             * SecureRandom rng;
             * std::vector<uint8_t> key;
             * if (rng.Generate(key, 32)) {
             *     // Use 256-bit key
             * }
             * @endcode
             */
            class SecureRandom {
            public:
                /**
                 * @brief Construct and initialize the RNG
                 * @note Initialization may fail silently; check Generate() return values
                 */
                SecureRandom() noexcept;

                /**
                 * @brief Destructor - releases CNG algorithm handle
                 */
                ~SecureRandom();

                // Non-copyable, non-movable (contains native handle)
                SecureRandom(const SecureRandom&) = delete;
                SecureRandom& operator=(const SecureRandom&) = delete;
                SecureRandom(SecureRandom&&) = delete;
                SecureRandom& operator=(SecureRandom&&) = delete;

                /**
                 * @brief Generate random bytes into a raw buffer
                 * @param buffer Output buffer (must be valid and sized >= size)
                 * @param size Number of bytes to generate
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool Generate(uint8_t* buffer, size_t size, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random bytes into a vector
                 * @param out Output vector (will be resized to size)
                 * @param size Number of bytes to generate
                 * @param err Optional error output
                 * @return true on success, false on failure
                 */
                [[nodiscard]] bool Generate(std::vector<uint8_t>& out, size_t size, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random bytes and return as vector
                 * @param size Number of bytes to generate
                 * @param err Optional error output
                 * @return Vector of random bytes (empty on failure)
                 */
                [[nodiscard]] std::vector<uint8_t> Generate(size_t size, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate a random 32-bit unsigned integer
                 * @param err Optional error output
                 * @return Random value (0 on failure)
                 */
                [[nodiscard]] uint32_t NextUInt32(Error* err = nullptr) noexcept;

                /**
                 * @brief Generate a random 64-bit unsigned integer
                 * @param err Optional error output
                 * @return Random value (0 on failure)
                 */
                [[nodiscard]] uint64_t NextUInt64(Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random integer in range [min, max)
                 * @param min Minimum value (inclusive)
                 * @param max Maximum value (exclusive)
                 * @param err Optional error output
                 * @return Random value in range, or min on failure
                 */
                [[nodiscard]] uint32_t NextUInt32(uint32_t min, uint32_t max, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random integer in range [min, max)
                 * @param min Minimum value (inclusive)
                 * @param max Maximum value (exclusive)
                 * @param err Optional error output
                 * @return Random value in range, or min on failure
                 */
                [[nodiscard]] uint64_t NextUInt64(uint64_t min, uint64_t max, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate a random alphanumeric string
                 * @param length Number of characters
                 * @param err Optional error output
                 * @return Random string (empty on failure)
                 */
                [[nodiscard]] std::string GenerateAlphanumeric(size_t length, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random bytes as hexadecimal string
                 * @param byteCount Number of bytes (string will be 2x this length)
                 * @param err Optional error output
                 * @return Hex string (empty on failure)
                 */
                [[nodiscard]] std::string GenerateHex(size_t byteCount, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate random bytes as Base64 string
                 * @param byteCount Number of bytes to generate
                 * @param err Optional error output
                 * @return Base64 string (empty on failure)
                 */
                [[nodiscard]] std::string GenerateBase64(size_t byteCount, Error* err = nullptr) noexcept;

                /**
                 * @brief Check if RNG is properly initialized
                 * @return true if initialized and ready
                 */
                [[nodiscard]] bool IsInitialized() const noexcept { return m_initialized; }

            private:
#ifdef _WIN32
                BCRYPT_ALG_HANDLE m_algHandle = nullptr;  ///< CNG algorithm handle
#endif
                bool m_initialized = false;  ///< Initialization status
            };

            // ============================================================================
            // Symmetric Encryption
            // ============================================================================

            /**
             * @brief Symmetric encryption cipher using Windows CNG
             *
             * Supports AES (CBC/GCM/CFB) and ChaCha20-Poly1305 algorithms.
             * Provides both one-shot and streaming encryption/decryption APIs.
             *
             * @note For AEAD modes (GCM, ChaCha20-Poly1305), use EncryptAEAD/DecryptAEAD.
             * @note This class is NOT thread-safe. Use separate instances per thread.
             *
             * @example One-shot encryption
             * @code
             * SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
             * std::vector<uint8_t> key, iv;
             * cipher.GenerateKey(key);
             * cipher.GenerateIV(iv);
             * std::vector<uint8_t> ciphertext, tag;
             * cipher.EncryptAEAD(plaintext, plaintextLen, nullptr, 0, ciphertext, tag);
             * @endcode
             */
            class SymmetricCipher {
            public:
                /**
                 * @brief Construct cipher with specified algorithm
                 * @param algorithm Symmetric algorithm to use
                 */
                explicit SymmetricCipher(SymmetricAlgorithm algorithm) noexcept;

                /**
                 * @brief Destructor - securely wipes key material
                 */
                ~SymmetricCipher();

                // Non-copyable
                SymmetricCipher(const SymmetricCipher&) = delete;
                SymmetricCipher& operator=(const SymmetricCipher&) = delete;

                // Movable
                SymmetricCipher(SymmetricCipher&& other) noexcept;
                SymmetricCipher& operator=(SymmetricCipher&& other) noexcept;

                // ========== Key Management ==========

                /**
                 * @brief Set encryption key from raw buffer
                 * @param key Key data (must match algorithm key size)
                 * @param keyLen Key length in bytes
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool SetKey(const uint8_t* key, size_t keyLen, Error* err = nullptr) noexcept;

                /**
                 * @brief Set encryption key from vector
                 * @param key Key data (must match algorithm key size)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool SetKey(const std::vector<uint8_t>& key, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate and set a new random key
                 * @param outKey Output vector to receive generated key
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool GenerateKey(std::vector<uint8_t>& outKey, Error* err = nullptr) noexcept;

                // ========== IV/Nonce Management ==========

                /**
                 * @brief Set IV/nonce from raw buffer
                 * @param iv IV data (must match algorithm IV size)
                 * @param ivLen IV length in bytes
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool SetIV(const uint8_t* iv, size_t ivLen, Error* err = nullptr) noexcept;

                /**
                 * @brief Set IV/nonce from vector
                 * @param iv IV data (must match algorithm IV size)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool SetIV(const std::vector<uint8_t>& iv, Error* err = nullptr) noexcept;

                /**
                 * @brief Generate and set a new random IV/nonce
                 * @param outIV Output vector to receive generated IV
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool GenerateIV(std::vector<uint8_t>& outIV, Error* err = nullptr) noexcept;

                /**
                 * @brief Set padding mode for block cipher operations
                 * @param mode Padding mode to use
                 * @note Only applies to non-AEAD modes (CBC, CFB)
                 */
                void SetPaddingMode(PaddingMode mode) noexcept { m_paddingMode = mode; }

                // ========== One-Shot Encryption (Non-AEAD) ==========

                /**
                 * @brief Encrypt data (non-AEAD modes only)
                 * @param plaintext Input data
                 * @param plaintextLen Input length
                 * @param ciphertext Output ciphertext
                 * @param err Optional error output
                 * @return true on success
                 * @note Use EncryptAEAD for GCM/ChaCha20-Poly1305
                 */
                [[nodiscard]] bool Encrypt(const uint8_t* plaintext, size_t plaintextLen,
                    std::vector<uint8_t>& ciphertext, Error* err = nullptr) noexcept;

                /**
                 * @brief Decrypt data (non-AEAD modes only)
                 * @param ciphertext Input ciphertext
                 * @param ciphertextLen Input length
                 * @param plaintext Output plaintext
                 * @param err Optional error output
                 * @return true on success
                 * @note Use DecryptAEAD for GCM/ChaCha20-Poly1305
                 */
                [[nodiscard]] bool Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
                    std::vector<uint8_t>& plaintext, Error* err = nullptr) noexcept;

                // ========== AEAD Encryption (GCM, ChaCha20-Poly1305) ==========

                /**
                 * @brief Encrypt with authentication (AEAD modes)
                 * @param plaintext Input data (may be nullptr if plaintextLen is 0)
                 * @param plaintextLen Input length
                 * @param aad Additional authenticated data (may be nullptr)
                 * @param aadLen AAD length
                 * @param ciphertext Output ciphertext
                 * @param tag Output authentication tag
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool EncryptAEAD(const uint8_t* plaintext, size_t plaintextLen,
                    const uint8_t* aad, size_t aadLen,
                    std::vector<uint8_t>& ciphertext,
                    std::vector<uint8_t>& tag, Error* err = nullptr) noexcept;

                /**
                 * @brief Decrypt with authentication verification (AEAD modes)
                 * @param ciphertext Input ciphertext
                 * @param ciphertextLen Input length
                 * @param aad Additional authenticated data (must match encryption)
                 * @param aadLen AAD length
                 * @param tag Authentication tag to verify
                 * @param tagLen Tag length
                 * @param plaintext Output plaintext
                 * @param err Optional error output
                 * @return true on success, false on authentication failure
                 */
                [[nodiscard]] bool DecryptAEAD(const uint8_t* ciphertext, size_t ciphertextLen,
                    const uint8_t* aad, size_t aadLen,
                    const uint8_t* tag, size_t tagLen,
                    std::vector<uint8_t>& plaintext, Error* err = nullptr) noexcept;

                // ========== Streaming Encryption ==========

                /**
                 * @brief Initialize streaming encryption
                 * @param err Optional error output
                 * @return true on success
                 * @note Not supported for AEAD modes
                 */
                [[nodiscard]] bool EncryptInit(Error* err = nullptr) noexcept;

                /**
                 * @brief Process encryption data chunk
                 * @param data Input data chunk
                 * @param len Input length
                 * @param out Output ciphertext (may be less than input due to block alignment)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool EncryptUpdate(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

                /**
                 * @brief Finalize streaming encryption
                 * @param out Final ciphertext block (includes padding)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool EncryptFinal(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

                // ========== Streaming Decryption ==========

                /**
                 * @brief Initialize streaming decryption
                 * @param err Optional error output
                 * @return true on success
                 * @note Not supported for AEAD modes
                 */
                [[nodiscard]] bool DecryptInit(Error* err = nullptr) noexcept;

                /**
                 * @brief Process decryption data chunk
                 * @param data Input ciphertext chunk
                 * @param len Input length
                 * @param out Output plaintext (may be less than input due to block alignment)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool DecryptUpdate(const uint8_t* data, size_t len,
                    std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

                /**
                 * @brief Finalize streaming decryption
                 * @param out Final plaintext block (padding removed)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool DecryptFinal(std::vector<uint8_t>& out, Error* err = nullptr) noexcept;

                // ========== Properties ==========

                /** @brief Get required key size in bytes */
                [[nodiscard]] size_t GetKeySize() const noexcept;

                /** @brief Get required IV/nonce size in bytes */
                [[nodiscard]] size_t GetIVSize() const noexcept;

                /** @brief Get cipher block size in bytes */
                [[nodiscard]] size_t GetBlockSize() const noexcept;

                /** @brief Get authentication tag size (0 for non-AEAD) */
                [[nodiscard]] size_t GetTagSize() const noexcept;

                /** @brief Check if algorithm is AEAD */
                [[nodiscard]] bool IsAEAD() const noexcept;

                /** @brief Get current algorithm */
                [[nodiscard]] SymmetricAlgorithm GetAlgorithm() const noexcept { return m_algorithm; }

                /** @brief Check if key has been set */
                [[nodiscard]] bool HasKey() const noexcept { return m_keySet; }

                /** @brief Check if IV has been set */
                [[nodiscard]] bool HasIV() const noexcept { return m_ivSet; }

            private:
                std::vector<uint8_t> m_streamBuffer;   ///< Internal buffer for streaming
                bool m_streamFinalized = false;        ///< Stream finalization flag
                SymmetricAlgorithm m_algorithm;        ///< Selected algorithm
                PaddingMode m_paddingMode = PaddingMode::PKCS7;  ///< Padding mode

#ifdef _WIN32
                BCRYPT_ALG_HANDLE m_algHandle = nullptr;   ///< CNG algorithm handle
                BCRYPT_KEY_HANDLE m_keyHandle = nullptr;   ///< CNG key handle
                std::vector<uint8_t> m_keyObject;          ///< Key object buffer
#endif
                std::vector<uint8_t> m_key;  ///< Key material (secure wiped on cleanup)
                std::vector<uint8_t> m_iv;   ///< IV/nonce (secure wiped on cleanup)
                bool m_keySet = false;       ///< Key set flag
                bool m_ivSet = false;        ///< IV set flag

                /** @brief Ensure CNG provider is initialized */
                [[nodiscard]] bool ensureProvider(Error* err) noexcept;

                /** @brief Clean up resources and wipe key material */
                void cleanup() noexcept;

                /** @brief Apply PKCS7 padding to data */
                [[nodiscard]] bool applyPadding(std::vector<uint8_t>& data, size_t blockSize) noexcept;

                /** @brief Remove and validate PKCS7 padding */
                [[nodiscard]] bool removePadding(std::vector<uint8_t>& data, size_t blockSize) noexcept;
            };

            // ============================================================================
            // Asymmetric Encryption (RSA/ECC)
            // ============================================================================

            /**
             * @brief Public key container for asymmetric operations
             *
             * Contains algorithm information and the raw key blob in Windows CNG format.
             * Supports PEM import/export for interoperability.
             */
            struct PublicKey {
                AsymmetricAlgorithm algorithm = AsymmetricAlgorithm::RSA_2048;  ///< Key algorithm
                std::vector<uint8_t> keyBlob;  ///< CNG key blob

                /**
                 * @brief Export key as raw binary
                 * @param out Output buffer
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;

                /**
                 * @brief Export key as PEM-encoded string
                 * @param out Output string
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool ExportPEM(std::string& out, Error* err = nullptr) const noexcept;

                /**
                 * @brief Import key from raw binary
                 * @param data Key data
                 * @param len Data length
                 * @param out Output key structure
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool Import(const uint8_t* data, size_t len,
                    PublicKey& out, Error* err = nullptr) noexcept;

                /**
                 * @brief Import key from PEM-encoded string
                 * @param pem PEM string
                 * @param out Output key structure
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool ImportPEM(std::string_view pem,
                    PublicKey& out, Error* err = nullptr) noexcept;

                /**
                 * @brief Check if key blob is non-empty
                 * @return true if key data is present
                 */
                [[nodiscard]] bool IsValid() const noexcept { return !keyBlob.empty(); }
            };

            /**
             * @brief Private key container for asymmetric operations
             *
             * Contains algorithm information and the raw key blob in Windows CNG format.
             * Supports PEM import/export with optional password encryption.
             *
             * @note Destructor automatically securely erases key material.
             */
            struct PrivateKey {
                AsymmetricAlgorithm algorithm = AsymmetricAlgorithm::RSA_2048;  ///< Key algorithm
                std::vector<uint8_t> keyBlob;  ///< CNG key blob (securely erased on destruction)

                /**
                 * @brief Export key as raw binary
                 * @param out Output buffer
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool Export(std::vector<uint8_t>& out, Error* err = nullptr) const noexcept;

                /**
                 * @brief Export key as PEM-encoded string
                 * @param out Output string
                 * @param encrypt Whether to encrypt the PEM
                 * @param password Password for encryption (required if encrypt=true)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool ExportPEM(std::string& out, bool encrypt = false,
                    std::string_view password = "", Error* err = nullptr) const noexcept;

                /**
                 * @brief Import key from raw binary
                 * @param data Key data
                 * @param len Data length
                 * @param out Output key structure
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool Import(const uint8_t* data, size_t len,
                    PrivateKey& out, Error* err = nullptr) noexcept;

                /**
                 * @brief Import key from PEM-encoded string
                 * @param pem PEM string
                 * @param out Output key structure
                 * @param password Password for decryption (if encrypted)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool ImportPEM(std::string_view pem, PrivateKey& out,
                    std::string_view password = "", Error* err = nullptr) noexcept;

                /**
                 * @brief Securely erase key material
                 * @note Called automatically by destructor
                 */
                void SecureErase() noexcept;

                /**
                 * @brief Check if key blob is non-empty
                 * @return true if key data is present
                 */
                [[nodiscard]] bool IsValid() const noexcept { return !keyBlob.empty(); }

                /**
                 * @brief Destructor - securely erases key material
                 */
                ~PrivateKey() { SecureErase(); }

                // Default constructor
                PrivateKey() = default;

                // Move operations (key material moves, source is cleared)
                PrivateKey(PrivateKey&& other) noexcept
                    : algorithm(other.algorithm), keyBlob(std::move(other.keyBlob)) {
                    other.algorithm = AsymmetricAlgorithm::RSA_2048;
                }

                PrivateKey& operator=(PrivateKey&& other) noexcept {
                    if (this != &other) {
                        SecureErase();
                        algorithm = other.algorithm;
                        keyBlob = std::move(other.keyBlob);
                        other.algorithm = AsymmetricAlgorithm::RSA_2048;
                    }
                    return *this;
                }

                // Non-copyable for security
                PrivateKey(const PrivateKey&) = delete;
                PrivateKey& operator=(const PrivateKey&) = delete;
            };

            /**
             * @brief Public/private key pair container
             */
            struct KeyPair {
                PublicKey publicKey;   ///< Public key
                PrivateKey privateKey; ///< Private key (securely erased on destruction)

                /**
                 * @brief Check if both keys are valid
                 * @return true if both keys have data
                 */
                [[nodiscard]] bool IsValid() const noexcept {
                    return publicKey.IsValid() && privateKey.IsValid();
                }
            };

            /**
             * @brief Asymmetric encryption cipher using Windows CNG
             *
             * Supports RSA encryption/decryption/signing and ECC key agreement/signing.
             * Provides various padding schemes including OAEP and PSS.
             *
             * @note This class is NOT thread-safe. Use separate instances per thread.
             */
            class AsymmetricCipher {
            public:
                /**
                 * @brief Construct cipher with specified algorithm
                 * @param algorithm Asymmetric algorithm to use
                 */
                explicit AsymmetricCipher(AsymmetricAlgorithm algorithm) noexcept;

                /**
                 * @brief Destructor - releases key handles
                 */
                ~AsymmetricCipher();

                // Non-copyable, non-movable (contains native handles)
                AsymmetricCipher(const AsymmetricCipher&) = delete;
                AsymmetricCipher& operator=(const AsymmetricCipher&) = delete;
                AsymmetricCipher(AsymmetricCipher&&) = delete;
                AsymmetricCipher& operator=(AsymmetricCipher&&) = delete;

                // ========== Key Generation ==========

                /**
                 * @brief Generate a new key pair
                 * @param outKeyPair Output key pair
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool GenerateKeyPair(KeyPair& outKeyPair, Error* err = nullptr) noexcept;

                // ========== Key Loading ==========

                /**
                 * @brief Load a public key for encryption/verification
                 * @param key Public key to load
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool LoadPublicKey(const PublicKey& key, Error* err = nullptr) noexcept;

                /**
                 * @brief Load a private key for decryption/signing
                 * @param key Private key to load
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool LoadPrivateKey(const PrivateKey& key, Error* err = nullptr) noexcept;

                // ========== RSA Encryption/Decryption ==========

                /**
                 * @brief Encrypt data with public key (RSA only)
                 * @param plaintext Input data
                 * @param plaintextLen Input length (must be <= GetMaxPlaintextSize)
                 * @param ciphertext Output ciphertext
                 * @param padding RSA padding scheme
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool Encrypt(const uint8_t* plaintext, size_t plaintextLen,
                    std::vector<uint8_t>& ciphertext,
                    RSAPaddingScheme padding = RSAPaddingScheme::OAEP_SHA256,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Decrypt data with private key (RSA only)
                 * @param ciphertext Input ciphertext
                 * @param ciphertextLen Input length
                 * @param plaintext Output plaintext
                 * @param padding RSA padding scheme (must match encryption)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
                    std::vector<uint8_t>& plaintext,
                    RSAPaddingScheme padding = RSAPaddingScheme::OAEP_SHA256,
                    Error* err = nullptr) noexcept;

                // ========== Digital Signatures ==========

                /**
                 * @brief Sign data with private key
                 * @param data Data to sign
                 * @param dataLen Data length
                 * @param signature Output signature
                 * @param hashAlg Hash algorithm for signature
                 * @param padding RSA padding scheme (PSS recommended)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool Sign(const uint8_t* data, size_t dataLen,
                    std::vector<uint8_t>& signature,
                    HashUtils::Algorithm hashAlg = HashUtils::Algorithm::SHA256,
                    RSAPaddingScheme padding = RSAPaddingScheme::PSS_SHA256,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Verify signature with public key
                 * @param data Original data
                 * @param dataLen Data length
                 * @param signature Signature to verify
                 * @param signatureLen Signature length
                 * @param hashAlg Hash algorithm (must match signing)
                 * @param padding RSA padding scheme (must match signing)
                 * @param err Optional error output
                 * @return true if signature is valid
                 */
                [[nodiscard]] bool Verify(const uint8_t* data, size_t dataLen,
                    const uint8_t* signature, size_t signatureLen,
                    HashUtils::Algorithm hashAlg = HashUtils::Algorithm::SHA256,
                    RSAPaddingScheme padding = RSAPaddingScheme::PSS_SHA256,
                    Error* err = nullptr) noexcept;

                // ========== ECDH Key Agreement ==========

                /**
                 * @brief Derive shared secret using ECDH (ECC only)
                 * @param peerPublicKey Peer's public key
                 * @param sharedSecret Output shared secret
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] bool DeriveSharedSecret(const PublicKey& peerPublicKey,
                    std::vector<uint8_t>& sharedSecret,
                    Error* err = nullptr) noexcept;

                // ========== Properties ==========

                /**
                 * @brief Get maximum plaintext size for RSA encryption
                 * @param padding Padding scheme to use
                 * @return Maximum bytes that can be encrypted
                 */
                [[nodiscard]] size_t GetMaxPlaintextSize(RSAPaddingScheme padding) const noexcept;

                /**
                 * @brief Get signature size in bytes
                 * @return Signature size for current algorithm
                 */
                [[nodiscard]] size_t GetSignatureSize() const noexcept;

                /** @brief Get current algorithm */
                [[nodiscard]] AsymmetricAlgorithm GetAlgorithm() const noexcept { return m_algorithm; }

                /** @brief Check if public key is loaded */
                [[nodiscard]] bool HasPublicKey() const noexcept { return m_publicKeyLoaded; }

                /** @brief Check if private key is loaded */
                [[nodiscard]] bool HasPrivateKey() const noexcept { return m_privateKeyLoaded; }

            private:
                AsymmetricAlgorithm m_algorithm;  ///< Selected algorithm

#ifdef _WIN32
                BCRYPT_ALG_HANDLE m_algHandle = nullptr;        ///< CNG algorithm handle
                BCRYPT_KEY_HANDLE m_publicKeyHandle = nullptr;  ///< CNG public key handle
                BCRYPT_KEY_HANDLE m_privateKeyHandle = nullptr; ///< CNG private key handle
#endif
                bool m_publicKeyLoaded = false;   ///< Public key loaded flag
                bool m_privateKeyLoaded = false;  ///< Private key loaded flag

                /** @brief Ensure CNG provider is initialized */
                [[nodiscard]] bool ensureProvider(Error* err) noexcept;

                /** @brief Clean up resources */
                void cleanup() noexcept;
            };

            // ============================================================================
            // Key Derivation Functions
            // ============================================================================

            /**
             * @brief Key derivation function implementations
             *
             * Provides PBKDF2 and HKDF implementations using Windows CNG.
             * All methods are static and thread-safe.
             *
             * @note Scrypt and Argon2id require external libraries and return
             *       "not implemented" errors when called.
             */
            class KeyDerivation {
            public:
                // Non-instantiable (static-only class)
                KeyDerivation() = delete;

                /**
                 * @brief Derive key using PBKDF2
                 * @param password Password bytes
                 * @param passwordLen Password length
                 * @param salt Salt bytes (minimum 16 bytes recommended)
                 * @param saltLen Salt length
                 * @param iterations Iteration count (minimum 100,000 recommended)
                 * @param hashAlg Hash algorithm to use
                 * @param outKey Output key buffer
                 * @param keyLen Desired key length
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool PBKDF2(const uint8_t* password, size_t passwordLen,
                    const uint8_t* salt, size_t saltLen,
                    uint32_t iterations,
                    HashUtils::Algorithm hashAlg,
                    uint8_t* outKey, size_t keyLen,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Derive key using HKDF (Extract and Expand)
                 * @param inputKeyMaterial Input key material
                 * @param ikmLen IKM length
                 * @param salt Salt bytes (optional, can be nullptr)
                 * @param saltLen Salt length (0 if salt is nullptr)
                 * @param info Context info bytes (optional)
                 * @param infoLen Info length (0 if info is nullptr)
                 * @param hashAlg Hash algorithm to use
                 * @param outKey Output key buffer
                 * @param keyLen Desired key length
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool HKDF(const uint8_t* inputKeyMaterial, size_t ikmLen,
                    const uint8_t* salt, size_t saltLen,
                    const uint8_t* info, size_t infoLen,
                    HashUtils::Algorithm hashAlg,
                    uint8_t* outKey, size_t keyLen,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Generic key derivation with parameters
                 * @param password Password bytes
                 * @param passwordLen Password length
                 * @param params KDF parameters
                 * @param outKey Output key vector
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool DeriveKey(const uint8_t* password, size_t passwordLen,
                    const KDFParams& params,
                    std::vector<uint8_t>& outKey,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Generic key derivation with string password
                 * @param password Password string
                 * @param params KDF parameters
                 * @param outKey Output key vector
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool DeriveKey(std::string_view password,
                    const KDFParams& params,
                    std::vector<uint8_t>& outKey,
                    Error* err = nullptr) noexcept;

                /**
                 * @brief Generate cryptographically secure random salt
                 * @param salt Output salt vector
                 * @param size Salt size in bytes (default 32)
                 * @param err Optional error output
                 * @return true on success
                 */
                [[nodiscard]] static bool GenerateSalt(std::vector<uint8_t>& salt,
                    size_t size = DEFAULT_SALT_SIZE_BYTES,
                    Error* err = nullptr) noexcept;
            };

            // ============================================================================
            // Secure Memory Management
            // ============================================================================

            /**
             * @brief Secure buffer with automatic memory wiping
             *
             * Provides a buffer that automatically wipes its contents when
             * destroyed or reallocated. Uses SecureZeroMemory on Windows
             * to prevent compiler optimization from removing the wipe.
             *
             * @tparam T Element type (must be trivially copyable)
             *
             * @note This buffer is NOT thread-safe.
             */
            template<typename T>
            class SecureBuffer {
                static_assert(std::is_trivially_copyable_v<T>,
                    "SecureBuffer requires trivially copyable type");

            public:
                /**
                 * @brief Construct buffer with optional initial size
                 * @param size Initial element count (default 0)
                 */
                explicit SecureBuffer(size_t size = 0);

                /**
                 * @brief Destructor - securely wipes and deallocates
                 */
                ~SecureBuffer();

                // Non-copyable for security
                SecureBuffer(const SecureBuffer&) = delete;
                SecureBuffer& operator=(const SecureBuffer&) = delete;

                // Movable (source is zeroed)
                SecureBuffer(SecureBuffer&& other) noexcept;
                SecureBuffer& operator=(SecureBuffer&& other) noexcept;

                /**
                 * @brief Resize buffer (wipes old data if shrinking)
                 * @param newSize New element count
                 * @throws std::bad_alloc on allocation failure
                 */
                void Resize(size_t newSize);

                /**
                 * @brief Clear and deallocate buffer
                 */
                void Clear();

                /** @brief Get mutable data pointer */
                [[nodiscard]] T* Data() noexcept { return m_data; }

                /** @brief Get const data pointer */
                [[nodiscard]] const T* Data() const noexcept { return m_data; }

                /** @brief Get element count */
                [[nodiscard]] size_t Size() const noexcept { return m_size; }

                /** @brief Check if empty */
                [[nodiscard]] bool Empty() const noexcept { return m_size == 0; }

                /**
                 * @brief Access element by index (no bounds checking)
                 * @param index Element index
                 * @return Reference to element
                 */
                [[nodiscard]] T& operator[](size_t index) noexcept {
                    return m_data[index];
                }

                /**
                 * @brief Access element by index (no bounds checking)
                 * @param index Element index
                 * @return Const reference to element
                 */
                [[nodiscard]] const T& operator[](size_t index) const noexcept {
                    return m_data[index];
                }

                /**
                 * @brief Copy data into buffer
                 * @param src Source data
                 * @param count Element count
                 */
                void CopyFrom(const T* src, size_t count);

                /**
                 * @brief Copy data from vector
                 * @param src Source vector
                 */
                void CopyFrom(const std::vector<T>& src);

            private:
                T* m_data = nullptr;   ///< Data pointer
                size_t m_size = 0;     ///< Element count

                /** @brief Allocate buffer */
                void allocate(size_t size);

                /** @brief Securely deallocate buffer */
                void deallocate();
            };

            /** @brief Secure byte buffer type alias */
            using SecureByteBuffer = SecureBuffer<uint8_t>;

            /**
             * @brief Secure string container for sensitive data like passwords
             *
             * Automatically wipes string contents when destroyed or modified.
             * Internally uses SecureBuffer<char> for secure memory handling.
             *
             * @note Supports both narrow (char) and wide (wchar_t) string input,
             *       but stores internally as UTF-8 (narrow) characters.
             */
            class SecureString {
            public:
                /** @brief Default constructor - empty string */
                SecureString() = default;

                /**
                 * @brief Construct from narrow string
                 * @param str String to copy
                 */
                explicit SecureString(std::string_view str);

                /**
                 * @brief Construct from wide string (converts to UTF-8)
                 * @param str Wide string to convert and copy
                 */
                explicit SecureString(std::wstring_view str);

                /**
                 * @brief Destructor - securely wipes contents
                 */
                ~SecureString();

                // Non-copyable for security
                SecureString(const SecureString&) = delete;
                SecureString& operator=(const SecureString&) = delete;

                // Movable (source is cleared)
                SecureString(SecureString&& other) noexcept;
                SecureString& operator=(SecureString&& other) noexcept;

                /**
                 * @brief Assign from narrow string
                 * @param str String to copy
                 */
                void Assign(std::string_view str);

                /**
                 * @brief Assign from wide string (converts to UTF-8)
                 * @param str Wide string to convert and copy
                 */
                void Assign(std::wstring_view str);

                /**
                 * @brief Clear and wipe contents
                 */
                void Clear();

                /** @brief Get data pointer */
                [[nodiscard]] const char* Data() const noexcept { return m_buffer.Data(); }

                /** @brief Get string length in bytes */
                [[nodiscard]] size_t Size() const noexcept { return m_buffer.Size(); }

                /** @brief Check if empty */
                [[nodiscard]] bool Empty() const noexcept { return m_buffer.Empty(); }

                /**
                 * @brief Get as string_view
                 * @return View of the string data
                 * @note The view is valid only while SecureString is alive
                 */
                [[nodiscard]] std::string_view ToStringView() const noexcept;

            private:
                SecureBuffer<char> m_buffer;  ///< Internal secure storage
            };

            // ============================================================================
            // High-Level Encryption/Decryption Functions
            // ============================================================================

            /**
             * @brief Encrypt file using AES-256-GCM
             * @param inputPath Source file path
             * @param outputPath Destination file path
             * @param key 32-byte encryption key
             * @param keyLen Key length (must be 32)
             * @param err Optional error output
             * @return true on success
             * @note Output format: [12-byte nonce][ciphertext][16-byte tag]
             */
            [[nodiscard]] bool EncryptFile(std::wstring_view inputPath,
                std::wstring_view outputPath,
                const uint8_t* key, size_t keyLen,
                Error* err = nullptr) noexcept;

            /**
             * @brief Decrypt file encrypted with EncryptFile
             * @param inputPath Encrypted file path
             * @param outputPath Destination file path
             * @param key 32-byte decryption key
             * @param keyLen Key length (must be 32)
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] bool DecryptFile(std::wstring_view inputPath,
                std::wstring_view outputPath,
                const uint8_t* key, size_t keyLen,
                Error* err = nullptr) noexcept;

            /**
             * @brief Encrypt file with password (PBKDF2 + AES-256-GCM)
             * @param inputPath Source file path
             * @param outputPath Destination file path
             * @param password Encryption password
             * @param err Optional error output
             * @return true on success
             * @note Output format: [32-byte salt][12-byte nonce][ciphertext][16-byte tag]
             */
            [[nodiscard]] bool EncryptFileWithPassword(std::wstring_view inputPath,
                std::wstring_view outputPath,
                std::string_view password,
                Error* err = nullptr) noexcept;

            /**
             * @brief Decrypt file encrypted with EncryptFileWithPassword
             * @param inputPath Encrypted file path
             * @param outputPath Destination file path
             * @param password Decryption password
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] bool DecryptFileWithPassword(std::wstring_view inputPath,
                std::wstring_view outputPath,
                std::string_view password,
                Error* err = nullptr) noexcept;

            /**
             * @brief Encrypt string and return as Base64
             * @param plaintext Input string
             * @param key 32-byte encryption key
             * @param keyLen Key length (must be 32)
             * @param outBase64Ciphertext Output Base64-encoded ciphertext
             * @param err Optional error output
             * @return true on success
             * @note Output contains nonce + ciphertext + tag, all Base64 encoded
             */
            [[nodiscard]] bool EncryptString(std::string_view plaintext,
                const uint8_t* key, size_t keyLen,
                std::string& outBase64Ciphertext,
                Error* err = nullptr) noexcept;

            /**
             * @brief Decrypt Base64-encoded ciphertext
             * @param base64Ciphertext Input Base64-encoded ciphertext
             * @param key 32-byte decryption key
             * @param keyLen Key length (must be 32)
             * @param outPlaintext Output plaintext string
             * @param err Optional error output
             * @return true on success
             */
            [[nodiscard]] bool DecryptString(std::string_view base64Ciphertext,
                const uint8_t* key, size_t keyLen,
                std::string& outPlaintext,
                Error* err = nullptr) noexcept;


            // ============================================================================
            // Base64 Encoding/Decoding
            // ============================================================================

            /**
             * @brief Base64 encoding/decoding utilities
             *
             * Delegates to Base64Utils for actual implementation.
             * Provided here for convenience within CryptoUtils namespace.
             */
            namespace Base64 {
                /**
                 * @brief Encode raw data as Base64 string
                 * @param data Input data
                 * @param len Data length
                 * @return Base64-encoded string (empty on failure)
                 */
                [[nodiscard]] std::string Encode(const uint8_t* data, size_t len) noexcept;

                /**
                 * @brief Encode vector as Base64 string
                 * @param data Input data
                 * @return Base64-encoded string (empty on failure)
                 */
                [[nodiscard]] std::string Encode(const std::vector<uint8_t>& data) noexcept;

                /**
                 * @brief Decode Base64 string to bytes
                 * @param base64 Input Base64 string
                 * @param out Output byte vector
                 * @return true on success
                 */
                [[nodiscard]] bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept;
            }

            // ============================================================================
            // Secure Comparison (timing-attack resistant)
            // ============================================================================

            /**
             * @brief Compare two buffers in constant time
             *
             * Prevents timing attacks by ensuring comparison takes the same
             * time regardless of where differences occur.
             *
             * @param a First buffer
             * @param b Second buffer
             * @param len Length to compare
             * @return true if buffers are equal
             * @note Returns false if either pointer is null (unless len is 0)
             */
            [[nodiscard]] bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept;

            /**
             * @brief Compare two vectors in constant time
             * @param a First vector
             * @param b Second vector
             * @return true if vectors are equal (size and content)
             */
            [[nodiscard]] bool SecureCompare(const std::vector<uint8_t>& a,
                const std::vector<uint8_t>& b) noexcept;

            // ============================================================================
            // Secure Memory Wipe
            // ============================================================================

            /**
             * @brief Securely wipe memory contents
             *
             * Uses platform-specific secure wipe functions that cannot be
             * optimized away by the compiler.
             *
             * @param ptr Memory to wipe
             * @param size Number of bytes to wipe
             * @note Safe to call with nullptr (no-op)
             */
            void SecureZeroMemory(void* ptr, size_t size) noexcept;

        } // namespace CryptoUtils
    } // namespace Utils
} // namespace ShadowStrike
