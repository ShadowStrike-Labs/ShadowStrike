/**
 * @file CryptoUtils.cpp
 * @brief Enterprise-grade cryptographic utilities implementation
 *
 * Implements symmetric/asymmetric encryption, secure random generation,
 * key derivation, and secure memory handling using Windows CNG APIs.
 *
 * @copyright Copyright (c) 2025 ShadowStrike Security Suite
 * @license MIT License
 */

#include "CryptoUtils.hpp"
#include "Base64Utils.hpp"
#include "HashUtils.hpp"
#include "FileUtils.hpp"
#include "Logger.hpp"

// ============================================================================
// Standard Library Headers
// ============================================================================
#include <sstream>
#include <cmath>
#include <limits>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <vector>
#include <memory>
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

#  ifndef CERT_KEY_CERT_SIGN_KEY_USAGE
#    define CERT_KEY_CERT_SIGN_KEY_USAGE 0x04  // Bit 5 (keyCertSign)
#  endif

#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0A00
#  endif

#  include <Windows.h>
#  include <wincrypt.h>
#  include <wintrust.h>
#  include <softpub.h>
#  include <bcrypt.h>
#  include <ncrypt.h>
#  include <mscat.h>
#  include <ntstatus.h>

#  pragma comment(lib, "crypt32.lib")
#  pragma comment(lib, "wintrust.lib")
#  pragma comment(lib, "bcrypt.lib")
#  pragma comment(lib, "ncrypt.lib")
#endif

namespace ShadowStrike {
    namespace Utils {
        namespace CryptoUtils {

            // =============================================================================
            // Internal Constants
            // =============================================================================

            /// Maximum iterations for rejection sampling to prevent infinite loops
            static constexpr uint32_t MAX_REJECTION_ITERATIONS = 1000UL;

            /// Log category for crypto operations
            static constexpr const wchar_t* LOG_CATEGORY = L"CryptoUtils";

            // =============================================================================
            // Helper Functions - Algorithm Mapping
            // =============================================================================

            /**
             * @brief Get CNG algorithm identifier for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return CNG algorithm name or nullptr if invalid
             */
            static const wchar_t* AlgName(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return BCRYPT_AES_ALGORITHM;
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return L"ChaCha20-Poly1305";
                default:
                    return nullptr;
                }
            }

            /**
             * @brief Get CNG chaining mode for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return CNG chaining mode or nullptr if not applicable
             */
            static const wchar_t* ChainingMode(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                    return BCRYPT_CHAIN_MODE_CBC;
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                    return BCRYPT_CHAIN_MODE_GCM;
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return BCRYPT_CHAIN_MODE_CFB;
                default:
                    return nullptr;
                }
            }

            /**
             * @brief Get key size in bytes for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return Key size in bytes, 0 if invalid
             */
            static size_t KeySizeForAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_128_CFB:
                    return 16ULL;  // 128 bits
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_192_CFB:
                    return 24ULL;  // 192 bits
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::AES_256_CFB:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return 32ULL;  // 256 bits
                default:
                    return 0ULL;
                }
            }

            /**
             * @brief Get IV/nonce size in bytes for symmetric algorithm
             * @param alg Symmetric algorithm enum
             * @return IV size in bytes, 0 if invalid
             */
            static size_t IVSizeForAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return GCM_NONCE_SIZE_BYTES;  // 12 bytes (96-bit nonce)
                case SymmetricAlgorithm::AES_128_CBC:
                case SymmetricAlgorithm::AES_192_CBC:
                case SymmetricAlgorithm::AES_256_CBC:
                case SymmetricAlgorithm::AES_128_CFB:
                case SymmetricAlgorithm::AES_192_CFB:
                case SymmetricAlgorithm::AES_256_CFB:
                    return AES_BLOCK_SIZE_BYTES;  // 16 bytes
                default:
                    return 0ULL;
                }
            }

            /**
             * @brief Check if algorithm is an AEAD mode
             * @param alg Symmetric algorithm enum
             * @return true if AEAD (provides authenticated encryption)
             */
            static bool IsAEADAlg(SymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case SymmetricAlgorithm::AES_128_GCM:
                case SymmetricAlgorithm::AES_192_GCM:
                case SymmetricAlgorithm::AES_256_GCM:
                case SymmetricAlgorithm::ChaCha20_Poly1305:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Get CNG algorithm identifier for asymmetric algorithm
             * @param alg Asymmetric algorithm enum
             * @return CNG algorithm name or nullptr if invalid
             */
            static const wchar_t* RSAAlgName(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048:
                case AsymmetricAlgorithm::RSA_3072:
                case AsymmetricAlgorithm::RSA_4096:
                    return BCRYPT_RSA_ALGORITHM;
                case AsymmetricAlgorithm::ECC_P256:
                    return BCRYPT_ECDH_P256_ALGORITHM;
                case AsymmetricAlgorithm::ECC_P384:
                    return BCRYPT_ECDH_P384_ALGORITHM;
                case AsymmetricAlgorithm::ECC_P521:
                    return BCRYPT_ECDH_P521_ALGORITHM;
                default:
                    return nullptr;
                }
            }

            /**
             * @brief Get key size in bits for asymmetric algorithm
             * @param alg Asymmetric algorithm enum
             * @return Key size in bits, 0 if invalid
             */
            static ULONG RSAKeySizeForAlg(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048: return 2048UL;
                case AsymmetricAlgorithm::RSA_3072: return 3072UL;
                case AsymmetricAlgorithm::RSA_4096: return 4096UL;
                case AsymmetricAlgorithm::ECC_P256: return 256UL;
                case AsymmetricAlgorithm::ECC_P384: return 384UL;
                case AsymmetricAlgorithm::ECC_P521: return 521UL;
                default: return 0UL;
                }
            }

            /**
             * @brief Check if algorithm is RSA-based
             * @param alg Asymmetric algorithm enum
             * @return true if RSA algorithm
             */
            [[maybe_unused]] static bool IsRSAAlgorithm(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::RSA_2048:
                case AsymmetricAlgorithm::RSA_3072:
                case AsymmetricAlgorithm::RSA_4096:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Check if algorithm is ECC-based
             * @param alg Asymmetric algorithm enum
             * @return true if ECC algorithm
             */
            [[maybe_unused]] static bool IsECCAlgorithm(AsymmetricAlgorithm alg) noexcept {
                switch (alg) {
                case AsymmetricAlgorithm::ECC_P256:
                case AsymmetricAlgorithm::ECC_P384:
                case AsymmetricAlgorithm::ECC_P521:
                    return true;
                default:
                    return false;
                }
            }

            /**
             * @brief Safe logging helper - logs to debug output if Logger not initialized
             * @param msg Message to log
             */
            static void SafeLogError(const wchar_t* msg) noexcept {
                if (msg == nullptr) return;
                
                try {
                    if (Logger::Instance().IsInitialized()) {
                        SS_LOG_ERROR(LOG_CATEGORY, L"%s", msg);
                    }
                    else {
                        OutputDebugStringW(L"[CryptoUtils] ");
                        OutputDebugStringW(msg);
                        OutputDebugStringW(L"\n");
                    }
                }
                catch (...) {
                    // Logging should never throw - silently ignore
                }
            }

            /**
             * @brief Safe logging helper for info messages
             * @param msg Message to log
             */
            static void SafeLogInfo(const wchar_t* msg) noexcept {
                if (msg == nullptr) return;
                
                try {
                    if (Logger::Instance().IsInitialized()) {
                        SS_LOG_INFO(LOG_CATEGORY, L"%s", msg);
                    }
                    else {
                        OutputDebugStringW(L"[CryptoUtils] ");
                        OutputDebugStringW(msg);
                        OutputDebugStringW(L"\n");
                    }
                }
                catch (...) {
                    // Logging should never throw - silently ignore
                }
            }

            // =============================================================================
            // Base64 Helpers
            // =============================================================================

            namespace Base64 {

                std::string Encode(const uint8_t* data, size_t len) noexcept {
                    // Handle edge cases
                    if (data == nullptr && len != 0) {
                        return std::string();
                    }
                    if (len == 0) {
                        return std::string();
                    }

                    try {
                        std::string out;
                        Utils::Base64EncodeOptions opt{};
                        const bool ok = Utils::Base64Encode(data, len, out, opt);
                        if (!ok) {
                            out.clear();
                        }
                        return out;
                    }
                    catch (const std::exception&) {
                        return std::string();
                    }
                }

                std::string Encode(const std::vector<uint8_t>& data) noexcept {
                    if (data.empty()) {
                        return std::string();
                    }
                    return Encode(data.data(), data.size());
                }

                bool Decode(std::string_view base64, std::vector<uint8_t>& out) noexcept {
                    out.clear();
                    
                    if (base64.empty()) {
                        return true;  // Empty input is valid
                    }

                    try {
                        Utils::Base64DecodeError derr = Utils::Base64DecodeError::None;
                        Utils::Base64DecodeOptions opt{};
                        return Utils::Base64Decode(base64, out, derr, opt);
                    }
                    catch (const std::exception&) {
                        out.clear();
                        return false;
                    }
                }

            } // namespace Base64

            // =============================================================================
            // Secure Comparison (Constant-Time)
            // =============================================================================

            bool SecureCompare(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
                // Handle pointer equality (same buffer)
                if (a == b) {
                    return true;
                }

                // Null pointer check (both must be valid unless len is 0)
                if (len == 0) {
                    return true;
                }
                if (a == nullptr || b == nullptr) {
                    return false;
                }

                // Constant-time comparison to prevent timing attacks
                // Uses volatile to prevent compiler optimization
                volatile unsigned char accumulator = 0;
                
                for (size_t i = 0; i < len; ++i) {
                    accumulator |= static_cast<unsigned char>(a[i] ^ b[i]);
                }

                // Return true only if no differences found
                return accumulator == 0;
            }

            bool SecureCompare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) noexcept {
                // Size comparison must be done in constant time to prevent length oracle
                // However, if sizes differ, result is always false
                if (a.size() != b.size()) {
                    return false;
                }

                if (a.empty()) {
                    return true;  // Both empty
                }

                return SecureCompare(a.data(), b.data(), a.size());
            }

            // =============================================================================
            // Secure Memory Wipe
            // =============================================================================

            void SecureZeroMemory(void* ptr, size_t size) noexcept {
                if (ptr == nullptr || size == 0) {
                    return;
                }

#ifdef _WIN32
                // Windows: Use RtlSecureZeroMemory which is guaranteed not to be optimized away
                ::RtlSecureZeroMemory(ptr, size);
#else
                // Non-Windows: Use volatile pointer to prevent optimization
                volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
                while (size > 0) {
                    *p++ = 0;
                    --size;
                }
                // Memory barrier to ensure writes complete
                std::atomic_thread_fence(std::memory_order_seq_cst);
#endif
            }

            // =============================================================================
            // SecureRandom Implementation
            // =============================================================================

            SecureRandom::SecureRandom() noexcept {
#ifdef _WIN32
                // Open algorithm provider for random number generation
                BCRYPT_ALG_HANDLE handle = nullptr;
                const NTSTATUS st = BCryptOpenAlgorithmProvider(
                    &handle,
                    BCRYPT_RNG_ALGORITHM,
                    nullptr,
                    0
                );

                if (BCRYPT_SUCCESS(st) && handle != nullptr) {
                    m_algHandle = handle;
                    m_initialized = true;
                }
                else {
                    // Initialization failed - will fall back to system RNG
                    m_algHandle = nullptr;
                    m_initialized = false;
                }
#else
                m_initialized = false;
#endif
            }

            SecureRandom::~SecureRandom() {
#ifdef _WIN32
                if (m_algHandle != nullptr) {
                    BCryptCloseAlgorithmProvider(m_algHandle, 0);
                    m_algHandle = nullptr;
                }
#endif
                m_initialized = false;
            }

            bool SecureRandom::Generate(uint8_t* buffer, size_t size, Error* err) noexcept {
                // Input validation
                if (buffer == nullptr || size == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid buffer or size for random generation");
                    }
                    return false;
                }

                // Size validation - prevent overflow when casting to ULONG
                if (size > static_cast<size_t>(ULONG_MAX)) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
                            L"Random generation size exceeds ULONG_MAX");
                    }
                    return false;
                }

#ifdef _WIN32
                NTSTATUS st = STATUS_UNSUCCESSFUL;

                if (m_initialized && m_algHandle != nullptr) {
                    // Use our dedicated RNG handle
                    st = BCryptGenRandom(
                        m_algHandle,
                        buffer,
                        static_cast<ULONG>(size),
                        0
                    );
                }
                else {
                    // Fallback to system preferred RNG (always available)
                    st = BCryptGenRandom(
                        nullptr,
                        buffer,
                        static_cast<ULONG>(size),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG
                    );
                }

                if (!BCRYPT_SUCCESS(st)) {
                    // Secure wipe the buffer on failure
                    SecureZeroMemory(buffer, size);

                    if (err != nullptr) {
                        err->SetNtStatus(st, L"BCryptGenRandom failed");
                    }
                    return false;
                }

                return true;
#else
                // Non-Windows platforms not supported
                SecureZeroMemory(buffer, size);
                if (err != nullptr) {
                    err->SetWin32Error(ERROR_NOT_SUPPORTED, L"Platform not supported");
                }
                return false;
#endif
            }

            bool SecureRandom::Generate(std::vector<uint8_t>& out, size_t size, Error* err) noexcept {
                // Handle zero-size request
                if (size == 0) {
                    out.clear();
                    return true;
                }

                try {
                    out.resize(size);
                }
                catch (const std::exception&) {
                    out.clear();
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate random buffer");
                    }
                    return false;
                }

                if (!Generate(out.data(), size, err)) {
                    SecureZeroMemory(out.data(), out.size());
                    out.clear();
                    return false;
                }

                return true;
            }

            std::vector<uint8_t> SecureRandom::Generate(size_t size, Error* err) noexcept {
                std::vector<uint8_t> out;
                if (!Generate(out, size, err)) {
                    return std::vector<uint8_t>();
                }
                return out;
            }

            uint32_t SecureRandom::NextUInt32(Error* err) noexcept {
                uint32_t val = 0;
                if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) {
                    return 0;
                }
                return val;
            }

            uint64_t SecureRandom::NextUInt64(Error* err) noexcept {
                uint64_t val = 0;
                if (!Generate(reinterpret_cast<uint8_t*>(&val), sizeof(val), err)) {
                    return 0;
                }
                return val;
            }

            uint32_t SecureRandom::NextUInt32(uint32_t min, uint32_t max, Error* err) noexcept {
                // Validate range
                if (min >= max) {
                    return min;
                }

                const uint32_t range = max - min;
                
                // Prevent division by zero (shouldn't happen given min < max check)
                if (range == 0) {
                    return min;
                }

                // Calculate rejection threshold to avoid modulo bias
                // We reject values >= limit to ensure uniform distribution
                const uint32_t limit = (UINT32_MAX / range) * range;

                uint32_t val = 0;
                uint32_t iterations = 0;

                do {
                    val = NextUInt32(err);
                    ++iterations;

                    // Safety limit to prevent infinite loop on RNG failure
                    if (iterations > MAX_REJECTION_ITERATIONS) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_TIMEOUT,
                                L"Random range generation exceeded iteration limit");
                        }
                        return min;
                    }
                } while (val >= limit);

                return min + (val % range);
            }

            uint64_t SecureRandom::NextUInt64(uint64_t min, uint64_t max, Error* err) noexcept {
                // Validate range
                if (min >= max) {
                    return min;
                }

                const uint64_t range = max - min;
                
                if (range == 0) {
                    return min;
                }

                // Calculate rejection threshold
                const uint64_t limit = (UINT64_MAX / range) * range;

                uint64_t val = 0;
                uint32_t iterations = 0;

                do {
                    val = NextUInt64(err);
                    ++iterations;

                    if (iterations > MAX_REJECTION_ITERATIONS) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_TIMEOUT,
                                L"Random range generation exceeded iteration limit");
                        }
                        return min;
                    }
                } while (val >= limit);

                return min + (val % range);
            }

            std::string SecureRandom::GenerateAlphanumeric(size_t length, Error* err) noexcept {
                // Character set for alphanumeric strings
                static constexpr char alphanum[] =
                    "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";
                static constexpr size_t alphaLen = sizeof(alphanum) - 1;  // Exclude null terminator

                if (length == 0) {
                    return std::string();
                }

                try {
                    std::string out;
                    out.reserve(length);

                    for (size_t i = 0; i < length; ++i) {
                        const uint32_t idx = NextUInt32(0, static_cast<uint32_t>(alphaLen), err);
                        out.push_back(alphanum[idx]);
                    }

                    return out;
                }
                catch (const std::exception&) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate alphanumeric string");
                    }
                    return std::string();
                }
            }

            std::string SecureRandom::GenerateHex(size_t byteCount, Error* err) noexcept {
                if (byteCount == 0) {
                    return std::string();
                }

                std::vector<uint8_t> bytes;
                if (!Generate(bytes, byteCount, err)) {
                    return std::string();
                }

                try {
                    return HashUtils::ToHexLower(bytes.data(), bytes.size());
                }
                catch (const std::exception&) {
                    SecureZeroMemory(bytes.data(), bytes.size());
                    return std::string();
                }
            }

            std::string SecureRandom::GenerateBase64(size_t byteCount, Error* err) noexcept {
                if (byteCount == 0) {
                    return std::string();
                }

                std::vector<uint8_t> bytes;
                if (!Generate(bytes, byteCount, err)) {
                    return std::string();
                }

                std::string result = Base64::Encode(bytes);
                
                // Securely wipe the raw bytes
                SecureZeroMemory(bytes.data(), bytes.size());
                
                return result;
            }

            // =============================================================================
            // SymmetricCipher Implementation
            // =============================================================================

            SymmetricCipher::SymmetricCipher(SymmetricAlgorithm algorithm) noexcept
                : m_streamBuffer()
                , m_streamFinalized(false)
                , m_algorithm(algorithm)
                , m_paddingMode(PaddingMode::PKCS7)
#ifdef _WIN32
                , m_algHandle(nullptr)
                , m_keyHandle(nullptr)
                , m_keyObject()
#endif
                , m_key()
                , m_iv()
                , m_keySet(false)
                , m_ivSet(false)
            {
            }

            SymmetricCipher::~SymmetricCipher() {
                cleanup();
            }

            SymmetricCipher::SymmetricCipher(SymmetricCipher&& other) noexcept
                : m_streamBuffer(std::move(other.m_streamBuffer))
                , m_streamFinalized(other.m_streamFinalized)
                , m_algorithm(other.m_algorithm)
                , m_paddingMode(other.m_paddingMode)
#ifdef _WIN32
                , m_algHandle(other.m_algHandle)
                , m_keyHandle(other.m_keyHandle)
                , m_keyObject(std::move(other.m_keyObject))
#endif
                , m_key(std::move(other.m_key))
                , m_iv(std::move(other.m_iv))
                , m_keySet(other.m_keySet)
                , m_ivSet(other.m_ivSet)
            {
                // Clear source handles to prevent double-close
#ifdef _WIN32
                other.m_algHandle = nullptr;
                other.m_keyHandle = nullptr;
#endif
                other.m_keySet = false;
                other.m_ivSet = false;
                other.m_streamFinalized = false;
            }

            SymmetricCipher& SymmetricCipher::operator=(SymmetricCipher&& other) noexcept {
                if (this != &other) {
                    // Clean up current resources first
                    cleanup();

                    // Move state from source
                    m_streamBuffer = std::move(other.m_streamBuffer);
                    m_streamFinalized = other.m_streamFinalized;
                    m_algorithm = other.m_algorithm;
                    m_paddingMode = other.m_paddingMode;

#ifdef _WIN32
                    m_algHandle = other.m_algHandle;
                    m_keyHandle = other.m_keyHandle;
                    m_keyObject = std::move(other.m_keyObject);
                    other.m_algHandle = nullptr;
                    other.m_keyHandle = nullptr;
#endif

                    m_key = std::move(other.m_key);
                    m_iv = std::move(other.m_iv);
                    m_keySet = other.m_keySet;
                    m_ivSet = other.m_ivSet;

                    // Clear source state
                    other.m_keySet = false;
                    other.m_ivSet = false;
                    other.m_streamFinalized = false;
                }
                return *this;
            }

            void SymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
                // Destroy key handle first (depends on algorithm handle)
                if (m_keyHandle != nullptr) {
                    BCryptDestroyKey(m_keyHandle);
                    m_keyHandle = nullptr;
                }

                // Close algorithm provider
                if (m_algHandle != nullptr) {
                    BCryptCloseAlgorithmProvider(m_algHandle, 0);
                    m_algHandle = nullptr;
                }

                // Secure wipe key object buffer
                if (!m_keyObject.empty()) {
                    SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
                    m_keyObject.clear();
                }
#endif

                // Secure wipe key material
                if (!m_key.empty()) {
                    SecureZeroMemory(m_key.data(), m_key.size());
                    m_key.clear();
                }

                // Secure wipe IV
                if (!m_iv.empty()) {
                    SecureZeroMemory(m_iv.data(), m_iv.size());
                    m_iv.clear();
                }

                // Secure wipe stream buffer
                if (!m_streamBuffer.empty()) {
                    SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
                    m_streamBuffer.clear();
                }

                // Reset state flags
                m_keySet = false;
                m_ivSet = false;
                m_streamFinalized = false;
            }

            bool SymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
                // Already initialized - return success
                if (m_algHandle != nullptr) {
                    return true;
                }

                // Get algorithm name for this cipher
                const wchar_t* algName = AlgName(m_algorithm);
                if (algName == nullptr || algName[0] == L'\0') {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid symmetric algorithm",
                            L"ensureProvider");
                    }

                    wchar_t debugMsg[256];
                    swprintf_s(debugMsg, _countof(debugMsg),
                        L"ensureProvider: invalid algorithm enum: %d",
                        static_cast<int>(m_algorithm));
                    SafeLogError(debugMsg);

                    return false;
                }

                // Open algorithm provider
                BCRYPT_ALG_HANDLE handle = nullptr;
                NTSTATUS st = BCryptOpenAlgorithmProvider(
                    &handle,
                    algName,
                    nullptr,
                    0
                );

                if (!BCRYPT_SUCCESS(st) || handle == nullptr) {
                    if (err != nullptr) {
                        err->SetNtStatus(st,
                            L"BCryptOpenAlgorithmProvider failed",
                            L"ensureProvider");
                    }

                    wchar_t debugMsg[512];
                    swprintf_s(debugMsg, _countof(debugMsg),
                        L"BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X",
                        algName, static_cast<unsigned>(st));
                    SafeLogError(debugMsg);

                    // Ensure handle is null on failure
                    m_algHandle = nullptr;
                    return false;
                }

                m_algHandle = handle;

                // Set chaining mode if applicable
                const wchar_t* chainMode = ChainingMode(m_algorithm);
                if (chainMode != nullptr) {
                    const size_t chainModeLen = wcslen(chainMode);
                    
                    // Validate string length to prevent overflow
                    if (chainModeLen > 0 && chainModeLen < 256) {
                        st = BCryptSetProperty(
                            m_algHandle,
                            BCRYPT_CHAINING_MODE,
                            reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainMode)),
                            static_cast<ULONG>((chainModeLen + 1) * sizeof(wchar_t)),
                            0
                        );

                        if (!BCRYPT_SUCCESS(st)) {
                            if (err != nullptr) {
                                err->SetNtStatus(st,
                                    L"BCryptSetProperty for chaining mode failed",
                                    L"ensureProvider");
                            }

                            wchar_t debugMsg[256];
                            swprintf_s(debugMsg, _countof(debugMsg),
                                L"BCryptSetProperty failed for mode %s: 0x%08X",
                                chainMode, static_cast<unsigned>(st));
                            SafeLogError(debugMsg);

                            // Cleanup on failure
                            BCryptCloseAlgorithmProvider(m_algHandle, 0);
                            m_algHandle = nullptr;
                            return false;
                        }
                    }
                }

                // Log successful initialization
                wchar_t infoMsg[256];
                swprintf_s(infoMsg, _countof(infoMsg),
                    L"Algorithm provider opened: %s (handle: %p)",
                    algName, static_cast<void*>(m_algHandle));
                SafeLogInfo(infoMsg);

                return true;
#else
                if (err != nullptr) {
                    err->SetWin32Error(ERROR_NOT_SUPPORTED,
                        L"Platform not supported",
                        L"ensureProvider");
                }
                return false;
#endif
            }

            bool SymmetricCipher::SetKey(const uint8_t* key, size_t keyLen, Error* err) noexcept {
                // Input validation
                if (key == nullptr || keyLen == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid key pointer or length",
                            L"SetKey");
                    }
                    return false;
                }

                // Validate key size matches algorithm requirements
                const size_t expectedSize = GetKeySize();
                if (expectedSize == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Unknown algorithm - cannot determine key size",
                            L"SetKey");
                    }
                    return false;
                }

                if (keyLen != expectedSize) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid key size for algorithm",
                            L"SetKey");
                    }
                    return false;
                }

                // Ensure provider is initialized
                if (!ensureProvider(err)) {
                    return false;
                }

#ifdef _WIN32
                // Destroy existing key if any
                if (m_keyHandle != nullptr) {
                    BCryptDestroyKey(m_keyHandle);
                    m_keyHandle = nullptr;
                }

                // Securely store key copy
                try {
                    m_key.assign(key, key + keyLen);
                }
                catch (const std::exception&) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate key storage",
                            L"SetKey");
                    }
                    return false;
                }

                // Get required key object size
                DWORD objLen = 0;
                DWORD cbResult = 0;
                NTSTATUS st = BCryptGetProperty(
                    m_algHandle,
                    BCRYPT_OBJECT_LENGTH,
                    reinterpret_cast<PUCHAR>(&objLen),
                    sizeof(objLen),
                    &cbResult,
                    0
                );

                if (!BCRYPT_SUCCESS(st)) {
                    if (err != nullptr) {
                        err->SetNtStatus(st,
                            L"BCryptGetProperty OBJECT_LENGTH failed",
                            L"SetKey");
                    }
                    SecureZeroMemory(m_key.data(), m_key.size());
                    m_key.clear();
                    return false;
                }

                // Allocate key object buffer
                try {
                    m_keyObject.resize(objLen);
                }
                catch (const std::exception&) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate key object buffer",
                            L"SetKey");
                    }
                    SecureZeroMemory(m_key.data(), m_key.size());
                    m_key.clear();
                    return false;
                }

                // Generate symmetric key from key material
                st = BCryptGenerateSymmetricKey(
                    m_algHandle,
                    &m_keyHandle,
                    m_keyObject.data(),
                    static_cast<ULONG>(m_keyObject.size()),
                    const_cast<uint8_t*>(m_key.data()),
                    static_cast<ULONG>(m_key.size()),
                    0
                );

                if (!BCRYPT_SUCCESS(st)) {
                    if (err != nullptr) {
                        err->SetNtStatus(st,
                            L"BCryptGenerateSymmetricKey failed",
                            L"SetKey");
                    }

                    wchar_t debugMsg[256];
                    swprintf_s(debugMsg, _countof(debugMsg),
                        L"BCryptGenerateSymmetricKey failed: 0x%08X",
                        static_cast<unsigned>(st));
                    SafeLogError(debugMsg);

                    // Cleanup on failure
                    SecureZeroMemory(m_key.data(), m_key.size());
                    m_key.clear();
                    SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
                    m_keyObject.clear();
                    m_keyHandle = nullptr;
                    return false;
                }

                m_keySet = true;
                return true;
#else
                if (err != nullptr) {
                    err->SetWin32Error(ERROR_NOT_SUPPORTED,
                        L"Platform not supported",
                        L"SetKey");
                }
                return false;
#endif
            }

            bool SymmetricCipher::SetKey(const std::vector<uint8_t>& key, Error* err) noexcept {
                if (key.empty()) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Empty key vector",
                            L"SetKey");
                    }
                    return false;
                }
                return SetKey(key.data(), key.size(), err);
            }

            bool SymmetricCipher::GenerateKey(std::vector<uint8_t>& outKey, Error* err) noexcept {
                const size_t keySize = GetKeySize();
                if (keySize == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Unknown algorithm - cannot determine key size",
                            L"GenerateKey");
                    }
                    return false;
                }

                // Generate random key
                SecureRandom rng;
                if (!rng.Generate(outKey, keySize, err)) {
                    return false;
                }

                // Set the generated key
                if (!SetKey(outKey, err)) {
                    SecureZeroMemory(outKey.data(), outKey.size());
                    outKey.clear();
                    return false;
                }

                return true;
            }
			
            bool SymmetricCipher::SetIV(const uint8_t* iv, size_t ivLen, Error* err) noexcept {
                const size_t expectedSize = GetIVSize();

                // Some algorithms don't need an IV
                if (expectedSize == 0) {
                    m_iv.clear();
                    m_ivSet = true;
                    return true;
                }

                // Validate IV pointer
                if (iv == nullptr) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"IV pointer is null",
                            L"SetIV");
                    }
                    return false;
                }

                // Validate IV size
                if (ivLen != expectedSize) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid IV size for algorithm",
                            L"SetIV");
                    }
                    return false;
                }

                try {
                    m_iv.assign(iv, iv + ivLen);
                }
                catch (const std::exception&) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate IV storage",
                            L"SetIV");
                    }
                    return false;
                }

                m_ivSet = true;
                return true;
            }

            bool SymmetricCipher::SetIV(const std::vector<uint8_t>& iv, Error* err) noexcept {
                const size_t expectedSize = GetIVSize();

                // Some algorithms don't need an IV
                if (expectedSize == 0) {
                    m_iv.clear();
                    m_ivSet = true;
                    return true;
                }

                if (iv.empty()) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Empty IV vector",
                            L"SetIV");
                    }
                    return false;
                }

                return SetIV(iv.data(), iv.size(), err);
            }

            bool SymmetricCipher::GenerateIV(std::vector<uint8_t>& outIV, Error* err) noexcept {
                const size_t ivSize = GetIVSize();

                // Some algorithms don't need an IV
                if (ivSize == 0) {
                    outIV.clear();
                    m_iv.clear();
                    m_ivSet = true;
                    return true;
                }

                // Generate random IV
                SecureRandom rng;
                if (!rng.Generate(outIV, ivSize, err)) {
                    return false;
                }

                // Set the generated IV
                if (!SetIV(outIV, err)) {
                    SecureZeroMemory(outIV.data(), outIV.size());
                    outIV.clear();
                    return false;
                }

                return true;
            }

            // =============================================================================
            // SymmetricCipher Property Accessors
            // =============================================================================

            size_t SymmetricCipher::GetKeySize() const noexcept {
                return KeySizeForAlg(m_algorithm);
            }

            size_t SymmetricCipher::GetIVSize() const noexcept {
                return IVSizeForAlg(m_algorithm);
            }

            size_t SymmetricCipher::GetBlockSize() const noexcept {
                // All supported algorithms use 16-byte (128-bit) blocks
                return AES_BLOCK_SIZE_BYTES;
            }

            size_t SymmetricCipher::GetTagSize() const noexcept {
                // AEAD modes use 16-byte (128-bit) authentication tags
                return IsAEAD() ? GCM_TAG_SIZE_BYTES : 0ULL;
            }

            bool SymmetricCipher::IsAEAD() const noexcept {
                return IsAEADAlg(m_algorithm);
            }

            // =============================================================================
            // SymmetricCipher Encrypt/Decrypt Implementation
            // =============================================================================

            bool SymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
                std::vector<uint8_t>& ciphertext, Error* err) noexcept
            {
                // Clear output buffer first
                ciphertext.clear();

                // ═══════════════════════════════════════════════════════════════════
                //  TIER-1 INPUT VALIDATION
                // ═══════════════════════════════════════════════════════════════════
                if (!m_keySet) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_STATE,
                            L"Key not set",
                            L"Encrypt");
                    }
                    return false;
                }

                if (!m_ivSet && GetIVSize() > 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_STATE,
                            L"IV not set",
                            L"Encrypt");
                    }
                    return false;
                }

                if (plaintext == nullptr && plaintextLen != 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid plaintext pointer",
                            L"Encrypt");
                    }
                    return false;
                }

                if (IsAEAD()) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Use EncryptAEAD for AEAD modes",
                            L"Encrypt");
                    }
                    return false;
                }

                // Size limit validation
                if (plaintextLen > MAX_PLAINTEXT_SIZE) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
                            L"Plaintext exceeds maximum size limit",
                            L"Encrypt");
                    }
                    return false;
                }

                // Handle empty plaintext
                if (plaintextLen == 0) {
                    ciphertext.clear();
                    return true;
                }

#ifdef _WIN32
                // ═══════════════════════════════════════════════════════════════════
                //  ALGORITHM CLASSIFICATION
                // ═══════════════════════════════════════════════════════════════════
                const bool isCBC = (m_algorithm == SymmetricAlgorithm::AES_128_CBC ||
                    m_algorithm == SymmetricAlgorithm::AES_192_CBC ||
                    m_algorithm == SymmetricAlgorithm::AES_256_CBC);

                const bool needsPadding = isCBC;
                const size_t blockSize = GetBlockSize();

                // Validate block size
                if (blockSize == 0) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_INVALID_PARAMETER,
                            L"Invalid block size for algorithm",
                            L"Encrypt");
                    }
                    return false;
                }

                // ═══════════════════════════════════════════════════════════════════
                //  PADDING STRATEGY (Manual PKCS7 - Industry Standard)
                // ═══════════════════════════════════════════════════════════════════
                if (plaintextLen > static_cast<size_t>(ULONG_MAX)) {
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_BUFFER_OVERFLOW,
                            L"Plaintext too large for Windows CNG API",
                            L"Encrypt");
                    }
                    return false;
                }

                std::vector<uint8_t> plaintextWithPadding;
                const uint8_t* effectivePlaintext = plaintext;
                size_t effectiveLen = plaintextLen;

                if (needsPadding && m_paddingMode == PaddingMode::PKCS7) {
                    // Apply PKCS7 padding manually
                    try {
                        plaintextWithPadding.assign(plaintext, plaintext + plaintextLen);
                    }
                    catch (const std::exception&) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                                L"Failed to allocate padding buffer",
                                L"Encrypt");
                        }
                        return false;
                    }

                    if (!applyPadding(plaintextWithPadding, blockSize)) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_INVALID_DATA,
                                L"PKCS7 padding failed",
                                L"Encrypt");
                        }
                        SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
                        return false;
                    }

                    effectivePlaintext = plaintextWithPadding.data();
                    effectiveLen = plaintextWithPadding.size();
                }
                else if (needsPadding && m_paddingMode == PaddingMode::None) {
                    // No padding - must be block-aligned
                    if (plaintextLen % blockSize != 0) {
                        if (err != nullptr) {
                            err->SetWin32Error(ERROR_INVALID_DATA,
                                L"Plaintext must be block-aligned when padding is disabled",
                                L"Encrypt");
                        }
                        return false;
                    }
                }

                // ═══════════════════════════════════════════════════════════════════
                //  IV LOCAL COPY (Prevent IV reuse attacks)
                // ═══════════════════════════════════════════════════════════════════
                std::vector<uint8_t> ivLocal;
                try {
                    ivLocal = m_iv;
                }
                catch (const std::exception&) {
                    SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate IV buffer",
                            L"Encrypt");
                    }
                    return false;
                }

                PUCHAR ivPtr = ivLocal.empty() ? nullptr : ivLocal.data();
                ULONG ivLen = static_cast<ULONG>(ivLocal.size());

                // ═══════════════════════════════════════════════════════════════════
                //  BCRYPT ENCRYPTION (NO PADDING FLAG)
                // ═══════════════════════════════════════════════════════════════════
                constexpr DWORD flags = 0;  // We handle padding ourselves

                // Query encrypted size
                ULONG cbResult = 0;
                NTSTATUS st = BCryptEncrypt(
                    m_keyHandle,
                    const_cast<uint8_t*>(effectivePlaintext),
                    static_cast<ULONG>(effectiveLen),
                    nullptr,
                    ivPtr,
                    ivLen,
                    nullptr,
                    0,
                    &cbResult,
                    flags
                );

                if (!BCRYPT_SUCCESS(st)) {
                    if (err != nullptr) {
                        err->SetNtStatus(st,
                            L"BCryptEncrypt size query failed",
                            L"Encrypt");
                    }
                    SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
                    return false;
                }

                // Allocate output buffer
                try {
                    ciphertext.resize(cbResult);
                }
                catch (const std::exception&) {
                    SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());
                    if (err != nullptr) {
                        err->SetWin32Error(ERROR_NOT_ENOUGH_MEMORY,
                            L"Failed to allocate ciphertext buffer",
                            L"Encrypt");
                    }
                    return false;
                }

                // Perform encryption
                st = BCryptEncrypt(
                    m_keyHandle,
                    const_cast<uint8_t*>(effectivePlaintext),
                    static_cast<ULONG>(effectiveLen),
                    nullptr,
                    ivPtr,
                    ivLen,
                    ciphertext.data(),
                    static_cast<ULONG>(ciphertext.size()),
                    &cbResult,
                    flags
                );

                // Secure cleanup of padded plaintext
                SecureZeroMemory(plaintextWithPadding.data(), plaintextWithPadding.size());

                if (!BCRYPT_SUCCESS(st)) {
                    if (err != nullptr) {
                        err->SetNtStatus(st,
                            L"BCryptEncrypt failed",
                            L"Encrypt");
                    }
                    SecureZeroMemory(ciphertext.data(), ciphertext.size());
                    ciphertext.clear();
                    return false;
                }

                ciphertext.resize(cbResult);

                // ═══════════════════════════════════════════════════════════════════
                //  IV CHAINING (CBC mode - for continuous streaming)
                // ═══════════════════════════════════════════════════════════════════
                if (isCBC && ivPtr != nullptr && ivLen > 0) {
                    if (ciphertext.size() >= ivLen) {
                        // Use last ciphertext block as next IV for chaining
                        std::memcpy(m_iv.data(),
                            ciphertext.data() + ciphertext.size() - ivLen,
                            ivLen);
                    }
                }

                return true;
#else
                if (err != nullptr) {
                    err->SetWin32Error(ERROR_NOT_SUPPORTED,
                        L"Platform not supported",
                        L"Encrypt");
                }
                return false;
#endif
            }

			bool SymmetricCipher::Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
				std::vector<uint8_t>& plaintext, Error* err) noexcept
			{
				// ═══════════════════════════════════════════════════════════════════
				//  TIER-1 INPUT VALIDATION
				// ═══════════════════════════════════════════════════════════════════
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}
				if (!ciphertext && ciphertextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid ciphertext pointer"; }
					return false;
				}
				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Use DecryptAEAD for AEAD modes"; }
					return false;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  ALGORITHM CLASSIFICATION
				// ═══════════════════════════════════════════════════════════════════
				const bool isCBC = (m_algorithm == SymmetricAlgorithm::AES_128_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_192_CBC ||
					m_algorithm == SymmetricAlgorithm::AES_256_CBC);
			
				const bool needsPadding = isCBC;
				const size_t blockSize = GetBlockSize();

				//  Block alignment validation
				if (needsPadding && (ciphertextLen % blockSize != 0)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Ciphertext not block-aligned"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  IV MUTATION PROTECTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal = m_iv;
				PUCHAR ivPtr = ivLocal.empty() ? nullptr : ivLocal.data();
				ULONG ivLen = static_cast<ULONG>(ivLocal.size());

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT DECRYPTION (NO PADDING FLAG)
				// ═══════════════════════════════════════════════════════════════════
				DWORD flags = 0; //  CRITICAL: We handle padding removal ourselves

				if (ciphertextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Ciphertext too large for Windows CNG API";
					}
					return false;
				}
				// Query decrypted size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					ivPtr, ivLen,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptDecrypt size query failed";
					}
					return false;
				}

				// Allocate output buffer
				plaintext.resize(cbResult);

				// Perform decryption
				st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					nullptr,
					ivPtr, ivLen,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptDecrypt failed";
					}
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				plaintext.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  MANUAL PADDING REMOVAL (Constant-time validation)
				// ═══════════════════════════════════════════════════════════════════
				if (needsPadding && m_paddingMode == PaddingMode::PKCS7) {
					const size_t originalSize = plaintext.size();

					if (!removePadding(plaintext, blockSize)) {
						//  SECURITY: Zero memory before reporting error
						SecureZeroMemory(plaintext.data(), originalSize);
						plaintext.clear();

						if (err) {
							err->win32 = ERROR_INVALID_DATA;
							err->message = L"Decrypt Failed";
						}
						return false;
					}
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}


			bool SymmetricCipher::EncryptAEAD(const uint8_t* plaintext, size_t plaintextLen,
				const uint8_t* aad, size_t aadLen,
				std::vector<uint8_t>& ciphertext,
				std::vector<uint8_t>& tag, Error* err) noexcept
			{
				if (aadLen > 0 && !aad) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"AAD pointer invalid"; }
					return false;
				}
				if (!IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Not an AEAD algorithm"; }
					return false;
				}

				if (!m_keySet || !m_ivSet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key or IV not set"; }
					return false;
				}

				if (plaintextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Plaintext too large for Windows CNG API";
					}
					return false;
				}

				if(aadLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"AAD too large for Windows CNG API";
					}
					return false;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  IV MUTATION PROTECTION - Create local copy
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> ivLocal = m_iv;

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT AUTHENTICATED CIPHER MODE INFO SETUP
				// ═══════════════════════════════════════════════════════════════════
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = ivLocal.data();
				authInfo.cbNonce = static_cast<ULONG>(ivLocal.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);

				// Allocate tag buffer
				const size_t tagSize = GetTagSize();
				tag.resize(tagSize);
				authInfo.pbTag = tag.data();
				authInfo.cbTag = static_cast<ULONG>(tagSize);
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = static_cast<ULONG>(plaintextLen);
				authInfo.dwFlags = 0;

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT AEAD ENCRYPTION
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&authInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear tag on failure
					SecureZeroMemory(tag.data(), tag.size());
					tag.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt AEAD size query failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					&authInfo,
					nullptr, 0,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both ciphertext and tag on failure
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					SecureZeroMemory(tag.data(), tag.size());
					ciphertext.clear();
					tag.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt AEAD failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptAEAD(const uint8_t* ciphertext, size_t ciphertextLen,
				const uint8_t* aad, size_t aadLen,
				const uint8_t* tag, size_t tagLen,
				std::vector<uint8_t>& plaintext, Error* err) noexcept
			{
				if (aadLen > 0 && !aad) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"AAD pointer invalid"; }
					return false;
				}
				if (!IsAEAD()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Not an AEAD algorithm"; }
					return false;
				}

				if (!m_keySet || !m_ivSet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key or IV not set"; }
					return false;
				}

				if (tagLen != GetTagSize()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid tag size"; }
					return false;
				}

				if (ciphertextLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"Ciphertext is too large for Windows CNG API";
					}
					return false;
				}

				if (aadLen > std::numeric_limits<ULONG>::max()) {
					if (err) {
						err->win32 = ERROR_BUFFER_OVERFLOW;
						err->message = L"AAD too large for Windows CNG API";
					}
					return false;
				}

#ifdef _WIN32
				std::vector<uint8_t> ivLocal = m_iv;

				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
				BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
				authInfo.pbNonce = ivLocal.data();
				authInfo.cbNonce = static_cast<ULONG>(m_iv.size());
				authInfo.pbAuthData = const_cast<uint8_t*>(aad);
				authInfo.cbAuthData = static_cast<ULONG>(aadLen);
				authInfo.pbTag = const_cast<uint8_t*>(tag);
				authInfo.cbTag = static_cast<ULONG>(tagLen);
				authInfo.pbMacContext = nullptr;
				authInfo.cbMacContext = 0;
				authInfo.cbAAD = static_cast<ULONG>(aadLen);
				authInfo.cbData = static_cast<ULONG>(ciphertextLen);
				authInfo.dwFlags = 0;

				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&authInfo,
					nullptr, 0,
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt AEAD size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					&authInfo,
					nullptr, 0,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, 0);
				if (st < 0) {
					SecureZeroMemory(plaintext.data(), plaintext.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt AEAD failed or authentication failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::EncryptInit(Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

				//clear the internal buffer for streaming
				m_streamBuffer.clear();
				m_streamFinalized = false;

				return true;
			}

			bool SymmetricCipher::EncryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();
				if (len == 0) return true;

				// streaming is not supported for AEAD modes
				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

				//Add the new data to the internal buffer
				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				//encrypt the block-aligned data in the buffer
				const size_t blockSize = GetBlockSize();
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				if (alignedSize == 0) {
					// there is not enough data to process a full block yet
					return true;
				}

#ifdef _WIN32
				// ═══════════════════════════════════════════════════════════════════
				//  EXTRACT BLOCK-ALIGNED DATA FOR ENCRYPTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> toEncrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);

				// Validate sizes for ULONG conversion
				if (toEncrypt.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_keyHandle,
					toEncrypt.data(), static_cast<ULONG>(toEncrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear temporary buffer on failure
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptEncrypt(m_keyHandle,
					toEncrypt.data(), static_cast<ULONG>(toEncrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
					SecureZeroMemory(out.data(), out.size());
					out.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV for modes that require it (CBC, CFB, OFB)
				if (!out.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), out.data() + out.size() - blockSize, blockSize);
				}

				// SECURITY: Securely clear temporary buffer after use
				SecureZeroMemory(toEncrypt.data(), toEncrypt.size());
				m_streamBuffer.erase(m_streamBuffer.begin(), m_streamBuffer.begin() + alignedSize);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::EncryptFinal(std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

#ifdef _WIN32
				// Empty buffer handling (no logger spam)
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  APPLY MANUAL PADDING (PKCS7)
				// ═══════════════════════════════════════════════════════════════════
				if (m_paddingMode == PaddingMode::PKCS7) {
					if (!applyPadding(m_streamBuffer, GetBlockSize())) {
						// SECURITY: Clear stream buffer on failure
						SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
						m_streamBuffer.clear();
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Padding failed"; }
						return false;
					}
				}

				// Validate size for ULONG conversion
				if (m_streamBuffer.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  ENCRYPT FINAL BLOCK (flags=0, BCrypt won't add padding)
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear stream buffer on failure
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"EncryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptEncrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(out.data(), out.size());
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					out.clear();
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"EncryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);

				// SECURITY: Securely clear stream buffer before clearing
				SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
				m_streamBuffer.clear();
				m_streamFinalized = true;
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptInit(Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Key not set"; }
					return false;
				}
				if (!m_ivSet && GetIVSize() > 0) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"IV not set"; }
					return false;
				}

				m_streamBuffer.clear();
				m_streamFinalized = false;

				return true;
			}

			bool SymmetricCipher::DecryptUpdate(const uint8_t* data, size_t len, std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"DecryptInit not called"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();
				if (len == 0) return true;

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

				//overflow guard
				if (len > SIZE_MAX - m_streamBuffer.size()) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Buffer overflow risk"; }
					return false;
				}

				m_streamBuffer.insert(m_streamBuffer.end(), data, data + len);

				const size_t blockSize = GetBlockSize();

				//blocksize validation
				if (blockSize == 0) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid block size"; }
					return false;
				}
				//overflow guard for blocksize
				if (m_streamBuffer.size() / blockSize > SIZE_MAX / blockSize) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Block size overflow"; }
					return false;
				}
				const size_t alignedSize = (m_streamBuffer.size() / blockSize) * blockSize;

				// hold the last block for padding
				const size_t keepSize = (m_paddingMode != PaddingMode::None && alignedSize > 0) ? blockSize : 0;
				const size_t processSize = (alignedSize > keepSize) ? (alignedSize - keepSize) : 0;

				if (processSize == 0) {
					return true;
				}

#ifdef _WIN32
				if (processSize > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"processSize too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  EXTRACT DATA FOR DECRYPTION
				// ═══════════════════════════════════════════════════════════════════
				std::vector<uint8_t> toDecrypt(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				// Validate sizes for ULONG conversion
				if (toDecrypt.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"toDecrypt size too large for ULONG"; }
					return false;
				}

				if (m_iv.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"IV size too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  BCRYPT DECRYPTION
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_keyHandle,
					toDecrypt.data(), static_cast<ULONG>(toDecrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear ciphertext copy on failure
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptDecrypt(m_keyHandle,
					toDecrypt.data(), static_cast<ULONG>(toDecrypt.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);
				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
					SecureZeroMemory(out.data(), out.size());
					out.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					return false;
				}

				out.resize(cbResult);

				// update IV (for CBC mode) - use ciphertext as next IV
				if (!toDecrypt.empty() && m_iv.size() == blockSize) {
					std::memcpy(m_iv.data(), toDecrypt.data() + toDecrypt.size() - blockSize, blockSize);
				}

				// SECURITY: Securely clear ciphertext copy
				SecureZeroMemory(toDecrypt.data(), toDecrypt.size());
				m_streamBuffer.erase(m_streamBuffer.begin(), m_streamBuffer.begin() + processSize);

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::DecryptFinal(std::vector<uint8_t>& out, Error* err) noexcept {
				if (!m_keySet) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"DecryptInit not called"; }
					return false;
				}
				if (m_streamFinalized) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Stream already finalized"; }
					return false;
				}

				out.clear();

				if (IsAEAD()) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"AEAD modes do not support streaming"; }
					return false;
				}

#ifdef _WIN32
				// Empty buffer handling
				if (m_streamBuffer.empty()) {
					m_streamFinalized = true;
					return true;
				}

				// Validate size for ULONG conversion
				if (m_streamBuffer.size() > static_cast<size_t>(std::numeric_limits<ULONG>::max())) {
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->win32 = ERROR_ARITHMETIC_OVERFLOW; err->message = L"Data too large for ULONG"; }
					return false;
				}

				// ═══════════════════════════════════════════════════════════════════
				//  DECRYPT FINAL BLOCK (flags=0, no BCrypt padding removal)
				// ═══════════════════════════════════════════════════════════════════
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					nullptr, 0, &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear stream buffer on failure
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"DecryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);
				st = BCryptDecrypt(
					m_keyHandle,
					m_streamBuffer.data(), static_cast<ULONG>(m_streamBuffer.size()),
					nullptr,
					m_iv.empty() ? nullptr : m_iv.data(), static_cast<ULONG>(m_iv.size()),
					out.data(), static_cast<ULONG>(out.size()), &cbResult, 0);

				if (st < 0) {
					// SECURITY: Clear both buffers on failure
					SecureZeroMemory(out.data(), out.size());
					SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
					out.clear();
					m_streamBuffer.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"DecryptFinal failed"; }
					return false;
				}

				out.resize(cbResult);

				// ═══════════════════════════════════════════════════════════════════
				//  MANUAL PADDING REMOVAL (Constant-time validation)
				// ═══════════════════════════════════════════════════════════════════
				if (m_paddingMode == PaddingMode::PKCS7) {
					const size_t originalSize = out.size();
					if (!removePadding(out, GetBlockSize())) {
						// SECURITY: Clear sensitive data on padding failure
						SecureZeroMemory(out.data(), originalSize);
						SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
						out.clear();
						m_streamBuffer.clear();
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid padding"; }
						return false;
					}
				}

				// SECURITY: Securely clear stream buffer
				SecureZeroMemory(m_streamBuffer.data(), m_streamBuffer.size());
				m_streamBuffer.clear();
				m_streamFinalized = true;
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool SymmetricCipher::applyPadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || blockSize > 255) return false;
				if (m_paddingMode != PaddingMode::PKCS7) return false;

				// PKCS7: Always add padding (even if block-aligned)
				const size_t remainder = data.size() % blockSize;
				const size_t padLen = (remainder == 0) ? blockSize : (blockSize - remainder);

				try {
					const uint8_t padByte = static_cast<uint8_t>(padLen);
					data.insert(data.end(), padLen, padByte);
					return true;
				}
				catch (const std::bad_alloc&) {
					return false;
				}
			}
			bool SymmetricCipher::removePadding(std::vector<uint8_t>& data, size_t blockSize) noexcept {
				if (blockSize == 0 || m_paddingMode != PaddingMode::PKCS7) return true;
				if (data.empty()) return false;
				if (data.size() % blockSize != 0) return false;

				const uint8_t padLen = data.back();

				// SECURITY: Validate padding length
				if (padLen == 0 || padLen > blockSize || padLen > data.size()) {
					return false;
				}

				// CONSTANT-TIME VALIDATION (Prevent padding oracle attacks)
				uint8_t diff = 0;
				for (size_t i = data.size() - padLen; i < data.size(); ++i) {
					diff |= (data[i] ^ padLen);
				}

				if (diff != 0) {
					return false; // Invalid padding
				}

				// Remove padding
				data.resize(data.size() - padLen);
				return true;
			}

			// =============================================================================
			// AsymmetricCipher Implementation
			// =============================================================================
			AsymmetricCipher::AsymmetricCipher(AsymmetricAlgorithm algorithm) noexcept : m_algorithm(algorithm) {}

			AsymmetricCipher::~AsymmetricCipher() {
				cleanup();
			}

			void AsymmetricCipher::cleanup() noexcept {
#ifdef _WIN32
				// Proper cleanup order (keys before provider)
				if (m_publicKeyHandle) {
					BCryptDestroyKey(m_publicKeyHandle);
					m_publicKeyHandle = nullptr;
				}
				if (m_privateKeyHandle) {
					BCryptDestroyKey(m_privateKeyHandle);
					m_privateKeyHandle = nullptr;
				}

				// Close provider handle
				if (m_algHandle) {
					NTSTATUS st = BCryptCloseAlgorithmProvider(m_algHandle, 0);
					if (st < 0) {
						SS_LOG_WARN(L"CryptoUtils", L"BCryptCloseAlgorithmProvider failed: 0x%08X", st);
					}
					m_algHandle = nullptr;
				}
#endif
				m_publicKeyLoaded = false;
				m_privateKeyLoaded = false;
			}

			bool AsymmetricCipher::ensureProvider(Error* err) noexcept {
#ifdef _WIN32
				//if already opened
				if (m_algHandle) {
					return true;
				}

				//Get Algorithm Name
				const wchar_t* algName = RSAAlgName(m_algorithm);
				if (!algName || !*algName) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->ntstatus = 0;
						err->message = L"Invalid asymmetric algorithm";
						err->context.clear();
					}
					
					//prevents abort() if logger not initialized
					if(Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"ensureProvider: invalid algorithm enum: %d", static_cast<int>(m_algorithm));
					}
					else
					{
						wchar_t debugMsg[256];
						swprintf_s(debugMsg, L"[CryptoUtils] ensureProvider: invalid algorithm enum: %d\n", 
							static_cast<int>(m_algorithm));
						OutputDebugStringW(debugMsg);
					}
					return false;
				}

				//Try to open
				BCRYPT_ALG_HANDLE h = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&h, algName, nullptr, 0);
				if (st < 0 || h == nullptr) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptOpenAlgorithmProvider failed for asymmetric";
						wchar_t tmp[256];
						swprintf_s(tmp, L"Algorithm=%s NTSTATUS=0x%08X Win32=%u", algName, static_cast<unsigned>(st), err->win32);
						err->context = tmp; //Copies std::wstring, no dangling
					}
					//prevents abort() if logger not initialized
					if (Logger::Instance().IsInitialized()) {
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u\n", static_cast<int>(m_algorithm));
					}
					else
					{
						wchar_t debugMsg[512];
						swprintf_s(debugMsg, 
							L"[CryptoUtils] BCryptOpenAlgorithmProvider failed: Algorithm=%s, NTSTATUS=0x%08X, Win32=%u\n",
							algName, static_cast<unsigned>(st), RtlNtStatusToDosError(st));
						OutputDebugStringW(debugMsg);
					}
					
					//Guarantee null handle on failure
					m_algHandle = nullptr;
					return false;
				}

				
				m_algHandle = h;

				
				if (Logger::Instance().IsInitialized()) {
					SS_LOG_INFO(L"CryptoUtils", L"Algorithm provider opened: %s (handle: %p)", algName, m_algHandle);
				} else {
					// Fallback to OutputDebugStringW if Logger not ready
					wchar_t debugMsg[256];
					swprintf_s(debugMsg, L"[CryptoUtils] Algorithm provider opened: %s (handle: %p)\n", 
						algName, static_cast<void*>(m_algHandle));
					OutputDebugStringW(debugMsg);
				}
				
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->ntstatus = 0; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::GenerateKeyPair(KeyPair& outKeyPair, Error* err) noexcept {
#ifdef _WIN32
				// Ensure provider is opened
				if (!ensureProvider(err)) {
					SS_LOG_ERROR(L"CryptoUtils", L"GenerateKeyPair: ensureProvider failed");
					return false;
				}

				if (!m_algHandle) {
					if (err) { err->win32 = ERROR_INVALID_HANDLE; err->ntstatus = 0; err->message = L"Algorithm provider handle is null"; }
					SS_LOG_ERROR(L"CryptoUtils", L"GenerateKeyPair: m_algHandle is null after ensureProvider");
					return false;
				}

				ULONG keySizeBits = RSAKeySizeForAlg(m_algorithm);
				SS_LOG_INFO(L"CryptoUtils", L"Generating key pair (alg=%d, bits=%u)", static_cast<int>(m_algorithm), keySizeBits);

				BCRYPT_KEY_HANDLE hKey = nullptr;
				NTSTATUS st = BCryptGenerateKeyPair(m_algHandle, &hKey, keySizeBits, 0);
				if (st < 0 || !hKey) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptGenerateKeyPair failed";
						wchar_t tmp[128];
						swprintf_s(tmp, L"KeySize=%u NTSTATUS=0x%08X", keySizeBits, static_cast<unsigned>(st));
						err->context = tmp;
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptGenerateKeyPair failed: 0x%08X", st);
					return false;
				}

				st = BCryptFinalizeKeyPair(hKey, 0);
				if (st < 0) {
					if (err) {
						err->ntstatus = st;
						err->win32 = RtlNtStatusToDosError(st);
						err->message = L"BCryptFinalizeKeyPair failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptFinalizeKeyPair failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				const bool isECC = (m_algorithm == AsymmetricAlgorithm::ECC_P256 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P384 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P521);

				const wchar_t* pubBlobType = isECC ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB;
				const wchar_t* privBlobType = isECC ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;

				// Export public key
				ULONG cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, pubBlobType, nullptr, 0, &cbBlob, 0);
				if (st < 0 || cbBlob == 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (public size) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (public size) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}
				outKeyPair.publicKey.algorithm = m_algorithm;
				outKeyPair.publicKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, pubBlobType, outKeyPair.publicKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					// SECURITY: Clear public key blob on failure
					outKeyPair.publicKey.keyBlob.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (public) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (public) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				// Export private key
				cbBlob = 0;
				st = BCryptExportKey(hKey, nullptr, privBlobType, nullptr, 0, &cbBlob, 0);
				if (st < 0 || cbBlob == 0) {
					// SECURITY: Clear public key blob since we're failing
					outKeyPair.publicKey.keyBlob.clear();
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (private size) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (private size) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}
				outKeyPair.privateKey.algorithm = m_algorithm;
				outKeyPair.privateKey.keyBlob.resize(cbBlob);
				st = BCryptExportKey(hKey, nullptr, privBlobType, outKeyPair.privateKey.keyBlob.data(), cbBlob, &cbBlob, 0);
				if (st < 0) {
					// SECURITY: Clear both key blobs on failure
					outKeyPair.publicKey.keyBlob.clear();
					if (!outKeyPair.privateKey.keyBlob.empty()) {
						SecureZeroMemory(outKeyPair.privateKey.keyBlob.data(), outKeyPair.privateKey.keyBlob.size());
						outKeyPair.privateKey.keyBlob.clear();
					}
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptExportKey (private) failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptExportKey (private) failed: 0x%08X", st);
					BCryptDestroyKey(hKey);
					return false;
				}

				BCryptDestroyKey(hKey);

				SS_LOG_INFO(L"CryptoUtils", L"Key pair generated (pub=%zu bytes, priv=%zu bytes)",
					outKeyPair.publicKey.keyBlob.size(), outKeyPair.privateKey.keyBlob.size());

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->ntstatus = 0; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::LoadPublicKey(const PublicKey& key, Error* err) noexcept {
#ifdef _WIN32
				if (!ensureProvider(err)) return false;

				if (m_publicKeyHandle) {
					BCryptDestroyKey(m_publicKeyHandle);
					m_publicKeyHandle = nullptr;
				}

				// ECC vs RSA blob type selection
				const bool isECC = (key.algorithm == AsymmetricAlgorithm::ECC_P256 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P384 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P521);
				const wchar_t* blobType = isECC ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_RSAPUBLIC_BLOB;

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, blobType,
					&m_publicKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair public failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair public failed: 0x%08X", st);
					return false;
				}

				m_publicKeyLoaded = true;
				SS_LOG_INFO(L"CryptoUtils", L"Public key loaded successfully");
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::LoadPrivateKey(const PrivateKey& key, Error* err) noexcept {
#ifdef _WIN32
				if (!ensureProvider(err)) return false;

				if (m_privateKeyHandle) {
					BCryptDestroyKey(m_privateKeyHandle);
					m_privateKeyHandle = nullptr;
				}

				// ECC vs RSA blob type selection
				const bool isECC = (key.algorithm == AsymmetricAlgorithm::ECC_P256 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P384 ||
					key.algorithm == AsymmetricAlgorithm::ECC_P521);
				const wchar_t* blobType = isECC ? BCRYPT_ECCPRIVATE_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;

				NTSTATUS st = BCryptImportKeyPair(m_algHandle, nullptr, blobType,
					&m_privateKeyHandle, const_cast<uint8_t*>(key.keyBlob.data()),
					static_cast<ULONG>(key.keyBlob.size()), 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair private failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair private failed: 0x%08X", st);
					return false;
				}
				// NOTE: Private key blob is securely erased after import.
                // Do not rely on key.keyBlob later in the program.
				SecureZeroMemory(const_cast<uint8_t*>(key.keyBlob.data()), key.keyBlob.size());
				const_cast<std::vector<uint8_t>&>(key.keyBlob).clear();
				m_privateKeyLoaded = true;
				SS_LOG_INFO(L"CryptoUtils", L"Private key loaded successfully");
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool AsymmetricCipher::Encrypt(const uint8_t* plaintext, size_t plaintextLen,
				std::vector<uint8_t>& ciphertext,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				// Basic state validation
				if (!m_publicKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key not loaded"; }
					return false;
				}

#ifdef _WIN32
				if (!m_publicKeyHandle) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key handle is null"; }
					return false;
				}

				if (!(m_algorithm == AsymmetricAlgorithm::RSA_2048 ||
					m_algorithm == AsymmetricAlgorithm::RSA_3072 ||
					m_algorithm == AsymmetricAlgorithm::RSA_4096)) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Only RSA encryption is supported"; }
					return false;
				}

				if (!plaintext && plaintextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid plaintext pointer"; }
					return false;
				}

				// Padding setup
				ULONG flags = 0;
				BCRYPT_OAEP_PADDING_INFO oaep{};
				oaep.pbLabel = nullptr;
				oaep.cbLabel = 0;
				const void* pPadInfo = nullptr;

				auto setOaepAlg = [&](RSAPaddingScheme s) -> bool {
					switch (s) {
					case RSAPaddingScheme::OAEP_SHA1:   oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA256: oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA384: oaep.pszAlgId = BCRYPT_SHA384_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA512: oaep.pszAlgId = BCRYPT_SHA512_ALGORITHM; break;
					default: return false;
					}
					return true;
					};

				bool isOAEP = (padding == RSAPaddingScheme::OAEP_SHA1 ||
					padding == RSAPaddingScheme::OAEP_SHA256 ||
					padding == RSAPaddingScheme::OAEP_SHA384 ||
					padding == RSAPaddingScheme::OAEP_SHA512);

				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pPadInfo = nullptr;
				}
				else if (isOAEP) {
					if (!setOaepAlg(padding)) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding scheme"; }
						return false;
					}
					flags = BCRYPT_PAD_OAEP;
					pPadInfo = &oaep;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding for encryption"; }
					return false;
				}

				// Max plaintext size validation using existing helper
				size_t maxPlain = GetMaxPlaintextSize(padding);
				if (plaintextLen > maxPlain) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Plaintext too large"; }
					return false;
				}

				// Query output size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt size query failed"; }
					return false;
				}

				ciphertext.resize(cbResult);
				st = BCryptEncrypt(m_publicKeyHandle,
					const_cast<uint8_t*>(plaintext), static_cast<ULONG>(plaintextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					ciphertext.data(), static_cast<ULONG>(ciphertext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptEncrypt failed"; }
					SecureZeroMemory(ciphertext.data(), ciphertext.size());
					return false;
				}

				ciphertext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}


			bool AsymmetricCipher::Decrypt(const uint8_t* ciphertext, size_t ciphertextLen,
				std::vector<uint8_t>& plaintext,
				RSAPaddingScheme padding,
				Error* err) noexcept
			{
				if (!m_privateKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
					return false;
				}

#ifdef _WIN32
				if (!m_privateKeyHandle) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key handle is null"; }
					return false;
				}


				if (!(m_algorithm == AsymmetricAlgorithm::RSA_2048 ||
					m_algorithm == AsymmetricAlgorithm::RSA_3072 ||
					m_algorithm == AsymmetricAlgorithm::RSA_4096)) {
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Only RSA decryption is supported"; }
					return false;
				}

				if (!ciphertext && ciphertextLen != 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid ciphertext pointer"; }
					return false;
				}

				ULONG flags = 0;
				BCRYPT_OAEP_PADDING_INFO oaep{};
				oaep.pbLabel = nullptr;
				oaep.cbLabel = 0;
				const void* pPadInfo = nullptr;

				auto setOaepAlg = [&](RSAPaddingScheme s) -> bool {
					switch (s) {
					case RSAPaddingScheme::OAEP_SHA1:   oaep.pszAlgId = BCRYPT_SHA1_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA256: oaep.pszAlgId = BCRYPT_SHA256_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA384: oaep.pszAlgId = BCRYPT_SHA384_ALGORITHM; break;
					case RSAPaddingScheme::OAEP_SHA512: oaep.pszAlgId = BCRYPT_SHA512_ALGORITHM; break;
					default: return false;
					}
					return true;
					};

				bool isOAEP = (padding == RSAPaddingScheme::OAEP_SHA1 ||
					padding == RSAPaddingScheme::OAEP_SHA256 ||
					padding == RSAPaddingScheme::OAEP_SHA384 ||
					padding == RSAPaddingScheme::OAEP_SHA512);

				if (padding == RSAPaddingScheme::PKCS1) {
					flags = BCRYPT_PAD_PKCS1;
					pPadInfo = nullptr;
				}
				else if (isOAEP) {
					if (!setOaepAlg(padding)) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding scheme"; }
						return false;
					}
					flags = BCRYPT_PAD_OAEP;
					pPadInfo = &oaep;
				}
				else {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid padding for decryption"; }
					return false;
				}

				// Query output size
				ULONG cbResult = 0;
				NTSTATUS st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					nullptr, 0, &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt size query failed"; }
					return false;
				}

				plaintext.resize(cbResult);
				st = BCryptDecrypt(m_privateKeyHandle,
					const_cast<uint8_t*>(ciphertext), static_cast<ULONG>(ciphertextLen),
					const_cast<void*>(pPadInfo),
					nullptr, 0,
					plaintext.data(), static_cast<ULONG>(plaintext.size()), &cbResult, flags);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDecrypt failed"; }
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				plaintext.resize(cbResult);
				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

				bool AsymmetricCipher::Sign(const uint8_t* data, size_t dataLen,
					std::vector<uint8_t>& signature,
					HashUtils::Algorithm hashAlg,
					RSAPaddingScheme padding,
					Error* err) noexcept
				{
					if (!m_privateKeyLoaded) {
						if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
						return false;
					}

					std::vector<uint8_t> hash;
					if (!HashUtils::Compute(hashAlg, data, dataLen, hash, nullptr)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Hash computation failed"; }
						return false;
					}

#ifdef _WIN32
					//Padding scheme selection
					ULONG flags = 0;
					void* pPaddingInfo = nullptr;

					BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
					BCRYPT_PSS_PADDING_INFO pssInfo{};

					// Map hash algorithm to BCrypt algorithm name
					auto getHashAlgName = [](HashUtils::Algorithm alg) -> LPCWSTR {
						switch (alg) {
						case HashUtils::Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
						case HashUtils::Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
						case HashUtils::Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
						case HashUtils::Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
						default: return nullptr;
						}
						};

					LPCWSTR hashAlgName = getHashAlgName(hashAlg);
					if (!hashAlgName) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported hash algorithm for signing"; }
						return false;
					}

					// Use correct padding struct based on scheme
					if (padding == RSAPaddingScheme::PKCS1) {
						flags = BCRYPT_PAD_PKCS1;
						pkcs1Info.pszAlgId = hashAlgName;
						pPaddingInfo = &pkcs1Info;
					}
					else if (padding == RSAPaddingScheme::PSS_SHA256 ||
						padding == RSAPaddingScheme::PSS_SHA384 ||
						padding == RSAPaddingScheme::PSS_SHA512)
					{
						flags = BCRYPT_PAD_PSS;
						pssInfo.pszAlgId = hashAlgName;
						pssInfo.cbSalt = static_cast<ULONG>(hash.size()); // ✅ CRITICAL: Salt length = hash length (RFC 8017)
						pPaddingInfo = &pssInfo;
					}
					else {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported padding scheme for signing"; }
						return false;
					}

					// Query signature size
					ULONG cbResult = 0;
					NTSTATUS st = BCryptSignHash(m_privateKeyHandle,
						pPaddingInfo,
						hash.data(), static_cast<ULONG>(hash.size()),
						nullptr, 0, &cbResult, flags);

					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"BCryptSignHash size query failed";
							wchar_t tmp[128];
							swprintf_s(tmp, L"NTSTATUS=0x%08X, Padding=%d", static_cast<unsigned>(st), static_cast<int>(padding));
							err->context = tmp;
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptSignHash size query failed: 0x%08X (padding: %d)", st, static_cast<int>(padding));
						return false;
					}

					signature.resize(cbResult);

					// Perform signing
					st = BCryptSignHash(m_privateKeyHandle,
						pPaddingInfo,
						hash.data(), static_cast<ULONG>(hash.size()),
						signature.data(), static_cast<ULONG>(signature.size()), &cbResult, flags);

					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"BCryptSignHash failed";
							wchar_t tmp[256];
							swprintf_s(tmp, L"NTSTATUS=0x%08X, HashLen=%zu, SigLen=%zu, Padding=%d",
								static_cast<unsigned>(st), hash.size(), signature.size(), static_cast<int>(padding));
							err->context = tmp;
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptSignHash failed: 0x%08X (hash: %zu bytes, padding: %d)",
							st, hash.size(), static_cast<int>(padding));
						return false;
					}

					signature.resize(cbResult);

					SS_LOG_INFO(L"CryptoUtils", L"Signature generated successfully (%zu bytes, padding: %d)",
						signature.size(), static_cast<int>(padding));
					return true;

#else
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
					return false;
#endif
				}

				bool AsymmetricCipher::Verify(const uint8_t* data, size_t dataLen,
					const uint8_t* signature, size_t signatureLen,
					HashUtils::Algorithm hashAlg,
					RSAPaddingScheme padding,
					Error* err) noexcept
				{
					if (!m_publicKeyLoaded) {
						if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Public key not loaded"; }
						return false;
					}

					std::vector<uint8_t> hash;
					if (!HashUtils::Compute(hashAlg, data, dataLen, hash, nullptr)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Hash computation failed"; }
						return false;
					}

#ifdef _WIN32
					// Padding scheme selection
					ULONG flags = 0;
					void* pPaddingInfo = nullptr;

					BCRYPT_PKCS1_PADDING_INFO pkcs1Info{};
					BCRYPT_PSS_PADDING_INFO pssInfo{};

					// Map hash algorithm to BCrypt algorithm name
					auto getHashAlgName = [](HashUtils::Algorithm alg) -> LPCWSTR {
						switch (alg) {
						case HashUtils::Algorithm::SHA1:   return BCRYPT_SHA1_ALGORITHM;
						case HashUtils::Algorithm::SHA256: return BCRYPT_SHA256_ALGORITHM;
						case HashUtils::Algorithm::SHA384: return BCRYPT_SHA384_ALGORITHM;
						case HashUtils::Algorithm::SHA512: return BCRYPT_SHA512_ALGORITHM;
						default: return nullptr;
						}
						};

					LPCWSTR hashAlgName = getHashAlgName(hashAlg);
					if (!hashAlgName) {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported hash algorithm for verification"; }
						return false;
					}

					// Use correct padding struct based on scheme
					if (padding == RSAPaddingScheme::PKCS1) {
						flags = BCRYPT_PAD_PKCS1;
						pkcs1Info.pszAlgId = hashAlgName;
						pPaddingInfo = &pkcs1Info;
					}
					else if (padding == RSAPaddingScheme::PSS_SHA256 ||
						padding == RSAPaddingScheme::PSS_SHA384 ||
						padding == RSAPaddingScheme::PSS_SHA512)
					{
						flags = BCRYPT_PAD_PSS;
						pssInfo.pszAlgId = hashAlgName;
						pssInfo.cbSalt = static_cast<ULONG>(hash.size()); // Salt length = hash length
						pPaddingInfo = &pssInfo;
					}
					else {
						if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported padding scheme for verification"; }
						return false;
					}

					// Verify signature
					NTSTATUS st = BCryptVerifySignature(m_publicKeyHandle,
						pPaddingInfo,
						hash.data(), static_cast<ULONG>(hash.size()),
						const_cast<uint8_t*>(signature), static_cast<ULONG>(signatureLen),
						flags);

					if (st < 0) {
						if (err) {
							err->ntstatus = st;
							err->win32 = RtlNtStatusToDosError(st);
							err->message = L"BCryptVerifySignature failed";
							wchar_t tmp[256];
							swprintf_s(tmp, L"NTSTATUS=0x%08X, HashLen=%zu, SigLen=%zu, Padding=%d",
								static_cast<unsigned>(st), hash.size(), signatureLen, static_cast<int>(padding));
							err->context = tmp;
						}
						SS_LOG_ERROR(L"CryptoUtils", L"BCryptVerifySignature failed: 0x%08X (padding: %d)",
							st, static_cast<int>(padding));
						return false;
					}

					SS_LOG_INFO(L"CryptoUtils", L"Signature verified successfully (padding: %d)", static_cast<int>(padding));
					return true;

#else
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
					return false;
#endif
				}

			bool AsymmetricCipher::DeriveSharedSecret(const PublicKey& peerPublicKey,
				std::vector<uint8_t>& sharedSecret,
				Error* err) noexcept
			{
				// Validate that we have a private key loaded
				if (!m_privateKeyLoaded) {
					if (err) { err->win32 = ERROR_INVALID_STATE; err->message = L"Private key not loaded"; }
					return false;
				}

				// Validate algorithm compatibility
				if (m_algorithm != AsymmetricAlgorithm::ECC_P256 &&
					m_algorithm != AsymmetricAlgorithm::ECC_P384 &&
					m_algorithm != AsymmetricAlgorithm::ECC_P521) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"ECDH only supported for ECC algorithms"; }
					return false;
				}

				// Validate peer public key algorithm matches
				if (peerPublicKey.algorithm != m_algorithm) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Peer public key algorithm mismatch"; }
					return false;
				}

				if (peerPublicKey.keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Peer public key is empty"; }
					return false;
				}

#ifdef _WIN32
				// Get the correct algorithm name for ECC
				const wchar_t* algName = nullptr;
				switch (m_algorithm) {
				case AsymmetricAlgorithm::ECC_P256: algName = BCRYPT_ECDH_P256_ALGORITHM; break;
				case AsymmetricAlgorithm::ECC_P384: algName = BCRYPT_ECDH_P384_ALGORITHM; break;
				case AsymmetricAlgorithm::ECC_P521: algName = BCRYPT_ECDH_P521_ALGORITHM; break;
				default:
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unsupported ECC algorithm"; }
					return false;
				}

				// RAII provider(no throw)
				struct EcdhProviderHandle {
					BCRYPT_ALG_HANDLE handle = nullptr;
					NTSTATUS status = 0;

					explicit EcdhProviderHandle(const wchar_t* name) {
						status = BCryptOpenAlgorithmProvider(&handle, name, nullptr, 0);
						if (status < 0) {
							handle = nullptr;
						}
					}
					~EcdhProviderHandle() {
						if (handle) {
							BCryptCloseAlgorithmProvider(handle, 0);
							handle = nullptr;
						}
					}
					EcdhProviderHandle(const EcdhProviderHandle&) = delete;
					EcdhProviderHandle& operator=(const EcdhProviderHandle&) = delete;
					EcdhProviderHandle(EcdhProviderHandle&& other) noexcept {
						handle = other.handle;
						status = other.status;
						other.handle = nullptr;
					}
					bool ok() const { return status >= 0 && handle != nullptr; }
				};

				EcdhProviderHandle provider(algName);
				if (!provider.ok()) {
					if (err) {
						err->ntstatus = provider.status;
						err->win32 = RtlNtStatusToDosError(provider.status);
						err->message = L"ECDH provider init failed";
					}
					SS_LOG_ERROR(L"CryptoUtils", L"ECDH provider init failed: 0x%08X", provider.status);
					return false;
				}

				// Import peer's public key
				BCRYPT_KEY_HANDLE hPeerPublicKey = nullptr;
				NTSTATUS st = BCryptImportKeyPair(provider.handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
					&hPeerPublicKey,
					const_cast<uint8_t*>(peerPublicKey.keyBlob.data()),
					static_cast<ULONG>(peerPublicKey.keyBlob.size()), 0);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptImportKeyPair for peer public key failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptImportKeyPair for peer failed: 0x%08X", st);
					return false; // provider RAII ile kapanacak
				}

				// Derive shared secret using BCryptSecretAgreement
				BCRYPT_SECRET_HANDLE hSecret = nullptr;
				st = BCryptSecretAgreement(m_privateKeyHandle, hPeerPublicKey, &hSecret, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptSecretAgreement failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptSecretAgreement failed: 0x%08X", st);
					BCryptDestroyKey(hPeerPublicKey);
					return false;
				}

				// Derive key material from the secret using RAW secret
				ULONG cbResult = 0;
				st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &cbResult, 0);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKey size query failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptDeriveKey size query failed: 0x%08X", st);
					BCryptDestroySecret(hSecret);
					BCryptDestroyKey(hPeerPublicKey);
					return false;
				}

				sharedSecret.resize(cbResult);

				st = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, nullptr,
					sharedSecret.data(), static_cast<ULONG>(sharedSecret.size()), &cbResult, 0);

				// Cleanup secret + peer key
				BCryptDestroySecret(hSecret);
				BCryptDestroyKey(hPeerPublicKey);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKey failed"; }
					SS_LOG_ERROR(L"CryptoUtils", L"BCryptDeriveKey failed: 0x%08X", st);
					SecureZeroMemory(sharedSecret.data(), sharedSecret.size());
					sharedSecret.clear();
					return false;
				}

				sharedSecret.resize(cbResult);

				SS_LOG_INFO(L"CryptoUtils", L"ECDH shared secret derived successfully (%zu bytes)", sharedSecret.size());
				return true;

#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			size_t AsymmetricCipher::GetMaxPlaintextSize(RSAPaddingScheme padding) const noexcept {
#ifdef _WIN32
				
				ULONG keySizeBits = 0;

				if (m_publicKeyLoaded && m_publicKeyHandle) {
					ULONG cbBlob = 0;
					NTSTATUS st = BCryptExportKey(m_publicKeyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
						nullptr, 0, &cbBlob, 0);
					if (st >= 0 && cbBlob >= sizeof(BCRYPT_RSAKEY_BLOB)) {
						std::vector<uint8_t> blob(cbBlob);
						st = BCryptExportKey(m_publicKeyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
							blob.data(), cbBlob, &cbBlob, 0);
						if (st >= 0 && cbBlob >= sizeof(BCRYPT_RSAKEY_BLOB)) {
							//Parse the blob header securely
							const auto* hdr = reinterpret_cast<const BCRYPT_RSAKEY_BLOB*>(blob.data());
							//Magic and bit length sanity check
							if (hdr->Magic == BCRYPT_RSAPUBLIC_MAGIC && (hdr->BitLength % 8) == 0) {
								const size_t kBytes = static_cast<size_t>(hdr->BitLength / 8);
								const size_t headerSize = sizeof(BCRYPT_RSAKEY_BLOB);
								const size_t expectedMin = headerSize + hdr->cbPublicExp + hdr->cbModulus;
								//Blob size and modulus size consistency check
								if (cbBlob >= expectedMin && hdr->cbModulus == kBytes) {
									keySizeBits = hdr->BitLength;
								}
								else {
									SS_LOG_WARN(L"CryptoUtils",
										L"Inconsistent RSA public blob: cbBlob=%lu, expectedMin=%zu, cbModulus=%lu, kBytes=%zu",
										cbBlob, expectedMin, hdr->cbModulus, kBytes);
									keySizeBits = 0;
								}
							}
							else {
								SS_LOG_WARN(L"CryptoUtils",
									L"Invalid RSA public blob header: Magic=0x%08X, BitLength=%lu",
									hdr->Magic, hdr->BitLength);
								keySizeBits = 0;
							}
						}
					}
				}

				if (keySizeBits == 0) {
					//Algorithm based fallback
					keySizeBits = RSAKeySizeForAlg(m_algorithm);
				}
#else
				const ULONG keySizeBits = RSAKeySizeForAlg(m_algorithm);
#endif

				//for ECC, return a predefined cap
				const bool isECC = (m_algorithm == AsymmetricAlgorithm::ECC_P256 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P384 ||
					m_algorithm == AsymmetricAlgorithm::ECC_P521);
				if (isECC) {
					// use a predefined ECC cap if exists, if not use the default 65536
					const size_t eccCap =
#ifdef HAS_ECC_CAP_MEMBER
						m_eccMaxPlaintextCap
#else
						static_cast<size_t>(65536)
#endif
						;
					return eccCap;
				}

				//bit-> byte conversion for RSA
				if (keySizeBits == 0 || (keySizeBits % 8) != 0) {
					SS_LOG_WARN(L"CryptoUtils", L"Invalid RSA key size bits: %lu", keySizeBits);
					return 0;
				}
				const size_t keySizeBytes = static_cast<size_t>(keySizeBits / 8);
				if (keySizeBytes == 0) return 0;

				// Sanity cap: block the unrealistic key sizes
				const size_t sanityCap = 1024 * 1024; // 1MB
				if (keySizeBytes > sanityCap) {
					SS_LOG_WARN(L"CryptoUtils", L"RSA key size bytes (%zu) exceeded sanity cap (%zu)", keySizeBytes, sanityCap);
					return 0;
				}

				//maximum plaintext size for the given padding
				switch (padding) {
				case RSAPaddingScheme::PKCS1:
					// PKCS#1 v1.5: max = k - 11
					if (keySizeBytes <= 11) return 0;
					return keySizeBytes - 11;

				case RSAPaddingScheme::OAEP_SHA1: {
					const size_t hLen = 20;
					// OAEP: max = k - 2*hLen - 2
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA256: {
					const size_t hLen = 32;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA384: {
					const size_t hLen = 48;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}
				case RSAPaddingScheme::OAEP_SHA512: {
					const size_t hLen = 64;
					if (keySizeBytes <= (2 * hLen + 2)) return 0;
					return keySizeBytes - (2 * hLen) - 2;
				}

				default:
					return 0;
				}
			}


			size_t AsymmetricCipher::GetSignatureSize() const noexcept {
				const ULONG keySize = RSAKeySizeForAlg(m_algorithm);
				return keySize / 8;
			}

			bool KeyDerivation::PBKDF2(const uint8_t* password, size_t passwordLen,
				const uint8_t* salt, size_t saltLen,
				uint32_t iterations,
				HashUtils::Algorithm hashAlg,
				uint8_t* outKey, size_t keyLen,
				Error* err) noexcept
			{
				if (!password || !salt || !outKey || keyLen == 0) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid parameters";
					}
					return false;
				}

				if (saltLen < 8) {
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"Salt length should be at least 8 bytes";
					}
					return false;
				}

#ifdef _WIN32
				// Map HashUtils::Algorithm to BCrypt algorithm
				const wchar_t* algName = BCRYPT_SHA256_ALGORITHM;
				switch (hashAlg) {
				case HashUtils::Algorithm::SHA1:   algName = BCRYPT_SHA1_ALGORITHM; break;
				case HashUtils::Algorithm::SHA256: algName = BCRYPT_SHA256_ALGORITHM; break;
				case HashUtils::Algorithm::SHA384: algName = BCRYPT_SHA384_ALGORITHM; break;
				case HashUtils::Algorithm::SHA512: algName = BCRYPT_SHA512_ALGORITHM; break;
				default: algName = BCRYPT_SHA256_ALGORITHM; break;
				}

				BCRYPT_ALG_HANDLE hAlg = nullptr;
				NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, algName, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptOpenAlgorithmProvider failed"; }
					return false;
				}

				st = BCryptDeriveKeyPBKDF2(hAlg,
					const_cast<uint8_t*>(password), static_cast<ULONG>(passwordLen),
					const_cast<uint8_t*>(salt), static_cast<ULONG>(saltLen),
					iterations,
					outKey, static_cast<ULONG>(keyLen),
					0);

				BCryptCloseAlgorithmProvider(hAlg, 0);

				if (st < 0) {
					if (err) { err->ntstatus = st; err->win32 = RtlNtStatusToDosError(st); err->message = L"BCryptDeriveKeyPBKDF2 failed"; }
					return false;
				}

				return true;
#else
				if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Platform not supported"; }
				return false;
#endif
			}

			bool KeyDerivation::HKDF(const uint8_t* inputKeyMaterial, size_t ikmLen,
				const uint8_t* salt, size_t saltLen,
				const uint8_t* info, size_t infoLen,
				HashUtils::Algorithm hashAlg,
				uint8_t* outKey, size_t keyLen,
				Error* err) noexcept
			{
				if (!inputKeyMaterial || !outKey || keyLen == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid parameters"; }
					return false;
				}

				// HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
				std::vector<uint8_t> prk;
				size_t hashLen = 32; // Default SHA256
				switch (hashAlg) {
				case HashUtils::Algorithm::SHA256: hashLen = 32; break;
				case HashUtils::Algorithm::SHA384: hashLen = 48; break;
				case HashUtils::Algorithm::SHA512: hashLen = 64; break;
				default: hashLen = 32; break;
				}

				prk.resize(hashLen);

				// Use HMAC for extraction
				std::vector<uint8_t> hmacKey;
				if (salt && saltLen > 0) {
					hmacKey.assign(salt, salt + saltLen);
				}
				else {
					hmacKey.assign(hashLen, 0); // Zero-filled salt(RFC 5869 standard).
				}

				// Use ComputeHmac helper (one-shot) instead of non-existent HashUtils::Hmac(...) function
				if (!HashUtils::ComputeHmac(hashAlg, hmacKey.data(), hmacKey.size(),
					inputKeyMaterial, ikmLen, prk, nullptr)) {
					// SECURITY: Clear hmacKey on failure
					SecureZeroMemory(hmacKey.data(), hmacKey.size());
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Extract failed"; }
					return false;
				}

				// SECURITY: Clear hmacKey after use (it may contain salt or zeros)
				SecureZeroMemory(hmacKey.data(), hmacKey.size());
				hmacKey.clear();

				if (keyLen > 255 * hashLen) {
					// SECURITY: Clear prk before returning
					SecureZeroMemory(prk.data(), prk.size());
					if (err) {
						err->win32 = ERROR_INVALID_PARAMETER;
						err->message = L"HKDF keyLen too large";
					}
					return false;
				}


				// HKDF-Expand: OKM = T(1) | T(2) | T(3) | ...
				size_t n = (keyLen + hashLen - 1) / hashLen; // Ceiling division
				std::vector<uint8_t> t;
				std::vector<uint8_t> okm;

				for (size_t i = 1; i <= n; ++i) {
					std::vector<uint8_t> msg;
					msg.insert(msg.end(), t.begin(), t.end());
					if (info && infoLen > 0) {
						msg.insert(msg.end(), info, info + infoLen);
					}
					msg.push_back(static_cast<uint8_t>(i));

					t.resize(hashLen);
					//Use ComputeHmac here as well
					if (!HashUtils::ComputeHmac(hashAlg, prk.data(), prk.size(),
						msg.data(), msg.size(), t, nullptr)) {
						// SECURITY: Clear all intermediate key material on failure
						SecureZeroMemory(prk.data(), prk.size());
						SecureZeroMemory(t.data(), t.size());
						SecureZeroMemory(okm.data(), okm.size());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"HKDF Expand failed"; }
						return false;
					}

					okm.insert(okm.end(), t.begin(), t.end());
				}

				std::memcpy(outKey, okm.data(), keyLen);

				// SECURITY: Clear all intermediate key material
				SecureZeroMemory(prk.data(), prk.size());
				SecureZeroMemory(t.data(), t.size());
				SecureZeroMemory(okm.data(), okm.size());

				return true;
			}

			bool KeyDerivation::DeriveKey(const uint8_t* password, size_t passwordLen,
				const KDFParams& params,
				std::vector<uint8_t>& outKey,
				Error* err) noexcept
			{
				if (!password || passwordLen == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid password"; }
					return false;
				}

				outKey.resize(params.keyLength);

				// Generate salt if not provided
				std::vector<uint8_t> salt = params.salt;
				if (salt.empty()) {
					if (!GenerateSalt(salt, 32, err)) return false;
				}

				switch (params.algorithm) {
				case KDFAlgorithm::PBKDF2_SHA256:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA256,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::PBKDF2_SHA384:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA384,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::PBKDF2_SHA512:
					return PBKDF2(password, passwordLen, salt.data(), salt.size(),
						params.iterations, HashUtils::Algorithm::SHA512,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA256:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA256,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA384:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA384,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::HKDF_SHA512:
					return HKDF(password, passwordLen, salt.data(), salt.size(),
						params.info.data(), params.info.size(),
						HashUtils::Algorithm::SHA512,
						outKey.data(), outKey.size(), err);

				case KDFAlgorithm::Scrypt:
				case KDFAlgorithm::Argon2id:
					if (err) { err->win32 = ERROR_NOT_SUPPORTED; err->message = L"Scrypt/Argon2 not implemented yet"; }
					return false;

				default:
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Unknown KDF algorithm"; }
					return false;
				}
			}

			bool KeyDerivation::DeriveKey(std::string_view password,
				const KDFParams& params,
				std::vector<uint8_t>& outKey,
				Error* err) noexcept
			{
				return DeriveKey(reinterpret_cast<const uint8_t*>(password.data()),
					password.size(), params, outKey, err);
			}

			bool KeyDerivation::GenerateSalt(std::vector<uint8_t>& salt, size_t size, Error* err) noexcept {
				SecureRandom rng;
				return rng.Generate(salt, size, err);
			}

			// =============================================================================
			// PublicKey Implementation
			// =============================================================================
			bool PublicKey::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
				out = keyBlob;
				return true;
			}

			bool PublicKey::ExportPEM(std::string& out, Error* err) const noexcept {
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}

				// Base64 encode the DER blob
				std::string base64 = Base64::Encode(keyBlob);
				if (base64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
					return false;
				}

				// PEM format: header + base64 (64 chars per line) + footer
				std::ostringstream oss;
				oss << "-----BEGIN PUBLIC KEY-----\n";

				// Split base64 into 64-character lines
				const size_t lineWidth = 64;
				for (size_t i = 0; i < base64.size(); i += lineWidth) {
					size_t chunkSize = std::min(lineWidth, base64.size() - i);
					oss << base64.substr(i, chunkSize) << "\n";
				}

				oss << "-----END PUBLIC KEY-----\n";

				out = oss.str();
				return true;
			}

			bool PublicKey::Import(const uint8_t* data, size_t len, PublicKey& out, Error* err) noexcept {
				if (!data || len == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input data"; }
					return false;
				}

				out.keyBlob.assign(data, data + len);
				return true;
			}

			bool PublicKey::ImportPEM(std::string_view pem, PublicKey& out, Error* err) noexcept {
				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Find PEM boundaries
				const std::string_view beginMarker = "-----BEGIN PUBLIC KEY-----";
				const std::string_view endMarker = "-----END PUBLIC KEY-----";

				size_t beginPos = pem.find(beginMarker);
				if (beginPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM begin marker not found"; }
					return false;
				}

				size_t endPos = pem.find(endMarker, beginPos);
				if (endPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM end marker not found"; }
					return false;
				}

				// Extract base64 content (skip header)
				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				// Remove whitespace (newlines, spaces, tabs)
				std::string cleanBase64;
				cleanBase64.reserve(base64Content.size());
				for (char c : base64Content) {
					if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
						cleanBase64.push_back(c);
					}
				}

				if (cleanBase64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM content is empty"; }
					return false;
				}

				// Base64 decode
				std::vector<uint8_t> decoded;
				if (!Base64::Decode(cleanBase64, decoded)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
					return false;
				}

				if (decoded.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decoded data is empty"; }
					return false;
				}

				out.keyBlob = std::move(decoded);
				return true;
			}


			// =============================================================================
			// PrivateKey Implementation
			// =============================================================================

			void PrivateKey::SecureErase() noexcept {
				if (!keyBlob.empty()) {
					SecureZeroMemory(keyBlob.data(), keyBlob.size());
					keyBlob.clear();
				}
			}
			bool PrivateKey::Export(std::vector<uint8_t>& out, Error* err) const noexcept {
				out = keyBlob;
				return true;
			}

			bool PrivateKey::ExportPEM(std::string& out, bool encrypt, std::string_view password, Error* err) const noexcept {
				if (keyBlob.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Key blob is empty"; }
					return false;
				}

				std::vector<uint8_t> dataToEncode = keyBlob;

				// If encryption requested, encrypt the DER blob first
				if (encrypt && !password.empty()) {
					// PKCS#8 encrypted private key format
					// Increase PBKDF2 iterations from 10000 to 600000 (OWASP 2023 recommendation)

					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = 600000; // Production-grade iteration count
					kdfParams.keyLength = 32;

					SecureRandom rng;
					std::vector<uint8_t> salt;
					if (!rng.Generate(salt, 32, err)) return false; // 32 bytes salt instead of 16
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					// SECURITY: Clear key immediately after setting
					SecureZeroMemory(key.data(), key.size());
					key.clear();

					std::vector<uint8_t> iv;
					if (!cipher.GenerateIV(iv, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					if(iv.size() != 16) {
						SecureZeroMemory(salt.data(), salt.size());
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
						return false;
					}
					std::vector<uint8_t> encrypted;
					if (!cipher.Encrypt(keyBlob.data(), keyBlob.size(), encrypted, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						return false;
					}

					// Format now includes iteration count for future-proofing
					// Format: [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
					dataToEncode.clear();
					const uint32_t version = 1;
					const uint32_t iterations = kdfParams.iterations;
					dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&version), reinterpret_cast<const uint8_t*>(&version) + sizeof(version));
					dataToEncode.insert(dataToEncode.end(), reinterpret_cast<const uint8_t*>(&iterations), reinterpret_cast<const uint8_t*>(&iterations) + sizeof(iterations));
					dataToEncode.insert(dataToEncode.end(), salt.begin(), salt.end());
					dataToEncode.insert(dataToEncode.end(), iv.begin(), iv.end());
					dataToEncode.insert(dataToEncode.end(), encrypted.begin(), encrypted.end());

					// SECURITY: Clear sensitive intermediate data
					SecureZeroMemory(salt.data(), salt.size());
				}

				// Base64 encode
				std::string base64 = Base64::Encode(dataToEncode);
				if (base64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 encoding failed"; }
					return false;
				}

				// PEM format
				std::ostringstream oss;
				if (encrypt && !password.empty()) {
					oss << "-----BEGIN ENCRYPTED PRIVATE KEY-----\n";
				}
				else {
					oss << "-----BEGIN PRIVATE KEY-----\n";
				}

				const size_t lineWidth = 64;
				for (size_t i = 0; i < base64.size(); i += lineWidth) {
					size_t chunkSize = std::min(lineWidth, base64.size() - i);
					oss << base64.substr(i, chunkSize) << "\n";
				}

				if (encrypt && !password.empty()) {
					oss << "-----END ENCRYPTED PRIVATE KEY-----\n";
				}
				else {
					oss << "-----END PRIVATE KEY-----\n";
				}

				out = oss.str();
				return true;
			}

			bool PrivateKey::Import(const uint8_t* data, size_t len, PrivateKey& out, Error* err) noexcept {
				if (!data || len == 0) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid input data"; }
					return false;
				}

				out.keyBlob.assign(data, data + len);
				return true;
			}
			// Helper for RSA PRIVATE KEY format
			static bool ImportPEM_RSAFormat(std::string_view pem, PrivateKey& out, std::string_view password, Error* err) noexcept {
				const std::string_view beginMarker = "-----BEGIN RSA PRIVATE KEY-----";
				const std::string_view endMarker = "-----END RSA PRIVATE KEY-----";

				size_t beginPos = pem.find(beginMarker);
				if (beginPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"RSA PEM begin marker not found"; }
					return false;
				}

				size_t endPos = pem.find(endMarker, beginPos);
				if (endPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"RSA PEM end marker not found"; }
					return false;
				}

				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				std::string cleanBase64;
				cleanBase64.reserve(base64Content.size());
				for (char c : base64Content) {
					if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
						cleanBase64.push_back(c);
					}
				}

				std::vector<uint8_t> decoded;
				if (!Base64::Decode(cleanBase64, decoded)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
					return false;
				}

				out.keyBlob = std::move(decoded);
				return true;
			}

			// Minimal ASN.1 sanity checks
			static bool ValidatePKCS1RSAPrivateKey(const std::vector<uint8_t>& der) noexcept {
				// Very light check: must start with SEQUENCE (0x30)
				if (der.size() < 2 || der[0] != 0x30) return false;
				// Optional deeper checks (heuristics): expect INTEGER tags 0x02 somewhere early
				// We keep it minimal to avoid full ASN.1 parsing.
				return true;
			}

			static bool ValidatePKCS8PrivateKeyInfo(const std::vector<uint8_t>& der) noexcept {
				// Very light check: must start with SEQUENCE (0x30)
				if (der.size() < 2 || der[0] != 0x30) return false;
				return true;
			}

			// Read little-endian uint32 safely (portable parsing)
			static uint32_t ReadLE32(const uint8_t* p) noexcept {
				return (static_cast<uint32_t>(p[0])) |
					(static_cast<uint32_t>(p[1]) << 8) |
					(static_cast<uint32_t>(p[2]) << 16) |
					(static_cast<uint32_t>(p[3]) << 24);
			}

			bool PrivateKey::ImportPEM(std::string_view pem,
				PrivateKey& out,
				std::string_view password,
				Error* err) noexcept
			{
				if (pem.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"PEM string is empty"; }
					return false;
				}

				// Detect custom PKCS#8 encrypted vs unencrypted
				const bool isEncrypted = (pem.find("-----BEGIN ENCRYPTED PRIVATE KEY-----") != std::string_view::npos);

				const std::string_view beginMarker = isEncrypted ?
					"-----BEGIN ENCRYPTED PRIVATE KEY-----" :
					"-----BEGIN PRIVATE KEY-----";
				const std::string_view endMarker = isEncrypted ?
					"-----END ENCRYPTED PRIVATE KEY-----" :
					"-----END PRIVATE KEY-----";

				// Fallback to PKCS#1 RSA PRIVATE KEY helper if PKCS#8 markers not found
				if (pem.find(beginMarker) == std::string_view::npos) {
					if (pem.find("-----BEGIN RSA PRIVATE KEY-----") != std::string_view::npos) {
						// Import PKCS#1 (unencrypted) via helper
						if (!ImportPEM_RSAFormat(pem, out, /*password ignored*/ std::string_view{}, err)) return false;
						// Minimal ASN.1 sanity check
						if (!ValidatePKCS1RSAPrivateKey(out.keyBlob)) {
							if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#1 RSA private key"; }
							// Zero sensitive data before returning
							SecureZeroMemory(out.keyBlob.data(), out.keyBlob.size());
							out.keyBlob.clear();
							return false;
						}
						return true;
					}
				}

				// Locate PEM block
				size_t beginPos = pem.find(beginMarker);
				if (beginPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM begin marker not found"; }
					return false;
				}
				size_t endPos = pem.find(endMarker, beginPos);
				if (endPos == std::string_view::npos) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM end marker not found"; }
					return false;
				}

				beginPos += beginMarker.size();
				std::string_view base64Content = pem.substr(beginPos, endPos - beginPos);

				// Clean base64 (strip whitespace/newlines)
				std::string cleanBase64;
				cleanBase64.reserve(base64Content.size());
				for (char c : base64Content) {
					if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
						cleanBase64.push_back(c);
					}
				}
				if (cleanBase64.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"PEM content is empty"; }
					return false;
				}

				// Base64 decode
				std::vector<uint8_t> decoded;
				if (!Base64::Decode(cleanBase64, decoded)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decoding failed"; }
					return false;
				}
				if (decoded.empty()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decoded data is empty"; }
					return false;
				}

				if (isEncrypted) {
					if (password.empty()) {
						if (err) { err->win32 = ERROR_INVALID_PASSWORD; err->message = L"Password required for encrypted key"; }
						// Zero decoded buffer (contains sensitive header and ciphertext)
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					// Custom encrypted PKCS#8 header:
					// [VERSION(4)] + [ITERATIONS(4)] + [SALT(32)] + [IV(16)] + [ENCRYPTED_DATA]
					if (decoded.size() < (4 + 4 + 32 + 16)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data too short"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					size_t offset = 0;
					const uint32_t version = ReadLE32(decoded.data() + offset); offset += 4;
					uint32_t iterations = ReadLE32(decoded.data() + offset); offset += 4;

					// Harden default if version mismatches (old blobs without iteration field should not reach here)
					if (version != 1) {
						// Fallback: enforce strong default
						iterations = 600000;
					}

					// Salt (fixed 32 bytes in v1 format)
					if (decoded.size() < offset + 32 + 16) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Encrypted data format mismatch"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					std::vector<uint8_t> salt(decoded.begin() + offset, decoded.begin() + offset + 32);
					offset += 32;

					// IV (16 bytes for AES-CBC)
					std::vector<uint8_t> iv(decoded.begin() + offset, decoded.begin() + offset + 16);
					offset += 16;

					const uint8_t* encryptedData = decoded.data() + offset;
					const size_t encryptedSize = decoded.size() - offset;

					// Derive key (PBKDF2-SHA256) with hardened iteration count
					if (iterations < 1000) iterations = 600000; // enforce minimum (OWASP 2023)
					KDFParams kdfParams{};
					kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
					kdfParams.iterations = iterations;
					kdfParams.keyLength = 32;
					kdfParams.salt = salt;

					std::vector<uint8_t> key;
					if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) {
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					// Decrypt AES-256-CBC
					SymmetricCipher cipher(SymmetricAlgorithm::AES_256_CBC);
					if (!cipher.SetKey(key, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					if (!cipher.SetIV(iv, err)) {
						SecureZeroMemory(key.data(), key.size());
						SecureZeroMemory(salt.data(), salt.size());
						SecureZeroMemory(iv.data(), iv.size());
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}

					std::vector<uint8_t> decrypted;
					const bool decOk = cipher.Decrypt(encryptedData, encryptedSize, decrypted, err);

					// Zero sensitive buffers regardless of success
					SecureZeroMemory(key.data(), key.size());
					SecureZeroMemory(salt.data(), salt.size());
					SecureZeroMemory(iv.data(), iv.size());
					SecureZeroMemory(decoded.data(), decoded.size());

					if (!decOk) return false;

					// ASN.1 minimal validation (reject obvious garbage)
					if (!ValidatePKCS1RSAPrivateKey(decrypted) && !ValidatePKCS8PrivateKeyInfo(decrypted)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Decrypted data is not a valid private key"; }
						SecureZeroMemory(decrypted.data(), decrypted.size());
						return false;
					}

					out.keyBlob = std::move(decrypted);
					return true;
				}
				else {
					// Unencrypted PKCS#8: minimal ASN.1 sanity
					if (!ValidatePKCS8PrivateKeyInfo(decoded)) {
						if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid PKCS#8 PrivateKeyInfo"; }
						SecureZeroMemory(decoded.data(), decoded.size());
						return false;
					}
					out.keyBlob = std::move(decoded);
					return true;
				}
			}

			// =============================================================================
			// SecureBuffer Implementation
			// =============================================================================
			template<typename T>
			SecureBuffer<T>::SecureBuffer(size_t size) : m_size(0) {
				if (size > 0) allocate(size);
			}

			template<typename T>
			SecureBuffer<T>::~SecureBuffer() {
				deallocate();
			}

			template<typename T>
			SecureBuffer<T>::SecureBuffer(SecureBuffer&& other) noexcept
				: m_data(other.m_data), m_size(other.m_size)
			{
				other.m_data = nullptr;
				other.m_size = 0;
			}

			template<typename T>
			SecureBuffer<T>& SecureBuffer<T>::operator=(SecureBuffer&& other) noexcept {
				if (this != &other) {
					deallocate();
					m_data = other.m_data;
					m_size = other.m_size;
					other.m_data = nullptr;
					other.m_size = 0;
				}
				return *this;
			}

			template<typename T>
			void SecureBuffer<T>::Resize(size_t newSize) {
				if (newSize == m_size) return;
				deallocate();
				if (newSize > 0) allocate(newSize);
			}

			template<typename T>
			void SecureBuffer<T>::Clear() {
				deallocate();
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const T* src, size_t count) {
				Resize(count);
				if (count > 0 && m_data && src) {
					std::memcpy(m_data, src, count * sizeof(T));
				}
			}

			template<typename T>
			void SecureBuffer<T>::CopyFrom(const std::vector<T>& src) {
				CopyFrom(src.data(), src.size());
			}

			template<typename T>
			void SecureBuffer<T>::allocate(size_t size) {
#ifdef _WIN32
				m_data = static_cast<T*>(VirtualAlloc(nullptr, size * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
				if (m_data) {
					m_size = size;
					VirtualLock(m_data, m_size * sizeof(T));
				}
#else
				m_data = static_cast<T*>(std::malloc(size * sizeof(T)));
				if (m_data) m_size = size;
#endif
			}

			template<typename T>
			void SecureBuffer<T>::deallocate() {
				if (m_data) {
					SecureZeroMemory(m_data, m_size * sizeof(T));
#ifdef _WIN32
					VirtualUnlock(m_data, m_size * sizeof(T));
					VirtualFree(m_data, 0, MEM_RELEASE);
#else
					std::free(m_data);
#endif
					m_data = nullptr;
					m_size = 0;
				}
			}

			// Explicit instantiation
			template class SecureBuffer<uint8_t>;
			template class SecureBuffer<char>;
			template class SecureBuffer<wchar_t>;

			// =============================================================================
			// SecureString Implementation	
			// =============================================================================
			SecureString::SecureString(std::string_view str) {
				Assign(str);
			}

			SecureString::SecureString(std::wstring_view str) {
				Assign(str);
			}

			SecureString::~SecureString() {
				Clear();
			}

			SecureString::SecureString(SecureString&& other) noexcept
				: m_buffer(std::move(other.m_buffer))
			{
			}

			SecureString& SecureString::operator=(SecureString&& other) noexcept {
				if (this != &other) {
					m_buffer = std::move(other.m_buffer);
				}
				return *this;
			}

			void SecureString::Assign(std::string_view str) {
				m_buffer.CopyFrom(str.data(), str.size() + 1);
			}

			void SecureString::Assign(std::wstring_view str) {
				// UTF-16 → UTF-8 conversion using Windows API
				if (str.empty()) {
					Clear();
					return;
				}

				int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					nullptr, 0, nullptr, nullptr);
				if (sizeNeeded <= 0) {
					Clear();
					return;
				}

				std::string narrow(sizeNeeded, '\0');
				WideCharToMultiByte(CP_UTF8, 0, str.data(), static_cast<int>(str.size()),
					&narrow[0], sizeNeeded, nullptr, nullptr);

				// Copy to secure buffer
				Assign(narrow);

				// SECURITY: Securely clear the temporary string
				SecureZeroMemory(narrow.data(), narrow.size());
			}

			void SecureString::Clear() {
				m_buffer.Clear();
			}

			std::string_view SecureString::ToStringView() const noexcept {
				if (m_buffer.Empty()) return std::string_view();
				return std::string_view(m_buffer.Data(), m_buffer.Size() > 0 ? m_buffer.Size() - 1 : 0);
			}

			// =============================================================================
			// High-Level File Encryption/Decryption
			// =============================================================================
			bool EncryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err) noexcept
			{
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) return false;

				std::vector<std::byte> plaintext;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, plaintext, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					// SECURITY: Clear plaintext before returning on error
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear plaintext immediately after encryption
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				// Format: [IV_SIZE][IV][TAG_SIZE][TAG][CIPHERTEXT]
				std::vector<std::byte> output;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				// Proper byte conversion
				const std::byte* ivSizeBytes = reinterpret_cast<const std::byte*>(&ivSize);
				const std::byte* tagSizeBytes = reinterpret_cast<const std::byte*>(&tagSize);

				output.insert(output.end(), ivSizeBytes, ivSizeBytes + sizeof(ivSize));
				for (auto b : iv) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
				for (auto b : tag) output.push_back(static_cast<std::byte>(b));
				for (auto b : ciphertext) output.push_back(static_cast<std::byte>(b));

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				return true;
			}

			bool DecryptFile(std::wstring_view inputPath,
				std::wstring_view outputPath,
				const uint8_t* key, size_t keyLen,
				Error* err) noexcept
			{
				// Input validation
				if (!key || keyLen != 32) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key (must be 32 bytes for AES-256)"; }
					return false;
				}

				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}
				
				// size validation
				const size_t minSize = sizeof(uint32_t) * 2 + 12 + 16; // sizes + min salt + min iv + min tag
				if (encrypted.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				// Sanity check IV size
				if (ivSize != 12 || offset + ivSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				// Sanity check tag size
				if (tagSize != 16 || offset + tagSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), encrypted.data() + offset, tagSize);
				offset += tagSize;

				const size_t ciphertextSize = encrypted.size() - offset;
				const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(encrypted.data() + offset);

				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				//uint8_t --> std::byte
				std::vector<std::byte> output;
				output.reserve(plaintext.size());
				std::transform(plaintext.begin(), plaintext.end(), std::back_inserter(output),
					[](uint8_t b) { return static_cast<std::byte>(b); }
				);

				// SECURITY: Clear plaintext after conversion
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					// SECURITY: Clear output buffer on write failure
					SecureZeroMemory(output.data(), output.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				// SECURITY: Clear output buffer after successful write
				SecureZeroMemory(output.data(), output.size());
				return true;
			}

			bool EncryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err) noexcept
			{
				if (password.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Password is empty"; }
					return false;
				}

				// Derive encryption key using PBKDF2
				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = 600000; // OWASP 2023 recommendation
				kdfParams.keyLength = 32; // AES-256

				SecureRandom rng;
				std::vector<uint8_t> salt;
				if (!rng.Generate(salt, 32, err)) return false;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				// Read input file
				std::vector<std::byte> plaintext;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, plaintext, &fileErr)) {
					// SECURITY: Clear key on failure
					SecureZeroMemory(key.data(), key.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read input file"; }
					return false;
				}

				// Encrypt with AES-256-GCM
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, err)) {
					SecureZeroMemory(key.data(), key.size());
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear key immediately after setting in cipher
				SecureZeroMemory(key.data(), key.size());
				key.clear();

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) {
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					// SECURITY: Clear plaintext on encryption failure
					SecureZeroMemory(plaintext.data(), plaintext.size());
					return false;
				}

				// SECURITY: Clear plaintext immediately after encryption
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				// Format: [SALT_SIZE(4)][SALT][ITERATIONS(4)][IV_SIZE(4)][IV][TAG_SIZE(4)][TAG][CIPHERTEXT]
				std::vector<std::byte> output;
				const uint32_t saltSize = static_cast<uint32_t>(salt.size());
				const uint32_t iterations = kdfParams.iterations;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				const std::byte* saltSizeBytes = reinterpret_cast<const std::byte*>(&saltSize);
				const std::byte* iterationsBytes = reinterpret_cast<const std::byte*>(&iterations);
				const std::byte* ivSizeBytes = reinterpret_cast<const std::byte*>(&ivSize);
				const std::byte* tagSizeBytes = reinterpret_cast<const std::byte*>(&tagSize);

				output.insert(output.end(), saltSizeBytes, saltSizeBytes + sizeof(saltSize));
				for (auto b : salt) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), iterationsBytes, iterationsBytes + sizeof(iterations));
				output.insert(output.end(), ivSizeBytes, ivSizeBytes + sizeof(ivSize));
				for (auto b : iv) output.push_back(static_cast<std::byte>(b));
				output.insert(output.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
				for (auto b : tag) output.push_back(static_cast<std::byte>(b));
				for (auto b : ciphertext) output.push_back(static_cast<std::byte>(b));

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				// SECURITY: Clear salt after use (key already cleared earlier)
				SecureZeroMemory(salt.data(), salt.size());
				return true;
			}

			bool DecryptFileWithPassword(std::wstring_view inputPath,
				std::wstring_view outputPath,
				std::string_view password,
				Error* err) noexcept
			{
				if (password.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Password is empty"; }
					return false;
				}

				// Read encrypted file
				std::vector<std::byte> encrypted;
				FileUtils::Error fileErr{};
				if (!FileUtils::ReadAllBytes(inputPath, encrypted, &fileErr)) {
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to read encrypted file"; }
					return false;
				}

				// Parse header: [SALT_SIZE(4)][SALT][ITERATIONS(4)][IV_SIZE(4)][IV][TAG_SIZE(4)][TAG][CIPHERTEXT]
				const size_t minSize = sizeof(uint32_t) * 4 + 32 + 12 + 16; // sizes + min salt + min iv + min tag
				if (encrypted.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted file format"; }
					return false;
				}

				size_t offset = 0;

				// Read salt size and salt
				uint32_t saltSize = 0;
				std::memcpy(&saltSize, encrypted.data() + offset, sizeof(saltSize));
				offset += sizeof(saltSize);

				if (saltSize > 128 || offset + saltSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid salt size"; }
					return false;
				}

				std::vector<uint8_t> salt(saltSize);
				std::memcpy(salt.data(), encrypted.data() + offset, saltSize);
				offset += saltSize;

				// Read iterations
				uint32_t iterations = 0;
				std::memcpy(&iterations, encrypted.data() + offset, sizeof(iterations));
				offset += sizeof(iterations);

				if (iterations < 10000 || iterations > 10000000) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid iteration count"; }
					return false;
				}

				// Read IV size and IV
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, encrypted.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				if (ivSize != 12 || offset + ivSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), encrypted.data() + offset, ivSize);
				offset += ivSize;

				// Read tag size and tag
				uint32_t tagSize = 0;
				std::memcpy(&tagSize, encrypted.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				if (tagSize != 16 || offset + tagSize > encrypted.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), encrypted.data() + offset, tagSize);
				offset += tagSize;

				const size_t ciphertextSize = encrypted.size() - offset;
				const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(encrypted.data() + offset);

				// Derive key
				KDFParams kdfParams{};
				kdfParams.algorithm = KDFAlgorithm::PBKDF2_SHA256;
				kdfParams.iterations = iterations;
				kdfParams.keyLength = 32;
				kdfParams.salt = salt;

				std::vector<uint8_t> key;
				if (!KeyDerivation::DeriveKey(password, kdfParams, key, err)) return false;

				// Decrypt
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, err)) {
					SecureZeroMemory(key.data(), key.size());
					return false;
				}

				// SECURITY: Clear key immediately after setting in cipher
				SecureZeroMemory(key.data(), key.size());
				key.clear();

				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				// Convert to std::byte
				std::vector<std::byte> output;
				output.reserve(plaintext.size());
				std::transform(plaintext.begin(), plaintext.end(), std::back_inserter(output),
					[](uint8_t b) { return static_cast<std::byte>(b); }
				);

				// SECURITY: Clear plaintext after conversion
				SecureZeroMemory(plaintext.data(), plaintext.size());
				plaintext.clear();

				if (!FileUtils::WriteAllBytesAtomic(outputPath, output, &fileErr)) {
					// SECURITY: Clear output on write failure
					SecureZeroMemory(output.data(), output.size());
					if (err) { err->win32 = fileErr.win32; err->message = L"Failed to write output file"; }
					return false;
				}

				// SECURITY: Clear output buffer after successful write
				SecureZeroMemory(output.data(), output.size());
				return true;
			}

			bool EncryptString(std::string_view plaintext,
				const uint8_t* key, size_t keyLen,
				std::string& outBase64Ciphertext,
				Error* err) noexcept
			{
				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;

				std::vector<uint8_t> iv;
				if (!cipher.GenerateIV(iv, err)) return false;

				std::vector<uint8_t> ciphertext, tag;
				if (!cipher.EncryptAEAD(reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
					nullptr, 0, ciphertext, tag, err))
				{
					return false;
				}

				std::vector<uint8_t> combined;
				const uint32_t ivSize = static_cast<uint32_t>(iv.size());
				const uint32_t tagSize = static_cast<uint32_t>(tag.size());

				combined.insert(combined.end(), reinterpret_cast<const uint8_t*>(&ivSize), reinterpret_cast<const uint8_t*>(&ivSize) + sizeof(ivSize));
				combined.insert(combined.end(), iv.begin(), iv.end());
				combined.insert(combined.end(), reinterpret_cast<const uint8_t*>(&tagSize), reinterpret_cast<const uint8_t*>(&tagSize) + sizeof(tagSize));
				combined.insert(combined.end(), tag.begin(), tag.end());
				combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());

				outBase64Ciphertext = Base64::Encode(combined);
				return true;
			}

			bool DecryptString(std::string_view base64Ciphertext,
				const uint8_t* key, size_t keyLen,
				std::string& outPlaintext,
				Error* err) noexcept
			{
				// Input validation
				if (!key || keyLen != 32) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Invalid key (must be 32 bytes)"; }
					return false;
				}

				if (base64Ciphertext.empty()) {
					if (err) { err->win32 = ERROR_INVALID_PARAMETER; err->message = L"Empty ciphertext"; }
					return false;
				}

				std::vector<uint8_t> combined;
				if (!Base64::Decode(base64Ciphertext, combined)) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Base64 decode failed"; }
					return false;
				}

				const size_t minSize = sizeof(uint32_t) * 2 + 12 + 16;
				if (combined.size() < minSize) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid encrypted data format"; }
					return false;
				}

				size_t offset = 0;
				uint32_t ivSize = 0;
				std::memcpy(&ivSize, combined.data() + offset, sizeof(ivSize));
				offset += sizeof(ivSize);

				// Validate IV size
				if (ivSize != 12 || offset + ivSize > combined.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid IV size"; }
					return false;
				}

				std::vector<uint8_t> iv(ivSize);
				std::memcpy(iv.data(), combined.data() + offset, ivSize);
				offset += ivSize;

				uint32_t tagSize = 0;
				std::memcpy(&tagSize, combined.data() + offset, sizeof(tagSize));
				offset += sizeof(tagSize);

				// Validate tag size
				if (tagSize != 16 || offset + tagSize > combined.size()) {
					if (err) { err->win32 = ERROR_INVALID_DATA; err->message = L"Invalid tag size"; }
					return false;
				}

				std::vector<uint8_t> tag(tagSize);
				std::memcpy(tag.data(), combined.data() + offset, tagSize);
				offset += tagSize;

				const size_t ciphertextSize = combined.size() - offset;
				const uint8_t* ciphertext = combined.data() + offset;

				SymmetricCipher cipher(SymmetricAlgorithm::AES_256_GCM);
				if (!cipher.SetKey(key, keyLen, err)) return false;
				if (!cipher.SetIV(iv, err)) return false;

				std::vector<uint8_t> plaintext;
				if (!cipher.DecryptAEAD(ciphertext, ciphertextSize, nullptr, 0, tag.data(), tag.size(), plaintext, err)) {
					return false;
				}

				outPlaintext.assign(reinterpret_cast<const char*>(plaintext.data()), plaintext.size());

				// SECURITY: Clear plaintext vector after assignment
				SecureZeroMemory(plaintext.data(), plaintext.size());
				return true;
			}

			}
			}
			}