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
 * ShadowStrike Security - CRYPTOGRAPHIC OPERATIONS MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file CryptoManager.cpp
 * @brief Enterprise-grade cryptographic operations manager implementation.
 *
 * Implements comprehensive cryptographic services using Windows CNG
 * (Cryptography Next Generation) API with hardware acceleration support.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "CryptoManager.hpp"

#include "../Utils/FileUtils.hpp"
#include "../Utils/StringUtils.hpp"

#include <sstream>
#include <iomanip>
#include <random>
#include <algorithm>
#include <cstring>
#include <intrin.h>
#include <wintrust.h>
#include <softpub.h>

// Link with required libraries
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

namespace ShadowStrike {
namespace Security {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================

static constexpr const wchar_t* LOG_CATEGORY = L"CryptoManager";

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {

    /// Maximum key ID length
    constexpr size_t MAX_KEY_ID_LENGTH = 64;

    /// File chunk size for streaming operations
    constexpr size_t FILE_CHUNK_SIZE = 64 * 1024;  // 64 KB

    /// NT Status success
    constexpr NTSTATUS STATUS_SUCCESS = 0;

    /**
     * @brief Internal atomic statistics (thread-safe counters for the impl).
     * The public CryptoManagerStatistics uses plain uint64_t snapshots.
     */
    struct InternalCryptoStats {
        std::atomic<uint64_t> totalEncryptions{0};
        std::atomic<uint64_t> totalDecryptions{0};
        std::atomic<uint64_t> totalHashes{0};
        std::atomic<uint64_t> totalSignatures{0};
        std::atomic<uint64_t> totalVerifications{0};
        std::atomic<uint64_t> totalKeyGenerations{0};
        std::atomic<uint64_t> totalKeyDerivations{0};
        std::atomic<uint64_t> totalRandomBytes{0};
        std::atomic<uint64_t> authenticationFailures{0};
        std::atomic<uint64_t> hardwareAccelerationOps{0};
        std::atomic<uint64_t> tpmOperations{0};
        std::atomic<size_t> activeKeys{0};
        TimePoint startTime = Clock::now();

        [[nodiscard]] CryptoManagerStatistics Snapshot() const noexcept {
            CryptoManagerStatistics snap;
            snap.totalEncryptions = totalEncryptions.load(std::memory_order_relaxed);
            snap.totalDecryptions = totalDecryptions.load(std::memory_order_relaxed);
            snap.totalHashes = totalHashes.load(std::memory_order_relaxed);
            snap.totalSignatures = totalSignatures.load(std::memory_order_relaxed);
            snap.totalVerifications = totalVerifications.load(std::memory_order_relaxed);
            snap.totalKeyGenerations = totalKeyGenerations.load(std::memory_order_relaxed);
            snap.totalKeyDerivations = totalKeyDerivations.load(std::memory_order_relaxed);
            snap.totalRandomBytes = totalRandomBytes.load(std::memory_order_relaxed);
            snap.authenticationFailures = authenticationFailures.load(std::memory_order_relaxed);
            snap.hardwareAccelerationOps = hardwareAccelerationOps.load(std::memory_order_relaxed);
            snap.tpmOperations = tpmOperations.load(std::memory_order_relaxed);
            snap.activeKeys = activeKeys.load(std::memory_order_relaxed);
            snap.startTime = startTime;
            return snap;
        }

        void Reset() noexcept {
            totalEncryptions.store(0, std::memory_order_relaxed);
            totalDecryptions.store(0, std::memory_order_relaxed);
            totalHashes.store(0, std::memory_order_relaxed);
            totalSignatures.store(0, std::memory_order_relaxed);
            totalVerifications.store(0, std::memory_order_relaxed);
            totalKeyGenerations.store(0, std::memory_order_relaxed);
            totalKeyDerivations.store(0, std::memory_order_relaxed);
            totalRandomBytes.store(0, std::memory_order_relaxed);
            authenticationFailures.store(0, std::memory_order_relaxed);
            hardwareAccelerationOps.store(0, std::memory_order_relaxed);
            tpmOperations.store(0, std::memory_order_relaxed);
            activeKeys.store(0, std::memory_order_relaxed);
            startTime = Clock::now();
        }
    };

    /**
     * @brief JSON-escape a string to prevent injection.
     * Escapes: \\ \" \n \r \t \b \f and control characters < 0x20.
     */
    [[nodiscard]] std::string JsonEscape(std::string_view input) {
        std::string out;
        out.reserve(input.size() + 8);
        for (char ch : input) {
            switch (ch) {
                case '\\': out += "\\\\"; break;
                case '"':  out += "\\\""; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                case '\b': out += "\\b";  break;
                case '\f': out += "\\f";  break;
                default:
                    if (static_cast<unsigned char>(ch) < 0x20) {
                        char buf[8];
                        snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(ch)));
                        out += buf;
                    } else {
                        out += ch;
                    }
                    break;
            }
        }
        return out;
    }

    /**
     * @brief RAII wrapper for BCrypt algorithm handles
     */
    class BCryptAlgorithmHandle {
    public:
        BCryptAlgorithmHandle() = default;

        ~BCryptAlgorithmHandle() {
            Close();
        }

        BCryptAlgorithmHandle(const BCryptAlgorithmHandle&) = delete;
        BCryptAlgorithmHandle& operator=(const BCryptAlgorithmHandle&) = delete;

        BCryptAlgorithmHandle(BCryptAlgorithmHandle&& other) noexcept
            : m_handle(other.m_handle) {
            other.m_handle = nullptr;
        }

        BCryptAlgorithmHandle& operator=(BCryptAlgorithmHandle&& other) noexcept {
            if (this != &other) {
                Close();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        [[nodiscard]] bool Open(LPCWSTR algorithmId, LPCWSTR implementation = nullptr,
                                DWORD flags = 0) {
            Close();
            NTSTATUS status = BCryptOpenAlgorithmProvider(&m_handle, algorithmId,
                                                          implementation, flags);
            return NT_SUCCESS(status);
        }

        void Close() {
            if (m_handle) {
                BCryptCloseAlgorithmProvider(m_handle, 0);
                m_handle = nullptr;
            }
        }

        [[nodiscard]] BCRYPT_ALG_HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] bool IsValid() const noexcept { return m_handle != nullptr; }
        [[nodiscard]] operator BCRYPT_ALG_HANDLE() const noexcept { return m_handle; }

    private:
        BCRYPT_ALG_HANDLE m_handle = nullptr;
    };

    /**
     * @brief RAII wrapper for BCrypt key handles
     */
    class BCryptKeyHandle {
    public:
        BCryptKeyHandle() = default;

        ~BCryptKeyHandle() {
            Close();
        }

        BCryptKeyHandle(const BCryptKeyHandle&) = delete;
        BCryptKeyHandle& operator=(const BCryptKeyHandle&) = delete;

        BCryptKeyHandle(BCryptKeyHandle&& other) noexcept
            : m_handle(other.m_handle), m_keyObject(std::move(other.m_keyObject)) {
            other.m_handle = nullptr;
        }

        BCryptKeyHandle& operator=(BCryptKeyHandle&& other) noexcept {
            if (this != &other) {
                Close();
                m_handle = other.m_handle;
                m_keyObject = std::move(other.m_keyObject);
                other.m_handle = nullptr;
            }
            return *this;
        }

        void Close() {
            if (m_handle) {
                BCryptDestroyKey(m_handle);
                m_handle = nullptr;
            }
            if (!m_keyObject.empty()) {
                SecureZeroMemory(m_keyObject.data(), m_keyObject.size());
                m_keyObject.clear();
            }
        }

        [[nodiscard]] BCRYPT_KEY_HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] BCRYPT_KEY_HANDLE* GetAddressOf() noexcept { return &m_handle; }
        [[nodiscard]] bool IsValid() const noexcept { return m_handle != nullptr; }
        [[nodiscard]] operator BCRYPT_KEY_HANDLE() const noexcept { return m_handle; }

        void SetKeyObject(std::vector<uint8_t>&& keyObj) {
            m_keyObject = std::move(keyObj);
        }

        [[nodiscard]] uint8_t* GetKeyObjectBuffer() {
            return m_keyObject.empty() ? nullptr : m_keyObject.data();
        }

        void ResizeKeyObject(size_t size) {
            m_keyObject.resize(size);
        }

    private:
        BCRYPT_KEY_HANDLE m_handle = nullptr;
        std::vector<uint8_t> m_keyObject;
    };

    /**
     * @brief RAII wrapper for BCrypt hash handles
     */
    class BCryptHashHandle {
    public:
        BCryptHashHandle() = default;

        ~BCryptHashHandle() {
            Close();
        }

        BCryptHashHandle(const BCryptHashHandle&) = delete;
        BCryptHashHandle& operator=(const BCryptHashHandle&) = delete;

        void Close() {
            if (m_handle) {
                BCryptDestroyHash(m_handle);
                m_handle = nullptr;
            }
            if (!m_hashObject.empty()) {
                SecureZeroMemory(m_hashObject.data(), m_hashObject.size());
                m_hashObject.clear();
            }
        }

        [[nodiscard]] BCRYPT_HASH_HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] BCRYPT_HASH_HANDLE* GetAddressOf() noexcept { return &m_handle; }
        [[nodiscard]] bool IsValid() const noexcept { return m_handle != nullptr; }

        void SetHashObject(std::vector<uint8_t>&& hashObj) {
            m_hashObject = std::move(hashObj);
        }

        [[nodiscard]] uint8_t* GetHashObjectBuffer() {
            return m_hashObject.empty() ? nullptr : m_hashObject.data();
        }

        void ResizeHashObject(size_t size) {
            m_hashObject.resize(size);
        }

    private:
        BCRYPT_HASH_HANDLE m_handle = nullptr;
        std::vector<uint8_t> m_hashObject;
    };

    /**
     * @brief Generate UUID for key IDs
     */
    [[nodiscard]] std::string GenerateKeyId() {
        UUID uuid;
        if (UuidCreate(&uuid) != RPC_S_OK) {
            // Fallback: use CSPRNG instead of mt19937 (CRITICAL: mt19937 is not cryptographically secure)
            uint8_t randomBytes[16]{};
            NTSTATUS status = BCryptGenRandom(
                nullptr, randomBytes, sizeof(randomBytes),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
            if (!NT_SUCCESS(status)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"GenerateKeyId: BCryptGenRandom fallback failed, NTSTATUS=0x%08X", status);
                return "";
            }
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (uint8_t b : randomBytes) {
                oss << std::setw(2) << static_cast<int>(b);
            }
            return oss.str();
        }

        RPC_CSTR uuidStr = nullptr;
        if (UuidToStringA(&uuid, &uuidStr) == RPC_S_OK) {
            std::string result(reinterpret_cast<char*>(uuidStr));
            RpcStringFreeA(&uuidStr);
            return result;
        }

        return "";
    }

    /**
     * @brief Convert bytes to hex string
     */
    [[nodiscard]] std::string BytesToHex(std::span<const uint8_t> data) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (uint8_t byte : data) {
            oss << std::setw(2) << static_cast<int>(byte);
        }
        return oss.str();
    }

    /**
     * @brief RAII wrapper for Win32 file handles (prevents handle leaks on exceptions/early returns)
     */
    class ScopedFileHandle {
    public:
        explicit ScopedFileHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : m_handle(h) {}
        ~ScopedFileHandle() { if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
        ScopedFileHandle(const ScopedFileHandle&) = delete;
        ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;
        [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
        [[nodiscard]] bool IsValid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
    private:
        HANDLE m_handle;
    };

}  // anonymous namespace

// ============================================================================
// MANAGED KEY STRUCTURE
// ============================================================================

struct ManagedKey {
    std::string id;
    KeyMetadata metadata;
    std::vector<uint8_t> keyData;
    std::vector<uint8_t> protectedData;
    NCRYPT_KEY_HANDLE ncryptHandle = 0;

    ManagedKey() = default;

    ~ManagedKey() {
        if (!keyData.empty()) {
            SecureZeroMemory(keyData.data(), keyData.size());
            keyData.clear();
        }
        if (ncryptHandle) {
            NCryptFreeObject(ncryptHandle);
            ncryptHandle = 0;
        }
    }

    ManagedKey(const ManagedKey&) = delete;
    ManagedKey& operator=(const ManagedKey&) = delete;

    ManagedKey(ManagedKey&& other) noexcept
        : id(std::move(other.id))
        , metadata(std::move(other.metadata))
        , keyData(std::move(other.keyData))
        , protectedData(std::move(other.protectedData))
        , ncryptHandle(other.ncryptHandle) {
        other.ncryptHandle = 0;
        if (!other.keyData.empty()) {
            SecureZeroMemory(other.keyData.data(), other.keyData.size());
            other.keyData.clear();
        }
    }

    ManagedKey& operator=(ManagedKey&& other) noexcept {
        if (this != &other) {
            if (!keyData.empty()) {
                SecureZeroMemory(keyData.data(), keyData.size());
            }
            if (ncryptHandle) {
                NCryptFreeObject(ncryptHandle);
            }
            id = std::move(other.id);
            metadata = std::move(other.metadata);
            keyData = std::move(other.keyData);
            protectedData = std::move(other.protectedData);
            ncryptHandle = other.ncryptHandle;
            other.ncryptHandle = 0;
            if (!other.keyData.empty()) {
                SecureZeroMemory(other.keyData.data(), other.keyData.size());
                other.keyData.clear();
            }
        }
        return *this;
    }
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class CryptoManagerImpl {
public:
    CryptoManagerImpl();
    ~CryptoManagerImpl();

    [[nodiscard]] bool Initialize(const CryptoManagerConfiguration& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    [[nodiscard]] bool SetConfiguration(const CryptoManagerConfiguration& config);
    [[nodiscard]] CryptoManagerConfiguration GetConfiguration() const;

    [[nodiscard]] EncryptionResult Encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> key,
        SymmetricAlgorithm algorithm,
        std::span<const uint8_t> iv,
        std::span<const uint8_t> aad);

    [[nodiscard]] DecryptionResult Decrypt(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> key,
        SymmetricAlgorithm algorithm,
        std::span<const uint8_t> iv,
        std::span<const uint8_t> tag,
        std::span<const uint8_t> aad);

    [[nodiscard]] CryptoResult EncryptFile(
        std::wstring_view inputPath,
        std::wstring_view outputPath,
        std::span<const uint8_t> key,
        SymmetricAlgorithm algorithm);

    [[nodiscard]] CryptoResult DecryptFile(
        std::wstring_view inputPath,
        std::wstring_view outputPath,
        std::span<const uint8_t> key,
        SymmetricAlgorithm algorithm);

    [[nodiscard]] EncryptionResult RSAEncrypt(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> publicKey,
        RSAPadding padding);

    [[nodiscard]] DecryptionResult RSADecrypt(
        std::span<const uint8_t> ciphertext,
        const std::string& privateKeyId,
        RSAPadding padding);

    [[nodiscard]] std::optional<std::vector<uint8_t>> ECDHKeyAgreement(
        std::span<const uint8_t> peerPublicKey,
        const std::string& privateKeyId);

    [[nodiscard]] SignatureResult Sign(
        std::span<const uint8_t> data,
        const std::string& privateKeyId,
        HashAlgorithm hashAlgorithm);

    [[nodiscard]] bool Verify(
        std::span<const uint8_t> data,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> publicKey,
        HashAlgorithm hashAlgorithm);

    [[nodiscard]] SignatureResult SignEd25519(
        std::span<const uint8_t> data,
        const std::string& privateKeyId);

    [[nodiscard]] bool VerifyEd25519(
        std::span<const uint8_t> data,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> publicKey);

    [[nodiscard]] std::vector<uint8_t> Hash(
        std::span<const uint8_t> data,
        HashAlgorithm algorithm);

    [[nodiscard]] Hash256 SHA256Hash(std::span<const uint8_t> data);
    [[nodiscard]] Hash384 SHA384Hash(std::span<const uint8_t> data);
    [[nodiscard]] Hash512 SHA512Hash(std::span<const uint8_t> data);

    [[nodiscard]] std::vector<uint8_t> ComputeHMAC(
        std::span<const uint8_t> data,
        std::span<const uint8_t> key,
        HashAlgorithm algorithm);

    [[nodiscard]] bool VerifyHMAC(
        std::span<const uint8_t> data,
        std::span<const uint8_t> expectedMAC,
        std::span<const uint8_t> key,
        HashAlgorithm algorithm);

    [[nodiscard]] std::optional<std::vector<uint8_t>> HashFile(
        std::wstring_view filePath,
        HashAlgorithm algorithm);

    [[nodiscard]] std::vector<uint8_t> GenerateRandomBytes(size_t length);
    [[nodiscard]] Nonce96 GenerateNonce();
    [[nodiscard]] IV128 GenerateIV();
    [[nodiscard]] Salt256 GenerateSalt();
    [[nodiscard]] uint32_t GenerateRandomUInt32();
    [[nodiscard]] uint64_t GenerateRandomUInt64();

    [[nodiscard]] KeyGenerationResult GenerateSymmetricKey(
        SymmetricAlgorithm algorithm,
        KeyStorage storage);

    [[nodiscard]] KeyGenerationResult GenerateRSAKeyPair(
        uint32_t keySizeBits,
        KeyStorage storage);

    [[nodiscard]] KeyGenerationResult GenerateECDSAKeyPair(
        AsymmetricAlgorithm curve,
        KeyStorage storage);

    [[nodiscard]] KeyGenerationResult GenerateEd25519KeyPair(KeyStorage storage);
    [[nodiscard]] KeyGenerationResult GenerateX25519KeyPair(KeyStorage storage);

    [[nodiscard]] std::vector<uint8_t> DeriveKey(
        std::string_view password,
        std::span<const uint8_t> salt,
        const KDFParameters& params);

    [[nodiscard]] std::vector<uint8_t> ComputeHKDF(
        std::span<const uint8_t> inputKeyMaterial,
        std::span<const uint8_t> salt,
        std::span<const uint8_t> info,
        size_t outputLength,
        HashAlgorithm algorithm);

    [[nodiscard]] std::string HashPassword(
        std::string_view password,
        KDFAlgorithm algorithm);

    [[nodiscard]] bool VerifyPassword(
        std::string_view password,
        std::string_view hash);

    [[nodiscard]] std::string StoreKey(
        std::span<const uint8_t> keyData,
        KeyType type,
        KeyStorage storage,
        std::string_view description);

    [[nodiscard]] std::optional<std::vector<uint8_t>> RetrieveKey(const std::string& keyId);
    [[nodiscard]] bool DeleteKey(const std::string& keyId);
    [[nodiscard]] std::optional<KeyMetadata> GetKeyMetadata(const std::string& keyId) const;
    [[nodiscard]] std::vector<KeyMetadata> ListKeys() const;
    [[nodiscard]] std::string RotateKey(const std::string& oldKeyId);

    [[nodiscard]] std::optional<std::vector<uint8_t>> ExportKey(
        const std::string& keyId,
        std::span<const uint8_t> wrappingKey);

    [[nodiscard]] std::string ImportKey(
        std::span<const uint8_t> wrappedKey,
        std::span<const uint8_t> wrappingKey,
        KeyType type,
        KeyStorage storage);

    [[nodiscard]] std::optional<std::vector<uint8_t>> DPAPIProtect(
        std::span<const uint8_t> data,
        std::span<const uint8_t> entropy);

    [[nodiscard]] std::optional<std::vector<uint8_t>> DPAPIUnprotect(
        std::span<const uint8_t> protectedData,
        std::span<const uint8_t> entropy);

    [[nodiscard]] bool IsTPMAvailable() const;
    [[nodiscard]] std::string CreateTPMKey(KeyType type);
    [[nodiscard]] std::optional<std::vector<uint8_t>> TPMSeal(std::span<const uint8_t> data);
    [[nodiscard]] std::optional<std::vector<uint8_t>> TPMUnseal(std::span<const uint8_t> sealedData);

    [[nodiscard]] void* SecureAlloc(size_t size);
    void SecureFree(void* ptr, size_t size);
    void SecureZero(void* ptr, size_t size);
    [[nodiscard]] bool ConstantTimeCompare(
        std::span<const uint8_t> a,
        std::span<const uint8_t> b) noexcept;

    [[nodiscard]] bool IsHardwareAccelerationAvailable() const;
    [[nodiscard]] bool IsFIPSModeEnabled() const;
    [[nodiscard]] std::vector<std::string> GetSupportedAlgorithms() const;

    void SetKeyRotationCallback(KeyRotationCallback callback);
    void SetAuditCallback(CryptoAuditCallback callback);

    [[nodiscard]] CryptoManagerStatistics GetStatistics() const;
    void ResetStatistics();
    [[nodiscard]] bool SelfTest();

    // Kernel channel attestation APIs
    [[nodiscard]] std::optional<CryptoManager::KernelSessionKeyResult> DeriveKernelSessionKey(
        std::span<const uint8_t> driverPublicKey,
        std::span<const uint8_t> driverHash,
        std::string_view contextLabel);
    [[nodiscard]] bool VerifyKernelMessageIntegrity(
        std::span<const uint8_t> message,
        std::span<const uint8_t> hmac,
        std::span<const uint8_t> sessionKey);
    [[nodiscard]] std::vector<uint8_t> ComputeKernelMessageHMAC(
        std::span<const uint8_t> message,
        std::span<const uint8_t> sessionKey);
    [[nodiscard]] bool ValidateKernelDriverAttestation(
        const std::wstring& driverPath,
        std::span<const uint8_t> expectedHash);

private:
    mutable std::shared_mutex m_configMutex;
    CryptoManagerConfiguration m_config;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};

    mutable std::shared_mutex m_algMutex;
    BCryptAlgorithmHandle m_aesAlg;
    BCryptAlgorithmHandle m_sha256Alg;
    BCryptAlgorithmHandle m_sha384Alg;
    BCryptAlgorithmHandle m_sha512Alg;
    BCryptAlgorithmHandle m_rngAlg;
    BCryptAlgorithmHandle m_rsaAlg;
    BCryptAlgorithmHandle m_ecdsaP256Alg;
    BCryptAlgorithmHandle m_ecdhP256Alg;

    mutable std::shared_mutex m_keyStoreMutex;
    std::unordered_map<std::string, std::unique_ptr<ManagedKey>> m_keyStore;

    std::atomic<bool> m_tpmAvailable{false};
    NCRYPT_PROV_HANDLE m_tpmProvider = 0;
    NCRYPT_KEY_HANDLE m_tpmSealKey = 0;

    mutable std::shared_mutex m_callbackMutex;
    KeyRotationCallback m_keyRotationCallback;
    CryptoAuditCallback m_auditCallback;

    mutable InternalCryptoStats m_stats;

    std::atomic<bool> m_hasAESNI{false};
    std::atomic<bool> m_hasRDRAND{false};

    [[nodiscard]] bool InitializeAlgorithms();
    [[nodiscard]] bool InitializeTPM();
    [[nodiscard]] bool DetectHardwareCapabilities();

    [[nodiscard]] size_t GetKeySize(SymmetricAlgorithm algorithm) const;
    [[nodiscard]] size_t GetIVSize(SymmetricAlgorithm algorithm) const;
    [[nodiscard]] size_t GetTagSize(SymmetricAlgorithm algorithm) const;
    [[nodiscard]] size_t GetHashSize(HashAlgorithm algorithm) const;
    [[nodiscard]] LPCWSTR GetBCryptHashAlgorithm(HashAlgorithm algorithm) const;

    [[nodiscard]] EncryptionResult EncryptAESGCM(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> aad);

    [[nodiscard]] DecryptionResult DecryptAESGCM(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> tag,
        std::span<const uint8_t> aad);

    [[nodiscard]] EncryptionResult EncryptAESCBC(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> key,
        std::span<const uint8_t> iv);

    [[nodiscard]] DecryptionResult DecryptAESCBC(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> key,
        std::span<const uint8_t> iv,
        std::span<const uint8_t> macTag);

    void NotifyKeyRotation(const std::string& keyId,
                           const KeyMetadata& oldMeta,
                           const KeyMetadata& newMeta);
    void NotifyAudit(const std::string& operation,
                     const std::string& keyId,
                     bool success);
};

// ============================================================================
// CRYPTOMANAGER SINGLETON
// ============================================================================

std::atomic<bool> CryptoManager::s_instanceCreated{false};

CryptoManager& CryptoManager::Instance() noexcept {
    static CryptoManager instance;
    return instance;
}

bool CryptoManager::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

CryptoManager::CryptoManager()
    : m_impl(std::make_unique<CryptoManagerImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"CryptoManager instance created");
}

CryptoManager::~CryptoManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    s_instanceCreated.store(false, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"CryptoManager instance destroyed");
}

bool CryptoManager::Initialize(const CryptoManagerConfiguration& config) {
    return m_impl->Initialize(config);
}

void CryptoManager::Shutdown() {
    m_impl->Shutdown();
}

bool CryptoManager::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus CryptoManager::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool CryptoManager::SetConfiguration(const CryptoManagerConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

CryptoManagerConfiguration CryptoManager::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

std::vector<uint8_t> CryptoManager::Encrypt(
    const std::vector<uint8_t>& data,
    const std::vector<uint8_t>& key) {
    auto result = m_impl->Encrypt(data, key, SymmetricAlgorithm::AES_256_GCM, {}, {});
    if (result.IsSuccess()) {
        return result.GetCombinedOutput();
    }
    return {};
}

EncryptionResult CryptoManager::Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> aad) {
    return m_impl->Encrypt(plaintext, key, algorithm, iv, aad);
}

std::vector<uint8_t> CryptoManager::Decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key) {
    if (ciphertext.size() < CryptoConstants::AES_GCM_NONCE_SIZE + CryptoConstants::AES_GCM_TAG_SIZE) {
        return {};
    }
    std::span<const uint8_t> iv(ciphertext.data(), CryptoConstants::AES_GCM_NONCE_SIZE);
    std::span<const uint8_t> tag(
        ciphertext.data() + ciphertext.size() - CryptoConstants::AES_GCM_TAG_SIZE,
        CryptoConstants::AES_GCM_TAG_SIZE);
    std::span<const uint8_t> ct(
        ciphertext.data() + CryptoConstants::AES_GCM_NONCE_SIZE,
        ciphertext.size() - CryptoConstants::AES_GCM_NONCE_SIZE - CryptoConstants::AES_GCM_TAG_SIZE);
    auto result = m_impl->Decrypt(ct, key, SymmetricAlgorithm::AES_256_GCM, iv, tag, {});
    if (result.IsSuccess()) {
        return result.plaintext;
    }
    return {};
}

DecryptionResult CryptoManager::Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> aad) {
    return m_impl->Decrypt(ciphertext, key, algorithm, iv, tag, aad);
}

CryptoResult CryptoManager::EncryptFile(
    std::wstring_view inputPath,
    std::wstring_view outputPath,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm) {
    return m_impl->EncryptFile(inputPath, outputPath, key, algorithm);
}

CryptoResult CryptoManager::DecryptFile(
    std::wstring_view inputPath,
    std::wstring_view outputPath,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm) {
    return m_impl->DecryptFile(inputPath, outputPath, key, algorithm);
}

EncryptionResult CryptoManager::RSAEncrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> publicKey,
    RSAPadding padding) {
    return m_impl->RSAEncrypt(plaintext, publicKey, padding);
}

DecryptionResult CryptoManager::RSADecrypt(
    std::span<const uint8_t> ciphertext,
    const std::string& privateKeyId,
    RSAPadding padding) {
    return m_impl->RSADecrypt(ciphertext, privateKeyId, padding);
}

std::optional<std::vector<uint8_t>> CryptoManager::ECDHKeyAgreement(
    std::span<const uint8_t> peerPublicKey,
    const std::string& privateKeyId) {
    return m_impl->ECDHKeyAgreement(peerPublicKey, privateKeyId);
}

SignatureResult CryptoManager::Sign(
    std::span<const uint8_t> data,
    const std::string& privateKeyId,
    HashAlgorithm hashAlgorithm) {
    return m_impl->Sign(data, privateKeyId, hashAlgorithm);
}

bool CryptoManager::Verify(
    std::span<const uint8_t> data,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> publicKey,
    HashAlgorithm hashAlgorithm) {
    return m_impl->Verify(data, signature, publicKey, hashAlgorithm);
}

SignatureResult CryptoManager::SignEd25519(
    std::span<const uint8_t> data,
    const std::string& privateKeyId) {
    return m_impl->SignEd25519(data, privateKeyId);
}

bool CryptoManager::VerifyEd25519(
    std::span<const uint8_t> data,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> publicKey) {
    return m_impl->VerifyEd25519(data, signature, publicKey);
}

std::vector<uint8_t> CryptoManager::Hash(
    std::span<const uint8_t> data,
    HashAlgorithm algorithm) {
    return m_impl->Hash(data, algorithm);
}

Hash256 CryptoManager::SHA256(std::span<const uint8_t> data) {
    return m_impl->SHA256Hash(data);
}

Hash384 CryptoManager::SHA384(std::span<const uint8_t> data) {
    return m_impl->SHA384Hash(data);
}

Hash512 CryptoManager::SHA512(std::span<const uint8_t> data) {
    return m_impl->SHA512Hash(data);
}

std::vector<uint8_t> CryptoManager::HMAC(
    std::span<const uint8_t> data,
    std::span<const uint8_t> key,
    HashAlgorithm algorithm) {
    return m_impl->ComputeHMAC(data, key, algorithm);
}

bool CryptoManager::VerifyHMAC(
    std::span<const uint8_t> data,
    std::span<const uint8_t> expectedMAC,
    std::span<const uint8_t> key,
    HashAlgorithm algorithm) {
    return m_impl->VerifyHMAC(data, expectedMAC, key, algorithm);
}

std::optional<std::vector<uint8_t>> CryptoManager::HashFile(
    std::wstring_view filePath,
    HashAlgorithm algorithm) {
    return m_impl->HashFile(filePath, algorithm);
}

std::vector<uint8_t> CryptoManager::GenerateRandomKey(size_t length) {
    return m_impl->GenerateRandomBytes(length);
}

KeyGenerationResult CryptoManager::GenerateSymmetricKey(
    SymmetricAlgorithm algorithm,
    KeyStorage storage) {
    return m_impl->GenerateSymmetricKey(algorithm, storage);
}

KeyGenerationResult CryptoManager::GenerateRSAKeyPair(
    uint32_t keySizeBits,
    KeyStorage storage) {
    return m_impl->GenerateRSAKeyPair(keySizeBits, storage);
}

KeyGenerationResult CryptoManager::GenerateECDSAKeyPair(
    AsymmetricAlgorithm curve,
    KeyStorage storage) {
    return m_impl->GenerateECDSAKeyPair(curve, storage);
}

KeyGenerationResult CryptoManager::GenerateEd25519KeyPair(KeyStorage storage) {
    return m_impl->GenerateEd25519KeyPair(storage);
}

KeyGenerationResult CryptoManager::GenerateX25519KeyPair(KeyStorage storage) {
    return m_impl->GenerateX25519KeyPair(storage);
}

std::vector<uint8_t> CryptoManager::DeriveKey(
    std::string_view password,
    std::span<const uint8_t> salt,
    const KDFParameters& params) {
    return m_impl->DeriveKey(password, salt, params);
}

std::vector<uint8_t> CryptoManager::HKDF(
    std::span<const uint8_t> inputKeyMaterial,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t outputLength,
    HashAlgorithm algorithm) {
    return m_impl->ComputeHKDF(inputKeyMaterial, salt, info, outputLength, algorithm);
}

std::string CryptoManager::HashPassword(
    std::string_view password,
    KDFAlgorithm algorithm) {
    return m_impl->HashPassword(password, algorithm);
}

bool CryptoManager::VerifyPassword(
    std::string_view password,
    std::string_view hash) {
    return m_impl->VerifyPassword(password, hash);
}

std::vector<uint8_t> CryptoManager::GenerateRandom(size_t length) {
    return m_impl->GenerateRandomBytes(length);
}

Nonce96 CryptoManager::GenerateNonce() {
    return m_impl->GenerateNonce();
}

IV128 CryptoManager::GenerateIV() {
    return m_impl->GenerateIV();
}

Salt256 CryptoManager::GenerateSalt() {
    return m_impl->GenerateSalt();
}

uint32_t CryptoManager::GenerateRandomUInt32() {
    return m_impl->GenerateRandomUInt32();
}

uint64_t CryptoManager::GenerateRandomUInt64() {
    return m_impl->GenerateRandomUInt64();
}

std::string CryptoManager::StoreKey(
    std::span<const uint8_t> keyData,
    KeyType type,
    KeyStorage storage,
    std::string_view description) {
    return m_impl->StoreKey(keyData, type, storage, description);
}

std::optional<std::vector<uint8_t>> CryptoManager::RetrieveKey(const std::string& keyId) {
    return m_impl->RetrieveKey(keyId);
}

bool CryptoManager::DeleteKey(const std::string& keyId) {
    return m_impl->DeleteKey(keyId);
}

std::optional<KeyMetadata> CryptoManager::GetKeyMetadata(const std::string& keyId) const {
    return m_impl->GetKeyMetadata(keyId);
}

std::vector<KeyMetadata> CryptoManager::ListKeys() const {
    return m_impl->ListKeys();
}

std::string CryptoManager::RotateKey(const std::string& oldKeyId) {
    return m_impl->RotateKey(oldKeyId);
}

std::optional<std::vector<uint8_t>> CryptoManager::ExportKey(
    const std::string& keyId,
    std::span<const uint8_t> wrappingKey) {
    return m_impl->ExportKey(keyId, wrappingKey);
}

std::string CryptoManager::ImportKey(
    std::span<const uint8_t> wrappedKey,
    std::span<const uint8_t> wrappingKey,
    KeyType type,
    KeyStorage storage) {
    return m_impl->ImportKey(wrappedKey, wrappingKey, type, storage);
}

std::optional<std::vector<uint8_t>> CryptoManager::DPAPIProtect(
    std::span<const uint8_t> data,
    std::span<const uint8_t> entropy) {
    return m_impl->DPAPIProtect(data, entropy);
}

std::optional<std::vector<uint8_t>> CryptoManager::DPAPIUnprotect(
    std::span<const uint8_t> protectedData,
    std::span<const uint8_t> entropy) {
    return m_impl->DPAPIUnprotect(protectedData, entropy);
}

bool CryptoManager::IsTPMAvailable() const {
    return m_impl->IsTPMAvailable();
}

std::string CryptoManager::CreateTPMKey(KeyType type) {
    return m_impl->CreateTPMKey(type);
}

std::optional<std::vector<uint8_t>> CryptoManager::TPMSeal(std::span<const uint8_t> data) {
    return m_impl->TPMSeal(data);
}

std::optional<std::vector<uint8_t>> CryptoManager::TPMUnseal(std::span<const uint8_t> sealedData) {
    return m_impl->TPMUnseal(sealedData);
}

void* CryptoManager::SecureAlloc(size_t size) {
    return m_impl->SecureAlloc(size);
}

void CryptoManager::SecureFree(void* ptr, size_t size) {
    m_impl->SecureFree(ptr, size);
}

void CryptoManager::SecureZero(void* ptr, size_t size) {
    m_impl->SecureZero(ptr, size);
}

bool CryptoManager::ConstantTimeCompare(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) noexcept {
    return m_impl->ConstantTimeCompare(a, b);
}

void CryptoManager::SetKeyRotationCallback(KeyRotationCallback callback) {
    m_impl->SetKeyRotationCallback(std::move(callback));
}

void CryptoManager::SetAuditCallback(CryptoAuditCallback callback) {
    m_impl->SetAuditCallback(std::move(callback));
}

bool CryptoManager::IsHardwareAccelerationAvailable() const {
    return m_impl->IsHardwareAccelerationAvailable();
}

bool CryptoManager::IsFIPSModeEnabled() const {
    return m_impl->IsFIPSModeEnabled();
}

std::vector<std::string> CryptoManager::GetSupportedAlgorithms() const {
    return m_impl->GetSupportedAlgorithms();
}

CryptoManagerStatistics CryptoManager::GetStatistics() const {
    return m_impl->GetStatistics();
}

void CryptoManager::ResetStatistics() {
    m_impl->ResetStatistics();
}

bool CryptoManager::SelfTest() {
    return m_impl->SelfTest();
}

std::string CryptoManager::GetVersionString() noexcept {
    try {
        char buf[32]{};
        snprintf(buf, sizeof(buf), "%u.%u.%u",
                 CryptoConstants::VERSION_MAJOR,
                 CryptoConstants::VERSION_MINOR,
                 CryptoConstants::VERSION_PATCH);
        return std::string(buf);
    } catch (...) {
        return "3.0.0";
    }
}

// ============================================================================
// CRYPTOMANAGER - KERNEL ATTESTATION WRAPPERS
// ============================================================================

std::optional<CryptoManager::KernelSessionKeyResult> CryptoManager::DeriveKernelSessionKey(
    std::span<const uint8_t> driverPublicKey,
    std::span<const uint8_t> driverHash,
    std::string_view contextLabel) {
    return m_impl->DeriveKernelSessionKey(driverPublicKey, driverHash, contextLabel);
}

bool CryptoManager::VerifyKernelMessageIntegrity(
    std::span<const uint8_t> message,
    std::span<const uint8_t> hmac,
    std::span<const uint8_t> sessionKey) {
    return m_impl->VerifyKernelMessageIntegrity(message, hmac, sessionKey);
}

std::vector<uint8_t> CryptoManager::ComputeKernelMessageHMAC(
    std::span<const uint8_t> message,
    std::span<const uint8_t> sessionKey) {
    return m_impl->ComputeKernelMessageHMAC(message, sessionKey);
}

bool CryptoManager::ValidateKernelDriverAttestation(
    const std::wstring& driverPath,
    std::span<const uint8_t> expectedHash) {
    return m_impl->ValidateKernelDriverAttestation(driverPath, expectedHash);
}

// ============================================================================
// CRYPTOMANAGERIMPL - LIFECYCLE
// ============================================================================

CryptoManagerImpl::CryptoManagerImpl() {
    m_stats.startTime = Clock::now();
}

CryptoManagerImpl::~CryptoManagerImpl() {
    Shutdown();
}

bool CryptoManagerImpl::Initialize(const CryptoManagerConfiguration& config) {
    if (m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_WARN(LOG_CATEGORY, L"CryptoManager already initialized");
        return true;
    }

    m_status.store(ModuleStatus::Initializing, std::memory_order_release);

    try {
        if (!config.IsValid()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        {
            std::unique_lock lock(m_configMutex);
            m_config = config;
        }

        if (!DetectHardwareCapabilities()) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to detect hardware capabilities");
        }

        if (!InitializeAlgorithms()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize algorithms");
            m_status.store(ModuleStatus::Error, std::memory_order_release);
            return false;
        }

        if (config.enableTPM) {
            if (!InitializeTPM()) {
                SS_LOG_WARN(LOG_CATEGORY, L"TPM initialization failed");
            }
        }

        ResetStatistics();

        m_initialized.store(true, std::memory_order_release);
        m_status.store(ModuleStatus::Running, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"CryptoManager initialized successfully");
        SS_LOG_INFO(LOG_CATEGORY, L"Hardware acceleration: %ls",
                    IsHardwareAccelerationAvailable() ? L"Available" : L"Not available");

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", e.what());
        m_status.store(ModuleStatus::Error, std::memory_order_release);
        return false;
    }
}

void CryptoManagerImpl::Shutdown() {
    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_status.store(ModuleStatus::Stopping, std::memory_order_release);

    {
        std::unique_lock lock(m_keyStoreMutex);
        m_keyStore.clear();
    }

    {
        std::unique_lock lock(m_algMutex);
        m_aesAlg.Close();
        m_sha256Alg.Close();
        m_sha384Alg.Close();
        m_sha512Alg.Close();
        m_rngAlg.Close();
        m_rsaAlg.Close();
        m_ecdsaP256Alg.Close();
        m_ecdhP256Alg.Close();
    }

    if (m_tpmSealKey) {
        NCryptFreeObject(m_tpmSealKey);
        m_tpmSealKey = 0;
    }
    if (m_tpmProvider) {
        NCryptFreeObject(m_tpmProvider);
        m_tpmProvider = 0;
    }
    m_tpmAvailable.store(false, std::memory_order_release);

    {
        std::unique_lock lock(m_callbackMutex);
        m_keyRotationCallback = nullptr;
        m_auditCallback = nullptr;
    }

    m_initialized.store(false, std::memory_order_release);
    m_status.store(ModuleStatus::Stopped, std::memory_order_release);

    SS_LOG_INFO(LOG_CATEGORY, L"CryptoManager shut down");
}

bool CryptoManagerImpl::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

ModuleStatus CryptoManagerImpl::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool CryptoManagerImpl::SetConfiguration(const CryptoManagerConfiguration& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid configuration update");
        return false;
    }

    std::unique_lock lock(m_configMutex);
    m_config = config;

    SS_LOG_INFO(LOG_CATEGORY, L"Configuration updated");
    return true;
}

CryptoManagerConfiguration CryptoManagerImpl::GetConfiguration() const {
    std::shared_lock lock(m_configMutex);
    return m_config;
}

// ============================================================================
// CRYPTOMANAGERIMPL - ENCRYPTION
// ============================================================================

EncryptionResult CryptoManagerImpl::Encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> aad) {

    EncryptionResult result;

    if (!m_initialized.load(std::memory_order_acquire)) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "CryptoManager not initialized";
        return result;
    }

    if (plaintext.empty()) {
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Empty plaintext";
        return result;
    }

    if (plaintext.size() > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Data exceeds maximum size";
        return result;
    }

    size_t expectedKeySize = GetKeySize(algorithm);
    if (key.size() != expectedKeySize) {
        result.result = CryptoResult::InvalidKey;
        result.errorMessage = "Invalid key size";
        return result;
    }

    try {
        switch (algorithm) {
            case SymmetricAlgorithm::AES_256_GCM:
            case SymmetricAlgorithm::AES_128_GCM:
            case SymmetricAlgorithm::AES_192_GCM: {
                std::vector<uint8_t> nonce;
                if (iv.empty()) {
                    auto generated = GenerateNonce();
                    nonce.assign(generated.begin(), generated.end());
                } else {
                    nonce.assign(iv.begin(), iv.end());
                }
                result = EncryptAESGCM(plaintext, key, nonce, aad);
                if (result.IsSuccess()) {
                    result.iv = std::move(nonce);
                }
                break;
            }

            case SymmetricAlgorithm::AES_256_CBC:
            case SymmetricAlgorithm::AES_128_CBC: {
                std::vector<uint8_t> ivVec;
                if (iv.empty()) {
                    auto generated = GenerateIV();
                    ivVec.assign(generated.begin(), generated.end());
                } else {
                    ivVec.assign(iv.begin(), iv.end());
                }
                result = EncryptAESCBC(plaintext, key, ivVec);
                if (result.IsSuccess()) {
                    result.iv = std::move(ivVec);
                }
                break;
            }

            default:
                result.result = CryptoResult::AlgorithmNotSupported;
                result.errorMessage = "Algorithm not supported";
                break;
        }

        if (result.IsSuccess()) {
            m_stats.totalEncryptions.fetch_add(1, std::memory_order_relaxed);
            if (m_hasAESNI.load(std::memory_order_relaxed)) {
                m_stats.hardwareAccelerationOps.fetch_add(1, std::memory_order_relaxed);
            }
            NotifyAudit("Encrypt", "", true);
        }

    } catch (const std::exception& e) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = e.what();
        SS_LOG_ERROR(LOG_CATEGORY, L"Encryption failed: %hs", e.what());
        NotifyAudit("Encrypt", "", false);
    }

    return result;
}

DecryptionResult CryptoManagerImpl::Decrypt(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> aad) {

    DecryptionResult result;

    if (!m_initialized.load(std::memory_order_acquire)) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "CryptoManager not initialized";
        return result;
    }

    if (ciphertext.empty()) {
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Empty ciphertext";
        return result;
    }

    size_t expectedKeySize = GetKeySize(algorithm);
    if (key.size() != expectedKeySize) {
        result.result = CryptoResult::InvalidKey;
        result.errorMessage = "Invalid key size";
        return result;
    }

    try {
        switch (algorithm) {
            case SymmetricAlgorithm::AES_256_GCM:
            case SymmetricAlgorithm::AES_128_GCM:
            case SymmetricAlgorithm::AES_192_GCM: {
                if (iv.empty() || tag.empty()) {
                    result.result = CryptoResult::InvalidIV;
                    result.errorMessage = "GCM requires IV and tag";
                    return result;
                }
                result = DecryptAESGCM(ciphertext, key, iv, tag, aad);
                break;
            }

            case SymmetricAlgorithm::AES_256_CBC:
            case SymmetricAlgorithm::AES_128_CBC: {
                if (iv.empty()) {
                    result.result = CryptoResult::InvalidIV;
                    result.errorMessage = "CBC requires IV";
                    return result;
                }
                if (tag.empty()) {
                    result.result = CryptoResult::AuthenticationFailed;
                    result.errorMessage = "CBC Encrypt-then-MAC requires authentication tag";
                    return result;
                }
                result = DecryptAESCBC(ciphertext, key, iv, tag);
                break;
            }

            default:
                result.result = CryptoResult::AlgorithmNotSupported;
                result.errorMessage = "Algorithm not supported";
                break;
        }

        if (result.IsSuccess()) {
            m_stats.totalDecryptions.fetch_add(1, std::memory_order_relaxed);
            NotifyAudit("Decrypt", "", true);
        } else {
            m_stats.authenticationFailures.fetch_add(1, std::memory_order_relaxed);
            NotifyAudit("Decrypt", "", false);
        }

    } catch (const std::exception& e) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = e.what();
    }

    return result;
}

EncryptionResult CryptoManagerImpl::EncryptAESGCM(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> aad) {

    EncryptionResult result;

    std::shared_lock algLock(m_algMutex);
    if (!m_aesAlg.IsValid()) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "AES algorithm not initialized";
        return result;
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    NTSTATUS status = BCryptGetProperty(
        m_aesAlg.Get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize),
        sizeof(keyObjectSize),
        &dataSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "Failed to get key object size";
        return result;
    }

    BCryptKeyHandle keyHandle;
    keyHandle.ResizeKeyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(
        m_aesAlg.Get(),
        keyHandle.GetAddressOf(),
        keyHandle.GetKeyObjectBuffer(),
        keyObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        result.errorMessage = "Failed to import key";
        return result;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    std::vector<uint8_t> nonceVec(nonce.begin(), nonce.end());
    authInfo.pbNonce = nonceVec.data();
    authInfo.cbNonce = static_cast<ULONG>(nonceVec.size());

    std::vector<uint8_t> aadVec;
    if (!aad.empty()) {
        aadVec.assign(aad.begin(), aad.end());
        authInfo.pbAuthData = aadVec.data();
        authInfo.cbAuthData = static_cast<ULONG>(aadVec.size());
    }

    std::vector<uint8_t> tag(CryptoConstants::AES_GCM_TAG_SIZE);
    authInfo.pbTag = tag.data();
    authInfo.cbTag = static_cast<ULONG>(tag.size());

    DWORD ciphertextSize = 0;
    status = BCryptEncrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &authInfo,
        nullptr,
        0,
        nullptr,
        0,
        &ciphertextSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "Failed to get ciphertext size";
        return result;
    }

    result.ciphertext.resize(ciphertextSize);
    status = BCryptEncrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(plaintext.data()),
        static_cast<ULONG>(plaintext.size()),
        &authInfo,
        nullptr,
        0,
        result.ciphertext.data(),
        static_cast<ULONG>(result.ciphertext.size()),
        &ciphertextSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "Encryption failed";
        return result;
    }

    result.ciphertext.resize(ciphertextSize);
    result.tag = std::move(tag);
    result.result = CryptoResult::Success;

    return result;
}

DecryptionResult CryptoManagerImpl::DecryptAESGCM(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> tag,
    std::span<const uint8_t> aad) {

    DecryptionResult result;

    std::shared_lock algLock(m_algMutex);
    if (!m_aesAlg.IsValid()) {
        result.result = CryptoResult::InternalError;
        result.errorMessage = "AES algorithm not initialized";
        return result;
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    NTSTATUS status = BCryptGetProperty(
        m_aesAlg.Get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize),
        sizeof(keyObjectSize),
        &dataSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCryptKeyHandle keyHandle;
    keyHandle.ResizeKeyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(
        m_aesAlg.Get(),
        keyHandle.GetAddressOf(),
        keyHandle.GetKeyObjectBuffer(),
        keyObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = {};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

    std::vector<uint8_t> nonceVec(nonce.begin(), nonce.end());
    authInfo.pbNonce = nonceVec.data();
    authInfo.cbNonce = static_cast<ULONG>(nonceVec.size());

    std::vector<uint8_t> aadVec;
    if (!aad.empty()) {
        aadVec.assign(aad.begin(), aad.end());
        authInfo.pbAuthData = aadVec.data();
        authInfo.cbAuthData = static_cast<ULONG>(aadVec.size());
    }

    std::vector<uint8_t> tagVec(tag.begin(), tag.end());
    authInfo.pbTag = tagVec.data();
    authInfo.cbTag = static_cast<ULONG>(tagVec.size());

    DWORD plaintextSize = 0;
    status = BCryptDecrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &authInfo,
        nullptr,
        0,
        nullptr,
        0,
        &plaintextSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.plaintext.resize(plaintextSize);
    status = BCryptDecrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        &authInfo,
        nullptr,
        0,
        result.plaintext.data(),
        static_cast<ULONG>(result.plaintext.size()),
        &plaintextSize,
        0);

    if (!NT_SUCCESS(status)) {
        if (status == static_cast<NTSTATUS>(0xC000A002L)) {
            result.result = CryptoResult::AuthenticationFailed;
            result.errorMessage = "Authentication tag mismatch";
        } else {
            result.result = CryptoResult::InternalError;
            result.errorMessage = "Decryption failed";
        }
        return result;
    }

    result.plaintext.resize(plaintextSize);
    result.result = CryptoResult::Success;

    return result;
}

EncryptionResult CryptoManagerImpl::EncryptAESCBC(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> iv) {

    EncryptionResult result;

    // Encrypt-then-MAC: derive separate encryption and MAC keys from the
    // provided key via HMAC-based key separation (NIST SP 800-108 KDF in feedback mode).
    // macKey = HMAC-SHA256(key, "ShadowStrike-CBC-MAC")
    // encKey = HMAC-SHA256(key, "ShadowStrike-CBC-ENC") truncated to key.size()
    static constexpr uint8_t kMacInfo[] = "ShadowStrike-CBC-MAC";
    static constexpr uint8_t kEncInfo[] = "ShadowStrike-CBC-ENC";

    auto macKey = ComputeHMAC(
        std::span<const uint8_t>(kMacInfo, sizeof(kMacInfo) - 1),
        key, HashAlgorithm::SHA256);
    auto encKey = ComputeHMAC(
        std::span<const uint8_t>(kEncInfo, sizeof(kEncInfo) - 1),
        key, HashAlgorithm::SHA256);

    if (macKey.empty() || encKey.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }
    // Truncate encKey to match original key size (supports AES-128 and AES-256)
    if (encKey.size() > key.size()) {
        encKey.resize(key.size());
    }

    BCryptAlgorithmHandle cbcAlg;
    if (!cbcAlg.Open(BCRYPT_AES_ALGORITHM)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    NTSTATUS status = BCryptSetProperty(
        cbcAlg.Get(),
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(cbcAlg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize), sizeof(keyObjectSize), &dataSize, 0);

    BCryptKeyHandle keyHandle;
    keyHandle.ResizeKeyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(
        cbcAlg.Get(),
        keyHandle.GetAddressOf(),
        keyHandle.GetKeyObjectBuffer(),
        keyObjectSize,
        encKey.data(),
        static_cast<ULONG>(encKey.size()),
        0);

    SecureZeroMemory(encKey.data(), encKey.size());

    if (!NT_SUCCESS(status)) {
        SecureZeroMemory(macKey.data(), macKey.size());
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    size_t blockSize = 16;
    size_t paddedSize = ((plaintext.size() / blockSize) + 1) * blockSize;
    std::vector<uint8_t> paddedPlaintext(paddedSize);
    std::memcpy(paddedPlaintext.data(), plaintext.data(), plaintext.size());

    uint8_t paddingValue = static_cast<uint8_t>(paddedSize - plaintext.size());
    std::memset(paddedPlaintext.data() + plaintext.size(), paddingValue, paddingValue);

    std::vector<uint8_t> ivCopy(iv.begin(), iv.end());
    DWORD ciphertextSize = 0;

    status = BCryptEncrypt(
        keyHandle.Get(),
        paddedPlaintext.data(),
        static_cast<ULONG>(paddedPlaintext.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        nullptr,
        0,
        &ciphertextSize,
        0);

    if (!NT_SUCCESS(status)) {
        SecureZeroMemory(paddedPlaintext.data(), paddedPlaintext.size());
        SecureZeroMemory(macKey.data(), macKey.size());
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.ciphertext.resize(ciphertextSize);
    ivCopy.assign(iv.begin(), iv.end());

    status = BCryptEncrypt(
        keyHandle.Get(),
        paddedPlaintext.data(),
        static_cast<ULONG>(paddedPlaintext.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        result.ciphertext.data(),
        static_cast<ULONG>(result.ciphertext.size()),
        &ciphertextSize,
        0);

    SecureZeroMemory(paddedPlaintext.data(), paddedPlaintext.size());

    if (!NT_SUCCESS(status)) {
        SecureZeroMemory(macKey.data(), macKey.size());
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.ciphertext.resize(ciphertextSize);

    // Encrypt-then-MAC: HMAC-SHA256(macKey, IV || ciphertext)
    // Store the tag in the EncryptionResult::tag field.
    std::vector<uint8_t> macInput;
    macInput.reserve(iv.size() + result.ciphertext.size());
    macInput.insert(macInput.end(), iv.begin(), iv.end());
    macInput.insert(macInput.end(), result.ciphertext.begin(), result.ciphertext.end());

    result.tag = ComputeHMAC(macInput, macKey, HashAlgorithm::SHA256);
    SecureZeroMemory(macKey.data(), macKey.size());

    if (result.tag.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.result = CryptoResult::Success;
    return result;
}

DecryptionResult CryptoManagerImpl::DecryptAESCBC(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> key,
    std::span<const uint8_t> iv,
    std::span<const uint8_t> macTag) {

    DecryptionResult result;

    // Encrypt-then-MAC: derive MAC and ENC keys identically to encrypt path.
    static constexpr uint8_t kMacInfo[] = "ShadowStrike-CBC-MAC";
    static constexpr uint8_t kEncInfo[] = "ShadowStrike-CBC-ENC";

    auto macKey = ComputeHMAC(
        std::span<const uint8_t>(kMacInfo, sizeof(kMacInfo) - 1),
        key, HashAlgorithm::SHA256);
    auto encKey = ComputeHMAC(
        std::span<const uint8_t>(kEncInfo, sizeof(kEncInfo) - 1),
        key, HashAlgorithm::SHA256);

    if (macKey.empty() || encKey.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }
    if (encKey.size() > key.size()) {
        encKey.resize(key.size());
    }

    // VERIFY MAC BEFORE DECRYPTION — this is the core defense against padding oracle.
    std::vector<uint8_t> macInput;
    macInput.reserve(iv.size() + ciphertext.size());
    macInput.insert(macInput.end(), iv.begin(), iv.end());
    macInput.insert(macInput.end(), ciphertext.begin(), ciphertext.end());

    auto computedMac = ComputeHMAC(macInput, macKey, HashAlgorithm::SHA256);
    SecureZeroMemory(macKey.data(), macKey.size());

    if (computedMac.empty() || !ConstantTimeCompare(computedMac, macTag)) {
        SecureZeroMemory(encKey.data(), encKey.size());
        result.result = CryptoResult::AuthenticationFailed;
        result.errorMessage = "CBC MAC verification failed";
        m_stats.authenticationFailures.fetch_add(1, std::memory_order_relaxed);
        return result;
    }

    BCryptAlgorithmHandle cbcAlg;
    if (!cbcAlg.Open(BCRYPT_AES_ALGORITHM)) {
        SecureZeroMemory(encKey.data(), encKey.size());
        result.result = CryptoResult::InternalError;
        return result;
    }

    NTSTATUS status = BCryptSetProperty(
        cbcAlg.Get(),
        BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0);

    if (!NT_SUCCESS(status)) {
        SecureZeroMemory(encKey.data(), encKey.size());
        result.result = CryptoResult::InternalError;
        return result;
    }

    DWORD keyObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(cbcAlg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&keyObjectSize), sizeof(keyObjectSize), &dataSize, 0);

    BCryptKeyHandle keyHandle;
    keyHandle.ResizeKeyObject(keyObjectSize);

    status = BCryptGenerateSymmetricKey(
        cbcAlg.Get(),
        keyHandle.GetAddressOf(),
        keyHandle.GetKeyObjectBuffer(),
        keyObjectSize,
        encKey.data(),
        static_cast<ULONG>(encKey.size()),
        0);

    SecureZeroMemory(encKey.data(), encKey.size());

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    std::vector<uint8_t> ivCopy(iv.begin(), iv.end());
    DWORD plaintextSize = 0;

    status = BCryptDecrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        nullptr,
        0,
        &plaintextSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.plaintext.resize(plaintextSize);
    ivCopy.assign(iv.begin(), iv.end());

    status = BCryptDecrypt(
        keyHandle.Get(),
        const_cast<PUCHAR>(ciphertext.data()),
        static_cast<ULONG>(ciphertext.size()),
        nullptr,
        ivCopy.data(),
        static_cast<ULONG>(ivCopy.size()),
        result.plaintext.data(),
        static_cast<ULONG>(result.plaintext.size()),
        &plaintextSize,
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.plaintext.resize(plaintextSize);

    // PKCS7 padding removal (MAC already verified, so padding oracle is not a risk here)
    if (result.plaintext.empty()) {
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Empty decryption output";
        return result;
    }

    const uint8_t paddingValue = result.plaintext.back();
    if (paddingValue == 0 || paddingValue > 16 ||
        static_cast<size_t>(paddingValue) > result.plaintext.size()) {
        SecureZeroMemory(result.plaintext.data(), result.plaintext.size());
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Invalid padding (integrity already verified)";
        return result;
    }

    // Still do constant-time padding check for defense-in-depth
    volatile uint8_t paddingError = 0;
    for (size_t i = result.plaintext.size() - paddingValue; i < result.plaintext.size(); ++i) {
        paddingError |= result.plaintext[i] ^ paddingValue;
    }

    if (paddingError != 0) {
        SecureZeroMemory(result.plaintext.data(), result.plaintext.size());
        result.result = CryptoResult::InvalidData;
        result.errorMessage = "Invalid padding (integrity already verified)";
        return result;
    }

    result.plaintext.resize(result.plaintext.size() - paddingValue);
    result.result = CryptoResult::Success;
    return result;
}

CryptoResult CryptoManagerImpl::EncryptFile(
    std::wstring_view inputPath,
    std::wstring_view outputPath,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm) {

    const std::wstring inputPathStr(inputPath);
    const std::wstring outputPathStr(outputPath);

    ScopedFileHandle hInput(CreateFileW(
        inputPathStr.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));

    if (!hInput.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Failed to open input file for encryption: %ls", inputPathStr.c_str());
        return CryptoResult::InvalidData;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hInput.Get(), &fileSize)) {
        return CryptoResult::InvalidData;
    }

    if (fileSize.QuadPart < 0 ||
        static_cast<uint64_t>(fileSize.QuadPart) > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"File too large for encryption: %ls", inputPathStr.c_str());
        return CryptoResult::InvalidData;
    }

    const auto readSize = static_cast<size_t>(fileSize.QuadPart);
    std::vector<uint8_t> fileContent(readSize);
    DWORD bytesRead = 0;
    if (readSize > 0 && !ReadFile(hInput.Get(), fileContent.data(),
                                   static_cast<DWORD>(readSize), &bytesRead, nullptr)) {
        return CryptoResult::InvalidData;
    }
    fileContent.resize(bytesRead);

    auto result = Encrypt(fileContent, key, algorithm, {}, {});
    SecureZeroMemory(fileContent.data(), fileContent.capacity());

    if (!result.IsSuccess()) {
        return result.result;
    }

    auto combined = result.GetCombinedOutput();

    ScopedFileHandle hOutput(CreateFileW(
        outputPathStr.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!hOutput.IsValid()) {
        return CryptoResult::InternalError;
    }

    DWORD written = 0;
    BOOL success = WriteFile(hOutput.Get(), combined.data(),
                             static_cast<DWORD>(combined.size()), &written, nullptr);

    if (!success || written != static_cast<DWORD>(combined.size())) {
        return CryptoResult::InternalError;
    }

    return CryptoResult::Success;
}

CryptoResult CryptoManagerImpl::DecryptFile(
    std::wstring_view inputPath,
    std::wstring_view outputPath,
    std::span<const uint8_t> key,
    SymmetricAlgorithm algorithm) {

    const std::wstring inputPathStr(inputPath);
    const std::wstring outputPathStr(outputPath);

    ScopedFileHandle hInput(CreateFileW(
        inputPathStr.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!hInput.IsValid()) {
        return CryptoResult::InvalidData;
    }

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(hInput.Get(), &fileSize)) {
        return CryptoResult::InvalidData;
    }

    if (fileSize.QuadPart < 0 ||
        static_cast<uint64_t>(fileSize.QuadPart) > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Encrypted file too large: %ls", inputPathStr.c_str());
        return CryptoResult::InvalidData;
    }

    const auto readSize = static_cast<size_t>(fileSize.QuadPart);
    std::vector<uint8_t> ciphertext(readSize);
    DWORD bytesRead = 0;
    if (readSize > 0 && !ReadFile(hInput.Get(), ciphertext.data(),
                                   static_cast<DWORD>(readSize), &bytesRead, nullptr)) {
        return CryptoResult::InvalidData;
    }
    ciphertext.resize(bytesRead);

    const size_t ivSize = GetIVSize(algorithm);
    const size_t tagSize = GetTagSize(algorithm);

    if (ciphertext.size() < ivSize + tagSize) {
        return CryptoResult::InvalidData;
    }

    std::span<const uint8_t> iv(ciphertext.data(), ivSize);
    std::span<const uint8_t> tag(
        ciphertext.data() + ciphertext.size() - tagSize,
        tagSize);
    std::span<const uint8_t> ct(
        ciphertext.data() + ivSize,
        ciphertext.size() - ivSize - tagSize);

    auto result = Decrypt(ct, key, algorithm, iv, tag, {});
    if (!result.IsSuccess()) {
        return result.result;
    }

    ScopedFileHandle hOutput(CreateFileW(
        outputPathStr.c_str(),
        GENERIC_WRITE,
        0,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr));

    if (!hOutput.IsValid()) {
        SecureZeroMemory(result.plaintext.data(), result.plaintext.size());
        return CryptoResult::InternalError;
    }

    DWORD written = 0;
    BOOL success = WriteFile(hOutput.Get(), result.plaintext.data(),
                             static_cast<DWORD>(result.plaintext.size()), &written, nullptr);
    SecureZeroMemory(result.plaintext.data(), result.plaintext.size());

    if (!success || written != static_cast<DWORD>(result.plaintext.size())) {
        return CryptoResult::InternalError;
    }

    return CryptoResult::Success;
}

// ============================================================================
// CRYPTOMANAGERIMPL - HASHING
// ============================================================================

std::vector<uint8_t> CryptoManagerImpl::Hash(
    std::span<const uint8_t> data,
    HashAlgorithm algorithm) {

    std::vector<uint8_t> result;

    LPCWSTR algId = GetBCryptHashAlgorithm(algorithm);
    if (!algId) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Unsupported hash algorithm");
        return result;
    }

    // Use cached algorithm handles for SHA-256/384/512 to avoid per-call Open overhead.
    // Copy the BCRYPT_ALG_HANDLE value (not a pointer to the wrapper) while holding the lock
    // to prevent TOCTOU if Shutdown() closes the handle between lock acquisitions.
    BCryptAlgorithmHandle tempAlg;
    BCRYPT_ALG_HANDLE algHandle = nullptr;
    {
        std::shared_lock algLock(m_algMutex);
        switch (algorithm) {
            case HashAlgorithm::SHA256:
                if (m_sha256Alg.IsValid()) algHandle = m_sha256Alg.Get();
                break;
            case HashAlgorithm::SHA384:
                if (m_sha384Alg.IsValid()) algHandle = m_sha384Alg.Get();
                break;
            case HashAlgorithm::SHA512:
                if (m_sha512Alg.IsValid()) algHandle = m_sha512Alg.Get();
                break;
            default:
                break;
        }
    }

    if (!algHandle) {
        if (!tempAlg.Open(algId)) {
            return result;
        }
        algHandle = tempAlg.Get();
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    NTSTATUS status = BCryptGetProperty(
        algHandle,
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize),
        sizeof(hashObjectSize),
        &dataSize,
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    DWORD hashSize = 0;
    status = BCryptGetProperty(
        algHandle,
        BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashSize),
        sizeof(hashSize),
        &dataSize,
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    status = BCryptCreateHash(
        algHandle,
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    status = BCryptHashData(
        hashHandle.Get(),
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    result.resize(hashSize);
    status = BCryptFinishHash(
        hashHandle.Get(),
        result.data(),
        static_cast<ULONG>(result.size()),
        0);

    if (!NT_SUCCESS(status)) {
        result.clear();
        return result;
    }

    m_stats.totalHashes.fetch_add(1, std::memory_order_relaxed);
    return result;
}

Hash256 CryptoManagerImpl::SHA256Hash(std::span<const uint8_t> data) {
    Hash256 result{};

    std::shared_lock algLock(m_algMutex);
    if (!m_sha256Alg.IsValid()) {
        return result;
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(
        m_sha256Alg.Get(),
        BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize),
        sizeof(hashObjectSize),
        &dataSize,
        0);

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    NTSTATUS status = BCryptCreateHash(
        m_sha256Alg.Get(),
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    status = BCryptHashData(
        hashHandle.Get(),
        const_cast<PUCHAR>(data.data()),
        static_cast<ULONG>(data.size()),
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    status = BCryptFinishHash(
        hashHandle.Get(),
        result.data(),
        static_cast<ULONG>(result.size()),
        0);

    if (NT_SUCCESS(status)) {
        m_stats.totalHashes.fetch_add(1, std::memory_order_relaxed);
    }

    return result;
}

Hash384 CryptoManagerImpl::SHA384Hash(std::span<const uint8_t> data) {
    Hash384 result{};

    std::shared_lock algLock(m_algMutex);
    if (!m_sha384Alg.IsValid()) {
        return result;
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(m_sha384Alg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(hashObjectSize), &dataSize, 0);

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    NTSTATUS status = BCryptCreateHash(
        m_sha384Alg.Get(),
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hashHandle.Get(),
            const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
    }

    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hashHandle.Get(),
            result.data(), static_cast<ULONG>(result.size()), 0);
    }

    if (NT_SUCCESS(status)) {
        m_stats.totalHashes.fetch_add(1, std::memory_order_relaxed);
    }

    return result;
}

Hash512 CryptoManagerImpl::SHA512Hash(std::span<const uint8_t> data) {
    Hash512 result{};

    std::shared_lock algLock(m_algMutex);
    if (!m_sha512Alg.IsValid()) {
        return result;
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(m_sha512Alg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(hashObjectSize), &dataSize, 0);

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    NTSTATUS status = BCryptCreateHash(
        m_sha512Alg.Get(),
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (NT_SUCCESS(status)) {
        status = BCryptHashData(hashHandle.Get(),
            const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
    }

    if (NT_SUCCESS(status)) {
        status = BCryptFinishHash(hashHandle.Get(),
            result.data(), static_cast<ULONG>(result.size()), 0);
    }

    if (NT_SUCCESS(status)) {
        m_stats.totalHashes.fetch_add(1, std::memory_order_relaxed);
    }

    return result;
}

std::vector<uint8_t> CryptoManagerImpl::ComputeHMAC(
    std::span<const uint8_t> data,
    std::span<const uint8_t> key,
    HashAlgorithm algorithm) {

    std::vector<uint8_t> result;

    LPCWSTR algId = GetBCryptHashAlgorithm(algorithm);
    if (!algId) {
        return result;
    }

    BCryptAlgorithmHandle alg;
    if (!alg.Open(algId, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) {
        return result;
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(alg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(hashObjectSize), &dataSize, 0);

    DWORD hashSize = 0;
    BCryptGetProperty(alg.Get(), BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &dataSize, 0);

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    NTSTATUS status = BCryptCreateHash(
        alg.Get(),
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        const_cast<PUCHAR>(key.data()),
        static_cast<ULONG>(key.size()),
        0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    status = BCryptHashData(hashHandle.Get(),
        const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);

    if (!NT_SUCCESS(status)) {
        return result;
    }

    result.resize(hashSize);
    status = BCryptFinishHash(hashHandle.Get(),
        result.data(), static_cast<ULONG>(result.size()), 0);

    if (!NT_SUCCESS(status)) {
        result.clear();
    }

    return result;
}

bool CryptoManagerImpl::VerifyHMAC(
    std::span<const uint8_t> data,
    std::span<const uint8_t> expectedMAC,
    std::span<const uint8_t> key,
    HashAlgorithm algorithm) {
    auto computed = ComputeHMAC(data, key, algorithm);
    return ConstantTimeCompare(computed, expectedMAC);
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::HashFile(
    std::wstring_view filePath,
    HashAlgorithm algorithm) {

    const std::wstring filePathStr(filePath);

    ScopedFileHandle hFile(CreateFileW(
        filePathStr.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr));

    if (!hFile.IsValid()) {
        return std::nullopt;
    }

    LPCWSTR algId = GetBCryptHashAlgorithm(algorithm);
    if (!algId) {
        return std::nullopt;
    }

    BCryptAlgorithmHandle alg;
    if (!alg.Open(algId)) {
        return std::nullopt;
    }

    DWORD hashObjectSize = 0;
    DWORD dataSize = 0;
    BCryptGetProperty(alg.Get(), BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&hashObjectSize), sizeof(hashObjectSize), &dataSize, 0);

    DWORD hashSize = 0;
    BCryptGetProperty(alg.Get(), BCRYPT_HASH_LENGTH,
        reinterpret_cast<PUCHAR>(&hashSize), sizeof(hashSize), &dataSize, 0);

    BCryptHashHandle hashHandle;
    hashHandle.ResizeHashObject(hashObjectSize);

    NTSTATUS status = BCryptCreateHash(
        alg.Get(),
        hashHandle.GetAddressOf(),
        hashHandle.GetHashObjectBuffer(),
        hashObjectSize,
        nullptr,
        0,
        0);

    if (!NT_SUCCESS(status)) {
        return std::nullopt;
    }

    std::vector<uint8_t> buffer(FILE_CHUNK_SIZE);
    DWORD bytesRead = 0;

    while (ReadFile(hFile.Get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr)
           && bytesRead > 0) {
        status = BCryptHashData(hashHandle.Get(), buffer.data(), bytesRead, 0);
        if (!NT_SUCCESS(status)) {
            return std::nullopt;
        }
    }

    std::vector<uint8_t> result(hashSize);
    status = BCryptFinishHash(hashHandle.Get(),
        result.data(), static_cast<ULONG>(result.size()), 0);

    if (!NT_SUCCESS(status)) {
        return std::nullopt;
    }

    m_stats.totalHashes.fetch_add(1, std::memory_order_relaxed);
    return result;
}

// ============================================================================
// CRYPTOMANAGERIMPL - RANDOM GENERATION
// ============================================================================

std::vector<uint8_t> CryptoManagerImpl::GenerateRandomBytes(size_t length) {
    if (length == 0 || length > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid random byte length requested: %zu", length);
        return {};
    }

    std::vector<uint8_t> result(length);

    std::shared_lock algLock(m_algMutex);
    if (!m_rngAlg.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"RNG algorithm not initialized");
        return {};
    }

    NTSTATUS status = BCryptGenRandom(
        m_rngAlg.Get(),
        result.data(),
        static_cast<ULONG>(result.size()),
        0);

    if (!NT_SUCCESS(status)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"BCryptGenRandom failed with NTSTATUS 0x%08lX", status);
        return {};
    }

    m_stats.totalRandomBytes.fetch_add(length, std::memory_order_relaxed);
    return result;
}

Nonce96 CryptoManagerImpl::GenerateNonce() {
    Nonce96 nonce{};
    auto random = GenerateRandomBytes(nonce.size());
    if (random.size() == nonce.size()) {
        std::memcpy(nonce.data(), random.data(), nonce.size());
    }
    return nonce;
}

IV128 CryptoManagerImpl::GenerateIV() {
    IV128 iv{};
    auto random = GenerateRandomBytes(iv.size());
    if (random.size() == iv.size()) {
        std::memcpy(iv.data(), random.data(), iv.size());
    }
    return iv;
}

Salt256 CryptoManagerImpl::GenerateSalt() {
    Salt256 salt{};
    auto random = GenerateRandomBytes(salt.size());
    if (random.size() == salt.size()) {
        std::memcpy(salt.data(), random.data(), salt.size());
    }
    return salt;
}

uint32_t CryptoManagerImpl::GenerateRandomUInt32() {
    auto bytes = GenerateRandomBytes(sizeof(uint32_t));
    if (bytes.size() < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t result = 0;
    std::memcpy(&result, bytes.data(), sizeof(uint32_t));
    return result;
}

uint64_t CryptoManagerImpl::GenerateRandomUInt64() {
    auto bytes = GenerateRandomBytes(sizeof(uint64_t));
    if (bytes.size() < sizeof(uint64_t)) {
        return 0;
    }
    uint64_t result = 0;
    std::memcpy(&result, bytes.data(), sizeof(uint64_t));
    return result;
}

// ============================================================================
// CRYPTOMANAGERIMPL - KEY GENERATION
// ============================================================================

KeyGenerationResult CryptoManagerImpl::GenerateSymmetricKey(
    SymmetricAlgorithm algorithm,
    KeyStorage storage) {

    KeyGenerationResult result;

    size_t keySize = GetKeySize(algorithm);
    if (keySize == 0) {
        result.result = CryptoResult::AlgorithmNotSupported;
        return result;
    }

    auto keyData = GenerateRandomBytes(keySize);
    if (keyData.size() != keySize) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    std::string keyId = StoreKey(keyData, KeyType::Symmetric, storage, "");
    if (keyId.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.keyId = keyId;
    result.keyData = std::move(keyData);
    result.metadata.id = keyId;
    result.metadata.type = KeyType::Symmetric;
    result.metadata.algorithm = algorithm;
    result.metadata.keySizeBits = static_cast<uint32_t>(keySize * 8);
    result.metadata.storage = storage;
    result.metadata.createdAt = std::chrono::system_clock::now();
    result.result = CryptoResult::Success;

    m_stats.totalKeyGenerations.fetch_add(1, std::memory_order_relaxed);

    return result;
}

KeyGenerationResult CryptoManagerImpl::GenerateRSAKeyPair(
    uint32_t keySizeBits,
    KeyStorage storage) {

    KeyGenerationResult result;

    if (keySizeBits < 2048 || keySizeBits > 4096) {
        result.result = CryptoResult::InvalidKey;
        result.errorMessage = "Invalid key size";
        return result;
    }

    std::shared_lock algLock(m_algMutex);
    if (!m_rsaAlg.IsValid()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(m_rsaAlg.Get(), &keyHandle, keySizeBits, 0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    status = BCryptFinalizeKeyPair(keyHandle, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    DWORD publicKeySize = 0;
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
        nullptr, 0, &publicKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.publicKey.resize(publicKeySize);
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAPUBLIC_BLOB,
        result.publicKey.data(), publicKeySize, &publicKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.publicKey.resize(publicKeySize);

    DWORD privateKeySize = 0;
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
        nullptr, 0, &privateKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    std::vector<uint8_t> privateKey(privateKeySize);
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
        privateKey.data(), privateKeySize, &privateKeySize, 0);

    BCryptDestroyKey(keyHandle);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    privateKey.resize(privateKeySize);

    std::string keyId = StoreKey(privateKey, KeyType::RSAPrivate, storage, "RSA-" + std::to_string(keySizeBits));
    SecureZeroMemory(privateKey.data(), privateKey.size());

    if (keyId.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.keyId = keyId;
    result.metadata.id = keyId;
    result.metadata.type = KeyType::RSAPrivate;
    result.metadata.algorithm = keySizeBits == 2048 ? AsymmetricAlgorithm::RSA_2048 :
                                 keySizeBits == 3072 ? AsymmetricAlgorithm::RSA_3072 :
                                                       AsymmetricAlgorithm::RSA_4096;
    result.metadata.keySizeBits = keySizeBits;
    result.metadata.storage = storage;
    result.metadata.createdAt = std::chrono::system_clock::now();
    result.result = CryptoResult::Success;

    m_stats.totalKeyGenerations.fetch_add(1, std::memory_order_relaxed);

    return result;
}

KeyGenerationResult CryptoManagerImpl::GenerateECDSAKeyPair(
    AsymmetricAlgorithm curve,
    KeyStorage storage) {

    KeyGenerationResult result;

    LPCWSTR algId = nullptr;
    uint32_t keyBits = 0;

    switch (curve) {
        case AsymmetricAlgorithm::ECDSA_P256:
            algId = BCRYPT_ECDSA_P256_ALGORITHM;
            keyBits = 256;
            break;
        case AsymmetricAlgorithm::ECDSA_P384:
            algId = BCRYPT_ECDSA_P384_ALGORITHM;
            keyBits = 384;
            break;
        case AsymmetricAlgorithm::ECDSA_P521:
            algId = BCRYPT_ECDSA_P521_ALGORITHM;
            keyBits = 521;
            break;
        default:
            result.result = CryptoResult::AlgorithmNotSupported;
            return result;
    }

    BCryptAlgorithmHandle alg;
    if (!alg.Open(algId)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(alg.Get(), &keyHandle, keyBits, 0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    status = BCryptFinalizeKeyPair(keyHandle, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    DWORD publicKeySize = 0;
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &publicKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.publicKey.resize(publicKeySize);
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                             result.publicKey.data(), publicKeySize, &publicKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    DWORD privateKeySize = 0;
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &privateKeySize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    std::vector<uint8_t> privateKey(privateKeySize);
    status = BCryptExportKey(keyHandle, nullptr, BCRYPT_ECCPRIVATE_BLOB,
                             privateKey.data(), privateKeySize, &privateKeySize, 0);

    BCryptDestroyKey(keyHandle);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    std::string keyId = StoreKey(privateKey, KeyType::ECDSAPrivate, storage, "ECDSA-P" + std::to_string(keyBits));
    SecureZeroMemory(privateKey.data(), privateKey.size());

    if (keyId.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.keyId = keyId;
    result.metadata.id = keyId;
    result.metadata.type = KeyType::ECDSAPrivate;
    result.metadata.algorithm = curve;
    result.metadata.keySizeBits = keyBits;
    result.metadata.storage = storage;
    result.metadata.createdAt = std::chrono::system_clock::now();
    result.result = CryptoResult::Success;

    m_stats.totalKeyGenerations.fetch_add(1, std::memory_order_relaxed);

    return result;
}

KeyGenerationResult CryptoManagerImpl::GenerateEd25519KeyPair(KeyStorage storage) {
    KeyGenerationResult result;
    result.result = CryptoResult::AlgorithmNotSupported;
    result.errorMessage = "Ed25519 not supported in Windows CNG";
    return result;
}

KeyGenerationResult CryptoManagerImpl::GenerateX25519KeyPair(KeyStorage storage) {
    KeyGenerationResult result;
    result.result = CryptoResult::AlgorithmNotSupported;
    result.errorMessage = "X25519 not supported in Windows CNG";
    return result;
}

// ============================================================================
// CRYPTOMANAGERIMPL - KEY DERIVATION
// ============================================================================

std::vector<uint8_t> CryptoManagerImpl::DeriveKey(
    std::string_view password,
    std::span<const uint8_t> salt,
    const KDFParameters& params) {

    std::vector<uint8_t> result;

    if (password.empty() || salt.empty()) {
        return result;
    }

    switch (params.algorithm) {
        case KDFAlgorithm::PBKDF2_SHA256:
        case KDFAlgorithm::PBKDF2_SHA512: {
            LPCWSTR hashAlg = (params.algorithm == KDFAlgorithm::PBKDF2_SHA256)
                              ? BCRYPT_SHA256_ALGORITHM
                              : BCRYPT_SHA512_ALGORITHM;

            BCryptAlgorithmHandle alg;
            if (!alg.Open(hashAlg, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG)) {
                return result;
            }

            result.resize(params.outputLength);

            NTSTATUS status = BCryptDeriveKeyPBKDF2(
                alg.Get(),
                reinterpret_cast<PUCHAR>(const_cast<char*>(password.data())),
                static_cast<ULONG>(password.size()),
                const_cast<PUCHAR>(salt.data()),
                static_cast<ULONG>(salt.size()),
                params.iterations,
                result.data(),
                static_cast<ULONG>(result.size()),
                0);

            if (!NT_SUCCESS(status)) {
                result.clear();
            } else {
                m_stats.totalKeyDerivations.fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }

        case KDFAlgorithm::Argon2id:
        case KDFAlgorithm::Argon2i:
        case KDFAlgorithm::Argon2d: {
            SS_LOG_WARN(LOG_CATEGORY,
                L"Argon2 not available in Windows CNG - falling back to PBKDF2-SHA256 "
                L"with %u iterations. Consider using PBKDF2 explicitly.",
                CryptoConstants::DEFAULT_PBKDF2_ITERATIONS);
            KDFParameters pbkdf2Params;
            pbkdf2Params.algorithm = KDFAlgorithm::PBKDF2_SHA256;
            pbkdf2Params.iterations = CryptoConstants::DEFAULT_PBKDF2_ITERATIONS;
            pbkdf2Params.outputLength = params.outputLength;
            return DeriveKey(password, salt, pbkdf2Params);
        }

        default:
            break;
    }

    return result;
}

std::vector<uint8_t> CryptoManagerImpl::ComputeHKDF(
    std::span<const uint8_t> inputKeyMaterial,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t outputLength,
    HashAlgorithm algorithm) {

    std::vector<uint8_t> result;

    // HKDF Extract
    std::vector<uint8_t> prk = ComputeHMAC(inputKeyMaterial, salt.empty() ?
        std::vector<uint8_t>(GetHashSize(algorithm), 0) :
        std::vector<uint8_t>(salt.begin(), salt.end()), algorithm);

    if (prk.empty()) {
        return result;
    }

    // HKDF Expand (RFC 5869: N must not exceed 255)
    size_t hashLen = GetHashSize(algorithm);
    if (hashLen == 0) {
        return result;
    }
    size_t n = (outputLength + hashLen - 1) / hashLen;
    if (n > 255) {
        SS_LOG_ERROR(LOG_CATEGORY, L"HKDF output length exceeds RFC 5869 limit (255 * HashLen)");
        return result;
    }

    result.reserve(n * hashLen);
    std::vector<uint8_t> t;
    t.reserve(hashLen + info.size() + 1);

    for (size_t i = 1; i <= n; ++i) {
        t.clear();
        if (i > 1) {
            t.insert(t.end(), result.end() - hashLen, result.end());
        }
        t.insert(t.end(), info.begin(), info.end());
        t.push_back(static_cast<uint8_t>(i));

        auto block = ComputeHMAC(t, prk, algorithm);
        result.insert(result.end(), block.begin(), block.end());
    }

    result.resize(outputLength);
    m_stats.totalKeyDerivations.fetch_add(1, std::memory_order_relaxed);

    return result;
}

std::string CryptoManagerImpl::HashPassword(
    std::string_view password,
    KDFAlgorithm algorithm) {

    auto salt = GenerateSalt();

    KDFParameters params;
    params.algorithm = algorithm;
    params.outputLength = 32;

    auto derived = DeriveKey(password, salt, params);
    if (derived.empty()) {
        return "";
    }

    std::ostringstream oss;
    oss << "$" << static_cast<int>(algorithm);
    oss << "$" << params.iterations;
    oss << "$" << BytesToHex(salt);
    oss << "$" << BytesToHex(derived);

    return oss.str();
}

bool CryptoManagerImpl::VerifyPassword(
    std::string_view password,
    std::string_view hash) {

    if (hash.empty() || hash[0] != '$') {
        return false;
    }

    std::string hashStr(hash);
    std::vector<std::string> parts;
    size_t start = 1;
    size_t end = 0;

    while ((end = hashStr.find('$', start)) != std::string::npos) {
        parts.push_back(hashStr.substr(start, end - start));
        start = end + 1;
    }
    parts.push_back(hashStr.substr(start));

    if (parts.size() != 4) {
        return false;
    }

    try {
        int rawAlgorithm = std::stoi(parts[0]);
        if (rawAlgorithm < static_cast<int>(KDFAlgorithm::None) ||
            rawAlgorithm > static_cast<int>(KDFAlgorithm::BCrypt)) {
            SS_LOG_WARN(LOG_CATEGORY, L"VerifyPassword: invalid KDF algorithm value %d", rawAlgorithm);
            return false;
        }
        KDFAlgorithm algorithm = static_cast<KDFAlgorithm>(rawAlgorithm);
        uint32_t iterations = static_cast<uint32_t>(std::stoul(parts[1]));

        std::vector<uint8_t> salt;
        for (size_t i = 0; i < parts[2].length(); i += 2) {
            salt.push_back(static_cast<uint8_t>(
                std::stoi(parts[2].substr(i, 2), nullptr, 16)));
        }

        std::vector<uint8_t> expectedHash;
        for (size_t i = 0; i < parts[3].length(); i += 2) {
            expectedHash.push_back(static_cast<uint8_t>(
                std::stoi(parts[3].substr(i, 2), nullptr, 16)));
        }

        KDFParameters params;
        params.algorithm = algorithm;
        params.iterations = iterations;
        params.outputLength = expectedHash.size();

        auto derived = DeriveKey(password, salt, params);
        return ConstantTimeCompare(derived, expectedHash);

    } catch (...) {
        return false;
    }
}

// ============================================================================
// CRYPTOMANAGERIMPL - KEY MANAGEMENT
// ============================================================================

std::string CryptoManagerImpl::StoreKey(
    std::span<const uint8_t> keyData,
    KeyType type,
    KeyStorage storage,
    std::string_view description) {

    if (keyData.empty()) {
        return "";
    }

    std::string keyId = GenerateKeyId();
    if (keyId.empty()) {
        return "";
    }

    auto managedKey = std::make_unique<ManagedKey>();
    managedKey->id = keyId;
    managedKey->metadata.id = keyId;
    managedKey->metadata.type = type;
    managedKey->metadata.storage = storage;
    managedKey->metadata.createdAt = std::chrono::system_clock::now();
    managedKey->metadata.description = std::string(description);
    managedKey->metadata.keySizeBits = static_cast<uint32_t>(keyData.size() * 8);

    switch (storage) {
        case KeyStorage::Memory:
            managedKey->keyData.assign(keyData.begin(), keyData.end());
            break;

        case KeyStorage::DPAPI: {
            auto protected_ = DPAPIProtect(keyData, {});
            if (!protected_) {
                return "";
            }
            managedKey->protectedData = std::move(*protected_);
            break;
        }

        default:
            managedKey->keyData.assign(keyData.begin(), keyData.end());
            break;
    }

    {
        std::unique_lock lock(m_keyStoreMutex);
        if (m_keyStore.size() >= CryptoConstants::MAX_KEY_COUNT) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Key store capacity limit reached (%zu keys)",
                         CryptoConstants::MAX_KEY_COUNT);
            return "";
        }
        m_keyStore[keyId] = std::move(managedKey);
        m_stats.activeKeys.store(m_keyStore.size(), std::memory_order_relaxed);
    }

    NotifyAudit("StoreKey", keyId, true);
    return keyId;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::RetrieveKey(const std::string& keyId) {
    if (keyId.empty()) {
        return std::nullopt;
    }

    // Exclusive lock required: we mutate usageCount and lastUsed
    std::unique_lock lock(m_keyStoreMutex);
    auto it = m_keyStore.find(keyId);
    if (it == m_keyStore.end()) {
        lock.unlock();
        NotifyAudit("RetrieveKey", keyId, false);
        return std::nullopt;
    }

    auto& managedKey = it->second;
    managedKey->metadata.usageCount++;
    managedKey->metadata.lastUsed = Clock::now();

    std::optional<std::vector<uint8_t>> result;

    switch (managedKey->metadata.storage) {
        case KeyStorage::Memory:
            result = managedKey->keyData;
            break;

        case KeyStorage::DPAPI: {
            auto protectedCopy = managedKey->protectedData;
            lock.unlock();
            auto unprotected = DPAPIUnprotect(protectedCopy, {});
            if (!unprotected) {
                NotifyAudit("RetrieveKey", keyId, false);
                return std::nullopt;
            }
            NotifyAudit("RetrieveKey", keyId, true);
            return unprotected;
        }

        default:
            result = managedKey->keyData;
            break;
    }

    lock.unlock();
    NotifyAudit("RetrieveKey", keyId, true);
    return result;
}

bool CryptoManagerImpl::DeleteKey(const std::string& keyId) {
    if (keyId.empty()) {
        return false;
    }

    std::unique_lock lock(m_keyStoreMutex);
    auto it = m_keyStore.find(keyId);
    if (it == m_keyStore.end()) {
        return false;
    }

    m_keyStore.erase(it);
    m_stats.activeKeys.store(m_keyStore.size(), std::memory_order_relaxed);

    NotifyAudit("DeleteKey", keyId, true);
    return true;
}

std::optional<KeyMetadata> CryptoManagerImpl::GetKeyMetadata(const std::string& keyId) const {
    if (keyId.empty()) {
        return std::nullopt;
    }

    std::shared_lock lock(m_keyStoreMutex);
    auto it = m_keyStore.find(keyId);
    if (it == m_keyStore.end()) {
        return std::nullopt;
    }

    return it->second->metadata;
}

std::vector<KeyMetadata> CryptoManagerImpl::ListKeys() const {
    std::vector<KeyMetadata> result;

    std::shared_lock lock(m_keyStoreMutex);
    result.reserve(m_keyStore.size());

    for (const auto& [id, key] : m_keyStore) {
        result.push_back(key->metadata);
    }

    return result;
}

std::string CryptoManagerImpl::RotateKey(const std::string& oldKeyId) {
    if (oldKeyId.empty()) {
        return "";
    }

    auto oldKeyData = RetrieveKey(oldKeyId);
    if (!oldKeyData) {
        return "";
    }

    auto oldMeta = GetKeyMetadata(oldKeyId);
    if (!oldMeta) {
        SecureZeroMemory(oldKeyData->data(), oldKeyData->size());
        return "";
    }

    auto newKeyData = GenerateRandomBytes(oldKeyData->size());
    SecureZeroMemory(oldKeyData->data(), oldKeyData->size());

    if (newKeyData.empty()) {
        return "";
    }

    std::string newKeyId = StoreKey(newKeyData, oldMeta->type, oldMeta->storage, oldMeta->description);
    SecureZeroMemory(newKeyData.data(), newKeyData.size());

    if (newKeyId.empty()) {
        return "";
    }

    auto newMeta = GetKeyMetadata(newKeyId);
    if (newMeta) {
        NotifyKeyRotation(oldKeyId, *oldMeta, *newMeta);
    }

    DeleteKey(oldKeyId);

    return newKeyId;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::ExportKey(
    const std::string& keyId,
    std::span<const uint8_t> wrappingKey) {

    auto keyData = RetrieveKey(keyId);
    if (!keyData) {
        return std::nullopt;
    }

    auto meta = GetKeyMetadata(keyId);
    if (!meta || !meta->isExportable) {
        return std::nullopt;
    }

    auto result = Encrypt(*keyData, wrappingKey, SymmetricAlgorithm::AES_256_GCM, {}, {});
    if (!result.IsSuccess()) {
        return std::nullopt;
    }

    NotifyAudit("ExportKey", keyId, true);
    return result.GetCombinedOutput();
}

std::string CryptoManagerImpl::ImportKey(
    std::span<const uint8_t> wrappedKey,
    std::span<const uint8_t> wrappingKey,
    KeyType type,
    KeyStorage storage) {

    if (wrappedKey.size() < CryptoConstants::AES_GCM_NONCE_SIZE + CryptoConstants::AES_GCM_TAG_SIZE) {
        return "";
    }

    std::span<const uint8_t> iv(wrappedKey.data(), CryptoConstants::AES_GCM_NONCE_SIZE);
    std::span<const uint8_t> tag(
        wrappedKey.data() + wrappedKey.size() - CryptoConstants::AES_GCM_TAG_SIZE,
        CryptoConstants::AES_GCM_TAG_SIZE);
    std::span<const uint8_t> ct(
        wrappedKey.data() + CryptoConstants::AES_GCM_NONCE_SIZE,
        wrappedKey.size() - CryptoConstants::AES_GCM_NONCE_SIZE - CryptoConstants::AES_GCM_TAG_SIZE);

    auto result = Decrypt(ct, wrappingKey, SymmetricAlgorithm::AES_256_GCM, iv, tag, {});
    if (!result.IsSuccess()) {
        return "";
    }

    std::string keyId = StoreKey(result.plaintext, type, storage, "Imported key");
    SecureZeroMemory(result.plaintext.data(), result.plaintext.size());

    if (!keyId.empty()) {
        NotifyAudit("ImportKey", keyId, true);
    }

    return keyId;
}

// ============================================================================
// CRYPTOMANAGERIMPL - DPAPI
// ============================================================================

std::optional<std::vector<uint8_t>> CryptoManagerImpl::DPAPIProtect(
    std::span<const uint8_t> data,
    std::span<const uint8_t> entropy) {

    DATA_BLOB inputBlob = {};
    inputBlob.cbData = static_cast<DWORD>(data.size());
    inputBlob.pbData = const_cast<BYTE*>(data.data());

    DATA_BLOB entropyBlob = {};
    DATA_BLOB* pEntropyBlob = nullptr;
    if (!entropy.empty()) {
        entropyBlob.cbData = static_cast<DWORD>(entropy.size());
        entropyBlob.pbData = const_cast<BYTE*>(entropy.data());
        pEntropyBlob = &entropyBlob;
    }

    DATA_BLOB outputBlob = {};

    BOOL success = CryptProtectData(
        &inputBlob,
        nullptr,
        pEntropyBlob,
        nullptr,
        nullptr,
        CRYPTPROTECT_LOCAL_MACHINE,
        &outputBlob);

    if (!success) {
        return std::nullopt;
    }

    std::vector<uint8_t> result(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    LocalFree(outputBlob.pbData);

    return result;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::DPAPIUnprotect(
    std::span<const uint8_t> protectedData,
    std::span<const uint8_t> entropy) {

    DATA_BLOB inputBlob = {};
    inputBlob.cbData = static_cast<DWORD>(protectedData.size());
    inputBlob.pbData = const_cast<BYTE*>(protectedData.data());

    DATA_BLOB entropyBlob = {};
    DATA_BLOB* pEntropyBlob = nullptr;
    if (!entropy.empty()) {
        entropyBlob.cbData = static_cast<DWORD>(entropy.size());
        entropyBlob.pbData = const_cast<BYTE*>(entropy.data());
        pEntropyBlob = &entropyBlob;
    }

    DATA_BLOB outputBlob = {};

    BOOL success = CryptUnprotectData(
        &inputBlob,
        nullptr,
        pEntropyBlob,
        nullptr,
        nullptr,
        0,
        &outputBlob);

    if (!success) {
        return std::nullopt;
    }

    std::vector<uint8_t> result(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
    SecureZeroMemory(outputBlob.pbData, outputBlob.cbData);
    LocalFree(outputBlob.pbData);

    return result;
}

// ============================================================================
// CRYPTOMANAGERIMPL - TPM
// ============================================================================

bool CryptoManagerImpl::IsTPMAvailable() const {
    return m_tpmAvailable.load(std::memory_order_acquire);
}

std::string CryptoManagerImpl::CreateTPMKey(KeyType type) {
    if (!m_tpmAvailable.load(std::memory_order_acquire) || !m_tpmProvider) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPM not available for key creation");
        return "";
    }

    LPCWSTR algId = nullptr;
    DWORD keyLength = 0;

    switch (type) {
        case KeyType::RSAPrivate:
            algId = NCRYPT_RSA_ALGORITHM;
            keyLength = CryptoConstants::RSA_2048_KEY_BITS;
            break;
        case KeyType::ECDSAPrivate:
            algId = NCRYPT_ECDSA_P256_ALGORITHM;
            keyLength = 256;
            break;
        case KeyType::Symmetric:
            algId = NCRYPT_AES_ALGORITHM;
            keyLength = 256;
            break;
        default:
            SS_LOG_ERROR(LOG_CATEGORY, L"Unsupported key type for TPM creation");
            return "";
    }

    std::string keyId = GenerateKeyId();
    if (keyId.empty()) {
        return "";
    }

    std::wstring keyName(keyId.begin(), keyId.end());

    NCRYPT_KEY_HANDLE keyHandle = 0;
    SECURITY_STATUS status = NCryptCreatePersistedKey(
        m_tpmProvider,
        &keyHandle,
        algId,
        keyName.c_str(),
        0,
        NCRYPT_OVERWRITE_KEY_FLAG);

    if (status != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CATEGORY, L"NCryptCreatePersistedKey failed: 0x%08lX", status);
        return "";
    }

    if (type == KeyType::RSAPrivate) {
        status = NCryptSetProperty(keyHandle, NCRYPT_LENGTH_PROPERTY,
            reinterpret_cast<PBYTE>(&keyLength), sizeof(keyLength), 0);
        if (status != ERROR_SUCCESS) {
            NCryptFreeObject(keyHandle);
            SS_LOG_ERROR(LOG_CATEGORY, L"Failed to set TPM key length: 0x%08lX", status);
            return "";
        }
    }

    status = NCryptFinalizeKey(keyHandle, 0);
    if (status != ERROR_SUCCESS) {
        NCryptFreeObject(keyHandle);
        SS_LOG_ERROR(LOG_CATEGORY, L"NCryptFinalizeKey failed: 0x%08lX", status);
        return "";
    }

    auto managedKey = std::make_unique<ManagedKey>();
    managedKey->id = keyId;
    managedKey->ncryptHandle = keyHandle;
    managedKey->metadata.id = keyId;
    managedKey->metadata.type = type;
    managedKey->metadata.storage = KeyStorage::TPM;
    managedKey->metadata.keySizeBits = keyLength;
    managedKey->metadata.createdAt = std::chrono::system_clock::now();
    managedKey->metadata.description = "TPM-protected key";

    {
        std::unique_lock lock(m_keyStoreMutex);
        if (m_keyStore.size() >= CryptoConstants::MAX_KEY_COUNT) {
            NCryptDeleteKey(keyHandle, 0);
            SS_LOG_ERROR(LOG_CATEGORY, L"Key store limit reached, cannot create TPM key");
            return "";
        }
        m_keyStore[keyId] = std::move(managedKey);
        m_stats.activeKeys.store(m_keyStore.size(), std::memory_order_relaxed);
    }

    m_stats.tpmOperations.fetch_add(1, std::memory_order_relaxed);
    NotifyAudit("CreateTPMKey", keyId, true);
    SS_LOG_INFO(LOG_CATEGORY, L"Created TPM key: %hs", keyId.c_str());
    return keyId;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::TPMSeal(std::span<const uint8_t> data) {
    if (!m_tpmAvailable.load(std::memory_order_acquire) || !m_tpmSealKey) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPM seal key not available");
        return std::nullopt;
    }

    if (data.empty() || data.size() > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid data size for TPM seal");
        return std::nullopt;
    }

    // Hybrid encryption: AES-256-GCM for data, TPM RSA-OAEP for AES key
    auto aesKey = GenerateRandomBytes(CryptoConstants::AES_256_KEY_SIZE);
    if (aesKey.size() != CryptoConstants::AES_256_KEY_SIZE) {
        return std::nullopt;
    }

    auto encResult = Encrypt(data, aesKey, SymmetricAlgorithm::AES_256_GCM, {}, {});
    if (!encResult.IsSuccess()) {
        SecureZeroMemory(aesKey.data(), aesKey.size());
        return std::nullopt;
    }

    // Seal the AES key with TPM RSA key
    BCRYPT_OAEP_PADDING_INFO oaepInfo{};
    oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    DWORD sealedKeySize = 0;
    SECURITY_STATUS status = NCryptEncrypt(m_tpmSealKey,
        aesKey.data(), static_cast<DWORD>(aesKey.size()),
        &oaepInfo, nullptr, 0, &sealedKeySize, NCRYPT_PAD_OAEP_FLAG);

    if (status != ERROR_SUCCESS) {
        SecureZeroMemory(aesKey.data(), aesKey.size());
        SS_LOG_ERROR(LOG_CATEGORY, L"TPMSeal: NCryptEncrypt size query failed: 0x%08lX", status);
        return std::nullopt;
    }

    std::vector<uint8_t> sealedKey(sealedKeySize);
    status = NCryptEncrypt(m_tpmSealKey,
        aesKey.data(), static_cast<DWORD>(aesKey.size()),
        &oaepInfo, sealedKey.data(), sealedKeySize, &sealedKeySize, NCRYPT_PAD_OAEP_FLAG);

    SecureZeroMemory(aesKey.data(), aesKey.size());

    if (status != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPMSeal: NCryptEncrypt failed: 0x%08lX", status);
        return std::nullopt;
    }
    sealedKey.resize(sealedKeySize);

    // Output: [4 bytes: sealed key len][sealed key][IV][ciphertext][tag]
    auto combined = encResult.GetCombinedOutput();
    const uint32_t skLen = static_cast<uint32_t>(sealedKey.size());

    std::vector<uint8_t> output;
    output.reserve(sizeof(skLen) + sealedKey.size() + combined.size());
    output.insert(output.end(),
                  reinterpret_cast<const uint8_t*>(&skLen),
                  reinterpret_cast<const uint8_t*>(&skLen) + sizeof(skLen));
    output.insert(output.end(), sealedKey.begin(), sealedKey.end());
    output.insert(output.end(), combined.begin(), combined.end());

    m_stats.tpmOperations.fetch_add(1, std::memory_order_relaxed);
    return output;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::TPMUnseal(std::span<const uint8_t> sealedData) {
    if (!m_tpmAvailable.load(std::memory_order_acquire) || !m_tpmSealKey) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPM seal key not available");
        return std::nullopt;
    }

    // Parse: [4 bytes: sealed key len][sealed key][IV(12)][ciphertext][tag(16)]
    constexpr size_t kHeaderSize = sizeof(uint32_t);
    if (sealedData.size() < kHeaderSize) {
        return std::nullopt;
    }

    uint32_t sealedKeyLen = 0;
    std::memcpy(&sealedKeyLen, sealedData.data(), sizeof(sealedKeyLen));

    if (sealedKeyLen == 0 || sealedKeyLen > 1024 ||
        sealedData.size() < kHeaderSize + sealedKeyLen +
        CryptoConstants::AES_GCM_NONCE_SIZE + CryptoConstants::AES_GCM_TAG_SIZE) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPMUnseal: Invalid sealed data format");
        return std::nullopt;
    }

    std::span<const uint8_t> sealedKey(
        sealedData.data() + kHeaderSize, sealedKeyLen);
    std::span<const uint8_t> encPayload(
        sealedData.data() + kHeaderSize + sealedKeyLen,
        sealedData.size() - kHeaderSize - sealedKeyLen);

    // Unseal the AES key with TPM RSA key
    BCRYPT_OAEP_PADDING_INFO oaepInfo{};
    oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    DWORD aesKeySize = 0;
    SECURITY_STATUS status = NCryptDecrypt(m_tpmSealKey,
        const_cast<PBYTE>(sealedKey.data()), static_cast<DWORD>(sealedKey.size()),
        &oaepInfo, nullptr, 0, &aesKeySize, NCRYPT_PAD_OAEP_FLAG);

    if (status != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPMUnseal: NCryptDecrypt size query failed: 0x%08lX", status);
        return std::nullopt;
    }

    std::vector<uint8_t> aesKey(aesKeySize);
    status = NCryptDecrypt(m_tpmSealKey,
        const_cast<PBYTE>(sealedKey.data()), static_cast<DWORD>(sealedKey.size()),
        &oaepInfo, aesKey.data(), aesKeySize, &aesKeySize, NCRYPT_PAD_OAEP_FLAG);

    if (status != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CATEGORY, L"TPMUnseal: NCryptDecrypt failed: 0x%08lX", status);
        return std::nullopt;
    }
    aesKey.resize(aesKeySize);

    // Parse IV + ciphertext + tag from encPayload
    if (encPayload.size() < CryptoConstants::AES_GCM_NONCE_SIZE + CryptoConstants::AES_GCM_TAG_SIZE) {
        SecureZeroMemory(aesKey.data(), aesKey.size());
        return std::nullopt;
    }

    std::span<const uint8_t> iv(encPayload.data(), CryptoConstants::AES_GCM_NONCE_SIZE);
    std::span<const uint8_t> tag(
        encPayload.data() + encPayload.size() - CryptoConstants::AES_GCM_TAG_SIZE,
        CryptoConstants::AES_GCM_TAG_SIZE);
    std::span<const uint8_t> ct(
        encPayload.data() + CryptoConstants::AES_GCM_NONCE_SIZE,
        encPayload.size() - CryptoConstants::AES_GCM_NONCE_SIZE - CryptoConstants::AES_GCM_TAG_SIZE);

    auto decResult = Decrypt(ct, aesKey, SymmetricAlgorithm::AES_256_GCM, iv, tag, {});
    SecureZeroMemory(aesKey.data(), aesKey.size());

    if (!decResult.IsSuccess()) {
        return std::nullopt;
    }

    m_stats.tpmOperations.fetch_add(1, std::memory_order_relaxed);
    return decResult.plaintext;
}

// ============================================================================
// CRYPTOMANAGERIMPL - SECURE MEMORY
// ============================================================================

void* CryptoManagerImpl::SecureAlloc(size_t size) {
    if (size == 0 || size > CryptoConstants::MAX_ENCRYPTION_SIZE) {
        return nullptr;
    }
    void* ptr = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (ptr) {
        if (!VirtualLock(ptr, size)) {
            SS_LOG_WARN(LOG_CATEGORY, L"VirtualLock failed for secure allocation of %zu bytes "
                        L"(working set limit may be reached)", size);
        }
    }
    return ptr;
}

void CryptoManagerImpl::SecureFree(void* ptr, size_t size) {
    if (ptr) {
        SecureZeroMemory(ptr, size);
        VirtualUnlock(ptr, size);
        VirtualFree(ptr, 0, MEM_RELEASE);
    }
}

void CryptoManagerImpl::SecureZero(void* ptr, size_t size) {
    if (ptr && size > 0) {
        SecureZeroMemory(ptr, size);
    }
}

bool CryptoManagerImpl::ConstantTimeCompare(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) noexcept {

    // Prevent timing side-channel: normalize execution time regardless of size match.
    // If sizes differ, iterate over the longer span with dummy XORs, then fail.
    const size_t maxLen = (std::max)(a.size(), b.size());
    if (maxLen == 0) {
        return a.size() == b.size();
    }

    volatile uint8_t result = 0;
    // XOR mismatch on size difference: ensures size inequality always causes failure
    result |= static_cast<uint8_t>(a.size() ^ b.size());

    for (size_t i = 0; i < maxLen; ++i) {
        // Safe indexing: clamp to valid range to avoid OOB while still iterating
        const uint8_t byteA = (i < a.size()) ? a[i] : 0;
        const uint8_t byteB = (i < b.size()) ? b[i] : 0;
        result |= byteA ^ byteB;
    }

    return result == 0;
}

// ============================================================================
// CRYPTOMANAGERIMPL - DIGITAL SIGNATURES
// ============================================================================

SignatureResult CryptoManagerImpl::Sign(
    std::span<const uint8_t> data,
    const std::string& privateKeyId,
    HashAlgorithm hashAlgorithm) {

    SignatureResult result;

    auto keyData = RetrieveKey(privateKeyId);
    if (!keyData) {
        result.result = CryptoResult::KeyNotFound;
        return result;
    }

    auto keyMeta = GetKeyMetadata(privateKeyId);
    if (!keyMeta) {
        result.result = CryptoResult::KeyNotFound;
        return result;
    }

    auto hash = Hash(data, hashAlgorithm);
    if (hash.empty()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    LPCWSTR algId = nullptr;
    LPCWSTR blobType = nullptr;

    if (keyMeta->type == KeyType::RSAPrivate) {
        algId = BCRYPT_RSA_ALGORITHM;
        blobType = BCRYPT_RSAFULLPRIVATE_BLOB;
    } else if (keyMeta->type == KeyType::ECDSAPrivate) {
        blobType = BCRYPT_ECCPRIVATE_BLOB;
        // Select correct curve algorithm from key metadata
        if (auto* asymAlg = std::get_if<AsymmetricAlgorithm>(&keyMeta->algorithm)) {
            switch (*asymAlg) {
                case AsymmetricAlgorithm::ECDSA_P384:
                    algId = BCRYPT_ECDSA_P384_ALGORITHM;
                    break;
                case AsymmetricAlgorithm::ECDSA_P521:
                    algId = BCRYPT_ECDSA_P521_ALGORITHM;
                    break;
                case AsymmetricAlgorithm::ECDSA_P256:
                default:
                    algId = BCRYPT_ECDSA_P256_ALGORITHM;
                    break;
            }
        } else {
            algId = BCRYPT_ECDSA_P256_ALGORITHM;
        }
    } else {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    BCryptAlgorithmHandle alg;
    if (!alg.Open(algId)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status = BCryptImportKeyPair(
        alg.Get(),
        nullptr,
        blobType,
        &keyHandle,
        const_cast<PUCHAR>(keyData->data()),
        static_cast<ULONG>(keyData->size()),
        0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    DWORD signatureSize = 0;
    status = BCryptSignHash(keyHandle, nullptr,
        hash.data(), static_cast<ULONG>(hash.size()),
        nullptr, 0, &signatureSize, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.signature.resize(signatureSize);
    status = BCryptSignHash(keyHandle, nullptr,
        hash.data(), static_cast<ULONG>(hash.size()),
        result.signature.data(), signatureSize, &signatureSize, 0);

    BCryptDestroyKey(keyHandle);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.signature.resize(signatureSize);
    result.result = CryptoResult::Success;

    m_stats.totalSignatures.fetch_add(1, std::memory_order_relaxed);
    NotifyAudit("Sign", privateKeyId, true);

    return result;
}

bool CryptoManagerImpl::Verify(
    std::span<const uint8_t> data,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> publicKey,
    HashAlgorithm hashAlgorithm) {

    auto hash = Hash(data, hashAlgorithm);
    if (hash.empty()) {
        return false;
    }

    // Determine key type from BCRYPT_KEY_BLOB Magic field instead of blindly trying both.
    // This prevents key type confusion attacks where an attacker crafts an ambiguous blob.
    if (publicKey.size() < sizeof(ULONG)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Verify: public key blob too small to contain magic");
        return false;
    }

    ULONG magic = 0;
    std::memcpy(&magic, publicKey.data(), sizeof(ULONG));

    BCryptAlgorithmHandle alg;
    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status;

    // RSA public key blobs: BCRYPT_RSAPUBLIC_MAGIC = 0x31415352 ('RSA1')
    if (magic == BCRYPT_RSAPUBLIC_MAGIC) {
        if (!alg.Open(BCRYPT_RSA_ALGORITHM)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Verify: failed to open RSA algorithm");
            return false;
        }
        status = BCryptImportKeyPair(alg.Get(), nullptr, BCRYPT_RSAPUBLIC_BLOB,
            &keyHandle, const_cast<PUCHAR>(publicKey.data()),
            static_cast<ULONG>(publicKey.size()), 0);
        if (!NT_SUCCESS(status)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Verify: RSA key import failed, NTSTATUS=0x%08X", status);
            return false;
        }

        BCRYPT_PKCS1_PADDING_INFO pkcs1Info;
        pkcs1Info.pszAlgId = GetBCryptHashAlgorithm(hashAlgorithm);
        status = BCryptVerifySignature(keyHandle, &pkcs1Info,
            hash.data(), static_cast<ULONG>(hash.size()),
            const_cast<PUCHAR>(signature.data()),
            static_cast<ULONG>(signature.size()), BCRYPT_PAD_PKCS1);

        BCryptDestroyKey(keyHandle);
        m_stats.totalVerifications.fetch_add(1, std::memory_order_relaxed);
        return NT_SUCCESS(status);
    }

    // ECC public key blobs: BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345 ('ECS1')
    //                        BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345 ('ECS3')
    //                        BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345 ('ECS5')
    if (magic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC) {
        if (!alg.Open(BCRYPT_ECDSA_P256_ALGORITHM)) {
            return false;
        }
    } else if (magic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC) {
        if (!alg.Open(BCRYPT_ECDSA_P384_ALGORITHM)) {
            return false;
        }
    } else if (magic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC) {
        if (!alg.Open(BCRYPT_ECDSA_P521_ALGORITHM)) {
            return false;
        }
    } else {
        SS_LOG_ERROR(LOG_CATEGORY, L"Verify: unrecognized key blob magic 0x%08X", magic);
        return false;
    }

    status = BCryptImportKeyPair(alg.Get(), nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &keyHandle, const_cast<PUCHAR>(publicKey.data()),
        static_cast<ULONG>(publicKey.size()), 0);

    if (!NT_SUCCESS(status)) {
        SS_LOG_WARN(LOG_CATEGORY, L"Verify: ECC key import failed, NTSTATUS=0x%08X", status);
        return false;
    }

    status = BCryptVerifySignature(keyHandle, nullptr,
        hash.data(), static_cast<ULONG>(hash.size()),
        const_cast<PUCHAR>(signature.data()),
        static_cast<ULONG>(signature.size()), 0);

    BCryptDestroyKey(keyHandle);
    m_stats.totalVerifications.fetch_add(1, std::memory_order_relaxed);
    return NT_SUCCESS(status);
}

SignatureResult CryptoManagerImpl::SignEd25519(
    std::span<const uint8_t> data,
    const std::string& privateKeyId) {
    SignatureResult result;
    result.result = CryptoResult::AlgorithmNotSupported;
    return result;
}

bool CryptoManagerImpl::VerifyEd25519(
    std::span<const uint8_t> data,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> publicKey) {
    return false;
}

// ============================================================================
// CRYPTOMANAGERIMPL - RSA ASYMMETRIC
// ============================================================================

EncryptionResult CryptoManagerImpl::RSAEncrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> publicKey,
    RSAPadding padding) {

    EncryptionResult result;

    std::shared_lock algLock(m_algMutex);
    if (!m_rsaAlg.IsValid()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status = BCryptImportKeyPair(m_rsaAlg.Get(), nullptr, BCRYPT_RSAPUBLIC_BLOB,
        &keyHandle, const_cast<PUCHAR>(publicKey.data()),
        static_cast<ULONG>(publicKey.size()), 0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    BCRYPT_OAEP_PADDING_INFO oaepInfo = {};
    void* paddingInfo = nullptr;
    ULONG flags = 0;

    switch (padding) {
        case RSAPadding::OAEP_SHA256:
            oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::OAEP_SHA384:
            oaepInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::OAEP_SHA512:
            oaepInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::PKCS1:
            if (IsFIPSModeEnabled()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"RSAEncrypt: PKCS1 v1.5 padding prohibited in FIPS mode — use OAEP");
                BCryptDestroyKey(keyHandle);
                result.result = CryptoResult::AlgorithmNotSupported;
                result.errorMessage = "PKCS1 v1.5 prohibited in FIPS mode";
                return result;
            }
            SS_LOG_WARN(LOG_CATEGORY, L"RSAEncrypt: PKCS1 v1.5 is DEPRECATED — migrate to OAEP");
            flags = BCRYPT_PAD_PKCS1;
            break;
        default:
            BCryptDestroyKey(keyHandle);
            result.result = CryptoResult::AlgorithmNotSupported;
            return result;
    }

    DWORD ciphertextSize = 0;
    status = BCryptEncrypt(keyHandle,
        const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
        paddingInfo, nullptr, 0, nullptr, 0, &ciphertextSize, flags);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.ciphertext.resize(ciphertextSize);
    status = BCryptEncrypt(keyHandle,
        const_cast<PUCHAR>(plaintext.data()), static_cast<ULONG>(plaintext.size()),
        paddingInfo, nullptr, 0,
        result.ciphertext.data(), ciphertextSize, &ciphertextSize, flags);

    BCryptDestroyKey(keyHandle);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.ciphertext.resize(ciphertextSize);
    result.result = CryptoResult::Success;

    m_stats.totalEncryptions.fetch_add(1, std::memory_order_relaxed);
    return result;
}

DecryptionResult CryptoManagerImpl::RSADecrypt(
    std::span<const uint8_t> ciphertext,
    const std::string& privateKeyId,
    RSAPadding padding) {

    DecryptionResult result;

    auto keyData = RetrieveKey(privateKeyId);
    if (!keyData) {
        result.result = CryptoResult::KeyNotFound;
        return result;
    }

    std::shared_lock algLock(m_algMutex);
    if (!m_rsaAlg.IsValid()) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    BCRYPT_KEY_HANDLE keyHandle = nullptr;
    NTSTATUS status = BCryptImportKeyPair(m_rsaAlg.Get(), nullptr, BCRYPT_RSAFULLPRIVATE_BLOB,
        &keyHandle, const_cast<PUCHAR>(keyData->data()),
        static_cast<ULONG>(keyData->size()), 0);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InvalidKey;
        return result;
    }

    BCRYPT_OAEP_PADDING_INFO oaepInfo = {};
    void* paddingInfo = nullptr;
    ULONG flags = 0;

    switch (padding) {
        case RSAPadding::OAEP_SHA256:
            oaepInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::OAEP_SHA384:
            oaepInfo.pszAlgId = BCRYPT_SHA384_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::OAEP_SHA512:
            oaepInfo.pszAlgId = BCRYPT_SHA512_ALGORITHM;
            paddingInfo = &oaepInfo;
            flags = BCRYPT_PAD_OAEP;
            break;
        case RSAPadding::PKCS1:
            if (IsFIPSModeEnabled()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"RSADecrypt: PKCS1 v1.5 padding prohibited in FIPS mode — use OAEP");
                BCryptDestroyKey(keyHandle);
                result.result = CryptoResult::AlgorithmNotSupported;
                result.errorMessage = "PKCS1 v1.5 prohibited in FIPS mode";
                return result;
            }
            SS_LOG_WARN(LOG_CATEGORY, L"RSADecrypt: PKCS1 v1.5 is DEPRECATED — migrate to OAEP");
            flags = BCRYPT_PAD_PKCS1;
            break;
        default:
            BCryptDestroyKey(keyHandle);
            result.result = CryptoResult::AlgorithmNotSupported;
            return result;
    }

    DWORD plaintextSize = 0;
    status = BCryptDecrypt(keyHandle,
        const_cast<PUCHAR>(ciphertext.data()), static_cast<ULONG>(ciphertext.size()),
        paddingInfo, nullptr, 0, nullptr, 0, &plaintextSize, flags);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(keyHandle);
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.plaintext.resize(plaintextSize);
    status = BCryptDecrypt(keyHandle,
        const_cast<PUCHAR>(ciphertext.data()), static_cast<ULONG>(ciphertext.size()),
        paddingInfo, nullptr, 0,
        result.plaintext.data(), plaintextSize, &plaintextSize, flags);

    BCryptDestroyKey(keyHandle);

    if (!NT_SUCCESS(status)) {
        result.result = CryptoResult::InternalError;
        return result;
    }

    result.plaintext.resize(plaintextSize);
    result.result = CryptoResult::Success;

    m_stats.totalDecryptions.fetch_add(1, std::memory_order_relaxed);
    NotifyAudit("RSADecrypt", privateKeyId, true);

    return result;
}

std::optional<std::vector<uint8_t>> CryptoManagerImpl::ECDHKeyAgreement(
    std::span<const uint8_t> peerPublicKey,
    const std::string& privateKeyId) {

    auto keyData = RetrieveKey(privateKeyId);
    if (!keyData) {
        return std::nullopt;
    }

    std::shared_lock algLock(m_algMutex);
    if (!m_ecdhP256Alg.IsValid()) {
        return std::nullopt;
    }

    BCRYPT_KEY_HANDLE privateKey = nullptr;
    NTSTATUS status = BCryptImportKeyPair(m_ecdhP256Alg.Get(), nullptr, BCRYPT_ECCPRIVATE_BLOB,
        &privateKey, const_cast<PUCHAR>(keyData->data()),
        static_cast<ULONG>(keyData->size()), 0);

    if (!NT_SUCCESS(status)) {
        return std::nullopt;
    }

    BCRYPT_KEY_HANDLE peerKey = nullptr;
    status = BCryptImportKeyPair(m_ecdhP256Alg.Get(), nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &peerKey, const_cast<PUCHAR>(peerPublicKey.data()),
        static_cast<ULONG>(peerPublicKey.size()), 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(privateKey);
        return std::nullopt;
    }

    BCRYPT_SECRET_HANDLE secret = nullptr;
    status = BCryptSecretAgreement(privateKey, peerKey, &secret, 0);

    BCryptDestroyKey(privateKey);
    BCryptDestroyKey(peerKey);

    if (!NT_SUCCESS(status)) {
        return std::nullopt;
    }

    DWORD derivedSize = 32;
    std::vector<uint8_t> derived(derivedSize);

    BCryptBuffer paramBuffer = {};
    paramBuffer.cbBuffer = sizeof(BCRYPT_SHA256_ALGORITHM);
    paramBuffer.BufferType = KDF_HASH_ALGORITHM;
    paramBuffer.pvBuffer = const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM);

    BCryptBufferDesc paramDesc = {};
    paramDesc.ulVersion = BCRYPTBUFFER_VERSION;
    paramDesc.cBuffers = 1;
    paramDesc.pBuffers = &paramBuffer;

    status = BCryptDeriveKey(secret, BCRYPT_KDF_HASH, &paramDesc,
        derived.data(), derivedSize, &derivedSize, 0);

    BCryptDestroySecret(secret);

    if (!NT_SUCCESS(status)) {
        return std::nullopt;
    }

    derived.resize(derivedSize);
    return derived;
}

// ============================================================================
// CRYPTOMANAGERIMPL - INTERNAL HELPERS
// ============================================================================

bool CryptoManagerImpl::InitializeAlgorithms() {
    std::unique_lock lock(m_algMutex);

    if (!m_aesAlg.Open(BCRYPT_AES_ALGORITHM)) {
        return false;
    }

    NTSTATUS status = BCryptSetProperty(m_aesAlg.Get(), BCRYPT_CHAINING_MODE,
        reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)),
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

    if (!NT_SUCCESS(status)) {
        return false;
    }

    if (!m_sha256Alg.Open(BCRYPT_SHA256_ALGORITHM)) {
        return false;
    }

    if (!m_sha384Alg.Open(BCRYPT_SHA384_ALGORITHM)) {
        return false;
    }

    if (!m_sha512Alg.Open(BCRYPT_SHA512_ALGORITHM)) {
        return false;
    }

    if (!m_rngAlg.Open(BCRYPT_RNG_ALGORITHM)) {
        return false;
    }

    m_rsaAlg.Open(BCRYPT_RSA_ALGORITHM);
    m_ecdsaP256Alg.Open(BCRYPT_ECDSA_P256_ALGORITHM);
    m_ecdhP256Alg.Open(BCRYPT_ECDH_P256_ALGORITHM);

    return true;
}

bool CryptoManagerImpl::InitializeTPM() {
    SECURITY_STATUS status = NCryptOpenStorageProvider(&m_tpmProvider,
        MS_PLATFORM_CRYPTO_PROVIDER, 0);

    if (status != ERROR_SUCCESS) {
        SS_LOG_WARN(LOG_CATEGORY, L"TPM provider not available: 0x%08lX", status);
        return false;
    }

    // Create or open a persistent RSA sealing key for TPMSeal/TPMUnseal
    status = NCryptOpenKey(m_tpmProvider, &m_tpmSealKey,
                           L"SS_TPM_SEAL_KEY", 0, 0);

    if (status != ERROR_SUCCESS) {
        // Key doesn't exist yet, create it
        status = NCryptCreatePersistedKey(m_tpmProvider, &m_tpmSealKey,
                                          NCRYPT_RSA_ALGORITHM,
                                          L"SS_TPM_SEAL_KEY", 0, 0);
        if (status != ERROR_SUCCESS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to create TPM seal key: 0x%08lX", status);
            m_tpmAvailable.store(true, std::memory_order_release);
            m_tpmSealKey = 0;
            SS_LOG_INFO(LOG_CATEGORY, L"TPM initialized (seal key unavailable)");
            return true;
        }

        DWORD keyLen = CryptoConstants::RSA_2048_KEY_BITS;
        NCryptSetProperty(m_tpmSealKey, NCRYPT_LENGTH_PROPERTY,
                          reinterpret_cast<PBYTE>(&keyLen), sizeof(keyLen), 0);

        status = NCryptFinalizeKey(m_tpmSealKey, 0);
        if (status != ERROR_SUCCESS) {
            SS_LOG_WARN(LOG_CATEGORY, L"Failed to finalize TPM seal key: 0x%08lX", status);
            NCryptFreeObject(m_tpmSealKey);
            m_tpmSealKey = 0;
        }
    }

    m_tpmAvailable.store(true, std::memory_order_release);
    SS_LOG_INFO(LOG_CATEGORY, L"TPM initialized successfully (seal key: %ls)",
                m_tpmSealKey ? L"available" : L"unavailable");
    return true;
}

bool CryptoManagerImpl::DetectHardwareCapabilities() {
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    m_hasAESNI.store((cpuInfo[2] & (1 << 25)) != 0, std::memory_order_release);
    m_hasRDRAND.store((cpuInfo[2] & (1 << 30)) != 0, std::memory_order_release);

    SS_LOG_INFO(LOG_CATEGORY, L"AES-NI: %ls, RDRAND: %ls",
                m_hasAESNI.load() ? L"Yes" : L"No",
                m_hasRDRAND.load() ? L"Yes" : L"No");

    return true;
}

size_t CryptoManagerImpl::GetKeySize(SymmetricAlgorithm algorithm) const {
    switch (algorithm) {
        case SymmetricAlgorithm::AES_128_GCM:
        case SymmetricAlgorithm::AES_128_CBC:
        case SymmetricAlgorithm::AES_128_CTR:
            return CryptoConstants::AES_128_KEY_SIZE;

        case SymmetricAlgorithm::AES_192_GCM:
            return CryptoConstants::AES_192_KEY_SIZE;

        case SymmetricAlgorithm::AES_256_GCM:
        case SymmetricAlgorithm::AES_256_CBC:
        case SymmetricAlgorithm::AES_256_CTR:
        case SymmetricAlgorithm::AES_256_XTS:
            return CryptoConstants::AES_256_KEY_SIZE;

        case SymmetricAlgorithm::ChaCha20_Poly1305:
            return CryptoConstants::CHACHA20_KEY_SIZE;

        default:
            return 0;
    }
}

size_t CryptoManagerImpl::GetIVSize(SymmetricAlgorithm algorithm) const {
    switch (algorithm) {
        case SymmetricAlgorithm::AES_128_GCM:
        case SymmetricAlgorithm::AES_192_GCM:
        case SymmetricAlgorithm::AES_256_GCM:
        case SymmetricAlgorithm::ChaCha20_Poly1305:
            return CryptoConstants::AES_GCM_NONCE_SIZE;

        case SymmetricAlgorithm::AES_128_CBC:
        case SymmetricAlgorithm::AES_256_CBC:
        case SymmetricAlgorithm::AES_128_CTR:
        case SymmetricAlgorithm::AES_256_CTR:
            return CryptoConstants::AES_CBC_IV_SIZE;

        default:
            return 0;
    }
}

size_t CryptoManagerImpl::GetTagSize(SymmetricAlgorithm algorithm) const {
    switch (algorithm) {
        case SymmetricAlgorithm::AES_128_GCM:
        case SymmetricAlgorithm::AES_192_GCM:
        case SymmetricAlgorithm::AES_256_GCM:
            return CryptoConstants::AES_GCM_TAG_SIZE;

        case SymmetricAlgorithm::ChaCha20_Poly1305:
            return CryptoConstants::POLY1305_TAG_SIZE;

        default:
            return 0;
    }
}

size_t CryptoManagerImpl::GetHashSize(HashAlgorithm algorithm) const {
    switch (algorithm) {
        case HashAlgorithm::SHA256:
        case HashAlgorithm::SHA3_256:
        case HashAlgorithm::BLAKE2b_256:
        case HashAlgorithm::BLAKE2s_256:
            return CryptoConstants::SHA256_SIZE;

        case HashAlgorithm::SHA384:
            return CryptoConstants::SHA384_SIZE;

        case HashAlgorithm::SHA512:
        case HashAlgorithm::SHA3_512:
        case HashAlgorithm::BLAKE2b_512:
            return CryptoConstants::SHA512_SIZE;

        case HashAlgorithm::MD5:
            return 16;

        case HashAlgorithm::SHA1:
            return 20;

        default:
            return 0;
    }
}

LPCWSTR CryptoManagerImpl::GetBCryptHashAlgorithm(HashAlgorithm algorithm) const {
    switch (algorithm) {
        case HashAlgorithm::SHA256:     return BCRYPT_SHA256_ALGORITHM;
        case HashAlgorithm::SHA384:     return BCRYPT_SHA384_ALGORITHM;
        case HashAlgorithm::SHA512:     return BCRYPT_SHA512_ALGORITHM;
        case HashAlgorithm::MD5:        return BCRYPT_MD5_ALGORITHM;
        case HashAlgorithm::SHA1:       return BCRYPT_SHA1_ALGORITHM;
        default:                        return nullptr;
    }
}

bool CryptoManagerImpl::IsHardwareAccelerationAvailable() const {
    return m_hasAESNI.load(std::memory_order_acquire);
}

bool CryptoManagerImpl::IsFIPSModeEnabled() const {
    std::shared_lock lock(m_configMutex);
    return m_config.enableFIPSMode;
}

std::vector<std::string> CryptoManagerImpl::GetSupportedAlgorithms() const {
    return {
        "AES-128-GCM", "AES-256-GCM", "AES-128-CBC", "AES-256-CBC",
        "RSA-2048", "RSA-3072", "RSA-4096",
        "ECDSA-P256", "ECDSA-P384", "ECDSA-P521",
        "ECDH-P256",
        "SHA-256", "SHA-384", "SHA-512",
        "HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512",
        "PBKDF2-SHA256", "HKDF-SHA256"
    };
}

// ============================================================================
// CRYPTOMANAGERIMPL - CALLBACKS
// ============================================================================

void CryptoManagerImpl::SetKeyRotationCallback(KeyRotationCallback callback) {
    std::unique_lock lock(m_callbackMutex);
    m_keyRotationCallback = std::move(callback);
}

void CryptoManagerImpl::SetAuditCallback(CryptoAuditCallback callback) {
    std::unique_lock lock(m_callbackMutex);
    m_auditCallback = std::move(callback);
}

void CryptoManagerImpl::NotifyKeyRotation(
    const std::string& keyId,
    const KeyMetadata& oldMeta,
    const KeyMetadata& newMeta) {

    std::shared_lock lock(m_callbackMutex);
    if (m_keyRotationCallback) {
        try {
            m_keyRotationCallback(keyId, oldMeta, newMeta);
        } catch (...) {}
    }
}

void CryptoManagerImpl::NotifyAudit(
    const std::string& operation,
    const std::string& keyId,
    bool success) {

    std::shared_lock lock(m_callbackMutex);
    if (m_auditCallback) {
        try {
            m_auditCallback(operation, keyId, success);
        } catch (...) {}
    }
}

// ============================================================================
// CRYPTOMANAGERIMPL - STATISTICS
// ============================================================================

CryptoManagerStatistics CryptoManagerImpl::GetStatistics() const {
    return m_stats.Snapshot();
}

void CryptoManagerImpl::ResetStatistics() {
    m_stats.Reset();
}

bool CryptoManagerImpl::SelfTest() {
    SS_LOG_INFO(LOG_CATEGORY, L"Running CryptoManager self-test");

    try {
        // Test 1: Random generation
        {
            auto random1 = GenerateRandomBytes(32);
            auto random2 = GenerateRandomBytes(32);
            if (random1.size() != 32 || random2.size() != 32) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Random generation");
                return false;
            }
            if (random1 == random2) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Random not unique");
                return false;
            }
        }

        // Test 2: Hashing
        {
            std::vector<uint8_t> testData = {'t', 'e', 's', 't'};
            auto hash = SHA256Hash(testData);

            std::array<uint8_t, 32> expected = {
                0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
                0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
                0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
                0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08
            };

            if (hash != expected) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: SHA-256 mismatch");
                return false;
            }
        }

        // Test 3: AES-GCM encryption/decryption
        {
            std::vector<uint8_t> key(32);
            std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

            auto randomKey = GenerateRandomBytes(32);
            std::copy(randomKey.begin(), randomKey.end(), key.begin());

            auto encResult = Encrypt(plaintext, key, SymmetricAlgorithm::AES_256_GCM, {}, {});
            if (!encResult.IsSuccess()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Encryption");
                return false;
            }

            auto decResult = Decrypt(encResult.ciphertext, key,
                                      SymmetricAlgorithm::AES_256_GCM,
                                      encResult.iv, encResult.tag, {});
            if (!decResult.IsSuccess()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Decryption");
                return false;
            }

            if (decResult.plaintext != plaintext) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Plaintext mismatch");
                return false;
            }
        }

        // Test 4: Constant-time comparison
        {
            std::vector<uint8_t> a = {1, 2, 3, 4};
            std::vector<uint8_t> b = {1, 2, 3, 4};
            std::vector<uint8_t> c = {1, 2, 3, 5};

            if (!ConstantTimeCompare(a, b)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: CT compare equal");
                return false;
            }

            if (ConstantTimeCompare(a, c)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: CT compare different");
                return false;
            }
        }

        // Test 5: Key storage
        {
            auto key = GenerateRandomBytes(32);
            std::string keyId = StoreKey(key, KeyType::Symmetric, KeyStorage::Memory, "Test key");

            if (keyId.empty()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Key storage");
                return false;
            }

            auto retrieved = RetrieveKey(keyId);
            if (!retrieved || *retrieved != key) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Self-test failed: Key retrieval");
                DeleteKey(keyId);
                return false;
            }

            DeleteKey(keyId);
        }

        SS_LOG_INFO(LOG_CATEGORY, L"CryptoManager self-test passed");
        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Self-test exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// CRYPTOMANAGERIMPL - KERNEL CHANNEL ATTESTATION
// ============================================================================

std::optional<CryptoManager::KernelSessionKeyResult> CryptoManagerImpl::DeriveKernelSessionKey(
    std::span<const uint8_t> driverPublicKey,
    std::span<const uint8_t> driverHash,
    std::string_view contextLabel) {

    if (driverPublicKey.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: empty driver public key");
        return std::nullopt;
    }
    if (driverHash.size() != 32) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: driver hash must be SHA-256 (32 bytes), got %zu", driverHash.size());
        return std::nullopt;
    }
    if (contextLabel.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: empty context label");
        return std::nullopt;
    }

    // Step 1: Generate ephemeral ECDH P-256 key pair for this session
    std::shared_lock algLock(m_algMutex);
    if (!m_ecdhP256Alg.IsValid()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: ECDH P-256 algorithm not initialized");
        return std::nullopt;
    }

    BCRYPT_KEY_HANDLE localKeyHandle = nullptr;
    NTSTATUS status = BCryptGenerateKeyPair(
        m_ecdhP256Alg.Get(), &localKeyHandle, 256, 0);
    algLock.unlock();

    if (!NT_SUCCESS(status) || !localKeyHandle) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: key pair generation failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    status = BCryptFinalizeKeyPair(localKeyHandle, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(localKeyHandle);
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: key pair finalization failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    // Step 1b: Export our ephemeral public key — the driver needs this for its side of ECDH
    DWORD localPubKeySize = 0;
    status = BCryptExportKey(localKeyHandle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        nullptr, 0, &localPubKeySize, 0);
    if (!NT_SUCCESS(status) || localPubKeySize == 0) {
        BCryptDestroyKey(localKeyHandle);
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: public key size query failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    std::vector<uint8_t> localPublicKey(localPubKeySize);
    status = BCryptExportKey(localKeyHandle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        localPublicKey.data(), localPubKeySize, &localPubKeySize, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(localKeyHandle);
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: public key export failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }
    localPublicKey.resize(localPubKeySize);

    // Step 2: Import driver's ECDH public key
    std::shared_lock algLock2(m_algMutex);
    BCRYPT_KEY_HANDLE remoteKeyHandle = nullptr;
    status = BCryptImportKeyPair(
        m_ecdhP256Alg.Get(), nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &remoteKeyHandle, const_cast<PUCHAR>(driverPublicKey.data()),
        static_cast<ULONG>(driverPublicKey.size()), 0);
    algLock2.unlock();

    if (!NT_SUCCESS(status) || !remoteKeyHandle) {
        BCryptDestroyKey(localKeyHandle);
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: driver key import failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    // Step 3: Perform ECDH key agreement to derive shared secret
    BCRYPT_SECRET_HANDLE secretHandle = nullptr;
    status = BCryptSecretAgreement(localKeyHandle, remoteKeyHandle, &secretHandle, 0);

    BCryptDestroyKey(localKeyHandle);
    BCryptDestroyKey(remoteKeyHandle);

    if (!NT_SUCCESS(status) || !secretHandle) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: ECDH agreement failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    // Step 4: Derive session key via BCryptDeriveKey (HKDF-like KDF)
    // Bind the key to the driver hash and context label for domain separation
    std::vector<uint8_t> kdfInfo;
    kdfInfo.reserve(contextLabel.size() + driverHash.size());
    kdfInfo.insert(kdfInfo.end(), contextLabel.begin(), contextLabel.end());
    kdfInfo.insert(kdfInfo.end(), driverHash.begin(), driverHash.end());

    BCryptBuffer paramBuffers[1] = {};
    paramBuffers[0].BufferType = KDF_HASH_ALGORITHM;
    paramBuffers[0].cbBuffer = static_cast<ULONG>(sizeof(BCRYPT_SHA256_ALGORITHM));
    paramBuffers[0].pvBuffer = const_cast<wchar_t*>(BCRYPT_SHA256_ALGORITHM);

    BCryptBufferDesc paramList = {};
    paramList.ulVersion = BCRYPTBUFFER_VERSION;
    paramList.cBuffers = 1;
    paramList.pBuffers = paramBuffers;

    constexpr ULONG sessionKeySize = 32; // AES-256
    std::vector<uint8_t> sessionKey(sessionKeySize);

    ULONG derivedSize = 0;
    status = BCryptDeriveKey(
        secretHandle,
        BCRYPT_KDF_HASH,
        &paramList,
        sessionKey.data(),
        sessionKeySize,
        &derivedSize,
        0);

    BCryptDestroySecret(secretHandle);

    if (!NT_SUCCESS(status) || derivedSize < sessionKeySize) {
        SecureZeroMemory(sessionKey.data(), sessionKey.size());
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: key derivation failed, NTSTATUS=0x%08X", status);
        return std::nullopt;
    }

    // Step 5: Mix in driver hash for additional binding via HMAC(sessionKey, driverHash || label)
    auto finalKey = ComputeHMAC(kdfInfo, sessionKey, HashAlgorithm::SHA256);
    SecureZeroMemory(sessionKey.data(), sessionKey.size());

    if (finalKey.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"DeriveKernelSessionKey: final HMAC mixing failed");
        return std::nullopt;
    }

    SS_LOG_INFO(LOG_CATEGORY, L"DeriveKernelSessionKey: session key derived successfully");
    m_stats.totalKeyDerivations.fetch_add(1, std::memory_order_relaxed);

    CryptoManager::KernelSessionKeyResult result;
    result.sessionKey = std::move(finalKey);
    result.localPublicKey = std::move(localPublicKey);
    return result;
}

bool CryptoManagerImpl::VerifyKernelMessageIntegrity(
    std::span<const uint8_t> message,
    std::span<const uint8_t> hmac,
    std::span<const uint8_t> sessionKey) {

    if (message.empty() || hmac.empty() || sessionKey.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"VerifyKernelMessageIntegrity: empty input parameter");
        return false;
    }
    if (hmac.size() != 32) {
        SS_LOG_WARN(LOG_CATEGORY, L"VerifyKernelMessageIntegrity: expected 32-byte HMAC-SHA256, got %zu", hmac.size());
        return false;
    }

    auto computed = ComputeHMAC(message, sessionKey, HashAlgorithm::SHA256);
    if (computed.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"VerifyKernelMessageIntegrity: HMAC computation failed");
        m_stats.authenticationFailures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    bool valid = ConstantTimeCompare(computed, hmac);
    if (!valid) {
        m_stats.authenticationFailures.fetch_add(1, std::memory_order_relaxed);
        SS_LOG_WARN(LOG_CATEGORY, L"VerifyKernelMessageIntegrity: HMAC mismatch — potential tampering or replay");
    }
    return valid;
}

std::vector<uint8_t> CryptoManagerImpl::ComputeKernelMessageHMAC(
    std::span<const uint8_t> message,
    std::span<const uint8_t> sessionKey) {

    if (message.empty() || sessionKey.empty()) {
        SS_LOG_WARN(LOG_CATEGORY, L"ComputeKernelMessageHMAC: empty input parameter");
        return {};
    }

    auto tag = ComputeHMAC(message, sessionKey, HashAlgorithm::SHA256);
    if (tag.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ComputeKernelMessageHMAC: HMAC-SHA256 computation failed");
    }
    return tag;
}

bool CryptoManagerImpl::ValidateKernelDriverAttestation(
    const std::wstring& driverPath,
    std::span<const uint8_t> expectedHash) {

    if (driverPath.empty()) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ValidateKernelDriverAttestation: empty driver path");
        return false;
    }
    if (expectedHash.size() != 32) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ValidateKernelDriverAttestation: expected 32-byte SHA-256 hash");
        return false;
    }

    // Step 1: Verify Authenticode signature via WinVerifyTrust
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = driverPath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG trustResult = WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &policyGUID,
        &winTrustData);

    // Close the trust state
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(
        static_cast<HWND>(INVALID_HANDLE_VALUE),
        &policyGUID,
        &winTrustData);

    if (trustResult != ERROR_SUCCESS) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"ValidateKernelDriverAttestation: Authenticode verification FAILED for '%s' (result=0x%08lX)",
            driverPath.c_str(), trustResult);
        return false;
    }

    // Step 2: Hash the driver file and compare against expected hash
    auto fileHash = HashFile(driverPath, HashAlgorithm::SHA256);
    if (!fileHash.has_value()) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"ValidateKernelDriverAttestation: failed to hash driver file '%s'",
            driverPath.c_str());
        return false;
    }

    if (!ConstantTimeCompare(fileHash.value(), expectedHash)) {
        SS_LOG_ERROR(LOG_CATEGORY,
            L"ValidateKernelDriverAttestation: driver hash MISMATCH for '%s' — possible tamper",
            driverPath.c_str());
        return false;
    }

    SS_LOG_INFO(LOG_CATEGORY,
        L"ValidateKernelDriverAttestation: driver '%s' passed Authenticode + hash attestation",
        driverPath.c_str());
    return true;
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

bool KeyMetadata::IsExpired() const {
    if (!expiresAt) {
        return false;
    }
    return std::chrono::system_clock::now() >= *expiresAt;
}

std::string KeyMetadata::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"id\":\"" << JsonEscape(id) << "\",";
    oss << "\"type\":" << static_cast<int>(type) << ",";
    oss << "\"keySizeBits\":" << keySizeBits << ",";
    oss << "\"storage\":" << static_cast<int>(storage) << ",";
    oss << "\"usageCount\":" << usageCount << ",";
    oss << "\"isExportable\":" << (isExportable ? "true" : "false") << ",";
    oss << "\"description\":\"" << JsonEscape(description) << "\"";
    oss << "}";
    return oss.str();
}

KDFParameters KDFParameters::PBKDF2(uint32_t iterations) {
    KDFParameters params;
    params.algorithm = KDFAlgorithm::PBKDF2_SHA256;
    params.iterations = iterations;
    params.outputLength = 32;
    return params;
}

KDFParameters KDFParameters::Argon2id(uint32_t memoryKB, uint32_t iterations) {
    KDFParameters params;
    params.algorithm = KDFAlgorithm::Argon2id;
    params.memoryKB = memoryKB;
    params.iterations = iterations;
    params.parallelism = 4;
    params.outputLength = 32;
    return params;
}

KDFParameters KDFParameters::HKDF(std::span<const uint8_t> info) {
    KDFParameters params;
    params.algorithm = KDFAlgorithm::HKDF_SHA256;
    params.info.assign(info.begin(), info.end());
    params.outputLength = 32;
    return params;
}

std::vector<uint8_t> EncryptionResult::GetCombinedOutput() const {
    std::vector<uint8_t> combined;
    combined.reserve(iv.size() + ciphertext.size() + tag.size());
    combined.insert(combined.end(), iv.begin(), iv.end());
    combined.insert(combined.end(), ciphertext.begin(), ciphertext.end());
    combined.insert(combined.end(), tag.begin(), tag.end());
    return combined;
}

bool CryptoManagerConfiguration::IsValid() const noexcept {
    if (maxCachedKeys == 0 || maxCachedKeys > 10000) {
        return false;
    }
    if (keyRotationIntervalSecs == 0) {
        return false;
    }
    return true;
}

void CryptoManagerStatistics::Reset() noexcept {
    totalEncryptions = 0;
    totalDecryptions = 0;
    totalHashes = 0;
    totalSignatures = 0;
    totalVerifications = 0;
    totalKeyGenerations = 0;
    totalKeyDerivations = 0;
    totalRandomBytes = 0;
    authenticationFailures = 0;
    hardwareAccelerationOps = 0;
    tpmOperations = 0;
    activeKeys = 0;
    startTime = Clock::now();
}

std::string CryptoManagerStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"totalEncryptions\":" << totalEncryptions << ",";
    oss << "\"totalDecryptions\":" << totalDecryptions << ",";
    oss << "\"totalHashes\":" << totalHashes << ",";
    oss << "\"totalSignatures\":" << totalSignatures << ",";
    oss << "\"totalVerifications\":" << totalVerifications << ",";
    oss << "\"totalKeyGenerations\":" << totalKeyGenerations << ",";
    oss << "\"totalKeyDerivations\":" << totalKeyDerivations << ",";
    oss << "\"totalRandomBytes\":" << totalRandomBytes << ",";
    oss << "\"authenticationFailures\":" << authenticationFailures << ",";
    oss << "\"hardwareAccelerationOps\":" << hardwareAccelerationOps << ",";
    oss << "\"tpmOperations\":" << tpmOperations << ",";
    oss << "\"activeKeys\":" << activeKeys;
    oss << "}";
    return oss.str();
}

// ============================================================================
// SECURE VECTOR IMPLEMENTATION
// ============================================================================

SecureVector::SecureVector(size_t size) : m_data(size) {}

SecureVector::~SecureVector() {
    if (!m_data.empty()) {
        SecureZeroMemory(m_data.data(), m_data.size());
    }
}

SecureVector::SecureVector(SecureVector&& other) noexcept
    : m_data(std::move(other.m_data)) {}

SecureVector& SecureVector::operator=(SecureVector&& other) noexcept {
    if (this != &other) {
        if (!m_data.empty()) {
            SecureZeroMemory(m_data.data(), m_data.size());
        }
        m_data = std::move(other.m_data);
    }
    return *this;
}

void SecureVector::resize(size_t newSize) {
    if (newSize < m_data.size()) {
        SecureZeroMemory(m_data.data() + newSize, m_data.size() - newSize);
    }
    m_data.resize(newSize);
}

void SecureVector::clear() {
    if (!m_data.empty()) {
        SecureZeroMemory(m_data.data(), m_data.size());
        m_data.clear();
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetSymmetricAlgorithmName(SymmetricAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case SymmetricAlgorithm::None:              return "None";
        case SymmetricAlgorithm::AES_128_GCM:       return "AES-128-GCM";
        case SymmetricAlgorithm::AES_256_GCM:       return "AES-256-GCM";
        case SymmetricAlgorithm::AES_128_CBC:       return "AES-128-CBC";
        case SymmetricAlgorithm::AES_256_CBC:       return "AES-256-CBC";
        case SymmetricAlgorithm::AES_256_XTS:       return "AES-256-XTS";
        case SymmetricAlgorithm::ChaCha20_Poly1305: return "ChaCha20-Poly1305";
        case SymmetricAlgorithm::AES_192_GCM:       return "AES-192-GCM";
        case SymmetricAlgorithm::AES_128_CTR:       return "AES-128-CTR";
        case SymmetricAlgorithm::AES_256_CTR:       return "AES-256-CTR";
        default:                                    return "Unknown";
    }
}

std::string_view GetAsymmetricAlgorithmName(AsymmetricAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case AsymmetricAlgorithm::None:         return "None";
        case AsymmetricAlgorithm::RSA_2048:     return "RSA-2048";
        case AsymmetricAlgorithm::RSA_3072:     return "RSA-3072";
        case AsymmetricAlgorithm::RSA_4096:     return "RSA-4096";
        case AsymmetricAlgorithm::ECDSA_P256:   return "ECDSA-P256";
        case AsymmetricAlgorithm::ECDSA_P384:   return "ECDSA-P384";
        case AsymmetricAlgorithm::ECDSA_P521:   return "ECDSA-P521";
        case AsymmetricAlgorithm::ECDH_P256:    return "ECDH-P256";
        case AsymmetricAlgorithm::ECDH_P384:    return "ECDH-P384";
        case AsymmetricAlgorithm::Ed25519:      return "Ed25519";
        case AsymmetricAlgorithm::X25519:       return "X25519";
        default:                                return "Unknown";
    }
}

std::string_view GetHashAlgorithmName(HashAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case HashAlgorithm::None:           return "None";
        case HashAlgorithm::MD5:            return "MD5";
        case HashAlgorithm::SHA1:           return "SHA-1";
        case HashAlgorithm::SHA256:         return "SHA-256";
        case HashAlgorithm::SHA384:         return "SHA-384";
        case HashAlgorithm::SHA512:         return "SHA-512";
        case HashAlgorithm::SHA3_256:       return "SHA3-256";
        case HashAlgorithm::SHA3_512:       return "SHA3-512";
        case HashAlgorithm::BLAKE2b_256:    return "BLAKE2b-256";
        case HashAlgorithm::BLAKE2b_512:    return "BLAKE2b-512";
        case HashAlgorithm::BLAKE2s_256:    return "BLAKE2s-256";
        case HashAlgorithm::BLAKE3:         return "BLAKE3";
        default:                            return "Unknown";
    }
}

std::string_view GetKDFAlgorithmName(KDFAlgorithm algorithm) noexcept {
    switch (algorithm) {
        case KDFAlgorithm::None:            return "None";
        case KDFAlgorithm::PBKDF2_SHA256:   return "PBKDF2-SHA256";
        case KDFAlgorithm::PBKDF2_SHA512:   return "PBKDF2-SHA512";
        case KDFAlgorithm::Argon2id:        return "Argon2id";
        case KDFAlgorithm::Argon2i:         return "Argon2i";
        case KDFAlgorithm::Argon2d:         return "Argon2d";
        case KDFAlgorithm::scrypt:          return "scrypt";
        case KDFAlgorithm::HKDF_SHA256:     return "HKDF-SHA256";
        case KDFAlgorithm::HKDF_SHA512:     return "HKDF-SHA512";
        case KDFAlgorithm::BCrypt:          return "BCrypt";
        default:                            return "Unknown";
    }
}

std::string_view GetCryptoResultName(CryptoResult result) noexcept {
    switch (result) {
        case CryptoResult::Success:                 return "Success";
        case CryptoResult::InvalidKey:              return "InvalidKey";
        case CryptoResult::InvalidData:             return "InvalidData";
        case CryptoResult::InvalidIV:               return "InvalidIV";
        case CryptoResult::InvalidTag:              return "InvalidTag";
        case CryptoResult::AuthenticationFailed:    return "AuthenticationFailed";
        case CryptoResult::BufferTooSmall:          return "BufferTooSmall";
        case CryptoResult::AlgorithmNotSupported:   return "AlgorithmNotSupported";
        case CryptoResult::KeyNotFound:             return "KeyNotFound";
        case CryptoResult::TPMError:                return "TPMError";
        case CryptoResult::HSMError:                return "HSMError";
        case CryptoResult::PermissionDenied:        return "PermissionDenied";
        case CryptoResult::InternalError:           return "InternalError";
        default:                                    return "Unknown";
    }
}

std::string_view GetKeyTypeName(KeyType type) noexcept {
    switch (type) {
        case KeyType::Symmetric:        return "Symmetric";
        case KeyType::RSAPublic:        return "RSAPublic";
        case KeyType::RSAPrivate:       return "RSAPrivate";
        case KeyType::ECDSAPublic:      return "ECDSAPublic";
        case KeyType::ECDSAPrivate:     return "ECDSAPrivate";
        case KeyType::ECDHPublic:       return "ECDHPublic";
        case KeyType::ECDHPrivate:      return "ECDHPrivate";
        case KeyType::Ed25519Public:    return "Ed25519Public";
        case KeyType::Ed25519Private:   return "Ed25519Private";
        case KeyType::X25519Public:     return "X25519Public";
        case KeyType::X25519Private:    return "X25519Private";
        case KeyType::HMAC:             return "HMAC";
        case KeyType::KDF:              return "KDF";
        default:                        return "Unknown";
    }
}

std::string_view GetKeyStorageName(KeyStorage storage) noexcept {
    switch (storage) {
        case KeyStorage::Memory:    return "Memory";
        case KeyStorage::DPAPI:     return "DPAPI";
        case KeyStorage::TPM:       return "TPM";
        case KeyStorage::HSM:       return "HSM";
        case KeyStorage::KeyVault:  return "KeyVault";
        case KeyStorage::File:      return "File";
        default:                    return "Unknown";
    }
}

}  // namespace Security
}  // namespace ShadowStrike
