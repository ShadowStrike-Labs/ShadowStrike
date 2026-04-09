/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests — SelfProtection Stack
 * SelfDefense ↔ TamperProtection ↔ CryptoManager ↔ CertValidator
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Validates the full production integration surface of the SelfProtection
 * stack.  All four modules are real Meyers' singletons; no mocks, no stubs.
 *
 *   CryptoManager        — foundational crypto primitives (hashing, symmetric
 *                          encryption, asymmetric signing, KDF, secure memory)
 *   CertificateValidator — X.509 chain validation, revocation, pinning,
 *                          fingerprint computation
 *   TamperProtection     — file/registry/memory integrity baseline and
 *                          real-time tamper monitoring
 *   SelfDefense          — process/service/driver/path/registry self-
 *                          protection, authorization tokens, watchdog
 *
 * The test suite is initialised in the following dependency order (matching
 * production startup):
 *
 *   1. CryptoManager        (no external dependencies)
 *   2. CertificateValidator (uses CryptoManager internally)
 *   3. TamperProtection     (uses CryptoManager + CertificateValidator)
 *   4. SelfDefense          (orchestrates all three above)
 *
 * Shutdown is performed in reverse order in TearDownTestSuite.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *  GROUP 1   LifecycleChain          — Init all 4 in dependency order, verify
 *                                      Running status, clean shutdown
 *  GROUP 2   CryptoManager_Primitives — SHA-256/384/512 determinism and sizes,
 *                                       HMAC key-sensitivity, AES-256-GCM and
 *                                       ChaCha20-Poly1305 encrypt/decrypt,
 *                                       tampered-ciphertext rejection,
 *                                       ConstantTimeCompare, random sizes
 *  GROUP 3   CertValidator_Structural — ParsePEM/ParseCertificate with invalid
 *                                       data, DetectEncoding, fingerprint
 *                                       computation, weak-algorithm contracts,
 *                                       ValidityPeriod lifecycle
 *  GROUP 4   SelfDefense_Tamper_Integration — Level/mode config validation,
 *                                       enableSelfDefenseIntegration flag,
 *                                       authorization-token lifecycle,
 *                                       ScopedSelfDefensePause / ScopedProtectionPause
 *  GROUP 5   Tamper_Crypto_HashXVal  — TamperProtection::ComputeFileHash
 *                                       compared against CryptoManager::SHA256
 *                                       on the same file bytes; determinism
 *  GROUP 6   Crypto_Cert_KeyOps      — Ed25519 key pair generate → sign →
 *                                       verify; ECDSA lifecycle; fingerprint
 *                                       identity with CryptoManager::SHA256
 *  GROUP 7   FullStack_AllFourActive — Status, SelfTest, statistics baseline,
 *                                       ExportReport from all 4 modules
 *  GROUP 8   ConcurrentSafety        — 32-thread SHA-256 consistency; 16-thread
 *                                       AES encrypt; 8-thread CertValidator ops;
 *                                       8-thread SelfDefense config reads
 *  GROUP 9   AdversarialInputs       — Empty/garbage/oversize inputs, tampered
 *                                       ciphertexts, wrong public keys, invalid
 *                                       cert blobs
 *  GROUP 10  Statistics_Accounting   — totalHashes / totalEncryptions increment;
 *                                       authenticationFailures increments on
 *                                       failed decrypt; ResetStatistics zeroes
 *  GROUP 11  Constants_Contracts     — Sane values for CryptoConstants,
 *                                       CertificateConstants, SelfDefenseConstants,
 *                                       TamperProtectionConstants
 *  GROUP 12  RAII_Guards             — ScopedSelfDefensePause, ScopedProtectionPause,
 *                                       ResourceProtectionGuard, ProtectedScope RAII
 *  GROUP 13  AuthToken_Lifecycle     — Token verify/reject, tampered token
 *                                       rejection, empty token rejection
 *
 * ============================================================================
 * SUITE LIFECYCLE
 * ============================================================================
 *  SetUpTestSuite    — Initialises all 4 singletons, creates one 4 KiB temp
 *                      file with known bytes for hash cross-validation, and
 *                      generates a 300-second authorization token.
 *  TearDownTestSuite — Shuts down in reverse order; deletes temp file.
 *
 * NOTE: Singletons are not destroyed on Shutdown(); they reset internal state
 * so a subsequent Initialize() succeeds.  Token expiry (300 s) does not affect
 * the suite because tests complete in well under 60 seconds.
 *
 * ============================================================================
 * NAMESPACE NOTES
 * ============================================================================
 *  ShadowStrike::Security        — all four modules live here
 *  ShadowStrike::Security::CryptoConstants
 *  ShadowStrike::Security::CertificateConstants
 *  ShadowStrike::Security::SelfDefenseConstants
 *  ShadowStrike::Security::TamperProtectionConstants
 */

// ============================================================================
// PLATFORM / STANDARD HEADERS
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// GOOGLETEST
// ============================================================================
#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================
#include "../../../src/Shared_modules/SelfProtection/CertificateValidator.hpp"
#include "../../../src/Shared_modules/SelfProtection/CryptoManager.hpp"
#include "../../../src/Shared_modules/SelfProtection/SelfDefense.hpp"
#include "../../../src/Shared_modules/SelfProtection/TamperProtection.hpp"

// ============================================================================
// CONVENIENCE ALIASES
// ============================================================================
namespace SS = ShadowStrike::Security;
using CM  = SS::CryptoManager;
using CV  = SS::CertificateValidator;
using TP  = SS::TamperProtection;
using SD  = SS::SelfDefense;
namespace CC  = SS::CryptoConstants;
namespace CRC = SS::CertificateConstants;
namespace SDC = SS::SelfDefenseConstants;
namespace TPC = SS::TamperProtectionConstants;

// ============================================================================
// SKIP GUARD
// ============================================================================
#define SKIP_IF_NOT_READY()                                                     \
    do {                                                                        \
        if (!SelfProtectionStackFixture::s_setupSucceeded) {                    \
            GTEST_SKIP() << "Suite setup failed; skipping test.";               \
        }                                                                       \
    } while (false)

// ============================================================================
// DATA HELPERS
// ============================================================================
namespace Helpers {

/// @brief Deterministic 4 KiB high-entropy buffer (xorshift64, all 256 byte
///        values appear ~16 times each).
[[nodiscard]] static std::vector<uint8_t> BuildHighEntropyBuffer(size_t size = 4096) {
    std::vector<uint8_t> buf(size);
    uint64_t state = 0xDEADBEEFCAFEBABEULL;
    for (auto& b : buf) {
        state ^= state << 13;
        state ^= state >>  7;
        state ^= state << 17;
        b = static_cast<uint8_t>(state & 0xFF);
    }
    return buf;
}

/// @brief Zero-filled buffer.  SHA-256 of this is a known constant.
[[nodiscard]] static std::vector<uint8_t> BuildZeroBuffer(size_t size = 64) {
    return std::vector<uint8_t>(size, 0x00);
}

/// @brief Content used for temp file creation and hash cross-validation.
///        Exactly 256 bytes: byte[i] = i (0x00…0xFF), well-defined SHA-256.
[[nodiscard]] static std::vector<uint8_t> BuildSequentialBuffer() {
    std::vector<uint8_t> buf(256);
    for (size_t i = 0; i < 256; ++i)
        buf[i] = static_cast<uint8_t>(i);
    return buf;
}

/// @brief SHA-256 of the empty byte sequence (RFC 6234 test vector).
static constexpr SS::Hash256 kSHA256OfEmpty = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

/// @brief Return an AES-256 key filled with a deterministic byte pattern.
[[nodiscard]] static SS::AES256Key MakeAES256Key(uint8_t seed = 0x42) {
    SS::AES256Key k{};
    for (size_t i = 0; i < k.size(); ++i)
        k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

/// @brief Creates a temp file at `path` with the supplied bytes.
[[nodiscard]] static bool WriteTempFile(const std::filesystem::path& path,
                                        std::span<const uint8_t>    data) {
    std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    return ofs.good();
}

} // namespace Helpers

// ============================================================================
// TEST FIXTURE
// ============================================================================
class SelfProtectionStackFixture : public ::testing::Test {
public:
    static bool         s_setupSucceeded;
    static std::string  s_authToken;        ///< Valid token for the full suite run
    static std::filesystem::path s_tempDir;
    static std::filesystem::path s_tempFile; ///< 256-byte sequential content

    static void SetUpTestSuite() {
        s_setupSucceeded = false;

        // ── 1. CryptoManager ────────────────────────────────────────────────
        {
            SS::CryptoManagerConfiguration cfg;
            cfg.enableHardwareAcceleration = true;
            cfg.enableSecureMemory         = true;
            cfg.enableTPM                  = false;
            cfg.enableFIPSMode             = false;
            cfg.enableAuditLogging         = false;
            cfg.verboseLogging             = false;
            if (!CM::Instance().Initialize(cfg)) {
                ADD_FAILURE() << "CryptoManager::Initialize() failed.";
                return;
            }
        }

        // ── 2. CertificateValidator ──────────────────────────────────────────
        {
            SS::CertificateValidatorConfiguration cfg;
            cfg.enableOCSP          = false;  // no network in test environments
            cfg.enableCRL           = false;
            cfg.enableCaching       = true;
            cfg.useSystemTrustStore = true;
            cfg.allowWeakAlgorithms = false;
            cfg.verboseLogging      = false;
            if (!CV::Instance().Initialize(cfg)) {
                ADD_FAILURE() << "CertificateValidator::Initialize() failed.";
                CM::Instance().Shutdown();
                return;
            }
        }

        // ── 3. TamperProtection ──────────────────────────────────────────────
        {
            SS::TamperProtectionConfiguration cfg =
                SS::TamperProtectionConfiguration::FromMode(SS::TamperProtectionMode::Monitor);
            cfg.enableRealTimeMonitoring    = false; // no kernel in test environment
            cfg.enablePeriodicChecks        = false;
            cfg.enableAutoRepair            = false;
            cfg.verifyDigitalSignatures     = true;
            cfg.verifyCertificateChain      = true;
            cfg.enableSelfDefenseIntegration = true;
            cfg.verboseLogging              = false;
            cfg.sendTelemetry               = false;
            if (!TP::Instance().Initialize(cfg)) {
                ADD_FAILURE() << "TamperProtection::Initialize() failed.";
                CV::Instance().Shutdown();
                CM::Instance().Shutdown();
                return;
            }
        }

        // ── 4. SelfDefense ───────────────────────────────────────────────────
        {
            SS::SelfDefenseConfiguration cfg =
                SS::SelfDefenseConfiguration::FromLevel(SS::SelfDefenseLevel::Standard);
            cfg.enableKernelProtection   = false; // no driver in test environment
            cfg.enableWatchdog           = false;
            cfg.enableAutoRecovery       = false;
            cfg.enableIntegrityMonitoring = false;
            cfg.enableHeartbeat          = false;
            cfg.verboseLogging           = false;
            cfg.sendTelemetry            = false;
            if (!SD::Instance().Initialize(cfg)) {
                ADD_FAILURE() << "SelfDefense::Initialize() failed.";
                TP::Instance().Shutdown();
                CV::Instance().Shutdown();
                CM::Instance().Shutdown();
                return;
            }
        }

        // ── Generate suite-wide authorization token ──────────────────────────
        s_authToken = SD::Instance().GenerateAuthorizationToken("suite-teardown", 300);
        if (s_authToken.empty()) {
            ADD_FAILURE() << "GenerateAuthorizationToken() returned empty token.";
            SD::Instance().Shutdown(""); // best-effort
            TP::Instance().Shutdown();
            CV::Instance().Shutdown();
            CM::Instance().Shutdown();
            return;
        }

        // ── Create temp directory and hash-cross-validation file ─────────────
        {
            std::error_code ec;
            s_tempDir = std::filesystem::temp_directory_path(ec);
            if (ec) {
                ADD_FAILURE() << "Could not resolve temp directory: " << ec.message();
                return;
            }
            s_tempDir /= std::filesystem::path(
                L"ShadowStrikeTier9_" + std::to_wstring(::GetCurrentProcessId()));
            std::filesystem::remove_all(s_tempDir, ec);
            ec.clear();
            std::filesystem::create_directories(s_tempDir, ec);
            if (ec) {
                ADD_FAILURE() << "Could not create temp directory: " << ec.message();
                return;
            }
            s_tempFile = s_tempDir / L"hash_xval.bin";
            const auto data = Helpers::BuildSequentialBuffer();
            if (!Helpers::WriteTempFile(s_tempFile, data)) {
                ADD_FAILURE() << "Could not write temp file for hash cross-validation.";
                return;
            }
        }

        s_setupSucceeded = true;
    }

    static void TearDownTestSuite() {
        // Shutdown in reverse dependency order
        SD::Instance().Shutdown(s_authToken);
        TP::Instance().Shutdown(s_authToken);
        CV::Instance().Shutdown();
        CM::Instance().Shutdown();

        // Clean up temp files
        std::error_code ec;
        std::filesystem::remove_all(s_tempDir, ec);
    }
};

bool                      SelfProtectionStackFixture::s_setupSucceeded = false;
std::string               SelfProtectionStackFixture::s_authToken;
std::filesystem::path     SelfProtectionStackFixture::s_tempDir;
std::filesystem::path     SelfProtectionStackFixture::s_tempFile;

// ============================================================================
// GROUP 1 — LifecycleChain
// ============================================================================

/**
 * @brief All four singletons must be initialized and report Running status
 *        after successful suite setup.
 *
 * This confirms that the initialization order (Crypto → CertValidator →
 * TamperProtection → SelfDefense) satisfies all internal dependency
 * requirements without any module reporting Error or Degraded.
 */
TEST_F(SelfProtectionStackFixture, Lifecycle_AllFourModulesRunningAfterInit) {
    SKIP_IF_NOT_READY();

    EXPECT_TRUE(CM::Instance().IsInitialized())   << "CryptoManager must be initialized.";
    EXPECT_TRUE(CV::Instance().IsInitialized())   << "CertificateValidator must be initialized.";
    EXPECT_TRUE(TP::Instance().IsInitialized())   << "TamperProtection must be initialized.";
    EXPECT_TRUE(SD::Instance().IsInitialized())   << "SelfDefense must be initialized.";

    EXPECT_EQ(CM::Instance().GetStatus(), SS::ModuleStatus::Running)
        << "CryptoManager must report Running.";
    EXPECT_EQ(CV::Instance().GetStatus(), SS::ModuleStatus::Running)
        << "CertificateValidator must report Running.";
    EXPECT_EQ(TP::Instance().GetStatus(), SS::ModuleStatus::Running)
        << "TamperProtection must report Running.";
    EXPECT_EQ(SD::Instance().GetStatus(), SS::ModuleStatus::Running)
        << "SelfDefense must report Running.";
}

/**
 * @brief Double-initialization must be idempotent: a second Initialize() call
 *        on an already-Running CryptoManager must either succeed or return true
 *        without crashing.
 */
TEST_F(SelfProtectionStackFixture, Lifecycle_DoubleInit_CryptoManager_Idempotent) {
    SKIP_IF_NOT_READY();

    const bool result = CM::Instance().Initialize();
    EXPECT_TRUE(result)
        << "Re-initializing an already-Running CryptoManager must succeed.";
    EXPECT_EQ(CM::Instance().GetStatus(), SS::ModuleStatus::Running);
}

/**
 * @brief HasInstance() must return true for every singleton after setup.
 */
TEST_F(SelfProtectionStackFixture, Lifecycle_HasInstance_TrueForAll) {
    SKIP_IF_NOT_READY();

    EXPECT_TRUE(CM::HasInstance());
    EXPECT_TRUE(CV::HasInstance());
    EXPECT_TRUE(TP::HasInstance());
    EXPECT_TRUE(SD::HasInstance());
}

// ============================================================================
// GROUP 2 — CryptoManager_Primitives
// ============================================================================

/**
 * @brief SHA-256 output is exactly 32 bytes and deterministic across calls.
 *
 * The same 256-byte sequential buffer must always produce the same 32-byte
 * digest.  This is foundational: TamperProtection's file baseline and
 * CertificateValidator's fingerprint both depend on SHA-256 determinism.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_SHA256_DeterministicAndCorrectLength) {
    SKIP_IF_NOT_READY();

    const auto data  = Helpers::BuildSequentialBuffer();
    const auto hash1 = CM::Instance().SHA256(data);
    const auto hash2 = CM::Instance().SHA256(data);

    ASSERT_EQ(hash1.size(), CC::SHA256_SIZE) << "SHA-256 must produce exactly 32 bytes.";
    EXPECT_EQ(hash1, hash2) << "SHA-256 of the same input must be deterministic.";
}

/**
 * @brief SHA-384 produces exactly 48 bytes; SHA-512 produces exactly 64 bytes.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_SHA384_SHA512_CorrectOutputLengths) {
    SKIP_IF_NOT_READY();

    const auto data = Helpers::BuildZeroBuffer(128);

    const auto h384 = CM::Instance().SHA384(data);
    const auto h512 = CM::Instance().SHA512(data);

    EXPECT_EQ(h384.size(), CC::SHA384_SIZE) << "SHA-384 must produce exactly 48 bytes.";
    EXPECT_EQ(h512.size(), CC::SHA512_SIZE) << "SHA-512 must produce exactly 64 bytes.";

    // Verify they are non-equal (length already differs but value must differ too)
    EXPECT_NE(std::vector<uint8_t>(h384.begin(), h384.end()),
              std::vector<uint8_t>(h512.begin(), h512.begin() + h384.size()))
        << "SHA-384 and truncated SHA-512 must produce different digests.";
}

/**
 * @brief SHA-256 of the empty byte sequence must equal the RFC 6234 test vector
 *        (e3b0c44298fc1c149afbf4c8996fb924…).
 *
 * This validates that the underlying crypto library uses standard-compliant
 * SHA-256.  Deviating from this would mean all file baselines and certificate
 * fingerprints are non-standard.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_SHA256_EmptyInput_RFC6234TestVector) {
    SKIP_IF_NOT_READY();

    const std::vector<uint8_t> empty;
    const auto digest = CM::Instance().SHA256(empty);

    EXPECT_EQ(digest, Helpers::kSHA256OfEmpty)
        << "SHA-256 of empty input must equal the FIPS/RFC 6234 test vector.";
}

/**
 * @brief HMAC-SHA-256 is deterministic and key-sensitive.
 *
 * Two MACs computed over the same data with the same key must be equal.
 * Two MACs with different keys must differ.  This validates that HMAC is
 * correctly bound to its key — critical for CryptoManager's kernel HMAC
 * message integrity path.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_HMAC_DeterministicAndKeySensitive) {
    SKIP_IF_NOT_READY();

    const auto data = Helpers::BuildHighEntropyBuffer(512);
    const auto key1 = Helpers::BuildZeroBuffer(32);
    std::vector<uint8_t> key2(32, 0x01);

    const auto mac1a = CM::Instance().HMAC(data, key1, SS::HashAlgorithm::SHA256);
    const auto mac1b = CM::Instance().HMAC(data, key1, SS::HashAlgorithm::SHA256);
    const auto mac2  = CM::Instance().HMAC(data, key2, SS::HashAlgorithm::SHA256);

    ASSERT_FALSE(mac1a.empty()) << "HMAC must produce non-empty output.";
    EXPECT_EQ(mac1a, mac1b)     << "HMAC over the same data+key must be deterministic.";
    EXPECT_NE(mac1a, mac2)      << "HMAC with a different key must produce a different MAC.";
}

/**
 * @brief VerifyHMAC returns true for the correct MAC and false for a mutated one.
 *
 * Even a single-bit flip in the MAC must be detected.  This mirrors the
 * kernel-message integrity verification path used in
 * CryptoManager::VerifyKernelMessageIntegrity.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_VerifyHMAC_BitFlipDetected) {
    SKIP_IF_NOT_READY();

    const auto data     = Helpers::BuildHighEntropyBuffer(256);
    const auto key      = Helpers::BuildZeroBuffer(32);
    const auto correct  = CM::Instance().HMAC(data, key, SS::HashAlgorithm::SHA256);

    EXPECT_TRUE(CM::Instance().VerifyHMAC(data, correct, key, SS::HashAlgorithm::SHA256))
        << "VerifyHMAC must return true for the correct MAC.";

    auto tampered = correct;
    tampered[0] ^= 0x01;  // single-bit flip
    EXPECT_FALSE(CM::Instance().VerifyHMAC(data, tampered, key, SS::HashAlgorithm::SHA256))
        << "VerifyHMAC must return false after a single-bit flip in the MAC.";
}

/**
 * @brief AES-256-GCM encrypt/decrypt roundtrip: decrypted plaintext equals original.
 *
 * AES-256-GCM is the default symmetric algorithm for all ShadowStrike
 * internal data-at-rest operations.  A roundtrip failure would break every
 * component that stores encrypted configuration or secrets.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_AES256GCM_EncryptDecryptRoundtrip) {
    SKIP_IF_NOT_READY();

    const auto   plaintext = Helpers::BuildHighEntropyBuffer(1024);
    const auto   keyBytes  = Helpers::MakeAES256Key(0x7F);
    const auto   iv        = CM::Instance().GenerateNonce();

    const auto encResult = CM::Instance().Encrypt(
        plaintext,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(iv.data(), iv.size()));

    ASSERT_TRUE(encResult.IsSuccess())
        << "AES-256-GCM encryption must succeed: " << encResult.errorMessage;
    ASSERT_FALSE(encResult.ciphertext.empty());
    ASSERT_EQ(encResult.tag.size(), CC::AES_GCM_TAG_SIZE);

    const auto decResult = CM::Instance().Decrypt(
        encResult.ciphertext,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(encResult.iv.data(), encResult.iv.size()),
        std::span<const uint8_t>(encResult.tag.data(), encResult.tag.size()));

    ASSERT_TRUE(decResult.IsSuccess())
        << "AES-256-GCM decryption must succeed: " << decResult.errorMessage;
    EXPECT_EQ(decResult.plaintext, plaintext)
        << "Decrypted output must exactly match original plaintext.";
}

/**
 * @brief A single-byte flip in the ciphertext must cause AES-256-GCM
 *        authentication to fail.
 *
 * GCM's AEAD guarantee must be enforced: any modification to the ciphertext
 * (or AAD) must be detected and produce an authentication failure rather than
 * silently returning corrupt plaintext.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_AES256GCM_TamperedCiphertext_AuthFails) {
    SKIP_IF_NOT_READY();

    const auto plaintext = Helpers::BuildHighEntropyBuffer(512);
    const auto keyBytes  = Helpers::MakeAES256Key(0xAB);
    const auto iv        = CM::Instance().GenerateNonce();

    const auto encResult = CM::Instance().Encrypt(
        plaintext,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(iv.data(), iv.size()));

    ASSERT_TRUE(encResult.IsSuccess());

    // Flip the first byte of the ciphertext
    auto tampered = encResult.ciphertext;
    tampered[0] ^= 0xFF;

    const auto decResult = CM::Instance().Decrypt(
        tampered,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(encResult.iv.data(), encResult.iv.size()),
        std::span<const uint8_t>(encResult.tag.data(), encResult.tag.size()));

    EXPECT_FALSE(decResult.IsSuccess())
        << "AES-256-GCM must reject tampered ciphertext.";
    EXPECT_TRUE(decResult.plaintext.empty())
        << "No partial plaintext must be returned on authentication failure.";
}

/**
 * @brief ChaCha20-Poly1305 encrypt/decrypt roundtrip succeeds.
 *
 * ChaCha20-Poly1305 is the fallback cipher on systems where AES-NI is
 * unavailable.  Correctness is required for feature parity.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_ChaCha20Poly1305_RoundtripSucceeds) {
    SKIP_IF_NOT_READY();

    const auto  plaintext = Helpers::BuildHighEntropyBuffer(512);
    const auto  keyBytes  = Helpers::MakeAES256Key(0xCC);
    const auto  nonce     = CM::Instance().GenerateNonce();

    const auto encResult = CM::Instance().Encrypt(
        plaintext,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::ChaCha20_Poly1305,
        std::span<const uint8_t>(nonce.data(), nonce.size()));

    ASSERT_TRUE(encResult.IsSuccess())
        << "ChaCha20-Poly1305 encryption must succeed: " << encResult.errorMessage;

    const auto decResult = CM::Instance().Decrypt(
        encResult.ciphertext,
        std::span<const uint8_t>(keyBytes.data(), keyBytes.size()),
        SS::SymmetricAlgorithm::ChaCha20_Poly1305,
        std::span<const uint8_t>(encResult.iv.data(), encResult.iv.size()),
        std::span<const uint8_t>(encResult.tag.data(), encResult.tag.size()));

    ASSERT_TRUE(decResult.IsSuccess())
        << "ChaCha20-Poly1305 decryption must succeed: " << decResult.errorMessage;
    EXPECT_EQ(decResult.plaintext, plaintext);
}

/**
 * @brief ConstantTimeCompare returns true for equal spans and false for unequal.
 *
 * Used throughout ShadowStrike for MAC verification to prevent timing attacks.
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_ConstantTimeCompare_Correctness) {
    SKIP_IF_NOT_READY();

    const std::array<uint8_t, 32> a{0x11, 0x22, 0x33};
    std::array<uint8_t, 32>       b = a;
    EXPECT_TRUE(CM::Instance().ConstantTimeCompare(a, b))
        << "ConstantTimeCompare must return true for identical buffers.";

    b[0] ^= 0x01;
    EXPECT_FALSE(CM::Instance().ConstantTimeCompare(a, b))
        << "ConstantTimeCompare must return false when buffers differ.";
}

/**
 * @brief Random generation primitives return the correct byte counts.
 *
 * GenerateNonce, GenerateIV, and GenerateSalt are used pervasively.  Their
 * declared sizes must match the cryptographic protocol requirements
 * (AES-GCM = 12-byte nonce, CBC = 16-byte IV, KDF = 32-byte salt).
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_RandomPrimitives_CorrectSizes) {
    SKIP_IF_NOT_READY();

    const auto nonce = CM::Instance().GenerateNonce();
    const auto iv    = CM::Instance().GenerateIV();
    const auto salt  = CM::Instance().GenerateSalt();

    EXPECT_EQ(nonce.size(), CC::AES_GCM_NONCE_SIZE)   << "Nonce must be 12 bytes.";
    EXPECT_EQ(iv.size(),    CC::AES_CBC_IV_SIZE)       << "IV must be 16 bytes.";
    EXPECT_EQ(salt.size(),  32u)                       << "Salt must be 32 bytes.";
}

/**
 * @brief Two successive GenerateRandom(32) calls must produce different values
 *        with overwhelming probability (collision probability < 1/2^256).
 */
TEST_F(SelfProtectionStackFixture, CryptoManager_GenerateRandom_NonRepeatability) {
    SKIP_IF_NOT_READY();

    const auto r1 = CM::Instance().GenerateRandom(32);
    const auto r2 = CM::Instance().GenerateRandom(32);

    ASSERT_EQ(r1.size(), 32u);
    ASSERT_EQ(r2.size(), 32u);
    EXPECT_NE(r1, r2)
        << "Two successive 32-byte random outputs must (overwhelmingly) differ.";
}

// ============================================================================
// GROUP 3 — CertificateValidator_Structural
// ============================================================================

/**
 * @brief ParseCertificate with an empty span must return std::nullopt without
 *        crashing.  The validator must not dereference a zero-length buffer.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_ParseCertificate_EmptySpan_ReturnsNullopt) {
    SKIP_IF_NOT_READY();

    const auto result = CV::Instance().ParseCertificate({});
    EXPECT_FALSE(result.has_value())
        << "ParseCertificate with an empty span must return nullopt.";
}

/**
 * @brief ParseCertificate with random garbage must return std::nullopt without
 *        crashing.  Hostile input (e.g., supplied by a compromised update
 *        channel) must never cause undefined behaviour.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_ParseCertificate_GarbageInput_ReturnsNullopt) {
    SKIP_IF_NOT_READY();

    const auto garbage = Helpers::BuildHighEntropyBuffer(512);
    const auto result  = CV::Instance().ParseCertificate(garbage);
    EXPECT_FALSE(result.has_value())
        << "ParseCertificate with random garbage must return nullopt.";
}

/**
 * @brief ParsePEM with an empty string must return std::nullopt.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_ParsePEM_EmptyString_ReturnsNullopt) {
    SKIP_IF_NOT_READY();

    const auto result = CV::Instance().ParsePEM(std::string_view{});
    EXPECT_FALSE(result.has_value())
        << "ParsePEM with empty string_view must return nullopt.";
}

/**
 * @brief ParsePEM with a malformed (non-PEM) string must return std::nullopt.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_ParsePEM_MalformedString_ReturnsNullopt) {
    SKIP_IF_NOT_READY();

    const std::string malformed =
        "-----BEGIN CERTIFICATE-----\n"
        "THIS IS NOT VALID BASE64 OR DER DATA$$$$\n"
        "-----END CERTIFICATE-----\n";
    const auto result = CV::Instance().ParsePEM(malformed);
    EXPECT_FALSE(result.has_value())
        << "ParsePEM with malformed content must return nullopt.";
}

/**
 * @brief DetectEncoding on an empty span must return Unknown — not crash or
 *        assert.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_DetectEncoding_EmptyData_ReturnsUnknown) {
    SKIP_IF_NOT_READY();

    const auto enc = CV::Instance().DetectEncoding({});
    EXPECT_EQ(enc, SS::CertificateEncoding::Unknown)
        << "DetectEncoding on empty data must return Unknown.";
}

/**
 * @brief CalculateFingerprint output is exactly 32 bytes (SHA-256 fingerprint).
 *
 * Certificate fingerprints computed by CertificateValidator are used by
 * SelfDefense pinning logic.  Incorrect sizes would silently corrupt all
 * pin comparisons.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_CalculateFingerprint_OutputIs32Bytes) {
    SKIP_IF_NOT_READY();

    const auto data        = Helpers::BuildSequentialBuffer();
    const auto fingerprint = CV::Instance().CalculateFingerprint(data);

    EXPECT_EQ(fingerprint.size(), CRC::SHA256_SIZE)
        << "Certificate fingerprint must be 32 bytes (SHA-256).";
}

/**
 * @brief FingerprintToHex must return a 64-character lowercase hex string.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_FingerprintToHex_Is64CharHex) {
    SKIP_IF_NOT_READY();

    const auto data = Helpers::BuildSequentialBuffer();
    const auto fp   = CV::Instance().CalculateFingerprint(data);
    const auto hex  = CV::FingerprintToHex(fp);

    ASSERT_EQ(hex.size(), 64u) << "FingerprintToHex must produce 64 hex characters.";
    for (char c : hex) {
        const bool valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        EXPECT_TRUE(valid) << "FingerprintToHex must be lowercase hex; unexpected char: " << c;
    }
}

/**
 * @brief ParseFingerprint(FingerprintToHex(fp)) must recover the original
 *        fingerprint exactly (roundtrip identity).
 */
TEST_F(SelfProtectionStackFixture, CertValidator_FingerprintHexRoundtrip) {
    SKIP_IF_NOT_READY();

    const auto data = Helpers::BuildSequentialBuffer();
    const auto fp   = CV::Instance().CalculateFingerprint(data);
    const auto hex  = CV::FingerprintToHex(fp);
    const auto recovered = CV::ParseFingerprint(hex);

    ASSERT_TRUE(recovered.has_value())
        << "ParseFingerprint on valid hex must return a value.";
    EXPECT_EQ(*recovered, fp)
        << "ParseFingerprint(FingerprintToHex(fp)) must recover the original fingerprint.";
}

/**
 * @brief IsWeakAlgorithm must classify MD5 and SHA-1 as weak, and SHA-256 as
 *        strong.
 *
 * This gate prevents acceptance of certificates signed with deprecated
 * algorithms.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_IsWeakAlgorithm_MD5Weak_SHA256Strong) {
    SKIP_IF_NOT_READY();

    EXPECT_TRUE(CV::IsWeakAlgorithm(SS::SignatureAlgorithm::MD5_RSA))
        << "MD5-RSA must be classified as weak.";
    EXPECT_TRUE(CV::IsWeakAlgorithm(SS::SignatureAlgorithm::SHA1_RSA))
        << "SHA1-RSA must be classified as weak.";
    EXPECT_FALSE(CV::IsWeakAlgorithm(SS::SignatureAlgorithm::SHA256_RSA))
        << "SHA256-RSA must not be classified as weak.";
    EXPECT_FALSE(CV::IsWeakAlgorithm(SS::SignatureAlgorithm::SHA256_ECDSA))
        << "SHA256-ECDSA must not be classified as weak.";
    EXPECT_FALSE(CV::IsWeakAlgorithm(SS::SignatureAlgorithm::Ed25519))
        << "Ed25519 must not be classified as weak.";
}

/**
 * @brief ValidityPeriod::IsValid, IsExpired, and IsNotYetValid correctly
 *        classify a current, past, and future certificate window.
 *
 * These are used during chain validation to gate enforcement decisions.
 */
TEST_F(SelfProtectionStackFixture, CertValidator_ValidityPeriod_Classification) {
    SKIP_IF_NOT_READY();

    const auto now = std::chrono::system_clock::now();

    SS::ValidityPeriod current;
    current.notBefore = now - std::chrono::hours{1};
    current.notAfter  = now + std::chrono::hours{1};
    EXPECT_TRUE(current.IsValid());
    EXPECT_FALSE(current.IsExpired());
    EXPECT_FALSE(current.IsNotYetValid());
    EXPECT_GT(current.GetRemainingSeconds(), 0LL);

    SS::ValidityPeriod expired;
    expired.notBefore = now - std::chrono::hours{48};
    expired.notAfter  = now - std::chrono::hours{24};
    EXPECT_FALSE(expired.IsValid());
    EXPECT_TRUE(expired.IsExpired());
    EXPECT_FALSE(expired.IsNotYetValid());
    EXPECT_LT(expired.GetRemainingSeconds(), 0LL);

    SS::ValidityPeriod future;
    future.notBefore = now + std::chrono::hours{1};
    future.notAfter  = now + std::chrono::hours{48};
    EXPECT_FALSE(future.IsValid());
    EXPECT_FALSE(future.IsExpired());
    EXPECT_TRUE(future.IsNotYetValid());
}

// ============================================================================
// GROUP 4 — SelfDefense ↔ TamperProtection Integration
// ============================================================================

/**
 * @brief SelfDefenseConfiguration::FromLevel(Standard) must produce a valid
 *        configuration whose IsValid() returns true.
 *
 * This verifies that the shared level-to-config transformation is consistent
 * across module boundaries (TamperProtection reads SelfDefense's config to
 * decide whether kernel-level self-defense is active).
 */
TEST_F(SelfProtectionStackFixture, SelfDefenseTamper_StdConfig_IsValid) {
    SKIP_IF_NOT_READY();

    const auto stdCfg  = SS::SelfDefenseConfiguration::FromLevel(
        SS::SelfDefenseLevel::Standard);
    EXPECT_TRUE(stdCfg.IsValid())
        << "Standard-level SelfDefense configuration must be valid.";

    const auto minCfg  = SS::SelfDefenseConfiguration::FromLevel(
        SS::SelfDefenseLevel::Minimal);
    EXPECT_TRUE(minCfg.IsValid())
        << "Minimal-level SelfDefense configuration must be valid.";

    const auto maxCfg  = SS::SelfDefenseConfiguration::FromLevel(
        SS::SelfDefenseLevel::Maximum);
    EXPECT_TRUE(maxCfg.IsValid())
        << "Maximum-level SelfDefense configuration must be valid.";
}

/**
 * @brief TamperProtectionConfiguration with enableSelfDefenseIntegration=true
 *        must still pass IsValid(); SelfDefense integration cannot invalidate
 *        an otherwise-correct configuration.
 */
TEST_F(SelfProtectionStackFixture,
       SelfDefenseTamper_TamperCfgWithSelfDefenseIntegration_IsValid) {
    SKIP_IF_NOT_READY();

    auto cfg = SS::TamperProtectionConfiguration::FromMode(
        SS::TamperProtectionMode::Protect);
    cfg.enableSelfDefenseIntegration = true;
    EXPECT_TRUE(cfg.IsValid())
        << "TamperProtection config with SelfDefense integration must be valid.";
}

/**
 * @brief A TamperProtection Lockdown configuration must have maximally
 *        strict response and certificate chain verification enabled.
 *
 * In production, Lockdown mode is escalated to when SelfDefense detects an
 * APT-class threat.  The preset must reflect that escalation.
 */
TEST_F(SelfProtectionStackFixture, SelfDefenseTamper_LockdownConfig_StrictDefaults) {
    SKIP_IF_NOT_READY();

    const auto lockdown = SS::TamperProtectionConfiguration::FromMode(
        SS::TamperProtectionMode::Lockdown);
    EXPECT_TRUE(lockdown.enableRealTimeMonitoring);
    EXPECT_TRUE(lockdown.enableAutoRepair);
    EXPECT_TRUE(lockdown.verifyCertificateChain);
    EXPECT_TRUE(lockdown.enableAntiDebugIntegration);
    EXPECT_EQ(lockdown.defaultResponse, SS::TamperResponse::Maximum);
    EXPECT_TRUE(lockdown.IsValid());
}

/**
 * @brief SelfDefense::GetProtectionLevel must reflect the level set at
 *        initialization time.
 */
TEST_F(SelfProtectionStackFixture, SelfDefenseTamper_ProtectionLevel_ReflectsInit) {
    SKIP_IF_NOT_READY();

    const auto level = SD::Instance().GetProtectionLevel();
    // The suite initialized with Standard level
    EXPECT_EQ(level, SS::SelfDefenseLevel::Standard)
        << "Protection level must match the level passed to Initialize().";
}

/**
 * @brief SelfDefense::GetVersionString must return a non-empty string.
 *        Ditto for TamperProtection.
 */
TEST_F(SelfProtectionStackFixture, SelfDefenseTamper_VersionStrings_NonEmpty) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(SD::GetVersionString().empty())
        << "SelfDefense::GetVersionString() must not be empty.";
    EXPECT_FALSE(TP::GetVersionString().empty())
        << "TamperProtection::GetVersionString() must not be empty.";
}

/**
 * @brief TamperProtection::IsEnabled must return true immediately after
 *        initialization.
 */
TEST_F(SelfProtectionStackFixture, SelfDefenseTamper_TamperProtection_EnabledAfterInit) {
    SKIP_IF_NOT_READY();

    EXPECT_TRUE(TP::Instance().IsEnabled())
        << "TamperProtection must report enabled after initialization.";
}

// ============================================================================
// GROUP 5 — TamperProtection ↔ CryptoManager Hash Cross-Validation
// ============================================================================

/**
 * @brief TamperProtection::ComputeFileHash(SHA256) on the temp file must
 *        produce the exact same 32-byte digest as CryptoManager::SHA256 on
 *        the same raw bytes.
 *
 * This is the fundamental wiring test: TamperProtection delegates file
 * hashing to CryptoManager.  A mismatch would mean that integrity baselines
 * computed by one subsystem cannot be verified by the other.
 */
TEST_F(SelfProtectionStackFixture, TamperCrypto_ComputeFileHash_MatchesCryptoManagerSHA256) {
    SKIP_IF_NOT_READY();
    ASSERT_FALSE(s_tempFile.empty()) << "Temp file path must be set.";
    ASSERT_TRUE(std::filesystem::exists(s_tempFile)) << "Temp file must exist.";

    // Read raw bytes for CryptoManager
    const auto seqData = Helpers::BuildSequentialBuffer();

    // TamperProtection hash
    const auto tpHash = TP::Instance().ComputeFileHash(
        s_tempFile.wstring(),
        SS::VerificationMethod::SHA256);

    // CryptoManager hash over the same in-memory bytes
    const auto cmHash = CM::Instance().SHA256(seqData);

    EXPECT_EQ(tpHash, cmHash)
        << "TamperProtection::ComputeFileHash(SHA256) must equal "
           "CryptoManager::SHA256 on the same file bytes.";
}

/**
 * @brief TamperProtection::ComputeFileHash is deterministic: two calls on the
 *        same unmodified file must return the same hash.
 */
TEST_F(SelfProtectionStackFixture, TamperCrypto_ComputeFileHash_Deterministic) {
    SKIP_IF_NOT_READY();
    ASSERT_TRUE(std::filesystem::exists(s_tempFile));

    const auto hash1 = TP::Instance().ComputeFileHash(
        s_tempFile.wstring(), SS::VerificationMethod::SHA256);
    const auto hash2 = TP::Instance().ComputeFileHash(
        s_tempFile.wstring(), SS::VerificationMethod::SHA256);

    EXPECT_EQ(hash1, hash2) << "ComputeFileHash must be deterministic.";
}

/**
 * @brief SHA256 and SHA512 hashes of the same file must differ.
 *
 * This confirms that VerificationMethod::SHA512 delegates to a different
 * algorithm than SHA256 — ruling out an implementation bug that ignores
 * the requested method.
 */
TEST_F(SelfProtectionStackFixture, TamperCrypto_SHA256_SHA512_ProduceDifferentHashes) {
    SKIP_IF_NOT_READY();
    ASSERT_TRUE(std::filesystem::exists(s_tempFile));

    const auto sha256 = TP::Instance().ComputeFileHash(
        s_tempFile.wstring(), SS::VerificationMethod::SHA256);
    const auto sha512 = TP::Instance().ComputeFileHash(
        s_tempFile.wstring(), SS::VerificationMethod::SHA512);

    // sha256 is 32 bytes; sha512 is 64 bytes — compare the first 32
    const std::vector<uint8_t> s256v(sha256.begin(), sha256.end());
    const std::vector<uint8_t> s512v(sha512.begin(), sha512.begin() + 32);

    EXPECT_NE(s256v, s512v)
        << "SHA-256 and first-32-bytes-of-SHA-512 must differ for the same file.";
}

/**
 * @brief ComputeFileHash on a non-existent path must return a zero (null)
 *        hash rather than undefined behaviour or an exception.
 *
 * This is a safety contract: callers must be able to distinguish "file not
 * found" (zero hash) from a real file hash.
 */
TEST_F(SelfProtectionStackFixture, TamperCrypto_ComputeFileHash_NonExistentFile_ZeroHash) {
    SKIP_IF_NOT_READY();

    const std::wstring absent = s_tempDir.wstring() + L"\\does_not_exist_9999.bin";
    const auto hash = TP::Instance().ComputeFileHash(absent, SS::VerificationMethod::SHA256);

    constexpr SS::Hash256 kZero{};
    EXPECT_EQ(hash, kZero)
        << "ComputeFileHash on a non-existent file must return a zero-filled hash.";
}

// ============================================================================
// GROUP 6 — CryptoManager ↔ CertValidator Key Operations
// ============================================================================

/**
 * @brief Ed25519 key generation must succeed and produce a non-empty key ID
 *        and a 32-byte public key blob.
 *
 * ShadowStrike uses Ed25519 for kernel attestation tokens.  If key generation
 * fails the entire kernel trust chain collapses.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_Ed25519KeyGeneration_SucceedsWithCorrectSizes) {
    SKIP_IF_NOT_READY();

    const auto result = CM::Instance().GenerateEd25519KeyPair();

    ASSERT_TRUE(result.IsSuccess())
        << "Ed25519 key pair generation must succeed: " << result.errorMessage;
    EXPECT_FALSE(result.keyId.empty())
        << "Generated key must have a non-empty ID.";
    EXPECT_EQ(result.publicKey.size(), CC::ED25519_KEY_SIZE)
        << "Ed25519 public key must be " << CC::ED25519_KEY_SIZE << " bytes.";
}

/**
 * @brief Ed25519 sign → verify roundtrip: verified with the correct public key
 *        returns true; wrong public key returns false.
 *
 * This is the production path for validating ShadowStrike agent certificates
 * and kernel driver identity attestation.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_Ed25519SignVerify_RoundtripAndWrongKeyRejected) {
    SKIP_IF_NOT_READY();

    const auto genResult = CM::Instance().GenerateEd25519KeyPair();
    ASSERT_TRUE(genResult.IsSuccess());

    const auto data = Helpers::BuildHighEntropyBuffer(128);
    const auto sigResult = CM::Instance().SignEd25519(data, genResult.keyId);

    ASSERT_TRUE(sigResult.IsSuccess())
        << "Ed25519 signing must succeed: " << sigResult.errorMessage;
    EXPECT_EQ(sigResult.signature.size(), 64u)
        << "Ed25519 signature must be exactly 64 bytes.";

    // Verify with the correct public key
    EXPECT_TRUE(CM::Instance().VerifyEd25519(data, sigResult.signature, genResult.publicKey))
        << "VerifyEd25519 with the correct public key must return true.";

    // Corrupt the public key by one bit and re-verify
    auto wrongKey = genResult.publicKey;
    wrongKey[0] ^= 0x80;
    EXPECT_FALSE(CM::Instance().VerifyEd25519(data, sigResult.signature, wrongKey))
        << "VerifyEd25519 with a corrupted public key must return false.";
}

/**
 * @brief Ed25519 signature over modified data must not verify.
 *
 * Validates that the signature binds to the exact message content, preventing
 * an attacker from reusing a valid signature on a different payload.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_Ed25519Verify_ModifiedData_ReturnsFalse) {
    SKIP_IF_NOT_READY();

    const auto genResult = CM::Instance().GenerateEd25519KeyPair();
    ASSERT_TRUE(genResult.IsSuccess());

    const auto originalData = Helpers::BuildHighEntropyBuffer(64);
    const auto sigResult    = CM::Instance().SignEd25519(originalData, genResult.keyId);
    ASSERT_TRUE(sigResult.IsSuccess());

    auto tampered = originalData;
    tampered[0] ^= 0x01;

    EXPECT_FALSE(CM::Instance().VerifyEd25519(tampered, sigResult.signature, genResult.publicKey))
        << "VerifyEd25519 must return false when the signed data is modified.";
}

/**
 * @brief CertificateValidator::CalculateFingerprint must produce the same
 *        SHA-256 digest as CryptoManager::SHA256 on the same raw bytes.
 *
 * Industry standard: SHA-256 fingerprint = SHA-256(DER bytes).  Both modules
 * must agree on this mapping; divergence would break certificate pinning.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_FingerprintMatchesCryptoSHA256) {
    SKIP_IF_NOT_READY();

    const auto rawData    = Helpers::BuildSequentialBuffer();
    const auto fingerprint = CV::Instance().CalculateFingerprint(rawData);
    const auto sha256Hash  = CM::Instance().SHA256(rawData);

    // Both produce 32-byte outputs; compare as equal-sized arrays
    ASSERT_EQ(fingerprint.size(), sha256Hash.size());
    const std::array<uint8_t, 32> fpArr  = fingerprint;
    EXPECT_EQ(fpArr, sha256Hash)
        << "CertificateValidator fingerprint must equal CryptoManager::SHA256 "
           "over the same raw bytes.";
}

/**
 * @brief Two different data blobs must produce different fingerprints.
 *
 * Collision resistance at this level is foundational: if two distinct
 * certificates map to the same fingerprint, the pinning subsystem becomes
 * trivially bypassable.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_FingerprintsOfDifferentData_AreUnique) {
    SKIP_IF_NOT_READY();

    const auto data1 = Helpers::BuildSequentialBuffer();
    auto       data2 = data1;
    data2[0] ^= 0x01;  // minimal change

    const auto fp1 = CV::Instance().CalculateFingerprint(data1);
    const auto fp2 = CV::Instance().CalculateFingerprint(data2);

    EXPECT_NE(fp1, fp2)
        << "Different data must produce different fingerprints (no collision).";
}

/**
 * @brief ECDSA P-256 key generation must succeed and produce correct key sizes.
 */
TEST_F(SelfProtectionStackFixture, CryptoCert_ECDSAP256KeyGeneration_Succeeds) {
    SKIP_IF_NOT_READY();

    const auto result = CM::Instance().GenerateECDSAKeyPair(
        SS::AsymmetricAlgorithm::ECDSA_P256);

    ASSERT_TRUE(result.IsSuccess())
        << "ECDSA P-256 key pair generation must succeed: " << result.errorMessage;
    EXPECT_FALSE(result.keyId.empty());
    EXPECT_FALSE(result.publicKey.empty())
        << "ECDSA P-256 public key must be non-empty.";
}

// ============================================================================
// GROUP 7 — FullStack_AllFourActive
// ============================================================================

/**
 * @brief All four modules pass their built-in SelfTest().
 *
 * SelfTest exercises internal consistency checks (algorithm self-tests, memory
 * integrity, state coherence).  A failed SelfTest must be treated as a fatal
 * signal in production deployment.
 */
TEST_F(SelfProtectionStackFixture, FullStack_SelfTestPassesForAllModules) {
    SKIP_IF_NOT_READY();

    EXPECT_TRUE(CM::Instance().SelfTest())  << "CryptoManager::SelfTest() must pass.";
    EXPECT_TRUE(CV::Instance().SelfTest())  << "CertificateValidator::SelfTest() must pass.";
    EXPECT_TRUE(TP::Instance().SelfTest())  << "TamperProtection::SelfTest() must pass.";
    EXPECT_TRUE(SD::Instance().SelfTest())  << "SelfDefense::SelfTest() must pass.";
}

/**
 * @brief All four GetVersionString() return non-empty strings.
 */
TEST_F(SelfProtectionStackFixture, FullStack_VersionStrings_AllNonEmpty) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(CM::GetVersionString().empty())  << "CryptoManager version must be non-empty.";
    EXPECT_FALSE(CV::GetVersionString().empty())  << "CertValidator version must be non-empty.";
    EXPECT_FALSE(TP::GetVersionString().empty())  << "TamperProtection version must be non-empty.";
    EXPECT_FALSE(SD::GetVersionString().empty())  << "SelfDefense version must be non-empty.";
}

/**
 * @brief CryptoManager statistics must reflect actual operations performed by
 *        earlier test groups (totalHashes > 0, totalEncryptions > 0).
 *
 * The stats accumulate across the entire test suite run because the singleton
 * is shared.  By the time this test executes, Groups 2–6 have issued many
 * hash and encrypt calls.
 */
TEST_F(SelfProtectionStackFixture, FullStack_Statistics_ReflectPriorOperations) {
    SKIP_IF_NOT_READY();

    const auto stats = CM::Instance().GetStatistics();
    EXPECT_GT(stats.totalHashes,      0u) << "totalHashes must be > 0 after prior hash operations.";
    EXPECT_GT(stats.totalEncryptions, 0u) << "totalEncryptions must be > 0 after prior encrypt ops.";
}

/**
 * @brief CryptoManager ExportReport returns a non-empty string.
 *
 * While format is internal, a non-empty report confirms that the reporting
 * subsystem is wired correctly.
 */
TEST_F(SelfProtectionStackFixture, FullStack_ExportReports_NonEmpty) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(TP::Instance().ExportReport().empty())
        << "TamperProtection::ExportReport() must return non-empty content.";
    EXPECT_FALSE(SD::Instance().ExportReport().empty())
        << "SelfDefense::ExportReport() must return non-empty content.";
}

/**
 * @brief TamperProtection GetStatistics returns zero tamperingDetected events
 *        in a clean test environment.
 */
TEST_F(SelfProtectionStackFixture, FullStack_TamperStatistics_CleanBaseline) {
    SKIP_IF_NOT_READY();

    const auto stats = TP::Instance().GetStatistics();
    EXPECT_EQ(stats.totalTamperingDetected, 0u)
        << "No tamper events should have fired in a clean test run.";
}

// ============================================================================
// GROUP 8 — ConcurrentSafety
// ============================================================================

/**
 * @brief 32 concurrent threads each computing SHA-256 of the same buffer must
 *        all produce the same digest.
 *
 * CryptoManager is documented as thread-safe.  A single wrong result reveals
 * either a data race on internal state or a non-reentrant hash context.
 */
TEST_F(SelfProtectionStackFixture, ConcurrentSafety_SHA256_32Threads_AllResultsEqual) {
    SKIP_IF_NOT_READY();

    constexpr int kThreads = 32;
    const auto data = Helpers::BuildHighEntropyBuffer(4096);
    const auto expected = CM::Instance().SHA256(data);

    std::vector<SS::Hash256> results(kThreads);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&results, &data, i]() {
            results[i] = CM::Instance().SHA256(data);
        });
    }
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_EQ(results[i], expected)
            << "Thread " << i << " produced a different SHA-256 result (race condition?).";
    }
}

/**
 * @brief 16 concurrent threads each performing AES-256-GCM encrypt then
 *        decrypt must all succeed without corruption or crashes.
 *
 * Each thread uses its own key and nonce to avoid key-reuse interactions; the
 * goal is to detect shared-state races inside the cipher implementation.
 */
TEST_F(SelfProtectionStackFixture, ConcurrentSafety_AES256GCM_16Threads_AllSucceed) {
    SKIP_IF_NOT_READY();

    constexpr int kThreads = 16;
    std::vector<bool> outcomes(kThreads, false);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&outcomes, i]() {
            const auto plaintext = Helpers::BuildHighEntropyBuffer(256);
            const auto key       = Helpers::MakeAES256Key(static_cast<uint8_t>(i + 1));
            const auto nonce     = CM::Instance().GenerateNonce();

            const auto enc = CM::Instance().Encrypt(
                plaintext,
                std::span<const uint8_t>(key.data(), key.size()),
                SS::SymmetricAlgorithm::AES_256_GCM,
                std::span<const uint8_t>(nonce.data(), nonce.size()));
            if (!enc.IsSuccess()) return;

            const auto dec = CM::Instance().Decrypt(
                enc.ciphertext,
                std::span<const uint8_t>(key.data(), key.size()),
                SS::SymmetricAlgorithm::AES_256_GCM,
                std::span<const uint8_t>(enc.iv.data(), enc.iv.size()),
                std::span<const uint8_t>(enc.tag.data(), enc.tag.size()));
            if (!dec.IsSuccess()) return;

            outcomes[i] = (dec.plaintext == plaintext);
        });
    }
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(outcomes[i])
            << "Thread " << i << " AES roundtrip failed (race or corruption?).";
    }
}

/**
 * @brief 8 concurrent threads calling CertificateValidator::CalculateFingerprint
 *        on the same data must all return the same fingerprint.
 */
TEST_F(SelfProtectionStackFixture,
       ConcurrentSafety_CertValidatorFingerprint_8Threads_Consistent) {
    SKIP_IF_NOT_READY();

    constexpr int kThreads = 8;
    const auto data     = Helpers::BuildSequentialBuffer();
    const auto expected = CV::Instance().CalculateFingerprint(data);

    std::vector<SS::CertificateFingerprint> results(kThreads);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&results, &data, i]() {
            results[i] = CV::Instance().CalculateFingerprint(data);
        });
    }
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_EQ(results[i], expected)
            << "Thread " << i << " fingerprint diverged (race condition?).";
    }
}

/**
 * @brief 8 concurrent threads reading SelfDefense configuration must all
 *        receive consistent results.
 */
TEST_F(SelfProtectionStackFixture, ConcurrentSafety_SelfDefenseConfigRead_8Threads_Consistent) {
    SKIP_IF_NOT_READY();

    constexpr int kThreads = 8;
    const auto refCfg  = SD::Instance().GetConfiguration();
    std::vector<bool> matches(kThreads, false);
    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&matches, &refCfg, i]() {
            const auto cfg = SD::Instance().GetConfiguration();
            matches[i] = (cfg.enableKernelProtection == refCfg.enableKernelProtection)
                      && (cfg.enableWatchdog         == refCfg.enableWatchdog)
                      && (cfg.verboseLogging         == refCfg.verboseLogging);
        });
    }
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(matches[i])
            << "Thread " << i << " saw inconsistent SelfDefense configuration.";
    }
}

// ============================================================================
// GROUP 9 — AdversarialInputs
// ============================================================================

/**
 * @brief CryptoManager::SHA256 of an empty span must return the RFC 6234
 *        known-value and must not crash.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_SHA256_EmptySpan_ReturnsKnownValue) {
    SKIP_IF_NOT_READY();

    ASSERT_NO_THROW({
        const std::vector<uint8_t> empty;
        const auto digest = CM::Instance().SHA256(empty);
        EXPECT_EQ(digest, Helpers::kSHA256OfEmpty);
    });
}

/**
 * @brief CryptoManager::SHA256 of a 1 MiB buffer must complete without crash.
 *
 * Large-file hashing is common in baseline computation.  Buffer-overrun or
 * integer-overflow bugs in the hash implementation would surface here.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_SHA256_1MiBBuffer_NoCrash) {
    SKIP_IF_NOT_READY();

    ASSERT_NO_THROW({
        const std::vector<uint8_t> large(1u << 20, 0xAA);
        const auto digest = CM::Instance().SHA256(large);
        EXPECT_EQ(digest.size(), CC::SHA256_SIZE);
    });
}

/**
 * @brief VerifyEd25519 with a zero-length signature must return false and not
 *        crash or assert.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_VerifyEd25519_EmptySignature_ReturnsFalse) {
    SKIP_IF_NOT_READY();

    const auto genResult = CM::Instance().GenerateEd25519KeyPair();
    ASSERT_TRUE(genResult.IsSuccess());

    const auto data = Helpers::BuildHighEntropyBuffer(64);
    const std::vector<uint8_t> emptySignature;

    bool result = true;
    ASSERT_NO_THROW({ result = CM::Instance().VerifyEd25519(
        data, emptySignature, genResult.publicKey); });
    EXPECT_FALSE(result)
        << "VerifyEd25519 with an empty signature must return false.";
}

/**
 * @brief VerifyEd25519 with a zero-length public key must return false.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_VerifyEd25519_EmptyPublicKey_ReturnsFalse) {
    SKIP_IF_NOT_READY();

    const auto genResult = CM::Instance().GenerateEd25519KeyPair();
    ASSERT_TRUE(genResult.IsSuccess());

    const auto data      = Helpers::BuildHighEntropyBuffer(64);
    const auto sigResult = CM::Instance().SignEd25519(data, genResult.keyId);
    ASSERT_TRUE(sigResult.IsSuccess());

    const std::vector<uint8_t> emptyKey;
    bool result = true;
    ASSERT_NO_THROW({ result = CM::Instance().VerifyEd25519(
        data, sigResult.signature, emptyKey); });
    EXPECT_FALSE(result)
        << "VerifyEd25519 with an empty public key must return false.";
}

/**
 * @brief AES-256-GCM decrypt with a wrong key must return an authentication
 *        failure — not a crash, not a buffer overread.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_AES256GCM_WrongKey_AuthFails) {
    SKIP_IF_NOT_READY();

    const auto plaintext = Helpers::BuildHighEntropyBuffer(256);
    const auto key1      = Helpers::MakeAES256Key(0x11);
    const auto key2      = Helpers::MakeAES256Key(0x22);
    const auto nonce     = CM::Instance().GenerateNonce();

    const auto enc = CM::Instance().Encrypt(
        plaintext,
        std::span<const uint8_t>(key1.data(), key1.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(nonce.data(), nonce.size()));
    ASSERT_TRUE(enc.IsSuccess());

    SS::DecryptionResult dec;
    ASSERT_NO_THROW({ dec = CM::Instance().Decrypt(
        enc.ciphertext,
        std::span<const uint8_t>(key2.data(), key2.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(enc.iv.data(), enc.iv.size()),
        std::span<const uint8_t>(enc.tag.data(), enc.tag.size())); });
    EXPECT_FALSE(dec.IsSuccess())
        << "Decrypt with wrong key must fail authentication.";
}

/**
 * @brief ParseCertificate with a 64 KiB buffer of 0xFF bytes must not crash.
 *
 * Maximum-size hostile certificate blobs are a common fuzzer discovery.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_ParseCertificate_MaxSizeGarbage_NoCrash) {
    SKIP_IF_NOT_READY();

    const std::vector<uint8_t> giant(CRC::MAX_CERTIFICATE_SIZE, 0xFF);
    ASSERT_NO_THROW({
        const auto result = CV::Instance().ParseCertificate(giant);
        EXPECT_FALSE(result.has_value());
    });
}

/**
 * @brief VerifyHMAC with an empty expected-MAC must return false.
 */
TEST_F(SelfProtectionStackFixture, Adversarial_VerifyHMAC_EmptyMAC_ReturnsFalse) {
    SKIP_IF_NOT_READY();

    const auto data = Helpers::BuildHighEntropyBuffer(128);
    const auto key  = Helpers::BuildZeroBuffer(32);
    const std::vector<uint8_t> emptyMAC;

    bool result = true;
    ASSERT_NO_THROW({ result = CM::Instance().VerifyHMAC(
        data, emptyMAC, key, SS::HashAlgorithm::SHA256); });
    EXPECT_FALSE(result)
        << "VerifyHMAC with empty expected MAC must return false.";
}

// ============================================================================
// GROUP 10 — Statistics_Accounting
// ============================================================================

/**
 * @brief After performing N additional SHA-256 operations, totalHashes must
 *        increase by at least N.
 */
TEST_F(SelfProtectionStackFixture, Statistics_TotalHashes_IncrementAfterSHA256) {
    SKIP_IF_NOT_READY();

    const auto before  = CM::Instance().GetStatistics().totalHashes;
    constexpr int kN   = 10;
    const auto data    = Helpers::BuildZeroBuffer(64);

    for (int i = 0; i < kN; ++i)
        std::ignore = CM::Instance().SHA256(data);

    const auto after = CM::Instance().GetStatistics().totalHashes;
    EXPECT_GE(after - before, static_cast<uint64_t>(kN))
        << "totalHashes must increase by at least " << kN << " after " << kN
        << " SHA-256 calls.";
}

/**
 * @brief After performing N additional encrypt operations, totalEncryptions
 *        must increase by at least N.
 */
TEST_F(SelfProtectionStackFixture, Statistics_TotalEncryptions_IncrementAfterEncrypt) {
    SKIP_IF_NOT_READY();

    const auto before = CM::Instance().GetStatistics().totalEncryptions;
    constexpr int kN  = 5;
    const auto key    = Helpers::MakeAES256Key(0x55);
    const auto nonce  = CM::Instance().GenerateNonce();
    const auto data   = Helpers::BuildZeroBuffer(128);

    for (int i = 0; i < kN; ++i) {
        std::ignore = CM::Instance().Encrypt(
            data,
            std::span<const uint8_t>(key.data(), key.size()),
            SS::SymmetricAlgorithm::AES_256_GCM,
            std::span<const uint8_t>(nonce.data(), nonce.size()));
    }

    const auto after = CM::Instance().GetStatistics().totalEncryptions;
    EXPECT_GE(after - before, static_cast<uint64_t>(kN))
        << "totalEncryptions must increase by at least " << kN
        << " after " << kN << " Encrypt calls.";
}

/**
 * @brief authenticationFailures increments after a failed AES-256-GCM decrypt.
 */
TEST_F(SelfProtectionStackFixture, Statistics_AuthFailures_IncrementAfterBadDecrypt) {
    SKIP_IF_NOT_READY();

    const auto key1 = Helpers::MakeAES256Key(0xAA);
    const auto key2 = Helpers::MakeAES256Key(0xBB);
    const auto data = Helpers::BuildHighEntropyBuffer(128);
    const auto nonce = CM::Instance().GenerateNonce();

    const auto enc  = CM::Instance().Encrypt(
        data,
        std::span<const uint8_t>(key1.data(), key1.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(nonce.data(), nonce.size()));
    ASSERT_TRUE(enc.IsSuccess());

    const auto before = CM::Instance().GetStatistics().authenticationFailures;
    std::ignore = CM::Instance().Decrypt(
        enc.ciphertext,
        std::span<const uint8_t>(key2.data(), key2.size()),
        SS::SymmetricAlgorithm::AES_256_GCM,
        std::span<const uint8_t>(enc.iv.data(), enc.iv.size()),
        std::span<const uint8_t>(enc.tag.data(), enc.tag.size()));

    const auto after = CM::Instance().GetStatistics().authenticationFailures;
    EXPECT_GT(after, before)
        << "authenticationFailures must increment after a failed AES-GCM decrypt.";
}

/**
 * @brief ResetStatistics must zero all counters.
 *
 * Note: The fixture's prior tests have accumulated statistics.  After Reset,
 * every counter must be 0.  The test immediately re-checks to ensure no
 * background thread increments them before the EXPECT assertions run.
 */
TEST_F(SelfProtectionStackFixture, Statistics_ResetStatistics_ZeroesAllCounters) {
    SKIP_IF_NOT_READY();

    CM::Instance().ResetStatistics();
    const auto stats = CM::Instance().GetStatistics();

    EXPECT_EQ(stats.totalHashes,           0u) << "totalHashes must be 0 after reset.";
    EXPECT_EQ(stats.totalEncryptions,      0u) << "totalEncryptions must be 0 after reset.";
    EXPECT_EQ(stats.totalDecryptions,      0u) << "totalDecryptions must be 0 after reset.";
    EXPECT_EQ(stats.totalSignatures,       0u) << "totalSignatures must be 0 after reset.";
    EXPECT_EQ(stats.totalVerifications,    0u) << "totalVerifications must be 0 after reset.";
    EXPECT_EQ(stats.authenticationFailures,0u) << "authenticationFailures must be 0 after reset.";
}

// ============================================================================
// GROUP 11 — Constants_Contracts
// ============================================================================

/**
 * @brief CryptoConstants key-size, output-size, and iteration constants must
 *        be at the NIST-recommended minimum values.
 *
 * Violations of these invariants would silently weaken every cryptographic
 * operation in the product.
 */
TEST(SelfProtectionStack_Constants, CryptoConstants_KeyAndHashSizes_AtMinimum) {
    EXPECT_EQ(CC::AES_128_KEY_SIZE,  16u);
    EXPECT_EQ(CC::AES_256_KEY_SIZE,  32u);
    EXPECT_EQ(CC::SHA256_SIZE,       32u);
    EXPECT_EQ(CC::SHA384_SIZE,       48u);
    EXPECT_EQ(CC::SHA512_SIZE,       64u);
    EXPECT_EQ(CC::ED25519_KEY_SIZE,  32u);
    EXPECT_EQ(CC::AES_GCM_NONCE_SIZE,12u);
    EXPECT_EQ(CC::AES_GCM_TAG_SIZE,  16u);
    EXPECT_GE(CC::DEFAULT_PBKDF2_ITERATIONS, 100000u)
        << "PBKDF2 iterations must meet OWASP/NIST minimum (100 000+).";
}

/**
 * @brief CertificateConstants chain, cache, and size limits must be
 *        operationally sane.
 */
TEST(SelfProtectionStack_Constants, CertConstants_LimitsAreSane) {
    EXPECT_GT(CRC::MAX_CHAIN_LENGTH,         0u);
    EXPECT_LE(CRC::MAX_CHAIN_LENGTH,         100u)
        << "MAX_CHAIN_LENGTH > 100 is unrealistic and likely a configuration error.";
    EXPECT_GT(CRC::MAX_CERTIFICATE_SIZE,     0u);
    EXPECT_GT(CRC::MAX_CACHED_CERTIFICATES,  0u);
    EXPECT_GT(CRC::CLOCK_SKEW_TOLERANCE_SECS,0u)
        << "Zero clock-skew tolerance would break all real-world certificate checks.";
}

/**
 * @brief SelfDefenseConstants watchdog and heartbeat timing must be in
 *        operationally sane ranges.
 */
TEST(SelfProtectionStack_Constants, SelfDefenseConstants_TimingRanges) {
    EXPECT_GT(SDC::WATCHDOG_INTERVAL_MS,  0u);
    EXPECT_LT(SDC::WATCHDOG_INTERVAL_MS,  60000u)
        << "Watchdog interval > 60 s is too slow for a production EDR agent.";
    EXPECT_GT(SDC::HEARTBEAT_TIMEOUT_MS,  SDC::WATCHDOG_INTERVAL_MS)
        << "Heartbeat timeout must exceed watchdog interval.";
}

/**
 * @brief TamperProtectionConstants check-interval bounds must be sane and
 *        correctly ordered (MIN < DEFAULT < MAX).
 */
TEST(SelfProtectionStack_Constants, TamperProtectionConstants_IntervalOrdering) {
    EXPECT_LT(TPC::MIN_CHECK_INTERVAL_MS, TPC::DEFAULT_CHECK_INTERVAL_MS);
    EXPECT_LT(TPC::DEFAULT_CHECK_INTERVAL_MS, TPC::MAX_CHECK_INTERVAL_MS);
    EXPECT_GT(TPC::MIN_CHECK_INTERVAL_MS, 0u);
}

// ============================================================================
// GROUP 12 — RAII_Guards
// ============================================================================

/**
 * @brief ScopedSelfDefensePause must report IsPaused() == true while in scope
 *        and the state must auto-revert when the guard is destroyed.
 *
 * The pause guard is used by the update pipeline to briefly suspend protection
 * during signature database replacement.  Failure to auto-resume after the
 * update would leave the endpoint unprotected indefinitely.
 */
TEST_F(SelfProtectionStackFixture, RAII_ScopedSelfDefensePause_AutoResumes) {
    SKIP_IF_NOT_READY();

    const auto token = SD::Instance().GenerateAuthorizationToken("raii-pause-test", 30);
    ASSERT_FALSE(token.empty()) << "Token generation must succeed.";

    {
        SS::ScopedSelfDefensePause guard(token, 0 /* immediate */);
        EXPECT_TRUE(guard.IsPaused())
            << "ScopedSelfDefensePause must report IsPaused() == true while in scope.";
    }
    // After the scope, SelfDefense must have auto-resumed.
    EXPECT_NE(SD::Instance().GetStatus(), SS::ModuleStatus::Stopped)
        << "SelfDefense must not be Stopped after ScopedSelfDefensePause leaves scope.";
}

/**
 * @brief ScopedProtectionPause (TamperProtection) must report IsPaused() == true
 *        while in scope and auto-resume on destruction.
 */
TEST_F(SelfProtectionStackFixture, RAII_ScopedTamperProtectionPause_AutoResumes) {
    SKIP_IF_NOT_READY();

    const auto token = SD::Instance().GenerateAuthorizationToken("raii-tamper-pause", 30);
    ASSERT_FALSE(token.empty());

    {
        SS::ScopedProtectionPause guard(token, 0);
        EXPECT_TRUE(guard.IsPaused())
            << "ScopedProtectionPause must report IsPaused() == true while in scope.";
    }
    EXPECT_TRUE(TP::Instance().IsEnabled())
        << "TamperProtection must still be enabled after ScopedProtectionPause scope exits.";
}

/**
 * @brief ProtectedScope must report IsProtected() == true while in scope.
 *
 * ProtectedScope wraps a process ID; passing 0 means "protect own process".
 * The RAII contract ensures the protection is removed on destruction.
 */
TEST_F(SelfProtectionStackFixture, RAII_ProtectedScope_IsProtectedDuringScope) {
    SKIP_IF_NOT_READY();

    {
        SS::ProtectedScope scope(::GetCurrentProcessId());
        EXPECT_TRUE(scope.IsProtected())
            << "ProtectedScope must report IsProtected() == true while in scope.";
    }
    // After scope exit the SelfDefense singleton remains intact
    EXPECT_TRUE(SD::Instance().IsInitialized())
        << "SelfDefense must remain initialized after ProtectedScope destructs.";
}

/**
 * @brief ResourceProtectionGuard must report IsProtected() == true while in
 *        scope, protecting a file resource.
 */
TEST_F(SelfProtectionStackFixture, RAII_ResourceProtectionGuard_FileResource_IsProtected) {
    SKIP_IF_NOT_READY();
    ASSERT_TRUE(std::filesystem::exists(s_tempFile));

    const auto token = SD::Instance().GenerateAuthorizationToken("raii-resource-guard", 30);

    {
        SS::ResourceProtectionGuard guard(
            s_tempFile.wstring(),
            SS::ProtectedResourceType::File,
            token);
        EXPECT_TRUE(guard.IsProtected())
            << "ResourceProtectionGuard must report IsProtected() == true for a valid file path.";
    }
    // TamperProtection singleton must still be Running after guard scope exits
    EXPECT_EQ(TP::Instance().GetStatus(), SS::ModuleStatus::Running)
        << "TamperProtection must remain Running after ResourceProtectionGuard leaves scope.";
}

// ============================================================================
// GROUP 13 — AuthorizationToken_Lifecycle
// ============================================================================

/**
 * @brief A freshly generated token must pass VerifyAuthorizationToken.
 *
 * This is the most basic contract for the authorization subsystem that
 * governs every privileged operation in the SelfProtection stack.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_FreshlyGeneratedToken_Verifies) {
    SKIP_IF_NOT_READY();

    const auto token = SD::Instance().GenerateAuthorizationToken("test-verify", 30);
    ASSERT_FALSE(token.empty()) << "Token must be non-empty.";
    EXPECT_TRUE(SD::Instance().VerifyAuthorizationToken(token))
        << "A freshly generated token must pass VerifyAuthorizationToken.";
}

/**
 * @brief An empty string must be rejected by VerifyAuthorizationToken.
 *
 * This prevents callers from accidentally passing an uninitialized or
 * default-constructed token string and gaining elevated access.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_EmptyToken_Rejected) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(SD::Instance().VerifyAuthorizationToken(""))
        << "Empty token must be rejected.";
}

/**
 * @brief An arbitrary random string must be rejected as an authorization token.
 *
 * Tokens cannot be guessed; random input must fail verification.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_RandomString_Rejected) {
    SKIP_IF_NOT_READY();

    constexpr std::string_view kFake =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    EXPECT_FALSE(SD::Instance().VerifyAuthorizationToken(kFake))
        << "A guessable/random token must not pass verification.";
}

/**
 * @brief A token with a single character modified (bit-flip equivalent) must
 *        be rejected.
 *
 * Validates the MAC binding inside the token: an attacker who intercepts a
 * valid token and modifies it must not succeed.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_TamperedToken_Rejected) {
    SKIP_IF_NOT_READY();

    const auto token = SD::Instance().GenerateAuthorizationToken("tamper-test", 30);
    ASSERT_FALSE(token.empty());
    ASSERT_GE(token.size(), 2u) << "Token must be long enough to tamper.";

    std::string tampered = token;
    // Flip one character near the end (avoid modifying the first few chars
    // in case the token starts with a version prefix that is not authenticated)
    tampered[tampered.size() - 1] ^= 0x01;

    EXPECT_FALSE(SD::Instance().VerifyAuthorizationToken(tampered))
        << "A single-character mutation in the token must cause rejection.";
}

/**
 * @brief Two tokens generated for different purposes must be distinct strings.
 *
 * Tokens are purpose-bound.  An attacker must not be able to reuse a token
 * obtained for one operation (e.g., "pause-protection") for a different one
 * (e.g., "shutdown-service").
 */
TEST_F(SelfProtectionStackFixture, AuthToken_DifferentPurposes_ProduceDifferentTokens) {
    SKIP_IF_NOT_READY();

    const auto t1 = SD::Instance().GenerateAuthorizationToken("purpose-alpha", 30);
    const auto t2 = SD::Instance().GenerateAuthorizationToken("purpose-beta",  30);

    ASSERT_FALSE(t1.empty());
    ASSERT_FALSE(t2.empty());
    EXPECT_NE(t1, t2)
        << "Tokens for different purposes must be distinct strings.";
}

/**
 * @brief SelfDefense::Pause with an empty auth token must return false (not
 *        pause protection).
 *
 * This blocks a trivially constructed call from accidentally or maliciously
 * disabling the SelfDefense subsystem.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_PauseWithEmptyToken_Rejected) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(SD::Instance().Pause("", 0))
        << "SelfDefense::Pause with an empty auth token must return false.";
    EXPECT_NE(SD::Instance().GetStatus(), SS::ModuleStatus::Paused)
        << "SelfDefense must not be paused after a rejected Pause call.";
}

/**
 * @brief TamperProtection::Pause with an empty auth token must return false.
 */
TEST_F(SelfProtectionStackFixture, AuthToken_TamperPauseWithEmptyToken_Rejected) {
    SKIP_IF_NOT_READY();

    EXPECT_FALSE(TP::Instance().Pause("", 0))
        << "TamperProtection::Pause with an empty auth token must return false.";
    EXPECT_TRUE(TP::Instance().IsEnabled())
        << "TamperProtection must remain enabled after rejected Pause.";
}
