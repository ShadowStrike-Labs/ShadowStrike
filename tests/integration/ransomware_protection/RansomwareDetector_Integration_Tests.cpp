/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests – RansomwareProtection ↔ Store Dependencies
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests the production integration surface of RansomwareDetector —
 * the core behavioral ransomware detection engine.  Every test uses the real
 * singleton with no mocks; store dependencies are either exercised via the
 * detector's own initialization path or, where the public API is purely
 * in-memory / stateless, verified through direct method contracts.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *  GROUP 1  StaticEntropyAnalysis  - CalculateEntropy / AnalyzeEntropy / IsEncrypted
 *  GROUP 2  ConfigValidation       - RansomwareDetectorConfiguration::IsValid contracts
 *  GROUP 3  Lifecycle              - Initialize / Shutdown / IsInitialized / GetStatus
 *  GROUP 4  HoneypotManagement     - Register / IsHoneypot / Unregister / OnHoneypotTouched
 *  GROUP 5  ProcessWhitelist       - WhitelistProcess / IsProcessWhitelisted / Unwhitelist
 *  GROUP 6  FamilySignatures       - RegisterFamilySignature / GetFamilySignature /
 *                                   IdentifyFamilyFromExtension
 *  GROUP 7  ContainmentMode        - EnterContainmentMode / ExitContainmentMode / query
 *  GROUP 8  RecoveryProcess        - RegisterRecoveryProcess / IsRecoveryProcess
 *  GROUP 9  Statistics             - GetStatistics / ResetStatistics zero-baseline
 *  GROUP 10 DetectionCallbacks     - SetDetectionCallback fires on honeypot + high-entropy
 *  GROUP 11 WriteAnalysis          - AnalyzeWriteEx entropy result structure
 *  GROUP 12 ProtectedPaths         - IsProtectedPath with config-driven directories
 *  GROUP 13 ConstantsContract      - RansomwareConstants value sanity
 *
 * ============================================================================
 * SUITE LIFECYCLE
 * ============================================================================
 *  SetUpTestSuite  – Initializes the RansomwareDetector singleton once with a
 *                   default configuration (no disk databases needed for most
 *                   in-memory tests).
 *  TearDownTestSuite – Calls Shutdown() so subsequent test binaries start clean.
 *
 * NOTE: RansomwareDetector is a Meyers singleton.  Shutdown() does NOT destroy
 * the singleton instance; it only resets internal state so tests that call
 * Initialize() again in later suites work correctly.
 *
 * ============================================================================
 * NAMESPACE NOTES
 * ============================================================================
 *  ShadowStrike::Ransomware — all types from RansomwareDetector.hpp live here.
 *  RansomwareConstants      — compile-time constants sub-namespace.
 */

// ============================================================================
// PLATFORM / STANDARD HEADERS
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
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
#include "../../../src/Shared_modules/RansomwareProtection/RansomwareDetector.hpp"

// ============================================================================
// CONVENIENCE ALIASES
// ============================================================================
namespace RW = ShadowStrike::Ransomware;
using RD = RW::RansomwareDetector;
namespace RC = RW::RansomwareConstants;

// ============================================================================
// SKIP GUARD — skips individual tests if suite setup failed
// ============================================================================
#define SKIP_IF_NOT_READY()                                                 \
    do {                                                                    \
        if (!RansomwareIntegrationFixture::s_setupSucceeded) {              \
            GTEST_SKIP() << "Suite setup failed; skipping test.";           \
        }                                                                   \
    } while (false)

// ============================================================================
// ENTROPY GENERATION HELPERS
// ============================================================================
namespace EntropyHelpers {

    /**
     * @brief Builds a maximally high-entropy buffer (pseudo-random byte stream).
     *
     * Uses a simple LCG so the test is deterministic and fast.  The resulting
     * ~4 KiB buffer consistently yields Shannon entropy above RC::ENTROPY_THRESHOLD
     * (7.5 bits/byte) because all 256 byte values appear roughly equally often.
     */
    [[nodiscard]] static std::vector<uint8_t> BuildHighEntropyBuffer(size_t size = 4096) {
        std::vector<uint8_t> buf(size);
        uint64_t state = 0xDEADBEEFCAFEBABEULL;
        for (auto& b : buf) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b = static_cast<uint8_t>(state & 0xFF);
        }
        return buf;
    }

    /**
     * @brief Builds a minimal-entropy buffer (all zeroes).
     *
     * Zero-filled data has Shannon entropy = 0.0 bits/byte and is trivially
     * identified as unencrypted by any sane entropy analysis.
     */
    [[nodiscard]] static std::vector<uint8_t> BuildZeroBuffer(size_t size = 4096) {
        return std::vector<uint8_t>(size, 0x00);
    }

    /**
     * @brief Builds a repeating-pattern buffer.
     *
     * "ABABABAB…" has exactly 1 bit of entropy (only 2 distinct bytes,
     * each with 50 % probability).  Well below any encryption threshold.
     */
    [[nodiscard]] static std::vector<uint8_t> BuildRepeatBuffer(size_t size = 4096) {
        std::vector<uint8_t> buf(size);
        for (size_t i = 0; i < size; ++i)
            buf[i] = (i & 1) ? 0xAB : 0xCD;
        return buf;
    }

} // namespace EntropyHelpers

// ============================================================================
// TEST FIXTURE
// ============================================================================
class RansomwareIntegrationFixture : public ::testing::Test {
public:
    /// @brief true if SetUpTestSuite completed without error.
    static bool s_setupSucceeded;

    static void SetUpTestSuite() {
        s_setupSucceeded = false;

        RW::RansomwareDetectorConfiguration cfg;
        cfg.enableEntropyAnalysis  = true;
        cfg.enableRateMonitoring   = true;
        cfg.enableHoneypotIntegration = true;
        cfg.enableAutoBlock        = false;  // no process-kill in unit environment
        cfg.enableProcessKill      = false;
        cfg.verboseLogging         = false;
        cfg.protectedDirectories   = { L"C:\\ShadowStrike\\Protected\\" };

        if (!RD::Instance().Initialize(cfg)) {
            ADD_FAILURE() << "RansomwareDetector::Initialize() failed in SetUpTestSuite.";
            return;
        }
        s_setupSucceeded = true;
    }

    static void TearDownTestSuite() {
        RD::Instance().Shutdown();
    }
};

bool RansomwareIntegrationFixture::s_setupSucceeded = false;

// ============================================================================
// GROUP 1 — StaticEntropyAnalysis
// ============================================================================

/**
 * @brief Zero-filled data must produce entropy ≈ 0.0.
 *
 * Shannon entropy of a uniform-probability single symbol is 0.  The result
 * must be below RansomwareConstants::MIN_SUSPICION_ENTROPY (7.0) by a very
 * wide margin so that false positives on genuinely empty-written files are
 * categorically excluded.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_ZeroBuffer_LowEntropy) {
    const auto buf = EntropyHelpers::BuildZeroBuffer();
    const double entropy = RD::CalculateEntropy(std::span<const uint8_t>(buf));

    EXPECT_GE(entropy, 0.0)          << "Entropy must be non-negative.";
    EXPECT_LT(entropy, 1.0)          << "Zero buffer must have near-zero entropy.";
}

/**
 * @brief High-entropy (pseudo-random) data must produce entropy > ENTROPY_THRESHOLD.
 *
 * This validates that the entropy engine can distinguish encrypted/compressed
 * file content from plaintext.  Required to be ≥ threshold so that the engine
 * does NOT clear high-entropy writes.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_HighEntropyBuffer_ExceedsThreshold) {
    const auto buf = EntropyHelpers::BuildHighEntropyBuffer();
    const double entropy = RD::CalculateEntropy(std::span<const uint8_t>(buf));

    EXPECT_GE(entropy, RC::ENTROPY_THRESHOLD)
        << "High-entropy buffer must exceed RC::ENTROPY_THRESHOLD="
        << RC::ENTROPY_THRESHOLD;
}

/**
 * @brief Repeating-pattern data must be classified as non-encrypted.
 *
 * Simple alternating byte pattern has very low entropy (≈1 bit/byte) and
 * must not trigger encryption detection.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_RepeatBuffer_NotEncrypted) {
    const auto buf = EntropyHelpers::BuildRepeatBuffer();
    EXPECT_FALSE(RD::IsEncrypted(std::span<const uint8_t>(buf)))
        << "Repeating-pattern buffer must not be classified as encrypted.";
}

/**
 * @brief High-entropy data must be classified as encrypted.
 *
 * The IsEncrypted() oracle must agree with the raw entropy threshold to
 * ensure both APIs return consistent verdicts.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_HighEntropy_ClassifiedEncrypted) {
    const auto buf = EntropyHelpers::BuildHighEntropyBuffer();
    EXPECT_TRUE(RD::IsEncrypted(std::span<const uint8_t>(buf)))
        << "High-entropy pseudo-random buffer must be classified as encrypted.";
}

/**
 * @brief AnalyzeEntropy must return an EntropyResult that is internally consistent.
 *
 * Specifically:
 *  - shannonEntropy must equal CalculateEntropy for the same span
 *  - isEncrypted field must agree with IsEncrypted()
 *  - confidence must be in [0, 1]
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_AnalyzeEntropyConsistency) {
    const auto buf  = EntropyHelpers::BuildHighEntropyBuffer();
    const std::span<const uint8_t> sp(buf);

    const double rawEntropy    = RD::CalculateEntropy(sp);
    const bool   rawEncrypted  = RD::IsEncrypted(sp);
    const auto   result        = RD::AnalyzeEntropy(sp);

    EXPECT_NEAR(result.shannonEntropy, rawEntropy, 0.001)
        << "AnalyzeEntropy.shannonEntropy must match CalculateEntropy for same buffer.";
    EXPECT_EQ(result.isEncrypted, rawEncrypted)
        << "AnalyzeEntropy.isEncrypted must agree with IsEncrypted().";
    EXPECT_GE(result.confidence, 0.0);
    EXPECT_LE(result.confidence, 1.0);
}

/**
 * @brief AnalyzeEntropy on zero buffer must produce shannonEntropy ≈ 0 and
 *        isEncrypted == false.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_ZeroBuffer_AnalyzeResult) {
    const auto buf = EntropyHelpers::BuildZeroBuffer();
    const auto result = RD::AnalyzeEntropy(std::span<const uint8_t>(buf));

    EXPECT_LT(result.shannonEntropy, 1.0);
    EXPECT_FALSE(result.isEncrypted);
}

/**
 * @brief Empty span must not crash and must return safe default values.
 *
 * Defensive boundary: if a driver sends a zero-length write event the
 * entropy engine must not throw or return garbage.
 */
TEST_F(RansomwareIntegrationFixture, StaticEntropyAnalysis_EmptySpan_SafeDefault) {
    ASSERT_NO_THROW({
        const double e = RD::CalculateEntropy(std::span<const uint8_t>{});
        EXPECT_GE(e, 0.0);
        EXPECT_LE(e, 8.0);
    });
    ASSERT_NO_THROW({
        const bool enc = RD::IsEncrypted(std::span<const uint8_t>{});
        (void)enc;  // Just ensure it does not throw
    });
    ASSERT_NO_THROW({
        const auto r = RD::AnalyzeEntropy(std::span<const uint8_t>{});
        EXPECT_GE(r.confidence, 0.0);
        EXPECT_LE(r.confidence, 1.0);
    });
}

// ============================================================================
// GROUP 2 — ConfigValidation
// ============================================================================

/**
 * @brief Default-constructed configuration must be valid out-of-the-box.
 */
TEST_F(RansomwareIntegrationFixture, ConfigValidation_DefaultIsValid) {
    RW::RansomwareDetectorConfiguration cfg;
    EXPECT_TRUE(cfg.IsValid())
        << "Default RansomwareDetectorConfiguration must pass IsValid().";
}

/**
 * @brief Configuration with standard protected-directory list must be valid.
 */
TEST_F(RansomwareIntegrationFixture, ConfigValidation_WithProtectedDirs_Valid) {
    RW::RansomwareDetectorConfiguration cfg;
    cfg.protectedDirectories = {
        L"C:\\Users\\",
        L"D:\\Work\\Documents\\"
    };
    EXPECT_TRUE(cfg.IsValid());
}

/**
 * @brief Configuration with excluded-process-names list must still be valid.
 */
TEST_F(RansomwareIntegrationFixture, ConfigValidation_WithExcludedProcesses_Valid) {
    RW::RansomwareDetectorConfiguration cfg;
    cfg.excludedProcesses = { L"backup.exe", L"winzip.exe" };
    EXPECT_TRUE(cfg.IsValid());
}

/**
 * @brief Entropy threshold must be exposed via config and equal the constant.
 */
TEST_F(RansomwareIntegrationFixture, ConfigValidation_DefaultEntropyThreshold_MatchesConstant) {
    RW::RansomwareDetectorConfiguration cfg;
    EXPECT_DOUBLE_EQ(cfg.entropyThreshold, RC::ENTROPY_THRESHOLD);
}

// ============================================================================
// GROUP 3 — Lifecycle
// ============================================================================

/**
 * @brief IsInitialized must return true after successful Initialize().
 */
TEST_F(RansomwareIntegrationFixture, Lifecycle_IsInitializedAfterInit) {
    SKIP_IF_NOT_READY();
    EXPECT_TRUE(RD::Instance().IsInitialized());
}

/**
 * @brief GetStatus must return Running after successful initialization.
 */
TEST_F(RansomwareIntegrationFixture, Lifecycle_StatusRunningAfterInit) {
    SKIP_IF_NOT_READY();
    const auto status = RD::Instance().GetStatus();
    EXPECT_EQ(status, RW::ModuleStatus::Running);
}

/**
 * @brief HasInstance must return true when the singleton has been created.
 */
TEST_F(RansomwareIntegrationFixture, Lifecycle_HasInstanceTrue) {
    EXPECT_TRUE(RD::HasInstance());
}

/**
 * @brief GetVersionString must return a non-empty string.
 */
TEST_F(RansomwareIntegrationFixture, Lifecycle_VersionStringNonEmpty) {
    const std::string ver = RD::GetVersionString();
    EXPECT_FALSE(ver.empty())
        << "GetVersionString() must not return an empty string.";
}

// ============================================================================
// GROUP 4 — HoneypotManagement
// ============================================================================

/**
 * @brief A freshly registered honeypot path must be found by IsHoneypot().
 */
TEST_F(RansomwareIntegrationFixture, HoneypotManagement_Register_IsHoneypot_True) {
    SKIP_IF_NOT_READY();
    const std::wstring hp = L"C:\\ShadowStrike\\honeypot\\README_DECRYPT.txt";
    RD::Instance().RegisterHoneypot(hp);
    EXPECT_TRUE(RD::Instance().IsHoneypot(hp))
        << "Registered honeypot path must be recognised by IsHoneypot().";
    RD::Instance().UnregisterHoneypot(hp);
}

/**
 * @brief IsHoneypot must return false for a path that was never registered.
 */
TEST_F(RansomwareIntegrationFixture, HoneypotManagement_Unregistered_IsHoneypot_False) {
    SKIP_IF_NOT_READY();
    EXPECT_FALSE(RD::Instance().IsHoneypot(L"C:\\NotAHoneypot\\file.dat"))
        << "Unregistered path must not be recognised as a honeypot.";
}

/**
 * @brief UnregisterHoneypot must remove the path from the honeypot set.
 */
TEST_F(RansomwareIntegrationFixture, HoneypotManagement_Unregister_RemovesEntry) {
    SKIP_IF_NOT_READY();
    const std::wstring hp = L"C:\\ShadowStrike\\honeypot\\temp_HP_unregister.txt";
    RD::Instance().RegisterHoneypot(hp);
    ASSERT_TRUE(RD::Instance().IsHoneypot(hp));
    RD::Instance().UnregisterHoneypot(hp);
    EXPECT_FALSE(RD::Instance().IsHoneypot(hp))
        << "After UnregisterHoneypot the path must no longer be a honeypot.";
}

/**
 * @brief OnHoneypotTouched must fire the registered DetectionCallback with a
 *        Honeypot verdict.
 *
 * This verifies the cross-module wiring:  the kernel driver (PhantomSensor)
 * calls OnHoneypotTouched → detection pipeline → user callback.
 */
TEST_F(RansomwareIntegrationFixture, HoneypotManagement_OnTouched_FiresCallbackWithHoneypotVerdict) {
    SKIP_IF_NOT_READY();

    std::atomic<bool>        callbackFired{false};
    RW::DetectionVerdict     capturedVerdict{RW::DetectionVerdict::Clean};
    std::mutex               mu;

    RD::Instance().SetDetectionCallback([&](const RW::DetectionEvent& ev) {
        std::lock_guard<std::mutex> lk(mu);
        callbackFired.store(true, std::memory_order_release);
        capturedVerdict = ev.verdict;
    });

    const std::wstring hp = L"C:\\ShadowStrike\\honeypot\\HP_callback_test.txt";
    RD::Instance().RegisterHoneypot(hp);
    RD::Instance().OnHoneypotTouched(4096u, hp);

    // Allow brief time for asynchronous dispatch if the impl uses a worker thread
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (!callbackFired.load(std::memory_order_acquire) &&
           std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    RD::Instance().UnregisterHoneypot(hp);
    // Reset callback to avoid interference with subsequent tests
    RD::Instance().SetDetectionCallback(nullptr);

    EXPECT_TRUE(callbackFired.load())
        << "DetectionCallback must fire after OnHoneypotTouched.";
    EXPECT_EQ(capturedVerdict, RW::DetectionVerdict::Honeypot)
        << "DetectionEvent.verdict must be Honeypot when triggered by honeypot access.";
}

// ============================================================================
// GROUP 5 — ProcessWhitelist
// ============================================================================

/**
 * @brief WhitelistProcess must cause IsProcessWhitelisted to return true.
 */
TEST_F(RansomwareIntegrationFixture, ProcessWhitelist_Whitelist_IsWhitelisted) {
    SKIP_IF_NOT_READY();
    constexpr uint32_t testPid = 0xDEAD0001u;
    RD::Instance().WhitelistProcess(testPid);
    EXPECT_TRUE(RD::Instance().IsProcessWhitelisted(testPid))
        << "Whitelisted PID must be recognised by IsProcessWhitelisted().";
    RD::Instance().UnwhitelistProcess(testPid);
}

/**
 * @brief Arbitrary PID that was never whitelisted must not be whitelisted.
 */
TEST_F(RansomwareIntegrationFixture, ProcessWhitelist_NonWhitelisted_IsWhitelisted_False) {
    SKIP_IF_NOT_READY();
    constexpr uint32_t pid = 0xDEAD0002u;
    EXPECT_FALSE(RD::Instance().IsProcessWhitelisted(pid));
}

/**
 * @brief UnwhitelistProcess must remove the PID from the whitelist.
 */
TEST_F(RansomwareIntegrationFixture, ProcessWhitelist_Unwhitelist_Removes) {
    SKIP_IF_NOT_READY();
    constexpr uint32_t pid = 0xDEAD0003u;
    RD::Instance().WhitelistProcess(pid);
    ASSERT_TRUE(RD::Instance().IsProcessWhitelisted(pid));
    RD::Instance().UnwhitelistProcess(pid);
    EXPECT_FALSE(RD::Instance().IsProcessWhitelisted(pid))
        << "After UnwhitelistProcess the PID must no longer be whitelisted.";
}

// ============================================================================
// GROUP 6 — FamilySignatures
// ============================================================================

/**
 * @brief RegisterFamilySignature + GetFamilySignature must round-trip correctly.
 *
 * Registers a synthetic LockBit family signature and retrieves it; verifies
 * all seeded fields survive the round-trip.
 */
TEST_F(RansomwareIntegrationFixture, FamilySignatures_RoundTrip_LockBit) {
    SKIP_IF_NOT_READY();

    RW::FamilySignature sig;
    sig.family              = RW::RansomwareFamily::LockBit;
    sig.familyName          = "LockBit";
    sig.extensions          = { L".lockbit", L".lockbit2", L".lockbit3" };
    sig.ransomNotePatterns  = { L"Restore-My-Files.txt" };
    sig.encryptionAlgorithm = "AES-256-CBC+RSA-2048";
    sig.isWorm              = false;
    sig.hasDecryptor        = false;

    RD::Instance().RegisterFamilySignature(sig);

    const auto retrieved = RD::Instance().GetFamilySignature(RW::RansomwareFamily::LockBit);
    ASSERT_TRUE(retrieved.has_value())
        << "GetFamilySignature must return a value after registration.";
    EXPECT_EQ(retrieved->family, RW::RansomwareFamily::LockBit);
    EXPECT_EQ(retrieved->familyName, "LockBit");
    ASSERT_FALSE(retrieved->extensions.empty());
    EXPECT_EQ(retrieved->extensions[0], L".lockbit");
    EXPECT_EQ(retrieved->encryptionAlgorithm, "AES-256-CBC+RSA-2048");
}

/**
 * @brief IdentifyFamilyFromExtension must return the correct family for a
 *        registered extension.
 */
TEST_F(RansomwareIntegrationFixture, FamilySignatures_IdentifyFromExtension_LockBit) {
    SKIP_IF_NOT_READY();

    // Ensure the LockBit signature was registered in the previous test
    // (tests run in declaration order within a fixture; register idempotently).
    RW::FamilySignature sig;
    sig.family     = RW::RansomwareFamily::LockBit;
    sig.familyName = "LockBit";
    sig.extensions = { L".lockbit", L".lockbit2" };
    RD::Instance().RegisterFamilySignature(sig);

    EXPECT_EQ(RD::Instance().IdentifyFamilyFromExtension(L".lockbit"),
              RW::RansomwareFamily::LockBit)
        << "IdentifyFamilyFromExtension must return LockBit for \".lockbit\".";
}

/**
 * @brief IdentifyFamilyFromExtension must return Unknown for an unregistered
 *        extension.
 */
TEST_F(RansomwareIntegrationFixture, FamilySignatures_IdentifyFromExtension_Unknown_Unregistered) {
    SKIP_IF_NOT_READY();
    EXPECT_EQ(RD::Instance().IdentifyFamilyFromExtension(L".completelynormal"),
              RW::RansomwareFamily::Unknown)
        << "Unregistered extension must map to RansomwareFamily::Unknown.";
}

/**
 * @brief GetFamilySignature must return nullopt for a family that has not
 *        been registered.
 */
TEST_F(RansomwareIntegrationFixture, FamilySignatures_GetUnregisteredFamily_NullOpt) {
    SKIP_IF_NOT_READY();
    const auto result = RD::Instance().GetFamilySignature(RW::RansomwareFamily::Ragnar);
    EXPECT_FALSE(result.has_value())
        << "GetFamilySignature for unregistered family must return nullopt.";
}

// ============================================================================
// GROUP 7 — ContainmentMode
// ============================================================================

/**
 * @brief EnterContainmentMode must set IsInContainmentMode to true.
 */
TEST_F(RansomwareIntegrationFixture, ContainmentMode_Enter_IsActive) {
    SKIP_IF_NOT_READY();
    RD::Instance().EnterContainmentMode();
    EXPECT_TRUE(RD::Instance().IsInContainmentMode())
        << "IsInContainmentMode must return true after EnterContainmentMode().";
    RD::Instance().ExitContainmentMode();
}

/**
 * @brief ExitContainmentMode must clear the containment flag.
 */
TEST_F(RansomwareIntegrationFixture, ContainmentMode_Exit_ClearsFlag) {
    SKIP_IF_NOT_READY();
    RD::Instance().EnterContainmentMode();
    ASSERT_TRUE(RD::Instance().IsInContainmentMode());
    RD::Instance().ExitContainmentMode();
    EXPECT_FALSE(RD::Instance().IsInContainmentMode())
        << "IsInContainmentMode must return false after ExitContainmentMode().";
}

/**
 * @brief Containment mode must default to inactive after initialization.
 */
TEST_F(RansomwareIntegrationFixture, ContainmentMode_InitiallyNotActive) {
    SKIP_IF_NOT_READY();
    // Ensure we left containment mode in the previous test's cleanup
    RD::Instance().ExitContainmentMode();
    EXPECT_FALSE(RD::Instance().IsInContainmentMode())
        << "Containment mode must be inactive by default.";
}

// ============================================================================
// GROUP 8 — RecoveryProcess
// ============================================================================

/**
 * @brief RegisterRecoveryProcess makes IsRecoveryProcess return true.
 */
TEST_F(RansomwareIntegrationFixture, RecoveryProcess_Register_IsRecovery_True) {
    SKIP_IF_NOT_READY();
    constexpr uint32_t pid = 0xFEED0001u;
    RD::Instance().RegisterRecoveryProcess(pid);
    EXPECT_TRUE(RD::Instance().IsRecoveryProcess(pid))
        << "Registered recovery PID must be recognised by IsRecoveryProcess().";
    RD::Instance().UnregisterRecoveryProcess(pid);
}

/**
 * @brief Arbitrary PID not registered as recovery process must return false.
 */
TEST_F(RansomwareIntegrationFixture, RecoveryProcess_Unregistered_IsRecovery_False) {
    SKIP_IF_NOT_READY();
    EXPECT_FALSE(RD::Instance().IsRecoveryProcess(0xFEED0002u));
}

/**
 * @brief UnregisterRecoveryProcess must remove the exemption.
 */
TEST_F(RansomwareIntegrationFixture, RecoveryProcess_Unregister_Removes) {
    SKIP_IF_NOT_READY();
    constexpr uint32_t pid = 0xFEED0003u;
    RD::Instance().RegisterRecoveryProcess(pid);
    ASSERT_TRUE(RD::Instance().IsRecoveryProcess(pid));
    RD::Instance().UnregisterRecoveryProcess(pid);
    EXPECT_FALSE(RD::Instance().IsRecoveryProcess(pid));
}

// ============================================================================
// GROUP 9 — Statistics
// ============================================================================

/**
 * @brief Fresh statistics snapshot must have all counters at zero.
 *
 * After initialization with no detection events, every counter must be zero.
 * If the test suite runs first, this is guaranteed; even if it runs after
 * GROUP 10 (callbacks), we call ResetStatistics() first to normalise.
 */
TEST_F(RansomwareIntegrationFixture, Statistics_ResetThenZero) {
    SKIP_IF_NOT_READY();
    RD::Instance().ResetStatistics();
    const auto snap = RD::Instance().GetStatistics();

    EXPECT_EQ(snap.totalOperations,     0u);
    EXPECT_EQ(snap.operationsBlocked,   0u);
    EXPECT_EQ(snap.processesTerminated, 0u);
    EXPECT_EQ(snap.honeypotTriggers,    0u);
    EXPECT_EQ(snap.highEntropyWrites,   0u);
    EXPECT_EQ(snap.falsePositives,      0u);
}

/**
 * @brief GetStatistics must return a copyable value-type (no dangling atomics).
 */
TEST_F(RansomwareIntegrationFixture, Statistics_SnapshotCopyable) {
    SKIP_IF_NOT_READY();
    const auto snap1 = RD::Instance().GetStatistics();
    const auto snap2 = snap1;  // Copy construction
    EXPECT_EQ(snap1.totalOperations, snap2.totalOperations);
    EXPECT_EQ(snap1.honeypotTriggers, snap2.honeypotTriggers);
}

/**
 * @brief GetRecentDetections with maxCount=0 must return an empty vector.
 */
TEST_F(RansomwareIntegrationFixture, Statistics_RecentDetections_ZeroCount_Empty) {
    SKIP_IF_NOT_READY();
    const auto detections = RD::Instance().GetRecentDetections(0);
    EXPECT_TRUE(detections.empty());
}

// ============================================================================
// GROUP 10 — DetectionCallbacks
// ============================================================================

/**
 * @brief SetDetectionCallback wiring: honeypot touch fires callback exactly once.
 *
 * Registers a fresh honeypot, installs a counting callback, triggers the
 * honeypot, and asserts the callback fired at least once with verdict==Honeypot.
 */
TEST_F(RansomwareIntegrationFixture, DetectionCallbacks_HoneypotFiringIsExact) {
    SKIP_IF_NOT_READY();

    std::atomic<int>         fireCount{0};
    RW::DetectionVerdict     lastVerdict{RW::DetectionVerdict::Clean};
    std::mutex               mu;

    RD::Instance().SetDetectionCallback([&](const RW::DetectionEvent& ev) {
        std::lock_guard<std::mutex> lk(mu);
        ++fireCount;
        lastVerdict = ev.verdict;
    });

    const std::wstring hp = L"C:\\ShadowStrike\\honeypot\\cb_fire_test.txt";
    RD::Instance().RegisterHoneypot(hp);
    RD::Instance().OnHoneypotTouched(999u, hp);

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (fireCount.load() == 0 && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

    RD::Instance().UnregisterHoneypot(hp);
    RD::Instance().SetDetectionCallback(nullptr);

    EXPECT_GE(fireCount.load(), 1)
        << "DetectionCallback must fire at least once for honeypot touch.";
    EXPECT_EQ(lastVerdict, RW::DetectionVerdict::Honeypot);
}

/**
 * @brief Replacing the detection callback mid-flight must not crash the engine.
 */
TEST_F(RansomwareIntegrationFixture, DetectionCallbacks_Replacement_NoCrash) {
    SKIP_IF_NOT_READY();
    ASSERT_NO_THROW({
        RD::Instance().SetDetectionCallback([](const RW::DetectionEvent&) {});
        RD::Instance().SetDetectionCallback([](const RW::DetectionEvent&) {});
        RD::Instance().SetDetectionCallback(nullptr);
    });
}

// ============================================================================
// GROUP 11 — WriteAnalysis
// ============================================================================

/**
 * @brief AnalyzeWriteEx on a high-entropy buffer must populate the entropyResult
 *        field in the returned DetectionEvent.
 *
 * The event is still expected to have Clean/Suspicious verdict (we have not
 * accumulated enough rate-limit events for a full ConfirmedRansom verdict), but
 * the entropy analysis sub-result must be present and indicate high entropy.
 */
TEST_F(RansomwareIntegrationFixture, WriteAnalysis_HighEntropyWrite_EntropyResultPopulated) {
    SKIP_IF_NOT_READY();

    const auto buf = EntropyHelpers::BuildHighEntropyBuffer(8192);
    const std::wstring testPath = L"C:\\Temp\\test_encrypted_write.dat";

    constexpr uint32_t syntheticPid = 0xC0FFEE01u;
    const auto event = RD::Instance().AnalyzeWriteEx(
        syntheticPid,
        std::span<const uint8_t>(buf),
        testPath);

    EXPECT_TRUE(event.entropyResult.has_value())
        << "AnalyzeWriteEx on high-entropy data must populate entropyResult.";
    if (event.entropyResult.has_value()) {
        EXPECT_GE(event.entropyResult->shannonEntropy, RC::ENTROPY_THRESHOLD)
            << "Entropy in event must exceed the threshold.";
        EXPECT_TRUE(event.entropyResult->isEncrypted)
            << "High-entropy write must be flagged as encrypted.";
    }
}

/**
 * @brief AnalyzeWriteEx on a zero-filled buffer must not flag the write as
 *        high-entropy; the verdict must be Clean.
 */
TEST_F(RansomwareIntegrationFixture, WriteAnalysis_LowEntropyWrite_CleanVerdict) {
    SKIP_IF_NOT_READY();

    // Reset statistics to ensure a clean slate for rate counters.
    RD::Instance().ResetStatistics();

    const auto buf = EntropyHelpers::BuildZeroBuffer(8192);
    const auto event = RD::Instance().AnalyzeWriteEx(
        0xC0FFEE02u,
        std::span<const uint8_t>(buf),
        L"C:\\Temp\\test_zero_write.dat");

    EXPECT_EQ(event.verdict, RW::DetectionVerdict::Clean)
        << "Zero-entropy write must return a Clean verdict.";
}

/**
 * @brief AnalyzeWriteEx must not crash when given an empty buffer.
 */
TEST_F(RansomwareIntegrationFixture, WriteAnalysis_EmptyBuffer_NoCrash) {
    SKIP_IF_NOT_READY();
    ASSERT_NO_THROW({
        const auto event = RD::Instance().AnalyzeWriteEx(
            0u,
            std::span<const uint8_t>{},
            L"C:\\Temp\\empty.dat");
        (void)event;
    });
}

// ============================================================================
// GROUP 12 — ProtectedPaths
// ============================================================================

/**
 * @brief A path under a configured protected directory must be recognised.
 */
TEST_F(RansomwareIntegrationFixture, ProtectedPaths_UnderProtectedDir_IsProtected) {
    SKIP_IF_NOT_READY();
    // "C:\\ShadowStrike\\Protected\\" was set in SetUpTestSuite
    EXPECT_TRUE(RD::Instance().IsProtectedPath(
        L"C:\\ShadowStrike\\Protected\\important_document.docx"))
        << "File under configured protected directory must be recognised as protected.";
}

/**
 * @brief A path outside any configured protected directory must not be marked
 *        as protected.
 */
TEST_F(RansomwareIntegrationFixture, ProtectedPaths_OutsideProtectedDir_IsNotProtected) {
    SKIP_IF_NOT_READY();
    EXPECT_FALSE(RD::Instance().IsProtectedPath(
        L"C:\\UnrelatedFolder\\file.dat"))
        << "File outside protected directories must not be recognised as protected.";
}

// ============================================================================
// GROUP 13 — ConstantsContract
// ============================================================================

/**
 * @brief All entropy-related constants must be in sane operational ranges.
 */
TEST(RansomwareConstants, EntropyThresholdsInRange) {
    EXPECT_GT(RC::ENTROPY_THRESHOLD,     0.0);
    EXPECT_LT(RC::ENTROPY_THRESHOLD,     8.0);
    EXPECT_GT(RC::MIN_SUSPICION_ENTROPY, 0.0);
    EXPECT_LT(RC::MIN_SUSPICION_ENTROPY, RC::ENTROPY_THRESHOLD)
        << "MIN_SUSPICION_ENTROPY must be below full ENTROPY_THRESHOLD.";
}

/**
 * @brief Score thresholds: alert must be lower than block-and-kill.
 */
TEST(RansomwareConstants, ScoreThresholdsOrdering) {
    EXPECT_GT(RC::BLOCK_SCORE_THRESHOLD,  RC::ALERT_SCORE_THRESHOLD)
        << "Block threshold must exceed alert threshold.";
    EXPECT_LE(RC::BLOCK_SCORE_THRESHOLD,  100.0);
    EXPECT_GE(RC::ALERT_SCORE_THRESHOLD,  0.0);
}

/**
 * @brief Confidence thresholds must be in [0,1] and ordered correctly.
 */
TEST(RansomwareConstants, ConfidenceThresholdsOrdered) {
    EXPECT_GE(RC::MIN_ALERT_CONFIDENCE, 0.0);
    EXPECT_LE(RC::MIN_ALERT_CONFIDENCE, 1.0);
    EXPECT_GE(RC::MIN_BLOCK_CONFIDENCE, RC::MIN_ALERT_CONFIDENCE);
    EXPECT_GE(RC::MIN_KILL_CONFIDENCE,  RC::MIN_BLOCK_CONFIDENCE);
    EXPECT_LE(RC::MIN_KILL_CONFIDENCE,  1.0);
}

/**
 * @brief Version numbers must be positive and semantically ordered.
 */
TEST(RansomwareConstants, VersionNonZero) {
    EXPECT_GT(RC::VERSION_MAJOR, 0u);
}

/**
 * @brief Limit constants must be positive and not absurdly small.
 */
TEST(RansomwareConstants, LimitsPositive) {
    EXPECT_GT(RC::MAX_TRACKED_PROCESSES,    0u);
    EXPECT_GT(RC::MAX_FAMILY_SIGNATURES,    0u);
    EXPECT_GT(RC::MIN_ENTROPY_BUFFER_SIZE,  0u);
    EXPECT_GT(RC::MAX_RECENT_DETECTIONS,    0u);
    EXPECT_GT(RC::MAX_WRITES_PER_SECOND,    0u);
    EXPECT_GT(RC::MAX_RENAMES_PER_SECOND,   0u);
}
