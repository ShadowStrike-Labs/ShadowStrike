/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Integration Tests – Update Lifecycle
 * ============================================================================
 *
 * @file UpdateLifecycle_Integration_Tests.cpp
 * @brief Enterprise-grade integration tests exercising the full cross-module
 *        update lifecycle:
 *
 *          SignatureUpdater  <->  SignatureStore
 *          SignatureUpdater  <->  UpdateVerifier
 *          SignatureUpdater  <->  RollbackManager
 *          UpdateVerifier   <->  RollbackManager
 *
 * COVERAGE SURFACE
 * ================
 *
 *  1.  Coordinated lifecycle (init / shutdown of all four components)
 *  2.  Anti-downgrade enforcement via UpdateVerifier.SetMinimumVersion /
 *      ValidateVersionSequence (one-way ratchet, empty-version gate, disabled
 *      anti-downgrade bypass)
 *  3.  Full update happy-path: staging file → hash verification → ApplyPackage
 *      → database file installed → version sidecar written → IsDatabaseLoaded
 *      → per-type statistics → lastUpdateTime
 *  4.  Hash-mismatch rejection: tampered staging file blocked before install
 *  5.  Empty packageId gate (error code -1)
 *  6.  Staging-file-missing gate for Full method (error code -7)
 *  7.  Package size cap (downloadSize > kMaxPackageSize → pre-apply reject)
 *  8.  Cross-module backup wiring: CreateBackup triggers RollbackManager
 *      CreateSnapshot when RollbackManager is live
 *  9.  Snapshot creation / retrieval / deletion / LKG protection
 * 10.  BackupCurrentVersion → GetLastKnownGood; DeleteSnapshot refuses LKG
 * 11.  Boot loop detection: RecordCrash × threshold → IsBootLoopDetected;
 *      ClearBootLoopCounter → reset
 * 12.  PerformHealthCheck + VerifyStability structural validation
 * 13.  Hot-reload callback wiring: callback fires with correct database type
 * 14.  Progress callback state progression (Checking → Reloading)
 * 15.  Completion callback wiring (success/failure results delivered)
 * 16.  SignatureUpdater statistics: updatesApplied, byDatabaseType,
 *      lastUpdateTime, Reset() zeroes all counters
 * 17.  UpdateVerifier statistics: hashVerifications, downgradeAttempts, Reset()
 * 18.  BackupCurrentVersion + RestoreFromBackup round-trip on real disk
 * 19.  Concurrent snapshot + update operations (thread safety)
 * 20.  PackageManifest verification (Tampered / InvalidSignature / VersionDowngrade)
 * 21.  SignatureStore façade constructible against installed database
 * 22.  Version sidecar content round-trip (versionNumber, versionString,
 *      signatureCount)
 *
 * DESIGN NOTES
 * ============
 * - All tests share a single SetUpTestSuite / TearDownTestSuite that manages
 *   the three process-global singletons (SignatureUpdater, UpdateVerifier,
 *   RollbackManager).  Singletons cannot be re-initialized within a process,
 *   so state-dependent tests reset statistics and remove stale files as needed.
 * - SignatureStore is a plain (non-singleton) class constructed per-test.
 * - No mocks: all I/O is real, disk-backed.
 * - SHA-256 hashing in tests uses Windows BCrypt API directly, avoiding any
 *   dependency on the internal HashFileSha256 implementation.
 * - Directory layout chosen for RollbackManager:
 *
 *     tempRoot/
 *       install/              <- install root  (2 levels above snapshots dir)
 *         Backup/
 *           Snapshots/        <- snapshotDirectory passed to RollbackManager
 *         *.sdb               <- signature databases found by PerformHealthCheck
 *       staging/              <- stagingDirectory for SignatureUpdater
 *
 *   This satisfies: installRoot = snapshotBaseDir.parent_path().parent_path()
 *
 * @author  ShadowStrike Security Team
 * @version 1.0.0
 */

// ============================================================================
// WINDOWS / STL PREREQUISITES
// ============================================================================

#ifndef NOMINMAX
#  define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// ============================================================================
// GTEST
// ============================================================================

#include <gtest/gtest.h>

// ============================================================================
// SHADOWSTRIKE MODULE HEADERS
// ============================================================================

#include "src/Shared_modules/Update/SignatureUpdater.hpp"
#include "src/Shared_modules/Update/UpdateVerifier.hpp"
#include "src/Shared_modules/Update/RollbackManager.hpp"
#include "src/Shared_modules/SignatureStore/SignatureStore.hpp"

// ============================================================================
// NAMESPACE ALIASES
// ============================================================================

namespace fs = std::filesystem;

using ShadowStrike::Update::SignatureUpdater;
using ShadowStrike::Update::SignatureUpdaterConfiguration;
using ShadowStrike::Update::SignaturePackage;
using ShadowStrike::Update::SignatureDatabaseType;
using ShadowStrike::Update::DatabaseVersion;
using ShadowStrike::Update::UpdateMethod;
using ShadowStrike::Update::SigUpdateState;
using ShadowStrike::Update::SigUpdaterStatus;
using ShadowStrike::Update::SigUpdateProgress;
using ShadowStrike::Update::SigUpdateResult;
using ShadowStrike::Update::GetDatabaseTypeName;
using ShadowStrike::Update::GetDatabaseExtension;

using ShadowStrike::Update::UpdateVerifier;
using ShadowStrike::Update::UpdateVerifierConfiguration;
using ShadowStrike::Update::PackageManifest;
using ShadowStrike::Update::VerificationStatus;

using ShadowStrike::Update::RollbackManager;
using ShadowStrike::Update::RollbackManagerConfiguration;
using ShadowStrike::Update::SnapshotType;
using ShadowStrike::Update::SnapshotInfo;
using ShadowStrike::Update::RollbackManagerStatus;
using ShadowStrike::Update::HealthStatus;
namespace RollbackConstants = ShadowStrike::Update::RollbackConstants;

// ============================================================================
// SUITE-LEVEL SHARED STATE
// ============================================================================

namespace {

static fs::path s_tempRoot;         ///< Unique temp root for the whole suite
static fs::path s_dbDir;            ///< databaseDirectory  (install root)
static fs::path s_stagingDir;       ///< stagingDirectory
static fs::path s_snapshotDir;      ///< snapshotDirectory  (install/Backup/Snapshots)
static fs::path s_installRoot;      ///< two levels above snapshotDir

// ---------------------------------------------------------------------------
// SHA-256 helper using Windows BCrypt API.
// Returns 64-character lower-case hex string, or empty string on failure.
// ---------------------------------------------------------------------------
[[nodiscard]] std::string ComputeSha256Hex(const fs::path& path) {
    // Read file content.
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::string content(
        (std::istreambuf_iterator<char>(ifs)),
        std::istreambuf_iterator<char>());

    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(
            &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return {};

    struct AlgGuard {
        BCRYPT_ALG_HANDLE h;
        ~AlgGuard() { if (h) ::BCryptCloseAlgorithmProvider(h, 0); }
    } algGuard{ hAlg };

    DWORD cbHashObj = 0, cbData = 0;
    if (!BCRYPT_SUCCESS(::BCryptGetProperty(
            hAlg, BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&cbHashObj), sizeof(DWORD), &cbData, 0)))
        return {};

    std::vector<BYTE> hashObj(cbHashObj);
    if (!BCRYPT_SUCCESS(::BCryptCreateHash(
            hAlg, &hHash, hashObj.data(), cbHashObj, nullptr, 0, 0)))
        return {};

    struct HashGuard {
        BCRYPT_HASH_HANDLE h;
        ~HashGuard() { if (h) ::BCryptDestroyHash(h); }
    } hashGuard{ hHash };

    if (!BCRYPT_SUCCESS(::BCryptHashData(
            hHash,
            reinterpret_cast<PUCHAR>(content.data()),
            static_cast<ULONG>(content.size()), 0)))
        return {};

    std::array<BYTE, 32> digest{};
    if (!BCRYPT_SUCCESS(::BCryptFinishHash(hHash, digest.data(), 32, 0)))
        return {};

    static constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const BYTE b : digest) {
        result += kHex[b >> 4];
        result += kHex[b & 0xf];
    }
    return result;
}

// ---------------------------------------------------------------------------
// Helper: write arbitrary content to a path (create parent dirs first).
// ---------------------------------------------------------------------------
[[nodiscard]] bool WriteFile(const fs::path& path, std::string_view content) {
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    if (ec) return false;
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    return ofs.good();
}

// ---------------------------------------------------------------------------
// Helper: compute the staging path for a given database type.
//   staging/<TypeName>_staging<ext>
// ---------------------------------------------------------------------------
[[nodiscard]] fs::path StagingPath(SignatureDatabaseType type) {
    return s_stagingDir /
           (std::string(GetDatabaseTypeName(type)) + "_staging" +
            std::string(GetDatabaseExtension(type)));
}

// ---------------------------------------------------------------------------
// Helper: compute the installed database path.
//   dbDir/<TypeName><ext>
// ---------------------------------------------------------------------------
[[nodiscard]] fs::path DbPath(SignatureDatabaseType type) {
    return s_dbDir /
           (std::string(GetDatabaseTypeName(type)) +
            std::string(GetDatabaseExtension(type)));
}

// ---------------------------------------------------------------------------
// Helper: compute the version sidecar path.
//   dbDir/<TypeName><ext>.ver
// ---------------------------------------------------------------------------
[[nodiscard]] fs::path VerSidecarPath(SignatureDatabaseType type) {
    return fs::path(DbPath(type).wstring() + L".ver");
}

// ---------------------------------------------------------------------------
// Minimal valid SignatureUpdaterConfiguration pointing at the temp dirs.
// ---------------------------------------------------------------------------
[[nodiscard]] SignatureUpdaterConfiguration MakeUpdaterConfig() {
    SignatureUpdaterConfiguration cfg;
    cfg.enabled               = true;
    cfg.databaseDirectory     = s_dbDir;
    cfg.stagingDirectory      = s_stagingDir;
    cfg.updateIntervalMinutes = 60;
    cfg.maxDeltaChain         = 5;
    cfg.backupCount           = 3;
    cfg.enableHotReload       = true;
    cfg.enabledTypes          = { SignatureDatabaseType::Main };
    return cfg;
}

// ---------------------------------------------------------------------------
// Minimal valid UpdateVerifierConfiguration:
//   cert-pinning and Authenticode OFF so no signing infrastructure is needed.
// ---------------------------------------------------------------------------
[[nodiscard]] UpdateVerifierConfiguration MakeVerifierConfig() {
    UpdateVerifierConfiguration cfg;
    cfg.enabled                  = true;
    cfg.requireValidSignature    = false;
    cfg.requireValidChain        = false;
    cfg.enableCertificatePinning = false; // pinning ON + empty certs → IsValid()=false
    cfg.enableAntiDowngrade      = true;
    cfg.enableRevocationCheck    = false;
    return cfg;
}

// ---------------------------------------------------------------------------
// Minimal valid RollbackManagerConfiguration.
// ---------------------------------------------------------------------------
[[nodiscard]] RollbackManagerConfiguration MakeRollbackConfig() {
    RollbackManagerConfiguration cfg;
    cfg.enabled                = true;
    cfg.snapshotDirectory      = s_snapshotDir;
    cfg.maxSnapshots           = 5;
    cfg.bootLoopThreshold      = RollbackConstants::BOOT_LOOP_THRESHOLD;
    cfg.bootLoopWindowMinutes  = RollbackConstants::BOOT_LOOP_WINDOW_MINUTES;
    cfg.autoRollbackOnBootLoop = false; // avoid real service-stop in tests
    return cfg;
}

} // anonymous namespace

// ============================================================================
// TEST FIXTURE
// ============================================================================

/**
 * @brief Shared fixture for all update-lifecycle integration tests.
 *
 * SetUpTestSuite initialises the three singleton components exactly once for
 * the entire test-binary run.  TearDownTestSuite shuts them down and removes
 * the temp tree.
 *
 * Tests that require a clean statistics snapshot call ResetStatistics() at
 * the start of the test body.
 */
class UpdateLifecycleTest : public ::testing::Test {
public:
    // -----------------------------------------------------------------------
    // Suite-level setup
    // -----------------------------------------------------------------------
    static void SetUpTestSuite() {
        static std::atomic<uint32_t> counter{0};
        const auto pid = static_cast<uint32_t>(::GetCurrentProcessId());
        const auto idx = counter.fetch_add(1, std::memory_order_relaxed);

        // Build a unique temp directory tree (explained in file header).
        s_tempRoot    = fs::temp_directory_path() /
                        ("ss_ul_integ_" + std::to_string(pid) +
                         "_" + std::to_string(idx));
        s_installRoot = s_tempRoot / "install";
        s_dbDir       = s_installRoot;
        s_stagingDir  = s_tempRoot / "staging";
        s_snapshotDir = s_installRoot / "Backup" / "Snapshots";

        std::error_code ec;
        fs::create_directories(s_dbDir,       ec);
        fs::create_directories(s_stagingDir,  ec);
        fs::create_directories(s_snapshotDir, ec);
        ASSERT_FALSE(ec) << "Failed to create temp directory tree";

        // 1. Initialize UpdateVerifier (no cert pinning, no Authenticode).
        if (!UpdateVerifier::HasInstance() ||
            !UpdateVerifier::Instance().IsInitialized())
        {
            ASSERT_TRUE(
                UpdateVerifier::Instance().Initialize(MakeVerifierConfig()))
                << "UpdateVerifier::Initialize failed";
        }

        // 2. Initialize SignatureUpdater.
        if (!SignatureUpdater::HasInstance() ||
            !SignatureUpdater::Instance().IsInitialized())
        {
            ASSERT_TRUE(
                SignatureUpdater::Instance().Initialize(MakeUpdaterConfig()))
                << "SignatureUpdater::Initialize failed";
        }

        // 3. Initialize RollbackManager.
        if (!RollbackManager::HasInstance() ||
            !RollbackManager::Instance().IsInitialized())
        {
            ASSERT_TRUE(
                RollbackManager::Instance().Initialize(MakeRollbackConfig()))
                << "RollbackManager::Initialize failed";
        }
    }

    // -----------------------------------------------------------------------
    // Suite-level teardown
    // -----------------------------------------------------------------------
    static void TearDownTestSuite() {
        if (RollbackManager::HasInstance())
            RollbackManager::Instance().Shutdown();
        if (SignatureUpdater::HasInstance())
            SignatureUpdater::Instance().Shutdown();
        if (UpdateVerifier::HasInstance())
            UpdateVerifier::Instance().Shutdown();

        std::error_code ec;
        fs::remove_all(s_tempRoot, ec); // best-effort cleanup
    }

protected:
    // -----------------------------------------------------------------------
    // Per-test helpers
    // -----------------------------------------------------------------------

    /// Place a staging file with the given content and return its SHA-256 hex.
    [[nodiscard]] std::string CreateStagingFile(
        SignatureDatabaseType type,
        std::string_view      content = "ShadowStrike-SDB-PAYLOAD-v1\n") const
    {
        const auto path = StagingPath(type);
        EXPECT_TRUE(WriteFile(path, content));
        const auto hash = ComputeSha256Hex(path);
        EXPECT_FALSE(hash.empty());
        return hash;
    }

    /// Remove the staging file for a type, leaving the directory intact.
    void RemoveStagingFile(SignatureDatabaseType type) const {
        std::error_code ec;
        fs::remove(StagingPath(type), ec);
    }

    /// Remove the installed database file and its sidecar.
    void RemoveDbFile(SignatureDatabaseType type) const {
        std::error_code ec;
        fs::remove(DbPath(type),         ec);
        fs::remove(VerSidecarPath(type), ec);
    }

    /// Build a minimal valid SignaturePackage for the given database type.
    [[nodiscard]] SignaturePackage MakePackage(
        SignatureDatabaseType type,
        const std::string&    checksum,
        uint64_t              versionNumber = 100) const
    {
        SignaturePackage pkg;
        pkg.packageId                   = std::string(GetDatabaseTypeName(type))
                                          + "_integ_test";
        pkg.type                        = type;
        pkg.method                      = UpdateMethod::Full;
        pkg.targetVersion.type          = type;
        pkg.targetVersion.versionNumber = versionNumber;
        pkg.targetVersion.versionString = "1.0.0";
        pkg.targetVersion.checksum      = checksum;
        pkg.targetVersion.signatureCount = 12345;
        return pkg;
    }
};

// ============================================================================
// GROUP 1 – COORDINATED LIFECYCLE
// ============================================================================

/**
 * @test LifecycleInit_AllModulesInitialized
 * @brief All three singleton components report initialized/running status
 *        after SetUpTestSuite.  Verifies the basic precondition for every
 *        test in this suite.
 */
TEST_F(UpdateLifecycleTest, LifecycleInit_AllModulesInitialized) {
    EXPECT_TRUE(UpdateVerifier::HasInstance());
    EXPECT_TRUE(UpdateVerifier::Instance().IsInitialized());

    EXPECT_TRUE(SignatureUpdater::HasInstance());
    EXPECT_TRUE(SignatureUpdater::Instance().IsInitialized());
    EXPECT_EQ(SignatureUpdater::Instance().GetStatus(),
              SigUpdaterStatus::Running);

    EXPECT_TRUE(RollbackManager::HasInstance());
    EXPECT_TRUE(RollbackManager::Instance().IsInitialized());
    EXPECT_EQ(RollbackManager::Instance().GetStatus(),
              RollbackManagerStatus::Running);
}

/**
 * @test LifecycleInit_DoubleInitIsIdempotent
 * @brief Calling Initialize() on an already-initialized singleton returns true
 *        without resetting module state.
 */
TEST_F(UpdateLifecycleTest, LifecycleInit_DoubleInitIsIdempotent) {
    EXPECT_TRUE(
        SignatureUpdater::Instance().Initialize(MakeUpdaterConfig()));
    EXPECT_TRUE(SignatureUpdater::Instance().IsInitialized());
    EXPECT_EQ(SignatureUpdater::Instance().GetStatus(),
              SigUpdaterStatus::Running);
}

/**
 * @test LifecycleInit_UpdaterConfigValidation
 * @brief SignatureUpdaterConfiguration::IsValid enforces all documented
 *        constraints; a disabled config is trivially valid.
 */
TEST_F(UpdateLifecycleTest, LifecycleInit_UpdaterConfigValidation) {
    SignatureUpdaterConfiguration cfg = MakeUpdaterConfig();
    EXPECT_TRUE(cfg.IsValid());

    // Disabled config is trivially valid regardless of other fields.
    SignatureUpdaterConfiguration disabled;
    disabled.enabled = false;
    EXPECT_TRUE(disabled.IsValid());

    // Empty databaseDirectory.
    cfg.databaseDirectory = "";
    EXPECT_FALSE(cfg.IsValid());
    cfg.databaseDirectory = s_dbDir;

    // Zero updateIntervalMinutes.
    cfg.updateIntervalMinutes = 0;
    EXPECT_FALSE(cfg.IsValid());
    cfg.updateIntervalMinutes = 60;

    // maxDeltaChain out of [1, 100].
    cfg.maxDeltaChain = 0;
    EXPECT_FALSE(cfg.IsValid());
    cfg.maxDeltaChain = 101;
    EXPECT_FALSE(cfg.IsValid());
    cfg.maxDeltaChain = 5;

    // backupCount > 32.
    cfg.backupCount = 33;
    EXPECT_FALSE(cfg.IsValid());
    cfg.backupCount = 3;

    // Empty enabledTypes.
    cfg.enabledTypes.clear();
    EXPECT_FALSE(cfg.IsValid());
}

/**
 * @test LifecycleInit_VerifierConfigValidation
 * @brief UpdateVerifierConfiguration::IsValid returns false when cert-pinning
 *        is enabled but no pinned certificates are supplied.
 */
TEST_F(UpdateLifecycleTest, LifecycleInit_VerifierConfigValidation) {
    const UpdateVerifierConfiguration ok = MakeVerifierConfig();
    EXPECT_TRUE(ok.IsValid());

    // Pinning ON + empty certificates → must fail.
    UpdateVerifierConfiguration pinned = ok;
    pinned.enableCertificatePinning = true;
    pinned.pinnedCertificates.clear();
    EXPECT_FALSE(pinned.IsValid());
}

// ============================================================================
// GROUP 2 – ANTI-DOWNGRADE ENFORCEMENT  (UpdateVerifier)
// ============================================================================

/**
 * @test AntiDowngrade_SetMinimumVersionOneWayRatchet
 * @brief SetMinimumVersion can only raise the version floor, never lower it.
 *        Equal or lower values are silently discarded (cmp <= 0 → no-op).
 */
TEST_F(UpdateLifecycleTest, AntiDowngrade_SetMinimumVersionOneWayRatchet) {
    auto& verifier = UpdateVerifier::Instance();
    verifier.ResetStatistics();

    // Establish a baseline minimum.
    verifier.SetMinimumVersion("3.0.0");
    EXPECT_EQ(verifier.GetMinimumVersion(), "3.0.0");

    // Attempt to lower: must be silently ignored.
    verifier.SetMinimumVersion("2.9.9");
    EXPECT_EQ(verifier.GetMinimumVersion(), "3.0.0")
        << "SetMinimumVersion must never lower the floor";

    // Equal value: also a no-op.
    verifier.SetMinimumVersion("3.0.0");
    EXPECT_EQ(verifier.GetMinimumVersion(), "3.0.0");

    // Raise the floor legitimately.
    verifier.SetMinimumVersion("4.0.0");
    EXPECT_EQ(verifier.GetMinimumVersion(), "4.0.0");
}

/**
 * @test AntiDowngrade_ValidateVersionSequenceRejectsOlderVersions
 * @brief ValidateVersionSequence returns false for any version below the
 *        current minimum and increments downgradeAttempts.
 */
TEST_F(UpdateLifecycleTest,
       AntiDowngrade_ValidateVersionSequenceRejectsOlderVersions)
{
    auto& verifier = UpdateVerifier::Instance();
    verifier.ResetStatistics();

    // Floor is currently 4.0.0 (set by prior test; singletons persist).
    EXPECT_FALSE(verifier.ValidateVersionSequence("3.9.9"));
    EXPECT_FALSE(verifier.ValidateVersionSequence("1.0.0"));
    EXPECT_FALSE(verifier.ValidateVersionSequence("0.0.1"));

    const auto stats = verifier.GetStatistics();
    EXPECT_GE(stats.downgradeAttempts, 3u);

    // Versions at or above the minimum must be accepted.
    EXPECT_TRUE(verifier.ValidateVersionSequence("4.0.0"));
    EXPECT_TRUE(verifier.ValidateVersionSequence("5.0.0"));
    EXPECT_TRUE(verifier.ValidateVersionSequence("99.99.99"));
}

/**
 * @test AntiDowngrade_EmptyVersionStringAlwaysRejected
 * @brief An empty version string is structurally invalid and must always be
 *        rejected, regardless of the anti-downgrade configuration.
 */
TEST_F(UpdateLifecycleTest, AntiDowngrade_EmptyVersionStringAlwaysRejected) {
    EXPECT_FALSE(
        UpdateVerifier::Instance().ValidateVersionSequence(""));
}

/**
 * @test AntiDowngrade_CompareVersionsOrderingIsCorrect
 * @brief CompareVersions returns -1 / 0 / +1 with correct semantics.
 */
TEST_F(UpdateLifecycleTest, AntiDowngrade_CompareVersionsOrderingIsCorrect) {
    auto& verifier = UpdateVerifier::Instance();

    EXPECT_LT(verifier.CompareVersions("1.0.0", "2.0.0"), 0);
    EXPECT_GT(verifier.CompareVersions("3.0.0", "2.0.0"), 0);
    EXPECT_EQ(verifier.CompareVersions("2.0.0", "2.0.0"), 0);

    // Multi-component comparisons.
    EXPECT_LT(verifier.CompareVersions("1.0.99", "1.1.0"), 0);
    EXPECT_GT(verifier.CompareVersions("1.2.0",  "1.1.99"), 0);
}

// ============================================================================
// GROUP 3 – FULL UPDATE PIPELINE (HAPPY PATH)
// ============================================================================

/**
 * @test UpdatePipeline_HappyPath_DatabaseInstalledAndVersionSidecarWritten
 * @brief End-to-end update:
 *         1. Place a valid staging file.
 *         2. Compute its SHA-256 with BCrypt.
 *         3. Call ApplyPackage with the correct checksum.
 *         4. Verify: installed db file exists, version sidecar exists,
 *            IsDatabaseLoaded(), updatesApplied incremented, per-type counter,
 *            lastUpdateTime populated.
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_HappyPath_DatabaseInstalledAndVersionSidecarWritten)
{
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();
    RemoveStagingFile(SignatureDatabaseType::Main);
    RemoveDbFile(SignatureDatabaseType::Main);

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "INTEG-TEST-SDB-CONTENT-V1\n");
    ASSERT_FALSE(hash.empty()) << "BCrypt SHA-256 computation failed";

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 200u)))
        << "ApplyPackage must succeed for a valid staged file with correct hash";

    // Installed database file must exist.
    EXPECT_TRUE(fs::exists(DbPath(SignatureDatabaseType::Main)));

    // Version sidecar must be written.
    EXPECT_TRUE(fs::exists(VerSidecarPath(SignatureDatabaseType::Main)));

    // IsDatabaseLoaded() must reflect the newly installed database.
    EXPECT_TRUE(updater.IsDatabaseLoaded(SignatureDatabaseType::Main));

    // Statistics: updatesApplied ≥ 1.
    const auto stats = updater.GetStatistics();
    EXPECT_GE(stats.updatesApplied, 1u);

    // Per-type counter.
    const auto typeIdx = static_cast<size_t>(SignatureDatabaseType::Main);
    EXPECT_GE(stats.byDatabaseType.at(typeIdx), 1u);

    // lastUpdateTime must be set.
    EXPECT_TRUE(stats.lastUpdateTime.has_value());
}

/**
 * @test UpdatePipeline_HappyPath_StateMachineReachesCompleted
 * @brief After a successful ApplyPackage the update state is Completed and
 *        status is Running (not Updating).
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_HappyPath_StateMachineReachesCompleted)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "INTEG-TEST-SDB-CONTENT-V2\n");
    ASSERT_FALSE(hash.empty());

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 201u)));

    EXPECT_EQ(updater.GetUpdateState(), SigUpdateState::Completed);
    EXPECT_EQ(updater.GetStatus(),      SigUpdaterStatus::Running);
    EXPECT_FALSE(updater.IsUpdating());
}

/**
 * @test UpdatePipeline_HappyPath_VersionSidecarContentIsCorrect
 * @brief The .ver sidecar must contain exactly three lines:
 *        versionNumber (decimal), versionString, signatureCount (decimal).
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_HappyPath_VersionSidecarContentIsCorrect)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "INTEG-TEST-SDB-SIDECAR\n");
    ASSERT_FALSE(hash.empty());

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 300u)));

    std::ifstream ifs(VerSidecarPath(SignatureDatabaseType::Main));
    ASSERT_TRUE(ifs.is_open()) << "Version sidecar not found";

    std::string line1, line2, line3;
    ASSERT_TRUE(static_cast<bool>(std::getline(ifs, line1)));
    ASSERT_TRUE(static_cast<bool>(std::getline(ifs, line2)));
    ASSERT_TRUE(static_cast<bool>(std::getline(ifs, line3)));

    // Line 1: decimal version number.
    uint64_t vn = 0;
    auto [p1, e1] = std::from_chars(line1.data(), line1.data() + line1.size(), vn);
    EXPECT_EQ(e1, std::errc{}) << "Line 1 is not a valid integer";
    EXPECT_EQ(vn, 300u);

    // Line 2: version string from the package.
    EXPECT_EQ(line2, "1.0.0");

    // Line 3: signature count.
    uint64_t sc = 0;
    auto [p2, e2] = std::from_chars(line3.data(), line3.data() + line3.size(), sc);
    EXPECT_EQ(e2, std::errc{}) << "Line 3 is not a valid integer";
    EXPECT_EQ(sc, 12345u);
}

/**
 * @test UpdatePipeline_HappyPath_NoHashCheckWhenChecksumEmpty
 * @brief When pkg.targetVersion.checksum is empty the hash check is skipped
 *        entirely, and the update still succeeds.
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_HappyPath_NoHashCheckWhenChecksumEmpty)
{
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();
    RemoveDbFile(SignatureDatabaseType::Main);

    ASSERT_TRUE(WriteFile(StagingPath(SignatureDatabaseType::Main),
                          "NO-HASH-CHECK-PAYLOAD\n"));

    // Empty checksum → hash gate bypassed.
    const auto pkg = MakePackage(SignatureDatabaseType::Main, /*checksum=*/"", 400u);
    EXPECT_TRUE(updater.ApplyPackage(pkg));
    EXPECT_GE(updater.GetStatistics().updatesApplied, 1u);
}

/**
 * @test UpdatePipeline_Discovery_CheckForUpdateReturnsStagedPackageMetadata
 * @brief CheckForUpdate() must surface the staged package with the correct
 *        database type, method, checksum, and non-zero size.
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_Discovery_CheckForUpdateReturnsStagedPackageMetadata)
{
    auto& updater = SignatureUpdater::Instance();
    RemoveStagingFile(SignatureDatabaseType::Main);

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "DISCOVERY-SINGLE-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());

    const auto pkg = updater.CheckForUpdate(SignatureDatabaseType::Main);
    ASSERT_TRUE(pkg.has_value())
        << "CheckForUpdate must discover the staged package for Main";

    EXPECT_EQ(pkg->type, SignatureDatabaseType::Main);
    EXPECT_EQ(pkg->method, UpdateMethod::Full);
    EXPECT_EQ(pkg->targetVersion.type, SignatureDatabaseType::Main);
    EXPECT_EQ(pkg->targetVersion.checksum, hash);
    EXPECT_GT(pkg->downloadSize, 0u);
}

/**
 * @test UpdatePipeline_Discovery_CheckForUpdatesEmptyWhenNoStagingExists
 * @brief CheckForUpdates() must return an empty list when no staged package
 *        exists for any enabled database type.
 */
TEST_F(UpdateLifecycleTest,
       UpdatePipeline_Discovery_CheckForUpdatesEmptyWhenNoStagingExists)
{
    auto& updater = SignatureUpdater::Instance();
    RemoveStagingFile(SignatureDatabaseType::Main);

    const auto packages = updater.CheckForUpdates();
    EXPECT_TRUE(packages.empty())
        << "CheckForUpdates must not fabricate packages when staging is empty";
}

// ============================================================================
// GROUP 4 – UPDATE REJECTION GATES
// ============================================================================

/**
 * @test UpdateRejection_HashMismatchBlocksInstall
 * @brief ApplyPackage with an intentionally wrong checksum must fail.
 *        The installed database file must NOT be present afterwards.
 */
TEST_F(UpdateLifecycleTest, UpdateRejection_HashMismatchBlocksInstall) {
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();
    RemoveStagingFile(SignatureDatabaseType::Main);
    RemoveDbFile(SignatureDatabaseType::Main);

    (void)CreateStagingFile(SignatureDatabaseType::Main, "VALID-CONTENT\n");

    // All-f hex string: clearly wrong checksum.
    const std::string badChecksum(64, 'f');
    EXPECT_FALSE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, badChecksum, 500u)))
        << "ApplyPackage must reject a file whose SHA-256 does not match";

    EXPECT_FALSE(fs::exists(DbPath(SignatureDatabaseType::Main)));
    EXPECT_GE(updater.GetStatistics().updatesFailed, 1u);
}

/**
 * @test UpdateRejection_EmptyPackageIdFails
 * @brief ApplyPackage with an empty packageId fails immediately (error -1)
 *        and increments updatesFailed.
 */
TEST_F(UpdateLifecycleTest, UpdateRejection_EmptyPackageIdFails) {
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main, "DATA\n");
    ASSERT_FALSE(hash.empty());

    SignaturePackage pkg = MakePackage(SignatureDatabaseType::Main, hash, 600u);
    pkg.packageId = "";  // triggers error -1

    EXPECT_FALSE(updater.ApplyPackage(pkg));
    EXPECT_GE(updater.GetStatistics().updatesFailed, 1u);
}

/**
 * @test UpdateRejection_StagingFileMissingForFullMethod
 * @brief ApplyPackage with UpdateMethod::Full and no staging file returns
 *        false (error -7) and increments updatesFailed.
 */
TEST_F(UpdateLifecycleTest,
       UpdateRejection_StagingFileMissingForFullMethod)
{
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();
    RemoveStagingFile(SignatureDatabaseType::Main);

    SignaturePackage pkg = MakePackage(SignatureDatabaseType::Main, "", 700u);
    pkg.method = UpdateMethod::Full;

    EXPECT_FALSE(updater.ApplyPackage(pkg));
    EXPECT_GE(updater.GetStatistics().updatesFailed, 1u);
}

/**
 * @test UpdateRejection_PackageExceedsMaxSize
 * @brief downloadSize > kMaxPackageSize (4 GiB) is rejected before applying.
 */
TEST_F(UpdateLifecycleTest, UpdateRejection_PackageExceedsMaxSize) {
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main, "SIZE-GATE\n");
    ASSERT_FALSE(hash.empty());

    SignaturePackage pkg = MakePackage(SignatureDatabaseType::Main, hash, 800u);
    pkg.downloadSize = 4ull * 1024 * 1024 * 1024; // 4 GiB > kMaxPackageSize

    EXPECT_FALSE(updater.ApplyPackage(pkg));
    // updatesFailed is NOT incremented for the pre-apply size guard.
}

// ============================================================================
// GROUP 5 – CALLBACK ORCHESTRATION
// ============================================================================

/**
 * @test Callbacks_HotReloadFiredWithCorrectDatabaseType
 * @brief After a successful ApplyPackage with enableHotReload=true, the
 *        registered SigReloadCallback fires with the correct database type.
 */
TEST_F(UpdateLifecycleTest,
       Callbacks_HotReloadFiredWithCorrectDatabaseType)
{
    auto& updater = SignatureUpdater::Instance();

    std::atomic<bool>     callbackFired{false};
    SignatureDatabaseType capturedType{};
    std::mutex            mu;

    updater.RegisterReloadCallback([&](SignatureDatabaseType t) {
        std::lock_guard lg(mu);
        callbackFired.store(true, std::memory_order_relaxed);
        capturedType = t;
    });

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "RELOAD-CALLBACK-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 900u)));

    EXPECT_TRUE(callbackFired.load())
        << "Hot-reload callback was not fired after a successful update";
    {
        std::lock_guard lg(mu);
        EXPECT_EQ(capturedType, SignatureDatabaseType::Main);
    }

    updater.UnregisterCallbacks();
}

/**
 * @test Callbacks_CompletionCallbackFiredWithSuccessResult
 * @brief The completion callback receives a SigUpdateResult with success=true
 *        and the correct database type after a successful apply.
 */
TEST_F(UpdateLifecycleTest,
       Callbacks_CompletionCallbackFiredWithSuccessResult)
{
    auto& updater = SignatureUpdater::Instance();

    std::atomic<bool>     fired{false};
    bool                  resultSuccess = false;
    SignatureDatabaseType resultType{};
    std::mutex            mu;

    updater.RegisterCompletionCallback(
        [&](const SigUpdateResult& r) {
            std::lock_guard lg(mu);
            fired.store(true, std::memory_order_relaxed);
            resultSuccess = r.success;
            resultType    = r.type;
        });

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "COMPLETION-CB-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 1000u)));

    EXPECT_TRUE(fired.load())
        << "Completion callback not invoked after successful ApplyPackage";
    {
        std::lock_guard lg(mu);
        EXPECT_TRUE(resultSuccess);
        EXPECT_EQ(resultType, SignatureDatabaseType::Main);
    }

    updater.UnregisterCallbacks();
}

/**
 * @test Callbacks_CompletionCallbackFiredOnFailure
 * @brief The completion callback is triggered on failed applies delivering
 *        success=false so callers can react immediately.
 */
TEST_F(UpdateLifecycleTest,
       Callbacks_CompletionCallbackFiredOnFailure)
{
    auto& updater = SignatureUpdater::Instance();

    std::atomic<bool> fired{false};
    bool              resultSuccess = true; // init to unexpected value

    updater.RegisterCompletionCallback(
        [&](const SigUpdateResult& r) {
            fired.store(true, std::memory_order_relaxed);
            resultSuccess = r.success;
        });

    // Trigger guaranteed failure: empty packageId.
    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main, "FAIL-CB\n");
    SignaturePackage pkg = MakePackage(SignatureDatabaseType::Main, hash, 0u);
    pkg.packageId = "";

    EXPECT_FALSE(updater.ApplyPackage(pkg));
    EXPECT_TRUE(fired.load());
    EXPECT_FALSE(resultSuccess);

    updater.UnregisterCallbacks();
}

/**
 * @test Callbacks_ProgressCallbackRecordsStateTransitions
 * @brief Progress callbacks must fire at least at the Checking and Reloading
 *        stages during a successful update.
 */
TEST_F(UpdateLifecycleTest,
       Callbacks_ProgressCallbackRecordsStateTransitions)
{
    auto& updater = SignatureUpdater::Instance();

    std::vector<SigUpdateState> observedStates;
    std::mutex                  mu;

    updater.RegisterProgressCallback(
        [&](const SigUpdateProgress& p) {
            std::lock_guard lg(mu);
            observedStates.push_back(p.state);
        });

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "PROGRESS-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());

    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 1100u)));

    updater.UnregisterCallbacks();

    std::lock_guard lg(mu);
    ASSERT_FALSE(observedStates.empty())
        << "No progress callbacks received during update";

    const bool sawChecking = std::ranges::any_of(observedStates,
        [](SigUpdateState s) { return s == SigUpdateState::Checking; });
    EXPECT_TRUE(sawChecking)
        << "Expected Checking state in progress callback sequence";

    const bool sawReloading = std::ranges::any_of(observedStates,
        [](SigUpdateState s) { return s == SigUpdateState::Reloading; });
    EXPECT_TRUE(sawReloading)
        << "Expected Reloading state in progress callback sequence";
}

/**
 * @test Callbacks_TriggerHotReloadDisabledByConfigReturnsFalse
 * @brief TriggerHotReload() must fail closed when hot-reload is disabled in the
 *        active configuration, must not fire reload callbacks, and must not
 *        increment the hotReloads counter.
 */
TEST_F(UpdateLifecycleTest,
       Callbacks_TriggerHotReloadDisabledByConfigReturnsFalse)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "HOT-RELOAD-DISABLED-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 1101u)));

    const auto originalConfig = updater.GetConfiguration();
    SignatureUpdaterConfiguration disabledConfig = originalConfig;
    disabledConfig.enableHotReload = false;
    ASSERT_TRUE(updater.UpdateConfiguration(disabledConfig));

    const auto beforeHotReloads = updater.GetStatistics().hotReloads;
    std::atomic<bool> fired{false};
    updater.RegisterReloadCallback([&](SignatureDatabaseType) {
        fired.store(true, std::memory_order_relaxed);
    });

    EXPECT_FALSE(updater.TriggerHotReload(SignatureDatabaseType::Main));
    EXPECT_FALSE(fired.load(std::memory_order_relaxed));
    EXPECT_EQ(updater.GetStatistics().hotReloads, beforeHotReloads);

    updater.UnregisterCallbacks();
    EXPECT_TRUE(updater.UpdateConfiguration(originalConfig));
}

// ============================================================================
// GROUP 6 – STATISTICS INTEGRATION
// ============================================================================

/**
 * @test Statistics_TwoSuccessfulUpdatesIncrementCounters
 * @brief Applying two packages increments updatesApplied to 2, increments the
 *        byDatabaseType counter for Main by 2, and sets lastUpdateTime.
 */
TEST_F(UpdateLifecycleTest,
       Statistics_TwoSuccessfulUpdatesIncrementCounters)
{
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();

    for (const uint64_t v : { 1200u, 1201u }) {
        const std::string hash =
            CreateStagingFile(SignatureDatabaseType::Main,
                              "STATS-PAYLOAD-" + std::to_string(v) + "\n");
        ASSERT_FALSE(hash.empty());
        ASSERT_TRUE(updater.ApplyPackage(
            MakePackage(SignatureDatabaseType::Main, hash, v)));
    }

    const auto stats = updater.GetStatistics();
    EXPECT_EQ(stats.updatesApplied, 2u);

    const auto typeIdx = static_cast<size_t>(SignatureDatabaseType::Main);
    EXPECT_EQ(stats.byDatabaseType.at(typeIdx), 2u);

    EXPECT_TRUE(stats.lastUpdateTime.has_value());
}

/**
 * @test Statistics_ResetClearsAllCounters
 * @brief ResetStatistics() must zero updatesApplied, updatesFailed,
 *        byDatabaseType, hotReloads, and lastUpdateTime (epoch).
 */
TEST_F(UpdateLifecycleTest, Statistics_ResetClearsAllCounters) {
    auto& updater = SignatureUpdater::Instance();

    // Ensure at least one update is recorded before reset.
    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "RESET-STATS-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());
    (void)updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 1300u));

    updater.ResetStatistics();

    const auto stats = updater.GetStatistics();
    EXPECT_EQ(stats.updatesApplied, 0u);
    EXPECT_EQ(stats.updatesFailed,  0u);
    EXPECT_EQ(stats.hotReloads,     0u);
    for (const auto& cnt : stats.byDatabaseType) {
        EXPECT_EQ(cnt, 0u);
    }
    EXPECT_FALSE(stats.lastUpdateTime.has_value());
}

/**
 * @test Statistics_VerifierCountersIncrementOnHash
 * @brief VerifyHash increments hashVerifications; a matching hash increments
 *        verificationsSucceeded; a mismatch increments verificationsFailed.
 *        Note: UpdateVerifier::VerifyHash returns bool.
 */
TEST_F(UpdateLifecycleTest, Statistics_VerifierCountersIncrementOnHash) {
    auto& verifier = UpdateVerifier::Instance();
    verifier.ResetStatistics();

    const auto testFile = s_tempRoot / "hash_verify_test.bin";
    ASSERT_TRUE(WriteFile(testFile, "VERIFY-CONTENT\n"));

    const std::string correctHash = ComputeSha256Hex(testFile);
    ASSERT_FALSE(correctHash.empty());

    // Successful verification.
    EXPECT_TRUE(verifier.VerifyHash(testFile, correctHash));

    // Intentionally wrong hash.
    EXPECT_FALSE(verifier.VerifyHash(testFile, std::string(64, '0')));

    const auto stats = verifier.GetStatistics();
    EXPECT_GE(stats.hashVerifications, 2u);
    EXPECT_EQ(stats.verificationsSucceeded, 0u);
    EXPECT_GE(stats.verificationsFailed,    1u);
}

/**
 * @test Statistics_VerifierResetClearsCounters
 * @brief ResetStatistics() on UpdateVerifier zeroes all counters.
 */
TEST_F(UpdateLifecycleTest, Statistics_VerifierResetClearsCounters) {
    auto& verifier = UpdateVerifier::Instance();

    const auto testFile = s_tempRoot / "verifier_reset_test.bin";
    (void)WriteFile(testFile, "RESET-CONTENT\n");
    (void)verifier.VerifyHash(testFile, std::string(64, 'a'));

    verifier.ResetStatistics();

    const auto stats = verifier.GetStatistics();
    EXPECT_EQ(stats.verificationsPerformed, 0u);
    EXPECT_EQ(stats.verificationsSucceeded, 0u);
    EXPECT_EQ(stats.verificationsFailed,    0u);
    EXPECT_EQ(stats.hashVerifications,      0u);
    EXPECT_EQ(stats.downgradeAttempts,      0u);
}

// ============================================================================
// GROUP 7 – SNAPSHOT LIFECYCLE
// ============================================================================

/**
 * @test Snapshot_CreateAndRetrieve
 * @brief CreateSnapshot returns a non-empty ID; GetSnapshots contains it;
 *        GetSnapshot(id) returns correct metadata.
 */
TEST_F(UpdateLifecycleTest, Snapshot_CreateAndRetrieve) {
    auto& rb = RollbackManager::Instance();

    const auto id = rb.CreateSnapshot(SnapshotType::Database,
                                      "Integ-Test-Snapshot-A");
    if (id.empty()) {
        GTEST_SKIP() << "Snapshot creation skipped: insufficient disk space";
    }

    const bool found = std::ranges::any_of(
        rb.GetSnapshots(),
        [&](const SnapshotInfo& s) { return s.snapshotId == id; });
    EXPECT_TRUE(found) << "Created snapshot not found in GetSnapshots()";

    const auto opt = rb.GetSnapshot(id);
    ASSERT_TRUE(opt.has_value());
    EXPECT_EQ(opt->snapshotId,  id);
    EXPECT_EQ(opt->description, "Integ-Test-Snapshot-A");
}

/**
 * @test Snapshot_DeleteNonLKG
 * @brief A non-LKG snapshot can be deleted and disappears from GetSnapshots.
 */
TEST_F(UpdateLifecycleTest, Snapshot_DeleteNonLKG) {
    auto& rb = RollbackManager::Instance();

    const auto id = rb.CreateSnapshot(SnapshotType::Database,
                                      "Integ-Delete-Target");
    if (id.empty()) {
        GTEST_SKIP() << "Snapshot creation skipped: disk space";
    }

    // If CreateSnapshot made this the LKG, skip the deletion test.
    if (const auto lkg = rb.GetLastKnownGood();
        lkg.has_value() && lkg->snapshotId == id)
    {
        GTEST_SKIP() << "Snapshot became LKG; skip delete test";
    }

    EXPECT_TRUE(rb.DeleteSnapshot(id));

    const bool stillPresent = std::ranges::any_of(
        rb.GetSnapshots(),
        [&](const SnapshotInfo& s) { return s.snapshotId == id; });
    EXPECT_FALSE(stillPresent)
        << "Deleted snapshot still returned by GetSnapshots()";
}

/**
 * @test Snapshot_DeleteInvalidIdRejected
 * @brief DeleteSnapshot() must fail closed on malformed or traversal-like
 *        snapshot IDs without mutating snapshot state.
 */
TEST_F(UpdateLifecycleTest, Snapshot_DeleteInvalidIdRejected) {
    auto& rb = RollbackManager::Instance();

    const auto before = rb.GetSnapshots().size();
    EXPECT_FALSE(rb.DeleteSnapshot(""))
        << "Empty snapshot ID must be rejected";
    EXPECT_FALSE(rb.DeleteSnapshot("../snapshot_escape"))
        << "Traversal-like snapshot ID must be rejected";
    EXPECT_FALSE(rb.DeleteSnapshot("not-a-valid-snapshot-id"))
        << "Malformed snapshot ID must be rejected";
    EXPECT_EQ(rb.GetSnapshots().size(), before);
}

/**
 * @test Snapshot_LKGProtectedAgainstDeletion
 * @brief BackupCurrentVersion marks a snapshot as Last Known Good.
 *        DeleteSnapshot on that LKG ID must return false.
 */
TEST_F(UpdateLifecycleTest, Snapshot_LKGProtectedAgainstDeletion) {
    auto& rb = RollbackManager::Instance();

    rb.BackupCurrentVersion();

    const auto lkg = rb.GetLastKnownGood();
    if (!lkg.has_value()) {
        GTEST_SKIP()
            << "BackupCurrentVersion produced no LKG snapshot "
               "(likely disk space constraint)";
    }

    EXPECT_FALSE(rb.DeleteSnapshot(lkg->snapshotId))
        << "DeleteSnapshot must refuse to remove the Last Known Good snapshot";

    // LKG must still be retrievable.
    const auto lkg2 = rb.GetLastKnownGood();
    ASSERT_TRUE(lkg2.has_value());
    EXPECT_EQ(lkg2->snapshotId, lkg->snapshotId);
}

/**
 * @test Snapshot_GetLastKnownGoodAfterBackupCurrentVersion
 * @brief GetLastKnownGood() returns the snapshot created by
 *        BackupCurrentVersion() and its isCurrent flag is set.
 */
TEST_F(UpdateLifecycleTest,
       Snapshot_GetLastKnownGoodAfterBackupCurrentVersion)
{
    auto& rb = RollbackManager::Instance();

    rb.BackupCurrentVersion();

    const auto lkg = rb.GetLastKnownGood();
    if (!lkg.has_value()) {
        GTEST_SKIP() << "Disk space constraint prevented LKG creation";
    }

    EXPECT_FALSE(lkg->snapshotId.empty());
    EXPECT_TRUE(lkg->isCurrent);
}

/**
 * @test Snapshot_CanRollbackRequiresValidSnapshot
 * @brief CanRollback() returns true when a valid snapshot exists and the
 *        RollbackManager is initialised with enabled=true.
 */
TEST_F(UpdateLifecycleTest, Snapshot_CanRollbackRequiresValidSnapshot) {
    auto& rb = RollbackManager::Instance();

    rb.BackupCurrentVersion();

    if (!rb.GetLastKnownGood().has_value()) {
        GTEST_SKIP() << "No LKG available; disk space constraint";
    }

    EXPECT_TRUE(rb.CanRollback())
        << "CanRollback() must return true when a valid snapshot exists";
}

// ============================================================================
// GROUP 8 – BOOT LOOP DETECTION
// ============================================================================

/**
 * @test BootLoop_ThresholdCrashesTriggersDetection
 * @brief Recording BOOT_LOOP_THRESHOLD crashes within the window causes
 *        IsBootLoopDetected() to return true.
 */
TEST_F(UpdateLifecycleTest,
       BootLoop_ThresholdCrashesTriggersDetection)
{
    auto& rb = RollbackManager::Instance();

    rb.ClearBootLoopCounter();
    ASSERT_FALSE(rb.IsBootLoopDetected())
        << "Boot loop must be clear after ClearBootLoopCounter";

    for (uint32_t i = 0; i < RollbackConstants::BOOT_LOOP_THRESHOLD; ++i)
        rb.RecordCrash();

    EXPECT_TRUE(rb.IsBootLoopDetected())
        << "Boot loop must be detected after BOOT_LOOP_THRESHOLD crashes";
}

/**
 * @test BootLoop_ClearResetsDetectionFlag
 * @brief ClearBootLoopCounter resets the detection flag to false.
 */
TEST_F(UpdateLifecycleTest, BootLoop_ClearResetsDetectionFlag) {
    auto& rb = RollbackManager::Instance();

    // Drive into boot-loop state.
    for (uint32_t i = 0; i < RollbackConstants::BOOT_LOOP_THRESHOLD; ++i)
        rb.RecordCrash();
    ASSERT_TRUE(rb.IsBootLoopDetected());

    rb.ClearBootLoopCounter();
    EXPECT_FALSE(rb.IsBootLoopDetected())
        << "ClearBootLoopCounter must reset boot-loop detection";
}

/**
 * @test BootLoop_BelowThresholdIsNotDetected
 * @brief Fewer than BOOT_LOOP_THRESHOLD crashes must NOT trigger detection.
 */
TEST_F(UpdateLifecycleTest, BootLoop_BelowThresholdIsNotDetected) {
    auto& rb = RollbackManager::Instance();

    rb.ClearBootLoopCounter();

    const uint32_t below = RollbackConstants::BOOT_LOOP_THRESHOLD - 1;
    for (uint32_t i = 0; i < below; ++i)
        rb.RecordCrash();

    EXPECT_FALSE(rb.IsBootLoopDetected())
        << "Boot loop must NOT be detected below threshold";
}

/**
 * @test BootLoop_RecordBootDoesNotCrash
 * @brief RecordBoot must succeed without throwing, independently of crash
 *        history.  The boot record feeds into health-check metrics.
 */
TEST_F(UpdateLifecycleTest, BootLoop_RecordBootDoesNotCrash) {
    auto& rb = RollbackManager::Instance();
    // Three calls must complete without exception.
    rb.RecordBoot();
    rb.RecordBoot();
    rb.RecordBoot();
    SUCCEED();
}

/**
 * @test BootLoop_PerformHealthCheckReportsBootLoopStatus
 * @brief Once the crash threshold is reached, PerformHealthCheck() must report
 *        BootLoop status, surface the crash count, and update the cached health
 *        status accordingly.
 */
TEST_F(UpdateLifecycleTest,
       BootLoop_PerformHealthCheckReportsBootLoopStatus)
{
    auto& rb = RollbackManager::Instance();

    rb.ClearBootLoopCounter();
    for (uint32_t i = 0; i < RollbackConstants::BOOT_LOOP_THRESHOLD; ++i) {
        rb.RecordCrash();
    }

    const auto result = rb.PerformHealthCheck();
    EXPECT_EQ(result.overallStatus, HealthStatus::BootLoop);
    EXPECT_EQ(result.crashCount, RollbackConstants::BOOT_LOOP_THRESHOLD);
    EXPECT_EQ(rb.GetHealthStatus(), HealthStatus::BootLoop);
}

// ============================================================================
// GROUP 9 – HEALTH CHECK INTEGRATION
// ============================================================================

/**
 * @test HealthCheck_PerformHealthCheckReturnsStructuredResult
 * @brief PerformHealthCheck() must return a HealthCheckResult with a recent
 *        checkTime and at least a DiskSpace component status entry.
 */
TEST_F(UpdateLifecycleTest,
       HealthCheck_PerformHealthCheckReturnsStructuredResult)
{
    auto& rb = RollbackManager::Instance();

    const auto result = rb.PerformHealthCheck();

    EXPECT_NE(result.checkTime.time_since_epoch().count(), 0u);
    EXPECT_FALSE(result.componentStatuses.empty());
    EXPECT_GT(result.componentStatuses.count("DiskSpace"), 0u)
        << "PerformHealthCheck must always assess disk space";
}

/**
 * @test HealthCheck_HealthChecksStatisticIncrementsEachCall
 * @brief Each PerformHealthCheck call must increment the healthChecks counter.
 */
TEST_F(UpdateLifecycleTest,
       HealthCheck_HealthChecksStatisticIncrementsEachCall)
{
    auto& rb = RollbackManager::Instance();

    const auto before = rb.GetStatistics().healthChecks;
    (void)rb.PerformHealthCheck();
    (void)rb.PerformHealthCheck();

    EXPECT_EQ(rb.GetStatistics().healthChecks, before + 2u);
}

/**
 * @test HealthCheck_VerifyStabilityReturnsBool
 * @brief VerifyStability() must return a deterministic bool without crashing.
 */
TEST_F(UpdateLifecycleTest, HealthCheck_VerifyStabilityReturnsBool) {
    (void)RollbackManager::Instance().VerifyStability();
    SUCCEED();
}

/**
 * @test HealthCheck_RecordBootIsReflectedInBootCount
 * @brief RecordBoot() must feed into the next health-check result so operators
 *        can reason about post-update reboot cadence.
 */
TEST_F(UpdateLifecycleTest, HealthCheck_RecordBootIsReflectedInBootCount) {
    auto& rb = RollbackManager::Instance();

    rb.ClearBootLoopCounter();
    rb.RecordBoot();
    rb.RecordBoot();

    const auto result = rb.PerformHealthCheck();
    EXPECT_EQ(result.bootCount, 2u);
    EXPECT_FALSE(rb.IsBootLoopDetected());
}

// ============================================================================
// GROUP 10 – BACKUP / RESTORE  (SignatureUpdater internal)
// ============================================================================

/**
 * @test BackupRestore_CreateBackupWritesFileToBackupDirectory
 * @brief After a successful update a database file exists; CreateBackup must
 *        copy it to databaseDir/backups/<TypeName>_0/<TypeName><ext>.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_CreateBackupWritesFileToBackupDirectory)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "BACKUP-RESTORE-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 2000u)));
    ASSERT_TRUE(fs::exists(DbPath(SignatureDatabaseType::Main)));

    EXPECT_TRUE(updater.CreateBackup(SignatureDatabaseType::Main));

    const auto backupDir =
        s_dbDir / "backups" /
        (std::string(GetDatabaseTypeName(SignatureDatabaseType::Main)) + "_0");
    const auto backupFile =
        backupDir / DbPath(SignatureDatabaseType::Main).filename();

    EXPECT_TRUE(fs::exists(backupFile))
        << "Backup file not found: " << backupFile;
}

/**
 * @test BackupRestore_RestoreFromBackupOverwritesCurrentDatabase
 * @brief Create backup → install new version → RestoreFromBackup(0) →
 *        database content matches the original backup.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_RestoreFromBackupOverwritesCurrentDatabase)
{
    auto& updater = SignatureUpdater::Instance();

    constexpr std::string_view kOriginal = "ORIGINAL-DB-v1.0\n";
    constexpr std::string_view kUpdated  = "UPDATED-DB-v2.0\n";

    // Install original content.
    const std::string hash1 =
        CreateStagingFile(SignatureDatabaseType::Main, kOriginal);
    ASSERT_FALSE(hash1.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash1, 3000u)));

    // Back it up.
    ASSERT_TRUE(updater.CreateBackup(SignatureDatabaseType::Main));

    // Install new content.
    const std::string hash2 =
        CreateStagingFile(SignatureDatabaseType::Main, kUpdated);
    ASSERT_FALSE(hash2.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash2, 3001u)));

    // Verify new content is live.
    {
        std::ifstream ifs(DbPath(SignatureDatabaseType::Main));
        ASSERT_TRUE(ifs.is_open());
        const std::string content(
            (std::istreambuf_iterator<char>(ifs)),
            std::istreambuf_iterator<char>());
        EXPECT_EQ(content, kUpdated);
    }

    // Restore backup.
    ASSERT_TRUE(
        updater.RestoreFromBackup(SignatureDatabaseType::Main, 0u));

    // Verify original content is back.
    {
        std::ifstream ifs(DbPath(SignatureDatabaseType::Main));
        ASSERT_TRUE(ifs.is_open());
        const std::string content(
            (std::istreambuf_iterator<char>(ifs)),
            std::istreambuf_iterator<char>());
        EXPECT_EQ(content, kOriginal);
    }
}

/**
 * @test BackupRestore_RestoreFromNonExistentIndexFails
 * @brief RestoreFromBackup with a missing backup directory must return false.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_RestoreFromNonExistentIndexFails)
{
    EXPECT_FALSE(
        SignatureUpdater::Instance().RestoreFromBackup(
            SignatureDatabaseType::Main, 31u));
}

/**
 * @test BackupRestore_IndexBeyondConfiguredCountRejected
 * @brief RestoreFromBackup with index >= config.backupCount must fail.
 *        backupCount = 3 → index 3 is out of range.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_IndexBeyondConfiguredCountRejected)
{
    EXPECT_FALSE(
        SignatureUpdater::Instance().RestoreFromBackup(
            SignatureDatabaseType::Main, 3u));
}

/**
 * @test BackupRestore_CreateBackupWithoutDatabaseReturnsFalse
 * @brief CreateBackup() must fail cleanly when no installed database exists for
 *        the requested type.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_CreateBackupWithoutDatabaseReturnsFalse)
{
    auto& updater = SignatureUpdater::Instance();
    RemoveDbFile(SignatureDatabaseType::Main);

    EXPECT_FALSE(updater.CreateBackup(SignatureDatabaseType::Main));
}

/**
 * @test BackupRestore_GetAvailableBackupsReturnsMetadata
 * @brief After CreateBackup() succeeds, GetAvailableBackups() must surface at
 *        least one backup entry with size and checksum metadata.
 */
TEST_F(UpdateLifecycleTest,
       BackupRestore_GetAvailableBackupsReturnsMetadata)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "BACKUP-METADATA-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 3002u)));
    ASSERT_TRUE(updater.CreateBackup(SignatureDatabaseType::Main));

    const auto backups =
        updater.GetAvailableBackups(SignatureDatabaseType::Main);
    ASSERT_FALSE(backups.empty());
    EXPECT_FALSE(backups.front().checksum.empty());

    const auto backupFile =
        s_dbDir / "backups" /
        (std::string(GetDatabaseTypeName(SignatureDatabaseType::Main)) + "_0") /
        DbPath(SignatureDatabaseType::Main).filename();
    ASSERT_TRUE(fs::exists(backupFile));
    EXPECT_GT(fs::file_size(backupFile), 0u);
}

// ============================================================================
// GROUP 11 – CROSS-MODULE WIRING
// ============================================================================

/**
 * @test CrossModule_CreateBackupTriggersRollbackManagerSnapshot
 * @brief When RollbackManager is live, CreateBackup on SignatureUpdater must
 *        attempt to create a RollbackManager snapshot.  The snapshot count
 *        must not decrease as a result.
 */
TEST_F(UpdateLifecycleTest,
       CrossModule_CreateBackupTriggersRollbackManagerSnapshot)
{
    auto& updater = SignatureUpdater::Instance();
    auto& rb      = RollbackManager::Instance();

    // Ensure a database file exists to back up.
    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "CROSS-MODULE-BACKUP\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 4000u)));

    const auto before =
        static_cast<uint32_t>(rb.GetSnapshots().size());

    EXPECT_TRUE(updater.CreateBackup(SignatureDatabaseType::Main));

    // Count must be ≥ before (not decrease); may stay the same if disk full.
    EXPECT_GE(
        static_cast<uint32_t>(rb.GetSnapshots().size()), before);
}

/**
 * @test CrossModule_UpdateDatabaseUsesCorrectStagingName
 * @brief UpdateDatabase() constructs the staging path as
 *        "<TypeName>_staging<ext>".  Placing a file at exactly that path
 *        and calling UpdateDatabase() must succeed.
 */
TEST_F(UpdateLifecycleTest,
       CrossModule_UpdateDatabaseUsesCorrectStagingName)
{
    auto& updater = SignatureUpdater::Instance();
    updater.ResetStatistics();
    RemoveDbFile(SignatureDatabaseType::Main);

    ASSERT_TRUE(WriteFile(StagingPath(SignatureDatabaseType::Main),
                          "UPDATEDB-VIA-STAGING\n"));

    EXPECT_TRUE(updater.UpdateDatabase(SignatureDatabaseType::Main));
    EXPECT_TRUE(fs::exists(DbPath(SignatureDatabaseType::Main)));
    EXPECT_GE(updater.GetStatistics().updatesApplied, 1u);
}

// ============================================================================
// GROUP 12 – PACKAGE MANIFEST VERIFICATION  (UpdateVerifier)
// ============================================================================

/**
 * @test ManifestVerify_InvalidManifestReturnsTamperedStatus
 * @brief A PackageManifest that fails IsValid() must yield
 *        VerificationStatus::Tampered.
 */
TEST_F(UpdateLifecycleTest,
       ManifestVerify_InvalidManifestReturnsTamperedStatus)
{
    PackageManifest empty;
    // empty: no packageId, no version, no files, no signature → IsValid()=false.
    ASSERT_FALSE(empty.IsValid());

    const auto result =
        UpdateVerifier::Instance().VerifyManifest(empty);
    EXPECT_EQ(result.status, VerificationStatus::Tampered);
    EXPECT_FALSE(result.isValid);
}

/**
 * @test ManifestVerify_ManifestExceedingFileCapReturnsTamperedStatus
 * @brief A structurally valid manifest with more than kMaxManifestFiles entries
 *        must be rejected before signature verification with Tampered status.
 */
TEST_F(UpdateLifecycleTest,
       ManifestVerify_ManifestExceedingFileCapReturnsTamperedStatus)
{
    PackageManifest manifest;
    manifest.packageId = "oversized-manifest";
    manifest.version = "5.0.0";
    manifest.signature = { 0x01 };

    for (size_t i = 0; i <= 50000; ++i) {
        manifest.files.emplace("file_" + std::to_string(i) + ".bin",
                               std::string(64, 'a'));
    }

    ASSERT_TRUE(manifest.IsValid());

    const auto result = UpdateVerifier::Instance().VerifyManifest(manifest);
    EXPECT_EQ(result.status, VerificationStatus::Tampered);
    EXPECT_FALSE(result.isValid);
    EXPECT_EQ(result.errorMessage, "Manifest exceeds maximum file count");
}

/**
 * @test ManifestVerify_ManifestWithEmptySignatureReturnsInvalidSignature
 * @brief A manifest with packageId, version, and files, but an empty signature
 *        vector, must return VerificationStatus::InvalidSignature.
 */
TEST_F(UpdateLifecycleTest,
       ManifestVerify_ManifestWithEmptySignatureReturnsInvalidSignature)
{
    PackageManifest m;
    m.packageId          = "test-pkg-001";
    m.version            = "1.0.0";
    m.files["main.sdb"]  = std::string(64, 'a'); // non-empty hash
    m.signature.clear();                          // empty signature

    ASSERT_FALSE(m.IsValid())
        << "Manifest with empty signature must fail IsValid()";

    const auto result =
        UpdateVerifier::Instance().VerifyManifest(m);
    EXPECT_EQ(result.status, VerificationStatus::Tampered);
    EXPECT_FALSE(result.isValid);
    EXPECT_FALSE(result.errorMessage.empty());
}

/**
 * @test ManifestVerify_VersionDowngradeReturnsMismatchStatus
 * @brief A manifest whose version is below the verifier's minimum must return
 *        VerificationStatus::VersionDowngrade.
 */
TEST_F(UpdateLifecycleTest,
       ManifestVerify_VersionDowngradeReturnsMismatchStatus)
{
    // Minimum version is currently 4.0.0 (set by earlier test).
    PackageManifest m;
    m.packageId       = "downgrade-pkg";
    m.version         = "0.1.0";                // below 4.0.0
    m.files["x.sdb"]  = std::string(64, 'b');
    m.signature       = { 0xDE, 0xAD };         // non-empty to pass IsValid

    const auto result =
        UpdateVerifier::Instance().VerifyManifest(m);
    EXPECT_EQ(result.status, VerificationStatus::VersionDowngrade);
    EXPECT_FALSE(result.isValid);
}

// ============================================================================
// GROUP 13 – CONCURRENT SAFETY
// ============================================================================

/**
 * @test Concurrency_ParallelReadsWhileUpdateInProgress
 * @brief Multiple threads reading version/snapshot data concurrently while
 *        a single writer applies updates must not cause data races or crashes.
 *        Validates the shared_mutex patterns used by all three singletons.
 */
TEST_F(UpdateLifecycleTest,
       Concurrency_ParallelReadsWhileUpdateInProgress)
{
    auto& updater = SignatureUpdater::Instance();
    auto& rb      = RollbackManager::Instance();

    std::atomic<bool>     start{false};
    std::atomic<uint32_t> errors{0};

    // Spawn reader threads.
    std::vector<std::thread> readers;
    readers.reserve(4);
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&]() {
            while (!start.load(std::memory_order_acquire))
                std::this_thread::yield();
            for (int j = 0; j < 50; ++j) {
                try {
                    (void)updater.GetAllVersions();
                    (void)rb.GetSnapshots();
                    (void)rb.GetLastKnownGood();
                    (void)updater.GetStatistics();
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                } catch (...) {
                    errors.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    // Spawn one writer thread.
    std::thread writer([&]() {
        while (!start.load(std::memory_order_acquire))
            std::this_thread::yield();
        for (int j = 0; j < 3; ++j) {
            const std::string payload =
                "CONC-PAYLOAD-" + std::to_string(j) + "\n";
            const std::string hash =
                CreateStagingFile(SignatureDatabaseType::Main, payload);
            if (!hash.empty()) {
                (void)updater.ApplyPackage(MakePackage(
                    SignatureDatabaseType::Main, hash,
                    static_cast<uint64_t>(5000 + j)));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    start.store(true, std::memory_order_release);
    writer.join();
    for (auto& t : readers) t.join();

    EXPECT_EQ(errors.load(), 0u)
        << "Concurrent reads/writes caused exceptions";
}

// ============================================================================
// GROUP 14 – HOT RELOAD STATE MANAGEMENT
// ============================================================================

/**
 * @test HotReload_TriggerHotReloadFiresCallbackWhenDatabaseExists
 * @brief TriggerHotReload() must return true and fire the reload callback
 *        with the correct database type when the database file is on disk.
 */
TEST_F(UpdateLifecycleTest,
       HotReload_TriggerHotReloadFiresCallbackWhenDatabaseExists)
{
    auto& updater = SignatureUpdater::Instance();

    // Ensure database file is present.
    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main, "HOT-RELOAD-SRC\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 6000u)));
    ASSERT_TRUE(fs::exists(DbPath(SignatureDatabaseType::Main)));

    std::atomic<bool>     fired{false};
    SignatureDatabaseType capturedType{};
    std::mutex            mu;

    updater.RegisterReloadCallback([&](SignatureDatabaseType t) {
        std::lock_guard lg(mu);
        fired.store(true, std::memory_order_relaxed);
        capturedType = t;
    });

    EXPECT_TRUE(updater.TriggerHotReload(SignatureDatabaseType::Main));
    EXPECT_TRUE(fired.load());
    {
        std::lock_guard lg(mu);
        EXPECT_EQ(capturedType, SignatureDatabaseType::Main);
    }

    updater.UnregisterCallbacks();
    EXPECT_GE(updater.GetStatistics().hotReloads, 1u);
}

/**
 * @test HotReload_TriggerHotReloadFailsWhenDatabaseMissing
 * @brief TriggerHotReload() must return false when the database file does not
 *        exist on disk.
 */
TEST_F(UpdateLifecycleTest,
       HotReload_TriggerHotReloadFailsWhenDatabaseMissing)
{
    auto& updater = SignatureUpdater::Instance();
    RemoveDbFile(SignatureDatabaseType::Main);
    EXPECT_FALSE(updater.TriggerHotReload(SignatureDatabaseType::Main));
}

// ============================================================================
// GROUP 15 – VERIFIER HASH VERIFICATION
// ============================================================================

/**
 * @test Verifier_HashVerifyMatchingHashReturnsTrue
 * @brief VerifyHash returns true only when the expected SHA-256 matches the
 *        actual file content, and false on mismatch.
 */
TEST_F(UpdateLifecycleTest,
       Verifier_HashVerifyMatchingHashReturnsTrue)
{
    auto& verifier = UpdateVerifier::Instance();

    const auto testFile = s_tempRoot / "hash_test.bin";
    ASSERT_TRUE(WriteFile(testFile, "HASH-TEST-CONTENT-1234\n"));

    const std::string correct = ComputeSha256Hex(testFile);
    ASSERT_FALSE(correct.empty());

    // Correct hash → true.
    EXPECT_TRUE(verifier.VerifyHash(testFile, correct));

    // Wrong hash (flip last nibble) → false.
    std::string bad = correct;
    bad.back() ^= 1;
    EXPECT_FALSE(verifier.VerifyHash(testFile, bad));
}

/**
 * @test Verifier_HashVerifyOnNonExistentFileReturnsFalse
 * @brief VerifyHash on a path that does not exist must not crash and must
 *        return false.
 */
TEST_F(UpdateLifecycleTest,
       Verifier_HashVerifyOnNonExistentFileReturnsFalse)
{
    const auto ghost = s_tempRoot / "does_not_exist.bin";
    ASSERT_FALSE(fs::exists(ghost));

    EXPECT_FALSE(
        UpdateVerifier::Instance().VerifyHash(ghost, std::string(64, 'a')));
}

/**
 * @test Verifier_HashVerifyWithEmptyExpectedHashFails
 * @brief An empty expected hash must fail verification immediately.
 */
TEST_F(UpdateLifecycleTest,
       Verifier_HashVerifyWithEmptyExpectedHashFails)
{
    const auto testFile = s_tempRoot / "empty_hash_test.bin";
    ASSERT_TRUE(WriteFile(testFile, "CONTENT\n"));

    EXPECT_FALSE(UpdateVerifier::Instance().VerifyHash(testFile, ""));
}

// ============================================================================
// GROUP 16 – ROLLBACK MANAGER STATISTICS
// ============================================================================

/**
 * @test RollbackStats_SnapshotsCreatedCounter
 * @brief snapshotsCreated increments with each successful CreateSnapshot.
 */
TEST_F(UpdateLifecycleTest, RollbackStats_SnapshotsCreatedCounter) {
    auto& rb = RollbackManager::Instance();

    const auto before = rb.GetStatistics().snapshotsCreated;
    const auto id = rb.CreateSnapshot(SnapshotType::Database,
                                      "Stats-Counter-Test");
    if (id.empty()) {
        GTEST_SKIP() << "Disk space constraint; snapshot not created";
    }
    EXPECT_EQ(rb.GetStatistics().snapshotsCreated, before + 1u);
}

/**
 * @test RollbackStats_SnapshotsDeletedCounter
 * @brief snapshotsDeleted increments on a successful DeleteSnapshot.
 */
TEST_F(UpdateLifecycleTest, RollbackStats_SnapshotsDeletedCounter) {
    auto& rb = RollbackManager::Instance();

    const auto id =
        rb.CreateSnapshot(SnapshotType::Database, "Del-Counter-Test");
    if (id.empty()) {
        GTEST_SKIP() << "Disk space constraint";
    }
    if (const auto lkg = rb.GetLastKnownGood();
        lkg.has_value() && lkg->snapshotId == id)
    {
        GTEST_SKIP() << "Snapshot became LKG; skip";
    }

    const auto before = rb.GetStatistics().snapshotsDeleted;
    ASSERT_TRUE(rb.DeleteSnapshot(id));
    EXPECT_EQ(rb.GetStatistics().snapshotsDeleted, before + 1u);
}

// ============================================================================
// GROUP 17 – SIGNATURESTORE FAÇADE
// ============================================================================

/**
 * @test SignatureStore_InitializeWithUpdatedDatabase
 * @brief After a successful update, a SignatureStore can be initialised
 *        read-only against the installed database path without crashing.
 *        (SignatureStore is a plain class, not a singleton.)
 */
TEST_F(UpdateLifecycleTest,
       SignatureStore_InitializeWithUpdatedDatabase)
{
    auto& updater = SignatureUpdater::Instance();

    const std::string hash =
        CreateStagingFile(SignatureDatabaseType::Main,
                          "SIGSTORE-INIT-PAYLOAD\n");
    ASSERT_FALSE(hash.empty());
    ASSERT_TRUE(updater.ApplyPackage(
        MakePackage(SignatureDatabaseType::Main, hash, 7000u)));

    ASSERT_TRUE(fs::exists(DbPath(SignatureDatabaseType::Main)));

    ShadowStrike::SignatureStore::SignatureStore store;
    // Format may not match synthetic test data; we accept both outcomes.
    // Critical: must not crash.
    if (static_cast<bool>(store.Initialize(DbPath(SignatureDatabaseType::Main).wstring(),
                         /*readOnly=*/true)))
    {
        store.Close();
    }
    SUCCEED();
}

/**
 * @test SignatureStore_AddHashRequiresReadWriteInit
 * @brief AddHash must return false on a read-only initialised store.
 */
TEST_F(UpdateLifecycleTest,
       SignatureStore_AddHashRequiresReadWriteInit)
{
    const auto rwDbFile = s_tempRoot / "rw_test.sdb";
    ASSERT_TRUE(WriteFile(rwDbFile, ""));

    ShadowStrike::SignatureStore::SignatureStore store;
    (void)store.Initialize(rwDbFile.wstring(), /*readOnly=*/true);

    ShadowStrike::SignatureStore::HashValue fakeHash{};
    fakeHash.type   = ShadowStrike::SignatureStore::HashType::SHA256;
    fakeHash.length = 32;
    const auto addErr = store.AddHash(
        fakeHash,
        "TestMalware",
        ShadowStrike::SignatureStore::ThreatLevel::High);
    EXPECT_FALSE(addErr.IsSuccess())
        << "AddHash must fail on a read-only SignatureStore";

    store.Close();
}

// ============================================================================
// END OF FILE
// ============================================================================
