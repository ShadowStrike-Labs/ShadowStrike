/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic SignatureUpdater contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>
#include <limits>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "../../../src/Shared_modules/Update/SignatureUpdater.hpp"
#include "Update_TestUtils.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(SignatureUpdaterTest, HelperNamesExtensionsAndDeltaPathRemainStable) {
    EXPECT_EQ(GetDatabaseTypeName(SignatureDatabaseType::Behavioral), "Behavioral");
    EXPECT_EQ(GetUpdateStateName(SigUpdateState::Reloading), "Reloading");
    EXPECT_EQ(GetUpdateMethodName(UpdateMethod::Incremental), "Incremental");
    EXPECT_EQ(GetDatabaseExtension(SignatureDatabaseType::Emergency), ".edb");
    EXPECT_EQ(GetDatabaseTypeName(static_cast<SignatureDatabaseType>(0xFF)), "Unknown");
    EXPECT_EQ(GetDatabaseExtension(static_cast<SignatureDatabaseType>(0xFF)), ".dat");

    const std::vector<DeltaPatchInfo> patches = {
        DeltaPatchInfo{"p12", 1, 2, 10, "12", "a", {}},
        DeltaPatchInfo{"p24", 2, 4, 10, "24", "b", {}},
        DeltaPatchInfo{"p14", 1, 4, 20, "14", "c", {}},
        DeltaPatchInfo{"p43", 4, 3, 5, "43", "d", {}}
    };

    const auto direct = CalculateDeltaPath(1, 4, patches);
    ASSERT_EQ(direct.size(), 1u);
    EXPECT_EQ(direct.front().patchId, "p14");

    EXPECT_TRUE(CalculateDeltaPath(4, 1, patches).empty());
    EXPECT_TRUE(CalculateDeltaPath(4, 4, patches).empty());
}

TEST(SignatureUpdaterTest, DtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    DatabaseVersion version;
    version.type = SignatureDatabaseType::YARA;
    version.versionNumber = 42;
    version.versionString = "2026.04.08";
    version.signatureCount = 5000;
    version.sizeBytes = 16384;
    version.buildDate = now;
    version.releaseDate = now;
    version.checksum = "bead";

    const json versionJson = json::parse(version.ToJson());
    EXPECT_EQ(versionJson.at("typeName"), "YARA");
    EXPECT_EQ(versionJson.at("versionNumber"), 42);

    DeltaPatchInfo patch;
    patch.patchId = "delta-42";
    patch.fromVersion = 40;
    patch.toVersion = 42;
    patch.patchSize = 2048;
    patch.downloadUrl = "https://updates.example/yara.delta";
    patch.checksum = "patchsum";
    patch.signature = {0xAA, 0xBB, 0xCC};

    const json patchJson = json::parse(patch.ToJson());
    EXPECT_EQ(patchJson.at("patchId"), "delta-42");
    EXPECT_EQ(patchJson.at("signatureLength"), 3);

    SignaturePackage package;
    package.packageId = "yara-update";
    package.type = SignatureDatabaseType::YARA;
    package.method = UpdateMethod::Delta;
    package.targetVersion = version;
    package.downloadSize = 1024;
    package.downloadUrl = "https://updates.example/yara.pkg";
    package.deltaPatches = {patch};
    package.isMandatory = true;
    package.releaseNotes = "rule refresh";

    const json packageJson = json::parse(package.ToJson());
    EXPECT_EQ(packageJson.at("packageId"), "yara-update");
    EXPECT_EQ(packageJson.at("typeName"), "YARA");
    EXPECT_EQ(packageJson.at("methodName"), "Delta");
    EXPECT_TRUE(packageJson.at("isMandatory").get<bool>());
    ASSERT_EQ(packageJson.at("deltaPatches").size(), 1u);

    SigUpdateProgress progress;
    progress.type = SignatureDatabaseType::Hashes;
    progress.state = SigUpdateState::Patching;
    progress.progressPercent = 90;
    progress.currentOperation = "Applying patch";
    progress.bytesDownloaded = 4096;
    progress.totalBytes = 8192;
    progress.speedBps = 256;
    progress.etaSeconds = 3;
    progress.errorMessage = "transient";

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_EQ(progressJson.at("typeName"), "Hashes");
    EXPECT_EQ(progressJson.at("stateName"), "Patching");
    EXPECT_EQ(progressJson.at("progressPercent"), 90);

    SigUpdateResult result;
    result.success = true;
    result.type = SignatureDatabaseType::Main;
    result.oldVersion = DatabaseVersion{SignatureDatabaseType::Main, 41, "41", 10, 100, now, now, "old"};
    result.newVersion = DatabaseVersion{SignatureDatabaseType::Main, 42, "42", 20, 200, now, now, "new"};
    result.methodUsed = UpdateMethod::Rollup;
    result.bytesDownloaded = 8192;
    result.durationSeconds = 30;
    result.appliedTime = now;

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("success").get<bool>());
    EXPECT_EQ(resultJson.at("methodName"), "Rollup");
    EXPECT_EQ(resultJson.at("bytesDownloaded"), 8192);

    SigUpdaterStatistics stats;
    stats.updatesApplied = 5;
    stats.updatesFailed = 1;
    stats.deltaPatchesApplied = 4;
    stats.fullDownloads = 2;
    stats.bytesDownloaded = 999;
    stats.bytesSaved = 111;
    stats.hotReloads = 3;
    stats.byDatabaseType[static_cast<size_t>(SignatureDatabaseType::Main)] = 7;
    stats.lastUpdateTime = now;

    stats.Reset();

    EXPECT_EQ(stats.updatesApplied, 0u);
    EXPECT_EQ(stats.bytesDownloaded, 0u);
    EXPECT_EQ(stats.hotReloads, 0u);
    EXPECT_FALSE(stats.lastUpdateTime.has_value());

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("updatesApplied"), 0);
    EXPECT_TRUE(statsJson.at("byDatabaseType").is_array());
    EXPECT_FALSE(statsJson.contains("lastUpdateTime"));

    SignatureUpdaterConfiguration config;
    config.databaseDirectory = "db";
    config.stagingDirectory = "stage";
    EXPECT_TRUE(config.IsValid());

    config.updateIntervalMinutes = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.databaseDirectory = "db";
    config.stagingDirectory = "stage";
    config.maxDeltaChain = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.databaseDirectory = "db";
    config.stagingDirectory = "stage";
    config.enabledTypes.clear();
    EXPECT_FALSE(config.IsValid());
}

TEST(SignatureUpdaterTest, DeltaPathSelectionAndDisabledConfigurationRemainDeterministic) {
    const std::vector<DeltaPatchInfo> patches = {
        DeltaPatchInfo{"p12", 1, 2, 10, "12", "a", {}},
        DeltaPatchInfo{"p25", 2, 5, 10, "25", "b", {}},
        DeltaPatchInfo{"p13", 1, 3, 10, "13", "c", {}},
        DeltaPatchInfo{"p35", 3, 5, 10, "35", "d", {}},
        DeltaPatchInfo{"p55", 5, 5, 1, "55", "e", {}}
    };

    const auto shortest = CalculateDeltaPath(1, 5, patches);
    ASSERT_EQ(shortest.size(), 2u);
    EXPECT_EQ(shortest[0].patchId, "p12");
    EXPECT_EQ(shortest[1].patchId, "p25");
    EXPECT_TRUE(CalculateDeltaPath(5, 6, patches).empty());

    SignatureUpdaterConfiguration disabledConfig;
    disabledConfig.enabled = false;
    EXPECT_TRUE(disabledConfig.IsValid());
}

TEST(SignatureUpdaterTest, RuntimeDefaultsAndInitializedNoWorkPathsRemainSafe) {
    auto& updater = SignatureUpdater::Instance();
    updater.Shutdown();

    EXPECT_FALSE(updater.IsInitialized());
    EXPECT_EQ(updater.GetStatus(), SigUpdaterStatus::Uninitialized);
    EXPECT_EQ(updater.GetUpdateState(), SigUpdateState::Idle);
    EXPECT_FALSE(updater.IsUpdating());
    EXPECT_EQ(updater.GetCurrentVersion(), "0.0.0");
    EXPECT_EQ(updater.GetDatabaseVersion(SignatureDatabaseType::Patterns).type,
              SignatureDatabaseType::Patterns);
    EXPECT_FALSE(updater.GetProgress().has_value());
    EXPECT_TRUE(updater.GetAllProgress().empty());
    EXPECT_TRUE(updater.CheckForUpdates().empty());
    EXPECT_FALSE(updater.CheckForUpdate(SignatureDatabaseType::Main).has_value());

    ScopedTempDir tempDir(L"signature_runtime_");
    SignatureUpdaterConfiguration config;
    config.databaseDirectory = tempDir.Path() / L"db";
    config.stagingDirectory = tempDir.Path() / L"stage";
    config.enabledTypes = {SignatureDatabaseType::Main};
    config.enableHotReload = true;
    ASSERT_TRUE(config.IsValid());
    ASSERT_TRUE(updater.Initialize(config));

    EXPECT_TRUE(updater.IsInitialized());
    EXPECT_EQ(updater.GetStatus(), SigUpdaterStatus::Running);
    EXPECT_EQ(updater.GetCurrentVersion(), "0");
    EXPECT_FALSE(updater.IsDatabaseLoaded(SignatureDatabaseType::Main));
    EXPECT_FALSE(updater.GetProgress().has_value());
    EXPECT_TRUE(updater.CheckForUpdates().empty());
    EXPECT_FALSE(updater.CheckForUpdate(SignatureDatabaseType::Main).has_value());
    EXPECT_FALSE(updater.TriggerHotReload(SignatureDatabaseType::Main));
    EXPECT_FALSE(updater.CreateBackup(SignatureDatabaseType::Main));
    EXPECT_FALSE(updater.UpdateDatabase(SignatureDatabaseType::Main));

    SignaturePackage oversized;
    oversized.packageId = "oversized";
    oversized.type = SignatureDatabaseType::Main;
    oversized.downloadSize = std::numeric_limits<uint64_t>::max();
    EXPECT_FALSE(updater.ApplyPackage(oversized));

    SignatureUpdaterConfiguration invalidConfig = config;
    invalidConfig.maxDeltaChain = 0;
    EXPECT_FALSE(updater.UpdateConfiguration(invalidConfig));

    updater.Shutdown();
}

}  // namespace ShadowStrike::Update::Test
