/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic RollbackManager contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/RollbackManager.hpp"
#include "Update_TestUtils.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(RollbackManagerTest, HelperNamesSnapshotIdsAndSizeAccountingRemainStable) {
    EXPECT_EQ(GetSnapshotTypeName(SnapshotType::Emergency), "Emergency");
    EXPECT_EQ(GetRollbackStateName(RollbackState::RestoringDrivers), "RestoringDrivers");
    EXPECT_EQ(GetHealthStatusName(HealthStatus::Critical), "Critical");
    EXPECT_EQ(GetComponentHealthName(ComponentHealth::Corrupted), "Corrupted");
    EXPECT_EQ(GetSnapshotTypeName(static_cast<SnapshotType>(0xFF)), "Unknown");

    const std::string versionString = RollbackManager::GetVersionString();
    EXPECT_FALSE(versionString.empty());
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 2);

    const std::string firstId = GenerateSnapshotId();
    const std::string secondId = GenerateSnapshotId();
    EXPECT_NE(firstId, secondId);
    EXPECT_GE(firstId.size(), 20u);
    EXPECT_NE(firstId.find('-'), std::string::npos);

    ScopedTempDir tempDir(L"rollback_size_");
    WriteAllBytes(tempDir.File(L"one.bin"), std::vector<uint8_t>{1, 2, 3});
    std::filesystem::create_directories(tempDir.Path() / "nested");
    WriteAllBytes(tempDir.Path() / "nested" / "two.bin", std::vector<uint8_t>{4, 5, 6, 7, 8});
    EXPECT_EQ(CalculateSnapshotSize(tempDir.Path()), 8u);
}

TEST(RollbackManagerTest, DtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    SnapshotInfo snapshot;
    snapshot.snapshotId = "snap-1";
    snapshot.type = SnapshotType::Database;
    snapshot.createdTime = now;
    snapshot.versionString = "3.0.0";
    snapshot.description = "pre-update";
    snapshot.sizeBytes = 4096;
    snapshot.fileCount = 12;
    snapshot.snapshotPath = "Snapshots/current";
    snapshot.isCurrent = true;
    snapshot.isValid = true;

    const json snapshotJson = json::parse(snapshot.ToJson());
    EXPECT_EQ(snapshotJson.at("snapshotId"), "snap-1");
    EXPECT_EQ(snapshotJson.at("type"), "Database");
    EXPECT_EQ(snapshotJson.at("fileCount"), 12);

    HealthCheckResult health;
    health.overallStatus = HealthStatus::Degraded;
    health.componentStatuses = {
        {"Service", ComponentHealth::Running},
        {"Driver", ComponentHealth::Corrupted}
    };
    health.serviceRunning = true;
    health.guiAccessible = false;
    health.databasesValid = true;
    health.networkConnected = true;
    health.selfTestPassed = false;
    health.bootCount = 2;
    health.crashCount = 1;
    health.checkTime = now;
    health.issues = {"driver mismatch"};

    const json healthJson = json::parse(health.ToJson());
    EXPECT_EQ(healthJson.at("overallStatus"), "Degraded");
    EXPECT_EQ(healthJson.at("issues").size(), 1u);
    EXPECT_EQ(healthJson.at("components").at("Driver"), "Corrupted");

    RollbackProgress progress;
    progress.state = RollbackState::RestoringFiles;
    progress.progressPercent = 33;
    progress.currentOperation = "Restoring binaries";
    progress.filesRestored = 2;
    progress.filesTotal = 6;
    progress.errorMessage = "none";

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_EQ(progressJson.at("state"), "RestoringFiles");
    EXPECT_EQ(progressJson.at("filesRestored"), 2);

    RollbackResult result;
    result.success = true;
    result.snapshotId = "snap-1";
    result.restoredVersion = "2.9.9";
    result.filesRestored = 12;
    result.durationSeconds = 44;
    result.rebootRequired = true;
    result.errorMessage = "";
    result.completionTime = now;

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("success").get<bool>());
    EXPECT_EQ(resultJson.at("restoredVersion"), "2.9.9");
    EXPECT_TRUE(resultJson.at("rebootRequired").get<bool>());

    RollbackStatistics stats;
    stats.snapshotsCreated = 5;
    stats.snapshotsDeleted = 1;
    stats.rollbacksPerformed = 2;
    stats.rollbacksFailed = 1;
    stats.bootLoopsDetected = 3;
    stats.autoRollbacks = 1;
    stats.healthChecks = 9;

    stats.Reset();

    EXPECT_EQ(stats.snapshotsCreated, 0u);
    EXPECT_EQ(stats.rollbacksPerformed, 0u);
    EXPECT_EQ(stats.healthChecks, 0u);

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("snapshotsCreated"), 0);
    EXPECT_EQ(statsJson.at("healthChecks"), 0);
    EXPECT_GE(statsJson.at("uptimeSeconds").get<int64_t>(), 0);

    RollbackManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxSnapshots = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.bootLoopThreshold = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.bootLoopWindowMinutes = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.healthCheckTimeoutSeconds = 301;
    EXPECT_FALSE(config.IsValid());
}

TEST(RollbackManagerTest, ConfigurationUpperBoundsAndMissingPathsRemainDeterministic) {
    RollbackManagerConfiguration config;
    config.maxSnapshots = 100;
    config.bootLoopThreshold = 50;
    config.bootLoopWindowMinutes = 1440;
    config.healthCheckTimeoutSeconds = 300;
    EXPECT_TRUE(config.IsValid());

    config.maxSnapshots = 101;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.bootLoopThreshold = 51;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.bootLoopWindowMinutes = 1441;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.healthCheckTimeoutSeconds = 301;
    EXPECT_FALSE(config.IsValid());

    ScopedTempDir tempDir(L"rollback_missing_");
    EXPECT_EQ(CalculateSnapshotSize(tempDir.Path() / "missing"), 0u);
}

}  // namespace ShadowStrike::Update::Test
