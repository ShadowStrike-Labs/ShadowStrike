/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic ProgramUpdater contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/ProgramUpdater.hpp"
#include "Update_TestUtils.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(ProgramUpdaterTest, HelperNamesAndVersionComparisonRemainStable) {
    EXPECT_EQ(GetComponentTypeName(ComponentType::NetworkDriver), "NetworkDriver");
    EXPECT_EQ(GetUpdateStateName(ProgUpdateState::RollingBack), "RollingBack");
    EXPECT_EQ(GetInstallMethodName(InstallMethod::MoveFileEx), "MoveFileEx");
    EXPECT_EQ(GetRebootRequirementName(RebootRequirement::Immediate), "Immediate");
    EXPECT_EQ(GetComponentTypeName(static_cast<ComponentType>(0xFF)), "Unknown");

    const std::string versionString = ProgramUpdater::GetVersionString();
    EXPECT_TRUE(versionString.starts_with("ProgramUpdater v"));
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 2);

    const ProgramVersion v1{1, 2, 3, 4, "", "", "", ""};
    const ProgramVersion v2{1, 2, 3, 5, "", "", "", ""};
    EXPECT_LT(v1, v2);
    EXPECT_GT(v2, v1);
    EXPECT_EQ(CompareVersions(v1, v2), -1);
    EXPECT_EQ(CompareVersions(v2, v1), 1);
    EXPECT_EQ(CompareVersions(v2, v2), 0);
}

TEST(ProgramUpdaterTest, DtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    ProgramVersion version;
    version.major = 7;
    version.minor = 8;
    version.patch = 9;
    version.build = 10;
    version.versionString = "7.8.9.10";
    version.productName = "ShadowStrike Agent";
    version.fileDescription = "Program Updater";
    version.copyright = "ShadowStrike";

    const json versionJson = json::parse(version.ToJson());
    EXPECT_EQ(versionJson.at("versionString"), "7.8.9.10");
    EXPECT_EQ(versionJson.at("productName"), "ShadowStrike Agent");
    EXPECT_EQ(version.ToString(), "7.8.9.10");

    ComponentInfo component;
    component.type = ComponentType::Service;
    component.displayName = "Service";
    component.fileName = L"service.exe";
    component.installPath = "service.exe";
    component.currentVersion = version;
    component.fileSize = 123456;
    component.fileHash = "cafebabe";
    component.isInstalled = true;
    component.isRunning = true;
    component.requiresElevation = true;
    component.isDriver = false;

    const json componentJson = json::parse(component.ToJson());
    EXPECT_EQ(componentJson.at("type"), "Service");
    EXPECT_EQ(componentJson.at("fileName"), "service.exe");
    EXPECT_TRUE(componentJson.at("requiresElevation").get<bool>());

    ProgramPackage package;
    package.packageId = "program-update";
    package.components = {ComponentType::Service, ComponentType::GUI};
    package.newVersion = version;
    package.packageSize = 16384;
    package.downloadUrl = "https://updates.example/program.pkg";
    package.checksum = "checksum";
    package.installMethod = InstallMethod::ShadowCopy;
    package.rebootRequirement = RebootRequirement::Required;
    package.isMandatory = true;
    package.changelog = {"Fix one", "Fix two"};
    package.dependencies = {"vc-runtime"};

    const json packageJson = json::parse(package.ToJson());
    EXPECT_EQ(packageJson.at("packageId"), "program-update");
    EXPECT_EQ(packageJson.at("installMethod"), "ShadowCopy");
    EXPECT_EQ(packageJson.at("rebootRequirement"), "Required");
    EXPECT_EQ(packageJson.at("componentsCount"), 2);
    EXPECT_EQ(packageJson.at("changelogEntries"), 2);

    ProgUpdateProgress progress;
    progress.state = ProgUpdateState::Replacing;
    progress.progressPercent = 75;
    progress.currentComponent = ComponentType::GUI;
    progress.currentOperation = "Replacing GUI";
    progress.bytesDownloaded = 512;
    progress.totalBytes = 1024;
    progress.componentsCompleted = 1;
    progress.componentsTotal = 2;
    progress.errorMessage = "none";

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_EQ(progressJson.at("state"), "Replacing");
    EXPECT_EQ(progressJson.at("currentComponent"), "GUI");
    EXPECT_EQ(progressJson.at("componentsTotal"), 2);

    ProgUpdateResult result;
    result.success = true;
    result.oldVersion = ProgramVersion{7, 8, 8, 9, "", "", "", ""};
    result.newVersion = version;
    result.updatedComponents = {ComponentType::Service, ComponentType::GUI};
    result.rebootRequired = true;
    result.wasRollback = false;
    result.appliedTime = now;
    result.durationSeconds = 12;

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("success").get<bool>());
    ASSERT_EQ(resultJson.at("updatedComponents").size(), 2u);
    EXPECT_EQ(resultJson.at("updatedComponents")[0], "Service");
    EXPECT_TRUE(resultJson.at("rebootRequired").get<bool>());

    ProgUpdaterStatistics stats;
    stats.updatesApplied = 11;
    stats.updatesFailed = 1;
    stats.rollbacksPerformed = 2;
    stats.driverUpdates = 3;
    stats.serviceRestarts = 4;
    stats.rebootsScheduled = 5;
    stats.bytesDownloaded = 6000;
    stats.lastUpdateTime = now;

    stats.Reset();

    EXPECT_EQ(stats.updatesApplied, 0u);
    EXPECT_EQ(stats.updatesFailed, 0u);
    EXPECT_EQ(stats.bytesDownloaded, 0u);
    EXPECT_FALSE(stats.lastUpdateTime.has_value());

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("updatesApplied"), 0);
    EXPECT_EQ(statsJson.at("rebootsScheduled"), 0);
    EXPECT_FALSE(statsJson.contains("lastUpdateTime"));

    ProgramUpdaterConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.bootLoopThreshold = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.bootLoopWindowMinutes = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxBackupVersions = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST(ProgramUpdaterTest, StringFormattingAndOptionalJsonFieldsRemainDeterministic) {
    ProgramVersion version;
    version.major = 1;
    version.minor = 2;
    version.patch = 3;
    version.build = 4;
    version.versionString = "release-candidate";
    EXPECT_EQ(version.ToString(), "1.2.3.4");

    ProgUpdateProgress progress;
    progress.state = ProgUpdateState::Idle;
    progress.progressPercent = 0;
    progress.bytesDownloaded = 0;
    progress.totalBytes = 0;
    progress.componentsCompleted = 0;
    progress.componentsTotal = 0;

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_FALSE(progressJson.contains("currentComponent"));
    EXPECT_FALSE(progressJson.contains("error"));

    ProgUpdateResult result;
    result.success = false;
    result.appliedTime = std::chrono::system_clock::now();
    result.durationSeconds = 0;

    const json resultJson = json::parse(result.ToJson());
    EXPECT_FALSE(resultJson.contains("error"));
}

TEST(ProgramUpdaterTest, DefaultRuntimeStateAndUninitializedMutatorsFailClosed) {
    auto& updater = ProgramUpdater::Instance();
    updater.Shutdown();

    EXPECT_FALSE(updater.IsInitialized());
    EXPECT_EQ(updater.GetStatus(), ProgUpdaterStatus::Uninitialized);
    EXPECT_EQ(updater.GetUpdateState(), ProgUpdateState::Idle);
    EXPECT_FALSE(updater.IsUpdateInProgress());
    EXPECT_TRUE(updater.GetCurrentVersion().versionString.empty());
    EXPECT_FALSE(updater.GetComponentInfo(ComponentType::Service).has_value());
    EXPECT_EQ(updater.GetProgress().state, ProgUpdateState::Idle);
    EXPECT_FALSE(updater.CheckForUpdate().has_value());

    ProgramUpdaterConfiguration invalidConfig;
    invalidConfig.bootLoopThreshold = 0;
    EXPECT_FALSE(updater.UpdateConfiguration(invalidConfig));
}

TEST(ProgramUpdaterTest, RepeatedInitializePreservesExistingConfiguration) {
    auto& updater = ProgramUpdater::Instance();
    updater.Shutdown();

    ScopedTempDir tempDir(L"program_reinit_");

    ProgramUpdaterConfiguration initialConfig;
    initialConfig.autoUpdate = true;
    initialConfig.allowDriverUpdates = false;
    initialConfig.stagingDirectory = tempDir.Path() / L"stage_a";
    initialConfig.backupDirectory = tempDir.Path() / L"backup_a";
    ASSERT_TRUE(initialConfig.IsValid());
    ASSERT_TRUE(updater.Initialize(initialConfig));

    ProgramUpdaterConfiguration replacementConfig = initialConfig;
    replacementConfig.autoUpdate = false;
    replacementConfig.allowDriverUpdates = true;
    replacementConfig.stagingDirectory = tempDir.Path() / L"stage_b";
    replacementConfig.backupDirectory = tempDir.Path() / L"backup_b";

    ASSERT_TRUE(updater.Initialize(replacementConfig));

    const auto effectiveConfig = updater.GetConfiguration();
    EXPECT_TRUE(effectiveConfig.autoUpdate);
    EXPECT_FALSE(effectiveConfig.allowDriverUpdates);
    EXPECT_EQ(effectiveConfig.stagingDirectory, initialConfig.stagingDirectory);
    EXPECT_EQ(effectiveConfig.backupDirectory, initialConfig.backupDirectory);

    updater.Shutdown();
}

}  // namespace ShadowStrike::Update::Test
