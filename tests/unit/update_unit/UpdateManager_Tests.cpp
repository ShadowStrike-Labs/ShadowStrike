/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic UpdateManager contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/UpdateManager.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(UpdateManagerTest, HelperNamesVersionParsingAndFormattingRemainStable) {
    EXPECT_EQ(GetStatusName(UpdateStatus::RollingBack), "RollingBack");
    EXPECT_EQ(GetUpdateTypeName(UpdateType::Emergency), "Emergency");
    EXPECT_EQ(GetPriorityName(UpdatePriority::Critical), "Critical");
    EXPECT_EQ(GetChannelName(UpdateChannel::Enterprise), "Enterprise");
    EXPECT_EQ(GetDownloadStateName(DownloadState::Cancelled), "Cancelled");
    EXPECT_EQ(GetStatusName(static_cast<UpdateStatus>(0xFF)), "Unknown");

    const std::string versionString = UpdateManager::GetVersionString();
    EXPECT_FALSE(versionString.empty());
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 2);

    const auto parsed = ParseVersionString("3.14.159.26");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->major, 3);
    EXPECT_EQ(parsed->minor, 14);
    EXPECT_EQ(parsed->patch, 159);
    EXPECT_EQ(parsed->build, 26u);

    const auto parsedShort = ParseVersionString("5.6.7");
    ASSERT_TRUE(parsedShort.has_value());
    EXPECT_EQ(parsedShort->build, 0u);

    EXPECT_FALSE(ParseVersionString("").has_value());

    const VersionInfo oldVersion{1, 2, 3, 4, "", std::chrono::system_clock::now()};
    const VersionInfo newVersion{1, 2, 4, 0, "", std::chrono::system_clock::now()};
    EXPECT_LT(oldVersion, newVersion);
    EXPECT_GT(newVersion, oldVersion);
    EXPECT_EQ(CompareVersions(oldVersion, newVersion), -1);
    EXPECT_EQ(CompareVersions(newVersion, oldVersion), 1);
    EXPECT_EQ(CompareVersions(newVersion, newVersion), 0);

    EXPECT_EQ(FormatDownloadSize(0), "0 B");
    EXPECT_EQ(FormatDownloadSize(1536), "1.5 KB");
    EXPECT_EQ(FormatDownloadSize(2ull * 1024ull * 1024ull), "2.00 MB");
}

TEST(UpdateManagerTest, DtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    VersionInfo version;
    version.major = 3;
    version.minor = 1;
    version.patch = 4;
    version.build = 159;
    version.versionString = "3.1.4-enterprise";
    version.releaseDate = now;

    const json versionJson = json::parse(version.ToJson());
    EXPECT_EQ(versionJson.at("major"), 3);
    EXPECT_EQ(versionJson.at("versionString"), "3.1.4-enterprise");
    EXPECT_EQ(version.ToString(), "3.1.4-enterprise");

    UpdatePackage package;
    package.packageId = "engine-hotfix";
    package.type = UpdateType::Engine;
    package.priority = UpdatePriority::Emergency;
    package.currentVersion = VersionInfo{3, 1, 3, 0, "3.1.3", now};
    package.newVersion = version;
    package.packageSize = 4096;
    package.downloadSize = 1024;
    package.downloadUrl = "https://updates.example/engine.pkg";
    package.checksum = "deadbeef";
    package.releaseNotes = "critical-fix";
    package.isDelta = true;
    package.requiresReboot = true;
    package.isMandatory = true;

    const json packageJson = json::parse(package.ToJson());
    EXPECT_EQ(packageJson.at("packageId"), "engine-hotfix");
    EXPECT_EQ(packageJson.at("type"), "Engine");
    EXPECT_EQ(packageJson.at("priority"), "Emergency");
    EXPECT_TRUE(packageJson.at("isMandatory").get<bool>());

    DownloadProgress progress;
    progress.packageId = "engine-hotfix";
    progress.state = DownloadState::Downloading;
    progress.bytesDownloaded = 600;
    progress.totalBytes = 1200;
    progress.progressPercent = 50;
    progress.speedBps = 300;
    progress.etaSeconds = 2;
    progress.startTime = now;
    progress.retryCount = 1;
    progress.errorMessage = "temporary";

    const json progressJson = json::parse(progress.ToJson());
    EXPECT_EQ(progressJson.at("state"), "Downloading");
    EXPECT_EQ(progressJson.at("progressPercent"), 50);
    EXPECT_EQ(progressJson.at("retryCount"), 1);

    UpdateResult result;
    result.success = true;
    result.type = UpdateType::Program;
    result.oldVersion = VersionInfo{3, 1, 3, 0, "3.1.3", now};
    result.newVersion = version;
    result.appliedTime = now;
    result.requiresReboot = false;
    result.wasRollback = false;

    const json resultJson = json::parse(result.ToJson());
    EXPECT_TRUE(resultJson.at("success").get<bool>());
    EXPECT_EQ(resultJson.at("type"), "Program");
    EXPECT_FALSE(resultJson.at("requiresReboot").get<bool>());

    UpdateHistoryEntry history;
    history.entryId = "entry-42";
    history.type = UpdateType::Configuration;
    history.version = version;
    history.appliedTime = now;
    history.success = true;
    history.wasRollback = false;
    history.size = 512;
    history.durationSeconds = 9;

    const json historyJson = json::parse(history.ToJson());
    EXPECT_EQ(historyJson.at("entryId"), "entry-42");
    EXPECT_EQ(historyJson.at("type"), "Configuration");
    EXPECT_EQ(historyJson.at("durationSeconds"), 9);

    UpdateStatistics stats;
    stats.checksPerformed = 10;
    stats.updatesApplied = 4;
    stats.updatesFailed = 1;
    stats.rollbacksPerformed = 2;
    stats.bytesDownloaded = 8192;
    stats.deltaUpdates = 3;
    stats.byUpdateType[static_cast<size_t>(UpdateType::Signature)] = 7;
    stats.lastCheckTime = now;
    stats.lastUpdateTime = now;

    stats.Reset();

    EXPECT_EQ(stats.checksPerformed, 0u);
    EXPECT_EQ(stats.updatesApplied, 0u);
    EXPECT_EQ(stats.bytesDownloaded, 0u);
    EXPECT_FALSE(stats.lastCheckTime.has_value());
    EXPECT_FALSE(stats.lastUpdateTime.has_value());

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("checksPerformed"), 0);
    EXPECT_TRUE(statsJson.at("byUpdateType").is_array());
    EXPECT_TRUE(statsJson.at("lastCheckTime").is_null());
    EXPECT_TRUE(statsJson.at("lastUpdateTime").is_null());

    UpdateConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.checkIntervalHours = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.downloadTimeoutSeconds = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxRetryAttempts = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST(UpdateManagerTest, BoundaryFormattingAndDefaultRuntimeStateRemainDeterministic) {
    const auto parsedGarbage = ParseVersionString("5.alpha.7");
    ASSERT_TRUE(parsedGarbage.has_value());
    EXPECT_EQ(parsedGarbage->major, 5);
    EXPECT_EQ(parsedGarbage->minor, 0);
    EXPECT_EQ(parsedGarbage->patch, 0);
    EXPECT_EQ(parsedGarbage->build, 0u);

    EXPECT_EQ(FormatDownloadSize(1023), "1023 B");
    EXPECT_EQ(FormatDownloadSize(1024), "1.0 KB");
    EXPECT_EQ(FormatDownloadSize(1024ull * 1024ull), "1.00 MB");
    EXPECT_EQ(FormatDownloadSize(1024ull * 1024ull * 1024ull), "1.00 GB");

    auto& manager = UpdateManager::Instance();
    manager.Shutdown();

    EXPECT_FALSE(manager.IsInitialized());
    EXPECT_EQ(manager.GetModuleStatus(), UpdateModuleStatus::Uninitialized);
    EXPECT_EQ(manager.GetStatus(), UpdateStatus::Idle);
    EXPECT_FALSE(manager.HasPendingUpdates());
    EXPECT_TRUE(manager.GetAvailableUpdates().empty());
    EXPECT_FALSE(manager.GetDownloadProgress().has_value());

    const auto moduleVersion = manager.GetCurrentVersion(UpdateType::Configuration);
    EXPECT_FALSE(moduleVersion.versionString.empty());

    const auto signatureVersion = manager.GetCurrentVersion(UpdateType::Signature);
    EXPECT_TRUE(signatureVersion.versionString.empty());
}

TEST(UpdateManagerTest, PreInitializationConfigurationAndNoOpOperationsRemainSafe) {
    auto& manager = UpdateManager::Instance();
    manager.Shutdown();

    UpdateConfiguration config;
    config.checkIntervalHours = 12;
    ASSERT_TRUE(config.IsValid());
    EXPECT_TRUE(manager.UpdateConfiguration(config));
    EXPECT_EQ(manager.GetConfiguration().checkIntervalHours, 12u);

    UpdateConfiguration invalidConfig = config;
    invalidConfig.downloadTimeoutSeconds = 0;
    EXPECT_FALSE(manager.UpdateConfiguration(invalidConfig));

    EXPECT_FALSE(manager.CheckForUpdate(UpdateType::Emergency).has_value());
    manager.CheckForUpdates();
    EXPECT_FALSE(manager.StartUpdate());
    EXPECT_FALSE(manager.StartAllUpdates());

    manager.PauseUpdate();
    manager.ResumeUpdate();
    manager.CancelUpdate();
    EXPECT_EQ(manager.GetStatus(), UpdateStatus::Idle);
}

}  // namespace ShadowStrike::Update::Test
