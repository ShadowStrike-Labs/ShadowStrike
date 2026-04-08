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
 * @file BackupProtector_Tests.cpp
 * @brief Comprehensive GTest coverage for Ransomware::BackupProtector.
 *
 * Coverage focus:
 * - configuration validation, statistics reset, helper mappings, and versioning
 * - command-pattern matching and destructive-tool classification
 * - whitelist behavior and protected-backup extension coverage
 * - process analysis, callback delivery, and blocked-attempt recording
 */

#include "pch.h"

#include "../../../src/Shared_modules/RansomwareProtection/BackupProtector.hpp"

#include <future>

namespace {

using namespace ShadowStrike::Ransomware;
using ::testing::HasSubstr;

class BackupProtectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& protector = BackupProtector::Instance();
        protector.Shutdown();
        protector.ResetStatistics();
        ASSERT_TRUE(protector.Initialize());
    }

    void TearDown() override {
        auto& protector = BackupProtector::Instance();
        protector.SetBlockCallback(nullptr);
        protector.SetDecisionCallback(nullptr);
        protector.Shutdown();
    }
};

TEST(BackupProtectorValueTests, ConfigurationStatisticsUtilitiesAndVersionRemainStable) {
    BackupProtectorConfiguration defaults;
    EXPECT_TRUE(defaults.IsValid());

    auto invalidProtections = defaults;
    invalidProtections.protectVSS = false;
    invalidProtections.protectBackupFiles = false;
    invalidProtections.protectBCD = false;
    invalidProtections.protectServices = false;
    invalidProtections.protectRegistry = false;
    EXPECT_FALSE(invalidProtections.IsValid());

    auto invalidWhitelistEntry = defaults;
    invalidWhitelistEntry.whitelistedProcesses.push_back(L"");
    EXPECT_FALSE(invalidWhitelistEntry.IsValid());

    CommandPattern pattern;
    pattern.patternName = "delete-shadows";
    pattern.regexPattern = L"delete\\s+shadows";
    pattern.keywords = { L"delete", L"shadows" };

    EXPECT_TRUE(pattern.Matches(L"VSSADMIN Delete Shadows /All /Quiet"));
    EXPECT_FALSE(pattern.Matches(L"vssadmin list shadows"));

    BackupProtectorStatistics stats;
    stats.attemptsBlocked = 3;
    stats.processesTerminated = 1;
    stats.vssDeletesBlocked = 2;
    stats.fileDeletesBlocked = 4;
    stats.serviceStopsBlocked = 5;
    stats.registryChangesBlocked = 6;
    stats.whitelistedAllowed = 7;
    stats.byThreatType[static_cast<size_t>(BackupThreatType::VSSDelete)] = 9;
    stats.Reset();

    EXPECT_EQ(stats.attemptsBlocked, 0u);
    EXPECT_EQ(stats.processesTerminated, 0u);
    EXPECT_EQ(stats.vssDeletesBlocked, 0u);
    EXPECT_EQ(stats.fileDeletesBlocked, 0u);
    EXPECT_EQ(stats.serviceStopsBlocked, 0u);
    EXPECT_EQ(stats.registryChangesBlocked, 0u);
    EXPECT_EQ(stats.whitelistedAllowed, 0u);
    EXPECT_EQ(stats.byThreatType[static_cast<size_t>(BackupThreatType::VSSDelete)], 0u);
    EXPECT_THAT(stats.ToJson(), HasSubstr("\"attemptsBlocked\":0"));

    EXPECT_EQ(GetThreatTypeName(BackupThreatType::WMIShadowDelete), "WMIShadowDelete");
    EXPECT_EQ(GetProtectionActionName(ProtectionAction::Quarantine), "Quarantine");
    EXPECT_EQ(GetToolTypeName(DangerousToolType::DiskShadow), "DiskShadow");
    EXPECT_EQ(IdentifyTool(L"C:\\Windows\\System32\\vssadmin.exe"), DangerousToolType::VSSAdmin);
    EXPECT_EQ(IdentifyTool(L"pwsh.exe"), DangerousToolType::PowerShell);
    EXPECT_EQ(IdentifyTool(L"notepad.exe"), DangerousToolType::Unknown);
    EXPECT_EQ(IdentifyThreat(L"vssadmin delete shadows /all /quiet"), BackupThreatType::VSSDelete);
    EXPECT_EQ(IdentifyThreat(L"wmic shadowcopy delete"), BackupThreatType::WMIShadowDelete);
    EXPECT_EQ(IdentifyThreat(L"bcdedit /set {default} recoveryenabled no"),
              BackupThreatType::RecoveryDisable);
    EXPECT_EQ(IdentifyThreat(L"echo harmless"), BackupThreatType::Unknown);
    EXPECT_EQ(BackupProtector::GetVersionString(), "3.1.0");
}

TEST_F(BackupProtectorTest, DestructiveToolClassificationHonorsWhitelistState) {
    auto& protector = BackupProtector::Instance();

    const std::wstring imagePath = L"C:\\Windows\\System32\\vssadmin.exe";
    const std::wstring commandLine = L"vssadmin delete shadows /all /quiet";

    EXPECT_TRUE(protector.IsDestructiveCommand(commandLine));
    EXPECT_FALSE(protector.IsDestructiveCommand(L"vssadmin list shadows"));
    EXPECT_TRUE(protector.IsDestructiveTool(imagePath, commandLine));

    protector.AddToWhitelist(imagePath);
    EXPECT_TRUE(protector.IsWhitelisted(L"c:\\windows\\system32\\VSSADMIN.exe"));
    EXPECT_FALSE(protector.IsDestructiveTool(imagePath, commandLine));

    protector.RemoveFromWhitelist(imagePath);
    EXPECT_FALSE(protector.IsWhitelisted(imagePath));
    EXPECT_TRUE(protector.IsDestructiveTool(imagePath, commandLine));
}

TEST_F(BackupProtectorTest, ProtectedBackupFileChecksReflectRuntimeConfiguration) {
    auto& protector = BackupProtector::Instance();

    EXPECT_TRUE(protector.IsProtectedBackupFile(L"C:\\Backups\\server-image.vhdx"));
    EXPECT_TRUE(protector.IsProtectedBackupFile(L"C:\\Backups\\archive.BAK"));
    EXPECT_FALSE(protector.IsProtectedBackupFile(L"C:\\Backups\\notes.txt"));

    auto updated = protector.GetConfiguration();
    updated.protectBackupFiles = false;
    ASSERT_TRUE(protector.UpdateConfiguration(updated));

    EXPECT_FALSE(protector.IsProtectedBackupFile(L"C:\\Backups\\server-image.vhdx"));
}

TEST_F(BackupProtectorTest, AnalyzeProcessBuildsBlockedAttemptUpdatesStatsAndInvokesCallback) {
    auto& protector = BackupProtector::Instance();

    std::promise<BlockedAttempt> callbackPromise;
    auto callbackFuture = callbackPromise.get_future();
    std::atomic<bool> callbackDelivered{ false };

    protector.SetBlockCallback(
        [&](const BlockedAttempt& attempt) {
            if (!callbackDelivered.exchange(true)) {
                callbackPromise.set_value(attempt);
            }
        });

    const auto result = protector.AnalyzeProcess(
        ::GetCurrentProcessId(),
        L"C:\\Windows\\System32\\vssadmin.exe",
        L"vssadmin delete shadows /all /quiet");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->toolType, DangerousToolType::VSSAdmin);
    EXPECT_EQ(result->threatType, BackupThreatType::VSSDelete);
    EXPECT_EQ(result->action, ProtectionAction::Block);
    EXPECT_EQ(result->processName, L"vssadmin.exe");

    ASSERT_EQ(callbackFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    const auto callbackAttempt = callbackFuture.get();
    EXPECT_EQ(callbackAttempt.attemptId, result->attemptId);
    EXPECT_EQ(callbackAttempt.commandLine, result->commandLine);

    const auto stats = protector.GetStatistics();
    EXPECT_EQ(stats.attemptsBlocked, 1u);
    EXPECT_EQ(stats.vssDeletesBlocked, 1u);
    EXPECT_EQ(stats.byThreatType[static_cast<size_t>(BackupThreatType::VSSDelete)], 1u);

    const auto recent = protector.GetRecentBlocks(10);
    ASSERT_FALSE(recent.empty());
    EXPECT_EQ(recent.front().attemptId, result->attemptId);
}

}  // namespace
