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
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../../src/PhantomCore/RansomwareProtection/BackupProtector.hpp"

#include <future>
#include <optional>
#include <stdexcept>

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

    auto invalidWhitelistLimit = defaults;
    invalidWhitelistLimit.whitelistedProcesses.assign(
        BackupProtectorConstants::MAX_WHITELIST_SIZE + 1, L"C:\\safe.exe");
    EXPECT_FALSE(invalidWhitelistLimit.IsValid());

    auto disabledNoProtections = invalidProtections;
    disabledNoProtections.enabled = false;
    EXPECT_TRUE(disabledNoProtections.IsValid());

    defaults.LoadDefaultPatterns();
    EXPECT_FALSE(defaults.commandPatterns.empty());
    defaults.LoadDefaultServices();
    ASSERT_FALSE(defaults.protectedServices.empty());
    EXPECT_EQ(defaults.protectedServices.front().serviceName, L"VSS");

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

    BlockedAttempt attempt;
    attempt.attemptId = 7;
    attempt.pid = 77;
    attempt.processName = L"wmic.exe";
    attempt.commandLine = L"wmic shadowcopy delete";
    attempt.target = L"shadowcopy";
    EXPECT_THAT(attempt.ToJson(), HasSubstr("\"attemptId\":7"));
    EXPECT_THAT(attempt.ToJson(), HasSubstr("\"commandLine\":\"wmic shadowcopy delete\""));

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
    const std::wstring commandLine = L"vssadmin.exe delete shadows /all /quiet";

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

TEST_F(BackupProtectorTest, FileServiceAndRegistryProtectionHelpersRejectDestructiveOperations) {
    auto& protector = BackupProtector::Instance();

    EXPECT_TRUE(protector.ShouldBlockFileAccess(
        L"C:\\Backups\\server-image.vhdx", ::GetCurrentProcessId(), DELETE));
    EXPECT_FALSE(protector.ShouldBlockFileAccess(
        L"C:\\Backups\\notes.txt", ::GetCurrentProcessId(), DELETE));
    EXPECT_FALSE(protector.ShouldBlockFileAccess(
        L"C:\\Backups\\server-image.vhdx", ::GetCurrentProcessId(), FILE_READ_DATA));

    EXPECT_TRUE(protector.ShouldBlockServiceOperation(L"VSS", 0x0020, ::GetCurrentProcessId()));
    EXPECT_FALSE(protector.ShouldBlockServiceOperation(L"Spooler", 0x0020, ::GetCurrentProcessId()));

    EXPECT_TRUE(protector.ShouldBlockRegistryOperation(
        LR"(SYSTEM\CurrentControlSet\Services\VSS)", L"Start", KEY_SET_VALUE,
        ::GetCurrentProcessId()));
    EXPECT_FALSE(protector.ShouldBlockRegistryOperation(
        LR"(SOFTWARE\ShadowStrike)", L"Test", KEY_SET_VALUE, ::GetCurrentProcessId()));
}

TEST_F(BackupProtectorTest, AnalyzeProcessBuildsBlockedAttemptUpdatesStatsAndInvokesCallback) {
    auto& protector = BackupProtector::Instance();
    auto updated = protector.GetConfiguration();
    updated.killOnDetection = false;
    updated.defaultAction = ProtectionAction::Block;
    ASSERT_TRUE(protector.UpdateConfiguration(updated));

    std::promise<BlockedAttempt> callbackPromise;
    auto callbackFuture = callbackPromise.get_future();
    std::atomic<bool> callbackDelivered{ false };

    protector.SetBlockCallback(
        [&](const BlockedAttempt& attempt) {
            if (!callbackDelivered.exchange(true)) {
                callbackPromise.set_value(attempt);
            }
        });

    constexpr uint32_t kAnalyzedPid = 0x4141;
    const auto result = protector.AnalyzeProcess(
        kAnalyzedPid,
        L"C:\\Windows\\System32\\vssadmin.exe",
        L"vssadmin.exe delete shadows /all /quiet");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->pid, kAnalyzedPid);
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

    const auto secondResult = protector.AnalyzeProcess(
        kAnalyzedPid + 1,
        L"C:\\Windows\\System32\\wmic.exe",
        L"wmic.exe shadowcopy delete /nointeractive");
    ASSERT_TRUE(secondResult.has_value());

    const auto newestOnly = protector.GetRecentBlocks(1);
    ASSERT_EQ(newestOnly.size(), 1u);
    EXPECT_EQ(newestOnly.front().attemptId, secondResult->attemptId);
    EXPECT_TRUE(protector.GetRecentBlocks(0).empty());
}

// ============================================================================
// DECISION CALLBACK CONTRACT
//
// DecisionCallback returns std::optional<ProtectionAction>. std::nullopt means
// NO OPINION and the built-in DetermineAction result stands; an engaged value is
// honoured verbatim, INCLUDING ProtectionAction::Allow.
//
// It previously returned a bare ProtectionAction, and QueryDecision answered
// Allow for "no callback registered", "the callback threw" and "the callback
// said allow" alike, while the one consumer applied the override only when the
// value was NOT Allow. So a registrant could express every verdict except the
// one it most needed - permit this - and that verdict was silently discarded.
// ============================================================================

TEST_F(BackupProtectorTest, DecisionCallbackCanPermitAnAttemptTheBuiltInPolicyWouldBlock) {
    auto& protector = BackupProtector::Instance();
    auto updated = protector.GetConfiguration();
    updated.killOnDetection = false;
    updated.defaultAction = ProtectionAction::Block;
    ASSERT_TRUE(protector.UpdateConfiguration(updated));

    const auto before = protector.GetStatistics();
    const auto recentBefore = protector.GetRecentBlocks(64).size();

    std::atomic<int> invocations{ 0 };
    protector.SetDecisionCallback(
        [&invocations](uint32_t, const std::wstring&, BackupThreatType)
            -> std::optional<ProtectionAction> {
            invocations.fetch_add(1, std::memory_order_relaxed);
            return ProtectionAction::Allow;  // deliberately permit
        });

    const auto result = protector.AnalyzeProcess(
        0x5150,
        L"C:\\Windows\\System32\\vssadmin.exe",
        L"vssadmin.exe delete shadows /all /quiet");

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(invocations.load(std::memory_order_relaxed), 1)
        << "the decision callback must be consulted exactly once per matched attempt";

    // THE DISCRIMINATOR. Against the previous signature the callback's Allow was
    // read as silence, so the action stayed Block and the attempt was recorded.
    EXPECT_EQ(result->action, ProtectionAction::Allow);

    const auto after = protector.GetStatistics();
    EXPECT_EQ(after.attemptsBlocked, before.attemptsBlocked)
        << "a permitted attempt must not be counted as blocked";
    EXPECT_EQ(protector.GetRecentBlocks(64).size(), recentBefore)
        << "a permitted attempt must not be recorded as a blocked attempt";
}

TEST_F(BackupProtectorTest, DecisionCallbackNulloptAndThrowBothLeaveTheBuiltInActionStanding) {
    auto& protector = BackupProtector::Instance();
    auto updated = protector.GetConfiguration();
    updated.killOnDetection = false;
    updated.defaultAction = ProtectionAction::Block;
    ASSERT_TRUE(protector.UpdateConfiguration(updated));

    const std::wstring image = L"C:\\Windows\\System32\\vssadmin.exe";
    const std::wstring cmd   = L"vssadmin.exe delete shadows /all /quiet";

    // (a) An explicit "no opinion" leaves the built-in policy in charge.
    std::atomic<int> declines{ 0 };
    protector.SetDecisionCallback(
        [&declines](uint32_t, const std::wstring&, BackupThreatType)
            -> std::optional<ProtectionAction> {
            declines.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        });

    const auto declined = protector.AnalyzeProcess(0x5151, image, cmd);
    ASSERT_TRUE(declined.has_value());
    EXPECT_EQ(declines.load(std::memory_order_relaxed), 1);
    EXPECT_EQ(declined->action, ProtectionAction::Block);

    // (b) A THROWING callback must also fall back to the built-in policy and
    // must never be mistaken for a permit. This is the direction that matters:
    // a failing hook must not become a bypass of this module's own decision.
    protector.SetDecisionCallback(
        [](uint32_t, const std::wstring&, BackupThreatType)
            -> std::optional<ProtectionAction> {
            throw std::runtime_error("decision callback failure");
        });

    const auto threw = protector.AnalyzeProcess(0x5152, image, cmd);
    ASSERT_TRUE(threw.has_value());
    EXPECT_EQ(threw->action, ProtectionAction::Block)
        << "a throwing decision callback must not permit the operation";
}

TEST_F(BackupProtectorTest, DecisionCallbackOverrideOfANonAllowVerdictIsStillHonoured) {
    // REGRESSION GUARD, not a discriminator: overriding to a non-Allow verdict
    // worked before this change and must keep working. Warn is used because the
    // block-execution branch acts only on Block and BlockKill, so nothing
    // destructive runs against the synthetic pid.
    auto& protector = BackupProtector::Instance();
    auto updated = protector.GetConfiguration();
    updated.killOnDetection = false;
    updated.defaultAction = ProtectionAction::Block;
    ASSERT_TRUE(protector.UpdateConfiguration(updated));

    protector.SetDecisionCallback(
        [](uint32_t, const std::wstring&, BackupThreatType)
            -> std::optional<ProtectionAction> {
            return ProtectionAction::Warn;
        });

    const auto result = protector.AnalyzeProcess(
        0x5153,
        L"C:\\Windows\\System32\\vssadmin.exe",
        L"vssadmin.exe delete shadows /all /quiet");

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->action, ProtectionAction::Warn);
}

}  // namespace
