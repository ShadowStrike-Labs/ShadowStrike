/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\FileIntegrityMonitor deterministic contracts.
 *
 * Focus:
 *   - string/MITRE mapping helpers and configuration presets
 *   - rule management, callback registration, and safe lookup helpers
 *   - statistics reset exposure without requiring live filesystem monitoring
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/FileIntegrityMonitor.hpp"

namespace ShadowStrike::RealTime::Tests {

class FileIntegrityMonitorTest : public ::testing::Test {
protected:
    FileIntegrityMonitor& fim = FileIntegrityMonitor::Instance();

    void SetUp() override {
        fim.Shutdown();
        fim.ResetStats();
    }

    void TearDown() override {
        fim.Shutdown();
    }
};

TEST_F(FileIntegrityMonitorTest, MappingHelpersAndConfigFactoriesRemainStable) {
    EXPECT_STREQ("Modified", FileChangeTypeToString(FileChangeType::Modified));
    EXPECT_STREQ("SecurityComponent", FileCategoryToString(FileCategory::SecurityComponent));
    EXPECT_STREQ("T1565.001", FileChangeToMitre(FileChangeType::Modified));

    const auto defaults = FIMConfig::CreateDefault();
    const auto strict = FIMConfig::CreateStrict();
    const auto compliance = FIMConfig::CreateCompliance();
    const auto lightweight = FIMConfig::CreateLightweight();

    EXPECT_TRUE(defaults.realTimeMonitoring);
    EXPECT_TRUE(defaults.scheduledVerification);
    EXPECT_EQ(FIMAction::Alert, defaults.defaultAction);

    EXPECT_EQ(FIMAction::Restore, strict.defaultAction);
    EXPECT_TRUE(strict.blockOnViolation);
    EXPECT_TRUE(strict.calculateSecondaryHash);
    EXPECT_TRUE(strict.trackTimestamps);
    EXPECT_EQ(60u, strict.criticalIntervalSec);

    EXPECT_TRUE(compliance.trackTimestamps);
    EXPECT_TRUE(compliance.calculateSecondaryHash);
    EXPECT_EQ(900u, compliance.verifyIntervalSec);

    EXPECT_FALSE(lightweight.trackAttributes);
    EXPECT_FALSE(lightweight.trackPermissions);
    EXPECT_FALSE(lightweight.trackADS);
    EXPECT_EQ(7200u, lightweight.verifyIntervalSec);
    EXPECT_EQ(2u, lightweight.verificationThreads);
}

TEST_F(FileIntegrityMonitorTest, RuleCallbacksAndLookupsRemainSafeWithoutLiveMonitoring) {
    MonitoringRule rule;
    rule.ruleId = "fim-system32";
    rule.name = L"System32 protection";
    rule.description = L"Monitor critical binaries";
    rule.pathPattern = L"C:\\Windows\\System32\\*";
    rule.category = FileCategory::SystemExecutable;
    rule.isCritical = true;
    rule.violationAction = FIMAction::Restore;

    EXPECT_TRUE(fim.AddRule(rule));
    EXPECT_FALSE(fim.GetRules().empty());
    EXPECT_TRUE(fim.RemoveRule(rule.ruleId));
    EXPECT_TRUE(fim.GetRules().empty());

    EXPECT_EQ(0u, fim.RegisterChangeCallback({}));

    const uint64_t changeId = fim.RegisterChangeCallback(
        [](const FileChangeEvent&) { return FIMAction::LogOnly; });
    const uint64_t violationId = fim.RegisterViolationCallback([](const IntegrityViolation&) {});
    const uint64_t verificationId = fim.RegisterVerificationCallback(
        [](const VerificationResult&) {});
    const uint64_t restoreId = fim.RegisterRestoreCallback(
        [](const std::wstring&, bool) {});

    EXPECT_NE(0u, changeId);
    EXPECT_NE(0u, violationId);
    EXPECT_NE(0u, verificationId);
    EXPECT_NE(0u, restoreId);

    EXPECT_TRUE(fim.UnregisterChangeCallback(changeId));
    EXPECT_TRUE(fim.UnregisterViolationCallback(violationId));
    EXPECT_TRUE(fim.UnregisterVerificationCallback(verificationId));
    EXPECT_TRUE(fim.UnregisterRestoreCallback(restoreId));
    EXPECT_FALSE(fim.UnregisterRestoreCallback(restoreId));

    EXPECT_FALSE(fim.GetBaseline(L"C:\\does-not-exist.bin").has_value());
    EXPECT_FALSE(fim.QueryFileAttributes(L"C:\\does-not-exist.bin").has_value());
    EXPECT_FALSE(fim.GetFileSignature(L"C:\\does-not-exist.bin").has_value());
}

TEST_F(FileIntegrityMonitorTest, StatisticsExposureStaysDeterministicAfterReset) {
    fim.ResetStats();

    const auto stats = fim.GetStats();
    EXPECT_EQ(0u, stats.monitoredFiles);
    EXPECT_EQ(0u, stats.monitoredDirectories);
    EXPECT_EQ(0u, stats.changesDetected);
    EXPECT_EQ(0u, stats.violations);
    EXPECT_EQ(0u, stats.verificationsPerformed);
    EXPECT_EQ(0u, stats.avgVerificationTimeMs);
}

}  // namespace ShadowStrike::RealTime::Tests
