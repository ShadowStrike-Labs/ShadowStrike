/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\ProcessCreationMonitor deterministic contracts.
 *
 * Focus:
 *   - public mapping helpers, decode helpers, and config presets
 *   - statistics reset behavior and safe default-state accessors
 *   - rule priority ordering and callback registration contracts
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/ProcessCreationMonitor.hpp"

namespace ShadowStrike::RealTime::Tests {

class ProcessCreationMonitorTest : public ::testing::Test {
protected:
    ProcessCreationMonitor& monitor = ProcessCreationMonitor::Instance();

    void SetUp() override {
        monitor.Shutdown();
        monitor.RemoveRule("high-priority");
        monitor.RemoveRule("low-priority");
    }

    void TearDown() override {
        monitor.RemoveRule("high-priority");
        monitor.RemoveRule("low-priority");
        monitor.Shutdown();
    }
};

TEST_F(ProcessCreationMonitorTest, MappingHelpersAndConfigFactoriesRemainStable) {
    EXPECT_STREQ("Block", ProcessVerdictToString(ProcessVerdict::Block));
    EXPECT_STREQ("PowerShell", LOLBASTypeToString(LOLBASType::PowerShell));
    EXPECT_STREQ("T1059.001", SuspiciousPatternToMitre(SuspiciousPattern::EncodedPowerShell));

    const auto defaults = ProcessMonitorConfig::CreateDefault();
    const auto strict = ProcessMonitorConfig::CreateStrict();
    const auto monitorOnly = ProcessMonitorConfig::CreateMonitorOnly();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_TRUE(defaults.preExecutionScan);
    EXPECT_TRUE(defaults.blockKnownMalicious);
    EXPECT_EQ(ProcessMonitorConstants::MAX_TRACKED_PROCESSES, defaults.maxTrackedProcesses);

    EXPECT_TRUE(strict.blockUnsigned);
    EXPECT_TRUE(strict.blockFromTemp);
    EXPECT_TRUE(strict.blockFromNetwork);
    EXPECT_TRUE(strict.blockOnTimeout);
    EXPECT_DOUBLE_EQ(30.0, strict.alertThreshold);
    EXPECT_DOUBLE_EQ(60.0, strict.blockThreshold);

    EXPECT_FALSE(monitorOnly.preExecutionScan);
    EXPECT_FALSE(monitorOnly.blockUnsigned);
    EXPECT_FALSE(monitorOnly.blockKnownMalicious);
    EXPECT_DOUBLE_EQ(100.0, monitorOnly.blockThreshold);
}

TEST_F(ProcessCreationMonitorTest, StatisticsResetAndDecodeHelpersRemainDeterministic) {
    ProcessMonitorStats stats;
    stats.totalProcessCreations = 12;
    stats.processesAllowed = 9;
    stats.processesBlocked = 3;
    stats.processesSuspicious = 4;
    stats.scansPerformed = 8;
    stats.scanTimeouts = 1;
    stats.encodedCommandDetections = 2;
    stats.trackedProcesses = 7;
    stats.avgDecisionTimeUs = 55;

    stats.Reset();

    EXPECT_EQ(0u, stats.totalProcessCreations);
    EXPECT_EQ(0u, stats.processesBlocked);
    EXPECT_EQ(0u, stats.scansPerformed);
    EXPECT_EQ(0u, stats.trackedProcesses);
    EXPECT_EQ(0u, stats.avgDecisionTimeUs);

    EXPECT_EQ(std::wstring(L"ABC"), monitor.DecodeEncodedContent(L"QQBCAEMA"));
    EXPECT_EQ(std::wstring(L"Hello"), monitor.DecodeEncodedContent(L"SGVsbG8="));
    EXPECT_EQ(std::wstring(L"powershell.exe"),
        GetProcessImageName(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"));
    EXPECT_EQ(std::wstring(L"cmd.exe"), GetProcessImageName(L"cmd.exe"));
}

TEST_F(ProcessCreationMonitorTest, RuleOrderingAndCallbacksRemainSafe) {
    EXPECT_FALSE(monitor.IsRunning());
    EXPECT_TRUE(monitor.GetAllProcesses().empty());
    EXPECT_EQ(0u, monitor.GetStats().trackedProcesses);

    ProcessPolicyRule lowRule;
    lowRule.ruleId = "low-priority";
    lowRule.name = L"Low priority";
    lowRule.description = L"Observe generic temp execution";
    lowRule.action = ProcessVerdict::AllowMonitored;
    lowRule.priority = 10;
    lowRule.imageNamePattern = L".*temp.*";

    ProcessPolicyRule highRule = lowRule;
    highRule.ruleId = "high-priority";
    highRule.name = L"High priority";
    highRule.action = ProcessVerdict::Block;
    highRule.priority = 90;
    highRule.commandLinePattern = L".*-enc.*";

    EXPECT_TRUE(monitor.AddRule(lowRule));
    EXPECT_TRUE(monitor.AddRule(highRule));

    const auto rules = monitor.GetRules();
    ASSERT_EQ(2u, rules.size());
    EXPECT_EQ(std::string("high-priority"), rules.front().ruleId);
    EXPECT_EQ(std::string("low-priority"), rules.back().ruleId);

    const uint64_t createId = monitor.RegisterCreateCallback(
        [](const ProcessCreateEvent&) { return ProcessVerdict::Allow; });
    const uint64_t terminateId = monitor.RegisterTerminateCallback(
        [](uint32_t, uint32_t) {});
    const uint64_t suspiciousId = monitor.RegisterSuspiciousCallback(
        [](const ProcessInfo&, const std::vector<SuspiciousPattern>&) {});

    EXPECT_NE(0u, createId);
    EXPECT_NE(0u, terminateId);
    EXPECT_NE(0u, suspiciousId);

    EXPECT_TRUE(monitor.UnregisterCreateCallback(createId));
    EXPECT_TRUE(monitor.UnregisterTerminateCallback(terminateId));
    EXPECT_TRUE(monitor.UnregisterSuspiciousCallback(suspiciousId));
    EXPECT_FALSE(monitor.UnregisterSuspiciousCallback(suspiciousId));
}

}  // namespace ShadowStrike::RealTime::Tests
