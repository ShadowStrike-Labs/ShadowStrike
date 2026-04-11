/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\BehaviorBlocker deterministic contracts.
 *
 * Focus:
 *   - configuration presets and JSON serialization surfaces
 *   - rule/exclusion lifecycle and statistics exposure
 *   - callback registration and safe default-state getters
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/RealTime/BehaviorBlocker.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class BehaviorBlockerTest : public ::testing::Test {
protected:
    BehaviorBlocker& blocker = BehaviorBlocker::Instance();

    void SetUp() override {
        blocker.Shutdown();
        (void)blocker.ClearRules();
    }

    void TearDown() override {
        (void)blocker.ClearRules();
        blocker.Shutdown();
    }
};

TEST_F(BehaviorBlockerTest, ConfigFactoriesAndSerializationRemainStable) {
    const auto defaults = BehaviorBlockerConfig::CreateDefault();
    const auto enterprise = BehaviorBlockerConfig::CreateEnterprise();

    EXPECT_TRUE(defaults.enableBlocking);
    EXPECT_TRUE(defaults.enableKernelIntegration);
    EXPECT_EQ(1000u, defaults.maxRules);
    EXPECT_EQ(500u, defaults.maxExclusions);
    EXPECT_EQ(5u, defaults.analysisTimeoutMs);
    EXPECT_FLOAT_EQ(0.7f, defaults.escalationThreshold);

    EXPECT_TRUE(enterprise.enableBlocking);
    EXPECT_EQ(5000u, enterprise.maxRules);
    EXPECT_EQ(2000u, enterprise.maxExclusions);
    EXPECT_EQ(3u, enterprise.analysisTimeoutMs);
    EXPECT_EQ(16384u, enterprise.regexMaxInputLength);
    EXPECT_FLOAT_EQ(0.5f, enterprise.escalationThreshold);

    ProcessBehavior behavior;
    behavior.processId = 1337;
    behavior.parentPid = 7;
    behavior.processPath = L"C:\\Tools\\powershell.exe";
    behavior.commandLine = L"powershell.exe -enc SGVsbG8=";
    behavior.type = BehaviorType::ScriptExecution;
    behavior.target = L"https://example.invalid";
    behavior.risk = RiskLevel::High;
    behavior.sessionId = 2;
    behavior.integrityLevel = 0x2000;
    behavior.correlationId = "chain-1";
    behavior.timestamp = 123456789;

    const std::string processJson = behavior.ToJson();
    EXPECT_TRUE(ContainsSubstring(processJson, "\"processId\":1337"));
    EXPECT_TRUE(ContainsSubstring(processJson, "\"parentPid\":7"));
    EXPECT_TRUE(ContainsSubstring(processJson, "\"correlationId\":\"chain-1\""));

    BlockEvent event;
    event.timestamp = 123;
    event.processId = 1337;
    event.processPath = L"C:\\Tools\\powershell.exe";
    event.behaviorType = BehaviorType::ScriptExecution;
    event.actionTaken = BlockAction::TerminateProcess;
    event.ruleId = "bb-rule";
    event.details = "Encoded PowerShell denied";
    event.correlationId = "chain-1";
    event.actionSucceeded = true;

    const std::string blockJson = event.ToJson();
    EXPECT_TRUE(ContainsSubstring(blockJson, "\"ruleId\":\"bb-rule\""));
    EXPECT_TRUE(ContainsSubstring(blockJson, "\"actionSucceeded\":true"));
    EXPECT_TRUE(ContainsSubstring(blockJson, "\"correlationId\":\"chain-1\""));
}

TEST_F(BehaviorBlockerTest, RuleAndExclusionLifecycleKeepsStatisticsConsistent) {
    BehaviorRule lowPriorityRule;
    lowPriorityRule.ruleId = "low";
    lowPriorityRule.description = "Low priority logging rule";
    lowPriorityRule.targetType = BehaviorType::ScriptExecution;
    lowPriorityRule.targetPattern = ".*";
    lowPriorityRule.minRiskLevel = RiskLevel::Low;
    lowPriorityRule.action = BlockAction::LogOnly;
    lowPriorityRule.priority = 10;
    lowPriorityRule.mitreAttackId = "T1059";

    BehaviorRule highPriorityRule = lowPriorityRule;
    highPriorityRule.ruleId = "high";
    highPriorityRule.description = "High priority blocking rule";
    highPriorityRule.action = BlockAction::TerminateProcess;
    highPriorityRule.priority = 90;

    BehaviorRule invalidRegexRule = lowPriorityRule;
    invalidRegexRule.ruleId = "invalid";
    invalidRegexRule.targetPattern = "[";

    EXPECT_TRUE(blocker.AddRule(lowPriorityRule));
    EXPECT_TRUE(blocker.AddRule(highPriorityRule));
    EXPECT_FALSE(blocker.AddRule(highPriorityRule));
    EXPECT_FALSE(blocker.AddRule(invalidRegexRule));

    auto stats = blocker.GetStatistics();
    EXPECT_EQ(2u, stats.activeRuleCount);
    EXPECT_EQ(0u, stats.activeExclusionCount);

    EXPECT_TRUE(blocker.DisableRule("high"));
    EXPECT_EQ(1u, blocker.GetStatistics().activeRuleCount);
    EXPECT_TRUE(blocker.EnableRule("high"));
    EXPECT_EQ(2u, blocker.GetStatistics().activeRuleCount);

    BehaviorExclusion exclusion;
    exclusion.exclusionId = "trusted-admin";
    exclusion.processPathPattern = R"(C:\\Windows\\System32\\WindowsPowerShell\\.*)";
    exclusion.commandLinePattern = ".*-File.*";
    exclusion.description = "Trusted automation";

    BehaviorExclusion duplicateExclusion = exclusion;
    BehaviorExclusion invalidExclusion = exclusion;
    invalidExclusion.exclusionId = "bad-regex";
    invalidExclusion.processPathPattern = "[";

    EXPECT_TRUE(blocker.AddExclusion(exclusion));
    EXPECT_FALSE(blocker.AddExclusion(duplicateExclusion));
    EXPECT_FALSE(blocker.AddExclusion(invalidExclusion));
    EXPECT_EQ(1u, blocker.GetStatistics().activeExclusionCount);

    EXPECT_TRUE(blocker.RemoveExclusion("trusted-admin"));
    EXPECT_EQ(0u, blocker.GetStatistics().activeExclusionCount);

    EXPECT_TRUE(blocker.ClearRules());
    EXPECT_EQ(0u, blocker.GetStatistics().activeRuleCount);
}

TEST_F(BehaviorBlockerTest, DefaultStateAndCallbackContractsRemainSafe) {
    EXPECT_FALSE(blocker.IsRunning());
    EXPECT_EQ(ComponentState::NotInitialized, blocker.GetState());
    EXPECT_TRUE(ContainsSubstring(blocker.GetStatisticsJson(), "\"activeRuleCount\":0"));

    EXPECT_EQ(0u, blocker.RegisterBlockCallback({}));

    const uint64_t callbackId = blocker.RegisterBlockCallback([](const BlockEvent&) {});
    EXPECT_NE(0u, callbackId);

    blocker.UnregisterBlockCallback(callbackId);
    blocker.UnregisterBlockCallback(callbackId);
}

TEST_F(BehaviorBlockerTest, LifecycleAndAnalysisGatesPreserveAllowByDefaultBehavior) {
    ASSERT_TRUE(blocker.Initialize(BehaviorBlockerConfig::CreateDefault()));
    EXPECT_EQ(ComponentState::Stopped, blocker.GetState());

    ProcessBehavior behavior;
    behavior.processId = 2048;
    behavior.parentPid = 4;
    behavior.processPath = L"C:\\Tools\\powershell.exe";
    behavior.commandLine = L"powershell.exe -enc SGVsbG8=";
    behavior.type = BehaviorType::ScriptExecution;

    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(behavior));
    EXPECT_FALSE(blocker.DisableRule("missing"));
    EXPECT_FALSE(blocker.EnableRule("missing"));
    EXPECT_FALSE(blocker.RemoveRule("missing"));
    EXPECT_FALSE(blocker.RemoveExclusion("missing"));

    ASSERT_TRUE(blocker.Start());
    EXPECT_TRUE(blocker.IsRunning());

    blocker.Pause();
    EXPECT_TRUE(blocker.IsPaused());
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(behavior));

    blocker.Resume();
    EXPECT_TRUE(blocker.IsRunning());

    ProcessBehavior emptyPathBehavior = behavior;
    emptyPathBehavior.processPath.clear();
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(emptyPathBehavior));

    ProcessBehavior systemBehavior = behavior;
    systemBehavior.processId = 4;
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(systemBehavior));

    blocker.Stop();
    EXPECT_EQ(ComponentState::Stopped, blocker.GetState());
}

}  // namespace ShadowStrike::RealTime::Tests
