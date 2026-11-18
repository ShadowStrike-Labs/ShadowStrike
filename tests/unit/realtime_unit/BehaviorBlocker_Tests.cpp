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

// ----------------------------------------------------------------------------
// Task 388: chain-escalation composite is the decayed MAXIMUM, not a SUM.
//
// The old composite summed up to 256 decayed per-event scores and compared the
// total to a single-event 0.70 threshold, so a process escalated on event VOLUME
// alone: the 1.0.133 run escalated MsMpEng ~1,500 times a second on an idle logon
// screen. Escalation is observed here through chainEscalationTerminationsWithheld
// with allowChainEscalationTermination left false (its default), so these tests
// exercise the real policy path and never terminate a real process.
// ----------------------------------------------------------------------------
namespace {

BehaviorBlockerConfig ChainTestConfig() {
    auto cfg = BehaviorBlockerConfig::CreateDefault();
    cfg.enableTemporalCorrelation       = true;
    cfg.allowChainEscalationTermination = false;  // observe via the withheld counter
    cfg.escalationThreshold             = 0.7f;
    return cfg;
}

ProcessBehavior ChainEvent(uint32_t pid, RiskLevel risk) {
    ProcessBehavior b;
    b.processId   = pid;
    b.parentPid   = 1000;
    b.processPath = L"C:\\test\\subject.exe";
    b.type        = BehaviorType::Discovery;  // no default rule targets Discovery
    b.risk        = risk;
    return b;
}

}  // namespace

TEST_F(BehaviorBlockerTest, CompositeIsDecayedMaxSoEventVolumeAloneDoesNotEscalate) {
    ASSERT_TRUE(blocker.Initialize(ChainTestConfig()));
    ASSERT_TRUE(blocker.Start());

    // 300 back-to-back Low events for one pid. Under the old sum these reached
    // ~256 * 0.15 = 38, far past 0.70; under the decayed max the composite stays
    // at 0.15 and never escalates.
    const auto low = ChainEvent(54321, RiskLevel::Low);
    for (int i = 0; i < 300; ++i) {
        EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(low));
    }
    EXPECT_EQ(0u, blocker.GetStatistics().chainEscalationTerminationsWithheld);
}

TEST_F(BehaviorBlockerTest, CompositeStillEscalatesOnASingleHighRiskEvent) {
    ASSERT_TRUE(blocker.Initialize(ChainTestConfig()));
    ASSERT_TRUE(blocker.Start());

    // One genuine High event reaches 0.70 == threshold and escalates; the kill is
    // withheld by default policy and counted. Real verdicts still escalate.
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(ChainEvent(54322, RiskLevel::High)));
    EXPECT_EQ(1u, blocker.GetStatistics().chainEscalationTerminationsWithheld);
}

TEST_F(BehaviorBlockerTest, CompositeDoesNotEscalateOnTwoMediumEvents) {
    ASSERT_TRUE(blocker.Initialize(ChainTestConfig()));
    ASSERT_TRUE(blocker.Start());

    // Two Medium events: decayed max = 0.35 < 0.70, no escalation. Under the old
    // sum they totalled 0.70 and escalated - the over-escalation 388 cites.
    const auto med = ChainEvent(54323, RiskLevel::Medium);
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(med));
    EXPECT_EQ(BlockAction::Allow, blocker.AnalyzeBehavior(med));
    EXPECT_EQ(0u, blocker.GetStatistics().chainEscalationTerminationsWithheld);
}

}  // namespace ShadowStrike::RealTime::Tests
