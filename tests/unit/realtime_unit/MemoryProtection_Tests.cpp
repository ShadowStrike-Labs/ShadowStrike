/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\MemoryProtection deterministic contracts.
 *
 * Focus:
 *   - JSON serialization for violation and scan results
 *   - configuration, monitoring, and callback contracts
 *   - safe default scan behavior and statistics/self-test surfaces
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/PhantomCore/RealTime/MemoryProtection.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

using MemoryProtectionEngine = ShadowStrike::RealTime::MemoryProtection;
using MemoryProtectionConfig = ShadowStrike::RealTime::MemoryProtectionConfig;
using MemoryScanResult = ShadowStrike::RealTime::MemoryScanResult;
using MemoryViolation = ShadowStrike::RealTime::MemoryViolation;

class MemoryProtectionTest : public ::testing::Test {
protected:
    MemoryProtectionEngine& protection = MemoryProtectionEngine::Instance();

    void SetUp() override {
        protection.Stop();
        (void)protection.UnmonitorProcess(4242);
    }

    void TearDown() override {
        (void)protection.UnmonitorProcess(4242);
        protection.Stop();
    }
};

TEST_F(MemoryProtectionTest, JsonSerializationAndConfigurationRemainStable) {
    MemoryViolation violation;
    violation.type = MemoryViolationType::Reflective_DLL;
    violation.address = 0x401000;
    violation.size = 512;
    violation.dump = { 0x90, 0x90, 0xCC };
    violation.confidence = 0.975f;
    violation.details = "Reflective loader markers";
    violation.severity = MemoryThreatSeverity::Critical;
    violation.mitreTechnique = MitreTechnique::T1620;
    violation.targetPid = 404;
    violation.sourcePid = 505;
    violation.threadId = 606;
    violation.entropy = 7.95;
    violation.fromKernel = true;

    const std::string violationJson = violation.ToJson();
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"type\":\"Reflective_DLL\""));
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"address\":\"0x401000\""));
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"severity\":\"Critical\""));
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"mitre\":\"T1620\""));
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"fromKernel\":true"));
    EXPECT_TRUE(ContainsSubstring(violationJson, "\"dump\":\"9090cc\""));

    MemoryScanResult result;
    result.pid = 404;
    result.compromised = true;
    result.pagesScanned = 128;
    result.violations.push_back(violation);
    result.scanDuration = std::chrono::microseconds(1500);
    result.highestSeverity = MemoryThreatSeverity::Critical;
    result.overallThreatScore = 92.5f;

    const std::string resultJson = result.ToJson();
    EXPECT_TRUE(ContainsSubstring(resultJson, "\"pid\":404"));
    EXPECT_TRUE(ContainsSubstring(resultJson, "\"compromised\":true"));
    EXPECT_TRUE(ContainsSubstring(resultJson, "\"pagesScanned\":128"));
    EXPECT_TRUE(ContainsSubstring(resultJson, "\"overallThreatScore\":92.50"));
    EXPECT_TRUE(ContainsSubstring(resultJson, "\"type\":\"Reflective_DLL\""));

    MemoryProtectionConfig config;
    config.enableContinuousMonitoring = false;
    config.enableTelemetry = false;
    config.alertThreshold = 0.75f;
    config.blockThreshold = 0.95f;
    config.highEntropyThreshold = 7.8;

    protection.Configure(config);
    const auto applied = protection.GetConfig();
    EXPECT_FALSE(applied.enableContinuousMonitoring);
    EXPECT_FALSE(applied.enableTelemetry);
    EXPECT_FLOAT_EQ(0.75f, applied.alertThreshold);
    EXPECT_FLOAT_EQ(0.95f, applied.blockThreshold);
    EXPECT_DOUBLE_EQ(7.8, applied.highEntropyThreshold);
}

TEST_F(MemoryProtectionTest, MonitoringAndCallbackContractsRemainSafe) {
    EXPECT_FALSE(protection.IsRunning());
    EXPECT_EQ(0u, protection.RegisterThreatCallback({}));
    EXPECT_FALSE(protection.UnregisterThreatCallback(0));

    const uint64_t callbackId = protection.RegisterThreatCallback(
        [](const MemoryViolation&, uint32_t) {});
    EXPECT_NE(0u, callbackId);

    EXPECT_TRUE(protection.MonitorProcess(4242));
    EXPECT_TRUE(protection.MonitorProcess(4242));
    EXPECT_TRUE(protection.EnableExploitProtection(4242, EXPLOIT_PROTECT_MONITOR_ONLY));
    EXPECT_FALSE(protection.EnableExploitProtection(0, EXPLOIT_PROTECT_MONITOR_ONLY));
    EXPECT_TRUE(ContainsSubstring(protection.GetStatistics(), "\"monitoredProcesses\":1"));
    EXPECT_TRUE(ContainsSubstring(protection.GetStatistics(), "\"registeredCallbacks\":1"));

    EXPECT_TRUE(protection.UnmonitorProcess(4242));
    EXPECT_FALSE(protection.UnmonitorProcess(4242));
    EXPECT_TRUE(protection.UnregisterThreatCallback(callbackId));
    EXPECT_FALSE(protection.UnregisterThreatCallback(callbackId));
}

TEST_F(MemoryProtectionTest, DefaultScanBehaviorAndDiagnosticsRemainDeterministic) {
    const auto missingProcessScan = protection.ScanProcess(0xDEADu, ScanMode::Fast);
    EXPECT_EQ(0u, missingProcessScan.pid);
    EXPECT_FALSE(missingProcessScan.compromised);
    EXPECT_EQ(0u, missingProcessScan.pagesScanned);
    EXPECT_TRUE(missingProcessScan.violations.empty());

    const auto invalidRegionScan = protection.ScanRegion(0xDEADu, 0x1000, 0);
    EXPECT_EQ(0u, invalidRegionScan.pid);
    EXPECT_FALSE(invalidRegionScan.compromised);
    EXPECT_TRUE(invalidRegionScan.violations.empty());

    const auto oversizedRegionScan = protection.ScanRegion(0xDEADu, 0x1000, (256ULL * 1024ULL * 1024ULL) + 1ULL);
    EXPECT_EQ(0u, oversizedRegionScan.pid);
    EXPECT_FALSE(oversizedRegionScan.compromised);
    EXPECT_TRUE(oversizedRegionScan.violations.empty());
    EXPECT_FALSE(protection.IsProcessCompromised(0xDEADu));
    EXPECT_TRUE(protection.HuntAPT(0xDEADu).violations.empty());

    EXPECT_TRUE(protection.SelfTest());
    EXPECT_TRUE(ContainsSubstring(protection.GetStatistics(), "\"scansPerformed\":0"));
    EXPECT_TRUE(ContainsSubstring(protection.GetStatistics(), "\"registeredCallbacks\":0"));
}

}  // namespace ShadowStrike::RealTime::Tests
