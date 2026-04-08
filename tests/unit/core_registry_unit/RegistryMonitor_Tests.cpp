/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Registry\RegistryMonitor deterministic contracts.
 *
 * Focus:
 *   - registry event classification and hive/category helpers
 *   - monitor preset factories and statistics reset behavior
 *   - in-process rule/protected-key/callback management
 *   - value analysis paths that do not require live kernel callbacks
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Core/Registry/RegistryMonitor.hpp"
#include "CoreRegistry_TestUtils.hpp"

namespace ShadowStrike::Core::Registry::Test {

class RegistryMonitorTest : public ::testing::Test {
protected:
    RegistryMonitor& monitor = RegistryMonitor::Instance();

    void SetUp() override {
        monitor.Shutdown();
        monitor.ResetStatistics();
        ClearRules();
        ClearProtectedKeys();
    }

    void TearDown() override {
        ClearRules();
        ClearProtectedKeys();
        monitor.Shutdown();
    }

private:
    void ClearRules() {
        for (const auto& rule : monitor.GetRules()) {
            (void)monitor.RemoveRule(rule.ruleId);
        }
    }

    void ClearProtectedKeys() {
        for (const auto& key : monitor.GetProtectedKeys()) {
            monitor.RemoveProtectedKey(key.keyPath);
        }
    }
};

TEST_F(RegistryMonitorTest, RegistryEventClassificationAndStaticKeyHelpersRemainStable) {
    RegistryEvent persistenceEvent;
    persistenceEvent.keyPath =
        L"\\Registry\\User\\S-1-5-21-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    EXPECT_TRUE(persistenceEvent.IsPersistenceKey());
    EXPECT_EQ(persistenceEvent.GetCategory(), KeyCategory::Persistence);
    EXPECT_EQ(persistenceEvent.GetHive(), L"HKCU");

    RegistryEvent serviceEvent;
    serviceEvent.keyPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\ShadowStrike";
    EXPECT_TRUE(serviceEvent.IsServiceKey());
    EXPECT_EQ(serviceEvent.GetCategory(), KeyCategory::System);
    EXPECT_EQ(serviceEvent.GetHive(), L"HKLM");

    RegistryEvent securityEvent;
    securityEvent.keyPath = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender";
    EXPECT_TRUE(securityEvent.IsSecurityKey());
    EXPECT_EQ(securityEvent.GetCategory(), KeyCategory::Security);

    RegistryEvent comEvent;
    comEvent.keyPath =
        L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32";
    EXPECT_TRUE(comEvent.IsCOMKey());
    EXPECT_EQ(comEvent.GetCategory(), KeyCategory::COM);
    EXPECT_EQ(comEvent.GetHive(), L"HKLM");

    RegistryEvent networkEvent;
    networkEvent.keyPath =
        L"\\Registry\\User\\S-1-5-21-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
    EXPECT_TRUE(networkEvent.IsNetworkKey());
    EXPECT_EQ(networkEvent.GetCategory(), KeyCategory::Network);

    RegistryEvent shellEvent;
    shellEvent.keyPath = L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";
    EXPECT_EQ(shellEvent.GetCategory(), KeyCategory::Shell);

    RegistryEvent driverEvent;
    driverEvent.keyPath = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Drivers\\Null";
    EXPECT_EQ(driverEvent.GetCategory(), KeyCategory::Driver);

    RegistryEvent mixedCaseHiveEvent;
    mixedCaseHiveEvent.keyPath = L"hKeY_cUrReNt_UsEr\\Software\\ShadowStrike";
    EXPECT_EQ(mixedCaseHiveEvent.GetHive(), L"HKCU");

    RegistryEvent unknownEvent;
    unknownEvent.keyPath = L"\\Registry\\A\\B";
    EXPECT_EQ(unknownEvent.GetCategory(), KeyCategory::Unknown);
    EXPECT_EQ(unknownEvent.GetHive(), L"UNKNOWN");

    EXPECT_TRUE(RegistryMonitor::IsCriticalKey(
        L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute"));
    EXPECT_TRUE(RegistryMonitor::IsCriticalKey(
        L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip"));
    EXPECT_FALSE(RegistryMonitor::IsCriticalKey(
        L"HKCU\\Software\\ShadowStrike\\Tests"));

    EXPECT_EQ(
        RegistryMonitor::GetKeyCategory(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender"),
        KeyCategory::Security);
}

TEST_F(RegistryMonitorTest, ConfigFactoriesAndStatisticsPreserveExpectedSecurityModes) {
    const auto defaults = RegistryMonitorConfig::CreateDefault();
    const auto highSecurity = RegistryMonitorConfig::CreateHighSecurity();
    const auto performance = RegistryMonitorConfig::CreatePerformance();
    const auto forensic = RegistryMonitorConfig::CreateForensic();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_TRUE(defaults.useKernelCallback);
    EXPECT_FALSE(defaults.useUserModeHooks);
    EXPECT_FALSE(defaults.monitorSecurity);
    EXPECT_FALSE(defaults.monitorTransactions);
    EXPECT_TRUE(defaults.detectFileless);
    EXPECT_TRUE(defaults.detectPersistence);
    EXPECT_TRUE(defaults.detectSecurityChanges);
    EXPECT_TRUE(defaults.selfDefenseEnabled);
    EXPECT_FALSE(defaults.deception.enabled);
    EXPECT_TRUE(defaults.logBlockedOnly);

    EXPECT_TRUE(highSecurity.monitorSecurity);
    EXPECT_TRUE(highSecurity.monitorTransactions);
    EXPECT_EQ(highSecurity.largeValueThreshold, 32u * 1024u);
    EXPECT_TRUE(highSecurity.deception.enabled);
    EXPECT_TRUE(highSecurity.deception.honeypotEnabled);
    EXPECT_TRUE(highSecurity.deception.fakeSuccessEnabled);
    EXPECT_TRUE(highSecurity.logAllOperations);
    EXPECT_FALSE(highSecurity.logBlockedOnly);

    EXPECT_FALSE(performance.monitorDeleteValue);
    EXPECT_FALSE(performance.monitorRename);
    EXPECT_FALSE(performance.monitorLoadHive);
    EXPECT_FALSE(performance.analyzeValues);
    EXPECT_FALSE(performance.detectFileless);
    EXPECT_EQ(performance.eventQueueSize, 20000u);
    EXPECT_EQ(performance.workerThreads, 4u);
    EXPECT_FALSE(performance.logPersistenceKeys);

    EXPECT_TRUE(forensic.useUserModeHooks);
    EXPECT_TRUE(forensic.monitorSecurity);
    EXPECT_TRUE(forensic.monitorTransactions);
    EXPECT_FALSE(forensic.selfDefenseEnabled);
    EXPECT_TRUE(forensic.logAllOperations);

    RegistryMonitorStatistics stats;
    stats.totalEvents.store(10, std::memory_order_relaxed);
    stats.createKeyEvents.store(1, std::memory_order_relaxed);
    stats.blockedOperations.store(2, std::memory_order_relaxed);
    stats.persistenceAttempts.store(3, std::memory_order_relaxed);
    stats.alertsGenerated.store(4, std::memory_order_relaxed);
    stats.avgCallbackTimeUs.store(5, std::memory_order_relaxed);
    stats.maxCallbackTimeUs.store(6, std::memory_order_relaxed);
    stats.droppedEvents.store(7, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.totalEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.createKeyEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.blockedOperations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.persistenceAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.alertsGenerated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.avgCallbackTimeUs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.maxCallbackTimeUs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.droppedEvents.load(std::memory_order_relaxed), 0u);
}

TEST_F(RegistryMonitorTest, AnalyzeValueDetectsDeterministicRiskSignalsWithoutLiveMonitoring) {
    const std::vector<uint8_t> expandPath =
        WideStringToRegistryBytes(L"%SystemRoot%\\System32\\cmd.exe");
    const ValueAnalysis expandAnalysis =
        monitor.AnalyzeValue(expandPath, RegistryValueType::EXPAND_SZ);

    EXPECT_TRUE(expandAnalysis.containsPath);
    EXPECT_TRUE(ContainsString(expandAnalysis.riskFactors, "Contains expandable environment variables"));
    EXPECT_FALSE(expandAnalysis.extractedPaths.empty());

    const std::vector<uint8_t> urlValue =
        WideStringToRegistryBytes(L"https://shadowstrike.dev/payload");
    const ValueAnalysis urlAnalysis =
        monitor.AnalyzeValue(urlValue, RegistryValueType::SZ);

    EXPECT_TRUE(urlAnalysis.containsUrl);
    ASSERT_EQ(urlAnalysis.extractedUrls.size(), 1u);
    EXPECT_EQ(urlAnalysis.extractedUrls.front(), "https://shadowstrike.dev/payload");

    std::vector<uint8_t> binaryBlob = HighEntropyBytes(2048);
    binaryBlob[0] = 'M';
    binaryBlob[1] = 'Z';
    const ValueAnalysis binaryAnalysis =
        monitor.AnalyzeValue(binaryBlob, RegistryValueType::BINARY);

    EXPECT_TRUE(binaryAnalysis.isBinaryBlob);
    EXPECT_TRUE(binaryAnalysis.containsExecutable);
    EXPECT_TRUE(binaryAnalysis.isHighEntropy);
    EXPECT_GE(static_cast<int>(binaryAnalysis.risk), static_cast<int>(RiskLevel::Medium));
    EXPECT_TRUE(ContainsString(binaryAnalysis.riskFactors, "Large binary blob"));
    EXPECT_TRUE(ContainsString(binaryAnalysis.riskFactors, "Contains executable signature"));
}

TEST_F(RegistryMonitorTest, RuleProtectionAndCallbackContractsRemainInProcess) {
    RegistryRule rule;
    rule.name = "Block ShadowStrike Self Defense";
    rule.keyPathPattern = L"HKLM\\Software\\ShadowStrike";
    rule.action = RuleAction::Block;
    rule.verdict = RegistryVerdict::Block;

    const uint64_t ruleId = monitor.AddRule(rule);
    EXPECT_NE(ruleId, 0u);

    const auto rules = monitor.GetRules();
    ASSERT_EQ(rules.size(), 1u);
    EXPECT_EQ(rules.front().ruleId, ruleId);
    EXPECT_TRUE(rules.front().enabled);

    EXPECT_TRUE(monitor.SetRuleEnabled(ruleId, false));
    EXPECT_FALSE(monitor.SetRuleEnabled(0xFFFFFFFFull, false));
    EXPECT_FALSE(monitor.RemoveRule(0xFFFFFFFFull));

    const std::wstring protectedKey = L"HKLM\\Software\\ShadowStrike\\SelfDefense";
    monitor.AddProtectedKey(protectedKey);
    EXPECT_TRUE(monitor.IsProtectedKey(protectedKey));
    EXPECT_TRUE(monitor.IsProtectedKey(protectedKey + L"\\SubKey"));
    EXPECT_FALSE(monitor.IsProtectedKey(L"HKLM\\Software\\ShadowStrike\\SelfDefense2"));
    EXPECT_FALSE(monitor.GetProtectedKeys().empty());
    monitor.RemoveProtectedKey(L"hklm\\software\\shadowstrike\\selfdefense");
    EXPECT_FALSE(monitor.IsProtectedKey(protectedKey));

    const uint64_t alertCallbackId = monitor.RegisterAlertCallback([](const RegistryAlert&) {});
    const uint64_t eventCallbackId =
        monitor.RegisterEventCallback([](const RegistryEvent&, RegistryVerdict) {});
    const uint64_t valueCallbackId =
        monitor.RegisterValueCallback([](const RegistryEvent&, const ValueAnalysis&) {});

    EXPECT_NE(alertCallbackId, 0u);
    EXPECT_NE(eventCallbackId, 0u);
    EXPECT_NE(valueCallbackId, 0u);

    EXPECT_TRUE(monitor.UnregisterCallback(alertCallbackId));
    EXPECT_TRUE(monitor.UnregisterCallback(eventCallbackId));
    EXPECT_TRUE(monitor.UnregisterCallback(valueCallbackId));
    EXPECT_FALSE(monitor.UnregisterCallback(valueCallbackId));
    EXPECT_TRUE(monitor.GetRecentEvents().empty());
}

TEST_F(RegistryMonitorTest, AnalyzeValueAndProcessEventBoundariesStayDeterministic) {
    const ValueAnalysis boundaryBinaryAnalysis =
        monitor.AnalyzeValue(HighEntropyBytes(1024), RegistryValueType::BINARY);
    EXPECT_FALSE(boundaryBinaryAnalysis.isBinaryBlob);

    const ValueAnalysis largeBinaryAnalysis =
        monitor.AnalyzeValue(HighEntropyBytes(1025), RegistryValueType::BINARY);
    EXPECT_TRUE(largeBinaryAnalysis.isBinaryBlob);
    EXPECT_TRUE(ContainsString(largeBinaryAnalysis.riskFactors, "Large binary blob"));

    std::wstring cloakedValue = L"C:\\Temp\\svc.exe";
    cloakedValue.push_back(L'\0');
    cloakedValue += L"--shadow";
    const ValueAnalysis cloakedAnalysis =
        monitor.AnalyzeValue(WideStringToRegistryBytes(cloakedValue), RegistryValueType::SZ);
    EXPECT_TRUE(cloakedAnalysis.containsPath);
    EXPECT_FALSE(cloakedAnalysis.extractedPaths.empty());
    EXPECT_TRUE(ContainsString(cloakedAnalysis.riskFactors, "Embedded null bytes (cloaking attempt)"));

    const ValueAnalysis plainExpandAnalysis =
        monitor.AnalyzeValue(
            WideStringToRegistryBytes(L"C:\\ProgramData\\ShadowStrike\\sensor.exe"),
            RegistryValueType::EXPAND_SZ);
    EXPECT_TRUE(plainExpandAnalysis.containsPath);
    ASSERT_EQ(plainExpandAnalysis.extractedPaths.size(), 1u);
    EXPECT_EQ(plainExpandAnalysis.extractedPaths.front(), L"C:\\ProgramData\\ShadowStrike\\sensor.exe");
    EXPECT_FALSE(ContainsString(
        plainExpandAnalysis.riskFactors,
        "Contains expandable environment variables"));

    RegistryEvent nullByteEvent;
    nullByteEvent.processId = 4;
    nullByteEvent.keyPath = L"HKLM\\Software\\ShadowStrike";
    nullByteEvent.keyPath.push_back(L'\0');
    nullByteEvent.keyPath += L"\\Hidden";
    EXPECT_EQ(monitor.ProcessEvent(nullByteEvent), RegistryVerdict::Block);
    EXPECT_TRUE(monitor.GetRecentEvents().empty());

    RegistryEvent firstAllowed;
    firstAllowed.processId = 10;
    firstAllowed.keyPath = L"HKCU\\Software\\ShadowStrike\\One";
    firstAllowed.operation = RegistryOp::QueryValue;
    EXPECT_EQ(monitor.ProcessEvent(firstAllowed), RegistryVerdict::Allow);

    RegistryEvent secondAllowed;
    secondAllowed.processId = 11;
    secondAllowed.keyPath = L"HKCU\\Software\\ShadowStrike\\Two";
    secondAllowed.operation = RegistryOp::QueryValue;
    EXPECT_EQ(monitor.ProcessEvent(secondAllowed), RegistryVerdict::Allow);

    auto recentEvents = monitor.GetRecentEvents(1);
    ASSERT_EQ(recentEvents.size(), 1u);
    EXPECT_EQ(recentEvents.front().keyPath, secondAllowed.keyPath);

    monitor.AddProtectedKey(L"HKLM\\Software\\ShadowStrike");
    EXPECT_TRUE(monitor.IsProtectedKey(L"HKLM\\Software\\ShadowStrike\\Config"));
    EXPECT_FALSE(monitor.IsProtectedKey(L"HKLM\\Software\\ShadowStrike2"));

    RegistryEvent protectedEvent;
    protectedEvent.processId = 12;
    protectedEvent.processName = "tamper.exe";
    protectedEvent.keyPath = L"HKLM\\Software\\ShadowStrike\\Config";
    protectedEvent.operation = RegistryOp::SetValue;
    EXPECT_EQ(monitor.ProcessEvent(protectedEvent), RegistryVerdict::Block);

    recentEvents = monitor.GetRecentEvents(10);
    ASSERT_EQ(recentEvents.size(), 2u);
    EXPECT_EQ(recentEvents.front().keyPath, secondAllowed.keyPath);
    EXPECT_EQ(recentEvents.back().keyPath, firstAllowed.keyPath);
}

}  // namespace ShadowStrike::Core::Registry::Test
