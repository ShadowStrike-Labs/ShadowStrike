/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Registry\SystemSettingsMonitor deterministic contracts.
 *
 * Focus:
 *   - configuration presets and statistics reset behavior
 *   - default-state accessors that remain in-process and deterministic
 *   - baseline, callback, and auto-remediation control surfaces
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Core/Registry/SystemSettingsMonitor.hpp"
#include "CoreRegistry_TestUtils.hpp"

namespace ShadowStrike::Core::Registry::Test {

class SystemSettingsMonitorTest : public ::testing::Test {
protected:
    SystemSettingsMonitor& monitor = SystemSettingsMonitor::Instance();
    TempDirectoryGuard temp{ L"ShadowStrike_SystemSettingsMonitor_UT" };

    void SetUp() override {
        monitor.Shutdown();
        monitor.ResetStatistics();
        monitor.SetAutoRemediation(false);
    }

    void TearDown() override {
        monitor.SetAutoRemediation(false);
        monitor.Shutdown();
    }
};

TEST_F(SystemSettingsMonitorTest, ConfigFactoriesAndStatisticsPreserveExpectedSecurityProfiles) {
    const auto defaults = SystemSettingsMonitorConfig::CreateDefault();
    const auto highSecurity = SystemSettingsMonitorConfig::CreateHighSecurity();
    const auto monitorOnly = SystemSettingsMonitorConfig::CreateMonitorOnly();

    EXPECT_TRUE(defaults.monitorUAC);
    EXPECT_TRUE(defaults.monitorDefender);
    EXPECT_TRUE(defaults.monitorFirewall);
    EXPECT_TRUE(defaults.monitorPolicy);
    EXPECT_FALSE(defaults.enableAutoRemediation);
    EXPECT_TRUE(defaults.remediateDefender);
    EXPECT_TRUE(defaults.remediateFirewall);
    EXPECT_EQ(defaults.minimumAlertSeverity, AlertSeverity::Medium);
    EXPECT_TRUE(defaults.useBaseline);
    EXPECT_TRUE(defaults.autoCreateBaseline);

    EXPECT_TRUE(highSecurity.enableAutoRemediation);
    EXPECT_TRUE(highSecurity.remediateUAC);
    EXPECT_TRUE(highSecurity.remediateDefender);
    EXPECT_TRUE(highSecurity.remediateFirewall);
    EXPECT_EQ(highSecurity.minimumAlertSeverity, AlertSeverity::Low);
    EXPECT_TRUE(highSecurity.alertOnAnyChange);
    EXPECT_TRUE(highSecurity.alertOnSecurityDegrade);

    EXPECT_FALSE(monitorOnly.enableAutoRemediation);
    EXPECT_FALSE(monitorOnly.remediateUAC);
    EXPECT_FALSE(monitorOnly.remediateDefender);
    EXPECT_FALSE(monitorOnly.remediateFirewall);
    EXPECT_EQ(monitorOnly.minimumAlertSeverity, AlertSeverity::Medium);
    EXPECT_FALSE(monitorOnly.alertOnAnyChange);

    SystemSettingsMonitorStatistics stats;
    stats.changesDetected.store(5, std::memory_order_relaxed);
    stats.securityDegrades.store(3, std::memory_order_relaxed);
    stats.alertsGenerated.store(2, std::memory_order_relaxed);
    stats.remediationsPerformed.store(1, std::memory_order_relaxed);
    stats.remediationsFailed.store(4, std::memory_order_relaxed);
    stats.uacChanges.store(6, std::memory_order_relaxed);
    stats.defenderChanges.store(7, std::memory_order_relaxed);
    stats.firewallChanges.store(8, std::memory_order_relaxed);
    stats.networkChanges.store(9, std::memory_order_relaxed);
    stats.shellChanges.store(10, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.changesDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.securityDegrades.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.alertsGenerated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.remediationsPerformed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.remediationsFailed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.uacChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.defenderChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.firewallChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.networkChanges.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.shellChanges.load(std::memory_order_relaxed), 0u);
}

TEST_F(SystemSettingsMonitorTest, DefaultStateAndBaselineContractsRemainDeterministic) {
    EXPECT_FALSE(monitor.IsMonitoring());

    const UACSettings uac = monitor.GetUACSettings();
    EXPECT_TRUE(uac.enabled);
    EXPECT_EQ(uac.level, UACLevel::NotifyChanges);
    EXPECT_FALSE(monitor.IsUACDisabled());
    EXPECT_EQ(monitor.GetUACLevel(), UACLevel::NotifyChanges);

    const DefenderSettings defender = monitor.GetDefenderSettings();
    EXPECT_TRUE(defender.enabled);
    EXPECT_TRUE(defender.realTimeProtection);
    EXPECT_FALSE(monitor.IsDefenderDisabled());
    EXPECT_FALSE(monitor.IsRealTimeProtectionDisabled());
    EXPECT_TRUE(monitor.GetDefenderExclusions().empty());

    const FirewallSettings firewall = monitor.GetFirewallSettings();
    EXPECT_TRUE(firewall.domainEnabled);
    EXPECT_TRUE(firewall.privateEnabled);
    EXPECT_TRUE(firewall.publicEnabled);
    EXPECT_FALSE(monitor.IsFirewallDisabled(FirewallProfile::Domain));
    EXPECT_FALSE(monitor.IsAnyFirewallDisabled());

    const ExploitProtection exploit = monitor.GetExploitProtection();
    EXPECT_TRUE(exploit.aslrEnabled);
    EXPECT_TRUE(exploit.depEnabled);
    EXPECT_FALSE(monitor.IsASLRDisabled());
    EXPECT_FALSE(monitor.IsDEPDisabled());

    const LSASettings lsa = monitor.GetLSASettings();
    EXPECT_FALSE(lsa.runAsPPL);
    EXPECT_FALSE(monitor.IsLSAPPLEnabled());

    const ProxySettings proxy = monitor.GetProxySettings();
    EXPECT_FALSE(proxy.proxyEnabled);
    EXPECT_FALSE(monitor.IsProxyEnabled());

    const DNSSettings dns = monitor.GetDNSSettings();
    EXPECT_TRUE(dns.useDHCP);
    EXPECT_FALSE(monitor.IsDNSSuspicious());

    const uint64_t baselineId = monitor.CreateBaseline("Core registry unit baseline");
    EXPECT_NE(baselineId, 0u);
    EXPECT_FALSE(monitor.GetBaseline(0xDEADBEEFull).has_value());

    const auto baseline = monitor.GetBaseline(baselineId);
    ASSERT_TRUE(baseline.has_value());
    EXPECT_EQ(baseline->snapshotId, baselineId);
    EXPECT_EQ(baseline->description, "Core registry unit baseline");

    EXPECT_FALSE(monitor.SetActiveBaseline(0xDEADBEEFull));
    EXPECT_FALSE(monitor.GetActiveBaseline().has_value());
    EXPECT_TRUE(monitor.SetActiveBaseline(baselineId));

    const auto activeBaseline = monitor.GetActiveBaseline();
    ASSERT_TRUE(activeBaseline.has_value());
    EXPECT_EQ(activeBaseline->snapshotId, baselineId);
    EXPECT_TRUE(monitor.CompareToBaseline(baselineId).empty());

    const ComplianceStatus compliance = monitor.CheckCompliance();
    EXPECT_TRUE(compliance.isCompliant);
    EXPECT_EQ(compliance.totalChecks, 6u);
    EXPECT_EQ(compliance.passedChecks, 6u);
    EXPECT_EQ(compliance.failedChecks, 0u);
    EXPECT_EQ(compliance.warnings, 0u);
    EXPECT_TRUE(compliance.failures.empty());
    EXPECT_TRUE(compliance.warningList.empty());

    const auto missingPolicyPath = temp.Path(L"missing-policy.json");
    const ComplianceStatus missingPolicy = monitor.CheckPolicyCompliance(missingPolicyPath.wstring());
    EXPECT_FALSE(missingPolicy.isCompliant);
    EXPECT_EQ(missingPolicy.totalChecks, 1u);
    EXPECT_EQ(missingPolicy.failedChecks, 1u);
    ASSERT_EQ(missingPolicy.failures.size(), 1u);
    EXPECT_NE(missingPolicy.failures.front().find("Policy file not found:"), std::string::npos);

    const auto policyPath = temp.WriteText(L"policy.json", "{}");
    const ComplianceStatus fileBackedCompliance = monitor.CheckPolicyCompliance(policyPath.wstring());
    EXPECT_TRUE(fileBackedCompliance.isCompliant);
    EXPECT_EQ(fileBackedCompliance.totalChecks, compliance.totalChecks);
    EXPECT_EQ(fileBackedCompliance.passedChecks, compliance.passedChecks);
}

TEST_F(SystemSettingsMonitorTest, AutoRemediationAndCallbackContractsRemainInProcess) {
    EXPECT_FALSE(monitor.IsAutoRemediationEnabled());
    monitor.SetAutoRemediation(true);
    EXPECT_TRUE(monitor.IsAutoRemediationEnabled());
    monitor.SetAutoRemediation(false);
    EXPECT_FALSE(monitor.IsAutoRemediationEnabled());
    EXPECT_TRUE(monitor.GetHistory().empty());
    EXPECT_TRUE(monitor.GetHistory(0).empty());
    EXPECT_TRUE(monitor.GetHistoryByCategory(SettingCategory::Security).empty());
    EXPECT_TRUE(monitor.GetActiveAlerts().empty());
    EXPECT_FALSE(monitor.AcknowledgeAlert(0xDEADBEEFull));
    monitor.ClearAlerts();
    EXPECT_FALSE(monitor.Remediate(0xDEADBEEFull));

    EXPECT_EQ(monitor.RegisterChangeCallback({}), 0u);
    EXPECT_EQ(monitor.RegisterAlertCallback({}), 0u);
    EXPECT_EQ(monitor.RegisterComplianceCallback({}), 0u);

    const uint64_t changeCallbackId =
        monitor.RegisterChangeCallback([](const SettingChange&) {});
    const uint64_t alertCallbackId =
        monitor.RegisterAlertCallback([](const SecurityAlert&) {});
    const uint64_t complianceCallbackId =
        monitor.RegisterComplianceCallback([](const ComplianceStatus&) {});

    EXPECT_NE(changeCallbackId, 0u);
    EXPECT_NE(alertCallbackId, 0u);
    EXPECT_NE(complianceCallbackId, 0u);

    EXPECT_TRUE(monitor.UnregisterCallback(changeCallbackId));
    EXPECT_TRUE(monitor.UnregisterCallback(alertCallbackId));
    EXPECT_TRUE(monitor.UnregisterCallback(complianceCallbackId));
    EXPECT_FALSE(monitor.UnregisterCallback(complianceCallbackId));
}

}  // namespace ShadowStrike::Core::Registry::Test
