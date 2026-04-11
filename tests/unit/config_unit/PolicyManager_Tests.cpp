/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for enterprise policy management.
 *
 * Focus:
 *   - policy/configuration validation and serialization
 *   - parsing, enforcement, violations, and callbacks
 *   - offline cache and sync behavior under local-only conditions
 */

#include "pch.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

#include "../../../src/PhantomCore/Config/PolicyManager.hpp"
#include "../../../src/PhantomCore/Config/ConfigManager.hpp"
#include "Config_TestUtils.hpp"

namespace ShadowStrike::Config::Test {

namespace {

Policy MakePolicy(std::string id,
                  std::string settingKey,
                  PolicyValue value,
                  bool mandatory = true,
                  uint32_t priority = 100,
                  PolicyType type = PolicyType::Custom) {
    Policy policy;
    policy.id = std::move(id);
    policy.name = "Unit Test Policy";
    policy.description = "Test policy";
    policy.type = type;
    policy.state = PolicyState::Pending;
    policy.enforcement = mandatory ? EnforcementLevel::Mandatory : EnforcementLevel::Advisory;
    policy.isMandatory = mandatory;
    policy.priority = priority;
    policy.version = 1;
    policy.effectiveFrom = std::chrono::system_clock::now();
    policy.createdAt = policy.effectiveFrom;
    policy.modifiedAt = policy.effectiveFrom;
    policy.createdBy = "unit-test";

    PolicySetting setting;
    setting.key = std::move(settingKey);
    setting.displayName = "Setting";
    setting.value = std::move(value);
    setting.enforcement = mandatory ? EnforcementLevel::Mandatory : EnforcementLevel::Advisory;
    setting.description = "Managed setting";
    policy.settings.emplace(setting.key, setting);
    return policy;
}

}  // namespace

class PolicyManagerTest : public ::testing::Test {
protected:
    ScopedTempDir tempDir{L"ShadowStrike_PolicyTests_"};
    PolicyManager& manager = PolicyManager::Instance();
    ConfigManager& configMgr = ConfigManager::Instance();

    void SetUp() override {
        // Initialize ConfigManager first (PolicyManager depends on it for compliance checks)
        configMgr.Shutdown();
        ConfigManagerConfiguration cfgConfig;
        // Use empty databasePath for in-memory operation
        (void)configMgr.Initialize(cfgConfig);

        manager.Shutdown();

        PolicyManagerConfiguration config;
        config.enableAutoSync = false;
        config.enableOfflineCache = true;
        config.offlineCachePath = tempDir.File(L"policy-cache.json");
        config.maxViolationHistory = 64;
        ASSERT_TRUE(manager.Initialize(config));
        manager.ResetStatistics();
    }

    void TearDown() override {
        // Shutdown clears all state including callbacks
        manager.Shutdown();
        configMgr.Shutdown();
    }
};

TEST_F(PolicyManagerTest, ConfigurationStructsAndNameLookupsCoverPublicContracts) {
    PolicyManagerConfiguration config;
    config.enableOfflineCache = true;
    config.offlineCachePath = tempDir.File(L"cache.json");
    EXPECT_TRUE(config.IsValid());

    config.syncIntervalSeconds = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.enableOfflineCache = true;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxViolationHistory = 0;
    EXPECT_FALSE(config.IsValid());

    PolicySetting setting;
    setting.key = "scan.mode";
    setting.displayName = "Scan Mode";
    setting.value = std::string("strict");
    setting.enforcement = EnforcementLevel::Mandatory;
    setting.description = "Policy controlled scan mode";
    const auto settingJson = ParseJson(setting.ToJson());
    EXPECT_EQ(settingJson.at("key").get<std::string>(), "scan.mode");
    EXPECT_EQ(settingJson.at("displayName").get<std::string>(), "Scan Mode");
    EXPECT_EQ(settingJson.at("value").get<std::string>(), "strict");
    EXPECT_EQ(settingJson.at("enforcement").get<uint8_t>(),
              static_cast<uint8_t>(EnforcementLevel::Mandatory));

    Policy validPolicy = MakePolicy("policy-1", "scan.mode", std::string("strict"));
    EXPECT_TRUE(validPolicy.IsValid());
    EXPECT_FALSE(validPolicy.IsExpired());

    Policy expiredPolicy = validPolicy;
    expiredPolicy.expiresAt = std::chrono::system_clock::now() - std::chrono::minutes(1);
    EXPECT_TRUE(expiredPolicy.IsExpired());
    EXPECT_FALSE(expiredPolicy.IsValid());

    Policy namelessPolicy = validPolicy;
    namelessPolicy.name.clear();
    EXPECT_FALSE(namelessPolicy.IsValid());

    const auto policyJson = ParseJson(validPolicy.ToJson());
    EXPECT_EQ(policyJson.at("id").get<std::string>(), "policy-1");
    EXPECT_EQ(policyJson.at("settings").at("scan.mode").at("value").get<std::string>(), "strict");

    PolicyViolation violation;
    violation.violationId = 9;
    violation.policyId = "policy-1";
    violation.settingKey = "scan.mode";
    violation.expectedValue = std::string("strict");
    violation.actualValue = std::string("relaxed");
    violation.timestamp = std::chrono::system_clock::time_point{std::chrono::seconds(60)};
    violation.machineName = "machine01";
    violation.userName = "alice";
    violation.processName = "tool.exe";
    violation.action = ViolationAction::Block;
    const auto violationJson = ParseJson(violation.ToJson());
    EXPECT_EQ(violationJson.at("policyId").get<std::string>(), "policy-1");
    EXPECT_EQ(violationJson.at("processName").get<std::string>(), "tool.exe");
    EXPECT_EQ(violationJson.at("action").get<uint8_t>(), static_cast<uint8_t>(ViolationAction::Block));

    ComplianceReport report;
    report.reportId = 4;
    report.machineName = "machine01";
    report.overallStatus = ComplianceStatus::PartiallyCompliant;
    report.totalPolicies = 4;
    report.compliantCount = 3;
    report.nonCompliantCount = 1;
    report.generatedAt = std::chrono::system_clock::time_point{std::chrono::seconds(90)};
    report.policyCompliance.emplace("policy-1", ComplianceStatus::Compliant);
    report.pendingViolations.push_back(violation);
    EXPECT_DOUBLE_EQ(report.GetCompliancePercentage(), 75.0);
    const auto reportJson = ParseJson(report.ToJson());
    EXPECT_EQ(reportJson.at("overallStatus").get<std::string>(), "PartiallyCompliant");
    EXPECT_EQ(reportJson.at("compliancePercentage").get<double>(), 75.0);
    EXPECT_EQ(reportJson.at("pendingViolations").size(), 1u);

    ComplianceReport emptyReport;
    EXPECT_DOUBLE_EQ(emptyReport.GetCompliancePercentage(), 100.0);

    PolicySyncResult syncResult;
    syncResult.success = true;
    syncResult.newPolicies = 2;
    syncResult.updatedPolicies = 1;
    syncResult.errors = {"none"};
    const auto syncJson = ParseJson(syncResult.ToJson());
    EXPECT_TRUE(syncJson.at("success").get<bool>());
    EXPECT_EQ(syncJson.at("newPolicies").get<uint32_t>(), 2u);
    EXPECT_EQ(syncJson.at("errors").size(), 1u);

    PolicyStatistics stats;
    stats.policiesApplied.store(7, std::memory_order_relaxed);
    stats.violationsDetected.store(2, std::memory_order_relaxed);
    stats.byPolicyType[static_cast<size_t>(PolicyType::Custom)].store(3, std::memory_order_relaxed);
    const auto statsJson = ParseJson(stats.ToJson());
    EXPECT_EQ(statsJson.at("policiesApplied").get<uint64_t>(), 7u);
    EXPECT_EQ(statsJson.at("violationsDetected").get<uint64_t>(), 2u);
    EXPECT_EQ(statsJson.at("byPolicyType").at(static_cast<size_t>(PolicyType::Custom)).get<uint64_t>(), 3u);
    stats.Reset();
    EXPECT_EQ(ParseJson(stats.ToJson()).at("policiesApplied").get<uint64_t>(), 0u);

    EXPECT_EQ(GetEnforcementLevelName(EnforcementLevel::AuditOnly), "AuditOnly");
    EXPECT_EQ(GetEnforcementLevelName(static_cast<EnforcementLevel>(0xFF)), "Unknown");
    EXPECT_EQ(GetPolicyTypeName(PolicyType::Firewall), "Firewall");
    EXPECT_EQ(GetPolicyStateName(PolicyState::Superseded), "Superseded");
    EXPECT_EQ(GetComplianceStatusName(ComplianceStatus::NotApplicable), "NotApplicable");
    EXPECT_EQ(GetViolationActionName(ViolationAction::Remediate), "Remediate");

    EXPECT_EQ(PolicyValueToString(PolicyValue{true}), "true");
    EXPECT_EQ(PolicyValueToString(PolicyValue{12.5}), "12.5");
    EXPECT_EQ(PolicyValueToString(PolicyValue{std::vector<std::string>{"a", "b"}}), "[\"a\",\"b\"]");
    EXPECT_EQ(PolicyValueToString(PolicyValue{std::map<std::string, std::string>{{"mode", "strict"}}}),
              "{\"mode\":\"strict\"}");
    EXPECT_EQ(PolicyManager::GetVersionString(), "3.0.0");
}

TEST_F(PolicyManagerTest, ParsePolicyFromJsonAndXmlRestoresExpectedFields) {
    const std::string json = R"({
        "id":"json-policy",
        "name":"Imported JSON Policy",
        "description":"json import",
        "type":13,
        "state":1,
        "enforcement":0,
        "isMandatory":true,
        "priority":250,
        "version":4,
        "effectiveFrom":"2026-01-01T12:00:00Z",
        "createdAt":"2026-01-01T12:00:00Z",
        "modifiedAt":"2026-01-02T12:00:00Z",
        "createdBy":"console",
        "signature":"0102ff",
        "settings":{
            "scan.mode":{
                "displayName":"Scan Mode",
                "value":"strict",
                "enforcement":0,
                "description":"managed"
            }
        },
        "targetGroups":["servers"]
    })";

    const auto parsedJsonPolicy = ParsePolicyFromJson(json);
    ASSERT_TRUE(parsedJsonPolicy.has_value());
    EXPECT_EQ(parsedJsonPolicy->id, "json-policy");
    EXPECT_EQ(parsedJsonPolicy->name, "Imported JSON Policy");
    EXPECT_TRUE(parsedJsonPolicy->isMandatory);
    EXPECT_EQ(parsedJsonPolicy->priority, 250u);
    EXPECT_EQ(parsedJsonPolicy->settings.at("scan.mode").displayName, "Scan Mode");
    EXPECT_EQ(std::get<std::string>(parsedJsonPolicy->settings.at("scan.mode").value), "strict");
    EXPECT_THAT(parsedJsonPolicy->signature,
                ::testing::ElementsAre(static_cast<uint8_t>(0x01),
                                       static_cast<uint8_t>(0x02),
                                       static_cast<uint8_t>(0xFF)));
    EXPECT_TRUE(parsedJsonPolicy->targetGroups.contains("servers"));

    const std::string xml = R"(<policy>
  <id>xml-policy</id>
  <name>Imported XML Policy</name>
  <description>xml import</description>
  <createdBy>console</createdBy>
  <type>13</type>
  <state>1</state>
  <enforcement>0</enforcement>
  <priority>7</priority>
  <version>2</version>
  <isMandatory>true</isMandatory>
  <effectiveFrom>2026-01-03T00:00:00Z</effectiveFrom>
  <createdAt>2026-01-03T00:00:00Z</createdAt>
  <modifiedAt>2026-01-03T01:00:00Z</modifiedAt>
  <settings>
    <item>
      <key>network.mode</key>
      <displayName>Network Mode</displayName>
      <value>locked</value>
      <enforcement>0</enforcement>
      <description>managed</description>
    </item>
  </settings>
  <targetMachines><item>host01</item></targetMachines>
</policy>)";

    const auto parsedXmlPolicy = ParsePolicyFromXml(xml);
    ASSERT_TRUE(parsedXmlPolicy.has_value());
    EXPECT_EQ(parsedXmlPolicy->id, "xml-policy");
    EXPECT_EQ(parsedXmlPolicy->name, "Imported XML Policy");
    EXPECT_TRUE(parsedXmlPolicy->isMandatory);
    EXPECT_EQ(parsedXmlPolicy->priority, 7u);
    EXPECT_EQ(parsedXmlPolicy->settings.at("network.mode").description, "managed");
    EXPECT_TRUE(parsedXmlPolicy->targetMachines.contains("host01"));

    EXPECT_FALSE(ParsePolicyFromJson("").has_value());
    EXPECT_FALSE(ParsePolicyFromXml("").has_value());
}

TEST_F(PolicyManagerTest, ApplyQueryEnforcementAndViolationLifecycleRemainConsistent) {
    std::vector<std::pair<std::string, bool>> policyChangeEvents;
    std::vector<PolicyViolation> violationEvents;

    const auto policyCallbackId = manager.RegisterPolicyChangeCallback(
        [&policyChangeEvents](const Policy& policy, const bool added) {
            policyChangeEvents.emplace_back(policy.id, added);
        });
    const auto violationCallbackId = manager.RegisterViolationCallback(
        [&violationEvents](const PolicyViolation& violation) {
            violationEvents.push_back(violation);
        });

    Policy primary = MakePolicy("policy-primary", "scan.mode", std::string("strict"), true, 10, PolicyType::Protection);
    Policy stronger = MakePolicy("policy-stronger", "scan.mode", std::string("locked"), true, 80, PolicyType::Protection);
    Policy advisory = MakePolicy("policy-advisory", "telemetry.level", std::string("audit"), false, 1, PolicyType::Logging);
    Policy invalid = primary;
    invalid.settings.clear();
    Policy signedPolicy = primary;
    signedPolicy.id = "policy-signed";
    signedPolicy.signature = {0xAA, 0xBB};

    ASSERT_TRUE(manager.ApplyPolicy(primary));
    ASSERT_TRUE(manager.ApplyPolicy(stronger));
    ASSERT_TRUE(manager.ApplyPolicy(advisory));
    EXPECT_FALSE(manager.ApplyPolicy(invalid));
    EXPECT_FALSE(manager.ApplyPolicy(signedPolicy));

    ASSERT_TRUE(manager.GetPolicy("policy-primary").has_value());
    EXPECT_EQ(manager.GetAllPolicies().size(), 3u);
    EXPECT_EQ(manager.GetPoliciesByType(PolicyType::Protection).size(), 2u);
    EXPECT_EQ(manager.GetActivePolicies().size(), 3u);
    EXPECT_EQ(manager.GetMandatoryPolicies().size(), 2u);

    EXPECT_TRUE(manager.IsEnforced("scan.mode"));
    EXPECT_FALSE(manager.IsEnforced("telemetry.level"));
    ASSERT_TRUE(manager.GetEnforcedValue("scan.mode").has_value());
    EXPECT_EQ(std::get<std::string>(*manager.GetEnforcedValue("scan.mode")), "locked");
    EXPECT_EQ(manager.GetPolicyValue("scan.mode"), "locked");
    EXPECT_EQ(manager.GetEnforcementLevel("scan.mode"), EnforcementLevel::Mandatory);
    EXPECT_TRUE(manager.ValidateSetting("scan.mode", PolicyValue{std::string("locked")}));
    EXPECT_FALSE(manager.ValidateSetting("scan.mode", PolicyValue{std::string("balanced")}));

    const auto violations = manager.GetPendingViolations();
    ASSERT_EQ(violations.size(), 1u);
    // Violation comes from highest priority policy (policy-stronger, priority 80)
    EXPECT_EQ(violations.front().policyId, "policy-stronger");
    EXPECT_EQ(violations.front().settingKey, "scan.mode");
    ASSERT_EQ(violationEvents.size(), 1u);
    EXPECT_EQ(violationEvents.front().policyId, "policy-stronger");

    EXPECT_TRUE(manager.RemediateViolation(violations.front().violationId));
    EXPECT_TRUE(manager.GetPendingViolations().empty());

    EXPECT_TRUE(manager.DeactivatePolicy("policy-primary"));
    ASSERT_TRUE(manager.GetPolicy("policy-primary").has_value());
    EXPECT_EQ(manager.GetPolicy("policy-primary")->state, PolicyState::Superseded);
    EXPECT_TRUE(manager.ActivatePolicy("policy-primary"));
    EXPECT_EQ(manager.GetPolicy("policy-primary")->state, PolicyState::Active);
    EXPECT_FALSE(manager.ActivatePolicy("missing-policy"));

    EXPECT_TRUE(manager.RemovePolicy("policy-advisory"));
    EXPECT_FALSE(manager.RemovePolicy("policy-advisory"));
    EXPECT_EQ(manager.GetAllPolicies().size(), 2u);

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.policiesApplied.load(std::memory_order_relaxed), 3u);
    EXPECT_GE(stats.violationsDetected.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(stats.enforcementChecks.load(std::memory_order_relaxed), 1u);
    EXPECT_GE(policyChangeEvents.size(), 4u);

    manager.UnregisterCallback(policyCallbackId);
    manager.UnregisterCallback(violationCallbackId);
}

TEST_F(PolicyManagerTest, BatchApplyOfflineCacheSyncAndSelfTestRemainOperational) {
    Policy validNew = MakePolicy("batch-new", "engine.mode", std::string("strict"), true, 10, PolicyType::Custom);
    Policy validUpdated = MakePolicy("batch-updated", "engine.retry", int64_t{3}, true, 20, PolicyType::Protection);
    Policy invalid = validNew;
    invalid.id = "batch-invalid";
    invalid.settings.clear();

    ASSERT_TRUE(manager.ApplyPolicy(validUpdated));

    const auto batchResult = manager.ApplyPolicies({validNew, validUpdated, invalid});
    EXPECT_FALSE(batchResult.success);
    EXPECT_EQ(batchResult.newPolicies, 1u);
    EXPECT_EQ(batchResult.updatedPolicies, 1u);
    EXPECT_EQ(batchResult.failedPolicies, 1u);
    EXPECT_EQ(batchResult.errors.size(), 1u);

    ASSERT_TRUE(manager.SaveToOfflineCache());
    const auto cached = ReadJsonFile(tempDir.File(L"policy-cache.json"));
    ASSERT_TRUE(cached.contains("policies"));
    EXPECT_GE(cached.at("policies").size(), 2u);

    EXPECT_TRUE(manager.RemovePolicy("batch-new"));
    EXPECT_TRUE(manager.RemovePolicy("batch-updated"));
    EXPECT_TRUE(manager.GetAllPolicies().empty());

    ASSERT_TRUE(manager.LoadFromOfflineCache());
    EXPECT_TRUE(manager.GetPolicy("batch-new").has_value());
    EXPECT_TRUE(manager.GetPolicy("batch-updated").has_value());

    uint32_t syncCallbackCount = 0;
    const auto syncCallbackId = manager.RegisterSyncCallback(
        [&syncCallbackCount](const PolicySyncResult& result) {
            if (result.success) {
                ++syncCallbackCount;
            }
        });

    const auto syncResult = manager.ForceSyncNow();
    EXPECT_TRUE(syncResult.success);
    EXPECT_TRUE(manager.GetLastSyncTime().has_value());
    EXPECT_EQ(syncCallbackCount, 1u);
    EXPECT_FALSE(manager.IsSyncInProgress());

    manager.UnregisterCallback(syncCallbackId);
    manager.ClearOfflineCache();
    EXPECT_FALSE(manager.LoadFromOfflineCache());
    EXPECT_TRUE(manager.SelfTest());
}

TEST_F(PolicyManagerTest, ComplianceViolationHistoryAndOfflineFailuresStayDeterministic) {
    EXPECT_EQ(manager.CheckCompliance(), ComplianceStatus::NotApplicable);
    EXPECT_DOUBLE_EQ(manager.GetCompliancePercentage(), 100.0);

    manager.Shutdown();

    PolicyManagerConfiguration config;
    config.enableAutoSync = false;
    config.enableOfflineCache = true;
    config.offlineCachePath = tempDir.File(L"policy-cache.json");
    config.maxViolationHistory = 2;
    ASSERT_TRUE(manager.Initialize(config));

    Policy mandatory = MakePolicy("policy-required", "scan.mode", std::string("strict"), true, 50,
                                  PolicyType::Protection);
    ASSERT_TRUE(manager.ApplyPolicy(mandatory));

    const auto report = manager.GenerateComplianceReport();
    EXPECT_EQ(report.totalPolicies, 1u);
    EXPECT_EQ(report.compliantCount, 0u);
    EXPECT_EQ(report.nonCompliantCount, 1u);
    EXPECT_EQ(report.overallStatus, ComplianceStatus::NonCompliant);
    ASSERT_EQ(report.pendingViolations.size(), 1u);
    EXPECT_EQ(report.pendingViolations.front().settingKey, "scan.mode");
    EXPECT_EQ(report.pendingViolations.front().action, ViolationAction::Audit);

    EXPECT_FALSE(manager.ValidateSetting("scan.mode", PolicyValue{std::string("relaxed")}));
    EXPECT_FALSE(manager.ValidateSetting("scan.mode", PolicyValue{std::string("audit")}));
    EXPECT_FALSE(manager.ValidateSetting("scan.mode", PolicyValue{std::string("balanced")}));

    const auto violations = manager.GetPendingViolations();
    ASSERT_EQ(violations.size(), 2u);
    EXPECT_EQ(PolicyValueToString(violations.front().actualValue), "audit");
    EXPECT_EQ(PolicyValueToString(violations.back().actualValue), "balanced");

    EXPECT_TRUE(manager.RemediateViolation(violations.front().violationId));
    EXPECT_FALSE(manager.RemediateViolation(violations.front().violationId));

    WriteUtf8File(tempDir.File(L"policy-cache.json"), "{ invalid json");
    EXPECT_FALSE(manager.LoadFromOfflineCache());

    const auto syncResult = manager.ForceSyncNow();
    EXPECT_FALSE(syncResult.success);
    EXPECT_FALSE(syncResult.errors.empty());
    EXPECT_FALSE(manager.IsSyncInProgress());
}

}  // namespace ShadowStrike::Config::Test
