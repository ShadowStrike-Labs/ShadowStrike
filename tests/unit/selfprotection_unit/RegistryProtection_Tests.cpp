#include "../../../src/pch.h"
#include <nlohmann/json.hpp>
#include "../../../src/Shared_modules/SelfProtection/RegistryProtection.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(RegistryProtectionTests, ProtectionModesAndValidationRemainConsistent) {
    const RegistryProtectionConfiguration disabled =
        RegistryProtectionConfiguration::FromMode(RegistryProtectionMode::Disabled);
    EXPECT_FALSE(disabled.enableKernelCallbacks);
    EXPECT_FALSE(disabled.enableUserModePolling);
    EXPECT_FALSE(disabled.enableIntegrityMonitoring);
    EXPECT_FALSE(disabled.enableSnapshots);
    EXPECT_EQ(disabled.defaultResponse, RegistryProtectionResponse::None);

    const RegistryProtectionConfiguration rollback =
        RegistryProtectionConfiguration::FromMode(RegistryProtectionMode::Rollback);
    EXPECT_TRUE(rollback.enableKernelCallbacks);
    EXPECT_TRUE(rollback.enableAutoRollback);
    EXPECT_TRUE(rollback.enableSnapshots);
    EXPECT_EQ(static_cast<uint32_t>(rollback.defaultResponse),
              static_cast<uint32_t>(RegistryProtectionResponse::Active |
                                    RegistryProtectionResponse::Rollback));
    EXPECT_TRUE(rollback.IsValid());

    RegistryProtectionConfiguration invalid = rollback;
    invalid.pollingIntervalMs = 99;
    EXPECT_FALSE(invalid.IsValid());

    invalid = rollback;
    invalid.maxSnapshotsPerKey = 0;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(RegistryProtectionTests, EventsSerializeOperationAndDecisionFieldsPredictably) {
    RegistryProtectionEvent event{};
    event.eventId = 51;
    event.type = RegistryProtectionEventType::OperationBlocked;
    event.keyPath = L"HKLM\\Software\\ShadowStrike";
    event.valueName = L"Config";
    event.operation = RegistryOperation::SetValue;
    event.decision = RegistryOperationDecision::Block;
    event.sourceProcessId = 777;
    event.sourceProcessName = L"malware.exe";
    event.wasBlocked = true;
    event.wasRolledBack = true;
    event.description = "Protected configuration change denied";

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("BLOCKED SetValue on HKLM\\Software\\ShadowStrike\\Config"));
    EXPECT_THAT(summary, ::testing::HasSubstr("by PID 777"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 51);
    EXPECT_EQ(payload.at("keyPath").get<std::string>(), "HKLM\\Software\\ShadowStrike");
    EXPECT_EQ(payload.at("valueName").get<std::string>(), "Config");
    EXPECT_EQ(payload.at("operation").get<int>(),
              static_cast<int>(RegistryOperation::SetValue));
    EXPECT_EQ(payload.at("decision").get<int>(),
              static_cast<int>(RegistryOperationDecision::Block));
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_TRUE(payload.at("wasRolledBack").get<bool>());

    event.eventId = 52;
    event.valueName.clear();
    event.sourceProcessId = 0;
    event.sourceProcessName.clear();
    event.wasBlocked = false;
    event.wasRolledBack = false;

    const std::string pidlessSummary = event.GetSummary();
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("ALLOWED SetValue on HKLM\\Software\\ShadowStrike"));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("\\Config")));
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("by PID 0"));
}

TEST(RegistryProtectionTests, StatisticsAndHelperNamesPreservePublicContracts) {
    RegistryProtectionStatistics stats{};
    stats.totalProtectedKeys = 3;
    stats.totalProtectedValues = 12;
    stats.totalOperations = 40;
    stats.totalBlocked = 5;
    stats.totalRollbacks = 2;
    stats.snapshotsRestored = 1;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalProtectedKeys").get<int>(), 3);
    EXPECT_EQ(payload.at("totalOperations").get<int>(), 40);
    EXPECT_EQ(payload.at("totalBlocked").get<int>(), 5);
    EXPECT_EQ(payload.at("snapshotsRestored").get<int>(), 1);
    EXPECT_GE(payload.at("uptimeSeconds").get<int64_t>(), 0);

    EXPECT_EQ(GetProtectionModeName(RegistryProtectionMode::Rollback), "Rollback");
    EXPECT_EQ(GetRegistryOperationName(RegistryOperation::RestoreKey), "RestoreKey");
    EXPECT_EQ(GetProtectionTypeName(KeyProtectionType::ValuesOnly), "ValuesOnly");
    EXPECT_EQ(GetIntegrityStatusName(RegistryIntegrityStatus::Restored), "Restored");
    EXPECT_EQ(GetValueTypeName(RegistryValueType::MultiString), "REG_MULTI_SZ");
}

}  // namespace
