#include "../../../src/pch.h"
#include <nlohmann/json.hpp>
#include "../../../src/Shared_modules/SelfProtection/TamperProtection.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(TamperProtectionTests, ModePresetsAndValidationStayConsistent) {
    const TamperProtectionConfiguration disabled =
        TamperProtectionConfiguration::FromMode(TamperProtectionMode::Disabled);
    EXPECT_FALSE(disabled.enableRealTimeMonitoring);
    EXPECT_FALSE(disabled.enablePeriodicChecks);
    EXPECT_FALSE(disabled.enableAutoRepair);
    EXPECT_EQ(disabled.defaultResponse, TamperResponse::Log);

    const TamperProtectionConfiguration lockdown =
        TamperProtectionConfiguration::FromMode(TamperProtectionMode::Lockdown);
    EXPECT_TRUE(lockdown.enableRealTimeMonitoring);
    EXPECT_TRUE(lockdown.enableAutoRepair);
    EXPECT_TRUE(lockdown.verifyCertificateChain);
    EXPECT_TRUE(lockdown.enableAntiDebugIntegration);
    EXPECT_EQ(lockdown.defaultResponse, TamperResponse::Maximum);
    EXPECT_TRUE(lockdown.IsValid());

    TamperProtectionConfiguration invalid = lockdown;
    invalid.checkIntervalMs = TamperProtectionConstants::MIN_CHECK_INTERVAL_MS - 1;
    EXPECT_FALSE(invalid.IsValid());

    invalid = lockdown;
    invalid.maxRepairAttempts = 11;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(TamperProtectionTests, TamperEventsSummariesAndJsonTrackRepairActions) {
    TamperEvent event{};
    event.eventId = 71;
    event.type = TamperEventType::FileModified;
    event.resourceType = ProtectedResourceType::File;
    event.resourceId = "agent-binary";
    event.resourcePath = L"C:\\Program Files\\ShadowStrike\\agent.exe";
    event.sourceProcessId = 808;
    event.sourceProcessName = L"attacker.exe";
    event.sourceThreadId = 15;
    event.changeDescription = "Unexpected code section mutation";
    event.responseTaken = TamperResponse::Repair;
    event.wasBlocked = true;
    event.wasRepaired = true;
    event.severityLevel = 9;
    event.expectedHash.fill(0x11);
    event.actualHash.fill(0x22);

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("FileModified on File"));
    EXPECT_THAT(summary, ::testing::HasSubstr("agent.exe"));
    EXPECT_THAT(summary, ::testing::HasSubstr("by PID 808"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[BLOCKED]"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[REPAIRED]"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 71);
    EXPECT_EQ(payload.at("typeName").get<std::string>(), "FileModified");
    EXPECT_EQ(payload.at("resourceId").get<std::string>(), "agent-binary");
    EXPECT_EQ(payload.at("resourcePath").get<std::string>(),
              "C:\\Program Files\\ShadowStrike\\agent.exe");
    EXPECT_EQ(payload.at("responseTaken").get<int>(),
              static_cast<int>(TamperResponse::Repair));
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_TRUE(payload.at("wasRepaired").get<bool>());
    EXPECT_EQ(payload.at("severityLevel").get<int>(), 9);
    EXPECT_EQ(payload.at("expectedHash").get<std::string>().size(), 64U);
    EXPECT_EQ(payload.at("actualHash").get<std::string>().size(), 64U);

    event.eventId = 72;
    event.resourcePath.clear();
    event.sourceProcessId = 0;
    event.sourceProcessName = L"hidden.exe";
    event.wasBlocked = false;
    event.wasRepaired = false;

    const std::string pidlessSummary = event.GetSummary();
    EXPECT_THAT(pidlessSummary, ::testing::HasSubstr("FileModified on File"));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("by PID")));
    EXPECT_THAT(pidlessSummary, ::testing::Not(::testing::HasSubstr("hidden.exe")));
}

TEST(TamperProtectionTests, StatisticsAndHelperNamesRemainStable) {
    TamperProtectionStatistics stats{};
    stats.totalResourcesMonitored = 12;
    stats.totalIntegrityChecks = 50;
    stats.totalTamperingDetected = 3;
    stats.totalTamperingBlocked = 2;
    stats.totalRepairsPerformed = 2;
    stats.successfulRepairs = 2;
    stats.uptimeMs = 1500;

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalResourcesMonitored").get<int>(), 12);
    EXPECT_EQ(payload.at("totalTamperingDetected").get<int>(), 3);
    EXPECT_EQ(payload.at("successfulRepairs").get<int>(), 2);
    EXPECT_EQ(payload.at("uptimeMs").get<int>(), 1500);

    EXPECT_EQ(GetModeName(TamperProtectionMode::Enforce), "Enforce");
    EXPECT_EQ(GetResourceTypeName(ProtectedResourceType::CodeSection), "CodeSection");
    EXPECT_EQ(GetEventTypeName(TamperEventType::DebuggerAttached), "DebuggerAttached");
    EXPECT_EQ(GetIntegrityStatusName(IntegrityStatus::Unauthorized), "Unauthorized");
    EXPECT_EQ(GetResponseName(TamperResponse::Repair), "Repair");
    EXPECT_EQ(GetResponseName(TamperResponse::Standard), "Multiple");
    EXPECT_EQ(GetSubsystemName(TamperSubsystem::FileProtection), "FileProtection");
}

}  // namespace
