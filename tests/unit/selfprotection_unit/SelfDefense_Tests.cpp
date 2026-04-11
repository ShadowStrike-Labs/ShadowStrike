#include "../../../src/pch.h"
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/SelfDefense.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(SelfDefenseTests, ProtectionLevelsAndValidationStayAligned) {
    const SelfDefenseConfiguration disabled =
        SelfDefenseConfiguration::FromLevel(SelfDefenseLevel::Disabled);
    EXPECT_EQ(disabled.enabledComponents, ProtectionComponent::None);
    EXPECT_FALSE(disabled.enableKernelProtection);
    EXPECT_FALSE(disabled.enableWatchdog);
    EXPECT_FALSE(disabled.enableIntegrityMonitoring);

    const SelfDefenseConfiguration paranoid =
        SelfDefenseConfiguration::FromLevel(SelfDefenseLevel::Paranoid);
    EXPECT_EQ(paranoid.enabledComponents, ProtectionComponent::All);
    EXPECT_EQ(paranoid.defaultResponse, SelfDefenseThreatResponse::Aggressive);
    EXPECT_TRUE(paranoid.verboseLogging);
    EXPECT_TRUE(paranoid.IsValid());

    SelfDefenseConfiguration invalid = paranoid;
    invalid.watchdogIntervalMs = 999;
    EXPECT_FALSE(invalid.IsValid());

    invalid = paranoid;
    invalid.heartbeatTimeoutMs = 4999;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(SelfDefenseTests, ThreatEventsExposeCoreBlockingMetadata) {
    ThreatEvent event{};
    event.eventId = 61;
    event.type = ThreatType::ProcessTermination;
    event.attackerProcessId = 404;
    event.targetIdentifier = L"ShadowStrikeService";
    event.wasBlocked = true;

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("type=0x1"));
    EXPECT_THAT(summary, ::testing::HasSubstr("attacker=404"));
    EXPECT_THAT(summary, ::testing::HasSubstr("target=ShadowStrikeService"));
    EXPECT_THAT(summary, ::testing::HasSubstr("blocked=yes"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 61);
    EXPECT_EQ(payload.at("type").get<int>(), static_cast<int>(ThreatType::ProcessTermination));
    EXPECT_EQ(payload.at("attackerPid").get<int>(), 404);
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
}

TEST(SelfDefenseTests, StatisticsResetAndHelperNamesRemainStable) {
    SelfDefenseStatistics stats{};
    const auto lastThreat = Clock::now();
    stats.totalThreatsDetected = 6;
    stats.totalThreatsBlocked = 5;
    stats.processTerminationBlocked = 2;
    stats.autoRecoveryEvents = 1;
    stats.successfulRecoveries = 1;
    stats.threatsByType[ThreatType::ProcessTermination] = 2;
    stats.lastThreatTime = lastThreat;

    stats.Reset();

    EXPECT_EQ(stats.totalThreatsDetected, 0ULL);
    EXPECT_EQ(stats.totalThreatsBlocked, 0ULL);
    EXPECT_EQ(stats.processTerminationBlocked, 0ULL);
    EXPECT_EQ(stats.successfulRecoveries, 0ULL);
    EXPECT_TRUE(stats.threatsByType.empty());
    EXPECT_EQ(stats.lastThreatTime, lastThreat);

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.size(), 3U);
    EXPECT_EQ(payload.at("totalThreats").get<int>(), 0);
    EXPECT_EQ(payload.at("blocked").get<int>(), 0);
    EXPECT_EQ(payload.at("recoveries").get<int>(), 0);
    EXPECT_FALSE(payload.contains("processTerminationBlocked"));
    EXPECT_FALSE(payload.contains("lastThreatTime"));

    EXPECT_EQ(GetComponentName(ProtectionComponent::Registry), "Registry");
    EXPECT_EQ(GetThreatTypeName(ThreatType::DebugAttach), "DebugAttach");
    EXPECT_EQ(GetHealthName(ComponentHealth::Recovering), "Recovering");
    EXPECT_EQ(GetProtectionLevelName(SelfDefenseLevel::Enhanced), "Enhanced");
}

}  // namespace
