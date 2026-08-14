#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/ProcessProtection.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(ProcessProtectionTests, ProtectionLevelsAndConfigurationValidationRemainDeterministic) {
    ProcessProtectionLevel antimalwarePpl{};
    antimalwarePpl.type = ProcessProtectionType::ProtectedLight;
    antimalwarePpl.signer = ProtectionSigner::Antimalware;

    ProcessProtectionLevel fullWindows{};
    fullWindows.type = ProcessProtectionType::Protected;
    fullWindows.signer = ProtectionSigner::Windows;

    EXPECT_TRUE(antimalwarePpl.IsPPL());
    EXPECT_TRUE(antimalwarePpl.IsAntimalware());
    EXPECT_EQ(antimalwarePpl.GetCombinedLevel(),
              (static_cast<uint32_t>(ProcessProtectionType::ProtectedLight) << 4) |
              static_cast<uint32_t>(ProtectionSigner::Antimalware));
    EXPECT_TRUE(fullWindows >= antimalwarePpl);
    EXPECT_FALSE(antimalwarePpl >= fullWindows);

    ProcessProtectionConfiguration config{};
    EXPECT_TRUE(config.IsValid());

    config.monitorIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());

    config = ProcessProtectionConfiguration{};
    config.monitorIntervalMs = 600001;
    EXPECT_FALSE(config.IsValid());
}

TEST(ProcessProtectionTests, BlockedAccessEventsSerializeCoreDecisionData) {
    BlockedAccessEvent event{};
    event.eventId = 44;
    event.request.type = ProcessProtectionAccessRequestType::ProcessOpen;
    event.request.callerProcessId = 111;
    event.request.targetProcessId = 222;
    event.request.desiredAccess = 0x1234;
    event.decision.decision = ProcessProtectionAccessDecision::Deny;
    event.threatAction = ThreatAction::MemoryWrite;

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("caller=111"));
    EXPECT_THAT(summary, ::testing::HasSubstr("target=222"));
    EXPECT_THAT(summary, ::testing::HasSubstr("access=0x1234"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 44);
    EXPECT_EQ(payload.at("callerPid").get<int>(), 111);
    EXPECT_EQ(payload.at("targetPid").get<int>(), 222);
    EXPECT_EQ(payload.at("desiredAccess").get<int>(), 0x1234);
    EXPECT_EQ(payload.at("decision").get<int>(),
              static_cast<int>(ProcessProtectionAccessDecision::Deny));
    EXPECT_EQ(payload.at("threatAction").get<int>(),
              static_cast<int>(ThreatAction::MemoryWrite));
}

TEST(ProcessProtectionTests, StatisticsResetAndHelperNamesStayStable) {
    ProcessProtectionStatistics stats{};
    const auto lastEvent = Clock::now();
    stats.totalProtectedProcesses = 4;
    stats.totalAccessRequests = 17;
    stats.totalAccessBlocked = 6;
    stats.memoryWriteBlocked = 2;
    stats.alertsRaised = 1;
    stats.lastEventTime = lastEvent;

    stats.Reset();

    EXPECT_EQ(stats.totalProtectedProcesses, 0ULL);
    EXPECT_EQ(stats.totalAccessRequests, 0ULL);
    EXPECT_EQ(stats.totalAccessBlocked, 0ULL);
    EXPECT_EQ(stats.memoryWriteBlocked, 0ULL);
    EXPECT_EQ(stats.alertsRaised, 0ULL);
    EXPECT_EQ(stats.lastEventTime, Clock::time_point{});

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalAccessRequests").get<int>(), 0);
    EXPECT_EQ(payload.at("memoryWriteBlocked").get<int>(), 0);
    EXPECT_EQ(payload.at("alertsRaised").get<int>(), 0);

    EXPECT_EQ(GetProtectionTypeName(ProcessProtectionType::Protected), "Protected");
    EXPECT_EQ(GetProtectionSignerName(ProtectionSigner::Antimalware), "Antimalware");
    EXPECT_EQ(GetProtectionStatusName(ProtectionStatus::PPLProtected), "PPL Protected");
    EXPECT_EQ(GetAccessRequestTypeName(AccessRequestType::APCQueue), "APC Queue");
    EXPECT_EQ(GetThreatActionName(ThreatAction::MemoryWrite), "Memory Write");
    EXPECT_EQ(GetThreatActionName(ThreatAction::AllMemory), "Multiple");
}

}  // namespace
