#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <limits>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/MemoryProtection.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(MemoryProtectionTests, ProtectionLevelsAndValidationFollowPresetExpectations) {
    const MemoryProtectionConfiguration disabled =
        MemoryProtectionConfiguration::FromLevel(MemoryProtectionLevel::Disabled);
    EXPECT_FALSE(disabled.enableASLR);
    EXPECT_FALSE(disabled.enableDEP);
    EXPECT_FALSE(disabled.enableSecureAllocator);
    EXPECT_FALSE(disabled.enableMemoryEncryption);
    EXPECT_EQ(disabled.defaultResponse, MemoryProtectionResponse::Log);

    const MemoryProtectionConfiguration maximum =
        MemoryProtectionConfiguration::FromLevel(MemoryProtectionLevel::Maximum);
    EXPECT_TRUE(maximum.enableGuardPages);
    EXPECT_TRUE(maximum.enableMemoryEncryption);
    EXPECT_TRUE(maximum.enableAntiScan);
    EXPECT_EQ(maximum.integrityCheckIntervalMs, 15000U);
    EXPECT_EQ(maximum.defaultResponse, MemoryProtectionResponse::Aggressive);
    EXPECT_TRUE(maximum.IsValid());

    MemoryProtectionConfiguration invalid = maximum;
    invalid.securePoolSize = 0;
    EXPECT_FALSE(invalid.IsValid());

    invalid = maximum;
    invalid.integrityCheckIntervalMs = 0;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(MemoryProtectionTests, ProtectionEventsRenderAddressesAndRepairFlagsCorrectly) {
    ProtectionEvent event{};
    event.eventId = 33;
    event.type = MemoryProtectionEventType::HookDetected;
    event.address = 0x7FF612341000ULL;
    event.size = 64;
    event.regionId = "text-section";
    event.sourceProcessId = 9001;
    event.sourceThreadId = 12;
    event.wasBlocked = true;
    event.wasRepaired = true;
    event.description = "Inline patch blocked";

    const std::string summary = event.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("Hook detected"));
    EXPECT_THAT(summary, ::testing::HasSubstr("0x7ff612341000"));
    EXPECT_THAT(summary, ::testing::HasSubstr("[BLOCKED]"));

    const json payload = ParseJson(event.ToJson());
    EXPECT_EQ(payload.at("eventId").get<int>(), 33);
    EXPECT_EQ(payload.at("address").get<std::string>(), "0x7ff612341000");
    EXPECT_EQ(payload.at("size").get<int>(), 64);
    EXPECT_EQ(payload.at("regionId").get<std::string>(), "text-section");
    EXPECT_TRUE(payload.at("wasBlocked").get<bool>());
    EXPECT_TRUE(payload.at("wasRepaired").get<bool>());
}

TEST(MemoryProtectionTests, StatisticsCopyResetAndHelperNamesRemainStable) {
    MemoryProtectionStatistics stats{};
    const auto lastEvent = Clock::now();
    stats.totalProtectedRegions = 9;
    stats.totalSecureAllocations = 3;
    stats.totalSecureBytes = 4096;
    stats.totalIntegrityChecks = 12;
    stats.hooksDetected = 2;
    stats.dumpAttemptsBlocked = 1;
    stats.lastEventTime = lastEvent;

    const MemoryProtectionStatistics copy(stats);
    EXPECT_EQ(copy.totalProtectedRegions.load(), 9ULL);
    EXPECT_EQ(copy.totalSecureAllocations.load(), 3ULL);
    EXPECT_EQ(copy.hooksDetected.load(), 2ULL);

    stats.Reset();
    EXPECT_EQ(stats.totalProtectedRegions.load(), 0ULL);
    EXPECT_EQ(stats.totalSecureAllocations.load(), 0ULL);
    EXPECT_EQ(stats.totalSecureBytes.load(), 0ULL);
    EXPECT_EQ(stats.dumpAttemptsBlocked.load(), 0ULL);
    EXPECT_EQ(stats.lastEventTime, lastEvent);

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("totalProtectedRegions").get<int>(), 0);
    EXPECT_EQ(payload.at("hooksDetected").get<int>(), 0);
    EXPECT_EQ(payload.at("dumpAttemptsBlocked").get<int>(), 0);

    EXPECT_EQ(GetProtectionLevelName(MemoryProtectionLevel::Maximum), "Maximum");
    EXPECT_EQ(GetMemoryRegionTypeName(MemoryRegionType::Guard), "Guard");
    EXPECT_EQ(GetIntegrityStatusName(MemoryIntegrityStatus::Hooked), "Hooked");
    EXPECT_EQ(GetAllocationTypeName(AllocationType::Encrypted), "Encrypted");
}

TEST(MemoryProtectionTests, SecureAllocatorRejectsOverflowSizedRequests) {
    SecureAllocator<wchar_t> allocator;
    const auto impossibleCount =
        (std::numeric_limits<size_t>::max)() / sizeof(wchar_t) + 1U;

    EXPECT_THROW(static_cast<void>(allocator.allocate(impossibleCount)), std::bad_alloc);
}

}  // namespace
