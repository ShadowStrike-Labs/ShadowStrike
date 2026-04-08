#include "../../../src/pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Communication/FilterConnection.hpp"
#include "../../../src/Shared_modules/Communication/ThreatIntelPusher.hpp"

#include <span>
#include <string>
#include <vector>

namespace Comm = ShadowStrike::Communication;

/*
 * ============================================================================
 * ShadowStrike ThreatIntelPusher - ENTERPRISE-GRADE UNIT TESTS
 * ============================================================================
 *
 * Coverage focus:
 * - Result aggregation helpers
 * - Deterministic empty-input behavior
 * - Disconnected fail-fast behavior without touching live kernel IPC
 *
 * ============================================================================
 */

TEST(ThreatIntelPusherTest, ResultHelpersComputeAggregateStateCorrectly) {
    Comm::PushResult push{};
    push.success = true;
    push.entriesAccepted = 7;
    push.entriesRejected = 0;
    EXPECT_TRUE(push.IsComplete());
    EXPECT_EQ(push.TotalEntries(), 7u);

    push.entriesRejected = 2;
    EXPECT_FALSE(push.IsComplete());
    EXPECT_EQ(push.TotalEntries(), 9u);

    Comm::SyncResult sync{};
    sync.hashes.success = true;
    sync.patterns.success = true;
    sync.signatures.success = true;
    sync.networkIOCs.success = true;
    sync.whitelist.success = true;
    sync.exclusions.success = true;
    sync.iocFeed.success = true;
    sync.behavioralRules.success = true;

    sync.hashes.entriesAccepted = 1;
    sync.patterns.entriesAccepted = 2;
    sync.signatures.entriesAccepted = 3;
    sync.networkIOCs.entriesAccepted = 4;
    sync.whitelist.entriesAccepted = 5;
    sync.exclusions.entriesAccepted = 6;
    sync.iocFeed.entriesAccepted = 7;
    sync.behavioralRules.entriesAccepted = 8;

    EXPECT_TRUE(sync.AllSucceeded());
    EXPECT_EQ(sync.TotalAccepted(), 36u);

    sync.whitelist.success = false;
    EXPECT_FALSE(sync.AllSucceeded());
}

TEST(ThreatIntelPusherTest, EmptyPushesSucceedWithoutNeedingKernelConnectivity) {
    Comm::FilterConnection connection(L"\\ShadowStrikeUnitTestPort");
    Comm::ThreatIntelPusher pusher(connection);

    EXPECT_FALSE(pusher.IsConnected());

    EXPECT_TRUE(pusher.PushHashes(std::span<const Comm::HashPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushPatterns(std::span<const Comm::HashPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushSignatures(std::span<const Comm::HashPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushNetworkIOCs(std::span<const Comm::NetworkIOCPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushWhitelist(std::span<const Comm::WhitelistPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushExclusions(std::span<const Comm::ExclusionPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushIoCFeed(std::span<const Comm::IoCFeedPushEntry>{}).success);
    EXPECT_TRUE(pusher.PushBehavioralRules(std::span<const Comm::BehavioralRulePushEntry>{}).success);

    const Comm::PusherStatisticsSnapshot stats = pusher.GetStatistics();
    EXPECT_EQ(stats.totalPushes, 0u);
    EXPECT_EQ(stats.totalBatchesSent, 0u);
    EXPECT_EQ(stats.failedPushes, 0u);
}

TEST(ThreatIntelPusherTest, DisconnectedConnectionFailsFastForNonEmptyHashPushes) {
    Comm::FilterConnection connection(L"\\ShadowStrikeUnitTestPort");
    Comm::ThreatIntelPusher pusher(connection);

    Comm::HashPushEntry entry{};
    entry.hashType = 2;
    entry.verdict = 2;
    entry.severity = 4;
    entry.score = 100;
    entry.threatName = "Unit.Test.Malware";

    const std::vector<Comm::HashPushEntry> entries{entry};
    const Comm::PushResult result = pusher.PushHashes(entries);

    EXPECT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find("not connected"), std::string::npos);
    EXPECT_EQ(result.entriesAccepted, 0u);
    EXPECT_EQ(result.batchesSent, 0u);

    pusher.ResetStatistics();
    const Comm::PusherStatisticsSnapshot stats = pusher.GetStatistics();
    EXPECT_EQ(stats.totalPushes, 0u);
    EXPECT_EQ(stats.failedPushes, 0u);
    EXPECT_EQ(stats.lastPushTimeMs, 0);
}
