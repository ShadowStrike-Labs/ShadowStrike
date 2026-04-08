/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\RealTimeProtection deterministic contracts.
 *
 * Focus:
 *   - RTP preset factories and statistics/performance reset helpers
 *   - exclusion/cache/status accessors that are safe without full initialization
 *   - callback registration and unregistration contracts
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/RealTimeProtection.hpp"
#include "RealTime_TestUtils.hpp"

namespace ShadowStrike::RealTime::Tests {

class RealTimeProtectionTest : public ::testing::Test {
protected:
    RealTimeProtection& rtp = RealTimeProtection::Instance();

    void SetUp() override {
        rtp.Stop();
        rtp.ClearAllExclusions();
        rtp.ClearVerdictCache();
        rtp.ResetStatistics();
    }

    void TearDown() override {
        rtp.ClearAllExclusions();
        rtp.ClearVerdictCache();
        rtp.Stop();
    }
};

TEST_F(RealTimeProtectionTest, ConfigFactoriesAndResetHelpersRemainStable) {
    const auto defaults = RTPConfig::CreateDefault();
    const auto highSecurity = RTPConfig::CreateHighSecurity();
    const auto highPerformance = RTPConfig::CreateHighPerformance();
    const auto server = RTPConfig::CreateServerOptimized();
    const auto workstation = RTPConfig::CreateWorkstationOptimized();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_EQ(ProtectionMode::BLOCK_KNOWN, defaults.mode);
    EXPECT_EQ(FailurePolicy::FAIL_OPEN, defaults.failurePolicy);

    EXPECT_EQ(ProtectionMode::BLOCK_UNKNOWN, highSecurity.mode);
    EXPECT_EQ(FailurePolicy::FAIL_CLOSED, highSecurity.failurePolicy);
    EXPECT_TRUE(highSecurity.scanOnWrite);
    EXPECT_TRUE(highSecurity.scanOnRename);
    EXPECT_TRUE(highSecurity.inspectHTTPS);
    EXPECT_EQ(120000u, highSecurity.scanTimeoutMs);

    EXPECT_EQ(ProtectionMode::BLOCK_KNOWN, highPerformance.mode);
    EXPECT_FALSE(highPerformance.scanOnWrite);
    EXPECT_FALSE(highPerformance.scanArchives);
    EXPECT_TRUE(highPerformance.throttleOnHighCPU);
    EXPECT_EQ(2u, highPerformance.maxConcurrentScans);

    EXPECT_TRUE(server.scanOnWrite);
    EXPECT_TRUE(server.scanOnExecute);
    EXPECT_TRUE(server.monitorProcessCreation);

    EXPECT_EQ(ProtectionMode::BLOCK_SUSPICIOUS, workstation.mode);
    EXPECT_TRUE(workstation.scanOnOpen);
    EXPECT_TRUE(workstation.scanOnExecute);
    EXPECT_TRUE(workstation.monitorProcessCreation);

    PerformanceMetrics metrics;
    metrics.totalScans.store(5, std::memory_order_relaxed);
    metrics.cacheHits.store(2, std::memory_order_relaxed);
    metrics.pendingScanQueue.store(3, std::memory_order_relaxed);
    metrics.kernelErrors.store(1, std::memory_order_relaxed);
    metrics.Reset();

    EXPECT_EQ(0u, metrics.totalScans.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.cacheHits.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.pendingScanQueue.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, metrics.kernelErrors.load(std::memory_order_relaxed));

    RTPStatistics stats;
    stats.totalEvents.store(11, std::memory_order_relaxed);
    stats.filesBlocked.store(4, std::memory_order_relaxed);
    stats.threatsDetected.store(7, std::memory_order_relaxed);
    stats.performance.cacheSize.store(9, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(0u, stats.totalEvents.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.filesBlocked.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.threatsDetected.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.performance.cacheSize.load(std::memory_order_relaxed));
}

TEST_F(RealTimeProtectionTest, StatusExclusionAndCacheAccessorsRemainSafe) {
    EXPECT_EQ(ProtectionState::UNINITIALIZED, rtp.GetState());
    EXPECT_EQ(rtp.GetStatus().state, rtp.GetState());
    EXPECT_EQ(rtp.GetStatus().mode, rtp.GetProtectionMode());
    EXPECT_EQ(static_cast<size_t>(ComponentType::COMPONENT_COUNT), rtp.GetStatus().components.size());

    const ComponentStatus invalidComponent = rtp.GetComponentStatus(ComponentType::COMPONENT_COUNT);
    EXPECT_EQ(ComponentType::COMPONENT_COUNT, invalidComponent.type);
    EXPECT_EQ(ProtectionComponentState::UNINITIALIZED, invalidComponent.state);

    EXPECT_TRUE(rtp.AddPathExclusion(L"C:\\Trusted"));
    EXPECT_TRUE(rtp.AddProcessExclusion(L"trusted.exe"));
    EXPECT_TRUE(rtp.AddHashExclusion(L"deadbeef"));

    const auto exclusions = rtp.GetExclusions();
    EXPECT_TRUE(ContainsWideString(exclusions.at(L"paths"), L"C:\\Trusted"));
    EXPECT_TRUE(ContainsWideString(exclusions.at(L"processes"), L"trusted.exe"));
    EXPECT_TRUE(ContainsWideString(exclusions.at(L"hashes"), L"deadbeef"));
    EXPECT_TRUE(exclusions.contains(L"extensions"));

    std::array<uint8_t, 32> zeroHash{};
    EXPECT_FALSE(rtp.QueryVerdictCache(zeroHash).has_value());
    EXPECT_EQ(0u, rtp.GetCacheSize());

    rtp.ClearAllExclusions();
    EXPECT_TRUE(rtp.GetExclusions().at(L"paths").empty());
    EXPECT_TRUE(rtp.GetExclusions().at(L"processes").empty());
    EXPECT_TRUE(rtp.GetExclusions().at(L"hashes").empty());
}

TEST_F(RealTimeProtectionTest, CallbackRegistrationAndUnregistrationRemainDeterministic) {
    const uint64_t fileScanId = rtp.RegisterFileScanCallback(
        [](const RTPFileScanRequest&, ScanResult&) { return false; });
    const uint64_t processId = rtp.RegisterProcessCreateCallback(
        [](const RTPProcessNotifyRequest&, bool&) {});
    const uint64_t threatId = rtp.RegisterThreatDetectionCallback(
        [](const ThreatEvent&) {});
    const uint64_t stateId = rtp.RegisterStateChangeCallback(
        [](ProtectionState, ProtectionState, std::wstring_view) {});
    const uint64_t componentId = rtp.RegisterComponentStatusCallback(
        [](ComponentType, ProtectionComponentState, ProtectionComponentState) {});
    const uint64_t notificationId = rtp.RegisterNotificationCallback(
        [](NotificationSeverity, std::wstring_view, std::wstring_view,
            const std::optional<ThreatEvent>&) {});

    EXPECT_NE(0u, fileScanId);
    EXPECT_NE(0u, processId);
    EXPECT_NE(0u, threatId);
    EXPECT_NE(0u, stateId);
    EXPECT_NE(0u, componentId);
    EXPECT_NE(0u, notificationId);

    EXPECT_TRUE(rtp.UnregisterCallback(fileScanId));
    EXPECT_TRUE(rtp.UnregisterCallback(processId));
    EXPECT_TRUE(rtp.UnregisterCallback(threatId));
    EXPECT_TRUE(rtp.UnregisterCallback(stateId));
    EXPECT_TRUE(rtp.UnregisterCallback(componentId));
    EXPECT_TRUE(rtp.UnregisterCallback(notificationId));
    EXPECT_FALSE(rtp.UnregisterCallback(notificationId));
}

}  // namespace ShadowStrike::RealTime::Tests
