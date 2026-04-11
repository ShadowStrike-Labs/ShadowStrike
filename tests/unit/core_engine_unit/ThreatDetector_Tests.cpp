/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for ThreatDetector deterministic helper/state behavior.
 *
 * Scope:
 *   - event/verdict/attack-chain helpers used by correlation telemetry
 *   - configuration factory profiles
 *   - statistics reset behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>
#include <string_view>

#include "../../../src/PhantomCore/Core/Engine/ThreatDetector.hpp"

namespace Engine = ShadowStrike::Core::Engine;
using namespace std::chrono_literals;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

}  // namespace

class ThreatDetectorFixture : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::ThreatDetector::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::ThreatDetector::Instance().Shutdown();
    }
};

TEST(ThreatDetectorTest, SystemEventHelpersReflectAgeAndCrossProcessBehavior) {
    Engine::SystemEvent event;
    event.timestamp = std::chrono::steady_clock::now() - 20ms;
    event.processId = 100;
    event.targetProcessId = 200;

    EXPECT_GE(event.GetAge().count(), 15);
    EXPECT_TRUE(event.IsCrossProcess());

    event.targetProcessId = 100;
    EXPECT_FALSE(event.IsCrossProcess());

    event.targetProcessId = 0;
    EXPECT_FALSE(event.IsCrossProcess());
}

TEST(ThreatDetectorTest, VerdictAndAttackChainJsonSurfacesExposeStableCounts) {
    Engine::ThreatVerdict verdict;
    verdict.isThreat = true;
    verdict.severity = Engine::ThreatSeverity::Critical;
    verdict.category = Engine::ThreatCategory::Ransomware;
    verdict.threatScore = 97.5;
    verdict.confidence = Engine::ConfidenceLevel::High;
    verdict.processId = 321;
    verdict.recommendedAction = Engine::ResponseAction::Block;
    verdict.engineDetections.push_back({});
    verdict.mitreTechniques.push_back("T1486");
    const std::string verdictJson = verdict.ToJson();
    EXPECT_TRUE(Contains(verdictJson, "\"isThreat\":true"));
    EXPECT_TRUE(Contains(verdictJson, "\"engineCount\":1"));
    EXPECT_TRUE(Contains(verdictJson, "\"mitreCount\":1"));
    EXPECT_TRUE(verdict.RequiresImmediateAction());
    EXPECT_EQ(verdict.GetSeverityString(), "Critical");

    verdict.severity = Engine::ThreatSeverity::High;
    verdict.recommendedAction = Engine::ResponseAction::None;
    EXPECT_TRUE(verdict.RequiresImmediateAction());

    verdict.severity = Engine::ThreatSeverity::Medium;
    verdict.recommendedAction = Engine::ResponseAction::Block;
    EXPECT_FALSE(verdict.RequiresImmediateAction());

    Engine::AttackChain chain;
    chain.chainId = 77;
    chain.creationTime = std::chrono::system_clock::now();
    chain.lastUpdateTime = chain.creationTime + 12s;
    chain.severity = Engine::ThreatSeverity::High;
    chain.confidence = 0.9;
    chain.involvedProcessIds = {321, 654};
    chain.eventIds = {1, 2, 3};
    chain.mitreTechniques = {"T1055"};
    const std::string chainJson = chain.ToJson();
    EXPECT_EQ(chain.GetDuration(), 12s);
    EXPECT_TRUE(Contains(chainJson, "\"processCount\":2"));
    EXPECT_TRUE(Contains(chainJson, "\"eventCount\":3"));
}

TEST(ThreatDetectorTest, ConfigurationFactoriesEncodeOperationalResponseProfiles) {
    const Engine::ThreatDetectorConfig defaultConfig = Engine::ThreatDetectorConfig::CreateDefault();
    const Engine::ThreatDetectorConfig aggressiveConfig = Engine::ThreatDetectorConfig::CreateAggressive();
    const Engine::ThreatDetectorConfig monitorOnlyConfig = Engine::ThreatDetectorConfig::CreateMonitorOnly();

    EXPECT_TRUE(defaultConfig.enabled);
    EXPECT_LT(aggressiveConfig.detectionThreshold, defaultConfig.detectionThreshold);
    EXPECT_TRUE(aggressiveConfig.autoBlockOnCritical);
    EXPECT_TRUE(aggressiveConfig.autoQuarantineOnHigh);
    EXPECT_TRUE(aggressiveConfig.autoTerminateRansomware);
    EXPECT_FALSE(monitorOnlyConfig.autoBlockOnCritical);
    EXPECT_FALSE(monitorOnlyConfig.autoQuarantineOnHigh);
    EXPECT_FALSE(monitorOnlyConfig.autoTerminateRansomware);
}

TEST(ThreatDetectorTest, StatisticsResetClearsAllRuntimeCounters) {
    Engine::ThreatDetectorStats stats;
    stats.totalEventsProcessed.store(20, std::memory_order_relaxed);
    stats.eventsByCategory[3].store(2, std::memory_order_relaxed);
    stats.totalThreatsDetected.store(4, std::memory_order_relaxed);
    stats.threatsBySeverity[2].store(5, std::memory_order_relaxed);
    stats.threatsByCategory[1].store(6, std::memory_order_relaxed);
    stats.detectionsBySource[4].store(7, std::memory_order_relaxed);
    stats.actionsTaken[2].store(8, std::memory_order_relaxed);
    stats.eventsPerSecond.store(9, std::memory_order_relaxed);
    stats.peakEventsPerSecond.store(10, std::memory_order_relaxed);
    stats.eventsDropped.store(1, std::memory_order_relaxed);
    stats.falsePositives.store(2, std::memory_order_relaxed);
    stats.avgProcessingTimeUs.store(120, std::memory_order_relaxed);

    stats.Reset();
    EXPECT_EQ(stats.totalEventsProcessed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsByCategory[3].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.totalThreatsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threatsBySeverity[2].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threatsByCategory[1].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.detectionsBySource[4].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.actionsTaken[2].load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsPerSecond.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.peakEventsPerSecond.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsDropped.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.falsePositives.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.avgProcessingTimeUs.load(std::memory_order_relaxed), 0u);
}

TEST_F(ThreatDetectorFixture, CallbackAndIdleQueueSurfacesRemainStableWithoutEvents) {
    auto& detector = Engine::ThreatDetector::Instance();
    EXPECT_FALSE(detector.IsInitialized());
    EXPECT_EQ(detector.GetQueueDepth(), 0u);

    const uint64_t verdictCallbackId =
        detector.RegisterVerdictCallback([](const Engine::ThreatVerdict&) {});
    const uint64_t chainCallbackId =
        detector.RegisterAttackChainCallback([](const Engine::AttackChain&) {});
    EXPECT_NE(verdictCallbackId, 0u);
    EXPECT_NE(chainCallbackId, 0u);
    EXPECT_TRUE(detector.UnregisterVerdictCallback(verdictCallbackId));
    EXPECT_TRUE(detector.UnregisterAttackChainCallback(chainCallbackId));
    EXPECT_FALSE(detector.UnregisterVerdictCallback(verdictCallbackId));
    EXPECT_FALSE(detector.UnregisterAttackChainCallback(chainCallbackId));

    const Engine::ThreatDetectorStats stats = detector.GetStats();
    EXPECT_EQ(stats.totalEventsProcessed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.falsePositives.load(std::memory_order_relaxed), 0u);
}

}  // namespace ShadowStrike::Core::Engine::Test
