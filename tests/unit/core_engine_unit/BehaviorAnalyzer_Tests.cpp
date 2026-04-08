/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for BehaviorAnalyzer deterministic helper/state behavior.
 *
 * Scope:
 *   - event/state age and severity helpers
 *   - state reset behavior implemented in BehaviorAnalyzer.cpp
 *   - configuration factory profiles and statistics reset helpers
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>

#include "../../../src/Shared_modules/Core/Engine/BehaviorAnalyzer.hpp"

namespace Engine = ShadowStrike::Core::Engine;
using namespace std::chrono_literals;

namespace ShadowStrike::Core::Engine::Test {

TEST(BehaviorAnalyzerTest, EventAndStateHelpersReflectRiskAndAging) {
    Engine::BehaviorEvent event;
    event.timestamp = std::chrono::steady_clock::now() - 25ms;
    EXPECT_GE(event.GetAge().count(), 20);

    Engine::ProcessBehaviorState state;
    state.stateCreatedAt = std::chrono::steady_clock::now() - 50ms;
    state.maliceScore = Engine::BehaviorConstants::BLOCK_THRESHOLD + 1.0;
    state.filesEncrypted = Engine::BehaviorConstants::RANSOMWARE_FILE_THRESHOLD;
    state.remoteThreadCount = 1;

    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::High);
    EXPECT_TRUE(state.HasRansomwareBehavior());
    EXPECT_TRUE(state.HasInjectionBehavior());
    EXPECT_GE(state.GetAge().count(), 40);
}

TEST(BehaviorAnalyzerTest, ClearResetsAccumulatedProcessState) {
    Engine::ProcessBehaviorState state;
    state.processId = 501;
    state.processName = L"encryptor.exe";
    state.maliceScore = 92.0;
    state.filesEncrypted = 128;
    state.shadowCopyOperations = 1;
    state.remoteThreadCount = 2;
    state.targetedProcessIds.insert(900);
    state.contactedDomains.insert("evil.example");
    state.currentVerdict = Engine::BehaviorVerdictType::Malicious;
    state.recommendedAction = Engine::RecommendedAction::Terminate;
    state.hasBeenReported = true;

    state.Clear();

    EXPECT_EQ(state.processId, 0u);
    EXPECT_TRUE(state.processName.empty());
    EXPECT_DOUBLE_EQ(state.maliceScore, 0.0);
    EXPECT_EQ(state.filesEncrypted, 0u);
    EXPECT_EQ(state.shadowCopyOperations, 0u);
    EXPECT_EQ(state.remoteThreadCount, 0u);
    EXPECT_TRUE(state.targetedProcessIds.empty());
    EXPECT_TRUE(state.contactedDomains.empty());
    EXPECT_EQ(state.currentVerdict, Engine::BehaviorVerdictType::Clean);
    EXPECT_EQ(state.recommendedAction, Engine::RecommendedAction::None);
    EXPECT_FALSE(state.hasBeenReported);
}

TEST(BehaviorAnalyzerTest, VerdictAndAttackChainHelpersEncodeImmediateResponseSemantics) {
    Engine::BehaviorVerdict verdict;
    verdict.action = Engine::RecommendedAction::Terminate;
    EXPECT_TRUE(verdict.RequiresImmediateAction());

    verdict.action = Engine::RecommendedAction::Alert;
    EXPECT_FALSE(verdict.RequiresImmediateAction());

    Engine::BehaviorAttackChain chain;
    Engine::BehaviorEvent firstEvent;
    firstEvent.systemTime = std::chrono::system_clock::now();
    Engine::BehaviorEvent secondEvent = firstEvent;
    secondEvent.systemTime += 9s;
    chain.events = {firstEvent, secondEvent};
    EXPECT_EQ(chain.GetDuration(), 9s);
}

TEST(BehaviorAnalyzerTest, ConfigurationFactoriesShiftSensitivityAndStatsResetCleanly) {
    const Engine::BehaviorAnalyzerConfig defaultConfig = Engine::BehaviorAnalyzerConfig::CreateDefault();
    const Engine::BehaviorAnalyzerConfig highSensitivity =
        Engine::BehaviorAnalyzerConfig::CreateHighSensitivity();
    const Engine::BehaviorAnalyzerConfig lowSensitivity =
        Engine::BehaviorAnalyzerConfig::CreateLowSensitivity();

    EXPECT_LT(highSensitivity.warningThreshold, defaultConfig.warningThreshold);
    EXPECT_LT(highSensitivity.blockThreshold, lowSensitivity.blockThreshold);
    EXPECT_GT(lowSensitivity.ransomwareFileThreshold, highSensitivity.ransomwareFileThreshold);

    Engine::BehaviorAnalyzerStats stats;
    stats.totalEventsProcessed.store(11, std::memory_order_relaxed);
    stats.ransomwareDetections.store(2, std::memory_order_relaxed);
    stats.eventsDropped.store(1, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.totalEventsProcessed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.ransomwareDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsDropped.load(std::memory_order_relaxed), 0u);
}

}  // namespace ShadowStrike::Core::Engine::Test
