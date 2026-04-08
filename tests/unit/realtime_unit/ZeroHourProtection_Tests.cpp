/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for RealTime\ZeroHourProtection deterministic contracts.
 *
 * Focus:
 *   - adaptive heuristic and zero-hour config preset factories
 *   - statistics reset and safe uninitialized analysis behavior
 *   - callback guard semantics and cache/state getters
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/RealTime/ZeroHourProtection.hpp"

namespace ShadowStrike::RealTime::Tests {

class ZeroHourProtectionTest : public ::testing::Test {
protected:
    ZeroHourProtection& protection = ZeroHourProtection::Instance();

    void SetUp() override {
        protection.Shutdown();
        protection.ResetStatistics();
    }

    void TearDown() override {
        protection.Shutdown();
    }
};

TEST_F(ZeroHourProtectionTest, HeuristicAndProtectionFactoriesPreserveExpectedProfiles) {
    const auto defaults = AdaptiveHeuristicConfig::CreateDefault();
    const auto aggressive = AdaptiveHeuristicConfig::CreateAggressive();
    const auto conservative = AdaptiveHeuristicConfig::CreateConservative();
    const auto outbreak = AdaptiveHeuristicConfig::CreateOutbreak();

    EXPECT_EQ(HeuristicMode::STANDARD, defaults.mode);
    EXPECT_TRUE(defaults.autoAdjust);

    EXPECT_EQ(HeuristicMode::AGGRESSIVE, aggressive.mode);
    EXPECT_FLOAT_EQ(0.5f, aggressive.mlDetectionThreshold);
    EXPECT_FLOAT_EQ(0.75f, aggressive.mlBlockThreshold);
    EXPECT_EQ(500u, aggressive.maxApiCallsPerSecond);
    EXPECT_TRUE(aggressive.autoAdjust);

    EXPECT_EQ(HeuristicMode::MINIMAL, conservative.mode);
    EXPECT_FLOAT_EQ(0.85f, conservative.mlDetectionThreshold);
    EXPECT_FLOAT_EQ(0.95f, conservative.mlBlockThreshold);
    EXPECT_EQ(2000u, conservative.maxApiCallsPerSecond);
    EXPECT_FALSE(conservative.autoAdjust);

    EXPECT_EQ(HeuristicMode::OUTBREAK, outbreak.mode);
    EXPECT_TRUE(outbreak.useEnsemble);
    EXPECT_GT(outbreak.mlBlockThreshold, outbreak.mlDetectionThreshold);

    const auto defaultConfig = ZeroHourProtectionConfig::CreateDefault();
    const auto enterprise = ZeroHourProtectionConfig::CreateEnterprise();
    const auto highSecurity = ZeroHourProtectionConfig::CreateHighSecurity();
    const auto performance = ZeroHourProtectionConfig::CreatePerformance();

    EXPECT_EQ(enterprise.enabled, defaultConfig.enabled);
    EXPECT_EQ(enterprise.holdUnknownFiles, defaultConfig.holdUnknownFiles);
    EXPECT_EQ(enterprise.cloudConfig.fallbackPolicy, defaultConfig.cloudConfig.fallbackPolicy);

    EXPECT_TRUE(enterprise.cloudLookupEnabled);
    EXPECT_TRUE(enterprise.holdUnknownFiles);
    EXPECT_EQ(HoldDecision::TIMEOUT_ALLOW, enterprise.timeoutDecision);
    EXPECT_EQ(FallbackPolicy::HOLD_TIMEOUT, enterprise.cloudConfig.fallbackPolicy);

    EXPECT_EQ(HoldDecision::TIMEOUT_BLOCK, highSecurity.timeoutDecision);
    EXPECT_EQ(FallbackPolicy::BLOCK_UNKNOWN, highSecurity.cloudConfig.fallbackPolicy);
    EXPECT_EQ(ThreatLevel::ELEVATED, highSecurity.autoEscalateLevel);
    EXPECT_EQ(HeuristicMode::AGGRESSIVE, highSecurity.heuristicConfig.mode);

    EXPECT_FALSE(performance.holdUnknownFiles);
    EXPECT_EQ(FallbackPolicy::ALLOW_UNKNOWN, performance.cloudConfig.fallbackPolicy);
    EXPECT_EQ(HeuristicMode::MINIMAL, performance.heuristicConfig.mode);
}

TEST_F(ZeroHourProtectionTest, StatisticsResetAndUninitializedAnalysisStayDeterministic) {
    ZeroHourStatistics stats;
    stats.totalCloudQueries.store(5, std::memory_order_relaxed);
    stats.filesHeld.store(3, std::memory_order_relaxed);
    stats.microSigUpdates.store(2, std::memory_order_relaxed);
    stats.currentThreatLevel.store(static_cast<uint8_t>(ThreatLevel::CRITICAL),
        std::memory_order_relaxed);
    stats.errorCount.store(1, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(0u, stats.totalCloudQueries.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.filesHeld.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.microSigUpdates.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.currentThreatLevel.load(std::memory_order_relaxed));
    EXPECT_EQ(0u, stats.errorCount.load(std::memory_order_relaxed));

    EXPECT_FALSE(protection.IsInitialized());
    EXPECT_FALSE(protection.IsOutbreakModeActive());
    EXPECT_EQ(ThreatLevel::NORMAL, protection.GetThreatLevel());
    EXPECT_EQ(0u, protection.GetCacheSize());

    FileAnalysisRequest request;
    request.filePath = L"C:\\Temp\\sample.exe";
    request.fileSize = 4096;

    const FileAnalysisResult result = protection.AnalyzeFile(request);
    EXPECT_EQ(1u, result.errorCode);
    EXPECT_EQ(std::wstring(L"Not initialized"), result.errorMessage);
    EXPECT_FALSE(result.shouldAllow);
}

TEST_F(ZeroHourProtectionTest, CallbackGuardsAndIdentifiersRemainStable) {
    EXPECT_EQ(0u, protection.RegisterSignatureUpdateCallback({}));
    EXPECT_EQ(0u, protection.RegisterCloudStatusCallback({}));

    const uint64_t verdictId = protection.RegisterVerdictCallback(
        [](const std::wstring&, const FileAnalysisResult&) {});
    const uint64_t holdId = protection.RegisterFileHoldCallback([](const HeldFile&) {});
    const uint64_t outbreakId = protection.RegisterOutbreakCallback(
        [](const OutbreakInfo&, bool) {});
    const uint64_t threatLevelId = protection.RegisterThreatLevelCallback(
        [](ThreatLevel, ThreatLevel, std::wstring_view) {});
    const uint64_t signatureId = protection.RegisterSignatureUpdateCallback(
        [](const MicroSigUpdatePackage&, bool) {});
    const uint64_t cloudId = protection.RegisterCloudStatusCallback(
        [](CloudServiceStatus, CloudServiceStatus) {});

    EXPECT_NE(0u, verdictId);
    EXPECT_NE(0u, holdId);
    EXPECT_NE(0u, outbreakId);
    EXPECT_NE(0u, threatLevelId);
    EXPECT_NE(0u, signatureId);
    EXPECT_NE(0u, cloudId);

    EXPECT_TRUE(protection.UnregisterCallback(verdictId));
    EXPECT_TRUE(protection.UnregisterCallback(holdId));
    EXPECT_TRUE(protection.UnregisterCallback(outbreakId));
    EXPECT_TRUE(protection.UnregisterCallback(threatLevelId));
    EXPECT_TRUE(protection.UnregisterCallback(signatureId));
    EXPECT_TRUE(protection.UnregisterCallback(cloudId));
    EXPECT_FALSE(protection.UnregisterCallback(cloudId));
}

}  // namespace ShadowStrike::RealTime::Tests
