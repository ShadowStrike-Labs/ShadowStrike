/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Registry\StartupAnalyzer deterministic contracts.
 *
 * Focus:
 *   - singleton/version and enum-name helper stability
 *   - config factory behavior and statistics reset
 *   - callback management and safe post-shutdown state
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <regex>

#include "../../../src/Shared_modules/Core/Registry/StartupAnalyzer.hpp"

namespace ShadowStrike::Core::Registry::Test {

class StartupAnalyzerTest : public ::testing::Test {
protected:
    StartupAnalyzer& analyzer = StartupAnalyzer::Instance();

    void SetUp() override {
        analyzer.Shutdown();
        analyzer.ResetStatistics();
    }

    void TearDown() override {
        analyzer.Shutdown();
    }
};

TEST_F(StartupAnalyzerTest, SingletonVersionAndEnumNamesRemainStableForConsumers) {
    EXPECT_EQ(&StartupAnalyzer::Instance(), &StartupAnalyzer::Instance());
    EXPECT_TRUE(StartupAnalyzer::HasInstance());
    EXPECT_TRUE(
        std::regex_match(StartupAnalyzer::GetVersionString(), std::regex(R"(\d+\.\d+\.\d+)")));

    EXPECT_EQ(GetStartupSourceName(StartupSource::RegistryRun_HKLM), "Registry Run (HKLM)");
    EXPECT_EQ(GetStartupSourceName(StartupSource::WMI_Subscription), "WMI Subscription");
    EXPECT_EQ(GetStartupStatusName(StartupStatus::Quarantined), "Quarantined");
    EXPECT_EQ(GetItemCategoryName(ItemCategory::Security), "Security");
    EXPECT_EQ(GetImpactLevelName(ImpactLevel::Critical), "Critical");
    EXPECT_EQ(GetActionResultName(ActionResult::AlreadyInState), "Already In State");
    EXPECT_EQ(
        GetOptimizationRecommendationName(OptimizationRecommendation::Investigate),
        "Investigate");

    EXPECT_EQ(GetStartupSourceName(static_cast<StartupSource>(0xFFFF)), "Unknown");
    EXPECT_EQ(GetItemCategoryName(static_cast<ItemCategory>(0xFF)), "Unknown");
    EXPECT_EQ(GetActionResultName(static_cast<ActionResult>(0xFF)), "Unknown");
}

TEST_F(StartupAnalyzerTest, ConfigFactoriesAndStatisticsPreserveExpectedProfiles) {
    const auto defaults = StartupAnalyzerConfig::CreateDefault();
    const auto security = StartupAnalyzerConfig::CreateSecurity();
    const auto performance = StartupAnalyzerConfig::CreatePerformance();

    EXPECT_TRUE(defaults.analyzeSignatures);
    EXPECT_TRUE(defaults.checkReputation);
    EXPECT_TRUE(defaults.measureBootImpact);
    EXPECT_TRUE(defaults.detectHidden);
    EXPECT_FALSE(defaults.autoDisableMalicious);
    EXPECT_TRUE(defaults.autoQuarantineMalicious);
    EXPECT_TRUE(defaults.alertOnNewItems);
    EXPECT_TRUE(defaults.alertOnSuspicious);
    EXPECT_FALSE(defaults.enableOptimization);
    EXPECT_FALSE(defaults.autoDelayNonCritical);
    EXPECT_TRUE(defaults.trackHistory);
    EXPECT_TRUE(defaults.createBackups);

    EXPECT_TRUE(security.autoDisableMalicious);
    EXPECT_TRUE(security.autoQuarantineMalicious);
    EXPECT_TRUE(security.createBackups);

    EXPECT_FALSE(performance.analyzeSignatures);
    EXPECT_FALSE(performance.checkReputation);
    EXPECT_TRUE(performance.measureBootImpact);
    EXPECT_TRUE(performance.enableOptimization);
    EXPECT_TRUE(performance.autoDelayNonCritical);

    StartupAnalyzerStatistics stats;
    stats.totalItemsAnalyzed.store(12, std::memory_order_relaxed);
    stats.enabledItems.store(3, std::memory_order_relaxed);
    stats.disabledItems.store(4, std::memory_order_relaxed);
    stats.maliciousItems.store(1, std::memory_order_relaxed);
    stats.itemsEnabled.store(5, std::memory_order_relaxed);
    stats.itemsDisabled.store(6, std::memory_order_relaxed);
    stats.itemsRemoved.store(7, std::memory_order_relaxed);
    stats.itemsQuarantined.store(8, std::memory_order_relaxed);
    stats.alertsGenerated.store(9, std::memory_order_relaxed);
    stats.lastBootTimeMs.store(1500, std::memory_order_relaxed);
    stats.baselineBootTimeMs.store(1200, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.totalItemsAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.enabledItems.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.disabledItems.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.maliciousItems.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.itemsEnabled.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.itemsDisabled.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.itemsRemoved.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.itemsQuarantined.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.alertsGenerated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.lastBootTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.baselineBootTimeMs.load(std::memory_order_relaxed), 0u);
}

TEST_F(StartupAnalyzerTest, CallbackAndDefaultStateContractsRemainSafeAfterShutdown) {
    EXPECT_FALSE(analyzer.IsInitialized());
    EXPECT_TRUE(analyzer.GetStartupItems().empty());
    EXPECT_FALSE(analyzer.GetItem(L"MissingEntry").has_value());
    EXPECT_FALSE(analyzer.GetItemById(0xDEADBEEFull).has_value());
    EXPECT_TRUE(analyzer.GetItemsBySource(StartupSource::Service).empty());
    EXPECT_TRUE(analyzer.GetItemsByCategory(ItemCategory::Malicious).empty());
    EXPECT_EQ(analyzer.GetBootBaseline(), 0u);

    const OptimizationPlan plan = analyzer.GetOptimizationPlan();
    EXPECT_EQ(plan.itemsToDelay, 0u);
    EXPECT_EQ(plan.itemsToDisable, 0u);
    EXPECT_EQ(plan.itemsToRemove, 0u);
    EXPECT_EQ(plan.estimatedTimeSavedMs, 0u);
    EXPECT_TRUE(plan.isSafe);

    const uint64_t newItemCallbackId =
        analyzer.RegisterNewItemCallback([](const StartupItem&) {});
    const uint64_t alertCallbackId =
        analyzer.RegisterAlertCallback([](const StartupAlert&) {});
    const uint64_t changeCallbackId =
        analyzer.RegisterChangeCallback([](const StartupChange&) {});

    EXPECT_NE(newItemCallbackId, 0u);
    EXPECT_NE(alertCallbackId, 0u);
    EXPECT_NE(changeCallbackId, 0u);

    EXPECT_TRUE(analyzer.UnregisterCallback(newItemCallbackId));
    EXPECT_TRUE(analyzer.UnregisterCallback(alertCallbackId));
    EXPECT_TRUE(analyzer.UnregisterCallback(changeCallbackId));
    EXPECT_FALSE(analyzer.UnregisterCallback(changeCallbackId));
}

}  // namespace ShadowStrike::Core::Registry::Test
