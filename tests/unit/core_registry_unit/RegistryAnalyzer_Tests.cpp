/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Registry\RegistryAnalyzer deterministic contracts.
 *
 * Focus:
 *   - analysis preset factories and statistics reset behavior
 *   - public entropy helper behavior used by anomaly scoring
 *   - safe callback and uninitialized-state accessors
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Core/Registry/RegistryAnalyzer.hpp"
#include "CoreRegistry_TestUtils.hpp"

namespace ShadowStrike::Core::Registry::Test {

class RegistryAnalyzerTest : public ::testing::Test {
protected:
    RegistryAnalyzer& analyzer = RegistryAnalyzer::Instance();
    TempDirectoryGuard temp{ L"ShadowStrike_RegistryAnalyzer_UT" };

    void SetUp() override {
        analyzer.Shutdown();
        analyzer.ResetStatistics();
        analyzer.ClearAnomalies();
    }

    void TearDown() override {
        analyzer.ClearAnomalies();
        analyzer.Shutdown();
    }
};

TEST_F(RegistryAnalyzerTest, ConfigFactoriesPreserveExpectedAnalysisProfiles) {
    const auto defaults = RegistryAnalyzerConfig::CreateDefault();
    const auto forensic = RegistryAnalyzerConfig::CreateForensic();
    const auto rootkit = RegistryAnalyzerConfig::CreateRootkitHunting();
    const auto quick = RegistryAnalyzerConfig::CreateQuick();

    EXPECT_EQ(defaults.defaultMode, AnalysisMode::Standard);
    EXPECT_TRUE(defaults.detectHiddenKeys);
    EXPECT_TRUE(defaults.detectHiddenValues);
    EXPECT_TRUE(defaults.analyzeEntropy);
    EXPECT_TRUE(defaults.detectEmbeddedExecutables);
    EXPECT_TRUE(defaults.enableCrossView);
    EXPECT_FALSE(defaults.recoverDeleted);
    EXPECT_FALSE(defaults.analyzeSlackSpace);
    EXPECT_TRUE(defaults.buildTimeline);
    EXPECT_TRUE(defaults.matchPatterns);
    EXPECT_TRUE(defaults.matchIOCs);
    EXPECT_EQ(defaults.threadCount, 4u);

    EXPECT_EQ(forensic.defaultMode, AnalysisMode::Forensic);
    EXPECT_TRUE(forensic.recoverDeleted);
    EXPECT_TRUE(forensic.analyzeSlackSpace);
    EXPECT_TRUE(forensic.buildTimeline);
    EXPECT_TRUE(forensic.detectEmbeddedExecutables);
    EXPECT_EQ(forensic.threadCount, 8u);

    EXPECT_EQ(rootkit.defaultMode, AnalysisMode::RootkitHunting);
    EXPECT_TRUE(rootkit.detectHiddenKeys);
    EXPECT_TRUE(rootkit.detectHiddenValues);
    EXPECT_FALSE(rootkit.detectEmbeddedExecutables);
    EXPECT_FALSE(rootkit.recoverDeleted);
    EXPECT_FALSE(rootkit.buildTimeline);
    EXPECT_EQ(rootkit.maxAnomalies, 10000u);
    EXPECT_EQ(rootkit.threadCount, 4u);

    EXPECT_EQ(quick.defaultMode, AnalysisMode::Quick);
    EXPECT_TRUE(quick.detectHiddenKeys);
    EXPECT_FALSE(quick.detectHiddenValues);
    EXPECT_FALSE(quick.analyzeEntropy);
    EXPECT_FALSE(quick.enableCrossView);
    EXPECT_FALSE(quick.detectDKOM);
    EXPECT_FALSE(quick.matchPatterns);
    EXPECT_FALSE(quick.matchIOCs);
    EXPECT_EQ(quick.maxAnomalies, 1000u);
    EXPECT_EQ(quick.threadCount, 2u);
}

TEST_F(RegistryAnalyzerTest, StatisticsResetAndEntropyStayDeterministic) {
    RegistryAnalyzerStatistics stats;
    stats.totalScans.store(7, std::memory_order_relaxed);
    stats.keysAnalyzed.store(91, std::memory_order_relaxed);
    stats.valuesAnalyzed.store(123, std::memory_order_relaxed);
    stats.bytesAnalyzed.store(4096, std::memory_order_relaxed);
    stats.anomaliesDetected.store(5, std::memory_order_relaxed);
    stats.hiddenKeysFound.store(2, std::memory_order_relaxed);
    stats.hiddenValuesFound.store(3, std::memory_order_relaxed);
    stats.rootkitIndicators.store(1, std::memory_order_relaxed);
    stats.maliciousEntries.store(4, std::memory_order_relaxed);
    stats.deletedRecovered.store(8, std::memory_order_relaxed);
    stats.patternsMatched.store(6, std::memory_order_relaxed);
    stats.iocsMatched.store(9, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.totalScans.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.keysAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.valuesAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bytesAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.anomaliesDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hiddenKeysFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hiddenValuesFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.rootkitIndicators.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.maliciousEntries.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.deletedRecovered.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.patternsMatched.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.iocsMatched.load(std::memory_order_relaxed), 0u);

    const std::vector<uint8_t> uniform(2048, 0x00);
    const std::vector<uint8_t> varied = HighEntropyBytes(2048);

    EXPECT_DOUBLE_EQ(analyzer.CalculateEntropy({}), 0.0);
    EXPECT_LT(analyzer.CalculateEntropy(uniform), analyzer.CalculateEntropy(varied));
    EXPECT_NEAR(analyzer.CalculateEntropy(varied), 8.0, 0.01);
}

TEST_F(RegistryAnalyzerTest, OfflineHiveAndIndicatorHelpersHandleMalformedInputsDeterministically) {
    ASSERT_TRUE(analyzer.Initialize(RegistryAnalyzerConfig::CreateDefault()));

    const auto missingHive = temp.Path(L"missing.hiv");
    const HiveHeader missingHeader = analyzer.ParseHiveHeader(missingHive.wstring());
    EXPECT_FALSE(missingHeader.isValid);
    EXPECT_FALSE(missingHeader.isCorrupted);
    EXPECT_FALSE(analyzer.ValidateHiveStructure(missingHive.wstring()));
    EXPECT_FALSE(analyzer.GetKeyCell(missingHive.wstring(), 0).has_value());
    EXPECT_FALSE(analyzer.GetKeyCell(missingHive.wstring(), 0xFFFFFFFFu).has_value());

    std::vector<uint8_t> malformedHive(0x100, 0x41);
    malformedHive[0] = 'B';
    malformedHive[1] = 'A';
    malformedHive[2] = 'D';
    malformedHive[3] = '!';
    const auto malformedHivePath = temp.WriteBytes(L"malformed.hiv", malformedHive);

    const HiveHeader malformedHeader = analyzer.ParseHiveHeader(malformedHivePath.wstring());
    EXPECT_FALSE(malformedHeader.isValid);
    EXPECT_TRUE(malformedHeader.isCorrupted);
    EXPECT_FALSE(analyzer.ValidateHiveStructure(malformedHivePath.wstring()));

    const AnalysisResult hiveResult = analyzer.AnalyzeHiveFile(malformedHivePath.wstring());
    EXPECT_TRUE(hiveResult.hadErrors);
    EXPECT_FALSE(hiveResult.completed);
    EXPECT_TRUE(ContainsString(hiveResult.errors, "Invalid hive file"));

    EXPECT_EQ(analyzer.LoadThreatIndicators(missingHive.wstring()), 0u);

    const auto indicatorsPath = temp.WriteText(
        L"indicators.txt",
        "# comment\n"
        "HKLM\\\\Software\\\\Bad|Run|ThreatOne|FamilyOne|T1112\n"
        "HKCU\\\\Software\\\\Bad|Value|ThreatTwo|FamilyTwo|\n");
    EXPECT_EQ(analyzer.LoadThreatIndicators(indicatorsPath.wstring()), 2u);
    EXPECT_TRUE(analyzer.SearchIOCs({ L"shadowstrike" }).empty());

    const auto timelinePath = temp.Path(L"timeline.csv");
    EXPECT_TRUE(analyzer.ExportTimeline(timelinePath.wstring()));
    EXPECT_EQ(
        temp.ReadText(timelinePath),
        "Timestamp,Action,Hive,KeyPath,ValueName,Description,IsAnomaly\n");
}

TEST_F(RegistryAnalyzerTest, CallbackAndUninitializedAccessContractsRemainSafe) {
    EXPECT_FALSE(analyzer.IsAnalysisRunning());
    EXPECT_TRUE(analyzer.GetHiddenKeys().empty());
    EXPECT_TRUE(analyzer.GetHiddenValues().empty());
    EXPECT_TRUE(analyzer.GetAnomalies().empty());
    EXPECT_TRUE(analyzer.GetAnomaliesByType(AnomalyType::APIHiddenKey).empty());
    EXPECT_TRUE(analyzer.GetAnomaliesBySeverity(AnomalySeverity::Low).empty());
    EXPECT_FALSE(analyzer.GetAnomalyById(0xDEADBEEFull).has_value());
    EXPECT_TRUE(analyzer.GetHighEntropyValues().empty());
    EXPECT_EQ(analyzer.RegisterAnomalyCallback({}), 0u);
    EXPECT_EQ(analyzer.RegisterProgressCallback({}), 0u);
    EXPECT_EQ(analyzer.RegisterHiddenEntryCallback({}), 0u);

    const uint64_t anomalyCallbackId =
        analyzer.RegisterAnomalyCallback([](const RegistryAnomaly&) {});
    const uint64_t progressCallbackId =
        analyzer.RegisterProgressCallback([](const std::wstring&, uint32_t) {});
    const uint64_t hiddenCallbackId =
        analyzer.RegisterHiddenEntryCallback([](const std::wstring&, bool) {});

    EXPECT_NE(anomalyCallbackId, 0u);
    EXPECT_NE(progressCallbackId, 0u);
    EXPECT_NE(hiddenCallbackId, 0u);
    EXPECT_NE(anomalyCallbackId, progressCallbackId);
    EXPECT_NE(progressCallbackId, hiddenCallbackId);

    EXPECT_TRUE(analyzer.UnregisterCallback(anomalyCallbackId));
    EXPECT_TRUE(analyzer.UnregisterCallback(progressCallbackId));
    EXPECT_TRUE(analyzer.UnregisterCallback(hiddenCallbackId));
    EXPECT_FALSE(analyzer.UnregisterCallback(hiddenCallbackId));
    EXPECT_FALSE(analyzer.UnregisterCallback(0xFFFFFFFFull));
}

}  // namespace ShadowStrike::Core::Registry::Test
