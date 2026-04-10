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
        "Timestamp,Action,Hive,KeyPath,ValueName,Description,IsAnomaly\r\n");
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

TEST_F(RegistryAnalyzerTest, HiveHeaderAndKeyCellBoundariesRemainDeterministic) {
    ASSERT_TRUE(analyzer.Initialize(RegistryAnalyzerConfig::CreateDefault()));

    std::vector<uint8_t> hiveBytes(0x3000, 0);

    const auto writeUInt16 = [&hiveBytes](size_t offset, uint16_t value) {
        std::memcpy(hiveBytes.data() + offset, &value, sizeof(value));
    };
    const auto writeUInt32 = [&hiveBytes](size_t offset, uint32_t value) {
        std::memcpy(hiveBytes.data() + offset, &value, sizeof(value));
    };
    const auto writeInt32 = [&hiveBytes](size_t offset, int32_t value) {
        std::memcpy(hiveBytes.data() + offset, &value, sizeof(value));
    };
    const auto writeUInt64 = [&hiveBytes](size_t offset, uint64_t value) {
        std::memcpy(hiveBytes.data() + offset, &value, sizeof(value));
    };

    hiveBytes[0] = 'r';
    hiveBytes[1] = 'e';
    hiveBytes[2] = 'g';
    hiveBytes[3] = 'f';
    writeUInt32(0x04, 1u);
    writeUInt32(0x08, 2u);
    writeUInt64(0x0C, 0u);
    writeUInt32(0x14, 1u);
    writeUInt32(0x18, 3u);
    writeUInt32(0x1C, 0u);
    writeUInt32(0x24, 0x40u);
    writeUInt32(0x28, 0x2000u);

    writeInt32(0x1000, 5);

    const size_t wrongSignatureCell = 0x1000 + 0x20;
    writeInt32(wrongSignatureCell, -0x60);
    writeUInt16(wrongSignatureCell + 4, 0x6B76);

    const size_t validCell = 0x1000 + 0x40;
    writeInt32(validCell, -0x600);
    writeUInt16(validCell + 4, 0x6B6E);
    writeUInt32(validCell + 4 + 0x10, 0x20u);
    writeUInt32(validCell + 4 + 0x14, 2u);
    writeUInt32(validCell + 4 + 0x24, 3u);
    writeUInt32(validCell + 4 + 0x2C, 0x88u);
    writeUInt32(validCell + 4 + 0x30, 0x99u);
    writeUInt16(validCell + 4 + 0x48, 1500u);

    for (size_t i = 0; i < 1500; ++i) {
        hiveBytes[validCell + 4 + 0x4C + i] = 'A';
    }
    hiveBytes[validCell + 4 + 0x4C + 12] = '\0';

    const auto hivePath = temp.WriteBytes(L"dirty-with-cells.hiv", hiveBytes);

    const HiveHeader header = analyzer.ParseHiveHeader(hivePath.wstring());
    EXPECT_TRUE(header.isValid);
    EXPECT_FALSE(header.isCorrupted);
    EXPECT_TRUE(header.isDirty);
    EXPECT_EQ(header.sequence1, 1u);
    EXPECT_EQ(header.sequence2, 2u);
    EXPECT_EQ(header.rootCellOffset, 0x40u);
    EXPECT_TRUE(analyzer.ValidateHiveStructure(hivePath.wstring()));

    EXPECT_FALSE(analyzer.GetKeyCell(hivePath.wstring(), 0u).has_value());
    EXPECT_FALSE(analyzer.GetKeyCell(hivePath.wstring(), 0x20u).has_value());

    const auto keyCell = analyzer.GetKeyCell(hivePath.wstring(), 0x40u);
    ASSERT_TRUE(keyCell.has_value());
    EXPECT_EQ(keyCell->offset, 0x40u);
    EXPECT_TRUE(keyCell->isAllocated);
    EXPECT_FALSE(keyCell->isDeleted);
    EXPECT_EQ(keyCell->parentOffset, 0x20u);
    EXPECT_EQ(keyCell->subKeyCount, 2u);
    EXPECT_EQ(keyCell->valueCount, 3u);
    EXPECT_EQ(keyCell->securityOffset, 0x88u);
    EXPECT_EQ(keyCell->classNameOffset, 0x99u);
    EXPECT_TRUE(keyCell->hasNullByte);
    EXPECT_LE(keyCell->keyName.size(), 1024u);
    EXPECT_LE(keyCell->keyNameRaw.size(), 1024u);
}

}  // namespace ShadowStrike::Core::Registry::Test
