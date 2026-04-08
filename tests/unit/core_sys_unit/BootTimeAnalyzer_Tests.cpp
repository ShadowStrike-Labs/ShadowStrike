/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
/**
 * @file BootTimeAnalyzer_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::BootTimeAnalyzer.
 *
 * Coverage focus:
 * - configuration defaults, statistics reset, enum-name helpers, and versioning
 * - singleton lifecycle and configuration round-tripping
 * - startup-folder disable/enable flows on real temporary files
 * - diagnostics, export surfaces, and self-test behavior
 */

#include "pch.h"

#include "CoreSystem_TestUtils.hpp"
#include "../../../src/Shared_modules/Core/System/BootTimeAnalyzer.hpp"

#include <chrono>

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::System;
using namespace ShadowStrike::Tests::CoreSystem;
using ::testing::HasSubstr;

class BootTimeAnalyzerTest : public TempDirectoryFixture {
protected:
    void SetUp() override {
        TempDirectoryFixture::SetUp();
        auto& analyzer = BootTimeAnalyzer::Instance();
        analyzer.Shutdown();
        analyzer.ResetStatistics();
    }

    void TearDown() override {
        BootTimeAnalyzer::Instance().Shutdown();
        TempDirectoryFixture::TearDown();
    }
};

TEST(BootTimeAnalyzerValueTests, ConfigStatisticsUtilitiesAndVersionRemainStable) {
    const auto defaults = BootTimeAnalyzerConfig::CreateDefault();
    EXPECT_TRUE(defaults.analyzeDrivers);
    EXPECT_TRUE(defaults.analyzeServices);
    EXPECT_TRUE(defaults.analyzeApplications);
    EXPECT_TRUE(defaults.evaluateSecurity);
    EXPECT_TRUE(defaults.generateRecommendations);

    BootTimeAnalyzerStatistics stats;
    stats.analysesPerformed.store(3, std::memory_order_relaxed);
    stats.startupItemsScanned.store(4, std::memory_order_relaxed);
    stats.suspiciousItemsFound.store(1, std::memory_order_relaxed);
    stats.optimizationsSuggested.store(2, std::memory_order_relaxed);
    stats.bcdTamperDetections.store(1, std::memory_order_relaxed);
    stats.kernelQueriesPerformed.store(5, std::memory_order_relaxed);
    stats.bootDriversAnalyzed.store(6, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.analysesPerformed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.startupItemsScanned.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.suspiciousItemsFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.optimizationsSuggested.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bcdTamperDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.kernelQueriesPerformed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.bootDriversAnalyzed.load(std::memory_order_relaxed), 0u);

    EXPECT_EQ(GetBootPhaseName(BootPhase::KernelInit), "Kernel Initialization");
    EXPECT_EQ(GetStartupItemTypeName(StartupItemType::ScheduledTask), "Scheduled Task");
    EXPECT_EQ(GetStartupItemRiskName(StartupItemRisk::Critical), "Critical");
    EXPECT_EQ(GetSecureBootStatusName(SecureBootStatus::NotSupported), "Not Supported");
    EXPECT_EQ(GetELAMDriverStatusName(ELAMDriverStatus::Unknown_), "Unknown to ELAM");
    EXPECT_EQ(GetBootPhaseName(static_cast<BootPhase>(0xFF)), "Unknown");
    EXPECT_EQ(BootTimeAnalyzer::GetVersionString(), "3.2.0");
}

TEST_F(BootTimeAnalyzerTest, InitializeUpdateConfigAndDiagnosticsExposePublicState) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));

    EXPECT_TRUE(BootTimeAnalyzer::HasInstance());
    EXPECT_TRUE(analyzer.IsInitialized());
    EXPECT_EQ(analyzer.GetShadowStrikeBootImpact(), 150ms);

    auto updated = analyzer.GetConfig();
    updated.analyzeDrivers = false;
    updated.evaluateSecurity = false;
    updated.generateRecommendations = false;
    ASSERT_TRUE(analyzer.UpdateConfig(updated));

    const auto reloaded = analyzer.GetConfig();
    EXPECT_FALSE(reloaded.analyzeDrivers);
    EXPECT_FALSE(reloaded.evaluateSecurity);
    EXPECT_FALSE(reloaded.generateRecommendations);

    const auto diagnostics = analyzer.RunDiagnostics();
    ASSERT_FALSE(diagnostics.empty());
    EXPECT_THAT(diagnostics.front(), HasSubstr(L"BootTimeAnalyzer Diagnostics"));
}

TEST_F(BootTimeAnalyzerTest, StartupFolderItemCanBeDisabledAndReenabledOnDisk) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));

    const auto startupFile = WriteText(L"startup\\agent.lnk", "shadowstrike");

    StartupItem enabledItem;
    enabledItem.name = startupFile.filename().wstring();
    enabledItem.path = startupFile.wstring();
    enabledItem.type = StartupItemType::StartupFolder;

    ASSERT_TRUE(analyzer.DisableStartupItem(enabledItem));
    const auto disabledPath = startupFile.parent_path() / L"Disabled" / startupFile.filename();
    EXPECT_FALSE(std::filesystem::exists(startupFile));
    ASSERT_TRUE(std::filesystem::exists(disabledPath));

    StartupItem disabledItem = enabledItem;
    disabledItem.path = disabledPath.wstring();

    EXPECT_TRUE(analyzer.EnableStartupItem(disabledItem));
    EXPECT_TRUE(std::filesystem::exists(startupFile));
    EXPECT_FALSE(std::filesystem::exists(disabledPath));
}

TEST_F(BootTimeAnalyzerTest, StartupAnalysisAndExportsProduceReadableArtifacts) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));

    const auto samplePath = WriteText(L"startup\\sample.exe", "shadowstrike-boot");
    const auto analyzed = analyzer.AnalyzeStartupItem(samplePath.wstring());
    EXPECT_EQ(analyzed.path, samplePath.wstring());
    EXPECT_EQ(analyzed.name, L"sample.exe");

    const auto reportPath = MakePath(L"boot-report.txt");
    const auto optimizationPath = MakePath(L"boot-optimizations.txt");
    ASSERT_TRUE(analyzer.ExportReport(reportPath.wstring()));
    ASSERT_TRUE(analyzer.ExportOptimizations(optimizationPath.wstring()));

    EXPECT_THAT(ReadTextFile(reportPath), HasSubstr("BootTimeAnalyzer Report"));
    EXPECT_THAT(ReadTextFile(optimizationPath), HasSubstr("Boot Optimization Suggestions"));
}

TEST_F(BootTimeAnalyzerTest, SelfTestPassesAfterInitialization) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));
    EXPECT_TRUE(analyzer.SelfTest());
}

}  // namespace
