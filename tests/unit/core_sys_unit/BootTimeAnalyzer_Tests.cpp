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
 * - singleton lifecycle and configuration round-tripping, including pre-init updates
 * - startup-folder disable/enable flows on real temporary files plus negative-path analysis
 * - diagnostics, export surfaces, and self-test behavior
 */

#include "pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "CoreSystem_TestUtils.hpp"
#include "../../../src/PhantomCore/Core/System/BootTimeAnalyzer.hpp"

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

TEST_F(BootTimeAnalyzerTest, PreInitConfigAndNegativeStartupAnalysisReflectCurrentGuards) {
    auto& analyzer = BootTimeAnalyzer::Instance();

    auto updated = BootTimeAnalyzerConfig::CreateDefault();
    updated.analyzeDrivers = false;
    updated.generateRecommendations = false;
    ASSERT_TRUE(analyzer.UpdateConfig(updated));

    const auto reloaded = analyzer.GetConfig();
    EXPECT_FALSE(reloaded.analyzeDrivers);
    EXPECT_FALSE(reloaded.generateRecommendations);

    const auto emptyItem = analyzer.AnalyzeStartupItem(L"");
    EXPECT_TRUE(emptyItem.path.empty());
    EXPECT_TRUE(emptyItem.name.empty());
    EXPECT_EQ(emptyItem.type, StartupItemType::Unknown);
    EXPECT_EQ(emptyItem.riskLevel, StartupItemRisk::Medium);
    EXPECT_TRUE(emptyItem.isSuspicious);
    EXPECT_EQ(emptyItem.suspicionReason, L"No executable path found");

    const auto missingPath = MakePath(L"missing-startup.exe");
    const auto missingItem = analyzer.AnalyzeStartupItem(missingPath.wstring());
    EXPECT_EQ(missingItem.path, missingPath.wstring());
    EXPECT_EQ(missingItem.name, L"missing-startup.exe");
    EXPECT_EQ(missingItem.type, StartupItemType::Unknown);
    EXPECT_EQ(missingItem.riskLevel, StartupItemRisk::Medium);
    EXPECT_TRUE(missingItem.isSuspicious);
    EXPECT_EQ(missingItem.suspicionReason, L"Target file not found");

    StartupItem unsupportedItem;
    unsupportedItem.name = L"unsupported";
    unsupportedItem.path = missingPath.wstring();
    unsupportedItem.type = StartupItemType::Unknown;
    EXPECT_FALSE(analyzer.DisableStartupItem(unsupportedItem));
    EXPECT_FALSE(analyzer.EnableStartupItem(unsupportedItem));
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

TEST_F(BootTimeAnalyzerTest, ExportAndEnableGuardsFollowCurrentFilesystemSemantics) {
    auto& analyzer = BootTimeAnalyzer::Instance();

    const auto reportPath = MakePath(L"preinit-boot-report.txt");
    ASSERT_TRUE(analyzer.ExportReport(reportPath.wstring()));
    EXPECT_THAT(ReadTextFile(reportPath), HasSubstr("BootTimeAnalyzer Report"));

    const auto missingParentReport = testRoot_ / L"missing-parent" / L"boot-report.txt";
    const auto missingParentOptimizations = testRoot_ / L"missing-parent" / L"boot-optimizations.txt";
    EXPECT_FALSE(analyzer.ExportReport(missingParentReport.wstring()));
    EXPECT_FALSE(analyzer.ExportOptimizations(missingParentOptimizations.wstring()));

    const auto startupFile = WriteText(L"startup\\enabled-only.lnk", "shadowstrike");

    StartupItem item;
    item.name = startupFile.filename().wstring();
    item.path = startupFile.wstring();
    item.type = StartupItemType::StartupFolder;

    EXPECT_FALSE(analyzer.EnableStartupItem(item));
}

TEST_F(BootTimeAnalyzerTest, ZeroCountSlowListsReturnEmptyVectors) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));

    EXPECT_TRUE(analyzer.GetSlowestDrivers(0).empty());
    EXPECT_TRUE(analyzer.GetSlowestServices(0).empty());
}

TEST_F(BootTimeAnalyzerTest, SelfTestPassesAfterInitialization) {
    auto& analyzer = BootTimeAnalyzer::Instance();
    ASSERT_TRUE(analyzer.Initialize(BootTimeAnalyzerConfig::CreateDefault()));
    EXPECT_TRUE(analyzer.SelfTest());
}

}  // namespace
