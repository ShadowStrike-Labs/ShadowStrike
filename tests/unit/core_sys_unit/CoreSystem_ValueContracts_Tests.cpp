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
 * @file CoreSystem_ValueContracts_Tests.cpp
 * @brief Value-contract coverage for Core::System modules whose honest unit seams
 *        are configuration factories and atomic statistics only.
 *
 * Coverage focus:
 * - CrashHandler operational presets across default, debug, and production modes
 * - DriverAnalyzer scan-depth presets plus vulnerable-driver lookup contracts
 * - runtime statistics reset semantics for both modules
 */

#include "pch.h"

#include "../../../src/PhantomCore/Core/System/CrashHandler.hpp"
#include "../../../src/PhantomCore/Core/System/DriverAnalyzer.hpp"

namespace {

using namespace std::chrono_literals;
using namespace ShadowStrike::Core::System;

TEST(CoreSystemValueContractTests, CrashHandlerConfigFactoriesReflectOperationalPolicies) {
    const auto defaults = CrashHandlerConfig::CreateDefault();
    const auto debug = CrashHandlerConfig::CreateDebug();
    const auto production = CrashHandlerConfig::CreateProduction();

    EXPECT_TRUE(defaults.createDumpOnCrash);
    EXPECT_EQ(defaults.defaultDumpType, DumpType::Normal);
    EXPECT_THAT(defaults.dumpDirectory, ::testing::HasSubstr(L"ProgramData\\ShadowStrike\\Dumps"));
    EXPECT_FALSE(defaults.compressDumps);
    EXPECT_EQ(defaults.defaultRecoveryAction, RecoveryAction::NotifyWatchdog);
    EXPECT_EQ(defaults.restartCooldown, 60000ms);
    EXPECT_FALSE(defaults.enableCrashReporting);
    EXPECT_FALSE(defaults.includeMemoryDump);
    EXPECT_FALSE(defaults.breakOnCrash);
    EXPECT_TRUE(defaults.logStackTrace);

    EXPECT_EQ(debug.defaultDumpType, DumpType::WithFullMemory);
    EXPECT_TRUE(debug.breakOnCrash);
    EXPECT_FALSE(debug.enableAutoRestart);
    EXPECT_TRUE(debug.logStackTrace);

    EXPECT_EQ(production.defaultDumpType, DumpType::FilterMemory);
    EXPECT_EQ(production.maxDumpFiles, 5u);
    EXPECT_TRUE(production.compressDumps);
    EXPECT_TRUE(production.enableCrashReporting);
    EXPECT_TRUE(production.enableAutoRestart);
    EXPECT_FALSE(production.breakOnCrash);
    EXPECT_FALSE(production.logStackTrace);
}

TEST(CoreSystemValueContractTests, CrashHandlerStatisticsResetClearsAllCounters) {
    CrashHandlerStatistics stats;
    stats.totalCrashes.store(4, std::memory_order_relaxed);
    stats.recoveredCrashes.store(2, std::memory_order_relaxed);
    stats.fatalCrashes.store(1, std::memory_order_relaxed);
    stats.dumpsCreated.store(3, std::memory_order_relaxed);
    stats.dumpsUploaded.store(1, std::memory_order_relaxed);
    stats.restartAttempts.store(2, std::memory_order_relaxed);
    stats.handledExceptions.store(4, std::memory_order_relaxed);
    stats.accessViolations.store(1, std::memory_order_relaxed);
    stats.stackOverflows.store(1, std::memory_order_relaxed);
    stats.heapCorruptions.store(1, std::memory_order_relaxed);
    stats.cppExceptions.store(1, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.totalCrashes.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.recoveredCrashes.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.fatalCrashes.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.dumpsCreated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.dumpsUploaded.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.restartAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.handledExceptions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.accessViolations.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.stackOverflows.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.heapCorruptions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cppExceptions.load(std::memory_order_relaxed), 0u);
}

TEST(CoreSystemValueContractTests, DriverAnalyzerConfigFactoriesReflectScanDepthTradeoffs) {
    const auto defaults = DriverAnalyzerConfig::CreateDefault();
    const auto deep = DriverAnalyzerConfig::CreateDeep();
    const auto quick = DriverAnalyzerConfig::CreateQuick();

    EXPECT_TRUE(defaults.verifySignatures);
    EXPECT_TRUE(defaults.detectHiddenDrivers);
    EXPECT_TRUE(defaults.scanForRootkits);
    EXPECT_TRUE(defaults.checkVulnerableDrivers);
    EXPECT_TRUE(defaults.monitorCallbacks);
    EXPECT_FALSE(defaults.analyzeIOCTL);

    EXPECT_TRUE(deep.analyzeIOCTL);
    EXPECT_TRUE(deep.scanForRootkits);
    EXPECT_TRUE(deep.monitorCallbacks);

    EXPECT_TRUE(quick.verifySignatures);
    EXPECT_FALSE(quick.detectHiddenDrivers);
    EXPECT_FALSE(quick.scanForRootkits);
    EXPECT_TRUE(quick.checkVulnerableDrivers);
    EXPECT_FALSE(quick.monitorCallbacks);
    EXPECT_FALSE(quick.analyzeIOCTL);
}

TEST(CoreSystemValueContractTests, DriverAnalyzerStatisticsResetClearsAllCounters) {
    DriverAnalyzerStatistics stats;
    stats.driversAnalyzed.store(7, std::memory_order_relaxed);
    stats.signaturesVerified.store(6, std::memory_order_relaxed);
    stats.hiddenDriversFound.store(1, std::memory_order_relaxed);
    stats.rootkitIndicatorsFound.store(2, std::memory_order_relaxed);
    stats.vulnerableDriversFound.store(3, std::memory_order_relaxed);
    stats.maliciousDriversFound.store(1, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.driversAnalyzed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.signaturesVerified.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.hiddenDriversFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.rootkitIndicatorsFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.vulnerableDriversFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.maliciousDriversFound.load(std::memory_order_relaxed), 0u);
}

TEST(CoreSystemValueContractTests, DriverAnalyzerLookupNormalizesKnownVulnerableHashes) {
    auto& analyzer = DriverAnalyzer::Instance();

    const std::wstring capcomHash = L"C1D5CF8C43E7679B782630E93F5E6420CA1749A7663159A581B87A8FA3A429C0";
    EXPECT_TRUE(analyzer.IsVulnerableDriver(capcomHash));

    const auto entry = analyzer.GetVulnerableDriverInfo(capcomHash);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->driverName, L"Capcom.sys");
    EXPECT_EQ(entry->vendor, L"Capcom");
    ASSERT_EQ(entry->cveIds.size(), 1u);
    EXPECT_EQ(entry->cveIds.front(), L"CVE-2016-9892");
    EXPECT_EQ(entry->category, VulnerableDriverCategory::CodeExecution);
    EXPECT_TRUE(entry->canBeExploited);

    EXPECT_FALSE(analyzer.IsVulnerableDriver(L"deadbeef"));
    EXPECT_FALSE(analyzer.GetVulnerableDriverInfo(L"deadbeef").has_value());
}

TEST(CoreSystemValueContractTests, DriverAnalyzerLookupIsCaseInsensitiveForKnownHashes) {
    auto& analyzer = DriverAnalyzer::Instance();

    const std::wstring lowerHash = L"c1d5cf8c43e7679b782630e93f5e6420ca1749a7663159a581b87a8fa3a429c0";
    EXPECT_TRUE(analyzer.IsVulnerableDriver(lowerHash));

    const auto lowerEntry = analyzer.GetVulnerableDriverInfo(lowerHash);
    ASSERT_TRUE(lowerEntry.has_value());
    EXPECT_EQ(lowerEntry->driverName, L"Capcom.sys");
    EXPECT_EQ(lowerEntry->vendor, L"Capcom");
}

}  // namespace
