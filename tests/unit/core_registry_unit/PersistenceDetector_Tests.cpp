/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for Core\Registry\PersistenceDetector deterministic contracts.
 *
 * Focus:
 *   - preset factory behavior and statistics reset
 *   - persistence entry conversions for services, tasks, and WMI subscriptions
 *   - callback registration and safe guard behavior before initialization
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "../../../src/Shared_modules/Core/Registry/PersistenceDetector.hpp"

namespace ShadowStrike::Core::Registry::Test {

class PersistenceDetectorTest : public ::testing::Test {
protected:
    PersistenceDetector& detector = PersistenceDetector::Instance();

    void SetUp() override {
        detector.Shutdown();
        detector.ResetStatistics();
    }

    void TearDown() override {
        detector.Shutdown();
    }
};

TEST_F(PersistenceDetectorTest, ConfigFactoriesAndStatisticsRemainStable) {
    const auto defaults = PersistenceDetectorConfig::CreateDefault();
    const auto quick = PersistenceDetectorConfig::CreateQuick();
    const auto thorough = PersistenceDetectorConfig::CreateThorough();
    const auto forensic = PersistenceDetectorConfig::CreateForensic();

    EXPECT_EQ(defaults.defaultScope, ScanScope::Standard);
    EXPECT_TRUE(defaults.resolveTargets);
    EXPECT_TRUE(defaults.verifySignatures);
    EXPECT_TRUE(defaults.checkHashes);
    EXPECT_TRUE(defaults.checkReputation);
    EXPECT_TRUE(defaults.detectHidden);
    EXPECT_TRUE(defaults.enableRealTimeAnalysis);
    EXPECT_TRUE(defaults.useCache);
    EXPECT_TRUE(defaults.logSuspiciousOnly);

    EXPECT_EQ(quick.defaultScope, ScanScope::Critical);
    EXPECT_FALSE(quick.verifySignatures);
    EXPECT_FALSE(quick.checkHashes);
    EXPECT_FALSE(quick.checkReputation);
    EXPECT_FALSE(quick.detectHidden);
    EXPECT_TRUE(quick.useCache);

    EXPECT_EQ(thorough.defaultScope, ScanScope::Extended);
    EXPECT_TRUE(thorough.verifySignatures);
    EXPECT_TRUE(thorough.checkHashes);
    EXPECT_TRUE(thorough.checkReputation);
    EXPECT_TRUE(thorough.detectHidden);
    EXPECT_FALSE(thorough.logAllEntries);
    EXPECT_TRUE(thorough.logSuspiciousOnly);

    EXPECT_EQ(forensic.defaultScope, ScanScope::Full);
    EXPECT_EQ(forensic.maxScanThreads, 16u);
    EXPECT_EQ(forensic.scanTimeoutMs, 600000u);
    EXPECT_FALSE(forensic.enableRealTimeAnalysis);
    EXPECT_TRUE(forensic.logAllEntries);
    EXPECT_FALSE(forensic.logSuspiciousOnly);

    PersistenceDetectorStatistics stats;
    stats.totalScans.store(2, std::memory_order_relaxed);
    stats.entriesScanned.store(8, std::memory_order_relaxed);
    stats.suspiciousEntriesFound.store(3, std::memory_order_relaxed);
    stats.realTimeAnalyses.store(5, std::memory_order_relaxed);
    stats.signaturesVerified.store(7, std::memory_order_relaxed);
    stats.cacheHits.store(11, std::memory_order_relaxed);
    stats.avgScanTimeMs.store(13, std::memory_order_relaxed);
    stats.avgAnalysisTimeUs.store(17, std::memory_order_relaxed);

    stats.Reset();

    EXPECT_EQ(stats.totalScans.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.entriesScanned.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.suspiciousEntriesFound.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.realTimeAnalyses.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.signaturesVerified.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.cacheHits.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.avgScanTimeMs.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.avgAnalysisTimeUs.load(std::memory_order_relaxed), 0u);
}

TEST_F(PersistenceDetectorTest, EntryConversionsPreserveExpectedLocationTypeAndMitreMapping) {
    ServiceEntry service;
    service.serviceName = L"ShadowStrikeSvc";
    service.description = L"Core service";
    service.imagePath = L"C:\\Program Files\\ShadowStrike\\service.exe";
    service.startType = SERVICE_AUTO_START;
    service.serviceType = SERVICE_WIN32_OWN_PROCESS;

    const PersistenceEntry serviceEntry = service.asPersistenceEntry();
    EXPECT_EQ(serviceEntry.type, PersistenceType::Service);
    EXPECT_EQ(serviceEntry.location, L"HKLM\\SYSTEM\\CurrentControlSet\\Services");
    EXPECT_EQ(serviceEntry.entryName, service.serviceName);
    EXPECT_EQ(serviceEntry.rawCommand, service.imagePath);
    EXPECT_EQ(serviceEntry.status, EntryStatus::Active);
    EXPECT_EQ(serviceEntry.mitreTechnique, "T1543.003");

    service.startType = SERVICE_DISABLED;
    service.serviceType = SERVICE_KERNEL_DRIVER;
    const PersistenceEntry driverEntry = service.asPersistenceEntry();
    EXPECT_EQ(driverEntry.type, PersistenceType::KernelDriver);
    EXPECT_EQ(driverEntry.status, EntryStatus::Disabled);

    service.startType = SERVICE_BOOT_START;
    service.serviceType = SERVICE_FILE_SYSTEM_DRIVER;
    const PersistenceEntry fileSystemDriverEntry = service.asPersistenceEntry();
    EXPECT_EQ(fileSystemDriverEntry.type, PersistenceType::KernelDriver);
    EXPECT_EQ(fileSystemDriverEntry.status, EntryStatus::Active);

    ScheduledTaskEntry task;
    task.taskName = L"ShadowStrikeTask";
    task.description = L"Task description";
    task.enabled = false;
    task.actions.push_back({
        L"Exec",
        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        L"-File C:\\Temp\\task.ps1",
        L"C:\\Temp"
    });

    const PersistenceEntry taskEntry = task.asPersistenceEntry();
    EXPECT_EQ(taskEntry.type, PersistenceType::ScheduledTask);
    EXPECT_EQ(taskEntry.location, L"Task Scheduler");
    EXPECT_EQ(taskEntry.entryName, task.taskName);
    EXPECT_EQ(taskEntry.status, EntryStatus::Disabled);
    EXPECT_EQ(taskEntry.target.path, task.actions.front().path);
    EXPECT_EQ(taskEntry.target.arguments, task.actions.front().arguments);
    EXPECT_EQ(taskEntry.mitreTechnique, "T1053.005");

    ScheduledTaskEntry actionlessTask;
    actionlessTask.taskName = L"ActionlessTask";
    actionlessTask.enabled = true;
    const PersistenceEntry actionlessTaskEntry = actionlessTask.asPersistenceEntry();
    EXPECT_TRUE(actionlessTaskEntry.rawCommand.empty());
    EXPECT_TRUE(actionlessTaskEntry.target.path.empty());
    EXPECT_EQ(actionlessTaskEntry.status, EntryStatus::Active);

    WMISubscription subscription;
    subscription.filterName = L"ShadowStrikeFilter";
    subscription.filterQuery = L"SELECT * FROM __InstanceCreationEvent";
    subscription.consumerName = L"ShadowStrikeConsumer";
    subscription.consumerCommand = L"powershell.exe -nop -w hidden";

    const PersistenceEntry wmiEntry = subscription.asPersistenceEntry();
    EXPECT_EQ(wmiEntry.type, PersistenceType::WMI_EventConsumer);
    EXPECT_EQ(wmiEntry.location, L"WMI Repository");
    EXPECT_EQ(wmiEntry.entryName, L"ShadowStrikeFilter -> ShadowStrikeConsumer");
    EXPECT_EQ(wmiEntry.rawCommand, subscription.consumerCommand);
    EXPECT_EQ(wmiEntry.mitreTechnique, "T1546.003");
}

TEST_F(PersistenceDetectorTest, CallbackContractsAndUninitializedGuardsRemainSafe) {
    const uint64_t progressCallbackId =
        detector.RegisterProgressCallback([](uint32_t, uint32_t, const std::wstring&) {});
    const uint64_t entryCallbackId =
        detector.RegisterEntryCallback([](const PersistenceEntry&) {});
    const uint64_t alertCallbackId =
        detector.RegisterAlertCallback([](const PersistenceAlert&) {});

    EXPECT_NE(progressCallbackId, 0u);
    EXPECT_NE(entryCallbackId, 0u);
    EXPECT_NE(alertCallbackId, 0u);
    EXPECT_NE(progressCallbackId, entryCallbackId);

    EXPECT_TRUE(detector.UnregisterCallback(progressCallbackId));
    EXPECT_TRUE(detector.UnregisterCallback(entryCallbackId));
    EXPECT_TRUE(detector.UnregisterCallback(alertCallbackId));
    EXPECT_FALSE(detector.UnregisterCallback(alertCallbackId));

    EXPECT_EQ(
        detector.IsPersistenceLocation(L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        PersistenceType::Unknown);
    EXPECT_EQ(
        detector.AnalyzeRealTime(
            L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            L"ShadowStrike",
            L"powershell.exe"),
        PersistenceRiskLevel::Unknown);
    EXPECT_TRUE(detector.ResolveTarget(L"\"C:\\Temp\\evil.exe\" -nop").path.empty());
    EXPECT_FALSE(detector.ResolveTarget(L"\"C:\\Temp\\evil.exe\" -nop").exists);
    EXPECT_TRUE(detector.ResolveComplexCommand(L"rundll32.exe C:\\Temp\\evil.dll,EntryPoint").empty());

    const RealTimeAnalysis analysis = detector.AnalyzeRealTimeFull(
        L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"ShadowStrike",
        L"powershell.exe");
    EXPECT_EQ(analysis.risk, PersistenceRiskLevel::Unknown);
    EXPECT_FALSE(analysis.isPersistenceAttempt);
    EXPECT_FALSE(analysis.isKnownBad);
}

}  // namespace ShadowStrike::Core::Registry::Test
