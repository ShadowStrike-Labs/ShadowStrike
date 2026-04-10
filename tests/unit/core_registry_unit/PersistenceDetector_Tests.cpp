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
#include "CoreRegistry_TestUtils.hpp"

namespace ShadowStrike::Core::Registry::Test {

namespace {

class ScopedEnvironmentVariable {
public:
    ScopedEnvironmentVariable(std::wstring_view name, const std::wstring& value)
        : name_(name) {
        DWORD required = ::GetEnvironmentVariableW(name_.c_str(), nullptr, 0);
        if (required > 0) {
            hadOriginalValue_ = true;
            originalValue_.resize(required - 1);
            (void)::GetEnvironmentVariableW(
                name_.c_str(),
                originalValue_.data(),
                static_cast<DWORD>(originalValue_.size() + 1));
        }

        (void)::SetEnvironmentVariableW(name_.c_str(), value.c_str());
    }

    ~ScopedEnvironmentVariable() {
        if (hadOriginalValue_) {
            (void)::SetEnvironmentVariableW(name_.c_str(), originalValue_.c_str());
        } else {
            (void)::SetEnvironmentVariableW(name_.c_str(), nullptr);
        }
    }

private:
    std::wstring name_;
    std::wstring originalValue_;
    bool hadOriginalValue_{ false };
};

}  // namespace

class PersistenceDetectorTest : public ::testing::Test {
protected:
    PersistenceDetector& detector = PersistenceDetector::Instance();
    TempDirectoryGuard temp{ L"ShadowStrike_PersistenceDetector_UT" };

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

TEST_F(PersistenceDetectorTest, InitializedParsingAndLocationNormalizationHandleRegistryEdgeCases) {
    ASSERT_TRUE(detector.Initialize(PersistenceDetectorConfig::CreateDefault()));

    const std::array<uint8_t, 2> minimalExecutable{ 'M', 'Z' };
    const auto envTargetPath = temp.WriteBytes(
        L"payload folder\\shadow payload.exe",
        minimalExecutable);
    const auto dllPath = temp.WriteBytes(L"plugin.dll", minimalExecutable);
    const auto htaPath = temp.WriteText(
        L"launcher.hta",
        "<html><script>close()</script></html>");

    const ScopedEnvironmentVariable envOverride(
        L"SHADOWSTRIKE_PERSISTENCE_UT_BIN",
        envTargetPath.wstring());

    const TargetBinary envResolved = detector.ResolveTarget(
        L"\"%SHADOWSTRIKE_PERSISTENCE_UT_BIN%\" --scan --quiet");
    EXPECT_EQ(envResolved.path, envTargetPath.wstring());
    EXPECT_EQ(envResolved.arguments, L"--scan --quiet");
    EXPECT_TRUE(envResolved.exists);
    EXPECT_TRUE(envResolved.isExecutable);

    EXPECT_EQ(
        detector.IsPersistenceLocation(
            L"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
        PersistenceType::RunKey);
    EXPECT_EQ(
        detector.IsPersistenceLocation(
            L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\notepad.exe"),
        PersistenceType::IFEO_Debugger);
    EXPECT_EQ(
        detector.IsPersistenceLocation(
            L"\\Registry\\User\\S-1-5-21-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        PersistenceType::RunKeyOnce);

    const auto rundllTargets = detector.ResolveComplexCommand(
        L"rundll32.exe " + dllPath.wstring() + L",EntryPoint");
    ASSERT_GE(rundllTargets.size(), 2u);
    EXPECT_EQ(rundllTargets[1].path, dllPath.wstring());
    EXPECT_EQ(rundllTargets[1].description, L"Target DLL loaded via rundll32");

    const auto regsvrTargets = detector.ResolveComplexCommand(
        L"regsvr32.exe /s " + dllPath.wstring());
    ASSERT_GE(regsvrTargets.size(), 2u);
    EXPECT_EQ(regsvrTargets[1].path, dllPath.wstring());
    EXPECT_EQ(regsvrTargets[1].description, L"Target DLL registered via regsvr32");

    const auto mshtaTargets = detector.ResolveComplexCommand(
        L"mshta.exe " + htaPath.wstring());
    ASSERT_GE(mshtaTargets.size(), 2u);
    EXPECT_EQ(mshtaTargets[1].path, htaPath.wstring());
    EXPECT_EQ(mshtaTargets[1].description, L"HTA/Script target executed via mshta");

    const auto powershellTargets = detector.ResolveComplexCommand(
        L"powershell.exe -enc "
        L"VwByAGkAdABlAC0ASABvAHMAdAAgAHMAaABhAGQAbwB3AHMAdAByAGkAawBlAA==");
    ASSERT_GE(powershellTargets.size(), 2u);
    EXPECT_EQ(powershellTargets.back().path, L"DECODED_SCRIPT");
    EXPECT_TRUE(powershellTargets.back().isScript);
    EXPECT_EQ(powershellTargets.back().arguments, L"Write-Host shadowstrike");
}

}  // namespace ShadowStrike::Core::Registry::Test
