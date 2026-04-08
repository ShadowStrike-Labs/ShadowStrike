/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for SandboxAnalyzer deterministic behavior.
 *
 * Scope:
 *   - structured validation and serialization helpers used by reporting
 *   - statistics reset behavior
 *   - safe singleton guard paths before sandbox initialization
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <string_view>

#include "../../../src/Shared_modules/Core/Engine/SandboxAnalyzer.hpp"

namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::string_view haystack, std::string_view needle) {
    return haystack.find(needle) != std::string_view::npos;
}

Engine::VMConfiguration MakeValidVmConfiguration() {
    Engine::VMConfiguration vm;
    vm.vmName = "shadow-win11";
    vm.snapshotName = "golden";
    vm.environment = Engine::SandboxEnvironment::HyperV;
    vm.guestOS = Engine::GuestOSType::Windows11_x64;
    vm.memoryMb = 8192;
    vm.cpuCores = 4;
    vm.networkIsolation = true;
    return vm;
}

}  // namespace

class SandboxAnalyzerTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::SandboxAnalyzer::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::SandboxAnalyzer::Instance().Shutdown();
    }
};

TEST_F(SandboxAnalyzerTest, ErrorAndVmConfigurationHelpersEnforceOperationalSafety) {
    Engine::SandboxError error;
    EXPECT_FALSE(error.HasError());

    error.code = ERROR_INVALID_PARAMETER;
    error.message = L"bad input";
    error.context = L"vm bootstrap";
    EXPECT_TRUE(error.HasError());

    error.Clear();
    EXPECT_FALSE(error.HasError());
    EXPECT_TRUE(error.message.empty());
    EXPECT_TRUE(error.context.empty());

    Engine::VMConfiguration vm = MakeValidVmConfiguration();
    EXPECT_TRUE(vm.IsValid());
    const std::string vmJson = vm.ToJson();
    EXPECT_TRUE(Contains(vmJson, "\"vmName\":\"shadow-win11\""));
    EXPECT_TRUE(Contains(vmJson, "\"memoryMb\":8192"));

    vm.vmName.clear();
    EXPECT_FALSE(vm.IsValid());

    vm = MakeValidVmConfiguration();
    vm.snapshotName.clear();
    EXPECT_TRUE(vm.IsValid());

    vm = MakeValidVmConfiguration();
    vm.memoryMb = 256;
    EXPECT_FALSE(vm.IsValid());

    vm = MakeValidVmConfiguration();
    vm.cpuCores = 0;
    EXPECT_FALSE(vm.IsValid());
}

TEST_F(SandboxAnalyzerTest, SerializationSurfacesRemainStableForAnalysisReporting) {
    Engine::ProcessEvent processEvent;
    processEvent.eventType = "create";
    processEvent.processId = 100;
    processEvent.parentProcessId = 4;
    processEvent.processName = L"cmd.exe";
    EXPECT_TRUE(Contains(processEvent.ToJson(), "\"processName\":\"cmd.exe\""));

    Engine::FileEvent fileEvent;
    fileEvent.eventType = "write";
    fileEvent.filePath = L"C:\\temp\\drop.bin";
    fileEvent.fileSize = 64;
    fileEvent.sha256Hash = "deadbeef";
    EXPECT_TRUE(Contains(fileEvent.ToJson(), "\"sha256\":\"deadbeef\""));

    Engine::RegistryEvent registryEvent;
    registryEvent.eventType = "set";
    registryEvent.keyPath = L"HKCU\\Software\\ShadowStrike";
    registryEvent.valueName = L"Run";
    EXPECT_TRUE(Contains(registryEvent.ToJson(), "\"valueName\":\"Run\""));

    Engine::NetworkEvent networkEvent;
    networkEvent.protocol = "tcp";
    networkEvent.sourceIP = "10.0.0.5";
    networkEvent.sourcePort = 4444;
    networkEvent.destinationIP = "198.51.100.7";
    networkEvent.destinationPort = 443;
    EXPECT_TRUE(Contains(networkEvent.ToJson(), "\"destinationPort\":443"));

    Engine::BehavioralIndicator indicator;
    indicator.indicatorId = "IND-7";
    indicator.description = "Drops executable content";
    indicator.severity = 9;
    indicator.mitreId = "T1105";
    EXPECT_TRUE(Contains(indicator.ToJson(), "\"severity\":9"));

    Engine::ExtractedArtifact artifact;
    artifact.artifactType = "dropped_pe";
    artifact.originalPath = L"C:\\temp\\drop.bin";
    artifact.size = 4096;
    artifact.sha256Hash = "cafebabe";
    artifact.isMalicious = true;
    EXPECT_TRUE(Contains(artifact.ToJson(), "\"isMalicious\":true"));

    Engine::ExtractedIOC ioc;
    ioc.iocType = "domain";
    ioc.value = "malicious.example";
    ioc.confidence = 0.9f;
    EXPECT_TRUE(Contains(ioc.ToJson(), "\"iocType\":\"domain\""));

    Engine::SandboxVerdict verdict;
    verdict.isMalicious = true;
    verdict.threatScore = 91;
    verdict.durationSeconds = 33;
    verdict.processEvents = {processEvent};
    verdict.fileEvents = {fileEvent};
    verdict.registryEvents = {registryEvent};
    verdict.networkEvents = {networkEvent};
    verdict.artifacts = {artifact};
    verdict.iocs = {ioc};
    const std::string verdictJson = verdict.ToJson();
    EXPECT_TRUE(Contains(verdictJson, "\"threatScore\":91"));
    EXPECT_TRUE(Contains(verdictJson, "\"artifacts\":1"));
    EXPECT_TRUE(Contains(verdictJson, "\"iocs\":1"));
}

TEST_F(SandboxAnalyzerTest, OptionAndConfigurationValidationProtectRuntimeBounds) {
    Engine::SandboxAnalysisOptions options;
    EXPECT_TRUE(options.IsValid());

    options.timeoutSeconds = 0;
    EXPECT_FALSE(options.IsValid());

    options.timeoutSeconds = Engine::SandboxConstants::MAX_TIMEOUT_SECONDS + 1;
    EXPECT_FALSE(options.IsValid());

    Engine::SandboxAnalyzerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.maxConcurrentAnalyses = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.vms.clear();
    EXPECT_TRUE(config.IsValid());

    config = {};
    config.defaultTimeoutSeconds = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.defaultTimeoutSeconds = Engine::SandboxConstants::MAX_TIMEOUT_SECONDS + 1;
    EXPECT_FALSE(config.IsValid());
}

TEST_F(SandboxAnalyzerTest, StatisticsResetClearsRuntimeCounters) {
    Engine::SandboxAnalyzer::Statistics stats;
    stats.totalAnalyses.store(3, std::memory_order_relaxed);
    stats.vmsStarted.store(1, std::memory_order_relaxed);
    stats.timeouts.store(4, std::memory_order_relaxed);
    stats.failures.store(2, std::memory_order_relaxed);
    stats.artifactsExtracted.store(5, std::memory_order_relaxed);
    const auto startTime = stats.startTime;

    stats.Reset();
    EXPECT_EQ(stats.totalAnalyses.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.vmsStarted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.timeouts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.failures.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.artifactsExtracted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.startTime, startTime);
}

TEST_F(SandboxAnalyzerTest, GuardPathsStayNonOperationalBeforeInitialization) {
    auto& analyzer = Engine::SandboxAnalyzer::Instance();
    EXPECT_FALSE(analyzer.IsInitialized());
    EXPECT_EQ(analyzer.GetStatus(), Engine::SandboxStatus::Stopped);

    Engine::SandboxError error;
    const Engine::SandboxVerdict verdict =
        analyzer.Analyze(L"C:\\does-not-exist.bin", Engine::SandboxAnalysisOptions{}, &error);
    EXPECT_FALSE(verdict.isMalicious);
    EXPECT_EQ(error.code, ERROR_NOT_READY);
    EXPECT_TRUE(error.HasError());

    error.Clear();
    const std::string taskId =
        analyzer.SubmitForAnalysis(L"C:\\does-not-exist.bin", Engine::SandboxAnalysisOptions{}, &error);
    EXPECT_TRUE(taskId.empty());
    EXPECT_EQ(error.code, ERROR_NOT_READY);

    EXPECT_FALSE(analyzer.GetAnalysisResult("missing").has_value());
    EXPECT_FALSE(analyzer.CancelAnalysis("missing"));
    EXPECT_TRUE(analyzer.GetPendingAnalyses().empty());
    EXPECT_TRUE(analyzer.GetAvailableVMs().empty());
    EXPECT_EQ(analyzer.GetVMStatus("shadow-win11"), "unavailable");
    EXPECT_FALSE(analyzer.RevertToSnapshot("shadow-win11", "golden"));
    EXPECT_FALSE(analyzer.StartVM("shadow-win11"));
    EXPECT_FALSE(analyzer.StopVM("shadow-win11"));
    EXPECT_TRUE(analyzer.GetArtifacts("missing").empty());
    EXPECT_FALSE(analyzer.DownloadArtifact("missing", "artifact", L"C:\\artifact.bin"));
    EXPECT_FALSE(analyzer.GetMemoryDump("missing").has_value());
    EXPECT_FALSE(analyzer.GetNetworkCapture("missing").has_value());
    analyzer.RegisterProgressCallback([](const std::string&, uint32_t, const std::string&) {});
    analyzer.RegisterCompleteCallback([](const std::string&, const Engine::SandboxVerdict&) {});
    analyzer.RegisterErrorCallback([](const std::string&, int) {});
    analyzer.UnregisterCallbacks();
    EXPECT_TRUE(Contains(Engine::SandboxAnalyzer::GetVersionString(), "3.0."));
    EXPECT_FALSE(analyzer.SelfTest());
}

}  // namespace ShadowStrike::Core::Engine::Test
