/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for BehaviorAnalyzer deterministic helper/state behavior.
 *
 * Scope:
 *   - event/state age and severity helpers
 *   - state reset behavior implemented in BehaviorAnalyzer.cpp
 *   - configuration factory profiles and statistics reset helpers
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <chrono>

#include "../../../src/Shared_modules/Core/Engine/BehaviorAnalyzer.hpp"

namespace Engine = ShadowStrike::Core::Engine;
using namespace std::chrono_literals;

namespace ShadowStrike::Core::Engine::Test {

TEST(BehaviorAnalyzerTest, EventAndStateHelpersReflectRiskAndAging) {
    Engine::BehaviorEvent event;
    event.timestamp = std::chrono::steady_clock::now() - 25ms;
    EXPECT_GE(event.GetAge().count(), 20);

    Engine::ProcessBehaviorState state;
    state.stateCreatedAt = std::chrono::steady_clock::now() - 50ms;
    state.maliceScore = Engine::BehaviorConstants::BLOCK_THRESHOLD + 1.0;
    state.filesEncrypted = Engine::BehaviorConstants::RANSOMWARE_FILE_THRESHOLD;
    state.remoteThreadCount = 1;

    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::High);
    EXPECT_TRUE(state.HasRansomwareBehavior());
    EXPECT_TRUE(state.HasInjectionBehavior());
    EXPECT_GE(state.GetAge().count(), 40);
}

TEST(BehaviorAnalyzerTest, ClearResetsAccumulatedProcessState) {
    Engine::ProcessBehaviorState state;
    state.processId = 501;
    state.processName = L"encryptor.exe";
    state.maliceScore = 92.0;
    state.filesEncrypted = 128;
    state.shadowCopyOperations = 1;
    state.remoteThreadCount = 2;
    state.targetedProcessIds.insert(900);
    state.contactedDomains.insert("evil.example");
    state.currentVerdict = Engine::BehaviorVerdictType::Malicious;
    state.recommendedAction = Engine::RecommendedAction::Terminate;
    state.hasBeenReported = true;
    state.hasBeenTerminated = true;
    state.exfilThresholdTriggered = true;

    state.Clear();

    EXPECT_EQ(state.processId, 0u);
    EXPECT_TRUE(state.processName.empty());
    EXPECT_DOUBLE_EQ(state.maliceScore, 0.0);
    EXPECT_EQ(state.filesEncrypted, 0u);
    EXPECT_EQ(state.shadowCopyOperations, 0u);
    EXPECT_EQ(state.remoteThreadCount, 0u);
    EXPECT_TRUE(state.targetedProcessIds.empty());
    EXPECT_TRUE(state.contactedDomains.empty());
    EXPECT_EQ(state.currentVerdict, Engine::BehaviorVerdictType::Clean);
    EXPECT_EQ(state.recommendedAction, Engine::RecommendedAction::None);
    EXPECT_FALSE(state.hasBeenReported);
    EXPECT_FALSE(state.hasBeenTerminated);
    EXPECT_FALSE(state.exfilThresholdTriggered);
}

TEST(BehaviorAnalyzerTest, VerdictAndAttackChainHelpersEncodeImmediateResponseSemantics) {
    Engine::BehaviorVerdict verdict;
    verdict.action = Engine::RecommendedAction::Terminate;
    EXPECT_TRUE(verdict.RequiresImmediateAction());

    verdict.action = Engine::RecommendedAction::Alert;
    EXPECT_FALSE(verdict.RequiresImmediateAction());

    Engine::BehaviorAttackChain chain;
    Engine::BehaviorEvent firstEvent;
    firstEvent.systemTime = std::chrono::system_clock::now();
    Engine::BehaviorEvent secondEvent = firstEvent;
    secondEvent.systemTime += 9s;
    chain.events = {firstEvent, secondEvent};
    EXPECT_EQ(chain.GetDuration(), 9s);
}

TEST(BehaviorAnalyzerTest, ThresholdsAndHelperFactoriesMatchCurrentDetectionSemantics) {
    Engine::ProcessBehaviorState state;
    state.maliceScore = Engine::BehaviorConstants::WARNING_THRESHOLD - 0.01;
    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::Info);

    state.maliceScore = Engine::BehaviorConstants::WARNING_THRESHOLD;
    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::Low);

    state.maliceScore = Engine::BehaviorConstants::ALERT_THRESHOLD;
    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::Medium);

    state.maliceScore = Engine::BehaviorConstants::BLOCK_THRESHOLD;
    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::High);

    state.maliceScore = Engine::BehaviorConstants::CRITICAL_THRESHOLD;
    EXPECT_EQ(state.GetSeverity(), Engine::BehaviorSeverity::Critical);

    state = {};
    state.shadowCopyOperations = 1;
    EXPECT_TRUE(state.HasRansomwareBehavior());
    state = {};
    state.canaryFilesTouched = 1;
    EXPECT_TRUE(state.HasRansomwareBehavior());
    state = {};
    state.ransomNoteIndicators = 1;
    EXPECT_TRUE(state.HasRansomwareBehavior());

    state = {};
    state.crossProcessWrites = 1;
    EXPECT_TRUE(state.HasInjectionBehavior());
    state = {};
    state.targetedProcessIds.insert(404);
    EXPECT_TRUE(state.HasInjectionBehavior());

    Engine::BehaviorVerdict verdict;
    verdict.action = Engine::RecommendedAction::Suspend;
    EXPECT_FALSE(verdict.RequiresImmediateAction());
    verdict.action = Engine::RecommendedAction::BlockAndQuarantine;
    EXPECT_TRUE(verdict.RequiresImmediateAction());

    Engine::BehaviorAttackChain emptyChain;
    EXPECT_EQ(emptyChain.GetDuration(), 0s);

    const Engine::BehaviorEvent fileEvent =
        Engine::CreateFileEvent(Engine::BehaviorEventType::FileWrite, 77, L"C:\\Temp\\note.txt", false);
    EXPECT_EQ(fileEvent.category, Engine::BehaviorEventCategory::FileSystem);
    EXPECT_EQ(fileEvent.processId, 77u);
    EXPECT_EQ(fileEvent.targetPath, L"C:\\Temp\\note.txt");
    EXPECT_EQ(fileEvent.fileExtension, L".txt");
    EXPECT_FALSE(fileEvent.success);

    const Engine::BehaviorEvent extensionlessFileEvent =
        Engine::CreateFileEvent(Engine::BehaviorEventType::FileRead, 78, L"C:\\Temp\\README", true);
    EXPECT_TRUE(extensionlessFileEvent.fileExtension.empty());

    const Engine::BehaviorEvent registryEvent = Engine::CreateRegistryEvent(
        Engine::BehaviorEventType::RegistrySetValue,
        91,
        L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"ShadowStrike",
        true);
    EXPECT_EQ(registryEvent.category, Engine::BehaviorEventCategory::Registry);
    EXPECT_EQ(registryEvent.valueName, L"ShadowStrike");
    EXPECT_TRUE(registryEvent.success);

    const Engine::BehaviorEvent networkEvent =
        Engine::CreateNetworkEvent(Engine::BehaviorEventType::NetworkConnect, 13, "198.51.100.7", 443, "TLS");
    EXPECT_EQ(networkEvent.category, Engine::BehaviorEventCategory::Network);
    EXPECT_EQ(networkEvent.remoteHostname, "198.51.100.7");
    EXPECT_EQ(networkEvent.remoteIP, "198.51.100.7");
    EXPECT_EQ(networkEvent.remotePort, 443);
    EXPECT_EQ(networkEvent.protocol, "TLS");

    const Engine::BehaviorEvent processEvent =
        Engine::CreateProcessEvent(Engine::BehaviorEventType::ProcessInject, 100, 200);
    EXPECT_EQ(processEvent.category, Engine::BehaviorEventCategory::Process);
    EXPECT_EQ(processEvent.processId, 100u);
    EXPECT_EQ(processEvent.targetProcessId, 200u);

    EXPECT_TRUE(Engine::IsRansomNotePattern(L"C:\\Users\\Public\\README_FOR_DECRYPT.txt"));
    EXPECT_TRUE(Engine::IsRansomNotePattern(L"C:\\Users\\Public\\IMPORTANT_READ_ME.HTA"));
    EXPECT_FALSE(Engine::IsRansomNotePattern(L"C:\\Users\\Public\\notes.txt"));
    EXPECT_TRUE(Engine::IsPersistenceRegistryPath(
        L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ShadowStrike"));
    EXPECT_TRUE(Engine::IsPersistenceRegistryPath(
        L"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\ShadowStrike"));
    EXPECT_FALSE(Engine::IsPersistenceRegistryPath(L"HKCU\\Software\\ShadowStrike"));
    EXPECT_TRUE(Engine::IsLSASSProcess(L"LSASS.EXE"));
    EXPECT_TRUE(Engine::IsLSASSProcess(L"LSAISO.EXE"));
    EXPECT_FALSE(Engine::IsLSASSProcess(L"lsass.exe.bak"));
    EXPECT_TRUE(Engine::IsDocumentApplication(L"WINWORD.EXE"));
    EXPECT_TRUE(Engine::IsDocumentApplication(L"AcroRd32.exe"));
    EXPECT_FALSE(Engine::IsDocumentApplication(L""));
    EXPECT_FALSE(Engine::IsDocumentApplication(L"powershell.exe"));
    EXPECT_TRUE(Engine::IsScriptInterpreter(L"PowerShell.EXE"));
    EXPECT_TRUE(Engine::IsScriptInterpreter(L"pwsh.exe"));
    EXPECT_FALSE(Engine::IsScriptInterpreter(L""));
    EXPECT_FALSE(Engine::IsScriptInterpreter(L"explorer.exe"));
}

TEST(BehaviorAnalyzerTest, ConfigurationFactoriesShiftSensitivityAndStatsResetCleanly) {
    const Engine::BehaviorAnalyzerConfig defaultConfig = Engine::BehaviorAnalyzerConfig::CreateDefault();
    const Engine::BehaviorAnalyzerConfig highSensitivity =
        Engine::BehaviorAnalyzerConfig::CreateHighSensitivity();
    const Engine::BehaviorAnalyzerConfig lowSensitivity =
        Engine::BehaviorAnalyzerConfig::CreateLowSensitivity();

    EXPECT_LT(highSensitivity.warningThreshold, defaultConfig.warningThreshold);
    EXPECT_LT(highSensitivity.blockThreshold, lowSensitivity.blockThreshold);
    EXPECT_GT(lowSensitivity.ransomwareFileThreshold, highSensitivity.ransomwareFileThreshold);

    Engine::BehaviorAnalyzerStats stats;
    stats.totalEventsProcessed.store(11, std::memory_order_relaxed);
    stats.ransomwareDetections.store(2, std::memory_order_relaxed);
    stats.eventsDropped.store(1, std::memory_order_relaxed);
    stats.Reset();
    EXPECT_EQ(stats.totalEventsProcessed.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.ransomwareDetections.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.eventsDropped.load(std::memory_order_relaxed), 0u);
}

}  // namespace ShadowStrike::Core::Engine::Test
