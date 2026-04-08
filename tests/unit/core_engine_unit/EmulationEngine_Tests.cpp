/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for EmulationEngine deterministic helpers.
 *
 * Scope:
 *   - result/session/stats snapshot helpers and configuration factories
 *   - callback registration and default-config storage
 *   - safe behavior for async/session APIs when the engine is not initialized
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <optional>
#include <string_view>
#include <vector>

#include "../../../src/Shared_modules/Core/Engine/EmulationEngine.hpp"

namespace Engine = ShadowStrike::Core::Engine;

namespace ShadowStrike::Core::Engine::Test {
namespace {

bool Contains(std::wstring_view haystack, std::wstring_view needle) {
    return haystack.find(needle) != std::wstring_view::npos;
}

}  // namespace

class EmulationEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        Engine::EmulationEngine::Instance().Shutdown();
    }

    void TearDown() override {
        Engine::EmulationEngine::Instance().Shutdown();
    }
};

TEST_F(EmulationEngineTest, ResultHelpersSummarizeAndSelectHighestSeverityApi) {
    Engine::APICallRecord benign;
    benign.dllName = "kernel32.dll";
    benign.functionName = "CreateFileW";
    benign.severity = Engine::APISeverity::Low;

    Engine::APICallRecord critical;
    critical.dllName = "kernel32.dll";
    critical.functionName = "WriteProcessMemory";
    critical.severity = Engine::APISeverity::Critical;

    Engine::EmulationResult result;
    result.sessionId = 42;
    result.state = Engine::EmulationState::Completed;
    result.backend = Engine::EmulationBackend::PhantomEmulator;
    result.instructionsExecuted = 1337;
    result.apiCallCount = 2;
    result.isMalicious = true;
    result.threatName = "Injector";
    result.apiCalls = {benign, critical};

    const std::wstring summary = result.GetSummary();
    EXPECT_TRUE(Contains(summary, L"Session 42"));
    EXPECT_TRUE(Contains(summary, L"Verdict=Malicious"));
    EXPECT_TRUE(Contains(summary, L"Injector"));

    const std::optional<Engine::APICallRecord> highest = result.GetHighestSeverityAPI();
    ASSERT_TRUE(highest.has_value());
    EXPECT_EQ(highest->functionName, "WriteProcessMemory");
    EXPECT_EQ(highest->severity, Engine::APISeverity::Critical);

    result.Clear();
    EXPECT_EQ(result.sessionId, 0u);
    EXPECT_FALSE(result.isMalicious);
    EXPECT_TRUE(result.apiCalls.empty());
}

TEST_F(EmulationEngineTest, ConfigurationFactoriesExpressIntendedExecutionProfiles) {
    const Engine::EmulationConfig defaultConfig = Engine::EmulationConfig::CreateDefault();
    EXPECT_EQ(defaultConfig.mode, Engine::EmulationMode::Full);
    EXPECT_TRUE(defaultConfig.enableUnpacking);
    EXPECT_TRUE(defaultConfig.enableMemoryScanning);

    const Engine::EmulationConfig fastConfig = Engine::EmulationConfig::CreateFast();
    EXPECT_EQ(fastConfig.timeoutMs, 5000u);
    EXPECT_FALSE(fastConfig.enableMemoryScanning);
    EXPECT_FALSE(fastConfig.traceAPIArguments);
    EXPECT_FALSE(fastConfig.captureDroppedFiles);

    const Engine::EmulationConfig unpackOnlyConfig = Engine::EmulationConfig::CreateUnpackOnly();
    EXPECT_EQ(unpackOnlyConfig.mode, Engine::EmulationMode::UnpackOnly);
    EXPECT_TRUE(unpackOnlyConfig.enableUnpacking);
    EXPECT_FALSE(unpackOnlyConfig.enableAPITracing);
    EXPECT_FALSE(unpackOnlyConfig.enableNetworkMonitoring);

    const Engine::EmulationConfig debugConfig = Engine::EmulationConfig::CreateDebug();
    EXPECT_EQ(debugConfig.mode, Engine::EmulationMode::Debug);
    EXPECT_TRUE(debugConfig.debugLogging);
    EXPECT_TRUE(debugConfig.instructionTracing);
    EXPECT_TRUE(debugConfig.memoryAccessTracing);

    const Engine::EmulationConfig shellcodeConfig = Engine::EmulationConfig::CreateShellcode();
    EXPECT_EQ(shellcodeConfig.mode, Engine::EmulationMode::Shellcode);
    EXPECT_EQ(shellcodeConfig.maxInstructions, 1'000'000u);
    EXPECT_FALSE(shellcodeConfig.enableUnpacking);
}

TEST_F(EmulationEngineTest, SessionAndStatsSnapshotsCopyAtomicStateCorrectly) {
    Engine::EmulationSession originalSession;
    originalSession.sessionId = 99;
    originalSession.state.store(Engine::EmulationState::Running, std::memory_order_relaxed);
    originalSession.instructionCount.store(1234, std::memory_order_relaxed);
    originalSession.apiCallCount.store(7, std::memory_order_relaxed);
    originalSession.activeBackend = Engine::EmulationBackend::PhantomEmulator;

    const Engine::EmulationSession copiedSession(originalSession);
    EXPECT_EQ(copiedSession.sessionId, 99u);
    EXPECT_EQ(copiedSession.state.load(std::memory_order_relaxed), Engine::EmulationState::Running);
    EXPECT_EQ(copiedSession.instructionCount.load(std::memory_order_relaxed), 1234u);
    EXPECT_EQ(copiedSession.apiCallCount.load(std::memory_order_relaxed), 7u);

    Engine::EmulationStats stats;
    stats.totalSessions.store(5, std::memory_order_relaxed);
    stats.totalInstructions.store(5000, std::memory_order_relaxed);
    stats.avgEmulationTimeUs.store(200, std::memory_order_relaxed);
    stats.phantomEmulatorAvailable = false;

    Engine::EmulationStats copiedStats(stats);
    EXPECT_EQ(copiedStats.totalSessions.load(std::memory_order_relaxed), 5u);
    EXPECT_EQ(copiedStats.totalInstructions.load(std::memory_order_relaxed), 5000u);
    EXPECT_FALSE(copiedStats.phantomEmulatorAvailable);

    copiedStats.Reset();
    EXPECT_EQ(copiedStats.totalSessions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(copiedStats.totalInstructions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(copiedStats.avgEmulationTimeUs.load(std::memory_order_relaxed), 0u);
}

TEST_F(EmulationEngineTest, NonOperationalSessionAndCallbackSurfacesRemainSafe) {
    auto& engine = Engine::EmulationEngine::Instance();
    EXPECT_FALSE(engine.IsInitialized());
    EXPECT_FALSE(engine.IsHardwareAccelerationAvailable());
    EXPECT_EQ(engine.GetAvailableBackends(), std::vector<Engine::EmulationBackend>{Engine::EmulationBackend::PhantomEmulator});

    const Engine::EmulationConfig debugConfig = Engine::EmulationConfig::CreateDebug();
    engine.SetDefaultConfig(debugConfig);
    const Engine::EmulationConfig storedConfig = engine.GetDefaultConfig();
    EXPECT_EQ(storedConfig.mode, Engine::EmulationMode::Debug);
    EXPECT_TRUE(storedConfig.debugLogging);

    EXPECT_EQ(engine.EmulatePEAsync({0x4D, 0x5A, 0x90, 0x00}, Engine::EmulationConfig::CreateDefault(), nullptr), 0u);
    EXPECT_FALSE(engine.GetSession(1).has_value());
    EXPECT_FALSE(engine.TerminateSession(1));
    EXPECT_FALSE(engine.PauseSession(1));
    EXPECT_FALSE(engine.ResumeSession(1));

    const uint64_t apiCallbackId = engine.RegisterAPICallback([](const Engine::APICallRecord&) {});
    const uint64_t fileCallbackId = engine.RegisterFileDropCallback([](const Engine::DroppedFile&) {});
    const uint64_t netCallbackId = engine.RegisterNetworkCallback([](const Engine::NetworkActivity&) {});
    const uint64_t unpackCallbackId = engine.RegisterUnpackCallback([](const Engine::UnpackLayer&) {});
    EXPECT_NE(apiCallbackId, 0u);
    EXPECT_NE(fileCallbackId, 0u);
    EXPECT_NE(netCallbackId, 0u);
    EXPECT_NE(unpackCallbackId, 0u);
    EXPECT_TRUE(engine.UnregisterAPICallback(apiCallbackId));
    EXPECT_TRUE(engine.UnregisterFileDropCallback(fileCallbackId));
    EXPECT_TRUE(engine.UnregisterNetworkCallback(netCallbackId));
    EXPECT_TRUE(engine.UnregisterUnpackCallback(unpackCallbackId));
}

}  // namespace ShadowStrike::Core::Engine::Test
