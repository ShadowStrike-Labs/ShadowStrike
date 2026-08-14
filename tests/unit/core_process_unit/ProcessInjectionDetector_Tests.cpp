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
 * @file ProcessInjectionDetector_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::Process::ProcessInjectionDetector helper logic.
 *
 * Coverage focus:
 * - preset configurations and statistics lifecycle
 * - event-pattern classification for major injection families
 * - confidence calculation, correlation boosts, whitelist reductions, and clamping
 */

#include "../../../src/pch.h"
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Core/Process/ProcessInjectionDetector.hpp"

namespace {

using namespace ShadowStrike::Core::Process;

HandleAccessEvent MakeHandleEvent() {
    HandleAccessEvent event;
    event.sourceProcessId = 1111;
    event.targetProcessId = 2222;
    return event;
}

MemoryOperationEvent MakeMemoryEvent(MemoryOperationEvent::OpType op) {
    MemoryOperationEvent event;
    event.sourceProcessId = 1111;
    event.targetProcessId = 2222;
    event.operation = op;
    return event;
}

ThreadOperationEvent MakeThreadEvent(
    ThreadOperationEvent::OpType op,
    bool remote = false,
    bool suspended = false,
    const std::wstring& module = L"")
{
    ThreadOperationEvent event;
    event.sourceProcessId = 1111;
    event.targetProcessId = 2222;
    event.operation = op;
    event.isRemote = remote;
    event.isSuspended = suspended;
    event.startAddressModule = module;
    return event;
}

class ProcessInjectionValueTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& detector = ProcessInjectionDetector::Instance();
        detector.Shutdown();
        detector.ResetStats();
    }

    void TearDown() override {
        auto& detector = ProcessInjectionDetector::Instance();
        detector.Shutdown();
        detector.ResetStats();
    }
};

TEST(ProcessInjectionValueTests, ConfigPresetsReflectStrictAndMonitorOnlyBehavior) {
    const auto defaults = InjectionDetectorConfig::CreateDefault();
    const auto strict = InjectionDetectorConfig::CreateStrict();
    const auto monitorOnly = InjectionDetectorConfig::CreateMonitorOnly();

    EXPECT_TRUE(defaults.enabled);
    EXPECT_TRUE(defaults.blockInjections);
    EXPECT_TRUE(defaults.detectChains);
    EXPECT_TRUE(defaults.trustMicrosoftSigned);

    EXPECT_TRUE(strict.blockInjections);
    EXPECT_LT(strict.alertConfidence, defaults.alertConfidence);
    EXPECT_LT(strict.blockConfidence, defaults.blockConfidence);
    EXPECT_FALSE(strict.trustMicrosoftSigned);

    EXPECT_FALSE(monitorOnly.blockInjections);
    EXPECT_DOUBLE_EQ(monitorOnly.blockConfidence, 100.0);
}

TEST(ProcessInjectionValueTests, StatisticsSnapshotAndResetClearObservedDetectionWork) {
    InjectionDetectorStats stats;
    stats.totalEvents.store(9, std::memory_order_relaxed);
    stats.handleEvents.store(2, std::memory_order_relaxed);
    stats.memoryEvents.store(3, std::memory_order_relaxed);
    stats.threadEvents.store(4, std::memory_order_relaxed);
    stats.injectionsDetected.store(5, std::memory_order_relaxed);
    stats.injectionsBlocked.store(1, std::memory_order_relaxed);
    stats.trackedProcesses.store(7, std::memory_order_relaxed);

    const InjectionDetectorStats snapshot = stats;
    EXPECT_EQ(snapshot.totalEvents.load(std::memory_order_relaxed), 9u);
    EXPECT_EQ(snapshot.memoryEvents.load(std::memory_order_relaxed), 3u);
    EXPECT_EQ(snapshot.threadEvents.load(std::memory_order_relaxed), 4u);
    EXPECT_EQ(snapshot.injectionsDetected.load(std::memory_order_relaxed), 5u);
    EXPECT_EQ(snapshot.trackedProcesses.load(std::memory_order_relaxed), 7u);

    stats.Reset();
    EXPECT_EQ(stats.totalEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.handleEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.memoryEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.threadEvents.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.injectionsDetected.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.injectionsBlocked.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.trackedProcesses.load(std::memory_order_relaxed), 0u);
}

TEST_F(ProcessInjectionValueTest, ClassificationRecognizesProcessHollowingReflectiveAndClassicDllInjection) {
    auto& detector = ProcessInjectionDetector::Instance();

    const auto hollowingType = detector.ClassifyInjection(
        {},
        {
            MakeMemoryEvent(MemoryOperationEvent::OpType::Unmap),
            MakeMemoryEvent(MemoryOperationEvent::OpType::Allocate),
            MakeMemoryEvent(MemoryOperationEvent::OpType::Write)
        },
        { MakeThreadEvent(ThreadOperationEvent::OpType::SetContext, false, true) });
    EXPECT_EQ(hollowingType, InjectionType::ProcessHollowing);

    const auto reflectiveType = detector.ClassifyInjection(
        {},
        { MakeMemoryEvent(MemoryOperationEvent::OpType::Write) },
        { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true, false, L"") });
    EXPECT_EQ(reflectiveType, InjectionType::ReflectiveDLL);

    const auto dllType = detector.ClassifyInjection(
        {},
        { MakeMemoryEvent(MemoryOperationEvent::OpType::Write) },
        { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true, false, L"kernel32.dll") });
    EXPECT_EQ(dllType, InjectionType::DLLInjection);
}

TEST_F(ProcessInjectionValueTest, ClassificationRecognizesApcEarlyBirdAndThreadHijackingPatterns) {
    auto& detector = ProcessInjectionDetector::Instance();

    const auto apcType = detector.ClassifyInjection(
        {},
        {},
        { MakeThreadEvent(ThreadOperationEvent::OpType::QueueAPC, true, false) });
    EXPECT_EQ(apcType, InjectionType::APC);

    const auto earlyBirdType = detector.ClassifyInjection(
        {},
        {},
        { MakeThreadEvent(ThreadOperationEvent::OpType::QueueAPC, true, true) });
    EXPECT_EQ(earlyBirdType, InjectionType::EarlyBird);

    const auto hijackType = detector.ClassifyInjection(
        {},
        {},
        {
            MakeThreadEvent(ThreadOperationEvent::OpType::Suspend, true),
            MakeThreadEvent(ThreadOperationEvent::OpType::SetContext, true),
            MakeThreadEvent(ThreadOperationEvent::OpType::Resume, true)
        });
    EXPECT_EQ(hijackType, InjectionType::ThreadHijacking);
}

TEST_F(ProcessInjectionValueTest, ClassificationFallsBackToSectionMappingRemoteThreadAndShellcodeHeuristics) {
    auto& detector = ProcessInjectionDetector::Instance();

    const auto sectionMappingType = detector.ClassifyInjection(
        {},
        {
            MakeMemoryEvent(MemoryOperationEvent::OpType::Map),
            MakeMemoryEvent(MemoryOperationEvent::OpType::Write)
        },
        {});
    EXPECT_EQ(sectionMappingType, InjectionType::SectionMapping);

    const auto remoteThreadType = detector.ClassifyInjection(
        {},
        {},
        { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true, false, L"user32.dll") });
    EXPECT_EQ(remoteThreadType, InjectionType::RemoteThread);

    const auto shellcodeType = detector.ClassifyInjection(
        {},
        { MakeMemoryEvent(MemoryOperationEvent::OpType::Write) },
        {});
    EXPECT_EQ(shellcodeType, InjectionType::ShellcodeInjection);
}

TEST_F(ProcessInjectionValueTest, ClassificationTreatsUnknownRemoteStartModulesAsReflectiveDll) {
    auto& detector = ProcessInjectionDetector::Instance();

    const auto reflectiveType = detector.ClassifyInjection(
        {},
        { MakeMemoryEvent(MemoryOperationEvent::OpType::Write) },
        { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true, false, L"<unknown>") });

    EXPECT_EQ(reflectiveType, InjectionType::ReflectiveDLL);
}

TEST_F(ProcessInjectionValueTest, ClassificationRequiresRemoteThreadForClassicDllInjection) {
    auto& detector = ProcessInjectionDetector::Instance();

    const auto type = detector.ClassifyInjection(
        {},
        { MakeMemoryEvent(MemoryOperationEvent::OpType::Write) },
        { MakeThreadEvent(ThreadOperationEvent::OpType::Create, false, false, L"kernel32.dll") });

    EXPECT_EQ(type, InjectionType::ShellcodeInjection);
}

TEST_F(ProcessInjectionValueTest, ConfidenceCalculationAppliesBoostsWhitelistReductionsAndClamping) {
    auto& detector = ProcessInjectionDetector::Instance();

    InjectionEvent baseline;
    baseline.startAddressLegitimate = true;
    EXPECT_DOUBLE_EQ(
        detector.CalculateConfidence(InjectionType::RemoteThread, baseline),
        70.0);

    InjectionEvent correlated;
    correlated.startAddressLegitimate = false;
    correlated.memoryEvents = {
        MakeMemoryEvent(MemoryOperationEvent::OpType::Write),
        MakeMemoryEvent(MemoryOperationEvent::OpType::Allocate)
    };
    correlated.threadEvents = { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true) };
    EXPECT_DOUBLE_EQ(
        detector.CalculateConfidence(InjectionType::RemoteThread, correlated),
        85.0);

    InjectionEvent clamped;
    clamped.startAddressLegitimate = false;
    clamped.handleEvents = { MakeHandleEvent() };
    clamped.memoryEvents = {
        MakeMemoryEvent(MemoryOperationEvent::OpType::Unmap),
        MakeMemoryEvent(MemoryOperationEvent::OpType::Allocate),
        MakeMemoryEvent(MemoryOperationEvent::OpType::Write)
    };
    clamped.threadEvents = { MakeThreadEvent(ThreadOperationEvent::OpType::SetContext, true) };
    EXPECT_DOUBLE_EQ(
        detector.CalculateConfidence(InjectionType::ProcessHollowing, clamped),
        100.0);

    InjectionEvent whitelisted;
    whitelisted.sourceProcessName = L"csrss.exe";
    whitelisted.targetProcessName = L"notepad.exe";
    whitelisted.startAddressLegitimate = false;
    whitelisted.memoryEvents = {
        MakeMemoryEvent(MemoryOperationEvent::OpType::Write),
        MakeMemoryEvent(MemoryOperationEvent::OpType::Allocate)
    };
    whitelisted.threadEvents = { MakeThreadEvent(ThreadOperationEvent::OpType::Create, true) };
    EXPECT_DOUBLE_EQ(
        detector.CalculateConfidence(InjectionType::RemoteThread, whitelisted),
        55.0);
}

TEST_F(ProcessInjectionValueTest, ClassificationAndConfidenceRemainDeterministicForEmptyAndWhitelistedSignals) {
    auto& detector = ProcessInjectionDetector::Instance();

    EXPECT_EQ(detector.ClassifyInjection({}, {}, {}), InjectionType::Unknown);

    InjectionEvent whitelistedUnknown;
    whitelistedUnknown.sourceProcessName = L"csrss.exe";
    whitelistedUnknown.targetProcessName = L"shadowstrike-test.exe";
    whitelistedUnknown.startAddressLegitimate = true;

    // 30, not 20, and the difference is a deliberate recalibration rather than
    // drift. CalculateConfidence bases an unclassified injection on the switch's
    // default arm, which was raised from 50 to 60 because techniques falling
    // through it - IFEO redirection, AppInit_DLLs, COM hijacking, cross-process
    // SetWindowsHookEx - landed below MIN_ALERT_CONFIDENCE (60) and became silent
    // no-ops. The arithmetic here is 60 base, no correlation boost (no events), no
    // illegitimate-start-address boost (it is legitimate), minus 30 for a
    // whitelisted process pair.
    //
    // If this assertion is ever "fixed" by lowering the base back to 50, those
    // techniques stop alerting again.
    EXPECT_DOUBLE_EQ(
        detector.CalculateConfidence(InjectionType::Unknown, whitelistedUnknown),
        30.0);
}

}  // namespace
