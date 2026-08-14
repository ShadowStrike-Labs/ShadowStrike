#include "../../../src/pch.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <nlohmann/json.hpp>
#include "../../../src/PhantomCore/SelfProtection/AntiDebug.hpp"

namespace {

using nlohmann::json;
using namespace ShadowStrike::Security;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

TEST(AntiDebugTests, ProtectionPresetsAndValidationStayConsistent) {
    const AntiDebugConfiguration disabled =
        AntiDebugConfiguration::FromProtectionLevel(AntiDebugProtectionLevel::Disabled);
    EXPECT_EQ(disabled.enabledTechniques, DetectionTechnique::None);
    EXPECT_EQ(disabled.responseActions, ResponseAction::None);
    EXPECT_EQ(disabled.monitoringMode, MonitoringMode::Disabled);
    EXPECT_FALSE(disabled.enableCodeIntegrity);
    EXPECT_FALSE(disabled.enableHookDetection);
    EXPECT_FALSE(disabled.enableTimingDetection);
    EXPECT_FALSE(disabled.enableExceptionDetection);
    EXPECT_FALSE(disabled.enableProcessDetection);
    EXPECT_FALSE(disabled.enableHardwareDetection);
    EXPECT_FALSE(disabled.autoHideThreads);
    EXPECT_FALSE(disabled.autoClearDebugRegisters);
    EXPECT_FALSE(disabled.sendTelemetry);

    const AntiDebugConfiguration paranoid =
        AntiDebugConfiguration::FromProtectionLevel(AntiDebugProtectionLevel::Paranoid);
    EXPECT_EQ(paranoid.monitoringMode, MonitoringMode::Continuous);
    EXPECT_TRUE(paranoid.enableTimingDetection);
    EXPECT_TRUE(paranoid.enableExceptionDetection);
    EXPECT_TRUE(paranoid.autoHideThreads);
    EXPECT_TRUE(paranoid.autoClearDebugRegisters);
    EXPECT_TRUE(paranoid.IsValid());

    AntiDebugConfiguration invalid = paranoid;
    invalid.monitoringIntervalMs = 0;
    EXPECT_FALSE(invalid.IsValid());

    invalid = paranoid;
    invalid.detectionThreshold = 101;
    EXPECT_FALSE(invalid.IsValid());
}

TEST(AntiDebugTests, MergeCombinesFlagsResponsesAndWhitelistEntries) {
    AntiDebugConfiguration base =
        AntiDebugConfiguration::FromProtectionLevel(AntiDebugProtectionLevel::Minimal);

    AntiDebugConfiguration overlay{};
    overlay.protectionLevel = AntiDebugProtectionLevel::Enhanced;
    overlay.enabledTechniques = DetectionTechnique::Hardware_DebugRegisters;
    overlay.responseActions = ResponseAction::Alert;
    overlay.whitelistedProcesses = {L"windbg.exe", L"devenv.exe"};

    base.Merge(overlay);

    EXPECT_EQ(base.protectionLevel, AntiDebugProtectionLevel::Enhanced);
    EXPECT_EQ(GetResponseActionName(base.responseActions), "Multiple");

    const uint64_t techniqueMask = static_cast<uint64_t>(base.enabledTechniques);
    EXPECT_NE(techniqueMask & static_cast<uint64_t>(DetectionTechnique::API_IsDebuggerPresent), 0ULL);
    EXPECT_NE(techniqueMask & static_cast<uint64_t>(DetectionTechnique::Hardware_DebugRegisters), 0ULL);

    ASSERT_EQ(base.whitelistedProcesses.size(), 2U);
    EXPECT_EQ(base.whitelistedProcesses[0], L"windbg.exe");
    EXPECT_EQ(base.whitelistedProcesses[1], L"devenv.exe");
}

TEST(AntiDebugTests, DetectionResultJsonAndDebugRegistersCaptureCoreSignals) {
    DetectionResult result{};
    result.debuggerDetected = true;
    result.overallConfidence = DetectionConfidence::High;
    result.totalScore = 87;
    result.primaryDebuggerType = DebuggerType::KernelMode;
    result.checksPerformed = 8;
    result.checksTriggered = 3;
    result.scanDuration = Milliseconds{12};
    result.possibleFalsePositive = true;

    const std::string summary = result.GetSummary();
    EXPECT_THAT(summary, ::testing::HasSubstr("DEBUGGER DETECTED"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Score: 87"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Checks: 3/8"));
    EXPECT_THAT(summary, ::testing::HasSubstr("Confidence: 3"));

    const json payload = ParseJson(result.ToJson());
    EXPECT_TRUE(payload.at("debuggerDetected").get<bool>());
    EXPECT_EQ(payload.at("totalScore").get<int>(), 87);
    EXPECT_EQ(payload.at("overallConfidence").get<int>(),
              static_cast<int>(DetectionConfidence::High));
    EXPECT_EQ(payload.at("primaryDebuggerType").get<int>(),
              static_cast<int>(DebuggerType::KernelMode));
    EXPECT_EQ(payload.at("scanDurationMs").get<int>(), 12);
    EXPECT_TRUE(payload.at("possibleFalsePositive").get<bool>());

    DebugRegisterState registers{};
    registers.dr0 = 0x1000;
    registers.dr2 = 0x2000;
    registers.dr7 = 0xFF;

    EXPECT_TRUE(registers.HasBreakpoints());
    EXPECT_EQ(registers.GetActiveBreakpointCount(), 4U);

    registers.Clear();
    registers.dr7 = 0x1;
    EXPECT_TRUE(registers.HasBreakpoints());
    EXPECT_EQ(registers.GetActiveBreakpointCount(), 1U);

    registers.Clear();
    EXPECT_FALSE(registers.HasBreakpoints());
    EXPECT_EQ(registers.GetActiveBreakpointCount(), 0U);
}

TEST(AntiDebugTests, StatisticsResetAndHelperNamesRemainStable) {
    AntiDebugStatistics stats{};
    const auto lastDetection = Clock::now();
    const auto lastCheck = lastDetection - std::chrono::seconds{1};
    stats.totalChecks = 41;
    stats.totalDetections = 9;
    stats.detectionsByTechnique[DetectionTechnique::Timing_RDTSC] = 2;
    stats.detectionsByType[DebuggerType::KernelMode] = 1;
    stats.falsePositives = 2;
    stats.actionsExecuted = 4;
    stats.threadsHidden = 3;
    stats.breakpointsCleared = 2;
    stats.hooksDetected = 5;
    stats.integrityViolations = 1;
    stats.avgCheckDurationUs = 900;
    stats.maxCheckDurationUs = 1300;
    stats.lastDetectionTime = lastDetection;
    stats.lastCheckTime = lastCheck;

    stats.Reset();

    EXPECT_EQ(stats.totalChecks, 0ULL);
    EXPECT_EQ(stats.totalDetections, 0ULL);
    EXPECT_EQ(stats.falsePositives, 0ULL);
    EXPECT_EQ(stats.actionsExecuted, 0ULL);
    EXPECT_EQ(stats.threadsHidden, 0ULL);
    EXPECT_EQ(stats.maxCheckDurationUs, 0ULL);
    EXPECT_TRUE(stats.detectionsByTechnique.empty());
    EXPECT_TRUE(stats.detectionsByType.empty());
    EXPECT_EQ(stats.lastDetectionTime, Clock::time_point{});
    EXPECT_EQ(stats.lastCheckTime, Clock::time_point{});

    const json payload = ParseJson(stats.ToJson());
    EXPECT_EQ(payload.at("threadsHidden").get<int>(), 0);
    EXPECT_EQ(payload.at("hooksDetected").get<int>(), 0);
    EXPECT_GE(payload.at("uptimeSeconds").get<int64_t>(), 0);

    EXPECT_EQ(GetTechniqueName(DetectionTechnique::Timing_RDTSC), "RDTSC Timing");
    EXPECT_EQ(GetDebuggerTypeName(DebuggerType::Sandbox), "Sandbox");
    EXPECT_EQ(GetConfidenceName(DetectionConfidence::Critical), "Critical");
    EXPECT_EQ(GetHookTypeName(HookType::InlineJump), "Inline Jump");
}

}  // namespace
