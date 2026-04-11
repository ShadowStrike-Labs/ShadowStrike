/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PerformanceProfiler.cpp.
 *
 * Coverage focus:
 * - report and resource-usage serialization
 * - session/profile lifecycle and disabled-mode guards
 * - scoped RAII profiling behavior plus aggregate-only profiling quirks
 * - report persistence and self-test behavior
 */

#include "pch.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cmath>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

#include "../../../src/PhantomCore/Performance/dev/PerformanceProfiler.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

using nlohmann::json;

json ParseJson(const std::string& text) {
    return json::parse(text);
}

class PerformanceProfilerTest : public ::testing::Test {
protected:
    PerformanceProfiler& profiler = PerformanceProfiler::Instance();

    void SetUp() override {
        profiler.SetEnabled(true);
        profiler.EndSession();
        profiler.ClearHistory();
    }

    void TearDown() override {
        profiler.SetEnabled(true);
        profiler.EndSession();
        profiler.ClearHistory();
    }
};

TEST_F(PerformanceProfilerTest, SystemResourceUsageSerializationContainsExpectedFields) {
    const SSP::SystemResourceUsage usage{
        12.5,
        4096,
        8192,
        100,
        200,
        7
    };
    const std::string json = usage.ToJson();
    EXPECT_NE(json.find("\"cpuUsagePercent\":12.5"), std::string::npos);
    EXPECT_NE(json.find("\"workingSetBytes\":4096"), std::string::npos);
    EXPECT_NE(json.find("\"pageFaultCount\":7"), std::string::npos);
}

TEST_F(PerformanceProfilerTest, EmptyReportAndResourceUsageExposeStableDefaultShape) {
    const json report = ParseJson(profiler.GenerateReport());
    EXPECT_EQ(report["session"], "");
    EXPECT_EQ(report["total_samples"], 0);
    EXPECT_TRUE(report["statistics"].is_object());
    EXPECT_TRUE(report["statistics"].empty());
    EXPECT_TRUE(report["events"].is_array());
    EXPECT_TRUE(report["events"].empty());

    const SSP::SystemResourceUsage usage = profiler.GetResourceUsage();
    EXPECT_TRUE(std::isfinite(usage.processCpuUsagePercent));
    EXPECT_GE(usage.processCpuUsagePercent, 0.0);
    EXPECT_LE(usage.processCpuUsagePercent, 100.0);
}

TEST_F(PerformanceProfilerTest, SessionLifecycleAndDisabledModeBehaveSafely) {
    EXPECT_TRUE(profiler.IsEnabled());
    EXPECT_FALSE(profiler.IsSessionActive());

    profiler.StartSession("");
    EXPECT_FALSE(profiler.IsSessionActive());

    profiler.StartSession("unit-session");
    ASSERT_TRUE(profiler.IsSessionActive());

    profiler.SetEnabled(false);
    profiler.StartProfile("disabled-profile");
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    profiler.StopProfile("disabled-profile");

    profiler.SetEnabled(true);
    profiler.StartProfile("active-profile");
    EXPECT_EQ(profiler.GetActiveProfileCount(), 1u);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    profiler.StopProfile("active-profile");
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    EXPECT_GT(profiler.GetAverageExecutionTimeMs("active-profile"), 0.0);

    profiler.EndSession();
    EXPECT_FALSE(profiler.IsSessionActive());
}

TEST_F(PerformanceProfilerTest, ScopedProfileRecordsEventsAndClearHistoryResetsAggregates) {
    profiler.StartSession("report-session");
    {
        SSP::ScopedProfile scoped("scoped-probe");
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    const double averageMs = profiler.GetAverageExecutionTimeMs("scoped-probe");
    const std::string report = profiler.GenerateReport();
    EXPECT_GT(averageMs, 0.0);
    EXPECT_NE(report.find("report-session"), std::string::npos);
    EXPECT_NE(report.find("scoped-probe"), std::string::npos);

    profiler.EndSession();
    profiler.ClearHistory();
    EXPECT_EQ(profiler.GetAverageExecutionTimeMs("scoped-probe"), 0.0);
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
}

TEST_F(PerformanceProfilerTest, ProfilesOutsideSessionsStillAccumulateAggregateStatistics) {
    profiler.StartProfile("aggregate-only");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    profiler.StopProfile("aggregate-only");

    const double averageMs = profiler.GetAverageExecutionTimeMs("aggregate-only");
    const json report = ParseJson(profiler.GenerateReport());
    EXPECT_GT(averageMs, 0.0);
    EXPECT_EQ(report["total_samples"], 0);
    EXPECT_TRUE(report["events"].empty());
    EXPECT_EQ(report["statistics"]["aggregate-only"]["count"], 1);
}

TEST_F(PerformanceProfilerTest, SessionReplacementAndNameLengthLimitsResetStateDeterministically) {
    profiler.StartSession("first-session");
    {
        SSP::ScopedProfile scoped("first-metric");
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    EXPECT_GT(profiler.GetAverageExecutionTimeMs("first-metric"), 0.0);

    profiler.StartSession("second-session");
    const json secondSessionReport = ParseJson(profiler.GenerateReport());
    EXPECT_EQ(secondSessionReport["session"], "second-session");
    EXPECT_TRUE(secondSessionReport["statistics"].empty());
    EXPECT_TRUE(secondSessionReport["events"].empty());
    EXPECT_EQ(profiler.GetAverageExecutionTimeMs("first-metric"), 0.0);

    const std::string maxLengthSessionName(300, 's');
    profiler.StartSession(maxLengthSessionName);
    const json truncatedReport = ParseJson(profiler.GenerateReport());
    ASSERT_TRUE(truncatedReport["session"].is_string());
    EXPECT_EQ(truncatedReport["session"].get<std::string>(),
              maxLengthSessionName.substr(0, 256));

    const std::string acceptedProfileName(256, 'p');
    profiler.StartProfile(acceptedProfileName);
    EXPECT_EQ(profiler.GetActiveProfileCount(), 1u);
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    profiler.StopProfile(acceptedProfileName);
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    EXPECT_GT(profiler.GetAverageExecutionTimeMs(acceptedProfileName), 0.0);

    const std::string rejectedProfileName(257, 'q');
    profiler.StartProfile(rejectedProfileName);
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    profiler.StopProfile(rejectedProfileName);
    EXPECT_EQ(profiler.GetAverageExecutionTimeMs(rejectedProfileName), 0.0);
}

TEST_F(PerformanceProfilerTest, SessionReplacementClearsInflightProfilesBeforeNewSessionStarts) {
    profiler.StartSession("first-session");
    profiler.StartProfile("carryover-profile");
    ASSERT_EQ(profiler.GetActiveProfileCount(), 1u);

    profiler.StartSession("second-session");
    EXPECT_TRUE(profiler.IsSessionActive());
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);

    const json report = ParseJson(profiler.GenerateReport());
    EXPECT_EQ(report["session"], "second-session");
    EXPECT_TRUE(report["statistics"].empty());
    EXPECT_TRUE(report["events"].empty());

    profiler.StopProfile("carryover-profile");
    EXPECT_EQ(profiler.GetAverageExecutionTimeMs("carryover-profile"), 0.0);

    profiler.StartProfile("second-session-profile");
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    profiler.StopProfile("second-session-profile");
    EXPECT_GT(profiler.GetAverageExecutionTimeMs("second-session-profile"), 0.0);
}

TEST_F(PerformanceProfilerTest, SaveReportRejectsUnsafePathsAndWritesTempReport) {
    EXPECT_FALSE(profiler.SaveReport({}));
    EXPECT_FALSE(profiler.SaveReport(std::filesystem::path(L"\\\\?\\C:\\unsafe-report.json")));
    EXPECT_FALSE(profiler.SaveReport(std::filesystem::path(L"\\\\.\\C:\\device-report.json")));

    profiler.StartSession("save-report");
    {
        SSP::ScopedProfile scoped("save-probe");
        std::this_thread::sleep_for(std::chrono::milliseconds(3));
    }
    profiler.EndSession();

    const std::filesystem::path reportPath =
        std::filesystem::temp_directory_path() / "shadowstrike-performance-profiler-report.json";
    std::error_code ec;
    std::filesystem::remove(reportPath, ec);

    ASSERT_TRUE(profiler.SaveReport(reportPath));

    std::ifstream input(reportPath, std::ios::binary);
    ASSERT_TRUE(input.is_open());
    const std::string content((std::istreambuf_iterator<char>(input)),
                              std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("save-report"), std::string::npos);
    EXPECT_NE(content.find("save-probe"), std::string::npos);

    input.close();
    std::filesystem::remove(reportPath, ec);

    const std::filesystem::path nestedDir =
        std::filesystem::temp_directory_path() / "shadowstrike-profiler-nested";
    const std::filesystem::path nestedReportPath = nestedDir / "report.txt";
    const std::filesystem::path unexpectedExtensionPath = nestedDir / "report.weird";
    std::filesystem::remove(nestedReportPath, ec);
    std::filesystem::remove(unexpectedExtensionPath, ec);
    std::filesystem::remove_all(nestedDir, ec);

    ASSERT_TRUE(profiler.SaveReport(nestedReportPath));
    EXPECT_TRUE(std::filesystem::exists(nestedReportPath));
    std::ifstream nestedInput(nestedReportPath, std::ios::binary);
    ASSERT_TRUE(nestedInput.is_open());
    const std::string nestedContent((std::istreambuf_iterator<char>(nestedInput)),
                                    std::istreambuf_iterator<char>());
    EXPECT_NE(nestedContent.find("save-report"), std::string::npos);
    nestedInput.close();

    ASSERT_TRUE(profiler.SaveReport(unexpectedExtensionPath));
    EXPECT_TRUE(std::filesystem::exists(unexpectedExtensionPath));

    std::filesystem::remove(nestedReportPath, ec);
    std::filesystem::remove(unexpectedExtensionPath, ec);
    std::filesystem::remove_all(nestedDir, ec);
}

TEST_F(PerformanceProfilerTest, ClearHistoryRemovesInflightProfilesAndLateStopsRemainNoOp) {
    profiler.StartSession("clear-history");
    profiler.StartProfile("inflight");
    EXPECT_EQ(profiler.GetActiveProfileCount(), 1u);

    profiler.ClearHistory();
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    profiler.StopProfile("inflight");
    EXPECT_EQ(profiler.GetAverageExecutionTimeMs("inflight"), 0.0);
}

TEST_F(PerformanceProfilerTest, DisablingBeforeStopStillDrainsInflightProfilesSafely) {
    profiler.StartSession("disable-inflight");
    profiler.StartProfile("stuck-profile");
    ASSERT_EQ(profiler.GetActiveProfileCount(), 1u);

    profiler.SetEnabled(false);
    profiler.StopProfile("stuck-profile");
    EXPECT_EQ(profiler.GetActiveProfileCount(), 0u);
    EXPECT_GT(profiler.GetAverageExecutionTimeMs("stuck-profile"), 0.0);
}

TEST_F(PerformanceProfilerTest, SelfTestPassesAndRestoresEnabledState) {
    profiler.SetEnabled(false);
    EXPECT_TRUE(profiler.SelfTest());
    EXPECT_FALSE(profiler.IsEnabled());
}

TEST_F(PerformanceProfilerTest, SelfTestEndsAnyActiveSessionAsPartOfDiagnostics) {
    profiler.StartSession("preexisting-session");
    ASSERT_TRUE(profiler.IsSessionActive());

    EXPECT_TRUE(profiler.SelfTest());
    EXPECT_FALSE(profiler.IsSessionActive());
    EXPECT_TRUE(profiler.IsEnabled());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
