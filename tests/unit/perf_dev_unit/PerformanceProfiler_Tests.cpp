/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for PerformanceProfiler.cpp.
 *
 * Coverage focus:
 * - report and resource-usage serialization
 * - session/profile lifecycle and disabled-mode guards
 * - scoped RAII profiling behavior
 * - report persistence and self-test behavior
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

#include "../../../src/Shared_modules/Performance/dev/PerformanceProfiler.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

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

TEST_F(PerformanceProfilerTest, SaveReportRejectsUnsafePathsAndWritesTempReport) {
    EXPECT_FALSE(profiler.SaveReport({}));
    EXPECT_FALSE(profiler.SaveReport(std::filesystem::path(L"\\\\?\\C:\\unsafe-report.json")));

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
}

TEST_F(PerformanceProfilerTest, SelfTestPassesAndRestoresEnabledState) {
    profiler.SetEnabled(false);
    EXPECT_TRUE(profiler.SelfTest());
    EXPECT_FALSE(profiler.IsEnabled());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
