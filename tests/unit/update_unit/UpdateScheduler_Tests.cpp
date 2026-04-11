/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for deterministic UpdateScheduler contracts.
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <string>

#include <nlohmann/json.hpp>

#include "../../../src/PhantomCore/Update/UpdateScheduler.hpp"

namespace ShadowStrike::Update::Test {
namespace {

using nlohmann::json;

}  // namespace

TEST(UpdateSchedulerTest, HelperNamesAndTimeWindowPredicatesRemainStable) {
    EXPECT_EQ(GetSchedulerStateName(SchedulerState::Checking), "Checking");
    EXPECT_EQ(GetCheckTriggerName(CheckTrigger::WakeFromSleep), "WakeFromSleep");
    EXPECT_EQ(GetDeferralReasonName(DeferralReason::MaintenanceWindow), "MaintenanceWindow");
    EXPECT_EQ(GetNetworkTypeName(NetworkType::VPN), "VPN");
    EXPECT_EQ(GetNetworkTypeName(static_cast<NetworkType>(0xFF)), "Unknown");

    const std::string versionString = UpdateScheduler::GetVersionString();
    EXPECT_TRUE(versionString.starts_with("UpdateScheduler "));
    EXPECT_EQ(std::count(versionString.begin(), versionString.end(), '.'), 2);

    ScheduleRule rule;
    rule.enabled = true;
    rule.daysOfWeek = 0x7F;
    rule.startMinutes = 0;
    rule.endMinutes = 24 * 60;
    EXPECT_TRUE(rule.IsActiveNow());

    rule.enabled = false;
    EXPECT_FALSE(rule.IsActiveNow());

    QuietHours quiet;
    quiet.enabled = true;
    quiet.daysOfWeek = 0x7F;
    quiet.startMinutes = 0;
    quiet.endMinutes = 24 * 60;
    EXPECT_TRUE(quiet.IsActiveNow());

    quiet.enabled = false;
    EXPECT_FALSE(quiet.IsActiveNow());

    MaintenanceWindow oneshot;
    oneshot.enabled = true;
    oneshot.startTime = std::chrono::system_clock::now() - std::chrono::minutes(10);
    oneshot.durationMinutes = 30;
    oneshot.recurrenceDays = 0;
    EXPECT_TRUE(oneshot.IsActiveNow());

    MaintenanceWindow future;
    future.enabled = true;
    future.startTime = std::chrono::system_clock::now() + std::chrono::minutes(30);
    future.durationMinutes = 30;
    future.recurrenceDays = 0;
    EXPECT_FALSE(future.IsActiveNow());

    MaintenanceWindow recurring;
    recurring.enabled = true;
    recurring.startTime = std::chrono::system_clock::now() - std::chrono::hours(25);
    recurring.durationMinutes = 120;
    recurring.recurrenceDays = 1;
    EXPECT_TRUE(recurring.IsActiveNow());
}

TEST(UpdateSchedulerTest, DtosStatisticsAndConfigurationRemainActionable) {
    const auto now = std::chrono::system_clock::now();

    ScheduleRule rule;
    rule.ruleId = "daily";
    rule.name = "Daily";
    rule.enabled = true;
    rule.intervalHours = 4;
    rule.daysOfWeek = 0x7F;
    rule.startMinutes = 60;
    rule.endMinutes = 180;

    const json ruleJson = json::parse(rule.ToJson());
    EXPECT_EQ(ruleJson.at("ruleId"), "daily");
    EXPECT_EQ(ruleJson.at("intervalHours"), 4);

    QuietHours quiet;
    quiet.enabled = true;
    quiet.startMinutes = 60;
    quiet.endMinutes = 120;
    quiet.daysOfWeek = 0x7F;

    const json quietJson = json::parse(quiet.ToJson());
    EXPECT_TRUE(quietJson.at("enabled").get<bool>());
    EXPECT_EQ(quietJson.at("endMinutes"), 120);

    MaintenanceWindow window;
    window.windowId = "mw-1";
    window.name = "Night";
    window.enabled = true;
    window.startTime = now;
    window.durationMinutes = 45;
    window.recurrenceDays = 7;

    const json windowJson = json::parse(window.ToJson());
    EXPECT_EQ(windowJson.at("windowId"), "mw-1");
    EXPECT_EQ(windowJson.at("durationMinutes"), 45);

    SystemState state;
    state.cpuUsage = 55;
    state.memoryUsage = 66;
    state.isGaming = true;
    state.isOnBattery = true;
    state.batteryPercent = 40;
    state.networkType = NetworkType::WiFi;
    state.isMetered = true;
    state.isVPN = false;
    state.isQuietHours = true;

    const json stateJson = json::parse(state.ToJson());
    EXPECT_EQ(stateJson.at("cpuUsage"), 55);
    EXPECT_EQ(stateJson.at("networkType"), "WiFi");
    EXPECT_TRUE(stateJson.at("isQuietHours").get<bool>());

    ScheduleInfo info;
    info.nextCheckTime = now;
    info.lastCheckTime = std::nullopt;
    info.lastCheckTrigger = CheckTrigger::Manual;
    info.deferralReason = DeferralReason::HighCPU;
    info.deferralCount = 2;
    info.checksToday = 3;

    const json infoJson = json::parse(info.ToJson());
    EXPECT_EQ(infoJson.at("lastCheckTrigger"), "Manual");
    EXPECT_EQ(infoJson.at("deferralReason"), "HighCPU");
    EXPECT_TRUE(infoJson.at("lastCheckTime").is_null());

    SchedulerStatistics stats;
    stats.checksTriggered = 4;
    stats.checksCompleted = 3;
    stats.checksFailed = 1;
    stats.checksDeferred = 2;
    stats.updatesFound = 5;
    stats.updatesApplied = 1;
    stats.byDeferralReason[static_cast<size_t>(DeferralReason::HighCPU)] = 7;
    stats.byTrigger[static_cast<size_t>(CheckTrigger::Manual)] = 8;

    stats.Reset();

    EXPECT_EQ(stats.checksTriggered, 0u);
    EXPECT_EQ(stats.updatesApplied, 0u);
    EXPECT_EQ(stats.byDeferralReason[static_cast<size_t>(DeferralReason::HighCPU)], 0u);
    EXPECT_EQ(stats.byTrigger[static_cast<size_t>(CheckTrigger::Manual)], 0u);

    const json statsJson = json::parse(stats.ToJson());
    EXPECT_EQ(statsJson.at("checksTriggered"), 0);
    EXPECT_TRUE(statsJson.at("byDeferralReason").is_array());
    EXPECT_GE(statsJson.at("uptimeSeconds").get<int64_t>(), 0);

    UpdateSchedulerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.defaultIntervalHours = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.cpuDeferThreshold = 101;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.maxDeferHours = 0;
    EXPECT_FALSE(config.IsValid());
}

TEST(UpdateSchedulerTest, DefaultAccessorsAndDisabledWindowsRemainFailClosed) {
    ScheduleRule rule;
    rule.enabled = true;
    rule.daysOfWeek = 0;
    rule.startMinutes = 30;
    rule.endMinutes = 30;
    EXPECT_FALSE(rule.IsActiveNow());

    QuietHours quiet;
    quiet.enabled = true;
    quiet.daysOfWeek = 0;
    quiet.startMinutes = 23 * 60;
    quiet.endMinutes = 60;
    EXPECT_FALSE(quiet.IsActiveNow());

    auto& scheduler = UpdateScheduler::Instance();
    scheduler.Shutdown();

    EXPECT_FALSE(scheduler.IsInitialized());
    EXPECT_EQ(scheduler.GetStatus(), SchedulerStatus::Uninitialized);
    EXPECT_EQ(scheduler.GetState(), SchedulerState::Stopped);
    EXPECT_FALSE(scheduler.IsRunning());
    EXPECT_EQ(scheduler.GetInterval(),
              std::chrono::hours(SchedulerConstants::DEFAULT_CHECK_INTERVAL_HOURS));
    EXPECT_TRUE(scheduler.GetRules().empty());
    EXPECT_FALSE(scheduler.GetQuietHours().enabled);
    EXPECT_TRUE(scheduler.GetMaintenanceWindows().empty());
    EXPECT_FALSE(scheduler.GetNextCheckTime().has_value());
    EXPECT_FALSE(scheduler.CanUpdateNow());
    EXPECT_EQ(scheduler.GetCurrentDeferralReason(), DeferralReason::None);
}

TEST(UpdateSchedulerTest, RuleWindowAndLifecycleTransitionsRemainDeterministic) {
    auto& scheduler = UpdateScheduler::Instance();
    scheduler.Shutdown();

    UpdateSchedulerConfiguration config;
    config.enabled = false;
    config.checkOnStartup = false;
    config.defaultIntervalHours = 24;
    ASSERT_TRUE(config.IsValid());
    ASSERT_TRUE(scheduler.Initialize(config));

    ScheduleRule rule;
    rule.ruleId = "daily";
    rule.name = "Daily";
    rule.enabled = true;
    rule.intervalHours = 24;
    rule.daysOfWeek = 0x7F;
    rule.startMinutes = 60;
    rule.endMinutes = 120;

    EXPECT_FALSE(scheduler.AddRule(ScheduleRule{}));
    EXPECT_TRUE(scheduler.AddRule(rule));
    EXPECT_FALSE(scheduler.AddRule(rule));
    EXPECT_EQ(scheduler.GetRules().size(), 1u);
    EXPECT_FALSE(scheduler.RemoveRule("missing"));
    EXPECT_TRUE(scheduler.RemoveRule(rule.ruleId));
    EXPECT_TRUE(scheduler.GetRules().empty());

    MaintenanceWindow window;
    window.windowId = "maintenance";
    window.name = "Window";
    window.enabled = true;
    window.startTime = std::chrono::system_clock::now() + std::chrono::hours(1);
    window.durationMinutes = 45;
    window.recurrenceDays = 0;

    EXPECT_FALSE(scheduler.AddMaintenanceWindow(MaintenanceWindow{}));
    EXPECT_TRUE(scheduler.AddMaintenanceWindow(window));
    EXPECT_FALSE(scheduler.AddMaintenanceWindow(window));
    EXPECT_EQ(scheduler.GetMaintenanceWindows().size(), 1u);
    EXPECT_FALSE(scheduler.RemoveMaintenanceWindow("missing"));
    EXPECT_TRUE(scheduler.RemoveMaintenanceWindow(window.windowId));
    EXPECT_TRUE(scheduler.GetMaintenanceWindows().empty());

    scheduler.Pause();
    scheduler.Resume();
    EXPECT_EQ(scheduler.GetState(), SchedulerState::Stopped);

    scheduler.Start();
    EXPECT_TRUE(scheduler.IsRunning());
    EXPECT_TRUE(scheduler.GetNextCheckTime().has_value());

    scheduler.Stop();
    EXPECT_EQ(scheduler.GetState(), SchedulerState::Stopped);
    EXPECT_FALSE(scheduler.IsRunning());
    EXPECT_FALSE(scheduler.GetNextCheckTime().has_value());

    scheduler.Stop();
    scheduler.Shutdown();
}

TEST(UpdateSchedulerTest, RepeatedInitializePreservesExistingIntervalAndQuietHours) {
    auto& scheduler = UpdateScheduler::Instance();
    scheduler.Shutdown();

    UpdateSchedulerConfiguration initialConfig;
    initialConfig.enabled = false;
    initialConfig.checkOnStartup = false;
    initialConfig.defaultIntervalHours = 12;
    initialConfig.quietHours.enabled = true;
    initialConfig.quietHours.daysOfWeek = 0x7F;
    initialConfig.quietHours.startMinutes = 90;
    initialConfig.quietHours.endMinutes = 180;
    ASSERT_TRUE(initialConfig.IsValid());
    ASSERT_TRUE(scheduler.Initialize(initialConfig));

    UpdateSchedulerConfiguration replacementConfig = initialConfig;
    replacementConfig.defaultIntervalHours = 48;
    replacementConfig.quietHours.enabled = false;
    replacementConfig.quietHours.startMinutes = 0;
    replacementConfig.quietHours.endMinutes = 0;

    ASSERT_TRUE(scheduler.Initialize(replacementConfig));

    EXPECT_EQ(scheduler.GetInterval(), std::chrono::hours(12));
    const auto effectiveQuietHours = scheduler.GetQuietHours();
    EXPECT_TRUE(effectiveQuietHours.enabled);
    EXPECT_EQ(effectiveQuietHours.startMinutes, 90u);
    EXPECT_EQ(effectiveQuietHours.endMinutes, 180u);

    scheduler.Shutdown();
}

}  // namespace ShadowStrike::Update::Test
