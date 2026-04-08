/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Comprehensive unit coverage for adaptive profile management.
 *
 * Focus:
 *   - profile definition validation, serialization, and utility helpers
 *   - built-in/custom profile lifecycle and emergency behavior
 *   - schedules, application triggers, resource overrides, and statistics
 */

#include "pch.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <limits>
#include <string>
#include <vector>

#include "../../../src/Shared_modules/Config/ProfileManager.hpp"
#include "Config_TestUtils.hpp"

namespace ShadowStrike::Config::Test {

namespace {

std::tm GetLocalTimeNow() {
    const std::time_t now = std::time(nullptr);
    std::tm localTm{};
    localtime_s(&localTm, &now);
    return localTm;
}

ProfileDefinition MakeCustomProfile(const std::string& name) {
    ProfileDefinition profile;
    profile.profileType = SystemProfile::Custom;
    profile.customName = name;
    profile.description = "Custom unit-test profile";
    profile.resources.maxCpuPercent = 35;
    profile.resources.maxMemoryMb = 768;
    profile.resources.ioPriority = 2;
    profile.resources.maxConcurrentScans = 2;
    profile.scan.heuristicLevel = 2;
    profile.notifications.enabled = true;
    profile.pathExclusions = {L"C:\\Temp\\Ignore"};
    profile.processExclusions = {L"builder.exe"};
    profile.extensionExclusions = {L".cache"};
    profile.createdAt = std::chrono::system_clock::now();
    profile.modifiedAt = profile.createdAt;
    return profile;
}

}  // namespace

class ProfileManagerTest : public ::testing::Test {
protected:
    ProfileManager& manager = ProfileManager::Instance();

    void SetUp() override {
        manager.Shutdown();

        ProfileManagerConfiguration config;
        config.initialProfile = SystemProfile::Standard;
        config.enableAutoDetection = false;
        config.switchCooldownSeconds = 0;
        ASSERT_TRUE(manager.Initialize(config));

        CleanupState();
        manager.ResetStatistics();
    }

    void TearDown() override {
        CleanupState();
        manager.Shutdown();
    }

    void CleanupState() {
        if (manager.IsInEmergencyMode()) {
            (void)manager.ExitEmergencyMode();
        }

        if (manager.GetActiveProfile() != SystemProfile::Standard) {
            (void)manager.SetActiveProfile(SystemProfile::Standard);
        }

        for (const auto& name : manager.ListCustomProfileNames()) {
            (void)manager.DeleteCustomProfile(name);
        }
        for (const auto& entry : manager.ListScheduleEntries()) {
            (void)manager.RemoveScheduleEntry(entry.scheduleId);
        }
        for (const auto& rule : manager.ListApplicationTriggers()) {
            (void)manager.RemoveApplicationTrigger(rule.ruleId);
        }
        manager.ClearResourceOverride();
    }
};

TEST_F(ProfileManagerTest, StructValidationSerializationAndUtilityHelpersAreStable) {
    ProfileManagerConfiguration config;
    EXPECT_TRUE(config.IsValid());

    config.autoDetectIntervalSeconds = 0;
    EXPECT_FALSE(config.IsValid());

    config = {};
    config.initialProfile = static_cast<SystemProfile>(0xFF);
    EXPECT_FALSE(config.IsValid());

    ResourceLimits resources;
    resources.maxCpuPercent = 42;
    resources.maxMemoryMb = 900;
    resources.ioPriority = 3;
    resources.maxConcurrentScans = 4;
    const auto resourceJson = ParseJson(resources.ToJson());
    EXPECT_EQ(resourceJson.at("maxCpuPercent").get<uint32_t>(), 42u);
    EXPECT_EQ(resourceJson.at("maxMemoryMb").get<uint32_t>(), 900u);
    EXPECT_EQ(resourceJson.at("ioPriority").get<uint32_t>(), 3u);

    ProfileScanSettings scan;
    scan.behaviorMonitoring = false;
    scan.heuristicLevel = 4;
    const auto scanJson = ParseJson(scan.ToJson());
    EXPECT_FALSE(scanJson.at("behaviorMonitoring").get<bool>());
    EXPECT_EQ(scanJson.at("heuristicLevel").get<uint32_t>(), 4u);

    ProfileNotificationSettings notifications;
    notifications.doNotDisturbEnabled = true;
    notifications.dndStartHour = 23;
    notifications.dndEndHour = 6;
    const auto notificationJson = ParseJson(notifications.ToJson());
    EXPECT_TRUE(notificationJson.at("doNotDisturbEnabled").get<bool>());
    EXPECT_EQ(notificationJson.at("dndStartHour").get<uint32_t>(), 23u);

    ProfileDefinition validCustom = MakeCustomProfile(UniqueUtf8("profile"));
    ASSERT_TRUE(validCustom.IsValid());
    const auto profileJson = ParseJson(validCustom.ToJson());
    EXPECT_EQ(profileJson.at("profileType").get<std::string>(), "Custom");
    EXPECT_EQ(profileJson.at("customName").get<std::string>(), validCustom.customName);
    EXPECT_EQ(profileJson.at("pathExclusions").at(0).get<std::string>(), "C:\\Temp\\Ignore");

    ProfileDefinition invalidCustom = validCustom;
    invalidCustom.customName.clear();
    EXPECT_FALSE(invalidCustom.IsValid());

    ProfileDefinition maxLengthName = validCustom;
    maxLengthName.customName.assign(ProfileConstants::MAX_PROFILE_NAME_LENGTH, 'a');
    EXPECT_TRUE(maxLengthName.IsValid());

    ProfileDefinition tooLongName = validCustom;
    tooLongName.customName.assign(ProfileConstants::MAX_PROFILE_NAME_LENGTH + 1, 'b');
    EXPECT_FALSE(tooLongName.IsValid());

    ProfileDefinition invalidCpu = validCustom;
    invalidCpu.resources.maxCpuPercent = 101;
    EXPECT_FALSE(invalidCpu.IsValid());

    ProfileDefinition invalidIo = validCustom;
    invalidIo.resources.ioPriority = 6;
    EXPECT_FALSE(invalidIo.IsValid());

    ProfileDefinition invalidHeuristics = validCustom;
    invalidHeuristics.scan.heuristicLevel = 5;
    EXPECT_FALSE(invalidHeuristics.IsValid());

    ProfileSwitchEvent switchEvent;
    switchEvent.previousProfile = SystemProfile::Standard;
    switchEvent.newProfile = SystemProfile::Gaming;
    switchEvent.trigger = ProfileTrigger::ApplicationStart;
    switchEvent.timestamp = std::chrono::system_clock::time_point{std::chrono::seconds(10)};
    switchEvent.switchDurationMs = 25;
    switchEvent.success = true;
    const auto switchJson = ParseJson(switchEvent.ToJson());
    EXPECT_EQ(switchJson.at("previousProfile").get<std::string>(), "Standard");
    EXPECT_EQ(switchJson.at("newProfile").get<std::string>(), "Gaming");
    EXPECT_EQ(switchJson.at("trigger").get<std::string>(), "ApplicationStart");

    const auto localTm = GetLocalTimeNow();
    const uint8_t todayMask = static_cast<uint8_t>(1u << localTm.tm_wday);
    const uint32_t currentMinutes = static_cast<uint32_t>(localTm.tm_hour) * 60u +
                                    static_cast<uint32_t>(localTm.tm_min);

    ProfileScheduleEntry activeEntry;
    activeEntry.daysOfWeek = todayMask;
    activeEntry.startHour = static_cast<uint32_t>(((currentMinutes + 1440u - 1u) % 1440u) / 60u);
    activeEntry.startMinute = static_cast<uint32_t>((currentMinutes + 1440u - 1u) % 60u);
    activeEntry.endHour = static_cast<uint32_t>(((currentMinutes + 1u) % 1440u) / 60u);
    activeEntry.endMinute = static_cast<uint32_t>((currentMinutes + 1u) % 60u);
    EXPECT_TRUE(activeEntry.IsActiveNow());

    ProfileScheduleEntry wrongDay = activeEntry;
    wrongDay.daysOfWeek = static_cast<uint8_t>(~todayMask);
    EXPECT_FALSE(wrongDay.IsActiveNow());

    ProfileScheduleEntry disabled = activeEntry;
    disabled.enabled = false;
    EXPECT_FALSE(disabled.IsActiveNow());

    const auto scheduleJson = ParseJson(activeEntry.ToJson());
    EXPECT_EQ(scheduleJson.at("profile").get<std::string>(), "Standard");
    EXPECT_EQ(scheduleJson.at("daysOfWeek").get<uint8_t>(), todayMask);

    ApplicationTriggerRule trigger;
    trigger.ruleId = 7;
    trigger.applicationPattern = L"*game.exe";
    trigger.profileWhenRunning = SystemProfile::Gaming;
    trigger.profileAfterExit = SystemProfile::Standard;
    trigger.switchDelaySeconds = 2;
    const auto triggerJson = ParseJson(trigger.ToJson());
    EXPECT_EQ(triggerJson.at("ruleId").get<uint64_t>(), 7u);
    EXPECT_EQ(triggerJson.at("applicationPattern").get<std::string>(), "*game.exe");
    EXPECT_EQ(triggerJson.at("profileWhenRunning").get<std::string>(), "Gaming");

    ProfileStatistics stats;
    stats.profileSwitches.store(5, std::memory_order_relaxed);
    stats.manualSwitches.store(4, std::memory_order_relaxed);
    stats.timeInProfile[static_cast<size_t>(SystemProfile::Standard)].store(20, std::memory_order_relaxed);
    const auto statsJson = ParseJson(stats.ToJson());
    EXPECT_EQ(statsJson.at("profileSwitches").get<uint64_t>(), 5u);
    EXPECT_EQ(statsJson.at("manualSwitches").get<uint64_t>(), 4u);
    EXPECT_EQ(statsJson.at("timeInProfileSeconds").at(static_cast<size_t>(SystemProfile::Standard)).get<uint64_t>(), 20u);
    stats.Reset();
    EXPECT_EQ(ParseJson(stats.ToJson()).at("profileSwitches").get<uint64_t>(), 0u);

    EXPECT_EQ(GetSystemProfileName(SystemProfile::LockedDown), "LockedDown");
    EXPECT_EQ(GetSystemProfileName(static_cast<SystemProfile>(0xFF)), "Unknown");
    EXPECT_EQ(GetMachineRoleName(MachineRole::DomainController), "DomainController");
    EXPECT_EQ(GetProfileTriggerName(ProfileTrigger::Emergency), "Emergency");
    EXPECT_EQ(GetDefaultProfileForRole(MachineRole::Server), SystemProfile::Server);
    EXPECT_EQ(GetDefaultProfileForRole(MachineRole::DomainController), SystemProfile::HighSecurity);
    EXPECT_EQ(GetDefaultProfileForRole(MachineRole::Container), SystemProfile::LowResource);
    EXPECT_EQ(ProfileManager::GetVersionString(), "3.0.0");
}

TEST_F(ProfileManagerTest, BuiltInProfilesCustomLifecycleAndEmergencyModeBehaveDeterministically) {
    ASSERT_TRUE(manager.SelfTest());
    EXPECT_EQ(manager.GetActiveProfile(), SystemProfile::Standard);
    EXPECT_EQ(manager.GetActiveProfileName(), "Standard");

    const auto standardProfile = manager.GetProfileDefinition(SystemProfile::Standard);
    EXPECT_TRUE(standardProfile.isBuiltIn);
    EXPECT_TRUE(standardProfile.isReadOnly);
    EXPECT_EQ(manager.ListProfiles().size(), 10u);

    const std::string customName = UniqueUtf8("custom-profile");
    ProfileDefinition customProfile = MakeCustomProfile(customName);
    ASSERT_TRUE(manager.CreateCustomProfile(customProfile));
    EXPECT_EQ(manager.ListCustomProfileNames(), std::vector<std::string>({customName}));

    auto storedCustom = manager.GetCustomProfile(customName);
    ASSERT_TRUE(storedCustom.has_value());
    EXPECT_FALSE(storedCustom->isBuiltIn);
    EXPECT_EQ(storedCustom->profileType, SystemProfile::Custom);

    customProfile.description = "Updated custom profile";
    customProfile.resources.maxMemoryMb = 1024;
    ASSERT_TRUE(manager.UpdateCustomProfile(customName, customProfile));
    storedCustom = manager.GetCustomProfile(customName);
    ASSERT_TRUE(storedCustom.has_value());
    EXPECT_EQ(storedCustom->description, "Updated custom profile");
    EXPECT_EQ(storedCustom->resources.maxMemoryMb, 1024u);

    std::vector<ProfileSwitchEvent> callbackEvents;
    const auto callbackId = manager.RegisterSwitchCallback(
        [&callbackEvents](const ProfileSwitchEvent& event) {
            callbackEvents.push_back(event);
        });

    ASSERT_TRUE(manager.SetActiveProfile(customName));
    EXPECT_EQ(manager.GetActiveProfile(), SystemProfile::Custom);
    EXPECT_EQ(manager.GetActiveProfileDefinition().customName, customName);

    ASSERT_TRUE(manager.SetActiveProfile(SystemProfile::Developer));
    EXPECT_EQ(manager.GetActiveProfile(), SystemProfile::Developer);

    ASSERT_TRUE(manager.ActivateEmergencyProfile());
    EXPECT_TRUE(manager.IsInEmergencyMode());
    EXPECT_EQ(manager.GetActiveProfile(), SystemProfile::Emergency);
    EXPECT_FALSE(manager.SetActiveProfile(SystemProfile::Standard));

    ASSERT_TRUE(manager.ExitEmergencyMode());
    EXPECT_FALSE(manager.IsInEmergencyMode());
    EXPECT_EQ(manager.GetActiveProfile(), SystemProfile::Developer);

    const auto history = manager.GetSwitchHistory(100);
    EXPECT_GE(history.size(), 3u);
    EXPECT_EQ(history.back().newProfile, SystemProfile::Developer);

    const auto stats = manager.GetStatistics();
    EXPECT_GE(stats.profileSwitches.load(std::memory_order_relaxed), 3u);
    EXPECT_GE(stats.manualSwitches.load(std::memory_order_relaxed), 2u);
    EXPECT_GE(stats.emergencySwitches.load(std::memory_order_relaxed), 1u);

    manager.UnregisterCallback(callbackId);
    EXPECT_TRUE(manager.DeleteCustomProfile(customName));
    EXPECT_FALSE(manager.DeleteCustomProfile(customName));
    EXPECT_FALSE(manager.GetCustomProfile(customName).has_value());
    EXPECT_GE(callbackEvents.size(), 3u);
}

TEST_F(ProfileManagerTest, SchedulesTriggersAndResourceOverridesStayLocallyConsistent) {
    ProfileScheduleEntry invalidEntry;
    invalidEntry.startHour = 25;
    EXPECT_EQ(manager.AddScheduleEntry(invalidEntry), 0u);

    ProfileScheduleEntry validEntry;
    validEntry.profile = SystemProfile::Gaming;
    validEntry.daysOfWeek = 0x7F;
    validEntry.startHour = 18;
    validEntry.startMinute = 0;
    validEntry.endHour = 23;
    validEntry.endMinute = 30;
    validEntry.priority = 500;

    const auto scheduleId = manager.AddScheduleEntry(validEntry);
    ASSERT_GT(scheduleId, 0u);
    auto schedules = manager.ListScheduleEntries();
    ASSERT_EQ(schedules.size(), 1u);
    EXPECT_EQ(schedules.front().scheduleId, scheduleId);

    ProfileScheduleEntry updatedEntry = schedules.front();
    updatedEntry.priority = 800;
    ASSERT_TRUE(manager.UpdateScheduleEntry(updatedEntry));
    schedules = manager.ListScheduleEntries();
    EXPECT_EQ(schedules.front().priority, 800u);
    EXPECT_TRUE(manager.RemoveScheduleEntry(scheduleId));
    EXPECT_FALSE(manager.RemoveScheduleEntry(scheduleId));

    ApplicationTriggerRule rule;
    rule.applicationPattern = L"*visualstudio.exe";
    rule.profileWhenRunning = SystemProfile::Developer;
    rule.profileAfterExit = SystemProfile::Standard;
    rule.exitDelaySeconds = 10;

    const auto ruleId = manager.AddApplicationTrigger(rule);
    ASSERT_GT(ruleId, 0u);
    auto rules = manager.ListApplicationTriggers();
    ASSERT_EQ(rules.size(), 1u);
    EXPECT_EQ(rules.front().ruleId, ruleId);

    ApplicationTriggerRule updatedRule = rules.front();
    updatedRule.profileWhenRunning = SystemProfile::Gaming;
    ASSERT_TRUE(manager.UpdateApplicationTrigger(updatedRule));
    rules = manager.ListApplicationTriggers();
    EXPECT_EQ(rules.front().profileWhenRunning, SystemProfile::Gaming);
    EXPECT_TRUE(manager.RemoveApplicationTrigger(ruleId));
    EXPECT_FALSE(manager.RemoveApplicationTrigger(ruleId));

    const auto standardLimits = manager.GetCurrentResourceLimits();
    EXPECT_EQ(standardLimits.maxCpuPercent, 50u);

    ResourceLimits overrideLimits;
    overrideLimits.maxCpuPercent = 9;
    overrideLimits.maxMemoryMb = 96;
    overrideLimits.ioPriority = 1;
    overrideLimits.maxConcurrentScans = 1;
    manager.OverrideResourceLimits(overrideLimits);
    const auto overridden = manager.GetCurrentResourceLimits();
    EXPECT_EQ(overridden.maxCpuPercent, 9u);
    EXPECT_EQ(overridden.maxMemoryMb, 96u);

    manager.ClearResourceOverride();
    const auto restored = manager.GetCurrentResourceLimits();
    EXPECT_EQ(restored.maxCpuPercent, 50u);
    EXPECT_EQ(restored.maxMemoryMb, 512u);
}

TEST_F(ProfileManagerTest, CapacityFlagsAndFailurePathsRejectInvalidOperations) {
    EXPECT_FALSE(manager.ExitEmergencyMode());

    manager.SetAutoDetectionEnabled(true);
    EXPECT_TRUE(manager.IsAutoDetectionEnabled());
    manager.SetAutoDetectionEnabled(false);
    EXPECT_FALSE(manager.IsAutoDetectionEnabled());

    ProfileDefinition firstProfile = MakeCustomProfile(std::string(ProfileConstants::MAX_PROFILE_NAME_LENGTH, 'n'));
    ASSERT_TRUE(manager.CreateCustomProfile(firstProfile));
    EXPECT_FALSE(manager.CreateCustomProfile(firstProfile));

    for (uint32_t index = 1; index < ProfileConstants::MAX_CUSTOM_PROFILES; ++index) {
        ASSERT_TRUE(manager.CreateCustomProfile(MakeCustomProfile("custom-" + std::to_string(index))));
    }
    EXPECT_EQ(manager.ListCustomProfileNames().size(), ProfileConstants::MAX_CUSTOM_PROFILES);
    EXPECT_FALSE(manager.CreateCustomProfile(MakeCustomProfile("overflow")));
    EXPECT_FALSE(manager.UpdateCustomProfile("missing-profile", MakeCustomProfile("replacement")));
    EXPECT_FALSE(manager.SetActiveProfile("missing-profile"));

    ProfileScheduleEntry invalidMinutes;
    invalidMinutes.startMinute = 60;
    EXPECT_EQ(manager.AddScheduleEntry(invalidMinutes), 0u);

    ProfileScheduleEntry missingSchedule;
    missingSchedule.scheduleId = 9999;
    EXPECT_FALSE(manager.UpdateScheduleEntry(missingSchedule));

    ApplicationTriggerRule missingRule;
    missingRule.ruleId = 12345;
    EXPECT_FALSE(manager.UpdateApplicationTrigger(missingRule));

    ASSERT_TRUE(manager.ActivateEmergencyProfile());
    EXPECT_TRUE(manager.ActivateEmergencyProfile());
    EXPECT_TRUE(manager.IsInEmergencyMode());
    ASSERT_TRUE(manager.ExitEmergencyMode());
    EXPECT_FALSE(manager.ExitEmergencyMode());
}

}  // namespace ShadowStrike::Config::Test
