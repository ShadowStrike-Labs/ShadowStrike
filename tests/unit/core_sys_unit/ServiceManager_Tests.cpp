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
 * @file ServiceManager_Tests.cpp
 * @brief Comprehensive GTest coverage for Core::System::ServiceManager.
 *
 * Coverage focus:
 * - configuration presets and statistics reset semantics
 * - safe default behavior before initialization for service-query surfaces
 * - callback registration and watchdog guards that are deterministic in unit scope
 */

#include "pch.h"

#include "../../../src/Shared_modules/Core/System/ServiceManager.hpp"

namespace {

using namespace ShadowStrike::Core::System;

class ServiceManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        auto& manager = ServiceManager::Instance();
        manager.StopWatchdog();
        manager.Shutdown();
        manager.ResetStatistics();
    }

    void TearDown() override {
        auto& manager = ServiceManager::Instance();
        manager.StopWatchdog();
        manager.Shutdown();
    }
};

TEST(ServiceManagerValueTests, ConfigPresetsAndStatisticsResetReflectProtectionIntent) {
    const auto defaults = ServiceManagerConfig::CreateDefault();
    const auto highSecurity = ServiceManagerConfig::CreateHighSecurity();

    EXPECT_TRUE(defaults.enableSelfProtection);
    EXPECT_TRUE(defaults.monitorServiceChanges);
    EXPECT_TRUE(defaults.autoRestartOnFailure);
    EXPECT_TRUE(defaults.validateSignatures);
    EXPECT_EQ(defaults.watchdogIntervalMs, 5000u);
    EXPECT_EQ(defaults.mainServiceName, L"ShadowStrikeAV");
    EXPECT_EQ(defaults.driverServiceName, L"ShadowStrikeDriver");

    EXPECT_TRUE(highSecurity.enableSelfProtection);
    EXPECT_EQ(highSecurity.watchdogIntervalMs, 2000u);

    ServiceManagerStatistics stats;
    stats.servicesEnumerated.store(1, std::memory_order_relaxed);
    stats.servicesStarted.store(2, std::memory_order_relaxed);
    stats.servicesStopped.store(3, std::memory_order_relaxed);
    stats.driversLoaded.store(4, std::memory_order_relaxed);
    stats.driversUnloaded.store(5, std::memory_order_relaxed);
    stats.remediationActions.store(6, std::memory_order_relaxed);
    stats.tamperAttempts.store(7, std::memory_order_relaxed);
    stats.selfRecoveries.store(8, std::memory_order_relaxed);
    stats.Reset();

    EXPECT_EQ(stats.servicesEnumerated.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.servicesStarted.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.servicesStopped.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.driversLoaded.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.driversUnloaded.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.remediationActions.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.tamperAttempts.load(std::memory_order_relaxed), 0u);
    EXPECT_EQ(stats.selfRecoveries.load(std::memory_order_relaxed), 0u);
}

TEST_F(ServiceManagerTest, UninitializedQuerySurfaceReturnsSafeDefaults) {
    auto& manager = ServiceManager::Instance();

    EXPECT_TRUE(manager.EnumerateServices().empty());
    EXPECT_TRUE(manager.EnumerateDrivers().empty());
    EXPECT_FALSE(manager.GetServiceInfo(L"ShadowStrikeAV").has_value());
    EXPECT_FALSE(manager.ServiceExists(L"ShadowStrikeAV"));
    EXPECT_EQ(manager.GetServiceState(L"ShadowStrikeAV"), ServiceState::Unknown);
    EXPECT_TRUE(manager.GetSuspiciousServices().empty());
}

TEST_F(ServiceManagerTest, CallbackRegistrationAndWatchdogGuardsAreStableBeforeInit) {
    auto& manager = ServiceManager::Instance();

    EXPECT_EQ(manager.RegisterServiceChangeCallback(ServiceChangeCallback{}), 0u);
    EXPECT_EQ(manager.RegisterTamperAlertCallback(TamperAlertCallback{}), 0u);

    const auto serviceCallbackId = manager.RegisterServiceChangeCallback([](const ServiceChangeEvent&) {});
    const auto tamperCallbackId = manager.RegisterTamperAlertCallback([](const TamperDetectionResult&) {});

    EXPECT_NE(serviceCallbackId, 0u);
    EXPECT_NE(tamperCallbackId, 0u);
    EXPECT_NE(serviceCallbackId, tamperCallbackId);

    manager.UnregisterServiceChangeCallback(serviceCallbackId);
    manager.UnregisterTamperAlertCallback(tamperCallbackId);

    manager.StartWatchdog();
    EXPECT_FALSE(manager.IsWatchdogRunning());
    manager.StopWatchdog();
    EXPECT_FALSE(manager.IsWatchdogRunning());
}

}  // namespace
