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
 * - callback registration, watchdog guards, and pre-init integrity-result semantics
 */

#include "pch.h"
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/Core/System/ServiceManager.hpp"

namespace {

using namespace ShadowStrike::Core::System;

// A service name that provably does not exist, used ONLY as an argument to calls made
// before Initialize(). Those cases assert that the pre-init surface answers safely; the
// name is incidental to what they test, and spelling our REAL service name there would
// make them depend on whether ShadowStrike happens to be installed on the machine
// running the suite. Deliberately shares no substring with either real service name so
// a search for those names cannot land here.
constexpr const wchar_t* kAbsentServiceName = L"NoSuchServiceForNegativeTests";

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
    // ShadowStrikePhantomService, not ShadowStrikeAV. Nothing has ever registered a
    // service called ShadowStrikeAV; packaging/installer/Components.wxs declares
    // <ServiceInstall Name="ShadowStrikePhantomService"> and that is the only installer
    // the deploy harness compiles. This assertion previously pinned "ShadowStrikeAV",
    // so it asserted the defect AS THE CONTRACT: the watchdog, VerifyServiceIntegrity,
    // recovery configuration and IsOwnServiceKey all resolve our identity through this
    // field, and every one of them was querying a service that does not exist. Same
    // defect class as driverServiceName below, and this assertion would put it back, so
    // it tracks the installer.
    EXPECT_EQ(defaults.mainServiceName, L"ShadowStrikePhantomService");
    // PhantomSensor, not ShadowStrikeDriver. Nothing has ever registered a service
    // called ShadowStrikeDriver: PhantomSensor.inf declares ServiceName =
    // "PhantomSensor", which is what the SCM creates, and the driver itself protects
    // its own key under ...\Services\PhantomSensor. The old name silently disabled
    // driver-presence detection (OpenServiceW failed, so IsDriverLoaded returned false
    // while the driver was loaded and filtering), driver recovery, and registry
    // protection for the driver's own service key. This assertion would put that name
    // back, so it tracks the real one.
    EXPECT_EQ(defaults.driverServiceName, L"PhantomSensor");

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
    EXPECT_FALSE(manager.GetServiceInfo(kAbsentServiceName).has_value());
    EXPECT_FALSE(manager.ServiceExists(kAbsentServiceName));
    EXPECT_EQ(manager.GetServiceState(kAbsentServiceName), ServiceState::Unknown);
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

TEST_F(ServiceManagerTest, VerifyServiceIntegrityFlagsNotInitializedAsTampering) {
    auto& manager = ServiceManager::Instance();

    const auto result = manager.VerifyServiceIntegrity(kAbsentServiceName);
    EXPECT_TRUE(result.isTampered);
    EXPECT_FALSE(result.binaryModified);
    EXPECT_FALSE(result.configModified);
    EXPECT_FALSE(result.startTypeChanged);
    EXPECT_FALSE(result.accountChanged);
    EXPECT_EQ(result.details, L"Not initialized");
}

TEST_F(ServiceManagerTest, PreInitLifecycleCallsAndInvalidCallbackIdsRemainSafe) {
    auto& manager = ServiceManager::Instance();

    EXPECT_FALSE(manager.StartService(kAbsentServiceName, {}, 1000));
    EXPECT_FALSE(manager.StopService(kAbsentServiceName, false, 1000));
    EXPECT_FALSE(manager.RestartService(kAbsentServiceName, 1000));
    EXPECT_FALSE(manager.ConfigureRecovery(
        kAbsentServiceName,
        FailureAction::Restart,
        FailureAction::None,
        FailureAction::None,
        0,
        0));

    EXPECT_NO_THROW({
        manager.UnregisterServiceChangeCallback(9999);
        manager.UnregisterTamperAlertCallback(9999);
        manager.StopWatchdog();
    });
    EXPECT_FALSE(manager.IsWatchdogRunning());
}

}  // namespace
