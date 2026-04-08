/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Unit coverage for NetworkPerformanceMonitor.cpp.
 *
 * Coverage focus:
 * - configuration and helper-total validation
 * - JSON serialization for alerts and telemetry snapshots
 * - safe singleton defaults before live network samples exist
 * - callback registration/reset behavior and explicit self-test surface
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <limits>
#include <string>

#include "../../../src/Shared_modules/Performance/NetworkPerformanceMonitor.hpp"

namespace SSP = ShadowStrike::Performance;

namespace ShadowStrike::Performance::Test {
namespace {

class NetworkPerformanceMonitorTest : public ::testing::Test {
protected:
    NetworkPerformanceMonitor& monitor = NetworkPerformanceMonitor::Instance();

    void SetUp() override {
        monitor.ClearAlertCallbacks();
        monitor.Shutdown();
    }

    void TearDown() override {
        monitor.ClearAlertCallbacks();
        monitor.Shutdown();
    }
};

TEST_F(NetworkPerformanceMonitorTest, ConfigValidationAndHelperTotalsRejectInvalidBoundaries) {
    SSP::NetworkMonitorConfig config;
    EXPECT_TRUE(config.IsValid());

    config.pollingIntervalMs = SSP::NetworkConstants::MIN_POLLING_INTERVAL_MS;
    EXPECT_TRUE(config.IsValid());
    config.pollingIntervalMs = SSP::NetworkConstants::MAX_POLLING_INTERVAL_MS;
    EXPECT_TRUE(config.IsValid());
    config.pollingIntervalMs = 99;
    EXPECT_FALSE(config.IsValid());
    config.pollingIntervalMs = SSP::NetworkConstants::DEFAULT_POLLING_INTERVAL_MS;

    config.highBandwidthThresholdMbps = std::numeric_limits<double>::quiet_NaN();
    EXPECT_FALSE(config.IsValid());
    config.highBandwidthThresholdMbps = 25.0;
    config.highBandwidthThresholdMbps = 0.0;
    EXPECT_FALSE(config.IsValid());
    config.highBandwidthThresholdMbps = 25.0;

    config.connectionFloodThreshold = 0;
    EXPECT_FALSE(config.IsValid());
    config.connectionFloodThreshold = 100;

    config.exfiltrationThresholdBytes = 1;
    EXPECT_TRUE(config.IsValid());
    config.exfiltrationThresholdBytes = 0;
    EXPECT_FALSE(config.IsValid());
    config.exfiltrationThresholdBytes = 1024;

    const SSP::ProcessNetworkUsage usage{
        15,
        L"netwatch",
        2,
        3,
        4,
        5,
        6,
        7,
        false,
        true,
        false
    };
    EXPECT_EQ(usage.TotalConnections(), 14u);

    const SSP::NetworkGlobalStats stats{
        1.0,
        2.0,
        10,
        20,
        30,
        40,
        2,
        3,
        4,
        5,
        {}
    };
    EXPECT_EQ(stats.TotalTcpConnections(), 30u);
    EXPECT_EQ(stats.TotalUdpListeners(), 70u);
}

TEST_F(NetworkPerformanceMonitorTest, SerializationProducesExpectedJsonShapes) {
    SSP::NetworkAlert alert;
    alert.type = SSP::NetworkAlertType::DataExfiltration;
    alert.severity = SSP::NetworkAlertSeverity::Critical;
    alert.processId = 501;
    alert.processName = L"net\"agent\nproc";
    alert.remoteAddress = "10.0.0.5";
    alert.remotePort = 443;
    alert.details = "line1\nline2";
    const std::string alertJson = alert.ToJson();
    EXPECT_NE(alertJson.find("\"type\":3"), std::string::npos);
    EXPECT_NE(alertJson.find("\"severity\":3"), std::string::npos);
    EXPECT_NE(alertJson.find("net\\\"agent\\nproc"), std::string::npos);
    EXPECT_NE(alertJson.find("\"remoteAddress\":\"10.0.0.5\""), std::string::npos);
    EXPECT_NE(alertJson.find("line1\\nline2"), std::string::npos);

    const SSP::NetworkInterfaceStats iface{
        "Ethernet0",
        "Corp \"LAN\"",
        "AA:BB:CC:DD:EE:FF",
        7,
        100.0,
        50.0,
        10.0,
        5.0,
        1000,
        2000,
        3000,
        4000,
        1,
        2,
        3,
        4,
        0.5,
        0.25,
        0.75,
        0.5,
        true,
        1'000'000'000ULL
    };
    const std::string ifaceJson = iface.ToJson();
    EXPECT_NE(ifaceJson.find("\"interfaceName\":\"Ethernet0\""), std::string::npos);
    EXPECT_NE(ifaceJson.find("Corp \\\"LAN\\\""), std::string::npos);
    EXPECT_NE(ifaceJson.find("\"isUp\":true"), std::string::npos);

    const SSP::ProcessNetworkUsage processUsage{
        88,
        L"browser",
        1,
        2,
        3,
        4,
        5,
        6,
        true,
        false,
        true
    };
    const std::string processJson = processUsage.ToJson();
    EXPECT_NE(processJson.find("\"processId\":88"), std::string::npos);
    EXPECT_NE(processJson.find("\"suspectedBeaconing\":true"), std::string::npos);
    EXPECT_NE(processJson.find("\"suspectedFlood\":true"), std::string::npos);

    SSP::NetworkGlobalStats globalStats;
    globalStats.totalInboundBitsPerSec = 12.0;
    globalStats.totalOutboundBitsPerSec = 34.0;
    globalStats.totalTcpConnectionsV4 = 5;
    globalStats.totalTcpConnectionsV6 = 6;
    globalStats.totalUdpListenersV4 = 7;
    globalStats.totalUdpListenersV6 = 8;
    globalStats.activeInterfaces = 2;
    globalStats.totalErrorsIn = 9;
    globalStats.totalErrorsOut = 10;
    const std::string globalJson = globalStats.ToJson();
    EXPECT_NE(globalJson.find("\"totalInboundBitsPerSec\":12"), std::string::npos);
    EXPECT_NE(globalJson.find("\"activeInterfaces\":2"), std::string::npos);

    const SSP::NetworkMonitorModuleStats moduleStats{1, 2, 3, 4, 5, 6};
    const std::string moduleJson = moduleStats.ToJson();
    EXPECT_NE(moduleJson.find("\"cyclesCompleted\":1"), std::string::npos);
    EXPECT_NE(moduleJson.find("\"uptimeSeconds\":6"), std::string::npos);
}

TEST_F(NetworkPerformanceMonitorTest, LifecycleAndConfigurationUpdatesRespectValidation) {
    SSP::NetworkMonitorConfig invalidConfig;
    invalidConfig.connectionFloodThreshold = 0;
    EXPECT_FALSE(monitor.Initialize(invalidConfig));
    EXPECT_FALSE(monitor.IsInitialized());

    SSP::NetworkMonitorConfig validConfig;
    validConfig.enabled = false;
    validConfig.pollingIntervalMs = 700;
    validConfig.trackPerProcess = false;
    validConfig.trackInterfaces = false;
    validConfig.highBandwidthThresholdMbps = 55.0;
    ASSERT_TRUE(monitor.Initialize(validConfig));
    EXPECT_TRUE(monitor.IsInitialized());

    const SSP::NetworkMonitorConfig initialized = monitor.GetConfig();
    EXPECT_EQ(initialized.pollingIntervalMs, 700u);
    EXPECT_FALSE(initialized.trackPerProcess);
    EXPECT_FALSE(initialized.trackInterfaces);

    SSP::NetworkMonitorConfig invalidUpdate = validConfig;
    invalidUpdate.exfiltrationThresholdBytes = 0;
    monitor.UpdateConfig(invalidUpdate);
    EXPECT_EQ(monitor.GetConfig().pollingIntervalMs, validConfig.pollingIntervalMs);

    SSP::NetworkMonitorConfig validUpdate = validConfig;
    validUpdate.pollingIntervalMs = 1800;
    validUpdate.trackInterfaces = true;
    monitor.UpdateConfig(validUpdate);

    const SSP::NetworkMonitorConfig updated = monitor.GetConfig();
    EXPECT_EQ(updated.pollingIntervalMs, 1800u);
    EXPECT_TRUE(updated.trackInterfaces);
}

TEST_F(NetworkPerformanceMonitorTest, AccessorsReturnSafeDefaultsWithoutPublishedSamples) {
    SSP::NetworkMonitorConfig config;
    config.enabled = false;
    ASSERT_TRUE(monitor.Initialize(config));

    const SSP::NetworkGlobalStats stats = monitor.GetGlobalStats();
    EXPECT_DOUBLE_EQ(stats.totalInboundBitsPerSec, 0.0);
    EXPECT_DOUBLE_EQ(stats.totalOutboundBitsPerSec, 0.0);
    EXPECT_EQ(stats.activeInterfaces, 0u);

    EXPECT_TRUE(monitor.GetInterfaceStats().empty());
    EXPECT_TRUE(monitor.GetTopProcesses(0).empty());
    EXPECT_TRUE(monitor.GetTopProcesses(5).empty());
    EXPECT_FALSE(monitor.GetProcessUsage(0xFFFFFFFFu).has_value());
    EXPECT_TRUE(monitor.GetRecentAlerts(0).empty());
    EXPECT_TRUE(monitor.GetRecentAlerts(10).empty());

    const SSP::NetworkMonitorModuleStats moduleStats = monitor.GetModuleStats();
    EXPECT_EQ(moduleStats.cyclesCompleted, 0u);
    EXPECT_EQ(moduleStats.alertsTriggered, 0u);
    EXPECT_EQ(moduleStats.totalConnectionsTracked, 0u);
    EXPECT_EQ(NetworkPerformanceMonitor::GetVersionString(), "4.0.0");
}

TEST_F(NetworkPerformanceMonitorTest, PreInitReinitAndShutdownTransitionsStaySafe) {
    EXPECT_FALSE(monitor.IsInitialized());
    EXPECT_FALSE(monitor.SelfTest());

    SSP::NetworkMonitorConfig firstConfig;
    firstConfig.enabled = false;
    firstConfig.pollingIntervalMs = 750;
    firstConfig.trackPerProcess = false;
    firstConfig.trackInterfaces = false;
    ASSERT_TRUE(monitor.Initialize(firstConfig));
    EXPECT_TRUE(monitor.IsInitialized());

    SSP::NetworkMonitorConfig secondConfig = firstConfig;
    secondConfig.pollingIntervalMs = 1800;
    secondConfig.trackInterfaces = true;
    ASSERT_TRUE(monitor.Initialize(secondConfig));

    const SSP::NetworkMonitorConfig persisted = monitor.GetConfig();
    EXPECT_EQ(persisted.pollingIntervalMs, firstConfig.pollingIntervalMs);
    EXPECT_FALSE(persisted.trackInterfaces);
    EXPECT_FALSE(persisted.trackPerProcess);

    monitor.Shutdown();
    EXPECT_FALSE(monitor.IsInitialized());
    monitor.Shutdown();

    const SSP::NetworkGlobalStats stats = monitor.GetGlobalStats();
    EXPECT_DOUBLE_EQ(stats.totalInboundBitsPerSec, 0.0);
    EXPECT_DOUBLE_EQ(stats.totalOutboundBitsPerSec, 0.0);
    EXPECT_EQ(stats.activeInterfaces, 0u);
    EXPECT_TRUE(monitor.GetInterfaceStats().empty());
    EXPECT_TRUE(monitor.GetTopProcesses(1).empty());
    EXPECT_TRUE(monitor.GetRecentAlerts(1).empty());
    EXPECT_FALSE(monitor.GetProcessUsage(::GetCurrentProcessId()).has_value());
}

TEST_F(NetworkPerformanceMonitorTest, AlertCallbackRegistrationAndResetAreSafeWithoutLiveAlerts) {
    monitor.RegisterAlertCallback({});
    monitor.RegisterAlertCallback([](const SSP::NetworkAlert&) {});
    monitor.ClearAlertCallbacks();
    monitor.ClearAlertCallbacks();
}

TEST_F(NetworkPerformanceMonitorTest, SelfTestPassesAfterInitialization) {
    SSP::NetworkMonitorConfig config;
    config.enabled = false;
    ASSERT_TRUE(monitor.Initialize(config));
    EXPECT_TRUE(monitor.SelfTest());
}

}  // namespace
}  // namespace ShadowStrike::Performance::Test
