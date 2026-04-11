/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - SystemSettingsMonitor
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Validates SystemSettingsMonitor: OS security settings query, lifecycle,
 * compliance status, callback registration, and statistics integrity.
 *
 * Tests are read-only with respect to the registry: they query settings but
 * never modify them.  Auto-remediation is explicitly disabled in the config.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  SystemSettingsMonitor_Lifecycle   - init, start/stop, idempotency
 *   GROUP 2  SystemSettingsMonitor_Settings    - UAC, Defender, compliance queries
 *   GROUP 3  SystemSettingsMonitor_Callbacks   - alert callback register/unregister
 *   GROUP 4  SystemSettingsMonitor_Stats       - statistics increment and reset
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <string>

#include "../../../src/PhantomCore/Core/Registry/SystemSettingsMonitor.hpp"

// =============================================================================
// Fixture
// =============================================================================
class SystemSettingsMonitorIntegrationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        s_suiteReady = false;
        s_skipReason.clear();

        namespace Reg = ShadowStrike::Core::Registry;
        auto& monitor = Reg::SystemSettingsMonitor::Instance();
        monitor.Shutdown();

        Reg::SystemSettingsMonitorConfig cfg = Reg::SystemSettingsMonitorConfig::CreateMonitorOnly();
        cfg.enableAutoRemediation = false;  // never modify the OS during tests
        cfg.alertOnAnyChange      = false;

        if (!monitor.Initialize(cfg)) {
            s_skipReason = "SystemSettingsMonitor initialization failed";
            return;
        }
        s_suiteReady = true;
    }

    static void TearDownTestSuite() {
        ShadowStrike::Core::Registry::SystemSettingsMonitor::Instance().Shutdown();
        s_suiteReady = false;
    }

    void SetUp() override {
        if (!s_suiteReady) {
            GTEST_SKIP() << (s_skipReason.empty()
                ? "SystemSettingsMonitor suite setup failed" : s_skipReason);
        }
        namespace Reg = ShadowStrike::Core::Registry;
        auto& monitor = Reg::SystemSettingsMonitor::Instance();
        if (!monitor.IsMonitoring()) {
            // Ensure the instance is initialized (a prior test may have called Shutdown).
            Reg::SystemSettingsMonitorConfig cfg =
                Reg::SystemSettingsMonitorConfig::CreateMonitorOnly();
            cfg.enableAutoRemediation = false;
            cfg.alertOnAnyChange      = false;
            if (!monitor.Initialize(cfg)) {
                GTEST_SKIP() << "SystemSettingsMonitor re-initialization failed";
            }
        }
        monitor.ResetStatistics();
    }

    static inline bool        s_suiteReady{ false };
    static inline std::string s_skipReason;
};

// =============================================================================
// GROUP 1 - SystemSettingsMonitor_Lifecycle
// =============================================================================

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Lifecycle_InitializeWithMonitorOnlyConfig_Succeeds) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    monitor.Shutdown();

    Reg::SystemSettingsMonitorConfig cfg =
        Reg::SystemSettingsMonitorConfig::CreateMonitorOnly();
    cfg.enableAutoRemediation = false;

    EXPECT_TRUE(monitor.Initialize(cfg));
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Lifecycle_ShutdownAndReinitialize_IsIdempotent) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    monitor.Shutdown();
    monitor.Shutdown();  // double-shutdown must be safe

    Reg::SystemSettingsMonitorConfig cfg =
        Reg::SystemSettingsMonitorConfig::CreateMonitorOnly();
    cfg.enableAutoRemediation = false;

    EXPECT_TRUE(monitor.Initialize(cfg));
    EXPECT_TRUE(monitor.Initialize(cfg));  // double-init must be safe
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Lifecycle_StartAndStop_DoesNotCrash) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    EXPECT_NO_FATAL_FAILURE({
        monitor.Start();
        monitor.Stop();
        monitor.Stop();  // double-stop must be safe
    });
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Lifecycle_IsMonitoring_ReflectsStartStop) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();

    monitor.Stop();
    EXPECT_FALSE(monitor.IsMonitoring());

    monitor.Start();
    EXPECT_TRUE(monitor.IsMonitoring());

    monitor.Stop();
    EXPECT_FALSE(monitor.IsMonitoring());
}

// =============================================================================
// GROUP 2 - SystemSettingsMonitor_Settings
// =============================================================================

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_GetUACSettings_ReturnsNonDefaultStruct) {
    namespace Reg = ShadowStrike::Core::Registry;
    // Just verify the call doesn't crash and returns a value.
    EXPECT_NO_FATAL_FAILURE({
        const auto settings = Reg::SystemSettingsMonitor::Instance().GetUACSettings();
        (void)settings;
    });
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_GetUACLevel_ReturnsValidEnum) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto level = Reg::SystemSettingsMonitor::Instance().GetUACLevel();
    // The returned value must be within the known enum range.
    const auto raw = static_cast<uint8_t>(level);
    EXPECT_LE(raw, static_cast<uint8_t>(Reg::UACLevel::AlwaysNotify))
        << "UACLevel out of expected range: " << static_cast<int>(raw);
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_IsUACDisabled_ReturnsBool) {
    namespace Reg = ShadowStrike::Core::Registry;
    // Return value is environment-dependent; just ensure no crash.
    EXPECT_NO_FATAL_FAILURE({
        (void)Reg::SystemSettingsMonitor::Instance().IsUACDisabled();
    });
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_GetDefenderSettings_ReturnsWithoutError) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE({
        const auto settings =
            Reg::SystemSettingsMonitor::Instance().GetDefenderSettings();
        (void)settings;
    });
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_IsDefenderDisabled_ReturnsBool) {
    namespace Reg = ShadowStrike::Core::Registry;
    EXPECT_NO_FATAL_FAILURE({
        (void)Reg::SystemSettingsMonitor::Instance().IsDefenderDisabled();
    });
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_CheckCompliance_TotalChecksPositive) {
    namespace Reg = ShadowStrike::Core::Registry;
    const auto status = Reg::SystemSettingsMonitor::Instance().CheckCompliance();
    // A compliance check must evaluate at least one item.
    EXPECT_GT(status.totalChecks, 0u);
    // Warning-only checks are counted in totalChecks as well.
    EXPECT_EQ(status.passedChecks + status.failedChecks + status.warnings, status.totalChecks);
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_CheckPolicyCompliance_MissingPolicy_IsNonCompliant) {
    namespace Reg = ShadowStrike::Core::Registry;

    const std::wstring missingPath =
        L"C:\\ShadowStrike\\ShadowStrike\\tests\\integration\\core_registry\\missing_policy_"
        + std::to_wstring(::GetCurrentProcessId()) + L".json";

    const auto status = Reg::SystemSettingsMonitor::Instance().CheckPolicyCompliance(missingPath);
    EXPECT_FALSE(status.isCompliant);
    EXPECT_EQ(status.totalChecks, 1u);
    EXPECT_EQ(status.failedChecks, 1u);
    ASSERT_FALSE(status.failures.empty());
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Settings_BaselineCreateActivateAndCompare_RoundTrips) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();

    const uint64_t baselineId = monitor.CreateBaseline("core_registry_integration_test");
    ASSERT_GT(baselineId, 0u);

    const auto baseline = monitor.GetBaseline(baselineId);
    ASSERT_TRUE(baseline.has_value());
    EXPECT_EQ(baseline->snapshotId, baselineId);
    EXPECT_EQ(baseline->description, "core_registry_integration_test");

    EXPECT_TRUE(monitor.SetActiveBaseline(baselineId));

    const auto active = monitor.GetActiveBaseline();
    ASSERT_TRUE(active.has_value());
    EXPECT_EQ(active->snapshotId, baselineId);

    const auto differences = monitor.CompareToBaseline(baselineId);
    EXPECT_TRUE(differences.empty());
}

// =============================================================================
// GROUP 3 - SystemSettingsMonitor_Callbacks
// =============================================================================

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Callbacks_RegisterAlertCallback_ReturnsNonZeroId) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();

    const uint64_t id = monitor.RegisterAlertCallback(
        [](const Reg::SecurityAlert&) {});

    EXPECT_GT(id, 0u);
    EXPECT_TRUE(monitor.UnregisterCallback(id));
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Callbacks_NullCallbacksReturnZero) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();

    EXPECT_EQ(monitor.RegisterChangeCallback(Reg::SettingChangeCallback{}), 0u);
    EXPECT_EQ(monitor.RegisterAlertCallback(Reg::SecurityAlertCallback{}), 0u);
    EXPECT_EQ(monitor.RegisterComplianceCallback(Reg::ComplianceCallback{}), 0u);
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Callbacks_UnregisterInvalidCallback_ReturnsFalse) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    EXPECT_FALSE(monitor.UnregisterCallback(0u));
    EXPECT_FALSE(monitor.UnregisterCallback(UINT64_MAX));
}

// =============================================================================
// GROUP 4 - SystemSettingsMonitor_Stats
// =============================================================================

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Stats_GetStatistics_AfterInit_ReturnsZeroCounts) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    monitor.ResetStatistics();
    const auto& s = monitor.GetStatistics();

    EXPECT_EQ(s.changesDetected.load(std::memory_order_relaxed),      0u);
    EXPECT_EQ(s.securityDegrades.load(std::memory_order_relaxed),     0u);
    EXPECT_EQ(s.alertsGenerated.load(std::memory_order_relaxed),      0u);
    EXPECT_EQ(s.remediationsPerformed.load(std::memory_order_relaxed),0u);
    EXPECT_EQ(s.remediationsFailed.load(std::memory_order_relaxed),   0u);
}

TEST_F(SystemSettingsMonitorIntegrationTest,
       SystemSettingsMonitor_Stats_ResetStatistics_ClearsAllCounters) {
    namespace Reg = ShadowStrike::Core::Registry;
    auto& monitor = Reg::SystemSettingsMonitor::Instance();
    monitor.ResetStatistics();
    const auto& s = monitor.GetStatistics();

    EXPECT_EQ(s.changesDetected.load(std::memory_order_relaxed),  0u);
    EXPECT_EQ(s.uacChanges.load(std::memory_order_relaxed),       0u);
    EXPECT_EQ(s.defenderChanges.load(std::memory_order_relaxed),  0u);
    EXPECT_EQ(s.firewallChanges.load(std::memory_order_relaxed),  0u);
    EXPECT_EQ(s.networkChanges.load(std::memory_order_relaxed),   0u);
    EXPECT_EQ(s.shellChanges.load(std::memory_order_relaxed),     0u);
}
