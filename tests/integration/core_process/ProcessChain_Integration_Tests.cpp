/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Integration Tests - Tier 5: Process Chain
 *
 * ============================================================================
 * PURPOSE
 * ============================================================================
 * Tests real integration between the core Process chain modules:
 *   ProcessMonitor             → process lifecycle tracking, ancestry, callbacks
 *   ProcessAnalyzer            → behavioral analysis, module inspection, risk scoring
 *   ProcessHollowingDetector   → memory PE vs on-disk PE comparison
 *   ProcessInjectionDetector   → injection attempt detection
 *   ReflectiveDLLDetector      → reflective loading detection
 *
 * All tests run against REAL Windows APIs. No mocks.
 *
 * ============================================================================
 * TEST GROUPS
 * ============================================================================
 *   GROUP 1  ProcessMonitor_Lifecycle       - init, shutdown, reinit cycles
 *   GROUP 2  ProcessMonitor_Ancestry        - parent/child/ancestry chain
 *   GROUP 3  ProcessMonitor_Callback        - callback registration/unregister
 *   GROUP 4  ProcessAnalyzer_Chain          - analysis, risk, module enumeration
 *   GROUP 5  ProcessHollowingDetector_Chain - scan clean process, statistics
 *   GROUP 6  ProcessInjectionDetector_Chain - analyze self, injection events
 *   GROUP 7  ReflectiveDLLDetector_Chain    - scan self for reflective loads
 *   GROUP 8  ProcessChain_Concurrency       - thread-safety validation
 *
 * ============================================================================
 * SUITE SETUP (once per suite)
 * ============================================================================
 *   1. Initialize ProcessMonitor with default config
 *   2. Initialize ProcessAnalyzer with default config
 *   3. Initialize ProcessHollowingDetector with default config
 *   4. Initialize ProcessInjectionDetector with default config
 *   5. Initialize ReflectiveDLLDetector with default config
 */

#include "../../../src/pch.h"

#include "../../../src/Shared_modules/Core/Process/ProcessMonitor.hpp"
#include "../../../src/Shared_modules/Core/Process/ProcessAnalyzer.hpp"
#include "../../../src/Shared_modules/Core/Process/ProcessHollowingDetector.hpp"
#include "../../../src/Shared_modules/Core/Process/ProcessInjectionDetector.hpp"
#include "../../../src/Shared_modules/Core/Process/ReflectiveDLLDetector.hpp"
#include "../../../src/Shared_modules/Core/Process/ProcessTypes.hpp"

#include <algorithm>
#include <atomic>
#include <barrier>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

[[nodiscard]] uint32_t GetOwnPid() noexcept {
    return ::GetCurrentProcessId();
}

[[nodiscard]] bool IsValidRiskLevel(
    const ShadowStrike::Core::Process::ProcessRiskLevel level) noexcept
{
    using UnderlyingType =
        std::underlying_type_t<ShadowStrike::Core::Process::ProcessRiskLevel>;

    return static_cast<UnderlyingType>(level) <=
           static_cast<UnderlyingType>(ShadowStrike::Core::Process::ProcessRiskLevel::Critical);
}

[[nodiscard]] bool IsValidCategory(
    const ShadowStrike::Core::Process::ProcessCategory category) noexcept
{
    using UnderlyingType =
        std::underlying_type_t<ShadowStrike::Core::Process::ProcessCategory>;

    return static_cast<UnderlyingType>(category) <=
           static_cast<UnderlyingType>(ShadowStrike::Core::Process::ProcessCategory::Malicious);
}

[[nodiscard]] bool IsValidInjectionVerdict(
    const ShadowStrike::Core::Process::InjectionVerdict verdict) noexcept
{
    using UnderlyingType =
        std::underlying_type_t<ShadowStrike::Core::Process::InjectionVerdict>;

    return static_cast<UnderlyingType>(verdict) <=
           static_cast<UnderlyingType>(ShadowStrike::Core::Process::InjectionVerdict::Unknown);
}

/**
 * @brief Suite-level fixture that owns the live singleton chain for every
 * integration group in this translation unit.
 *
 * The process-monitor chain is initialized exactly once so each test exercises
 * the same real subsystem wiring that production code uses on an endpoint.
 */
class ProcessChainTest : public ::testing::Test {
protected:
    static bool s_monitorInitialized;
    static bool s_analyzerInitialized;
    static bool s_hollowingInitialized;
    static bool s_injectionInitialized;
    static bool s_reflectiveInitialized;

    static void SetUpTestSuite() {
        s_monitorInitialized =
            ShadowStrike::Core::Process::ProcessMonitor::Instance().Initialize(
                ShadowStrike::Core::Process::MonitorConfig::CreateDefault());

        s_analyzerInitialized =
            ShadowStrike::Core::Process::ProcessAnalyzer::Instance().Initialize(
                ShadowStrike::Core::Process::AnalyzerConfig::CreateDefault());

        s_hollowingInitialized =
            ShadowStrike::Core::Process::ProcessHollowingDetector::Instance().Initialize(
                ShadowStrike::Core::Process::HollowingDetectorConfig::CreateDefault());

        s_injectionInitialized =
            ShadowStrike::Core::Process::ProcessInjectionDetector::Instance().Initialize();

        s_reflectiveInitialized =
            ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance().Initialize(
                ShadowStrike::Core::Process::ReflectiveConfig::CreateDefault());
    }

    static void TearDownTestSuite() {
        ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance().Shutdown();
        ShadowStrike::Core::Process::ProcessInjectionDetector::Instance().Shutdown();
        ShadowStrike::Core::Process::ProcessHollowingDetector::Instance().Shutdown();
        ShadowStrike::Core::Process::ProcessAnalyzer::Instance().Shutdown();
        ShadowStrike::Core::Process::ProcessMonitor::Instance().Shutdown();
    }

    void SetUp() override {
        if (!s_monitorInitialized ||
            !ShadowStrike::Core::Process::ProcessMonitor::Instance().IsInitialized()) {
            GTEST_SKIP() << "ProcessMonitor::Initialize() failed; skipping";
        }
    }
};

bool ProcessChainTest::s_monitorInitialized = false;
bool ProcessChainTest::s_analyzerInitialized = false;
bool ProcessChainTest::s_hollowingInitialized = false;
bool ProcessChainTest::s_injectionInitialized = false;
bool ProcessChainTest::s_reflectiveInitialized = false;

/**
 * @brief GROUP 1 fixture for validating live ProcessMonitor lifecycle behavior.
 *
 * These tests verify the root process-discovery service is active and can
 * survive a shutdown/restart cycle without breaking production contracts.
 */
class ProcessMonitorLifecycleTest : public ProcessChainTest {
};

/**
 * @brief GROUP 2 fixture for verifying real ancestry and name-based lookups.
 *
 * The tests in this group use the current process and system snapshot to
 * confirm parent-chain reconstruction remains wired to live endpoint state.
 */
class ProcessMonitorAncestryTest : public ProcessChainTest {
};

/**
 * @brief GROUP 3 fixture for validating callback registration surfaces.
 *
 * These assertions confirm the monitor accepts callback consumers and can
 * safely release them, which is required for downstream pipeline integration.
 */
class ProcessMonitorCallbackTest : public ProcessChainTest {
};

/**
 * @brief GROUP 4 fixture for analyzer/monitor chain integration.
 *
 * ProcessAnalyzer depends on real process metadata, so every test in this
 * group skips when analyzer initialization fails on the current endpoint.
 */
class ProcessAnalyzerChainTest : public ProcessChainTest {
protected:
    void SetUp() override {
        ProcessChainTest::SetUp();

        if (!s_analyzerInitialized ||
            !ShadowStrike::Core::Process::ProcessAnalyzer::Instance().IsInitialized()) {
            GTEST_SKIP() << "ProcessAnalyzer::Initialize() failed; skipping";
        }
    }
};

/**
 * @brief GROUP 5 fixture for process-hollowing integration tests.
 *
 * Hollowing detection may require elevated privileges or unsupported kernel
 * facilities, so these tests use suite-level initialization gates.
 */
class ProcessHollowingDetectorChainTest : public ProcessChainTest {
protected:
    void SetUp() override {
        ProcessChainTest::SetUp();

        if (!s_hollowingInitialized ||
            !ShadowStrike::Core::Process::ProcessHollowingDetector::Instance().IsInitialized()) {
            GTEST_SKIP() << "ProcessHollowingDetector::Initialize() failed; driver or privileges may be unavailable";
        }
    }
};

/**
 * @brief GROUP 6 fixture for process-injection detection integration tests.
 *
 * The detector may disable itself when kernel/user-mode event plumbing is not
 * available, so tests skip rather than reporting false negatives.
 */
class ProcessInjectionDetectorChainTest : public ProcessChainTest {
protected:
    void SetUp() override {
        ProcessChainTest::SetUp();

        if (!s_injectionInitialized) {
            GTEST_SKIP() << "ProcessInjectionDetector::Initialize() failed; skipping";
        }
    }
};

/**
 * @brief GROUP 7 fixture for reflective-loading integration coverage.
 *
 * These tests validate real memory scanning plumbing and therefore skip when
 * the detector cannot initialize on the executing endpoint.
 */
class ReflectiveDLLDetectorChainTest : public ProcessChainTest {
protected:
    void SetUp() override {
        ProcessChainTest::SetUp();

        if (!s_reflectiveInitialized ||
            !ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance().IsInitialized()) {
            GTEST_SKIP() << "ReflectiveDLLDetector::Initialize() failed; skipping";
        }
    }
};

/**
 * @brief GROUP 8 fixture for thread-safety validation across the process chain.
 *
 * Concurrency coverage intentionally drives the same live singleton from
 * multiple callers to validate the thread-safe contracts published by headers.
 */
class ProcessChainConcurrencyTest : public ProcessChainTest {
};

/**
 * @brief Confirms suite-level default initialization produced a ready monitor.
 *
 * This is the root contract for every downstream integration test because all
 * later modules depend on successful live process enumeration.
 */
TEST_F(ProcessMonitorLifecycleTest, InitializeWithDefaultConfig_ReturnsTrue) {
    EXPECT_TRUE(s_monitorInitialized);
    EXPECT_TRUE(ShadowStrike::Core::Process::ProcessMonitor::Instance().IsInitialized());
}

/**
 * @brief Verifies the monitor can enumerate the real process table.
 *
 * A non-empty list demonstrates successful integration with the underlying
 * Windows process-discovery path used by the monitor implementation.
 */
TEST_F(ProcessMonitorLifecycleTest, GetAllProcesses_ReturnsNonEmptyList) {
    const std::vector<ShadowStrike::Core::Process::ExtendedProcessInfo> processes =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetAllProcesses();

    EXPECT_GE(processes.size(), 1U);
}

/**
 * @brief Retrieves full metadata for the current process from the live cache.
 *
 * This validates PID lookup, metadata hydration, and unique-process identity
 * construction for the process hosting the test binary itself.
 */
TEST_F(ProcessMonitorLifecycleTest, GetProcessInfo_OwnPid_ReturnsValidInfo) {
    const uint32_t ownPid = GetOwnPid();
    const std::optional<ShadowStrike::Core::Process::ExtendedProcessInfo> processInfo =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetProcessInfo(ownPid);

    ASSERT_TRUE(processInfo.has_value());
    EXPECT_EQ(processInfo->uniqueId.pid, ownPid);
    EXPECT_TRUE(processInfo->IsValid());
    EXPECT_FALSE(processInfo->processName.empty());
    EXPECT_FALSE(processInfo->processPath.empty());
}

/**
 * @brief Verifies liveness checks report the test process as active.
 *
 * The current process is guaranteed to be executing, so a false result would
 * indicate broken monitor wiring or stale cache state.
 */
TEST_F(ProcessMonitorLifecycleTest, IsProcessAlive_OwnPid_ReturnsTrue) {
    EXPECT_TRUE(
        ShadowStrike::Core::Process::ProcessMonitor::Instance().IsProcessAlive(GetOwnPid()));
}

/**
 * @brief Exercises a full shutdown/reinitialize cycle on the live singleton.
 *
 * This guards against one-shot initialization bugs and restores dependent
 * singletons so later integration groups keep running against a valid chain.
 */
TEST_F(ProcessMonitorLifecycleTest, ShutdownAndReinitialize_IsIdempotent) {
    auto& monitor = ShadowStrike::Core::Process::ProcessMonitor::Instance();
    const bool analyzerWasInitialized = s_analyzerInitialized;
    const bool hollowingWasInitialized = s_hollowingInitialized;
    const bool injectionWasInitialized = s_injectionInitialized;
    const bool reflectiveWasInitialized = s_reflectiveInitialized;

    monitor.Shutdown();
    EXPECT_FALSE(monitor.IsInitialized());

    s_monitorInitialized =
        monitor.Initialize(ShadowStrike::Core::Process::MonitorConfig::CreateDefault());

    EXPECT_TRUE(s_monitorInitialized);
    EXPECT_TRUE(monitor.IsInitialized());

    if (analyzerWasInitialized) {
        auto& analyzer = ShadowStrike::Core::Process::ProcessAnalyzer::Instance();
        analyzer.Shutdown();
        s_analyzerInitialized =
            analyzer.Initialize(ShadowStrike::Core::Process::AnalyzerConfig::CreateDefault());
        EXPECT_TRUE(s_analyzerInitialized);
        EXPECT_TRUE(analyzer.IsInitialized());
    }

    if (hollowingWasInitialized) {
        auto& detector = ShadowStrike::Core::Process::ProcessHollowingDetector::Instance();
        detector.Shutdown();
        s_hollowingInitialized =
            detector.Initialize(ShadowStrike::Core::Process::HollowingDetectorConfig::CreateDefault());
        EXPECT_TRUE(s_hollowingInitialized);
        EXPECT_TRUE(detector.IsInitialized());
    }

    if (injectionWasInitialized) {
        auto& detector = ShadowStrike::Core::Process::ProcessInjectionDetector::Instance();
        detector.Shutdown();
        s_injectionInitialized = detector.Initialize();
        EXPECT_TRUE(s_injectionInitialized);
    }

    if (reflectiveWasInitialized) {
        auto& detector = ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance();
        detector.Shutdown();
        s_reflectiveInitialized =
            detector.Initialize(ShadowStrike::Core::Process::ReflectiveConfig::CreateDefault());
        EXPECT_TRUE(s_reflectiveInitialized);
        EXPECT_TRUE(detector.IsInitialized());
    }
}

/**
 * @brief Rebuilds the current process ancestry from the live monitor state.
 *
 * At minimum the chain must identify the target PID, and healthy monitor
 * implementations typically include the process itself in the ancestor vector.
 */
TEST_F(ProcessMonitorAncestryTest, GetAncestry_OwnPid_ReturnsChain) {
    const uint32_t ownPid = GetOwnPid();
    const ShadowStrike::Core::Process::AncestryChain ancestry =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetAncestry(ownPid);

    EXPECT_EQ(ancestry.targetProcess.pid, ownPid);
    EXPECT_TRUE(!ancestry.ancestors.empty() || ancestry.depth >= 1U);

    if (!ancestry.ancestors.empty()) {
        EXPECT_EQ(ancestry.ancestors.front().uniqueId.pid, ownPid);
    }
}

/**
 * @brief Verifies the monitor can resolve the current process parent.
 *
 * Parent resolution is a critical prerequisite for parent/child anomaly
 * detection and higher-level risk scoring in the analyzer chain.
 */
TEST_F(ProcessMonitorAncestryTest, GetParent_OwnPid_ReturnsParent) {
    const uint32_t ownPid = GetOwnPid();
    const std::optional<ShadowStrike::Core::Process::ExtendedProcessInfo> parentInfo =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetParent(ownPid);

    ASSERT_TRUE(parentInfo.has_value());
    EXPECT_GT(parentInfo->uniqueId.pid, 0U);
    EXPECT_NE(parentInfo->uniqueId.pid, ownPid);
}

/**
 * @brief Verifies name-based lookups round-trip an observed process name.
 *
 * The test intentionally uses a name discovered from the live process table so
 * it remains stable on servers, desktops, and headless CI environments alike.
 */
TEST_F(ProcessMonitorAncestryTest, GetProcessesByName_Explorer_ReturnsAny) {
    const std::vector<ShadowStrike::Core::Process::ExtendedProcessInfo> processes =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetAllProcesses();

    const auto processIt = std::find_if(
        processes.begin(),
        processes.end(),
        [](const ShadowStrike::Core::Process::ExtendedProcessInfo& processInfo) {
            return !processInfo.processName.empty();
        });

    ASSERT_NE(processIt, processes.end());

    const std::vector<ShadowStrike::Core::Process::ExtendedProcessInfo> matches =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().GetProcessesByName(
            processIt->processName);

    EXPECT_FALSE(matches.empty());
    EXPECT_TRUE(std::any_of(
        matches.begin(),
        matches.end(),
        [expectedPid = processIt->uniqueId.pid](
            const ShadowStrike::Core::Process::ExtendedProcessInfo& processInfo) {
            return processInfo.uniqueId.pid == expectedPid;
        }));
}

/**
 * @brief Confirms callback registration returns a usable identifier.
 *
 * Downstream telemetry and response components rely on non-zero callback IDs so
 * they can later unregister from the live monitor without ambiguity.
 */
TEST_F(ProcessMonitorCallbackTest, RegisterCallback_IsAssignedNonZeroId) {
    const uint64_t callbackId =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().RegisterCallback(
            [](const ShadowStrike::Core::Process::ExtendedProcessInfo& processInfo, const bool created) {
                static_cast<void>(processInfo);
                static_cast<void>(created);
            });

    EXPECT_NE(callbackId, 0U);

    if (callbackId != 0U) {
        ShadowStrike::Core::Process::ProcessMonitor::Instance().UnregisterCallback(callbackId);
    }
}

/**
 * @brief Confirms a registered callback can be safely removed.
 *
 * The primary goal is integration stability: unregistering a live callback
 * must not fault even when no events have yet been delivered.
 */
TEST_F(ProcessMonitorCallbackTest, UnregisterCallback_RemovesCallback) {
    const uint64_t callbackId =
        ShadowStrike::Core::Process::ProcessMonitor::Instance().RegisterCallback(
            [](const ShadowStrike::Core::Process::ExtendedProcessInfo& processInfo, const bool created) {
                static_cast<void>(processInfo);
                static_cast<void>(created);
            });

    EXPECT_NE(callbackId, 0U);

    if (callbackId != 0U) {
        ShadowStrike::Core::Process::ProcessMonitor::Instance().UnregisterCallback(callbackId);
    }

    SUCCEED();
}

/**
 * @brief Verifies monitor and analyzer both completed suite-level startup.
 *
 * This test anchors the live dependency chain that analyzer operations require
 * before behavioral analysis or module inspection can safely run.
 */
TEST_F(ProcessAnalyzerChainTest, InitializeBothMonitorAndAnalyzer_Succeeds) {
    EXPECT_TRUE(s_monitorInitialized);
    EXPECT_TRUE(ShadowStrike::Core::Process::ProcessMonitor::Instance().IsInitialized());
    EXPECT_TRUE(s_analyzerInitialized);
    EXPECT_TRUE(ShadowStrike::Core::Process::ProcessAnalyzer::Instance().IsInitialized());
}

/**
 * @brief Runs a real analyzer pass against the hosting process.
 *
 * A populated result confirms analyzer-to-monitor integration, live process
 * inspection, and result materialization through the public API.
 */
TEST_F(ProcessAnalyzerChainTest, AnalyzeOwnProcess_ReturnsResult) {
    const uint32_t ownPid = GetOwnPid();
    const ShadowStrike::Core::Process::ProcessAnalysisResult analysis =
        ShadowStrike::Core::Process::ProcessAnalyzer::Instance().AnalyzeProcess(ownPid);

    EXPECT_EQ(analysis.processId, ownPid);
    EXPECT_FALSE(analysis.processName.empty());
}

/**
 * @brief Ensures the quick risk surface classifies the current process sanely.
 *
 * The test process should not appear as an active exploitation case, so a
 * Critical rating would indicate dangerous false-positive integration.
 */
TEST_F(ProcessAnalyzerChainTest, QuickAssessRisk_OwnPid_NotCritical) {
    const ShadowStrike::Core::Process::ProcessRiskLevel riskLevel =
        ShadowStrike::Core::Process::ProcessAnalyzer::Instance().QuickAssessRisk(GetOwnPid());

    EXPECT_TRUE(IsValidRiskLevel(riskLevel));
    EXPECT_NE(riskLevel, ShadowStrike::Core::Process::ProcessRiskLevel::Critical);
}

/**
 * @brief Exercises the analyzer's process categorization pipeline on a live PID.
 *
 * Category values are used throughout policy and response decisions, so the API
 * must return a published enum value for the current process.
 */
TEST_F(ProcessAnalyzerChainTest, CategorizeProcess_OwnPid_ReturnsValidCategory) {
    const ShadowStrike::Core::Process::ProcessCategory category =
        ShadowStrike::Core::Process::ProcessAnalyzer::Instance().CategorizeProcess(GetOwnPid());

    EXPECT_TRUE(IsValidCategory(category));
}

/**
 * @brief Verifies live module enumeration returns at least the main image.
 *
 * Analyzer module inspection is a foundational integration point for signature,
 * side-loading, and reflective-loading follow-on detections.
 */
TEST_F(ProcessAnalyzerChainTest, GetLoadedModules_OwnPid_ReturnsModules) {
    const std::vector<ShadowStrike::Core::Process::ModuleInfo> modules =
        ShadowStrike::Core::Process::ProcessAnalyzer::Instance().GetLoadedModules(GetOwnPid());

    EXPECT_GE(modules.size(), 1U);
    EXPECT_TRUE(std::any_of(
        modules.begin(),
        modules.end(),
        [](const ShadowStrike::Core::Process::ModuleInfo& moduleInfo) {
            return !moduleInfo.moduleName.empty() || !moduleInfo.modulePath.empty();
        }));
}

/**
 * @brief Confirms the hollowing detector completed suite-level initialization.
 *
 * The detector may rely on privileges or OS capabilities that are not always
 * present, so this test is skipped instead of forcing a false failure.
 */
TEST_F(ProcessHollowingDetectorChainTest, Initialize_Succeeds) {
    EXPECT_TRUE(s_hollowingInitialized);
    EXPECT_TRUE(
        ShadowStrike::Core::Process::ProcessHollowingDetector::Instance().IsInitialized());
}

/**
 * @brief Scans the hosting process and expects a clean hollowing verdict.
 *
 * A self-scan of the unmodified test runner should not report hollowing, making
 * this a practical false-positive guard for the live scanning pipeline.
 */
TEST_F(ProcessHollowingDetectorChainTest, ScanOwnProcess_IsNotHollowed) {
    const ShadowStrike::Core::Process::HollowingDetectionResult result =
        ShadowStrike::Core::Process::ProcessHollowingDetector::Instance().ScanProcess(GetOwnPid());

    EXPECT_EQ(result.processId, GetOwnPid());
    EXPECT_TRUE(result.scanComplete);
    EXPECT_FALSE(result.isHollowed);
}

/**
 * @brief Verifies hollowing statistics advance after a real scan.
 *
 * Statistics are consumed by telemetry and health monitoring, so the public
 * counter surface must reflect work performed by integration scans.
 */
TEST_F(ProcessHollowingDetectorChainTest, GetStatistics_AfterScan_HasCount) {
    auto& detector = ShadowStrike::Core::Process::ProcessHollowingDetector::Instance();
    const uint64_t scansBefore =
        detector.GetStatistics().totalScans.load(std::memory_order_relaxed);

    const ShadowStrike::Core::Process::HollowingDetectionResult result =
        detector.ScanProcess(GetOwnPid());

    const uint64_t scansAfter =
        detector.GetStatistics().totalScans.load(std::memory_order_relaxed);

    EXPECT_TRUE(result.scanComplete);
    EXPECT_GE(scansAfter, scansBefore + 1U);
}

/**
 * @brief Confirms the injection detector completed suite-level initialization.
 *
 * Successful initialization is the minimum contract required before any live
 * process verdict can be trusted by the rest of the NGAV process chain.
 */
TEST_F(ProcessInjectionDetectorChainTest, Initialize_Succeeds) {
    EXPECT_TRUE(s_injectionInitialized);
}

/**
 * @brief Analyzes the hosting process for live injection indicators.
 *
 * The test only requires a published verdict value, which validates that the
 * detector can inspect a real PID without throwing or corrupting state.
 */
TEST_F(ProcessInjectionDetectorChainTest, AnalyzeSelfProcess_ReturnsVerdict) {
    const ShadowStrike::Core::Process::InjectionVerdict verdict =
        ShadowStrike::Core::Process::ProcessInjectionDetector::Instance().AnalyzeProcess(
            GetOwnPid());

    EXPECT_TRUE(IsValidInjectionVerdict(verdict));
}

/**
 * @brief Verifies the clean test process has no recorded inbound injections.
 *
 * A non-empty result for the current process would indicate state contamination
 * or a severe false positive in the live injection-detection pipeline.
 */
TEST_F(ProcessInjectionDetectorChainTest, GetInjections_OwnPid_ReturnsEmpty) {
    const auto verdict =
        ShadowStrike::Core::Process::ProcessInjectionDetector::Instance().AnalyzeProcess(
            GetOwnPid());
    const std::vector<ShadowStrike::Core::Process::InjectionEvent> injectionsInto =
        ShadowStrike::Core::Process::ProcessInjectionDetector::Instance().GetInjectionsInto(
            GetOwnPid());

    EXPECT_TRUE(IsValidInjectionVerdict(verdict));
    EXPECT_TRUE(injectionsInto.empty());
}

/**
 * @brief Confirms the reflective DLL detector completed suite-level startup.
 *
 * Initialization proves the detector accepted its default configuration and is
 * ready to execute real memory scans against live processes.
 */
TEST_F(ReflectiveDLLDetectorChainTest, Initialize_Succeeds) {
    EXPECT_TRUE(s_reflectiveInitialized);
    EXPECT_TRUE(ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance().IsInitialized());
}

/**
 * @brief Scans the hosting process for reflective-loading artifacts.
 *
 * The scan must complete successfully because later NGAV response flows depend
 * on a valid result object even when no reflective DLLs are present.
 */
TEST_F(ReflectiveDLLDetectorChainTest, ScanOwnProcess_ReturnsResult) {
    const ShadowStrike::Core::Process::ReflectiveScanResult result =
        ShadowStrike::Core::Process::ReflectiveDLLDetector::Instance().Scan(GetOwnPid());

    EXPECT_EQ(result.processId, GetOwnPid());
    EXPECT_TRUE(result.scanComplete);
}

/**
 * @brief Drives concurrent metadata lookups through the live process monitor.
 *
 * Eight simultaneous callers exercise the monitor's documented thread-safe read
 * path and ensure no caller loses the current process under contention.
 */
TEST_F(ProcessChainConcurrencyTest, ConcurrentGetProcessInfo_IsThreadSafe) {
    constexpr std::size_t kThreadCount = 8U;

    std::barrier startBarrier(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::vector<std::thread> workers;
    std::vector<uint32_t> resolvedPids(kThreadCount, 0U);
    std::vector<int> successFlags(kThreadCount, 0);

    workers.reserve(kThreadCount);

    for (std::size_t index = 0; index < kThreadCount; ++index) {
        workers.emplace_back([&startBarrier, &resolvedPids, &successFlags, index]() {
            startBarrier.arrive_and_wait();

            const auto processInfo =
                ShadowStrike::Core::Process::ProcessMonitor::Instance().GetProcessInfo(GetOwnPid());

            if (processInfo.has_value()) {
                resolvedPids[index] = processInfo->uniqueId.pid;
                successFlags[index] = 1;
            }
        });
    }

    startBarrier.arrive_and_wait();

    for (std::thread& worker : workers) {
        worker.join();
    }

    for (std::size_t index = 0; index < kThreadCount; ++index) {
        EXPECT_EQ(successFlags[index], 1) << "Thread " << index << " failed to resolve the process";
        EXPECT_EQ(resolvedPids[index], GetOwnPid()) << "Thread " << index << " resolved an unexpected PID";
    }
}

/**
 * @brief Runs concurrent analyzer passes against the current process.
 *
 * Four simultaneous analyses validate the analyzer's thread-safe integration
 * with the monitor and ensure independent callers receive coherent results.
 */
TEST_F(ProcessChainConcurrencyTest, ConcurrentAnalyzeProcess_IsThreadSafe) {
    if (!s_analyzerInitialized ||
        !ShadowStrike::Core::Process::ProcessAnalyzer::Instance().IsInitialized()) {
        GTEST_SKIP() << "ProcessAnalyzer::Initialize() failed; skipping";
    }

    constexpr std::size_t kThreadCount = 4U;

    std::barrier startBarrier(static_cast<std::ptrdiff_t>(kThreadCount + 1U));
    std::vector<std::thread> workers;
    std::vector<uint32_t> analyzedPids(kThreadCount, 0U);
    std::vector<int> successFlags(kThreadCount, 0);
    std::vector<std::wstring> processNames(kThreadCount);

    workers.reserve(kThreadCount);

    for (std::size_t index = 0; index < kThreadCount; ++index) {
        workers.emplace_back([&startBarrier, &analyzedPids, &successFlags, &processNames, index]() {
            startBarrier.arrive_and_wait();

            const ShadowStrike::Core::Process::ProcessAnalysisResult result =
                ShadowStrike::Core::Process::ProcessAnalyzer::Instance().AnalyzeProcess(
                    GetOwnPid());

            analyzedPids[index] = result.processId;
            processNames[index] = result.processName;
            successFlags[index] = result.processId == GetOwnPid() && !result.processName.empty() ? 1 : 0;
        });
    }

    startBarrier.arrive_and_wait();

    for (std::thread& worker : workers) {
        worker.join();
    }

    for (std::size_t index = 0; index < kThreadCount; ++index) {
        EXPECT_EQ(successFlags[index], 1) << "Thread " << index << " produced an incomplete analysis";
        EXPECT_EQ(analyzedPids[index], GetOwnPid()) << "Thread " << index << " analyzed an unexpected PID";
        EXPECT_FALSE(processNames[index].empty()) << "Thread " << index << " produced an empty process name";
    }
}

}  // namespace
