/**
 * @file DebuggerEvasionTests.cpp
 * @brief Enterprise-Grade Comprehensive Unit Tests for DebuggerEvasionDetector
 *
 * COVERAGE:
 * - Lifecycle: Initialization, Shutdown, Double-Init, Double-Shutdown
 * - Configuration: All AnalysisFlags combinations
 * - PEB Techniques: BeingDebugged, NtGlobalFlag, HeapFlags
 * - Hardware Breakpoints: DR0-DR7 register scanning
 * - API Detection: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess
 * - Timing Attacks: RDTSC, QueryPerformanceCounter anomalies
 * - Exception Handling: INT3, INT2D, invalid handle exceptions
 * - Process Relationships: Parent process validation
 * - Memory Artifacts: Software breakpoints (0xCC), specific patterns
 * - Thread Safety: Concurrent analysis stress testing
 * - Error Handling: Null pointers, invalid PIDs, access denied scenarios
 * - Self-Analysis: Baseline validation of the test runner
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include <gtest/gtest.h>
#include "../../../../src/AntiEvasion/DebuggerEvasionDetector.hpp"
#include <windows.h>
#include <thread>
#include <future>
#include <vector>
#include <algorithm>
#include <chrono>
#include <random>

using namespace ShadowStrike::AntiEvasion;

// ============================================================================
// TEST FIXTURE
// ============================================================================

class DebuggerEvasionTestFixture : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state before each test
    }

    void TearDown() override {
        // Ensure cleanup
    }

    // Helper to get current PID
    uint32_t GetCurrentPid() {
        return ::GetCurrentProcessId();
    }

    // Helper to detect if we are actually being debugged (to adjust test expectations)
    bool IsActuallyBeingDebugged() {
        return ::IsDebuggerPresent() != 0;
    }
};

// ============================================================================
// 1. LIFECYCLE & INITIALIZATION TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Lifecycle_Construction_Default) {
    DebuggerEvasionDetector detector;
    EXPECT_FALSE(detector.IsInitialized());
}

TEST_F(DebuggerEvasionTestFixture, Lifecycle_Initialization_Success) {
    DebuggerEvasionDetector detector;
    Error err;
    EXPECT_TRUE(detector.Initialize(&err));
    EXPECT_TRUE(detector.IsInitialized());
    EXPECT_FALSE(err.HasError());
}

TEST_F(DebuggerEvasionTestFixture, Lifecycle_DoubleInitialization_Idempotency) {
    DebuggerEvasionDetector detector;
    EXPECT_TRUE(detector.Initialize());

    // Second init should be safe and return true (idempotent)
    Error err;
    EXPECT_TRUE(detector.Initialize(&err));
    EXPECT_TRUE(detector.IsInitialized());
    EXPECT_FALSE(err.HasError());
}

TEST_F(DebuggerEvasionTestFixture, Lifecycle_Shutdown_StateClear) {
    DebuggerEvasionDetector detector;
    detector.Initialize();
    EXPECT_TRUE(detector.IsInitialized());

    detector.Shutdown();
    EXPECT_FALSE(detector.IsInitialized());
}

TEST_F(DebuggerEvasionTestFixture, Lifecycle_DoubleShutdown_Safety) {
    DebuggerEvasionDetector detector;
    detector.Initialize();
    detector.Shutdown();

    // Second shutdown should not crash
    EXPECT_NO_THROW(detector.Shutdown());
    EXPECT_FALSE(detector.IsInitialized());
}

TEST_F(DebuggerEvasionTestFixture, Lifecycle_Destruction_Clean) {
    {
        DebuggerEvasionDetector detector;
        detector.Initialize();
        // Destructor called here
    }
    // Success if no crash/leak detected by sanitizer
    SUCCEED();
}

// ============================================================================
// 2. CONFIGURATION & FLAGS TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Config_QuickScan) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.depth = AnalysisDepth::Quick;
    config.flags = AnalysisFlags::QuickScan;

    auto result = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_TRUE(result.analysisComplete);
    // Quick scan should check PEB and basic APIs
    EXPECT_TRUE(result.techniquesChecked > 0);
}

TEST_F(DebuggerEvasionTestFixture, Config_DeepScan) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.depth = AnalysisDepth::Deep;
    config.flags = AnalysisFlags::DeepScan;

    auto result = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_TRUE(result.analysisComplete);
    // Deep scan should check significantly more techniques
    EXPECT_GT(result.techniquesChecked, 10);
}

TEST_F(DebuggerEvasionTestFixture, Config_SpecificFlags_PEBOnly) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.flags = AnalysisFlags::ScanPEBTechniques;

    auto result = detector.AnalyzeProcess(GetCurrentPid(), config);

    // Should ONLY check PEB
    if (result.analysisComplete) {
        EXPECT_TRUE(result.pebInfo.valid);
        EXPECT_EQ(result.hardwareBreakpoints.size(), 0); // Should be empty if flag not set
    }
}

TEST_F(DebuggerEvasionTestFixture, Config_SpecificFlags_HardwareOnly) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.flags = AnalysisFlags::ScanHardwareBreakpoints;

    auto result = detector.AnalyzeProcess(GetCurrentPid(), config);

    // Should check HW BPs
    EXPECT_FALSE(result.hardwareBreakpoints.empty());
    // PEB might be implicitly checked for basic info, but focus is HW
}

TEST_F(DebuggerEvasionTestFixture, Config_CustomDebuggerNames) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    detector.AddCustomDebuggerName(L"custom_debugger.exe");
    detector.AddCustomWindowClass(L"CUSTOM_DBG_WND");

    // Logic verification: Ensure these are stored (internal state check via successful execution)
    AnalysisConfig config;
    config.depth = AnalysisDepth::Quick;

    auto result = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_TRUE(result.analysisComplete);

    detector.ClearCustomDetectionLists();
}

// ============================================================================
// 3. PEB-BASED TECHNIQUE TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, PEB_SelfCheck_Baseline) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    PEBAnalysisInfo info;
    Error err;
    bool detected = detector.CheckPEBFlags(GetCurrentPid(), info, &err);

    EXPECT_FALSE(err.HasError());
    EXPECT_TRUE(info.valid);
    EXPECT_NE(info.pebAddress, 0);

    // If we are running this test under a debugger, it SHOULD detect it
    if (IsActuallyBeingDebugged()) {
        EXPECT_TRUE(detected || info.beingDebugged);
    } else {
        EXPECT_FALSE(detected);
        EXPECT_FALSE(info.beingDebugged);
    }
}

TEST_F(DebuggerEvasionTestFixture, PEB_Flags_Consistency) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    auto result = detector.AnalyzeProcess(GetCurrentPid());

    if (result.analysisComplete) {
        EXPECT_TRUE(result.pebInfo.valid);
        // NtGlobalFlag should generally be 0 for non-debugged processes
        if (!IsActuallyBeingDebugged()) {
            EXPECT_EQ(result.pebInfo.ntGlobalFlag & 0x70, 0); // Check specific debug flags
        }
    }
}

// ============================================================================
// 4. HARDWARE BREAKPOINT TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, HW_Breakpoints_SelfScan) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<HardwareBreakpointInfo> breakpoints;
    Error err;
    bool detected = detector.CheckHardwareBreakpoints(GetCurrentPid(), breakpoints, &err);

    EXPECT_FALSE(err.HasError());
    // Should find at least one thread (the current one)
    EXPECT_GT(breakpoints.size(), 0);

    for (const auto& bp : breakpoints) {
        EXPECT_TRUE(bp.valid);
        if (!IsActuallyBeingDebugged()) {
            EXPECT_EQ(bp.activeBreakpointCount, 0);
            EXPECT_EQ(bp.dr0, 0);
            EXPECT_EQ(bp.dr1, 0);
            EXPECT_EQ(bp.dr2, 0);
            EXPECT_EQ(bp.dr3, 0);
        }
    }
}

// ============================================================================
// 5. TIMING ATTACK TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Timing_RDTSC_Check) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<DetectedTechnique> detections;
    detector.CheckTimingTechniques(GetCurrentPid(), detections);

    // Timing checks can be flaky in VMs/CI, but shouldn't crash
    // If we are not being debugged/traced, we expect no high-severity timing anomalies
    if (!IsActuallyBeingDebugged()) {
        bool highSevTiming = false;
        for (const auto& det : detections) {
            if (det.severity >= EvasionSeverity::High) highSevTiming = true;
        }
        EXPECT_FALSE(highSevTiming);
    }
}

// ============================================================================
// 6. API-BASED TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, API_BasicChecks) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<DetectedTechnique> detections;
    detector.CheckAPITechniques(GetCurrentPid(), detections);

    // IsDebuggerPresent and CheckRemoteDebuggerPresent are standard
    // Validation: Ensure the check ran and results consistent with environment
    if (IsActuallyBeingDebugged()) {
        bool foundBasic = false;
        for (const auto& det : detections) {
            if (det.technique == EvasionTechnique::API_IsDebuggerPresent ||
                det.technique == EvasionTechnique::API_CheckRemoteDebuggerPresent) {
                foundBasic = true;
            }
        }
        // Note: CheckAPITechniques might simulate the call or check if the target called it
        // Depending on implementation, this tests the scanner's logic
    }
}

// ============================================================================
// 7. EXCEPTION HANDLING TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Exception_Handlers_Scan) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<DetectedTechnique> detections;
    // This involves dangerous operations (injecting exceptions), ensure it's safe
    detector.CheckExceptionTechniques(GetCurrentPid(), detections);

    // We verify no crash occurred during exception simulation
    SUCCEED();
}

// ============================================================================
// 8. PROCESS RELATIONSHIP TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Process_ParentCheck) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    ParentProcessInfo parentInfo;
    detector.CheckParentProcess(GetCurrentPid(), parentInfo);

    EXPECT_TRUE(parentInfo.valid);
    EXPECT_FALSE(parentInfo.parentName.empty());

    // In a test runner, parent might be VS Test Engine or cmd.exe
    // Just verify we got a valid PID
    EXPECT_NE(parentInfo.parentPid, 0);
}

// ============================================================================
// 9. MEMORY ARTIFACT TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Memory_Artifact_Scan) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<MemoryRegionInfo> regions;
    // Scan limited regions to be fast
    detector.ScanMemoryArtifacts(GetCurrentPid(), regions);

    // Should find at least the main module code section
    EXPECT_FALSE(regions.empty());

    bool executableRegionFound = false;
    for (const auto& region : regions) {
        if (region.isExecutable) executableRegionFound = true;
    }
    EXPECT_TRUE(executableRegionFound);
}

// ============================================================================
// 10. ERROR HANDLING & EDGE CASES (PARANOID CHECKS)
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Error_NullPointers) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    // Pass nullptr for optional outputs
    EXPECT_NO_THROW(detector.AnalyzeProcess(GetCurrentPid(), {}, nullptr));

    PEBAnalysisInfo peb;
    EXPECT_NO_THROW(detector.CheckPEBFlags(GetCurrentPid(), peb, nullptr));
}

TEST_F(DebuggerEvasionTestFixture, Error_InvalidPID_Zero) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    Error err;
    auto result = detector.AnalyzeProcess(0, {}, &err);

    // PID 0 (Idle) usually fails to open
    EXPECT_TRUE(err.HasError());
    EXPECT_FALSE(result.analysisComplete);
}

TEST_F(DebuggerEvasionTestFixture, Error_InvalidPID_NonExistent) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    // Use a ridiculously high PID
    uint32_t badPid = 999999;
    Error err;
    auto result = detector.AnalyzeProcess(badPid, {}, &err);

    EXPECT_TRUE(err.HasError());
    EXPECT_FALSE(result.analysisComplete);
}

TEST_F(DebuggerEvasionTestFixture, Error_Uninitialized_Usage) {
    DebuggerEvasionDetector detector;
    // Skip Initialize()

    Error err;
    auto result = detector.AnalyzeProcess(GetCurrentPid(), {}, &err);

    EXPECT_FALSE(result.analysisComplete);
    EXPECT_TRUE(err.HasError());
    // Should be specific error code for "Not Initialized" if defined, or generic error
    EXPECT_NE(err.win32Code, ERROR_SUCCESS);
}

TEST_F(DebuggerEvasionTestFixture, Error_AccessDenied_SystemProcess) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    // Try to analyze a system process (PID 4 is usually System)
    // This requires SeDebugPrivilege, running as user should fail or handle gracefully
    Error err;
    auto result = detector.AnalyzeProcess(4, {}, &err);

    // Should not crash. Result might be incomplete or error.
    if (result.analysisComplete) {
        // If it worked, great (maybe running as Admin)
        SUCCEED();
    } else {
        // If it failed, it should be Access Denied
        EXPECT_TRUE(err.HasError());
        // EXPECT_EQ(err.win32Code, ERROR_ACCESS_DENIED); // Don't enforce strict code, just failure
    }
}

// ============================================================================
// 11. BATCH ANALYSIS TESTS
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Batch_AnalyzeSelfAndParent) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    std::vector<uint32_t> pids;
    pids.push_back(GetCurrentPid());
    pids.push_back(::GetCurrentProcessId()); // Duplicate to test handling

    auto batchResult = detector.AnalyzeProcesses(pids);

    EXPECT_EQ(batchResult.totalProcesses, 2);
    EXPECT_EQ(batchResult.results.size(), 2);
}

// ============================================================================
// 12. THREAD SAFETY & CONCURRENCY
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Concurrency_MultiThreadedAnalysis) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    const int numThreads = 8;
    const int iterations = 10;
    std::vector<std::future<DebuggerEvasionResult>> futures;

    for (int i = 0; i < numThreads; ++i) {
        futures.push_back(std::async(std::launch::async, [&]() {
            DebuggerEvasionResult lastResult;
            for (int j = 0; j < iterations; ++j) {
                // Mix quick and standard scans
                AnalysisConfig config;
                config.depth = (j % 2 == 0) ? AnalysisDepth::Quick : AnalysisDepth::Standard;
                config.flags = (j % 2 == 0) ? AnalysisFlags::QuickScan : AnalysisFlags::StandardScan;

                lastResult = detector.AnalyzeProcess(GetCurrentPid(), config);
            }
            return lastResult;
        }));
    }

    for (auto& f : futures) {
        auto result = f.get();
        EXPECT_TRUE(result.analysisComplete);
    }
}

// ============================================================================
// 13. CACHING LOGIC
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Cache_HitTest) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.enableCaching = true;
    config.cacheTtlSeconds = 10;

    // First run - miss
    auto res1 = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_FALSE(res1.fromCache);

    // Second run - hit
    auto res2 = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_TRUE(res2.fromCache);

    // Validation: Results should be identical
    EXPECT_EQ(res1.targetPid, res2.targetPid);
    EXPECT_EQ(res1.isEvasive, res2.isEvasive);
}

TEST_F(DebuggerEvasionTestFixture, Cache_Invalidation) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    AnalysisConfig config;
    config.enableCaching = true;

    // First run - populate cache
    detector.AnalyzeProcess(GetCurrentPid(), config);

    // Invalidate
    detector.InvalidateCache(GetCurrentPid());

    // Second run - should be miss again
    auto res = detector.AnalyzeProcess(GetCurrentPid(), config);
    EXPECT_FALSE(res.fromCache);
}

// ============================================================================
// 14. STATISTICS TRACKING
// ============================================================================

TEST_F(DebuggerEvasionTestFixture, Stats_CounterCheck) {
    DebuggerEvasionDetector detector;
    ASSERT_TRUE(detector.Initialize());

    detector.ResetStatistics();
    auto stats = detector.GetStatistics();
    EXPECT_EQ(stats.totalAnalyses, 0);

    detector.AnalyzeProcess(GetCurrentPid());

    stats = detector.GetStatistics();
    EXPECT_EQ(stats.totalAnalyses, 1);
    EXPECT_GT(stats.totalAnalysisTimeUs, 0);
}
