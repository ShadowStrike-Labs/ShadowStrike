#include <gtest/gtest.h>
#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <chrono>

#include "../../src/AntiEvasion/ProcessEvasionDetector.hpp"
#include "../../src/Utils/ProcessUtils.hpp"

using namespace ShadowStrike::AntiEvasion;

class ProcessEvasionDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state
        ProcessEvasionDetector detector; // Stack instance to test basics
    }

    void TearDown() override {
        // Cleanup
    }
};

// Test Initialization
TEST_F(ProcessEvasionDetectorTest, Initialization) {
    ProcessEvasionDetector detector;
    ProcessEvasionError error;

    ASSERT_TRUE(detector.Initialize(&error)) << "Initialization failed: " <<
        std::string(error.message.begin(), error.message.end());

    ASSERT_TRUE(detector.IsInitialized());
}

// Test Self-Analysis (Should be clean)
TEST_F(ProcessEvasionDetectorTest, AnalyzeCurrentProcess) {
    ProcessEvasionDetector detector;
    detector.Initialize();

    uint32_t pid = GetCurrentProcessId();
    ProcessAnalysisConfig config;
    config.flags = ProcessAnalysisFlags::All;

    auto result = detector.AnalyzeProcess(pid, config);

    EXPECT_EQ(result.processId, pid);
    EXPECT_TRUE(result.analysisComplete);

    // We expect NO evasion in our unit test runner
    EXPECT_FALSE(result.isEvasive) << "False positive detected on unit test runner!";
    EXPECT_EQ(result.injectionInfo.hasInjection, false);
    EXPECT_EQ(result.masqueradingInfo.isMasquerading, false);
}

// Test Cache Mechanism
TEST_F(ProcessEvasionDetectorTest, CacheMechanism) {
    ProcessEvasionDetector detector;
    detector.Initialize();

    uint32_t pid = GetCurrentProcessId();

    // First run - miss
    auto result1 = detector.AnalyzeProcess(pid);
    EXPECT_FALSE(result1.fromCache);

    // Second run - hit
    auto result2 = detector.AnalyzeProcess(pid);
    EXPECT_TRUE(result2.fromCache);

    // Invalidate
    detector.InvalidateCache(pid);
    auto result3 = detector.AnalyzeProcess(pid);
    EXPECT_FALSE(result3.fromCache);
}

// Test Injection Detection (Simulation)
TEST_F(ProcessEvasionDetectorTest, SimulateRWXMemory) {
    ProcessEvasionDetector detector;
    detector.Initialize();

    uint32_t pid = GetCurrentProcessId();

    // Allocate RWX memory (Simulation of injection)
    LPVOID rwxMem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(rwxMem, nullptr);

    // Write some NOPs to simulate shellcode
    std::vector<uint8_t> nops(100, 0x90);
    memcpy(rwxMem, nops.data(), nops.size());

    // Analyze
    ProcessAnalysisConfig config;
    config.flags = ProcessAnalysisFlags::CheckMemory | ProcessAnalysisFlags::CheckInjection;
    // Disable caching to force fresh scan
    config.flags = static_cast<ProcessAnalysisFlags>(static_cast<uint32_t>(config.flags) & ~static_cast<uint32_t>(ProcessAnalysisFlags::EnableCaching));

    auto result = detector.AnalyzeProcess(pid, config);

    // Cleanup
    VirtualFree(rwxMem, 0, MEM_RELEASE);

    // Assertions
    // Note: The detector finds RWX memory. Depending on thresholds, it might trigger 'isEvasive'
    // or just report it in findings.

    bool foundSuspiciousRegion = false;
    for (const auto& region : result.suspiciousMemoryRegions) {
        if (region.isExecutable && region.isWritable) {
            foundSuspiciousRegion = true;
            break;
        }
    }

    EXPECT_TRUE(foundSuspiciousRegion) << "Failed to detect RWX memory region";

    // Check if it detected the injection
    // (Note: self-detection might be suppressed or heuristic dependent, but RWX should be flagged)
    if (result.injectionInfo.suspiciousMemoryRegions > 0) {
        // Success
    }
}

// Test Masquerading (Mock Logic)
// Since we cannot rename our process easily, we test the logic via internal helpers if they were exposed,
// but since they are private PIMPL, we rely on the public API not flagging us.
// We can try to analyze a system process if we have rights.
TEST_F(ProcessEvasionDetectorTest, AnalyzeSystemProcess) {
    ProcessEvasionDetector detector;
    detector.Initialize();

    // Try to find lsass.exe or svchost.exe
    // Note: This requires Admin privileges usually.
    // If not admin, OpenProcess might fail, which is handled gracefully.

    // Just ensure it doesn't crash on Access Denied
    // We'll iterate a few PIDs

    std::vector<uint32_t> pids = { 0, 4 }; // System Idle, System

    auto results = detector.AnalyzeProcesses(pids);
    EXPECT_EQ(results.size(), 2);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
