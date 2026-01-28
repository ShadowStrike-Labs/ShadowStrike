#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <vector>
#include <memory>
#include "../../src/AntiEvasion/TimeBasedEvasionDetector.hpp"
#include "../../src/Utils/ThreadPool.hpp"
#include "../../src/Utils/ProcessUtils.hpp"

// Define test fixture
class TimeBasedEvasionDetectorTest : public ::testing::Test {
protected:
    std::shared_ptr<ShadowStrike::Utils::ThreadPool> m_threadPool;

    void SetUp() override {
        // Create a real thread pool for the detector
        m_threadPool = std::make_shared<ShadowStrike::Utils::ThreadPool>(2);

        // Initialize singleton
        auto& detector = ShadowStrike::AntiEvasion::TimeBasedEvasionDetector::Instance();
        // Force re-initialization if needed (though it's a singleton, we try to ensure clean state)
        if (!detector.IsInitialized()) {
            detector.Initialize(m_threadPool);
        }

        // Reset stats and cache before each test
        detector.ResetStats();
        detector.ClearCache();
    }

    void TearDown() override {
        // We don't shutdown the singleton completely to avoid destabilizing other tests
        // that might run in the same process, but we stop monitoring.
        auto& detector = ShadowStrike::AntiEvasion::TimeBasedEvasionDetector::Instance();
        detector.StopAllMonitoring();
    }
};

using namespace ShadowStrike::AntiEvasion;

// Test Initialization
TEST_F(TimeBasedEvasionDetectorTest, InitializationState) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    EXPECT_TRUE(detector.IsInitialized()) << "Detector should be initialized";

    auto stats = detector.GetStats();
    EXPECT_EQ(stats.totalProcessesAnalyzed.load(), 0) << "Stats should be reset";
}

// Test Configuration Update
TEST_F(TimeBasedEvasionDetectorTest, ConfigurationUpdates) {
    auto& detector = TimeBasedEvasionDetector::Instance();

    auto originalConfig = detector.GetConfig();

    // Create a custom config
    auto newConfig = TimingDetectorConfig::CreateHighSensitivity();
    newConfig.rdtscFrequencyThreshold = 5000;

    detector.UpdateConfig(newConfig);

    auto currentConfig = detector.GetConfig();
    EXPECT_EQ(currentConfig.rdtscFrequencyThreshold, 5000);
    EXPECT_TRUE(currentConfig.detectSideChannels);

    // Restore original
    detector.UpdateConfig(originalConfig);
}

// Test Basic Process Analysis (Self-Analysis)
TEST_F(TimeBasedEvasionDetectorTest, AnalyzeCurrentProcess) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    auto result = detector.AnalyzeProcess(currentPid);

    EXPECT_TRUE(result.analysisComplete);
    EXPECT_EQ(result.processId, currentPid);
    EXPECT_FALSE(result.processName.empty());

    // We expect NO evasion in our clean test runner
    EXPECT_FALSE(result.isEvasive);
    EXPECT_EQ(result.findings.size(), 0);
}

// Test Sleep Analysis Logic
TEST_F(TimeBasedEvasionDetectorTest, SleepAnalysisLogic) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    // Perform some sleeps to generate history (if the detector hooks them,
    // but since we are in user mode test without hooks, we rely on the AnalyzeSleep function logic
    // which normally reads data.
    // NOTE: In a unit test environment without the kernel driver feeding data,
    // the internal trackers (m_sleepTrackers) will be empty unless we simulate events.
    // The class exposes RecordTimingEvent via a private interface or we need to rely on
    // what AnalyzeSleep does.
    // Looking at the implementation, AnalyzeSleep reads from m_sleepTrackers.
    // To test the LOGIC, we really need to inject data.
    // However, since we cannot easily access the private Impl or private methods from here
    // without friend classes, we will test the public interface behavior on 'empty' data
    // which should be safe and return neutral results.

    auto analysis = detector.AnalyzeSleep(currentPid);
    EXPECT_EQ(analysis.processId, currentPid);
    EXPECT_FALSE(analysis.HasSleepEvasion());
    EXPECT_EQ(analysis.sleepCallCount, 0);
}

// Test Continuous Monitoring Lifecycle
TEST_F(TimeBasedEvasionDetectorTest, MonitoringLifecycle) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    // Start Monitoring
    EXPECT_TRUE(detector.StartMonitoring(currentPid));
    EXPECT_TRUE(detector.IsMonitoring(currentPid));
    EXPECT_EQ(detector.GetMonitoringState(currentPid), MonitoringState::Active);

    // Pause
    detector.PauseMonitoring(currentPid);
    EXPECT_EQ(detector.GetMonitoringState(currentPid), MonitoringState::Paused);

    // Resume
    detector.ResumeMonitoring(currentPid);
    EXPECT_EQ(detector.GetMonitoringState(currentPid), MonitoringState::Active);

    // Stop
    detector.StopMonitoring(currentPid);
    EXPECT_FALSE(detector.IsMonitoring(currentPid));
    EXPECT_EQ(detector.GetMonitoringState(currentPid), MonitoringState::Inactive);
}

// Test Callbacks
TEST_F(TimeBasedEvasionDetectorTest, CallbackRegistration) {
    auto& detector = TimeBasedEvasionDetector::Instance();

    bool callbackCalled = false;
    auto cbId = detector.RegisterCallback([&](const TimingEvasionResult& res) {
        callbackCalled = true;
    });

    EXPECT_NE(cbId, 0);

    // We cannot easily trigger the callback without simulating an evasion event,
    // but we can verify registration and unregistration.

    EXPECT_TRUE(detector.UnregisterCallback(cbId));
    EXPECT_FALSE(detector.UnregisterCallback(cbId)); // Should fail second time
}

// Test Async Analysis
TEST_F(TimeBasedEvasionDetectorTest, AsyncAnalysis) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    std::atomic<bool> completed{false};

    bool started = detector.AnalyzeProcessAsync(currentPid,
        [&](TimingEvasionResult result) {
            EXPECT_EQ(result.processId, currentPid);
            completed = true;
        }
    );

    EXPECT_TRUE(started);

    // Wait for completion (with timeout)
    int attempts = 0;
    while (!completed && attempts < 20) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        attempts++;
    }

    EXPECT_TRUE(completed) << "Async analysis did not complete in time";
}

// Test Quick Scan
TEST_F(TimeBasedEvasionDetectorTest, QuickScan) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    // Quick scan should be fast and not throw
    EXPECT_NO_THROW({
        bool suspicious = detector.QuickScanProcess(currentPid);
        EXPECT_FALSE(suspicious); // Should be false for our benign process
    });
}

// Test Caching
TEST_F(TimeBasedEvasionDetectorTest, ResultCaching) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    uint32_t currentPid = GetCurrentProcessId();

    // Force an analysis to populate cache
    detector.AnalyzeProcess(currentPid);

    // Check if result is cached
    auto cachedResult = detector.GetCachedResult(currentPid);
    EXPECT_TRUE(cachedResult.has_value());
    EXPECT_EQ(cachedResult->processId, currentPid);

    // Clear cache
    detector.ClearCache();
    auto emptyResult = detector.GetCachedResult(currentPid);
    EXPECT_FALSE(emptyResult.has_value());
}

// Test Statistics
TEST_F(TimeBasedEvasionDetectorTest, StatisticsTracking) {
    auto& detector = TimeBasedEvasionDetector::Instance();

    // Reset first
    detector.ResetStats();

    // Run analysis
    detector.AnalyzeProcess(GetCurrentProcessId());

    auto stats = detector.GetStats();
    EXPECT_GE(stats.totalProcessesAnalyzed.load(), 1);

    // We expect a cache miss on the first run after reset
    EXPECT_GE(stats.cacheMisses.load(), 1);
}

// Test RDTSC Analysis Defaults
TEST_F(TimeBasedEvasionDetectorTest, RDTSCAnalysisDefaults) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    auto analysis = detector.AnalyzeRDTSC(GetCurrentProcessId());

    EXPECT_FALSE(analysis.HasRDTSCEvasion());
    EXPECT_EQ(analysis.rdtscCount, 0);
}

// Test NTP Analysis Defaults
TEST_F(TimeBasedEvasionDetectorTest, NTPAnalysisDefaults) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    auto analysis = detector.AnalyzeNTP(GetCurrentProcessId());

    EXPECT_FALSE(analysis.HasNTPEvasion());
    EXPECT_EQ(analysis.ntpQueryCount, 0);
}

// Test API Timing Defaults
TEST_F(TimeBasedEvasionDetectorTest, APITimingDefaults) {
    auto& detector = TimeBasedEvasionDetector::Instance();
    auto analysis = detector.AnalyzeAPITiming(GetCurrentProcessId());

    EXPECT_FALSE(analysis.HasAPITimingEvasion());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
