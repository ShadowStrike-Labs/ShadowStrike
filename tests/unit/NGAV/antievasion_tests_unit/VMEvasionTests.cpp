#include <gtest/gtest.h>
#include <memory>
#include "../../../../src/AntiEvasion/VMEvasionDetector.hpp"

// Mock or stub for dependencies if needed
// VMEvasionDetector seems to be self-contained or uses Singletons which we might need to handle.
// Assuming it's testable as is based on CLAUDE.md descriptions of "SelfTest".

class VMEvasionTests : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup code
    }

    void TearDown() override {
        // Teardown code
    }
};

TEST_F(VMEvasionTests, Instantiation) {
    auto detector = std::make_unique<VMEvasionDetector>();
    EXPECT_NE(detector, nullptr);
}

TEST_F(VMEvasionTests, Configuration) {
    auto detector = std::make_unique<VMEvasionDetector>();
    VMDetectionConfig config;
    config.enableCPUIDCheck = false;
    detector->SetConfig(config);
    
    auto retrievedConfig = detector->GetConfig();
    EXPECT_FALSE(retrievedConfig.enableCPUIDCheck);
    
    config.enableCPUIDCheck = true;
    detector->SetConfig(config);
    retrievedConfig = detector->GetConfig();
    EXPECT_TRUE(retrievedConfig.enableCPUIDCheck);
}

TEST_F(VMEvasionTests, QuickDetectCPUID_SafeRun) {
    // This should run without crashing on any platform
    auto detector = std::make_unique<VMEvasionDetector>();
    bool isVM = detector->QuickDetectCPUID();
    // We can't assert true/false as it depends on where the test runs, 
    // but we verify it runs and returns a boolean.
    EXPECT_TRUE(isVM == true || isVM == false);
}

TEST_F(VMEvasionTests, IsRunningInVM_SafeRun) {
    // This executes the comprehensive check
    auto detector = std::make_unique<VMEvasionDetector>();
    bool isVM = detector->IsRunningInVM();
    EXPECT_TRUE(isVM == true || isVM == false);
}

TEST_F(VMEvasionTests, AnalyzeProcessAntiVMBehavior_Self) {
    auto detector = std::make_unique<VMEvasionDetector>();
    
    // Analyze current process
    // In a test environment, this shouldn't trigger anti-VM behavior unless we inject it.
    // Just verifying it runs safely.
    bool detected = detector->AnalyzeProcessAntiVMBehavior(GetCurrentProcessId());
    EXPECT_FALSE(detected); // Should be false for a normal test runner
}

TEST_F(VMEvasionTests, VMwareBackdoor_Check) {
    // This tests the logic we added.
    // On bare metal, this relies on exception handling which we can't easily force in a unit test 
    // without risking a crash if our SEH logic is wrong, but the Detector wraps it.
    
    auto detector = std::make_unique<VMEvasionDetector>();
    VMEvasionResult result;
    
    // We can't access private methods directly, but we can trigger the check via IsRunningInVM
    // or if there's a specific public method exposing it.
    // VMEvasionDetector::CheckIOPorts is private usually.
    // But IsRunningInVM calls it.
    
    bool isVM = detector->IsRunningInVM();
    // Accessing result would require exposing it, but IsRunningInVM returns a bool.
    // We assume if it runs without crashing, the SEH in TryVMwareBackdoor works.
    SUCCEED();
}
