/*
 * ============================================================================
 * ShadowStrike Test Runner
 * ============================================================================
 *
 * Copyright (c) 2026 ShadowStrike Security Suite
 * All rights reserved.
 *
 * PROPRIETARY AND CONFIDENTIAL
 *
 * Main test runner for executing all unit tests and generating reports
 *
 * NOTE: This file provides main() for Google Test. Test cases are defined
 *       in separate *_Tests.cpp files which will be automatically discovered
 *       by the linker when compiled together.
 *
 * ============================================================================
 */

#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <chrono>


// Custom test event listener for detailed reporting
class DetailedTestListener : public ::testing::TestEventListener {
private:
    ::testing::TestEventListener* default_listener_;
    std::chrono::time_point<std::chrono::high_resolution_clock> test_start_time_;
    std::chrono::time_point<std::chrono::high_resolution_clock> suite_start_time_;
    int total_tests_ = 0;
    int passed_tests_ = 0;
    int failed_tests_ = 0;
    
public:
    explicit DetailedTestListener(::testing::TestEventListener* listener) 
        : default_listener_(listener) {}

    ~DetailedTestListener() override {
        delete default_listener_;
    }

    void OnTestProgramStart(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnTestProgramStart(unit_test);
        std::cout << "\n";
        std::cout << "========================================================================\n";
        std::cout << "  ShadowStrike Base64Utils Test Suite\n";
        std::cout << "  Copyright (c) 2026 ShadowStrike Security Suite\n";
        std::cout << "========================================================================\n";
        std::cout << "\n";
    }

    void OnTestIterationStart(const ::testing::UnitTest& unit_test, int iteration) override {
        default_listener_->OnTestIterationStart(unit_test, iteration);
        std::cout << "Running " << unit_test.total_test_count() << " tests from " 
                  << unit_test.test_suite_to_run_count() << " test suites\n\n";
    }

    void OnTestSuiteStart(const ::testing::TestSuite& test_suite) override {
        default_listener_->OnTestSuiteStart(test_suite);
        suite_start_time_ = std::chrono::high_resolution_clock::now();
        std::cout << "------------------------------------------------------------------------\n";
        std::cout << "Test Suite: " << test_suite.name() << "\n";
        std::cout << "------------------------------------------------------------------------\n";
    }

    void OnTestStart(const ::testing::TestInfo& test_info) override {
        default_listener_->OnTestStart(test_info);
        test_start_time_ = std::chrono::high_resolution_clock::now();
        std::cout << "  [ RUN      ] " << test_info.test_suite_name() << "." 
                  << test_info.name() << std::endl;
    }

    void OnTestPartResult(const ::testing::TestPartResult& result) override {
        default_listener_->OnTestPartResult(result);
        if (result.failed()) {
            std::cout << "    " << result.file_name() << ":" << result.line_number() << "\n";
            std::cout << "    " << result.summary() << "\n";
        }
    }

    void OnTestEnd(const ::testing::TestInfo& test_info) override {
        default_listener_->OnTestEnd(test_info);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end_time - test_start_time_);
        
        total_tests_++;
        if (test_info.result()->Passed()) {
            passed_tests_++;
            std::cout << "  [       OK ] " << test_info.test_suite_name() << "." 
                      << test_info.name() << " (" << duration.count() << " μs)\n";
        } else {
            failed_tests_++;
            std::cout << "  [  FAILED  ] " << test_info.test_suite_name() << "." 
                      << test_info.name() << " (" << duration.count() << " μs)\n";
        }
    }

    void OnTestSuiteEnd(const ::testing::TestSuite& test_suite) override {
        default_listener_->OnTestSuiteEnd(test_suite);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - suite_start_time_);
        
        std::cout << "\nTest Suite Complete: " << test_suite.name() 
                  << " (" << duration.count() << " ms)\n";
        std::cout << "  Tests: " << test_suite.total_test_count() 
                  << " | Passed: " << test_suite.successful_test_count()
                  << " | Failed: " << test_suite.failed_test_count() << "\n\n";
    }

    void OnTestIterationEnd(const ::testing::UnitTest& unit_test, int iteration) override {
        default_listener_->OnTestIterationEnd(unit_test, iteration);
        
        std::cout << "========================================================================\n";
        std::cout << "  TEST SUMMARY\n";
        std::cout << "========================================================================\n";
        std::cout << "  Total Tests:   " << total_tests_ << "\n";
        
        if (total_tests_ > 0) {
            std::cout << "  Passed:        " << std::setw(3) << passed_tests_ 
                      << " (" << std::fixed << std::setprecision(1) 
                      << (100.0 * passed_tests_ / total_tests_) << "%)\n";
            std::cout << "  Failed:        " << std::setw(3) << failed_tests_ 
                      << " (" << std::fixed << std::setprecision(1) 
                      << (100.0 * failed_tests_ / total_tests_) << "%)\n";
        } else {
            std::cout << "  Passed:          0 (0.0%)\n";
            std::cout << "  Failed:          0 (0.0%)\n";
        }
        
        std::cout << "========================================================================\n";
        
        if (failed_tests_ == 0 && total_tests_ > 0) {
            std::cout << "\n✓ ALL TESTS PASSED - Implementation meets enterprise security standards\n\n";
        } else if (total_tests_ == 0) {
            std::cout << "\n✗ NO TESTS FOUND - Please check project configuration\n\n";
        } else {
            std::cout << "\n✗ TESTS FAILED - Please review and address failures before deployment\n\n";
        }
    }

    void OnTestProgramEnd(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnTestProgramEnd(unit_test);
    }

    void OnEnvironmentsSetUpStart(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnEnvironmentsSetUpStart(unit_test);
    }

    void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnEnvironmentsSetUpEnd(unit_test);
    }

    void OnEnvironmentsTearDownStart(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnEnvironmentsTearDownStart(unit_test);
    }

    void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& unit_test) override {
        default_listener_->OnEnvironmentsTearDownEnd(unit_test);
    }
};

int main(int argc, char** argv) {
    std::cout << "\n========================================================================\n";
    std::cout << "  ShadowStrike Test Runner - Initializing...\n";
    std::cout << "========================================================================\n\n";
    
    // Initialize Google Test framework
    ::testing::InitGoogleTest(&argc, argv);
    
    // Get the default test event listener
    ::testing::TestEventListeners& listeners = 
        ::testing::UnitTest::GetInstance()->listeners();
    
    // Remove default listener and add our custom listener
    ::testing::TestEventListener* default_listener = 
        listeners.Release(listeners.default_result_printer());
    listeners.Append(new DetailedTestListener(default_listener));
    
    std::cout << "Google Test Framework Initialized\n";
    std::cout << "Test Discovery: " << ::testing::UnitTest::GetInstance()->total_test_count() 
              << " tests found\n\n";
    
    if (::testing::UnitTest::GetInstance()->total_test_count() == 0) {
        std::cerr << "ERROR: No tests were found!\n";
        std::cerr << "This usually means:\n";
        std::cerr << "  1. Test files are not being compiled\n";
        std::cerr << "  2. Test files are not linked into the executable\n";
        std::cerr << "  3. TEST_F macros are not being expanded\n\n";
        std::cerr << "Please check your build configuration.\n";
        return 1;
    }
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    // Return exit code (0 for success, non-zero for failure)
    return result;
}
