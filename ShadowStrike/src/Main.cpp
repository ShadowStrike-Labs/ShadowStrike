#include <gtest/gtest.h>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <exception>
#include "../../../src/Utils/Logger.hpp"

using namespace ShadowStrike::Utils;

class DetailedTestListener : public ::testing::TestEventListener {
    ::testing::TestEventListener* default_;
    std::chrono::high_resolution_clock::time_point testStart_;
    std::chrono::high_resolution_clock::time_point suiteStart_;
    int total_ = 0, passed_ = 0, failed_ = 0;
public:
    explicit DetailedTestListener(::testing::TestEventListener* d) : default_(d) {}
    ~DetailedTestListener() override { delete default_; }

    void OnTestProgramStart(const ::testing::UnitTest& u) override {
        default_->OnTestProgramStart(u);
        std::cout << "\n========================================================================\n"
            << "  ShadowStrike CryptoUtils Test Suite\n"
            << "========================================================================\n\n";
    }
    void OnTestIterationStart(const ::testing::UnitTest& u, int it) override {
        default_->OnTestIterationStart(u, it);
        std::cout << "Running " << u.total_test_count() << " tests from "
            << u.test_suite_to_run_count() << " test suites\n\n";
    }
    void OnTestSuiteStart(const ::testing::TestSuite& s) override {
        default_->OnTestSuiteStart(s);
        suiteStart_ = std::chrono::high_resolution_clock::now();
        std::cout << "------------------------------------------------------------------------\n"
            << "Test Suite: " << s.name() << "\n"
            << "------------------------------------------------------------------------\n";
    }
    void OnTestStart(const ::testing::TestInfo& i) override {
        default_->OnTestStart(i);
        testStart_ = std::chrono::high_resolution_clock::now();
        std::cout << "  [ RUN      ] " << i.test_suite_name() << "." << i.name() << "\n";
    }
    void OnTestPartResult(const ::testing::TestPartResult& r) override {
        default_->OnTestPartResult(r);
        if (r.failed()) {
            std::cout << "    " << r.file_name() << ":" << r.line_number() << "\n"
                << "    " << r.summary() << "\n";
        }
    }
    void OnTestEnd(const ::testing::TestInfo& i) override {
        default_->OnTestEnd(i);
        auto dur = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::high_resolution_clock::now() - testStart_);
        ++total_;
        if (i.result()->Passed()) {
            ++passed_;
            std::cout << "  [       OK ] " << i.test_suite_name() << "." << i.name()
                << " (" << dur.count() << " μs)\n";
        }
        else {
            ++failed_;
            std::cout << "  [  FAILED  ] " << i.test_suite_name() << "." << i.name()
                << " (" << dur.count() << " μs)\n";
        }
    }
    void OnTestSuiteEnd(const ::testing::TestSuite& s) override {
        default_->OnTestSuiteEnd(s);
        auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::high_resolution_clock::now() - suiteStart_);
        std::cout << "\nTest Suite Complete: " << s.name() << " (" << dur.count() << " ms)\n"
            << "  Tests: " << s.total_test_count()
            << " | Passed: " << s.successful_test_count()
            << " | Failed: " << s.failed_test_count() << "\n\n";
    }
    void OnTestIterationEnd(const ::testing::UnitTest& u, int it) override {
        default_->OnTestIterationEnd(u, it);
        std::cout << "========================================================================\n"
            << "  TEST SUMMARY\n"
            << "========================================================================\n"
            << "  Total Tests:   " << total_ << "\n";
        if (total_ > 0) {
            auto pct = [](int a, int b) { return b ? (100.0 * a / b) : 0.0; };
            std::cout << "  Passed:        " << std::setw(3) << passed_
                << " (" << std::fixed << std::setprecision(1) << pct(passed_, total_) << "%)\n"
                << "  Failed:        " << std::setw(3) << failed_
                << " (" << std::fixed << std::setprecision(1) << pct(failed_, total_) << "%)\n";
        }
        else {
            std::cout << "  Passed:          0 (0.0%)\n"
                << "  Failed:          0 (0.0%)\n";
        }
        std::cout << "========================================================================\n";
        if (failed_ == 0 && total_ > 0)
            std::cout << "\n✓ ALL TESTS PASSED\n\n";
        else if (total_ == 0)
            std::cout << "\n✗ NO TESTS FOUND\n\n";
        else
            std::cout << "\n✗ TESTS FAILED\n\n";
    }
    // Remaining pass-throughs
    void OnTestProgramEnd(const ::testing::UnitTest& u) override { default_->OnTestProgramEnd(u); }
    void OnEnvironmentsSetUpStart(const ::testing::UnitTest& u) override { default_->OnEnvironmentsSetUpStart(u); }
    void OnEnvironmentsSetUpEnd(const ::testing::UnitTest& u) override { default_->OnEnvironmentsSetUpEnd(u); }
    void OnEnvironmentsTearDownStart(const ::testing::UnitTest& u) override { default_->OnEnvironmentsTearDownStart(u); }
    void OnEnvironmentsTearDownEnd(const ::testing::UnitTest& u) override { default_->OnEnvironmentsTearDownEnd(u); }
};

int main(int argc, char** argv) {
    LoggerConfig cfg{};
    cfg.toConsole = true;
    cfg.toFile = false;
    cfg.async = false;          // Keep synchronous in test mode
    cfg.flushLevel = LogLevel::Error;
    cfg.toEventLog = false;
    try {
        Logger::Instance().Initialize(cfg);
    }
    catch (const std::exception& ex) {
        std::cerr << "[FATAL] Logger exception: " << ex.what() << "\n";
        return 1;
    }
    catch (const std::system_error& se) {
        std::cerr << "[FATAL] Logger system_error: " << se.what()
            << " (code: " << se.code() << ")\n";
        return 1;
    }
    catch (...) {
        std::cerr << "[FATAL] Logger threw unknown exception during initialization\n";
        return 1;
    }

    if (!Logger::Instance().IsInitialized()) {
        std::cerr << "[FATAL] Logger not initialized\n";
        return 1;
    }

    std::cout << "\n========================================================================\n"
        << "  ShadowStrike CryptoUtils Test Runner\n"
        << "========================================================================\n\n";

    ::testing::InitGoogleTest(&argc, argv);

    auto& listeners = ::testing::UnitTest::GetInstance()->listeners();
    auto* defaultPrinter = listeners.Release(listeners.default_result_printer());
    listeners.Append(new DetailedTestListener(defaultPrinter));

    int discovered = ::testing::UnitTest::GetInstance()->total_test_count();
    if (discovered == 0) {
        std::cerr << "No tests discovered.\n";
        Logger::Instance().ShutDown();
        return 1;
    }

    int result = 0;
    try {
        result = RUN_ALL_TESTS();
    }
    catch (const std::exception& ex) {
        std::cerr << "[UNCAUGHT EXCEPTION] " << ex.what() << "\n";
        result = 1;
    }
    catch (...) {
        std::cerr << "[UNCAUGHT UNKNOWN EXCEPTION]\n";
        result = 1;
    }

    Logger::Instance().ShutDown();
    return result;
}