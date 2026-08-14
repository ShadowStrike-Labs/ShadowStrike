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
#include <gtest/gtest.h>

#include "../src/PhantomCore/Utils/Logger.hpp"

#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {

    // ============================================================================
    // Logger ownership for the test binary
    // ============================================================================
    //
    // WHY THIS EXISTS, and it is not cosmetic setup.
    //
    // Logger::EnsureInitialized() (Logger.cpp:116) is called from the logging
    // write path and flips m_initialized to true with a console-only default the
    // first time ANY code logs. Logger::Initialize() then CAS-guards that same
    // flag and silently ignores a later call. Together those two facts mean the
    // logger's configuration -- and whether IsInitialized() answers true at all
    // -- depended on whether some unrelated test had happened to log first.
    //
    // That was not a theoretical problem. The entire CryptoUtilsTest suite (30
    // cases covering AES-256-GCM including AAD-mismatch and truncated-tag
    // REJECTION, AES-CBC, RSA-2048, ECDH P-256, PBKDF2, HKDF, file/string
    // encryption and constant-time compare) gated its fixture on
    // Logger::IsInitialized() and called GTEST_SKIP() when it read false. So
    // 30 tests ran or did not run according to test ORDERING, and in practice
    // they did not run -- which left the cryptography behind the encrypted
    // kernel channel and the quarantine vault with no executed coverage.
    //
    // Initialising here, before RUN_ALL_TESTS, makes the state deterministic and
    // identical for every test regardless of order. It must happen in main()
    // rather than in a fixture precisely because of the CAS: the first writer
    // wins, and a fixture runs too late to be that writer.
    //
    // DELIBERATELY NO ShutDown() ANYWHERE HERE. Logger::~Logger() (Logger.cpp:93)
    // already calls ShutDown(), and the Logger is a singleton whose construction
    // completes first and whose destruction therefore happens last -- the same
    // property that makes it safe for ScanEngine's destructor to log during
    // static destruction (see tests/unit/scan_engine_teardown). Adding a global
    // TearDown that shut the logger down would (a) duplicate the destructor's
    // job and (b) silence any diagnostic emitted by teardown paths that run
    // after gtest returns, which is exactly where the scan-engine suite looks.
    class LoggerEnvironment : public ::testing::Environment {
    public:
        void SetUp() override {
            // The assertion is the point of this class, not the initialisation.
            // If someone later removes the Initialize call below, or a static
            // initialiser logs before main() and claims the CAS with the
            // console-only default, this fails loudly for the whole binary
            // instead of quietly restoring 30 skipped crypto tests. A guard that
            // silently stops guarding is worse than no guard.
            ASSERT_TRUE(::ShadowStrike::Utils::Logger::Instance().IsInitialized())
                << "The Logger was not initialised before the first test. Fixtures "
                   "that require it will skip or fail, and the configuration below "
                   "was ignored because Logger::Initialize CAS-guards the same flag "
                   "that the logging write path sets via EnsureInitialized().";
        }
    };

    void InitializeTestLogger() {
        ::ShadowStrike::Utils::LoggerConfig cfg{};

        // Console off: 4,886 tests emitting product log lines onto stdout would
        // bury googletest's own output and make a failure harder to find, which
        // is the opposite of what a test log is for.
        cfg.toConsole = false;

        // File on, and to a real file, because the product's file sink is itself
        // code under test here -- formatting, rotation and the write path all run.
        // A run that logs nowhere would satisfy IsInitialized() while exercising
        // none of it.
        cfg.toFile = true;
        cfg.toEventLog = false;

        // Outside the repository. A log written into the source tree is either
        // committed by accident or shows up as a dirty working tree on every run.
        std::error_code ec{};
        const auto logDir = std::filesystem::temp_directory_path(ec) / "phantom-tests-logs";
        if (!ec) {
            std::filesystem::create_directories(logDir, ec);
            cfg.logDirectory = logDir.wstring();
        }
        cfg.baseFileName = L"phantom-tests";

        // Bounded on purpose: 30 MB ceiling for the whole binary. Without this a
        // long run writes an unbounded file into the temp directory.
        cfg.maxFileSizeBytes = 10ULL * 1024ULL * 1024ULL;
        cfg.maxFileCount = 3;

        // Async with DropOldest so logging can never block a test or change its
        // timing. Several suites assert on durations and queue behaviour; a
        // synchronous file write on the test thread would make those depend on
        // disk latency. Dropping the oldest line under pressure is the right
        // trade here because the log is a diagnostic aid, not an assertion input.
        cfg.async = true;
        cfg.bpPolicy = ::ShadowStrike::Utils::LoggerConfig::BackPressurePolicy::DropOldest;

        // Production parity. The service runs at Info, and the SS_LOG_* macros
        // early-return on IsEnabled(), so raising the threshold here would stop
        // Info-level format strings in the code under test from ever being
        // formatted -- a defect in one of them would then be invisible to the
        // suite. Cost is bounded by the async queue and the size cap above.
        cfg.minimalLevel = ::ShadowStrike::Utils::LogLevel::Info;
        cfg.flushLevel = ::ShadowStrike::Utils::LogLevel::Error;

        ::ShadowStrike::Utils::Logger::Instance().Initialize(cfg);
    }

}  // namespace

namespace {

    // ========================================================================
    // SKIP REPORT - the structural defence against a silently disabled test
    // ========================================================================
    //
    // A skipped test reports neither pass nor fail. It contributes nothing and
    // costs nothing to leave in place, which is exactly what makes it the
    // easiest way for coverage to disappear without anyone noticing. gtest
    // prints skips inline among thousands of lines of output and then reports a
    // cheerful "[  PASSED  ] N tests" that does not mention them at all.
    //
    // THIS IS NOT HYPOTHETICAL IN THIS REPOSITORY. Established from git:
    //
    //   2026-04-08  9f1f8e6d  "fix: resolve all 253 Shared_modules compilation
    //                          errors" is the commit that changed the number of
    //                          GTEST_SKIP occurrences in CryptoUtils_Tests.cpp.
    //                          A commit whose stated purpose was fixing
    //                          compilation errors disabled a test suite, and
    //                          said nothing about it in its message.
    //   2026-08-14  7c62acc5  the file entered the build for the first time,
    //                          which is when those skips finally became visible
    //                          as 30 skipped tests.
    //
    // For four months the entire crypto suite was dark: AES-256-GCM including
    // AAD-mismatch and truncated-tag rejection, AES-CBC, RSA-2048, ECDH P-256,
    // PBKDF2, HKDF and constant-time compare. Those are the primitives the
    // encrypted kernel channel and the quarantine vault are built on.
    //
    // So this banner prints on EVERY run, including - deliberately - when the
    // count is zero. A report that only appears when something is wrong trains
    // the reader to expect silence, and silence is the failure mode here. Naming
    // the number every time is what makes a change in it obvious.
    //
    // Skips are reported rather than banned because some are legitimate: a test
    // whose precondition genuinely cannot exist on this host has nothing useful
    // to assert. TrustDetermination_Tests skips when a system binary is no
    // longer of the signing form the case is written to cover. The distinction
    // that matters is not skip-versus-no-skip, it is whether a human decided.
    // PHANTOM_TESTS_STRICT_NO_SKIP=1 turns any skip into a non-zero exit, for
    // CI or for a run where the answer is meant to be "everything executed".

    [[nodiscard]] std::string FirstSkipReason(const ::testing::TestResult* result) {
        if (result == nullptr) return {};
        for (int i = 0; i < result->total_part_count(); ++i) {
            const auto& part = result->GetTestPartResult(i);
            if (part.type() == ::testing::TestPartResult::kSkip) {
                std::string msg = part.message() != nullptr ? part.message() : "";
                // Collapse to a single line: these messages are multi-line and a
                // one-per-test report is far easier to scan.
                for (char& c : msg) {
                    if (c == '\n' || c == '\r') c = ' ';
                }
                if (msg.size() > 160) msg = msg.substr(0, 157) + "...";
                return msg;
            }
        }
        return {};
    }

    // Returns the number of skipped tests, after printing the report.
    int ReportSkippedTests() {
        const auto* unitTest = ::testing::UnitTest::GetInstance();
        if (unitTest == nullptr) return 0;

        struct SkippedCase {
            std::string name;
            std::string reason;
        };
        std::vector<SkippedCase> skipped;

        for (int s = 0; s < unitTest->total_test_suite_count(); ++s) {
            const auto* suite = unitTest->GetTestSuite(s);
            if (suite == nullptr) continue;
            for (int t = 0; t < suite->total_test_count(); ++t) {
                const auto* info = suite->GetTestInfo(t);
                if (info == nullptr) continue;
                // A test excluded by --gtest_filter never ran and is not a skip.
                if (!info->should_run()) continue;
                const auto* result = info->result();
                if (result == nullptr || !result->Skipped()) continue;
                skipped.push_back(
                    SkippedCase{std::string(info->test_suite_name()) + "." + info->name(),
                                FirstSkipReason(result)});
            }
        }

        const int ran = unitTest->test_to_run_count();

        std::cout << "\n"
                  << "================================================================================\n"
                  << " SKIP REPORT\n"
                  << "================================================================================\n"
                  << " " << ran << " tests were selected to run. " << skipped.size()
                  << " were SKIPPED.\n";

        if (skipped.empty()) {
            std::cout << "\n Every selected test executed and returned a real verdict.\n";
        } else {
            std::cout << "\n A skipped test reports neither pass nor fail. Each of these is a gap\n"
                         " in coverage until someone decides otherwise:\n\n";
            for (const auto& c : skipped) {
                std::cout << "   " << c.name << "\n";
                if (!c.reason.empty()) {
                    std::cout << "       reason: " << c.reason << "\n";
                }
            }
        }

        std::cout << "\n This banner prints on every run, including at zero, because a skip that\n"
                     " nobody sees is indistinguishable from coverage. Set\n"
                     " PHANTOM_TESTS_STRICT_NO_SKIP=1 to make any skip a non-zero exit.\n"
                  << "================================================================================\n"
                  << std::endl;

        return static_cast<int>(skipped.size());
    }

    [[nodiscard]] bool StrictNoSkipRequested() {
        char* value = nullptr;
        std::size_t len = 0;
        if (::_dupenv_s(&value, &len, "PHANTOM_TESTS_STRICT_NO_SKIP") != 0 || value == nullptr) {
            return false;
        }
        const bool on = (len > 0) && (value[0] != '\0') && (value[0] != '0');
        std::free(value);
        return on;
    }

}  // namespace

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Before RUN_ALL_TESTS and before any fixture: see the note above on the
    // Initialize/EnsureInitialized CAS. The first writer wins, so this has to be
    // the first thing that touches the logger in the process.
    InitializeTestLogger();

    ::testing::AddGlobalTestEnvironment(new LoggerEnvironment());

    const int gtestResult = RUN_ALL_TESTS();

    // After RUN_ALL_TESTS so every result is final. Reported unconditionally -
    // see the long note above ReportSkippedTests for why this is not optional.
    const int skippedCount = ReportSkippedTests();

    if (skippedCount > 0 && StrictNoSkipRequested()) {
        std::cout << "PHANTOM_TESTS_STRICT_NO_SKIP is set and " << skippedCount
                  << " test(s) were skipped: failing the run." << std::endl;
        // Deliberately does not mask a real gtest failure: if tests also failed,
        // that exit code is the more urgent one and is preserved.
        return gtestResult != 0 ? gtestResult : 2;
    }

    return gtestResult;
}
