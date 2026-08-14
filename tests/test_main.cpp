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

#include <filesystem>
#include <string>

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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    // Before RUN_ALL_TESTS and before any fixture: see the note above on the
    // Initialize/EnsureInitialized CAS. The first writer wins, so this has to be
    // the first thing that touches the logger in the process.
    InitializeTestLogger();

    ::testing::AddGlobalTestEnvironment(new LoggerEnvironment());

    return RUN_ALL_TESTS();
}
