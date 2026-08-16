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

// Windows headers come first, and the two guards below are load-bearing rather
// than habitual: <windows.h> defines min/max as macros unless NOMINMAX is set,
// which breaks std::min/std::max in every header pulled in afterwards - and
// googletest includes <windows.h> itself on this platform, so if it got there
// first these defines would arrive too late to have any effect.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <aclapi.h>

// SetNamedSecurityInfoW lives in advapi32. Named here rather than in the project
// file so this translation unit states its own dependency.
#pragma comment(lib, "advapi32.lib")

#include <gtest/gtest.h>

#include "../src/PhantomCore/Utils/Logger.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace {

    // ========================================================================
    // PROCESS-SCOPED TEMPORARY SANDBOX
    // ========================================================================
    //
    // MEASURED, not suspected. One clean, fully passing run of this binary
    // (5,016 tests from 518 suites, exit 0, zero skips) left 136 files and
    // 14,142 MB behind in the system temporary directory. 133 of those files
    // and 14,134 MB of that total were ThreatIntel databases: 131 x 100 MB,
    // one x 1 GB and one x 10 MB. Ten full-suite runs is 138 GB of disk that
    // nothing ever reclaims, and the files are not sparse - logical size and
    // allocated size were both confirmed at 104,857,600 bytes each.
    //
    // WHERE THEY COME FROM. ThreatIntelStore::Initialize() taking no arguments
    // substitutes StoreConfig::CreateDefault(), and that factory mints a UNIQUE
    // file name under GetTempPathW() per instance (process id plus a monotonic
    // counter). Several suites legitimately exercise that default-configuration
    // path, so each such call produced another 100 MB file with no owner. The
    // product-side defect - that a configuration factory chooses a storage
    // location at all, and that two production callers still ship a 1 GB and a
    // 10 MB throwaway database into a world-writable directory - is tracked
    // separately. It is a security and correctness matter in its own right and
    // is deliberately NOT conflated with this change.
    //
    // WHY THIS IS SOLVED HERE AND NOT IN 57 TEST FILES. 57 files under tests/
    // reach into the system temporary directory across 73 call sites, and 62 of
    // them already attempt their own cleanup across 106 removal calls. So the
    // missing ingredient is not care - it is a structure that can hold. Per-file
    // cleanup fails in three ways that no amount of diligence repairs:
    //
    //   1. A fatal assertion in SetUp() means googletest never calls TearDown(),
    //      so the cleanup a fixture carefully wrote does not run at all.
    //   2. A crash or an external kill takes the process out. This suite has
    //      produced faults during static destruction before (the whole of
    //      tests/unit/scan_engine_teardown exists because of one), and the
    //      bounded runner used against this binary calls Kill() when a run
    //      exceeds its deadline. A killed process runs no teardown, ever.
    //   3. Every test added in future is another chance to forget.
    //
    // So ownership moves to the only scope that can actually hold it: the
    // process. Everything the run writes goes inside ONE directory, and that
    // directory is removed when the process ends.
    //
    // NOTHING ABOUT ANY TEST IS WEAKENED BY THIS. Every file is still really
    // created, at its real size, through the real code path; every allocation,
    // memory mapping and rotation still happens; no assertion, threshold or
    // size constant is relaxed anywhere. Only the LOCATION changes, and the
    // lifetime acquires an owner.
    //
    // THE REDIRECT IS WHAT MAKES THIS COVER PRODUCT CODE. GetTempPathW reads the
    // process environment block, so setting TEMP and TMP for this process moves
    // std::filesystem::temp_directory_path() AND every GetTempPathW call inside
    // the code under test - including StoreConfig::CreateDefault(), which this
    // file has no other way to reach. That is precisely why the mechanism is an
    // environment redirect rather than a helper that 57 files must remember to
    // call: a helper only covers the call sites someone converted, while the
    // redirect covers the ones nobody has written yet.
    //
    // ORPHANS ARE RECLAIMED AT STARTUP, AND THAT IS THE HALF THAT SURVIVES A
    // CRASH. Removing the directory at exit alone would still leak on every
    // killed or faulting run - which, given the bounded runner, is not a rare
    // case. Each run therefore also sweeps the sandbox root for directories
    // belonging to processes that no longer exist. A directory whose owning
    // process is still alive is LEFT ALONE: process id reuse can then only ever
    // cause this to skip a directory, never to delete a live run's working set,
    // and a skipped orphan is reclaimed by some later run. Conservative in the
    // safe direction, and bounded either way.

    [[nodiscard]] std::uintmax_t DirectorySizeBytes(const std::filesystem::path& dir) {
        std::error_code ec{};
        std::filesystem::recursive_directory_iterator it(
            dir, std::filesystem::directory_options::skip_permission_denied, ec);
        if (ec) return 0;

        const std::filesystem::recursive_directory_iterator end{};
        std::uintmax_t total = 0;
        for (; it != end; it.increment(ec)) {
            if (ec) break;
            std::error_code fec{};
            if (it->is_regular_file(fec) && !fec) {
                const auto sz = it->file_size(fec);
                if (!fec) total += sz;
            }
        }
        return total;
    }

    // Treats "cannot tell" as alive, deliberately. The only consequence of a
    // false positive here is that a directory is left for a later run to
    // reclaim; the consequence of a false negative would be deleting the
    // working set of a running test process, which must never happen.
    [[nodiscard]] bool ProcessIsAlive(DWORD pid) {
        if (pid == 0) return true;

        const HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (h == nullptr) {
            // ERROR_INVALID_PARAMETER is the documented answer for "no process
            // has that id". Anything else - ERROR_ACCESS_DENIED in particular -
            // means a process does exist and we simply may not inspect it.
            return ::GetLastError() != ERROR_INVALID_PARAMETER;
        }

        DWORD exitCode = 0;
        const bool queried = ::GetExitCodeProcess(h, &exitCode) != FALSE;
        ::CloseHandle(h);
        return !queried || exitCode == STILL_ACTIVE;
    }

    [[nodiscard]] bool KeepSandboxRequested() {
        char* value = nullptr;
        std::size_t len = 0;
        if (::_dupenv_s(&value, &len, "PHANTOM_TESTS_KEEP_TEMP") != 0 || value == nullptr) {
            return false;
        }
        const bool on = (len > 0) && (value[0] != '\0') && (value[0] != '0');
        std::free(value);
        return on;
    }

    // Restores this process's own access to an entry it created, so a file the
    // code under test deliberately hardened can still be reclaimed afterwards.
    //
    // MEASURED NEED, not defensive programming. EventLogger_Tests.cpp:284 has the
    // product write a forensic evidence buffer, and the product hardens that file
    // to SYSTEM and BUILTIN\Administrators only - which is CORRECT behaviour for
    // tamper-resistant evidence and is not a defect. The test binary does not run
    // elevated, so it ends up owning a 654-byte file it has no granted right to
    // delete. That single file aborted the removal of 14,135 MB, because
    // std::filesystem::remove_all stops at its first error and NTFS enumerated
    // ShadowStrike_CoreSystem_UT_* before ShadowStrike_ThreatIntel_*.
    //
    // A NULL DACL means "no protection at all", which would be indefensible on
    // product data. It is applied ONLY to a path inside a scratch directory this
    // process created for itself and is in the act of deleting, and only after a
    // normal delete has already been refused. The owner of an object always
    // retains the right to rewrite its DACL, so this needs no privilege the run
    // does not already have.
    void RestoreOwnAccessForDeletion(const std::filesystem::path& target) noexcept {
        const DWORD attrs = ::GetFileAttributesW(target.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY) != 0) {
            // Read-only defeats deletion regardless of the DACL, so it is cleared
            // first and independently.
            (void)::SetFileAttributesW(target.c_str(), attrs & ~FILE_ATTRIBUTE_READONLY);
        }

        std::wstring mutablePath = target.wstring();
        (void)::SetNamedSecurityInfoW(mutablePath.data(), SE_FILE_OBJECT,
                                      DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                      nullptr, nullptr);
    }

    struct RemovalOutcome {
        std::uintmax_t            bytesRemoved = 0;
        std::size_t               entriesRemoved = 0;
        std::vector<std::string>  resisted{};
    };

    // Deletes depth-first, one entry at a time, and CONTINUES PAST FAILURES.
    // That difference is the whole point: remove_all() treats the tree as a
    // single operation, so anything it cannot delete protects everything it has
    // not yet visited. Here a stubborn entry costs only itself, and is named.
    void RemoveTreeInto(const std::filesystem::path& dir, RemovalOutcome& outcome) {
        std::error_code ec{};
        std::filesystem::directory_iterator it(
            dir, std::filesystem::directory_options::skip_permission_denied, ec);

        if (!ec) {
            const std::filesystem::directory_iterator end{};
            for (; it != end; it.increment(ec)) {
                if (ec) break;

                const std::filesystem::path entry = it->path();

                std::error_code kindEc{};
                const bool isDirectory = it->is_directory(kindEc) && !kindEc;
                if (isDirectory) {
                    RemoveTreeInto(entry, outcome);
                    continue;
                }

                std::error_code sizeEc{};
                const std::uintmax_t size = std::filesystem::file_size(entry, sizeEc);

                std::error_code rmEc{};
                bool removed = std::filesystem::remove(entry, rmEc);
                if (!removed || rmEc) {
                    RestoreOwnAccessForDeletion(entry);
                    rmEc.clear();
                    removed = std::filesystem::remove(entry, rmEc);
                }

                if (!removed || rmEc) {
                    outcome.resisted.push_back(entry.string());
                    continue;
                }

                outcome.entriesRemoved += 1;
                if (!sizeEc) outcome.bytesRemoved += size;
            }
        }

        std::error_code dirEc{};
        bool dirRemoved = std::filesystem::remove(dir, dirEc);
        if (!dirRemoved || dirEc) {
            RestoreOwnAccessForDeletion(dir);
            dirEc.clear();
            dirRemoved = std::filesystem::remove(dir, dirEc);
        }

        if (dirRemoved && !dirEc) {
            outcome.entriesRemoved += 1;
        } else if (outcome.resisted.empty()) {
            // Only reported when nothing inside it resisted; otherwise the
            // directory's survival is already explained by its contents.
            outcome.resisted.push_back(dir.string());
        }
    }

    [[nodiscard]] RemovalOutcome RemoveTreeRobustly(const std::filesystem::path& root) {
        RemovalOutcome outcome{};
        std::error_code ec{};
        if (!std::filesystem::exists(root, ec) || ec) return outcome;
        RemoveTreeInto(root, outcome);
        return outcome;
    }

    class TempSandbox {
    public:
        static TempSandbox& Instance() {
            static TempSandbox s_instance;
            return s_instance;
        }

        [[nodiscard]] bool Establish() {
            std::error_code ec{};

            // Captured BEFORE the redirect, because the logger is deliberately
            // kept outside the sandbox and needs the real location.
            m_systemTemp = std::filesystem::temp_directory_path(ec);
            if (ec || m_systemTemp.empty()) {
                m_failure = "the system temporary directory could not be resolved";
                return false;
            }

            m_root = m_systemTemp / L"phantom-tests-sandbox";
            std::filesystem::create_directories(m_root, ec);
            if (ec) {
                m_failure = "the sandbox root could not be created: " + ec.message();
                return false;
            }

            // Process id identifies the owner so a later run can tell whether
            // this directory is still in use. The tick count keeps the name
            // unique if a process id is reused within one boot.
            m_ownerPid = ::GetCurrentProcessId();
            const std::wstring runName =
                L"run-" + std::to_wstring(m_ownerPid) + L"-" +
                std::to_wstring(static_cast<unsigned long long>(::GetTickCount64()));

            m_run = m_root / runName;
            std::filesystem::create_directories(m_run, ec);
            if (ec) {
                m_failure = "the per-run sandbox directory could not be created: " + ec.message();
                return false;
            }

            // Sweep before redirecting, so a failure here cannot leave this run
            // pointed at a directory it then deletes.
            m_reclaimed = SweepOrphans();

            const std::wstring runPath = m_run.wstring();

            // SetEnvironmentVariableW is the one that matters: GetTempPathW
            // reads the Win32 process environment block, and that is what both
            // std::filesystem::temp_directory_path() and the product code under
            // test ultimately consult.
            if (::SetEnvironmentVariableW(L"TMP", runPath.c_str()) == FALSE ||
                ::SetEnvironmentVariableW(L"TEMP", runPath.c_str()) == FALSE) {
                m_failure = "the TEMP/TMP redirect was refused by the operating system";
                return false;
            }

            // The CRT keeps its own copy of the environment for getenv/_wgetenv.
            // Setting both means code that reads either view agrees, instead of
            // the answer depending on which API a given module happens to use.
            (void)::_wputenv_s(L"TMP", runPath.c_str());
            (void)::_wputenv_s(L"TEMP", runPath.c_str());

            m_established = true;
            return true;
        }

        void Report() const {
            std::cout << "\n"
                      << "================================================================================\n"
                      << " TEMPORARY FILE SANDBOX\n"
                      << "================================================================================\n";
            if (!m_established) {
                std::cout << " NOT ESTABLISHED: " << m_failure << "\n"
                          << " Files written to the system temporary directory by this run will NOT\n"
                          << " be reclaimed. This is reported rather than ignored because a silent\n"
                          << " fallback here is what allowed 14 GB per run to accumulate unnoticed.\n"
                          << "================================================================================\n"
                          << std::endl;
                return;
            }
            std::cout << " This run's temporary files are confined to:\n   "
                      << m_run.string() << "\n"
                      << " TEMP and TMP are redirected there for this process, so both the test code\n"
                      << " and the product code under test write inside it.\n";
            if (m_reclaimed.directories > 0 || m_reclaimed.partial > 0) {
                std::cout << " Reclaimed " << m_reclaimed.directories
                          << " orphaned sandbox(es) from earlier runs that ended without cleanup";
                if (m_reclaimed.partial > 0) {
                    std::cout << ", and partially reclaimed " << m_reclaimed.partial << " more";
                }
                std::cout << ", freeing " << FormatMb(m_reclaimed.bytes) << " MB.\n";
            } else {
                std::cout << " No orphaned sandboxes from earlier runs were found.\n";
            }
            std::cout << "================================================================================\n"
                      << std::endl;
        }

        void Dispose() noexcept {
            if (!m_established) return;

            const std::uintmax_t heldAtExit = DirectorySizeBytes(m_run);

            std::cout << "\n"
                      << "================================================================================\n"
                      << " TEMPORARY FILE SANDBOX - DISPOSAL\n"
                      << "================================================================================\n"
                      << " Held at exit: " << FormatMb(heldAtExit) << " MB in "
                      << m_run.string() << "\n";

            if (KeepSandboxRequested()) {
                std::cout << " PHANTOM_TESTS_KEEP_TEMP is set, so the directory is being LEFT IN PLACE\n"
                          << " for inspection. It will be reclaimed automatically by the next run once\n"
                          << " this process has exited. Unset the variable to dispose of it here.\n"
                          << "================================================================================\n"
                          << std::endl;
                return;
            }

            const RemovalOutcome outcome = RemoveTreeRobustly(m_run);

            std::cout << " Removed " << outcome.entriesRemoved << " entr"
                      << (outcome.entriesRemoved == 1 ? "y" : "ies") << ", reclaiming "
                      << FormatMb(outcome.bytesRemoved) << " MB.\n";

            if (!outcome.resisted.empty()) {
                std::cout << " " << outcome.resisted.size() << " path"
                          << (outcome.resisted.size() == 1 ? "" : "s")
                          << " could not be removed, named below. Reported rather than\n"
                          << " swallowed: an unreclaimable path is either a handle still held at\n"
                          << " exit or a permission this run cannot recover, and both are worth\n"
                          << " knowing about. They are retried by the next run's startup sweep.\n";
                std::size_t shown = 0;
                for (const auto& path : outcome.resisted) {
                    if (shown == 5) {
                        std::cout << "   ... and " << (outcome.resisted.size() - shown)
                                  << " more\n";
                        break;
                    }
                    std::cout << "   " << path << "\n";
                    ++shown;
                }
            }

            // The root goes only when it is empty, so a concurrently running
            // suite keeps its own directory.
            std::error_code rootEc{};
            std::filesystem::remove(m_root, rootEc);

            std::cout << "================================================================================\n"
                      << std::endl;
        }

        [[nodiscard]] const std::filesystem::path& SystemTemp() const noexcept { return m_systemTemp; }
        [[nodiscard]] const std::filesystem::path& Run() const noexcept { return m_run; }
        [[nodiscard]] bool Established() const noexcept { return m_established; }
        [[nodiscard]] const std::string& FailureReason() const noexcept { return m_failure; }

    private:
        struct Reclaimed {
            std::size_t     directories = 0;
            std::size_t     partial = 0;
            std::uintmax_t  bytes = 0;
        };

        TempSandbox() = default;

        [[nodiscard]] static std::string FormatMb(std::uintmax_t bytes) {
            const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
            char buf[64]{};
            (void)::sprintf_s(buf, sizeof(buf), "%.2f", mb);
            return std::string(buf);
        }

        // Parses the owning process id back out of "run-<pid>-<ticks>".
        // Returns 0 when the name is not one of ours, which ProcessIsAlive
        // treats as alive so an unrecognised directory is never deleted.
        [[nodiscard]] static DWORD OwnerPidFromName(const std::wstring& name) {
            constexpr std::wstring_view prefix = L"run-";
            if (name.size() <= prefix.size() || name.compare(0, prefix.size(), prefix) != 0) {
                return 0;
            }
            const std::size_t dash = name.find(L'-', prefix.size());
            if (dash == std::wstring::npos) return 0;

            const std::wstring pidText = name.substr(prefix.size(), dash - prefix.size());
            if (pidText.empty()) return 0;
            for (const wchar_t c : pidText) {
                if (c < L'0' || c > L'9') return 0;
            }
            try {
                const unsigned long parsed = std::stoul(pidText);
                return static_cast<DWORD>(parsed);
            } catch (...) {
                return 0;
            }
        }

        [[nodiscard]] Reclaimed SweepOrphans() const {
            Reclaimed result{};

            std::error_code ec{};
            std::filesystem::directory_iterator it(m_root, ec);
            if (ec) return result;

            const std::filesystem::directory_iterator end{};
            for (; it != end; it.increment(ec)) {
                if (ec) break;

                std::error_code dirEc{};
                if (!it->is_directory(dirEc) || dirEc) continue;

                const std::filesystem::path candidate = it->path();
                if (candidate == m_run) continue;

                const DWORD owner = OwnerPidFromName(candidate.filename().wstring());
                if (owner == m_ownerPid) continue;      // ours, differently stamped
                if (ProcessIsAlive(owner)) continue;    // in use, or unrecognised

                const RemovalOutcome outcome = RemoveTreeRobustly(candidate);
                result.bytes += outcome.bytesRemoved;

                if (outcome.resisted.empty()) {
                    result.directories += 1;
                } else {
                    // Partially reclaimed. The bytes actually freed are already
                    // counted above, so the reported figure never overstates what
                    // happened, and whatever survived is retried by a later run.
                    result.partial += 1;
                }
            }

            return result;
        }

        std::filesystem::path m_systemTemp{};
        std::filesystem::path m_root{};
        std::filesystem::path m_run{};
        DWORD                 m_ownerPid = 0;
        bool                  m_established = false;
        std::string           m_failure{};
        Reclaimed             m_reclaimed{};
    };

    // The assertion is the point of this class, exactly as with
    // LoggerEnvironment above. If the redirect ever silently stops taking
    // effect - a future edit reordering main(), or a platform change to how
    // GetTempPathW resolves - the whole binary fails loudly on the first test
    // rather than quietly resuming the accumulation of 14 GB per run. A guard
    // that stops guarding without saying so is worse than no guard.
    class SandboxEnvironment : public ::testing::Environment {
    public:
        void SetUp() override {
            const auto& sandbox = TempSandbox::Instance();
            ASSERT_TRUE(sandbox.Established())
                << "The temporary sandbox was not established: " << sandbox.FailureReason();

            std::error_code ec{};
            const auto resolved = std::filesystem::temp_directory_path(ec);
            ASSERT_FALSE(ec) << "temp_directory_path() failed after the redirect: " << ec.message();

            ASSERT_EQ(std::filesystem::weakly_canonical(resolved, ec),
                      std::filesystem::weakly_canonical(sandbox.Run(), ec))
                << "std::filesystem::temp_directory_path() does not resolve inside the sandbox, "
                   "so temporary files created by this run will not be reclaimed. Resolved to: "
                << resolved.string() << " but the sandbox is " << sandbox.Run().string();
        }
    };

}  // namespace

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

    void InitializeTestLogger(const std::filesystem::path& logDirectory) {
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
        //
        // ALSO OUTSIDE THE TEMPORARY SANDBOX, and that is deliberate: the
        // sandbox is deleted when the run ends, and a diagnostic that disappears
        // with the run it describes cannot be used to investigate it. The caller
        // passes the real temporary directory, captured before the redirect.
        // This log is not part of the growth problem the sandbox solves - it is
        // bounded by the rotation settings below at 30 MB, measured at 7.5 MB
        // for a full 5,016-test run.
        std::error_code ec{};
        std::filesystem::create_directories(logDirectory, ec);
        if (!ec) {
            cfg.logDirectory = logDirectory.wstring();
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

    // ------------------------------------------------------------------------
    // The sandbox is established FIRST - before the logger, before any global
    // environment and before any fixture - because it changes where every
    // subsequent temporary path in this process resolves. Anything that ran
    // beforehand would still be writing into the real temporary directory, and
    // those files would not be reclaimed by anyone.
    // ------------------------------------------------------------------------
    auto& sandbox = TempSandbox::Instance();
    const bool sandboxReady = sandbox.Establish();
    sandbox.Report();

    std::filesystem::path logRoot = sandbox.SystemTemp();
    if (logRoot.empty()) {
        std::error_code ec{};
        logRoot = std::filesystem::temp_directory_path(ec);
    }

    // Before RUN_ALL_TESTS and before any fixture: see the note above on the
    // Initialize/EnsureInitialized CAS. The first writer wins, so this has to be
    // the first thing that touches the logger in the process.
    InitializeTestLogger(logRoot / "phantom-tests-logs");

    ::testing::AddGlobalTestEnvironment(new LoggerEnvironment());

    // Registered only when the sandbox is genuinely in place. Registering it
    // unconditionally would turn a host that legitimately has no usable
    // temporary directory into 5,016 identical failures, which reports the wrong
    // defect entirely - and Report() above has already said so on stdout.
    if (sandboxReady) {
        ::testing::AddGlobalTestEnvironment(new SandboxEnvironment());
    }

    const int gtestResult = RUN_ALL_TESTS();

    // After RUN_ALL_TESTS so every result is final. Reported unconditionally -
    // see the long note above ReportSkippedTests for why this is not optional.
    const int skippedCount = ReportSkippedTests();

    // Disposal happens here, in main, rather than in a global environment's
    // TearDown - and that is a considered choice, not convenience. A fatal
    // failure in another environment's SetUp can cause googletest to skip
    // TearDown, which is the very trap that makes per-fixture cleanup
    // unreliable and this sandbox necessary. main() returning is the one point
    // that is reached on every path a process actually survives.
    //
    // A process that does NOT survive - a crash, or the bounded runner's Kill()
    // on a timeout - never reaches here at all. That case is covered by the
    // startup sweep in Establish(), not by this call.
    sandbox.Dispose();

    if (skippedCount > 0 && StrictNoSkipRequested()) {
        std::cout << "PHANTOM_TESTS_STRICT_NO_SKIP is set and " << skippedCount
                  << " test(s) were skipped: failing the run." << std::endl;
        // Deliberately does not mask a real gtest failure: if tests also failed,
        // that exit code is the more urgent one and is preserved.
        return gtestResult != 0 ? gtestResult : 2;
    }

    return gtestResult;
}
