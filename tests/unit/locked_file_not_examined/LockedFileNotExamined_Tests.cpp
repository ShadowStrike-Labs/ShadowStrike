// ===========================================================================
// LockedFileNotExamined_Tests.cpp
//
// A file another process holds open cannot be read by us. That is a platform
// condition, not a fault in this product, and it recurs for as long as the
// handle lives.
//
// THE 1.0.109 FIELD RUN measured what treating it as a fault costs. 16,175 of
// the run's 16,348 ERROR records were ERROR_SHARING_VIOLATION, and 15,979 of
// those came from three files:
//
//   ProgramData\Microsoft\Network\Downloader\edb.log       6,440
//   AppData\Local\Microsoft\Windows\WebCache\V01.log       5,785
//   Windows\SoftwareDistribution\DataStore\Logs\edb.log    3,754
//
// All three are ESE transaction logs held open exclusively by a Windows service
// - the BITS downloader, the WebCache and Windows Update - for as long as that
// service runs. They can never be opened by us, they are written constantly,
// and every write brings them back through the on-access path. One was
// re-attempted 1,725 times in a single run. The result was a 10.3 MB service
// log, 8.6x the size of 1.0.108's, in which the genuine faults were 173 records
// out of 16,348.
//
// THE ASSERTION THAT MATTERS MOST IS THE ONE ABOUT THE VERDICT. A file that was
// not examined must never be reported Clean. Reclassifying the log severity must
// not quietly become a fail-open, so that is pinned first and explicitly.
// ===========================================================================

#include "pch.h"
#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <Windows.h>

#include "../../../src/PhantomCore/Core/Engine/ScanEngine.hpp"
#include "../../../src/PhantomCore/Utils/FileUtils.hpp"

using ShadowStrike::Core::Engine::ScanEngine;
using ShadowStrike::Core::Engine::ScanVerdict;
using ShadowStrike::Core::Engine::EngineConfig;
using ShadowStrike::Core::Engine::ScanContext;
using ShadowStrike::Core::Engine::ScanType;

namespace {

// A file held open with dwShareMode 0, which is exactly what the ESE
// transaction logs in the field report do: no other process may read it.
class ExclusivelyHeldFile {
public:
    explicit ExclusivelyHeldFile(const std::string& tag) {
        m_dir = std::filesystem::temp_directory_path() / "phantom-locked-file";
        std::filesystem::create_directories(m_dir);
        m_path = m_dir / ("locked-" + tag + ".bin");

        {
            std::ofstream f(m_path, std::ios::binary | std::ios::trunc);
            const std::vector<char> filler(4096, 0x5A);
            f.write(filler.data(), static_cast<std::streamsize>(filler.size()));
        }

        // dwShareMode = 0: deny all sharing, which is what produces
        // ERROR_SHARING_VIOLATION for any other opener.
        m_handle = ::CreateFileW(m_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                                 0, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    ~ExclusivelyHeldFile() {
        if (m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
        }
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
    }

    ExclusivelyHeldFile(const ExclusivelyHeldFile&) = delete;
    ExclusivelyHeldFile& operator=(const ExclusivelyHeldFile&) = delete;

    [[nodiscard]] bool Held() const { return m_handle != INVALID_HANDLE_VALUE; }
    [[nodiscard]] const std::filesystem::path& Path() const { return m_path; }

private:
    std::filesystem::path m_dir;
    std::filesystem::path m_path;
    HANDLE m_handle = INVALID_HANDLE_VALUE;
};

void EnsureEngineReady() {
    auto& engine = ScanEngine::Instance();
    if (!engine.IsInitialized()) {
        EngineConfig config{};
        config.signatureDbPath.clear();
        config.enableHeuristics = false;
        config.enableMachineLearning = false;
        config.enableBehaviorAnalysis = false;
        config.enableCloudLookup = false;
        ASSERT_TRUE(engine.Initialize(config));
    }
    ASSERT_TRUE(engine.IsInitialized());
    // Shutdown is deliberately NOT called: tests/unit/scan_engine_teardown
    // registers a global environment requiring the engine to stay up.
}

} // namespace

// ---------------------------------------------------------------------------
// NOT EXAMINED MUST NOT MEAN CLEAN. This is the fail-open guard, and it is the
// reason the severity change elsewhere is safe.
// ---------------------------------------------------------------------------
TEST(LockedFileNotExaminedTest, ALockedFileIsNotReportedClean) {
    ASSERT_NO_FATAL_FAILURE(EnsureEngineReady());

    const ExclusivelyHeldFile locked("verdict");
    ASSERT_TRUE(locked.Held())
        << "could not take an exclusive handle, so this test cannot reproduce "
           "the field condition and must not report success";
    ASSERT_TRUE(std::filesystem::exists(locked.Path()));

    ScanContext context{};
    context.type = ScanType::OnDemand;
    const auto result =
        ScanEngine::Instance().ScanFile(locked.Path().wstring(), context);

    EXPECT_NE(result.verdict, ScanVerdict::Clean)
        << "a file that could not be opened was reported Clean - that is a "
           "fail-open on the scan path";

    EXPECT_EQ(result.verdict, ScanVerdict::Error)
        << "a file that could not be read should carry the Error verdict so the "
           "caller can apply its failure policy";
}

// ---------------------------------------------------------------------------
// The REASON must reach the caller, because that is what lets
// RealTimeProtection count a platform condition apart from a scan fault.
// ---------------------------------------------------------------------------
TEST(LockedFileNotExaminedTest, TheSharingViolationReachesTheCaller) {
    ASSERT_NO_FATAL_FAILURE(EnsureEngineReady());

    const ExclusivelyHeldFile locked("errorcode");
    ASSERT_TRUE(locked.Held());

    ScanContext context{};
    context.type = ScanType::OnDemand;
    const auto result =
        ScanEngine::Instance().ScanFile(locked.Path().wstring(), context);

    EXPECT_EQ(result.errorCode, static_cast<uint32_t>(ERROR_SHARING_VIOLATION))
        << "errorCode was " << result.errorCode
        << ", so the caller cannot tell a locked file from any other failure and "
           "must count it as a scan fault";

    EXPECT_TRUE(ShadowStrike::Utils::FileUtils::IsFileLockedError(result.errorCode))
        << "the engine's own error code is not recognised by the classifier that "
           "exists to recognise it";

    EXPECT_FALSE(result.errorMessage.empty())
        << "no reason was recorded for a file that was not examined";
}

// ---------------------------------------------------------------------------
// THE CLASSIFIER'S BOUNDARIES. The exclusion of ERROR_ACCESS_DENIED is the
// important half: that code can mean a real permissions defect or an attacker
// denying us a file, and classifying it as routine would hide it.
// ---------------------------------------------------------------------------
TEST(LockedFileNotExaminedTest, TheClassifierRecognisesOnlyHeldOpenCodes) {
    using ShadowStrike::Utils::FileUtils::IsFileLockedError;

    EXPECT_TRUE(IsFileLockedError(ERROR_SHARING_VIOLATION));   // 32
    EXPECT_TRUE(IsFileLockedError(ERROR_LOCK_VIOLATION));      // 33
    EXPECT_TRUE(IsFileLockedError(ERROR_USER_MAPPED_FILE));    // 1224

    EXPECT_FALSE(IsFileLockedError(ERROR_ACCESS_DENIED))
        << "ERROR_ACCESS_DENIED must NOT be classified as routine: it can be a "
           "real permissions defect or an attacker denying us a file, and "
           "folding it in would relabel a genuine failure as expected";

    EXPECT_FALSE(IsFileLockedError(ERROR_SUCCESS));
    EXPECT_FALSE(IsFileLockedError(ERROR_FILE_NOT_FOUND));
    EXPECT_FALSE(IsFileLockedError(ERROR_PATH_NOT_FOUND));
    EXPECT_FALSE(IsFileLockedError(ERROR_DISK_FULL));
}

// ---------------------------------------------------------------------------
// The two not-examined classes must stay distinct. A cloud placeholder and a
// locked file need different remedies - fetch the content versus wait for the
// holder - so a single counter for both would be useless, which is the mistake
// the cloud counter was originally introduced to correct.
// ---------------------------------------------------------------------------
TEST(LockedFileNotExaminedTest, TheTwoNotExaminedClassesDoNotOverlap) {
    using ShadowStrike::Utils::FileUtils::IsFileLockedError;
    using ShadowStrike::Utils::FileUtils::IsContentNotLocalError;

    const DWORD lockedCodes[] = {
        ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_USER_MAPPED_FILE
    };
    for (const DWORD code : lockedCodes) {
        EXPECT_TRUE(IsFileLockedError(code));
        EXPECT_FALSE(IsContentNotLocalError(code))
            << "code " << code << " is classified as BOTH held-open and "
               "not-local, so the two counters would double-count it";
    }

    // ERROR_CLOUD_FILE_ACCESS_DENIED (395) is the code from the 1.0.94 run.
    EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_ACCESS_DENIED));
    EXPECT_FALSE(IsFileLockedError(ERROR_CLOUD_FILE_ACCESS_DENIED))
        << "a cloud placeholder is being reported as held open by another "
           "process, which points at the wrong remedy";
}
