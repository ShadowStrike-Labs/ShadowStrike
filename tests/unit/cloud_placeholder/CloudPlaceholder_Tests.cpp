// ============================================================================
//  CloudPlaceholder_Tests.cpp
//
//  Covers the cloud-placeholder handling added for task 90.
//
//  WHAT THE FIELD SHOWED, and why this file exists: in the 1.0.94 run
//  eicar.com and eicar_com.zip were both physically present on the user's
//  Desktop, inside OneDrive, and every attempt to read either returned
//  WinError 395 (ERROR_CLOUD_FILE_ACCESS_DENIED). A known-malicious file could
//  not be examined, and the result was indistinguishable from a clean scan.
//
//  WHAT THESE TESTS CAN AND CANNOT PROVE - stated plainly, because the limit
//  matters more than the count:
//
//    CAN: the tag classification the fix rests on, the error mapping, the
//    handle-free property of the locality probe, and that none of the existing
//    behaviour regressed.
//
//    CANNOT: the placeholder path itself. Creating a real dehydrated
//    placeholder needs a registered Cloud Filter provider, and reproducing the
//    denial additionally needs the caller to be a service in session 0 - which
//    is precisely the condition that cannot be met from a test process. The
//    build host has an empty OneDrive folder, no sync engine running, and no
//    file anywhere carrying FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, all measured
//    rather than assumed. That half is verifiable only in the field, and the
//    new ContentNotLocal reason plus the DEBUG lines are what will report it.
//
//  So these tests pin the DECISIONS, not the platform interaction. That is the
//  half that can silently rot: someone simplifying the reparse check back to
//  "refuse anything with a reparse point" reintroduces the exact coverage loss
//  this change removed, and NameSurrogate_DataVirtualisingTagsAreAllowed is
//  what stops that landing quietly.
// ============================================================================

#include <gtest/gtest.h>

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "PhantomCore/Utils/FileUtils.hpp"
#include "PhantomCore/Utils/HashUtils.hpp"
#include "PhantomCore/SignatureStore/SignatureStore.hpp"

namespace {

    using ShadowStrike::Utils::FileUtils::ContentLocality;
    using ShadowStrike::Utils::FileUtils::GetContentLocality;
    using ShadowStrike::Utils::FileUtils::IsContentNotLocalError;

    namespace fs = std::filesystem;

    // ------------------------------------------------------------------------
    // Fixture. Names are deliberately unique to this file - PhantomTests fails
    // the build on duplicate fixture names, because two identically named
    // fixtures in different translation units is an ODR violation that
    // googletest cannot detect (task 73).
    // ------------------------------------------------------------------------
    class CloudPlaceholderFilesTest : public ::testing::Test {
    protected:
        void SetUp() override {
            wchar_t tempPath[MAX_PATH]{};
            const DWORD n = ::GetTempPathW(MAX_PATH, tempPath);
            ASSERT_GT(n, 0u) << "could not resolve a temp directory";

            // Process id plus a monotonic counter is enough to be unique here
            // and avoids pulling COM in for a directory name. The counter makes
            // each case in this fixture independent even within one run.
            static unsigned long long counter = 0;
            const std::wstring unique =
                L"ss_cloud_" + std::to_wstring(::GetCurrentProcessId()) +
                L"_" + std::to_wstring(::GetTickCount64()) +
                L"_" + std::to_wstring(++counter);

            dir_ = fs::path(tempPath) / unique;
            std::error_code ec;
            fs::create_directories(dir_, ec);
            ASSERT_FALSE(ec) << "could not create the test directory";
        }

        void TearDown() override {
            std::error_code ec;
            fs::remove_all(dir_, ec);   // best effort; a leftover temp dir is not a failure
        }

        // Writes exact bytes. Returns the path.
        std::wstring WriteFile(const wchar_t* name, const std::string& content) {
            const fs::path p = dir_ / name;
            std::ofstream f(p, std::ios::binary | std::ios::trunc);
            f.write(content.data(), static_cast<std::streamsize>(content.size()));
            f.close();
            return p.wstring();
        }

        fs::path dir_;
    };

    // ========================================================================
    // THE CLASSIFICATION THE WHOLE FIX RESTS ON
    //
    // Two entirely different things carry FILE_ATTRIBUTE_REPARSE_POINT. The
    // old code refused both, which meant no file carrying any reparse tag
    // could be hashed - and every file in a OneDrive sync root carries a cloud
    // tag whether or not its content is resident. IsReparseTagNameSurrogate
    // (bit 29 of the tag) is the documented test that separates them.
    // ========================================================================

    TEST(CloudPlaceholderNameSurrogateTest, RedirectingTagsAreNameSurrogates) {
        // These REDIRECT to another object. Following one would hash a file the
        // caller never named, which is the attack the refusal exists to stop.
        // It must keep being refused.
        EXPECT_NE(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(IO_REPARSE_TAG_SYMLINK)))
            << "a symlink must be treated as a redirection";
        EXPECT_NE(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(IO_REPARSE_TAG_MOUNT_POINT)))
            << "a junction / mount point must be treated as a redirection";
    }

    TEST(CloudPlaceholderNameSurrogateTest, DataVirtualisingTagsAreAllowed) {
        // THIS IS THE DISCRIMINATOR FOR THE WHOLE CHANGE. These tags do not
        // redirect anywhere - the path IS the file and the tag only says the
        // bytes are produced by a filter. If someone reverts the check to
        // "refuse any reparse point", this test fails, which is the point.
        EXPECT_EQ(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(IO_REPARSE_TAG_CLOUD)))
            << "a cloud placeholder does not redirect and must remain hashable";
        EXPECT_EQ(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(IO_REPARSE_TAG_WOF)))
            << "WOF-compressed files must remain hashable";
        EXPECT_EQ(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(IO_REPARSE_TAG_DEDUP)))
            << "deduplicated files must remain hashable";
    }

    TEST(CloudPlaceholderNameSurrogateTest, EveryTagInTheCloudFamilyIsAllowed) {
        // OneDrive is only one provider. The cloud family is 16 tags and a
        // machine with several sync providers will use more than one of them,
        // so the classification has to hold across the whole range rather than
        // just the base tag.
        const ULONG cloudTags[] = {
            IO_REPARSE_TAG_CLOUD,   IO_REPARSE_TAG_CLOUD_1, IO_REPARSE_TAG_CLOUD_2,
            IO_REPARSE_TAG_CLOUD_3, IO_REPARSE_TAG_CLOUD_4, IO_REPARSE_TAG_CLOUD_5,
            IO_REPARSE_TAG_CLOUD_6, IO_REPARSE_TAG_CLOUD_7, IO_REPARSE_TAG_CLOUD_8,
            IO_REPARSE_TAG_CLOUD_9, IO_REPARSE_TAG_CLOUD_A, IO_REPARSE_TAG_CLOUD_B,
            IO_REPARSE_TAG_CLOUD_C, IO_REPARSE_TAG_CLOUD_D, IO_REPARSE_TAG_CLOUD_E,
            IO_REPARSE_TAG_CLOUD_F
        };

        for (const ULONG tag : cloudTags) {
            EXPECT_EQ(0u, static_cast<unsigned>(IsReparseTagNameSurrogate(tag)))
                << "cloud tag 0x" << std::hex << tag
                << " was classified as a redirection, which would make it unhashable";
        }
    }

    // ========================================================================
    // ERROR MAPPING
    // ========================================================================

    TEST(CloudPlaceholderErrorTest, TheErrorSeenInTheFieldIsRecognised) {
        // 395 is not an arbitrary choice of constant: it is the literal value
        // logged against eicar.com on the user's Desktop.
        EXPECT_EQ(395, ERROR_CLOUD_FILE_ACCESS_DENIED)
            << "the constant moved; the field evidence was recorded against 395";
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_ACCESS_DENIED));
    }

    TEST(CloudPlaceholderErrorTest, EveryFetchFailureIsRecognised) {
        // All of these mean the same actionable thing: the cloud filter did not
        // give us the bytes, so the file was not examined.
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_PROVIDER_TERMINATED));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_NOT_IN_SYNC));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_REQUEST_ABORTED));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_REQUEST_CANCELED));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_REQUEST_TIMEOUT));
        EXPECT_TRUE(IsContentNotLocalError(ERROR_CLOUD_FILE_HYDRATION_NOT_AVAILABLE));
    }

    TEST(CloudPlaceholderErrorTest, OrdinaryFailuresAreNotRelabelled) {
        // The consequence of a wrong answer here is asymmetric and severe. A
        // genuine permission or sharing failure misclassified as "not
        // downloaded yet" would be quietly downgraded to a routine condition
        // and logged at DEBUG, so a file we are being actively prevented from
        // reading would stop being visible at all.
        EXPECT_FALSE(IsContentNotLocalError(ERROR_ACCESS_DENIED));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_FILE_NOT_FOUND));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_PATH_NOT_FOUND));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_SHARING_VIOLATION));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_SUCCESS));
    }

    TEST(CloudPlaceholderErrorTest, BrokenSyncStateIsNotSoftenedIntoNotLocal) {
        // Deliberately excluded from the not-local set. A corrupt sync root or
        // a corrupt property blob is a real fault that deserves to surface as
        // an error; folding it in here would relabel a broken provider as a
        // file that simply has not been downloaded, and lose the only signal
        // that something is actually wrong.
        EXPECT_FALSE(IsContentNotLocalError(ERROR_CLOUD_FILE_SYNC_ROOT_METADATA_CORRUPT));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_CLOUD_FILE_METADATA_CORRUPT));
        EXPECT_FALSE(IsContentNotLocalError(ERROR_CLOUD_FILE_PROPERTY_CORRUPT));
    }

    // ========================================================================
    // THE LOCALITY PROBE
    // ========================================================================

    TEST_F(CloudPlaceholderFilesTest, OrdinaryFileReportsContentLocal) {
        const std::wstring p = WriteFile(L"ordinary.bin", "some content");
        EXPECT_EQ(ContentLocality::Local, GetContentLocality(p));
    }

    TEST_F(CloudPlaceholderFilesTest, MissingFileIsUnknownAndNeverNotLocal) {
        // The distinction decides whether the file is SKIPPED. NotLocal means
        // "do not bother opening this", so a probe that cannot answer must
        // report Unknown and let the caller attempt the read - unknown must
        // never mean skip, the same rule the oversize gate follows.
        const std::wstring missing = (dir_ / L"does_not_exist.bin").wstring();
        const ContentLocality got = GetContentLocality(missing);
        EXPECT_NE(ContentLocality::NotLocal, got)
            << "a file we could not interrogate must not be treated as non-resident";
        EXPECT_EQ(ContentLocality::Unknown, got);
    }

    TEST_F(CloudPlaceholderFilesTest, ProbeTakesNoHandleOnTheFile) {
        // THE POINT OF THIS TEST is the property, not the answer. The probe
        // runs on threads that owe the kernel a scan verdict, so it must not
        // open the file: an open would re-enter our own minifilter, and on a
        // placeholder it is the open itself that triggers the hydration the
        // probe exists to avoid.
        //
        // Holding the file with NO sharing rights makes the difference
        // observable. GetFileAttributesExW still answers; anything that tried
        // to open the file would get ERROR_SHARING_VIOLATION and degrade to
        // Unknown.
        const std::wstring p = WriteFile(L"exclusive.bin", "locked content");

        HANDLE h = ::CreateFileW(p.c_str(), GENERIC_READ,
                                 0,              // no sharing at all
                                 nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
        ASSERT_NE(INVALID_HANDLE_VALUE, h) << "could not take an exclusive handle for the test";

        const ContentLocality got = GetContentLocality(p);
        ::CloseHandle(h);

        EXPECT_EQ(ContentLocality::Local, got)
            << "the probe appears to open the file rather than query its attributes";
    }

    // ========================================================================
    // NO REGRESSION IN WHAT ALREADY WORKED
    // ========================================================================

    TEST_F(CloudPlaceholderFilesTest, OrdinaryFileStillHashesCorrectly) {
        // "abc" against the published SHA-256 test vector, so this checks the
        // digest is RIGHT rather than merely present. Reordering the new
        // locality and reparse logic in a way that corrupts the read would
        // still produce some digest; only a known vector catches that.
        const std::wstring p = WriteFile(L"abc.bin", "abc");

        std::vector<uint8_t> digest;
        ShadowStrike::Utils::HashUtils::Error err{};
        ASSERT_TRUE(ShadowStrike::Utils::HashUtils::ComputeFile(
            ShadowStrike::Utils::HashUtils::Algorithm::SHA256, p, digest, &err))
            << "hashing an ordinary file regressed; win32=" << err.win32;

        const std::string hex = ShadowStrike::Utils::HashUtils::ToHexLower(digest);
        EXPECT_EQ("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hex);
    }

    TEST_F(CloudPlaceholderFilesTest, DirectoryIsStillRefusedByHashing) {
        std::vector<uint8_t> digest;
        ShadowStrike::Utils::HashUtils::Error err{};
        EXPECT_FALSE(ShadowStrike::Utils::HashUtils::ComputeFile(
            ShadowStrike::Utils::HashUtils::Algorithm::SHA256,
            dir_.wstring(), digest, &err));
    }

    TEST_F(CloudPlaceholderFilesTest, MissingFileIsStillRefusedByHashing) {
        const std::wstring missing = (dir_ / L"nope.bin").wstring();
        std::vector<uint8_t> digest;
        ShadowStrike::Utils::HashUtils::Error err{};
        EXPECT_FALSE(ShadowStrike::Utils::HashUtils::ComputeFile(
            ShadowStrike::Utils::HashUtils::Algorithm::SHA256, missing, digest, &err));
    }

    TEST_F(CloudPlaceholderFilesTest, ReadAllBytesStillReadsAnOrdinaryFile) {
        const std::wstring p = WriteFile(L"payload.bin", "0123456789");

        std::vector<std::byte> out;
        ShadowStrike::Utils::FileUtils::Error err{};
        ASSERT_TRUE(ShadowStrike::Utils::FileUtils::ReadAllBytes(p, out, &err))
            << "reading an ordinary file regressed; win32=" << err.win32;
        EXPECT_EQ(10u, out.size());
    }

    // ========================================================================
    // DIAGNOSABILITY
    // ========================================================================

    TEST_F(CloudPlaceholderFilesTest, AFailedReadNamesTheFileAndTheReason) {
        // In the 1.0.94 run this exact object was returned with win32 set and
        // message EMPTY, and ExecutableAnalyzer::Analyze prints the message and
        // nothing else - so 53 errors, the only errors that run counted, read
        // "Failed to read file: " and identified neither the file nor the
        // cause. A code without a description is how a diagnosable failure
        // becomes an undiagnosable one.
        const std::wstring missing = (dir_ / L"absent_file_xyz.bin").wstring();

        std::vector<std::byte> out;
        ShadowStrike::Utils::FileUtils::Error err{};
        ASSERT_FALSE(ShadowStrike::Utils::FileUtils::ReadAllBytes(missing, out, &err));

        EXPECT_NE(0u, err.win32) << "a failure must carry a code";
        ASSERT_FALSE(err.message.empty())
            << "a failure must carry a description, or the log line that prints it says nothing";
        EXPECT_NE(std::string::npos, err.message.find("absent_file_xyz"))
            << "the description must name the file it failed on; got: " << err.message;
    }

    // ========================================================================
    // THE REASON CODE
    // ========================================================================

    TEST(CloudPlaceholderReasonTest, ContentNotLocalIsDistinctAndNotExamined) {
        using ShadowStrike::SignatureStore::NotExaminedReason;

        // Distinct from AccessDenied on purpose: one may be ours to fix, the
        // other is a platform constraint that no retry or privilege changes.
        EXPECT_NE(NotExaminedReason::ContentNotLocal, NotExaminedReason::AccessDenied);

        // And it must never be mistaken for a completed examination.
        EXPECT_NE(NotExaminedReason::ContentNotLocal, NotExaminedReason::Examined);

        // A result carrying it must report itself unexamined and unsuccessful,
        // which is the property that keeps an unreadable file out of the same
        // bucket as a file that was scanned and found clean.
        ShadowStrike::SignatureStore::ScanResult r{};
        r.examinedState = NotExaminedReason::ContentNotLocal;
        EXPECT_FALSE(r.WasExamined());
        EXPECT_FALSE(r.IsSuccessful());
    }

    TEST(CloudPlaceholderReasonTest, AppendingTheReasonDidNotRenumberTheOthers) {
        using ShadowStrike::SignatureStore::NotExaminedReason;

        // The new enumerator was appended rather than inserted. Pinning the
        // established values means an insertion in the middle - which would
        // silently change the meaning of any stored or compared value - fails
        // here instead of in the field.
        EXPECT_EQ(0, static_cast<int>(NotExaminedReason::NotAttempted));
        EXPECT_EQ(1, static_cast<int>(NotExaminedReason::Examined));
        EXPECT_LT(static_cast<int>(NotExaminedReason::InternalError),
                  static_cast<int>(NotExaminedReason::ContentNotLocal));
    }

}  // namespace
