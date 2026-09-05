// ===========================================================================
// PublisherTrustSuppression_Tests.cpp
//
// The 1.0.109 field run reported fourteen threats and every one was false.
// Five were real executables convicted by heuristics alone, four of them
// Microsoft operating-system binaries:
//
//   System32\d3d11.dll                risk 73.0  Heuristic:Win/Generic
//   System32\usbmon.dll               risk 63.0  Heuristic:Win/Generic
//   SysWOW64\IME\IMEJP\IMJPDAPI.DLL   risk 63.0  Heuristic:Win/Packed
//   System32\drivers\ndis.sys         risk 83.0  Heuristic:Win/Packed
//   OneDriveStandaloneUpdater.exe     risk 78     Heur:PE.Suspicious
//
// Stage 5 convicts at sensitivityLevel * 30.0 = 60.0 by default. Windows system
// binaries land at 63 to 83 while mssmbios.sys scored 53.0 and d2d1.dll 40.0,
// so there is no clean threshold that separates them - entropy, packing and
// import heuristics do not distinguish Microsoft's optimised, resource-heavy
// system binaries from packed malware.
//
// WHAT THIS SUITE COVERS AND WHAT IT DOES NOT. It tests the TRUST PREDICATE
// against the real operating system: that a catalog-signed Windows binary
// verifies as valid and Microsoft-signed under the exact option set the scan
// path uses, and that the same bytes with one byte altered do NOT. That is the
// half a structural guard cannot check, because it depends on Windows.
//
// The WIRING - that stage 5 and stage 5.5 consult the predicate before
// convicting, that a suppression does not end the scan, and that the counter is
// incremented - is guarded structurally in
// tests/kernel_contracts/test_phantom_sensor_scanner_identity.py. It is done
// there deliberately: an end-to-end behavioural assertion would depend on a
// machine-specific heuristic risk score, and a test that silently stops
// discriminating when a score drifts below a threshold is worse than no test.
// ===========================================================================

#include "pch.h"
#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <Windows.h>

#include "../../../src/PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"
#include "../../../src/PhantomCore/Core/Engine/ScanEngine.hpp"

using ShadowStrike::Security::DigitalSignatureValidator;
using ShadowStrike::Security::SignatureValidationFlags;
using ShadowStrike::Security::SignatureValidationOptions;

namespace {

// The exact option set ScanEngine::Impl::EvaluatePublisherTrust uses. Kept in
// one place here so the two cannot drift apart silently: OfflineOnly because a
// CRL or OCSP fetch on the scan path caused a 180-second CryptSvc wedge (task
// 48), AllowCatalogSignatures because Windows system binaries are catalog
// signed rather than embedded signed, CacheResult so a repeat conviction on the
// same binary is answered from cache.
SignatureValidationOptions ScanPathOptions() {
    SignatureValidationOptions options{};
    options.flags = static_cast<SignatureValidationFlags>(
        static_cast<uint32_t>(SignatureValidationFlags::OfflineOnly) |
        static_cast<uint32_t>(SignatureValidationFlags::VerifyChain) |
        static_cast<uint32_t>(SignatureValidationFlags::AllowCatalogSignatures) |
        static_cast<uint32_t>(SignatureValidationFlags::CacheResult));
    return options;
}

std::filesystem::path SystemDirectory() {
    wchar_t buf[MAX_PATH] = {};
    const UINT n = ::GetSystemDirectoryW(buf, static_cast<UINT>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) {
        return {};
    }
    return std::filesystem::path(buf);
}

// A Microsoft-signed binary that is present on every supported Windows build.
// kernel32.dll is chosen over the specific files from the field report because
// those are build-dependent, while this one cannot be absent on a running
// system - and it is the same trust question.
std::filesystem::path SignedSystemBinary() {
    const auto dir = SystemDirectory();
    if (dir.empty()) {
        return {};
    }
    return dir / L"kernel32.dll";
}

void EnsureValidatorReady() {
    auto& validator = DigitalSignatureValidator::Instance();
    if (!validator.IsInitialized()) {
        ASSERT_TRUE(validator.Initialize());
    }
    ASSERT_TRUE(validator.IsInitialized());
}

// RAII copy of a file with one byte altered, so the content no longer matches
// any catalog entry and the embedded signature no longer verifies. This is the
// discriminator the suite rests on: same structure, same approximate heuristic
// profile, no valid signature.
class TamperedCopy {
public:
    explicit TamperedCopy(const std::filesystem::path& source,
                          const std::string& tag) {
        m_dir = std::filesystem::temp_directory_path() / "phantom-trust-suppression";
        std::filesystem::create_directories(m_dir);
        m_path = m_dir / ("tampered-" + tag + ".bin");

        std::error_code ec;
        std::filesystem::copy_file(
            source, m_path,
            std::filesystem::copy_options::overwrite_existing, ec);
        m_copied = !ec;
        if (!m_copied) {
            return;
        }

        // Flip one byte deep inside the file. Chosen past the headers so the
        // image still parses as a PE - the point is to invalidate the
        // signature, not to produce a malformed file that fails for an
        // unrelated reason.
        std::fstream f(m_path, std::ios::binary | std::ios::in | std::ios::out);
        if (!f.is_open()) {
            m_copied = false;
            return;
        }
        const auto size = std::filesystem::file_size(m_path, ec);
        if (ec || size < 0x2000) {
            m_copied = false;
            return;
        }
        const std::streamoff offset = static_cast<std::streamoff>(size / 2);
        f.seekg(offset);
        char original = 0;
        f.read(&original, 1);
        f.clear();
        f.seekp(offset);
        const char flipped = static_cast<char>(~static_cast<unsigned char>(original));
        f.write(&flipped, 1);
        f.close();
    }

    ~TamperedCopy() {
        std::error_code ec;
        std::filesystem::remove(m_path, ec);
    }

    TamperedCopy(const TamperedCopy&) = delete;
    TamperedCopy& operator=(const TamperedCopy&) = delete;

    [[nodiscard]] bool Ok() const { return m_copied; }
    [[nodiscard]] const std::filesystem::path& Path() const { return m_path; }

private:
    std::filesystem::path m_dir;
    std::filesystem::path m_path;
    bool m_copied = false;
};

} // namespace

// ---------------------------------------------------------------------------
// The precondition the whole fix depends on: a Windows system binary must be
// recognised as validly signed by Microsoft, offline, with catalog signatures
// allowed. If this fails, suppression can never engage and the false positives
// return - which is exactly the state 1.0.93 and 1.0.109 were in.
// ---------------------------------------------------------------------------
TEST(PublisherTrustSuppressionTest, AWindowsSystemBinaryVerifiesAsMicrosoftSigned) {
    ASSERT_NO_FATAL_FAILURE(EnsureValidatorReady());

    const auto binary = SignedSystemBinary();
    ASSERT_FALSE(binary.empty());
    ASSERT_TRUE(std::filesystem::exists(binary)) << binary.string();

    const auto info = DigitalSignatureValidator::Instance()
                          .VerifyFile(binary.wstring(), ScanPathOptions());

    EXPECT_TRUE(info.isValid)
        << "a Windows system binary did not verify as validly signed, so the "
           "trust path can never suppress a heuristic false positive on an OS "
           "file. Signer was '"
        << std::string(info.signer.signerName.begin(), info.signer.signerName.end())
        << "'";

    EXPECT_TRUE(info.isMicrosoftSigned)
        << "a Windows system binary was not recognised as Microsoft-signed";
}

// ---------------------------------------------------------------------------
// THE ANTI-DELETION HALF. If the predicate answered "trusted" for anything, the
// suppression would blind the heuristic detectors entirely. One altered byte
// must be enough to withdraw trust.
// ---------------------------------------------------------------------------
TEST(PublisherTrustSuppressionTest, OneAlteredByteWithdrawsTrust) {
    ASSERT_NO_FATAL_FAILURE(EnsureValidatorReady());

    const auto binary = SignedSystemBinary();
    ASSERT_FALSE(binary.empty());
    ASSERT_TRUE(std::filesystem::exists(binary));

    const TamperedCopy copy(binary, "onebyte");
    ASSERT_TRUE(copy.Ok()) << "could not create the tampered copy, so this test "
                              "cannot discriminate and must not report success";
    ASSERT_TRUE(std::filesystem::exists(copy.Path()));

    const auto info = DigitalSignatureValidator::Instance()
                          .VerifyFile(copy.Path().wstring(), ScanPathOptions());

    const bool trusted = info.isValid && info.isMicrosoftSigned;
    EXPECT_FALSE(trusted)
        << "a modified copy of a system binary was still treated as validly "
           "Microsoft-signed. Publisher-trust suppression would then apply to "
           "tampered files, which would blind the heuristic detectors instead "
           "of making them precise";
}

// ---------------------------------------------------------------------------
// Trust must come from the signature, not from where the file sits. A file
// placed in the system directory earns nothing.
// ---------------------------------------------------------------------------
TEST(PublisherTrustSuppressionTest, TrustDoesNotFollowFromLocationAlone) {
    ASSERT_NO_FATAL_FAILURE(EnsureValidatorReady());

    // A file that certainly is not signed, named to look like a system DLL.
    const auto dir = std::filesystem::temp_directory_path() /
                     "phantom-trust-suppression";
    std::filesystem::create_directories(dir);
    const auto fake = dir / "kernel32.dll";
    {
        std::ofstream f(fake, std::ios::binary | std::ios::trunc);
        const char mz[] = "MZ";
        f.write(mz, 2);
        const std::vector<char> filler(8192, 0x41);
        f.write(filler.data(), static_cast<std::streamsize>(filler.size()));
    }
    ASSERT_TRUE(std::filesystem::exists(fake));

    const auto info = DigitalSignatureValidator::Instance()
                          .VerifyFile(fake.wstring(), ScanPathOptions());

    EXPECT_FALSE(info.isValid && info.isMicrosoftSigned)
        << "an unsigned file named kernel32.dll was treated as Microsoft-signed";

    std::error_code ec;
    std::filesystem::remove(fake, ec);
}

// ---------------------------------------------------------------------------
// The counter must exist and be readable, because it is the only field
// observable that distinguishes "no false positives happened" from "the
// suppression never ran". Those are indistinguishable in a threat count.
// ---------------------------------------------------------------------------
TEST(PublisherTrustSuppressionTest, TheSuppressionCounterIsReadable) {
    auto& engine = ShadowStrike::Core::Engine::ScanEngine::Instance();

    // Bring the engine up if no earlier suite has. Initialize is idempotent, and
    // Shutdown is deliberately NOT called: tests/unit/scan_engine_teardown
    // registers a global environment that requires the engine still up after
    // every suite. An earlier version of this test simply asserted
    // IsInitialized() and failed whenever the suite was run under a filter,
    // which is a defect in the test rather than in the product.
    if (!engine.IsInitialized()) {
        ShadowStrike::Core::Engine::EngineConfig config{};
        config.signatureDbPath.clear();
        config.enableHeuristics = false;
        config.enableMachineLearning = false;
        config.enableBehaviorAnalysis = false;
        config.enableCloudLookup = false;
        ASSERT_TRUE(engine.Initialize(config));
    }
    ASSERT_TRUE(engine.IsInitialized());

    const auto stats = engine.GetStatistics();

    // Reading it is the contract. Its value depends on what else this binary
    // scanned, so no magnitude is asserted - only that the snapshot carries it
    // at all, which is what was missing for archivesScanned before 0771f440.
    EXPECT_GE(stats.heuristicVerdictsSuppressedByTrust, 0ull);
}
