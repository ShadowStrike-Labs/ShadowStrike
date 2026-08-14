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

// ============================================================================
// WHY THIS SUITE EXISTS
// ============================================================================
//
// The 1.0.93 field run convicted fourteen files and every one of them was a
// Microsoft or OneDrive binary. We attempted to QUARANTINE
// C:\Windows\System32\urlmon.dll five times, and blocked ucrtbase.dll. The
// endpoint survived only because the quarantine failed - urlmon.dll was in use.
// Had it succeeded we would have broken the machine ourselves.
//
// The capacity report in that same run showed trustVerdictsCached=0 across all
// 34 samples while the trust determination queue demonstrably drained (depth
// 714 -> 945 -> 53 -> 0, peak 1024, 43 dropped). So thousands of files went
// through DigitalSignatureValidator::IsMicrosoftSigned and NOT ONE came back
// Microsoft-signed. Every OS binary therefore stayed "unknown" forever and took
// the full heuristic pipeline on every access, where the heuristics convicted
// some of them.
//
// This suite pins the contract that was being violated: a Microsoft-signed
// operating-system binary must be recognised as Microsoft-signed. It exists so
// that defect is caught on this machine in seconds rather than on the endpoint
// after a deploy, install and reboot cycle.
//
// IT DELIBERATELY COVERS BOTH SIGNING FORMS, because measurement showed the
// field failure spans both and they travel different code paths:
//
//   embedded Authenticode   kernel32.dll (17,008 B cert dir), ntmarta.dll (11,592 B)
//   catalog only            urlmon.dll (cert dir 0), usbmon.dll (cert dir 0)
//
// urlmon.dll and usbmon.dll are the two files the field run tried hardest to
// quarantine and both carry NO embedded signature - Windows vouches for them
// through a security catalog. ntmarta.dll carries a real embedded signature and
// was convicted anyway. One test over one file could not have told those apart.
//
// EACH TEST VERIFIES ITS OWN PREMISE. A test named "catalog only" that silently
// starts exercising the embedded path because a future Windows build changed the
// file is worse than no test, so the signing form is read out of the PE
// certificate directory at run time and a mismatch skips with the reason stated.
// That is a genuine capability skip - the condition the test needs is absent -
// as opposed to a fixture precondition standing in for work not done.

#include "pch.h"
#include <gtest/gtest.h>

#include "../../../src/PhantomCore/SelfProtection/DigitalSignatureValidator.hpp"

#include <Windows.h>

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

namespace {

    using ShadowStrike::Security::DigitalSignatureValidator;
    using ShadowStrike::Security::SignatureInfo;

    // ------------------------------------------------------------------------
    // Premise check: does this file carry an EMBEDDED Authenticode signature?
    // ------------------------------------------------------------------------
    // Reads IMAGE_DIRECTORY_ENTRY_SECURITY (data directory index 4) straight out
    // of the PE headers. A size of zero means there is no embedded signature and
    // the file can only be vouched for by a catalog.
    //
    // Done by hand rather than through a product helper on purpose: this is the
    // test's independent statement of ground truth, and routing it through the
    // same code under test would let one defect satisfy both sides.
    enum class EmbeddedSignature { Absent, Present, Unreadable };

    [[nodiscard]] EmbeddedSignature ReadEmbeddedSignaturePresence(const std::wstring& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f) return EmbeddedSignature::Unreadable;

        auto readAt = [&f](std::streamoff off, void* dst, std::size_t n) -> bool {
            f.clear();
            f.seekg(off, std::ios::beg);
            if (!f) return false;
            f.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
            return static_cast<std::size_t>(f.gcount()) == n;
        };

        int32_t peOffset = 0;
        if (!readAt(0x3C, &peOffset, sizeof(peOffset)) || peOffset <= 0) {
            return EmbeddedSignature::Unreadable;
        }

        // Optional header begins at peOffset + 4 (signature) + 20 (COFF header).
        const std::streamoff optionalHeader = static_cast<std::streamoff>(peOffset) + 24;

        uint16_t magic = 0;
        if (!readAt(optionalHeader, &magic, sizeof(magic))) {
            return EmbeddedSignature::Unreadable;
        }

        // Data directories start at +96 in PE32 and +112 in PE32+ (0x20B).
        const std::streamoff dirBase = optionalHeader + (magic == 0x20B ? 112 : 96);

        // Entry 4 is the certificate table; each entry is {RVA, Size}, 8 bytes.
        uint32_t certSize = 0;
        if (!readAt(dirBase + (4 * 8) + 4, &certSize, sizeof(certSize))) {
            return EmbeddedSignature::Unreadable;
        }

        return certSize > 0 ? EmbeddedSignature::Present : EmbeddedSignature::Absent;
    }

    [[nodiscard]] std::wstring SystemFile(const wchar_t* leaf) {
        wchar_t dir[MAX_PATH]{};
        const UINT n = ::GetSystemDirectoryW(dir, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return {};
        std::wstring p(dir, n);
        p.push_back(L'\\');
        p.append(leaf);
        return p;
    }

    [[nodiscard]] std::string Narrow(const std::wstring& w) {
        if (w.empty()) return {};
        const int need = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                               nullptr, 0, nullptr, nullptr);
        if (need <= 0) return {};
        std::string out(static_cast<std::size_t>(need), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                              out.data(), need, nullptr, nullptr);
        return out;
    }

    // Full diagnostic line for a verification result. The point of this suite is
    // that a failure must NAME THE MECHANISM rather than just report false, so
    // every assertion below attaches this. The result enum is printed
    // numerically: there is no public enum-to-string helper on this type and
    // inventing enumerator names in a test is how a test stops compiling for
    // reasons unrelated to the product.
    [[nodiscard]] std::string Describe(const std::wstring& path, const SignatureInfo& info) {
        std::string s;
        s += "\n  file            : " + Narrow(path);
        s += "\n  result (enum)   : " + std::to_string(static_cast<int>(info.result));
        s += "\n  isValid         : " + std::string(info.isValid ? "true" : "false");
        s += "\n  isMicrosoftSign : " + std::string(info.isMicrosoftSigned ? "true" : "false");
        s += "\n  isTrustedRoot   : " + std::string(info.isTrustedRoot ? "true" : "false");
        s += "\n  signer          : " + Narrow(info.signer.signerName);
        s += "\n  catalogPath     : " + Narrow(info.catalogPath);
        s += "\n  errorCode       : " + std::to_string(info.errorCode);
        s += "\n  errorMessage    : " + info.errorMessage;
        s += "\n  chain length    : " + std::to_string(info.chain.size());
        return s;
    }

    class TrustDeterminationTest : public ::testing::Test {
    protected:
        static void SetUpTestSuite() {
            // Initialize is idempotent-safe to call here; the validator is a
            // singleton shared with any other suite that touched it. Its result
            // is recorded rather than asserted so a failure to initialise is
            // reported by the tests themselves with full context.
            s_initialized = DigitalSignatureValidator::Instance().Initialize();
        }

        void SetUp() override {
            ASSERT_TRUE(s_initialized)
                << "DigitalSignatureValidator::Initialize() returned false, so no "
                   "verification result below would mean anything.";
        }

        // Shared body for both signing forms. Returns void so ASSERT_* is legal.
        static void ExpectRecognisedAsMicrosoftSigned(const wchar_t* leaf,
                                                      EmbeddedSignature expectedForm,
                                                      const char* formName) {
            const std::wstring path = SystemFile(leaf);
            ASSERT_FALSE(path.empty()) << "GetSystemDirectoryW failed.";

            if (::GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                GTEST_SKIP() << "Not present on this Windows build: " << Narrow(path);
            }

            // Premise, verified rather than assumed - see the note at the top.
            const EmbeddedSignature form = ReadEmbeddedSignaturePresence(path);
            if (form == EmbeddedSignature::Unreadable) {
                GTEST_SKIP() << "Could not read the PE certificate directory of "
                             << Narrow(path) << ", so this test cannot confirm it is "
                             << "exercising the " << formName << " path.";
            }
            if (form != expectedForm) {
                GTEST_SKIP() << Narrow(path) << " is no longer "
                             << formName
                             << " on this Windows build, so this case would silently "
                                "stop covering that path. Pick a different file for "
                                "the "
                             << formName << " case rather than deleting this check.";
            }

            auto& validator = DigitalSignatureValidator::Instance();

            // Reported first so the diagnostic is available even when the
            // boolean below is what fails.
            const SignatureInfo info = validator.VerifyFile(path);

            EXPECT_TRUE(info.isValid)
                << "VerifyFile did not consider a Windows operating-system binary's "
                   "signature valid. Windows itself reports this file as Valid."
                << Describe(path, info);

            EXPECT_TRUE(info.isMicrosoftSigned)
                << "VerifyFile did not identify a Microsoft operating-system binary "
                   "as Microsoft-signed."
                << Describe(path, info);

            // The contract the product actually consumes. RealTimeProtection's
            // trust fast path calls exactly this, and when it answers false the
            // file takes the full heuristic pipeline on every single access -
            // which is what produced the field's fourteen false positives.
            EXPECT_TRUE(validator.IsMicrosoftSigned(path))
                << "IsMicrosoftSigned() returned false for a Microsoft "
                   "operating-system binary. This is the exact condition that made "
                   "the 1.0.93 endpoint attempt to quarantine urlmon.dll: with no "
                   "trust verdict, every OS binary is treated as unknown and judged "
                   "by heuristics alone."
                << Describe(path, info);
        }

        static bool s_initialized;
    };

    bool TrustDeterminationTest::s_initialized = false;

    // ------------------------------------------------------------------------
    // Embedded Authenticode. kernel32.dll is present on every supported build.
    // ------------------------------------------------------------------------
    TEST_F(TrustDeterminationTest, EmbeddedSignedSystemBinaryIsRecognisedAsMicrosoftSigned) {
        ExpectRecognisedAsMicrosoftSigned(L"kernel32.dll", EmbeddedSignature::Present,
                                          "embedded-signed");
    }

    // ntmarta.dll carries an embedded signature (measured: 11,592 byte certificate
    // directory) and the field run convicted it as Heur:PE.Suspicious.
    TEST_F(TrustDeterminationTest, FieldConvictedEmbeddedSignedBinaryIsRecognisedAsMicrosoftSigned) {
        ExpectRecognisedAsMicrosoftSigned(L"ntmarta.dll", EmbeddedSignature::Present,
                                          "embedded-signed");
    }

    // ------------------------------------------------------------------------
    // Catalog only. These carry NO embedded signature at all.
    // ------------------------------------------------------------------------
    // urlmon.dll is the file the field run tried to quarantine five times.
    TEST_F(TrustDeterminationTest, CatalogOnlySystemBinaryIsRecognisedAsMicrosoftSigned) {
        ExpectRecognisedAsMicrosoftSigned(L"urlmon.dll", EmbeddedSignature::Absent,
                                          "catalog-only");
    }

    // usbmon.dll was convicted twice as Heuristic:Win/Generic.
    TEST_F(TrustDeterminationTest, SecondCatalogOnlySystemBinaryIsRecognisedAsMicrosoftSigned) {
        ExpectRecognisedAsMicrosoftSigned(L"usbmon.dll", EmbeddedSignature::Absent,
                                          "catalog-only");
    }

    // ------------------------------------------------------------------------
    // The premise itself, asserted once so the suite cannot quietly become
    // vacuous. If no catalog-only system binary can be found, the two cases
    // above are skipping and the coverage they represent is gone.
    // ------------------------------------------------------------------------
    TEST_F(TrustDeterminationTest, BothSigningFormsArePresentOnThisHostSoBothPathsAreCovered) {
        const std::wstring embedded = SystemFile(L"kernel32.dll");
        const std::wstring catalog = SystemFile(L"urlmon.dll");
        ASSERT_FALSE(embedded.empty());
        ASSERT_FALSE(catalog.empty());

        EXPECT_EQ(EmbeddedSignature::Present, ReadEmbeddedSignaturePresence(embedded))
            << "kernel32.dll has no embedded signature on this host, so the "
               "embedded-signature cases are skipping and that path is uncovered.";

        EXPECT_EQ(EmbeddedSignature::Absent, ReadEmbeddedSignaturePresence(catalog))
            << "urlmon.dll now carries an embedded signature on this host, so the "
               "catalog-only cases are skipping and the catalog path - which is how "
               "Windows vouches for a large share of system binaries - is uncovered. "
               "Find another catalog-only binary rather than dropping the coverage.";
    }

}  // namespace
