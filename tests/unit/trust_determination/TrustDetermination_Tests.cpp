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
#include "../../../src/PhantomCore/RealTime/RealTimeProtection.hpp"

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

    // ------------------------------------------------------------------------
    // The property that the field defect actually violated
    // ------------------------------------------------------------------------
    // Whether a file is Microsoft-signed is a question about WHO SIGNED IT. It
    // must not change based on whether this machine currently happens to hold a
    // usable CRL. Before the status triage, requesting revocation was enough to
    // turn a valid Microsoft signature into InvalidSignature on a host with a
    // cold revocation cache, because CRYPT_E_REVOCATION_OFFLINE and
    // CERT_E_REVOCATION_FAILURE were unnamed and fell into a default arm that
    // reported "invalid signature".
    //
    // This case is host-independent: on a warm cache both paths succeed, on a
    // cold cache the revocation path returns a revocation status, and either way
    // the IDENTITY answer must agree. A disagreement is the defect.
    //
    // CacheResult is deliberately CLEARED in both option sets. VerifyFile caches
    // by path, so leaving it on would let the first call's verdict be replayed to
    // the second and the comparison would be vacuous -- it would pass no matter
    // what the code did.
    TEST_F(TrustDeterminationTest, MicrosoftTrustDoesNotDependOnRevocationReachability) {
        using ShadowStrike::Security::SignatureValidationFlags;
        using ShadowStrike::Security::SignatureValidationOptions;

        for (const wchar_t* leaf : {L"kernel32.dll", L"urlmon.dll"}) {
            const std::wstring path = SystemFile(leaf);
            ASSERT_FALSE(path.empty());
            if (::GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                continue;
            }

            SignatureValidationOptions withRevocation;
            withRevocation.flags = SignatureValidationFlags::VerifyChain |
                                   SignatureValidationFlags::CheckRevocation |
                                   SignatureValidationFlags::AllowCatalogSignatures;

            SignatureValidationOptions withoutRevocation;
            withoutRevocation.flags = SignatureValidationFlags::VerifyChain |
                                      SignatureValidationFlags::AllowCatalogSignatures;

            auto& validator = DigitalSignatureValidator::Instance();
            const SignatureInfo a = validator.VerifyFile(path, withRevocation);
            const SignatureInfo b = validator.VerifyFile(path, withoutRevocation);

            EXPECT_EQ(a.isMicrosoftSigned, b.isMicrosoftSigned)
                << "Whether this binary is Microsoft-signed changed depending on "
                   "whether revocation was requested. Signer identity cannot depend "
                   "on CRL availability."
                << "\n  with revocation:" << Describe(path, a)
                << "\n  without revocation:" << Describe(path, b);

            EXPECT_EQ(a.isValid, b.isValid)
                << "Signature validity changed depending on whether revocation was "
                   "requested, on a file Windows reports as Valid."
                << "\n  with revocation:" << Describe(path, a)
                << "\n  without revocation:" << Describe(path, b);
        }
    }

    // ------------------------------------------------------------------------
    // The contract, asserted directly
    // ------------------------------------------------------------------------
    // "Revocation could not be checked" is not "the signature is invalid". This
    // assertion is CONDITIONAL by nature: it can only fire on a host where the
    // revocation lookup actually fails, which is the freshly imaged machine the
    // field defect appeared on and not necessarily a long-lived build host. It is
    // written this way deliberately rather than skipped, because a conditional
    // assertion that is silent here still fails loudly on the machine that
    // matters, whereas a skip would report nothing anywhere.
    TEST_F(TrustDeterminationTest, RevocationFailureIsNeverReportedAsAnInvalidSignature) {
        using ShadowStrike::Security::SignatureValidationFlags;
        using ShadowStrike::Security::SignatureValidationOptions;

        // Values are stated numerically as well as by name because the whole
        // point is that these two specific HRESULTs used to be anonymous.
        constexpr int32_t kCryptERevocationOffline  = static_cast<int32_t>(0x80092013);
        constexpr int32_t kCertERevocationFailure   = static_cast<int32_t>(0x80092012);

        for (const wchar_t* leaf : {L"kernel32.dll", L"urlmon.dll", L"ntmarta.dll"}) {
            const std::wstring path = SystemFile(leaf);
            if (path.empty() ||
                ::GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                continue;
            }

            SignatureValidationOptions options;
            options.flags = SignatureValidationFlags::VerifyChain |
                            SignatureValidationFlags::CheckRevocation |
                            SignatureValidationFlags::AllowCatalogSignatures;

            const SignatureInfo info =
                DigitalSignatureValidator::Instance().VerifyFile(path, options);

            if (info.errorCode == kCryptERevocationOffline ||
                info.errorCode == kCertERevocationFailure) {
                EXPECT_TRUE(info.isValid)
                    << "A revocation check that could not be PERFORMED was reported "
                       "as a signature that is INVALID. The digest verified and the "
                       "chain built; only the revocation state is unknown."
                    << Describe(path, info);
                EXPECT_FALSE(info.revocationChecked)
                    << "Revocation was reported as checked despite returning a "
                       "revocation-unavailable status."
                    << Describe(path, info);
            }

            // Holds on every host: a valid verdict must never claim revocation was
            // established when revocation was not even requested.
            if (info.isValid && info.revocationChecked) {
                EXPECT_TRUE((options.flags & SignatureValidationFlags::CheckRevocation) !=
                            SignatureValidationFlags::None)
                    << "revocationChecked is true but revocation was never requested."
                    << Describe(path, info);
            }
        }
    }

    // ------------------------------------------------------------------------
    // The diagnostic gap that made the field run unreadable
    // ------------------------------------------------------------------------
    // errorCode used to be assigned ONLY in the default arm of the status switch,
    // so any named failure returned 0 and a caller could not tell which status
    // produced the verdict. A successful verification must report 0 because
    // ERROR_SUCCESS is 0; a refusal must report something.
    TEST_F(TrustDeterminationTest, ARefusedVerdictCarriesTheStatusCodeThatCausedIt) {
        const std::wstring path = SystemFile(L"kernel32.dll");
        ASSERT_FALSE(path.empty());
        ASSERT_NE(INVALID_FILE_ATTRIBUTES, ::GetFileAttributesW(path.c_str()));

        const SignatureInfo info =
            DigitalSignatureValidator::Instance().VerifyFile(path);

        if (info.isValid) {
            EXPECT_EQ(0, info.errorCode)
                << "A valid signature reported a non-zero status code."
                << Describe(path, info);
        } else {
            EXPECT_NE(0, info.errorCode)
                << "Trust was refused for a Windows system binary and the verdict "
                   "carried no status code, so nothing downstream can report WHY. "
                   "This is the exact condition that made the 1.0.93 field run "
                   "impossible to diagnose from its logs."
                << Describe(path, info);
        }
    }

    // ========================================================================
    // REMEDIATION POLICY
    // ========================================================================
    // The classifier below decides whether a detection carries enough authority
    // to destroy a file the operating system vouches for. Getting it wrong is
    // expensive in both directions: too permissive and the product deletes parts
    // of Windows, which is what the 1.0.93 field run attempted five times on
    // System32\urlmon.dll; too strict and real malware carrying a stolen
    // Microsoft signature is detected and then left in place.
    //
    // The source strings are asserted individually rather than as a set, because
    // each one is a separate decision and a reader should be able to see which
    // way each falls without running anything.

    TEST(RemediationPolicyTest, IdentifyingSourcesRetainAuthorityToRemediate) {
        using ShadowStrike::RealTime::RealTimeProtection;

        // A named known-bad match. On a signed file this is the stolen-certificate
        // and supply-chain case, which is precisely when we must still act.
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("HashStore"));
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("SignatureStore"));
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("ThreatIntelStore"));
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("ThreatIntel"));
    }

    TEST(RemediationPolicyTest, InferentialSourcesDoNotAuthoriseDestroyingASignedFile) {
        using ShadowStrike::RealTime::RealTimeProtection;

        // Every one of these produced a false positive on a Microsoft or OneDrive
        // binary in the 1.0.93 field run, or is of the same class as one that did.
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("Heuristic"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("ExecutableAnalyzer"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("PolymorphicDetector"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("SandboxAnalyzer"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("EmulationEngine"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("ZeroDayDetector"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat(
            "EmulationEngine+ExecutableAnalyzer"));

        // Similarity, not identity. "Resembles something bad" is not grounds to
        // delete part of Windows.
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("FuzzyHasher"));

        // Script scanners: a signed OS binary is not a script, so a hit here on
        // one is far more likely to be wrong than right.
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("PowerShellScanner"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("MacroDetector"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("DocumentScanner"));
    }

    TEST(RemediationPolicyTest, UnknownSourceDefaultsToRequiringStrongerEvidence) {
        using ShadowStrike::RealTime::RealTimeProtection;

        // The default for a DESTRUCTIVE action must be to require the stronger
        // evidence, not to assume it. A detector added later that nobody
        // classified must not inherit the authority to delete system files.
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat(""));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("SomeFutureDetector"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("Unknown"));
    }

    TEST(RemediationPolicyTest, ComposedSourceNamesAreClassifiedByTheirPrefix) {
        using ShadowStrike::RealTime::RealTimeProtection;

        // ScanEngine composes some source names at the assignment site, so the
        // match is by prefix. These pin that behaviour in both directions so a
        // future composite cannot silently change class.
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("HashStore.SHA256"));
        EXPECT_TRUE(RealTimeProtection::DetectionSourceIdentifiesThreat("SignatureStore/YARA"));
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("PowerShellScanner.Batch"));

        // A source that merely CONTAINS an identifying name must not be promoted:
        // only a prefix counts, so a hypothetical "PseudoHashStore" stays
        // inferential.
        EXPECT_FALSE(RealTimeProtection::DetectionSourceIdentifiesThreat("PseudoHashStore"));
    }

}  // namespace
