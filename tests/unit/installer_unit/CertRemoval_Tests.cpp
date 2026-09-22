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
/*
 * ============================================================================
 * Revoking the machine-wide trust grant the installer creates
 * ============================================================================
 *
 * The installer writes the ShadowStrike signing certificate into
 * LocalMachine\Root and LocalMachine\TrustedPublisher. Root is not "trust this
 * driver" - it is "trust this key to vouch for ANY Authenticode signature, and
 * any TLS chain that consults the machine store".
 *
 * Nothing removed it. CertDeleteCertificateFromStore appeared nowhere in the
 * tree, and --uninstall removed the driver service only, so uninstalling the
 * product left the grant behind permanently, for a key whose private half sits
 * in a public repository.
 *
 * These cases exercise the removal against a THROWAWAY store under CurrentUser,
 * never a real trust store. That keeps them runnable without elevation and means
 * a failing case cannot damage the host's trust configuration. The code path is
 * the same one uninstall takes; only the store location and name differ, which
 * is why the function is parameterised on both.
 *
 * THE CASE THAT MATTERS is the second one. Matching on the subject name would be
 * the obvious implementation and would be wrong: it could delete somebody else's
 * certificate that happens to be named similarly. Removal matches on the SHA-256
 * of the SubjectPublicKey, and an unrelated certificate sharing the store must
 * survive.
 * ============================================================================
 */

#include "pch.h"

#include <gtest/gtest.h>

#include <Windows.h>
#include <wincrypt.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "Products/Community/PhantomHome/Installer/DriverResume/RootCertInstall.hpp"

// ----------------------------------------------------------------------------
// The installer's logging sink, supplied for this binary.
//
// Every DriverResume translation unit declares ShadowStrike::Installer::Internal::Log
// and routes LOG_INFO / LOG_WARN / LOG_ERROR through it, but the only definition
// lives in DriverResumeMain.cpp beside wmain, which cannot be linked into a test
// executable. Providing the sink here is what lets RootCertInstall.cpp be tested
// at all, and it changes no production code: the installer keeps its own
// definition, and this one exists only in the test binary.
//
// Deliberately silent. These cases exercise failure paths on purpose, and their
// log output would be noise that looks like breakage in the suite transcript.
// ----------------------------------------------------------------------------
namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* /*level*/, const wchar_t* /*fmt*/, ...) {}
}  // namespace ShadowStrike::Installer::Internal

namespace {

namespace fs = std::filesystem;

using ShadowStrike::Installer::kShadowStrikeSignerPublicKeySha256;
using ShadowStrike::Installer::RemoveCertificatesByPublicKeyHash;

/// @brief A scratch CurrentUser store that deletes itself.
///
/// Deliberately NOT "Root" or "TrustedPublisher". A test that writes to a real
/// trust store to prove it can clean up afterwards is a test that changes the
/// machine's trust configuration if it fails halfway.
constexpr const wchar_t* kScratchStore = L"ShadowStrikePhantomRemovalTest";

[[nodiscard]] fs::path RepoRoot() {
    std::error_code ec;
    fs::path here = fs::current_path(ec);
    if (ec) return {};
    for (int up = 0; up < 6; ++up) {
        if (fs::exists(here / "packaging" / "signing" / "ShadowStrike-Dev.cer", ec)) return here;
        if (!here.has_parent_path() || here.parent_path() == here) break;
        here = here.parent_path();
    }
    return {};
}

[[nodiscard]] std::vector<uint8_t> ReadAll(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

class CertRemovalTest : public ::testing::Test {
protected:
    void SetUp() override { PurgeScratchStore(); }
    void TearDown() override { PurgeScratchStore(); }

    /// @brief Empties and deletes the scratch store, leaving no trace.
    static void PurgeScratchStore() {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore);
        if (store == nullptr) return;
        // Delete every certificate, restarting after each because deletion frees
        // the enumeration cursor.
        bool again = true;
        while (again) {
            again = false;
            PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(store, nullptr);
            if (ctx != nullptr) {
                PCCERT_CONTEXT dup = CertDuplicateCertificateContext(ctx);
                CertFreeCertificateContext(ctx);
                if (dup != nullptr && CertDeleteCertificateFromStore(dup)) again = true;
            }
        }
        CertCloseStore(store, 0);
    }

    /// @brief Adds a DER certificate to the scratch store.
    [[nodiscard]] static bool AddToScratch(const std::vector<uint8_t>& der) {
        if (der.empty()) return false;
        PCCERT_CONTEXT ctx = CertCreateCertificateContext(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der.data(),
            static_cast<DWORD>(der.size()));
        if (ctx == nullptr) return false;

        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore);
        bool ok = false;
        if (store != nullptr) {
            ok = CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_REPLACE_EXISTING,
                                                 nullptr) != FALSE;
            CertCloseStore(store, 0);
        }
        CertFreeCertificateContext(ctx);
        return ok;
    }

    [[nodiscard]] static size_t CountScratch() {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore);
        if (store == nullptr) return 0;
        size_t n = 0;
        PCCERT_CONTEXT ctx = nullptr;
        while ((ctx = CertEnumCertificatesInStore(store, ctx)) != nullptr) ++n;
        CertCloseStore(store, 0);
        return n;
    }

    /// @brief The certificate the installer grants trust to.
    [[nodiscard]] static std::vector<uint8_t> OurCertDer() {
        const fs::path root = RepoRoot();
        if (root.empty()) return {};
        return ReadAll(root / "packaging" / "signing" / "ShadowStrike-Dev.cer");
    }

    /// @brief An unrelated certificate: whatever signed a Windows system binary.
    [[nodiscard]] static std::vector<uint8_t> UnrelatedCertDer() {
        HCERTSTORE store = nullptr;
        HCRYPTMSG msg = nullptr;
        std::vector<uint8_t> der;
        if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, L"C:\\Windows\\System32\\kernel32.dll",
                              CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                              CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
                              &store, &msg, nullptr)) {
            return der;
        }
        PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(store, nullptr);
        if (ctx != nullptr && ctx->pbCertEncoded != nullptr && ctx->cbCertEncoded > 0) {
            der.assign(ctx->pbCertEncoded, ctx->pbCertEncoded + ctx->cbCertEncoded);
            CertFreeCertificateContext(ctx);
        }
        if (msg) CryptMsgClose(msg);
        if (store) CertCloseStore(store, 0);
        return der;
    }
};

// ============================================================================

TEST_F(CertRemovalTest, TheGrantedCertificateIsFoundAndRemoved) {
    const auto ours = OurCertDer();
    ASSERT_FALSE(ours.empty()) << "packaging/signing/ShadowStrike-Dev.cer could not be read";
    ASSERT_TRUE(AddToScratch(ours)) << "could not stage the certificate in the scratch store";
    ASSERT_EQ(1u, CountScratch());

    unsigned int removed = 0;
    const DWORD err = RemoveCertificatesByPublicKeyHash(
        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore,
        kShadowStrikeSignerPublicKeySha256, removed);

    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), err);
    EXPECT_EQ(1u, removed) << "the certificate the installer grants trust to was not removed";
    EXPECT_EQ(0u, CountScratch()) << "the store still holds a certificate after removal";
}

TEST_F(CertRemovalTest, AnUnrelatedCertificateInTheSameStoreSurvives) {
    // THE CASE THAT MATTERS. Matching by subject name would be the obvious
    // implementation and could delete a stranger's certificate. The criterion is
    // the public key, so an unrelated certificate must be left alone even while
    // sharing the store with the one being removed.
    const auto ours = OurCertDer();
    const auto theirs = UnrelatedCertDer();
    ASSERT_FALSE(ours.empty());
    ASSERT_FALSE(theirs.empty()) << "could not obtain an unrelated certificate to stage";

    ASSERT_TRUE(AddToScratch(theirs));
    ASSERT_TRUE(AddToScratch(ours));
    ASSERT_EQ(2u, CountScratch()) << "both certificates should be staged";

    unsigned int removed = 0;
    const DWORD err = RemoveCertificatesByPublicKeyHash(
        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore,
        kShadowStrikeSignerPublicKeySha256, removed);

    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), err);
    EXPECT_EQ(1u, removed) << "exactly one certificate should have matched";
    EXPECT_EQ(1u, CountScratch())
        << "removal deleted an unrelated certificate. Matching is too broad, and on a real "
           "Root store that would destroy a third party's trust anchor.";
}

TEST_F(CertRemovalTest, RemovingFromAStoreWithoutTheCertificateIsSuccessNotFailure) {
    // Absence is the desired end state. Reporting an error for it would make a
    // second uninstall, or an uninstall after a manual cleanup, look broken.
    unsigned int removed = 0;
    const DWORD err = RemoveCertificatesByPublicKeyHash(
        CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore,
        kShadowStrikeSignerPublicKeySha256, removed);

    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS), err)
        << "an empty store reported failure, so removal is not idempotent";
    EXPECT_EQ(0u, removed);
}

TEST_F(CertRemovalTest, RemovalIsIdempotent) {
    // Uninstall may run more than once, and MSI rollback can re-enter it.
    const auto ours = OurCertDer();
    ASSERT_FALSE(ours.empty());
    ASSERT_TRUE(AddToScratch(ours));

    unsigned int first = 0;
    ASSERT_EQ(static_cast<DWORD>(ERROR_SUCCESS),
              RemoveCertificatesByPublicKeyHash(CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore,
                                                kShadowStrikeSignerPublicKeySha256, first));
    EXPECT_EQ(1u, first);

    unsigned int second = 0;
    EXPECT_EQ(static_cast<DWORD>(ERROR_SUCCESS),
              RemoveCertificatesByPublicKeyHash(CERT_SYSTEM_STORE_CURRENT_USER, kScratchStore,
                                                kShadowStrikeSignerPublicKeySha256, second));
    EXPECT_EQ(0u, second) << "the second pass claimed to remove something already gone";
}

TEST_F(CertRemovalTest, ABadArgumentIsRejected) {
    unsigned int removed = 7;
    EXPECT_EQ(static_cast<DWORD>(ERROR_INVALID_PARAMETER),
              RemoveCertificatesByPublicKeyHash(CERT_SYSTEM_STORE_CURRENT_USER, nullptr,
                                                kShadowStrikeSignerPublicKeySha256, removed));
    EXPECT_EQ(0u, removed) << "the out-parameter must be cleared even on a rejected call";
}

TEST_F(CertRemovalTest, TheAnchorIsTheKeyTheDriverIsActuallySignedWith) {
    // Ties this constant to the same artefact driver attestation pins. If the
    // signing key is rotated and only one of the two anchors is updated, the
    // product would either refuse its own driver or fail to revoke the grant it
    // created - and this fails instead.
    const auto ours = OurCertDer();
    ASSERT_FALSE(ours.empty());

    PCCERT_CONTEXT ctx = CertCreateCertificateContext(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ours.data(),
        static_cast<DWORD>(ours.size()));
    ASSERT_NE(nullptr, ctx) << "ShadowStrike-Dev.cer did not parse as a certificate";

    const auto& pub = ctx->pCertInfo->SubjectPublicKeyInfo.PublicKey;
    ASSERT_NE(nullptr, pub.pbData);
    ASSERT_GT(pub.cbData, 0u);

    std::array<uint8_t, 32> digest{};
    ASSERT_GE(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, pub.pbData, pub.cbData,
                         digest.data(), static_cast<ULONG>(digest.size())),
              0);
    CertFreeCertificateContext(ctx);

    for (size_t i = 0; i < digest.size(); ++i) {
        EXPECT_EQ(kShadowStrikeSignerPublicKeySha256[i], digest[i])
            << "anchor byte " << i << " does not match the signing certificate";
    }
}

}  // namespace
