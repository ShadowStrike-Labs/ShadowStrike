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
 * Kernel driver attestation - the signer pin
 * ============================================================================
 *
 * ValidateKernelDriverAttestation decides whether the encrypted kernel channel
 * may be trusted. It used to decide nothing at all.
 *
 * Its caller hashed the driver and passed that hash in as the value to verify
 * against; the function then hashed the same file and compared the two. The
 * comparison was SHA256(f) == SHA256(f) and could not fail, on any input,
 * including a driver replaced wholesale. The only other check was
 * WinVerifyTrust accepting ERROR_SUCCESS, which asks whether the chain ends in
 * a root THIS MACHINE trusts and never asks who signed - so any driver signed
 * by any trusted CA passed.
 *
 * The check is now a signer pin against a build-declared public key.
 *
 * THE CASE THAT PROVES THE DIFFERENCE is the Microsoft-signed one below. A
 * Windows system binary is validly signed and its chain is trusted, so the old
 * code accepted it on both counts. The pin rejects it, because Microsoft is not
 * the signer this build trusts to be its kernel sensor. That single case
 * separates "the signature is valid" from "the signature is ours", which is the
 * distinction the old code did not draw.
 *
 * The accepting case doubles as a drift guard. The staged driver is signed by
 * packaging/signing/ShadowStrike-Dev.cer, so if the compiled anchor and that
 * certificate ever diverge, attestation starts refusing the product's own
 * driver and this case fails rather than the channel silently closing in the
 * field.
 * ============================================================================
 */

#include "pch.h"

#include <gtest/gtest.h>

#include "PhantomCore/SelfProtection/CryptoManager.hpp"

#include <filesystem>
#include <fstream>
#include <string>

namespace {

namespace fs = std::filesystem;

using ShadowStrike::Security::CryptoManager;

/// @brief Repository root, located by walking up for a known marker.
///
/// The suite's working directory is the repository root today, but a test that
/// silently passes when its input is missing is worse than one that cannot run,
/// so the path is resolved rather than assumed.
[[nodiscard]] fs::path RepoRoot() {
    std::error_code ec;
    fs::path here = fs::current_path(ec);
    if (ec) return {};
    for (int up = 0; up < 6; ++up) {
        if (fs::exists(here / "packaging" / "signing" / "ShadowStrike-Dev.cer", ec)) {
            return here;
        }
        if (!here.has_parent_path() || here.parent_path() == here) break;
        here = here.parent_path();
    }
    return {};
}

class DriverAttestationTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        if (!CryptoManager::Instance().IsInitialized()) {
            (void)CryptoManager::Instance().Initialize();
        }
        ASSERT_TRUE(CryptoManager::Instance().IsInitialized())
            << "CryptoManager could not be initialised, so attestation cannot be exercised";
    }
};

// ============================================================================
// The pin discriminates
// ============================================================================

TEST_F(DriverAttestationTest, AMicrosoftSignedBinaryIsRefusedDespiteAValidTrustedSignature) {
    // THE CASE THAT PROVES THE FIX. kernel32.dll is validly signed and its chain
    // is trusted, so the previous implementation accepted it on both of its
    // checks - WinVerifyTrust returned ERROR_SUCCESS and the hash comparison was
    // against a hash of the same file. A valid signature is not the same claim
    // as the right signer.
    const fs::path system32 = fs::path(L"C:/Windows/System32");
    const fs::path signedButNotOurs = system32 / "kernel32.dll";

    std::error_code ec;
    ASSERT_TRUE(fs::exists(signedButNotOurs, ec))
        << "kernel32.dll is expected to exist on any Windows host";

    EXPECT_FALSE(CryptoManager::Instance().ValidateKernelDriverAttestation(
        signedButNotOurs.wstring()))
        << "a Microsoft-signed binary was accepted as this product's kernel sensor. "
           "The signer pin is not discriminating, so attestation has regressed to "
           "'somebody trustworthy signed something'.";
}

TEST_F(DriverAttestationTest, AnUnsignedFileIsRefused) {
    // TRUST_E_NOSIGNATURE must stay fatal: an unsigned file carries no identity
    // to pin, so there is nothing to compare and nothing to trust.
    const fs::path temp = fs::temp_directory_path() /
                          ("ss_attest_unsigned_" + std::to_string(::GetCurrentProcessId()) + ".sys");
    {
        std::ofstream out(temp, std::ios::binary);
        // A minimal PE-ish header so the failure is "no signature", not "not a file".
        out << "MZ";
        out.write("\0\0\0\0\0\0", 6);
    }

    EXPECT_FALSE(CryptoManager::Instance().ValidateKernelDriverAttestation(temp.wstring()))
        << "an unsigned file passed attestation";

    std::error_code ec;
    fs::remove(temp, ec);
}

TEST_F(DriverAttestationTest, AMissingFileAndAnEmptyPathAreRefused) {
    // Non-vacuity, and the safe direction: a path that cannot be examined is not
    // a path that passed.
    EXPECT_FALSE(CryptoManager::Instance().ValidateKernelDriverAttestation(L""))
        << "an empty path was accepted";

    const fs::path missing = fs::temp_directory_path() / "ss_attest_does_not_exist_12345.sys";
    std::error_code ec;
    fs::remove(missing, ec);
    EXPECT_FALSE(CryptoManager::Instance().ValidateKernelDriverAttestation(missing.wstring()))
        << "a path with no file behind it was accepted";
}

// ============================================================================
// The pin accepts the real driver - and so guards anchor drift
// ============================================================================

TEST_F(DriverAttestationTest, TheProductsOwnDriverIsAccepted) {
    // This is also the drift guard. The staged driver is signed by
    // packaging/signing/ShadowStrike-Dev.cer, so if the compiled anchor and that
    // certificate diverge, this fails here instead of the channel closing in the
    // field with "attestation enforcement active".
    //
    // It must pass on a host that does NOT trust the development root. That is
    // the point of triaging the trust result: CERT_E_UNTRUSTEDROOT is tolerated
    // because trust comes from the pinned key, which is what removes the need to
    // put a development certificate into the machine root store at all.
    const fs::path root = RepoRoot();
    ASSERT_FALSE(root.empty())
        << "could not locate the repository root, so the staged driver cannot be found";

    const fs::path driver = root / "build" / "installer" / "staging" / "drivers" / "PhantomSensor.sys";
    std::error_code ec;
    ASSERT_TRUE(fs::exists(driver, ec))
        << "the staged driver is missing at " << driver.string()
        << " - it is tracked, so a checkout should have it";

    EXPECT_TRUE(CryptoManager::Instance().ValidateKernelDriverAttestation(driver.wstring()))
        << "attestation REFUSED this product's own signed driver at " << driver.string()
        << ". Either the driver was re-signed with a different key, or the anchor "
           "compiled into CryptoManager no longer matches "
           "packaging/signing/ShadowStrike-Dev.cer. Left unfixed, the service will "
           "refuse its own kernel channel.";
}

}  // namespace
