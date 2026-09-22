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
#pragma once

/**
 * @file RootCertInstall.hpp
 * @brief Install and remove the ShadowStrike code-signing certificate in the
 *        LocalMachine\Root and LocalMachine\TrustedPublisher stores.
 *
 * Used by the MSI deferred custom action and by Stage 2 (defence-in-depth) so
 * the test-signed PhantomSensor driver passes Authenticode validation.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <string>

namespace ShadowStrike::Installer {

/**
 * @brief Install a DER- or PEM-encoded certificate into the LocalMachine Root
 *        AND TrustedPublisher stores (CERT_STORE_ADD_REPLACE_EXISTING).
 *
 * @param cerFilePath  Absolute path to a .cer file (DER or PEM). The file is
 *                     read into a heap buffer capped at 64 KB; larger files
 *                     are rejected with ERROR_FILE_TOO_LARGE.
 * @return ERROR_SUCCESS if BOTH stores were successfully written. A Win32
 *         error code otherwise.
 */
[[nodiscard]] DWORD InstallShadowStrikeRootCert(const std::wstring& cerFilePath) noexcept;

/**
 * @brief SHA-256 of the ShadowStrike signing certificate's SubjectPublicKey bits.
 *
 * The same bytes CryptoManager pins for driver attestation, and the same bytes
 * Invoke-PhantomDeploy compares. Removal matches on THIS rather than on a subject
 * name so that it cannot delete somebody else's certificate that happens to be
 * named similarly, and so a renewal that keeps the key is still recognised.
 */
extern const unsigned char kShadowStrikeSignerPublicKeySha256[32];

/**
 * @brief Deletes every certificate in one system store whose SubjectPublicKey
 *        SHA-256 equals @p publicKeySha256.
 *
 * Exposed separately from the LocalMachine wrapper below so the matching and
 * deletion logic can be exercised against a throwaway store without requiring
 * elevation or touching a trust store.
 *
 * @param systemStoreLocation  CERT_SYSTEM_STORE_LOCAL_MACHINE or
 *                             CERT_SYSTEM_STORE_CURRENT_USER.
 * @param storeName            Store to search, e.g. L"Root".
 * @param publicKeySha256      32-byte digest to match.
 * @param removedOut           Receives the number of certificates deleted.
 * @return ERROR_SUCCESS when the store was searched successfully, INCLUDING the
 *         case where nothing matched - absence is the desired end state, not an
 *         error. A Win32 error code if the store could not be opened or a
 *         deletion failed.
 */
[[nodiscard]] DWORD RemoveCertificatesByPublicKeyHash(
    DWORD systemStoreLocation,
    const wchar_t* storeName,
    const unsigned char publicKeySha256[32],
    unsigned int& removedOut) noexcept;

/**
 * @brief Removes the ShadowStrike signing certificate from the LocalMachine Root
 *        AND TrustedPublisher stores.
 *
 * The counterpart to InstallShadowStrikeRootCert, and it did not exist. Installing
 * into LocalMachine\\Root grants that certificate authority to vouch for ANY
 * Authenticode signature and any TLS chain that consults the machine store. Nothing
 * revoked it: uninstall removed the driver service and left the grant behind, so a
 * machine that no longer has the product still trusted the key.
 *
 * @param removedOut  Total certificates deleted across both stores.
 * @return ERROR_SUCCESS if both stores were searched. Reports the FIRST failure if
 *         one occurred, but always attempts both stores - leaving the Root entry
 *         behind because TrustedPublisher failed would keep the broader grant.
 */
[[nodiscard]] DWORD RemoveShadowStrikeRootCert(unsigned int& removedOut) noexcept;

} // namespace ShadowStrike::Installer
