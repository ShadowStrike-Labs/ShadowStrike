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
 * @brief Install the ShadowStrike code-signing root certificate into the
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

} // namespace ShadowStrike::Installer
