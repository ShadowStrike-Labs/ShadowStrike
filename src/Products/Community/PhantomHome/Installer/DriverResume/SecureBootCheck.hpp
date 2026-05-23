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
 * @file SecureBootCheck.hpp
 * @brief Detect the firmware Secure Boot state.
 *
 * Test-signed kernel drivers cannot load while UEFI Secure Boot is enabled.
 * Stage 1 checks this state up-front and refuses to enable testsigning when
 * the firmware blocks it; the operator must turn Secure Boot off first.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

namespace ShadowStrike::Installer {

enum class SecureBootState {
    Unknown,
    Enabled,
    Disabled
};

/**
 * @brief Query firmware Secure Boot state.
 *
 * Two independent sources are consulted:
 *  1. UEFI variable "SecureBoot" in {8be4df61-93ca-11d2-aa0d-00e098032b8c}
 *     via GetFirmwareEnvironmentVariableW (requires SE_SYSTEM_ENVIRONMENT_NAME).
 *     ERROR_INVALID_FUNCTION from this call indicates legacy BIOS/CSM, which
 *     implies Secure Boot is disabled.
 *  2. HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State value
 *     UEFISecureBootEnabled (REG_DWORD).
 *
 * Consensus rule: both sources must agree.  Disagreement returns Unknown,
 * which forces explicit operator action.
 *
 * @return SecureBootState (never throws).
 */
[[nodiscard]] SecureBootState QuerySecureBootState() noexcept;

} // namespace ShadowStrike::Installer
