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
 * @file DefenderExclusions.hpp
 * @brief Best-effort registration of the ShadowStrike install footprint with
 *        Microsoft Defender's path-exclusion list.
 *
 * Failure of this routine MUST NOT fail the install: signed binaries should
 * pass Defender on their own.  The exclusions are purely a co-existence
 * hygiene measure to avoid Defender quarantining staged minifilter binaries
 * during early boot races.
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
 * @brief Register the ShadowStrike install footprint with Defender's
 *        path-exclusion list.
 *
 * Paths added (each best-effort, individually):
 *   <installFolder>
 *   %ProgramData%\ShadowStrike
 *   <installFolder>\Drivers\PhantomSensor.sys
 *   <System32>\drivers\PhantomSensor.sys
 *
 * Strategy:
 *   1. PowerShell: Add-MpPreference -ExclusionPath '<p>' -ErrorAction
 *      SilentlyContinue, per path, 10 s hard timeout each.
 *   2. Fallback (only if powershell.exe missing): wmic.exe with the same
 *      semantics.  COM is intentionally NOT used.
 *
 * @return ERROR_SUCCESS if AT LEAST ONE exclusion succeeded.  Returns the
 *         last Win32 error if every attempt failed.  Never throws.
 */
[[nodiscard]] DWORD AddPhantomDefenderExclusions(const std::wstring& installFolder) noexcept;

} // namespace ShadowStrike::Installer
