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

/**
 * @brief Best-effort Defender coexistence: stop two real-time AV engines from
 *        competing (the primary cause of severe CPU/latency alongside Defender).
 *
 * Behaviour:
 *   - Defender absent / real-time protection already off -> nothing to do.
 *   - Real-time protection ON, Tamper Protection OFF -> disable it via the
 *     supported Set-MpPreference API and re-verify.
 *   - Real-time protection ON, Tamper Protection ON -> cannot be changed
 *     programmatically (Windows blocks it by design); log clear guidance and
 *     record HKLM\SOFTWARE\ShadowStrike\PhantomHome\Driver\DefenderRtpActive=1
 *     so the UI can prompt the user to turn Tamper Protection off.
 *
 * The durable production mechanism is Windows Security Center registration
 * (Microsoft Virus Initiative), after which Windows disables Defender
 * automatically; this routine is the pre-MVI stopgap.
 *
 * @return ERROR_SUCCESS in all cases except when PowerShell is entirely absent.
 *         MUST NOT fail the install. Never throws.
 */
[[nodiscard]] DWORD ConfigureDefenderCoexistence() noexcept;

} // namespace ShadowStrike::Installer
