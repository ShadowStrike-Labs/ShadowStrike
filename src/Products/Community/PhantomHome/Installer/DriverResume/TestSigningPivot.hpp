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
 * @file TestSigningPivot.hpp
 * @brief BCD test-signing detection and SYSTEM stage-2 reboot-pivot logic.
 *
 * Provides:
 *  - Detection of the Windows BCD "testsigning" boot option via
 *    (a) registry key HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Boot
 *        and (b) spawning bcdedit /enum {current} /v and parsing stdout.
 *  - Enablement of testsigning via CreateProcessW → bcdedit /set testsigning on.
 *  - Registering a SYSTEM scheduled task so the driver installs after reboot.
 *  - Returning a reboot-required status to the MSI/Burn installer.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <string>
#include <cstdint>

namespace ShadowStrike::Installer {

// ────────────────────────────────────────────────────────────────────────────
//  Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * @brief Determine if Windows BCD test-signing is currently enabled.
 *
 * Two independent sources are checked:
 *  1. HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Boot
 *     value "TestSigningLevel" (REG_DWORD, 0 = off, non-zero = on).
 *  2. Output of `bcdedit /enum {current} /v` – look for "testsigning   Yes".
 *
 * Both sources must agree that testsigning is ON for this function to return
 * true.  If the sources disagree (partial corruption / race), the function
 * returns false to force re-enablement.
 *
 * @param[out] outEnabled  Set to true if testsigning is confidently ON.
 * @return ERROR_SUCCESS or a Win32 error code (bcdedit spawn failure, etc.).
 */
[[nodiscard]] DWORD QueryTestSigningState(bool& outEnabled);

/**
 * @brief Enable BCD test-signing via `bcdedit /set {current} testsigning on`.
 *
 * Spawns bcdedit.exe through CreateProcessW (NOT ShellExecute — must not
 * trigger UAC prompt from inside an already-elevated context).  Waits for
 * the child process to exit and checks the exit code.
 *
 * @return ERROR_SUCCESS if bcdedit exited with 0; otherwise a Win32 error
 *         code (or ERROR_FUNCTION_FAILED if bcdedit returned non-zero).
 */
[[nodiscard]] DWORD EnableTestSigning();

/**
 * @brief Register the Stage 2 command as a SYSTEM scheduled task.
 *
 * RunOnce executes in an interactive user token and is consumed before a failed
 * elevated command can retry. The post-reboot driver install must therefore be
 * owned by Task Scheduler and run as LocalSystem.
 *
 * @param stage2ExePath  Full path to ShadowStrikeDriverResume.exe.
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD RegisterStage2ScheduledTask(const std::wstring& stage2ExePath);

/**
 * @brief Remove the Stage 2 SYSTEM scheduled task after a successful pivot.
 *
 * Missing tasks are reported as non-fatal to callers so cleanup is idempotent
 * across repaired installs and manual --stage2 invocations.
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD DeleteStage2ScheduledTask();

/**
 * @brief Initiate a graceful system restart with a 60-second countdown.
 *
 * Acquires SE_SHUTDOWN_NAME privilege, then calls InitiateSystemShutdownExW
 * with:
 *   - Timeout:     60 seconds
 *   - ForceAppsClosed: FALSE (give apps time to save)
 *   - RebootAfterShutdown: TRUE
 *   - Reason: SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_FLAG_PLANNED
 *   - Message: "ShadowStrike Phantom Home is completing driver installation.
 *               Your system will restart in 60 seconds."
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD ScheduleReboot();

/**
 * @brief Spawn a child process and capture its stdout.
 *
 * Uses anonymous pipes for stdout/stderr capture.  The child inherits only
 * the write-end of the pipe; the read-end is consumed by the caller thread.
 * The returned string is UTF-8 (the raw byte output of the child).
 *
 * @param cmdLine    Full command line including executable.
 * @param[out] output  Captured stdout + stderr (interleaved).
 * @param[out] exitCode  Child process exit code.
 * @return ERROR_SUCCESS or a Win32 error code (spawn failure).
 */
[[nodiscard]] DWORD SpawnAndCapture(const std::wstring& cmdLine,
                                     std::string&        output,
                                     DWORD&              exitCode);

} // namespace ShadowStrike::Installer
