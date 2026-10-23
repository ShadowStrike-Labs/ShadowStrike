/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
/**
 * @file ServiceStartWatchdog.hpp
 * @brief Boot-time supervisor that starts the Home service if SCM gave up on it (task 334).
 *
 * THE DEFECT. On 5 of 9 measured first boots after install (1.0.120-1.0.122) SCM logged
 * 7009/7000 - the service did not connect within 30 s - and the service stayed stopped
 * until the next boot. The process never ran its first compiler-segment initialiser in
 * those runs, so the time was lost in the loader, every time while Windows Update was
 * installing Defender platform or signature updates. On good boots the same image reaches
 * StartServiceCtrlDispatcher 216 ms after process creation.
 *
 * WHY RECOVERY ACTIONS DO NOT COVER IT. Measured with a throw-away service that never
 * connects (tools/vm-harness/Test-RecoveryOnStartTimeout.ps1): SCM logs 7009 and 7000 and
 * applies none of the configured failure actions, even with the failure-actions flag set.
 * Those actions fire when a RUNNING service dies, not when a start attempt times out.
 *
 * THE FIX. A SYSTEM scheduled task, registered by Stage 2 and removed by uninstall, runs
 * ShadowStrikeDriverResume.exe --start-service once per boot, after the delayed
 * auto-start window. If the service is already running that is a status query; if SCM
 * gave up, it starts it again with a fresh 30 s window, retrying a bounded number of
 * times. It does not restart a service someone stopped later in the session: it runs
 * once, at boot.
 *
 * SECURITY. The task runs as LocalSystem, so its definition is fixed here: the command
 * is the installed DriverResume binary (under Program Files, writable only by
 * administrators), the argument is a constant, and the task lives in \ShadowStrike, which
 * inherits the administrators-only ACL of the task root. The XML is built by a pure
 * function so those properties are unit-tested rather than assumed.
 */

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <string>

namespace ShadowStrike::Installer {

inline constexpr wchar_t kServiceWatchdogTaskFolder[] = L"\\ShadowStrike";
inline constexpr wchar_t kServiceWatchdogTaskName[]   = L"PhantomServiceStartWatchdog";

/// Boot delay before the check: after SCM's delayed auto-start (about 2 min after
/// boot) has had its own attempt and its 30 s connect window.
inline constexpr wchar_t kServiceWatchdogBootDelay[]  = L"PT4M";

/// Attempts per boot, and the pause between them, for a start that times out.
inline constexpr unsigned kServiceStartMaxAttempts = 3;
inline constexpr DWORD    kServiceStartRetryDelayMs = 60'000;

/// Whether a failed start attempt is the transient condition this watchdog exists for.
/// Only a start that ran out of time is retried; anything else (service disabled,
/// marked for deletion, binary missing, access denied) is a configuration fault that a
/// retry would only repeat, so it is reported and left alone.
[[nodiscard]] constexpr bool IsRetryableServiceStartFailure(DWORD err) noexcept {
    return err == ERROR_SERVICE_REQUEST_TIMEOUT || err == WAIT_TIMEOUT;
}

/// Task Scheduler 1.2 XML for the watchdog task. Pure: no system state is read.
/// @param driverResumePath absolute path of the installed ShadowStrikeDriverResume.exe
/// @returns the XML, or an empty string if the path is not absolute or contains a
///          character that has no business in an installed executable path
[[nodiscard]] std::wstring BuildServiceWatchdogTaskXml(const std::wstring& driverResumePath);

/// Register (create or replace) the watchdog task. Requires administrator or SYSTEM.
[[nodiscard]] DWORD RegisterServiceWatchdogTask(const std::wstring& driverResumePath);

/// Delete the watchdog task. Absence is success.
[[nodiscard]] DWORD DeleteServiceWatchdogTask();

} // namespace ShadowStrike::Installer
