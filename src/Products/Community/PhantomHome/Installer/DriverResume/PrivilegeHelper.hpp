/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */
#pragma once

/**
 * @file PrivilegeHelper.hpp
 * @brief Enable the Win32 token privileges that ShadowStrikeDriverResume needs
 *        to drive bcdedit, GetFirmwareEnvironmentVariableW, BCD store registry
 *        access, the BCD hive backup/restore path, the reboot pivot, and the
 *        kernel driver load step.
 *
 * Rationale
 * ─────────
 * SYSTEM and elevated Administrator tokens carry every relevant privilege in
 * their *present* set, but most are *disabled by default*.  A child process
 * spawned via CreateProcessW inherits the parent token's *enabled* set only;
 * therefore bcdedit launched from a non-adjusted DriverResume process sees the
 * privileges as not-held and fails with ERROR_PRIVILEGE_NOT_HELD (0x65B).
 *
 * `EnableInstallerPrivileges()` enables the following on the current process
 * token (and therefore propagates to every subsequent CreateProcess child):
 *
 *   - SeSystemEnvironmentPrivilege  ── GetFirmwareEnvironmentVariableW,
 *                                      BCD writes
 *   - SeShutdownPrivilege           ── InitiateSystemShutdownExW reboot pivot
 *   - SeTakeOwnershipPrivilege      ── BCD store ownership in some BCD layouts
 *   - SeBackupPrivilege             ── BCD hive read on locked layouts
 *   - SeRestorePrivilege            ── BCD hive write on locked layouts
 *   - SeLoadDriverPrivilege         ── FilterLoad / driver SCM start
 *   - SeSecurityPrivilege           ── SACL access on protected stores
 *
 * Any privilege not assigned to the token is logged as a non-fatal WARN; the
 * function returns the count actually enabled so callers can fail-soft when a
 * specific privilege is genuinely missing (e.g. a deprivileged service token).
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <cstddef>

namespace ShadowStrike::Installer {

/**
 * @brief Enable every installer-relevant privilege on the current process
 *        token via TOKEN_ADJUST_PRIVILEGES + AdjustTokenPrivileges.
 *
 * Each privilege is enabled in isolation so that a partial denial does not
 * leak across calls (AdjustTokenPrivileges is all-or-nothing per request).
 *
 * @return Number of privileges that ended up enabled.  Zero indicates total
 *         failure (token open or every privilege denied).
 */
[[nodiscard]] std::size_t EnableInstallerPrivileges() noexcept;

}  // namespace ShadowStrike::Installer
