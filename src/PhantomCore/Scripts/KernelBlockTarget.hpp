/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
#pragma once

#include <cstdint>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace ShadowStrike::Scripts {

/// @brief Whether a script scanner may ask the kernel to block @p pid.
///
/// A scan result's process id names the process the content came from. Content the
/// service reads from disk itself has no such process and carries 0; a result that
/// names the service is an attribution error, not a target. Refused:
///   - 0: no originating process (file-backed and service-side scans)
///   - 4: System
///   - the calling process: blocking the service disables protection
[[nodiscard]] inline bool IsKernelBlockTarget(uint32_t pid) noexcept {
    return pid != 0 && pid != 4 && pid != static_cast<uint32_t>(::GetCurrentProcessId());
}

}  // namespace ShadowStrike::Scripts
