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
 * @file Stage1Diagnostics.hpp
 * @brief Snapshot of Stage 1 outcome, serialised atomically to
 *        %ProgramData%\ShadowStrike\State\driver-stage1.json so the bundle
 *        (and post-install diagnostics) can detect what happened across the
 *        reboot pivot.
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

struct Stage1Snapshot {
    bool         service_registered          = false;
    DWORD        service_registration_error  = ERROR_SUCCESS;
    bool         testsigning_state_before    = false;
    bool         testsigning_state_after     = false;
    bool         secureboot_blocks           = false;
    DWORD        bcdedit_exit                = 0;
    bool         stage2_task_registered      = false;
    bool         reboot_required             = false;
    std::wstring last_error_message;
};

/**
 * @brief Serialise the snapshot as flat JSON (UTF-8) and write atomically
 *        to %ProgramData%\ShadowStrike\State\driver-stage1.json.
 *
 * The directory tree is created with SHCreateDirectoryExW.  The file is
 * written first to a sibling ".tmp" file and then promoted via
 * MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH).
 *
 * ACL (SDDL): O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)
 *   SYSTEM/Admins: full control.  Authenticated Users: read only.
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD WriteStage1Snapshot(const Stage1Snapshot& snapshot) noexcept;

} // namespace ShadowStrike::Installer
