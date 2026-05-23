/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file PrivilegeHelper.cpp
 * @brief Implementation of EnableInstallerPrivileges().
 *
 * Audit notes
 * ───────────
 *  - Uses the existing HandleGuard RAII wrapper from DriverInstaller.hpp; no
 *    raw CloseHandle in this TU.
 *  - All errors are logged through the shared logging trampoline declared in
 *    DriverResumeMain.cpp (ShadowStrike::Installer::Internal::Log).  This
 *    matches the rest of the DriverResume module; we do not pull in the
 *    PhantomCore Utils::Logger to keep the binary's link-time surface small.
 *  - The function is noexcept; any C++ exception would be a hard contract
 *    violation since this runs in the early installer hot path.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include "PrivilegeHelper.hpp"
#include "DriverInstaller.hpp"  // HandleGuard

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

namespace {

// Enable a single privilege on an already-open token.  Returns true only when
// AdjustTokenPrivileges actually granted SE_PRIVILEGE_ENABLED (i.e. did NOT
// return ERROR_NOT_ALL_ASSIGNED).
[[nodiscard]] bool EnableOne(HANDLE token, const wchar_t* name) noexcept
{
    LUID luid{};
    if (!::LookupPrivilegeValueW(nullptr, name, &luid)) {
        const DWORD err = ::GetLastError();
        LOG_WARN(L"Privilege: LookupPrivilegeValueW(%ls) failed (0x%08X).",
                 name, err);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // AdjustTokenPrivileges returns TRUE both on full success AND on partial
    // denial (ERROR_NOT_ALL_ASSIGNED).  The caller MUST inspect GetLastError().
    ::SetLastError(ERROR_SUCCESS);
    const BOOL ok =
        ::AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD err = ::GetLastError();

    if (!ok) {
        LOG_WARN(L"Privilege: AdjustTokenPrivileges(%ls) failed (0x%08X).",
                 name, err);
        return false;
    }
    if (err == ERROR_NOT_ALL_ASSIGNED) {
        LOG_WARN(L"Privilege: %ls is not assigned to this token (not held).",
                 name);
        return false;
    }
    LOG_INFO(L"Privilege: %ls enabled.", name);
    return true;
}

}  // namespace

std::size_t EnableInstallerPrivileges() noexcept
{
    HANDLE rawToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(),
                            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                            &rawToken))
    {
        const DWORD err = ::GetLastError();
        LOG_ERROR(L"Privilege: OpenProcessToken failed (0x%08X). "
                  L"Subsequent bcdedit/firmware operations WILL fail.", err);
        return 0;
    }
    HandleGuard tok(rawToken);

    // Order is deliberate: firmware/BCD first (the actual failure observed on
    // the VM was SeSystemEnvironmentPrivilege), then the reboot pivot, then
    // the rest in descending criticality.
    static constexpr const wchar_t* kPrivs[] = {
        SE_SYSTEM_ENVIRONMENT_NAME,   // bcdedit, GetFirmwareEnvironmentVariable
        SE_SHUTDOWN_NAME,             // InitiateSystemShutdownExW
        SE_TAKE_OWNERSHIP_NAME,       // BCD store ownership
        SE_BACKUP_NAME,               // BCD hive read on locked layouts
        SE_RESTORE_NAME,              // BCD hive write on locked layouts
        SE_LOAD_DRIVER_NAME,          // FilterLoad / driver SCM start
        SE_SECURITY_NAME,             // SACL access (paranoia)
    };

    std::size_t enabled = 0;
    for (const wchar_t* name : kPrivs) {
        if (EnableOne(tok.get(), name)) {
            ++enabled;
        }
    }

    LOG_INFO(L"Privilege: %zu/%zu installer privileges enabled on token.",
             enabled, sizeof(kPrivs) / sizeof(kPrivs[0]));
    return enabled;
}

}  // namespace ShadowStrike::Installer
