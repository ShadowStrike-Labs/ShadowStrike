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

/**
 * @file SecureBootCheck.cpp
 * @brief Detect firmware Secure Boot state via UEFI variable + registry.
 *
 * Consensus rule: both the UEFI runtime variable AND the kernel-published
 * registry mirror must agree.  Disagreement returns Unknown so the operator
 * is forced to investigate rather than the installer silently proceeding.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

// winreg.h declares RegOpenKeyExW with a SAL annotation on ulOptions that
// /analyze /sdl misclassifies as C6553 ("value annotation is not valid for
// value type") – the annotation lives in the SDK header, not in our code.
// Suppress at TU scope to keep /WX clean.
#pragma warning(disable: 6553)

#include "SecureBootCheck.hpp"
#include "DriverInstaller.hpp"  // HandleGuard, RegKeyGuard

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

namespace {

// Adjust SE_SYSTEM_ENVIRONMENT_NAME on the current process token.  This
// privilege is required to read UEFI runtime variables on Windows.
[[nodiscard]] bool EnableSystemEnvironmentPrivilege() noexcept
{
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &rawToken))
    {
        LOG_WARN(L"SecureBoot: OpenProcessToken failed (0x%08X).", GetLastError());
        return false;
    }
    HandleGuard tok(rawToken);

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid)) {
        LOG_WARN(L"SecureBoot: LookupPrivilegeValueW(SE_SYSTEM_ENVIRONMENT_NAME) "
                 L"failed (0x%08X).", GetLastError());
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tok.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        LOG_WARN(L"SecureBoot: AdjustTokenPrivileges failed (0x%08X).", GetLastError());
        return false;
    }
    // AdjustTokenPrivileges may return TRUE while still leaving the privilege
    // unassigned (ERROR_NOT_ALL_ASSIGNED).  Detect that explicitly.
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        LOG_WARN(L"SecureBoot: SE_SYSTEM_ENVIRONMENT_NAME not held by token.");
        return false;
    }
    return true;
}

// UEFI variable read.  Returns Enabled / Disabled / Unknown.
[[nodiscard]] SecureBootState ProbeFirmwareVariable() noexcept
{
    constexpr wchar_t kGlobalGuid[] = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

    DWORD val = 0;
    SetLastError(ERROR_SUCCESS);
    const DWORD bytes = GetFirmwareEnvironmentVariableW(
        L"SecureBoot", kGlobalGuid, &val, sizeof(val));

    if (bytes == sizeof(val)) {
        if (val == 1) {
            LOG_INFO(L"SecureBoot: UEFI variable reports Enabled.");
            return SecureBootState::Enabled;
        }
        if (val == 0) {
            LOG_INFO(L"SecureBoot: UEFI variable reports Disabled.");
            return SecureBootState::Disabled;
        }
        LOG_WARN(L"SecureBoot: UEFI variable returned unexpected value %lu.", val);
        return SecureBootState::Unknown;
    }

    const DWORD err = GetLastError();
    if (err == ERROR_INVALID_FUNCTION) {
        // Legacy BIOS / CSM: UEFI runtime services are not available, so
        // Secure Boot is by definition off.
        LOG_INFO(L"SecureBoot: GetFirmwareEnvironmentVariableW returned "
                 L"ERROR_INVALID_FUNCTION; legacy BIOS/CSM, Secure Boot is "
                 L"Disabled.");
        return SecureBootState::Disabled;
    }
    LOG_WARN(L"SecureBoot: GetFirmwareEnvironmentVariableW failed (0x%08X, "
             L"bytes=%lu).", err, bytes);
    return SecureBootState::Unknown;
}

// Registry corroboration:
// HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State!UEFISecureBootEnabled
[[nodiscard]] SecureBootState ProbeRegistry() noexcept
{
    HKEY raw = nullptr;
    LONG rc = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State",
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &raw);
    if (rc != ERROR_SUCCESS) {
        // Pre-Win8 systems and CSM-only systems lack this key entirely.
        LOG_INFO(L"SecureBoot: registry State key not present (rc=%ld); "
                 L"treating registry source as Disabled.", rc);
        return SecureBootState::Disabled;
    }
    RegKeyGuard hk(raw);

    DWORD val  = 0;
    DWORD cb   = sizeof(val);
    DWORD type = 0;
    rc = RegQueryValueExW(hk.get(),
                          L"UEFISecureBootEnabled",
                          nullptr,
                          &type,
                          reinterpret_cast<LPBYTE>(&val),
                          &cb);
    if (rc != ERROR_SUCCESS || type != REG_DWORD || cb != sizeof(val)) {
        LOG_WARN(L"SecureBoot: RegQueryValueExW(UEFISecureBootEnabled) failed "
                 L"(rc=%ld, type=%lu, cb=%lu).", rc, type, cb);
        return SecureBootState::Unknown;
    }
    if (val == 1) {
        LOG_INFO(L"SecureBoot: registry reports Enabled.");
        return SecureBootState::Enabled;
    }
    if (val == 0) {
        LOG_INFO(L"SecureBoot: registry reports Disabled.");
        return SecureBootState::Disabled;
    }
    LOG_WARN(L"SecureBoot: registry value out of range (%lu).", val);
    return SecureBootState::Unknown;
}

} // anonymous namespace

SecureBootState QuerySecureBootState() noexcept
{
    (void)EnableSystemEnvironmentPrivilege();  // best-effort; logged on failure

    const SecureBootState firmware = ProbeFirmwareVariable();
    const SecureBootState registry = ProbeRegistry();

    if (firmware == SecureBootState::Unknown || registry == SecureBootState::Unknown) {
        LOG_WARN(L"SecureBoot: at least one source returned Unknown "
                 L"(firmware=%d, registry=%d); reporting Unknown.",
                 static_cast<int>(firmware), static_cast<int>(registry));
        return SecureBootState::Unknown;
    }
    if (firmware != registry) {
        LOG_WARN(L"SecureBoot: sources disagree (firmware=%d, registry=%d). "
                 L"Reporting Unknown to force operator action.",
                 static_cast<int>(firmware), static_cast<int>(registry));
        return SecureBootState::Unknown;
    }
    return firmware;
}

} // namespace ShadowStrike::Installer
