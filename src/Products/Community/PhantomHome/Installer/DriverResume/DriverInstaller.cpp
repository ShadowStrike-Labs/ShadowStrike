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
 * @file DriverInstaller.cpp
 * @brief PhantomSensor SCM installer and minifilter loader implementation.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winsvc.h>
#include <fltuser.h>
#include <ShlObj.h>

#include <string>
#include <cstdio>
#include <cstdint>
#include <cassert>
#include <array>

#include "DriverInstaller.hpp"

// ────────────────────────────────────────────────────────────────────────────
//  Internal logging trampoline (defined in DriverResumeMain.cpp)
// ────────────────────────────────────────────────────────────────────────────
namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

namespace ShadowStrike::Installer {

// ────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ────────────────────────────────────────────────────────────────────────────

static std::wstring GetOwnDirectory()
{
    wchar_t buf[MAX_PATH + 1] = {};
    DWORD   len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return {};

    std::wstring path(buf, len);
    auto pos = path.rfind(L'\\');
    if (pos == std::wstring::npos)
        return {};

    return path.substr(0, pos);
}

static std::wstring BuildSystemDriverPath()
{
    wchar_t sysRoot[MAX_PATH + 1] = {};
    if (!GetWindowsDirectoryW(sysRoot, MAX_PATH))
        return {};

    std::wstring path(sysRoot);
    path += kSystem32Drivers;
    path += kDriverSysName;
    return path;
}

// ────────────────────────────────────────────────────────────────────────────
//  ResolveInstalledDriverPath
// ────────────────────────────────────────────────────────────────────────────
DWORD ResolveInstalledDriverPath(std::wstring& outPath)
{
    // Primary: driver lives next to this EXE in a "Drivers\" subdirectory.
    std::wstring dir = GetOwnDirectory();
    if (dir.empty()) {
        LOG_ERROR(L"GetModuleFileNameW failed (0x%08X)", GetLastError());
        return GetLastError();
    }

    std::wstring candidate = dir + L"\\" + kDriverSubPath;

    // Normalise to extended-length path to handle long paths safely.
    if (candidate.rfind(L"\\\\?\\", 0) != 0)
        candidate = L"\\\\?\\" + candidate;

    DWORD attr = GetFileAttributesW(candidate.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        LOG_ERROR(L"Driver binary not found at '%ls' (0x%08X)", candidate.c_str(), err);
        return err;
    }

    LOG_INFO(L"Resolved driver source: %ls", candidate.c_str());
    outPath = std::move(candidate);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  CopyDriverBinary  (write-then-rename for atomicity)
// ────────────────────────────────────────────────────────────────────────────
DWORD CopyDriverBinary(const std::wstring& srcPath, std::wstring& dstPath)
{
    dstPath = BuildSystemDriverPath();
    if (dstPath.empty()) {
        LOG_ERROR(L"GetWindowsDirectoryW failed (0x%08X)", GetLastError());
        return GetLastError();
    }

    // Temporary name: suffix .tmp so a failed copy doesn't leave a broken .sys
    std::wstring tmpDst = dstPath + L".tmp";

    LOG_INFO(L"Copying driver: %ls -> %ls", srcPath.c_str(), tmpDst.c_str());

    if (!CopyFileW(srcPath.c_str(), tmpDst.c_str(), FALSE /*bFailIfExists*/)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CopyFileW failed (0x%08X): src=%ls", err, srcPath.c_str());
        return err;
    }

    // Atomically rename .tmp -> final path.
    if (!MoveFileExW(tmpDst.c_str(), dstPath.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"MoveFileExW failed (0x%08X): %ls -> %ls",
                  err, tmpDst.c_str(), dstPath.c_str());
        // Clean up orphaned .tmp
        DeleteFileW(tmpDst.c_str());
        return err;
    }

    LOG_INFO(L"Driver staged to: %ls", dstPath.c_str());
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  StopAndDeleteExistingService
// ────────────────────────────────────────────────────────────────────────────
DWORD StopAndDeleteExistingService(SC_HANDLE hScm)
{
    ScHandleGuard svc(OpenServiceW(hScm, kServiceName,
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
    if (!svc.valid()) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            LOG_INFO(L"Service '%ls' does not exist; nothing to remove.", kServiceName);
            return ERROR_SUCCESS;
        }
        LOG_ERROR(L"OpenServiceW failed (0x%08X)", err);
        return err;
    }

    // Query current state
    SERVICE_STATUS ss{};
    if (QueryServiceStatus(svc.get(), &ss) &&
        ss.dwCurrentState != SERVICE_STOPPED)
    {
        LOG_INFO(L"Stopping service '%ls' (current state: %lu)...",
                 kServiceName, ss.dwCurrentState);

        SERVICE_STATUS ctrlStatus{};
        ControlService(svc.get(), SERVICE_CONTROL_STOP, &ctrlStatus);

        // Wait up to 10 s for the service to stop.
        constexpr int kTimeoutMs  = 10'000;
        constexpr int kPollMs     = 250;
        int           waited      = 0;

        while (waited < kTimeoutMs) {
            Sleep(static_cast<DWORD>(kPollMs));
            waited += kPollMs;
            SERVICE_STATUS ss2{};
            if (QueryServiceStatus(svc.get(), &ss2) &&
                ss2.dwCurrentState == SERVICE_STOPPED)
            {
                LOG_INFO(L"Service stopped after %d ms.", waited);
                break;
            }
        }

        SERVICE_STATUS ss3{};
        if (QueryServiceStatus(svc.get(), &ss3) &&
            ss3.dwCurrentState != SERVICE_STOPPED)
        {
            LOG_WARN(L"Service did not stop within %d ms; forcing deletion anyway.",
                     kTimeoutMs);
        }
    }

    if (!DeleteService(svc.get())) {
        DWORD err = GetLastError();
        // ERROR_SERVICE_MARKED_FOR_DELETE is acceptable; SCM will remove on reboot.
        if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
            LOG_ERROR(L"DeleteService failed (0x%08X)", err);
            return err;
        }
        LOG_WARN(L"Service marked for delete (will be removed on next SCM restart).");
    } else {
        LOG_INFO(L"Service '%ls' deleted.", kServiceName);
    }

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  CreateDriverService
// ────────────────────────────────────────────────────────────────────────────
DWORD CreateDriverService(SC_HANDLE hScm, const std::wstring& sysDst)
{
    LOG_INFO(L"Creating SCM service entry for '%ls'...", kServiceName);

    ScHandleGuard svc(
        CreateServiceW(
            hScm,
            kServiceName,                   // lpServiceName
            kServiceDisplayName,            // lpDisplayName
            SERVICE_ALL_ACCESS,             // dwDesiredAccess
            SERVICE_FILE_SYSTEM_DRIVER,     // dwServiceType
            SERVICE_DEMAND_START,           // dwStartType
            SERVICE_ERROR_NORMAL,           // dwErrorControl
            sysDst.c_str(),                 // lpBinaryPathName
            kLoadOrderGroup,                // lpLoadOrderGroup
            nullptr,                        // lpdwTagId
            nullptr,                        // lpDependencies
            nullptr,                        // lpServiceStartName (LocalSystem)
            nullptr                         // lpPassword
        ));

    if (!svc.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreateServiceW failed (0x%08X)", err);
        return err;
    }

    // Set human-readable description.
    SERVICE_DESCRIPTIONW sd{};
    sd.lpDescription = const_cast<LPWSTR>(kServiceDescription);
    if (!ChangeServiceConfig2W(svc.get(), SERVICE_CONFIG_DESCRIPTION, &sd)) {
        // Non-fatal: description is cosmetic.
        LOG_WARN(L"ChangeServiceConfig2W (description) failed (0x%08X)", GetLastError());
    }

    LOG_INFO(L"SCM service '%ls' created successfully.", kServiceName);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ConfigureMinifilterRegistry
// ────────────────────────────────────────────────────────────────────────────
DWORD ConfigureMinifilterRegistry()
{
    // Base: HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor
    constexpr wchar_t kSvcBase[]       =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor";
    constexpr wchar_t kSvcParameters[] =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances";
    constexpr wchar_t kSvcInstance[]   =
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances\\PhantomSensor Instance";

    auto OpenOrCreate = [](const wchar_t* subKey) -> RegKeyGuard {
        HKEY hk = nullptr;
        DWORD disp = 0;
        LONG rc = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE, subKey, 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, &disp);
        if (rc != ERROR_SUCCESS)
            return RegKeyGuard{};
        return RegKeyGuard{hk};
    };

    // 1. Parameters\Instances – DefaultInstance
    {
        RegKeyGuard hInst = OpenOrCreate(kSvcParameters);
        if (!hInst.valid()) {
            LOG_ERROR(L"Failed to create registry key: %ls (0x%08X)",
                      kSvcParameters, GetLastError());
            return GetLastError();
        }

        const DWORD cbDefault =
            static_cast<DWORD>((wcslen(kDefaultInstance) + 1) * sizeof(wchar_t));
        LONG rc = RegSetValueExW(hInst.get(), L"DefaultInstance", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(kDefaultInstance),
                                 cbDefault);
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW DefaultInstance failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }
    }

    // 2. Instance sub-key – Altitude and Flags
    {
        RegKeyGuard hIKey = OpenOrCreate(kSvcInstance);
        if (!hIKey.valid()) {
            LOG_ERROR(L"Failed to create registry key: %ls (0x%08X)",
                      kSvcInstance, GetLastError());
            return GetLastError();
        }

        // Altitude (REG_SZ)
        const DWORD cbAlt =
            static_cast<DWORD>((wcslen(kAltitude) + 1) * sizeof(wchar_t));
        LONG rc = RegSetValueExW(hIKey.get(), L"Altitude", 0, REG_SZ,
                                 reinterpret_cast<const BYTE*>(kAltitude),
                                 cbAlt);
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW Altitude failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }

        // Flags (REG_DWORD = 0x0)
        DWORD flags = 0;
        rc = RegSetValueExW(hIKey.get(), L"Flags", 0, REG_DWORD,
                            reinterpret_cast<const BYTE*>(&flags), sizeof(flags));
        if (rc != ERROR_SUCCESS) {
            LOG_ERROR(L"RegSetValueExW Flags failed (%ld)", rc);
            return static_cast<DWORD>(rc);
        }
    }

    LOG_INFO(L"Minifilter registry configuration complete "
             L"(altitude=%ls, instance='%ls').", kAltitude, kDefaultInstance);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  LoadDriver  (FilterLoad → StartServiceW fallback)
// ────────────────────────────────────────────────────────────────────────────
DWORD LoadDriver(SC_HANDLE hScm)
{
    LOG_INFO(L"Loading driver via FilterLoad('%ls')...", kServiceName);

    HRESULT hr = FilterLoad(kServiceName);
    if (SUCCEEDED(hr)) {
        LOG_INFO(L"FilterLoad succeeded (HRESULT=0x%08X).", hr);
        return ERROR_SUCCESS;
    }

    // HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION) means the driver is not a
    // FltMgr-registered minifilter — fall back to StartServiceW.
    if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION)) {
        LOG_WARN(L"FilterLoad returned ERROR_INVALID_FUNCTION; "
                 L"driver may not be a minifilter. Falling back to StartServiceW...");
    } else {
        LOG_WARN(L"FilterLoad returned 0x%08X; trying StartServiceW as fallback.", hr);
    }

    ScHandleGuard svc(OpenServiceW(hScm, kServiceName,
                                   SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenServiceW for start failed (0x%08X)", err);
        return err;
    }

    if (!StartServiceW(svc.get(), 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_INFO(L"Driver service is already running.");
            return ERROR_SUCCESS;
        }
        LOG_ERROR(L"StartServiceW failed (0x%08X)", err);
        return err;
    }

    // Wait for SERVICE_RUNNING (up to 10 s).
    constexpr int kPollMs  = 500;
    constexpr int kMaxWait = 10'000;
    int waited = 0;
    while (waited < kMaxWait) {
        Sleep(static_cast<DWORD>(kPollMs));
        waited += kPollMs;
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(svc.get(), &ss)) {
            if (ss.dwCurrentState == SERVICE_RUNNING) {
                LOG_INFO(L"Driver service running after %d ms.", waited);
                return ERROR_SUCCESS;
            }
            if (ss.dwCurrentState == SERVICE_STOPPED) {
                LOG_ERROR(L"Driver service stopped unexpectedly "
                          L"(win32ExitCode=0x%08X).", ss.dwWin32ExitCode);
                return ss.dwWin32ExitCode ? ss.dwWin32ExitCode : ERROR_FUNCTION_FAILED;
            }
        }
    }

    LOG_WARN(L"Driver service did not reach RUNNING state within %d ms.", kMaxWait);
    return ERROR_TIMEOUT;
}

// ────────────────────────────────────────────────────────────────────────────
//  SetInstallCompleteMarker
// ────────────────────────────────────────────────────────────────────────────
DWORD SetInstallCompleteMarker()
{
    HKEY  hk    = nullptr;
    DWORD disp  = 0;
    LONG  rc = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, kInstallCompleteKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, &disp);

    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegCreateKeyExW '%ls' failed (%ld)", kInstallCompleteKey, rc);
        return static_cast<DWORD>(rc);
    }

    RegKeyGuard key(hk);
    DWORD       value = 1;
    rc = RegSetValueExW(key.get(), kInstallCompleteVal, 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegSetValueExW InstallComplete failed (%ld)", rc);
        return static_cast<DWORD>(rc);
    }

    LOG_INFO(L"InstallComplete marker written to HKLM\\%ls.", kInstallCompleteKey);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ClearRunOnceEntry
// ────────────────────────────────────────────────────────────────────────────
DWORD ClearRunOnceEntry()
{
    HKEY hk = nullptr;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRunOnceKey, 0,
                            KEY_SET_VALUE, &hk);
    if (rc == ERROR_FILE_NOT_FOUND) {
        // RunOnce key absent – nothing to clean up.
        return ERROR_SUCCESS;
    }
    if (rc != ERROR_SUCCESS) {
        LOG_WARN(L"RegOpenKeyExW RunOnce failed (%ld) – skipping cleanup.", rc);
        return ERROR_SUCCESS; // Non-fatal
    }

    RegKeyGuard key(hk);
    rc = RegDeleteValueW(key.get(), kRunOnceValName);
    if (rc == ERROR_FILE_NOT_FOUND) {
        LOG_INFO(L"RunOnce entry not present; no cleanup needed.");
        return ERROR_SUCCESS;
    }
    if (rc != ERROR_SUCCESS) {
        LOG_WARN(L"RegDeleteValueW RunOnce failed (%ld) – non-fatal.", rc);
        return ERROR_SUCCESS; // Non-fatal
    }

    LOG_INFO(L"RunOnce entry '%ls' removed.", kRunOnceValName);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  UninstallDriver
// ────────────────────────────────────────────────────────────────────────────
DWORD UninstallDriver(SC_HANDLE hScm)
{
    LOG_INFO(L"Beginning driver uninstall...");

    // 1. Stop and remove the SCM entry (tolerate missing service).
    DWORD err = StopAndDeleteExistingService(hScm);
    if (err != ERROR_SUCCESS && err != ERROR_SERVICE_DOES_NOT_EXIST) {
        LOG_WARN(L"StopAndDeleteExistingService returned 0x%08X; continuing.", err);
    }

    // 2. Remove the driver binary from System32\drivers
    std::wstring sysDst = BuildSystemDriverPath();
    if (!sysDst.empty()) {
        if (!DeleteFileW(sysDst.c_str())) {
            err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND) {
                LOG_WARN(L"DeleteFileW('%ls') failed (0x%08X) – may require reboot.",
                         sysDst.c_str(), err);
            }
        } else {
            LOG_INFO(L"Removed driver binary: %ls", sysDst.c_str());
        }
    }

    // 3. Clear install-complete marker.
    {
        HKEY hk = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kInstallCompleteKey, 0,
                                KEY_SET_VALUE, &hk);
        if (rc == ERROR_SUCCESS) {
            RegKeyGuard key(hk);
            RegDeleteValueW(key.get(), kInstallCompleteVal);
            LOG_INFO(L"InstallComplete marker removed.");
        }
    }

    // 4. Remove minifilter instance keys (best-effort).
    RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances\\PhantomSensor Instance",
        KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\PhantomSensor\\Parameters\\Instances",
        KEY_WOW64_64KEY, 0);

    LOG_INFO(L"Driver uninstall complete.");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
