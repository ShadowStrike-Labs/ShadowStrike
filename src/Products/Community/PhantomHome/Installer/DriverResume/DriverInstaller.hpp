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
 * @file DriverInstaller.hpp
 * @brief PhantomSensor kernel minifilter driver SCM installer and loader.
 *
 * Provides:
 *  - RAII wrappers for SCM/Service/HKEY handles (ZERO raw CloseHandle calls in callers).
 *  - Stop and remove any pre-existing PhantomSensor service entry.
 *  - Atomic copy of PhantomSensor.sys into System32\drivers\ (write-then-move pattern).
 *  - CreateServiceW with correct FILE_SYSTEM_DRIVER / DEMAND_START parameters.
 *  - Minifilter instance registry configuration (altitude, flags, DefaultInstance).
 *  - Driver load: FilterLoad first; fall back to StartServiceW for WDM-only path.
 *  - Install-complete registry marker and RunOnce key cleanup.
 *
 * All operations are logged via DriveResumeLog (internal lightweight logger).
 * Thread safety: all public API is intended for single-threaded installer use only.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winsvc.h>
#include <string>
#include <cstdint>

namespace ShadowStrike::Installer {

// ────────────────────────────────────────────────────────────────────────────
//  Driver / service constants
// ────────────────────────────────────────────────────────────────────────────

inline constexpr wchar_t kServiceName[]        = L"PhantomSensor";
inline constexpr wchar_t kServiceDisplayName[] = L"ShadowStrike PhantomSensor";
inline constexpr wchar_t kServiceDescription[] =
    L"ShadowStrike Next-Generation AntiVirus kernel sensor for real-time "
    L"threat detection, ransomware protection, and endpoint security.";
inline constexpr wchar_t kLoadOrderGroup[]     = L"FSFilter Anti-Virus";
inline constexpr wchar_t kAltitude[]           = L"385210";
inline constexpr wchar_t kDefaultInstance[]    = L"PhantomSensor Instance";
inline constexpr wchar_t kDriverSysName[]      = L"PhantomSensor.sys";
inline constexpr wchar_t kDriverSubPath[]      = L"Drivers\\PhantomSensor.sys";
inline constexpr wchar_t kSystem32Drivers[]    = L"\\System32\\drivers\\";

// Registry keys
inline constexpr wchar_t kInstallCompleteKey[] =
    L"SOFTWARE\\ShadowStrike\\PhantomHome\\Driver";
inline constexpr wchar_t kInstallCompleteVal[] = L"InstallComplete";
inline constexpr wchar_t kRunOnceKey[]         =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
inline constexpr wchar_t kRunOnceValName[]     = L"PhantomSensorDriverInstall";

// ────────────────────────────────────────────────────────────────────────────
//  RAII handle wrappers
// ────────────────────────────────────────────────────────────────────────────

/** RAII wrapper for Win32 HANDLE. */
struct HandleGuard {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit HandleGuard(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : h(handle) {}
    ~HandleGuard() noexcept { if (h != INVALID_HANDLE_VALUE && h != nullptr) CloseHandle(h); }

    HandleGuard(const HandleGuard&)            = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
    HandleGuard& operator=(HandleGuard&& o) noexcept {
        if (this != &o) {
            if (h != INVALID_HANDLE_VALUE && h != nullptr) CloseHandle(h);
            h = o.h; o.h = INVALID_HANDLE_VALUE;
        }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept {
        return h != INVALID_HANDLE_VALUE && h != nullptr;
    }
    [[nodiscard]] HANDLE get() const noexcept { return h; }
    HANDLE release() noexcept { HANDLE r = h; h = INVALID_HANDLE_VALUE; return r; }
};

/** RAII wrapper for SC_HANDLE (SCM or service). */
struct ScHandleGuard {
    SC_HANDLE h = nullptr;
    explicit ScHandleGuard(SC_HANDLE handle = nullptr) noexcept : h(handle) {}
    ~ScHandleGuard() noexcept { if (h) { CloseServiceHandle(h); h = nullptr; } }

    ScHandleGuard(const ScHandleGuard&)            = delete;
    ScHandleGuard& operator=(const ScHandleGuard&) = delete;
    ScHandleGuard(ScHandleGuard&& o) noexcept : h(o.h) { o.h = nullptr; }
    ScHandleGuard& operator=(ScHandleGuard&& o) noexcept {
        if (this != &o) { if (h) CloseServiceHandle(h); h = o.h; o.h = nullptr; }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept { return h != nullptr; }
    [[nodiscard]] SC_HANDLE get() const noexcept { return h; }
    SC_HANDLE release() noexcept { SC_HANDLE r = h; h = nullptr; return r; }
};

/** RAII wrapper for HKEY. */
struct RegKeyGuard {
    HKEY h = nullptr;
    explicit RegKeyGuard(HKEY handle = nullptr) noexcept : h(handle) {}
    ~RegKeyGuard() noexcept { if (h) { RegCloseKey(h); h = nullptr; } }

    RegKeyGuard(const RegKeyGuard&)            = delete;
    RegKeyGuard& operator=(const RegKeyGuard&) = delete;
    RegKeyGuard(RegKeyGuard&& o) noexcept : h(o.h) { o.h = nullptr; }
    RegKeyGuard& operator=(RegKeyGuard&& o) noexcept {
        if (this != &o) { if (h) RegCloseKey(h); h = o.h; o.h = nullptr; }
        return *this;
    }

    [[nodiscard]] bool valid() const noexcept { return h != nullptr; }
    [[nodiscard]] HKEY get() const noexcept { return h; }
};

// ────────────────────────────────────────────────────────────────────────────
//  Public API
// ────────────────────────────────────────────────────────────────────────────

/**
 * @brief Resolve the full path to the staged PhantomSensor.sys.
 *
 * The driver is expected at:
 *   <install_folder>\Drivers\PhantomSensor.sys
 *
 * Where <install_folder> is determined from:
 *   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{product-code}\InstallLocation
 * or falls back to the directory of the running executable.
 *
 * @param[out] outPath  Receives the full UNC-safe path (\\?\ prefixed).
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD ResolveInstalledDriverPath(std::wstring& outPath);

/**
 * @brief Copy PhantomSensor.sys from the install Drivers\ folder to System32\drivers\.
 *
 * Uses a write-then-rename atomic pattern:
 *  1. Write to System32\drivers\PhantomSensor.sys.tmp
 *  2. MoveFileExW with MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
 *
 * This avoids a partial-write window where a broken .sys sits at the final path.
 *
 * @param srcPath  Full path to source .sys (from ResolveInstalledDriverPath).
 * @param dstPath  Full path to destination (System32\drivers\PhantomSensor.sys).
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD CopyDriverBinary(const std::wstring& srcPath,
                                      std::wstring&       dstPath);

/**
 * @brief Stop and delete any existing PhantomSensor SCM entry.
 *
 * Sends SERVICE_CONTROL_STOP (waits up to 10 s for SERVICE_STOPPED),
 * then calls DeleteService. If the service does not exist, returns
 * ERROR_SUCCESS immediately (idempotent).
 *
 * @param hScm  Open SCM handle (SC_MANAGER_ALL_ACCESS).
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD StopAndDeleteExistingService(SC_HANDLE hScm);

/**
 * @brief Create the PhantomSensor SCM service entry.
 *
 * ConfigurationType: SERVICE_FILE_SYSTEM_DRIVER
 * StartType:         SERVICE_DEMAND_START
 * ErrorControl:      SERVICE_ERROR_NORMAL
 * LoadOrderGroup:    FSFilter Anti-Virus
 *
 * @param hScm   Open SCM handle.
 * @param sysDst Full path to the driver binary in System32\drivers\.
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD CreateDriverService(SC_HANDLE         hScm,
                                         const std::wstring& sysDst);

/**
 * @brief Write minifilter instance registry keys under the service tree.
 *
 * Writes:
 *   HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Instances
 *       DefaultInstance = "PhantomSensor Instance"
 *   HKLM\SYSTEM\CurrentControlSet\Services\PhantomSensor\Instances\PhantomSensor Instance
 *       Altitude = "385210"
 *       Flags    = 0x00000000 (DWORD)
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD ConfigureMinifilterRegistry();

/**
 * @brief Load the driver via FilterLoad; fall back to StartServiceW.
 *
 * FilterLoad is the correct method for minifilters.  If it returns
 * HRESULT_FROM_WIN32(ERROR_INVALID_FUNCTION) the driver is not a minifilter
 * and StartServiceW is attempted instead.
 *
 * @param hScm  Open SCM handle (for the StartServiceW fallback path).
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD LoadDriver(SC_HANDLE hScm);

/**
 * @brief Mark driver installation complete in the registry.
 *
 * Writes:
 *   HKLM\SOFTWARE\ShadowStrike\PhantomHome\Driver\InstallComplete = 1 (DWORD)
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD SetInstallCompleteMarker();

/**
 * @brief Remove the RunOnce registry entry added by Stage 1.
 *
 * Idempotent: does nothing if the value is not present.
 *
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD ClearRunOnceEntry();

/**
 * @brief Uninstall the PhantomSensor driver (reverse of Stage 2).
 *
 * Stops and deletes the SCM service, removes System32\drivers\PhantomSensor.sys,
 * clears the install-complete marker, and removes minifilter instance keys.
 *
 * @param hScm  Open SCM handle.
 * @return ERROR_SUCCESS or a Win32 error code.
 */
[[nodiscard]] DWORD UninstallDriver(SC_HANDLE hScm);

} // namespace ShadowStrike::Installer
