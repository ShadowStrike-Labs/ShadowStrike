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
 * @file TestSigningPivot.cpp
 * @brief BCD test-signing detection, enablement, and reboot-pivot implementation.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winreg.h>
#include <reason.h>         // SHTDN_REASON_* constants
#include <powrprof.h>

#include <string>
#include <vector>
#include <cstdio>
#include <cstdint>
#include <cctype>

#include "TestSigningPivot.hpp"
#include "DriverInstaller.hpp"  // kRunOnceKey / kRunOnceValName

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
//  SpawnAndCapture
// ────────────────────────────────────────────────────────────────────────────
DWORD SpawnAndCapture(const std::wstring& cmdLine,
                       std::string&        output,
                       DWORD&              exitCode)
{
    // Create anonymous pipe for stdout/stderr capture.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;

    HANDLE hReadPipe  = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreatePipe failed (0x%08X)", err);
        return err;
    }

    // The parent's read-end must NOT be inherited.
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        DWORD err = GetLastError();
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        LOG_ERROR(L"SetHandleInformation failed (0x%08X)", err);
        return err;
    }

    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = INVALID_HANDLE_VALUE;
    si.hStdOutput  = hWritePipe;
    si.hStdError   = hWritePipe;

    PROCESS_INFORMATION pi{};

    // Mutable copy required by CreateProcessW.
    std::wstring cmd = cmdLine;

    BOOL ok = CreateProcessW(
        nullptr,
        cmd.data(),
        nullptr,     // process security
        nullptr,     // thread security
        TRUE,        // bInheritHandles – lets child inherit write pipe
        CREATE_NO_WINDOW,
        nullptr,     // environment
        nullptr,     // current directory
        &si,
        &pi);

    // Close the write-end in the parent immediately after CreateProcess;
    // the child holds it open. Without this, ReadFile never returns EOF.
    CloseHandle(hWritePipe);

    if (!ok) {
        DWORD err = GetLastError();
        CloseHandle(hReadPipe);
        LOG_ERROR(L"CreateProcessW('%ls') failed (0x%08X)", cmdLine.c_str(), err);
        return err;
    }

    // Read all output from the pipe.
    output.clear();
    std::vector<char> buf(4096);
    for (;;) {
        DWORD bytesRead = 0;
        if (!ReadFile(hReadPipe, buf.data(), static_cast<DWORD>(buf.size()),
                      &bytesRead, nullptr))
            break;
        if (bytesRead == 0)
            break;
        output.append(buf.data(), bytesRead);
    }

    CloseHandle(hReadPipe);

    // Wait for child to exit (generous timeout: 30 s for bcdedit).
    WaitForSingleObject(pi.hProcess, 30'000);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  QueryTestSigningState
// ────────────────────────────────────────────────────────────────────────────
DWORD QueryTestSigningState(bool& outEnabled)
{
    outEnabled = false;

    // ── Source 1: Registry ──────────────────────────────────────────────────
    bool regSaysEnabled = false;
    {
        constexpr wchar_t kBootKey[] =
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot";

        HKEY hk = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kBootKey, 0,
                                KEY_QUERY_VALUE, &hk);
        if (rc == ERROR_SUCCESS) {
            RegKeyGuard key(hk);
            DWORD val  = 0;
            DWORD size = sizeof(val);
            DWORD type = 0;
            rc = RegQueryValueExW(key.get(), L"TestSigningLevel", nullptr,
                                  &type, reinterpret_cast<BYTE*>(&val), &size);
            if (rc == ERROR_SUCCESS && type == REG_DWORD && val != 0) {
                regSaysEnabled = true;
                LOG_INFO(L"Registry TestSigningLevel = %lu (testsigning ON).", val);
            } else {
                LOG_INFO(L"Registry TestSigningLevel = 0 or absent (testsigning OFF).");
            }
        } else {
            LOG_WARN(L"Could not open Boot registry key (%ld); treating as OFF.", rc);
        }
    }

    // ── Source 2: bcdedit output ─────────────────────────────────────────────
    bool bcdSaysEnabled = false;
    {
        wchar_t sysDir[MAX_PATH + 1] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);

        std::wstring cmd = std::wstring(sysDir) +
                           L"\\bcdedit.exe /enum {current} /v";

        std::string bcdOut;
        DWORD       bcdExit = 0;
        DWORD       err     = SpawnAndCapture(cmd, bcdOut, bcdExit);

        if (err != ERROR_SUCCESS) {
            LOG_WARN(L"bcdedit spawn failed (0x%08X); relying on registry only.", err);
        } else if (bcdExit != 0) {
            LOG_WARN(L"bcdedit exited with %lu; relying on registry only.", bcdExit);
        } else {
            // Case-insensitive search for "testsigning" followed by "Yes".
            // bcdedit output example line: "testsigning             Yes"
            std::string lower = bcdOut;
            for (char& c : lower) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            auto pos = lower.find("testsigning");
            if (pos != std::string::npos) {
                auto yesPos = lower.find("yes", pos);
                // Ensure "yes" is on the same logical line (within 100 chars)
                if (yesPos != std::string::npos && (yesPos - pos) < 100) {
                    bcdSaysEnabled = true;
                    LOG_INFO(L"bcdedit confirms testsigning is ON.");
                } else {
                    LOG_INFO(L"bcdedit confirms testsigning is OFF.");
                }
            } else {
                // "testsigning" absent from output means it hasn't been set at all.
                LOG_INFO(L"bcdedit output does not contain 'testsigning' entry.");
            }
        }
    }

    // Both sources must agree for us to declare testsigning ON.
    outEnabled = (regSaysEnabled && bcdSaysEnabled);
    LOG_INFO(L"TestSigning consensus: registry=%hs bcd=%hs => %hs",
             regSaysEnabled ? "ON" : "OFF",
             bcdSaysEnabled ? "ON" : "OFF",
             outEnabled     ? "ENABLED" : "DISABLED");

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  EnableTestSigning
// ────────────────────────────────────────────────────────────────────────────
DWORD EnableTestSigning()
{
    wchar_t sysDir[MAX_PATH + 1] = {};
    GetSystemDirectoryW(sysDir, MAX_PATH);

    std::wstring cmd = std::wstring(sysDir) +
                       L"\\bcdedit.exe /set {current} testsigning on";

    LOG_INFO(L"Enabling test signing: %ls", cmd.c_str());

    std::string bcdOut;
    DWORD       bcdExit = 0;
    DWORD       err     = SpawnAndCapture(cmd, bcdOut, bcdExit);

    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"bcdedit spawn failed (0x%08X)", err);
        return err;
    }

    if (bcdExit != 0) {
        LOG_ERROR(L"bcdedit /set testsigning on exited with %lu. Output: %hs",
                  bcdExit, bcdOut.c_str());
        return ERROR_FUNCTION_FAILED;
    }

    LOG_INFO(L"bcdedit /set testsigning on succeeded. Output: %hs", bcdOut.c_str());

    // Verify the change was persisted by re-querying.
    bool confirmed = false;
    err = QueryTestSigningState(confirmed);
    if (err == ERROR_SUCCESS && !confirmed) {
        LOG_WARN(L"bcdedit reported success but state query still says OFF. "
                 L"This may resolve after reboot.");
    }

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  WriteRunOnceStage2
// ────────────────────────────────────────────────────────────────────────────
DWORD WriteRunOnceStage2(const std::wstring& stage2ExePath)
{
    // Build the full command: "<path>" --stage2
    std::wstring cmdValue = L"\"" + stage2ExePath + L"\" --stage2";

    HKEY  hk    = nullptr;
    DWORD disp  = 0;
    LONG  rc = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE, kRunOnceKey, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hk, &disp);

    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegCreateKeyExW RunOnce failed (%ld)", rc);
        return static_cast<DWORD>(rc);
    }

    RegKeyGuard key(hk);
    const DWORD cb = static_cast<DWORD>((cmdValue.size() + 1) * sizeof(wchar_t));
    rc = RegSetValueExW(key.get(), kRunOnceValName, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(cmdValue.c_str()), cb);
    if (rc != ERROR_SUCCESS) {
        LOG_ERROR(L"RegSetValueExW RunOnce cmd failed (%ld)", rc);
        return static_cast<DWORD>(rc);
    }

    LOG_INFO(L"RunOnce entry written: %ls = %ls", kRunOnceValName, cmdValue.c_str());
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ScheduleReboot
// ────────────────────────────────────────────────────────────────────────────
DWORD ScheduleReboot()
{
    // Acquire SE_SHUTDOWN_NAME privilege.
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenProcessToken failed (0x%08X)", err);
        return err;
    }

    struct TokenGuard {
        HANDLE h;
        ~TokenGuard() { if (h) CloseHandle(h); }
    } tg{hToken};

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME,
                               &tp.Privileges[0].Luid)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"LookupPrivilegeValueW(SE_SHUTDOWN_NAME) failed (0x%08X)", err);
        return err;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) ||
        GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        DWORD err = GetLastError();
        LOG_ERROR(L"AdjustTokenPrivileges failed (0x%08X) -- need SeShutdownPrivilege.", err);
        return (err != ERROR_SUCCESS) ? err : ERROR_PRIVILEGE_NOT_HELD;
    }

    constexpr wchar_t kMessage[] =
        L"ShadowStrike Phantom Home is completing driver installation.\n"
        L"Your system will restart in 60 seconds to enable kernel-mode protection.";

    LOG_INFO(L"Initiating system restart (60 s countdown)...");

    BOOL ok = InitiateSystemShutdownExW(
        nullptr,            // local machine
        const_cast<LPWSTR>(kMessage),
        60,                 // timeout in seconds
        FALSE,              // bForceAppsClosed – allow apps to save
        TRUE,               // bRebootAfterShutdown
        SHTDN_REASON_MAJOR_APPLICATION | SHTDN_REASON_FLAG_PLANNED);

    if (!ok) {
        DWORD err = GetLastError();
        LOG_ERROR(L"InitiateSystemShutdownExW failed (0x%08X)", err);
        return err;
    }

    LOG_INFO(L"System restart scheduled successfully.");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
