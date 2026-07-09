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
 * @file DriverResumeMain.cpp
 * @brief ShadowStrikeDriverResume.exe – production-grade PhantomSensor driver
 *        installer helper.
 *
 * Execution modes (command-line argument):
 *   --stage1       Called by MSI deferred CA immediately after install.
 *                  Detects testsigning; if off, enables it, registers a SYSTEM
 *                  scheduled task for Stage 2, exits 3010
 *                  (ERROR_SUCCESS_REBOOT_REQUIRED). If already on, runs Stage 2
 *                  inline.
 *   --stage1-msi   MSI-safe Stage 1 wrapper: performs the same work but maps
 *                  the reboot-required 3010 result to success because Windows
 *                  Installer treats EXE custom-action non-zero exits as
 *                  failures/rollback. The MSI schedules the reboot explicitly.
 *
 *   --stage2       Called by the SYSTEM scheduled task after reboot. Installs
 *                  and loads the PhantomSensor minifilter driver.
 *
 *   --install-now  Force immediate driver install (admin-only, no reboot pivot).
 *
 *   --start-service
 *                  Start ShadowStrikePhantomService through SCM with bounded
 *                  diagnostics. Used for post-install triage and safe retries.
 *
 *   --uninstall    Stop and remove the PhantomSensor driver service.
 *
 * Architecture guarantees:
 *   - SEH top-level handler prevents crash propagation.
 *   - Privilege checked before any driver operation.
 *   - All handles are RAII-guarded (no raw CloseHandle in callers).
 *   - Logs go to %ProgramData%\ShadowStrike\Logs\DriverResume.<PID>.log.
 *
 * Linking requirements (see ShadowStrikeDriverResume.vcxproj):
 *   advapi32.lib  kernel32.lib  user32.lib  shell32.lib  fltlib.lib
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <winsvc.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include <string>
#include <string_view>
#include <mutex>
#include <optional>
#include <vector>
#include <cwctype>

#include "DriverInstaller.hpp"
#include "TestSigningPivot.hpp"
#include "RootCertInstall.hpp"
#include "SecureBootCheck.hpp"
#include "Stage1Diagnostics.hpp"
#include "DefenderExclusions.hpp"
#include "PrivilegeHelper.hpp"

// ────────────────────────────────────────────────────────────────────────────
//  Exit codes (matching standard Windows installer conventions)
// ────────────────────────────────────────────────────────────────────────────
static constexpr int kExitSuccess          = 0;
static constexpr int kExitRebootRequired   = 3010;  // ERROR_SUCCESS_REBOOT_REQUIRED
static constexpr int kExitGenericFailure   = 1;
static constexpr int kExitInsufficientPriv = 5;     // ERROR_ACCESS_DENIED
static constexpr int kExitSecureBootBlocked = 6;    // Snapshot-only signal; stage1-msi maps to success
static constexpr int kExitBadArgs          = 87;    // ERROR_INVALID_PARAMETER

// ────────────────────────────────────────────────────────────────────────────
//  Lightweight file logger
//  Writes to %ProgramData%\ShadowStrike\Logs\DriverResume.<PID>.log
// ────────────────────────────────────────────────────────────────────────────
static HANDLE    g_logFile = INVALID_HANDLE_VALUE;
static std::mutex g_logMtx;

static void InitLogger() noexcept
{
    wchar_t dataDir[MAX_PATH + 1] = {};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr,
                                SHGFP_TYPE_CURRENT, dataDir)))
    {
        wcscpy_s(dataDir, MAX_PATH, L"C:\\ProgramData");
    }

    wchar_t logDir[MAX_PATH + 1];
    _snwprintf_s(logDir, MAX_PATH, _TRUNCATE, L"%ls\\ShadowStrike\\Logs", dataDir);
    CreateDirectoryW(logDir, nullptr);  // Idempotent; ignore ERROR_ALREADY_EXISTS.

    wchar_t logPath[MAX_PATH + 1];
    _snwprintf_s(logPath, MAX_PATH, _TRUNCATE,
                 L"%ls\\DriverResume.%lu.log", logDir, GetCurrentProcessId());

    g_logFile = CreateFileW(
        logPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    // If creation fails, logs go to OutputDebugString only. Non-fatal.
}

static void WriteLogLine(const wchar_t* level, const wchar_t* msg) noexcept
{
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t line[4096];
    _snwprintf_s(line, _countof(line), _TRUNCATE,
                 L"%04d-%02d-%02dT%02d:%02d:%02d.%03d [%ls] %ls\r\n",
                 st.wYear, st.wMonth, st.wDay,
                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 level, msg);

    std::lock_guard<std::mutex> lk(g_logMtx);
    OutputDebugStringW(line);

    if (g_logFile != INVALID_HANDLE_VALUE) {
        // UTF-8 encode for cross-tool compatibility.
        int cbUtf8 = WideCharToMultiByte(CP_UTF8, 0, line, -1,
                                          nullptr, 0, nullptr, nullptr);
        if (cbUtf8 > 1) {
            std::string u8(static_cast<size_t>(cbUtf8 - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, line, -1,
                                u8.data(), cbUtf8 - 1, nullptr, nullptr);
            DWORD written = 0;
            WriteFile(g_logFile, u8.data(), static_cast<DWORD>(u8.size()),
                      &written, nullptr);
        }
    }
}

static void FlushLogger() noexcept
{
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(g_logFile);
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Logging trampoline – consumed by DriverInstaller.cpp and TestSigningPivot.cpp
// ────────────────────────────────────────────────────────────────────────────
namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...)
{
    wchar_t buf[2048];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    WriteLogLine(level, buf);
}
} // namespace ShadowStrike::Installer::Internal

#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

// ────────────────────────────────────────────────────────────────────────────
//  Privilege check
// ────────────────────────────────────────────────────────────────────────────
[[nodiscard]] static bool IsRunningAsAdmin() noexcept
{
    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&ntAuth, 2,
                                   SECURITY_BUILTIN_DOMAIN_RID,
                                   DOMAIN_ALIAS_RID_ADMINS,
                                   0, 0, 0, 0, 0, 0, &adminSid))
        return false;

    BOOL isMember = FALSE;
    CheckTokenMembership(nullptr, adminSid, &isMember);
    FreeSid(adminSid);
    return !!isMember;
}

// ────────────────────────────────────────────────────────────────────────────
//  Own exe path (for RunOnce registration)
// ────────────────────────────────────────────────────────────────────────────
[[nodiscard]] static std::wstring GetOwnExePath()
{
    wchar_t buf[MAX_PATH + 1] = {};
    DWORD len = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
        return {};
    return std::wstring(buf, len);
}

// ────────────────────────────────────────────────────────────────────────────
//  Forward declarations for all modes
// ────────────────────────────────────────────────────────────────────────────
[[nodiscard]] static std::wstring GetInstallDirectory();

// ────────────────────────────────────────────────────────────────────────────
//  Install-folder anchor (written by the MSI under HKLM)
//  HKLM\SOFTWARE\ShadowStrike\PhantomHome\Install!InstallFolder = REG_SZ
// ────────────────────────────────────────────────────────────────────────────
static constexpr wchar_t kInstallAnchorKey[]   =
    L"SOFTWARE\\ShadowStrike\\PhantomHome\\Install";
static constexpr wchar_t kInstallAnchorValue[] = L"InstallFolder";
static constexpr wchar_t kRootCertRelPath[]    = L"Certs\\ShadowStrike-Dev.cer";

[[nodiscard]] static DWORD ReadInstallFolderFromAnchor(std::wstring& outFolder) noexcept
{
    // KEY_WOW64_64KEY explicitly because the MSI writes the native 64-bit view.
    DWORD cb = 0;
    LONG  rc = RegGetValueW(HKEY_LOCAL_MACHINE,
                            kInstallAnchorKey,
                            kInstallAnchorValue,
                            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                            nullptr,
                            nullptr,
                            &cb);
    if (rc != ERROR_SUCCESS || cb == 0 || cb > 32u * 1024u) {
        return rc != ERROR_SUCCESS ? static_cast<DWORD>(rc) : ERROR_INVALID_DATA;
    }
    std::wstring buf(cb / sizeof(wchar_t), L'\0');
    rc = RegGetValueW(HKEY_LOCAL_MACHINE,
                      kInstallAnchorKey,
                      kInstallAnchorValue,
                      RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                      nullptr,
                      buf.data(),
                      &cb);
    if (rc != ERROR_SUCCESS) {
        return static_cast<DWORD>(rc);
    }
    // Strip trailing NUL(s) and separators.
    while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
    while (!buf.empty() && (buf.back() == L'\\' || buf.back() == L'/')) buf.pop_back();
    if (buf.empty()) {
        return ERROR_INVALID_DATA;
    }
    outFolder = std::move(buf);
    return ERROR_SUCCESS;
}

// Resolve the install folder via the anchor; fall back to the exe directory
// (Stage 2 task runs from the install folder anyway, so it is a safe fallback).
[[nodiscard]] static std::wstring ResolveInstallFolderOrExeDir() noexcept
{
    std::wstring fromAnchor;
    if (ReadInstallFolderFromAnchor(fromAnchor) == ERROR_SUCCESS) {
        return fromAnchor;
    }
    return GetInstallDirectory();
}

[[nodiscard]] static DWORD ResolveRootCertPath(std::wstring& outPath) noexcept
{
    const std::wstring folder = ResolveInstallFolderOrExeDir();
    if (folder.empty()) {
        LOG_ERROR(L"ResolveRootCertPath: cannot determine install folder.");
        return ERROR_PATH_NOT_FOUND;
    }
    outPath = folder + L"\\" + kRootCertRelPath;
    return ERROR_SUCCESS;
}

[[nodiscard]] static int RunInstallRootCert(int argc, wchar_t* argv[])
{
    LOG_INFO(L"=== Mode: --install-root-cert ===");

    std::wstring cerPath;
    if (argc >= 3 && argv[2] != nullptr && argv[2][0] != L'\0') {
        cerPath = argv[2];
    } else {
        DWORD err = ResolveRootCertPath(cerPath);
        if (err != ERROR_SUCCESS) {
            LOG_ERROR(L"RunInstallRootCert: could not resolve cer path "
                      L"(0x%08X).", err);
            return kExitGenericFailure;
        }
    }

    const DWORD err = ShadowStrike::Installer::InstallShadowStrikeRootCert(cerPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"RunInstallRootCert: failed (0x%08X).", err);
        return kExitGenericFailure;
    }
    return kExitSuccess;
}

[[nodiscard]] static int RunStage2();
[[nodiscard]] static int RunStage1();
[[nodiscard]] static int RunStage1Msi();
[[nodiscard]] static int RunInstallNow();
[[nodiscard]] static int RunStartService();
[[nodiscard]] static int RunUninstall();
[[nodiscard]] static int RunInstallRootCert(int argc, wchar_t* argv[]);

// ────────────────────────────────────────────────────────────────────────────
//  PhantomHome user-mode service startup
// ────────────────────────────────────────────────────────────────────────────
static constexpr wchar_t kHomeServiceName[] = L"ShadowStrikePhantomService";
static constexpr DWORD kHomeServiceStartTimeoutMs = 30000;
static constexpr DWORD kHomeServicePollIntervalMs = 500;

[[nodiscard]] static std::wstring GetInstallDirectory()
{
    const std::wstring ownPath = GetOwnExePath();
    const std::wstring::size_type slash = ownPath.find_last_of(L"\\/");
    if (ownPath.empty() || slash == std::wstring::npos) {
        return {};
    }
    return ownPath.substr(0, slash);
}

[[nodiscard]] static std::wstring StripServiceBinaryArguments(std::wstring path)
{
    while (!path.empty() && iswspace(path.front())) {
        path.erase(path.begin());
    }

    if (!path.empty() && path.front() == L'"') {
        const auto endQuote = path.find(L'"', 1);
        if (endQuote != std::wstring::npos) {
            return path.substr(1, endQuote - 1);
        }
    }

    const auto exePos = path.find(L".exe");
    if (exePos != std::wstring::npos) {
        return path.substr(0, exePos + 4);
    }

    return path;
}

[[nodiscard]] static std::optional<std::wstring> GetNormalizedFullPath(const std::wstring& path)
{
    if (path.empty()) {
        return std::nullopt;
    }

    const DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (required == 0 || required > 32768) {
        return std::nullopt;
    }

    std::wstring full(required, L'\0');
    const DWORD written = GetFullPathNameW(path.c_str(), required, full.data(), nullptr);
    if (written == 0 || written >= required) {
        return std::nullopt;
    }

    full.resize(written);
    return full;
}

[[nodiscard]] static bool SamePath(const std::wstring& lhs, const std::wstring& rhs)
{
    const std::optional<std::wstring> lhsFull = GetNormalizedFullPath(lhs);
    const std::optional<std::wstring> rhsFull = GetNormalizedFullPath(rhs);
    if (!lhsFull || !rhsFull) {
        return false;
    }
    return _wcsicmp(lhsFull->c_str(), rhsFull->c_str()) == 0;
}

[[nodiscard]] static DWORD VerifyHomeServiceRegistered() noexcept
{
    using namespace ShadowStrike::Installer;

    const std::wstring installDir = GetInstallDirectory();
    if (installDir.empty()) {
        LOG_ERROR(L"Cannot resolve install directory for service verification.");
        return ERROR_INVALID_DATA;
    }

    std::wstring expectedBinary = installDir;
    expectedBinary += L"\\ShadowStrikePhantomService.exe";
    if (GetFileAttributesW(expectedBinary.c_str()) == INVALID_FILE_ATTRIBUTES) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"Expected service binary is missing: '%ls' (0x%08X).",
                  expectedBinary.c_str(), err);
        return err;
    }

    ScHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"OpenSCManagerW for service verification failed (0x%08X).", err);
        return err;
    }

    ScHandleGuard svc(OpenServiceW(scm.get(), kHomeServiceName, SERVICE_QUERY_CONFIG));
    if (!svc.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"Required service '%ls' is not registered in SCM (0x%08X).",
                  kHomeServiceName, err);
        return err;
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(svc.get(), nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"QueryServiceConfigW size query failed for '%ls' (0x%08X).",
                  kHomeServiceName, err);
        return err;
    }

    std::vector<BYTE> storage(bytesNeeded);
    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    if (!QueryServiceConfigW(svc.get(), cfg, bytesNeeded, &bytesNeeded)) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"QueryServiceConfigW failed for '%ls' (0x%08X).",
                  kHomeServiceName, err);
        return err;
    }

    const std::wstring actualBinary =
        StripServiceBinaryArguments(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"");
    if (!SamePath(actualBinary, expectedBinary)) {
        LOG_ERROR(L"Service '%ls' binary path mismatch. Expected='%ls' Actual='%ls'.",
                  kHomeServiceName, expectedBinary.c_str(), actualBinary.c_str());
        return ERROR_BAD_CONFIGURATION;
    }

    LOG_INFO(L"Verified SCM service '%ls' registered with binary '%ls'.",
             kHomeServiceName, expectedBinary.c_str());
    return ERROR_SUCCESS;
}

[[nodiscard]] static DWORD StartHomeServiceBestEffort(const wchar_t* reason) noexcept
{
    using namespace ShadowStrike::Installer;

    LOG_INFO(L"Starting '%ls' via SCM (%ls).",
             kHomeServiceName, reason ? reason : L"no reason");

    ScHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"OpenSCManagerW for home service start failed (0x%08X).", err);
        return err;
    }

    ScHandleGuard svc(OpenServiceW(
        scm.get(),
        kHomeServiceName,
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE));
    if (!svc.valid()) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"OpenServiceW('%ls') failed (0x%08X).",
                  kHomeServiceName, err);
        return err;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                              reinterpret_cast<LPBYTE>(&ssp),
                              sizeof(ssp), &bytesNeeded)) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"Initial QueryServiceStatusEx('%ls') failed (0x%08X).",
                  kHomeServiceName, err);
        return err;
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        LOG_INFO(L"Home service is already running (pid=%lu).", ssp.dwProcessId);
        return ERROR_SUCCESS;
    }

    if (ssp.dwCurrentState != SERVICE_START_PENDING) {
        if (!StartServiceW(svc.get(), 0, nullptr)) {
            const DWORD err = GetLastError();
            if (err != ERROR_SERVICE_ALREADY_RUNNING) {
                LOG_ERROR(L"StartServiceW('%ls') failed immediately "
                          L"(0x%08X, state=%lu, win32Exit=%lu, serviceExit=%lu).",
                          kHomeServiceName, err, ssp.dwCurrentState,
                          ssp.dwWin32ExitCode, ssp.dwServiceSpecificExitCode);
                return err;
            }
        }
    }

    const ULONGLONG deadline = GetTickCount64() + kHomeServiceStartTimeoutMs;
    for (;;) {
        ZeroMemory(&ssp, sizeof(ssp));
        bytesNeeded = 0;
        if (!QueryServiceStatusEx(svc.get(), SC_STATUS_PROCESS_INFO,
                                  reinterpret_cast<LPBYTE>(&ssp),
                                  sizeof(ssp), &bytesNeeded)) {
            const DWORD err = GetLastError();
            LOG_ERROR(L"QueryServiceStatusEx('%ls') during start failed "
                      L"(0x%08X).", kHomeServiceName, err);
            return err;
        }

        if (ssp.dwCurrentState == SERVICE_RUNNING) {
            LOG_INFO(L"Home service reached RUNNING (pid=%lu).", ssp.dwProcessId);
            return ERROR_SUCCESS;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            const DWORD err = ssp.dwWin32ExitCode != ERROR_SUCCESS
                ? ssp.dwWin32ExitCode
                : ERROR_SERVICE_NOT_ACTIVE;
            LOG_ERROR(L"Home service stopped during startup "
                      L"(win32Exit=%lu, serviceExit=%lu, checkpoint=%lu).",
                      ssp.dwWin32ExitCode, ssp.dwServiceSpecificExitCode,
                      ssp.dwCheckPoint);
            return err;
        }

        if (GetTickCount64() >= deadline) {
            LOG_ERROR(L"Timed out after %lu ms waiting for '%ls' to reach "
                      L"RUNNING (state=%lu, checkpoint=%lu, waitHint=%lu).",
                      kHomeServiceStartTimeoutMs, kHomeServiceName,
                      ssp.dwCurrentState, ssp.dwCheckPoint, ssp.dwWaitHint);
            return WAIT_TIMEOUT;
        }

        Sleep(kHomeServicePollIntervalMs);
    }
}

// ────────────────────────────────────────────────────────────────────────────
//  Stage 2 — SCM create, sys copy, minifilter load
// ────────────────────────────────────────────────────────────────────────────
static int RunStage2()
{
    using namespace ShadowStrike::Installer;

    LOG_INFO(L"=== Stage 2: Driver SCM registration and load ===");

    // Defence-in-depth: ensure the ShadowStrike root cert is in the
    // LocalMachine Root + TrustedPublisher stores BEFORE we attempt to
    // FilterLoad the (test-)signed driver. The MSI custom action SHOULD
    // already have done this, but Stage 2 cannot trust prior state.
    {
        std::wstring cerPath;
        DWORD certErr = ResolveRootCertPath(cerPath);
        if (certErr != ERROR_SUCCESS) {
            LOG_ERROR(L"Stage 2: cannot resolve root-cert path (0x%08X).", certErr);
            return kExitGenericFailure;
        }
        certErr = ShadowStrike::Installer::InstallShadowStrikeRootCert(cerPath);
        if (certErr != ERROR_SUCCESS) {
            LOG_ERROR(L"Stage 2: InstallShadowStrikeRootCert('%ls') failed "
                      L"(0x%08X).", cerPath.c_str(), certErr);
            return kExitGenericFailure;
        }
    }

    ScHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenSCManagerW failed (0x%08X) — insufficient privileges.", err);
        return kExitInsufficientPriv;
    }

    // 1. Stop and delete any pre-existing service entry (idempotent).
    DWORD err = StopAndDeleteExistingService(scm.get());
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"StopAndDeleteExistingService failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    // 2. Resolve staged driver source path.
    std::wstring srcPath;
    err = ResolveInstalledDriverPath(srcPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"ResolveInstalledDriverPath failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    // 3. Copy driver to System32\drivers\ via write-then-rename.
    std::wstring dstPath;
    err = CopyDriverBinary(srcPath, dstPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"CopyDriverBinary failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    // 4. Create SCM service entry.
    err = CreateDriverService(scm.get(), dstPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"CreateDriverService failed (0x%08X).", err);
        DeleteFileW(dstPath.c_str());  // Clean up orphan binary.
        return kExitGenericFailure;
    }

    // 5. Write minifilter instance registry keys (Altitude, Flags, DefaultInstance).
    err = ConfigureMinifilterRegistry();
    if (err != ERROR_SUCCESS) {
        LOG_WARN(L"ConfigureMinifilterRegistry failed (0x%08X); continuing with WDM-only load.",
                 err);
    }

    // 6. Load the driver: FilterLoad → StartServiceW fallback.
    err = LoadDriver(scm.get());
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"LoadDriver failed (0x%08X). Rolling back SCM entry and driver binary.", err);
        // Rollback: remove service and binary so the next install attempt starts clean.
        // Leaving an SCM entry pointing to a non-running driver is a dangerous orphan.
        (void)StopAndDeleteExistingService(scm.get());
        DeleteFileW(dstPath.c_str());
        return kExitGenericFailure;
    }
    LOG_INFO(L"Driver loaded and running.");

    // 7. Write InstallComplete registry marker ONLY on full success.
    //    If this is skipped (LoadDriver failed above, we returned), the bundle
    //    will attempt the full install again on next launch, which is correct.
    DWORD markerErr = SetInstallCompleteMarker();
    if (markerErr != ERROR_SUCCESS) {
        LOG_WARN(L"SetInstallCompleteMarker failed (0x%08X) — bundle detection may re-run.",
                 markerErr);
    }

    // 8. Clean up legacy RunOnce and current scheduled-task pivots (idempotent).
    (void)ClearRunOnceEntry();
    (void)DeleteStage2ScheduledTask();

    // FIX: Do NOT synchronously start ShadowStrikePhantomService here.
    //
    // The service is registered with Start=auto + DelayedAutostart=1 (see
    // packaging/installer/Components.wxs), so SCM will start it ~2 minutes
    // after boot when initial boot I/O pressure has subsided. Starting it
    // here — immediately after FilterLoad, while the MSI is still finishing
    // and the VMware host is under heavy I/O — has been observed to wedge
    // the guest: the service spawns N worker threads that all hammer
    // FilterConnectCommunicationPort against a freshly-loaded minifilter,
    // producing a ConnectNotify storm that hard-hangs the system (grey
    // screen, no BSOD, no minidump).
    //
    // The DELAYED_AUTO_START recovery policy and service registration set up
    // earlier in this stage continue to govern start-up; if SCM fails to
    // start the service it will retry per its recovery policy. The next
    // explicit start happens at next boot, which is the desired behaviour.
    LOG_INFO(L"Home service start deferred to SCM delayed-auto-start "
             L"(prevents post-FilterLoad ConnectNotify storm on first boot).");

    // Best-effort Defender exclusions post-success.  Failure here MUST NOT
    // fail Stage 2 -- signed binaries should pass Defender on their own.
    {
        const std::wstring installFolder = ResolveInstallFolderOrExeDir();
        if (!installFolder.empty()) {
            const DWORD defErr =
                ShadowStrike::Installer::AddPhantomDefenderExclusions(installFolder);
            if (defErr != ERROR_SUCCESS) {
                LOG_WARN(L"Stage 2: Defender exclusion registration returned "
                         L"0x%08X (best-effort, ignoring).", defErr);
            }
        }
    }

    // Best-effort Defender coexistence: two real-time engines competing is a
    // primary CPU/latency source. Disables Defender RTP when Tamper Protection
    // is off; otherwise records a marker + logs guidance for the UI. Never fails
    // the install.
    {
        const DWORD coexErr = ShadowStrike::Installer::ConfigureDefenderCoexistence();
        if (coexErr != ERROR_SUCCESS) {
            LOG_WARN(L"Stage 2: Defender coexistence step returned 0x%08X "
                     L"(best-effort, ignoring).", coexErr);
        }
    }

    LOG_INFO(L"=== Stage 2 complete. ===");
    return kExitSuccess;
}

// ────────────────────────────────────────────────────────────────────────────
//  Stage 1 — testsigning detection + reboot pivot (or inline Stage 2)
// ────────────────────────────────────────────────────────────────────────────
static int RunStage1()
{
    using namespace ShadowStrike::Installer;

    LOG_INFO(L"=== Stage 1: TestSigning detection and reboot pivot ===");

    Stage1Snapshot snapshot;

    // ── Service registration verification ────────────────────────────────
    DWORD err = VerifyHomeServiceRegistered();
    snapshot.service_registered         = (err == ERROR_SUCCESS);
    snapshot.service_registration_error = err;
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"Service registration verification failed before Stage 1 (0x%08X).", err);
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"ShadowStrikePhantomService is not registered (0x%08X).", err);
        snapshot.last_error_message = msg;
        (void)WriteStage1Snapshot(snapshot);
        return kExitGenericFailure;
    }

    // ── Secure Boot guard (must run BEFORE QueryTestSigningState) ────────
    const SecureBootState sbState = QuerySecureBootState();
    if (sbState == SecureBootState::Enabled) {
        snapshot.secureboot_blocks   = true;
        snapshot.last_error_message =
            L"SecureBoot is enabled in firmware. Disable SecureBoot in the "
            L"VM/PC firmware before installing ShadowStrike Phantom.";
        LOG_ERROR(L"Stage 1 aborting: %ls", snapshot.last_error_message.c_str());
        (void)WriteStage1Snapshot(snapshot);
        return kExitSecureBootBlocked;
    }
    if (sbState == SecureBootState::Unknown) {
        LOG_WARN(L"SecureBoot state is Unknown; proceeding cautiously. "
                 L"Operator should verify firmware settings.");
    }

    // ── TestSigning detection ────────────────────────────────────────────
    bool testSigningOn = false;
    err = QueryTestSigningState(testSigningOn);
    if (err != ERROR_SUCCESS) {
        LOG_WARN(L"QueryTestSigningState returned 0x%08X; treating as OFF.", err);
        testSigningOn = false;
    }
    snapshot.testsigning_state_before = testSigningOn;
    snapshot.testsigning_state_after  = testSigningOn;

    int result;

    if (testSigningOn) {
        LOG_INFO(L"TestSigning is already ON — skipping reboot pivot, running Stage 2 inline.");
        result = RunStage2();
        if (result == kExitSuccess) {
            snapshot.reboot_required = false;
        } else {
            wchar_t msg[128];
            _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                         L"Stage 2 (inline) failed with exit %d.", result);
            snapshot.last_error_message = msg;
        }
        (void)WriteStage1Snapshot(snapshot);
        if (result == kExitSuccess) {
            // Defender exclusions are also best-effort here.
            const std::wstring installFolder = ResolveInstallFolderOrExeDir();
            if (!installFolder.empty()) {
                const DWORD defErr = AddPhantomDefenderExclusions(installFolder);
                if (defErr != ERROR_SUCCESS) {
                    LOG_WARN(L"Stage 1 inline path: Defender exclusion "
                             L"returned 0x%08X (best-effort).", defErr);
                }
            }
        }
        return result;
    }

    // ── Enable testsigning (off → on) ────────────────────────────────────
    err = EnableTestSigning();
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"EnableTestSigning failed (0x%08X).", err);
        snapshot.bcdedit_exit = err;
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"bcdedit /set testsigning on failed (0x%08X).", err);
        snapshot.last_error_message = msg;
        (void)WriteStage1Snapshot(snapshot);
        return kExitGenericFailure;
    }
    snapshot.testsigning_state_after = true;

    // Register Stage 2 as a SYSTEM scheduled task. HKLM RunOnce executes under
    // an interactive user token and can be consumed before a privileged driver
    // install succeeds, leaving the product permanently offline after reboot.
    std::wstring ownPath = GetOwnExePath();
    if (ownPath.empty()) {
        LOG_ERROR(L"Cannot determine own exe path for Stage 2 task registration.");
        snapshot.last_error_message = L"GetModuleFileNameW returned an empty path.";
        (void)WriteStage1Snapshot(snapshot);
        return kExitGenericFailure;
    }

    err = RegisterStage2ScheduledTask(ownPath);
    snapshot.stage2_task_registered = (err == ERROR_SUCCESS);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"RegisterStage2ScheduledTask failed (0x%08X).", err);
        wchar_t msg[256];
        _snwprintf_s(msg, _countof(msg), _TRUNCATE,
                     L"Stage 2 scheduled task registration failed (0x%08X).", err);
        snapshot.last_error_message = msg;
        (void)WriteStage1Snapshot(snapshot);
        return kExitGenericFailure;
    }

    snapshot.reboot_required = true;
    (void)WriteStage1Snapshot(snapshot);

    // Best-effort Defender exclusions before the reboot pivot, so the
    // driver sitting in the install Drivers\ folder survives a Defender
    // scan during early boot.
    {
        const std::wstring installFolder = ResolveInstallFolderOrExeDir();
        if (!installFolder.empty()) {
            const DWORD defErr = AddPhantomDefenderExclusions(installFolder);
            if (defErr != ERROR_SUCCESS) {
                LOG_WARN(L"Stage 1: Defender exclusion returned 0x%08X "
                         L"(best-effort).", defErr);
            }
        }
    }

    LOG_INFO(L"Stage 1 complete. Reboot is required; returning 3010 for installer UI.");
    return kExitRebootRequired;
}

// ────────────────────────────────────────────────────────────────────────────
//  Stage 1 MSI wrapper
// ────────────────────────────────────────────────────────────────────────────
static int RunStage1Msi()
{
    const int result = RunStage1();
    if (result == kExitRebootRequired) {
        LOG_INFO(L"Stage 1 requires reboot; returning success to MSI. "
                 L"The MSI ScheduleReboot action owns the user-visible restart prompt.");
        return kExitSuccess;
    }
    if (result == kExitSecureBootBlocked) {
        // SecureBoot blocks driver load. We MUST NOT fail the MSI here —
        // the bundle inspects driver-stage1.json to surface the firmware
        // remediation step to the user. Rolling back the MSI would also
        // remove the install footprint the operator needs to keep so they
        // can reboot into firmware, disable Secure Boot, and re-run.
        LOG_WARN(L"Stage 1 reported SecureBoot block; returning success to "
                 L"MSI per design (snapshot drives bundle UX).");
        return kExitSuccess;
    }
    return result;
}

// ────────────────────────────────────────────────────────────────────────────
//  --install-now  (force immediate install; no reboot pivot)
// ────────────────────────────────────────────────────────────────────────────
static int RunInstallNow()
{
    LOG_INFO(L"=== Mode: --install-now (forced immediate install) ===");
    return RunStage2();
}

// ────────────────────────────────────────────────────────────────────────────
//  --start-service
// ────────────────────────────────────────────────────────────────────────────
static int RunStartService()
{
    LOG_INFO(L"=== Mode: --start-service ===");
    const DWORD err = StartHomeServiceBestEffort(L"explicit command");
    return err == ERROR_SUCCESS ? kExitSuccess : kExitGenericFailure;
}

// ────────────────────────────────────────────────────────────────────────────
//  --uninstall
// ────────────────────────────────────────────────────────────────────────────
static int RunUninstall()
{
    using namespace ShadowStrike::Installer;

    LOG_INFO(L"=== Mode: --uninstall ===");

    ScHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
    if (!scm.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenSCManagerW failed (0x%08X).", err);
        return kExitInsufficientPriv;
    }

    DWORD err = UninstallDriver(scm.get());
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"UninstallDriver failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    LOG_INFO(L"Uninstall complete.");
    return kExitSuccess;
}

// ────────────────────────────────────────────────────────────────────────────
//  Inner main (SEH wrapper calls this)
// ────────────────────────────────────────────────────────────────────────────
static int InnerMain(int argc, wchar_t* argv[])
{
    InitLogger();
    LOG_INFO(L"ShadowStrikeDriverResume.exe starting (PID=%lu).", GetCurrentProcessId());

    if (!IsRunningAsAdmin()) {
        LOG_ERROR(L"Privilege check failed: must run as Administrator or SYSTEM.");
        FlushLogger();
        return kExitInsufficientPriv;
    }
    LOG_INFO(L"Privilege check passed.");

    // Enable all BCD / firmware / driver-load privileges on the process token
    // BEFORE any sub-mode runs.  Without this, bcdedit child processes inherit
    // a token with SeSystemEnvironmentPrivilege disabled and fail with
    // ERROR_PRIVILEGE_NOT_HELD (0x65B) regardless of running as SYSTEM.  This
    // is best-effort: a partial enable still lets us proceed and report
    // exactly which privileges are missing via Stage1Diagnostics.
    const std::size_t privsEnabled =
        ::ShadowStrike::Installer::EnableInstallerPrivileges();
    if (privsEnabled == 0) {
        LOG_WARN(L"No installer privileges could be enabled. bcdedit and "
                 L"firmware reads are expected to fail; continuing so that "
                 L"the diagnostic snapshot can capture the failure mode.");
    }

    if (argc < 2) {
        LOG_ERROR(L"No mode argument. Usage: ShadowStrikeDriverResume.exe "
                  L"[--stage1 | --stage1-msi | --stage2 | --install-now | "
                  L"--start-service | --uninstall | --install-root-cert [path]]");
        FlushLogger();
        return kExitBadArgs;
    }

    std::wstring_view mode(argv[1]);
    int result;

    if (mode == L"--stage1")
        result = RunStage1();
    else if (mode == L"--stage1-msi")
        result = RunStage1Msi();
    else if (mode == L"--stage2")
        result = RunStage2();
    else if (mode == L"--install-now")
        result = RunInstallNow();
    else if (mode == L"--start-service")
        result = RunStartService();
    else if (mode == L"--uninstall")
        result = RunUninstall();
    else if (mode == L"--install-root-cert")
        result = RunInstallRootCert(argc, argv);
    else {
        LOG_ERROR(L"Unknown mode argument: '%ls'", argv[1]);
        result = kExitBadArgs;
    }

    LOG_INFO(L"ShadowStrikeDriverResume.exe exiting with %d.", result);
    FlushLogger();
    return result;
}

// ────────────────────────────────────────────────────────────────────────────
//  SEH filter — captures GetExceptionCode() into the supplied out-parameter
//  and always elects to handle the exception at the wmain level.  Using a
//  named filter avoids /analyze C6320 ("constant EXCEPTION_EXECUTE_HANDLER
//  may mask exceptions") while preserving the original behaviour.
// ────────────────────────────────────────────────────────────────────────────
static int SehTopLevelFilter(DWORD code, DWORD* outCode) noexcept
{
    if (outCode != nullptr) {
        *outCode = code;
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

// ────────────────────────────────────────────────────────────────────────────
//  wmain — SEH-guarded entry point
// ────────────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    DWORD sehCode = 0;
    __try {
        return InnerMain(argc, argv);
    }
    __except (SehTopLevelFilter(GetExceptionCode(), &sehCode)) {
        wchar_t buf[256];
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                     L"[FATAL] Unhandled SEH exception 0x%08X -- aborting.\r\n", sehCode);
        OutputDebugStringW(buf);
        WriteLogLine(L"FATAL", buf);
        FlushLogger();
        return kExitGenericFailure;
    }
}
