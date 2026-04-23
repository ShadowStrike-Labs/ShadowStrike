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
 *                  Detects testsigning; if off, enables it, writes RunOnce,
 *                  schedules reboot, exits 3010 (ERROR_SUCCESS_REBOOT_REQUIRED).
 *                  If already on, runs Stage 2 inline.
 *
 *   --stage2       Called by RunOnce after reboot. Installs and loads the
 *                  PhantomSensor minifilter driver.
 *
 *   --install-now  Force immediate driver install (admin-only, no reboot pivot).
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

#include "DriverInstaller.hpp"
#include "TestSigningPivot.hpp"

// ────────────────────────────────────────────────────────────────────────────
//  Exit codes (matching standard Windows installer conventions)
// ────────────────────────────────────────────────────────────────────────────
static constexpr int kExitSuccess          = 0;
static constexpr int kExitRebootRequired   = 3010;  // ERROR_SUCCESS_REBOOT_REQUIRED
static constexpr int kExitGenericFailure   = 1;
static constexpr int kExitInsufficientPriv = 5;     // ERROR_ACCESS_DENIED
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
[[nodiscard]] static int RunStage2();
[[nodiscard]] static int RunStage1();
[[nodiscard]] static int RunInstallNow();
[[nodiscard]] static int RunUninstall();

// ────────────────────────────────────────────────────────────────────────────
//  Stage 2 — SCM create, sys copy, minifilter load
// ────────────────────────────────────────────────────────────────────────────
static int RunStage2()
{
    using namespace ShadowStrike::Installer;

    LOG_INFO(L"=== Stage 2: Driver SCM registration and load ===");

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

    // 8. Clean up RunOnce entry (idempotent).
    (void)ClearRunOnceEntry();

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

    bool testSigningOn = false;
    DWORD err = QueryTestSigningState(testSigningOn);
    if (err != ERROR_SUCCESS) {
        LOG_WARN(L"QueryTestSigningState returned 0x%08X; treating as OFF.", err);
        testSigningOn = false;
    }

    if (testSigningOn) {
        LOG_INFO(L"TestSigning is already ON — skipping reboot pivot, running Stage 2 inline.");
        return RunStage2();
    }

    // Enable testsigning.
    err = EnableTestSigning();
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"EnableTestSigning failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    // Register Stage 2 in RunOnce.
    std::wstring ownPath = GetOwnExePath();
    if (ownPath.empty()) {
        LOG_ERROR(L"Cannot determine own exe path for RunOnce registration.");
        return kExitGenericFailure;
    }

    err = WriteRunOnceStage2(ownPath);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"WriteRunOnceStage2 failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    // Schedule system restart.
    err = ScheduleReboot();
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"ScheduleReboot failed (0x%08X).", err);
        return kExitGenericFailure;
    }

    LOG_INFO(L"Stage 1 complete. System restart in 60 s. Returning 3010.");
    return kExitRebootRequired;
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

    if (argc < 2) {
        LOG_ERROR(L"No mode argument. Usage: ShadowStrikeDriverResume.exe "
                  L"[--stage1 | --stage2 | --install-now | --uninstall]");
        FlushLogger();
        return kExitBadArgs;
    }

    std::wstring_view mode(argv[1]);
    int result;

    if (mode == L"--stage1")
        result = RunStage1();
    else if (mode == L"--stage2")
        result = RunStage2();
    else if (mode == L"--install-now")
        result = RunInstallNow();
    else if (mode == L"--uninstall")
        result = RunUninstall();
    else {
        LOG_ERROR(L"Unknown mode argument: '%ls'", argv[1]);
        result = kExitBadArgs;
    }

    LOG_INFO(L"ShadowStrikeDriverResume.exe exiting with %d.", result);
    FlushLogger();
    return result;
}

// ────────────────────────────────────────────────────────────────────────────
//  wmain — SEH-guarded entry point
// ────────────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t* argv[])
{
    __try {
        return InnerMain(argc, argv);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DWORD code = GetExceptionCode();
        wchar_t buf[256];
        _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                     L"[FATAL] Unhandled SEH exception 0x%08X — aborting.\r\n", code);
        OutputDebugStringW(buf);
        WriteLogLine(L"FATAL", buf);
        FlushLogger();
        return kExitGenericFailure;
    }
}
