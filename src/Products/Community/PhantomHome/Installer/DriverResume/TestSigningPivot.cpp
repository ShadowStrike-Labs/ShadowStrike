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
 * @brief BCD test-signing detection, enablement, and reboot pivot logic.
 *
 * Security design:
 *  - bcdedit.exe and schtasks.exe are always invoked via absolute path derived from
 *    GetSystemDirectoryW — never via PATH search. This prevents DLL/binary
 *    hijacking via PATH manipulation.
 *  - SpawnAndCapture uses a dedicated reader thread with a hard timeout to
 *    prevent the pipe-read loop from blocking indefinitely if bcdedit hangs.
 *  - Pipe handles are manually inherited only to the child process (PROC_THREAD
 *    ATTRIBUTE_HANDLE_LIST) to prevent accidental inheritance by other children.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

// winreg.h (Win SDK 10.0.26100) declares RegOpenKeyExW with a SAL
// "_Param_" annotation on ulOptions that /analyze /sdl flags as C6553
// ("value annotation is not valid for value type").  The annotation is
// inside the SDK header, not our code; suppress at TU scope so the
// installer can build clean under /analyze /sdl /WX.
#pragma warning(disable: 6553)

#include <string>
#include <string_view>
#include <vector>
#include <cstdio>
#include <cstdlib>

#include "TestSigningPivot.hpp"
#include "DriverInstaller.hpp"  // for HandleGuard, RegKeyGuard

namespace ShadowStrike::Installer::Internal {
void Log(const wchar_t* level, const wchar_t* fmt, ...);
}
#define LOG_INFO(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"INFO ", fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ::ShadowStrike::Installer::Internal::Log(L"WARN ", fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ::ShadowStrike::Installer::Internal::Log(L"ERROR", fmt, ##__VA_ARGS__)

// ────────────────────────────────────────────────────────────────────────────
//  Reader thread context for the pipe-drain thread
// ────────────────────────────────────────────────────────────────────────────
namespace {

constexpr wchar_t kStage2TaskName[] = L"\\ShadowStrike\\PhantomSensorDriverInstall";

struct PipeReaderContext {
    HANDLE       hReadPipe = INVALID_HANDLE_VALUE;
    std::string  output;        // Accumulated bytes (UTF-8 / ANSI)
    DWORD        error = ERROR_SUCCESS;
    // Hard cap on captured output to bound memory in the unlikely event the
    // spawned tool produces a runaway stream.  4 MB is far beyond any
    // legitimate bcdedit output and prevents a tampered substitute binary
    // from exhausting RAM.
    static constexpr std::size_t kMaxOutputBytes = 4u * 1024u * 1024u;
};

DWORD WINAPI PipeReaderThread(LPVOID lpParam)
{
    auto* ctx = static_cast<PipeReaderContext*>(lpParam);

    constexpr DWORD kBufSize = 4096;
    char  buf[kBufSize];

    for (;;) {
        DWORD bytesRead = 0;
        BOOL  ok = ReadFile(ctx->hReadPipe, buf, kBufSize, &bytesRead, nullptr);
        if (ok && bytesRead > 0) {
            const std::size_t room =
                (ctx->output.size() < PipeReaderContext::kMaxOutputBytes)
                ? (PipeReaderContext::kMaxOutputBytes - ctx->output.size())
                : 0;
            const std::size_t take =
                (bytesRead < room) ? static_cast<std::size_t>(bytesRead) : room;
            if (take > 0) {
                ctx->output.append(buf, take);
            }
            // If we've hit the cap, keep draining to allow the child to exit
            // (closing the write end), but discard further bytes.
        } else {
            // ERROR_BROKEN_PIPE / ERROR_HANDLE_EOF signal normal EOF.
            DWORD e = GetLastError();
            if (!ok && e != ERROR_BROKEN_PIPE && e != ERROR_HANDLE_EOF)
                ctx->error = e;
            break;
        }
    }
    return 0;
}

[[nodiscard]] DWORD BuildSystemToolPath(const wchar_t* toolName, std::wstring& outPath)
{
    if (toolName == nullptr || toolName[0] == L'\0') {
        return ERROR_INVALID_PARAMETER;
    }

    wchar_t sysDir[MAX_PATH];
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) {
        const DWORD err = GetLastError();
        LOG_ERROR(L"GetSystemDirectoryW failed while resolving %ls (0x%08X)", toolName, err);
        return err;
    }

    outPath.assign(sysDir);
    outPath += L"\\";
    outPath += toolName;
    return ERROR_SUCCESS;
}

} // anonymous namespace

namespace ShadowStrike::Installer {

// ────────────────────────────────────────────────────────────────────────────
//  HandleGuard re-use for this TU (already defined in DriverInstaller.hpp)
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
//  SpawnAndCapture
//  Executes a trusted system binary (absolute path only) and captures stdout.
//
//  Security requirements:
//   • cmdLine must be built from trusted system paths only (no user input).
//   • Stdout pipe is drained by a dedicated thread with kTimeoutMs timeout.
//     If the child hangs, we TerminateProcess it rather than blocking forever.
//   • Stdin of child is set to NUL (not our stdin) to prevent inheritance
//     of unrelated handles.
//   • No inherited handles except the write end of the stdout pipe.
// ────────────────────────────────────────────────────────────────────────────
// Public definition (declared in TestSigningPivot.hpp; reused by
// DefenderExclusions.cpp).  The header carries the default timeoutMs.
DWORD SpawnAndCapture(
    const std::wstring& cmdLine,
    std::string&        outStdout,
    DWORD&              outExitCode,
    DWORD               timeoutMs)
{
    outExitCode = STILL_ACTIVE;
    // Create anonymous pipe for child stdout.
    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle       = TRUE;

    HANDLE hReadRaw  = INVALID_HANDLE_VALUE;
    HANDLE hWriteRaw = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&hReadRaw, &hWriteRaw, &sa, 0)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreatePipe failed (0x%08X)", err);
        return err;
    }

    HandleGuard hRead(hReadRaw);
    HandleGuard hWrite(hWriteRaw);

    // Make the read end non-inheritable so the child cannot accidentally
    // inherit our copy of it.
    if (!SetHandleInformation(hRead.get(), HANDLE_FLAG_INHERIT, 0)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"SetHandleInformation(hRead, non-inherit) failed (0x%08X)", err);
        return err;
    }

    // Open NUL device for child stdin.
    SECURITY_ATTRIBUTES nulSa{};
    nulSa.nLength        = sizeof(nulSa);
    nulSa.bInheritHandle = TRUE;
    HandleGuard hNul(
        CreateFileW(L"NUL",
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    &nulSa,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr));

    if (!hNul.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"Could not open NUL device for child stdin (0x%08X)", err);
        return err;
    }

    // Use PROC_THREAD_ATTRIBUTE_HANDLE_LIST so ONLY our write-pipe handle
    // and the NUL handle are inherited. All other handles are blocked.
    // This is the safe form of handle inheritance (Vista+).
    const HANDLE inheritHandles[] = { hWrite.get(), hNul.get() };

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);
    if (attrListSize == 0) {
        // Defence in depth: a zero size would yield a zero-byte allocation
        // and a nullptr data() pointer.  /analyze flags the subsequent
        // attribute-list calls otherwise; this branch should be unreachable
        // on any supported Windows version.
        LOG_ERROR(L"InitializeProcThreadAttributeList reported zero buffer size.");
        return ERROR_FUNCTION_FAILED;
    }
    std::vector<BYTE> attrListBuf(attrListSize);
    auto* pAttrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrListBuf.data());
    if (pAttrList == nullptr ||
        !InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrListSize))
    {
        DWORD err = GetLastError();
        LOG_ERROR(L"InitializeProcThreadAttributeList failed (0x%08X)", err);
        return err ? err : ERROR_FUNCTION_FAILED;
    }

    bool attrUpdated = UpdateProcThreadAttribute(
        pAttrList, 0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        const_cast<HANDLE*>(inheritHandles),
        sizeof(inheritHandles),
        nullptr, nullptr);

    if (!attrUpdated) {
        DWORD err = GetLastError();
        DeleteProcThreadAttributeList(pAttrList);
        LOG_ERROR(L"UpdateProcThreadAttribute (handle list) failed (0x%08X)", err);
        return err;
    }

    STARTUPINFOEXW siEx{};
    siEx.StartupInfo.cb          = sizeof(siEx);
    siEx.StartupInfo.dwFlags     = STARTF_USESTDHANDLES;
    siEx.StartupInfo.hStdInput   = hNul.get();
    siEx.StartupInfo.hStdOutput  = hWrite.get();
    siEx.StartupInfo.hStdError   = hWrite.get();
    siEx.lpAttributeList         = pAttrList;

    // cmdLine may be modified by CreateProcessW; make a mutable copy.
    std::wstring mutableCmd = cmdLine;

    PROCESS_INFORMATION pi{};
    BOOL created = CreateProcessW(
        nullptr,
        mutableCmd.data(),
        nullptr,               // process security
        nullptr,               // thread security
        TRUE,                  // bInheritHandles = TRUE (handles enumerated in list)
        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
        nullptr,               // inherit environment
        nullptr,               // inherit CWD
        reinterpret_cast<LPSTARTUPINFOW>(&siEx),
        &pi);

    DeleteProcThreadAttributeList(pAttrList);

    if (!created) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreateProcessW failed for '%ls' (0x%08X)", cmdLine.c_str(), err);
        return err;
    }

    HandleGuard hProc(pi.hProcess);
    HandleGuard hThread(pi.hThread);

    // Close the write end of the pipe in THIS process so the read end gets
    // EOF when the child exits (otherwise ReadFile blocks forever).
    hWrite = HandleGuard{};

    // Start reader thread to drain child stdout asynchronously.
    PipeReaderContext readerCtx;
    readerCtx.hReadPipe = hRead.get();

    HandleGuard hReaderThread(
        CreateThread(nullptr, 0, PipeReaderThread, &readerCtx, 0, nullptr));

    if (!hReaderThread.valid()) {
        DWORD err = GetLastError();
        LOG_ERROR(L"CreateThread for pipe reader failed (0x%08X)", err);
        // Kill the child and bail.
        TerminateProcess(hProc.get(), 1);
        WaitForSingleObject(hProc.get(), 5'000);
        return err;
    }

    // Wait for the process to finish (or timeout).
    DWORD waitResult = WaitForSingleObject(hProc.get(), timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        LOG_ERROR(L"Process '%ls' timed out after %lu ms. Terminating.", cmdLine.c_str(), timeoutMs);
        TerminateProcess(hProc.get(), ERROR_TIMEOUT);
        // After TerminateProcess the kernel closes all child handles
        // including its copy of the pipe write-end, so ReadFile on hRead
        // will return EOF.  Wait for the reader to fully drain before we
        // let the on-stack PipeReaderContext leave scope.
        WaitForSingleObject(hProc.get(), 5'000);
    }

    // Wait for the reader thread to drain remaining output.  We must wait
    // indefinitely (after capping the wait above) because the
    // PipeReaderContext lives on this stack frame — detaching the thread
    // would create a use-after-free window if ReadFile is still pending.
    // The pipe is guaranteed to reach EOF because (a) the parent's write
    // handle was already closed and (b) the child process is now exited.
    if (hReaderThread.valid()) {
        if (WaitForSingleObject(hReaderThread.get(), 5'000) == WAIT_TIMEOUT) {
            // Last-resort recovery: force ReadFile to fail by closing the
            // read end, then wait without bound for the thread to exit.
            // CancelSynchronousIo would be cleaner but is only effective
            // from the owning thread; closing the handle unblocks
            // any pending I/O on it.
            hRead = HandleGuard{};
            WaitForSingleObject(hReaderThread.get(), INFINITE);
        }
    }

    DWORD exitCode = 1;
    GetExitCodeProcess(hProc.get(), &exitCode);
    outExitCode = exitCode;

    if (waitResult == WAIT_TIMEOUT)
        return ERROR_TIMEOUT;
    if (exitCode != 0) {
        LOG_WARN(L"Process '%ls' exited with code %lu.", cmdLine.c_str(), exitCode);
    }

    outStdout = std::move(readerCtx.output);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  QueryTestSigningState
//  Consensus: both the BCD registry value AND bcdedit /enum output are checked.
//  If either is inaccessible, the other is used with a warning.
// ────────────────────────────────────────────────────────────────────────────
#pragma warning(push)
#pragma warning(disable: 6553)
DWORD QueryTestSigningState(bool& outIsOn)
{
    outIsOn = false;

    // ── Source 1: registry ────────────────────────────────────────────────
    bool regSaysOn = false;
    bool regReadable = false;
    {
        HKEY  hk = nullptr;
        LONG  rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                 L"SYSTEM\\CurrentControlSet\\Control\\"
                                 L"Session Manager\\Boot",
                                 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hk);
        if (rc == ERROR_SUCCESS) {
            RegKeyGuard key(hk);
            DWORD val  = 0;
            DWORD size = sizeof(val);
            DWORD type = 0;
            rc = RegQueryValueExW(key.get(), L"TestSigningLevel", nullptr,
                                  &type, reinterpret_cast<BYTE*>(&val), &size);
            if (rc == ERROR_SUCCESS && type == REG_DWORD) {
                regSaysOn  = (val != 0);
                regReadable = true;
                LOG_INFO(L"BCD registry: TestSigningLevel=%lu (ON=%s)",
                         val, regSaysOn ? L"true" : L"false");
            } else {
                LOG_WARN(L"BCD registry: RegQueryValueExW TestSigningLevel failed (%ld)", rc);
            }
        } else {
            LOG_WARN(L"BCD registry: RegOpenKeyExW failed (%ld)", rc);
        }
    }

    // ── Source 2: bcdedit ─────────────────────────────────────────────────
    bool bcdeditSaysOn = false;
    bool bcdeditReadable = false;
    {
        wchar_t sysDir[MAX_PATH + 1] = {};
        if (!GetSystemDirectoryW(sysDir, MAX_PATH)) {
            LOG_WARN(L"GetSystemDirectoryW failed (0x%08X); skipping bcdedit check.",
                     GetLastError());
        } else {
            std::wstring cmdLine;
            cmdLine.reserve(MAX_PATH + 32);
            cmdLine  = L"\"";
            cmdLine += sysDir;
            cmdLine += L"\\bcdedit.exe\" /enum {current} /v";

            std::string bcdeditOutput;
            DWORD       bcdeditExit = 1;
            DWORD err = SpawnAndCapture(cmdLine, bcdeditOutput, bcdeditExit, 15'000);
            if (err != ERROR_SUCCESS) {
                LOG_WARN(L"SpawnAndCapture(bcdedit) returned 0x%08X; "
                         L"falling back to registry only.", err);
            } else if (bcdeditExit != 0) {
                LOG_WARN(L"bcdedit /enum exited with %lu; falling back to registry only.",
                         bcdeditExit);
            } else {
                // Find the "testsigning" field and inspect its value on the
                // SAME LINE.  The previous implementation searched the entire
                // output for "yes" anywhere, which falsely matched unrelated
                // fields ("bootmenupolicy ... Yes", localized output, etc.)
                // and would mis-report testsigning as ON.
                std::string lower = bcdeditOutput;
                for (auto& c : lower)
                    c = static_cast<char>(tolower(static_cast<unsigned char>(c)));

                bcdeditReadable = true;
                bcdeditSaysOn   = false;

                std::size_t pos = lower.find("testsigning");
                if (pos != std::string::npos) {
                    // Examine from "testsigning" to the next line terminator.
                    std::size_t eol = lower.find_first_of("\r\n", pos);
                    if (eol == std::string::npos)
                        eol = lower.size();
                    std::string_view line(lower.data() + pos, eol - pos);
                    bcdeditSaysOn = (line.find("yes") != std::string_view::npos);
                }
                LOG_INFO(L"bcdedit: testsigning=%ls",
                         bcdeditSaysOn ? L"Yes" : L"No");
            }
        }
    }

    // ── Consensus ─────────────────────────────────────────────────────────
    if (regReadable && bcdeditReadable) {
        outIsOn = (regSaysOn && bcdeditSaysOn);
        if (regSaysOn != bcdeditSaysOn) {
            LOG_WARN(L"TestSigning state disagrees: registry=%ls, bcdedit=%ls. "
                     L"Treating as OFF (conservative — reboot may resolve).",
                     regSaysOn ? L"ON" : L"OFF",
                     bcdeditSaysOn ? L"ON" : L"OFF");
        }
    } else if (regReadable) {
        outIsOn = regSaysOn;
        LOG_WARN(L"Only registry source available; using regSaysOn=%ls.",
                 regSaysOn ? L"ON" : L"OFF");
    } else if (bcdeditReadable) {
        outIsOn = bcdeditSaysOn;
        LOG_WARN(L"Only bcdedit source available; using bcdeditSaysOn=%ls.",
                 bcdeditSaysOn ? L"ON" : L"OFF");
    } else {
        LOG_ERROR(L"Neither BCD registry nor bcdedit was readable. Cannot determine state.");
        return ERROR_FUNCTION_FAILED;
    }

    return ERROR_SUCCESS;
}
#pragma warning(pop)

// ────────────────────────────────────────────────────────────────────────────
//  EnableTestSigning
//  Runs: <System32>\bcdedit.exe /set {current} testsigning on
// ────────────────────────────────────────────────────────────────────────────
DWORD EnableTestSigning()
{
    wchar_t sysDir[MAX_PATH + 1] = {};
    if (!GetSystemDirectoryW(sysDir, MAX_PATH)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"GetSystemDirectoryW failed (0x%08X)", err);
        return err;
    }

    std::wstring cmdLine;
    cmdLine  = L"\"";
    cmdLine += sysDir;
    cmdLine += L"\\bcdedit.exe\" /set {current} testsigning on";

    LOG_INFO(L"Enabling testsigning: %ls", cmdLine.c_str());

    std::string output;
    DWORD       bcdeditExit = 1;
    DWORD err = SpawnAndCapture(cmdLine, output, bcdeditExit, 15'000);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"EnableTestSigning: SpawnAndCapture failed (0x%08X).", err);
        return err;
    }

    // The bcdedit exit code is the authoritative signal.  The "successfully"
    // substring check is locale-dependent (non-English Windows produces a
    // translated message) and previously caused the installer to proceed
    // with reboot pivot even when bcdedit had returned a non-zero status.
    if (bcdeditExit != 0) {
        LOG_ERROR(L"bcdedit /set testsigning on exited with %lu. "
                  L"Output (truncated): %.256hs",
                  bcdeditExit, output.c_str());
        return ERROR_FUNCTION_FAILED;
    }

    if (output.find("successfully") != std::string::npos) {
        LOG_INFO(L"bcdedit /set testsigning on succeeded.");
    } else {
        // Non-English Windows: exit code 0 is sufficient, message will differ.
        LOG_INFO(L"bcdedit /set testsigning on returned exit 0 (locale-translated message).");
    }

    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  RegisterStage2ScheduledTask
//  Creates a one-shot-on-boot SYSTEM task:
//    "\ShadowStrike\PhantomSensorDriverInstall" -> "<exePath>" --stage2
// ────────────────────────────────────────────────────────────────────────────
DWORD RegisterStage2ScheduledTask(const std::wstring& exePath)
{
    if (exePath.empty() || exePath.find(L'"') != std::wstring::npos) {
        LOG_ERROR(L"RegisterStage2ScheduledTask rejected an empty or quoted executable path.");
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring schtasksPath;
    DWORD err = BuildSystemToolPath(L"schtasks.exe", schtasksPath);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    // schtasks requires the inner task command quotes to be escaped for the
    // command-line parser. The executable path originates from GetModuleFileNameW
    // and Windows paths cannot contain double quotes.
    std::wstring cmdLine = L"\"";
    cmdLine += schtasksPath;
    cmdLine += L"\" /Create /TN \"";
    cmdLine += kStage2TaskName;
    cmdLine += L"\" /SC ONSTART /RU SYSTEM /RL HIGHEST /TR \"\\\"";
    cmdLine += exePath;
    cmdLine += L"\\\" --stage2\" /F";

    std::string output;
    DWORD exitCode = 1;
    err = SpawnAndCapture(cmdLine, output, exitCode, 30'000);
    if (err != ERROR_SUCCESS) {
        LOG_ERROR(L"schtasks /Create spawn failed (0x%08X).", err);
        return err;
    }
    if (exitCode != 0) {
        LOG_ERROR(L"schtasks /Create exited with %lu. Output (truncated): %.256hs",
                  exitCode, output.c_str());
        return ERROR_FUNCTION_FAILED;
    }

    LOG_INFO(L"Stage 2 scheduled task registered: %ls", kStage2TaskName);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  DeleteStage2ScheduledTask
// ────────────────────────────────────────────────────────────────────────────
DWORD DeleteStage2ScheduledTask()
{
    std::wstring schtasksPath;
    DWORD err = BuildSystemToolPath(L"schtasks.exe", schtasksPath);
    if (err != ERROR_SUCCESS) {
        return err;
    }

    std::wstring cmdLine = L"\"";
    cmdLine += schtasksPath;
    cmdLine += L"\" /Delete /TN \"";
    cmdLine += kStage2TaskName;
    cmdLine += L"\" /F";

    std::string output;
    DWORD exitCode = 1;
    err = SpawnAndCapture(cmdLine, output, exitCode, 30'000);
    if (err != ERROR_SUCCESS) {
        LOG_WARN(L"schtasks /Delete spawn failed (0x%08X).", err);
        return err;
    }
    if (exitCode != 0) {
        LOG_WARN(L"schtasks /Delete exited with %lu. Output (truncated): %.256hs",
                 exitCode, output.c_str());
        return ERROR_FUNCTION_FAILED;
    }

    LOG_INFO(L"Stage 2 scheduled task deleted: %ls", kStage2TaskName);
    return ERROR_SUCCESS;
}

// ────────────────────────────────────────────────────────────────────────────
//  ScheduleReboot
//  Uses InitiateSystemShutdownExW with a 60-second delay and a user-visible
//  reason message.  Acquires SE_SHUTDOWN_NAME privilege first.
// ────────────────────────────────────────────────────────────────────────────
DWORD ScheduleReboot()
{
    // Acquire shutdown privilege.
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok))
    {
        DWORD err = GetLastError();
        LOG_ERROR(L"OpenProcessToken failed (0x%08X)", err);
        return err;
    }
    HandleGuard tok(hTok);

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, SE_SHUTDOWN_NAME,
                               &tp.Privileges[0].Luid))
    {
        DWORD err = GetLastError();
        LOG_ERROR(L"LookupPrivilegeValueW(SE_SHUTDOWN_NAME) failed (0x%08X)", err);
        return err;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        DWORD err = GetLastError();
        LOG_ERROR(L"AdjustTokenPrivileges(SE_SHUTDOWN_NAME) failed (0x%08X)", err);
        return err;
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        LOG_ERROR(L"SE_SHUTDOWN_NAME privilege not assigned to this token.");
        return ERROR_PRIVILEGE_NOT_HELD;
    }

    const wchar_t* kMessage =
        L"ShadowStrike PhantomHome: Your computer will restart in 60 seconds "
        L"to complete installation of the PhantomSensor protection driver. "
        L"Please save your work.";

    // dwShutdownCode = SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
    //                 SHTDN_REASON_MINOR_INSTALLATION |
    //                 SHTDN_REASON_FLAG_PLANNED
    constexpr DWORD kReason = 0x00040003 | 0x80000000;

    // C28159 ("rearchitect to avoid reboot") is a design-level /analyze
    // advisory; this installer's contract is precisely to schedule a reboot
    // after enabling testsigning, so the suggestion does not apply here.
#pragma warning(push)
#pragma warning(disable: 28159)
    if (!InitiateSystemShutdownExW(
            nullptr,    // local machine
            const_cast<LPWSTR>(kMessage),
            60,         // 60-second countdown
            FALSE,      // bForceAppsClosed (graceful)
            TRUE,       // bRebootAfterShutdown
            kReason))
    {
        DWORD err = GetLastError();
        LOG_ERROR(L"InitiateSystemShutdownExW failed (0x%08X)", err);
        return err;
    }
#pragma warning(pop)

    LOG_INFO(L"System restart scheduled in 60 seconds.");
    return ERROR_SUCCESS;
}

} // namespace ShadowStrike::Installer
