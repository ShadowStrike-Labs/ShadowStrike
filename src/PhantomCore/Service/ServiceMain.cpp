/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file ServiceMain.cpp
 * @brief Entry point for ShadowStrikePhantomService.exe.
 *
 * Responsibilities:
 *   - Initialise the process-wide Logger before any subsystem runs so that
 *     wiring static initialisers can emit diagnostics to %ProgramData%\ShadowStrike\Logs.
 *   - Dispatch CLI verbs --install / --uninstall (both require elevation).
 *   - Hand control to AntivirusService::Run() which registers with the SCM,
 *     brings up HomeProductOrchestrator + ServiceCommunicator +
 *     HomeIpcDispatcher and loops on the stop event.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <format>
#include <string>

#include "AntivirusService.hpp"
#include "ServiceInstaller.hpp"
#include "PhantomCore/Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogSource = L"ShadowStrike Phantom Service";

// ---------------------------------------------------------------------------
// Boot trace — written via direct CreateFileW (CREATE_ALWAYS with FILE_FLAG_
// WRITE_THROUGH) at the very top of wmain(), BEFORE the async Logger is
// initialised.  This lets post-mortem triage tell apart:
//   (a) the SCM never spawned the service exe        → file does not exist;
//   (b) the .exe was spawned but crashed before Run() → file exists with the
//       "entry" line only;
//   (c) Defender quarantined the .exe between MSI commit and SCM start → file
//       does not exist AND DriverResume.<pid>.log shows no service start
//       attempt either.
// The file path is %ProgramData%\ShadowStrike\Logs\PhantomHome.Service.boot.log
// (idempotent, recreated each launch) so the previous boot's trace is
// preserved in the next file rotation only via journal copy; the file itself
// is overwritten on every launch to avoid runaway growth.
// ---------------------------------------------------------------------------
void WriteBootTrace(const wchar_t* event, int argc, wchar_t** argv) noexcept {
    wchar_t programData[MAX_PATH + 1] = {};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike\\Logs",
                                    programData, MAX_PATH) == 0) {
        return;
    }

    wchar_t parent[MAX_PATH + 1] = {};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike",
                                    parent, MAX_PATH) != 0) {
        (void)::CreateDirectoryW(parent, nullptr);
    }
    (void)::CreateDirectoryW(programData, nullptr);

    wchar_t path[MAX_PATH + 1] = {};
    if (::_snwprintf_s(path, _countof(path), _TRUNCATE,
                       L"%ls\\PhantomHome.Service.boot.log", programData) < 0)
    {
        return;
    }

    const HANDLE h = ::CreateFileW(
        path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    SYSTEMTIME st{};
    ::GetSystemTime(&st);

    wchar_t cmdLineSummary[512] = {};
    int written = ::_snwprintf_s(
        cmdLineSummary, _countof(cmdLineSummary), _TRUNCATE,
        L"argc=%d arg0=%ls arg1=%ls",
        argc,
        (argc >= 1 && argv != nullptr && argv[0] != nullptr) ? argv[0] : L"<none>",
        (argc >= 2 && argv != nullptr && argv[1] != nullptr) ? argv[1] : L"<none>");
    if (written < 0) {
        cmdLineSummary[0] = L'\0';
    }

    wchar_t line[1024] = {};
    DWORD sessionId = 0;
    (void)::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId);
    written = ::_snwprintf_s(
        line, _countof(line), _TRUNCATE,
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ [BOOT] pid=%lu sid=%lu %ls %ls\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
        ::GetCurrentProcessId(),
        sessionId,
        event,
        cmdLineSummary);
    if (written < 0) {
        ::CloseHandle(h);
        return;
    }

    // Append, then immediately fsync so a crash in the next millisecond
    // cannot lose the trace.
    //
    // BUG FIX: previously we passed cbMultiByte = cbUtf8 - 1, which is one
    // byte short of what the first call (size query with cchWideChar = -1,
    // i.e. *including* the terminator) reported.  That caused
    // WideCharToMultiByte to fail with ERROR_INSUFFICIENT_BUFFER and return 0,
    // so WriteFile never ran -> 0-byte PhantomHome.Service.boot.log on disk.
    // We now pass the full reported size and write cbUtf8 - 1 bytes (excluding
    // the trailing NUL) into the file.
    int cbUtf8 = ::WideCharToMultiByte(CP_UTF8, 0, line, -1, nullptr, 0, nullptr, nullptr);
    if (cbUtf8 > 1) {
        char buf[2048] = {};
        const int cap = static_cast<int>(sizeof(buf));
        const int outBytes = (cbUtf8 < cap) ? cbUtf8 : cap;
        const int converted = ::WideCharToMultiByte(
            CP_UTF8, 0, line, -1, buf, outBytes, nullptr, nullptr);
        if (converted > 1) {
            // converted includes the trailing NUL; skip it when writing.
            const DWORD bytesToWrite = static_cast<DWORD>(converted - 1);
            DWORD writtenBytes = 0;
            (void)::WriteFile(h, buf, bytesToWrite, &writtenBytes, nullptr);
            (void)::FlushFileBuffers(h);
        }
    }
    ::CloseHandle(h);
}

// (BootTrace helper is defined out-of-line in BootTrace.cpp; see BootTrace.hpp.)

// ---------------------------------------------------------------------------
// Unhandled SEH filter — writes a synchronous crash marker to the log so a
// silent access-violation or stack-overflow in a module's Initialize path is
// visible in the next run's triage instead of a truncated log.
// ---------------------------------------------------------------------------
LONG WINAPI ShadowStrikeUnhandledFilter(EXCEPTION_POINTERS* ep) noexcept {
    try {
        DWORD code = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionCode : 0;
        void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
        ShadowStrike::Utils::Logger::Instance().Flush();
        ::ShadowStrike::Utils::Logger::Error(
            "FATAL unhandled SEH exception: code=0x{:08X} address={:p}",
            static_cast<unsigned>(code), addr);
        ShadowStrike::Utils::Logger::Instance().Flush();
    } catch (...) {
        // Best effort only; process is about to die.
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

std::wstring ResolveLogDirectory() noexcept {
    wchar_t expanded[MAX_PATH]{};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike\\Logs",
                                    expanded, MAX_PATH) == 0) {
        return L"logs";
    }

    wchar_t parent[MAX_PATH]{};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike",
                                    parent, MAX_PATH) != 0) {
        (void)::CreateDirectoryW(parent, nullptr);
    }

    if (!::CreateDirectoryW(expanded, nullptr)) {
        const DWORD err = ::GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            return L"logs";
        }
    }
    return std::wstring{expanded};
}

void InitialiseLogger() noexcept {
    try {
        using ::ShadowStrike::Utils::Logger;
        using ::ShadowStrike::Utils::LoggerConfig;
        using ::ShadowStrike::Utils::LogLevel;

        LoggerConfig cfg{};
        cfg.async               = true;
        cfg.toConsole           = false;
        cfg.toFile              = true;
        cfg.toEventLog          = true;
        cfg.logDirectory        = ResolveLogDirectory();
        cfg.baseFileName        = L"PhantomHome.Service";
        cfg.maxFileSizeBytes    = 20ULL * 1024ULL * 1024ULL;
        cfg.maxFileCount        = 10;
        cfg.minimalLevel        = LogLevel::Info;
        cfg.flushLevel          = LogLevel::Error;
        cfg.eventLogSource      = kLogSource;
        cfg.useUtcTime          = true;
        cfg.includeSrcLocation  = true;
        cfg.includeProcThreadId = true;

        Logger::Instance().Initialize(cfg);
    } catch (...) {
        // Best-effort: Logger auto-inits on first call if we fail here.
    }
}

}  // namespace

extern "C" int wmain(int argc, wchar_t* argv[]) {
    // Boot trace must be the FIRST observable side effect so we can tell, on
    // VM triage, whether SCM (or Defender) even managed to spawn this exe.
    // Written via a direct, synchronous CreateFileW so the trace survives an
    // immediate crash in InitialiseLogger / static initialisers.
    WriteBootTrace(L"wmain-entry", argc, argv);

    ::SetUnhandledExceptionFilter(ShadowStrikeUnhandledFilter);
    InitialiseLogger();
    WriteBootTrace(L"logger-initialised", argc, argv);

    if (argc >= 2 && argv != nullptr && argv[1] != nullptr) {
        const std::wstring arg{argv[1]};
        if (arg == L"--install" || arg == L"-install" || arg == L"/install") {
            if (!::ShadowStrike::Service::ServiceInstaller::Install()) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --install: ServiceInstaller::Install returned false");
                return 2;
            }
            ShadowStrike::Utils::Logger::Info("wmain --install: service registered");
            return 0;
        }
        if (arg == L"--uninstall" || arg == L"-uninstall" || arg == L"/uninstall") {
            if (!::ShadowStrike::Service::ServiceInstaller::Uninstall()) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --uninstall: ServiceInstaller::Uninstall returned false");
                return 3;
            }
            ShadowStrike::Utils::Logger::Info("wmain --uninstall: service removed");
            return 0;
        }
    }

    if (!::ShadowStrike::Service::AntivirusService::Instance().Run()) {
        ShadowStrike::Utils::Logger::Error("wmain: AntivirusService::Run returned false");
        WriteBootTrace(L"AntivirusService-Run-returned-false", argc, argv);
        return 1;
    }
    WriteBootTrace(L"AntivirusService-Run-returned-true", argc, argv);
    return 0;
}
