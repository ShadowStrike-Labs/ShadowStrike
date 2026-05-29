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
 * Boot-trace coverage: pre-wmain (.CRT$XCT static initializer in BootTrace.cpp),
 * wmain-entry, every SetServiceStatus transition (via AntivirusService.cpp),
 * unhandled SEH filter, std::terminate handler, _set_invalid_parameter_handler,
 * _set_purecall_handler, atexit, and POSIX signal handlers. The trace is
 * guaranteed to survive any subsequent crash because every write is
 * FILE_FLAG_WRITE_THROUGH and the file is closed between writes.
 */

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>
#include <crtdbg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <cstdint>
#include <exception>
#include <format>
#include <string>

#include "AntivirusService.hpp"
#include "BootTrace.hpp"
#include "ServiceInstaller.hpp"
#include "../Utils/Logger.hpp"

namespace {

constexpr const wchar_t* kLogSource = L"ShadowStrike Phantom Service";

// ---------------------------------------------------------------------------
// Process-wide failure-mode handlers. Each one emits a synchronous boot trace
// to PhantomHome.Service.boot.log before relinquishing control, so even a
// fatal failure inside a subsystem's static initializer or deep in
// AntivirusServiceImpl::Initialize leaves a deterministic last-line marker
// on disk for post-mortem triage.
// ---------------------------------------------------------------------------

LONG WINAPI ShadowStrikeUnhandledFilter(EXCEPTION_POINTERS* ep) noexcept {
    DWORD code = 0;
    void* addr = nullptr;
    if (ep != nullptr && ep->ExceptionRecord != nullptr) {
        code = ep->ExceptionRecord->ExceptionCode;
        addr = ep->ExceptionRecord->ExceptionAddress;
    }

    wchar_t tag[256] = {};
    (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                         L"unhandled-seh code=0x%08X addr=%p", code, addr);
    ::ShadowStrikeAppendBootTrace(tag);

    // Best-effort second-channel log; harmless if Logger is dead.
    __try {
        ShadowStrike::Utils::Logger::Instance().Flush();
        ShadowStrike::Utils::Logger::Error(
            "FATAL unhandled SEH: code=0x{:08X} addr={:p}",
            static_cast<unsigned>(code), addr);
        ShadowStrike::Utils::Logger::Instance().Flush();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Process is dying; nothing useful to do.
    }

    // Returning EXCEPTION_EXECUTE_HANDLER terminates the process normally.
    // We deliberately do NOT return EXCEPTION_CONTINUE_SEARCH, which would
    // let WER pop a dialog under Session 0 and pin the service forever.
    return EXCEPTION_EXECUTE_HANDLER;
}

void __cdecl ShadowStrikeTerminateHandler() noexcept {
    ::ShadowStrikeAppendBootTrace(L"std-terminate");
    ::abort();
}

void __cdecl ShadowStrikeInvalidParameter(
    const wchar_t* expression, const wchar_t* function,
    const wchar_t* file, unsigned int line, uintptr_t /*reserved*/) noexcept
{
    wchar_t tag[512] = {};
    (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                         L"crt-invalid-parameter expr=%ls fn=%ls file=%ls line=%u",
                         expression ? expression : L"<null>",
                         function   ? function   : L"<null>",
                         file       ? file       : L"<null>",
                         line);
    ::ShadowStrikeAppendBootTrace(tag);
    ::abort();
}

void __cdecl ShadowStrikePurecall() noexcept {
    ::ShadowStrikeAppendBootTrace(L"crt-pure-virtual-call");
    ::abort();
}

void __cdecl ShadowStrikeAtExit() noexcept {
    ::ShadowStrikeAppendBootTrace(L"atexit");
}

void __cdecl ShadowStrikeSignalHandler(int sig) noexcept {
    wchar_t tag[64] = {};
    (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE, L"signal sig=%d", sig);
    ::ShadowStrikeAppendBootTrace(tag);
    // Re-raise default to allow WER dump capture if configured.
    ::signal(sig, SIG_DFL);
    ::raise(sig);
}

void InstallProcessWideHandlers() noexcept {
    // Suppress WER dialogs that would pin a Session 0 service forever.
    ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    ::SetUnhandledExceptionFilter(ShadowStrikeUnhandledFilter);
    std::set_terminate(ShadowStrikeTerminateHandler);
    _set_invalid_parameter_handler(ShadowStrikeInvalidParameter);
    _set_purecall_handler(ShadowStrikePurecall);
    (void)::atexit(ShadowStrikeAtExit);

    ::signal(SIGABRT, ShadowStrikeSignalHandler);
    ::signal(SIGFPE,  ShadowStrikeSignalHandler);
    ::signal(SIGILL,  ShadowStrikeSignalHandler);
    ::signal(SIGSEGV, ShadowStrikeSignalHandler);
    ::signal(SIGTERM, ShadowStrikeSignalHandler);
}

std::wstring ResolveLogDirectory() noexcept {
    // Logger may use env vars; that's tolerable because the boot trace is
    // independent and uses a hard-coded \\?\C:\ProgramData\... path.
    wchar_t expanded[MAX_PATH]{};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike\\Logs",
                                    expanded, MAX_PATH) == 0) {
        return L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs";
    }
    wchar_t parent[MAX_PATH]{};
    if (::ExpandEnvironmentStringsW(L"%ProgramData%\\ShadowStrike",
                                    parent, MAX_PATH) != 0) {
        (void)::CreateDirectoryW(parent, nullptr);
    }
    if (!::CreateDirectoryW(expanded, nullptr)) {
        const DWORD err = ::GetLastError();
        if (err != ERROR_ALREADY_EXISTS) {
            return L"\\\\?\\C:\\ProgramData\\ShadowStrike\\Logs";
        }
    }
    return std::wstring{expanded};
}

void InitialiseLogger() noexcept {
    ::ShadowStrikeAppendBootTrace(L"logger-Initialise-enter");
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
        ::ShadowStrikeAppendBootTrace(L"logger-Initialise-ok");
    } catch (...) {
        ::ShadowStrikeAppendBootTrace(L"logger-Initialise-EXCEPTION");
    }
}

}  // namespace

extern "C" int wmain(int argc, wchar_t* argv[]) {
    // The pre-wmain boot trace has already run from a .CRT$XCT initializer
    // in BootTrace.cpp; this is the wmain-body trace.
    {
        wchar_t tag[512] = {};
        (void)::_snwprintf_s(tag, _countof(tag), _TRUNCATE,
                             L"wmain-entry argc=%d arg0=%ls arg1=%ls",
                             argc,
                             (argc >= 1 && argv && argv[0]) ? argv[0] : L"<none>",
                             (argc >= 2 && argv && argv[1]) ? argv[1] : L"<none>");
        ::ShadowStrikeAppendBootTrace(tag);
    }

    InstallProcessWideHandlers();
    ::ShadowStrikeAppendBootTrace(L"handlers-installed");

    InitialiseLogger();

    if (argc >= 2 && argv != nullptr && argv[1] != nullptr) {
        const std::wstring arg{argv[1]};
        if (arg == L"--install" || arg == L"-install" || arg == L"/install") {
            ::ShadowStrikeAppendBootTrace(L"verb-install-enter");
            if (!::ShadowStrike::Service::ServiceInstaller::Install()) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --install: ServiceInstaller::Install returned false");
                ::ShadowStrikeAppendBootTrace(L"verb-install-FAIL");
                return 2;
            }
            ShadowStrike::Utils::Logger::Info("wmain --install: service registered");
            ::ShadowStrikeAppendBootTrace(L"verb-install-ok");
            return 0;
        }
        if (arg == L"--uninstall" || arg == L"-uninstall" || arg == L"/uninstall") {
            ::ShadowStrikeAppendBootTrace(L"verb-uninstall-enter");
            if (!::ShadowStrike::Service::ServiceInstaller::Uninstall()) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --uninstall: ServiceInstaller::Uninstall returned false");
                ::ShadowStrikeAppendBootTrace(L"verb-uninstall-FAIL");
                return 3;
            }
            ShadowStrike::Utils::Logger::Info("wmain --uninstall: service removed");
            ::ShadowStrikeAppendBootTrace(L"verb-uninstall-ok");
            return 0;
        }
    }

    ::ShadowStrikeAppendBootTrace(L"pre-AntivirusService-Run");
    const bool runOk = ::ShadowStrike::Service::AntivirusService::Instance().Run();
    ::ShadowStrikeAppendBootTrace(runOk ? L"post-AntivirusService-Run-ok"
                                        : L"post-AntivirusService-Run-FAIL");
    if (!runOk) {
        ShadowStrike::Utils::Logger::Error("wmain: AntivirusService::Run returned false");
        return 1;
    }
    return 0;
}
