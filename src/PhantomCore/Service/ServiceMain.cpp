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
    ::SetUnhandledExceptionFilter(ShadowStrikeUnhandledFilter);
    InitialiseLogger();

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
        return 1;
    }
    return 0;
}
