/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * main.cpp — Phantom tray-process entry point.
 *
 * Sole responsibility: wWinMain → TrayApp::Instance().Run().
 * All logic lives in TrayApp.cpp; this file is intentionally minimal.
 */
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>

#include <string>

#include "TrayApp.hpp"

// <format> MUST precede Logger.hpp. This project builds at stdcpp20 while
// Logger.hpp names std::format_string, which MSVC only exposes once <format> has
// been included in that mode. TrayIpc.cpp carries the same ordering and the same
// note. The real fix is to move this project to stdcpp23 as PhantomCoreLib and
// PhantomTests already are, which is its own change.
#include <format>
#include <PhantomCore/Utils/Logger.hpp>

namespace {

// ---------------------------------------------------------------------------
// Tray logger initialisation
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS. The tray makes 96 logging calls and, until this was added,
// configured no logger at all. Logger::EnsureInitialized is what then ran, on
// the first write from anywhere, and its default is toFile = false with
// toConsole = true. The tray is a /SUBSYSTEM:WINDOWS binary with no console, so
// every one of those 96 diagnostics was formatted and thrown away.
//
// That is not a cosmetic gap. Two of the discarded lines are the only evidence
// this process produces when it cannot talk to the service:
//   TrayIpc.cpp  "IpcAuthToken::ReadForCurrentSession() returned empty; cannot
//                 authenticate"
//   TrayIpc.cpp  the CreateFileW failure on the service pipe, with the error code
// The 1.0.93 field run ended with the UI never completing a single IPC request
// and no client-side explanation anywhere, and this is why: the client that
// would have said so had nowhere to say it.
//
// MUST HAPPEN HERE, BEFORE Run(). Logger::Initialize is CAS-guarded on the same
// flag EnsureInitialized sets, so the FIRST writer wins and a later Initialize is
// silently ignored. Configuring the logger after any code has logged would
// therefore do nothing at all - the same trap that made the crypto test suite's
// skip depend on which test happened to log first.
//
// Path matches the UI's own resolution rather than %ProgramData%: the install
// directory is read-only to the interactive user, and the tray runs as that user.
void InitTrayLogger() noexcept
{
    using namespace ShadowStrike::Utils;

    std::wstring logDir;
    wchar_t localAppData[MAX_PATH]{};
    const DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (n > 0 && n < MAX_PATH) {
        logDir.assign(localAppData, n);
        logDir += L"\\ShadowStrike\\Logs";
    } else {
        wchar_t tempPath[MAX_PATH]{};
        const DWORD t = ::GetTempPathW(MAX_PATH, tempPath);
        if (t == 0 || t >= MAX_PATH) {
            // No writable location could be resolved. Leave the logger alone
            // rather than claiming a destination: EnsureInitialized's console
            // default is useless here but it is honest, and inventing a relative
            // path would put the file wherever this process happens to be
            // started from.
            return;
        }
        logDir.assign(tempPath, t);
        if (!logDir.empty() && logDir.back() != L'\\') logDir.push_back(L'\\');
        logDir += L"ShadowStrike\\Logs";
    }

    LoggerConfig cfg{};
    cfg.async               = true;
    cfg.toConsole           = false;  // no console exists in a GUI subsystem binary
    cfg.toFile              = true;
    cfg.toEventLog          = false;
    cfg.jsonLines           = false;
    cfg.logDirectory        = logDir;
    // Distinct base name so the tray's log cannot be confused with the UI's in
    // the same directory - they are separate processes with separate failures.
    cfg.baseFileName        = L"PhantomHomeTray";
    cfg.maxFileSizeBytes    = 4ULL * 1024ULL * 1024ULL;
    cfg.maxFileCount        = 3;
    cfg.minimalLevel        = LogLevel::Info;
    cfg.flushLevel          = LogLevel::Error;
    cfg.includeSrcLocation  = true;
    cfg.includeProcThreadId = true;

    Logger::Instance().Initialize(cfg);
}

}  // namespace

int APIENTRY wWinMain(
    HINSTANCE hInstance,
    HINSTANCE /*hPrev*/,
    LPWSTR    /*cmdLine*/,
    int       /*nShow*/)
{
    // First statement in the process, deliberately. See InitTrayLogger.
    InitTrayLogger();

    return ShadowStrike::PhantomHome::Tray::TrayApp::Instance().Run(hInstance);
}
