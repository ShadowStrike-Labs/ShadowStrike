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
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
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

// ---------------------------------------------------------------------------
// Crash-handler watchdog. The unhandled-exception filter below writes a crash
// minidump in-process. On a corrupt heap MiniDumpWriteDump can itself hang;
// and when THIS process is the connected kernel scanner, a hung crash handler
// means the process never exits, its FilterConnectCommunicationPort handle
// never closes, and the minifilter keeps routing synchronous file-create scans
// to a scanner that will never reply — wedging ALL system file I/O into an
// unresettable whole-machine freeze (observed in the field; the 0-byte crash
// dump is the tell-tale — the dump write itself stalled).
//
// The watchdog is a thread created at startup that idles on an event. The SEH
// filter signals it before touching the heap/dump; if the handler has not
// finished within a short bound, the watchdog force-terminates the process.
// TerminateProcess is serviced entirely by the kernel and cannot be blocked by
// a hung user thread or a corrupt heap, so the filter port ALWAYS closes
// promptly and the kernel fails open. Net effect: a scanner crash degrades to
// "service offline," never a frozen machine.
// ---------------------------------------------------------------------------
static HANDLE g_crashWatchdogEvent  = nullptr;   // manual-reset; set by the SEH filter
static HANDLE g_crashWatchdogThread = nullptr;
static constexpr DWORD kCrashWatchdogTimeoutMs = 4000;

static DWORD WINAPI ShadowStrikeCrashWatchdogProc(LPVOID) noexcept {
    if (g_crashWatchdogEvent != nullptr) {
        (void)::WaitForSingleObject(g_crashWatchdogEvent, INFINITE);
    }
    // A crash is in progress. Allow a bounded window for the in-process dump,
    // then force teardown regardless of the main thread's state. If the dump
    // finished quickly the process has already exited and this never runs.
    ::Sleep(kCrashWatchdogTimeoutMs);
    ::ShadowStrikeAppendBootTrace(L"crash-watchdog-force-terminate");
    ::TerminateProcess(::GetCurrentProcess(), 0xDEAD0001);
    return 0;
}

// ---------------------------------------------------------------------------
// Stack-overflow-safe crash dump capture.
//
// A STATUS_STACK_OVERFLOW (0xC00000FD) leaves the faulting thread with no
// usable stack, so calling MiniDumpWriteDump directly from the exception
// filter — which runs on that same exhausted stack — silently fails and yields
// a 0-byte dump (exactly what we saw in the field). Two measures fix this:
//   1. SetThreadStackGuarantee reserves a stack region so the filter itself can
//      still run after the overflow (applied to the main thread here and to
//      every scan worker at its entry point).
//   2. The MiniDumpWriteDump call is performed by a dedicated dumper thread
//      that owns a fresh, healthy stack. The filter only publishes the
//      EXCEPTION_POINTERS, signals the dumper, and waits (bounded) for it.
//      MiniDumpWriteDump captures every thread, so the faulting thread's full
//      overflowed call stack is still recorded for post-mortem analysis.
// ---------------------------------------------------------------------------
static HANDLE g_crashDumpRequest  = nullptr;   // auto-reset; set by the SEH filter
static HANDLE g_crashDumpDone     = nullptr;   // auto-reset; set by the dumper
static HANDLE g_crashDumperThread = nullptr;
static EXCEPTION_POINTERS* volatile g_crashEp = nullptr;
static volatile DWORD g_crashThreadId = 0;

// Write a crash minidump. Safe to call from either the dumper thread (normal
// case) or inline (fallback). Uses only stack buffers and direct Win32/DbgHelp
// calls, wrapped in SEH so a failure here can never block process teardown.
static void ShadowStrikeWriteCrashMinidump(EXCEPTION_POINTERS* ep, DWORD threadId) noexcept {
    __try {
        wchar_t dumpPath[MAX_PATH] = {};
        SYSTEMTIME st;
        ::GetSystemTime(&st);
        (void)::_snwprintf_s(
            dumpPath, _countof(dumpPath), _TRUNCATE,
            L"C:\\ProgramData\\ShadowStrike\\Logs\\PhantomHome.Service.crash_"
            L"%04u%02u%02u_%02u%02u%02u.dmp",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

        HANDLE hDump = ::CreateFileW(dumpPath, GENERIC_WRITE, 0, nullptr,
                                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hDump == INVALID_HANDLE_VALUE) {
            ::ShadowStrikeAppendBootTrace(L"crash-minidump-create-FAILED");
            return;
        }

        MINIDUMP_EXCEPTION_INFORMATION mei{};
        mei.ThreadId = threadId;
        mei.ExceptionPointers = ep;
        mei.ClientPointers = FALSE;

        // Dump contents are a deliberate trade-off.
        //
        // MiniDumpNormal alone gives thread stacks and the module list with no
        // heap walk, which is why it was chosen: it survives a corrupt heap. But
        // it was not enough to diagnose the startup crash in the IPC receive
        // path - the unwound frames were garbage and none of the pointers held in
        // registers could be examined, so the cause stayed unknown.
        //
        // MiniDumpWithIndirectlyReferencedMemory closes that gap without giving up
        // the safety property: it captures the pages that stack values and
        // registers point AT, resolved by address, rather than enumerating heap
        // structures the way MiniDumpWithFullMemory does. A corrupted heap header
        // therefore cannot send the writer into a bad traversal. MiniDumpWithDataSegs
        // adds our globals and statics, which is cheap and often decisive for
        // "what state was this subsystem in".
        //
        // Cost is a larger file (megabytes rather than hundreds of kilobytes) on a
        // path that only runs when the process is already dying, so it buys real
        // diagnostic ability for no steady-state cost.
        const MINIDUMP_TYPE dumpType = static_cast<MINIDUMP_TYPE>(
            MiniDumpNormal |
            MiniDumpWithUnloadedModules |
            MiniDumpWithThreadInfo |
            MiniDumpWithIndirectlyReferencedMemory |
            MiniDumpWithDataSegs);

        const BOOL dumpOk = ::MiniDumpWriteDump(
            ::GetCurrentProcess(), ::GetCurrentProcessId(),
            hDump, dumpType, (ep != nullptr ? &mei : nullptr), nullptr, nullptr);
        const DWORD dumpErr = dumpOk ? 0u : ::GetLastError();
        ::FlushFileBuffers(hDump);
        ::CloseHandle(hDump);

        wchar_t doneTag[360] = {};
        if (dumpOk) {
            (void)::_snwprintf_s(doneTag, _countof(doneTag), _TRUNCATE,
                                 L"crash-minidump-written %ls", dumpPath);
        } else {
            (void)::_snwprintf_s(doneTag, _countof(doneTag), _TRUNCATE,
                                 L"crash-minidump-FAILED err=0x%08X (%ls)", dumpErr, dumpPath);
        }
        ::ShadowStrikeAppendBootTrace(doneTag);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ::ShadowStrikeAppendBootTrace(L"crash-minidump-EXCEPTION");
    }
}

static DWORD WINAPI ShadowStrikeCrashDumperProc(LPVOID) noexcept {
    if (g_crashDumpRequest == nullptr) {
        return 0;
    }
    for (;;) {
        if (::WaitForSingleObject(g_crashDumpRequest, INFINITE) != WAIT_OBJECT_0) {
            return 0;
        }
        ShadowStrikeWriteCrashMinidump(g_crashEp, g_crashThreadId);
        if (g_crashDumpDone != nullptr) {
            (void)::SetEvent(g_crashDumpDone);
        }
    }
}

// Reserve a stack region so the unhandled-exception filter can still execute
// after a STATUS_STACK_OVERFLOW. Called on the main thread and on every scan
// worker; 256 KiB is ample for the filter's signal-and-wait path.
void ShadowStrikeEnableStackOverflowDumps() noexcept {
    ULONG guaranteeBytes = 256u * 1024u;
    (void)::SetThreadStackGuarantee(&guaranteeBytes);
}

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

    // Arm the watchdog FIRST — before any heap touch or dump — so a hung
    // MiniDumpWriteDump can never keep this process (and thus its kernel filter
    // port) alive and freeze system-wide file I/O behind a dead scanner.
    if (g_crashWatchdogEvent != nullptr) {
        (void)::SetEvent(g_crashWatchdogEvent);
    }

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

    // Hand the dump off to the dedicated dumper thread, which owns a fresh,
    // healthy stack. On a STATUS_STACK_OVERFLOW the faulting thread has no stack
    // left to run MiniDumpWriteDump itself — this is why earlier dumps were
    // 0 bytes. The filter only publishes the exception context, signals the
    // dumper, and waits a bounded interval (shorter than the watchdog's
    // force-terminate window) for the dump to be written. MiniDumpWriteDump
    // captures every thread, so the faulting thread's overflowed stack is
    // recorded regardless of which thread writes the dump.
    bool dumpedViaThread = false;
    if (g_crashDumpRequest != nullptr && g_crashDumpDone != nullptr &&
        g_crashDumperThread != nullptr) {
        g_crashEp = ep;
        g_crashThreadId = ::GetCurrentThreadId();
        if (::SetEvent(g_crashDumpRequest)) {
            (void)::WaitForSingleObject(g_crashDumpDone, 3000);
            dumpedViaThread = true;
        }
    }
    if (!dumpedViaThread) {
        // Fallback for faults where the current stack is still usable (i.e. not
        // a stack overflow) or if the dumper thread could not be created.
        ShadowStrikeWriteCrashMinidump(ep, ::GetCurrentThreadId());
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
    // SEM_NOGPFAULTERRORBOX MUST remain set. It tells Windows this process
    // self-handles faults, which suppresses Windows Error Reporting for them.
    //
    // 1.0.30.0 cleared it (to let WER capture the ~50 s __fastfail stack-overflow
    // crash out-of-process). That backfired into a STARTUP DEADLOCK: without this
    // flag, ANY fault routes to WerFault.exe, which must open a handle to this
    // process to write its dump — but our own kernel self-protection
    // (ObRegisterCallbacks handle-stripping on the protected service process)
    // denies that handle, so WerFault blocks indefinitely and the faulting
    // service thread waits on it forever. Net effect observed in the field:
    // service launches, hangs before its first boot-trace line, stays in
    // SERVICE_START_PENDING, and wedges the SCM (Get-Service itself hangs).
    // Keeping the flag restores the known-good 1.0.29 startup. The __fastfail
    // crash is being addressed at its source (scan-path memory safety) instead.
    ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    // Pre-create the crash watchdog (event + idle thread) BEFORE installing the
    // unhandled-exception filter, so the filter can bound its own runtime
    // without allocating anything in the crash path (see watchdog notes above).
    g_crashWatchdogEvent = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_crashWatchdogEvent != nullptr) {
        g_crashWatchdogThread = ::CreateThread(nullptr, 0,
                                               ShadowStrikeCrashWatchdogProc,
                                               nullptr, 0, nullptr);
        if (g_crashWatchdogThread == nullptr) {
            ::ShadowStrikeAppendBootTrace(L"crash-watchdog-thread-create-FAILED");
        }
    } else {
        ::ShadowStrikeAppendBootTrace(L"crash-watchdog-event-create-FAILED");
    }

    // Pre-create the stack-overflow-safe crash dumper (events + idle thread)
    // BEFORE installing the filter, so even an early fault captures a real
    // minidump on a healthy stack instead of a 0-byte file.
    g_crashDumpRequest = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_crashDumpDone    = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (g_crashDumpRequest != nullptr && g_crashDumpDone != nullptr) {
        g_crashDumperThread = ::CreateThread(nullptr, 0,
                                             ShadowStrikeCrashDumperProc,
                                             nullptr, 0, nullptr);
        if (g_crashDumperThread == nullptr) {
            ::ShadowStrikeAppendBootTrace(L"crash-dumper-thread-create-FAILED");
        }
    } else {
        ::ShadowStrikeAppendBootTrace(L"crash-dumper-event-create-FAILED");
    }

    // Reserve a stack region for THIS (main) thread so the filter can run after
    // a stack overflow here too; scan workers set their own guarantee at entry.
    ShadowStrikeEnableStackOverflowDumps();

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
