// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) ShadowStrike-Labs. All rights reserved.
//
// ShadowStrikePhantomUI.exe entry point.
//
// Responsibilities:
//   * Boot QGuiApplication + QQmlApplicationEngine.
//   * Resolve the current interactive session id (WTSGetActiveConsoleSessionId /
//     ProcessIdToSessionId fallback).
//   * Connect a PipeClient to \\.\pipe\ShadowStrike.Phantom.UI.<sid>.
//   * Expose a `protectionVm` context property to QML.
//   * Load qrc:/ShadowStrike/Phantom/qml/App.qml.

#include <QDir>
#include <QFile>
#include <QGuiApplication>
#include <QIcon>
#include <QList>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQmlError>
#include <QString>
#include <QStandardPaths>
#include <QTextStream>
#include <QUrl>

#include <memory>
#include <chrono>
#include <exception>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wtsapi32.h>
#include <strsafe.h>

#include "IPC/PipeClient.hpp"
#include "ViewModels/ProtectionViewModel.hpp"
#include "../PerfBudget/PerfBudget.hpp"

namespace {

std::uint32_t CurrentSessionId() noexcept {
    DWORD sid = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sid)) {
        return static_cast<std::uint32_t>(sid);
    }
    return static_cast<std::uint32_t>(::WTSGetActiveConsoleSessionId());
}

// ---------------------------------------------------------------------------
// QML error log written to %LOCALAPPDATA%\ShadowStrike\Phantom\ui_errors.log.
// Written before exit(2) so the tray MessageBox can point the user to it.
// ---------------------------------------------------------------------------
static QString s_logPath;

void WriteQmlErrors(const QList<QQmlError>& errors) noexcept {
    if (s_logPath.isEmpty() || errors.isEmpty()) return;

    QFile f(s_logPath);
    if (!f.open(QIODevice::Append | QIODevice::Text)) return;
    QTextStream ts(&f);
    for (const QQmlError& err : errors) {
        ts << "[QML] " << err.toString() << "\n";
    }
}

// Qt message handler — also writes critical/fatal messages to the log file
// so that loader-time plugin failures are captured.
void SsQtMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg) noexcept {
    if (type == QtDebugMsg) return;          // suppress debug noise in production

    if (!s_logPath.isEmpty()) {
        QFile f(s_logPath);
        if (f.open(QIODevice::Append | QIODevice::Text)) {
            QTextStream ts(&f);
            const char* level =
                (type == QtWarningMsg)  ? "[WARN ] " :
                (type == QtCriticalMsg) ? "[CRIT ] " :
                (type == QtFatalMsg)    ? "[FATAL] " : "[INFO ] ";
            ts << level << msg;
            if (ctx.file) ts << "  (" << ctx.file << ":" << ctx.line << ")";
            ts << "\n";
        }
    }

    // For fatal messages let Qt's default handler abort.
    if (type == QtFatalMsg) {
        std::abort();
    }
}

// ---------------------------------------------------------------------------
// Top-level unhandled-exception filter. When the UI dies on an access
// violation, stack overflow, pure virtual call, etc. this filter writes a
// compact crash header (exception code + faulting address + first frames)
// to ui_errors.log *before* the process disappears. Without this hook a
// crash leaves zero forensic trace — the pipe silently closes and the
// user sees a permanently "Loading…" dashboard on the next start.
// ---------------------------------------------------------------------------
LONG WINAPI SsTopLevelCrashFilter(EXCEPTION_POINTERS* info) noexcept {
    if (s_logPath.isEmpty() || info == nullptr || info->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    QFile f(s_logPath);
    if (!f.open(QIODevice::Append | QIODevice::Text)) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    QTextStream ts(&f);

    const EXCEPTION_RECORD* rec = info->ExceptionRecord;
    ts << "[CRASH] UI process faulted: code=0x"
       << QString::number(static_cast<quint32>(rec->ExceptionCode), 16).toUpper()
       << " flags=0x"
       << QString::number(static_cast<quint32>(rec->ExceptionFlags), 16).toUpper()
       << " addr=0x"
       << QString::number(reinterpret_cast<quintptr>(rec->ExceptionAddress), 16).toUpper();

    // Access-violation extra info: [0] = read/write/dep, [1] = va.
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
        const ULONG_PTR kind = rec->ExceptionInformation[0];
        const ULONG_PTR va   = rec->ExceptionInformation[1];
        const char* op = (kind == 0) ? "read" : (kind == 1) ? "write" : (kind == 8) ? "dep" : "?";
        ts << " av_op=" << op
           << " av_va=0x" << QString::number(static_cast<quint64>(va), 16).toUpper();
    }
    ts << "\n";

    // Dump a few return addresses from the context so we at least know
    // which module faulted even without symbols. CaptureStackBackTrace runs
    // from the exception thread context.
    void* frames[16]{};
    const USHORT n = ::CaptureStackBackTrace(0, 16, frames, nullptr);
    ts << "[CRASH] frames(" << n << "):";
    for (USHORT i = 0; i < n; ++i) {
        ts << " 0x"
           << QString::number(reinterpret_cast<quintptr>(frames[i]), 16).toUpper();
    }
    ts << "\n";
    ts.flush();
    f.flush();
    f.close();

    // Let Windows Error Reporting continue so the process terminates cleanly
    // (and any WER minidump machinery still fires).
    return EXCEPTION_CONTINUE_SEARCH;
}

// Vectored handler runs *before* the top-level filter, which matters when a
// debugger or WER takes over the unhandled-exception path. We install it as
// a belt-and-braces so the log line always lands regardless of who wins the
// exception race.
LONG WINAPI SsVectoredCrashLogger(EXCEPTION_POINTERS* info) noexcept {
    if (info == nullptr || info->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    const DWORD code = info->ExceptionRecord->ExceptionCode;
    // Only log genuinely fatal / uncaught categories. C++ exceptions
    // (0xE06D7363) and DLL-load probes generate a lot of false positives.
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_STACK_OVERFLOW:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
    case EXCEPTION_NONCONTINUABLE_EXCEPTION:
    case EXCEPTION_IN_PAGE_ERROR:
        (void)SsTopLevelCrashFilter(info);
        break;
    default:
        break;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void SsTerminateHandler() noexcept {
    if (!s_logPath.isEmpty()) {
        QFile f(s_logPath);
        if (f.open(QIODevice::Append | QIODevice::Text)) {
            QTextStream ts(&f);
            ts << "[CRASH] std::terminate invoked (unhandled C++ exception or noexcept violation)\n";
        }
    }
    std::abort();
}

} // namespace

int main(int argc, char* argv[]) {
    // -----------------------------------------------------------------------
    // Log path: %LOCALAPPDATA%\ShadowStrike\Phantom\ui_errors.log
    // Written before Qt is fully up so it captures loader-time errors too.
    // -----------------------------------------------------------------------
    {
        wchar_t appdata[MAX_PATH]{};
        if (::GetEnvironmentVariableW(L"LOCALAPPDATA", appdata, MAX_PATH) > 0) {
            s_logPath = QString::fromWCharArray(appdata)
                      + QStringLiteral("\\ShadowStrike\\Phantom\\ui_errors.log");
            QDir().mkpath(QFileInfo(s_logPath).absolutePath());
            // Truncate old log on fresh start so it doesn't grow unbounded.
            QFile f(s_logPath);
            f.open(QIODevice::WriteOnly | QIODevice::Truncate);
        }
    }
    qInstallMessageHandler(SsQtMessageHandler);

    // Install crash handlers *before* anything else runs so any fault during
    // QGuiApplication ctor, QML plugin load, PipeClient thread spawn, etc.
    // gets forensic breadcrumbs on disk.
    ::SetUnhandledExceptionFilter(&SsTopLevelCrashFilter);
    ::AddVectoredExceptionHandler(/*FirstHandler=*/0, &SsVectoredCrashLogger);
    std::set_terminate(&SsTerminateHandler);

    // -----------------------------------------------------------------------
    // Performance budget
    // -----------------------------------------------------------------------
    using PB  = ::ShadowStrike::PhantomHome::UI::PerfBudget;
    using PBL = ::ShadowStrike::PhantomHome::UI::PerfBudgetLimits;
    PB::Instance().MarkProcessStart();
    {
        PBL lim{};
        lim.soft_rss_bytes  = 120ull * 1024ull * 1024ull;
        lim.hard_rss_bytes  = 240ull * 1024ull * 1024ull;
        lim.soft_startup_ms = std::chrono::milliseconds{500};
        lim.hard_startup_ms = std::chrono::milliseconds{2000};
        PB::Instance().Start(lim, "PhantomHome.UI");
    }

    // High-DPI is automatic on Qt 6; just enable crisp scaling for QtSvg.
    QGuiApplication::setOrganizationName(QStringLiteral("ShadowStrike-Labs"));
    QGuiApplication::setOrganizationDomain(QStringLiteral("shadowstrike.dev"));
    QGuiApplication::setApplicationName(QStringLiteral("ShadowStrike Phantom Home"));
    QGuiApplication::setApplicationVersion(QStringLiteral("0.1.0"));

    QGuiApplication app(argc, argv);
    // Brand icon for the window / taskbar / alt-tab list. Prefer the high-
    // resolution PNG shipped in the qrc; fall back to the SVG if the PNG is
    // missing (e.g. old resource builds) so the window is never iconless.
    {
        QIcon brand(QStringLiteral(":/ShadowStrike/Phantom/qml/assets/logo.png"));
        if (brand.isNull()) {
            brand = QIcon(QStringLiteral(":/ShadowStrike/Phantom/qml/assets/logo.svg"));
        }
        app.setWindowIcon(brand);
    }

    using namespace ShadowStrike::PhantomHome;

    IPC::PipeClient::Options opts;
    opts.session_id    = CurrentSessionId();
    opts.client_build  = "ShadowStrike-Phantom-Home-UI/0.1.0";

    auto client = std::make_shared<IPC::PipeClient>(std::move(opts));
    client->Start();

    auto vm = std::make_unique<UI::Client::ProtectionViewModel>(client);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(
        QStringLiteral("protectionVm"), vm.get());

    // Capture any QML parse/binding errors to the log file BEFORE we
    // check rootObjects(), so the log is populated even if load() fails.
    QObject::connect(&engine, &QQmlApplicationEngine::warnings,
        [](const QList<QQmlError>& errors) noexcept {
            WriteQmlErrors(errors);
        });

    engine.load(QUrl(QStringLiteral("qrc:/ShadowStrike/Phantom/qml/App.qml")));
    if (engine.rootObjects().isEmpty()) {
        // Surface the error log path in a dialog so the user can find it.
        const std::wstring logW = s_logPath.isEmpty()
            ? L"(log unavailable)"
            : s_logPath.toStdWString();

        wchar_t msg[1024]{};
        ::StringCchPrintfW(msg, 1024,
            L"ShadowStrike Phantom dashboard failed to initialize the UI.\n\n"
            L"The QML engine could not load the main application interface.\n\n"
            L"Error log: %ls\n\n"
            L"Please attach this log when reporting the issue.",
            logW.c_str());
        ::MessageBoxW(nullptr, msg, L"ShadowStrike Phantom",
                      MB_ICONERROR | MB_OK | MB_SETFOREGROUND);
        return 2;
    }

    PB::Instance().MarkProcessReady();

    const int rc = app.exec();

    // Graceful teardown order: QML (app.exec return) → PipeClient → VM.
    client->Stop();
    vm.reset();
    client.reset();
    return rc;
}
