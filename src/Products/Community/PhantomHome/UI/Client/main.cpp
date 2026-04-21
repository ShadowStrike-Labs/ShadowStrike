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
