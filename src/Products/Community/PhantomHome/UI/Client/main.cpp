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
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QUrl>

#include <memory>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wtsapi32.h>

#include "IPC/PipeClient.hpp"
#include "ViewModels/ProtectionViewModel.hpp"

namespace {

std::uint32_t CurrentSessionId() noexcept {
    DWORD sid = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sid)) {
        return static_cast<std::uint32_t>(sid);
    }
    return static_cast<std::uint32_t>(::WTSGetActiveConsoleSessionId());
}

} // namespace

int main(int argc, char* argv[]) {
    // High-DPI is automatic on Qt 6; just enable crisp scaling for QtSvg.
    QGuiApplication::setOrganizationName(QStringLiteral("ShadowStrike-Labs"));
    QGuiApplication::setOrganizationDomain(QStringLiteral("shadowstrike.dev"));
    QGuiApplication::setApplicationName(QStringLiteral("ShadowStrike Phantom Home"));
    QGuiApplication::setApplicationVersion(QStringLiteral("0.1.0"));

    QGuiApplication app(argc, argv);
    app.setWindowIcon(QIcon(QStringLiteral(":/ShadowStrike/Phantom/qml/assets/logo.svg")));

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

    // Import path for the Theming singleton module.
    engine.addImportPath(QStringLiteral("qrc:/ShadowStrike/Phantom/qml"));

    engine.load(QUrl(QStringLiteral("qrc:/ShadowStrike/Phantom/qml/App.qml")));
    if (engine.rootObjects().isEmpty()) {
        return 2;
    }

    const int rc = app.exec();

    // Graceful teardown order: QML (app.exec return) → PipeClient → VM.
    client->Stop();
    vm.reset();
    client.reset();
    return rc;
}
