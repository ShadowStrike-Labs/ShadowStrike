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
 * ============================================================================
 * ShadowStrike NGAV — PHANTOM HOME UI — ENTRY POINT
 * ============================================================================
 *
 * @file main.cpp
 * @brief Process entry point for ShadowStrikePhantomUI.exe.
 *
 * Startup sequence:
 *   1. PerfBudget::ApplyEngineTuning()    — env vars before QApplication
 *   2. Logger initialisation
 *   3. Single-instance mutex guard        — second instance signals first and exits
 *   4. QApplication construction (DPI, style)
 *   5. Translator::LoadFromConfigOrSystem()
 *   6. HighContrastContext, PerfBudgetContext, WindowActivator
 *   7. PipeClient::Start()
 *   8. ViewModel construction
 *   9. QQmlApplicationEngine + context properties
 *  10. Load qrc:/qml/Main.qml
 *  11. PerfBudget::EndStartupAndValidate()
 *  12. QApplication::exec()
 *  13. Shutdown: PipeClient::Stop(), Logger::ShutDown()
 *
 * Threading model:
 *   All context properties are QObjects owned by the Qt main thread.
 *   PipeClient and WindowActivator own their own std::jthreads internally
 *   and marshal callbacks to the main thread via QMetaObject::invokeMethod.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @date 2026
 * ============================================================================
 */

// Windows headers must precede Qt headers to avoid macro collisions.
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <shellapi.h>  // CommandLineToArgvW

// Qt — application
#include <QApplication>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickWindow>
#include <QTimer>
#include <QMetaObject>
#include <QStringList>
#include <QVariant>

// Qt — utilities
#include <QLoggingCategory>
#include <QtGlobal>
#include <QQmlError>
#include <QList>

#include <cstdint>
#include <cwchar>
#include <cstring>
#include <vector>

// ShadowStrike — logger (must come after windows.h)
#include <PhantomCore/Utils/Logger.hpp>

// ShadowStrike — startup budget
#include <Products/Community/PhantomHome/UI/PerfBudget/PerfBudget.hpp>

// ShadowStrike — localisation
#include <Products/Community/PhantomHome/UI/I18n/Translator.hpp>

// ShadowStrike — HCM bridge
#include <Products/Community/PhantomHome/UI/Accessibility/HighContrastContext.hpp>

// ShadowStrike — service IPC
#include <Products/Community/PhantomHome/UI/Client/IPC/PipeClient.hpp>

// ShadowStrike — view models
#include <Products/Community/PhantomHome/UI/Client/ViewModels/ProtectionViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/ScanViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/QuarantineModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/ReportsModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/SettingsViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/ModulesListModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/PgtiViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/RecommendationsModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/ZeroTrustViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/PrivacyViewModel.hpp>
#include <Products/Community/PhantomHome/UI/Client/ViewModels/PerformanceViewModel.hpp>

// ShadowStrike — single-instance activation bridge
#include <Products/Community/PhantomHome/UI/Client/WindowActivator.hpp>

// ShadowStrike — CLI argument constants (tray ↔ UI contract)
#include <Products/Community/PhantomHome/UI/Shared/TrayUiArgs.hpp>

// ShadowStrike — version
#include <Products/Community/PhantomHome/UI/Tray/Version.hpp>

// ============================================================================
// CONSTANTS
// ============================================================================

static constexpr wchar_t kSingleInstanceMutex[] =
    L"Global\\ShadowStrike.PhantomHome.UI";

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

namespace {

using namespace ShadowStrike::Utils;
using namespace ShadowStrike::PhantomHome::UI;
using namespace ShadowStrike::PhantomHome::UI::IPC;
using namespace ShadowStrike::PhantomHome::UI::ViewModels;
using namespace ShadowStrike::PhantomHome::Tray::Version;

// ---------------------------------------------------------------------------
// Parsed startup arguments
// ---------------------------------------------------------------------------
struct StartupArgs {
    bool    minimized   = false;
    bool    fromTray    = false;
    QString initialRoute;       ///< e.g. "settings", "reports", "quarantine"

    // Action flags — forwarded to the appropriate ViewModel after startup.
    bool    quickScan         = false;
    bool    fullScan          = false;
    bool    pauseProtection   = false;
    bool    resumeProtection  = false;
    bool    checkForUpdates   = false;
};

// ---------------------------------------------------------------------------
// Parse argv using the TrayUiArgs contract.
// ---------------------------------------------------------------------------
[[nodiscard]] StartupArgs ParseArgsFromArgv(int argc, LPWSTR* wargv) noexcept
{
    StartupArgs args{};

    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg{wargv[i]};

        if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kOpenDashboard) {
            args.initialRoute = QStringLiteral("dashboard");
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kOpenSettings) {
            args.initialRoute = QStringLiteral("settings");
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kOpenReports) {
            args.initialRoute = QStringLiteral("reports");
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kOpenQuarantine) {
            args.initialRoute = QStringLiteral("quarantine");
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kQuickScan) {
            args.quickScan = true;
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kFullScan) {
            args.fullScan = true;
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kPauseProtection) {
            args.pauseProtection = true;
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kResumeProtection) {
            args.resumeProtection = true;
        } else if (arg == ShadowStrike::PhantomHome::UI::TrayArgs::kCheckForUpdates) {
            args.checkForUpdates = true;
        } else if (arg == L"--minimized") {
            args.minimized = true;
        } else if (arg == L"--from-tray") {
            args.fromTray = true;
        }
    }

    return args;
}

[[nodiscard]] StartupArgs ParseArgs() noexcept
{
    int    argc  = 0;
    LPWSTR*wargv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!wargv) {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"CommandLineToArgvW failed (error=%lu); using defaults",
                    ::GetLastError());
        return {};
    }

    const StartupArgs args = ParseArgsFromArgv(argc, wargv);
    ::LocalFree(wargv);
    return args;
}

[[nodiscard]] StartupArgs ParseArgsFromCommandLine(const QString& commandLine) noexcept
{
    if (commandLine.isEmpty()) {
        return {};
    }

    const std::wstring raw = commandLine.toStdWString();
    int argc = 0;
    LPWSTR* wargv = ::CommandLineToArgvW(raw.c_str(), &argc);
    if (!wargv) {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"CommandLineToArgvW failed for activation payload (error=%lu)",
                    ::GetLastError());
        return {};
    }

    const StartupArgs args = ParseArgsFromArgv(argc, wargv);
    ::LocalFree(wargv);
    return args;
}

// ---------------------------------------------------------------------------
// Attempt to signal the first instance to show its window.
// Best-effort: any failure is logged at WARN and ignored.
// ---------------------------------------------------------------------------
void SignalFirstInstance() noexcept
{
    HANDLE pipe = ::CreateFileW(
        WindowActivator::kPipeName,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (pipe == INVALID_HANDLE_VALUE) {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"Could not open activation pipe to first instance (error=%lu)",
                    ::GetLastError());
        return;
    }

    const wchar_t* commandLine = ::GetCommandLineW();
    const std::size_t chars = commandLine ? std::wcslen(commandLine) : 0u;
    const std::size_t payloadBytes = chars * sizeof(wchar_t);

    DWORD written = 0;
    bool ok = false;

    if (payloadBytes <= WindowActivator::kMaxActivationPayloadBytes) {
        std::vector<std::uint8_t> frame;
        frame.resize(sizeof(WindowActivator::kActivationFrameMagic) +
                     sizeof(std::uint32_t) +
                     payloadBytes);

        std::memcpy(frame.data(),
                    WindowActivator::kActivationFrameMagic,
                    sizeof(WindowActivator::kActivationFrameMagic));

        const std::uint32_t payloadSize = static_cast<std::uint32_t>(payloadBytes);
        frame[4] = static_cast<std::uint8_t>(payloadSize & 0xFFu);
        frame[5] = static_cast<std::uint8_t>((payloadSize >> 8u) & 0xFFu);
        frame[6] = static_cast<std::uint8_t>((payloadSize >> 16u) & 0xFFu);
        frame[7] = static_cast<std::uint8_t>((payloadSize >> 24u) & 0xFFu);

        if (payloadBytes != 0u) {
            std::memcpy(frame.data() + 8u, commandLine, payloadBytes);
        }

        ok = ::WriteFile(pipe,
                         frame.data(),
                         static_cast<DWORD>(frame.size()),
                         &written,
                         nullptr) != FALSE;
    } else {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"Activation command line is %zu bytes; falling back to legacy token",
                    payloadBytes);
        ok = ::WriteFile(pipe,
                         WindowActivator::kLegacyActivateToken,
                         static_cast<DWORD>(sizeof(WindowActivator::kLegacyActivateToken)),
                         &written,
                         nullptr) != FALSE;
    }
    if (!ok) {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"WriteFile to activation pipe failed (error=%lu)",
                    ::GetLastError());
    }

    ::CloseHandle(pipe);
}

// ---------------------------------------------------------------------------
// Logger initialisation
// ---------------------------------------------------------------------------
void InitLogger() noexcept
{
    // Resolve per-user log directory so the UI works under the read-only
    // Program Files install location.  Fallback chain:
    //   1. %LOCALAPPDATA%\ShadowStrike\Logs           (preferred)
    //   2. %TEMP%\ShadowStrike\Logs                   (service-like fallback)
    //   3. "logs"                                     (dev runs from bin\Release)
    std::wstring logDir;
    {
        wchar_t localAppData[MAX_PATH]{};
        DWORD n = ::GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            logDir.assign(localAppData, n);
            logDir += L"\\ShadowStrike\\Logs";
        } else {
            wchar_t tempPath[MAX_PATH]{};
            DWORD t = ::GetTempPathW(MAX_PATH, tempPath);
            if (t > 0 && t < MAX_PATH) {
                logDir.assign(tempPath, t);
                if (!logDir.empty() && logDir.back() != L'\\') logDir.push_back(L'\\');
                logDir += L"ShadowStrike\\Logs";
            } else {
                logDir = L"logs";
            }
        }
    }

    LoggerConfig cfg{};
    cfg.async             = true;
    cfg.toConsole         = false;  // GUI application — no console window
    cfg.toFile            = true;
    cfg.toEventLog        = false;
    cfg.jsonLines         = false;
    cfg.logDirectory      = logDir;
    cfg.baseFileName      = L"PhantomHomeUI";
    cfg.maxFileSizeBytes  = 10ULL * 1024ULL * 1024ULL;  // 10 MiB
    cfg.maxFileCount      = 5;
    cfg.minimalLevel      = LogLevel::Info;
    cfg.flushLevel        = LogLevel::Error;
    cfg.includeSrcLocation = true;
    cfg.includeProcThreadId = true;

    Logger::Instance().Initialize(cfg);
}

// ---------------------------------------------------------------------------
// Qt → ShadowStrike Logger bridge.
//
// Qt emits QML errors, property binding loops, and module-import failures via
// qWarning/qCritical routed through QtMessageHandler. Without a handler these
// messages go to stderr / OutputDebugString and are invisible in a GUI install,
// which turns "QML failed to load" into a silent exit.  We route everything
// into our structured logger so post-mortem analysis of customer installs has
// actionable diagnostics.
// ---------------------------------------------------------------------------
void QtMessageToLogger(QtMsgType type,
                       const QMessageLogContext& ctx,
                       const QString& msg) noexcept
{
    const std::wstring wmsg = msg.toStdWString();
    const char* category = (ctx.category && *ctx.category) ? ctx.category : "Qt";
    const std::wstring wcat(category, category + std::strlen(category));

    switch (type) {
    case QtDebugMsg:
        SS_LOG_DEBUG(L"PhantomHome.Qt", L"[%ls] %ls", wcat.c_str(), wmsg.c_str());
        break;
    case QtInfoMsg:
        SS_LOG_INFO(L"PhantomHome.Qt", L"[%ls] %ls", wcat.c_str(), wmsg.c_str());
        break;
    case QtWarningMsg:
        SS_LOG_WARN(L"PhantomHome.Qt", L"[%ls] %ls", wcat.c_str(), wmsg.c_str());
        break;
    case QtCriticalMsg:
        SS_LOG_ERROR(L"PhantomHome.Qt", L"[%ls] %ls", wcat.c_str(), wmsg.c_str());
        break;
    case QtFatalMsg:
        SS_LOG_ERROR(L"PhantomHome.Qt", L"[FATAL][%ls] %ls", wcat.c_str(), wmsg.c_str());
        break;
    }
}

} // anonymous namespace

// ============================================================================
// ENTRY POINT
// ============================================================================

int main(int argc, char* argv[])
{
    // ── Step 1: Engine tuning (before QApplication) ────────────────────────
    PerfBudget::ApplyEngineTuning();

    // Force Basic style — we own all visual styling through Theme.qml.
    qputenv("QT_QUICK_CONTROLS_STYLE", "Basic");

    // Pass-through DPI scale so the OS compositor handles fractional scales
    // without Qt rounding errors on mixed-DPI setups.
    QGuiApplication::setHighDpiScaleFactorRoundingPolicy(
        Qt::HighDpiScaleFactorRoundingPolicy::PassThrough);

    // ── Step 2: Logger ─────────────────────────────────────────────────────
    InitLogger();

    // Route Qt's own diagnostics (qWarning/qCritical, QML errors, binding
    // loops, plugin load failures) into our logger so production installs can
    // be diagnosed post-mortem without attaching a debugger.
    qInstallMessageHandler(&QtMessageToLogger);

    SS_LOG_INFO(L"PhantomHome.Main",
                L"ShadowStrike PhantomHome UI starting — version %ls",
                kVersion);

    // ── Step 3: Single-instance guard ──────────────────────────────────────
    HANDLE hMutex = ::CreateMutexW(nullptr, FALSE, kSingleInstanceMutex);
    const DWORD mutexErr = ::GetLastError();

    if (hMutex == nullptr) {
        SS_LOG_ERROR(L"PhantomHome.Main",
                     L"CreateMutexW failed — cannot guarantee single-instance (error=%lu)",
                     ::GetLastError());
        // Proceed anyway; this is a non-fatal degraded state.
    } else if (mutexErr == ERROR_ALREADY_EXISTS) {
        SS_LOG_INFO(L"PhantomHome.Main",
                    L"Another instance is already running — signalling activation and exiting");
        SignalFirstInstance();
        ::CloseHandle(hMutex);
        return 0;
    }

    // ── Step 4: QApplication ───────────────────────────────────────────────
    QApplication app(argc, argv);

    QCoreApplication::setOrganizationName(QStringLiteral("ShadowStrike Labs"));
    QCoreApplication::setOrganizationDomain(QStringLiteral("ShadowStrike.dev"));
    QCoreApplication::setApplicationName(QStringLiteral("ShadowStrike Phantom Home"));
    QCoreApplication::setApplicationVersion(QStringLiteral("1.0.0-dev"));

    // ── Step 5: CLI args ───────────────────────────────────────────────────
    const StartupArgs startArgs = ParseArgs();

    SS_LOG_INFO(L"PhantomHome.Main",
                L"Startup args: minimized=%d fromTray=%d route=%ls quickScan=%d",
                startArgs.minimized,
                startArgs.fromTray,
                startArgs.initialRoute.toStdWString().c_str(),
                startArgs.quickScan);

    // ── Step 6: Localisation ───────────────────────────────────────────────
    const QString effectiveLocale = Translator::LoadFromConfigOrSystem();
    SS_LOG_INFO(L"PhantomHome.Main", L"Active locale: %ls",
                effectiveLocale.toStdWString().c_str());

    // ── Step 7: High Contrast context ──────────────────────────────────────
    HighContrastContext& hcmCtx = HighContrastContext::Instance();

    // ── Step 8: Perf budget context ────────────────────────────────────────
    PerfBudgetContext& perfCtx = PerfBudget::Context();
    PerfBudget::BeginStartup();

    // ── Step 9: WindowActivator (single-instance pipe server) ──────────────
    WindowActivator windowActivator;
    windowActivator.Start();

    // ── Step 10: Service pipe client ───────────────────────────────────────
    PipeClient& pipeClient = PipeClient::Instance();
    if (!pipeClient.Start()) {
        SS_LOG_WARN(L"PhantomHome.Main",
                    L"PipeClient::Start() failed — UI will operate in disconnected mode");
    }

    // ── Step 11: ViewModels ────────────────────────────────────────────────
    ProtectionViewModel protectionViewModel;
    ScanViewModel       scanViewModel;
    QuarantineModel     quarantineModel;
    ReportsModel        reportsModel;
    SettingsViewModel   settingsViewModel;
    ModulesListModel    modulesListModel;
    PgtiViewModel       pgtiViewModel;
    RecommendationsModel recommendationsViewModel;
    ZeroTrustViewModel  zeroTrustViewModel;
    PrivacyViewModel    privacyViewModel;
    PerformanceViewModel performanceViewModel;

    // ── Step 12: QML engine ────────────────────────────────────────────────
    QQmlApplicationEngine engine;

    // Route QML parser / type-compile warnings into our logger.  This gives
    // us the concrete filename:line:column and diagnostic string (e.g.
    // "module 'ShadowStrike.Foo' is not installed") that would otherwise
    // only appear on stderr which GUI apps do not surface.
    QObject::connect(&engine, &QQmlApplicationEngine::warnings, &app,
        [](const QList<QQmlError>& errors) {
            for (const QQmlError& err : errors) {
                const std::wstring url  = err.url().toString().toStdWString();
                const std::wstring desc = err.description().toStdWString();
                SS_LOG_ERROR(L"PhantomHome.Qml",
                             L"QML error at %ls:%d:%d — %ls",
                             url.c_str(),
                             err.line(),
                             err.column(),
                             desc.c_str());
            }
        });

    // Tell the import machinery where to find ShadowStrike.* QML modules.
    engine.addImportPath(QStringLiteral("qrc:/qml"));

    // Expose all context properties before load so QML bindings resolve.
    QQmlContext* ctx = engine.rootContext();

    ctx->setContextProperty(QStringLiteral("hcmCtx"),              &hcmCtx);
    ctx->setContextProperty(QStringLiteral("perfBudget"),          &perfCtx);
    ctx->setContextProperty(QStringLiteral("windowActivator"),     &windowActivator);
    ctx->setContextProperty(QStringLiteral("pipeClient"),          &pipeClient);

    ctx->setContextProperty(QStringLiteral("protectionViewModel"), &protectionViewModel);
    ctx->setContextProperty(QStringLiteral("scanViewModel"),       &scanViewModel);
    ctx->setContextProperty(QStringLiteral("quarantineModel"),     &quarantineModel);
    ctx->setContextProperty(QStringLiteral("reportsModel"),        &reportsModel);
    ctx->setContextProperty(QStringLiteral("settingsViewModel"),   &settingsViewModel);
    ctx->setContextProperty(QStringLiteral("modulesListModel"),    &modulesListModel);
    ctx->setContextProperty(QStringLiteral("pgtiViewModel"),       &pgtiViewModel);
    ctx->setContextProperty(QStringLiteral("recommendationsViewModel"), &recommendationsViewModel);
    ctx->setContextProperty(QStringLiteral("zeroTrustViewModel"),  &zeroTrustViewModel);
    ctx->setContextProperty(QStringLiteral("privacyViewModel"),    &privacyViewModel);
    ctx->setContextProperty(QStringLiteral("performanceViewModel"), &performanceViewModel);

    // initialRoute is a plain string — read once by Main.qml at Component.onCompleted.
    ctx->setContextProperty(QStringLiteral("initialRoute"),
                            startArgs.initialRoute);

    // ── Step 13: Load Main.qml ─────────────────────────────────────────────
    const QUrl mainUrl(QStringLiteral("qrc:/qml/Main.qml"));

    // Fatal guard: if Main.qml fails to load we cannot continue.
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        [&mainUrl](const QUrl& url) {
            if (url == mainUrl) {
                SS_LOG_ERROR(L"PhantomHome.Main",
                             L"Fatal: QML engine failed to create root object from Main.qml");
                QCoreApplication::exit(1);
            }
        },
        Qt::QueuedConnection);

    engine.load(mainUrl);

    if (engine.rootObjects().isEmpty()) {
        SS_LOG_ERROR(L"PhantomHome.Main",
                     L"Fatal: QML engine produced no root objects after loading Main.qml");
        // Surface the failure to the user so a silent install-time regression
        // (e.g. missing Qt QML module, broken qrc) is immediately visible
        // instead of the UI appearing to do nothing when launched from the tray.
        ::MessageBoxW(
            nullptr,
            L"ShadowStrike Phantom could not start its user interface.\n\n"
            L"The QML engine failed to load the main view. This usually means a "
            L"required Qt runtime component is missing or damaged.\n\n"
            L"Please reinstall from the signed bundle (ShadowStrikePhantom-Home-Setup.exe) "
            L"and, if the problem persists, send the log file found under:\n"
            L"    %LOCALAPPDATA%\\ShadowStrike\\Logs\\PhantomHomeUI*.log",
            L"ShadowStrike Phantom Home — startup failure",
            MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        pipeClient.Stop();
        windowActivator.Stop();
        if (hMutex) ::CloseHandle(hMutex);
        Logger::Instance().ShutDown();
        return 1;
    }

    // ── Step 14: Post-load actions ─────────────────────────────────────────
    // Wire ApplicationWindow::activeChanged → PerfBudget::OnWindowActiveChanged
    // now that the root window object exists.  Previously this was bound
    // inline in Main.qml but PerfBudgetContext has no invokable entry point,
    // so the call lives C++-side where the static can be invoked directly.
    {
        const auto& roots = engine.rootObjects();
        for (QObject* obj : roots) {
            if (auto* win = qobject_cast<QQuickWindow*>(obj)) {
                QObject::connect(win, &QWindow::activeChanged, &app,
                                 [win]() noexcept {
                                     PerfBudget::OnWindowActiveChanged(win->isActive());
                                 });
                break;
            }
        }
    }

    auto raiseRootWindow = [&engine]() noexcept {
        const auto& roots = engine.rootObjects();
        for (QObject* obj : roots) {
            if (auto* win = qobject_cast<QQuickWindow*>(obj)) {
                win->show();
                win->raise();
                win->requestActivate();
                break;
            }
        }
    };

    auto navigateToRoute = [&engine](const QString& route) {
        if (route.isEmpty()) {
            return;
        }

        const auto& roots = engine.rootObjects();
        for (QObject* obj : roots) {
            if (QMetaObject::invokeMethod(obj,
                                          "navigateToRoute",
                                          Qt::QueuedConnection,
                                          Q_ARG(QVariant, QVariant(route)))) {
                return;
            }
        }

        SS_LOG_WARN(L"PhantomHome.Main",
                    L"Unable to dispatch tray route '%ls' to QML root",
                    route.toStdWString().c_str());
    };

    auto applyStartupAction = [&](const StartupArgs& args) {
        if (!args.initialRoute.isEmpty()) {
            navigateToRoute(args.initialRoute);
        } else if (args.checkForUpdates) {
            navigateToRoute(QStringLiteral("settings"));
        }

        if (args.quickScan) {
            QMetaObject::invokeMethod(&scanViewModel,
                                      "startFastScan",
                                      Qt::QueuedConnection);
        } else if (args.fullScan) {
            QMetaObject::invokeMethod(&scanViewModel,
                                      "startFullScan",
                                      Qt::QueuedConnection);
        }

        if (args.pauseProtection) {
            QMetaObject::invokeMethod(&protectionViewModel,
                                      "pauseProtection",
                                      Qt::QueuedConnection,
                                      Q_ARG(int, 0));
        } else if (args.resumeProtection) {
            QMetaObject::invokeMethod(&protectionViewModel,
                                      "resumeProtection",
                                      Qt::QueuedConnection);
        }

        if (args.checkForUpdates) {
            SS_LOG_INFO(L"PhantomHome.Main",
                        L"Tray requested update check; routed user to Settings updates section");
        }
    };

    QObject::connect(&windowActivator,
                     &WindowActivator::activate,
                     &app,
                     [&](const QString& commandLine) {
                         raiseRootWindow();
                         applyStartupAction(ParseArgsFromCommandLine(commandLine));
                     });

    // Apply minimized state and action args via a single-shot timer so the
    // window has completed its first paint before we manipulate it.
    QTimer::singleShot(0, [&]() {
        if (startArgs.minimized) {
            const auto& roots = engine.rootObjects();
            for (QObject* obj : roots) {
                if (auto* win = qobject_cast<QQuickWindow*>(obj)) {
                    win->showMinimized();
                    break;
                }
            }
        }

        applyStartupAction(startArgs);
    });

    PerfBudget::EndStartupAndValidate();

    // ── Step 15: Event loop ────────────────────────────────────────────────
    const int exitCode = QApplication::exec();

    // ── Step 16: Shutdown ──────────────────────────────────────────────────
    SS_LOG_INFO(L"PhantomHome.Main",
                L"Event loop exited with code %d — shutting down", exitCode);

    pipeClient.Stop();
    windowActivator.Stop();

    if (hMutex) {
        ::CloseHandle(hMutex);
        hMutex = nullptr;
    }

    Logger::Instance().ShutDown();

    return exitCode;
}
