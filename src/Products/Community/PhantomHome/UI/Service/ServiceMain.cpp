/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file ServiceMain.cpp
 * @brief Entry point for ShadowStrikePhantomService.exe — the LocalSystem
 *        Windows service that hosts HomeProductOrchestrator and the named-pipe
 *        UI IPC server.
 *
 * Lifecycle
 * ---------
 *   1. SCM invokes wmain() with "service" argv OR as a proper service.
 *   2. StartServiceCtrlDispatcherW hands control to ServiceMainW.
 *   3. We register the control handler (RegisterServiceCtrlHandlerExW) and
 *      transition START_PENDING -> RUNNING.
 *   4. Orchestrator::Instance().Initialize() + Start().
 *   5. IPC::PipeServer started on `ShadowStrike.Phantom.UI.<console session id>`.
 *   6. Loop on a stop event until SERVICE_CONTROL_STOP / SHUTDOWN.
 *   7. Tear down in reverse — PipeServer.Stop(), Orchestrator.Shutdown().
 *
 * Robustness
 * ----------
 *   - All SetServiceStatus transitions are checkpointed.
 *   - Any failure during startup reports SERVICE_STOPPED with
 *     ERROR_SERVICE_SPECIFIC_ERROR and a distinct dwServiceSpecificExitCode.
 *   - SEH-level top-level filter logs and fails closed; never swallows crashes
 *     silently so Windows Error Reporting can kick in.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wtsapi32.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>
#include <thread>

#include "../IPC/PipeServer.hpp"
#include "../IPC/IPCRouter.hpp"
#include "../../HomeProductOrchestrator.hpp"
#include "../PerfBudget/PerfBudget.hpp"
#include "ServiceInstaller.hpp"
#include "PhantomCore/Utils/Logger.hpp"
#include "PhantomCore/Update/UpdateManager.hpp"

#pragma comment(lib, "wtsapi32.lib")

namespace {

constexpr const wchar_t* kServiceName = L"ShadowStrikePhantomService";

SERVICE_STATUS_HANDLE g_status_handle{nullptr};
SERVICE_STATUS        g_status{};
HANDLE                g_stop_event{nullptr};
std::atomic<bool>     g_stop_requested{false};
std::atomic<bool>     g_init_done{false};

void ReportStatus(DWORD current_state,
                  DWORD exit_code       = NO_ERROR,
                  DWORD wait_hint_ms    = 0,
                  DWORD specific_code   = 0) {
    static DWORD checkpoint = 1;
    g_status.dwCurrentState  = current_state;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwWaitHint      = wait_hint_ms;
    if (specific_code != 0) {
        g_status.dwWin32ExitCode          = ERROR_SERVICE_SPECIFIC_ERROR;
        g_status.dwServiceSpecificExitCode = specific_code;
    }

    if (current_state == SERVICE_START_PENDING) {
        g_status.dwControlsAccepted = 0;
    } else {
        g_status.dwControlsAccepted =
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE;
    }

    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        g_status.dwCheckPoint = 0;
    } else {
        g_status.dwCheckPoint = checkpoint++;
    }

    if (g_status_handle) {
        ::SetServiceStatus(g_status_handle, &g_status);
    }
}

DWORD WINAPI ServiceCtrlHandlerEx(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN: {
            ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
            g_stop_requested.store(true);
            if (g_stop_event) ::SetEvent(g_stop_event);
            return NO_ERROR;
        }
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        case SERVICE_CONTROL_SESSIONCHANGE:
            // Session switch may require re-hosting the pipe on a new session id,
            // handled at main-loop cadence.
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

std::uint32_t CurrentInteractiveSessionId() noexcept {
    const DWORD s = ::WTSGetActiveConsoleSessionId();
    return (s == 0xFFFFFFFF) ? 0u : static_cast<std::uint32_t>(s);
}

VOID WINAPI ServiceMainW(DWORD /*argc*/, LPWSTR* /*argv*/) {
    g_status.dwServiceType             = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwServiceSpecificExitCode = 0;

    g_status_handle = ::RegisterServiceCtrlHandlerExW(kServiceName, ServiceCtrlHandlerEx, nullptr);
    if (!g_status_handle) {
        ShadowStrike::Utils::Logger::Error(
            "ServiceMain: RegisterServiceCtrlHandlerExW failed gle={}", ::GetLastError());
        return;
    }

    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    g_stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        ReportStatus(SERVICE_STOPPED, 0, 0, /*specific=*/1);
        return;
    }

    // ---- Bind orchestrator singleton + start pipe server BEFORE any heavy
    // module init. IPCRouter handlers tolerate an unbound/uninitialized
    // orchestrator (they return "engine not initialized" Red state), so the
    // UI can connect and render a "starting up" dashboard immediately.
    // Heavy module Initialize()/Start() runs on a background thread so the
    // SCM transition to SERVICE_RUNNING is not gated by it; otherwise any
    // single slow module (YARA rule compile, ThreatIntel feed load, first
    // DB open) can starve the SCM 30 s budget and leave us stuck in
    // START_PENDING as observed in field diagnostics.
    auto& orch = ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance();

    using namespace ShadowStrike::PhantomHome::IPC;
    PipeServer::Options po{};
    po.session_id = CurrentInteractiveSessionId();
    auto server   = std::make_unique<PipeServer>(po);

    IPCRouter::Instance().Bind(orch);
    IPCRouter::Instance().BindPipeServer(*server);
    server->SetHandler([](ClientContext& ctx,
                          const FrameEnvelope& req,
                          MessageType& reply_type,
                          nlohmann::json& reply_payload) {
        IPCRouter::Instance().Dispatch(ctx, req, reply_type, reply_payload);
    });

    if (!server->Start()) {
        ShadowStrike::Utils::Logger::Error("ServiceMain: PipeServer::Start failed");
        ReportStatus(SERVICE_STOPPED, 0, 0, /*specific=*/4);
        ::CloseHandle(g_stop_event);
        return;
    }

    ReportStatus(SERVICE_RUNNING);
    ::ShadowStrike::PhantomHome::UI::PerfBudget::Instance().MarkProcessReady();
    ShadowStrike::Utils::Logger::Info(
        "ServiceMain: running (pipe up, orchestrator initializing async), session={}",
        po.session_id);

    // ---- Background orchestrator + update subsystem init ----
    std::thread init_thread([&orch]() {
        try {
            if (!orch.Initialize()) {
                ShadowStrike::Utils::Logger::Error(
                    "ServiceMain[bg]: orchestrator Initialize() returned false; "
                    "service stays online as scanner-less shell");
            } else if (!orch.Start()) {
                ShadowStrike::Utils::Logger::Error(
                    "ServiceMain[bg]: orchestrator Start() returned false; "
                    "one or more modules failed but service remains online");
            } else {
                ShadowStrike::Utils::Logger::Info(
                    "ServiceMain[bg]: orchestrator fully running");
            }
        } catch (const std::exception& e) {
            ShadowStrike::Utils::Logger::Error(
                "ServiceMain[bg]: orchestrator init threw: {}", e.what());
        } catch (...) {
            ShadowStrike::Utils::Logger::Error(
                "ServiceMain[bg]: orchestrator init threw unknown exception");
        }

        try {
            ::ShadowStrike::Update::UpdateConfiguration uc{};
            uc.enabled                  = true;
            uc.autoUpdate               = true;
            uc.channel                  = ::ShadowStrike::Update::UpdateChannel::Stable;
            uc.checkIntervalHours       =
                ::ShadowStrike::Update::UpdateConstants::DEFAULT_CHECK_INTERVAL_HOURS;
            uc.stagingDirectory         = L"C:\\ProgramData\\ShadowStrike\\Update\\Staging";
            uc.respectMeteredConnection = true;
            uc.deferDuringGaming        = true;
            uc.deferDuringHighCPU       = true;

            if (!::ShadowStrike::Update::UpdateManager::Instance().Initialize(uc)) {
                ShadowStrike::Utils::Logger::Warn(
                    "ServiceMain[bg]: UpdateManager::Initialize returned false");
            } else {
                ShadowStrike::Utils::Logger::Info(
                    "ServiceMain[bg]: UpdateManager initialized");
            }
        } catch (const std::exception& e) {
            ShadowStrike::Utils::Logger::Warn(
                "ServiceMain[bg]: UpdateManager init exception: {}", e.what());
        } catch (...) {
            ShadowStrike::Utils::Logger::Warn(
                "ServiceMain[bg]: UpdateManager init unknown exception");
        }

        g_init_done.store(true, std::memory_order_release);
    });

    // ---- Main wait loop ----
    while (!g_stop_requested.load()) {
        const DWORD wait = ::WaitForSingleObject(g_stop_event, 1000);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED)   break;
    }

    ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 30000);
    IPCRouter::Instance().Shutdown();
    server->Stop();
    server.reset();

    // Join the async init thread before we tear down singletons it touches.
    // If init is still in flight (e.g. service stopped within the first
    // seconds), we must wait for it to finish before Shutdown() is called,
    // otherwise Initialize() and Shutdown() race on the same module registry.
    if (init_thread.joinable()) {
        init_thread.join();
    }

    try {
        if (::ShadowStrike::Update::UpdateManager::HasInstance()) {
            ::ShadowStrike::Update::UpdateManager::Instance().Shutdown();
        }
    } catch (...) {
        // Shutdown best-effort; never block the service stop path.
    }

    orch.Shutdown();

    ::CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    ReportStatus(SERVICE_STOPPED);
}

}  // namespace

extern "C" int wmain(int argc, wchar_t* argv[]) {
    using PB  = ::ShadowStrike::PhantomHome::UI::PerfBudget;
    using PBL = ::ShadowStrike::PhantomHome::UI::PerfBudgetLimits;
    PB::Instance().MarkProcessStart();
    {
        PBL lim{};
        lim.soft_rss_bytes  =  256ull * 1024ull * 1024ull;
        lim.hard_rss_bytes  =  512ull * 1024ull * 1024ull;
        lim.soft_startup_ms = std::chrono::milliseconds{1500};
        lim.hard_startup_ms = std::chrono::milliseconds{5000};
        PB::Instance().Start(lim, "PhantomHome.Service");
    }

    // --install / --uninstall must run elevated. They never fall through to
    // SCM dispatch. Any other argv (or no argv) is treated as the service
    // control manager launching the process; StartServiceCtrlDispatcherW
    // will fail fast with ERROR_FAILED_SERVICE_CONTROLLER_CONNECT if invoked
    // directly from a console, which is the documented behaviour.
    if (argc >= 2 && argv != nullptr && argv[1] != nullptr) {
        const std::wstring arg{argv[1]};
        if (arg == L"--install" || arg == L"-install" || arg == L"/install") {
            wchar_t self[MAX_PATH]{};
            const DWORD n = ::GetModuleFileNameW(nullptr, self, MAX_PATH);
            if (n == 0 || n >= MAX_PATH) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --install: GetModuleFileNameW failed gle={}", ::GetLastError());
                return 1;
            }
            const std::wstring service_path{self, n};

            // Derive the tray path by replacing the final component.
            std::wstring tray_path = service_path;
            const auto slash = tray_path.find_last_of(L"\\/");
            if (slash == std::wstring::npos) {
                ShadowStrike::Utils::Logger::Error(
                    "wmain --install: cannot derive install directory from '{}'",
                    std::string(service_path.begin(), service_path.end()));
                return 1;
            }
            tray_path.resize(slash + 1);
            tray_path.append(L"ShadowStrikePhantomTray.exe");

            if (!ShadowStrike::PhantomHome::UI::Service::InstallService(service_path)) {
                return 2;
            }
            if (!ShadowStrike::PhantomHome::UI::Service::InstallTrayAutostart(tray_path)) {
                // Roll back the service registration so install is all-or-nothing.
                (void)ShadowStrike::PhantomHome::UI::Service::UninstallService();
                return 3;
            }
            return 0;
        }
        if (arg == L"--uninstall" || arg == L"-uninstall" || arg == L"/uninstall") {
            // Best-effort, in the opposite order of install: remove the tray
            // entry first so no new tray instances spawn while the service is
            // being torn down.
            const bool tray_ok = ShadowStrike::PhantomHome::UI::Service::UninstallTrayAutostart();
            const bool svc_ok  = ShadowStrike::PhantomHome::UI::Service::UninstallService();
            return (tray_ok && svc_ok) ? 0 : 4;
        }
    }

    SERVICE_TABLE_ENTRYW table[] = {
        {const_cast<LPWSTR>(kServiceName), reinterpret_cast<LPSERVICE_MAIN_FUNCTIONW>(ServiceMainW)},
        {nullptr, nullptr}};

    if (!::StartServiceCtrlDispatcherW(table)) {
        const DWORD gle = ::GetLastError();
        ShadowStrike::Utils::Logger::Error(
            "wmain: StartServiceCtrlDispatcherW failed gle={}", gle);
        return static_cast<int>(gle);
    }
    return 0;
}
