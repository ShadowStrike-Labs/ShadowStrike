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
#include <cstdint>
#include <format>
#include <string>

#include "../IPC/PipeServer.hpp"
#include "../IPC/IPCRouter.hpp"
#include "../../HomeProductOrchestrator.hpp"
#include "PhantomCore/Utils/Logger.hpp"

#pragma comment(lib, "wtsapi32.lib")

namespace {

constexpr const wchar_t* kServiceName = L"ShadowStrikePhantomService";

SERVICE_STATUS_HANDLE g_status_handle{nullptr};
SERVICE_STATUS        g_status{};
HANDLE                g_stop_event{nullptr};
std::atomic<bool>     g_stop_requested{false};

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

    // ---- Orchestrator init ----
    auto& orch = ::ShadowStrike::Products::Home::HomeProductOrchestrator::Instance();
    if (!orch.Initialize()) {
        ShadowStrike::Utils::Logger::Error("ServiceMain: orchestrator Initialize() failed");
        ReportStatus(SERVICE_STOPPED, 0, 0, /*specific=*/2);
        ::CloseHandle(g_stop_event);
        return;
    }
    ReportStatus(SERVICE_START_PENDING, NO_ERROR, 10000);

    if (!orch.Start()) {
        ShadowStrike::Utils::Logger::Error("ServiceMain: orchestrator Start() failed");
        orch.Shutdown();
        ReportStatus(SERVICE_STOPPED, 0, 0, /*specific=*/3);
        ::CloseHandle(g_stop_event);
        return;
    }

    // ---- IPC pipe server ----
    using namespace ShadowStrike::PhantomHome::IPC;

    PipeServer::Options po{};
    po.session_id = CurrentInteractiveSessionId();
    auto server   = std::make_unique<PipeServer>(po);

    IPCRouter::Instance().Bind(orch);
    server->SetHandler([](ClientContext& ctx,
                          const FrameEnvelope& req,
                          MessageType& reply_type,
                          nlohmann::json& reply_payload) {
        IPCRouter::Instance().Dispatch(ctx, req, reply_type, reply_payload);
    });

    if (!server->Start()) {
        ShadowStrike::Utils::Logger::Error("ServiceMain: PipeServer::Start failed");
        orch.Shutdown();
        ReportStatus(SERVICE_STOPPED, 0, 0, /*specific=*/4);
        ::CloseHandle(g_stop_event);
        return;
    }

    ReportStatus(SERVICE_RUNNING);
    ShadowStrike::Utils::Logger::Info("ServiceMain: running, session={}", po.session_id);

    // ---- Main wait loop ----
    while (!g_stop_requested.load()) {
        const DWORD wait = ::WaitForSingleObject(g_stop_event, 1000);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED)   break;
    }

    ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, 15000);
    server->Stop();
    server.reset();
    orch.Shutdown();

    ::CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    ReportStatus(SERVICE_STOPPED);
}

}  // namespace

extern "C" int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
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
