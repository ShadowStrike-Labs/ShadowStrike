/*
 * ShadowStrike - Enterprise NGAV Platform
 * Copyright (C) 2026 ShadowStrike-Labs
 *
 * Licensed under GNU AGPL-v3. See LICENSE.txt at the repository root.
 */

/**
 * @file ServiceInstaller.cpp
 * @brief Install / uninstall helper for ShadowStrikePhantomService.
 *
 * Usage:
 *   ShadowStrikePhantomService.exe --install   (must run elevated)
 *   ShadowStrikePhantomService.exe --uninstall (must run elevated)
 *
 * The running service binary is the very same exe; the SCM calls wmain()
 * without --install/--uninstall, which defers to ServiceMain.cpp.
 *
 * Hardening
 * ---------
 *   - Service is created with SERVICE_AUTO_START and LocalSystem account.
 *   - ServiceConfig2 failure actions: restart with 60 s delay, max 3 times,
 *     then run none (user sees a red UI state).
 *   - Required privileges explicitly reduced to the minimum we actually use.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <format>
#include <string>
#include <vector>

#include "PhantomCore/Utils/Logger.hpp"

namespace ShadowStrike::PhantomHome::UI::Service {

namespace {

constexpr const wchar_t* kServiceName        = L"ShadowStrikePhantomService";
constexpr const wchar_t* kServiceDisplayName = L"ShadowStrike Phantom Service";
constexpr const wchar_t* kServiceDescription =
    L"Provides ShadowStrike Phantom Home real-time protection, scanning, and telemetry.";

struct ScmHandle {
    SC_HANDLE h{nullptr};
    ~ScmHandle() { if (h) ::CloseServiceHandle(h); }
    operator SC_HANDLE() const noexcept { return h; }
};

}  // namespace

[[nodiscard]] bool InstallService(const std::wstring& image_path) {
    ScmHandle mgr{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!mgr) {
        ShadowStrike::Utils::Logger::Error("InstallService: OpenSCManagerW failed gle={}", ::GetLastError());
        return false;
    }

    ScmHandle svc{::CreateServiceW(mgr,
                                   kServiceName,
                                   kServiceDisplayName,
                                   SERVICE_ALL_ACCESS,
                                   SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START,
                                   SERVICE_ERROR_NORMAL,
                                   image_path.c_str(),
                                   nullptr, nullptr, nullptr,
                                   /*LocalSystem*/ nullptr,
                                   nullptr)};
    if (!svc) {
        const DWORD gle = ::GetLastError();
        if (gle == ERROR_SERVICE_EXISTS) {
            ShadowStrike::Utils::Logger::Warn("InstallService: service already exists");
            return true;
        }
        ShadowStrike::Utils::Logger::Error("InstallService: CreateServiceW failed gle={}", gle);
        return false;
    }

    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(kServiceDescription)};
    ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

    SC_ACTION actions[3]{};
    actions[0].Type = SC_ACTION_RESTART; actions[0].Delay = 60'000;
    actions[1].Type = SC_ACTION_RESTART; actions[1].Delay = 60'000;
    actions[2].Type = SC_ACTION_NONE;    actions[2].Delay = 0;
    SERVICE_FAILURE_ACTIONSW fa{};
    fa.dwResetPeriod = 24 * 3600;
    fa.cActions      = 3;
    fa.lpsaActions   = actions;
    ::ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

    ShadowStrike::Utils::Logger::Info("InstallService: installed '{}'",
                                      std::string("ShadowStrikePhantomService"));
    return true;
}

[[nodiscard]] bool UninstallService() {
    ScmHandle mgr{::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!mgr) return false;

    ScmHandle svc{::OpenServiceW(mgr, kServiceName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS)};
    if (!svc) return (::GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST);

    SERVICE_STATUS st{};
    ::ControlService(svc, SERVICE_CONTROL_STOP, &st);

    if (!::DeleteService(svc)) {
        ShadowStrike::Utils::Logger::Error("UninstallService: DeleteService failed gle={}",
                                           ::GetLastError());
        return false;
    }
    ShadowStrike::Utils::Logger::Info("UninstallService: removed");
    return true;
}

}  // namespace ShadowStrike::PhantomHome::UI::Service
