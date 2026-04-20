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
#include <optional>
#include <string>
#include <vector>

#include "PhantomCore/Utils/Logger.hpp"
#include "Products/Community/PhantomHome/UI/Service/ServiceInstaller.hpp"

namespace ShadowStrike::PhantomHome::UI::Service {

namespace {

constexpr const wchar_t* kServiceName        = L"ShadowStrikePhantomService";
constexpr const wchar_t* kServiceDisplayName = L"ShadowStrike Phantom Service";
constexpr const wchar_t* kServiceDescription =
    L"Provides ShadowStrike Phantom Home real-time protection, scanning, and telemetry.";

// Machine-wide Run key. Writing here requires administrator rights, which is
// exactly what we want: only the installer running elevated may toggle the
// tray autostart, matching the trust boundary of the service itself.
constexpr const wchar_t* kRunKeyPath =
    L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
constexpr const wchar_t* kRunValueName = L"ShadowStrikePhantomTray";

// Bounded to keep corrupt/hostile environments from causing runaway string
// operations during install. Windows cannot launch from paths longer than
// this via the Run key anyway.
constexpr std::size_t kMaxAutostartPathChars = 32'767;

struct ScmHandle {
    SC_HANDLE h{nullptr};
    ~ScmHandle() { if (h) ::CloseServiceHandle(h); }
    operator SC_HANDLE() const noexcept { return h; }
};

[[nodiscard]] std::optional<std::wstring> QuoteServiceBinaryPath(std::wstring_view image_path) {
    if (image_path.empty()) {
        return std::nullopt;
    }
    if (image_path.find(L'"') != std::wstring_view::npos) {
        return std::nullopt;
    }

    std::wstring quoted;
    quoted.reserve(image_path.size() + 2);
    quoted.push_back(L'"');
    quoted.append(image_path);
    quoted.push_back(L'"');
    return quoted;
}

}  // namespace

[[nodiscard]] bool InstallService(const std::wstring& image_path) {
    const auto quoted_image_path = QuoteServiceBinaryPath(image_path);
    if (!quoted_image_path) {
        ShadowStrike::Utils::Logger::Error(
            "InstallService: refusing to register an invalid service image path");
        return false;
    }

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
                                   quoted_image_path->c_str(),
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

[[nodiscard]] bool InstallTrayAutostart(const std::wstring& tray_path) {
    if (tray_path.empty() || tray_path.size() > kMaxAutostartPathChars) {
        ShadowStrike::Utils::Logger::Error(
            "InstallTrayAutostart: tray_path has invalid length {}", tray_path.size());
        return false;
    }
    // Embedded NUL or existing quote characters indicate caller-supplied
    // garbage and must never be written to the registry.
    if (tray_path.find(L'\0') != std::wstring::npos ||
        tray_path.find(L'"')  != std::wstring::npos) {
        ShadowStrike::Utils::Logger::Error(
            "InstallTrayAutostart: refusing to register a path containing quotes or NULs");
        return false;
    }

    HKEY key{nullptr};
    const LSTATUS open_st = ::RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        kRunKeyPath,
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_WOW64_64KEY,
        nullptr,
        &key,
        nullptr);
    if (open_st != ERROR_SUCCESS || key == nullptr) {
        ShadowStrike::Utils::Logger::Error(
            "InstallTrayAutostart: RegCreateKeyExW failed status={}", open_st);
        return false;
    }

    // Always quote the path so explorer/cmd do not treat embedded spaces as
    // argument separators (the unquoted-service-path trick also applies to
    // Run entries when a future tray build accepts positional args).
    std::wstring quoted;
    quoted.reserve(tray_path.size() + 2);
    quoted.push_back(L'"');
    quoted.append(tray_path);
    quoted.push_back(L'"');

    const DWORD cb = static_cast<DWORD>((quoted.size() + 1) * sizeof(wchar_t));
    const LSTATUS set_st = ::RegSetValueExW(
        key,
        kRunValueName,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(quoted.c_str()),
        cb);
    ::RegCloseKey(key);

    if (set_st != ERROR_SUCCESS) {
        ShadowStrike::Utils::Logger::Error(
            "InstallTrayAutostart: RegSetValueExW failed status={}", set_st);
        return false;
    }
    ShadowStrike::Utils::Logger::Info("InstallTrayAutostart: tray autostart registered");
    return true;
}

[[nodiscard]] bool UninstallTrayAutostart() {
    HKEY key{nullptr};
    const LSTATUS open_st = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        kRunKeyPath,
        0,
        KEY_SET_VALUE | KEY_WOW64_64KEY,
        &key);
    if (open_st == ERROR_FILE_NOT_FOUND) {
        return true;  // never installed; idempotent success.
    }
    if (open_st != ERROR_SUCCESS || key == nullptr) {
        ShadowStrike::Utils::Logger::Error(
            "UninstallTrayAutostart: RegOpenKeyExW failed status={}", open_st);
        return false;
    }

    const LSTATUS del_st = ::RegDeleteValueW(key, kRunValueName);
    ::RegCloseKey(key);

    if (del_st != ERROR_SUCCESS && del_st != ERROR_FILE_NOT_FOUND) {
        ShadowStrike::Utils::Logger::Error(
            "UninstallTrayAutostart: RegDeleteValueW failed status={}", del_st);
        return false;
    }
    ShadowStrike::Utils::Logger::Info("UninstallTrayAutostart: tray autostart removed");
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
