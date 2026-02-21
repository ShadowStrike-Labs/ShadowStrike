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
 * ShadowStrike NGAV - SERVICE INSTALLATION MANAGER IMPLEMENTATION
 * ============================================================================
 *
 * @file ServiceInstaller.cpp
 * @brief Implementation of the ServiceInstaller class using Windows SCM APIs.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "ServiceInstaller.hpp"
#include "AntivirusService.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <vector>
#include <sstream>

namespace ShadowStrike {
namespace Service {

// ============================================================================
// PUBLIC API IMPLEMENTATION
// ============================================================================

bool ServiceInstaller::Install() {
    // Get current module path
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) == 0) {
        SS_LOG_ERROR(L"Installer", L"Failed to get module file name. Error: %lu", GetLastError());
        return false;
    }

    // Default configuration
    ServiceConfig config;
    config.name = ServiceConstants::SERVICE_NAME;
    config.displayName = ServiceConstants::DISPLAY_NAME;
    config.description = ServiceConstants::DESCRIPTION;
    config.binaryPath = std::wstring(L"\"") + modulePath + L"\"";
    config.startType = SERVICE_AUTO_START;
    config.delayedStart = true;
    config.enableRecovery = true;

    // Dependencies: RPC is required for almost everything, WMI for management
    config.dependencies = { L"RpcSs", L"Winmgmt" };

    return Install(config);
}

bool ServiceInstaller::Install(const ServiceConfig& config) {
    SS_LOG_INFO(L"Installer", L"Installing service: %ls", config.name.c_str());

    // Open Service Control Manager
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,                    // Local computer
        nullptr,                    // ServicesActive database
        SC_MANAGER_CREATE_SERVICE   // Access required
    );

    if (!hSCManager) {
        SS_LOG_ERROR(L"Installer", L"OpenSCManager failed. Error: %lu", GetLastError());
        return false;
    }

    // Ensure SCM handle is closed
    std::shared_ptr<void> scmGuard(hSCManager, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    // Format dependencies
    std::wstring dependencies = FormatDependencies(config.dependencies);

    // Create the service
    SC_HANDLE hService = CreateServiceW(
        hSCManager,                 // SCM database
        config.name.c_str(),        // Name of service
        config.displayName.c_str(), // Service name to display
        SERVICE_ALL_ACCESS,         // Desired access
        SERVICE_WIN32_OWN_PROCESS,  // Service type
        config.startType,           // Start type
        config.errorControl,        // Error control type
        config.binaryPath.c_str(),  // Path to service's binary
        nullptr,                    // No load ordering group
        nullptr,                    // No tag identifier
        dependencies.empty() ? nullptr : dependencies.c_str(), // Dependencies
        config.account.empty() ? nullptr : config.account.c_str(), // LocalSystem
        config.password.empty() ? nullptr : config.password.c_str() // Password
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            SS_LOG_WARN(L"Installer", L"Service already exists.");
            // We might want to update config here, but for now just return success?
            // Or fail? Generally Install should fail if already installed unless Reinstall is called.
            // Let's return false to indicate it wasn't created.
        } else {
            SS_LOG_ERROR(L"Installer", L"CreateService failed. Error: %lu", err);
        }
        return false;
    }

    // Ensure service handle is closed
    std::shared_ptr<void> serviceGuard(hService, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    bool success = true;

    // Configure description
    if (!config.description.empty()) {
        if (!ConfigureDescription(hService, config.description)) {
            SS_LOG_WARN(L"Installer", L"Failed to set service description.");
            success = false;
        }
    }

    // Configure delayed auto-start
    if (config.delayedStart && config.startType == SERVICE_AUTO_START) {
        if (!ConfigureDelayedAutoStart(hService, true)) {
            SS_LOG_WARN(L"Installer", L"Failed to set delayed auto-start.");
            success = false;
        }
    }

    // Configure recovery options
    if (config.enableRecovery) {
        if (!ConfigureRecovery(hService, config)) {
            SS_LOG_WARN(L"Installer", L"Failed to set recovery options.");
            success = false;
        }
    }

    if (success) {
        SS_LOG_INFO(L"Installer", L"Service installed successfully.");
    }

    return success;
}

bool ServiceInstaller::Uninstall() {
    SS_LOG_INFO(L"Installer", L"Uninstalling service: %ls", ServiceConstants::SERVICE_NAME);

    // Open Service Control Manager
    SC_HANDLE hSCManager = OpenSCManagerW(
        nullptr,
        nullptr,
        SC_MANAGER_CONNECT
    );

    if (!hSCManager) {
        SS_LOG_ERROR(L"Installer", L"OpenSCManager failed. Error: %lu", GetLastError());
        return false;
    }

    std::shared_ptr<void> scmGuard(hSCManager, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    // Open Service
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        ServiceConstants::SERVICE_NAME,
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS
    );

    if (!hService) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) {
            SS_LOG_WARN(L"Installer", L"Service not found.");
            return true; // Consider success if it's already gone
        }
        SS_LOG_ERROR(L"Installer", L"OpenService failed. Error: %lu", err);
        return false;
    }

    std::shared_ptr<void> serviceGuard(hService, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    // Stop service if running
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytesNeeded)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            SS_LOG_INFO(L"Installer", L"Stopping service before deletion...");
            SERVICE_STATUS status;
            ControlService(hService, SERVICE_CONTROL_STOP, &status);
            // Give it some time to stop
            Sleep(1000);
        }
    }

    // Delete service
    if (!DeleteService(hService)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_MARKED_FOR_DELETE) {
            SS_LOG_WARN(L"Installer", L"Service already marked for deletion.");
            return true;
        }
        SS_LOG_ERROR(L"Installer", L"DeleteService failed. Error: %lu", err);
        return false;
    }

    SS_LOG_INFO(L"Installer", L"Service uninstalled successfully.");
    return true;
}

bool ServiceInstaller::Reinstall() {
    if (IsInstalled()) {
        if (!Uninstall()) return false;
        // Wait for SCM to process deletion
        Sleep(1000);
    }
    return Install();
}

bool ServiceInstaller::IsInstalled() {
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager) return false;

    std::shared_ptr<void> scmGuard(hSCManager, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        ServiceConstants::SERVICE_NAME,
        SERVICE_QUERY_STATUS
    );

    if (hService) {
        CloseServiceHandle(hService);
        return true;
    }

    return false;
}

bool ServiceInstaller::Start() {
    SS_LOG_INFO(L"Installer", L"Starting service...");

    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager) return false;
    std::shared_ptr<void> scmGuard(hSCManager, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        ServiceConstants::SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS
    );

    if (!hService) {
        SS_LOG_ERROR(L"Installer", L"Failed to open service for starting.");
        return false;
    }
    std::shared_ptr<void> serviceGuard(hService, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    if (!StartServiceW(hService, 0, nullptr)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            return true;
        }
        SS_LOG_ERROR(L"Installer", L"StartService failed. Error: %lu", err);
        return false;
    }

    SS_LOG_INFO(L"Installer", L"Service start request sent.");
    return true;
}

bool ServiceInstaller::Stop() {
    SS_LOG_INFO(L"Installer", L"Stopping service...");

    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCManager) return false;
    std::shared_ptr<void> scmGuard(hSCManager, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        ServiceConstants::SERVICE_NAME,
        SERVICE_STOP | SERVICE_QUERY_STATUS
    );

    if (!hService) {
        SS_LOG_ERROR(L"Installer", L"Failed to open service for stopping.");
        return false;
    }
    std::shared_ptr<void> serviceGuard(hService, [](void* h) { CloseServiceHandle((SC_HANDLE)h); });

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) {
            return true;
        }
        SS_LOG_ERROR(L"Installer", L"ControlService(STOP) failed. Error: %lu", err);
        return false;
    }

    SS_LOG_INFO(L"Installer", L"Service stop request sent.");
    return true;
}

// ============================================================================
// INTERNAL HELPERS IMPLEMENTATION
// ============================================================================

bool ServiceInstaller::ConfigureRecovery(SC_HANDLE hService, const ServiceConfig& config) {
    SERVICE_FAILURE_ACTIONS_FLAG flag;
    flag.fFailureActionsOnNonCrashFailures = TRUE;

    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &flag)) {
        SS_LOG_WARN(L"Installer", L"Failed to set failure flag. Error: %lu", GetLastError());
        // Continue anyway
    }

    // Configure restart actions
    std::vector<SC_ACTION> actions;
    // 1st failure: Restart service
    actions.push_back({ SC_ACTION_RESTART, config.restartDelayMs });
    // 2nd failure: Restart service
    actions.push_back({ SC_ACTION_RESTART, config.restartDelayMs });
    // 3rd failure: Restart service (persistent)
    actions.push_back({ SC_ACTION_RESTART, config.restartDelayMs });

    SERVICE_FAILURE_ACTIONSW sfa;
    ZeroMemory(&sfa, sizeof(sfa));
    sfa.dwResetPeriod = config.resetPeriodDays * 86400; // Convert days to seconds
    sfa.lpRebootMsg = nullptr;
    sfa.lpCommand = nullptr;
    sfa.cActions = static_cast<DWORD>(actions.size());
    sfa.lpsaActions = actions.data();

    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa)) {
        SS_LOG_ERROR(L"Installer", L"Failed to set failure actions. Error: %lu", GetLastError());
        return false;
    }

    return true;
}

bool ServiceInstaller::ConfigureDescription(SC_HANDLE hService, const std::wstring& description) {
    SERVICE_DESCRIPTIONW sd;
    sd.lpDescription = const_cast<LPWSTR>(description.c_str());

    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd)) {
        return false;
    }
    return true;
}

bool ServiceInstaller::ConfigureDelayedAutoStart(SC_HANDLE hService, bool delayed) {
    SERVICE_DELAYED_AUTO_START_INFO info;
    info.fDelayedAutostart = delayed ? TRUE : FALSE;

    if (!ChangeServiceConfig2W(hService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &info)) {
        return false;
    }
    return true;
}

std::wstring ServiceInstaller::FormatDependencies(const std::vector<std::wstring>& deps) {
    if (deps.empty()) return L"";

    std::wstring result;
    for (const auto& dep : deps) {
        result += dep;
        result.push_back(L'\0');
    }
    result.push_back(L'\0'); // Double null terminator

    return result;
}

} // namespace Service
} // namespace ShadowStrike
