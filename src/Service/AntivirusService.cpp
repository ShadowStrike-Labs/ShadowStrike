/**
 * ============================================================================
 * ShadowStrike NGAV - MAIN SERVICE IMPLEMENTATION
 * ============================================================================
 *
 * @file AntivirusService.cpp
 * @brief Enterprise-grade Windows Service implementation.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "AntivirusService.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../Utils/Logger.hpp"
#include "../Utils/ThreadPool.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/FileUtils.hpp"

// ============================================================================
// SECURITY MODULE INCLUDES
// ============================================================================
#include "../Security/TamperProtection.hpp"
#include "../Security/CertificateValidator.hpp"
#include "../Scripts/AMSIIntegration.hpp"
#include "../RealTime/RealTimeProtection.hpp"
#include "../Communication/IPCManager.hpp"
#include "../Update/UpdateManager.hpp"
#include "../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// WINDOWS SDK
// ============================================================================
#include <tchar.h>
#include <strsafe.h>
#include <sddl.h>

namespace ShadowStrike {
namespace Service {

// ============================================================================
// LOGGING CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"Service";

// ============================================================================
// STATIC INITIALIZATION
// ============================================================================
std::atomic<bool> AntivirusService::s_instanceCreated{false};

// ============================================================================
// SERVICE IMPLEMENTATION (PIMPL)
// ============================================================================

class AntivirusServiceImpl final {
public:
    AntivirusServiceImpl() = default;
    ~AntivirusServiceImpl() { Stop(); }

    // Non-copyable
    AntivirusServiceImpl(const AntivirusServiceImpl&) = delete;
    AntivirusServiceImpl& operator=(const AntivirusServiceImpl&) = delete;

    [[nodiscard]] bool Initialize() {
        std::unique_lock lock(m_mutex);

        if (m_initialized) return true;

        try {
            // 1. Initialize Logging
            // In a real scenario, we'd read config to determine log level/path
            Utils::Logger::Instance().Initialize(L"ShadowStrikeService");
            SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service initializing...");

            // 2. Initialize Infrastructure
            if (!Utils::ThreadPool::Instance().Initialize(4, 8)) {
                SS_LOG_CRITICAL(LOG_CATEGORY, L"Failed to initialize ThreadPool");
                return false;
            }

            // 3. Initialize Security Subsystems
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing security subsystems...");

            // Threat Intel (Database)
            if (!ThreatIntel::ThreatIntelManager::Instance().Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize ThreatIntelManager");
                // Continue? Depending on policy. Critical failure usually.
                return false;
            }

            // Tamper Protection (Critical - protect self first)
            Security::TamperProtectionConfiguration tamperConfig;
            tamperConfig.mode = Security::TamperProtectionMode::Enforce;
            if (!Security::TamperProtection::Instance().Initialize(tamperConfig)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize TamperProtection");
                return false;
            }
            Security::TamperProtection::Instance().ProtectSelf();

            // Real-Time Protection
            if (!RealTime::RealTimeProtection::Instance().Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize RealTimeProtection");
                return false;
            }

            // AMSI Integration
            if (!Scripts::AMSIIntegration::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize AMSIIntegration");
                // Warning only, service can run without AMSI
            }

            // Certificate Validator
            Security::CertificateValidatorConfiguration certConfig;
            if (!Security::CertificateValidator::Instance().Initialize(certConfig)) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize CertificateValidator");
            }

            // 4. Initialize Communication
            if (!Communication::IPCManager::Instance().Initialize()) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Failed to initialize IPCManager");
                return false;
            }

            // 5. Initialize Update Manager
            if (!Update::UpdateManager::Instance().Initialize()) {
                SS_LOG_WARN(LOG_CATEGORY, L"Failed to initialize UpdateManager");
            }

            m_initialized = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Service initialization complete");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_CRITICAL(LOG_CATEGORY, L"Exception during initialization: %hs", e.what());
            return false;
        } catch (...) {
            SS_LOG_CRITICAL(LOG_CATEGORY, L"Unknown exception during initialization");
            return false;
        }
    }

    void Start() {
        std::unique_lock lock(m_mutex);
        if (!m_initialized || m_running) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Starting services...");

        // Start Subsystems
        Security::TamperProtection::Instance().SetEnabled(true);
        RealTime::RealTimeProtection::Instance().Start();
        Communication::IPCManager::Instance().StartListening();

        // Register AMSI provider
        Scripts::AMSIIntegration::Instance().RegisterProvider();

        m_running = true;
        SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service is RUNNING");
    }

    void Stop() {
        std::unique_lock lock(m_mutex);
        if (!m_running) return;

        SS_LOG_INFO(LOG_CATEGORY, L"Stopping services...");

        // Shutdown in reverse order
        Communication::IPCManager::Instance().StopListening();

        Scripts::AMSIIntegration::Instance().UnregisterProvider();
        Scripts::AMSIIntegration::Instance().Shutdown();

        RealTime::RealTimeProtection::Instance().Stop();
        RealTime::RealTimeProtection::Instance().Shutdown();

        Security::TamperProtection::Instance().Shutdown("INTERNAL_SHUTDOWN");

        ThreatIntel::ThreatIntelManager::Instance().Shutdown();

        Utils::ThreadPool::Instance().Shutdown();

        m_running = false;
        m_initialized = false;
        SS_LOG_INFO(LOG_CATEGORY, L"ShadowStrike NGAV Service STOPPED");
    }

    void Pause() {
        SS_LOG_INFO(LOG_CATEGORY, L"Pausing protection...");
        RealTime::RealTimeProtection::Instance().Pause();
        // We generally don't stop IPC during pause to allow admin commands
    }

    void Continue() {
        SS_LOG_INFO(LOG_CATEGORY, L"Resuming protection...");
        RealTime::RealTimeProtection::Instance().Resume();
    }

    [[nodiscard]] std::string GetStatusReport() const {
        // Collect status from all modules
        // In reality, use JSON library
        return "{\"status\": \"running\"}";
    }

    // Service Installation Helpers
    [[nodiscard]] bool InstallService() {
        SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!hSCManager) {
            SS_LOG_ERROR(LOG_CATEGORY, L"OpenSCManager failed: %u", GetLastError());
            return false;
        }

        // Get executable path
        TCHAR szPath[MAX_PATH];
        if (!GetModuleFileName(nullptr, szPath, MAX_PATH)) {
            CloseServiceHandle(hSCManager);
            return false;
        }

        // Quote path for security
        std::wstring binaryPath = L"\"";
        binaryPath += szPath;
        binaryPath += L"\"";

        SC_HANDLE hService = CreateService(
            hSCManager,
            ServiceConstants::SERVICE_NAME,
            ServiceConstants::DISPLAY_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            binaryPath.c_str(),
            nullptr,
            nullptr,
            ServiceConstants::DEPENDENCIES,
            nullptr, // LocalSystem
            nullptr
        );

        if (!hService) {
            SS_LOG_ERROR(LOG_CATEGORY, L"CreateService failed: %u", GetLastError());
            CloseServiceHandle(hSCManager);
            return false;
        }

        // Set description
        SERVICE_DESCRIPTION sd;
        sd.lpDescription = const_cast<LPWSTR>(ServiceConstants::DESCRIPTION);
        ChangeServiceConfig2(hService, SERVICE_CONFIG_DESCRIPTION, &sd);

        // Set recovery options
        SERVICE_FAILURE_ACTIONS sfa;
        SC_ACTION actions[3];
        actions[0].Type = SC_ACTION_RESTART;
        actions[0].Delay = 60000; // 1 min
        actions[1].Type = SC_ACTION_RESTART;
        actions[1].Delay = 60000;
        actions[2].Type = SC_ACTION_NONE;
        actions[2].Delay = 0;

        sfa.dwResetPeriod = 86400; // 1 day
        sfa.lpRebootMsg = nullptr;
        sfa.lpCommand = nullptr;
        sfa.cActions = 3;
        sfa.lpsaActions = actions;

        ChangeServiceConfig2(hService, SERVICE_CONFIG_FAILURE_ACTIONS, &sfa);

        SS_LOG_INFO(LOG_CATEGORY, L"Service installed successfully");

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

    [[nodiscard]] bool UninstallService() {
        SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!hSCManager) return false;

        SC_HANDLE hService = OpenService(hSCManager, ServiceConstants::SERVICE_NAME, DELETE);
        if (!hService) {
            CloseServiceHandle(hSCManager);
            return false;
        }

        if (!DeleteService(hService)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"DeleteService failed: %u", GetLastError());
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Service uninstalled successfully");

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return true;
    }

private:
    std::recursive_mutex m_mutex;
    bool m_initialized = false;
    bool m_running = false;
};

// ============================================================================
// PUBLIC INTERFACE IMPLEMENTATION
// ============================================================================

AntivirusService& AntivirusService::Instance() noexcept {
    static AntivirusService instance;
    return instance;
}

AntivirusService::AntivirusService()
    : m_impl(std::make_unique<AntivirusServiceImpl>()) {
    s_instanceCreated.store(true);
}

AntivirusService::~AntivirusService() = default;

// ============================================================================
// SCM ENTRY POINTS
// ============================================================================

void WINAPI AntivirusService::ServiceMain(DWORD argc, LPTSTR* argv) {
    Instance().OnStart(argc, argv);
}

DWORD WINAPI AntivirusService::ServiceCtrlHandler(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context) {
    auto& service = Instance();

    switch (control) {
        case SERVICE_CONTROL_STOP:
            service.OnStop();
            return NO_ERROR;
        case SERVICE_CONTROL_PAUSE:
            service.OnPause();
            return NO_ERROR;
        case SERVICE_CONTROL_CONTINUE:
            service.OnContinue();
            return NO_ERROR;
        case SERVICE_CONTROL_SHUTDOWN:
            service.OnShutdown();
            return NO_ERROR;
        case SERVICE_CONTROL_SESSIONCHANGE:
            service.OnSessionChange(eventType, static_cast<WTSSESSION_NOTIFICATION*>(eventData));
            return NO_ERROR;
        case SERVICE_CONTROL_POWEREVENT:
            service.OnPowerEvent(eventType, static_cast<POWERBROADCAST_SETTING*>(eventData));
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

// ============================================================================
// SERVICE LOGIC
// ============================================================================

bool AntivirusService::Run() {
    SERVICE_TABLE_ENTRY dispatchTable[] = {
        { const_cast<LPWSTR>(ServiceConstants::SERVICE_NAME), static_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain) },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcher(dispatchTable)) {
        // If it failed, it might be running as a console app for debug
        if (GetLastError() == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Debug mode
            SS_LOG_INFO(LOG_CATEGORY, L"Running in console mode...");
            if (m_impl->Initialize()) {
                m_impl->Start();

                SS_LOG_INFO(LOG_CATEGORY, L"Press Enter to stop...");
                getchar();

                m_impl->Stop();
                return true;
            }
        }
        return false;
    }
    return true;
}

bool AntivirusService::Install() {
    return m_impl->InstallService();
}

bool AntivirusService::Uninstall() {
    return m_impl->UninstallService();
}

void AntivirusService::OnStart(DWORD argc, LPTSTR* argv) {
    m_statusHandle = RegisterServiceCtrlHandlerEx(
        ServiceConstants::SERVICE_NAME,
        ServiceCtrlHandler,
        nullptr
    );

    if (!m_statusHandle) return;

    SetServiceStatus(SERVICE_START_PENDING, NO_ERROR, 3000);

    // Initialize subsystems
    if (!m_impl->Initialize()) {
        SetServiceStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR);
        return;
    }

    // Start services
    m_impl->Start();

    SetServiceStatus(SERVICE_RUNNING);
}

void AntivirusService::OnStop() {
    SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 5000);
    m_impl->Stop();
    SetServiceStatus(SERVICE_STOPPED);
}

void AntivirusService::OnPause() {
    SetServiceStatus(SERVICE_PAUSE_PENDING, NO_ERROR, 1000);
    m_impl->Pause();
    SetServiceStatus(SERVICE_PAUSED);
}

void AntivirusService::OnContinue() {
    SetServiceStatus(SERVICE_CONTINUE_PENDING, NO_ERROR, 1000);
    m_impl->Continue();
    SetServiceStatus(SERVICE_RUNNING);
}

void AntivirusService::OnShutdown() {
    SetServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, ServiceConstants::SHUTDOWN_TIMEOUT_MS);
    m_impl->Stop();
    SetServiceStatus(SERVICE_STOPPED);
}

void AntivirusService::OnSessionChange(DWORD eventType, WTSSESSION_NOTIFICATION* notification) {
    if (!notification) return;

    // Notify IPC manager or other components about session changes
    // This is important for GUI interactions (Tray Icon)
    // Communication::IPCManager::Instance().BroadcastSessionChange(...)
}

void AntivirusService::OnPowerEvent(DWORD eventType, POWERBROADCAST_SETTING* setting) {
    // Handle power events (e.g. disable heavy scans on battery)
}

void AntivirusService::SetServiceStatus(DWORD currentState, DWORD win32ExitCode, DWORD waitHint) {
    static DWORD checkPoint = 1;

    m_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_serviceStatus.dwCurrentState = currentState;
    m_serviceStatus.dwWin32ExitCode = win32ExitCode;
    m_serviceStatus.dwWaitHint = waitHint;

    if (currentState == SERVICE_START_PENDING ||
        currentState == SERVICE_STOP_PENDING ||
        currentState == SERVICE_PAUSE_PENDING ||
        currentState == SERVICE_CONTINUE_PENDING) {
        m_serviceStatus.dwControlsAccepted = 0;
        m_serviceStatus.dwCheckPoint = checkPoint++;
    } else {
        m_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP |
                                           SERVICE_ACCEPT_SHUTDOWN |
                                           SERVICE_ACCEPT_PAUSE_CONTINUE |
                                           SERVICE_ACCEPT_SESSIONCHANGE |
                                           SERVICE_ACCEPT_POWEREVENT;
        m_serviceStatus.dwCheckPoint = 0;
    }

    if (currentState == SERVICE_RUNNING || currentState == SERVICE_STOPPED) {
        m_serviceStatus.dwCheckPoint = 0;
    }

    ::SetServiceStatus(m_statusHandle, &m_serviceStatus);
}

std::string AntivirusService::GetStatusReport() const {
    return m_impl->GetStatusReport();
}

bool AntivirusService::IsHealthy() const noexcept {
    // In a real impl, check all subsystems
    return true;
}

} // namespace Service
} // namespace ShadowStrike
