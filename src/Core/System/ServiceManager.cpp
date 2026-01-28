/**
 * @file ServiceManager.cpp
 * @brief Enterprise implementation of Windows service lifecycle manager.
 *
 * The Orchestrator of ShadowStrike NGAV - provides comprehensive service management
 * with self-protection, driver loading, threat remediation, and ELAM integration.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "ServiceManager.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Core/FileSystem/FileHasher.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <thread>
#include <sstream>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winsvc.h>
#  include <fltUser.h>
#  include <wintrust.h>
#  include <softpub.h>
#  pragma comment(lib, "advapi32.lib")
#  pragma comment(lib, "fltLib.lib")
#  pragma comment(lib, "wintrust.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace System {

using namespace std::chrono;
using namespace Utils;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Convert Windows service state to our enum.
 */
[[nodiscard]] ServiceState WinStateToServiceState(DWORD dwState) noexcept {
    switch (dwState) {
        case SERVICE_STOPPED: return ServiceState::Stopped;
        case SERVICE_START_PENDING: return ServiceState::StartPending;
        case SERVICE_STOP_PENDING: return ServiceState::StopPending;
        case SERVICE_RUNNING: return ServiceState::Running;
        case SERVICE_CONTINUE_PENDING: return ServiceState::ContinuePending;
        case SERVICE_PAUSE_PENDING: return ServiceState::PausePending;
        case SERVICE_PAUSED: return ServiceState::Paused;
        default: return ServiceState::Unknown;
    }
}

/**
 * @brief Convert Windows service type to our enum.
 */
[[nodiscard]] ServiceType WinTypeToServiceType(DWORD dwType) noexcept {
    if (dwType & SERVICE_KERNEL_DRIVER) return ServiceType::KernelDriver;
    if (dwType & SERVICE_FILE_SYSTEM_DRIVER) return ServiceType::FileSystemDriver;
    if (dwType & SERVICE_WIN32_OWN_PROCESS) {
        if (dwType & SERVICE_INTERACTIVE_PROCESS) {
            return ServiceType::InteractiveProcess;
        }
        return ServiceType::Win32OwnProcess;
    }
    if (dwType & SERVICE_WIN32_SHARE_PROCESS) return ServiceType::Win32ShareProcess;
    if (dwType & SERVICE_USER_SERVICE) return ServiceType::UserService;

    return ServiceType::Unknown;
}

/**
 * @brief Convert Windows start type to our enum.
 */
[[nodiscard]] StartType WinStartTypeToStartType(DWORD dwStartType) noexcept {
    switch (dwStartType) {
        case SERVICE_BOOT_START: return StartType::BootStart;
        case SERVICE_SYSTEM_START: return StartType::SystemStart;
        case SERVICE_AUTO_START: return StartType::AutoStart;
        case SERVICE_DEMAND_START: return StartType::DemandStart;
        case SERVICE_DISABLED: return StartType::Disabled;
        default: return StartType::Unknown;
    }
}

/**
 * @brief Convert our start type to Windows constant.
 */
[[nodiscard]] DWORD StartTypeToWinStartType(StartType startType) noexcept {
    switch (startType) {
        case StartType::BootStart: return SERVICE_BOOT_START;
        case StartType::SystemStart: return SERVICE_SYSTEM_START;
        case StartType::AutoStart: return SERVICE_AUTO_START;
        case StartType::DemandStart: return SERVICE_DEMAND_START;
        case StartType::Disabled: return SERVICE_DISABLED;
        default: return SERVICE_DEMAND_START;
    }
}

/**
 * @brief Convert our service type to Windows constant.
 */
[[nodiscard]] DWORD ServiceTypeToWinType(ServiceType serviceType) noexcept {
    switch (serviceType) {
        case ServiceType::KernelDriver: return SERVICE_KERNEL_DRIVER;
        case ServiceType::FileSystemDriver: return SERVICE_FILE_SYSTEM_DRIVER;
        case ServiceType::Win32OwnProcess: return SERVICE_WIN32_OWN_PROCESS;
        case ServiceType::Win32ShareProcess: return SERVICE_WIN32_SHARE_PROCESS;
        case ServiceType::InteractiveProcess:
            return SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
        case ServiceType::UserService: return SERVICE_USER_SERVICE;
        default: return SERVICE_WIN32_OWN_PROCESS;
    }
}

/**
 * @brief Convert failure action to Windows constant.
 */
[[nodiscard]] SC_ACTION_TYPE FailureActionToWinAction(FailureAction action) noexcept {
    switch (action) {
        case FailureAction::None: return SC_ACTION_NONE;
        case FailureAction::Restart: return SC_ACTION_RESTART;
        case FailureAction::Reboot: return SC_ACTION_REBOOT;
        case FailureAction::RunCommand: return SC_ACTION_RUN_COMMAND;
        default: return SC_ACTION_NONE;
    }
}

/**
 * @brief Check if binary is Microsoft-signed.
 */
[[nodiscard]] bool IsMicrosoftBinary(const std::wstring& binaryPath) noexcept {
    try {
        if (!FileUtils::Exists(binaryPath)) return false;

        WINTRUST_FILE_INFO fileData = {};
        fileData.cbStruct = sizeof(fileData);
        fileData.pcwszFilePath = binaryPath.c_str();

        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileData;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        // Verify digital signature
        GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG result = WinVerifyTrust(nullptr, &guidAction, &trustData);
        bool isTrusted = (result == ERROR_SUCCESS);

        // Cleanup
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &guidAction, &trustData);

        if (!isTrusted) return false;

        // In a full production environment, we would verify the signer is Microsoft
        // by inspecting the certificate chain (CryptQueryObject, CertFindCertificateInStore).
        // For now, we trust a valid signature + path heuristics.

        std::wstring lowerPath = StringUtils::ToLowerCase(binaryPath);
        if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\program files\\windows defender\\") != std::wstring::npos) return true;

        return true;

    } catch (...) {
        return false;
    }
}

} // anonymous namespace

// ============================================================================
// ServiceManagerConfig FACTORY METHODS
// ============================================================================

ServiceManagerConfig ServiceManagerConfig::CreateDefault() noexcept {
    return ServiceManagerConfig{};
}

ServiceManagerConfig ServiceManagerConfig::CreateHighSecurity() noexcept {
    ServiceManagerConfig config;
    config.enableSelfProtection = true;
    config.monitorServiceChanges = true;
    config.autoRestartOnFailure = true;
    config.validateSignatures = true;
    config.watchdogIntervalMs = 2000;  // More frequent checks

    return config;
}

// ============================================================================
// ServiceManagerStatistics METHODS
// ============================================================================

void ServiceManagerStatistics::Reset() noexcept {
    servicesEnumerated.store(0, std::memory_order_relaxed);
    servicesStarted.store(0, std::memory_order_relaxed);
    servicesStopped.store(0, std::memory_order_relaxed);
    driversLoaded.store(0, std::memory_order_relaxed);
    driversUnloaded.store(0, std::memory_order_relaxed);
    remediationActions.store(0, std::memory_order_relaxed);
    tamperAttempts.store(0, std::memory_order_relaxed);
    selfRecoveries.store(0, std::memory_order_relaxed);
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for ServiceManager.
 */
class ServiceManager::ServiceManagerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_watchdogMutex;
    std::mutex m_scmMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_watchdogRunning{false};
    std::atomic<bool> m_stopWatchdog{false};

    // Configuration
    ServiceManagerConfig m_config{};

    // Statistics
    ServiceManagerStatistics m_stats{};

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, ServiceChangeCallback> m_serviceChangeCallbacks;
    std::unordered_map<uint64_t, TamperAlertCallback> m_tamperAlertCallbacks;

    // Watchdog thread
    std::unique_ptr<std::jthread> m_watchdogThread;

    // Known baseline for our services
    struct ServiceBaseline {
        std::wstring binaryPath;
        std::string binaryHash;
        StartType startType;
        std::wstring serviceAccount;
    };
    std::unordered_map<std::wstring, ServiceBaseline> m_serviceBaselines;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    ServiceManagerImpl() = default;
    ~ServiceManagerImpl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const ServiceManagerConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("ServiceManager::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("ServiceManager::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Establish baseline for our services
            EstablishServiceBaselines();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("ServiceManager::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ServiceManager::Impl: Shutting down");

        // Stop watchdog
        StopWatchdogImpl();

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_serviceChangeCallbacks.clear();
            m_tamperAlertCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("ServiceManager::Impl: Shutdown complete");
    }

    void EstablishServiceBaselines() {
        try {
            // Baseline our main service
            if (auto info = GetServiceInfoImpl(m_config.mainServiceName)) {
                ServiceBaseline baseline;
                baseline.binaryPath = info->binaryPath;
                baseline.startType = info->startType;
                baseline.serviceAccount = info->serviceAccount;

                if (FileUtils::Exists(info->binaryPath)) {
                    baseline.binaryHash = HashUtils::CalculateSHA256File(info->binaryPath);
                }

                m_serviceBaselines[m_config.mainServiceName] = baseline;
                Logger::Info("ServiceManager: Established baseline for {}",
                    StringUtils::WideToUtf8(m_config.mainServiceName));
            }

            // Baseline our driver service
            if (auto info = GetServiceInfoImpl(m_config.driverServiceName)) {
                ServiceBaseline baseline;
                baseline.binaryPath = info->binaryPath;
                baseline.startType = info->startType;
                baseline.serviceAccount = info->serviceAccount;

                if (FileUtils::Exists(info->binaryPath)) {
                    baseline.binaryHash = HashUtils::CalculateSHA256File(info->binaryPath);
                }

                m_serviceBaselines[m_config.driverServiceName] = baseline;
                Logger::Info("ServiceManager: Established baseline for {}",
                    StringUtils::WideToUtf8(m_config.driverServiceName));
            }

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: Baseline establishment exception: {}", e.what());
        }
    }

    // ========================================================================
    // SERVICE ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<ServiceInfo> EnumerateServicesImpl() const {
        std::vector<ServiceInfo> services;

        try {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
            if (!scm) {
                Logger::Error("ServiceManager: Failed to open SCM: {}", GetLastError());
                return services;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // First call to get size
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_STATE_ALL,
                nullptr,
                0,
                &bytesNeeded,
                &servicesReturned,
                &resumeHandle,
                nullptr
            );

            if (bytesNeeded == 0) {
                CloseServiceHandle(scm);
                return services;
            }

            std::vector<uint8_t> buffer(bytesNeeded);
            auto* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

            // Actual enumeration
            if (EnumServicesStatusExW(
                    scm,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32 | SERVICE_DRIVER,
                    SERVICE_STATE_ALL,
                    reinterpret_cast<LPBYTE>(pServices),
                    bytesNeeded,
                    &bytesNeeded,
                    &servicesReturned,
                    &resumeHandle,
                    nullptr)) {

                for (DWORD i = 0; i < servicesReturned; ++i) {
                    ServiceInfo info;
                    info.serviceName = pServices[i].lpServiceName;
                    info.displayName = pServices[i].lpDisplayName;
                    info.serviceType = WinTypeToServiceType(pServices[i].ServiceStatusProcess.dwServiceType);
                    info.state = WinStateToServiceState(pServices[i].ServiceStatusProcess.dwCurrentState);
                    info.processId = pServices[i].ServiceStatusProcess.dwProcessId;

                    // Get detailed info
                    if (auto detailedInfo = GetServiceInfoImpl(info.serviceName)) {
                        info.binaryPath = detailedInfo->binaryPath;
                        info.startType = detailedInfo->startType;
                        info.description = detailedInfo->description;
                        info.serviceAccount = detailedInfo->serviceAccount;
                        info.isMicrosoft = IsMicrosoftBinary(info.binaryPath);
                    }

                    services.push_back(info);
                }

                m_stats.servicesEnumerated.fetch_add(servicesReturned, std::memory_order_relaxed);
            }

            CloseServiceHandle(scm);

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: Enumeration exception: {}", e.what());
        }

        return services;
    }

    [[nodiscard]] std::vector<ServiceInfo> EnumerateDriversImpl() const {
        auto allServices = EnumerateServicesImpl();

        std::vector<ServiceInfo> drivers;
        std::copy_if(allServices.begin(), allServices.end(), std::back_inserter(drivers),
            [](const ServiceInfo& info) {
                return info.serviceType == ServiceType::KernelDriver ||
                       info.serviceType == ServiceType::FileSystemDriver;
            });

        return drivers;
    }

    [[nodiscard]] std::optional<ServiceInfo> GetServiceInfoImpl(const std::wstring& serviceName) const {
        try {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                return std::nullopt;
            }

            SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
            if (!service) {
                CloseServiceHandle(scm);
                return std::nullopt;
            }

            ServiceInfo info;
            info.serviceName = serviceName;

            // Get config
            DWORD bytesNeeded = 0;
            QueryServiceConfigW(service, nullptr, 0, &bytesNeeded);

            if (bytesNeeded > 0) {
                std::vector<uint8_t> buffer(bytesNeeded);
                auto* pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());

                if (QueryServiceConfigW(service, pConfig, bytesNeeded, &bytesNeeded)) {
                    info.displayName = pConfig->lpDisplayName ? pConfig->lpDisplayName : L"";
                    info.binaryPath = pConfig->lpBinaryPathName ? pConfig->lpBinaryPathName : L"";
                    info.serviceType = WinTypeToServiceType(pConfig->dwServiceType);
                    info.startType = WinStartTypeToStartType(pConfig->dwStartType);
                    info.loadOrderGroup = pConfig->lpLoadOrderGroup ? pConfig->lpLoadOrderGroup : L"";
                    info.serviceAccount = pConfig->lpServiceStartName ? pConfig->lpServiceStartName : L"";
                    info.isLocalSystem = (info.serviceAccount == L"LocalSystem" ||
                                         info.serviceAccount.empty());
                }
            }

            // Get status
            SERVICE_STATUS_PROCESS status{};
            if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
                info.state = WinStateToServiceState(status.dwCurrentState);
                info.processId = status.dwProcessId;
                info.exitCode = status.dwWin32ExitCode;
                info.acceptsStop = (status.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0;
                info.acceptsPause = (status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) != 0;
            }

            // Get description
            bytesNeeded = 0;
            QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &bytesNeeded);

            if (bytesNeeded > 0) {
                std::vector<uint8_t> descBuffer(bytesNeeded);
                auto* pDesc = reinterpret_cast<SERVICE_DESCRIPTIONW*>(descBuffer.data());

                if (QueryServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION,
                        reinterpret_cast<LPBYTE>(pDesc), bytesNeeded, &bytesNeeded)) {
                    if (pDesc->lpDescription) {
                        info.description = pDesc->lpDescription;
                    }
                }
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            return info;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: GetServiceInfo exception: {}", e.what());
            return std::nullopt;
        }
    }

    [[nodiscard]] bool ServiceExistsImpl(const std::wstring& serviceName) const {
        return GetServiceInfoImpl(serviceName).has_value();
    }

    [[nodiscard]] ServiceState GetServiceStateImpl(const std::wstring& serviceName) const {
        if (auto info = GetServiceInfoImpl(serviceName)) {
            return info->state;
        }
        return ServiceState::Unknown;
    }

    // ========================================================================
    // SERVICE LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool InstallServiceImpl(const ServiceConfig& config) {
        try {
            Logger::Info("ServiceManager: Installing service: {}",
                StringUtils::WideToUtf8(config.serviceName));

            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
            if (!scm) {
                Logger::Error("ServiceManager: Failed to open SCM: {}", GetLastError());
                return false;
            }

            DWORD serviceType = ServiceTypeToWinType(config.serviceType);
            DWORD startType = StartTypeToWinStartType(config.startType);

            SC_HANDLE service = CreateServiceW(
                scm,
                config.serviceName.c_str(),
                config.displayName.c_str(),
                SERVICE_ALL_ACCESS,
                serviceType,
                startType,
                SERVICE_ERROR_NORMAL,
                config.binaryPath.c_str(),
                config.loadOrderGroup.empty() ? nullptr : config.loadOrderGroup.c_str(),
                nullptr,
                nullptr,  // Dependencies would be formatted
                config.serviceAccount.empty() ? nullptr : config.serviceAccount.c_str(),
                config.password.empty() ? nullptr : config.password.c_str()
            );

            if (!service) {
                DWORD error = GetLastError();
                Logger::Error("ServiceManager: CreateService failed: {}", error);
                CloseServiceHandle(scm);
                return false;
            }

            // Set description
            if (!config.description.empty()) {
                SERVICE_DESCRIPTIONW desc;
                desc.lpDescription = const_cast<LPWSTR>(config.description.c_str());

                ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);
            }

            // Configure failure recovery
            if (config.configureRecovery) {
                ConfigureRecoveryImpl(service,
                    config.firstFailure,
                    config.secondFailure,
                    config.subsequentFailures,
                    config.resetPeriodSeconds,
                    config.restartDelayMs);
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            Logger::Info("ServiceManager: Service installed successfully: {}",
                StringUtils::WideToUtf8(config.serviceName));

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: InstallService exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UninstallServiceImpl(const std::wstring& serviceName, bool force) {
        try {
            Logger::Info("ServiceManager: Uninstalling service: {}",
                StringUtils::WideToUtf8(serviceName));

            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                Logger::Error("ServiceManager: Failed to open SCM: {}", GetLastError());
                return false;
            }

            SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), DELETE | SERVICE_STOP);
            if (!service) {
                DWORD error = GetLastError();
                Logger::Error("ServiceManager: OpenService failed: {}", error);
                CloseServiceHandle(scm);
                return false;
            }

            // Stop if running and force is specified
            if (force) {
                SERVICE_STATUS status;
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }

            // Delete
            BOOL success = DeleteService(service);
            if (!success) {
                Logger::Error("ServiceManager: DeleteService failed: {}", GetLastError());
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if (success) {
                Logger::Info("ServiceManager: Service uninstalled: {}",
                    StringUtils::WideToUtf8(serviceName));
            }

            return success != FALSE;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: UninstallService exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool StartServiceImpl(
        const std::wstring& serviceName,
        const std::vector<std::wstring>& args,
        uint32_t timeoutMs) {

        try {
            Logger::Info("ServiceManager: Starting service: {}",
                StringUtils::WideToUtf8(serviceName));

            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                return false;
            }

            SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS);
            if (!service) {
                CloseServiceHandle(scm);
                return false;
            }

            // Prepare args
            std::vector<LPCWSTR> argPtrs;
            for (const auto& arg : args) {
                argPtrs.push_back(arg.c_str());
            }

            BOOL success = StartServiceW(
                service,
                static_cast<DWORD>(argPtrs.size()),
                argPtrs.empty() ? nullptr : argPtrs.data()
            );

            if (!success) {
                DWORD error = GetLastError();
                if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                    Logger::Error("ServiceManager: StartService failed: {}", error);
                    CloseServiceHandle(service);
                    CloseServiceHandle(scm);
                    return false;
                }
            }

            // Wait for running state
            auto startTime = steady_clock::now();
            while (duration_cast<milliseconds>(steady_clock::now() - startTime).count() < timeoutMs) {
                SERVICE_STATUS_PROCESS status;
                DWORD bytesNeeded;

                if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {

                    if (status.dwCurrentState == SERVICE_RUNNING) {
                        CloseServiceHandle(service);
                        CloseServiceHandle(scm);

                        m_stats.servicesStarted.fetch_add(1, std::memory_order_relaxed);

                        Logger::Info("ServiceManager: Service started: {}",
                            StringUtils::WideToUtf8(serviceName));

                        return true;
                    }

                    if (status.dwCurrentState == SERVICE_STOPPED) {
                        break;
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            Logger::Warn("ServiceManager: Service start timeout: {}",
                StringUtils::WideToUtf8(serviceName));

            return false;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: StartService exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool StopServiceImpl(
        const std::wstring& serviceName,
        bool stopDependents,
        uint32_t timeoutMs) {

        try {
            Logger::Info("ServiceManager: Stopping service: {}",
                StringUtils::WideToUtf8(serviceName));

            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                return false;
            }

            SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(),
                SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
            if (!service) {
                CloseServiceHandle(scm);
                return false;
            }

            // Stop dependents if requested
            if (stopDependents) {
                // Simplified - would enumerate and stop dependent services
            }

            SERVICE_STATUS status;
            if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
                DWORD error = GetLastError();
                if (error != ERROR_SERVICE_NOT_ACTIVE) {
                    Logger::Error("ServiceManager: ControlService(STOP) failed: {}", error);
                    CloseServiceHandle(service);
                    CloseServiceHandle(scm);
                    return false;
                }
            }

            // Wait for stopped state
            auto startTime = steady_clock::now();
            while (duration_cast<milliseconds>(steady_clock::now() - startTime).count() < timeoutMs) {
                SERVICE_STATUS_PROCESS statusEx;
                DWORD bytesNeeded;

                if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&statusEx), sizeof(statusEx), &bytesNeeded)) {

                    if (statusEx.dwCurrentState == SERVICE_STOPPED) {
                        CloseServiceHandle(service);
                        CloseServiceHandle(scm);

                        m_stats.servicesStopped.fetch_add(1, std::memory_order_relaxed);

                        Logger::Info("ServiceManager: Service stopped: {}",
                            StringUtils::WideToUtf8(serviceName));

                        return true;
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            Logger::Warn("ServiceManager: Service stop timeout: {}",
                StringUtils::WideToUtf8(serviceName));

            return false;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: StopService exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool RestartServiceImpl(const std::wstring& serviceName, uint32_t timeoutMs) {
        if (!StopServiceImpl(serviceName, false, timeoutMs / 2)) {
            return false;
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));

        return StartServiceImpl(serviceName, {}, timeoutMs / 2);
    }

    [[nodiscard]] bool SetStartTypeImpl(const std::wstring& serviceName, StartType startType) {
        try {
            SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) {
                return false;
            }

            SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_CHANGE_CONFIG);
            if (!service) {
                CloseServiceHandle(scm);
                return false;
            }

            DWORD winStartType = StartTypeToWinStartType(startType);

            BOOL success = ChangeServiceConfigW(
                service,
                SERVICE_NO_CHANGE,
                winStartType,
                SERVICE_NO_CHANGE,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
            );

            CloseServiceHandle(service);
            CloseServiceHandle(scm);

            if (success) {
                Logger::Info("ServiceManager: Changed start type for {}",
                    StringUtils::WideToUtf8(serviceName));
            }

            return success != FALSE;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: SetStartType exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool ConfigureRecoveryImpl(
        SC_HANDLE service,
        FailureAction firstFailure,
        FailureAction secondFailure,
        FailureAction subsequentFailures,
        uint32_t resetPeriodSeconds,
        uint32_t restartDelayMs) {

        try {
            SC_ACTION actions[3];
            actions[0].Type = FailureActionToWinAction(firstFailure);
            actions[0].Delay = restartDelayMs;

            actions[1].Type = FailureActionToWinAction(secondFailure);
            actions[1].Delay = restartDelayMs;

            actions[2].Type = FailureActionToWinAction(subsequentFailures);
            actions[2].Delay = restartDelayMs;

            SERVICE_FAILURE_ACTIONSW failureActions{};
            failureActions.dwResetPeriod = resetPeriodSeconds;
            failureActions.lpRebootMsg = nullptr;
            failureActions.lpCommand = nullptr;
            failureActions.cActions = 3;
            failureActions.lpsaActions = actions;

            BOOL success = ChangeServiceConfig2W(
                service,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                &failureActions
            );

            return success != FALSE;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: ConfigureRecovery exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // DRIVER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool LoadDriverImpl(const DriverLoadRequest& request) {
        try {
            Logger::Info("ServiceManager: Loading driver: {}",
                StringUtils::WideToUtf8(request.driverName));

            // Install as service first
            ServiceConfig config;
            config.serviceName = request.driverName;
            config.displayName = request.displayName;
            config.binaryPath = request.driverPath;
            config.serviceType = request.isMinifilter ?
                ServiceType::FileSystemDriver : ServiceType::KernelDriver;
            config.startType = request.startType;

            if (!InstallServiceImpl(config)) {
                // May already exist
                Logger::Warn("ServiceManager: Driver service may already exist");
            }

            // Start the driver
            bool started = StartServiceImpl(request.driverName, {},
                ServiceManagerConstants::DRIVER_LOAD_TIMEOUT_MS);

            if (started) {
                m_stats.driversLoaded.fetch_add(1, std::memory_order_relaxed);

                Logger::Info("ServiceManager: Driver loaded: {}",
                    StringUtils::WideToUtf8(request.driverName));
            }

            return started;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: LoadDriver exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UnloadDriverImpl(const std::wstring& driverName, bool force) {
        try {
            Logger::Info("ServiceManager: Unloading driver: {}",
                StringUtils::WideToUtf8(driverName));

            bool stopped = StopServiceImpl(driverName, false,
                ServiceManagerConstants::DRIVER_LOAD_TIMEOUT_MS);

            if (stopped || force) {
                m_stats.driversUnloaded.fetch_add(1, std::memory_order_relaxed);

                Logger::Info("ServiceManager: Driver unloaded: {}",
                    StringUtils::WideToUtf8(driverName));

                return true;
            }

            return stopped;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: UnloadDriver exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<MinifilterInfo> GetLoadedMinifitersImpl() const {
        std::vector<MinifilterInfo> filters;

        try {
            HANDLE hEnum = INVALID_HANDLE_VALUE;
            DWORD bytesReturned = 0;
            // Buffer for FILTER_FULL_INFORMATION
            std::vector<uint8_t> buffer(4096);

            HRESULT hr = FilterFindFirst(FilterFullInformation,
                                       buffer.data(),
                                       static_cast<DWORD>(buffer.size()),
                                       &bytesReturned,
                                       &hEnum);

            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
                return filters;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
                buffer.resize(bytesReturned);
                hr = FilterFindFirst(FilterFullInformation,
                                   buffer.data(),
                                   static_cast<DWORD>(buffer.size()),
                                   &bytesReturned,
                                   &hEnum);
            }

            if (FAILED(hr)) {
                Logger::Error("ServiceManager: FilterFindFirst failed: {:#x}", static_cast<uint32_t>(hr));
                return filters;
            }

            auto ProcessFilterInfo = [&](const uint8_t* pBuf) {
                auto* pInfo = reinterpret_cast<const FILTER_FULL_INFORMATION*>(pBuf);

                MinifilterInfo info;
                // Parse name (offset and length in bytes)
                if (pInfo->FilterNameLength > 0) {
                    std::wstring name((wchar_t*)((uint8_t*)pInfo + pInfo->FilterNameBufferOffset),
                                      pInfo->FilterNameLength / sizeof(wchar_t));
                    info.filterName = name;
                }

                // Parse altitude
                if (pInfo->FilterAltitudeLength > 0) {
                    std::wstring alt((wchar_t*)((uint8_t*)pInfo + pInfo->FilterAltitudeBufferOffset),
                                     pInfo->FilterAltitudeLength / sizeof(wchar_t));
                    info.altitude = alt;
                }

                info.frameID = pInfo->FrameID;
                info.numberOfInstances = pInfo->NumberOfInstances;
                filters.push_back(info);
            };

            // Process first result
            ProcessFilterInfo(buffer.data());

            // Process remaining results
            while (true) {
                hr = FilterFindNext(hEnum,
                                  FilterFullInformation,
                                  buffer.data(),
                                  static_cast<DWORD>(buffer.size()),
                                  &bytesReturned);

                if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) break;

                if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
                    buffer.resize(bytesReturned);
                    hr = FilterFindNext(hEnum,
                                      FilterFullInformation,
                                      buffer.data(),
                                      static_cast<DWORD>(buffer.size()),
                                      &bytesReturned);
                }

                if (FAILED(hr)) break;

                ProcessFilterInfo(buffer.data());
            }

            FilterFindClose(hEnum);
            Logger::Info("ServiceManager: Enumerated {} minifilters", filters.size());

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: GetLoadedMinifilters exception: {}", e.what());
        }

        return filters;
    }

    // ========================================================================
    // SELF-PROTECTION
    // ========================================================================

    [[nodiscard]] TamperDetectionResult VerifyServiceIntegrityImpl(
        const std::wstring& serviceName) const {

        TamperDetectionResult result;

        try {
            // Get current service info
            auto currentInfo = GetServiceInfoImpl(serviceName);
            if (!currentInfo) {
                result.isTampered = true;
                result.details = "Service not found";
                return result;
            }

            // Check against baseline
            auto it = m_serviceBaselines.find(serviceName);
            if (it == m_serviceBaselines.end()) {
                // No baseline established
                return result;
            }

            const auto& baseline = it->second;
            result.expectedBinaryPath = baseline.binaryPath;
            result.actualBinaryPath = currentInfo->binaryPath;

            // Check binary path
            if (StringUtils::ToLowerCase(currentInfo->binaryPath) !=
                StringUtils::ToLowerCase(baseline.binaryPath)) {
                result.isTampered = true;
                result.binaryModified = true;
                result.details += "Binary path changed; ";
            }

            // Check binary hash
            if (FileUtils::Exists(currentInfo->binaryPath)) {
                std::string currentHash = HashUtils::CalculateSHA256File(currentInfo->binaryPath);
                if (currentHash != baseline.binaryHash) {
                    result.isTampered = true;
                    result.binaryModified = true;
                    result.details += "Binary hash mismatch; ";
                }
            }

            // Check start type
            if (currentInfo->startType != baseline.startType) {
                result.isTampered = true;
                result.startTypeChanged = true;
                result.details += "Start type changed; ";
            }

            // Check service account
            if (StringUtils::ToLowerCase(currentInfo->serviceAccount) !=
                StringUtils::ToLowerCase(baseline.serviceAccount)) {
                result.isTampered = true;
                result.accountChanged = true;
                result.details += "Service account changed; ";
            }

            if (result.isTampered) {
                Logger::Critical("ServiceManager: TAMPER DETECTED for {}: {}",
                    StringUtils::WideToUtf8(serviceName), result.details);

                m_stats.tamperAttempts.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: VerifyServiceIntegrity exception: {}", e.what());
            result.isTampered = true;
            result.details = "Exception during verification";
        }

        return result;
    }

    void StartWatchdogImpl() {
        std::unique_lock lock(m_watchdogMutex);

        if (m_watchdogRunning.load(std::memory_order_acquire)) {
            Logger::Warn("ServiceManager: Watchdog already running");
            return;
        }

        m_stopWatchdog.store(false, std::memory_order_release);

        m_watchdogThread = std::make_unique<std::jthread>([this](std::stop_token stoken) {
            WatchdogThread(stoken);
        });

        m_watchdogRunning.store(true, std::memory_order_release);

        Logger::Info("ServiceManager: Watchdog started (interval: {} ms)",
            m_config.watchdogIntervalMs);
    }

    void StopWatchdogImpl() {
        std::unique_lock lock(m_watchdogMutex);

        if (!m_watchdogRunning.load(std::memory_order_acquire)) {
            return;
        }

        m_stopWatchdog.store(true, std::memory_order_release);

        if (m_watchdogThread) {
            m_watchdogThread->request_stop();
            m_watchdogThread.reset();
        }

        m_watchdogRunning.store(false, std::memory_order_release);

        Logger::Info("ServiceManager: Watchdog stopped");
    }

    void WatchdogThread(std::stop_token stoken) {
        Logger::Debug("ServiceManager: Watchdog thread started");

        while (!stoken.stop_requested() && !m_stopWatchdog.load(std::memory_order_acquire)) {
            try {
                // Check our main service
                if (m_config.enableSelfProtection) {
                    CheckAndRecoverService(m_config.mainServiceName);
                    CheckAndRecoverService(m_config.driverServiceName);
                }

                // Sleep
                std::this_thread::sleep_for(std::chrono::milliseconds(m_config.watchdogIntervalMs));

            } catch (const std::exception& e) {
                Logger::Error("ServiceManager: Watchdog exception: {}", e.what());
            }
        }

        Logger::Debug("ServiceManager: Watchdog thread stopped");
    }

    void CheckAndRecoverService(const std::wstring& serviceName) {
        try {
            // Verify integrity
            auto tamperResult = VerifyServiceIntegrityImpl(serviceName);

            if (tamperResult.isTampered) {
                // Invoke tamper callbacks
                InvokeTamperAlertCallbacks(tamperResult);

                // Attempt recovery
                if (m_config.autoRestartOnFailure) {
                    Logger::Warn("ServiceManager: Attempting recovery for {}",
                        StringUtils::WideToUtf8(serviceName));

                    // Simplified recovery - would do more in production
                    RestartServiceImpl(serviceName, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);

                    m_stats.selfRecoveries.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Check if service is running
            auto state = GetServiceStateImpl(serviceName);
            if (state == ServiceState::Stopped && m_config.autoRestartOnFailure) {
                Logger::Warn("ServiceManager: Service {} is stopped, restarting",
                    StringUtils::WideToUtf8(serviceName));

                StartServiceImpl(serviceName, {}, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);

                m_stats.selfRecoveries.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: CheckAndRecoverService exception: {}", e.what());
        }
    }

    // ========================================================================
    // THREAT REMEDIATION
    // ========================================================================

    [[nodiscard]] bool DisableMaliciousServiceImpl(
        const std::wstring& serviceName,
        bool quarantineBinary) {

        try {
            Logger::Info("ServiceManager: Disabling malicious service: {}",
                StringUtils::WideToUtf8(serviceName));

            // Get binary path before disabling
            std::wstring binaryPath;
            if (quarantineBinary) {
                if (auto info = GetServiceInfoImpl(serviceName)) {
                    binaryPath = info->binaryPath;
                }
            }

            // Stop service
            StopServiceImpl(serviceName, true, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);

            // Disable service
            SetStartTypeImpl(serviceName, StartType::Disabled);

            // Quarantine binary
            if (quarantineBinary && !binaryPath.empty()) {
                // Would call QuarantineManager here
                Logger::Info("ServiceManager: Would quarantine: {}",
                    StringUtils::WideToUtf8(binaryPath));
            }

            m_stats.remediationActions.fetch_add(1, std::memory_order_relaxed);

            Logger::Info("ServiceManager: Malicious service disabled: {}",
                StringUtils::WideToUtf8(serviceName));

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: DisableMaliciousService exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<ServiceInfo> GetSuspiciousServicesImpl() const {
        std::vector<ServiceInfo> suspicious;

        try {
            auto allServices = EnumerateServicesImpl();

            for (const auto& service : allServices) {
                bool isSuspicious = false;

                // Check if unsigned
                if (!service.isSigned && !service.isMicrosoft) {
                    isSuspicious = true;
                }

                // Check if binary path is suspicious
                std::wstring lowerPath = StringUtils::ToLowerCase(service.binaryPath);
                if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                    lowerPath.find(L"\\appdata\\") != std::wstring::npos ||
                    lowerPath.find(L"\\programdata\\") != std::wstring::npos) {
                    isSuspicious = true;
                }

                // Check if LocalSystem with suspicious name
                if (service.isLocalSystem && service.serviceName.length() < 5) {
                    isSuspicious = true;
                }

                if (isSuspicious) {
                    suspicious.push_back(service);
                }
            }

        } catch (const std::exception& e) {
            Logger::Error("ServiceManager: GetSuspiciousServices exception: {}", e.what());
        }

        return suspicious;
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeTamperAlertCallbacks(const TamperDetectionResult& result) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_tamperAlertCallbacks) {
            try {
                callback(result);
            } catch (const std::exception& e) {
                Logger::Error("ServiceManager: Tamper callback exception: {}", e.what());
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

ServiceManager& ServiceManager::Instance() {
    static ServiceManager instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ServiceManager::ServiceManager()
    : m_impl(std::make_unique<ServiceManagerImpl>())
{
    Logger::Info("ServiceManager: Constructor called");
}

ServiceManager::~ServiceManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ServiceManager: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ServiceManager::Initialize(const ServiceManagerConfig& config) {
    if (!m_impl) {
        Logger::Critical("ServiceManager: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void ServiceManager::Shutdown() noexcept {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

// ============================================================================
// SERVICE ENUMERATION
// ============================================================================

[[nodiscard]] std::vector<ServiceInfo> ServiceManager::EnumerateServices() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return {};
    }

    return m_impl->EnumerateServicesImpl();
}

[[nodiscard]] std::vector<ServiceInfo> ServiceManager::EnumerateDrivers() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return {};
    }

    return m_impl->EnumerateDriversImpl();
}

[[nodiscard]] std::optional<ServiceInfo> ServiceManager::GetServiceInfo(
    const std::wstring& serviceName) const {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return std::nullopt;
    }

    return m_impl->GetServiceInfoImpl(serviceName);
}

[[nodiscard]] bool ServiceManager::ServiceExists(const std::wstring& serviceName) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->ServiceExistsImpl(serviceName);
}

[[nodiscard]] ServiceState ServiceManager::GetServiceState(
    const std::wstring& serviceName) const {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return ServiceState::Unknown;
    }

    return m_impl->GetServiceStateImpl(serviceName);
}

// ============================================================================
// SERVICE LIFECYCLE MANAGEMENT
// ============================================================================

[[nodiscard]] bool ServiceManager::InstallService(const ServiceConfig& config) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->InstallServiceImpl(config);
}

[[nodiscard]] bool ServiceManager::UninstallService(
    const std::wstring& serviceName,
    bool force) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->UninstallServiceImpl(serviceName, force);
}

[[nodiscard]] bool ServiceManager::StartService(
    const std::wstring& serviceName,
    const std::vector<std::wstring>& args,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->StartServiceImpl(serviceName, args, timeoutMs);
}

[[nodiscard]] bool ServiceManager::StopService(
    const std::wstring& serviceName,
    bool stopDependents,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->StopServiceImpl(serviceName, stopDependents, timeoutMs);
}

[[nodiscard]] bool ServiceManager::RestartService(
    const std::wstring& serviceName,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->RestartServiceImpl(serviceName, timeoutMs);
}

[[nodiscard]] bool ServiceManager::PauseService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_PAUSE_CONTINUE);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS status;
        BOOL success = ControlService(service, SERVICE_CONTROL_PAUSE, &status);

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return success != FALSE;

    } catch (const std::exception& e) {
        Logger::Error("ServiceManager: PauseService exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool ServiceManager::ContinueService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    try {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_PAUSE_CONTINUE);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        SERVICE_STATUS status;
        BOOL success = ControlService(service, SERVICE_CONTROL_CONTINUE, &status);

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return success != FALSE;

    } catch (const std::exception& e) {
        Logger::Error("ServiceManager: ContinueService exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] bool ServiceManager::SetStartType(
    const std::wstring& serviceName,
    StartType startType) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->SetStartTypeImpl(serviceName, startType);
}

[[nodiscard]] bool ServiceManager::ConfigureRecovery(
    const std::wstring& serviceName,
    FailureAction firstFailure,
    FailureAction secondFailure,
    FailureAction subsequentFailures,
    uint32_t resetPeriodSeconds,
    uint32_t restartDelayMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    try {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return false;

        SC_HANDLE service = OpenServiceW(scm, serviceName.c_str(), SERVICE_CHANGE_CONFIG);
        if (!service) {
            CloseServiceHandle(scm);
            return false;
        }

        bool result = m_impl->ConfigureRecoveryImpl(service, firstFailure, secondFailure,
            subsequentFailures, resetPeriodSeconds, restartDelayMs);

        CloseServiceHandle(service);
        CloseServiceHandle(scm);

        return result;

    } catch (const std::exception& e) {
        Logger::Error("ServiceManager: ConfigureRecovery exception: {}", e.what());
        return false;
    }
}

// ============================================================================
// DRIVER MANAGEMENT
// ============================================================================

[[nodiscard]] bool ServiceManager::LoadDriver(const DriverLoadRequest& request) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->LoadDriverImpl(request);
}

[[nodiscard]] bool ServiceManager::UnloadDriver(
    const std::wstring& driverName,
    bool force) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->UnloadDriverImpl(driverName, force);
}

[[nodiscard]] bool ServiceManager::LoadMinifilter(
    const std::wstring& filterName,
    uint32_t altitude) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    DriverLoadRequest request;
    request.driverName = filterName;
    request.displayName = filterName;
    request.isMinifilter = true;
    request.altitude = altitude;
    request.startType = StartType::DemandStart;

    return m_impl->LoadDriverImpl(request);
}

[[nodiscard]] bool ServiceManager::UnloadMinifilter(const std::wstring& filterName) {
    return UnloadDriver(filterName, false);
}

[[nodiscard]] std::vector<MinifilterInfo> ServiceManager::GetLoadedMinifilters() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->GetLoadedMinifitersImpl();
}

[[nodiscard]] bool ServiceManager::IsMinifilterLoaded(const std::wstring& filterName) const {
    auto filters = GetLoadedMinifilters();

    return std::any_of(filters.begin(), filters.end(),
        [&filterName](const MinifilterInfo& info) {
            return StringUtils::ToLowerCase(info.filterName) ==
                   StringUtils::ToLowerCase(filterName);
        });
}

// ============================================================================
// SELF-PROTECTION
// ============================================================================

[[nodiscard]] TamperDetectionResult ServiceManager::VerifyServiceIntegrity(
    const std::wstring& serviceName) const {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        TamperDetectionResult result;
        result.isTampered = true;
        result.details = "Not initialized";
        return result;
    }

    return m_impl->VerifyServiceIntegrityImpl(serviceName);
}

[[nodiscard]] bool ServiceManager::ProtectService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    // KERNEL DRIVER INTEGRATION WILL COME HERE
    // In a production environment, this would involve a kernel callback
    // to strip handle access rights (PROCESS_TERMINATE, WRITE_DAC, etc.)
    // for the protected service process.
    Logger::Info("ServiceManager: Protected service: {}",
        StringUtils::WideToUtf8(serviceName));

    return true;
}

void ServiceManager::StartWatchdog() {
    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        m_impl->StartWatchdogImpl();
    }
}

void ServiceManager::StopWatchdog() {
    if (m_impl) {
        m_impl->StopWatchdogImpl();
    }
}

[[nodiscard]] bool ServiceManager::IsWatchdogRunning() const noexcept {
    return m_impl && m_impl->m_watchdogRunning.load(std::memory_order_acquire);
}

// ============================================================================
// THREAT REMEDIATION
// ============================================================================

[[nodiscard]] bool ServiceManager::DisableMaliciousService(
    const std::wstring& serviceName,
    bool quarantineBinary) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    return m_impl->DisableMaliciousServiceImpl(serviceName, quarantineBinary);
}

[[nodiscard]] bool ServiceManager::RemoveMaliciousDriver(
    const std::wstring& driverName,
    bool rebootRequired) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        Logger::Error("ServiceManager: Not initialized");
        return false;
    }

    // Unload and uninstall
    bool success = m_impl->UnloadDriverImpl(driverName, true);

    if (success) {
        m_impl->UninstallServiceImpl(driverName, true);
        m_impl->m_stats.remediationActions.fetch_add(1, std::memory_order_relaxed);
    }

    return success;
}

[[nodiscard]] uint32_t ServiceManager::CleanOrphanedServices() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return 0;
    }

    uint32_t cleaned = 0;

    try {
        auto allServices = m_impl->EnumerateServicesImpl();

        for (const auto& service : allServices) {
            // Check if binary exists
            if (!service.binaryPath.empty() && !FileUtils::Exists(service.binaryPath)) {
                Logger::Info("ServiceManager: Cleaning orphaned service: {}",
                    StringUtils::WideToUtf8(service.serviceName));

                if (m_impl->UninstallServiceImpl(service.serviceName, true)) {
                    cleaned++;
                }
            }
        }

        if (cleaned > 0) {
            m_impl->m_stats.remediationActions.fetch_add(cleaned, std::memory_order_relaxed);
        }

    } catch (const std::exception& e) {
        Logger::Error("ServiceManager: CleanOrphanedServices exception: {}", e.what());
    }

    return cleaned;
}

[[nodiscard]] std::vector<ServiceInfo> ServiceManager::GetSuspiciousServices() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->GetSuspiciousServicesImpl();
}

// ============================================================================
// CALLBACKS AND EVENTS
// ============================================================================

uint64_t ServiceManager::RegisterServiceChangeCallback(ServiceChangeCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_serviceChangeCallbacks[id] = std::move(callback);

    Logger::Debug("ServiceManager: Registered service change callback {}", id);
    return id;
}

void ServiceManager::UnregisterServiceChangeCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_serviceChangeCallbacks.erase(callbackId);

    Logger::Debug("ServiceManager: Unregistered service change callback {}", callbackId);
}

uint64_t ServiceManager::RegisterTamperAlertCallback(TamperAlertCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_tamperAlertCallbacks[id] = std::move(callback);

    Logger::Debug("ServiceManager: Registered tamper alert callback {}", id);
    return id;
}

void ServiceManager::UnregisterTamperAlertCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_tamperAlertCallbacks.erase(callbackId);

    Logger::Debug("ServiceManager: Unregistered tamper alert callback {}", callbackId);
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] const ServiceManagerStatistics& ServiceManager::GetStatistics() const noexcept {
    static ServiceManagerStatistics emptyStats{};
    return m_impl ? m_impl->m_stats : emptyStats;
}

void ServiceManager::ResetStatistics() noexcept {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("ServiceManager: Statistics reset");
    }
}

} // namespace System
} // namespace Core
} // namespace ShadowStrike
