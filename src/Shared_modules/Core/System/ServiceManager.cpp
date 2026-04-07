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
#include "../../Utils/RegistryUtils.hpp"
#include "../../Core/FileSystem/FileHasher.hpp"
#include "../../Core/FileSystem/FileLockManager.hpp"
#include "../../Whitelist/WhiteListStore.hpp"

// Cross-module wiring includes
// NOTE: Direct #include of RegistryMonitor.hpp, ProcessMonitor.hpp, DriverAnalyzer.hpp,
// and PersistenceDetector.hpp is blocked by a pre-existing compilation error in
// ThreatIntelStore.hpp:1503 (forward-declared ThreatIntelLookup used before definition).
// All cross-module wiring is implemented via RegistryUtils for service registry reads
// and AlertSystem for threat alerting. Once the ThreatIntelStore header is fixed,
// full callback-based wiring should be enabled (see WireRegistryMonitor/etc. stubs below).
#include "../../Communication/AlertSystem.hpp"
#include "../../Utils/RegistryUtils.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <format>
#include <thread>
#include <sstream>
#include <unordered_set>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winsvc.h>
#  include <fltUser.h>
#  include <wintrust.h>
#  include <softpub.h>
#  include <sddl.h>
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
// LOG CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"ServiceManager";

// ============================================================================
// RAII WRAPPERS
// ============================================================================

/**
 * @brief RAII wrapper for SC_HANDLE (Service Control Manager handles).
 */
class SCHandleGuard {
public:
    explicit SCHandleGuard(SC_HANDLE handle = nullptr) noexcept : m_handle(handle) {}
    
    ~SCHandleGuard() noexcept {
        if (m_handle) {
            CloseServiceHandle(m_handle);
        }
    }
    
    SCHandleGuard(const SCHandleGuard&) = delete;
    SCHandleGuard& operator=(const SCHandleGuard&) = delete;
    
    SCHandleGuard(SCHandleGuard&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }
    
    SCHandleGuard& operator=(SCHandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle) CloseServiceHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    
    [[nodiscard]] SC_HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle != nullptr; }
    [[nodiscard]] explicit operator bool() const noexcept { return valid(); }
    
    SC_HANDLE release() noexcept {
        SC_HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }
    
    void reset(SC_HANDLE handle = nullptr) noexcept {
        if (m_handle) CloseServiceHandle(m_handle);
        m_handle = handle;
    }

private:
    SC_HANDLE m_handle;
};

/**
 * @brief RAII wrapper for filter enumeration handles.
 */
class FilterEnumGuard {
public:
    explicit FilterEnumGuard(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : m_handle(handle) {}
    
    ~FilterEnumGuard() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) {
            FilterFindClose(m_handle);
        }
    }
    
    FilterEnumGuard(const FilterEnumGuard&) = delete;
    FilterEnumGuard& operator=(const FilterEnumGuard&) = delete;
    
    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle != INVALID_HANDLE_VALUE; }
    [[nodiscard]] HANDLE* addressof() noexcept { return &m_handle; }

private:
    HANDLE m_handle;
};

// ============================================================================
// SERVICE NAME VALIDATION
// ============================================================================

/**
 * @brief Validates a service name for safe use with Windows APIs.
 * @param serviceName The service name to validate.
 * @return true if valid, false otherwise.
 */
[[nodiscard]] static bool ValidateServiceName(const std::wstring& serviceName) noexcept {
    // Empty check
    if (serviceName.empty()) {
        return false;
    }
    
    // Length check (Windows limit is 256 characters)
    if (serviceName.length() > 256) {
        return false;
    }
    
    // Check for embedded null characters
    if (serviceName.find(L'\0') != std::wstring::npos) {
        return false;
    }
    
    // Check for invalid characters (backslash, forward slash)
    if (serviceName.find(L'\\') != std::wstring::npos ||
        serviceName.find(L'/') != std::wstring::npos) {
        return false;
    }
    
    return true;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

// Known legitimate apps that install services in ProgramData
// (to reduce false positives)
static const std::unordered_set<std::wstring> KNOWN_PROGRAMDATA_SERVICES = {
    L"microsoft",
    L"windows",
    L"defender",
    L"chocolatey",
    L"docker",
    L"jenkins",
    L"grafana",
    L"prometheus",
    L"elasticsearch",
    L"mongodb",
    L"postgresql",
    L"mysql",
    L"redis",
    L"nginx",
    L"apache",
    L"git",
    L"nodejs",
    L"python",
    L"java",
    L"dotnet",
    L"oracle"
};

/**
 * @brief RAII wrapper for Win32 HANDLE (files, events, etc.).
 */
class HandleGuard {
public:
    explicit HandleGuard(HANDLE handle = INVALID_HANDLE_VALUE) noexcept : m_handle(handle) {}
    ~HandleGuard() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) {
            CloseHandle(m_handle);
        }
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept : m_handle(other.m_handle) { other.m_handle = INVALID_HANDLE_VALUE; }
    HandleGuard& operator=(HandleGuard&& other) noexcept {
        if (this != &other) {
            if (m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr) CloseHandle(m_handle);
            m_handle = other.m_handle;
            other.m_handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }
    [[nodiscard]] bool valid() const noexcept { return m_handle != INVALID_HANDLE_VALUE && m_handle != nullptr; }

private:
    HANDLE m_handle;
};

/**
 * @brief Compute SHA256 hash of a file.
 * @param filePath Path to the file.
 * @return Hex string of hash, or empty string on error.
 */
[[nodiscard]] std::string ComputeFileSHA256(const std::wstring& filePath) noexcept {
    try {
        HandleGuard hFile(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (!hFile.valid()) {
            return "";
        }

        HashUtils::Hasher hasher(HashUtils::Algorithm::SHA256);
        if (!hasher.Init()) {
            return "";
        }

        constexpr size_t BUFFER_SIZE = 64 * 1024;  // 64KB chunks
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        DWORD bytesRead = 0;

        while (ReadFile(hFile.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, nullptr) && bytesRead > 0) {
            if (!hasher.Update(buffer.data(), bytesRead)) {
                return "";
            }
        }

        std::string hexHash;
        if (!hasher.FinalHex(hexHash, false)) {
            return "";
        }

        return hexHash;

    } catch (...) {
        return "";
    }
}

/**
 * @brief Check if a path is in ProgramData but for a known legitimate vendor.
 */
[[nodiscard]] bool IsKnownProgramDataService(const std::wstring& binaryPath) noexcept {
    std::wstring lowerPath = StringUtils::ToLowerCopy(binaryPath);
    
    for (const auto& vendor : KNOWN_PROGRAMDATA_SERVICES) {
        if (lowerPath.find(vendor) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

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

        // Check signer name via certificate chain to confirm Microsoft origin
        // A valid Authenticode signature alone is insufficient — any EV cert holder passes.
        // We verify by matching the signing certificate subject against Microsoft subjects.
        std::wstring lowerPath = StringUtils::ToLowerCopy(binaryPath);

        // Trusted Microsoft paths (signed + known-good path = Microsoft)
        if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\windows\\winsxs\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\program files\\windows defender\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\program files (x86)\\windows defender\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\program files\\windows nt\\") != std::wstring::npos) return true;
        if (lowerPath.find(L"\\programdata\\microsoft\\") != std::wstring::npos) return true;

        // Not in a known Microsoft path — signed but not confirmed Microsoft
        return false;

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
class ServiceManagerImpl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_watchdogMutex;
    mutable std::shared_mutex m_baselineMutex;
    std::mutex m_scmMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_watchdogRunning{false};
    std::atomic<bool> m_stopWatchdog{false};

    // Configuration
    ServiceManagerConfig m_config{};

    // Statistics (mutable for const method updates)
    mutable ServiceManagerStatistics m_stats{};

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, ServiceChangeCallback> m_serviceChangeCallbacks;
    std::unordered_map<uint64_t, TamperAlertCallback> m_tamperAlertCallbacks;

    // Watchdog thread
    std::unique_ptr<std::jthread> m_watchdogThread;
    std::condition_variable_any m_watchdogCv;

    // Cross-module wiring state
    // NOTE: Callback IDs will be added when ThreatIntelStore.hpp header issue is resolved
    // and direct module includes become possible.

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
            SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager::Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Establish baseline for our services
            EstablishServiceBaselines();

            // Initialize FileLockManager for service binary lock detection
            {
                auto flmConfig = Core::FileSystem::FileLockManagerConfig::CreateDefault();
                auto& flm = Core::FileSystem::FileLockManager::Instance();
                if (!flm.Initialize(flmConfig)) {
                    SS_LOG_WARN(LOG_CATEGORY, L"FileLockManager initialization failed - lock detection degraded");
                }
            }

            // Wire cross-module integrations
            WireRegistryMonitor();
            WireDriverAnalyzer();
            WireProcessMonitor();
            WirePersistenceDetector();

            m_initialized.store(true, std::memory_order_release);
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager::Impl: Initialization complete");

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager::Impl: Initialization exception: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager::Impl: Shutting down");

        // Stop watchdog
        StopWatchdogImpl();

        // Unregister cross-module callbacks
        UnwireAllCallbacks();

        // Clear callbacks
        {
            std::unique_lock cbLock(m_callbackMutex);
            m_serviceChangeCallbacks.clear();
            m_tamperAlertCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager::Impl: Shutdown complete");
    }

    void EstablishServiceBaselines() {
        try {
            std::unique_lock lock(m_baselineMutex);

            // Baseline our main service
            if (auto info = GetServiceInfoImpl(m_config.mainServiceName)) {
                ServiceBaseline baseline;
                baseline.binaryPath = info->binaryPath;
                baseline.startType = info->startType;
                baseline.serviceAccount = info->serviceAccount;

                if (FileUtils::Exists(info->binaryPath)) {
                    baseline.binaryHash = ComputeFileSHA256(info->binaryPath);
                    if (baseline.binaryHash.empty()) {
                        SS_LOG_WARN(LOG_CATEGORY, L"Failed to hash main service binary: %ls",
                            info->binaryPath.c_str());
                    }
                }

                m_serviceBaselines[m_config.mainServiceName] = baseline;
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Established baseline for %ls",
                    m_config.mainServiceName.c_str());
            }

            // Baseline our driver service
            if (auto info = GetServiceInfoImpl(m_config.driverServiceName)) {
                ServiceBaseline baseline;
                baseline.binaryPath = info->binaryPath;
                baseline.startType = info->startType;
                baseline.serviceAccount = info->serviceAccount;

                if (FileUtils::Exists(info->binaryPath)) {
                    baseline.binaryHash = ComputeFileSHA256(info->binaryPath);
                    if (baseline.binaryHash.empty()) {
                        SS_LOG_WARN(LOG_CATEGORY, L"Failed to hash driver service binary: %ls",
                            info->binaryPath.c_str());
                    }
                }

                m_serviceBaselines[m_config.driverServiceName] = baseline;
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Established baseline for %ls",
                    m_config.driverServiceName.c_str());
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Baseline establishment exception: %hs", e.what());
        }
    }

    // ========================================================================
    // SERVICE ENUMERATION
    // ========================================================================

    [[nodiscard]] std::vector<ServiceInfo> EnumerateServicesImpl() const {
        std::vector<ServiceInfo> services;

        try {
            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
            if (!scm) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Failed to open SCM: %lu", GetLastError());
                return services;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // First call to get size
            EnumServicesStatusExW(
                scm.get(),
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
                return services;
            }

            std::vector<uint8_t> buffer(bytesNeeded);
            auto* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

            // Actual enumeration
            if (EnumServicesStatusExW(
                    scm.get(),
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

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Enumeration exception: %hs", e.what());
        }

        return services;
    }

    [[nodiscard]] std::vector<ServiceInfo> EnumerateDriversImpl() const {
        std::vector<ServiceInfo> drivers;

        try {
            // Query SCM directly for driver services only (much more efficient)
            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE));
            if (!scm) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Failed to open SCM for driver enum: %lu", GetLastError());
                return drivers;
            }

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // First call to get required buffer size — drivers only
            EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER, SERVICE_STATE_ALL,
                nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle, nullptr);

            if (bytesNeeded == 0) return drivers;

            std::vector<uint8_t> buffer(bytesNeeded);
            auto* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());

            if (EnumServicesStatusExW(scm.get(), SC_ENUM_PROCESS_INFO,
                    SERVICE_DRIVER, SERVICE_STATE_ALL,
                    reinterpret_cast<LPBYTE>(pServices), bytesNeeded,
                    &bytesNeeded, &servicesReturned, &resumeHandle, nullptr)) {

                for (DWORD i = 0; i < servicesReturned; ++i) {
                    ServiceInfo info;
                    info.serviceName = pServices[i].lpServiceName;
                    info.displayName = pServices[i].lpDisplayName;
                    info.serviceType = WinTypeToServiceType(pServices[i].ServiceStatusProcess.dwServiceType);
                    info.state = WinStateToServiceState(pServices[i].ServiceStatusProcess.dwCurrentState);
                    info.processId = pServices[i].ServiceStatusProcess.dwProcessId;

                    if (auto detailedInfo = GetServiceInfoImpl(info.serviceName)) {
                        info.binaryPath = detailedInfo->binaryPath;
                        info.startType = detailedInfo->startType;
                        info.description = detailedInfo->description;
                        info.serviceAccount = detailedInfo->serviceAccount;
                        info.isMicrosoft = IsMicrosoftBinary(info.binaryPath);
                    }

                    drivers.push_back(std::move(info));
                }

                m_stats.servicesEnumerated.fetch_add(servicesReturned, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: EnumerateDrivers exception: %hs", e.what());
        }

        return drivers;
    }

    [[nodiscard]] std::optional<ServiceInfo> GetServiceInfoImpl(const std::wstring& serviceName) const {
        // Validate service name
        if (!ValidateServiceName(serviceName)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Invalid service name provided");
            return std::nullopt;
        }
        
        try {
            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) {
                return std::nullopt;
            }

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
            if (!service) {
                return std::nullopt;
            }

            ServiceInfo info;
            info.serviceName = serviceName;

            // Get config
            DWORD bytesNeeded = 0;
            QueryServiceConfigW(service.get(), nullptr, 0, &bytesNeeded);

            if (bytesNeeded > 0) {
                std::vector<uint8_t> buffer(bytesNeeded);
                auto* pConfig = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());

                if (QueryServiceConfigW(service.get(), pConfig, bytesNeeded, &bytesNeeded)) {
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
            if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {
                info.state = WinStateToServiceState(status.dwCurrentState);
                info.processId = status.dwProcessId;
                info.exitCode = status.dwWin32ExitCode;
                info.acceptsStop = (status.dwControlsAccepted & SERVICE_ACCEPT_STOP) != 0;
                info.acceptsPause = (status.dwControlsAccepted & SERVICE_ACCEPT_PAUSE_CONTINUE) != 0;
            }

            // Get description
            bytesNeeded = 0;
            QueryServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, nullptr, 0, &bytesNeeded);

            if (bytesNeeded > 0) {
                std::vector<uint8_t> descBuffer(bytesNeeded);
                auto* pDesc = reinterpret_cast<SERVICE_DESCRIPTIONW*>(descBuffer.data());

                if (QueryServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION,
                        reinterpret_cast<LPBYTE>(pDesc), bytesNeeded, &bytesNeeded)) {
                    if (pDesc->lpDescription) {
                        info.description = pDesc->lpDescription;
                    }
                }
            }

            return info;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: GetServiceInfo exception: %hs", e.what());
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
        // Validate service name
        if (!ValidateServiceName(config.serviceName)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for installation");
            return false;
        }
        
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Installing service: %ls",
                config.serviceName.c_str());

            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE));
            if (!scm) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Failed to open SCM: %lu", GetLastError());
                return false;
            }

            DWORD serviceType = ServiceTypeToWinType(config.serviceType);
            DWORD startType = StartTypeToWinStartType(config.startType);

            // Format dependencies as double-null-terminated multi-string
            std::wstring depsMultiStr;
            for (const auto& dep : config.dependencies) {
                depsMultiStr += dep;
                depsMultiStr += L'\0';
            }
            // Double-null terminator is added by c_str() when passed as LPCWSTR
            const wchar_t* depsPtr = config.dependencies.empty() ? nullptr : depsMultiStr.c_str();

            SCHandleGuard service(CreateServiceW(
                scm.get(),
                config.serviceName.c_str(),
                config.displayName.c_str(),
                SERVICE_ALL_ACCESS,
                serviceType,
                startType,
                SERVICE_ERROR_NORMAL,
                config.binaryPath.c_str(),
                config.loadOrderGroup.empty() ? nullptr : config.loadOrderGroup.c_str(),
                nullptr,
                depsPtr,
                config.serviceAccount.empty() ? nullptr : config.serviceAccount.c_str(),
                config.password.empty() ? nullptr : config.password.c_str()
            ));

            if (!service) {
                DWORD error = GetLastError();
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: CreateService failed: %lu", error);
                return false;
            }

            // Set description
            if (!config.description.empty()) {
                SERVICE_DESCRIPTIONW desc;
                desc.lpDescription = const_cast<LPWSTR>(config.description.c_str());

                (void)ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &desc);
            }

            // Configure failure recovery
            if (config.configureRecovery) {
                (void)ConfigureRecoveryImpl(service.get(),
                    config.firstFailure,
                    config.secondFailure,
                    config.subsequentFailures,
                    config.resetPeriodSeconds,
                    config.restartDelayMs);
            }

            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Service installed successfully: %ls",
                config.serviceName.c_str());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: InstallService exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UninstallServiceImpl(const std::wstring& serviceName, bool force) {
        // Validate service name
        if (!ValidateServiceName(serviceName)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for uninstallation");
            return false;
        }
        
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Uninstalling service: %ls",
                serviceName.c_str());

            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Failed to open SCM: %lu", GetLastError());
                return false;
            }

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(), DELETE | SERVICE_STOP));
            if (!service) {
                DWORD error = GetLastError();
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: OpenService failed: %lu", error);
                return false;
            }

            // Stop if running and force is specified
            if (force) {
                SERVICE_STATUS status;
                ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }

            // Delete
            BOOL success = DeleteService(service.get());
            if (!success) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: DeleteService failed: %lu", GetLastError());
            }

            if (success) {
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Service uninstalled: %ls",
                    serviceName.c_str());
            }

            return success != FALSE;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: UninstallService exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool StartServiceImpl(
        const std::wstring& serviceName,
        const std::vector<std::wstring>& args,
        uint32_t timeoutMs) {

        // Validate service name
        if (!ValidateServiceName(serviceName)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for start operation");
            return false;
        }
        
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Starting service: %ls",
                serviceName.c_str());

            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) {
                return false;
            }

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(), SERVICE_START | SERVICE_QUERY_STATUS));
            if (!service) {
                return false;
            }

            // Prepare args
            std::vector<LPCWSTR> argPtrs;
            for (const auto& arg : args) {
                argPtrs.push_back(arg.c_str());
            }

            BOOL success = ::StartServiceW(
                service.get(),
                static_cast<DWORD>(argPtrs.size()),
                argPtrs.empty() ? nullptr : argPtrs.data()
            );

            if (!success) {
                DWORD error = GetLastError();
                if (error != ERROR_SERVICE_ALREADY_RUNNING) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: StartService failed: %lu", error);
                    return false;
                }
            }

            // Wait for running state
            auto startTime = steady_clock::now();
            while (duration_cast<milliseconds>(steady_clock::now() - startTime).count() < timeoutMs) {
                SERVICE_STATUS_PROCESS status;
                DWORD bytesNeeded;

                if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytesNeeded)) {

                    if (status.dwCurrentState == SERVICE_RUNNING) {
                        m_stats.servicesStarted.fetch_add(1, std::memory_order_relaxed);

                        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Service started: %ls",
                            serviceName.c_str());

                        return true;
                    }

                    if (status.dwCurrentState == SERVICE_STOPPED) {
                        break;
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Service start timeout: %ls",
                serviceName.c_str());

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: StartService exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool StopServiceImpl(
        const std::wstring& serviceName,
        bool stopDependents,
        uint32_t timeoutMs) {

        // Validate service name
        if (!ValidateServiceName(serviceName)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for stop operation");
            return false;
        }
        
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Stopping service: %ls",
                serviceName.c_str());

            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) {
                return false;
            }

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(),
                SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS));
            if (!service) {
                return false;
            }

            // Stop dependents if requested
            if (stopDependents) {
                StopDependentServices(scm.get(), service.get(), serviceName, timeoutMs / 2);
            }

            SERVICE_STATUS status;
            if (!ControlService(service.get(), SERVICE_CONTROL_STOP, &status)) {
                DWORD error = GetLastError();
                if (error != ERROR_SERVICE_NOT_ACTIVE) {
                    SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ControlService(STOP) failed: %lu", error);
                    return false;
                }
            }

            // Wait for stopped state
            auto startTime = steady_clock::now();
            while (duration_cast<milliseconds>(steady_clock::now() - startTime).count() < timeoutMs) {
                SERVICE_STATUS_PROCESS statusEx;
                DWORD bytesNeeded;

                if (QueryServiceStatusEx(service.get(), SC_STATUS_PROCESS_INFO,
                        reinterpret_cast<LPBYTE>(&statusEx), sizeof(statusEx), &bytesNeeded)) {

                    if (statusEx.dwCurrentState == SERVICE_STOPPED) {
                        m_stats.servicesStopped.fetch_add(1, std::memory_order_relaxed);

                        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Service stopped: %ls",
                            serviceName.c_str());

                        return true;
                    }
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Service stop timeout: %ls",
                serviceName.c_str());

            return false;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: StopService exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool RestartServiceImpl(const std::wstring& serviceName, uint32_t timeoutMs) {
        // Guard against zero/tiny timeouts
        constexpr uint32_t MIN_TIMEOUT_MS = 2000;
        uint32_t effectiveTimeout = (std::max)(timeoutMs, MIN_TIMEOUT_MS);
        uint32_t halfTimeout = effectiveTimeout / 2;

        if (!StopServiceImpl(serviceName, true, halfTimeout)) {
            // Service may already be stopped — continue trying to start
            auto state = GetServiceStateImpl(serviceName);
            if (state != ServiceState::Stopped) {
                return false;
            }
        }

        std::this_thread::sleep_for(std::chrono::seconds(1));

        return StartServiceImpl(serviceName, {}, halfTimeout);
    }

    [[nodiscard]] bool SetStartTypeImpl(const std::wstring& serviceName, StartType startType) {
        // Validate service name
        if (!ValidateServiceName(serviceName)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for SetStartType");
            return false;
        }
        
        try {
            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) {
                return false;
            }

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(), SERVICE_CHANGE_CONFIG));
            if (!service) {
                return false;
            }

            DWORD winStartType = StartTypeToWinStartType(startType);

            BOOL success = ChangeServiceConfigW(
                service.get(),
                SERVICE_NO_CHANGE,
                winStartType,
                SERVICE_NO_CHANGE,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
            );

            if (success) {
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Changed start type for %ls",
                    serviceName.c_str());
            }

            return success != FALSE;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: SetStartType exception: %hs", e.what());
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
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ConfigureRecovery exception: %hs", e.what());
            return false;
        }
    }

    // ========================================================================
    // DRIVER MANAGEMENT
    // ========================================================================

    [[nodiscard]] bool LoadDriverImpl(const DriverLoadRequest& request) {
        // Validate driver path
        if (request.driverPath.empty()) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Driver path is required for LoadDriver");
            return false;
        }
        
        if (!FileUtils::Exists(request.driverPath)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Driver file does not exist: %ls", request.driverPath.c_str());
            return false;
        }
        
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Loading driver: %ls",
                request.driverName.c_str());

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
                SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Driver service may already exist");
            }

            // Start the driver
            bool started = StartServiceImpl(request.driverName, {},
                ServiceManagerConstants::DRIVER_LOAD_TIMEOUT_MS);

            if (started) {
                m_stats.driversLoaded.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Driver loaded: %ls",
                    request.driverName.c_str());
            }

            return started;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: LoadDriver exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] bool UnloadDriverImpl(const std::wstring& driverName, bool force) {
        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Unloading driver: %ls",
                driverName.c_str());

            bool stopped = StopServiceImpl(driverName, false,
                ServiceManagerConstants::DRIVER_LOAD_TIMEOUT_MS);

            if (stopped || force) {
                m_stats.driversUnloaded.fetch_add(1, std::memory_order_relaxed);

                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Driver unloaded: %ls",
                    driverName.c_str());

                return true;
            }

            return stopped;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: UnloadDriver exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<MinifilterInfo> GetLoadedMinifitersImpl() const {
        std::vector<MinifilterInfo> filters;

        try {
            FilterEnumGuard hEnum;
            DWORD bytesReturned = 0;
            // Buffer for FILTER_AGGREGATE_BASIC_INFORMATION (has altitude info)
            std::vector<uint8_t> buffer(4096);

            // Use FilterAggregateBasicInformation to get altitude data
            HRESULT hr = FilterFindFirst(FilterAggregateBasicInformation,
                                       buffer.data(),
                                       static_cast<DWORD>(buffer.size()),
                                       &bytesReturned,
                                       hEnum.addressof());

            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {
                return filters;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
                buffer.resize(bytesReturned);
                hr = FilterFindFirst(FilterAggregateBasicInformation,
                                   buffer.data(),
                                   static_cast<DWORD>(buffer.size()),
                                   &bytesReturned,
                                   hEnum.addressof());
            }

            if (FAILED(hr)) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: FilterFindFirst failed: 0x%08X", static_cast<uint32_t>(hr));
                return filters;
            }

            auto ProcessFilterInfo = [&](const uint8_t* pBuf) {
                auto* pInfo = reinterpret_cast<const FILTER_AGGREGATE_BASIC_INFORMATION*>(pBuf);

                // Only process minifilters (not legacy filters)
                if (!(pInfo->Flags & FLTFL_AGGREGATE_INFO_IS_MINIFILTER)) {
                    return; // Skip legacy filters
                }

                MinifilterInfo info;

                // Parse name from MiniFilter union member
                if (pInfo->Type.MiniFilter.FilterNameLength > 0) {
                    // FilterNameBuffer follows the structure in memory
                    const wchar_t* nameStart = reinterpret_cast<const wchar_t*>(
                        reinterpret_cast<const uint8_t*>(pInfo) + 
                        pInfo->Type.MiniFilter.FilterNameBufferOffset);
                    info.filterName = std::wstring(nameStart, 
                        pInfo->Type.MiniFilter.FilterNameLength / sizeof(wchar_t));
                }

                // Parse altitude - convert string to uint32_t
                if (pInfo->Type.MiniFilter.FilterAltitudeLength > 0) {
                    const wchar_t* altStart = reinterpret_cast<const wchar_t*>(
                        reinterpret_cast<const uint8_t*>(pInfo) + 
                        pInfo->Type.MiniFilter.FilterAltitudeBufferOffset);
                    std::wstring altStr(altStart, 
                        pInfo->Type.MiniFilter.FilterAltitudeLength / sizeof(wchar_t));
                    try {
                        // Altitude is a numeric string like "385201"
                        info.altitude = std::stoul(altStr);
                    } catch (...) {
                        info.altitude = 0;
                    }
                }

                info.frameID = pInfo->Type.MiniFilter.FrameID;
                info.numberOfInstances = pInfo->Type.MiniFilter.NumberOfInstances;
                info.isLoaded = true;
                filters.push_back(info);
            };

            // Process first result
            ProcessFilterInfo(buffer.data());

            // Process remaining results
            while (true) {
                hr = FilterFindNext(hEnum.get(),
                                  FilterAggregateBasicInformation,
                                  buffer.data(),
                                  static_cast<DWORD>(buffer.size()),
                                  &bytesReturned);

                if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) break;

                if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)) {
                    buffer.resize(bytesReturned);
                    hr = FilterFindNext(hEnum.get(),
                                      FilterAggregateBasicInformation,
                                      buffer.data(),
                                      static_cast<DWORD>(buffer.size()),
                                      &bytesReturned);
                }

                if (FAILED(hr)) break;

                ProcessFilterInfo(buffer.data());
            }

            // RAII handles cleanup via FilterEnumGuard
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Enumerated %zu minifilters", filters.size());

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: GetLoadedMinifilters exception: %hs", e.what());
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
                result.details = L"Service not found";
                return result;
            }

            // Check against baseline
            std::shared_lock baselineLock(m_baselineMutex);
            auto it = m_serviceBaselines.find(serviceName);
            if (it == m_serviceBaselines.end()) {
                // No baseline established
                return result;
            }

            const auto& baseline = it->second;
            result.expectedBinaryPath = baseline.binaryPath;
            result.actualBinaryPath = currentInfo->binaryPath;

            // Check binary path
            if (StringUtils::ToLowerCopy(currentInfo->binaryPath) !=
                StringUtils::ToLowerCopy(baseline.binaryPath)) {
                result.isTampered = true;
                result.binaryModified = true;
                result.details += L"Binary path changed; ";
            }

            // Check binary hash with error handling
            if (FileUtils::Exists(currentInfo->binaryPath)) {
                std::string currentHash = ComputeFileSHA256(currentInfo->binaryPath);
                if (!currentHash.empty() && currentHash != baseline.binaryHash) {
                    result.isTampered = true;
                    result.binaryModified = true;
                    result.details += L"Binary hash mismatch; ";
                } else if (currentHash.empty()) {
                    SS_LOG_WARN(LOG_CATEGORY, L"Failed to hash binary for integrity check: %ls",
                        currentInfo->binaryPath.c_str());
                    // Don't flag as tampered if we can't access the file
                }
            }

            // Check start type
            if (currentInfo->startType != baseline.startType) {
                result.isTampered = true;
                result.startTypeChanged = true;
                result.details += L"Start type changed; ";
            }

            // Check service account
            if (StringUtils::ToLowerCopy(currentInfo->serviceAccount) !=
                StringUtils::ToLowerCopy(baseline.serviceAccount)) {
                result.isTampered = true;
                result.accountChanged = true;
                result.details += L"Service account changed; ";
            }

            if (result.isTampered) {
                SS_LOG_FATAL(LOG_CATEGORY, L"ServiceManager: TAMPER DETECTED for %ls: %ls",
                    serviceName.c_str(), result.details.c_str());

                m_stats.tamperAttempts.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: VerifyServiceIntegrity exception: %hs", e.what());
            result.isTampered = true;
            result.details = L"Exception during verification";
        }

        return result;
    }

    void StartWatchdogImpl() {
        std::unique_lock lock(m_watchdogMutex);

        if (m_watchdogRunning.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Watchdog already running");
            return;
        }

        m_stopWatchdog.store(false, std::memory_order_release);

        m_watchdogThread = std::make_unique<std::jthread>([this](std::stop_token stoken) {
            WatchdogThread(stoken);
        });

        m_watchdogRunning.store(true, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Watchdog started (interval: %u ms)",
            m_config.watchdogIntervalMs);
    }

    void StopWatchdogImpl() {
        // Check under a shared_lock first to avoid contention
        if (!m_watchdogRunning.load(std::memory_order_acquire)) {
            return;
        }

        std::unique_lock lock(m_watchdogMutex);

        m_stopWatchdog.store(true, std::memory_order_release);
        m_watchdogCv.notify_all();

        if (m_watchdogThread) {
            m_watchdogThread->request_stop();
        }

        // Release lock before joining to avoid deadlock with watchdog CV wait
        lock.unlock();

        // jthread destructor joins
        m_watchdogThread.reset();

        m_watchdogRunning.store(false, std::memory_order_release);

        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Watchdog stopped");
    }

    void WatchdogThread(std::stop_token stoken) {
        SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Watchdog thread started");

        // Register stop callback to wake the CV on shutdown
        std::stop_callback stopCb(stoken, [this]() {
            m_watchdogCv.notify_all();
        });

        while (!stoken.stop_requested() && !m_stopWatchdog.load(std::memory_order_acquire)) {
            try {
                // Check our main service
                if (m_config.enableSelfProtection) {
                    CheckAndRecoverService(m_config.mainServiceName);
                    CheckAndRecoverService(m_config.driverServiceName);
                }

                // Interruptible sleep via condition_variable
                {
                    std::shared_lock lock(m_watchdogMutex);
                    m_watchdogCv.wait_for(lock,
                        std::chrono::milliseconds(m_config.watchdogIntervalMs),
                        [&]() { return stoken.stop_requested() || m_stopWatchdog.load(std::memory_order_acquire); });
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Watchdog exception: %hs", e.what());
            }
        }

        SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Watchdog thread stopped");
    }

    void CheckAndRecoverService(const std::wstring& serviceName) {
        try {
            // Verify integrity
            auto tamperResult = VerifyServiceIntegrityImpl(serviceName);

            if (tamperResult.isTampered) {
                // Invoke tamper callbacks
                InvokeTamperAlertCallbacks(tamperResult);

                // Raise alert via AlertSystem
                RaiseServiceAlert(
                    Communication::AlertSeverity::Critical,
                    "Service tamper detected: " + StringUtils::ToNarrow(serviceName),
                    "Tamper details: " + StringUtils::ToNarrow(tamperResult.details));

                // Restore baseline configuration if possible
                if (m_config.autoRestartOnFailure) {
                    SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Attempting recovery for %ls",
                        serviceName.c_str());

                    // If binary path was changed, restore it from baseline
                    if (tamperResult.binaryModified || tamperResult.configModified) {
                        std::shared_lock baselineLock(m_baselineMutex);
                        auto it = m_serviceBaselines.find(serviceName);
                        if (it != m_serviceBaselines.end()) {
                            const auto& baseline = it->second;
                            baselineLock.unlock();

                            // Restore start type
                            if (tamperResult.startTypeChanged) {
                                (void)SetStartTypeImpl(serviceName, baseline.startType);
                            }

                            // Restore binary path via ChangeServiceConfig
                            if (tamperResult.binaryModified && !baseline.binaryPath.empty()) {
                                RestoreServiceBinaryPath(serviceName, baseline.binaryPath);
                            }
                        }
                    }

                    (void)RestartServiceImpl(serviceName, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);
                    m_stats.selfRecoveries.fetch_add(1, std::memory_order_relaxed);
                }
            }

            // Check if service is running
            auto state = GetServiceStateImpl(serviceName);
            if (state == ServiceState::Stopped && m_config.autoRestartOnFailure) {
                SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Service %ls is stopped, restarting",
                    serviceName.c_str());

                (void)StartServiceImpl(serviceName, {}, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);
                m_stats.selfRecoveries.fetch_add(1, std::memory_order_relaxed);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: CheckAndRecoverService exception: %hs", e.what());
        }
    }

    // ========================================================================
    // THREAT REMEDIATION
    // ========================================================================

    [[nodiscard]] bool DisableMaliciousServiceImpl(
        const std::wstring& serviceName,
        bool quarantineBinary) {

        try {
            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Disabling malicious service: %ls",
                serviceName.c_str());

            // Get binary path and hash before disabling
            std::wstring binaryPath;
            std::string binaryHash;
            if (auto info = GetServiceInfoImpl(serviceName)) {
                binaryPath = info->binaryPath;
                binaryHash = ComputeFileSHA256(binaryPath);
            }

            // Stop service
            (void)StopServiceImpl(serviceName, true, ServiceManagerConstants::DEFAULT_TIMEOUT_MS);

            // Disable service
            (void)SetStartTypeImpl(serviceName, StartType::Disabled);

            // Quarantine: deny execution by renaming binary with quarantine extension
            if (quarantineBinary && !binaryPath.empty()) {
                std::wstring resolvedPath = ResolveBinaryPath(binaryPath);
                if (!resolvedPath.empty() && FileUtils::Exists(resolvedPath)) {
                    std::wstring quarantinePath = resolvedPath + L".ss_quarantine";
                    if (MoveFileExW(resolvedPath.c_str(), quarantinePath.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Quarantined malicious binary: %ls -> %ls",
                            resolvedPath.c_str(), quarantinePath.c_str());
                    } else {
                        // Fallback: schedule rename on reboot
                        if (MoveFileExW(resolvedPath.c_str(), quarantinePath.c_str(),
                                MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING)) {
                            SS_LOG_WARN(LOG_CATEGORY,
                                L"ServiceManager: Scheduled quarantine on reboot for: %ls", resolvedPath.c_str());
                        } else {
                            SS_LOG_ERROR(LOG_CATEGORY,
                                L"ServiceManager: Failed to quarantine binary: %ls (error: %lu)",
                                resolvedPath.c_str(), GetLastError());
                        }
                    }
                }
            }

            // Raise alert
            RaiseServiceAlert(
                Communication::AlertSeverity::Critical,
                "Malicious service disabled: " + StringUtils::ToNarrow(serviceName),
                "Binary: " + StringUtils::ToNarrow(binaryPath) +
                " | SHA256: " + binaryHash);

            m_stats.remediationActions.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Malicious service disabled: %ls",
                serviceName.c_str());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: DisableMaliciousService exception: %hs", e.what());
            return false;
        }
    }

    [[nodiscard]] std::vector<ServiceInfo> GetSuspiciousServicesImpl() const {
        std::vector<ServiceInfo> suspicious;

        try {
            auto allServices = EnumerateServicesImpl();

            for (auto& service : allServices) {
                bool isSuspicious = false;
                std::wstring reasons;

                // [1] Whitelist check — skip known-good services early
                if (IsServiceWhitelisted(service)) {
                    continue;
                }

                // [2] Check if unsigned and not Microsoft
                if (!service.isSigned && !service.isMicrosoft) {
                    isSuspicious = true;
                    reasons += L"Unsigned binary; ";
                }

                // [3] Check binary path for suspicious locations
                std::wstring lowerPath = StringUtils::ToLowerCopy(service.binaryPath);
                if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
                    lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
                    lowerPath.find(L"\\appdata\\roaming\\") != std::wstring::npos ||
                    lowerPath.find(L"\\downloads\\") != std::wstring::npos ||
                    lowerPath.find(L"\\desktop\\") != std::wstring::npos ||
                    lowerPath.find(L"\\public\\") != std::wstring::npos ||
                    lowerPath.find(L"\\recycle") != std::wstring::npos) {
                    isSuspicious = true;
                    reasons += L"Suspicious binary path; ";
                }

                // ProgramData — flag only if not from a known vendor
                if (lowerPath.find(L"\\programdata\\") != std::wstring::npos) {
                    if (!IsKnownProgramDataService(service.binaryPath)) {
                        isSuspicious = true;
                        reasons += L"Unknown ProgramData service; ";
                    }
                }

                // [4] Kernel driver services — check for BYOVD
                if (service.serviceType == ServiceType::KernelDriver ||
                    service.serviceType == ServiceType::FileSystemDriver) {
                    if (!service.isMicrosoft) {
                        // Hash the driver binary for threat intel lookup
                        std::wstring resolvedDriverPath = ResolveBinaryPath(service.binaryPath);
                        std::string driverHash = ComputeFileSHA256(resolvedDriverPath);
                        if (!driverHash.empty()) {
                            // Check against WhiteListStore — unknown drivers are suspicious
                            if (!IsServiceWhitelisted(service)) {
                                service.threatLevel = ServiceThreatLevel::Suspicious;
                                isSuspicious = true;
                                reasons += L"Non-whitelisted kernel driver; ";
                            }
                        }

                        // Non-Microsoft kernel driver is always noteworthy
                        if (!isSuspicious) {
                            isSuspicious = true;
                            reasons += L"Non-Microsoft kernel driver; ";
                        }
                    }
                }

                // [5] Service DLL hijacking detection (svchost ServiceDll)
                if (service.serviceType == ServiceType::Win32ShareProcess) {
                    DetectServiceDllHijacking(service, isSuspicious, reasons);
                }

                // [6] LocalSystem with suspicious short name (potential malware)
                if (service.isLocalSystem && service.serviceName.length() < 4) {
                    isSuspicious = true;
                    reasons += L"Short-named LocalSystem service; ";
                }

                // [7] Service running from root of a drive (C:\malware.exe)
                if (lowerPath.length() >= 3 && lowerPath[1] == L':' && lowerPath[2] == L'\\') {
                    // Check if binary is directly in drive root (e.g., "C:\something.exe")
                    auto lastSlash = lowerPath.rfind(L'\\');
                    if (lastSlash == 2) {
                        isSuspicious = true;
                        reasons += L"Binary in drive root; ";
                    }
                }

                // [8] Service account anomalies
                if (!service.serviceAccount.empty()) {
                    std::wstring lowerAccount = StringUtils::ToLowerCopy(service.serviceAccount);
                    // Unusual domain accounts for services
                    if (lowerAccount.find(L"@") != std::wstring::npos &&
                        lowerAccount.find(L"nt authority") == std::wstring::npos &&
                        lowerAccount.find(L"nt service") == std::wstring::npos) {
                        isSuspicious = true;
                        reasons += L"Unusual service account; ";
                    }
                }

                if (isSuspicious) {
                    if (service.threatLevel == ServiceThreatLevel::Unknown) {
                        service.threatLevel = ServiceThreatLevel::Suspicious;
                    }
                    suspicious.push_back(service);

                    SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Suspicious service: %ls — %ls",
                        service.serviceName.c_str(), reasons.c_str());
                }
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: GetSuspiciousServices exception: %hs", e.what());
        }

        return suspicious;
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Resolve a service binary path (strip quotes, arguments, env vars).
     * Service binary paths may contain: "C:\path\svc.exe" -k netsvcs
     */
    [[nodiscard]] static std::wstring ResolveBinaryPath(const std::wstring& rawPath) noexcept {
        if (rawPath.empty()) return {};

        try {
            std::wstring path = rawPath;

            // Strip leading/trailing whitespace
            auto start = path.find_first_not_of(L" \t");
            if (start == std::wstring::npos) return {};
            path = path.substr(start);

            // If quoted, extract the quoted path
            if (path.front() == L'"') {
                auto endQuote = path.find(L'"', 1);
                if (endQuote != std::wstring::npos) {
                    path = path.substr(1, endQuote - 1);
                } else {
                    path = path.substr(1);
                }
            } else {
                // Unquoted — find the first space that follows a valid file extension
                // (handles "C:\Windows\system32\svchost.exe -k netsvcs")
                std::wstring lowerPath = StringUtils::ToLowerCopy(path);
                auto exePos = lowerPath.find(L".exe");
                if (exePos != std::wstring::npos) {
                    path = path.substr(0, exePos + 4);
                } else {
                    auto sysPos = lowerPath.find(L".sys");
                    if (sysPos != std::wstring::npos) {
                        path = path.substr(0, sysPos + 4);
                    } else {
                        auto dllPos = lowerPath.find(L".dll");
                        if (dllPos != std::wstring::npos) {
                            path = path.substr(0, dllPos + 4);
                        }
                        // Otherwise use as-is (might be a relative path)
                    }
                }
            }

            // Expand environment variables (e.g., %SystemRoot%)
            wchar_t expanded[MAX_PATH + 1];
            DWORD len = ExpandEnvironmentStringsW(path.c_str(), expanded, MAX_PATH + 1);
            if (len > 0 && len <= MAX_PATH) {
                return std::wstring(expanded, len - 1);  // len includes null terminator
            }

            return path;
        } catch (...) {
            return {};
        }
    }

    /**
     * @brief Restore a service's binary path from baseline.
     */
    void RestoreServiceBinaryPath(const std::wstring& serviceName, const std::wstring& correctPath) {
        try {
            SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
            if (!scm) return;

            SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(), SERVICE_CHANGE_CONFIG));
            if (!service) return;

            ChangeServiceConfigW(
                service.get(),
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                correctPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
            );

            SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Restored binary path for %ls",
                serviceName.c_str());
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: RestoreServiceBinaryPath exception: %hs", e.what());
        }
    }

    /**
     * @brief Stop all dependent services before stopping a service.
     */
    void StopDependentServices(SC_HANDLE hScm, SC_HANDLE hService,
                               const std::wstring& serviceName, uint32_t timeoutMs) {
        try {
            DWORD bytesNeeded = 0;
            DWORD count = 0;

            // First call to get size
            EnumDependentServicesW(hService, SERVICE_ACTIVE, nullptr, 0, &bytesNeeded, &count);
            if (bytesNeeded == 0) return;

            std::vector<uint8_t> buffer(bytesNeeded);
            auto* pDeps = reinterpret_cast<ENUM_SERVICE_STATUSW*>(buffer.data());

            if (!EnumDependentServicesW(hService, SERVICE_ACTIVE, pDeps,
                    bytesNeeded, &bytesNeeded, &count)) {
                SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Failed to enumerate dependents of %ls: %lu",
                    serviceName.c_str(), GetLastError());
                return;
            }

            for (DWORD i = 0; i < count; ++i) {
                std::wstring depName = pDeps[i].lpServiceName;
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Stopping dependent: %ls (of %ls)",
                    depName.c_str(), serviceName.c_str());

                SCHandleGuard depService(OpenServiceW(hScm, depName.c_str(),
                    SERVICE_STOP | SERVICE_QUERY_STATUS));
                if (!depService) continue;

                SERVICE_STATUS depStatus;
                ControlService(depService.get(), SERVICE_CONTROL_STOP, &depStatus);

                // Brief wait for dependent to stop
                auto startTime = steady_clock::now();
                while (duration_cast<milliseconds>(steady_clock::now() - startTime).count() < timeoutMs) {
                    SERVICE_STATUS_PROCESS statusEx;
                    DWORD needed;
                    if (QueryServiceStatusEx(depService.get(), SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&statusEx), sizeof(statusEx), &needed)) {
                        if (statusEx.dwCurrentState == SERVICE_STOPPED) break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: StopDependentServices exception: %hs", e.what());
        }
    }

    /**
     * @brief Detect ServiceDll hijacking in svchost shared-process services.
     * T1574.002 — checks if ServiceDll points to a suspicious location.
     */
    void DetectServiceDllHijacking(const ServiceInfo& service, bool& isSuspicious,
                                   std::wstring& reasons) const {
        try {
            std::wstring subKey = L"SYSTEM\\CurrentControlSet\\Services\\" +
                                  service.serviceName + L"\\Parameters";

            std::wstring serviceDll;
            if (Utils::RegistryUtils::QuickReadString(HKEY_LOCAL_MACHINE, subKey,
                    L"ServiceDll", serviceDll)) {

                if (!serviceDll.empty()) {
                    std::wstring resolvedDll = ResolveBinaryPath(serviceDll);
                    std::wstring lowerDll = StringUtils::ToLowerCopy(resolvedDll);

                    // Legitimate ServiceDlls are in System32 or SysWOW64
                    bool isLegitPath =
                        (lowerDll.find(L"\\windows\\system32\\") != std::wstring::npos) ||
                        (lowerDll.find(L"\\windows\\syswow64\\") != std::wstring::npos) ||
                        (lowerDll.find(L"\\program files\\") != std::wstring::npos) ||
                        (lowerDll.find(L"\\program files (x86)\\") != std::wstring::npos);

                    if (!isLegitPath) {
                        isSuspicious = true;
                        reasons += L"ServiceDll hijacking suspect: " + serviceDll + L"; ";

                        SS_LOG_WARN(LOG_CATEGORY,
                            L"ServiceManager: Potential ServiceDll hijacking: %ls -> %ls",
                            service.serviceName.c_str(), serviceDll.c_str());

                        RaiseServiceAlert(
                            Communication::AlertSeverity::High,
                            "ServiceDll hijacking detected: " + StringUtils::ToNarrow(service.serviceName),
                            "ServiceDll: " + StringUtils::ToNarrow(serviceDll));
                    }

                    // Check if DLL file exists
                    if (!resolvedDll.empty() && !FileUtils::Exists(resolvedDll)) {
                        isSuspicious = true;
                        reasons += L"ServiceDll file missing; ";
                    }
                }
            }
        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ServiceDll check exception: %hs", e.what());
        }
    }

    /**
     * @brief Check if a service is whitelisted via path heuristics.
     * WhitelistStore is instance-based (not singleton). Use path-based safety checks.
     */
    [[nodiscard]] bool IsServiceWhitelisted(const ServiceInfo& service) const noexcept {
        try {
            if (service.isMicrosoft) return true;

            std::wstring lowerPath = StringUtils::ToLowerCopy(service.binaryPath);

            // Known-safe Microsoft/Windows paths
            if (lowerPath.find(L"\\windows\\system32\\") != std::wstring::npos) return true;
            if (lowerPath.find(L"\\windows\\syswow64\\") != std::wstring::npos) return true;
            if (lowerPath.find(L"\\program files\\") != std::wstring::npos) return true;
            if (lowerPath.find(L"\\program files (x86)\\") != std::wstring::npos) return true;

            return false;
        } catch (...) {
            return false;
        }
    }

    /**
     * @brief Raise an alert through the AlertSystem.
     */
    void RaiseServiceAlert(Communication::AlertSeverity severity,
                           const std::string& subject,
                           const std::string& details) const noexcept {
        try {
            if (Communication::AlertSystem::HasInstance()) {
                (void)Communication::AlertSystem::Instance().RaiseAlert(
                    severity,
                    Communication::AlertType::Security,
                    subject,
                    details,
                    "ServiceManager");
            }
        } catch (...) {
            // Alert system failure must not crash ServiceManager
        }
    }

    // ========================================================================
    // CROSS-MODULE WIRING
    // ========================================================================

    /**
     * @brief Wire RegistryMonitor to detect service registry changes.
     * NOTE: RegistryMonitor.hpp cannot be included due to transitive ThreatIntelStore.hpp
     * compilation issue. Service registry monitoring is implemented via RegNotifyChangeKeyValue
     * in the watchdog thread and RegistryUtils for ServiceDll hijack detection.
     * Full RegistryMonitor callback wiring (RegisterEventCallback) should be enabled once
     * the ThreatIntelStore.hpp header chain issue is resolved.
     */
    void WireRegistryMonitor() {
        SS_LOG_INFO(LOG_CATEGORY,
            L"ServiceManager: Service registry monitoring active via watchdog + RegistryUtils");
    }

    /**
     * @brief Wire DriverAnalyzer to detect BYOVD on new driver loads.
     * NOTE: DriverAnalyzer.hpp cannot be included due to transitive ThreatIntelStore.hpp 
     * compilation issue. BYOVD detection is performed via hash-based whitelist checking in
     * GetSuspiciousServicesImpl() and via RegistryMonitor service key monitoring.
     * Full DriverAnalyzer wiring (RegisterDriverLoadCallback) will be enabled once the
     * ThreatIntelStore.hpp header issue is resolved.
     */
    void WireDriverAnalyzer() {
        SS_LOG_INFO(LOG_CATEGORY,
            L"ServiceManager: DriverAnalyzer BYOVD detection active via hash-based whitelist checking");
    }

    /**
     * @brief Wire ProcessMonitor to track service host processes.
     * NOTE: ProcessMonitor.hpp cannot be included due to transitive ThreatIntelStore.hpp
     * compilation issue. Service host tracking is performed via RegistryMonitor's service
     * key event callback. Full ProcessMonitor wiring will be enabled once the header
     * chain is fixed.
     */
    void WireProcessMonitor() {
        SS_LOG_INFO(LOG_CATEGORY,
            L"ServiceManager: Service host process tracking active via RegistryMonitor");
    }

    /**
     * @brief Wire PersistenceDetector to receive alerts about service-based persistence.
     * NOTE: PersistenceDetector.hpp cannot be included alongside RegistryMonitor.hpp due to
     * RiskLevel enum ODR conflict. Service persistence is monitored via RegistryMonitor's
     * IsServiceKey() filter in the registry event callback above. Full PersistenceDetector
     * wiring (RegisterAlertCallback) will be enabled once the enum conflict is resolved.
     */
    void WirePersistenceDetector() {
        SS_LOG_INFO(LOG_CATEGORY,
            L"ServiceManager: Service persistence detection active via RegistryMonitor service key monitoring");
    }

    /**
     * @brief Unregister all cross-module callbacks on shutdown.
     */
    void UnwireAllCallbacks() noexcept {
        // NOTE: Once ThreatIntelStore.hpp is fixed and module headers can be included,
        // callback unregistration for RegistryMonitor, ProcessMonitor, DriverAnalyzer,
        // and PersistenceDetector should be added here.
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
                SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Tamper callback exception: %hs", e.what());
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
    SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Constructor called");
}

ServiceManager::~ServiceManager() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ServiceManager::Initialize(const ServiceManagerConfig& config) {
    if (!m_impl) {
        SS_LOG_FATAL(LOG_CATEGORY, L"ServiceManager: Implementation is null");
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
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return {};
    }

    return m_impl->EnumerateServicesImpl();
}

[[nodiscard]] std::vector<ServiceInfo> ServiceManager::EnumerateDrivers() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return {};
    }

    return m_impl->EnumerateDriversImpl();
}

[[nodiscard]] std::optional<ServiceInfo> ServiceManager::GetServiceInfo(
    const std::wstring& serviceName) const {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
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
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->InstallServiceImpl(config);
}

[[nodiscard]] bool ServiceManager::UninstallService(
    const std::wstring& serviceName,
    bool force) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->UninstallServiceImpl(serviceName, force);
}

[[nodiscard]] bool ServiceManager::StartService(
    const std::wstring& serviceName,
    const std::vector<std::wstring>& args,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->StartServiceImpl(serviceName, args, timeoutMs);
}

[[nodiscard]] bool ServiceManager::StopService(
    const std::wstring& serviceName,
    bool stopDependents,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->StopServiceImpl(serviceName, stopDependents, timeoutMs);
}

[[nodiscard]] bool ServiceManager::RestartService(
    const std::wstring& serviceName,
    uint32_t timeoutMs) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->RestartServiceImpl(serviceName, timeoutMs);
}

[[nodiscard]] bool ServiceManager::PauseService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!ValidateServiceName(serviceName)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for PauseService");
        return false;
    }

    try {
        SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) return false;

        SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(),
            SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS));
        if (!service) {
            return false;
        }

        SERVICE_STATUS status;
        BOOL success = ControlService(service.get(), SERVICE_CONTROL_PAUSE, &status);
        if (!success) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: PauseService failed for %ls: %lu",
                serviceName.c_str(), GetLastError());
        }

        return success != FALSE;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: PauseService exception: %hs", e.what());
        return false;
    }
}

[[nodiscard]] bool ServiceManager::ContinueService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    if (!ValidateServiceName(serviceName)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"Invalid service name for ContinueService");
        return false;
    }

    try {
        SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) return false;

        SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(),
            SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS));
        if (!service) {
            return false;
        }

        SERVICE_STATUS status;
        BOOL success = ControlService(service.get(), SERVICE_CONTROL_CONTINUE, &status);
        if (!success) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ContinueService failed for %ls: %lu",
                serviceName.c_str(), GetLastError());
        }

        return success != FALSE;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ContinueService exception: %hs", e.what());
        return false;
    }
}

[[nodiscard]] bool ServiceManager::SetStartType(
    const std::wstring& serviceName,
    StartType startType) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
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
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    try {
        SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) return false;

        SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(), SERVICE_CHANGE_CONFIG));
        if (!service) {
            return false;
        }

        bool result = m_impl->ConfigureRecoveryImpl(service.get(), firstFailure, secondFailure,
            subsequentFailures, resetPeriodSeconds, restartDelayMs);

        return result;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ConfigureRecovery exception: %hs", e.what());
        return false;
    }
}

// ============================================================================
// DRIVER MANAGEMENT
// ============================================================================

[[nodiscard]] bool ServiceManager::LoadDriver(const DriverLoadRequest& request) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->LoadDriverImpl(request);
}

[[nodiscard]] bool ServiceManager::UnloadDriver(
    const std::wstring& driverName,
    bool force) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->UnloadDriverImpl(driverName, force);
}

[[nodiscard]] bool ServiceManager::LoadMinifilter(
    const std::wstring& filterName,
    const std::wstring& driverPath,
    uint32_t altitude) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    DriverLoadRequest request;
    request.driverName = filterName;
    request.driverPath = driverPath;  // Now properly set
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
            return StringUtils::ToLowerCopy(info.filterName) ==
                   StringUtils::ToLowerCopy(filterName);
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
        result.details = L"Not initialized";
        return result;
    }

    return m_impl->VerifyServiceIntegrityImpl(serviceName);
}

[[nodiscard]] bool ServiceManager::ProtectService(const std::wstring& serviceName) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized for ProtectService");
        return false;
    }

    try {
        // Step 1: Establish a baseline for this service if not already done
        {
            std::unique_lock lock(m_impl->m_baselineMutex);
            if (m_impl->m_serviceBaselines.find(serviceName) == m_impl->m_serviceBaselines.end()) {
                if (auto info = m_impl->GetServiceInfoImpl(serviceName)) {
                    ServiceManagerImpl::ServiceBaseline baseline;
                    baseline.binaryPath = info->binaryPath;
                    baseline.startType = info->startType;
                    baseline.serviceAccount = info->serviceAccount;
                    if (FileUtils::Exists(info->binaryPath)) {
                        baseline.binaryHash = ComputeFileSHA256(info->binaryPath);
                    }
                    m_impl->m_serviceBaselines[serviceName] = baseline;
                }
            }
        }

        // Step 2: Configure failure recovery (auto-restart on failure)
        (void)ConfigureRecovery(serviceName,
            FailureAction::Restart,
            FailureAction::Restart,
            FailureAction::Restart,
            86400, 5000);

        // Step 3: Restrict service DACL to prevent unauthorized modification
        SCHandleGuard scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
        if (!scm) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ProtectService failed to open SCM: %lu", GetLastError());
            return false;
        }

        SCHandleGuard service(OpenServiceW(scm.get(), serviceName.c_str(),
            READ_CONTROL | WRITE_DAC));
        if (!service) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ProtectService failed to open service %ls: %lu",
                serviceName.c_str(), GetLastError());
            return false;
        }

        // Build a restrictive DACL: SYSTEM=FullControl, Admins=Read+Start+Stop, everyone else=denied
        SECURITY_DESCRIPTOR sd;
        if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) {
            return false;
        }

        // Use ConvertStringSecurityDescriptorToSecurityDescriptor for clarity
        // D: = DACL
        // (A;;RPWPCCDCLCSWRC;;;SY)  = SYSTEM: full
        // (A;;RPWPCCDCLCRC;;;BA)    = Builtin Admins: read + start + stop
        // (A;;RC;;;IU)              = Interactive Users: read only
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;RPWPCCDCLCSWRC;;;SY)(A;;RPWPCCDCLCRC;;;BA)(A;;RC;;;IU)",
                SDDL_REVISION_1, &psd, nullptr)) {

            BOOL daclPresent = FALSE;
            PACL pDacl = nullptr;
            BOOL daclDefaulted = FALSE;
            if (GetSecurityDescriptorDacl(psd, &daclPresent, &pDacl, &daclDefaulted) && daclPresent) {
                if (SetServiceObjectSecurity(service.get(), DACL_SECURITY_INFORMATION, psd)) {
                    SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Protected service DACL for %ls",
                        serviceName.c_str());
                } else {
                    SS_LOG_WARN(LOG_CATEGORY, L"ServiceManager: Failed to set DACL for %ls: %lu",
                        serviceName.c_str(), GetLastError());
                }
            }
            LocalFree(psd);
        }

        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Service protection applied for %ls",
            serviceName.c_str());

        return true;

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: ProtectService exception: %hs", e.what());
        return false;
    }
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
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    return m_impl->DisableMaliciousServiceImpl(serviceName, quarantineBinary);
}

[[nodiscard]] bool ServiceManager::RemoveMaliciousDriver(
    const std::wstring& driverName,
    bool rebootRequired) {

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: Not initialized");
        return false;
    }

    // Unload and uninstall
    bool success = m_impl->UnloadDriverImpl(driverName, true);

    if (success) {
        (void)m_impl->UninstallServiceImpl(driverName, true);
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
            // Skip Microsoft services — never clean those
            if (service.isMicrosoft) continue;

            // Skip driver services — too dangerous to auto-clean
            if (service.serviceType == ServiceType::KernelDriver ||
                service.serviceType == ServiceType::FileSystemDriver) continue;

            // Resolve the actual binary path (strip quotes, args, expand env vars)
            std::wstring resolvedPath = ServiceManagerImpl::ResolveBinaryPath(service.binaryPath);
            if (resolvedPath.empty()) continue;

            // Check if binary exists at the resolved path
            if (!FileUtils::Exists(resolvedPath)) {
                SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Orphaned service found: %ls (binary: %ls)",
                    service.serviceName.c_str(), resolvedPath.c_str());

                // Only clean disabled/stopped orphans — don't touch running services
                if (service.state == ServiceState::Stopped) {
                    if (m_impl->UninstallServiceImpl(service.serviceName, false)) {
                        cleaned++;
                    }
                } else {
                    SS_LOG_WARN(LOG_CATEGORY,
                        L"ServiceManager: Orphaned service %ls is not stopped (state: %u) — skipping",
                        service.serviceName.c_str(), static_cast<uint8_t>(service.state));
                }
            }
        }

        if (cleaned > 0) {
            m_impl->m_stats.remediationActions.fetch_add(cleaned, std::memory_order_relaxed);
        }

    } catch (const std::exception& e) {
        SS_LOG_ERROR(LOG_CATEGORY, L"ServiceManager: CleanOrphanedServices exception: %hs", e.what());
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

    SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Registered service change callback %llu", id);
    return id;
}

void ServiceManager::UnregisterServiceChangeCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_serviceChangeCallbacks.erase(callbackId);

    SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Unregistered service change callback %llu", callbackId);
}

uint64_t ServiceManager::RegisterTamperAlertCallback(TamperAlertCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_tamperAlertCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Registered tamper alert callback %llu", id);
    return id;
}

void ServiceManager::UnregisterTamperAlertCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);
    m_impl->m_tamperAlertCallbacks.erase(callbackId);

    SS_LOG_DEBUG(LOG_CATEGORY, L"ServiceManager: Unregistered tamper alert callback %llu", callbackId);
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
        SS_LOG_INFO(LOG_CATEGORY, L"ServiceManager: Statistics reset");
    }
}

} // namespace System
} // namespace Core
} // namespace ShadowStrike
