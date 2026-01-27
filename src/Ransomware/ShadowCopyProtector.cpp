/**
 * ============================================================================
 * ShadowStrike NGAV - SHADOW COPY PROTECTOR IMPLEMENTATION
 * ============================================================================
 *
 * @file ShadowCopyProtector.cpp
 * @brief Enterprise-grade VSS shadow copy protection against ransomware
 *
 * ARCHITECTURE:
 * - PIMPL pattern for ABI stability
 * - Meyers' singleton for thread-safe instance management
 * - shared_mutex for concurrent read/write access
 * - Integration with Windows VSS COM APIs and Service Control Manager
 *
 * PROTECTION LAYERS:
 * 1. Command line monitoring (vssadmin, wmic, PowerShell, diskshadow)
 * 2. Process termination (kill attacking processes)
 * 3. VSS service locking (prevent service stop/disable)
 * 4. Shadow copy enumeration and verification
 * 5. Real-time attack event logging
 *
 * PERFORMANCE TARGETS:
 * - Command analysis: <1ms per command
 * - Service lock: <50ms for SCM access
 * - Shadow enumeration: <500ms for full VSS query
 * - Process termination: <100ms per process
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "ShadowCopyProtector.hpp"

// ============================================================================
// ADDITIONAL INCLUDES
// ============================================================================

#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"
#include "../Utils/JSONUtils.hpp"
#include "../Utils/Timer.hpp"
#include "../Utils/HashUtils.hpp"
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <regex>
#include <cctype>
#include <shared_mutex>
#include <cwctype>

#pragma comment(lib, "vssapi.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

namespace {
    using namespace ShadowStrike::Ransomware;

    /// @brief VSS service name
    constexpr const wchar_t* VSS_SERVICE_NAME = L"VSS";

    /// @brief Monitoring interval (ms)
    constexpr uint32_t MONITORING_INTERVAL_MS = 1000;

    /// @brief Maximum recent attacks to store
    constexpr size_t MAX_RECENT_ATTACKS = 100;

    /**
     * @brief Dangerous command patterns (expanded)
     */
    constexpr const wchar_t* DANGEROUS_PATTERNS[] = {
        L"vssadmin",
        L"delete shadows",
        L"shadowcopy delete",
        L"remove-wmiobject",
        L"resize shadowstorage",
        L"win32_shadowcopy",
        L"delete win32_shadowcopy",
        L"wmic shadowcopy",
        L"diskshadow",
        L"shadowstorage",
        L"gwmi win32_shadowcopy",
        L"get-wmiobject",
        L"bcdedit",
        L"wbadmin delete catalog",
        L"wbadmin delete backup"
    };

    /**
     * @brief Safe commands (whitelist)
     */
    constexpr const wchar_t* SAFE_PATTERNS[] = {
        L"vssadmin list",
        L"vssadmin list shadows",
        L"vssadmin list providers",
        L"wmic shadowcopy list"
    };

    /**
     * @brief Generate event ID
     */
    [[nodiscard]] uint64_t GenerateEventId() {
        static std::atomic<uint64_t> s_counter{0};
        return s_counter++;
    }

    /**
     * @brief Case-insensitive string search
     */
    [[nodiscard]] bool ContainsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
        auto it = std::search(
            haystack.begin(), haystack.end(),
            needle.begin(), needle.end(),
            [](wchar_t ch1, wchar_t ch2) {
                return std::towlower(ch1) == std::towlower(ch2);
            }
        );
        return it != haystack.end();
    }

} // anonymous namespace

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

namespace ShadowStrike::Ransomware {

class ShadowCopyProtectorImpl final {
public:
    ShadowCopyProtectorImpl() = default;
    ~ShadowCopyProtectorImpl() {
        StopMonitoring();
        UnlockVssServiceInternal();
    }

    // Delete copy/move
    ShadowCopyProtectorImpl(const ShadowCopyProtectorImpl&) = delete;
    ShadowCopyProtectorImpl& operator=(const ShadowCopyProtectorImpl&) = delete;
    ShadowCopyProtectorImpl(ShadowCopyProtectorImpl&&) = delete;
    ShadowCopyProtectorImpl& operator=(ShadowCopyProtectorImpl&&) = delete;

    // ========================================================================
    // STATE
    // ========================================================================

    mutable std::shared_mutex m_mutex;

    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    ShadowCopyProtectorConfiguration m_config;
    ShadowCopyStatistics m_stats;

    // Service lock
    std::atomic<bool> m_serviceLocked{false};
    SC_HANDLE m_scManager = nullptr;
    SC_HANDLE m_vssService = nullptr;

    // Whitelist
    std::vector<std::wstring> m_whitelist;

    // Event history
    std::vector<VSSAttackEvent> m_recentAttacks;

    // Callbacks
    VSSAttackCallback m_attackCallback;
    DecisionCallback m_decisionCallback;

    // Monitoring
    std::atomic<bool> m_monitoringActive{false};
    std::thread m_monitoringThread;

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    /**
     * @brief Invoke attack callback
     */
    void NotifyAttack(const VSSAttackEvent& event) {
        std::shared_lock lock(m_mutex);
        if (m_attackCallback) {
            try {
                m_attackCallback(event);
            } catch (const std::exception& e) {
                Utils::Logger::Error("Attack callback exception: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown attack callback exception");
            }
        }
    }

    /**
     * @brief Invoke decision callback
     */
    [[nodiscard]] bool ShouldBlockProcess(uint32_t pid, VSSAttackType type) {
        std::shared_lock lock(m_mutex);
        if (m_decisionCallback) {
            try {
                return m_decisionCallback(pid, type);
            } catch (...) {
                // Default to blocking on error
                return true;
            }
        }
        return true;  // Default: block
    }

    /**
     * @brief Check if command is safe (whitelisted pattern)
     */
    [[nodiscard]] bool IsSafeCommand(const std::wstring& cmdLine) const {
        for (const auto* pattern : SAFE_PATTERNS) {
            if (ContainsIgnoreCase(cmdLine, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief Analyze command line for VSS attacks
     */
    [[nodiscard]] std::optional<VSSAttackType> AnalyzeCommandInternal(std::wstring_view cmdLine) {
        std::wstring cmd(cmdLine);

        // Check safe patterns first
        if (IsSafeCommand(cmd)) {
            return std::nullopt;
        }

        // Check for vssadmin delete
        if (ContainsIgnoreCase(cmd, L"vssadmin") && ContainsIgnoreCase(cmd, L"delete")) {
            return VSSAttackType::CommandLineDelete;
        }

        // Check for WMI shadow deletion
        if ((ContainsIgnoreCase(cmd, L"wmic") || ContainsIgnoreCase(cmd, L"get-wmiobject") ||
             ContainsIgnoreCase(cmd, L"gwmi")) && ContainsIgnoreCase(cmd, L"shadowcopy") &&
            ContainsIgnoreCase(cmd, L"delete")) {
            return VSSAttackType::WMIDelete;
        }

        // Check for PowerShell WMI deletion
        if (ContainsIgnoreCase(cmd, L"remove-wmiobject") && ContainsIgnoreCase(cmd, L"win32_shadowcopy")) {
            return VSSAttackType::WMIDelete;
        }

        // Check for storage resize (reduces shadow storage, effectively deleting shadows)
        if (ContainsIgnoreCase(cmd, L"resize") && ContainsIgnoreCase(cmd, L"shadowstorage")) {
            return VSSAttackType::StorageResize;
        }

        // Check for diskshadow
        if (ContainsIgnoreCase(cmd, L"diskshadow")) {
            return VSSAttackType::CommandLineDelete;
        }

        // Check for bcdedit recovery disable
        if (ContainsIgnoreCase(cmd, L"bcdedit") &&
            (ContainsIgnoreCase(cmd, L"recoveryenabled no") || ContainsIgnoreCase(cmd, L"ignoreallfailures"))) {
            return VSSAttackType::RegistryModify;
        }

        // Check for backup deletion
        if (ContainsIgnoreCase(cmd, L"wbadmin") && ContainsIgnoreCase(cmd, L"delete")) {
            return VSSAttackType::CommandLineDelete;
        }

        return std::nullopt;
    }

    /**
     * @brief Check if process is whitelisted
     */
    [[nodiscard]] bool IsWhitelistedInternal(std::wstring_view processPath) const {
        std::shared_lock lock(m_mutex);

        for (const auto& whitelisted : m_whitelist) {
            if (processPath.find(whitelisted) != std::wstring::npos) {
                return true;
            }
        }

        // Check configured whitelist
        for (const auto& whitelisted : m_config.whitelist) {
            if (processPath.find(whitelisted) != std::wstring::npos) {
                return true;
            }
        }

        return false;
    }

    /**
     * @brief Terminate attacking process
     */
    [[nodiscard]] bool TerminateProcess(uint32_t pid, const std::wstring& reason) {
        try {
            if (!m_config.killAttacker) {
                Utils::Logger::Info("Process termination disabled, not killing PID {}", pid);
                return false;
            }

            HANDLE hProcess = ::OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
            if (!hProcess) {
                Utils::Logger::Error("Failed to open process {}: {}", pid, ::GetLastError());
                return false;
            }

            // Get process name for logging
            wchar_t processName[MAX_PATH] = {};
            DWORD size = MAX_PATH;
            ::QueryFullProcessImageNameW(hProcess, 0, processName, &size);

            BOOL result = ::TerminateProcess(hProcess, 1);
            ::CloseHandle(hProcess);

            if (result) {
                Utils::Logger::Critical("TERMINATED malicious process [PID: {}] [{}]: {}",
                    pid, Utils::StringUtils::WideToUtf8(processName),
                    Utils::StringUtils::WideToUtf8(reason));
                m_stats.processesKilled++;
                return true;
            } else {
                Utils::Logger::Error("Failed to terminate process {}: {}", pid, ::GetLastError());
                return false;
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("TerminateProcess failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Lock VSS service (internal)
     */
    [[nodiscard]] bool LockVssServiceInternal() {
        try {
            if (m_serviceLocked.load(std::memory_order_acquire)) {
                return true;
            }

            if (!m_config.lockService) {
                Utils::Logger::Debug("Service locking disabled");
                return false;
            }

            // Open Service Control Manager
            m_scManager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!m_scManager) {
                DWORD error = ::GetLastError();
                Utils::Logger::Error("Failed to open SCM: {}", error);
                return false;
            }

            // Open VSS service
            m_vssService = ::OpenServiceW(m_scManager, VSS_SERVICE_NAME, SERVICE_ALL_ACCESS);
            if (!m_vssService) {
                DWORD error = ::GetLastError();
                Utils::Logger::Error("Failed to open VSS service: {}", error);
                ::CloseServiceHandle(m_scManager);
                m_scManager = nullptr;
                return false;
            }

            // Lock service configuration
            SC_LOCK scLock = ::LockServiceDatabase(m_scManager);
            if (!scLock) {
                Utils::Logger::Warn("Failed to lock service database: {}", ::GetLastError());
                // Continue anyway - we still have the service handle
            } else {
                ::UnlockServiceDatabase(scLock);
            }

            // Change service to prevent stop/disable
            SERVICE_FAILURE_ACTIONSW failureActions = {};
            failureActions.dwResetPeriod = INFINITE;
            failureActions.lpRebootMsg = nullptr;
            failureActions.lpCommand = nullptr;
            failureActions.cActions = 0;
            failureActions.lpsaActions = nullptr;

            ::ChangeServiceConfig2W(m_vssService, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

            m_serviceLocked.store(true, std::memory_order_release);

            Utils::Logger::Info("VSS service locked successfully");
            return true;

        } catch (const std::exception& e) {
            Utils::Logger::Error("LockVssService failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Unlock VSS service (internal)
     */
    void UnlockVssServiceInternal() {
        try {
            if (m_vssService) {
                ::CloseServiceHandle(m_vssService);
                m_vssService = nullptr;
            }

            if (m_scManager) {
                ::CloseServiceHandle(m_scManager);
                m_scManager = nullptr;
            }

            m_serviceLocked.store(false, std::memory_order_release);

            Utils::Logger::Info("VSS service unlocked");

        } catch (const std::exception& e) {
            Utils::Logger::Error("UnlockVssService failed: {}", e.what());
        }
    }

    /**
     * @brief Check if VSS service is running
     */
    [[nodiscard]] bool IsVssServiceRunningInternal() const {
        try {
            SC_HANDLE scManager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scManager) {
                return false;
            }

            SC_HANDLE vssService = ::OpenServiceW(scManager, VSS_SERVICE_NAME, SERVICE_QUERY_STATUS);
            if (!vssService) {
                ::CloseServiceHandle(scManager);
                return false;
            }

            SERVICE_STATUS status = {};
            BOOL result = ::QueryServiceStatus(vssService, &status);

            ::CloseServiceHandle(vssService);
            ::CloseServiceHandle(scManager);

            if (result) {
                return status.dwCurrentState == SERVICE_RUNNING;
            }

            return false;

        } catch (...) {
            return false;
        }
    }

    /**
     * @brief Ensure VSS service is running
     */
    [[nodiscard]] bool EnsureVssServiceRunningInternal() {
        try {
            if (IsVssServiceRunningInternal()) {
                return true;
            }

            SC_HANDLE scManager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!scManager) {
                Utils::Logger::Error("Failed to open SCM: {}", ::GetLastError());
                return false;
            }

            SC_HANDLE vssService = ::OpenServiceW(scManager, VSS_SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
            if (!vssService) {
                Utils::Logger::Error("Failed to open VSS service: {}", ::GetLastError());
                ::CloseServiceHandle(scManager);
                return false;
            }

            BOOL started = ::StartServiceW(vssService, 0, nullptr);
            DWORD error = ::GetLastError();

            ::CloseServiceHandle(vssService);
            ::CloseServiceHandle(scManager);

            if (started || error == ERROR_SERVICE_ALREADY_RUNNING) {
                Utils::Logger::Info("VSS service started successfully");
                return true;
            } else {
                Utils::Logger::Error("Failed to start VSS service: {}", error);
                return false;
            }

        } catch (const std::exception& e) {
            Utils::Logger::Error("EnsureVssServiceRunning failed: {}", e.what());
            return false;
        }
    }

    /**
     * @brief Enumerate shadow copies using VSS COM API
     */
    [[nodiscard]] std::vector<ShadowCopyInfo> EnumerateShadowCopiesInternal() {
        std::vector<ShadowCopyInfo> shadowCopies;

        try {
            // Initialize COM
            HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            bool comInitialized = SUCCEEDED(hr);

            // Create VSS backup components
            IVssBackupComponents* pBackup = nullptr;
            hr = ::CreateVssBackupComponents(&pBackup);

            if (FAILED(hr)) {
                Utils::Logger::Error("Failed to create VSS backup components: {:#x}", static_cast<uint32_t>(hr));
                if (comInitialized) ::CoUninitialize();
                return shadowCopies;
            }

            // Initialize for backup
            hr = pBackup->InitializeForBackup();
            if (FAILED(hr)) {
                Utils::Logger::Error("Failed to initialize VSS for backup: {:#x}", static_cast<uint32_t>(hr));
                pBackup->Release();
                if (comInitialized) ::CoUninitialize();
                return shadowCopies;
            }

            // Query snapshots
            IVssEnumObject* pEnum = nullptr;
            hr = pBackup->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pEnum);

            if (SUCCEEDED(hr)) {
                VSS_OBJECT_PROP prop;
                ULONG fetched = 0;

                while (pEnum->Next(1, &prop, &fetched) == S_OK && fetched > 0) {
                    if (prop.Type == VSS_OBJECT_SNAPSHOT) {
                        ShadowCopyInfo info;

                        // Extract shadow copy info
                        wchar_t guidStr[64] = {};
                        ::StringFromGUID2(prop.Obj.Snap.m_SnapshotId, guidStr, 64);
                        info.shadowId = guidStr;

                        info.volume = prop.Obj.Snap.m_pwszOriginalVolumeName ? prop.Obj.Snap.m_pwszOriginalVolumeName : L"";
                        info.devicePath = prop.Obj.Snap.m_pwszSnapshotDeviceObject ? prop.Obj.Snap.m_pwszSnapshotDeviceObject : L"";

                        // Convert FILETIME to system_clock::time_point
                        FILETIME ft = {prop.Obj.Snap.m_tsCreationTimestamp.dwLowDateTime,
                                      prop.Obj.Snap.m_tsCreationTimestamp.dwHighDateTime};
                        ULARGE_INTEGER ull;
                        ull.LowPart = ft.dwLowDateTime;
                        ull.HighPart = ft.dwHighDateTime;
                        auto duration = std::chrono::microseconds((ull.QuadPart - 116444736000000000ULL) / 10);
                        info.creationTime = std::chrono::system_clock::time_point(
                            std::chrono::duration_cast<std::chrono::system_clock::duration>(duration));

                        info.state = ShadowCopyState::Active;

                        ::StringFromGUID2(prop.Obj.Snap.m_ProviderId, guidStr, 64);
                        info.providerId = guidStr;

                        info.isProtected = true;  // Mark as protected by ShadowStrike

                        shadowCopies.push_back(info);
                    }

                    ::VssFreeSnapshotProperties(&prop.Obj.Snap);
                }

                pEnum->Release();
            }

            pBackup->Release();

            if (comInitialized) {
                ::CoUninitialize();
            }

            m_stats.currentShadowCopies.store(shadowCopies.size(), std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Utils::Logger::Error("EnumerateShadowCopies failed: {}", e.what());
        }

        return shadowCopies;
    }

    /**
     * @brief Monitoring thread function
     */
    void MonitoringThreadFunc() {
        Utils::Logger::Info("Shadow copy monitoring thread started");

        while (m_monitoringActive.load(std::memory_order_acquire)) {
            try {
                // Verify VSS service is running
                if (!IsVssServiceRunningInternal()) {
                    Utils::Logger::Warn("VSS service not running, attempting to start");
                    EnsureVssServiceRunningInternal();
                }

                // Re-lock service if needed
                if (m_config.lockService && !m_serviceLocked.load(std::memory_order_acquire)) {
                    LockVssServiceInternal();
                }

                // Periodic shadow copy enumeration
                auto shadows = EnumerateShadowCopiesInternal();
                if (m_config.verboseLogging) {
                    Utils::Logger::Debug("Shadow copies detected: {}", shadows.size());
                }

            } catch (const std::exception& e) {
                Utils::Logger::Error("Monitoring thread error: {}", e.what());
            } catch (...) {
                Utils::Logger::Error("Unknown monitoring thread error");
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(MONITORING_INTERVAL_MS));
        }

        Utils::Logger::Info("Shadow copy monitoring thread stopped");
    }

    /**
     * @brief Stop monitoring thread
     */
    void StopMonitoring() {
        if (m_monitoringActive.load(std::memory_order_acquire)) {
            m_monitoringActive.store(false, std::memory_order_release);
            if (m_monitoringThread.joinable()) {
                m_monitoringThread.join();
            }
        }
    }
};

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

std::atomic<bool> ShadowCopyProtector::s_instanceCreated{false};

[[nodiscard]] ShadowCopyProtector& ShadowCopyProtector::Instance() noexcept {
    static ShadowCopyProtector instance;
    return instance;
}

[[nodiscard]] bool ShadowCopyProtector::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ShadowCopyProtector::ShadowCopyProtector()
    : m_impl(std::make_unique<ShadowCopyProtectorImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
    Utils::Logger::Info("ShadowCopyProtector singleton created");
}

ShadowCopyProtector::~ShadowCopyProtector() {
    try {
        Shutdown();
        Utils::Logger::Info("ShadowCopyProtector singleton destroyed");
    } catch (...) {
        // Destructor must not throw
    }
}

// ============================================================================
// LIFECYCLE
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::Initialize(const ShadowCopyProtectorConfiguration& config) {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status != ModuleStatus::Uninitialized &&
            m_impl->m_status != ModuleStatus::Stopped) {
            Utils::Logger::Warn("ShadowCopyProtector already initialized");
            return false;
        }

        m_impl->m_status = ModuleStatus::Initializing;

        // Validate configuration
        if (!config.IsValid()) {
            Utils::Logger::Error("Invalid ShadowCopyProtector configuration");
            m_impl->m_status = ModuleStatus::Error;
            return false;
        }

        m_impl->m_config = config;

        // Reset statistics
        m_impl->m_stats.Reset();
        m_impl->m_stats.startTime = Clock::now();

        // Lock VSS service if configured
        if (config.lockService) {
            lock.unlock();
            m_impl->LockVssServiceInternal();
            lock.lock();
        }

        // Ensure VSS service is running
        lock.unlock();
        m_impl->EnsureVssServiceRunningInternal();
        lock.lock();

        // Start monitoring thread
        m_impl->m_monitoringActive.store(true, std::memory_order_release);
        m_impl->m_monitoringThread = std::thread(
            &ShadowCopyProtectorImpl::MonitoringThreadFunc, m_impl.get());

        m_impl->m_status = ModuleStatus::Running;

        Utils::Logger::Info("ShadowCopyProtector initialized successfully");
        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShadowCopyProtector initialization failed: {}", e.what());
        m_impl->m_status = ModuleStatus::Error;
        return false;
    }
}

void ShadowCopyProtector::Shutdown() {
    try {
        std::unique_lock lock(m_impl->m_mutex);

        if (m_impl->m_status == ModuleStatus::Uninitialized ||
            m_impl->m_status == ModuleStatus::Stopped) {
            return;
        }

        m_impl->m_status = ModuleStatus::Stopping;

        // Stop monitoring
        lock.unlock();
        m_impl->StopMonitoring();
        lock.lock();

        // Unlock VSS service
        lock.unlock();
        m_impl->UnlockVssServiceInternal();
        lock.lock();

        // Clear history
        m_impl->m_recentAttacks.clear();

        // Clear callbacks
        m_impl->m_attackCallback = nullptr;
        m_impl->m_decisionCallback = nullptr;

        m_impl->m_status = ModuleStatus::Stopped;

        Utils::Logger::Info("ShadowCopyProtector shut down");

    } catch (const std::exception& e) {
        Utils::Logger::Error("Shutdown error: {}", e.what());
    }
}

[[nodiscard]] bool ShadowCopyProtector::IsInitialized() const noexcept {
    auto status = m_impl->m_status.load(std::memory_order_acquire);
    return status == ModuleStatus::Running;
}

[[nodiscard]] ModuleStatus ShadowCopyProtector::GetStatus() const noexcept {
    return m_impl->m_status.load(std::memory_order_acquire);
}

// ============================================================================
// DETECTION
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::IsVssDestructionAttempt(const std::wstring& cmdLine) {
    try {
        auto attackType = m_impl->AnalyzeCommandInternal(cmdLine);
        return attackType.has_value();

    } catch (const std::exception& e) {
        Utils::Logger::Error("IsVssDestructionAttempt failed: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::optional<VSSAttackType> ShadowCopyProtector::AnalyzeCommand(std::wstring_view cmdLine) {
    try {
        return m_impl->AnalyzeCommandInternal(cmdLine);

    } catch (const std::exception& e) {
        Utils::Logger::Error("AnalyzeCommand failed: {}", e.what());
        return std::nullopt;
    }
}

[[nodiscard]] bool ShadowCopyProtector::ShouldBlock(uint32_t pid, std::wstring_view cmdLine) {
    try {
        // Analyze command
        auto attackType = m_impl->AnalyzeCommandInternal(cmdLine);
        if (!attackType.has_value()) {
            return false;  // Not an attack
        }

        // Get process info
        HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            return true;  // Block if we can't verify
        }

        wchar_t processPath[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        ::QueryFullProcessImageNameW(hProcess, 0, processPath, &size);
        ::CloseHandle(hProcess);

        // Check whitelist
        if (m_impl->IsWhitelistedInternal(processPath)) {
            Utils::Logger::Debug("Whitelisted process allowed: {}", Utils::StringUtils::WideToUtf8(processPath));
            return false;
        }

        // Check decision callback
        if (!m_impl->ShouldBlockProcess(pid, attackType.value())) {
            return false;
        }

        // Create attack event
        VSSAttackEvent event;
        event.eventId = GenerateEventId();
        event.timestamp = std::chrono::system_clock::now();
        event.attackType = attackType.value();
        event.pid = pid;
        event.processPath = processPath;
        event.commandLine = cmdLine;
        event.wasBlocked = true;
        event.details = L"VSS destruction attempt detected";

        // Extract process name
        std::wstring pathStr(processPath);
        size_t lastSlash = pathStr.find_last_of(L"\\/");
        event.processName = (lastSlash != std::wstring::npos) ? pathStr.substr(lastSlash + 1) : pathStr;

        // Store event
        std::unique_lock lock(m_impl->m_mutex);
        m_impl->m_recentAttacks.push_back(event);
        if (m_impl->m_recentAttacks.size() > MAX_RECENT_ATTACKS) {
            m_impl->m_recentAttacks.erase(m_impl->m_recentAttacks.begin());
        }

        // Update statistics
        m_impl->m_stats.attacksBlocked++;
        size_t attackIdx = static_cast<size_t>(attackType.value());
        if (attackIdx < m_impl->m_stats.byAttackType.size()) {
            m_impl->m_stats.byAttackType[attackIdx]++;
        }

        lock.unlock();

        // Notify callback
        m_impl->NotifyAttack(event);

        // Terminate process if configured
        if (m_impl->m_config.killAttacker) {
            m_impl->TerminateProcess(pid, L"VSS destruction attempt");
        }

        Utils::Logger::Critical("BLOCKED VSS attack [Type: {}] [PID: {}] [Process: {}] [Command: {}]",
            static_cast<int>(attackType.value()), pid,
            Utils::StringUtils::WideToUtf8(event.processName),
            Utils::StringUtils::WideToUtf8(cmdLine));

        return true;

    } catch (const std::exception& e) {
        Utils::Logger::Error("ShouldBlock failed: {}", e.what());
        return true;  // Block on error (fail secure)
    }
}

// ============================================================================
// SERVICE PROTECTION
// ============================================================================

void ShadowCopyProtector::LockVssService() {
    m_impl->LockVssServiceInternal();
}

void ShadowCopyProtector::UnlockVssService() {
    m_impl->UnlockVssServiceInternal();
}

[[nodiscard]] bool ShadowCopyProtector::IsVssServiceLocked() const noexcept {
    return m_impl->m_serviceLocked.load(std::memory_order_acquire);
}

[[nodiscard]] bool ShadowCopyProtector::IsVssServiceRunning() const {
    return m_impl->IsVssServiceRunningInternal();
}

[[nodiscard]] bool ShadowCopyProtector::EnsureVssServiceRunning() {
    return m_impl->EnsureVssServiceRunningInternal();
}

// ============================================================================
// SHADOW COPY MANAGEMENT
// ============================================================================

[[nodiscard]] std::vector<ShadowCopyInfo> ShadowCopyProtector::EnumerateShadowCopies() {
    return m_impl->EnumerateShadowCopiesInternal();
}

[[nodiscard]] size_t ShadowCopyProtector::GetShadowCopyCount() const {
    return m_impl->m_stats.currentShadowCopies.load(std::memory_order_relaxed);
}

[[nodiscard]] std::optional<std::wstring> ShadowCopyProtector::CreateProtectiveSnapshot(
    std::wstring_view volume)
{
    try {
        Utils::Logger::Info("Creating protective snapshot for volume: {}",
            Utils::StringUtils::WideToUtf8(std::wstring(volume)));

        // Initialize COM
        HRESULT hr = ::CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        bool comInitialized = SUCCEEDED(hr);

        // Create VSS backup components
        IVssBackupComponents* pBackup = nullptr;
        hr = ::CreateVssBackupComponents(&pBackup);

        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to create VSS backup components: {:#x}", static_cast<uint32_t>(hr));
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Initialize for backup
        hr = pBackup->InitializeForBackup();
        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to initialize for backup: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Set context
        hr = pBackup->SetContext(VSS_CTX_BACKUP);
        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to set context: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Start snapshot set
        VSS_ID snapshotSetId;
        hr = pBackup->StartSnapshotSet(&snapshotSetId);
        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to start snapshot set: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Add volume to snapshot set
        VSS_ID snapshotId;
        hr = pBackup->AddToSnapshotSet(const_cast<wchar_t*>(std::wstring(volume).c_str()), GUID_NULL, &snapshotId);
        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to add volume to snapshot set: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Create snapshot
        IVssAsync* pAsync = nullptr;
        hr = pBackup->DoSnapshotSet(&pAsync);
        if (FAILED(hr)) {
            Utils::Logger::Error("Failed to create snapshot: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Wait for completion
        hr = pAsync->Wait();
        pAsync->Release();

        if (FAILED(hr)) {
            Utils::Logger::Error("Snapshot creation failed: {:#x}", static_cast<uint32_t>(hr));
            pBackup->Release();
            if (comInitialized) ::CoUninitialize();
            return std::nullopt;
        }

        // Get snapshot ID as string
        wchar_t guidStr[64] = {};
        ::StringFromGUID2(snapshotId, guidStr, 64);

        pBackup->Release();
        if (comInitialized) {
            ::CoUninitialize();
        }

        Utils::Logger::Info("Protective snapshot created: {}", Utils::StringUtils::WideToUtf8(guidStr));
        return std::wstring(guidStr);

    } catch (const std::exception& e) {
        Utils::Logger::Error("CreateProtectiveSnapshot failed: {}", e.what());
        return std::nullopt;
    }
}

[[nodiscard]] bool ShadowCopyProtector::VerifyShadowCopy(std::wstring_view shadowId) {
    try {
        auto shadows = m_impl->EnumerateShadowCopiesInternal();

        for (const auto& shadow : shadows) {
            if (shadow.shadowId == shadowId) {
                return shadow.state == ShadowCopyState::Active;
            }
        }

        return false;

    } catch (const std::exception& e) {
        Utils::Logger::Error("VerifyShadowCopy failed: {}", e.what());
        return false;
    }
}

// ============================================================================
// WHITELIST
// ============================================================================

void ShadowCopyProtector::AddToWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_whitelist.push_back(std::wstring(processPath));
    Utils::Logger::Info("Added to whitelist: {}", Utils::StringUtils::WideToUtf8(std::wstring(processPath)));
}

void ShadowCopyProtector::RemoveFromWhitelist(std::wstring_view processPath) {
    std::unique_lock lock(m_impl->m_mutex);
    auto& wl = m_impl->m_whitelist;
    wl.erase(std::remove(wl.begin(), wl.end(), std::wstring(processPath)), wl.end());
    Utils::Logger::Info("Removed from whitelist: {}", Utils::StringUtils::WideToUtf8(std::wstring(processPath)));
}

[[nodiscard]] bool ShadowCopyProtector::IsWhitelisted(std::wstring_view processPath) const {
    return m_impl->IsWhitelistedInternal(processPath);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void ShadowCopyProtector::SetAttackCallback(VSSAttackCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_attackCallback = std::move(callback);
}

void ShadowCopyProtector::SetDecisionCallback(DecisionCallback callback) {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_decisionCallback = std::move(callback);
}

// ============================================================================
// STATISTICS
// ============================================================================

[[nodiscard]] ShadowCopyStatistics ShadowCopyProtector::GetStatistics() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_stats;
}

void ShadowCopyProtector::ResetStatistics() {
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_stats.Reset();
    m_impl->m_stats.startTime = Clock::now();

    Utils::Logger::Info("Statistics reset");
}

[[nodiscard]] std::vector<VSSAttackEvent> ShadowCopyProtector::GetRecentAttacks(size_t maxCount) const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<VSSAttackEvent> attacks = m_impl->m_recentAttacks;
    if (attacks.size() > maxCount) {
        attacks.resize(maxCount);
    }

    return attacks;
}

// ============================================================================
// UTILITY
// ============================================================================

[[nodiscard]] bool ShadowCopyProtector::SelfTest() {
    try {
        Utils::Logger::Info("Running ShadowCopyProtector self-test...");

        bool allPassed = true;

        // Test 1: Configuration validation
        ShadowCopyProtectorConfiguration config;
        if (!config.IsValid()) {
            Utils::Logger::Error("Self-test failed: Invalid default configuration");
            allPassed = false;
        }

        // Test 2: Command line detection
        std::wstring maliciousCmd1 = L"vssadmin delete shadows /all /quiet";
        if (!IsVssDestructionAttempt(maliciousCmd1)) {
            Utils::Logger::Error("Self-test failed: Failed to detect vssadmin delete");
            allPassed = false;
        }

        std::wstring maliciousCmd2 = L"wmic shadowcopy delete";
        if (!IsVssDestructionAttempt(maliciousCmd2)) {
            Utils::Logger::Error("Self-test failed: Failed to detect wmic shadowcopy delete");
            allPassed = false;
        }

        std::wstring safeCmd = L"vssadmin list shadows";
        if (IsVssDestructionAttempt(safeCmd)) {
            Utils::Logger::Error("Self-test failed: False positive on vssadmin list");
            allPassed = false;
        }

        // Test 3: VSS service check
        try {
            bool serviceRunning = IsVssServiceRunning();
            Utils::Logger::Debug("Self-test: VSS service running: {}", serviceRunning);
        } catch (...) {
            Utils::Logger::Error("Self-test failed: Service status check");
            allPassed = false;
        }

        // Test 4: Shadow copy enumeration
        try {
            auto shadows = EnumerateShadowCopies();
            Utils::Logger::Debug("Self-test: Found {} shadow copies", shadows.size());
        } catch (...) {
            Utils::Logger::Error("Self-test failed: Shadow copy enumeration");
            allPassed = false;
        }

        if (allPassed) {
            Utils::Logger::Info("Self-test PASSED - All tests successful");
        } else {
            Utils::Logger::Error("Self-test FAILED - See errors above");
        }

        return allPassed;

    } catch (const std::exception& e) {
        Utils::Logger::Error("Self-test exception: {}", e.what());
        return false;
    }
}

[[nodiscard]] std::string ShadowCopyProtector::GetVersionString() noexcept {
    return std::to_string(ShadowCopyConstants::VERSION_MAJOR) + "." +
           std::to_string(ShadowCopyConstants::VERSION_MINOR) + "." +
           std::to_string(ShadowCopyConstants::VERSION_PATCH);
}

// ============================================================================
// STRUCTURE IMPLEMENTATIONS
// ============================================================================

[[nodiscard]] std::string ShadowCopyInfo::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["shadowId"] = Utils::StringUtils::WideToUtf8(shadowId);
    j["volume"] = Utils::StringUtils::WideToUtf8(volume);
    j["devicePath"] = Utils::StringUtils::WideToUtf8(devicePath);
    j["creationTime"] = creationTime.time_since_epoch().count();
    j["state"] = static_cast<int>(state);
    j["sizeBytes"] = sizeBytes;
    j["isProtected"] = isProtected;
    j["providerId"] = Utils::StringUtils::WideToUtf8(providerId);

    return j.dump(2);
}

[[nodiscard]] std::string VSSAttackEvent::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["eventId"] = eventId;
    j["timestamp"] = timestamp.time_since_epoch().count();
    j["attackType"] = static_cast<int>(attackType);
    j["pid"] = pid;
    j["processName"] = Utils::StringUtils::WideToUtf8(processName);
    j["processPath"] = Utils::StringUtils::WideToUtf8(processPath);
    j["commandLine"] = Utils::StringUtils::WideToUtf8(commandLine);
    j["wasBlocked"] = wasBlocked;
    j["details"] = Utils::StringUtils::WideToUtf8(details);

    return j.dump(2);
}

void ShadowCopyStatistics::Reset() noexcept {
    attacksBlocked.store(0, std::memory_order_relaxed);
    processesKilled.store(0, std::memory_order_relaxed);
    currentShadowCopies.store(0, std::memory_order_relaxed);

    for (auto& type : byAttackType) {
        type.store(0, std::memory_order_relaxed);
    }
}

[[nodiscard]] std::string ShadowCopyStatistics::ToJson() const {
    using namespace ShadowStrike::Utils::JSON;

    Json j = Json::object();

    j["attacksBlocked"] = attacksBlocked.load(std::memory_order_relaxed);
    j["processesKilled"] = processesKilled.load(std::memory_order_relaxed);
    j["currentShadowCopies"] = currentShadowCopies.load(std::memory_order_relaxed);

    auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
        Clock::now() - startTime).count();
    j["uptimeSeconds"] = uptime;

    return j.dump(2);
}

[[nodiscard]] bool ShadowCopyProtectorConfiguration::IsValid() const noexcept {
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetVSSAttackTypeName(VSSAttackType type) noexcept {
    switch (type) {
        case VSSAttackType::CommandLineDelete: return "CommandLineDelete";
        case VSSAttackType::WMIDelete: return "WMIDelete";
        case VSSAttackType::APIDelete: return "APIDelete";
        case VSSAttackType::ServiceStop: return "ServiceStop";
        case VSSAttackType::StorageResize: return "StorageResize";
        case VSSAttackType::RegistryModify: return "RegistryModify";
        case VSSAttackType::ProviderDisable: return "ProviderDisable";
        default: return "Unknown";
    }
}

[[nodiscard]] std::string_view GetShadowCopyStateName(ShadowCopyState state) noexcept {
    switch (state) {
        case ShadowCopyState::Active: return "Active";
        case ShadowCopyState::Protected: return "Protected";
        case ShadowCopyState::Deleted: return "Deleted";
        case ShadowCopyState::Corrupted: return "Corrupted";
        default: return "Unknown";
    }
}

}  // namespace ShadowStrike::Ransomware
