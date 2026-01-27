/**
 * ============================================================================
 * ShadowStrike Security - PROCESS PROTECTION ENGINE
 * ============================================================================
 *
 * @file ProcessProtection.cpp
 * @brief Enterprise-grade process protection implementation for ShadowStrike
 *        antivirus user-mode processes and services.
 *
 * PURPOSE:
 * ========
 * This module protects ShadowStrike's user-land processes from being terminated,
 * suspended, injected into, or otherwise tampered with by malware. It works in
 * conjunction with the kernel-mode Shadow Sensor driver for comprehensive
 * protection.
 *
 * PROTECTION LAYERS:
 * ==================
 * - User-mode: Security descriptor hardening, handle filtering, integrity checks
 * - Kernel-mode: PPL elevation (via ELAM driver), ObRegisterCallbacks integration
 *
 * All tampering attempts are logged for SIEM integration and incident response.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2024
 * @copyright (c) 2024 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "pch.h"
#include "ProcessProtection.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <algorithm>
#include <numeric>
#include <sstream>
#include <iomanip>
#include <random>
#include <deque>

// ============================================================================
// WINDOWS SDK ADDITIONAL INCLUDES
// ============================================================================

#ifdef _WIN32
#pragma comment(lib, "advapi32.lib")

// NTDLL function typedefs
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);

typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* RtlSetProcessIsCritical_t)(
    BOOLEAN bNew,
    PBOOLEAN pbOld,
    BOOLEAN bNeedScmPermission
);

// Process information classes
constexpr PROCESSINFOCLASS ProcessBreakOnTermination = static_cast<PROCESSINFOCLASS>(29);
constexpr PROCESSINFOCLASS ProcessProtectionInformation = static_cast<PROCESSINFOCLASS>(61);

// Thread information class
constexpr THREADINFOCLASS ThreadHideFromDebugger = static_cast<THREADINFOCLASS>(17);

// PS_PROTECTION structure
#pragma pack(push, 1)
struct PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
};
#pragma pack(pop)

#endif // _WIN32

namespace ShadowStrike {
namespace Security {

// ============================================================================
// ANONYMOUS NAMESPACE FOR INTERNAL HELPERS
// ============================================================================

namespace {

/**
 * @brief Generate unique event ID
 */
[[nodiscard]] uint64_t GenerateEventId() noexcept {
    static std::atomic<uint64_t> s_eventCounter{0};
    return s_eventCounter.fetch_add(1, std::memory_order_relaxed);
}

/**
 * @brief Generate authorization token for internal use
 */
[[nodiscard]] std::string GenerateInternalAuthToken() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    std::ostringstream oss;
    oss << "SS_INTERNAL_" << std::hex << dist(gen) << dist(gen);
    return oss.str();
}

/**
 * @brief Get current thread ID
 */
[[nodiscard]] uint32_t GetCurrentThreadIdSafe() noexcept {
#ifdef _WIN32
    return ::GetCurrentThreadId();
#else
    return 0;
#endif
}

/**
 * @brief Get current process ID
 */
[[nodiscard]] uint32_t GetCurrentProcessIdSafe() noexcept {
#ifdef _WIN32
    return ::GetCurrentProcessId();
#else
    return 0;
#endif
}

/**
 * @brief Wide to narrow string conversion
 */
[[nodiscard]] std::string WideToNarrow(std::wstring_view wide) {
    if (wide.empty()) return {};

#ifdef _WIN32
    int size = ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                                      static_cast<int>(wide.size()),
                                      nullptr, 0, nullptr, nullptr);
    if (size <= 0) return {};

    std::string result(static_cast<size_t>(size), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wide.data(),
                          static_cast<int>(wide.size()),
                          result.data(), size, nullptr, nullptr);
    return result;
#else
    return std::string(wide.begin(), wide.end());
#endif
}

/**
 * @brief Narrow to wide string conversion
 */
[[nodiscard]] std::wstring NarrowToWide(std::string_view narrow) {
    if (narrow.empty()) return {};

#ifdef _WIN32
    int size = ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                                      static_cast<int>(narrow.size()),
                                      nullptr, 0);
    if (size <= 0) return {};

    std::wstring result(static_cast<size_t>(size), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, narrow.data(),
                          static_cast<int>(narrow.size()),
                          result.data(), size);
    return result;
#else
    return std::wstring(narrow.begin(), narrow.end());
#endif
}

/**
 * @brief Case-insensitive wide string comparison
 */
[[nodiscard]] bool WideStringEqualsIgnoreCase(std::wstring_view a, std::wstring_view b) noexcept {
    if (a.size() != b.size()) return false;

    for (size_t i = 0; i < a.size(); ++i) {
        if (std::towlower(a[i]) != std::towlower(b[i])) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Verify authorization token
 */
[[nodiscard]] bool VerifyAuthToken(std::string_view token) {
    // In production, this would verify against a secure token store
    // For now, accept internal tokens
    return token.find("SS_INTERNAL_") == 0 || token.find("SS_AUTH_") == 0;
}

/**
 * @brief Get process name from PID
 */
[[nodiscard]] std::wstring GetProcessName(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return {};

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;

    if (::QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        ::CloseHandle(hProcess);

        std::wstring fullPath = path;
        size_t pos = fullPath.find_last_of(L'\\');
        if (pos != std::wstring::npos) {
            return fullPath.substr(pos + 1);
        }
        return fullPath;
    }

    ::CloseHandle(hProcess);
#endif
    return {};
}

/**
 * @brief Get process image path from PID
 */
[[nodiscard]] std::wstring GetProcessImagePath(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return {};

    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;

    if (::QueryFullProcessImageNameW(hProcess, 0, path, &size)) {
        ::CloseHandle(hProcess);
        return path;
    }

    ::CloseHandle(hProcess);
#endif
    return {};
}

/**
 * @brief Check if process is elevated
 */
[[nodiscard]] bool IsProcessElevated(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return false;

    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        ::CloseHandle(hProcess);
        return false;
    }

    TOKEN_ELEVATION elevation = {};
    DWORD size = sizeof(elevation);

    bool isElevated = false;
    if (::GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
        isElevated = elevation.TokenIsElevated != 0;
    }

    ::CloseHandle(hToken);
    ::CloseHandle(hProcess);
    return isElevated;
#else
    return false;
#endif
}

/**
 * @brief Check if process is SYSTEM
 */
[[nodiscard]] bool IsSystemProcess(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return false;

    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        ::CloseHandle(hProcess);
        return false;
    }

    DWORD size = 0;
    ::GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);

    if (size == 0) {
        ::CloseHandle(hToken);
        ::CloseHandle(hProcess);
        return false;
    }

    std::vector<uint8_t> buffer(size);
    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(buffer.data());

    bool isSystem = false;
    if (::GetTokenInformation(hToken, TokenUser, pTokenUser, size, &size)) {
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        PSID pSystemSid = nullptr;

        if (::AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                       0, 0, 0, 0, 0, 0, 0, &pSystemSid)) {
            isSystem = ::EqualSid(pTokenUser->User.Sid, pSystemSid) != 0;
            ::FreeSid(pSystemSid);
        }
    }

    ::CloseHandle(hToken);
    ::CloseHandle(hProcess);
    return isSystem;
#else
    return false;
#endif
}

} // anonymous namespace

// ============================================================================
// PROCESS PROTECTION IMPLEMENTATION CLASS
// ============================================================================

/**
 * @class ProcessProtectionImpl
 * @brief PIMPL implementation for ProcessProtection
 */
class ProcessProtectionImpl final {
public:
    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    ProcessProtectionImpl();
    ~ProcessProtectionImpl();

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const ProcessProtectionConfiguration& config);
    void Shutdown(std::string_view authorizationToken);
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] bool SetConfiguration(const ProcessProtectionConfiguration& config);
    [[nodiscard]] ProcessProtectionConfiguration GetConfiguration() const;
    void SetDefaultResponse(ThreatResponse response);
    void SetThreatResponse(ThreatAction action, ThreatResponse response);

    // ========================================================================
    // PPL PROTECTION
    // ========================================================================

    [[nodiscard]] bool ElevateToPPL();
    [[nodiscard]] bool IsPPLProtected() const;
    [[nodiscard]] ProtectionLevel GetProtectionLevel(uint32_t processId);
    [[nodiscard]] uint32_t GetProtectionLevelRaw(uint32_t processId);
    [[nodiscard]] bool HasRequiredProtectionLevel(uint32_t processId, ProtectionLevel required);

    // ========================================================================
    // PROCESS PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectProcess(uint32_t processId);
    [[nodiscard]] bool UnprotectProcess(uint32_t processId, std::string_view authorizationToken);
    [[nodiscard]] bool IsProcessProtected(uint32_t processId) const;
    [[nodiscard]] std::optional<ProtectedProcessInfo> GetProtectedProcessInfo(uint32_t processId) const;
    [[nodiscard]] std::vector<ProtectedProcessInfo> GetAllProtectedProcesses() const;
    [[nodiscard]] bool SetCriticalProcess(uint32_t processId, bool critical);
    [[nodiscard]] bool IsCriticalProcess(uint32_t processId) const;

    // ========================================================================
    // THREAD PROTECTION
    // ========================================================================

    [[nodiscard]] bool ProtectThread(uint32_t threadId);
    [[nodiscard]] size_t ProtectAllThreads(uint32_t processId);
    [[nodiscard]] bool UnprotectThread(uint32_t threadId, std::string_view authorizationToken);
    [[nodiscard]] bool IsThreadProtected(uint32_t threadId) const;
    [[nodiscard]] std::optional<ProtectedThreadInfo> GetProtectedThreadInfo(uint32_t threadId) const;
    [[nodiscard]] std::vector<ProtectedThreadInfo> GetProtectedThreads(uint32_t processId) const;
    [[nodiscard]] bool HideThreadFromDebugger(uint32_t threadId);

    // ========================================================================
    // ACCESS CONTROL
    // ========================================================================

    [[nodiscard]] bool IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess);
    [[nodiscard]] AccessDecisionResult FilterAccessRequest(const AccessRequest& request);
    [[nodiscard]] uint32_t StripDangerousAccess(uint32_t desiredAccess, bool isThread);
    void SetBlockedProcessAccess(uint32_t accessMask);
    void SetBlockedThreadAccess(uint32_t accessMask);

    // ========================================================================
    // SECURITY DESCRIPTOR
    // ========================================================================

    [[nodiscard]] bool ApplyRestrictiveSecurityDescriptor(uint32_t processId);
    [[nodiscard]] std::vector<uint8_t> GetProcessSecurityDescriptor(uint32_t processId);
    [[nodiscard]] bool SetProcessIntegrityLevel(uint32_t processId, uint32_t integrityLevel);
    [[nodiscard]] uint32_t GetProcessIntegrityLevel(uint32_t processId);

    // ========================================================================
    // WHITELIST
    // ========================================================================

    [[nodiscard]] bool AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken);
    [[nodiscard]] bool RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken);
    [[nodiscard]] bool IsWhitelisted(std::wstring_view processName) const;
    [[nodiscard]] bool IsWhitelisted(uint32_t processId) const;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    [[nodiscard]] uint64_t RegisterAccessCallback(AccessDecisionCallback callback);
    void UnregisterAccessCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterBlockedAccessCallback(BlockedAccessCallback callback);
    void UnregisterBlockedAccessCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterProtectionStatusCallback(ProtectionStatusCallback callback);
    void UnregisterProtectionStatusCallback(uint64_t callbackId);
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatCallback callback);
    void UnregisterThreatCallback(uint64_t callbackId);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] ProcessProtectionStatistics GetStatistics() const;
    void ResetStatistics(std::string_view authorizationToken);
    [[nodiscard]] std::vector<BlockedAccessEvent> GetBlockedAccessHistory(size_t maxEntries) const;
    void ClearBlockedAccessHistory(std::string_view authorizationToken);
    [[nodiscard]] std::string ExportReport() const;

    // ========================================================================
    // UTILITY
    // ========================================================================

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] bool VerifyProcessIntegrity(uint32_t processId);

private:
    // ========================================================================
    // INTERNAL HELPERS
    // ========================================================================

    void SetStatus(ModuleStatus newStatus);
    void StartMonitoringThread();
    void StopMonitoringThread();
    void MonitoringThreadFunc();
    void NotifyBlockedAccess(const BlockedAccessEvent& event);
    void NotifyProtectionStatus(uint32_t processId, ProtectionStatus newStatus);
    void NotifyThreat(ThreatAction action, const AccessRequest& request);
    void RecordBlockedAccess(const BlockedAccessEvent& event);
    [[nodiscard]] bool ValidateConfiguration(const ProcessProtectionConfiguration& config) const;
    [[nodiscard]] ThreatResponse GetResponseForAction(ThreatAction action) const;
    [[nodiscard]] ThreatAction ClassifyAccessRequest(const AccessRequest& request) const;
    [[nodiscard]] bool LoadNtdllFunctions();
    [[nodiscard]] std::vector<uint32_t> EnumerateThreadIds(uint32_t processId) const;
    [[nodiscard]] bool IsOwnProcess(uint32_t processId) const;
    [[nodiscard]] bool IsShadowStrikeComponent(uint32_t processId) const;

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    // Synchronization
    mutable std::shared_mutex m_mutex;
    mutable std::mutex m_callbackMutex;
    mutable std::mutex m_historyMutex;

    // State
    std::atomic<ModuleStatus> m_status{ModuleStatus::Uninitialized};
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_isPPL{false};

    // Configuration
    ProcessProtectionConfiguration m_config;

    // Protected processes
    std::unordered_map<uint32_t, ProtectedProcessInfo> m_protectedProcesses;

    // Protected threads
    std::unordered_map<uint32_t, ProtectedThreadInfo> m_protectedThreads;

    // Threat response mapping
    std::unordered_map<ThreatAction, ThreatResponse> m_threatResponses;

    // Whitelisted callers
    std::unordered_set<std::wstring> m_whitelistedCallers;

    // Monitoring thread
    std::unique_ptr<std::thread> m_monitoringThread;
    std::atomic<bool> m_stopMonitoring{false};
    std::condition_variable m_monitoringCV;
    std::mutex m_monitoringMutex;

    // Blocked access history
    std::deque<BlockedAccessEvent> m_blockedAccessHistory;
    static constexpr size_t MAX_HISTORY_SIZE = 1000;

    // Statistics
    ProcessProtectionStatistics m_stats;

    // Callbacks
    std::unordered_map<uint64_t, AccessDecisionCallback> m_accessCallbacks;
    std::unordered_map<uint64_t, BlockedAccessCallback> m_blockedCallbacks;
    std::unordered_map<uint64_t, ProtectionStatusCallback> m_statusCallbacks;
    std::unordered_map<uint64_t, ThreatCallback> m_threatCallbacks;
    std::atomic<uint64_t> m_nextCallbackId{1};

    // NTDLL functions
#ifdef _WIN32
    HMODULE m_hNtdll = nullptr;
    NtQueryInformationProcess_t m_pNtQueryInformationProcess = nullptr;
    NtSetInformationProcess_t m_pNtSetInformationProcess = nullptr;
    NtSetInformationThread_t m_pNtSetInformationThread = nullptr;
    RtlSetProcessIsCritical_t m_pRtlSetProcessIsCritical = nullptr;
#endif

    // Internal auth token
    std::string m_internalAuthToken;

    // ShadowStrike component names
    static constexpr std::array<std::wstring_view, 5> SHADOWSTRIKE_COMPONENTS = {
        L"ShadowStrike.exe",
        L"ShadowStrikeSvc.exe",
        L"ShadowSensor.sys",
        L"SSAgent.exe",
        L"SSUpdater.exe"
    };
};

// ============================================================================
// PROCESSPROTECTIONIMPL IMPLEMENTATION
// ============================================================================

ProcessProtectionImpl::ProcessProtectionImpl() {
    m_stats.startTime = Clock::now();
    m_internalAuthToken = GenerateInternalAuthToken();

    // Initialize default threat responses
    m_threatResponses[ThreatAction::ProcessTerminate] = ThreatResponse::Aggressive;
    m_threatResponses[ThreatAction::ProcessSuspend] = ThreatResponse::Active;
    m_threatResponses[ThreatAction::ThreadTerminate] = ThreatResponse::Active;
    m_threatResponses[ThreatAction::ThreadSuspend] = ThreatResponse::Active;
    m_threatResponses[ThreatAction::MemoryWrite] = ThreatResponse::Aggressive;
    m_threatResponses[ThreatAction::ThreadCreate] = ThreatResponse::Active;
    m_threatResponses[ThreatAction::APCQueue] = ThreatResponse::Aggressive;
    m_threatResponses[ThreatAction::HandleDuplicate] = ThreatResponse::Passive;
    m_threatResponses[ThreatAction::DebugAttach] = ThreatResponse::Aggressive;
}

ProcessProtectionImpl::~ProcessProtectionImpl() {
    Shutdown(m_internalAuthToken);
}

bool ProcessProtectionImpl::Initialize(const ProcessProtectionConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (m_initialized.load(std::memory_order_acquire)) {
        Utils::Logger::Warn("[ProcessProtection] Already initialized");
        return true;
    }

    SetStatus(ModuleStatus::Initializing);

    // Validate configuration
    if (!ValidateConfiguration(config)) {
        Utils::Logger::Error("[ProcessProtection] Invalid configuration");
        SetStatus(ModuleStatus::Error);
        return false;
    }

    m_config = config;

    // Load NTDLL functions
    if (!LoadNtdllFunctions()) {
        Utils::Logger::Error("[ProcessProtection] Failed to load NTDLL functions");
        SetStatus(ModuleStatus::Error);
        return false;
    }

    // Initialize whitelisted callers
    for (const auto& caller : m_config.whitelistedCallers) {
        std::wstring lowerCaller = caller;
        std::transform(lowerCaller.begin(), lowerCaller.end(), lowerCaller.begin(), ::towlower);
        m_whitelistedCallers.insert(lowerCaller);
    }

    // Protect current process
    uint32_t currentPid = GetCurrentProcessIdSafe();
    lock.unlock();  // Unlock before calling ProtectProcess

    if (!ProtectProcess(currentPid)) {
        Utils::Logger::Warn("[ProcessProtection] Failed to protect current process");
    }

    // Protect additional PIDs from config
    for (uint32_t pid : config.additionalProtectedPids) {
        if (!ProtectProcess(pid)) {
            Utils::Logger::Warn("[ProcessProtection] Failed to protect process {}", pid);
        }
    }

    lock.lock();
    m_initialized.store(true, std::memory_order_release);
    SetStatus(ModuleStatus::Running);

    // Start monitoring thread
    StartMonitoringThread();

    Utils::Logger::Info("[ProcessProtection] Initialized successfully - protecting {} processes",
                        m_protectedProcesses.size());

    return true;
}

void ProcessProtectionImpl::Shutdown(std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken) && authorizationToken != m_internalAuthToken) {
        Utils::Logger::Warn("[ProcessProtection] Shutdown rejected - invalid authorization");
        return;
    }

    std::unique_lock lock(m_mutex);

    if (!m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SetStatus(ModuleStatus::Stopping);

    // Stop monitoring thread
    lock.unlock();
    StopMonitoringThread();
    lock.lock();

    // Clear protected processes and threads
    m_protectedProcesses.clear();
    m_protectedThreads.clear();
    m_whitelistedCallers.clear();

    m_initialized.store(false, std::memory_order_release);
    SetStatus(ModuleStatus::Stopped);

    Utils::Logger::Info("[ProcessProtection] Shutdown complete");
}

bool ProcessProtectionImpl::IsInitialized() const noexcept {
    return m_initialized.load(std::memory_order_acquire);
}

ModuleStatus ProcessProtectionImpl::GetStatus() const noexcept {
    return m_status.load(std::memory_order_acquire);
}

bool ProcessProtectionImpl::SetConfiguration(const ProcessProtectionConfiguration& config) {
    std::unique_lock lock(m_mutex);

    if (!ValidateConfiguration(config)) {
        Utils::Logger::Error("[ProcessProtection] Invalid configuration update");
        return false;
    }

    m_config = config;

    // Update whitelisted callers
    m_whitelistedCallers.clear();
    for (const auto& caller : m_config.whitelistedCallers) {
        std::wstring lowerCaller = caller;
        std::transform(lowerCaller.begin(), lowerCaller.end(), lowerCaller.begin(), ::towlower);
        m_whitelistedCallers.insert(lowerCaller);
    }

    Utils::Logger::Info("[ProcessProtection] Configuration updated");
    return true;
}

ProcessProtectionConfiguration ProcessProtectionImpl::GetConfiguration() const {
    std::shared_lock lock(m_mutex);
    return m_config;
}

void ProcessProtectionImpl::SetDefaultResponse(ThreatResponse response) {
    std::unique_lock lock(m_mutex);
    m_config.defaultResponse = response;
}

void ProcessProtectionImpl::SetThreatResponse(ThreatAction action, ThreatResponse response) {
    std::unique_lock lock(m_mutex);
    m_threatResponses[action] = response;
}

// ============================================================================
// PPL PROTECTION
// ============================================================================

bool ProcessProtectionImpl::ElevateToPPL() {
#ifdef _WIN32
    // PPL elevation requires:
    // 1. ELAM (Early Launch Anti-Malware) driver signed by Microsoft
    // 2. The driver to call PsRegisterElamCertificate during boot
    // 3. The user-mode process to be started by the ELAM driver

    // Check if already PPL protected
    ProtectionLevel level = GetProtectionLevel(GetCurrentProcessIdSafe());
    if (level.IsPPL()) {
        m_isPPL.store(true, std::memory_order_release);
        Utils::Logger::Info("[ProcessProtection] Already PPL protected");
        return true;
    }

    // User-mode cannot directly elevate to PPL
    // This would require communication with the kernel driver
    Utils::Logger::Warn("[ProcessProtection] PPL elevation requires kernel driver support");

    // For now, return false - actual implementation would communicate with Shadow Sensor driver
    return false;
#else
    return false;
#endif
}

bool ProcessProtectionImpl::IsPPLProtected() const {
    return m_isPPL.load(std::memory_order_acquire);
}

ProtectionLevel ProcessProtectionImpl::GetProtectionLevel(uint32_t processId) {
    ProtectionLevel level;

#ifdef _WIN32
    if (!m_pNtQueryInformationProcess) {
        return level;
    }

    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return level;
    }

    PS_PROTECTION protection = {};
    NTSTATUS status = m_pNtQueryInformationProcess(
        hProcess,
        ProcessProtectionInformation,
        &protection,
        sizeof(protection),
        nullptr
    );

    ::CloseHandle(hProcess);

    if (NT_SUCCESS(status)) {
        level.rawLevel = protection.Level;
        level.type = static_cast<ProtectionType>(protection.Type);
        level.signer = static_cast<ProtectionSigner>(protection.Signer);
    }
#endif

    return level;
}

uint32_t ProcessProtectionImpl::GetProtectionLevelRaw(uint32_t processId) {
    ProtectionLevel level = GetProtectionLevel(processId);
    return level.rawLevel;
}

bool ProcessProtectionImpl::HasRequiredProtectionLevel(uint32_t processId, ProtectionLevel required) {
    ProtectionLevel current = GetProtectionLevel(processId);
    return current >= required;
}

// ============================================================================
// PROCESS PROTECTION
// ============================================================================

bool ProcessProtectionImpl::ProtectProcess(uint32_t processId) {
    if (processId == 0) {
        Utils::Logger::Error("[ProcessProtection] Invalid process ID");
        return false;
    }

    std::unique_lock lock(m_mutex);

    // Check if already protected
    if (m_protectedProcesses.find(processId) != m_protectedProcesses.end()) {
        return true;
    }

    // Check limit
    if (m_protectedProcesses.size() >= ProcessProtectionConstants::MAX_PROTECTED_PROCESSES) {
        Utils::Logger::Warn("[ProcessProtection] Maximum protected processes reached");
        return false;
    }

    // Gather process information
    ProtectedProcessInfo info;
    info.processId = processId;
    info.processName = GetProcessName(processId);
    info.imagePath = GetProcessImagePath(processId);
    info.protectedSince = Clock::now();
    info.isShadowStrikeComponent = IsShadowStrikeComponent(processId);

#ifdef _WIN32
    // Get process handle for protection operations
    info.processHandle = ::OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | READ_CONTROL | WRITE_DAC,
        FALSE,
        processId
    );

    if (!info.processHandle) {
        Utils::Logger::Warn("[ProcessProtection] Failed to open process {} for protection: 0x{:08X}",
                           processId, ::GetLastError());
        // Continue anyway - some protections may still work
    }
#endif

    // Get protection level
    info.protectionLevel = GetProtectionLevel(processId);

    // Get integrity level
    info.integrityLevel = GetProcessIntegrityLevel(processId);

    // Determine protection status
    if (info.protectionLevel.IsPPL()) {
        info.status = ProtectionStatus::PPLProtected;
    } else if (info.processHandle) {
        info.status = ProtectionStatus::UserModeOnly;
    } else {
        info.status = ProtectionStatus::Unprotected;
    }

    // Store protected process info
    m_protectedProcesses[processId] = info;

    // Unlock before calling other methods
    lock.unlock();

    // Apply restrictive security descriptor
    if (m_config.enableHandleFiltering) {
        if (!ApplyRestrictiveSecurityDescriptor(processId)) {
            Utils::Logger::Warn("[ProcessProtection] Failed to apply security descriptor to process {}", processId);
        }
    }

    // Set critical process if configured
    if (m_config.setCriticalProcess) {
        SetCriticalProcess(processId, true);
    }

    // Protect all threads
    if (m_config.enableThreadProtection) {
        size_t threadCount = ProtectAllThreads(processId);

        lock.lock();
        if (m_protectedProcesses.find(processId) != m_protectedProcesses.end()) {
            m_protectedProcesses[processId].threadCount = static_cast<uint32_t>(threadCount);
        }
        lock.unlock();
    }

    m_stats.totalProtectedProcesses.store(m_protectedProcesses.size(), std::memory_order_relaxed);

    Utils::Logger::Info("[ProcessProtection] Protected process {} ({}) - status: {}",
                       processId, WideToNarrow(info.processName),
                       static_cast<int>(info.status));

    // Notify callbacks
    NotifyProtectionStatus(processId, info.status);

    return true;
}

bool ProcessProtectionImpl::UnprotectProcess(uint32_t processId, std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        Utils::Logger::Warn("[ProcessProtection] Unprotect rejected - invalid authorization");
        return false;
    }

    std::unique_lock lock(m_mutex);

    auto it = m_protectedProcesses.find(processId);
    if (it == m_protectedProcesses.end()) {
        return false;
    }

#ifdef _WIN32
    // Close process handle
    if (it->second.processHandle) {
        ::CloseHandle(it->second.processHandle);
    }
#endif

    m_protectedProcesses.erase(it);

    // Remove associated threads
    for (auto threadIt = m_protectedThreads.begin(); threadIt != m_protectedThreads.end();) {
        if (threadIt->second.processId == processId) {
            threadIt = m_protectedThreads.erase(threadIt);
        } else {
            ++threadIt;
        }
    }

    m_stats.totalProtectedProcesses.store(m_protectedProcesses.size(), std::memory_order_relaxed);

    Utils::Logger::Info("[ProcessProtection] Unprotected process {}", processId);

    lock.unlock();
    NotifyProtectionStatus(processId, ProtectionStatus::Unprotected);

    return true;
}

bool ProcessProtectionImpl::IsProcessProtected(uint32_t processId) const {
    std::shared_lock lock(m_mutex);
    return m_protectedProcesses.find(processId) != m_protectedProcesses.end();
}

std::optional<ProtectedProcessInfo> ProcessProtectionImpl::GetProtectedProcessInfo(uint32_t processId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_protectedProcesses.find(processId);
    if (it != m_protectedProcesses.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<ProtectedProcessInfo> ProcessProtectionImpl::GetAllProtectedProcesses() const {
    std::shared_lock lock(m_mutex);

    std::vector<ProtectedProcessInfo> result;
    result.reserve(m_protectedProcesses.size());

    for (const auto& [pid, info] : m_protectedProcesses) {
        result.push_back(info);
    }

    return result;
}

bool ProcessProtectionImpl::SetCriticalProcess(uint32_t processId, bool critical) {
#ifdef _WIN32
    // Setting a process as critical means BSOD if it terminates
    // This is a strong protection but should be used carefully

    if (!m_pRtlSetProcessIsCritical) {
        Utils::Logger::Warn("[ProcessProtection] RtlSetProcessIsCritical not available");
        return false;
    }

    // Need SE_DEBUG_PRIVILEGE
    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        ::CloseHandle(hToken);
        return false;
    }

    ::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    ::CloseHandle(hToken);

    // Only works on current process
    if (processId != GetCurrentProcessIdSafe()) {
        Utils::Logger::Warn("[ProcessProtection] Can only set critical flag on current process");
        return false;
    }

    BOOLEAN wasCritical = FALSE;
    NTSTATUS status = m_pRtlSetProcessIsCritical(
        critical ? TRUE : FALSE,
        &wasCritical,
        FALSE
    );

    if (NT_SUCCESS(status)) {
        std::unique_lock lock(m_mutex);
        auto it = m_protectedProcesses.find(processId);
        if (it != m_protectedProcesses.end()) {
            it->second.isCritical = critical;
            if (critical) {
                it->second.status = ProtectionStatus::Critical;
            }
        }

        Utils::Logger::Info("[ProcessProtection] Process {} set as critical: {}", processId, critical);
        return true;
    }

    Utils::Logger::Error("[ProcessProtection] Failed to set critical flag: 0x{:08X}", status);
    return false;
#else
    return false;
#endif
}

bool ProcessProtectionImpl::IsCriticalProcess(uint32_t processId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_protectedProcesses.find(processId);
    if (it != m_protectedProcesses.end()) {
        return it->second.isCritical;
    }

    return false;
}

// ============================================================================
// THREAD PROTECTION
// ============================================================================

bool ProcessProtectionImpl::ProtectThread(uint32_t threadId) {
    if (threadId == 0) {
        threadId = GetCurrentThreadIdSafe();
    }

    std::unique_lock lock(m_mutex);

    // Check if already protected
    if (m_protectedThreads.find(threadId) != m_protectedThreads.end()) {
        return true;
    }

    // Check limit
    if (m_protectedThreads.size() >= ProcessProtectionConstants::MAX_PROTECTED_THREADS) {
        Utils::Logger::Warn("[ProcessProtection] Maximum protected threads reached");
        return false;
    }

    ProtectedThreadInfo info;
    info.threadId = threadId;
    info.protectedSince = Clock::now();

#ifdef _WIN32
    // Get thread handle
    info.threadHandle = ::OpenThread(
        THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION,
        FALSE,
        threadId
    );

    if (!info.threadHandle) {
        Utils::Logger::Warn("[ProcessProtection] Failed to open thread {}", threadId);
        return false;
    }

    // Get owner process ID
    info.processId = ::GetProcessIdOfThread(info.threadHandle);
#endif

    m_protectedThreads[threadId] = info;

    m_stats.totalProtectedThreads.store(m_protectedThreads.size(), std::memory_order_relaxed);

    lock.unlock();

    // Hide from debugger if configured
    if (m_config.enableAntiInjection) {
        HideThreadFromDebugger(threadId);
    }

    return true;
}

size_t ProcessProtectionImpl::ProtectAllThreads(uint32_t processId) {
    std::vector<uint32_t> threadIds = EnumerateThreadIds(processId);
    size_t count = 0;

    for (uint32_t tid : threadIds) {
        if (ProtectThread(tid)) {
            count++;
        }
    }

    Utils::Logger::Info("[ProcessProtection] Protected {} threads for process {}", count, processId);
    return count;
}

bool ProcessProtectionImpl::UnprotectThread(uint32_t threadId, std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        return false;
    }

    std::unique_lock lock(m_mutex);

    auto it = m_protectedThreads.find(threadId);
    if (it == m_protectedThreads.end()) {
        return false;
    }

#ifdef _WIN32
    if (it->second.threadHandle) {
        ::CloseHandle(it->second.threadHandle);
    }
#endif

    m_protectedThreads.erase(it);
    m_stats.totalProtectedThreads.store(m_protectedThreads.size(), std::memory_order_relaxed);

    return true;
}

bool ProcessProtectionImpl::IsThreadProtected(uint32_t threadId) const {
    std::shared_lock lock(m_mutex);
    return m_protectedThreads.find(threadId) != m_protectedThreads.end();
}

std::optional<ProtectedThreadInfo> ProcessProtectionImpl::GetProtectedThreadInfo(uint32_t threadId) const {
    std::shared_lock lock(m_mutex);

    auto it = m_protectedThreads.find(threadId);
    if (it != m_protectedThreads.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<ProtectedThreadInfo> ProcessProtectionImpl::GetProtectedThreads(uint32_t processId) const {
    std::shared_lock lock(m_mutex);

    std::vector<ProtectedThreadInfo> result;
    for (const auto& [tid, info] : m_protectedThreads) {
        if (info.processId == processId) {
            result.push_back(info);
        }
    }

    return result;
}

bool ProcessProtectionImpl::HideThreadFromDebugger(uint32_t threadId) {
#ifdef _WIN32
    if (!m_pNtSetInformationThread) {
        return false;
    }

    HANDLE hThread = nullptr;

    if (threadId == 0 || threadId == GetCurrentThreadIdSafe()) {
        hThread = ::GetCurrentThread();
    } else {
        hThread = ::OpenThread(THREAD_SET_INFORMATION, FALSE, threadId);
        if (!hThread) {
            return false;
        }
    }

    NTSTATUS status = m_pNtSetInformationThread(
        hThread,
        ThreadHideFromDebugger,
        nullptr,
        0
    );

    if (threadId != 0 && threadId != GetCurrentThreadIdSafe()) {
        ::CloseHandle(hThread);
    }

    if (NT_SUCCESS(status)) {
        std::unique_lock lock(m_mutex);
        auto it = m_protectedThreads.find(threadId == 0 ? GetCurrentThreadIdSafe() : threadId);
        if (it != m_protectedThreads.end()) {
            it->second.isHiddenFromDebugger = true;
        }
        return true;
    }

    return false;
#else
    return false;
#endif
}

// ============================================================================
// ACCESS CONTROL
// ============================================================================

bool ProcessProtectionImpl::IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess) {
    AccessRequest request;
    request.type = AccessRequestType::ProcessOpen;
    request.callerProcessId = callerPid;
    request.targetProcessId = targetPid;
    request.desiredAccess = desiredAccess;
    request.timestamp = Clock::now();

    auto result = FilterAccessRequest(request);
    return result.decision == AccessDecision::Allow || result.decision == AccessDecision::AllowReduced;
}

AccessDecisionResult ProcessProtectionImpl::FilterAccessRequest(const AccessRequest& request) {
    AccessDecisionResult result;
    result.decision = AccessDecision::Allow;
    result.grantedAccess = request.desiredAccess;

    // Check if target is protected
    bool isTargetProtected = IsProcessProtected(request.targetProcessId);
    if (!isTargetProtected) {
        return result;
    }

    // Check if caller is whitelisted
    if (request.callerIsWhitelisted || IsWhitelisted(request.callerProcessId)) {
        result.reason = "Caller is whitelisted";
        return result;
    }

    // Check if caller is a ShadowStrike component
    if (IsShadowStrikeComponent(request.callerProcessId)) {
        result.reason = "Caller is ShadowStrike component";
        return result;
    }

    // Check if caller is SYSTEM
    if (IsSystemProcess(request.callerProcessId)) {
        result.reason = "Caller is SYSTEM";
        return result;
    }

    // Check if caller has higher or equal protection level
    ProtectionLevel callerLevel = GetProtectionLevel(request.callerProcessId);
    ProtectionLevel targetLevel;

    {
        std::shared_lock lock(m_mutex);
        auto it = m_protectedProcesses.find(request.targetProcessId);
        if (it != m_protectedProcesses.end()) {
            targetLevel = it->second.protectionLevel;
        }
    }

    if (callerLevel >= targetLevel && callerLevel.IsPPL()) {
        result.reason = "Caller has sufficient protection level";
        return result;
    }

    // Classify the threat
    ThreatAction threatAction = ClassifyAccessRequest(request);

    // Check for dangerous access
    uint32_t dangerousAccess = request.desiredAccess &
        (request.type == AccessRequestType::ThreadOpen ?
         m_config.blockedThreadAccess : m_config.blockedProcessAccess);

    if (dangerousAccess != 0) {
        // Strip dangerous access rights
        result.grantedAccess = request.desiredAccess & ~dangerousAccess;
        result.strippedAccess = dangerousAccess;

        if (result.grantedAccess == 0) {
            result.decision = AccessDecision::Deny;
            result.reason = "All requested access is blocked";
        } else {
            result.decision = AccessDecision::AllowReduced;
            result.reason = "Dangerous access stripped";
        }

        result.shouldLog = true;
        result.shouldAlert = (dangerousAccess & PROCESS_TERMINATE) != 0;

        // Update statistics
        m_stats.totalAccessBlocked.fetch_add(1, std::memory_order_relaxed);

        if (dangerousAccess & PROCESS_TERMINATE) {
            m_stats.processTerminationBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (dangerousAccess & PROCESS_VM_WRITE) {
            m_stats.memoryWriteBlocked.fetch_add(1, std::memory_order_relaxed);
        }
        if (dangerousAccess & PROCESS_CREATE_THREAD) {
            m_stats.threadCreationBlocked.fetch_add(1, std::memory_order_relaxed);
        }

        // Create blocked access event
        BlockedAccessEvent event;
        event.eventId = GenerateEventId();
        event.request = request;
        event.decision = result;
        event.threatAction = threatAction;
        event.responseTaken = GetResponseForAction(threatAction);
        event.timestamp = Clock::now();

        RecordBlockedAccess(event);
        NotifyBlockedAccess(event);
        NotifyThreat(threatAction, request);

        Utils::Logger::Warn("[ProcessProtection] Blocked access: caller={}, target={}, access=0x{:08X}",
                           request.callerProcessId, request.targetProcessId, dangerousAccess);
    }

    m_stats.totalAccessRequests.fetch_add(1, std::memory_order_relaxed);

    // Query custom callbacks for override
    std::vector<AccessDecisionCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        for (const auto& [id, cb] : m_accessCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            auto override = cb(request);
            if (override.has_value()) {
                return *override;
            }
        } catch (...) {
            // Ignore callback errors
        }
    }

    return result;
}

uint32_t ProcessProtectionImpl::StripDangerousAccess(uint32_t desiredAccess, bool isThread) {
    std::shared_lock lock(m_mutex);

    uint32_t blockedMask = isThread ? m_config.blockedThreadAccess : m_config.blockedProcessAccess;
    return desiredAccess & ~blockedMask;
}

void ProcessProtectionImpl::SetBlockedProcessAccess(uint32_t accessMask) {
    std::unique_lock lock(m_mutex);
    m_config.blockedProcessAccess = accessMask;
}

void ProcessProtectionImpl::SetBlockedThreadAccess(uint32_t accessMask) {
    std::unique_lock lock(m_mutex);
    m_config.blockedThreadAccess = accessMask;
}

// ============================================================================
// SECURITY DESCRIPTOR
// ============================================================================

bool ProcessProtectionImpl::ApplyRestrictiveSecurityDescriptor(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(WRITE_DAC | READ_CONTROL, FALSE, processId);
    if (!hProcess) {
        Utils::Logger::Warn("[ProcessProtection] Failed to open process {} for DACL modification", processId);
        return false;
    }

    // Create a restrictive DACL
    // Allow: SYSTEM (full), Administrators (limited), Owner (query only)
    // Deny: Everyone else

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;

    // SDDL string for restrictive access
    // D: DACL
    // (A;;GA;;;SY) - Allow Generic All for SYSTEM
    // (A;;GRGX;;;BA) - Allow Read/Execute for Administrators
    // (D;;WPDTSD;;;WD) - Deny Write, Process/Thread dangerous ops for Everyone
    LPCWSTR sddl = L"D:(A;;GA;;;SY)(A;;GRGX;;;BA)(D;;0x0001F1FF;;;WD)";

    if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, nullptr)) {
        ::CloseHandle(hProcess);
        return false;
    }

    BOOL hasDacl = FALSE;
    BOOL daclDefaulted = FALSE;

    if (!::GetSecurityDescriptorDacl(pSD, &hasDacl, &pDacl, &daclDefaulted)) {
        ::LocalFree(pSD);
        ::CloseHandle(hProcess);
        return false;
    }

    DWORD result = ::SetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        pDacl,
        nullptr
    );

    ::LocalFree(pSD);
    ::CloseHandle(hProcess);

    if (result != ERROR_SUCCESS) {
        Utils::Logger::Warn("[ProcessProtection] Failed to set security descriptor: {}", result);
        return false;
    }

    Utils::Logger::Info("[ProcessProtection] Applied restrictive security descriptor to process {}", processId);
    return true;
#else
    return false;
#endif
}

std::vector<uint8_t> ProcessProtectionImpl::GetProcessSecurityDescriptor(uint32_t processId) {
    std::vector<uint8_t> result;

#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(READ_CONTROL, FALSE, processId);
    if (!hProcess) {
        return result;
    }

    PSECURITY_DESCRIPTOR pSD = nullptr;
    DWORD sdSize = 0;

    DWORD err = ::GetSecurityInfo(
        hProcess,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        &pSD
    );

    ::CloseHandle(hProcess);

    if (err != ERROR_SUCCESS || !pSD) {
        return result;
    }

    DWORD length = ::GetSecurityDescriptorLength(pSD);
    result.resize(length);
    std::memcpy(result.data(), pSD, length);

    ::LocalFree(pSD);
#endif

    return result;
}

bool ProcessProtectionImpl::SetProcessIntegrityLevel(uint32_t processId, uint32_t integrityLevel) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return false;
    }

    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(hProcess, TOKEN_ADJUST_DEFAULT | TOKEN_QUERY, &hToken)) {
        ::CloseHandle(hProcess);
        return false;
    }

    ::CloseHandle(hProcess);

    // Create mandatory label SID
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_MANDATORY_LABEL_AUTHORITY;
    PSID pIntegritySid = nullptr;

    if (!::AllocateAndInitializeSid(&authority, 1, integrityLevel,
                                    0, 0, 0, 0, 0, 0, 0, &pIntegritySid)) {
        ::CloseHandle(hToken);
        return false;
    }

    TOKEN_MANDATORY_LABEL tml = {};
    tml.Label.Attributes = SE_GROUP_INTEGRITY;
    tml.Label.Sid = pIntegritySid;

    BOOL success = ::SetTokenInformation(
        hToken,
        TokenIntegrityLevel,
        &tml,
        sizeof(tml) + ::GetLengthSid(pIntegritySid)
    );

    ::FreeSid(pIntegritySid);
    ::CloseHandle(hToken);

    return success != FALSE;
#else
    return false;
#endif
}

uint32_t ProcessProtectionImpl::GetProcessIntegrityLevel(uint32_t processId) {
#ifdef _WIN32
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) {
        return 0;
    }

    HANDLE hToken = nullptr;
    if (!::OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        ::CloseHandle(hProcess);
        return 0;
    }

    ::CloseHandle(hProcess);

    DWORD size = 0;
    ::GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &size);

    if (size == 0) {
        ::CloseHandle(hToken);
        return 0;
    }

    std::vector<uint8_t> buffer(size);
    PTOKEN_MANDATORY_LABEL pTML = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(buffer.data());

    if (!::GetTokenInformation(hToken, TokenIntegrityLevel, pTML, size, &size)) {
        ::CloseHandle(hToken);
        return 0;
    }

    ::CloseHandle(hToken);

    DWORD subAuthCount = *::GetSidSubAuthorityCount(pTML->Label.Sid);
    if (subAuthCount > 0) {
        return *::GetSidSubAuthority(pTML->Label.Sid, subAuthCount - 1);
    }

    return 0;
#else
    return 0;
#endif
}

// ============================================================================
// WHITELIST
// ============================================================================

bool ProcessProtectionImpl::AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        Utils::Logger::Warn("[ProcessProtection] Add to whitelist rejected - invalid authorization");
        return false;
    }

    std::unique_lock lock(m_mutex);

    std::wstring lowerName(processName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    auto [it, inserted] = m_whitelistedCallers.insert(lowerName);

    if (inserted) {
        m_config.whitelistedCallers.emplace_back(processName);
        Utils::Logger::Info("[ProcessProtection] Added to whitelist: {}", WideToNarrow(processName));
    }

    return inserted;
}

bool ProcessProtectionImpl::RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        return false;
    }

    std::unique_lock lock(m_mutex);

    std::wstring lowerName(processName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    size_t removed = m_whitelistedCallers.erase(lowerName);

    if (removed > 0) {
        auto it = std::remove_if(m_config.whitelistedCallers.begin(), m_config.whitelistedCallers.end(),
                                 [&lowerName](const std::wstring& name) {
                                     std::wstring lower = name;
                                     std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                                     return lower == lowerName;
                                 });
        m_config.whitelistedCallers.erase(it, m_config.whitelistedCallers.end());

        Utils::Logger::Info("[ProcessProtection] Removed from whitelist: {}", WideToNarrow(processName));
    }

    return removed > 0;
}

bool ProcessProtectionImpl::IsWhitelisted(std::wstring_view processName) const {
    std::shared_lock lock(m_mutex);

    std::wstring lowerName(processName);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    return m_whitelistedCallers.find(lowerName) != m_whitelistedCallers.end();
}

bool ProcessProtectionImpl::IsWhitelisted(uint32_t processId) const {
    std::wstring processName = GetProcessName(processId);
    if (processName.empty()) {
        return false;
    }

    return IsWhitelisted(processName);
}

// ============================================================================
// CALLBACKS
// ============================================================================

uint64_t ProcessProtectionImpl::RegisterAccessCallback(AccessDecisionCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_accessCallbacks[id] = std::move(callback);
    return id;
}

void ProcessProtectionImpl::UnregisterAccessCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_accessCallbacks.erase(callbackId);
}

uint64_t ProcessProtectionImpl::RegisterBlockedAccessCallback(BlockedAccessCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_blockedCallbacks[id] = std::move(callback);
    return id;
}

void ProcessProtectionImpl::UnregisterBlockedAccessCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_blockedCallbacks.erase(callbackId);
}

uint64_t ProcessProtectionImpl::RegisterProtectionStatusCallback(ProtectionStatusCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_statusCallbacks[id] = std::move(callback);
    return id;
}

void ProcessProtectionImpl::UnregisterProtectionStatusCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_statusCallbacks.erase(callbackId);
}

uint64_t ProcessProtectionImpl::RegisterThreatCallback(ThreatCallback callback) {
    std::lock_guard lock(m_callbackMutex);
    uint64_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_threatCallbacks[id] = std::move(callback);
    return id;
}

void ProcessProtectionImpl::UnregisterThreatCallback(uint64_t callbackId) {
    std::lock_guard lock(m_callbackMutex);
    m_threatCallbacks.erase(callbackId);
}

// ============================================================================
// STATISTICS
// ============================================================================

ProcessProtectionStatistics ProcessProtectionImpl::GetStatistics() const {
    std::shared_lock lock(m_mutex);
    return m_stats;
}

void ProcessProtectionImpl::ResetStatistics(std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        return;
    }

    m_stats.Reset();
}

std::vector<BlockedAccessEvent> ProcessProtectionImpl::GetBlockedAccessHistory(size_t maxEntries) const {
    std::lock_guard lock(m_historyMutex);

    size_t count = std::min(maxEntries, m_blockedAccessHistory.size());
    std::vector<BlockedAccessEvent> result;
    result.reserve(count);

    auto it = m_blockedAccessHistory.rbegin();
    for (size_t i = 0; i < count && it != m_blockedAccessHistory.rend(); ++i, ++it) {
        result.push_back(*it);
    }

    return result;
}

void ProcessProtectionImpl::ClearBlockedAccessHistory(std::string_view authorizationToken) {
    if (!VerifyAuthToken(authorizationToken)) {
        return;
    }

    std::lock_guard lock(m_historyMutex);
    m_blockedAccessHistory.clear();
}

std::string ProcessProtectionImpl::ExportReport() const {
    std::shared_lock lock(m_mutex);

    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"module\": \"ProcessProtection\",\n";
    oss << "  \"version\": \"" << ProcessProtection::GetVersionString() << "\",\n";
    oss << "  \"status\": " << static_cast<int>(m_status.load()) << ",\n";
    oss << "  \"isPPL\": " << (m_isPPL.load() ? "true" : "false") << ",\n";
    oss << "  \"protectedProcesses\": " << m_protectedProcesses.size() << ",\n";
    oss << "  \"protectedThreads\": " << m_protectedThreads.size() << ",\n";
    oss << "  \"statistics\": " << m_stats.ToJson() << "\n";
    oss << "}\n";

    return oss.str();
}

// ============================================================================
// UTILITY
// ============================================================================

bool ProcessProtectionImpl::SelfTest() {
    Utils::Logger::Info("[ProcessProtection] Starting self-test...");

    bool passed = true;

    // Test 1: Configuration validation
    ProcessProtectionConfiguration testConfig;
    if (!testConfig.IsValid()) {
        Utils::Logger::Error("[ProcessProtection] Self-test FAILED: Default config invalid");
        passed = false;
    }

    // Test 2: Protection level query
    try {
        ProtectionLevel level = GetProtectionLevel(GetCurrentProcessIdSafe());
        Utils::Logger::Info("[ProcessProtection] Self-test: Current protection level type={}",
                           static_cast<int>(level.type));
    } catch (const std::exception& e) {
        Utils::Logger::Error("[ProcessProtection] Self-test FAILED: Protection level query: {}", e.what());
        passed = false;
    }

    // Test 3: Integrity level query
    try {
        uint32_t level = GetProcessIntegrityLevel(GetCurrentProcessIdSafe());
        Utils::Logger::Info("[ProcessProtection] Self-test: Current integrity level=0x{:X}", level);
    } catch (const std::exception& e) {
        Utils::Logger::Error("[ProcessProtection] Self-test FAILED: Integrity level query: {}", e.what());
        passed = false;
    }

    // Test 4: Access filtering
    try {
        AccessRequest request;
        request.type = AccessRequestType::ProcessOpen;
        request.callerProcessId = 1234;
        request.targetProcessId = GetCurrentProcessIdSafe();
        request.desiredAccess = PROCESS_TERMINATE;

        auto result = FilterAccessRequest(request);
        Utils::Logger::Info("[ProcessProtection] Self-test: Access filter returned decision={}",
                           static_cast<int>(result.decision));
    } catch (const std::exception& e) {
        Utils::Logger::Error("[ProcessProtection] Self-test FAILED: Access filter: {}", e.what());
        passed = false;
    }

    Utils::Logger::Info("[ProcessProtection] Self-test completed: {}", passed ? "PASSED" : "FAILED");
    return passed;
}

bool ProcessProtectionImpl::VerifyProcessIntegrity(uint32_t processId) {
    std::shared_lock lock(m_mutex);

    auto it = m_protectedProcesses.find(processId);
    if (it == m_protectedProcesses.end()) {
        return false;
    }

    // Verify process is still running
#ifdef _WIN32
    if (it->second.processHandle) {
        DWORD exitCode = 0;
        if (::GetExitCodeProcess(it->second.processHandle, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                Utils::Logger::Warn("[ProcessProtection] Process {} has terminated", processId);
                return false;
            }
        }
    }
#endif

    // Update last verified time
    const_cast<ProtectedProcessInfo&>(it->second).lastVerified = Clock::now();

    return true;
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

void ProcessProtectionImpl::SetStatus(ModuleStatus newStatus) {
    m_status.store(newStatus, std::memory_order_release);
}

void ProcessProtectionImpl::StartMonitoringThread() {
    if (m_monitoringThread && m_monitoringThread->joinable()) {
        return;
    }

    m_stopMonitoring.store(false, std::memory_order_release);
    m_monitoringThread = std::make_unique<std::thread>(&ProcessProtectionImpl::MonitoringThreadFunc, this);

    Utils::Logger::Info("[ProcessProtection] Monitoring thread started");
}

void ProcessProtectionImpl::StopMonitoringThread() {
    m_stopMonitoring.store(true, std::memory_order_release);
    m_monitoringCV.notify_one();

    if (m_monitoringThread && m_monitoringThread->joinable()) {
        m_monitoringThread->join();
        m_monitoringThread.reset();
    }

    Utils::Logger::Info("[ProcessProtection] Monitoring thread stopped");
}

void ProcessProtectionImpl::MonitoringThreadFunc() {
    Utils::Logger::Info("[ProcessProtection] Monitoring thread running");

    while (!m_stopMonitoring.load(std::memory_order_acquire)) {
        uint32_t intervalMs;
        {
            std::shared_lock lock(m_mutex);
            intervalMs = m_config.monitorIntervalMs;
        }

        {
            std::unique_lock lock(m_monitoringMutex);
            m_monitoringCV.wait_for(lock, Milliseconds(intervalMs), [this]() {
                return m_stopMonitoring.load(std::memory_order_acquire);
            });
        }

        if (m_stopMonitoring.load(std::memory_order_acquire)) {
            break;
        }

        // Verify all protected processes are still alive
        std::vector<uint32_t> deadProcesses;

        {
            std::shared_lock lock(m_mutex);
            for (const auto& [pid, info] : m_protectedProcesses) {
                if (!VerifyProcessIntegrity(pid)) {
                    deadProcesses.push_back(pid);
                }
            }
        }

        // Remove dead processes
        for (uint32_t pid : deadProcesses) {
            UnprotectProcess(pid, m_internalAuthToken);
            Utils::Logger::Warn("[ProcessProtection] Removed terminated process {} from protection", pid);
        }

        // Check for new threads in protected processes
        if (m_config.enableThreadProtection) {
            std::shared_lock lock(m_mutex);
            for (const auto& [pid, info] : m_protectedProcesses) {
                lock.unlock();
                ProtectAllThreads(pid);
                lock.lock();
            }
        }
    }
}

void ProcessProtectionImpl::NotifyBlockedAccess(const BlockedAccessEvent& event) {
    std::vector<BlockedAccessCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        for (const auto& [id, cb] : m_blockedCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(event);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[ProcessProtection] Blocked access callback threw: {}", e.what());
        }
    }
}

void ProcessProtectionImpl::NotifyProtectionStatus(uint32_t processId, ProtectionStatus newStatus) {
    std::vector<ProtectionStatusCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        for (const auto& [id, cb] : m_statusCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(processId, newStatus);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[ProcessProtection] Status callback threw: {}", e.what());
        }
    }
}

void ProcessProtectionImpl::NotifyThreat(ThreatAction action, const AccessRequest& request) {
    std::vector<ThreatCallback> callbacks;
    {
        std::lock_guard lock(m_callbackMutex);
        for (const auto& [id, cb] : m_threatCallbacks) {
            callbacks.push_back(cb);
        }
    }

    for (const auto& cb : callbacks) {
        try {
            cb(action, request);
        } catch (const std::exception& e) {
            Utils::Logger::Error("[ProcessProtection] Threat callback threw: {}", e.what());
        }
    }
}

void ProcessProtectionImpl::RecordBlockedAccess(const BlockedAccessEvent& event) {
    std::lock_guard lock(m_historyMutex);

    m_blockedAccessHistory.push_back(event);

    while (m_blockedAccessHistory.size() > MAX_HISTORY_SIZE) {
        m_blockedAccessHistory.pop_front();
    }

    m_stats.lastEventTime = event.timestamp;
}

bool ProcessProtectionImpl::ValidateConfiguration(const ProcessProtectionConfiguration& config) const {
    if (config.monitorIntervalMs < 100 || config.monitorIntervalMs > 600000) {
        return false;
    }

    return true;
}

ThreatResponse ProcessProtectionImpl::GetResponseForAction(ThreatAction action) const {
    std::shared_lock lock(m_mutex);

    auto it = m_threatResponses.find(action);
    if (it != m_threatResponses.end()) {
        return it->second;
    }

    return m_config.defaultResponse;
}

ThreatAction ProcessProtectionImpl::ClassifyAccessRequest(const AccessRequest& request) const {
    uint32_t access = request.desiredAccess;

    if (request.type == AccessRequestType::ProcessOpen ||
        request.type == AccessRequestType::ProcessDuplicate) {

        if (access & PROCESS_TERMINATE) {
            return ThreatAction::ProcessTerminate;
        }
        if (access & PROCESS_SUSPEND_RESUME) {
            return ThreatAction::ProcessSuspend;
        }
        if (access & PROCESS_VM_WRITE) {
            return ThreatAction::MemoryWrite;
        }
        if (access & PROCESS_CREATE_THREAD) {
            return ThreatAction::ThreadCreate;
        }
    }

    if (request.type == AccessRequestType::ThreadOpen ||
        request.type == AccessRequestType::ThreadDuplicate) {

        if (access & THREAD_TERMINATE) {
            return ThreatAction::ThreadTerminate;
        }
        if (access & THREAD_SUSPEND_RESUME) {
            return ThreatAction::ThreadSuspend;
        }
        if (access & THREAD_SET_CONTEXT) {
            return ThreatAction::ContextModify;
        }
    }

    if (request.type == AccessRequestType::APCQueue) {
        return ThreatAction::APCQueue;
    }

    return ThreatAction::None;
}

bool ProcessProtectionImpl::LoadNtdllFunctions() {
#ifdef _WIN32
    m_hNtdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!m_hNtdll) {
        return false;
    }

    m_pNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(
        ::GetProcAddress(m_hNtdll, "NtQueryInformationProcess"));

    m_pNtSetInformationProcess = reinterpret_cast<NtSetInformationProcess_t>(
        ::GetProcAddress(m_hNtdll, "NtSetInformationProcess"));

    m_pNtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(
        ::GetProcAddress(m_hNtdll, "NtSetInformationThread"));

    m_pRtlSetProcessIsCritical = reinterpret_cast<RtlSetProcessIsCritical_t>(
        ::GetProcAddress(m_hNtdll, "RtlSetProcessIsCritical"));

    return m_pNtQueryInformationProcess != nullptr;
#else
    return true;
#endif
}

std::vector<uint32_t> ProcessProtectionImpl::EnumerateThreadIds(uint32_t processId) const {
    std::vector<uint32_t> threadIds;

#ifdef _WIN32
    HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return threadIds;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    if (::Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {
                threadIds.push_back(te.th32ThreadID);
            }
        } while (::Thread32Next(hSnapshot, &te));
    }

    ::CloseHandle(hSnapshot);
#endif

    return threadIds;
}

bool ProcessProtectionImpl::IsOwnProcess(uint32_t processId) const {
    return processId == GetCurrentProcessIdSafe();
}

bool ProcessProtectionImpl::IsShadowStrikeComponent(uint32_t processId) const {
    std::wstring processName = GetProcessName(processId);
    if (processName.empty()) {
        return false;
    }

    std::wstring lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    for (const auto& component : SHADOWSTRIKE_COMPONENTS) {
        std::wstring lowerComponent(component);
        std::transform(lowerComponent.begin(), lowerComponent.end(), lowerComponent.begin(), ::towlower);

        if (lowerName == lowerComponent) {
            return true;
        }
    }

    return false;
}

// ============================================================================
// PROCESSPROTECTION CLASS IMPLEMENTATION (PUBLIC WRAPPER)
// ============================================================================

std::atomic<bool> ProcessProtection::s_instanceCreated{false};

ProcessProtection& ProcessProtection::Instance() noexcept {
    static ProcessProtection instance;
    return instance;
}

bool ProcessProtection::HasInstance() noexcept {
    return s_instanceCreated.load(std::memory_order_acquire);
}

ProcessProtection::ProcessProtection() : m_impl(std::make_unique<ProcessProtectionImpl>()) {
    s_instanceCreated.store(true, std::memory_order_release);
}

ProcessProtection::~ProcessProtection() {
    s_instanceCreated.store(false, std::memory_order_release);
}

bool ProcessProtection::Initialize(const ProcessProtectionConfiguration& config) {
    return m_impl->Initialize(config);
}

void ProcessProtection::Shutdown(std::string_view authorizationToken) {
    m_impl->Shutdown(authorizationToken);
}

bool ProcessProtection::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

ModuleStatus ProcessProtection::GetStatus() const noexcept {
    return m_impl->GetStatus();
}

bool ProcessProtection::SetConfiguration(const ProcessProtectionConfiguration& config) {
    return m_impl->SetConfiguration(config);
}

ProcessProtectionConfiguration ProcessProtection::GetConfiguration() const {
    return m_impl->GetConfiguration();
}

void ProcessProtection::SetDefaultResponse(ThreatResponse response) {
    m_impl->SetDefaultResponse(response);
}

void ProcessProtection::SetThreatResponse(ThreatAction action, ThreatResponse response) {
    m_impl->SetThreatResponse(action, response);
}

bool ProcessProtection::ElevateToPPL() {
    return m_impl->ElevateToPPL();
}

bool ProcessProtection::IsPPLProtected() const {
    return m_impl->IsPPLProtected();
}

ProtectionLevel ProcessProtection::GetProtectionLevel(uint32_t processId) {
    return m_impl->GetProtectionLevel(processId);
}

uint32_t ProcessProtection::GetProtectionLevelRaw(uint32_t processId) {
    return m_impl->GetProtectionLevelRaw(processId);
}

bool ProcessProtection::HasRequiredProtectionLevel(uint32_t processId, ProtectionLevel required) {
    return m_impl->HasRequiredProtectionLevel(processId, required);
}

bool ProcessProtection::ProtectProcess(uint32_t processId) {
    return m_impl->ProtectProcess(processId);
}

bool ProcessProtection::UnprotectProcess(uint32_t processId, std::string_view authorizationToken) {
    return m_impl->UnprotectProcess(processId, authorizationToken);
}

bool ProcessProtection::IsProcessProtected(uint32_t processId) const {
    return m_impl->IsProcessProtected(processId);
}

std::optional<ProtectedProcessInfo> ProcessProtection::GetProtectedProcessInfo(uint32_t processId) const {
    return m_impl->GetProtectedProcessInfo(processId);
}

std::vector<ProtectedProcessInfo> ProcessProtection::GetAllProtectedProcesses() const {
    return m_impl->GetAllProtectedProcesses();
}

bool ProcessProtection::SetCriticalProcess(uint32_t processId, bool critical) {
    return m_impl->SetCriticalProcess(processId, critical);
}

bool ProcessProtection::IsCriticalProcess(uint32_t processId) const {
    return m_impl->IsCriticalProcess(processId);
}

bool ProcessProtection::ProtectThread(uint32_t threadId) {
    return m_impl->ProtectThread(threadId);
}

size_t ProcessProtection::ProtectAllThreads(uint32_t processId) {
    return m_impl->ProtectAllThreads(processId);
}

bool ProcessProtection::UnprotectThread(uint32_t threadId, std::string_view authorizationToken) {
    return m_impl->UnprotectThread(threadId, authorizationToken);
}

bool ProcessProtection::IsThreadProtected(uint32_t threadId) const {
    return m_impl->IsThreadProtected(threadId);
}

std::optional<ProtectedThreadInfo> ProcessProtection::GetProtectedThreadInfo(uint32_t threadId) const {
    return m_impl->GetProtectedThreadInfo(threadId);
}

std::vector<ProtectedThreadInfo> ProcessProtection::GetProtectedThreads(uint32_t processId) const {
    return m_impl->GetProtectedThreads(processId);
}

bool ProcessProtection::HideThreadFromDebugger(uint32_t threadId) {
    return m_impl->HideThreadFromDebugger(threadId);
}

bool ProcessProtection::IsAccessAllowed(uint32_t callerPid, uint32_t targetPid, uint32_t desiredAccess) {
    return m_impl->IsAccessAllowed(callerPid, targetPid, desiredAccess);
}

AccessDecisionResult ProcessProtection::FilterAccessRequest(const AccessRequest& request) {
    return m_impl->FilterAccessRequest(request);
}

uint32_t ProcessProtection::StripDangerousAccess(uint32_t desiredAccess, bool isThread) {
    return m_impl->StripDangerousAccess(desiredAccess, isThread);
}

void ProcessProtection::SetBlockedProcessAccess(uint32_t accessMask) {
    m_impl->SetBlockedProcessAccess(accessMask);
}

void ProcessProtection::SetBlockedThreadAccess(uint32_t accessMask) {
    m_impl->SetBlockedThreadAccess(accessMask);
}

bool ProcessProtection::ApplyRestrictiveSecurityDescriptor(uint32_t processId) {
    return m_impl->ApplyRestrictiveSecurityDescriptor(processId);
}

std::vector<uint8_t> ProcessProtection::GetProcessSecurityDescriptor(uint32_t processId) {
    return m_impl->GetProcessSecurityDescriptor(processId);
}

bool ProcessProtection::SetProcessIntegrityLevel(uint32_t processId, uint32_t integrityLevel) {
    return m_impl->SetProcessIntegrityLevel(processId, integrityLevel);
}

uint32_t ProcessProtection::GetProcessIntegrityLevel(uint32_t processId) {
    return m_impl->GetProcessIntegrityLevel(processId);
}

bool ProcessProtection::AddToWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    return m_impl->AddToWhitelist(processName, authorizationToken);
}

bool ProcessProtection::RemoveFromWhitelist(std::wstring_view processName, std::string_view authorizationToken) {
    return m_impl->RemoveFromWhitelist(processName, authorizationToken);
}

bool ProcessProtection::IsWhitelisted(std::wstring_view processName) const {
    return m_impl->IsWhitelisted(processName);
}

bool ProcessProtection::IsWhitelisted(uint32_t processId) const {
    return m_impl->IsWhitelisted(processId);
}

uint64_t ProcessProtection::RegisterAccessCallback(AccessDecisionCallback callback) {
    return m_impl->RegisterAccessCallback(std::move(callback));
}

void ProcessProtection::UnregisterAccessCallback(uint64_t callbackId) {
    m_impl->UnregisterAccessCallback(callbackId);
}

uint64_t ProcessProtection::RegisterBlockedAccessCallback(BlockedAccessCallback callback) {
    return m_impl->RegisterBlockedAccessCallback(std::move(callback));
}

void ProcessProtection::UnregisterBlockedAccessCallback(uint64_t callbackId) {
    m_impl->UnregisterBlockedAccessCallback(callbackId);
}

uint64_t ProcessProtection::RegisterProtectionStatusCallback(ProtectionStatusCallback callback) {
    return m_impl->RegisterProtectionStatusCallback(std::move(callback));
}

void ProcessProtection::UnregisterProtectionStatusCallback(uint64_t callbackId) {
    m_impl->UnregisterProtectionStatusCallback(callbackId);
}

uint64_t ProcessProtection::RegisterThreatCallback(ThreatCallback callback) {
    return m_impl->RegisterThreatCallback(std::move(callback));
}

void ProcessProtection::UnregisterThreatCallback(uint64_t callbackId) {
    m_impl->UnregisterThreatCallback(callbackId);
}

ProcessProtectionStatistics ProcessProtection::GetStatistics() const {
    return m_impl->GetStatistics();
}

void ProcessProtection::ResetStatistics(std::string_view authorizationToken) {
    m_impl->ResetStatistics(authorizationToken);
}

std::vector<BlockedAccessEvent> ProcessProtection::GetBlockedAccessHistory(size_t maxEntries) const {
    return m_impl->GetBlockedAccessHistory(maxEntries);
}

void ProcessProtection::ClearBlockedAccessHistory(std::string_view authorizationToken) {
    m_impl->ClearBlockedAccessHistory(authorizationToken);
}

std::string ProcessProtection::ExportReport() const {
    return m_impl->ExportReport();
}

bool ProcessProtection::SelfTest() {
    return m_impl->SelfTest();
}

bool ProcessProtection::VerifyProcessIntegrity(uint32_t processId) {
    return m_impl->VerifyProcessIntegrity(processId);
}

std::string ProcessProtection::GetVersionString() noexcept {
    return std::to_string(ProcessProtectionConstants::VERSION_MAJOR) + "." +
           std::to_string(ProcessProtectionConstants::VERSION_MINOR) + "." +
           std::to_string(ProcessProtectionConstants::VERSION_PATCH);
}

// ============================================================================
// CONFIGURATION METHODS
// ============================================================================

bool ProcessProtectionConfiguration::IsValid() const noexcept {
    if (monitorIntervalMs < 100 || monitorIntervalMs > 600000) {
        return false;
    }

    return true;
}

// ============================================================================
// STRUCTURE METHODS
// ============================================================================

std::string BlockedAccessEvent::GetSummary() const {
    std::ostringstream oss;
    oss << "Blocked access: caller=" << request.callerProcessId
        << " target=" << request.targetProcessId
        << " access=0x" << std::hex << request.desiredAccess
        << " threat=" << static_cast<uint32_t>(threatAction);
    return oss.str();
}

std::string BlockedAccessEvent::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"eventId\": " << eventId << ",\n";
    oss << "  \"callerPid\": " << request.callerProcessId << ",\n";
    oss << "  \"targetPid\": " << request.targetProcessId << ",\n";
    oss << "  \"desiredAccess\": " << request.desiredAccess << ",\n";
    oss << "  \"decision\": " << static_cast<int>(decision.decision) << ",\n";
    oss << "  \"threatAction\": " << static_cast<uint32_t>(threatAction) << "\n";
    oss << "}";
    return oss.str();
}

void ProcessProtectionStatistics::Reset() noexcept {
    totalProtectedProcesses.store(0, std::memory_order_relaxed);
    totalProtectedThreads.store(0, std::memory_order_relaxed);
    totalAccessRequests.store(0, std::memory_order_relaxed);
    totalAccessBlocked.store(0, std::memory_order_relaxed);
    totalAccessReduced.store(0, std::memory_order_relaxed);
    processTerminationBlocked.store(0, std::memory_order_relaxed);
    threadTerminationBlocked.store(0, std::memory_order_relaxed);
    memoryWriteBlocked.store(0, std::memory_order_relaxed);
    threadCreationBlocked.store(0, std::memory_order_relaxed);
    apcInjectionBlocked.store(0, std::memory_order_relaxed);
    handleDuplicationBlocked.store(0, std::memory_order_relaxed);
    startTime = Clock::now();
}

std::string ProcessProtectionStatistics::ToJson() const {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"totalProtectedProcesses\": " << totalProtectedProcesses.load() << ",\n";
    oss << "  \"totalProtectedThreads\": " << totalProtectedThreads.load() << ",\n";
    oss << "  \"totalAccessRequests\": " << totalAccessRequests.load() << ",\n";
    oss << "  \"totalAccessBlocked\": " << totalAccessBlocked.load() << ",\n";
    oss << "  \"processTerminationBlocked\": " << processTerminationBlocked.load() << ",\n";
    oss << "  \"threadTerminationBlocked\": " << threadTerminationBlocked.load() << ",\n";
    oss << "  \"memoryWriteBlocked\": " << memoryWriteBlocked.load() << ",\n";
    oss << "  \"threadCreationBlocked\": " << threadCreationBlocked.load() << ",\n";
    oss << "  \"apcInjectionBlocked\": " << apcInjectionBlocked.load() << "\n";
    oss << "}";
    return oss.str();
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

std::string_view GetProtectionTypeName(ProtectionType type) noexcept {
    switch (type) {
        case ProtectionType::None: return "None";
        case ProtectionType::ProtectedLight: return "Protected Light";
        case ProtectionType::Protected: return "Protected";
        default: return "Unknown";
    }
}

std::string_view GetProtectionSignerName(ProtectionSigner signer) noexcept {
    switch (signer) {
        case ProtectionSigner::None: return "None";
        case ProtectionSigner::Authenticode: return "Authenticode";
        case ProtectionSigner::CodeGen: return "CodeGen";
        case ProtectionSigner::Antimalware: return "Antimalware";
        case ProtectionSigner::Lsa: return "LSA";
        case ProtectionSigner::Windows: return "Windows";
        case ProtectionSigner::WinTcb: return "WinTcb";
        default: return "Unknown";
    }
}

std::string_view GetProtectionStatusName(ProtectionStatus status) noexcept {
    switch (status) {
        case ProtectionStatus::Unprotected: return "Unprotected";
        case ProtectionStatus::UserModeOnly: return "User-Mode Only";
        case ProtectionStatus::KernelProtected: return "Kernel Protected";
        case ProtectionStatus::PPLProtected: return "PPL Protected";
        case ProtectionStatus::Critical: return "Critical";
        default: return "Unknown";
    }
}

std::string_view GetAccessRequestTypeName(AccessRequestType type) noexcept {
    switch (type) {
        case AccessRequestType::ProcessOpen: return "Process Open";
        case AccessRequestType::ProcessDuplicate: return "Process Duplicate";
        case AccessRequestType::ThreadOpen: return "Thread Open";
        case AccessRequestType::ThreadDuplicate: return "Thread Duplicate";
        case AccessRequestType::HandleDuplicate: return "Handle Duplicate";
        case AccessRequestType::MemoryRead: return "Memory Read";
        case AccessRequestType::MemoryWrite: return "Memory Write";
        case AccessRequestType::ThreadCreate: return "Thread Create";
        case AccessRequestType::APCQueue: return "APC Queue";
        default: return "Unknown";
    }
}

std::string_view GetThreatActionName(ThreatAction action) noexcept {
    switch (action) {
        case ThreatAction::None: return "None";
        case ThreatAction::ProcessTerminate: return "Process Terminate";
        case ThreatAction::ProcessSuspend: return "Process Suspend";
        case ThreatAction::ThreadTerminate: return "Thread Terminate";
        case ThreatAction::ThreadSuspend: return "Thread Suspend";
        case ThreatAction::MemoryWrite: return "Memory Write";
        case ThreatAction::MemoryAlloc: return "Memory Allocate";
        case ThreatAction::ThreadCreate: return "Thread Create";
        case ThreatAction::APCQueue: return "APC Queue";
        case ThreatAction::HandleDuplicate: return "Handle Duplicate";
        case ThreatAction::TokenSteal: return "Token Steal";
        case ThreatAction::ContextModify: return "Context Modify";
        case ThreatAction::DebugAttach: return "Debug Attach";
        default: return "Multiple";
    }
}

std::string FormatAccessRights(uint32_t accessRights, bool isThread) {
    std::ostringstream oss;
    oss << "0x" << std::hex << accessRights << " (";

    std::vector<std::string> rights;

    if (!isThread) {
        if (accessRights & PROCESS_TERMINATE) rights.push_back("TERMINATE");
        if (accessRights & PROCESS_CREATE_THREAD) rights.push_back("CREATE_THREAD");
        if (accessRights & PROCESS_VM_OPERATION) rights.push_back("VM_OPERATION");
        if (accessRights & PROCESS_VM_READ) rights.push_back("VM_READ");
        if (accessRights & PROCESS_VM_WRITE) rights.push_back("VM_WRITE");
        if (accessRights & PROCESS_DUP_HANDLE) rights.push_back("DUP_HANDLE");
        if (accessRights & PROCESS_SUSPEND_RESUME) rights.push_back("SUSPEND_RESUME");
        if (accessRights & PROCESS_QUERY_INFORMATION) rights.push_back("QUERY_INFO");
        if (accessRights & PROCESS_SET_INFORMATION) rights.push_back("SET_INFO");
    } else {
        if (accessRights & THREAD_TERMINATE) rights.push_back("TERMINATE");
        if (accessRights & THREAD_SUSPEND_RESUME) rights.push_back("SUSPEND_RESUME");
        if (accessRights & THREAD_GET_CONTEXT) rights.push_back("GET_CONTEXT");
        if (accessRights & THREAD_SET_CONTEXT) rights.push_back("SET_CONTEXT");
        if (accessRights & THREAD_SET_INFORMATION) rights.push_back("SET_INFO");
        if (accessRights & THREAD_QUERY_INFORMATION) rights.push_back("QUERY_INFO");
    }

    for (size_t i = 0; i < rights.size(); ++i) {
        if (i > 0) oss << "|";
        oss << rights[i];
    }

    oss << ")";
    return oss.str();
}

// ============================================================================
// RAII HELPERS
// ============================================================================

ProcessProtectionGuard::ProcessProtectionGuard(uint32_t processId)
    : m_processId(processId == 0 ? GetCurrentProcessIdSafe() : processId) {

    m_authToken = GenerateInternalAuthToken();

    if (ProcessProtection::HasInstance()) {
        m_protected = ProcessProtection::Instance().ProtectProcess(m_processId);
    }
}

ProcessProtectionGuard::~ProcessProtectionGuard() {
    if (m_protected && ProcessProtection::HasInstance()) {
        ProcessProtection::Instance().UnprotectProcess(m_processId, m_authToken);
    }
}

}  // namespace Security
}  // namespace ShadowStrike
