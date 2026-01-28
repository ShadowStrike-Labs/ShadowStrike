/**
 * @file ProcessMonitor.cpp
 * @brief Enterprise implementation of real-time process lifecycle monitoring system.
 *
 * The Census Taker of ShadowStrike NGAV - maintains a live, consistent view of all
 * processes on the system with full metadata, ancestry relationships, and security
 * contexts. Built for extreme scalability to handle systems with thousands of
 * concurrent processes and rapid turnover.
 *
 * @author ShadowStrike Security Team
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#include "pch.h"
#include "ProcessMonitor.hpp"

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/Logger.hpp"
#include "../../Utils/FileUtils.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/SystemUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/HashUtils.hpp"
#include "../../Whitelist/WhitelistStore.hpp"
#include "../../ThreatIntel/ThreatIntelManager.hpp"

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <algorithm>
#include <chrono>
#include <format>
#include <fstream>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <sstream>
#include <deque>
#include <unordered_set>

// ============================================================================
// WINDOWS INCLUDES
// ============================================================================
#ifdef _WIN32
#  include <Windows.h>
#  include <winternl.h>
#  include <psapi.h>
#  include <tlhelp32.h>
#  pragma comment(lib, "psapi.lib")
#endif

namespace ShadowStrike {
namespace Core {
namespace Process {

using namespace std::chrono;
using namespace Utils;
namespace fs = std::filesystem;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Convert FILETIME to uint64_t for comparison.
 */
[[nodiscard]] uint64_t FileTimeToUint64(const FILETIME& ft) noexcept {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

/**
 * @brief Convert uint64_t to system_clock time_point.
 */
[[nodiscard]] system_clock::time_point FileTimeToTimePoint(uint64_t fileTime) noexcept {
    // FILETIME is 100-nanosecond intervals since 1601-01-01
    // Convert to microseconds and adjust epoch
    const uint64_t EPOCH_DIFF = 116444736000000000ULL; // 1601 to 1970
    if (fileTime < EPOCH_DIFF) return system_clock::time_point{};

    uint64_t unixTime = (fileTime - EPOCH_DIFF) / 10; // to microseconds
    return system_clock::time_point{microseconds(unixTime)};
}

/**
 * @brief Get process start time as FILETIME uint64.
 */
[[nodiscard]] uint64_t GetProcessStartTime(HANDLE hProcess) noexcept {
    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        return FileTimeToUint64(createTime);
    }
    return MonitorConstants::INVALID_START_TIME;
}

/**
 * @brief Get process integrity level.
 */
[[nodiscard]] uint32_t GetProcessIntegrityLevel(HANDLE hProcess) noexcept {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return 0;
    }

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLength);

    std::vector<uint8_t> buffer(dwLength);
    auto pIntegrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());

    uint32_t integrityLevel = 0;
    if (GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrity, dwLength, &dwLength)) {
        DWORD sidSubAuthCount = *GetSidSubAuthorityCount(pIntegrity->Label.Sid);
        integrityLevel = *GetSidSubAuthority(pIntegrity->Label.Sid, sidSubAuthCount - 1);
    }

    CloseHandle(hToken);
    return integrityLevel;
}

/**
 * @brief Check if process is elevated.
 */
[[nodiscard]] bool IsProcessElevated(HANDLE hProcess) noexcept {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return false;
    }

    TOKEN_ELEVATION elevation;
    DWORD dwSize = 0;
    bool isElevated = false;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        isElevated = (elevation.TokenIsElevated != 0);
    }

    CloseHandle(hToken);
    return isElevated;
}

/**
 * @brief Get user name from process token.
 */
[[nodiscard]] std::pair<std::wstring, std::wstring> GetProcessUser(HANDLE hProcess) {
    std::wstring userName, domainName;

    HANDLE hToken = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return {userName, domainName};
    }

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);

    std::vector<uint8_t> buffer(dwLength);
    auto pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwLength, &dwLength)) {
        wchar_t user[256] = {}, domain[256] = {};
        DWORD userSize = 256, domainSize = 256;
        SID_NAME_USE sidType;

        if (LookupAccountSidW(nullptr, pTokenUser->User.Sid, user, &userSize,
                             domain, &domainSize, &sidType)) {
            userName = user;
            domainName = domain;
        }
    }

    CloseHandle(hToken);
    return {userName, domainName};
}

/**
 * @brief Categorize process based on path and name.
 */
[[nodiscard]] ProcessCategory CategorizeProcess(
    const std::wstring& processName,
    const std::wstring& processPath
) noexcept {
    std::wstring lowerName = StringUtils::ToLowerCase(processName);
    std::wstring lowerPath = StringUtils::ToLowerCase(processPath);

    // System critical
    if (lowerName == L"system" || lowerName == L"smss.exe" ||
        lowerName == L"csrss.exe" || lowerName == L"wininit.exe") {
        return ProcessCategory::SystemCritical;
    }

    // System core
    if (lowerName == L"services.exe" || lowerName == L"lsass.exe" ||
        lowerName == L"winlogon.exe" || lowerName == L"svchost.exe") {
        return ProcessCategory::SystemCore;
    }

    // Browsers
    if (lowerName == L"chrome.exe" || lowerName == L"firefox.exe" ||
        lowerName == L"msedge.exe" || lowerName == L"iexplore.exe") {
        return ProcessCategory::Browser;
    }

    // Office
    if (lowerName.find(L"winword") != std::wstring::npos ||
        lowerName.find(L"excel") != std::wstring::npos ||
        lowerName.find(L"powerpnt") != std::wstring::npos) {
        return ProcessCategory::Office;
    }

    // Script hosts
    if (lowerName == L"powershell.exe" || lowerName == L"pwsh.exe" ||
        lowerName == L"cscript.exe" || lowerName == L"wscript.exe" ||
        lowerName == L"python.exe" || lowerName == L"node.exe") {
        return ProcessCategory::ScriptHost;
    }

    // LOLBins
    if (lowerName == L"certutil.exe" || lowerName == L"bitsadmin.exe" ||
        lowerName == L"rundll32.exe" || lowerName == L"regsvr32.exe" ||
        lowerName == L"mshta.exe" || lowerName == L"installutil.exe") {
        return ProcessCategory::LOLBin;
    }

    // System utilities
    if (lowerName == L"cmd.exe" || lowerName == L"conhost.exe" ||
        lowerName == L"reg.exe" || lowerName == L"sc.exe") {
        return ProcessCategory::SystemUtility;
    }

    // Check if in System32
    if (lowerPath.find(L"\\system32\\") != std::wstring::npos ||
        lowerPath.find(L"\\syswow64\\") != std::wstring::npos) {
        return ProcessCategory::SystemService;
    }

    return ProcessCategory::UserApplication;
}

} // anonymous namespace

// ============================================================================
// MonitorConfig FACTORY METHODS
// ============================================================================

MonitorConfig MonitorConfig::CreateDefault() noexcept {
    return MonitorConfig{};
}

MonitorConfig MonitorConfig::CreateMinimal() noexcept {
    MonitorConfig config;
    config.useKernelCallback = false;
    config.useETWProvider = false;
    config.useFilterManager = false;
    config.useWMI = false;

    config.maxCachedProcesses = 4096;
    config.maxCachedTerminated = 1024;
    config.enablePeriodicSnapshots = true;
    config.snapshotIntervalMs = 300000; // 5 minutes

    config.collectCommandLine = false;
    config.collectWorkingDirectory = false;
    config.computeImageHash = false;
    config.lazyMetadataFetch = true;

    config.trackAncestry = false;
    config.detectPPIDSpoofing = false;
    config.enableHistoricalTracking = false;

    return config;
}

MonitorConfig MonitorConfig::CreateForensic() noexcept {
    MonitorConfig config;
    config.useKernelCallback = true;
    config.useETWProvider = true;
    config.useFilterManager = true;
    config.useWMI = true;

    config.maxCachedProcesses = MonitorConstants::MAX_CACHED_PROCESSES;
    config.maxCachedTerminated = MonitorConstants::MAX_CACHED_TERMINATED;
    config.enablePeriodicSnapshots = true;
    config.snapshotIntervalMs = 60000; // 1 minute

    config.collectCommandLine = true;
    config.collectWorkingDirectory = true;
    config.collectUserInfo = true;
    config.collectIntegrity = true;
    config.computeImageHash = true;
    config.lazyMetadataFetch = false;

    config.trackAncestry = true;
    config.detectPPIDSpoofing = true;
    config.enableHistoricalTracking = true;
    config.maxHistoricalEntries = MonitorConstants::MAX_HISTORICAL_ENTRIES;

    config.enableWhitelistIntegration = true;
    config.enableThreatIntelIntegration = true;

    return config;
}

// ============================================================================
// MonitorStatistics METHODS
// ============================================================================

void MonitorStatistics::Reset() noexcept {
    totalProcessesTracked.store(0, std::memory_order_relaxed);
    currentActiveProcesses.store(0, std::memory_order_relaxed);
    processCreations.store(0, std::memory_order_relaxed);
    processTerminations.store(0, std::memory_order_relaxed);
    processesDiscoveredBySnapshot.store(0, std::memory_order_relaxed);

    eventsReceived.store(0, std::memory_order_relaxed);
    eventsProcessed.store(0, std::memory_order_relaxed);
    eventsDropped.store(0, std::memory_order_relaxed);
    eventQueueHighWatermark.store(0, std::memory_order_relaxed);

    cacheLookups.store(0, std::memory_order_relaxed);
    cacheHits.store(0, std::memory_order_relaxed);
    cacheMisses.store(0, std::memory_order_relaxed);
    cacheFetchedLive.store(0, std::memory_order_relaxed);
    cacheEvictions.store(0, std::memory_order_relaxed);
    staleEntryDetections.store(0, std::memory_order_relaxed);

    totalLookupTimeUs.store(0, std::memory_order_relaxed);
    minLookupTimeUs.store(UINT64_MAX, std::memory_order_relaxed);
    maxLookupTimeUs.store(0, std::memory_order_relaxed);

    ancestryLookups.store(0, std::memory_order_relaxed);
    orphanProcessesDetected.store(0, std::memory_order_relaxed);
    ppidSpoofingDetected.store(0, std::memory_order_relaxed);

    lookupErrors.store(0, std::memory_order_relaxed);
    accessDeniedErrors.store(0, std::memory_order_relaxed);
    eventProcessingErrors.store(0, std::memory_order_relaxed);

    callbacksInvoked.store(0, std::memory_order_relaxed);
    callbackErrors.store(0, std::memory_order_relaxed);
}

[[nodiscard]] double MonitorStatistics::GetCacheHitRatio() const noexcept {
    uint64_t lookups = cacheLookups.load(std::memory_order_relaxed);
    if (lookups == 0) return 0.0;

    uint64_t hits = cacheHits.load(std::memory_order_relaxed);
    return (static_cast<double>(hits) / lookups) * 100.0;
}

[[nodiscard]] double MonitorStatistics::GetAverageLookupTimeUs() const noexcept {
    uint64_t lookups = cacheLookups.load(std::memory_order_relaxed);
    if (lookups == 0) return 0.0;

    uint64_t totalTime = totalLookupTimeUs.load(std::memory_order_relaxed);
    return static_cast<double>(totalTime) / lookups;
}

[[nodiscard]] double MonitorStatistics::GetEventsPerSecond() const noexcept {
    // This would need timing tracking - simplified for now
    return 0.0;
}

// ============================================================================
// ExtendedProcessInfo METHODS
// ============================================================================

[[nodiscard]] Utils::ProcessUtils::ProcessInfo ExtendedProcessInfo::ToProcessInfo() const {
    Utils::ProcessUtils::ProcessInfo info;
    info.pid = uniqueId.pid;
    info.processName = processName;
    info.processPath = processPath;
    info.commandLine = commandLine;
    info.parentPid = parentPid;
    info.sessionId = sessionId;
    info.isWow64 = isWow64;
    return info;
}

[[nodiscard]] Utils::ProcessUtils::ProcessBasicInfo ExtendedProcessInfo::ToBasicInfo() const {
    Utils::ProcessUtils::ProcessBasicInfo info;
    info.pid = uniqueId.pid;
    info.processName = processName;
    info.processPath = processPath;
    info.parentPid = parentPid;
    return info;
}

[[nodiscard]] bool ExtendedProcessInfo::IsStale(std::chrono::milliseconds maxAge) const noexcept {
    if (!metadataComplete) return true;

    auto age = system_clock::now() - lastUpdateTime;
    return age > maxAge;
}

// ============================================================================
// PIMPL IMPLEMENTATION
// ============================================================================

/**
 * @brief Private implementation class for ProcessMonitor.
 */
class ProcessMonitor::Impl {
public:
    // ========================================================================
    // MEMBERS
    // ========================================================================

    // Thread safety
    mutable std::shared_mutex m_configMutex;
    mutable std::shared_mutex m_cacheMutex;
    mutable std::shared_mutex m_eventMutex;
    mutable std::shared_mutex m_callbackMutex;
    mutable std::shared_mutex m_historyMutex;
    mutable std::mutex m_eventQueueMutex;

    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_shuttingDown{false};
    std::atomic<uint64_t> m_cacheVersion{1};
    std::atomic<uint64_t> m_eventSequence{1};

    // Configuration
    MonitorConfig m_config{};

    // Statistics
    MonitorStatistics m_stats{};

    // Process cache (PID + start time -> full info)
    std::unordered_map<ProcessUniqueId, ExtendedProcessInfo, ProcessUniqueIdHash> m_processCache;
    std::unordered_map<uint32_t, ProcessUniqueId> m_pidToUniqueId;  // Quick PID lookup

    // Historical data (terminated processes)
    std::deque<ExtendedProcessInfo> m_terminatedProcesses;
    std::unordered_map<ProcessUniqueId, ExtendedProcessInfo, ProcessUniqueIdHash> m_historicalCache;

    // Event queue
    std::deque<ProcessEvent> m_eventQueue;
    std::condition_variable m_eventCV;

    // Callbacks
    std::atomic<uint64_t> m_nextCallbackId{1};
    std::unordered_map<uint64_t, ProcessCallback> m_processCallbacks;
    std::unordered_map<uint64_t, ProcessEventCallback> m_eventCallbacks;
    std::unordered_map<uint64_t, SuspiciousActivityCallback> m_suspiciousCallbacks;
    std::unordered_map<uint64_t, AncestryAnomalyCallback> m_ancestryCallbacks;

    // Worker threads
    std::vector<std::jthread> m_workerThreads;

    // ========================================================================
    // CONSTRUCTOR / DESTRUCTOR
    // ========================================================================

    Impl() = default;
    ~Impl() = default;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    [[nodiscard]] bool Initialize(const MonitorConfig& config) {
        std::unique_lock lock(m_configMutex);

        if (m_initialized.load(std::memory_order_acquire)) {
            Logger::Warn("ProcessMonitor::Impl already initialized");
            return true;
        }

        try {
            Logger::Info("ProcessMonitor::Impl: Initializing");

            // Store configuration
            m_config = config;

            // Reset statistics
            m_stats.Reset();

            // Perform initial snapshot
            if (!TakeInitialSnapshot()) {
                Logger::Error("ProcessMonitor: Failed to take initial snapshot");
                return false;
            }

            // Start worker threads
            StartWorkerThreads();

            m_initialized.store(true, std::memory_order_release);
            Logger::Info("ProcessMonitor::Impl: Initialization complete - {} processes tracked",
                m_processCache.size());

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ProcessMonitor::Impl: Initialization exception: {}", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        Logger::Info("ProcessMonitor::Impl: Shutting down");

        m_shuttingDown.store(true, std::memory_order_release);

        // Stop worker threads
        m_eventCV.notify_all();
        m_workerThreads.clear();

        // Clear data structures
        {
            std::unique_lock cacheLock(m_cacheMutex);
            m_processCache.clear();
            m_pidToUniqueId.clear();
        }

        {
            std::unique_lock historyLock(m_historyMutex);
            m_terminatedProcesses.clear();
            m_historicalCache.clear();
        }

        {
            std::unique_lock eventLock(m_eventQueueMutex);
            m_eventQueue.clear();
        }

        {
            std::unique_lock cbLock(m_callbackMutex);
            m_processCallbacks.clear();
            m_eventCallbacks.clear();
            m_suspiciousCallbacks.clear();
            m_ancestryCallbacks.clear();
        }

        m_initialized.store(false, std::memory_order_release);
        Logger::Info("ProcessMonitor::Impl: Shutdown complete");
    }

    // ========================================================================
    // INITIAL SNAPSHOT
    // ========================================================================

    [[nodiscard]] bool TakeInitialSnapshot() {
        try {
            Logger::Info("ProcessMonitor: Taking initial system snapshot");

            // KERNEL DRIVER INTEGRATION WILL COME HERE
            // For enterprise-grade visibility, we would use NtQuerySystemInformation
            // or walk the EPROCESS list in the kernel to detect hidden processes (DKOM)
            // that CreateToolhelp32Snapshot cannot see.

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                Logger::Error("ProcessMonitor: CreateToolhelp32Snapshot failed: {}",
                    GetLastError());
                return false;
            }

            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            uint32_t processCount = 0;
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    // Create process info
                    ExtendedProcessInfo info = CreateProcessInfoFromSnapshot(pe32);

                    if (info.IsValid()) {
                        std::unique_lock lock(m_cacheMutex);
                        m_processCache[info.uniqueId] = info;
                        m_pidToUniqueId[info.uniqueId.pid] = info.uniqueId;
                        processCount++;
                    }

                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

            m_stats.totalProcessesTracked.store(processCount, std::memory_order_relaxed);
            m_stats.currentActiveProcesses.store(processCount, std::memory_order_relaxed);
            m_stats.processesDiscoveredBySnapshot.store(processCount, std::memory_order_relaxed);

            Logger::Info("ProcessMonitor: Initial snapshot complete - {} processes", processCount);
            return true;

        } catch (const std::exception& e) {
            Logger::Error("ProcessMonitor: Initial snapshot exception: {}", e.what());
            return false;
        }
    }

    [[nodiscard]] ExtendedProcessInfo CreateProcessInfoFromSnapshot(const PROCESSENTRY32W& pe32) {
        ExtendedProcessInfo info{};
        info.uniqueId.pid = pe32.th32ProcessID;
        info.processName = pe32.szExeFile;
        info.parentPid = pe32.th32ParentProcessID;
        info.createTime = system_clock::now(); // Approximation
        info.lastSeenTime = system_clock::now();
        info.lastUpdateTime = system_clock::now();
        info.state = ProcessState::Running;
        info.discoverySource = EventSource::Snapshot;

        // Open process for detailed info
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pe32.th32ProcessID
        );

        if (hProcess) {
            // Get start time
            info.uniqueId.startTime = GetProcessStartTime(hProcess);
            info.createTime = FileTimeToTimePoint(info.uniqueId.startTime);

            // Get process path
            wchar_t processPath[MAX_PATH] = {};
            DWORD pathSize = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
                info.processPath = processPath;
            }

            // Get session ID
            DWORD sessionId = 0;
            if (ProcessIdToSessionId(pe32.th32ProcessID, &sessionId)) {
                info.sessionId = sessionId;
            }

            // Get user info if configured
            if (m_config.collectUserInfo) {
                auto [userName, domainName] = GetProcessUser(hProcess);
                info.userName = userName;
                info.domainName = domainName;
            }

            // Get integrity level if configured
            if (m_config.collectIntegrity) {
                info.integrityLevel = GetProcessIntegrityLevel(hProcess);
                info.isElevated = IsProcessElevated(hProcess);
            }

            // Check WOW64
            BOOL isWow64 = FALSE;
            if (IsWow64Process(hProcess, &isWow64)) {
                info.isWow64 = (isWow64 != FALSE);
            }

            CloseHandle(hProcess);
        } else {
            // Process inaccessible - likely system process or protected
            if (GetLastError() == ERROR_ACCESS_DENIED) {
                info.isProtectedProcess = true;
                m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            }

            // Use approximate start time
            info.uniqueId.startTime = FileTimeToUint64(FILETIME{});
        }

        // Categorize process
        info.category = CategorizeProcess(info.processName, info.processPath);
        info.isSystemProcess = (info.category == ProcessCategory::SystemCritical ||
                               info.category == ProcessCategory::SystemCore);
        info.isCriticalProcess = (info.category == ProcessCategory::SystemCritical);
        info.isLOLBin = (info.category == ProcessCategory::LOLBin);

        // Check whitelist if configured
        if (m_config.enableWhitelistIntegration && !info.processPath.empty()) {
            // Would integrate with WhitelistStore here
            // info.isWhitelisted = WhitelistStore::Instance().IsWhitelisted(info.processPath);
        }

        info.metadataComplete = true;
        info.cacheVersion = m_cacheVersion.load(std::memory_order_relaxed);

        return info;
    }

    // ========================================================================
    // CACHE OPERATIONS
    // ========================================================================

    [[nodiscard]] std::optional<ExtendedProcessInfo> GetProcessInfoImpl(uint32_t pid) const {
        const auto lookupStart = steady_clock::now();
        m_stats.cacheLookups.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock lock(m_cacheMutex);

        // Quick lookup via PID map
        auto pidIt = m_pidToUniqueId.find(pid);
        if (pidIt == m_pidToUniqueId.end()) {
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();

            // Try to fetch live from system
            return FetchLiveProcessInfo(pid);
        }

        // Found in cache
        auto cacheIt = m_processCache.find(pidIt->second);
        if (cacheIt == m_processCache.end()) {
            m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();
            return FetchLiveProcessInfo(pid);
        }

        const auto& info = cacheIt->second;

        // Check if stale
        if (info.IsStale(milliseconds(m_config.cacheEntryTTLMs))) {
            m_stats.staleEntryDetections.fetch_add(1, std::memory_order_relaxed);
            lock.unlock();
            return FetchLiveProcessInfo(pid);
        }

        m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);

        auto lookupEnd = steady_clock::now();
        uint64_t lookupTimeUs = duration_cast<microseconds>(lookupEnd - lookupStart).count();

        m_stats.totalLookupTimeUs.fetch_add(lookupTimeUs, std::memory_order_relaxed);
        UpdateMinMax(m_stats.minLookupTimeUs, m_stats.maxLookupTimeUs, lookupTimeUs);

        return info;
    }

    [[nodiscard]] std::optional<ExtendedProcessInfo> GetProcessInfoImpl(
        const ProcessUniqueId& uniqueId
    ) const {
        std::shared_lock lock(m_cacheMutex);

        auto it = m_processCache.find(uniqueId);
        if (it != m_processCache.end()) {
            m_stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
            return it->second;
        }

        m_stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        return std::nullopt;
    }

    [[nodiscard]] std::optional<ExtendedProcessInfo> FetchLiveProcessInfo(uint32_t pid) const {
        m_stats.cacheFetchedLive.fetch_add(1, std::memory_order_relaxed);

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid
        );

        if (!hProcess) {
            m_stats.lookupErrors.fetch_add(1, std::memory_order_relaxed);
            return std::nullopt;
        }

        ExtendedProcessInfo info{};
        info.uniqueId.pid = pid;
        info.uniqueId.startTime = GetProcessStartTime(hProcess);
        info.createTime = FileTimeToTimePoint(info.uniqueId.startTime);

        // Get process path
        wchar_t processPath[MAX_PATH] = {};
        DWORD pathSize = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize)) {
            info.processPath = processPath;
            info.processName = fs::path(processPath).filename().wstring();
        }

        // Get session ID
        DWORD sessionId = 0;
        if (ProcessIdToSessionId(pid, &sessionId)) {
            info.sessionId = sessionId;
        }

        info.state = ProcessState::Running;
        info.lastSeenTime = system_clock::now();
        info.lastUpdateTime = system_clock::now();
        info.metadataComplete = false; // Minimal fetch

        CloseHandle(hProcess);
        return info;
    }

    void UpdateMinMax(
        std::atomic<uint64_t>& minVal,
        std::atomic<uint64_t>& maxVal,
        uint64_t newVal
    ) const noexcept {
        // Update minimum
        uint64_t currentMin = minVal.load(std::memory_order_relaxed);
        while (newVal < currentMin &&
               !minVal.compare_exchange_weak(currentMin, newVal, std::memory_order_relaxed));

        // Update maximum
        uint64_t currentMax = maxVal.load(std::memory_order_relaxed);
        while (newVal > currentMax &&
               !maxVal.compare_exchange_weak(currentMax, newVal, std::memory_order_relaxed));
    }

    // ========================================================================
    // ANCESTRY OPERATIONS
    // ========================================================================

    [[nodiscard]] AncestryChain GetAncestryImpl(uint32_t pid, uint32_t maxDepth) const {
        AncestryChain chain{};
        m_stats.ancestryLookups.fetch_add(1, std::memory_order_relaxed);

        std::shared_lock lock(m_cacheMutex);

        // Start with target process
        auto processInfo = GetProcessInfoImpl(pid);
        if (!processInfo) {
            return chain;
        }

        chain.targetProcess = processInfo->uniqueId;
        chain.ancestors.push_back(*processInfo);
        chain.ancestorNames.push_back(processInfo->processName);

        // Walk up the parent chain
        uint32_t currentPid = processInfo->parentPid;
        uint32_t depth = 0;
        std::unordered_set<uint32_t> visitedPids; // Cycle detection

        while (currentPid != 0 && depth < maxDepth) {
            // Cycle detection
            if (visitedPids.count(currentPid)) {
                Logger::Warn("ProcessMonitor: Cycle detected in ancestry for PID {}", pid);
                chain.hasOrphan = true;
                chain.orphanAtDepth = depth;
                break;
            }
            visitedPids.insert(currentPid);

            // Get parent info
            auto parentInfo = GetProcessInfoImpl(currentPid);
            if (!parentInfo) {
                // Parent not found - orphan
                m_stats.orphanProcessesDetected.fetch_add(1, std::memory_order_relaxed);
                chain.hasOrphan = true;
                chain.orphanAtDepth = depth;
                break;
            }

            chain.ancestors.push_back(*parentInfo);
            chain.ancestorNames.push_back(parentInfo->processName);

            // Check if reached system root (System process)
            if (currentPid == 4 || parentInfo->parentPid == 0) {
                chain.isComplete = true;
                break;
            }

            currentPid = parentInfo->parentPid;
            depth++;
        }

        chain.depth = static_cast<uint32_t>(chain.ancestors.size());
        return chain;
    }

    [[nodiscard]] std::vector<ExtendedProcessInfo> GetChildrenImpl(uint32_t pid) const {
        std::vector<ExtendedProcessInfo> children;
        std::shared_lock lock(m_cacheMutex);

        for (const auto& [uniqueId, info] : m_processCache) {
            if (info.parentPid == pid && info.state != ProcessState::Terminated) {
                children.push_back(info);
            }
        }

        return children;
    }

    [[nodiscard]] bool DetectPPIDSpoofingImpl(uint32_t pid) const {
        if (!m_config.detectPPIDSpoofing) return false;

        auto processInfo = GetProcessInfoImpl(pid);
        if (!processInfo) return false;

        // Get claimed parent
        auto parentInfo = GetProcessInfoImpl(processInfo->parentPid);
        if (!parentInfo) {
            // Parent doesn't exist - possible spoofing or orphan
            return true;
        }

        // Check if parent was created AFTER child (impossible naturally)
        if (parentInfo->createTime > processInfo->createTime) {
            Logger::Warn("ProcessMonitor: PPID spoofing detected - PID {} claims parent {} "
                        "created after child", pid, processInfo->parentPid);
            m_stats.ppidSpoofingDetected.fetch_add(1, std::memory_order_relaxed);

            InvokeSuspiciousCallbacks(processInfo->uniqueId,
                L"PPID spoofing: Parent created after child");

            return true;
        }

        return false;
    }

    // ========================================================================
    // EVENT PROCESSING
    // ========================================================================

    void OnProcessCreateImpl(const ProcessEvent& event) {
        try {
            // KERNEL DRIVER INTEGRATION WILL COME HERE
            // In a production environment, we would use PsSetCreateProcessNotifyRoutine
            // to get synchronous callbacks from the kernel, ensuring we never miss a
            // short-lived process and can block execution before the main thread starts.

            m_stats.eventsReceived.fetch_add(1, std::memory_order_relaxed);
            m_stats.processCreations.fetch_add(1, std::memory_order_relaxed);

            // Create extended info from event
            ExtendedProcessInfo info{};
            info.uniqueId = event.processId;
            info.processName = event.processName;
            info.processPath = event.processPath;
            info.commandLine = event.commandLine;
            info.parentPid = event.parentId.pid;
            info.parentStartTime = event.parentId.startTime;
            info.sessionId = event.sessionId;
            info.userName = event.userName;
            info.isElevated = event.isElevated;
            info.isWow64 = event.isWow64;
            info.createTime = event.timestamp;
            info.lastSeenTime = event.timestamp;
            info.lastUpdateTime = event.timestamp;
            info.state = ProcessState::Starting;
            info.discoverySource = event.source;
            info.category = CategorizeProcess(info.processName, info.processPath);

            // Add to cache
            {
                std::unique_lock lock(m_cacheMutex);
                m_processCache[info.uniqueId] = info;
                m_pidToUniqueId[info.uniqueId.pid] = info.uniqueId;

                // Update parent's children list
                ProcessUniqueId parentId = event.parentId;
                auto parentIt = m_processCache.find(parentId);
                if (parentIt != m_processCache.end()) {
                    parentIt->second.childPids.push_back(info.uniqueId.pid);
                }
            }

            m_stats.currentActiveProcesses.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalProcessesTracked.fetch_add(1, std::memory_order_relaxed);

            Logger::Info("ProcessMonitor: Process created - PID {} ({})",
                info.uniqueId.pid, StringUtils::WideToUtf8(info.processName));

            // Invoke callbacks
            InvokeProcessCallbacks(info, true);
            InvokeEventCallbacks(event);

            // Check for PPID spoofing
            if (m_config.detectPPIDSpoofing) {
                DetectPPIDSpoofingImpl(info.uniqueId.pid);
            }

        } catch (const std::exception& e) {
            Logger::Error("ProcessMonitor: OnProcessCreate exception: {}", e.what());
            m_stats.eventProcessingErrors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void OnProcessTerminateImpl(uint32_t pid, uint32_t exitCode) {
        try {
            m_stats.processTerminations.fetch_add(1, std::memory_order_relaxed);

            std::unique_lock lock(m_cacheMutex);

            // Find process in cache
            auto pidIt = m_pidToUniqueId.find(pid);
            if (pidIt == m_pidToUniqueId.end()) {
                Logger::Debug("ProcessMonitor: Terminate event for unknown PID {}", pid);
                return;
            }

            auto cacheIt = m_processCache.find(pidIt->second);
            if (cacheIt == m_processCache.end()) {
                return;
            }

            auto& info = cacheIt->second;
            info.state = ProcessState::Terminated;
            info.isTerminated = true;
            info.exitCode = exitCode;
            info.exitTime = system_clock::now();

            Logger::Info("ProcessMonitor: Process terminated - PID {} ({}) exitCode: {}",
                pid, StringUtils::WideToUtf8(info.processName), exitCode);

            // Move to historical storage if configured
            if (m_config.enableHistoricalTracking) {
                std::unique_lock historyLock(m_historyMutex);
                m_historicalCache[info.uniqueId] = info;
                m_terminatedProcesses.push_back(info);

                if (m_terminatedProcesses.size() > m_config.maxHistoricalEntries) {
                    auto& oldest = m_terminatedProcesses.front();
                    m_historicalCache.erase(oldest.uniqueId);
                    m_terminatedProcesses.pop_front();
                }
            }

            // Invoke callbacks before removal
            InvokeProcessCallbacks(info, false);

            // Remove from active cache (but keep in historical)
            m_processCache.erase(cacheIt);
            m_pidToUniqueId.erase(pidIt);

            m_stats.currentActiveProcesses.fetch_sub(1, std::memory_order_relaxed);

        } catch (const std::exception& e) {
            Logger::Error("ProcessMonitor: OnProcessTerminate exception: {}", e.what());
            m_stats.eventProcessingErrors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ========================================================================
    // WORKER THREADS
    // ========================================================================

    void StartWorkerThreads() {
        // Event processing thread
        m_workerThreads.emplace_back([this](std::stop_token stoken) {
            EventProcessingThread(stoken);
        });

        // Periodic snapshot thread
        if (m_config.enablePeriodicSnapshots) {
            m_workerThreads.emplace_back([this](std::stop_token stoken) {
                SnapshotThread(stoken);
            });
        }

        // Dead process cleanup thread
        m_workerThreads.emplace_back([this](std::stop_token stoken) {
            CleanupThread(stoken);
        });

        Logger::Info("ProcessMonitor: {} worker threads started", m_workerThreads.size());
    }

    void EventProcessingThread(std::stop_token stoken) {
        Logger::Debug("ProcessMonitor: Event processing thread started");

        while (!stoken.stop_requested() && !m_shuttingDown.load(std::memory_order_acquire)) {
            try {
                std::unique_lock lock(m_eventQueueMutex);

                m_eventCV.wait_for(lock, milliseconds(m_config.eventProcessIntervalMs),
                    [this, &stoken]() {
                        return !m_eventQueue.empty() || stoken.stop_requested() ||
                               m_shuttingDown.load(std::memory_order_acquire);
                    });

                if (m_eventQueue.empty()) continue;

                // Process batch of events
                size_t batchSize = std::min(m_eventQueue.size(),
                                          static_cast<size_t>(m_config.eventBatchSize));

                std::vector<ProcessEvent> batch;
                batch.reserve(batchSize);

                for (size_t i = 0; i < batchSize; i++) {
                    batch.push_back(std::move(m_eventQueue.front()));
                    m_eventQueue.pop_front();
                }

                lock.unlock();

                // Process events outside lock
                for (const auto& event : batch) {
                    ProcessEventImpl(event);
                }

                m_stats.eventsProcessed.fetch_add(batchSize, std::memory_order_relaxed);

            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Event processing thread exception: {}", e.what());
            }
        }

        Logger::Debug("ProcessMonitor: Event processing thread stopped");
    }

    void ProcessEventImpl(const ProcessEvent& event) {
        switch (event.type) {
            case ProcessEventType::Created:
                OnProcessCreateImpl(event);
                break;
            case ProcessEventType::Terminated:
                OnProcessTerminateImpl(event.processId.pid, event.exitCode);
                break;
            default:
                // Other event types would be handled here
                break;
        }
    }

    void SnapshotThread(std::stop_token stoken) {
        Logger::Debug("ProcessMonitor: Snapshot thread started");

        while (!stoken.stop_requested() && !m_shuttingDown.load(std::memory_order_acquire)) {
            try {
                std::this_thread::sleep_for(milliseconds(m_config.snapshotIntervalMs));

                if (stoken.stop_requested()) break;

                RefreshSnapshotImpl();

            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Snapshot thread exception: {}", e.what());
            }
        }

        Logger::Debug("ProcessMonitor: Snapshot thread stopped");
    }

    void CleanupThread(std::stop_token stoken) {
        Logger::Debug("ProcessMonitor: Cleanup thread started");

        while (!stoken.stop_requested() && !m_shuttingDown.load(std::memory_order_acquire)) {
            try {
                std::this_thread::sleep_for(
                    milliseconds(m_config.deadProcessCleanupIntervalMs)
                );

                if (stoken.stop_requested()) break;

                CleanupDeadProcesses();

            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Cleanup thread exception: {}", e.what());
            }
        }

        Logger::Debug("ProcessMonitor: Cleanup thread stopped");
    }

    void CleanupDeadProcesses() {
        std::unique_lock lock(m_cacheMutex);

        std::vector<ProcessUniqueId> toRemove;
        auto now = system_clock::now();

        for (const auto& [uniqueId, info] : m_processCache) {
            if (info.state == ProcessState::Terminated) {
                auto timeSinceTermination = now - info.exitTime;
                if (timeSinceTermination > milliseconds(m_config.terminatedProcessRetentionMs)) {
                    toRemove.push_back(uniqueId);
                }
            }
        }

        for (const auto& uniqueId : toRemove) {
            m_processCache.erase(uniqueId);
            m_pidToUniqueId.erase(uniqueId.pid);
            m_stats.cacheEvictions.fetch_add(1, std::memory_order_relaxed);
        }

        if (!toRemove.empty()) {
            Logger::Debug("ProcessMonitor: Cleaned up {} dead processes", toRemove.size());
        }
    }

    bool RefreshSnapshotImpl() {
        Logger::Debug("ProcessMonitor: Refreshing process snapshot");

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                return false;
            }

            std::unordered_set<uint32_t> currentPids;
            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    currentPids.insert(pe32.th32ProcessID);

                    // Check if new process
                    std::shared_lock lock(m_cacheMutex);
                    if (m_pidToUniqueId.find(pe32.th32ProcessID) == m_pidToUniqueId.end()) {
                        lock.unlock();

                        // New process discovered by snapshot
                        ExtendedProcessInfo info = CreateProcessInfoFromSnapshot(pe32);
                        if (info.IsValid()) {
                            std::unique_lock writeLock(m_cacheMutex);
                            m_processCache[info.uniqueId] = info;
                            m_pidToUniqueId[info.uniqueId.pid] = info.uniqueId;

                            m_stats.processesDiscoveredBySnapshot.fetch_add(1,
                                std::memory_order_relaxed);

                            Logger::Info("ProcessMonitor: Discovered process via snapshot - PID {}",
                                info.uniqueId.pid);
                        }
                    }

                } while (Process32NextW(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);

            // Check for terminated processes
            {
                std::unique_lock lock(m_cacheMutex);
                std::vector<uint32_t> terminatedPids;

                for (const auto& [pid, uniqueId] : m_pidToUniqueId) {
                    if (currentPids.find(pid) == currentPids.end()) {
                        terminatedPids.push_back(pid);
                    }
                }

                lock.unlock();

                for (uint32_t pid : terminatedPids) {
                    OnProcessTerminateImpl(pid, 0);
                }
            }

            return true;

        } catch (const std::exception& e) {
            Logger::Error("ProcessMonitor: Snapshot refresh exception: {}", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeProcessCallbacks(const ExtendedProcessInfo& info, bool created) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_processCallbacks) {
            try {
                callback(info, created);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Process callback exception: {}", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void InvokeEventCallbacks(const ProcessEvent& event) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_eventCallbacks) {
            try {
                callback(event);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Event callback exception: {}", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void InvokeSuspiciousCallbacks(
        const ProcessUniqueId& processId,
        const std::wstring& description
    ) const {
        std::shared_lock lock(m_callbackMutex);

        for (const auto& [id, callback] : m_suspiciousCallbacks) {
            try {
                callback(processId, description);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                Logger::Error("ProcessMonitor: Suspicious callback exception: {}", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
};

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

ProcessMonitor& ProcessMonitor::Instance() {
    static ProcessMonitor instance;
    return instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

ProcessMonitor::ProcessMonitor()
    : m_impl(std::make_unique<Impl>())
{
    Logger::Info("ProcessMonitor: Constructor called");
}

ProcessMonitor::~ProcessMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    Logger::Info("ProcessMonitor: Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ProcessMonitor::Initialize(const MonitorConfig& config) {
    if (!m_impl) {
        Logger::Critical("ProcessMonitor: Implementation is null");
        return false;
    }

    return m_impl->Initialize(config);
}

void ProcessMonitor::Shutdown() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

[[nodiscard]] bool ProcessMonitor::IsInitialized() const noexcept {
    return m_impl && m_impl->m_initialized.load(std::memory_order_acquire);
}

bool ProcessMonitor::UpdateConfig(const MonitorConfig& config) {
    if (!m_impl) return false;

    std::unique_lock lock(m_impl->m_configMutex);
    m_impl->m_config = config;

    Logger::Info("ProcessMonitor: Configuration updated");
    return true;
}

[[nodiscard]] MonitorConfig ProcessMonitor::GetConfig() const {
    if (!m_impl) return MonitorConfig{};

    std::shared_lock lock(m_impl->m_configMutex);
    return m_impl->m_config;
}

// ============================================================================
// PROCESS LOOKUP
// ============================================================================

[[nodiscard]] std::optional<ExtendedProcessInfo> ProcessMonitor::GetProcessInfo(uint32_t pid) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    return m_impl->GetProcessInfoImpl(pid);
}

[[nodiscard]] std::optional<ExtendedProcessInfo> ProcessMonitor::GetProcessInfo(
    const ProcessUniqueId& uniqueId
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    return m_impl->GetProcessInfoImpl(uniqueId);
}

[[nodiscard]] std::optional<Utils::ProcessUtils::ProcessBasicInfo> ProcessMonitor::GetBasicInfo(
    uint32_t pid
) const {
    auto info = GetProcessInfo(pid);
    if (!info) return std::nullopt;

    return info->ToBasicInfo();
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetProcessesByName(
    const std::wstring& processName
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    std::wstring lowerName = StringUtils::ToLowerCase(processName);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        if (StringUtils::ToLowerCase(info.processName) == lowerName) {
            result.push_back(info);
        }
    }

    return result;
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetProcessesByPath(
    const std::wstring& processPath
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        if (StringUtils::EqualsIgnoreCase(info.processPath, processPath)) {
            result.push_back(info);
        }
    }

    return result;
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetProcessesByUser(
    const std::wstring& userName,
    const std::wstring& domainName
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        bool userMatches = StringUtils::EqualsIgnoreCase(info.userName, userName);
        bool domainMatches = domainName.empty() ||
                            StringUtils::EqualsIgnoreCase(info.domainName, domainName);

        if (userMatches && domainMatches) {
            result.push_back(info);
        }
    }

    return result;
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetProcessesBySession(
    uint32_t sessionId
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        if (info.sessionId == sessionId) {
            result.push_back(info);
        }
    }

    return result;
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetProcessesByCategory(
    ProcessCategory category
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        if (info.category == category) {
            result.push_back(info);
        }
    }

    return result;
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetAllProcesses() const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    std::vector<ExtendedProcessInfo> result;
    std::shared_lock lock(m_impl->m_cacheMutex);

    result.reserve(m_impl->m_processCache.size());
    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        result.push_back(info);
    }

    return result;
}

[[nodiscard]] bool ProcessMonitor::IsProcessAlive(uint32_t pid) const {
    auto info = GetProcessInfo(pid);
    return info && info->state != ProcessState::Terminated;
}

[[nodiscard]] bool ProcessMonitor::IsProcessAlive(const ProcessUniqueId& uniqueId) const {
    auto info = GetProcessInfo(uniqueId);
    return info && info->state != ProcessState::Terminated;
}

[[nodiscard]] std::wstring ProcessMonitor::GetProcessPath(uint32_t pid) const {
    auto info = GetProcessInfo(pid);
    return info ? info->processPath : L"";
}

[[nodiscard]] std::wstring ProcessMonitor::GetCommandLine(uint32_t pid) const {
    auto info = GetProcessInfo(pid);
    return info ? info->commandLine : L"";
}

// ============================================================================
// ANCESTRY OPERATIONS
// ============================================================================

[[nodiscard]] AncestryChain ProcessMonitor::GetAncestry(
    uint32_t pid,
    uint32_t maxDepth
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return AncestryChain{};
    }

    return m_impl->GetAncestryImpl(pid, maxDepth);
}

[[nodiscard]] std::optional<ExtendedProcessInfo> ProcessMonitor::GetParent(uint32_t pid) const {
    auto info = GetProcessInfo(pid);
    if (!info) return std::nullopt;

    return GetProcessInfo(info->parentPid);
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetChildren(uint32_t pid) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return {};
    }

    return m_impl->GetChildrenImpl(pid);
}

[[nodiscard]] std::vector<ExtendedProcessInfo> ProcessMonitor::GetDescendants(
    uint32_t pid,
    uint32_t maxDepth
) const {
    std::vector<ExtendedProcessInfo> descendants;
    std::unordered_set<uint32_t> visited;

    std::function<void(uint32_t, uint32_t)> collectDescendants =
        [&](uint32_t currentPid, uint32_t depth) {
        if (depth >= maxDepth || visited.count(currentPid)) return;
        visited.insert(currentPid);

        auto children = GetChildren(currentPid);
        for (const auto& child : children) {
            descendants.push_back(child);
            collectDescendants(child.uniqueId.pid, depth + 1);
        }
    };

    collectDescendants(pid, 0);
    return descendants;
}

[[nodiscard]] std::unique_ptr<ProcessTreeNode> ProcessMonitor::GetProcessTree(
    uint32_t rootPid
) const {
    auto rootInfo = rootPid == 0 ?
        GetProcessInfo(4) :  // System process
        GetProcessInfo(rootPid);

    if (!rootInfo) return nullptr;

    auto root = std::make_unique<ProcessTreeNode>();
    root->processId = rootInfo->uniqueId;
    root->processName = rootInfo->processName;
    root->processPath = rootInfo->processPath;
    root->state = rootInfo->state;
    root->createTime = rootInfo->createTime;
    root->depth = 0;

    // Recursively build tree
    std::function<void(ProcessTreeNode*, uint32_t)> buildTree =
        [&](ProcessTreeNode* node, uint32_t depth) {
        auto children = GetChildren(node->processId.pid);
        for (const auto& childInfo : children) {
            auto childNode = std::make_unique<ProcessTreeNode>();
            childNode->processId = childInfo.uniqueId;
            childNode->processName = childInfo.processName;
            childNode->processPath = childInfo.processPath;
            childNode->state = childInfo.state;
            childNode->createTime = childInfo.createTime;
            childNode->parent = node;
            childNode->depth = depth + 1;

            if (depth < MonitorConstants::MAX_ANCESTRY_DEPTH) {
                buildTree(childNode.get(), depth + 1);
            }

            node->children.push_back(std::move(childNode));
        }
    };

    buildTree(root.get(), 0);
    return root;
}

[[nodiscard]] bool ProcessMonitor::IsAncestorOf(
    uint32_t ancestorPid,
    uint32_t descendantPid
) const {
    auto chain = GetAncestry(descendantPid);

    for (const auto& ancestor : chain.ancestors) {
        if (ancestor.uniqueId.pid == ancestorPid) {
            return true;
        }
    }

    return false;
}

[[nodiscard]] bool ProcessMonitor::ValidateParent(uint32_t childPid) const {
    auto childInfo = GetProcessInfo(childPid);
    if (!childInfo) return false;

    auto parentInfo = GetProcessInfo(childInfo->parentPid);
    if (!parentInfo) return false;

    // Parent must have been created before child
    return parentInfo->createTime < childInfo->createTime;
}

[[nodiscard]] bool ProcessMonitor::DetectPPIDSpoofing(uint32_t pid) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->DetectPPIDSpoofingImpl(pid);
}

// ============================================================================
// EVENT INGESTION
// ============================================================================

void ProcessMonitor::OnProcessCreate(const ProcessEvent& event) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    // Queue event for processing
    {
        std::unique_lock lock(m_impl->m_eventQueueMutex);

        if (m_impl->m_eventQueue.size() >= m_impl->m_config.eventQueueSize) {
            m_impl->m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            Logger::Warn("ProcessMonitor: Event queue full, dropping event");
            return;
        }

        m_impl->m_eventQueue.push_back(event);

        uint64_t queueSize = m_impl->m_eventQueue.size();
        uint64_t currentMax = m_impl->m_stats.eventQueueHighWatermark.load(
            std::memory_order_relaxed);

        if (queueSize > currentMax) {
            m_impl->m_stats.eventQueueHighWatermark.store(queueSize,
                std::memory_order_relaxed);
        }
    }

    m_impl->m_eventCV.notify_one();
}

void ProcessMonitor::OnProcessTerminate(uint32_t pid, uint32_t exitCode) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    m_impl->OnProcessTerminateImpl(pid, exitCode);
}

void ProcessMonitor::OnProcessTerminate(const ProcessEvent& event) {
    OnProcessTerminate(event.processId.pid, event.exitCode);
}

void ProcessMonitor::OnModuleLoad(
    uint32_t pid,
    const std::wstring& modulePath,
    uintptr_t moduleBase,
    size_t moduleSize
) {
    // Module tracking would be implemented here
    Logger::Debug("ProcessMonitor: Module loaded - PID {} module {}",
        pid, StringUtils::WideToUtf8(modulePath));
}

void ProcessMonitor::SubmitEvents(std::vector<ProcessEvent> events) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock lock(m_impl->m_eventQueueMutex);

    for (auto& event : events) {
        if (m_impl->m_eventQueue.size() >= m_impl->m_config.eventQueueSize) {
            m_impl->m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            break;
        }

        m_impl->m_eventQueue.push_back(std::move(event));
    }

    lock.unlock();
    m_impl->m_eventCV.notify_one();
}

// ============================================================================
// SNAPSHOT OPERATIONS
// ============================================================================

bool ProcessMonitor::RefreshSnapshot() {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    return m_impl->RefreshSnapshotImpl();
}

[[nodiscard]] ProcessSnapshot ProcessMonitor::TakeSnapshot() const {
    ProcessSnapshot snapshot;
    snapshot.timestamp = system_clock::now();
    snapshot.snapshotVersion = m_impl ?
        m_impl->m_cacheVersion.load(std::memory_order_relaxed) : 0;

    if (m_impl && m_impl->m_initialized.load(std::memory_order_acquire)) {
        std::shared_lock lock(m_impl->m_cacheMutex);

        snapshot.processes.reserve(m_impl->m_processCache.size());
        for (const auto& [uniqueId, info] : m_impl->m_processCache) {
            snapshot.processes.push_back(info);
        }

        snapshot.processCount = static_cast<uint32_t>(snapshot.processes.size());
    }

    return snapshot;
}

[[nodiscard]] std::pair<std::vector<ExtendedProcessInfo>, std::vector<ExtendedProcessInfo>>
ProcessMonitor::CompareSnapshots(const ProcessSnapshot& previousSnapshot) const {
    std::vector<ExtendedProcessInfo> created;
    std::vector<ExtendedProcessInfo> terminated;

    auto currentSnapshot = TakeSnapshot();

    // Build sets for comparison
    std::unordered_set<ProcessUniqueId, ProcessUniqueIdHash> previousPids;
    for (const auto& info : previousSnapshot.processes) {
        previousPids.insert(info.uniqueId);
    }

    std::unordered_set<ProcessUniqueId, ProcessUniqueIdHash> currentPids;
    for (const auto& info : currentSnapshot.processes) {
        currentPids.insert(info.uniqueId);
    }

    // Find created processes
    for (const auto& info : currentSnapshot.processes) {
        if (previousPids.find(info.uniqueId) == previousPids.end()) {
            created.push_back(info);
        }
    }

    // Find terminated processes
    for (const auto& info : previousSnapshot.processes) {
        if (currentPids.find(info.uniqueId) == currentPids.end()) {
            terminated.push_back(info);
        }
    }

    return {created, terminated};
}

// ============================================================================
// CALLBACK REGISTRATION
// ============================================================================

uint64_t ProcessMonitor::RegisterCallback(ProcessCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_processCallbacks[id] = std::move(callback);

    Logger::Debug("ProcessMonitor: Registered process callback {}", id);
    return id;
}

uint64_t ProcessMonitor::RegisterEventCallback(ProcessEventCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_eventCallbacks[id] = std::move(callback);

    Logger::Debug("ProcessMonitor: Registered event callback {}", id);
    return id;
}

uint64_t ProcessMonitor::RegisterSuspiciousCallback(SuspiciousActivityCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_suspiciousCallbacks[id] = std::move(callback);

    Logger::Debug("ProcessMonitor: Registered suspicious callback {}", id);
    return id;
}

uint64_t ProcessMonitor::RegisterAncestryCallback(AncestryAnomalyCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_ancestryCallbacks[id] = std::move(callback);

    Logger::Debug("ProcessMonitor: Registered ancestry callback {}", id);
    return id;
}

void ProcessMonitor::UnregisterCallback(uint64_t callbackId) {
    if (!m_impl) return;

    std::unique_lock lock(m_impl->m_callbackMutex);

    bool removed = false;
    removed |= m_impl->m_processCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_eventCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_suspiciousCallbacks.erase(callbackId) > 0;
    removed |= m_impl->m_ancestryCallbacks.erase(callbackId) > 0;

    if (removed) {
        Logger::Debug("ProcessMonitor: Unregistered callback {}", callbackId);
    }
}

// ============================================================================
// CACHE MANAGEMENT
// ============================================================================

void ProcessMonitor::ClearCache(bool keepRunning) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock lock(m_impl->m_cacheMutex);

    if (keepRunning) {
        std::vector<ProcessUniqueId> toRemove;
        for (const auto& [uniqueId, info] : m_impl->m_processCache) {
            if (info.state == ProcessState::Terminated) {
                toRemove.push_back(uniqueId);
            }
        }

        for (const auto& uniqueId : toRemove) {
            m_impl->m_processCache.erase(uniqueId);
            m_impl->m_pidToUniqueId.erase(uniqueId.pid);
        }

        Logger::Info("ProcessMonitor: Cleared {} terminated entries", toRemove.size());
    } else {
        m_impl->m_processCache.clear();
        m_impl->m_pidToUniqueId.clear();
        Logger::Info("ProcessMonitor: Cache cleared completely");
    }
}

void ProcessMonitor::InvalidateCacheEntry(uint32_t pid) {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    std::unique_lock lock(m_impl->m_cacheMutex);

    auto it = m_impl->m_pidToUniqueId.find(pid);
    if (it != m_impl->m_pidToUniqueId.end()) {
        m_impl->m_processCache.erase(it->second);
        m_impl->m_pidToUniqueId.erase(it);
    }
}

std::optional<ExtendedProcessInfo> ProcessMonitor::RefreshCacheEntry(uint32_t pid) {
    InvalidateCacheEntry(pid);
    return GetProcessInfo(pid);
}

[[nodiscard]] size_t ProcessMonitor::GetCacheSize() const noexcept {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return 0;
    }

    std::shared_lock lock(m_impl->m_cacheMutex);
    return m_impl->m_processCache.size();
}

// ============================================================================
// STATISTICS & DIAGNOSTICS
// ============================================================================

[[nodiscard]] MonitorStatistics ProcessMonitor::GetStatistics() const {
    if (!m_impl) return MonitorStatistics{};
    return m_impl->m_stats;
}

[[nodiscard]] ProcessTreeStatistics ProcessMonitor::GetTreeStatistics() const {
    ProcessTreeStatistics stats{};

    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return stats;
    }

    std::shared_lock lock(m_impl->m_cacheMutex);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        stats.totalProcesses++;

        if (info.state == ProcessState::Running) stats.runningProcesses++;
        if (info.state == ProcessState::Suspended) stats.suspendedProcesses++;
        if (info.isSystemProcess) stats.systemProcesses++;
        if (!info.isSystemProcess) stats.userProcesses++;
        if (info.isElevated) stats.elevatedProcesses++;
        if (info.isProtectedProcess) stats.protectedProcesses++;
        if (info.isWow64) stats.wow64Processes++;

        stats.countByCategory[info.category]++;
        stats.countBySession[info.sessionId]++;
    }

    return stats;
}

void ProcessMonitor::ResetStatistics() {
    if (m_impl) {
        m_impl->m_stats.Reset();
        Logger::Info("ProcessMonitor: Statistics reset");
    }
}

[[nodiscard]] std::wstring ProcessMonitor::GetVersion() noexcept {
    return std::format(L"{}.{}.{}",
        MonitorConstants::VERSION_MAJOR,
        MonitorConstants::VERSION_MINOR,
        MonitorConstants::VERSION_PATCH);
}

[[nodiscard]] std::vector<std::wstring> ProcessMonitor::RunDiagnostics() const {
    std::vector<std::wstring> diagnostics;

    if (!m_impl) {
        diagnostics.push_back(L"ERROR: Implementation is null");
        return diagnostics;
    }

    if (!m_impl->m_initialized.load(std::memory_order_acquire)) {
        diagnostics.push_back(L"WARNING: Not initialized");
        return diagnostics;
    }

    diagnostics.push_back(L"ProcessMonitor Diagnostics:");
    diagnostics.push_back(std::format(L"  Version: {}", GetVersion()));
    diagnostics.push_back(std::format(L"  Cached Processes: {}", GetCacheSize()));
    diagnostics.push_back(std::format(L"  Cache Hit Ratio: {:.2f}%",
        m_impl->m_stats.GetCacheHitRatio()));
    diagnostics.push_back(std::format(L"  Avg Lookup Time: {:.2f} μs",
        m_impl->m_stats.GetAverageLookupTimeUs()));
    diagnostics.push_back(std::format(L"  Total Processes Tracked: {}",
        m_impl->m_stats.totalProcessesTracked.load(std::memory_order_relaxed)));
    diagnostics.push_back(std::format(L"  Events Processed: {}",
        m_impl->m_stats.eventsProcessed.load(std::memory_order_relaxed)));
    diagnostics.push_back(std::format(L"  Events Dropped: {}",
        m_impl->m_stats.eventsDropped.load(std::memory_order_relaxed)));

    return diagnostics;
}

// ============================================================================
// UTILITY METHODS
// ============================================================================

bool ProcessMonitor::WaitForTermination(uint32_t pid, uint32_t timeoutMs) {
    auto startTime = steady_clock::now();
    auto timeout = milliseconds(timeoutMs);

    while (steady_clock::now() - startTime < timeout) {
        if (!IsProcessAlive(pid)) {
            return true;
        }
        std::this_thread::sleep_for(milliseconds(100));
    }

    return false;
}

[[nodiscard]] std::optional<ProcessUniqueId> ProcessMonitor::GetUniqueId(uint32_t pid) const {
    auto info = GetProcessInfo(pid);
    return info ? std::optional(info->uniqueId) : std::nullopt;
}

[[nodiscard]] bool ProcessMonitor::WasPidReused(uint32_t pid) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return false;
    }

    std::shared_lock historyLock(m_impl->m_historyMutex);

    auto now = system_clock::now();
    auto reuseWindow = milliseconds(MonitorConstants::PID_REUSE_WINDOW_MS);

    for (const auto& info : m_impl->m_terminatedProcesses) {
        if (info.uniqueId.pid == pid) {
            auto timeSinceTermination = now - info.exitTime;
            if (timeSinceTermination < reuseWindow) {
                return true;
            }
        }
    }

    return false;
}

[[nodiscard]] std::optional<ExtendedProcessInfo> ProcessMonitor::GetHistoricalInfo(
    const ProcessUniqueId& uniqueId
) const {
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return std::nullopt;
    }

    std::shared_lock lock(m_impl->m_historyMutex);

    auto it = m_impl->m_historicalCache.find(uniqueId);
    if (it != m_impl->m_historicalCache.end()) {
        return it->second;
    }

    return std::nullopt;
}

} // namespace Process
} // namespace Core
} // namespace ShadowStrike
