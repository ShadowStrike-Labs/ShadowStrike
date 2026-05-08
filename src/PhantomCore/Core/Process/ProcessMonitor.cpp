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
#include "../../Communication/IPCManager.hpp"

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
 * @brief RAII wrapper for Windows HANDLE.
 */
struct HandleGuard {
    HANDLE h;
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    operator HANDLE() const noexcept { return h; }
    explicit operator bool() const noexcept { return h && h != INVALID_HANDLE_VALUE; }
};

/**
 * @brief Get process integrity level.
 */
[[nodiscard]] uint32_t GetProcessIntegrityLevel(HANDLE hProcess) noexcept {
    HANDLE hTokenRaw = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenRaw)) {
        return 0;
    }
    HandleGuard hToken(hTokenRaw);

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwLength);
    if (dwLength == 0 || dwLength > 4096) return 0;

    try {
        std::vector<uint8_t> buffer(dwLength);
        auto pIntegrity = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(buffer.data());

        uint32_t integrityLevel = 0;
        if (GetTokenInformation(hToken, TokenIntegrityLevel, pIntegrity, dwLength, &dwLength)) {
            DWORD sidSubAuthCount = *GetSidSubAuthorityCount(pIntegrity->Label.Sid);
            if (sidSubAuthCount > 0) {
                integrityLevel = *GetSidSubAuthority(pIntegrity->Label.Sid, sidSubAuthCount - 1);
            }
        }
        return integrityLevel;
    } catch (...) {
        return 0;
    }
}

/**
 * @brief Check if process is elevated.
 */
[[nodiscard]] bool IsProcessElevated(HANDLE hProcess) noexcept {
    HANDLE hTokenRaw = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenRaw)) {
        return false;
    }
    HandleGuard hToken(hTokenRaw);

    TOKEN_ELEVATION elevation{};
    DWORD dwSize = 0;

    if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
        return elevation.TokenIsElevated != 0;
    }
    return false;
}

/**
 * @brief Get user name from process token.
 */
[[nodiscard]] std::pair<std::wstring, std::wstring> GetProcessUser(HANDLE hProcess) {
    std::wstring userName, domainName;

    HANDLE hTokenRaw = nullptr;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hTokenRaw)) {
        return {userName, domainName};
    }
    HandleGuard hToken(hTokenRaw);

    DWORD dwLength = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwLength);
    if (dwLength == 0 || dwLength > 4096) return {userName, domainName};

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

    return {userName, domainName};
}

/**
 * @brief Categorize process based on path and name.
 */
[[nodiscard]] ProcessCategory CategorizeProcess(
    const std::wstring& processName,
    const std::wstring& processPath
) noexcept {
    std::wstring lowerName = StringUtils::ToLowerCopy(processName);
    std::wstring lowerPath = StringUtils::ToLowerCopy(processPath);

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

    startTime = std::chrono::system_clock::now();
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
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() - startTime).count();
    if (elapsed <= 0) return 0.0;

    uint64_t processed = eventsProcessed.load(std::memory_order_relaxed);
    return static_cast<double>(processed) / static_cast<double>(elapsed);
}

// ============================================================================
// ExtendedProcessInfo METHODS
// ============================================================================

[[nodiscard]] Utils::ProcessUtils::ProcessInfo ExtendedProcessInfo::ToProcessInfo() const {
    Utils::ProcessUtils::ProcessInfo info;
    info.basic.pid = uniqueId.pid;
    info.basic.name = processName;
    info.basic.executablePath = processPath;
    info.basic.commandLine = commandLine;
    info.basic.parentPid = parentPid;
    info.basic.sessionId = sessionId;
    info.basic.isWow64 = isWow64;
    info.basic.isSystemProcess = isSystemProcess;
    info.basic.isProtected = isProtectedProcess;
    return info;
}

[[nodiscard]] Utils::ProcessUtils::ProcessBasicInfo ExtendedProcessInfo::ToBasicInfo() const {
    Utils::ProcessUtils::ProcessBasicInfo info;
    info.pid = uniqueId.pid;
    info.name = processName;
    info.executablePath = processPath;
    info.parentPid = parentPid;
    info.sessionId = sessionId;
    info.isWow64 = isWow64;
    info.isSystemProcess = isSystemProcess;
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

    // Statistics (mutable — atomics are updated from const lookup paths)
    mutable MonitorStatistics m_stats{};

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

    // Kernel wiring state
    bool m_kernelHandlerRegistered = false;
    system_clock::time_point m_initTime{};

    // Optional WhitelistStore reference (set by caller, not owned)
    Whitelist::WhitelistStore* m_whitelistStore = nullptr;

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
            SS_LOG_WARN(L"ProcessMonitor", L"Impl already initialized");
            return true;
        }

        try {
            SS_LOG_INFO(L"ProcessMonitor", L"Impl: Initializing");

            m_config = config;
            m_stats.Reset();
            m_initTime = system_clock::now();

            // Perform initial snapshot
            if (!TakeInitialSnapshot()) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Failed to take initial snapshot");
                return false;
            }

            // Start worker threads
            StartWorkerThreads();

            m_initialized.store(true, std::memory_order_release);

            // Wire kernel process callback via IPCManager.
            // Must be done after m_initialized=true so our handler can process events.
            if (m_config.useKernelCallback) {
                RegisterKernelProcessHandler();
            }

            SS_LOG_INFO(L"ProcessMonitor", L"Impl: Initialization complete - %zu processes tracked",
                m_processCache.size());

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor", L"Impl: Initialization exception: %S", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        std::unique_lock lock(m_configMutex);

        if (!m_initialized.load(std::memory_order_acquire)) {
            return;
        }

        SS_LOG_INFO(L"ProcessMonitor", L"Impl: Shutting down");

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
        SS_LOG_INFO(L"ProcessMonitor", L"Impl: Shutdown complete");
    }

    // ========================================================================
    // INITIAL SNAPSHOT
    // ========================================================================

    [[nodiscard]] bool TakeInitialSnapshot() {
        try {
            SS_LOG_INFO(L"ProcessMonitor", L"Taking initial system snapshot");

            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                SS_LOG_ERROR(L"ProcessMonitor", L"CreateToolhelp32Snapshot failed: %lu", GetLastError());
                return false;
            }
            // RAII guard for snapshot handle
            auto snapshotGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hSnapshot, CloseHandle);

            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            // Collect all entries, then batch-insert under a single lock
            std::vector<ExtendedProcessInfo> entries;
            entries.reserve(512);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    ExtendedProcessInfo info = CreateProcessInfoFromSnapshot(pe32);
                    if (info.IsValid()) {
                        entries.push_back(std::move(info));
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }

            // Batch insert under single lock. Capture uniqueId before moving
            // info (moved-from ExtendedProcessInfo has unspecified contents
            // for non-trivial members) and update the PID→UniqueId index in
            // lock-step instead of clearing and rebuilding it.
            {
                std::unique_lock lock(m_cacheMutex);
                for (auto& info : entries) {
                    const ProcessUniqueId uid = info.uniqueId;
                    const uint32_t pid = uid.pid;
                    m_processCache[uid] = std::move(info);
                    m_pidToUniqueId[pid] = uid;
                }
            }

            const uint32_t processCount = static_cast<uint32_t>(entries.size());
            m_stats.totalProcessesTracked.store(processCount, std::memory_order_relaxed);
            m_stats.currentActiveProcesses.store(processCount, std::memory_order_relaxed);
            m_stats.processesDiscoveredBySnapshot.store(processCount, std::memory_order_relaxed);

            SS_LOG_INFO(L"ProcessMonitor", L"Initial snapshot complete - %u processes", processCount);
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor", L"Initial snapshot exception: %S", e.what());
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
            auto handleGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hProcess, CloseHandle);

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
        } else {
            // Process inaccessible - likely system process or protected
            if (GetLastError() == ERROR_ACCESS_DENIED) {
                info.isProtectedProcess = true;
                m_stats.accessDeniedErrors.fetch_add(1, std::memory_order_relaxed);
            }

            // Use a synthetic unique start time so IsValid() returns true.
            // We use the PID shifted to guarantee uniqueness among inaccessible processes.
            info.uniqueId.startTime = static_cast<uint64_t>(pe32.th32ProcessID) + 1;
        }

        // Categorize process
        info.category = CategorizeProcess(info.processName, info.processPath);
        info.isSystemProcess = (info.category == ProcessCategory::SystemCritical ||
                               info.category == ProcessCategory::SystemCore);
        info.isCriticalProcess = (info.category == ProcessCategory::SystemCritical);
        info.isLOLBin = (info.category == ProcessCategory::LOLBin);

        // Check whitelist if configured
        if (m_config.enableWhitelistIntegration && !info.processPath.empty() && m_whitelistStore) {
            try {
                auto wlResult = m_whitelistStore->IsWhitelisted(info.processPath);
                info.isWhitelisted = wlResult.found;
            } catch (...) {
                // WhitelistStore may not be initialized during early snapshot
            }
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
        auto handleGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hProcess, CloseHandle);

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
        info.category = CategorizeProcess(info.processName, info.processPath);

        return info;
    }

    /**
     * @brief Evict the stalest terminated entry from cache. Caller must hold unique_lock on m_cacheMutex.
     */
    void EvictStalestEntryLocked() {
        auto now = system_clock::now();
        auto oldestTime = now;
        ProcessUniqueId oldestId{};
        bool found = false;

        // Prefer evicting terminated processes first
        for (const auto& [uid, pinfo] : m_processCache) {
            if (pinfo.state == ProcessState::Terminated && pinfo.exitTime < oldestTime) {
                oldestTime = pinfo.exitTime;
                oldestId = uid;
                found = true;
            }
        }

        // If no terminated entries, evict least-recently-seen running process
        if (!found) {
            for (const auto& [uid, pinfo] : m_processCache) {
                if (pinfo.lastSeenTime < oldestTime) {
                    oldestTime = pinfo.lastSeenTime;
                    oldestId = uid;
                    found = true;
                }
            }
        }

        if (found) {
            m_processCache.erase(oldestId);
            m_pidToUniqueId.erase(oldestId.pid);
            m_stats.cacheEvictions.fetch_add(1, std::memory_order_relaxed);
        }
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

        // Take a single lock for the entire ancestry walk to avoid
        // re-entrant lock attempts and provide a consistent snapshot.
        std::shared_lock lock(m_cacheMutex);

        // Start with target process (lockless lookup since we hold the lock)
        auto processInfo = LookupInCacheLocked(pid);
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
                SS_LOG_WARN(L"ProcessMonitor", L"Cycle detected in ancestry for PID %u at depth %u", pid, depth);
                chain.hasOrphan = true;
                chain.orphanAtDepth = depth;
                break;
            }
            visitedPids.insert(currentPid);

            // Lockless lookup — we hold m_cacheMutex
            auto parentInfo = LookupInCacheLocked(currentPid);
            if (!parentInfo) {
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

        // Use full locking lookups here since this is called outside lock
        auto processInfo = GetProcessInfoImpl(pid);
        if (!processInfo) return false;

        auto parentInfo = GetProcessInfoImpl(processInfo->parentPid);
        if (!parentInfo) {
            // Parent doesn't exist — possible spoofing or orphan
            ProcessUniqueId synthParent{};
            synthParent.pid = processInfo->parentPid;
            InvokeAncestryCallbacks(processInfo->uniqueId, synthParent,
                L"Ancestry anomaly: claimed parent does not exist");
            return true;
        }

        // Check if parent was created AFTER child (impossible naturally)
        if (parentInfo->createTime > processInfo->createTime) {
            SS_LOG_WARN(L"ProcessMonitor", L"PPID spoofing detected - PID %u claims parent %u "
                        "created after child", pid, processInfo->parentPid);
            m_stats.ppidSpoofingDetected.fetch_add(1, std::memory_order_relaxed);

            InvokeSuspiciousCallbacks(processInfo->uniqueId,
                L"PPID spoofing: Parent created after child");
            InvokeAncestryCallbacks(processInfo->uniqueId, parentInfo->uniqueId,
                L"PPID spoofing: Parent created after child");

            return true;
        }

        // Additional spoofing heuristic: validate parent can legitimately create children.
        // System-critical processes (csrss, smss) don't normally spawn user apps.
        // But svchost.exe children are common and legitimate.
        if (parentInfo->category == ProcessCategory::SystemCritical &&
            processInfo->category == ProcessCategory::UserApplication) {
            // csrss.exe spawning user apps is normal (console hosting), but
            // smss.exe directly spawning user apps is suspicious.
            std::wstring parentLower = StringUtils::ToLowerCopy(parentInfo->processName);
            if (parentLower == L"smss.exe") {
                SS_LOG_WARN(L"ProcessMonitor",
                    L"Suspicious ancestry: PID %u (%ls) claims parent smss.exe (PID %u)",
                    pid, processInfo->processName.c_str(), processInfo->parentPid);
                m_stats.ppidSpoofingDetected.fetch_add(1, std::memory_order_relaxed);
                InvokeSuspiciousCallbacks(processInfo->uniqueId,
                    L"PPID spoofing: User process claims smss.exe as parent");
                InvokeAncestryCallbacks(processInfo->uniqueId, parentInfo->uniqueId,
                    L"PPID spoofing: User process claims smss.exe as parent");
                return true;
            }
        }

        return false;
    }

    // ========================================================================
    // INTERNAL CACHE LOOKUP (caller holds m_cacheMutex)
    // ========================================================================

    /**
     * @brief Look up a process by PID while m_cacheMutex is already held.
     * @note Caller MUST hold at least a shared_lock on m_cacheMutex.
     */
    [[nodiscard]] std::optional<ExtendedProcessInfo> LookupInCacheLocked(uint32_t pid) const {
        auto pidIt = m_pidToUniqueId.find(pid);
        if (pidIt == m_pidToUniqueId.end()) {
            return std::nullopt;
        }
        auto cacheIt = m_processCache.find(pidIt->second);
        if (cacheIt == m_processCache.end()) {
            return std::nullopt;
        }
        return cacheIt->second;
    }

    // ========================================================================
    // EVENT PROCESSING
    // ========================================================================

    void OnProcessCreateImpl(const ProcessEvent& event) {
        try {
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
            info.isSystemProcess = (info.category == ProcessCategory::SystemCritical ||
                                   info.category == ProcessCategory::SystemCore);
            info.isCriticalProcess = (info.category == ProcessCategory::SystemCritical);
            info.isLOLBin = (info.category == ProcessCategory::LOLBin);

            // WhitelistStore integration
            if (m_config.enableWhitelistIntegration && !info.processPath.empty() && m_whitelistStore) {
                try {
                    auto wlResult = m_whitelistStore->IsWhitelisted(info.processPath);
                    info.isWhitelisted = wlResult.found;
                } catch (...) {
                    SS_LOG_DEBUG(L"ProcessMonitor", L"WhitelistStore lookup failed for PID %u", info.uniqueId.pid);
                }
            }

            // Cache capacity enforcement before insertion
            {
                std::unique_lock lock(m_cacheMutex);

                if (m_processCache.size() >= m_config.maxCachedProcesses) {
                    EvictStalestEntryLocked();
                }

                m_processCache[info.uniqueId] = info;
                m_pidToUniqueId[info.uniqueId.pid] = info.uniqueId;

                // Update parent's children list
                ProcessUniqueId parentId = event.parentId;
                auto parentIt = m_processCache.find(parentId);
                if (parentIt != m_processCache.end()) {
                    auto& childPids = parentIt->second.childPids;
                    if (childPids.size() < MonitorConstants::MAX_CHILDREN_PER_PROCESS) {
                        childPids.push_back(info.uniqueId.pid);
                    }
                }
            }
            // Cache lock released — safe for callbacks

            m_stats.currentActiveProcesses.fetch_add(1, std::memory_order_relaxed);
            m_stats.totalProcessesTracked.fetch_add(1, std::memory_order_relaxed);

            SS_LOG_INFO(L"ProcessMonitor", L"Process created - PID %u (%ls) parent %u src %u",
                info.uniqueId.pid, info.processName.c_str(), info.parentPid,
                static_cast<uint32_t>(event.source));

            // Invoke callbacks outside cache lock
            InvokeProcessCallbacks(info, true);
            InvokeEventCallbacks(event);

            // PPID spoofing detection
            if (m_config.detectPPIDSpoofing) {
                DetectPPIDSpoofingImpl(info.uniqueId.pid);
            }

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor", L"OnProcessCreate exception: %S", e.what());
            m_stats.eventProcessingErrors.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void OnProcessTerminateImpl(uint32_t pid, uint32_t exitCode) {
        try {
            m_stats.processTerminations.fetch_add(1, std::memory_order_relaxed);

            ExtendedProcessInfo infoCopy;

            // Phase 1: Update and remove from active cache
            {
                std::unique_lock lock(m_cacheMutex);

                auto pidIt = m_pidToUniqueId.find(pid);
                if (pidIt == m_pidToUniqueId.end()) {
                    SS_LOG_DEBUG(L"ProcessMonitor", L"Terminate event for unknown PID %u", pid);
                    return;
                }

                auto cacheIt = m_processCache.find(pidIt->second);
                if (cacheIt == m_processCache.end()) {
                    m_pidToUniqueId.erase(pidIt);
                    return;
                }

                auto& info = cacheIt->second;
                info.state = ProcessState::Terminated;
                info.isTerminated = true;
                info.exitCode = exitCode;
                info.exitTime = system_clock::now();

                // Copy before erasing — callbacks and history need this
                infoCopy = info;

                m_processCache.erase(cacheIt);
                m_pidToUniqueId.erase(pidIt);
            }
            // m_cacheMutex released — safe to acquire other locks and invoke callbacks

            SS_LOG_INFO(L"ProcessMonitor", L"Process terminated - PID %u (%ls) exitCode: %u",
                pid, infoCopy.processName.c_str(), exitCode);

            m_stats.currentActiveProcesses.fetch_sub(1, std::memory_order_relaxed);

            // Phase 2: Move to historical storage (separate lock)
            if (m_config.enableHistoricalTracking) {
                std::unique_lock historyLock(m_historyMutex);
                m_historicalCache[infoCopy.uniqueId] = infoCopy;
                m_terminatedProcesses.push_back(infoCopy);

                while (m_terminatedProcesses.size() > m_config.maxHistoricalEntries) {
                    auto& oldest = m_terminatedProcesses.front();
                    m_historicalCache.erase(oldest.uniqueId);
                    m_terminatedProcesses.pop_front();
                }
            }

            // Phase 3: Invoke callbacks outside ALL locks
            InvokeProcessCallbacks(infoCopy, false);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor", L"OnProcessTerminate exception: %S", e.what());
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

        SS_LOG_INFO(L"ProcessMonitor", L"%zu worker threads started", m_workerThreads.size());
    }

    void EventProcessingThread(std::stop_token stoken) {
        SS_LOG_DEBUG(L"ProcessMonitor", L"Event processing thread started");

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
                SS_LOG_ERROR(L"ProcessMonitor", L"Event processing thread exception: %S", e.what());
            }
        }

        SS_LOG_DEBUG(L"ProcessMonitor", L"Event processing thread stopped");
    }

    void ProcessEventImpl(const ProcessEvent& event) {
        switch (event.type) {
            case ProcessEventType::Created:
                OnProcessCreateImpl(event);
                break;
            case ProcessEventType::Terminated:
                OnProcessTerminateImpl(event.processId.pid, event.exitCode);
                break;
            case ProcessEventType::ModuleLoaded:
            case ProcessEventType::ModuleUnloaded:
            case ProcessEventType::ImageLoaded:
                // Dispatch module events to registered event callbacks
                InvokeEventCallbacks(event);
                break;
            case ProcessEventType::Suspended:
            case ProcessEventType::Resumed: {
                // Update process state in cache
                std::unique_lock lock(m_cacheMutex);
                auto pidIt = m_pidToUniqueId.find(event.processId.pid);
                if (pidIt != m_pidToUniqueId.end()) {
                    auto cacheIt = m_processCache.find(pidIt->second);
                    if (cacheIt != m_processCache.end()) {
                        cacheIt->second.state = (event.type == ProcessEventType::Suspended)
                            ? ProcessState::Suspended : ProcessState::Running;
                        cacheIt->second.lastSeenTime = system_clock::now();
                    }
                }
                InvokeEventCallbacks(event);
                break;
            }
            default:
                // Forward unhandled event types to event callbacks for extensibility
                InvokeEventCallbacks(event);
                break;
        }
    }

    void SnapshotThread(std::stop_token stoken) {
        SS_LOG_DEBUG(L"ProcessMonitor", L"Snapshot thread started");

        while (!stoken.stop_requested() && !m_shuttingDown.load(std::memory_order_acquire)) {
            try {
                std::this_thread::sleep_for(milliseconds(m_config.snapshotIntervalMs));

                if (stoken.stop_requested()) break;

                RefreshSnapshotImpl();

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Snapshot thread exception: %S", e.what());
            }
        }

        SS_LOG_DEBUG(L"ProcessMonitor", L"Snapshot thread stopped");
    }

    void CleanupThread(std::stop_token stoken) {
        SS_LOG_DEBUG(L"ProcessMonitor", L"Cleanup thread started");

        while (!stoken.stop_requested() && !m_shuttingDown.load(std::memory_order_acquire)) {
            try {
                std::this_thread::sleep_for(
                    milliseconds(m_config.deadProcessCleanupIntervalMs)
                );

                if (stoken.stop_requested()) break;

                CleanupDeadProcesses();

            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Cleanup thread exception: %S", e.what());
            }
        }

        SS_LOG_DEBUG(L"ProcessMonitor", L"Cleanup thread stopped");
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
            SS_LOG_DEBUG(L"ProcessMonitor", L"Cleaned up %zu dead processes", toRemove.size());
        }
    }

    bool RefreshSnapshotImpl() {
        SS_LOG_DEBUG(L"ProcessMonitor", L"Refreshing process snapshot");

        try {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot == INVALID_HANDLE_VALUE) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Snapshot refresh CreateToolhelp32Snapshot failed: %lu", GetLastError());
                return false;
            }
            auto snapshotGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hSnapshot, CloseHandle);

            // Phase 1: Enumerate all current PIDs and collect new processes (no lock)
            std::unordered_set<uint32_t> currentPids;
            std::vector<PROCESSENTRY32W> newEntries;
            PROCESSENTRY32W pe32{};
            pe32.dwSize = sizeof(PROCESSENTRY32W);

            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    currentPids.insert(pe32.th32ProcessID);
                } while (Process32NextW(hSnapshot, &pe32));
            }

            // Phase 2: Identify new and terminated PIDs under a single lock
            std::vector<uint32_t> newPids;
            std::vector<uint32_t> terminatedPids;

            {
                std::shared_lock lock(m_cacheMutex);
                for (uint32_t pid : currentPids) {
                    if (m_pidToUniqueId.find(pid) == m_pidToUniqueId.end()) {
                        newPids.push_back(pid);
                    }
                }
                for (const auto& [pid, uniqueId] : m_pidToUniqueId) {
                    if (currentPids.find(pid) == currentPids.end()) {
                        terminatedPids.push_back(pid);
                    }
                }
            }

            // Phase 3: Fetch info for new processes (outside lock — calls OpenProcess)
            // Re-enumerate to get PROCESSENTRY32W data for new PIDs
            std::vector<ExtendedProcessInfo> newInfos;
            if (!newPids.empty()) {
                std::unordered_set<uint32_t> newPidSet(newPids.begin(), newPids.end());

                HANDLE hSnap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (hSnap2 != INVALID_HANDLE_VALUE) {
                    auto snap2Guard = std::unique_ptr<void, decltype(&CloseHandle)>(hSnap2, CloseHandle);
                    PROCESSENTRY32W pe{};
                    pe.dwSize = sizeof(PROCESSENTRY32W);

                    if (Process32FirstW(hSnap2, &pe)) {
                        do {
                            if (newPidSet.count(pe.th32ProcessID)) {
                                ExtendedProcessInfo info = CreateProcessInfoFromSnapshot(pe);
                                if (info.IsValid()) {
                                    newInfos.push_back(std::move(info));
                                }
                            }
                        } while (Process32NextW(hSnap2, &pe));
                    }
                }
            }

            // Phase 4: Insert new processes
            if (!newInfos.empty()) {
                std::unique_lock lock(m_cacheMutex);
                for (auto& info : newInfos) {
                    // Re-check under write lock (another thread may have added it)
                    if (m_pidToUniqueId.find(info.uniqueId.pid) == m_pidToUniqueId.end()) {
                        m_pidToUniqueId[info.uniqueId.pid] = info.uniqueId;
                        m_processCache[info.uniqueId] = std::move(info);
                        m_stats.processesDiscoveredBySnapshot.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            }

            // Phase 5: Handle terminated processes
            for (uint32_t pid : terminatedPids) {
                OnProcessTerminateImpl(pid, 0);
            }

            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor", L"Snapshot refresh exception: %S", e.what());
            return false;
        }
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void InvokeProcessCallbacks(const ExtendedProcessInfo& info, bool created) const {
        // Snapshot under shared_lock then dispatch unlocked. Holding
        // m_callbackMutex across user callbacks deadlocks any callback that
        // (un)registers another callback (which acquires unique_lock on the
        // same mutex) and serializes long-running callbacks behind our
        // hot-path event delivery.
        std::vector<ProcessCallback> snapshot;
        try {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_processCallbacks.size());
            for (const auto& [id, cb] : m_processCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& callback : snapshot) {
            try {
                callback(info, created);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Process callback exception: %S", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Process callback unknown exception");
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void InvokeEventCallbacks(const ProcessEvent& event) const {
        std::vector<ProcessEventCallback> snapshot;
        try {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_eventCallbacks.size());
            for (const auto& [id, cb] : m_eventCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& callback : snapshot) {
            try {
                callback(event);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Event callback exception: %S", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Event callback unknown exception");
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void InvokeSuspiciousCallbacks(
        const ProcessUniqueId& processId,
        const std::wstring& description
    ) const {
        std::vector<SuspiciousActivityCallback> snapshot;
        try {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_suspiciousCallbacks.size());
            for (const auto& [id, cb] : m_suspiciousCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& callback : snapshot) {
            try {
                callback(processId, description);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Suspicious callback exception: %S", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Suspicious callback unknown exception");
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void InvokeAncestryCallbacks(
        const ProcessUniqueId& processId,
        const ProcessUniqueId& parentId,
        const std::wstring& anomalyType
    ) const {
        std::vector<AncestryAnomalyCallback> snapshot;
        try {
            std::shared_lock lock(m_callbackMutex);
            snapshot.reserve(m_ancestryCallbacks.size());
            for (const auto& [id, cb] : m_ancestryCallbacks) {
                if (cb) snapshot.push_back(cb);
            }
        } catch (...) { return; }

        for (const auto& callback : snapshot) {
            try {
                callback(processId, parentId, anomalyType);
                m_stats.callbacksInvoked.fetch_add(1, std::memory_order_relaxed);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Ancestry callback exception: %S", e.what());
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                SS_LOG_ERROR(L"ProcessMonitor", L"Ancestry callback unknown exception");
                m_stats.callbackErrors.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    // ========================================================================
    // KERNEL WIRING — IPCManager FilterPort integration
    // ========================================================================

    /**
     * @brief Register with IPCManager to receive kernel PsSetCreateProcessNotifyRoutineEx
     *        callbacks via the minifilter communication port.
     *
     * The kernel driver (PhantomSensor) receives synchronous process creation/termination
     * notifications from PsSetCreateProcessNotifyRoutineEx and sends them to user-mode
     * via FltSendMessage. IPCManager dispatches them to our handler.
     *
     * We process kernel events SYNCHRONOUSLY (no queueing) for minimal latency —
     * critical for blocking malicious process creation before the main thread starts.
     */
    void RegisterKernelProcessHandler() {
        try {
            auto& ipc = Communication::IPCManager::Instance();

            if (!ipc.IsInitialized()) {
                SS_LOG_WARN(L"ProcessMonitor",
                    L"IPCManager not initialized — kernel process callback deferred. "
                    L"Snapshot-only mode until kernel wiring is established.");
                return;
            }

            ipc.RegisterProcessHandler(
                [this](const Communication::ProcessNotifyRequest& req) -> SHADOWSTRIKE_SCAN_VERDICT {
                    return OnKernelProcessNotify(req);
                }
            );

            m_kernelHandlerRegistered = true;
            SS_LOG_INFO(L"ProcessMonitor",
                L"Kernel process handler registered via IPCManager FilterPort");

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor",
                L"Failed to register kernel process handler: %S", e.what());
        }
    }

    /**
     * @brief Handle a kernel process create/terminate notification.
     *
     * Called synchronously from IPCManager's IOCP worker thread.
     * MUST be fast — the kernel is blocked waiting for our verdict.
     */
    [[nodiscard]] SHADOWSTRIKE_SCAN_VERDICT OnKernelProcessNotify(
        const Communication::ProcessNotifyRequest& req
    ) {
        if (m_shuttingDown.load(std::memory_order_acquire)) {
            return Verdict_Clean;
        }

        try {
            if (req.isCreation) {
                // Build ProcessEvent from kernel data
                ProcessEvent event{};
                event.type = ProcessEventType::Created;
                event.source = EventSource::KernelCallback;
                event.processId.pid = req.processId;
                event.parentId.pid = req.parentProcessId;
                event.sessionId = 0;
                event.timestamp = system_clock::now();
                event.sequenceNumber = m_eventSequence.fetch_add(1, std::memory_order_relaxed);
                event.isElevated = false;
                event.isWow64 = false;

                // Extract variable-length image path
                if (req.imagePathLength > 0 && req.imagePathCharLen() > 0) {
                    event.processPath.assign(req.imagePathData(), req.imagePathCharLen());
                    // Extract process name from full path
                    auto lastSlash = event.processPath.find_last_of(L'\\');
                    event.processName = (lastSlash != std::wstring::npos)
                        ? event.processPath.substr(lastSlash + 1)
                        : event.processPath;
                }

                // Extract command line
                if (req.commandLineLength > 0 && req.commandLineCharLen() > 0) {
                    event.commandLine.assign(req.commandLineData(), req.commandLineCharLen());
                }

                // Synchronous processing for kernel events — no queueing.
                // This ensures we never miss short-lived processes and can
                // provide a verdict to block malicious execution.
                OnProcessCreateImpl(event);

                // Enrich with live process data (start time, integrity, etc.)
                EnrichFromLiveProcess(req.processId);

            } else {
                // Termination
                OnProcessTerminateImpl(req.processId, 0);
            }

            return Verdict_Clean;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(L"ProcessMonitor",
                L"Kernel process notify handler exception for PID %u: %S",
                req.processId, e.what());
            m_stats.eventProcessingErrors.fetch_add(1, std::memory_order_relaxed);
            return Verdict_Clean;
        }
    }

    /**
     * @brief Enrich a cached process entry with live data after kernel notification.
     *
     * Kernel callbacks provide PID/PPID/path but not start time, integrity,
     * user context etc. We fetch these asynchronously from the live process.
     */
    void EnrichFromLiveProcess(uint32_t pid) {
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE, pid);

        if (!hProcess) return;

        auto handleGuard = std::unique_ptr<void, decltype(&CloseHandle)>(hProcess, CloseHandle);

        std::unique_lock lock(m_cacheMutex);
        auto pidIt = m_pidToUniqueId.find(pid);
        if (pidIt == m_pidToUniqueId.end()) return;

        auto cacheIt = m_processCache.find(pidIt->second);
        if (cacheIt == m_processCache.end()) return;

        auto& info = cacheIt->second;

        // Update start time (critical for PID reuse detection)
        uint64_t startTime = GetProcessStartTime(hProcess);
        if (startTime != MonitorConstants::INVALID_START_TIME &&
            info.uniqueId.startTime != startTime) {
            // Update the unique ID with actual start time
            ProcessUniqueId oldId = info.uniqueId;
            info.uniqueId.startTime = startTime;
            info.createTime = FileTimeToTimePoint(startTime);

            // Re-key in cache if start time changed
            if (oldId.startTime != startTime) {
                ExtendedProcessInfo moved = std::move(info);
                m_processCache.erase(cacheIt);
                m_processCache[moved.uniqueId] = std::move(moved);
                m_pidToUniqueId[pid] = m_processCache.find(
                    ProcessUniqueId{pid, startTime})->first;
                cacheIt = m_processCache.find(ProcessUniqueId{pid, startTime});
                if (cacheIt == m_processCache.end()) return;
            }
        }

        auto& enriched = cacheIt->second;

        // Integrity and elevation
        if (m_config.collectIntegrity) {
            enriched.integrityLevel = GetProcessIntegrityLevel(hProcess);
            enriched.isElevated = IsProcessElevated(hProcess);
        }

        // User info
        if (m_config.collectUserInfo) {
            auto [user, domain] = GetProcessUser(hProcess);
            enriched.userName = std::move(user);
            enriched.domainName = std::move(domain);
        }

        // WoW64 check
        BOOL isWow64 = FALSE;
        if (IsWow64Process(hProcess, &isWow64)) {
            enriched.isWow64 = (isWow64 != FALSE);
        }

        // Session ID
        DWORD sessionId = 0;
        if (ProcessIdToSessionId(pid, &sessionId)) {
            enriched.sessionId = sessionId;
        }

        enriched.state = ProcessState::Running;
        enriched.lastUpdateTime = system_clock::now();
        enriched.metadataComplete = true;
        enriched.cacheVersion = m_cacheVersion.fetch_add(1, std::memory_order_relaxed);
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
    SS_LOG_INFO(L"ProcessMonitor", L"Constructor called");
}

ProcessMonitor::~ProcessMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
    SS_LOG_INFO(L"ProcessMonitor", L"Destructor called");
}

// ============================================================================
// LIFECYCLE MANAGEMENT
// ============================================================================

bool ProcessMonitor::Initialize(const MonitorConfig& config) {
    if (!m_impl) {
        SS_LOG_ERROR(L"ProcessMonitor", L"Implementation is null");
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

    SS_LOG_INFO(L"ProcessMonitor", L"Configuration updated");
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

    std::wstring lowerName = StringUtils::ToLowerCopy(processName);

    for (const auto& [uniqueId, info] : m_impl->m_processCache) {
        if (StringUtils::ToLowerCopy(info.processName) == lowerName) {
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
        if (StringUtils::IEquals(info.processPath, processPath)) {
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
        bool userMatches = StringUtils::IEquals(info.userName, userName);
        bool domainMatches = domainName.empty() ||
                            StringUtils::IEquals(info.domainName, domainName);

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

    // Kernel-sourced events are processed synchronously for minimal latency.
    // Other sources go through the async queue.
    if (event.source == EventSource::KernelCallback) {
        m_impl->OnProcessCreateImpl(event);
        return;
    }

    // Queue event for async processing
    {
        std::unique_lock lock(m_impl->m_eventQueueMutex);

        if (m_impl->m_eventQueue.size() >= m_impl->m_config.eventQueueSize) {
            m_impl->m_stats.eventsDropped.fetch_add(1, std::memory_order_relaxed);
            SS_LOG_WARN(L"ProcessMonitor", L"Event queue full (%zu), dropping event for PID %u",
                m_impl->m_eventQueue.size(), event.processId.pid);
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
    if (!m_impl || !m_impl->m_initialized.load(std::memory_order_acquire)) {
        return;
    }

    SS_LOG_DEBUG(L"ProcessMonitor", L"Module loaded - PID %u module %ls base 0x%llX size %zu",
        pid, modulePath.c_str(), static_cast<uint64_t>(moduleBase), moduleSize);

    // Build and dispatch module load event to all registered event callbacks
    ProcessEvent event{};
    event.type = ProcessEventType::ModuleLoaded;
    event.source = EventSource::KernelCallback;
    event.processId.pid = pid;
    event.modulePath = modulePath;
    event.moduleBase = moduleBase;
    event.moduleSize = moduleSize;
    event.timestamp = std::chrono::system_clock::now();
    event.sequenceNumber = m_impl->m_eventSequence.fetch_add(1, std::memory_order_relaxed);

    // Look up process unique ID for the event
    {
        std::shared_lock lock(m_impl->m_cacheMutex);
        auto pidIt = m_impl->m_pidToUniqueId.find(pid);
        if (pidIt != m_impl->m_pidToUniqueId.end()) {
            event.processId = pidIt->second;
        }
    }

    m_impl->InvokeEventCallbacks(event);
    m_impl->m_stats.eventsReceived.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_stats.eventsProcessed.fetch_add(1, std::memory_order_relaxed);
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

    SS_LOG_DEBUG(L"ProcessMonitor", L"Registered process callback %llu", id);
    return id;
}

uint64_t ProcessMonitor::RegisterEventCallback(ProcessEventCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_eventCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ProcessMonitor", L"Registered event callback %llu", id);
    return id;
}

uint64_t ProcessMonitor::RegisterSuspiciousCallback(SuspiciousActivityCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_suspiciousCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ProcessMonitor", L"Registered suspicious callback %llu", id);
    return id;
}

uint64_t ProcessMonitor::RegisterAncestryCallback(AncestryAnomalyCallback callback) {
    if (!callback || !m_impl) return 0;

    std::unique_lock lock(m_impl->m_callbackMutex);

    uint64_t id = m_impl->m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
    m_impl->m_ancestryCallbacks[id] = std::move(callback);

    SS_LOG_DEBUG(L"ProcessMonitor", L"Registered ancestry callback %llu", id);
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
        SS_LOG_DEBUG(L"ProcessMonitor", L"Unregistered callback %llu", callbackId);
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

        SS_LOG_INFO(L"ProcessMonitor", L"Cleared %zu terminated entries", toRemove.size());
    } else {
        m_impl->m_processCache.clear();
        m_impl->m_pidToUniqueId.clear();
        SS_LOG_INFO(L"ProcessMonitor", L"Cache cleared completely");
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

void ProcessMonitor::GetStatistics(MonitorStatistics& out) const {
    out.Reset();
    if (!m_impl) return;

    const auto& s = m_impl->m_stats;
    out.totalProcessesTracked.store(s.totalProcessesTracked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.currentActiveProcesses.store(s.currentActiveProcesses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.processCreations.store(s.processCreations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.processTerminations.store(s.processTerminations.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.processesDiscoveredBySnapshot.store(s.processesDiscoveredBySnapshot.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.eventsReceived.store(s.eventsReceived.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.eventsProcessed.store(s.eventsProcessed.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.eventsDropped.store(s.eventsDropped.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.eventQueueHighWatermark.store(s.eventQueueHighWatermark.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.cacheLookups.store(s.cacheLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.cacheHits.store(s.cacheHits.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.cacheMisses.store(s.cacheMisses.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.cacheFetchedLive.store(s.cacheFetchedLive.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.cacheEvictions.store(s.cacheEvictions.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.staleEntryDetections.store(s.staleEntryDetections.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.totalLookupTimeUs.store(s.totalLookupTimeUs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.minLookupTimeUs.store(s.minLookupTimeUs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.maxLookupTimeUs.store(s.maxLookupTimeUs.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.ancestryLookups.store(s.ancestryLookups.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.orphanProcessesDetected.store(s.orphanProcessesDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.ppidSpoofingDetected.store(s.ppidSpoofingDetected.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.lookupErrors.store(s.lookupErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.accessDeniedErrors.store(s.accessDeniedErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.eventProcessingErrors.store(s.eventProcessingErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.callbacksInvoked.store(s.callbacksInvoked.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.callbackErrors.store(s.callbackErrors.load(std::memory_order_relaxed), std::memory_order_relaxed);
    out.startTime = s.startTime;
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
        SS_LOG_INFO(L"ProcessMonitor", L"Statistics reset");
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
