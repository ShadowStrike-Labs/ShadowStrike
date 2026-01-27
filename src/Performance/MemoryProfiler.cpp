/**
 * ============================================================================
 * ShadowStrike NGAV - MEMORY PROFILER IMPLEMENTATION
 * ============================================================================
 *
 * @file MemoryProfiler.cpp
 * @brief Implementation of the MemoryProfiler class using Windows PSAPI.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "MemoryProfiler.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <thread>
#include <shared_mutex>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <deque>

#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct ProcessMemoryHistory {
    std::deque<uint64_t> privateBytesSamples;
    uint64_t initialPrivateBytes{0};
    std::chrono::steady_clock::time_point startTime;
    bool active{false};
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MemoryProfilerImpl {
public:
    MemoryProfilerImpl() = default;
    ~MemoryProfilerImpl() { Shutdown(); }

    MemoryProfilerConfig m_config;
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isMonitoring{false};
    std::atomic<bool> m_stopRequested{false};
    std::thread m_monitorThread;

    // System Stats
    SystemMemoryStats m_currentSystemStats{};

    // Process Stats
    // Map PID -> History (for leak detection)
    std::unordered_map<uint32_t, ProcessMemoryHistory> m_processHistory;
    // Map PID -> Current Info (Cached for readers)
    std::unordered_map<uint32_t, ProcessMemoryInfo> m_processCache;

    bool Initialize(const MemoryProfilerConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;

        // Initial baseline reading
        RefreshSystemStatsInternal();

        return true;
    }

    void Shutdown() {
        StopMonitoring();
        std::unique_lock lock(m_mutex);
        m_processHistory.clear();
        m_processCache.clear();
    }

    bool StartMonitoring() {
        std::unique_lock lock(m_mutex);
        if (m_isMonitoring) return true;

        m_stopRequested = false;
        m_monitorThread = std::thread(&MemoryProfilerImpl::MonitoringLoop, this);
        m_isMonitoring = true;

        SS_LOG_INFO(L"MemoryProfiler", L"Monitoring started. Interval: %u ms", m_config.samplingIntervalMs);
        return true;
    }

    void StopMonitoring() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_isMonitoring) return;
            m_stopRequested = true;
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        m_isMonitoring = false;
        SS_LOG_INFO(L"MemoryProfiler", L"Monitoring stopped.");
    }

    void MonitoringLoop() {
        while (!m_stopRequested) {
            auto start = std::chrono::steady_clock::now();

            PerformRefresh();

            auto end = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            int64_t sleepTime = m_config.samplingIntervalMs - elapsed;
            if (sleepTime > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
            } else {
                std::this_thread::yield();
            }
        }
    }

    void PerformRefresh() {
        // 1. Update System Usage
        RefreshSystemStatsInternal();

        // 2. Update Process Usage
        if (m_config.trackPerProcess) {
            RefreshProcessStatsInternal();
        }
    }

    void RefreshSystemStatsInternal() {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);

        if (GlobalMemoryStatusEx(&memInfo)) {
            std::unique_lock lock(m_mutex);
            m_currentSystemStats.totalPhysical = memInfo.ullTotalPhys;
            m_currentSystemStats.availablePhysical = memInfo.ullAvailPhys;
            m_currentSystemStats.totalCommit = memInfo.ullTotalPageFile;
            m_currentSystemStats.availableCommit = memInfo.ullAvailPageFile;
            m_currentSystemStats.memoryLoad = memInfo.dwMemoryLoad;

            // These aren't directly in MEMORYSTATUSEX, typically need GetPerformanceInfo
            // For simplicity in this structure, we leave pool as 0 or implement GetPerformanceInfo later
            // PERFORMANCE_INFORMATION perfInfo; ... GetPerformanceInfo(&perfInfo, sizeof(perfInfo));
            // m_currentSystemStats.pagedPool = perfInfo.KernelPaged * perfInfo.PageSize;
            m_currentSystemStats.nonPagedPool = 0;
            m_currentSystemStats.pagedPool = 0;

            // Optional: Alert on high load
            if (memInfo.dwMemoryLoad >= m_config.highLoadThreshold) {
                SS_LOG_WARN(L"MemoryProfiler", L"High System Memory Load: %u%%", memInfo.dwMemoryLoad);
            }
        }
    }

    void RefreshProcessStatsInternal() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return;
        }

        // Mark existing for GC
        {
            std::unique_lock lock(m_mutex);
            for (auto& pair : m_processHistory) {
                pair.second.active = false;
            }
        }

        std::vector<ProcessMemoryInfo> newStats;
        newStats.reserve(128);

        uint64_t totalPhys = 1;
        {
            std::shared_lock lock(m_mutex);
            if (m_currentSystemStats.totalPhysical > 0) totalPhys = m_currentSystemStats.totalPhysical;
        }

        do {
            uint32_t pid = pe32.th32ProcessID;
            if (pid == 0) continue;

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    ProcessMemoryInfo info;
                    info.pid = pid;
                    info.name = pe32.szExeFile;
                    info.workingSetSize = pmc.WorkingSetSize;
                    info.privateUsage = pmc.PrivateUsage;
                    info.peakWorkingSetSize = pmc.PeakWorkingSetSize;
                    info.pageFaultCount = pmc.PageFaultCount;
                    info.percentOfSystemMemory = ((double)pmc.WorkingSetSize / totalPhys) * 100.0;
                    info.isLeaking = false;

                    // Leak detection logic
                    {
                        std::unique_lock lock(m_mutex);
                        auto& history = m_processHistory[pid];
                        if (!history.active && history.initialPrivateBytes == 0) {
                            // New process or first track
                            history.initialPrivateBytes = pmc.PrivateUsage;
                            history.startTime = std::chrono::steady_clock::now();
                        }
                        history.active = true;

                        history.privateBytesSamples.push_back(pmc.PrivateUsage);
                        if (history.privateBytesSamples.size() > m_config.historySize) {
                            history.privateBytesSamples.pop_front();
                        }

                        // Simple Heuristic: If grew by > leakThreshold since start
                        // and current is max of recent history
                        if (pmc.PrivateUsage > history.initialPrivateBytes + m_config.leakThresholdBytes) {
                            // Check if consistent growth (slope positive)
                            // For enterprise grade, we'd use linear regression here
                            // Simplified: Current is max of last N samples
                            bool isMax = true;
                            for (auto val : history.privateBytesSamples) {
                                if (val > pmc.PrivateUsage) { isMax = false; break; }
                            }
                            if (isMax) info.isLeaking = true;
                        }
                    }

                    newStats.push_back(info);
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);

        // Commit Updates
        {
            std::unique_lock lock(m_mutex);

            // GC
            auto it = m_processHistory.begin();
            while (it != m_processHistory.end()) {
                if (!it->second.active) {
                    it = m_processHistory.erase(it);
                } else {
                    ++it;
                }
            }

            // Update Cache
            m_processCache.clear();
            for (const auto& info : newStats) {
                m_processCache[info.pid] = info;
            }
        }
    }
};

// ============================================================================
// STATIC INSTANCE
// ============================================================================

static std::atomic<bool> s_instanceCreated{false};

MemoryProfiler& MemoryProfiler::Instance() noexcept {
    static MemoryProfiler instance;
    return instance;
}

bool MemoryProfiler::HasInstance() noexcept {
    return s_instanceCreated.load();
}

// ============================================================================
// PUBLIC METHODS
// ============================================================================

MemoryProfiler::MemoryProfiler() : m_impl(std::make_unique<MemoryProfilerImpl>()) {
    s_instanceCreated = true;
}

MemoryProfiler::~MemoryProfiler() {
    Shutdown();
    s_instanceCreated = false;
}

bool MemoryProfiler::Initialize(const MemoryProfilerConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"MemoryProfiler", L"Invalid configuration.");
        return false;
    }
    return m_impl->Initialize(config);
}

void MemoryProfiler::Shutdown() {
    m_impl->Shutdown();
}

bool MemoryProfiler::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void MemoryProfiler::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool MemoryProfiler::IsMonitoring() const noexcept {
    return m_impl->m_isMonitoring.load();
}

SystemMemoryStats MemoryProfiler::GetSystemStats() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSystemStats;
}

std::optional<ProcessMemoryInfo> MemoryProfiler::GetProcessInfo(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ProcessMemoryInfo> MemoryProfiler::GetTopConsumers(size_t count, bool byPrivateBytes) const {
    std::shared_lock lock(m_impl->m_mutex);

    std::vector<ProcessMemoryInfo> allProcesses;
    allProcesses.reserve(m_impl->m_processCache.size());

    for (const auto& [pid, info] : m_impl->m_processCache) {
        allProcesses.push_back(info);
    }

    auto sorter = [byPrivateBytes](const ProcessMemoryInfo& a, const ProcessMemoryInfo& b) {
        if (byPrivateBytes) return a.privateUsage > b.privateUsage;
        return a.workingSetSize > b.workingSetSize;
    };

    std::partial_sort(allProcesses.begin(),
                      allProcesses.begin() + std::min(count, allProcesses.size()),
                      allProcesses.end(),
                      sorter);

    if (allProcesses.size() > count) {
        allProcesses.resize(count);
    }

    return allProcesses;
}

bool MemoryProfiler::RefreshNow() {
    m_impl->PerformRefresh();
    return true;
}

bool MemoryProfiler::UpdateConfiguration(const MemoryProfilerConfig& config) {
    if (!config.IsValid()) return false;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

MemoryProfilerConfig MemoryProfiler::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool MemoryProfiler::SelfTest() {
    // Basic API test
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (!GlobalMemoryStatusEx(&memInfo)) return false;

    // Verify self process
    uint32_t myPid = GetCurrentProcessId();
    RefreshNow();
    if (!GetProcessInfo(myPid).has_value()) return false;

    return true;
}

std::string MemoryProfiler::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// SERIALIZATION
// ============================================================================

std::string ProcessMemoryInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"pid\":" << pid << ","
        << "\"name\":\"" << Utils::StringUtils::ToString(name) << "\","
        << "\"workingSet\":" << workingSetSize << ","
        << "\"privateBytes\":" << privateUsage << ","
        << "\"percentMem\":" << percentOfSystemMemory << ","
        << "\"isLeaking\":" << (isLeaking ? "true" : "false")
        << "}";
    return oss.str();
}

std::string SystemMemoryStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalPhys\":" << totalPhysical << ","
        << "\"availPhys\":" << availablePhysical << ","
        << "\"load\":" << memoryLoad << ","
        << "\"totalCommit\":" << totalCommit
        << "}";
    return oss.str();
}

bool MemoryProfilerConfig::IsValid() const noexcept {
    return samplingIntervalMs >= 100;
}

} // namespace Performance
} // namespace ShadowStrike
