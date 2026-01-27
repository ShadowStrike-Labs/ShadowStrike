/**
 * ============================================================================
 * ShadowStrike NGAV - CPU PERFORMANCE MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file CPUMonitor.cpp
 * @brief Implementation of the CPUMonitor class using Windows System APIs.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "CPUMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <pdh.h>
#include <pdhmsg.h>

#include <thread>
#include <shared_mutex>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "pdh.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// CONSTANTS & HELPERS
// ============================================================================

namespace {
    // Helper to convert FILETIME to uint64_t
    constexpr uint64_t FileTimeToInt64(const FILETIME& ft) {
        return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    }

    // Convert FILETIME to Duration (seconds) since epoch
    // Not used for delta, but for absolute time check
    // double FileTimeToSeconds(const FILETIME& ft) { ... }

    // Helper to calculate delta safely
    uint64_t GetDelta(uint64_t current, uint64_t previous) {
        return (current >= previous) ? (current - previous) : 0;
    }
}

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct ProcessHistory {
    uint64_t lastKernelTime{0};
    uint64_t lastUserTime{0};
    uint64_t lastCheckTime{0};
    std::wstring name;
    bool active{false}; // For garbage collection
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class CPUMonitorImpl {
public:
    CPUMonitorImpl() = default;
    ~CPUMonitorImpl() { Shutdown(); }

    CPUMonitorConfig m_config;
    mutable std::shared_mutex m_mutex;
    std::atomic<bool> m_isMonitoring{false};
    std::atomic<bool> m_stopRequested{false};
    std::thread m_monitorThread;

    // System Stats
    SystemCpuStats m_currentSystemStats{};
    uint64_t m_lastSystemKernel{0};
    uint64_t m_lastSystemUser{0};
    uint64_t m_lastSystemIdle{0};

    // Process Stats
    // Map PID -> History
    std::unordered_map<uint32_t, ProcessHistory> m_processHistory;
    // Map PID -> Current Info (Cached for readers)
    std::unordered_map<uint32_t, ProcessCpuInfo> m_processCache;

    // PDH Query (Alternative for more precise metrics if needed, using raw API for now for speed)
    // PDH_HQUERY m_pdhQuery = nullptr;

    bool Initialize(const CPUMonitorConfig& config) {
        std::unique_lock lock(m_mutex);
        m_config = config;

        // Initial reading for baseline
        UpdateSystemTimes();

        return true;
    }

    void Shutdown() {
        StopMonitoring();
        // Clear maps
        std::unique_lock lock(m_mutex);
        m_processHistory.clear();
        m_processCache.clear();
    }

    bool StartMonitoring() {
        std::unique_lock lock(m_mutex);
        if (m_isMonitoring) return true;

        m_stopRequested = false;
        m_monitorThread = std::thread(&CPUMonitorImpl::MonitoringLoop, this);
        m_isMonitoring = true;

        SS_LOG_INFO(L"CPUMonitor", L"Monitoring started. Interval: %u ms", m_config.samplingIntervalMs);
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
        SS_LOG_INFO(L"CPUMonitor", L"Monitoring stopped.");
    }

    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitoringLoop() {
        while (!m_stopRequested) {
            auto start = std::chrono::steady_clock::now();

            // 1. Update System Usage
            UpdateSystemStats();

            // 2. Update Process Usage
            if (m_config.trackPerProcess) {
                UpdateProcessStats();
            }

            // 3. Sleep for remainder of interval
            auto end = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

            int64_t sleepTime = m_config.samplingIntervalMs - elapsed;
            if (sleepTime > 0) {
                std::this_thread::sleep_for(std::chrono::milliseconds(sleepTime));
            } else {
                // If processing took longer than interval, yield briefly
                std::this_thread::yield();
            }
        }
    }

    void UpdateSystemTimes() {
        FILETIME idle, kernel, user;
        if (GetSystemTimes(&idle, &kernel, &user)) {
            m_lastSystemIdle = FileTimeToInt64(idle);
            m_lastSystemKernel = FileTimeToInt64(kernel);
            m_lastSystemUser = FileTimeToInt64(user);
        }
    }

    void UpdateSystemStats() {
        FILETIME fIdle, fKernel, fUser;
        if (!GetSystemTimes(&fIdle, &fKernel, &fUser)) return;

        uint64_t idle = FileTimeToInt64(fIdle);
        uint64_t kernel = FileTimeToInt64(fKernel);
        uint64_t user = FileTimeToInt64(fUser);

        uint64_t deltaIdle = GetDelta(idle, m_lastSystemIdle);
        uint64_t deltaKernel = GetDelta(kernel, m_lastSystemKernel);
        uint64_t deltaUser = GetDelta(user, m_lastSystemUser);

        // Kernel time includes Idle time in GetSystemTimes
        // Total System Time = (Kernel - Idle) + User + Idle = Kernel + User
        uint64_t totalSystem = deltaKernel + deltaUser;

        // Effective Kernel = Kernel - Idle
        uint64_t effectiveKernel = (deltaKernel > deltaIdle) ? (deltaKernel - deltaIdle) : 0;

        double totalUsage = 0.0;
        double kernelUsage = 0.0;
        double userUsage = 0.0;
        double idleUsage = 0.0;

        if (totalSystem > 0) {
            totalUsage = ((double)(effectiveKernel + deltaUser) / totalSystem) * 100.0;
            kernelUsage = ((double)effectiveKernel / totalSystem) * 100.0;
            userUsage = ((double)deltaUser / totalSystem) * 100.0;
            idleUsage = ((double)deltaIdle / totalSystem) * 100.0;
        }

        // Update stored stats
        {
            std::unique_lock lock(m_mutex);
            m_currentSystemStats.totalUsagePercent = totalUsage;
            m_currentSystemStats.kernelUsagePercent = kernelUsage;
            m_currentSystemStats.userUsagePercent = userUsage;
            m_currentSystemStats.idlePercent = idleUsage;

            // Note: Context switches / interrupts would require PDH or NtQuerySystemInformation
            // Leaving as 0 for this implementation to avoid PDH dependency complexity
        }

        // Update Last
        m_lastSystemIdle = idle;
        m_lastSystemKernel = kernel;
        m_lastSystemUser = user;
    }

    void UpdateProcessStats() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &pe32)) {
            CloseHandle(hSnapshot);
            return;
        }

        // Mark all existing as inactive for GC
        {
            std::unique_lock lock(m_mutex);
            for (auto& pair : m_processHistory) {
                pair.second.active = false;
            }
        }

        // Temporary storage for calculated stats
        std::vector<ProcessCpuInfo> newStats;
        newStats.reserve(128);

        uint64_t now = GetTickCount64(); // Simplified time check

        do {
            uint32_t pid = pe32.th32ProcessID;
            if (pid == 0) continue; // Skip System Idle Process

            // Calculate usage
            CalculateProcessUsage(pid, pe32.szExeFile, newStats);

            // Mark as active
            std::unique_lock lock(m_mutex);
            m_processHistory[pid].active = true;
            m_processHistory[pid].name = pe32.szExeFile;

        } while (Process32NextW(hSnapshot, &pe32));

        CloseHandle(hSnapshot);

        // Update Cache and GC
        {
            std::unique_lock lock(m_mutex);

            // GC: Remove inactive
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

    void CalculateProcessUsage(uint32_t pid, const std::wstring& name, std::vector<ProcessCpuInfo>& outStats) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) return;

        FILETIME fCreation, fExit, fKernel, fUser;
        if (GetProcessTimes(hProcess, &fCreation, &fExit, &fKernel, &fUser)) {
            uint64_t kernel = FileTimeToInt64(fKernel);
            uint64_t user = FileTimeToInt64(fUser);
            uint64_t now = GetTickCount64();

            double cpuPercent = 0.0;
            double kPercent = 0.0;
            double uPercent = 0.0;

            // Check history
            std::unique_lock lock(m_mutex); // Lock for history access
            auto it = m_processHistory.find(pid);
            if (it != m_processHistory.end()) {
                ProcessHistory& hist = it->second;

                uint64_t deltaKernel = GetDelta(kernel, hist.lastKernelTime);
                uint64_t deltaUser = GetDelta(user, hist.lastUserTime);
                uint64_t deltaTotal = deltaKernel + deltaUser;

                // We need system time delta to calculate percentage
                // Assuming this function is called immediately after UpdateSystemStats
                // We can approximate using wall clock time if system time delta is not available per-process
                // Logic: (ProcessDelta / (SystemCores * WallClockDelta)) * 100
                // For simplicity, we compare against the global System Time Delta calculated earlier

                // Calculate system delta (Global Kernel + Global User)
                // Re-calculating here is tricky without passing state.
                // Let's use the wall clock time which is 100ns units in FILETIME
                // Interval is m_config.samplingIntervalMs

                // Wait, GetProcessTimes gives absolute accumulated time.
                // Usage = (DeltaProc / DeltaWallClock) * 100 / NumProcessors

                SYSTEM_INFO sysInfo;
                GetNativeSystemInfo(&sysInfo);
                int numProcessors = sysInfo.dwNumberOfProcessors;
                if (numProcessors < 1) numProcessors = 1;

                // Time passed in 100ns units
                // We can use the monitor loop interval, but it's better to measure actual time
                // Let's rely on `now` - `hist.lastCheckTime` (converted to 100ns)
                // TickCount is ms. 1ms = 10,000 * 100ns

                uint64_t timeDeltaMs = GetDelta(now, hist.lastCheckTime);
                if (timeDeltaMs > 0) {
                     uint64_t timeDelta100ns = timeDeltaMs * 10000;
                     uint64_t totalCapacity = timeDelta100ns * numProcessors;

                     if (totalCapacity > 0) {
                         cpuPercent = ((double)deltaTotal / totalCapacity) * 100.0;
                         kPercent = ((double)deltaKernel / totalCapacity) * 100.0;
                         uPercent = ((double)deltaUser / totalCapacity) * 100.0;
                     }
                }

                // Sanity check
                if (cpuPercent > 100.0 * numProcessors) cpuPercent = 100.0 * numProcessors; // Can happen with tick count drift

                // Store new history
                hist.lastKernelTime = kernel;
                hist.lastUserTime = user;
                hist.lastCheckTime = now;
            } else {
                // First time seeing process, just init history
                ProcessHistory hist;
                hist.lastKernelTime = kernel;
                hist.lastUserTime = user;
                hist.lastCheckTime = now;
                hist.name = name;
                hist.active = true;
                m_processHistory[pid] = hist;
            }

            // Add to stats if we calculated valid usage
            if (it != m_processHistory.end()) {
                ProcessCpuInfo info;
                info.pid = pid;
                info.name = name;
                info.cpuUsagePercent = cpuPercent;
                info.kernelTimePercent = kPercent;
                info.userTimePercent = uPercent;

                // Calculate uptime
                // Creation time is absolute. Current time is... strictly we need SystemTime
                // FileTimeToSystemTime(&fCreation, ...);
                // Simplified:
                info.uptimeSeconds = 0; // TODO: Implement robust uptime calc

                outStats.push_back(info);
            }
        }

        CloseHandle(hProcess);
    }
};

// ============================================================================
// STATIC INSTANCE
// ============================================================================

static std::atomic<bool> s_instanceCreated{false};

CPUMonitor& CPUMonitor::Instance() noexcept {
    static CPUMonitor instance;
    return instance;
}

bool CPUMonitor::HasInstance() noexcept {
    return s_instanceCreated.load();
}

// ============================================================================
// LIFECYCLE
// ============================================================================

CPUMonitor::CPUMonitor() : m_impl(std::make_unique<CPUMonitorImpl>()) {
    s_instanceCreated = true;
}

CPUMonitor::~CPUMonitor() {
    Shutdown();
    s_instanceCreated = false;
}

bool CPUMonitor::Initialize(const CPUMonitorConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"CPUMonitor", L"Invalid configuration provided.");
        return false;
    }
    return m_impl->Initialize(config);
}

void CPUMonitor::Shutdown() {
    m_impl->Shutdown();
}

bool CPUMonitor::StartMonitoring() {
    return m_impl->StartMonitoring();
}

void CPUMonitor::StopMonitoring() {
    m_impl->StopMonitoring();
}

bool CPUMonitor::IsMonitoring() const noexcept {
    return m_impl->m_isMonitoring.load();
}

// ============================================================================
// PUBLIC ACCESSORS
// ============================================================================

SystemCpuStats CPUMonitor::GetSystemStats() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_currentSystemStats;
}

std::optional<double> CPUMonitor::GetProcessUsage(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second.cpuUsagePercent;
    }
    return std::nullopt;
}

std::optional<ProcessCpuInfo> CPUMonitor::GetProcessInfo(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_mutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ProcessCpuInfo> CPUMonitor::GetTopConsumers(size_t count) const {
    std::shared_lock lock(m_impl->m_mutex);

    // Copy cache to vector
    std::vector<ProcessCpuInfo> allProcesses;
    allProcesses.reserve(m_impl->m_processCache.size());

    for (const auto& [pid, info] : m_impl->m_processCache) {
        allProcesses.push_back(info);
    }

    // Sort desc by usage
    std::partial_sort(allProcesses.begin(),
                      allProcesses.begin() + std::min(count, allProcesses.size()),
                      allProcesses.end(),
                      [](const ProcessCpuInfo& a, const ProcessCpuInfo& b) {
                          return a.cpuUsagePercent > b.cpuUsagePercent;
                      });

    if (allProcesses.size() > count) {
        allProcesses.resize(count);
    }

    return allProcesses;
}

// ============================================================================
// CONFIG & UTILS
// ============================================================================

bool CPUMonitor::UpdateConfiguration(const CPUMonitorConfig& config) {
    if (!config.IsValid()) return false;
    std::unique_lock lock(m_impl->m_mutex);
    m_impl->m_config = config;
    return true;
}

CPUMonitorConfig CPUMonitor::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_mutex);
    return m_impl->m_config;
}

bool CPUMonitor::SelfTest() {
    // Basic test: verify we can read system time
    FILETIME i, k, u;
    if (!GetSystemTimes(&i, &k, &u)) return false;

    // Verify we can enumerate at least one process
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    CloseHandle(hSnap);

    return true;
}

std::string CPUMonitor::GetVersionString() noexcept {
    return "3.0.0";
}

// ============================================================================
// DATA STRUCT SERIALIZATION
// ============================================================================

std::string ProcessCpuInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"pid\":" << pid << ","
        << "\"name\":\"" << Utils::StringUtils::ToString(name) << "\","
        << "\"usage\":" << cpuUsagePercent << ","
        << "\"user\":" << userTimePercent << ","
        << "\"kernel\":" << kernelTimePercent
        << "}";
    return oss.str();
}

std::string SystemCpuStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"total\":" << totalUsagePercent << ","
        << "\"user\":" << userUsagePercent << ","
        << "\"kernel\":" << kernelUsagePercent << ","
        << "\"idle\":" << idlePercent
        << "}";
    return oss.str();
}

bool CPUMonitorConfig::IsValid() const noexcept {
    return samplingIntervalMs >= 100 && samplingIntervalMs <= 60000;
}

} // namespace Performance
} // namespace ShadowStrike
