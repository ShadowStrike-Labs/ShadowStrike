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
 * ShadowStrike NGAV - MEMORY PROFILER IMPLEMENTATION
 * ============================================================================
 *
 * @file MemoryProfiler.cpp
 * @brief Implementation of the MemoryProfiler class using Windows PSAPI.
 *        Provides system-wide and per-process memory monitoring with
 *        linear-regression-based leak detection.
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#include "pch.h"
#include "MemoryProfiler.hpp"
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <thread>
#include <shared_mutex>
#include <mutex>
#include <condition_variable>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <deque>
#include <cmath>

#pragma comment(lib, "psapi.lib")

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

class ScopedHandle final {
public:
    explicit ScopedHandle(HANDLE handle = nullptr) noexcept : m_handle(handle) {}

    ~ScopedHandle() noexcept { reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    ScopedHandle(ScopedHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }

    ScopedHandle& operator=(ScopedHandle&& other) noexcept {
        if (this != &other) {
            reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    void reset() noexcept {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
            m_handle = nullptr;
        }
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }

    [[nodiscard]] HANDLE get() const noexcept { return m_handle; }

private:
    HANDLE m_handle;
};

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct TimestampedSample {
    uint64_t privateBytes;
    std::chrono::steady_clock::time_point timestamp;
};

struct ProcessMemoryHistory {
    std::deque<TimestampedSample> samples;
    // Captured process image name from the most recent sample. Used to detect
    // PID reuse (kernel recycles PIDs aggressively) and discard stale samples
    // that would otherwise contaminate the leak-detection regression.
    std::wstring lastName;
    bool active{false};
};

// ============================================================================
// LINEAR REGRESSION FOR LEAK DETECTION
// ============================================================================

struct RegressionResult {
    double slope;       // Bytes per second growth rate
    double rSquared;    // Goodness of fit (0.0 - 1.0)
    bool valid;         // Enough data for meaningful result
};

// Least-squares linear regression on (time_seconds, private_bytes) pairs.
// Returns slope (bytes/sec) and R² for trend strength assessment.
[[nodiscard]] static RegressionResult ComputeLinearRegression(
    const std::deque<TimestampedSample>& samples) noexcept
{
    RegressionResult result{0.0, 0.0, false};

    const size_t n = samples.size();
    if (n < 3) return result;

    const auto baseTime = samples.front().timestamp;

    double sumX = 0.0, sumY = 0.0, sumXY = 0.0, sumX2 = 0.0;

    for (const auto& s : samples) {
        const double x = std::chrono::duration<double>(s.timestamp - baseTime).count();
        const double y = static_cast<double>(s.privateBytes);
        sumX  += x;
        sumY  += y;
        sumXY += x * y;
        sumX2 += x * x;
    }

    const double dn = static_cast<double>(n);
    const double denominator = dn * sumX2 - sumX * sumX;

    if (std::abs(denominator) < 1e-10) return result;

    result.slope = (dn * sumXY - sumX * sumY) / denominator;
    const double intercept = (sumY - result.slope * sumX) / dn;

    // Compute R² (coefficient of determination)
    const double yMean = sumY / dn;
    double ssTot = 0.0, ssRes = 0.0;

    for (const auto& s : samples) {
        const double x = std::chrono::duration<double>(s.timestamp - baseTime).count();
        const double y = static_cast<double>(s.privateBytes);
        const double yPred = result.slope * x + intercept;
        ssTot += (y - yMean) * (y - yMean);
        ssRes += (y - yPred) * (y - yPred);
    }

    result.rSquared = (ssTot > 1e-10) ? (1.0 - ssRes / ssTot) : 0.0;
    result.valid = true;

    return result;
}

// ============================================================================
// JSON STRING ESCAPING
// ============================================================================

[[nodiscard]] static std::string EscapeJsonString(const std::string& input) noexcept {
    std::string result;
    result.reserve(input.size() + 16);

    for (const char c : input) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b";  break;
            case '\f': result += "\\f";  break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
                break;
        }
    }

    return result;
}

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class MemoryProfilerImpl {
public:
    MemoryProfilerImpl() = default;
    ~MemoryProfilerImpl() { Shutdown(); }

    MemoryProfilerImpl(const MemoryProfilerImpl&) = delete;
    MemoryProfilerImpl& operator=(const MemoryProfilerImpl&) = delete;

    // ---- Configuration & Data (protected by m_dataMutex) ----
    MemoryProfilerConfig m_config;
    mutable std::shared_mutex m_dataMutex;
    SystemMemoryStats m_currentSystemStats{};
    std::unordered_map<uint32_t, ProcessMemoryHistory> m_processHistory;
    std::unordered_map<uint32_t, ProcessMemoryInfo> m_processCache;

    // ---- Thread Control ----
    std::mutex m_sleepMutex;
    std::condition_variable m_sleepCv;
    std::atomic<bool> m_isMonitoring{false};
    std::atomic<bool> m_stopRequested{false};
    std::thread m_monitorThread;

    // Serializes Start/StopMonitoring to prevent two concurrent callers from
    // racing on the std::thread object (joining a thread from two threads is
    // undefined behavior, and a Start/Stop interleave could leak the worker
    // and terminate() from std::thread's destructor).
    std::mutex m_lifecycleMutex;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    bool Initialize(const MemoryProfilerConfig& config) {
        // A live monitoring thread reads m_config concurrently; tear it down
        // first so the new configuration is applied atomically and no sample
        // is taken with a half-updated configuration.
        const bool wasMonitoring = m_isMonitoring.load(std::memory_order_acquire);
        if (wasMonitoring) {
            StopMonitoring();
        }

        {
            std::unique_lock lock(m_dataMutex);
            m_config = config;
            // Drop history accumulated under previous configuration so that
            // history-size and leak-detection thresholds apply consistently.
            m_processHistory.clear();
            m_processCache.clear();
        }

        if (!RefreshSystemStats()) {
            SS_LOG_WARN(L"MemoryProfiler",
                        L"Initial system stats refresh failed during initialization");
        }

        SS_LOG_INFO(L"MemoryProfiler",
                    L"Initialized. Interval=%ums History=%u MaxProcs=%u MinSamplesLeak=%u",
                    config.samplingIntervalMs, config.historySize,
                    config.maxTrackedProcesses, config.minSamplesForLeakDetection);

        if (wasMonitoring) {
            // Best-effort: restore prior monitoring state. Failure to recreate
            // the worker is reported but does not invalidate the new config.
            if (!StartMonitoring()) {
                SS_LOG_WARN(L"MemoryProfiler",
                            L"Initialize: monitoring was active but could not be resumed");
            }
        }
        return true;
    }

    void Shutdown() {
        StopMonitoring();
        std::unique_lock lock(m_dataMutex);
        m_processHistory.clear();
        m_processCache.clear();
    }

    bool StartMonitoring() {
        // Serialize against concurrent Start/StopMonitoring callers; without
        // this guard, two threads can both observe m_isMonitoring == false
        // and try to construct m_monitorThread, or a Stop call may race with
        // an in-progress Start and leak the worker thread.
        std::lock_guard lifecycle(m_lifecycleMutex);

        if (m_isMonitoring.load(std::memory_order_acquire)) {
            return true;
        }

        // If a previous monitor thread terminated abnormally, std::thread
        // remains joinable but cannot be reassigned without joining first.
        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        m_stopRequested.store(false, std::memory_order_release);

        // Publish the monitoring flag BEFORE constructing the worker so any
        // concurrent IsMonitoring/StopMonitoring observer sees a consistent
        // state. Roll back on construction failure.
        m_isMonitoring.store(true, std::memory_order_release);

        try {
            m_monitorThread = std::thread(&MemoryProfilerImpl::MonitoringLoop, this);
        } catch (const std::system_error& e) {
            m_isMonitoring.store(false, std::memory_order_release);
            SS_LOG_ERROR(L"MemoryProfiler",
                         L"Failed to create monitoring thread: error_code=%d", e.code().value());
            return false;
        }

        uint32_t interval;
        {
            std::shared_lock lock(m_dataMutex);
            interval = m_config.samplingIntervalMs;
        }
        SS_LOG_INFO(L"MemoryProfiler", L"Monitoring started. Interval: %u ms", interval);
        return true;
    }

    void StopMonitoring() {
        std::lock_guard lifecycle(m_lifecycleMutex);

        if (!m_isMonitoring.load(std::memory_order_acquire)) {
            // If a prior StartMonitoring failed mid-flight, the thread object
            // may still be joinable; reap it to keep the std::thread destructor
            // contract intact.
            if (m_monitorThread.joinable()) {
                m_monitorThread.join();
            }
            return;
        }

        m_stopRequested.store(true, std::memory_order_release);
        {
            std::lock_guard lock(m_sleepMutex);
        }
        m_sleepCv.notify_all();

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        m_isMonitoring.store(false, std::memory_order_release);
        SS_LOG_INFO(L"MemoryProfiler", L"Monitoring stopped.");
    }

    // ========================================================================
    // MONITORING LOOP
    // ========================================================================

    void MonitoringLoop() {
        SS_LOG_DEBUG(L"MemoryProfiler", L"Monitor thread started (tid=%u)",
                     ::GetCurrentThreadId());

        while (!m_stopRequested.load(std::memory_order_acquire)) {
            const auto cycleStart = std::chrono::steady_clock::now();

            PerformRefresh();

            const auto cycleEnd = std::chrono::steady_clock::now();
            const auto elapsedMs = std::chrono::duration_cast<
                std::chrono::milliseconds>(cycleEnd - cycleStart).count();

            uint32_t intervalMs;
            {
                std::shared_lock lock(m_dataMutex);
                intervalMs = m_config.samplingIntervalMs;
            }

            const int64_t remainingMs = static_cast<int64_t>(intervalMs) - elapsedMs;
            if (remainingMs > 0) {
                std::unique_lock sleepLock(m_sleepMutex);
                m_sleepCv.wait_for(sleepLock,
                    std::chrono::milliseconds(remainingMs),
                    [this] { return m_stopRequested.load(std::memory_order_acquire); });
            } else {
                std::this_thread::yield();
            }
        }

        SS_LOG_DEBUG(L"MemoryProfiler", L"Monitor thread exiting (tid=%u)",
                     ::GetCurrentThreadId());
    }

    // ========================================================================
    // REFRESH OPERATIONS
    // ========================================================================

    bool PerformRefresh() {
        const bool systemOk = RefreshSystemStats();

        bool trackProcs;
        {
            std::shared_lock lock(m_dataMutex);
            trackProcs = m_config.trackPerProcess;
        }

        bool processOk = true;
        if (trackProcs) {
            processOk = RefreshProcessStats();
        } else {
            std::unique_lock lock(m_dataMutex);
            m_processHistory.clear();
            m_processCache.clear();
        }

        return systemOk && processOk;
    }

    bool RefreshSystemStats() {
        MEMORYSTATUSEX memInfo{};
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);

        if (!::GlobalMemoryStatusEx(&memInfo)) {
            SS_LOG_LAST_ERROR(L"MemoryProfiler", L"GlobalMemoryStatusEx failed");
            return false;
        }

        // Query kernel pool statistics via GetPerformanceInfo. On failure we
        // intentionally preserve the previous pool readings rather than
        // overwriting the cached values with zeros — a transient GetPerformanceInfo
        // failure (e.g., during high system load) must not surface as a sudden
        // "pool collapsed to 0" telemetry point.
        bool perfOk = false;
        uint64_t pagedPool = 0;
        uint64_t nonPagedPool = 0;
        PERFORMANCE_INFORMATION perfInfo{};
        perfInfo.cb = sizeof(perfInfo);
        if (::GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
            const uint64_t pageSize = static_cast<uint64_t>(perfInfo.PageSize);
            pagedPool    = static_cast<uint64_t>(perfInfo.KernelPaged) * pageSize;
            nonPagedPool = static_cast<uint64_t>(perfInfo.KernelNonpaged) * pageSize;
            perfOk = true;
        } else {
            SS_LOG_LAST_ERROR(L"MemoryProfiler", L"GetPerformanceInfo failed (non-critical)");
        }

        uint32_t highLoad   = 0;
        uint32_t threshold  = 0;
        {
            std::unique_lock lock(m_dataMutex);
            m_currentSystemStats.totalPhysical    = memInfo.ullTotalPhys;
            m_currentSystemStats.availablePhysical = memInfo.ullAvailPhys;
            m_currentSystemStats.totalCommit       = memInfo.ullTotalPageFile;
            m_currentSystemStats.availableCommit   = memInfo.ullAvailPageFile;
            m_currentSystemStats.memoryLoad        = memInfo.dwMemoryLoad;
            if (perfOk) {
                m_currentSystemStats.pagedPool    = pagedPool;
                m_currentSystemStats.nonPagedPool = nonPagedPool;
            }
            highLoad  = memInfo.dwMemoryLoad;
            threshold = m_config.highLoadThreshold;
        }

        // Log outside the writer lock to keep the critical section short and
        // to avoid stalling readers if the logger backend blocks on I/O.
        if (highLoad >= threshold) {
            SS_LOG_WARN(L"MemoryProfiler",
                        L"High system memory load: %u%% (threshold: %u%%)",
                        highLoad, threshold);
        }

        return true;
    }

    bool RefreshProcessStats() {
        ScopedHandle hSnapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) {
            SS_LOG_LAST_ERROR(L"MemoryProfiler", L"CreateToolhelp32Snapshot failed");
            return false;
        }

        PROCESSENTRY32W pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!::Process32FirstW(hSnapshot.get(), &pe32)) {
            SS_LOG_LAST_ERROR(L"MemoryProfiler", L"Process32FirstW failed");
            return false;
        }

        // Snapshot config and system stats under shared lock
        uint32_t historySize;
        uint32_t minSamples;
        uint64_t leakThresholdBytes;
        uint64_t totalPhys;
        uint32_t maxTracked;
        {
            std::shared_lock lock(m_dataMutex);
            historySize        = m_config.historySize;
            minSamples         = m_config.minSamplesForLeakDetection;
            leakThresholdBytes = m_config.leakThresholdBytes;
            maxTracked         = m_config.maxTrackedProcesses;
            totalPhys = (m_currentSystemStats.totalPhysical > 0)
                        ? m_currentSystemStats.totalPhysical
                        : 1ULL;
        }

        // Collect process data without holding our data mutex (Win32 API calls)
        struct CollectedProcess {
            ProcessMemoryInfo info;
            std::chrono::steady_clock::time_point sampleTime;
        };

        std::vector<CollectedProcess> collected;
        collected.reserve(256);

        const auto now = std::chrono::steady_clock::now();
        const uint32_t selfPid = ::GetCurrentProcessId();

        do {
            const uint32_t pid = pe32.th32ProcessID;
            if (pid == 0) continue; // Skip System Idle Process

            ScopedHandle hProcess(::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
            if (!hProcess) {
                continue; // Access denied or process exited
            }

            PROCESS_MEMORY_COUNTERS_EX pmc{};
            pmc.cb = sizeof(pmc);
            if (!::GetProcessMemoryInfo(hProcess.get(),
                    reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                continue;
            }

            CollectedProcess cp{};
            cp.info.pid                  = pid;
            cp.info.name                 = pe32.szExeFile;
            cp.info.workingSetSize       = pmc.WorkingSetSize;
            cp.info.privateUsage         = pmc.PrivateUsage;
            cp.info.peakWorkingSetSize   = pmc.PeakWorkingSetSize;
            cp.info.pageFaultCount       = pmc.PageFaultCount;
            cp.info.percentOfSystemMemory =
                (static_cast<double>(pmc.WorkingSetSize) / static_cast<double>(totalPhys)) * 100.0;
            cp.info.isLeaking            = false;
            cp.sampleTime                = now;

            collected.push_back(std::move(cp));

        } while (::Process32NextW(hSnapshot.get(), &pe32));

        // Enforce process count cap: retain self PID + top N-1 by private bytes
        if (maxTracked > 0 && collected.size() > maxTracked) {
            std::sort(collected.begin(), collected.end(),
                [selfPid](const CollectedProcess& a, const CollectedProcess& b) {
                    if (a.info.pid == selfPid) return true;
                    if (b.info.pid == selfPid) return false;
                    return a.info.privateUsage > b.info.privateUsage;
                });
            collected.resize(maxTracked);
        }

        // Apply all updates atomically under a single write lock
        {
            std::unique_lock lock(m_dataMutex);

            // Mark all existing history as inactive for GC
            for (auto& [pid, history] : m_processHistory) {
                history.active = false;
            }

            // Update histories with new samples.
            //
            // PID-reuse defence: Windows recycles process IDs aggressively
            // (especially on long-running endpoints). If a PID we previously
            // tracked has been assigned to a freshly spawned process, the
            // image name will differ. In that case we must discard the prior
            // sample series — otherwise the linear regression will fit a
            // synthetic upward slope spanning two unrelated processes and
            // emit a false-positive memory-leak alert.
            for (const auto& cp : collected) {
                auto& history = m_processHistory[cp.info.pid];
                if (!history.lastName.empty() && history.lastName != cp.info.name) {
                    history.samples.clear();
                }
                history.lastName = cp.info.name;
                history.active = true;
                history.samples.push_back({cp.info.privateUsage, cp.sampleTime});

                while (history.samples.size() > historySize) {
                    history.samples.pop_front();
                }
            }

            // Perform leak detection using linear regression
            for (auto& cp : collected) {
                auto histIt = m_processHistory.find(cp.info.pid);
                if (histIt == m_processHistory.end()) continue;

                const auto& history = histIt->second;
                if (history.samples.size() < minSamples) continue;

                // Fast path: no growth means no leak
                const uint64_t firstPrivate = history.samples.front().privateBytes;
                const uint64_t lastPrivate  = history.samples.back().privateBytes;
                if (lastPrivate <= firstPrivate) continue;

                const uint64_t absoluteGrowth = lastPrivate - firstPrivate;
                if (absoluteGrowth < leakThresholdBytes) continue;

                // Compute linear regression for trend confirmation
                const auto regression = ComputeLinearRegression(history.samples);
                if (!regression.valid) continue;

                // Leak criteria:
                //  1. Positive slope (memory growing over time)
                //  2. R² > 0.7 (strong linear trend, not random spikes)
                //  3. Slope > 1 KB/sec sustained growth rate
                constexpr double kMinLeakSlopeBytesPerSec = 1024.0;
                constexpr double kMinRSquared = 0.7;

                if (regression.slope > kMinLeakSlopeBytesPerSec &&
                    regression.rSquared > kMinRSquared) {
                    cp.info.isLeaking = true;
                    SS_LOG_WARN(L"MemoryProfiler",
                        L"Potential memory leak: PID=%u Name=%ls Growth=%.1fMB "
                        L"Slope=%.1fKB/s R\u00B2=%.3f",
                        cp.info.pid, cp.info.name.c_str(),
                        static_cast<double>(absoluteGrowth) / (1024.0 * 1024.0),
                        regression.slope / 1024.0,
                        regression.rSquared);
                }
            }

            // GC: Remove history entries for dead processes
            std::erase_if(m_processHistory, [](const auto& pair) {
                return !pair.second.active;
            });

            // Rebuild process cache atomically
            m_processCache.clear();
            m_processCache.reserve(collected.size());
            for (auto& cp : collected) {
                const uint32_t pid = cp.info.pid;
                m_processCache.emplace(pid, std::move(cp.info));
            }
        }

        return true;
    }

    // ========================================================================
    // SELF-MONITORING
    // ========================================================================

    [[nodiscard]] ProcessMemoryInfo QuerySelfMemoryUsage() const {
        ProcessMemoryInfo self{};
        self.pid = ::GetCurrentProcessId();

        // GetCurrentProcess() returns a pseudo-handle — no need to close
        const HANDLE hSelf = ::GetCurrentProcess();

        wchar_t moduleName[MAX_PATH]{};
        const DWORD nameLen = ::GetModuleBaseNameW(hSelf, nullptr, moduleName, MAX_PATH);
        self.name = (nameLen > 0) ? std::wstring(moduleName, nameLen) : L"<self>";

        PROCESS_MEMORY_COUNTERS_EX pmc{};
        pmc.cb = sizeof(pmc);
        if (::GetProcessMemoryInfo(hSelf,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
            self.workingSetSize     = pmc.WorkingSetSize;
            self.privateUsage       = pmc.PrivateUsage;
            self.peakWorkingSetSize = pmc.PeakWorkingSetSize;
            self.pageFaultCount     = pmc.PageFaultCount;

            uint64_t totalPhys;
            {
                std::shared_lock lock(m_dataMutex);
                totalPhys = (m_currentSystemStats.totalPhysical > 0)
                            ? m_currentSystemStats.totalPhysical
                            : 1ULL;
            }
            self.percentOfSystemMemory =
                (static_cast<double>(pmc.WorkingSetSize) / static_cast<double>(totalPhys)) * 100.0;
        } else {
            SS_LOG_LAST_ERROR(L"MemoryProfiler",
                              L"GetProcessMemoryInfo failed for self process");
        }

        // Pull leak status from the monitoring cache if available
        {
            std::shared_lock lock(m_dataMutex);
            auto it = m_processCache.find(self.pid);
            if (it != m_processCache.end()) {
                self.isLeaking = it->second.isLeaking;
            }
        }

        return self;
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
    return s_instanceCreated.load(std::memory_order_acquire);
}

// ============================================================================
// PUBLIC METHODS
// ============================================================================

MemoryProfiler::MemoryProfiler()
    : m_impl(std::make_unique<MemoryProfilerImpl>())
{
    s_instanceCreated.store(true, std::memory_order_release);
}

MemoryProfiler::~MemoryProfiler() {
    Shutdown();
    s_instanceCreated.store(false, std::memory_order_release);
}

bool MemoryProfiler::Initialize(const MemoryProfilerConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"MemoryProfiler",
                     L"Invalid configuration: interval=%ums history=%u maxProcs=%u minSamples=%u",
                     config.samplingIntervalMs, config.historySize,
                     config.maxTrackedProcesses, config.minSamplesForLeakDetection);
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
    return m_impl->m_isMonitoring.load(std::memory_order_acquire);
}

SystemMemoryStats MemoryProfiler::GetSystemStats() const {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_currentSystemStats;
}

std::optional<ProcessMemoryInfo> MemoryProfiler::GetProcessInfo(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_dataMutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ProcessMemoryInfo> MemoryProfiler::GetTopConsumers(
    size_t count, bool byPrivateBytes) const
{
    std::shared_lock lock(m_impl->m_dataMutex);

    std::vector<ProcessMemoryInfo> allProcesses;
    allProcesses.reserve(m_impl->m_processCache.size());

    for (const auto& [pid, info] : m_impl->m_processCache) {
        allProcesses.push_back(info);
    }

    const auto sorter = [byPrivateBytes](const ProcessMemoryInfo& a,
                                         const ProcessMemoryInfo& b) {
        return byPrivateBytes ? (a.privateUsage > b.privateUsage)
                              : (a.workingSetSize > b.workingSetSize);
    };

    const size_t resultCount = std::min(count, allProcesses.size());
    std::partial_sort(allProcesses.begin(),
                      allProcesses.begin() + static_cast<ptrdiff_t>(resultCount),
                      allProcesses.end(),
                      sorter);

    allProcesses.resize(resultCount);
    return allProcesses;
}

ProcessMemoryInfo MemoryProfiler::GetSelfMemoryUsage() const {
    return m_impl->QuerySelfMemoryUsage();
}

bool MemoryProfiler::RefreshNow() {
    return m_impl->PerformRefresh();
}

bool MemoryProfiler::UpdateConfiguration(const MemoryProfilerConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"MemoryProfiler", L"Rejected invalid configuration update");
        return false;
    }
    std::unique_lock lock(m_impl->m_dataMutex);
    m_impl->m_config = config;
    SS_LOG_INFO(L"MemoryProfiler", L"Configuration updated. Interval=%ums History=%u MaxProcs=%u",
                config.samplingIntervalMs, config.historySize, config.maxTrackedProcesses);
    return true;
}

MemoryProfilerConfig MemoryProfiler::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_config;
}

bool MemoryProfiler::SelfTest() {
    SS_LOG_INFO(L"MemoryProfiler", L"Running self-test...");

    // Test 1: System memory query
    MEMORYSTATUSEX memInfo{};
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (!::GlobalMemoryStatusEx(&memInfo)) {
        SS_LOG_LAST_ERROR(L"MemoryProfiler",
                          L"Self-test FAILED: GlobalMemoryStatusEx error");
        return false;
    }
    if (memInfo.ullTotalPhys == 0) {
        SS_LOG_ERROR(L"MemoryProfiler",
                     L"Self-test FAILED: Reported 0 bytes total physical memory");
        return false;
    }

    // Test 2: Self-process memory query using pseudo-handle
    const HANDLE hSelf = ::GetCurrentProcess();
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (!::GetProcessMemoryInfo(hSelf,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        SS_LOG_LAST_ERROR(L"MemoryProfiler",
                          L"Self-test FAILED: GetProcessMemoryInfo on self");
        return false;
    }

    // Test 3: Verify refresh pipeline
    if (!RefreshNow()) {
        SS_LOG_ERROR(L"MemoryProfiler",
                     L"Self-test FAILED: RefreshNow returned false");
        return false;
    }

    // Test 4: Verify self PID appears in process cache
    {
        std::shared_lock lock(m_impl->m_dataMutex);
        if (m_impl->m_config.trackPerProcess) {
            const uint32_t myPid = ::GetCurrentProcessId();
            if (m_impl->m_processCache.find(myPid) == m_impl->m_processCache.end()) {
                SS_LOG_ERROR(L"MemoryProfiler",
                             L"Self-test FAILED: Self PID %u not in process cache", myPid);
                return false;
            }
        }
    }

    SS_LOG_INFO(L"MemoryProfiler",
                L"Self-test PASSED. TotalRAM=%llu MB, SelfWS=%llu KB",
                memInfo.ullTotalPhys / (1024ULL * 1024ULL),
                pmc.WorkingSetSize / 1024ULL);
    return true;
}

std::string MemoryProfiler::GetVersionString() noexcept {
    return "3.1.0";
}

// ============================================================================
// SERIALIZATION
// ============================================================================

std::string ProcessMemoryInfo::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"pid\":" << pid << ","
        << "\"name\":\"" << EscapeJsonString(ShadowStrike::Utils::StringUtils::ToNarrow(name)) << "\","
        << "\"workingSetBytes\":" << workingSetSize << ","
        << "\"privateBytes\":" << privateUsage << ","
        << "\"peakWorkingSetBytes\":" << peakWorkingSetSize << ","
        << "\"pageFaultCount\":" << pageFaultCount << ","
        << "\"percentOfSystemMemory\":" << std::fixed << std::setprecision(2)
            << percentOfSystemMemory << ","
        << "\"isLeaking\":" << (isLeaking ? "true" : "false")
        << "}";
    return oss.str();
}

std::string SystemMemoryStats::ToJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"totalPhysicalBytes\":" << totalPhysical << ","
        << "\"availablePhysicalBytes\":" << availablePhysical << ","
        << "\"totalCommitBytes\":" << totalCommit << ","
        << "\"availableCommitBytes\":" << availableCommit << ","
        << "\"nonPagedPoolBytes\":" << nonPagedPool << ","
        << "\"pagedPoolBytes\":" << pagedPool << ","
        << "\"memoryLoadPercent\":" << memoryLoad
        << "}";
    return oss.str();
}

bool MemoryProfilerConfig::IsValid() const noexcept {
    if (samplingIntervalMs < 100 || samplingIntervalMs > 3600000) return false;
    if (historySize < 3 || historySize > 10000) return false;
    if (highLoadThreshold == 0 || highLoadThreshold > 100) return false;
    if (leakThresholdBytes == 0) return false;
    if (maxTrackedProcesses == 0 || maxTrackedProcesses > 100000) return false;
    if (minSamplesForLeakDetection < 3 || minSamplesForLeakDetection > historySize) return false;
    return true;
}

} // namespace Performance
} // namespace ShadowStrike
