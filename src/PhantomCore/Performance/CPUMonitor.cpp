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
 * ShadowStrike NGAV - CPU PERFORMANCE MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file CPUMonitor.cpp
 * @brief Implementation of the CPUMonitor class using Windows System APIs.
 *
 * DESIGN NOTES:
 * - Lock-minimized architecture: expensive API calls (OpenProcess,
 *   GetProcessTimes, CreateToolhelp32Snapshot) are performed WITHOUT
 *   holding any lock. A single short write-lock swaps the entire cache.
 * - RAII wrappers for all HANDLE types prevent leaks on any code path.
 * - Overflow-safe arithmetic via SafeMul / SafeDelta on all uint64 math.
 * - Responsive shutdown via condition_variable (sub-millisecond stop).
 * - Self-monitoring runs unconditionally even when trackPerProcess is off.
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

#include "CPUMonitor.hpp"
#include "../Utils/Logger.hpp"
#include "../Utils/StringUtils.hpp"
#include "../Utils/SystemUtils.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <climits>

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// RAII HANDLE WRAPPERS
// ============================================================================

namespace {

/**
 * @brief RAII wrapper for process HANDLEs (nullptr == invalid).
 */
class ScopedProcessHandle final {
public:
    explicit ScopedProcessHandle(HANDLE h = nullptr) noexcept : m_handle(h) {}
    ~ScopedProcessHandle() noexcept { Close(); }

    ScopedProcessHandle(const ScopedProcessHandle&) = delete;
    ScopedProcessHandle& operator=(const ScopedProcessHandle&) = delete;

    ScopedProcessHandle(ScopedProcessHandle&& o) noexcept
        : m_handle(o.m_handle) { o.m_handle = nullptr; }
    ScopedProcessHandle& operator=(ScopedProcessHandle&& o) noexcept {
        if (this != &o) { Close(); m_handle = o.m_handle; o.m_handle = nullptr; }
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
    }
    explicit operator bool() const noexcept { return IsValid(); }

private:
    void Close() noexcept {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(m_handle);
            m_handle = nullptr;
        }
    }
    HANDLE m_handle;
};

/**
 * @brief RAII wrapper for snapshot HANDLEs (INVALID_HANDLE_VALUE == invalid).
 */
class ScopedSnapshotHandle final {
public:
    explicit ScopedSnapshotHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept
        : m_handle(h) {}
    ~ScopedSnapshotHandle() noexcept {
        if (m_handle != INVALID_HANDLE_VALUE) { ::CloseHandle(m_handle); }
    }

    ScopedSnapshotHandle(const ScopedSnapshotHandle&) = delete;
    ScopedSnapshotHandle& operator=(const ScopedSnapshotHandle&) = delete;

    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] bool IsValid() const noexcept {
        return m_handle != INVALID_HANDLE_VALUE;
    }
    explicit operator bool() const noexcept { return IsValid(); }

private:
    HANDLE m_handle;
};

// ============================================================================
// CONSTANTS
// ============================================================================

constexpr uint64_t kFileTime100nsPerMs  = 10'000ULL;
constexpr uint64_t kFileTime100nsPerSec = 10'000'000ULL;
constexpr uint64_t kMaxSafeMsFor100ns   = UINT64_MAX / kFileTime100nsPerMs;
constexpr uint32_t kMaxReasonableProcessors = 1024;
constexpr size_t   kAbsoluteMaxTrackedProcesses = 65536;

// ============================================================================
// OVERFLOW-SAFE HELPERS
// ============================================================================

constexpr uint64_t FileTimeToUint64(const FILETIME& ft) noexcept {
    return (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
}

[[nodiscard]] constexpr uint64_t SafeDelta(uint64_t current,
                                           uint64_t previous) noexcept {
    return (current >= previous) ? (current - previous) : 0;
}

[[nodiscard]] constexpr uint64_t SafeMul(uint64_t a, uint64_t b) noexcept {
    if (a == 0 || b == 0) return 0;
    if (a > UINT64_MAX / b) return UINT64_MAX; // saturate
    return a * b;
}

[[nodiscard]] double SafePercent(uint64_t numerator,
                                 uint64_t denominator) noexcept {
    if (denominator == 0) return 0.0;
    return std::clamp(
        (static_cast<double>(numerator) / static_cast<double>(denominator)) * 100.0,
        0.0, 100.0);
}

// ============================================================================
// JSON HELPERS
// ============================================================================

/**
 * @brief Escape a UTF-8 string for safe embedding in a JSON value.
 *
 * Handles quotes, backslashes, and control characters. UTF-8 multi-byte
 * sequences pass through unmodified (continuation bytes are >= 0x80).
 */
[[nodiscard]] std::string EscapeJsonString(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (unsigned char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x",
                             static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

// ============================================================================
// SYSTEM QUERY HELPERS
// ============================================================================

[[nodiscard]] uint32_t QueryProcessorCount() noexcept {
    SYSTEM_INFO si{};
    ::GetNativeSystemInfo(&si);
    uint32_t n = si.dwNumberOfProcessors;
    if (n == 0) n = 1;
    if (n > kMaxReasonableProcessors) n = kMaxReasonableProcessors;
    return n;
}

} // anonymous namespace

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

struct ProcessTimingHistory {
    uint64_t lastKernelTime{0};
    uint64_t lastUserTime{0};
    uint64_t lastCheckTimeMs{0};     ///< GetTickCount64() at last sample
    std::wstring name;
};

struct CallbackEntry {
    uint32_t id{0};
    HighCpuCallback callback;
};

// ============================================================================
// IMPLEMENTATION CLASS (PIMPL)
// ============================================================================

class CPUMonitorImpl {
public:
    // ────────────────────────────────────────────────────────────────────────
    // Construction / Destruction
    // ────────────────────────────────────────────────────────────────────────

    CPUMonitorImpl()
        : m_processorCount(QueryProcessorCount())
        , m_selfPid(::GetCurrentProcessId())
    {}

    ~CPUMonitorImpl() { Shutdown(); }

    // ────────────────────────────────────────────────────────────────────────
    // State
    // ────────────────────────────────────────────────────────────────────────

    CPUMonitorConfig          m_config;
    mutable std::shared_mutex m_dataMutex;         // guards all data below
    std::atomic<bool>         m_initialized{false};
    std::atomic<bool>         m_isMonitoring{false};
    std::atomic<bool>         m_stopRequested{false};

    // Thread management
    std::thread              m_monitorThread;
    std::mutex               m_cvMutex;            // guards only the CV
    std::condition_variable  m_stopCv;

    // Cached constants (written once in ctor, immutable after)
    const uint32_t m_processorCount;
    const DWORD    m_selfPid;

    // System-level stats
    SystemCpuStats m_currentSystemStats{};
    uint64_t       m_lastSystemKernel{0};   // only touched by monitor thread
    uint64_t       m_lastSystemUser{0};
    uint64_t       m_lastSystemIdle{0};

    // Per-process data
    std::unordered_map<uint32_t, ProcessTimingHistory> m_processHistory;
    std::unordered_map<uint32_t, ProcessCpuInfo>       m_processCache;

    // Self-monitoring (always active, even when trackPerProcess is off)
    double               m_selfCpuUsage{0.0};    // guarded by m_dataMutex
    ProcessTimingHistory  m_selfHistory{};         // only touched by monitor thread

    // Callbacks – separate lock to avoid holding m_dataMutex during dispatch
    mutable std::shared_mutex  m_callbackMutex;
    std::vector<CallbackEntry> m_callbacks;
    std::atomic<uint32_t>      m_nextCallbackId{1};

    // ====================================================================
    // LIFECYCLE
    // ====================================================================

    bool Initialize(const CPUMonitorConfig& config) {
        if (m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_WARN(L"CPUMonitor", L"Re-initializing – shutting down first");
            Shutdown();
        }

        {
            std::unique_lock lock(m_dataMutex);
            m_config = config;
        }

        if (!TakeSystemBaseline()) {
            SS_LOG_ERROR(L"CPUMonitor",
                L"Failed to read initial system-times baseline");
            return false;
        }

        TakeSelfBaseline();

        m_initialized.store(true, std::memory_order_release);
        SS_LOG_INFO(L"CPUMonitor",
            L"Initialized. interval=%ums, highThresh=%.1f%%, minerThresh=%.1f%%, "
            L"selfThresh=%.1f%%, processors=%u",
            config.samplingIntervalMs, config.highUsageThreshold,
            config.cryptoMinerThresholdPercent,
            config.selfUsageAlertThreshold, m_processorCount);
        return true;
    }

    void Shutdown() {
        StopMonitoring();

        std::unique_lock lock(m_dataMutex);
        m_processHistory.clear();
        m_processCache.clear();
        m_selfCpuUsage = 0.0;
        m_currentSystemStats = {};
        m_initialized.store(false, std::memory_order_release);
    }

    bool StartMonitoring() {
        if (!m_initialized.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(L"CPUMonitor",
                L"Cannot start monitoring: not initialized");
            return false;
        }

        // Atomic CAS so only one caller wins
        bool expected = false;
        if (!m_isMonitoring.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            SS_LOG_DEBUG(L"CPUMonitor", L"Already monitoring");
            return true;
        }

        m_stopRequested.store(false, std::memory_order_release);

        try {
            m_monitorThread = std::thread(
                &CPUMonitorImpl::MonitoringLoop, this);
        } catch (const std::system_error& e) {
            m_isMonitoring.store(false, std::memory_order_release);
            SS_LOG_ERROR(L"CPUMonitor",
                L"Failed to create monitoring thread: %hs", e.what());
            return false;
        }

        uint32_t intervalMs;
        {
            std::shared_lock lock(m_dataMutex);
            intervalMs = m_config.samplingIntervalMs;
        }
        SS_LOG_INFO(L"CPUMonitor",
            L"Monitoring started. interval=%ums", intervalMs);
        return true;
    }

    void StopMonitoring() {
        bool expected = true;
        if (!m_isMonitoring.compare_exchange_strong(expected, false,
                std::memory_order_acq_rel)) {
            return; // not monitoring
        }

        // Signal the CV so the loop wakes immediately
        m_stopRequested.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(m_cvMutex);
            m_stopCv.notify_all();
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        SS_LOG_INFO(L"CPUMonitor", L"Monitoring stopped");
    }

    // ====================================================================
    // BASELINE (called before monitoring thread starts – no races)
    // ====================================================================

    bool TakeSystemBaseline() noexcept {
        FILETIME idle{}, kernel{}, user{};
        if (!::GetSystemTimes(&idle, &kernel, &user)) {
            SS_LOG_LAST_ERROR(L"CPUMonitor",
                L"GetSystemTimes failed during baseline");
            return false;
        }
        m_lastSystemIdle   = FileTimeToUint64(idle);
        m_lastSystemKernel = FileTimeToUint64(kernel);
        m_lastSystemUser   = FileTimeToUint64(user);
        return true;
    }

    void TakeSelfBaseline() noexcept {
        ScopedProcessHandle hSelf(
            ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_selfPid));
        if (!hSelf) return;

        FILETIME creation{}, exitTime{}, kernel{}, user{};
        if (::GetProcessTimes(hSelf.Get(),
                &creation, &exitTime, &kernel, &user)) {
            m_selfHistory.lastKernelTime  = FileTimeToUint64(kernel);
            m_selfHistory.lastUserTime    = FileTimeToUint64(user);
            m_selfHistory.lastCheckTimeMs = ::GetTickCount64();
        }
    }

    // ====================================================================
    // MONITORING LOOP
    // ====================================================================

    void MonitoringLoop() {
        SS_LOG_DEBUG(L"CPUMonitor", L"Monitor thread entered (tid=%u)",
                     ::GetCurrentThreadId());

        while (!m_stopRequested.load(std::memory_order_acquire)) {
            const auto cycleStart = std::chrono::steady_clock::now();

            // Snapshot config under brief read-lock
            CPUMonitorConfig cfgSnap;
            {
                std::shared_lock lock(m_dataMutex);
                cfgSnap = m_config;
            }

            // 1. System-wide CPU
            UpdateSystemStats();

            // 2. Per-process (if enabled)
            if (cfgSnap.trackPerProcess) {
                UpdateProcessStats(cfgSnap);
            }

            // 3. Self-monitoring (always runs)
            UpdateSelfUsage();

            // 4. Fire high-CPU alerts
            CheckHighCpuAlerts(cfgSnap);

            // 5. Interruptible sleep for remainder of interval
            const auto elapsed = std::chrono::steady_clock::now() - cycleStart;
            const auto target  = std::chrono::milliseconds(cfgSnap.samplingIntervalMs);
            if (elapsed < target) {
                std::unique_lock<std::mutex> lk(m_cvMutex);
                m_stopCv.wait_for(lk, target - elapsed, [this] {
                    return m_stopRequested.load(std::memory_order_acquire);
                });
            } else {
                std::this_thread::yield();
            }
        }

        SS_LOG_DEBUG(L"CPUMonitor", L"Monitor thread exiting");
    }

    // ====================================================================
    // SYSTEM STATS
    // ====================================================================

    void UpdateSystemStats() {
        FILETIME fIdle{}, fKernel{}, fUser{};
        if (!::GetSystemTimes(&fIdle, &fKernel, &fUser)) {
            SS_LOG_LAST_ERROR(L"CPUMonitor",
                L"GetSystemTimes failed during update cycle");
            return;
        }

        const uint64_t idle   = FileTimeToUint64(fIdle);
        const uint64_t kernel = FileTimeToUint64(fKernel);
        const uint64_t user   = FileTimeToUint64(fUser);

        const uint64_t dIdle   = SafeDelta(idle,   m_lastSystemIdle);
        const uint64_t dKernel = SafeDelta(kernel, m_lastSystemKernel);
        const uint64_t dUser   = SafeDelta(user,   m_lastSystemUser);

        // GetSystemTimes kernel time INCLUDES idle time
        const uint64_t totalSystem    = dKernel + dUser;
        const uint64_t effectiveKernel = SafeDelta(dKernel, dIdle);

        SystemCpuStats snap{};
        if (totalSystem > 0) {
            snap.totalUsagePercent  = SafePercent(effectiveKernel + dUser,
                                                  totalSystem);
            snap.kernelUsagePercent = SafePercent(effectiveKernel, totalSystem);
            snap.userUsagePercent   = SafePercent(dUser, totalSystem);
            snap.idlePercent        = SafePercent(dIdle, totalSystem);
        } else {
            snap.idlePercent = 100.0;
        }

        // Commit under write-lock (very brief – just copying doubles)
        {
            std::unique_lock lock(m_dataMutex);
            m_currentSystemStats.totalUsagePercent  = snap.totalUsagePercent;
            m_currentSystemStats.kernelUsagePercent = snap.kernelUsagePercent;
            m_currentSystemStats.userUsagePercent   = snap.userUsagePercent;
            m_currentSystemStats.idlePercent        = snap.idlePercent;
        }

        // Update baseline for next cycle (monitor-thread only – no lock)
        m_lastSystemIdle   = idle;
        m_lastSystemKernel = kernel;
        m_lastSystemUser   = user;
    }

    // ====================================================================
    // PER-PROCESS STATS
    // ====================================================================

    void UpdateProcessStats(const CPUMonitorConfig& cfg) {
        // --- Step 1: Snapshot (no lock) ---
        ScopedSnapshotHandle snapshot(
            ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshot) {
            SS_LOG_LAST_ERROR(L"CPUMonitor",
                L"CreateToolhelp32Snapshot failed");
            return;
        }

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (!::Process32FirstW(snapshot.Get(), &pe)) {
            SS_LOG_LAST_ERROR(L"CPUMonitor", L"Process32FirstW failed");
            return;
        }

        // --- Step 2: Copy old history under brief read-lock ---
        std::unordered_map<uint32_t, ProcessTimingHistory> oldHistory;
        {
            std::shared_lock lock(m_dataMutex);
            oldHistory = m_processHistory;
        }

        // --- Step 3: Enumerate & calculate WITHOUT holding any lock ---
        std::unordered_map<uint32_t, ProcessCpuInfo>       newCache;
        std::unordered_map<uint32_t, ProcessTimingHistory>  newHistory;
        newCache.reserve(256);
        newHistory.reserve(256);

        uint32_t processCount = 0;
        uint32_t threadCount  = 0;
        const uint64_t nowMs  = ::GetTickCount64();

        do {
            processCount++;
            threadCount += pe.cntThreads;

            const uint32_t pid = pe.th32ProcessID;
            if (pid == 0) continue; // System Idle Process

            // Cap per-process tracking only; continue tallying totals so the
            // system snapshot reflects the real process/thread count rather
            // than truncating at the tracked-process cap.
            if (newCache.size() < cfg.maxTrackedProcesses) {
                CalculateProcessUsage(pid, pe.szExeFile, nowMs,
                                      oldHistory, newCache, newHistory);
            }

        } while (::Process32NextW(snapshot.Get(), &pe));

        // --- Step 4: Single write-lock to swap everything atomically ---
        {
            std::unique_lock lock(m_dataMutex);
            m_processHistory = std::move(newHistory);
            m_processCache   = std::move(newCache);
            m_currentSystemStats.processesCount = processCount;
            m_currentSystemStats.threadsCount   = threadCount;
        }
    }

    /**
     * @brief Compute CPU% for one process (runs WITHOUT any lock).
     *
     * All inputs are local copies; all outputs go into local maps.
     * This keeps the critical section as short as possible.
     */
    void CalculateProcessUsage(
        uint32_t pid,
        const wchar_t* exeName,
        uint64_t nowMs,
        const std::unordered_map<uint32_t, ProcessTimingHistory>& oldHist,
        std::unordered_map<uint32_t, ProcessCpuInfo>& outCache,
        std::unordered_map<uint32_t, ProcessTimingHistory>& outHistory)
    {
        ScopedProcessHandle hProc(
            ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!hProc) return;

        FILETIME fCreation{}, fExit{}, fKernel{}, fUser{};
        if (!::GetProcessTimes(hProc.Get(),
                &fCreation, &fExit, &fKernel, &fUser)) {
            return;
        }

        const uint64_t kernel = FileTimeToUint64(fKernel);
        const uint64_t user   = FileTimeToUint64(fUser);

        // Always record updated history for next cycle
        ProcessTimingHistory newHist;
        newHist.lastKernelTime  = kernel;
        newHist.lastUserTime    = user;
        newHist.lastCheckTimeMs = nowMs;
        newHist.name            = exeName;
        outHistory[pid]         = newHist;

        // Need prior observation to compute a delta
        auto prev = oldHist.find(pid);
        if (prev == oldHist.end()) return;

        const ProcessTimingHistory& ph = prev->second;
        const uint64_t dKernel   = SafeDelta(kernel, ph.lastKernelTime);
        const uint64_t dUser     = SafeDelta(user,   ph.lastUserTime);
        const uint64_t dTotal    = dKernel + dUser;
        const uint64_t dTimeMs   = SafeDelta(nowMs,  ph.lastCheckTimeMs);

        if (dTimeMs == 0) return;

        // Wall-clock delta → 100-ns units (same as FILETIME)
        const uint64_t dTime100ns = SafeMul(
            std::min(dTimeMs, kMaxSafeMsFor100ns), kFileTime100nsPerMs);

        // Total CPU capacity = wall-time × #processors
        const uint64_t totalCap = SafeMul(
            dTime100ns, static_cast<uint64_t>(m_processorCount));

        if (totalCap == 0) return;

        ProcessCpuInfo info;
        info.pid              = pid;
        info.name             = exeName;
        info.cpuUsagePercent  = SafePercent(dTotal,  totalCap);
        info.kernelTimePercent = SafePercent(dKernel, totalCap);
        info.userTimePercent  = SafePercent(dUser,   totalCap);

        // Compute wall-clock uptime from absolute creation FILETIME
        FILETIME ftNow{};
        ::GetSystemTimeAsFileTime(&ftNow);
        const uint64_t now100ns      = FileTimeToUint64(ftNow);
        const uint64_t creation100ns = FileTimeToUint64(fCreation);
        if (now100ns > creation100ns) {
            info.uptimeSeconds = SafeDelta(now100ns, creation100ns)
                                 / kFileTime100nsPerSec;
        }

        outCache[pid] = std::move(info);
    }

    // ====================================================================
    // SELF-MONITORING  (runs every cycle regardless of trackPerProcess)
    // ====================================================================

    void UpdateSelfUsage() {
        ScopedProcessHandle hSelf(
            ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_selfPid));
        if (!hSelf) return;

        FILETIME creation{}, exitTime{}, kernel{}, user{};
        if (!::GetProcessTimes(hSelf.Get(),
                &creation, &exitTime, &kernel, &user)) {
            return;
        }

        const uint64_t k     = FileTimeToUint64(kernel);
        const uint64_t u     = FileTimeToUint64(user);
        const uint64_t nowMs = ::GetTickCount64();

        const uint64_t dK      = SafeDelta(k,     m_selfHistory.lastKernelTime);
        const uint64_t dU      = SafeDelta(u,     m_selfHistory.lastUserTime);
        const uint64_t dTotal  = dK + dU;
        const uint64_t dTimeMs = SafeDelta(nowMs, m_selfHistory.lastCheckTimeMs);

        double usage = 0.0;
        if (dTimeMs > 0) {
            const uint64_t dt100ns = SafeMul(
                std::min(dTimeMs, kMaxSafeMsFor100ns), kFileTime100nsPerMs);
            const uint64_t cap = SafeMul(
                dt100ns, static_cast<uint64_t>(m_processorCount));
            if (cap > 0) {
                usage = SafePercent(dTotal, cap);
            }
        }

        // Update baseline (monitor-thread only – no lock needed)
        m_selfHistory.lastKernelTime  = k;
        m_selfHistory.lastUserTime    = u;
        m_selfHistory.lastCheckTimeMs = nowMs;

        // Publish (brief write-lock)
        {
            std::unique_lock lock(m_dataMutex);
            m_selfCpuUsage = usage;
        }
    }

    // ====================================================================
    // HIGH-CPU / CRYPTO-MINER ALERTING
    // ====================================================================

    void CheckHighCpuAlerts(const CPUMonitorConfig& cfg) {
        // EDR SELF-USAGE ALERT — evaluated FIRST and independent of any external
        // offender. This previously sat *after* the "if (offenders.empty())
        // return;" below, so the service's own excessive CPU was only ever
        // reported when some OTHER process happened to be above the crypto-miner
        // threshold at the same time. The self-usage signal therefore vanished
        // in exactly the case that matters most — the EDR itself being the sole
        // CPU hog — which is why a 60-70% self-CPU run logged zero self-usage
        // warnings. Emit it unconditionally.
        {
            double self = 0.0;
            {
                std::shared_lock lock(m_dataMutex);
                self = m_selfCpuUsage;
            }
            if (self > cfg.selfUsageAlertThreshold) {
                SS_LOG_WARN(L"CPUMonitor",
                    L"EDR self-usage excessive: %.2f%% (threshold %.1f%%)",
                    self, cfg.selfUsageAlertThreshold);
                // Name the hottest OWN threads. The service is a protected
                // process (PPL) with handle stripping, so nothing outside can
                // enumerate its threads — this in-process sampler is the only
                // way to attribute the self-CPU to a subsystem.
                LogTopSelfThreads();
            }
        }

        // Collect external offenders under brief read-lock
        std::vector<ProcessCpuInfo> offenders;
        {
            std::shared_lock lock(m_dataMutex);
            for (const auto& [pid, info] : m_processCache) {
                if (info.cpuUsagePercent >= cfg.cryptoMinerThresholdPercent) {
                    offenders.push_back(info);
                }
            }
        }

        if (offenders.empty()) return;

        // Log each offender
        for (const auto& p : offenders) {
            SS_LOG_WARN(L"CPUMonitor",
                L"High CPU detected: PID=%u Name='%s' Usage=%.1f%%",
                p.pid, p.name.c_str(), p.cpuUsagePercent);
        }

        // Snapshot callbacks under shared lock, then dispatch WITHOUT holding
        // any lock. Holding m_callbackMutex during dispatch would deadlock if
        // a handler called UnregisterHighCpuCallback (which acquires unique
        // ownership of the same shared_mutex on the dispatching thread).
        std::vector<CallbackEntry> dispatchList;
        {
            std::shared_lock cbLock(m_callbackMutex);
            dispatchList = m_callbacks;
        }
        for (const auto& entry : dispatchList) {
            for (const auto& p : offenders) {
                try {
                    entry.callback(p.pid, p.name, p.cpuUsagePercent);
                } catch (const std::exception& ex) {
                    SS_LOG_ERROR(L"CPUMonitor",
                        L"Callback id=%u threw: %hs", entry.id, ex.what());
                } catch (...) {
                    SS_LOG_ERROR(L"CPUMonitor",
                        L"Callback id=%u threw unknown exception", entry.id);
                }
            }
        }
    }

    // ====================================================================
    // SELF-THREAD CPU ATTRIBUTION
    // ====================================================================

    // Name the OWN threads burning CPU. The service runs as a protected
    // process (PPL) with handle stripping, so no external profiler can open
    // its threads or read their Win32 start addresses — a process can always
    // inspect its own, so this must run in-process. Rate-limited to ~3 s and
    // only reached once the self-usage alert already tripped, so the Toolhelp
    // snapshot cost is bounded. Deltas are computed against the previous
    // sample; the logged start-address RVA (start - exeBase) maps back to a
    // function offline via the .map / .pdb, which is how an otherwise-silent
    // hot thread gets identified.
    void LogTopSelfThreads() {
        static std::unordered_map<DWORD, uint64_t> s_prev;  // tid -> cumulative 100ns (monitor thread only)
        static uint64_t s_prevTick = 0;

        const uint64_t nowTick = ::GetTickCount64();
        if (s_prevTick != 0 && (nowTick - s_prevTick) < 3000) {
            return;  // rate-limit: at most one attribution dump per ~3s
        }

        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return;

        // ThreadQuerySetWin32StartAddress (9) via ntdll — best-effort.
        using NtQueryInformationThreadFn =
            LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        static NtQueryInformationThreadFn ntQueryThread =
            reinterpret_cast<NtQueryInformationThreadFn>(::GetProcAddress(
                ::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));

        const DWORD selfPid = ::GetCurrentProcessId();
        struct Row { DWORD tid; uint64_t cur; uint64_t delta; uintptr_t start; };
        std::vector<Row> rows;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (::Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == selfPid) {
                    // THREAD_QUERY_INFORMATION (not _LIMITED_): the Win32
                    // start-address query below is denied under the limited
                    // right, which is why the first cut logged start=0x0. A
                    // process always has this access to its own threads, PPL
                    // included.
                    HANDLE ht = ::OpenThread(THREAD_QUERY_INFORMATION,
                                             FALSE, te.th32ThreadID);
                    if (ht) {
                        FILETIME c{}, e{}, k{}, u{};
                        if (::GetThreadTimes(ht, &c, &e, &k, &u)) {
                            ULARGE_INTEGER uk{}, uu{};
                            uk.LowPart = k.dwLowDateTime; uk.HighPart = k.dwHighDateTime;
                            uu.LowPart = u.dwLowDateTime; uu.HighPart = u.dwHighDateTime;
                            const uint64_t cur = uk.QuadPart + uu.QuadPart;
                            const auto it = s_prev.find(te.th32ThreadID);
                            const uint64_t prev = (it != s_prev.end()) ? it->second : 0;

                            uintptr_t startAddr = 0;
                            if (ntQueryThread) {
                                PVOID a = nullptr;
                                if (ntQueryThread(ht, 9, &a, sizeof(a), nullptr) >= 0) {
                                    startAddr = reinterpret_cast<uintptr_t>(a);
                                }
                            }
                            rows.push_back({ te.th32ThreadID, cur,
                                             (cur >= prev) ? (cur - prev) : 0, startAddr });
                        }
                        ::CloseHandle(ht);
                    }
                }
                te.dwSize = sizeof(te);
            } while (::Thread32Next(snap, &te));
        }
        ::CloseHandle(snap);

        const uint64_t dMs = (s_prevTick != 0 && nowTick > s_prevTick)
                                 ? (nowTick - s_prevTick) : 0;
        s_prev.clear();
        for (const auto& r : rows) s_prev[r.tid] = r.cur;
        s_prevTick = nowTick;

        if (rows.empty()) return;

        const bool haveDelta = (dMs > 0);
        std::sort(rows.begin(), rows.end(), [haveDelta](const Row& a, const Row& b) {
            return haveDelta ? (a.delta > b.delta) : (a.cur > b.cur);
        });

        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        const double ncores = si.dwNumberOfProcessors
                                  ? static_cast<double>(si.dwNumberOfProcessors) : 1.0;
        const uintptr_t exeBase =
            reinterpret_cast<uintptr_t>(::GetModuleHandleW(nullptr));

        SS_LOG_WARN(L"CPUMonitor",
            L"self-CPU thread attribution (exeBase=0x%llX interval=%llums threads=%zu):",
            static_cast<unsigned long long>(exeBase),
            static_cast<unsigned long long>(dMs), rows.size());

        const size_t n = (rows.size() < 10) ? rows.size() : 10;
        for (size_t i = 0; i < n; ++i) {
            const Row& r = rows[i];
            double pct = 0.0;
            if (haveDelta) {
                pct = static_cast<double>(r.delta)
                    / (static_cast<double>(dMs) * 10000.0 * ncores) * 100.0;
            }

            // Resolve the start address to its owning module + offset. That
            // names the code a silent hot thread runs (the service exe,
            // onnxruntime.dll, an emulator module, ...); the offset maps to the
            // exact function offline via the .map / .pdb.
            wchar_t modName[MAX_PATH];
            const wchar_t* modDisp = L"<unresolved>";
            unsigned long long modOff = 0;
            if (r.start) {
                HMODULE hm = nullptr;
                if (::GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        reinterpret_cast<LPCWSTR>(r.start), &hm) && hm) {
                    if (::GetModuleBaseNameW(::GetCurrentProcess(), hm,
                                             modName, MAX_PATH) > 0) {
                        modDisp = modName;
                        modOff = static_cast<unsigned long long>(
                            r.start - reinterpret_cast<uintptr_t>(hm));
                    }
                }
            }
            SS_LOG_WARN(L"CPUMonitor",
                L"  tid=%u cpu=%.1f%% cumMs=%llu %s+0x%llX (start=0x%llX)",
                r.tid, pct,
                static_cast<unsigned long long>(r.cur / 10000ull),
                modDisp, modOff,
                static_cast<unsigned long long>(r.start));
        }
    }

    // ====================================================================
    // CALLBACK MANAGEMENT
    // ====================================================================

    uint32_t RegisterCallback(HighCpuCallback cb) {
        if (!cb) {
            SS_LOG_ERROR(L"CPUMonitor",
                L"Attempted to register null high-CPU callback");
            return 0;
        }

        uint32_t id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        // Skip 0 (our sentinel for "invalid") on wraparound
        if (id == 0) {
            id = m_nextCallbackId.fetch_add(1, std::memory_order_relaxed);
        }

        {
            std::unique_lock lock(m_callbackMutex);
            m_callbacks.push_back({id, std::move(cb)});
        }

        SS_LOG_INFO(L"CPUMonitor",
            L"Registered high-CPU callback id=%u", id);
        return id;
    }

    void UnregisterCallback(uint32_t id) {
        std::unique_lock lock(m_callbackMutex);
        auto it = std::remove_if(m_callbacks.begin(), m_callbacks.end(),
            [id](const CallbackEntry& e) { return e.id == id; });
        if (it != m_callbacks.end()) {
            m_callbacks.erase(it, m_callbacks.end());
            SS_LOG_INFO(L"CPUMonitor",
                L"Unregistered high-CPU callback id=%u", id);
        }
    }
};

// ============================================================================
// SINGLETON INFRASTRUCTURE
// ============================================================================

namespace {
    std::atomic<bool>& InstanceCreatedFlag() noexcept {
        static std::atomic<bool> flag{false};
        return flag;
    }
} // anonymous

CPUMonitor& CPUMonitor::Instance() noexcept {
    static CPUMonitor instance;
    InstanceCreatedFlag().store(true, std::memory_order_release);
    return instance;
}

bool CPUMonitor::HasInstance() noexcept {
    return InstanceCreatedFlag().load(std::memory_order_acquire);
}

// ============================================================================
// LIFECYCLE DELEGATES
// ============================================================================

CPUMonitor::CPUMonitor()
    : m_impl(std::make_unique<CPUMonitorImpl>())
{}

CPUMonitor::~CPUMonitor() {
    if (m_impl) {
        m_impl->Shutdown();
    }
}

bool CPUMonitor::Initialize(const CPUMonitorConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"CPUMonitor",
            L"Rejected invalid configuration: interval=%ums "
            L"highThresh=%.1f%% minerThresh=%.1f%% maxProcs=%u hist=%u",
            config.samplingIntervalMs, config.highUsageThreshold,
            config.cryptoMinerThresholdPercent,
            config.maxTrackedProcesses, config.historySize);
        return false;
    }
    return m_impl->Initialize(config);
}

void CPUMonitor::Shutdown()       { m_impl->Shutdown(); }
bool CPUMonitor::StartMonitoring() { return m_impl->StartMonitoring(); }
void CPUMonitor::StopMonitoring()  { m_impl->StopMonitoring(); }

bool CPUMonitor::IsMonitoring() const noexcept {
    return m_impl->m_isMonitoring.load(std::memory_order_acquire);
}

// ============================================================================
// SYSTEM & PROCESS ACCESSORS
// ============================================================================

SystemCpuStats CPUMonitor::GetSystemStats() const {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_currentSystemStats;
}

std::optional<double> CPUMonitor::GetProcessUsage(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_dataMutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second.cpuUsagePercent;
    }
    return std::nullopt;
}

std::optional<ProcessCpuInfo> CPUMonitor::GetProcessInfo(uint32_t pid) const {
    std::shared_lock lock(m_impl->m_dataMutex);
    auto it = m_impl->m_processCache.find(pid);
    if (it != m_impl->m_processCache.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ProcessCpuInfo> CPUMonitor::GetTopConsumers(size_t count) const {
    if (count == 0) return {};

    std::shared_lock lock(m_impl->m_dataMutex);

    std::vector<ProcessCpuInfo> all;
    all.reserve(m_impl->m_processCache.size());
    for (const auto& [pid, info] : m_impl->m_processCache) {
        all.push_back(info);
    }

    const auto n = static_cast<ptrdiff_t>(std::min(count, all.size()));
    std::partial_sort(all.begin(), all.begin() + n, all.end(),
        [](const ProcessCpuInfo& a, const ProcessCpuInfo& b) {
            return a.cpuUsagePercent > b.cpuUsagePercent;
        });

    all.resize(static_cast<size_t>(n));
    return all;
}

// ============================================================================
// SELF-MONITORING
// ============================================================================

double CPUMonitor::GetSelfUsage() const noexcept {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_selfCpuUsage;
}

bool CPUMonitor::IsSelfUsageExcessive() const noexcept {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_selfCpuUsage > m_impl->m_config.selfUsageAlertThreshold;
}

// ============================================================================
// SYSTEM LOAD
// ============================================================================

bool CPUMonitor::IsSystemUnderLoad(double thresholdPercent) const noexcept {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_currentSystemStats.totalUsagePercent >= thresholdPercent;
}

uint32_t CPUMonitor::GetProcessorCount() noexcept {
    return QueryProcessorCount();
}

// ============================================================================
// CALLBACK MANAGEMENT
// ============================================================================

uint32_t CPUMonitor::RegisterHighCpuCallback(HighCpuCallback callback) {
    return m_impl->RegisterCallback(std::move(callback));
}

void CPUMonitor::UnregisterHighCpuCallback(uint32_t callbackId) {
    m_impl->UnregisterCallback(callbackId);
}

// ============================================================================
// CONFIGURATION
// ============================================================================

bool CPUMonitor::UpdateConfiguration(const CPUMonitorConfig& config) {
    if (!config.IsValid()) {
        SS_LOG_ERROR(L"CPUMonitor",
            L"UpdateConfiguration rejected: invalid parameters");
        return false;
    }
    std::unique_lock lock(m_impl->m_dataMutex);
    // If per-process tracking was just disabled, purge cached history so the
    // memory footprint matches the active configuration and GetTopConsumers()
    // does not surface stale samples from a previous policy window.
    if (m_impl->m_config.trackPerProcess && !config.trackPerProcess) {
        m_impl->m_processHistory.clear();
        m_impl->m_processCache.clear();
    }
    m_impl->m_config = config;
    SS_LOG_INFO(L"CPUMonitor",
        L"Configuration updated. interval=%ums highThresh=%.1f%%",
        config.samplingIntervalMs, config.highUsageThreshold);
    return true;
}

CPUMonitorConfig CPUMonitor::GetConfiguration() const {
    std::shared_lock lock(m_impl->m_dataMutex);
    return m_impl->m_config;
}

// ============================================================================
// DIAGNOSTICS
// ============================================================================

bool CPUMonitor::SelfTest() {
    // 1. Verify GetSystemTimes API
    FILETIME idle{}, kernel{}, user{};
    if (!::GetSystemTimes(&idle, &kernel, &user)) {
        SS_LOG_LAST_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: GetSystemTimes unavailable");
        return false;
    }

    // 2. Verify process enumeration
    ScopedSnapshotHandle snap(
        ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) {
        SS_LOG_LAST_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: CreateToolhelp32Snapshot unavailable");
        return false;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!::Process32FirstW(snap.Get(), &pe)) {
        SS_LOG_LAST_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: Process32FirstW returned no entries");
        return false;
    }

    // 3. Verify we can query our own process times
    ScopedProcessHandle hSelf(
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                      m_impl->m_selfPid));
    if (!hSelf) {
        SS_LOG_LAST_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: cannot open own process PID=%u",
            m_impl->m_selfPid);
        return false;
    }

    FILETIME creation{}, exitTime{}, kTime{}, uTime{};
    if (!::GetProcessTimes(hSelf.Get(),
            &creation, &exitTime, &kTime, &uTime)) {
        SS_LOG_LAST_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: GetProcessTimes failed for PID=%u",
            m_impl->m_selfPid);
        return false;
    }

    // 4. Verify processor count is sane
    if (m_impl->m_processorCount == 0 ||
        m_impl->m_processorCount > kMaxReasonableProcessors) {
        SS_LOG_ERROR(L"CPUMonitor",
            L"SelfTest FAIL: processor count=%u out of range",
            m_impl->m_processorCount);
        return false;
    }

    SS_LOG_INFO(L"CPUMonitor",
        L"SelfTest PASS. processors=%u selfPID=%u",
        m_impl->m_processorCount, m_impl->m_selfPid);
    return true;
}

std::string CPUMonitor::GetVersionString() noexcept {
    return "3.1.0";
}

// ============================================================================
// DATA STRUCT SERIALIZATION
// ============================================================================

std::string ProcessCpuInfo::ToJson() const {
    const std::string escapedName = EscapeJsonString(
        Utils::StringUtils::ToNarrow(name));

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << "{\"pid\":" << pid
        << ",\"name\":\"" << escapedName << "\""
        << ",\"usage\":" << cpuUsagePercent
        << ",\"user\":" << userTimePercent
        << ",\"kernel\":" << kernelTimePercent
        << ",\"uptimeSeconds\":" << uptimeSeconds
        << "}";
    return oss.str();
}

std::string SystemCpuStats::ToJson() const {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2)
        << "{\"total\":" << totalUsagePercent
        << ",\"user\":" << userUsagePercent
        << ",\"kernel\":" << kernelUsagePercent
        << ",\"idle\":" << idlePercent
        << ",\"processes\":" << processesCount
        << ",\"threads\":" << threadsCount
        << "}";
    return oss.str();
}

// ============================================================================
// CONFIG VALIDATION
// ============================================================================

bool CPUMonitorConfig::IsValid() const noexcept {
    if (samplingIntervalMs < 100 || samplingIntervalMs > 60000) return false;
    if (highUsageThreshold < 1.0 || highUsageThreshold > 100.0) return false;
    if (cryptoMinerThresholdPercent < 1.0 ||
        cryptoMinerThresholdPercent > 100.0) return false;
    if (selfUsageAlertThreshold < 0.1 ||
        selfUsageAlertThreshold > 100.0) return false;
    if (maxTrackedProcesses == 0 ||
        maxTrackedProcesses > kAbsoluteMaxTrackedProcesses) return false;
    if (historySize == 0 || historySize > 3600) return false;
    return true;
}

} // namespace Performance
} // namespace ShadowStrike
