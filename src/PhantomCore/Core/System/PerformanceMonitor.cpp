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
 * ShadowStrike Core System - PERFORMANCE MONITOR IMPLEMENTATION
 * ============================================================================
 *
 * @file PerformanceMonitor.cpp
 * @brief Enterprise-grade system and process performance monitoring engine.
 *
 * This module provides comprehensive performance monitoring including CPU,
 * memory, I/O, and network metrics with anomaly detection, cryptominer
 * detection, and AV self-optimization capabilities.
 *
 * Key Features:
 * - Per-process resource tracking (CPU, memory, I/O, handles)
 * - System-wide metrics with PDH counters
 * - Real-time anomaly detection (high CPU, memory leaks, mining)
 * - Resource pressure assessment
 * - AV self-throttling recommendations
 * - Historical data tracking
 * - System idle state detection
 *
 * Detection Capabilities:
 * - Cryptominer detection (sustained high CPU patterns)
 * - Memory leak detection (monotonic growth)
 * - Handle leak detection
 * - I/O flood detection
 * - Resource exhaustion attacks
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 */

#include "pch.h"
#include "PerformanceMonitor.hpp"

// Infrastructure includes
#include "../../Utils/Logger.hpp"
#include "../../Utils/StringUtils.hpp"
#include "../../Utils/ProcessUtils.hpp"
#include "../../Utils/SystemUtils.hpp"

// Windows headers (order matters: winsock2 before iphlpapi for GetIfTable2)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// Standard library
#include <algorithm>
#include <queue>
#include <deque>
#include <format>
#include <cmath>
#include <unordered_set>
#include <filesystem>

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// LOG CATEGORY
// ============================================================================
static constexpr const wchar_t* LOG_CATEGORY = L"PerformanceMonitor";

// ============================================================================
// RAII HANDLE WRAPPER
// ============================================================================

/**
 * @brief RAII wrapper for Windows HANDLE to prevent leaks.
 * 
 * Guarantees cleanup on all code paths including exceptions.
 * Non-copyable, move-only semantics.
 */
class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : m_handle(handle) {}
    
    ~UniqueHandle() noexcept {
        Reset();
    }
    
    // Non-copyable
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    
    // Move-only
    UniqueHandle(UniqueHandle&& other) noexcept : m_handle(other.m_handle) {
        other.m_handle = nullptr;
    }
    
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }
    
    [[nodiscard]] HANDLE Get() const noexcept { return m_handle; }
    [[nodiscard]] explicit operator bool() const noexcept { 
        return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; 
    }
    
    void Reset(HANDLE handle = nullptr) noexcept {
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
        m_handle = handle;
    }
    
    HANDLE Release() noexcept {
        HANDLE h = m_handle;
        m_handle = nullptr;
        return h;
    }

private:
    HANDLE m_handle;
};

// ============================================================================
// THROTTLE LEVEL CONSTANTS
// ============================================================================

namespace ThrottleConstants {
    // Resource utilization thresholds for throttle level calculation
    // These values are tuned based on empirical testing to balance
    // AV responsiveness with system performance impact.
    
    /** Below this utilization, no throttling is needed */
    constexpr double kNoThrottleThreshold = 0.6;
    
    /** Light throttling zone: 60-80% utilization */
    constexpr double kLightThrottleThreshold = 0.8;
    
    /** Moderate throttling zone: 80-90% utilization */
    constexpr double kModerateThrottleThreshold = 0.9;
    
    // Throttle levels (0.0 = full speed, 1.0 = maximum throttle)
    constexpr double kNoThrottleLevel = 0.0;
    constexpr double kLightThrottleLevel = 0.3;
    constexpr double kModerateThrottleLevel = 0.6;
    constexpr double kHeavyThrottleLevel = 0.9;
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

namespace {

/**
 * @brief Calculate CPU usage percentage from process times.
 * 
 * Handles counter wraparound/reset on PID reuse by returning 0 if
 * current values are less than previous (indicates process restart).
 */
double CalculateCPUUsage(uint64_t prevKernelTime, uint64_t prevUserTime,
                         uint64_t currKernelTime, uint64_t currUserTime,
                         uint64_t elapsedMs, uint32_t processorCount) {
    if (elapsedMs == 0) return 0.0;
    
    // SECURITY FIX: Validate processorCount to prevent division by zero
    // std::thread::hardware_concurrency() can return 0 per C++ spec
    if (processorCount == 0) {
        processorCount = 1;
    }

    const uint64_t prevTotal = prevKernelTime + prevUserTime;
    const uint64_t currTotal = currKernelTime + currUserTime;
    
    // SECURITY FIX: Handle counter reset/wraparound on PID reuse
    // When a PID is reused, the new process has near-zero times but
    // our tracking has the old process's large values. Detect and handle.
    if (currTotal < prevTotal) {
        // Counter went backwards - likely PID reuse. Return 0 and let
        // the next sample establish a valid baseline.
        return 0.0;
    }
    
    const uint64_t deltaTime = currTotal - prevTotal;

    // Convert to milliseconds (times are in 100-nanosecond units)
    const double deltaMs = static_cast<double>(deltaTime) / 10000.0;

    // Calculate percentage
    double percent = (deltaMs / static_cast<double>(elapsedMs)) * 100.0;

    // Normalize by processor count
    return std::min(percent / static_cast<double>(processorCount), 100.0);
}

/**
 * @brief Convert ResourcePressure to string.
 */
std::wstring PressureToString(ResourcePressure pressure) {
    switch (pressure) {
        case ResourcePressure::Low: return L"Low";
        case ResourcePressure::Normal: return L"Normal";
        case ResourcePressure::Elevated: return L"Elevated";
        case ResourcePressure::High: return L"High";
        case ResourcePressure::Critical: return L"Critical";
        default: return L"Unknown";
    }
}

/**
 * @brief Convert anomaly type to string.
 */
std::wstring AnomalyTypeToString(PerformanceAnomalyType type) {
    switch (type) {
        case PerformanceAnomalyType::HighCPU: return L"High CPU Usage";
        case PerformanceAnomalyType::MemoryLeak: return L"Memory Leak";
        case PerformanceAnomalyType::HighIO: return L"High I/O Activity";
        case PerformanceAnomalyType::HandleLeak: return L"Handle Leak";
        case PerformanceAnomalyType::ThreadSpawn: return L"Rapid Thread Creation";
        case PerformanceAnomalyType::NetworkFlood: return L"Network Flood";
        case PerformanceAnomalyType::Cryptomining: return L"Cryptomining Activity";
        default: return L"Unknown";
    }
}

/**
 * @brief Calculate resource pressure from usage percentage.
 */
ResourcePressure CalculatePressure(double usagePercent) {
    if (usagePercent < 30.0) return ResourcePressure::Low;
    if (usagePercent < 60.0) return ResourcePressure::Normal;
    if (usagePercent < 80.0) return ResourcePressure::Elevated;
    if (usagePercent < 95.0) return ResourcePressure::High;
    return ResourcePressure::Critical;
}

/**
 * @brief Get idle time in milliseconds.
 *
 * LASTINPUTINFO::dwTime is a 32-bit DWORD tick count produced by the same
 * source as GetTickCount(); it wraps every ~49.7 days. The supported way
 * to compute idle is therefore in DWORD width so modular subtraction
 * handles wrap implicitly. The previous implementation compared a 64-bit
 * GetTickCount64() against a 32-bit dwTime, which yields enormous idle
 * values immediately after the first wrap of dwTime (any system uptime
 * beyond 49.7 days), and treated the unrelated "wrap" branch with a
 * mathematically wrong formula. This is corrected here.
 */
/**
 * @brief Sanitize a wide string for safe inclusion in log records.
 *
 * Strips CR/LF and other C0 control characters that an attacker-controlled
 * process name or path could embed to forge fake log lines (CWE-117).
 * Replaces such code units with a printable placeholder, bounds total
 * length to prevent log floods.
 */
std::wstring SanitizeForLog(const std::wstring& in) {
    constexpr size_t kMaxLen = 512;
    std::wstring out;
    out.reserve(std::min(in.size(), kMaxLen));
    for (wchar_t ch : in) {
        if (out.size() >= kMaxLen) {
            out.append(L"...");
            break;
        }
        // Strip C0 (0x00-0x1F), DEL (0x7F), and Unicode line/paragraph
        // separators which terminals/log viewers may treat as new lines.
        if (ch < 0x20 || ch == 0x7F || ch == 0x2028 || ch == 0x2029) {
            out.push_back(L'?');
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

uint64_t GetSystemIdleTime() {
    LASTINPUTINFO lii = {};
    lii.cbSize = sizeof(LASTINPUTINFO);

    if (!GetLastInputInfo(&lii)) {
        return 0;
    }

    // DWORD subtraction wraps modulo 2^32 which is exactly what we need
    // because both GetTickCount() and dwTime use the same modular tick
    // count. Cast back to 64-bit unsigned for the public return type.
    const DWORD currentTick = GetTickCount();
    const DWORD delta = currentTick - lii.dwTime;
    return static_cast<uint64_t>(delta);
}

} // anonymous namespace

// ============================================================================
// CONFIGURATION FACTORY METHODS
// ============================================================================

PerformanceMonitorConfig PerformanceMonitorConfig::CreateDefault() noexcept {
    PerformanceMonitorConfig config;
    // Defaults already set in struct definition
    return config;
}

PerformanceMonitorConfig PerformanceMonitorConfig::CreateLowImpact() noexcept {
    PerformanceMonitorConfig config;

    config.monitorProcesses = true;
    config.monitorSystem = true;
    config.detectAnomalies = true;
    config.autoThrottle = true;

    // Less frequent sampling
    config.samplingIntervalMs = 5000;  // 5 seconds
    config.historyDepthSeconds = 180;   // 3 minutes

    // Higher thresholds (less sensitive)
    config.thresholds.highCpuThreshold = 90.0;
    config.thresholds.highCpuDurationSec = 120;
    config.thresholds.memoryLeakGrowthMBPerMin = 20.0;

    config.cpuThrottleThreshold = 80.0;
    config.memoryThrottleThreshold = 90.0;

    return config;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

void PerformanceMonitorStatistics::Reset() noexcept {
    samplesTaken.store(0, std::memory_order_relaxed);
    processesMonitored.store(0, std::memory_order_relaxed);
    anomaliesDetected.store(0, std::memory_order_relaxed);
    throttleEngagements.store(0, std::memory_order_relaxed);
    highCpuDetections.store(0, std::memory_order_relaxed);
    memoryLeakDetections.store(0, std::memory_order_relaxed);
    miningDetections.store(0, std::memory_order_relaxed);
}

// ============================================================================
// CALLBACK MANAGER
// ============================================================================

class CallbackManager {
public:
    uint64_t RegisterResourceUsage(ResourceUsageCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_resourceCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterAnomaly(AnomalyCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_anomalyCallbacks[id] = std::move(callback);
        return id;
    }

    uint64_t RegisterThrottle(ThrottleCallback callback) {
        std::unique_lock lock(m_mutex);
        const uint64_t id = m_nextId++;
        m_throttleCallbacks[id] = std::move(callback);
        return id;
    }

    bool UnregisterResourceUsage(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_resourceCallbacks.erase(id) > 0;
    }

    bool UnregisterAnomaly(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_anomalyCallbacks.erase(id) > 0;
    }

    bool UnregisterThrottle(uint64_t id) {
        std::unique_lock lock(m_mutex);
        return m_throttleCallbacks.erase(id) > 0;
    }

    /**
     * @brief Invokes resource usage callbacks with minimal lock hold time.
     * 
     * PERFORMANCE FIX: Copies callbacks under lock, then invokes outside lock.
     * This prevents slow callbacks from blocking registration/unregistration.
     */
    void InvokeResourceUsage(const SystemResourceUsage& usage) {
        // Copy callbacks under lock to minimize lock hold time
        std::vector<ResourceUsageCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_resourceCallbacks.size());
            for (const auto& [id, callback] : m_resourceCallbacks) {
                callbacksCopy.push_back(callback);
            }
        }
        
        // Invoke outside lock - slow callbacks won't block registration
        for (const auto& callback : callbacksCopy) {
            try {
                callback(usage);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ResourceUsageCallback exception: %hs", e.what());
            }
        }
    }

    /**
     * @brief Invokes anomaly callbacks with minimal lock hold time.
     */
    void InvokeAnomaly(const PerformanceAnomaly& anomaly) {
        std::vector<AnomalyCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_anomalyCallbacks.size());
            for (const auto& [id, callback] : m_anomalyCallbacks) {
                callbacksCopy.push_back(callback);
            }
        }
        
        for (const auto& callback : callbacksCopy) {
            try {
                callback(anomaly);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"AnomalyCallback exception: %hs", e.what());
            }
        }
    }

    /**
     * @brief Invokes throttle callbacks with minimal lock hold time.
     */
    void InvokeThrottle(bool shouldThrottle, double currentLoad) {
        std::vector<ThrottleCallback> callbacksCopy;
        {
            std::shared_lock lock(m_mutex);
            callbacksCopy.reserve(m_throttleCallbacks.size());
            for (const auto& [id, callback] : m_throttleCallbacks) {
                callbacksCopy.push_back(callback);
            }
        }
        
        for (const auto& callback : callbacksCopy) {
            try {
                callback(shouldThrottle, currentLoad);
            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"ThrottleCallback exception: %hs", e.what());
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint64_t m_nextId{ 1 };
    std::unordered_map<uint64_t, ResourceUsageCallback> m_resourceCallbacks;
    std::unordered_map<uint64_t, AnomalyCallback> m_anomalyCallbacks;
    std::unordered_map<uint64_t, ThrottleCallback> m_throttleCallbacks;
};

// ============================================================================
// HISTORY MANAGER
// ============================================================================

class HistoryManager {
public:
    void AddSystemSample(const SystemResourceUsage& usage) {
        std::unique_lock lock(m_mutex);

        m_systemHistory.push_back(usage);

        // Cap history size based on configured maximum
        if (m_systemHistory.size() > m_maxSamples) {
            m_systemHistory.pop_front();
        }
    }

    void AddProcessSample(uint32_t pid, const ProcessResourceUsage& usage) {
        std::unique_lock lock(m_mutex);

        auto& history = m_processHistory[pid];
        history.push_back(usage);

        // Limit per-process history
        if (history.size() > m_maxSamples) {
            history.pop_front();
        }
    }

    std::vector<SystemResourceUsage> GetSystemHistory(std::chrono::seconds duration) const {
        std::shared_lock lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const auto cutoff = now - duration;

        std::vector<SystemResourceUsage> result;
        for (const auto& sample : m_systemHistory) {
            if (sample.sampleTime >= cutoff) {
                result.push_back(sample);
            }
        }

        return result;
    }

    std::vector<ProcessResourceUsage> GetProcessHistory(uint32_t pid,
                                                        std::chrono::seconds duration) const {
        std::shared_lock lock(m_mutex);

        auto it = m_processHistory.find(pid);
        if (it == m_processHistory.end()) {
            return {};
        }

        const auto now = std::chrono::steady_clock::now();
        const auto cutoff = now - duration;

        std::vector<ProcessResourceUsage> result;
        for (const auto& sample : it->second) {
            if (sample.sampleTime >= cutoff) {
                result.push_back(sample);
            }
        }

        return result;
    }

    void SetMaxHistorySeconds(uint32_t seconds, uint32_t samplingIntervalMs = 1000) {
        std::unique_lock lock(m_mutex);
        m_maxHistorySeconds = seconds;
        // Calculate max samples: seconds / (intervalMs / 1000), capped at reasonable limit
        const uint32_t intervalSec = std::max(samplingIntervalMs / 1000u, 1u);
        m_maxSamples = static_cast<size_t>(std::min(seconds / intervalSec, 86400u)); // Cap at 24h
    }

    void Clear() {
        std::unique_lock lock(m_mutex);
        m_systemHistory.clear();
        m_processHistory.clear();
    }

    /**
     * @brief Removes process history entries for PIDs with no recent samples.
     *
     * Prevents unbounded memory growth as processes start and terminate.
     * Entries with no samples in the last 5 minutes are considered stale.
     */
    void CleanStaleProcessHistory() {
        std::unique_lock lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const auto staleThreshold = std::chrono::minutes(5);

        for (auto it = m_processHistory.begin(); it != m_processHistory.end();) {
            if (it->second.empty() ||
                (now - it->second.back().sampleTime > staleThreshold)) {
                it = m_processHistory.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    mutable std::shared_mutex m_mutex;
    uint32_t m_maxHistorySeconds{ 300 };
    size_t m_maxSamples{ 300 };
    std::deque<SystemResourceUsage> m_systemHistory;
    std::unordered_map<uint32_t, std::deque<ProcessResourceUsage>> m_processHistory;
};

// ============================================================================
// ANOMALY DETECTOR
// ============================================================================

class AnomalyDetector {
public:
    /**
     * @brief Constructs the detector with configurable thresholds and a
     *        sampling interval used to size the per-process sample window.
     *
     * The sample deque must span the longest temporal threshold (memory
     * leak window, mining sustain window, sustained high-CPU window),
     * otherwise the relevant heuristics never trigger. The previous fixed
     * 60-sample cap silently disabled memory-leak detection at the default
     * 1 s sampling interval (window <= 60 s, threshold = 10 min).
     */
    AnomalyDetector(const ResourceThresholds& thresholds,
                    uint32_t samplingIntervalMs)
        : m_thresholds(thresholds) {
        const uint32_t intervalSec = std::max<uint32_t>(1U, samplingIntervalMs / 1000U);

        const uint64_t memLeakSec = static_cast<uint64_t>(thresholds.memoryLeakDurationMin) * 60ULL;
        const uint64_t miningSec  = static_cast<uint64_t>(thresholds.miningPatternDurationSec);
        const uint64_t cpuSec     = static_cast<uint64_t>(thresholds.highCpuDurationSec);

        const uint64_t longestWindowSec = std::max({memLeakSec, miningSec, cpuSec});

        // Add 10% headroom plus a minimum of 60 samples to keep short-window
        // heuristics stable when sampling is slow. Cap at 24 h equivalent to
        // prevent runaway memory growth on misconfiguration.
        constexpr uint64_t kMinSamples  = 60ULL;
        constexpr uint64_t kMaxSamples  = 24ULL * 60ULL * 60ULL;  // 1 sample/sec for 24h
        const uint64_t windowSamples    = (longestWindowSec / intervalSec) + (longestWindowSec / (intervalSec * 10U)) + 1ULL;
        const uint64_t bounded          = std::clamp<uint64_t>(windowSamples, kMinSamples, kMaxSamples);

        m_maxSamples = static_cast<size_t>(bounded);
    }

    void Update(const ProcessResourceUsage& usage) {
        std::unique_lock lock(m_mutex);

        const uint32_t pid = usage.processId;
        auto& tracker = m_processTrackers[pid];

        // Update tracking data
        tracker.lastUpdate = std::chrono::steady_clock::now();
        tracker.samples.push_back(usage);

        // Limit sample history to the configured window. Sized in ctor to
        // span the longest temporal threshold; bounded to keep memory growth
        // O(per-PID).
        while (tracker.samples.size() > m_maxSamples) {
            tracker.samples.pop_front();
        }

        // Check for anomalies
        CheckHighCPU(pid, usage, tracker);
        CheckMemoryLeak(pid, usage, tracker);
        CheckHandleLeak(pid, usage, tracker);
        CheckCryptomining(pid, usage, tracker);
        CheckIOFlood(pid, usage, tracker);
        CheckNetworkFlood(pid, usage, tracker);
    }

    /**
     * @brief Gets anomalies that have NOT yet been reported to callbacks.
     * 
     * CALLBACK STORM FIX: Only returns anomalies that haven't been sent to
     * callbacks yet. Marks them as reported after retrieval. This prevents
     * the same anomaly from triggering callbacks on every monitoring iteration.
     * 
     * @return Vector of newly detected anomalies not yet reported
     */
    std::vector<PerformanceAnomaly> GetNewAnomalies() {
        std::unique_lock lock(m_mutex);

        std::vector<PerformanceAnomaly> result;
        for (auto& [pid, anomalies] : m_activeAnomalies) {
            for (auto& anomaly : anomalies) {
                // Create unique key for this anomaly
                AnomalyKey key{ pid, anomaly.type };
                
                // Only return if not already reported
                if (m_reportedAnomalies.find(key) == m_reportedAnomalies.end()) {
                    result.push_back(anomaly);
                    m_reportedAnomalies.insert(key);
                }
            }
        }

        return result;
    }

    /**
     * @brief Gets all active anomalies (for query purposes, not callbacks).
     */
    std::vector<PerformanceAnomaly> GetActiveAnomalies() const {
        std::shared_lock lock(m_mutex);

        std::vector<PerformanceAnomaly> result;
        for (const auto& [pid, anomalies] : m_activeAnomalies) {
            for (const auto& anomaly : anomalies) {
                result.push_back(anomaly);
            }
        }

        return result;
    }

    std::vector<PerformanceAnomaly> GetProcessAnomalies(uint32_t pid) const {
        std::shared_lock lock(m_mutex);

        auto it = m_activeAnomalies.find(pid);
        if (it != m_activeAnomalies.end()) {
            return it->second;
        }

        return {};
    }

    std::vector<uint32_t> GetPotentialMiners() const {
        std::shared_lock lock(m_mutex);

        std::vector<uint32_t> miners;
        for (const auto& [pid, anomalies] : m_activeAnomalies) {
            for (const auto& anomaly : anomalies) {
                if (anomaly.type == PerformanceAnomalyType::Cryptomining) {
                    miners.push_back(pid);
                    break;
                }
            }
        }

        return miners;
    }

    void ClearStaleTracking() {
        std::unique_lock lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const auto staleThreshold = std::chrono::seconds(60);

        // Remove stale process trackers
        for (auto it = m_processTrackers.begin(); it != m_processTrackers.end();) {
            if (now - it->second.lastUpdate > staleThreshold) {
                // Clear reported anomalies for this PID so they can be re-reported
                // if the process restarts and exhibits the same behavior
                const uint32_t pid = it->first;
                for (auto rit = m_reportedAnomalies.begin(); rit != m_reportedAnomalies.end();) {
                    if (rit->pid == pid) {
                        rit = m_reportedAnomalies.erase(rit);
                    } else {
                        ++rit;
                    }
                }
                m_activeAnomalies.erase(it->first);
                it = m_processTrackers.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    struct ProcessTracker {
        std::chrono::steady_clock::time_point lastUpdate;
        std::deque<ProcessResourceUsage> samples;
        std::chrono::steady_clock::time_point highCpuStart;
        uint64_t baselineMemory{ 0 };
        uint32_t baselineHandles{ 0 };
    };

    /**
     * @brief Key for tracking which anomalies have been reported to callbacks.
     */
    struct AnomalyKey {
        uint32_t pid;
        PerformanceAnomalyType type;
        
        bool operator==(const AnomalyKey& other) const {
            return pid == other.pid && type == other.type;
        }
    };
    
    struct AnomalyKeyHash {
        size_t operator()(const AnomalyKey& key) const {
            return std::hash<uint32_t>{}(key.pid) ^ 
                   (std::hash<uint8_t>{}(static_cast<uint8_t>(key.type)) << 8);
        }
    };

    void CheckHighCPU(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        if (usage.cpuPercent >= m_thresholds.highCpuThreshold) {
            if (tracker.highCpuStart == std::chrono::steady_clock::time_point{}) {
                tracker.highCpuStart = std::chrono::steady_clock::now();
            } else {
                const auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - tracker.highCpuStart
                );

                if (duration.count() >= m_thresholds.highCpuDurationSec) {
                    AddAnomaly(pid, PerformanceAnomalyType::HighCPU, usage.processName,
                              std::format(L"Sustained high CPU usage: {:.1f}%", usage.cpuPercent),
                              usage.cpuPercent, m_thresholds.highCpuThreshold, 70);
                }
            }
        } else {
            tracker.highCpuStart = std::chrono::steady_clock::time_point{};
        }
    }

    void CheckMemoryLeak(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        if (tracker.samples.size() < 10) {
            tracker.baselineMemory = usage.workingSetBytes;
            return;
        }

        // Calculate memory growth rate
        const auto& oldSample = tracker.samples.front();
        const auto timeDelta = std::chrono::duration_cast<std::chrono::minutes>(
            usage.sampleTime - oldSample.sampleTime
        );

        if (timeDelta.count() > 0) {
            const int64_t memoryGrowth = static_cast<int64_t>(usage.workingSetBytes) -
                                        static_cast<int64_t>(oldSample.workingSetBytes);
            const double growthMBPerMin = (static_cast<double>(memoryGrowth) / (1024.0 * 1024.0)) /
                                         static_cast<double>(timeDelta.count());

            if (growthMBPerMin >= m_thresholds.memoryLeakGrowthMBPerMin &&
                static_cast<uint32_t>(timeDelta.count()) >= m_thresholds.memoryLeakDurationMin) {
                AddAnomaly(pid, PerformanceAnomalyType::MemoryLeak, usage.processName,
                          std::format(L"Memory leak detected: {:.2f} MB/min growth", growthMBPerMin),
                          growthMBPerMin, m_thresholds.memoryLeakGrowthMBPerMin, 80);
            }
        }
    }

    void CheckHandleLeak(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        if (tracker.samples.size() < 10) {
            tracker.baselineHandles = usage.handleCount;
            return;
        }

        const auto& oldSample = tracker.samples.front();
        const int32_t handleGrowth = static_cast<int32_t>(usage.handleCount) -
                                    static_cast<int32_t>(oldSample.handleCount);

        if (handleGrowth >= static_cast<int32_t>(m_thresholds.handleLeakThreshold)) {
            AddAnomaly(pid, PerformanceAnomalyType::HandleLeak, usage.processName,
                      std::format(L"Handle leak detected: {} new handles", handleGrowth),
                      static_cast<double>(handleGrowth), m_thresholds.handleLeakThreshold, 60);
        }
    }

    void CheckCryptomining(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        // Mining detection: sustained very high CPU (>90%) for extended period
        if (usage.cpuPercent >= m_thresholds.miningCpuThreshold &&
            tracker.samples.size() >= 10) {

            // Check if CPU has been consistently high
            uint32_t highCpuCount = 0;
            for (const auto& sample : tracker.samples) {
                if (sample.cpuPercent >= m_thresholds.miningCpuThreshold * 0.95) {
                    highCpuCount++;
                }
            }

            const double consistencyRatio = static_cast<double>(highCpuCount) /
                                           static_cast<double>(tracker.samples.size());

            if (consistencyRatio >= 0.9) {  // 90% of samples are high
                AddAnomaly(pid, PerformanceAnomalyType::Cryptomining, usage.processName,
                          std::format(L"Potential cryptomining: {:.1f}% CPU sustained", usage.cpuPercent),
                          usage.cpuPercent, m_thresholds.miningCpuThreshold, 95);
            }
        }
    }

    /**
     * @brief Detect I/O flood patterns (ransomware, wipers).
     *
     * Ransomware encrypts files at maximum I/O bandwidth. We detect
     * sustained high write rates that exceed the configured threshold.
     * Combines write rate with write operation count to reduce false
     * positives from legitimate bulk operations (e.g., database backup).
     */
    void CheckIOFlood(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        const double totalIOBytesPerSec = usage.ioReadBytesPerSec + usage.ioWriteBytesPerSec;
        if (totalIOBytesPerSec < m_thresholds.highIOBytesPerSec) {
            return;
        }

        if (tracker.samples.size() < 5) return;

        // Check for sustained high I/O across recent samples
        uint32_t highIOCount = 0;
        for (const auto& sample : tracker.samples) {
            const double sampleIO = sample.ioReadBytesPerSec + sample.ioWriteBytesPerSec;
            if (sampleIO >= m_thresholds.highIOBytesPerSec * 0.8) {
                highIOCount++;
            }
        }

        const double consistencyRatio = static_cast<double>(highIOCount) /
                                       static_cast<double>(tracker.samples.size());

        // Require sustained high I/O (>70% of samples) to avoid false positives
        if (consistencyRatio >= 0.7) {
            // Ransomware heuristic: high write rate + many small write ops
            const bool ransomwarePattern =
                usage.ioWriteBytesPerSec > m_thresholds.highIOBytesPerSec * 0.6 &&
                usage.ioWriteOps > 100;

            const uint8_t severity = ransomwarePattern ? 90 : 70;

            AddAnomaly(pid, PerformanceAnomalyType::HighIO, usage.processName,
                      std::format(L"I/O flood: {:.1f} MB/s (write: {:.1f} MB/s, {} ops)",
                                  totalIOBytesPerSec / (1024.0 * 1024.0),
                                  usage.ioWriteBytesPerSec / (1024.0 * 1024.0),
                                  usage.ioWriteOps),
                      totalIOBytesPerSec, m_thresholds.highIOBytesPerSec, severity);
        }
    }

    /**
     * @brief Detect network flood patterns (data exfiltration, C2 beaconing).
     *
     * Detects sustained high outbound network traffic that may indicate
     * data exfiltration by APTs or C2 communication. Threshold-based
     * with consistency check to avoid false positives from legitimate
     * uploads/streaming.
     */
    void CheckNetworkFlood(uint32_t pid, const ProcessResourceUsage& usage, ProcessTracker& tracker) {
        // Network flood: sustained high send rate
        // Threshold: 10 MB/s outbound sustained
        constexpr double kNetworkFloodThreshold = 10.0 * 1024.0 * 1024.0;

        if (usage.networkSendBytes == 0 && usage.networkRecvBytes == 0) {
            return;  // No network data available for this process
        }

        if (tracker.samples.size() < 5) return;

        // Calculate send rate from deltas
        const auto& prevSample = tracker.samples[tracker.samples.size() - 2];
        const auto timeDelta = std::chrono::duration_cast<std::chrono::seconds>(
            usage.sampleTime - prevSample.sampleTime
        );

        if (timeDelta.count() <= 0) return;

        const double sendRate = (usage.networkSendBytes > prevSample.networkSendBytes)
            ? static_cast<double>(usage.networkSendBytes - prevSample.networkSendBytes) /
              static_cast<double>(timeDelta.count())
            : 0.0;

        if (sendRate < kNetworkFloodThreshold) return;

        // Check consistency across samples
        uint32_t highNetCount = 0;
        for (size_t i = 1; i < tracker.samples.size(); ++i) {
            const auto& prev = tracker.samples[i - 1];
            const auto& curr = tracker.samples[i];
            const auto dt = std::chrono::duration_cast<std::chrono::seconds>(
                curr.sampleTime - prev.sampleTime
            );
            if (dt.count() > 0 && curr.networkSendBytes > prev.networkSendBytes) {
                const double rate = static_cast<double>(curr.networkSendBytes - prev.networkSendBytes) /
                                   static_cast<double>(dt.count());
                if (rate >= kNetworkFloodThreshold * 0.7) {
                    highNetCount++;
                }
            }
        }

        const double consistency = static_cast<double>(highNetCount) /
                                  static_cast<double>(tracker.samples.size() - 1);

        if (consistency >= 0.6) {
            AddAnomaly(pid, PerformanceAnomalyType::NetworkFlood, usage.processName,
                      std::format(L"Network flood: {:.1f} MB/s outbound sustained",
                                  sendRate / (1024.0 * 1024.0)),
                      sendRate, kNetworkFloodThreshold, 85);
        }
    }

    void AddAnomaly(uint32_t pid, PerformanceAnomalyType type, const std::wstring& processName,
                   const std::wstring& description, double value, double threshold, uint8_t severity) {
        // Check if already in active anomalies list
        auto& anomalies = m_activeAnomalies[pid];
        for (const auto& existing : anomalies) {
            if (existing.type == type) {
                return;  // Already in list
            }
        }

        PerformanceAnomaly anomaly;
        anomaly.type = type;
        anomaly.processId = pid;
        anomaly.processName = processName;
        anomaly.description = description;
        anomaly.value = value;
        anomaly.threshold = threshold;
        anomaly.detectionTime = std::chrono::system_clock::now();
        anomaly.severity = severity;

        anomalies.push_back(anomaly);

        SS_LOG_WARN(LOG_CATEGORY, L"Performance anomaly detected - PID %u: %ls",
                    pid, SanitizeForLog(description).c_str());
    }

    mutable std::shared_mutex m_mutex;
    ResourceThresholds m_thresholds;
    size_t m_maxSamples{ 60 };
    std::unordered_map<uint32_t, ProcessTracker> m_processTrackers;
    std::unordered_map<uint32_t, std::vector<PerformanceAnomaly>> m_activeAnomalies;
    
    // Track which anomalies have been reported to callbacks to prevent storm
    std::unordered_set<AnomalyKey, AnomalyKeyHash> m_reportedAnomalies;
};

// ============================================================================
// PROCESS TRACKER
// ============================================================================

class ProcessResourceTracker {
public:
    /**
     * @brief Constructor with processor count validation.
     *
     * SECURITY FIX: std::thread::hardware_concurrency() can return 0
     * per C++ spec if the value is "not computable or well defined".
     * We default to 1 to prevent division by zero in CPU calculations.
     */
    ProcessResourceTracker() {
        m_processorCount = std::thread::hardware_concurrency();
        if (m_processorCount == 0) {
            SS_LOG_WARN(LOG_CATEGORY, L"ProcessResourceTracker: hardware_concurrency returned 0, defaulting to 1");
            m_processorCount = 1;
        }
        m_selfPid = GetCurrentProcessId();
    }

    /**
     * @brief Gets resource usage for a specific process (thread-safe).
     */
    ProcessResourceUsage GetUsage(uint32_t pid) {
        std::unique_lock lock(m_mutex);
        return GetUsageUnlocked(pid);
    }

    /**
     * @brief Gets resource usage for all processes (thread-safe).
     */
    std::vector<ProcessResourceUsage> GetAllProcessUsage() {
        std::unique_lock lock(m_mutex);

        std::vector<ProcessResourceUsage> result;

        UniqueHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) {
            return result;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot.Get(), &pe32)) {
            do {
                if (pe32.th32ProcessID > 4) {  // Skip System/Idle
                    auto usage = GetUsageUnlocked(pe32.th32ProcessID);
                    if (!usage.processName.empty()) {
                        result.push_back(std::move(usage));
                    }
                }
            } while (Process32NextW(hSnapshot.Get(), &pe32));
        }

        // Periodically clean stale entries from m_previousTimes
        CleanStalePreviousTimes();

        return result;
    }

    /**
     * @brief Gets the EDR's own resource usage for self-monitoring.
     */
    SelfResourceUsage GetSelfUsage() {
        std::unique_lock lock(m_mutex);

        SelfResourceUsage self;
        self.sampleTime = std::chrono::steady_clock::now();

        auto procUsage = GetUsageUnlocked(m_selfPid);
        self.cpuPercent = procUsage.cpuPercent;
        self.workingSetBytes = procUsage.workingSetBytes;
        self.privateBytes = procUsage.privateBytes;
        self.handleCount = procUsage.handleCount;
        self.threadCount = procUsage.threadCount;

        return self;
    }

private:
    /**
     * @brief Gets resource usage without locking (caller must hold m_mutex).
     *
     * CRITICAL FIX: Previous version stored m_previousTimes[pid] BEFORE
     * I/O counters were read, causing I/O rate calculations to always
     * compare against the current sample (elapsed ≈ 0) → rates always 0.
     * Now stores AFTER all metrics are collected.
     */
    ProcessResourceUsage GetUsageUnlocked(uint32_t pid) {
        ProcessResourceUsage usage;
        usage.processId = pid;
        usage.sampleTime = std::chrono::steady_clock::now();

        // Look up previous sample for delta calculations BEFORE overwriting
        const ProcessResourceUsage* prevUsage = nullptr;
        auto prevIt = m_previousTimes.find(pid);
        if (prevIt != m_previousTimes.end()) {
            prevUsage = &prevIt->second;
        }

        UniqueHandle hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!hProcess) {
            return usage;
        }

        try {
            // Get process name
            wchar_t imagePath[MAX_PATH];
            DWORD size = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess.Get(), 0, imagePath, &size)) {
                std::filesystem::path path(imagePath);
                usage.processName = path.filename().wstring();
                usage.imagePath = imagePath;
            }

            // Get CPU times
            FILETIME createTime, exitTime, kernelTime, userTime;
            if (GetProcessTimes(hProcess.Get(), &createTime, &exitTime, &kernelTime, &userTime)) {
                usage.kernelTimeMs = FileTimeToMs(kernelTime);
                usage.userTimeMs = FileTimeToMs(userTime);

                // Calculate CPU percentage from delta against previous sample
                if (prevUsage) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        usage.sampleTime - prevUsage->sampleTime
                    );

                    usage.cpuPercent = CalculateCPUUsage(
                        prevUsage->kernelTimeMs,
                        prevUsage->userTimeMs,
                        usage.kernelTimeMs,
                        usage.userTimeMs,
                        elapsed.count(),
                        m_processorCount
                    );
                }
                // DO NOT store m_previousTimes here — must wait until all metrics collected
            }

            // Get memory info
            PROCESS_MEMORY_COUNTERS_EX pmc = {};
            pmc.cb = sizeof(pmc);
            if (GetProcessMemoryInfo(hProcess.Get(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
                usage.workingSetBytes = pmc.WorkingSetSize;
                usage.privateBytes = pmc.PrivateUsage;
                usage.peakWorkingSetBytes = pmc.PeakWorkingSetSize;
                usage.pagefileUsageBytes = pmc.PagefileUsage;
            }

            // Get I/O counters
            IO_COUNTERS ioCounters = {};
            if (GetProcessIoCounters(hProcess.Get(), &ioCounters)) {
                usage.ioReadBytes = ioCounters.ReadTransferCount;
                usage.ioWriteBytes = ioCounters.WriteTransferCount;
                usage.ioOtherBytes = ioCounters.OtherTransferCount;
                usage.ioReadOps = ioCounters.ReadOperationCount;
                usage.ioWriteOps = ioCounters.WriteOperationCount;

                // Calculate I/O rates using PREVIOUS sample (not the one we just stored)
                if (prevUsage) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        usage.sampleTime - prevUsage->sampleTime
                    );

                    if (elapsed.count() > 0) {
                        const double elapsedSec = static_cast<double>(elapsed.count()) / 1000.0;

                        if (usage.ioReadBytes >= prevUsage->ioReadBytes) {
                            usage.ioReadBytesPerSec = static_cast<double>(
                                usage.ioReadBytes - prevUsage->ioReadBytes) / elapsedSec;
                        } else {
                            usage.ioReadBytesPerSec = 0.0;
                        }

                        if (usage.ioWriteBytes >= prevUsage->ioWriteBytes) {
                            usage.ioWriteBytesPerSec = static_cast<double>(
                                usage.ioWriteBytes - prevUsage->ioWriteBytes) / elapsedSec;
                        } else {
                            usage.ioWriteBytesPerSec = 0.0;
                        }
                    }
                }
            }

            // Get handle count
            DWORD handleCount = 0;
            if (GetProcessHandleCount(hProcess.Get(), &handleCount)) {
                usage.handleCount = handleCount;
            }

            // Get thread count (requires enumeration)
            usage.threadCount = GetProcessThreadCount(pid);

            // Get GDI/USER object counts
            usage.gdiObjectCount = GetGuiResources(hProcess.Get(), GR_GDIOBJECTS);
            usage.userObjectCount = GetGuiResources(hProcess.Get(), GR_USEROBJECTS);

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"ProcessResourceTracker::GetUsage exception for PID %u: %hs", pid, e.what());
        }

        // Store AFTER all metrics collected for correct delta calculations next time
        m_previousTimes[pid] = usage;
        return usage;
    }

    /**
     * @brief Removes stale entries from m_previousTimes to prevent unbounded growth.
     *
     * Called periodically during GetAllProcessUsage. Entries older than
     * 2 minutes are removed (the process likely terminated and the PID
     * may be reused with stale baseline data).
     */
    void CleanStalePreviousTimes() {
        const auto now = std::chrono::steady_clock::now();
        const auto staleThreshold = std::chrono::minutes(2);

        // Only clean every 30 seconds
        if (now - m_lastCleanupTime < std::chrono::seconds(30)) return;
        m_lastCleanupTime = now;

        for (auto it = m_previousTimes.begin(); it != m_previousTimes.end();) {
            if (now - it->second.sampleTime > staleThreshold) {
                it = m_previousTimes.erase(it);
            } else {
                ++it;
            }
        }
    }

    uint64_t FileTimeToMs(const FILETIME& ft) const {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart / 10000;  // Convert 100-nanosecond units to milliseconds
    }

    uint32_t GetProcessThreadCount(uint32_t pid) const {
        uint32_t count = 0;

        UniqueHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
        if (!hSnapshot) {
            return count;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hSnapshot.Get(), &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    count++;
                }
            } while (Thread32Next(hSnapshot.Get(), &te32));
        }

        return count;
    }

    mutable std::shared_mutex m_mutex;
    std::unordered_map<uint32_t, ProcessResourceUsage> m_previousTimes;
    uint32_t m_processorCount{ 1 };
    uint32_t m_selfPid{ 0 };
    std::chrono::steady_clock::time_point m_lastCleanupTime;
};

// ============================================================================
// SYSTEM TRACKER
// ============================================================================

class SystemResourceTracker {
public:
    SystemResourceTracker() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_processorCount = sysInfo.dwNumberOfProcessors;

        // Initialize previous system times
        UpdateSystemTimes();
        InitializePDHCounters();
        InitializeNetworkBaseline();
    }

    ~SystemResourceTracker() {
        CleanupPDHCounters();
    }

    // Non-copyable
    SystemResourceTracker(const SystemResourceTracker&) = delete;
    SystemResourceTracker& operator=(const SystemResourceTracker&) = delete;

    SystemResourceUsage GetUsage() {
        std::unique_lock lock(m_mutex);

        SystemResourceUsage usage;
        usage.sampleTime = std::chrono::steady_clock::now();

        // Update CPU usage
        UpdateCPUUsage(usage);

        // Get memory info
        UpdateMemoryInfo(usage);

        // Get process counts
        UpdateProcessCounts(usage);

        // Update disk I/O via PDH
        UpdateDiskMetrics(usage);

        // Update network metrics via interface table
        UpdateNetworkMetrics(usage);

        // Calculate pressure levels
        usage.cpuPressure = CalculatePressure(usage.totalCpuPercent);
        usage.memoryPressure = CalculatePressure(usage.memoryUsagePercent);
        usage.ioPressure = CalculatePressure(usage.diskTimePercent);

        // Get idle state
        UpdateIdleState(usage);

        return usage;
    }

private:
    // ====================================================================
    // PDH COUNTER INITIALIZATION
    // ====================================================================

    /**
     * @brief Initializes PDH counters for disk I/O metrics.
     *
     * Uses PdhAddEnglishCounterW which accepts English counter names
     * regardless of OS locale, ensuring portability across all Windows
     * language packs. Gracefully degrades if PDH service is unavailable.
     */
    void InitializePDHCounters() {
        PDH_STATUS status = PdhOpenQueryW(nullptr, 0, &m_pdhQuery);
        if (status != ERROR_SUCCESS) {
            SS_LOG_WARN(LOG_CATEGORY, L"PDH query open failed: 0x%08X - disk metrics unavailable", status);
            m_pdhQuery = nullptr;
            return;
        }

        // Disk counters (English names, locale-independent)
        auto addCounter = [this](const wchar_t* path, PDH_HCOUNTER& counter) -> bool {
            PDH_STATUS s = PdhAddEnglishCounterW(m_pdhQuery, path, 0, &counter);
            if (s != ERROR_SUCCESS) {
                SS_LOG_WARN(LOG_CATEGORY, L"PDH counter add failed for '%ls': 0x%08X", path, s);
                counter = nullptr;
                return false;
            }
            return true;
        };

        addCounter(L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec", m_diskReadCounter);
        addCounter(L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec", m_diskWriteCounter);
        addCounter(L"\\PhysicalDisk(_Total)\\Current Disk Queue Length", m_diskQueueCounter);
        addCounter(L"\\PhysicalDisk(_Total)\\% Disk Time", m_diskTimeCounter);

        // Collect initial sample (PDH rate counters require two samples)
        PdhCollectQueryData(m_pdhQuery);

        SS_LOG_INFO(LOG_CATEGORY, L"PDH disk I/O counters initialized");
    }

    void CleanupPDHCounters() {
        if (m_pdhQuery) {
            PdhCloseQuery(m_pdhQuery);
            m_pdhQuery = nullptr;
        }
        m_diskReadCounter = nullptr;
        m_diskWriteCounter = nullptr;
        m_diskQueueCounter = nullptr;
        m_diskTimeCounter = nullptr;
    }

    // ====================================================================
    // NETWORK BASELINE
    // ====================================================================

    void InitializeNetworkBaseline() {
        MIB_IF_TABLE2* rawTable = nullptr;
        if (GetIfTable2(&rawTable) != NO_ERROR || !rawTable) {
            SS_LOG_WARN(LOG_CATEGORY, L"GetIfTable2 failed - network metrics unavailable");
            return;
        }

        uint64_t totalSend = 0, totalRecv = 0;
        for (ULONG i = 0; i < rawTable->NumEntries; i++) {
            const auto& row = rawTable->Table[i];
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
                row.Type == IF_TYPE_TUNNEL ||
                row.OperStatus != IfOperStatusUp) {
                continue;
            }
            totalSend += row.OutOctets;
            totalRecv += row.InOctets;
        }
        FreeMibTable(rawTable);

        m_prevNetworkSendBytes = totalSend;
        m_prevNetworkRecvBytes = totalRecv;
        m_prevNetworkSampleTime = std::chrono::steady_clock::now();
        m_networkInitialized = true;

        SS_LOG_INFO(LOG_CATEGORY, L"Network baseline initialized");
    }

    // ====================================================================
    // CPU METRICS
    // ====================================================================

    void UpdateSystemTimes() {
        GetSystemTimes(&m_prevIdleTime, &m_prevKernelTime, &m_prevUserTime);
        m_prevSampleTime = std::chrono::steady_clock::now();
    }

    void UpdateCPUUsage(SystemResourceUsage& usage) {
        FILETIME idleTime, kernelTime, userTime;
        if (!GetSystemTimes(&idleTime, &kernelTime, &userTime)) {
            return;
        }

        const uint64_t prevIdle = FileTimeToUint64(m_prevIdleTime);
        const uint64_t prevKernel = FileTimeToUint64(m_prevKernelTime);
        const uint64_t prevUser = FileTimeToUint64(m_prevUserTime);

        const uint64_t currIdle = FileTimeToUint64(idleTime);
        const uint64_t currKernel = FileTimeToUint64(kernelTime);
        const uint64_t currUser = FileTimeToUint64(userTime);

        const uint64_t idleDelta = currIdle - prevIdle;
        const uint64_t kernelDelta = currKernel - prevKernel;
        const uint64_t userDelta = currUser - prevUser;

        // kernelTime includes idleTime
        const uint64_t systemDelta = kernelDelta + userDelta - idleDelta;
        const uint64_t totalDelta = kernelDelta + userDelta;

        if (totalDelta > 0) {
            // SECURITY FIX: kernelDelta nominally includes idleDelta but a
            // racing reader between GetSystemTimes() snapshots can rarely
            // observe kernelDelta < idleDelta. Saturate to zero to prevent
            // unsigned underflow producing a huge bogus kernel CPU percent.
            const uint64_t kernelBusyDelta =
                (kernelDelta >= idleDelta) ? (kernelDelta - idleDelta) : 0;

            usage.totalCpuPercent = (static_cast<double>(systemDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.idleCpuPercent = (static_cast<double>(idleDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.kernelCpuPercent = (static_cast<double>(kernelBusyDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.userCpuPercent = (static_cast<double>(userDelta) / static_cast<double>(totalDelta)) * 100.0;

            // Clamp to [0, 100] in case of sampling skew between successive snapshots.
            usage.totalCpuPercent = std::clamp(usage.totalCpuPercent, 0.0, 100.0);
            usage.idleCpuPercent = std::clamp(usage.idleCpuPercent, 0.0, 100.0);
            usage.kernelCpuPercent = std::clamp(usage.kernelCpuPercent, 0.0, 100.0);
            usage.userCpuPercent = std::clamp(usage.userCpuPercent, 0.0, 100.0);
        }

        // Store for next calculation
        m_prevIdleTime = idleTime;
        m_prevKernelTime = kernelTime;
        m_prevUserTime = userTime;
        m_prevSampleTime = usage.sampleTime;
    }

    // ====================================================================
    // MEMORY METRICS
    // ====================================================================

    void UpdateMemoryInfo(SystemResourceUsage& usage) {
        MEMORYSTATUSEX memStatus = {};
        memStatus.dwLength = sizeof(memStatus);

        if (GlobalMemoryStatusEx(&memStatus)) {
            usage.totalPhysicalBytes = memStatus.ullTotalPhys;
            usage.availablePhysicalBytes = memStatus.ullAvailPhys;
            usage.usedPhysicalBytes = usage.totalPhysicalBytes - usage.availablePhysicalBytes;
            usage.memoryUsagePercent = static_cast<double>(memStatus.dwMemoryLoad);
            usage.commitedBytes = memStatus.ullTotalPageFile - memStatus.ullAvailPageFile;
            usage.commitLimitBytes = memStatus.ullTotalPageFile;
        }

        PERFORMANCE_INFORMATION perfInfo = {};
        perfInfo.cb = sizeof(perfInfo);

        if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
            usage.cachedBytes = perfInfo.SystemCache * perfInfo.PageSize;
            usage.handleCount = perfInfo.HandleCount;
            usage.processCount = perfInfo.ProcessCount;
            usage.threadCount = perfInfo.ThreadCount;
        }
    }

    void UpdateProcessCounts(SystemResourceUsage& usage) {
        // Already set by GetPerformanceInfo in UpdateMemoryInfo
    }

    // ====================================================================
    // DISK I/O METRICS (PDH)
    // ====================================================================

    /**
     * @brief Collects disk I/O metrics via PDH counters.
     *
     * PDH handles are validated before use: disconnected or invalidated
     * counters return PDH_INVALID_DATA which we handle gracefully.
     */
    void UpdateDiskMetrics(SystemResourceUsage& usage) {
        if (!m_pdhQuery) return;

        PDH_STATUS status = PdhCollectQueryData(m_pdhQuery);
        if (status != ERROR_SUCCESS) {
            // PDH query can fail if counters become invalid (e.g., disk removed)
            SS_LOG_DEBUG(LOG_CATEGORY, L"PDH collect failed: 0x%08X", status);
            return;
        }

        PDH_FMT_COUNTERVALUE value;
        DWORD counterType = 0;

        if (m_diskReadCounter) {
            status = PdhGetFormattedCounterValue(m_diskReadCounter, PDH_FMT_DOUBLE, &counterType, &value);
            if (status == ERROR_SUCCESS && (value.CStatus == PDH_CSTATUS_VALID_DATA ||
                                             value.CStatus == PDH_CSTATUS_NEW_DATA)) {
                usage.diskReadBytesPerSec = std::max(0.0, value.doubleValue);
            }
        }

        if (m_diskWriteCounter) {
            status = PdhGetFormattedCounterValue(m_diskWriteCounter, PDH_FMT_DOUBLE, &counterType, &value);
            if (status == ERROR_SUCCESS && (value.CStatus == PDH_CSTATUS_VALID_DATA ||
                                             value.CStatus == PDH_CSTATUS_NEW_DATA)) {
                usage.diskWriteBytesPerSec = std::max(0.0, value.doubleValue);
            }
        }

        if (m_diskQueueCounter) {
            status = PdhGetFormattedCounterValue(m_diskQueueCounter, PDH_FMT_DOUBLE, &counterType, &value);
            if (status == ERROR_SUCCESS && (value.CStatus == PDH_CSTATUS_VALID_DATA ||
                                             value.CStatus == PDH_CSTATUS_NEW_DATA)) {
                usage.diskQueueLength = std::max(0.0, value.doubleValue);
            }
        }

        if (m_diskTimeCounter) {
            status = PdhGetFormattedCounterValue(m_diskTimeCounter, PDH_FMT_DOUBLE, &counterType, &value);
            if (status == ERROR_SUCCESS && (value.CStatus == PDH_CSTATUS_VALID_DATA ||
                                             value.CStatus == PDH_CSTATUS_NEW_DATA)) {
                usage.diskTimePercent = std::clamp(value.doubleValue, 0.0, 100.0);
            }
        }
    }

    // ====================================================================
    // NETWORK METRICS (GetIfTable2)
    // ====================================================================

    /**
     * @brief Collects network throughput via GetIfTable2.
     *
     * Sums byte counters across all non-loopback, non-tunnel, operational
     * interfaces. Calculates rates from deltas against previous sample.
     * More reliable than PDH wildcard counters for network metrics.
     */
    void UpdateNetworkMetrics(SystemResourceUsage& usage) {
        MIB_IF_TABLE2* rawTable = nullptr;
        if (GetIfTable2(&rawTable) != NO_ERROR || !rawTable) {
            return;
        }

        uint64_t totalSend = 0, totalRecv = 0;
        for (ULONG i = 0; i < rawTable->NumEntries; i++) {
            const auto& row = rawTable->Table[i];
            if (row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
                row.Type == IF_TYPE_TUNNEL ||
                row.OperStatus != IfOperStatusUp) {
                continue;
            }
            totalSend += row.OutOctets;
            totalRecv += row.InOctets;
        }
        FreeMibTable(rawTable);

        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - m_prevNetworkSampleTime
        );

        if (elapsed.count() > 0 && m_networkInitialized) {
            const double elapsedSec = static_cast<double>(elapsed.count()) / 1000.0;

            if (totalSend >= m_prevNetworkSendBytes) {
                usage.networkSendBytesPerSec = static_cast<double>(
                    totalSend - m_prevNetworkSendBytes) / elapsedSec;
            }
            if (totalRecv >= m_prevNetworkRecvBytes) {
                usage.networkRecvBytesPerSec = static_cast<double>(
                    totalRecv - m_prevNetworkRecvBytes) / elapsedSec;
            }
        }

        m_prevNetworkSendBytes = totalSend;
        m_prevNetworkRecvBytes = totalRecv;
        m_prevNetworkSampleTime = now;
        m_networkInitialized = true;
    }

    // ====================================================================
    // IDLE STATE
    // ====================================================================

    void UpdateIdleState(SystemResourceUsage& usage) {
        const uint64_t idleMs = GetSystemIdleTime();
        usage.idleDuration = std::chrono::milliseconds(idleMs);

        if (idleMs < 5000) {  // 5 seconds
            usage.idleState = SystemIdleState::Active;
        } else if (idleMs < 60000) {  // 1 minute
            usage.idleState = SystemIdleState::Idle;
        } else if (idleMs < 300000) {  // 5 minutes
            usage.idleState = SystemIdleState::DeepIdle;
        } else {
            usage.idleState = SystemIdleState::Sleeping;
        }
    }

    uint64_t FileTimeToUint64(const FILETIME& ft) const {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart;
    }

    // ====================================================================
    // MEMBER VARIABLES
    // ====================================================================

    mutable std::shared_mutex m_mutex;
    uint32_t m_processorCount;
    FILETIME m_prevIdleTime{};
    FILETIME m_prevKernelTime{};
    FILETIME m_prevUserTime{};
    std::chrono::steady_clock::time_point m_prevSampleTime;

    // PDH disk I/O counters
    PDH_HQUERY m_pdhQuery{ nullptr };
    PDH_HCOUNTER m_diskReadCounter{ nullptr };
    PDH_HCOUNTER m_diskWriteCounter{ nullptr };
    PDH_HCOUNTER m_diskQueueCounter{ nullptr };
    PDH_HCOUNTER m_diskTimeCounter{ nullptr };

    // Network tracking state
    uint64_t m_prevNetworkSendBytes{ 0 };
    uint64_t m_prevNetworkRecvBytes{ 0 };
    std::chrono::steady_clock::time_point m_prevNetworkSampleTime;
    bool m_networkInitialized{ false };
};

// ============================================================================
// PIMPL IMPLEMENTATION CLASS
// ============================================================================

class PerformanceMonitorImpl {
public:
    PerformanceMonitorImpl() = default;
    ~PerformanceMonitorImpl() {
        StopMonitoring();
    }

    // Prevent copying
    PerformanceMonitorImpl(const PerformanceMonitorImpl&) = delete;
    PerformanceMonitorImpl& operator=(const PerformanceMonitorImpl&) = delete;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    bool Initialize(const PerformanceMonitorConfig& config) {
        // SECURITY FIX: refuse re-initialization while the monitor thread is
        // running. Otherwise the unique_ptr<*> members are swapped under the
        // worker's nose, which uses them lock-free and would dereference
        // freed memory. Caller must Shutdown() first.
        if (m_monitoring.load(std::memory_order_acquire)) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialize rejected: monitor thread is active; call Shutdown() first");
            return false;
        }

        std::unique_lock lock(m_mutex);

        // Validate configuration to prevent integer-overflow / zero-sampling
        // pathologies in downstream rate calculations.
        PerformanceMonitorConfig safeConfig = config;
        if (safeConfig.samplingIntervalMs == 0) {
            SS_LOG_WARN(LOG_CATEGORY, L"samplingIntervalMs == 0; clamping to 100 ms");
            safeConfig.samplingIntervalMs = 100;
        }
        if (safeConfig.samplingIntervalMs > 60u * 60u * 1000u) {
            SS_LOG_WARN(LOG_CATEGORY, L"samplingIntervalMs > 1h; clamping to 1h");
            safeConfig.samplingIntervalMs = 60u * 60u * 1000u;
        }
        if (safeConfig.historyDepthSeconds == 0) {
            safeConfig.historyDepthSeconds = 60;
        }
        if (safeConfig.thresholds.highCpuThreshold < 0.0)   safeConfig.thresholds.highCpuThreshold = 0.0;
        if (safeConfig.thresholds.highCpuThreshold > 100.0) safeConfig.thresholds.highCpuThreshold = 100.0;
        if (safeConfig.thresholds.miningCpuThreshold < 0.0)   safeConfig.thresholds.miningCpuThreshold = 0.0;
        if (safeConfig.thresholds.miningCpuThreshold > 100.0) safeConfig.thresholds.miningCpuThreshold = 100.0;
        if (safeConfig.cpuThrottleThreshold < 0.0)    safeConfig.cpuThrottleThreshold = 0.0;
        if (safeConfig.cpuThrottleThreshold > 100.0)  safeConfig.cpuThrottleThreshold = 100.0;
        if (safeConfig.memoryThrottleThreshold < 0.0)    safeConfig.memoryThrottleThreshold = 0.0;
        if (safeConfig.memoryThrottleThreshold > 100.0)  safeConfig.memoryThrottleThreshold = 100.0;

        try {
            SS_LOG_INFO(LOG_CATEGORY, L"Initializing...");

            m_config = safeConfig;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_historyManager = std::make_unique<HistoryManager>();
            m_anomalyDetector = std::make_unique<AnomalyDetector>(safeConfig.thresholds, safeConfig.samplingIntervalMs);
            m_processTracker = std::make_unique<ProcessResourceTracker>();
            m_systemTracker = std::make_unique<SystemResourceTracker>();

            m_historyManager->SetMaxHistorySeconds(safeConfig.historyDepthSeconds, safeConfig.samplingIntervalMs);

            m_initialized = true;
            SS_LOG_INFO(LOG_CATEGORY, L"Initialized successfully");
            return true;

        } catch (const std::exception& e) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Initialization failed: %hs", e.what());
            return false;
        }
    }

    void Shutdown() noexcept {
        StopMonitoring();

        std::unique_lock lock(m_mutex);
        m_initialized = false;

        SS_LOG_INFO(LOG_CATEGORY, L"Shutdown complete");
    }

    [[nodiscard]] bool IsInitialized() const noexcept {
        std::shared_lock lock(m_mutex);
        return m_initialized;
    }

    // ========================================================================
    // MONITORING CONTROL
    // ========================================================================

    void StartMonitoring() {
        std::unique_lock lock(m_mutex);

        if (!m_initialized) {
            SS_LOG_ERROR(LOG_CATEGORY, L"Not initialized");
            return;
        }

        if (m_monitoring.load(std::memory_order_acquire)) {
            SS_LOG_WARN(LOG_CATEGORY, L"Already monitoring");
            return;
        }

        m_monitoring.store(true, std::memory_order_release);
        m_monitorThread = std::thread(&PerformanceMonitorImpl::MonitorThreadFunc, this);

        SS_LOG_INFO(LOG_CATEGORY, L"Monitoring started (interval: %ums)",
                    m_config.samplingIntervalMs);
    }

    void StopMonitoring() {
        {
            std::unique_lock lock(m_mutex);
            if (!m_monitoring.load(std::memory_order_acquire)) return;
            m_monitoring.store(false, std::memory_order_release);
        }

        if (m_monitorThread.joinable()) {
            m_monitorThread.join();
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Monitoring stopped");
    }

    // ========================================================================
    // PROCESS MONITORING
    // ========================================================================

    ProcessResourceUsage GetProcessUsage(uint32_t processId) const {
        return m_processTracker->GetUsage(processId);
    }

    std::vector<ProcessResourceUsage> GetAllProcessUsage() const {
        return m_processTracker->GetAllProcessUsage();
    }

    std::vector<ProcessResourceUsage> GetTopCPUProcesses(uint32_t count) const {
        auto all = GetAllProcessUsage();

        std::partial_sort(all.begin(),
                         all.begin() + std::min(count, static_cast<uint32_t>(all.size())),
                         all.end(),
                         [](const ProcessResourceUsage& a, const ProcessResourceUsage& b) {
                             return a.cpuPercent > b.cpuPercent;
                         });

        all.resize(std::min(count, static_cast<uint32_t>(all.size())));
        return all;
    }

    std::vector<ProcessResourceUsage> GetTopMemoryProcesses(uint32_t count) const {
        auto all = GetAllProcessUsage();

        std::partial_sort(all.begin(),
                         all.begin() + std::min(count, static_cast<uint32_t>(all.size())),
                         all.end(),
                         [](const ProcessResourceUsage& a, const ProcessResourceUsage& b) {
                             return a.workingSetBytes > b.workingSetBytes;
                         });

        all.resize(std::min(count, static_cast<uint32_t>(all.size())));
        return all;
    }

    std::vector<ProcessResourceUsage> GetTopIOProcesses(uint32_t count) const {
        auto all = GetAllProcessUsage();

        std::partial_sort(all.begin(),
                         all.begin() + std::min(count, static_cast<uint32_t>(all.size())),
                         all.end(),
                         [](const ProcessResourceUsage& a, const ProcessResourceUsage& b) {
                             return (a.ioReadBytesPerSec + a.ioWriteBytesPerSec) >
                                   (b.ioReadBytesPerSec + b.ioWriteBytesPerSec);
                         });

        all.resize(std::min(count, static_cast<uint32_t>(all.size())));
        return all;
    }

    // ========================================================================
    // SYSTEM MONITORING
    // ========================================================================

    SystemResourceUsage GetSystemUsage() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage;
    }

    double GetCPUUsage() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.totalCpuPercent;
    }

    double GetMemoryUsage() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.memoryUsagePercent;
    }

    uint64_t GetAvailableMemory() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.availablePhysicalBytes;
    }

    ResourcePressure GetCPUPressure() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.cpuPressure;
    }

    ResourcePressure GetMemoryPressure() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.memoryPressure;
    }

    ResourcePressure GetIOPressure() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.ioPressure;
    }

    SystemIdleState GetIdleState() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.idleState;
    }

    bool IsSystemIdle() const {
        std::shared_lock lock(m_mutex);
        return m_currentSystemUsage.idleState != SystemIdleState::Active;
    }

    // ========================================================================
    // ANOMALY DETECTION
    // ========================================================================

    std::vector<PerformanceAnomaly> GetActiveAnomalies() const {
        return m_anomalyDetector->GetActiveAnomalies();
    }

    std::vector<PerformanceAnomaly> GetProcessAnomalies(uint32_t processId) const {
        return m_anomalyDetector->GetProcessAnomalies(processId);
    }

    std::vector<uint32_t> DetectPotentialMiners() const {
        return m_anomalyDetector->GetPotentialMiners();
    }

    // ========================================================================
    // SELF-OPTIMIZATION
    // ========================================================================

    bool ShouldThrottle() const {
        std::shared_lock lock(m_mutex);

        if (!m_config.autoThrottle) {
            return false;
        }

        return m_currentSystemUsage.totalCpuPercent >= m_config.cpuThrottleThreshold ||
               m_currentSystemUsage.memoryUsagePercent >= m_config.memoryThrottleThreshold;
    }

    double GetRecommendedThrottleLevel() const {
        std::shared_lock lock(m_mutex);

        // Calculate throttle level based on resource pressure
        const double cpuFactor = m_currentSystemUsage.totalCpuPercent / 100.0;
        const double memFactor = m_currentSystemUsage.memoryUsagePercent / 100.0;

        const double maxFactor = std::max(cpuFactor, memFactor);

        // Use named constants for throttle thresholds
        using namespace ThrottleConstants;
        if (maxFactor < kNoThrottleThreshold) return kNoThrottleLevel;
        if (maxFactor < kLightThrottleThreshold) return kLightThrottleLevel;
        if (maxFactor < kModerateThrottleThreshold) return kModerateThrottleLevel;
        return kHeavyThrottleLevel;
    }

    bool IsGoodTimeForIntensiveScan() const {
        std::shared_lock lock(m_mutex);

        const bool isIdle = m_currentSystemUsage.idleState == SystemIdleState::DeepIdle ||
                           m_currentSystemUsage.idleState == SystemIdleState::Sleeping;

        const bool lowPressure = m_currentSystemUsage.cpuPressure <= ResourcePressure::Normal &&
                                m_currentSystemUsage.memoryPressure <= ResourcePressure::Normal;

        const auto anomalies = m_anomalyDetector->GetActiveAnomalies();
        bool noCriticalAnomalies = true;
        for (const auto& anomaly : anomalies) {
            if (anomaly.severity >= 80) {
                noCriticalAnomalies = false;
                break;
            }
        }

        return isIdle && lowPressure && noCriticalAnomalies;
    }

    // ========================================================================
    // SELF-MONITORING
    // ========================================================================

    /**
     * @brief Gets the EDR's own resource usage for self-monitoring.
     */
    SelfResourceUsage GetSelfResourceUsage() const {
        return m_processTracker->GetSelfUsage();
    }

    // ========================================================================
    // KERNEL METRICS INTEGRATION
    // ========================================================================

    /**
     * @brief Accepts kernel-reported resource metrics.
     *
     * Called by the kernel IPC bridge when the driver pushes metrics.
     * Thread-safe: can be called from any thread.
     */
    void UpdateKernelMetrics(const KernelResourceMetrics& metrics) {
        std::unique_lock lock(m_kernelMetricsMutex);
        m_kernelMetrics = metrics;
        m_kernelMetrics.hasKernelData = true;
        m_kernelMetrics.sampleTime = std::chrono::steady_clock::now();

        SS_LOG_TRACE(LOG_CATEGORY, L"Kernel metrics updated: nonPagedPool=%llu, interrupts=%u, DPCs=%u",
                     metrics.nonPagedPoolUsageBytes, metrics.interruptRate, metrics.dpcRate);
    }

    /**
     * @brief Returns the latest kernel resource metrics.
     */
    KernelResourceMetrics GetKernelMetrics() const {
        std::shared_lock lock(m_kernelMetricsMutex);
        return m_kernelMetrics;
    }

    // ========================================================================
    // HISTORY
    // ========================================================================

    std::vector<SystemResourceUsage> GetUsageHistory(std::chrono::seconds duration) const {
        return m_historyManager->GetSystemHistory(duration);
    }

    std::vector<ProcessResourceUsage> GetProcessHistory(uint32_t processId,
                                                        std::chrono::seconds duration) const {
        return m_historyManager->GetProcessHistory(processId, duration);
    }

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    uint64_t RegisterResourceUsageCallback(ResourceUsageCallback callback) {
        return m_callbackManager->RegisterResourceUsage(std::move(callback));
    }

    void UnregisterResourceUsageCallback(uint64_t callbackId) {
        m_callbackManager->UnregisterResourceUsage(callbackId);
    }

    uint64_t RegisterAnomalyCallback(AnomalyCallback callback) {
        return m_callbackManager->RegisterAnomaly(std::move(callback));
    }

    void UnregisterAnomalyCallback(uint64_t callbackId) {
        m_callbackManager->UnregisterAnomaly(callbackId);
    }

    uint64_t RegisterThrottleCallback(ThrottleCallback callback) {
        return m_callbackManager->RegisterThrottle(std::move(callback));
    }

    void UnregisterThrottleCallback(uint64_t callbackId) {
        m_callbackManager->UnregisterThrottle(callbackId);
    }

    // ========================================================================
    // STATISTICS
    // ========================================================================

    const PerformanceMonitorStatistics& GetStatistics() const noexcept {
        return m_stats;
    }

    void ResetStatistics() noexcept {
        m_stats.Reset();
    }

private:
    // ========================================================================
    // INTERNAL IMPLEMENTATION
    // ========================================================================

    void MonitorThreadFunc() {
        SS_LOG_INFO(LOG_CATEGORY, L"Monitor thread started");

        const auto samplingInterval = std::chrono::milliseconds(m_config.samplingIntervalMs);
        uint32_t iterationCount = 0;

        // EDR self-monitoring thresholds
        constexpr double kSelfCpuWarnThreshold = 15.0;   // EDR using >15% CPU
        constexpr double kSelfCpuCritThreshold = 30.0;   // EDR using >30% CPU
        constexpr uint64_t kSelfMemWarnBytes = 512ULL * 1024 * 1024;  // 512 MB
        constexpr uint64_t kSelfMemCritBytes = 1024ULL * 1024 * 1024; // 1 GB

        while (m_monitoring.load(std::memory_order_acquire)) {
            try {
                const auto startTime = std::chrono::steady_clock::now();

                // Sample system usage
                if (m_config.monitorSystem) {
                    auto systemUsage = m_systemTracker->GetUsage();

                    {
                        std::unique_lock lock(m_mutex);
                        m_currentSystemUsage = systemUsage;
                    }

                    m_historyManager->AddSystemSample(systemUsage);
                    m_callbackManager->InvokeResourceUsage(systemUsage);

                    // Check throttling with atomic operations
                    if (m_config.autoThrottle) {
                        const bool shouldThrottle = ShouldThrottle();
                        const bool lastState = m_lastThrottleState.load(std::memory_order_acquire);
                        if (shouldThrottle != lastState) {
                            m_lastThrottleState.store(shouldThrottle, std::memory_order_release);
                            m_stats.throttleEngagements.fetch_add(1, std::memory_order_relaxed);
                            m_callbackManager->InvokeThrottle(shouldThrottle, systemUsage.totalCpuPercent);
                        }
                    }
                }

                // Sample process usage
                if (m_config.monitorProcesses) {
                    auto processes = m_processTracker->GetAllProcessUsage();

                    m_stats.processesMonitored.store(processes.size(), std::memory_order_relaxed);

                    for (const auto& usage : processes) {
                        m_historyManager->AddProcessSample(usage.processId, usage);

                        // Anomaly detection
                        if (m_config.detectAnomalies) {
                            m_anomalyDetector->Update(usage);
                        }
                    }
                }

                // Check for new anomalies - ONLY invoke callbacks for NEW anomalies
                if (m_config.detectAnomalies) {
                    auto newAnomalies = m_anomalyDetector->GetNewAnomalies();

                    auto allAnomalies = m_anomalyDetector->GetActiveAnomalies();
                    m_stats.anomaliesDetected.store(allAnomalies.size(), std::memory_order_relaxed);

                    for (const auto& anomaly : newAnomalies) {
                        switch (anomaly.type) {
                            case PerformanceAnomalyType::HighCPU:
                                m_stats.highCpuDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            case PerformanceAnomalyType::MemoryLeak:
                                m_stats.memoryLeakDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            case PerformanceAnomalyType::Cryptomining:
                                m_stats.miningDetections.fetch_add(1, std::memory_order_relaxed);
                                break;
                            default:
                                break;
                        }

                        m_callbackManager->InvokeAnomaly(anomaly);
                    }

                    // Clean stale tracking
                    m_anomalyDetector->ClearStaleTracking();
                }

                // ============================================================
                // EDR SELF-MONITORING (every 5 iterations to reduce overhead)
                // ============================================================
                if (++iterationCount % 5 == 0) {
                    auto selfUsage = m_processTracker->GetSelfUsage();

                    if (selfUsage.cpuPercent >= kSelfCpuCritThreshold) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"EDR self-monitoring CRITICAL: CPU %.1f%% exceeds %.1f%% - engaging throttle",
                            selfUsage.cpuPercent, kSelfCpuCritThreshold);
                        // Force throttle engagement
                        if (!m_lastThrottleState.load(std::memory_order_acquire)) {
                            m_lastThrottleState.store(true, std::memory_order_release);
                            m_stats.throttleEngagements.fetch_add(1, std::memory_order_relaxed);
                            m_callbackManager->InvokeThrottle(true, selfUsage.cpuPercent);
                        }
                    } else if (selfUsage.cpuPercent >= kSelfCpuWarnThreshold) {
                        SS_LOG_DEBUG(LOG_CATEGORY,
                            L"EDR self-monitoring: CPU %.1f%% approaching threshold",
                            selfUsage.cpuPercent);
                    }

                    if (selfUsage.workingSetBytes >= kSelfMemCritBytes) {
                        SS_LOG_WARN(LOG_CATEGORY,
                            L"EDR self-monitoring CRITICAL: memory %llu MB exceeds %llu MB limit",
                            selfUsage.workingSetBytes / (1024 * 1024),
                            kSelfMemCritBytes / (1024 * 1024));
                    } else if (selfUsage.workingSetBytes >= kSelfMemWarnBytes) {
                        SS_LOG_DEBUG(LOG_CATEGORY,
                            L"EDR self-monitoring: memory %llu MB approaching limit",
                            selfUsage.workingSetBytes / (1024 * 1024));
                    }

                    // Periodically clean stale process history (every 60 iterations)
                    if (iterationCount % 60 == 0) {
                        m_historyManager->CleanStaleProcessHistory();
                    }
                }

                m_stats.samplesTaken.fetch_add(1, std::memory_order_relaxed);

                // Sleep for remaining interval
                const auto elapsed = std::chrono::steady_clock::now() - startTime;
                const auto remaining = samplingInterval - elapsed;

                if (remaining > std::chrono::milliseconds(0)) {
                    std::this_thread::sleep_for(remaining);
                }

            } catch (const std::exception& e) {
                SS_LOG_ERROR(LOG_CATEGORY, L"Monitor thread exception: %hs", e.what());
            }
        }

        SS_LOG_INFO(LOG_CATEGORY, L"Monitor thread stopped");
    }

    // ========================================================================
    // MEMBER VARIABLES
    // ========================================================================

    mutable std::shared_mutex m_mutex;
    bool m_initialized{ false };
    std::atomic<bool> m_monitoring{ false };  // Atomic for thread-safe shutdown check
    PerformanceMonitorConfig m_config;

    // Current state
    SystemResourceUsage m_currentSystemUsage;
    
    // THREAD SAFETY NOTE: m_lastThrottleState is only accessed from the
    // monitoring thread (MonitorThreadFunc), making it thread-confined.
    // Using std::atomic for defensive programming and future-proofing.
    std::atomic<bool> m_lastThrottleState{ false };

    // Managers
    std::unique_ptr<CallbackManager> m_callbackManager;
    std::unique_ptr<HistoryManager> m_historyManager;
    std::unique_ptr<AnomalyDetector> m_anomalyDetector;
    std::unique_ptr<ProcessResourceTracker> m_processTracker;
    std::unique_ptr<SystemResourceTracker> m_systemTracker;

    // Kernel metrics (updated via UpdateKernelMetrics from IPC bridge)
    mutable std::shared_mutex m_kernelMetricsMutex;
    KernelResourceMetrics m_kernelMetrics;

    // Monitoring thread
    std::thread m_monitorThread;

    // Statistics
    mutable PerformanceMonitorStatistics m_stats;
};

// ============================================================================
// MAIN CLASS IMPLEMENTATION (SINGLETON + FORWARDING)
// ============================================================================

PerformanceMonitor::PerformanceMonitor()
    : m_impl(std::make_unique<PerformanceMonitorImpl>()) {
}

PerformanceMonitor::~PerformanceMonitor() = default;

PerformanceMonitor& PerformanceMonitor::Instance() {
    static PerformanceMonitor instance;
    return instance;
}

bool PerformanceMonitor::Initialize(const PerformanceMonitorConfig& config) {
    return m_impl->Initialize(config);
}

void PerformanceMonitor::Shutdown() noexcept {
    m_impl->Shutdown();
}

bool PerformanceMonitor::IsInitialized() const noexcept {
    return m_impl->IsInitialized();
}

void PerformanceMonitor::StartMonitoring() {
    m_impl->StartMonitoring();
}

void PerformanceMonitor::StopMonitoring() {
    m_impl->StopMonitoring();
}

ProcessResourceUsage PerformanceMonitor::GetProcessUsage(uint32_t processId) const {
    return m_impl->GetProcessUsage(processId);
}

std::vector<ProcessResourceUsage> PerformanceMonitor::GetAllProcessUsage() const {
    return m_impl->GetAllProcessUsage();
}

std::vector<ProcessResourceUsage> PerformanceMonitor::GetTopCPUProcesses(uint32_t count) const {
    return m_impl->GetTopCPUProcesses(count);
}

std::vector<ProcessResourceUsage> PerformanceMonitor::GetTopMemoryProcesses(uint32_t count) const {
    return m_impl->GetTopMemoryProcesses(count);
}

std::vector<ProcessResourceUsage> PerformanceMonitor::GetTopIOProcesses(uint32_t count) const {
    return m_impl->GetTopIOProcesses(count);
}

SystemResourceUsage PerformanceMonitor::GetSystemUsage() const {
    return m_impl->GetSystemUsage();
}

double PerformanceMonitor::GetCPUUsage() const {
    return m_impl->GetCPUUsage();
}

double PerformanceMonitor::GetMemoryUsage() const {
    return m_impl->GetMemoryUsage();
}

uint64_t PerformanceMonitor::GetAvailableMemory() const {
    return m_impl->GetAvailableMemory();
}

ResourcePressure PerformanceMonitor::GetCPUPressure() const {
    return m_impl->GetCPUPressure();
}

ResourcePressure PerformanceMonitor::GetMemoryPressure() const {
    return m_impl->GetMemoryPressure();
}

ResourcePressure PerformanceMonitor::GetIOPressure() const {
    return m_impl->GetIOPressure();
}

SystemIdleState PerformanceMonitor::GetIdleState() const {
    return m_impl->GetIdleState();
}

bool PerformanceMonitor::IsSystemIdle() const {
    return m_impl->IsSystemIdle();
}

std::vector<PerformanceAnomaly> PerformanceMonitor::GetActiveAnomalies() const {
    return m_impl->GetActiveAnomalies();
}

std::vector<PerformanceAnomaly> PerformanceMonitor::GetProcessAnomalies(uint32_t processId) const {
    return m_impl->GetProcessAnomalies(processId);
}

std::vector<uint32_t> PerformanceMonitor::DetectPotentialMiners() const {
    return m_impl->DetectPotentialMiners();
}

bool PerformanceMonitor::ShouldThrottle() const {
    return m_impl->ShouldThrottle();
}

double PerformanceMonitor::GetRecommendedThrottleLevel() const {
    return m_impl->GetRecommendedThrottleLevel();
}

bool PerformanceMonitor::IsGoodTimeForIntensiveScan() const {
    return m_impl->IsGoodTimeForIntensiveScan();
}

SelfResourceUsage PerformanceMonitor::GetSelfResourceUsage() const {
    return m_impl->GetSelfResourceUsage();
}

void PerformanceMonitor::UpdateKernelMetrics(const KernelResourceMetrics& metrics) {
    m_impl->UpdateKernelMetrics(metrics);
}

KernelResourceMetrics PerformanceMonitor::GetKernelMetrics() const {
    return m_impl->GetKernelMetrics();
}

std::vector<SystemResourceUsage> PerformanceMonitor::GetUsageHistory(
    std::chrono::seconds duration) const {
    return m_impl->GetUsageHistory(duration);
}

std::vector<ProcessResourceUsage> PerformanceMonitor::GetProcessHistory(
    uint32_t processId, std::chrono::seconds duration) const {
    return m_impl->GetProcessHistory(processId, duration);
}

uint64_t PerformanceMonitor::RegisterResourceUsageCallback(ResourceUsageCallback callback) {
    return m_impl->RegisterResourceUsageCallback(std::move(callback));
}

void PerformanceMonitor::UnregisterResourceUsageCallback(uint64_t callbackId) {
    m_impl->UnregisterResourceUsageCallback(callbackId);
}

uint64_t PerformanceMonitor::RegisterAnomalyCallback(AnomalyCallback callback) {
    return m_impl->RegisterAnomalyCallback(std::move(callback));
}

void PerformanceMonitor::UnregisterAnomalyCallback(uint64_t callbackId) {
    m_impl->UnregisterAnomalyCallback(callbackId);
}

uint64_t PerformanceMonitor::RegisterThrottleCallback(ThrottleCallback callback) {
    return m_impl->RegisterThrottleCallback(std::move(callback));
}

void PerformanceMonitor::UnregisterThrottleCallback(uint64_t callbackId) {
    m_impl->UnregisterThrottleCallback(callbackId);
}

const PerformanceMonitorStatistics& PerformanceMonitor::GetStatistics() const noexcept {
    return m_impl->GetStatistics();
}

void PerformanceMonitor::ResetStatistics() noexcept {
    m_impl->ResetStatistics();
}

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
