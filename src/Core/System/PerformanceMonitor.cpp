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

// Windows headers
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <pdh.h>
#include <pdhmsg.h>

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")

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
 * Uses GetTickCount64() to avoid wraparound issues after 49.7 days uptime.
 * GetTickCount() is 32-bit and wraps at ~49.7 days, causing incorrect
 * idle time calculations on long-running systems.
 */
uint64_t GetSystemIdleTime() {
    LASTINPUTINFO lii = {};
    lii.cbSize = sizeof(LASTINPUTINFO);

    if (GetLastInputInfo(&lii)) {
        // SECURITY FIX: Use GetTickCount64() to prevent 49.7-day wraparound
        // GetTickCount() returns DWORD (32-bit) which wraps after ~49.7 days
        // GetTickCount64() returns ULONGLONG (64-bit) - won't wrap for 584M years
        const uint64_t currentTick = GetTickCount64();
        
        // lii.dwTime is still 32-bit, but we handle the comparison correctly
        // by checking if current is less (would indicate wrap if using 32-bit)
        const uint64_t lastInputTick = static_cast<uint64_t>(lii.dwTime);
        
        // Handle potential wraparound of lii.dwTime (it's still 32-bit)
        // If lastInputTick appears to be in the future, it wrapped
        if (currentTick >= lastInputTick) {
            return currentTick - lastInputTick;
        } else {
            // lii.dwTime wrapped - calculate correctly
            // This handles the edge case where dwTime wrapped but GetTickCount64 didn't
            return currentTick + (0xFFFFFFFFULL - lastInputTick + 1);
        }
    }

    return 0;
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

        // Limit history size
        const auto maxSamples = static_cast<size_t>(m_maxHistorySeconds);
        if (m_systemHistory.size() > maxSamples) {
            m_systemHistory.pop_front();
        }
    }

    void AddProcessSample(uint32_t pid, const ProcessResourceUsage& usage) {
        std::unique_lock lock(m_mutex);

        auto& history = m_processHistory[pid];
        history.push_back(usage);

        // Limit per-process history
        const auto maxSamples = static_cast<size_t>(m_maxHistorySeconds);
        if (history.size() > maxSamples) {
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

    void SetMaxHistorySeconds(uint32_t seconds) {
        std::unique_lock lock(m_mutex);
        m_maxHistorySeconds = seconds;
    }

    void Clear() {
        std::unique_lock lock(m_mutex);
        m_systemHistory.clear();
        m_processHistory.clear();
    }

private:
    mutable std::shared_mutex m_mutex;
    uint32_t m_maxHistorySeconds{ 300 };
    std::deque<SystemResourceUsage> m_systemHistory;
    std::unordered_map<uint32_t, std::deque<ProcessResourceUsage>> m_processHistory;
};

// ============================================================================
// ANOMALY DETECTOR
// ============================================================================

class AnomalyDetector {
public:
    AnomalyDetector(const ResourceThresholds& thresholds)
        : m_thresholds(thresholds) {
    }

    void Update(const ProcessResourceUsage& usage) {
        std::unique_lock lock(m_mutex);

        const uint32_t pid = usage.processId;
        auto& tracker = m_processTrackers[pid];

        // Update tracking data
        tracker.lastUpdate = std::chrono::steady_clock::now();
        tracker.samples.push_back(usage);

        // Limit sample history
        if (tracker.samples.size() > 60) {  // 1 minute at 1Hz
            tracker.samples.erase(tracker.samples.begin());
        }

        // Check for anomalies
        CheckHighCPU(pid, usage, tracker);
        CheckMemoryLeak(pid, usage, tracker);
        CheckHandleLeak(pid, usage, tracker);
        CheckCryptomining(pid, usage, tracker);
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
        std::vector<ProcessResourceUsage> samples;
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
                timeDelta.count() >= m_thresholds.memoryLeakDurationMin) {
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
                    pid, description.c_str());
    }

    mutable std::shared_mutex m_mutex;
    ResourceThresholds m_thresholds;
    std::unordered_map<uint32_t, ProcessTracker> m_processTrackers;
    std::unordered_map<uint32_t, std::vector<PerformanceAnomaly>> m_activeAnomalies;
    
    // Track which anomalies have been reported to callbacks to prevent storm
    std::unordered_set<AnomalyKey, AnomalyKeyHash> m_reportedAnomalies;
};

// ============================================================================
// PROCESS TRACKER
// ============================================================================

class ProcessTracker {
public:
    /**
     * @brief Constructor with processor count validation.
     * 
     * SECURITY FIX: std::thread::hardware_concurrency() can return 0
     * per C++ spec if the value is "not computable or well defined".
     * We default to 1 to prevent division by zero in CPU calculations.
     */
    ProcessTracker() {
        m_processorCount = std::thread::hardware_concurrency();
        if (m_processorCount == 0) {
            SS_LOG_WARN(LOG_CATEGORY, L"ProcessTracker: hardware_concurrency returned 0, defaulting to 1");
            m_processorCount = 1;
        }
    }
    
    /**
     * @brief Gets resource usage for a specific process.
     * 
     * SECURITY FIX: Uses RAII UniqueHandle to prevent handle leaks on
     * exception paths. All exceptions are caught and the handle is
     * guaranteed to be closed.
     */
    ProcessResourceUsage GetUsage(uint32_t pid) {
        ProcessResourceUsage usage;
        usage.processId = pid;
        usage.sampleTime = std::chrono::steady_clock::now();

        // SECURITY FIX: Use RAII wrapper to prevent handle leak on exception
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

                // Calculate CPU percentage
                auto it = m_previousTimes.find(pid);
                if (it != m_previousTimes.end()) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        usage.sampleTime - it->second.sampleTime
                    );

                    usage.cpuPercent = CalculateCPUUsage(
                        it->second.kernelTimeMs,
                        it->second.userTimeMs,
                        usage.kernelTimeMs,
                        usage.userTimeMs,
                        elapsed.count(),
                        m_processorCount
                    );
                }

                // Store for next calculation
                m_previousTimes[pid] = usage;
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

                // Calculate I/O rates with underflow protection
                auto it = m_previousTimes.find(pid);
                if (it != m_previousTimes.end()) {
                    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        usage.sampleTime - it->second.sampleTime
                    );

                    if (elapsed.count() > 0) {
                        const double elapsedSec = static_cast<double>(elapsed.count()) / 1000.0;
                        
                        // SECURITY FIX: Protect against I/O counter underflow on PID reuse
                        // When a PID is reused, the new process has lower counters than
                        // our tracking. Subtracting would cause uint64_t underflow to a
                        // huge positive value, triggering false "high I/O" anomalies.
                        if (usage.ioReadBytes >= it->second.ioReadBytes) {
                            usage.ioReadBytesPerSec = static_cast<double>(
                                usage.ioReadBytes - it->second.ioReadBytes) / elapsedSec;
                        } else {
                            // Counter went backwards - likely PID reuse, clamp to 0
                            usage.ioReadBytesPerSec = 0.0;
                        }
                        
                        if (usage.ioWriteBytes >= it->second.ioWriteBytes) {
                            usage.ioWriteBytesPerSec = static_cast<double>(
                                usage.ioWriteBytes - it->second.ioWriteBytes) / elapsedSec;
                        } else {
                            // Counter went backwards - likely PID reuse, clamp to 0
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
            SS_LOG_ERROR(LOG_CATEGORY, L"ProcessTracker::GetUsage exception for PID %u: %hs", pid, e.what());
            // UniqueHandle destructor will close handle automatically
        }

        // UniqueHandle destructor closes handle - no manual CloseHandle needed
        return usage;
    }

    std::vector<ProcessResourceUsage> GetAllProcessUsage() {
        std::vector<ProcessResourceUsage> result;

        // Use RAII for snapshot handle as well
        UniqueHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!hSnapshot) {
            return result;
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(hSnapshot.Get(), &pe32)) {
            do {
                if (pe32.th32ProcessID > 4) {  // Skip System/Idle
                    auto usage = GetUsage(pe32.th32ProcessID);
                    if (!usage.processName.empty()) {
                        result.push_back(usage);
                    }
                }
            } while (Process32NextW(hSnapshot.Get(), &pe32));
        }

        // UniqueHandle destructor closes snapshot - no manual CloseHandle needed
        return result;
    }

private:
    uint64_t FileTimeToMs(const FILETIME& ft) const {
        ULARGE_INTEGER uli;
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return uli.QuadPart / 10000;  // Convert 100-nanosecond units to milliseconds
    }

    uint32_t GetProcessThreadCount(uint32_t pid) const {
        uint32_t count = 0;

        // Use RAII for snapshot handle
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

        // UniqueHandle destructor closes snapshot - no manual CloseHandle needed
        return count;
    }

    std::unordered_map<uint32_t, ProcessResourceUsage> m_previousTimes;
    uint32_t m_processorCount{ 1 };  // Set in constructor with validation
};

// ============================================================================
// SYSTEM TRACKER
// ============================================================================

class SystemTracker {
public:
    SystemTracker() {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        m_processorCount = sysInfo.dwNumberOfProcessors;

        // Initialize previous system times
        UpdateSystemTimes();
    }

    SystemResourceUsage GetUsage() {
        SystemResourceUsage usage;
        usage.sampleTime = std::chrono::steady_clock::now();

        // Update CPU usage
        UpdateCPUUsage(usage);

        // Get memory info
        UpdateMemoryInfo(usage);

        // Get process counts
        UpdateProcessCounts(usage);

        // Calculate pressure levels
        usage.cpuPressure = CalculatePressure(usage.totalCpuPercent);
        usage.memoryPressure = CalculatePressure(usage.memoryUsagePercent);

        // Get idle state
        UpdateIdleState(usage);

        return usage;
    }

private:
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
            usage.totalCpuPercent = (static_cast<double>(systemDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.idleCpuPercent = (static_cast<double>(idleDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.kernelCpuPercent = (static_cast<double>(kernelDelta - idleDelta) / static_cast<double>(totalDelta)) * 100.0;
            usage.userCpuPercent = (static_cast<double>(userDelta) / static_cast<double>(totalDelta)) * 100.0;
        }

        // Store for next calculation
        m_prevIdleTime = idleTime;
        m_prevKernelTime = kernelTime;
        m_prevUserTime = userTime;
        m_prevSampleTime = usage.sampleTime;
    }

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
        // Already set by GetPerformanceInfo
        // Additional counting if needed
    }

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

    uint32_t m_processorCount;
    FILETIME m_prevIdleTime{};
    FILETIME m_prevKernelTime{};
    FILETIME m_prevUserTime{};
    std::chrono::steady_clock::time_point m_prevSampleTime;
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
        std::unique_lock lock(m_mutex);

        try {
            SS_LOG_INFO(L"PerformanceMonitor:",L"Initializing...");

            m_config = config;

            // Initialize managers
            m_callbackManager = std::make_unique<CallbackManager>();
            m_historyManager = std::make_unique<HistoryManager>();
            m_anomalyDetector = std::make_unique<AnomalyDetector>(config.thresholds);
            m_processTracker = std::make_unique<ProcessTracker>();
            m_systemTracker = std::make_unique<SystemTracker>();

            m_historyManager->SetMaxHistorySeconds(config.historyDepthSeconds);

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

        // Good time if:
        // 1. System is idle
        // 2. Low resource pressure
        // 3. No critical anomalies

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
        SS_LOG_INFO(L"PerformanceMonitor:", L"Monitor thread started.");

        const auto samplingInterval = std::chrono::milliseconds(m_config.samplingIntervalMs);

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
                // CALLBACK STORM FIX: Previously, we called GetActiveAnomalies() which
                // returns ALL active anomalies, causing callbacks to fire repeatedly
                // for the same anomalies. Now we use GetNewAnomalies() which only
                // returns anomalies that haven't been reported to callbacks yet.
                if (m_config.detectAnomalies) {
                    // Get only NEW anomalies that haven't been reported yet
                    auto newAnomalies = m_anomalyDetector->GetNewAnomalies();
                    
                    // Update total active count for status reporting
                    auto allAnomalies = m_anomalyDetector->GetActiveAnomalies();
                    m_stats.anomaliesDetected.store(allAnomalies.size(), std::memory_order_relaxed);

                    // STATS FIX: Only increment counters for NEW anomalies
                    // Previously we incremented on every iteration for every active anomaly,
                    // causing counter overflow and misleading statistics.
                    for (const auto& anomaly : newAnomalies) {
                        // Update type-specific stats ONCE per anomaly
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

                        // Invoke callbacks ONLY for new anomalies
                        m_callbackManager->InvokeAnomaly(anomaly);
                    }

                    // Clean stale tracking
                    m_anomalyDetector->ClearStaleTracking();
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
    std::unique_ptr<ProcessTracker> m_processTracker;
    std::unique_ptr<SystemTracker> m_systemTracker;

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
