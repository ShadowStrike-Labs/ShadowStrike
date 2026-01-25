/**
 * ============================================================================
 * ShadowStrike Core System - PERFORMANCE MONITOR (The Resource Guardian)
 * ============================================================================
 *
 * @file PerformanceMonitor.hpp
 * @brief Enterprise-grade system and process performance monitoring.
 *
 * This module provides comprehensive performance monitoring including
 * per-process resource usage, system-wide metrics, anomaly detection,
 * and AV self-optimization based on resource availability.
 *
 * Key Capabilities:
 * =================
 * 1. PROCESS MONITORING
 *    - CPU usage per process
 *    - Memory consumption (working set, private)
 *    - I/O operations
 *    - Handle/thread counts
 *
 * 2. SYSTEM METRICS
 *    - Total CPU utilization
 *    - Memory pressure
 *    - Disk I/O rates
 *    - Network throughput
 *
 * 3. ANOMALY DETECTION
 *    - Cryptominer detection (high CPU)
 *    - Memory leak detection
 *    - I/O flood detection
 *    - Resource exhaustion attacks
 *
 * 4. AV SELF-OPTIMIZATION
 *    - Adaptive scan throttling
 *    - Memory limit awareness
 *    - Background vs foreground modes
 *    - System idle detection
 *
 * Security Relevance:
 * ===================
 * - Detect resource-intensive malware (miners)
 * - Identify DoS conditions
 * - Monitor suspicious process behavior
 * - Ensure AV doesn't degrade system performance
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see HardwareMonitor.hpp for hardware-level metrics
 * @see ProcessMonitor.hpp for process security
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>

namespace ShadowStrike {
namespace Core {
namespace System {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class PerformanceMonitorImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum ResourcePressure
 * @brief System resource pressure level.
 */
enum class ResourcePressure : uint8_t {
    Low = 0,                       // Resources readily available
    Normal = 1,                    // Normal usage
    Elevated = 2,                  // Above normal
    High = 3,                      // System stressed
    Critical = 4                   // Resource exhaustion
};

/**
 * @enum PerformanceAnomalyType
 * @brief Type of performance anomaly.
 */
enum class PerformanceAnomalyType : uint8_t {
    None = 0,
    HighCPU = 1,                   // Sustained high CPU
    MemoryLeak = 2,                // Growing memory usage
    HighIO = 3,                    // Excessive I/O
    HandleLeak = 4,                // Growing handle count
    ThreadSpawn = 5,               // Rapid thread creation
    NetworkFlood = 6,              // High network activity
    Cryptomining = 7               // Mining pattern detected
};

/**
 * @enum SystemIdleState
 * @brief System idle state.
 */
enum class SystemIdleState : uint8_t {
    Active = 0,                    // User actively using system
    Idle = 1,                      // User inactive
    DeepIdle = 2,                  // Extended idle (screensaver, etc.)
    Sleeping = 3                   // About to sleep
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct ProcessResourceUsage
 * @brief Resource usage for a specific process.
 */
struct alignas(128) ProcessResourceUsage {
    uint32_t processId{ 0 };
    std::wstring processName;
    std::wstring imagePath;
    
    // CPU
    double cpuPercent{ 0.0 };         // Current CPU usage
    double cpuPercentAvg{ 0.0 };      // Average over monitoring window
    uint64_t kernelTimeMs{ 0 };
    uint64_t userTimeMs{ 0 };
    
    // Memory
    uint64_t workingSetBytes{ 0 };
    uint64_t privateBytes{ 0 };
    uint64_t virtualBytes{ 0 };
    uint64_t peakWorkingSetBytes{ 0 };
    uint64_t pagefileUsageBytes{ 0 };
    
    // I/O
    uint64_t ioReadBytes{ 0 };
    uint64_t ioWriteBytes{ 0 };
    uint64_t ioOtherBytes{ 0 };
    uint64_t ioReadOps{ 0 };
    uint64_t ioWriteOps{ 0 };
    
    // Rate (per second)
    double ioReadBytesPerSec{ 0.0 };
    double ioWriteBytesPerSec{ 0.0 };
    
    // Handles/Threads
    uint32_t handleCount{ 0 };
    uint32_t threadCount{ 0 };
    uint32_t gdiObjectCount{ 0 };
    uint32_t userObjectCount{ 0 };
    
    // Network (if available)
    uint64_t networkSendBytes{ 0 };
    uint64_t networkRecvBytes{ 0 };
    
    // Sampling time
    std::chrono::steady_clock::time_point sampleTime;
};

/**
 * @struct SystemResourceUsage
 * @brief System-wide resource usage.
 */
struct alignas(128) SystemResourceUsage {
    // CPU
    double totalCpuPercent{ 0.0 };
    double userCpuPercent{ 0.0 };
    double kernelCpuPercent{ 0.0 };
    double idleCpuPercent{ 0.0 };
    std::vector<double> perCoreCpuPercent;
    
    // Memory
    uint64_t totalPhysicalBytes{ 0 };
    uint64_t availablePhysicalBytes{ 0 };
    uint64_t usedPhysicalBytes{ 0 };
    double memoryUsagePercent{ 0.0 };
    uint64_t commitedBytes{ 0 };
    uint64_t commitLimitBytes{ 0 };
    uint64_t cachedBytes{ 0 };
    uint64_t pageFaultsPerSec{ 0 };
    
    // Disk
    double diskReadBytesPerSec{ 0.0 };
    double diskWriteBytesPerSec{ 0.0 };
    double diskQueueLength{ 0.0 };
    double diskTimePercent{ 0.0 };
    
    // Network
    double networkSendBytesPerSec{ 0.0 };
    double networkRecvBytesPerSec{ 0.0 };
    
    // Process counts
    uint32_t processCount{ 0 };
    uint32_t threadCount{ 0 };
    uint32_t handleCount{ 0 };
    
    // Pressure levels
    ResourcePressure cpuPressure{ ResourcePressure::Normal };
    ResourcePressure memoryPressure{ ResourcePressure::Normal };
    ResourcePressure ioPressure{ ResourcePressure::Normal };
    
    // Idle state
    SystemIdleState idleState{ SystemIdleState::Active };
    std::chrono::milliseconds idleDuration{ 0 };
    
    // Sampling time
    std::chrono::steady_clock::time_point sampleTime;
};

/**
 * @struct PerformanceAnomaly
 * @brief Detected performance anomaly.
 */
struct alignas(64) PerformanceAnomaly {
    PerformanceAnomalyType type{ PerformanceAnomalyType::None };
    uint32_t processId{ 0 };
    std::wstring processName;
    std::wstring description;
    double value{ 0.0 };              // Relevant metric value
    double threshold{ 0.0 };          // Threshold that was exceeded
    std::chrono::system_clock::time_point detectionTime;
    uint8_t severity{ 0 };            // 0-100
};

/**
 * @struct ResourceThresholds
 * @brief Thresholds for anomaly detection.
 */
struct alignas(32) ResourceThresholds {
    // CPU
    double highCpuThreshold{ 80.0 };          // Percent
    uint32_t highCpuDurationSec{ 60 };        // Sustained duration
    
    // Memory
    double memoryLeakGrowthMBPerMin{ 10.0 };
    uint32_t memoryLeakDurationMin{ 10 };
    
    // I/O
    double highIOBytesPerSec{ 100.0 * 1024 * 1024 };  // 100 MB/s
    
    // Handles
    uint32_t handleLeakThreshold{ 1000 };     // New handles per minute
    
    // Mining detection
    double miningCpuThreshold{ 90.0 };
    uint32_t miningPatternDurationSec{ 300 };
};

/**
 * @struct PerformanceMonitorConfig
 * @brief Configuration for performance monitor.
 */
struct alignas(64) PerformanceMonitorConfig {
    bool monitorProcesses{ true };
    bool monitorSystem{ true };
    bool detectAnomalies{ true };
    bool autoThrottle{ true };           // Auto-throttle AV when system busy
    
    uint32_t samplingIntervalMs{ 1000 };
    uint32_t historyDepthSeconds{ 300 };
    
    ResourceThresholds thresholds;
    
    // Self-throttle settings
    double cpuThrottleThreshold{ 70.0 };
    double memoryThrottleThreshold{ 85.0 };
    
    static PerformanceMonitorConfig CreateDefault() noexcept;
    static PerformanceMonitorConfig CreateLowImpact() noexcept;
};

/**
 * @struct PerformanceMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(128) PerformanceMonitorStatistics {
    std::atomic<uint64_t> samplesTaken{ 0 };
    std::atomic<uint64_t> processesMonitored{ 0 };
    std::atomic<uint64_t> anomaliesDetected{ 0 };
    std::atomic<uint64_t> throttleEngagements{ 0 };
    std::atomic<uint64_t> highCpuDetections{ 0 };
    std::atomic<uint64_t> memoryLeakDetections{ 0 };
    std::atomic<uint64_t> miningDetections{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using ResourceUsageCallback = std::function<void(const SystemResourceUsage& usage)>;
using ProcessUsageCallback = std::function<void(const ProcessResourceUsage& usage)>;
using AnomalyCallback = std::function<void(const PerformanceAnomaly& anomaly)>;
using ThrottleCallback = std::function<void(bool shouldThrottle, double currentLoad)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class PerformanceMonitor
 * @brief Enterprise-grade performance monitoring.
 *
 * Thread-safe singleton providing comprehensive performance monitoring
 * with anomaly detection and self-optimization capabilities.
 */
class PerformanceMonitor {
public:
    /**
     * @brief Gets singleton instance.
     */
    static PerformanceMonitor& Instance();
    
    /**
     * @brief Initializes performance monitor.
     */
    bool Initialize(const PerformanceMonitorConfig& config);
    
    /**
     * @brief Shuts down performance monitor.
     */
    void Shutdown() noexcept;
    
    /**
     * @brief Starts continuous monitoring.
     */
    void StartMonitoring();
    
    /**
     * @brief Stops continuous monitoring.
     */
    void StopMonitoring();
    
    // ========================================================================
    // PROCESS MONITORING
    // ========================================================================
    
    /**
     * @brief Gets resource usage for a process.
     */
    [[nodiscard]] ProcessResourceUsage GetProcessUsage(uint32_t processId) const;
    
    /**
     * @brief Gets resource usage for all processes.
     */
    [[nodiscard]] std::vector<ProcessResourceUsage> GetAllProcessUsage() const;
    
    /**
     * @brief Gets top CPU consumers.
     */
    [[nodiscard]] std::vector<ProcessResourceUsage> GetTopCPUProcesses(
        uint32_t count = 10) const;
    
    /**
     * @brief Gets top memory consumers.
     */
    [[nodiscard]] std::vector<ProcessResourceUsage> GetTopMemoryProcesses(
        uint32_t count = 10) const;
    
    /**
     * @brief Gets top I/O consumers.
     */
    [[nodiscard]] std::vector<ProcessResourceUsage> GetTopIOProcesses(
        uint32_t count = 10) const;
    
    // ========================================================================
    // SYSTEM MONITORING
    // ========================================================================
    
    /**
     * @brief Gets current system resource usage.
     */
    [[nodiscard]] SystemResourceUsage GetSystemUsage() const;
    
    /**
     * @brief Gets CPU usage percentage.
     */
    [[nodiscard]] double GetCPUUsage() const;
    
    /**
     * @brief Gets memory usage percentage.
     */
    [[nodiscard]] double GetMemoryUsage() const;
    
    /**
     * @brief Gets available memory in bytes.
     */
    [[nodiscard]] uint64_t GetAvailableMemory() const;
    
    /**
     * @brief Gets resource pressure levels.
     */
    [[nodiscard]] ResourcePressure GetCPUPressure() const;
    [[nodiscard]] ResourcePressure GetMemoryPressure() const;
    [[nodiscard]] ResourcePressure GetIOPressure() const;
    
    /**
     * @brief Gets system idle state.
     */
    [[nodiscard]] SystemIdleState GetIdleState() const;
    
    /**
     * @brief Checks if system is idle.
     */
    [[nodiscard]] bool IsSystemIdle() const;
    
    // ========================================================================
    // ANOMALY DETECTION
    // ========================================================================
    
    /**
     * @brief Gets detected anomalies.
     */
    [[nodiscard]] std::vector<PerformanceAnomaly> GetActiveAnomalies() const;
    
    /**
     * @brief Checks if process has anomalies.
     */
    [[nodiscard]] std::vector<PerformanceAnomaly> GetProcessAnomalies(
        uint32_t processId) const;
    
    /**
     * @brief Checks for potential cryptominer activity.
     */
    [[nodiscard]] std::vector<uint32_t> DetectPotentialMiners() const;
    
    // ========================================================================
    // SELF-OPTIMIZATION
    // ========================================================================
    
    /**
     * @brief Checks if AV should throttle.
     */
    [[nodiscard]] bool ShouldThrottle() const;
    
    /**
     * @brief Gets recommended throttle level (0.0-1.0).
     */
    [[nodiscard]] double GetRecommendedThrottleLevel() const;
    
    /**
     * @brief Checks if conditions are good for intensive scanning.
     */
    [[nodiscard]] bool IsGoodTimeForIntensiveScan() const;
    
    // ========================================================================
    // HISTORY
    // ========================================================================
    
    /**
     * @brief Gets historical system usage.
     */
    [[nodiscard]] std::vector<SystemResourceUsage> GetUsageHistory(
        std::chrono::seconds duration) const;
    
    /**
     * @brief Gets historical process usage.
     */
    [[nodiscard]] std::vector<ProcessResourceUsage> GetProcessHistory(
        uint32_t processId,
        std::chrono::seconds duration) const;
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Registers callback for system usage updates.
     */
    uint64_t RegisterResourceUsageCallback(ResourceUsageCallback callback);
    
    /**
     * @brief Unregisters system usage callback.
     */
    void UnregisterResourceUsageCallback(uint64_t callbackId);
    
    /**
     * @brief Registers callback for anomaly detection.
     */
    uint64_t RegisterAnomalyCallback(AnomalyCallback callback);
    
    /**
     * @brief Unregisters anomaly callback.
     */
    void UnregisterAnomalyCallback(uint64_t callbackId);
    
    /**
     * @brief Registers callback for throttle recommendations.
     */
    uint64_t RegisterThrottleCallback(ThrottleCallback callback);
    
    /**
     * @brief Unregisters throttle callback.
     */
    void UnregisterThrottleCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const PerformanceMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    PerformanceMonitor();
    ~PerformanceMonitor();
    
    PerformanceMonitor(const PerformanceMonitor&) = delete;
    PerformanceMonitor& operator=(const PerformanceMonitor&) = delete;
    
    std::unique_ptr<PerformanceMonitorImpl> m_impl;
};

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
