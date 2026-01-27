/**
 * ============================================================================
 * ShadowStrike NGAV - CPU PERFORMANCE MONITOR
 * ============================================================================
 *
 * @file CPUMonitor.hpp
 * @brief Enterprise-grade CPU usage monitoring engine.
 *        Tracks system-wide and per-process CPU consumption in real-time.
 *
 * FEATURES:
 * - System-wide CPU usage tracking (Kernel/User/Idle split)
 * - Per-process CPU usage monitoring
 * - Top consumer identification (Top-N)
 * - Thread-safe historical data access
 * - High-usage alerting system
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <chrono>
#include <optional>

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Represents CPU usage snapshot for a specific process
 */
struct ProcessCpuInfo {
    uint32_t pid;
    std::wstring name;
    double cpuUsagePercent;     // Total CPU usage (0.0 - 100.0)
    double userTimePercent;     // User mode usage
    double kernelTimePercent;   // Kernel mode usage
    uint64_t uptimeSeconds;     // Process uptime

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System-wide CPU statistics
 */
struct SystemCpuStats {
    double totalUsagePercent;
    double userUsagePercent;
    double kernelUsagePercent;
    double idlePercent;
    uint32_t contextSwitchesPerSec;
    uint32_t interruptsPerSec;
    uint32_t processesCount;
    uint32_t threadsCount;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration for the CPU Monitor
 */
struct CPUMonitorConfig {
    bool enabled = true;
    uint32_t samplingIntervalMs = 1000;
    uint32_t historySize = 60;          // Keep last 60 samples
    double highUsageThreshold = 90.0;   // Alert if > 90%
    bool trackPerProcess = true;        // Enable process scanning

    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CPU MONITOR CLASS
// ============================================================================

class CPUMonitorImpl; // PIMPL

/**
 * @class CPUMonitor
 * @brief Singleton class for monitoring CPU performance metrics.
 */
class CPUMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static CPUMonitor& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    // Deleted copy/move
    CPUMonitor(const CPUMonitor&) = delete;
    CPUMonitor& operator=(const CPUMonitor&) = delete;
    CPUMonitor(CPUMonitor&&) = delete;
    CPUMonitor& operator=(CPUMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    /**
     * @brief Initialize the monitor with configuration
     * @param config Initial configuration
     * @return true if successful
     */
    [[nodiscard]] bool Initialize(const CPUMonitorConfig& config);

    /**
     * @brief Shutdown the monitor and stop background threads
     */
    void Shutdown();

    /**
     * @brief Start the monitoring thread
     * @return true if started
     */
    [[nodiscard]] bool StartMonitoring();

    /**
     * @brief Stop the monitoring thread
     */
    void StopMonitoring();

    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // ACCESSORS
    // ========================================================================

    /**
     * @brief Get the latest system-wide CPU statistics
     */
    [[nodiscard]] SystemCpuStats GetSystemStats() const;

    /**
     * @brief Get CPU usage for a specific process
     * @param pid Process ID
     * @return Usage percentage (0.0 - 100.0) or nullopt if not found
     */
    [[nodiscard]] std::optional<double> GetProcessUsage(uint32_t pid) const;

    /**
     * @brief Get detailed info for a process
     */
    [[nodiscard]] std::optional<ProcessCpuInfo> GetProcessInfo(uint32_t pid) const;

    /**
     * @brief Get top N CPU consumers
     * @param count Number of processes to return
     * @return Vector of top consumers sorted by usage desc
     */
    [[nodiscard]] std::vector<ProcessCpuInfo> GetTopConsumers(size_t count) const;

    // ========================================================================
    // UTILITIES
    // ========================================================================

    [[nodiscard]] bool UpdateConfiguration(const CPUMonitorConfig& config);
    [[nodiscard]] CPUMonitorConfig GetConfiguration() const;

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    CPUMonitor();
    ~CPUMonitor();

    std::unique_ptr<CPUMonitorImpl> m_impl;
};

} // namespace Performance
} // namespace ShadowStrike
