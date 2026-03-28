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
 * ShadowStrike NGAV - CPU PERFORMANCE MONITOR
 * ============================================================================
 *
 * @file CPUMonitor.hpp
 * @brief Enterprise-grade CPU usage monitoring engine.
 *        Tracks system-wide and per-process CPU consumption in real-time.
 *
 * FEATURES:
 * - System-wide CPU usage tracking (Kernel/User/Idle split)
 * - Per-process CPU usage monitoring with overflow-safe delta math
 * - Top consumer identification (Top-N)
 * - EDR self-monitoring (own CPU impact tracking)
 * - System load assessment for scan throttling
 * - High-CPU / crypto-miner alerting via callbacks
 * - Thread-safe with minimal lock hold times
 *
 * @author ShadowStrike Security Team
 * @version 3.1.0
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
#include <functional>
#include <cstdint>

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * @brief Callback invoked when a process exceeds the crypto-miner CPU threshold.
 * @param pid         Process ID of the high-CPU consumer
 * @param processName Name of the process executable
 * @param cpuPercent  Current CPU usage percentage (0.0 – 100.0)
 *
 * Callbacks are invoked from the monitoring thread. Implementations MUST NOT
 * call back into CPUMonitor (risk of deadlock) and SHOULD return quickly.
 */
using HighCpuCallback = std::function<void(uint32_t pid,
                                           const std::wstring& processName,
                                           double cpuPercent)>;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @brief Represents CPU usage snapshot for a specific process.
 */
struct ProcessCpuInfo {
    uint32_t pid{0};
    std::wstring name;
    double cpuUsagePercent{0.0};     ///< Total CPU (0.0 – 100.0, normalized)
    double userTimePercent{0.0};     ///< User-mode portion
    double kernelTimePercent{0.0};   ///< Kernel-mode portion
    uint64_t uptimeSeconds{0};       ///< Wall-clock process uptime

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief System-wide CPU statistics.
 */
struct SystemCpuStats {
    double totalUsagePercent{0.0};
    double userUsagePercent{0.0};
    double kernelUsagePercent{0.0};
    double idlePercent{100.0};
    uint32_t contextSwitchesPerSec{0};  ///< Reserved – requires PDH for population
    uint32_t interruptsPerSec{0};       ///< Reserved – requires PDH for population
    uint32_t processesCount{0};         ///< Populated from snapshot enumeration
    uint32_t threadsCount{0};           ///< Populated from snapshot enumeration

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Configuration for the CPU Monitor.
 */
struct CPUMonitorConfig {
    bool enabled = true;
    uint32_t samplingIntervalMs = 1000;              ///< 100 – 60 000 ms
    uint32_t historySize = 60;                       ///< Ring-buffer depth (1 – 3600)
    double highUsageThreshold = 90.0;                ///< System-wide alert %
    double cryptoMinerThresholdPercent = 80.0;       ///< Per-process miner-flag %
    double selfUsageAlertThreshold = 5.0;            ///< EDR self-usage ceiling %
    uint32_t maxTrackedProcesses = 4096;             ///< Cap on tracked PIDs (1 – 65536)
    bool trackPerProcess = true;                     ///< Enable per-process enumeration

    [[nodiscard]] bool IsValid() const noexcept;
};

// ============================================================================
// CPU MONITOR CLASS
// ============================================================================

class CPUMonitorImpl; // PIMPL

/**
 * @class CPUMonitor
 * @brief Singleton for monitoring CPU performance metrics.
 *
 * Thread-safety: all public methods are safe to call from any thread.
 * The monitoring thread runs at the configured sampling interval and
 * publishes snapshots that readers consume under a shared_mutex.
 */
class CPUMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================

    [[nodiscard]] static CPUMonitor& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    CPUMonitor(const CPUMonitor&) = delete;
    CPUMonitor& operator=(const CPUMonitor&) = delete;
    CPUMonitor(CPUMonitor&&) = delete;
    CPUMonitor& operator=(CPUMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const CPUMonitorConfig& config);
    void Shutdown();
    [[nodiscard]] bool StartMonitoring();
    void StopMonitoring();
    [[nodiscard]] bool IsMonitoring() const noexcept;

    // ========================================================================
    // SYSTEM STATS
    // ========================================================================

    [[nodiscard]] SystemCpuStats GetSystemStats() const;

    // ========================================================================
    // PROCESS STATS
    // ========================================================================

    [[nodiscard]] std::optional<double> GetProcessUsage(uint32_t pid) const;
    [[nodiscard]] std::optional<ProcessCpuInfo> GetProcessInfo(uint32_t pid) const;
    [[nodiscard]] std::vector<ProcessCpuInfo> GetTopConsumers(size_t count) const;

    // ========================================================================
    // SELF-MONITORING  (EDR agent's own CPU footprint)
    // ========================================================================

    /** @brief CPU% consumed by this EDR process (0.0 – 100.0). */
    [[nodiscard]] double GetSelfUsage() const noexcept;

    /** @brief True when self-usage exceeds config.selfUsageAlertThreshold. */
    [[nodiscard]] bool IsSelfUsageExcessive() const noexcept;

    // ========================================================================
    // SYSTEM LOAD ASSESSMENT (for scan-throttling decisions)
    // ========================================================================

    /** @brief True when system-wide CPU >= thresholdPercent. */
    [[nodiscard]] bool IsSystemUnderLoad(double thresholdPercent = 80.0) const noexcept;

    /** @brief Logical processor count (cached, thread-safe). */
    [[nodiscard]] static uint32_t GetProcessorCount() noexcept;

    // ========================================================================
    // HIGH-CPU / CRYPTO-MINER ALERTING
    // ========================================================================

    /**
     * @brief Register a callback for high-CPU process alerts.
     * @return Non-zero callback ID, or 0 on failure.
     */
    [[nodiscard]] uint32_t RegisterHighCpuCallback(HighCpuCallback callback);
    void UnregisterHighCpuCallback(uint32_t callbackId);

    // ========================================================================
    // CONFIGURATION & DIAGNOSTICS
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
