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
 * ShadowStrike NGAV - DISK MONITORING MODULE
 * ============================================================================
 *
 * @file DiskMonitor.hpp
 * @brief Enterprise-grade disk I/O monitoring and analytics engine.
 *
 * Provides real-time monitoring of disk activity, identifying processes with
 * high I/O impact, detecting potential ransomware behavior (rapid high-volume writes),
 * and tracking storage health/capacity.
 *
 * CAPABILITIES:
 * =============
 * 1. REAL-TIME I/O METRICS
 *    - Read/Write throughput (B/s)
 *    - IOPS monitoring
 *    - Per-process "other" ops tracking (directory enumeration signal)
 *
 * 2. PROCESS ATTRIBUTION
 *    - Per-process I/O tracking via GetProcessIoCounters
 *    - Top consumer identification
 *    - Self-monitoring (EDR's own I/O footprint)
 *
 * 3. ANOMALY DETECTION
 *    - Sustained ransomware-like write pattern detection (time-windowed)
 *    - File enumeration storm detection (high other-ops rate)
 *    - PID reuse detection (counter reset on name change)
 *
 * 4. STORAGE HEALTH
 *    - Free space monitoring per volume
 *    - Space consumption rate tracking
 *    - Low-space alerting with configurable thresholds
 *
 * @author ShadowStrike Security Team
 * @version 4.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <functional>
#include <optional>

// ============================================================================
// WINDOWS SDK INCLUDES
// ============================================================================
#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
namespace ShadowStrike::Performance {
    class DiskMonitorImpl;
}

namespace ShadowStrike {
namespace Performance {

// ============================================================================
// CONSTANTS
// ============================================================================
namespace DiskConstants {
    constexpr uint32_t DEFAULT_POLLING_INTERVAL_MS      = 1000;
    constexpr uint32_t MIN_POLLING_INTERVAL_MS          = 100;
    constexpr uint32_t MAX_POLLING_INTERVAL_MS          = 60000;
    constexpr size_t   MAX_HISTORY_POINTS               = 60;

    constexpr uint32_t DEFAULT_SUSTAINED_WINDOW_SEC     = 5;
    constexpr uint32_t MIN_SUSTAINED_WINDOW_SEC         = 2;
    constexpr uint32_t MAX_SUSTAINED_WINDOW_SEC         = 60;

    constexpr uint32_t DEFAULT_FILE_ENUM_THRESHOLD_OPS  = 500;
    constexpr uint32_t DEFAULT_FILE_ENUM_WINDOW_SEC     = 3;

    constexpr size_t   MAX_TRACKED_PROCESSES            = 10000;

    constexpr double   DEFAULT_LOW_SPACE_PERCENT        = 95.0;
    constexpr uint64_t DEFAULT_LOW_SPACE_BYTES          = 1024ULL * 1024 * 1024;
}

// ============================================================================
// TYPE ALIASES
// ============================================================================
using Clock     = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Raw I/O counters for a specific snapshot.
 */
struct DiskIoCounters {
    uint64_t readBytes  = 0;
    uint64_t writeBytes = 0;
    uint64_t otherBytes = 0;
    uint64_t readOps    = 0;
    uint64_t writeOps   = 0;
    uint64_t otherOps   = 0;

    DiskIoCounters& operator+=(const DiskIoCounters& other) noexcept {
        readBytes  += other.readBytes;
        writeBytes += other.writeBytes;
        otherBytes += other.otherBytes;
        readOps    += other.readOps;
        writeOps   += other.writeOps;
        otherOps   += other.otherOps;
        return *this;
    }
};

/**
 * @brief Computed disk usage metrics for a process.
 */
struct ProcessDiskUsage {
    uint32_t     processId   = 0;
    std::wstring processName;

    double readBytesPerSec  = 0.0;
    double writeBytesPerSec = 0.0;
    double readOpsPerSec    = 0.0;
    double writeOpsPerSec   = 0.0;
    double otherOpsPerSec   = 0.0;

    uint64_t totalReadBytes  = 0;
    uint64_t totalWriteBytes = 0;

    bool highWriteRate       = false;
    bool highFileEnumeration = false;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Ransomware behavioral alert (sustained high writes).
 */
struct RansomwareAlert {
    uint32_t     processId                     = 0;
    std::wstring processName;
    double       sustainedWriteBytesPerSec     = 0.0;
    uint32_t     sustainedDurationSamples      = 0;
    uint64_t     totalBytesWrittenDuringWindow = 0;
    TimePoint    detectedAt;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief File enumeration storm alert (sustained high other-ops).
 */
struct FileEnumAlert {
    uint32_t     processId                = 0;
    std::wstring processName;
    double       sustainedOtherOpsPerSec  = 0.0;
    uint32_t     sustainedDurationSamples = 0;
    TimePoint    detectedAt;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Per-volume drive information with consumption rate.
 */
struct DriveInfo {
    std::wstring mountPoint;
    std::wstring volumeName;
    std::wstring fileSystem;
    uint64_t totalBytes            = 0;
    uint64_t freeBytes             = 0;
    uint64_t availableBytes        = 0;
    double   usagePercent          = 0.0;
    double   freeBytesDeltaPerSec  = 0.0;
    bool     isSystemDrive         = false;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Global disk I/O statistics.
 */
struct DiskGlobalStats {
    double   totalReadBytesPerSec  = 0.0;
    double   totalWriteBytesPerSec = 0.0;
    double   totalReadOpsPerSec    = 0.0;
    double   totalWriteOpsPerSec   = 0.0;
    uint32_t activeProcesses       = 0;
    TimePoint timestamp;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Disk monitor configuration.
 */
struct DiskMonitorConfig {
    bool     enabled                      = true;
    uint32_t pollingIntervalMs            = DiskConstants::DEFAULT_POLLING_INTERVAL_MS;
    bool     enableProcessMonitoring      = true;
    bool     enableDriveSpaceMonitoring   = true;
    bool     enableSelfMonitoring         = true;

    uint64_t ransomwareWriteThresholdBps  = 50ULL * 1024 * 1024;
    uint32_t ransomwareSustainedWindowSec = DiskConstants::DEFAULT_SUSTAINED_WINDOW_SEC;
    uint32_t fileEnumThresholdOpsPerSec   = DiskConstants::DEFAULT_FILE_ENUM_THRESHOLD_OPS;
    uint32_t fileEnumSustainedWindowSec   = DiskConstants::DEFAULT_FILE_ENUM_WINDOW_SEC;
    uint32_t highIoProcessCountLimit      = 10;
    double   lowSpaceThresholdPercent     = DiskConstants::DEFAULT_LOW_SPACE_PERCENT;
    uint64_t lowSpaceThresholdBytes       = DiskConstants::DEFAULT_LOW_SPACE_BYTES;
    size_t   maxTrackedProcesses          = DiskConstants::MAX_TRACKED_PROCESSES;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Module statistics snapshot (plain types — safe to copy/return by value).
 */
struct DiskMonitorModuleStats {
    uint64_t cyclesCompleted           = 0;
    uint64_t alertsTriggered           = 0;
    uint64_t errorsEncountered         = 0;
    uint64_t processesTracked          = 0;
    uint64_t ransomwareAlertsTriggered = 0;
    uint64_t fileEnumAlertsTriggered   = 0;
    double   uptimeSeconds             = 0.0;

    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACKS
// ============================================================================
using HighIoCallback     = std::function<void(const ProcessDiskUsage&)>;
using LowSpaceCallback   = std::function<void(const DriveInfo&)>;
using RansomwareCallback = std::function<void(const RansomwareAlert&)>;
using FileEnumCallback   = std::function<void(const FileEnumAlert&)>;

// ============================================================================
// DISK MONITOR CLASS
// ============================================================================

/**
 * @class DiskMonitor
 * @brief Singleton class for monitoring system disk activity.
 *
 * Thread-safe. All public accessors may be called concurrently.
 * Registered callbacks are invoked from the monitor thread — they
 * must be non-blocking and exception-safe.
 */
class DiskMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    [[nodiscard]] static DiskMonitor& Instance() noexcept;

    DiskMonitor(const DiskMonitor&)            = delete;
    DiskMonitor& operator=(const DiskMonitor&) = delete;
    DiskMonitor(DiskMonitor&&)                 = delete;
    DiskMonitor& operator=(DiskMonitor&&)      = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    [[nodiscard]] bool Initialize(const DiskMonitorConfig& config);
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    void UpdateConfig(const DiskMonitorConfig& config);
    [[nodiscard]] DiskMonitorConfig GetConfig() const;

    // ========================================================================
    // DATA ACCESS
    // ========================================================================

    /** @brief Get disk usage for a specific process. */
    [[nodiscard]] std::optional<ProcessDiskUsage> GetProcessUsage(uint32_t pid) const;

    /** @brief Get top consumers by total throughput (read + write B/s). */
    [[nodiscard]] std::vector<ProcessDiskUsage> GetTopConsumers(size_t count = 5) const;

    /** @brief Get global disk I/O statistics. */
    [[nodiscard]] DiskGlobalStats GetGlobalStats() const;

    /** @brief Get drive space information for all fixed drives. */
    [[nodiscard]] std::vector<DriveInfo> GetDriveInfo() const;

    /** @brief Get the EDR agent's own I/O usage (always available). */
    [[nodiscard]] std::optional<ProcessDiskUsage> GetSelfIoUsage() const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================
    void RegisterHighIoCallback(HighIoCallback callback);
    void RegisterLowSpaceCallback(LowSpaceCallback callback);
    void RegisterRansomwareCallback(RansomwareCallback callback);
    void RegisterFileEnumCallback(FileEnumCallback callback);
    void UnregisterCallbacks() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================
    [[nodiscard]] DiskMonitorModuleStats GetModuleStats() const;
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DiskMonitor();
    ~DiskMonitor();

    std::unique_ptr<DiskMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

} // namespace Performance
} // namespace ShadowStrike
