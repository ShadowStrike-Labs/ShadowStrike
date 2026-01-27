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
 *    - Latency tracking (where available via ETW/PDH)
 *
 * 2. PROCESS ATTRIBUTION
 *    - Per-process I/O tracking
 *    - Top consumer identification
 *    - I/O priority analysis
 *
 * 3. ANOMALY DETECTION
 *    - Ransomware-like write pattern detection
 *    - Massive file enumeration detection
 *    - Hidden stream (ADS) activity monitoring
 *
 * 4. STORAGE HEALTH
 *    - Free space monitoring
 *    - Drive availability tracking
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
#include <map>
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
    constexpr uint32_t DEFAULT_POLLING_INTERVAL_MS = 1000;
    constexpr uint32_t MIN_POLLING_INTERVAL_MS = 100;
    constexpr uint32_t MAX_POLLING_INTERVAL_MS = 60000;
    constexpr size_t MAX_HISTORY_POINTS = 60; // Keep last 60 seconds
}

// ============================================================================
// TYPE ALIASES
// ============================================================================
using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Raw I/O counters for a specific snapshot
 */
struct DiskIoCounters {
    uint64_t readBytes = 0;
    uint64_t writeBytes = 0;
    uint64_t otherBytes = 0;
    uint64_t readOps = 0;
    uint64_t writeOps = 0;
    uint64_t otherOps = 0;

    DiskIoCounters& operator+=(const DiskIoCounters& other) {
        readBytes += other.readBytes;
        writeBytes += other.writeBytes;
        otherBytes += other.otherBytes;
        readOps += other.readOps;
        writeOps += other.writeOps;
        otherOps += other.otherOps;
        return *this;
    }
};

/**
 * @brief Computed disk usage metrics for a process
 */
struct ProcessDiskUsage {
    uint32_t processId = 0;
    std::wstring processName;

    // Rates (per second)
    double readBytesPerSec = 0.0;
    double writeBytesPerSec = 0.0;
    double readOpsPerSec = 0.0;
    double writeOpsPerSec = 0.0;

    // Totals since monitoring start (or process start)
    uint64_t totalReadBytes = 0;
    uint64_t totalWriteBytes = 0;

    // Risk indicators
    bool highWriteRate = false;      // Potential ransomware indicator
    bool highFileEnumeration = false; // Potential scan indicator

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Drive information
 */
struct DriveInfo {
    std::wstring mountPoint;     // e.g. "C:\"
    std::wstring volumeName;     // e.g. "System"
    std::wstring fileSystem;     // e.g. "NTFS"
    uint64_t totalBytes = 0;
    uint64_t freeBytes = 0;
    uint64_t availableBytes = 0; // Available to user
    double usagePercent = 0.0;
    bool isSystemDrive = false;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Global disk statistics
 */
struct DiskGlobalStats {
    double totalReadBytesPerSec = 0.0;
    double totalWriteBytesPerSec = 0.0;
    double totalReadOpsPerSec = 0.0;
    double totalWriteOpsPerSec = 0.0;
    uint32_t activeProcesses = 0; // Number of processes with disk activity > 0
    TimePoint timestamp;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Disk monitor configuration
 */
struct DiskMonitorConfig {
    bool enabled = true;
    uint32_t pollingIntervalMs = DiskConstants::DEFAULT_POLLING_INTERVAL_MS;
    bool enableProcessMonitoring = true;
    bool enableDriveSpaceMonitoring = true;

    // Thresholds for alerts
    uint64_t ransomwareWriteThresholdBps = 50 * 1024 * 1024; // 50 MB/s sustained
    uint32_t highIoProcessCountLimit = 10;

    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Internal statistics for the module
 */
struct DiskMonitorModuleStats {
    std::atomic<uint64_t> cyclesCompleted{0};
    std::atomic<uint64_t> alertsTriggered{0};
    std::atomic<uint64_t> errorsEncountered{0};
    std::atomic<uint64_t> processesTracked{0};
    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACKS
// ============================================================================
using HighIoCallback = std::function<void(const ProcessDiskUsage&)>;
using LowSpaceCallback = std::function<void(const DriveInfo&)>;

// ============================================================================
// DISK MONITOR CLASS
// ============================================================================

/**
 * @class DiskMonitor
 * @brief Singleton class for monitoring system disk activity.
 */
class DiskMonitor final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    [[nodiscard]] static DiskMonitor& Instance() noexcept;

    // Non-copyable/movable
    DiskMonitor(const DiskMonitor&) = delete;
    DiskMonitor& operator=(const DiskMonitor&) = delete;
    DiskMonitor(DiskMonitor&&) = delete;
    DiskMonitor& operator=(DiskMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================
    [[nodiscard]] bool Initialize(const DiskMonitorConfig& config);
    void Shutdown();
    [[nodiscard]] bool IsInitialized() const noexcept;

    // ========================================================================
    // CONFIGURATION
    // ========================================================================
    void UpdateConfig(const DiskMonitorConfig& config);
    [[nodiscard]] DiskMonitorConfig GetConfig() const;

    // ========================================================================
    // DATA ACCESS
    // ========================================================================

    /**
     * @brief Get disk usage for a specific process
     * @param pid Process ID
     * @return Optional usage data (nullopt if process not found or no I/O)
     */
    [[nodiscard]] std::optional<ProcessDiskUsage> GetProcessUsage(uint32_t pid) const;

    /**
     * @brief Get top consumers by total throughput (Read+Write)
     * @param count Number of processes to return
     * @return Vector of top consumers
     */
    [[nodiscard]] std::vector<ProcessDiskUsage> GetTopConsumers(size_t count = 5) const;

    /**
     * @brief Get global disk I/O statistics
     */
    [[nodiscard]] DiskGlobalStats GetGlobalStats() const;

    /**
     * @brief Get drive space information
     */
    [[nodiscard]] std::vector<DriveInfo> GetDriveInfo() const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================
    void RegisterHighIoCallback(HighIoCallback callback);
    void RegisterLowSpaceCallback(LowSpaceCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================
    [[nodiscard]] DiskMonitorModuleStats GetModuleStats() const;
    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DiskMonitor();
    ~DiskMonitor();

    // PIMPL idiom
    std::unique_ptr<DiskMonitorImpl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

} // namespace Performance
} // namespace ShadowStrike
