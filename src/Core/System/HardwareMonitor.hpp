/**
 * ============================================================================
 * ShadowStrike Core System - HARDWARE MONITOR (The System Sensor)
 * ============================================================================
 *
 * @file HardwareMonitor.hpp
 * @brief Enterprise-grade hardware health and environmental monitoring.
 *
 * This module provides comprehensive hardware monitoring capabilities
 * including disk health (S.M.A.R.T.), thermal management, power state
 * awareness, and hardware anomaly detection.
 *
 * Key Capabilities:
 * =================
 * 1. DISK HEALTH MONITORING
 *    - S.M.A.R.T. attribute analysis
 *    - Predictive failure detection
 *    - SSD wear level tracking
 *    - NVMe health status
 *
 * 2. THERMAL MONITORING
 *    - CPU temperature
 *    - GPU temperature
 *    - Disk temperature
 *    - Thermal throttling detection
 *
 * 3. POWER MANAGEMENT
 *    - AC/Battery detection
 *    - Battery health/capacity
 *    - Power plan awareness
 *    - UPS detection
 *
 * 4. HARDWARE ANOMALY DETECTION
 *    - New device insertion
 *    - Hardware configuration changes
 *    - Suspicious devices
 *    - Firmware version changes
 *
 * Security Relevance:
 * ===================
 * - Adjust scan intensity based on thermal/power state
 * - Detect hardware-based attacks (BadUSB, etc.)
 * - Monitor for firmware tampering
 * - Optimize AV performance based on hardware
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see SystemInfo.hpp for system identification
 * @see PerformanceMonitor.hpp for resource usage
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>
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
class HardwareMonitorImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum DiskType
 * @brief Type of storage device.
 */
enum class DiskType : uint8_t {
    Unknown = 0,
    HDD = 1,                       // Magnetic hard drive
    SSD_SATA = 2,                  // SATA SSD
    SSD_NVMe = 3,                  // NVMe SSD
    USB = 4,                       // USB storage
    SD = 5,                        // SD card
    Virtual = 6                    // Virtual disk
};

/**
 * @enum DiskHealthStatus
 * @brief Overall health status of disk.
 */
enum class DiskHealthStatus : uint8_t {
    Unknown = 0,
    Healthy = 1,
    Warning = 2,                   // Some concerns
    Critical = 3,                  // Failure imminent
    Failed = 4                     // Already failing
};

/**
 * @enum PowerSource
 * @brief Current power source.
 */
enum class PowerSource : uint8_t {
    Unknown = 0,
    ACPower = 1,
    Battery = 2,
    UPS = 3
};

/**
 * @enum BatteryStatus
 * @brief Battery charging status.
 */
enum class BatteryStatus : uint8_t {
    Unknown = 0,
    Charging = 1,
    Discharging = 2,
    Full = 3,
    NotPresent = 4
};

/**
 * @enum ThermalStatus
 * @brief Thermal condition.
 */
enum class ThermalStatus : uint8_t {
    Unknown = 0,
    Normal = 1,
    Warm = 2,                      // Above normal
    Hot = 3,                       // Throttling possible
    Critical = 4                   // Thermal emergency
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct SMARTAttribute
 * @brief Individual S.M.A.R.T. attribute.
 */
struct alignas(32) SMARTAttribute {
    uint8_t id{ 0 };
    std::wstring name;
    uint8_t currentValue{ 0 };
    uint8_t worstValue{ 0 };
    uint8_t threshold{ 0 };
    uint64_t rawValue{ 0 };
    bool isCritical{ false };
    bool isPreFail{ false };
};

/**
 * @struct DiskHealthInfo
 * @brief Comprehensive disk health information.
 */
struct alignas(256) DiskHealthInfo {
    // Identity
    std::wstring devicePath;
    std::wstring model;
    std::wstring serialNumber;
    std::wstring firmwareVersion;
    DiskType diskType{ DiskType::Unknown };
    
    // Capacity
    uint64_t totalBytes{ 0 };
    uint64_t freeBytes{ 0 };
    
    // Health
    DiskHealthStatus healthStatus{ DiskHealthStatus::Unknown };
    uint8_t healthPercent{ 0 };       // 0-100%
    uint32_t temperatureCelsius{ 0 };
    
    // S.M.A.R.T.
    bool smartSupported{ false };
    bool smartEnabled{ false };
    std::vector<SMARTAttribute> smartAttributes;
    
    // SSD specific
    uint64_t totalHostWrites{ 0 };    // Total bytes written
    uint8_t wearLevelPercent{ 0 };    // SSD wear level
    uint64_t powerOnHours{ 0 };
    uint32_t powerCycleCount{ 0 };
    
    // NVMe specific
    uint8_t availableSpare{ 0 };
    uint8_t availableSpareThreshold{ 0 };
    uint8_t percentageUsed{ 0 };
    
    // Prediction
    bool failurePredicted{ false };
    std::chrono::system_clock::time_point predictedFailureDate;
    std::wstring failureReason;
};

/**
 * @struct CPUThermalInfo
 * @brief CPU thermal information.
 */
struct alignas(64) CPUThermalInfo {
    std::vector<uint32_t> coreTemperatures;  // Per-core temps
    uint32_t packageTemperature{ 0 };
    uint32_t maxTemperature{ 0 };
    uint32_t throttleTemperature{ 0 };
    ThermalStatus thermalStatus{ ThermalStatus::Unknown };
    bool isThrottling{ false };
    double throttlePercent{ 0.0 };
};

/**
 * @struct GPUThermalInfo
 * @brief GPU thermal information.
 */
struct alignas(64) GPUThermalInfo {
    std::wstring gpuName;
    uint32_t temperature{ 0 };
    uint32_t maxTemperature{ 0 };
    ThermalStatus thermalStatus{ ThermalStatus::Unknown };
    bool isThrottling{ false };
    uint32_t fanSpeedRPM{ 0 };
    uint8_t fanSpeedPercent{ 0 };
};

/**
 * @struct BatteryInfo
 * @brief Battery status information.
 */
struct alignas(64) BatteryInfo {
    bool hasBattery{ false };
    BatteryStatus status{ BatteryStatus::Unknown };
    uint8_t chargePercent{ 0 };       // 0-100%
    uint32_t estimatedMinutesRemaining{ 0 };
    uint32_t estimatedMinutesToFullCharge{ 0 };
    
    // Health
    uint32_t designCapacityMWh{ 0 };
    uint32_t fullChargeCapacityMWh{ 0 };
    uint8_t healthPercent{ 0 };       // Based on capacity degradation
    uint32_t cycleCount{ 0 };
    
    // Power
    int32_t currentPowerMW{ 0 };      // Negative = discharging
    uint32_t voltageMV{ 0 };
};

/**
 * @struct PowerInfo
 * @brief System power information.
 */
struct alignas(128) PowerInfo {
    PowerSource powerSource{ PowerSource::Unknown };
    BatteryInfo battery;
    
    // Power plan
    std::wstring activePowerPlan;
    bool isHighPerformance{ false };
    bool isPowerSaver{ false };
    
    // UPS (if detected)
    bool hasUPS{ false };
    std::wstring upsModel;
    uint8_t upsBatteryPercent{ 0 };
    uint32_t upsRuntimeMinutes{ 0 };
};

/**
 * @struct HardwareChangeEvent
 * @brief Hardware configuration change event.
 */
struct alignas(64) HardwareChangeEvent {
    std::wstring changeType;          // "DeviceAdded", "DeviceRemoved", etc.
    std::wstring deviceClass;
    std::wstring deviceName;
    std::wstring deviceId;
    std::chrono::system_clock::time_point timestamp;
    bool isSuspicious{ false };
    std::wstring suspicionReason;
};

/**
 * @struct HardwareMonitorConfig
 * @brief Configuration for hardware monitor.
 */
struct alignas(32) HardwareMonitorConfig {
    bool monitorDisks{ true };
    bool monitorThermals{ true };
    bool monitorPower{ true };
    bool monitorDeviceChanges{ true };
    uint32_t pollingIntervalMs{ 5000 };
    
    // Thresholds
    uint32_t diskTempWarningCelsius{ 50 };
    uint32_t diskTempCriticalCelsius{ 60 };
    uint32_t cpuTempWarningCelsius{ 80 };
    uint32_t cpuTempCriticalCelsius{ 95 };
    uint8_t batteryLowPercent{ 20 };
    uint8_t batteryCriticalPercent{ 10 };
    
    static HardwareMonitorConfig CreateDefault() noexcept;
};

/**
 * @struct HardwareMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) HardwareMonitorStatistics {
    std::atomic<uint64_t> pollingCycles{ 0 };
    std::atomic<uint64_t> diskHealthChecks{ 0 };
    std::atomic<uint64_t> thermalWarnings{ 0 };
    std::atomic<uint64_t> powerStateChanges{ 0 };
    std::atomic<uint64_t> deviceChanges{ 0 };
    
    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DiskHealthCallback = std::function<void(const DiskHealthInfo& info)>;
using ThermalAlertCallback = std::function<void(ThermalStatus status, uint32_t temperature)>;
using PowerChangeCallback = std::function<void(const PowerInfo& info)>;
using HardwareChangeCallback = std::function<void(const HardwareChangeEvent& event)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class HardwareMonitor
 * @brief Enterprise-grade hardware health monitoring.
 *
 * Thread-safe singleton providing comprehensive hardware monitoring
 * with alerting and anomaly detection.
 */
class HardwareMonitor {
public:
    /**
     * @brief Gets singleton instance.
     */
    static HardwareMonitor& Instance();
    
    /**
     * @brief Initializes hardware monitor.
     */
    bool Initialize(const HardwareMonitorConfig& config);
    
    /**
     * @brief Shuts down hardware monitor.
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
    
    /**
     * @brief Forces immediate refresh.
     */
    void Refresh();
    
    // ========================================================================
    // DISK HEALTH
    // ========================================================================
    
    /**
     * @brief Gets health info for all disks.
     */
    [[nodiscard]] std::vector<DiskHealthInfo> GetDiskHealth() const;
    
    /**
     * @brief Gets health info for specific disk.
     */
    [[nodiscard]] std::optional<DiskHealthInfo> GetDiskHealth(
        const std::wstring& devicePath) const;
    
    /**
     * @brief Checks if any disk has health issues.
     */
    [[nodiscard]] bool HasDiskHealthIssues() const;
    
    /**
     * @brief Gets disks with predicted failures.
     */
    [[nodiscard]] std::vector<DiskHealthInfo> GetFailingDisks() const;
    
    // ========================================================================
    // THERMAL MONITORING
    // ========================================================================
    
    /**
     * @brief Gets CPU thermal info.
     */
    [[nodiscard]] CPUThermalInfo GetCPUThermal() const;
    
    /**
     * @brief Gets GPU thermal info (if available).
     */
    [[nodiscard]] std::optional<GPUThermalInfo> GetGPUThermal() const;
    
    /**
     * @brief Gets overall thermal status.
     */
    [[nodiscard]] ThermalStatus GetThermalStatus() const;
    
    /**
     * @brief Checks if system is thermally throttling.
     */
    [[nodiscard]] bool IsThrottling() const;
    
    // ========================================================================
    // POWER MONITORING
    // ========================================================================
    
    /**
     * @brief Gets power information.
     */
    [[nodiscard]] PowerInfo GetPowerInfo() const;
    
    /**
     * @brief Checks if on battery power.
     */
    [[nodiscard]] bool IsOnBattery() const;
    
    /**
     * @brief Checks if battery is low.
     */
    [[nodiscard]] bool IsBatteryLow() const;
    
    /**
     * @brief Gets battery charge percentage.
     */
    [[nodiscard]] uint8_t GetBatteryPercent() const;
    
    // ========================================================================
    // DEVICE CHANGES
    // ========================================================================
    
    /**
     * @brief Gets recent hardware changes.
     */
    [[nodiscard]] std::vector<HardwareChangeEvent> GetRecentChanges(
        uint32_t maxEvents = 100) const;
    
    /**
     * @brief Clears hardware change history.
     */
    void ClearChangeHistory();
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Registers disk health callback.
     */
    uint64_t RegisterDiskHealthCallback(DiskHealthCallback callback);
    
    /**
     * @brief Unregisters disk health callback.
     */
    void UnregisterDiskHealthCallback(uint64_t callbackId);
    
    /**
     * @brief Registers thermal alert callback.
     */
    uint64_t RegisterThermalAlertCallback(ThermalAlertCallback callback);
    
    /**
     * @brief Unregisters thermal alert callback.
     */
    void UnregisterThermalAlertCallback(uint64_t callbackId);
    
    /**
     * @brief Registers power change callback.
     */
    uint64_t RegisterPowerChangeCallback(PowerChangeCallback callback);
    
    /**
     * @brief Unregisters power change callback.
     */
    void UnregisterPowerChangeCallback(uint64_t callbackId);
    
    /**
     * @brief Registers hardware change callback.
     */
    uint64_t RegisterHardwareChangeCallback(HardwareChangeCallback callback);
    
    /**
     * @brief Unregisters hardware change callback.
     */
    void UnregisterHardwareChangeCallback(uint64_t callbackId);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    [[nodiscard]] const HardwareMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    HardwareMonitor();
    ~HardwareMonitor();
    
    HardwareMonitor(const HardwareMonitor&) = delete;
    HardwareMonitor& operator=(const HardwareMonitor&) = delete;
    
    std::unique_ptr<HardwareMonitorImpl> m_impl;
};

}  // namespace System
}  // namespace Core
}  // namespace ShadowStrike
