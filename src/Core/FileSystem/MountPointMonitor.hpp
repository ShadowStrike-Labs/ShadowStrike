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
 * ShadowStrike Core FileSystem - MOUNT POINT MONITOR (The Guardian Gate)
 * ============================================================================
 *
 * @file MountPointMonitor.hpp
 * @brief Enterprise-grade mount point and removable media security monitoring.
 *
 * This module provides comprehensive monitoring of mount points, removable
 * media, virtual drives, and network shares for security-relevant events.
 *
 * Key Capabilities:
 * =================
 * 1. DRIVE MONITORING
 *    - USB drive insertion/removal
 *    - CD/DVD media changes
 *    - Network share mounting
 *    - Virtual disk mounting (VHD/VHDX/ISO)
 *
 * 2. SECURITY POLICY ENFORCEMENT
 *    - Block unauthorized devices
 *    - Read-only enforcement
 *    - Device whitelisting
 *    - Autorun prevention
 *
 * 3. THREAT DETECTION
 *    - BadUSB detection
 *    - Rubber Ducky patterns
 *    - USB kill detection
 *    - Mass storage masquerading
 *
 * 4. FORENSIC LOGGING
 *    - Device serial tracking
 *    - First-seen timestamps
 *    - Usage history
 *    - File activity correlation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see DirectoryMonitor.hpp for path monitoring
 * @see FileWatcher.hpp for file change detection
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // Drive enumeration
#include "../../Utils/SystemUtils.hpp"        // Device info
#include "../../Whitelist/WhiteListStore.hpp" // Device whitelist

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
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class MountPointMonitorImpl;

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace MountPointMonitorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum tracked devices in history
    inline constexpr size_t MAX_DEVICE_HISTORY = 10000;

    /// @brief Event queue capacity
    inline constexpr size_t EVENT_QUEUE_CAPACITY = 1000;

    /// @brief Polling interval for drive enumeration (milliseconds)
    inline constexpr uint32_t POLLING_INTERVAL_MS = 1000;

}  // namespace MountPointMonitorConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum MountPointMonitorStatus
 * @brief Status of mount point monitor.
 */
enum class MountPointMonitorStatus : uint8_t {
    Uninitialized = 0,
    Initializing = 1,
    Running = 2,
    Paused = 3,
    Error = 4,
    Stopping = 5,
    Stopped = 6
};

/**
 * @enum DriveType
 * @brief Type of drive or mount point.
 */
enum class DriveType : uint8_t {
    Unknown = 0,
    Fixed = 1,                     // HDD/SSD
    Removable = 2,                 // USB
    Network = 3,                   // Network share
    CDRom = 4,                     // CD/DVD
    RAMDisk = 5,                   // RAM disk
    VirtualHardDisk = 6,           // VHD/VHDX
    ISOImage = 7                   // Mounted ISO
};

/**
 * @enum MountEvent
 * @brief Type of mount event.
 */
enum class MountEvent : uint8_t {
    DriveArrival = 1,
    DriveRemoval = 2,
    MediaInserted = 3,
    MediaRemoved = 4,
    NetworkConnected = 5,
    NetworkDisconnected = 6,
    VirtualMounted = 7,
    VirtualUnmounted = 8
};

/**
 * @enum DeviceThreatType
 * @brief Device threat classification.
 */
enum class DeviceThreatType : uint8_t {
    None = 0,
    BadUSB = 1,                    // HID masquerading
    RubberDucky = 2,               // Keystroke injection
    USBKill = 3,                   // Power surge device
    Masquerading = 4,              // Type spoofing
    Unauthorized = 5,              // Not whitelisted
    PolicyViolation = 6            // Policy breach
};

/**
 * @enum DevicePolicy
 * @brief Policy action for device.
 */
enum class DevicePolicy : uint8_t {
    Allow = 0,
    AllowReadOnly = 1,
    Block = 2,
    BlockAndAlert = 3,
    RequireApproval = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct DriveInfo
 * @brief Information about a mounted drive.
 */
struct alignas(128) DriveInfo {
    wchar_t driveLetter{ L'\0' };
    std::wstring devicePath;
    std::wstring volumeName;
    std::wstring fileSystem;
    DriveType driveType{ DriveType::Unknown };

    // USB device info
    std::wstring vendorId;
    std::wstring productId;
    std::wstring serialNumber;
    std::wstring friendlyName;

    // Capacity
    uint64_t totalBytes{ 0 };
    uint64_t freeBytes{ 0 };

    // Security
    bool isReadOnly{ false };
    bool isWhitelisted{ false };
    DeviceThreatType threatType{ DeviceThreatType::None };

    // Timestamps
    std::chrono::system_clock::time_point mountTime;
    std::chrono::system_clock::time_point firstSeen;
    uint32_t connectionCount{ 0 };
};

/**
 * @struct MountEventInfo
 * @brief Information about a mount event.
 */
struct alignas(64) MountEventInfo {
    MountEvent event{ MountEvent::DriveArrival };
    std::wstring path;
    DriveInfo driveInfo;
    std::chrono::system_clock::time_point timestamp;
    DevicePolicy appliedPolicy{ DevicePolicy::Allow };
};

/**
 * @struct DeviceHistoryEntry
 * @brief Historical device connection record.
 */
struct DeviceHistoryEntry {
    std::wstring serialNumber;
    std::wstring vendorId;
    std::wstring productId;
    std::wstring friendlyName;
    std::chrono::system_clock::time_point firstSeen;
    std::chrono::system_clock::time_point lastSeen;
    uint32_t connectionCount{ 0 };
    bool isWhitelisted{ false };
};

/**
 * @struct MountPointMonitorConfig
 * @brief Configuration for mount point monitor.
 */
struct alignas(32) MountPointMonitorConfig {
    bool monitorUSB{ true };
    bool monitorNetwork{ true };
    bool monitorVirtual{ true };
    bool enforceWhitelist{ false };
    bool blockAutorun{ true };
    bool detectBadUSB{ true };

    DevicePolicy defaultRemovablePolicy{ DevicePolicy::Allow };
    DevicePolicy defaultNetworkPolicy{ DevicePolicy::Allow };

    static MountPointMonitorConfig CreateDefault() noexcept;
    static MountPointMonitorConfig CreateHighSecurity() noexcept;
};

/**
 * @struct MountPointMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) MountPointMonitorStatistics {
    std::atomic<uint64_t> totalEvents{ 0 };
    std::atomic<uint64_t> devicesBlocked{ 0 };
    std::atomic<uint64_t> threatsDetected{ 0 };
    std::atomic<uint32_t> activeMounts{ 0 };
    std::atomic<uint64_t> usbConnections{ 0 };
    std::atomic<uint64_t> networkMounts{ 0 };
    std::atomic<uint64_t> virtualMounts{ 0 };
    std::atomic<uint64_t> autorunBlocked{ 0 };
    std::atomic<uint64_t> errors{ 0 };
    std::atomic<uint64_t> totalProcessingTimeUs{ 0 };

    std::array<std::atomic<uint64_t>, 8> byDriveType{};  // Per DriveType
    std::array<std::atomic<uint64_t>, 8> byEventType{};  // Per MountEvent

    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] double GetAverageProcessingTimeMs() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using MountEventCallback = std::function<void(const MountEventInfo& event)>;
using DevicePolicyCallback = std::function<DevicePolicy(const DriveInfo& device)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class MountPointMonitor
 * @brief Enterprise-grade mount point security monitor.
 *
 * Thread-safe singleton providing comprehensive monitoring of removable media,
 * network shares, and virtual drives with security policy enforcement and
 * threat detection capabilities.
 */
class MountPointMonitor final {
public:
    [[nodiscard]] static MountPointMonitor& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    MountPointMonitor(const MountPointMonitor&) = delete;
    MountPointMonitor& operator=(const MountPointMonitor&) = delete;
    MountPointMonitor(MountPointMonitor&&) = delete;
    MountPointMonitor& operator=(MountPointMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const MountPointMonitorConfig& config = {});
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] MountPointMonitorStatus GetStatus() const noexcept;

    /**
     * @brief Starts monitoring for mount point changes.
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stops monitoring.
     */
    void Stop() noexcept;

    /**
     * @brief Checks if monitor is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // DRIVE ENUMERATION
    // ========================================================================

    /**
     * @brief Gets all currently mounted drives.
     */
    [[nodiscard]] std::vector<DriveInfo> GetMountedDrives() const;

    /**
     * @brief Gets drive info by letter.
     */
    [[nodiscard]] std::optional<DriveInfo> GetDriveInfo(wchar_t driveLetter) const;

    /**
     * @brief Gets all removable drives.
     */
    [[nodiscard]] std::vector<DriveInfo> GetRemovableDrives() const;

    /**
     * @brief Gets all network drives.
     */
    [[nodiscard]] std::vector<DriveInfo> GetNetworkDrives() const;

    /**
     * @brief Refreshes drive enumeration.
     */
    void RefreshDriveList();

    // ========================================================================
    // DEVICE HISTORY AND TRACKING
    // ========================================================================

    /**
     * @brief Gets device connection history.
     */
    [[nodiscard]] std::vector<DeviceHistoryEntry> GetDeviceHistory() const;

    /**
     * @brief Gets history for specific device.
     */
    [[nodiscard]] std::optional<DeviceHistoryEntry> GetDeviceHistory(const std::wstring& serialNumber) const;

    /**
     * @brief Clears device history.
     */
    void ClearDeviceHistory();

    // ========================================================================
    // WHITELIST MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds device to whitelist.
     */
    void WhitelistDevice(const std::wstring& serialNumber);

    /**
     * @brief Removes device from whitelist.
     */
    void RemoveFromWhitelist(const std::wstring& serialNumber);

    /**
     * @brief Checks if device is whitelisted.
     */
    [[nodiscard]] bool IsWhitelisted(const std::wstring& serialNumber) const;

    /**
     * @brief Gets all whitelisted devices.
     */
    [[nodiscard]] std::vector<std::wstring> GetWhitelistedDevices() const;

    // ========================================================================
    // DEVICE CONTROL
    // ========================================================================

    /**
     * @brief Safely ejects a drive.
     */
    [[nodiscard]] bool EjectDrive(wchar_t driveLetter);

    /**
     * @brief Blocks a specific drive.
     */
    [[nodiscard]] bool BlockDrive(wchar_t driveLetter);

    /**
     * @brief Sets drive to read-only.
     */
    [[nodiscard]] bool SetReadOnly(wchar_t driveLetter, bool readOnly);

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetMountEventCallback(MountEventCallback callback);
    void SetPolicyCallback(DevicePolicyCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] MountPointMonitorConfig GetConfiguration() const;
    void SetConfiguration(const MountPointMonitorConfig& config);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const MountPointMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // TESTING & DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    MountPointMonitor();
    ~MountPointMonitor();

    // PIMPL - ALL implementation details hidden
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetDriveTypeName(DriveType type) noexcept;
[[nodiscard]] std::string_view GetMountEventName(MountEvent event) noexcept;
[[nodiscard]] std::string_view GetDeviceThreatTypeName(DeviceThreatType threat) noexcept;
[[nodiscard]] std::string_view GetDevicePolicyName(DevicePolicy policy) noexcept;
[[nodiscard]] std::string_view GetMonitorStatusName(MountPointMonitorStatus status) noexcept;

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
