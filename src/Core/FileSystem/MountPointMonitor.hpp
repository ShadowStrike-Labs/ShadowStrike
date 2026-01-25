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
// ENUMERATIONS
// ============================================================================

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

    void Reset() noexcept;
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
 */
class MountPointMonitor {
public:
    static MountPointMonitor& Instance();

    bool Initialize(const MountPointMonitorConfig& config);
    void Shutdown() noexcept;

    /**
     * @brief Gets all currently mounted drives.
     */
    [[nodiscard]] std::vector<DriveInfo> GetMountedDrives() const;

    /**
     * @brief Gets drive info by letter.
     */
    [[nodiscard]] std::optional<DriveInfo> GetDriveInfo(wchar_t driveLetter) const;

    /**
     * @brief Gets device connection history.
     */
    [[nodiscard]] std::vector<DeviceHistoryEntry> GetDeviceHistory() const;

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
     * @brief Safely ejects a drive.
     */
    [[nodiscard]] bool EjectDrive(wchar_t driveLetter);

    void SetMountEventCallback(MountEventCallback callback);
    void SetPolicyCallback(DevicePolicyCallback callback);

    [[nodiscard]] const MountPointMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    MountPointMonitor();
    ~MountPointMonitor();

    MountPointMonitor(const MountPointMonitor&) = delete;
    MountPointMonitor& operator=(const MountPointMonitor&) = delete;

    std::unique_ptr<MountPointMonitorImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
