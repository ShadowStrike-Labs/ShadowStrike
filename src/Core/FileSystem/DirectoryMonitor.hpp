/**
 * ============================================================================
 * ShadowStrike Core FileSystem - DIRECTORY MONITOR (The High-Level Watcher)
 * ============================================================================
 *
 * @file DirectoryMonitor.hpp
 * @brief Enterprise-grade high-level directory monitoring orchestrator.
 *
 * This module provides intelligent directory monitoring that wraps FileWatcher
 * with automatic management of critical paths, dynamic path discovery, and
 * security-focused filtering.
 *
 * Key Capabilities:
 * =================
 * 1. CRITICAL PATH MONITORING
 *    - System directories (System32, drivers)
 *    - User directories (AppData, Downloads)
 *    - Startup locations
 *    - Temporary directories
 *
 * 2. DYNAMIC DISCOVERY
 *    - New user profiles
 *    - Removable drives
 *    - Network shares
 *    - Cloud sync folders
 *
 * 3. INTELLIGENT FILTERING
 *    - Security-relevant changes only
 *    - Known-safe exclusions
 *    - Rate limiting per path
 *    - Priority-based processing
 *
 * 4. INTEGRATION
 *    - Scan engine triggering
 *    - Event correlation
 *    - Alert generation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see FileWatcher.hpp for low-level monitoring
 * @see MountPointMonitor.hpp for drive detection
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // Path operations
#include "../../Utils/SystemUtils.hpp"        // System paths
#include "../../Whitelist/WhiteListStore.hpp" // Excluded paths

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
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
class DirectoryMonitorImpl;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum PathCategory
 * @brief Category of monitored path.
 */
enum class PathCategory : uint8_t {
    Unknown = 0,
    SystemCritical = 1,            // System32, drivers
    UserProfile = 2,               // AppData, Documents
    Startup = 3,                   // Startup folders, Run keys
    Downloads = 4,                 // Download locations
    Temporary = 5,                 // Temp directories
    RemovableMedia = 6,            // USB drives
    NetworkShare = 7,              // Network paths
    CloudSync = 8,                 // OneDrive, Dropbox
    Custom = 9                     // User-defined
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct MonitoredPath
 * @brief Information about monitored path.
 */
struct alignas(64) MonitoredPath {
    uint32_t monitorId{ 0 };
    std::wstring path;
    PathCategory category{ PathCategory::Unknown };
    bool recursive{ true };
    bool isActive{ false };

    std::atomic<uint64_t> eventsReceived{ 0 };
    std::chrono::steady_clock::time_point lastEvent;
};

/**
 * @struct DirectoryMonitorConfig
 * @brief Configuration for directory monitor.
 */
struct alignas(32) DirectoryMonitorConfig {
    bool monitorSystemPaths{ true };
    bool monitorUserPaths{ true };
    bool monitorStartupLocations{ true };
    bool monitorTempDirectories{ true };
    bool monitorRemovableMedia{ true };
    bool monitorNetworkShares{ false };
    bool autoDiscoverNewPaths{ true };

    std::vector<std::wstring> additionalPaths;
    std::vector<std::wstring> excludedPaths;

    static DirectoryMonitorConfig CreateDefault() noexcept;
    static DirectoryMonitorConfig CreateHighSecurity() noexcept;
};

/**
 * @struct DirectoryMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) DirectoryMonitorStatistics {
    std::atomic<uint32_t> activeMonitors{ 0 };
    std::atomic<uint64_t> totalEvents{ 0 };
    std::atomic<uint64_t> filteredEvents{ 0 };

    void Reset() noexcept;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DirectoryEventCallback = std::function<void(const std::wstring& path, const std::wstring& filename, uint32_t action)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DirectoryMonitor
 * @brief High-level directory monitoring orchestrator.
 */
class DirectoryMonitor {
public:
    static DirectoryMonitor& Instance();

    bool Initialize(const DirectoryMonitorConfig& config);
    void Shutdown() noexcept;

    /**
     * @brief Starts monitoring all critical paths.
     */
    void MonitorCriticalPaths();

    /**
     * @brief Starts monitoring specific path.
     */
    [[nodiscard]] uint32_t AddMonitor(const std::wstring& path, PathCategory category, bool recursive = true);

    /**
     * @brief Removes monitor.
     */
    void RemoveMonitor(uint32_t monitorId);

    /**
     * @brief Checks if path is monitored.
     */
    [[nodiscard]] bool IsMonitored(const std::wstring& path) const;

    /**
     * @brief Gets all monitored paths.
     */
    [[nodiscard]] std::vector<MonitoredPath> GetMonitoredPaths() const;

    /**
     * @brief Pauses all monitoring.
     */
    void PauseAll() noexcept;

    /**
     * @brief Resumes all monitoring.
     */
    void ResumeAll() noexcept;

    void SetEventCallback(DirectoryEventCallback callback);

    [[nodiscard]] const DirectoryMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

private:
    DirectoryMonitor();
    ~DirectoryMonitor();

    DirectoryMonitor(const DirectoryMonitor&) = delete;
    DirectoryMonitor& operator=(const DirectoryMonitor&) = delete;

    std::unique_ptr<DirectoryMonitorImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
