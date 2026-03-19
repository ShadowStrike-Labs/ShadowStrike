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
#include "../../Utils/Logger.hpp"             // Logging

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
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace DirectoryMonitorConstants {

    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    /// @brief Maximum concurrent monitors
    inline constexpr size_t MAX_CONCURRENT_MONITORS = 1000;

    /// @brief Event queue capacity per monitor
    inline constexpr size_t EVENT_QUEUE_CAPACITY = 10000;

    /// @brief Event processing timeout (milliseconds)
    inline constexpr uint32_t EVENT_TIMEOUT_MS = 100;

    /// @brief Rate limiting window (seconds)
    inline constexpr uint32_t RATE_LIMIT_WINDOW_SEC = 60;

    /// @brief Maximum events per path per window
    inline constexpr uint32_t MAX_EVENTS_PER_PATH_PER_WINDOW = 1000;

}  // namespace DirectoryMonitorConstants

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

/**
 * @enum DirectoryMonitorStatus
 * @brief Status of directory monitor.
 */
enum class DirectoryMonitorStatus : uint8_t {
    Uninitialized = 0,
    Initializing = 1,
    Running = 2,
    Paused = 3,
    Error = 4,
    Stopping = 5,
    Stopped = 6
};

/**
 * @enum FileSystemAction
 * @brief Type of file system action detected.
 */
enum class FileSystemAction : uint32_t {
    Unknown = 0,
    FileAdded = 1,
    FileRemoved = 2,
    FileModified = 3,
    FileRenamed = 4,
    DirectoryAdded = 5,
    DirectoryRemoved = 6,
    DirectoryRenamed = 7
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
    TimePoint lastEvent;
    TimePoint createdTime;

    [[nodiscard]] std::string ToJson() const;
};

/**
 * @struct DirectoryMonitorConfig
 * @brief Configuration for directory monitor.
 */
struct alignas(32) DirectoryMonitorConfig {
    bool enabled{ true };
    bool monitorSystemPaths{ true };
    bool monitorUserPaths{ true };
    bool monitorStartupLocations{ true };
    bool monitorTempDirectories{ true };
    bool monitorRemovableMedia{ true };
    bool monitorNetworkShares{ false };
    bool autoDiscoverNewPaths{ true };
    bool enableRateLimiting{ true };
    bool enableIntelligentFiltering{ true };

    uint32_t maxConcurrentMonitors{ DirectoryMonitorConstants::MAX_CONCURRENT_MONITORS };
    uint32_t eventQueueCapacity{ DirectoryMonitorConstants::EVENT_QUEUE_CAPACITY };
    uint32_t rateLimitWindowSec{ DirectoryMonitorConstants::RATE_LIMIT_WINDOW_SEC };
    uint32_t maxEventsPerWindow{ DirectoryMonitorConstants::MAX_EVENTS_PER_PATH_PER_WINDOW };

    std::vector<std::wstring> additionalPaths;
    std::vector<std::wstring> excludedPaths;

    [[nodiscard]] static DirectoryMonitorConfig CreateDefault() noexcept;
    [[nodiscard]] static DirectoryMonitorConfig CreateHighSecurity() noexcept;
    [[nodiscard]] bool IsValid() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @struct DirectoryMonitorStatistics
 * @brief Runtime statistics.
 */
struct alignas(64) DirectoryMonitorStatistics {
    std::atomic<uint32_t> activeMonitors{ 0 };
    std::atomic<uint64_t> totalEvents{ 0 };
    std::atomic<uint64_t> filteredEvents{ 0 };
    std::atomic<uint64_t> rateLimitedEvents{ 0 };
    std::atomic<uint64_t> errors{ 0 };
    std::atomic<uint64_t> callbackInvocations{ 0 };
    std::atomic<uint64_t> pathsDiscovered{ 0 };
    std::atomic<uint64_t> totalProcessingTimeUs{ 0 };

    std::array<std::atomic<uint64_t>, 10> byCategory{};  // Per PathCategory
    std::array<std::atomic<uint64_t>, 8> byAction{};      // Per FileSystemAction

    TimePoint startTime = Clock::now();

    void Reset() noexcept;
    [[nodiscard]] double GetAverageProcessingTimeMs() const noexcept;
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @struct DirectoryEvent
 * @brief File system event information.
 */
struct DirectoryEvent {
    uint64_t eventId{ 0 };
    uint32_t monitorId{ 0 };
    std::wstring path;
    std::wstring filename;
    std::wstring oldFilename;  // For renames
    FileSystemAction action{ FileSystemAction::Unknown };
    PathCategory category{ PathCategory::Unknown };
    SystemTimePoint timestamp;

    [[nodiscard]] std::string ToJson() const;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

using DirectoryEventCallback = std::function<void(const DirectoryEvent& event)>;
using MonitorStatusCallback = std::function<void(uint32_t monitorId, bool active)>;
using ErrorCallback = std::function<void(const std::wstring& path, const std::string& error)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class DirectoryMonitor
 * @brief High-level directory monitoring orchestrator.
 *
 * Thread-safe singleton providing enterprise-grade directory monitoring
 * with intelligent filtering, automatic critical path discovery, and
 * seamless integration with ShadowStrike detection engines.
 */
class DirectoryMonitor final {
public:
    [[nodiscard]] static DirectoryMonitor& Instance() noexcept;
    [[nodiscard]] static bool HasInstance() noexcept;

    DirectoryMonitor(const DirectoryMonitor&) = delete;
    DirectoryMonitor& operator=(const DirectoryMonitor&) = delete;
    DirectoryMonitor(DirectoryMonitor&&) = delete;
    DirectoryMonitor& operator=(DirectoryMonitor&&) = delete;

    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    [[nodiscard]] bool Initialize(const DirectoryMonitorConfig& config = {});
    void Shutdown() noexcept;
    [[nodiscard]] bool IsInitialized() const noexcept;
    [[nodiscard]] DirectoryMonitorStatus GetStatus() const noexcept;

    // ========================================================================
    // MONITOR MANAGEMENT
    // ========================================================================

    /**
     * @brief Starts monitoring all critical system paths.
     */
    void MonitorCriticalPaths();

    /**
     * @brief Starts monitoring specific path.
     */
    [[nodiscard]] uint32_t AddMonitor(const std::wstring& path,
                                       PathCategory category = PathCategory::Custom,
                                       bool recursive = true);

    /**
     * @brief Removes monitor by ID.
     */
    void RemoveMonitor(uint32_t monitorId);

    /**
     * @brief Removes all monitors.
     */
    void RemoveAllMonitors();

    /**
     * @brief Checks if path is currently monitored.
     */
    [[nodiscard]] bool IsMonitored(const std::wstring& path) const;

    /**
     * @brief Gets all monitored paths.
     */
    [[nodiscard]] std::vector<MonitoredPath> GetMonitoredPaths() const;

    /**
     * @brief Gets specific monitor by ID.
     */
    [[nodiscard]] std::optional<MonitoredPath> GetMonitorById(uint32_t monitorId) const;

    /**
     * @brief Gets count of active monitors.
     */
    [[nodiscard]] size_t GetActiveMonitorCount() const noexcept;

    // ========================================================================
    // MONITOR CONTROL
    // ========================================================================

    /**
     * @brief Pauses all monitoring.
     */
    void PauseAll() noexcept;

    /**
     * @brief Resumes all monitoring.
     */
    void ResumeAll() noexcept;

    /**
     * @brief Pauses specific monitor.
     */
    void PauseMonitor(uint32_t monitorId) noexcept;

    /**
     * @brief Resumes specific monitor.
     */
    void ResumeMonitor(uint32_t monitorId) noexcept;

    // ========================================================================
    // CALLBACKS
    // ========================================================================

    void SetEventCallback(DirectoryEventCallback callback);
    void SetMonitorStatusCallback(MonitorStatusCallback callback);
    void SetErrorCallback(ErrorCallback callback);
    void UnregisterCallbacks();

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    [[nodiscard]] DirectoryMonitorConfig GetConfiguration() const;
    void SetConfiguration(const DirectoryMonitorConfig& config);

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const DirectoryMonitorStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // TESTING & DIAGNOSTICS
    // ========================================================================

    [[nodiscard]] bool SelfTest();
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    DirectoryMonitor();
    ~DirectoryMonitor();

    // PIMPL - ALL implementation details hidden
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

[[nodiscard]] std::string_view GetPathCategoryName(PathCategory category) noexcept;
[[nodiscard]] std::string_view GetFileSystemActionName(FileSystemAction action) noexcept;
[[nodiscard]] std::string_view GetMonitorStatusName(DirectoryMonitorStatus status) noexcept;

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
