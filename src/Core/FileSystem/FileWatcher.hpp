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
 * ShadowStrike Core FileSystem - FILE WATCHER (The Sentinel)
 * ============================================================================
 *
 * @file FileWatcher.hpp
 * @brief Enterprise-grade high-performance directory monitoring system.
 *
 * This module provides comprehensive file system monitoring using Windows I/O
 * Completion Ports (IOCP) and ReadDirectoryChangesW for maximum performance.
 * It serves as the user-mode companion to the kernel minifilter driver.
 *
 * Key Capabilities:
 * =================
 * 1. REAL-TIME MONITORING
 *    - IOCP-based asynchronous I/O
 *    - Zero-copy buffer management
 *    - Multi-directory support
 *    - Recursive monitoring
 *
 * 2. EVENT PROCESSING
 *    - Event debouncing/coalescing
 *    - Event filtering by type/pattern
 *    - Rate limiting
 *    - Event correlation
 *
 * 3. PERFORMANCE FEATURES
 *    - Lock-free event queue
 *    - Configurable thread pool
 *    - Memory pooling
 *    - Burst handling
 *
 * 4. SECURITY FEATURES
 *    - Ransomware pattern detection
 *    - Rapid modification detection
 *    - Exclusion management
 *    - Self-protection paths
 *
 * 5. INTEGRATION
 *    - Kernel minifilter fallback
 *    - Scan engine triggering
 *    - Alert generation
 *    - Statistics collection
 *
 * Architecture:
 * =============
 *   ┌─────────────────────────────────────────────────────────────────────┐
 *   │                         FileWatcher                                 │
 *   ├─────────────────────────────────────────────────────────────────────┤
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │  IOCP Pool   │  │EventProcessor│  │    CallbackDispatcher    │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - WorkerPool │  │ - Debounce   │  │ - Async dispatch         │  │
 *   │  │ - Completion │  │ - Filter     │  │ - Priority queue         │  │
 *   │  │ - Overlapped │  │ - Correlate  │  │ - Rate limit             │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   │                                                                     │
 *   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
 *   │  │WatchManager  │  │PatternEngine │  │    StatisticsCollector   │  │
 *   │  │              │  │              │  │                          │  │
 *   │  │ - Add/Remove │  │ - Glob       │  │ - Events/sec             │  │
 *   │  │ - Recursive  │  │ - Regex      │  │ - Latency                │  │
 *   │  │ - Validate   │  │ - Exclusion  │  │ - Memory                 │  │
 *   │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
 *   └─────────────────────────────────────────────────────────────────────┘
 *
 * Integration Points:
 * ===================
 * - ScanEngine: Trigger on-access scans
 * - FileReputation: Quick reputation checks
 * - RansomwareDetector: Rapid change detection
 * - Kernel Driver: Fallback and correlation
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1486: Data Encrypted for Impact
 * - T1485: Data Destruction
 * - T1565: Data Manipulation
 *
 * Thread Safety:
 * ==============
 * - All public methods are thread-safe
 * - Lock-free event queue
 * - IOCP provides thread safety
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright 2026 ShadowStrike Security Suite
 *
 * @see MountPointMonitor.hpp for drive monitoring
 * @see DirectoryMonitor.hpp for high-level management
 */

#pragma once

// ============================================================================
// INFRASTRUCTURE INCLUDES
// ============================================================================
#include "../../Utils/FileUtils.hpp"          // Path normalization
#include "../../Utils/StringUtils.hpp"        // Path pattern matching
#include "../../Utils/ThreadPool.hpp"         // Event processing
#include "../../Whitelist/WhiteListStore.hpp" // Excluded paths

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <optional>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <shared_mutex>
#include <thread>
#include <filesystem>

// Windows Headers
#include <windows.h>

namespace ShadowStrike {
namespace Core {
namespace FileSystem {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================
class FileWatcherImpl;  // PIMPL implementation

// ============================================================================
// NAMESPACE CONSTANTS
// ============================================================================
namespace FileWatcherConstants {

    // Version
    constexpr uint32_t VERSION_MAJOR = 3;
    constexpr uint32_t VERSION_MINOR = 0;
    constexpr uint32_t VERSION_PATCH = 0;

    // Limits
    constexpr size_t MAX_WATCHES = 1000;
    constexpr size_t MAX_PENDING_EVENTS = 100000;
    constexpr size_t MAX_PATH_LENGTH = 32767;

    // Buffer sizes
    constexpr size_t WATCH_BUFFER_SIZE = 64 * 1024;      // 64KB per watch
    constexpr size_t EVENT_QUEUE_SIZE = 10000;

    // Timing
    constexpr uint32_t DEFAULT_DEBOUNCE_MS = 100;
    constexpr uint32_t MIN_DEBOUNCE_MS = 10;
    constexpr uint32_t MAX_DEBOUNCE_MS = 5000;
    constexpr uint32_t DEFAULT_RATE_LIMIT_PER_SEC = 10000;

    // Worker threads
    constexpr uint32_t MIN_WORKER_THREADS = 1;
    constexpr uint32_t MAX_WORKER_THREADS = 16;
    constexpr uint32_t DEFAULT_WORKER_THREADS = 4;

}  // namespace FileWatcherConstants

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @enum FileAction
 * @brief Types of file system changes detected.
 */
enum class FileAction : uint8_t {
    Unknown = 0,
    Added = 1,                     // FILE_ACTION_ADDED
    Removed = 2,                   // FILE_ACTION_REMOVED
    Modified = 3,                  // FILE_ACTION_MODIFIED
    RenamedOldName = 4,            // FILE_ACTION_RENAMED_OLD_NAME
    RenamedNewName = 5,            // FILE_ACTION_RENAMED_NEW_NAME
    SecurityChanged = 6,           // Custom: ACL changes
    AttributesChanged = 7,         // Custom: Attribute changes
    StreamAdded = 8,               // Alternate data stream
    StreamRemoved = 9,
    StreamModified = 10
};

/**
 * @enum WatchFilter
 * @brief Filter flags for watch notifications.
 */
enum class WatchFilter : uint32_t {
    None = 0,
    FileName = 0x00000001,         // FILE_NOTIFY_CHANGE_FILE_NAME
    DirName = 0x00000002,          // FILE_NOTIFY_CHANGE_DIR_NAME
    Attributes = 0x00000004,       // FILE_NOTIFY_CHANGE_ATTRIBUTES
    Size = 0x00000008,             // FILE_NOTIFY_CHANGE_SIZE
    LastWrite = 0x00000010,        // FILE_NOTIFY_CHANGE_LAST_WRITE
    LastAccess = 0x00000020,       // FILE_NOTIFY_CHANGE_LAST_ACCESS
    Creation = 0x00000040,         // FILE_NOTIFY_CHANGE_CREATION
    Security = 0x00000100,         // FILE_NOTIFY_CHANGE_SECURITY

    // Composite filters
    AllChanges = 0x000001FF,
    FileChanges = FileName | Size | LastWrite | Creation,
    DirectoryChanges = DirName | Attributes,
    SecurityChanges = Security | Attributes
};

// Enable bitwise operations for WatchFilter
inline WatchFilter operator|(WatchFilter a, WatchFilter b) {
    return static_cast<WatchFilter>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline WatchFilter operator&(WatchFilter a, WatchFilter b) {
    return static_cast<WatchFilter>(static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

/**
 * @enum WatchPriority
 * @brief Priority level for watch directories.
 */
enum class WatchPriority : uint8_t {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3                   // Ransomware-sensitive paths
};

/**
 * @enum EventSeverity
 * @brief Severity classification for events.
 */
enum class EventSeverity : uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4                   // Ransomware indicators
};

/**
 * @enum WatchState
 * @brief State of a watch entry.
 */
enum class WatchState : uint8_t {
    Pending = 0,
    Active = 1,
    Paused = 2,
    Error = 3,
    Removed = 4
};

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct FileEvent
 * @brief Comprehensive file system change event.
 */
struct alignas(128) FileEvent {
    // Event identity
    uint64_t eventId{ 0 };
    std::chrono::steady_clock::time_point timestamp;

    // Location
    std::wstring directory;
    std::wstring filename;
    std::wstring fullPath;
    std::wstring oldName;                  // For rename operations

    // Action
    FileAction action{ FileAction::Unknown };
    EventSeverity severity{ EventSeverity::Info };

    // Context
    uint32_t watchId{ 0 };
    WatchPriority priority{ WatchPriority::Normal };

    // File metadata (if available)
    uint64_t fileSize{ 0 };
    bool isDirectory{ false };
    bool isHidden{ false };
    bool isSystem{ false };
    bool isExecutable{ false };

    // Correlation
    uint64_t processId{ 0 };               // If available from driver
    std::wstring processPath;
    uint64_t correlationId{ 0 };           // For related events (rename pairs)

    // Debouncing
    uint32_t coalescedCount{ 1 };          // Number of events coalesced

    /**
     * @brief Gets the full path of the file.
     */
    [[nodiscard]] std::wstring GetFullPath() const {
        if (!fullPath.empty()) return fullPath;
        return (std::filesystem::path(directory) / filename).wstring();
    }
};

/**
 * @struct WatchEntry
 * @brief Configuration for a watched directory.
 */
struct alignas(64) WatchEntry {
    uint32_t watchId{ 0 };
    std::wstring directory;
    bool recursive{ true };
    WatchFilter filter{ WatchFilter::AllChanges };
    WatchPriority priority{ WatchPriority::Normal };
    WatchState state{ WatchState::Pending };

    // Pattern filters
    std::vector<std::wstring> includePatterns;   // Glob patterns to include
    std::vector<std::wstring> excludePatterns;   // Glob patterns to exclude

    // Statistics
    std::atomic<uint64_t> eventsReceived{ 0 };
    std::chrono::steady_clock::time_point createdTime;
    std::chrono::steady_clock::time_point lastEventTime;
};

/**
 * @struct RapidChangeDetection
 * @brief Configuration for ransomware-like activity detection.
 */
struct alignas(32) RapidChangeDetection {
    bool enabled{ true };
    uint32_t windowSizeMs{ 1000 };         // Time window
    uint32_t thresholdCount{ 50 };         // Events in window
    double entropyThreshold{ 0.8 };        // High entropy detection
    bool alertOnDetection{ true };
    bool pauseWatchOnDetection{ false };
};

/**
 * @struct EventStatistics
 * @brief Per-event-type statistics.
 */
struct alignas(64) EventStatistics {
    std::atomic<uint64_t> added{ 0 };
    std::atomic<uint64_t> removed{ 0 };
    std::atomic<uint64_t> modified{ 0 };
    std::atomic<uint64_t> renamed{ 0 };
    std::atomic<uint64_t> securityChanged{ 0 };
    std::atomic<uint64_t> attributesChanged{ 0 };

    void Reset() noexcept {
        added.store(0, std::memory_order_relaxed);
        removed.store(0, std::memory_order_relaxed);
        modified.store(0, std::memory_order_relaxed);
        renamed.store(0, std::memory_order_relaxed);
        securityChanged.store(0, std::memory_order_relaxed);
        attributesChanged.store(0, std::memory_order_relaxed);
    }
};

/**
 * @struct FileWatcherConfig
 * @brief Configuration for file watcher.
 */
struct alignas(64) FileWatcherConfig {
    // Worker threads
    uint32_t workerThreads{ FileWatcherConstants::DEFAULT_WORKER_THREADS };

    // Event processing
    uint32_t debounceMs{ FileWatcherConstants::DEFAULT_DEBOUNCE_MS };
    uint32_t rateLimitPerSec{ FileWatcherConstants::DEFAULT_RATE_LIMIT_PER_SEC };
    bool enableEventCoalescing{ true };
    bool enablePriorityProcessing{ true };

    // Buffer management
    size_t watchBufferSize{ FileWatcherConstants::WATCH_BUFFER_SIZE };
    size_t eventQueueSize{ FileWatcherConstants::EVENT_QUEUE_SIZE };

    // Features
    bool collectFileMetadata{ true };
    bool correlateRenameEvents{ true };
    bool enableRapidChangeDetection{ true };
    RapidChangeDetection rapidChangeConfig;

    // Filtering
    std::vector<std::wstring> globalExclusions;
    bool excludeHiddenFiles{ false };
    bool excludeSystemFiles{ false };
    bool excludeTempFiles{ true };

    // Factory methods
    static FileWatcherConfig CreateDefault() noexcept;
    static FileWatcherConfig CreateHighPerformance() noexcept;
    static FileWatcherConfig CreateLowLatency() noexcept;
    static FileWatcherConfig CreateRansomwareDetection() noexcept;
};

/**
 * @struct FileWatcherStatistics
 * @brief Runtime statistics for file watcher.
 */
struct alignas(128) FileWatcherStatistics {
    // Event counts
    std::atomic<uint64_t> totalEventsReceived{ 0 };
    std::atomic<uint64_t> eventsProcessed{ 0 };
    std::atomic<uint64_t> eventsDropped{ 0 };
    std::atomic<uint64_t> eventsCoalesced{ 0 };

    // Per-type statistics
    EventStatistics byType;

    // Performance metrics
    std::atomic<uint64_t> peakEventsPerSecond{ 0 };
    std::atomic<uint64_t> averageLatencyUs{ 0 };
    std::atomic<uint64_t> maxLatencyUs{ 0 };

    // Watch statistics
    std::atomic<uint32_t> activeWatches{ 0 };
    std::atomic<uint32_t> failedWatches{ 0 };
    std::atomic<uint64_t> watchRestarts{ 0 };

    // Memory
    std::atomic<uint64_t> memoryUsageBytes{ 0 };
    std::atomic<uint64_t> bufferPoolSize{ 0 };

    // Alerts
    std::atomic<uint64_t> rapidChangeAlerts{ 0 };

    void Reset() noexcept;
};

/**
 * @struct WatchAlert
 * @brief Alert generated by file watcher.
 */
struct alignas(128) WatchAlert {
    uint64_t alertId{ 0 };
    std::chrono::system_clock::time_point timestamp;

    std::string alertType;                 // RapidChange, WatchError, etc.
    EventSeverity severity{ EventSeverity::Medium };
    std::wstring watchDirectory;
    uint32_t watchId{ 0 };

    std::string description;
    uint64_t eventCount{ 0 };
    uint32_t timeWindowMs{ 0 };

    std::vector<std::wstring> affectedFiles;
};

// ============================================================================
// CALLBACK TYPE DEFINITIONS
// ============================================================================

/**
 * @brief Callback for file events.
 */
using EventCallback = std::function<void(const FileEvent& event)>;

/**
 * @brief Callback for batch events.
 */
using BatchEventCallback = std::function<void(const std::vector<FileEvent>& events)>;

/**
 * @brief Callback for watch alerts.
 */
using WatchAlertCallback = std::function<void(const WatchAlert& alert)>;

/**
 * @brief Callback for watch state changes.
 */
using WatchStateCallback = std::function<void(uint32_t watchId, WatchState newState)>;

// ============================================================================
// MAIN CLASS DEFINITION
// ============================================================================

/**
 * @class FileWatcher
 * @brief Enterprise-grade high-performance file system monitor.
 *
 * Thread Safety:
 * All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * FileWatcher watcher;
 * 
 * // Configure
 * auto config = FileWatcherConfig::CreateRansomwareDetection();
 * 
 * // Set callback
 * watcher.Start([](const FileEvent& event) {
 *     if (event.severity >= EventSeverity::High) {
 *         LOG_ALERT << "Suspicious activity: " << event.fullPath;
 *     }
 * });
 * 
 * // Add watches
 * watcher.AddWatch(L"C:\\Users", true, WatchPriority::High);
 * watcher.AddWatch(L"C:\\Windows\\System32", true, WatchPriority::Critical);
 * 
 * // Add patterns
 * watcher.AddExclusionPattern(L"*.tmp");
 * watcher.AddExclusionPattern(L"~$*");
 * 
 * // Monitor for ransomware
 * watcher.EnableRapidChangeDetection([](const WatchAlert& alert) {
 *     LOG_CRITICAL << "Possible ransomware activity detected!";
 * });
 * @endcode
 */
class FileWatcher {
public:
    // ========================================================================
    // LIFECYCLE
    // ========================================================================

    FileWatcher();
    ~FileWatcher();

    // Disable copy
    FileWatcher(const FileWatcher&) = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    // Enable move
    FileWatcher(FileWatcher&& other) noexcept;
    FileWatcher& operator=(FileWatcher&& other) noexcept;

    // ========================================================================
    // INITIALIZATION
    // ========================================================================

    /**
     * @brief Initializes the file watcher with configuration.
     * @param config Configuration settings.
     * @return True if successful.
     */
    bool Initialize(const FileWatcherConfig& config);

    /**
     * @brief Starts the monitoring threads.
     * @param callback Function to invoke on file changes.
     * @return True if started successfully.
     */
    bool Start(EventCallback callback);

    /**
     * @brief Starts with batch processing.
     * @param callback Function for batch events.
     * @param batchSize Maximum events per batch.
     * @param batchTimeoutMs Maximum wait time for batch.
     * @return True if started successfully.
     */
    bool StartBatch(BatchEventCallback callback, size_t batchSize = 100, uint32_t batchTimeoutMs = 100);

    /**
     * @brief Stops monitoring and closes all handles.
     */
    void Stop() noexcept;

    /**
     * @brief Checks if watcher is running.
     * @return True if running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    // ========================================================================
    // WATCH MANAGEMENT
    // ========================================================================

    /**
     * @brief Adds a directory to the watch list.
     * @param directory Path to monitor.
     * @param recursive Watch subdirectories.
     * @param priority Watch priority.
     * @param filter Event filter.
     * @return Watch ID or 0 on failure.
     */
    [[nodiscard]] uint32_t AddWatch(
        const std::wstring& directory,
        bool recursive = true,
        WatchPriority priority = WatchPriority::Normal,
        WatchFilter filter = WatchFilter::AllChanges);

    /**
     * @brief Adds watch with patterns.
     * @param directory Path to monitor.
     * @param includePatterns Glob patterns to include.
     * @param excludePatterns Glob patterns to exclude.
     * @param recursive Watch subdirectories.
     * @return Watch ID or 0 on failure.
     */
    [[nodiscard]] uint32_t AddWatchWithPatterns(
        const std::wstring& directory,
        const std::vector<std::wstring>& includePatterns,
        const std::vector<std::wstring>& excludePatterns,
        bool recursive = true);

    /**
     * @brief Removes a directory from the watch list.
     * @param watchId ID returned by AddWatch.
     * @return True if removed.
     */
    bool RemoveWatch(uint32_t watchId);

    /**
     * @brief Removes watch by path.
     * @param directory Path to remove.
     * @return True if removed.
     */
    bool RemoveWatchByPath(const std::wstring& directory);

    /**
     * @brief Removes all watches.
     */
    void RemoveAll() noexcept;

    /**
     * @brief Pauses a watch.
     * @param watchId Watch ID.
     * @return True if paused.
     */
    bool PauseWatch(uint32_t watchId);

    /**
     * @brief Resumes a watch.
     * @param watchId Watch ID.
     * @return True if resumed.
     */
    bool ResumeWatch(uint32_t watchId);

    /**
     * @brief Gets watch info.
     * @param watchId Watch ID.
     * @return Watch entry, or nullopt.
     */
    [[nodiscard]] std::optional<WatchEntry> GetWatchInfo(uint32_t watchId) const;

    /**
     * @brief Gets all watches.
     * @return Vector of watch entries.
     */
    [[nodiscard]] std::vector<WatchEntry> GetAllWatches() const;

    /**
     * @brief Checks if path is being watched.
     * @param path Path to check.
     * @return True if watched.
     */
    [[nodiscard]] bool IsWatched(const std::wstring& path) const;

    // ========================================================================
    // FILTERING
    // ========================================================================

    /**
     * @brief Adds global exclusion pattern.
     * @param pattern Glob pattern (e.g., "*.tmp").
     */
    void AddExclusionPattern(const std::wstring& pattern);

    /**
     * @brief Removes exclusion pattern.
     * @param pattern Pattern to remove.
     */
    void RemoveExclusionPattern(const std::wstring& pattern);

    /**
     * @brief Adds exclusion for specific path.
     * @param path Full path to exclude.
     */
    void AddExclusionPath(const std::wstring& path);

    /**
     * @brief Removes path exclusion.
     * @param path Path to remove.
     */
    void RemoveExclusionPath(const std::wstring& path);

    /**
     * @brief Gets all exclusion patterns.
     * @return Vector of patterns.
     */
    [[nodiscard]] std::vector<std::wstring> GetExclusionPatterns() const;

    // ========================================================================
    // RAPID CHANGE DETECTION
    // ========================================================================

    /**
     * @brief Enables rapid change detection (ransomware).
     * @param callback Alert callback.
     * @param config Detection configuration.
     */
    void EnableRapidChangeDetection(WatchAlertCallback callback, const RapidChangeDetection& config = {});

    /**
     * @brief Disables rapid change detection.
     */
    void DisableRapidChangeDetection() noexcept;

    /**
     * @brief Checks if rapid change was detected.
     * @param watchId Watch ID (0 for any).
     * @return True if detected.
     */
    [[nodiscard]] bool IsRapidChangeDetected(uint32_t watchId = 0) const;

    // ========================================================================
    // CALLBACK REGISTRATION
    // ========================================================================

    [[nodiscard]] uint64_t RegisterEventCallback(EventCallback callback);
    [[nodiscard]] uint64_t RegisterAlertCallback(WatchAlertCallback callback);
    [[nodiscard]] uint64_t RegisterStateCallback(WatchStateCallback callback);
    bool UnregisterCallback(uint64_t callbackId);

    // ========================================================================
    // CONFIGURATION
    // ========================================================================

    /**
     * @brief Sets debounce time.
     * @param debounceMs Debounce in milliseconds.
     */
    void SetDebounceTime(uint32_t debounceMs);

    /**
     * @brief Sets rate limit.
     * @param eventsPerSecond Maximum events per second.
     */
    void SetRateLimit(uint32_t eventsPerSecond);

    /**
     * @brief Enables/disables event coalescing.
     * @param enable Enable flag.
     */
    void SetEventCoalescing(bool enable) noexcept;

    // ========================================================================
    // STATISTICS
    // ========================================================================

    [[nodiscard]] const FileWatcherStatistics& GetStatistics() const noexcept;
    void ResetStatistics() noexcept;

    // ========================================================================
    // DIAGNOSTICS
    // ========================================================================

    /**
     * @brief Gets pending event count.
     * @return Number of pending events.
     */
    [[nodiscard]] size_t GetPendingEventCount() const noexcept;

    /**
     * @brief Gets current events per second.
     * @return Events per second.
     */
    [[nodiscard]] double GetCurrentEventsPerSecond() const noexcept;

    /**
     * @brief Exports diagnostics report.
     * @param outputPath Output file path.
     * @return True if successful.
     */
    bool ExportDiagnostics(const std::wstring& outputPath) const;

private:
    std::unique_ptr<FileWatcherImpl> m_impl;
};

}  // namespace FileSystem
}  // namespace Core
}  // namespace ShadowStrike
