/**
 * ============================================================================
 * ShadowStrike Real-Time - FILE SYSTEM FILTER (The Sentry)
 * ============================================================================
 *
 * @file FileSystemFilter.hpp
 * @brief User-mode interface for kernel minifilter driver communication.
 *
 * This module provides the user-mode side of the file system filtering stack.
 * It communicates with the ShadowStrike kernel minifilter driver via Windows
 * Filter Manager communication ports to receive file I/O events and send
 * scan verdicts back to the kernel.
 *
 * =============================================================================
 * ARCHITECTURE
 * =============================================================================
 *
 * ```
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           USER MODE                                          │
 * ├─────────────────────────────────────────────────────────────────────────────┤
 * │                                                                              │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                     FileSystemFilter                                 │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │   │
 * │  │  │  Message Port   │  │  Reply Port     │  │  Event Queue    │      │   │
 * │  │  │  (Receive)      │  │  (Send)         │  │  (Async)        │      │   │
 * │  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘      │   │
 * │  │           │                    │                    │               │   │
 * │  └───────────┼────────────────────┼────────────────────┼───────────────┘   │
 * │              │                    │                    │                   │
 * │              │    FilterConnectCommunicationPort()     │                   │
 * │              │    FilterGetMessage() / FilterReplyMessage()                │
 * │              │                    │                    │                   │
 * └──────────────┼────────────────────┼────────────────────┼───────────────────┘
 *                │                    │                    │
 * ═══════════════╪════════════════════╪════════════════════╪═══════════════════
 *                │     KERNEL BOUNDARY (Ring 0)            │
 * ═══════════════╪════════════════════╪════════════════════╪═══════════════════
 *                │                    │                    │
 * ┌──────────────┼────────────────────┼────────────────────┼───────────────────┐
 * │              ▼                    ▼                    ▼                   │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                  ShadowStrike Minifilter Driver                      │   │
 * │  │                                                                       │   │
 * │  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │   │
 * │  │  │ Communication   │  │  Pre-Operation  │  │ Post-Operation  │      │   │
 * │  │  │ Port Server     │  │  Callbacks      │  │ Callbacks       │      │   │
 * │  │  └─────────────────┘  └─────────────────┘  └─────────────────┘      │   │
 * │  │                                                                       │   │
 * │  │  Registered Operations:                                               │   │
 * │  │  - IRP_MJ_CREATE        (File Open)                                   │   │
 * │  │  - IRP_MJ_WRITE         (File Write)                                  │   │
 * │  │  - IRP_MJ_SET_INFORMATION (File Rename/Delete)                        │   │
 * │  │  - IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION (Execute/Map)           │   │
 * │  │                                                                       │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                           │                                                │
 * │                           ▼                                                │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                     Filter Manager (FltMgr.sys)                      │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                           │                                                │
 * │                           ▼                                                │
 * │  ┌─────────────────────────────────────────────────────────────────────┐   │
 * │  │                        File System (NTFS.sys)                        │   │
 * │  └─────────────────────────────────────────────────────────────────────┘   │
 * │                                                                            │
 * │                           KERNEL MODE                                      │
 * └────────────────────────────────────────────────────────────────────────────┘
 * ```
 *
 * =============================================================================
 * COMMUNICATION PROTOCOL
 * =============================================================================
 *
 * **Message Flow (Synchronous Scan):**
 * ```
 * 1. [Kernel] IRP_MJ_CREATE received for suspicious file
 * 2. [Kernel] Pre-operation callback triggered
 * 3. [Kernel] FltSendMessage() to user-mode with file info
 * 4. [User]   FilterGetMessage() receives scan request
 * 5. [User]   ScanEngine scans file
 * 6. [User]   FilterReplyMessage() sends verdict
 * 7. [Kernel] Pre-operation completes (Allow/Block)
 * ```
 *
 * **Message Flow (Asynchronous Notification):**
 * ```
 * 1. [Kernel] IRP_MJ_WRITE completed
 * 2. [Kernel] Post-operation callback triggered
 * 3. [Kernel] FltSendMessage() notification (no reply needed)
 * 4. [User]   Event logged for behavioral analysis
 * ```
 *
 * =============================================================================
 * MESSAGE TYPES
 * =============================================================================
 *
 * | Type                  | Direction      | Reply Required | Description          |
 * |-----------------------|----------------|----------------|----------------------|
 * | FileScanRequest       | Kernel → User  | Yes            | Request file scan    |
 * | ScanVerdict           | User → Kernel  | -              | Scan result          |
 * | FileWriteNotify       | Kernel → User  | No             | Write completed      |
 * | FileRenameNotify      | Kernel → User  | No             | Rename completed     |
 * | FileDeleteNotify      | Kernel → User  | No             | Delete completed     |
 * | ExecuteMapNotify      | Kernel → User  | No             | Execute/map attempt  |
 * | DriverStatusRequest   | User → Kernel  | Yes            | Query driver status  |
 * | PolicyUpdate          | User → Kernel  | -              | Update filter policy |
 * | ExclusionUpdate       | User → Kernel  | -              | Update exclusions    |
 *
 * =============================================================================
 * INTEGRATION POINTS
 * =============================================================================
 *
 * - **ScanEngine**: File content scanning
 * - **ThreatDetector**: Behavioral event correlation
 * - **Whitelist**: Path/process exclusion checking
 * - **SignatureStore**: Real-time signature matching
 * - **HashStore**: Hash-based allow/block lists
 * - **QuarantineManager**: Threat isolation
 *
 * =============================================================================
 * PERFORMANCE CONSIDERATIONS
 * =============================================================================
 *
 * - Uses overlapped I/O for non-blocking message retrieval
 * - Thread pool for parallel scan request processing
 * - Request prioritization (executables > documents > others)
 * - LRU cache for recently scanned files (by hash)
 * - Configurable scan timeout with fail-open/fail-closed policy
 *
 * @note Thread-safe for all public methods
 * @note Requires administrator privileges
 * @note Requires ShadowStrike minifilter driver installed
 *
 * @see IPCManager for process-level IPC
 * @see ScanEngine for file scanning
 * @see ThreatDetector for event correlation
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @copyright (c) 2026 ShadowStrike Security Suite. All rights reserved.
 */

#pragma once

#include <atomic>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <shared_mutex>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#  include <fltUser.h>  // Filter Manager user-mode APIs
#endif

// Forward declarations
namespace ShadowStrike {
    namespace Utils {
        class ThreadPool;
        class CacheManager;
    }
    namespace Whitelist {
        class WhitelistStore;
    }
    namespace HashStore {
        class HashStore;
    }
    namespace Core {
        namespace Engine {
            class ScanEngine;
            class ThreatDetector;
        }
    }
}

namespace ShadowStrike {
namespace RealTime {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class FileSystemFilter;
struct FilterMessage;
struct FilterReply;
struct FileAccessEvent;

// ============================================================================
// CONSTANTS
// ============================================================================

namespace FilterConstants {
    // -------------------------------------------------------------------------
    // Communication Port
    // -------------------------------------------------------------------------
    
    /// @brief Default communication port name
    constexpr wchar_t DEFAULT_PORT_NAME[] = L"\\ShadowStrikePort";
    
    /// @brief Maximum connections to port
    constexpr DWORD MAX_PORT_CONNECTIONS = 8;
    
    /// @brief Message buffer size
    constexpr size_t MESSAGE_BUFFER_SIZE = 65536;
    
    /// @brief Maximum message data size
    constexpr size_t MAX_MESSAGE_DATA_SIZE = 65000;
    
    /// @brief Reply timeout (milliseconds)
    constexpr DWORD REPLY_TIMEOUT_MS = 30000;
    
    // -------------------------------------------------------------------------
    // Message Types
    // -------------------------------------------------------------------------
    
    /// @brief Message header magic
    constexpr uint32_t MESSAGE_MAGIC = 0x53534653;  // "SSFS"
    
    /// @brief Current protocol version
    constexpr uint16_t PROTOCOL_VERSION = 2;
    
    // -------------------------------------------------------------------------
    // Performance
    // -------------------------------------------------------------------------
    
    /// @brief Maximum pending requests
    constexpr size_t MAX_PENDING_REQUESTS = 10000;
    
    /// @brief Worker thread count
    constexpr size_t WORKER_THREAD_COUNT = 4;
    
    /// @brief Scan cache capacity
    constexpr size_t SCAN_CACHE_CAPACITY = 100000;
    
    /// @brief Cache entry TTL (seconds)
    constexpr uint32_t CACHE_TTL_SECONDS = 300;
    
    /// @brief Default scan timeout (milliseconds)
    constexpr uint32_t DEFAULT_SCAN_TIMEOUT_MS = 30000;
    
    // -------------------------------------------------------------------------
    // Limits
    // -------------------------------------------------------------------------
    
    /// @brief Maximum path length
    constexpr size_t MAX_PATH_LENGTH = 32767;
    
    /// @brief Maximum file size for sync scan (larger = async)
    constexpr uint64_t MAX_SYNC_SCAN_SIZE = 64 * 1024 * 1024;  // 64 MB
    
    /// @brief Minimum file size to scan
    constexpr uint64_t MIN_SCAN_SIZE = 1;
    
    /// @brief Maximum exclusion paths
    constexpr size_t MAX_EXCLUSION_PATHS = 10000;
    
    /// @brief Maximum exclusion extensions
    constexpr size_t MAX_EXCLUSION_EXTENSIONS = 1000;
    
    /// @brief Maximum exclusion processes
    constexpr size_t MAX_EXCLUSION_PROCESSES = 1000;
}

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Filter communication status.
 */
enum class FilterStatus : uint8_t {
    /// @brief Not initialized
    NotInitialized = 0,
    
    /// @brief Initializing
    Initializing = 1,
    
    /// @brief Running and connected
    Running = 2,
    
    /// @brief Paused (not filtering)
    Paused = 3,
    
    /// @brief Stopped
    Stopped = 4,
    
    /// @brief Error state
    Error = 5,
    
    /// @brief Driver not installed
    DriverNotInstalled = 6,
    
    /// @brief Access denied
    AccessDenied = 7,
    
    /// @brief Port busy
    PortBusy = 8
};

/**
 * @brief Filter message type.
 */
enum class FilterMessageType : uint16_t {
    /// @brief Unknown/invalid
    Unknown = 0,
    
    // -------------------------------------------------------------------------
    // Scan Requests (Kernel → User, Reply Required)
    // -------------------------------------------------------------------------
    
    /// @brief Request to scan file on open
    FileScanOnOpen = 1,
    
    /// @brief Request to scan file on execute/map
    FileScanOnExecute = 2,
    
    /// @brief Request to scan file on write completion
    FileScanOnWrite = 3,
    
    /// @brief Request to scan network file
    FileScanNetwork = 4,
    
    // -------------------------------------------------------------------------
    // Notifications (Kernel → User, No Reply)
    // -------------------------------------------------------------------------
    
    /// @brief File was created
    NotifyFileCreate = 100,
    
    /// @brief File was written
    NotifyFileWrite = 101,
    
    /// @brief File was renamed
    NotifyFileRename = 102,
    
    /// @brief File was deleted
    NotifyFileDelete = 103,
    
    /// @brief File attributes changed
    NotifyFileAttributeChange = 104,
    
    /// @brief Directory created
    NotifyDirectoryCreate = 105,
    
    /// @brief Directory deleted
    NotifyDirectoryDelete = 106,
    
    /// @brief File mapped for execution
    NotifyFileMap = 107,
    
    /// @brief Alternate data stream created
    NotifyADSCreate = 108,
    
    // -------------------------------------------------------------------------
    // Control Messages (User → Kernel)
    // -------------------------------------------------------------------------
    
    /// @brief Query driver status
    QueryDriverStatus = 200,
    
    /// @brief Update filter policy
    UpdatePolicy = 201,
    
    /// @brief Update path exclusions
    UpdateExclusions = 202,
    
    /// @brief Enable filtering
    EnableFiltering = 203,
    
    /// @brief Disable filtering
    DisableFiltering = 204,
    
    /// @brief Flush cache
    FlushCache = 205,
    
    /// @brief Get driver statistics
    GetStatistics = 206,
    
    // -------------------------------------------------------------------------
    // Replies (User → Kernel)
    // -------------------------------------------------------------------------
    
    /// @brief Scan verdict reply
    ScanVerdict = 300,
    
    /// @brief Acknowledgement
    Acknowledge = 301
};

/**
 * @brief Scan verdict sent to kernel.
 */
enum class ScanVerdict : uint8_t {
    /// @brief Allow access
    Allow = 0,
    
    /// @brief Block access
    Block = 1,
    
    /// @brief Allow but mark suspicious
    AllowSuspicious = 2,
    
    /// @brief Block and quarantine
    BlockAndQuarantine = 3,
    
    /// @brief Timeout - use policy default
    Timeout = 4,
    
    /// @brief Error - use policy default
    Error = 5,
    
    /// @brief Request retry (transient error)
    Retry = 6,
    
    /// @brief Cache hit - allow
    CacheHitAllow = 7,
    
    /// @brief Cache hit - block
    CacheHitBlock = 8
};

/**
 * @brief File access type that triggered filter.
 */
enum class FileAccessType : uint8_t {
    /// @brief Unknown access
    Unknown = 0,
    
    /// @brief Open for read
    Read = 1,
    
    /// @brief Open for write
    Write = 2,
    
    /// @brief Open for execute
    Execute = 3,
    
    /// @brief Memory map
    Map = 4,
    
    /// @brief Delete
    Delete = 5,
    
    /// @brief Rename
    Rename = 6,
    
    /// @brief Create new file
    Create = 7,
    
    /// @brief Attribute change
    AttributeChange = 8,
    
    /// @brief Security change
    SecurityChange = 9
};

/**
 * @brief File disposition (create options).
 */
enum class FileDisposition : uint8_t {
    /// @brief Unknown
    Unknown = 0,
    
    /// @brief Open existing only
    Open = 1,
    
    /// @brief Create new only
    Create = 2,
    
    /// @brief Open or create
    OpenOrCreate = 3,
    
    /// @brief Overwrite existing
    Overwrite = 4,
    
    /// @brief Open and truncate
    OpenTruncate = 5
};

/**
 * @brief Request priority.
 */
enum class RequestPriority : uint8_t {
    /// @brief Background priority
    Background = 0,
    
    /// @brief Normal priority
    Normal = 1,
    
    /// @brief High priority (executables)
    High = 2,
    
    /// @brief Critical priority (system files)
    Critical = 3
};

/**
 * @brief Get string representation of FilterStatus.
 */
[[nodiscard]] constexpr const char* FilterStatusToString(FilterStatus status) noexcept;

/**
 * @brief Get string representation of ScanVerdict.
 */
[[nodiscard]] constexpr const char* ScanVerdictToString(ScanVerdict verdict) noexcept;

// ============================================================================
// DATA STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Message header (shared with kernel driver).
 */
struct FilterMessageHeader {
    /// @brief Magic number (MESSAGE_MAGIC)
    uint32_t magic = FilterConstants::MESSAGE_MAGIC;
    
    /// @brief Protocol version
    uint16_t version = FilterConstants::PROTOCOL_VERSION;
    
    /// @brief Message type
    FilterMessageType messageType = FilterMessageType::Unknown;
    
    /// @brief Message ID for correlation
    uint64_t messageId = 0;
    
    /// @brief Total message size including header
    uint32_t totalSize = 0;
    
    /// @brief Data size
    uint32_t dataSize = 0;
    
    /// @brief Timestamp (kernel ticks)
    uint64_t timestamp = 0;
    
    /// @brief Flags
    uint32_t flags = 0;
    
    /// @brief Reserved
    uint32_t reserved = 0;
};

/**
 * @brief File scan request from kernel.
 */
struct FileScanRequest {
    /// @brief Request message ID
    uint64_t messageId = 0;
    
    /// @brief Access type
    FileAccessType accessType = FileAccessType::Unknown;
    
    /// @brief File disposition
    FileDisposition disposition = FileDisposition::Unknown;
    
    /// @brief Request priority
    RequestPriority priority = RequestPriority::Normal;
    
    /// @brief Requires reply
    bool requiresReply = true;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /// @brief File size (0 if not known)
    uint64_t fileSize = 0;
    
    /// @brief File attributes
    uint32_t fileAttributes = 0;
    
    /// @brief Desired access mask
    uint32_t desiredAccess = 0;
    
    /// @brief Share access mask
    uint32_t shareAccess = 0;
    
    /// @brief Create options
    uint32_t createOptions = 0;
    
    /// @brief Volume serial number
    uint32_t volumeSerial = 0;
    
    /// @brief File ID (if available)
    uint64_t fileId = 0;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Is network file
    bool isNetworkFile = false;
    
    /// @brief Is removable media
    bool isRemovableMedia = false;
    
    /// @brief Has alternate data streams
    bool hasADS = false;
    
    /// @brief File path length
    uint16_t pathLength = 0;
    
    /// @brief Process name length
    uint16_t processNameLength = 0;
    
    /// @brief File path (variable length, follows struct)
    // wchar_t filePath[pathLength];
    
    /// @brief Process name (variable length, follows path)
    // wchar_t processName[processNameLength];
};

/**
 * @brief Scan verdict reply to kernel.
 */
struct ScanVerdictReply {
    /// @brief Message ID being replied to
    uint64_t messageId = 0;
    
    /// @brief Verdict
    ScanVerdict verdict = ScanVerdict::Allow;
    
    /// @brief Scan result code
    uint32_t resultCode = 0;
    
    /// @brief Threat detected
    bool threatDetected = false;
    
    /// @brief Threat score (0-100)
    uint8_t threatScore = 0;
    
    /// @brief Cache this result
    bool cacheResult = true;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTTL = FilterConstants::CACHE_TTL_SECONDS;
    
    /// @brief Reserved
    uint32_t reserved = 0;
    
    /// @brief Threat name length
    uint16_t threatNameLength = 0;
    
    /// @brief Threat name (variable length)
    // wchar_t threatName[threatNameLength];
};

/**
 * @brief File notification from kernel.
 */
struct FileNotification {
    /// @brief Notification type
    FilterMessageType notificationType = FilterMessageType::Unknown;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Bytes written (for write notifications)
    uint64_t bytesWritten = 0;
    
    /// @brief File attributes
    uint32_t fileAttributes = 0;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Path length
    uint16_t pathLength = 0;
    
    /// @brief New path length (for rename)
    uint16_t newPathLength = 0;
    
    /// @brief Process name length
    uint16_t processNameLength = 0;
    
    /// @brief Paths follow structure:
    // wchar_t filePath[pathLength];
    // wchar_t newPath[newPathLength];  // For rename only
    // wchar_t processName[processNameLength];
};

/**
 * @brief Driver status response.
 */
struct DriverStatus {
    /// @brief Driver version major
    uint16_t versionMajor = 0;
    
    /// @brief Driver version minor
    uint16_t versionMinor = 0;
    
    /// @brief Driver version build
    uint16_t versionBuild = 0;
    
    /// @brief Is filtering active
    bool filteringActive = false;
    
    /// @brief Scan on open enabled
    bool scanOnOpenEnabled = false;
    
    /// @brief Scan on execute enabled
    bool scanOnExecuteEnabled = false;
    
    /// @brief Scan on write enabled
    bool scanOnWriteEnabled = false;
    
    /// @brief Notifications enabled
    bool notificationsEnabled = false;
    
    /// @brief Total files scanned
    uint64_t totalFilesScanned = 0;
    
    /// @brief Files blocked
    uint64_t filesBlocked = 0;
    
    /// @brief Current pending requests
    uint32_t pendingRequests = 0;
    
    /// @brief Peak pending requests
    uint32_t peakPendingRequests = 0;
    
    /// @brief Cache hits
    uint64_t cacheHits = 0;
    
    /// @brief Cache misses
    uint64_t cacheMisses = 0;
    
    /// @brief Exclusion path count
    uint32_t exclusionPathCount = 0;
    
    /// @brief Exclusion extension count
    uint32_t exclusionExtensionCount = 0;
    
    /// @brief Exclusion process count
    uint32_t exclusionProcessCount = 0;
};

/**
 * @brief Policy update message to kernel.
 */
struct PolicyUpdate {
    /// @brief Enable scan on open
    bool scanOnOpen = true;
    
    /// @brief Enable scan on execute
    bool scanOnExecute = true;
    
    /// @brief Enable scan on write
    bool scanOnWrite = false;
    
    /// @brief Enable notifications
    bool enableNotifications = true;
    
    /// @brief Block on timeout
    bool blockOnTimeout = false;
    
    /// @brief Block on error
    bool blockOnError = false;
    
    /// @brief Scan network files
    bool scanNetworkFiles = true;
    
    /// @brief Scan removable media
    bool scanRemovableMedia = true;
    
    /// @brief Maximum file size to scan (0 = unlimited)
    uint64_t maxScanFileSize = 0;
    
    /// @brief Scan timeout (milliseconds)
    uint32_t scanTimeoutMs = FilterConstants::DEFAULT_SCAN_TIMEOUT_MS;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTTLSeconds = FilterConstants::CACHE_TTL_SECONDS;
};

#pragma pack(pop)

/**
 * @brief Decoded file access event.
 */
struct FileAccessEvent {
    /// @brief Message ID
    uint64_t messageId = 0;
    
    /// @brief Event timestamp
    std::chrono::system_clock::time_point timestamp{};
    
    /// @brief Message type
    FilterMessageType messageType = FilterMessageType::Unknown;
    
    /// @brief Access type
    FileAccessType accessType = FileAccessType::Unknown;
    
    /// @brief File path
    std::wstring filePath;
    
    /// @brief New path (for rename)
    std::wstring newPath;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Process path
    std::wstring processPath;
    
    /// @brief File size
    uint64_t fileSize = 0;
    
    /// @brief Bytes written/read
    uint64_t bytesTransferred = 0;
    
    /// @brief File attributes
    uint32_t fileAttributes = 0;
    
    /// @brief Desired access
    uint32_t desiredAccess = 0;
    
    /// @brief Is directory
    bool isDirectory = false;
    
    /// @brief Is network file
    bool isNetworkFile = false;
    
    /// @brief Is removable media
    bool isRemovableMedia = false;
    
    /// @brief Requires reply
    bool requiresReply = false;
    
    /// @brief Priority
    RequestPriority priority = RequestPriority::Normal;
    
    /// @brief Was event handled
    bool handled = false;
    
    /// @brief Verdict sent
    ScanVerdict verdict = ScanVerdict::Allow;
};

/**
 * @brief Exclusion entry.
 */
struct FilterExclusion {
    /// @brief Exclusion type
    enum class Type {
        Path,           ///< Path prefix/pattern
        Extension,      ///< File extension
        Process,        ///< Process name
        ProcessPath,    ///< Full process path
        Hash            ///< File hash
    };
    
    /// @brief Exclusion type
    Type type = Type::Path;
    
    /// @brief Exclusion pattern/value
    std::wstring pattern;
    
    /// @brief Is wildcard pattern
    bool isWildcard = false;
    
    /// @brief Case insensitive
    bool caseInsensitive = true;
    
    /// @brief Comment/reason
    std::wstring comment;
    
    /// @brief Expiration time (optional)
    std::optional<std::chrono::system_clock::time_point> expiration;
    
    /// @brief Source of exclusion
    std::wstring source;
};

/**
 * @brief Configuration for file system filter.
 */
struct FileSystemFilterConfig {
    // -------------------------------------------------------------------------
    // Connection Settings
    // -------------------------------------------------------------------------
    
    /// @brief Communication port name
    std::wstring portName = FilterConstants::DEFAULT_PORT_NAME;
    
    /// @brief Number of message threads
    size_t messageThreadCount = FilterConstants::WORKER_THREAD_COUNT;
    
    /// @brief Message buffer size
    size_t messageBufferSize = FilterConstants::MESSAGE_BUFFER_SIZE;
    
    // -------------------------------------------------------------------------
    // Scan Policy
    // -------------------------------------------------------------------------
    
    /// @brief Enable scan on file open
    bool scanOnOpen = true;
    
    /// @brief Enable scan on execute/map
    bool scanOnExecute = true;
    
    /// @brief Enable scan on write completion
    bool scanOnWrite = false;
    
    /// @brief Scan network files
    bool scanNetworkFiles = true;
    
    /// @brief Scan removable media
    bool scanRemovableMedia = true;
    
    /// @brief Maximum file size to scan (0 = unlimited)
    uint64_t maxScanFileSize = 0;
    
    /// @brief Scan timeout (milliseconds)
    uint32_t scanTimeoutMs = FilterConstants::DEFAULT_SCAN_TIMEOUT_MS;
    
    // -------------------------------------------------------------------------
    // Failure Policy
    // -------------------------------------------------------------------------
    
    /// @brief Block on scan timeout (false = allow)
    bool blockOnTimeout = false;
    
    /// @brief Block on scan error (false = allow)
    bool blockOnError = false;
    
    /// @brief Block on driver communication error
    bool blockOnCommError = false;
    
    // -------------------------------------------------------------------------
    // Notification Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable file notifications
    bool enableNotifications = true;
    
    /// @brief Notify on file create
    bool notifyOnCreate = true;
    
    /// @brief Notify on file write
    bool notifyOnWrite = true;
    
    /// @brief Notify on file rename
    bool notifyOnRename = true;
    
    /// @brief Notify on file delete
    bool notifyOnDelete = true;
    
    // -------------------------------------------------------------------------
    // Cache Settings
    // -------------------------------------------------------------------------
    
    /// @brief Enable scan result caching
    bool enableCache = true;
    
    /// @brief Cache capacity
    size_t cacheCapacity = FilterConstants::SCAN_CACHE_CAPACITY;
    
    /// @brief Cache TTL (seconds)
    uint32_t cacheTTLSeconds = FilterConstants::CACHE_TTL_SECONDS;
    
    /// @brief Cache negative results (blocks)
    bool cacheNegativeResults = true;
    
    // -------------------------------------------------------------------------
    // Performance Settings
    // -------------------------------------------------------------------------
    
    /// @brief Maximum pending requests
    size_t maxPendingRequests = FilterConstants::MAX_PENDING_REQUESTS;
    
    /// @brief Enable request prioritization
    bool enablePrioritization = true;
    
    /// @brief Batch notification delivery
    bool batchNotifications = true;
    
    /// @brief Notification batch size
    size_t notificationBatchSize = 100;
    
    // -------------------------------------------------------------------------
    // Factory Methods
    // -------------------------------------------------------------------------
    
    /**
     * @brief Create default configuration.
     */
    [[nodiscard]] static FileSystemFilterConfig CreateDefault() noexcept {
        return FileSystemFilterConfig{};
    }
    
    /**
     * @brief Create high-performance configuration.
     */
    [[nodiscard]] static FileSystemFilterConfig CreateHighPerformance() noexcept {
        FileSystemFilterConfig config;
        config.scanOnWrite = false;
        config.enableNotifications = false;
        config.maxScanFileSize = 128 * 1024 * 1024;  // 128 MB limit
        config.cacheCapacity = 500000;
        return config;
    }
    
    /**
     * @brief Create paranoid configuration.
     */
    [[nodiscard]] static FileSystemFilterConfig CreateParanoid() noexcept {
        FileSystemFilterConfig config;
        config.scanOnWrite = true;
        config.blockOnTimeout = true;
        config.blockOnError = true;
        config.cacheNegativeResults = false;
        return config;
    }
};

/**
 * @brief Statistics for file system filter.
 */
struct FileSystemFilterStats {
    /// @brief Total scan requests received
    std::atomic<uint64_t> totalScanRequests{ 0 };
    
    /// @brief Scan requests completed
    std::atomic<uint64_t> scanRequestsCompleted{ 0 };
    
    /// @brief Files allowed
    std::atomic<uint64_t> filesAllowed{ 0 };
    
    /// @brief Files blocked
    std::atomic<uint64_t> filesBlocked{ 0 };
    
    /// @brief Files quarantined
    std::atomic<uint64_t> filesQuarantined{ 0 };
    
    /// @brief Scan timeouts
    std::atomic<uint64_t> scanTimeouts{ 0 };
    
    /// @brief Scan errors
    std::atomic<uint64_t> scanErrors{ 0 };
    
    /// @brief Cache hits
    std::atomic<uint64_t> cacheHits{ 0 };
    
    /// @brief Cache misses
    std::atomic<uint64_t> cacheMisses{ 0 };
    
    /// @brief Notifications received
    std::atomic<uint64_t> notificationsReceived{ 0 };
    
    /// @brief Exclusions matched
    std::atomic<uint64_t> exclusionsMatched{ 0 };
    
    /// @brief Current pending requests
    std::atomic<uint32_t> pendingRequests{ 0 };
    
    /// @brief Peak pending requests
    std::atomic<uint32_t> peakPendingRequests{ 0 };
    
    /// @brief Average scan time (microseconds)
    std::atomic<uint64_t> avgScanTimeUs{ 0 };
    
    /// @brief Total bytes scanned
    std::atomic<uint64_t> totalBytesScanned{ 0 };
    
    /// @brief Driver connection count
    std::atomic<uint32_t> driverReconnects{ 0 };
    
    /**
     * @brief Reset all statistics.
     */
    void Reset() noexcept {
        totalScanRequests.store(0, std::memory_order_relaxed);
        scanRequestsCompleted.store(0, std::memory_order_relaxed);
        filesAllowed.store(0, std::memory_order_relaxed);
        filesBlocked.store(0, std::memory_order_relaxed);
        filesQuarantined.store(0, std::memory_order_relaxed);
        scanTimeouts.store(0, std::memory_order_relaxed);
        scanErrors.store(0, std::memory_order_relaxed);
        cacheHits.store(0, std::memory_order_relaxed);
        cacheMisses.store(0, std::memory_order_relaxed);
        notificationsReceived.store(0, std::memory_order_relaxed);
        exclusionsMatched.store(0, std::memory_order_relaxed);
        pendingRequests.store(0, std::memory_order_relaxed);
        peakPendingRequests.store(0, std::memory_order_relaxed);
        avgScanTimeUs.store(0, std::memory_order_relaxed);
        totalBytesScanned.store(0, std::memory_order_relaxed);
        driverReconnects.store(0, std::memory_order_relaxed);
    }
};

/**
 * @brief Callback types.
 */
using ScanRequestCallback = std::function<ScanVerdict(const FileAccessEvent&)>;
using FileNotificationCallback = std::function<void(const FileAccessEvent&)>;
using FilterStatusCallback = std::function<void(FilterStatus, const std::wstring&)>;
using ThreatDetectedCallback = std::function<void(const FileAccessEvent&, const std::wstring&, double)>;

// ============================================================================
// MAIN FILE SYSTEM FILTER CLASS
// ============================================================================

/**
 * @brief User-mode interface for kernel minifilter communication.
 *
 * Manages the communication channel with the ShadowStrike kernel minifilter
 * driver, receiving file access events and sending scan verdicts.
 *
 * Thread Safety: All public methods are thread-safe.
 *
 * Usage Example:
 * @code
 * auto& filter = FileSystemFilter::Instance();
 * 
 * // Initialize
 * FileSystemFilterConfig config = FileSystemFilterConfig::CreateDefault();
 * filter.Initialize(threadPool, config);
 * 
 * // Set scan engine
 * filter.SetScanEngine(&ScanEngine::Instance());
 * 
 * // Register callbacks
 * filter.RegisterScanCallback([](const FileAccessEvent& event) -> ScanVerdict {
 *     // Custom scan logic if needed
 *     return ScanVerdict::Allow;
 * });
 * 
 * filter.RegisterNotificationCallback([](const FileAccessEvent& event) {
 *     // Handle file system notifications
 *     LOG_DEBUG(L"File event: {} on {}", 
 *               FilterMessageTypeToString(event.messageType), event.filePath);
 * });
 * 
 * // Start filtering
 * if (filter.Start()) {
 *     LOG_INFO("File system filter started");
 * }
 * 
 * // Add exclusions
 * FilterExclusion exclusion;
 * exclusion.type = FilterExclusion::Type::Path;
 * exclusion.pattern = L"C:\\Windows\\Temp\\";
 * filter.AddExclusion(exclusion);
 * 
 * // Update policy at runtime
 * filter.UpdatePolicy(policy);
 * 
 * // Query status
 * DriverStatus status = filter.GetDriverStatus();
 * 
 * filter.Stop();
 * filter.Shutdown();
 * @endcode
 */
class FileSystemFilter {
public:
    // =========================================================================
    // Singleton Access
    // =========================================================================

    /**
     * @brief Get the singleton instance.
     * @return Reference to the global FileSystemFilter instance.
     */
    [[nodiscard]] static FileSystemFilter& Instance();

    // Non-copyable, non-movable
    FileSystemFilter(const FileSystemFilter&) = delete;
    FileSystemFilter& operator=(const FileSystemFilter&) = delete;
    FileSystemFilter(FileSystemFilter&&) = delete;
    FileSystemFilter& operator=(FileSystemFilter&&) = delete;

    // =========================================================================
    // Lifecycle Management
    // =========================================================================

    /**
     * @brief Initialize the filter.
     * @return true on success.
     */
    [[nodiscard]] bool Initialize();

    /**
     * @brief Initialize with thread pool.
     */
    [[nodiscard]] bool Initialize(std::shared_ptr<Utils::ThreadPool> threadPool);

    /**
     * @brief Initialize with configuration.
     */
    [[nodiscard]] bool Initialize(
        std::shared_ptr<Utils::ThreadPool> threadPool,
        const FileSystemFilterConfig& config
    );

    /**
     * @brief Shutdown the filter.
     */
    void Shutdown();

    /**
     * @brief Start filtering.
     * @return true if started successfully.
     */
    [[nodiscard]] bool Start();

    /**
     * @brief Stop filtering.
     */
    void Stop();

    /**
     * @brief Pause filtering temporarily.
     */
    void Pause();

    /**
     * @brief Resume filtering.
     */
    void Resume();

    /**
     * @brief Check if filter is running.
     */
    [[nodiscard]] bool IsRunning() const noexcept;

    /**
     * @brief Check if filter is initialized.
     */
    [[nodiscard]] bool IsInitialized() const noexcept;

    /**
     * @brief Get current filter status.
     */
    [[nodiscard]] FilterStatus GetStatus() const noexcept;

    /**
     * @brief Update configuration at runtime.
     */
    void UpdateConfig(const FileSystemFilterConfig& config);

    /**
     * @brief Get current configuration.
     */
    [[nodiscard]] FileSystemFilterConfig GetConfig() const;

    // =========================================================================
    // Policy Management
    // =========================================================================

    /**
     * @brief Update filter policy in kernel.
     */
    bool UpdatePolicy(const PolicyUpdate& policy);

    /**
     * @brief Enable scan on open.
     */
    void SetScanOnOpen(bool enable);

    /**
     * @brief Enable scan on execute.
     */
    void SetScanOnExecute(bool enable);

    /**
     * @brief Enable scan on write.
     */
    void SetScanOnWrite(bool enable);

    /**
     * @brief Enable notifications.
     */
    void SetNotificationsEnabled(bool enable);

    /**
     * @brief Set scan timeout.
     */
    void SetScanTimeout(uint32_t timeoutMs);

    /**
     * @brief Set maximum file size for scanning.
     */
    void SetMaxScanFileSize(uint64_t maxSize);

    // =========================================================================
    // Exclusion Management
    // =========================================================================

    /**
     * @brief Add exclusion.
     */
    bool AddExclusion(const FilterExclusion& exclusion);

    /**
     * @brief Remove exclusion.
     */
    bool RemoveExclusion(const std::wstring& pattern);

    /**
     * @brief Clear all exclusions.
     */
    void ClearExclusions();

    /**
     * @brief Get all exclusions.
     */
    [[nodiscard]] std::vector<FilterExclusion> GetExclusions() const;

    /**
     * @brief Check if path is excluded.
     */
    [[nodiscard]] bool IsPathExcluded(const std::wstring& path) const;

    /**
     * @brief Check if process is excluded.
     */
    [[nodiscard]] bool IsProcessExcluded(
        const std::wstring& processName,
        const std::wstring& processPath = L""
    ) const;

    /**
     * @brief Sync exclusions to kernel driver.
     */
    bool SyncExclusionsToDriver();

    // =========================================================================
    // Verdict Operations
    // =========================================================================

    /**
     * @brief Send verdict for a pending request.
     * @param messageId Message ID to reply to.
     * @param verdict Scan verdict.
     * @param threatName Threat name (if blocked).
     * @param cacheResult Whether to cache the result.
     * @return true if verdict was sent.
     */
    bool SendVerdict(
        uint64_t messageId,
        ScanVerdict verdict,
        const std::wstring& threatName = L"",
        bool cacheResult = true
    );

    /**
     * @brief Cancel pending request.
     * @param messageId Message ID to cancel.
     */
    void CancelRequest(uint64_t messageId);

    // =========================================================================
    // Cache Management
    // =========================================================================

    /**
     * @brief Flush scan cache.
     */
    void FlushCache();

    /**
     * @brief Invalidate cache entry by path.
     */
    void InvalidateCacheEntry(const std::wstring& path);

    /**
     * @brief Invalidate cache entry by hash.
     */
    void InvalidateCacheEntryByHash(const std::string& hash);

    /**
     * @brief Get cache hit rate.
     */
    [[nodiscard]] double GetCacheHitRate() const noexcept;

    // =========================================================================
    // Driver Communication
    // =========================================================================

    /**
     * @brief Get driver status.
     */
    [[nodiscard]] DriverStatus GetDriverStatus() const;

    /**
     * @brief Check if driver is installed.
     */
    [[nodiscard]] bool IsDriverInstalled() const;

    /**
     * @brief Get driver version.
     */
    [[nodiscard]] std::string GetDriverVersion() const;

    /**
     * @brief Reconnect to driver.
     */
    bool Reconnect();

    // =========================================================================
    // Statistics
    // =========================================================================

    /**
     * @brief Get filter statistics.
     */
    [[nodiscard]] FileSystemFilterStats GetStats() const;

    /**
     * @brief Reset statistics.
     */
    void ResetStats();

    // =========================================================================
    // Callbacks
    // =========================================================================

    /**
     * @brief Register scan request callback.
     * @note If registered, this callback handles scanning instead of ScanEngine.
     */
    void RegisterScanCallback(ScanRequestCallback callback);

    /**
     * @brief Register notification callback.
     */
    [[nodiscard]] uint64_t RegisterNotificationCallback(FileNotificationCallback callback);

    /**
     * @brief Unregister notification callback.
     */
    bool UnregisterNotificationCallback(uint64_t callbackId);

    /**
     * @brief Register status change callback.
     */
    [[nodiscard]] uint64_t RegisterStatusCallback(FilterStatusCallback callback);

    /**
     * @brief Unregister status callback.
     */
    bool UnregisterStatusCallback(uint64_t callbackId);

    /**
     * @brief Register threat detected callback.
     */
    [[nodiscard]] uint64_t RegisterThreatCallback(ThreatDetectedCallback callback);

    /**
     * @brief Unregister threat callback.
     */
    bool UnregisterThreatCallback(uint64_t callbackId);

    // =========================================================================
    // External Integration
    // =========================================================================

    /**
     * @brief Set scan engine.
     */
    void SetScanEngine(Core::Engine::ScanEngine* engine);

    /**
     * @brief Set threat detector.
     */
    void SetThreatDetector(Core::Engine::ThreatDetector* detector);

    /**
     * @brief Set whitelist store.
     */
    void SetWhitelistStore(Whitelist::WhitelistStore* store);

    /**
     * @brief Set hash store (for allow/block lists).
     */
    void SetHashStore(HashStore::HashStore* store);

    /**
     * @brief Set cache manager.
     */
    void SetCacheManager(Utils::CacheManager* cache);

private:
    // =========================================================================
    // Private Constructor (Singleton)
    // =========================================================================

    FileSystemFilter();
    ~FileSystemFilter();

    // =========================================================================
    // Internal Methods
    // =========================================================================

    /**
     * @brief Connect to driver communication port.
     */
    bool ConnectToDriver();

    /**
     * @brief Disconnect from driver.
     */
    void DisconnectFromDriver();

    /**
     * @brief Message receiving loop.
     */
    void MessageLoop();

    /**
     * @brief Process received message.
     */
    void ProcessMessage(const FilterMessageHeader* header, const void* data);

    /**
     * @brief Handle scan request.
     */
    void HandleScanRequest(const FileScanRequest* request, const void* data);

    /**
     * @brief Handle notification.
     */
    void HandleNotification(const FileNotification* notification, const void* data);

    /**
     * @brief Decode file access event from message.
     */
    FileAccessEvent DecodeEvent(const FileScanRequest* request, const void* data);

    /**
     * @brief Perform file scan.
     */
    ScanVerdict PerformScan(const FileAccessEvent& event);

    /**
     * @brief Check exclusions.
     */
    bool CheckExclusions(const FileAccessEvent& event);

    /**
     * @brief Check scan cache.
     */
    std::optional<ScanVerdict> CheckCache(const std::wstring& path);

    /**
     * @brief Update scan cache.
     */
    void UpdateCache(const std::wstring& path, ScanVerdict verdict);

    /**
     * @brief Determine request priority.
     */
    RequestPriority DeterminePriority(const FileAccessEvent& event);

    /**
     * @brief Invoke notification callbacks.
     */
    void InvokeNotificationCallbacks(const FileAccessEvent& event);

    /**
     * @brief Invoke status callbacks.
     */
    void InvokeStatusCallbacks(FilterStatus status, const std::wstring& message);

    /**
     * @brief Invoke threat callbacks.
     */
    void InvokeThreatCallbacks(const FileAccessEvent& event, const std::wstring& threatName, double score);

    /**
     * @brief Update status.
     */
    void SetStatus(FilterStatus status);

    // =========================================================================
    // Internal Data (PIMPL)
    // =========================================================================

    struct Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Convert FilterMessageType to string.
 */
[[nodiscard]] const char* FilterMessageTypeToString(FilterMessageType type) noexcept;

/**
 * @brief Convert FileAccessType to string.
 */
[[nodiscard]] const char* FileAccessTypeToString(FileAccessType type) noexcept;

/**
 * @brief Get file extension from path.
 */
[[nodiscard]] std::wstring GetFileExtension(const std::wstring& path) noexcept;

/**
 * @brief Normalize path for comparison.
 */
[[nodiscard]] std::wstring NormalizePath(const std::wstring& path) noexcept;

/**
 * @brief Check if path matches wildcard pattern.
 */
[[nodiscard]] bool PathMatchesPattern(
    const std::wstring& path,
    const std::wstring& pattern,
    bool caseInsensitive = true
) noexcept;

/**
 * @brief Check if file is executable based on extension.
 */
[[nodiscard]] bool IsExecutableExtension(const std::wstring& extension) noexcept;

/**
 * @brief Check if file is a script based on extension.
 */
[[nodiscard]] bool IsScriptExtension(const std::wstring& extension) noexcept;

/**
 * @brief Get minifilter altitude for registration.
 */
[[nodiscard]] constexpr const wchar_t* GetFilterAltitude() noexcept {
    // Altitude 320000-329999 is for AV file system filter drivers
    return L"328451";
}

} // namespace RealTime
} // namespace ShadowStrike
