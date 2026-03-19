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
 * ShadowStrike Forensics - INCIDENT RECORDING ENGINE
 * ============================================================================
 *
 * @file IncidentRecorder.hpp
 * @brief Enterprise-grade security incident recording and journaling system
 *        for persistent storage of security events, detections, and forensic data.
 *
 * This module provides comprehensive incident recording capabilities with
 * tamper-proof logging, structured data storage, and forensic context linking.
 *
 * RECORDING CAPABILITIES:
 * =======================
 *
 * 1. EVENT JOURNALING
 *    - Block/detection events
 *    - Policy violations
 *    - System changes
 *    - User actions
 *    - Network events
 *
 * 2. STRUCTURED STORAGE
 *    - SQLite database backend
 *    - Efficient indexing
 *    - Full-text search
 *    - Time-series optimization
 *    - Compression support
 *
 * 3. FORENSIC CONTEXT
 *    - PID to executable hash linking
 *    - Process ancestry chains
 *    - File hash associations
 *    - Network connection mapping
 *    - Registry change tracking
 *
 * 4. TAMPER PROTECTION
 *    - Cryptographic signing
 *    - Hash chaining
 *    - Integrity verification
 *    - Write-ahead logging
 *    - Backup rotation
 *
 * 5. QUERY INTERFACE
 *    - Time-based queries
 *    - Severity filtering
 *    - Category filtering
 *    - Full-text search
 *    - Complex joins
 *
 * 6. EXPORT CAPABILITIES
 *    - JSON export
 *    - CSV export
 *    - SIEM integration
 *    - Evidence packaging
 *    - Report generation
 *
 * DATABASE SCHEMA:
 * ================
 * - incidents: Core incident records
 * - events: Detailed event log
 * - processes: Process execution history
 * - files: File hash associations
 * - network: Network activity log
 * - timeline: Unified timeline
 *
 * @note Uses SQLite with WAL mode for concurrent access.
 * @note Implements circular buffer for log rotation.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0
 * @date 2026
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 *
 * COMPLIANCE: SOC2, ISO 27001, NIST, GDPR
 * LICENSE: Proprietary - ShadowStrike Enterprise License
 * ============================================================================
 */

#pragma once

// ============================================================================
// STANDARD LIBRARY INCLUDES
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <set>
#include <optional>
#include <variant>
#include <memory>
#include <functional>
#include <chrono>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <span>
#include <any>

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
// SHADOWSTRIKE INFRASTRUCTURE INCLUDES
// ============================================================================

#include "../Utils/Logger.hpp"
#include "../Utils/FileUtils.hpp"
#include "../Utils/HashUtils.hpp"
#include "../Utils/CryptoUtils.hpp"
#include "../Utils/DatabaseUtils.hpp"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace ShadowStrike::Forensics {
    class IncidentRecorderImpl;
    class EvidenceCollector;
    class TimelineAnalyzer;
}

namespace ShadowStrike {
namespace Forensics {

// ============================================================================
// COMPILE-TIME CONSTANTS
// ============================================================================

namespace IncidentConstants {

    // ========================================================================
    // VERSION
    // ========================================================================
    
    inline constexpr uint32_t VERSION_MAJOR = 3;
    inline constexpr uint32_t VERSION_MINOR = 0;
    inline constexpr uint32_t VERSION_PATCH = 0;

    // ========================================================================
    // DATABASE
    // ========================================================================
    
    /// @brief Database file name
    inline constexpr std::wstring_view DATABASE_FILENAME = L"incidents.db";
    
    /// @brief Maximum database size (bytes)
    inline constexpr uint64_t MAX_DATABASE_SIZE = 10ULL * 1024 * 1024 * 1024;  // 10GB
    
    /// @brief WAL checkpoint threshold
    inline constexpr uint32_t WAL_CHECKPOINT_THRESHOLD = 10000;

    // ========================================================================
    // LIMITS
    // ========================================================================
    
    /// @brief Maximum incidents to store
    inline constexpr size_t MAX_INCIDENTS = 10000000;
    
    /// @brief Maximum events per incident
    inline constexpr size_t MAX_EVENTS_PER_INCIDENT = 10000;
    
    /// @brief Maximum recent incidents
    inline constexpr size_t DEFAULT_RECENT_LIMIT = 100;
    
    /// @brief Maximum query results
    inline constexpr size_t MAX_QUERY_RESULTS = 100000;
    
    /// @brief Maximum detail string length
    inline constexpr size_t MAX_DETAIL_LENGTH = 65536;

    // ========================================================================
    // RETENTION
    // ========================================================================
    
    /// @brief Default retention period (days)
    inline constexpr uint32_t DEFAULT_RETENTION_DAYS = 365;
    
    /// @brief Minimum retention period (days)
    inline constexpr uint32_t MIN_RETENTION_DAYS = 30;
    
    /// @brief Maximum retention period (days)
    inline constexpr uint32_t MAX_RETENTION_DAYS = 3650;  // 10 years

    // ========================================================================
    // HASH SIZE
    // ========================================================================
    
    inline constexpr size_t SHA256_SIZE = 32;
    inline constexpr size_t HASH_CHAIN_SIZE = 32;

}  // namespace IncidentConstants

// ============================================================================
// TYPE ALIASES
// ============================================================================

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::steady_clock::time_point;
using SystemTimePoint = std::chrono::system_clock::time_point;
using Hash256 = std::array<uint8_t, 32>;

// ============================================================================
// ENUMERATIONS
// ============================================================================

/**
 * @brief Incident category
 */
enum class IncidentCategory : uint8_t {
    Unknown         = 0,
    Detection       = 1,    ///< Malware detection
    Exploit         = 2,    ///< Exploit attempt
    Policy          = 3,    ///< Policy violation
    Network         = 4,    ///< Network threat
    Behavioral      = 5,    ///< Behavioral detection
    Ransomware      = 6,    ///< Ransomware activity
    DataExfil       = 7,    ///< Data exfiltration
    PrivilegeEsc    = 8,    ///< Privilege escalation
    LateralMovement = 9,    ///< Lateral movement
    Persistence     = 10,   ///< Persistence attempt
    Evasion         = 11,   ///< Evasion attempt
    System          = 12,   ///< System event
    Audit           = 13,   ///< Audit event
    Custom          = 255   ///< Custom category
};

/**
 * @brief Incident severity
 */
enum class IncidentSeverity : uint8_t {
    Unknown     = 0,
    Info        = 1,    ///< Informational
    Low         = 2,    ///< Low severity
    Medium      = 3,    ///< Medium severity
    High        = 4,    ///< High severity
    Critical    = 5     ///< Critical severity
};

/**
 * @brief Incident status
 */
enum class IncidentStatus : uint8_t {
    Open        = 0,    ///< New/open incident
    Investigating = 1,  ///< Under investigation
    Contained   = 2,    ///< Threat contained
    Remediated  = 3,    ///< Threat remediated
    Closed      = 4,    ///< Incident closed
    FalsePositive = 5   ///< False positive
};

/**
 * @brief Event type
 */
enum class EventType : uint32_t {
    Unknown             = 0x00000000,
    ProcessCreate       = 0x00000001,
    ProcessTerminate    = 0x00000002,
    FileCreate          = 0x00000004,
    FileDelete          = 0x00000008,
    FileModify          = 0x00000010,
    FileAccess          = 0x00000020,
    RegistryCreate      = 0x00000040,
    RegistryDelete      = 0x00000080,
    RegistryModify      = 0x00000100,
    NetworkConnect      = 0x00000200,
    NetworkListen       = 0x00000400,
    NetworkReceive      = 0x00000800,
    DNSQuery            = 0x00001000,
    ImageLoad           = 0x00002000,
    DriverLoad          = 0x00004000,
    ThreadCreate        = 0x00008000,
    ThreadRemote        = 0x00010000,
    MemoryAlloc         = 0x00020000,
    MemoryWrite         = 0x00040000,
    Detection           = 0x00080000,
    Block               = 0x00100000,
    Alert               = 0x00200000,
    Quarantine          = 0x00400000,
    Remediation         = 0x00800000,
    
    All                 = 0xFFFFFFFF
};

inline constexpr EventType operator|(EventType a, EventType b) noexcept {
    return static_cast<EventType>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

/**
 * @brief Action taken
 */
enum class ActionTaken : uint8_t {
    None            = 0,
    Detected        = 1,
    Blocked         = 2,
    Quarantined     = 3,
    Cleaned         = 4,
    Deleted         = 5,
    Terminated      = 6,
    Allowed         = 7,
    Logged          = 8,
    Alerted         = 9,
    Escalated       = 10
};

/**
 * @brief Query sort order
 */
enum class SortOrder : uint8_t {
    Ascending   = 0,
    Descending  = 1
};

/**
 * @brief Query field
 */
enum class QueryField : uint8_t {
    Id          = 0,
    Timestamp   = 1,
    Category    = 2,
    Severity    = 3,
    Status      = 4,
    ProcessId   = 5,
    FilePath    = 6,
    Hash        = 7
};

/**
 * @brief Module status
 */
enum class ModuleStatus : uint8_t {
    Uninitialized   = 0,
    Initializing    = 1,
    Running         = 2,
    Degraded        = 3,
    Paused          = 4,
    Stopping        = 5,
    Stopped         = 6,
    Error           = 7
};

// ============================================================================
// STRUCTURES
// ============================================================================

/**
 * @brief Incident record
 */
struct Incident {
    /// @brief Incident ID
    uint64_t id = 0;
    
    /// @brief Timestamp (Unix epoch microseconds)
    uint64_t timestamp = 0;
    
    /// @brief Category
    IncidentCategory category = IncidentCategory::Unknown;
    
    /// @brief Severity
    IncidentSeverity severity = IncidentSeverity::Unknown;
    
    /// @brief Status
    IncidentStatus status = IncidentStatus::Open;
    
    /// @brief Details string
    std::string details;
    
    /// @brief Source process ID
    uint32_t processId = 0;
    
    /// @brief Source process name
    std::wstring processName;
    
    /// @brief Source process path
    std::wstring processPath;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Associated file path
    std::wstring filePath;
    
    /// @brief File hash
    Hash256 fileHash{};
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief User SID
    std::wstring userSID;
    
    /// @brief Hostname
    std::wstring hostname;
    
    /// @brief Action taken
    ActionTaken action = ActionTaken::None;
    
    /// @brief Detection name
    std::string detectionName;
    
    /// @brief Threat ID (from ThreatIntel)
    std::string threatId;
    
    /// @brief MITRE ATT&CK technique
    std::string mitreTechnique;
    
    /// @brief Network remote address
    std::string remoteAddress;
    
    /// @brief Network remote port
    uint16_t remotePort = 0;
    
    /// @brief Related incident IDs
    std::vector<uint64_t> relatedIncidents;
    
    /// @brief Tags
    std::vector<std::string> tags;
    
    /// @brief Custom metadata
    std::unordered_map<std::string, std::string> metadata;
    
    /// @brief Hash chain (for integrity)
    Hash256 hashChain{};
    
    /// @brief Is verified (integrity)
    bool isVerified = false;
    
    /**
     * @brief Get category name
     */
    [[nodiscard]] std::string GetCategoryString() const;
    
    /**
     * @brief Get severity name
     */
    [[nodiscard]] std::string GetSeverityString() const;
    
    /**
     * @brief Get status name
     */
    [[nodiscard]] std::string GetStatusString() const;
    
    /**
     * @brief Get timestamp as system time
     */
    [[nodiscard]] SystemTimePoint GetTimestamp() const;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
    
    /**
     * @brief Compute record hash
     */
    [[nodiscard]] Hash256 ComputeHash() const;
};

/**
 * @brief Detailed event record
 */
struct EventRecord {
    /// @brief Event ID
    uint64_t id = 0;
    
    /// @brief Parent incident ID
    uint64_t incidentId = 0;
    
    /// @brief Timestamp (Unix epoch microseconds)
    uint64_t timestamp = 0;
    
    /// @brief Event type
    EventType type = EventType::Unknown;
    
    /// @brief Event details
    std::string details;
    
    /// @brief Source process ID
    uint32_t processId = 0;
    
    /// @brief Thread ID
    uint32_t threadId = 0;
    
    /// @brief Target process ID (for injection, etc.)
    uint32_t targetProcessId = 0;
    
    /// @brief File/Registry path
    std::wstring path;
    
    /// @brief Old value (for modifications)
    std::vector<uint8_t> oldValue;
    
    /// @brief New value (for modifications)
    std::vector<uint8_t> newValue;
    
    /// @brief Network information
    std::string networkInfo;
    
    /// @brief Stack trace
    std::vector<uint64_t> stackTrace;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Process execution record
 */
struct ProcessRecord {
    /// @brief Record ID
    uint64_t id = 0;
    
    /// @brief Process ID
    uint32_t processId = 0;
    
    /// @brief Parent process ID
    uint32_t parentProcessId = 0;
    
    /// @brief Process name
    std::wstring processName;
    
    /// @brief Full path
    std::wstring processPath;
    
    /// @brief Command line
    std::wstring commandLine;
    
    /// @brief Executable hash
    Hash256 hash{};
    
    /// @brief Start time
    uint64_t startTime = 0;
    
    /// @brief End time (0 if still running)
    uint64_t endTime = 0;
    
    /// @brief User name
    std::wstring userName;
    
    /// @brief User SID
    std::wstring userSID;
    
    /// @brief Integrity level
    uint32_t integrityLevel = 0;
    
    /// @brief Is elevated
    bool isElevated = false;
    
    /// @brief Is system process
    bool isSystem = false;
    
    /// @brief Parent process hash
    Hash256 parentHash{};
    
    /// @brief Session ID
    uint32_t sessionId = 0;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Query filter
 */
struct QueryFilter {
    /// @brief Time range start
    std::optional<SystemTimePoint> startTime;
    
    /// @brief Time range end
    std::optional<SystemTimePoint> endTime;
    
    /// @brief Categories to include
    std::vector<IncidentCategory> categories;
    
    /// @brief Minimum severity
    std::optional<IncidentSeverity> minSeverity;
    
    /// @brief Maximum severity
    std::optional<IncidentSeverity> maxSeverity;
    
    /// @brief Statuses to include
    std::vector<IncidentStatus> statuses;
    
    /// @brief Event types to include
    EventType eventTypes = EventType::All;
    
    /// @brief Process ID filter
    std::optional<uint32_t> processId;
    
    /// @brief File path pattern (LIKE query)
    std::wstring filePathPattern;
    
    /// @brief File hash filter
    std::optional<Hash256> fileHash;
    
    /// @brief User name filter
    std::wstring userName;
    
    /// @brief Text search (in details)
    std::string textSearch;
    
    /// @brief Tags filter (any match)
    std::vector<std::string> tags;
    
    /// @brief Detection name filter
    std::string detectionName;
    
    /// @brief MITRE technique filter
    std::string mitreTechnique;
    
    /// @brief Sort field
    QueryField sortField = QueryField::Timestamp;
    
    /// @brief Sort order
    SortOrder sortOrder = SortOrder::Descending;
    
    /// @brief Maximum results
    size_t limit = IncidentConstants::DEFAULT_RECENT_LIMIT;
    
    /// @brief Offset for pagination
    size_t offset = 0;
};

/**
 * @brief Incident recorder configuration
 */
struct IncidentRecorderConfiguration {
    /// @brief Database path
    std::wstring databasePath;
    
    /// @brief Maximum database size (bytes)
    uint64_t maxDatabaseSize = IncidentConstants::MAX_DATABASE_SIZE;
    
    /// @brief Retention period (days)
    uint32_t retentionDays = IncidentConstants::DEFAULT_RETENTION_DAYS;
    
    /// @brief Enable WAL mode
    bool enableWAL = true;
    
    /// @brief Enable compression
    bool enableCompression = true;
    
    /// @brief Enable integrity verification
    bool enableIntegrity = true;
    
    /// @brief Sync mode (0=OFF, 1=NORMAL, 2=FULL)
    uint32_t syncMode = 1;
    
    /// @brief Auto-vacuum mode
    bool autoVacuum = true;
    
    /// @brief Backup interval (hours)
    uint32_t backupIntervalHours = 24;
    
    /// @brief Maximum backups to keep
    uint32_t maxBackups = 7;
    
    /// @brief SIEM export enabled
    bool siemExportEnabled = false;
    
    /// @brief SIEM endpoint URL
    std::string siemEndpoint;
    
    /// @brief Verbose logging
    bool verboseLogging = false;
    
    /**
     * @brief Validate configuration
     */
    [[nodiscard]] bool IsValid() const noexcept;
};

/**
 * @brief Incident statistics
 */
struct IncidentStatistics {
    /// @brief Total incidents recorded
    std::atomic<uint64_t> totalIncidents{0};
    
    /// @brief Total events recorded
    std::atomic<uint64_t> totalEvents{0};
    
    /// @brief Incidents by severity
    std::array<std::atomic<uint64_t>, 6> bySeverity{};
    
    /// @brief Incidents by category
    std::array<std::atomic<uint64_t>, 16> byCategory{};
    
    /// @brief Open incidents
    std::atomic<uint64_t> openIncidents{0};
    
    /// @brief Incidents today
    std::atomic<uint64_t> incidentsToday{0};
    
    /// @brief Database size (bytes)
    std::atomic<uint64_t> databaseSize{0};
    
    /// @brief Start time
    TimePoint startTime = Clock::now();
    
    /**
     * @brief Reset statistics
     */
    void Reset() noexcept;
    
    /**
     * @brief Serialize to JSON
     */
    [[nodiscard]] std::string ToJson() const;
};

/**
 * @brief Query result
 */
struct QueryResult {
    /// @brief Incidents matching query
    std::vector<Incident> incidents;
    
    /// @brief Total matching (before limit)
    size_t totalMatching = 0;
    
    /// @brief Query execution time (microseconds)
    uint64_t executionTimeUs = 0;
    
    /// @brief Is result truncated
    bool isTruncated = false;
};

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/// @brief New incident callback
using IncidentCallback = std::function<void(const Incident&)>;

/// @brief Severity threshold callback
using SeverityCallback = std::function<void(const Incident&, IncidentSeverity)>;

/// @brief Export callback
using ExportCallback = std::function<void(const std::string& json)>;

// ============================================================================
// INCIDENT RECORDER ENGINE CLASS
// ============================================================================

/**
 * @class IncidentRecorder
 * @brief Enterprise-grade security incident recording engine
 *
 * Provides comprehensive incident recording with tamper-proof logging,
 * structured storage, and forensic context linking.
 *
 * THREAD SAFETY: All public methods are thread-safe.
 *
 * USAGE:
 * @code
 *     auto& recorder = IncidentRecorder::Instance();
 *     
 *     // Record incident
 *     Incident incident;
 *     incident.category = IncidentCategory::Detection;
 *     incident.severity = IncidentSeverity::High;
 *     incident.details = "Malware detected";
 *     recorder.RecordIncident(incident);
 *     
 *     // Query incidents
 *     auto recent = recorder.GetRecentIncidents(100);
 * @endcode
 */
class IncidentRecorder final {
public:
    // ========================================================================
    // SINGLETON ACCESS
    // ========================================================================
    
    /**
     * @brief Get singleton instance
     */
    [[nodiscard]] static IncidentRecorder& Instance() noexcept;
    
    /**
     * @brief Check if instance exists
     */
    [[nodiscard]] static bool HasInstance() noexcept;
    
    // Non-copyable, non-movable
    IncidentRecorder(const IncidentRecorder&) = delete;
    IncidentRecorder& operator=(const IncidentRecorder&) = delete;
    IncidentRecorder(IncidentRecorder&&) = delete;
    IncidentRecorder& operator=(IncidentRecorder&&) = delete;

    // ========================================================================
    // LIFECYCLE MANAGEMENT
    // ========================================================================
    
    /**
     * @brief Initialize incident recorder
     */
    [[nodiscard]] bool Initialize(const IncidentRecorderConfiguration& config = {});
    
    /**
     * @brief Shutdown incident recorder
     */
    void Shutdown();
    
    /**
     * @brief Check if initialized
     */
    [[nodiscard]] bool IsInitialized() const noexcept;
    
    /**
     * @brief Get current status
     */
    [[nodiscard]] ModuleStatus GetStatus() const noexcept;
    
    // ========================================================================
    // INCIDENT RECORDING
    // ========================================================================
    
    /**
     * @brief Commit a new security incident to the database
     */
    void RecordIncident(const Incident& incident);
    
    /**
     * @brief Record incident and return ID
     */
    [[nodiscard]] uint64_t RecordIncidentWithId(const Incident& incident);
    
    /**
     * @brief Record incident with severity threshold check
     */
    void RecordIncident(const Incident& incident, IncidentSeverity alertThreshold);
    
    /**
     * @brief Update existing incident
     */
    [[nodiscard]] bool UpdateIncident(uint64_t incidentId, const Incident& updated);
    
    /**
     * @brief Update incident status
     */
    [[nodiscard]] bool UpdateStatus(uint64_t incidentId, IncidentStatus newStatus);
    
    /**
     * @brief Add tag to incident
     */
    [[nodiscard]] bool AddTag(uint64_t incidentId, std::string_view tag);
    
    /**
     * @brief Remove tag from incident
     */
    [[nodiscard]] bool RemoveTag(uint64_t incidentId, std::string_view tag);
    
    // ========================================================================
    // EVENT RECORDING
    // ========================================================================
    
    /**
     * @brief Record detailed event
     */
    [[nodiscard]] uint64_t RecordEvent(const EventRecord& event);
    
    /**
     * @brief Record event linked to incident
     */
    [[nodiscard]] uint64_t RecordEvent(uint64_t incidentId, const EventRecord& event);
    
    /**
     * @brief Get events for incident
     */
    [[nodiscard]] std::vector<EventRecord> GetIncidentEvents(uint64_t incidentId);
    
    // ========================================================================
    // PROCESS RECORDING
    // ========================================================================
    
    /**
     * @brief Record process execution
     */
    void RecordProcess(const ProcessRecord& process);
    
    /**
     * @brief Update process end time
     */
    void UpdateProcessEnd(uint32_t processId, uint64_t endTime);
    
    /**
     * @brief Get process ancestry chain
     */
    [[nodiscard]] std::vector<ProcessRecord> GetProcessAncestry(uint32_t processId);
    
    // ========================================================================
    // QUERY INTERFACE
    // ========================================================================
    
    /**
     * @brief Retrieve incidents for analysis
     */
    [[nodiscard]] std::vector<Incident> GetRecentIncidents(uint32_t limit = 100);
    
    /**
     * @brief Query incidents with filter
     */
    [[nodiscard]] QueryResult QueryIncidents(const QueryFilter& filter);
    
    /**
     * @brief Get incident by ID
     */
    [[nodiscard]] std::optional<Incident> GetIncident(uint64_t incidentId);
    
    /**
     * @brief Get incidents by severity
     */
    [[nodiscard]] std::vector<Incident> GetIncidentsBySeverity(IncidentSeverity severity,
                                                               uint32_t limit = 100);
    
    /**
     * @brief Get incidents by category
     */
    [[nodiscard]] std::vector<Incident> GetIncidentsByCategory(IncidentCategory category,
                                                               uint32_t limit = 100);
    
    /**
     * @brief Get incidents by time range
     */
    [[nodiscard]] std::vector<Incident> GetIncidentsByTimeRange(SystemTimePoint start,
                                                                SystemTimePoint end,
                                                                uint32_t limit = 1000);
    
    /**
     * @brief Search incidents by text
     */
    [[nodiscard]] std::vector<Incident> SearchIncidents(std::string_view searchText,
                                                        uint32_t limit = 100);
    
    /**
     * @brief Get related incidents
     */
    [[nodiscard]] std::vector<Incident> GetRelatedIncidents(uint64_t incidentId);
    
    // ========================================================================
    // INTEGRITY
    // ========================================================================
    
    /**
     * @brief Verify incident integrity
     */
    [[nodiscard]] bool VerifyIncidentIntegrity(uint64_t incidentId);
    
    /**
     * @brief Verify all incidents integrity
     */
    [[nodiscard]] std::vector<uint64_t> VerifyAllIntegrity();
    
    /**
     * @brief Get hash chain head
     */
    [[nodiscard]] Hash256 GetHashChainHead() const;
    
    // ========================================================================
    // EXPORT
    // ========================================================================
    
    /**
     * @brief Export incidents to JSON
     */
    [[nodiscard]] std::string ExportToJson(const QueryFilter& filter);
    
    /**
     * @brief Export incidents to CSV
     */
    [[nodiscard]] std::string ExportToCSV(const QueryFilter& filter);
    
    /**
     * @brief Export for SIEM
     */
    [[nodiscard]] bool ExportToSIEM(const QueryFilter& filter);
    
    /**
     * @brief Generate incident report
     */
    [[nodiscard]] std::string GenerateReport(uint64_t incidentId);
    
    // ========================================================================
    // MAINTENANCE
    // ========================================================================
    
    /**
     * @brief Purge old incidents
     */
    [[nodiscard]] size_t PurgeOldIncidents(uint32_t olderThanDays);
    
    /**
     * @brief Compact database
     */
    [[nodiscard]] bool CompactDatabase();
    
    /**
     * @brief Create backup
     */
    [[nodiscard]] bool CreateBackup(std::wstring_view backupPath);
    
    /**
     * @brief Restore from backup
     */
    [[nodiscard]] bool RestoreFromBackup(std::wstring_view backupPath);
    
    // ========================================================================
    // CALLBACKS
    // ========================================================================
    
    /**
     * @brief Set new incident callback
     */
    void SetIncidentCallback(IncidentCallback callback);
    
    /**
     * @brief Set severity threshold callback
     */
    void SetSeverityCallback(SeverityCallback callback, IncidentSeverity threshold);
    
    // ========================================================================
    // STATISTICS
    // ========================================================================
    
    /**
     * @brief Get statistics
     */
    [[nodiscard]] IncidentStatistics GetStatistics() const;
    
    /**
     * @brief Reset statistics
     */
    void ResetStatistics();
    
    /**
     * @brief Get database info
     */
    [[nodiscard]] std::unordered_map<std::string, std::string> GetDatabaseInfo() const;
    
    // ========================================================================
    // UTILITY
    // ========================================================================
    
    /**
     * @brief Self-test
     */
    [[nodiscard]] bool SelfTest();
    
    /**
     * @brief Get version string
     */
    [[nodiscard]] static std::string GetVersionString() noexcept;

private:
    // ========================================================================
    // PRIVATE CONSTRUCTOR
    // ========================================================================
    
    IncidentRecorder();
    ~IncidentRecorder();
    
    // ========================================================================
    // PIMPL
    // ========================================================================
    
    std::unique_ptr<IncidentRecorderImpl> m_impl;
    
    // ========================================================================
    // STATIC INSTANCE FLAG
    // ========================================================================
    
    static std::atomic<bool> s_instanceCreated;
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief Get incident category name
 */
[[nodiscard]] std::string_view GetIncidentCategoryName(IncidentCategory category) noexcept;

/**
 * @brief Get incident severity name
 */
[[nodiscard]] std::string_view GetIncidentSeverityName(IncidentSeverity severity) noexcept;

/**
 * @brief Get incident status name
 */
[[nodiscard]] std::string_view GetIncidentStatusName(IncidentStatus status) noexcept;

/**
 * @brief Get event type name
 */
[[nodiscard]] std::string_view GetEventTypeName(EventType type) noexcept;

/**
 * @brief Get action taken name
 */
[[nodiscard]] std::string_view GetActionTakenName(ActionTaken action) noexcept;

/**
 * @brief Parse incident from JSON
 */
[[nodiscard]] std::optional<Incident> ParseIncidentFromJson(std::string_view json);

}  // namespace Forensics
}  // namespace ShadowStrike

// ============================================================================
// MACROS
// ============================================================================

/**
 * @brief Record incident
 */
#define SS_RECORD_INCIDENT(incident) \
    ::ShadowStrike::Forensics::IncidentRecorder::Instance().RecordIncident(incident)

/**
 * @brief Get recent incidents
 */
#define SS_GET_RECENT_INCIDENTS(limit) \
    ::ShadowStrike::Forensics::IncidentRecorder::Instance().GetRecentIncidents(limit)
