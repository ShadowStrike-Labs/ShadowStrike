/**
 * ============================================================================
 * ShadowStrike NGAV - TELEMETRY TYPES
 * ============================================================================
 *
 * @file TelemetryTypes.h
 * @brief Telemetry and statistics data structures for kernel<->user communication.
 *
 * This file defines all data structures used for driver telemetry,
 * performance statistics, health monitoring, and diagnostic data
 * between the kernel driver and user-mode management service.
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_TELEMETRY_TYPES_H
#define SHADOWSTRIKE_TELEMETRY_TYPES_H

#ifdef _KERNEL_MODE
    #include <fltKernel.h>
#else
    #include <windows.h>
#endif

#include "SharedDefs.h"

// ============================================================================
// TELEMETRY CONSTANTS
// ============================================================================

#define MAX_TELEMETRY_STRING_LENGTH       256
#define MAX_TELEMETRY_BATCH_SIZE          100
#define MAX_COMPONENT_NAME_LENGTH         64
#define MAX_ERROR_MESSAGE_LENGTH          512

// Telemetry protocol version
#define TELEMETRY_PROTOCOL_VERSION        1

// ============================================================================
// TELEMETRY EVENT TYPES
// ============================================================================

/**
 * @brief Telemetry event types.
 */
typedef enum _TELEMETRY_EVENT_TYPE {
    TelemetryEvent_None = 0,
    
    // Health events
    TelemetryEvent_Heartbeat,             // Periodic heartbeat
    TelemetryEvent_StartupComplete,       // Driver initialized
    TelemetryEvent_ShutdownInitiated,     // Driver shutting down
    TelemetryEvent_ConfigurationChange,   // Config changed
    
    // Performance events
    TelemetryEvent_PerformanceSnapshot,   // Periodic perf stats
    TelemetryEvent_HighLatencyWarning,    // Latency exceeded threshold
    TelemetryEvent_ResourcePressure,      // Memory/CPU pressure
    TelemetryEvent_QueueOverflow,         // Message queue overflow
    
    // Error events
    TelemetryEvent_Error,                 // Generic error
    TelemetryEvent_CriticalError,         // Critical error
    TelemetryEvent_ComponentFailure,      // Component failed
    TelemetryEvent_RecoveryAttempt,       // Recovery attempt
    TelemetryEvent_RecoverySuccess,       // Recovery succeeded
    TelemetryEvent_RecoveryFailure,       // Recovery failed
    
    // Diagnostic events
    TelemetryEvent_DiagnosticDump,        // Diagnostic data dump
    TelemetryEvent_DebugInfo,             // Debug information
    TelemetryEvent_Assertion,             // Assertion failure
    
    // Security events
    TelemetryEvent_TamperAttempt,         // Tamper attempt detected
    TelemetryEvent_EvasionAttempt,        // Evasion attempt detected
    TelemetryEvent_SelfProtectionTriggered, // Self-protection engaged
    
    // Statistics events
    TelemetryEvent_StatisticsBatch,       // Batched statistics
    TelemetryEvent_ThreatStatistics,      // Threat detection stats
    TelemetryEvent_NetworkStatistics,     // Network stats
    TelemetryEvent_ProcessStatistics,     // Process monitoring stats
    
    TelemetryEvent_Max
} TELEMETRY_EVENT_TYPE;

/**
 * @brief Component identifiers for health tracking.
 */
typedef enum _DRIVER_COMPONENT_ID {
    Component_None = 0,
    Component_Core,                       // Core driver
    Component_FilterManager,              // Minifilter registration
    Component_Communication,              // User-mode communication
    Component_Cache,                      // Scan cache
    Component_ProcessMonitor,             // Process callbacks
    Component_ThreadMonitor,              // Thread callbacks
    Component_ImageMonitor,               // Image load callbacks
    Component_FileSystemMonitor,          // File system minifilter
    Component_RegistryMonitor,            // Registry callbacks
    Component_NetworkMonitor,             // WFP filtering
    Component_MemoryMonitor,              // Memory monitoring
    Component_BehavioralEngine,           // Behavioral analysis
    Component_SelfProtection,             // Self-protection
    Component_Telemetry,                  // Telemetry subsystem
    Component_ETWProvider,                // ETW provider
    Component_Max
} DRIVER_COMPONENT_ID;

/**
 * @brief Component health status.
 */
typedef enum _COMPONENT_HEALTH_STATUS {
    Health_Unknown = 0,
    Health_Healthy,
    Health_Degraded,
    Health_Failed,
    Health_Recovering,
    Health_Disabled,
    Health_Max
} COMPONENT_HEALTH_STATUS;

/**
 * @brief Error severity levels.
 */
typedef enum _ERROR_SEVERITY {
    ErrorSeverity_Info = 0,
    ErrorSeverity_Warning,
    ErrorSeverity_Error,
    ErrorSeverity_Critical,
    ErrorSeverity_Fatal
} ERROR_SEVERITY;

// ============================================================================
// TELEMETRY STRUCTURES
// ============================================================================

#pragma pack(push, 1)

/**
 * @brief Telemetry event header.
 */
typedef struct _TELEMETRY_EVENT_HEADER {
    UINT32 Size;                          // Total event size
    UINT16 Version;                       // Protocol version
    UINT16 Flags;                         // Event flags
    TELEMETRY_EVENT_TYPE EventType;       // Event type
    UINT64 Timestamp;                     // Event timestamp
    UINT64 SequenceNumber;                // Monotonic sequence
    DRIVER_COMPONENT_ID ComponentId;      // Source component
    UINT32 Reserved;
} TELEMETRY_EVENT_HEADER, *PTELEMETRY_EVENT_HEADER;

// Telemetry event flags
#define TELEMETRY_FLAG_URGENT             0x0001  // High priority
#define TELEMETRY_FLAG_REQUIRES_ACK       0x0002  // Needs acknowledgment
#define TELEMETRY_FLAG_BATCHED            0x0004  // Part of batch
#define TELEMETRY_FLAG_COMPRESSED         0x0008  // Compressed payload
#define TELEMETRY_FLAG_ENCRYPTED          0x0010  // Encrypted payload

/**
 * @brief Heartbeat event.
 */
typedef struct _TELEMETRY_HEARTBEAT {
    TELEMETRY_EVENT_HEADER Header;
    
    // Uptime
    UINT64 DriverUptimeMs;                // Driver uptime in milliseconds
    UINT64 SystemUptimeMs;                // System uptime
    
    // Health summary
    UINT32 HealthyComponents;
    UINT32 DegradedComponents;
    UINT32 FailedComponents;
    UINT32 TotalComponents;
    
    // Quick stats
    UINT64 TotalEventsProcessed;
    UINT64 TotalThreatsDetected;
    UINT64 TotalThreatsBlocked;
    UINT64 TotalFilesScanned;
    
    // Resource usage
    UINT32 PoolUsageBytes;                // Non-paged pool usage
    UINT32 LookasideUsageBytes;           // Lookaside list usage
    UINT32 PendingOperations;             // Pending async operations
    UINT32 ActiveConnections;             // Active comm connections
    
    // Timestamps
    UINT64 LastConfigUpdateTime;
    UINT64 LastThreatDetectionTime;
    UINT64 LastErrorTime;
    
    UINT32 Reserved[4];
} TELEMETRY_HEARTBEAT, *PTELEMETRY_HEARTBEAT;

/**
 * @brief Performance statistics snapshot.
 */
typedef struct _TELEMETRY_PERFORMANCE {
    TELEMETRY_EVENT_HEADER Header;
    
    // Time window
    UINT64 WindowStartTime;
    UINT64 WindowEndTime;
    UINT32 WindowDurationMs;
    UINT32 Reserved1;
    
    // File system statistics
    struct {
        UINT64 TotalOperations;
        UINT64 PreCreateCalls;
        UINT64 PostCreateCalls;
        UINT64 PreWriteCalls;
        UINT64 PostWriteCalls;
        UINT64 PreCleanupCalls;
        UINT64 CacheHits;
        UINT64 CacheMisses;
        UINT32 AverageLatencyUs;          // Microseconds
        UINT32 MaxLatencyUs;
        UINT32 P95LatencyUs;              // 95th percentile
        UINT32 P99LatencyUs;              // 99th percentile
        UINT64 BytesScanned;
        UINT64 FilesBlocked;
    } FileSystem;
    
    // Process monitoring statistics
    struct {
        UINT64 ProcessCreates;
        UINT64 ProcessTerminates;
        UINT64 ProcessesBlocked;
        UINT64 ThreadCreates;
        UINT64 RemoteThreadsDetected;
        UINT64 ImageLoads;
        UINT64 SuspiciousImageLoads;
        UINT32 AverageLatencyUs;
        UINT32 MaxLatencyUs;
    } Process;
    
    // Network statistics
    struct {
        UINT64 ConnectionsMonitored;
        UINT64 ConnectionsBlocked;
        UINT64 DnsQueriesMonitored;
        UINT64 DnsQueriesBlocked;
        UINT64 BytesSent;
        UINT64 BytesReceived;
        UINT64 C2DetectionCount;
        UINT64 ExfiltrationDetectionCount;
        UINT32 AverageLatencyUs;
        UINT32 MaxLatencyUs;
    } Network;
    
    // Memory monitoring statistics
    struct {
        UINT64 AllocationsMonitored;
        UINT64 ProtectionChanges;
        UINT64 ShellcodeDetections;
        UINT64 InjectionDetections;
        UINT64 HollowingDetections;
        UINT32 AverageLatencyUs;
        UINT32 MaxLatencyUs;
    } Memory;
    
    // Communication statistics
    struct {
        UINT64 MessagesSent;
        UINT64 MessagesReceived;
        UINT64 MessagesDropped;
        UINT64 BytesSent;
        UINT64 BytesReceived;
        UINT32 QueueDepth;
        UINT32 MaxQueueDepth;
        UINT32 AverageLatencyUs;
        UINT32 MaxLatencyUs;
    } Communication;
    
    // Resource statistics
    struct {
        UINT32 NonPagedPoolUsedBytes;
        UINT32 NonPagedPoolPeakBytes;
        UINT32 PagedPoolUsedBytes;
        UINT32 PagedPoolPeakBytes;
        UINT32 LookasideAllocations;
        UINT32 LookasideFrees;
        UINT32 WorkItemsQueued;
        UINT32 WorkItemsCompleted;
        UINT32 DpcCount;
        UINT32 IsrCount;
    } Resources;
} TELEMETRY_PERFORMANCE, *PTELEMETRY_PERFORMANCE;

/**
 * @brief Component health status event.
 */
typedef struct _TELEMETRY_COMPONENT_HEALTH {
    TELEMETRY_EVENT_HEADER Header;
    
    DRIVER_COMPONENT_ID ComponentId;
    COMPONENT_HEALTH_STATUS Status;
    COMPONENT_HEALTH_STATUS PreviousStatus;
    UINT32 Reserved1;
    
    // Health metrics
    UINT64 LastSuccessfulOperation;
    UINT64 LastFailedOperation;
    UINT64 OperationCount;
    UINT64 FailureCount;
    UINT32 ConsecutiveFailures;
    UINT32 RecoveryAttempts;
    
    // Error info (if degraded/failed)
    UINT32 LastErrorCode;
    ERROR_SEVERITY ErrorSeverity;
    WCHAR ErrorMessage[MAX_ERROR_MESSAGE_LENGTH];
    WCHAR ComponentName[MAX_COMPONENT_NAME_LENGTH];
    
    // Additional context
    UINT64 AdditionalData[4];
} TELEMETRY_COMPONENT_HEALTH, *PTELEMETRY_COMPONENT_HEALTH;

/**
 * @brief Error event.
 */
typedef struct _TELEMETRY_ERROR {
    TELEMETRY_EVENT_HEADER Header;
    
    // Error details
    UINT32 ErrorCode;                     // NTSTATUS or custom code
    ERROR_SEVERITY Severity;
    DRIVER_COMPONENT_ID SourceComponent;
    UINT32 Reserved1;
    
    // Context
    UINT64 ContextValue1;
    UINT64 ContextValue2;
    UINT64 ContextValue3;
    UINT32 ProcessId;
    UINT32 ThreadId;
    
    // Location
    UINT32 LineNumber;
    UINT32 Reserved2;
    CHAR FileName[64];
    CHAR FunctionName[64];
    
    // Message
    WCHAR ErrorMessage[MAX_ERROR_MESSAGE_LENGTH];
    
    // Stack trace (if available)
    UINT64 StackTrace[16];
    UINT32 StackFrameCount;
    UINT32 Reserved3;
} TELEMETRY_ERROR, *PTELEMETRY_ERROR;

/**
 * @brief Tamper/evasion attempt detection.
 */
typedef struct _TELEMETRY_TAMPER_ATTEMPT {
    TELEMETRY_EVENT_HEADER Header;
    
    // Attempt details
    UINT32 TamperType;                    // TAMPER_ATTEMPT_TYPE
    UINT32 Severity;
    UINT32 ProcessId;
    UINT32 ThreadId;
    
    // Target info
    DRIVER_COMPONENT_ID TargetComponent;
    UINT32 Reserved1;
    UINT64 TargetAddress;
    UINT64 OriginalValue;
    UINT64 AttemptedValue;
    
    // Process info
    WCHAR ProcessImagePath[MAX_FILE_PATH_LENGTH];
    WCHAR ProcessCommandLine[MAX_COMMAND_LINE_LENGTH];
    
    // Response
    UINT32 ResponseAction;                // TAMPER_RESPONSE_ACTION
    BOOLEAN AttemptBlocked;
    UINT8 Reserved2[3];
} TELEMETRY_TAMPER_ATTEMPT, *PTELEMETRY_TAMPER_ATTEMPT;

// Tamper attempt types
typedef enum _TAMPER_ATTEMPT_TYPE {
    Tamper_None = 0,
    Tamper_CallbackRemoval,               // Attempt to remove callbacks
    Tamper_DriverUnload,                  // Attempt to unload driver
    Tamper_ProcessTerminate,              // Attempt to kill our process
    Tamper_FileDelete,                    // Attempt to delete our files
    Tamper_RegistryModify,                // Attempt to modify our registry
    Tamper_ServiceStop,                   // Attempt to stop service
    Tamper_HandleAccess,                  // Suspicious handle access
    Tamper_MemoryModify,                  // Attempt to modify our memory
    Tamper_HookInstall,                   // Attempt to hook our code
    Tamper_Max
} TAMPER_ATTEMPT_TYPE;

// Tamper response actions
typedef enum _TAMPER_RESPONSE_ACTION {
    TamperResponse_None = 0,
    TamperResponse_Block,                 // Blocked the attempt
    TamperResponse_Alert,                 // Alert only
    TamperResponse_Terminate,             // Terminated attacker
    TamperResponse_Quarantine,            // Quarantined attacker
    TamperResponse_Max
} TAMPER_RESPONSE_ACTION;

/**
 * @brief Threat statistics summary.
 */
typedef struct _TELEMETRY_THREAT_STATS {
    TELEMETRY_EVENT_HEADER Header;
    
    // Time window
    UINT64 WindowStartTime;
    UINT64 WindowEndTime;
    
    // Detection counts by category
    UINT64 MalwareDetections;
    UINT64 SuspiciousDetections;
    UINT64 PUADetections;
    UINT64 ExploitDetections;
    UINT64 RansomwareDetections;
    UINT64 CoinminerDetections;
    
    // Detection counts by source
    UINT64 SignatureDetections;
    UINT64 HeuristicDetections;
    UINT64 BehavioralDetections;
    UINT64 MLDetections;
    UINT64 ReputationDetections;
    
    // Action counts
    UINT64 ThreatsBlocked;
    UINT64 ThreatsQuarantined;
    UINT64 ThreatsAllowed;
    UINT64 FalsePositiveReports;
    
    // Severity breakdown
    UINT64 CriticalThreats;
    UINT64 HighThreats;
    UINT64 MediumThreats;
    UINT64 LowThreats;
    
    // Top threats (hashes of top 5)
    UINT8 TopThreatHashes[5][32];
    UINT64 TopThreatCounts[5];
    
    UINT32 Reserved[4];
} TELEMETRY_THREAT_STATS, *PTELEMETRY_THREAT_STATS;

/**
 * @brief Diagnostic data dump.
 */
typedef struct _TELEMETRY_DIAGNOSTIC {
    TELEMETRY_EVENT_HEADER Header;
    
    // System info
    UINT16 OsMajorVersion;
    UINT16 OsMinorVersion;
    UINT32 OsBuildNumber;
    UINT64 SystemMemoryBytes;
    UINT32 ProcessorCount;
    UINT32 Reserved1;
    
    // Driver info
    UINT16 DriverMajorVersion;
    UINT16 DriverMinorVersion;
    UINT16 DriverBuildNumber;
    UINT16 Reserved2;
    UINT64 DriverLoadTime;
    
    // Configuration summary
    UINT32 EnabledFeatures;               // Bitmask
    UINT32 DisabledFeatures;              // Bitmask
    UINT32 PolicyFlags;
    UINT32 Reserved3;
    
    // Component states (bitmask of healthy components)
    UINT32 HealthyComponents;
    UINT32 DegradedComponents;
    UINT32 FailedComponents;
    UINT32 Reserved4;
    
    // Memory state
    UINT64 TotalPoolUsage;
    UINT64 PeakPoolUsage;
    UINT64 TotalLookasideUsage;
    UINT64 AvailableSystemMemory;
    
    // Pending work
    UINT32 PendingFileScans;
    UINT32 PendingProcessAnalysis;
    UINT32 PendingNetworkAnalysis;
    UINT32 PendingMessages;
    
    // Error summary
    UINT64 TotalErrors;
    UINT64 CriticalErrors;
    UINT32 LastErrorCode;
    UINT32 Reserved5;
    UINT64 LastErrorTime;
    
    UINT32 Reserved6[8];
} TELEMETRY_DIAGNOSTIC, *PTELEMETRY_DIAGNOSTIC;

#pragma pack(pop)

// ============================================================================
// TELEMETRY BATCH STRUCTURES
// ============================================================================

/**
 * @brief Batched telemetry header.
 */
typedef struct _TELEMETRY_BATCH_HEADER {
    UINT32 TotalSize;                     // Total batch size
    UINT16 Version;                       // Protocol version
    UINT16 Flags;                         // Batch flags
    UINT32 EventCount;                    // Number of events
    UINT32 Reserved;
    UINT64 BatchId;                       // Unique batch ID
    UINT64 FirstEventTimestamp;
    UINT64 LastEventTimestamp;
    // Variable: Events follow
} TELEMETRY_BATCH_HEADER, *PTELEMETRY_BATCH_HEADER;

// ============================================================================
// TELEMETRY CONFIGURATION
// ============================================================================

/**
 * @brief Telemetry configuration.
 */
typedef struct _TELEMETRY_CONFIG {
    BOOLEAN EnableTelemetry;
    BOOLEAN EnablePerformanceStats;
    BOOLEAN EnableHealthMonitoring;
    BOOLEAN EnableErrorReporting;
    BOOLEAN EnableThreatStats;
    BOOLEAN EnableDiagnostics;
    UINT16 Reserved1;
    
    UINT32 HeartbeatIntervalMs;           // Heartbeat frequency
    UINT32 PerformanceIntervalMs;         // Perf stats frequency
    UINT32 BatchFlushIntervalMs;          // Batch flush frequency
    UINT32 MaxBatchSize;                  // Max events per batch
    
    UINT32 MaxQueueDepth;                 // Max queued events
    UINT32 HighLatencyThresholdUs;        // Latency warning threshold
    UINT32 ResourcePressureThreshold;     // Memory pressure threshold %
    
    UINT32 Reserved2[4];
} TELEMETRY_CONFIG, *PTELEMETRY_CONFIG;

// ============================================================================
// HELPER MACROS
// ============================================================================

/**
 * @brief Initialize telemetry event header.
 */
#define INIT_TELEMETRY_HEADER(hdr, type, component, size) do { \
    (hdr)->Size = (size); \
    (hdr)->Version = TELEMETRY_PROTOCOL_VERSION; \
    (hdr)->Flags = 0; \
    (hdr)->EventType = (type); \
    (hdr)->ComponentId = (component); \
    (hdr)->Reserved = 0; \
} while(0)

/**
 * @brief Check if telemetry event is urgent.
 */
#define TELEMETRY_IS_URGENT(event) \
    (((event)->Header.Flags & TELEMETRY_FLAG_URGENT) != 0)

/**
 * @brief Check if component is healthy.
 */
#define COMPONENT_IS_HEALTHY(status) \
    ((status) == Health_Healthy)

/**
 * @brief Check if error is critical.
 */
#define ERROR_IS_CRITICAL(severity) \
    ((severity) >= ErrorSeverity_Critical)

#endif // SHADOWSTRIKE_TELEMETRY_TYPES_H
