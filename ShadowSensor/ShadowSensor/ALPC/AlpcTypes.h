/**
 * ============================================================================
 * ShadowStrike NGAV - ALPC TYPE DEFINITIONS
 * ============================================================================
 *
 * @file AlpcTypes.h
 * @brief Type definitions for ALPC (Advanced Local Procedure Call) monitoring.
 *
 * This header defines structures and types for monitoring ALPC port operations.
 * ALPC is Windows' primary IPC mechanism used by RPC, COM, and system services.
 *
 * ALPC Security Relevance:
 * ========================
 * - CVE-2023-21674: ALPC use-after-free privilege escalation
 * - CVE-2018-8440: ALPC task scheduler privilege escalation
 * - Sandbox escapes via ALPC port impersonation
 * - Handle passing between processes via ALPC
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1134.001: Access Token Manipulation - Token Impersonation via ALPC
 * - T1055.012: Process Injection - Process Hollowing via ALPC
 * - T1559.001: Inter-Process Communication - Component Object Model
 *
 * @author ShadowStrike Security Team
 * @version 2.0.0 (Enterprise Edition - Security Hardened)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_ALPC_TYPES_H
#define SHADOWSTRIKE_ALPC_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>
#include <ntifs.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define SHADOW_ALPC_PORT_TAG        'tPAs'  // ALPC Port tracking
#define SHADOW_ALPC_CONN_TAG        'nCAs'  // ALPC Connection tracking
#define SHADOW_ALPC_EVENT_TAG       'vEAs'  // ALPC Event records
#define SHADOW_ALPC_CACHE_TAG       'hCAs'  // ALPC Cache entries
#define SHADOW_ALPC_STRING_TAG      'rSAs'  // ALPC String allocations
#define SHADOW_ALPC_WORK_TAG        'wWAs'  // ALPC Work items

// ============================================================================
// CONSTANTS
// ============================================================================

/**
 * @brief Maximum tracked ALPC ports
 */
#define SHADOW_ALPC_MAX_PORTS               4096

/**
 * @brief Maximum connections per port
 */
#define SHADOW_ALPC_MAX_CONNECTIONS_PER_PORT 256

/**
 * @brief Hash bucket count for port cache (power of 2)
 */
#define SHADOW_ALPC_HASH_BUCKETS            256
#define SHADOW_ALPC_HASH_MASK               (SHADOW_ALPC_HASH_BUCKETS - 1)

/**
 * @brief Maximum port name length (characters)
 */
#define SHADOW_ALPC_MAX_PORT_NAME           260

/**
 * @brief Rate limit window (100ns units = 1 second)
 */
#define SHADOW_ALPC_RATE_LIMIT_WINDOW       (10000000LL)

/**
 * @brief Maximum connections per second before rate limiting
 */
#define SHADOW_ALPC_MAX_CONNECTIONS_PER_SEC 50

/**
 * @brief Event queue maximum size
 */
#define SHADOW_ALPC_MAX_EVENT_QUEUE         1024

/**
 * @brief Port tracking entry TTL (100ns units = 5 minutes)
 */
#define SHADOW_ALPC_PORT_TTL                (5LL * 60LL * 10000000LL)

/**
 * @brief Maximum process name length
 */
#define SHADOW_ALPC_MAX_PROCESS_NAME        64

// ============================================================================
// UNDOCUMENTED ALPC PORT ACCESS RIGHTS
// ============================================================================

#ifndef PORT_CONNECT
#define PORT_CONNECT                        0x0001
#endif

#ifndef PORT_ALL_ACCESS
#define PORT_ALL_ACCESS                     (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1)
#endif

// ============================================================================
// INTEGRITY LEVEL DEFINITIONS (Windows Mandatory Integrity)
// ============================================================================

#ifndef SECURITY_MANDATORY_UNTRUSTED_RID
#define SECURITY_MANDATORY_UNTRUSTED_RID            0x00000000
#endif

#ifndef SECURITY_MANDATORY_LOW_RID
#define SECURITY_MANDATORY_LOW_RID                  0x00001000
#endif

#ifndef SECURITY_MANDATORY_MEDIUM_RID
#define SECURITY_MANDATORY_MEDIUM_RID               0x00002000
#endif

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID          0x00002100
#endif

#ifndef SECURITY_MANDATORY_HIGH_RID
#define SECURITY_MANDATORY_HIGH_RID                 0x00003000
#endif

#ifndef SECURITY_MANDATORY_SYSTEM_RID
#define SECURITY_MANDATORY_SYSTEM_RID               0x00004000
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID    0x00005000
#endif

// ============================================================================
// UNDOCUMENTED ALPC STRUCTURES (Stable across Windows versions)
// ============================================================================

/**
 * @brief ALPC port flags (partial)
 */
typedef enum _ALPC_PORT_FLAGS {
    ALPC_PORTFLG_LPC_MODE           = 0x00001000,
    ALPC_PORTFLG_ALLOW_IMPERSONATION = 0x00010000,
    ALPC_PORTFLG_ALLOW_LPC_REQUESTS  = 0x00020000,
    ALPC_PORTFLG_WAITABLE_PORT       = 0x00040000,
    ALPC_PORTFLG_ALLOW_DUP_OBJECT    = 0x00080000,
    ALPC_PORTFLG_SYSTEM_PROCESS      = 0x00100000,
    ALPC_PORTFLG_SYSTEM_INIT         = 0x00200000,
} ALPC_PORT_FLAGS;

/**
 * @brief ALPC message attributes (partial)
 */
typedef enum _ALPC_MESSAGE_ATTRIBUTES {
    ALPC_MESSAGE_SECURITY_ATTRIBUTE  = 0x80000000,
    ALPC_MESSAGE_VIEW_ATTRIBUTE      = 0x40000000,
    ALPC_MESSAGE_CONTEXT_ATTRIBUTE   = 0x20000000,
    ALPC_MESSAGE_HANDLE_ATTRIBUTE    = 0x10000000,
    ALPC_MESSAGE_TOKEN_ATTRIBUTE     = 0x08000000,
    ALPC_MESSAGE_DIRECT_ATTRIBUTE    = 0x04000000,
    ALPC_MESSAGE_WORK_ON_BEHALF_ATTRIBUTE = 0x02000000,
} ALPC_MESSAGE_ATTRIBUTES;

// ============================================================================
// ALPC PORT OPERATION TYPES
// ============================================================================

/**
 * @brief ALPC operation types for tracking
 */
typedef enum _SHADOW_ALPC_OPERATION {
    AlpcOperationUnknown = 0,
    AlpcOperationCreatePort,
    AlpcOperationConnectPort,
    AlpcOperationAcceptConnect,
    AlpcOperationSendMessage,
    AlpcOperationReceiveMessage,
    AlpcOperationDisconnect,
    AlpcOperationClosePort,
    AlpcOperationImpersonate,
    AlpcOperationCancelMessage,
    AlpcOperationQueryInformation,
    AlpcOperationSetInformation,
} SHADOW_ALPC_OPERATION;

/**
 * @brief ALPC port types
 */
typedef enum _SHADOW_ALPC_PORT_TYPE {
    AlpcPortTypeUnknown = 0,
    AlpcPortTypeServer,             // Connection port (NtAlpcCreatePort)
    AlpcPortTypeClient,             // Client communication port
    AlpcPortTypeConnection,         // Server-side connection port
} SHADOW_ALPC_PORT_TYPE;

/**
 * @brief Suspicion indicators for ALPC operations
 */
typedef enum _SHADOW_ALPC_SUSPICION {
    AlpcSuspicionNone               = 0x00000000,
    AlpcSuspicionCrossSession       = 0x00000001,  // Cross-session connection
    AlpcSuspicionLowToHigh          = 0x00000002,  // Low integrity -> High
    AlpcSuspicionImpersonation      = 0x00000004,  // Client impersonation
    AlpcSuspicionSystemPort         = 0x00000008,  // Access to system port
    AlpcSuspicionRapidConnect       = 0x00000010,  // Rate limit exceeded
    AlpcSuspicionHandlePassing      = 0x00000020,  // Handle passed via ALPC
    AlpcSuspicionSensitivePort      = 0x00000040,  // Known sensitive port name
    AlpcSuspicionUntrustedSource    = 0x00000080,  // Untrusted process
    AlpcSuspicionAnomalousMessage   = 0x00000100,  // Anomalous message size/type
    AlpcSuspicionSandboxEscape      = 0x00000200,  // Potential sandbox escape
} SHADOW_ALPC_SUSPICION;

/**
 * @brief Verdict for ALPC operations
 */
typedef enum _SHADOW_ALPC_VERDICT {
    AlpcVerdictAllow = 0,           // Allow operation
    AlpcVerdictMonitor,             // Allow but log/alert
    AlpcVerdictStrip,               // Strip dangerous attributes
    AlpcVerdictBlock,               // Block operation
} SHADOW_ALPC_VERDICT;

/**
 * @brief ALPC event types for alerting
 */
typedef enum _SHADOW_ALPC_EVENT_TYPE {
    AlpcEventPortCreated = 1,
    AlpcEventPortConnected,
    AlpcEventPortDisconnected,
    AlpcEventPortClosed,
    AlpcEventImpersonationAttempt,
    AlpcEventHandlePassed,
    AlpcEventSuspiciousAccess,
    AlpcEventRateLimitExceeded,
    AlpcEventSandboxEscapeAttempt,
} SHADOW_ALPC_EVENT_TYPE;

// ============================================================================
// ALPC TRACKING STRUCTURES
// ============================================================================

/**
 * @brief Known sensitive ALPC port patterns
 */
typedef struct _SHADOW_ALPC_SENSITIVE_PORT {
    PCWSTR PortNamePattern;         // Port name pattern (can be prefix)
    BOOLEAN IsPrefix;               // TRUE if pattern is a prefix match
    ULONG ThreatWeight;             // Added to threat score if matched
    PCWSTR Description;             // Human-readable description
} SHADOW_ALPC_SENSITIVE_PORT, *PSHADOW_ALPC_SENSITIVE_PORT;

/**
 * @brief ALPC connection tracking entry
 */
typedef struct _SHADOW_ALPC_CONNECTION {
    LIST_ENTRY ListEntry;           // For per-port connection list

    //
    // Connection identification
    //
    HANDLE ClientProcessId;
    HANDLE ServerProcessId;
    PVOID ClientPortObject;         // Client's port object
    PVOID ServerPortObject;         // Server's port object (connection port)

    //
    // Security context
    //
    ULONG ClientSessionId;
    ULONG ServerSessionId;
    ULONG ClientIntegrityLevel;

    //
    // Timing
    //
    LARGE_INTEGER ConnectTime;
    LARGE_INTEGER LastMessageTime;

    //
    // Statistics
    //
    volatile LONG MessageCount;
    volatile LONG ImpersonationCount;
    volatile LONG HandleTransferCount;

    //
    // Suspicion tracking
    //
    SHADOW_ALPC_SUSPICION SuspicionFlags;
    ULONG ThreatScore;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG RemovedFromList;

} SHADOW_ALPC_CONNECTION, *PSHADOW_ALPC_CONNECTION;

/**
 * @brief ALPC port tracking entry
 */
typedef struct _SHADOW_ALPC_PORT_ENTRY {
    LIST_ENTRY HashEntry;           // For hash bucket list
    LIST_ENTRY GlobalEntry;         // For global LRU list

    //
    // Port identification
    //
    PVOID PortObject;               // Kernel object pointer
    SHADOW_ALPC_PORT_TYPE PortType;
    HANDLE OwnerProcessId;

    //
    // Port name (if available)
    //
    WCHAR PortName[SHADOW_ALPC_MAX_PORT_NAME];
    USHORT PortNameLength;
    BOOLEAN IsSensitivePort;

    //
    // Security attributes
    //
    ULONG OwnerSessionId;
    ULONG OwnerIntegrityLevel;
    BOOLEAN AllowsImpersonation;

    //
    // Connection tracking
    //
    LIST_ENTRY ConnectionList;
    EX_PUSH_LOCK ConnectionLock;
    volatile LONG ConnectionCount;

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastAccessTime;

    //
    // Rate limiting
    //
    LARGE_INTEGER RateLimitWindowStart;
    volatile LONG ConnectionsInWindow;
    BOOLEAN IsRateLimited;

    //
    // Statistics
    //
    volatile LONG64 TotalConnections;
    volatile LONG64 TotalMessages;
    volatile LONG64 TotalImpersonations;
    volatile LONG64 SuspiciousEvents;

    //
    // Reference counting
    //
    volatile LONG ReferenceCount;
    volatile LONG RemovedFromList;

} SHADOW_ALPC_PORT_ENTRY, *PSHADOW_ALPC_PORT_ENTRY;

/**
 * @brief Hash bucket for port lookup
 */
typedef struct _SHADOW_ALPC_HASH_BUCKET {
    LIST_ENTRY PortList;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} SHADOW_ALPC_HASH_BUCKET, *PSHADOW_ALPC_HASH_BUCKET;

/**
 * @brief ALPC event for alerting/logging
 */
typedef struct _SHADOW_ALPC_EVENT {
    LIST_ENTRY ListEntry;

    SHADOW_ALPC_EVENT_TYPE EventType;
    SHADOW_ALPC_SUSPICION SuspicionFlags;
    ULONG ThreatScore;

    HANDLE SourceProcessId;
    HANDLE TargetProcessId;

    WCHAR SourceProcessName[SHADOW_ALPC_MAX_PROCESS_NAME];
    WCHAR TargetProcessName[SHADOW_ALPC_MAX_PROCESS_NAME];
    WCHAR PortName[SHADOW_ALPC_MAX_PORT_NAME];

    LARGE_INTEGER Timestamp;

    //
    // Additional context
    //
    SHADOW_ALPC_OPERATION Operation;
    ACCESS_MASK RequestedAccess;
    BOOLEAN WasBlocked;

} SHADOW_ALPC_EVENT, *PSHADOW_ALPC_EVENT;

/**
 * @brief ALPC monitoring statistics
 */
typedef struct _SHADOW_ALPC_STATISTICS {
    //
    // Port operations
    //
    volatile LONG64 PortsCreated;
    volatile LONG64 PortsClosed;
    volatile LONG64 ConnectionsEstablished;
    volatile LONG64 ConnectionsTerminated;

    //
    // Message operations
    //
    volatile LONG64 MessagesSent;
    volatile LONG64 MessagesReceived;

    //
    // Security events
    //
    volatile LONG64 ImpersonationAttempts;
    volatile LONG64 ImpersonationsBlocked;
    volatile LONG64 HandleTransfers;
    volatile LONG64 CrossSessionConnections;
    volatile LONG64 LowToHighConnections;
    volatile LONG64 SandboxEscapeAttempts;

    //
    // Rate limiting
    //
    volatile LONG64 RateLimitViolations;

    //
    // Detection results
    //
    volatile LONG64 SuspiciousOperations;
    volatile LONG64 BlockedOperations;
    volatile LONG64 AlertsGenerated;

    //
    // Cache performance
    //
    volatile LONG64 CacheHits;
    volatile LONG64 CacheMisses;

    //
    // Timing
    //
    LARGE_INTEGER StartTime;

} SHADOW_ALPC_STATISTICS, *PSHADOW_ALPC_STATISTICS;

/**
 * @brief Work item for deferred PASSIVE_LEVEL operations
 */
typedef struct _SHADOW_ALPC_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    PVOID Context;
    PVOID PortObject;
    HANDLE SourceProcessId;
    ULONG SourceSessionId;
    ULONG SourceIntegrityLevel;
    WCHAR SourceProcessName[SHADOW_ALPC_MAX_PROCESS_NAME];
    WCHAR PortName[SHADOW_ALPC_MAX_PORT_NAME];
    SHADOW_ALPC_OPERATION Operation;
    ACCESS_MASK OriginalAccess;
    BOOLEAN IsKernelHandle;
} SHADOW_ALPC_WORK_ITEM, *PSHADOW_ALPC_WORK_ITEM;

/**
 * @brief ALPC operation context for callbacks
 */
typedef struct _SHADOW_ALPC_OPERATION_CONTEXT {
    //
    // Operation details
    //
    SHADOW_ALPC_OPERATION Operation;
    LARGE_INTEGER Timestamp;

    //
    // Source process
    //
    HANDLE SourceProcessId;
    PEPROCESS SourceProcess;
    ULONG SourceSessionId;
    ULONG SourceIntegrityLevel;
    WCHAR SourceProcessName[SHADOW_ALPC_MAX_PROCESS_NAME];

    //
    // Target port
    //
    PVOID PortObject;
    PSHADOW_ALPC_PORT_ENTRY PortEntry;
    WCHAR PortName[SHADOW_ALPC_MAX_PORT_NAME];

    //
    // Target process (for connections)
    //
    HANDLE TargetProcessId;
    ULONG TargetSessionId;
    ULONG TargetIntegrityLevel;

    //
    // Analysis results
    //
    SHADOW_ALPC_SUSPICION SuspicionFlags;
    ULONG ThreatScore;
    SHADOW_ALPC_VERDICT Verdict;

    //
    // Handle operation specifics
    //
    ACCESS_MASK OriginalAccess;
    ACCESS_MASK ModifiedAccess;
    BOOLEAN IsKernelHandle;

} SHADOW_ALPC_OPERATION_CONTEXT, *PSHADOW_ALPC_OPERATION_CONTEXT;

/**
 * @brief ALPC monitor global state
 */
typedef struct _SHADOW_ALPC_MONITOR_STATE {
    //
    // Initialization state
    //
    volatile LONG InitializationState;
    BOOLEAN Initialized;
    volatile LONG ShuttingDown;

    //
    // Rundown protection for safe shutdown
    //
    EX_RUNDOWN_REF RundownProtection;

    //
    // Object callback registration
    //
    PVOID ObjectCallbackHandle;
    BOOLEAN CallbacksRegistered;

    //
    // Port hash table
    //
    SHADOW_ALPC_HASH_BUCKET HashBuckets[SHADOW_ALPC_HASH_BUCKETS];

    //
    // Global port list (LRU order)
    //
    LIST_ENTRY PortList;
    EX_PUSH_LOCK PortListLock;
    volatile LONG PortCount;
    ULONG MaxPorts;

    //
    // Lookaside lists for fast allocation
    //
    NPAGED_LOOKASIDE_LIST PortEntryLookaside;
    NPAGED_LOOKASIDE_LIST ConnectionLookaside;
    NPAGED_LOOKASIDE_LIST EventLookaside;
    NPAGED_LOOKASIDE_LIST WorkItemLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Event queue
    //
    LIST_ENTRY EventQueue;
    KSPIN_LOCK EventLock;
    volatile LONG EventCount;
    ULONG MaxEvents;

    //
    // Configuration
    //
    struct {
        BOOLEAN MonitoringEnabled;
        BOOLEAN BlockingEnabled;
        BOOLEAN AlertOnImpersonation;
        BOOLEAN AlertOnCrossSession;
        BOOLEAN AlertOnSandboxEscape;
        BOOLEAN RateLimitingEnabled;
        ULONG ThreatThreshold;
        ULONG MaxConnectionsPerSecond;
    } Config;

    //
    // Statistics
    //
    SHADOW_ALPC_STATISTICS Stats;

    //
    // Worker thread for cleanup
    //
    PETHREAD WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;

    //
    // Timer for periodic cleanup
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // DPC completion tracking for safe shutdown
    //
    volatile LONG DpcOutstanding;

} SHADOW_ALPC_MONITOR_STATE, *PSHADOW_ALPC_MONITOR_STATE;

// ============================================================================
// INLINE HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Hash an ALPC port object pointer.
 */
FORCEINLINE
ULONG
ShadowAlpcHashPortObject(
    _In_ PVOID PortObject
    )
{
    ULONG_PTR value = (ULONG_PTR)PortObject;

    value ^= (value >> 16);
    value *= 0x85EBCA6B;
    value ^= (value >> 13);
    value *= 0xC2B2AE35;
    value ^= (value >> 16);

    return (ULONG)(value & SHADOW_ALPC_HASH_MASK);
}

/**
 * @brief Check if an ALPC operation is a connection operation.
 */
FORCEINLINE
BOOLEAN
ShadowAlpcIsConnectionOperation(
    _In_ SHADOW_ALPC_OPERATION Operation
    )
{
    return (Operation == AlpcOperationConnectPort ||
            Operation == AlpcOperationAcceptConnect ||
            Operation == AlpcOperationDisconnect);
}

/**
 * @brief Check if suspicion flags indicate high threat.
 */
FORCEINLINE
BOOLEAN
ShadowAlpcIsHighThreat(
    _In_ SHADOW_ALPC_SUSPICION Flags
    )
{
    return ((Flags & AlpcSuspicionSandboxEscape) != 0 ||
            (Flags & AlpcSuspicionLowToHigh) != 0 ||
            ((Flags & AlpcSuspicionImpersonation) &&
             (Flags & AlpcSuspicionCrossSession)));
}

/**
 * @brief Convert SHADOW_INTEGRITY_LEVEL to RID for comparison.
 */
FORCEINLINE
ULONG
ShadowAlpcIntegrityLevelToRid(
    _In_ ULONG IntegrityLevel
    )
{
    //
    // Maps SHADOW_INTEGRITY_LEVEL enum to Windows integrity RID
    //
    switch (IntegrityLevel) {
        case 0: // ShadowIntegrityUntrusted
            return SECURITY_MANDATORY_UNTRUSTED_RID;
        case 1: // ShadowIntegrityLow
            return SECURITY_MANDATORY_LOW_RID;
        case 2: // ShadowIntegrityMedium
            return SECURITY_MANDATORY_MEDIUM_RID;
        case 3: // ShadowIntegrityMediumPlus
            return SECURITY_MANDATORY_MEDIUM_PLUS_RID;
        case 4: // ShadowIntegrityHigh
            return SECURITY_MANDATORY_HIGH_RID;
        case 5: // ShadowIntegritySystem
            return SECURITY_MANDATORY_SYSTEM_RID;
        case 6: // ShadowIntegrityProtected
            return SECURITY_MANDATORY_PROTECTED_PROCESS_RID;
        default:
            return SECURITY_MANDATORY_MEDIUM_RID;
    }
}

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_ALPC_TYPES_H
