/**
 * ============================================================================
 * ShadowStrike NGAV - NAMED PIPE MONITORING
 * ============================================================================
 *
 * @file NamedPipeMonitor.h
 * @brief Enterprise-grade Named Pipe monitoring for lateral movement
 *        and C2 communication detection.
 *
 * Detects:
 * - CobaltStrike SMB beacon pipes (\MSSE-*, \msagent_*, \postex_*)
 * - PsExec service pipes (\PSEXESVC)
 * - Meterpreter named pipes (\meterpreter*)
 * - Impacket/WMIExec pipes
 * - Custom C2 pipes with high-entropy names
 * - Cross-process pipe communication anomalies
 * - Suspicious pipe creation by non-system processes
 *
 * MITRE ATT&CK Coverage:
 * ======================
 * - T1570: Lateral Tool Transfer (pipe-based file transfer)
 * - T1021.002: SMB/Windows Admin Shares (PsExec/SMB beacons)
 * - T1071.002: Application Layer Protocol: File Transfer Protocol
 * - T1572: Protocol Tunneling (pipe-based tunneling)
 * - T1090.001: Internal Proxy (pipe relay)
 *
 * Architecture:
 * =============
 * 1. Minifilter IRP_MJ_CREATE_NAMED_PIPE callback for pipe creation
 * 2. IRP_MJ_CREATE on \Device\NamedPipe\ for pipe connection events
 * 3. Known C2 pipe name pattern matching (hash-based lookup)
 * 4. Shannon entropy analysis for randomized pipe names
 * 5. Cross-process pipe communication tracking
 * 6. User-mode event notification via filter port
 *
 * @author ShadowStrike Security Team
 * @version 1.0.0
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#ifndef SHADOWSTRIKE_NAMED_PIPE_MONITOR_H
#define SHADOWSTRIKE_NAMED_PIPE_MONITOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <fltKernel.h>

// ============================================================================
// POOL TAGS
// ============================================================================

#define NPM_POOL_TAG                'pNSS'  // SSNp - NamedPipeMonitor
#define NPM_POOL_TAG_ENTRY          'eNSS'  // SSNe - Pipe entry
#define NPM_POOL_TAG_EVENT          'vNSS'  // SSNv - Pipe event

// ============================================================================
// CONSTANTS
// ============================================================================

#define NPM_MAX_PIPE_NAME_CCH           256
#define NPM_MAX_TRACKED_PIPES           2048
#define NPM_HASH_TABLE_SIZE             128
#define NPM_MAX_EVENT_QUEUE             256
#define NPM_ENTROPY_THRESHOLD_HIGH      4.2f
#define NPM_CLEANUP_INTERVAL_MS         120000
#define NPM_PIPE_IDLE_TIMEOUT_100NS     (-(LONGLONG)300 * 10000000LL)   // 5 min
#define NPM_MAX_CONNECTIONS_PER_PIPE    64
#define NPM_RATE_LIMIT_WINDOW_MS        1000
#define NPM_RATE_LIMIT_MAX_CREATES      50

//
// CAS-based lifecycle states
//
#define NPM_STATE_UNINITIALIZED         0
#define NPM_STATE_INITIALIZING          1
#define NPM_STATE_READY                 2
#define NPM_STATE_SHUTTING_DOWN         3

// ============================================================================
// THREAT LEVELS
// ============================================================================

typedef enum _NPM_THREAT_LEVEL {
    NpmThreat_None              = 0,
    NpmThreat_Low               = 25,
    NpmThreat_Medium            = 50,
    NpmThreat_High              = 75,
    NpmThreat_Critical          = 100
} NPM_THREAT_LEVEL;

// ============================================================================
// PIPE CLASSIFICATION
// ============================================================================

typedef enum _NPM_PIPE_CLASS {
    NpmClass_Unknown            = 0,
    NpmClass_System,                // Windows system pipes (lsass, etc.)
    NpmClass_KnownApplication,      // Known legitimate application pipes
    NpmClass_C2_CobaltStrike,       // CobaltStrike beacon patterns
    NpmClass_C2_Meterpreter,        // Meterpreter pipe patterns
    NpmClass_C2_PsExec,             // PsExec service pipes
    NpmClass_C2_Impacket,           // Impacket/WMIExec pipes
    NpmClass_C2_Generic,            // Generic C2 patterns
    NpmClass_HighEntropy,           // Suspicious randomized name
    NpmClass_Suspicious             // Other suspicious patterns
} NPM_PIPE_CLASS;

// ============================================================================
// STATISTICS
// ============================================================================

typedef struct _NPM_STATISTICS {
    volatile LONG64 TotalPipesCreated;
    volatile LONG64 TotalPipesConnected;
    volatile LONG64 TotalPipesBlocked;
    volatile LONG64 SuspiciousPipesDetected;
    volatile LONG64 C2PipesDetected;
    volatile LONG64 HighEntropyPipesDetected;
    volatile LONG64 CrossProcessConnections;
    volatile LONG64 EventsQueued;
    volatile LONG64 EventsDropped;
} NPM_STATISTICS, *PNPM_STATISTICS;

// ============================================================================
// PIPE TRACKING ENTRY
// ============================================================================

typedef struct _NPM_PIPE_ENTRY {
    LIST_ENTRY ListEntry;               // Hash bucket chain
    LIST_ENTRY LruEntry;                // LRU eviction chain

    WCHAR PipeName[NPM_MAX_PIPE_NAME_CCH];
    USHORT PipeNameLength;              // In bytes (not including null)

    HANDLE CreatorProcessId;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER LastAccessTime;

    NPM_PIPE_CLASS Classification;
    NPM_THREAT_LEVEL ThreatLevel;
    ULONG ThreatScore;

    volatile LONG ConnectionCount;
    volatile LONG ReferenceCount;

    BOOLEAN IsBlocked;
    BOOLEAN IsMonitored;
} NPM_PIPE_ENTRY, *PNPM_PIPE_ENTRY;

// ============================================================================
// PIPE EVENT (for user-mode notification)
// ============================================================================

typedef struct _NPM_PIPE_EVENT {
    LIST_ENTRY ListEntry;

    LARGE_INTEGER Timestamp;
    HANDLE CreatorProcessId;
    HANDLE ConnectorProcessId;

    WCHAR PipeName[NPM_MAX_PIPE_NAME_CCH];
    USHORT PipeNameLength;

    NPM_PIPE_CLASS Classification;
    NPM_THREAT_LEVEL ThreatLevel;
    ULONG ThreatScore;

    BOOLEAN WasBlocked;
    BOOLEAN IsCreation;             // TRUE = created, FALSE = connected
} NPM_PIPE_EVENT, *PNPM_PIPE_EVENT;

// ============================================================================
// PUBLIC API — LIFECYCLE
// ============================================================================

/**
 * @brief Initialize named pipe monitoring subsystem.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
NpMonInitialize(
    VOID
    );

/**
 * @brief Shutdown named pipe monitoring subsystem.
 * @irql PASSIVE_LEVEL
 */
_IRQL_requires_(PASSIVE_LEVEL)
VOID
NpMonShutdown(
    VOID
    );

/**
 * @brief Check if named pipe monitor is active.
 * @irql Any
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
NpMonIsActive(
    VOID
    );

// ============================================================================
// PUBLIC API — MINIFILTER CALLBACKS
// ============================================================================

/**
 * @brief Pre-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 *        Intercepts pipe creation to detect C2/lateral movement pipes.
 */
FLT_PREOP_CALLBACK_STATUS
NpMonPreCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

/**
 * @brief Post-operation callback for IRP_MJ_CREATE_NAMED_PIPE.
 *        Records successfully created pipes for tracking.
 */
FLT_POSTOP_CALLBACK_STATUS
NpMonPostCreateNamedPipe(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

// ============================================================================
// PUBLIC API — STATISTICS / EVENTS
// ============================================================================

/**
 * @brief Get atomic snapshot of pipe monitoring statistics.
 * @irql <= DISPATCH_LEVEL
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
NpMonGetStatistics(
    _Out_ PNPM_STATISTICS Stats
    );

/**
 * @brief Dequeue a pipe event for user-mode delivery.
 * @irql <= APC_LEVEL
 * @return STATUS_SUCCESS with event, STATUS_NO_MORE_ENTRIES if queue empty.
 *         Caller must free returned event with ExFreePoolWithTag(NPM_POOL_TAG_EVENT).
 */
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS
NpMonDequeueEvent(
    _Outptr_ PNPM_PIPE_EVENT *Event
    );

#ifdef __cplusplus
}
#endif

#endif // SHADOWSTRIKE_NAMED_PIPE_MONITOR_H
