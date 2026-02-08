/*++
===============================================================================
ShadowStrike NGAV - HANDLE TRACKER PUBLIC INTERFACE
===============================================================================

@file HandleTracker.h
@brief Enterprise-grade handle forensics and tracking for comprehensive threat detection.

This module provides real-time handle tracking capabilities including:
- Cross-process handle detection and analysis
- Handle duplication monitoring
- Sensitive process handle access detection (LSASS, CSRSS, etc.)
- High-privilege handle identification
- Process/thread handle enumeration
- Token handle manipulation detection
- System handle abuse detection

IRQL Contract:
- All public APIs must be called at PASSIVE_LEVEL
- Internal callbacks may execute at DISPATCH_LEVEL (DPC)

Thread Safety:
- All public APIs are thread-safe
- Uses EX_RUNDOWN_REF for safe shutdown synchronization
- Reference counting for handle snapshots

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

//
// Pool tags
//
#define HT_POOL_TAG         'KRTH'
#define HT_POOL_TAG_ENTRY   'eHTK'
#define HT_POOL_TAG_PROCESS 'pHTK'
#define HT_POOL_TAG_BUFFER  'bHTK'
#define HT_POOL_TAG_STRING  'sHTK'

//
// Limits
//
#define HT_MAX_HANDLES_PER_PROCESS      65536
#define HT_MAX_OBJECT_NAME_LENGTH       520
#define HT_MAX_IMAGE_PATH_LENGTH        520

//
// Handle types enumeration
//
typedef enum _HT_HANDLE_TYPE {
    HtType_Unknown = 0,
    HtType_Process,
    HtType_Thread,
    HtType_File,
    HtType_Key,
    HtType_Section,
    HtType_Token,
    HtType_Event,
    HtType_Semaphore,
    HtType_Mutex,
    HtType_Timer,
    HtType_Port,
    HtType_Device,
    HtType_Driver,
    HtType_MaxValue
} HT_HANDLE_TYPE;

//
// Suspicion flags (bitmask)
//
typedef enum _HT_SUSPICION {
    HtSuspicion_None                = 0x00000000,
    HtSuspicion_CrossProcess        = 0x00000001,
    HtSuspicion_HighPrivilege       = 0x00000002,
    HtSuspicion_DuplicatedIn        = 0x00000004,
    HtSuspicion_SensitiveTarget     = 0x00000008,
    HtSuspicion_ManyHandles         = 0x00000010,
    HtSuspicion_SystemHandle        = 0x00000020,
    HtSuspicion_InjectionCapable    = 0x00000040,
    HtSuspicion_TokenSteal          = 0x00000080,
    HtSuspicion_CredentialAccess    = 0x00000100,
} HT_SUSPICION;

//
// Opaque handle types - internal structures are hidden
//
typedef struct _HT_TRACKER *PHT_TRACKER;
typedef struct _HT_PROCESS_HANDLES *PHT_PROCESS_HANDLES;
typedef struct _HT_HANDLE_ENTRY *PHT_HANDLE_ENTRY;

//
// Public handle entry information (read-only view)
//
typedef struct _HT_HANDLE_INFO {
    HANDLE HandleValue;
    HT_HANDLE_TYPE Type;
    ACCESS_MASK GrantedAccess;
    HANDLE TargetProcessId;
    BOOLEAN IsDuplicated;
    HANDLE DuplicatedFromProcess;
    HT_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    WCHAR ObjectName[HT_MAX_OBJECT_NAME_LENGTH / sizeof(WCHAR)];
    USHORT ObjectNameLength;
} HT_HANDLE_INFO, *PHT_HANDLE_INFO;

//
// Public process handles summary (read-only view)
//
typedef struct _HT_PROCESS_HANDLES_INFO {
    HANDLE ProcessId;
    LONG HandleCount;
    HT_SUSPICION AggregatedSuspicion;
    ULONG SuspicionScore;
    ULONG ProcessHandleCount;
    ULONG ThreadHandleCount;
    ULONG FileHandleCount;
    ULONG TokenHandleCount;
    ULONG SectionHandleCount;
    ULONG OtherHandleCount;
    ULONG CrossProcessHandleCount;
    ULONG HighPrivilegeHandleCount;
    LARGE_INTEGER SnapshotTime;
} HT_PROCESS_HANDLES_INFO, *PHT_PROCESS_HANDLES_INFO;

//
// Tracker statistics
//
typedef struct _HT_STATISTICS {
    volatile LONG64 HandlesTracked;
    volatile LONG64 SuspiciousHandles;
    volatile LONG64 CrossProcessHandles;
    volatile LONG64 TotalEnumerations;
    volatile LONG64 DuplicationsRecorded;
    volatile LONG64 SensitiveAccessDetected;
    volatile LONG64 HighPrivilegeHandles;
    volatile LONG64 TokenHandlesTracked;
    volatile LONG64 InjectionHandlesDetected;
    LARGE_INTEGER StartTime;
} HT_STATISTICS, *PHT_STATISTICS;

//
// Configuration structure
//
typedef struct _HT_CONFIG {
    BOOLEAN EnableCrossProcessDetection;
    BOOLEAN EnableDuplicationTracking;
    BOOLEAN EnableSensitiveProcessMonitoring;
    ULONG MaxHandlesPerProcess;
    ULONG MaxDuplications;
    ULONG SuspicionThreshold;
    ULONG CleanupIntervalMs;
    ULONG CacheTimeoutMs;
} HT_CONFIG, *PHT_CONFIG;

//
// ============================================================================
// PUBLIC API FUNCTIONS
// ============================================================================
//

/*++
Routine Description:
    Initializes the handle tracker subsystem.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Tracker - Receives pointer to initialized tracker.
    Config - Optional configuration. If NULL, defaults are used.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INSUFFICIENT_RESOURCES on allocation failure.
    STATUS_INVALID_PARAMETER if Tracker is NULL.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
HtInitialize(
    _Out_ PHT_TRACKER* Tracker,
    _In_opt_ PHT_CONFIG Config
    );

/*++
Routine Description:
    Shuts down the handle tracker subsystem safely.
    Waits for all outstanding operations to complete.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Tracker - Tracker instance to shutdown. Set to NULL on return.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
VOID
HtShutdown(
    _Inout_ PHT_TRACKER* Tracker
    );

/*++
Routine Description:
    Takes a snapshot of all handles for a process.
    The returned handle snapshot must be freed with HtReleaseHandles.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to snapshot.
    Handles - Receives handle snapshot.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
    STATUS_INSUFFICIENT_RESOURCES on allocation failure.
    STATUS_NOT_FOUND if process doesn't exist.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
HtSnapshotHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PHT_PROCESS_HANDLES* Handles
    );

/*++
Routine Description:
    Gets summary information about a handle snapshot.

    IRQL: May be called at PASSIVE_LEVEL or APC_LEVEL.

Arguments:
    Handles - Handle snapshot.
    Info - Receives summary information.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
--*/
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
HtGetHandlesInfo(
    _In_ PHT_PROCESS_HANDLES Handles,
    _Out_ PHT_PROCESS_HANDLES_INFO Info
    );

/*++
Routine Description:
    Enumerates handle entries in a snapshot.

    IRQL: May be called at PASSIVE_LEVEL or APC_LEVEL.

Arguments:
    Handles - Handle snapshot.
    Index - Zero-based index of handle to retrieve.
    Info - Receives handle information.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
    STATUS_NO_MORE_ENTRIES if index is out of range.
--*/
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
HtGetHandleByIndex(
    _In_ PHT_PROCESS_HANDLES Handles,
    _In_ ULONG Index,
    _Out_ PHT_HANDLE_INFO Info
    );

/*++
Routine Description:
    Records a handle duplication event for tracking.

    IRQL: May be called at PASSIVE_LEVEL or APC_LEVEL.

Arguments:
    Tracker - Tracker instance.
    SourceProcess - Source process ID.
    TargetProcess - Target process ID.
    SourceHandle - Source handle value.
    TargetHandle - Target handle value (in target process).
    GrantedAccess - Access rights granted.
    HandleType - Type of handle being duplicated.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
    STATUS_QUOTA_EXCEEDED if duplication limit reached.
--*/
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
HtRecordDuplication(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle,
    _In_ ACCESS_MASK GrantedAccess,
    _In_ HT_HANDLE_TYPE HandleType
    );

/*++
Routine Description:
    Analyzes handles for suspicious patterns.

    IRQL: May be called at PASSIVE_LEVEL or APC_LEVEL.

Arguments:
    Tracker - Tracker instance.
    Handles - Handle snapshot to analyze.
    Flags - Receives aggregated suspicion flags.
    Score - Receives suspicion score (0-100).

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
--*/
_IRQL_requires_max_(APC_LEVEL)
_Must_inspect_result_
NTSTATUS
HtAnalyzeHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles,
    _Out_ HT_SUSPICION* Flags,
    _Out_opt_ PULONG Score
    );

/*++
Routine Description:
    Finds all handles in other processes that reference the target process.

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Tracker - Tracker instance.
    TargetProcessId - Target process to find handles for.
    Entries - Array to receive handle information.
    MaxEntries - Maximum entries array can hold.
    Count - Receives actual count of entries found.

Return Value:
    STATUS_SUCCESS on success (partial results possible).
    STATUS_INVALID_PARAMETER on invalid input.
    STATUS_BUFFER_TOO_SMALL if more entries exist than MaxEntries.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
HtFindCrossProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE TargetProcessId,
    _Out_writes_to_(MaxEntries, *Count) PHT_HANDLE_INFO Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG Count
    );

/*++
Routine Description:
    Releases a process handles snapshot.

    IRQL: May be called at PASSIVE_LEVEL or APC_LEVEL.

Arguments:
    Tracker - Tracker instance.
    Handles - Handles snapshot to release.
--*/
_IRQL_requires_max_(APC_LEVEL)
VOID
HtReleaseHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles
    );

/*++
Routine Description:
    Gets current tracker statistics.

    IRQL: May be called at any IRQL.

Arguments:
    Tracker - Tracker instance.
    Stats - Receives statistics.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
--*/
_IRQL_requires_max_(DISPATCH_LEVEL)
_Must_inspect_result_
NTSTATUS
HtGetStatistics(
    _In_ PHT_TRACKER Tracker,
    _Out_ PHT_STATISTICS Stats
    );

/*++
Routine Description:
    Checks if a process is considered sensitive (e.g., LSASS, CSRSS).

    IRQL: Must be called at PASSIVE_LEVEL.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process ID to check.
    IsSensitive - Receives TRUE if process is sensitive.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_INVALID_PARAMETER on invalid input.
--*/
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
HtIsSensitiveProcess(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PBOOLEAN IsSensitive
    );

#ifdef __cplusplus
}
#endif
