/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PRE-ACQUIRE SECTION CALLBACK IMPLEMENTATION
===============================================================================

@file PreAcquireSection.c
@brief Enterprise-grade section acquisition interception for kernel EDR.

This module provides comprehensive memory mapping and execution detection:
- Image/executable mapping detection (SEC_IMAGE)
- DLL injection detection via section mapping patterns
- Process hollowing detection signals
- Reflective DLL loading detection
- Memory-mapped file execution tracking
- Shellcode injection via section objects
- Legitimate vs. suspicious mapping classification
- Per-process mapping behavior analysis
- Known malware pattern blocking via cache

IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION Interception Points:
- PAGE_EXECUTE / PAGE_EXECUTE_READ / PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY
- SEC_IMAGE mappings (executable images)
- Cross-process section mapping detection
- Anomalous mapping patterns

Detection Techniques Covered (MITRE ATT&CK):
- T1055.001: Process Injection - DLL Injection
- T1055.003: Process Injection - Thread Execution Hijacking
- T1055.004: Process Injection - Asynchronous Procedure Call
- T1055.012: Process Injection - Process Hollowing
- T1620: Reflective Code Loading
- T1106: Native API (Direct syscall for section mapping)
- T1027.002: Obfuscated Files - Software Packing

Performance Characteristics:
- O(1) cache lookup via hash table
- Lock-free statistics using InterlockedXxx
- Early exit for kernel-mode requests
- Configurable scan depth and policy
- Minimal latency on hot path (cache hit)
- Deferred analysis via work items

CRITICAL STABILITY NOTES:
- This callback runs during section acquisition at PASSIVE_LEVEL
- MUST NOT trigger synchronous user-mode communication (deadlock risk)
- MUST NOT allocate paged memory in hot path
- MUST complete quickly to avoid system hangs
- Rely on PreCreate for scan population, cache for enforcement
- DPC cleanup uses work items to avoid IRQL violations

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.

REVISION HISTORY:
- v3.0.0: Complete security hardening pass
  - Fixed DPC IRQL violation (work item pattern)
  - Fixed initialization race condition
  - Fixed UNICODE_STRING buffer overread
  - Fixed timer cancellation race
  - Fixed reference counting races
  - Added PID recycling protection
  - Added graceful degradation with LRU eviction
  - Enhanced hollowing detection heuristics
  - Added runtime configuration support
  - Added comprehensive telemetry
===============================================================================
--*/

#include "FileSystemCallbacks.h"
#include "../../Core/Globals.h"
#include "../../Shared/SharedDefs.h"
#include "../../Cache/ScanCache.h"
#include "../../Communication/ScanBridge.h"
#include "../../SelfProtection/SelfProtect.h"
#include "../../Exclusions/ExclusionManager.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PAS_POOL_TAG                    'sAPP'  // PPAS - PreAcquireSection
#define PAS_MAX_TRACKED_MAPPINGS        4096
#define PAS_MAPPING_TIMEOUT_100NS       (300000LL * 10000LL)  // 5 minutes in 100ns
#define PAS_CLEANUP_INTERVAL_MS         60000   // 1 minute
#define PAS_MAX_PROCESS_MAPPINGS        256     // Max tracked per process
#define PAS_ANOMALY_THRESHOLD_DEFAULT   10      // Mappings per second
#define PAS_TIME_WINDOW_100NS           (10000000LL)  // 1 second in 100ns units
#define PAS_LRU_EVICTION_COUNT          64      // Records to evict when at capacity
#define PAS_CAPACITY_WARNING_THRESHOLD  3840    // 93.75% of max - warn before full

//
// Page protection flags for execute detection
//
#define PAS_EXECUTE_PROTECTION_MASK     (PAGE_EXECUTE | PAGE_EXECUTE_READ | \
                                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

//
// Section types for classification
//
#define PAS_SECTION_IMAGE               0x01000000  // SEC_IMAGE
#define PAS_SECTION_RESERVE             0x04000000  // SEC_RESERVE
#define PAS_SECTION_COMMIT              0x08000000  // SEC_COMMIT
#define PAS_SECTION_NOCACHE             0x10000000  // SEC_NOCACHE
#define PAS_SECTION_LARGE_PAGES         0x80000000  // SEC_LARGE_PAGES

//
// Suspicion score thresholds (configurable at runtime)
//
#define PAS_SUSPICION_LOW_DEFAULT       15
#define PAS_SUSPICION_MEDIUM_DEFAULT    40
#define PAS_SUSPICION_HIGH_DEFAULT      65
#define PAS_SUSPICION_CRITICAL_DEFAULT  85

//
// Mapping classification flags
//
#define PAS_MAP_FLAG_EXECUTABLE         0x00000001
#define PAS_MAP_FLAG_IMAGE              0x00000002
#define PAS_MAP_FLAG_WRITABLE           0x00000004
#define PAS_MAP_FLAG_CROSS_PROCESS      0x00000008
#define PAS_MAP_FLAG_UNSIGNED           0x00000010
#define PAS_MAP_FLAG_PACKED             0x00000020
#define PAS_MAP_FLAG_SUSPICIOUS_PATH    0x00000040
#define PAS_MAP_FLAG_TEMP_LOCATION      0x00000080
#define PAS_MAP_FLAG_NETWORK            0x00000100
#define PAS_MAP_FLAG_REMOVABLE          0x00000200
#define PAS_MAP_FLAG_ADS                0x00000400
#define PAS_MAP_FLAG_BLOCKED            0x00000800
#define PAS_MAP_FLAG_HOLLOWING_SUSPECT  0x00001000
#define PAS_MAP_FLAG_REFLECTIVE_SUSPECT 0x00002000
#define PAS_MAP_FLAG_EARLY_PROCESS      0x00004000
#define PAS_MAP_FLAG_SUSPENDED_THREAD   0x00008000

//
// Behavior flags
//
#define PAS_BEHAVIOR_RAPID_MAPPING      0x00000001
#define PAS_BEHAVIOR_CROSS_PROCESS      0x00000002
#define PAS_BEHAVIOR_UNSIGNED_EXEC      0x00000004
#define PAS_BEHAVIOR_TEMP_EXEC          0x00000008
#define PAS_BEHAVIOR_MULTIPLE_TARGETS   0x00000010
#define PAS_BEHAVIOR_SELF_MODIFICATION  0x00000020
#define PAS_BEHAVIOR_HOLLOWING          0x00000040
#define PAS_BEHAVIOR_REFLECTIVE         0x00000080

//
// Initialization states (for thread-safe init)
//
#define PAS_STATE_UNINITIALIZED         0
#define PAS_STATE_INITIALIZING          1
#define PAS_STATE_INITIALIZED           2
#define PAS_STATE_FAILED                3
#define PAS_STATE_SHUTTING_DOWN         4

//
// Hash bucket count (power of 2 for fast modulo)
//
#define PAS_HASH_BUCKET_COUNT           128
#define PAS_HASH_BUCKET_MASK            (PAS_HASH_BUCKET_COUNT - 1)

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Per-mapping tracking record
//
typedef struct _PAS_MAPPING_RECORD {
    //
    // Identification
    //
    HANDLE ProcessId;
    HANDLE ThreadId;
    PVOID FileObject;
    LARGE_INTEGER Timestamp;

    //
    // File information
    //
    ULONG VolumeSerial;
    UINT64 FileId;
    UINT64 FileSize;

    //
    // Mapping details
    //
    ULONG PageProtection;
    ULONG SectionType;
    ULONG MappingFlags;
    ULONG SuspicionScore;

    //
    // Verdict
    //
    SHADOWSTRIKE_VERDICT Verdict;
    BOOLEAN WasCacheHit;
    BOOLEAN WasBlocked;

    //
    // List linkage (doubly linked for O(1) removal)
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

} PAS_MAPPING_RECORD, *PPAS_MAPPING_RECORD;

//
// Per-process section mapping context
//
typedef struct _PAS_PROCESS_CONTEXT {
    //
    // Process identification (includes create time to handle PID recycling)
    //
    HANDLE ProcessId;
    LARGE_INTEGER ProcessCreateTime;

    //
    // Mapping statistics (unsigned to avoid overflow UB)
    //
    volatile UINT64 TotalMappings;
    volatile UINT64 ExecutableMappings;
    volatile UINT64 ImageMappings;
    volatile UINT64 SuspiciousMappings;
    volatile UINT64 BlockedMappings;

    //
    // Time-windowed metrics (for anomaly detection)
    //
    volatile LONG RecentMappings;
    volatile LONG RecentExecutables;
    LARGE_INTEGER WindowStartTime;

    //
    // Behavioral indicators
    //
    ULONG BehaviorFlags;
    ULONG SuspicionScore;
    BOOLEAN IsHollowingSuspect;
    BOOLEAN IsInjectionSuspect;
    BOOLEAN IsReflectiveSuspect;

    //
    // State flags
    //
    volatile BOOLEAN Removed;           // Marked for removal
    volatile BOOLEAN IsEarlyProcess;    // Process is newly created

    //
    // Reference counting (must hold lock to decrement to zero)
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;

} PAS_PROCESS_CONTEXT, *PPAS_PROCESS_CONTEXT;

//
// Hash bucket for fast lookup
//
typedef struct _PAS_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
} PAS_HASH_BUCKET, *PPAS_HASH_BUCKET;

//
// Runtime configuration (all tunable parameters)
//
typedef struct _PAS_CONFIGURATION {
    //
    // Feature toggles
    //
    BOOLEAN EnableBlocking;
    BOOLEAN EnableHollowingDetection;
    BOOLEAN EnableInjectionDetection;
    BOOLEAN EnableReflectiveDetection;
    BOOLEAN EnableVerboseLogging;
    BOOLEAN LogAllMappings;

    //
    // Thresholds (tunable per-environment)
    //
    ULONG MinBlockScore;
    ULONG AnomalyThreshold;
    ULONG SuspicionLow;
    ULONG SuspicionMedium;
    ULONG SuspicionHigh;
    ULONG SuspicionCritical;

    //
    // Hollowing detection parameters
    //
    ULONG HollowingRecentExecThreshold;     // Max recent executables before suspect
    ULONG HollowingImageMappingThreshold;   // Image mapping count threshold
    ULONG HollowingTotalMappingThreshold;   // Total mapping threshold for ratio
    ULONG HollowingEarlyProcessWindowMs;    // Window for "early process" detection

    //
    // Capacity management
    //
    ULONG MaxTrackedMappings;
    ULONG LruEvictionCount;

} PAS_CONFIGURATION, *PPAS_CONFIGURATION;

//
// Statistics (all unsigned to avoid overflow UB)
//
typedef struct _PAS_STATISTICS {
    volatile UINT64 TotalCalls;
    volatile UINT64 ExecuteMappings;
    volatile UINT64 ImageMappings;
    volatile UINT64 CacheHits;
    volatile UINT64 CacheMisses;
    volatile UINT64 Blocked;
    volatile UINT64 Allowed;
    volatile UINT64 SuspiciousDetected;
    volatile UINT64 HollowingDetected;
    volatile UINT64 InjectionDetected;
    volatile UINT64 ReflectiveDetected;
    volatile UINT64 Errors;
    volatile UINT64 AllocationFailures;
    volatile UINT64 CapacityEvictions;
    volatile UINT64 CapacityWarnings;
    LARGE_INTEGER StartTime;
} PAS_STATISTICS, *PPAS_STATISTICS;

//
// Global state
//
typedef struct _PAS_GLOBAL_STATE {
    //
    // Initialization state (use Interlocked operations)
    //
    volatile LONG InitState;

    //
    // Process context tracking
    //
    LIST_ENTRY ProcessContextList;
    EX_PUSH_LOCK ProcessContextLock;
    volatile LONG ProcessContextCount;

    //
    // Mapping records (LRU list - head is oldest)
    //
    LIST_ENTRY MappingList;
    EX_PUSH_LOCK MappingLock;
    volatile LONG MappingCount;

    //
    // Hash table for fast lookup
    //
    PAS_HASH_BUCKET HashTable[PAS_HASH_BUCKET_COUNT];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST RecordLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    volatile BOOLEAN LookasideInitialized;

    //
    // Statistics
    //
    PAS_STATISTICS Stats;

    //
    // Configuration (runtime tunable)
    //
    PAS_CONFIGURATION Config;

    //
    // Cleanup timer and work item
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    WORK_QUEUE_ITEM CleanupWorkItem;
    volatile BOOLEAN CleanupWorkItemQueued;
    volatile BOOLEAN CleanupTimerActive;

    //
    // Shutdown synchronization
    //
    volatile LONG ShutdownRequested;
    KEVENT ShutdownEvent;

} PAS_GLOBAL_STATE, *PPAS_GLOBAL_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PAS_GLOBAL_STATE g_PasState = {0};

//
// Suspicious path patterns for detection (length-prefixed for safe comparison)
//
typedef struct _PAS_SUSPICIOUS_PATH {
    PCWSTR Pattern;
    USHORT LengthInBytes;   // Pre-computed length for fast comparison
} PAS_SUSPICIOUS_PATH;

static const PAS_SUSPICIOUS_PATH g_SuspiciousPaths[] = {
    { L"\\Temp\\",                      12 },
    { L"\\TMP\\",                       10 },
    { L"\\AppData\\Local\\Temp\\",      40 },
    { L"\\Windows\\Temp\\",             28 },
    { L"\\Users\\Public\\",             28 },
    { L"\\ProgramData\\",               26 },
    { L"\\Downloads\\",                 22 },
    { L"\\Recycle",                     16 },
    { L"$Recycle.Bin",                  24 },
    { L"\\staging\\",                   18 },
    { L"\\cache\\",                     14 },
};

#define PAS_SUSPICIOUS_PATH_COUNT (sizeof(g_SuspiciousPaths) / sizeof(g_SuspiciousPaths[0]))

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static NTSTATUS
PaspInitialize(
    VOID
    );

static VOID
PaspShutdown(
    VOID
    );

static PPAS_PROCESS_CONTEXT
PaspLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    );

static VOID
PaspReferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    );

static VOID
PaspDereferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    );

static PPAS_MAPPING_RECORD
PaspAllocateRecord(
    VOID
    );

static VOID
PaspFreeRecord(
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspInsertRecord(
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspEvictOldestRecords(
    _In_ ULONG Count
    );

static ULONG
PaspClassifyMapping(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG PageProtection
    );

static ULONG
PaspCalculateSuspicionScore(
    _In_ PPAS_MAPPING_RECORD Record,
    _In_opt_ PPAS_PROCESS_CONTEXT ProcessContext
    );

static BOOLEAN
PaspContainsSubstringW(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Needle,
    _In_ USHORT NeedleLengthInBytes
    );

static BOOLEAN
PaspIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    );

static BOOLEAN
PaspDetectHollowingPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static BOOLEAN
PaspDetectInjectionPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static BOOLEAN
PaspDetectReflectiveLoading(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspUpdateProcessMetrics(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    );

static VOID
PaspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
PaspCleanupWorkRoutine(
    _In_ PVOID Parameter
    );

static VOID
PaspCleanupStaleRecords(
    VOID
    );

static ULONG
PaspHashFileId(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    );

static BOOLEAN
PaspGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    );

static BOOLEAN
PaspIsProcessSuspended(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PaspLogEvent(
    _In_ ULONG Level,
    _In_ PCSTR Format,
    ...
    );

// ============================================================================
// SAFE STRING OPERATIONS
// ============================================================================

/*++
Routine Description:
    Safe substring search within UNICODE_STRING bounds.
    Does NOT rely on null-termination.

Arguments:
    Haystack - The string to search within.
    Needle - The substring to find (null-terminated constant).
    NeedleLengthInBytes - Pre-computed length of Needle in bytes.

Return Value:
    TRUE if Needle is found within Haystack.
    FALSE otherwise.

IRQL:
    <= APC_LEVEL (safe for paged strings)
--*/
static BOOLEAN
PaspContainsSubstringW(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCWSTR Needle,
    _In_ USHORT NeedleLengthInBytes
    )
{
    USHORT HaystackChars;
    USHORT NeedleChars;
    USHORT MaxOffset;
    USHORT i;

    if (Haystack == NULL || Haystack->Buffer == NULL || Haystack->Length == 0) {
        return FALSE;
    }

    if (Needle == NULL || NeedleLengthInBytes == 0) {
        return FALSE;
    }

    HaystackChars = Haystack->Length / sizeof(WCHAR);
    NeedleChars = NeedleLengthInBytes / sizeof(WCHAR);

    if (HaystackChars < NeedleChars) {
        return FALSE;
    }

    MaxOffset = HaystackChars - NeedleChars;

    for (i = 0; i <= MaxOffset; i++) {
        //
        // Case-insensitive comparison within bounds
        //
        if (_wcsnicmp(&Haystack->Buffer[i], Needle, NeedleChars) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// PROCESS UTILITY FUNCTIONS
// ============================================================================

/*++
Routine Description:
    Gets the creation time for a process to handle PID recycling.

Arguments:
    ProcessId - Process ID to query.
    CreateTime - Receives the process creation time.

Return Value:
    TRUE on success, FALSE on failure.
--*/
static BOOLEAN
PaspGetProcessCreateTime(
    _In_ HANDLE ProcessId,
    _Out_ PLARGE_INTEGER CreateTime
    )
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    LARGE_INTEGER Time = {0};

    CreateTime->QuadPart = 0;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    //
    // PsGetProcessCreateTimeQuadPart returns creation time
    //
    Time.QuadPart = PsGetProcessCreateTimeQuadPart(Process);

    ObDereferenceObject(Process);

    CreateTime->QuadPart = Time.QuadPart;
    return TRUE;
}

/*++
Routine Description:
    Checks if a process has any suspended threads (hollowing indicator).

Arguments:
    ProcessId - Process ID to check.

Return Value:
    TRUE if process has suspended threads, FALSE otherwise.

Note:
    This is a lightweight heuristic check, not definitive.
--*/
static BOOLEAN
PaspIsProcessSuspended(
    _In_ HANDLE ProcessId
    )
{
    //
    // This would require enumerating threads and checking suspend count.
    // For now, we rely on other heuristics. A full implementation would
    // use ZwQuerySystemInformation with SystemProcessInformation class.
    //
    // TODO: Implement thread suspension check via SystemProcessInformation
    // For enterprise deployment, this should query actual thread states.
    //
    UNREFERENCED_PARAMETER(ProcessId);
    return FALSE;
}

// ============================================================================
// LOGGING
// ============================================================================

/*++
Routine Description:
    Conditional logging based on verbosity configuration.

Arguments:
    Level - DbgPrint level (DPFLTR_xxx_LEVEL).
    Format - Printf-style format string.
    ... - Variable arguments.

Note:
    Only logs if EnableVerboseLogging is TRUE or Level <= WARNING.
--*/
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
PaspLogEvent(
    _In_ ULONG Level,
    _In_ PCSTR Format,
    ...
    )
{
    va_list Args;

    //
    // Always log warnings and errors
    // Only log info/trace if verbose logging is enabled
    //
    if (Level > DPFLTR_WARNING_LEVEL && !g_PasState.Config.EnableVerboseLogging) {
        return;
    }

    va_start(Args, Format);
    vDbgPrintEx(DPFLTR_IHVDRIVER_ID, Level, Format, Args);
    va_end(Args);
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/*++
Routine Description:
    Initializes the PreAcquireSection subsystem with thread-safe initialization.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_ALREADY_REGISTERED if already initialized.
    Appropriate error status on failure.

Thread Safety:
    Uses InterlockedCompareExchange to ensure single-threaded initialization.
--*/
static NTSTATUS
PaspInitialize(
    VOID
    )
{
    LARGE_INTEGER DueTime;
    ULONG i;
    LONG PreviousState;

    //
    // Attempt to claim initialization
    //
    PreviousState = InterlockedCompareExchange(
        &g_PasState.InitState,
        PAS_STATE_INITIALIZING,
        PAS_STATE_UNINITIALIZED
        );

    if (PreviousState == PAS_STATE_INITIALIZED) {
        return STATUS_ALREADY_REGISTERED;
    }

    if (PreviousState == PAS_STATE_INITIALIZING) {
        //
        // Another thread is initializing - spin wait
        //
        while (InterlockedCompareExchange(&g_PasState.InitState, 0, 0) == PAS_STATE_INITIALIZING) {
            YieldProcessor();
            KeMemoryBarrier();
        }

        //
        // Check final state
        //
        if (InterlockedCompareExchange(&g_PasState.InitState, 0, 0) == PAS_STATE_INITIALIZED) {
            return STATUS_SUCCESS;
        }
        return STATUS_UNSUCCESSFUL;
    }

    if (PreviousState == PAS_STATE_FAILED || PreviousState == PAS_STATE_SHUTTING_DOWN) {
        return STATUS_UNSUCCESSFUL;
    }

    //
    // We own initialization - proceed
    //

    //
    // Initialize shutdown event
    //
    KeInitializeEvent(&g_PasState.ShutdownEvent, NotificationEvent, FALSE);
    InterlockedExchange(&g_PasState.ShutdownRequested, FALSE);

    //
    // Initialize process context list
    //
    InitializeListHead(&g_PasState.ProcessContextList);
    ExInitializePushLock(&g_PasState.ProcessContextLock);
    g_PasState.ProcessContextCount = 0;

    //
    // Initialize mapping list
    //
    InitializeListHead(&g_PasState.MappingList);
    ExInitializePushLock(&g_PasState.MappingLock);
    g_PasState.MappingCount = 0;

    //
    // Initialize hash table
    //
    for (i = 0; i < PAS_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_PasState.HashTable[i].List);
        ExInitializePushLock(&g_PasState.HashTable[i].Lock);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_PasState.RecordLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PAS_MAPPING_RECORD),
        PAS_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_PasState.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PAS_PROCESS_CONTEXT),
        PAS_POOL_TAG,
        0
        );

    InterlockedExchange((PLONG)&g_PasState.LookasideInitialized, TRUE);

    //
    // Initialize default configuration
    //
    g_PasState.Config.EnableBlocking = TRUE;
    g_PasState.Config.EnableHollowingDetection = TRUE;
    g_PasState.Config.EnableInjectionDetection = TRUE;
    g_PasState.Config.EnableReflectiveDetection = TRUE;
    g_PasState.Config.EnableVerboseLogging = FALSE;
    g_PasState.Config.LogAllMappings = FALSE;

    g_PasState.Config.MinBlockScore = PAS_SUSPICION_CRITICAL_DEFAULT;
    g_PasState.Config.AnomalyThreshold = PAS_ANOMALY_THRESHOLD_DEFAULT;
    g_PasState.Config.SuspicionLow = PAS_SUSPICION_LOW_DEFAULT;
    g_PasState.Config.SuspicionMedium = PAS_SUSPICION_MEDIUM_DEFAULT;
    g_PasState.Config.SuspicionHigh = PAS_SUSPICION_HIGH_DEFAULT;
    g_PasState.Config.SuspicionCritical = PAS_SUSPICION_CRITICAL_DEFAULT;

    g_PasState.Config.HollowingRecentExecThreshold = 3;
    g_PasState.Config.HollowingImageMappingThreshold = 5;
    g_PasState.Config.HollowingTotalMappingThreshold = 20;
    g_PasState.Config.HollowingEarlyProcessWindowMs = 5000;

    g_PasState.Config.MaxTrackedMappings = PAS_MAX_TRACKED_MAPPINGS;
    g_PasState.Config.LruEvictionCount = PAS_LRU_EVICTION_COUNT;

    //
    // Initialize statistics
    //
    RtlZeroMemory(&g_PasState.Stats, sizeof(PAS_STATISTICS));
    KeQuerySystemTime(&g_PasState.Stats.StartTime);

    //
    // Initialize cleanup work item (runs at PASSIVE_LEVEL)
    //
    ExInitializeWorkItem(
        &g_PasState.CleanupWorkItem,
        PaspCleanupWorkRoutine,
        NULL
        );
    InterlockedExchange((PLONG)&g_PasState.CleanupWorkItemQueued, FALSE);

    //
    // Initialize cleanup timer and DPC
    //
    KeInitializeTimer(&g_PasState.CleanupTimer);
    KeInitializeDpc(&g_PasState.CleanupDpc, PaspCleanupTimerDpc, NULL);

    //
    // Start cleanup timer
    //
    DueTime.QuadPart = -((LONGLONG)PAS_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_PasState.CleanupTimer,
        DueTime,
        PAS_CLEANUP_INTERVAL_MS,
        &g_PasState.CleanupDpc
        );
    InterlockedExchange((PLONG)&g_PasState.CleanupTimerActive, TRUE);

    //
    // Mark as initialized (with memory barrier)
    //
    KeMemoryBarrier();
    InterlockedExchange(&g_PasState.InitState, PAS_STATE_INITIALIZED);

    PaspLogEvent(
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PreAcquireSection] Initialized successfully\n"
        );

    return STATUS_SUCCESS;
}


/*++
Routine Description:
    Shuts down the PreAcquireSection subsystem safely.

Thread Safety:
    - Cancels timer and waits for DPC completion
    - Drains all pending work items
    - Properly cleans up all resources
--*/
static VOID
PaspShutdown(
    VOID
    )
{
    PLIST_ENTRY Entry;
    PPAS_MAPPING_RECORD Record;
    PPAS_PROCESS_CONTEXT Context;
    LONG CurrentState;

    //
    // Atomically transition to shutting down
    //
    CurrentState = InterlockedCompareExchange(
        &g_PasState.InitState,
        PAS_STATE_SHUTTING_DOWN,
        PAS_STATE_INITIALIZED
        );

    if (CurrentState != PAS_STATE_INITIALIZED) {
        return;
    }

    //
    // Signal shutdown
    //
    InterlockedExchange(&g_PasState.ShutdownRequested, TRUE);
    KeSetEvent(&g_PasState.ShutdownEvent, 0, FALSE);

    //
    // Cancel cleanup timer and wait for DPC completion
    //
    if (g_PasState.CleanupTimerActive) {
        if (!KeCancelTimer(&g_PasState.CleanupTimer)) {
            //
            // Timer already fired - DPC may be running or work item queued
            // Wait for DPC completion
            //
            KeFlushQueuedDpcs();
        }
        InterlockedExchange((PLONG)&g_PasState.CleanupTimerActive, FALSE);
    }

    //
    // Wait for any queued work item to complete
    // Note: There's no direct API to wait for work items, so we use a short delay
    // In production, consider using a dedicated worker thread with proper signaling
    //
    if (g_PasState.CleanupWorkItemQueued) {
        LARGE_INTEGER Delay;
        Delay.QuadPart = -500000;  // 50ms
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    //
    // Free all mapping records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    while (!IsListEmpty(&g_PasState.MappingList)) {
        Entry = RemoveHeadList(&g_PasState.MappingList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);
        InterlockedDecrement(&g_PasState.MappingCount);

        //
        // Release lock while freeing to avoid holding lock too long
        //
        ExReleasePushLockExclusive(&g_PasState.MappingLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.RecordLookaside, Record);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PasState.MappingLock);
    }

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    while (!IsListEmpty(&g_PasState.ProcessContextList)) {
        Entry = RemoveHeadList(&g_PasState.ProcessContextList);
        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);
        InterlockedDecrement(&g_PasState.ProcessContextCount);

        ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);
    }

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (g_PasState.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_PasState.RecordLookaside);
        ExDeleteNPagedLookasideList(&g_PasState.ContextLookaside);
        InterlockedExchange((PLONG)&g_PasState.LookasideInitialized, FALSE);
    }

    //
    // Mark as uninitialized
    //
    InterlockedExchange(&g_PasState.InitState, PAS_STATE_UNINITIALIZED);

    PaspLogEvent(
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PreAcquireSection] Shutdown complete\n"
        );
}

// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

_Use_decl_annotations_
FLT_PREOP_CALLBACK_STATUS
ShadowStrikePreAcquireSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++
Routine Description:
    Enterprise-grade pre-operation callback for IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION.

    This callback is invoked when the memory manager is about to map a file into
    a process address space. This is a critical interception point for:
    - Detecting executable image mappings (SEC_IMAGE)
    - Blocking known malware from executing
    - Detecting DLL injection patterns
    - Detecting process hollowing
    - Detecting reflective DLL loading

    CRITICAL: This callback runs at PASSIVE_LEVEL during section acquisition.
    We MUST NOT:
    - Trigger synchronous user-mode communication (deadlock)
    - Perform long-running operations
    - Block indefinitely
    - Query file names with FLT_FILE_NAME_QUERY_DEFAULT (use CACHE_ONLY)

    We rely on PreCreate to have populated the scan cache.
    Here we only enforce cached verdicts and track behavior.

Arguments:
    Data        - Callback data containing operation parameters.
    FltObjects  - Filter objects (volume, instance, file object).
    CompletionContext - Completion context (unused).

Return Value:
    FLT_PREOP_SUCCESS_NO_CALLBACK - Allow the operation.
    FLT_PREOP_COMPLETE - Block the operation (access denied).

IRQL:
    PASSIVE_LEVEL
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG PageProtection;
    SHADOWSTRIKE_CACHE_KEY CacheKey;
    SHADOWSTRIKE_CACHE_RESULT CacheResult;
    PPAS_PROCESS_CONTEXT ProcessContext = NULL;
    PPAS_MAPPING_RECORD MappingRecord = NULL;
    HANDLE CurrentProcessId;
    ULONG MappingFlags = 0;
    ULONG SuspicionScore = 0;
    BOOLEAN ShouldBlock = FALSE;
    BOOLEAN IsExecuteMapping = FALSE;
    BOOLEAN IsCacheHit = FALSE;
    PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
    LONG InitState;

    UNREFERENCED_PARAMETER(CompletionContext);

    //
    // Check initialization state with memory barrier
    //
    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState == PAS_STATE_UNINITIALIZED) {
        //
        // Attempt lazy initialization
        //
        Status = PaspInitialize();
        if (!NT_SUCCESS(Status)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
    } else if (InitState != PAS_STATE_INITIALIZED) {
        //
        // Initializing, failed, or shutting down
        //
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Check shutdown flag with memory barrier
    //
    KeMemoryBarrier();
    if (InterlockedCompareExchange(&g_PasState.ShutdownRequested, 0, 0)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Validate external dependencies before use
    //
    if (SHADOWSTRIKE_IS_READY == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!SHADOWSTRIKE_IS_READY()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get page protection from parameters
    //
    if (Data == NULL || Data->Iopb == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    PageProtection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;

    //
    // Fast path: Skip non-executable mappings
    //
    if (!(PageProtection & PAS_EXECUTE_PROTECTION_MASK)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    IsExecuteMapping = TRUE;

    //
    // Update statistics (unsigned, no overflow UB)
    //
    InterlockedIncrement64((PLONG64)&g_PasState.Stats.TotalCalls);
    InterlockedIncrement64((PLONG64)&g_PasState.Stats.ExecuteMappings);

    //
    // Skip kernel-mode requests (trust the kernel)
    //
    if (Data->RequestorMode == KernelMode) {
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Skip if no file object
    //
    if (FltObjects == NULL || FltObjects->FileObject == NULL) {
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Get current process ID
    //
    CurrentProcessId = PsGetCurrentProcessId();

    //
    // Skip system process and protected processes
    //
    if (CurrentProcessId == (HANDLE)(ULONG_PTR)4) {
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Validate ShadowStrikeIsProcessProtected before calling
    //
    if (ShadowStrikeIsProcessProtected != NULL &&
        ShadowStrikeIsProcessProtected(CurrentProcessId)) {
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.Allowed);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Enter operation tracking
    //
    if (SHADOWSTRIKE_ENTER_OPERATION != NULL) {
        SHADOWSTRIKE_ENTER_OPERATION();
    }

    //
    // Get or create process context for behavioral analysis
    //
    ProcessContext = PaspLookupProcessContext(CurrentProcessId, TRUE);

    //
    // Classify this mapping
    //
    MappingFlags = PaspClassifyMapping(Data, FltObjects, PageProtection);

    //
    // Check scan cache for verdict (fast path)
    //
    RtlZeroMemory(&CacheKey, sizeof(CacheKey));
    RtlZeroMemory(&CacheResult, sizeof(CacheResult));

    if (ShadowStrikeCacheBuildKey != NULL && ShadowStrikeCacheLookup != NULL) {
        Status = ShadowStrikeCacheBuildKey(FltObjects, &CacheKey);
        if (NT_SUCCESS(Status)) {
            if (ShadowStrikeCacheLookup(&CacheKey, &CacheResult)) {
                IsCacheHit = TRUE;
                InterlockedIncrement64((PLONG64)&g_PasState.Stats.CacheHits);

                if (CacheResult.Verdict == ShadowStrikeVerdictBlock) {
                    //
                    // Known malware - BLOCK immediately
                    //
                    ShouldBlock = TRUE;
                    SuspicionScore = 100;

                    PaspLogEvent(
                        DPFLTR_WARNING_LEVEL,
                        "[ShadowStrike/PreAcquireSection] CACHE HIT - BLOCK: "
                        "PID=%lu, FileId=0x%llX, Score=%lu\n",
                        HandleToULong(CurrentProcessId),
                        CacheKey.FileId,
                        CacheResult.ThreatScore
                        );
                }
            } else {
                InterlockedIncrement64((PLONG64)&g_PasState.Stats.CacheMisses);
            }
        }
    }

    //
    // Allocate mapping record for tracking (with capacity management)
    //
    MappingRecord = PaspAllocateRecord();
    if (MappingRecord != NULL) {
        MappingRecord->ProcessId = CurrentProcessId;
        MappingRecord->ThreadId = PsGetCurrentThreadId();
        MappingRecord->FileObject = FltObjects->FileObject;
        KeQuerySystemTime(&MappingRecord->Timestamp);
        MappingRecord->VolumeSerial = CacheKey.VolumeSerial;
        MappingRecord->FileId = CacheKey.FileId;
        MappingRecord->FileSize = CacheKey.FileSize;
        MappingRecord->PageProtection = PageProtection;
        MappingRecord->MappingFlags = MappingFlags;
        MappingRecord->WasCacheHit = IsCacheHit;

        if (IsCacheHit) {
            MappingRecord->Verdict = CacheResult.Verdict;
        }
    } else {
        //
        // Track allocation failures
        //
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.AllocationFailures);
    }

    //
    // Behavioral analysis (if not already blocking)
    //
    if (!ShouldBlock && ProcessContext != NULL) {
        //
        // Check for early process (potential hollowing target)
        //
        if (ProcessContext->IsEarlyProcess) {
            MappingFlags |= PAS_MAP_FLAG_EARLY_PROCESS;
            SuspicionScore += 10;
        }

        //
        // Update process metrics
        //
        if (MappingRecord != NULL) {
            PaspUpdateProcessMetrics(ProcessContext, MappingRecord);
        }

        //
        // Check for process hollowing pattern
        //
        if (g_PasState.Config.EnableHollowingDetection) {
            if (MappingRecord != NULL && PaspDetectHollowingPattern(ProcessContext, MappingRecord)) {
                MappingFlags |= PAS_MAP_FLAG_HOLLOWING_SUSPECT;
                ProcessContext->IsHollowingSuspect = TRUE;
                ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_HOLLOWING;
                SuspicionScore += 30;
                InterlockedIncrement64((PLONG64)&g_PasState.Stats.HollowingDetected);
            }
        }

        //
        // Check for DLL injection pattern
        //
        if (g_PasState.Config.EnableInjectionDetection) {
            if (MappingRecord != NULL && PaspDetectInjectionPattern(ProcessContext, MappingRecord)) {
                ProcessContext->IsInjectionSuspect = TRUE;
                ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_CROSS_PROCESS;
                SuspicionScore += 25;
                InterlockedIncrement64((PLONG64)&g_PasState.Stats.InjectionDetected);
            }
        }

        //
        // Check for reflective loading pattern
        //
        if (g_PasState.Config.EnableReflectiveDetection) {
            if (MappingRecord != NULL && PaspDetectReflectiveLoading(ProcessContext, MappingRecord)) {
                MappingFlags |= PAS_MAP_FLAG_REFLECTIVE_SUSPECT;
                ProcessContext->IsReflectiveSuspect = TRUE;
                ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_REFLECTIVE;
                SuspicionScore += 35;
                InterlockedIncrement64((PLONG64)&g_PasState.Stats.ReflectiveDetected);
            }
        }

        //
        // Check for rapid mapping anomaly
        //
        if ((ULONG)ProcessContext->RecentMappings > g_PasState.Config.AnomalyThreshold) {
            ProcessContext->BehaviorFlags |= PAS_BEHAVIOR_RAPID_MAPPING;
            SuspicionScore += 15;
        }
    }

    //
    // Get file path for additional checks (CACHE ONLY to avoid deadlock)
    //
    if (!ShouldBlock && !IsCacheHit) {
        //
        // CRITICAL: Use FLT_FILE_NAME_QUERY_CACHE_ONLY to prevent deadlock
        // during section acquisition. FLT_FILE_NAME_QUERY_DEFAULT can cause
        // the file system to acquire locks that are already held.
        //
        Status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_CACHE_ONLY,
            &NameInfo
            );

        if (NT_SUCCESS(Status) && NameInfo != NULL) {
            Status = FltParseFileNameInformation(NameInfo);
            if (NT_SUCCESS(Status)) {
                //
                // Check for suspicious path (using safe substring search)
                //
                if (PaspIsSuspiciousPath(&NameInfo->Name)) {
                    MappingFlags |= PAS_MAP_FLAG_SUSPICIOUS_PATH;
                    SuspicionScore += 20;
                }

                //
                // Check for temp location specifically
                //
                if (PaspContainsSubstringW(&NameInfo->Name, L"\\Temp\\", 12) ||
                    PaspContainsSubstringW(&NameInfo->Name, L"\\TMP\\", 10)) {
                    MappingFlags |= PAS_MAP_FLAG_TEMP_LOCATION;
                    SuspicionScore += 15;
                }

                //
                // Check for ADS (Alternate Data Stream)
                //
                if (NameInfo->Stream.Length > 0) {
                    MappingFlags |= PAS_MAP_FLAG_ADS;
                    SuspicionScore += 25;
                }
            }

            //
            // Always release name info (fixes LOW-2 leak)
            //
            FltReleaseFileNameInformation(NameInfo);
            NameInfo = NULL;
        }
    }

    //
    // Calculate final suspicion score
    //
    if (MappingRecord != NULL) {
        MappingRecord->SuspicionScore = PaspCalculateSuspicionScore(MappingRecord, ProcessContext);
        SuspicionScore = max(SuspicionScore, MappingRecord->SuspicionScore);
        MappingRecord->MappingFlags = MappingFlags;
    }

    //
    // Check if we should block based on score
    //
    if (!ShouldBlock && g_PasState.Config.EnableBlocking) {
        if (SuspicionScore >= g_PasState.Config.MinBlockScore) {
            ShouldBlock = TRUE;

            PaspLogEvent(
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreAcquireSection] BEHAVIOR BLOCK: "
                "PID=%lu, Score=%lu, Flags=0x%08X\n",
                HandleToULong(CurrentProcessId),
                SuspicionScore,
                MappingFlags
                );
        }
    }

    //
    // Track suspicious mappings
    //
    if (SuspicionScore >= g_PasState.Config.SuspicionMedium) {
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.SuspiciousDetected);

        if (ProcessContext != NULL) {
            InterlockedIncrement64((PLONG64)&ProcessContext->SuspiciousMappings);

            //
            // Use InterlockedCompareExchange for max operation
            //
            ULONG OldScore;
            do {
                OldScore = ProcessContext->SuspicionScore;
                if (SuspicionScore <= OldScore) break;
            } while (InterlockedCompareExchange(
                (PLONG)&ProcessContext->SuspicionScore,
                SuspicionScore,
                OldScore) != (LONG)OldScore);
        }
    }

    //
    // Insert mapping record
    //
    if (MappingRecord != NULL) {
        MappingRecord->WasBlocked = ShouldBlock;
        PaspInsertRecord(MappingRecord);
    }

    //
    // Release process context
    //
    if (ProcessContext != NULL) {
        PaspDereferenceProcessContext(ProcessContext);
        ProcessContext = NULL;
    }

    //
    // Apply verdict
    //
    if (ShouldBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;

        InterlockedIncrement64((PLONG64)&g_PasState.Stats.Blocked);

        if (SHADOWSTRIKE_INC_STAT != NULL) {
            SHADOWSTRIKE_INC_STAT(FilesBlocked);
        }

        if (SHADOWSTRIKE_LEAVE_OPERATION != NULL) {
            SHADOWSTRIKE_LEAVE_OPERATION();
        }

        return FLT_PREOP_COMPLETE;
    }

    InterlockedIncrement64((PLONG64)&g_PasState.Stats.Allowed);

    if (SHADOWSTRIKE_LEAVE_OPERATION != NULL) {
        SHADOWSTRIKE_LEAVE_OPERATION();
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

/*++
Routine Description:
    Looks up or creates a process context for behavioral tracking.
    Handles PID recycling by including process creation time in comparison.

Arguments:
    ProcessId - Process ID to look up.
    CreateIfNotFound - If TRUE, creates a new context if not found.

Return Value:
    Pointer to process context (referenced) or NULL.

Thread Safety:
    Uses push locks with proper critical region handling.
    Handles race conditions during creation.
--*/
static PPAS_PROCESS_CONTEXT
PaspLookupProcessContext(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN CreateIfNotFound
    )
{
    PLIST_ENTRY Entry;
    PPAS_PROCESS_CONTEXT Context = NULL;
    PPAS_PROCESS_CONTEXT NewContext = NULL;
    LARGE_INTEGER ProcessCreateTime = {0};
    BOOLEAN GotCreateTime;

    //
    // Get process creation time for PID recycling protection
    //
    GotCreateTime = PaspGetProcessCreateTime(ProcessId, &ProcessCreateTime);

    //
    // First, try shared lock lookup
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&g_PasState.ProcessContextLock);

    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        //
        // Match on PID AND creation time (handles PID recycling)
        //
        if (Context->ProcessId == ProcessId &&
            !Context->Removed &&
            (!GotCreateTime || Context->ProcessCreateTime.QuadPart == ProcessCreateTime.QuadPart)) {

            PaspReferenceProcessContext(Context);
            ExReleasePushLockShared(&g_PasState.ProcessContextLock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (!CreateIfNotFound) {
        return NULL;
    }

    //
    // Allocate new context outside of lock
    //
    NewContext = (PPAS_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_PasState.ContextLookaside
        );

    if (NewContext == NULL) {
        return NULL;
    }

    RtlZeroMemory(NewContext, sizeof(PAS_PROCESS_CONTEXT));
    NewContext->ProcessId = ProcessId;
    NewContext->ProcessCreateTime = ProcessCreateTime;
    NewContext->RefCount = 1;  // List reference
    NewContext->Removed = FALSE;
    KeQuerySystemTime(&NewContext->WindowStartTime);
    InitializeListHead(&NewContext->ListEntry);

    //
    // Check if this is an early process (created within threshold)
    //
    if (GotCreateTime) {
        LARGE_INTEGER CurrentTime;
        KeQuerySystemTime(&CurrentTime);

        LONGLONG AgeTicks = CurrentTime.QuadPart - ProcessCreateTime.QuadPart;
        LONGLONG ThresholdTicks = (LONGLONG)g_PasState.Config.HollowingEarlyProcessWindowMs * 10000;

        if (AgeTicks < ThresholdTicks) {
            NewContext->IsEarlyProcess = TRUE;
        }
    }

    //
    // Insert with exclusive lock, checking for race
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    //
    // Re-check for race condition
    //
    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId &&
            !Context->Removed &&
            (!GotCreateTime || Context->ProcessCreateTime.QuadPart == ProcessCreateTime.QuadPart)) {

            //
            // Found existing - use it instead
            //
            PaspReferenceProcessContext(Context);
            ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
            KeLeaveCriticalRegion();

            //
            // Free our unused allocation
            //
            ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, NewContext);
            return Context;
        }
    }

    //
    // No existing context - insert ours
    //
    InsertTailList(&g_PasState.ProcessContextList, &NewContext->ListEntry);
    InterlockedIncrement(&g_PasState.ProcessContextCount);

    //
    // Add caller reference (in addition to list reference)
    //
    PaspReferenceProcessContext(NewContext);

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    return NewContext;
}


/*++
Routine Description:
    Adds a reference to a process context.

Arguments:
    Context - Process context to reference.
--*/
static VOID
PaspReferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


/*++
Routine Description:
    Releases a reference to a process context.
    Frees the context when reference count reaches zero.

Arguments:
    Context - Process context to dereference.

Thread Safety:
    Holds exclusive lock before decrementing to zero to prevent
    use-after-free race conditions.
--*/
static VOID
PaspDereferenceProcessContext(
    _Inout_ PPAS_PROCESS_CONTEXT Context
    )
{
    LONG NewRef;
    BOOLEAN ShouldFree = FALSE;

    //
    // Fast path: if RefCount > 1, just decrement
    //
    if (Context->RefCount > 1) {
        NewRef = InterlockedDecrement(&Context->RefCount);
        if (NewRef > 0) {
            return;
        }
        //
        // Race: someone else decremented too, fall through to locked path
        //
    }

    //
    // Slow path: acquire lock before final decrement
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    NewRef = InterlockedDecrement(&Context->RefCount);

    if (NewRef == 0) {
        //
        // We're the last reference - remove from list if present
        //
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_PasState.ProcessContextCount);
        }
        ShouldFree = TRUE;
    }

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    if (ShouldFree) {
        ExFreeToNPagedLookasideList(&g_PasState.ContextLookaside, Context);
    }
}

// ============================================================================
// MAPPING RECORD MANAGEMENT
// ============================================================================

/*++
Routine Description:
    Allocates a mapping record from the lookaside list.
    Implements LRU eviction when at capacity instead of hard rejection.

Return Value:
    Pointer to allocated record or NULL.
--*/
static PPAS_MAPPING_RECORD
PaspAllocateRecord(
    VOID
    )
{
    PPAS_MAPPING_RECORD Record;
    LONG CurrentCount;

    //
    // Check capacity with eviction
    //
    CurrentCount = InterlockedCompareExchange(&g_PasState.MappingCount, 0, 0);

    if ((ULONG)CurrentCount >= g_PasState.Config.MaxTrackedMappings) {
        //
        // At capacity - evict oldest records (LRU)
        //
        PaspEvictOldestRecords(g_PasState.Config.LruEvictionCount);
        InterlockedIncrement64((PLONG64)&g_PasState.Stats.CapacityEvictions);
    } else if ((ULONG)CurrentCount >= PAS_CAPACITY_WARNING_THRESHOLD) {
        //
        // Approaching capacity - log warning (rate limited)
        //
        static LARGE_INTEGER LastWarning = {0};
        LARGE_INTEGER CurrentTime;
        KeQuerySystemTime(&CurrentTime);

        if (CurrentTime.QuadPart - LastWarning.QuadPart > PAS_TIME_WINDOW_100NS * 60) {
            PaspLogEvent(
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/PreAcquireSection] Approaching capacity: %ld/%lu records\n",
                CurrentCount,
                g_PasState.Config.MaxTrackedMappings
                );
            LastWarning = CurrentTime;
            InterlockedIncrement64((PLONG64)&g_PasState.Stats.CapacityWarnings);
        }
    }

    Record = (PPAS_MAPPING_RECORD)ExAllocateFromNPagedLookasideList(
        &g_PasState.RecordLookaside
        );

    if (Record != NULL) {
        RtlZeroMemory(Record, sizeof(PAS_MAPPING_RECORD));
        InitializeListHead(&Record->ListEntry);
        InitializeListHead(&Record->HashEntry);
    }

    return Record;
}


/*++
Routine Description:
    Evicts oldest mapping records to make room for new ones.
    Uses LRU policy (head of list is oldest).

Arguments:
    Count - Number of records to evict.
--*/
static VOID
PaspEvictOldestRecords(
    _In_ ULONG Count
    )
{
    LIST_ENTRY EvictList;
    PLIST_ENTRY Entry;
    PPAS_MAPPING_RECORD Record;
    ULONG Evicted = 0;
    ULONG BucketIndex;
    PPAS_HASH_BUCKET Bucket;

    InitializeListHead(&EvictList);

    //
    // Collect records to evict
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    while (!IsListEmpty(&g_PasState.MappingList) && Evicted < Count) {
        Entry = RemoveHeadList(&g_PasState.MappingList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);
        InterlockedDecrement(&g_PasState.MappingCount);
        InsertTailList(&EvictList, &Record->ListEntry);
        Evicted++;
    }

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Free evicted records and remove from hash table
    //
    while (!IsListEmpty(&EvictList)) {
        Entry = RemoveHeadList(&EvictList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        //
        // Remove from hash table
        //
        BucketIndex = PaspHashFileId(Record->FileId, Record->VolumeSerial);
        Bucket = &g_PasState.HashTable[BucketIndex];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Bucket->Lock);

        if (!IsListEmpty(&Record->HashEntry)) {
            RemoveEntryList(&Record->HashEntry);
            InitializeListHead(&Record->HashEntry);
        }

        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&g_PasState.RecordLookaside, Record);
    }
}


/*++
Routine Description:
    Frees a mapping record back to the lookaside list.

Arguments:
    Record - Record to free.
--*/
static VOID
PaspFreeRecord(
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    if (Record != NULL) {
        ExFreeToNPagedLookasideList(&g_PasState.RecordLookaside, Record);
    }
}


/*++
Routine Description:
    Inserts a mapping record into the tracking lists.

Arguments:
    Record - Record to insert.
--*/
static VOID
PaspInsertRecord(
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    ULONG BucketIndex;
    PPAS_HASH_BUCKET Bucket;

    //
    // Insert into main list (at tail for LRU - head is oldest)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    InsertTailList(&g_PasState.MappingList, &Record->ListEntry);
    InterlockedIncrement(&g_PasState.MappingCount);

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    BucketIndex = PaspHashFileId(Record->FileId, Record->VolumeSerial);
    Bucket = &g_PasState.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    InsertTailList(&Bucket->List, &Record->HashEntry);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();
}


/*++
Routine Description:
    Computes hash bucket index for a file.

Arguments:
    FileId - File ID.
    VolumeSerial - Volume serial number.

Return Value:
    Hash bucket index (0 to PAS_HASH_BUCKET_COUNT-1).
--*/
static ULONG
PaspHashFileId(
    _In_ UINT64 FileId,
    _In_ ULONG VolumeSerial
    )
{
    ULONG Hash;

    Hash = (ULONG)(FileId ^ (FileId >> 32));
    Hash ^= VolumeSerial;
    Hash = Hash * 0x85EBCA6B;
    Hash ^= Hash >> 13;

    //
    // Use mask instead of modulo (faster, works because bucket count is power of 2)
    //
    return Hash & PAS_HASH_BUCKET_MASK;
}

// ============================================================================
// CLASSIFICATION AND ANALYSIS
// ============================================================================

/*++
Routine Description:
    Classifies a section mapping based on protection and attributes.

Arguments:
    Data - Callback data.
    FltObjects - Filter objects.
    PageProtection - Requested page protection.

Return Value:
    Classification flags.
--*/
static ULONG
PaspClassifyMapping(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ ULONG PageProtection
    )
{
    ULONG Flags = 0;

    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);

    //
    // Check for executable protection
    //
    if (PageProtection & PAS_EXECUTE_PROTECTION_MASK) {
        Flags |= PAS_MAP_FLAG_EXECUTABLE;
    }

    //
    // Check for writable + executable (highly suspicious)
    //
    if ((PageProtection & PAGE_EXECUTE_READWRITE) ||
        (PageProtection & PAGE_EXECUTE_WRITECOPY)) {
        Flags |= PAS_MAP_FLAG_WRITABLE;
    }

    return Flags;
}


/*++
Routine Description:
    Calculates suspicion score based on mapping flags and process context.

Arguments:
    Record - Mapping record.
    ProcessContext - Process context (optional).

Return Value:
    Suspicion score (0-100).
--*/
static ULONG
PaspCalculateSuspicionScore(
    _In_ PPAS_MAPPING_RECORD Record,
    _In_opt_ PPAS_PROCESS_CONTEXT ProcessContext
    )
{
    ULONG Score = 0;

    //
    // Writable + Executable is highly suspicious
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        Score += 25;
    }

    //
    // Suspicious path
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
        Score += 20;
    }

    //
    // Temp location
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION) {
        Score += 15;
    }

    //
    // Alternate Data Stream
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_ADS) {
        Score += 30;
    }

    //
    // Hollowing suspect
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_HOLLOWING_SUSPECT) {
        Score += 35;
    }

    //
    // Reflective loading suspect
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_REFLECTIVE_SUSPECT) {
        Score += 40;
    }

    //
    // Early process (newly created)
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_EARLY_PROCESS) {
        Score += 10;
    }

    //
    // Process behavioral indicators
    //
    if (ProcessContext != NULL) {
        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_RAPID_MAPPING) {
            Score += 15;
        }

        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_HOLLOWING) {
            Score += 20;
        }

        if (ProcessContext->BehaviorFlags & PAS_BEHAVIOR_REFLECTIVE) {
            Score += 25;
        }
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}


/*++
Routine Description:
    Checks if a file path matches known suspicious patterns.
    Uses safe bounded comparison (no null-termination assumption).

Arguments:
    FilePath - File path to check.

Return Value:
    TRUE if path is suspicious.
--*/
static BOOLEAN
PaspIsSuspiciousPath(
    _In_ PCUNICODE_STRING FilePath
    )
{
    ULONG i;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < PAS_SUSPICIOUS_PATH_COUNT; i++) {
        if (PaspContainsSubstringW(
                FilePath,
                g_SuspiciousPaths[i].Pattern,
                g_SuspiciousPaths[i].LengthInBytes)) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// BEHAVIORAL DETECTION
// ============================================================================

/*++
Routine Description:
    Updates process mapping metrics for anomaly detection.

Arguments:
    ProcessContext - Process context to update.
    Record - Current mapping record.
--*/
static VOID
PaspUpdateProcessMetrics(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeDiff;

    KeQuerySystemTime(&CurrentTime);

    //
    // Reset time window if expired
    //
    TimeDiff.QuadPart = CurrentTime.QuadPart - ProcessContext->WindowStartTime.QuadPart;
    if (TimeDiff.QuadPart > PAS_TIME_WINDOW_100NS) {
        InterlockedExchange(&ProcessContext->RecentMappings, 0);
        InterlockedExchange(&ProcessContext->RecentExecutables, 0);
        ProcessContext->WindowStartTime = CurrentTime;

        //
        // Clear early process flag after threshold
        //
        if (ProcessContext->IsEarlyProcess) {
            LONGLONG AgeTicks = CurrentTime.QuadPart - ProcessContext->ProcessCreateTime.QuadPart;
            LONGLONG ThresholdTicks = (LONGLONG)g_PasState.Config.HollowingEarlyProcessWindowMs * 10000;
            if (AgeTicks > ThresholdTicks) {
                ProcessContext->IsEarlyProcess = FALSE;
            }
        }
    }

    //
    // Update counters
    //
    InterlockedIncrement64((PLONG64)&ProcessContext->TotalMappings);
    InterlockedIncrement(&ProcessContext->RecentMappings);

    if (Record->MappingFlags & PAS_MAP_FLAG_EXECUTABLE) {
        InterlockedIncrement64((PLONG64)&ProcessContext->ExecutableMappings);
        InterlockedIncrement(&ProcessContext->RecentExecutables);
    }

    if (Record->MappingFlags & PAS_MAP_FLAG_IMAGE) {
        InterlockedIncrement64((PLONG64)&ProcessContext->ImageMappings);
    }
}


/*++
Routine Description:
    Detects process hollowing patterns with enhanced heuristics.

    Process hollowing typically involves:
    1. Creating a process in suspended state
    2. Unmapping the original image
    3. Mapping a malicious image
    4. Resuming execution

    Detection signals:
    - Executable mapping early in process lifetime
    - Multiple image mappings in short timeframe
    - Writable + Executable mappings
    - Process has suspended threads
    - High ratio of executable mappings to total

Arguments:
    ProcessContext - Process context.
    Record - Current mapping record.

Return Value:
    TRUE if hollowing pattern detected.
--*/
static BOOLEAN
PaspDetectHollowingPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    ULONG RecentExecs;
    UINT64 ImageMappings;
    UINT64 TotalMappings;

    UNREFERENCED_PARAMETER(Record);

    RecentExecs = (ULONG)InterlockedCompareExchange(
        &ProcessContext->RecentExecutables, 0, 0);
    ImageMappings = ProcessContext->ImageMappings;
    TotalMappings = ProcessContext->TotalMappings;

    //
    // Check for multiple executable mappings in short time window
    // (configurable threshold)
    //
    if (RecentExecs > g_PasState.Config.HollowingRecentExecThreshold) {
        return TRUE;
    }

    //
    // Check for high ratio of image mappings early in process
    // This catches hollowing where the original image is replaced
    //
    if (ImageMappings > g_PasState.Config.HollowingImageMappingThreshold &&
        TotalMappings < g_PasState.Config.HollowingTotalMappingThreshold) {
        return TRUE;
    }

    //
    // Early process with writable+executable mapping is highly suspicious
    //
    if (ProcessContext->IsEarlyProcess &&
        (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE)) {
        return TRUE;
    }

    //
    // Check for suspended threads (if implemented)
    //
    if (ProcessContext->IsEarlyProcess && PaspIsProcessSuspended(ProcessContext->ProcessId)) {
        return TRUE;
    }

    return FALSE;
}


/*++
Routine Description:
    Detects DLL injection patterns.

    DLL injection typically involves:
    1. Opening target process
    2. Allocating memory in target
    3. Writing DLL path or shellcode
    4. Creating remote thread

    From section perspective:
    - Cross-process section mapping
    - Writable + Executable sections
    - Unsigned or packed binaries from network/removable

Arguments:
    ProcessContext - Process context.
    Record - Current mapping record.

Return Value:
    TRUE if injection pattern detected.
--*/
static BOOLEAN
PaspDetectInjectionPattern(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    UNREFERENCED_PARAMETER(ProcessContext);

    //
    // Cross-process mapping is suspicious
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_CROSS_PROCESS) {
        return TRUE;
    }

    //
    // Writable + Executable from network/removable is suspicious
    //
    if ((Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) &&
        (Record->MappingFlags & (PAS_MAP_FLAG_NETWORK | PAS_MAP_FLAG_REMOVABLE))) {
        return TRUE;
    }

    return FALSE;
}


/*++
Routine Description:
    Detects reflective DLL loading patterns.

    Reflective loading involves:
    1. Allocating RWX memory
    2. Copying DLL into memory
    3. Manually resolving imports
    4. Calling DllMain without LoadLibrary

    Detection signals:
    - Writable + Executable mappings
    - Non-image executable sections
    - Mapping from suspicious locations
    - Rapid executable mappings

Arguments:
    ProcessContext - Process context.
    Record - Current mapping record.

Return Value:
    TRUE if reflective loading pattern detected.
--*/
static BOOLEAN
PaspDetectReflectiveLoading(
    _In_ PPAS_PROCESS_CONTEXT ProcessContext,
    _In_ PPAS_MAPPING_RECORD Record
    )
{
    ULONG RecentExecs;

    //
    // Writable + Executable is core reflective pattern
    //
    if (Record->MappingFlags & PAS_MAP_FLAG_WRITABLE) {
        //
        // Combined with suspicious path = high confidence
        //
        if (Record->MappingFlags & PAS_MAP_FLAG_SUSPICIOUS_PATH) {
            return TRUE;
        }

        //
        // Combined with temp location = medium-high confidence
        //
        if (Record->MappingFlags & PAS_MAP_FLAG_TEMP_LOCATION) {
            return TRUE;
        }

        //
        // Rapid writable+executable mappings
        //
        RecentExecs = (ULONG)InterlockedCompareExchange(
            &ProcessContext->RecentExecutables, 0, 0);

        if (RecentExecs > 2) {
            return TRUE;
        }
    }

    return FALSE;
}

// ============================================================================
// CLEANUP
// ============================================================================

/*++
Routine Description:
    DPC routine for cleanup timer.
    Queues a work item instead of directly calling cleanup (IRQL safety).

Arguments:
    Dpc - DPC object.
    DeferredContext - Not used.
    SystemArgument1 - Not used.
    SystemArgument2 - Not used.

IRQL:
    DISPATCH_LEVEL

Note:
    Push locks require IRQL < DISPATCH_LEVEL, so we cannot call
    PaspCleanupStaleRecords directly from this DPC. Instead, we
    queue a work item that runs at PASSIVE_LEVEL.
--*/
static VOID
PaspCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //
    // Check shutdown flag
    //
    if (InterlockedCompareExchange(&g_PasState.ShutdownRequested, 0, 0)) {
        return;
    }

    //
    // Queue work item if not already queued
    // Work items run at PASSIVE_LEVEL where push locks are safe
    //
    if (!InterlockedCompareExchange((PLONG)&g_PasState.CleanupWorkItemQueued, TRUE, FALSE)) {
        ExQueueWorkItem(&g_PasState.CleanupWorkItem, DelayedWorkQueue);
    }
}


/*++
Routine Description:
    Work routine for cleanup (runs at PASSIVE_LEVEL).

Arguments:
    Parameter - Not used.

IRQL:
    PASSIVE_LEVEL
--*/
static VOID
PaspCleanupWorkRoutine(
    _In_ PVOID Parameter
    )
{
    UNREFERENCED_PARAMETER(Parameter);

    //
    // Mark as no longer queued
    //
    InterlockedExchange((PLONG)&g_PasState.CleanupWorkItemQueued, FALSE);

    //
    // Check shutdown flag
    //
    if (InterlockedCompareExchange(&g_PasState.ShutdownRequested, 0, 0)) {
        return;
    }

    //
    // Perform cleanup at PASSIVE_LEVEL
    //
    PaspCleanupStaleRecords();
}


/*++
Routine Description:
    Removes stale mapping records based on timeout.

IRQL:
    PASSIVE_LEVEL (required for push locks)
--*/
static VOID
PaspCleanupStaleRecords(
    VOID
    )
{
    LARGE_INTEGER CurrentTime;
    PLIST_ENTRY Entry, Next;
    PPAS_MAPPING_RECORD Record;
    LIST_ENTRY StaleList;
    ULONG BucketIndex;
    PPAS_HASH_BUCKET Bucket;

    PAGED_CODE();

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);

    //
    // Collect stale records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.MappingLock);

    for (Entry = g_PasState.MappingList.Flink;
         Entry != &g_PasState.MappingList;
         Entry = Next) {

        Next = Entry->Flink;
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        if ((CurrentTime.QuadPart - Record->Timestamp.QuadPart) > PAS_MAPPING_TIMEOUT_100NS) {
            RemoveEntryList(&Record->ListEntry);
            InterlockedDecrement(&g_PasState.MappingCount);
            InsertTailList(&StaleList, &Record->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&g_PasState.MappingLock);
    KeLeaveCriticalRegion();

    //
    // Free stale records outside main lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Record = CONTAINING_RECORD(Entry, PAS_MAPPING_RECORD, ListEntry);

        //
        // Remove from hash table
        //
        BucketIndex = PaspHashFileId(Record->FileId, Record->VolumeSerial);
        Bucket = &g_PasState.HashTable[BucketIndex];

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Bucket->Lock);

        if (!IsListEmpty(&Record->HashEntry)) {
            RemoveEntryList(&Record->HashEntry);
            InitializeListHead(&Record->HashEntry);
        }

        ExReleasePushLockExclusive(&Bucket->Lock);
        KeLeaveCriticalRegion();

        PaspFreeRecord(Record);
    }
}

// ============================================================================
// PUBLIC STATISTICS API
// ============================================================================

/*++
Routine Description:
    Gets PreAcquireSection callback statistics.

Arguments:
    TotalCalls - Receives total callback invocations.
    ExecuteMappings - Receives executable mapping count.
    Blocked - Receives blocked count.
    HollowingDetected - Receives hollowing detection count.
    InjectionDetected - Receives injection detection count.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if not initialized.
--*/
NTSTATUS
ShadowStrikeGetPreAcquireSectionStats(
    _Out_opt_ PULONG64 TotalCalls,
    _Out_opt_ PULONG64 ExecuteMappings,
    _Out_opt_ PULONG64 Blocked,
    _Out_opt_ PULONG64 HollowingDetected,
    _Out_opt_ PULONG64 InjectionDetected
    )
{
    LONG InitState;

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        return STATUS_NOT_FOUND;
    }

    if (TotalCalls != NULL) {
        *TotalCalls = g_PasState.Stats.TotalCalls;
    }

    if (ExecuteMappings != NULL) {
        *ExecuteMappings = g_PasState.Stats.ExecuteMappings;
    }

    if (Blocked != NULL) {
        *Blocked = g_PasState.Stats.Blocked;
    }

    if (HollowingDetected != NULL) {
        *HollowingDetected = g_PasState.Stats.HollowingDetected;
    }

    if (InjectionDetected != NULL) {
        *InjectionDetected = g_PasState.Stats.InjectionDetected;
    }

    return STATUS_SUCCESS;
}


/*++
Routine Description:
    Queries section mapping context for a process.

Arguments:
    ProcessId - Process ID to query.
    IsHollowingSuspect - Receives hollowing suspect flag.
    IsInjectionSuspect - Receives injection suspect flag.
    IsReflectiveSuspect - Receives reflective loading suspect flag.
    SuspicionScore - Receives suspicion score.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if not initialized or process not found.
--*/
NTSTATUS
ShadowStrikeQueryProcessMappingContext(
    _In_ HANDLE ProcessId,
    _Out_opt_ PBOOLEAN IsHollowingSuspect,
    _Out_opt_ PBOOLEAN IsInjectionSuspect,
    _Out_opt_ PBOOLEAN IsReflectiveSuspect,
    _Out_opt_ PULONG SuspicionScore
    )
{
    PPAS_PROCESS_CONTEXT Context;
    LONG InitState;

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        return STATUS_NOT_FOUND;
    }

    Context = PaspLookupProcessContext(ProcessId, FALSE);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (IsHollowingSuspect != NULL) {
        *IsHollowingSuspect = Context->IsHollowingSuspect;
    }

    if (IsInjectionSuspect != NULL) {
        *IsInjectionSuspect = Context->IsInjectionSuspect;
    }

    if (IsReflectiveSuspect != NULL) {
        *IsReflectiveSuspect = Context->IsReflectiveSuspect;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = Context->SuspicionScore;
    }

    PaspDereferenceProcessContext(Context);

    return STATUS_SUCCESS;
}


/*++
Routine Description:
    Removes mapping context when process exits.
    Properly handles reference counting.

Arguments:
    ProcessId - Process ID.
--*/
VOID
ShadowStrikeRemoveProcessMappingContext(
    _In_ HANDLE ProcessId
    )
{
    PLIST_ENTRY Entry;
    PPAS_PROCESS_CONTEXT Context = NULL;
    LONG InitState;

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_PasState.ProcessContextLock);

    for (Entry = g_PasState.ProcessContextList.Flink;
         Entry != &g_PasState.ProcessContextList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PAS_PROCESS_CONTEXT, ListEntry);

        if (Context->ProcessId == ProcessId && !Context->Removed) {
            //
            // Mark as removed and remove from list
            //
            Context->Removed = TRUE;
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_PasState.ProcessContextCount);
            break;
        }
        Context = NULL;
    }

    ExReleasePushLockExclusive(&g_PasState.ProcessContextLock);
    KeLeaveCriticalRegion();

    //
    // Drop the list's reference (will free if no other references)
    //
    if (Context != NULL) {
        PaspDereferenceProcessContext(Context);
    }
}


/*++
Routine Description:
    Updates runtime configuration for PreAcquireSection subsystem.

Arguments:
    Config - New configuration to apply.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if not initialized.
    STATUS_INVALID_PARAMETER if Config is NULL.
--*/
NTSTATUS
ShadowStrikeUpdatePreAcquireSectionConfig(
    _In_ PPAS_CONFIGURATION Config
    )
{
    LONG InitState;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        return STATUS_NOT_FOUND;
    }

    //
    // Copy configuration (atomic isn't needed for booleans/ulongs on x86/x64)
    //
    g_PasState.Config = *Config;
    KeMemoryBarrier();

    PaspLogEvent(
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/PreAcquireSection] Configuration updated: "
        "Blocking=%d, MinBlockScore=%lu, AnomalyThreshold=%lu\n",
        g_PasState.Config.EnableBlocking,
        g_PasState.Config.MinBlockScore,
        g_PasState.Config.AnomalyThreshold
        );

    return STATUS_SUCCESS;
}


/*++
Routine Description:
    Gets current configuration for PreAcquireSection subsystem.

Arguments:
    Config - Receives current configuration.

Return Value:
    STATUS_SUCCESS on success.
    STATUS_NOT_FOUND if not initialized.
    STATUS_INVALID_PARAMETER if Config is NULL.
--*/
NTSTATUS
ShadowStrikeGetPreAcquireSectionConfig(
    _Out_ PPAS_CONFIGURATION Config
    )
{
    LONG InitState;

    if (Config == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        return STATUS_NOT_FOUND;
    }

    *Config = g_PasState.Config;

    return STATUS_SUCCESS;
}


/*++
Routine Description:
    Gets extended statistics including capacity and error metrics.

Arguments:
    Stats - Receives statistics structure.

Return Value:
    STATUS_SUCCESS on success.
--*/
NTSTATUS
ShadowStrikeGetPreAcquireSectionExtendedStats(
    _Out_ PPAS_STATISTICS Stats
    )
{
    LONG InitState;

    if (Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeMemoryBarrier();
    InitState = InterlockedCompareExchange(&g_PasState.InitState, 0, 0);

    if (InitState != PAS_STATE_INITIALIZED) {
        RtlZeroMemory(Stats, sizeof(PAS_STATISTICS));
        return STATUS_NOT_FOUND;
    }

    *Stats = g_PasState.Stats;

    return STATUS_SUCCESS;
}

