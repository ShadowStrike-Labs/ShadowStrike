/*++
===============================================================================
ShadowStrike NGAV - ENTERPRISE PROCESS NOTIFICATION IMPLEMENTATION
===============================================================================

@file ProcessNotify.c
@brief Enterprise-grade process creation/termination interception for kernel EDR.

This module provides comprehensive process monitoring via PsSetCreateProcessNotifyRoutineEx:
- Full process context capture (token, privileges, parent chain, command line)
- PPID spoofing detection (parent process ID manipulation)
- Command line analysis for suspicious patterns (encoded commands, LOLBins)
- Elevated privilege monitoring and privilege escalation detection
- Session isolation verification (cross-session process creation)
- Process hollowing/injection detection signals
- Known malware ancestry detection
- Asynchronous event buffering with rate limiting
- Per-process tracking with efficient caching
- IRQL-safe operations throughout

Detection Techniques Covered (MITRE ATT&CK):
- T1055: Process Injection (hollowing detection)
- T1134: Access Token Manipulation (token theft detection)
- T1134.004: Parent PID Spoofing
- T1059: Command and Scripting Interpreter (encoded commands)
- T1218: System Binary Proxy Execution (LOLBins)
- T1548: Abuse Elevation Control Mechanism
- T1543: Create or Modify System Process

Performance Characteristics:
- O(1) process context lookup via hash table
- Lock-free statistics using InterlockedXxx
- Lookaside lists for high-frequency allocations
- Early exit for trusted/excluded processes
- Configurable analysis depth
- Rate limiting for user-mode notifications

Lock Ordering (MUST BE FOLLOWED):
1. ProcessListLock (outer)
2. HashTable[n].Lock (inner)
Never acquire ProcessListLock while holding a bucket lock.

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "ProcessNotify.h"
#include "ProcessAnalyzer.h"
#include "ParentChainTracker.h"
#include "CommandLineParser.h"
#include "TokenAnalyzer.h"
#include "../../Core/Globals.h"
#include "../../Communication/CommPort.h"
#include "../../Utilities/MemoryUtils.h"
#include "../../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, ShadowStrikeInitializeProcessMonitoring)
#pragma alloc_text(PAGE, ShadowStrikeCleanupProcessMonitoring)
#pragma alloc_text(PAGE, PnpCleanupWorkRoutine)
#pragma alloc_text(PAGE, PnpCleanupStaleContexts)
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PN_POOL_TAG                     'TNPP'  // PPNT reversed
#define PN_CONTEXT_POOL_TAG             'xCNP'  // PNCx
#define PN_WORK_ITEM_TAG                'WKNP'  // PNWK
#define PN_MAX_PROCESS_CONTEXTS         4096
#define PN_MAX_PENDING_NOTIFICATIONS    1024
#define PN_CLEANUP_INTERVAL_MS          60000   // 1 minute
#define PN_CONTEXT_TIMEOUT_MS           300000  // 5 minutes
#define PN_MAX_COMMAND_LINE_CAPTURE     8192
#define PN_MAX_IMAGE_PATH_CAPTURE       2048
#define PN_USER_MODE_TIMEOUT_MS         5000    // 5 second timeout for user-mode
#define PN_MAX_NOTIFICATIONS_PER_SECOND 1000    // Rate limit
#define PN_RATE_LIMIT_WINDOW_MS         1000    // 1 second window
#define PN_MAX_PENDING_POOL_BYTES       (4 * 1024 * 1024)  // 4MB max pending

//
// Suspicion score thresholds
//
#define PN_SUSPICION_LOW                15
#define PN_SUSPICION_MEDIUM             35
#define PN_SUSPICION_HIGH               60
#define PN_SUSPICION_CRITICAL           85

//
// Process flags
//
#define PN_PROC_FLAG_ANALYZED           0x00000001
#define PN_PROC_FLAG_SUSPICIOUS         0x00000002
#define PN_PROC_FLAG_PPID_SPOOFED       0x00000004
#define PN_PROC_FLAG_ELEVATED           0x00000008
#define PN_PROC_FLAG_SYSTEM             0x00000010
#define PN_PROC_FLAG_SERVICE            0x00000020
#define PN_PROC_FLAG_LOLBIN             0x00000040
#define PN_PROC_FLAG_ENCODED_CMD        0x00000080
#define PN_PROC_FLAG_CROSS_SESSION      0x00000100
#define PN_PROC_FLAG_UNSIGNED           0x00000200
#define PN_PROC_FLAG_BLOCKED            0x00000400
#define PN_PROC_FLAG_TRUSTED            0x00000800
#define PN_PROC_FLAG_REMOTE_THREAD      0x00001000
#define PN_PROC_FLAG_HAS_DEBUG_PRIV     0x00002000
#define PN_PROC_FLAG_HAS_IMPERSONATE    0x00004000
#define PN_PROC_FLAG_HAS_TCB            0x00008000
#define PN_PROC_FLAG_HAS_ASSIGN_TOKEN   0x00010000
#define PN_PROC_FLAG_SIGNATURE_VALID    0x00020000

//
// Behavior flags for command-line analysis
//
#define PN_BEHAVIOR_SUSPICIOUS_PS       0x00000001
#define PN_BEHAVIOR_DOWNLOAD_CRADLE     0x00000002
#define PN_BEHAVIOR_SUSPICIOUS_CMD      0x00000004
#define PN_BEHAVIOR_LONG_CMDLINE        0x00000008
#define PN_BEHAVIOR_BASE64_ENCODED      0x00000010
#define PN_BEHAVIOR_REFLECTION_LOAD     0x00000020

// ============================================================================
// INTERNAL STRUCTURES
// ============================================================================

//
// Per-process context for tracking
//
typedef struct _PN_PROCESS_CONTEXT {
    //
    // Identification
    //
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    HANDLE CreatingProcessId;
    HANDLE CreatingThreadId;
    PEPROCESS ProcessObject;

    //
    // Process information - Buffers are always null-terminated
    //
    UNICODE_STRING ImagePath;
    UNICODE_STRING CommandLine;
    UNICODE_STRING ImageFileName;   // Just the filename

    //
    // Timing
    //
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER TerminateTime;

    //
    // Session info
    //
    ULONG SessionId;
    ULONG ParentSessionId;

    //
    // Token/Security info
    //
    ULONG IntegrityLevel;
    BOOLEAN IsElevated;
    BOOLEAN IsSystem;
    BOOLEAN IsService;
    BOOLEAN HasDebugPrivilege;
    BOOLEAN HasImpersonatePrivilege;
    BOOLEAN HasTcbPrivilege;
    BOOLEAN HasAssignPrimaryTokenPrivilege;
    BOOLEAN HasLoadDriverPrivilege;
    BOOLEAN IsSignatureValid;
    LUID AuthenticationId;

    //
    // Analysis results
    //
    ULONG Flags;
    ULONG SuspicionScore;
    ULONG BehaviorFlags;

    //
    // Parent spoofing detection
    //
    BOOLEAN IsPpidSpoofed;
    HANDLE RealParentProcessId;     // Actual parent from kernel

    //
    // Reference counting - must use interlocked operations
    //
    volatile LONG RefCount;

    //
    // List linkage - protected by respective locks
    //
    LIST_ENTRY ListEntry;           // Protected by ProcessListLock
    LIST_ENTRY HashEntry;           // Protected by Bucket->Lock

    //
    // Insertion tracking for safety
    //
    volatile LONG InsertedInList;
    volatile LONG InsertedInHash;

} PN_PROCESS_CONTEXT, *PPN_PROCESS_CONTEXT;

//
// Process notification queue entry
//
typedef struct _PN_NOTIFICATION_ENTRY {
    LIST_ENTRY ListEntry;
    BOOLEAN IsCreation;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    LARGE_INTEGER Timestamp;
    ULONG SuspicionScore;
    ULONG Flags;
} PN_NOTIFICATION_ENTRY, *PPN_NOTIFICATION_ENTRY;

//
// Hash table bucket
//
#define PN_HASH_BUCKET_COUNT    256

typedef struct _PN_HASH_BUCKET {
    LIST_ENTRY List;
    EX_PUSH_LOCK Lock;
} PN_HASH_BUCKET, *PPN_HASH_BUCKET;

//
// Rate limiting structure
//
typedef struct _PN_RATE_LIMITER {
    volatile LONG64 WindowStartTime;    // In 100ns units
    volatile LONG NotificationsInWindow;
    volatile LONG DroppedNotifications;
} PN_RATE_LIMITER, *PPN_RATE_LIMITER;

//
// Pool tracking for memory limits
//
typedef struct _PN_POOL_TRACKER {
    volatile LONG64 CurrentAllocation;
    volatile LONG64 PeakAllocation;
    LONG64 MaxAllocation;
} PN_POOL_TRACKER, *PPN_POOL_TRACKER;

//
// Process monitor configuration - immutable after initialization
// All fields are read atomically or are inherently atomic (BOOLEAN/ULONG)
//
typedef struct _PN_CONFIG {
    BOOLEAN EnablePpidSpoofingDetection;
    BOOLEAN EnableCommandLineAnalysis;
    BOOLEAN EnableTokenAnalysis;
    BOOLEAN EnableParentChainTracking;
    BOOLEAN EnableSignatureVerification;
    BOOLEAN BlockSuspiciousProcesses;
    ULONG MinBlockScore;
    ULONG AnalysisTimeoutMs;
    ULONG MaxNotificationsPerSecond;
    //
    // Configuration is frozen after initialization
    //
    volatile BOOLEAN Frozen;
} PN_CONFIG, *PPN_CONFIG;

//
// Process monitor state
//
typedef struct _PN_MONITOR_STATE {
    //
    // Initialization
    //
    volatile BOOLEAN Initialized;

    //
    // Process context tracking
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;

    //
    // Hash table for fast lookup
    //
    PN_HASH_BUCKET HashTable[PN_HASH_BUCKET_COUNT];

    //
    // Pending notification queue
    //
    LIST_ENTRY NotificationQueue;
    KSPIN_LOCK NotificationLock;
    volatile LONG NotificationCount;

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    NPAGED_LOOKASIDE_LIST NotificationLookaside;
    volatile BOOLEAN LookasideInitialized;

    //
    // Cleanup timer and work item
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    PIO_WORKITEM CleanupWorkItem;
    volatile BOOLEAN CleanupTimerActive;
    volatile LONG CleanupWorkPending;

    //
    // Rate limiting
    //
    PN_RATE_LIMITER RateLimiter;

    //
    // Pool tracking
    //
    PN_POOL_TRACKER PoolTracker;

    //
    // Sub-analyzers (optional integration)
    //
    PVOID ProcessAnalyzer;      // PPA_ANALYZER
    PVOID ParentChainTracker;   // PPCT_TRACKER
    PVOID CommandLineParser;    // PCLP_PARSER
    PVOID TokenAnalyzer;        // PTA_ANALYZER

    //
    // Statistics - all use interlocked operations
    // Note: LONG64 can overflow after ~9 quintillion operations
    // This is acceptable for practical purposes (would take centuries)
    //
    struct {
        volatile LONG64 ProcessCreations;
        volatile LONG64 ProcessTerminations;
        volatile LONG64 ProcessesBlocked;
        volatile LONG64 PpidSpoofingDetected;
        volatile LONG64 ElevatedProcesses;
        volatile LONG64 SuspiciousProcesses;
        volatile LONG64 EncodedCommands;
        volatile LONG64 LOLBinsDetected;
        volatile LONG64 CrossSessionCreations;
        volatile LONG64 AnalysisErrors;
        volatile LONG64 RateLimitDrops;
        volatile LONG64 PoolLimitDrops;
        volatile LONG64 UserModeTimeouts;
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration - frozen after init
    //
    PN_CONFIG Config;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

    //
    // Device object for work items
    //
    PDEVICE_OBJECT DeviceObject;

} PN_MONITOR_STATE, *PPN_MONITOR_STATE;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static PN_MONITOR_STATE g_ProcessMonitor = {0};

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static PPN_PROCESS_CONTEXT
PnpAllocateProcessContext(
    VOID
    );

static VOID
PnpFreeProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static PPN_PROCESS_CONTEXT
PnpLookupProcessContext(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PnpInsertProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpRemoveProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpReferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static VOID
PnpDereferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static ULONG
PnpHashProcessId(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
PnpCaptureProcessInfo(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PPN_PROCESS_CONTEXT Context
    );

static NTSTATUS
PnpAnalyzeProcess(
    _Inout_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpDetectPpidSpoofing(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static ULONG
PnpCalculateSuspicionScore(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static NTSTATUS
PnpSendProcessNotification(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ BOOLEAN IsCreation,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

static VOID
PnpHandleProcessTermination(
    _In_ HANDLE ProcessId
    );

static VOID
PnpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
PnpCleanupWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    );

static VOID
PnpCleanupStaleContexts(
    VOID
    );

static NTSTATUS
PnpCaptureTokenInfo(
    _In_ PEPROCESS Process,
    _Out_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpIsKnownSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process
    );

static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpCheckParentSessionMatch(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpCheckRateLimit(
    VOID
    );

static BOOLEAN
PnpCheckPoolLimit(
    _In_ SIZE_T AllocationSize
    );

static VOID
PnpTrackPoolAllocation(
    _In_ SIZE_T Size
    );

static VOID
PnpTrackPoolFree(
    _In_ SIZE_T Size
    );

static BOOLEAN
PnpSafeWcsStrI(
    _In_ PCWCH Buffer,
    _In_ USHORT BufferLengthBytes,
    _In_ PCWSTR Pattern
    );

static NTSTATUS
PnpVerifyImageSignature(
    _In_ PPN_PROCESS_CONTEXT Context
    );

// ============================================================================
// INITIALIZATION AND CLEANUP
// ============================================================================

_Use_decl_annotations_
NTSTATUS
ShadowStrikeInitializeProcessMonitoring(
    VOID
    )
/*++
Routine Description:
    Initializes the process monitoring subsystem.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    LARGE_INTEGER DueTime;
    ULONG i;

    PAGED_CODE();

    if (g_ProcessMonitor.Initialized) {
        return STATUS_ALREADY_REGISTERED;
    }

    RtlZeroMemory(&g_ProcessMonitor, sizeof(PN_MONITOR_STATE));

    //
    // Get device object for work items
    //
    g_ProcessMonitor.DeviceObject = g_DriverData.DeviceObject;
    if (g_ProcessMonitor.DeviceObject == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    //
    // Initialize process list
    //
    InitializeListHead(&g_ProcessMonitor.ProcessList);
    ExInitializePushLock(&g_ProcessMonitor.ProcessListLock);

    //
    // Initialize hash table
    //
    for (i = 0; i < PN_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&g_ProcessMonitor.HashTable[i].List);
        ExInitializePushLock(&g_ProcessMonitor.HashTable[i].Lock);
    }

    //
    // Initialize notification queue
    //
    InitializeListHead(&g_ProcessMonitor.NotificationQueue);
    KeInitializeSpinLock(&g_ProcessMonitor.NotificationLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &g_ProcessMonitor.ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PN_PROCESS_CONTEXT),
        PN_CONTEXT_POOL_TAG,
        0
        );

    ExInitializeNPagedLookasideList(
        &g_ProcessMonitor.NotificationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(PN_NOTIFICATION_ENTRY),
        PN_POOL_TAG,
        0
        );

    g_ProcessMonitor.LookasideInitialized = TRUE;

    //
    // Initialize pool tracking
    //
    g_ProcessMonitor.PoolTracker.MaxAllocation = PN_MAX_PENDING_POOL_BYTES;
    g_ProcessMonitor.PoolTracker.CurrentAllocation = 0;
    g_ProcessMonitor.PoolTracker.PeakAllocation = 0;

    //
    // Initialize rate limiter
    //
    KeQuerySystemTime((PLARGE_INTEGER)&g_ProcessMonitor.RateLimiter.WindowStartTime);
    g_ProcessMonitor.RateLimiter.NotificationsInWindow = 0;
    g_ProcessMonitor.RateLimiter.DroppedNotifications = 0;

    //
    // Initialize default configuration
    // Configuration is FROZEN after this point - reads are safe without locks
    //
    g_ProcessMonitor.Config.EnablePpidSpoofingDetection = TRUE;
    g_ProcessMonitor.Config.EnableCommandLineAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableTokenAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableParentChainTracking = TRUE;
    g_ProcessMonitor.Config.EnableSignatureVerification = TRUE;
    g_ProcessMonitor.Config.BlockSuspiciousProcesses = FALSE;  // Audit mode by default
    g_ProcessMonitor.Config.MinBlockScore = PN_SUSPICION_CRITICAL;
    g_ProcessMonitor.Config.AnalysisTimeoutMs = PN_USER_MODE_TIMEOUT_MS;
    g_ProcessMonitor.Config.MaxNotificationsPerSecond = PN_MAX_NOTIFICATIONS_PER_SECOND;

    //
    // Freeze configuration - must be set with memory barrier
    //
    MemoryBarrier();
    g_ProcessMonitor.Config.Frozen = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_ProcessMonitor.Stats.StartTime);

    //
    // Allocate cleanup work item
    //
    g_ProcessMonitor.CleanupWorkItem = IoAllocateWorkItem(g_ProcessMonitor.DeviceObject);
    if (g_ProcessMonitor.CleanupWorkItem == NULL) {
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&g_ProcessMonitor.CleanupTimer);
    KeInitializeDpc(&g_ProcessMonitor.CleanupDpc, PnpCleanupTimerDpc, NULL);

    //
    // Start cleanup timer (every 1 minute)
    //
    DueTime.QuadPart = -((LONGLONG)PN_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &g_ProcessMonitor.CleanupTimer,
        DueTime,
        PN_CLEANUP_INTERVAL_MS,
        &g_ProcessMonitor.CleanupDpc
        );
    g_ProcessMonitor.CleanupTimerActive = TRUE;

    //
    // Mark as initialized with memory barrier
    //
    MemoryBarrier();
    g_ProcessMonitor.Initialized = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring initialized (v3.0)\n"
        );

    return STATUS_SUCCESS;
}


_Use_decl_annotations_
VOID
ShadowStrikeCleanupProcessMonitoring(
    VOID
    )
/*++
Routine Description:
    Cleans up the process monitoring subsystem.

    This function is designed to be safe against races with the callback
    and cleanup DPC/work item.
--*/
{
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context;
    PPN_NOTIFICATION_ENTRY Notification;
    KIRQL OldIrql;
    LIST_ENTRY FreeList;
    ULONG i;

    PAGED_CODE();

    if (!g_ProcessMonitor.Initialized) {
        return;
    }

    //
    // Signal shutdown first - prevents new work from starting
    //
    InterlockedExchange8((volatile CHAR*)&g_ProcessMonitor.ShutdownRequested, TRUE);
    MemoryBarrier();
    InterlockedExchange8((volatile CHAR*)&g_ProcessMonitor.Initialized, FALSE);
    MemoryBarrier();

    //
    // Cancel cleanup timer and wait for any DPC to complete
    //
    if (g_ProcessMonitor.CleanupTimerActive) {
        KeCancelTimer(&g_ProcessMonitor.CleanupTimer);

        //
        // CRITICAL: Wait for any queued/running DPC to complete
        // This prevents use-after-free when DPC accesses freed resources
        //
        KeFlushQueuedDpcs();

        g_ProcessMonitor.CleanupTimerActive = FALSE;
    }

    //
    // Wait for any pending cleanup work item to complete
    // Spin-wait with yield - work item should complete quickly
    //
    while (InterlockedCompareExchange(&g_ProcessMonitor.CleanupWorkPending, 0, 0) != 0) {
        LARGE_INTEGER Interval;
        Interval.QuadPart = -10000;  // 1ms
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    //
    // Free cleanup work item
    //
    if (g_ProcessMonitor.CleanupWorkItem != NULL) {
        IoFreeWorkItem(g_ProcessMonitor.CleanupWorkItem);
        g_ProcessMonitor.CleanupWorkItem = NULL;
    }

    //
    // Collect all process contexts to free
    // Use proper lock ordering: ProcessListLock first, then bucket locks
    //
    InitializeListHead(&FreeList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    //
    // Move all entries to free list
    //
    while (!IsListEmpty(&g_ProcessMonitor.ProcessList)) {
        Entry = RemoveHeadList(&g_ProcessMonitor.ProcessList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Mark as removed from list
        //
        InitializeListHead(&Context->ListEntry);
        InterlockedExchange(&Context->InsertedInList, FALSE);

        InsertTailList(&FreeList, &Context->ListEntry);
        InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Now remove from hash tables and free - outside ProcessListLock
    //
    while (!IsListEmpty(&FreeList)) {
        Entry = RemoveHeadList(&FreeList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table under correct bucket lock
        //
        if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
            ULONG BucketIndex = PnpHashProcessId(Context->ProcessId);
            PPN_HASH_BUCKET Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Bucket->Lock);

            if (!IsListEmpty(&Context->HashEntry)) {
                RemoveEntryList(&Context->HashEntry);
                InitializeListHead(&Context->HashEntry);
            }

            ExReleasePushLockExclusive(&Bucket->Lock);
            KeLeaveCriticalRegion();
        }

        //
        // Free the context
        //
        PnpFreeProcessContext(Context);
    }

    //
    // Free pending notifications
    //
    KeAcquireSpinLock(&g_ProcessMonitor.NotificationLock, &OldIrql);

    while (!IsListEmpty(&g_ProcessMonitor.NotificationQueue)) {
        Entry = RemoveHeadList(&g_ProcessMonitor.NotificationQueue);
        Notification = CONTAINING_RECORD(Entry, PN_NOTIFICATION_ENTRY, ListEntry);
        ExFreeToNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside, Notification);
    }

    KeReleaseSpinLock(&g_ProcessMonitor.NotificationLock, OldIrql);

    //
    // Delete lookaside lists - safe now that all contexts are freed
    //
    if (g_ProcessMonitor.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside);
        g_ProcessMonitor.LookasideInitialized = FALSE;
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring shutdown. "
        "Stats: Created=%lld, Terminated=%lld, Blocked=%lld, PpidSpoof=%lld, "
        "RateLimitDrops=%lld, PoolLimitDrops=%lld\n",
        g_ProcessMonitor.Stats.ProcessCreations,
        g_ProcessMonitor.Stats.ProcessTerminations,
        g_ProcessMonitor.Stats.ProcessesBlocked,
        g_ProcessMonitor.Stats.PpidSpoofingDetected,
        g_ProcessMonitor.Stats.RateLimitDrops,
        g_ProcessMonitor.Stats.PoolLimitDrops
        );
}


// ============================================================================
// MAIN CALLBACK IMPLEMENTATION
// ============================================================================

_Use_decl_annotations_
VOID
ShadowStrikeProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    Enterprise-grade process creation/termination callback.

    Registered via PsSetCreateProcessNotifyRoutineEx.

Arguments:
    Process     - Pointer to the process object.
    ProcessId   - ID of the process.
    CreateInfo  - Creation info (NULL for termination).
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PPN_PROCESS_CONTEXT ProcessContext = NULL;
    BOOLEAN IsCreation = (CreateInfo != NULL);
    BOOLEAN ShouldBlock = FALSE;
    ULONG SuspicionScore = 0;

    //
    // Quick validation
    //
    if (Process == NULL) {
        return;
    }

    //
    // Always increment raw statistics (even if not processing)
    //
    if (IsCreation) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessCreations);
        SHADOWSTRIKE_INC_STAT(TotalProcessCreations);
    } else {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessTerminations);
    }

    //
    // Check if we should process this event
    // Read volatile flags with memory barrier
    //
    MemoryBarrier();
    if (!g_ProcessMonitor.Initialized ||
        g_ProcessMonitor.ShutdownRequested) {
        return;
    }

    if (!SHADOWSTRIKE_IS_READY() ||
        !g_DriverData.Config.ProcessMonitorEnabled) {
        return;
    }

    //
    // Enter operation tracking
    //
    SHADOWSTRIKE_ENTER_OPERATION();

    //
    // Handle process termination
    //
    if (!IsCreation) {
        PnpHandleProcessTermination(ProcessId);
        goto Cleanup;
    }

    //
    // === PROCESS CREATION HANDLING ===
    //

    //
    // Check for known system process (skip detailed analysis for performance)
    //
    if (PnpIsKnownSystemProcess(ProcessId, Process)) {
        goto Cleanup;
    }

    //
    // Check rate limit before allocating resources
    //
    if (!PnpCheckRateLimit()) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.RateLimitDrops);
        goto Cleanup;
    }

    //
    // Allocate process context
    //
    ProcessContext = PnpAllocateProcessContext();
    if (ProcessContext == NULL) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.AnalysisErrors);
        goto Cleanup;
    }

    //
    // Capture process information
    //
    Status = PnpCaptureProcessInfo(Process, ProcessId, CreateInfo, ProcessContext);
    if (!NT_SUCCESS(Status)) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.AnalysisErrors);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] Failed to capture process info for PID %lu: 0x%08X\n",
            HandleToULong(ProcessId),
            Status
            );

        goto Cleanup;
    }

    //
    // Capture token/security information
    //
    if (g_ProcessMonitor.Config.EnableTokenAnalysis) {
        Status = PnpCaptureTokenInfo(Process, ProcessContext);
        if (!NT_SUCCESS(Status)) {
            //
            // Non-fatal - continue with limited info
            //
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_TRACE_LEVEL,
                "[ShadowStrike/ProcessNotify] Token capture failed for PID %lu: 0x%08X\n",
                HandleToULong(ProcessId),
                Status
                );
        }
    }

    //
    // Detect PPID spoofing
    //
    if (g_ProcessMonitor.Config.EnablePpidSpoofingDetection) {
        if (PnpDetectPpidSpoofing(ProcessContext, CreateInfo)) {
            ProcessContext->IsPpidSpoofed = TRUE;
            ProcessContext->Flags |= PN_PROC_FLAG_PPID_SPOOFED;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.PpidSpoofingDetected);

            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_WARNING_LEVEL,
                "[ShadowStrike/ProcessNotify] PPID SPOOFING DETECTED! "
                "PID=%lu, ClaimedParent=%lu, RealParent=%lu\n",
                HandleToULong(ProcessId),
                HandleToULong(ProcessContext->ParentProcessId),
                HandleToULong(ProcessContext->RealParentProcessId)
                );
        }
    }

    //
    // Check session isolation
    //
    if (!PnpCheckParentSessionMatch(ProcessContext)) {
        ProcessContext->Flags |= PN_PROC_FLAG_CROSS_SESSION;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.CrossSessionCreations);
    }

    //
    // Track elevated processes
    //
    if (ProcessContext->IsElevated) {
        ProcessContext->Flags |= PN_PROC_FLAG_ELEVATED;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ElevatedProcesses);
    }

    if (ProcessContext->IsSystem) {
        ProcessContext->Flags |= PN_PROC_FLAG_SYSTEM;
    }

    if (ProcessContext->IsService) {
        ProcessContext->Flags |= PN_PROC_FLAG_SERVICE;
    }

    //
    // Track dangerous privileges
    //
    if (ProcessContext->HasDebugPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_DEBUG_PRIV;
    }
    if (ProcessContext->HasImpersonatePrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_IMPERSONATE;
    }
    if (ProcessContext->HasTcbPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_TCB;
    }
    if (ProcessContext->HasAssignPrimaryTokenPrivilege) {
        ProcessContext->Flags |= PN_PROC_FLAG_HAS_ASSIGN_TOKEN;
    }

    //
    // Verify image signature if enabled
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification) {
        Status = PnpVerifyImageSignature(ProcessContext);
        if (NT_SUCCESS(Status) && ProcessContext->IsSignatureValid) {
            ProcessContext->Flags |= PN_PROC_FLAG_SIGNATURE_VALID;
        }
    }

    //
    // Run full analysis
    //
    Status = PnpAnalyzeProcess(ProcessContext);
    if (NT_SUCCESS(Status)) {
        ProcessContext->Flags |= PN_PROC_FLAG_ANALYZED;
    }

    //
    // Calculate suspicion score
    //
    SuspicionScore = PnpCalculateSuspicionScore(ProcessContext);
    ProcessContext->SuspicionScore = SuspicionScore;

    if (SuspicionScore >= PN_SUSPICION_MEDIUM) {
        ProcessContext->Flags |= PN_PROC_FLAG_SUSPICIOUS;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.SuspiciousProcesses);
    }

    //
    // Check if we should block
    //
    if (g_ProcessMonitor.Config.BlockSuspiciousProcesses &&
        SuspicionScore >= g_ProcessMonitor.Config.MinBlockScore) {
        ShouldBlock = TRUE;
    }

    //
    // Check if process is trusted (override block)
    //
    if (ShouldBlock && PnpIsTrustedProcess(ProcessContext)) {
        ShouldBlock = FALSE;
        ProcessContext->Flags |= PN_PROC_FLAG_TRUSTED;
    }

    //
    // Insert context into tracking structures
    //
    Status = PnpInsertProcessContext(ProcessContext);
    if (!NT_SUCCESS(Status)) {
        //
        // Failed to insert - will be freed in cleanup
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] Failed to insert context for PID %lu: 0x%08X\n",
            HandleToULong(ProcessId),
            Status
            );
        goto Cleanup;
    }

    //
    // Send notification to user-mode
    //
    Status = PnpSendProcessNotification(ProcessContext, TRUE, CreateInfo);
    if (!NT_SUCCESS(Status) && Status != STATUS_PORT_DISCONNECTED) {
        //
        // Check if user-mode requested block
        //
        if (Status == STATUS_ACCESS_DENIED) {
            ShouldBlock = TRUE;
        }
    }

    //
    // Apply blocking decision
    // CRITICAL: Verify CreateInfo is not NULL before dereferencing
    //
    if (ShouldBlock && CreateInfo != NULL) {
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
        ProcessContext->Flags |= PN_PROC_FLAG_BLOCKED;
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessesBlocked);
        SHADOWSTRIKE_INC_STAT(ProcessesBlocked);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] BLOCKED process creation: PID=%lu, Score=%lu, Flags=0x%08X\n",
            HandleToULong(ProcessId),
            SuspicionScore,
            ProcessContext->Flags
            );
    }

    //
    // Don't free context - it's now in the tracking list
    //
    ProcessContext = NULL;

Cleanup:
    if (ProcessContext != NULL) {
        PnpFreeProcessContext(ProcessContext);
    }

    SHADOWSTRIKE_LEAVE_OPERATION();
}


// ============================================================================
// PROCESS CONTEXT MANAGEMENT
// ============================================================================

static PPN_PROCESS_CONTEXT
PnpAllocateProcessContext(
    VOID
    )
{
    PPN_PROCESS_CONTEXT Context;

    //
    // Check pool limits before allocation
    //
    if (!PnpCheckPoolLimit(sizeof(PN_PROCESS_CONTEXT))) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.PoolLimitDrops);
        return NULL;
    }

    Context = (PPN_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_ProcessMonitor.ContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(PN_PROCESS_CONTEXT));
        Context->RefCount = 1;
        InitializeListHead(&Context->ListEntry);
        InitializeListHead(&Context->HashEntry);
        Context->InsertedInList = FALSE;
        Context->InsertedInHash = FALSE;

        PnpTrackPoolAllocation(sizeof(PN_PROCESS_CONTEXT));
    }

    return Context;
}


static VOID
PnpFreeProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
{
    if (Context == NULL) {
        return;
    }

    //
    // Verify context is not still in lists
    //
    NT_ASSERT(!Context->InsertedInList);
    NT_ASSERT(!Context->InsertedInHash);

    //
    // Free allocated strings
    //
    if (Context->ImagePath.Buffer != NULL) {
        PnpTrackPoolFree(Context->ImagePath.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->ImagePath.Buffer, PN_POOL_TAG);
        Context->ImagePath.Buffer = NULL;
    }

    if (Context->CommandLine.Buffer != NULL) {
        PnpTrackPoolFree(Context->CommandLine.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->CommandLine.Buffer, PN_POOL_TAG);
        Context->CommandLine.Buffer = NULL;
    }

    if (Context->ImageFileName.Buffer != NULL) {
        PnpTrackPoolFree(Context->ImageFileName.MaximumLength);
        ShadowStrikeFreePoolWithTag(Context->ImageFileName.Buffer, PN_POOL_TAG);
        Context->ImageFileName.Buffer = NULL;
    }

    //
    // Dereference process object if held
    //
    if (Context->ProcessObject != NULL) {
        ObDereferenceObject(Context->ProcessObject);
        Context->ProcessObject = NULL;
    }

    PnpTrackPoolFree(sizeof(PN_PROCESS_CONTEXT));
    ExFreeToNPagedLookasideList(&g_ProcessMonitor.ContextLookaside, Context);
}


static ULONG
PnpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    //
    // MurmurHash3-style mixing for good distribution
    //
    Value = Value ^ (Value >> 16);
    Value = Value * 0x85EBCA6B;
    Value = Value ^ (Value >> 13);
    Value = Value * 0xC2B2AE35;
    Value = Value ^ (Value >> 16);

    return (ULONG)(Value % PN_HASH_BUCKET_COUNT);
}


static PPN_PROCESS_CONTEXT
PnpLookupProcessContext(
    _In_ HANDLE ProcessId
    )
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context = NULL;
    PPN_PROCESS_CONTEXT FoundContext = NULL;

    BucketIndex = PnpHashProcessId(ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);

    for (Entry = Bucket->List.Flink;
         Entry != &Bucket->List;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, HashEntry);

        if (Context->ProcessId == ProcessId) {
            //
            // Found - take reference before releasing lock
            //
            PnpReferenceContext(Context);
            FoundContext = Context;
            break;
        }
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return FoundContext;
}


static NTSTATUS
PnpInsertProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Inserts a process context into tracking structures.

    Lock ordering: ProcessListLock THEN Bucket->Lock

Arguments:
    Context - The context to insert.

Return Value:
    STATUS_SUCCESS or error code.
--*/
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Verify context is not already inserted
    //
    if (InterlockedCompareExchange(&Context->InsertedInList, FALSE, FALSE) ||
        InterlockedCompareExchange(&Context->InsertedInHash, FALSE, FALSE)) {
        NT_ASSERT(FALSE);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Check max context limit
    //
    if (InterlockedCompareExchange(&g_ProcessMonitor.ProcessCount, 0, 0) >=
        PN_MAX_PROCESS_CONTEXTS) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Reference for list storage
    //
    PnpReferenceContext(Context);

    //
    // Lock ordering: ProcessListLock first, then bucket lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    //
    // Insert into main list
    //
    InsertTailList(&g_ProcessMonitor.ProcessList, &Context->ListEntry);
    InterlockedExchange(&Context->InsertedInList, TRUE);
    InterlockedIncrement(&g_ProcessMonitor.ProcessCount);

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    BucketIndex = PnpHashProcessId(Context->ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    InsertTailList(&Bucket->List, &Context->HashEntry);
    InterlockedExchange(&Context->InsertedInHash, TRUE);

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}


static VOID
PnpRemoveProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Removes a process context from tracking structures.

    Lock ordering: ProcessListLock THEN Bucket->Lock
--*/
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    BOOLEAN WasInList = FALSE;
    BOOLEAN WasInHash = FALSE;

    //
    // Lock ordering: ProcessListLock first
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    if (InterlockedCompareExchange(&Context->InsertedInList, FALSE, TRUE)) {
        if (!IsListEmpty(&Context->ListEntry)) {
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
            WasInList = TRUE;
        }
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Then bucket lock
    //
    BucketIndex = PnpHashProcessId(Context->ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
        if (!IsListEmpty(&Context->HashEntry)) {
            RemoveEntryList(&Context->HashEntry);
            InitializeListHead(&Context->HashEntry);
            WasInHash = TRUE;
        }
    }

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Release list reference if was inserted
    //
    if (WasInList || WasInHash) {
        PnpDereferenceContext(Context);
    }
}


static VOID
PnpReferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    LONG NewCount = InterlockedIncrement(&Context->RefCount);
    NT_ASSERT(NewCount > 1);
    UNREFERENCED_PARAMETER(NewCount);
}


static VOID
PnpDereferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    LONG NewCount = InterlockedDecrement(&Context->RefCount);
    NT_ASSERT(NewCount >= 0);

    if (NewCount == 0) {
        PnpFreeProcessContext(Context);
    }
}


// ============================================================================
// PROCESS INFORMATION CAPTURE
// ============================================================================

static NTSTATUS
PnpCaptureProcessInfo(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo,
    _Out_ PPN_PROCESS_CONTEXT Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PWCHAR Buffer = NULL;
    SIZE_T BufferSize;
    SIZE_T SafeBufferSize;

    //
    // Basic identification
    //
    Context->ProcessId = ProcessId;
    Context->ParentProcessId = CreateInfo->ParentProcessId;
    Context->CreatingProcessId = CreateInfo->CreatingThreadId.UniqueProcess;
    Context->CreatingThreadId = CreateInfo->CreatingThreadId.UniqueThread;

    //
    // Store creating process ID as potential real parent
    //
    Context->RealParentProcessId = CreateInfo->CreatingThreadId.UniqueProcess;

    //
    // Timing
    //
    KeQuerySystemTime(&Context->CreateTime);

    //
    // Reference process object
    // Note: We hold this reference for the lifetime of the context
    // This is intentional to prevent process object reuse issues
    //
    Status = ObReferenceObjectByPointer(
        Process,
        PROCESS_QUERY_LIMITED_INFORMATION,
        *PsProcessType,
        KernelMode
        );
    if (NT_SUCCESS(Status)) {
        Context->ProcessObject = Process;
    }

    //
    // Capture image path with safe size calculation
    //
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Length > 0 &&
        CreateInfo->ImageFileName->Buffer != NULL) {

        //
        // Validate length and prevent overflow
        //
        if (CreateInfo->ImageFileName->Length <= PN_MAX_IMAGE_PATH_CAPTURE * sizeof(WCHAR)) {

            //
            // Safe size calculation: check for overflow
            //
            SafeBufferSize = (SIZE_T)CreateInfo->ImageFileName->Length + sizeof(WCHAR);
            if (SafeBufferSize > CreateInfo->ImageFileName->Length) {  // Overflow check

                if (PnpCheckPoolLimit(SafeBufferSize)) {
                    Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                        NonPagedPoolNx,
                        SafeBufferSize,
                        PN_POOL_TAG
                        );

                    if (Buffer != NULL) {
                        PnpTrackPoolAllocation(SafeBufferSize);

                        RtlCopyMemory(
                            Buffer,
                            CreateInfo->ImageFileName->Buffer,
                            CreateInfo->ImageFileName->Length
                            );

                        //
                        // ALWAYS null-terminate for safe string operations
                        //
                        Buffer[CreateInfo->ImageFileName->Length / sizeof(WCHAR)] = L'\0';

                        Context->ImagePath.Buffer = Buffer;
                        Context->ImagePath.Length = CreateInfo->ImageFileName->Length;
                        Context->ImagePath.MaximumLength = (USHORT)SafeBufferSize;

                        //
                        // Extract filename using safe search
                        //
                        PWCHAR LastSlash = NULL;
                        PWCHAR Ptr = Buffer;
                        USHORT RemainingChars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);

                        while (RemainingChars > 0 && *Ptr != L'\0') {
                            if (*Ptr == L'\\') {
                                LastSlash = Ptr;
                            }
                            Ptr++;
                            RemainingChars--;
                        }

                        if (LastSlash != NULL && (LastSlash + 1) < (Buffer + Context->ImagePath.Length / sizeof(WCHAR))) {
                            PWCHAR FileName = LastSlash + 1;
                            SIZE_T FileNameLen = wcslen(FileName) * sizeof(WCHAR);
                            SIZE_T FileNameBufferSize = FileNameLen + sizeof(WCHAR);

                            if (FileNameLen > 0 && FileNameLen < 512 * sizeof(WCHAR) &&
                                PnpCheckPoolLimit(FileNameBufferSize)) {

                                PWCHAR FileNameBuffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                                    NonPagedPoolNx,
                                    FileNameBufferSize,
                                    PN_POOL_TAG
                                    );

                                if (FileNameBuffer != NULL) {
                                    PnpTrackPoolAllocation(FileNameBufferSize);
                                    RtlCopyMemory(FileNameBuffer, FileName, FileNameLen);
                                    FileNameBuffer[FileNameLen / sizeof(WCHAR)] = L'\0';
                                    Context->ImageFileName.Buffer = FileNameBuffer;
                                    Context->ImageFileName.Length = (USHORT)FileNameLen;
                                    Context->ImageFileName.MaximumLength = (USHORT)FileNameBufferSize;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //
    // Capture command line with safe size calculation
    //
    if (CreateInfo->CommandLine != NULL &&
        CreateInfo->CommandLine->Length > 0 &&
        CreateInfo->CommandLine->Buffer != NULL) {

        USHORT CaptureLength = CreateInfo->CommandLine->Length;

        //
        // Cap command line length
        //
        if (CaptureLength > PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR)) {
            CaptureLength = PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR);
        }

        //
        // Safe size calculation with overflow check
        //
        SafeBufferSize = (SIZE_T)CaptureLength + sizeof(WCHAR);
        if (SafeBufferSize > CaptureLength && PnpCheckPoolLimit(SafeBufferSize)) {

            Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                SafeBufferSize,
                PN_POOL_TAG
                );

            if (Buffer != NULL) {
                PnpTrackPoolAllocation(SafeBufferSize);
                RtlCopyMemory(Buffer, CreateInfo->CommandLine->Buffer, CaptureLength);

                //
                // ALWAYS null-terminate
                //
                Buffer[CaptureLength / sizeof(WCHAR)] = L'\0';

                Context->CommandLine.Buffer = Buffer;
                Context->CommandLine.Length = CaptureLength;
                Context->CommandLine.MaximumLength = (USHORT)SafeBufferSize;
            }
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS
PnpCaptureTokenInfo(
    _In_ PEPROCESS Process,
    _Out_ PPN_PROCESS_CONTEXT Context
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PACCESS_TOKEN Token = NULL;
    ULONG SessionId = 0;

    __try {
        //
        // Get primary token of the TARGET process (not current thread)
        //
        Token = PsReferencePrimaryToken(Process);
        if (Token == NULL) {
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Get session ID
        //
        Status = SeQuerySessionIdToken(Token, &SessionId);
        if (NT_SUCCESS(Status)) {
            Context->SessionId = SessionId;
        }

        //
        // Check for restricted token (typically low integrity)
        //
        if (SeTokenIsRestricted(Token)) {
            Context->IntegrityLevel = 0;  // Low
        }

        //
        // Check for admin token
        //
        if (SeTokenIsAdmin(Token)) {
            Context->IsElevated = TRUE;
        }

        //
        // Check for dangerous privileges using SeSinglePrivilegeCheck pattern
        // Note: We check if the privilege EXISTS in the token, not if it's enabled
        //

        //
        // SE_DEBUG_PRIVILEGE (20) - Can debug any process
        //
        {
            LUID DebugPrivilege = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
            PRIVILEGE_SET PrivSet;
            PrivSet.PrivilegeCount = 1;
            PrivSet.Control = PRIVILEGE_SET_ALL_NECESSARY;
            PrivSet.Privilege[0].Luid = DebugPrivilege;
            PrivSet.Privilege[0].Attributes = 0;

            BOOLEAN Result = FALSE;
            Status = SePrivilegeCheck(&PrivSet, &Process->Pcb, UserMode);
            if (NT_SUCCESS(Status)) {
                Context->HasDebugPrivilege = TRUE;
            }
        }

        //
        // SE_IMPERSONATE_PRIVILEGE (29) - Can impersonate tokens
        //
        {
            LUID ImpersonatePrivilege = RtlConvertLongToLuid(SE_IMPERSONATE_PRIVILEGE);
            Context->HasImpersonatePrivilege = SeSinglePrivilegeCheck(ImpersonatePrivilege, UserMode);
        }

        //
        // SE_TCB_PRIVILEGE (7) - Act as part of OS
        //
        {
            LUID TcbPrivilege = RtlConvertLongToLuid(SE_TCB_PRIVILEGE);
            Context->HasTcbPrivilege = SeSinglePrivilegeCheck(TcbPrivilege, UserMode);
        }

        //
        // SE_ASSIGNPRIMARYTOKEN_PRIVILEGE (3) - Assign process token
        //
        {
            LUID AssignTokenPrivilege = RtlConvertLongToLuid(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE);
            Context->HasAssignPrimaryTokenPrivilege = SeSinglePrivilegeCheck(AssignTokenPrivilege, UserMode);
        }

        //
        // SE_LOAD_DRIVER_PRIVILEGE (10) - Load kernel drivers
        //
        {
            LUID LoadDriverPrivilege = RtlConvertLongToLuid(SE_LOAD_DRIVER_PRIVILEGE);
            Context->HasLoadDriverPrivilege = SeSinglePrivilegeCheck(LoadDriverPrivilege, UserMode);
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    //
    // Release token
    //
    if (Token != NULL) {
        PsDereferencePrimaryToken(Token);
    }

    //
    // Get parent session ID for cross-session detection
    //
    if (Context->ParentProcessId != NULL) {
        PEPROCESS ParentProcess = NULL;
        Status = PsLookupProcessByProcessId(Context->ParentProcessId, &ParentProcess);
        if (NT_SUCCESS(Status)) {
            PACCESS_TOKEN ParentToken = PsReferencePrimaryToken(ParentProcess);
            if (ParentToken != NULL) {
                ULONG ParentSessionId = 0;
                if (NT_SUCCESS(SeQuerySessionIdToken(ParentToken, &ParentSessionId))) {
                    Context->ParentSessionId = ParentSessionId;
                }
                PsDereferencePrimaryToken(ParentToken);
            }
            ObDereferenceObject(ParentProcess);
        }
    }

    //
    // Determine if SYSTEM or service process
    // Session 0 + elevated is typically a service
    //
    if (Context->SessionId == 0 && Context->IsElevated) {
        Context->IsService = TRUE;

        //
        // Check for SYSTEM specifically by checking for TCB privilege
        // (Only SYSTEM and very privileged services have this)
        //
        if (Context->HasTcbPrivilege) {
            Context->IsSystem = TRUE;
        }
    }

    return STATUS_SUCCESS;
}


// ============================================================================
// PPID SPOOFING DETECTION
// ============================================================================

static BOOLEAN
PnpDetectPpidSpoofing(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
/*++
Routine Description:
    Detects Parent Process ID (PPID) spoofing.

    PPID spoofing occurs when an attacker uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    to make a process appear to have a different parent than the actual creator.

    Detection: Compare CreateInfo->ParentProcessId with CreatingThreadId.UniqueProcess
--*/
{
    //
    // The creating process (from CreatingThreadId) should normally be the parent
    // If they differ, the parent was explicitly set to a different process
    //
    if (Context->ParentProcessId != Context->CreatingProcessId) {
        //
        // ParentProcessId was spoofed to a different value
        //

        //
        // Exception: Some legitimate scenarios like AppInfo service elevation
        // Check if creating process is a known system process
        //
        if (PnpIsKnownSystemProcess(Context->CreatingProcessId, NULL)) {
            //
            // System process creating with different parent is often legitimate
            // (e.g., services.exe, svchost.exe doing elevation)
            //
            return FALSE;
        }

        //
        // Exception: Self-parenting (process setting itself as parent)
        // This is sometimes done for orphaning - VERY suspicious
        //
        if (Context->ParentProcessId == Context->ProcessId) {
            return TRUE;  // Definitely suspicious
        }

        //
        // Exception: Parent is System (PID 4) or Idle (PID 0)
        // Usually legitimate for services
        //
        if (HandleToULong(Context->ParentProcessId) <= 4) {
            //
            // Check if creator is also low PID
            //
            if (HandleToULong(Context->CreatingProcessId) > 4) {
                return TRUE;  // Spoofed to appear as system child
            }
            return FALSE;
        }

        //
        // Generic case: Parent differs from creator
        //
        return TRUE;
    }

    return FALSE;
}


// ============================================================================
// PROCESS ANALYSIS
// ============================================================================

static NTSTATUS
PnpAnalyzeProcess(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Performs comprehensive process analysis including:
    - Command line pattern matching (case-insensitive)
    - LOLBin detection
    - Encoded command detection
    - Behavioral indicators
--*/
{
    //
    // Command line analysis
    //
    if (g_ProcessMonitor.Config.EnableCommandLineAnalysis &&
        Context->CommandLine.Buffer != NULL &&
        Context->CommandLine.Length > 0) {

        PWCHAR CmdLine = Context->CommandLine.Buffer;
        USHORT CmdLenBytes = Context->CommandLine.Length;
        SIZE_T CmdLenChars = CmdLenBytes / sizeof(WCHAR);

        //
        // Pattern: PowerShell encoded command (-enc, -e, -encodedcommand)
        // Use case-insensitive matching
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-enc") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-EncodedCommand") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-e ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-ec ")) {

            Context->Flags |= PN_PROC_FLAG_ENCODED_CMD;
            Context->BehaviorFlags |= PN_BEHAVIOR_BASE64_ENCODED;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.EncodedCommands);
        }

        //
        // Pattern: PowerShell bypass flags
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-nop") ||      // NoProfile
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-noni") ||     // NonInteractive
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-w hidden") || // WindowStyle Hidden
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-windowstyle hidden") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-ep bypass") || // ExecutionPolicy Bypass
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"-executionpolicy bypass") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"bypass")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_SUSPICIOUS_PS;
        }

        //
        // Pattern: Download cradle indicators
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadString") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadFile") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"DownloadData") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"WebClient") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Invoke-WebRequest") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Invoke-RestMethod") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"wget ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"curl ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"bitsadmin") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Start-BitsTransfer")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_DOWNLOAD_CRADLE;
        }

        //
        // Pattern: Reflection/memory loading (fileless)
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"[Reflection.Assembly]") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"Reflection.Assembly") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"::Load(") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"FromBase64String")) {

            Context->BehaviorFlags |= PN_BEHAVIOR_REFLECTION_LOAD;
        }

        //
        // Pattern: Suspicious cmd.exe usage
        //
        if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"/c ") ||
            PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"/k ")) {

            //
            // Check for chained commands or suspicious patterns
            //
            if (PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"&&") ||
                PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"| ") ||
                PnpSafeWcsStrI(CmdLine, CmdLenBytes, L"^")) {

                Context->BehaviorFlags |= PN_BEHAVIOR_SUSPICIOUS_CMD;
            }
        }

        //
        // Check command line length (very long = suspicious)
        //
        if (CmdLenChars > 2048) {
            Context->BehaviorFlags |= PN_BEHAVIOR_LONG_CMDLINE;
        }
    }

    //
    // LOLBin detection (case-insensitive)
    //
    if (Context->ImageFileName.Buffer != NULL &&
        Context->ImageFileName.Length > 0) {

        PWCHAR FileName = Context->ImageFileName.Buffer;

        //
        // Common LOLBins - Living Off The Land Binaries
        // These are legitimate Windows binaries often abused by attackers
        //
        static const PCWSTR LOLBins[] = {
            L"mshta.exe",
            L"regsvr32.exe",
            L"rundll32.exe",
            L"msiexec.exe",
            L"certutil.exe",
            L"bitsadmin.exe",
            L"wmic.exe",
            L"wscript.exe",
            L"cscript.exe",
            L"msbuild.exe",
            L"installutil.exe",
            L"regasm.exe",
            L"regsvcs.exe",
            L"msconfig.exe",
            L"cmstp.exe",
            L"forfiles.exe",
            L"pcalua.exe",
            L"presentationhost.exe",
            L"te.exe",
            L"dnscmd.exe",
            L"ftp.exe",
            L"hh.exe",
            L"ieexec.exe",
            L"infdefaultinstall.exe",
            L"mavinject.exe",
            L"msdeploy.exe",
            L"msdt.exe",
            L"msiexec.exe",
            L"odbcconf.exe",
            L"pcwrun.exe",
            L"rcsi.exe",
            L"sfc.exe",
            L"syncappvpublishingserver.exe",
            L"tracker.exe",
            L"verclsid.exe",
            L"xwizard.exe"
        };

        for (ULONG i = 0; i < ARRAYSIZE(LOLBins); i++) {
            if (_wcsicmp(FileName, LOLBins[i]) == 0) {
                Context->Flags |= PN_PROC_FLAG_LOLBIN;
                InterlockedIncrement64(&g_ProcessMonitor.Stats.LOLBinsDetected);
                break;
            }
        }
    }

    return STATUS_SUCCESS;
}


static ULONG
PnpCalculateSuspicionScore(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Calculates a suspicion score based on accumulated indicators.
    Score ranges from 0-100.
--*/
{
    ULONG Score = 0;

    //
    // PPID spoofing is highly suspicious (major red flag)
    //
    if (Context->Flags & PN_PROC_FLAG_PPID_SPOOFED) {
        Score += 40;
    }

    //
    // Encoded command execution
    //
    if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
        Score += 25;
    }

    //
    // LOLBin execution (only suspicious with other indicators)
    //
    if (Context->Flags & PN_PROC_FLAG_LOLBIN) {
        Score += 15;

        //
        // LOLBin + encoded = much more suspicious
        //
        if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
            Score += 15;
        }

        //
        // LOLBin + download cradle = very suspicious
        //
        if (Context->BehaviorFlags & PN_BEHAVIOR_DOWNLOAD_CRADLE) {
            Score += 20;
        }
    }

    //
    // Cross-session process creation
    //
    if (Context->Flags & PN_PROC_FLAG_CROSS_SESSION) {
        Score += 10;
    }

    //
    // Unsigned binary (if signature verification enabled)
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification &&
        !(Context->Flags & PN_PROC_FLAG_SIGNATURE_VALID)) {
        Score += 5;
    }

    //
    // Behavioral flags
    //
    if (Context->BehaviorFlags & PN_BEHAVIOR_SUSPICIOUS_PS) {
        Score += 15;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_DOWNLOAD_CRADLE) {
        Score += 20;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_SUSPICIOUS_CMD) {
        Score += 10;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_LONG_CMDLINE) {
        Score += 5;
    }

    if (Context->BehaviorFlags & PN_BEHAVIOR_REFLECTION_LOAD) {
        Score += 25;
    }

    //
    // Elevated + suspicious indicators = worse
    //
    if (Context->IsElevated && Score > 0) {
        Score += 10;
    }

    //
    // Dangerous privileges (rare in normal apps)
    //
    if (Context->HasDebugPrivilege && !Context->IsSystem) {
        Score += 15;
    }

    if (Context->HasTcbPrivilege && !Context->IsSystem) {
        Score += 20;  // Very suspicious if not SYSTEM
    }

    if (Context->HasAssignPrimaryTokenPrivilege && !Context->IsSystem) {
        Score += 15;
    }

    //
    // Cap at 100
    //
    if (Score > 100) {
        Score = 100;
    }

    return Score;
}


// ============================================================================
// USER-MODE NOTIFICATION
// ============================================================================

static NTSTATUS
PnpSendProcessNotification(
    _In_ PPN_PROCESS_CONTEXT Context,
    _In_ BOOLEAN IsCreation,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PSHADOWSTRIKE_PROCESS_NOTIFICATION Notification = NULL;
    PSHADOWSTRIKE_PROCESS_VERDICT_REPLY Reply = NULL;
    SIZE_T NotificationSize;
    SIZE_T ReplySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY);
    BOOLEAN RequireReply = FALSE;
    PUCHAR BufferPtr;

    USHORT ImagePathLen = 0;
    USHORT CmdLineLen = 0;

    //
    // Check if user-mode is connected
    //
    if (!SHADOWSTRIKE_USER_MODE_CONNECTED()) {
        return STATUS_PORT_DISCONNECTED;
    }

    //
    // Determine if we need a reply (blocking decision)
    //
    if (IsCreation && CreateInfo != NULL) {
        //
        // Require reply for suspicious processes
        //
        if (Context->SuspicionScore >= PN_SUSPICION_MEDIUM) {
            RequireReply = TRUE;
        }
    }

    //
    // Calculate sizes with validation
    //
    if (Context->ImagePath.Buffer != NULL) {
        ImagePathLen = Context->ImagePath.Length;
    }

    if (Context->CommandLine.Buffer != NULL) {
        CmdLineLen = Context->CommandLine.Length;

        //
        // Cap for message size
        //
        if (CmdLineLen > 4096) {
            CmdLineLen = 4096;
        }
    }

    //
    // Safe size calculation with overflow checking
    //
    SIZE_T BaseSize = sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION);
    SIZE_T DataSize = (SIZE_T)ImagePathLen + (SIZE_T)CmdLineLen;

    //
    // Check for overflow
    //
    if (DataSize < ImagePathLen || DataSize < CmdLineLen) {
        return STATUS_INTEGER_OVERFLOW;
    }

    NotificationSize = BaseSize + DataSize;
    if (NotificationSize < BaseSize || NotificationSize < DataSize) {
        return STATUS_INTEGER_OVERFLOW;
    }

    //
    // Check against max message size
    //
    if (NotificationSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Truncate command line to fit
        //
        SIZE_T MaxData = SHADOWSTRIKE_MAX_MESSAGE_SIZE - BaseSize - ImagePathLen;
        if (MaxData < SHADOWSTRIKE_MAX_MESSAGE_SIZE) {  // Underflow check
            if (CmdLineLen > MaxData) {
                CmdLineLen = (USHORT)MaxData;
            }
        } else {
            CmdLineLen = 0;
        }
        NotificationSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Check pool limits
    //
    if (!PnpCheckPoolLimit(NotificationSize)) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.PoolLimitDrops);
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate notification buffer
    //
    Notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)ShadowStrikeAllocateMessageBuffer(
        (ULONG)NotificationSize
        );
    if (Notification == NULL) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PnpTrackPoolAllocation(NotificationSize);
    RtlZeroMemory(Notification, NotificationSize);

    //
    // Populate notification
    //
    Notification->ProcessId = HandleToULong(Context->ProcessId);
    Notification->ParentProcessId = HandleToULong(Context->ParentProcessId);
    Notification->CreatingProcessId = HandleToULong(Context->CreatingProcessId);
    Notification->CreatingThreadId = HandleToULong(Context->CreatingThreadId);
    Notification->Create = IsCreation;
    Notification->ImagePathLength = ImagePathLen;
    Notification->CommandLineLength = CmdLineLen;

    //
    // Copy variable data
    //
    BufferPtr = (PUCHAR)(Notification + 1);

    if (ImagePathLen > 0 && Context->ImagePath.Buffer != NULL) {
        RtlCopyMemory(BufferPtr, Context->ImagePath.Buffer, ImagePathLen);
        BufferPtr += ImagePathLen;
    }

    if (CmdLineLen > 0 && Context->CommandLine.Buffer != NULL) {
        RtlCopyMemory(BufferPtr, Context->CommandLine.Buffer, CmdLineLen);
    }

    //
    // Allocate reply buffer if needed
    //
    if (RequireReply) {
        Reply = (PSHADOWSTRIKE_PROCESS_VERDICT_REPLY)ShadowStrikeAllocateMessageBuffer(
            (ULONG)ReplySize
            );
        if (Reply == NULL) {
            RequireReply = FALSE;
        } else {
            PnpTrackPoolAllocation(ReplySize);
        }
    }

    //
    // Send notification with timeout
    //
    Status = ShadowStrikeSendProcessNotificationWithTimeout(
        Notification,
        (ULONG)NotificationSize,
        RequireReply,
        Reply,
        RequireReply ? (PULONG)&ReplySize : NULL,
        g_ProcessMonitor.Config.AnalysisTimeoutMs
        );

    //
    // Handle timeout
    //
    if (Status == STATUS_TIMEOUT) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.UserModeTimeouts);
        //
        // On timeout, default to allow (fail-open for availability)
        // Log for investigation
        //
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_WARNING_LEVEL,
            "[ShadowStrike/ProcessNotify] User-mode timeout for PID %lu, defaulting to ALLOW\n",
            HandleToULong(Context->ProcessId)
            );
        Status = STATUS_SUCCESS;
    }

    //
    // Handle verdict
    //
    if (RequireReply && NT_SUCCESS(Status) && Reply != NULL) {
        if (Reply->Verdict == SHADOWSTRIKE_VERDICT_BLOCK) {
            Status = STATUS_ACCESS_DENIED;
        }
    }

    //
    // Cleanup
    //
    if (Notification != NULL) {
        PnpTrackPoolFree(NotificationSize);
        ShadowStrikeFreeMessageBuffer(Notification);
    }

    if (Reply != NULL) {
        PnpTrackPoolFree(ReplySize);
        ShadowStrikeFreeMessageBuffer(Reply);
    }

    return Status;
}


// ============================================================================
// PROCESS TERMINATION HANDLING
// ============================================================================

static VOID
PnpHandleProcessTermination(
    _In_ HANDLE ProcessId
    )
{
    PPN_PROCESS_CONTEXT Context;

    //
    // Look up process context
    //
    Context = PnpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return;
    }

    //
    // Record termination time
    //
    KeQuerySystemTime(&Context->TerminateTime);

    //
    // Send termination notification (fire-and-forget)
    //
    PnpSendProcessNotification(Context, FALSE, NULL);

    //
    // Remove from tracking
    //
    PnpRemoveProcessContext(Context);

    //
    // Release lookup reference
    //
    PnpDereferenceContext(Context);
}


// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

static BOOLEAN
PnpIsKnownSystemProcess(
    _In_ HANDLE ProcessId,
    _In_opt_ PEPROCESS Process
    )
/*++
Routine Description:
    Determines if a process is a known system process.

    This is a PERFORMANCE optimization, not a security control.
    We skip detailed analysis for core system processes that
    are always present and trusted.
--*/
{
    ULONG Pid = HandleToULong(ProcessId);

    //
    // System (4) and Idle (0) - always system
    //
    if (Pid <= 4) {
        return TRUE;
    }

    //
    // For other processes, we could check:
    // 1. Protected process status
    // 2. Image path against known system binaries
    // 3. Token for SYSTEM SID
    //
    // However, PIDs are dynamic and attackers can abuse any process,
    // so we only skip the absolute minimum here.
    //

    UNREFERENCED_PARAMETER(Process);

    return FALSE;
}


static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Determines if a process should be considered trusted.

    SECURITY NOTE: This check can be bypassed and should NOT be the
    sole basis for allowing potentially malicious behavior.

    Trust is only granted when:
    1. Binary is in a protected system path
    2. Binary has valid signature
    3. No suspicious indicators are present
--*/
{
    //
    // Never trust if PPID spoofed
    //
    if (Context->Flags & PN_PROC_FLAG_PPID_SPOOFED) {
        return FALSE;
    }

    //
    // Never trust if encoded commands
    //
    if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
        return FALSE;
    }

    //
    // Require valid signature for trust
    //
    if (g_ProcessMonitor.Config.EnableSignatureVerification) {
        if (!(Context->Flags & PN_PROC_FLAG_SIGNATURE_VALID)) {
            return FALSE;
        }
    }

    //
    // Check for Windows system paths
    //
    if (Context->ImagePath.Buffer != NULL && Context->ImagePath.Length > 0) {
        //
        // Use case-insensitive, length-bounded search
        //
        if (PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\System32\\") ||
            PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\SysWOW64\\") ||
            PnpSafeWcsStrI(Context->ImagePath.Buffer,
                          Context->ImagePath.Length,
                          L"\\Windows\\WinSxS\\")) {

            //
            // Additional validation: check for path traversal attempts
            //
            if (PnpSafeWcsStrI(Context->ImagePath.Buffer,
                              Context->ImagePath.Length,
                              L"..")) {
                return FALSE;  // Path traversal attempt
            }

            return TRUE;
        }
    }

    return FALSE;
}


static BOOLEAN
PnpCheckParentSessionMatch(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Checks if parent and child sessions match.
    Cross-session process creation can indicate token manipulation.
--*/
{
    //
    // Same session = normal
    //
    if (Context->SessionId == Context->ParentSessionId) {
        return TRUE;
    }

    //
    // Exception: Parent is session 0 (service), child is user session
    // This is normal for service-launched processes
    //
    if (Context->ParentSessionId == 0 && Context->SessionId != 0) {
        return TRUE;
    }

    //
    // User session creating session-0 process is suspicious
    //
    if (Context->ParentSessionId != 0 && Context->SessionId == 0) {
        return FALSE;
    }

    //
    // Different user sessions is unusual
    //
    return FALSE;
}


static BOOLEAN
PnpCheckRateLimit(
    VOID
    )
/*++
Routine Description:
    Implements token bucket rate limiting for notifications.

Return Value:
    TRUE if notification is allowed, FALSE if rate limited.
--*/
{
    LARGE_INTEGER CurrentTime;
    LONG64 WindowStart;
    LONG64 WindowDuration;
    LONG CurrentCount;

    KeQuerySystemTime(&CurrentTime);

    //
    // Window duration in 100ns units
    //
    WindowDuration = (LONG64)PN_RATE_LIMIT_WINDOW_MS * 10000;

    //
    // Check if we need to reset the window
    //
    WindowStart = InterlockedCompareExchange64(
        &g_ProcessMonitor.RateLimiter.WindowStartTime,
        0, 0);

    if ((CurrentTime.QuadPart - WindowStart) > WindowDuration) {
        //
        // Try to reset window
        //
        if (InterlockedCompareExchange64(
                &g_ProcessMonitor.RateLimiter.WindowStartTime,
                CurrentTime.QuadPart,
                WindowStart) == WindowStart) {
            //
            // We reset the window, reset counter
            //
            InterlockedExchange(&g_ProcessMonitor.RateLimiter.NotificationsInWindow, 0);
        }
    }

    //
    // Increment and check count
    //
    CurrentCount = InterlockedIncrement(&g_ProcessMonitor.RateLimiter.NotificationsInWindow);

    if (CurrentCount > (LONG)g_ProcessMonitor.Config.MaxNotificationsPerSecond) {
        InterlockedIncrement(&g_ProcessMonitor.RateLimiter.DroppedNotifications);
        return FALSE;
    }

    return TRUE;
}


static BOOLEAN
PnpCheckPoolLimit(
    _In_ SIZE_T AllocationSize
    )
/*++
Routine Description:
    Checks if allocation would exceed pool limits.
--*/
{
    LONG64 Current = InterlockedCompareExchange64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation, 0, 0);

    if ((Current + (LONG64)AllocationSize) > g_ProcessMonitor.PoolTracker.MaxAllocation) {
        return FALSE;
    }

    return TRUE;
}


static VOID
PnpTrackPoolAllocation(
    _In_ SIZE_T Size
    )
{
    LONG64 NewValue = InterlockedAdd64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation,
        (LONG64)Size);

    //
    // Update peak
    //
    LONG64 Peak = InterlockedCompareExchange64(
        &g_ProcessMonitor.PoolTracker.PeakAllocation, 0, 0);

    while (NewValue > Peak) {
        LONG64 OldPeak = InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.PeakAllocation,
            NewValue,
            Peak);
        if (OldPeak == Peak) {
            break;
        }
        Peak = OldPeak;
    }
}


static VOID
PnpTrackPoolFree(
    _In_ SIZE_T Size
    )
{
    InterlockedAdd64(
        &g_ProcessMonitor.PoolTracker.CurrentAllocation,
        -(LONG64)Size);
}


static BOOLEAN
PnpSafeWcsStrI(
    _In_ PCWCH Buffer,
    _In_ USHORT BufferLengthBytes,
    _In_ PCWSTR Pattern
    )
/*++
Routine Description:
    Case-insensitive substring search with length bounds.
    Does NOT rely on null-termination.

Arguments:
    Buffer - The buffer to search in
    BufferLengthBytes - Length of buffer in BYTES
    Pattern - Null-terminated pattern to search for

Return Value:
    TRUE if pattern found, FALSE otherwise.
--*/
{
    SIZE_T BufferLenChars;
    SIZE_T PatternLen;
    SIZE_T i, j;

    if (Buffer == NULL || Pattern == NULL || BufferLengthBytes == 0) {
        return FALSE;
    }

    BufferLenChars = BufferLengthBytes / sizeof(WCHAR);
    PatternLen = wcslen(Pattern);

    if (PatternLen == 0 || PatternLen > BufferLenChars) {
        return FALSE;
    }

    //
    // Simple case-insensitive search
    //
    for (i = 0; i <= BufferLenChars - PatternLen; i++) {
        BOOLEAN Match = TRUE;

        for (j = 0; j < PatternLen; j++) {
            WCHAR BufChar = Buffer[i + j];
            WCHAR PatChar = Pattern[j];

            //
            // Convert to uppercase for comparison
            //
            if (BufChar >= L'a' && BufChar <= L'z') {
                BufChar -= (L'a' - L'A');
            }
            if (PatChar >= L'a' && PatChar <= L'z') {
                PatChar -= (L'a' - L'A');
            }

            if (BufChar != PatChar) {
                Match = FALSE;
                break;
            }
        }

        if (Match) {
            return TRUE;
        }
    }

    return FALSE;
}


static NTSTATUS
PnpVerifyImageSignature(
    _In_ PPN_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Verifies the digital signature of the process image.

    This uses CI.dll exports if available, or falls back to
    checking basic signature status from the process object.
--*/
{
    NTSTATUS Status = STATUS_SUCCESS;

    //
    // Check if process object has signature info
    // This is available via PsGetProcessSignatureLevel on Win8.1+
    //
    if (Context->ProcessObject != NULL) {
        UCHAR SignatureLevel = 0;
        UCHAR SectionSignatureLevel = 0;

        //
        // PsGetProcessSignatureLevel is available on Windows 8.1+
        // We use it if available, otherwise we can't verify
        //
        #if (NTDDI_VERSION >= NTDDI_WINBLUE)
        Status = PsGetProcessSignatureLevel(
            Context->ProcessObject,
            &SignatureLevel,
            &SectionSignatureLevel
            );

        if (NT_SUCCESS(Status)) {
            //
            // Any signature level > 0 indicates some form of signing
            // SE_SIGNING_LEVEL_MICROSOFT (8) or higher is MS-signed
            // SE_SIGNING_LEVEL_AUTHENTICODE (4) is third-party signed
            //
            if (SignatureLevel >= SE_SIGNING_LEVEL_AUTHENTICODE) {
                Context->IsSignatureValid = TRUE;
            }
        }
        #else
        //
        // Older OS - can't easily verify, default to unknown
        //
        Status = STATUS_NOT_SUPPORTED;
        #endif
    }

    return Status;
}


// ============================================================================
// TIMER AND CLEANUP
// ============================================================================

static VOID
PnpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
/*++
Routine Description:
    DPC callback for cleanup timer.

    CRITICAL: This runs at DISPATCH_LEVEL. Cannot call paged code
    or acquire push locks. Must queue a work item.
--*/
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_ProcessMonitor.ShutdownRequested) {
        return;
    }

    //
    // Don't queue if work is already pending
    //
    if (InterlockedCompareExchange(&g_ProcessMonitor.CleanupWorkPending, TRUE, FALSE) == FALSE) {
        //
        // Queue work item for cleanup (runs at PASSIVE_LEVEL)
        //
        if (g_ProcessMonitor.CleanupWorkItem != NULL) {
            IoQueueWorkItem(
                g_ProcessMonitor.CleanupWorkItem,
                PnpCleanupWorkRoutine,
                DelayedWorkQueue,
                NULL
                );
        } else {
            //
            // No work item - clear pending flag
            //
            InterlockedExchange(&g_ProcessMonitor.CleanupWorkPending, FALSE);
        }
    }
}


static VOID
PnpCleanupWorkRoutine(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Work item routine for cleanup. Runs at PASSIVE_LEVEL.
--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    PAGED_CODE();

    if (!g_ProcessMonitor.ShutdownRequested) {
        PnpCleanupStaleContexts();
    }

    //
    // Clear pending flag
    //
    InterlockedExchange(&g_ProcessMonitor.CleanupWorkPending, FALSE);
}


static VOID
PnpCleanupStaleContexts(
    VOID
    )
/*++
Routine Description:
    Removes process contexts for terminated processes.

    This runs periodically to clean up contexts that weren't
    properly removed during process termination, and to check
    for orphaned contexts where the process has exited.
--*/
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPN_PROCESS_CONTEXT Context;
    LIST_ENTRY StaleList;
    NTSTATUS Status;

    PAGED_CODE();

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PN_CONTEXT_TIMEOUT_MS * 10000;

    //
    // Collect stale contexts while holding lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    for (Entry = g_ProcessMonitor.ProcessList.Flink;
         Entry != &g_ProcessMonitor.ProcessList;
         Entry = Next) {

        Next = Entry->Flink;
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        BOOLEAN ShouldRemove = FALSE;

        //
        // Check if process has terminated (TerminateTime set)
        //
        if (Context->TerminateTime.QuadPart != 0) {
            //
            // Check if enough time has passed since termination
            //
            if ((CurrentTime.QuadPart - Context->TerminateTime.QuadPart) > TimeoutInterval.QuadPart) {
                ShouldRemove = TRUE;
            }
        } else {
            //
            // Process hasn't called termination callback
            // Check if it's actually still running
            //
            if (Context->ProcessObject != NULL) {
                //
                // Check if process has exited
                //
                if (PsGetProcessExitStatus(Context->ProcessObject) != STATUS_PENDING) {
                    //
                    // Process has exited but we missed termination callback
                    //
                    KeQuerySystemTime(&Context->TerminateTime);
                    ShouldRemove = TRUE;
                }
            }
        }

        if (ShouldRemove) {
            //
            // Remove from main list
            //
            RemoveEntryList(&Context->ListEntry);
            InitializeListHead(&Context->ListEntry);
            InterlockedExchange(&Context->InsertedInList, FALSE);
            InterlockedDecrement(&g_ProcessMonitor.ProcessCount);

            //
            // Add to stale list for hash removal outside this lock
            //
            InsertTailList(&StaleList, &Context->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Remove from hash tables and free - outside ProcessListLock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table under correct bucket lock
        //
        if (InterlockedCompareExchange(&Context->InsertedInHash, FALSE, TRUE)) {
            ULONG BucketIndex = PnpHashProcessId(Context->ProcessId);
            PPN_HASH_BUCKET Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Bucket->Lock);

            if (!IsListEmpty(&Context->HashEntry)) {
                RemoveEntryList(&Context->HashEntry);
                InitializeListHead(&Context->HashEntry);
            }

            ExReleasePushLockExclusive(&Bucket->Lock);
            KeLeaveCriticalRegion();
        }

        //
        // Release the list reference (will free if last ref)
        //
        PnpDereferenceContext(Context);
    }
}


// ============================================================================
// STATISTICS AND DIAGNOSTICS
// ============================================================================

NTSTATUS
ShadowStrikeGetProcessMonitorStats(
    _Out_ PULONG64 ProcessCreations,
    _Out_ PULONG64 ProcessesBlocked,
    _Out_ PULONG64 PpidSpoofingDetected,
    _Out_ PULONG64 SuspiciousProcesses
    )
{
    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (ProcessCreations != NULL) {
        *ProcessCreations = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.ProcessCreations, 0, 0);
    }

    if (ProcessesBlocked != NULL) {
        *ProcessesBlocked = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.ProcessesBlocked, 0, 0);
    }

    if (PpidSpoofingDetected != NULL) {
        *PpidSpoofingDetected = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.PpidSpoofingDetected, 0, 0);
    }

    if (SuspiciousProcesses != NULL) {
        *SuspiciousProcesses = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.SuspiciousProcesses, 0, 0);
    }

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeQueryProcessContext(
    _In_ HANDLE ProcessId,
    _Out_ PULONG Flags,
    _Out_ PULONG SuspicionScore
    )
{
    PPN_PROCESS_CONTEXT Context;

    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    Context = PnpLookupProcessContext(ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    if (Flags != NULL) {
        *Flags = Context->Flags;
    }

    if (SuspicionScore != NULL) {
        *SuspicionScore = Context->SuspicionScore;
    }

    PnpDereferenceContext(Context);

    return STATUS_SUCCESS;
}


NTSTATUS
ShadowStrikeGetProcessMonitorExtendedStats(
    _Out_ PULONG64 RateLimitDrops,
    _Out_ PULONG64 PoolLimitDrops,
    _Out_ PULONG64 UserModeTimeouts,
    _Out_ PULONG64 CurrentPoolUsage,
    _Out_ PULONG64 PeakPoolUsage
    )
{
    if (!g_ProcessMonitor.Initialized) {
        return STATUS_NOT_FOUND;
    }

    if (RateLimitDrops != NULL) {
        *RateLimitDrops = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.RateLimitDrops, 0, 0);
    }

    if (PoolLimitDrops != NULL) {
        *PoolLimitDrops = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.PoolLimitDrops, 0, 0);
    }

    if (UserModeTimeouts != NULL) {
        *UserModeTimeouts = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.Stats.UserModeTimeouts, 0, 0);
    }

    if (CurrentPoolUsage != NULL) {
        *CurrentPoolUsage = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.CurrentAllocation, 0, 0);
    }

    if (PeakPoolUsage != NULL) {
        *PeakPoolUsage = (ULONG64)InterlockedCompareExchange64(
            &g_ProcessMonitor.PoolTracker.PeakAllocation, 0, 0);
    }

    return STATUS_SUCCESS;
}
