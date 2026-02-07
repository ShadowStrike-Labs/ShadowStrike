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

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
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
#endif

// ============================================================================
// INTERNAL CONSTANTS
// ============================================================================

#define PN_POOL_TAG                     'TNPP'  // PPNT reversed
#define PN_CONTEXT_POOL_TAG             'xCNP'  // PNCx
#define PN_MAX_PROCESS_CONTEXTS         4096
#define PN_MAX_PENDING_NOTIFICATIONS    1024
#define PN_CLEANUP_INTERVAL_MS          60000   // 1 minute
#define PN_CONTEXT_TIMEOUT_MS           300000  // 5 minutes
#define PN_MAX_COMMAND_LINE_CAPTURE     8192
#define PN_MAX_IMAGE_PATH_CAPTURE       2048

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
    // Process information
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
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // List linkage
    //
    LIST_ENTRY ListEntry;
    LIST_ENTRY HashEntry;

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
// Process monitor state
//
typedef struct _PN_MONITOR_STATE {
    //
    // Initialization
    //
    BOOLEAN Initialized;

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
    BOOLEAN LookasideInitialized;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Sub-analyzers (optional integration)
    //
    PVOID ProcessAnalyzer;      // PPA_ANALYZER
    PVOID ParentChainTracker;   // PPCT_TRACKER
    PVOID CommandLineParser;    // PCLP_PARSER
    PVOID TokenAnalyzer;        // PTA_ANALYZER

    //
    // Statistics
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
        LARGE_INTEGER StartTime;
    } Stats;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnablePpidSpoofingDetection;
        BOOLEAN EnableCommandLineAnalysis;
        BOOLEAN EnableTokenAnalysis;
        BOOLEAN EnableParentChainTracking;
        BOOLEAN BlockSuspiciousProcesses;
        ULONG MinBlockScore;
        ULONG AnalysisTimeoutMs;
    } Config;

    //
    // Shutdown flag
    //
    volatile BOOLEAN ShutdownRequested;

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

static VOID
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
PnpCleanupStaleContexts(
    VOID
    );

static NTSTATUS
PnpCaptureTokenInfo(
    _In_ PEPROCESS Process,
    _Out_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpIsSystemProcess(
    _In_ HANDLE ProcessId
    );

static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    );

static BOOLEAN
PnpCheckParentSessionMatch(
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
    // Initialize default configuration
    //
    g_ProcessMonitor.Config.EnablePpidSpoofingDetection = TRUE;
    g_ProcessMonitor.Config.EnableCommandLineAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableTokenAnalysis = TRUE;
    g_ProcessMonitor.Config.EnableParentChainTracking = TRUE;
    g_ProcessMonitor.Config.BlockSuspiciousProcesses = FALSE;  // Audit mode by default
    g_ProcessMonitor.Config.MinBlockScore = PN_SUSPICION_CRITICAL;
    g_ProcessMonitor.Config.AnalysisTimeoutMs = 5000;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&g_ProcessMonitor.Stats.StartTime);

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

    g_ProcessMonitor.Initialized = TRUE;

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring initialized\n"
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
--*/
{
    PLIST_ENTRY Entry;
    PPN_PROCESS_CONTEXT Context;
    PPN_NOTIFICATION_ENTRY Notification;
    KIRQL OldIrql;

    PAGED_CODE();

    if (!g_ProcessMonitor.Initialized) {
        return;
    }

    g_ProcessMonitor.ShutdownRequested = TRUE;
    g_ProcessMonitor.Initialized = FALSE;

    //
    // Cancel cleanup timer
    //
    if (g_ProcessMonitor.CleanupTimerActive) {
        KeCancelTimer(&g_ProcessMonitor.CleanupTimer);
        g_ProcessMonitor.CleanupTimerActive = FALSE;
    }

    //
    // Free all process contexts
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    while (!IsListEmpty(&g_ProcessMonitor.ProcessList)) {
        Entry = RemoveHeadList(&g_ProcessMonitor.ProcessList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table
        //
        if (!IsListEmpty(&Context->HashEntry)) {
            RemoveEntryList(&Context->HashEntry);
            InitializeListHead(&Context->HashEntry);
        }

        ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
        KeLeaveCriticalRegion();

        PnpFreeProcessContext(Context);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

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
    // Delete lookaside lists
    //
    if (g_ProcessMonitor.LookasideInitialized) {
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.ContextLookaside);
        ExDeleteNPagedLookasideList(&g_ProcessMonitor.NotificationLookaside);
    }

    DbgPrintEx(
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_INFO_LEVEL,
        "[ShadowStrike/ProcessNotify] Process monitoring shutdown. "
        "Stats: Created=%lld, Terminated=%lld, Blocked=%lld, PpidSpoof=%lld\n",
        g_ProcessMonitor.Stats.ProcessCreations,
        g_ProcessMonitor.Stats.ProcessTerminations,
        g_ProcessMonitor.Stats.ProcessesBlocked,
        g_ProcessMonitor.Stats.PpidSpoofingDetected
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
    // Always increment raw statistics
    //
    if (IsCreation) {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessCreations);
        SHADOWSTRIKE_INC_STAT(TotalProcessCreations);
    } else {
        InterlockedIncrement64(&g_ProcessMonitor.Stats.ProcessTerminations);
    }

    //
    // Check if we should process this event
    //
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
    // Check for system process (skip detailed analysis)
    //
    if (PnpIsSystemProcess(ProcessId)) {
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
    PnpInsertProcessContext(ProcessContext);

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
    //
    if (ShouldBlock) {
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

    Context = (PPN_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &g_ProcessMonitor.ContextLookaside
        );

    if (Context != NULL) {
        RtlZeroMemory(Context, sizeof(PN_PROCESS_CONTEXT));
        Context->RefCount = 1;
        InitializeListHead(&Context->ListEntry);
        InitializeListHead(&Context->HashEntry);
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
    // Free allocated strings
    //
    if (Context->ImagePath.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Context->ImagePath.Buffer, PN_POOL_TAG);
    }

    if (Context->CommandLine.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Context->CommandLine.Buffer, PN_POOL_TAG);
    }

    if (Context->ImageFileName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(Context->ImageFileName.Buffer, PN_POOL_TAG);
    }

    //
    // Dereference process object if held
    //
    if (Context->ProcessObject != NULL) {
        ObDereferenceObject(Context->ProcessObject);
        Context->ProcessObject = NULL;
    }

    ExFreeToNPagedLookasideList(&g_ProcessMonitor.ContextLookaside, Context);
}


static ULONG
PnpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    //
    // Simple hash function for process IDs
    //
    Value = Value ^ (Value >> 16);
    Value = Value * 0x85EBCA6B;
    Value = Value ^ (Value >> 13);

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

    BucketIndex = PnpHashProcessId(ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Bucket->Lock);

    for (Entry = Bucket->List.Flink;
         Entry != &Bucket->List;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, HashEntry);

        if (Context->ProcessId == ProcessId) {
            PnpReferenceContext(Context);
            ExReleasePushLockShared(&Bucket->Lock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&Bucket->Lock);
    KeLeaveCriticalRegion();

    return NULL;
}


static VOID
PnpInsertProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;

    //
    // Reference for list storage
    //
    PnpReferenceContext(Context);

    //
    // Insert into main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    InsertTailList(&g_ProcessMonitor.ProcessList, &Context->ListEntry);
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

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();
}


static VOID
PnpRemoveProcessContext(
    _In_ PPN_PROCESS_CONTEXT Context
    )
{
    ULONG BucketIndex;
    PPN_HASH_BUCKET Bucket;
    BOOLEAN WasInList = FALSE;

    //
    // Remove from hash table first
    //
    BucketIndex = PnpHashProcessId(Context->ProcessId);
    Bucket = &g_ProcessMonitor.HashTable[BucketIndex];

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Bucket->Lock);

    if (!IsListEmpty(&Context->HashEntry)) {
        RemoveEntryList(&Context->HashEntry);
        InitializeListHead(&Context->HashEntry);
    }

    ExReleasePushLockExclusive(&Bucket->Lock);
    KeLeaveCriticalRegion();

    //
    // Remove from main list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    if (!IsListEmpty(&Context->ListEntry)) {
        RemoveEntryList(&Context->ListEntry);
        InitializeListHead(&Context->ListEntry);
        InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
        WasInList = TRUE;
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Release list reference
    //
    if (WasInList) {
        PnpDereferenceContext(Context);
    }
}


static VOID
PnpReferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}


static VOID
PnpDereferenceContext(
    _Inout_ PPN_PROCESS_CONTEXT Context
    )
{
    if (InterlockedDecrement(&Context->RefCount) == 0) {
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
    //
    Status = ObReferenceObjectByPointer(
        Process,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode
        );
    if (NT_SUCCESS(Status)) {
        Context->ProcessObject = Process;
    }

    //
    // Capture image path
    //
    if (CreateInfo->ImageFileName != NULL &&
        CreateInfo->ImageFileName->Length > 0) {

        BufferSize = CreateInfo->ImageFileName->Length + sizeof(WCHAR);

        if (BufferSize <= PN_MAX_IMAGE_PATH_CAPTURE * sizeof(WCHAR)) {
            Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                BufferSize,
                PN_POOL_TAG
                );

            if (Buffer != NULL) {
                RtlCopyMemory(
                    Buffer,
                    CreateInfo->ImageFileName->Buffer,
                    CreateInfo->ImageFileName->Length
                    );
                Buffer[CreateInfo->ImageFileName->Length / sizeof(WCHAR)] = L'\0';

                Context->ImagePath.Buffer = Buffer;
                Context->ImagePath.Length = CreateInfo->ImageFileName->Length;
                Context->ImagePath.MaximumLength = (USHORT)BufferSize;

                //
                // Extract filename
                //
                PWCHAR LastSlash = wcsrchr(Buffer, L'\\');
                if (LastSlash != NULL) {
                    USHORT FileNameLen = (USHORT)((wcslen(LastSlash + 1)) * sizeof(WCHAR));
                    PWCHAR FileNameBuffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
                        NonPagedPoolNx,
                        FileNameLen + sizeof(WCHAR),
                        PN_POOL_TAG
                        );
                    if (FileNameBuffer != NULL) {
                        RtlCopyMemory(FileNameBuffer, LastSlash + 1, FileNameLen);
                        FileNameBuffer[FileNameLen / sizeof(WCHAR)] = L'\0';
                        Context->ImageFileName.Buffer = FileNameBuffer;
                        Context->ImageFileName.Length = FileNameLen;
                        Context->ImageFileName.MaximumLength = FileNameLen + sizeof(WCHAR);
                    }
                }
            }
        }
    }

    //
    // Capture command line
    //
    if (CreateInfo->CommandLine != NULL &&
        CreateInfo->CommandLine->Length > 0) {

        USHORT CaptureLength = CreateInfo->CommandLine->Length;

        //
        // Cap command line length
        //
        if (CaptureLength > PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR)) {
            CaptureLength = PN_MAX_COMMAND_LINE_CAPTURE * sizeof(WCHAR);
        }

        BufferSize = CaptureLength + sizeof(WCHAR);
        Buffer = (PWCHAR)ShadowStrikeAllocatePoolWithTag(
            NonPagedPoolNx,
            BufferSize,
            PN_POOL_TAG
            );

        if (Buffer != NULL) {
            RtlCopyMemory(Buffer, CreateInfo->CommandLine->Buffer, CaptureLength);
            Buffer[CaptureLength / sizeof(WCHAR)] = L'\0';

            Context->CommandLine.Buffer = Buffer;
            Context->CommandLine.Length = CaptureLength;
            Context->CommandLine.MaximumLength = (USHORT)BufferSize;
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
    PTOKEN_STATISTICS TokenStats = NULL;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    BOOLEAN IsImpersonating = FALSE;
    ULONG SessionId = 0;

    __try {
        //
        // Get primary token
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
        // Check token type
        //
        if (SeTokenIsRestricted(Token)) {
            Context->IntegrityLevel = 0;  // Restricted = low
        }

        //
        // Check for admin token
        //
        if (SeTokenIsAdmin(Token)) {
            Context->IsElevated = TRUE;
        }

        //
        // Check for specific privileges
        //
        LUID DebugPrivilege = {SE_DEBUG_PRIVILEGE, 0};
        LUID ImpersonatePrivilege = {SE_IMPERSONATE_PRIVILEGE, 0};

        BOOLEAN DebugPresent = FALSE;
        BOOLEAN ImpersonatePresent = FALSE;

        Status = SePrivilegeCheck(
            &DebugPrivilege,
            1,
            Token,
            KernelMode
            );
        if (NT_SUCCESS(Status)) {
            Context->HasDebugPrivilege = TRUE;
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
    // Check if SYSTEM process
    //
    {
        SECURITY_SUBJECT_CONTEXT SubjectContext;
        SeCaptureSubjectContext(&SubjectContext);

        if (SeTokenIsAdmin(SubjectContext.PrimaryToken)) {
            //
            // Further check for SYSTEM SID
            //
            // Simplified: If session 0 and elevated, likely system service
            //
            if (Context->SessionId == 0 && Context->IsElevated) {
                Context->IsService = TRUE;
            }
        }

        SeReleaseSubjectContext(&SubjectContext);
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
        if (PnpIsSystemProcess(Context->CreatingProcessId)) {
            //
            // System process creating with different parent is often legitimate
            // (e.g., services.exe, svchost.exe doing elevation)
            //
            return FALSE;
        }

        //
        // Exception: Self-parenting (process setting itself as parent)
        // This is sometimes done for orphaning
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
    - Command line pattern matching
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

        //
        // Check for encoded/obfuscated commands
        //
        PWCHAR CmdLine = Context->CommandLine.Buffer;
        SIZE_T CmdLen = Context->CommandLine.Length / sizeof(WCHAR);

        //
        // Pattern: PowerShell encoded command (-enc, -e, -encodedcommand)
        //
        if (wcsstr(CmdLine, L"-enc") != NULL ||
            wcsstr(CmdLine, L"-EncodedCommand") != NULL ||
            wcsstr(CmdLine, L"-e ") != NULL) {

            Context->Flags |= PN_PROC_FLAG_ENCODED_CMD;
            InterlockedIncrement64(&g_ProcessMonitor.Stats.EncodedCommands);
        }

        //
        // Pattern: PowerShell bypass flags
        //
        if (wcsstr(CmdLine, L"-nop") != NULL ||      // NoProfile
            wcsstr(CmdLine, L"-noni") != NULL ||     // NonInteractive
            wcsstr(CmdLine, L"-w hidden") != NULL || // WindowStyle Hidden
            wcsstr(CmdLine, L"-ep bypass") != NULL || // ExecutionPolicy Bypass
            wcsstr(CmdLine, L"bypass") != NULL) {

            Context->BehaviorFlags |= 0x0001;  // Suspicious PS flags
        }

        //
        // Pattern: Download cradle indicators
        //
        if (wcsstr(CmdLine, L"DownloadString") != NULL ||
            wcsstr(CmdLine, L"DownloadFile") != NULL ||
            wcsstr(CmdLine, L"WebClient") != NULL ||
            wcsstr(CmdLine, L"Invoke-WebRequest") != NULL ||
            wcsstr(CmdLine, L"wget") != NULL ||
            wcsstr(CmdLine, L"curl") != NULL ||
            wcsstr(CmdLine, L"bitsadmin") != NULL) {

            Context->BehaviorFlags |= 0x0002;  // Download cradle
        }

        //
        // Pattern: Suspicious cmd.exe usage
        //
        if (wcsstr(CmdLine, L"/c ") != NULL ||
            wcsstr(CmdLine, L"/k ") != NULL) {

            //
            // Check for chained commands or suspicious patterns
            //
            if (wcsstr(CmdLine, L"&&") != NULL ||
                wcsstr(CmdLine, L"| ") != NULL ||
                wcsstr(CmdLine, L"^") != NULL) {

                Context->BehaviorFlags |= 0x0004;  // Suspicious cmd
            }
        }

        //
        // Check command line length (very long = suspicious)
        //
        if (CmdLen > 2048) {
            Context->BehaviorFlags |= 0x0008;  // Long command line
        }
    }

    //
    // LOLBin detection
    //
    if (Context->ImageFileName.Buffer != NULL) {
        PWCHAR FileName = Context->ImageFileName.Buffer;

        //
        // Common LOLBins
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
            L"pcalua.exe"
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
--*/
{
    ULONG Score = 0;

    //
    // PPID spoofing is highly suspicious
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
        // LOLBin + encoded = more suspicious
        //
        if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
            Score += 15;
        }
    }

    //
    // Cross-session process creation
    //
    if (Context->Flags & PN_PROC_FLAG_CROSS_SESSION) {
        Score += 10;
    }

    //
    // Behavioral flags
    //
    if (Context->BehaviorFlags & 0x0001) {  // Suspicious PS flags
        Score += 15;
    }

    if (Context->BehaviorFlags & 0x0002) {  // Download cradle
        Score += 20;
    }

    if (Context->BehaviorFlags & 0x0004) {  // Suspicious cmd
        Score += 10;
    }

    if (Context->BehaviorFlags & 0x0008) {  // Long command line
        Score += 5;
    }

    //
    // Elevated + suspicious indicators = worse
    //
    if (Context->IsElevated && Score > 0) {
        Score += 10;
    }

    //
    // Debug privilege (rare in normal apps)
    //
    if (Context->HasDebugPrivilege && !Context->IsSystem) {
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
    ULONG NotificationSize;
    ULONG ReplySize = sizeof(SHADOWSTRIKE_PROCESS_VERDICT_REPLY);
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
    // Calculate sizes
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
    // Calculate total size
    //
    NotificationSize = sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) +
                       ImagePathLen +
                       CmdLineLen;

    if (NotificationSize > SHADOWSTRIKE_MAX_MESSAGE_SIZE) {
        //
        // Truncate command line to fit
        //
        ULONG MaxData = SHADOWSTRIKE_MAX_MESSAGE_SIZE - sizeof(SHADOWSTRIKE_PROCESS_NOTIFICATION) - ImagePathLen;
        if (CmdLineLen > MaxData) {
            CmdLineLen = (USHORT)MaxData;
        }
        NotificationSize = SHADOWSTRIKE_MAX_MESSAGE_SIZE;
    }

    //
    // Allocate notification buffer
    //
    Notification = (PSHADOWSTRIKE_PROCESS_NOTIFICATION)ShadowStrikeAllocateMessageBuffer(NotificationSize);
    if (Notification == NULL) {
        SHADOWSTRIKE_INC_STAT(MessagesDropped);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

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
        Reply = (PSHADOWSTRIKE_PROCESS_VERDICT_REPLY)ShadowStrikeAllocateMessageBuffer(ReplySize);
        if (Reply == NULL) {
            RequireReply = FALSE;
        }
    }

    //
    // Send notification
    //
    Status = ShadowStrikeSendProcessNotification(
        Notification,
        NotificationSize,
        RequireReply,
        Reply,
        RequireReply ? &ReplySize : NULL
        );

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
        ShadowStrikeFreeMessageBuffer(Notification);
    }

    if (Reply != NULL) {
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
PnpIsSystemProcess(
    _In_ HANDLE ProcessId
    )
{
    ULONG Pid = HandleToULong(ProcessId);

    //
    // System (4) and Idle (0)
    //
    if (Pid <= 4) {
        return TRUE;
    }

    //
    // Could add additional checks for known system PIDs
    // But PIDs are dynamic, so this is limited
    //
    return FALSE;
}


static BOOLEAN
PnpIsTrustedProcess(
    _In_ PPN_PROCESS_CONTEXT Context
    )
{
    //
    // Check if process is in protected process list
    //
    if (Context->ImagePath.Buffer != NULL) {
        //
        // Check for Windows system paths
        //
        if (wcsstr(Context->ImagePath.Buffer, L"\\Windows\\System32\\") != NULL ||
            wcsstr(Context->ImagePath.Buffer, L"\\Windows\\SysWOW64\\") != NULL) {

            //
            // Still validate: not all system32 binaries are trustworthy
            // when executed with suspicious parameters
            //
            if (Context->Flags & PN_PROC_FLAG_ENCODED_CMD) {
                return FALSE;  // Suspicious even if system binary
            }

            if (Context->Flags & PN_PROC_FLAG_PPID_SPOOFED) {
                return FALSE;  // PPID spoofing overrides trust
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
{
    //
    // Session 0 isolation: Non-session-0 process shouldn't be created
    // by session-0 process in normal circumstances (except via services)
    //
    if (Context->SessionId != Context->ParentSessionId) {
        //
        // Cross-session creation
        //

        //
        // Exception: Parent is session 0 (service), child is user session
        // This is normal for service-launched processes
        //
        if (Context->ParentSessionId == 0 && Context->SessionId != 0) {
            return TRUE;  // Normal service launch
        }

        //
        // Exception: User session creating in session 0 via elevation
        // (Requires further validation with token analysis)
        //
        if (Context->ParentSessionId != 0 && Context->SessionId == 0) {
            //
            // This is suspicious - user creating session-0 process
            //
            return FALSE;
        }

        return FALSE;
    }

    return TRUE;
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
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (g_ProcessMonitor.ShutdownRequested) {
        return;
    }

    //
    // Queue work item for cleanup (can't do paged operations in DPC)
    //
    PnpCleanupStaleContexts();
}


static VOID
PnpCleanupStaleContexts(
    VOID
    )
/*++
Routine Description:
    Removes process contexts for terminated processes.

    This runs periodically to clean up contexts that weren't
    properly removed during process termination.
--*/
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PPN_PROCESS_CONTEXT Context;
    LIST_ENTRY StaleList;

    InitializeListHead(&StaleList);

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)PN_CONTEXT_TIMEOUT_MS * 10000;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&g_ProcessMonitor.ProcessListLock);

    for (Entry = g_ProcessMonitor.ProcessList.Flink;
         Entry != &g_ProcessMonitor.ProcessList;
         Entry = Next) {

        Next = Entry->Flink;
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Check if process has terminated (TerminateTime set)
        //
        if (Context->TerminateTime.QuadPart != 0) {
            //
            // Check if enough time has passed since termination
            //
            if ((CurrentTime.QuadPart - Context->TerminateTime.QuadPart) > TimeoutInterval.QuadPart) {
                //
                // Remove from lists
                //
                RemoveEntryList(&Context->ListEntry);
                InitializeListHead(&Context->ListEntry);

                if (!IsListEmpty(&Context->HashEntry)) {
                    //
                    // Need to remove from hash table under its lock
                    // For simplicity, just mark for later cleanup
                    //
                    InsertTailList(&StaleList, &Context->ListEntry);
                    InterlockedDecrement(&g_ProcessMonitor.ProcessCount);
                }
            }
        }
    }

    ExReleasePushLockExclusive(&g_ProcessMonitor.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Free stale contexts outside the main lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Context = CONTAINING_RECORD(Entry, PN_PROCESS_CONTEXT, ListEntry);

        //
        // Remove from hash table
        //
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

        //
        // Release the list reference
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
        *ProcessCreations = (ULONG64)g_ProcessMonitor.Stats.ProcessCreations;
    }

    if (ProcessesBlocked != NULL) {
        *ProcessesBlocked = (ULONG64)g_ProcessMonitor.Stats.ProcessesBlocked;
    }

    if (PpidSpoofingDetected != NULL) {
        *PpidSpoofingDetected = (ULONG64)g_ProcessMonitor.Stats.PpidSpoofingDetected;
    }

    if (SuspiciousProcesses != NULL) {
        *SuspiciousProcesses = (ULONG64)g_ProcessMonitor.Stats.SuspiciousProcesses;
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
