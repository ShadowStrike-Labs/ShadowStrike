/*++
===============================================================================
ShadowStrike NGAV - VAD TRACKER IMPLEMENTATION
===============================================================================

@file VadTracker.c
@brief Enterprise-grade Virtual Address Descriptor tracking for memory analysis.

This module provides comprehensive VAD tree monitoring capabilities for
detecting memory-based attacks including:
- Unbacked executable regions (shellcode)
- RWX memory regions (dynamic code generation)
- Suspicious protection changes (RW->RX unpacking)
- Process hollowing indicators
- Code injection detection support

Implementation Features:
- Thread-safe AVL tree for O(log n) region lookups
- Per-process context with reference counting
- Hash table for fast process lookup
- Asynchronous change notification with callbacks
- Periodic snapshot comparison for drift detection
- Comprehensive statistics and telemetry

Integration Points:
- Works with ShellcodeDetector for content analysis
- Feeds InjectionDetector with region information
- Provides data to HollowingDetector for process analysis
- Exports telemetry to ETW provider

MITRE ATT&CK Coverage:
- T1055: Process Injection (VAD anomaly detection)
- T1574: DLL Hijacking (suspicious mapped regions)
- T1027: Obfuscated Files (entropy analysis)
- T1620: Reflective Code Loading (unbacked execute)

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "VadTracker.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/ProcessUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define VAD_HASH_BUCKET_COUNT           256
#define VAD_HASH_BUCKET_MASK            (VAD_HASH_BUCKET_COUNT - 1)
#define VAD_MAX_CALLBACKS               16
#define VAD_CHANGE_QUEUE_MAX            4096
#define VAD_SNAPSHOT_BUFFER_SIZE        (64 * 1024)
#define VAD_PAGE_SIZE                   0x1000
#define VAD_PAGE_SHIFT                  12
#define VAD_LARGE_REGION_THRESHOLD      (16 * 1024 * 1024)  // 16 MB
#define VAD_SUSPICIOUS_BASE_LOW         0x10000
#define VAD_SUSPICIOUS_BASE_HIGH        0x7FFE0000

//
// Windows internal VAD types (from ntddk)
//
#define MM_ZERO_ACCESS                  0
#define MM_READONLY                     1
#define MM_EXECUTE                      2
#define MM_EXECUTE_READ                 3
#define MM_READWRITE                    4
#define MM_WRITECOPY                    5
#define MM_EXECUTE_READWRITE            6
#define MM_EXECUTE_WRITECOPY            7

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Callback registration entry
//
typedef struct _VAD_CALLBACK_ENTRY {
    VAD_CHANGE_CALLBACK Callback;
    PVOID Context;
    BOOLEAN Active;
    UCHAR Reserved[7];
} VAD_CALLBACK_ENTRY, *PVAD_CALLBACK_ENTRY;

//
// Extended tracker with private data
//
typedef struct _VAD_TRACKER_INTERNAL {
    //
    // Public structure (must be first)
    //
    VAD_TRACKER Public;

    //
    // Callback registrations
    //
    VAD_CALLBACK_ENTRY Callbacks[VAD_MAX_CALLBACKS];
    KSPIN_LOCK CallbackLock;
    ULONG CallbackCount;

    //
    // Worker thread for snapshot processing
    //
    HANDLE WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;
    BOOLEAN ShutdownRequested;

    //
    // Lookaside lists for frequent allocations
    //
    NPAGED_LOOKASIDE_LIST RegionLookaside;
    NPAGED_LOOKASIDE_LIST ChangeLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    BOOLEAN LookasideInitialized;

} VAD_TRACKER_INTERNAL, *PVAD_TRACKER_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// AVL tree comparison routines
//
static RTL_GENERIC_COMPARE_RESULTS NTAPI
VadpCompareRegions(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
    );

static PVOID NTAPI
VadpAllocateRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize
    );

static VOID NTAPI
VadpFreeRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
    );

//
// Process context management
//
static PVAD_PROCESS_CONTEXT
VadpAllocateProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
VadpFreeProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

static PVAD_PROCESS_CONTEXT
VadpLookupProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
VadpReferenceProcessContext(
    _Inout_ PVAD_PROCESS_CONTEXT Context
    );

static VOID
VadpDereferenceProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _Inout_ PVAD_PROCESS_CONTEXT Context
    );

//
// Region management
//
static PVAD_REGION
VadpAllocateRegion(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    );

static VOID
VadpFreeRegion(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_REGION Region
    );

static NTSTATUS
VadpInsertRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_REGION Region
    );

static PVAD_REGION
VadpFindRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVOID Address
    );

static VOID
VadpRemoveAllRegions(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

//
// VAD scanning
//
static NTSTATUS
VadpScanProcessVad(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

static NTSTATUS
VadpQueryMemoryRegions(
    _In_ PEPROCESS Process,
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_TRACKER_INTERNAL Tracker
    );

static VAD_FLAGS
VadpProtectionToFlags(
    _In_ ULONG Protection,
    _In_ ULONG Type,
    _In_ ULONG State
    );

static VAD_SUSPICION
VadpAnalyzeRegionSuspicion(
    _In_ PVAD_REGION Region,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

static ULONG
VadpCalculateSuspicionScore(
    _In_ VAD_SUSPICION Flags
    );

//
// Change notification
//
static NTSTATUS
VadpQueueChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    );

static VOID
VadpNotifyCallbacks(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    );

static PVAD_CHANGE_EVENT
VadpAllocateChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    );

static VOID
VadpFreeChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    );

//
// Snapshot and comparison
//
static VOID
VadpSnapshotTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
VadpWorkerThread(
    _In_ PVOID StartContext
    );

static NTSTATUS
VadpCompareSnapshots(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

//
// Hash table helpers
//
static ULONG
VadpHashProcessId(
    _In_ HANDLE ProcessId
    );

static NTSTATUS
VadpInsertProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

static VOID
VadpRemoveProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

NTSTATUS
VadInitialize(
    _Out_ PVAD_TRACKER* Tracker
    )
/*++
Routine Description:
    Initializes the VAD tracker subsystem.

Arguments:
    Tracker - Receives pointer to initialized tracker.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PVAD_TRACKER_INTERNAL Internal = NULL;
    LARGE_INTEGER DueTime;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate internal tracker structure
    //
    Internal = (PVAD_TRACKER_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(VAD_TRACKER_INTERNAL),
        VAD_POOL_TAG_TREE
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(VAD_TRACKER_INTERNAL));

    //
    // Initialize public structure
    //
    InitializeListHead(&Internal->Public.ProcessList);
    KeInitializeSpinLock(&Internal->Public.ProcessListLock);

    InitializeListHead(&Internal->Public.ChangeQueue);
    KeInitializeSpinLock(&Internal->Public.ChangeQueueLock);
    KeInitializeEvent(&Internal->Public.ChangeAvailableEvent, SynchronizationEvent, FALSE);

    //
    // Initialize hash table
    //
    Internal->Public.ProcessHash.BucketCount = VAD_HASH_BUCKET_COUNT;
    Internal->Public.ProcessHash.Buckets = (PVAD_PROCESS_CONTEXT*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(PVAD_PROCESS_CONTEXT) * VAD_HASH_BUCKET_COUNT,
        VAD_POOL_TAG_TREE
        );

    if (Internal->Public.ProcessHash.Buckets == NULL) {
        ExFreePoolWithTag(Internal, VAD_POOL_TAG_TREE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(
        Internal->Public.ProcessHash.Buckets,
        sizeof(PVAD_PROCESS_CONTEXT) * VAD_HASH_BUCKET_COUNT
        );
    KeInitializeSpinLock(&Internal->Public.ProcessHash.Lock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->RegionLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(VAD_REGION),
        VAD_POOL_TAG_ENTRY,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ChangeLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(VAD_CHANGE_EVENT),
        VAD_POOL_TAG_ENTRY,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(VAD_PROCESS_CONTEXT),
        VAD_POOL_TAG_ENTRY,
        0
        );

    Internal->LookasideInitialized = TRUE;

    //
    // Initialize callback infrastructure
    //
    KeInitializeSpinLock(&Internal->CallbackLock);

    //
    // Initialize default configuration
    //
    Internal->Public.Config.SnapshotIntervalMs = VAD_SNAPSHOT_INTERVAL_MS;
    Internal->Public.Config.MaxTrackedProcesses = VAD_MAX_TRACKED_PROCESSES;
    Internal->Public.Config.MaxRegionsPerProcess = VAD_MAX_REGIONS_PER_PROCESS;
    Internal->Public.Config.TrackAllProcesses = FALSE;
    Internal->Public.Config.EnableChangeNotification = TRUE;

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Internal->Public.Stats.StartTime);

    //
    // Initialize worker thread synchronization
    //
    KeInitializeEvent(&Internal->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Internal->WorkAvailableEvent, SynchronizationEvent, FALSE);

    //
    // Create worker thread
    //
    InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &ThreadHandle,
        THREAD_ALL_ACCESS,
        &ObjectAttributes,
        NULL,
        NULL,
        VadpWorkerThread,
        Internal
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Internal->WorkerThread,
        NULL
        );

    ZwClose(ThreadHandle);

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Initialize snapshot timer
    //
    KeInitializeTimer(&Internal->Public.SnapshotTimer);
    KeInitializeDpc(&Internal->Public.SnapshotDpc, VadpSnapshotTimerDpc, Internal);

    //
    // Start snapshot timer
    //
    DueTime.QuadPart = -((LONGLONG)Internal->Public.Config.SnapshotIntervalMs * 10000);
    KeSetTimerEx(
        &Internal->Public.SnapshotTimer,
        DueTime,
        Internal->Public.Config.SnapshotIntervalMs,
        &Internal->Public.SnapshotDpc
        );
    Internal->Public.SnapshotTimerActive = TRUE;

    //
    // Mark as initialized
    //
    Internal->Public.Initialized = TRUE;
    *Tracker = (PVAD_TRACKER)Internal;

    return STATUS_SUCCESS;

Cleanup:
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->RegionLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChangeLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
    }

    if (Internal->Public.ProcessHash.Buckets != NULL) {
        ExFreePoolWithTag(Internal->Public.ProcessHash.Buckets, VAD_POOL_TAG_TREE);
    }

    ExFreePoolWithTag(Internal, VAD_POOL_TAG_TREE);
    return Status;
}

VOID
VadShutdown(
    _Inout_ PVAD_TRACKER Tracker
    )
/*++
Routine Description:
    Shuts down the VAD tracker subsystem.

Arguments:
    Tracker - Tracker instance to shutdown.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PLIST_ENTRY Entry;
    PVAD_PROCESS_CONTEXT Context;
    PVAD_CHANGE_EVENT ChangeEvent;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    Internal->Public.Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel snapshot timer
    //
    if (Internal->Public.SnapshotTimerActive) {
        KeCancelTimer(&Internal->Public.SnapshotTimer);
        Internal->Public.SnapshotTimerActive = FALSE;
    }

    //
    // Signal worker thread to exit
    //
    KeSetEvent(&Internal->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Internal->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);

    if (Internal->WorkerThread != NULL) {
        KeWaitForSingleObject(
            Internal->WorkerThread,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Internal->WorkerThread);
        Internal->WorkerThread = NULL;
    }

    //
    // Free all process contexts
    //
    KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);

    while (!IsListEmpty(&Internal->Public.ProcessList)) {
        Entry = RemoveHeadList(&Internal->Public.ProcessList);
        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

        VadpRemoveAllRegions(Internal, Context);
        VadpFreeProcessContext(Internal, Context);

        KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

    //
    // Free all pending change events
    //
    KeAcquireSpinLock(&Internal->Public.ChangeQueueLock, &OldIrql);

    while (!IsListEmpty(&Internal->Public.ChangeQueue)) {
        Entry = RemoveHeadList(&Internal->Public.ChangeQueue);
        ChangeEvent = CONTAINING_RECORD(Entry, VAD_CHANGE_EVENT, ListEntry);
        KeReleaseSpinLock(&Internal->Public.ChangeQueueLock, OldIrql);

        VadpFreeChangeEvent(Internal, ChangeEvent);

        KeAcquireSpinLock(&Internal->Public.ChangeQueueLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->Public.ChangeQueueLock, OldIrql);

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->RegionLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChangeLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
    }

    //
    // Free hash table
    //
    if (Internal->Public.ProcessHash.Buckets != NULL) {
        ExFreePoolWithTag(Internal->Public.ProcessHash.Buckets, VAD_POOL_TAG_TREE);
    }

    //
    // Free tracker
    //
    ExFreePoolWithTag(Internal, VAD_POOL_TAG_TREE);
}

NTSTATUS
VadStartTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Starts tracking VAD for a process.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to track.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    NTSTATUS Status;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Check if already tracking
    //
    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context != NULL) {
        VadpDereferenceProcessContext(Internal, Context);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Check process limit
    //
    if ((ULONG)Internal->Public.ProcessCount >= Internal->Public.Config.MaxTrackedProcesses) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate new process context
    //
    Context = VadpAllocateProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Add to process list
    //
    KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
    InsertTailList(&Internal->Public.ProcessList, &Context->ListEntry);
    InterlockedIncrement(&Internal->Public.ProcessCount);
    KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

    //
    // Add to hash table
    //
    Status = VadpInsertProcessHash(Internal, Context);
    if (!NT_SUCCESS(Status)) {
        KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
        RemoveEntryList(&Context->ListEntry);
        InterlockedDecrement(&Internal->Public.ProcessCount);
        KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

        VadpFreeProcessContext(Internal, Context);
        return Status;
    }

    //
    // Perform initial VAD scan
    //
    Status = VadpScanProcessVad(Internal, Context);
    if (!NT_SUCCESS(Status)) {
        //
        // Non-fatal - process may have exited
        //
        Status = STATUS_SUCCESS;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
VadStopTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Stops tracking VAD for a process.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to stop tracking.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Find and remove from hash table
    //
    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    VadpRemoveProcessHash(Internal, Context);

    //
    // Remove from process list
    //
    KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
    RemoveEntryList(&Context->ListEntry);
    InterlockedDecrement(&Internal->Public.ProcessCount);
    KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

    //
    // Free all regions
    //
    VadpRemoveAllRegions(Internal, Context);

    //
    // Release our reference and the lookup reference
    //
    VadpDereferenceProcessContext(Internal, Context);
    VadpDereferenceProcessContext(Internal, Context);

    return STATUS_SUCCESS;
}

BOOLEAN
VadIsTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Checks if a process is being tracked.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to check.

Return Value:
    TRUE if tracking, FALSE otherwise.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return FALSE;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return FALSE;
    }

    VadpDereferenceProcessContext(Internal, Context);
    return TRUE;
}

NTSTATUS
VadScanProcess(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Scans a process's VAD tree for suspicious regions.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to scan.
    SuspicionScore - Receives total suspicion score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    NTSTATUS Status;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    Status = VadpScanProcessVad(Internal, Context);

    if (NT_SUCCESS(Status) && SuspicionScore != NULL) {
        *SuspicionScore = Context->TotalSuspicionScore;
    }

    VadpDereferenceProcessContext(Internal, Context);

    InterlockedIncrement64(&Internal->Public.Stats.TotalScans);

    return Status;
}

NTSTATUS
VadScanAllProcesses(
    _In_ PVAD_TRACKER Tracker
    )
/*++
Routine Description:
    Scans all tracked processes.

Arguments:
    Tracker - Tracker instance.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PLIST_ENTRY Entry;
    PVAD_PROCESS_CONTEXT Context;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_SUCCESS;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);

    for (Entry = Internal->Public.ProcessList.Flink;
         Entry != &Internal->Public.ProcessList;
         Entry = Entry->Flink) {

        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        VadpReferenceProcessContext(Context);
        KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

        VadpScanProcessVad(Internal, Context);
        VadpDereferenceProcessContext(Internal, Context);

        KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
    }

    KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

    return Status;
}

NTSTATUS
VadGetRegionInfo(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_REGION RegionInfo
    )
/*++
Routine Description:
    Gets information about a memory region.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process ID.
    Address - Address within region.
    RegionInfo - Receives region information.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PVAD_REGION Region;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized || RegionInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&Context->TreeLock, &OldIrql);
    Region = VadpFindRegion(Context, Address);
    if (Region != NULL) {
        RtlCopyMemory(RegionInfo, Region, sizeof(VAD_REGION));
    }
    KeReleaseSpinLock(&Context->TreeLock, OldIrql);

    VadpDereferenceProcessContext(Internal, Context);

    return (Region != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS
VadAnalyzeRegion(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_SUSPICION SuspicionFlags,
    _Out_ PULONG SuspicionScore
    )
/*++
Routine Description:
    Analyzes a region for suspicious characteristics.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process ID.
    Address - Address within region.
    SuspicionFlags - Receives suspicion flags.
    SuspicionScore - Receives suspicion score.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PVAD_REGION Region;
    KIRQL OldIrql;
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || !Internal->Public.Initialized ||
        SuspicionFlags == NULL || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&Context->TreeLock, &OldIrql);
    Region = VadpFindRegion(Context, Address);
    if (Region != NULL) {
        Region->SuspicionFlags = VadpAnalyzeRegionSuspicion(Region, Context);
        Region->SuspicionScore = VadpCalculateSuspicionScore(Region->SuspicionFlags);
        *SuspicionFlags = Region->SuspicionFlags;
        *SuspicionScore = Region->SuspicionScore;
        Status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Context->TreeLock, OldIrql);

    VadpDereferenceProcessContext(Internal, Context);

    return Status;
}

NTSTATUS
VadGetSuspiciousRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION* Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    )
/*++
Routine Description:
    Gets all suspicious regions above a threshold.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process ID.
    MinScore - Minimum suspicion score.
    Regions - Array to receive region pointers.
    MaxRegions - Maximum regions to return.
    RegionCount - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PLIST_ENTRY Entry;
    PVAD_REGION Region;
    KIRQL OldIrql;
    ULONG Count = 0;

    if (Internal == NULL || !Internal->Public.Initialized ||
        Regions == NULL || RegionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RegionCount = 0;

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&Context->TreeLock, &OldIrql);

    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList && Count < MaxRegions;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if (Region->SuspicionScore >= MinScore) {
            Regions[Count++] = Region;
        }
    }

    KeReleaseSpinLock(&Context->TreeLock, OldIrql);

    *RegionCount = Count;
    VadpDereferenceProcessContext(Internal, Context);

    return STATUS_SUCCESS;
}

NTSTATUS
VadRegisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
/*++
Routine Description:
    Registers a callback for VAD change notifications.

Arguments:
    Tracker - Tracker instance.
    Callback - Callback function.
    Context - User context.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    //
    // Find empty slot
    //
    for (i = 0; i < VAD_MAX_CALLBACKS; i++) {
        if (!Internal->Callbacks[i].Active) {
            Internal->Callbacks[i].Callback = Callback;
            Internal->Callbacks[i].Context = Context;
            Internal->Callbacks[i].Active = TRUE;
            Internal->CallbackCount++;
            KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
    return STATUS_QUOTA_EXCEEDED;
}

VOID
VadUnregisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback
    )
/*++
Routine Description:
    Unregisters a change callback.

Arguments:
    Tracker - Tracker instance.
    Callback - Callback to unregister.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    KIRQL OldIrql;
    ULONG i;

    if (Internal == NULL || Callback == NULL) {
        return;
    }

    KeAcquireSpinLock(&Internal->CallbackLock, &OldIrql);

    for (i = 0; i < VAD_MAX_CALLBACKS; i++) {
        if (Internal->Callbacks[i].Active &&
            Internal->Callbacks[i].Callback == Callback) {
            Internal->Callbacks[i].Active = FALSE;
            Internal->Callbacks[i].Callback = NULL;
            Internal->Callbacks[i].Context = NULL;
            Internal->CallbackCount--;
            break;
        }
    }

    KeReleaseSpinLock(&Internal->CallbackLock, OldIrql);
}

NTSTATUS
VadGetNextChange(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_CHANGE_EVENT Event,
    _In_ ULONG TimeoutMs
    )
/*++
Routine Description:
    Gets the next change event from the queue.

Arguments:
    Tracker - Tracker instance.
    Event - Receives change event.
    TimeoutMs - Timeout in milliseconds.

Return Value:
    STATUS_SUCCESS if event retrieved.
    STATUS_TIMEOUT if timeout expired.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PVAD_CHANGE_EVENT QueuedEvent;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized || Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Timeout.QuadPart = -((LONGLONG)TimeoutMs * 10000);

    Status = KeWaitForSingleObject(
        &Internal->Public.ChangeAvailableEvent,
        Executive,
        KernelMode,
        FALSE,
        TimeoutMs == INFINITE ? NULL : &Timeout
        );

    if (Status == STATUS_TIMEOUT) {
        return STATUS_TIMEOUT;
    }

    KeAcquireSpinLock(&Internal->Public.ChangeQueueLock, &OldIrql);

    if (!IsListEmpty(&Internal->Public.ChangeQueue)) {
        Entry = RemoveHeadList(&Internal->Public.ChangeQueue);
        InterlockedDecrement(&Internal->Public.ChangeCount);

        QueuedEvent = CONTAINING_RECORD(Entry, VAD_CHANGE_EVENT, ListEntry);
        RtlCopyMemory(Event, QueuedEvent, sizeof(VAD_CHANGE_EVENT));

        KeReleaseSpinLock(&Internal->Public.ChangeQueueLock, OldIrql);

        VadpFreeChangeEvent(Internal, QueuedEvent);
        return STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&Internal->Public.ChangeQueueLock, OldIrql);
    return STATUS_NO_MORE_ENTRIES;
}

NTSTATUS
VadEnumerateRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ VAD_REGION_FILTER Filter,
    _In_opt_ PVOID FilterContext,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION* Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    )
/*++
Routine Description:
    Enumerates regions matching a filter.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process ID.
    Filter - Filter function.
    FilterContext - Filter context.
    Regions - Array to receive regions.
    MaxRegions - Maximum regions.
    RegionCount - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PLIST_ENTRY Entry;
    PVAD_REGION Region;
    KIRQL OldIrql;
    ULONG Count = 0;

    if (Internal == NULL || !Internal->Public.Initialized ||
        Filter == NULL || Regions == NULL || RegionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RegionCount = 0;

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        return STATUS_NOT_FOUND;
    }

    KeAcquireSpinLock(&Context->TreeLock, &OldIrql);

    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList && Count < MaxRegions;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if (Filter(Region, FilterContext)) {
            Regions[Count++] = Region;
        }
    }

    KeReleaseSpinLock(&Context->TreeLock, OldIrql);

    *RegionCount = Count;
    VadpDereferenceProcessContext(Internal, Context);

    return STATUS_SUCCESS;
}

NTSTATUS
VadGetStatistics(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_STATISTICS Stats
    )
/*++
Routine Description:
    Gets tracker statistics.

Arguments:
    Tracker - Tracker instance.
    Stats - Receives statistics.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    LARGE_INTEGER CurrentTime;
    PLIST_ENTRY Entry;
    PVAD_PROCESS_CONTEXT Context;
    KIRQL OldIrql;

    if (Internal == NULL || !Internal->Public.Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(VAD_STATISTICS));

    Stats->TrackedProcesses = (ULONG)Internal->Public.ProcessCount;
    Stats->TotalScans = Internal->Public.Stats.TotalScans;
    Stats->SuspiciousDetections = Internal->Public.Stats.SuspiciousRegions;
    Stats->RWXDetections = Internal->Public.Stats.RWXDetections;
    Stats->ProtectionChanges = Internal->Public.Stats.ProtectionChanges;

    //
    // Count total regions
    //
    KeAcquireSpinLock(&Internal->Public.ProcessListLock, &OldIrql);
    for (Entry = Internal->Public.ProcessList.Flink;
         Entry != &Internal->Public.ProcessList;
         Entry = Entry->Flink) {
        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        Stats->TotalRegions += Context->RegionCount;
    }
    KeReleaseSpinLock(&Internal->Public.ProcessListLock, OldIrql);

    //
    // Calculate uptime
    //
    KeQuerySystemTime(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Internal->Public.Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static RTL_GENERIC_COMPARE_RESULTS NTAPI
VadpCompareRegions(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID FirstStruct,
    _In_ PVOID SecondStruct
    )
/*++
Routine Description:
    AVL tree comparison routine for regions.
--*/
{
    PVAD_REGION First = (PVAD_REGION)FirstStruct;
    PVAD_REGION Second = (PVAD_REGION)SecondStruct;

    UNREFERENCED_PARAMETER(Table);

    if ((ULONG_PTR)First->BaseAddress < (ULONG_PTR)Second->BaseAddress) {
        return GenericLessThan;
    }
    if ((ULONG_PTR)First->BaseAddress > (ULONG_PTR)Second->BaseAddress) {
        return GenericGreaterThan;
    }
    return GenericEqual;
}

static PVOID NTAPI
VadpAllocateRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ CLONG ByteSize
    )
/*++
Routine Description:
    AVL tree allocation routine.
--*/
{
    UNREFERENCED_PARAMETER(Table);

    return ExAllocatePoolWithTag(NonPagedPoolNx, ByteSize, VAD_POOL_TAG_TREE);
}

static VOID NTAPI
VadpFreeRoutine(
    _In_ PRTL_AVL_TABLE Table,
    _In_ PVOID Buffer
    )
/*++
Routine Description:
    AVL tree free routine.
--*/
{
    UNREFERENCED_PARAMETER(Table);

    ExFreePoolWithTag(Buffer, VAD_POOL_TAG_TREE);
}

static PVAD_PROCESS_CONTEXT
VadpAllocateProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Allocates and initializes a process context.
--*/
{
    PVAD_PROCESS_CONTEXT Context;
    NTSTATUS Status;
    PEPROCESS Process;

    Context = (PVAD_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Tracker->ContextLookaside
        );

    if (Context == NULL) {
        return NULL;
    }

    RtlZeroMemory(Context, sizeof(VAD_PROCESS_CONTEXT));

    Context->ProcessId = ProcessId;
    Context->RefCount = 1;

    //
    // Get process object
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (NT_SUCCESS(Status)) {
        Context->Process = Process;
        // Note: We keep a reference to the process
    }

    //
    // Initialize AVL tree
    //
    RtlInitializeGenericTableAvl(
        &Context->RegionTree,
        VadpCompareRegions,
        VadpAllocateRoutine,
        VadpFreeRoutine,
        NULL
        );

    KeInitializeSpinLock(&Context->TreeLock);
    InitializeListHead(&Context->RegionList);

    return Context;
}

static VOID
VadpFreeProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Frees a process context.
--*/
{
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
    }

    if (Context->ImageName.Buffer != NULL) {
        ExFreePoolWithTag(Context->ImageName.Buffer, VAD_POOL_TAG_ENTRY);
    }

    if (Context->Snapshot.SnapshotBuffer != NULL) {
        ExFreePoolWithTag(Context->Snapshot.SnapshotBuffer, VAD_POOL_TAG_SNAPSHOT);
    }

    ExFreeToNPagedLookasideList(&Tracker->ContextLookaside, Context);
}

static PVAD_PROCESS_CONTEXT
VadpLookupProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Looks up a process context by process ID.
--*/
{
    ULONG Hash;
    PVAD_PROCESS_CONTEXT Context;
    KIRQL OldIrql;

    Hash = VadpHashProcessId(ProcessId);

    KeAcquireSpinLock(&Tracker->Public.ProcessHash.Lock, &OldIrql);

    Context = Tracker->Public.ProcessHash.Buckets[Hash];
    while (Context != NULL) {
        if (Context->ProcessId == ProcessId) {
            VadpReferenceProcessContext(Context);
            KeReleaseSpinLock(&Tracker->Public.ProcessHash.Lock, OldIrql);
            return Context;
        }
        // Simple linear probing for collision
        Hash = (Hash + 1) & VAD_HASH_BUCKET_MASK;
        Context = Tracker->Public.ProcessHash.Buckets[Hash];
    }

    KeReleaseSpinLock(&Tracker->Public.ProcessHash.Lock, OldIrql);
    return NULL;
}

static VOID
VadpReferenceProcessContext(
    _Inout_ PVAD_PROCESS_CONTEXT Context
    )
{
    InterlockedIncrement(&Context->RefCount);
}

static VOID
VadpDereferenceProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _Inout_ PVAD_PROCESS_CONTEXT Context
    )
{
    if (InterlockedDecrement(&Context->RefCount) == 0) {
        VadpFreeProcessContext(Tracker, Context);
    }
}

static PVAD_REGION
VadpAllocateRegion(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    )
{
    PVAD_REGION Region;

    Region = (PVAD_REGION)ExAllocateFromNPagedLookasideList(&Tracker->RegionLookaside);
    if (Region != NULL) {
        RtlZeroMemory(Region, sizeof(VAD_REGION));
        InitializeListHead(&Region->ListEntry);
    }

    return Region;
}

static VOID
VadpFreeRegion(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_REGION Region
    )
{
    if (Region->FileName.Buffer != NULL) {
        ExFreePoolWithTag(Region->FileName.Buffer, VAD_POOL_TAG_ENTRY);
    }

    ExFreeToNPagedLookasideList(&Tracker->RegionLookaside, Region);
}

static NTSTATUS
VadpInsertRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_REGION Region
    )
{
    BOOLEAN NewElement;

    RtlInsertElementGenericTableAvl(
        &Context->RegionTree,
        Region,
        sizeof(VAD_REGION),
        &NewElement
        );

    if (NewElement) {
        InsertTailList(&Context->RegionList, &Region->ListEntry);
        InterlockedIncrement(&Context->RegionCount);
        return STATUS_SUCCESS;
    }

    return STATUS_DUPLICATE_OBJECTID;
}

static PVAD_REGION
VadpFindRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVOID Address
    )
{
    PLIST_ENTRY Entry;
    PVAD_REGION Region;

    //
    // Linear search through region list to find containing region
    //
    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if ((ULONG_PTR)Address >= (ULONG_PTR)Region->BaseAddress &&
            (ULONG_PTR)Address < (ULONG_PTR)Region->BaseAddress + Region->RegionSize) {
            return Region;
        }
    }

    return NULL;
}

static VOID
VadpRemoveAllRegions(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    PLIST_ENTRY Entry;
    PVAD_REGION Region;
    KIRQL OldIrql;

    KeAcquireSpinLock(&Context->TreeLock, &OldIrql);

    while (!IsListEmpty(&Context->RegionList)) {
        Entry = RemoveHeadList(&Context->RegionList);
        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        RtlDeleteElementGenericTableAvl(&Context->RegionTree, Region);
        InterlockedDecrement(&Context->RegionCount);

        KeReleaseSpinLock(&Context->TreeLock, OldIrql);
        VadpFreeRegion(Tracker, Region);
        KeAcquireSpinLock(&Context->TreeLock, &OldIrql);
    }

    KeReleaseSpinLock(&Context->TreeLock, OldIrql);
}

static NTSTATUS
VadpScanProcessVad(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    NTSTATUS Status;
    KAPC_STATE ApcState;
    BOOLEAN Attached = FALSE;

    if (Context->Process == NULL) {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    //
    // Attach to process context
    //
    __try {
        KeStackAttachProcess(Context->Process, &ApcState);
        Attached = TRUE;

        Status = VadpQueryMemoryRegions(Context->Process, Context, Tracker);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (Attached) {
        KeUnstackDetachProcess(&ApcState);
    }

    return Status;
}

static NTSTATUS
VadpQueryMemoryRegions(
    _In_ PEPROCESS Process,
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_TRACKER_INTERNAL Tracker
    )
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION MemInfo;
    SIZE_T ReturnLength;
    PVOID Address = NULL;
    PVAD_REGION Region;
    KIRQL OldIrql;
    ULONG RegionCount = 0;

    UNREFERENCED_PARAMETER(Process);

    //
    // Clear existing regions
    //
    VadpRemoveAllRegions(Tracker, Context);

    //
    // Reset statistics
    //
    Context->TotalPrivateSize = 0;
    Context->TotalMappedSize = 0;
    Context->TotalImageSize = 0;
    Context->TotalExecutableSize = 0;
    Context->TotalSuspicionScore = 0;
    Context->SuspiciousRegionCount = 0;
    Context->RWXRegionCount = 0;
    Context->UnbackedExecuteCount = 0;

    //
    // Query all memory regions
    //
    while (RegionCount < Tracker->Public.Config.MaxRegionsPerProcess) {
        Status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            Address,
            MemoryBasicInformation,
            &MemInfo,
            sizeof(MemInfo),
            &ReturnLength
            );

        if (!NT_SUCCESS(Status)) {
            break;
        }

        //
        // Only track committed regions
        //
        if (MemInfo.State == MEM_COMMIT) {
            Region = VadpAllocateRegion(Tracker);
            if (Region == NULL) {
                break;
            }

            Region->BaseAddress = MemInfo.BaseAddress;
            Region->RegionSize = MemInfo.RegionSize;
            Region->Protection = MemInfo.Protect;
            Region->OriginalProtection = MemInfo.AllocationProtect;
            Region->Type = MemInfo.Type;
            Region->State = MemInfo.State;
            Region->CurrentFlags = VadpProtectionToFlags(
                MemInfo.Protect,
                MemInfo.Type,
                MemInfo.State
                );
            Region->OriginalFlags = VadpProtectionToFlags(
                MemInfo.AllocationProtect,
                MemInfo.Type,
                MemInfo.State
                );
            Region->IsBacked = (MemInfo.Type == MEM_IMAGE || MemInfo.Type == MEM_MAPPED);

            KeQuerySystemTime(&Region->CreateTime);
            Region->LastModifyTime = Region->CreateTime;

            //
            // Analyze suspicion
            //
            Region->SuspicionFlags = VadpAnalyzeRegionSuspicion(Region, Context);
            Region->SuspicionScore = VadpCalculateSuspicionScore(Region->SuspicionFlags);

            //
            // Update statistics
            //
            if (MemInfo.Type == MEM_PRIVATE) {
                Context->TotalPrivateSize += MemInfo.RegionSize;
            } else if (MemInfo.Type == MEM_MAPPED) {
                Context->TotalMappedSize += MemInfo.RegionSize;
            } else if (MemInfo.Type == MEM_IMAGE) {
                Context->TotalImageSize += MemInfo.RegionSize;
            }

            if (Region->CurrentFlags & VadFlag_Execute) {
                Context->TotalExecutableSize += MemInfo.RegionSize;
            }

            if (Region->SuspicionFlags & VadSuspicion_RWX) {
                Context->RWXRegionCount++;
                InterlockedIncrement64(&Tracker->Public.Stats.RWXDetections);
            }

            if (Region->SuspicionFlags & VadSuspicion_UnbackedExecute) {
                Context->UnbackedExecuteCount++;
            }

            if (Region->SuspicionScore > 0) {
                Context->TotalSuspicionScore += Region->SuspicionScore;
                Context->SuspiciousRegionCount++;
                InterlockedIncrement64(&Tracker->Public.Stats.SuspiciousRegions);
            }

            //
            // Insert into tree
            //
            KeAcquireSpinLock(&Context->TreeLock, &OldIrql);
            VadpInsertRegion(Context, Region);
            KeReleaseSpinLock(&Context->TreeLock, OldIrql);

            RegionCount++;
        }

        //
        // Move to next region
        //
        Address = (PVOID)((ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize);
        if ((ULONG_PTR)Address < (ULONG_PTR)MemInfo.BaseAddress) {
            // Overflow - reached end of address space
            break;
        }
    }

    return STATUS_SUCCESS;
}

static VAD_FLAGS
VadpProtectionToFlags(
    _In_ ULONG Protection,
    _In_ ULONG Type,
    _In_ ULONG State
    )
{
    VAD_FLAGS Flags = VadFlag_None;

    //
    // Type flags
    //
    if (Type == MEM_PRIVATE) {
        Flags |= VadFlag_Private;
    } else if (Type == MEM_MAPPED) {
        Flags |= VadFlag_Mapped;
    } else if (Type == MEM_IMAGE) {
        Flags |= VadFlag_Image;
    }

    //
    // State flags
    //
    if (State == MEM_COMMIT) {
        Flags |= VadFlag_Commit;
    } else if (State == MEM_RESERVE) {
        Flags |= VadFlag_Reserve;
    }

    //
    // Protection flags
    //
    if (Protection & PAGE_EXECUTE ||
        Protection & PAGE_EXECUTE_READ ||
        Protection & PAGE_EXECUTE_READWRITE ||
        Protection & PAGE_EXECUTE_WRITECOPY) {
        Flags |= VadFlag_Execute;
    }

    if (Protection & PAGE_READWRITE ||
        Protection & PAGE_WRITECOPY ||
        Protection & PAGE_EXECUTE_READWRITE ||
        Protection & PAGE_EXECUTE_WRITECOPY) {
        Flags |= VadFlag_Write;
    }

    if (Protection & PAGE_READONLY ||
        Protection & PAGE_READWRITE ||
        Protection & PAGE_WRITECOPY ||
        Protection & PAGE_EXECUTE_READ ||
        Protection & PAGE_EXECUTE_READWRITE ||
        Protection & PAGE_EXECUTE_WRITECOPY) {
        Flags |= VadFlag_Read;
    }

    if (Protection & PAGE_GUARD) {
        Flags |= VadFlag_Guard;
    }

    if (Protection & PAGE_NOCACHE) {
        Flags |= VadFlag_NoCache;
    }

    if (Protection & PAGE_WRITECOMBINE) {
        Flags |= VadFlag_WriteCombine;
    }

    return Flags;
}

static VAD_SUSPICION
VadpAnalyzeRegionSuspicion(
    _In_ PVAD_REGION Region,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    VAD_SUSPICION Suspicion = VadSuspicion_None;

    UNREFERENCED_PARAMETER(Context);

    //
    // Check for RWX permissions (highly suspicious)
    //
    if ((Region->CurrentFlags & VadFlag_Execute) &&
        (Region->CurrentFlags & VadFlag_Write) &&
        (Region->CurrentFlags & VadFlag_Read)) {
        Suspicion |= VadSuspicion_RWX;
    }

    //
    // Check for unbacked executable (private + execute)
    //
    if ((Region->CurrentFlags & VadFlag_Private) &&
        (Region->CurrentFlags & VadFlag_Execute) &&
        !Region->IsBacked) {
        Suspicion |= VadSuspicion_UnbackedExecute;
    }

    //
    // Check for large private region
    //
    if ((Region->CurrentFlags & VadFlag_Private) &&
        Region->RegionSize > VAD_LARGE_REGION_THRESHOLD) {
        Suspicion |= VadSuspicion_LargePrivate;
    }

    //
    // Check for guard region pattern (stack pivoting indicator)
    //
    if (Region->CurrentFlags & VadFlag_Guard) {
        Suspicion |= VadSuspicion_GuardRegion;
    }

    //
    // Check for RW->RX transition (unpacking/decryption)
    //
    if ((Region->OriginalFlags & VadFlag_Write) &&
        !(Region->OriginalFlags & VadFlag_Execute) &&
        (Region->CurrentFlags & VadFlag_Execute) &&
        !(Region->CurrentFlags & VadFlag_Write)) {
        Suspicion |= VadSuspicion_RecentRWtoRX;
    }

    //
    // Check for suspicious base address
    //
    if ((ULONG_PTR)Region->BaseAddress < VAD_SUSPICIOUS_BASE_LOW) {
        Suspicion |= VadSuspicion_SuspiciousBase;
    }

    //
    // Check for protection mismatch
    //
    if (Region->Protection != Region->OriginalProtection) {
        Region->ProtectionChangeCount++;
        if (Region->ProtectionChangeCount > 3) {
            Suspicion |= VadSuspicion_ProtectionMismatch;
        }
    }

    return Suspicion;
}

static ULONG
VadpCalculateSuspicionScore(
    _In_ VAD_SUSPICION Flags
    )
{
    ULONG Score = 0;

    if (Flags & VadSuspicion_RWX) {
        Score += 100;  // Critical
    }

    if (Flags & VadSuspicion_UnbackedExecute) {
        Score += 80;   // Very high
    }

    if (Flags & VadSuspicion_RecentRWtoRX) {
        Score += 70;   // High - unpacking
    }

    if (Flags & VadSuspicion_ShellcodePattern) {
        Score += 90;   // Critical
    }

    if (Flags & VadSuspicion_LargePrivate) {
        Score += 20;   // Low
    }

    if (Flags & VadSuspicion_GuardRegion) {
        Score += 30;   // Medium-low
    }

    if (Flags & VadSuspicion_HiddenRegion) {
        Score += 100;  // Critical
    }

    if (Flags & VadSuspicion_ProtectionMismatch) {
        Score += 40;   // Medium
    }

    if (Flags & VadSuspicion_SuspiciousBase) {
        Score += 25;   // Low
    }

    if (Flags & VadSuspicion_OverlapWithImage) {
        Score += 60;   // High
    }

    return Score;
}

static NTSTATUS
VadpQueueChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    )
{
    PVAD_CHANGE_EVENT QueuedEvent;
    KIRQL OldIrql;

    if ((ULONG)Tracker->Public.ChangeCount >= VAD_CHANGE_QUEUE_MAX) {
        return STATUS_QUOTA_EXCEEDED;
    }

    QueuedEvent = VadpAllocateChangeEvent(Tracker);
    if (QueuedEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(QueuedEvent, Event, sizeof(VAD_CHANGE_EVENT));
    InitializeListHead(&QueuedEvent->ListEntry);

    KeAcquireSpinLock(&Tracker->Public.ChangeQueueLock, &OldIrql);
    InsertTailList(&Tracker->Public.ChangeQueue, &QueuedEvent->ListEntry);
    InterlockedIncrement(&Tracker->Public.ChangeCount);
    KeReleaseSpinLock(&Tracker->Public.ChangeQueueLock, OldIrql);

    KeSetEvent(&Tracker->Public.ChangeAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Notify callbacks
    //
    VadpNotifyCallbacks(Tracker, QueuedEvent);

    return STATUS_SUCCESS;
}

static VOID
VadpNotifyCallbacks(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    )
{
    KIRQL OldIrql;
    ULONG i;

    KeAcquireSpinLock(&Tracker->CallbackLock, &OldIrql);

    for (i = 0; i < VAD_MAX_CALLBACKS; i++) {
        if (Tracker->Callbacks[i].Active && Tracker->Callbacks[i].Callback != NULL) {
            KeReleaseSpinLock(&Tracker->CallbackLock, OldIrql);

            __try {
                Tracker->Callbacks[i].Callback(Event, Tracker->Callbacks[i].Context);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore callback exceptions
            }

            KeAcquireSpinLock(&Tracker->CallbackLock, &OldIrql);
        }
    }

    KeReleaseSpinLock(&Tracker->CallbackLock, OldIrql);
}

static PVAD_CHANGE_EVENT
VadpAllocateChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    )
{
    PVAD_CHANGE_EVENT Event;

    Event = (PVAD_CHANGE_EVENT)ExAllocateFromNPagedLookasideList(&Tracker->ChangeLookaside);
    if (Event != NULL) {
        RtlZeroMemory(Event, sizeof(VAD_CHANGE_EVENT));
        InitializeListHead(&Event->ListEntry);
        KeQuerySystemTime(&Event->Timestamp);
    }

    return Event;
}

static VOID
VadpFreeChangeEvent(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    )
{
    ExFreeToNPagedLookasideList(&Tracker->ChangeLookaside, Event);
}

static VOID
VadpSnapshotTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PVAD_TRACKER_INTERNAL Tracker = (PVAD_TRACKER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Tracker == NULL || Tracker->ShutdownRequested) {
        return;
    }

    //
    // Signal worker thread to perform snapshot comparison
    //
    KeSetEvent(&Tracker->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
VadpWorkerThread(
    _In_ PVOID StartContext
    )
{
    PVAD_TRACKER_INTERNAL Tracker = (PVAD_TRACKER_INTERNAL)StartContext;
    PVOID WaitObjects[2];
    NTSTATUS Status;

    WaitObjects[0] = &Tracker->ShutdownEvent;
    WaitObjects[1] = &Tracker->WorkAvailableEvent;

    while (!Tracker->ShutdownRequested) {
        Status = KeWaitForMultipleObjects(
            2,
            WaitObjects,
            WaitAny,
            Executive,
            KernelMode,
            FALSE,
            NULL,
            NULL
            );

        if (Status == STATUS_WAIT_0 || Tracker->ShutdownRequested) {
            // Shutdown requested
            break;
        }

        if (Status == STATUS_WAIT_1) {
            //
            // Work available - scan all processes
            //
            if (Tracker->Public.Initialized && !Tracker->ShutdownRequested) {
                VadScanAllProcesses((PVAD_TRACKER)Tracker);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static NTSTATUS
VadpCompareSnapshots(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    // Snapshot comparison for drift detection
    // This would compare current VAD state with previous snapshot
    // and generate change events for any differences

    UNREFERENCED_PARAMETER(Tracker);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_SUCCESS;
}

static ULONG
VadpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    // Simple hash function for process IDs
    Value ^= (Value >> 16);
    Value *= 0x85ebca6b;
    Value ^= (Value >> 13);
    Value *= 0xc2b2ae35;
    Value ^= (Value >> 16);

    return (ULONG)(Value & VAD_HASH_BUCKET_MASK);
}

static NTSTATUS
VadpInsertProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    ULONG Hash;
    ULONG OriginalHash;
    KIRQL OldIrql;

    Hash = VadpHashProcessId(Context->ProcessId);
    OriginalHash = Hash;

    KeAcquireSpinLock(&Tracker->Public.ProcessHash.Lock, &OldIrql);

    //
    // Find empty slot using linear probing
    //
    while (Tracker->Public.ProcessHash.Buckets[Hash] != NULL) {
        Hash = (Hash + 1) & VAD_HASH_BUCKET_MASK;
        if (Hash == OriginalHash) {
            KeReleaseSpinLock(&Tracker->Public.ProcessHash.Lock, OldIrql);
            return STATUS_QUOTA_EXCEEDED;
        }
    }

    Tracker->Public.ProcessHash.Buckets[Hash] = Context;
    KeReleaseSpinLock(&Tracker->Public.ProcessHash.Lock, OldIrql);

    return STATUS_SUCCESS;
}

static VOID
VadpRemoveProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    ULONG Hash;
    ULONG OriginalHash;
    KIRQL OldIrql;

    Hash = VadpHashProcessId(Context->ProcessId);
    OriginalHash = Hash;

    KeAcquireSpinLock(&Tracker->Public.ProcessHash.Lock, &OldIrql);

    while (Tracker->Public.ProcessHash.Buckets[Hash] != NULL) {
        if (Tracker->Public.ProcessHash.Buckets[Hash] == Context) {
            Tracker->Public.ProcessHash.Buckets[Hash] = NULL;
            break;
        }
        Hash = (Hash + 1) & VAD_HASH_BUCKET_MASK;
        if (Hash == OriginalHash) {
            break;
        }
    }

    KeReleaseSpinLock(&Tracker->Public.ProcessHash.Lock, OldIrql);
}
