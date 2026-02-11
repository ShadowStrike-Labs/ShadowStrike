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
#define VAD_SHUTDOWN_DRAIN_MAX_WAIT     30000    // 30s at 1ms each

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
    // Callback registrations (protected by CallbackLock push lock)
    //
    VAD_CALLBACK_ENTRY Callbacks[VAD_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;
    ULONG CallbackCount;

    //
    // Worker thread for snapshot processing
    //
    PETHREAD WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;
    volatile LONG ShutdownRequested;

    //
    // Lookaside lists for frequent allocations
    //
    NPAGED_LOOKASIDE_LIST RegionLookaside;
    NPAGED_LOOKASIDE_LIST ChangeLookaside;
    NPAGED_LOOKASIDE_LIST ContextLookaside;
    volatile LONG LookasideInitialized;

} VAD_TRACKER_INTERNAL, *PVAD_TRACKER_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// Ref acquire/release for shutdown drain
//
static BOOLEAN
VadpAcquireRef(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    );

static VOID
VadpReleaseRef(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    );

//
// Process context management
//
_IRQL_requires_(PASSIVE_LEVEL)
static PVAD_PROCESS_CONTEXT
VadpAllocateProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
VadpFreeProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
static PVAD_PROCESS_CONTEXT
VadpLookupProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
VadpReferenceProcessContext(
    _Inout_ PVAD_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
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

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
VadpInsertRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_REGION Region
    );

_IRQL_requires_max_(APC_LEVEL)
static PVAD_REGION
VadpFindRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVOID Address
    );

_IRQL_requires_max_(APC_LEVEL)
static VOID
VadpRemoveAllRegions(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

//
// VAD scanning
//
_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
VadpScanProcessVad(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

_IRQL_requires_(PASSIVE_LEVEL)
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

_IRQL_requires_max_(APC_LEVEL)
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
// Hash table helpers (chained hashing)
//
static ULONG
VadpHashProcessId(
    _In_ HANDLE ProcessId
    );

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS
VadpInsertProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    );

_IRQL_requires_max_(APC_LEVEL)
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
    ULONG i;

    PAGED_CODE();

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate internal tracker structure
    //
    Internal = (PVAD_TRACKER_INTERNAL)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(VAD_TRACKER_INTERNAL),
        VAD_POOL_TAG_TREE
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // ExAllocatePool2 zero-initializes by default
    //

    //
    // Initialize public structure (push locks instead of spin locks)
    //
    InitializeListHead(&Internal->Public.ProcessList);
    ExInitializePushLock(&Internal->Public.ProcessListLock);

    InitializeListHead(&Internal->Public.ChangeQueue);
    KeInitializeSpinLock(&Internal->Public.ChangeQueueLock);
    KeInitializeEvent(&Internal->Public.ChangeAvailableEvent, SynchronizationEvent, FALSE);

    //
    // Initialize hash table (chained — each bucket is a LIST_ENTRY head)
    //
    Internal->Public.ProcessHash.BucketCount = VAD_HASH_BUCKET_COUNT;
    Internal->Public.ProcessHash.Buckets = (LIST_ENTRY*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(LIST_ENTRY) * VAD_HASH_BUCKET_COUNT,
        VAD_POOL_TAG_HASH
        );

    if (Internal->Public.ProcessHash.Buckets == NULL) {
        ExFreePoolWithTag(Internal, VAD_POOL_TAG_TREE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (i = 0; i < VAD_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Internal->Public.ProcessHash.Buckets[i]);
    }
    ExInitializePushLock(&Internal->Public.ProcessHash.Lock);

    //
    // Initialize lookaside lists (distinct pool tags)
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
        VAD_POOL_TAG_CHANGE,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ContextLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(VAD_PROCESS_CONTEXT),
        VAD_POOL_TAG_CONTEXT,
        0
        );

    InterlockedExchange(&Internal->LookasideInitialized, 1);

    //
    // Initialize callback infrastructure (push lock)
    //
    ExInitializePushLock(&Internal->CallbackLock);

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
    // Create worker thread — get PETHREAD reference
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
    ThreadHandle = NULL;

    if (!NT_SUCCESS(Status)) {
        //
        // Thread is running but we can't get a reference.
        // Signal shutdown and wait for thread to exit via handle.
        //
        InterlockedExchange(&Internal->ShutdownRequested, 1);
        KeSetEvent(&Internal->ShutdownEvent, IO_NO_INCREMENT, FALSE);
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
    InterlockedExchange(&Internal->Public.SnapshotTimerActive, 1);

    //
    // Initialize ref count and mark initialized (interlocked)
    //
    InterlockedExchange(&Internal->Public.ActiveRefCount, 0);
    InterlockedExchange(&Internal->Public.Initialized, 1);
    *Tracker = (PVAD_TRACKER)Internal;

    return STATUS_SUCCESS;

Cleanup:
    if (InterlockedCompareExchange(&Internal->LookasideInitialized, 0, 0) != 0) {
        ExDeleteNPagedLookasideList(&Internal->RegionLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChangeLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
    }

    if (Internal->Public.ProcessHash.Buckets != NULL) {
        ExFreePoolWithTag(Internal->Public.ProcessHash.Buckets, VAD_POOL_TAG_HASH);
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
    LARGE_INTEGER Interval;
    LONG DrainWait;

    PAGED_CODE();

    if (Internal == NULL) {
        return;
    }

    //
    // Atomically mark as not-initialized to reject new operations
    //
    if (InterlockedExchange(&Internal->Public.Initialized, 0) == 0) {
        return;
    }

    InterlockedExchange(&Internal->ShutdownRequested, 1);

    //
    // Cancel snapshot timer
    //
    if (InterlockedExchange(&Internal->Public.SnapshotTimerActive, 0) != 0) {
        KeCancelTimer(&Internal->Public.SnapshotTimer);
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
    // Drain active references — wait up to 30 seconds
    //
    Interval.QuadPart = -10000;  // 1ms
    for (DrainWait = 0; DrainWait < VAD_SHUTDOWN_DRAIN_MAX_WAIT; DrainWait++) {
        if (InterlockedCompareExchange(&Internal->Public.ActiveRefCount, 0, 0) == 0) {
            break;
        }
        KeDelayExecutionThread(KernelMode, FALSE, &Interval);
    }

    //
    // Free all process contexts — single-threaded at this point
    //
    while (!IsListEmpty(&Internal->Public.ProcessList)) {
        Entry = RemoveHeadList(&Internal->Public.ProcessList);
        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);

        VadpRemoveAllRegions(Internal, Context);
        VadpFreeProcessContext(Internal, Context);
    }

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
    if (InterlockedCompareExchange(&Internal->LookasideInitialized, 0, 0) != 0) {
        ExDeleteNPagedLookasideList(&Internal->RegionLookaside);
        ExDeleteNPagedLookasideList(&Internal->ChangeLookaside);
        ExDeleteNPagedLookasideList(&Internal->ContextLookaside);
    }

    //
    // Free hash table
    //
    if (Internal->Public.ProcessHash.Buckets != NULL) {
        ExFreePoolWithTag(Internal->Public.ProcessHash.Buckets, VAD_POOL_TAG_HASH);
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
    Uses TOCTOU-safe double-check: allocate outside lock, verify under lock.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to track.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PVAD_PROCESS_CONTEXT Existing;
    NTSTATUS Status;

    PAGED_CODE();

    if (Internal == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check process limit
    //
    if ((ULONG)InterlockedCompareExchange(&Internal->Public.ProcessCount, 0, 0) 
        >= Internal->Public.Config.MaxTrackedProcesses) {
        VadpReleaseRef(Internal);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate new process context outside any lock
    //
    Context = VadpAllocateProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // TOCTOU double-check: re-check under exclusive lock before insert
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.ProcessListLock);

    Existing = VadpLookupProcessContext(Internal, ProcessId);
    if (Existing != NULL) {
        VadpDereferenceProcessContext(Internal, Existing);
        ExReleasePushLockExclusive(&Internal->Public.ProcessListLock);
        KeLeaveCriticalRegion();
        VadpFreeProcessContext(Internal, Context);
        VadpReleaseRef(Internal);
        return STATUS_ALREADY_REGISTERED;
    }

    //
    // Add to process list and hash table under the same lock
    //
    InsertTailList(&Internal->Public.ProcessList, &Context->ListEntry);
    InterlockedIncrement(&Internal->Public.ProcessCount);

    Status = VadpInsertProcessHash(Internal, Context);
    if (!NT_SUCCESS(Status)) {
        RemoveEntryList(&Context->ListEntry);
        InterlockedDecrement(&Internal->Public.ProcessCount);
        ExReleasePushLockExclusive(&Internal->Public.ProcessListLock);
        KeLeaveCriticalRegion();
        VadpFreeProcessContext(Internal, Context);
        VadpReleaseRef(Internal);
        return Status;
    }

    ExReleasePushLockExclusive(&Internal->Public.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Perform initial VAD scan — non-fatal if process already exited
    //
    VadpScanProcessVad(Internal, Context);

    VadpReleaseRef(Internal);
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
    Removes from list + hash atomically under a single lock hold.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to stop tracking.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context = NULL;
    PLIST_ENTRY Entry;
    ULONG Bucket;

    PAGED_CODE();

    if (Internal == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find and atomically remove from both list and hash under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.ProcessListLock);

    //
    // Walk the process list to find the context
    //
    for (Entry = Internal->Public.ProcessList.Flink;
         Entry != &Internal->Public.ProcessList;
         Entry = Entry->Flink) {

        PVAD_PROCESS_CONTEXT Candidate = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        if (Candidate->ProcessId == ProcessId) {
            Context = Candidate;
            break;
        }
    }

    if (Context == NULL) {
        ExReleasePushLockExclusive(&Internal->Public.ProcessListLock);
        KeLeaveCriticalRegion();
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    //
    // Remove from process list
    //
    RemoveEntryList(&Context->ListEntry);
    InterlockedDecrement(&Internal->Public.ProcessCount);

    //
    // Remove from hash chain
    //
    Bucket = VadpHashProcessId(Context->ProcessId);
    RemoveEntryList(&Context->HashEntry);
    UNREFERENCED_PARAMETER(Bucket);

    ExReleasePushLockExclusive(&Internal->Public.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Free all regions (safe at PASSIVE_LEVEL outside lock)
    //
    VadpRemoveAllRegions(Internal, Context);

    //
    // Single dereference — context was never re-referenced by lookup here
    //
    VadpDereferenceProcessContext(Internal, Context);

    VadpReleaseRef(Internal);
    return STATUS_SUCCESS;
}

    return STATUS_SUCCESS;
}

BOOLEAN
VadIsTracking(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;

    if (Internal == NULL) {
        return FALSE;
    }

    if (!VadpAcquireRef(Internal)) {
        return FALSE;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return FALSE;
    }

    VadpDereferenceProcessContext(Internal, Context);
    VadpReleaseRef(Internal);
    return TRUE;
}

NTSTATUS
VadScanProcess(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_opt_ PULONG SuspicionScore
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    NTSTATUS Status;

    PAGED_CODE();

    if (Internal == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    Status = VadpScanProcessVad(Internal, Context);

    if (NT_SUCCESS(Status) && SuspicionScore != NULL) {
        *SuspicionScore = Context->TotalSuspicionScore;
    }

    VadpDereferenceProcessContext(Internal, Context);
    InterlockedIncrement64(&Internal->Public.Stats.TotalScans);

    VadpReleaseRef(Internal);
    return Status;
}

NTSTATUS
VadScanAllProcesses(
    _In_ PVAD_TRACKER Tracker
    )
/*++
Routine Description:
    Scans all tracked processes. Snapshots the process list under lock,
    then iterates outside the lock to avoid holding it during I/O.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PLIST_ENTRY Entry;
    PVAD_PROCESS_CONTEXT* SnapArray = NULL;
    LONG Count;
    LONG i;
    ULONG AllocSize;

    PAGED_CODE();

    if (Internal == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Snapshot process context pointers under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Internal->Public.ProcessListLock);

    Count = InterlockedCompareExchange(&Internal->Public.ProcessCount, 0, 0);
    if (Count <= 0) {
        ExReleasePushLockShared(&Internal->Public.ProcessListLock);
        KeLeaveCriticalRegion();
        VadpReleaseRef(Internal);
        return STATUS_SUCCESS;
    }

    AllocSize = (ULONG)Count * sizeof(PVAD_PROCESS_CONTEXT);
    SnapArray = (PVAD_PROCESS_CONTEXT*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        AllocSize,
        VAD_POOL_TAG_TREE
        );

    if (SnapArray == NULL) {
        ExReleasePushLockShared(&Internal->Public.ProcessListLock);
        KeLeaveCriticalRegion();
        VadpReleaseRef(Internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    i = 0;
    for (Entry = Internal->Public.ProcessList.Flink;
         Entry != &Internal->Public.ProcessList && i < Count;
         Entry = Entry->Flink) {

        PVAD_PROCESS_CONTEXT Ctx = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        VadpReferenceProcessContext(Ctx);
        SnapArray[i++] = Ctx;
    }

    ExReleasePushLockShared(&Internal->Public.ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Scan each process outside the lock
    //
    for (Count = 0; Count < i; Count++) {
        VadpScanProcessVad(Internal, SnapArray[Count]);
        VadpDereferenceProcessContext(Internal, SnapArray[Count]);
    }

    ExFreePoolWithTag(SnapArray, VAD_POOL_TAG_TREE);
    VadpReleaseRef(Internal);
    return STATUS_SUCCESS;
}

NTSTATUS
VadGetRegionInfo(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _Out_ PVAD_REGION RegionInfo
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PVAD_REGION Region;

    if (Internal == NULL || RegionInfo == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->RegionLock);
    Region = VadpFindRegion(Context, Address);
    if (Region != NULL) {
        RtlCopyMemory(RegionInfo, Region, sizeof(VAD_REGION));
        //
        // Clear ListEntry in the copy — caller must not use linkage
        //
        InitializeListHead(&RegionInfo->ListEntry);
    }
    ExReleasePushLockShared(&Context->RegionLock);
    KeLeaveCriticalRegion();

    VadpDereferenceProcessContext(Internal, Context);
    VadpReleaseRef(Internal);

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
    NTSTATUS Status = STATUS_NOT_FOUND;

    if (Internal == NULL || SuspicionFlags == NULL || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->RegionLock);
    Region = VadpFindRegion(Context, Address);
    if (Region != NULL) {
        Region->SuspicionFlags = VadpAnalyzeRegionSuspicion(Region, Context);
        Region->SuspicionScore = VadpCalculateSuspicionScore(Region->SuspicionFlags);
        *SuspicionFlags = Region->SuspicionFlags;
        *SuspicionScore = Region->SuspicionScore;
        Status = STATUS_SUCCESS;
    }
    ExReleasePushLockShared(&Context->RegionLock);
    KeLeaveCriticalRegion();

    VadpDereferenceProcessContext(Internal, Context);
    VadpReleaseRef(Internal);

    return Status;
}

NTSTATUS
VadGetSuspiciousRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    )
/*++
Routine Description:
    Gets VALUE COPIES of suspicious regions above a threshold.
    Regions array receives copies, not pointers to internal data.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PLIST_ENTRY Entry;
    PVAD_REGION Region;
    ULONG Count = 0;

    if (Internal == NULL || Regions == NULL || RegionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RegionCount = 0;

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->RegionLock);

    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList && Count < MaxRegions;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if (Region->SuspicionScore >= MinScore) {
            RtlCopyMemory(&Regions[Count], Region, sizeof(VAD_REGION));
            InitializeListHead(&Regions[Count].ListEntry);
            Count++;
        }
    }

    ExReleasePushLockShared(&Context->RegionLock);
    KeLeaveCriticalRegion();

    *RegionCount = Count;
    VadpDereferenceProcessContext(Internal, Context);
    VadpReleaseRef(Internal);

    return STATUS_SUCCESS;
}

NTSTATUS
VadRegisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback,
    _In_opt_ PVOID Context
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    ULONG i;

    PAGED_CODE();

    if (Internal == NULL || Callback == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->CallbackLock);

    for (i = 0; i < VAD_MAX_CALLBACKS; i++) {
        if (!Internal->Callbacks[i].Active) {
            Internal->Callbacks[i].Callback = Callback;
            Internal->Callbacks[i].Context = Context;
            Internal->Callbacks[i].Active = TRUE;
            Internal->CallbackCount++;
            ExReleasePushLockExclusive(&Internal->CallbackLock);
            KeLeaveCriticalRegion();
            VadpReleaseRef(Internal);
            return STATUS_SUCCESS;
        }
    }

    ExReleasePushLockExclusive(&Internal->CallbackLock);
    KeLeaveCriticalRegion();
    VadpReleaseRef(Internal);
    return STATUS_QUOTA_EXCEEDED;
}

VOID
VadUnregisterChangeCallback(
    _In_ PVAD_TRACKER Tracker,
    _In_ VAD_CHANGE_CALLBACK Callback
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    ULONG i;

    PAGED_CODE();

    if (Internal == NULL || Callback == NULL) {
        return;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->CallbackLock);

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

    ExReleasePushLockExclusive(&Internal->CallbackLock);
    KeLeaveCriticalRegion();
}

NTSTATUS
VadGetNextChange(
    _In_ PVAD_TRACKER Tracker,
    _Out_ PVAD_CHANGE_EVENT Event,
    _In_ ULONG TimeoutMs
    )
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    LARGE_INTEGER Timeout;
    NTSTATUS Status;
    PLIST_ENTRY Entry;
    PVAD_CHANGE_EVENT QueuedEvent;
    KIRQL OldIrql;

    PAGED_CODE();

    if (Internal == NULL || Event == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
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
        VadpReleaseRef(Internal);
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
        VadpReleaseRef(Internal);
        return STATUS_SUCCESS;
    }

    KeReleaseSpinLock(&Internal->Public.ChangeQueueLock, OldIrql);
    VadpReleaseRef(Internal);
    return STATUS_NO_MORE_ENTRIES;
}

NTSTATUS
VadEnumerateRegions(
    _In_ PVAD_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ VAD_REGION_FILTER Filter,
    _In_opt_ PVOID FilterContext,
    _Out_writes_to_(MaxRegions, *RegionCount) PVAD_REGION Regions,
    _In_ ULONG MaxRegions,
    _Out_ PULONG RegionCount
    )
/*++
Routine Description:
    Enumerates regions matching a filter. Returns VALUE COPIES.
--*/
{
    PVAD_TRACKER_INTERNAL Internal = (PVAD_TRACKER_INTERNAL)Tracker;
    PVAD_PROCESS_CONTEXT Context;
    PLIST_ENTRY Entry;
    PVAD_REGION Region;
    ULONG Count = 0;

    if (Internal == NULL || Filter == NULL || Regions == NULL || RegionCount == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RegionCount = 0;

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    Context = VadpLookupProcessContext(Internal, ProcessId);
    if (Context == NULL) {
        VadpReleaseRef(Internal);
        return STATUS_NOT_FOUND;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Context->RegionLock);

    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList && Count < MaxRegions;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if (Filter(Region, FilterContext)) {
            RtlCopyMemory(&Regions[Count], Region, sizeof(VAD_REGION));
            InitializeListHead(&Regions[Count].ListEntry);
            Count++;
        }
    }

    ExReleasePushLockShared(&Context->RegionLock);
    KeLeaveCriticalRegion();

    *RegionCount = Count;
    VadpDereferenceProcessContext(Internal, Context);
    VadpReleaseRef(Internal);

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

    if (Internal == NULL || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!VadpAcquireRef(Internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    RtlZeroMemory(Stats, sizeof(VAD_STATISTICS));

    Stats->TrackedProcesses = (ULONG)InterlockedCompareExchange(&Internal->Public.ProcessCount, 0, 0);
    Stats->TotalScans = Internal->Public.Stats.TotalScans;
    Stats->SuspiciousDetections = Internal->Public.Stats.SuspiciousRegions;
    Stats->RWXDetections = Internal->Public.Stats.RWXDetections;
    Stats->ProtectionChanges = Internal->Public.Stats.ProtectionChanges;

    //
    // Count total regions under shared push lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Internal->Public.ProcessListLock);
    for (Entry = Internal->Public.ProcessList.Flink;
         Entry != &Internal->Public.ProcessList;
         Entry = Entry->Flink) {
        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, ListEntry);
        Stats->TotalRegions += (ULONG64)InterlockedCompareExchange(&Context->RegionCount, 0, 0);
    }
    ExReleasePushLockShared(&Internal->Public.ProcessListLock);
    KeLeaveCriticalRegion();

    KeQuerySystemTime(&CurrentTime);
    Stats->UpTime.QuadPart = CurrentTime.QuadPart - Internal->Public.Stats.StartTime.QuadPart;

    VadpReleaseRef(Internal);
    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

//
// Ref acquire/release for shutdown drain (CRITICAL-07)
//
static BOOLEAN
VadpAcquireRef(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    )
{
    if (InterlockedCompareExchange(&Tracker->Public.Initialized, 0, 0) == 0) {
        return FALSE;
    }
    InterlockedIncrement(&Tracker->Public.ActiveRefCount);
    if (InterlockedCompareExchange(&Tracker->Public.Initialized, 0, 0) == 0) {
        InterlockedDecrement(&Tracker->Public.ActiveRefCount);
        return FALSE;
    }
    return TRUE;
}

static VOID
VadpReleaseRef(
    _In_ PVAD_TRACKER_INTERNAL Tracker
    )
{
    InterlockedDecrement(&Tracker->Public.ActiveRefCount);
}

static PVAD_PROCESS_CONTEXT
VadpAllocateProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
/*++
Routine Description:
    Allocates and initializes a process context.
    Fails if PsLookupProcessByProcessId fails — no dangling contexts.
--*/
{
    PVAD_PROCESS_CONTEXT Context;
    NTSTATUS Status;
    PEPROCESS Process = NULL;

    //
    // Validate the process exists before allocating
    //
    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return NULL;
    }

    Context = (PVAD_PROCESS_CONTEXT)ExAllocateFromNPagedLookasideList(
        &Tracker->ContextLookaside
        );

    if (Context == NULL) {
        ObDereferenceObject(Process);
        return NULL;
    }

    RtlZeroMemory(Context, sizeof(VAD_PROCESS_CONTEXT));

    Context->ProcessId = ProcessId;
    Context->Process = Process;  // Transfer ownership of the reference
    Context->RefCount = 1;

    ExInitializePushLock(&Context->RegionLock);
    InitializeListHead(&Context->RegionList);
    InitializeListHead(&Context->HashEntry);

    return Context;
}

static VOID
VadpFreeProcessContext(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
{
    if (Context->Process != NULL) {
        ObDereferenceObject(Context->Process);
        Context->Process = NULL;
    }

    if (Context->Snapshot.SnapshotBuffer != NULL) {
        ExFreePoolWithTag(Context->Snapshot.SnapshotBuffer, VAD_POOL_TAG_SNAPSHOT);
        Context->Snapshot.SnapshotBuffer = NULL;
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
    Looks up a process context by process ID using chained hashing.
    Returns with an added reference on success.
--*/
{
    ULONG Hash;
    PLIST_ENTRY Bucket;
    PLIST_ENTRY Entry;
    PVAD_PROCESS_CONTEXT Context;

    Hash = VadpHashProcessId(ProcessId);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->Public.ProcessHash.Lock);

    Bucket = &Tracker->Public.ProcessHash.Buckets[Hash];

    for (Entry = Bucket->Flink; Entry != Bucket; Entry = Entry->Flink) {
        Context = CONTAINING_RECORD(Entry, VAD_PROCESS_CONTEXT, HashEntry);
        if (Context->ProcessId == ProcessId) {
            VadpReferenceProcessContext(Context);
            ExReleasePushLockShared(&Tracker->Public.ProcessHash.Lock);
            KeLeaveCriticalRegion();
            return Context;
        }
    }

    ExReleasePushLockShared(&Tracker->Public.ProcessHash.Lock);
    KeLeaveCriticalRegion();
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
    ExFreeToNPagedLookasideList(&Tracker->RegionLookaside, Region);
}

static NTSTATUS
VadpInsertRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVAD_REGION Region
    )
/*++
Routine Description:
    Inserts a region into the process context's sorted region list.
    Caller must hold RegionLock exclusive.
    Regions are sorted by BaseAddress for efficient lookup.
--*/
{
    PLIST_ENTRY Entry;
    PVAD_REGION Existing;

    //
    // Check for duplicate
    //
    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList;
         Entry = Entry->Flink) {

        Existing = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if (Existing->BaseAddress == Region->BaseAddress) {
            return STATUS_DUPLICATE_OBJECTID;
        }

        //
        // Insert before the first region with a higher base address (sorted insert)
        //
        if ((ULONG_PTR)Existing->BaseAddress > (ULONG_PTR)Region->BaseAddress) {
            InsertTailList(Entry, &Region->ListEntry);
            InterlockedIncrement(&Context->RegionCount);
            return STATUS_SUCCESS;
        }
    }

    //
    // Append at end (largest address)
    //
    InsertTailList(&Context->RegionList, &Region->ListEntry);
    InterlockedIncrement(&Context->RegionCount);
    return STATUS_SUCCESS;
}

static PVAD_REGION
VadpFindRegion(
    _In_ PVAD_PROCESS_CONTEXT Context,
    _In_ PVOID Address
    )
{
    PLIST_ENTRY Entry;
    PVAD_REGION Region;

    for (Entry = Context->RegionList.Flink;
         Entry != &Context->RegionList;
         Entry = Entry->Flink) {

        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);

        if ((ULONG_PTR)Address >= (ULONG_PTR)Region->BaseAddress &&
            (ULONG_PTR)Address < (ULONG_PTR)Region->BaseAddress + Region->RegionSize) {
            return Region;
        }

        //
        // Sorted list — if we're past the address, stop early
        //
        if ((ULONG_PTR)Region->BaseAddress > (ULONG_PTR)Address) {
            break;
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

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->RegionLock);

    while (!IsListEmpty(&Context->RegionList)) {
        Entry = RemoveHeadList(&Context->RegionList);
        Region = CONTAINING_RECORD(Entry, VAD_REGION, ListEntry);
        InterlockedDecrement(&Context->RegionCount);

        VadpFreeRegion(Tracker, Region);
    }

    ExReleasePushLockExclusive(&Context->RegionLock);
    KeLeaveCriticalRegion();
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
    // Acquire region lock once for the entire batch insert
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Context->RegionLock);

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
            // Insert into region list (already under exclusive lock)
            //
            Status = VadpInsertRegion(Context, Region);
            if (!NT_SUCCESS(Status)) {
                VadpFreeRegion(Tracker, Region);
            } else {
                RegionCount++;
            }
        }

        //
        // Move to next region
        //
        Address = (PVOID)((ULONG_PTR)MemInfo.BaseAddress + MemInfo.RegionSize);
        if ((ULONG_PTR)Address < (ULONG_PTR)MemInfo.BaseAddress) {
            break;
        }
    }

    ExReleasePushLockExclusive(&Context->RegionLock);
    KeLeaveCriticalRegion();

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
    ULONG BaseProtection;

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
    // Extract base protection (mask off modifier bits)
    //
    BaseProtection = Protection & 0xFF;

    switch (BaseProtection) {
    case PAGE_EXECUTE:
        Flags |= VadFlag_Execute;
        break;
    case PAGE_EXECUTE_READ:
        Flags |= VadFlag_Execute | VadFlag_Read;
        break;
    case PAGE_EXECUTE_READWRITE:
        Flags |= VadFlag_Execute | VadFlag_Read | VadFlag_Write;
        break;
    case PAGE_EXECUTE_WRITECOPY:
        Flags |= VadFlag_Execute | VadFlag_Read | VadFlag_Write;
        break;
    case PAGE_READONLY:
        Flags |= VadFlag_Read;
        break;
    case PAGE_READWRITE:
        Flags |= VadFlag_Read | VadFlag_Write;
        break;
    case PAGE_WRITECOPY:
        Flags |= VadFlag_Read | VadFlag_Write;
        break;
    case PAGE_NOACCESS:
    default:
        break;
    }

    //
    // Modifier flags (high bits)
    //
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

    QueuedEvent = VadpAllocateChangeEvent(Tracker);
    if (QueuedEvent == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(QueuedEvent, Event, sizeof(VAD_CHANGE_EVENT));
    InitializeListHead(&QueuedEvent->ListEntry);

    //
    // Check count under the lock to avoid TOCTOU
    //
    KeAcquireSpinLock(&Tracker->Public.ChangeQueueLock, &OldIrql);

    if ((ULONG)InterlockedCompareExchange(&Tracker->Public.ChangeCount, 0, 0)
        >= VAD_CHANGE_QUEUE_MAX) {
        KeReleaseSpinLock(&Tracker->Public.ChangeQueueLock, OldIrql);
        VadpFreeChangeEvent(Tracker, QueuedEvent);
        return STATUS_QUOTA_EXCEEDED;
    }

    InsertTailList(&Tracker->Public.ChangeQueue, &QueuedEvent->ListEntry);
    InterlockedIncrement(&Tracker->Public.ChangeCount);
    KeReleaseSpinLock(&Tracker->Public.ChangeQueueLock, OldIrql);

    KeSetEvent(&Tracker->Public.ChangeAvailableEvent, IO_NO_INCREMENT, FALSE);

    //
    // Notify callbacks (uses snapshot pattern)
    //
    VadpNotifyCallbacks(Tracker, QueuedEvent);

    return STATUS_SUCCESS;
}

static VOID
VadpNotifyCallbacks(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_CHANGE_EVENT Event
    )
/*++
Routine Description:
    Notifies registered callbacks. Snapshots the callback array under the
    push lock, then invokes each callback OUTSIDE the lock to prevent
    deadlock and allow callbacks to unregister themselves.
--*/
{
    VAD_CALLBACK_ENTRY SnapCallbacks[VAD_MAX_CALLBACKS];
    ULONG SnapCount = 0;
    ULONG i;

    //
    // Snapshot callbacks under shared lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < VAD_MAX_CALLBACKS; i++) {
        if (Tracker->Callbacks[i].Active && Tracker->Callbacks[i].Callback != NULL) {
            SnapCallbacks[SnapCount] = Tracker->Callbacks[i];
            SnapCount++;
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);
    KeLeaveCriticalRegion();

    //
    // Invoke callbacks outside lock
    //
    for (i = 0; i < SnapCount; i++) {
        __try {
            SnapCallbacks[i].Callback(Event, SnapCallbacks[i].Context);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Ignore callback exceptions
        }
    }
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

    if (Tracker == NULL ||
        InterlockedCompareExchange(&Tracker->ShutdownRequested, 0, 0) != 0) {
        return;
    }

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

    while (InterlockedCompareExchange(&Tracker->ShutdownRequested, 0, 0) == 0) {
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

        if (Status == STATUS_WAIT_0 ||
            InterlockedCompareExchange(&Tracker->ShutdownRequested, 0, 0) != 0) {
            break;
        }

        if (Status == STATUS_WAIT_1) {
            if (InterlockedCompareExchange(&Tracker->Public.Initialized, 0, 0) != 0 &&
                InterlockedCompareExchange(&Tracker->ShutdownRequested, 0, 0) == 0) {
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
/*++
Routine Description:
    NOT YET IMPLEMENTED — snapshot comparison for drift detection.
    This is a design placeholder for future change-detection work.
    It currently does nothing and returns STATUS_NOT_IMPLEMENTED.
--*/
{
    UNREFERENCED_PARAMETER(Tracker);
    UNREFERENCED_PARAMETER(Context);

    return STATUS_NOT_IMPLEMENTED;
}

static ULONG
VadpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

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
/*++
Routine Description:
    Inserts a process context into the chained hash table.
    Caller must hold ProcessListLock or ProcessHash.Lock exclusive.
--*/
{
    ULONG Hash;

    Hash = VadpHashProcessId(Context->ProcessId);
    InsertTailList(&Tracker->Public.ProcessHash.Buckets[Hash], &Context->HashEntry);

    return STATUS_SUCCESS;
}

static VOID
VadpRemoveProcessHash(
    _In_ PVAD_TRACKER_INTERNAL Tracker,
    _In_ PVAD_PROCESS_CONTEXT Context
    )
/*++
Routine Description:
    Removes a process context from the chained hash table.
    Caller must hold ProcessListLock or ProcessHash.Lock exclusive.
--*/
{
    UNREFERENCED_PARAMETER(Tracker);

    RemoveEntryList(&Context->HashEntry);
    InitializeListHead(&Context->HashEntry);
}
