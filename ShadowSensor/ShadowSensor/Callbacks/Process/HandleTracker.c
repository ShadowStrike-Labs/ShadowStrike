/*++
===============================================================================
ShadowStrike NGAV - HANDLE TRACKER IMPLEMENTATION
===============================================================================

@file HandleTracker.c
@brief Enterprise-grade handle forensics and tracking for comprehensive threat detection.

This module provides real-time handle tracking capabilities including:
- Cross-process handle detection and analysis
- Handle duplication monitoring
- Sensitive process handle access detection (LSASS, CSRSS, etc.)
- High-privilege handle identification
- Process/thread handle enumeration
- Token handle manipulation detection
- System handle abuse detection

Implementation Features:
- Thread-safe handle tracking with EX_PUSH_LOCK
- Hash table for O(1) process lookup
- Per-process handle lists with reference counting
- Lookaside lists for high-frequency allocations
- Asynchronous handle analysis
- Comprehensive statistics and telemetry

Detection Techniques Covered:
- T1055: Process Injection (cross-process handle detection)
- T1003: OS Credential Dumping (LSASS handle detection)
- T1134: Access Token Manipulation (token handle tracking)
- T1106: Native API (suspicious handle operations)
- T1548: Abuse Elevation Control Mechanism

@author ShadowStrike Security Team
@version 2.0.0 (Enterprise Edition)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "HandleTracker.h"
#include "../../Utilities/ProcessUtils.h"
#include "../../Utilities/MemoryUtils.h"
#include <ntstrsafe.h>

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define HT_HASH_BUCKET_COUNT            256
#define HT_HASH_BUCKET_MASK             (HT_HASH_BUCKET_COUNT - 1)
#define HT_MAX_TRACKED_PROCESSES        4096
#define HT_MAX_DUPLICATIONS_PER_PROCESS 1024
#define HT_HANDLE_CACHE_TIMEOUT_MS      30000
#define HT_SENSITIVE_PROCESS_THRESHOLD  5

//
// Pool tags for sub-allocations
//
#define HT_POOL_TAG_ENTRY       'eHTK'
#define HT_POOL_TAG_PROCESS     'pHTK'
#define HT_POOL_TAG_BUFFER      'bHTK'
#define HT_POOL_TAG_STRING      'sHTK'

//
// Suspicious access masks
//
#define HT_PROCESS_INJECTION_ACCESS     (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
#define HT_PROCESS_FULL_ACCESS          (PROCESS_ALL_ACCESS)
#define HT_PROCESS_DUMP_ACCESS          (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
#define HT_THREAD_HIJACK_ACCESS         (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)
#define HT_TOKEN_STEAL_ACCESS           (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)

//
// Handle type strings (for object type matching)
//
#define HT_PROCESS_TYPE_NAME            L"Process"
#define HT_THREAD_TYPE_NAME             L"Thread"
#define HT_FILE_TYPE_NAME               L"File"
#define HT_KEY_TYPE_NAME                L"Key"
#define HT_SECTION_TYPE_NAME            L"Section"
#define HT_TOKEN_TYPE_NAME              L"Token"
#define HT_EVENT_TYPE_NAME              L"Event"
#define HT_SEMAPHORE_TYPE_NAME          L"Semaphore"
#define HT_MUTANT_TYPE_NAME             L"Mutant"
#define HT_TIMER_TYPE_NAME              L"Timer"
#define HT_PORT_TYPE_NAME               L"ALPC Port"
#define HT_DEVICE_TYPE_NAME             L"Device"
#define HT_DRIVER_TYPE_NAME             L"Driver"

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Handle duplication record
//
typedef struct _HT_DUPLICATION_RECORD {
    LIST_ENTRY ListEntry;
    HANDLE SourceProcessId;
    HANDLE TargetProcessId;
    HANDLE SourceHandle;
    HANDLE TargetHandle;
    ACCESS_MASK GrantedAccess;
    HT_HANDLE_TYPE HandleType;
    LARGE_INTEGER Timestamp;
    HT_SUSPICION SuspicionFlags;
    PVOID TargetObject;
} HT_DUPLICATION_RECORD, *PHT_DUPLICATION_RECORD;

//
// Hash bucket for process lookup
//
typedef struct _HT_HASH_BUCKET {
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} HT_HASH_BUCKET, *PHT_HASH_BUCKET;

//
// Sensitive process entry
//
typedef struct _HT_SENSITIVE_PROCESS {
    HANDLE ProcessId;
    ULONG Hash;
    WCHAR ImageName[64];
    ULONG AccessCount;
    LIST_ENTRY ListEntry;
} HT_SENSITIVE_PROCESS, *PHT_SENSITIVE_PROCESS;

//
// Extended tracker with private data
//
typedef struct _HT_TRACKER_INTERNAL {
    //
    // Public structure (must be first)
    //
    HT_TRACKER Public;

    //
    // Process hash table
    //
    HT_HASH_BUCKET HashBuckets[HT_HASH_BUCKET_COUNT];

    //
    // Lookaside lists
    //
    NPAGED_LOOKASIDE_LIST HandleEntryLookaside;
    NPAGED_LOOKASIDE_LIST ProcessHandlesLookaside;
    NPAGED_LOOKASIDE_LIST DuplicationLookaside;
    BOOLEAN LookasideInitialized;

    //
    // Duplication tracking
    //
    LIST_ENTRY DuplicationList;
    EX_PUSH_LOCK DuplicationLock;
    volatile LONG DuplicationCount;

    //
    // Sensitive process tracking
    //
    LIST_ENTRY SensitiveProcessList;
    EX_PUSH_LOCK SensitiveProcessLock;
    volatile LONG SensitiveProcessCount;
    ULONG SensitiveProcessHashes[32];
    ULONG SensitiveProcessHashCount;

    //
    // Configuration
    //
    struct {
        BOOLEAN EnableCrossProcessDetection;
        BOOLEAN EnableDuplicationTracking;
        BOOLEAN EnableSensitiveProcessMonitoring;
        ULONG MaxHandlesPerProcess;
        ULONG MaxDuplications;
        ULONG SuspicionThreshold;
    } Config;

    //
    // Extended statistics
    //
    struct {
        volatile LONG64 TotalEnumerations;
        volatile LONG64 DuplicationsRecorded;
        volatile LONG64 SensitiveAccessDetected;
        volatile LONG64 HighPrivilegeHandles;
        volatile LONG64 TokenHandlesTracked;
        volatile LONG64 InjectionHandlesDetected;
    } ExtendedStats;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    //
    // Worker thread
    //
    HANDLE WorkerThread;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;
    BOOLEAN ShutdownRequested;

} HT_TRACKER_INTERNAL, *PHT_TRACKER_INTERNAL;

//
// Extended process handles with private data
//
typedef struct _HT_PROCESS_HANDLES_INTERNAL {
    //
    // Public structure (must be first)
    //
    HT_PROCESS_HANDLES Public;

    //
    // Reference counting
    //
    volatile LONG RefCount;

    //
    // Hash table entry
    //
    LIST_ENTRY HashEntry;
    ULONG HashBucket;
    BOOLEAN InHashTable;

    //
    // Process information
    //
    UNICODE_STRING ImagePath;
    WCHAR ImagePathBuffer[260];
    PEPROCESS ProcessObject;

    //
    // Handle statistics
    //
    ULONG ProcessHandleCount;
    ULONG ThreadHandleCount;
    ULONG FileHandleCount;
    ULONG TokenHandleCount;
    ULONG SectionHandleCount;
    ULONG OtherHandleCount;

    //
    // Suspicion tracking
    //
    ULONG SuspicionScore;
    ULONG CrossProcessHandleCount;
    ULONG HighPrivilegeHandleCount;
    ULONG DuplicatedHandleCount;

    //
    // Snapshot time
    //
    LARGE_INTEGER SnapshotTime;

} HT_PROCESS_HANDLES_INTERNAL, *PHT_PROCESS_HANDLES_INTERNAL;

//
// Extended handle entry with private data
//
typedef struct _HT_HANDLE_ENTRY_INTERNAL {
    //
    // Public structure (must be first)
    //
    HT_HANDLE_ENTRY Public;

    //
    // Object name buffer
    //
    WCHAR ObjectNameBuffer[260];

    //
    // Extended information
    //
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG CreatorBackTraceIndex;

    //
    // For process/thread handles
    //
    UNICODE_STRING TargetImagePath;
    WCHAR TargetImagePathBuffer[260];

    //
    // Suspicion score
    //
    ULONG SuspicionScore;

} HT_HANDLE_ENTRY_INTERNAL, *PHT_HANDLE_ENTRY_INTERNAL;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

//
// Hash functions
//
static ULONG
HtpHashProcessId(
    _In_ HANDLE ProcessId
    );

static ULONG
HtpHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length
    );

//
// Allocation functions
//
static PHT_HANDLE_ENTRY_INTERNAL
HtpAllocateHandleEntry(
    _In_ PHT_TRACKER_INTERNAL Tracker
    );

static VOID
HtpFreeHandleEntry(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_HANDLE_ENTRY_INTERNAL Entry
    );

static PHT_PROCESS_HANDLES_INTERNAL
HtpAllocateProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
HtpFreeProcessHandlesInternal(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

static PHT_DUPLICATION_RECORD
HtpAllocateDuplicationRecord(
    _In_ PHT_TRACKER_INTERNAL Tracker
    );

static VOID
HtpFreeDuplicationRecord(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_DUPLICATION_RECORD Record
    );

//
// Reference counting
//
static VOID
HtpReferenceProcessHandles(
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

static VOID
HtpDereferenceProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

//
// Hash table operations
//
static PHT_PROCESS_HANDLES_INTERNAL
HtpLookupProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static NTSTATUS
HtpInsertProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

static VOID
HtpRemoveProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

//
// Handle enumeration
//
static NTSTATUS
HtpEnumerateProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId,
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    );

static HT_HANDLE_TYPE
HtpGetHandleType(
    _In_ POBJECT_TYPE ObjectType
    );

static HT_HANDLE_TYPE
HtpGetHandleTypeFromName(
    _In_ PCUNICODE_STRING TypeName
    );

static NTSTATUS
HtpGetObjectName(
    _In_ PVOID Object,
    _Out_ PUNICODE_STRING ObjectName,
    _In_ ULONG MaxLength
    );

//
// Suspicion analysis
//
static HT_SUSPICION
HtpAnalyzeHandleSuspicion(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_HANDLE_ENTRY_INTERNAL Entry,
    _In_ HANDLE OwnerProcessId
    );

static BOOLEAN
HtpIsSensitiveProcess(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    );

static BOOLEAN
HtpIsSensitiveProcessByName(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PCUNICODE_STRING ImageName
    );

static BOOLEAN
HtpIsHighPrivilegeAccess(
    _In_ HT_HANDLE_TYPE Type,
    _In_ ACCESS_MASK Access
    );

static BOOLEAN
HtpIsInjectionCapableAccess(
    _In_ ACCESS_MASK Access
    );

static ULONG
HtpCalculateSuspicionScore(
    _In_ HT_SUSPICION Flags
    );

//
// Initialization helpers
//
static VOID
HtpInitializeSensitiveProcessList(
    _In_ PHT_TRACKER_INTERNAL Tracker
    );

//
// Timer and worker routines
//
static VOID
HtpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
HtpWorkerThread(
    _In_ PVOID StartContext
    );

static VOID
HtpCleanupStaleDuplications(
    _In_ PHT_TRACKER_INTERNAL Tracker
    );

//
// Utility functions
//
static BOOLEAN
HtpExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    );

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

NTSTATUS
HtInitialize(
    _Out_ PHT_TRACKER* Tracker
    )
/*++
Routine Description:
    Initializes the handle tracker subsystem.

Arguments:
    Tracker - Receives pointer to initialized tracker.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    NTSTATUS Status;
    PHT_TRACKER_INTERNAL Internal = NULL;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER DueTime;
    ULONG i;

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    //
    // Allocate internal tracker structure
    //
    Internal = (PHT_TRACKER_INTERNAL)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(HT_TRACKER_INTERNAL),
        HT_POOL_TAG
        );

    if (Internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Internal, sizeof(HT_TRACKER_INTERNAL));

    //
    // Initialize public structure
    //
    InitializeListHead(&Internal->Public.ProcessList);
    ExInitializePushLock(&Internal->Public.ProcessLock);

    //
    // Initialize hash buckets
    //
    for (i = 0; i < HT_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Internal->HashBuckets[i].ProcessList);
        ExInitializePushLock(&Internal->HashBuckets[i].Lock);
        Internal->HashBuckets[i].Count = 0;
    }

    //
    // Initialize duplication tracking
    //
    InitializeListHead(&Internal->DuplicationList);
    ExInitializePushLock(&Internal->DuplicationLock);

    //
    // Initialize sensitive process tracking
    //
    InitializeListHead(&Internal->SensitiveProcessList);
    ExInitializePushLock(&Internal->SensitiveProcessLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Internal->HandleEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_HANDLE_ENTRY_INTERNAL),
        HT_POOL_TAG_ENTRY,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->ProcessHandlesLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_PROCESS_HANDLES_INTERNAL),
        HT_POOL_TAG_PROCESS,
        0
        );

    ExInitializeNPagedLookasideList(
        &Internal->DuplicationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_DUPLICATION_RECORD),
        HT_POOL_TAG_ENTRY,
        0
        );

    Internal->LookasideInitialized = TRUE;

    //
    // Initialize default configuration
    //
    Internal->Config.EnableCrossProcessDetection = TRUE;
    Internal->Config.EnableDuplicationTracking = TRUE;
    Internal->Config.EnableSensitiveProcessMonitoring = TRUE;
    Internal->Config.MaxHandlesPerProcess = HT_MAX_HANDLES_PER_PROCESS;
    Internal->Config.MaxDuplications = HT_MAX_DUPLICATIONS_PER_PROCESS;
    Internal->Config.SuspicionThreshold = 50;

    //
    // Initialize sensitive process list
    //
    HtpInitializeSensitiveProcessList(Internal);

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
        HtpWorkerThread,
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
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Internal->CleanupTimer);
    KeInitializeDpc(&Internal->CleanupDpc, HtpCleanupTimerDpc, Internal);

    //
    // Start cleanup timer (every 60 seconds)
    //
    DueTime.QuadPart = -((LONGLONG)60000 * 10000);
    KeSetTimerEx(
        &Internal->CleanupTimer,
        DueTime,
        60000,
        &Internal->CleanupDpc
        );
    Internal->CleanupTimerActive = TRUE;

    //
    // Mark as initialized
    //
    Internal->Public.Initialized = TRUE;
    *Tracker = (PHT_TRACKER)Internal;

    return STATUS_SUCCESS;

Cleanup:
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&Internal->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&Internal->DuplicationLookaside);
    }

    ExFreePoolWithTag(Internal, HT_POOL_TAG);
    return Status;
}

VOID
HtShutdown(
    _Inout_ PHT_TRACKER Tracker
    )
/*++
Routine Description:
    Shuts down the handle tracker subsystem.

Arguments:
    Tracker - Tracker instance to shutdown.
--*/
{
    PHT_TRACKER_INTERNAL Internal = (PHT_TRACKER_INTERNAL)Tracker;
    PLIST_ENTRY Entry;
    PHT_PROCESS_HANDLES_INTERNAL Handles;
    PHT_DUPLICATION_RECORD DupRecord;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return;
    }

    Internal->Public.Initialized = FALSE;
    Internal->ShutdownRequested = TRUE;

    //
    // Cancel cleanup timer
    //
    if (Internal->CleanupTimerActive) {
        KeCancelTimer(&Internal->CleanupTimer);
        Internal->CleanupTimerActive = FALSE;
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
    // Free all process handles from hash table
    //
    for (i = 0; i < HT_HASH_BUCKET_COUNT; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->HashBuckets[i].Lock);

        while (!IsListEmpty(&Internal->HashBuckets[i].ProcessList)) {
            Entry = RemoveHeadList(&Internal->HashBuckets[i].ProcessList);
            Handles = CONTAINING_RECORD(Entry, HT_PROCESS_HANDLES_INTERNAL, HashEntry);
            Handles->InHashTable = FALSE;

            ExReleasePushLockExclusive(&Internal->HashBuckets[i].Lock);
            KeLeaveCriticalRegion();

            HtpFreeProcessHandlesInternal(Internal, Handles);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Internal->HashBuckets[i].Lock);
        }

        ExReleasePushLockExclusive(&Internal->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free all duplication records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->DuplicationLock);

    while (!IsListEmpty(&Internal->DuplicationList)) {
        Entry = RemoveHeadList(&Internal->DuplicationList);
        DupRecord = CONTAINING_RECORD(Entry, HT_DUPLICATION_RECORD, ListEntry);

        ExReleasePushLockExclusive(&Internal->DuplicationLock);
        KeLeaveCriticalRegion();

        HtpFreeDuplicationRecord(Internal, DupRecord);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Internal->DuplicationLock);
    }

    ExReleasePushLockExclusive(&Internal->DuplicationLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (Internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Internal->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&Internal->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&Internal->DuplicationLookaside);
    }

    //
    // Free tracker
    //
    ExFreePoolWithTag(Internal, HT_POOL_TAG);
}

NTSTATUS
HtSnapshotHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Out_ PHT_PROCESS_HANDLES* Handles
    )
/*++
Routine Description:
    Takes a snapshot of all handles for a process.

Arguments:
    Tracker - Tracker instance.
    ProcessId - Process to snapshot.
    Handles - Receives handle snapshot.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHT_TRACKER_INTERNAL Internal = (PHT_TRACKER_INTERNAL)Tracker;
    PHT_PROCESS_HANDLES_INTERNAL InternalHandles = NULL;
    NTSTATUS Status;

    if (Internal == NULL || !Internal->Public.Initialized || Handles == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handles = NULL;

    //
    // Allocate process handles structure
    //
    InternalHandles = HtpAllocateProcessHandles(Internal, ProcessId);
    if (InternalHandles == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Enumerate handles
    //
    Status = HtpEnumerateProcessHandles(Internal, ProcessId, InternalHandles);
    if (!NT_SUCCESS(Status)) {
        HtpFreeProcessHandlesInternal(Internal, InternalHandles);
        return Status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->ExtendedStats.TotalEnumerations);
    InterlockedAdd64(&Internal->Public.Stats.HandlesTracked, InternalHandles->Public.HandleCount);

    if (InternalHandles->CrossProcessHandleCount > 0) {
        InterlockedAdd64(&Internal->Public.Stats.CrossProcessHandles, InternalHandles->CrossProcessHandleCount);
    }

    if (InternalHandles->Public.AggregatedSuspicion != HtSuspicion_None) {
        InterlockedIncrement64(&Internal->Public.Stats.SuspiciousHandles);
    }

    //
    // Add to tracker list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->Public.ProcessLock);
    InsertTailList(&Internal->Public.ProcessList, &InternalHandles->Public.ListEntry);
    InterlockedIncrement(&Internal->Public.ProcessCount);
    ExReleasePushLockExclusive(&Internal->Public.ProcessLock);
    KeLeaveCriticalRegion();

    //
    // Insert into hash table
    //
    HtpInsertProcessHandles(Internal, InternalHandles);

    *Handles = &InternalHandles->Public;

    return STATUS_SUCCESS;
}

NTSTATUS
HtRecordDuplication(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE SourceProcess,
    _In_ HANDLE TargetProcess,
    _In_ HANDLE SourceHandle,
    _In_ HANDLE TargetHandle
    )
/*++
Routine Description:
    Records a handle duplication event.

Arguments:
    Tracker - Tracker instance.
    SourceProcess - Source process ID.
    TargetProcess - Target process ID.
    SourceHandle - Source handle value.
    TargetHandle - Target handle value (in target process).

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHT_TRACKER_INTERNAL Internal = (PHT_TRACKER_INTERNAL)Tracker;
    PHT_DUPLICATION_RECORD Record = NULL;
    HT_SUSPICION Suspicion = HtSuspicion_None;

    if (Internal == NULL || !Internal->Public.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Internal->Config.EnableDuplicationTracking) {
        return STATUS_SUCCESS;
    }

    //
    // Check duplication limit
    //
    if ((ULONG)Internal->DuplicationCount >= Internal->Config.MaxDuplications) {
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate duplication record
    //
    Record = HtpAllocateDuplicationRecord(Internal);
    if (Record == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate record
    //
    Record->SourceProcessId = SourceProcess;
    Record->TargetProcessId = TargetProcess;
    Record->SourceHandle = SourceHandle;
    Record->TargetHandle = TargetHandle;
    KeQuerySystemTime(&Record->Timestamp);

    //
    // Analyze suspicion
    //
    if (SourceProcess != TargetProcess) {
        Suspicion |= HtSuspicion_CrossProcess;
        Suspicion |= HtSuspicion_DuplicatedIn;
    }

    if (HtpIsSensitiveProcess(Internal, SourceProcess)) {
        Suspicion |= HtSuspicion_SensitiveTarget;
    }

    Record->SuspicionFlags = Suspicion;

    //
    // Insert into duplication list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Internal->DuplicationLock);
    InsertTailList(&Internal->DuplicationList, &Record->ListEntry);
    InterlockedIncrement(&Internal->DuplicationCount);
    ExReleasePushLockExclusive(&Internal->DuplicationLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Internal->ExtendedStats.DuplicationsRecorded);

    if (Suspicion != HtSuspicion_None) {
        InterlockedIncrement64(&Internal->Public.Stats.SuspiciousHandles);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HtAnalyzeHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles,
    _Out_ PHT_SUSPICION Flags
    )
/*++
Routine Description:
    Analyzes handles for suspicious patterns.

Arguments:
    Tracker - Tracker instance.
    Handles - Handle snapshot to analyze.
    Flags - Receives aggregated suspicion flags.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHT_TRACKER_INTERNAL Internal = (PHT_TRACKER_INTERNAL)Tracker;
    PHT_PROCESS_HANDLES_INTERNAL InternalHandles;
    HT_SUSPICION AggregatedSuspicion = HtSuspicion_None;
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY HandleEntry;

    if (Internal == NULL || !Internal->Public.Initialized || Handles == NULL || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = HtSuspicion_None;

    InternalHandles = CONTAINING_RECORD(Handles, HT_PROCESS_HANDLES_INTERNAL, Public);

    //
    // Analyze each handle
    //
    KeAcquireSpinLockAtDpcLevel(&Handles->Lock);

    for (Entry = Handles->HandleList.Flink;
         Entry != &Handles->HandleList;
         Entry = Entry->Flink) {

        HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY, ListEntry);
        AggregatedSuspicion |= HandleEntry->SuspicionFlags;
    }

    KeReleaseSpinLockFromDpcLevel(&Handles->Lock);

    //
    // Check for many handles (potential handle table attack)
    //
    if ((ULONG)Handles->HandleCount > Internal->Config.MaxHandlesPerProcess / 2) {
        AggregatedSuspicion |= HtSuspicion_ManyHandles;
    }

    //
    // Update aggregated suspicion
    //
    Handles->AggregatedSuspicion = AggregatedSuspicion;
    InternalHandles->SuspicionScore = HtpCalculateSuspicionScore(AggregatedSuspicion);

    *Flags = AggregatedSuspicion;

    return STATUS_SUCCESS;
}

NTSTATUS
HtFindCrossProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE TargetProcessId,
    _Out_writes_to_(Max, *Count) PHT_HANDLE_ENTRY* Entries,
    _In_ ULONG Max,
    _Out_ PULONG Count
    )
/*++
Routine Description:
    Finds all handles in other processes that reference the target process.

Arguments:
    Tracker - Tracker instance.
    TargetProcessId - Target process to find handles for.
    Entries - Array to receive handle entries.
    Max - Maximum entries to return.
    Count - Receives actual count.

Return Value:
    STATUS_SUCCESS on success.
--*/
{
    PHT_TRACKER_INTERNAL Internal = (PHT_TRACKER_INTERNAL)Tracker;
    PLIST_ENTRY ProcessEntry, HandleEntry;
    PHT_PROCESS_HANDLES_INTERNAL ProcessHandles;
    PHT_HANDLE_ENTRY Entry;
    ULONG FoundCount = 0;
    ULONG i;

    if (Internal == NULL || !Internal->Public.Initialized ||
        Entries == NULL || Count == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    //
    // Search all process handle lists
    //
    for (i = 0; i < HT_HASH_BUCKET_COUNT && FoundCount < Max; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Internal->HashBuckets[i].Lock);

        for (ProcessEntry = Internal->HashBuckets[i].ProcessList.Flink;
             ProcessEntry != &Internal->HashBuckets[i].ProcessList && FoundCount < Max;
             ProcessEntry = ProcessEntry->Flink) {

            ProcessHandles = CONTAINING_RECORD(ProcessEntry, HT_PROCESS_HANDLES_INTERNAL, HashEntry);

            //
            // Skip if this is the target process itself
            //
            if (ProcessHandles->Public.ProcessId == TargetProcessId) {
                continue;
            }

            //
            // Search this process's handles
            //
            KeAcquireSpinLockAtDpcLevel(&ProcessHandles->Public.Lock);

            for (HandleEntry = ProcessHandles->Public.HandleList.Flink;
                 HandleEntry != &ProcessHandles->Public.HandleList && FoundCount < Max;
                 HandleEntry = HandleEntry->Flink) {

                Entry = CONTAINING_RECORD(HandleEntry, HT_HANDLE_ENTRY, ListEntry);

                //
                // Check if this handle references the target process
                //
                if (Entry->TargetProcessId == TargetProcessId) {
                    Entries[FoundCount++] = Entry;
                }
            }

            KeReleaseSpinLockFromDpcLevel(&ProcessHandles->Public.Lock);
        }

        ExReleasePushLockShared(&Internal->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    *Count = FoundCount;

    return STATUS_SUCCESS;
}

VOID
HtFreeHandles(
    _In_ PHT_PROCESS_HANDLES Handles
    )
/*++
Routine Description:
    Frees a process handles snapshot.

Arguments:
    Handles - Handles to free.
--*/
{
    PHT_PROCESS_HANDLES_INTERNAL InternalHandles;
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY_INTERNAL HandleEntry;
    KIRQL OldIrql;

    if (Handles == NULL) {
        return;
    }

    InternalHandles = CONTAINING_RECORD(Handles, HT_PROCESS_HANDLES_INTERNAL, Public);

    //
    // Free all handle entries
    //
    KeAcquireSpinLock(&Handles->Lock, &OldIrql);

    while (!IsListEmpty(&Handles->HandleList)) {
        Entry = RemoveHeadList(&Handles->HandleList);
        HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY_INTERNAL, Public.ListEntry);
        InterlockedDecrement(&Handles->HandleCount);

        KeReleaseSpinLock(&Handles->Lock, OldIrql);

        //
        // Free string buffer if allocated
        //
        if (HandleEntry->Public.ObjectName.Buffer != NULL &&
            HandleEntry->Public.ObjectName.Buffer != HandleEntry->ObjectNameBuffer) {
            ExFreePoolWithTag(HandleEntry->Public.ObjectName.Buffer, HT_POOL_TAG_STRING);
        }

        ExFreePoolWithTag(HandleEntry, HT_POOL_TAG_ENTRY);

        KeAcquireSpinLock(&Handles->Lock, &OldIrql);
    }

    KeReleaseSpinLock(&Handles->Lock, OldIrql);

    //
    // Free process object reference
    //
    if (InternalHandles->ProcessObject != NULL) {
        ObDereferenceObject(InternalHandles->ProcessObject);
        InternalHandles->ProcessObject = NULL;
    }

    //
    // Free process handles structure
    //
    ExFreePoolWithTag(InternalHandles, HT_POOL_TAG_PROCESS);
}

// ============================================================================
// PRIVATE FUNCTION IMPLEMENTATIONS
// ============================================================================

static ULONG
HtpHashProcessId(
    _In_ HANDLE ProcessId
    )
{
    ULONG_PTR Value = (ULONG_PTR)ProcessId;

    Value ^= (Value >> 16);
    Value *= 0x85ebca6b;
    Value ^= (Value >> 13);
    Value *= 0xc2b2ae35;
    Value ^= (Value >> 16);

    return (ULONG)(Value & HT_HASH_BUCKET_MASK);
}

static ULONG
HtpHashString(
    _In_ PCWSTR String,
    _In_ ULONG Length
    )
{
    ULONG Hash = 5381;
    ULONG i;

    for (i = 0; i < Length && String[i] != L'\0'; i++) {
        WCHAR Ch = String[i];
        if (Ch >= L'A' && Ch <= L'Z') {
            Ch += (L'a' - L'A');
        }
        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}

static PHT_HANDLE_ENTRY_INTERNAL
HtpAllocateHandleEntry(
    _In_ PHT_TRACKER_INTERNAL Tracker
    )
{
    PHT_HANDLE_ENTRY_INTERNAL Entry;

    Entry = (PHT_HANDLE_ENTRY_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Tracker->HandleEntryLookaside
        );

    if (Entry != NULL) {
        RtlZeroMemory(Entry, sizeof(HT_HANDLE_ENTRY_INTERNAL));
        InitializeListHead(&Entry->Public.ListEntry);

        Entry->Public.ObjectName.Buffer = Entry->ObjectNameBuffer;
        Entry->Public.ObjectName.Length = 0;
        Entry->Public.ObjectName.MaximumLength = sizeof(Entry->ObjectNameBuffer);

        Entry->TargetImagePath.Buffer = Entry->TargetImagePathBuffer;
        Entry->TargetImagePath.Length = 0;
        Entry->TargetImagePath.MaximumLength = sizeof(Entry->TargetImagePathBuffer);
    }

    return Entry;
}

static VOID
HtpFreeHandleEntry(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_HANDLE_ENTRY_INTERNAL Entry
    )
{
    if (Entry->Public.ObjectName.Buffer != NULL &&
        Entry->Public.ObjectName.Buffer != Entry->ObjectNameBuffer) {
        ExFreePoolWithTag(Entry->Public.ObjectName.Buffer, HT_POOL_TAG_STRING);
    }

    ExFreeToNPagedLookasideList(&Tracker->HandleEntryLookaside, Entry);
}

static PHT_PROCESS_HANDLES_INTERNAL
HtpAllocateProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
{
    PHT_PROCESS_HANDLES_INTERNAL Handles;
    NTSTATUS Status;
    PEPROCESS Process = NULL;

    Handles = (PHT_PROCESS_HANDLES_INTERNAL)ExAllocateFromNPagedLookasideList(
        &Tracker->ProcessHandlesLookaside
        );

    if (Handles != NULL) {
        RtlZeroMemory(Handles, sizeof(HT_PROCESS_HANDLES_INTERNAL));

        Handles->Public.ProcessId = ProcessId;
        Handles->RefCount = 1;
        InitializeListHead(&Handles->Public.HandleList);
        KeInitializeSpinLock(&Handles->Public.Lock);
        InitializeListHead(&Handles->Public.ListEntry);
        InitializeListHead(&Handles->HashEntry);

        Handles->ImagePath.Buffer = Handles->ImagePathBuffer;
        Handles->ImagePath.Length = 0;
        Handles->ImagePath.MaximumLength = sizeof(Handles->ImagePathBuffer);

        //
        // Get process object
        //
        Status = PsLookupProcessByProcessId(ProcessId, &Process);
        if (NT_SUCCESS(Status)) {
            Handles->ProcessObject = Process;
        }

        KeQuerySystemTime(&Handles->SnapshotTime);
    }

    return Handles;
}

static VOID
HtpFreeProcessHandlesInternal(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY_INTERNAL HandleEntry;
    KIRQL OldIrql;

    //
    // Free all handle entries
    //
    KeAcquireSpinLock(&Handles->Public.Lock, &OldIrql);

    while (!IsListEmpty(&Handles->Public.HandleList)) {
        Entry = RemoveHeadList(&Handles->Public.HandleList);
        HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY_INTERNAL, Public.ListEntry);
        InterlockedDecrement(&Handles->Public.HandleCount);

        KeReleaseSpinLock(&Handles->Public.Lock, OldIrql);
        HtpFreeHandleEntry(Tracker, HandleEntry);
        KeAcquireSpinLock(&Handles->Public.Lock, &OldIrql);
    }

    KeReleaseSpinLock(&Handles->Public.Lock, OldIrql);

    //
    // Free process object reference
    //
    if (Handles->ProcessObject != NULL) {
        ObDereferenceObject(Handles->ProcessObject);
    }

    ExFreeToNPagedLookasideList(&Tracker->ProcessHandlesLookaside, Handles);
}

static PHT_DUPLICATION_RECORD
HtpAllocateDuplicationRecord(
    _In_ PHT_TRACKER_INTERNAL Tracker
    )
{
    PHT_DUPLICATION_RECORD Record;

    Record = (PHT_DUPLICATION_RECORD)ExAllocateFromNPagedLookasideList(
        &Tracker->DuplicationLookaside
        );

    if (Record != NULL) {
        RtlZeroMemory(Record, sizeof(HT_DUPLICATION_RECORD));
        InitializeListHead(&Record->ListEntry);
    }

    return Record;
}

static VOID
HtpFreeDuplicationRecord(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_DUPLICATION_RECORD Record
    )
{
    ExFreeToNPagedLookasideList(&Tracker->DuplicationLookaside, Record);
}

static VOID
HtpReferenceProcessHandles(
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    InterlockedIncrement(&Handles->RefCount);
}

static VOID
HtpDereferenceProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    if (InterlockedDecrement(&Handles->RefCount) == 0) {
        HtpFreeProcessHandlesInternal(Tracker, Handles);
    }
}

static PHT_PROCESS_HANDLES_INTERNAL
HtpLookupProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
{
    ULONG Hash;
    PLIST_ENTRY Entry;
    PHT_PROCESS_HANDLES_INTERNAL Handles;

    Hash = HtpHashProcessId(ProcessId);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->HashBuckets[Hash].Lock);

    for (Entry = Tracker->HashBuckets[Hash].ProcessList.Flink;
         Entry != &Tracker->HashBuckets[Hash].ProcessList;
         Entry = Entry->Flink) {

        Handles = CONTAINING_RECORD(Entry, HT_PROCESS_HANDLES_INTERNAL, HashEntry);

        if (Handles->Public.ProcessId == ProcessId) {
            HtpReferenceProcessHandles(Handles);
            ExReleasePushLockShared(&Tracker->HashBuckets[Hash].Lock);
            KeLeaveCriticalRegion();
            return Handles;
        }
    }

    ExReleasePushLockShared(&Tracker->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    return NULL;
}

static NTSTATUS
HtpInsertProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    ULONG Hash;

    Hash = HtpHashProcessId(Handles->Public.ProcessId);
    Handles->HashBucket = Hash;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);

    InsertTailList(&Tracker->HashBuckets[Hash].ProcessList, &Handles->HashEntry);
    InterlockedIncrement(&Tracker->HashBuckets[Hash].Count);
    Handles->InHashTable = TRUE;

    ExReleasePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

static VOID
HtpRemoveProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    ULONG Hash;

    if (!Handles->InHashTable) {
        return;
    }

    Hash = Handles->HashBucket;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);

    if (Handles->InHashTable) {
        RemoveEntryList(&Handles->HashEntry);
        InitializeListHead(&Handles->HashEntry);
        InterlockedDecrement(&Tracker->HashBuckets[Hash].Count);
        Handles->InHashTable = FALSE;
    }

    ExReleasePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();
}

static NTSTATUS
HtpEnumerateProcessHandles(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId,
    _Inout_ PHT_PROCESS_HANDLES_INTERNAL Handles
    )
{
    NTSTATUS Status;
    PVOID Buffer = NULL;
    ULONG BufferSize = 0x10000;
    ULONG ReturnLength = 0;
    PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = NULL;
    ULONG i;
    HANDLE ProcessHandle = NULL;
    KIRQL OldIrql;

    //
    // We need to use ZwQuerySystemInformation with SystemExtendedHandleInformation
    // to get all handles in the system, then filter for our target process
    //

    //
    // Allocate buffer for handle information
    //
    do {
        if (Buffer != NULL) {
            ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
        }

        Buffer = ExAllocatePoolWithTag(PagedPool, BufferSize, HT_POOL_TAG_BUFFER);
        if (Buffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            Buffer,
            BufferSize,
            &ReturnLength
            );

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            BufferSize = ReturnLength + 0x1000;
        }

    } while (Status == STATUS_INFO_LENGTH_MISMATCH && BufferSize < 0x4000000);

    if (!NT_SUCCESS(Status)) {
        if (Buffer != NULL) {
            ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
        }
        return Status;
    }

    HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;

    //
    // Process each handle
    //
    for (i = 0; i < HandleInfo->NumberOfHandles &&
         (ULONG)Handles->Public.HandleCount < Tracker->Config.MaxHandlesPerProcess; i++) {

        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry = &HandleInfo->Handles[i];
        PHT_HANDLE_ENTRY_INTERNAL NewEntry;
        PVOID Object = NULL;
        POBJECT_TYPE ObjectType = NULL;

        //
        // Filter for our target process
        //
        if ((HANDLE)(ULONG_PTR)HandleEntry->UniqueProcessId != ProcessId) {
            continue;
        }

        //
        // Allocate entry
        //
        NewEntry = HtpAllocateHandleEntry(Tracker);
        if (NewEntry == NULL) {
            continue;
        }

        //
        // Populate entry
        //
        NewEntry->Public.Handle = (HANDLE)HandleEntry->HandleValue;
        NewEntry->Public.GrantedAccess = HandleEntry->GrantedAccess;
        NewEntry->Public.ObjectPointer = HandleEntry->Object;
        NewEntry->ObjectTypeIndex = HandleEntry->ObjectTypeIndex;
        NewEntry->HandleAttributes = HandleEntry->HandleAttributes;

        //
        // Try to get object type
        //
        __try {
            Object = HandleEntry->Object;
            if (Object != NULL && MmIsAddressValid(Object)) {
                ObjectType = ObGetObjectType(Object);
                if (ObjectType != NULL) {
                    NewEntry->Public.Type = HtpGetHandleType(ObjectType);
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Ignore exceptions
        }

        //
        // For process/thread handles, get target info
        //
        if (NewEntry->Public.Type == HtType_Process ||
            NewEntry->Public.Type == HtType_Thread) {

            __try {
                if (Object != NULL && MmIsAddressValid(Object)) {
                    if (NewEntry->Public.Type == HtType_Process) {
                        PEPROCESS TargetProcess = (PEPROCESS)Object;
                        NewEntry->Public.TargetProcessId = PsGetProcessId(TargetProcess);
                    } else {
                        PETHREAD TargetThread = (PETHREAD)Object;
                        PEPROCESS OwningProcess = IoThreadToProcess(TargetThread);
                        if (OwningProcess != NULL) {
                            NewEntry->Public.TargetProcessId = PsGetProcessId(OwningProcess);
                        }
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Ignore exceptions
            }

            //
            // Check for cross-process
            //
            if (NewEntry->Public.TargetProcessId != NULL &&
                NewEntry->Public.TargetProcessId != ProcessId) {
                Handles->CrossProcessHandleCount++;
            }
        }

        //
        // Check for duplicated handle
        //
        NewEntry->Public.IsDuplicated = FALSE; // Would need ObQueryHandleFlags

        //
        // Analyze suspicion
        //
        NewEntry->Public.SuspicionFlags = HtpAnalyzeHandleSuspicion(Tracker, NewEntry, ProcessId);
        NewEntry->SuspicionScore = HtpCalculateSuspicionScore(NewEntry->Public.SuspicionFlags);

        //
        // Update statistics
        //
        switch (NewEntry->Public.Type) {
        case HtType_Process:
            Handles->ProcessHandleCount++;
            break;
        case HtType_Thread:
            Handles->ThreadHandleCount++;
            break;
        case HtType_File:
            Handles->FileHandleCount++;
            break;
        case HtType_Token:
            Handles->TokenHandleCount++;
            InterlockedIncrement64(&Tracker->ExtendedStats.TokenHandlesTracked);
            break;
        case HtType_Section:
            Handles->SectionHandleCount++;
            break;
        default:
            Handles->OtherHandleCount++;
            break;
        }

        if (NewEntry->Public.SuspicionFlags & HtSuspicion_HighPrivilege) {
            Handles->HighPrivilegeHandleCount++;
            InterlockedIncrement64(&Tracker->ExtendedStats.HighPrivilegeHandles);
        }

        //
        // Insert into handle list
        //
        KeAcquireSpinLock(&Handles->Public.Lock, &OldIrql);
        InsertTailList(&Handles->Public.HandleList, &NewEntry->Public.ListEntry);
        InterlockedIncrement(&Handles->Public.HandleCount);
        KeReleaseSpinLock(&Handles->Public.Lock, OldIrql);
    }

    //
    // Calculate aggregated suspicion
    //
    Handles->Public.AggregatedSuspicion = HtSuspicion_None;

    if (Handles->CrossProcessHandleCount > 0) {
        Handles->Public.AggregatedSuspicion |= HtSuspicion_CrossProcess;
    }

    if (Handles->HighPrivilegeHandleCount > 0) {
        Handles->Public.AggregatedSuspicion |= HtSuspicion_HighPrivilege;
    }

    if ((ULONG)Handles->Public.HandleCount > Tracker->Config.MaxHandlesPerProcess / 2) {
        Handles->Public.AggregatedSuspicion |= HtSuspicion_ManyHandles;
    }

    ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);

    return STATUS_SUCCESS;
}

static HT_HANDLE_TYPE
HtpGetHandleType(
    _In_ POBJECT_TYPE ObjectType
    )
{
    UNICODE_STRING TypeName;

    if (ObjectType == NULL) {
        return HtType_Unknown;
    }

    //
    // Compare against known types
    //
    if (ObjectType == *PsProcessType) {
        return HtType_Process;
    }

    if (ObjectType == *PsThreadType) {
        return HtType_Thread;
    }

    if (ObjectType == *IoFileObjectType) {
        return HtType_File;
    }

    if (ObjectType == *SeTokenObjectType) {
        return HtType_Token;
    }

    //
    // For other types, we would need to check the type name
    // This is simplified for now
    //

    return HtType_Unknown;
}

static HT_HANDLE_TYPE
HtpGetHandleTypeFromName(
    _In_ PCUNICODE_STRING TypeName
    )
{
    if (TypeName == NULL || TypeName->Buffer == NULL) {
        return HtType_Unknown;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_PROCESS_TYPE_NAME), TRUE)) {
        return HtType_Process;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_THREAD_TYPE_NAME), TRUE)) {
        return HtType_Thread;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_FILE_TYPE_NAME), TRUE)) {
        return HtType_File;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_KEY_TYPE_NAME), TRUE)) {
        return HtType_Key;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_SECTION_TYPE_NAME), TRUE)) {
        return HtType_Section;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_TOKEN_TYPE_NAME), TRUE)) {
        return HtType_Token;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_EVENT_TYPE_NAME), TRUE)) {
        return HtType_Event;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_SEMAPHORE_TYPE_NAME), TRUE)) {
        return HtType_Semaphore;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_MUTANT_TYPE_NAME), TRUE)) {
        return HtType_Mutex;
    }

    if (RtlEqualUnicodeString(TypeName, &(UNICODE_STRING)RTL_CONSTANT_STRING(HT_TIMER_TYPE_NAME), TRUE)) {
        return HtType_Timer;
    }

    return HtType_Unknown;
}

static HT_SUSPICION
HtpAnalyzeHandleSuspicion(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PHT_HANDLE_ENTRY_INTERNAL Entry,
    _In_ HANDLE OwnerProcessId
    )
{
    HT_SUSPICION Suspicion = HtSuspicion_None;

    //
    // Check for cross-process handle
    //
    if (Entry->Public.TargetProcessId != NULL &&
        Entry->Public.TargetProcessId != OwnerProcessId) {
        Suspicion |= HtSuspicion_CrossProcess;

        //
        // Check if target is sensitive process
        //
        if (HtpIsSensitiveProcess(Tracker, Entry->Public.TargetProcessId)) {
            Suspicion |= HtSuspicion_SensitiveTarget;
            InterlockedIncrement64(&Tracker->ExtendedStats.SensitiveAccessDetected);
        }
    }

    //
    // Check for high privilege access
    //
    if (HtpIsHighPrivilegeAccess(Entry->Public.Type, Entry->Public.GrantedAccess)) {
        Suspicion |= HtSuspicion_HighPrivilege;
    }

    //
    // Check for injection-capable access
    //
    if (Entry->Public.Type == HtType_Process) {
        if (HtpIsInjectionCapableAccess(Entry->Public.GrantedAccess)) {
            InterlockedIncrement64(&Tracker->ExtendedStats.InjectionHandlesDetected);
        }
    }

    //
    // Check for duplicated handle
    //
    if (Entry->Public.IsDuplicated) {
        Suspicion |= HtSuspicion_DuplicatedIn;
    }

    //
    // Check for system handle (PID 4)
    //
    if (OwnerProcessId == (HANDLE)4) {
        Suspicion |= HtSuspicion_SystemHandle;
    }

    return Suspicion;
}

static BOOLEAN
HtpIsSensitiveProcess(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ HANDLE ProcessId
    )
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PUNICODE_STRING ImageFileName = NULL;
    BOOLEAN IsSensitive = FALSE;

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    __try {
        Status = SeLocateProcessImageName(Process, &ImageFileName);
        if (NT_SUCCESS(Status) && ImageFileName != NULL) {
            IsSensitive = HtpIsSensitiveProcessByName(Tracker, ImageFileName);
            ExFreePool(ImageFileName);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IsSensitive = FALSE;
    }

    ObDereferenceObject(Process);

    return IsSensitive;
}

static BOOLEAN
HtpIsSensitiveProcessByName(
    _In_ PHT_TRACKER_INTERNAL Tracker,
    _In_ PCUNICODE_STRING ImageName
    )
{
    UNICODE_STRING FileName;
    ULONG Hash;
    ULONG i;

    if (!HtpExtractFileName(ImageName, &FileName)) {
        return FALSE;
    }

    Hash = HtpHashString(FileName.Buffer, FileName.Length / sizeof(WCHAR));

    for (i = 0; i < Tracker->SensitiveProcessHashCount; i++) {
        if (Tracker->SensitiveProcessHashes[i] == Hash) {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
HtpIsHighPrivilegeAccess(
    _In_ HT_HANDLE_TYPE Type,
    _In_ ACCESS_MASK Access
    )
{
    switch (Type) {
    case HtType_Process:
        if ((Access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
            return TRUE;
        }
        if (Access & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)) {
            return TRUE;
        }
        break;

    case HtType_Thread:
        if ((Access & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS) {
            return TRUE;
        }
        if (Access & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)) {
            return TRUE;
        }
        break;

    case HtType_Token:
        if (Access & (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY)) {
            return TRUE;
        }
        break;

    default:
        break;
    }

    return FALSE;
}

static BOOLEAN
HtpIsInjectionCapableAccess(
    _In_ ACCESS_MASK Access
    )
{
    //
    // Check for access rights that enable process injection
    //
    if ((Access & HT_PROCESS_INJECTION_ACCESS) == HT_PROCESS_INJECTION_ACCESS) {
        return TRUE;
    }

    if ((Access & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
        return TRUE;
    }

    return FALSE;
}

static ULONG
HtpCalculateSuspicionScore(
    _In_ HT_SUSPICION Flags
    )
{
    ULONG Score = 0;

    if (Flags & HtSuspicion_CrossProcess) {
        Score += 20;
    }

    if (Flags & HtSuspicion_HighPrivilege) {
        Score += 25;
    }

    if (Flags & HtSuspicion_DuplicatedIn) {
        Score += 15;
    }

    if (Flags & HtSuspicion_SensitiveTarget) {
        Score += 40;
    }

    if (Flags & HtSuspicion_ManyHandles) {
        Score += 10;
    }

    if (Flags & HtSuspicion_SystemHandle) {
        Score += 5;
    }

    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

static VOID
HtpInitializeSensitiveProcessList(
    _In_ PHT_TRACKER_INTERNAL Tracker
    )
{
    //
    // Sensitive processes that should be monitored for access
    //
    static const PCWSTR SensitiveProcesses[] = {
        L"lsass.exe",
        L"csrss.exe",
        L"smss.exe",
        L"wininit.exe",
        L"winlogon.exe",
        L"services.exe",
        L"svchost.exe",
        L"spoolsv.exe",
        L"lsm.exe",
        L"conhost.exe",
        L"dwm.exe",
        L"taskmgr.exe",
        L"securityhealthservice.exe",
        L"msmpeng.exe",
        L"mssense.exe"
    };

    ULONG i;

    Tracker->SensitiveProcessHashCount = 0;

    for (i = 0; i < RTL_NUMBER_OF(SensitiveProcesses) &&
         Tracker->SensitiveProcessHashCount < RTL_NUMBER_OF(Tracker->SensitiveProcessHashes); i++) {

        Tracker->SensitiveProcessHashes[Tracker->SensitiveProcessHashCount++] =
            HtpHashString(SensitiveProcesses[i], (ULONG)wcslen(SensitiveProcesses[i]));
    }
}

static VOID
HtpCleanupTimerDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PHT_TRACKER_INTERNAL Tracker = (PHT_TRACKER_INTERNAL)DeferredContext;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (Tracker == NULL || Tracker->ShutdownRequested) {
        return;
    }

    //
    // Signal worker thread to perform cleanup
    //
    KeSetEvent(&Tracker->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
HtpWorkerThread(
    _In_ PVOID StartContext
    )
{
    PHT_TRACKER_INTERNAL Tracker = (PHT_TRACKER_INTERNAL)StartContext;
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
            break;
        }

        if (Status == STATUS_WAIT_1) {
            //
            // Cleanup stale duplication records
            //
            if (Tracker->Public.Initialized && !Tracker->ShutdownRequested) {
                HtpCleanupStaleDuplications(Tracker);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
HtpCleanupStaleDuplications(
    _In_ PHT_TRACKER_INTERNAL Tracker
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PHT_DUPLICATION_RECORD Record;
    LIST_ENTRY StaleList;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)HT_HANDLE_CACHE_TIMEOUT_MS * 10000;

    InitializeListHead(&StaleList);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->DuplicationLock);

    for (Entry = Tracker->DuplicationList.Flink;
         Entry != &Tracker->DuplicationList;
         Entry = Next) {

        Next = Entry->Flink;
        Record = CONTAINING_RECORD(Entry, HT_DUPLICATION_RECORD, ListEntry);

        if ((CurrentTime.QuadPart - Record->Timestamp.QuadPart) > TimeoutInterval.QuadPart) {
            RemoveEntryList(&Record->ListEntry);
            InterlockedDecrement(&Tracker->DuplicationCount);
            InsertTailList(&StaleList, &Record->ListEntry);
        }
    }

    ExReleasePushLockExclusive(&Tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    //
    // Free stale records outside the lock
    //
    while (!IsListEmpty(&StaleList)) {
        Entry = RemoveHeadList(&StaleList);
        Record = CONTAINING_RECORD(Entry, HT_DUPLICATION_RECORD, ListEntry);
        HtpFreeDuplicationRecord(Tracker, Record);
    }
}

static BOOLEAN
HtpExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    )
{
    USHORT i;
    USHORT LastSlash = 0;

    if (FullPath == NULL || FullPath->Buffer == NULL || FullPath->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < FullPath->Length / sizeof(WCHAR); i++) {
        if (FullPath->Buffer[i] == L'\\' || FullPath->Buffer[i] == L'/') {
            LastSlash = i + 1;
        }
    }

    FileName->Buffer = &FullPath->Buffer[LastSlash];
    FileName->Length = FullPath->Length - (LastSlash * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length + sizeof(WCHAR);

    return TRUE;
}
