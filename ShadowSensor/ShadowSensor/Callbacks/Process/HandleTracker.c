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
- EX_RUNDOWN_REF for safe shutdown synchronization
- Safe handle enumeration without raw object pointer access

Detection Techniques Covered:
- T1055: Process Injection (cross-process handle detection)
- T1003: OS Credential Dumping (LSASS handle detection)
- T1134: Access Token Manipulation (token handle tracking)
- T1106: Native API (suspicious handle operations)
- T1548: Abuse Elevation Control Mechanism

SECURITY NOTES:
- NO use of MmIsAddressValid (unsafe TOCTOU)
- NO direct access to unreferenced object pointers
- Proper IRQL validation throughout
- EX_RUNDOWN_REF for shutdown synchronization
- Consistent lock hierarchy to prevent deadlocks

@author ShadowStrike Security Team
@version 3.0.0 (Enterprise Edition - Security Hardened)
@copyright (c) 2026 ShadowStrike Security. All rights reserved.
===============================================================================
--*/

#include "HandleTracker.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HtInitialize)
#pragma alloc_text(PAGE, HtShutdown)
#pragma alloc_text(PAGE, HtSnapshotHandles)
#pragma alloc_text(PAGE, HtFindCrossProcessHandles)
#pragma alloc_text(PAGE, HtIsSensitiveProcess)
#endif

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define HT_HASH_BUCKET_COUNT            256
#define HT_HASH_BUCKET_MASK             (HT_HASH_BUCKET_COUNT - 1)
#define HT_MAX_TRACKED_PROCESSES        4096
#define HT_MAX_DUPLICATIONS             4096
#define HT_DEFAULT_CLEANUP_INTERVAL_MS  60000
#define HT_DEFAULT_CACHE_TIMEOUT_MS     30000
#define HT_MAX_BUFFER_SIZE              0x4000000   // 64MB max for handle enumeration
#define HT_INITIAL_BUFFER_SIZE          0x100000    // 1MB initial
#define HT_MAX_SENSITIVE_PROCESSES      32
#define HT_SIGNATURE                    'HtTr'

//
// Suspicious access masks
//
#define HT_PROCESS_INJECTION_ACCESS     (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)
#define HT_PROCESS_DUMP_ACCESS          (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
#define HT_THREAD_HIJACK_ACCESS         (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME)
#define HT_TOKEN_STEAL_ACCESS           (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)

// ============================================================================
// SYSTEM STRUCTURES (for ZwQuerySystemInformation)
// ============================================================================

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ ULONG ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

#define ObjectTypeInformation 2

typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    UCHAR TypeIndex;
    CHAR ReservedByte;
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

//
// Handle entry (internal)
//
typedef struct _HT_HANDLE_ENTRY {
    LIST_ENTRY ListEntry;
    HANDLE HandleValue;
    HT_HANDLE_TYPE Type;
    ACCESS_MASK GrantedAccess;
    HANDLE TargetProcessId;
    BOOLEAN IsDuplicated;
    HANDLE DuplicatedFromProcess;
    HT_SUSPICION SuspicionFlags;
    ULONG SuspicionScore;
    USHORT ObjectTypeIndex;
    WCHAR ObjectName[HT_MAX_OBJECT_NAME_LENGTH / sizeof(WCHAR)];
    USHORT ObjectNameLength;
} HT_HANDLE_ENTRY, *PHT_HANDLE_ENTRY;

//
// Process handles snapshot (internal)
//
typedef struct _HT_PROCESS_HANDLES {
    ULONG Signature;
    volatile LONG RefCount;
    HANDLE ProcessId;
    PEPROCESS ProcessObject;

    //
    // Handle list (protected by Lock)
    //
    LIST_ENTRY HandleList;
    EX_PUSH_LOCK Lock;
    volatile LONG HandleCount;

    //
    // Aggregated data
    //
    HT_SUSPICION AggregatedSuspicion;
    ULONG SuspicionScore;

    //
    // Statistics
    //
    ULONG ProcessHandleCount;
    ULONG ThreadHandleCount;
    ULONG FileHandleCount;
    ULONG TokenHandleCount;
    ULONG SectionHandleCount;
    ULONG OtherHandleCount;
    ULONG CrossProcessHandleCount;
    ULONG HighPrivilegeHandleCount;
    ULONG DuplicatedHandleCount;

    //
    // Snapshot time
    //
    LARGE_INTEGER SnapshotTime;

    //
    // Hash table linkage
    //
    LIST_ENTRY HashEntry;
    ULONG HashBucket;
    BOOLEAN InHashTable;

    //
    // Global list linkage
    //
    LIST_ENTRY GlobalEntry;

} HT_PROCESS_HANDLES, *PHT_PROCESS_HANDLES;

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
} HT_DUPLICATION_RECORD, *PHT_DUPLICATION_RECORD;

//
// Hash bucket
//
typedef struct _HT_HASH_BUCKET {
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK Lock;
    volatile LONG Count;
} HT_HASH_BUCKET, *PHT_HASH_BUCKET;

//
// Sensitive process entry
//
typedef struct _HT_SENSITIVE_PROCESS_ENTRY {
    ULONG Hash;
    WCHAR Name[64];
    USHORT NameLength;
} HT_SENSITIVE_PROCESS_ENTRY, *PHT_SENSITIVE_PROCESS_ENTRY;

//
// Main tracker structure (internal)
//
typedef struct _HT_TRACKER {
    ULONG Signature;
    volatile LONG Initialized;

    //
    // Rundown protection for safe shutdown
    //
    EX_RUNDOWN_REF RundownRef;

    //
    // Global process list
    //
    LIST_ENTRY ProcessList;
    EX_PUSH_LOCK ProcessListLock;
    volatile LONG ProcessCount;

    //
    // Hash table for process lookup
    //
    PHT_HASH_BUCKET HashBuckets;
    ULONG HashBucketCount;

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
    // Sensitive process list
    //
    HT_SENSITIVE_PROCESS_ENTRY SensitiveProcesses[HT_MAX_SENSITIVE_PROCESSES];
    ULONG SensitiveProcessCount;

    //
    // Configuration
    //
    HT_CONFIG Config;

    //
    // Statistics
    //
    HT_STATISTICS Stats;

    //
    // Cleanup timer
    //
    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    volatile LONG CleanupTimerActive;

    //
    // Worker thread
    //
    PETHREAD WorkerThreadObject;
    KEVENT ShutdownEvent;
    KEVENT WorkAvailableEvent;
    volatile LONG ShutdownRequested;

} HT_TRACKER, *PHT_TRACKER;

// ============================================================================
// PRIVATE FUNCTION PROTOTYPES
// ============================================================================

static ULONG
HtpHashProcessId(
    _In_ HANDLE ProcessId
    );

static ULONG
HtpHashString(
    _In_ PCWSTR String,
    _In_ ULONG CharCount
    );

static PHT_HANDLE_ENTRY
HtpAllocateHandleEntry(
    _In_ PHT_TRACKER Tracker
    );

static VOID
HtpFreeHandleEntry(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_HANDLE_ENTRY Entry
    );

static PHT_PROCESS_HANDLES
HtpAllocateProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

static VOID
HtpReferenceProcessHandles(
    _Inout_ PHT_PROCESS_HANDLES Handles
    );

static VOID
HtpDereferenceProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _Inout_ PHT_PROCESS_HANDLES Handles
    );

static PHT_DUPLICATION_RECORD
HtpAllocateDuplicationRecord(
    _In_ PHT_TRACKER Tracker
    );

static VOID
HtpFreeDuplicationRecord(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_DUPLICATION_RECORD Record
    );

static NTSTATUS
HtpInsertProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles
    );

static VOID
HtpRemoveProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles
    );

_IRQL_requires_(PASSIVE_LEVEL)
static NTSTATUS
HtpEnumerateProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _Inout_ PHT_PROCESS_HANDLES Handles
    );

static HT_HANDLE_TYPE
HtpGetHandleTypeFromIndex(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE HandleValue,
    _In_ USHORT ObjectTypeIndex
    );

static HT_HANDLE_TYPE
HtpGetHandleTypeFromName(
    _In_ PCUNICODE_STRING TypeName
    );

static HT_SUSPICION
HtpAnalyzeHandleSuspicion(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_HANDLE_ENTRY Entry,
    _In_ HANDLE OwnerProcessId
    );

_IRQL_requires_(PASSIVE_LEVEL)
static BOOLEAN
HtpIsSensitiveProcessInternal(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    );

static BOOLEAN
HtpIsSensitiveProcessByName(
    _In_ PHT_TRACKER Tracker,
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

static VOID
HtpInitializeSensitiveProcessList(
    _In_ PHT_TRACKER Tracker
    );

static BOOLEAN
HtpExtractFileName(
    _In_ PCUNICODE_STRING FullPath,
    _Out_ PUNICODE_STRING FileName
    );

static VOID
HtpCleanupDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );

static VOID
HtpWorkerThreadRoutine(
    _In_ PVOID StartContext
    );

static VOID
HtpCleanupStaleDuplications(
    _In_ PHT_TRACKER Tracker
    );

static VOID
HtpFreeAllHandleEntries(
    _In_ PHT_TRACKER Tracker,
    _Inout_ PHT_PROCESS_HANDLES Handles
    );

// ============================================================================
// INLINE HELPERS
// ============================================================================

FORCEINLINE
BOOLEAN
HtpIsValidTracker(
    _In_opt_ PHT_TRACKER Tracker
    )
{
    return (Tracker != NULL &&
            Tracker->Signature == HT_SIGNATURE &&
            Tracker->Initialized != 0);
}

FORCEINLINE
BOOLEAN
HtpIsValidProcessHandles(
    _In_opt_ PHT_PROCESS_HANDLES Handles
    )
{
    return (Handles != NULL && Handles->Signature == HT_SIGNATURE);
}

FORCEINLINE
BOOLEAN
HtpAcquireRundownProtection(
    _In_ PHT_TRACKER Tracker
    )
{
    return ExAcquireRundownProtection(&Tracker->RundownRef);
}

FORCEINLINE
VOID
HtpReleaseRundownProtection(
    _In_ PHT_TRACKER Tracker
    )
{
    ExReleaseRundownProtection(&Tracker->RundownRef);
}

// ============================================================================
// PUBLIC FUNCTION IMPLEMENTATIONS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
HtInitialize(
    PHT_TRACKER* OutTracker,
    PHT_CONFIG Config
    )
{
    NTSTATUS Status;
    PHT_TRACKER Tracker = NULL;
    HANDLE ThreadHandle = NULL;
    OBJECT_ATTRIBUTES ObjectAttributes;
    LARGE_INTEGER DueTime;
    ULONG i;
    SIZE_T HashTableSize;

    PAGED_CODE();

    if (OutTracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutTracker = NULL;

    //
    // Allocate tracker structure from NonPagedPoolNx
    //
    Tracker = (PHT_TRACKER)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HT_TRACKER),
        HT_POOL_TAG
        );

    if (Tracker == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Tracker, sizeof(HT_TRACKER));
    Tracker->Signature = HT_SIGNATURE;

    //
    // Initialize rundown protection
    //
    ExInitializeRundownProtection(&Tracker->RundownRef);

    //
    // Initialize global process list
    //
    InitializeListHead(&Tracker->ProcessList);
    ExInitializePushLock(&Tracker->ProcessListLock);

    //
    // Allocate and initialize hash buckets
    //
    Tracker->HashBucketCount = HT_HASH_BUCKET_COUNT;
    HashTableSize = (SIZE_T)HT_HASH_BUCKET_COUNT * sizeof(HT_HASH_BUCKET);

    Tracker->HashBuckets = (PHT_HASH_BUCKET)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        HashTableSize,
        HT_POOL_TAG
        );

    if (Tracker->HashBuckets == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(Tracker->HashBuckets, HashTableSize);

    for (i = 0; i < HT_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&Tracker->HashBuckets[i].ProcessList);
        ExInitializePushLock(&Tracker->HashBuckets[i].Lock);
    }

    //
    // Initialize duplication tracking
    //
    InitializeListHead(&Tracker->DuplicationList);
    ExInitializePushLock(&Tracker->DuplicationLock);

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &Tracker->HandleEntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_HANDLE_ENTRY),
        HT_POOL_TAG_ENTRY,
        0
        );

    ExInitializeNPagedLookasideList(
        &Tracker->ProcessHandlesLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_PROCESS_HANDLES),
        HT_POOL_TAG_PROCESS,
        0
        );

    ExInitializeNPagedLookasideList(
        &Tracker->DuplicationLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(HT_DUPLICATION_RECORD),
        HT_POOL_TAG_ENTRY,
        0
        );

    Tracker->LookasideInitialized = TRUE;

    //
    // Apply configuration
    //
    if (Config != NULL) {
        Tracker->Config = *Config;
    } else {
        Tracker->Config.EnableCrossProcessDetection = TRUE;
        Tracker->Config.EnableDuplicationTracking = TRUE;
        Tracker->Config.EnableSensitiveProcessMonitoring = TRUE;
        Tracker->Config.MaxHandlesPerProcess = HT_MAX_HANDLES_PER_PROCESS;
        Tracker->Config.MaxDuplications = HT_MAX_DUPLICATIONS;
        Tracker->Config.SuspicionThreshold = 50;
        Tracker->Config.CleanupIntervalMs = HT_DEFAULT_CLEANUP_INTERVAL_MS;
        Tracker->Config.CacheTimeoutMs = HT_DEFAULT_CACHE_TIMEOUT_MS;
    }

    //
    // Validate configuration limits
    //
    if (Tracker->Config.MaxHandlesPerProcess == 0) {
        Tracker->Config.MaxHandlesPerProcess = HT_MAX_HANDLES_PER_PROCESS;
    }
    if (Tracker->Config.MaxDuplications == 0) {
        Tracker->Config.MaxDuplications = HT_MAX_DUPLICATIONS;
    }
    if (Tracker->Config.CleanupIntervalMs < 1000) {
        Tracker->Config.CleanupIntervalMs = HT_DEFAULT_CLEANUP_INTERVAL_MS;
    }

    //
    // Initialize sensitive process list
    //
    HtpInitializeSensitiveProcessList(Tracker);

    //
    // Initialize statistics
    //
    KeQuerySystemTime(&Tracker->Stats.StartTime);

    //
    // Initialize worker thread synchronization
    //
    KeInitializeEvent(&Tracker->ShutdownEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Tracker->WorkAvailableEvent, SynchronizationEvent, FALSE);

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
        HtpWorkerThreadRoutine,
        Tracker
        );

    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    //
    // Get thread object reference
    //
    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Tracker->WorkerThreadObject,
        NULL
        );

    ZwClose(ThreadHandle);
    ThreadHandle = NULL;

    if (!NT_SUCCESS(Status)) {
        //
        // Signal thread to exit since it's running
        //
        InterlockedExchange(&Tracker->ShutdownRequested, 1);
        KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        goto Cleanup;
    }

    //
    // Initialize cleanup timer
    //
    KeInitializeTimer(&Tracker->CleanupTimer);
    KeInitializeDpc(&Tracker->CleanupDpc, HtpCleanupDpcRoutine, Tracker);

    //
    // Start cleanup timer
    //
    DueTime.QuadPart = -((LONGLONG)Tracker->Config.CleanupIntervalMs * 10000);
    KeSetTimerEx(
        &Tracker->CleanupTimer,
        DueTime,
        Tracker->Config.CleanupIntervalMs,
        &Tracker->CleanupDpc
        );
    InterlockedExchange(&Tracker->CleanupTimerActive, 1);

    //
    // Mark as initialized
    //
    InterlockedExchange(&Tracker->Initialized, 1);
    *OutTracker = Tracker;

    return STATUS_SUCCESS;

Cleanup:
    //
    // Wait for worker thread if it was created
    //
    if (Tracker->WorkerThreadObject != NULL) {
        InterlockedExchange(&Tracker->ShutdownRequested, 1);
        KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        KeWaitForSingleObject(
            Tracker->WorkerThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Tracker->WorkerThreadObject);
    }

    if (Tracker->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Tracker->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&Tracker->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&Tracker->DuplicationLookaside);
    }

    if (Tracker->HashBuckets != NULL) {
        ExFreePoolWithTag(Tracker->HashBuckets, HT_POOL_TAG);
    }

    ExFreePoolWithTag(Tracker, HT_POOL_TAG);
    return Status;
}

_Use_decl_annotations_
VOID
HtShutdown(
    PHT_TRACKER* TrackerPtr
    )
{
    PHT_TRACKER Tracker;
    PLIST_ENTRY Entry;
    PHT_PROCESS_HANDLES Handles;
    PHT_DUPLICATION_RECORD DupRecord;
    ULONG i;

    PAGED_CODE();

    if (TrackerPtr == NULL || *TrackerPtr == NULL) {
        return;
    }

    Tracker = *TrackerPtr;
    *TrackerPtr = NULL;

    if (!HtpIsValidTracker(Tracker)) {
        return;
    }

    //
    // Mark as not initialized to prevent new operations
    //
    InterlockedExchange(&Tracker->Initialized, 0);
    InterlockedExchange(&Tracker->ShutdownRequested, 1);

    //
    // Wait for all outstanding operations to complete
    //
    ExWaitForRundownProtectionRelease(&Tracker->RundownRef);

    //
    // Cancel cleanup timer
    //
    if (InterlockedExchange(&Tracker->CleanupTimerActive, 0)) {
        KeCancelTimer(&Tracker->CleanupTimer);
        KeFlushQueuedDpcs();
    }

    //
    // Signal worker thread to exit and wait
    //
    KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Tracker->WorkAvailableEvent, IO_NO_INCREMENT, FALSE);

    if (Tracker->WorkerThreadObject != NULL) {
        KeWaitForSingleObject(
            Tracker->WorkerThreadObject,
            Executive,
            KernelMode,
            FALSE,
            NULL
            );
        ObDereferenceObject(Tracker->WorkerThreadObject);
        Tracker->WorkerThreadObject = NULL;
    }

    //
    // Free all process handles from hash table
    //
    for (i = 0; i < Tracker->HashBucketCount; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Tracker->HashBuckets[i].Lock);

        while (!IsListEmpty(&Tracker->HashBuckets[i].ProcessList)) {
            Entry = RemoveHeadList(&Tracker->HashBuckets[i].ProcessList);
            Handles = CONTAINING_RECORD(Entry, HT_PROCESS_HANDLES, HashEntry);
            Handles->InHashTable = FALSE;
            InterlockedDecrement(&Tracker->HashBuckets[i].Count);

            ExReleasePushLockExclusive(&Tracker->HashBuckets[i].Lock);
            KeLeaveCriticalRegion();

            //
            // Free all handle entries
            //
            HtpFreeAllHandleEntries(Tracker, Handles);

            //
            // Free process object reference
            //
            if (Handles->ProcessObject != NULL) {
                ObDereferenceObject(Handles->ProcessObject);
            }

            //
            // Return to lookaside list
            //
            ExFreeToNPagedLookasideList(&Tracker->ProcessHandlesLookaside, Handles);

            KeEnterCriticalRegion();
            ExAcquirePushLockExclusive(&Tracker->HashBuckets[i].Lock);
        }

        ExReleasePushLockExclusive(&Tracker->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Free all duplication records
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->DuplicationLock);

    while (!IsListEmpty(&Tracker->DuplicationList)) {
        Entry = RemoveHeadList(&Tracker->DuplicationList);
        DupRecord = CONTAINING_RECORD(Entry, HT_DUPLICATION_RECORD, ListEntry);
        InterlockedDecrement(&Tracker->DuplicationCount);

        ExReleasePushLockExclusive(&Tracker->DuplicationLock);
        KeLeaveCriticalRegion();

        ExFreeToNPagedLookasideList(&Tracker->DuplicationLookaside, DupRecord);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Tracker->DuplicationLock);
    }

    ExReleasePushLockExclusive(&Tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    //
    // Delete lookaside lists
    //
    if (Tracker->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&Tracker->HandleEntryLookaside);
        ExDeleteNPagedLookasideList(&Tracker->ProcessHandlesLookaside);
        ExDeleteNPagedLookasideList(&Tracker->DuplicationLookaside);
    }

    //
    // Free hash buckets
    //
    if (Tracker->HashBuckets != NULL) {
        ExFreePoolWithTag(Tracker->HashBuckets, HT_POOL_TAG);
    }

    //
    // Invalidate signature and free tracker
    //
    Tracker->Signature = 0;
    ExFreePoolWithTag(Tracker, HT_POOL_TAG);
}

_Use_decl_annotations_
NTSTATUS
HtSnapshotHandles(
    PHT_TRACKER Tracker,
    HANDLE ProcessId,
    PHT_PROCESS_HANDLES* OutHandles
    )
{
    NTSTATUS Status;
    PHT_PROCESS_HANDLES Handles = NULL;

    PAGED_CODE();

    if (!HtpIsValidTracker(Tracker) || OutHandles == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *OutHandles = NULL;

    //
    // Acquire rundown protection
    //
    if (!HtpAcquireRundownProtection(Tracker)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Allocate process handles structure
    //
    Handles = HtpAllocateProcessHandles(Tracker, ProcessId);
    if (Handles == NULL) {
        HtpReleaseRundownProtection(Tracker);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Enumerate handles (this is the expensive operation)
    //
    Status = HtpEnumerateProcessHandles(Tracker, ProcessId, Handles);
    if (!NT_SUCCESS(Status)) {
        HtpDereferenceProcessHandles(Tracker, Handles);
        HtpReleaseRundownProtection(Tracker);
        return Status;
    }

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalEnumerations);
    InterlockedAdd64(&Tracker->Stats.HandlesTracked, Handles->HandleCount);

    if (Handles->CrossProcessHandleCount > 0) {
        InterlockedAdd64(&Tracker->Stats.CrossProcessHandles, Handles->CrossProcessHandleCount);
    }

    if (Handles->AggregatedSuspicion != HtSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousHandles);
    }

    //
    // Insert into hash table for caching
    //
    HtpInsertProcessHandles(Tracker, Handles);

    *OutHandles = Handles;

    HtpReleaseRundownProtection(Tracker);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HtGetHandlesInfo(
    PHT_PROCESS_HANDLES Handles,
    PHT_PROCESS_HANDLES_INFO Info
    )
{
    if (!HtpIsValidProcessHandles(Handles) || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(HT_PROCESS_HANDLES_INFO));

    Info->ProcessId = Handles->ProcessId;
    Info->HandleCount = Handles->HandleCount;
    Info->AggregatedSuspicion = Handles->AggregatedSuspicion;
    Info->SuspicionScore = Handles->SuspicionScore;
    Info->ProcessHandleCount = Handles->ProcessHandleCount;
    Info->ThreadHandleCount = Handles->ThreadHandleCount;
    Info->FileHandleCount = Handles->FileHandleCount;
    Info->TokenHandleCount = Handles->TokenHandleCount;
    Info->SectionHandleCount = Handles->SectionHandleCount;
    Info->OtherHandleCount = Handles->OtherHandleCount;
    Info->CrossProcessHandleCount = Handles->CrossProcessHandleCount;
    Info->HighPrivilegeHandleCount = Handles->HighPrivilegeHandleCount;
    Info->SnapshotTime = Handles->SnapshotTime;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HtGetHandleByIndex(
    PHT_PROCESS_HANDLES Handles,
    ULONG Index,
    PHT_HANDLE_INFO Info
    )
{
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY HandleEntry;
    ULONG CurrentIndex = 0;

    if (!HtpIsValidProcessHandles(Handles) || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(HT_HANDLE_INFO));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Handles->Lock);

    for (Entry = Handles->HandleList.Flink;
         Entry != &Handles->HandleList;
         Entry = Entry->Flink) {

        if (CurrentIndex == Index) {
            HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY, ListEntry);

            Info->HandleValue = HandleEntry->HandleValue;
            Info->Type = HandleEntry->Type;
            Info->GrantedAccess = HandleEntry->GrantedAccess;
            Info->TargetProcessId = HandleEntry->TargetProcessId;
            Info->IsDuplicated = HandleEntry->IsDuplicated;
            Info->DuplicatedFromProcess = HandleEntry->DuplicatedFromProcess;
            Info->SuspicionFlags = HandleEntry->SuspicionFlags;
            Info->SuspicionScore = HandleEntry->SuspicionScore;
            Info->ObjectNameLength = HandleEntry->ObjectNameLength;

            if (HandleEntry->ObjectNameLength > 0) {
                RtlCopyMemory(
                    Info->ObjectName,
                    HandleEntry->ObjectName,
                    min(HandleEntry->ObjectNameLength, sizeof(Info->ObjectName) - sizeof(WCHAR))
                    );
            }

            ExReleasePushLockShared(&Handles->Lock);
            KeLeaveCriticalRegion();
            return STATUS_SUCCESS;
        }

        CurrentIndex++;
    }

    ExReleasePushLockShared(&Handles->Lock);
    KeLeaveCriticalRegion();

    return STATUS_NO_MORE_ENTRIES;
}

_Use_decl_annotations_
NTSTATUS
HtRecordDuplication(
    PHT_TRACKER Tracker,
    HANDLE SourceProcess,
    HANDLE TargetProcess,
    HANDLE SourceHandle,
    HANDLE TargetHandle,
    ACCESS_MASK GrantedAccess,
    HT_HANDLE_TYPE HandleType
    )
{
    PHT_DUPLICATION_RECORD Record = NULL;
    HT_SUSPICION Suspicion = HtSuspicion_None;

    if (!HtpIsValidTracker(Tracker)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!Tracker->Config.EnableDuplicationTracking) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire rundown protection
    //
    if (!HtpAcquireRundownProtection(Tracker)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Check duplication limit
    //
    if ((ULONG)Tracker->DuplicationCount >= Tracker->Config.MaxDuplications) {
        HtpReleaseRundownProtection(Tracker);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate duplication record
    //
    Record = HtpAllocateDuplicationRecord(Tracker);
    if (Record == NULL) {
        HtpReleaseRundownProtection(Tracker);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Populate record
    //
    Record->SourceProcessId = SourceProcess;
    Record->TargetProcessId = TargetProcess;
    Record->SourceHandle = SourceHandle;
    Record->TargetHandle = TargetHandle;
    Record->GrantedAccess = GrantedAccess;
    Record->HandleType = HandleType;
    KeQuerySystemTime(&Record->Timestamp);

    //
    // Analyze suspicion
    //
    if (SourceProcess != TargetProcess) {
        Suspicion |= HtSuspicion_CrossProcess;
        Suspicion |= HtSuspicion_DuplicatedIn;
    }

    if (HandleType == HtType_Process && HtpIsInjectionCapableAccess(GrantedAccess)) {
        Suspicion |= HtSuspicion_InjectionCapable;
    }

    if (HandleType == HtType_Token && (GrantedAccess & HT_TOKEN_STEAL_ACCESS)) {
        Suspicion |= HtSuspicion_TokenSteal;
    }

    Record->SuspicionFlags = Suspicion;

    //
    // Insert into duplication list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->DuplicationLock);
    InsertTailList(&Tracker->DuplicationList, &Record->ListEntry);
    InterlockedIncrement(&Tracker->DuplicationCount);
    ExReleasePushLockExclusive(&Tracker->DuplicationLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.DuplicationsRecorded);

    if (Suspicion != HtSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousHandles);
    }

    HtpReleaseRundownProtection(Tracker);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HtAnalyzeHandles(
    PHT_TRACKER Tracker,
    PHT_PROCESS_HANDLES Handles,
    HT_SUSPICION* Flags,
    PULONG Score
    )
{
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY HandleEntry;
    HT_SUSPICION AggregatedSuspicion = HtSuspicion_None;

    if (!HtpIsValidTracker(Tracker) || !HtpIsValidProcessHandles(Handles) || Flags == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Flags = HtSuspicion_None;
    if (Score != NULL) {
        *Score = 0;
    }

    //
    // Acquire rundown protection
    //
    if (!HtpAcquireRundownProtection(Tracker)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Aggregate suspicion from all handles
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Handles->Lock);

    for (Entry = Handles->HandleList.Flink;
         Entry != &Handles->HandleList;
         Entry = Entry->Flink) {

        HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY, ListEntry);
        AggregatedSuspicion |= HandleEntry->SuspicionFlags;
    }

    ExReleasePushLockShared(&Handles->Lock);
    KeLeaveCriticalRegion();

    //
    // Check for many handles (potential handle table attack)
    //
    if ((ULONG)Handles->HandleCount > Tracker->Config.MaxHandlesPerProcess / 2) {
        AggregatedSuspicion |= HtSuspicion_ManyHandles;
    }

    //
    // Update handle structure
    //
    Handles->AggregatedSuspicion = AggregatedSuspicion;
    Handles->SuspicionScore = HtpCalculateSuspicionScore(AggregatedSuspicion);

    *Flags = AggregatedSuspicion;
    if (Score != NULL) {
        *Score = Handles->SuspicionScore;
    }

    HtpReleaseRundownProtection(Tracker);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HtFindCrossProcessHandles(
    PHT_TRACKER Tracker,
    HANDLE TargetProcessId,
    PHT_HANDLE_INFO Entries,
    ULONG MaxEntries,
    PULONG Count
    )
{
    NTSTATUS Status = STATUS_SUCCESS;
    PLIST_ENTRY ProcessEntry, HandleEntry;
    PHT_PROCESS_HANDLES ProcessHandles;
    PHT_HANDLE_ENTRY Entry;
    ULONG FoundCount = 0;
    ULONG i;

    PAGED_CODE();

    if (!HtpIsValidTracker(Tracker) || Entries == NULL || Count == NULL || MaxEntries == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *Count = 0;

    //
    // Acquire rundown protection
    //
    if (!HtpAcquireRundownProtection(Tracker)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Search all hash buckets
    //
    for (i = 0; i < Tracker->HashBucketCount && FoundCount < MaxEntries; i++) {
        KeEnterCriticalRegion();
        ExAcquirePushLockShared(&Tracker->HashBuckets[i].Lock);

        for (ProcessEntry = Tracker->HashBuckets[i].ProcessList.Flink;
             ProcessEntry != &Tracker->HashBuckets[i].ProcessList && FoundCount < MaxEntries;
             ProcessEntry = ProcessEntry->Flink) {

            ProcessHandles = CONTAINING_RECORD(ProcessEntry, HT_PROCESS_HANDLES, HashEntry);

            //
            // Skip if this is the target process itself
            //
            if (ProcessHandles->ProcessId == TargetProcessId) {
                continue;
            }

            //
            // Search this process's handles
            //
            ExAcquirePushLockShared(&ProcessHandles->Lock);

            for (HandleEntry = ProcessHandles->HandleList.Flink;
                 HandleEntry != &ProcessHandles->HandleList && FoundCount < MaxEntries;
                 HandleEntry = HandleEntry->Flink) {

                Entry = CONTAINING_RECORD(HandleEntry, HT_HANDLE_ENTRY, ListEntry);

                //
                // Check if this handle references the target process
                //
                if (Entry->TargetProcessId == TargetProcessId) {
                    PHT_HANDLE_INFO Info = &Entries[FoundCount];

                    Info->HandleValue = Entry->HandleValue;
                    Info->Type = Entry->Type;
                    Info->GrantedAccess = Entry->GrantedAccess;
                    Info->TargetProcessId = Entry->TargetProcessId;
                    Info->IsDuplicated = Entry->IsDuplicated;
                    Info->DuplicatedFromProcess = Entry->DuplicatedFromProcess;
                    Info->SuspicionFlags = Entry->SuspicionFlags;
                    Info->SuspicionScore = Entry->SuspicionScore;
                    Info->ObjectNameLength = Entry->ObjectNameLength;

                    if (Entry->ObjectNameLength > 0) {
                        RtlCopyMemory(
                            Info->ObjectName,
                            Entry->ObjectName,
                            min(Entry->ObjectNameLength, sizeof(Info->ObjectName) - sizeof(WCHAR))
                            );
                    }

                    FoundCount++;
                }
            }

            ExReleasePushLockShared(&ProcessHandles->Lock);
        }

        ExReleasePushLockShared(&Tracker->HashBuckets[i].Lock);
        KeLeaveCriticalRegion();
    }

    *Count = FoundCount;

    //
    // Check if we hit the limit (more entries may exist)
    //
    if (FoundCount == MaxEntries) {
        Status = STATUS_BUFFER_TOO_SMALL;
    }

    HtpReleaseRundownProtection(Tracker);
    return Status;
}

_Use_decl_annotations_
VOID
HtReleaseHandles(
    PHT_TRACKER Tracker,
    PHT_PROCESS_HANDLES Handles
    )
{
    if (!HtpIsValidTracker(Tracker) || !HtpIsValidProcessHandles(Handles)) {
        return;
    }

    //
    // Remove from hash table first
    //
    HtpRemoveProcessHandles(Tracker, Handles);

    //
    // Dereference (will free when refcount hits zero)
    //
    HtpDereferenceProcessHandles(Tracker, Handles);
}

_Use_decl_annotations_
NTSTATUS
HtGetStatistics(
    PHT_TRACKER Tracker,
    PHT_STATISTICS Stats
    )
{
    if (Tracker == NULL || Tracker->Signature != HT_SIGNATURE || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Copy statistics (all fields are volatile, so this is safe at any IRQL)
    //
    Stats->HandlesTracked = Tracker->Stats.HandlesTracked;
    Stats->SuspiciousHandles = Tracker->Stats.SuspiciousHandles;
    Stats->CrossProcessHandles = Tracker->Stats.CrossProcessHandles;
    Stats->TotalEnumerations = Tracker->Stats.TotalEnumerations;
    Stats->DuplicationsRecorded = Tracker->Stats.DuplicationsRecorded;
    Stats->SensitiveAccessDetected = Tracker->Stats.SensitiveAccessDetected;
    Stats->HighPrivilegeHandles = Tracker->Stats.HighPrivilegeHandles;
    Stats->TokenHandlesTracked = Tracker->Stats.TokenHandlesTracked;
    Stats->InjectionHandlesDetected = Tracker->Stats.InjectionHandlesDetected;
    Stats->StartTime = Tracker->Stats.StartTime;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
HtIsSensitiveProcess(
    PHT_TRACKER Tracker,
    HANDLE ProcessId,
    PBOOLEAN IsSensitive
    )
{
    PAGED_CODE();

    if (!HtpIsValidTracker(Tracker) || IsSensitive == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsSensitive = FALSE;

    if (!Tracker->Config.EnableSensitiveProcessMonitoring) {
        return STATUS_SUCCESS;
    }

    //
    // Acquire rundown protection
    //
    if (!HtpAcquireRundownProtection(Tracker)) {
        return STATUS_DEVICE_NOT_READY;
    }

    *IsSensitive = HtpIsSensitiveProcessInternal(Tracker, ProcessId);

    HtpReleaseRundownProtection(Tracker);
    return STATUS_SUCCESS;
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

    //
    // MurmurHash3 finalizer
    //
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
    _In_ ULONG CharCount
    )
{
    ULONG Hash = 5381;
    ULONG i;

    for (i = 0; i < CharCount && String[i] != L'\0'; i++) {
        WCHAR Ch = String[i];

        //
        // Case-insensitive hash
        //
        if (Ch >= L'A' && Ch <= L'Z') {
            Ch += (L'a' - L'A');
        }

        Hash = ((Hash << 5) + Hash) + (ULONG)Ch;
    }

    return Hash;
}

static PHT_HANDLE_ENTRY
HtpAllocateHandleEntry(
    _In_ PHT_TRACKER Tracker
    )
{
    PHT_HANDLE_ENTRY Entry;

    Entry = (PHT_HANDLE_ENTRY)ExAllocateFromNPagedLookasideList(
        &Tracker->HandleEntryLookaside
        );

    if (Entry != NULL) {
        RtlZeroMemory(Entry, sizeof(HT_HANDLE_ENTRY));
        InitializeListHead(&Entry->ListEntry);
    }

    return Entry;
}

static VOID
HtpFreeHandleEntry(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_HANDLE_ENTRY Entry
    )
{
    ExFreeToNPagedLookasideList(&Tracker->HandleEntryLookaside, Entry);
}

static PHT_PROCESS_HANDLES
HtpAllocateProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessId
    )
{
    PHT_PROCESS_HANDLES Handles;
    NTSTATUS Status;
    PEPROCESS Process = NULL;

    Handles = (PHT_PROCESS_HANDLES)ExAllocateFromNPagedLookasideList(
        &Tracker->ProcessHandlesLookaside
        );

    if (Handles != NULL) {
        RtlZeroMemory(Handles, sizeof(HT_PROCESS_HANDLES));

        Handles->Signature = HT_SIGNATURE;
        Handles->RefCount = 1;
        Handles->ProcessId = ProcessId;
        InitializeListHead(&Handles->HandleList);
        ExInitializePushLock(&Handles->Lock);
        InitializeListHead(&Handles->HashEntry);
        InitializeListHead(&Handles->GlobalEntry);

        //
        // Get process object reference (for lifetime management)
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
HtpReferenceProcessHandles(
    _Inout_ PHT_PROCESS_HANDLES Handles
    )
{
    InterlockedIncrement(&Handles->RefCount);
}

static VOID
HtpDereferenceProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _Inout_ PHT_PROCESS_HANDLES Handles
    )
{
    LONG NewRefCount;

    NewRefCount = InterlockedDecrement(&Handles->RefCount);
    NT_ASSERT(NewRefCount >= 0);

    if (NewRefCount == 0) {
        //
        // Free all handle entries
        //
        HtpFreeAllHandleEntries(Tracker, Handles);

        //
        // Free process object reference
        //
        if (Handles->ProcessObject != NULL) {
            ObDereferenceObject(Handles->ProcessObject);
            Handles->ProcessObject = NULL;
        }

        //
        // Invalidate signature
        //
        Handles->Signature = 0;

        //
        // Return to lookaside list
        //
        ExFreeToNPagedLookasideList(&Tracker->ProcessHandlesLookaside, Handles);
    }
}

static VOID
HtpFreeAllHandleEntries(
    _In_ PHT_TRACKER Tracker,
    _Inout_ PHT_PROCESS_HANDLES Handles
    )
{
    PLIST_ENTRY Entry;
    PHT_HANDLE_ENTRY HandleEntry;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Handles->Lock);

    while (!IsListEmpty(&Handles->HandleList)) {
        Entry = RemoveHeadList(&Handles->HandleList);
        HandleEntry = CONTAINING_RECORD(Entry, HT_HANDLE_ENTRY, ListEntry);
        InterlockedDecrement(&Handles->HandleCount);

        ExReleasePushLockExclusive(&Handles->Lock);
        KeLeaveCriticalRegion();

        HtpFreeHandleEntry(Tracker, HandleEntry);

        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Handles->Lock);
    }

    ExReleasePushLockExclusive(&Handles->Lock);
    KeLeaveCriticalRegion();
}

static PHT_DUPLICATION_RECORD
HtpAllocateDuplicationRecord(
    _In_ PHT_TRACKER Tracker
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
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_DUPLICATION_RECORD Record
    )
{
    ExFreeToNPagedLookasideList(&Tracker->DuplicationLookaside, Record);
}

static NTSTATUS
HtpInsertProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles
    )
{
    ULONG Hash;

    Hash = HtpHashProcessId(Handles->ProcessId);
    Handles->HashBucket = Hash;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);

    if (!Handles->InHashTable) {
        InsertTailList(&Tracker->HashBuckets[Hash].ProcessList, &Handles->HashEntry);
        InterlockedIncrement(&Tracker->HashBuckets[Hash].Count);
        Handles->InHashTable = TRUE;
        HtpReferenceProcessHandles(Handles);
    }

    ExReleasePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    //
    // Also add to global list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ProcessListLock);
    InsertTailList(&Tracker->ProcessList, &Handles->GlobalEntry);
    InterlockedIncrement(&Tracker->ProcessCount);
    ExReleasePushLockExclusive(&Tracker->ProcessListLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

static VOID
HtpRemoveProcessHandles(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_PROCESS_HANDLES Handles
    )
{
    ULONG Hash;
    BOOLEAN WasInHashTable = FALSE;

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
        WasInHashTable = TRUE;
    }

    ExReleasePushLockExclusive(&Tracker->HashBuckets[Hash].Lock);
    KeLeaveCriticalRegion();

    //
    // Remove from global list
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->ProcessListLock);
    if (!IsListEmpty(&Handles->GlobalEntry)) {
        RemoveEntryList(&Handles->GlobalEntry);
        InitializeListHead(&Handles->GlobalEntry);
        InterlockedDecrement(&Tracker->ProcessCount);
    }
    ExReleasePushLockExclusive(&Tracker->ProcessListLock);
    KeLeaveCriticalRegion();

    //
    // Release reference from hash table
    //
    if (WasInHashTable) {
        HtpDereferenceProcessHandles(Tracker, Handles);
    }
}

_Use_decl_annotations_
static NTSTATUS
HtpEnumerateProcessHandles(
    PHT_TRACKER Tracker,
    HANDLE ProcessId,
    PHT_PROCESS_HANDLES Handles
    )
{
    NTSTATUS Status;
    PVOID Buffer = NULL;
    ULONG BufferSize = HT_INITIAL_BUFFER_SIZE;
    ULONG ReturnLength = 0;
    PSYSTEM_HANDLE_INFORMATION_EX HandleInfo = NULL;
    ULONG_PTR i;
    PEPROCESS TargetProcess = NULL;
    HANDLE TargetProcessHandle = NULL;

    PAGED_CODE();

    //
    // Verify target process exists
    //
    Status = PsLookupProcessByProcessId(ProcessId, &TargetProcess);
    if (!NT_SUCCESS(Status)) {
        return STATUS_NOT_FOUND;
    }

    //
    // Open handle to target process for handle queries
    //
    Status = ObOpenObjectByPointer(
        TargetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        &TargetProcessHandle
        );

    ObDereferenceObject(TargetProcess);
    TargetProcess = NULL;

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Allocate buffer for handle information (paged pool - we're at PASSIVE_LEVEL)
    //
    do {
        if (Buffer != NULL) {
            ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
            Buffer = NULL;
        }

        Buffer = ExAllocatePool2(
            POOL_FLAG_PAGED,
            BufferSize,
            HT_POOL_TAG_BUFFER
            );

        if (Buffer == NULL) {
            ZwClose(TargetProcessHandle);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQuerySystemInformation(
            SystemExtendedHandleInformation,
            Buffer,
            BufferSize,
            &ReturnLength
            );

        if (Status == STATUS_INFO_LENGTH_MISMATCH) {
            BufferSize = ReturnLength + 0x10000;
            if (BufferSize > HT_MAX_BUFFER_SIZE) {
                ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
                ZwClose(TargetProcessHandle);
                return STATUS_BUFFER_OVERFLOW;
            }
        }

    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
        ZwClose(TargetProcessHandle);
        return Status;
    }

    HandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)Buffer;

    //
    // Process each handle belonging to our target process
    //
    for (i = 0; i < HandleInfo->NumberOfHandles &&
         (ULONG)Handles->HandleCount < Tracker->Config.MaxHandlesPerProcess; i++) {

        PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX HandleEntry = &HandleInfo->Handles[i];
        PHT_HANDLE_ENTRY NewEntry;
        HANDLE DuplicatedHandle = NULL;
        NTSTATUS DupStatus;

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
        // Populate basic entry data from system information
        // NOTE: We do NOT access HandleEntry->Object directly - it's an unreferenced pointer!
        //
        NewEntry->HandleValue = (HANDLE)HandleEntry->HandleValue;
        NewEntry->GrantedAccess = HandleEntry->GrantedAccess;
        NewEntry->ObjectTypeIndex = HandleEntry->ObjectTypeIndex;

        //
        // Safely determine handle type by duplicating the handle to our process
        // and querying its type. This is the ONLY safe way to access handle information.
        //
        DupStatus = ZwDuplicateObject(
            TargetProcessHandle,
            (HANDLE)HandleEntry->HandleValue,
            ZwCurrentProcess(),
            &DuplicatedHandle,
            0,
            0,
            DUPLICATE_SAME_ACCESS
            );

        if (NT_SUCCESS(DupStatus) && DuplicatedHandle != NULL) {
            //
            // Query handle type using the safely duplicated handle
            //
            NewEntry->Type = HtpGetHandleTypeFromIndex(
                Tracker,
                ZwCurrentProcess(),
                DuplicatedHandle,
                HandleEntry->ObjectTypeIndex
                );

            //
            // For process/thread handles, get target process ID safely
            //
            if (NewEntry->Type == HtType_Process) {
                PROCESS_BASIC_INFORMATION BasicInfo;
                ULONG RetLen;

                Status = ZwQueryInformationProcess(
                    DuplicatedHandle,
                    ProcessBasicInformation,
                    &BasicInfo,
                    sizeof(BasicInfo),
                    &RetLen
                    );

                if (NT_SUCCESS(Status)) {
                    NewEntry->TargetProcessId = (HANDLE)BasicInfo.UniqueProcessId;
                }
            } else if (NewEntry->Type == HtType_Thread) {
                THREAD_BASIC_INFORMATION ThreadInfo;
                ULONG RetLen;

                Status = ZwQueryInformationThread(
                    DuplicatedHandle,
                    ThreadBasicInformation,
                    &ThreadInfo,
                    sizeof(ThreadInfo),
                    &RetLen
                    );

                if (NT_SUCCESS(Status)) {
                    NewEntry->TargetProcessId = ThreadInfo.ClientId.UniqueProcess;
                }
            }

            ZwClose(DuplicatedHandle);
            DuplicatedHandle = NULL;
        }

        //
        // Check for cross-process handle
        //
        if (NewEntry->TargetProcessId != NULL &&
            NewEntry->TargetProcessId != ProcessId) {
            Handles->CrossProcessHandleCount++;
        }

        //
        // Analyze suspicion
        //
        NewEntry->SuspicionFlags = HtpAnalyzeHandleSuspicion(Tracker, NewEntry, ProcessId);
        NewEntry->SuspicionScore = HtpCalculateSuspicionScore(NewEntry->SuspicionFlags);

        //
        // Update type statistics
        //
        switch (NewEntry->Type) {
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
            InterlockedIncrement64(&Tracker->Stats.TokenHandlesTracked);
            break;
        case HtType_Section:
            Handles->SectionHandleCount++;
            break;
        default:
            Handles->OtherHandleCount++;
            break;
        }

        if (NewEntry->SuspicionFlags & HtSuspicion_HighPrivilege) {
            Handles->HighPrivilegeHandleCount++;
            InterlockedIncrement64(&Tracker->Stats.HighPrivilegeHandles);
        }

        if (NewEntry->SuspicionFlags & HtSuspicion_InjectionCapable) {
            InterlockedIncrement64(&Tracker->Stats.InjectionHandlesDetected);
        }

        //
        // Insert into handle list
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&Handles->Lock);
        InsertTailList(&Handles->HandleList, &NewEntry->ListEntry);
        InterlockedIncrement(&Handles->HandleCount);
        ExReleasePushLockExclusive(&Handles->Lock);
        KeLeaveCriticalRegion();
    }

    //
    // Calculate aggregated suspicion
    //
    Handles->AggregatedSuspicion = HtSuspicion_None;

    if (Handles->CrossProcessHandleCount > 0) {
        Handles->AggregatedSuspicion |= HtSuspicion_CrossProcess;
    }

    if (Handles->HighPrivilegeHandleCount > 0) {
        Handles->AggregatedSuspicion |= HtSuspicion_HighPrivilege;
    }

    if ((ULONG)Handles->HandleCount > Tracker->Config.MaxHandlesPerProcess / 2) {
        Handles->AggregatedSuspicion |= HtSuspicion_ManyHandles;
    }

    Handles->SuspicionScore = HtpCalculateSuspicionScore(Handles->AggregatedSuspicion);

    ExFreePoolWithTag(Buffer, HT_POOL_TAG_BUFFER);
    ZwClose(TargetProcessHandle);

    return STATUS_SUCCESS;
}

static HT_HANDLE_TYPE
HtpGetHandleTypeFromIndex(
    _In_ PHT_TRACKER Tracker,
    _In_ HANDLE ProcessHandle,
    _In_ HANDLE HandleValue,
    _In_ USHORT ObjectTypeIndex
    )
{
    NTSTATUS Status;
    POBJECT_TYPE_INFORMATION TypeInfo = NULL;
    ULONG TypeInfoSize = sizeof(OBJECT_TYPE_INFORMATION) + 256;
    ULONG ReturnLength;
    HT_HANDLE_TYPE Type = HtType_Unknown;

    UNREFERENCED_PARAMETER(Tracker);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ObjectTypeIndex);

    //
    // Query object type information using the handle
    //
    TypeInfo = (POBJECT_TYPE_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED,
        TypeInfoSize,
        HT_POOL_TAG_BUFFER
        );

    if (TypeInfo == NULL) {
        return HtType_Unknown;
    }

    Status = ZwQueryObject(
        HandleValue,
        ObjectTypeInformation,
        TypeInfo,
        TypeInfoSize,
        &ReturnLength
        );

    if (NT_SUCCESS(Status) && TypeInfo->TypeName.Buffer != NULL) {
        Type = HtpGetHandleTypeFromName(&TypeInfo->TypeName);
    }

    ExFreePoolWithTag(TypeInfo, HT_POOL_TAG_BUFFER);

    return Type;
}

static HT_HANDLE_TYPE
HtpGetHandleTypeFromName(
    _In_ PCUNICODE_STRING TypeName
    )
{
    static const struct {
        PCWSTR Name;
        USHORT Length;
        HT_HANDLE_TYPE Type;
    } TypeMap[] = {
        { L"Process",     14, HtType_Process },
        { L"Thread",      12, HtType_Thread },
        { L"File",        8,  HtType_File },
        { L"Key",         6,  HtType_Key },
        { L"Section",     14, HtType_Section },
        { L"Token",       10, HtType_Token },
        { L"Event",       10, HtType_Event },
        { L"Semaphore",   18, HtType_Semaphore },
        { L"Mutant",      12, HtType_Mutex },
        { L"Timer",       10, HtType_Timer },
        { L"ALPC Port",   18, HtType_Port },
        { L"Device",      12, HtType_Device },
        { L"Driver",      12, HtType_Driver },
    };

    ULONG i;

    if (TypeName == NULL || TypeName->Buffer == NULL || TypeName->Length == 0) {
        return HtType_Unknown;
    }

    for (i = 0; i < RTL_NUMBER_OF(TypeMap); i++) {
        UNICODE_STRING CompareString;

        CompareString.Buffer = (PWCH)TypeMap[i].Name;
        CompareString.Length = TypeMap[i].Length;
        CompareString.MaximumLength = TypeMap[i].Length + sizeof(WCHAR);

        if (RtlEqualUnicodeString(TypeName, &CompareString, TRUE)) {
            return TypeMap[i].Type;
        }
    }

    return HtType_Unknown;
}

static HT_SUSPICION
HtpAnalyzeHandleSuspicion(
    _In_ PHT_TRACKER Tracker,
    _In_ PHT_HANDLE_ENTRY Entry,
    _In_ HANDLE OwnerProcessId
    )
{
    HT_SUSPICION Suspicion = HtSuspicion_None;

    //
    // Check for cross-process handle
    //
    if (Entry->TargetProcessId != NULL &&
        Entry->TargetProcessId != OwnerProcessId) {
        Suspicion |= HtSuspicion_CrossProcess;

        //
        // Check if target is sensitive process (only at PASSIVE_LEVEL)
        //
        if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
            if (HtpIsSensitiveProcessInternal(Tracker, Entry->TargetProcessId)) {
                Suspicion |= HtSuspicion_SensitiveTarget;
                InterlockedIncrement64(&Tracker->Stats.SensitiveAccessDetected);

                //
                // LSASS access is credential access
                //
                if (Entry->Type == HtType_Process &&
                    (Entry->GrantedAccess & HT_PROCESS_DUMP_ACCESS) == HT_PROCESS_DUMP_ACCESS) {
                    Suspicion |= HtSuspicion_CredentialAccess;
                }
            }
        }
    }

    //
    // Check for high privilege access
    //
    if (HtpIsHighPrivilegeAccess(Entry->Type, Entry->GrantedAccess)) {
        Suspicion |= HtSuspicion_HighPrivilege;
    }

    //
    // Check for injection-capable access
    //
    if (Entry->Type == HtType_Process) {
        if (HtpIsInjectionCapableAccess(Entry->GrantedAccess)) {
            Suspicion |= HtSuspicion_InjectionCapable;
        }
    }

    //
    // Check for token steal access
    //
    if (Entry->Type == HtType_Token) {
        if (Entry->GrantedAccess & HT_TOKEN_STEAL_ACCESS) {
            Suspicion |= HtSuspicion_TokenSteal;
        }
    }

    //
    // Check for duplicated handle
    //
    if (Entry->IsDuplicated) {
        Suspicion |= HtSuspicion_DuplicatedIn;
    }

    //
    // Check for system handle (PID 4)
    //
    if (OwnerProcessId == (HANDLE)(ULONG_PTR)4) {
        Suspicion |= HtSuspicion_SystemHandle;
    }

    return Suspicion;
}

_Use_decl_annotations_
static BOOLEAN
HtpIsSensitiveProcessInternal(
    PHT_TRACKER Tracker,
    HANDLE ProcessId
    )
{
    NTSTATUS Status;
    PEPROCESS Process = NULL;
    PUNICODE_STRING ImageFileName = NULL;
    BOOLEAN IsSensitive = FALSE;

    PAGED_CODE();

    Status = PsLookupProcessByProcessId(ProcessId, &Process);
    if (!NT_SUCCESS(Status)) {
        return FALSE;
    }

    Status = SeLocateProcessImageName(Process, &ImageFileName);
    if (NT_SUCCESS(Status) && ImageFileName != NULL) {
        IsSensitive = HtpIsSensitiveProcessByName(Tracker, ImageFileName);
        ExFreePool(ImageFileName);
    }

    ObDereferenceObject(Process);

    return IsSensitive;
}

static BOOLEAN
HtpIsSensitiveProcessByName(
    _In_ PHT_TRACKER Tracker,
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

    //
    // Check hash match, then verify with full string comparison to prevent collisions
    //
    for (i = 0; i < Tracker->SensitiveProcessCount; i++) {
        if (Tracker->SensitiveProcesses[i].Hash == Hash) {
            //
            // Full string comparison to confirm (prevents false positives from hash collisions)
            //
            UNICODE_STRING SensitiveName;
            SensitiveName.Buffer = Tracker->SensitiveProcesses[i].Name;
            SensitiveName.Length = Tracker->SensitiveProcesses[i].NameLength;
            SensitiveName.MaximumLength = sizeof(Tracker->SensitiveProcesses[i].Name);

            if (RtlEqualUnicodeString(&FileName, &SensitiveName, TRUE)) {
                return TRUE;
            }
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
        if (Access & (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION)) {
            return TRUE;
        }
        break;

    case HtType_Thread:
        if ((Access & THREAD_ALL_ACCESS) == THREAD_ALL_ACCESS) {
            return TRUE;
        }
        if (Access & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT)) {
            return TRUE;
        }
        break;

    case HtType_Token:
        if (Access & (TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY)) {
            return TRUE;
        }
        break;

    case HtType_Section:
        if (Access & (SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)) {
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
        Score += 15;
    }

    if (Flags & HtSuspicion_HighPrivilege) {
        Score += 20;
    }

    if (Flags & HtSuspicion_DuplicatedIn) {
        Score += 15;
    }

    if (Flags & HtSuspicion_SensitiveTarget) {
        Score += 35;
    }

    if (Flags & HtSuspicion_ManyHandles) {
        Score += 10;
    }

    if (Flags & HtSuspicion_SystemHandle) {
        Score += 5;
    }

    if (Flags & HtSuspicion_InjectionCapable) {
        Score += 25;
    }

    if (Flags & HtSuspicion_TokenSteal) {
        Score += 30;
    }

    if (Flags & HtSuspicion_CredentialAccess) {
        Score += 40;
    }

    if (Score > 100) {
        Score = 100;
    }

    return Score;
}

static VOID
HtpInitializeSensitiveProcessList(
    _In_ PHT_TRACKER Tracker
    )
{
    static const PCWSTR SensitiveProcessNames[] = {
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
        L"SecurityHealthService.exe",
        L"MsMpEng.exe",
        L"MsSense.exe",
        L"ShadowSensor.exe"
    };

    ULONG i;
    ULONG Count = 0;

    for (i = 0; i < RTL_NUMBER_OF(SensitiveProcessNames) &&
         Count < HT_MAX_SENSITIVE_PROCESSES; i++) {

        SIZE_T NameLen = wcslen(SensitiveProcessNames[i]);

        if (NameLen < RTL_NUMBER_OF(Tracker->SensitiveProcesses[0].Name)) {
            RtlCopyMemory(
                Tracker->SensitiveProcesses[Count].Name,
                SensitiveProcessNames[i],
                (NameLen + 1) * sizeof(WCHAR)
                );

            Tracker->SensitiveProcesses[Count].NameLength = (USHORT)(NameLen * sizeof(WCHAR));
            Tracker->SensitiveProcesses[Count].Hash = HtpHashString(
                SensitiveProcessNames[i],
                (ULONG)NameLen
                );

            Count++;
        }
    }

    Tracker->SensitiveProcessCount = Count;
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

    if (LastSlash >= FullPath->Length / sizeof(WCHAR)) {
        return FALSE;
    }

    FileName->Buffer = &FullPath->Buffer[LastSlash];
    FileName->Length = FullPath->Length - (LastSlash * sizeof(WCHAR));
    FileName->MaximumLength = FileName->Length;

    return TRUE;
}

static VOID
HtpCleanupDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PHT_TRACKER Tracker = (PHT_TRACKER)DeferredContext;

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
HtpWorkerThreadRoutine(
    _In_ PVOID StartContext
    )
{
    PHT_TRACKER Tracker = (PHT_TRACKER)StartContext;
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
            // Perform cleanup of stale duplication records
            //
            if (Tracker->Initialized && !Tracker->ShutdownRequested) {
                HtpCleanupStaleDuplications(Tracker);
            }
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
HtpCleanupStaleDuplications(
    _In_ PHT_TRACKER Tracker
    )
{
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeoutInterval;
    PLIST_ENTRY Entry, Next;
    PHT_DUPLICATION_RECORD Record;
    LIST_ENTRY StaleList;

    KeQuerySystemTime(&CurrentTime);
    TimeoutInterval.QuadPart = (LONGLONG)Tracker->Config.CacheTimeoutMs * 10000;

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
