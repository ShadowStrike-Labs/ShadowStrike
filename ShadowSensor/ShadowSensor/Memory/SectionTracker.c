/**
 * ============================================================================
 * ShadowStrike NGAV - ENTERPRISE SECTION TRACKER IMPLEMENTATION
 * ============================================================================
 *
 * @file SectionTracker.c
 * @brief Enterprise-grade section object tracking for kernel-mode EDR.
 *
 * This module implements comprehensive section monitoring with:
 * - NtCreateSection/NtMapViewOfSection tracking
 * - Process doppelganging detection (transacted sections via TxF)
 * - Cross-process section mapping detection
 * - Suspicious section characteristics analysis
 * - PE header analysis for image sections
 * - Reference counting with correct lifetime management
 *
 * Security Detection Capabilities:
 * - T1055.012: Process Hollowing via section manipulation
 * - T1055.013: Process Doppelganging (TxF transactions)
 * - T1055.004: Asynchronous Procedure Call (section-based)
 * - T1106: Native API abuse (section objects)
 *
 * Locking:
 *   All synchronization uses EX_PUSH_LOCK exclusively (no spin locks).
 *   Hierarchy: SectionLock > MapListLock > CallbackLock.
 *   All locks require KeEnterCriticalRegion / KeLeaveCriticalRegion.
 *
 * @author ShadowStrike Security Team
 * @version 3.0.0 (Enterprise Edition)
 * @copyright (c) 2026 ShadowStrike Security. All rights reserved.
 * ============================================================================
 */

#include "SectionTracker.h"
#include "../Utilities/MemoryUtils.h"
#include "../Utilities/HashUtils.h"
#include "../ETW/TelemetryEvents.h"

// ============================================================================
// PRIVATE CONSTANTS
// ============================================================================

#define SEC_VERSION                     3
#define SEC_SIGNATURE                   0x53454354  // 'SECT'
#define SEC_CLEANUP_INTERVAL_MS         60000       // 1 minute cleanup
#define SEC_STALE_THRESHOLD_100NS       (300LL * 10000000LL) // 5 minutes in 100ns
#define SEC_MAX_CALLBACKS               8
#define SEC_PE_HEADER_SIZE              4096

// Suspicion score weights
#define SEC_SCORE_TRANSACTED            300
#define SEC_SCORE_DELETED               250
#define SEC_SCORE_CROSS_PROCESS         150
#define SEC_SCORE_UNUSUAL_PATH          100
#define SEC_SCORE_LARGE_ANONYMOUS       80
#define SEC_SCORE_EXECUTE_ANONYMOUS     200
#define SEC_SCORE_HIDDEN_PE             250
#define SEC_SCORE_REMOTE_MAP            120
#define SEC_SCORE_SUSPICIOUS_NAME       80
#define SEC_SCORE_NO_BACKING_FILE       180
#define SEC_SCORE_MODIFIED_IMAGE        220
#define SEC_SCORE_OVERLAY_DATA          60

// ============================================================================
// PRIVATE STRUCTURES
// ============================================================================

typedef enum _SEC_CALLBACK_TYPE {
    SecCallbackType_Create = 0,
    SecCallbackType_Map    = 1,
} SEC_CALLBACK_TYPE;

typedef struct _SEC_CALLBACK_ENTRY {
    union {
        SEC_CREATE_CALLBACK CreateCallback;
        SEC_MAP_CALLBACK    MapCallback;
    };
    PVOID              Context;
    volatile BOOLEAN   InUse;
    SEC_CALLBACK_TYPE  Type;
    ULONG              SlotIndex;
} SEC_CALLBACK_ENTRY, *PSEC_CALLBACK_ENTRY;

typedef struct _SEC_CLEANUP_WORK_ITEM {
    WORK_QUEUE_ITEM     WorkItem;
    PSEC_TRACKER        Tracker;
} SEC_CLEANUP_WORK_ITEM, *PSEC_CLEANUP_WORK_ITEM;

typedef struct _SEC_TRACKER_INTERNAL {
    SEC_TRACKER Public;

    ULONG Signature;

    SEC_CALLBACK_ENTRY CreateCallbacks[SEC_MAX_CALLBACKS];
    SEC_CALLBACK_ENTRY MapCallbacks[SEC_MAX_CALLBACKS];
    EX_PUSH_LOCK CallbackLock;

    KTIMER CleanupTimer;
    KDPC CleanupDpc;
    BOOLEAN CleanupTimerActive;

    NPAGED_LOOKASIDE_LIST EntryLookaside;
    NPAGED_LOOKASIDE_LIST MapLookaside;
    BOOLEAN LookasideInitialized;

    volatile LONG ShuttingDown;
    volatile LONG ActiveOperations;
    KEVENT ShutdownEvent;
} SEC_TRACKER_INTERNAL, *PSEC_TRACKER_INTERNAL;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

static KDEFERRED_ROUTINE SecpCleanupDpcRoutine;

static VOID
SecpCleanupWorkRoutine(
    _In_ PVOID Parameter
    );

static PSEC_ENTRY
SecpAllocateEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpFreeEntryResources(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    );

static VOID
SecpFreeEntryToPool(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    );

static PSEC_MAP_ENTRY
SecpAllocateMapEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpFreeMapEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_MAP_ENTRY MapEntry
    );

static ULONG
SecpHashSectionObject(
    _In_ PVOID SectionObject,
    _In_ ULONG BucketCount
    );

static PSEC_ENTRY
SecpFindEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PVOID SectionObject
    );

static VOID
SecpInsertEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    );

static VOID
SecpRemoveEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    );

static SEC_SECTION_TYPE
SecpDetermineSectionType(
    _In_ SEC_FLAGS Flags
    );

static VOID
SecpAnalyzePE(
    _In_ PSEC_ENTRY Entry,
    _In_ PFILE_OBJECT FileObject
    );

static VOID
SecpComputeFileHash(
    _In_ PSEC_ENTRY Entry,
    _In_ PFILE_OBJECT FileObject
    );

static VOID
SecpUpdateSuspicionScore(
    _Inout_ PSEC_ENTRY Entry
    );

static VOID
SecpFillSectionInfo(
    _In_ PSEC_ENTRY Entry,
    _Out_ PSEC_SECTION_INFO Info
    );

static VOID
SecpFillMapInfo(
    _In_ PSEC_MAP_ENTRY MapEntry,
    _Out_ PSEC_MAP_INFO Info
    );

static VOID
SecpInvokeCreateCallbacks(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    );

static VOID
SecpInvokeMapCallbacks(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry,
    _In_ PSEC_MAP_ENTRY MapEntry
    );

static BOOLEAN
SecpIsTransactedFile(
    _In_ PFILE_OBJECT FileObject
    );

static BOOLEAN
SecpIsFileDeleted(
    _In_ PFILE_OBJECT FileObject
    );

static BOOLEAN
SecpIsUnusualPath(
    _In_ PUNICODE_STRING FilePath
    );

static BOOLEAN
SecpIsSuspiciousName(
    _In_ PUNICODE_STRING FilePath
    );

static BOOLEAN
SecpAcquireReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpReleaseReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    );

static VOID
SecpAddEntryRef(
    _In_ PSEC_ENTRY Entry
    );

static VOID
SecpReleaseEntry(
    _In_ PSEC_ENTRY Entry
    );

static BOOLEAN
SecpUnicodeStringContains(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle,
    _In_ BOOLEAN CaseInsensitive
    );

static USHORT
SecpUnicodeCharLen(
    _In_ PCUNICODE_STRING Str
    );

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecInitialize(
    _Out_ PSEC_TRACKER* Tracker
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PSEC_TRACKER_INTERNAL internal = NULL;
    ULONG i;
    LARGE_INTEGER dueTime;

    if (Tracker == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Tracker = NULL;

    internal = (PSEC_TRACKER_INTERNAL)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SEC_TRACKER_INTERNAL),
        SEC_POOL_TAG_CONTEXT
    );

    if (internal == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(internal, sizeof(SEC_TRACKER_INTERNAL));
    internal->Signature = SEC_SIGNATURE;

    ExInitializePushLock(&internal->Public.SectionLock);
    ExInitializePushLock(&internal->CallbackLock);
    InitializeListHead(&internal->Public.SectionList);

    KeInitializeEvent(&internal->ShutdownEvent, NotificationEvent, FALSE);
    internal->ActiveOperations = 1;  // Initial reference

    //
    // Allocate hash table buckets (NonPaged — accessed under push lock)
    //
    internal->Public.SectionHash.BucketCount = SEC_HASH_BUCKET_COUNT;
    internal->Public.SectionHash.Buckets = (PLIST_ENTRY)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        SEC_HASH_BUCKET_COUNT * sizeof(LIST_ENTRY),
        SEC_POOL_TAG_CONTEXT
    );

    if (internal->Public.SectionHash.Buckets == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    for (i = 0; i < SEC_HASH_BUCKET_COUNT; i++) {
        InitializeListHead(&internal->Public.SectionHash.Buckets[i]);
    }

    //
    // Initialize lookaside lists
    //
    ExInitializeNPagedLookasideList(
        &internal->EntryLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SEC_ENTRY),
        SEC_POOL_TAG_ENTRY,
        0
    );

    ExInitializeNPagedLookasideList(
        &internal->MapLookaside,
        NULL,
        NULL,
        POOL_NX_ALLOCATION,
        sizeof(SEC_MAP_ENTRY),
        SEC_POOL_TAG_MAP,
        0
    );

    internal->LookasideInitialized = TRUE;

    //
    // Initialize callback slot metadata
    //
    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        internal->CreateCallbacks[i].SlotIndex = i;
        internal->CreateCallbacks[i].Type = SecCallbackType_Create;
        internal->MapCallbacks[i].SlotIndex = i;
        internal->MapCallbacks[i].Type = SecCallbackType_Map;
    }

    internal->Public.Config.MaxSections = SEC_MAX_TRACKED_SECTIONS;
    internal->Public.Config.TrackAllSections = FALSE;
    internal->Public.Config.EnablePEAnalysis = TRUE;
    internal->Public.Config.EnableFileHashing = TRUE;

    KeQuerySystemTime(&internal->Public.Stats.StartTime);

    //
    // Initialize cleanup timer — DPC queues a work item for PASSIVE_LEVEL cleanup
    //
    KeInitializeTimer(&internal->CleanupTimer);
    KeInitializeDpc(&internal->CleanupDpc, SecpCleanupDpcRoutine, internal);

    dueTime.QuadPart = -((LONGLONG)SEC_CLEANUP_INTERVAL_MS * 10000);
    KeSetTimerEx(
        &internal->CleanupTimer,
        dueTime,
        SEC_CLEANUP_INTERVAL_MS,
        &internal->CleanupDpc
    );
    internal->CleanupTimerActive = TRUE;

    internal->Public.Initialized = TRUE;

    *Tracker = &internal->Public;

    return STATUS_SUCCESS;

Cleanup:
    if (internal != NULL) {
        if (internal->Public.SectionHash.Buckets != NULL) {
            ShadowStrikeFreePoolWithTag(
                internal->Public.SectionHash.Buckets,
                SEC_POOL_TAG_CONTEXT
            );
        }

        if (internal->LookasideInitialized) {
            ExDeleteNPagedLookasideList(&internal->EntryLookaside);
            ExDeleteNPagedLookasideList(&internal->MapLookaside);
        }

        ShadowStrikeFreePoolWithTag(internal, SEC_POOL_TAG_CONTEXT);
    }

    return status;
}

_Use_decl_annotations_
VOID
SecShutdown(
    _Inout_ PSEC_TRACKER Tracker
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_MAP_ENTRY mapEntry;
    LARGE_INTEGER timeout;

    if (Tracker == NULL || !Tracker->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->Signature != SEC_SIGNATURE) {
        return;
    }

    //
    // Signal shutdown FIRST — prevents new operations from starting
    //
    InterlockedExchange(&internal->ShuttingDown, 1);

    //
    // Mark not-initialized to stop callers checking that flag
    //
    Tracker->Initialized = FALSE;

    //
    // Cancel cleanup timer and wait for any in-flight DPC to complete
    //
    if (internal->CleanupTimerActive) {
        KeCancelTimer(&internal->CleanupTimer);
        internal->CleanupTimerActive = FALSE;
        KeFlushQueuedDpcs();
    }

    //
    // Release initial operation reference and wait for all active ops to drain
    //
    SecpReleaseReference(internal);
    timeout.QuadPart = -((LONGLONG)10000 * 10000);  // 10 second timeout
    KeWaitForSingleObject(
        &internal->ShutdownEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    //
    // All operations are drained. Free all section entries under exclusive lock.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionLock);

    while (!IsListEmpty(&Tracker->SectionList)) {
        listEntry = RemoveHeadList(&Tracker->SectionList);
        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        RemoveEntryList(&entry->HashEntry);
        InterlockedDecrement(&Tracker->SectionCount);

        //
        // Free all map entries for this section (under MapListLock for correctness)
        //
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&entry->MapListLock);

        while (!IsListEmpty(&entry->MapList)) {
            PLIST_ENTRY mapListEntry = RemoveHeadList(&entry->MapList);
            mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);
            SecpFreeMapEntry(internal, mapEntry);
        }

        ExReleasePushLockExclusive(&entry->MapListLock);
        KeLeaveCriticalRegion();

        SecpFreeEntryResources(internal, entry);
        SecpFreeEntryToPool(internal, entry);
    }

    ExReleasePushLockExclusive(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    //
    // Free hash table
    //
    if (Tracker->SectionHash.Buckets != NULL) {
        ShadowStrikeFreePoolWithTag(
            Tracker->SectionHash.Buckets,
            SEC_POOL_TAG_CONTEXT
        );
        Tracker->SectionHash.Buckets = NULL;
    }

    //
    // Delete lookaside lists
    //
    if (internal->LookasideInitialized) {
        ExDeleteNPagedLookasideList(&internal->EntryLookaside);
        ExDeleteNPagedLookasideList(&internal->MapLookaside);
        internal->LookasideInitialized = FALSE;
    }

    //
    // Clear signature and free
    //
    internal->Signature = 0;
    ShadowStrikeFreePoolWithTag(internal, SEC_POOL_TAG_CONTEXT);
}

// ============================================================================
// SECTION TRACKING
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecTrackSectionCreate(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _In_ HANDLE CreatorProcessId,
    _In_ SEC_FLAGS Flags,
    _In_opt_ PFILE_OBJECT FileObject,
    _In_ PLARGE_INTEGER MaximumSize,
    _Out_opt_ PULONG SectionId
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry = NULL;
    PSEC_ENTRY existing;
    NTSTATUS status = STATUS_SUCCESS;
    POBJECT_NAME_INFORMATION nameInfo = NULL;

    if (Tracker == NULL || !Tracker->Initialized ||
        SectionObject == NULL || MaximumSize == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SectionId != NULL) {
        *SectionId = 0;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    //
    // Acquire tracker reference BEFORE checking ShuttingDown (HIGH-7 fix)
    //
    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    if ((ULONG)Tracker->SectionCount >= Tracker->Config.MaxSections) {
        SecpReleaseReference(internal);
        return STATUS_QUOTA_EXCEEDED;
    }

    //
    // Allocate entry BEFORE taking lock to minimize hold time
    //
    entry = SecpAllocateEntry(internal);
    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //
    // Initialize entry (outside lock — no contention on private data)
    //
    RtlZeroMemory(entry, sizeof(SEC_ENTRY));
    entry->SectionObject = SectionObject;
    entry->CreatorProcessId = CreatorProcessId;
    entry->Flags = Flags;
    entry->SectionId = (ULONG)InterlockedIncrement(&Tracker->NextSectionId);
    entry->Type = SecpDetermineSectionType(Flags);
    entry->RefCount = 1;
    entry->RemovedFromTracker = FALSE;
    entry->Tracker = Tracker;
    entry->MaximumSize = *MaximumSize;

    InitializeListHead(&entry->MapList);
    ExInitializePushLock(&entry->MapListLock);
    KeQuerySystemTime(&entry->CreateTime);

    //
    // Process backing file information
    //
    if (FileObject != NULL) {
        //
        // MED-1: Take a reference on the file object for safe future access
        //
        ObReferenceObject(FileObject);
        entry->BackingFile.FileObject = FileObject;

        //
        // Get file name (IoQueryFileDosDeviceName requires PASSIVE_LEVEL)
        //
        status = IoQueryFileDosDeviceName(FileObject, &nameInfo);
        if (NT_SUCCESS(status) && nameInfo != NULL) {
            entry->BackingFile.FileName.MaximumLength =
                nameInfo->Name.Length + sizeof(WCHAR);
            entry->BackingFile.FileName.Buffer = (PWCH)ShadowStrikeAllocatePoolWithTag(
                NonPagedPoolNx,
                entry->BackingFile.FileName.MaximumLength,
                SEC_POOL_TAG_ENTRY
            );

            if (entry->BackingFile.FileName.Buffer != NULL) {
                RtlCopyUnicodeString(&entry->BackingFile.FileName, &nameInfo->Name);
                //
                // Null-terminate for safe use with C string functions
                //
                entry->BackingFile.FileName.Buffer[
                    entry->BackingFile.FileName.Length / sizeof(WCHAR)] = L'\0';
            }

            ExFreePool(nameInfo);
            nameInfo = NULL;
        }
        status = STATUS_SUCCESS; // Name query failure is non-fatal

        //
        // HIGH-2: Check for transacted file (process doppelganging indicator)
        //
        entry->BackingFile.IsTransacted = SecpIsTransactedFile(FileObject);
        if (entry->BackingFile.IsTransacted) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_Transacted);
            InterlockedIncrement64(&Tracker->Stats.TransactedDetections);
        }

        entry->BackingFile.IsDeleted = SecpIsFileDeleted(FileObject);
        if (entry->BackingFile.IsDeleted) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_Deleted);
        }

        if (entry->BackingFile.FileName.Buffer != NULL) {
            if (SecpIsUnusualPath(&entry->BackingFile.FileName)) {
                InterlockedOr(&entry->SuspicionFlags, SecSuspicion_UnusualPath);
            }

            if (SecpIsSuspiciousName(&entry->BackingFile.FileName)) {
                InterlockedOr(&entry->SuspicionFlags, SecSuspicion_SuspiciousName);
            }
        }

        //
        // Analyze PE header for image sections (CRITICAL-5: properly implemented)
        //
        if ((Flags & SecFlag_Image) && internal->Public.Config.EnablePEAnalysis) {
            SecpAnalyzePE(entry, FileObject);
        }

        //
        // Compute file hash if enabled
        //
        if (internal->Public.Config.EnableFileHashing) {
            SecpComputeFileHash(entry, FileObject);
        }

    } else {
        //
        // No backing file — anonymous section
        //
        if (entry->MaximumSize.QuadPart > SEC_SUSPICIOUS_SIZE_THRESHOLD) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_LargeAnonymous);
        }

        if (Flags & SecFlag_Execute) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_ExecuteAnonymous);
        }

        if (Flags & SecFlag_Image) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_NoBackingFile);
        }
    }

    SecpUpdateSuspicionScore(entry);

    //
    // CRITICAL-2 fix: Atomic check-and-insert under EXCLUSIVE lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionLock);

    existing = SecpFindEntryLocked(internal, SectionObject);

    if (existing != NULL) {
        //
        // Already tracked — return existing ID safely under lock
        //
        if (SectionId != NULL) {
            *SectionId = existing->SectionId;
        }

        ExReleasePushLockExclusive(&Tracker->SectionLock);
        KeLeaveCriticalRegion();

        //
        // Clean up the entry we prepared but won't insert
        //
        SecpFreeEntryResources(internal, entry);
        SecpFreeEntryToPool(internal, entry);
        SecpReleaseReference(internal);
        return STATUS_OBJECT_NAME_EXISTS;
    }

    SecpInsertEntryLocked(internal, entry);

    ExReleasePushLockExclusive(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    //
    // Update statistics
    //
    InterlockedIncrement64(&Tracker->Stats.TotalCreated);

    if (entry->SuspicionFlags != (LONG)SecSuspicion_None) {
        InterlockedIncrement64(&Tracker->Stats.SuspiciousDetections);
    }

    //
    // Invoke callbacks (outside lock)
    //
    SecpInvokeCreateCallbacks(internal, entry);

    if (SectionId != NULL) {
        *SectionId = entry->SectionId;
    }

    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecTrackSectionMap(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _In_ HANDLE ProcessId,
    _In_ PVOID ViewBase,
    _In_ SIZE_T ViewSize,
    _In_ ULONG64 SectionOffset,
    _In_ ULONG Protection
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;
    PSEC_MAP_ENTRY mapEntry;
    BOOLEAN isCrossProcess;

    if (Tracker == NULL || !Tracker->Initialized || SectionObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find section entry under shared lock, take a reference
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);
    if (entry != NULL) {
        SecpAddEntryRef(entry);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    if (entry->MapCount >= SEC_MAX_MAPS_PER_SECTION) {
        SecpReleaseEntry(entry);
        SecpReleaseReference(internal);
        return STATUS_QUOTA_EXCEEDED;
    }

    mapEntry = SecpAllocateMapEntry(internal);
    if (mapEntry == NULL) {
        SecpReleaseEntry(entry);
        SecpReleaseReference(internal);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(mapEntry, sizeof(SEC_MAP_ENTRY));
    mapEntry->ProcessId = ProcessId;
    mapEntry->ViewBase = ViewBase;
    mapEntry->ViewSize = ViewSize;
    mapEntry->SectionOffset = SectionOffset;
    mapEntry->Protection = Protection;
    mapEntry->IsMapped = TRUE;
    KeQuerySystemTime(&mapEntry->MapTime);

    isCrossProcess = (ProcessId != entry->CreatorProcessId);

    //
    // Insert under push lock (not spin lock — CRITICAL-1 fix)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&entry->MapListLock);

    InsertTailList(&entry->MapList, &mapEntry->ListEntry);
    InterlockedIncrement(&entry->MapCount);

    if (isCrossProcess) {
        InterlockedIncrement(&entry->CrossProcessMapCount);
        InterlockedOr(&entry->SuspicionFlags, SecSuspicion_CrossProcess);

        if (entry->CreatorProcessId != PsGetCurrentProcessId()) {
            InterlockedOr(&entry->SuspicionFlags, SecSuspicion_RemoteMap);
        }
    }

    KeQuerySystemTime(&entry->LastMapTime);

    ExReleasePushLockExclusive(&entry->MapListLock);
    KeLeaveCriticalRegion();

    SecpUpdateSuspicionScore(entry);

    InterlockedIncrement64(&Tracker->Stats.TotalMapped);

    if (isCrossProcess) {
        InterlockedIncrement64(&Tracker->Stats.CrossProcessMaps);
    }

    SecpInvokeMapCallbacks(internal, entry, mapEntry);

    SecpReleaseEntry(entry);
    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecTrackSectionUnmap(
    _In_ PSEC_TRACKER Tracker,
    _In_ HANDLE ProcessId,
    _In_ PVOID ViewBase
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY mapListEntry;
    PSEC_ENTRY entry;
    PSEC_MAP_ENTRY mapEntry;
    BOOLEAN found = FALSE;

    if (Tracker == NULL || !Tracker->Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // CRITICAL-1 fix: Use push lock throughout, no spin lock nesting.
    // Acquire SectionLock shared, then MapListLock exclusive per entry.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        ExAcquirePushLockExclusive(&entry->MapListLock);

        for (mapListEntry = entry->MapList.Flink;
             mapListEntry != &entry->MapList;
             mapListEntry = mapListEntry->Flink) {

            mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);

            if (mapEntry->ProcessId == ProcessId &&
                mapEntry->ViewBase == ViewBase &&
                mapEntry->IsMapped) {

                mapEntry->IsMapped = FALSE;
                KeQuerySystemTime(&mapEntry->UnmapTime);
                found = TRUE;
                break;
            }
        }

        ExReleasePushLockExclusive(&entry->MapListLock);

        if (found) {
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (found) {
        InterlockedIncrement64(&Tracker->Stats.TotalUnmapped);
    }

    SecpReleaseReference(internal);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
SecUntrackSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || !Tracker->Initialized || SectionObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // CRITICAL-4 fix: Remove from lists under exclusive lock,
    // then release the entry via ref-counting. Do NOT free directly.
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    if (entry != NULL) {
        SecpRemoveEntryLocked(internal, entry);
        entry->RemovedFromTracker = TRUE;
    }

    ExReleasePushLockExclusive(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    //
    // CRITICAL-3 fix: Release the tracker's reference. If ref hits 0,
    // SecpReleaseEntry will free resources and return to pool.
    //
    SecpReleaseEntry(entry);

    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// SECTION QUERY — Returns opaque snapshots (DESIGN-1 fix)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecGetSectionInfo(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PSEC_SECTION_INFO Info
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || !Tracker->Initialized ||
        SectionObject == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SEC_SECTION_INFO));

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    if (entry != NULL) {
        SecpFillSectionInfo(entry, Info);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    SecpReleaseReference(internal);

    return (entry != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
SecGetSectionById(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG SectionId,
    _Out_ PSEC_SECTION_INFO Info
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_TRACKER_INTERNAL internal;
    BOOLEAN found = FALSE;

    if (Tracker == NULL || !Tracker->Initialized || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SEC_SECTION_INFO));

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if (entry->SectionId == SectionId) {
            SecpFillSectionInfo(entry, Info);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    SecpReleaseReference(internal);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
SecFindSectionByFile(
    _In_ PSEC_TRACKER Tracker,
    _In_ PUNICODE_STRING FileName,
    _Out_ PSEC_SECTION_INFO Info
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_TRACKER_INTERNAL internal;
    BOOLEAN found = FALSE;

    if (Tracker == NULL || !Tracker->Initialized ||
        FileName == NULL || Info == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Info, sizeof(SEC_SECTION_INFO));

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if (entry->BackingFile.FileName.Buffer != NULL &&
            RtlEqualUnicodeString(&entry->BackingFile.FileName, FileName, TRUE)) {
            SecpFillSectionInfo(entry, Info);
            found = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    SecpReleaseReference(internal);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ============================================================================
// SUSPICION ANALYSIS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecAnalyzeSection(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ SEC_SUSPICION* SuspicionFlags,
    _Out_ PULONG SuspicionScore
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || SuspicionFlags == NULL || SuspicionScore == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *SuspicionFlags = SecSuspicion_None;
    *SuspicionScore = 0;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);

    if (entry != NULL) {
        SecpAddEntryRef(entry);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    SecpUpdateSuspicionScore(entry);

    *SuspicionFlags = (SEC_SUSPICION)entry->SuspicionFlags;
    *SuspicionScore = (ULONG)entry->SuspicionScore;

    SecpReleaseEntry(entry);
    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecDetectDoppelganging(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsTransacted,
    _Out_ PBOOLEAN FileDeleted
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || IsTransacted == NULL || FileDeleted == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsTransacted = FALSE;
    *FileDeleted = FALSE;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);
    if (entry != NULL) {
        SecpAddEntryRef(entry);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    *IsTransacted = entry->BackingFile.IsTransacted;
    *FileDeleted = entry->BackingFile.IsDeleted;

    if (*IsTransacted || *FileDeleted) {
        TeLogMemoryEvent(
            TeEvent_InjectionDetected,
            (UINT32)(ULONG_PTR)entry->CreatorProcessId,
            0,
            (UINT64)(ULONG_PTR)SectionObject,
            (UINT64)entry->MaximumSize.QuadPart,
            0,
            (UINT32)entry->SuspicionScore,
            TE_MEM_FLAG_INJECTION
        );
    }

    SecpReleaseEntry(entry);
    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecGetSuspiciousSections(
    _In_ PSEC_TRACKER Tracker,
    _In_ ULONG MinScore,
    _Out_writes_to_(MaxEntries, *EntryCount) PSEC_SECTION_INFO Entries,
    _In_ ULONG MaxEntries,
    _Out_ PULONG EntryCount
    )
{
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;
    PSEC_TRACKER_INTERNAL internal;
    ULONG count = 0;

    if (Tracker == NULL || !Tracker->Initialized ||
        Entries == NULL || EntryCount == NULL || MaxEntries == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *EntryCount = 0;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    for (listEntry = Tracker->SectionList.Flink;
         listEntry != &Tracker->SectionList && count < MaxEntries;
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        if ((ULONG)entry->SuspicionScore >= MinScore) {
            SecpFillSectionInfo(entry, &Entries[count]);
            count++;
        }
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    *EntryCount = count;

    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// CROSS-PROCESS ANALYSIS — Returns copied snapshots (HIGH-4 fix)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecGetCrossProcessMaps(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_writes_to_(MaxMaps, *MapCount) PSEC_MAP_INFO Maps,
    _In_ ULONG MaxMaps,
    _Out_ PULONG MapCount
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;
    PLIST_ENTRY mapListEntry;
    PSEC_MAP_ENTRY mapEntry;
    ULONG count = 0;

    if (Tracker == NULL || Maps == NULL || MapCount == NULL || MaxMaps == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    *MapCount = 0;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    //
    // Find section and take a reference
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);
    if (entry != NULL) {
        SecpAddEntryRef(entry);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    //
    // Copy map data under MapListLock (push lock, not spin lock)
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&entry->MapListLock);

    for (mapListEntry = entry->MapList.Flink;
         mapListEntry != &entry->MapList && count < MaxMaps;
         mapListEntry = mapListEntry->Flink) {

        mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);

        if (mapEntry->ProcessId != entry->CreatorProcessId) {
            SecpFillMapInfo(mapEntry, &Maps[count]);
            count++;
        }
    }

    ExReleasePushLockShared(&entry->MapListLock);
    KeLeaveCriticalRegion();

    *MapCount = count;

    SecpReleaseEntry(entry);
    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SecIsCrossProcessMapped(
    _In_ PSEC_TRACKER Tracker,
    _In_ PVOID SectionObject,
    _Out_ PBOOLEAN IsCrossProcess,
    _Out_opt_ PULONG ProcessCount
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_ENTRY entry;

    if (Tracker == NULL || IsCrossProcess == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsCrossProcess = FALSE;
    if (ProcessCount != NULL) {
        *ProcessCount = 0;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    if (!SecpAcquireReference(internal)) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->SectionLock);

    entry = SecpFindEntryLocked(internal, SectionObject);
    if (entry != NULL) {
        SecpAddEntryRef(entry);
    }

    ExReleasePushLockShared(&Tracker->SectionLock);
    KeLeaveCriticalRegion();

    if (entry == NULL) {
        SecpReleaseReference(internal);
        return STATUS_NOT_FOUND;
    }

    *IsCrossProcess = (entry->CrossProcessMapCount > 0);

    if (ProcessCount != NULL) {
        *ProcessCount = (ULONG)entry->CrossProcessMapCount;
    }

    SecpReleaseEntry(entry);
    SecpReleaseReference(internal);

    return STATUS_SUCCESS;
}

// ============================================================================
// CALLBACKS — Per-registration handle (DESIGN-3 fix)
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecRegisterCreateCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CREATE_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ SEC_CALLBACK_HANDLE* Handle
    )
{
    PSEC_TRACKER_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Tracker == NULL || !Tracker->Initialized ||
        Callback == NULL || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handle = NULL;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (!internal->CreateCallbacks[i].InUse) {
            internal->CreateCallbacks[i].CreateCallback = Callback;
            internal->CreateCallbacks[i].Context = Context;
            internal->CreateCallbacks[i].InUse = TRUE;
            *Handle = &internal->CreateCallbacks[i];
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
NTSTATUS
SecRegisterMapCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_MAP_CALLBACK Callback,
    _In_opt_ PVOID Context,
    _Out_ SEC_CALLBACK_HANDLE* Handle
    )
{
    PSEC_TRACKER_INTERNAL internal;
    ULONG i;
    NTSTATUS status = STATUS_QUOTA_EXCEEDED;

    if (Tracker == NULL || !Tracker->Initialized ||
        Callback == NULL || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *Handle = NULL;

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (!internal->MapCallbacks[i].InUse) {
            internal->MapCallbacks[i].MapCallback = Callback;
            internal->MapCallbacks[i].Context = Context;
            internal->MapCallbacks[i].InUse = TRUE;
            *Handle = &internal->MapCallbacks[i];
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return status;
}

_Use_decl_annotations_
NTSTATUS
SecUnregisterCallback(
    _In_ PSEC_TRACKER Tracker,
    _In_ SEC_CALLBACK_HANDLE Handle
    )
{
    PSEC_TRACKER_INTERNAL internal;
    PSEC_CALLBACK_ENTRY callbackEntry;

    if (Tracker == NULL || !Tracker->Initialized || Handle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);
    callbackEntry = (PSEC_CALLBACK_ENTRY)Handle;

    //
    // Validate the handle points into our callback arrays
    //
    BOOLEAN isCreateSlot =
        (callbackEntry >= &internal->CreateCallbacks[0]) &&
        (callbackEntry < &internal->CreateCallbacks[SEC_MAX_CALLBACKS]);
    BOOLEAN isMapSlot =
        (callbackEntry >= &internal->MapCallbacks[0]) &&
        (callbackEntry < &internal->MapCallbacks[SEC_MAX_CALLBACKS]);

    if (!isCreateSlot && !isMapSlot) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    callbackEntry->InUse = FALSE;
    callbackEntry->CreateCallback = NULL;
    callbackEntry->Context = NULL;

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
SecUnregisterAllCallbacks(
    _In_ PSEC_TRACKER Tracker
    )
{
    PSEC_TRACKER_INTERNAL internal;
    ULONG i;

    if (Tracker == NULL || !Tracker->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(Tracker, SEC_TRACKER_INTERNAL, Public);

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&internal->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        internal->CreateCallbacks[i].InUse = FALSE;
        internal->CreateCallbacks[i].CreateCallback = NULL;
        internal->CreateCallbacks[i].Context = NULL;

        internal->MapCallbacks[i].InUse = FALSE;
        internal->MapCallbacks[i].MapCallback = NULL;
        internal->MapCallbacks[i].Context = NULL;
    }

    ExReleasePushLockExclusive(&internal->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// STATISTICS
// ============================================================================

_Use_decl_annotations_
NTSTATUS
SecGetStatistics(
    _In_ PSEC_TRACKER Tracker,
    _Out_ PSEC_STATISTICS Stats
    )
{
    LARGE_INTEGER currentTime;

    if (Tracker == NULL || !Tracker->Initialized || Stats == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Stats, sizeof(SEC_STATISTICS));

    Stats->ActiveSections = (ULONG)Tracker->SectionCount;
    Stats->TotalCreated = Tracker->Stats.TotalCreated;
    Stats->TotalMapped = Tracker->Stats.TotalMapped;
    Stats->TotalUnmapped = Tracker->Stats.TotalUnmapped;
    Stats->SuspiciousDetections = Tracker->Stats.SuspiciousDetections;
    Stats->CrossProcessMaps = Tracker->Stats.CrossProcessMaps;
    Stats->TransactedDetections = Tracker->Stats.TransactedDetections;

    KeQuerySystemTime(&currentTime);
    Stats->UpTime.QuadPart = currentTime.QuadPart - Tracker->Stats.StartTime.QuadPart;

    return STATUS_SUCCESS;
}

// ============================================================================
// PRIVATE: REFERENCE COUNTING (CRITICAL-3, CRITICAL-4 fixes)
// ============================================================================

/**
 * SecpAddEntryRef - Increment reference count on a section entry.
 * Must be called while holding at least a shared lock that guarantees
 * the entry is still valid (i.e., SectionLock shared or exclusive).
 */
static VOID
SecpAddEntryRef(
    _In_ PSEC_ENTRY Entry
    )
{
    NT_ASSERT(Entry != NULL);
    NT_ASSERT(Entry->RefCount > 0);
    InterlockedIncrement(&Entry->RefCount);
}

/**
 * SecpReleaseEntry - Decrement reference count. When it hits 0,
 * free all resources and return the entry to the lookaside list.
 * This is the ONLY path that frees entries (CRITICAL-3 fix).
 */
static VOID
SecpReleaseEntry(
    _In_ PSEC_ENTRY Entry
    )
{
    LONG newCount;
    PSEC_TRACKER_INTERNAL internal;
    PLIST_ENTRY mapListEntry;
    PSEC_MAP_ENTRY mapEntry;

    if (Entry == NULL) {
        return;
    }

    newCount = InterlockedDecrement(&Entry->RefCount);
    NT_ASSERT(newCount >= 0);

    if (newCount > 0) {
        return;
    }

    //
    // RefCount == 0: entry must have been removed from tracker
    //
    NT_ASSERT(Entry->RemovedFromTracker);

    internal = CONTAINING_RECORD(Entry->Tracker, SEC_TRACKER_INTERNAL, Public);

    //
    // Free all map entries (no lock needed — we're the sole owner)
    //
    while (!IsListEmpty(&Entry->MapList)) {
        mapListEntry = RemoveHeadList(&Entry->MapList);
        mapEntry = CONTAINING_RECORD(mapListEntry, SEC_MAP_ENTRY, ListEntry);
        SecpFreeMapEntry(internal, mapEntry);
    }

    SecpFreeEntryResources(internal, Entry);
    SecpFreeEntryToPool(internal, Entry);
}

// ============================================================================
// PRIVATE: CLEANUP DPC AND WORK ITEM (HIGH-3 fix)
// ============================================================================

/**
 * DPC routine: runs at DISPATCH_LEVEL.
 * Queues a work item for PASSIVE_LEVEL cleanup.
 */
static VOID
SecpCleanupDpcRoutine(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    PSEC_TRACKER_INTERNAL internal = (PSEC_TRACKER_INTERNAL)DeferredContext;
    PSEC_CLEANUP_WORK_ITEM workItem;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (internal == NULL || internal->ShuttingDown) {
        return;
    }

    //
    // Allocate work item from NonPaged pool (we're at DISPATCH_LEVEL)
    //
    workItem = (PSEC_CLEANUP_WORK_ITEM)ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(SEC_CLEANUP_WORK_ITEM),
        SEC_POOL_TAG_CONTEXT
    );

    if (workItem == NULL) {
        return;
    }

    workItem->Tracker = &internal->Public;
    ExInitializeWorkItem(&workItem->WorkItem, SecpCleanupWorkRoutine, workItem);
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);
}

/**
 * Work item routine: runs at PASSIVE_LEVEL.
 * Removes stale unmapped entries that have been inactive for SEC_STALE_THRESHOLD.
 */
static VOID
SecpCleanupWorkRoutine(
    _In_ PVOID Parameter
    )
{
    PSEC_CLEANUP_WORK_ITEM workItem = (PSEC_CLEANUP_WORK_ITEM)Parameter;
    PSEC_TRACKER tracker;
    PSEC_TRACKER_INTERNAL internal;
    PLIST_ENTRY listEntry;
    PLIST_ENTRY nextEntry;
    PSEC_ENTRY entry;
    LARGE_INTEGER currentTime;
    PSEC_ENTRY staleEntries[64];
    ULONG staleCount = 0;
    ULONG i;

    if (workItem == NULL) {
        return;
    }

    tracker = workItem->Tracker;
    ShadowStrikeFreePoolWithTag(workItem, SEC_POOL_TAG_CONTEXT);

    if (tracker == NULL || !tracker->Initialized) {
        return;
    }

    internal = CONTAINING_RECORD(tracker, SEC_TRACKER_INTERNAL, Public);

    if (internal->ShuttingDown) {
        return;
    }

    if (!SecpAcquireReference(internal)) {
        return;
    }

    KeQuerySystemTime(&currentTime);

    //
    // Collect stale entries under exclusive lock
    //
    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&tracker->SectionLock);

    for (listEntry = tracker->SectionList.Flink;
         listEntry != &tracker->SectionList && staleCount < ARRAYSIZE(staleEntries);
         listEntry = nextEntry) {

        nextEntry = listEntry->Flink;
        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, ListEntry);

        //
        // Check if entry has no active mappings and is old enough
        //
        if (entry->MapCount == 0 &&
            (currentTime.QuadPart - entry->CreateTime.QuadPart) > SEC_STALE_THRESHOLD_100NS) {

            SecpRemoveEntryLocked(internal, entry);
            entry->RemovedFromTracker = TRUE;
            staleEntries[staleCount++] = entry;
        }
    }

    ExReleasePushLockExclusive(&tracker->SectionLock);
    KeLeaveCriticalRegion();

    //
    // Release refs outside lock (may trigger free)
    //
    for (i = 0; i < staleCount; i++) {
        SecpReleaseEntry(staleEntries[i]);
    }

    SecpReleaseReference(internal);
}

// ============================================================================
// PRIVATE: ALLOCATION AND FREE
// ============================================================================

static PSEC_ENTRY
SecpAllocateEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    if (!Tracker->LookasideInitialized) {
        return NULL;
    }

    return (PSEC_ENTRY)ExAllocateFromNPagedLookasideList(&Tracker->EntryLookaside);
}

/**
 * Free resources owned by an entry (file name buffer, file object reference).
 * Does NOT return the entry struct to the pool.
 */
static VOID
SecpFreeEntryResources(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    UNREFERENCED_PARAMETER(Tracker);

    if (Entry->BackingFile.FileName.Buffer != NULL) {
        ShadowStrikeFreePoolWithTag(
            Entry->BackingFile.FileName.Buffer,
            SEC_POOL_TAG_ENTRY
        );
        Entry->BackingFile.FileName.Buffer = NULL;
    }

    //
    // MED-1: Release file object reference
    //
    if (Entry->BackingFile.FileObject != NULL) {
        ObDereferenceObject(Entry->BackingFile.FileObject);
        Entry->BackingFile.FileObject = NULL;
    }
}

/**
 * Return entry struct to lookaside pool.
 */
static VOID
SecpFreeEntryToPool(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    if (Tracker->LookasideInitialized && Entry != NULL) {
        ExFreeToNPagedLookasideList(&Tracker->EntryLookaside, Entry);
    }
}

static PSEC_MAP_ENTRY
SecpAllocateMapEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    if (!Tracker->LookasideInitialized) {
        return NULL;
    }

    return (PSEC_MAP_ENTRY)ExAllocateFromNPagedLookasideList(&Tracker->MapLookaside);
}

static VOID
SecpFreeMapEntry(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_MAP_ENTRY MapEntry
    )
{
    if (Tracker->LookasideInitialized && MapEntry != NULL) {
        ExFreeToNPagedLookasideList(&Tracker->MapLookaside, MapEntry);
    }
}

// ============================================================================
// PRIVATE: HASH TABLE (HIGH-6 fix — proper 64-bit hash)
// ============================================================================

static ULONG
SecpHashSectionObject(
    _In_ PVOID SectionObject,
    _In_ ULONG BucketCount
    )
{
    ULONG_PTR ptr = (ULONG_PTR)SectionObject;
    ULONG64 hash64;

    //
    // 64-bit Fibonacci hash with proper distribution
    //
    hash64 = (ULONG64)ptr * 0x9E3779B97F4A7C15ULL;
    hash64 ^= hash64 >> 32;
    hash64 *= 0xBF58476D1CE4E5B9ULL;
    hash64 ^= hash64 >> 32;

    return (ULONG)(hash64 % (ULONG64)BucketCount);
}

static PSEC_ENTRY
SecpFindEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PVOID SectionObject
    )
{
    ULONG bucket;
    PLIST_ENTRY listEntry;
    PSEC_ENTRY entry;

    bucket = SecpHashSectionObject(
        SectionObject,
        Tracker->Public.SectionHash.BucketCount
    );

    for (listEntry = Tracker->Public.SectionHash.Buckets[bucket].Flink;
         listEntry != &Tracker->Public.SectionHash.Buckets[bucket];
         listEntry = listEntry->Flink) {

        entry = CONTAINING_RECORD(listEntry, SEC_ENTRY, HashEntry);

        if (entry->SectionObject == SectionObject) {
            return entry;
        }
    }

    return NULL;
}

static VOID
SecpInsertEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    ULONG bucket;

    InsertTailList(&Tracker->Public.SectionList, &Entry->ListEntry);
    InterlockedIncrement(&Tracker->Public.SectionCount);

    bucket = SecpHashSectionObject(
        Entry->SectionObject,
        Tracker->Public.SectionHash.BucketCount
    );

    InsertTailList(&Tracker->Public.SectionHash.Buckets[bucket], &Entry->HashEntry);
}

static VOID
SecpRemoveEntryLocked(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    RemoveEntryList(&Entry->ListEntry);
    InitializeListHead(&Entry->ListEntry);
    InterlockedDecrement(&Tracker->Public.SectionCount);

    RemoveEntryList(&Entry->HashEntry);
    InitializeListHead(&Entry->HashEntry);
}

// ============================================================================
// PRIVATE: SECTION TYPE DETERMINATION
// ============================================================================

static SEC_SECTION_TYPE
SecpDetermineSectionType(
    _In_ SEC_FLAGS Flags
    )
{
    if (Flags & SecFlag_Image) {
        return SecType_Image;
    }
    if (Flags & SecFlag_ImageNoExecute) {
        return SecType_ImageNoExecute;
    }
    if (Flags & SecFlag_Physical) {
        return SecType_Physical;
    }
    if (Flags & SecFlag_PageFile) {
        return SecType_PageFile;
    }
    if (Flags & SecFlag_Reserve) {
        return SecType_Reserve;
    }
    if (Flags & SecFlag_Commit) {
        return SecType_Commit;
    }
    return SecType_Data;
}

// ============================================================================
// PRIVATE: PE ANALYSIS (CRITICAL-5 fix — proper implementation)
// ============================================================================

static VOID
SecpAnalyzePE(
    _In_ PSEC_ENTRY Entry,
    _In_ PFILE_OBJECT FileObject
    )
{
    NTSTATUS status;
    PVOID headerBuffer = NULL;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK ioStatus;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    ULONG e_lfanew;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK openIoStatus;
    UNICODE_STRING emptyName;

    if (FileObject == NULL) {
        return;
    }

    Entry->PE.IsPE = FALSE;

    headerBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        SEC_PE_HEADER_SIZE,
        SEC_POOL_TAG_CONTEXT
    );

    if (headerBuffer == NULL) {
        return;
    }

    RtlZeroMemory(headerBuffer, SEC_PE_HEADER_SIZE);

    //
    // Open file handle from the file object's name for ZwReadFile
    //
    if (Entry->BackingFile.FileName.Buffer == NULL ||
        Entry->BackingFile.FileName.Length == 0) {
        goto CleanupPE;
    }

    RtlInitUnicodeString(&emptyName, NULL);
    InitializeObjectAttributes(
        &objAttr,
        &Entry->BackingFile.FileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &openIoStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status)) {
        goto CleanupPE;
    }

    offset.QuadPart = 0;

    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        headerBuffer,
        SEC_PE_HEADER_SIZE,
        &offset,
        NULL
    );

    if (!NT_SUCCESS(status) || ioStatus.Information < sizeof(IMAGE_DOS_HEADER)) {
        goto CleanupPE;
    }

    dosHeader = (PIMAGE_DOS_HEADER)headerBuffer;

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        goto CleanupPE;
    }

    e_lfanew = (ULONG)dosHeader->e_lfanew;

    if (e_lfanew >= SEC_PE_HEADER_SIZE - sizeof(IMAGE_NT_HEADERS)) {
        goto CleanupPE;
    }

    if ((ULONG_PTR)e_lfanew + sizeof(IMAGE_NT_HEADERS) > ioStatus.Information) {
        goto CleanupPE;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)headerBuffer + e_lfanew);

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        goto CleanupPE;
    }

    //
    // Valid PE — extract metadata
    //
    Entry->PE.IsPE = TRUE;
    Entry->PE.Machine = ntHeaders->FileHeader.Machine;
    Entry->PE.Characteristics = ntHeaders->FileHeader.Characteristics;

    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        PIMAGE_OPTIONAL_HEADER32 opt32 =
            (PIMAGE_OPTIONAL_HEADER32)&ntHeaders->OptionalHeader;
        Entry->PE.ImageSize = opt32->SizeOfImage;
        Entry->PE.EntryPoint = opt32->AddressOfEntryPoint;

        //
        // Check for .NET: COM descriptor directory entry
        //
        if (opt32->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
            opt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
            Entry->PE.IsDotNet = TRUE;
        }
    } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_OPTIONAL_HEADER64 opt64 =
            (PIMAGE_OPTIONAL_HEADER64)&ntHeaders->OptionalHeader;
        Entry->PE.ImageSize = opt64->SizeOfImage;
        Entry->PE.EntryPoint = opt64->AddressOfEntryPoint;

        if (opt64->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR &&
            opt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0) {
            Entry->PE.IsDotNet = TRUE;
        }
    }

CleanupPE:
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    ShadowStrikeFreePoolWithTag(headerBuffer, SEC_POOL_TAG_CONTEXT);
}

// ============================================================================
// PRIVATE: FILE HASH (HIGH-1 fix — real implementation using HashUtils)
// ============================================================================

static VOID
SecpComputeFileHash(
    _In_ PSEC_ENTRY Entry,
    _In_ PFILE_OBJECT FileObject
    )
{
    NTSTATUS status;
    SHADOWSTRIKE_HASH_CONTEXT hashCtx;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    PVOID readBuffer = NULL;
    LARGE_INTEGER offset;
    ULONG bytesRead;
    static const ULONG HASH_READ_CHUNK = 65536;

    UNREFERENCED_PARAMETER(FileObject);

    Entry->BackingFile.HashValid = FALSE;

    if (Entry->BackingFile.FileName.Buffer == NULL ||
        Entry->BackingFile.FileName.Length == 0) {
        return;
    }

    RtlZeroMemory(&hashCtx, sizeof(hashCtx));

    status = ShadowStrikeHashContextInit(&hashCtx, ShadowHashAlgorithmSha256);
    if (!NT_SUCCESS(status)) {
        return;
    }

    readBuffer = ShadowStrikeAllocatePoolWithTag(
        NonPagedPoolNx,
        HASH_READ_CHUNK,
        SEC_POOL_TAG_CONTEXT
    );

    if (readBuffer == NULL) {
        ShadowStrikeHashContextCleanup(&hashCtx);
        return;
    }

    InitializeObjectAttributes(
        &objAttr,
        &Entry->BackingFile.FileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
    );

    if (!NT_SUCCESS(status)) {
        goto CleanupHash;
    }

    offset.QuadPart = 0;

    for (;;) {
        status = ZwReadFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            readBuffer,
            HASH_READ_CHUNK,
            &offset,
            NULL
        );

        if (status == STATUS_END_OF_FILE || ioStatus.Information == 0) {
            break;
        }

        if (!NT_SUCCESS(status)) {
            goto CleanupHash;
        }

        bytesRead = (ULONG)ioStatus.Information;

        status = ShadowStrikeHashContextUpdate(&hashCtx, readBuffer, bytesRead);
        if (!NT_SUCCESS(status)) {
            goto CleanupHash;
        }

        offset.QuadPart += bytesRead;
    }

    status = ShadowStrikeHashContextFinalize(
        &hashCtx,
        Entry->BackingFile.FileHash,
        sizeof(Entry->BackingFile.FileHash)
    );

    if (NT_SUCCESS(status)) {
        Entry->BackingFile.HashValid = TRUE;
    }

CleanupHash:
    if (fileHandle != NULL) {
        ZwClose(fileHandle);
    }

    ShadowStrikeHashContextCleanup(&hashCtx);

    if (readBuffer != NULL) {
        ShadowStrikeFreePoolWithTag(readBuffer, SEC_POOL_TAG_CONTEXT);
    }
}

// ============================================================================
// PRIVATE: SUSPICION SCORE (MED-4 fix — thread-safe)
// ============================================================================

static VOID
SecpUpdateSuspicionScore(
    _Inout_ PSEC_ENTRY Entry
    )
{
    ULONG score = 0;
    LONG flags = Entry->SuspicionFlags;
    ULONG indicatorCount = 0;
    LONG temp;

    if (flags & SecSuspicion_Transacted)        score += SEC_SCORE_TRANSACTED;
    if (flags & SecSuspicion_Deleted)           score += SEC_SCORE_DELETED;
    if (flags & SecSuspicion_CrossProcess)      score += SEC_SCORE_CROSS_PROCESS;
    if (flags & SecSuspicion_UnusualPath)       score += SEC_SCORE_UNUSUAL_PATH;
    if (flags & SecSuspicion_LargeAnonymous)    score += SEC_SCORE_LARGE_ANONYMOUS;
    if (flags & SecSuspicion_ExecuteAnonymous)  score += SEC_SCORE_EXECUTE_ANONYMOUS;
    if (flags & SecSuspicion_HiddenPE)          score += SEC_SCORE_HIDDEN_PE;
    if (flags & SecSuspicion_RemoteMap)          score += SEC_SCORE_REMOTE_MAP;
    if (flags & SecSuspicion_SuspiciousName)    score += SEC_SCORE_SUSPICIOUS_NAME;
    if (flags & SecSuspicion_NoBackingFile)     score += SEC_SCORE_NO_BACKING_FILE;
    if (flags & SecSuspicion_ModifiedImage)     score += SEC_SCORE_MODIFIED_IMAGE;
    if (flags & SecSuspicion_OverlayData)       score += SEC_SCORE_OVERLAY_DATA;

    //
    // Count set bits for combination bonus
    //
    temp = flags;
    while (temp) {
        indicatorCount += (temp & 1);
        temp >>= 1;
    }

    if (indicatorCount >= 3) {
        score += indicatorCount * 50;
    }

    InterlockedExchange(&Entry->SuspicionScore, (LONG)score);
}

// ============================================================================
// PRIVATE: SNAPSHOT HELPERS (DESIGN-1 — fill read-only copies for callers)
// ============================================================================

static VOID
SecpFillSectionInfo(
    _In_ PSEC_ENTRY Entry,
    _Out_ PSEC_SECTION_INFO Info
    )
{
    RtlZeroMemory(Info, sizeof(SEC_SECTION_INFO));

    Info->SectionId = Entry->SectionId;
    Info->CreatorProcessId = Entry->CreatorProcessId;
    Info->Type = Entry->Type;
    Info->Flags = Entry->Flags;
    Info->MaximumSize = Entry->MaximumSize;

    //
    // Copy backing file info (UNICODE_STRING points to Entry's buffer —
    // valid as long as we're under lock. Caller should treat as read-only snapshot.)
    //
    Info->BackingFile.FileName = Entry->BackingFile.FileName;
    Info->BackingFile.FileSize = Entry->BackingFile.FileSize;
    Info->BackingFile.FileCreationTime = Entry->BackingFile.FileCreationTime;
    Info->BackingFile.IsTransacted = Entry->BackingFile.IsTransacted;
    Info->BackingFile.IsDeleted = Entry->BackingFile.IsDeleted;
    Info->BackingFile.HashValid = Entry->BackingFile.HashValid;
    RtlCopyMemory(Info->BackingFile.FileHash,
                   Entry->BackingFile.FileHash,
                   sizeof(Info->BackingFile.FileHash));

    Info->PE = Entry->PE;

    Info->MapCount = Entry->MapCount;
    Info->CrossProcessMapCount = Entry->CrossProcessMapCount;
    Info->SuspicionFlags = (SEC_SUSPICION)Entry->SuspicionFlags;
    Info->SuspicionScore = (ULONG)Entry->SuspicionScore;
    Info->CreateTime = Entry->CreateTime;
    Info->LastMapTime = Entry->LastMapTime;
}

static VOID
SecpFillMapInfo(
    _In_ PSEC_MAP_ENTRY MapEntry,
    _Out_ PSEC_MAP_INFO Info
    )
{
    Info->ProcessId = MapEntry->ProcessId;
    Info->ViewBase = MapEntry->ViewBase;
    Info->ViewSize = MapEntry->ViewSize;
    Info->SectionOffset = MapEntry->SectionOffset;
    Info->Protection = MapEntry->Protection;
    Info->AllocationType = MapEntry->AllocationType;
    Info->MapTime = MapEntry->MapTime;
    Info->UnmapTime = MapEntry->UnmapTime;
    Info->IsMapped = MapEntry->IsMapped;
}

// ============================================================================
// PRIVATE: CALLBACK INVOCATION
// Callbacks receive stack-local snapshots, never internal pointers.
// ============================================================================

static VOID
SecpInvokeCreateCallbacks(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry
    )
{
    ULONG i;
    SEC_SECTION_INFO info;

    SecpFillSectionInfo(Entry, &info);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (Tracker->CreateCallbacks[i].InUse &&
            Tracker->CreateCallbacks[i].CreateCallback != NULL) {

            Tracker->CreateCallbacks[i].CreateCallback(
                &info,
                Tracker->CreateCallbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);
    KeLeaveCriticalRegion();
}

static VOID
SecpInvokeMapCallbacks(
    _In_ PSEC_TRACKER_INTERNAL Tracker,
    _In_ PSEC_ENTRY Entry,
    _In_ PSEC_MAP_ENTRY MapEntry
    )
{
    ULONG i;
    SEC_SECTION_INFO sectionInfo;
    SEC_MAP_INFO mapInfo;

    SecpFillSectionInfo(Entry, &sectionInfo);
    SecpFillMapInfo(MapEntry, &mapInfo);

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&Tracker->CallbackLock);

    for (i = 0; i < SEC_MAX_CALLBACKS; i++) {
        if (Tracker->MapCallbacks[i].InUse &&
            Tracker->MapCallbacks[i].MapCallback != NULL) {

            Tracker->MapCallbacks[i].MapCallback(
                &sectionInfo,
                &mapInfo,
                Tracker->MapCallbacks[i].Context
            );
        }
    }

    ExReleasePushLockShared(&Tracker->CallbackLock);
    KeLeaveCriticalRegion();
}

// ============================================================================
// PRIVATE: FILE ANALYSIS HELPERS
// ============================================================================

/**
 * HIGH-2 fix: Proper TxF transaction detection using IoGetTransactionParameterBlock.
 */
static BOOLEAN
SecpIsTransactedFile(
    _In_ PFILE_OBJECT FileObject
    )
{
    PTXN_PARAMETER_BLOCK txnBlock;

    if (FileObject == NULL) {
        return FALSE;
    }

    txnBlock = IoGetTransactionParameterBlock(FileObject);

    return (txnBlock != NULL);
}

static BOOLEAN
SecpIsFileDeleted(
    _In_ PFILE_OBJECT FileObject
    )
{
    if (FileObject == NULL) {
        return FALSE;
    }

    if (FileObject->DeletePending) {
        return TRUE;
    }

    //
    // Also check SectionObjectPointer for dismounted/purged state
    //
    if (FileObject->SectionObjectPointer != NULL &&
        FileObject->SectionObjectPointer->DataSectionObject == NULL &&
        FileObject->SectionObjectPointer->ImageSectionObject == NULL) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE: PATH ANALYSIS (CRITICAL-6, CRITICAL-7, MED-6 fixes)
// All string operations use UNICODE_STRING-safe functions.
// ============================================================================

/**
 * UNICODE_STRING-safe substring search.
 * Does NOT rely on null termination.
 */
static BOOLEAN
SecpUnicodeStringContains(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle,
    _In_ BOOLEAN CaseInsensitive
    )
{
    USHORT haystackChars;
    USHORT needleChars;
    USHORT i;

    if (Haystack == NULL || Haystack->Buffer == NULL ||
        Needle == NULL || Needle->Buffer == NULL) {
        return FALSE;
    }

    haystackChars = Haystack->Length / sizeof(WCHAR);
    needleChars = Needle->Length / sizeof(WCHAR);

    if (needleChars == 0 || needleChars > haystackChars) {
        return FALSE;
    }

    for (i = 0; i <= haystackChars - needleChars; i++) {
        UNICODE_STRING sub;
        sub.Buffer = &Haystack->Buffer[i];
        sub.Length = Needle->Length;
        sub.MaximumLength = Needle->Length;

        if (RtlEqualUnicodeString(&sub, Needle, CaseInsensitive)) {
            return TRUE;
        }
    }

    return FALSE;
}

static USHORT
SecpUnicodeCharLen(
    _In_ PCUNICODE_STRING Str
    )
{
    return Str->Length / sizeof(WCHAR);
}

static BOOLEAN
SecpIsUnusualPath(
    _In_ PUNICODE_STRING FilePath
    )
{
    static const UNICODE_STRING suspiciousPaths[] = {
        RTL_CONSTANT_STRING(L"\\Temp\\"),
        RTL_CONSTANT_STRING(L"\\AppData\\Local\\Temp\\"),
        RTL_CONSTANT_STRING(L"\\Downloads\\"),
        RTL_CONSTANT_STRING(L"\\ProgramData\\"),
        RTL_CONSTANT_STRING(L"\\Users\\Public\\"),
    };

    ULONG i;

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(suspiciousPaths); i++) {
        if (SecpUnicodeStringContains(FilePath, &suspiciousPaths[i], TRUE)) {
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * MED-6 fix: No wcsrchr/wcslen/_wcsicmp on UNICODE_STRING.
 * All operations use length-bounded UNICODE_STRING APIs.
 */
static BOOLEAN
SecpIsSuspiciousName(
    _In_ PUNICODE_STRING FilePath
    )
{
    USHORT charLen;
    USHORT fileNameStartIdx = 0;
    USHORT fileNameLen;
    USHORT dotCount = 0;
    USHORT lastDotIdx = 0;
    USHORT i;
    UNICODE_STRING extension;
    UNICODE_STRING exeExt = RTL_CONSTANT_STRING(L".exe");
    UNICODE_STRING dllExt = RTL_CONSTANT_STRING(L".dll");
    UNICODE_STRING scrExt = RTL_CONSTANT_STRING(L".scr");

    if (FilePath == NULL || FilePath->Buffer == NULL || FilePath->Length == 0) {
        return FALSE;
    }

    charLen = SecpUnicodeCharLen(FilePath);

    //
    // Find last backslash to extract filename portion
    //
    for (i = 0; i < charLen; i++) {
        if (FilePath->Buffer[i] == L'\\') {
            fileNameStartIdx = i + 1;
        }
    }

    fileNameLen = charLen - fileNameStartIdx;

    if (fileNameLen == 0) {
        return FALSE;
    }

    //
    // Count dots and find last dot in filename
    //
    for (i = fileNameStartIdx; i < charLen; i++) {
        if (FilePath->Buffer[i] == L'.') {
            dotCount++;
            lastDotIdx = i;
        }
    }

    //
    // Check for double extensions with suspicious final extension
    //
    if (dotCount >= 2 && lastDotIdx > fileNameStartIdx) {
        extension.Buffer = &FilePath->Buffer[lastDotIdx];
        extension.Length = (charLen - lastDotIdx) * sizeof(WCHAR);
        extension.MaximumLength = extension.Length;

        if (RtlEqualUnicodeString(&extension, &exeExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &dllExt, TRUE) ||
            RtlEqualUnicodeString(&extension, &scrExt, TRUE)) {
            return TRUE;
        }
    }

    //
    // Very long filename (> 200 chars) — possible evasion
    //
    if (fileNameLen > 200) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// PRIVATE: TRACKER OPERATION REFERENCE COUNTING (HIGH-7 fix)
// ============================================================================

/**
 * Acquire an operation reference. Returns FALSE if shutting down.
 * Pattern: increment FIRST, then check ShuttingDown.
 * This eliminates the TOCTOU race in the original code.
 */
static BOOLEAN
SecpAcquireReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    InterlockedIncrement(&Tracker->ActiveOperations);

    if (Tracker->ShuttingDown) {
        //
        // Shutting down — undo the increment and bail
        //
        if (InterlockedDecrement(&Tracker->ActiveOperations) == 0) {
            KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
        }
        return FALSE;
    }

    return TRUE;
}

static VOID
SecpReleaseReference(
    _In_ PSEC_TRACKER_INTERNAL Tracker
    )
{
    if (InterlockedDecrement(&Tracker->ActiveOperations) == 0) {
        KeSetEvent(&Tracker->ShutdownEvent, IO_NO_INCREMENT, FALSE);
    }
}
